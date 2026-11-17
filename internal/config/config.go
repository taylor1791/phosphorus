// Package config parses the files people write: the workspace and package
// carbon.toml files, .carbon/people/*.toml, .carbon/machines/*.toml and
// .carbon/teams.toml. It reads them from a [Source], which is the working
// tree or a git ref, and never executes anything in them.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// FileName is the name of workspace and package files.
const FileName = "carbon.toml"

// Paths inside the workspace root.
const (
	CarbonDir   = ".carbon"
	PeopleDir   = ".carbon/people"
	MachinesDir = ".carbon/machines"
	TeamsFile   = ".carbon/teams.toml"
)

// Format is the only workspace format this binary understands.
const Format = 1

// ErrTrunkSettingRemoved is returned for a workspace file that still has
// [workspace] trunk. The trunk ref is chosen per clone (CARBON_TRUNK, git
// config carbon.trunk, or the remote default branch), never by a commit.
var ErrTrunkSettingRemoved = errors.New(`[workspace] trunk was removed: delete the line, and if this clone needs a trunk other than the remote default branch, run "git config carbon.trunk <ref>" or set CARBON_TRUNK`)

// TrunkWorktree is the trunk value (from CARBON_TRUNK or git config only)
// that reads policy from the working tree always.
const TrunkWorktree = "worktree"

// IsLegacy reports whether data parses as a carbon 0.0.3 carbon.toml (it
// has a [push] or [pull] table).
func IsLegacy(data []byte) bool {
	var loose map[string]any
	if toml.Unmarshal(data, &loose) != nil {
		return false
	}
	_, push := loose["push"]
	_, pull := loose["pull"]
	return push || pull
}

// LegacyError means a carbon.toml is a carbon 0.0.3 file.
type LegacyError struct{ Path string }

func (e *LegacyError) Error() string {
	return fmt.Sprintf("%s is a carbon 0.0.3 file (it has a [push] or [pull] table)", e.Path)
}

// FileError wraps a parse or validation error with the file it came from.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e *FileError) Unwrap() error { return e.Err }

// Access is one environment's entry in an [access] table.
type Access struct {
	Readers []string
	// RequirePQ and Drops are nil when the entry does not set them.
	RequirePQ *bool
	Drops     *bool
}

// Secret is a declaration in a package's [secrets] table.
type Secret struct {
	Description string `toml:"description"`
	Generate    string `toml:"generate"`
	RotateAfter string `toml:"rotate_after"`
	Private     bool   `toml:"private"`
}

// Package is a package's carbon.toml.
type Package struct {
	Name string
	// File is the slash path of the carbon.toml relative to the workspace
	// root; Dir is its directory ("." for the root package).
	File, Dir string
	Access    map[string]Access
	Secrets   map[string]Secret
	Vars      map[string]map[string]string // var -> env (or "default") -> value
	Env       map[string]string            // process variable -> template
}

// Workspace is the root carbon.toml.
type Workspace struct {
	Format             int
	Environments       []string
	DefaultEnvironment string
	Access             map[string]Access
	// Package is set when the root file is also a package.
	Package *Package
}

// HasEnvironment reports whether env is one of the workspace environments.
func (w *Workspace) HasEnvironment(env string) bool {
	for _, e := range w.Environments {
		if e == env {
			return true
		}
	}
	return false
}

// Resolved is the effective access for one package in one environment.
type Resolved struct {
	Readers   []string
	RequirePQ bool
	Drops     bool
	// ReadersFrom is the file whose [access] entry supplied the readers:
	// the package's carbon.toml or the workspace's. Empty when neither
	// names the environment.
	ReadersFrom string
}

// ResolveAccess applies the inheritance rule: a package entry's readers
// replace the workspace's; require_pq and drops inherit from the workspace
// unless the package's long form sets them.
func (w *Workspace) ResolveAccess(p *Package, env string) Resolved {
	r := Resolved{Drops: true}
	if wa, ok := w.Access[env]; ok {
		r.Readers = append([]string(nil), wa.Readers...)
		r.ReadersFrom = FileName
		if wa.RequirePQ != nil {
			r.RequirePQ = *wa.RequirePQ
		}
		if wa.Drops != nil {
			r.Drops = *wa.Drops
		}
	}
	if p != nil {
		if pa, ok := p.Access[env]; ok {
			r.Readers = append([]string(nil), pa.Readers...)
			r.ReadersFrom = p.File
			if pa.RequirePQ != nil {
				r.RequirePQ = *pa.RequirePQ
			}
			if pa.Drops != nil {
				r.Drops = *pa.Drops
			}
		}
	}
	return r
}

type workspaceTOML struct {
	Format             *int     `toml:"format"`
	Environments       []string `toml:"environments"`
	DefaultEnvironment string   `toml:"default_environment"`
	// Trunk was removed: the trunk ref never comes from a commit. It is
	// decoded only to explain the error.
	Trunk *string `toml:"trunk"`
}

type fileTOML struct {
	Workspace *workspaceTOML               `toml:"workspace"`
	Name      string                       `toml:"name"`
	Access    map[string]any               `toml:"access"`
	Secrets   map[string]Secret            `toml:"secrets"`
	Vars      map[string]map[string]string `toml:"vars"`
	Env       map[string]string            `toml:"env"`
}

// ParseFile parses a carbon.toml at the slash path file. It returns the
// workspace (if the file has [workspace]) and the package (if it has name).
// A 0.0.3 file returns a *LegacyError; conflict markers a *ConflictError.
func ParseFile(file string, data []byte) (*Workspace, *Package, error) {
	if HasConflictMarkers(data) {
		return nil, nil, &ConflictError{Path: file}
	}
	var loose map[string]any
	if err := toml.Unmarshal(data, &loose); err != nil {
		return nil, nil, &FileError{file, tomlErr(err)}
	}
	if _, ok := loose["push"]; ok {
		return nil, nil, &LegacyError{Path: file}
	}
	if _, ok := loose["pull"]; ok {
		return nil, nil, &LegacyError{Path: file}
	}
	var f fileTOML
	if err := strictDecode(data, &f); err != nil {
		return nil, nil, &FileError{file, err}
	}
	var ws *Workspace
	var pkg *Package
	if f.Workspace != nil {
		w, err := buildWorkspace(f)
		if err != nil {
			return nil, nil, &FileError{file, err}
		}
		ws = w
	}
	if f.Name != "" || f.Secrets != nil || f.Vars != nil || f.Env != nil || (f.Workspace == nil) {
		if f.Name == "" {
			return nil, nil, &FileError{file, errors.New("a package file needs name = \"<package>\"")}
		}
		p, err := buildPackage(file, f)
		if err != nil {
			return nil, nil, &FileError{file, err}
		}
		pkg = p
	}
	if ws != nil {
		ws.Package = pkg
		if pkg != nil {
			// At the root, [access] is the workspace default; the root
			// package has no override of its own.
			pkg.Access = map[string]Access{}
		}
		if err := ws.ValidatePackage(pkg); err != nil {
			return nil, nil, &FileError{file, err}
		}
	}
	return ws, pkg, nil
}

func buildWorkspace(f fileTOML) (*Workspace, error) {
	wt := f.Workspace
	if wt.Format == nil {
		return nil, errors.New("[workspace] needs format = 1")
	}
	if *wt.Format != Format {
		return nil, fmt.Errorf("workspace format %d is not supported by this carbon (it reads format %d)", *wt.Format, Format)
	}
	if len(wt.Environments) == 0 {
		return nil, errors.New("[workspace] needs environments = [...]")
	}
	seen := map[string]bool{}
	for _, e := range wt.Environments {
		if err := CheckName("environment", e); err != nil {
			return nil, err
		}
		if e == "default" {
			return nil, errors.New(`"default" cannot be an environment name; it is reserved in [vars]`)
		}
		if seen[e] {
			return nil, fmt.Errorf("environment %q is listed twice", e)
		}
		seen[e] = true
	}
	ws := &Workspace{
		Format:             *wt.Format,
		Environments:       wt.Environments,
		DefaultEnvironment: wt.DefaultEnvironment,
	}
	if ws.DefaultEnvironment == "" {
		ws.DefaultEnvironment = ws.Environments[0]
	}
	if !ws.HasEnvironment(ws.DefaultEnvironment) {
		return nil, fmt.Errorf("default_environment %q is not in environments", ws.DefaultEnvironment)
	}
	if wt.Trunk != nil {
		return nil, ErrTrunkSettingRemoved
	}
	acc, err := parseAccess(f.Access)
	if err != nil {
		return nil, err
	}
	for env := range acc {
		if !ws.HasEnvironment(env) {
			return nil, fmt.Errorf("[access] names environment %q, which is not in environments", env)
		}
	}
	ws.Access = acc
	return ws, nil
}

func buildPackage(file string, f fileTOML) (*Package, error) {
	if err := CheckName("package", f.Name); err != nil {
		return nil, err
	}
	p := &Package{
		Name:    f.Name,
		File:    file,
		Dir:     dirOf(file),
		Secrets: f.Secrets,
		Vars:    f.Vars,
		Env:     f.Env,
	}
	if p.Secrets == nil {
		p.Secrets = map[string]Secret{}
	}
	if p.Vars == nil {
		p.Vars = map[string]map[string]string{}
	}
	if p.Env == nil {
		p.Env = map[string]string{}
	}
	acc, err := parseAccess(f.Access)
	if err != nil {
		return nil, err
	}
	p.Access = acc
	for name, s := range p.Secrets {
		if err := CheckSecretName(name); err != nil {
			return nil, err
		}
		if s.Generate != "" {
			if _, err := ParseGenerate(s.Generate); err != nil {
				return nil, fmt.Errorf("secret %s: %w", name, err)
			}
		}
		if s.RotateAfter != "" {
			if _, err := ParseDuration(s.RotateAfter); err != nil {
				return nil, fmt.Errorf("secret %s: rotate_after: %w", name, err)
			}
		}
	}
	for name := range p.Vars {
		if err := CheckSecretName(name); err != nil {
			return nil, fmt.Errorf("var: %w", err)
		}
	}
	for name, tmpl := range p.Env {
		if !ValidSecretName(name) {
			return nil, fmt.Errorf("[env] key %q is not a valid variable name", name)
		}
		if _, err := ParseTemplate(tmpl); err != nil {
			return nil, fmt.Errorf("[env] %s: %w", name, err)
		}
	}
	return p, nil
}

// ValidatePackage checks a package against the workspace: every environment
// it names in [access] and [vars] exists. A nil package is valid.
func (w *Workspace) ValidatePackage(p *Package) error {
	if p == nil {
		return nil
	}
	for env := range p.Access {
		if !w.HasEnvironment(env) {
			return fmt.Errorf("[access] names environment %q, which is not in the workspace's environments", env)
		}
	}
	for name, byEnv := range p.Vars {
		for env := range byEnv {
			if env != "default" && !w.HasEnvironment(env) {
				return fmt.Errorf("[vars.%s] names environment %q, which is not in the workspace's environments", name, env)
			}
		}
	}
	return nil
}

func parseAccess(raw map[string]any) (map[string]Access, error) {
	out := map[string]Access{}
	for env, v := range raw {
		if !ValidName(env) {
			return nil, fmt.Errorf("[access] key %q is not an environment name", env)
		}
		var a Access
		switch v := v.(type) {
		case []any:
			rs, err := readerList(env, v)
			if err != nil {
				return nil, err
			}
			a.Readers = rs
		case map[string]any:
			for k, fv := range v {
				switch k {
				case "readers":
					list, ok := fv.([]any)
					if !ok {
						return nil, fmt.Errorf("[access] %s.readers must be a list of strings", env)
					}
					rs, err := readerList(env, list)
					if err != nil {
						return nil, err
					}
					a.Readers = rs
				case "require_pq", "drops":
					b, ok := fv.(bool)
					if !ok {
						return nil, fmt.Errorf("[access] %s.%s must be true or false", env, k)
					}
					if k == "require_pq" {
						a.RequirePQ = &b
					} else {
						a.Drops = &b
					}
				default:
					return nil, fmt.Errorf("[access] %s has unknown key %q (want readers, require_pq, drops)", env, k)
				}
			}
			if a.Readers == nil {
				return nil, fmt.Errorf("[access] %s needs readers = [...]", env)
			}
		default:
			return nil, fmt.Errorf("[access] %s must be a list of readers or a table with readers", env)
		}
		out[env] = a
	}
	return out, nil
}

func readerList(env string, list []any) ([]string, error) {
	rs := []string{}
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("[access] %s: readers must be strings", env)
		}
		if err := CheckReader(s); err != nil {
			return nil, fmt.Errorf("[access] %s: %w", env, err)
		}
		rs = append(rs, s)
	}
	return rs, nil
}

// ReaderKind classifies an access-list entry.
type ReaderKind string

const (
	ReaderTeam    ReaderKind = "team"
	ReaderPerson  ReaderKind = "person"
	ReaderMachine ReaderKind = "machine"
)

// ParseReader splits "@team", "person" or "machine:name".
func ParseReader(s string) (ReaderKind, string, error) {
	switch {
	case strings.HasPrefix(s, "@"):
		if n := s[1:]; ValidName(n) {
			return ReaderTeam, n, nil
		}
	case strings.HasPrefix(s, MachinePrefix):
		if n := s[len(MachinePrefix):]; ValidName(n) {
			return ReaderMachine, n, nil
		}
	case ValidName(s):
		return ReaderPerson, s, nil
	}
	return "", "", fmt.Errorf("reader %q is not @team, person, or machine:name", s)
}

// CheckReader returns an error if s is not a valid reader.
func CheckReader(s string) error { _, _, err := ParseReader(s); return err }

// ParseDuration parses "<n>d" or "<n>h".
func ParseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("duration %q is not <n>d or <n>h", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("duration %q is not <n>d or <n>h", s)
	}
	switch s[len(s)-1] {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	}
	return 0, fmt.Errorf("duration %q is not <n>d or <n>h", s)
}

// MaxGenerateBytes bounds generate = "random:<n>".
const MaxGenerateBytes = 1024

// ParseGenerate parses generate = "random:<bytes>" and returns the byte count.
// The generated value is the bytes in unpadded URL-safe base64.
func ParseGenerate(s string) (int, error) {
	n, ok := strings.CutPrefix(s, "random:")
	if !ok {
		return 0, fmt.Errorf("generate %q is not random:<bytes>", s)
	}
	v, err := strconv.Atoi(n)
	if err != nil || v < 1 || v > MaxGenerateBytes {
		return 0, fmt.Errorf("generate %q needs a byte count from 1 to %d", s, MaxGenerateBytes)
	}
	return v, nil
}

func strictDecode(data []byte, v any) error {
	d := toml.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return tomlErr(d.Decode(v))
}

func tomlErr(err error) error {
	if err == nil {
		return nil
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, col := de.Position()
		return fmt.Errorf("line %d column %d: %s", row, col, de.Error())
	}
	var sm *toml.StrictMissingError
	if errors.As(err, &sm) {
		var keys []string
		for _, e := range sm.Errors {
			keys = append(keys, strings.Join(e.Key(), "."))
		}
		return fmt.Errorf("unknown key %s", strings.Join(keys, ", "))
	}
	return err
}

// sortedKeys returns the keys of a string-keyed map in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
