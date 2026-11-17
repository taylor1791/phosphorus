// Package legacy reads a carbon 0.0.3 repository: the per-service
// carbon.toml files and the registry and sops files under .carbon/. It never
// runs anything those files name, and it does not decrypt; see Decrypt.
package legacy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Names fixed by carbon 0.0.3.
const (
	ConfigDir      = ".carbon"
	ServiceFile    = "carbon.toml"
	PrivateKeyFile = ".carbon/private-key.age"
	DefaultOutFile = ".environment.json"
)

// Expr is one push or derive expression, or a pull default: a value or a
// command, optionally limited to registries matching Pattern.
type Expr struct {
	Pattern      *string
	Value        *string
	Command      *string
	ExpectUnused bool
}

// HasCommand reports whether the expression runs a command.
func (e Expr) HasCommand() bool { return e.Command != nil }

// Pull is one [pull.<local>] entry.
type Pull struct {
	Local   string
	Service string // empty when the entry names no service
	Name    string // the pushed key; defaults to Local
	Default *Expr
}

// Service is one 0.0.3 carbon.toml.
type Service struct {
	Name string
	File string // slash path relative to the repository root
	Dir  string // "." for the root
	// Push and Derive map a key to its expressions in file order.
	Push        map[string][]Expr
	Pull        map[string]Pull
	Derive      map[string][]Expr
	HasRegistry bool   // a [registry] table (current/use)
	OutFile     string // `file`, or .environment.json
	HasFile     bool   // `file` was set explicitly
	Problems    []string
}

// PushKeys returns the push keys in order.
func (s *Service) PushKeys() []string { return sortedKeys(s.Push) }

// PullKeys returns the pull local names in order.
func (s *Service) PullKeys() []string { return sortedKeys(s.Pull) }

// DeriveKeys returns the derive names in order.
func (s *Service) DeriveKeys() []string { return sortedKeys(s.Derive) }

// User is one entry of `users` in a sops config.
type User struct {
	Name string
	Key  string
}

// Registry is one 0.0.3 registry: the unnamed default ("") or a named one.
type Registry struct {
	Name         string
	RegistryFile string // slash path; may not exist
	SopsFile     string // slash path; may not exist
	HasRegistry  bool
	HasSops      bool
	Users        []User
	// Requested are the age recipients in the sops creation rule: everyone
	// who ran `carbon request`. Granted are the recipients the encrypted
	// registry is actually wrapped to, which is who can read it.
	Requested []string
	Granted   []string
}

// Label renders the registry for people.
func (r *Registry) Label() string {
	if r.Name == "" {
		return "(default)"
	}
	return r.Name
}

// Repo is everything read from a 0.0.3 repository.
type Repo struct {
	Root       string
	Services   []*Service
	Registries []*Registry // default first, then by name
}

// IsLegacyConfig reports whether a carbon.toml's content is a 0.0.3 service
// file: it has a name and no [workspace] table.
func IsLegacyConfig(data []byte) bool {
	var m map[string]any
	if toml.Unmarshal(data, &m) != nil {
		return false
	}
	if _, ok := m["workspace"]; ok {
		return false
	}
	_, push := m["push"]
	_, pull := m["pull"]
	_, derive := m["derive"]
	_, name := m["name"]
	return push || pull || derive || name
}

// Load reads the services named by files (slash paths of carbon.toml files
// relative to root) and the registries under .carbon/.
func Load(root string, files []string) (*Repo, error) {
	repo := &Repo{Root: root}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		if !IsLegacyConfig(data) {
			continue
		}
		s, err := ParseService(f, data)
		if err != nil {
			return nil, err
		}
		repo.Services = append(repo.Services, s)
	}
	sort.Slice(repo.Services, func(i, j int) bool { return repo.Services[i].File < repo.Services[j].File })
	regs, err := loadRegistries(root)
	if err != nil {
		return nil, err
	}
	repo.Registries = regs
	return repo, nil
}

// ParseService parses a 0.0.3 carbon.toml at slash path file.
func ParseService(file string, data []byte) (*Service, error) {
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	s := &Service{
		File:    file,
		Dir:     path.Dir(file),
		Push:    map[string][]Expr{},
		Pull:    map[string]Pull{},
		Derive:  map[string][]Expr{},
		OutFile: DefaultOutFile,
	}
	name, ok := m["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("%s: a carbon 0.0.3 service needs name = \"...\"", file)
	}
	s.Name = name
	if f, ok := m["file"].(string); ok {
		s.OutFile, s.HasFile = f, true
	}
	if _, ok := m["registry"]; ok {
		s.HasRegistry = true
	}
	if raw, ok := m["push"]; ok {
		t, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: [push] is not a table", file)
		}
		for k, v := range t {
			exprs, err := parseExprs(v)
			if err != nil {
				return nil, fmt.Errorf("%s: push.%s: %w", file, k, err)
			}
			s.Push[k] = exprs
		}
	}
	if raw, ok := m["derive"]; ok {
		t, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: [derive] is not a table", file)
		}
		for k, v := range t {
			exprs, err := parseExprs(v)
			if err != nil {
				return nil, fmt.Errorf("%s: derive.%s: %w", file, k, err)
			}
			s.Derive[k] = exprs
		}
	}
	if raw, ok := m["pull"]; ok {
		t, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: [pull] is not a table", file)
		}
		for k, v := range t {
			pt, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: pull.%s is not a table", file, k)
			}
			p := Pull{Local: k, Name: k}
			if sv, ok := pt["service"]; ok {
				p.Service = scalar(sv)
			}
			if nv, ok := pt["name"]; ok {
				p.Name = scalar(nv)
			}
			if dv, ok := pt["default"]; ok {
				dt, ok := dv.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%s: pull.%s.default is not a table", file, k)
				}
				e := exprFrom(dt)
				p.Default = &e
			}
			s.Pull[k] = p
		}
	}
	return s, nil
}

func parseExprs(v any) ([]Expr, error) {
	switch v := v.(type) {
	case map[string]any:
		return []Expr{exprFrom(v)}, nil
	case []any:
		var out []Expr
		for _, x := range v {
			t, ok := x.(map[string]any)
			if !ok {
				return nil, errors.New("an array entry is not a table")
			}
			out = append(out, exprFrom(t))
		}
		return out, nil
	case []map[string]any:
		var out []Expr
		for _, t := range v {
			out = append(out, exprFrom(t))
		}
		return out, nil
	}
	return nil, fmt.Errorf("must be a table or an array of tables, not %T", v)
}

func exprFrom(t map[string]any) Expr {
	var e Expr
	if v, ok := t["registry_pattern"]; ok {
		s := scalar(v)
		e.Pattern = &s
	}
	if v, ok := t["value"]; ok {
		s := scalar(v)
		e.Value = &s
	}
	if v, ok := t["command"]; ok {
		s := scalar(v)
		e.Command = &s
	}
	if v, ok := t["expect_unused"].(bool); ok {
		e.ExpectUnused = v
	}
	return e
}

// scalar renders a TOML value the way nushell's `into string` would for the
// common cases (strings verbatim, numbers and booleans in decimal).
func scalar(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// Select returns the expression carbon 0.0.3 would use in registry, with
// find_expression's precedence: exactly one registry_pattern that matches
// wins; with none, the single expression without a pattern; anything else
// is an error. Patterns are unanchored regular expressions matched against
// the registry name ("" for the default registry).
func Select(exprs []Expr, registry string) (*Expr, error) {
	i, err := SelectIndex(exprs, registry)
	if err != nil {
		return nil, err
	}
	return &exprs[i], nil
}

// SelectIndex is Select returning the index of the expression.
func SelectIndex(exprs []Expr, registry string) (int, error) {
	var matched, defaults []int
	for i, e := range exprs {
		if e.Pattern == nil {
			defaults = append(defaults, i)
			continue
		}
		re, err := regexp.Compile(*e.Pattern)
		if err != nil {
			return -1, fmt.Errorf("registry_pattern %q does not compile: %v", *e.Pattern, err)
		}
		if re.MatchString(registry) {
			matched = append(matched, i)
		}
	}
	switch {
	case len(matched) == 1:
		return matched[0], nil
	case len(matched) > 1:
		return -1, fmt.Errorf("%d registry patterns match, which carbon 0.0.3 rejects", len(matched))
	case len(defaults) == 1:
		return defaults[0], nil
	case len(defaults) > 1:
		return -1, fmt.Errorf("%d expressions have no registry_pattern, which carbon 0.0.3 rejects", len(defaults))
	}
	return -1, errors.New("no registry pattern matches and there is no default")
}

// RegistryFile and SopsFile are the 0.0.3 paths for a registry name.
func RegistryFile(name string) string { return path.Join(ConfigDir, suffixed("registry", name)) }

// SopsFile is the sops config path for a registry name.
func SopsFile(name string) string { return path.Join(ConfigDir, suffixed("sops", name)) }

func suffixed(stem, name string) string {
	if name == "" {
		return stem + ".yaml"
	}
	return stem + "." + name + ".yaml"
}

func loadRegistries(root string) ([]*Registry, error) {
	entries, err := os.ReadDir(filepath.Join(root, ConfigDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		for _, stem := range []string{"registry", "sops"} {
			if n == stem+".yaml" {
				names[""] = true
			} else if mid, ok := strings.CutPrefix(n, stem+"."); ok {
				if reg, ok := strings.CutSuffix(mid, ".yaml"); ok && reg != "" {
					names[reg] = true
				}
			}
		}
	}
	var out []*Registry
	for _, n := range sortedKeys(names) {
		r := &Registry{Name: n, RegistryFile: RegistryFile(n), SopsFile: SopsFile(n)}
		if data, err := os.ReadFile(filepath.Join(root, r.SopsFile)); err == nil {
			r.HasSops = true
			r.Users = parseUsers(string(data))
			r.Requested = recipientsIn(creationRules(string(data)))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if data, err := os.ReadFile(filepath.Join(root, r.RegistryFile)); err == nil {
			r.HasRegistry = true
			r.Granted = sopsRecipients(string(data))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

var (
	ageRecipientRe  = regexp.MustCompile(`age1[02-9ac-hj-np-z]{58}`)
	sopsRecipientRe = regexp.MustCompile(`(?m)recipient:\s*['"]?(age1[02-9ac-hj-np-z]+)`)
)

func recipientsIn(s string) []string { return uniq(ageRecipientRe.FindAllString(s, -1)) }

// sopsRecipients reads the age recipients from an encrypted registry's sops
// metadata: the people the data key is wrapped to.
func sopsRecipients(s string) []string {
	var out []string
	for _, m := range sopsRecipientRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return uniq(out)
}

// topLevel returns the block of a YAML document under a top-level key, up to
// the next top-level key. nushell writes sops configs with `to yaml`, and
// carbon-migrate only needs two keys from them, so this is not a general
// YAML parser.
func topLevel(doc, key string) (string, bool) {
	lines := strings.Split(doc, "\n")
	for i, l := range lines {
		if strings.TrimRight(l, " \t\r") == key+":" || strings.HasPrefix(l, key+": ") {
			var b strings.Builder
			b.WriteString(strings.TrimPrefix(l, key+":"))
			b.WriteByte('\n')
			for _, m := range lines[i+1:] {
				if m != "" && m[0] != ' ' && m[0] != '-' && m[0] != '#' {
					break
				}
				b.WriteString(m)
				b.WriteByte('\n')
			}
			return b.String(), true
		}
	}
	return "", false
}

func creationRules(doc string) string { s, _ := topLevel(doc, "creation_rules"); return s }

// parseUsers reads `users:` (a sequence of {name, key} mappings) from a sops
// config.
func parseUsers(doc string) []User {
	block, ok := topLevel(doc, "users")
	if !ok {
		return nil
	}
	var out []User
	var cur *User
	flush := func() {
		if cur != nil && (cur.Name != "" || cur.Key != "") {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, l := range strings.Split(block, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || t == "[]" {
			continue
		}
		if rest, ok := strings.CutPrefix(t, "- "); ok {
			flush()
			cur = &User{}
			t = strings.TrimSpace(rest)
		} else if strings.HasPrefix(t, "-") && t == "-" {
			flush()
			cur = &User{}
			continue
		}
		if cur == nil {
			continue
		}
		// Flow mapping: {name: a, key: b}
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			for _, kv := range strings.Split(t[1:len(t)-1], ",") {
				setUserField(cur, kv)
			}
			continue
		}
		setUserField(cur, t)
	}
	flush()
	return out
}

func setUserField(u *User, kv string) {
	k, v, ok := strings.Cut(kv, ":")
	if !ok {
		return
	}
	k, v = strings.TrimSpace(k), unquote(strings.TrimSpace(v))
	switch k {
	case "name":
		u.Name = v
	case "key":
		u.Key = v
	}
}

func unquote(s string) string {
	if len(s) >= 2 {
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
		if s[0] == '"' && s[len(s)-1] == '"' {
			r := strings.NewReplacer(`\"`, `"`, `\\`, `\`)
			return r.Replace(s[1 : len(s)-1])
		}
	}
	return s
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
