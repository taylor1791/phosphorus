package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/store"
)

// State is everything the audit reads, loaded once: the working tree's
// policy (loaded tolerantly, so one broken file is a finding rather than the
// end of the run), trunk's policy, and every scope's files in the working
// tree and at trunk.
type State struct {
	Root      string
	Repo      *gitx.Repo
	Workspace *config.Workspace
	// Worktree is the working tree's policy. Files that did not parse are
	// left out and reported.
	Worktree *policy.Policy
	// Trunk is the policy the slot rules use: trunk's, or the working
	// tree's under the bootstrap and "worktree"-trunk exceptions (see
	// Origin). Nil when trunk could not be read.
	Trunk *policy.Policy
	// Scopes is every working-tree package in every workspace environment,
	// ordered by package name, then environment in workspace order.
	Scopes []*ScopeFiles
	// Removed are scopes trunk has keys for that the working tree no longer
	// has (package or environment removed).
	Removed []RemovedScope
	// Orphans are keys and secrets files that belong to no working-tree
	// scope, as slash paths.
	Orphans []string

	// TrunkRef is how this clone chose its trunk (CARBON_TRUNK, git config,
	// remote default); nil when it could not choose one (TrunkErr).
	TrunkRef *policy.Trunk
	// TrunkErr is set when no trunk can be resolved: a *policy.NoTrunkError,
	// a *policy.TrunkMissingError, or an invalid override. Slot and key
	// rules are then skipped; `check` fails on it.
	TrunkErr error

	trunkSrc     *gitx.RefSource
	badDirs      []string // package directories whose carbon.toml did not parse
	loadFindings []Finding
}

// ScopeFiles is one scope's keys and secrets files.
type ScopeFiles struct {
	Package *config.Package
	Env     string
	// Keys is the working tree's keys file; nil when there is none (or it
	// did not parse: BadKeys).
	Keys *store.Keys
	// Secrets is the working tree's secrets file, empty when missing (or
	// when it did not parse: BadSecrets).
	Secrets *store.Secrets
	// TrunkKeys is the keys file at trunk, when policy came from trunk and
	// the file exists there.
	TrunkKeys *store.Keys
	// TrunkSecrets is the secrets file at trunk, under the same condition.
	TrunkSecrets *store.Secrets
	KeysFile     string // slash path relative to the root
	SecretFile   string

	BadKeys, BadSecrets bool
}

// Name is "<package>/<env>".
func (sf *ScopeFiles) Name() string { return config.ScopeName(sf.Package.Name, sf.Env) }

// Scope returns the files for one scope, or nil.
func (s *State) Scope(pkg, env string) *ScopeFiles {
	for _, sf := range s.Scopes {
		if sf.Package.Name == pkg && sf.Env == env {
			return sf
		}
	}
	return nil
}

// TrunkIsReviewed reports whether slot rules compare with a reviewed trunk
// ref (false under bootstrap and "worktree"-trunk, or when trunk could not
// be read).
func (s *State) TrunkIsReviewed() bool {
	return s.Trunk != nil && s.Trunk.Origin == policy.OriginTrunk
}

// Load reads the workspace at repo's root, choosing trunk with getenv (for
// CARBON_TRUNK; usually os.Getenv). Only an unreadable root carbon.toml (or
// a failing git) is an error; a trunk that cannot be resolved is TrunkErr,
// and every other problem becomes a finding returned by [State.Check].
func Load(repo *gitx.Repo, getenv func(string) string) (*State, error) {
	src := config.DirSource{Root: repo.Root}
	ws, err := config.LoadWorkspace(src)
	if err != nil {
		return nil, err
	}
	st := &State{Root: repo.Root, Repo: repo, Workspace: ws}
	pkgs, err := st.loadPackages(src, ws)
	if err != nil {
		return nil, err
	}
	people, machines, teams, err := st.loadPrincipals(src)
	if err != nil {
		return nil, err
	}
	st.Worktree = &policy.Policy{Origin: policy.OriginWorktree, Workspace: ws,
		Packages: pkgs, People: people, Machines: machines, Teams: teams}
	if err := st.loadTrunk(getenv); err != nil {
		return nil, err
	}
	st.loadScopes()
	return st, nil
}

func (s *State) add(f Finding) { s.loadFindings = append(s.loadFindings, f) }

// rel turns paths under the root inside a message into relative ones.
func (s *State) rel(msg string) string {
	return strings.ReplaceAll(msg, s.Root+string(filepath.Separator), "")
}

func (s *State) loadPackages(src config.DirSource, ws *config.Workspace) (map[string]*config.Package, error) {
	files, err := src.Find(config.FileName)
	if err != nil {
		return nil, err
	}
	pkgs := map[string]*config.Package{}
	for _, f := range files {
		data, err := src.ReadFile(f)
		if err != nil {
			return nil, err
		}
		fws, p, err := config.ParseFile(f, data)
		if err != nil {
			s.fileError(f, data, err)
			s.badDirs = append(s.badDirs, path.Dir(f))
			continue
		}
		if fws != nil && f != config.FileName {
			s.add(Finding{Severity: Error, Rule: RuleConfigInvalid, File: f,
				Message: f + " has a [workspace] table; only the root carbon.toml may have one.",
				Hint:    "Remove the [workspace] table from " + f + "."})
			continue
		}
		if p == nil {
			continue
		}
		if err := ws.ValidatePackage(p); err != nil {
			s.add(Finding{Severity: Error, Rule: RuleConfigInvalid, File: f, Package: p.Name,
				Message: f + ": " + err.Error(), Hint: "Fix " + f + "."})
			continue
		}
		if prev, ok := pkgs[p.Name]; ok {
			s.add(Finding{Severity: Error, Rule: RuleDuplicatePackage, File: f, Package: p.Name,
				Message: fmt.Sprintf("%s and %s both name a package %q; package names must be unique.", prev.File, f, p.Name),
				Hint:    "Rename one of them (carbon rename re-seals its values under the new name)."})
			continue
		}
		pkgs[p.Name] = p
	}
	return pkgs, nil
}

// fileError turns a carbon.toml parse error into findings, naming bad names
// specifically when it can.
func (s *State) fileError(file string, data []byte, err error) {
	var legacy *config.LegacyError
	var conflict *config.ConflictError
	switch {
	case errors.As(err, &legacy):
		s.add(Finding{Severity: Error, Rule: RuleConfigLegacy, File: file,
			Message: file + " is a carbon 0.0.3 file (it has a [push] or [pull] table); carbon 1.0 cannot read it.",
			Hint:    "Migrate it with carbon-migrate, which converts the files and re-seals every secret."})
		return
	case errors.As(err, &conflict):
		s.add(Finding{Severity: Error, Rule: RuleConfigInvalid, File: file,
			Message: file + " has unresolved git conflict markers.",
			Hint:    "Resolve the conflict by keeping one side of each conflicting line."})
		return
	}
	if names := nameFindings(file, data); len(names) > 0 {
		s.loadFindings = append(s.loadFindings, names...)
		return
	}
	s.add(Finding{Severity: Error, Rule: RuleConfigInvalid, File: file,
		Message: s.rel(err.Error()), Hint: "Fix " + file + "; every command refuses it until then."})
}

// nameFindings reports invalid and reserved names in a carbon.toml that the
// strict parser rejected.
func nameFindings(file string, data []byte) []Finding {
	var loose map[string]any
	if toml.Unmarshal(data, &loose) != nil {
		return nil
	}
	var out []Finding
	bad := func(rule, msg string) {
		out = append(out, Finding{Severity: Error, Rule: rule, File: file, Message: file + ": " + msg,
			Hint: "Rename it in " + file + "."})
	}
	if name, ok := loose["name"].(string); ok {
		for _, r := range config.ReservedPackageNames {
			if name == r {
				bad(RuleNameReserved, fmt.Sprintf("package name %q is reserved (%s are reserved).", name, strings.Join(config.ReservedPackageNames, " and ")))
			}
		}
		if !config.ValidName(name) {
			bad(RuleNameInvalid, fmt.Sprintf("package name %q is invalid: use lower-case letters, digits, '-' and '_', starting with a letter or digit.", name))
		}
	}
	for _, table := range []string{"secrets", "vars", "env"} {
		m, ok := loose[table].(map[string]any)
		if !ok {
			continue
		}
		for _, k := range sortedKeys(m) {
			if !config.ValidSecretName(k) {
				bad(RuleNameInvalid, fmt.Sprintf("[%s] name %q is invalid: use letters, digits and '_', not starting with a digit.", table, k))
			}
		}
	}
	return out
}

func (s *State) loadPrincipals(src config.DirSource) (map[string]*config.Person, map[string]*config.Machine, config.Teams, error) {
	people := map[string]*config.Person{}
	machines := map[string]*config.Machine{}
	each := func(dir, kind string, fn func(file, id string, data []byte) error) error {
		names, err := src.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, n := range names {
			id, ok := strings.CutSuffix(n, ".toml")
			if !ok {
				continue
			}
			file := path.Join(dir, n)
			data, err := src.ReadFile(file)
			if err != nil {
				return err
			}
			if perr := fn(file, id, data); perr != nil {
				rule := RuleConfigInvalid
				if !config.ValidName(id) {
					rule = RuleNameInvalid
				}
				s.add(Finding{Severity: Error, Rule: rule, File: file, Message: s.rel(perr.Error()),
					Hint: fmt.Sprintf("Fix %s; this %s is ignored until then.", file, kind)})
			}
		}
		return nil
	}
	err := each(config.PeopleDir, "person", func(file, id string, data []byte) error {
		p, err := config.ParsePerson(file, id, data)
		if err == nil {
			people[id] = p
		}
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	err = each(config.MachinesDir, "machine", func(file, id string, data []byte) error {
		m, err := config.ParseMachine(file, id, data)
		if err == nil {
			machines[id] = m
		}
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	teams := config.Teams{}
	data, err := src.ReadFile(config.TeamsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, nil, nil, err
	default:
		t, perr := config.ParseTeams(config.TeamsFile, data)
		if perr != nil {
			s.add(Finding{Severity: Error, Rule: RuleConfigInvalid, File: config.TeamsFile, Message: s.rel(perr.Error()),
				Hint: "Fix " + config.TeamsFile + "; teams are ignored until then."})
		} else {
			teams = t
		}
	}
	return people, machines, teams, nil
}

// loadTrunk applies the trunk rules of docs/implementation.md the way
// policy.LoadTrunkAt does, but keeps the tolerant working-tree policy for the
// exceptions and reports an unreadable trunk as a finding. A trunk that
// cannot be chosen or does not resolve is recorded in TrunkErr: check fails
// on it, status carries on without trunk.
func (s *State) loadTrunk(getenv func(string) string) error {
	fromWorktree := func(origin policy.Origin, ref, notice string) {
		c := *s.Worktree
		c.Origin, c.Ref, c.Notice, c.Trunk = origin, ref, notice, s.TrunkRef
		s.Trunk = &c
	}
	t, err := policy.ResolveTrunk(s.Repo, getenv)
	if err != nil {
		s.TrunkErr = err
		return nil
	}
	s.TrunkRef = t
	if t.IsWorktree() {
		fromWorktree(policy.OriginWorktreeTrunk, "", "")
		s.add(Finding{Severity: Warning, Rule: RuleTrunkWorktree,
			Message: fmt.Sprintf("The trunk is \"worktree\" (from %s): policy is read from whatever is checked out, never from a reviewed ref, so any branch can grant itself access when a reader runs carbon apply.", t.From),
			Hint:    "Protect a trunk branch and point this clone at it: unset " + policy.TrunkEnv + " or run `git config " + policy.TrunkConfigKey + " <ref>`."})
		return nil
	}
	bootstrap := func(why string) {
		notice := why + "; policy is read from the working tree until carbon is on trunk."
		fromWorktree(policy.OriginBootstrap, t.Ref, notice)
		hint := "Merge the carbon workspace to trunk."
		if t.Ref != "" {
			hint = "Merge the carbon workspace to " + t.Ref + "."
		}
		s.add(Finding{Severity: Info, Rule: RuleTrunkBootstrap, File: config.FileName,
			Message: "Carbon is not on trunk yet: " + notice + " Slots are compared with the working tree's policy.",
			Hint:    hint})
	}
	if t.From == policy.TrunkFromNone {
		bootstrap(fmt.Sprintf("this repository has no trunk yet (no remote and no %s)", policy.TrunkConfigKey))
		return nil
	}
	ok, err := s.Repo.RefExists(t.Ref)
	if err != nil {
		return err
	}
	if !ok {
		s.TrunkErr = &policy.TrunkMissingError{Ref: t.Ref, From: t.From}
		return nil
	}
	ref := t.Ref
	s.trunkSrc = s.Repo.Source(ref)
	if _, err := s.trunkSrc.ReadFile(config.FileName); errors.Is(err, fs.ErrNotExist) {
		bootstrap(fmt.Sprintf("trunk %s has no %s", ref, config.FileName))
		return nil
	} else if err != nil {
		return err
	}
	p, err := policy.Load(s.trunkSrc)
	if err != nil {
		s.add(Finding{Severity: Error, Rule: RuleTrunkUnreadable, File: ref,
			Message: fmt.Sprintf("Policy on trunk %s cannot be read: %v. Slot and key rules were skipped.", ref, err),
			Hint:    "Fix the policy files on trunk; until then nobody can run `carbon apply`."})
		return nil
	}
	p.Origin, p.Ref, p.Trunk = policy.OriginTrunk, ref, t
	s.Trunk = p
	return nil
}

func (s *State) loadScopes() {
	for _, name := range sortedKeys(s.Worktree.Packages) {
		p := s.Worktree.Packages[name]
		dir := scope.PackageDir(s.Root, p.Dir)
		for _, env := range s.Workspace.Environments {
			sf := &ScopeFiles{Package: p, Env: env, Secrets: store.NewSecrets(),
				KeysFile:   path.Join(p.Dir, config.CarbonDir, env+".keys.toml"),
				SecretFile: path.Join(p.Dir, config.CarbonDir, env+".secrets.toml")}
			sf.KeysFile, sf.SecretFile = path.Clean(sf.KeysFile), path.Clean(sf.SecretFile)
			if k, err := store.ReadKeys(store.KeysPath(dir, env)); err != nil {
				sf.BadKeys = true
				s.storeError(sf, sf.KeysFile, err)
			} else if k != nil && k.Scope != sf.Name() {
				sf.BadKeys = true
				s.add(Finding{Severity: Error, Rule: RuleStoreInvalid, Scope: sf.Name(), Package: p.Name, Env: env, File: sf.KeysFile,
					Message: fmt.Sprintf("%s says scope = %q, but it is %s's keys file: it was copied or moved.", sf.KeysFile, k.Scope, sf.Name()),
					Hint:    "Restore it from git history."})
			} else {
				sf.Keys = k
			}
			if sec, err := store.ReadSecrets(store.SecretsPath(dir, env)); err != nil {
				sf.BadSecrets = true
				s.storeError(sf, sf.SecretFile, err)
			} else {
				sf.Secrets = sec
			}
			if s.TrunkIsReviewed() && s.trunkSrc != nil {
				at := p.Dir
				if tp, ok := s.Trunk.Packages[p.Name]; ok {
					at = tp.Dir
				}
				tk, err := scope.ReadKeysAt(s.trunkSrc, at, env)
				switch {
				case err != nil:
					s.add(Finding{Severity: Error, Rule: RuleTrunkUnreadable, Scope: sf.Name(), Package: p.Name, Env: env,
						Message: fmt.Sprintf("The keys file of %s on trunk cannot be read: %v. Key changes in %s were not checked.", sf.Name(), err, sf.Name()),
						Hint:    "Fix the keys file on trunk."})
				case tk != nil && tk.Scope != sf.Name():
					s.add(Finding{Severity: Error, Rule: RuleTrunkUnreadable, Scope: sf.Name(), Package: p.Name, Env: env,
						Message: fmt.Sprintf("The keys file of %s on trunk says scope = %q.", sf.Name(), tk.Scope),
						Hint:    "Fix the keys file on trunk."})
				default:
					sf.TrunkKeys = tk
				}
				sf.TrunkSecrets = s.trunkSecrets(sf, at, env)
			}
			s.Scopes = append(s.Scopes, sf)
		}
	}
	s.loadRemoved()
	s.loadOrphans()
}

// trunkSecrets reads a scope's secrets file at trunk; nil when absent or
// unreadable (reported).
func (s *State) trunkSecrets(sf *ScopeFiles, dir, env string) *store.Secrets {
	rel := path.Join(dir, config.CarbonDir, env+".secrets.toml")
	data, err := s.trunkSrc.ReadFile(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		var sec *store.Secrets
		if sec, err = store.ParseSecrets(s.trunkSrc.String()+":"+rel, data); err == nil {
			return sec
		}
	}
	s.add(Finding{Severity: Error, Rule: RuleTrunkUnreadable, Scope: sf.Name(), Package: sf.Package.Name, Env: env,
		Message: fmt.Sprintf("The secrets file of %s on trunk cannot be read: %v. Entries in %s were not compared with trunk.", sf.Name(), err, sf.Name()),
		Hint:    "Fix the secrets file on trunk."})
	return nil
}

// RemovedScope is a scope trunk has a keys file for that the working tree no
// longer loads as a scope: its package or environment was removed.
type RemovedScope struct {
	Package, Env string
	// TrunkFile is the keys file's slash path at trunk.
	TrunkFile string
	// StillHere is set when the working tree still has that file.
	StillHere bool
}

// Name is "<package>/<env>".
func (r RemovedScope) Name() string { return config.ScopeName(r.Package, r.Env) }

func (s *State) loadRemoved() {
	if !s.TrunkIsReviewed() || s.trunkSrc == nil {
		return
	}
	for _, name := range sortedKeys(s.Trunk.Packages) {
		tp := s.Trunk.Packages[name]
		for _, env := range s.Trunk.Workspace.Environments {
			if wp, ok := s.Worktree.Packages[name]; ok && s.Workspace.HasEnvironment(env) && wp != nil {
				continue
			}
			tk, err := scope.ReadKeysAt(s.trunkSrc, tp.Dir, env)
			if err != nil || tk == nil {
				continue
			}
			rel := path.Join(tp.Dir, config.CarbonDir, env+".keys.toml")
			_, statErr := os.Stat(filepath.Join(s.Root, filepath.FromSlash(rel)))
			s.Removed = append(s.Removed, RemovedScope{Package: name, Env: env, TrunkFile: rel, StillHere: statErr == nil})
		}
	}
}

// loadOrphans finds keys and secrets files under a .carbon directory that
// belong to no scope of the working tree: an unknown environment, or no
// package in that directory.
func (s *State) loadOrphans() {
	owned := map[string]bool{}
	for _, sf := range s.Scopes {
		owned[sf.KeysFile], owned[sf.SecretFile] = true, true
	}
	filepath.WalkDir(s.Root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			n := e.Name()
			if p != s.Root && (n == ".git" || n == "node_modules" || (strings.HasPrefix(n, ".") && n != config.CarbonDir)) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(filepath.Dir(p)) != config.CarbonDir {
			return nil
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".keys.toml") && !strings.HasSuffix(n, ".secrets.toml") {
			return nil
		}
		rel, rerr := filepath.Rel(s.Root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		pkgDir := path.Dir(path.Dir(rel))
		for _, d := range s.badDirs {
			if d == pkgDir {
				return nil // its carbon.toml is already reported
			}
		}
		if !owned[rel] {
			s.Orphans = append(s.Orphans, rel)
		}
		return nil
	})
}

func (s *State) storeError(sf *ScopeFiles, file string, err error) {
	var conflict *config.ConflictError
	f := Finding{Severity: Error, Rule: RuleStoreInvalid, Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env, File: file}
	if errors.As(err, &conflict) {
		f.Message = file + " has unresolved git conflict markers."
		f.Hint = "Keep one side of each conflicting line; if both sides rotated the key, keep either and run `carbon apply`."
	} else {
		f.Message = s.rel(err.Error())
		f.Hint = "Restore " + file + " from git history; carbon writes it and it is not edited by hand."
	}
	s.add(f)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
