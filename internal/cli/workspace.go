package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/pins"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/store"
)

// Workspace is the carbon workspace a command runs in. Its root is the git
// repository's top level, which is what makes trunk paths line up.
type Workspace struct {
	Root   string // absolute
	Repo   *gitx.Repo
	Config *config.Workspace

	packages map[string]*config.Package
}

// Workspace finds the workspace for the current directory: the root
// carbon.toml of the enclosing git repository. Every carbon.toml from the
// current directory up to the root is checked for the 0.0.3 format first,
// so a 0.0.3 repository always gets the migration error.
func (c *Context) Workspace() (*Workspace, error) {
	if c.ws != nil {
		return c.ws, nil
	}
	repo, err := gitx.Find(c.Cwd)
	if err != nil {
		return nil, err
	}
	if err := checkLegacyUpward(c.Cwd, repo.Root); err != nil {
		return nil, err
	}
	ws, err := config.LoadWorkspace(config.DirSource{Root: repo.Root})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &Error{Code: ExitNotFound, Message: "this repository has no carbon workspace",
			Details: []string{"There is no carbon.toml at " + repo.Root + "."},
			Hint:    "To start one:   carbon init"}
	}
	if err != nil {
		return nil, err
	}
	c.ws = &Workspace{Root: repo.Root, Repo: repo, Config: ws}
	return c.ws, nil
}

func checkLegacyUpward(dir, root string) error {
	for {
		p := filepath.Join(dir, config.FileName)
		if data, err := os.ReadFile(p); err == nil {
			rel, _ := filepath.Rel(root, p)
			if _, _, err := config.ParseFile(filepath.ToSlash(rel), data); err != nil {
				var le *config.LegacyError
				if errors.As(err, &le) {
					return err
				}
			}
		}
		if dir == root || dir == filepath.Dir(dir) {
			return nil
		}
		dir = filepath.Dir(dir)
	}
}

// Packages returns every package in the working tree, by name.
func (w *Workspace) Packages() (map[string]*config.Package, error) {
	if w.packages == nil {
		pkgs, err := config.LoadPackages(config.DirSource{Root: w.Root}, w.Config)
		if err != nil {
			return nil, err
		}
		w.packages = pkgs
	}
	return w.packages, nil
}

// Dir returns a package's absolute directory.
func (w *Workspace) Dir(p *config.Package) string { return scope.PackageDir(w.Root, p.Dir) }

// Rel renders an absolute path relative to the workspace root, for
// messages.
func (w *Workspace) Rel(abs string) string {
	if r, err := filepath.Rel(w.Root, abs); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return abs
}

// Package resolves the package: --package, else the nearest carbon.toml
// with a name at or above the current directory (within the workspace).
func (c *Context) Package(w *Workspace) (*config.Package, error) {
	pkgs, err := w.Packages()
	if err != nil {
		return nil, err
	}
	if name := c.Global.Package; name != "" {
		if p, ok := pkgs[name]; ok {
			return p, nil
		}
		return nil, &Error{Code: ExitNotFound, Message: fmt.Sprintf("no package named %q", name),
			Hint: "Run `carbon ls` inside a package, or check the name in its carbon.toml."}
	}
	dir := c.Cwd
	for {
		rel, err := filepath.Rel(w.Root, dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			break
		}
		file := filepath.ToSlash(filepath.Join(rel, config.FileName))
		for _, p := range pkgs {
			if p.File == file {
				return p, nil
			}
		}
		if dir == w.Root {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil, &Error{Code: ExitNotFound, Message: "not inside a package",
		Details: []string{"No carbon.toml with a name was found from " + c.Cwd + " up to the workspace root."},
		Hint:    "cd into a package, pass --package <name>, or create one here with `carbon init`."}
}

// EnvUseFile is where `carbon env use` stores the worktree's environment:
// carbon-env inside the worktree's git directory, so it is per worktree and
// cannot be committed.
func EnvUseFile(repo *gitx.Repo) (string, error) {
	gd, err := repo.GitDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(gd, "carbon-env"), nil
}

// ReadEnvUse returns the environment chosen with `carbon env use`, or "".
func ReadEnvUse(repo *gitx.Repo) (string, error) {
	p, err := EnvUseFile(repo)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

// Environment resolves the environment: --env, CARBON_ENV, `carbon env
// use`, then default_environment. An unknown name is a usage error.
func (c *Context) Environment(w *Workspace) (string, error) {
	env, from := c.Global.Env, "--env"
	if env == "" {
		env, from = c.Getenv("CARBON_ENV"), "CARBON_ENV"
	}
	if env == "" {
		used, err := ReadEnvUse(w.Repo)
		if err != nil {
			return "", err
		}
		env, from = used, "`carbon env use`"
	}
	if env == "" {
		return w.Config.DefaultEnvironment, nil
	}
	if !w.Config.HasEnvironment(env) {
		return "", &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown environment %q (from %s)", env, from),
			Hint: "Environments in this workspace: " + strings.Join(w.Config.Environments, ", ")}
	}
	return env, nil
}

// TrunkPolicy reads policy from trunk, with the bootstrap and
// trunk = "worktree" exceptions, and prints the bootstrap notice on stderr.
// Use it for anything that wraps keys or writes drops.
func (c *Context) TrunkPolicy(w *Workspace) (*policy.Policy, error) {
	if c.trunkPol != nil {
		return c.trunkPol, nil
	}
	p, err := policy.LoadTrunkWith(w.Repo, c.Getenv)
	if err != nil {
		return nil, err
	}
	if p.Notice != "" {
		c.Notice("%s", p.Notice)
	}
	c.trunkPol = p
	return p, nil
}

// WorktreePolicy reads policy from the working tree (who, access, status,
// run, and messages).
func (c *Context) WorktreePolicy(w *Workspace) (*policy.Policy, error) {
	return policy.LoadWorktree(w.Root)
}

// IdentityPath is the identity file: CARBON_IDENTITY_FILE, else
// $XDG_CONFIG_HOME/carbon/identity, else ~/.config/carbon/identity.
func (c *Context) IdentityPath() string {
	if p := c.Getenv("CARBON_IDENTITY_FILE"); p != "" {
		return p
	}
	base := c.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(c.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "carbon", "identity")
}

// Identities loads the caller's identities from CARBON_IDENTITY (content)
// or the identity file. With required, a missing identity is an exit-6
// error; otherwise it returns nil. A passphrase-protected file prompts on
// the terminal, and is an exit-6 error without one.
func (c *Context) Identities(required bool) ([]agewrap.Identity, error) {
	var data []byte
	source := "CARBON_IDENTITY"
	if v := c.Getenv("CARBON_IDENTITY"); v != "" {
		data = []byte(v)
	} else {
		source = c.IdentityPath()
		b, err := os.ReadFile(source)
		if errors.Is(err, fs.ErrNotExist) {
			if !required {
				return nil, nil
			}
			return nil, &Error{Code: ExitNoIdentity, Message: "you have no carbon identity on this device",
				Details: []string{"Looked for " + source + " and the CARBON_IDENTITY variable."},
				Hint:    "To create one:   carbon join"}
		}
		if err != nil {
			return nil, err
		}
		data = b
	}
	defer clear(data)
	var pass func() (string, error)
	if c.StdinIsTerminal {
		pass = func() (string, error) { return c.ReadPassphrase("Passphrase for "+source+": ", false) }
	}
	ids, err := agewrap.ParseIdentityFile(data, pass)
	if errors.Is(err, agewrap.ErrPassphraseRequired) {
		return nil, &Error{Code: ExitNoIdentity, Message: "your identity is passphrase-protected and there is no terminal to ask",
			Hint: "Run the command from a terminal, or supply the identity's content in CARBON_IDENTITY."}
	}
	if err != nil {
		if errors.Is(err, agewrap.ErrBadPassphrase) {
			return nil, AsError(err)
		}
		return nil, &Error{Code: ExitNoIdentity, Message: "cannot read your identity from " + source, Details: []string{err.Error()}, Err: err}
	}
	return ids, nil
}

// Me returns the devices in pol whose keys match ids.
func Me(pol *policy.Policy, ids []agewrap.Identity) []policy.Device {
	var out []policy.Device
	for _, id := range ids {
		if d, ok := pol.Identify(id.Recipient); ok {
			out = append(out, d)
		}
	}
	return out
}

// DeviceIDs returns the ids of devices.
func DeviceIDs(ds []policy.Device) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.ID
	}
	return out
}

// LoadScope loads a package's scope from the working tree.
func (c *Context) LoadScope(w *Workspace, p *config.Package, env string) (*scope.Scope, error) {
	return scope.Load(w.Dir(p), p.Name, env)
}

// OpenScope opens a scope for reading with the caller's identities and
// turns the failure cases into the design's errors: no key yet (exit 5),
// not a reader (exit 3, explaining who reads it and how to ask), no
// identity (exit 6).
func (c *Context) OpenScope(w *Workspace, p *config.Package, s *scope.Scope) (*scope.Opened, error) {
	if !s.HasKey() {
		return nil, &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s has no secrets yet", s.Name()),
			Hint: fmt.Sprintf("To set one:   carbon set <name> --env %s", s.Env)}
	}
	ids, err := c.Identities(true)
	if err != nil {
		return nil, err
	}
	pol, err := c.WorktreePolicy(w)
	if err != nil {
		return nil, err
	}
	me := Me(pol, ids)
	o, err := s.Open(ids, DeviceIDs(me)...)
	if errors.Is(err, scope.ErrNotReader) {
		return nil, c.NoAccessErr(pol, p.Name, s.Env, me, s.SlotIDs())
	}
	if err != nil {
		return nil, err
	}
	if err := c.VerifyTrunk(w, p, o); err != nil {
		o.Close()
		return nil, err
	}
	return o, nil
}

// VerifyTrunk checks an opened scope against trunk's keys file with
// scope.Opened.VerifyTrunk, when trunk is a ref that has one, and turns a
// failure into an error with the fix. It then checks the reader's pin
// for the scope (scope.Opened.CheckPin; pins in <git common dir>/carbon) and
// moves it forward when the key legitimately changed. Every path that opens a scope to read
// or seal must call it (OpenScope does).
func (c *Context) VerifyTrunk(w *Workspace, p *config.Package, o *scope.Opened) error {
	trunk, err := c.verifyTrunkKeys(w, p, o)
	if err != nil {
		return err
	}
	return c.checkPin(w, p, o, trunk)
}

// verifyTrunkKeys is the trunk half of VerifyTrunk. It returns trunk's keys
// file for the scope (nil when trunk is not a ref or has none).
func (c *Context) verifyTrunkKeys(w *Workspace, p *config.Package, o *scope.Opened) (*store.Keys, error) {
	pol, err := c.TrunkPolicy(w)
	if err != nil {
		return nil, err
	}
	if pol.Origin != policy.OriginTrunk {
		return nil, nil
	}
	keys, err := c.TrunkKeys(w, pol, p, o.Env)
	if err != nil {
		return nil, err
	}
	err = o.VerifyTrunk(keys)
	if errors.Is(err, scope.ErrNotFromTrunk) {
		rel := w.Rel(o.KeysPath())
		return nil, &Error{Code: ExitError, Err: err,
			Message: fmt.Sprintf("the key for %s on this branch does not descend from trunk's", o.Name()),
			Details: []string{err.Error(), "carbon will not read or seal under a key that trunk did not lead to."},
			Hint: fmt.Sprintf("Restore the keys file from trunk:   git checkout %s -- %s\nor bring this branch up to date:   git merge %s",
				pol.Ref, rel, pol.Ref)}
	}
	return keys, err
}

// LoadPins loads this clone's pins file (<git common dir>/carbon/pins.toml).
// A corrupt file is an error naming the file and the fix.
func (c *Context) LoadPins(w *Workspace) (*pins.File, error) {
	path, err := pins.Path(w.Repo)
	if err != nil {
		return nil, err
	}
	f, err := pins.Load(path)
	var ce *pins.CorruptError
	if errors.As(err, &ce) {
		return nil, &Error{Code: ExitError, Err: err, Message: ce.Error(),
			Details: []string{"It holds the last scope key you verified for each scope in this clone."},
			Hint:    "Delete it; carbon re-pins each scope the next time you open it:   rm " + path}
	}
	return f, err
}

// checkPin applies scope.Opened.CheckPin with the pin of the identities
// that opened o, and stores the new pin when it moves.
func (c *Context) checkPin(w *Workspace, p *config.Package, o *scope.Opened, trunk *store.Keys) error {
	ids := o.Identities()
	if len(ids) == 0 {
		return nil
	}
	f, err := c.LoadPins(w)
	if err != nil {
		return err
	}
	reader := pins.ReaderID(ids)
	pin, _ := f.Get(reader, o.Name())
	next, err := o.CheckPin(pin, trunk)
	var pe *scope.PinError
	if errors.As(err, &pe) {
		rel := w.Rel(o.KeysPath())
		return &Error{Code: ExitError, Err: err,
			Message: fmt.Sprintf("the key for %s was replaced by someone who did not hold the previous key (or your pin is stale)", o.Name()),
			Details: []string{
				fmt.Sprintf("Pinned key:  %s (the last key you verified in this clone)", pe.PinnedID),
				fmt.Sprintf("Current key: %s (%s)", pe.CurrentID, pe.Reason),
				"carbon will not read or seal under it.",
			},
			Hint: fmt.Sprintf("Investigate the commit that changed it:   git log -p -- %s\nIf the change is known to be legitimate (for example the scope was re-created):   carbon trust %s --env %s",
				rel, p.Name, o.Env)}
	}
	if err != nil || next == nil {
		return err
	}
	f.Set(reader, o.Name(), *next)
	return f.Save()
}

// RecordPin pins o's current key for the holder of ids (o.Identities() when
// ids is nil). Call it after Scope.Save when the caller created the scope's
// key, or after a rotation it performed is saved, so its own new key is not
// later mistaken for a replacement.
func (c *Context) RecordPin(w *Workspace, o *scope.Opened, ids []agewrap.Identity) error {
	if ids == nil {
		ids = o.Identities()
	}
	if len(ids) == 0 {
		return nil
	}
	f, err := c.LoadPins(w)
	if err != nil {
		return err
	}
	f.Set(pins.ReaderID(ids), o.Name(), o.CurrentPin())
	return f.Save()
}

// RenamePins moves every reader's pin from oldScope to newScope
// ("<package>/<env>") in this clone, for `rename`.
func (c *Context) RenamePins(w *Workspace, oldScope, newScope string) error {
	f, err := c.LoadPins(w)
	if err != nil {
		return err
	}
	if f.Rename(oldScope, newScope) {
		return f.Save()
	}
	return nil
}

// NoAccessErr builds the "you cannot read <package> in <env>" error: who
// reads the scope, who you are, and the next command.
func (c *Context) NoAccessErr(pol *policy.Policy, pkg, env string, me []policy.Device, slots []string) *Error {
	name := config.ScopeName(pkg, env)
	e := &Error{Code: ExitNoAccess, Message: fmt.Sprintf("you cannot read %s in %s", pkg, env)}
	sa, err := pol.Scope(pkg, env)
	if err == nil {
		if len(sa.Readers) == 0 {
			e.Details = append(e.Details, name+" has no readers in policy.")
		} else {
			e.Details = append(e.Details, fmt.Sprintf("%s is readable by %s.", name, joinAnd(sa.Readers)))
		}
	}
	switch {
	case len(me) == 0:
		e.Details = append(e.Details, "Your identity is not in .carbon/people or .carbon/machines.")
		e.Hint = "To add yourself:   carbon join"
	default:
		d := me[0]
		who := d.ID
		if !d.Machine {
			who = d.Person
			if teams := pol.TeamsOf(d.Person); len(teams) > 0 {
				for i := range teams {
					teams[i] = "@" + teams[i]
				}
				who += ", a member of " + joinAnd(teams)
			}
		}
		e.Details = append(e.Details, fmt.Sprintf("You are %s.", who))
		if sa != nil && sa.Readable(DeviceIDs(me)...) {
			e.Details = append(e.Details, "Policy names you, but your device has no slot yet: a reader has not run `carbon apply` since.")
			e.Hint = "Ask a current reader of " + name + " to run:   carbon apply"
		} else {
			e.Hint = fmt.Sprintf("To ask for access:   carbon request %s --env %s", pkg, env)
		}
	}
	return e
}

func joinAnd(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " and " + xs[1]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + ", and " + xs[len(xs)-1]
}

// TrunkKeys reads a scope's keys file from trunk when pol came from trunk,
// using the package's directory at trunk if it moved. For bootstrap and
// trunk = "worktree" policies it returns the working tree's file instead,
// as the contract's exceptions say. It returns nil when there is none.
func (c *Context) TrunkKeys(w *Workspace, pol *policy.Policy, p *config.Package, env string) (*store.Keys, error) {
	if pol.Origin != policy.OriginTrunk {
		return store.ReadKeys(store.KeysPath(w.Dir(p), env))
	}
	dir := p.Dir
	if tp, ok := pol.Packages[p.Name]; ok {
		dir = tp.Dir
	}
	return scope.ReadKeysAt(w.Repo.Source(pol.Ref), dir, env)
}
