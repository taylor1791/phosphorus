package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/resolve"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// resolvePackageEnv resolves pkg's [env] table in env for run and export.
// The caller zeroes the result with Zero. Identities and working-tree policy
// are loaded once, however many scopes the table references, so a
// passphrase is asked for at most once.
func (c *Context) resolvePackageEnv(w *Workspace, pkg *config.Package, env string) (*resolve.Result, error) {
	pkgs, err := w.Packages()
	if err != nil {
		return nil, err
	}
	op := &scopeOpener{c: c, w: w, env: env}
	r := &resolve.Resolver{
		Env:      env,
		Packages: pkgs,
		Getenv:   c.lookupEnv,
		Open:     op.open,
	}
	defer r.Close()
	res, err := r.Resolve(pkg)
	if err != nil {
		return nil, resolveErr(pkg, err)
	}
	for _, u := range res.Used {
		if u.Drop {
			c.Notice("note: %s %s is a drop, not yet reviewed; a reader's `carbon apply` promotes it.",
				config.ScopeName(u.Package, env), u.Name)
		}
	}
	return res, nil
}

// lookupEnv is the calling process's environment for ${env:NAME}. Context
// only exposes Getenv, which cannot tell empty from unset, so an empty
// answer is checked against the real process environment: a variable set
// to "" is set.
func (c *Context) lookupEnv(name string) (string, bool) {
	if v := c.Getenv(name); v != "" {
		return v, true
	}
	if _, ok := os.LookupEnv(name); ok {
		return "", true
	}
	return "", false
}

type scopeOpener struct {
	c   *Context
	w   *Workspace
	env string

	loaded bool
	ids    []agewrap.Identity
	pol    *policy.Policy
	me     []policy.Device
}

func (o *scopeOpener) open(p *config.Package) (resolve.Values, error) {
	s, err := o.c.LoadScope(o.w, p, o.env)
	if err != nil {
		return nil, err
	}
	if !s.HasKey() {
		// Nothing was ever set here: every reference is "not set".
		return emptyScope{}, nil
	}
	if !o.loaded {
		if o.ids, err = o.c.Identities(true); err != nil {
			return nil, err
		}
		if o.pol, err = o.c.WorktreePolicy(o.w); err != nil {
			return nil, err
		}
		o.me = Me(o.pol, o.ids)
		o.loaded = true
	}
	opened, err := s.Open(o.ids, DeviceIDs(o.me)...)
	if errors.Is(err, scope.ErrNotReader) {
		return nil, o.c.NoAccessErr(o.pol, p.Name, o.env, o.me, s.SlotIDs())
	}
	if err != nil {
		return nil, err
	}
	return opened, nil
}

type emptyScope struct{}

func (emptyScope) Reveal(name string) (*scope.Value, error) {
	return nil, fmt.Errorf("%s: %w", name, scope.ErrNotFound)
}

// resolveErr turns a resolution error into the CLI's error, keeping a
// scope's own error (exit 3 "you cannot read X in Y", exit 6, ...) and
// adding which [env] entry needed it.
func resolveErr(pkg *config.Package, err error) error {
	var re *resolve.Error
	if !errors.As(err, &re) {
		return err
	}
	need := fmt.Sprintf("%s needs it: %s = %q in %s.", pkg.Name, re.Var, re.Template, pkg.File)
	if re.Kind == resolve.ErrOpen || re.Kind == resolve.ErrReveal {
		inner := AsError(re.Err)
		e := *inner
		e.Details = append(append([]string(nil), inner.Details...), need)
		return &e
	}
	code := ExitError
	switch re.Kind {
	case resolve.ErrUnknownPackage, resolve.ErrUndeclared, resolve.ErrUnset:
		code = ExitNotFound
	case resolve.ErrPrivate:
		code = ExitNoAccess
	}
	return &Error{Code: code, Message: re.Msg, Details: []string{need}, Hint: re.Hint, Err: err}
}
