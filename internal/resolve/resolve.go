// Package resolve turns a package's [env] table into concrete process
// variables for one environment: what `carbon run` and `carbon export`
// give a command.
//
// Templates are parsed by [config.ParseTemplate]. The references are:
//
//   - ${name}: this package's secret or var
//   - ${pkg.name}: another package's secret or var; a secret marked
//     private = true is refused
//   - ${env:NAME}: the calling process's environment; an error if unset
//   - ${carbon.env}: the environment name
//   - $$: a literal "$"
//
// Vars are per environment with an optional "default". Secrets are read
// through an [OpenFunc] that the caller supplies, so this package needs no
// identity and knows nothing about policy: the caller decides how a scope is
// opened and what "cannot read" looks like. Each scope is opened at most once
// per [Resolver], whether that succeeds or not.
//
// No error from this package contains a secret value.
package resolve

import (
	"errors"
	"fmt"
	"sort"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// Values is an opened scope: something that reveals stored secrets.
// *scope.Opened satisfies it. Reveal returns an error wrapping
// scope.ErrNotFound for a name with no stored value.
type Values interface {
	Reveal(name string) (*scope.Value, error)
}

// OpenFunc opens the scope of pkg in the resolver's environment. Its error
// is returned to the caller wrapped in an *Error with Kind ErrOpen, so the
// caller can recover its own error type with errors.As.
type OpenFunc func(pkg *config.Package) (Values, error)

// Kind classifies a resolution error.
type Kind int

const (
	// ErrSyntax: the template does not parse.
	ErrSyntax Kind = iota + 1
	// ErrUnknownPackage: ${pkg.name} names a package that does not exist.
	ErrUnknownPackage
	// ErrUndeclared: the package declares no secret or var of that name.
	ErrUndeclared
	// ErrAmbiguous: the name is both a secret and a var.
	ErrAmbiguous
	// ErrNoVarValue: the var has no value for the environment and no default.
	ErrNoVarValue
	// ErrUnset: the secret is declared but has no stored value.
	ErrUnset
	// ErrPrivate: ${pkg.name} names another package's private secret.
	ErrPrivate
	// ErrEnvUnset: ${env:NAME} and NAME is not set.
	ErrEnvUnset
	// ErrOpen: opening the scope failed; Err is the OpenFunc's error.
	ErrOpen
	// ErrReveal: the scope opened but the value did not decrypt.
	ErrReveal
	// ErrNUL: the resolved value contains a NUL byte, which no process
	// environment can hold.
	ErrNUL
	// ErrForbiddenEnv: ${env:NAME} names one of carbon's identity
	// variables, which never leave carbon (whether set or not).
	ErrForbiddenEnv
)

// forbiddenEnv are the variables that carry carbon's identity. They match
// gitx's scrub list: neither a subprocess nor a template may receive them.
var forbiddenEnv = map[string]bool{"CARBON_IDENTITY": true, "CARBON_IDENTITY_FILE": true}

// Error is a resolution failure, naming the [env] entry and the reference.
type Error struct {
	Kind Kind
	// Var is the [env] key being resolved; Template its template; Ref the
	// reference as written ("${db.password}"), empty for whole-value errors.
	Var, Template, Ref string
	// Package is the package the reference points into (for package refs);
	// Name the secret, var or environment variable.
	Package, Name string
	// Env is the environment.
	Env string
	// Msg says what is wrong; Hint is the next step, if any.
	Msg, Hint string
	// Err is the underlying cause (the OpenFunc's error for ErrOpen).
	Err error
}

func (e *Error) Error() string {
	where := e.Var
	if e.Ref != "" {
		where += " (" + e.Ref + ")"
	}
	return where + ": " + e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// Var is one resolved process variable.
type Var struct {
	Name  string
	Value []byte
}

// Use records one secret a resolution read, for notices about drops and
// values under retired keys.
type Use struct {
	Package, Name string
	Drop, Stale   bool
}

// Result is a resolved [env] table.
type Result struct {
	// Vars are sorted by name.
	Vars []Var
	// Used lists each secret read, sorted by package then name.
	Used []Use
}

// Zero overwrites every value.
func (r *Result) Zero() {
	if r == nil {
		return
	}
	for _, v := range r.Vars {
		clear(v.Value)
	}
}

// Map returns the variables as strings, keyed by name.
func (r *Result) Map() map[string]string {
	m := make(map[string]string, len(r.Vars))
	for _, v := range r.Vars {
		m[v.Name] = string(v.Value)
	}
	return m
}

// Resolver resolves [env] tables in one environment.
type Resolver struct {
	// Env is the environment name.
	Env string
	// Packages are the workspace's packages by name.
	Packages map[string]*config.Package
	// Getenv looks up the calling process's environment for ${env:NAME}.
	Getenv func(string) (string, bool)
	// Open opens a scope. It is called at most once per package.
	Open OpenFunc

	opened  map[string]Values
	openErr map[string]error
	values  map[valueKey]*scope.Value
}

type valueKey struct{ pkg, name string }

// Close zeroes every secret held by the resolver and closes opened scopes
// that have a Close method.
func (r *Resolver) Close() {
	for _, v := range r.values {
		v.Zero()
	}
	r.values = nil
	for _, o := range r.opened {
		if c, ok := o.(interface{ Close() }); ok {
			c.Close()
		}
	}
	r.opened = nil
}

// Resolve resolves pkg's [env] table. On error nothing is returned and any
// partial values are zeroed.
func (r *Resolver) Resolve(pkg *config.Package) (*Result, error) {
	names := make([]string, 0, len(pkg.Env))
	for n := range pkg.Env {
		names = append(names, n)
	}
	sort.Strings(names)
	res := &Result{}
	used := map[valueKey]Use{}
	for _, n := range names {
		v, err := r.resolveOne(pkg, n, pkg.Env[n], used)
		if err != nil {
			res.Zero()
			return nil, err
		}
		res.Vars = append(res.Vars, Var{Name: n, Value: v})
	}
	keys := make([]valueKey, 0, len(used))
	for k := range used {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pkg != keys[j].pkg {
			return keys[i].pkg < keys[j].pkg
		}
		return keys[i].name < keys[j].name
	})
	for _, k := range keys {
		res.Used = append(res.Used, used[k])
	}
	return res, nil
}

// Template resolves one template as if it were the [env] entry varName of
// pkg.
func (r *Resolver) Template(pkg *config.Package, varName, tmpl string) ([]byte, error) {
	return r.resolveOne(pkg, varName, tmpl, map[valueKey]Use{})
}

func (r *Resolver) resolveOne(pkg *config.Package, varName, tmpl string, used map[valueKey]Use) ([]byte, error) {
	parts, err := config.ParseTemplate(tmpl)
	if err != nil {
		return nil, &Error{Kind: ErrSyntax, Var: varName, Template: tmpl, Env: r.Env,
			Msg:  err.Error(),
			Hint: fmt.Sprintf("Fix the [env] entry in %s. Write $$ for a literal $.", pkg.File)}
	}
	var out []byte
	fail := func(e *Error) ([]byte, error) {
		clear(out)
		e.Var, e.Template, e.Env = varName, tmpl, r.Env
		return nil, e
	}
	for _, p := range parts {
		if p.Ref == nil {
			out = append(out, p.Literal...)
			continue
		}
		ref := *p.Ref
		switch ref.Kind {
		case config.RefCarbonEnv:
			out = append(out, r.Env...)
		case config.RefEnv:
			if forbiddenEnv[ref.Name] {
				return fail(&Error{Kind: ErrForbiddenEnv, Ref: refString(ref), Name: ref.Name,
					Msg: fmt.Sprintf("%s holds carbon's private key material and cannot be passed on", ref.Name),
					Hint: fmt.Sprintf("Remove %s from the [env] table in %s. A process that needs secrets should get them "+
						"through [env], not carbon's identity.", refString(ref), pkg.File)})
			}
			v, ok := "", false
			if r.Getenv != nil {
				v, ok = r.Getenv(ref.Name)
			}
			if !ok {
				return fail(&Error{Kind: ErrEnvUnset, Ref: refString(ref), Name: ref.Name,
					Msg:  fmt.Sprintf("the environment variable %s is not set", ref.Name),
					Hint: fmt.Sprintf("Set it before running carbon, for example:   export %s=...", ref.Name)})
			}
			out = append(out, v...)
		case config.RefLocal, config.RefPackage:
			target := pkg
			if ref.Kind == config.RefPackage && ref.Package != pkg.Name {
				t, ok := r.Packages[ref.Package]
				if !ok {
					return fail(&Error{Kind: ErrUnknownPackage, Ref: refString(ref), Package: ref.Package, Name: ref.Name,
						Msg:  fmt.Sprintf("there is no package named %s", ref.Package),
						Hint: fmt.Sprintf("Check the name in %s's [env] table against the package's carbon.toml.", pkg.Name)})
				}
				target = t
			}
			b, e := r.lookup(pkg, target, ref, used)
			if e != nil {
				return fail(e)
			}
			out = append(out, b...)
		default:
			return fail(&Error{Kind: ErrSyntax, Ref: refString(ref), Msg: "unknown reference"})
		}
	}
	for _, c := range out {
		if c == 0 {
			return fail(&Error{Kind: ErrNUL, Msg: "the value contains a NUL byte, which a process environment cannot hold",
				Hint: "Store the value base64-encoded and decode it in the program."})
		}
	}
	if out == nil {
		out = []byte{}
	}
	return out, nil
}

// lookup returns the value of a secret or var of target, referenced from
// from. The returned slice must not be retained or modified.
func (r *Resolver) lookup(from, target *config.Package, ref config.Ref, used map[valueKey]Use) ([]byte, *Error) {
	rs := refString(ref)
	decl, isSecret := target.Secrets[ref.Name]
	byEnv, isVar := target.Vars[ref.Name]
	switch {
	case isSecret && isVar:
		return nil, &Error{Kind: ErrAmbiguous, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg:  fmt.Sprintf("%s is both a secret and a var in %s", ref.Name, target.File),
			Hint: "Rename one of them; secrets and vars share one namespace."}
	case isVar:
		if v, ok := byEnv[r.Env]; ok {
			return []byte(v), nil
		}
		if v, ok := byEnv["default"]; ok {
			return []byte(v), nil
		}
		return nil, &Error{Kind: ErrNoVarValue, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg:  fmt.Sprintf("var %s in %s has no value for %s and no default", ref.Name, target.Name, r.Env),
			Hint: fmt.Sprintf("Add %s = \"...\" or default = \"...\" under [vars.%s] in %s.", r.Env, ref.Name, target.File)}
	case !isSecret:
		return nil, &Error{Kind: ErrUndeclared, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg:  fmt.Sprintf("%s declares no secret or var named %s", target.Name, ref.Name),
			Hint: fmt.Sprintf("Declare it under [secrets] or [vars.%s] in %s, or fix the reference.", ref.Name, target.File)}
	}
	if decl.Private && target.Name != from.Name {
		return nil, &Error{Kind: ErrPrivate, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg: fmt.Sprintf("%s.%s is private to %s", target.Name, ref.Name, target.Name),
			Hint: fmt.Sprintf("A secret marked private = true cannot be referenced from another package. "+
				"Remove the reference from %s, or ask %s's owners to drop private = true.", from.File, target.Name)}
	}
	k := valueKey{target.Name, ref.Name}
	if v, ok := r.values[k]; ok {
		used[k] = Use{Package: k.pkg, Name: k.name, Drop: v.Drop, Stale: v.Stale}
		return v.Bytes, nil
	}
	vals, err := r.open(target)
	if err != nil {
		return nil, &Error{Kind: ErrOpen, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg: fmt.Sprintf("cannot open %s: %v", config.ScopeName(target.Name, r.Env), err), Err: err}
	}
	v, err := vals.Reveal(ref.Name)
	if errors.Is(err, scope.ErrNotFound) {
		return nil, &Error{Kind: ErrUnset, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg:  fmt.Sprintf("%s %s is not set", config.ScopeName(target.Name, r.Env), ref.Name),
			Hint: fmt.Sprintf("A reader sets it with:   carbon set %s --package %s --env %s", ref.Name, target.Name, r.Env)}
	}
	if err != nil {
		return nil, &Error{Kind: ErrReveal, Ref: rs, Package: target.Name, Name: ref.Name,
			Msg: err.Error(), Err: err}
	}
	if r.values == nil {
		r.values = map[valueKey]*scope.Value{}
	}
	r.values[k] = v
	used[k] = Use{Package: k.pkg, Name: k.name, Drop: v.Drop, Stale: v.Stale}
	return v.Bytes, nil
}

// open opens target's scope once, remembering failures too.
func (r *Resolver) open(target *config.Package) (Values, error) {
	if v, ok := r.opened[target.Name]; ok {
		return v, nil
	}
	if err, ok := r.openErr[target.Name]; ok {
		return nil, err
	}
	if r.Open == nil {
		return nil, errors.New("no way to open scopes")
	}
	v, err := r.Open(target)
	if err != nil {
		if r.openErr == nil {
			r.openErr = map[string]error{}
		}
		r.openErr[target.Name] = err
		return nil, err
	}
	if r.opened == nil {
		r.opened = map[string]Values{}
	}
	r.opened[target.Name] = v
	return v, nil
}

func refString(ref config.Ref) string {
	switch ref.Kind {
	case config.RefEnv:
		return "${env:" + ref.Name + "}"
	case config.RefCarbonEnv:
		return "${carbon.env}"
	case config.RefPackage:
		return "${" + ref.Package + "." + ref.Name + "}"
	}
	return "${" + ref.Name + "}"
}
