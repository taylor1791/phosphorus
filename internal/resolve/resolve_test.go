package resolve

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/scope"
)

const secretMarker = "SECRETVALUE"

type fakeScope struct {
	pkg    string
	values map[string]string
	drops  map[string]bool
	stale  map[string]bool
	err    map[string]error
	closed bool
}

func (f *fakeScope) Reveal(name string) (*scope.Value, error) {
	if err := f.err[name]; err != nil {
		return nil, err
	}
	v, ok := f.values[name]
	if !ok {
		return nil, fmt.Errorf("%s %s: %w", f.pkg, name, scope.ErrNotFound)
	}
	return &scope.Value{Name: name, Bytes: []byte(v), Drop: f.drops[name], Stale: f.stale[name]}, nil
}

func (f *fakeScope) Close() { f.closed = true }

type world struct {
	pkgs   map[string]*config.Package
	scopes map[string]*fakeScope
	denied map[string]error
	opens  map[string]int
	env    map[string]string
}

func newWorld() *world {
	w := &world{
		pkgs:   map[string]*config.Package{},
		scopes: map[string]*fakeScope{},
		denied: map[string]error{},
		opens:  map[string]int{},
		env:    map[string]string{"AWS_PROFILE": "dev-profile", "EMPTY": ""},
	}
	w.pkgs["checkout"] = &config.Package{
		Name: "checkout", File: "services/checkout/carbon.toml",
		Secrets: map[string]config.Secret{
			"session_key": {}, "stripe_api_key": {}, "unset_one": {}, "own_private": {Private: true},
			"both": {}, "nul": {}, "broken": {},
		},
		Vars: map[string]map[string]string{
			"public_url": {"dev": "http://localhost:3000", "prod": "https://checkout.example.com"},
			"region":     {"default": "us-east-1", "prod": "eu-west-1"},
			"only_prod":  {"prod": "x"},
			"both":       {"default": "v"},
		},
		Env: map[string]string{},
	}
	w.pkgs["db"] = &config.Package{
		Name: "db", File: "services/db/carbon.toml",
		Secrets: map[string]config.Secret{"password": {}, "root_password": {Private: true}},
		Vars:    map[string]map[string]string{"host": {"default": "db.internal"}},
		Env:     map[string]string{},
	}
	w.scopes["checkout"] = &fakeScope{pkg: "checkout", values: map[string]string{
		"session_key": secretMarker + "-session", "stripe_api_key": secretMarker + "-stripe",
		"own_private": secretMarker + "-private", "nul": "a\x00b",
	}, drops: map[string]bool{"stripe_api_key": true}, stale: map[string]bool{"session_key": true},
		err: map[string]error{"broken": fmt.Errorf("checkout/dev broken: value %w: it was edited", scope.ErrTampered)}}
	w.scopes["db"] = &fakeScope{pkg: "db", values: map[string]string{
		"password": secretMarker + "-db", "root_password": secretMarker + "-root"}}
	return w
}

func (w *world) resolver(env string) *Resolver {
	return &Resolver{
		Env:      env,
		Packages: w.pkgs,
		Getenv: func(k string) (string, bool) {
			v, ok := w.env[k]
			return v, ok
		},
		Open: func(p *config.Package) (Values, error) {
			w.opens[p.Name]++
			if err := w.denied[p.Name]; err != nil {
				return nil, err
			}
			s, ok := w.scopes[p.Name]
			if !ok {
				return nil, fmt.Errorf("no scope %s", p.Name)
			}
			return s, nil
		},
	}
}

func TestTemplateForms(t *testing.T) {
	cases := []struct {
		env, tmpl, want string
	}{
		{"dev", "plain", "plain"},
		{"dev", "", ""},
		{"dev", "${session_key}", secretMarker + "-session"},
		{"dev", "${public_url}", "http://localhost:3000"},
		{"prod", "${public_url}", "https://checkout.example.com"},
		{"dev", "${region}", "us-east-1"},
		{"prod", "${region}", "eu-west-1"},
		{"dev", "${db.password}", secretMarker + "-db"},
		{"dev", "${db.host}", "db.internal"},
		{"dev", "postgres://checkout:${db.password}@${db.host}:5432/checkout", "postgres://checkout:" + secretMarker + "-db@db.internal:5432/checkout"},
		{"dev", "${env:AWS_PROFILE}", "dev-profile"},
		{"dev", "x${env:EMPTY}y", "xy"},
		{"staging", "${carbon.env}", "staging"},
		{"dev", "$$", "$"},
		{"dev", "$${session_key}", "${session_key}"},
		{"dev", "cost: $$5 in ${carbon.env}", "cost: $5 in dev"},
		{"dev", "${checkout.session_key}", secretMarker + "-session"},
		{"dev", "${own_private}", secretMarker + "-private"},
		{"dev", "${checkout.own_private}", secretMarker + "-private"},
	}
	for _, c := range cases {
		w := newWorld()
		r := w.resolver(c.env)
		got, err := r.Template(w.pkgs["checkout"], "X", c.tmpl)
		if err != nil {
			t.Errorf("%s in %s: %v", c.tmpl, c.env, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s in %s = %q, want %q", c.tmpl, c.env, got, c.want)
		}
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		tmpl string
		kind Kind
		msg  string
	}{
		{"$x", ErrSyntax, "'$' must start"},
		{"${", ErrSyntax, "unterminated"},
		{"${1bad}", ErrSyntax, "not a valid reference"},
		{"${nope.password}", ErrUnknownPackage, "no package named nope"},
		{"${missing}", ErrUndeclared, "checkout declares no secret or var named missing"},
		{"${db.missing}", ErrUndeclared, "db declares no secret or var named missing"},
		{"${both}", ErrAmbiguous, "both a secret and a var"},
		{"${only_prod}", ErrNoVarValue, "no value for dev and no default"},
		{"${unset_one}", ErrUnset, "checkout/dev unset_one is not set"},
		{"${db.root_password}", ErrPrivate, "db.root_password is private to db"},
		{"${env:NOT_SET}", ErrEnvUnset, "NOT_SET is not set"},
		{"${nul}", ErrNUL, "NUL byte"},
		{"${broken}", ErrReveal, "failed authentication"},
	}
	for _, c := range cases {
		w := newWorld()
		r := w.resolver("dev")
		_, err := r.Template(w.pkgs["checkout"], "MY_VAR", c.tmpl)
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("%s: want *Error, got %v", c.tmpl, err)
			continue
		}
		if e.Kind != c.kind {
			t.Errorf("%s: kind %d, want %d (%v)", c.tmpl, e.Kind, c.kind, err)
		}
		if !strings.Contains(err.Error(), c.msg) || !strings.HasPrefix(err.Error(), "MY_VAR") {
			t.Errorf("%s: error %q does not contain %q", c.tmpl, err, c.msg)
		}
		if e.Var != "MY_VAR" || e.Env != "dev" || e.Template != c.tmpl {
			t.Errorf("%s: error fields %+v", c.tmpl, e)
		}
		if strings.Contains(err.Error()+e.Hint, secretMarker) {
			t.Errorf("%s: error leaks a secret value: %v / %s", c.tmpl, err, e.Hint)
		}
		if c.kind == ErrPrivate && w.opens["db"] != 0 {
			t.Errorf("a private reference opened the provider's scope")
		}
	}
}

func TestOpenErrorIsWrappedAndOpenedOnce(t *testing.T) {
	w := newWorld()
	denied := errors.New("you cannot read db in dev")
	w.denied["db"] = denied
	w.pkgs["checkout"].Env = map[string]string{
		"A": "${db.password}", "B": "${db.password}", "C": "${db.host}",
	}
	r := w.resolver("dev")
	_, err := r.Resolve(w.pkgs["checkout"])
	if !errors.Is(err, denied) {
		t.Fatalf("want the open error wrapped, got %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrOpen || e.Package != "db" || e.Var != "A" {
		t.Fatalf("error %+v", e)
	}
	// A second resolution with the same resolver does not retry the open.
	r.Template(w.pkgs["checkout"], "B", "${db.password}")
	if w.opens["db"] != 1 {
		t.Fatalf("db opened %d times", w.opens["db"])
	}
}

func TestResolveOpensEachScopeOnceAndReportsUse(t *testing.T) {
	w := newWorld()
	w.pkgs["checkout"].Env = map[string]string{
		"SESSION_KEY":    "${session_key}",
		"SESSION_AGAIN":  "${session_key}${session_key}",
		"STRIPE_API_KEY": "${stripe_api_key}",
		"DATABASE_URL":   "postgres://checkout:${db.password}@${db.host}/x",
		"DB_PASSWORD":    "${db.password}",
		"PUBLIC_URL":     "${public_url}",
		"lower_case":     "${carbon.env}",
	}
	r := w.resolver("dev")
	res, err := r.Resolve(w.pkgs["checkout"])
	if err != nil {
		t.Fatal(err)
	}
	if w.opens["checkout"] != 1 || w.opens["db"] != 1 {
		t.Fatalf("opens: %v", w.opens)
	}
	var names []string
	for _, v := range res.Vars {
		names = append(names, v.Name)
	}
	if got := strings.Join(names, ","); got != "DATABASE_URL,DB_PASSWORD,PUBLIC_URL,SESSION_AGAIN,SESSION_KEY,STRIPE_API_KEY,lower_case" {
		t.Fatalf("vars %s", got)
	}
	m := res.Map()
	if m["SESSION_AGAIN"] != secretMarker+"-session"+secretMarker+"-session" || m["lower_case"] != "dev" {
		t.Fatalf("values %v", m)
	}
	want := []Use{
		{Package: "checkout", Name: "session_key", Stale: true},
		{Package: "checkout", Name: "stripe_api_key", Drop: true},
		{Package: "db", Name: "password"},
	}
	if fmt.Sprint(res.Used) != fmt.Sprint(want) {
		t.Fatalf("used %v, want %v", res.Used, want)
	}
	res.Zero()
	for _, v := range res.Vars {
		for _, b := range v.Value {
			if b != 0 {
				t.Fatalf("%s not zeroed", v.Name)
			}
		}
	}
	r.Close()
	if !w.scopes["checkout"].closed || !w.scopes["db"].closed {
		t.Fatal("scopes not closed")
	}
}

func TestVarsOnlyNeverOpenAScope(t *testing.T) {
	w := newWorld()
	w.pkgs["checkout"].Env = map[string]string{"URL": "${public_url}", "HOST": "${db.host}", "E": "${carbon.env}"}
	w.denied["checkout"] = errors.New("denied")
	w.denied["db"] = errors.New("denied")
	if _, err := w.resolver("prod").Resolve(w.pkgs["checkout"]); err != nil {
		t.Fatal(err)
	}
	if len(w.opens) != 0 {
		t.Fatalf("opened %v", w.opens)
	}
}

func TestResolveErrorZeroesNothingLeaks(t *testing.T) {
	w := newWorld()
	w.pkgs["checkout"].Env = map[string]string{"A": "${session_key}", "B": "${env:NOPE}"}
	res, err := w.resolver("dev").Resolve(w.pkgs["checkout"])
	if res != nil || err == nil {
		t.Fatalf("want an error, got %v %v", res, err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatal("error leaks a value")
	}
}
