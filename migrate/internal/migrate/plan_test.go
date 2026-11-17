package migrate

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/migrate/internal/legacy"
)

const (
	keyA = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	keyB = "age1pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
)

func svc(t *testing.T, file, body string) *legacy.Service {
	t.Helper()
	s, err := legacy.ParseService(file, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func reg(name string, users ...legacy.User) *legacy.Registry {
	r := &legacy.Registry{Name: name, RegistryFile: legacy.RegistryFile(name), SopsFile: legacy.SopsFile(name), HasRegistry: true, HasSops: true, Users: users}
	for _, u := range users {
		r.Requested = append(r.Requested, u.Key)
		r.Granted = append(r.Granted, u.Key)
	}
	return r
}

func baseInput(services []*legacy.Service, values map[string]legacy.Values, regs ...*legacy.Registry) Input {
	return Input{
		Repo:          &legacy.Repo{Services: services, Registries: regs},
		Values:        values,
		DecryptErrors: map[string]string{},
		Me:            keyA,
		KeyFile:       legacy.PrivateKeyFile,
		MoveKey:       true,
		IdentityPath:  "/home/x/.config/carbon/identity",
	}
}

func file(t *testing.T, p *Plan, path string) map[string]any {
	t.Helper()
	for _, f := range p.Files {
		if f.Path == path {
			var m map[string]any
			if err := toml.Unmarshal(f.Content, &m); err != nil {
				t.Fatalf("%s: %v\n%s", path, err, f.Content)
			}
			return m
		}
	}
	t.Fatalf("plan writes no %s", path)
	return nil
}

func contains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestPlanRootServiceAndRenames(t *testing.T) {
	root := svc(t, "carbon.toml", `
name = "Root App"
[push.token]
command = "x"
[[push.url]]
registry_pattern = "^$"
value = "http://local/{{carbon.registry}}"
[[push.url]]
value = "https://{{carbon.registry}}.example.com"
[derive.PRICE]
value = "$5 for {{env.USER}} in {{carbon.registry}} {{derive.other}}"
`)
	alice := legacy.User{Name: "alice", Key: keyA}
	in := baseInput([]*legacy.Service{root}, map[string]legacy.Values{
		"":     {"Root App": {"token": "t-local"}},
		"prod": {"Root App": {"token": "t-prod"}},
	}, reg("", alice), reg("prod", alice))
	in.DefaultEnv = "local"
	p := Build(in)
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers: %v", p.Blockers)
	}
	m := file(t, p, "carbon.toml")
	if m["name"] != "root-app" {
		t.Errorf("root package name = %v", m["name"])
	}
	ws := m["workspace"].(map[string]any)
	if ws["default_environment"] != "local" {
		t.Errorf("workspace = %v", ws)
	}
	vars := m["vars"].(map[string]any)["url"].(map[string]any)
	if vars["local"] != "http://local/" || vars["prod"] != "https://prod.example.com" {
		t.Errorf("url var = %v", vars)
	}
	env := m["env"].(map[string]any)
	if env["PRICE"] != "$$5 for ${env:USER} in ${carbon.env} {{derive.other}}" {
		t.Errorf("PRICE = %q", env["PRICE"])
	}
	if len(p.Copies) != 2 || p.Copies[0].Value() != "t-local" || p.Copies[0].Env != "local" || p.Copies[0].Package != "root-app" {
		t.Errorf("copies = %+v", p.Copies)
	}
	if !contains(p.Manual, `service "Root App" became package "root-app"`) {
		t.Errorf("manual = %v", p.Manual)
	}
	var sb strings.Builder
	p.Render(&sb, true)
	if strings.Contains(sb.String(), "t-local") || strings.Contains(sb.String(), "t-prod") {
		t.Error("the plan prints a secret value")
	}
}

func TestPlanPatternsAndDefaults(t *testing.T) {
	db := svc(t, "db/carbon.toml", `
name = "db"
[[push.host]]
registry_pattern = "d"
value = "a"
[[push.host]]
registry_pattern = "e"
value = "b"
[push.only_prd]
command = "x"
`)
	app := svc(t, "app/carbon.toml", `
name = "app"
[pull.host]
service = "db"
[pull.only_prd]
service = "db"
default = { value = "fallback" }
[pull.ghost]
service = "nope"
[[derive.MODE]]
registry_pattern = "prd"
value = "{{pull.host}}-prod"
[[derive.MODE]]
value = "{{pull.host}}-dev"
`)
	alice := legacy.User{Name: "alice", Key: keyA}
	in := baseInput([]*legacy.Service{app, db}, map[string]legacy.Values{
		"dev": {}, "prd": {"db": {"only_prd": "v"}},
	}, reg("dev", alice), reg("prd", alice))
	p := Build(in)
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers: %v", p.Blockers)
	}
	// "dev" matches both "d" and "e": 0.0.3 errors, so there is no value.
	dbf := file(t, p, "db/carbon.toml")
	host := dbf["vars"].(map[string]any)["host"].(map[string]any)
	if _, ok := host["dev"]; ok || host["prd"] != "a" {
		t.Errorf("host = %v", host)
	}
	if !contains(p.Manual, "push host has no value in dev: 2 registry patterns match") {
		t.Errorf("manual lacks the multi-match: %v", p.Manual)
	}
	if !contains(p.Manual, "pull only_prd had a default value; 1.0 has no defaults. Today it has no value in dev") {
		t.Errorf("manual lacks the pull default: %v", p.Manual)
	}
	if !contains(p.Manual, `pull ghost: service "nope" has no carbon.toml`) {
		t.Errorf("manual lacks the dangling pull: %v", p.Manual)
	}
	if !contains(p.Manual, "derive MODE differs per registry and uses templates") {
		t.Errorf("manual lacks the derive: %v", p.Manual)
	}
	appf := file(t, p, "app/carbon.toml")
	if appf["env"].(map[string]any)["MODE"] != "${db.host}-dev" {
		t.Errorf("MODE = %v", appf["env"])
	}
}

func TestPlanBlockers(t *testing.T) {
	alice := legacy.User{Name: "alice", Key: keyA}
	cases := []struct {
		name  string
		edit  func(*Input)
		svcs  []string // file:name
		block string
	}{
		{"reserved package", nil, []string{"a/carbon.toml:env"}, `"env" (service "env") is reserved`},
		{"duplicate service", nil, []string{"a/carbon.toml:x", "b/carbon.toml:x"}, `service name "x" is used by`},
		{"hidden dir", nil, []string{".carbon/svc/carbon.toml:svc"}, "does not search"},
		{"env collision", func(in *Input) { in.EnvNames = map[string]string{"prd": "dev"} }, []string{"a/carbon.toml:a"}, "would both become environment"},
		{"bad env name", func(in *Input) { in.EnvNames = map[string]string{"prd": "Prod"} }, []string{"a/carbon.toml:a"}, "cannot be the environment"},
		{"identity conflict", func(in *Input) { in.IdentityExists, in.IdentityExisting = true, keyB }, []string{"a/carbon.toml:a"}, "never overwrites an identity"},
		{"cannot decrypt", func(in *Input) { in.DecryptErrors = map[string]string{"prd": "no key"} }, []string{"a/carbon.toml:a"}, "cannot decrypt .carbon/registry.prd.yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var services []*legacy.Service
			for _, s := range c.svcs {
				f, n, _ := strings.Cut(s, ":")
				services = append(services, svc(t, f, "name = \""+n+"\"\n"))
			}
			in := baseInput(services, map[string]legacy.Values{}, reg("", alice), reg("prd", alice))
			if c.edit != nil {
				c.edit(&in)
			}
			p := Build(in)
			if !contains(p.Blockers, c.block) {
				t.Fatalf("blockers %v lack %q", p.Blockers, c.block)
			}
		})
	}
}

func TestPlanPeople(t *testing.T) {
	r := reg("", legacy.User{Name: "Ada Okafor", Key: keyA})
	r.Granted = append(r.Granted, keyB) // granted by hand, no users entry
	p := Build(baseInput([]*legacy.Service{svc(t, "a/carbon.toml", "name = \"a\"\n")}, nil, r))
	if len(p.People) != 2 || p.People[0].ID != "ada-okafor" || p.People[1].ID != "unknown-1" || p.Me != "ada-okafor" {
		t.Fatalf("people = %+v me %q", p.People, p.Me)
	}
	ws := file(t, p, "carbon.toml")
	if got := ws["access"].(map[string]any)["dev"]; len(got.([]any)) != 2 {
		t.Errorf("dev readers = %v", got)
	}
	if !contains(p.Manual, "no `users` entry names it") {
		t.Errorf("manual = %v", p.Manual)
	}
}

// TestPlanMigratorMustReadEveryScope: carbon 1.0 lets only a reader create a
// scope's first key, so the plan blocks when the migrator's key would not
// read an environment that gets values; empty values are copied.
func TestPlanMigratorMustReadEveryScope(t *testing.T) {
	db := svc(t, "db/carbon.toml", "name = \"db\"\n[push.pw]\ncommand = \"x\"\n")
	alice := legacy.User{Name: "alice", Key: keyA}
	bob := legacy.User{Name: "bob", Key: keyB}
	values := map[string]legacy.Values{"": {"db": {"pw": ""}}, "prd": {"db": {"pw": "p"}}}
	p := Build(baseInput([]*legacy.Service{db}, values, reg("", alice), reg("prd", bob)))
	if !contains(p.Blockers, "would not be a reader of environment prd") {
		t.Fatalf("blockers = %v", p.Blockers)
	}
	p = Build(baseInput([]*legacy.Service{db}, values, reg("", alice), reg("prd", alice, bob)))
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers = %v", p.Blockers)
	}
	if len(p.Copies) != 2 || p.Copies[0].Value() != "" || p.Copies[0].Env != "dev" {
		t.Fatalf("an empty value was not copied: %+v", p.Copies)
	}
}

// TestStdinFor checks the framing against carbon set's stdin rule: one
// trailing "\r\n" or "\n" is stripped (internal/cli/prompt.go ReadSecret).
func TestStdinFor(t *testing.T) {
	strip := func(b []byte) string {
		s := string(b)
		if strings.HasSuffix(s, "\r\n") {
			return s[:len(s)-2]
		}
		return strings.TrimSuffix(s, "\n")
	}
	for _, v := range []string{"plain", "ends\n", "ends\n\n", "ends\r", "ends\r\n", "multi\nline", " "} {
		if got := strip(stdinFor(v)); got != v {
			t.Errorf("%q arrives as %q", v, got)
		}
	}
}
