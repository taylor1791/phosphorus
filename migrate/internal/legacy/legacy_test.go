package legacy

import (
	"strings"
	"testing"
)

func s(v string) *string { return &v }

// The cases are 0.0.3's own find_expression tests (test/unit.bats).
func TestSelectMatchesFindExpression(t *testing.T) {
	dev := Expr{Pattern: s("dev"), Value: s("D")}
	def := Expr{Value: s("DEFAULT")}
	cases := []struct {
		name     string
		registry string
		exprs    []Expr
		want     string // value, or "error: <substring>"
	}{
		{"bare record", "dev", []Expr{{Value: s("only")}}, "only"},
		{"matching pattern wins over default", "dev", []Expr{dev, def}, "D"},
		{"default when nothing matches", "prd", []Expr{dev, def}, "DEFAULT"},
		{"regex, not literal", "staging-2", []Expr{{Pattern: s("^stag"), Value: s("S")}, def}, "S"},
		{"unanchored", "prd", []Expr{{Pattern: s("r"), Value: s("R")}, def}, "R"},
		{"no match, no default", "prd", []Expr{dev}, "error: no registry pattern matches"},
		{"two defaults", "dev", []Expr{{Value: s("A")}, {Value: s("B")}}, "error: 2 expressions have no registry_pattern"},
		{"two patterns match: an error, not first-wins", "dev", []Expr{{Pattern: s("de"), Value: s("A")}, {Pattern: s("ev"), Value: s("B")}}, "error: 2 registry patterns match"},
		// The unnamed registry is the empty string to 0.0.3.
		{"default registry is empty", "", []Expr{{Pattern: s("^$"), Value: s("E")}, def}, "E"},
		{"default registry misses named patterns", "", []Expr{dev, def}, "DEFAULT"},
		{"empty pattern matches everything", "", []Expr{{Pattern: s(""), Value: s("ANY")}, def}, "ANY"},
		{"bad regex", "dev", []Expr{{Pattern: s("("), Value: s("X")}}, "error: does not compile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := Select(c.exprs, c.registry)
			if want, ok := strings.CutPrefix(c.want, "error: "); ok {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("got %v, %v; want error containing %q", e, err, want)
				}
				return
			}
			if err != nil || *e.Value != c.want {
				t.Fatalf("got %v, %v; want %q", e, err, c.want)
			}
		})
	}
}

// This is what nushell 0.116's `to yaml` writes for a 0.0.3 sops config.
const sopsYAML = `creation_rules:
- age: |-
    age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq,
    age1ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
users:
- name: alice
  key: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
- name: 'Enter your name'
  key: age1ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
`

func TestParseSopsConfig(t *testing.T) {
	users := parseUsers(sopsYAML)
	if len(users) != 2 || users[0].Name != "alice" || users[1].Name != "Enter your name" ||
		!strings.HasPrefix(users[1].Key, "age1ppp") {
		t.Fatalf("users = %+v", users)
	}
	rec := recipientsIn(creationRules(sopsYAML))
	if len(rec) != 2 {
		t.Fatalf("requested = %v", rec)
	}
	if got := parseUsers("creation_rules:\n- age: ''\nusers: []\n"); len(got) != 0 {
		t.Fatalf("empty users = %+v", got)
	}
	indented := "users:\n  - name: \"bob\"\n    key: age1zzzz\n  - {name: carol, key: age1yyyy}\n"
	if got := parseUsers(indented); len(got) != 2 || got[0].Name != "bob" || got[1].Key != "age1yyyy" {
		t.Fatalf("indented users = %+v", got)
	}
}

func TestSopsRecipients(t *testing.T) {
	doc := `_carbon:
    version: ENC[AES256_GCM,data:x,type:str]
sops:
    age:
        - recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            -----END AGE ENCRYPTED FILE-----
        - recipient: age1ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
          enc: |
            x
`
	if got := sopsRecipients(doc); len(got) != 2 {
		t.Fatalf("granted = %v", got)
	}
}

func TestParseService(t *testing.T) {
	svc, err := ParseService("svc/carbon.toml", []byte(`
name = "svc"
file = "out.json"

[pull.database_url]
service = "db-service"
name = "connection_string"
default = { value = "sqlite://localhost" }

[pull.self]
service = "svc"

[push.api_key]
value = "my-secret"

[push.generated_token]
command = "cat secrets.json | jq -r '.token'"

[[push.service_url]]
registry_pattern = "dev"
value = "http://localhost:3000"

[[push.service_url]]
value = "http://localhost:3000"

[derive.pool_url]
value = "{{pull.database_url}}?poolSize=10"

[registry]
current = { command = "cat .registry" }
`))
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "svc" || svc.Dir != "svc" || svc.OutFile != "out.json" || !svc.HasFile || !svc.HasRegistry {
		t.Fatalf("service = %+v", svc)
	}
	if p := svc.Pull["database_url"]; p.Service != "db-service" || p.Name != "connection_string" || p.Default == nil || *p.Default.Value != "sqlite://localhost" {
		t.Fatalf("pull = %+v", p)
	}
	if p := svc.Pull["self"]; p.Name != "self" {
		t.Fatalf("pull name should default to the local name: %+v", p)
	}
	if len(svc.Push["service_url"]) != 2 || !svc.Push["generated_token"][0].HasCommand() {
		t.Fatalf("push = %+v", svc.Push)
	}
}

func TestIsLegacyConfig(t *testing.T) {
	if !IsLegacyConfig([]byte("name = \"x\"\n[push.a]\nvalue = \"b\"\n")) {
		t.Error("0.0.3 service not recognised")
	}
	if IsLegacyConfig([]byte("[workspace]\nformat = 1\n")) {
		t.Error("1.0 workspace taken for 0.0.3")
	}
}
