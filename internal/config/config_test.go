package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
)

const wsFile = `
[workspace]
format = 1
environments = ["dev", "staging", "prod"]
default_environment = "dev"
trunk = "origin/main"

[access]
dev  = ["@engineering"]
prod = { readers = ["@sre"], require_pq = true, drops = false }
`

const pkgFile = `
name = "checkout"

[access]
prod = ["@payments", "machine:deploy-checkout"]

[secrets]
session_key    = { description = "HMAC", generate = "random:32" }
stripe_api_key = { description = "Stripe", rotate_after = "90d", private = true }

[vars.public_url]
dev  = "http://localhost:3000"
default = "https://checkout.example.com"

[env]
SESSION_KEY  = "${session_key}"
DATABASE_URL = "postgres://checkout:${db.password}@${db.host}:5432/x"
AWS_PROFILE  = "${env:AWS_PROFILE}"
`

func TestParseWorkspaceAndPackage(t *testing.T) {
	ws, pkg, err := ParseFile("carbon.toml", []byte(wsFile))
	if err != nil {
		t.Fatal(err)
	}
	if pkg != nil || ws.Trunk != "origin/main" || ws.DefaultEnvironment != "dev" || len(ws.Environments) != 3 {
		t.Fatalf("ws = %+v pkg = %+v", ws, pkg)
	}
	if *ws.Access["prod"].RequirePQ != true || *ws.Access["prod"].Drops != false || ws.Access["dev"].Drops != nil {
		t.Fatalf("access = %+v", ws.Access)
	}

	_, p, err := ParseFile("services/checkout/carbon.toml", []byte(pkgFile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "checkout" || p.Dir != "services/checkout" || !p.Secrets["stripe_api_key"].Private {
		t.Fatalf("pkg = %+v", p)
	}
	if err := ws.ValidatePackage(p); err != nil {
		t.Fatal(err)
	}

	r := ws.ResolveAccess(p, "prod")
	want := Resolved{Readers: []string{"@payments", "machine:deploy-checkout"}, RequirePQ: true, Drops: false, ReadersFrom: "services/checkout/carbon.toml"}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("prod = %+v", r)
	}
	r = ws.ResolveAccess(p, "dev")
	if !reflect.DeepEqual(r, Resolved{Readers: []string{"@engineering"}, Drops: true, ReadersFrom: "carbon.toml"}) {
		t.Fatalf("dev = %+v", r)
	}
	if r := ws.ResolveAccess(p, "staging"); len(r.Readers) != 0 || r.ReadersFrom != "" || !r.Drops {
		t.Fatalf("staging = %+v", r)
	}
}

func TestPackageLongFormOverridesFlags(t *testing.T) {
	ws, _, _ := ParseFile("carbon.toml", []byte(wsFile))
	_, p, err := ParseFile("a/carbon.toml", []byte(`name = "a"
[access]
prod = { readers = ["ada"], drops = true }
`))
	if err != nil {
		t.Fatal(err)
	}
	r := ws.ResolveAccess(p, "prod")
	if !r.RequirePQ || !r.Drops || r.Readers[0] != "ada" {
		t.Fatalf("%+v", r)
	}
}

func TestRootFileCanBeAPackage(t *testing.T) {
	ws, p, err := ParseFile("carbon.toml", []byte(wsFile+"\nname = \"root\"\n"))
	if err == nil {
		// name after a table header belongs to the table: expect an error.
		t.Fatalf("parsed name inside [access]: %+v %+v", ws, p)
	}
	ws, p, err = ParseFile("carbon.toml", []byte("name = \"root\"\n"+wsFile))
	if err != nil {
		t.Fatal(err)
	}
	if ws.Package != p || p.Name != "root" || p.Dir != "." || len(p.Access) != 0 {
		t.Fatalf("root package = %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":         "name = \"a\"\ncolour = 1\n",
		"bad name":            "name = \"A\"\n",
		"reserved":            "name = \"env\"\n",
		"bad secret":          "name = \"a\"\n[secrets]\n1x = {}\n",
		"bad generate":        "name = \"a\"\n[secrets]\nx = { generate = \"shell:rm\" }\n",
		"bad duration":        "name = \"a\"\n[secrets]\nx = { rotate_after = \"3w\" }\n",
		"bad secret field":    "name = \"a\"\n[secrets]\nx = { command = \"ls\" }\n",
		"bad reader":          "name = \"a\"\n[access]\ndev = [\"@Bad\"]\n",
		"bad access key":      "name = \"a\"\n[access]\ndev = { readers = [], colour = 1 }\n",
		"bad template":        "name = \"a\"\n[env]\nX = \"$HOME\"\n",
		"no name":             "[secrets]\nx = {}\n",
		"no format":           "[workspace]\nenvironments=[\"dev\"]\ntrunk=\"main\"\n",
		"wrong format":        "[workspace]\nformat=2\nenvironments=[\"dev\"]\ntrunk=\"main\"\n",
		"no trunk":            "[workspace]\nformat=1\nenvironments=[\"dev\"]\n",
		"bad default env":     "[workspace]\nformat=1\nenvironments=[\"dev\"]\ndefault_environment=\"prod\"\ntrunk=\"main\"\n",
		"unknown access env":  "[workspace]\nformat=1\nenvironments=[\"dev\"]\ntrunk=\"main\"\n[access]\nprod=[]\n",
		"not toml":            "name = ",
		"default env":         "[workspace]\nformat=1\nenvironments=[\"default\"]\ntrunk=\"main\"\n",
		"duplicate env":       "[workspace]\nformat=1\nenvironments=[\"dev\",\"dev\"]\ntrunk=\"main\"\n",
		"long form no reader": "name = \"a\"\n[access]\ndev = { drops = false }\n",
	}
	for name, src := range cases {
		if _, _, err := ParseFile("x/carbon.toml", []byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLegacyAndConflicts(t *testing.T) {
	var le *LegacyError
	for _, src := range []string{"name = \"x\"\n[push]\na = 1\n", "[pull]\nx = {}\n"} {
		if _, _, err := ParseFile("carbon.toml", []byte(src)); !errors.As(err, &le) {
			t.Errorf("legacy file: %v", err)
		}
	}
	var ce *ConflictError
	src := "name = \"x\"\n<<<<<<< HEAD\n[secrets]\n=======\n>>>>>>> branch\n"
	if _, _, err := ParseFile("carbon.toml", []byte(src)); !errors.As(err, &ce) || ce.Path != "carbon.toml" {
		t.Errorf("conflict: %v", err)
	}
	if HasConflictMarkers([]byte("a = \"=======\"\n")) {
		t.Error("marker inside a value counted")
	}
}

func TestPeopleMachinesTeams(t *testing.T) {
	_, hy, _ := agewrap.GenerateIdentity(agewrap.KindHybrid)
	_, x, _ := agewrap.GenerateIdentity(agewrap.KindX25519)
	p := &Person{ID: "ada", Name: "Ada \"O\" Okafor", Devices: map[string]string{"laptop": hy, "desk": x}}
	data := MarshalPerson(p)
	got, err := ParsePerson("p", "ada", data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip: %+v", got)
	}
	if _, err := ParsePerson("p", "ada", []byte("[devices]\nlaptop = \"ssh-ed25519 AAA\"\n")); err == nil {
		t.Error("bad recipient accepted")
	}

	m := &Machine{ID: "deploy", Description: "ci", Key: hy}
	gm, err := ParseMachine("m", "deploy", MarshalMachine(m))
	if err != nil || !reflect.DeepEqual(gm, m) {
		t.Fatalf("machine: %+v %v", gm, err)
	}

	teams := Teams{"engineering": {"ada", "lin"}, "payments": {"lin"}}
	gt, err := ParseTeams("t", MarshalTeams(teams))
	if err != nil || !reflect.DeepEqual(gt, teams) {
		t.Fatalf("teams: %+v %v", gt, err)
	}
	if _, err := ParseTeams("t", []byte("eng = [\"@x\"]\n")); err == nil {
		t.Error("team listing a team accepted")
	}
}

func TestLoadFromDir(t *testing.T) {
	root := t.TempDir()
	write := func(rel, s string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, hy, _ := agewrap.GenerateIdentity(agewrap.KindHybrid)
	write("carbon.toml", wsFile)
	write("services/checkout/carbon.toml", pkgFile)
	write("node_modules/x/carbon.toml", "garbage")
	write(".hidden/carbon.toml", "garbage")
	write(".carbon/people/ada.toml", "[devices]\nlaptop = \""+hy+"\"\n")
	write(".carbon/people/README", "not toml")
	write(".carbon/machines/deploy.toml", "key = \""+hy+"\"\n")
	write(".carbon/teams.toml", "engineering = [\"ada\"]\n")

	src := DirSource{Root: root}
	ws, err := LoadWorkspace(src)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(src, ws)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs["checkout"] == nil {
		t.Fatalf("packages = %v", pkgs)
	}
	people, err := LoadPeople(src)
	if err != nil || len(people) != 1 || people["ada"].Devices["laptop"] != hy {
		t.Fatalf("people = %v %v", people, err)
	}
	machines, err := LoadMachines(src)
	if err != nil || machines["deploy"].Key != hy {
		t.Fatalf("machines = %v %v", machines, err)
	}
	teams, err := LoadTeams(src)
	if err != nil || teams["engineering"][0] != "ada" {
		t.Fatalf("teams = %v %v", teams, err)
	}

	write("other/carbon.toml", "name = \"checkout\"\n")
	if _, err := LoadPackages(src, ws); err == nil {
		t.Fatal("duplicate package name accepted")
	}
}

func TestTemplates(t *testing.T) {
	parts, err := ParseTemplate("pg://u:${db.password}@${host}/$${x}-${env:HOME}-${carbon.env}")
	if err != nil {
		t.Fatal(err)
	}
	want := []Part{
		{Literal: "pg://u:"},
		{Ref: &Ref{Kind: RefPackage, Package: "db", Name: "password"}},
		{Literal: "@"},
		{Ref: &Ref{Kind: RefLocal, Name: "host"}},
		{Literal: "/${x}-"},
		{Ref: &Ref{Kind: RefEnv, Name: "HOME"}},
		{Literal: "-"},
		{Ref: &Ref{Kind: RefCarbonEnv}},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("parts = %+v", parts)
	}
	for _, bad := range []string{"$", "$x", "${", "${}", "${a.b.c}", "${env:}", "${1x}", "${Bad.x}"} {
		if _, err := ParseTemplate(bad); err == nil {
			t.Errorf("ParseTemplate(%q) accepted", bad)
		}
	}
}

func TestDurationsAndGenerate(t *testing.T) {
	if d, _ := ParseDuration("90d"); d != 90*24*time.Hour {
		t.Error(d)
	}
	if d, _ := ParseDuration("12h"); d != 12*time.Hour {
		t.Error(d)
	}
	for _, bad := range []string{"", "d", "0d", "-1d", "1w", "1.5d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
	if n, _ := ParseGenerate("random:32"); n != 32 {
		t.Error(n)
	}
	for _, bad := range []string{"random:0", "random:", "random:99999", "hex:32"} {
		if _, err := ParseGenerate(bad); err == nil {
			t.Errorf("ParseGenerate(%q) accepted", bad)
		}
	}
}

func TestNames(t *testing.T) {
	if !ValidKeyID("k3f9q2") || ValidKeyID("k3f9q") || ValidKeyID("K3f9q2") || ValidKeyID("k3f9q2x") {
		t.Error("key id rules")
	}
	if !ValidDeviceID("lin/laptop") || !ValidDeviceID("machine:deploy") || ValidDeviceID("lin") || ValidDeviceID("machine:") {
		t.Error("device id rules")
	}
	if pkg, env, err := ParseScopeName("checkout/prod"); err != nil || pkg != "checkout" || env != "prod" {
		t.Error("scope name")
	}
	if _, _, err := ParseScopeName("carbon/prod"); err == nil {
		t.Error("reserved package accepted as scope")
	}
	if Quote("a\"b\\c\n\x01") != `"a\"b\\c\n\u0001"` {
		t.Error(Quote("a\"b\\c\n\x01"))
	}
}
