package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// secretsInFixture lists every (registry, service, key) whose value is a
// secret (pushed by a command), with the 1.0 package, environment and name it
// must arrive under.
var secretsInFixture = []struct {
	reg, svc, key    string
	pkg, env, name   string
	pushedInRegistry bool
}{
	{"", "db", "password", "db", "dev", "password", true},
	{"prd", "db", "password", "db", "prd", "password", true},
	{"stg", "db", "password", "db", "stg", "password", true},
	{"", "db", "multi", "db", "dev", "multi", true},
	{"prd", "db", "multi", "db", "prd", "multi", true},
	{"stg", "db", "multi", "db", "stg", "multi", true},
	{"", "db", "cert", "db", "dev", "cert", true},
	{"prd", "db", "cert", "db", "prd", "cert", true},
	// A static variant of a command secret: ends in "\r\n", so the stdin
	// framing for `carbon set` is exercised for real.
	{"stg", "db", "cert", "db", "stg", "cert", true},
	{"", "api", "session_key", "api", "dev", "session_key", true},
	{"prd", "api", "session_key", "api", "prd", "session_key", true},
	{"stg", "api", "session_key", "api", "stg", "session_key", true},
	{"", "api", "api-token", "api", "dev", "api_token", true},
	{"prd", "api", "api-token", "api", "prd", "api_token", true},
	{"stg", "api", "api-token", "api", "stg", "api_token", false},
}

var envOf = map[string]string{"": "dev", "prd": "prd", "stg": "stg"}

// TestMigrateFixture is the design's exit test: a 0.0.3 fixture repo is
// migrated and every value reads back identical.
func TestMigrateFixture(t *testing.T) {
	f := newFixture(t)

	// Ground truth from 0.0.3 itself, before anything changes.
	type want struct{ pkg, env, name, value string }
	var wants []want
	var secretValues []string
	for _, s := range secretsInFixture {
		v, ok := f.oldValue(s.reg, s.svc, s.key)
		if ok != s.pushedInRegistry {
			t.Fatalf("fixture: 0.0.3 read %s %s.%s: present=%v, want %v", s.reg, s.svc, s.key, ok, s.pushedInRegistry)
		}
		if ok {
			wants = append(wants, want{s.pkg, s.env, s.name, v})
			secretValues = append(secretValues, v)
		}
	}
	if len(wants) != 14 {
		t.Fatalf("fixture has %d secret values, want 14", len(wants))
	}
	if v, _ := f.oldValue("stg", "db", "cert"); !strings.HasSuffix(v, "\r\n") {
		t.Fatalf("fixture: stg cert should end in CRLF, got %q", v)
	}
	oldVars := map[string]string{} // "env/var" -> value
	for _, reg := range []string{"", "prd", "stg"} {
		for _, key := range []string{"host", "port", "queue"} {
			v, ok := f.oldValue(reg, "db", key)
			if !ok {
				t.Fatalf("fixture: db.%s missing in registry %q", key, reg)
			}
			oldVars[envOf[reg]+"/"+key] = v
		}
	}
	if oldVars["dev/queue"] != "jobs-" || oldVars["prd/host"] != "db.prod.internal" || oldVars["stg/host"] != "db.staging.internal" || oldVars["dev/host"] != "localhost" {
		t.Fatalf("fixture: unexpected 0.0.3 vars %v", oldVars)
	}
	aliceKey, err := os.ReadFile(filepath.Join(f.root, ".carbon", "private-key.age"))
	if err != nil {
		t.Fatal(err)
	}

	// Dry run: prints the plan and changes nothing.
	code, out, errOut := f.migrate(nil, nil)
	if code != ExitOK {
		t.Fatalf("dry run exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, s := range []string{"dry run", "Secrets to copy with `carbon set` (14 values", "db/prd", "Needs a manual choice", "--- services/api/carbon.toml", ".carbon/registry.prd.yaml"} {
		if !strings.Contains(out, s) {
			t.Errorf("dry run output lacks %q", s)
		}
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("dry run changed the tree:\n%s", st)
	}
	if _, err := os.Stat(f.identity()); err == nil {
		t.Fatal("dry run installed an identity")
	}
	assertNoSecrets(t, "dry run", out+errOut, secretValues)

	// The migration.
	code, out, errOut = f.migrate(nil, func(o *Options) { o.Write = true })
	t.Logf("carbon-migrate --write output:\n%s\n%s", out, errOut)
	if code != ExitOK {
		t.Fatalf("migrate --write exit %d", code)
	}
	assertNoSecrets(t, "--write", out+errOut, secretValues)
	if !strings.Contains(out, "14 of 14 value(s) read back identical") {
		t.Errorf("migrate did not report its own verification")
	}

	// Every value reads back identical through `carbon get`, using the
	// identity carbon-migrate moved to $XDG_CONFIG_HOME/carbon/identity.
	same := 0
	for _, w := range wants {
		got, stderr, err := f.get1("", w.pkg, w.env, w.name)
		if err != nil {
			t.Errorf("carbon get %s --env %s --package %s: %v\n%s", w.name, w.env, w.pkg, err, stderr)
			continue
		}
		if got != w.value {
			t.Errorf("%s/%s %s does not read back identical (len %d, want len %d)", w.pkg, w.env, w.name, len(got), len(w.value))
			continue
		}
		same++
	}
	t.Logf("exit test: %d of %d migrated secret values read back identical through carbon get", same, len(wants))
	for _, p := range []string{"carbon.toml", "services/db/carbon.toml", "services/api/carbon.toml", ".carbon/people/alice.toml"} {
		t.Logf("--- %s\n%s", p, f.read(p))
	}

	// The identity moved unchanged.
	id, err := os.ReadFile(f.identity())
	if err != nil {
		t.Fatalf("identity not installed: %v", err)
	}
	if string(id) != string(aliceKey) {
		t.Error("installed identity differs from the 0.0.3 key")
	}
	if st, _ := os.Stat(f.identity()); st.Mode().Perm() != 0o600 {
		t.Errorf("identity mode %v, want 0600", st.Mode().Perm())
	}

	// The old files are gone.
	for _, p := range []string{".carbon/private-key.age", ".carbon/registry.yaml", ".carbon/registry.prd.yaml", ".carbon/registry.stg.yaml", ".carbon/sops.yaml", ".carbon/sops.prd.yaml", ".carbon/sops.stg.yaml"} {
		if f.exists(p) {
			t.Errorf("%s still exists", p)
		}
	}

	// The policy files parse, as TOML and for carbon itself.
	for _, p := range []string{"carbon.toml", "services/db/carbon.toml", "services/api/carbon.toml", ".carbon/people/alice.toml", ".carbon/people/bob.toml", ".carbon/people/carol.toml"} {
		var m map[string]any
		if err := toml.Unmarshal([]byte(f.read(p)), &m); err != nil {
			t.Errorf("%s does not parse: %v", p, err)
		}
	}
	for _, pkg := range []string{"db", "api"} {
		for _, env := range []string{"dev", "prd", "stg"} {
			if _, stderr, err := f.cmd(f.root, f.env, nil, f.carbon, "ls", "--package", pkg, "--env", env); err != nil {
				t.Errorf("carbon ls --package %s --env %s: %v\n%s", pkg, env, err, stderr)
			}
		}
	}

	var ws struct {
		Workspace struct {
			Environments       []string `toml:"environments"`
			DefaultEnvironment string   `toml:"default_environment"`
			Trunk              string   `toml:"trunk"`
		} `toml:"workspace"`
		Access map[string][]string `toml:"access"`
	}
	if err := toml.Unmarshal([]byte(f.read("carbon.toml")), &ws); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ws.Workspace.Environments, ","); got != "dev,prd,stg" || ws.Workspace.DefaultEnvironment != "dev" {
		t.Errorf("environments %s default %s", got, ws.Workspace.DefaultEnvironment)
	}
	if got := strings.Join(ws.Access["dev"], ","); got != "alice,bob" {
		t.Errorf("dev readers %q, want alice,bob", got)
	}
	if got := strings.Join(ws.Access["prd"], ","); got != "alice" {
		t.Errorf("prd readers %q, want alice (carol only requested)", got)
	}

	// The package files follow the mapping table.
	var db, api struct {
		Name    string                       `toml:"name"`
		Secrets map[string]map[string]any    `toml:"secrets"`
		Vars    map[string]map[string]string `toml:"vars"`
		Env     map[string]string            `toml:"env"`
	}
	if err := toml.Unmarshal([]byte(f.read("services/db/carbon.toml")), &db); err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal([]byte(f.read("services/api/carbon.toml")), &api); err != nil {
		t.Fatal(err)
	}
	for k, v := range oldVars {
		env, name, _ := strings.Cut(k, "/")
		got, ok := db.Vars[name][env]
		if !ok {
			got, ok = db.Vars[name]["default"]
		}
		if !ok || got != v {
			t.Errorf("db var %s in %s = %q, want %q (from 0.0.3)", name, env, got, v)
		}
	}
	if _, ok := db.Secrets["retired_flag"]; ok {
		t.Error("an orphaned registry key became a secret")
	}
	if !strings.Contains(out, "db.retired_flag, which no carbon.toml pushes") {
		t.Error("orphaned registry key not listed for a manual choice")
	}
	wantEnv := map[string]string{
		"db_password":  "${db.password}",
		"db_host":      "${db.host}",
		"session_key":  "${session_key}",
		"DATABASE_URL": "postgres://app:${db.password}@${db.host}:5432/${carbon.env}",
		"AWS_REGION":   "${AWS_REGION}",
		"WORK_DIR":     "${env:HOME}/api",
	}
	for k, v := range wantEnv {
		if api.Env[k] != v {
			t.Errorf("api [env] %s = %q, want %q", k, api.Env[k], v)
		}
	}
	if got := api.Vars["AWS_REGION"]; got["prd"] != "us-east-1" || got["dev"] != "local" || got["stg"] != "local" {
		t.Errorf("api AWS_REGION var = %v", got)
	}
	for _, s := range []string{"session_key", "api_token"} {
		if _, ok := api.Secrets[s]; !ok {
			t.Errorf("api does not declare secret %s", s)
		}
	}
	for _, s := range []string{
		"pull session_key had a default command",
		"derive WORK_DIR differs per registry",
		"api_token was never pushed in stg",
		"[registry] (current/use) was dropped",
		".environment.json is a plaintext file",
		"carol requested access to registry prd",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("manual items lack %q", s)
		}
	}

	// Access carried over: bob reads dev but not prd; carol reads nothing.
	if got, _, err := f.get1(f.keys["bob"], "db", "dev", "password"); err != nil || got != wants[0].value {
		t.Errorf("bob cannot read db/dev password after migration (err %v)", err)
	}
	if _, _, err := f.get1(f.keys["bob"], "db", "prd", "password"); err == nil {
		t.Error("bob can read db/prd, which 0.0.3 never granted him")
	}
	if _, _, err := f.get1(f.keys["carol"], "db", "prd", "password"); err == nil {
		t.Error("carol can read db/prd, which she only requested")
	}

	// Running it again finds a migrated repository.
	f.git("add", "-A")
	f.git("commit", "-qm", "migrate")
	if code, _, _ := f.migrate(nil, nil); code != ExitBlocked {
		t.Errorf("second run exit %d, want %d (blocked)", code, ExitBlocked)
	}
}

func assertNoSecrets(t *testing.T, what, output string, values []string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(output, v) {
			t.Errorf("%s output contains a secret value", what)
		}
	}
}

// TestMigrateRefusesDirtyTree checks the --force gate.
func TestMigrateRefusesDirtyTree(t *testing.T) {
	f := newFixture(t)
	f.write("services/db/notes.md", "uncommitted\n")
	code, out, _ := f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitBlocked || !strings.Contains(out, "uncommitted changes") {
		t.Fatalf("dirty tree: exit %d, output:\n%s", code, out)
	}
	if !f.exists(".carbon/registry.yaml") || f.exists("carbon.toml") {
		t.Fatal("a blocked run changed files")
	}
}

// TestMigrateNeverOverwritesIdentity checks that an existing, different 1.0
// identity stops the migration before anything is written.
func TestMigrateNeverOverwritesIdentity(t *testing.T) {
	f := newFixture(t)
	other, err := os.ReadFile(f.keys["bob"])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.identity()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.identity(), other, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitBlocked || !strings.Contains(out, "never overwrites an identity") {
		t.Fatalf("identity conflict: exit %d, output:\n%s", code, out)
	}
	if got, _ := os.ReadFile(f.identity()); string(got) != string(other) {
		t.Fatal("the existing identity was changed")
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("a blocked run changed the tree:\n%s", st)
	}
}

// TestMigrateFailureRollsBack makes `carbon set` fail part-way and checks
// that nothing old is deleted and that the printed commands restore the
// repository exactly.
func TestMigrateFailureRollsBack(t *testing.T) {
	f := newFixture(t)
	// A carbon that works for four sets and then fails.
	wrapper := filepath.Join(f.tmp, "bin", "carbon-flaky")
	counter := filepath.Join(f.tmp, "count")
	script := "#!/bin/sh\nif [ \"$1\" = set ]; then n=$(cat " + counter + " 2>/dev/null || echo 0); n=$((n+1)); echo $n > " + counter + "; if [ $n -gt 4 ]; then echo 'simulated failure' >&2; exit 1; fi; fi\nexec " + f.carbon + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true; o.Carbon = wrapper })
	if code != ExitFailed {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, ExitFailed, out, errOut)
	}
	for _, p := range []string{".carbon/private-key.age", ".carbon/registry.yaml", ".carbon/sops.prd.yaml"} {
		if !f.exists(p) {
			t.Errorf("%s was deleted by a failed run", p)
		}
	}
	if !strings.Contains(errOut, "Nothing old was deleted") {
		t.Errorf("failure message does not say old files are intact:\n%s", errOut)
	}
	// Run exactly the undo commands it printed.
	var ran int
	for _, line := range strings.Split(errOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "git checkout -- ") || strings.HasPrefix(line, "git clean -f -- ") {
			f.must(f.root, f.env, "sh", "-c", line)
			ran++
		}
	}
	if ran != 2 {
		t.Fatalf("expected a git checkout and a git clean line, ran %d:\n%s", ran, errOut)
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("undo commands did not restore the tree:\n%s", st)
	}
	if _, err := os.Stat(f.identity()); err == nil {
		t.Error("a run that failed before verification left an identity behind")
	}
	// And the repository still migrates afterwards.
	if code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true }); code != ExitOK {
		t.Fatalf("migrating after the undo: exit %d\n%s\n%s", code, out, errOut)
	}
}
