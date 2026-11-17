package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

var (
	childOnce sync.Once
	childPath string
	childErr  error
)

// childHelper builds testdata/childhelper next to the carbon test binary
// (so clitest.Main removes it) and returns its path.
func childHelper(t testing.TB) string {
	t.Helper()
	bin := clitest.Binary(t)
	childOnce.Do(func() {
		childPath = filepath.Join(filepath.Dir(bin), "childhelper")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", childPath, "./testdata/childhelper")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			childErr = fmt.Errorf("building childhelper: %v\n%s", err, out)
		}
	})
	if childErr != nil {
		t.Fatal(childErr)
	}
	return childPath
}

// Values used in tests. None may appear in any error output.
const (
	stripeValue  = "sk_live_STRIPE-0123"
	sessionValue = "sess-VALUE-4567"
	dbValue      = "db pass \"quoted\" 'single'\n# not a comment $HOME `tick` \\ end"
	rootValue    = "ROOT-PW-8910"
	dropValue    = "DROPPED-VALUE-1112"
)

var allValues = []string{stripeValue, sessionValue, dbValue, rootValue, dropValue, "DROPPED-VALUE", "db pass"}

func noLeak(t *testing.T, res *clitest.Result) {
	t.Helper()
	for _, v := range allValues {
		if strings.Contains(res.Stderr, v) {
			t.Fatalf("stderr contains a secret value %q:\n%s", v, res)
		}
	}
}

const checkoutWithEnv = clitest.CheckoutPackage + `
[vars.public_url]
dev  = "http://localhost:3000"
prod = "https://checkout.example.com"

[vars.region]
default = "us-east-1"

[env]
STRIPE_API_KEY = "${stripe_api_key}"
SESSION_KEY    = "${session_key}"
DATABASE_URL   = "postgres://checkout:${db.password}@${db.host}:5432/checkout"
DB_PASSWORD    = "${db.password}"
PUBLIC_URL     = "${public_url}"
REGION         = "${region}"
CARBON_ENV_NAME = "${carbon.env}"
PRICE          = "$$5"
FROM_SHELL     = "${env:FROM_SHELL}"
lower          = "lower-${carbon.env}"
`

const dbPackage = `[access]
dev = ["lin"]

[secrets]
password      = { description = "database password" }
root_password = { description = "superuser", private = true }

[vars.host]
default = "db.internal"
`

// runWorld is the standard world plus a db package (dev readable by lin
// only) and checkout's [env] table, committed to trunk. Lin has set
// checkout/dev's stripe_api_key and session_key and db/dev's password
// and root_password, all committed.
func runWorld(t *testing.T) *clitest.World {
	t.Helper()
	w := clitest.Standard(t)
	w.AddPackage(w.PkgDir, "checkout", checkoutWithEnv)
	w.AddPackage("services/db", "db", dbPackage)
	w.AddPackage("services/empty", "empty", "")
	w.Commit("packages")
	lin := w.Lin.In(w.PkgDir)
	lin.Stdin(stripeValue).Must("set", "stripe_api_key")
	w.Lin.In(w.PkgDir).Stdin(sessionValue).Must("set", "session_key")
	w.Lin.In("services/db").Stdin(dbValue).Must("set", "password")
	w.Lin.In("services/db").Stdin(rootValue).Must("set", "root_password")
	w.Commit("secrets")
	return w
}

type childOut struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func parseChild(t *testing.T, res *clitest.Result) childOut {
	t.Helper()
	var c childOut
	if err := json.Unmarshal([]byte(res.Stdout), &c); err != nil {
		t.Fatalf("child output: %v\n%s", err, res)
	}
	return c
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestRunPassesExactEnvironmentAndExitCode(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	parent := []string{"FROM_SHELL=shell value", "SESSION_KEY=from-parent", "LOWER=upper-case-parent", "PARENT_ONLY=1"}

	// Baseline: a package with an empty [env] gets exactly the parent's.
	base := w.Lin.With(parent...).In("services/empty").Must("run", "--", helper, "env")
	baseEnv := envMap(parseChild(t, base).Env)

	res := w.Lin.With(parent...).In(w.PkgDir).Run("run", "--", helper, "env", "7", "--env", "x")
	if res.Code != 7 {
		t.Fatalf("want the child's exit code 7\n%s", res)
	}
	child := parseChild(t, res)
	if got := strings.Join(child.Args[1:], " "); got != "env 7 --env x" {
		t.Fatalf("child args %q", got)
	}
	got := envMap(child.Env)
	want := map[string]string{}
	for k, v := range baseEnv {
		want[k] = v
	}
	resolved := map[string]string{
		"STRIPE_API_KEY":  stripeValue,
		"SESSION_KEY":     sessionValue,
		"DATABASE_URL":    "postgres://checkout:" + dbValue + "@db.internal:5432/checkout",
		"DB_PASSWORD":     dbValue,
		"PUBLIC_URL":      "http://localhost:3000",
		"REGION":          "us-east-1",
		"CARBON_ENV_NAME": "dev",
		"PRICE":           "$5",
		"FROM_SHELL":      "shell value",
		"lower":           "lower-dev",
	}
	for k, v := range resolved {
		want[k] = v
	}
	if len(got) != len(want) || len(child.Env) != len(want) {
		t.Errorf("child has %d variables (%d entries), want %d", len(got), len(child.Env), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected variable %s", k)
		}
	}
	// Case-sensitive: LOWER from the parent and lower from [env] both exist.
	if got["LOWER"] != "upper-case-parent" {
		t.Errorf("LOWER = %q", got["LOWER"])
	}
	// No secret in carbon's argv or on disk: the run wrote nothing.
	if st := w.Git("status", "--porcelain"); st != "" {
		t.Fatalf("run changed the work tree:\n%s", st)
	}
}

func TestRunErrors(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)

	res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(1, "run", "--", "no-such-command-carbon")
	contains(t, "stderr", res.Stderr, "command not found: no-such-command-carbon")
	noLeak(t, res)

	res = w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(1, "run", "--", "./nope")
	contains(t, "stderr", res.Stderr, "command not found: ./nope", "does not exist")

	// ${env:FROM_SHELL} unset.
	res = w.Lin.In(w.PkgDir).Fails(1, "run", "--", helper, "env")
	contains(t, "stderr", res.Stderr, "the environment variable FROM_SHELL is not set", "FROM_SHELL = \"${env:FROM_SHELL}\"", "export FROM_SHELL=")
	noLeak(t, res)

	// Set but empty counts as set.
	w.Lin.With("FROM_SHELL=").In(w.PkgDir).Must("run", "--", helper, "env")

	w.Lin.In(w.PkgDir).Fails(2, "run")
	w.Lin.In(w.PkgDir).Fails(2, "run", "--json", "--", helper, "env")
	w.Lin.In(w.PkgDir).Fails(2, "run", "x", "--", helper)

	// A reference to a secret that is not set.
	w.Replace(w.PkgDir+"/carbon.toml", `PRICE          = "$$5"`, `PRICE = "${webhook_secret}"`)
	res = w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(5, "run", "--", helper, "env")
	contains(t, "stderr", res.Stderr, "checkout/dev webhook_secret is not set", "carbon set webhook_secret --package checkout --env dev")
	noLeak(t, res)
}

func TestCrossPackageReferenceNeedsReadAccess(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	// Lin reads checkout/dev and db/dev: works (TestRunPassesExact...).
	// Ada reads checkout/dev but not db/dev.
	res := w.Ada.With("FROM_SHELL=x").In(w.PkgDir).Fails(3, "run", "--", helper, "env")
	contains(t, "stderr", res.Stderr,
		"error: you cannot read db in dev",
		"db/dev is readable by lin.",
		"You are ada, a member of @engineering.",
		"checkout needs it: DATABASE_URL",
		"carbon request db --env dev")
	noLeak(t, res)
	if res.Stdout != "" {
		t.Fatalf("the command ran:\n%s", res)
	}
	res = w.Ada.With("FROM_SHELL=x").In(w.PkgDir).Fails(3, "export")
	contains(t, "stderr", res.Stderr, "you cannot read db in dev")
	noLeak(t, res)
	res = w.Ada.With("FROM_SHELL=x").In(w.PkgDir).Fails(3, "export", "--json")
	var je struct {
		Error struct {
			Code int    `json:"code"`
			Hint string `json:"hint"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &je); err != nil || je.Error.Code != 3 || !strings.Contains(je.Error.Hint, "carbon request db --env dev") {
		t.Fatalf("json error: %v\n%s", err, res)
	}

	// Sam is not in policy for prod either: checkout/prod has no key at all,
	// and its references are "not set", not an access error.
	res = w.Sam.With("FROM_SHELL=x").In(w.PkgDir).Fails(5, "run", "--env", "prod", "--", helper, "env")
	contains(t, "stderr", res.Stderr, "db/prod password is not set")

	// No identity at all.
	res = w.Anyone().With("FROM_SHELL=x").In(w.PkgDir).Fails(6, "run", "--", helper, "env")
	noLeak(t, res)
}

func TestPrivateSecretCannotBeReferenced(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.Replace(w.PkgDir+"/carbon.toml", `PRICE          = "$$5"`, `ROOT = "${db.root_password}"`)
	for _, args := range [][]string{{"run", "--", helper, "env"}, {"export"}} {
		res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(3, args...)
		contains(t, "stderr", res.Stderr, "db.root_password is private to db", "ROOT = \"${db.root_password}\"", "private = true")
		noLeak(t, res)
		if strings.Contains(res.Stdout, rootValue) {
			t.Fatalf("private value printed:\n%s", res)
		}
	}
	// The owning package may use it.
	w.Write("services/db/carbon.toml", "name = \"db\"\n\n"+dbPackage+"\n[env]\nROOT = \"${root_password}\"\n")
	res := w.Lin.In("services/db").Must("export")
	contains(t, "stdout", res.Stdout, "ROOT="+rootValue)
}

func TestDropByNonReaderIsVisibleInRunAndExport(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	// Ada cannot read db/dev: her set is a drop to trunk's inbox.
	res := w.Ada.In("services/db").Stdin(dropValue).Must("set", "password")
	contains(t, "stderr", res.Stderr, "this will be a drop")
	contains(t, "secrets", w.Read("services/db/.carbon/dev.secrets.toml"), "password = { key = ", "drop = \"age1:")

	res = w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Must("run", "--", helper, "env")
	if got := envMap(parseChild(t, res).Env)["DB_PASSWORD"]; got != dropValue {
		t.Fatalf("DB_PASSWORD = %q", got)
	}
	contains(t, "stderr", res.Stderr, "db/dev password is a drop")
	noLeak(t, res)

	res = w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Must("export", "--format", "json")
	var m map[string]string
	if err := json.Unmarshal([]byte(res.Stdout), &m); err != nil || m["DB_PASSWORD"] != dropValue {
		t.Fatalf("export: %v\n%s", err, res)
	}
}

// parseDotenv implements the quoting export documents: bare values, or
// double quotes with \\ \" \$ \` \n \r \t.
func parseDotenv(t *testing.T, s string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for len(s) > 0 {
		nl := strings.IndexByte(s, '=')
		if nl < 0 {
			t.Fatalf("no = in %q", s)
		}
		name := s[:nl]
		s = s[nl+1:]
		if !strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s, '\n')
			out[name] = s[:end]
			s = s[end+1:]
			continue
		}
		var b strings.Builder
		i := 1
		for ; s[i] != '"'; i++ {
			if s[i] == '\n' {
				t.Fatalf("raw newline inside quotes")
			}
			if s[i] != '\\' {
				b.WriteByte(s[i])
				continue
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\', '"', '$', '`':
				b.WriteByte(s[i])
			default:
				t.Fatalf("unknown escape \\%c", s[i])
			}
		}
		out[name] = b.String()
		if s[i+1] != '\n' {
			t.Fatalf("junk after quoted value")
		}
		s = s[i+2:]
	}
	return out
}

func TestExportFormatsAndFiles(t *testing.T) {
	w := runWorld(t)
	lin := func() *clitest.Run { return w.Lin.With("FROM_SHELL=has space").In(w.PkgDir) }

	res := lin().Must("export")
	contains(t, "dotenv", res.Stdout, "REGION=us-east-1\n", "PRICE=\"\\$5\"\n", "FROM_SHELL=\"has space\"\n",
		`DB_PASSWORD="db pass \"quoted\" 'single'\n# not a comment \$HOME \`+"`"+`tick\`+"`"+` \\ end"`)
	got := parseDotenv(t, res.Stdout)
	if got["DB_PASSWORD"] != dbValue || got["STRIPE_API_KEY"] != stripeValue || got["lower"] != "lower-dev" || len(got) != 10 {
		t.Fatalf("dotenv round trip: %q", got)
	}
	if lin().Must("export", "-o", "-").Stdout != res.Stdout {
		t.Fatal("-o - differs from stdout")
	}

	res = lin().Must("export", "--format", "json")
	var m map[string]string
	if err := json.Unmarshal([]byte(res.Stdout), &m); err != nil || m["DB_PASSWORD"] != dbValue || len(m) != 10 {
		t.Fatalf("json: %v %q", err, res.Stdout)
	}
	res = lin().Must("export", "--json")
	if err := json.Unmarshal([]byte(res.Stdout), &m); err != nil || m["SESSION_KEY"] != sessionValue {
		t.Fatalf("--json: %v %q", err, res.Stdout)
	}
	lin().Fails(2, "export", "--json", "--format", "dotenv")
	lin().Fails(2, "export", "--format", "yaml")

	// A path git does not ignore is refused, and nothing is written.
	res = lin().Fails(2, "export", "-o", ".env")
	contains(t, "stderr", res.Stderr, "refusing to write secrets to services/checkout/.env: git does not ignore it", ".gitignore")
	noLeak(t, res)
	if _, err := os.Stat(w.Path(w.PkgDir + "/.env")); err == nil {
		t.Fatal(".env was written")
	}
	// A tracked file is not ignored even if a pattern matches it.
	w.Write(w.PkgDir+"/tracked.env", "x")
	w.Commit("tracked")
	w.Write(".gitignore", "*.env\n")
	res = lin().Fails(2, "export", "-o", "tracked.env")
	noLeak(t, res)

	// Ignored: written with mode 0600, replacing a looser existing file.
	w.Write(w.PkgDir+"/.env", "old")
	if err := os.Chmod(w.Path(w.PkgDir+"/.env"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = lin().Must("export", "-o", ".env")
	contains(t, "stdout", res.Stdout, "Wrote 10 variable(s) for checkout/dev to services/checkout/.env (mode 0600).")
	fi, err := os.Stat(w.Path(w.PkgDir + "/.env"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	if parseDotenv(t, w.Read(w.PkgDir+"/.env"))["DB_PASSWORD"] != dbValue {
		t.Fatal("file content")
	}
	if strings.Contains(res.Stdout, stripeValue) {
		t.Fatal("value on stdout with -o")
	}
	res = lin().Must("export", "-o", ".env", "--format", "json", "--json")
	var sum struct {
		Path      string   `json:"path"`
		Format    string   `json:"format"`
		Variables []string `json:"variables"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &sum); err != nil || sum.Path != "services/checkout/.env" || sum.Format != "json" || len(sum.Variables) != 10 {
		t.Fatalf("summary: %v %s", err, res.Stdout)
	}
	if st := w.Git("status", "--porcelain", "--ignored=no"); strings.Contains(st, ".env") {
		t.Fatalf("export left something for git:\n%s", st)
	}

	// Outside the repository git cannot commit it: allowed.
	out := filepath.Join(t.TempDir(), "secrets.env")
	lin().Must("export", "-o", out)
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("outside: %v %v", fi, err)
	}
	// A directory that does not exist.
	res = lin().Fails(1, "export", "-o", "missing/dir/.env")
	noLeak(t, res)

}

func TestExportOtherEnvAndEmptyEnv(t *testing.T) {
	w := runWorld(t)
	res := w.Lin.In("services/empty").Must("export")
	if res.Stdout != "" {
		t.Fatalf("empty [env] exported %q", res.Stdout)
	}
	res = w.Lin.In("services/empty").Must("export", "--format", "json")
	if strings.TrimSpace(res.Stdout) != "{}" {
		t.Fatalf("empty json %q", res.Stdout)
	}
	// Vars only: no identity needed.
	w.AddPackage("services/web", "web", "[vars.url]\ndefault = \"u\"\n[env]\nURL = \"${url}\"\nDB_HOST = \"${db.host}\"\n")
	res = w.Anyone().In("services/web").Must("export")
	names := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	sort.Strings(names)
	if strings.Join(names, ",") != "DB_HOST=db.internal,URL=u" {
		t.Fatalf("vars only: %q", res.Stdout)
	}
}
