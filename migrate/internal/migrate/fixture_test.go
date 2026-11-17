package migrate

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The fixture is a real carbon 0.0.3 repository made by the real 0.0.3
// script (testdata/carbon-0.0.3, a verbatim copy of carbon 0.0.3), run under
// nushell with sops and rage exactly as its own bats suite does. Expected
// values are read back with the old script's own `carbon read`, so the exit
// test compares Carbon 1.0 against what 0.0.3 itself says the values are.

// requireTools skips the test unless every named program is on PATH.
func requireTools(t *testing.T, names ...string) {
	t.Helper()
	var missing []string
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		t.Skipf("SKIPPED: needs %s on PATH to build a real carbon 0.0.3 fixture; see migrate/README.md (Tests) for the nix shell command", strings.Join(missing, ", "))
	}
}

var (
	carbonOnce sync.Once
	carbonBin  string
	carbonErr  error
)

// carbonBinary builds the Carbon 1.0 binary from the parent module.
func carbonBinary(t *testing.T) string {
	t.Helper()
	carbonOnce.Do(func() {
		wd, _ := os.Getwd()
		root := wd
		for {
			if _, err := os.Stat(filepath.Join(root, "cmd", "carbon")); err == nil {
				if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
					break
				}
			}
			parent := filepath.Dir(root)
			if parent == root {
				carbonErr = fmt.Errorf("cannot find the carbon module above %s", wd)
				return
			}
			root = parent
		}
		dir, err := os.MkdirTemp("", "carbon-migrate-test-")
		if err != nil {
			carbonErr = err
			return
		}
		carbonBin = filepath.Join(dir, "carbon")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", carbonBin, "./cmd/carbon")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			carbonErr = fmt.Errorf("building carbon: %v\n%s", err, out)
		}
	})
	if carbonErr != nil {
		t.Fatal(carbonErr)
	}
	return carbonBin
}

type fixture struct {
	t      *testing.T
	root   string // the repository
	tmp    string
	env    []string
	old    string            // the 0.0.3 script
	keys   map[string]string // user -> saved private key
	carbon string            // the 1.0 binary
}

func (f *fixture) xdg() string { return filepath.Join(f.tmp, "xdg") }

// identity is where carbon 1.0 looks for the migrator's identity.
func (f *fixture) identity() string { return filepath.Join(f.xdg(), "carbon", "identity") }

func (f *fixture) cmd(dir string, env []string, stdin []byte, name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (f *fixture) must(dir string, env []string, name string, args ...string) string {
	f.t.Helper()
	out, errOut, err := f.cmd(dir, env, nil, name, args...)
	if err != nil {
		f.t.Fatalf("%s %s: %v\nstdout:\n%s\nstderr:\n%s", name, strings.Join(args, " "), err, out, errOut)
	}
	return out
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	return f.must(f.root, f.env, "git", args...)
}

// oldCarbon runs the 0.0.3 script as user.
func (f *fixture) oldCarbon(user string, args ...string) string {
	f.t.Helper()
	return f.must(f.root, append(f.env, "USER="+user), f.old, args...)
}

func (f *fixture) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) read(rel string) string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(rel)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(rel)))
	return err == nil
}

// asUser makes user's saved key the repository's .carbon/private-key.age.
func (f *fixture) asUser(user string) {
	f.t.Helper()
	b, err := os.ReadFile(f.keys[user])
	if err != nil {
		f.t.Fatal(err)
	}
	f.write(".carbon/private-key.age", string(b))
}

// saveKey moves the current .carbon/private-key.age aside as user's.
func (f *fixture) saveKey(user string) {
	f.t.Helper()
	src := filepath.Join(f.root, ".carbon", "private-key.age")
	dst := filepath.Join(f.tmp, "keys", user+".age")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(src, dst); err != nil {
		f.t.Fatal(err)
	}
	f.keys[user] = dst
}

// Service files. The 0.0.3 script picks a service's registry with
// [registry] current, so pushing to a named registry needs a variant of the
// file that names it; the unnamed default needs no [registry] at all (an
// empty `current` is an error in 0.0.3).

func dbToml(registry string, withRetired bool) string {
	s := `name = "db"

[push.password]
command = "cat password-{{carbon.registry}}.txt"

[[push.host]]
registry_pattern = "^prd$"
value = "db.prod.internal"

[[push.host]]
registry_pattern = "^st"
value = "db.staging.internal"

[[push.host]]
value = "localhost"

[push.port]
value = "5432"
expect_unused = true

[push.queue]
value = "jobs-{{carbon.registry}}"

[push.multi]
command = "cat multi.txt"

[[push.cert]]
registry_pattern = "^stg$"
value = "-----BEGIN-----\r\nstg\r\n"

[[push.cert]]
command = "cat cert.txt"

[[push.optional]]
registry_pattern = "^prd$"
value = ""

[[push.optional]]
command = "cat optional.txt"
`
	if withRetired {
		s += "\n[push.retired_flag]\ncommand = \"echo gone\"\n"
	}
	if registry != "" {
		s += fmt.Sprintf("\n[registry]\ncurrent = { value = %q }\n", registry)
	}
	return s
}

const apiBody = `
[pull.db_password]
service = "db"
name = "password"

[pull.db_host]
service = "db"
name = "host"

[pull.session_key]
service = "api"
[pull.session_key.default]
command = "head -c 16 /dev/urandom | base64"

[push.session_key]
command = "cat session-{{carbon.registry}}.txt"

[derive.DATABASE_URL]
value = "postgres://app:{{pull.db_password}}@{{pull.db_host}}:5432/{{carbon.registry}}"

[[derive.AWS_REGION]]
registry_pattern = "prd"
value = "us-east-1"

[[derive.AWS_REGION]]
value = "local"

[[derive.WORK_DIR]]
registry_pattern = "prd"
value = "/srv/api"

[[derive.WORK_DIR]]
value = "{{env.HOME}}/api"
`

func apiToml(registry string, withToken bool, final bool) string {
	s := "name = \"api\"\n" + apiBody
	if withToken {
		s += "\n[push.api-token]\ncommand = \"cat token.txt\"\n"
	}
	switch {
	case final:
		s += "\n[registry]\ncurrent = { command = \"cat .registry\" }\nuse = { command = \"echo {{carbon.registry}} > .registry\" }\n"
	case registry != "":
		s += fmt.Sprintf("\n[registry]\ncurrent = { value = %q }\n", registry)
	}
	return s
}

// Secret material pushed by the fixture's commands, per registry.
var fixtureFiles = map[string]string{
	"services/db/password-.txt":    "dev-pw-1\n",
	"services/db/password-prd.txt": "prd pw with spaces & $dollar 'quote' \"dq\"\n",
	"services/db/password-stg.txt": "stg-pw\n",
	"services/db/multi.txt":        "first line\nsecond: \"quoted\" ünïcödé {{not.a.template}} ${not_a_ref}\n",
	"services/api/session-.txt":    "sess-dev\n",
	"services/api/session-prd.txt": "sess-prd\n",
	"services/api/session-stg.txt": "sess-stg\n",
	"services/api/token.txt":       "tok-123\n",
	"services/db/cert.txt":         "-----BEGIN-----\ncmd\n-----END-----\n",
	"services/db/optional.txt":     "opt-value-9f3\n",
}

// newFixture builds the 0.0.3 repository:
//
//	alice  creates the default registry and prd, stg; she runs the migration
//	bob    requests the default registry and alice grants it (rekey)
//	carol  requests prd and is never granted
//	db     pushes a command secret, pattern vars, a static var, a
//	       {{carbon.registry}} var, a multi-line secret, and a key it later
//	       stops pushing (an orphan in the registry)
//	api    pulls from db and itself (with a default command), derives with
//	       {{pull.x}}, {{env.X}} and {{carbon.registry}}, pushes a key with a
//	       dash that is never pushed in stg, and was pulled to
//	       .environment.json
func newFixture(t *testing.T) *fixture {
	t.Helper()
	requireTools(t, "git", "sops", "nu", "rage-keygen")
	tmp := t.TempDir()
	f := &fixture{t: t, tmp: tmp, root: filepath.Join(tmp, "repo"), keys: map[string]string{}}
	for _, d := range []string{f.root, filepath.Join(tmp, "home"), f.xdg(), filepath.Join(tmp, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(tmp, "home"),
		"XDG_CONFIG_HOME=" + f.xdg(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1",
		"SOPS_DISABLE_VERSION_CHECK=1",
		"TZ=UTC",
	}
	// Install the 0.0.3 script with its shebang pointed at the nushell on
	// PATH, as the bats helper's install_carbon does.
	src, err := os.ReadFile(filepath.Join("testdata", "carbon-0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	nu, _ := exec.LookPath("nu")
	_, rest, _ := strings.Cut(string(src), "\n")
	f.old = filepath.Join(tmp, "bin", "carbon")
	if err := os.WriteFile(f.old, []byte("#!"+nu+"\n"+rest), 0o755); err != nil {
		t.Fatal(err)
	}
	f.carbon = carbonBinary(t)

	f.git("init", "-q", "-b", "main", ".")
	f.write(".gitignore", "*.txt\n.environment.json\n.registry\n")
	for p, c := range fixtureFiles {
		f.write(p, c)
	}

	// Access, the way the bats helpers set it up.
	f.oldCarbon("alice", "init")
	f.oldCarbon("alice", "request", "prd", "stg")
	f.saveKey("alice")
	f.oldCarbon("bob", "request")
	f.saveKey("bob")
	f.oldCarbon("carol", "request", "prd")
	f.saveKey("carol")
	f.asUser("alice")
	f.oldCarbon("alice", "rekey")

	// Pushes, one registry at a time.
	for _, reg := range []string{"", "prd", "stg"} {
		f.write("services/db/carbon.toml", dbToml(reg, true))
		f.write("services/api/carbon.toml", apiToml(reg, reg != "stg", false))
		f.oldCarbon("alice", "push", "services/db")
		f.oldCarbon("alice", "push", "services/api")
	}
	// The default registry's plaintext file, as `carbon pull` leaves it.
	f.write("services/api/carbon.toml", apiToml("", true, false))
	f.oldCarbon("alice", "pull", "services/api")
	if !f.exists("services/api/.environment.json") {
		t.Fatal("0.0.3 pull did not write .environment.json")
	}
	// The committed state.
	f.write("services/db/carbon.toml", dbToml("", false))
	f.write("services/api/carbon.toml", apiToml("", true, true))
	// A service at the root, so trunk's root carbon.toml is a 0.0.3 file.
	f.write("carbon.toml", "name = \"web\"\n\n[pull.db_host]\nservice = \"db\"\nname = \"host\"\n")
	f.git("add", "-A")
	f.git("commit", "-qm", "carbon 0.0.3 fixture")

	// The realistic cutover: trunk (origin/main, the remote's default
	// branch) holds the 0.0.3 files, and the migration runs on a branch.
	origin := filepath.Join(tmp, "origin.git")
	f.must(tmp, f.env, "git", "init", "-q", "--bare", origin)
	f.git("remote", "add", "origin", origin)
	f.git("push", "-q", "-u", "origin", "main")
	f.git("remote", "set-head", "origin", "main")
	f.git("checkout", "-q", "-b", "carbon-1.0")
	return f
}

// oldValue reads a value with 0.0.3's own `carbon read`. ok is false when
// the registry does not hold it.
func (f *fixture) oldValue(registry, service, key string) (string, bool) {
	f.t.Helper()
	args := []string{"read", service, key}
	if registry != "" {
		args = append(args, "-r", registry)
	}
	out, _, err := f.cmd(f.root, append(f.env, "USER=alice"), nil, f.old, args...)
	if err != nil {
		return "", false
	}
	return out, true
}

// migrate runs carbon-migrate in-process.
func (f *fixture) migrate(extraEnv []string, opts func(*Options)) (int, string, string) {
	f.t.Helper()
	var stdout, stderr bytes.Buffer
	o := Options{
		Dir:     f.root,
		Carbon:  f.carbon,
		Stdout:  &stdout,
		Stderr:  &stderr,
		Environ: append(append([]string{}, f.env...), extraEnv...),
	}
	if opts != nil {
		opts(&o)
	}
	code := Run(o)
	return code, stdout.String(), stderr.String()
}

// get1 runs Carbon 1.0 `carbon get` with an explicit identity file ("" for
// the default XDG location).
func (f *fixture) get1(identityFile, pkg, env, name string) (string, string, error) {
	e := append([]string{}, f.env...)
	if identityFile != "" {
		e = append(e, "CARBON_IDENTITY_FILE="+identityFile)
	}
	return f.cmd(f.root, e, nil, f.carbon, "get", name, "--env", env, "--package", pkg)
}
