// Package clitest drives the real carbon binary in temporary git
// repositories, as one or more simulated people, without touching the
// developer's own config or repositories.
//
// A typical test:
//
//	func TestMain(m *testing.M) { clitest.Main(m) }
//
//	func TestSomething(t *testing.T) {
//		w := clitest.Standard(t)           // ada, lin, sam, machine deploy-checkout, package checkout
//		w.Lin.Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod").In("services/checkout")
//		...
//	}
//
// See docs/contributing.md for more.
package clitest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
	buildDir  string
)

// Main runs the tests and removes the binary built for them. Call it from
// TestMain.
func Main(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// Binary builds ./cmd/carbon once per test process (CGO_ENABLED=0) and
// returns its path.
func Binary(t testing.TB) string {
	t.Helper()
	buildOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}
		buildDir, err = os.MkdirTemp("", "carbon-clitest-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(buildDir, "carbon")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binPath, "./cmd/carbon")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build ./cmd/carbon: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above the test directory")
		}
		dir = parent
	}
}

// Repo is a temporary git repository with a trunk branch.
type Repo struct {
	T testing.TB
	// Dir is the repository root.
	Dir string
	// Trunk is the trunk ref written into carbon.toml ("main").
	Trunk string
	base  string
	anon  *Person
}

// NewRepo creates an empty git repository on branch main. Nothing is
// committed, so the trunk ref does not exist yet (the bootstrap case).
func NewRepo(t testing.TB) *Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	Binary(t)
	base := t.TempDir()
	r := &Repo{T: t, Dir: filepath.Join(base, "repo"), Trunk: "main", base: base}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.Git("init", "-q", "-b", "main")
	r.anon = r.Person("nobody")
	return r
}

// NewWorkspace is NewRepo plus `carbon init --trunk main`, uncommitted.
func NewWorkspace(t testing.TB) *Repo {
	t.Helper()
	r := NewRepo(t)
	r.anon.Must("init", "--trunk", r.Trunk)
	return r
}

// Path returns the absolute path of a slash path relative to the root.
func (r *Repo) Path(rel string) string { return filepath.Join(r.Dir, filepath.FromSlash(rel)) }

// Write writes a file relative to the root, creating directories.
func (r *Repo) Write(rel, content string) {
	r.T.Helper()
	p := r.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.T.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.T.Fatal(err)
	}
}

// Read returns a file's content relative to the root ("" if missing).
func (r *Repo) Read(rel string) string {
	b, err := os.ReadFile(r.Path(rel))
	if err != nil {
		return ""
	}
	return string(b)
}

// Replace replaces the first occurrence of old in a file and fails the
// test if it is not there.
func (r *Repo) Replace(rel, old, new string) {
	r.T.Helper()
	s := r.Read(rel)
	if !strings.Contains(s, old) {
		r.T.Fatalf("%s does not contain %q", rel, old)
	}
	r.Write(rel, strings.Replace(s, old, new, 1))
}

// SetTeams rewrites .carbon/teams.toml.
func (r *Repo) SetTeams(teams map[string][]string) {
	r.T.Helper()
	names := make([]string, 0, len(teams))
	for n := range teams {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		q := make([]string, len(teams[n]))
		for i, m := range teams[n] {
			q[i] = fmt.Sprintf("%q", m)
		}
		fmt.Fprintf(&b, "%s = [%s]\n", n, strings.Join(q, ", "))
	}
	r.Write(".carbon/teams.toml", b.String())
}

// AddPackage writes <dir>/carbon.toml with name and the given body (TOML
// tables such as [access] and [secrets]).
func (r *Repo) AddPackage(dir, name, body string) {
	r.T.Helper()
	r.Write(dir+"/carbon.toml", fmt.Sprintf("name = %q\n\n%s", name, body))
}

// Git runs git in the root and returns trimmed stdout, failing the test on
// error.
func (r *Repo) Git(args ...string) string {
	r.T.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Dir
	cmd.Env = r.baseEnv(filepath.Join(r.base, "git-home"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		r.T.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// Commit stages everything and commits on the current branch.
func (r *Repo) Commit(msg string) {
	r.T.Helper()
	r.Git("add", "-A")
	r.Git("commit", "-q", "--allow-empty", "-m", msg)
}

// Branch creates and checks out a branch.
func (r *Repo) Branch(name string) { r.T.Helper(); r.Git("checkout", "-q", "-b", name) }

// Checkout switches to an existing branch.
func (r *Repo) Checkout(name string) { r.T.Helper(); r.Git("checkout", "-q", name) }

// Merge merges a branch into the current one (no editor).
func (r *Repo) Merge(name string) { r.T.Helper(); r.Git("merge", "-q", "--no-edit", name) }

func (r *Repo) baseEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_AUTHOR_NAME=carbon test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=carbon test", "GIT_COMMITTER_EMAIL=test@example.com",
		"LC_ALL=C", "TZ=UTC",
	}
}

// Person is someone (or something) that runs carbon: their own HOME and
// XDG_CONFIG_HOME, so their identity file is theirs alone.
type Person struct {
	Name string
	Home string
	// Env holds extra environment entries ("K=V") for every run, e.g.
	// CARBON_IDENTITY for a machine.
	Env  []string
	Repo *Repo
}

// Person returns a new simulated person with an empty home. It does not
// join; call Join.
func (r *Repo) Person(name string) *Person {
	r.T.Helper()
	home := filepath.Join(r.base, "home-"+name)
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		r.T.Fatal(err)
	}
	return &Person{Name: name, Home: home, Repo: r, Env: []string{"USER=" + name}}
}

// Anyone is a person with no identity, for commands that need none.
func (r *Repo) Anyone() *Person { return r.anon }

// Join runs `carbon join --person <name> --device laptop` plus args and
// fails the test unless it succeeds.
func (p *Person) Join(args ...string) *Result {
	p.Repo.T.Helper()
	return p.Must(append([]string{"join", "--person", p.Name, "--device", "laptop"}, args...)...)
}

// IdentityFile is the person's identity path.
func (p *Person) IdentityFile() string { return filepath.Join(p.Home, ".config", "carbon", "identity") }

// Machine runs `carbon join --machine <name>` and returns a Person whose
// runs carry the printed private key in CARBON_IDENTITY.
func (r *Repo) Machine(name string, args ...string) *Person {
	r.T.Helper()
	res := r.anon.Must(append([]string{"join", "--machine", name}, args...)...)
	if !strings.Contains(res.Stdout, "AGE-SECRET-KEY-") {
		r.T.Fatalf("join --machine printed no key:\n%s", res)
	}
	m := r.Person("machine-" + name)
	m.Env = append(m.Env, "CARBON_IDENTITY="+res.Stdout)
	return m
}

// Result is one carbon run.
type Result struct {
	Args   []string
	Dir    string
	Stdout string
	Stderr string
	Code   int
}

func (r *Result) String() string {
	return fmt.Sprintf("$ carbon %s   (in %s)\nexit %d\n--- stdout\n%s--- stderr\n%s",
		strings.Join(r.Args, " "), r.Dir, r.Code, r.Stdout, r.Stderr)
}

// Run options, built fluently: p.In("services/checkout").Stdin("v").Run(...).
type Run struct {
	p     *Person
	dir   string
	stdin string
	env   []string
}

// In returns a runner that starts in dir, relative to the repo root.
func (p *Person) In(dir string) *Run { return &Run{p: p, dir: dir} }

// Stdin returns a runner that feeds s on stdin.
func (p *Person) Stdin(s string) *Run { return &Run{p: p, stdin: s} }

// With returns a runner with extra environment entries.
func (p *Person) With(env ...string) *Run { return &Run{p: p, env: env} }

// In sets the directory, relative to the repo root.
func (r *Run) In(dir string) *Run { r.dir = dir; return r }

// Stdin sets stdin.
func (r *Run) Stdin(s string) *Run { r.stdin = s; return r }

// With adds environment entries.
func (r *Run) With(env ...string) *Run { r.env = append(r.env, env...); return r }

// Run runs carbon and returns the result whatever the exit code.
func (p *Person) Run(args ...string) *Result { return (&Run{p: p}).Run(args...) }

// Must runs carbon and fails the test unless it exits 0.
func (p *Person) Must(args ...string) *Result {
	p.Repo.T.Helper()
	return (&Run{p: p}).Must(args...)
}

// Fails runs carbon and fails the test unless it exits with code.
func (p *Person) Fails(code int, args ...string) *Result {
	p.Repo.T.Helper()
	return (&Run{p: p}).Fails(code, args...)
}

// Run runs carbon with the runner's options.
func (r *Run) Run(args ...string) *Result {
	p := r.p
	p.Repo.T.Helper()
	dir := p.Repo.Dir
	if r.dir != "" {
		dir = p.Repo.Path(r.dir)
	}
	cmd := exec.Command(Binary(p.Repo.T), args...)
	cmd.Dir = dir
	cmd.Env = append(append(p.Repo.baseEnv(p.Home), p.Env...), r.env...)
	cmd.Stdin = strings.NewReader(r.stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := &Result{Args: args, Dir: dir, Stdout: stdout.String(), Stderr: stderr.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		res.Code = ee.ExitCode()
	} else if err != nil {
		p.Repo.T.Fatalf("running carbon: %v", err)
	}
	return res
}

// Must runs and fails the test unless carbon exits 0.
func (r *Run) Must(args ...string) *Result {
	r.p.Repo.T.Helper()
	res := r.Run(args...)
	if res.Code != 0 {
		r.p.Repo.T.Fatalf("%s: expected success\n%s", r.p.Name, res)
	}
	return res
}

// Fails runs and fails the test unless carbon exits with code.
func (r *Run) Fails(code int, args ...string) *Result {
	r.p.Repo.T.Helper()
	res := r.Run(args...)
	if res.Code != code {
		r.p.Repo.T.Fatalf("%s: expected exit %d\n%s", r.p.Name, code, res)
	}
	return res
}

// World is the standard multi-person scenario.
type World struct {
	*Repo
	Ada, Lin, Sam *Person
	// Deploy is machine:deploy-checkout.
	Deploy *Person
	// PkgDir is the checkout package directory, "services/checkout".
	PkgDir string
}

// CheckoutPackage is the package Standard creates.
const CheckoutPackage = `[access]
prod = ["@payments", "machine:deploy-checkout"]

[secrets]
session_key    = { description = "HMAC key for session cookies", generate = "random:32" }
stripe_api_key = { description = "Stripe restricted key", rotate_after = "90d" }
webhook_secret = { description = "Stripe webhook signing secret" }
`

// Standard builds the scenario from the design, committed to trunk (main):
//
//   - workspace: environments dev, staging, prod; trunk main; every
//     environment readable by @engineering
//   - people ada, lin, sam (device "laptop" each, hybrid keys)
//   - teams: engineering = [ada, lin, sam], payments = [lin]
//   - machine:deploy-checkout
//   - package checkout in services/checkout, prod readable by @payments
//     and machine:deploy-checkout, secrets session_key, stripe_api_key and
//     webhook_secret
//
// No scope has a key yet. Tests run on main unless they branch.
func Standard(t testing.TB) *World {
	t.Helper()
	r := NewWorkspace(t)
	w := &World{Repo: r, PkgDir: "services/checkout"}
	w.Ada, w.Lin, w.Sam = r.Person("ada"), r.Person("lin"), r.Person("sam")
	w.Ada.Join()
	w.Lin.Join()
	w.Sam.Join()
	r.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam"}, "payments": {"lin"}})
	w.Deploy = r.Machine("deploy-checkout")
	r.AddPackage(w.PkgDir, "checkout", CheckoutPackage)
	r.Commit("carbon workspace")
	return w
}
