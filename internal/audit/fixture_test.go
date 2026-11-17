package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// Times: values are set at t0; checks run at now.
var (
	t0  = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	now = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
)

// fx is a git repository holding a clean carbon workspace, committed to
// main (the trunk):
//
//   - environments dev, prod; dev read by @eng, prod by @ops and
//     machine:deploy
//   - people ada, lin, sam (hybrid laptops); eng = [ada, lin, sam],
//     ops = [lin]
//   - package app in svc/app: secret token, var url, [env] using both
//   - token set in dev and prod, every named device wrapped
type fx struct {
	t    *testing.T
	repo *gitx.Repo
	root string
	// ids holds each device's identities, by device id.
	ids  map[string][]agewrap.Identity
	recs map[string]string
}

const workspaceTOML = `[workspace]
format = 1
environments = ["dev", "prod"]
default_environment = "dev"
trunk = "main"

[access]
dev = ["@eng"]
prod = ["@ops", "machine:deploy"]
`

const appTOML = `name = "app"

[secrets]
token = { description = "API token" }

[vars.url]
default = "http://localhost"

[env]
TOKEN = "${token}"
URL = "${url}"
`

func newFx(t *testing.T) *fx {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.com")
	f := &fx{t: t, root: root, ids: map[string][]agewrap.Identity{}, recs: map[string]string{}}
	f.git("init", "-q", "-b", "main")
	repo, err := gitx.Find(root)
	if err != nil {
		t.Fatal(err)
	}
	f.repo = repo
	f.root = repo.Root

	f.write("carbon.toml", workspaceTOML)
	for _, p := range []string{"ada", "lin", "sam"} {
		f.write(".carbon/people/"+p+".toml", "[devices]\nlaptop = \""+f.key(p+"/laptop", agewrap.KindHybrid)+"\"\n")
	}
	f.write(".carbon/machines/deploy.toml", "key = \""+f.key("machine:deploy", agewrap.KindHybrid)+"\"\n")
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\", \"sam\"]\nops = [\"lin\"]\n")
	f.write("svc/app/carbon.toml", appTOML)
	for _, env := range []string{"dev", "prod"} {
		o := f.create("app", env)
		f.seal(o, "token", t0)
		f.save(o.Scope)
	}
	f.commit("workspace")
	return f
}

// key generates a key pair for a device id and returns its recipient.
func (f *fx) key(id string, kind agewrap.Kind) string {
	f.t.Helper()
	secret, rec, err := agewrap.GenerateIdentity(kind)
	if err != nil {
		f.t.Fatal(err)
	}
	ids, err := agewrap.ParseIdentityFile([]byte(secret+"\n"), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.ids[id], f.recs[id] = ids, rec
	return rec
}

func (f *fx) git(args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = f.root
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *fx) commit(msg string) {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "-q", "--allow-empty", "-m", msg)
}

func (f *fx) path(rel string) string { return filepath.Join(f.root, filepath.FromSlash(rel)) }

func (f *fx) write(rel, s string) {
	f.t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) read(rel string) string {
	f.t.Helper()
	b, err := os.ReadFile(f.path(rel))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *fx) replace(rel, old, new string) {
	f.t.Helper()
	s := f.read(rel)
	if !strings.Contains(s, old) {
		f.t.Fatalf("%s does not contain %q:\n%s", rel, old, s)
	}
	f.write(rel, strings.Replace(s, old, new, 1))
}

// devices returns the devices the working tree's policy names for a scope.
func (f *fx) devices(pkg, env string) []policy.Device {
	f.t.Helper()
	pol, err := policy.LoadWorktree(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	sa, err := pol.Scope(pkg, env)
	if err != nil {
		f.t.Fatal(err)
	}
	return sa.Devices
}

func (f *fx) pkgDir(pkg string) string {
	f.t.Helper()
	pol, err := policy.LoadWorktree(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	return scope.PackageDir(f.root, pol.Packages[pkg].Dir)
}

func (f *fx) load(pkg, env string) *scope.Scope {
	f.t.Helper()
	s, err := scope.Load(f.pkgDir(pkg), pkg, env)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// create makes a scope's first key, wrapped to the devices policy names.
func (f *fx) create(pkg, env string) *scope.Opened {
	f.t.Helper()
	o, err := f.load(pkg, env).Create(f.devices(pkg, env), t0)
	if err != nil {
		f.t.Fatal(err)
	}
	return o
}

// open opens a scope as one device.
func (f *fx) open(pkg, env, as string) *scope.Opened {
	f.t.Helper()
	o, err := f.load(pkg, env).Open(f.ids[as], as)
	if err != nil {
		f.t.Fatalf("open %s/%s as %s: %v", pkg, env, as, err)
	}
	return o
}

func (f *fx) seal(o *scope.Opened, name string, at time.Time) {
	f.t.Helper()
	if err := o.Seal(name, []byte("value-of-"+name), at); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) save(s *scope.Scope) {
	f.t.Helper()
	if _, err := s.Save(); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) check(opts Options) *Report {
	f.t.Helper()
	st, err := Load(f.repo)
	if err != nil {
		f.t.Fatal(err)
	}
	if opts.Now.IsZero() {
		opts.Now = now
	}
	return st.Check(opts)
}

// want fails unless the report has a finding with rule and severity, and
// returns the first.
func want(t *testing.T, rep *Report, rule string, sev Severity) Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Rule == rule && f.Severity == sev {
			return f
		}
	}
	t.Fatalf("no %s finding %s in:\n%s", sev, rule, dump(rep))
	return Finding{}
}

// none fails if the report has a finding with rule.
func none(t *testing.T, rep *Report, rule string) {
	t.Helper()
	if fs := rep.ByRule(rule); len(fs) > 0 {
		t.Fatalf("unexpected %s in:\n%s", rule, dump(rep))
	}
}

func dump(rep *Report) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		b.WriteString(string(f.Severity) + " " + f.Rule + " " + f.Scope + " " + f.Device + ": " + f.Message + "\n")
	}
	return b.String()
}

// addPackage writes <dir>/carbon.toml.
func (f *fx) addPackage(dir, body string) { f.write(dir+"/"+config.FileName, body) }
