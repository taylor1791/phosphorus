package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/gitx"
)

type fixture struct {
	t    *testing.T
	root string
	keys map[string]string // label -> recipient
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, root: t.TempDir(), keys: map[string]string{}}
	for _, l := range []string{"ada/laptop", "lin/laptop", "lin/yubikey", "sam/laptop", "deploy"} {
		kind := agewrap.KindHybrid
		if l == "lin/yubikey" {
			kind = agewrap.KindX25519
		}
		_, rec, err := agewrap.GenerateIdentity(kind)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[l] = rec
	}
	f.write("carbon.toml", `[workspace]
format = 1
environments = ["dev", "prod"]
default_environment = "dev"

[access]
dev  = ["@engineering"]
prod = { readers = ["@sre"], require_pq = true }
`)
	f.write("services/checkout/carbon.toml", `name = "checkout"
[access]
prod = ["@payments", "machine:deploy-checkout", "lin", "ghost", "@nobody"]
`)
	f.write("services/search/carbon.toml", "name = \"search\"\n")
	f.write(".carbon/teams.toml", "engineering = [\"ada\", \"lin\", \"sam\"]\npayments = [\"lin\", \"zed\"]\nsre = [\"sam\"]\n")
	f.write(".carbon/people/ada.toml", "[devices]\nlaptop = \""+f.keys["ada/laptop"]+"\"\n")
	f.write(".carbon/people/lin.toml", "[devices]\nlaptop = \""+f.keys["lin/laptop"]+"\"\nyubikey = \""+f.keys["lin/yubikey"]+"\"\n")
	f.write(".carbon/people/sam.toml", "[devices]\nlaptop = \""+f.keys["sam/laptop"]+"\"\n")
	f.write(".carbon/machines/deploy-checkout.toml", "key = \""+f.keys["deploy"]+"\"\n")
	return f
}

func (f *fixture) write(rel, s string) {
	p := filepath.Join(f.root, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func ids(ds []Device) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.ID)
	}
	return out
}

func TestScopeResolution(t *testing.T) {
	f := newFixture(t)
	p, err := LoadWorktree(f.root)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := p.Scope("checkout", "prod")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"lin/laptop", "lin/yubikey", "machine:deploy-checkout"}
	if !reflect.DeepEqual(ids(sa.Devices), want) {
		t.Fatalf("devices = %v", ids(sa.Devices))
	}
	if !reflect.DeepEqual(sa.Why["lin/laptop"], []string{"@payments", "lin"}) {
		t.Fatalf("why lin = %v", sa.Why["lin/laptop"])
	}
	if !reflect.DeepEqual(sa.Unresolved, []string{"@payments: zed", "ghost", "@nobody"}) {
		t.Fatalf("unresolved = %v", sa.Unresolved)
	}
	if !sa.RequirePQ || !sa.Drops || sa.ReadersFrom != "services/checkout/carbon.toml" || !sa.PackageKnown {
		t.Fatalf("flags = %+v", sa)
	}
	ok, skipped := sa.Eligible()
	if !reflect.DeepEqual(ids(skipped), []string{"lin/yubikey"}) || len(ok) != 2 {
		t.Fatalf("eligible %v skipped %v", ids(ok), ids(skipped))
	}
	if !sa.Names("machine:deploy-checkout") || sa.Names("sam/laptop") {
		t.Fatal("Names")
	}

	dev, _ := p.Scope("search", "dev")
	if !reflect.DeepEqual(ids(dev.Devices), []string{"ada/laptop", "lin/laptop", "lin/yubikey", "sam/laptop"}) {
		t.Fatalf("search/dev = %v", ids(dev.Devices))
	}
	if dev.ReadersFrom != "carbon.toml" {
		t.Fatal(dev.ReadersFrom)
	}

	unknown, _ := p.Scope("newpkg", "prod")
	if unknown.PackageKnown || !reflect.DeepEqual(ids(unknown.Devices), []string{"sam/laptop"}) {
		t.Fatalf("unknown package falls back to workspace: %+v", unknown)
	}
	if _, err := p.Scope("checkout", "qa"); err == nil {
		t.Fatal("unknown env accepted")
	}

	d, ok2 := p.Identify(f.keys["lin/yubikey"])
	if !ok2 || d.ID != "lin/yubikey" || d.Hybrid() {
		t.Fatalf("Identify = %+v", d)
	}
	if !reflect.DeepEqual(p.TeamsOf("lin"), []string{"engineering", "payments"}) {
		t.Fatal(p.TeamsOf("lin"))
	}
	var got []string
	for _, s := range p.ScopesOf("lin") {
		got = append(got, s.Name())
	}
	if !reflect.DeepEqual(got, []string{"checkout/dev", "checkout/prod", "search/dev"}) {
		t.Fatalf("ScopesOf(lin) = %v", got)
	}
	got = nil
	for _, s := range p.ScopesOf("machine:deploy-checkout") {
		got = append(got, s.Name())
	}
	if !reflect.DeepEqual(got, []string{"checkout/prod"}) {
		t.Fatalf("ScopesOf(machine) = %v", got)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestLoadTrunkRules exercises what the CLI does: ResolveTrunk from the
// environment, git config and remotes, then LoadTrunkAt. Nothing in the
// working tree takes part.
func TestLoadTrunkRules(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	f := newFixture(t)
	git(t, f.root, "init", "-q", "-b", "main")
	repo, err := gitx.Find(f.root)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	load := func() (*Policy, error) { return LoadTrunkWith(repo, getenv) }
	mustLoad := func() *Policy {
		t.Helper()
		p, err := load()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 1. A new local repository: no override, no remote. Bootstrap.
	p := mustLoad()
	if p.Origin != OriginBootstrap || p.Trunk.From != TrunkFromNone || !strings.Contains(p.Notice, "no trunk yet") {
		t.Fatalf("new repo: origin %s trunk %+v notice %q", p.Origin, p.Trunk, p.Notice)
	}

	// 2. An override that does not resolve is always an error.
	git(t, f.root, "config", "--local", TrunkConfigKey, "main")
	var missing *TrunkMissingError
	if _, err := load(); !errors.As(err, &missing) || missing.From != TrunkFromGitConfig {
		t.Fatalf("unborn override: %v", err)
	}

	// 3. The ref exists without carbon.toml: bootstrap.
	f.write("README", "x")
	git(t, f.root, "add", "README")
	git(t, f.root, "commit", "-qm", "readme")
	if p = mustLoad(); p.Origin != OriginBootstrap || !strings.Contains(p.Notice, "has no carbon.toml") {
		t.Fatalf("origin %s notice %q", p.Origin, p.Notice)
	}

	// 4. carbon on trunk: policy comes from the ref, not the working tree.
	git(t, f.root, "add", "-A")
	git(t, f.root, "commit", "-qm", "carbon")
	git(t, f.root, "checkout", "-qb", "feature")
	f.write(".carbon/teams.toml", "engineering = [\"ada\"]\npayments = [\"ada\"]\nsre = [\"ada\"]\n")
	p = mustLoad()
	if p.Origin != OriginTrunk || p.Notice != "" || p.Ref != "main" || p.Trunk.From != TrunkFromGitConfig {
		t.Fatalf("origin %s trunk %+v", p.Origin, p.Trunk)
	}
	if sa, _ := p.Scope("checkout", "prod"); sa.Names("ada/laptop") {
		t.Fatal("working-tree policy leaked into trunk policy")
	}
	wt, _ := LoadWorktree(f.root)
	if sa, _ := wt.Scope("checkout", "prod"); !sa.Names("ada/laptop") {
		t.Fatal("working tree policy not read")
	}

	// 5. CARBON_TRUNK beats git config; "worktree" only from these two.
	env[TrunkEnv] = "worktree"
	if p = mustLoad(); p.Origin != OriginWorktreeTrunk || p.Trunk.From != TrunkFromEnv {
		t.Fatalf("CARBON_TRUNK=worktree: %s %+v", p.Origin, p.Trunk)
	}
	env[TrunkEnv] = "--all"
	if _, err := load(); err == nil || !strings.Contains(err.Error(), TrunkEnv) {
		t.Fatalf("CARBON_TRUNK=--all: %v", err)
	}
	delete(env, TrunkEnv)
	git(t, f.root, "config", "--local", TrunkConfigKey, "HEAD")
	if _, err := load(); err == nil {
		t.Fatal("git config carbon.trunk HEAD accepted")
	}
	git(t, f.root, "config", "--local", TrunkConfigKey, "worktree")
	if p = mustLoad(); p.Origin != OriginWorktreeTrunk {
		t.Fatalf("git config worktree: %s", p.Origin)
	}

	// 6. No override: the remote default branch.
	git(t, f.root, "config", "--local", "--unset", TrunkConfigKey)
	git(t, f.root, "update-ref", "refs/remotes/origin/feature-x", "main")
	var none *NoTrunkError
	if _, err := load(); !errors.As(err, &none) {
		t.Fatalf("remotes without a default: %v", err)
	}
	git(t, f.root, "update-ref", "refs/remotes/origin/master", "main")
	if p = mustLoad(); p.Ref != "origin/master" || p.Trunk.From != TrunkFromRemote || p.Origin != OriginTrunk {
		t.Fatalf("origin/master: %+v %s", p.Trunk, p.Origin)
	}
	git(t, f.root, "update-ref", "refs/remotes/origin/main", "main")
	if p = mustLoad(); p.Ref != "origin/main" {
		t.Fatalf("origin/main preferred: %+v", p.Trunk)
	}
	git(t, f.root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/feature-x")
	if p = mustLoad(); p.Ref != "origin/feature-x" {
		t.Fatalf("origin/HEAD target: %+v", p.Trunk)
	}
	// A remote HEAD pointing nowhere is an error, not a fallback.
	git(t, f.root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/gone")
	if _, err := load(); !errors.As(err, &missing) || missing.From != TrunkFromRemote {
		t.Fatalf("dangling origin/HEAD: %v", err)
	}
	// carbon never wrote git config.
	if _, ok, _ := repo.ConfigGet(TrunkConfigKey); ok {
		t.Fatal("carbon wrote git config")
	}
}

func mustRead(t *testing.T, root, rel string) string {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
