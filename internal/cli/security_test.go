package cli_test

// Regression tests from the security review of the foundation. Each one
// failed before its fix.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

const (
	pkgFile     = "services/checkout/carbon.toml"
	keysFile    = "services/checkout/.carbon/prod.keys.toml"
	secretsFile = "services/checkout/.carbon/prod.secrets.toml"
	prodAccess  = `prod = ["@payments", "machine:deploy-checkout"]`
)

// addTrunkSetting puts the removed [workspace] trunk setting back into the
// working tree's carbon.toml, as an old file or an attacker's branch would.
func addTrunkSetting(w *clitest.World, value string) {
	w.Replace("carbon.toml", "[workspace]\n", "[workspace]\ntrunk = \""+value+"\"\n")
}

// Finding 1: a branch's carbon.toml chose the trunk. With trunk = "worktree"
// (or "HEAD") on her branch, ada replaced the scope key, and then sam's drop
// and lin's value on that branch went to a key she held. The setting is now
// gone; a file that has it is refused.
func TestBranchCannotChooseTrunk(t *testing.T) {
	for _, trunk := range []string{"worktree", "HEAD", "feature"} {
		t.Run(trunk, func(t *testing.T) {
			w := clitest.Standard(t)
			w.Lin.Stdin("sk_live_real").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
			w.Commit("lin sets stripe")

			w.Branch("evil")
			addTrunkSetting(w, trunk)
			w.Replace(pkgFile, prodAccess, `prod = ["@payments", "machine:deploy-checkout", "ada"]`)
			w.Git("rm", "-q", keysFile, secretsFile)
			res := w.Ada.Stdin("decoy").In(w.PkgDir).Run("set", "stripe_api_key", "--env", "prod")
			if res.Code == 0 || !strings.Contains(res.Stderr, "[workspace] trunk, which was removed") {
				t.Fatalf("ada's branch chose the trunk:\n%s", res)
			}
			if w.Read(keysFile) != "" {
				t.Fatal("a keys file was written")
			}
			w.Git("checkout", "main", "--", "carbon.toml", keysFile, secretsFile)
			w.Replace(pkgFile, `, "ada"]`, `]`)
			w.Commit("innocent change")

			w.Sam.Stdin("whsec_sam").In(w.PkgDir).Must("set", "webhook_secret", "--env", "prod")
			w.Lin.Stdin("sk_live_new").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
			g1 := w.Ada.In(w.PkgDir).Run("get", "webhook_secret", "--env", "prod")
			g2 := w.Ada.In(w.PkgDir).Run("get", "stripe_api_key", "--env", "prod")
			if strings.Contains(g1.Stdout, "whsec_sam") || strings.Contains(g2.Stdout, "sk_live_new") {
				t.Fatalf("non-reader ada read values set on her branch")
			}
		})
	}
}

// Finding 1: trunk names that are git syntax are refused, from every source.
func TestTrunkOptionInjection(t *testing.T) {
	w := clitest.Standard(t)
	for _, ref := range []string{"--all", "-h", "--output=/tmp/x", "main:carbon.toml", "@{-1}", "HEAD", "a..b"} {
		res := w.Sam.With("CARBON_TRUNK="+ref).Stdin("v").In(w.PkgDir).Run("set", "webhook_secret", "--env", "prod")
		if res.Code == 0 || !strings.Contains(res.Stderr, "not a plain git ref name") || !strings.Contains(res.Stderr, "CARBON_TRUNK") {
			t.Errorf("CARBON_TRUNK=%q:\n%s", ref, res)
		}
		w.SetTrunk(ref)
		res = w.Sam.Stdin("v").In(w.PkgDir).Run("set", "webhook_secret", "--env", "prod")
		if res.Code == 0 || !strings.Contains(res.Stderr, "git config carbon.trunk") {
			t.Errorf("git config carbon.trunk %q:\n%s", ref, res)
		}
		w.SetTrunk("main")
	}
	if w.Read(keysFile) != "" {
		t.Fatal("a key was created")
	}
	res := w.Anyone().Fails(2, "init", "--trunk", "--all")
	contains(t, "stderr", res.Stderr, "not a plain git ref name")
}

// Finding 1: with no override, the trunk is the remote default branch, and
// carbon never writes git config.
func TestTrunkIsTheRemoteDefaultBranch(t *testing.T) {
	w := clitest.Standard(t)
	w.Git("config", "--local", "--unset", "carbon.trunk")
	w.Git("update-ref", "refs/remotes/origin/main", "main")
	res := w.Lin.Stdin("v").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	if strings.Contains(res.Stderr, "notice") {
		t.Fatalf("unexpected notice:\n%s", res)
	}
	w.Commit("key")
	w.Git("update-ref", "refs/remotes/origin/main", "main")
	res = w.Ada.Stdin("x").In(w.PkgDir).Must("set", "webhook_secret", "--env", "prod")
	contains(t, "stdout", res.Stdout, "Dropped.")
	cmd := exec.Command("git", "config", "--local", "--get", "carbon.trunk")
	cmd.Dir = w.Dir
	if out, _ := cmd.Output(); len(out) > 0 {
		t.Fatalf("carbon wrote git config: %s", out)
	}
}

// Finding 1: remotes but no default and no override is an error with the
// fixes; so is an override that does not resolve. Never a silent fall back
// to working-tree policy.
func TestMissingTrunkWithRemotesIsAnError(t *testing.T) {
	w := clitest.Standard(t)
	w.Git("update-ref", "refs/remotes/origin/feature", "HEAD")
	w.SetTrunk("origin/main")
	res := w.Ada.Stdin("v").In(w.PkgDir).Fails(1, "set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "trunk origin/main", "does not exist", "git fetch", "git config carbon.trunk <ref>")

	w.Git("config", "--local", "--unset", "carbon.trunk")
	res = w.Ada.Stdin("v").In(w.PkgDir).Fails(1, "set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "cannot tell which branch is trunk", "git remote set-head origin -a", "git fetch", "git config carbon.trunk <ref>")
	if w.Read(keysFile) != "" {
		t.Fatal("a key was created from working-tree policy")
	}
}

// Finding 2: a reader verifies the working tree's keys file against
// trunk's. Ada builds her own key on a branch (her CARBON_TRUNK=worktree
// affects only her own process); lin must refuse to seal or read under it.
func TestReaderRefusesKeyNotFromTrunk(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk_live_real").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("lin sets stripe")

	w.Branch("evil")
	w.Replace(pkgFile, prodAccess, `prod = ["@payments", "machine:deploy-checkout", "ada"]`)
	w.Git("rm", "-q", keysFile, secretsFile)
	w.Ada.With("CARBON_TRUNK=worktree").Stdin("decoy").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Replace(pkgFile, `, "ada"]`, `]`)
	w.Commit("refresh keys")

	res := w.Lin.Stdin("sk_live_rotated").In(w.PkgDir).Fails(1, "set", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "does not descend from trunk", "git checkout refs/heads/main -- services/checkout/.carbon/prod.keys.toml")
	res = w.Lin.In(w.PkgDir).Fails(1, "get", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "does not descend from trunk")
	if g := w.Ada.In(w.PkgDir).Run("get", "stripe_api_key", "--env", "prod"); strings.Contains(g.Stdout, "sk_live_rotated") {
		t.Fatal("lin sealed under ada's key")
	}
	// Restoring trunk's keys file is the fix.
	w.Git("checkout", "main", "--", keysFile, secretsFile)
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_live_real" {
		t.Fatalf("after restore: %q", got)
	}
}

// Finding 3: only a reader creates a scope's key.
func TestNonReaderCannotCreateScope(t *testing.T) {
	w := clitest.Standard(t)
	res := w.Sam.In(w.PkgDir).Stdin("sk_from_sam").Fails(3, "set", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "nobody has created the key for checkout/prod yet",
		"carbon set", "carbon apply", "@payments and machine:deploy-checkout")
	w.Anyone().In(w.PkgDir).Stdin("x").Fails(3, "set", "stripe_api_key", "--env", "prod")
	if w.Read(keysFile) != "" {
		t.Fatal("keys file written")
	}
	w.Lin.In(w.PkgDir).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
}

// rotate rotates checkout/<env> as lin through the scope API (standing in
// for `carbon apply`), keeping lin and the deploy machine.
func rotate(t *testing.T, w *clitest.World, env, reason string) {
	t.Helper()
	data, err := os.ReadFile(w.Lin.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	ids, err := agewrap.ParseIdentityFile(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(filepath.Join(w.Dir, w.PkgDir), "checkout", env)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Open(ids)
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.LoadWorktree(w.Dir)
	sa, _ := pol.Scope("checkout", env)
	if _, err := o.Rotate(sa.Devices, reason, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

// Finding 7: a branch that already rotated past the local trunk ref means
// the local trunk is stale; a drop to its inbox would go to a retired key.
func TestDropRefusedWhenLocalTrunkIsBehind(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	w.Branch("rotated")
	rotate(t, w, "prod", "removed sam")
	w.Commit("rotate")
	res := w.Ada.Stdin("x").In(w.PkgDir).Fails(1, "set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "behind", "git fetch")
}

// Finding 4: a value under a retired key proves only that its writer held
// that key; ls says so.
func TestLsMarksValuesUnderRetiredKeys(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Lin.Stdin("wh").In(w.PkgDir).Must("set", "webhook_secret", "--env", "prod")
	old := regexp.MustCompile(`(?m)^webhook_secret = .*$`).FindString(w.Read(secretsFile))
	rotate(t, w, "prod", "removed sam")
	w.Replace(secretsFile, regexp.MustCompile(`(?m)^webhook_secret = .*$`).FindString(w.Read(secretsFile)), old)
	res := w.Lin.In(w.PkgDir).Must("ls", "--env", "prod")
	contains(t, "ls", res.Stdout, "webhook_secret   stale: retired key, author unproven", "stripe_api_key   sealed")
	contains(t, "ls --json", w.Lin.In(w.PkgDir).Must("ls", "--env", "prod", "--json").Stdout, `"unproven": true`)
	// Old branches still read it.
	if got := w.Lin.In(w.PkgDir).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "wh" {
		t.Fatalf("stale value = %q", got)
	}
}

// Finding 10: joining does not add anyone to a team once carbon is on trunk.
func TestJoinAddsToTeamsOnlyBeforeTrunk(t *testing.T) {
	r := clitest.NewWorkspace(t)
	r.Commit("carbon on trunk, no people yet")
	r.SetTrunk("main")
	r.Person("ada").Join()
	contains(t, "teams", r.Read(".carbon/teams.toml"), "engineering = []")
}

// B: a reader removed from trunk policy, whose slot still opens the key
// until the next rotation, cannot seal values that would look reader-made.
func TestRemovedReaderCannotSetBeforeRotation(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam"}, "payments": {}})
	w.Commit("remove lin from payments")
	res := w.Lin.Stdin("sk_after_removal").In(w.PkgDir).Fails(3, "set", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "trunk policy no longer names you for checkout/prod")
	// Reading is unaffected until the rotation.
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk" {
		t.Fatalf("get = %q", got)
	}
	// Still named: the machine may set.
	w.Deploy.Stdin("sk2").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
}
