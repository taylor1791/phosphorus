package cli_test

import (
	"os"
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

// A scope key that exists only on the branch is never extended, and the
// command exits 1 even though another scope was applied.
func TestApplyLeavesKeysThatAreNotOnTrunk(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	umSetAll(t, w)
	// prod has no key on trunk; dev has a pending grant for nia.
	w.Git("rm", "-q", co+"/.carbon/prod.keys.toml", co+"/.carbon/prod.secrets.toml")
	nia := w.Person("nia")
	nia.Join()
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam", "nia"}, "payments": {"lin", "nia"}})
	w.Commit("nia joins; prod has no key")

	// mallory's branch adds a prod key wrapped to lin, with her value.
	w.Branch("evil")
	rec := regexp.MustCompile(`laptop = "(age1[^"]+)"`).FindStringSubmatch(w.Read(".carbon/people/lin.toml"))[1]
	forged, err := scope.Load(t.TempDir(), "checkout", "prod")
	if err != nil {
		t.Fatal(err)
	}
	fo, err := forged.Create([]policy.Device{{ID: "lin/laptop", Recipient: rec, Kind: agewrap.RecipientKind(rec)}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fo.Seal("stripe_api_key", []byte("sk_mallory"), time.Now())
	w.Write(co+"/.carbon/prod.keys.toml", string(forged.Keys.Marshal()))
	w.Write(co+"/.carbon/prod.secrets.toml", string(forged.Secrets.Marshal()))
	w.Commit("set up prod")
	keys := w.Read(co + "/.carbon/prod.keys.toml")

	res := w.Lin.Fails(1, "apply", "--yes")
	contains(t, "apply", res.Stdout, "checkout/prod   (blocked)", "not on trunk refs/heads/main yet", "Merge the change that created it first", "Applied")
	if w.Read(co+"/.carbon/prod.keys.toml") != keys {
		t.Fatal("extended a key that is not on trunk")
	}
	if got := w.Git("show", "--name-only", "--format=", "HEAD"); strings.Contains(got, "prod") {
		t.Fatalf("committed prod: %s", got)
	}
	// The other scopes were applied.
	if v, _ := umGet(t, nia, "checkout", "dev", "stripe_api_key"); v != "sk_dev" {
		t.Fatal(v)
	}
	// --dry-run reports it too, with exit 1.
	w.Lin.Fails(1, "apply", "--dry-run", "--env", "prod")
}

// A rotation on a branch whose files differ from trunk's would re-seal a
// value the removed reader wrote under the still-current key.
func TestApplyRotatesOnlyFromTrunksFiles(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("real").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev value")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")

	// On a branch, sam (still holding the current dev key) replaces the
	// value. Written with the library, as `set` may refuse him.
	w.Branch("sam-branch")
	umSealAs(t, w, w.Sam, co, "dev", "stripe_api_key", "forged")
	w.Commit("sam's change")
	keys, secrets := w.Read(co+"/.carbon/dev.keys.toml"), w.Read(co+"/.carbon/dev.secrets.toml")

	head := umHead(w)
	res := w.Lin.Fails(1, "apply", "--yes", "--env", "dev")
	contains(t, "apply", res.Stdout, "checkout/dev   (blocked)", "differs from trunk refs/heads/main", "git checkout refs/heads/main")
	if umHead(w) != head || w.Read(co+"/.carbon/dev.keys.toml") != keys || w.Read(co+"/.carbon/dev.secrets.toml") != secrets {
		t.Fatal("rotated from a branch's files")
	}

	// On trunk itself the rotation runs, and sam's value is not there.
	w.Checkout("main")
	w.Lin.Must("apply", "--yes", "--env", "dev")
	if v, _ := umGet(t, w.Lin, "checkout", "dev", "stripe_api_key"); v != "real" {
		t.Fatal(v)
	}
}

// A rename and a directory move in one change leave nothing on trunk to
// compare the keys with.
func TestApplyRefusesRenamePlusMove(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod")
	w.Branch("rename")
	w.Lin.Must("rename", "checkout", "shop", "--yes")
	w.Commit("rename")
	w.Git("mv", co, "services/shop")
	w.Commit("move")
	for _, args := range [][]string{{"apply", "--dry-run", "--env", "prod"}, {"apply", "--yes", "--env", "prod"}} {
		res := w.Lin.Fails(1, args...)
		contains(t, strings.Join(args, " "), res.Stdout, "shop/prod   (blocked)", "cannot find shop/prod's key on trunk",
			"split the rename and the directory move into separate pull requests")
		if strings.Contains(res.Stdout, "gains access") {
			t.Fatalf("planned grants from the workspace default:\n%s", res)
		}
	}
	umClean(t, w)
}

func TestApplyRefusesToCommitOnDetachedHEAD(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	nia := w.Person("nia")
	nia.Join()
	w.Replace(co+"/carbon.toml", `"machine:deploy-checkout"]`, `"machine:deploy-checkout", "nia"]`)
	w.Commit("nia reads prod")
	w.Git("checkout", "-q", "--detach")
	res := w.Lin.Fails(1, "apply", "--yes", "--env", "prod")
	contains(t, "detached", res.Stderr, "HEAD is detached", "--no-commit")
	umClean(t, w)
	w.Lin.Must("apply", "--yes", "--env", "prod", "--no-commit")
	contains(t, "written", w.Git("status", "--porcelain"), "prod.keys.toml")
}

// A rename that cannot write one of its files restores the others.
func TestRenameIsAllOrNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	w := clitest.Standard(t)
	co := w.PkgDir
	w.AddPackage("services/web", "web", "[env]\nKEY = \"${checkout.stripe_api_key}\"\n")
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("values")
	web := w.Path("services/web")
	if err := os.Chmod(web, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(web, 0o755)
	res := w.Lin.Fails(1, "rename", "checkout", "shop", "--yes")
	contains(t, "rename", res.Stderr, "nothing was changed")
	umClean(t, w)
	if _, err := os.Stat(filepath.Join(web, "carbon.toml")); err != nil {
		t.Fatal(err)
	}
}

// A removed reader relabels his slot as a device that policy names and has
// no slot yet. The slot's `to` is not that device's key: apply rotates.
func TestApplyCatchesARelabelledSlot(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("v1").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev value")
	desk := w.Person("ada-desk")
	desk.Must("join", "--person", "ada", "--device", "desk")
	w.Commit("ada desk")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")

	w.Branch("sam-relabel")
	w.Replace(co+"/.carbon/dev.keys.toml", `"sam/laptop"`, `"ada/desk"`)
	w.Commit("carbon apply: grant ada/desk")
	w.Checkout("main")
	w.Merge("sam-relabel")

	res := w.Lin.Must("apply", "--yes", "--env", "dev")
	contains(t, "apply", res.Stdout, "key changed", "ada/desk's key changed", "rotates", `reason "rekeyed ada/desk"`)
	contains(t, "keys", w.Read(co+"/.carbon/dev.keys.toml"), `reason = "rekeyed ada/desk"`)
	w.Lin.In(co).Stdin("v2-after-removal").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("new value")
	g := w.Sam.Run("get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	if g.Code == 0 || strings.Contains(g.Stdout, "v2-after-removal") {
		t.Fatalf("removed sam reads a later value:\n%s", g)
	}
	if v, _ := umGet(t, desk, "checkout", "dev", "stripe_api_key"); v != "v2-after-removal" {
		t.Fatal(v)
	}
}

// A device removed and re-joined under the same id with a new key: the
// stolen identity must not read values set afterwards.
func TestApplyRotatesWhenADeviceRejoinsWithANewKey(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	desk := w.Person("ada-desk")
	desk.Must("join", "--person", "ada", "--device", "desk")
	w.Commit("ada desk")
	w.Ada.In(co).Stdin("v1").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev value")
	desk.Must("remove", "ada/laptop", "--yes")
	w.Commit("remove stolen laptop")
	newLaptop := w.Person("ada-new")
	newLaptop.Must("join", "--person", "ada", "--device", "laptop")
	w.Commit("ada's new laptop")
	fp := regexp.MustCompile(`Fingerprint\s+(\S+)`).FindStringSubmatch(newLaptop.Must("join", "--person", "ada", "--device", "laptop").Stdout)[1]

	// rename will not re-wrap a changed key: it names it and stops.
	res := w.Lin.Fails(1, "rename", "checkout", "shop", "--yes")
	contains(t, "rename", res.Stderr, "checkout/dev ada/laptop", fp, "carbon apply")
	umClean(t, w)

	res = w.Lin.Must("apply", "--yes", "--env", "dev")
	contains(t, "apply", res.Stdout, "ada/laptop's key changed", "new "+fp, `reason "rekeyed ada/laptop"`)
	w.Lin.In(co).Stdin("v2").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("v2")
	g := w.Ada.Run("get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	if g.Code == 0 || strings.Contains(g.Stdout, "v2") {
		t.Fatalf("the stolen laptop reads a later value:\n%s", g)
	}
	if v, _ := umGet(t, newLaptop, "checkout", "dev", "stripe_api_key"); v != "v2" {
		t.Fatal(v)
	}
	contains(t, "after", w.Lin.Must("apply", "--env", "dev").Stdout, "Nothing to do")
}

// umSealAs seals a value as p directly through the scope API (bypassing
// the CLI's checks, as a modified client could), and saves the files.
func umSealAs(t *testing.T, w *clitest.World, p *clitest.Person, dir, env, name, value string) {
	t.Helper()
	ids, err := agewrap.ParseIdentityFile(mustReadFile(t, p.IdentityFile()), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(w.Path(dir), "checkout", env)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Open(ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Seal(name, []byte(value), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
