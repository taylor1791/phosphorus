package cli_test

// Regression tests for the final review's findings.

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

// Finding 1: a tag named like trunk ("main", "origin/main") must never
// stand in for the trunk branch. git resolves refs/tags/<x> before
// refs/heads/<x> and refs/remotes/<x>, and CI fetches tags.
func TestTrunkTagCannotStandInForTheBranch(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	real := w.Git("rev-parse", "HEAD")
	w.Git("update-ref", "refs/remotes/origin/main", "HEAD")

	// Off trunk, a commit that grants ada prod and replaces prod's key,
	// tagged with both trunk names.
	w.Branch("evil")
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`, `prod = ["@payments", "machine:deploy-checkout", "ada"]`)
	forgeKeys(t, w, "sk_forged")
	w.Commit("evil")
	w.Git("tag", "main")
	w.Git("tag", "origin/main")
	w.Checkout("main")

	for _, trunk := range []string{"", "CARBON_TRUNK=origin/main", "CARBON_TRUNK=refs/remotes/origin/main"} {
		env := []string{}
		if trunk != "" {
			env = append(env, trunk)
		}
		res := w.Anyone().With(env...).Must("check", "--json")
		if !strings.Contains(res.Stdout, `"commit": "`+real+`"`) {
			t.Fatalf("%s: check did not compare with the branch %s:\n%s", trunk, real, res.Stdout)
		}
		// get verifies against the branch's keys: the real value.
		res = w.Lin.With(env...).In(co).Must("get", "stripe_api_key", "--env", "prod")
		if res.Stdout != "sk_prod" {
			t.Fatalf("%s: get = %q", trunk, res.Stdout)
		}
		// apply reads policy from the branch: nothing for ada.
		res = w.Lin.With(env...).Must("apply", "--yes", "--dry-run")
		if strings.Contains(res.Stdout, "ada/laptop") {
			t.Fatalf("%s: apply used the tag's policy:\n%s", trunk, res)
		}
	}
	// The drop path takes the inbox from the branch, so a reader opens it.
	w.Ada.In(co).Stdin("wh_drop").Must("set", "webhook_secret", "--env", "prod")
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "wh_drop" {
		t.Fatalf("drop went to another inbox: %q", got)
	}
	// Naming a tag is refused outright.
	res := w.Anyone().With("CARBON_TRUNK=refs/tags/main").Fails(1, "check")
	mustContain(t, "check with a tag", res.Stderr, "never a tag")
	// The trunk line shows the full ref and the commit.
	res = w.Anyone().Must("check")
	mustContain(t, "check", res.Stdout, "Compared with trunk: refs/heads/main at "+real[:7])
}

// Finding 3: apply on a branch must not promote a drop trunk does not
// have: that would take an unreviewed value out of check's banner.
func TestApplyLeavesDropsThatAreNotOnTrunk(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	w.Branch("mallory")
	w.Ada.In(co).Stdin("evil").Must("set", "webhook_secret", "--env", "prod")
	w.Commit("drop")
	head := w.Git("rev-parse", "HEAD")
	res := w.Lin.Must("apply", "--yes")
	if w.Git("rev-parse", "HEAD") != head {
		t.Fatalf("apply committed on the drop's branch:\n%s", res)
	}
	ci(t, w.Repo, 0).has(t, "drop.pending", "checkout/prod webhook_secret")
	res = w.Lin.Must("apply", "--dry-run", "--env", "prod")
	mustNotContain(t, "plan", res.Stdout, "promotes drop")
	// Once trunk has it, apply promotes it.
	w.Checkout("main")
	w.Merge("mallory")
	res = w.Lin.Must("apply", "--yes")
	mustContain(t, "apply on trunk", res.Stdout, "promotes drop", "webhook_secret")
	ci(t, w.Repo, 0).lacks(t, "drop.pending")
}

// setTime rewrites the set time of name in a secrets file, as anyone with
// a text editor can.
func setTime(t *testing.T, w *clitest.World, file, name, newSet string) {
	t.Helper()
	s := w.Read(file)
	re := regexp.MustCompile(`(?m)^(` + name + ` = \{ key = "[^"]+", set = )[0-9TZ:-]+`)
	if !re.MatchString(s) {
		t.Fatalf("no line for %s in\n%s", name, s)
	}
	w.Write(file, re.ReplaceAllString(s, "${1}"+newSet))
}

// Finding 4: re-dating a line (same ciphertext, new set time) hid its
// rotation debt and passed check silently.
func TestRedatingCannotHideDebt(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")
	ci(t, w.Repo, 0).has(t, "debt.removal", "checkout/dev stripe_api_key")

	w.Branch("redate")
	setTime(t, w, co+"/.carbon/dev.secrets.toml", "stripe_api_key", "2099-01-01T00:00:00Z")
	setTime(t, w, co+"/.carbon/dev.secrets.toml", "session_key", time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"))
	w.Commit("innocent")
	cj := ci(t, w.Repo, 4)
	cj.has(t, "secret.redated", "error checkout/dev stripe_api_key", "error checkout/dev session_key")
	cj.has(t, "secret.future", "error checkout/dev stripe_api_key", "error checkout/dev session_key")
	cj.has(t, "debt.removal", "checkout/dev stripe_api_key", "checkout/dev session_key")
	res := w.Lin.Must("status", "--all")
	mustContain(t, "status", res.Stdout, "checkout/dev", "stripe_api_key")

	// A future set time on a fresh line is an error too.
	w.Checkout("main")
	w.Branch("future")
	w.Lin.In(co).Stdin("v").Must("set", "webhook_secret", "--env", "staging")
	setTime(t, w, co+"/.carbon/staging.secrets.toml", "webhook_secret", "2099-01-01T00:00:00Z")
	ci(t, w.Repo, 4).has(t, "secret.future", "checkout/staging webhook_secret")
}

// Finding 5: a rename done as documented failed check. It is now one
// banner item per scope, and any change beyond the rename is an error.
func TestJourneyRename(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	w.Branch("rename")
	w.Lin.Must("rename", "checkout", "shop", "--yes")
	w.Commit("rename checkout to shop")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "scope.renamed", "shop/dev", "shop/staging", "shop/prod")
	cj.lacks(t, "key.removed", "key.new", "trunk.unreadable", "key.changed", "slot.unbacked")
	for _, b := range cj.banner() {
		if b != "scope.renamed" {
			t.Fatalf("banner %v\n%s", cj.banner(), cj)
		}
	}
	// Anything beyond the rename is an error: a re-dated line here.
	keep := w.Read(co + "/.carbon/dev.secrets.toml")
	setTime(t, w, co+"/.carbon/dev.secrets.toml", "stripe_api_key", "2020-01-01T00:00:00Z")
	ci(t, w.Repo, 4).has(t, "key.changed", "error shop/dev")
	w.Write(co+"/.carbon/dev.secrets.toml", keep)

	w.Checkout("main")
	w.Merge("rename")
	ci(t, w.Repo, 0).clean(t)
	if got := w.Lin.In(co).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_prod" {
		t.Fatalf("get after rename = %q", got)
	}
	if got := w.Deploy.Must("get", "stripe_api_key", "--package", "shop", "--env", "prod").Stdout; got != "sk_prod" {
		t.Fatalf("deploy get after rename = %q", got)
	}
}

// Finding 8: a changed public key or a new device of an existing person
// is the most dangerous policy edit; it is in the banner, with the new
// key's fingerprint.
func TestKeyChangesInPolicyAreInTheBanner(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	w.Branch("swap")
	mal := w.Person("mallory")
	res := mal.Must("join", "--person", "malx", "--device", "laptop")
	fp := regexp.MustCompile(`Fingerprint\s+(\S+)`).FindStringSubmatch(res.Stdout)[1]
	newKey := regexp.MustCompile(`laptop = "([^"]+)"`).FindStringSubmatch(w.Read(".carbon/people/malx.toml"))[1]
	os.Remove(w.Path(".carbon/people/malx.toml"))
	lin := w.Read(".carbon/people/lin.toml")
	w.Write(".carbon/people/lin.toml", regexp.MustCompile(`laptop = "[^"]+"`).ReplaceAllString(lin, `laptop = "`+newKey+`"`))
	w.Write(".carbon/people/ada.toml", w.Read(".carbon/people/ada.toml")+"desk = \""+newKey+"\"\n")
	w.Commit("innocent-looking policy edit")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "policy.device-key-changed", "lin/laptop")
	cj.has(t, "policy.device-added", "ada/desk")
	res = w.Anyone().Must("check")
	mustContain(t, "banner", res.Stdout, "TO REVIEW", "KEY CHANGED for lin/laptop: new fingerprint "+fp, "NEW DEVICE ada/desk")
	ci(t, w.Repo, 0, "--strict") // review items, not failures
}

// Finding 9: check never bootstraps without --bootstrap, also when trunk
// resolves but carbon 1.0 is not on it.
func TestCheckNeverBootstrapsSilently(t *testing.T) {
	r := clitest.NewRepo(t)
	r.Write("README", "hello\n")
	r.Commit("readme")
	r.SetTrunk("main")
	r.Branch("adopt")
	ada := r.Person("ada")
	ada.Must("init")
	ada.Join()
	r.Commit("adopt carbon")
	res := r.Anyone().Fails(1, "check")
	mustContain(t, "check", res.Stderr, "no carbon 1.0 carbon.toml", "carbon check --bootstrap")
	r.Anyone().Must("check", "--bootstrap")
	// A carbon 0.0.3 root on trunk (the migration cutover) needs it too.
	r.Checkout("main")
	r.Write("carbon.toml", "name = \"svc\"\n\n[push]\nx = { value = \"1\" }\n")
	r.Commit("0.0.3 service")
	r.Checkout("adopt")
	r.Anyone().Fails(1, "check")
	r.Anyone().Must("check", "--bootstrap")
}

// Finding 11: a rotation's reason must be the one apply writes, or debt
// (which reads it) could be hidden or pinned on the wrong person.
func TestRotationReasonIsChecked(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Branch("rotate")
	w.Lin.Must("apply", "--yes")
	ci(t, w.Repo, 0).lacks(t, "key.changed")
	w.Replace(co+"/.carbon/dev.keys.toml", `reason = "removed sam"`, `reason = "routine rotation"`)
	w.Commit("edit reason")
	cj := ci(t, w.Repo, 4)
	cj.has(t, "key.changed", "error checkout/dev")
}

// Finding 12: keys files are not hidden from review: init does not mark
// them generated, and doctor does not ask for it.
func TestKeysFilesAreNotMarkedGenerated(t *testing.T) {
	w := clitest.Standard(t)
	if strings.Contains(w.Read(".gitattributes"), "linguist-generated") {
		t.Fatal("init marked keys files generated")
	}
	res := w.Lin.In(w.PkgDir).Run("doctor")
	mustNotContain(t, "doctor", res.Stdout+res.Stderr, "gitattributes", "generated")
}
