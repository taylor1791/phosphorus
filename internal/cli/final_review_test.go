package cli_test

// Regression tests for the final review's findings.

import (
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
