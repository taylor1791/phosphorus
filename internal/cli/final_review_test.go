package cli_test

// Regression tests for the final review's findings.

import (
	"strings"
	"testing"

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
