package cli_test

import (
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

// A branch whose checkout/dev keys file holds a key that does not descend
// from trunk's: run, export and edit refuse to read under it.
func TestRunExportEditRefuseKeyNotFromTrunk(t *testing.T) {
	w := runWorld(t) // trunk main has checkout/dev and db/dev keys
	helper := childHelper(t)

	// Branch off before the secrets commit, and make a fresh checkout/dev
	// key there with trunk overridden to the working tree.
	w.Git("checkout", "-q", "-b", "rogue", "HEAD~1")
	w.Lin.With("CARBON_TRUNK=worktree").In(w.PkgDir).Stdin("ROGUE-STRIPE").Must("set", "stripe_api_key")
	w.Lin.With("CARBON_TRUNK=worktree").In(w.PkgDir).Stdin("ROGUE-SESSION").Must("set", "session_key")
	w.Git("checkout", "-q", "main", "--", "services/db/.carbon")
	// Sanity: under the override the branch's key reads fine.
	w.Lin.With("CARBON_TRUNK=worktree", "FROM_SHELL=x").In(w.PkgDir).Must("run", "--", helper, "env")

	for _, args := range [][]string{{"run", "--", helper, "env"}, {"export"}, {"export", "--format", "json"}} {
		res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(1, args...)
		contains(t, "stderr", res.Stderr, "the key for checkout/dev on this branch does not descend from trunk's",
			"git checkout refs/heads/main -- services/checkout/.carbon/dev.keys.toml")
		if strings.Contains(res.Stdout, "ROGUE") || strings.Contains(res.Stderr, "ROGUE") || res.Stdout != "" {
			t.Fatalf("a value under the rogue key was released:\n%s", res)
		}
		noLeak(t, res)
	}
	r, _ := editRun(t, w, w.Lin)
	res := r.Fails(1, "edit")
	contains(t, "stderr", res.Stderr, "does not descend from trunk's")
	if strings.Contains(res.Stdout+res.Stderr, "ROGUE") {
		t.Fatalf("edit released a value:\n%s", res)
	}
}

// The command and the editor never receive carbon's identity variables.
func TestRunAndEditScrubIdentityVariables(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.Lin.In(w.PkgDir).Stdin(stripeValue).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")

	// The machine reads with CARBON_IDENTITY; a bogus CARBON_IDENTITY_FILE too.
	res := w.Deploy.With("CARBON_IDENTITY_FILE=/nonexistent").In("services/empty").Must("run", "--", helper, "env")
	env := envMap(parseChild(t, res).Env)
	for _, k := range []string{"CARBON_IDENTITY", "CARBON_IDENTITY_FILE"} {
		if _, ok := env[k]; ok {
			t.Fatalf("the command received %s", k)
		}
	}
	if strings.Contains(res.Stdout, "AGE-SECRET-KEY") {
		t.Fatal("the private key reached the command")
	}

	// The editor (checkEditLog asserts identity-vars=false).
	r, log := editRun(t, w, w.Deploy, `HELPER_EDIT_SET={"webhook_secret":"whsec_1"}`)
	r.Must("edit", "--env", "prod")
	checkEditLog(t, log)
}

func TestDoctorTrunkSources(t *testing.T) {
	w := clitest.Standard(t)
	res := w.Ada.With("CARBON_TRUNK=nope").Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  trunk", "trunk nope (from CARBON_TRUNK) does not exist", "fix: ")
	res = w.Ada.With("CARBON_TRUNK=worktree").Must("doctor")
	contains(t, "doctor", res.Stdout, `WARN  trunk`, `trunk is "worktree" (from CARBON_TRUNK)`, "unset CARBON_TRUNK")

	// A workspace file that still names a trunk.
	w.Replace("carbon.toml", "[workspace]\n", "[workspace]\ntrunk = \"main\"\n")
	res = w.Ada.Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  workspace", "Delete the trunk line from carbon.toml")
}
