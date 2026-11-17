package cli_test

import (
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

// TestSetAllowEmpty: an empty value is refused by default and stored with
// --allow-empty (carbon-migrate needs it for empty 0.0.3 values); it reads
// back empty, sealed and as a drop.
func TestSetAllowEmpty(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	res := w.Ada.In(co).Stdin("").Fails(2, "set", "webhook_secret")
	if !strings.Contains(res.Stderr, "--allow-empty") {
		t.Fatalf("refusal does not mention --allow-empty:\n%s", res.Stderr)
	}
	w.Ada.In(co).Stdin("\n").Must("set", "webhook_secret", "--allow-empty")
	if got := w.Ada.In(co).Must("get", "webhook_secret").Stdout; got != "" {
		t.Fatalf("get = %q, want empty", got)
	}
	// A drop: ada cannot read checkout/prod; lin can, once trunk has a key.
	w.Lin.In(co).Stdin("x").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")
	w.Ada.In(co).Stdin("").Must("set", "webhook_secret", "--env", "prod", "--allow-empty")
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "" {
		t.Fatalf("drop get = %q, want empty", got)
	}
}

// edit follows set's rule: emptying a value is refused unless
// --allow-empty is given; and an empty stored value counts as set in run,
// export and check.
func TestEditAllowEmptyAndEmptyValuesAreSet(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"\n[env]\nWEBHOOK = \"${webhook_secret}\"\n")
	setAll(t, w)

	r, _ := editRun(t, w, w.Lin, `HELPER_EDIT_SET={"webhook_secret":""}`)
	res := r.Fails(2, "edit", "--env", "dev")
	contains(t, "edit refuses", res.Stderr, "webhook_secret is empty", "--allow-empty")
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "dev").Stdout; got != "wh_dev" {
		t.Fatalf("refused edit changed the value: %q", got)
	}
	r, _ = editRun(t, w, w.Lin, `HELPER_EDIT_SET={"webhook_secret":""}`)
	res = r.Must("edit", "--env", "dev", "--allow-empty")
	contains(t, "edit --allow-empty", res.Stdout, "webhook_secret")
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "dev").Stdout; got != "" {
		t.Fatalf("get after emptying = %q", got)
	}
	w.Commit("empty webhook secret in dev")

	res = w.Lin.In(co).Must("run", "--env", "dev", "--", "printenv", "WEBHOOK")
	if res.Stdout != "\n" {
		t.Fatalf("run gave %q for an empty value", res.Stdout)
	}
	res = w.Lin.In(co).Must("export", "--env", "dev", "--format", "json")
	if !strings.Contains(res.Stdout, `"WEBHOOK": ""`) && !strings.Contains(res.Stdout, `"WEBHOOK":""`) {
		t.Fatalf("export = %s", res.Stdout)
	}
	res = w.Anyone().Must("check")
	if strings.Contains(res.Stdout, "secret.unset") {
		t.Fatalf("check treats an empty value as unset:\n%s", res)
	}
}
