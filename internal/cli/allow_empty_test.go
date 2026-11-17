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
