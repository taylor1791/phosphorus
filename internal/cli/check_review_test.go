package cli_test

import (
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

// A CI checkout of one commit has no remote-tracking refs: check must not
// fall back to judging the branch by itself.
func TestCheckWithNoTrunkNeedsBootstrap(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	w.Git("config", "--unset", "carbon.trunk")
	res := w.Anyone().Fails(1, "check")
	contains(t, "stderr", res.Stderr, "check has no trunk to compare with", "In CI: set CARBON_TRUNK", "carbon check --bootstrap")
	res = w.Anyone().Must("check", "--bootstrap")
	contains(t, "check", res.Stdout, "Compared with trunk: none yet")
}

func TestStatusDoesNotUnlockByDefault(t *testing.T) {
	r := clitest.NewWorkspace(t)
	lin := r.Person("lin")
	lin.Stdin("correct horse\n").Must("join", "--person", "lin", "--device", "laptop", "--passphrase")
	res := lin.Must("status")
	contains(t, "status", res.Stdout, "passphrase-protected", "carbon status --unlock")
	// --unlock without a terminal (as with a wrong passphrase) means "no
	// usable identity", not an abort.
	res = lin.Must("status", "--unlock")
	contains(t, "status", res.Stdout, "Your identity could not be loaded")
}
