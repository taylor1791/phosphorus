package cli_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

func pinsFile(w *clitest.World) string { return w.Read(".git/carbon/pins.toml") }

func pinnedKey(t *testing.T, w *clitest.World) string {
	t.Helper()
	m := regexp.MustCompile(`"checkout/prod" = \{ key = "(k[a-z0-9]{5})"`).FindAllStringSubmatch(pinsFile(w), -1)
	if len(m) != 1 {
		t.Fatalf("want one pin for checkout/prod:\n%s", pinsFile(w))
	}
	return m[0][1]
}

func currentKey(w *clitest.World) string {
	return regexp.MustCompile(`current = "(k[a-z0-9]{5})"`).FindStringSubmatch(w.Read(keysFile))[1]
}

// forgeKeys is what a non-reader can do without the scope key: generate a
// new key, wrap it to every device policy names, invent an inbox, and add a
// fabricated retired record for the old id (sealed under the new key, but
// holding bytes that are not the old key). The secrets file is re-sealed
// under the forged key with a value of the attacker's choosing.
func forgeKeys(t *testing.T, w *clitest.World, value string) string {
	t.Helper()
	old, err := store.ParseKeys("old", []byte(w.Read(keysFile)))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.LoadWorktree(w.Dir)
	sa, _ := pol.Scope("checkout", "prod")
	key, _ := seal.NewKey()
	newID := "kforge"
	now := time.Now().UTC().Truncate(time.Second)
	secret, inbox, _ := agewrap.GenerateIdentity(agewrap.KindHybrid)
	ad, _ := seal.InboxAD("checkout", "prod", newID)
	inboxSealed, _ := seal.Seal(key, []byte(secret), ad)
	rec := &store.Key{Created: now, Inbox: inbox, InboxSealed: inboxSealed, Slots: map[string]string{}, SlotTo: map[string]string{}}
	for _, d := range sa.Devices {
		r, _ := agewrap.ParseRecipient(d.Recipient)
		slot, _ := agewrap.WrapSlot(r, "checkout/prod", newID, key)
		rec.SetSlot(d.ID, d.RecipientHash(), slot)
	}
	var fake [32]byte
	rand.Read(fake[:])
	rad, _ := seal.RetiredAD("checkout", "prod", old.Current, newID, now, "removed sam")
	sealedOld, _ := seal.Seal(key, fake[:], rad)
	forged := &store.Keys{Scope: "checkout/prod", Current: newID, Keys: map[string]*store.Key{
		newID:       rec,
		old.Current: {Created: old.CurrentKey().Created, Retired: now, Reason: "removed sam", Successor: newID, Sealed: sealedOld},
	}}
	w.Write(keysFile, string(forged.Marshal()))
	vad, _ := seal.ValueAD("checkout", "prod", "stripe_api_key", newID, now)
	blob, _ := seal.Seal(key, []byte(value), vad)
	sec := &store.Secrets{Entries: map[string]store.Entry{"stripe_api_key": {Key: newID, Set: now, Value: blob}}}
	w.Write(secretsFile, string(sec.Marshal()))
	return newID
}

// (1) A forged keys file that lands on trunk passes the trunk check
// vacuously; a reader who opened the scope before refuses it.
func TestPinRefusesForgedKeyOnTrunk(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk_live_real").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_live_real" {
		t.Fatal(got)
	}
	first := pinnedKey(t, w)

	newID := forgeKeys(t, w, "sk_forged")
	w.Commit("routine key refresh") // merged to trunk
	for _, args := range [][]string{{"get", "stripe_api_key", "--env", "prod"}} {
		res := w.Lin.In(w.PkgDir).Fails(1, args...)
		contains(t, "stderr", res.Stderr,
			"the key for checkout/prod was replaced by someone who did not hold the previous key",
			"Pinned key:  "+first, "Current key: "+newID,
			"git log -p -- services/checkout/.carbon/prod.keys.toml",
			"carbon trust checkout --env prod")
	}
	res := w.Lin.In(w.PkgDir).Stdin("sk_new").Fails(1, "set", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "was replaced by someone who did not hold the previous key")
	if pinnedKey(t, w) != first {
		t.Fatal("a refused key moved the pin")
	}

	// trust shows what it is about to trust and needs confirmation.
	res = w.Lin.In(w.PkgDir).Fails(7, "trust", "--env", "prod")
	contains(t, "stderr", res.Stderr, "Pinned", first, "Current", newID, "routine key refresh")
	res = w.Lin.Must("trust", "checkout", "--env", "prod", "--yes")
	contains(t, "stdout", res.Stdout, "Trusted key "+newID+" for checkout/prod.")
	if pinnedKey(t, w) != newID {
		t.Fatal("trust did not re-pin")
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_forged" {
		t.Fatalf("after trust: %q", got)
	}
	contains(t, "trust again", w.Lin.Must("trust", "checkout", "--env", "prod").Stdout, "already trusted")
}

// (2) A legitimate rotation (by someone who held the key) moves the pin.
func TestPinFollowsLegitimateRotation(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	w.Deploy.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod")
	if strings.Count(pinsFile(w), `"checkout/prod"`) != 2 {
		t.Fatalf("want a pin for lin (creation) and for the machine (first open):\n%s", pinsFile(w))
	}
	rotate(t, w, "prod", "removed sam")
	w.Commit("rotate")
	res := w.Deploy.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod")
	if res.Stdout != "sk" || res.Stderr != "" {
		t.Fatalf("rotation was not silent:\n%s", res)
	}
	w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod")
	if strings.Count(pinsFile(w), `key = "`+currentKey(w)+`"`) != 2 {
		t.Fatalf("pins did not move to %s:\n%s", currentKey(w), pinsFile(w))
	}
}

// (3) A branch behind trunk still opens, and does not move the pin back.
func TestPinAllowsBranchBehindTrunk(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	w.Branch("old")
	w.Checkout("main")
	rotate(t, w, "prod", "removed sam")
	w.Commit("rotate")
	w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod")
	newer := currentKey(w)
	w.Checkout("old")
	if currentKey(w) == newer {
		t.Fatal("branch is not behind")
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk" {
		t.Fatal(got)
	}
	if !strings.Contains(pinsFile(w), `key = "`+newer+`"`) {
		t.Fatal("pin moved back")
	}
}

// (4) The first open pins (per identity), in the clone's common git dir.
func TestFirstOpenPins(t *testing.T) {
	w := clitest.Standard(t)
	w.Lin.Stdin("sk").In(w.PkgDir).Must("set", "stripe_api_key", "--env", "prod")
	if strings.Count(pinsFile(w), `"checkout/prod"`) != 1 {
		t.Fatalf("creation did not pin:\n%s", pinsFile(w))
	}
	w.Deploy.In(w.PkgDir).Must("get", "stripe_api_key", "--env", "prod")
	if strings.Count(pinsFile(w), `"checkout/prod"`) != 2 || strings.Count(pinsFile(w), "[readers.") != 2 {
		t.Fatalf("first open did not pin per identity:\n%s", pinsFile(w))
	}
	fi, err := os.Stat(filepath.Join(w.Dir, ".git", "carbon", "pins.toml"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pins file: %v %v", fi, err)
	}
	// A corrupt pins file is an error with the fix, never ignored.
	w.Write(".git/carbon/pins.toml", "garbage [")
	res := w.Lin.In(w.PkgDir).Fails(1, "get", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "pins.toml is corrupt", "rm ")
}
