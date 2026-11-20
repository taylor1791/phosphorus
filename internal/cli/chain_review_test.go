package cli_test

// Regression tests for the chain re-review.

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// twoRotations: K0 -> K1 (ada removed, sam stays), K1 -> K2 (sam removed).
// Returns sam's K1 id and key (taken from his slot before his removal).
func twoRotations(t *testing.T, w *clitest.World) (string, *seal.Key) {
	co := w.PkgDir
	setAll(t, w)
	w.Lin.Must("remove", "ada", "--yes")
	w.Commit("remove ada")
	w.Lin.Must("apply", "--yes")
	w.Commit("rotate 1")
	k1id, k1 := samOldKey(t, w, w.Read(co+"/.carbon/dev.keys.toml"), "checkout/dev")
	w.Lin.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")
	w.Commit("rotate 2")
	ci(t, w.Repo, 0)
	return k1id, k1
}

// Finding 1: sam, removed at the second rotation and holding K1, rewrites
// K0's record (sealed under K1) so that it carries a value of his choosing.
// K1's record, sealed under K2, holds the digest of K0's record, so the
// chain breaks there and nothing under K1 or K0 opens.
func TestRewritingAnOlderRetiredRecordIsDetected(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	k1id, k1 := twoRotations(t, w)
	kf := co + "/.carbon/dev.keys.toml"
	sf := co + "/.carbon/dev.secrets.toml"
	ks, _ := store.ParseKeys("k", []byte(w.Read(kf)))
	ss, _ := store.ParseSecrets("s", []byte(w.Read(sf)))
	k0id := ks.Keys[k1id].Predecessor
	if k0id == "" {
		t.Fatal("K1 has no predecessor")
	}
	r0 := ks.Keys[k0id]
	ad, _ := seal.RetiredAD("checkout", "dev", k0id, r0.Successor, r0.Retired, r0.Reason, r0.Predecessor, ks.RecordDigest(r0.Predecessor), r0.Carried)
	raw, err := seal.Open(k1, r0.Sealed, ad)
	if err != nil {
		t.Fatal(err)
	}
	k0, _ := seal.KeyFromBytes(raw)
	name := "stripe_api_key"
	old := ss.Entries[name]
	if old.Key != k0id {
		t.Fatalf("stripe under %s", old.Key)
	}
	vad, _ := seal.ValueAD("checkout", "dev", name, k0id, old.Set)
	blob, _ := seal.Seal(k0, []byte("sk_EVIL"), vad)
	ne := store.Entry{Key: k0id, Set: old.Set, Value: blob}
	var carried []string
	for _, h := range r0.Carried {
		if h != store.LineHash(name, old) {
			carried = append(carried, h)
		}
	}
	carried = append(carried, store.LineHash(name, ne))
	sort.Strings(carried)
	nad, _ := seal.RetiredAD("checkout", "dev", k0id, r0.Successor, r0.Retired, r0.Reason, r0.Predecessor, ks.RecordDigest(r0.Predecessor), carried)
	r0.Sealed, _ = seal.Seal(k1, raw, nad)
	r0.Carried = carried
	ss.Entries[name] = ne
	w.Branch("sam-pr")
	w.Write(kf, string(ks.Marshal()))
	w.Write(sf, string(ss.Marshal()))
	w.Commit("innocuous")

	res := w.Lin.In(co).Fails(1, "get", name, "--env", "dev")
	mustContain(t, "get", res.Stderr, k1id, k0id, "restore the keys file from trunk")
	mustNotContain(t, "get", res.Stdout+res.Stderr, "sk_EVIL")
	ci(t, w.Repo, 4).has(t, "key.retired-changed", "error checkout/dev")
	_ = time.Now
	_ = strings.Contains
}
