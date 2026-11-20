package scope

// Regression tests for the security review of the foundation. Each failed
// (or did not compile) before its fix.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// cloneKeys deep-copies a keys file, as reading trunk's copy would.
func cloneKeys(t *testing.T, k *store.Keys) *store.Keys {
	t.Helper()
	c, err := store.ParseKeys("trunk", k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Finding 2: a reader verifies the working tree's keys against trunk's.
func TestVerifyTrunk(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	ada := newPerson(t, "ada/laptop", agewrap.KindHybrid)

	setup := func() (*Opened, *store.Keys) {
		o := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
		trunk := cloneKeys(t, o.Keys)
		s := reload(t, o.Scope)
		r, err := s.Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		return r, trunk
	}

	t.Run("same key", func(t *testing.T) {
		o, trunk := setup()
		if err := o.VerifyTrunk(trunk); err != nil {
			t.Fatal(err)
		}
		if err := o.VerifyTrunk(nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("same id, other inbox", func(t *testing.T) {
		o, trunk := setup()
		other := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
		trunk.CurrentKey().Inbox = other.Keys.CurrentKey().Inbox
		if err := o.VerifyTrunk(trunk); !errors.Is(err, ErrNotFromTrunk) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("attacker's fresh key", func(t *testing.T) {
		// Ada deletes the keys file on a branch and creates her own key,
		// wrapped to herself and lin: lin would seal under it.
		_, trunk := setup()
		evil := mustCreate(t, t.TempDir(), "checkout", "prod", lin, ada)
		s := reload(t, evil.Scope)
		o, _ := s.Open(lin.ids)
		if err := o.VerifyTrunk(trunk); !errors.Is(err, ErrNotFromTrunk) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("branch behind trunk", func(t *testing.T) {
		o, _ := setup()
		branch := cloneKeys(t, o.Keys)
		if _, err := o.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		trunk := cloneKeys(t, o.Keys) // trunk rotated; the branch did not
		s := &Scope{Package: "checkout", Env: "prod", Dir: o.Dir, Keys: branch, Secrets: store.NewSecrets()}
		b, err := s.Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.VerifyTrunk(trunk); err != nil {
			t.Fatalf("behind: %v", err)
		}
		// An attacker key reusing the id trunk retired is not accepted.
		evil := mustCreate(t, t.TempDir(), "checkout", "prod", lin, ada)
		ek := cloneKeys(t, evil.Keys)
		rec := ek.Keys[ek.Current]
		delete(ek.Keys, ek.Current)
		ek.Current = branch.Current
		ek.Keys[ek.Current] = rec
		// Re-wrap lin's slot under the reused id so it opens.
		key := evil.keys[evil.CurrentID()]
		r, _ := agewrap.ParseRecipient(lin.dev.Recipient)
		rec.Slots["lin/laptop"], _ = agewrap.WrapSlot(r, "checkout/prod", ek.Current, key)
		ad, _ := seal.InboxAD("checkout", "prod", ek.Current)
		inboxID, _ := seal.Open(key, evil.Keys.Keys[evil.CurrentID()].InboxSealed, func() []byte {
			b, _ := seal.InboxAD("checkout", "prod", evil.CurrentID())
			return b
		}())
		rec.InboxSealed, _ = seal.Seal(key, inboxID, ad)
		es := &Scope{Package: "checkout", Env: "prod", Dir: o.Dir, Keys: ek, Secrets: store.NewSecrets()}
		eo, err := es.Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		if err := eo.VerifyTrunk(trunk); !errors.Is(err, ErrNotFromTrunk) {
			t.Fatalf("reused retired id: %v", err)
		}
	})
	t.Run("branch rotated past trunk", func(t *testing.T) {
		o, trunk := setup()
		if _, err := o.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := o.VerifyTrunk(trunk); err != nil {
			t.Fatalf("legitimate rotation: %v", err)
		}
		// A forged chain: the attacker's key "retires" an id equal to
		// trunk's current, but that retired key is not trunk's key.
		evil := mustCreate(t, t.TempDir(), "checkout", "prod", lin, ada)
		fake := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
		fk := cloneKeys(t, fake.Keys)
		rec := fk.Keys[fk.Current]
		delete(fk.Keys, fk.Current)
		fk.Current = trunk.Current
		fk.Keys[fk.Current] = rec
		ek := cloneKeys(t, evil.Keys)
		retired := &store.Key{Created: t0, Retired: t0.Add(time.Hour), Reason: "x", Successor: ek.Current, Carried: []string{}}
		ad, _ := seal.RetiredAD("checkout", "prod", trunk.Current, ek.Current, retired.Retired, retired.Reason, "", retired.Carried)
		retired.Sealed, _ = seal.Seal(evil.keys[evil.CurrentID()], fake.keys[fake.CurrentID()][:], ad)
		ek.Keys[trunk.Current] = retired
		es := &Scope{Package: "checkout", Env: "prod", Dir: o.Dir, Keys: ek, Secrets: store.NewSecrets()}
		eo, err := es.Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		if err := eo.VerifyTrunk(trunk); !errors.Is(err, ErrNotFromTrunk) {
			t.Fatalf("forged chain: %v", err)
		}
	})
	t.Run("wrong scope", func(t *testing.T) {
		o, trunk := setup()
		trunk.Scope = "search/prod"
		if err := o.VerifyTrunk(trunk); !errors.Is(err, ErrWrongScope) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Finding 4: a removed reader keeps the old key and can seal under its id.
// Reveal still works (old branches), but the value is marked unproven and
// ResealUnproven reports it instead of silently laundering it.
func TestRetiredKeyForgeryIsFlagged(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin, sam)
	oldID := o.CurrentID()
	samKey := *o.keys[oldID]
	retiredAt := t0.Add(time.Hour)
	if _, err := o.Rotate(devices(lin), "removed sam", retiredAt); err != nil {
		t.Fatal(err)
	}
	s := reload(t, o.Scope)
	set := retiredAt.Add(24 * time.Hour)
	ad, _ := seal.ValueAD("checkout", "prod", "stripe_api_key", oldID, set)
	blob, _ := seal.Seal(&samKey, []byte("attacker-value"), ad)
	s.Secrets.Entries["stripe_api_key"] = store.Entry{Key: oldID, Set: set, Value: blob}

	st := s.StaleEntries()
	if len(st) != 1 || !st[0].SetAfterRetired || !st[0].KeyKnown || st[0].KeyID != oldID {
		t.Fatalf("StaleEntries = %+v", st)
	}
	list := s.List(map[string]config.Secret{"stripe_api_key": {}})
	if !list[0].Unproven || !list[0].SetAfterRetired || list[0].State() != "stale" {
		t.Fatalf("List = %+v", list)
	}
	r, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.Reveal("stripe_api_key"); err != nil || !v.Stale {
		t.Fatalf("Reveal: %+v %v", v, err)
	}
	res, err := r.ResealUnproven()
	if err != nil || len(res.Moved) != 1 || !res.Moved[0].SetAfterRetired {
		t.Fatalf("ResealUnproven = %+v %v", res, err)
	}
}

// Finding 5: one unopenable drop no longer blocks rotation or refresh.
func TestRotateSkipsDropsThatDoNotOpen(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	junk := newPerson(t, "x/y", agewrap.KindX25519)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin, sam)
	o.Seal("a", []byte("v"), t0)
	firstID := o.CurrentID()
	if err := o.Scope.Drop(Inbox{KeyID: firstID, Recipient: junk.dev.Recipient}, "junk", []byte("x"), t0); err != nil {
		t.Fatal(err)
	}
	junkEntry := o.Secrets.Entries["junk"]
	s := reload(t, o.Scope)
	r, _ := s.Open(lin.ids)
	valueEntry := s.Secrets.Entries["a"]
	if _, err := r.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// A rotation never touches the secrets file.
	if s.Secrets.Entries["junk"] != junkEntry || s.Secrets.Entries["a"] != valueEntry {
		t.Fatal("the rotation changed an entry")
	}
	if reveal(t, r, "a") != "v" {
		t.Fatal("value lost")
	}
	// Both were carried, so nothing is unproven.
	res, err := r.ResealUnproven()
	if err != nil || len(res.SkippedDrops) != 0 || len(res.Moved) != 0 {
		t.Fatalf("reseal: %+v %v", res, err)
	}
	if _, err := r.Rotate(devices(lin), "removed ada", t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("Rotate with a junk drop: %v", err)
	}
}

// Finding 6: a dropper chooses the set time; promotion clamps a future one.
func TestPromoteClampsFutureSetTime(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	future := t0.Add(365 * 24 * time.Hour)
	o.Scope.Drop(Inbox{KeyID: o.CurrentID(), Recipient: o.Keys.CurrentKey().Inbox}, "f", []byte("x"), future)
	o.Scope.Drop(Inbox{KeyID: o.CurrentID(), Recipient: o.Keys.CurrentKey().Inbox}, "p", []byte("y"), t0)
	now := t0.Add(time.Hour)
	done, err := o.PromoteDropsAt(now)
	if err != nil || len(done) != 2 {
		t.Fatal(done, err)
	}
	if got := o.Secrets.Entries["f"].Set; !got.Equal(now) {
		t.Fatalf("future set kept: %v", got)
	}
	if got := o.Secrets.Entries["p"].Set; !got.Equal(t0) {
		t.Fatalf("past set changed: %v", got)
	}
}

// Finding 11: a retired inbox_sealed that fails to open is tampering, and
// drops under it say so.
func TestTamperedRetiredInboxIsReported(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	firstID := o.CurrentID()
	o.Scope.Drop(Inbox{KeyID: firstID, Recipient: o.Keys.CurrentKey().Inbox}, "d", []byte("x"), t0)
	drop := o.Secrets.Entries["d"]
	if _, err := o.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	other := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	o.Keys.Keys[firstID].InboxSealed = other.Keys.CurrentKey().InboxSealed
	s := reload(t, o.Scope)
	s.Secrets.Entries["d"] = drop
	r, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reveal("d"); !errors.Is(err, ErrTampered) {
		t.Fatalf("err = %v", err)
	}
}

// Slots record the recipient they were wrapped to, so DiffSlots catches a
// device re-added with a new key, and a removed reader who relabels his own
// slot line as another device's.
func TestDiffSlotsByRecipient(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin, sam)
	cur := o.Keys.CurrentKey()
	if cur.SlotTo["lin/laptop"] != lin.dev.RecipientHash() || cur.SlotTo["lin/laptop"] != agewrap.RecipientHash(lin.dev.Recipient) {
		t.Fatalf("to = %q", cur.SlotTo["lin/laptop"])
	}
	if d := o.DiffSlots(devices(lin, sam)); len(d.Missing)+len(d.Extra)+len(d.Rekeyed) != 0 {
		t.Fatalf("clean diff: %+v", d)
	}

	// sam's laptop is re-added with a new key under the same device id.
	sam2 := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	d := o.DiffSlots(devices(lin, sam2))
	if len(d.Rekeyed) != 1 || d.Rekeyed[0].ID != "sam/laptop" ||
		len(d.Missing) != 1 || d.Missing[0].ID != "sam/laptop" ||
		len(d.Extra) != 1 || d.Extra[0] != "sam/laptop" {
		t.Fatalf("rekeyed: %+v", d)
	}
	// AddSlots does not paper over it; only a rotation does.
	if added, _ := o.AddSlots(devices(lin, sam2)); len(added) != 0 {
		t.Fatalf("AddSlots replaced a rekeyed slot: %v", added)
	}
	if _, err := o.Rotate(devices(lin, sam2), "removed sam/laptop", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if d := o.DiffSlots(devices(lin, sam2)); len(d.Missing)+len(d.Extra)+len(d.Rekeyed) != 0 {
		t.Fatalf("after rotation: %+v", d)
	}

	// Removed sam relabels his slot as lin's: the recorded `to` gives him away.
	o2 := mustCreate(t, t.TempDir(), "checkout", "prod", lin, sam)
	k := o2.Keys.CurrentKey()
	k.Slots["lin/laptop"], k.SlotTo["lin/laptop"] = k.Slots["sam/laptop"], k.SlotTo["sam/laptop"]
	delete(k.Slots, "sam/laptop")
	delete(k.SlotTo, "sam/laptop")
	d = o2.DiffSlots(devices(lin))
	if len(d.Rekeyed) != 1 || len(d.Extra) != 1 || d.Extra[0] != "lin/laptop" {
		t.Fatalf("relabelled slot: %+v", d)
	}
}

// A removed reader who kept a retired key cannot forge a record that
// carries a value of his choosing: the chain is authenticated backwards
// (each retired key names its predecessor in its associated data), and a
// record off the chain makes the scope refuse, naming it.
func TestForgedRetiredRecordIsRefused(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "dev", lin, sam)
	o.Seal("a", []byte("v"), t0)
	k1 := o.CurrentID()
	samKey := *o.keys[k1]
	if _, err := o.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Rotate(devices(lin), "removed ada/laptop", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s := reload(t, o.Scope)
	if s.Keys.Keys[k1].Predecessor != "" {
		t.Fatal("first key has a predecessor")
	}
	chain, err := s.Keys.Chain()
	if err != nil || len(chain) != 2 || chain[1] != k1 || s.Keys.Keys[chain[0]].Predecessor != k1 {
		t.Fatalf("chain %v %v", chain, err)
	}
	// sam forges kfake9 -> k1 with a fresh key sealed under k1, carrying
	// a value of his choosing.
	fake, _ := seal.NewKey()
	set := t0.Add(30 * time.Minute)
	vad, _ := seal.ValueAD("checkout", "dev", "forged", "kfake9", set)
	blob, _ := seal.Seal(fake, []byte("evil"), vad)
	e := store.Entry{Key: "kfake9", Set: set, Value: blob}
	carried := []string{store.LineHash("forged", e)}
	rad, _ := seal.RetiredAD("checkout", "dev", "kfake9", k1, t0.Add(time.Hour), "rekeyed sam/laptop", "", carried)
	sealed, _ := seal.Seal(&samKey, fake[:], rad)
	s.Keys.Keys["kfake9"] = &store.Key{Created: t0, Retired: t0.Add(time.Hour), Reason: "rekeyed sam/laptop", Successor: k1, Sealed: sealed, Carried: carried}
	s.Secrets.Entries["forged"] = e
	if _, err := s.Open(lin.ids); !errors.Is(err, ErrTampered) || !strings.Contains(err.Error(), "kfake9") {
		t.Fatalf("Open with a forged record: %v", err)
	}
	if !s.IsUnproven("forged", e) {
		t.Fatal("a value carried by a record off the chain counts as carried")
	}
	// Rewriting k1's predecessor to point at the forgery breaks k1's
	// authentication instead.
	s.Keys.Keys[k1].Predecessor = "kfake9"
	r, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reveal("a"); !errors.Is(err, ErrTampered) {
		t.Fatalf("value under a record with an edited predecessor: %v", err)
	}
	if _, err := r.Reveal("forged"); err == nil {
		t.Fatal("the forged value opened")
	}
}
