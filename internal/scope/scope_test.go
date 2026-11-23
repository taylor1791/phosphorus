package scope

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

type person struct {
	dev policy.Device
	ids []agewrap.Identity
}

func newPerson(t *testing.T, id string, kind agewrap.Kind) person {
	t.Helper()
	secret, rec, err := agewrap.GenerateIdentity(kind)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := agewrap.ParseIdentityFile([]byte(secret+"\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, d, _ := strings.Cut(id, "/")
	return person{dev: policy.Device{ID: id, Person: p, Device: d, Recipient: rec, Kind: kind}, ids: ids}
}

var t0 = time.Date(2026, 11, 2, 17, 4, 11, 0, time.UTC)

func devices(ps ...person) []policy.Device {
	var out []policy.Device
	for _, p := range ps {
		out = append(out, p.dev)
	}
	return out
}

func mustCreate(t *testing.T, dir, pkg, env string, ps ...person) *Opened {
	t.Helper()
	s, err := Load(dir, pkg, env)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Create(devices(ps...), t0)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func reload(t *testing.T, s *Scope) *Scope {
	t.Helper()
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
	n, err := Load(s.Dir, s.Package, s.Env)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func reveal(t *testing.T, o *Opened, name string) string {
	t.Helper()
	v, err := o.Reveal(name)
	if err != nil {
		t.Fatalf("Reveal(%s): %v", name, err)
	}
	return string(v.Bytes)
}

func TestCreateSealOpenReveal(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	deploy := newPerson(t, "machine:deploy", agewrap.KindX25519)
	ada := newPerson(t, "ada/laptop", agewrap.KindHybrid)
	dir := t.TempDir()

	o := mustCreate(t, dir, "checkout", "prod", lin, deploy)
	if err := o.Seal("stripe_api_key", []byte("sk_live_1"), t0.Add(1500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	s := reload(t, o.Scope)

	got, err := s.Open(lin.ids, "lin/laptop")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if got.Slot != "lin/laptop" || reveal(t, got, "stripe_api_key") != "sk_live_1" {
		t.Fatalf("slot %s", got.Slot)
	}
	v, _ := got.Reveal("stripe_api_key")
	if !v.Set.Equal(t0.Add(time.Second)) || v.Drop || v.Stale {
		t.Fatalf("value meta %+v", v)
	}
	// Without a preferred slot, the identity is found by trying every slot.
	if o2, err := s.Open(deploy.ids); err != nil || o2.Slot != "machine:deploy" {
		t.Fatalf("machine open: %v", err)
	}
	if _, err := s.Open(ada.ids, "ada/laptop"); !errors.Is(err, ErrNotReader) {
		t.Fatalf("non-reader: %v", err)
	}
	if _, err := s.Open(nil); !errors.Is(err, ErrNotReader) {
		t.Fatalf("no identity: %v", err)
	}
	if _, err := got.Reveal("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	// The files are what the contract says.
	keys, _ := os.ReadFile(s.KeysPath())
	if !strings.HasPrefix(string(keys), "scope = \"checkout/prod\"\ncurrent = \"k") {
		t.Fatalf("keys file:\n%s", keys)
	}
	sec, _ := os.ReadFile(s.SecretsPath())
	if !strings.Contains(string(sec), "[stripe_api_key]\nkey = \"k") || !strings.Contains(string(sec), "\nset = 2026-11-02T17:04:12Z\nvalue = \"carbon1:") {
		t.Fatalf("secrets file:\n%s", sec)
	}
}

func TestCreateNeedsDevicesAndOnlyOnce(t *testing.T) {
	s, _ := Load(t.TempDir(), "a", "dev")
	if _, err := s.Create(nil, t0); !errors.Is(err, ErrNoDevices) {
		t.Fatal(err)
	}
	p := newPerson(t, "a/b", agewrap.KindHybrid)
	if _, err := s.Create(devices(p), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(devices(p), t0); err == nil {
		t.Fatal("second create accepted")
	}
	if _, err := (&Scope{Package: "a", Env: "dev", Secrets: store.NewSecrets()}).Open(p.ids); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
}

// editSecrets rewrites one entry of a scope's secrets file.
func editEntry(t *testing.T, s *Scope, name string, fn func(e *store.Entry)) {
	t.Helper()
	e := s.Secrets.Entries[name]
	fn(&e)
	s.Secrets.Entries[name] = e
}

func TestSealedValuesCannotMove(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	root := t.TempDir()
	o := mustCreate(t, filepath.Join(root, "checkout"), "checkout", "prod", lin)
	o.Seal("a", []byte("A"), t0)
	o.Seal("b", []byte("B"), t0)
	s := reload(t, o.Scope)

	t.Run("renamed", func(t *testing.T) {
		s := reload(t, s)
		s.Secrets.Entries["c"] = s.Secrets.Entries["a"]
		o, _ := s.Open(lin.ids)
		if _, err := o.Reveal("c"); !errors.Is(err, ErrTampered) {
			t.Fatalf("renamed value: %v", err)
		}
	})
	t.Run("swapped", func(t *testing.T) {
		s := reload(t, s)
		s.Secrets.Entries["a"], s.Secrets.Entries["b"] = s.Secrets.Entries["b"], s.Secrets.Entries["a"]
		o, _ := s.Open(lin.ids)
		if _, err := o.Reveal("a"); !errors.Is(err, ErrTampered) {
			t.Fatalf("swapped value: %v", err)
		}
	})
	t.Run("set time edited", func(t *testing.T) {
		s := reload(t, s)
		editEntry(t, s, "a", func(e *store.Entry) { e.Set = e.Set.Add(24 * time.Hour) })
		o, _ := s.Open(lin.ids)
		if _, err := o.Reveal("a"); !errors.Is(err, ErrTampered) {
			t.Fatalf("edited set: %v", err)
		}
	})
	t.Run("ciphertext tampered", func(t *testing.T) {
		s := reload(t, s)
		editEntry(t, s, "a", func(e *store.Entry) {
			raw, _ := seal.Decode(e.Value)
			raw[len(raw)-3] ^= 0x40
			e.Value = seal.Prefix + seal.Encoding.EncodeToString(raw)
		})
		o, _ := s.Open(lin.ids)
		if _, err := o.Reveal("a"); !errors.Is(err, ErrTampered) {
			t.Fatalf("tampered: %v", err)
		}
		if reveal(t, o, "b") != "B" {
			t.Fatal("untouched value broke")
		}
	})
	t.Run("moved to another package and env", func(t *testing.T) {
		for _, target := range [][2]string{{"search", "prod"}, {"checkout", "dev"}} {
			other := mustCreate(t, filepath.Join(root, target[0]+target[1]), target[0], target[1], lin)
			other.Secrets.Entries["a"] = store.Entry{Key: other.CurrentID(), Set: t0, Value: s.Secrets.Entries["a"].Value}
			if _, err := other.Reveal("a"); !errors.Is(err, ErrTampered) {
				t.Fatalf("moved to %v: %v", target, err)
			}
		}
	})
}

func TestSlotCopiedFromAnotherScopeFails(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	ada := newPerson(t, "ada/laptop", agewrap.KindHybrid)
	root := t.TempDir()
	a := mustCreate(t, filepath.Join(root, "a"), "checkout", "dev", lin, ada)
	b := mustCreate(t, filepath.Join(root, "b"), "checkout", "prod", lin)
	// ada copies her checkout/dev slot into checkout/prod.
	b.Keys.CurrentKey().Slots["ada/laptop"] = a.Keys.CurrentKey().Slots["ada/laptop"]
	b.Keys.CurrentKey().SlotTo["ada/laptop"] = a.Keys.CurrentKey().SlotTo["ada/laptop"]
	bs := reload(t, b.Scope)
	if _, err := bs.Open(ada.ids, "ada/laptop"); !errors.Is(err, ErrTampered) {
		t.Fatalf("copied slot: %v", err)
	}
	// lin, a legitimate reader, is unaffected when his own slot is tried first.
	if _, err := bs.Open(lin.ids, "lin/laptop"); err != nil {
		t.Fatalf("lin: %v", err)
	}
	// A slot with the right scope but another key id also fails.
	b.Keys.CurrentKey().Slots["ada/laptop"] = a.Keys.CurrentKey().Slots["ada/laptop"]
	b.Keys.CurrentKey().SlotTo["ada/laptop"] = a.Keys.CurrentKey().SlotTo["ada/laptop"]
	b.Keys.Scope = "checkout/dev"
	if _, err := b.Scope.Open(ada.ids); !errors.Is(err, ErrTampered) {
		t.Fatalf("other key id: %v", err)
	}
}

func TestInboxSwapFailsForReaders(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	_, attacker, _ := agewrap.GenerateIdentity(agewrap.KindHybrid)
	o.Keys.CurrentKey().Inbox = attacker
	s := reload(t, o.Scope)
	if _, err := s.Open(lin.ids); !errors.Is(err, ErrInboxMismatch) {
		t.Fatalf("swapped inbox: %v", err)
	}
	// Swapping inbox_sealed too (for one sealed under another key) fails.
	other := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	s.Keys.CurrentKey().Inbox = other.Keys.CurrentKey().Inbox
	s.Keys.CurrentKey().InboxSealed = other.Keys.CurrentKey().InboxSealed
	if _, err := s.Open(lin.ids); !errors.Is(err, ErrTampered) {
		t.Fatalf("swapped inbox and sealed half: %v", err)
	}
}

func TestDropByNonReader(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	dir := t.TempDir()
	o := mustCreate(t, dir, "checkout", "prod", lin)
	trunkKeys := o.Keys // what the drop path would read from trunk
	s := reload(t, o.Scope)

	// ada has no slot and no key: she drops using the trunk inbox only.
	sa, _ := Load(dir, "checkout", "prod")
	inbox, err := TrunkInbox(trunkKeys, "checkout", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.Drop(inbox, "webhook_secret", []byte("whsec_1"), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := TrunkInbox(trunkKeys, "search", "prod"); !errors.Is(err, ErrWrongScope) {
		t.Fatal(err)
	}
	s = reload(t, sa)
	sec, _ := os.ReadFile(s.SecretsPath())
	if !strings.Contains(string(sec), "drop = \"age1:") {
		t.Fatalf("secrets:\n%s", sec)
	}

	r, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Reveal("webhook_secret")
	if err != nil || string(v.Bytes) != "whsec_1" || !v.Drop {
		t.Fatalf("reader reads drop: %+v %v", v, err)
	}

	// A drop moved to another name fails.
	s.Secrets.Entries["other"] = s.Secrets.Entries["webhook_secret"]
	if _, err := r.Reveal("other"); !errors.Is(err, ErrTampered) {
		t.Fatalf("moved drop: %v", err)
	}
	delete(s.Secrets.Entries, "other")

	// Promotion keeps the set time and turns it into a sealed value.
	ok, err := r.Promote("webhook_secret")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	v, _ = r.Reveal("webhook_secret")
	if v.Drop || !v.Set.Equal(t0) || string(v.Bytes) != "whsec_1" {
		t.Fatalf("promoted %+v", v)
	}
	if ok, _ := r.Promote("webhook_secret"); ok {
		t.Fatal("promoted a value")
	}
}

func TestRotateRetireAndChain(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	dir := t.TempDir()
	o := mustCreate(t, dir, "payments", "prod", lin, sam)
	o.Seal("stripe", []byte("sk_1"), t0)
	o.Scope.Drop(Inbox{KeyID: o.CurrentID(), Recipient: o.Keys.CurrentKey().Inbox}, "hook", []byte("wh_1"), t0)
	firstID := o.CurrentID()

	// An older branch: same scope before the rotation, with a value and a
	// drop that are not on trunk yet.
	branchValue := func() store.Entry {
		b := &Opened{Scope: &Scope{Package: o.Package, Env: o.Env, Keys: o.Keys, Secrets: store.NewSecrets()}, keys: o.keys, inboxes: o.inboxes}
		b.Seal("from_branch", []byte("old-branch"), t0.Add(time.Hour))
		return b.Secrets.Entries["from_branch"]
	}()
	branchDrop := func() store.Entry {
		sc := &Scope{Package: o.Package, Env: o.Env, Secrets: store.NewSecrets()}
		sc.Drop(Inbox{KeyID: firstID, Recipient: o.Keys.CurrentKey().Inbox}, "branch_drop", []byte("dropped-on-branch"), t0)
		return sc.Secrets.Entries["branch_drop"]
	}()

	later := t0.Add(48 * time.Hour)
	newID, err := o.Rotate(devices(lin), "removed sam", later)
	if err != nil {
		t.Fatal(err)
	}
	if newID == firstID || o.CurrentID() != newID {
		t.Fatal("current not moved")
	}
	old := o.Keys.Keys[firstID]
	if !old.IsRetired() || old.Reason != "removed sam" || old.Successor != newID || len(old.Slots) != 0 || old.Inbox != "" {
		t.Fatalf("retired record %+v", old)
	}
	// The secrets file is untouched: entries stay under the old key, which
	// lists them as carried.
	for _, name := range []string{"stripe", "hook"} {
		e := o.Secrets.Entries[name]
		if e.Key != firstID || !e.Set.Equal(t0) || o.IsUnproven(name, e) {
			t.Fatalf("%s moved by the rotation, or not carried: %+v", name, e)
		}
	}
	if len(old.Carried) != 2 {
		t.Fatalf("carried %v", old.Carried)
	}
	if !o.Secrets.Entries["hook"].IsDrop() {
		t.Fatal("rotation promoted a drop")
	}
	s := reload(t, o.Scope)

	if _, err := s.Open(sam.ids); !errors.Is(err, ErrNotReader) {
		t.Fatalf("removed device still reads: %v", err)
	}
	r, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if reveal(t, r, "stripe") != "sk_1" || reveal(t, r, "hook") != "wh_1" {
		t.Fatal("values lost in rotation")
	}

	// The older branch merges: its entries open through the retired key.
	s.Secrets.Entries["from_branch"] = branchValue
	s.Secrets.Entries["branch_drop"] = branchDrop
	v, err := r.Reveal("from_branch")
	if err != nil || string(v.Bytes) != "old-branch" || !v.Stale {
		t.Fatalf("value under retired key: %+v %v", v, err)
	}
	v, err = r.Reveal("branch_drop")
	if err != nil || string(v.Bytes) != "dropped-on-branch" || !v.Drop {
		t.Fatalf("drop under retired inbox: %+v %v", v, err)
	}
	res, err := r.ResealUnproven()
	var moved []string
	for _, m := range res.Moved {
		moved = append(moved, m.Name)
	}
	if err != nil || !reflect.DeepEqual(moved, []string{"branch_drop", "from_branch"}) {
		t.Fatalf("ResealUnproven = %v %v", moved, err)
	}
	if e := s.Secrets.Entries["stripe"]; e.Key != firstID {
		t.Fatalf("a carried value was re-sealed: %+v", e)
	}
	if e := s.Secrets.Entries["from_branch"]; e.Key != newID || !e.Set.Equal(t0.Add(time.Hour)) || e.IsDrop() {
		t.Fatalf("refreshed value %+v", e)
	}
	if e := s.Secrets.Entries["branch_drop"]; e.Key != newID || !e.IsDrop() {
		t.Fatalf("refreshed drop %+v", e)
	}

	// A second rotation: the chain k1 -> k2 -> k3 still opens k1 values.
	thirdID, err := r.Rotate(devices(lin), "removed ada/laptop", later.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s = reload(t, r.Scope)
	s.Secrets.Entries["from_branch"] = branchValue // sealed under k1, two keys back
	r3, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if r3.CurrentID() != thirdID {
		t.Fatal("third key")
	}
	if v, err := r3.Reveal("from_branch"); err != nil || string(v.Bytes) != "old-branch" {
		t.Fatalf("two-step chain: %v", err)
	}

	// Tampering with a retired record only breaks values under it.
	rec := s.Keys.Keys[firstID]
	rec.Reason = "removed nobody"
	r4, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r4.Reveal("from_branch"); !errors.Is(err, ErrTampered) {
		t.Fatalf("edited retirement reason: %v", err)
	}
	// stripe is carried under k1 too, so it breaks the same way.
	if _, err := r4.Reveal("stripe"); !errors.Is(err, ErrTampered) {
		t.Fatalf("carried value under an edited record: %v", err)
	}
	rec.Reason = "removed sam"

	// So does editing the carried list: its digest is authenticated.
	rec.Carried = append([]string{}, rec.Carried[1:]...)
	r5, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r5.Reveal("stripe"); !errors.Is(err, ErrTampered) {
		t.Fatalf("edited carried list: %v", err)
	}
}

// A rotation does not open values, so a damaged one does not stop it; the
// line is left exactly as it was.
func TestRotateLeavesBrokenValuesAlone(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "p", "dev", lin)
	o.Seal("a", []byte("x"), t0)
	editEntry(t, o.Scope, "a", func(e *store.Entry) { e.Set = e.Set.Add(time.Second) })
	broken := o.Secrets.Entries["a"]
	if _, err := o.Rotate(devices(lin), "removed sam", t0); err != nil {
		t.Fatalf("err = %v", err)
	}
	if o.Secrets.Entries["a"] != broken {
		t.Fatal("rotation changed a broken line")
	}
	if _, err := o.Rotate(devices(lin), "two\nlines", t0); err == nil {
		t.Fatal("multi-line reason accepted")
	}
}

func TestAddSlotsAndDiff(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	ada := newPerson(t, "ada/laptop", agewrap.KindX25519)
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "p", "dev", lin, sam)
	d := o.DiffSlots(devices(lin, ada))
	if len(d.Missing) != 1 || d.Missing[0].ID != "ada/laptop" || !reflect.DeepEqual(d.Extra, []string{"sam/laptop"}) {
		t.Fatalf("diff %+v", d)
	}
	added, err := o.AddSlots(devices(lin, ada))
	if err != nil || !reflect.DeepEqual(added, []string{"ada/laptop"}) {
		t.Fatal(added, err)
	}
	s := reload(t, o.Scope)
	if _, err := s.Open(ada.ids); err != nil {
		t.Fatalf("granted device: %v", err)
	}
	if !reflect.DeepEqual(s.SlotIDs(), []string{"ada/laptop", "lin/laptop", "sam/laptop"}) {
		t.Fatal(s.SlotIDs())
	}
}

func TestWrongScopeFileAndList(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	dir := t.TempDir()
	o := mustCreate(t, dir, "checkout", "prod", lin)
	o.Seal("a", []byte("x"), t0)
	o.Scope.Drop(Inbox{KeyID: o.CurrentID(), Recipient: o.Keys.CurrentKey().Inbox}, "d", []byte("y"), t0)
	o.Save()
	if _, err := Load(dir, "search", "prod"); err == nil {
		// search/prod reads search's own path, which is the same dir here,
		// so the scope line must catch it.
		t.Fatal("keys file of another scope accepted")
	}
	list := o.List(map[string]config.Secret{"a": {}, "b": {Private: true}})
	var states []string
	for _, st := range list {
		states = append(states, st.Name+"="+st.State())
	}
	if !reflect.DeepEqual(states, []string{"a=sealed", "b=unset", "d=undeclared"}) {
		t.Fatal(states)
	}
}

func TestKeyIDs(t *testing.T) {
	seen := map[string]*store.Key{}
	for i := 0; i < 200; i++ {
		id, err := newKeyID(seen)
		if err != nil || !config.ValidKeyID(id) {
			t.Fatalf("%q %v", id, err)
		}
		if seen[id] != nil {
			t.Fatal("duplicate")
		}
		seen[id] = &store.Key{}
	}
}
