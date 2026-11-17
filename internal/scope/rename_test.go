package scope

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/store"
)

func TestRename(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	deploy := newPerson(t, "machine:deploy", agewrap.KindX25519)
	dir := t.TempDir()
	o := mustCreate(t, dir, "old", "prod", lin, deploy)
	o.Seal("a", []byte("A"), t0)
	firstID := o.CurrentID()
	firstInbox := Inbox{KeyID: firstID, Recipient: o.Keys.CurrentKey().Inbox}
	if _, err := o.Rotate(devices(lin, deploy), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	o.Seal("b", []byte("B"), t0.Add(2*time.Hour))
	// A value from a branch cut before the rotation (sealed under the
	// retired key) and drops to both inboxes.
	b := &Opened{Scope: o.Scope, keys: o.keys, inboxes: o.inboxes}
	cur := o.Keys.Current
	o.Keys.Current = firstID
	b.Seal("stale", []byte("S"), t0.Add(30*time.Minute))
	o.Keys.Current = cur
	if err := o.Scope.Drop(firstInbox, "old_drop", []byte("D1"), t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := o.Scope.Drop(Inbox{KeyID: cur, Recipient: o.Keys.CurrentKey().Inbox}, "new_drop", []byte("D2"), t0.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s := reload(t, o.Scope)
	o, err := s.Open(lin.ids)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]*Value{}
	for _, n := range []string{"a", "b", "stale", "old_drop", "new_drop"} {
		v, err := o.Reveal(n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		before[n] = v
	}

	// A slot with no device to re-wrap to stops the rename untouched.
	if err := o.Rename("new", devices(lin)); err == nil || !strings.Contains(err.Error(), "machine:deploy") {
		t.Fatalf("missing device: %v", err)
	}
	if o.Package != "old" || o.Keys.Scope != "old/prod" {
		t.Fatal("failed rename changed the scope")
	}
	if err := o.Rename("Bad Name", devices(lin, deploy)); err == nil {
		t.Fatal("bad name accepted")
	}

	if err := o.Rename("new", devices(lin, deploy)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "old", "prod"); !errors.Is(err, ErrWrongScope) {
		t.Fatalf("old name still loads: %v", err)
	}
	for _, p := range []person{lin, deploy} {
		s, err := Load(dir, "new", "prod")
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Open(p.ids)
		if err != nil {
			t.Fatalf("%s: %v", p.dev.ID, err)
		}
		for n, want := range before {
			v, err := r.Reveal(n)
			if err != nil {
				t.Fatalf("%s %s: %v", p.dev.ID, n, err)
			}
			if string(v.Bytes) != string(want.Bytes) || !v.Set.Equal(want.Set) || v.Drop != want.Drop || v.KeyID != want.KeyID {
				t.Fatalf("%s changed: %+v vs %+v", n, v, want)
			}
		}
		if rec := s.Keys.Keys[firstID]; rec.Reason != "removed sam" || !rec.IsRetired() {
			t.Fatalf("retired record %+v", rec)
		}
	}

	// A renamed file copied back under the old name does not open as the
	// old package: the binding moved.
	s2, _ := Load(dir, "new", "prod")
	s2.Package = "old"
	s2.Keys.Scope = "old/prod"
	if _, err := s2.Open(lin.ids); err == nil {
		t.Fatal("renamed slots open under the old name")
	}
}

func TestVerifyTrunkAfterRename(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	o := mustCreate(t, t.TempDir(), "old", "prod", lin)
	o.Seal("a", []byte("A"), t0)
	trunk, err := store.ParseKeys("trunk", o.Keys.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	// Another key under the same old name and id: not trunk's.
	other := mustCreate(t, t.TempDir(), "old", "prod", lin)
	foreign, _ := store.ParseKeys("foreign", other.Keys.Marshal())
	foreign.Keys = map[string]*store.Key{trunk.Current: foreign.CurrentKey()}
	foreign.Current = trunk.Current

	if err := o.Rename("new", devices(lin)); err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyTrunk(trunk); err != nil {
		t.Fatalf("renamed scope vs trunk under the old name: %v", err)
	}
	if got := o.Keys.CurrentKey().SlotTo["lin/laptop"]; got != lin.dev.RecipientHash() {
		t.Fatalf("re-wrapped slot records %q", got)
	}
	if err := o.VerifyTrunk(foreign); !errors.Is(err, ErrNotFromTrunk) {
		t.Fatalf("foreign key accepted: %v", err)
	}
	staging, _ := store.ParseKeys("x", trunk.Marshal())
	staging.Scope = "old/staging"
	if err := o.VerifyTrunk(staging); !errors.Is(err, ErrWrongScope) {
		t.Fatalf("other environment: %v", err)
	}

	// The branch rotates after renaming: trunk's key is retired here.
	if _, err := o.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := o.VerifyTrunk(trunk); err != nil {
		t.Fatalf("rotated past trunk after rename: %v", err)
	}
}
