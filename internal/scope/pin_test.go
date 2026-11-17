package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

func TestKeyFingerprint(t *testing.T) {
	var k seal.Key
	for i := range k {
		k[i] = byte(i)
	}
	sum := sha256.Sum256(append([]byte("carbon/v1/pin\n"), k[:]...))
	if KeyFingerprint(&k) != hex.EncodeToString(sum[:]) {
		t.Fatal("fingerprint is not SHA-256 of the purpose line and the key")
	}
}

func TestCheckPin(t *testing.T) {
	lin := newPerson(t, "lin/laptop", agewrap.KindHybrid)
	open := func(o *Opened) *Opened {
		t.Helper()
		r, err := reload(t, o.Scope).Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	isRefusal := func(err error) bool {
		var pe *PinError
		return errors.As(err, &pe) && errors.Is(err, ErrKeyReplaced)
	}

	o := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	first := o.CurrentPin()

	t.Run("no pin records the current key", func(t *testing.T) {
		next, err := open(o).CheckPin(nil, nil)
		if err != nil || next == nil || *next != first {
			t.Fatalf("%+v %v", next, err)
		}
	})
	t.Run("same key", func(t *testing.T) {
		next, err := open(o).CheckPin(&first, nil)
		if err != nil || next != nil {
			t.Fatalf("%+v %v", next, err)
		}
	})
	t.Run("same id, other key", func(t *testing.T) {
		bad := KeyPin{KeyID: first.KeyID, Fingerprint: KeyFingerprint(&seal.Key{})}
		if _, err := open(o).CheckPin(&bad, nil); !isRefusal(err) {
			t.Fatalf("err = %v", err)
		}
	})

	rotated := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
	rotatedFirst := rotated.CurrentPin()
	if _, err := rotated.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Run("pinned key retired through the chain moves forward", func(t *testing.T) {
		r := open(rotated)
		next, err := r.CheckPin(&rotatedFirst, nil)
		if err != nil || next == nil || next.KeyID != r.CurrentID() || *next != r.CurrentPin() {
			t.Fatalf("%+v %v", next, err)
		}
	})
	t.Run("retired key under the pinned id is not the pinned key", func(t *testing.T) {
		forged := KeyPin{KeyID: rotatedFirst.KeyID, Fingerprint: KeyFingerprint(&seal.Key{1})}
		if _, err := open(rotated).CheckPin(&forged, nil); !isRefusal(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("pinned key not in the chain", func(t *testing.T) {
		other := KeyPin{KeyID: "kzzzzz", Fingerprint: first.Fingerprint}
		if _, err := open(o).CheckPin(&other, nil); !isRefusal(err) {
			t.Fatalf("no trunk: %v", err)
		}
		// Trunk has the current key as current: still refused.
		if _, err := open(o).CheckPin(&other, cloneKeys(t, o.Keys)); !isRefusal(err) {
			t.Fatalf("trunk current: %v", err)
		}
	})
	t.Run("branch behind trunk keeps the pin", func(t *testing.T) {
		// The branch is at the first key; trunk and the pin moved on.
		branch := mustCreate(t, t.TempDir(), "checkout", "prod", lin)
		behind := cloneKeys(t, branch.Keys)
		if _, err := branch.Rotate(devices(lin), "removed sam", t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		trunk := cloneKeys(t, branch.Keys)
		pin := branch.CurrentPin()
		s := &Scope{Package: "checkout", Env: "prod", Dir: branch.Dir, Keys: behind, Secrets: store.NewSecrets()}
		b, err := s.Open(lin.ids)
		if err != nil {
			t.Fatal(err)
		}
		next, err := b.CheckPin(&pin, trunk)
		if err != nil || next != nil {
			t.Fatalf("behind: %+v %v", next, err)
		}
		if _, err := b.CheckPin(&pin, nil); !isRefusal(err) {
			t.Fatalf("behind without trunk evidence: %v", err)
		}
	})
}
