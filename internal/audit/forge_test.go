package audit

import (
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// What a non-reader can build with public keys alone (adapted from the
// review's internal/scope/forge_review.go, using exported APIs only so it
// can live beside these tests).

// forgery is an attacker-made scope key.
type forgery struct {
	id  string
	key *seal.Key
}

// forge replaces the scope's keys file with a fresh key under id, wrapped to
// devices, and empties the secrets file. Nothing is saved.
func forge(t *testing.T, s *scope.Scope, id string, devices []policy.Device, now time.Time) forgery {
	t.Helper()
	key, err := seal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, recipient, err := agewrap.GenerateIdentity(agewrap.KindHybrid)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := seal.InboxAD(s.Package, s.Env, id)
	if err != nil {
		t.Fatal(err)
	}
	inboxSealed, err := seal.Seal(key, []byte(secret), ad)
	if err != nil {
		t.Fatal(err)
	}
	now = now.UTC().Truncate(time.Second)
	rec := &store.Key{Created: now, Inbox: recipient, InboxSealed: inboxSealed, Slots: map[string]string{}}
	for _, d := range devices {
		r, err := agewrap.ParseRecipient(d.Recipient)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Slots[d.ID], err = agewrap.WrapSlot(r, s.Name(), id, key); err != nil {
			t.Fatal(err)
		}
	}
	s.Keys = &store.Keys{Scope: s.Name(), Current: id, Keys: map[string]*store.Key{id: rec}}
	s.Secrets = store.NewSecrets()
	return forgery{id: id, key: key}
}

// sealAs seals a value under the forged key.
func (fg forgery) sealAs(t *testing.T, s *scope.Scope, name, value string, set time.Time) {
	t.Helper()
	set = set.UTC().Truncate(time.Second)
	ad, err := seal.ValueAD(s.Package, s.Env, name, fg.id, set)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := seal.Seal(fg.key, []byte(value), ad)
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets.Entries[name] = store.Entry{Key: fg.id, Set: set, Value: blob}
}
