package scope

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/store"
)

var update = flag.Bool("update", false, "regenerate testdata/vectors/scope")

// The example scope in testdata/vectors/scope is a complete checkout/prod:
// two slots (X25519 and hybrid), sealed values, a drop, one retired key and
// a value still sealed under it. docs/format.md walks through decrypting it
// with the age CLI and tools/decrypt.py. Its identities are test keys.
const vectorDir = "../../testdata/vectors/scope"

type expected struct {
	Scope  string            `json:"scope"`
	Values map[string]string `json:"values"`
	Drops  []string          `json:"drops"`
	Stale  []string          `json:"stale"`
}

func TestExampleScopeVector(t *testing.T) {
	if *update {
		writeExampleScope(t)
	}
	var want expected
	data, err := os.ReadFile(filepath.Join(vectorDir, "expected.json"))
	if err != nil {
		t.Fatalf("%v (run go test ./internal/scope -run ExampleScope -update)", err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	for _, idFile := range []string{"identity-x25519.txt", "identity-hybrid.txt"} {
		t.Run(idFile, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(vectorDir, idFile))
			if err != nil {
				t.Fatal(err)
			}
			ids, err := agewrap.ParseIdentityFile(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			s, err := Load(vectorDir, "checkout", "prod")
			if err != nil {
				t.Fatal(err)
			}
			o, err := s.Open(ids)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			var drops, stale []string
			for _, name := range s.Secrets.Names() {
				v, err := o.Reveal(name)
				if err != nil {
					t.Fatal(err)
				}
				got[name] = string(v.Bytes)
				if v.Drop {
					drops = append(drops, name)
				}
				if v.Stale {
					stale = append(stale, name)
				}
			}
			if len(got) != len(want.Values) {
				t.Fatalf("values = %v, want %v", got, want.Values)
			}
			for k, v := range want.Values {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			if len(drops) != len(want.Drops) || len(stale) != len(want.Stale) {
				t.Fatalf("drops %v stale %v, want %v %v", drops, stale, want.Drops, want.Stale)
			}
		})
	}
}

func writeExampleScope(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(vectorDir, ".carbon"), 0o755); err != nil {
		t.Fatal(err)
	}
	var devs []policy.Device
	var ids []agewrap.Identity
	for _, k := range []struct {
		kind agewrap.Kind
		file string
		id   string
	}{{agewrap.KindX25519, "identity-x25519.txt", "test/x25519"}, {agewrap.KindHybrid, "identity-hybrid.txt", "test/hybrid"}} {
		secret, rec, err := agewrap.GenerateIdentity(k.kind)
		if err != nil {
			t.Fatal(err)
		}
		data := append([]byte("# TEST KEY for carbon's format vectors. Never use it for anything else.\n"),
			agewrap.IdentityFile(secret, rec, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))...)
		if err := os.WriteFile(filepath.Join(vectorDir, k.file), data, 0o644); err != nil {
			t.Fatal(err)
		}
		parsed, _ := agewrap.ParseIdentityFile(data, nil)
		ids = append(ids, parsed...)
		devs = append(devs, policy.Device{ID: k.id, Recipient: rec, Kind: k.kind})
	}
	sam := newPerson(t, "sam/laptop", agewrap.KindHybrid)
	os.Remove(store.KeysPath(vectorDir, "prod"))
	os.Remove(store.SecretsPath(vectorDir, "prod"))
	s, _ := Load(vectorDir, "checkout", "prod")
	t1 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	o, err := s.Create(append(devs, sam.dev), t1)
	if err != nil {
		t.Fatal(err)
	}
	o.Seal("stripe_api_key", []byte("sk_live_example"), time.Date(2026, 9, 14, 9, 30, 2, 0, time.UTC))
	// A value on an older branch, sealed under the first key.
	o.Seal("legacy_token", []byte("from before the rotation"), time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC))
	legacy := o.Secrets.Entries["legacy_token"]
	delete(o.Secrets.Entries, "legacy_token")
	if _, err := o.Rotate(devs, "removed sam", time.Date(2026, 11, 2, 17, 4, 11, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	o.Seal("session_key", []byte("bXlzZXNzaW9ua2V5"), time.Date(2026, 11, 2, 17, 4, 11, 0, time.UTC))
	if err := s.Drop(Inbox{KeyID: o.CurrentID(), Recipient: s.Keys.CurrentKey().Inbox}, "webhook_secret",
		[]byte("whsec_example"), time.Date(2026, 11, 10, 8, 12, 40, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	s.Secrets.Entries["legacy_token"] = legacy
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
	exp := expected{
		Scope: "checkout/prod",
		Values: map[string]string{
			"stripe_api_key": "sk_live_example", "session_key": "bXlzZXNzaW9ua2V5",
			"webhook_secret": "whsec_example", "legacy_token": "from before the rotation",
		},
		Drops: []string{"webhook_secret"},
		Stale: []string{"legacy_token"},
	}
	data, _ := json.MarshalIndent(exp, "", "  ")
	if err := os.WriteFile(filepath.Join(vectorDir, "expected.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = ids
}
