package agewrap

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age/plugin"

	"github.com/taylor1791/phosphorus/internal/seal"
)

func newIdentity(t *testing.T, kind Kind) Identity {
	t.Helper()
	secret, rec, err := GenerateIdentity(kind)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := ParseIdentityFile(IdentityFile(secret, rec, time.Now()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0].Recipient != rec || ids[0].Kind != kind {
		t.Fatalf("parsed identity = %+v, want recipient %s", ids, rec)
	}
	return ids[0]
}

func TestRecipientKind(t *testing.T) {
	h := newIdentity(t, KindHybrid)
	x := newIdentity(t, KindX25519)
	if RecipientKind(h.Recipient) != KindHybrid || !strings.HasPrefix(h.Recipient, "age1pq1") {
		t.Errorf("hybrid recipient %s kind %s", h.Recipient, RecipientKind(h.Recipient))
	}
	if RecipientKind(x.Recipient) != KindX25519 {
		t.Errorf("x25519 kind = %s", RecipientKind(x.Recipient))
	}
	if RecipientKind(plugin.EncodeRecipient("yubikey", []byte("0123456789abcdef0123456789abcdef"))) != KindPlugin {
		t.Error("plugin recipient not detected")
	}
	for _, bad := range []string{"", "ssh-ed25519 AAAA", "age1:abc", "AGE-SECRET-KEY-1"} {
		if _, err := ParseRecipient(bad); err == nil {
			t.Errorf("ParseRecipient(%q) succeeded", bad)
		}
	}
}

func TestSlotRoundTripAndMismatch(t *testing.T) {
	for _, kind := range []Kind{KindHybrid, KindX25519} {
		t.Run(string(kind), func(t *testing.T) {
			id := newIdentity(t, kind)
			other := newIdentity(t, kind)
			r, err := ParseRecipient(id.Recipient)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := seal.NewKey()
			blob, err := WrapSlot(r, "checkout/prod", "k3f9q2", key)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(blob, BlobPrefix) {
				t.Fatalf("blob prefix: %.10s", blob)
			}
			types, err := StanzaTypes(blob)
			if err != nil {
				t.Fatal(err)
			}
			want := StanzaX25519
			if kind == KindHybrid {
				want = StanzaHybrid
			}
			if len(types) != 1 || types[0] != want {
				t.Fatalf("stanzas = %v, want [%s]", types, want)
			}

			got, err := OpenSlot(blob, []Identity{other, id}, "checkout/prod", "k3f9q2")
			if err != nil || *got != *key {
				t.Fatalf("OpenSlot: %v", err)
			}
			if _, err := OpenSlot(blob, []Identity{other}, "checkout/prod", "k3f9q2"); !errors.Is(err, ErrNoMatch) {
				t.Fatalf("wrong identity: %v", err)
			}
			if _, err := OpenSlot(blob, []Identity{id}, "search/prod", "k3f9q2"); !errors.Is(err, ErrPayloadMismatch) {
				t.Fatalf("moved scope: %v", err)
			}
			if _, err := OpenSlot(blob, []Identity{id}, "checkout/prod", "k000000"); !errors.Is(err, ErrPayloadMismatch) {
				t.Fatalf("moved key id: %v", err)
			}
		})
	}
}

func TestDropRoundTripAndMismatch(t *testing.T) {
	inbox := newIdentity(t, KindHybrid)
	r, _ := ParseRecipient(inbox.Recipient)
	set := time.Date(2026, 11, 10, 8, 12, 40, 0, time.UTC)
	d := Drop{Package: "checkout", Env: "prod", Name: "webhook_secret", Set: set, Value: []byte("whsec\n\x00x")}
	blob, err := WriteDrop(r, d)
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenDrop(blob, []Identity{inbox}, Drop{Package: "checkout", Env: "prod", Name: "webhook_secret", Set: set})
	if err != nil || !bytes.Equal(v, d.Value) {
		t.Fatalf("OpenDrop = %q, %v", v, err)
	}
	for _, w := range []Drop{
		{Package: "search", Env: "prod", Name: "webhook_secret", Set: set},
		{Package: "checkout", Env: "dev", Name: "webhook_secret", Set: set},
		{Package: "checkout", Env: "prod", Name: "other", Set: set},
		{Package: "checkout", Env: "prod", Name: "webhook_secret", Set: set.Add(time.Hour)},
	} {
		if _, err := OpenDrop(blob, []Identity{inbox}, w); !errors.Is(err, ErrPayloadMismatch) {
			t.Errorf("moved drop %+v: %v", w, err)
		}
	}

	empty := Drop{Package: "p", Env: "e", Name: "n", Set: set}
	blob, _ = WriteDrop(r, empty)
	if v, err := OpenDrop(blob, []Identity{inbox}, empty); err != nil || len(v) != 0 {
		t.Fatalf("empty drop: %q %v", v, err)
	}
}

func TestPayloadParsingIsStrict(t *testing.T) {
	key, _ := seal.NewKey()
	good := SlotPayload{Scope: "a/b", KeyID: "k00000", Key: key}.Marshal()
	if _, err := ParseSlotPayload(good); err != nil {
		t.Fatal(err)
	}
	bad := [][]byte{
		bytes.TrimSuffix(good, []byte("\n")),
		append(append([]byte{}, good...), "extra\n"...),
		bytes.Replace(good, []byte(PurposeSlot), []byte(PurposeDrop), 1),
		[]byte(PurposeSlot + "\na/b\nk00000\nAAAA\n"),
	}
	for _, b := range bad {
		if _, err := ParseSlotPayload(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestPassphraseIdentityFile(t *testing.T) {
	secret, rec, _ := GenerateIdentity(KindHybrid)
	plain := IdentityFile(secret, rec, time.Now())
	enc, err := EncryptIdentityFile(plain, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedIdentityFile(enc) || bytes.Contains(enc, []byte("AGE-SECRET")) {
		t.Fatal("encrypted identity file looks plain")
	}
	if _, err := ParseIdentityFile(enc, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := ParseIdentityFile(enc, func() (string, error) { return "wrong", nil }); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	ids, err := ParseIdentityFile(enc, func() (string, error) { return "correct horse", nil })
	if err != nil || ids[0].Recipient != rec {
		t.Fatalf("right passphrase: %v", err)
	}
}

func TestIdentityErrorsDoNotLeakKeyMaterial(t *testing.T) {
	_, err := ParseIdentityFile([]byte("AGE-SECRET-KEY-1NOTREALLYAKEYBUTSECRETLOOKING\n"), nil)
	if err == nil || strings.Contains(err.Error(), "NOTREALLY") {
		t.Fatalf("err = %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	if len(Words) != 2048 {
		t.Fatalf("word list has %d words", len(Words))
	}
	seen := map[string]bool{}
	for _, w := range Words {
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
	}
	fp := Fingerprint("age1example")
	if strings.Count(fp, "-") != 3 {
		t.Fatalf("fingerprint %q", fp)
	}
	if fp != Fingerprint("age1example") || fp == Fingerprint("age1example2") {
		t.Fatal("fingerprint is not a stable function of the recipient")
	}
}

func TestFingerprintBitLayout(t *testing.T) {
	// The first 44 bits select words: word i is bits [11i, 11i+11).
	// Find a recipient string whose digest starts with known bytes by
	// recomputing the indexes independently here.
	rec := "age1pq1test"
	fp := strings.Split(Fingerprint(rec), "-")
	sum := sha256Sum(rec)
	idx := func(start int) int {
		v := 0
		for b := start; b < start+11; b++ {
			bit := (sum[b/8] >> (7 - b%8)) & 1
			v = v<<1 | int(bit)
		}
		return v
	}
	for i := 0; i < 4; i++ {
		if fp[i] != Words[idx(11*i)] {
			t.Fatalf("word %d = %s, want %s", i, fp[i], Words[idx(11*i)])
		}
	}
}
