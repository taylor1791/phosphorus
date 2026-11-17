package seal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var setTime = time.Date(2026, 11, 2, 17, 4, 11, 0, time.UTC)

func TestAssociatedDataExact(t *testing.T) {
	ad, err := ValueAD("checkout", "prod", "stripe_api_key", "k3f9q2", setTime)
	if err != nil {
		t.Fatal(err)
	}
	want := "carbon/v1/value\ncheckout\nprod\nstripe_api_key\nk3f9q2\n2026-11-02T17:04:11Z"
	if string(ad) != want {
		t.Fatalf("value AD = %q, want %q", ad, want)
	}

	ad, _ = InboxAD("checkout", "prod", "k3f9q2")
	if string(ad) != "carbon/v1/inbox\ncheckout\nprod\nk3f9q2" {
		t.Fatalf("inbox AD = %q", ad)
	}

	ad, _ = RetiredAD("checkout", "prod", "k1a8c0", "k3f9q2", setTime, "removed sam")
	if string(ad) != "carbon/v1/retired\ncheckout\nprod\nk1a8c0\nk3f9q2\n2026-11-02T17:04:11Z\nremoved sam" {
		t.Fatalf("retired AD = %q", ad)
	}
}

func TestAssociatedDataRejectsAmbiguity(t *testing.T) {
	if _, err := AssociatedData(PurposeValue, "a\nb"); err == nil {
		t.Fatal("newline in a field was accepted")
	}
	if _, err := AssociatedData(PurposeValue, "a", ""); err == nil {
		t.Fatal("empty field was accepted")
	}
}

func TestFormatTimeNormalises(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	in := time.Date(2026, 11, 2, 18, 4, 11, 999, loc)
	if got := FormatTime(in); got != "2026-11-02T17:04:11Z" {
		t.Fatalf("FormatTime = %q", got)
	}
}

func TestRoundTripAndBinding(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := ValueAD("checkout", "prod", "a", "k00000", setTime)
	blob, err := Seal(key, []byte("hunter2"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(blob, Prefix) || strings.HasSuffix(blob, "=") {
		t.Fatalf("bad encoding %q", blob)
	}
	pt, err := Open(key, blob, ad)
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("Open = %q, %v", pt, err)
	}

	moved := []struct {
		name string
		ad   func() []byte
	}{
		{"other name", func() []byte { b, _ := ValueAD("checkout", "prod", "b", "k00000", setTime); return b }},
		{"other package", func() []byte { b, _ := ValueAD("search", "prod", "a", "k00000", setTime); return b }},
		{"other env", func() []byte { b, _ := ValueAD("checkout", "dev", "a", "k00000", setTime); return b }},
		{"other key id", func() []byte { b, _ := ValueAD("checkout", "prod", "a", "k11111", setTime); return b }},
		{"other set time", func() []byte {
			b, _ := ValueAD("checkout", "prod", "a", "k00000", setTime.Add(time.Second))
			return b
		}},
		{"other purpose", func() []byte { b, _ := InboxAD("checkout", "prod", "k00000"); return b }},
	}
	for _, m := range moved {
		if _, err := Open(key, blob, m.ad()); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: err = %v, want ErrAuth", m.name, err)
		}
	}

	other, _ := NewKey()
	if _, err := Open(other, blob, ad); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: err = %v", err)
	}

	raw, _ := Decode(blob)
	raw[len(raw)-1] ^= 1
	if _, err := Open(key, Prefix+Encoding.EncodeToString(raw), ad); !errors.Is(err, ErrAuth) {
		t.Errorf("tampered: err = %v", err)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, s := range []string{"", "carbon2:AAAA", "carbon1:!!!", "carbon1:AAAA"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("Decode(%q) succeeded", s)
		}
	}
}

func TestNoncesDiffer(t *testing.T) {
	key, _ := NewKey()
	ad, _ := InboxAD("p", "e", "k00000")
	a, _ := Seal(key, []byte("x"), ad)
	b, _ := Seal(key, []byte("x"), ad)
	if a == b {
		t.Fatal("two seals produced the same blob")
	}
}

// vector mirrors one entry of testdata/vectors/sealed.json.
type vector struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Key       string   `json:"key_hex"`
	Nonce     string   `json:"nonce_hex"`
	Fields    []string `json:"ad_fields"`
	AD        string   `json:"associated_data"`
	Plaintext string   `json:"plaintext_hex"`
	Blob      string   `json:"blob"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "sealed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return doc.Vectors
}

func vectorAD(t *testing.T, v vector) []byte {
	t.Helper()
	f := v.Fields
	var ad []byte
	var err error
	parse := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	switch v.Kind {
	case "value":
		ad, err = ValueAD(f[0], f[1], f[2], f[3], parse(f[4]))
	case "inbox":
		ad, err = InboxAD(f[0], f[1], f[2])
	case "retired":
		ad, err = RetiredAD(f[0], f[1], f[2], f[3], parse(f[4]), f[5])
	default:
		t.Fatalf("unknown kind %q", v.Kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			kb, _ := hex.DecodeString(v.Key)
			nonce, _ := hex.DecodeString(v.Nonce)
			pt, _ := hex.DecodeString(v.Plaintext)
			key, err := KeyFromBytes(kb)
			if err != nil {
				t.Fatal(err)
			}
			ad := vectorAD(t, v)
			if string(ad) != v.AD {
				t.Fatalf("associated data = %q, vector says %q", ad, v.AD)
			}
			blob, err := sealWithNonce(key, nonce, pt, ad)
			if err != nil {
				t.Fatal(err)
			}
			if blob != v.Blob {
				t.Fatalf("blob = %s\nwant   %s", blob, v.Blob)
			}
			got, err := Open(key, v.Blob, ad)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("Open = %x, %v", got, err)
			}
		})
	}
}
