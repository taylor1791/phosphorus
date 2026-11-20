// Command genvectors writes testdata/vectors/sealed.json: deterministic test
// vectors for carbon's sealed blobs. It builds the associated data and the
// blob from docs/format.md directly with golang.org/x/crypto, independently
// of internal/seal, so the vectors cross-check the implementation.
//
//	go run ./tools/genvectors > testdata/vectors/sealed.json
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type vector struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Key       string   `json:"key_hex"`
	Nonce     string   `json:"nonce_hex"`
	Fields    []string `json:"ad_fields"`
	AD        string   `json:"associated_data"`
	Plaintext string   `json:"plaintext_hex"`
	Blob      string   `json:"blob"`
	// Carried is the retired key's carried list, for a retired vector; its
	// digest is the last associated data field.
	Carried []string `json:"carried,omitempty"`
	// PredecessorRecord is the predecessor's retired record, for a retired
	// vector that has one; its digest is the next-to-last field.
	PredecessorRecord *record `json:"predecessor_record,omitempty"`
}

// record is a retired key record, as in a keys file.
type record struct {
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Retired     string   `json:"retired"`
	Reason      string   `json:"reason"`
	Successor   string   `json:"successor"`
	Predecessor string   `json:"predecessor"`
	Sealed      string   `json:"sealed"`
	Carried     []string `json:"carried"`
	InboxSealed string   `json:"inbox_sealed"`
}

func hexSum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// digest is the record digest of docs/format.md, computed from the spec.
func (r *record) digest() string {
	return hexSum(strings.Join([]string{"carbon/v1/record", r.ID, r.Created, r.Retired, r.Reason, r.Successor,
		orDash(r.Predecessor), r.Sealed, hexSum(strings.Join(r.Carried, "\n")), orDash(r.InboxSealed)}, "\n"))
}

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func main() {
	scopeKey := seq(0x00, 32)                                    // the scope key of k3f9q2
	retiredKey := seq(0x80, 32)                                  // the retired key k1a8c0
	inboxIdentity := "AGE-SECRET-KEY-PQ-1EXAMPLEONLYNOTAREALKEY" // any string; an inbox_sealed holds the inbox identity
	purpose := map[string]string{"value": "carbon/v1/value", "inbox": "carbon/v1/inbox", "retired": "carbon/v1/retired"}

	mk := func(name, kind string, key []byte, nonceStart byte, plaintext []byte, fields ...string) vector {
		nonce := seq(nonceStart, chacha20poly1305.NonceSizeX)
		ad := strings.Join(append([]string{purpose[kind]}, fields...), "\n")
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			panic(err)
		}
		ct := aead.Seal(append([]byte{}, nonce...), nonce, plaintext, []byte(ad))
		return vector{
			Name: name, Kind: kind,
			Key: hex.EncodeToString(key), Nonce: hex.EncodeToString(nonce),
			Fields: fields, AD: ad, Plaintext: hex.EncodeToString(plaintext),
			Blob: "carbon1:" + base64.RawStdEncoding.EncodeToString(ct),
		}
	}

	// A value under the retired key, carried by its retirement: the carried
	// list holds the SHA-256 of its secrets-file line; the retired blob's
	// last associated data field is the SHA-256 of the list joined by "\n";
	// the one before it is the predecessor key id, "-" for a first key.
	underRetired := mk("value-under-retired-key", "value", retiredKey, 0x70, []byte("sk_live_old"),
		"checkout", "prod", "stripe_api_key", "k1a8c0", "2026-09-14T09:30:02Z")
	line := `stripe_api_key = { key = "k1a8c0", set = 2026-09-14T09:30:02Z, value = "` + underRetired.Blob + `" }`
	lineSum := sha256.Sum256([]byte(line))
	carried := []string{"sha256:" + hex.EncodeToString(lineSum[:])}
	digest := sha256.Sum256([]byte(strings.Join(carried, "\n")))
	// The scope's first key k0b2z7, retired in favour of k1a8c0 and sealed
	// under it: no predecessor, nothing carried.
	olderKey := seq(0xc0, 32)
	first := mk("retired-first", "retired", retiredKey, 0x61, olderKey,
		"checkout", "prod", "k0b2z7", "k1a8c0", "2026-06-01T10:00:00Z", "removed ada/laptop", "-", "-", hexSum(""))
	first.Carried = []string{}
	firstRec := &record{ID: "k0b2z7", Created: "2026-01-05T09:00:00Z", Retired: "2026-06-01T10:00:00Z", Reason: "removed ada/laptop",
		Successor: "k1a8c0", Sealed: first.Blob, Carried: []string{}}
	// k1a8c0, retired in favour of k3f9q2: its predecessor is k0b2z7, and
	// the digest of k0b2z7's record is in its associated data.
	retired := mk("retired", "retired", scopeKey, 0x60, retiredKey,
		"checkout", "prod", "k1a8c0", "k3f9q2", "2026-11-02T17:04:11Z", "removed sam", "k0b2z7", firstRec.digest(), hex.EncodeToString(digest[:]))
	retired.Carried = carried
	retired.PredecessorRecord = firstRec

	doc := struct {
		Comment string   `json:"comment"`
		Vectors []vector `json:"vectors"`
	}{
		Comment: "Carbon sealed-blob test vectors. See docs/format.md. Generated by tools/genvectors; verified by internal/seal and tools/decrypt.py.",
		Vectors: []vector{
			mk("value", "value", scopeKey, 0x40, []byte("sk_live_example"),
				"checkout", "prod", "stripe_api_key", "k3f9q2", "2026-11-02T17:04:11Z"),
			mk("value-empty", "value", scopeKey, 0x41, []byte{},
				"checkout", "prod", "empty_value", "k3f9q2", "2026-11-02T17:04:11Z"),
			mk("value-binary", "value", scopeKey, 0x42, []byte("line one\nline two\x00\xff"),
				"checkout", "dev", "multi_line", "k3f9q2", "2026-01-01T00:00:00Z"),
			mk("inbox", "inbox", scopeKey, 0x50, []byte(inboxIdentity),
				"checkout", "prod", "k3f9q2"),
			first,
			retired,
			underRetired,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		panic(err)
	}
}
