package agewrap

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/taylor1791/phosphorus/internal/seal"
)

// Payload purpose lines.
const (
	PurposeSlot = "carbon/v1/slot"
	PurposeDrop = "carbon/v1/drop"
)

// SlotPayload is the plaintext of a slot: which scope key it carries.
type SlotPayload struct {
	Scope string // "<package>/<env>"
	KeyID string
	Key   *seal.Key
}

// Marshal renders the payload: four lines, each ending in "\n".
func (p SlotPayload) Marshal() []byte {
	return fmt.Appendf(nil, "%s\n%s\n%s\n%s\n", PurposeSlot, p.Scope, p.KeyID, seal.Encoding.EncodeToString(p.Key[:]))
}

// ParseSlotPayload parses a slot's plaintext strictly.
func ParseSlotPayload(b []byte) (SlotPayload, error) {
	lines, err := payloadLines(b, PurposeSlot, 4)
	if err != nil {
		return SlotPayload{}, err
	}
	kb, err := seal.DecodeBase64(lines[3])
	if err != nil {
		return SlotPayload{}, errors.New("slot payload: key is not valid base64")
	}
	defer clear(kb)
	key, err := seal.KeyFromBytes(kb)
	if err != nil {
		return SlotPayload{}, fmt.Errorf("slot payload: %w", err)
	}
	return SlotPayload{Scope: lines[1], KeyID: lines[2], Key: key}, nil
}

// WrapSlot encrypts a scope key to one recipient.
func WrapSlot(r age.Recipient, scope, keyID string, key *seal.Key) (string, error) {
	pt := SlotPayload{Scope: scope, KeyID: keyID, Key: key}.Marshal()
	defer clear(pt)
	return Encrypt(r, pt)
}

// OpenSlot opens a slot with ids and checks that it carries the key for
// scope and keyID. It returns [ErrNoMatch] when no identity is the slot's
// recipient, and an error wrapping [ErrPayloadMismatch] when the slot opened
// but belongs elsewhere (for example a slot copied from another scope).
func OpenSlot(blob string, ids []Identity, scope, keyID string) (*seal.Key, error) {
	pt, err := Decrypt(blob, ids)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	p, err := ParseSlotPayload(pt)
	if err != nil {
		return nil, err
	}
	if p.Scope != scope || p.KeyID != keyID {
		p.Key.Zero()
		return nil, fmt.Errorf("%w: slot is for %s key %s, found in %s key %s",
			ErrPayloadMismatch, p.Scope, p.KeyID, scope, keyID)
	}
	return p.Key, nil
}

// Drop is a value written to a scope's inbox by someone who may not be a
// reader. Package, Env, Name and Set identify the line it sits on.
type Drop struct {
	Package string
	Env     string
	Name    string
	Set     time.Time
	Value   []byte
}

// Marshal renders the drop's plaintext: six lines, each ending in "\n".
func (d Drop) Marshal() []byte {
	return fmt.Appendf(nil, "%s\n%s\n%s\n%s\n%s\n%s\n", PurposeDrop, d.Package, d.Env, d.Name,
		seal.FormatTime(d.Set), seal.Encoding.EncodeToString(d.Value))
}

// ParseDrop parses a drop's plaintext strictly.
func ParseDrop(b []byte) (Drop, error) {
	lines, err := payloadLines(b, PurposeDrop, 6)
	if err != nil {
		return Drop{}, err
	}
	set, err := time.Parse(time.RFC3339, lines[4])
	if err != nil || seal.FormatTime(set) != lines[4] {
		return Drop{}, errors.New("drop payload: set time is not RFC 3339 UTC whole seconds")
	}
	v, err := seal.DecodeBase64(lines[5])
	if err != nil {
		return Drop{}, errors.New("drop payload: value is not valid base64")
	}
	return Drop{Package: lines[1], Env: lines[2], Name: lines[3], Set: set, Value: v}, nil
}

// WriteDrop encrypts d to an inbox recipient.
func WriteDrop(inbox age.Recipient, d Drop) (string, error) {
	pt := d.Marshal()
	defer clear(pt)
	return Encrypt(inbox, pt)
}

// OpenDrop opens a drop with the inbox identity and checks that it belongs
// on the line described by want (Value is ignored). It returns the value.
func OpenDrop(blob string, inbox []Identity, want Drop) ([]byte, error) {
	pt, err := Decrypt(blob, inbox)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	d, err := ParseDrop(pt)
	if err != nil {
		return nil, err
	}
	if d.Package != want.Package || d.Env != want.Env || d.Name != want.Name ||
		seal.FormatTime(d.Set) != seal.FormatTime(want.Set) {
		clear(d.Value)
		return nil, fmt.Errorf("%w: drop is for %s/%s %s set %s, found at %s/%s %s set %s",
			ErrPayloadMismatch, d.Package, d.Env, d.Name, seal.FormatTime(d.Set),
			want.Package, want.Env, want.Name, seal.FormatTime(want.Set))
	}
	return d.Value, nil
}

func payloadLines(b []byte, purpose string, n int) ([]string, error) {
	if !bytes.HasSuffix(b, []byte("\n")) {
		return nil, fmt.Errorf("%s payload does not end in a newline", purpose)
	}
	lines := strings.Split(string(b[:len(b)-1]), "\n")
	if len(lines) != n {
		return nil, fmt.Errorf("%s payload has %d lines, want %d", purpose, len(lines), n)
	}
	if lines[0] != purpose {
		return nil, fmt.Errorf("payload purpose is %q, want %q", lines[0], purpose)
	}
	for i, l := range lines {
		if l == "" && !(purpose == PurposeDrop && i == 5) { // an empty value is legal
			return nil, fmt.Errorf("%s payload line %d is empty", purpose, i+1)
		}
	}
	return lines, nil
}

//go:embed wordlist/english.txt
var wordlistText string

// Words is the embedded 2048-word list used for fingerprints (BIP-39
// English; see wordlist/LICENSE).
var Words = strings.Fields(wordlistText)

// Fingerprint returns four words chosen by the first 44 bits of SHA-256 of
// the recipient string, 11 bits each, joined with "-".
func Fingerprint(recipient string) string {
	sum := sha256.Sum256([]byte(recipient))
	var bits uint64
	for i := 0; i < 8; i++ {
		bits = bits<<8 | uint64(sum[i])
	}
	words := make([]string, 4)
	for i := range words {
		idx := (bits >> (64 - 11*(i+1))) & 0x7ff
		words[i] = Words[idx]
	}
	return strings.Join(words, "-")
}

// RecipientHash is "sha256:" and the hex SHA-256 of a recipient string,
// exactly as written in the people or machine file. A keys file records it
// as each slot's `to`. This is the only place it is computed.
func RecipientHash(recipient string) string {
	sum := sha256.Sum256([]byte(recipient))
	return "sha256:" + hex.EncodeToString(sum[:])
}
