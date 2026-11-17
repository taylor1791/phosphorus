// Package seal implements carbon's sealed blobs: XChaCha20-Poly1305 under a
// 32-byte scope key, encoded as "carbon1:<base64(nonce || ciphertext)>".
//
// Every sealed blob is bound to where it lives by associated data. The
// associated data is built in exactly one place, [AssociatedData], from a
// purpose line and the fields listed in docs/implementation.md, joined with
// "\n". The typed constructors [ValueAD], [InboxAD] and [RetiredAD] are the
// only intended callers.
package seal

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Prefix starts every sealed blob.
const Prefix = "carbon1:"

// KeySize is the size of a scope key in bytes.
const KeySize = chacha20poly1305.KeySize

// NonceSize is the size of the random XChaCha20 nonce in bytes.
const NonceSize = chacha20poly1305.NonceSizeX

// Purpose lines: the first line of the associated data of each blob kind.
const (
	PurposeValue   = "carbon/v1/value"
	PurposeInbox   = "carbon/v1/inbox"
	PurposeRetired = "carbon/v1/retired"
)

// Encoding is the base64 used everywhere in carbon's formats: the standard
// alphabet without padding, strict (unused trailing bits must be zero).
// Decode with [DecodeBase64], which also rejects line breaks.
var Encoding = base64.RawStdEncoding.Strict()

// DecodeBase64 decodes carbon base64: standard alphabet, no padding,
// canonical trailing bits, and no "\r" or "\n" (which the standard decoder
// would otherwise skip), so each blob has exactly one encoding.
func DecodeBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("base64 contains a line break")
	}
	return Encoding.DecodeString(s)
}

// ErrAuth means a blob failed authentication: it was tampered with, or it was
// moved to a place (name, package, environment, key, time) it was not sealed
// for, or the key is wrong.
var ErrAuth = errors.New("sealed value failed authentication")

// Key is a 32-byte scope key.
type Key [KeySize]byte

// NewKey returns a fresh key from crypto/rand.
func NewKey() (*Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return nil, fmt.Errorf("generating scope key: %w", err)
	}
	return &k, nil
}

// KeyFromBytes copies b into a Key. b must be exactly KeySize bytes.
func KeyFromBytes(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("scope key is %d bytes, want %d", len(b), KeySize)
	}
	var k Key
	copy(k[:], b)
	return &k, nil
}

// Zero overwrites the key with zeros.
func (k *Key) Zero() {
	if k != nil {
		clear(k[:])
	}
}

// FormatTime renders t the way carbon writes times into associated data and
// payloads: RFC 3339, UTC, whole seconds.
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// AssociatedData joins purpose and fields with "\n", with no trailing
// newline. It is the only function in carbon that builds associated data.
// A field containing a newline would make the encoding ambiguous and is
// rejected; so is an empty field.
func AssociatedData(purpose string, fields ...string) ([]byte, error) {
	lines := make([]string, 0, len(fields)+1)
	lines = append(lines, purpose)
	lines = append(lines, fields...)
	for i, l := range lines {
		if l == "" {
			return nil, fmt.Errorf("associated data line %d is empty", i+1)
		}
		if strings.ContainsAny(l, "\n\r") {
			return nil, fmt.Errorf("associated data line %d contains a newline", i+1)
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// ValueAD is the associated data of a sealed secret value.
func ValueAD(pkg, env, name, keyID string, set time.Time) ([]byte, error) {
	return AssociatedData(PurposeValue, pkg, env, name, keyID, FormatTime(set))
}

// InboxAD is the associated data of a scope key's sealed inbox identity.
func InboxAD(pkg, env, keyID string) ([]byte, error) {
	return AssociatedData(PurposeInbox, pkg, env, keyID)
}

// RetiredAD is the associated data of a retired key sealed under its
// successor.
func RetiredAD(pkg, env, retiredID, successorID string, retired time.Time, reason string) ([]byte, error) {
	return AssociatedData(PurposeRetired, pkg, env, retiredID, successorID, FormatTime(retired), reason)
}

// Seal encrypts plaintext under key with a random nonce and returns the
// encoded blob.
func Seal(key *Key, plaintext, ad []byte) (string, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return sealWithNonce(key, nonce[:], plaintext, ad)
}

// sealWithNonce is Seal with a caller-chosen nonce. Only test vectors use it
// directly; a nonce must never be reused under one key.
func sealWithNonce(key *Key, nonce, plaintext, ad []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, ad)
	return Prefix + Encoding.EncodeToString(out), nil
}

// Open decodes and decrypts a blob. A blob that does not authenticate returns
// an error wrapping [ErrAuth].
func Open(key *Key, blob string, ad []byte) ([]byte, error) {
	raw, err := Decode(blob)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce, ct := raw[:NonceSize], raw[NonceSize:]
	pt, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// Decode checks a blob's prefix and length and returns nonce || ciphertext.
func Decode(blob string) ([]byte, error) {
	rest, ok := strings.CutPrefix(blob, Prefix)
	if !ok {
		return nil, fmt.Errorf("sealed value does not start with %q", Prefix)
	}
	raw, err := DecodeBase64(rest)
	if err != nil {
		return nil, fmt.Errorf("sealed value is not valid base64: %w", err)
	}
	if len(raw) < NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("sealed value is too short")
	}
	return raw, nil
}
