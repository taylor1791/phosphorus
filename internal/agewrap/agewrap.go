// Package agewrap is carbon's only user of filippo.io/age. It parses
// recipients and identities, writes and opens slots and drops (single-recipient
// age files carrying a typed payload), and computes fingerprints.
//
// Every blob it writes is "age1:<base64(binary age file)>", base64 being the
// standard alphabet without padding. Strip the prefix, decode, and the result
// opens with the stock `age -d`.
package agewrap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/taylor1791/phosphorus/internal/seal"
)

// BlobPrefix starts every slot and drop.
const BlobPrefix = "age1:"

// Kind classifies a recipient or identity.
type Kind string

const (
	KindHybrid Kind = "hybrid" // ML-KEM-768 + X25519, "age1pq1..."
	KindX25519 Kind = "x25519" // classic, "age1..."
	KindPlugin Kind = "plugin" // "age1<plugin>1...", handled by an age-plugin-<name> binary
)

// Stanza types as they appear in an age header.
const (
	StanzaHybrid = "mlkem768x25519"
	StanzaX25519 = "X25519"
)

var (
	// ErrNoMatch means none of the identities could open the age file: the
	// holder is not a recipient.
	ErrNoMatch = errors.New("no identity matches")
	// ErrPayloadMismatch means the age file opened but its payload names a
	// different place than the one it was found in.
	ErrPayloadMismatch = errors.New("payload does not match its location")
)

// RecipientKind reports the kind of a recipient string without parsing it
// fully. It returns "" for something that is not an age recipient.
func RecipientKind(s string) Kind {
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		return KindHybrid
	case strings.HasPrefix(s, "age1") && !strings.HasPrefix(s, "age1:"):
		// "age1" followed by bech32 data: X25519 has the separator right
		// after the "age" HRP, plugins have "age1<name>1...".
		if _, _, err := plugin.ParseRecipient(s); err == nil {
			return KindPlugin
		}
		return KindX25519
	}
	return ""
}

// ParseRecipient parses a hybrid, X25519, or plugin recipient string.
// Plugin recipients run the age-plugin-<name> binary from PATH when used.
func ParseRecipient(s string) (age.Recipient, error) {
	switch RecipientKind(s) {
	case KindHybrid:
		return age.ParseHybridRecipient(s)
	case KindX25519:
		return age.ParseX25519Recipient(s)
	case KindPlugin:
		return plugin.NewRecipient(s, pluginUI())
	}
	return nil, fmt.Errorf("%q is not an age recipient (want age1pq1..., age1..., or a plugin recipient)", s)
}

func pluginUI() *plugin.ClientUI {
	out := func(format string, v ...any) { fmt.Fprintf(os.Stderr, format+"\n", v...) }
	return plugin.NewTerminalUI(out, out)
}

// Encrypt writes an age file for exactly one recipient and returns it as an
// "age1:" blob.
func Encrypt(r age.Recipient, plaintext []byte) (string, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return BlobPrefix + seal.Encoding.EncodeToString(buf.Bytes()), nil
}

// DecodeBlob strips the "age1:" prefix and returns the binary age file.
func DecodeBlob(blob string) ([]byte, error) {
	rest, ok := strings.CutPrefix(blob, BlobPrefix)
	if !ok {
		return nil, fmt.Errorf("age blob does not start with %q", BlobPrefix)
	}
	raw, err := seal.DecodeBase64(rest)
	if err != nil {
		return nil, fmt.Errorf("age blob is not valid base64: %w", err)
	}
	return raw, nil
}

// EncodeBlob turns a binary age file into an "age1:" blob.
func EncodeBlob(ageFile []byte) string {
	return BlobPrefix + seal.Encoding.EncodeToString(ageFile)
}

// Decrypt opens an "age1:" blob with any of ids. It returns an error wrapping
// [ErrNoMatch] when no identity is a recipient.
func Decrypt(blob string, ids []Identity) ([]byte, error) {
	raw, err := DecodeBlob(blob)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, ErrNoMatch
	}
	ais := make([]age.Identity, len(ids))
	for i, id := range ids {
		ais[i] = id.Identity
	}
	r, err := age.Decrypt(bytes.NewReader(raw), ais...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrNoMatch
		}
		return nil, fmt.Errorf("age: %w", err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age: %w", err)
	}
	return pt, nil
}

// StanzaTypes returns the recipient stanza types in an age blob's header,
// without decrypting it. `check` uses it to require exactly one stanza and,
// under require_pq, the hybrid type.
func StanzaTypes(blob string) ([]string, error) {
	raw, err := DecodeBlob(blob)
	if err != nil {
		return nil, err
	}
	hdr, err := age.ExtractHeader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var types []string
	sc := bufio.NewScanner(bytes.NewReader(hdr))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "-> "); ok {
			typ, _, _ := strings.Cut(rest, " ")
			types = append(types, typ)
		}
	}
	return types, sc.Err()
}
