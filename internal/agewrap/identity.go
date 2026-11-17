package agewrap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
)

// Identity is a loaded private key together with its public recipient
// string, which is how carbon works out who the holder is.
type Identity struct {
	age.Identity
	// Recipient is the public key string. For plugin identities it comes
	// from a "# public key:" or "# Recipient:" comment in the identity file
	// and is empty when the file has none.
	Recipient string
	Kind      Kind
}

// ErrPassphraseRequired is returned when an identity file is
// passphrase-encrypted and no passphrase function was supplied.
var ErrPassphraseRequired = errors.New("identity file is passphrase-protected")

// ErrBadPassphrase is returned for a wrong passphrase.
var ErrBadPassphrase = errors.New("incorrect passphrase")

// GenerateIdentity creates a new identity of the given kind (KindHybrid or
// KindX25519) and returns its secret and recipient strings.
func GenerateIdentity(kind Kind) (secret, recipient string, err error) {
	switch kind {
	case KindHybrid:
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return "", "", err
		}
		return id.String(), id.Recipient().String(), nil
	case KindX25519:
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return "", "", err
		}
		return id.String(), id.Recipient().String(), nil
	}
	return "", "", fmt.Errorf("cannot generate a %q identity", kind)
}

// IdentityFile renders an identity in age's identity-file format, the same
// layout age-keygen writes.
func IdentityFile(secret, recipient string, created time.Time) []byte {
	return fmt.Appendf(nil, "# created: %s\n# public key: %s\n%s\n",
		created.UTC().Format(time.RFC3339), recipient, secret)
}

// EncryptIdentityFile encrypts an identity file with a passphrase (age's
// scrypt recipient), armored, as `age -p -a` would.
func EncryptIdentityFile(data []byte, passphrase string) ([]byte, error) {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IsEncryptedIdentityFile reports whether data is an age-encrypted file
// (binary or armored) rather than a plain identity file.
func IsEncryptedIdentityFile(data []byte) bool {
	return bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) ||
		bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte(armor.Header))
}

// ParseIdentityFile parses identity-file content. If the content is
// passphrase-encrypted, passphrase is called once to decrypt it; a nil
// passphrase yields [ErrPassphraseRequired].
func ParseIdentityFile(data []byte, passphrase func() (string, error)) ([]Identity, error) {
	if IsEncryptedIdentityFile(data) {
		if passphrase == nil {
			return nil, ErrPassphraseRequired
		}
		plain, err := decryptWithPassphrase(data, passphrase)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		if IsEncryptedIdentityFile(plain) {
			return nil, errors.New("identity file is encrypted twice")
		}
		return parsePlainIdentities(plain)
	}
	return parsePlainIdentities(data)
}

func decryptWithPassphrase(data []byte, passphrase func() (string, error)) ([]byte, error) {
	var src io.Reader = bytes.NewReader(data)
	if !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) {
		src = armor.NewReader(bytes.NewReader(bytes.TrimLeft(data, " \t\r\n")))
	}
	pass, err := passphrase()
	if err != nil {
		return nil, err
	}
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrBadPassphrase
		}
		return nil, fmt.Errorf("decrypting identity file: %w", err)
	}
	return io.ReadAll(r)
}

func parsePlainIdentities(data []byte) ([]Identity, error) {
	var ids []Identity
	var commentRecipient string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if c, ok := strings.CutPrefix(line, "#"); ok {
			c = strings.TrimSpace(c)
			for _, p := range []string{"public key:", "Recipient:", "recipient:"} {
				if v, ok := strings.CutPrefix(c, p); ok {
					commentRecipient = strings.TrimSpace(v)
				}
			}
			continue
		}
		id, err := parseIdentityLine(line, commentRecipient)
		if err != nil {
			// Never include the line: it is private key material.
			return nil, fmt.Errorf("identity file line %d: %v", n, err)
		}
		ids = append(ids, id)
		commentRecipient = ""
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("identity file contains no identities")
	}
	return ids, nil
}

func parseIdentityLine(line, commentRecipient string) (Identity, error) {
	switch {
	case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
		id, err := age.ParseHybridIdentity(line)
		if err != nil {
			return Identity{}, errors.New("malformed hybrid secret key")
		}
		return Identity{Identity: id, Recipient: id.Recipient().String(), Kind: KindHybrid}, nil
	case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return Identity{}, errors.New("malformed X25519 secret key")
		}
		return Identity{Identity: id, Recipient: id.Recipient().String(), Kind: KindX25519}, nil
	case strings.HasPrefix(line, "AGE-PLUGIN-"):
		id, err := plugin.NewIdentity(line, pluginUI())
		if err != nil {
			return Identity{}, errors.New("malformed plugin identity")
		}
		return Identity{Identity: id, Recipient: commentRecipient, Kind: KindPlugin}, nil
	}
	return Identity{}, errors.New("not an age identity")
}
