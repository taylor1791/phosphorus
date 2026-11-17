// Package agekey reads a native age X25519 identity file and derives its
// recipient. It exists so carbon-migrate can tell who is running it without
// linking an age library: Bech32 and X25519 (crypto/ecdh) are all it needs.
package agekey

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

const (
	secretHRP    = "age-secret-key-"
	recipientHRP = "age"
)

// Recipient returns the age1... recipient for the first AGE-SECRET-KEY-1...
// line in an identity file (the format rage-keygen and age-keygen write).
func Recipient(identityFile []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(identityFile))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(line), "AGE-SECRET-KEY-1") {
			return "", errors.New("the identity file holds something other than a native age X25519 key")
		}
		hrp, data, err := decode(line)
		if err != nil {
			return "", fmt.Errorf("the age secret key does not parse: %w", err)
		}
		if hrp != secretHRP || len(data) != 32 {
			return "", errors.New("the age secret key does not parse")
		}
		priv, err := ecdh.X25519().NewPrivateKey(data)
		if err != nil {
			return "", err
		}
		return encode(recipientHRP, priv.PublicKey().Bytes())
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("the identity file holds no AGE-SECRET-KEY-1 line")
}

// Generate makes a new X25519 identity file in the age-keygen format and
// returns it with its recipient. carbon-migrate itself never generates keys;
// tests use it to build 0.0.3 fixtures without age-keygen.
func Generate() (identityFile, recipient string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	sk, err := encode(secretHRP, priv.Bytes())
	if err != nil {
		return "", "", err
	}
	rec, err := encode(recipientHRP, priv.PublicKey().Bytes())
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("# public key: %s\n%s\n", rec, strings.ToUpper(sk)), rec, nil
}

// IsRecipient reports whether s looks like a native X25519 recipient.
func IsRecipient(s string) bool {
	hrp, data, err := decode(s)
	return err == nil && hrp == recipientHRP && len(data) == 32
}

// Bech32 (BIP 173), the encoding age uses for keys, without the 90-char limit.

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte
	maxv := uint32(1)<<to - 1
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, errors.New("invalid data range")
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("invalid padding")
	}
	return out, nil
}

func encode(hrp string, data []byte) (string, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	exp := append(hrpExpand(hrp), values...)
	exp = append(exp, 0, 0, 0, 0, 0, 0)
	mod := polymod(exp) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range values {
		b.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(charset[(mod>>uint(5*(5-i)))&31])
	}
	return b.String(), nil
}

func decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bad separator position")
	}
	hrp := s[:pos]
	var values []byte
	for i := pos + 1; i < len(s); i++ {
		d := strings.IndexByte(charset, s[i])
		if d < 0 {
			return "", nil, errors.New("invalid character")
		}
		values = append(values, byte(d))
	}
	if polymod(append(hrpExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bad checksum")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
