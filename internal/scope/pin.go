package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// PinPurpose prefixes the key bytes in a pin fingerprint.
const PinPurpose = "carbon/v1/pin\n"

// KeyPin is a reader's memory of the last scope key it verified: the key id
// and a fingerprint of the key bytes. It lets a reader notice a key replaced
// by someone who never held the previous one, even after the replacement is
// on trunk (where VerifyTrunk passes vacuously).
type KeyPin struct {
	KeyID       string
	Fingerprint string
}

// KeyFingerprint is hex(SHA-256("carbon/v1/pin\n" || key)).
func KeyFingerprint(key *seal.Key) string {
	h := sha256.New()
	h.Write([]byte(PinPurpose))
	h.Write(key[:])
	return hex.EncodeToString(h.Sum(nil))
}

// CurrentPin is the pin for the current key.
func (o *Opened) CurrentPin() KeyPin {
	return KeyPin{KeyID: o.Keys.Current, Fingerprint: KeyFingerprint(o.keys[o.Keys.Current])}
}

// ErrKeyReplaced means the scope's key was replaced by someone who did not
// hold the previous key, or the reader's pin is stale.
var ErrKeyReplaced = errors.New("scope key was replaced by someone who did not hold the previous key")

// PinError is a refusal from CheckPin.
type PinError struct {
	Scope     string
	PinnedID  string
	CurrentID string
	Reason    string
}

func (e *PinError) Error() string {
	return fmt.Sprintf("%s: %s: pinned key %s, current key %s (%s)", e.Scope, ErrKeyReplaced, e.PinnedID, e.CurrentID, e.Reason)
}

func (e *PinError) Unwrap() error { return ErrKeyReplaced }

// CheckPin applies the pin rule to an opened scope. pin is the reader's
// stored pin for this scope (nil if none); trunk is trunk's keys file for
// the scope (nil if none or trunk is not a ref). It returns the pin to store
// (nil: leave the stored pin alone) or a *PinError:
//
//   - no pin: trust on first use, pin the current key;
//   - pinned id == current id: the fingerprints must match;
//   - pinned id is a retired key that opened through the chain: its
//     fingerprint must match the pin; the pin moves to the current key;
//   - pinned id not in the chain: accepted (pin unchanged) only if trunk
//     lists the working tree's current key as retired, i.e. this branch is
//     behind; otherwise refused.
func (o *Opened) CheckPin(pin *KeyPin, trunk *store.Keys) (*KeyPin, error) {
	cur := o.CurrentPin()
	if pin == nil {
		return &cur, nil
	}
	refuse := func(why string) error {
		return &PinError{Scope: o.Name(), PinnedID: pin.KeyID, CurrentID: cur.KeyID, Reason: why}
	}
	if pin.KeyID == cur.KeyID {
		if pin.Fingerprint != cur.Fingerprint {
			return nil, refuse("same key id, different key")
		}
		return nil, nil
	}
	if k := o.keys[pin.KeyID]; k != nil {
		if r, ok := o.Keys.Keys[pin.KeyID]; ok && r.IsRetired() {
			if KeyFingerprint(k) != pin.Fingerprint {
				return nil, refuse("the retired key under the pinned id is not the pinned key")
			}
			return &cur, nil
		}
	}
	if trunk != nil {
		if r, ok := trunk.Keys[cur.KeyID]; ok && r.IsRetired() {
			return nil, nil // this branch is behind trunk
		}
	}
	return nil, refuse("the pinned key is not in this scope's chain of retired keys")
}
