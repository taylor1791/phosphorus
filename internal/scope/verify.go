package scope

import (
	"errors"
	"fmt"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// ErrNotFromTrunk means the scope's key in the working tree does not descend
// from trunk's: someone replaced the keys file on this branch. Reading or
// sealing under it could hand values to whoever made it.
var ErrNotFromTrunk = errors.New("the scope's key on this branch does not descend from trunk's")

// VerifyTrunk checks an opened scope's keys against trunk's keys file for
// the same scope (read from the trunk ref). A nil trunk (no keys file on
// trunk, or trunk is not a ref) passes. The rules:
//
//   - Same current key id: the working tree's inbox and inbox_sealed for it
//     must equal trunk's.
//   - The working tree's current key is a retired key on trunk (this branch
//     is behind trunk): accepted. When trunk's record keeps inbox_sealed,
//     the opened key must unseal it, proving it is the same key.
//   - Trunk's current key is a retired key in the working tree's chain that
//     opened (this branch rotated past trunk): accepted only if that opened
//     key unseals trunk's inbox_sealed for its id to a recipient equal to
//     trunk's inbox, which proves whoever made the new key held trunk's.
//   - Anything else: an error wrapping ErrNotFromTrunk.
//
// Every reader path (get, run, set, export, apply) should call it after
// Open; apply should call it before writing anything.
func (o *Opened) VerifyTrunk(trunk *store.Keys) error {
	if trunk == nil {
		return nil
	}
	if trunk.Scope != o.Name() {
		return o.verifyRenamed(trunk) // rename_verify.go
	}
	fail := func(why string) error {
		return fmt.Errorf("%w: %s (%s)", ErrNotFromTrunk, why, o.KeysPath())
	}
	cur, tcur := o.Keys.CurrentKey(), trunk.CurrentKey()
	if o.Keys.Current == trunk.Current {
		if cur.Inbox != tcur.Inbox || cur.InboxSealed != tcur.InboxSealed {
			return fail(fmt.Sprintf("key %s has a different inbox than on trunk", trunk.Current))
		}
		return nil
	}
	if tr, ok := trunk.Keys[o.Keys.Current]; ok && tr.IsRetired() {
		if tr.InboxSealed != "" && !o.unsealsInbox(o.Keys.Current, tr.InboxSealed, "") {
			return fail(fmt.Sprintf("key %s is not the key trunk retired under that id", o.Keys.Current))
		}
		return nil
	}
	if k := o.keys[trunk.Current]; k != nil {
		if r, ok := o.Keys.Keys[trunk.Current]; ok && r.IsRetired() && o.unsealsInbox(trunk.Current, tcur.InboxSealed, tcur.Inbox) {
			return nil
		}
		return fail(fmt.Sprintf("trunk's key %s is in this branch's chain but is not the same key", trunk.Current))
	}
	return fail(fmt.Sprintf("current key %s is neither trunk's key %s, one trunk retired, nor its successor", o.Keys.Current, trunk.Current))
}

// unsealsInbox reports whether the opened key with id unseals sealed (an
// inbox_sealed field) and, when wantRecipient is set, yields that recipient.
func (o *Opened) unsealsInbox(id, sealed, wantRecipient string) bool {
	k := o.keys[id]
	if k == nil || sealed == "" {
		return false
	}
	ad, err := seal.InboxAD(o.Package, o.Env, id)
	if err != nil {
		return false
	}
	pt, err := seal.Open(k, sealed, ad)
	if err != nil {
		return false
	}
	defer clear(pt)
	if wantRecipient == "" {
		return true
	}
	ids, err := agewrap.ParseIdentityFile(pt, nil)
	return err == nil && len(ids) == 1 && ids[0].Recipient == wantRecipient
}
