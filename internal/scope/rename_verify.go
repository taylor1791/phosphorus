package scope

import (
	"fmt"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// verifyRenamed is VerifyTrunk for a scope renamed on this branch (see
// Opened.Rename): trunk's keys file, in the same package directory, still
// names the old package, so its inbox_sealed fields authenticate the old
// name and cannot be compared byte for byte. Instead the opened keys must
// unseal trunk's inbox_sealed under trunk's package name, which proves they
// are trunk's keys (or, rotated past trunk, that the rotator held them).
//
// The environment must be the same; only the package name may differ.
func (o *Opened) verifyRenamed(trunk *store.Keys) error {
	tpkg, tenv, err := config.ParseScopeName(trunk.Scope)
	if err != nil || tenv != o.Env {
		return fmt.Errorf("%w: trunk's keys file says scope = %q", ErrWrongScope, trunk.Scope)
	}
	fail := func(why string) error {
		// Both: the key is not trunk's, and trunk's file names another
		// package that this branch's keys do not prove a rename from.
		return fmt.Errorf("%w: %s (%s; %w: trunk's says %s)", ErrNotFromTrunk, why, o.KeysPath(), ErrWrongScope, trunk.Scope)
	}
	cur, tcur := o.Keys.CurrentKey(), trunk.CurrentKey()
	if o.Keys.Current == trunk.Current {
		if cur.Inbox != tcur.Inbox || !o.unsealsInboxAs(tpkg, trunk.Current, tcur.InboxSealed, tcur.Inbox) {
			return fail(fmt.Sprintf("key %s is not trunk's key %s under the old name", o.Keys.Current, trunk.Current))
		}
		return nil
	}
	if tr, ok := trunk.Keys[o.Keys.Current]; ok && tr.IsRetired() {
		if tr.InboxSealed != "" && !o.unsealsInboxAs(tpkg, o.Keys.Current, tr.InboxSealed, "") {
			return fail(fmt.Sprintf("key %s is not the key trunk retired under that id", o.Keys.Current))
		}
		return nil
	}
	if r, ok := o.Keys.Keys[trunk.Current]; ok && r.IsRetired() && o.keys[trunk.Current] != nil &&
		o.unsealsInboxAs(tpkg, trunk.Current, tcur.InboxSealed, tcur.Inbox) {
		return nil
	}
	return fail(fmt.Sprintf("current key %s is neither trunk's key %s, one trunk retired, nor its successor", o.Keys.Current, trunk.Current))
}

// unsealsInboxAs is unsealsInbox with the associated data of package pkg.
func (o *Opened) unsealsInboxAs(pkg, id, sealed, wantRecipient string) bool {
	k := o.keys[id]
	if k == nil || sealed == "" {
		return false
	}
	ad, err := seal.InboxAD(pkg, o.Env, id)
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
