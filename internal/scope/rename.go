package scope

import (
	"fmt"
	"sort"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// Rename re-binds an opened scope to the package newPkg. Everything whose
// authenticated data or payload names the package is re-written: every
// value (under the key it was sealed with), every drop (to the inbox it was
// written to), every key's inbox_sealed, every retired key's sealed blob,
// and the current key's slots, which are re-wrapped to devices. Key ids,
// created and retired times, reasons and set times are kept.
//
// devices must hold a device for every slot id on the current key (their
// public keys, typically from trunk policy). Nothing changes on error. The
// caller saves; the files stay in the package directory.
func (o *Opened) Rename(newPkg string, devices []policy.Device) error {
	if err := config.CheckName("package", newPkg); err != nil {
		return err
	}
	newScope := config.ScopeName(newPkg, o.Env)
	byID := map[string]policy.Device{}
	for _, d := range devices {
		byID[d.ID] = d
	}
	values, err := o.RevealAll()
	if err != nil {
		return fmt.Errorf("rename stopped before changing anything: %w", err)
	}
	defer func() {
		for _, v := range values {
			v.Zero()
		}
	}()

	entries := map[string]store.Entry{}
	for _, v := range values {
		e := o.Secrets.Entries[v.Name]
		if v.Drop {
			inbox, ok := o.inboxes[e.Key]
			if !ok {
				return fmt.Errorf("rename stopped before changing anything: %s %s: the inbox of key %s cannot be opened", o.Name(), v.Name, e.Key)
			}
			r, err := agewrap.ParseRecipient(inbox.Recipient)
			if err != nil {
				return err
			}
			blob, err := agewrap.WriteDrop(r, agewrap.Drop{Package: newPkg, Env: o.Env, Name: v.Name, Set: v.Set, Value: v.Bytes})
			if err != nil {
				return err
			}
			entries[v.Name] = store.Entry{Key: e.Key, Set: e.Set, Drop: blob}
			continue
		}
		k, err := o.key(e.Key)
		if err != nil {
			return err
		}
		ad, err := seal.ValueAD(newPkg, o.Env, v.Name, e.Key, e.Set)
		if err != nil {
			return err
		}
		blob, err := seal.Seal(k, v.Bytes, ad)
		if err != nil {
			return err
		}
		entries[v.Name] = store.Entry{Key: e.Key, Set: e.Set, Value: blob}
	}

	// A retired key's carried list names entry lines, which the rename
	// re-writes: map each carried entry to its new line.
	newHash := map[string]string{}
	for name, e := range o.Secrets.Entries {
		if ne, ok := entries[name]; ok {
			newHash[store.LineHash(name, e)] = store.LineHash(name, ne)
		}
	}

	keys := map[string]*store.Key{}
	// Oldest first: each retired record's associated data holds the
	// digest of its predecessor's record, which the rename re-writes.
	chain, err := o.Keys.Chain()
	if err != nil {
		return fmt.Errorf("rename stopped before changing anything: %w: %v", ErrTampered, err)
	}
	order := []string{}
	for i := len(chain) - 1; i >= 0; i-- {
		order = append(order, chain[i])
	}
	order = append(order, o.Keys.Current)
	for _, id := range order {
		r := o.Keys.Keys[id]
		k, err := o.key(id)
		if err != nil {
			return fmt.Errorf("rename stopped before changing anything: %w", err)
		}
		nr := *r
		if r.InboxSealed != "" {
			inbox, ok := o.inboxes[id]
			if !ok {
				return fmt.Errorf("rename stopped before changing anything: the inbox of key %s in %s cannot be opened", id, o.Name())
			}
			secret, ok := inbox.Identity.(fmt.Stringer)
			if !ok {
				return fmt.Errorf("the inbox of key %s cannot be re-sealed", id)
			}
			s := []byte(secret.String())
			ad, err := seal.InboxAD(newPkg, o.Env, id)
			if err != nil {
				return err
			}
			nr.InboxSealed, err = seal.Seal(k, s, ad)
			clear(s)
			if err != nil {
				return err
			}
		}
		if r.IsRetired() {
			succ, err := o.key(r.Successor)
			if err != nil {
				return err
			}
			nr.Carried = []string{}
			for _, h := range r.Carried {
				if nh, ok := newHash[h]; ok {
					nr.Carried = append(nr.Carried, nh)
				}
			}
			sort.Strings(nr.Carried)
			predDigest := ""
			if p := keys[r.Predecessor]; r.Predecessor != "" && p != nil {
				predDigest = seal.RecordDigest(r.Predecessor, p.Created, p.Retired, p.Reason, p.Successor, p.Predecessor, p.Sealed, p.Carried, p.InboxSealed)
			}
			ad, err := seal.RetiredAD(newPkg, o.Env, id, r.Successor, r.Retired, r.Reason, r.Predecessor, predDigest, nr.Carried)
			if err != nil {
				return err
			}
			if nr.Sealed, err = seal.Seal(succ, k[:], ad); err != nil {
				return err
			}
		} else {
			nr.Slots, nr.SlotTo = map[string]string{}, map[string]string{}
			for dev := range r.Slots {
				d, ok := byID[dev]
				if !ok {
					return fmt.Errorf("rename stopped before changing anything: %s has a slot for %s, which has no public key in policy", o.Name(), dev)
				}
				slot, err := wrapTo(d, newScope, id, k)
				if err != nil {
					return err
				}
				nr.SetSlot(dev, d.RecipientHash(), slot)
			}
		}
		keys[id] = &nr
	}

	o.Package = newPkg
	o.Keys.Scope = newScope
	o.Keys.Keys = keys
	o.Secrets.Entries = entries
	return nil
}
