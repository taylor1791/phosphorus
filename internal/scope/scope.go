// Package scope is carbon's high-level API for scope keys: one package in one
// environment, with its keys file and secrets file.
//
// The lifecycle, as in docs/implementation.md:
//
//   - [Scope.Create] makes the first key and inbox and wraps the key to the
//     devices trunk policy names. Anyone may create a scope.
//   - [Scope.Open] finds a slot the caller's identities open, verifies the
//     slot payload, verifies the inbox against its sealed half, and walks the
//     retired chain. The result, an [Opened], holds every key in memory.
//   - [Opened.Seal] / [Opened.Reveal] seal and read values; Reveal opens
//     drops and values under retired keys transparently.
//   - [Scope.Drop] writes a value to an inbox without any key: the path for
//     non-readers. The inbox must come from trunk ([TrunkInbox]).
//   - [Opened.AddSlots], [Opened.Rotate], [Opened.Promote] and
//     [Opened.Refresh] are what `apply` orchestrates.
//
// Nothing here reads policy or prompts; callers pass devices from
// internal/policy and identities from internal/agewrap. Call [Opened.Close]
// to zero keys when done.
package scope

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

var (
	// ErrNoKey: the scope has no keys file yet.
	ErrNoKey = errors.New("scope has no key yet")
	// ErrNotReader: none of the identities opens a slot of the current key.
	ErrNotReader = errors.New("no slot opens with your identity")
	// ErrInboxMismatch: the inbox public key differs from the recipient of
	// its sealed private half. Someone replaced the inbox key.
	ErrInboxMismatch = errors.New("inbox public key does not match its sealed private half")
	// ErrNotFound: no value or drop is stored under the name.
	ErrNotFound = errors.New("secret is not set")
	// ErrTampered: a sealed value, drop, slot or retired key failed
	// authentication or names a different place than where it was found.
	ErrTampered = errors.New("failed authentication")
	// ErrUnknownKey: an entry names a key id this scope cannot open.
	ErrUnknownKey = errors.New("unknown key id")
	// ErrNoDevices: a key would be wrapped to nobody.
	ErrNoDevices = errors.New("no device to wrap the scope key to")
	// ErrWrongScope: a keys file names a different scope than its location.
	ErrWrongScope = errors.New("keys file belongs to a different scope")
)

// Scope is a scope's two files, loaded.
type Scope struct {
	Package, Env string
	// Dir is the package directory (absolute or relative to the process).
	Dir     string
	Keys    *store.Keys // nil until the scope has a key
	Secrets *store.Secrets
}

// Load reads <dir>/.carbon/<env>.keys.toml and .secrets.toml. Missing files
// are fine: Keys stays nil and Secrets empty. Conflict markers return a
// *config.ConflictError.
func Load(dir, pkg, env string) (*Scope, error) {
	s := &Scope{Package: pkg, Env: env, Dir: dir}
	var err error
	if s.Keys, err = store.ReadKeys(s.KeysPath()); err != nil {
		return nil, err
	}
	if s.Keys != nil && s.Keys.Scope != s.Name() {
		return nil, fmt.Errorf("%w: %s says scope = %q, but it is %s's file", ErrWrongScope, s.KeysPath(), s.Keys.Scope, s.Name())
	}
	if s.Secrets, err = store.ReadSecrets(s.SecretsPath()); err != nil {
		return nil, err
	}
	return s, nil
}

// Name is "<package>/<env>".
func (s *Scope) Name() string { return config.ScopeName(s.Package, s.Env) }

// KeysPath is the keys file path.
func (s *Scope) KeysPath() string { return store.KeysPath(s.Dir, s.Env) }

// SecretsPath is the secrets file path.
func (s *Scope) SecretsPath() string { return store.SecretsPath(s.Dir, s.Env) }

// HasKey reports whether the scope has a key.
func (s *Scope) HasKey() bool { return s.Keys != nil }

// Save writes the keys file (if the scope has a key) and the secrets file
// (if it has entries or already exists). It returns the paths written.
func (s *Scope) Save() ([]string, error) {
	var written []string
	if s.Keys != nil {
		if err := store.WriteFile(s.KeysPath(), s.Keys.Marshal()); err != nil {
			return written, err
		}
		written = append(written, s.KeysPath())
	}
	_, statErr := os.Stat(s.SecretsPath())
	if len(s.Secrets.Entries) > 0 || statErr == nil {
		if err := store.WriteFile(s.SecretsPath(), s.Secrets.Marshal()); err != nil {
			return written, err
		}
		written = append(written, s.SecretsPath())
	}
	return written, nil
}

// SlotIDs returns the device ids with a slot on the current key, sorted.
func (s *Scope) SlotIDs() []string {
	if s.Keys == nil {
		return nil
	}
	return sortedKeys(s.Keys.CurrentKey().Slots)
}

// SlotDiff compares the current key's slots with the devices policy names.
type SlotDiff struct {
	Missing []policy.Device // named, no slot for its current key: pending grants
	Extra   []string        // slot for a key policy does not name: pending revocations
	// Rekeyed are named devices whose slot was wrapped to a different public
	// key than the one policy now lists (its `to` differs from
	// Device.RecipientHash). Each is also in Missing and in Extra: the old
	// key must be revoked by rotation and the new one granted.
	Rekeyed []policy.Device
	// Slots are the device ids of every slot of the current key, sorted.
	Slots []string
}

// DiffSlots compares the current key's slots with devices, by device id and
// by the recipient hash each slot records.
func (s *Scope) DiffSlots(devices []policy.Device) SlotDiff {
	var d SlotDiff
	slots, to := map[string]string{}, map[string]string{}
	if s.Keys != nil {
		slots, to = s.Keys.CurrentKey().Slots, s.Keys.CurrentKey().SlotTo
	}
	valid := map[string]bool{}
	for _, dev := range devices {
		_, has := slots[dev.ID]
		switch {
		case !has:
			d.Missing = append(d.Missing, dev)
		case to[dev.ID] != dev.RecipientHash():
			d.Missing = append(d.Missing, dev)
			d.Rekeyed = append(d.Rekeyed, dev)
		default:
			valid[dev.ID] = true
		}
	}
	d.Slots = sortedKeys(slots)
	for _, id := range sortedKeys(slots) {
		if !valid[id] {
			d.Extra = append(d.Extra, id)
		}
	}
	return d
}

// Opened is a scope whose keys are in memory.
type Opened struct {
	*Scope
	// Slot is the device id whose slot opened the scope; empty when the
	// scope was just created.
	Slot    string
	keys    map[string]*seal.Key
	inboxes map[string]agewrap.Identity
	// keyErrs records retired keys that could not be opened, so that only
	// values under them fail.
	keyErrs map[string]error
	// inboxErrs records retired inbox_sealed fields that failed to open:
	// drops under them report tampering.
	inboxErrs map[string]error
	// ids are the identities Open was called with (nil after Create).
	ids []agewrap.Identity
}

// Identities returns the identities the scope was opened with (nil for a
// scope just created). pins.ReaderID keys pins by them.
func (o *Opened) Identities() []agewrap.Identity { return o.ids }

// Close zeroes the keys held in memory.
func (o *Opened) Close() {
	for _, k := range o.keys {
		k.Zero()
	}
	o.keys = nil
	o.inboxes = nil
}

// CurrentID is the current key id.
func (o *Opened) CurrentID() string { return o.Keys.Current }

// Create makes the scope's first key and inbox and wraps the key to each
// device. It fails if the scope already has a key or devices is empty.
func (s *Scope) Create(devices []policy.Device, now time.Time) (*Opened, error) {
	if s.Keys != nil {
		return nil, fmt.Errorf("%s already has a key", s.Name())
	}
	if len(devices) == 0 {
		return nil, ErrNoDevices
	}
	now = wholeSecond(now)
	o := &Opened{Scope: s, keys: map[string]*seal.Key{}, inboxes: map[string]agewrap.Identity{}, keyErrs: map[string]error{}}
	id, rec, key, inbox, err := o.newKeyRecord(devices, now, map[string]*store.Key{})
	if err != nil {
		return nil, err
	}
	s.Keys = &store.Keys{Scope: s.Name(), Current: id, Keys: map[string]*store.Key{id: rec}}
	o.keys[id] = key
	o.inboxes[id] = inbox
	return o, nil
}

// newKeyRecord generates a key, an inbox pair and slots for devices.
func (o *Opened) newKeyRecord(devices []policy.Device, now time.Time, existing map[string]*store.Key) (string, *store.Key, *seal.Key, agewrap.Identity, error) {
	fail := func(err error) (string, *store.Key, *seal.Key, agewrap.Identity, error) {
		return "", nil, nil, agewrap.Identity{}, err
	}
	id, err := newKeyID(existing)
	if err != nil {
		return fail(err)
	}
	key, err := seal.NewKey()
	if err != nil {
		return fail(err)
	}
	secret, recipient, err := agewrap.GenerateIdentity(agewrap.KindHybrid)
	if err != nil {
		return fail(err)
	}
	inboxIDs, err := agewrap.ParseIdentityFile([]byte(secret+"\n"), nil)
	if err != nil {
		return fail(err)
	}
	ad, err := seal.InboxAD(o.Package, o.Env, id)
	if err != nil {
		return fail(err)
	}
	inboxSealed, err := seal.Seal(key, []byte(secret), ad)
	if err != nil {
		return fail(err)
	}
	rec := &store.Key{Created: now, Inbox: recipient, InboxSealed: inboxSealed, Slots: map[string]string{}, SlotTo: map[string]string{}}
	for _, d := range devices {
		slot, err := wrapTo(d, o.Name(), id, key)
		if err != nil {
			return fail(err)
		}
		rec.SetSlot(d.ID, d.RecipientHash(), slot)
	}
	return id, rec, key, inboxIDs[0], nil
}

func wrapTo(d policy.Device, scopeName, keyID string, key *seal.Key) (string, error) {
	r, err := agewrap.ParseRecipient(d.Recipient)
	if err != nil {
		return "", fmt.Errorf("device %s: %w", d.ID, err)
	}
	slot, err := agewrap.WrapSlot(r, scopeName, keyID, key)
	if err != nil {
		return "", fmt.Errorf("wrapping to %s: %w", d.ID, err)
	}
	return slot, nil
}

// Open opens the current key with ids. prefer lists device ids whose slots
// are tried first (typically the caller's own devices, from
// policy.Identify); after those, every other slot is tried with the
// non-plugin identities only, so a hardware key is never asked to try
// slots that are not its own.
func (s *Scope) Open(ids []agewrap.Identity, prefer ...string) (*Opened, error) {
	if s.Keys == nil {
		return nil, ErrNoKey
	}
	// Every retired record must be on the chain back from the current
	// key; a stray one (for example a record forged by someone holding a
	// retired key, claiming a place it was never given) is never ignored.
	chain, err := s.Keys.Chain()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v; restore it from trunk (git checkout <trunk> -- %s)", ErrTampered, s.KeysPath(), err, s.KeysPath())
	}
	cur := s.Keys.CurrentKey()
	o := &Opened{Scope: s, keys: map[string]*seal.Key{}, inboxes: map[string]agewrap.Identity{}, keyErrs: map[string]error{}}
	o.ids = ids

	var soft []agewrap.Identity
	for _, id := range ids {
		if id.Kind != agewrap.KindPlugin {
			soft = append(soft, id)
		}
	}
	tried := map[string]bool{}
	var order []string
	var orderIDs [][]agewrap.Identity
	for _, p := range prefer {
		if _, ok := cur.Slots[p]; ok && !tried[p] {
			tried[p] = true
			order = append(order, p)
			orderIDs = append(orderIDs, ids)
		}
	}
	for _, dev := range sortedKeys(cur.Slots) {
		if !tried[dev] && len(soft) > 0 {
			order = append(order, dev)
			orderIDs = append(orderIDs, soft)
		}
	}
	var key *seal.Key
	for i, dev := range order {
		k, err := agewrap.OpenSlot(cur.Slots[dev], orderIDs[i], s.Name(), s.Keys.Current)
		if errors.Is(err, agewrap.ErrNoMatch) {
			continue
		}
		if errors.Is(err, agewrap.ErrPayloadMismatch) {
			return nil, fmt.Errorf("%w: slot %q in %s: %v", ErrTampered, dev, s.KeysPath(), err)
		}
		if err != nil {
			// A slot that does not parse is someone else's problem unless
			// it is ours; `check` reports it.
			continue
		}
		key, o.Slot = k, dev
		break
	}
	if key == nil {
		return nil, ErrNotReader
	}
	o.keys[s.Keys.Current] = key

	inbox, err := o.openInbox(s.Keys.Current, cur.InboxSealed)
	if err != nil {
		o.Close()
		return nil, err
	}
	if inbox.Recipient != cur.Inbox {
		o.Close()
		return nil, fmt.Errorf("%w in %s (key %s): carbon refuses to use this scope until the inbox is restored from trunk",
			ErrInboxMismatch, s.KeysPath(), s.Keys.Current)
	}
	o.inboxes[s.Keys.Current] = inbox
	o.walkRetired(chain)
	return o, nil
}

func (o *Opened) openInbox(keyID, sealed string) (agewrap.Identity, error) {
	ad, err := seal.InboxAD(o.Package, o.Env, keyID)
	if err != nil {
		return agewrap.Identity{}, err
	}
	pt, err := seal.Open(o.keys[keyID], sealed, ad)
	if err != nil {
		return agewrap.Identity{}, fmt.Errorf("%w: inbox_sealed of key %s in %s: %v", ErrTampered, keyID, o.KeysPath(), err)
	}
	defer clear(pt)
	ids, err := agewrap.ParseIdentityFile(pt, nil)
	if err != nil || len(ids) != 1 {
		return agewrap.Identity{}, fmt.Errorf("%w: inbox_sealed of key %s does not hold one identity", ErrTampered, keyID)
	}
	return ids[0], nil
}

// walkRetired opens the chain of retired keys back from the current key,
// in order (store.Keys.Chain): each record is unsealed by the key after it,
// with its predecessor and carried list in the associated data, so every
// link is authenticated in both directions. A link that does not open
// makes it and every older key unavailable (values under them report
// why). The chain's structure was checked by Open.
func (o *Opened) walkRetired(chain []string) {
	after := o.Keys.Current
	var broken error
	for _, id := range chain {
		r := o.Keys.Keys[id]
		if broken != nil {
			o.keyErrs[id] = broken
			continue
		}
		ad, err := seal.RetiredAD(o.Package, o.Env, id, r.Successor, r.Retired, r.Reason, r.Predecessor, r.Carried)
		if err != nil {
			broken = err
			o.keyErrs[id] = err
			continue
		}
		pt, err := seal.Open(o.keys[after], r.Sealed, ad)
		if err != nil {
			broken = fmt.Errorf("%w: retired key %s in %s: %v", ErrTampered, id, o.KeysPath(), err)
			o.keyErrs[id] = broken
			continue
		}
		k, err := seal.KeyFromBytes(pt)
		clear(pt)
		if err != nil {
			broken = fmt.Errorf("%w: retired key %s: %v", ErrTampered, id, err)
			o.keyErrs[id] = broken
			continue
		}
		o.keys[id] = k
		if r.InboxSealed != "" {
			if in, err := o.openInbox(id, r.InboxSealed); err == nil {
				o.inboxes[id] = in
			} else {
				if o.inboxErrs == nil {
					o.inboxErrs = map[string]error{}
				}
				o.inboxErrs[id] = err
			}
		}
		after = id
	}
}

// key returns the scope key for id, or why it is unavailable.
func (o *Opened) key(id string) (*seal.Key, error) {
	if k := o.keys[id]; k != nil {
		return k, nil
	}
	if err := o.keyErrs[id]; err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w %s in %s", ErrUnknownKey, id, o.Name())
}

// Value is a revealed secret.
type Value struct {
	Name  string
	Bytes []byte
	Set   time.Time
	KeyID string
	Drop  bool // written to the inbox, not yet promoted
	Stale bool // unproven: under a retired key that does not list it as carried (IsUnproven)
}

// Zero overwrites the value bytes.
func (v *Value) Zero() {
	if v != nil {
		clear(v.Bytes)
	}
}

// Reveal decrypts one entry. Errors wrap ErrNotFound, ErrTampered or
// ErrUnknownKey. The value's location (package, env, name, key, set time) is
// authenticated: an entry copied or edited fails with ErrTampered.
func (o *Opened) Reveal(name string) (*Value, error) {
	e, ok := o.Secrets.Entries[name]
	if !ok {
		return nil, fmt.Errorf("%s %s: %w", o.Name(), name, ErrNotFound)
	}
	v := &Value{Name: name, Set: e.Set, KeyID: e.Key, Drop: e.IsDrop(), Stale: o.IsUnproven(name, e)}
	if e.IsDrop() {
		inbox, ok := o.inboxes[e.Key]
		if !ok {
			if err := o.inboxErrs[e.Key]; err != nil {
				return nil, fmt.Errorf("%s %s: drop: %w", o.Name(), name, err)
			}
			if _, err := o.key(e.Key); err != nil {
				return nil, fmt.Errorf("%s %s: drop: %w", o.Name(), name, err)
			}
			return nil, fmt.Errorf("%s %s: %w: the drop was written to the inbox of key %s, which is not available; ask its author to run `carbon set` again",
				o.Name(), name, ErrUnknownKey, e.Key)
		}
		b, err := agewrap.OpenDrop(e.Drop, []agewrap.Identity{inbox},
			agewrap.Drop{Package: o.Package, Env: o.Env, Name: name, Set: e.Set})
		if err != nil {
			return nil, fmt.Errorf("%s %s: drop %w: %v", o.Name(), name, ErrTampered, err)
		}
		v.Bytes = b
		return v, nil
	}
	k, err := o.key(e.Key)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", o.Name(), name, err)
	}
	ad, err := seal.ValueAD(o.Package, o.Env, name, e.Key, e.Set)
	if err != nil {
		return nil, err
	}
	b, err := seal.Open(k, e.Value, ad)
	if err != nil {
		return nil, fmt.Errorf("%s %s: value %w: it was edited, or moved here from another name, package, environment or set time", o.Name(), name, ErrTampered)
	}
	v.Bytes = b
	return v, nil
}

// RevealAll decrypts every entry, in name order. It stops at the first
// error.
func (o *Opened) RevealAll() ([]*Value, error) {
	var out []*Value
	for _, name := range o.Secrets.Names() {
		v, err := o.Reveal(name)
		if err != nil {
			for _, x := range out {
				x.Zero()
			}
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Seal stores value under name, sealed with the current key, set at the
// given time (truncated to whole seconds, UTC). It replaces any value or
// drop under the name.
func (o *Opened) Seal(name string, value []byte, set time.Time) error {
	if err := config.CheckSecretName(name); err != nil {
		return err
	}
	set = wholeSecond(set)
	cur := o.Keys.Current
	k, err := o.key(cur)
	if err != nil {
		return err
	}
	ad, err := seal.ValueAD(o.Package, o.Env, name, cur, set)
	if err != nil {
		return err
	}
	blob, err := seal.Seal(k, value, ad)
	if err != nil {
		return err
	}
	o.Secrets.Entries[name] = store.Entry{Key: cur, Set: set, Value: blob}
	return nil
}

// Promote is PromoteAt(name, time.Now()).
func (o *Opened) Promote(name string) (bool, error) { return o.PromoteAt(name, time.Now()) }

// PromoteAt re-seals a drop as a value under the current key, keeping its
// set time unless that is later than now: a dropper chooses the set time, so
// a future one is clamped to now. It reports whether name was a drop.
func (o *Opened) PromoteAt(name string, now time.Time) (bool, error) {
	e, ok := o.Secrets.Entries[name]
	if !ok {
		return false, fmt.Errorf("%s %s: %w", o.Name(), name, ErrNotFound)
	}
	if !e.IsDrop() {
		return false, nil
	}
	v, err := o.Reveal(name)
	if err != nil {
		return false, err
	}
	defer v.Zero()
	set := v.Set
	if now = wholeSecond(now); set.After(now) {
		set = now
	}
	return true, o.Seal(name, v.Bytes, set)
}

// PromoteDrops is PromoteDropsAt(time.Now()).
func (o *Opened) PromoteDrops() ([]string, error) { return o.PromoteDropsAt(time.Now()) }

// PromoteDropsAt promotes every drop (see PromoteAt) and returns the names
// promoted. It stops at the first drop that does not open.
func (o *Opened) PromoteDropsAt(now time.Time) ([]string, error) {
	var done []string
	for _, name := range o.Secrets.Names() {
		ok, err := o.PromoteAt(name, now)
		if err != nil {
			return done, err
		}
		if ok {
			done = append(done, name)
		}
	}
	return done, nil
}

// StaleEntry is an entry under a key other than the current one. A value
// under a retired key proves only that its writer held that key, which a
// removed reader still does: its author is unproven, so `apply` must list
// these for confirmation before re-sealing them, and `ls` marks them.
type StaleEntry struct {
	Name  string
	KeyID string
	Set   time.Time
	Drop  bool
	// KeyKnown is false when the keys file has no record of KeyID.
	KeyKnown bool
	// Retired is when KeyID was retired (zero if unknown or not retired).
	Retired time.Time
	// SetAfterRetired is true when Set is later than Retired: written, or
	// claimed to be written, after the key was retired. Treat as suspect.
	SetAfterRetired bool
}

// StaleEntries lists the unproven entries (IsUnproven), in name order. It
// needs no key.
func (s *Scope) StaleEntries() []StaleEntry {
	if s.Keys == nil {
		return nil
	}
	var out []StaleEntry
	for _, name := range s.Secrets.Names() {
		e := s.Secrets.Entries[name]
		if !s.IsUnproven(name, e) {
			continue
		}
		st := StaleEntry{Name: name, KeyID: e.Key, Set: e.Set, Drop: e.IsDrop()}
		if r, ok := s.Keys.Keys[e.Key]; ok {
			st.KeyKnown, st.Retired = true, r.Retired
			st.SetAfterRetired = r.IsRetired() && e.Set.After(r.Retired)
		}
		out = append(out, st)
	}
	return out
}

// RefreshResult says what ResealUnproven did.
type RefreshResult struct {
	// Moved are the entries re-written under the current key, as they were
	// before the move (so SetAfterRetired still describes them).
	Moved []StaleEntry
	// SkippedDrops are drops that did not open; they are left exactly as
	// they were.
	SkippedDrops []string
}

// ResealUnproven moves every unproven entry (StaleEntries) to the current
// key, keeping its set time: values are re-sealed, drops are re-dropped to
// the current inbox (they stay drops). Carried entries are left alone. A value that does not open is an error;
// a drop that does not open is skipped and reported. Callers should show
// result.Moved (StaleEntries before the call) for confirmation: re-sealing
// launders an unproven author into a current-key value.
func (o *Opened) ResealUnproven() (RefreshResult, error) {
	var r RefreshResult
	for _, st := range o.StaleEntries() {
		if err := o.move(st.Name); err != nil {
			if st.Drop {
				r.SkippedDrops = append(r.SkippedDrops, st.Name)
				continue
			}
			return r, err
		}
		r.Moved = append(r.Moved, st)
	}
	return r, nil
}

// move re-writes one entry under the current key, preserving kind and set.
func (o *Opened) move(name string) error {
	v, err := o.Reveal(name)
	if err != nil {
		return err
	}
	defer v.Zero()
	if !v.Drop {
		return o.Seal(name, v.Bytes, v.Set)
	}
	cur := o.Keys.CurrentKey()
	return o.Scope.Drop(Inbox{KeyID: o.Keys.Current, Recipient: cur.Inbox}, name, v.Bytes, v.Set)
}

// AddSlots wraps the current key to each device that has no slot yet and
// returns the ids added. A device whose slot exists but records another
// recipient (SlotDiff.Rekeyed) is left alone: its old key can still read, so
// it needs a rotation, which writes fresh slots.
func (o *Opened) AddSlots(devices []policy.Device) ([]string, error) {
	cur := o.Keys.CurrentKey()
	k, err := o.key(o.Keys.Current)
	if err != nil {
		return nil, err
	}
	var added []string
	for _, d := range devices {
		if _, ok := cur.Slots[d.ID]; ok {
			continue
		}
		slot, err := wrapTo(d, o.Name(), o.Keys.Current, k)
		if err != nil {
			return added, err
		}
		cur.SetSlot(d.ID, d.RecipientHash(), slot)
		added = append(added, d.ID)
	}
	return added, nil
}

// Rotate replaces the current key: a new key and inbox pair with slots for
// devices, and the old key retired, sealed under the new one, with reason
// ("removed <who>" for a removal). The secrets file is not touched: every
// entry stays under the key id it was written with and keeps opening
// through the retired chain. A removed reader has seen those values
// already, so re-sealing them would protect nothing, and leaving them makes
// a rotation commit touch only the keys file. The retired record lists in
// Carried the line hash of every entry under it at this moment; an entry
// under it that is not listed was added later and its author is unproven.
// It returns the new key id.
func (o *Opened) Rotate(devices []policy.Device, reason string, now time.Time) (string, error) {
	if reason == "" || strings.ContainsAny(reason, "\r\n") {
		return "", errors.New("a rotation needs a one-line reason")
	}
	if len(devices) == 0 {
		return "", ErrNoDevices
	}
	now = wholeSecond(now)
	oldID := o.Keys.Current
	oldKey, err := o.key(oldID)
	if err != nil {
		return "", err
	}
	newID, rec, newKey, newInbox, err := o.newKeyRecord(devices, now, o.Keys.Keys)
	if err != nil {
		return "", err
	}
	// The key being retired replaced the newest retired key, if any.
	chain, err := o.Keys.Chain()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTampered, err)
	}
	predecessor := ""
	if len(chain) > 0 {
		predecessor = chain[0]
	}
	carried := o.CarriedBy(oldID)
	ad, err := seal.RetiredAD(o.Package, o.Env, oldID, newID, now, reason, predecessor, carried)
	if err != nil {
		return "", err
	}
	sealedOld, err := seal.Seal(newKey, oldKey[:], ad)
	if err != nil {
		return "", err
	}
	old := o.Keys.Keys[oldID]
	old.Retired, old.Reason, old.Successor, old.Sealed, old.Carried, old.Predecessor = now, reason, newID, sealedOld, carried, predecessor
	old.Inbox, old.Slots, old.SlotTo = "", nil, nil
	o.Keys.Keys[newID] = rec
	o.Keys.Current = newID
	o.keys[newID] = newKey
	o.inboxes[newID] = newInbox
	return newID, nil
}

// CarriedBy returns the sorted line hashes of the entries under key id in
// the secrets file: what a rotation of id records as carried.
func (s *Scope) CarriedBy(id string) []string {
	out := []string{}
	for _, name := range s.Secrets.Names() {
		if e := s.Secrets.Entries[name]; e.Key == id {
			out = append(out, store.LineHash(name, e))
		}
	}
	sort.Strings(out)
	return out
}

// Inbox is where non-readers drop values: a key id and its inbox recipient.
type Inbox struct {
	KeyID     string
	Recipient string
}

// TrunkInbox returns the current inbox of a keys file read from trunk. The
// caller must read keys from the trunk ref, never the working tree, so a
// key swapped on a branch is never used.
func TrunkInbox(keys *store.Keys, pkg, env string) (Inbox, error) {
	if keys == nil {
		return Inbox{}, ErrNoKey
	}
	if keys.Scope != config.ScopeName(pkg, env) {
		return Inbox{}, fmt.Errorf("%w: trunk keys file says %q", ErrWrongScope, keys.Scope)
	}
	return Inbox{KeyID: keys.Current, Recipient: keys.CurrentKey().Inbox}, nil
}

// ReadKeysAt reads a scope's keys file from src (for example the trunk ref)
// given the package directory as a slash path relative to the root. It
// returns (nil, nil) when the file does not exist there.
func ReadKeysAt(src config.Source, pkgDir, env string) (*store.Keys, error) {
	rel := path.Join(pkgDir, config.CarbonDir, env+".keys.toml")
	data, err := src.ReadFile(rel)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return store.ParseKeys(src.String()+":"+rel, data)
}

// Drop writes value as a drop to inbox under name. It needs no key: this is
// how someone who cannot read the scope sets a secret.
func (s *Scope) Drop(inbox Inbox, name string, value []byte, set time.Time) error {
	if err := config.CheckSecretName(name); err != nil {
		return err
	}
	if agewrap.RecipientKind(inbox.Recipient) == "" {
		return fmt.Errorf("inbox %q is not an age recipient", inbox.Recipient)
	}
	r, err := agewrap.ParseRecipient(inbox.Recipient)
	if err != nil {
		return err
	}
	set = wholeSecond(set)
	blob, err := agewrap.WriteDrop(r, agewrap.Drop{Package: s.Package, Env: s.Env, Name: name, Set: set, Value: value})
	if err != nil {
		return err
	}
	s.Secrets.Entries[name] = store.Entry{Key: inbox.KeyID, Set: set, Drop: blob}
	return nil
}

// Status is what `ls` shows for one name, with no key needed.
type Status struct {
	Name     string
	Declared bool
	Stored   bool
	Drop     bool
	KeyID    string
	Set      time.Time
	Stale    bool // stored under a key other than the current one
	Private  bool
	// Unproven is a stale sealed value: it proves only that its writer held
	// a retired key, which a removed reader may still hold.
	Unproven bool
	// SetAfterRetired: stale, and set later than its key was retired.
	SetAfterRetired bool
}

// State returns a short word for the status: "sealed", "drop", "unset",
// "undeclared", or "stale".
func (st Status) State() string {
	switch {
	case !st.Stored:
		return "unset"
	case !st.Declared:
		return "undeclared"
	case st.Drop:
		return "drop"
	case st.Stale:
		return "stale"
	}
	return "sealed"
}

// List merges declarations with stored entries, sorted by name.
func (s *Scope) List(declared map[string]config.Secret) []Status {
	byName := map[string]*Status{}
	for name, d := range declared {
		byName[name] = &Status{Name: name, Declared: true, Private: d.Private}
	}
	for name, e := range s.Secrets.Entries {
		st, ok := byName[name]
		if !ok {
			st = &Status{Name: name}
			byName[name] = st
		}
		st.Stored, st.Drop, st.KeyID, st.Set = true, e.IsDrop(), e.Key, e.Set
		st.Stale = s.IsUnproven(name, e)
		st.Unproven = st.Stale && !st.Drop
		if st.Stale {
			if r, ok := s.Keys.Keys[e.Key]; ok && r.IsRetired() && e.Set.After(r.Retired) {
				st.SetAfterRetired = true
			}
		}
	}
	out := make([]Status, 0, len(byName))
	for _, n := range sortedKeys(byName) {
		out = append(out, *byName[n])
	}
	return out
}

// newKeyID returns "k" and 5 random [a-z0-9] characters, unique in existing.
func newKeyID(existing map[string]*store.Key) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for {
		var b [5]byte
		for i := 0; i < len(b); {
			var r [1]byte
			if _, err := rand.Read(r[:]); err != nil {
				return "", err
			}
			if r[0] >= 252 { // 252 = 7*36: reject to avoid modulo bias
				continue
			}
			b[i] = alphabet[int(r[0])%len(alphabet)]
			i++
		}
		id := "k" + string(b[:])
		if _, ok := existing[id]; !ok {
			return id, nil
		}
	}
}

func wholeSecond(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PackageDir joins a workspace root and a package's slash Dir.
func PackageDir(root, dir string) string { return filepath.Join(root, filepath.FromSlash(dir)) }

// RotationReason is the reason `apply` records on the key it retires,
// from the slot diff against trunk policy (sa): "removed <who>" for slots
// whose device policy no longer names (a person when all of their slots go
// and policy names none of their devices, else each device; machines as
// machine:<name>), and "rekeyed <device>, ..." for slots wrapped to a key
// the device no longer has; joined with ", ". `check` recomputes it from
// trunk's key and trunk policy and requires the same text, so the two
// cannot drift.
func RotationReason(d SlotDiff, sa *policy.ScopeAccess) string {
	rekeyed := map[string]bool{}
	for _, dev := range d.Rekeyed {
		rekeyed[dev.ID] = true
	}
	var removed, rekeyedIDs []string
	for _, id := range d.Extra {
		if rekeyed[id] {
			rekeyedIDs = append(rekeyedIDs, id)
		} else {
			removed = append(removed, id)
		}
	}
	var reasons []string
	if len(removed) > 0 {
		reasons = append(reasons, "removed "+removedWho(removed, d.Slots, sa))
	}
	if len(rekeyedIDs) > 0 {
		reasons = append(reasons, "rekeyed "+strings.Join(rekeyedIDs, ", "))
	}
	return strings.Join(reasons, ", ")
}

// removedWho names what a rotation removes: a person when all of their
// slots go and policy names none of their devices, else each device; and
// machines.
func removedWho(extra, slots []string, sa *policy.ScopeAccess) string {
	byPerson := map[string][]string{}
	var people, out []string
	for _, id := range extra {
		if strings.HasPrefix(id, config.MachinePrefix) {
			continue
		}
		person, _, _ := strings.Cut(id, "/")
		if _, ok := byPerson[person]; !ok {
			people = append(people, person)
		}
		byPerson[person] = append(byPerson[person], id)
	}
	sort.Strings(people)
	for _, person := range people {
		all := 0
		for _, id := range slots {
			if strings.HasPrefix(id, person+"/") {
				all++
			}
		}
		named := false
		for _, d := range sa.Devices {
			if d.Person == person {
				named = true
			}
		}
		if all == len(byPerson[person]) && !named {
			out = append(out, person)
		} else {
			out = append(out, byPerson[person]...)
		}
	}
	for _, id := range extra {
		if strings.HasPrefix(id, config.MachinePrefix) {
			out = append(out, id)
		}
	}
	return strings.Join(out, ", ")
}

// IsUnproven reports whether an entry's author is unproven: it is under a
// key other than the current one, and the retired record of that key does
// not list its line as carried (the entries under the key when it was
// retired). A carried entry is an ordinary value that a rotation left in
// place; an unproven one was written later by someone holding a retired
// key, which a removed reader may. An entry under an unknown key id is
// unproven too.
//
// Carried lists count only on the chain of keys back from the current key
// (store.Keys.Chain); a record off it carries nothing. Opened.IsUnproven
// further requires the record to have opened, which authenticates it.
func (s *Scope) IsUnproven(name string, e store.Entry) bool {
	if s.Keys == nil || e.Key == s.Keys.Current {
		return false
	}
	r, ok := s.Keys.Keys[e.Key]
	if !ok || !r.IsRetired() {
		return true
	}
	chain, err := s.Keys.Chain()
	if err != nil || !slices.Contains(chain, e.Key) {
		return true
	}
	h := store.LineHash(name, e)
	i := sort.SearchStrings(r.Carried, h)
	return i == len(r.Carried) || r.Carried[i] != h
}

// IsUnproven is Scope.IsUnproven, and an entry under a retired key that
// did not open (its record failed authentication) is unproven too.
func (o *Opened) IsUnproven(name string, e store.Entry) bool {
	if o.Scope.IsUnproven(name, e) {
		return true
	}
	return e.Key != o.Keys.Current && o.keys[e.Key] == nil
}
