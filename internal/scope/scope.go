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
	Missing []policy.Device // named, no slot: pending grants
	Extra   []string        // slot, not named: pending revocations
}

// DiffSlots compares the current key's slots with devices.
func (s *Scope) DiffSlots(devices []policy.Device) SlotDiff {
	var d SlotDiff
	slots := map[string]string{}
	if s.Keys != nil {
		slots = s.Keys.CurrentKey().Slots
	}
	named := map[string]bool{}
	for _, dev := range devices {
		named[dev.ID] = true
		if _, ok := slots[dev.ID]; !ok {
			d.Missing = append(d.Missing, dev)
		}
	}
	for _, id := range sortedKeys(slots) {
		if !named[id] {
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
}

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
	rec := &store.Key{Created: now, Inbox: recipient, InboxSealed: inboxSealed, Slots: map[string]string{}}
	for _, d := range devices {
		slot, err := wrapTo(d, o.Name(), id, key)
		if err != nil {
			return fail(err)
		}
		rec.Slots[d.ID] = slot
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
	cur := s.Keys.CurrentKey()
	o := &Opened{Scope: s, keys: map[string]*seal.Key{}, inboxes: map[string]agewrap.Identity{}, keyErrs: map[string]error{}}

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
	o.walkRetired()
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

// walkRetired opens every retired key reachable from the current key
// through successors.
func (o *Opened) walkRetired() {
	for progress := true; progress; {
		progress = false
		for _, id := range o.Keys.IDs() {
			r := o.Keys.Keys[id]
			if !r.IsRetired() || o.keys[id] != nil || o.keyErrs[id] != nil {
				continue
			}
			succ := o.keys[r.Successor]
			if succ == nil {
				if o.keyErrs[r.Successor] != nil {
					o.keyErrs[id] = o.keyErrs[r.Successor]
					progress = true
				}
				continue
			}
			progress = true
			ad, err := seal.RetiredAD(o.Package, o.Env, id, r.Successor, r.Retired, r.Reason)
			if err != nil {
				o.keyErrs[id] = err
				continue
			}
			pt, err := seal.Open(succ, r.Sealed, ad)
			if err != nil {
				o.keyErrs[id] = fmt.Errorf("%w: retired key %s in %s: %v", ErrTampered, id, o.KeysPath(), err)
				continue
			}
			k, err := seal.KeyFromBytes(pt)
			clear(pt)
			if err != nil {
				o.keyErrs[id] = fmt.Errorf("%w: retired key %s: %v", ErrTampered, id, err)
				continue
			}
			o.keys[id] = k
			if r.InboxSealed != "" {
				if in, err := o.openInbox(id, r.InboxSealed); err == nil {
					o.inboxes[id] = in
				}
			}
		}
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
	Stale bool // under a key other than the current one
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
	v := &Value{Name: name, Set: e.Set, KeyID: e.Key, Drop: e.IsDrop(), Stale: e.Key != o.Keys.Current}
	if e.IsDrop() {
		inbox, ok := o.inboxes[e.Key]
		if !ok {
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

// Promote re-seals a drop as a value under the current key, keeping its set
// time. It reports whether name was a drop.
func (o *Opened) Promote(name string) (bool, error) {
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
	return true, o.Seal(name, v.Bytes, v.Set)
}

// PromoteDrops promotes every drop and returns the names promoted.
func (o *Opened) PromoteDrops() ([]string, error) {
	var done []string
	for _, name := range o.Secrets.Names() {
		ok, err := o.Promote(name)
		if err != nil {
			return done, err
		}
		if ok {
			done = append(done, name)
		}
	}
	return done, nil
}

// Refresh moves every entry under a retired key to the current key, keeping
// its set time: values are re-sealed, drops are re-dropped to the current
// inbox (they stay drops). It returns the names moved.
func (o *Opened) Refresh() ([]string, error) {
	var done []string
	for _, name := range o.Secrets.Names() {
		e := o.Secrets.Entries[name]
		if e.Key == o.Keys.Current {
			continue
		}
		if err := o.move(name); err != nil {
			return done, err
		}
		done = append(done, name)
	}
	return done, nil
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
// returns the ids added.
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
		cur.Slots[d.ID] = slot
		added = append(added, d.ID)
	}
	return added, nil
}

// Rotate replaces the current key: a new key and inbox pair with slots for
// devices, every entry re-written under the new key keeping its set time
// (drops stay drops, in the new inbox), and the old key retired, sealed
// under the new one, with reason ("removed <who>" for a removal). Nothing
// changes if any entry fails to open. It returns the new key id.
func (o *Opened) Rotate(devices []policy.Device, reason string, now time.Time) (string, error) {
	if reason == "" || strings.ContainsAny(reason, "\r\n") {
		return "", errors.New("a rotation needs a one-line reason")
	}
	if len(devices) == 0 {
		return "", ErrNoDevices
	}
	now = wholeSecond(now)
	values, err := o.RevealAll()
	if err != nil {
		return "", fmt.Errorf("rotation stopped before changing anything: %w", err)
	}
	defer func() {
		for _, v := range values {
			v.Zero()
		}
	}()
	oldID := o.Keys.Current
	oldKey, err := o.key(oldID)
	if err != nil {
		return "", err
	}
	newID, rec, newKey, newInbox, err := o.newKeyRecord(devices, now, o.Keys.Keys)
	if err != nil {
		return "", err
	}
	ad, err := seal.RetiredAD(o.Package, o.Env, oldID, newID, now, reason)
	if err != nil {
		return "", err
	}
	sealedOld, err := seal.Seal(newKey, oldKey[:], ad)
	if err != nil {
		return "", err
	}

	// Re-write entries into a fresh secrets table before touching state.
	entries := map[string]store.Entry{}
	for _, v := range values {
		if v.Drop {
			r, err := agewrap.ParseRecipient(rec.Inbox)
			if err != nil {
				return "", err
			}
			blob, err := agewrap.WriteDrop(r, agewrap.Drop{Package: o.Package, Env: o.Env, Name: v.Name, Set: v.Set, Value: v.Bytes})
			if err != nil {
				return "", err
			}
			entries[v.Name] = store.Entry{Key: newID, Set: v.Set, Drop: blob}
			continue
		}
		vad, err := seal.ValueAD(o.Package, o.Env, v.Name, newID, v.Set)
		if err != nil {
			return "", err
		}
		blob, err := seal.Seal(newKey, v.Bytes, vad)
		if err != nil {
			return "", err
		}
		entries[v.Name] = store.Entry{Key: newID, Set: v.Set, Value: blob}
	}

	old := o.Keys.Keys[oldID]
	old.Retired, old.Reason, old.Successor, old.Sealed = now, reason, newID, sealedOld
	old.Inbox, old.Slots = "", nil
	o.Keys.Keys[newID] = rec
	o.Keys.Current = newID
	o.Secrets.Entries = entries
	o.keys[newID] = newKey
	o.inboxes[newID] = newInbox
	return newID, nil
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
		st.Stale = s.Keys != nil && e.Key != s.Keys.Current
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
