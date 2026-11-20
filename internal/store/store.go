// Package store reads and writes the two files carbon writes for each scope:
// <package dir>/.carbon/<env>.secrets.toml and <env>.keys.toml.
//
// Parsing is strict (unknown keys, malformed ids, and conflict markers are
// errors). Writing is deterministic: fixed field order, map keys sorted, one
// logical item per line, LF endings and a trailing newline, so that
// independent changes merge.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/internal/config"
)

// SecretsPath is <pkgDir>/.carbon/<env>.secrets.toml.
func SecretsPath(pkgDir, env string) string {
	return filepath.Join(pkgDir, config.CarbonDir, env+".secrets.toml")
}

// KeysPath is <pkgDir>/.carbon/<env>.keys.toml.
func KeysPath(pkgDir, env string) string {
	return filepath.Join(pkgDir, config.CarbonDir, env+".keys.toml")
}

// ParseError is a malformed secrets or keys file.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

// Entry is one line of a secrets file. Exactly one of Value and Drop is set.
type Entry struct {
	Key   string    // key id the value is sealed under, or whose inbox the drop was written to
	Set   time.Time // UTC, whole seconds
	Value string    // "carbon1:..." sealed by a reader
	Drop  string    // "age1:..." written to the inbox, maybe by a non-reader
}

// IsDrop reports whether the entry is a drop.
func (e Entry) IsDrop() bool { return e.Drop != "" }

// Secrets is a parsed secrets file.
type Secrets struct {
	Entries map[string]Entry
}

// NewSecrets returns an empty secrets file.
func NewSecrets() *Secrets { return &Secrets{Entries: map[string]Entry{}} }

// Names returns the secret names in order.
func (s *Secrets) Names() []string { return sortedKeys(s.Entries) }

type entryTOML struct {
	Key   string     `toml:"key"`
	Set   *time.Time `toml:"set"`
	Value string     `toml:"value"`
	Drop  string     `toml:"drop"`
}

// ParseSecrets parses a secrets file. path is used in errors only.
func ParseSecrets(path string, data []byte) (*Secrets, error) {
	if config.HasConflictMarkers(data) {
		return nil, &config.ConflictError{Path: path}
	}
	var raw map[string]entryTOML
	if err := strictDecode(data, &raw); err != nil {
		return nil, &ParseError{path, err}
	}
	if loose, err := looseTables(data); err != nil {
		return nil, &ParseError{path, err}
	} else if err := offsetTimesOnly(data, loose, "set"); err != nil {
		return nil, &ParseError{path, err}
	}
	s := NewSecrets()
	for name, e := range raw {
		if err := config.CheckSecretName(name); err != nil {
			return nil, &ParseError{path, err}
		}
		if !config.ValidKeyID(e.Key) {
			return nil, &ParseError{path, fmt.Errorf("%s: key %q is not a key id", name, e.Key)}
		}
		if e.Set == nil {
			return nil, &ParseError{path, fmt.Errorf("%s: missing set time", name)}
		}
		set, err := checkTime(*e.Set)
		if err != nil {
			return nil, &ParseError{path, fmt.Errorf("%s: set: %w", name, err)}
		}
		switch {
		case e.Value != "" && e.Drop != "":
			return nil, &ParseError{path, fmt.Errorf("%s has both value and drop", name)}
		case e.Value == "" && e.Drop == "":
			return nil, &ParseError{path, fmt.Errorf("%s has neither value nor drop", name)}
		case e.Value != "" && !strings.HasPrefix(e.Value, "carbon1:"):
			return nil, &ParseError{path, fmt.Errorf("%s: value is not a carbon1: blob", name)}
		case e.Drop != "" && !strings.HasPrefix(e.Drop, "age1:"):
			return nil, &ParseError{path, fmt.Errorf("%s: drop is not an age1: blob", name)}
		}
		s.Entries[name] = Entry{Key: e.Key, Set: set, Value: e.Value, Drop: e.Drop}
	}
	return s, nil
}

// Marshal renders the secrets file.
func (s *Secrets) Marshal() []byte {
	var b bytes.Buffer
	for _, name := range s.Names() {
		b.WriteString(EntryLine(name, s.Entries[name]))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// EntryLine is the line the deterministic writer emits for one entry,
// without its trailing newline.
func EntryLine(name string, e Entry) string {
	field, blob := "value", e.Value
	if e.IsDrop() {
		field, blob = "drop", e.Drop
	}
	return fmt.Sprintf("%s = { key = %s, set = %s, %s = %s }",
		name, config.Quote(e.Key), formatTime(e.Set), field, config.Quote(blob))
}

// LineHash is "sha256:" and the hex SHA-256 of EntryLine(name, e): how a
// retired key's carried list names the entries that were under it when it
// was retired.
func LineHash(name string, e Entry) string {
	sum := sha256.Sum256([]byte(EntryLine(name, e)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Key is one [keys.<id>] table. A current key has Created, Inbox,
// InboxSealed and Slots. A retired key has Created, Retired, Reason,
// Successor and Sealed, plus InboxSealed so that drops written to its inbox
// on older branches still open (see docs/deviations.md).
type Key struct {
	Created     time.Time
	Inbox       string
	InboxSealed string
	Slots       map[string]string // device id -> "age1:..."
	// SlotTo maps each slot's device id to "sha256:<64 hex>": the SHA-256 of
	// the recipient string the slot was wrapped to, exactly as written in the
	// people or machine file (agewrap.RecipientHash). Every slot needs one;
	// set both maps together (SetSlot). Not authenticated by cryptography:
	// `check` protects it against trunk.
	SlotTo map[string]string

	Retired   time.Time
	Reason    string
	Successor string
	// Predecessor is the id of the key this key replaced, "" for a
	// scope's first key. Authenticated in Sealed's associated data, it
	// links the chain backwards, so a record that claims a successor it
	// was never the predecessor of is detected.
	Predecessor string
	Sealed      string
	// Carried lists, for a retired key, the LineHash of every entry that
	// was under it when it was retired, sorted. Entries under a retired
	// key that are not listed were added later: their author is unproven.
	// It is authenticated: its digest is part of Sealed's associated data.
	Carried []string
}

// IsRetired reports whether the key has been retired.
func (k *Key) IsRetired() bool { return !k.Retired.IsZero() }

// Keys is a parsed keys file.
type Keys struct {
	Scope   string // "<package>/<env>"
	Current string
	Keys    map[string]*Key
}

// CurrentKey returns the current key's record.
func (k *Keys) CurrentKey() *Key { return k.Keys[k.Current] }

// IDs returns every key id, sorted.
func (k *Keys) IDs() []string { return sortedKeys(k.Keys) }

type keyTOML struct {
	Created     *time.Time          `toml:"created"`
	Inbox       string              `toml:"inbox"`
	InboxSealed string              `toml:"inbox_sealed"`
	Slots       map[string]slotTOML `toml:"slots"`
	Retired     *time.Time          `toml:"retired"`
	Reason      string              `toml:"reason"`
	Successor   string              `toml:"successor"`
	Predecessor string              `toml:"predecessor"`
	Sealed      string              `toml:"sealed"`
	Carried     *[]string           `toml:"carried"`
}

type slotTOML struct {
	To   string `toml:"to"`
	Slot string `toml:"slot"`
}

type keysTOML struct {
	Scope   string             `toml:"scope"`
	Current string             `toml:"current"`
	Keys    map[string]keyTOML `toml:"keys"`
}

// ParseKeys parses a keys file and checks its structure: the current key
// exists and is the only unretired key, every retired key names an existing
// successor, ids are valid, and blobs carry the right prefix.
func ParseKeys(path string, data []byte) (*Keys, error) {
	if config.HasConflictMarkers(data) {
		return nil, &config.ConflictError{Path: path}
	}
	var raw keysTOML
	if loose, err := looseTables(data); err != nil {
		return nil, &ParseError{path, err}
	} else if id, dev, old := oldSlotForm(loose); old {
		return nil, &ParseError{path, fmt.Errorf("[keys.%s.slots] %q uses the old slot format (a bare string): a slot is now { to = \"sha256:...\", slot = \"age1:...\" }; regenerate the keys file", id, dev)}
	} else if keys, ok := loose["keys"].(map[string]any); ok {
		if err := offsetTimesOnly(data, keys, "created", "retired"); err != nil {
			return nil, &ParseError{path, err}
		}
	}
	if err := strictDecode(data, &raw); err != nil {
		return nil, &ParseError{path, err}
	}
	fail := func(f string, a ...any) error { return &ParseError{path, fmt.Errorf(f, a...)} }
	if _, _, err := config.ParseScopeName(raw.Scope); err != nil {
		return nil, fail("scope: %v", err)
	}
	ks := &Keys{Scope: raw.Scope, Current: raw.Current, Keys: map[string]*Key{}}
	for id, r := range raw.Keys {
		if !config.ValidKeyID(id) {
			return nil, fail("[keys.%s]: not a key id", id)
		}
		k := &Key{Inbox: r.Inbox, InboxSealed: r.InboxSealed, Slots: map[string]string{}, SlotTo: map[string]string{},
			Reason: r.Reason, Successor: r.Successor, Predecessor: r.Predecessor, Sealed: r.Sealed}
		if r.Created == nil {
			return nil, fail("[keys.%s]: missing created", id)
		}
		var err error
		if k.Created, err = checkTime(*r.Created); err != nil {
			return nil, fail("[keys.%s] created: %v", id, err)
		}
		for dev, s := range r.Slots {
			k.Slots[dev], k.SlotTo[dev] = s.Slot, s.To
		}
		if (r.Retired == nil || k.InboxSealed != "") && !strings.HasPrefix(k.InboxSealed, "carbon1:") {
			return nil, fail("[keys.%s]: inbox_sealed must be a carbon1: blob", id)
		}
		if r.Retired != nil {
			if k.Retired, err = checkTime(*r.Retired); err != nil {
				return nil, fail("[keys.%s] retired: %v", id, err)
			}
			switch {
			case k.Inbox != "" || len(k.Slots) > 0:
				return nil, fail("[keys.%s] is retired but still has an inbox or slots", id)
			case k.Reason == "":
				return nil, fail("[keys.%s] is retired without a reason", id)
			case strings.ContainsAny(k.Reason, "\r\n"):
				return nil, fail("[keys.%s] reason contains a newline", id)
			case k.Predecessor != "" && (!config.ValidKeyID(k.Predecessor) || k.Predecessor == id):
				return nil, fail("[keys.%s] predecessor is not a valid key id", id)
			case !config.ValidKeyID(k.Successor):
				return nil, fail("[keys.%s] is retired without a valid successor", id)
			case !strings.HasPrefix(k.Sealed, "carbon1:"):
				return nil, fail("[keys.%s] is retired without a sealed key", id)
			case r.Carried == nil:
				return nil, fail("[keys.%s] is retired without a carried list", id)
			}
			for i, h := range *r.Carried {
				if !slotToRe.MatchString(h) {
					return nil, fail("[keys.%s] carried: %q is not \"sha256:<64 hex>\"", id, h)
				}
				if i > 0 && (*r.Carried)[i-1] >= h {
					return nil, fail("[keys.%s] carried must be sorted, without repeats", id)
				}
			}
			k.Carried = append([]string{}, *r.Carried...)
		} else {
			switch {
			case r.Carried != nil:
				return nil, fail("[keys.%s] has a carried list but no retired time", id)
			case k.Reason != "" || k.Successor != "" || k.Sealed != "" || k.Predecessor != "":
				return nil, fail("[keys.%s] has retirement fields but no retired time", id)
			case k.Inbox == "":
				return nil, fail("[keys.%s] has no inbox", id)
			}
			for dev, slot := range k.Slots {
				if !config.ValidDeviceID(dev) {
					return nil, fail("[keys.%s.slots]: %q is not <person>/<device> or machine:<name>", id, dev)
				}
				if !strings.HasPrefix(slot, "age1:") {
					return nil, fail("[keys.%s.slots] %s is not an age1: blob", id, dev)
				}
				if !slotToRe.MatchString(k.SlotTo[dev]) {
					return nil, fail("[keys.%s.slots] %s: to must be \"sha256:<64 hex>\", the hash of the recipient it is wrapped to", id, dev)
				}
			}
		}
		ks.Keys[id] = k
	}
	cur, ok := ks.Keys[ks.Current]
	if !ok {
		return nil, fail("current key %q has no [keys.%s] table", ks.Current, ks.Current)
	}
	if cur.IsRetired() {
		return nil, fail("current key %s is retired", ks.Current)
	}
	for id, k := range ks.Keys {
		if id != ks.Current && !k.IsRetired() {
			return nil, fail("key %s is neither current nor retired", id)
		}
		if k.IsRetired() {
			if _, ok := ks.Keys[k.Successor]; !ok {
				return nil, fail("retired key %s names successor %s, which is not in the file", id, k.Successor)
			}
		}
	}
	// Every retired key must reach the current key through successors.
	for id := range ks.Keys {
		seen := map[string]bool{}
		for at := id; at != ks.Current; at = ks.Keys[at].Successor {
			if seen[at] {
				return nil, fail("retired keys form a cycle at %s", at)
			}
			seen[at] = true
		}
	}
	return ks, nil
}

// Marshal renders the keys file. Field order follows
// docs/implementation.md; key ids and slot ids are sorted.
func (k *Keys) Marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "scope = %s\ncurrent = %s\n", config.Quote(k.Scope), config.Quote(k.Current))
	for _, id := range k.IDs() {
		r := k.Keys[id]
		fmt.Fprintf(&b, "\n[keys.%s]\n", id)
		fmt.Fprintf(&b, "created = %s\n", formatTime(r.Created))
		if r.IsRetired() {
			fmt.Fprintf(&b, "retired = %s\n", formatTime(r.Retired))
			fmt.Fprintf(&b, "reason = %s\n", config.Quote(r.Reason))
			fmt.Fprintf(&b, "successor = %s\n", config.Quote(r.Successor))
			if r.Predecessor != "" {
				fmt.Fprintf(&b, "predecessor = %s\n", config.Quote(r.Predecessor))
			}
			fmt.Fprintf(&b, "sealed = %s\n", config.Quote(r.Sealed))
			q := make([]string, len(r.Carried))
			for i, h := range r.Carried {
				q[i] = config.Quote(h)
			}
			fmt.Fprintf(&b, "carried = [%s]\n", strings.Join(q, ", "))
			if r.InboxSealed != "" {
				fmt.Fprintf(&b, "inbox_sealed = %s\n", config.Quote(r.InboxSealed))
			}
			continue
		}
		fmt.Fprintf(&b, "inbox = %s\n", config.Quote(r.Inbox))
		fmt.Fprintf(&b, "inbox_sealed = %s\n", config.Quote(r.InboxSealed))
		if len(r.Slots) > 0 {
			fmt.Fprintf(&b, "\n[keys.%s.slots]\n", id)
			for _, dev := range sortedKeys(r.Slots) {
				fmt.Fprintf(&b, "%s = { to = %s, slot = %s }\n", config.Quote(dev), config.Quote(r.SlotTo[dev]), config.Quote(r.Slots[dev]))
			}
		}
	}
	return b.Bytes()
}

// ReadSecrets reads a secrets file; a missing file is an empty one.
func ReadSecrets(path string) (*Secrets, error) {
	if err := config.NoSymlinkFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return NewSecrets(), nil
	}
	if err != nil {
		return nil, err
	}
	return ParseSecrets(path, data)
}

// ReadKeys reads a keys file. It returns (nil, nil) when the scope has no
// keys file yet.
func ReadKeys(path string) (*Keys, error) {
	if err := config.NoSymlinkFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseKeys(path, data)
}

// WriteFile replaces path atomically (write a temporary file, then rename),
// creating the parent directory. Files carbon writes are mode 0644: they
// are committed and hold only ciphertext.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := config.NoSymlinkFile(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".carbon-tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func formatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

func checkTime(t time.Time) (time.Time, error) {
	if _, off := t.Zone(); off != 0 {
		return time.Time{}, errors.New("must be UTC (end in Z)")
	}
	if t.Nanosecond() != 0 {
		return time.Time{}, errors.New("must be whole seconds")
	}
	return t.UTC(), nil
}

func strictDecode(data []byte, v any) error {
	d := toml.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	err := d.Decode(v)
	if err == nil {
		return nil
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, col := de.Position()
		return fmt.Errorf("line %d column %d: %s", row, col, de.Error())
	}
	var sm *toml.StrictMissingError
	if errors.As(err, &sm) {
		var keys []string
		for _, e := range sm.Errors {
			keys = append(keys, strings.Join(e.Key(), "."))
		}
		return fmt.Errorf("unknown key %s", strings.Join(keys, ", "))
	}
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// offsetTimesOnly rejects TOML local date-times and dates in the named
// fields: they would otherwise be read in the machine's time zone. tables
// maps a table name to its fields; fields of every inline table under it
// are checked.
func offsetTimesOnly(data []byte, tables map[string]any, fields ...string) error {
	for name, v := range tables {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for _, f := range fields {
			if x, present := m[f]; present {
				if _, ok := x.(time.Time); !ok {
					return fmt.Errorf("%s: %s must be a UTC date-time like 2026-11-02T17:04:11Z", name, f)
				}
			}
		}
	}
	return nil
}

func looseTables(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

var slotToRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SetSlot stores a slot and the hash of the recipient it was wrapped to.
func (k *Key) SetSlot(device, to, slot string) {
	if k.Slots == nil {
		k.Slots = map[string]string{}
	}
	if k.SlotTo == nil {
		k.SlotTo = map[string]string{}
	}
	k.Slots[device], k.SlotTo[device] = slot, to
}

// oldSlotForm reports a slot written in the pre-`to` string form.
func oldSlotForm(loose map[string]any) (string, string, bool) {
	keys, _ := loose["keys"].(map[string]any)
	for id, v := range keys {
		rec, _ := v.(map[string]any)
		slots, _ := rec["slots"].(map[string]any)
		for dev, s := range slots {
			if _, ok := s.(string); ok {
				return id, dev, true
			}
		}
	}
	return "", "", false
}

// ChainError names a retired record that is not on the scope's chain of
// keys: another record already holds its place, or nothing links to it.
type ChainError struct {
	ID  string
	Why string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("retired key %s is not on this scope's chain of keys: %s", e.ID, e.Why)
}

// Chain returns the retired key ids on the chain back from the current
// key, newest first: the one record whose successor is the current key,
// then, from each record, the record its Predecessor names, which must
// have that record as its successor. Every other retired record is an
// error (*ChainError): a second record claiming the same successor, or a
// record nothing reaches. Readers authenticate each link when they open
// the chain (Predecessor is in the associated data); Chain checks only the
// structure, which is what keyless callers can see.
func (k *Keys) Chain() ([]string, error) {
	claims := map[string][]string{}
	for _, id := range k.IDs() {
		if r := k.Keys[id]; r.IsRetired() {
			claims[r.Successor] = append(claims[r.Successor], id)
		}
	}
	var chain []string
	on := map[string]bool{}
	at := k.Current
	next := ""
	if c := claims[at]; len(c) > 1 {
		return nil, &ChainError{ID: c[1], Why: fmt.Sprintf("%s and %s both claim to be the key that %s replaced", c[0], c[1], at)}
	} else if len(c) == 1 {
		next = c[0]
	}
	for next != "" {
		if on[next] {
			return nil, &ChainError{ID: next, Why: "the predecessors form a cycle"}
		}
		r := k.Keys[next]
		for _, other := range claims[at] {
			if other != next {
				return nil, &ChainError{ID: other, Why: fmt.Sprintf("it claims %s as its successor, but %s names %s as its predecessor", at, at, next)}
			}
		}
		chain = append(chain, next)
		on[next] = true
		at = next
		next = r.Predecessor
		if next == "" {
			if c := claims[at]; len(c) > 0 {
				return nil, &ChainError{ID: c[0], Why: fmt.Sprintf("it claims %s as its successor, but %s was the scope's first key", at, at)}
			}
			break
		}
		p, ok := k.Keys[next]
		if !ok || !p.IsRetired() || p.Successor != at {
			return nil, &ChainError{ID: at, Why: fmt.Sprintf("its predecessor %s is missing or does not name it as successor", next)}
		}
	}
	for _, id := range k.IDs() {
		if k.Keys[id].IsRetired() && !on[id] {
			return nil, &ChainError{ID: id, Why: "no key on the chain names it as its predecessor"}
		}
	}
	return chain, nil
}

// Lookup returns the entry for name; it is safe on a nil *Secrets.
func (s *Secrets) Lookup(name string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	e, ok := s.Entries[name]
	return e, ok
}
