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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// GitAttributesLine marks keys files as generated; `init` adds it to
// .gitattributes.
const GitAttributesLine = "**/.carbon/*.keys.toml linguist-generated"

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
		e := s.Entries[name]
		field, blob := "value", e.Value
		if e.IsDrop() {
			field, blob = "drop", e.Drop
		}
		fmt.Fprintf(&b, "%s = { key = %s, set = %s, %s = %s }\n",
			name, config.Quote(e.Key), formatTime(e.Set), field, config.Quote(blob))
	}
	return b.Bytes()
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

	Retired   time.Time
	Reason    string
	Successor string
	Sealed    string
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
	Created     *time.Time        `toml:"created"`
	Inbox       string            `toml:"inbox"`
	InboxSealed string            `toml:"inbox_sealed"`
	Slots       map[string]string `toml:"slots"`
	Retired     *time.Time        `toml:"retired"`
	Reason      string            `toml:"reason"`
	Successor   string            `toml:"successor"`
	Sealed      string            `toml:"sealed"`
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
	if err := strictDecode(data, &raw); err != nil {
		return nil, &ParseError{path, err}
	}
	if loose, err := looseTables(data); err != nil {
		return nil, &ParseError{path, err}
	} else if keys, ok := loose["keys"].(map[string]any); ok {
		if err := offsetTimesOnly(data, keys, "created", "retired"); err != nil {
			return nil, &ParseError{path, err}
		}
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
		k := &Key{Inbox: r.Inbox, InboxSealed: r.InboxSealed, Slots: r.Slots,
			Reason: r.Reason, Successor: r.Successor, Sealed: r.Sealed}
		if r.Created == nil {
			return nil, fail("[keys.%s]: missing created", id)
		}
		var err error
		if k.Created, err = checkTime(*r.Created); err != nil {
			return nil, fail("[keys.%s] created: %v", id, err)
		}
		if k.Slots == nil {
			k.Slots = map[string]string{}
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
			case !config.ValidKeyID(k.Successor):
				return nil, fail("[keys.%s] is retired without a valid successor", id)
			case !strings.HasPrefix(k.Sealed, "carbon1:"):
				return nil, fail("[keys.%s] is retired without a sealed key", id)
			}
		} else {
			switch {
			case k.Reason != "" || k.Successor != "" || k.Sealed != "":
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
			fmt.Fprintf(&b, "sealed = %s\n", config.Quote(r.Sealed))
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
				fmt.Fprintf(&b, "%s = %s\n", config.Quote(dev), config.Quote(r.Slots[dev]))
			}
		}
	}
	return b.Bytes()
}

// ReadSecrets reads a secrets file; a missing file is an empty one.
func ReadSecrets(path string) (*Secrets, error) {
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
