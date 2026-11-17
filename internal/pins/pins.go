// Package pins stores each reader's memory of the last scope key it
// verified, in <git common dir>/carbon/pins.toml: shared by every worktree
// of a clone, never in the work tree, mode 0600.
//
// The file is keyed by reader (a hash of the identity's public keys), so
// several people on one machine, or simulated people in tests sharing one
// clone, never see each other's pins:
//
//	# carbon reader pins: the last scope key each identity verified.
//	[readers.0123456789abcdef0123456789abcdef]
//	"checkout/prod" = { key = "k3f9q2", fingerprint = "<64 hex>" }
//
// The rule for using a pin is scope.Opened.CheckPin.
package pins

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

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// FileName is the pins file inside <git common dir>/carbon/.
const FileName = "pins.toml"

// Path returns <git common dir>/carbon/pins.toml for repo.
func Path(repo *gitx.Repo) (string, error) {
	dir, err := repo.CommonDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "carbon", FileName), nil
}

// CorruptError means the pins file does not parse. It is never ignored.
type CorruptError struct {
	Path string
	Err  error
}

func (e *CorruptError) Error() string {
	return fmt.Sprintf("%s is corrupt: %v", e.Path, e.Err)
}
func (e *CorruptError) Unwrap() error { return e.Err }

// File is a loaded pins file.
type File struct {
	Path string
	// Readers maps a reader id (ReaderID) to scope name -> pin.
	Readers map[string]map[string]scope.KeyPin
}

// ReaderID identifies the holder of a set of identities: the first 16 bytes
// (hex) of SHA-256 over their sorted public keys, one per line. It depends
// only on the local identity, never on anything in the repository.
func ReaderID(ids []agewrap.Identity) string {
	recs := make([]string, 0, len(ids))
	for _, id := range ids {
		recs = append(recs, id.Recipient)
	}
	sort.Strings(recs)
	sum := sha256.Sum256([]byte(strings.Join(recs, "\n")))
	return hex.EncodeToString(sum[:16])
}

var (
	readerRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fpRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type pinTOML struct {
	Key         string `toml:"key"`
	Fingerprint string `toml:"fingerprint"`
}

type fileTOML struct {
	Readers map[string]map[string]pinTOML `toml:"readers"`
}

// Load reads the pins file at path; a missing file is an empty one.
func Load(path string) (*File, error) {
	f := &File{Path: path, Readers: map[string]map[string]scope.KeyPin{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	var raw fileTOML
	d := toml.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&raw); err != nil {
		return nil, &CorruptError{path, err}
	}
	for reader, scopes := range raw.Readers {
		if !readerRe.MatchString(reader) {
			return nil, &CorruptError{path, fmt.Errorf("reader %q is not 32 hex digits", reader)}
		}
		m := map[string]scope.KeyPin{}
		for name, p := range scopes {
			if _, _, err := config.ParseScopeName(name); err != nil {
				return nil, &CorruptError{path, err}
			}
			if !config.ValidKeyID(p.Key) || !fpRe.MatchString(p.Fingerprint) {
				return nil, &CorruptError{path, fmt.Errorf("%s: bad key id or fingerprint", name)}
			}
			m[name] = scope.KeyPin{KeyID: p.Key, Fingerprint: p.Fingerprint}
		}
		f.Readers[reader] = m
	}
	return f, nil
}

// Get returns a reader's pin for a scope.
func (f *File) Get(reader, scopeName string) (*scope.KeyPin, bool) {
	p, ok := f.Readers[reader][scopeName]
	if !ok {
		return nil, false
	}
	return &p, true
}

// Set stores a reader's pin for a scope.
func (f *File) Set(reader, scopeName string, p scope.KeyPin) {
	if f.Readers[reader] == nil {
		f.Readers[reader] = map[string]scope.KeyPin{}
	}
	f.Readers[reader][scopeName] = p
}

// Rename moves every reader's pin for oldScope to newScope (for a package
// rename: "old/env" -> "new/env"). It reports whether anything moved.
func (f *File) Rename(oldScope, newScope string) bool {
	moved := false
	for _, m := range f.Readers {
		if p, ok := m[oldScope]; ok {
			m[newScope] = p
			delete(m, oldScope)
			moved = true
		}
	}
	return moved
}

// Marshal renders the file deterministically.
func (f *File) Marshal() []byte {
	var b strings.Builder
	b.WriteString("# carbon reader pins: the last scope key each identity verified in this clone.\n")
	b.WriteString("# Delete this file (or run `carbon trust`) to re-pin on next use.\n")
	readers := make([]string, 0, len(f.Readers))
	for r, m := range f.Readers {
		if len(m) > 0 {
			readers = append(readers, r)
		}
	}
	sort.Strings(readers)
	for _, r := range readers {
		fmt.Fprintf(&b, "\n[readers.%s]\n", r)
		names := make([]string, 0, len(f.Readers[r]))
		for n := range f.Readers[r] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := f.Readers[r][n]
			fmt.Fprintf(&b, "%s = { key = %s, fingerprint = %s }\n", config.Quote(n), config.Quote(p.KeyID), config.Quote(p.Fingerprint))
		}
	}
	return []byte(b.String())
}

// Save writes the file atomically, mode 0600 (directory 0700).
func (f *File) Save() error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pins-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(f.Marshal()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
