package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Source is where configuration is read from: the working tree
// ([DirSource]) or a git ref (gitx.RefSource). All paths are slash-separated
// and relative to the workspace root.
type Source interface {
	// ReadFile returns a file's content. A missing file returns an error
	// for which errors.Is(err, fs.ErrNotExist) holds.
	ReadFile(name string) ([]byte, error)
	// ReadDir lists the regular files directly inside dir, sorted. A
	// missing dir is not an error.
	ReadDir(dir string) ([]string, error)
	// Find lists every file in the tree whose base name is base, sorted.
	Find(base string) ([]string, error)
	// String describes the source for messages: "the working tree", or a ref.
	String() string
}

// DirSource reads the working tree under Root. It refuses any path with a
// symbolic link in it (store.SymlinkError), and Find refuses a symlinked
// file of the name it looks for, unless SkipSymlinks is set (then such a
// file is left out; `carbon check` reports it as a finding instead).
type DirSource struct {
	Root         string
	SkipSymlinks bool
}

func (d DirSource) String() string { return "the working tree" }

func (d DirSource) ReadFile(name string) ([]byte, error) {
	if err := NoSymlinks(d.Root, name); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(d.Root, filepath.FromSlash(name)))
}

func (d DirSource) ReadDir(dir string) ([]string, error) {
	if err := NoSymlinks(d.Root, dir); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(filepath.Join(d.Root, filepath.FromSlash(dir)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// Find walks the tree. It skips directories whose name starts with "." and
// node_modules directories, so package files under .git, editor state, or
// installed dependencies are never picked up.
func (d DirSource) Find(base string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(d.Root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if p != d.Root && (strings.HasPrefix(e.Name(), ".") || e.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Name() == base && e.Type()&fs.ModeSymlink != 0 && !d.SkipSymlinks {
			rel, _ := filepath.Rel(d.Root, p)
			return &SymlinkError{Path: filepath.ToSlash(rel)}
		}
		if e.Name() == base && e.Type().IsRegular() {
			rel, err := filepath.Rel(d.Root, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// ConflictError means a file carbon reads contains git conflict markers.
type ConflictError struct{ Path string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s contains git conflict markers", e.Path)
}

// HasConflictMarkers reports whether data contains a line that starts a git
// conflict hunk ("<<<<<<< ", "=======", ">>>>>>> ", or "||||||| ").
func HasConflictMarkers(data []byte) bool {
	for line := range bytes.Lines(data) {
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case bytes.HasPrefix(line, []byte("<<<<<<< ")), bytes.Equal(line, []byte("<<<<<<<")),
			bytes.HasPrefix(line, []byte(">>>>>>> ")), bytes.Equal(line, []byte(">>>>>>>")),
			bytes.HasPrefix(line, []byte("||||||| ")),
			bytes.Equal(line, []byte("=======")):
			return true
		}
	}
	return false
}

// readIfExists returns nil content and no error for a missing file.
func readIfExists(src Source, name string) ([]byte, error) {
	b, err := src.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// dirOf returns the slash directory of a file path, "." at the root.
func dirOf(p string) string { return path.Dir(p) }
