package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SymlinkError means a carbon file or directory is a symbolic link. carbon
// never reads or writes its files through a link: one committed to the
// repository could point anywhere on the machine of whoever runs carbon.
type SymlinkError struct{ Path string }

func (e *SymlinkError) Error() string {
	return e.Path + " is a symbolic link; carbon does not read or write its files through links, which could point outside the repository"
}

// NoSymlinks reports a *SymlinkError if any component of rel (a slash
// path relative to root; root itself is not checked) is a symbolic link.
// Components that do not exist are fine.
func NoSymlinks(root, rel string) error {
	cur := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			r, _ := filepath.Rel(root, cur)
			return &SymlinkError{Path: filepath.ToSlash(r)}
		}
	}
	return nil
}

// noSymlinkFile reports a *SymlinkError if path or its directory (a
// package's .carbon directory) is a symbolic link.
func noSymlinkFile(path string) error {
	for _, p := range []string{filepath.Dir(path), path} {
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return &SymlinkError{Path: p}
		}
	}
	return nil
}

// NoSymlinkFile reports a *SymlinkError if path or its directory (a
// package's .carbon directory) is a symbolic link.
func NoSymlinkFile(path string) error { return noSymlinkFile(path) }
