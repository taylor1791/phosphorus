package gitx

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IsAncestor reports whether commit a is an ancestor of (or equal to)
// commit b (`git merge-base --is-ancestor a b`).
func (r *Repo) IsAncestor(a, b string) (bool, error) {
	_, err := r.Git("merge-base", "--is-ancestor", a+"^{commit}", b+"^{commit}")
	if err == nil {
		return true, nil
	}
	var ge *Error
	var ee *exec.ExitError
	if errors.As(err, &ge) && errors.As(ge.Err, &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// ErrNoMergeBase means two commits share no history this clone has: unrelated
// histories, or a shallow clone that stops before their merge base.
var ErrNoMergeBase = errors.New("no merge base in this clone's history")

// MergeBase returns the best common ancestor of a and b. It returns
// [ErrNoMergeBase] when there is none (or the clone is too shallow to see it).
func (r *Repo) MergeBase(a, b string) (string, error) {
	out, err := r.Git("merge-base", a+"^{commit}", b+"^{commit}")
	if err != nil {
		var ge *Error
		var ee *exec.ExitError
		if errors.As(err, &ge) && errors.As(ge.Err, &ee) && ee.ExitCode() == 1 {
			return "", ErrNoMergeBase
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// UnchangedSince reports whether the working tree's file at the slash path
// rel has exactly the content it had at commit (both absent counts as
// unchanged). It compares bytes, so an untracked file counts as a change.
func (r *Repo) UnchangedSince(commit, rel string) (bool, error) {
	then, err := r.Source(commit).ReadFile(rel)
	thenMissing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !thenMissing {
		return false, err
	}
	now, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(rel)))
	nowMissing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !nowMissing {
		return false, err
	}
	if thenMissing || nowMissing {
		return thenMissing == nowMissing, nil
	}
	return bytes.Equal(then, now), nil
}
