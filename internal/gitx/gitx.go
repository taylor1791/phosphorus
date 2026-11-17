// Package gitx is carbon's git plumbing. git is the only external program
// carbon runs; this package is the only place that runs it. Arguments are
// never secret values, and git never prompts.
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrNotRepo means the directory is not inside a git work tree.
var ErrNotRepo = errors.New("not inside a git repository")

// Error is a failed git command.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error { return e.Err }

// Repo is a git work tree.
type Repo struct {
	// Root is the absolute path of the work tree's top level.
	Root string
}

// Find returns the repo containing dir.
func Find(dir string) (*Repo, error) {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		var ge *Error
		if errors.As(err, &ge) && strings.Contains(ge.Stderr, "not a git repository") {
			return nil, ErrNotRepo
		}
		return nil, err
	}
	return &Repo{Root: strings.TrimSpace(string(out))}, nil
}

// Git runs git in the repo root and returns stdout.
func (r *Repo) Git(args ...string) ([]byte, error) { return run(r.Root, args...) }

func run(dir string, args ...string) ([]byte, error) {
	full := append([]string{"-c", "core.quotepath=off"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(ScrubbedEnviron(os.Environ()), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &Error{Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// GitDir returns the absolute git directory of this work tree (per
// worktree, so `carbon env use` state is per worktree).
func (r *Repo) GitDir() (string, error) {
	out, err := r.Git("rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// RefExists reports whether ref names a commit.
func (r *Repo) RefExists(ref string) (bool, error) {
	_, err := r.Git("rev-parse", "--verify", "--quiet", ref+"^{commit}")
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

// ResolveRef returns the commit id ref points to.
func (r *Repo) ResolveRef(ref string) (string, error) {
	out, err := r.Git("rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsIgnored reports whether git ignores path (relative to the repo root or
// absolute).
func (r *Repo) IsIgnored(p string) (bool, error) {
	_, err := r.Git("check-ignore", "-q", "--", p)
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

// Add stages paths.
func (r *Repo) Add(paths ...string) error {
	_, err := r.Git(append([]string{"add", "--"}, paths...)...)
	return err
}

// Commit commits exactly paths (staging them first) with message.
func (r *Repo) Commit(message string, paths ...string) error {
	if err := r.Add(paths...); err != nil {
		return err
	}
	_, err := r.Git(append([]string{"commit", "-q", "-m", message, "--"}, paths...)...)
	return err
}

// Rel converts an absolute path inside the repo to a slash path relative to
// the root.
func (r *Repo) Rel(abs string) (string, error) {
	rel, err := filepath.Rel(r.Root, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the repository", abs)
	}
	return filepath.ToSlash(rel), nil
}

// RefSource reads files at a git ref. It satisfies config.Source. The file
// list is read once with `git ls-tree` and file contents with
// `git cat-file`; nothing in the working tree is consulted.
type RefSource struct {
	Repo *Repo
	Ref  string

	once  sync.Once
	files map[string]bool
	err   error
}

// Source returns a RefSource for ref.
func (r *Repo) Source(ref string) *RefSource { return &RefSource{Repo: r, Ref: ref} }

func (s *RefSource) String() string { return s.Ref }

func (s *RefSource) list() (map[string]bool, error) {
	s.once.Do(func() {
		out, err := s.Repo.Git("ls-tree", "-r", "-z", "--full-tree", "--name-only", s.Ref)
		if err != nil {
			s.err = err
			return
		}
		s.files = map[string]bool{}
		for _, f := range bytes.Split(out, []byte{0}) {
			if len(f) > 0 {
				s.files[string(f)] = true
			}
		}
	})
	return s.files, s.err
}

// Files returns every file path at the ref, sorted.
func (s *RefSource) Files() ([]string, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for f := range files {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// ReadFile returns a file's content at the ref (fs.ErrNotExist if absent).
func (s *RefSource) ReadFile(name string) ([]byte, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	name = path.Clean(name)
	if !files[name] {
		return nil, &fs.PathError{Op: "read", Path: s.Ref + ":" + name, Err: fs.ErrNotExist}
	}
	return s.Repo.Git("cat-file", "blob", s.Ref+":"+name)
}

// ReadDir lists the files directly inside dir at the ref.
func (s *RefSource) ReadDir(dir string) ([]string, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	dir = path.Clean(dir)
	var out []string
	for f := range files {
		if path.Dir(f) == dir {
			out = append(out, path.Base(f))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Find lists every file at the ref whose base name is base, skipping the
// same directories config.DirSource skips.
func (s *RefSource) Find(base string) ([]string, error) {
	files, err := s.list()
	if err != nil {
		return nil, err
	}
	var out []string
	for f := range files {
		if path.Base(f) != base || skipped(f) {
			continue
		}
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

func skipped(f string) bool {
	parts := strings.Split(f, "/")
	for _, p := range parts[:len(parts)-1] {
		if strings.HasPrefix(p, ".") || p == "node_modules" {
			return true
		}
	}
	return false
}

// identityVars are environment variables that carry carbon key material or
// point at it. They are removed from every subprocess carbon starts.
var identityVars = []string{"CARBON_IDENTITY", "CARBON_IDENTITY_FILE"}

// ScrubbedEnviron returns environ (as from os.Environ) without
// CARBON_IDENTITY and CARBON_IDENTITY_FILE. Every git subprocess gets it;
// `run` should use it for the child process too.
func ScrubbedEnviron(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, v := range identityVars {
			if name == v {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}

// ConfigGet reads a key from the repository's own git config (--local). ok
// is false when the key is unset.
func (r *Repo) ConfigGet(key string) (value string, ok bool, err error) {
	out, err := r.Git("config", "--local", "--get", key)
	if err != nil {
		var ge *Error
		var ee *exec.ExitError
		if errors.As(err, &ge) && errors.As(ge.Err, &ee) && ee.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(string(out)), true, nil
}

// ConfigSet writes a key to the repository's own git config (--local).
func (r *Repo) ConfigSet(key, value string) error {
	_, err := r.Git("config", "--local", key, value)
	return err
}

// HasRemoteRefs reports whether the repository has any remote-tracking refs.
func (r *Repo) HasRemoteRefs() (bool, error) {
	out, err := r.Git("for-each-ref", "--count=1", "--format=%(refname)", "refs/remotes/")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// RemoteDefault returns the remote default branch as a short ref, trying
// refs/remotes/origin/HEAD, then origin/main, then origin/master. ok is false
// when none exists.
func (r *Repo) RemoteDefault() (ref string, ok bool, err error) {
	if out, err := r.Git("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s, true, nil
		}
	}
	for _, c := range []string{"origin/main", "origin/master"} {
		ok, err := r.RefExists("refs/remotes/" + c)
		if err != nil {
			return "", false, err
		}
		if ok {
			return c, true, nil
		}
	}
	return "", false, nil
}

// CommonDir returns the absolute git common directory: shared by every
// worktree of a clone (unlike GitDir, which is per worktree).
func (r *Repo) CommonDir() (string, error) {
	out, err := r.Git("rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
