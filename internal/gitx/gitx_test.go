package gitx

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.com")
	if _, err := run(dir, "init", "-q", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	r, err := Find(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func write(t *testing.T, r *Repo, rel, s string) {
	t.Helper()
	p := filepath.Join(r.Root, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindOutsideRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", os.TempDir())
	dir := t.TempDir()
	if _, err := Find(dir); !errors.Is(err, ErrNotRepo) {
		t.Fatalf("err = %v", err)
	}
}

func TestRefSource(t *testing.T) {
	r := newRepo(t)
	if ok, err := r.RefExists("main"); ok || err != nil {
		t.Fatalf("unborn main exists: %v %v", ok, err)
	}
	write(t, r, "carbon.toml", "a")
	write(t, r, "svc/x/carbon.toml", "b")
	write(t, r, "node_modules/y/carbon.toml", "c")
	write(t, r, ".carbon/people/ada.toml", "ada")
	write(t, r, ".carbon/people/lin.toml", "lin")
	write(t, r, "with space/carbon.toml", "d")
	if err := r.Commit("init", "."); err != nil {
		t.Fatal(err)
	}
	write(t, r, "carbon.toml", "changed in worktree")
	write(t, r, "svc/new/carbon.toml", "uncommitted")

	if ok, err := r.RefExists("main"); !ok || err != nil {
		t.Fatalf("main missing: %v", err)
	}
	if ok, _ := r.RefExists("origin/main"); ok {
		t.Fatal("origin/main exists")
	}
	src := r.Source("main")
	b, err := src.ReadFile("carbon.toml")
	if err != nil || string(b) != "a" {
		t.Fatalf("ReadFile = %q %v", b, err)
	}
	if _, err := src.ReadFile("svc/new/carbon.toml"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("uncommitted file: %v", err)
	}
	names, _ := src.ReadDir(".carbon/people")
	if !reflect.DeepEqual(names, []string{"ada.toml", "lin.toml"}) {
		t.Fatalf("ReadDir = %v", names)
	}
	found, _ := src.Find("carbon.toml")
	if !reflect.DeepEqual(found, []string{"carbon.toml", "svc/x/carbon.toml", "with space/carbon.toml"}) {
		t.Fatalf("Find = %v", found)
	}
	if src.String() != "main" {
		t.Fatal(src.String())
	}
}

func TestGitDirAndIgnore(t *testing.T) {
	r := newRepo(t)
	write(t, r, ".gitignore", ".env\n")
	gd, err := r.GitDir()
	if err != nil || gd != filepath.Join(r.Root, ".git") {
		t.Fatalf("GitDir = %q %v", gd, err)
	}
	if ok, err := r.IsIgnored(".env"); !ok || err != nil {
		t.Fatalf(".env ignored = %v %v", ok, err)
	}
	if ok, err := r.IsIgnored("main.go"); ok || err != nil {
		t.Fatalf("main.go ignored = %v %v", ok, err)
	}
	rel, err := r.Rel(filepath.Join(r.Root, "a", "b"))
	if err != nil || rel != "a/b" {
		t.Fatal(rel, err)
	}
	if _, err := r.Rel(filepath.Dir(r.Root)); err == nil {
		t.Fatal("path outside repo accepted")
	}
}
