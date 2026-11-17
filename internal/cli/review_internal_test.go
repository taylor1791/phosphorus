package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func sameDevice(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && sa.Dev == sb.Dev
}

func TestWritePrivateDirectFallback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.env")
	os.WriteFile(p, []byte("old and longer content"), 0o644)
	os.Chmod(p, 0o666)
	if err := writeDirect(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// Never through a symlink.
	target := filepath.Join(dir, "tracked")
	os.WriteFile(target, []byte("keep"), 0o644)
	link := filepath.Join(dir, "link.env")
	os.Symlink(target, link)
	if err := writeDirect(link, []byte("x")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("symlink target changed")
	}
}

func TestWritePrivateAcrossFilesystems(t *testing.T) {
	other := "/dev/shm"
	a, err1 := os.Stat(other)
	dir := t.TempDir()
	b, err2 := os.Stat(dir)
	if err1 != nil || err2 != nil || !a.IsDir() || sameDevice(a, b) {
		t.Skip("no second filesystem to test the cross-device fallback")
	}
	tmp, err := os.MkdirTemp(other, "carbon-test-")
	if err != nil {
		t.Skip(err)
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(dir, "out.env")
	if err := writePrivate(p, tmp, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temporary file left in %s", tmp)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("extra files in the target directory: %v", ents)
	}
}

func TestFindExecutableReportsSkippedRelativeEntry(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "bin", "tool"), []byte("#!/bin/sh\n"), 0o755)
	t.Chdir(dir)
	_, err := findExecutable("tool", "/nonexistent:bin")
	e := AsError(err)
	if err == nil || !strings.Contains(strings.Join(e.Details, " "), `only in the relative PATH entry "bin"`) || !strings.Contains(e.Hint, "bin/tool") {
		t.Fatalf("%v %v %s", err, e.Details, e.Hint)
	}
	// The first absolute match wins, in PATH order.
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, d := range []string{a, b} {
		os.Mkdir(d, 0o755)
		os.WriteFile(filepath.Join(d, "tool"), []byte("#!/bin/sh\n"), 0o755)
	}
	if p, err := findExecutable("tool", "bin:"+b+":"+a); err != nil || p != filepath.Join(b, "tool") {
		t.Fatalf("%q %v", p, err)
	}
	if lookupIn([]string{"PATH=/first", "PATH=/second"}, "PATH") != "/first" {
		t.Fatal("lookupIn must return the first entry, as getenv does")
	}
}
