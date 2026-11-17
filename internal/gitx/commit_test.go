package gitx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Commit takes paths literally and runs no hook from the repository.
func TestCommitIsLiteralAndRunsNoHooks(t *testing.T) {
	r := newRepo(t)
	write(t, r, "a.txt", "a\n")
	if _, err := r.Git("add", "a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Git("commit", "-qm", "base"); err != nil {
		t.Fatal(err)
	}
	// A hooks directory the branch ships, configured as core.hooksPath.
	marker := filepath.Join(r.Root, "hook-ran")
	for _, h := range []string{"pre-commit", "commit-msg", "post-commit"} {
		write(t, r, ".githooks/"+h, "#!/bin/sh\ntouch "+marker+"\nexit 1\n")
		os.Chmod(filepath.Join(r.Root, ".githooks", h), 0o755)
	}
	if _, err := r.Git("config", "core.hooksPath", ".githooks"); err != nil {
		t.Fatal(err)
	}
	// "*.txt" is a file name here, not a glob: b.txt must stay out.
	write(t, r, "*.txt", "star\n")
	write(t, r, "b.txt", "b\n")
	if err := r.Commit("literal", "*.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a repository hook ran")
	}
	out, _ := r.Git("show", "--name-only", "--format=", "HEAD")
	if strings.TrimSpace(string(out)) != "*.txt" {
		t.Fatalf("committed %q", out)
	}
	if d, err := r.Detached(); err != nil || d {
		t.Fatal(d, err)
	}
	r.Git("checkout", "-q", "--detach")
	if d, err := r.Detached(); err != nil || !d {
		t.Fatal(d, err)
	}
}
