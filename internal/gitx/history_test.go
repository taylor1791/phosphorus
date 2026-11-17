package gitx

import (
	"errors"
	"strings"
	"testing"
)

func TestAncestryAndUnchangedSince(t *testing.T) {
	r := newRepo(t)
	write(t, r, "a.txt", "one")
	if err := r.Commit("one", "."); err != nil {
		t.Fatal(err)
	}
	base, _ := r.ResolveRef("HEAD")
	if _, err := r.Git("branch", "side"); err != nil {
		t.Fatal(err)
	}
	write(t, r, "a.txt", "two")
	if err := r.Commit("two", "."); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.IsAncestor("side", "main"); !ok || err != nil {
		t.Fatalf("side ancestor of main: %v %v", ok, err)
	}
	if ok, err := r.IsAncestor("main", "side"); ok || err != nil {
		t.Fatalf("main ancestor of side: %v %v", ok, err)
	}
	mb, err := r.MergeBase("main", "side")
	if err != nil || mb != base {
		t.Fatalf("merge base %q %v, want %s", mb, err, base)
	}

	if ok, err := r.UnchangedSince(base, "a.txt"); ok || err != nil {
		t.Fatalf("a.txt changed since base: %v %v", ok, err)
	}
	if ok, err := r.UnchangedSince("HEAD", "a.txt"); !ok || err != nil {
		t.Fatalf("a.txt unchanged since HEAD: %v %v", ok, err)
	}
	if ok, _ := r.UnchangedSince("HEAD", "missing.txt"); !ok {
		t.Fatal("absent on both sides is unchanged")
	}
	write(t, r, "new.txt", "untracked")
	if ok, _ := r.UnchangedSince("HEAD", "new.txt"); ok {
		t.Fatal("an untracked new file is a change")
	}

	// Unrelated history has no merge base.
	if _, err := r.Git("checkout", "-q", "--orphan", "other"); err != nil {
		t.Fatal(err)
	}
	write(t, r, "b.txt", "x")
	if err := r.Commit("other", "b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.MergeBase("main", "other"); !errors.Is(err, ErrNoMergeBase) {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.IsAncestor("nope", "main"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("missing ref: %v", err)
	}
}
