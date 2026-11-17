package gitx

import (
	"errors"
	"io/fs"
	"testing"
)

func TestRefSourceBatchReadsManyFiles(t *testing.T) {
	r := newRepo(t)
	files := map[string]string{
		"a.toml":            "alpha\n",
		"empty.toml":        "",
		"with space/x.toml": "spaced",
		"bin.dat":           "\x00\xff\n\nbinary",
		"d/e/f.toml":        "deep",
	}
	for p, c := range files {
		write(t, r, p, c)
	}
	if err := r.Commit("init", "."); err != nil {
		t.Fatal(err)
	}
	r.CacheSources = true
	src := r.Source("main")
	if r.Source("main") != src {
		t.Fatal("CacheSources did not return the same source")
	}
	defer src.Close()
	for round := 0; round < 2; round++ {
		for p, want := range files {
			got, err := src.ReadFile(p)
			if err != nil || string(got) != want {
				t.Fatalf("%s = %q %v, want %q", p, got, err, want)
			}
		}
	}
	// Paths outside the listing are never asked of git.
	for _, p := range []string{"missing.toml", "d", "d/e", "../a.toml"} {
		if _, err := src.ReadFile(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	// Still usable after a miss.
	if got, _ := src.ReadFile("a.toml"); string(got) != "alpha\n" {
		t.Fatal("batch broken after a miss")
	}
	src.Close()
	if got, _ := src.ReadFile("d/e/f.toml"); string(got) != "deep" {
		t.Fatal("reopen after Close")
	}
	if r2 := (&Repo{Root: r.Root}); r2.Source("main") == r2.Source("main") {
		t.Fatal("sources cached without CacheSources")
	}
}
