package pins

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/scope"
)

const fpA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fpB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestRoundTripAndDeterminism(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carbon", FileName)
	f, err := Load(path)
	if err != nil || len(f.Readers) != 0 {
		t.Fatal(f, err)
	}
	r1, r2 := strings.Repeat("1", 32), strings.Repeat("2", 32)
	f.Set(r2, "search/dev", scope.KeyPin{KeyID: "k22222", Fingerprint: fpB})
	f.Set(r1, "checkout/prod", scope.KeyPin{KeyID: "k11111", Fingerprint: fpA})
	f.Set(r1, "checkout/dev", scope.KeyPin{KeyID: "k33333", Fingerprint: fpB})
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	data, _ := os.ReadFile(path)
	want := "# carbon reader pins: the last scope key each identity verified in this clone.\n" +
		"# Delete this file (or run `carbon trust`) to re-pin on next use.\n" +
		"\n[readers." + r1 + "]\n" +
		`"checkout/dev" = { key = "k33333", fingerprint = "` + fpB + `" }` + "\n" +
		`"checkout/prod" = { key = "k11111", fingerprint = "` + fpA + `" }` + "\n" +
		"\n[readers." + r2 + "]\n" +
		`"search/dev" = { key = "k22222", fingerprint = "` + fpB + `" }` + "\n"
	if string(data) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", data, want)
	}
	g, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := g.Get(r1, "checkout/prod"); !ok || p.KeyID != "k11111" || p.Fingerprint != fpA {
		t.Fatal(p, ok)
	}
	if _, ok := g.Get(r2, "checkout/prod"); ok {
		t.Fatal("pins leaked between readers")
	}
	if !g.Rename("checkout/prod", "shop/prod") || g.Rename("nope/prod", "x/prod") {
		t.Fatal("Rename")
	}
	if _, ok := g.Get(r1, "shop/prod"); !ok {
		t.Fatal("renamed pin missing")
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	for _, bad := range []string{
		"not toml [",
		"[readers.zz]\n",
		"[readers." + strings.Repeat("1", 32) + "]\n\"checkout/prod\" = { key = \"bad\", fingerprint = \"" + fpA + "\" }\n",
		"[readers." + strings.Repeat("1", 32) + "]\n\"checkout/prod\" = { key = \"k11111\", fingerprint = \"short\" }\n",
		"[readers." + strings.Repeat("1", 32) + "]\n\"checkout\" = { key = \"k11111\", fingerprint = \"" + fpA + "\" }\n",
		"[other]\n",
	} {
		path := filepath.Join(t.TempDir(), FileName)
		os.WriteFile(path, []byte(bad), 0o600)
		var ce *CorruptError
		if _, err := Load(path); !errors.As(err, &ce) || ce.Path != path {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestReaderID(t *testing.T) {
	_, a, _ := agewrap.GenerateIdentity(agewrap.KindX25519)
	_, b, _ := agewrap.GenerateIdentity(agewrap.KindX25519)
	ia, ib := agewrap.Identity{Recipient: a}, agewrap.Identity{Recipient: b}
	id := ReaderID([]agewrap.Identity{ia, ib})
	if len(id) != 32 || id != ReaderID([]agewrap.Identity{ib, ia}) || id == ReaderID([]agewrap.Identity{ia}) {
		t.Fatal("ReaderID")
	}
}

func TestPathIsSharedByWorktrees(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	git := func(d string, args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = d
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	main := filepath.Join(dir, "main")
	os.MkdirAll(main, 0o755)
	git(main, "init", "-q", "-b", "main")
	git(main, "commit", "-q", "--allow-empty", "-m", "x")
	git(main, "worktree", "add", "-q", filepath.Join(dir, "wt"))
	r1, _ := gitx.Find(main)
	r2, _ := gitx.Find(filepath.Join(dir, "wt"))
	p1, err1 := Path(r1)
	p2, err2 := Path(r2)
	if err1 != nil || err2 != nil || p1 != p2 || p1 != filepath.Join(main, ".git", "carbon", FileName) {
		t.Fatalf("%q %q %v %v", p1, p2, err1, err2)
	}
}
