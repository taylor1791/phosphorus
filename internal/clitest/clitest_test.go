package clitest

import (
	"strings"
	"testing"
)

func TestMain(m *testing.M) { Main(m) }

func TestStandardWorld(t *testing.T) {
	w := Standard(t)
	for _, p := range []string{"ada", "lin", "sam"} {
		if !strings.Contains(w.Read(".carbon/people/"+p+".toml"), "laptop = \"age1pq1") {
			t.Fatalf("%s did not join", p)
		}
	}
	if !strings.Contains(w.Read(".carbon/machines/deploy-checkout.toml"), "key = \"age1pq1") {
		t.Fatal("machine missing")
	}
	if w.Git("status", "--porcelain") != "" {
		t.Fatal("standard world left uncommitted changes")
	}
	if w.Git("rev-parse", "--abbrev-ref", "HEAD") != "main" {
		t.Fatal("not on main")
	}
	// Each person has their own identity; the machine has none on disk.
	if w.Ada.IdentityFile() == w.Lin.IdentityFile() {
		t.Fatal("people share a home")
	}
	res := w.Deploy.In(w.PkgDir).Run("ls")
	if res.Code != 0 || !strings.Contains(res.Stdout, "checkout/dev") {
		t.Fatalf("machine run:\n%s", res)
	}
	if !strings.Contains(res.String(), "$ carbon ls") {
		t.Fatal("Result.String")
	}
}
