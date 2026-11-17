package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
)

// TestLoadTrunkLegacyRootIsBootstrap: a trunk whose root carbon.toml is a
// carbon 0.0.3 file has not adopted carbon 1.0 yet (the carbon-migrate
// cutover branch), so policy comes from the working tree with a notice. A
// 0.0.3 file in the working tree is still the legacy error.
func TestLoadTrunkLegacyRootIsBootstrap(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	f := newFixture(t)
	ws, err := os.ReadFile(filepath.Join(f.root, "carbon.toml"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := "name = \"web\"\n[pull.host]\nservice = \"db\"\n"
	git(t, f.root, "init", "-q", "-b", "main")
	f.write("carbon.toml", legacy)
	git(t, f.root, "add", "-A")
	git(t, f.root, "commit", "-qm", "0.0.3")
	git(t, f.root, "checkout", "-qb", "cutover")
	f.write("carbon.toml", string(ws))
	repo, err := gitx.Find(f.root)
	if err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == TrunkEnv {
			return "main"
		}
		return ""
	}
	p, err := LoadTrunkWith(repo, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginBootstrap || !strings.Contains(p.Notice, "0.0.3") {
		t.Fatalf("origin %s notice %q", p.Origin, p.Notice)
	}
	if sa, _ := p.Scope("checkout", "prod"); !sa.Names("lin/laptop") {
		t.Fatal("working-tree policy not used")
	}
	f.write("carbon.toml", legacy)
	var le *config.LegacyError
	if _, err := LoadTrunkWith(repo, getenv); !errors.As(err, &le) {
		t.Fatalf("0.0.3 working tree: %v, want the legacy error", err)
	}
}
