package policy

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
)

// A branch edits its own carbon.toml to escape trunk policy. The workspace
// passed to LoadTrunk is the working tree's, exactly as commands load it.
func TestLoadTrunkIgnoresTheBranchsTrunkName(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	f := newFixture(t)
	git(t, f.root, "init", "-q", "-b", "main")
	git(t, f.root, "add", "-A")
	git(t, f.root, "commit", "-qm", "carbon")
	git(t, f.root, "checkout", "-qb", "evil")
	repo, err := gitx.Find(f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.write(".carbon/teams.toml", "engineering = [\"ada\"]\npayments = [\"ada\"]\nsre = [\"ada\"]\n")
	for _, trunk := range []string{"worktree", "evil"} {
		f.write("carbon.toml", strings.Replace(mustRead(t, f.root, "carbon.toml"), `trunk = "main"`, `trunk = "`+trunk+`"`, 1))
		git(t, f.root, "add", "-A")
		git(t, f.root, "commit", "-qm", "escape via "+trunk)
		ws, err := config.LoadWorkspace(config.DirSource{Root: f.root})
		if err != nil {
			t.Fatal(err)
		}
		p, err := LoadTrunk(repo, ws)
		if err != nil {
			t.Fatal(err)
		}
		if p.Origin != OriginTrunk || p.Ref != "main" {
			t.Fatalf("trunk = %q on the branch: origin %s ref %s", trunk, p.Origin, p.Ref)
		}
		if sa, _ := p.Scope("checkout", "prod"); sa.Names("ada/laptop") {
			t.Fatalf("trunk = %q: branch policy leaked", trunk)
		}
		f.write("carbon.toml", strings.Replace(mustRead(t, f.root, "carbon.toml"), `trunk = "`+trunk+`"`, `trunk = "main"`, 1))
	}
}
