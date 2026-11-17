package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/migrate/internal/legacy"
)

// Regression tests for the review of carbon-migrate. Each fails on the code
// before the fix.

func readsOf(p *Plan, id string) []string {
	for _, per := range p.People {
		if per.ID == id {
			return per.Reads
		}
	}
	return nil
}

// Review 1: keys sharing a `users` name must not pool their access.
func TestPlanSplitsPeopleByAccess(t *testing.T) {
	laptop := legacy.User{Name: "alice", Key: keyA}
	desktop := legacy.User{Name: "alice", Key: keyB}
	db := svc(t, "db/carbon.toml", "name = \"db\"\n")
	p := Build(baseInput([]*legacy.Service{db}, nil, reg("", laptop, desktop), reg("prd", laptop)))
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers: %v", p.Blockers)
	}
	if got := strings.Join(readsOf(p, "alice"), ","); got != "dev,prd" {
		t.Errorf("alice reads %q", got)
	}
	if got := strings.Join(readsOf(p, "alice-2"), ","); got != "dev" {
		t.Errorf("alice-2 reads %q, want dev only (the desktop key was never a prd recipient)", got)
	}
	if !contains(p.Manual, "split: 2 keys are recorded as \"alice\"") {
		t.Errorf("split not listed: %v", p.Manual)
	}
	if v := CheckAccess(p); len(v) > 0 {
		t.Errorf("invariant: %v", v)
	}

	// Same access: one person, two devices, listed as a merge.
	p = Build(baseInput([]*legacy.Service{db}, nil, reg("", laptop, desktop), reg("prd", laptop, desktop)))
	if len(p.People) != 1 || len(p.People[0].Devices) != 2 || !contains(p.Manual, "merge: 2 keys") {
		t.Errorf("people %+v manual %v", p.People, p.Manual)
	}
}

// Review 1: the invariant catches a key that would gain access.
func TestCheckAccessInvariant(t *testing.T) {
	alice := legacy.User{Name: "alice", Key: keyA}
	p := Build(baseInput([]*legacy.Service{svc(t, "db/carbon.toml", "name = \"db\"\n")}, nil, reg("", alice), reg("prd", alice)))
	if v := CheckAccess(p); len(v) > 0 {
		t.Fatalf("clean plan: %v", v)
	}
	p.People[0].Devices["stolen"] = keyB
	v := CheckAccess(p)
	if len(v) != 2 || !strings.Contains(v[0], "alice/stolen") {
		t.Fatalf("violations = %v", v)
	}
}

// Review 3: a recipient removed from the creation rule is a pending removal,
// not a reader, unless --keep-recipient names it.
func TestPlanPendingRemoval(t *testing.T) {
	r := reg("", legacy.User{Name: "alice", Key: keyA})
	r.Granted = append(r.Granted, keyB) // bob: still a recipient, no longer in the rule
	db := svc(t, "db/carbon.toml", "name = \"db\"\n")
	p := Build(baseInput([]*legacy.Service{db}, nil, r))
	if len(p.People) != 1 || p.People[0].ID != "alice" {
		t.Errorf("people = %+v (a pending removal must not become a reader)", p.People)
	}
	if !contains(p.Manual, "pending removal: key") || !contains(p.Manual, "--keep-recipient "+keyB) {
		t.Errorf("manual = %v", p.Manual)
	}
	in := baseInput([]*legacy.Service{db}, nil, r)
	in.KeepRecipients = []string{keyB}
	p = Build(in)
	if got := strings.Join(readsOf(p, "unknown-1"), ","); got != "dev" {
		t.Errorf("--keep-recipient: unknown-1 reads %q", got)
	}
	for _, m := range p.Manual {
		if strings.Contains(m, "unknown-1") && strings.Contains(m, "rename the file") {
			t.Errorf("the unknown-key note nudges towards keeping access: %s", m)
		}
	}
}

// Review 2: the identity path being the 0.0.3 key blocks.
func TestPlanIdentityIsKeyBlocks(t *testing.T) {
	in := baseInput([]*legacy.Service{svc(t, "a/carbon.toml", "name = \"a\"\n")}, nil, reg("", legacy.User{Name: "alice", Key: keyA}))
	in.IdentityExists, in.IdentityExisting, in.IdentitySameAsKey = true, keyA, true
	if p := Build(in); !contains(p.Blockers, "would delete its only copy") || p.IdentityAction != "conflict" {
		t.Fatalf("blockers %v action %s", p.Blockers, p.IdentityAction)
	}
	in.IdentitySameAsKey, in.IdentityExists, in.IdentityInRepo = false, false, true
	if p := Build(in); !contains(p.Blockers, "inside the repository") {
		t.Fatalf("blockers %v", p.Blockers)
	}
}

func TestSameFileAndInsideDir(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "repo", ".carbon", "private-key.age")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "identity")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if !sameFile(link, key) || sameFile(filepath.Join(dir, "nope"), key) {
		t.Error("sameFile")
	}
	cfg := filepath.Join(dir, "cfg")
	if err := os.Symlink(filepath.Join(dir, "repo"), cfg); err != nil {
		t.Fatal(err)
	}
	if !insideDir(filepath.Join(cfg, "carbon", "identity"), filepath.Join(dir, "repo")) {
		t.Error("a path through a symlink into the repo is not inside it")
	}
	if insideDir(filepath.Join(dir, "home", "identity"), filepath.Join(dir, "repo")) {
		t.Error("an outside path is inside")
	}
}

// Review 5: two pull/derive names on one [env] key block.
func TestPlanEnvKeyCollision(t *testing.T) {
	db := svc(t, "db/carbon.toml", "name = \"db\"\n[push.u]\nvalue = \"x\"\n")
	app := svc(t, "app/carbon.toml", "name = \"app\"\n[pull.db-url]\nservice = \"db\"\nname = \"u\"\n[derive.db_url]\nvalue = \"y\"\n")
	p := Build(baseInput([]*legacy.Service{app, db}, nil, reg("", legacy.User{Name: "alice", Key: keyA})))
	if !contains(p.Blockers, `would both become [env] key "db_url"`) {
		t.Fatalf("blockers = %v", p.Blockers)
	}
	// A derive overriding a pull of the same name is 0.0.3's own rule.
	app = svc(t, "app/carbon.toml", "name = \"app\"\n[pull.u]\nservice = \"db\"\n[derive.u]\nvalue = \"y\"\n")
	p = Build(baseInput([]*legacy.Service{app, db}, nil, reg("", legacy.User{Name: "alice", Key: keyA})))
	if len(p.Blockers) > 0 {
		t.Fatalf("blockers = %v", p.Blockers)
	}
}

// Review 6: a carbon.toml with 1.0 keys is never rewritten.
func TestNewFormatFileBlocks(t *testing.T) {
	root := t.TempDir()
	for f, c := range map[string]string{
		"a/carbon.toml": "name = \"a\"\n[push.x]\nvalue = \"1\"\n",
		"b/carbon.toml": "name = \"b\"\n[secrets]\nx = {}\n",
		"c/carbon.toml": "name = \"c\"\n[pull.x]\nservice = \"a\"\n[env]\nX = \"1\"\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := legacy.Load(root, []string{"a/carbon.toml", "b/carbon.toml", "c/carbon.toml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.Services) != 1 || len(repo.NewFormat) != 2 {
		t.Fatalf("services %d new-format %+v", len(repo.Services), repo.NewFormat)
	}
	in := baseInput(repo.Services, nil, reg("", legacy.User{Name: "alice", Key: keyA}))
	in.Repo.NewFormat = repo.NewFormat
	p := Build(in)
	if !contains(p.Blockers, "b/carbon.toml has Carbon 1.0 keys (secrets)") || !contains(p.Blockers, "c/carbon.toml has Carbon 1.0 keys (env)") {
		t.Fatalf("blockers = %v", p.Blockers)
	}
	for _, f := range p.Files {
		if f.Path == "b/carbon.toml" || f.Path == "c/carbon.toml" {
			t.Errorf("plan rewrites %s", f.Path)
		}
	}
}
