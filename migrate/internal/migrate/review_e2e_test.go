package migrate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/migrate/internal/agekey"
)

// Fixture-backed regression tests from the review of carbon-migrate. Every
// repository here is made by the real 0.0.3 script.

// newBare is an empty git repository with the 0.0.3 script installed.
func newBare(t *testing.T) *fixture {
	t.Helper()
	requireTools(t, "git", "sops", "nu", "rage-keygen")
	tmp := t.TempDir()
	f := &fixture{t: t, tmp: tmp, root: filepath.Join(tmp, "repo"), keys: map[string]string{}}
	for _, d := range []string{f.root, filepath.Join(tmp, "home"), f.xdg(), filepath.Join(tmp, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(tmp, "home"), "XDG_CONFIG_HOME=" + f.xdg(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		"GIT_CONFIG_NOSYSTEM=1", "SOPS_DISABLE_VERSION_CHECK=1"}
	src, err := os.ReadFile(filepath.Join("testdata", "carbon-0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	nu, _ := exec.LookPath("nu")
	_, rest, _ := strings.Cut(string(src), "\n")
	f.old = filepath.Join(tmp, "bin", "carbon")
	if err := os.WriteFile(f.old, []byte("#!"+nu+"\n"+rest), 0o755); err != nil {
		t.Fatal(err)
	}
	f.carbon = carbonBinary(t)
	f.git("init", "-q", "-b", "main", ".")
	f.write(".gitignore", "*.txt\n.environment.json\n")
	return f
}

// finish commits, pushes to a bare origin and branches, as a cutover would.
func (f *fixture) finish() {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "-qm", "0.0.3")
	origin := filepath.Join(f.tmp, "origin.git")
	f.must(f.tmp, f.env, "git", "init", "-q", "--bare", origin)
	f.git("remote", "add", "origin", origin)
	f.git("push", "-q", "-u", "origin", "main")
	f.git("remote", "set-head", "origin", "main")
	f.git("checkout", "-q", "-b", "carbon-1.0")
}

func (f *fixture) recipient(user string) string {
	f.t.Helper()
	b, err := os.ReadFile(f.keys[user])
	if err != nil {
		f.t.Fatal(err)
	}
	r, err := agekey.Recipient(b)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// simpleRepo: alice and bob both read the default registry; svc pushes tok.
func simpleRepo(t *testing.T) *fixture {
	f := newBare(t)
	f.oldCarbon("alice", "init")
	f.saveKey("alice")
	f.oldCarbon("bob", "request")
	f.saveKey("bob")
	f.asUser("alice")
	f.oldCarbon("alice", "rekey")
	f.write("svc/s.txt", "secret\n")
	f.write("svc/carbon.toml", "name = \"svc\"\n[push.tok]\ncommand = \"cat s.txt\"\n")
	f.oldCarbon("alice", "push", "svc")
	return f
}

// runUndo runs the git and rm lines carbon-migrate printed.
func (f *fixture) runUndo(text string) int {
	f.t.Helper()
	ran := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "git checkout -- ") || strings.HasPrefix(line, "git clean -f -- ") || strings.HasPrefix(line, "rm ") {
			f.must(f.root, f.env, "sh", "-c", line)
			ran++
		}
	}
	return ran
}

// retryAfterUndo checks that a rolled-back migration, which left carbon's
// scope-key pins behind in the git dir, migrates again with no manual pin
// cleanup.
func (f *fixture) retryAfterUndo() {
	f.t.Helper()
	pins := filepath.Join(f.root, ".git", "carbon", "pins.toml")
	if _, err := os.Stat(pins); err != nil {
		f.t.Fatalf("expected the failed run to have left pins at %s: %v", pins, err)
	}
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitOK || !strings.Contains(out, "17 of 17 value(s) read back identical") {
		f.t.Fatalf("retry after undo: exit %d\n%s\n%s", code, out, errOut)
	}
}

// Review 1: same $USER, two keys; the desktop key never read prd and must
// not after migration.
func TestReviewPersonMergeGainsAccess(t *testing.T) {
	f := newBare(t)
	f.oldCarbon("alice", "init")
	f.oldCarbon("alice", "request", "prd")
	f.saveKey("laptop")
	f.oldCarbon("alice", "request")
	f.saveKey("desktop")
	f.asUser("laptop")
	f.oldCarbon("alice", "rekey")
	f.write("svc/s.txt", "secret\n")
	for _, reg := range []string{"", "prd"} {
		toml := "name = \"svc\"\n[push.tok]\ncommand = \"cat s.txt\"\n"
		if reg != "" {
			toml += "[registry]\ncurrent = { value = \"" + reg + "\" }\n"
		}
		f.write("svc/carbon.toml", toml)
		f.oldCarbon("alice", "push", "svc")
	}
	f.write("svc/carbon.toml", "name = \"svc\"\n[push.tok]\ncommand = \"cat s.txt\"\n")
	f.finish()
	f.asUser("desktop")
	if _, ok := f.oldValue("prd", "svc", "tok"); ok {
		t.Fatal("fixture: desktop could read prd in 0.0.3")
	}
	f.asUser("laptop")
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if _, _, err := f.get1(f.keys["desktop"], "svc", "prd", "tok"); err == nil {
		t.Error("ACCESS GAIN: the desktop key, never a prd recipient, reads prd after migration")
	}
	if got, _, err := f.get1(f.keys["desktop"], "svc", "dev", "tok"); err != nil || got != "secret" {
		t.Errorf("desktop lost dev: %v", err)
	}
	if !strings.Contains(out, "split: 2 keys are recorded as \"alice\"") || !f.exists(".carbon/people/alice-2.toml") {
		t.Errorf("the split is not listed or written:\n%s", out)
	}
}

// Review 2: an identity path that is the 0.0.3 key (directly or via a
// symlink) blocks before anything is written, and the key survives.
func TestReviewIdentityIsKeyPath(t *testing.T) {
	f := simpleRepo(t)
	f.finish()
	kp := filepath.Join(f.root, ".carbon", "private-key.age")
	code, out, _ := f.migrate([]string{"CARBON_IDENTITY_FILE=" + kp}, func(o *Options) { o.Write = true })
	if code != ExitBlocked || !strings.Contains(out, "only copy") {
		t.Fatalf("CARBON_IDENTITY_FILE = key: exit %d\n%s", code, out)
	}
	if !f.exists(".carbon/private-key.age") {
		t.Fatal("KEY LOST")
	}
	// The default identity path, symlinked to the key.
	if err := os.MkdirAll(filepath.Dir(f.identity()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kp, f.identity()); err != nil {
		t.Fatal(err)
	}
	code, out, _ = f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitBlocked || !strings.Contains(out, "only copy") {
		t.Fatalf("symlinked identity: exit %d\n%s", code, out)
	}
	if !f.exists(".carbon/private-key.age") {
		t.Fatal("KEY LOST through the symlink")
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("a blocked run changed the tree:\n%s", st)
	}
}

// Review 3: bob removed from the creation rule but not rekeyed is a pending
// removal, not a reader; --keep-recipient carries him over.
func TestReviewPendingRemoval(t *testing.T) {
	for _, keep := range []bool{false, true} {
		f := simpleRepo(t)
		bob := f.recipient("bob")
		var kept []string
		for _, l := range strings.Split(f.read(".carbon/sops.yaml"), "\n") {
			if strings.Contains(l, bob) || strings.Contains(l, "name: bob") {
				continue
			}
			kept = append(kept, strings.TrimSuffix(l, ","))
		}
		f.write(".carbon/sops.yaml", strings.Join(kept, "\n"))
		f.finish()
		code, out, errOut := f.migrate(nil, func(o *Options) {
			o.Write = true
			if keep {
				o.KeepRecipients = []string{bob}
			}
		})
		if code != ExitOK {
			t.Fatalf("keep=%v: exit %d\n%s\n%s", keep, code, out, errOut)
		}
		_, _, err := f.get1(f.keys["bob"], "svc", "dev", "tok")
		switch {
		case !keep && err == nil:
			t.Error("a pending removal became a reader")
		case !keep && !strings.Contains(out, "pending removal: key"):
			t.Errorf("pending removal not listed:\n%s", out)
		case keep && err != nil:
			t.Errorf("--keep-recipient: bob cannot read: %v", err)
		}
	}
}

// Review 7: a failure during verification leaves the old files and prints
// undo commands, including removing the installed identity.
func TestReviewVerifyFailureUndo(t *testing.T) {
	f := newFixture(t)
	wrapper := filepath.Join(f.tmp, "bin", "carbon-badget")
	script := "#!/bin/sh\nif [ \"$1\" = get ]; then printf wrong; exit 0; fi\nexec " + f.carbon + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true; o.Carbon = wrapper })
	if code != ExitFailed || !strings.Contains(errOut, "verification failed") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !f.exists(".carbon/registry.yaml") || !f.exists(".carbon/private-key.age") {
		t.Fatal("old files deleted after a failed verification")
	}
	if _, err := os.Stat(f.identity()); err != nil {
		t.Fatal("expected the identity to have been installed before verification")
	}
	if !strings.Contains(errOut, "rm "+f.identity()) {
		t.Fatalf("undo lacks the identity:\n%s", errOut)
	}
	if n := f.runUndo(errOut); n != 3 {
		t.Fatalf("ran %d undo lines:\n%s", n, errOut)
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("undo left:\n%s", st)
	}
	if _, err := os.Stat(f.identity()); err == nil {
		t.Fatal("identity still installed after undo")
	}
	f.retryAfterUndo()
}

// Review 7: a failure while deleting the old files is recoverable too.
func TestReviewDeleteFailureUndo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("SKIPPED: root ignores directory permissions")
	}
	f := newFixture(t)
	carbonDir := filepath.Join(f.root, ".carbon")
	wrapper := filepath.Join(f.tmp, "bin", "carbon-lockdir")
	// After each successful get, make .carbon read-only so deletion fails.
	script := "#!/bin/sh\n" + f.carbon + " \"$@\"; rc=$?\nif [ \"$1\" = get ]; then chmod 0555 " + carbonDir + "; fi\nexit $rc\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(carbonDir, 0o755)
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true; o.Carbon = wrapper })
	if code != ExitFailed || !strings.Contains(errOut, "deleting .carbon/") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if err := os.Chmod(carbonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !f.exists(".carbon/private-key.age") {
		t.Fatal("the key was removed although deletion failed")
	}
	if n := f.runUndo(errOut); n != 3 {
		t.Fatalf("ran %d undo lines:\n%s", n, errOut)
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("undo left:\n%s", st)
	}
	if _, err := os.Stat(f.identity()); err == nil {
		t.Fatal("identity still installed after undo")
	}
	f.retryAfterUndo()
}

// Review 7: --env-name and --package-name.
func TestReviewRenames(t *testing.T) {
	f := newFixture(t)
	want, _ := f.oldValue("prd", "db", "password")
	code, out, errOut := f.migrate(nil, func(o *Options) {
		o.Write = true
		o.EnvNames = map[string]string{"prd": "prod"}
		o.PackageNames = map[string]string{"db": "database"}
	})
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if got, stderr, err := f.get1("", "database", "prod", "password"); err != nil || got != want {
		t.Fatalf("database/prod password: %v %s", err, stderr)
	}
	api := f.read("services/api/carbon.toml")
	if !strings.Contains(api, `db_password = "${database.password}"`) {
		t.Errorf("api does not reference the renamed package:\n%s", api)
	}
	if !strings.Contains(f.read("carbon.toml"), `environments = ["dev", "prod", "stg"]`) {
		t.Errorf("workspace:\n%s", f.read("carbon.toml"))
	}
	if !strings.Contains(f.read("services/db/carbon.toml"), "prod = \"db.prod.internal\"") {
		t.Errorf("db vars do not use the new environment name")
	}
}

// Review 7: --key from outside the repository is copied, never removed.
func TestReviewKeyFlag(t *testing.T) {
	f := newFixture(t)
	elsewhere := filepath.Join(f.tmp, "elsewhere.age")
	if err := os.Rename(filepath.Join(f.root, ".carbon", "private-key.age"), elsewhere); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true; o.Key = elsewhere })
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	a, _ := os.ReadFile(elsewhere)
	b, err := os.ReadFile(f.identity())
	if err != nil || len(a) == 0 || string(a) != string(b) {
		t.Fatalf("--key was not installed unchanged (or was removed): %v", err)
	}
	if !strings.Contains(out, "17 of 17 value(s) read back identical") {
		t.Errorf("--key run did not verify:\n%s", out)
	}
}

// Review 7: a real sops decrypt failure (bob cannot read prd or stg) blocks.
func TestReviewSopsDecryptFailure(t *testing.T) {
	f := newFixture(t)
	f.asUser("bob")
	code, out, errOut := f.migrate(nil, nil)
	if code != ExitBlocked || !strings.Contains(out, "cannot decrypt .carbon/registry.prd.yaml") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}

// Values with awkward bytes survive 0.0.3 -> sops -> carbon set -> get.
func TestReviewEdgeValues(t *testing.T) {
	f := newBare(t)
	f.oldCarbon("alice", "init")
	vals := map[string]string{
		"nl2": "a\n\n", "nlonly": "\n", "cr": "x\r", "crlf2": "x\r\n\r\n", "spaces": "  pad  ",
		"flag": "--allow-empty", "tomlv": "k = \"v\"\n[t]\n", "emoji": "héllo 😀 ​", "tab": "\ta\tb",
		"ctrl": "a\u0001b\u007f", "long": strings.Repeat("0123456789abcdef", 6000), "yamlish": "yes",
		"num": "0123", "json": "{\"a\":1}",
	}
	toml := "name = \"svc\"\n"
	for k, v := range vals {
		toml += "[[push." + k + "]]\nvalue = " + quote(v) + "\n[[push." + k + "]]\nregistry_pattern = \"^never$\"\ncommand = \"false\"\n"
	}
	f.write("svc/carbon.toml", toml)
	f.oldCarbon("alice", "push", "svc")
	f.finish()
	old := map[string]string{}
	for k := range vals {
		o, ok := f.oldValue("", "svc", k)
		if !ok {
			t.Fatalf("0.0.3 has no %s", k)
		}
		old[k] = o
	}
	code, out, errOut := f.migrate(nil, func(o *Options) { o.Write = true })
	if code != ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for k := range vals {
		if got, stderr, err := f.get1("", "svc", "dev", k); err != nil || got != old[k] {
			t.Errorf("%s: got %q err %v %s, want %q", k, got, err, stderr, old[k])
		}
	}
}
