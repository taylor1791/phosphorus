package cli_test

// Regression tests for the review of run, export, edit and doctor.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// 1. ${env:CARBON_IDENTITY} must never hand the key to the command or a file.
func TestIdentityVariablesCannotBeReferenced(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	id, err := os.ReadFile(w.Lin.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CARBON_IDENTITY", "CARBON_IDENTITY_FILE"} {
		w.AddPackage(w.PkgDir, "checkout", checkoutWithEnv+"LEAK = \"${env:"+name+"}\"\n")
		with := []string{"FROM_SHELL=x", "CARBON_IDENTITY=" + string(id), "CARBON_IDENTITY_FILE=" + w.Lin.IdentityFile()}
		for _, args := range [][]string{{"run", "--", helper, "env"}, {"export"}, {"export", "--format", "json"}} {
			res := w.Lin.With(with...).In(w.PkgDir).Fails(1, args...)
			contains(t, "stderr", res.Stderr, name+" holds carbon's private key material", "LEAK = \"${env:"+name+"}\"")
			if strings.Contains(res.Stdout+res.Stderr, "AGE-SECRET-KEY") || res.Stdout != "" {
				t.Fatalf("identity released:\n%s", res)
			}
		}
	}
}

// 2. edit keeps concurrent changes, refuses when its own names moved, and
// never rewrites the keys file.
func TestEditKeepsConcurrentChanges(t *testing.T) {
	w := runWorld(t)
	bin := clitest.Binary(t)
	helper := childHelper(t)

	script := writeScript(t, "printf 'CONCURRENT-NEW' | "+bin+" set session_key >&2 || exit 9\nexec "+helper+" edit \"$@\"\n")
	res := w.Lin.With("EDITOR="+script, `HELPER_EDIT_SET={"stripe_api_key":"edited"}`).In(w.PkgDir).Must("edit")
	contains(t, "stdout", res.Stdout, "Sealed 1 changed secret(s) in checkout/dev: stripe_api_key.")
	if got := w.Lin.In(w.PkgDir).Must("get", "session_key").Stdout; got != "CONCURRENT-NEW" {
		t.Fatalf("lost update: session_key = %q", got)
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key").Stdout; got != "edited" {
		t.Fatalf("stripe_api_key = %q", got)
	}

	// The same name changed on disk meanwhile: refuse, keep theirs.
	script = writeScript(t, "printf 'THEIRS' | "+bin+" set stripe_api_key >&2 || exit 9\nexec "+helper+" edit \"$@\"\n")
	res = w.Lin.With("EDITOR="+script, `HELPER_EDIT_SET={"stripe_api_key":"mine"}`).In(w.PkgDir).Fails(1, "edit")
	contains(t, "stderr", res.Stderr, "nothing was saved: stripe_api_key changed on disk while the editor was open")
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key").Stdout; got != "THEIRS" {
		t.Fatalf("stripe_api_key = %q", got)
	}
}

func TestEditDoesNotUndoARotation(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	keys := w.PkgDir + "/.carbon/dev.keys.toml"
	secrets := w.PkgDir + "/.carbon/dev.secrets.toml"
	origKeys, origSecrets := w.Read(keys), w.Read(secrets)

	// Rotate checkout/dev away from sam, as `carbon apply` would after his
	// removal, and keep the rotated files.
	data, _ := os.ReadFile(w.Lin.IdentityFile())
	ids, err := agewrap.ParseIdentityFile(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(w.Path(w.PkgDir), "checkout", "dev")
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Open(ids, "lin/laptop")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadWorktree(w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var keep []policy.Device
	for _, d := range pol.AllDevices() {
		if d.ID == "ada/laptop" || d.ID == "lin/laptop" {
			keep = append(keep, d)
		}
	}
	if _, err := o.Rotate(keep, "removed sam", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(); err != nil {
		t.Fatal(err)
	}
	o.Close()
	rotKeys, rotSecrets := w.Read(keys), w.Read(secrets)
	if rotKeys == origKeys || !strings.Contains(origKeys, `"sam/laptop"`) || strings.Contains(rotKeys, `"sam/laptop"`) {
		t.Fatal("rotation did not happen")
	}
	w.Write(keys, origKeys)
	w.Write(secrets, origSecrets)
	stash := t.TempDir()
	os.WriteFile(filepath.Join(stash, "k"), []byte(rotKeys), 0o644)
	os.WriteFile(filepath.Join(stash, "s"), []byte(rotSecrets), 0o644)

	// The rotation lands while the editor is open.
	script := writeScript(t, "cp "+filepath.Join(stash, "k")+" "+w.Path(keys)+" && cp "+filepath.Join(stash, "s")+" "+w.Path(secrets)+" || exit 9\nexec "+helper+" edit \"$@\"\n")
	w.Lin.With("EDITOR="+script, `HELPER_EDIT_SET={"webhook_secret":"after-removal"}`).In(w.PkgDir).Must("edit")
	if w.Read(keys) != rotKeys {
		t.Fatal("edit rewrote the keys file")
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "webhook_secret").Stdout; got != "after-removal" {
		t.Fatalf("webhook_secret = %q", got)
	}
	res := w.Sam.In(w.PkgDir).Fails(3, "get", "webhook_secret")
	if strings.Contains(res.Stdout, "after-removal") {
		t.Fatal("sam reads a value set after his removal")
	}
}

const envOnlyPackage = `[env]
E = "${carbon.env}"
`

// 3. run stops reading its own flags at the command.
func TestRunPassesFlagsAfterTheCommand(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.AddPackage("services/envonly", "envonly", envOnlyPackage)
	p := w.Lin.In("services/envonly")

	res := p.Must("run", helper, "env", "0", "--env", "staging", "-C", "build", "--json")
	c := parseChild(t, res)
	if got := strings.Join(c.Args[1:], " "); got != "env 0 --env staging -C build --json" {
		t.Fatalf("args %q", got)
	}
	if envMap(c.Env)["E"] != "dev" {
		t.Fatalf("carbon read the command's --env: E = %q", envMap(c.Env)["E"])
	}
	res = p.Must("run", "--env", "staging", helper, "env", "--flag")
	c = parseChild(t, res)
	if envMap(c.Env)["E"] != "staging" || c.Args[len(c.Args)-1] != "--flag" {
		t.Fatalf("E = %q args %q", envMap(c.Env)["E"], c.Args)
	}
	res = p.Must("run", "--env", "prod", "--", helper, "env", "--", "-x")
	c = parseChild(t, res)
	if envMap(c.Env)["E"] != "prod" || strings.Join(c.Args[1:], " ") != "env -- -x" {
		t.Fatalf("E = %q args %q", envMap(c.Env)["E"], c.Args)
	}
}

// 5. -C applies to the command run starts.
func TestRunHonoursDashC(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.AddPackage("services/envonly", "envonly", envOnlyPackage)
	if err := os.Symlink(helper, w.Path("services/envonly/tool")); err != nil {
		t.Fatal(err)
	}
	res := w.Lin.Must("-C", "services/envonly", "run", "--", helper, "pwd")
	want, _ := filepath.EvalSymlinks(w.Path("services/envonly"))
	if got, _ := filepath.EvalSymlinks(strings.TrimSpace(res.Stdout)); got != want {
		t.Fatalf("command ran in %q, want %q", res.Stdout, want)
	}
	res = w.Lin.Must("-C", "services/envonly", "run", "./tool", "pwd")
	if got, _ := filepath.EvalSymlinks(strings.TrimSpace(res.Stdout)); got != want {
		t.Fatalf("./tool ran in %q", res.Stdout)
	}
	res = w.Lin.Fails(1, "-C", "services/envonly", "run", "./missing")
	contains(t, "stderr", res.Stderr, "command not found: ./missing", "Check the path")
	if strings.Contains(res.Stderr, "././") {
		t.Fatalf("hint repeats ./:\n%s", res)
	}
	// Found only through a relative PATH entry.
	res = w.Lin.With("PATH=.:"+os.Getenv("PATH")).Fails(1, "-C", "services/envonly", "run", "tool", "pwd")
	contains(t, "stderr", res.Stderr, `only in the relative PATH entry "."`, "./tool")
}

// 6. ^C in the editor is the editor's business; SIGTERM stops and cleans up.
func TestEditSignals(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	r, log := editRun(t, w, w.Lin, `HELPER_EDIT_SET={"stripe_api_key":"after-int"}`)
	script := writeScript(t, "kill -INT $PPID\nsleep 0.2\nexec "+helper+" edit \"$@\"\n")
	r.With("EDITOR=" + script).Must("edit")
	checkEditLog(t, log)
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key").Stdout; got != "after-int" {
		t.Fatalf("stripe_api_key = %q", got)
	}

	seen := filepath.Join(t.TempDir(), "seen")
	before := w.Read(w.PkgDir + "/.carbon/dev.secrets.toml")
	script = writeScript(t, "echo \"$1\" > "+seen+"\nkill -TERM $PPID\nexec sleep 10\n")
	start := time.Now()
	res := w.Lin.With("EDITOR="+script).In(w.PkgDir).Fails(1, "edit")
	if time.Since(start) > 8*time.Second {
		t.Fatal("carbon waited for the editor after SIGTERM")
	}
	contains(t, "stderr", res.Stderr, "stopped by terminated; nothing was saved")
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(strings.TrimSpace(string(b)))); !os.IsNotExist(err) {
		t.Fatalf("temporary directory left behind after SIGTERM: %v", err)
	}
	if w.Read(w.PkgDir+"/.carbon/dev.secrets.toml") != before {
		t.Fatal("SIGTERM edit changed the secrets file")
	}
}

// 7. JSON cannot hold non-UTF-8 values unchanged.
func TestExportJSONRefusesBinary(t *testing.T) {
	w := runWorld(t)
	w.Lin.In(w.PkgDir).Stdin("\xff\xfebin").Must("set", "webhook_secret")
	w.AddPackage(w.PkgDir, "checkout", checkoutWithEnv+"BIN = \"${webhook_secret}\"\n")
	res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(1, "export", "--format", "json")
	contains(t, "stderr", res.Stderr, "BIN is not UTF-8 text, so JSON cannot hold it unchanged")
	if res.Stdout != "" {
		t.Fatalf("partial output: %q", res.Stdout)
	}
}

// 8. XDG_RUNTIME_DIR and the editor that does not wait.
func TestEditTempDirAndQuickExitWarning(t *testing.T) {
	w := runWorld(t)
	rt := t.TempDir()
	r, log := editRun(t, w, w.Lin, "XDG_RUNTIME_DIR="+rt)
	res := r.Must("edit")
	checkEditLog(t, log)
	b, _ := os.ReadFile(log)
	if !strings.HasPrefix(string(b), rt+string(filepath.Separator)) {
		t.Fatalf("temp file %q not under XDG_RUNTIME_DIR %s", b, rt)
	}
	contains(t, "stderr", res.Stderr, "without changing the file", "--wait")
}

// 9. A value that cannot be revealed does not block the rest of the scope.
func TestEditSkipsUnreadableValues(t *testing.T) {
	w := runWorld(t)
	w.Lin.In(w.PkgDir).Stdin(stripeValue).Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")
	w.Ada.In(w.PkgDir).Stdin(dropValue).Must("set", "webhook_secret", "--env", "prod")
	// Damage the drop: its set time is authenticated inside the payload.
	f := w.PkgDir + "/.carbon/prod.secrets.toml"
	re := regexp.MustCompile(`(webhook_secret = \{ key = "[a-z0-9]+", set = )(\d{4})`)
	if !re.MatchString(w.Read(f)) {
		t.Fatalf("no drop line:\n%s", w.Read(f))
	}
	w.Write(f, re.ReplaceAllString(w.Read(f), "${1}2001"))
	damaged := regexp.MustCompile(`webhook_secret = .*`).FindString(w.Read(f))

	r, log := editRun(t, w, w.Lin, `HELPER_EDIT_SET={"stripe_api_key":"new-prod"}`)
	res := r.Must("edit", "--env", "prod")
	checkEditLog(t, log)
	contains(t, "stdout", res.Stdout, "Sealed 1 changed secret(s) in checkout/prod: stripe_api_key.")
	if got := regexp.MustCompile(`webhook_secret = .*`).FindString(w.Read(f)); got != damaged {
		t.Fatalf("damaged drop was touched:\n%s\n%s", damaged, got)
	}
	noLeak(t, res)
	// Uncommenting it is refused, not silently sealed.
	r, _ = editRun(t, w, w.Lin, "HELPER_EDIT_APPEND=webhook_secret = \"x\"\n")
	res = r.Fails(2, "edit", "--env", "prod")
	contains(t, "stderr", res.Stderr, "webhook_secret cannot be edited here")
}

// 10, 14. export -o: symlinks, -C, and no temporary files left anywhere.
func TestExportPaths(t *testing.T) {
	w := runWorld(t)
	w.Write(".gitignore", "*.env\n")
	gitDir := w.Git("rev-parse", "--absolute-git-dir")

	// An ignored symlink to a tracked file: the link is replaced, the
	// tracked file untouched.
	if err := os.Symlink("carbon.toml", w.Path("link.env")); err != nil {
		t.Fatal(err)
	}
	before := w.Read("carbon.toml")
	w.Lin.With("FROM_SHELL=x").Must("export", "--package", "checkout", "-o", "link.env")
	fi, err := os.Lstat(w.Path("link.env"))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("link.env: %v %v", fi.Mode(), err)
	}
	if w.Read("carbon.toml") != before {
		t.Fatal("export wrote through the symlink")
	}
	// A symlinked directory resolves before the ignore check.
	os.MkdirAll(w.Path("real"), 0o755)
	os.Symlink("real", w.Path("alias"))
	res := w.Lin.With("FROM_SHELL=x").Fails(2, "export", "--package", "checkout", "-o", "alias/secrets.txt")
	contains(t, "stderr", res.Stderr, "real/secrets.txt: git does not ignore it")

	// -C: relative to the -C directory.
	w.Lin.With("FROM_SHELL=x").Must("-C", w.PkgDir, "export", "-o", "x.env")
	if fi, err := os.Stat(w.Path(w.PkgDir + "/x.env")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("-C: %v", err)
	}

	// Nothing left behind in the work tree or the git directory.
	for _, dir := range []string{w.Dir, w.Path(w.PkgDir), gitDir} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.Contains(e.Name(), "carbon-export") {
				t.Fatalf("temporary file %s left in %s", e.Name(), dir)
			}
		}
	}
	if st := w.Git("status", "--porcelain"); strings.Contains(st, "carbon-export") {
		t.Fatalf("git sees a temporary file:\n%s", st)
	}
}

// 11. git processes per run do not grow with scopes or people.
func TestRunGitProcessCount(t *testing.T) {
	w := runWorld(t)
	for _, n := range []string{"kim", "raj", "eve", "joe"} {
		w.Person(n).Join()
	}
	w.Commit("more people")
	helper := childHelper(t)
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "log")
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\necho \"$*\" >> "+log+"\nexec "+real+" \"$@\"\n"), 0o755)
	path := "PATH=" + bin + ":" + os.Getenv("PATH")
	count := func() (int, string) {
		b, _ := os.ReadFile(log)
		os.Remove(log)
		return strings.Count(string(b), "\n"), string(b)
	}
	w.Lin.With("FROM_SHELL=x", path).In(w.PkgDir).Must("run", "--", helper, "exit")
	two, calls := count()
	w.AddPackage(w.PkgDir, "checkout", strings.Replace(strings.Replace(checkoutWithEnv,
		"DATABASE_URL", "#DATABASE_URL", 1), "DB_PASSWORD", "#DB_PASSWORD", 1))
	w.Lin.With("FROM_SHELL=x", path).In(w.PkgDir).Must("run", "--", helper, "exit")
	one, _ := count()
	t.Logf("git processes: %d for two scopes, %d for one\n%s", two, one, calls)
	if two != one {
		t.Errorf("git processes grow with scopes: %d for two, %d for one\n%s", two, one, calls)
	}
	if strings.Count(calls, "cat-file") > 1 {
		t.Errorf("more than one cat-file process:\n%s", calls)
	}
	if two > 8 {
		t.Errorf("%d git processes for one run:\n%s", two, calls)
	}
}

// 12. doctor: unknown package, identity inside the repo, real slot check.
func TestDoctorReviewFixes(t *testing.T) {
	w := runWorld(t)
	res := w.Lin.Fails(1, "doctor", "--package", "nope")
	contains(t, "doctor", res.Stdout, "FAIL  package", `no package named "nope"`)

	// The identity file inside the repository, named relatively, through a
	// symlinked directory, and with a name starting with "..".
	id, _ := os.ReadFile(w.Lin.IdentityFile())
	w.Write("..keys/identity", string(id))
	os.Chmod(w.Path("..keys/identity"), 0o600)
	os.Symlink(w.Path("..keys"), filepath.Join(t.TempDir(), "x"))
	link := filepath.Join(t.TempDir(), "keys")
	os.Symlink(w.Path("..keys"), link)
	for _, p := range []string{"..keys/identity", filepath.Join(link, "identity")} {
		res := w.Lin.With("CARBON_IDENTITY_FILE="+p).Fails(1, "doctor")
		contains(t, "doctor "+p, res.Stdout, "FAIL  identity", "is inside the repository")
	}

	// A key on this branch that does not descend from trunk's.
	w.Git("checkout", "-q", "-b", "rogue", "HEAD~1")
	w.Lin.With("CARBON_TRUNK=worktree").In(w.PkgDir).Stdin("ROGUE").Must("set", "stripe_api_key")
	res = w.Lin.In(w.PkgDir).Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  scope", "does not descend from trunk's")
}

// 14. Values are data; references inside them are not expanded.
func TestRunDoesNotReexpandValues(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.Lin.In(w.PkgDir).Stdin("${db.password}$${env:HOME}$$").Must("set", "session_key")
	res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Must("run", "--", helper, "env")
	if got := envMap(parseChild(t, res).Env)["SESSION_KEY"]; got != "${db.password}$${env:HOME}$$" {
		t.Fatalf("SESSION_KEY = %q", got)
	}
}

// 14. A referenced package's scope with a key not from trunk is refused.
func TestReferencedScopeNotFromTrunkIsRefused(t *testing.T) {
	w := runWorld(t)
	helper := childHelper(t)
	w.Git("checkout", "-q", "-b", "rogue", "HEAD~1")
	w.Lin.With("CARBON_TRUNK=worktree").In("services/db").Stdin("ROGUE-DB").Must("set", "password")
	w.Git("checkout", "-q", "main", "--", w.PkgDir+"/.carbon")
	for _, args := range [][]string{{"run", "--", helper, "env"}, {"export"}} {
		res := w.Lin.With("FROM_SHELL=x").In(w.PkgDir).Fails(1, args...)
		contains(t, "stderr", res.Stderr, "the key for db/dev on this branch does not descend from trunk's", "checkout needs it: DATABASE_URL")
		if strings.Contains(res.Stdout+res.Stderr, "ROGUE") {
			t.Fatalf("released:\n%s", res)
		}
	}
}
