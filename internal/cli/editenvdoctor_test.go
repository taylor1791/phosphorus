package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

func secretsLine(t *testing.T, w *clitest.World, env, name string) string {
	t.Helper()
	b := secretBlock(w.Read(w.PkgDir+"/.carbon/"+env+".secrets.toml"), name)
	if b == "" {
		t.Fatalf("no [%s] in %s", name, env)
	}
	return b
}

// editRun runs `carbon edit` as p with the helper as EDITOR, logging what
// the editor saw to a file it returns.
func editRun(t *testing.T, w *clitest.World, p *clitest.Person, env ...string) (*clitest.Run, string) {
	log := filepath.Join(t.TempDir(), "edit.log")
	all := append([]string{"EDITOR=" + childHelper(t) + " edit", "HELPER_EDIT_LOG=" + log}, env...)
	return p.With(all...).In(w.PkgDir), log
}

func checkEditLog(t *testing.T, log string) {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the editor did not run: %v", err)
	}
	f := strings.Fields(string(b))
	if len(f) != 4 || f[1] != "0600" || f[2] != "0700" {
		t.Fatalf("editor saw %q, want file 0600 in a 0700 directory", b)
	}
	if f[3] != "identity-vars=false" {
		t.Fatalf("the editor received CARBON_IDENTITY or CARBON_IDENTITY_FILE: %q", b)
	}
	if _, err := os.Stat(filepath.Dir(f[0])); !os.IsNotExist(err) {
		t.Fatalf("temporary directory %s still exists (%v)", filepath.Dir(f[0]), err)
	}
}

func TestEditChangesOnlyEditedValues(t *testing.T) {
	w := runWorld(t)
	// Make the set times differ from "now" by a second at least.
	beforeSession := secretsLine(t, w, "dev", "session_key")
	beforeStripe := secretsLine(t, w, "dev", "stripe_api_key")

	set, _ := json.Marshal(map[string]string{"stripe_api_key": "new \"stripe\"\nvalue", "webhook_secret": "whsec_NEW"})
	r, log := editRun(t, w, w.Lin, "HELPER_EDIT_SET="+string(set))
	res := r.Must("edit")
	checkEditLog(t, log)
	contains(t, "stdout", res.Stdout, "Sealed 2 changed secret(s) in checkout/dev: stripe_api_key, webhook_secret.",
		"Commit services/checkout/.carbon/dev.secrets.toml")
	if strings.Contains(res.Stdout+res.Stderr, sessionValue) || strings.Contains(res.Stdout+res.Stderr, stripeValue) {
		t.Fatalf("edit printed a value:\n%s", res)
	}
	if got := secretsLine(t, w, "dev", "session_key"); got != beforeSession {
		t.Fatalf("unchanged session_key was re-sealed:\n%s\n%s", beforeSession, got)
	}
	if secretsLine(t, w, "dev", "stripe_api_key") == beforeStripe {
		t.Fatal("stripe_api_key was not re-sealed")
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "stripe_api_key").Stdout; got != "new \"stripe\"\nvalue" {
		t.Fatalf("stripe_api_key = %q", got)
	}
	if got := w.Lin.In(w.PkgDir).Must("get", "webhook_secret").Stdout; got != "whsec_NEW" {
		t.Fatalf("webhook_secret = %q", got)
	}

	// Saving without changes changes nothing.
	r, log = editRun(t, w, w.Lin)
	before := w.Read(w.PkgDir + "/.carbon/dev.secrets.toml")
	res = r.Must("edit", "--json")
	checkEditLog(t, log)
	var jr struct {
		Changed []string `json:"changed"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &jr); err != nil || len(jr.Changed) != 0 {
		t.Fatalf("json: %v %s", err, res.Stdout)
	}
	if w.Read(w.PkgDir+"/.carbon/dev.secrets.toml") != before {
		t.Fatal("a no-op edit rewrote the file")
	}
}

func TestEditRejectsAndCleansUp(t *testing.T) {
	w := runWorld(t)
	before := w.Read(w.PkgDir + "/.carbon/dev.secrets.toml")

	// An undeclared name: nothing saved, temp removed.
	r, log := editRun(t, w, w.Lin, "HELPER_EDIT_APPEND=undeclared_thing = \"x\"\n",
		`HELPER_EDIT_SET={"stripe_api_key":"changed"}`)
	res := r.Fails(2, "edit")
	checkEditLog(t, log)
	contains(t, "stderr", res.Stderr, "nothing was saved", "services/checkout/carbon.toml does not declare undeclared_thing.")
	noLeak(t, res)

	// A var name.
	r, log = editRun(t, w, w.Lin, "HELPER_EDIT_APPEND=public_url = \"x\"\n")
	res = r.Fails(2, "edit")
	checkEditLog(t, log)
	contains(t, "stderr", res.Stderr, "public_url is a var")

	// Invalid TOML: the message gives a position, not the line's content.
	r, log = editRun(t, w, w.Lin, "HELPER_EDIT_APPEND=oops "+stripeValue+"\n")
	res = r.Fails(2, "edit")
	checkEditLog(t, log)
	contains(t, "stderr", res.Stderr, "is not valid TOML")
	noLeak(t, res)
	if strings.Contains(res.Stderr, stripeValue) {
		t.Fatal("leaked")
	}

	// Emptying a value is refused.
	r, log = editRun(t, w, w.Lin, `HELPER_EDIT_SET={"session_key":""}`)
	res = r.Fails(2, "edit")
	checkEditLog(t, log)
	contains(t, "stderr", res.Stderr, "session_key is empty")

	// The editor fails: nothing saved, temp removed.
	r, log = editRun(t, w, w.Lin, `HELPER_EDIT_SET={"session_key":"zzz"}`, "HELPER_EDIT_EXIT=3")
	res = r.Fails(1, "edit")
	checkEditLog(t, log)
	contains(t, "stderr", res.Stderr, "the editor exited with status 3; nothing was saved")

	if w.Read(w.PkgDir+"/.carbon/dev.secrets.toml") != before {
		t.Fatal("a failed edit changed the secrets file")
	}

	// No editor at all.
	res = w.Lin.With("EDITOR=", "VISUAL=").In(w.PkgDir).Fails(2, "edit")
	contains(t, "stderr", res.Stderr, "no editor: VISUAL and EDITOR are both unset", "export EDITOR=")
	// VISUAL wins over EDITOR.
	r, log = editRun(t, w, w.Lin)
	r.With("VISUAL="+childHelper(t)+" edit", "EDITOR=/nonexistent/editor").Must("edit")
	checkEditLog(t, log)
	// An editor that is not there.
	res = w.Lin.With("EDITOR=/nonexistent/editor").In(w.PkgDir).Fails(1, "edit")
	contains(t, "stderr", res.Stderr, "cannot start the editor")

	// A non-reader cannot edit.
	w.Lin.In(w.PkgDir).Stdin(stripeValue).Must("set", "stripe_api_key", "--env", "prod")
	r, _ = editRun(t, w, w.Ada)
	res = r.Fails(3, "edit", "--env", "prod")
	contains(t, "stderr", res.Stderr, "you cannot read checkout in prod", "carbon request checkout --env prod")
	noLeak(t, res)
}

func TestEnvAndEnvUse(t *testing.T) {
	r := clitest.NewWorkspace(t)
	any := r.Anyone()
	res := any.Must("env")
	contains(t, "env", res.Stdout, "Environment: dev (the workspace's default_environment)", "Available:   dev, staging, prod")

	res = any.Must("env", "use", "prod")
	contains(t, "env use", res.Stdout, "This worktree now uses prod")
	gitDir := r.Git("rev-parse", "--absolute-git-dir")
	if b, _ := os.ReadFile(filepath.Join(gitDir, "carbon-env")); string(b) != "prod\n" {
		t.Fatalf("carbon-env = %q", b)
	}
	if strings.Contains(r.Git("status", "--porcelain"), "carbon-env") {
		t.Fatal("carbon-env is visible to git")
	}
	res = any.Must("env")
	contains(t, "env", res.Stdout, "Environment: prod (from `carbon env use`, stored in "+filepath.Join(gitDir, "carbon-env"))

	res = any.With("CARBON_ENV=staging").Must("env")
	contains(t, "env", res.Stdout, "Environment: staging (from the CARBON_ENV variable)", "`carbon env use` stored prod for this worktree; it is overridden.")
	res = any.Must("env", "--env", "dev", "--json")
	var je struct {
		Environment, Source, Stored string
	}
	if err := json.Unmarshal([]byte(res.Stdout), &je); err != nil || je.Environment != "dev" || je.Source != "flag" || je.Stored != "prod" {
		t.Fatalf("json %v %s", err, res.Stdout)
	}
	res = any.With("CARBON_ENV=staging").Must("env", "use", "dev")
	contains(t, "stderr", res.Stderr, "CARBON_ENV=staging is set in your shell and overrides this")

	res = any.Fails(2, "env", "use", "nope")
	contains(t, "stderr", res.Stderr, `unknown environment "nope"`, "dev, staging, prod")
	any.Fails(2, "env", "use")
	any.Fails(2, "env", "use", "dev", "--clear")
	res = any.With("CARBON_ENV=bogus").Fails(2, "env")
	contains(t, "stderr", res.Stderr, `unknown environment "bogus" (from the CARBON_ENV variable)`)

	res = any.Must("env", "use", "--clear")
	contains(t, "stdout", res.Stdout, "Cleared. This worktree uses the default environment, dev.")
	contains(t, "env", any.Must("env").Stdout, "Environment: dev (the workspace's default_environment)")
	any.Must("env", "use", "--clear") // idempotent
}

func TestEnvUseIsPerWorktreeAndDrivesCommands(t *testing.T) {
	w := runWorld(t)
	w.Lin.Must("env", "use", "prod")
	res := w.Lin.In(w.PkgDir).Must("ls", "--json")
	contains(t, "ls", res.Stdout, `"scope": "checkout/prod"`)

	wt := filepath.Join(t.TempDir(), "other")
	w.Git("worktree", "add", "-q", wt, "-b", "other")
	if b, err := os.ReadFile(filepath.Join(w.Git("-C", wt, "rev-parse", "--absolute-git-dir"), "carbon-env")); err == nil {
		t.Fatalf("the other worktree inherited carbon-env %q", b)
	}
}

type doctorJSON struct {
	OK     bool `json:"ok"`
	Checks []struct {
		Name, Status, Message, Fix string
	} `json:"checks"`
}

func doctorChecks(t *testing.T, res *clitest.Result) doctorJSON {
	t.Helper()
	var d doctorJSON
	if err := json.Unmarshal([]byte(res.Stdout), &d); err != nil {
		t.Fatalf("doctor json: %v\n%s", err, res)
	}
	return d
}

func TestDoctor(t *testing.T) {
	w := runWorld(t)
	res := w.Lin.In(w.PkgDir).Must("doctor")
	contains(t, "doctor", res.Stdout,
		"ok    git", "ok    workspace", "carbon.toml format 1, environments dev, staging, prod",
		"ok    trunk", "refs/heads/main at ", "holds 1 key(s)", "hybrid post-quantum",
		"you are lin (device laptop), a member of @engineering and @payments",
		"ok    environment", "dev (the default)",
		"checkout/dev: your key opens it (slot lin/laptop) and it matches trunk",
		"No problems")

	w.Lin.In(w.PkgDir).Stdin(stripeValue).Must("set", "stripe_api_key", "--env", "prod")
	// Ada in prod: not a reader, a hint, not a failure.
	res = w.Ada.In(w.PkgDir).Must("doctor", "--env", "prod")
	contains(t, "doctor", res.Stdout, "checkout/prod: you are not a reader", "carbon request checkout --env prod")

	d := doctorChecks(t, w.Lin.In(w.PkgDir).Must("doctor", "--json"))
	if !d.OK || len(d.Checks) < 6 {
		t.Fatalf("doctor json %+v", d)
	}

	// A loose identity file is broken, with the fix.
	if err := os.Chmod(w.Sam.IdentityFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	res = w.Sam.In(w.PkgDir).Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  identity", "has mode 0644", "fix: Restrict it:   chmod 600 "+w.Sam.IdentityFile())
	d = doctorChecks(t, w.Sam.In(w.PkgDir).Fails(1, "doctor", "--json"))
	if d.OK {
		t.Fatal("ok with a loose identity")
	}

	// No identity.
	res = w.Anyone().In(w.PkgDir).Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  identity", "fix: Create one:   carbon join")

	// An identity nobody knows.
	stranger := w.Person("stranger")
	stranger.Join()
	w.Git("checkout", "-q", "--", ".carbon")
	w.Git("clean", "-fdq", ".carbon")
	res = stranger.In(w.PkgDir).Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  who", "your key is not in .carbon/people or .carbon/machines", "carbon join")

	// A machine identity from CARBON_IDENTITY.
	res = w.Deploy.In(w.PkgDir).Must("doctor", "--env", "prod")
	contains(t, "doctor", res.Stdout, "from the CARBON_IDENTITY variable", "you are machine:deploy-checkout")

	// A bad environment.
	res = w.Lin.With("CARBON_ENV=bogus").In(w.PkgDir).Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, `FAIL  environment`, `"bogus" (from CARBON_ENV)`, "unset CARBON_ENV")

	// A person on the branch but not on trunk.
	w.Branch("newbie")
	nb := w.Person("newbie")
	nb.Join()
	res = nb.In(w.PkgDir).Must("doctor")
	contains(t, "doctor", res.Stdout, "WARN  who", "newbie/laptop is not on trunk refs/heads/main")
}

func TestDoctorBootstrapAndOutsideAWorkspace(t *testing.T) {
	r := clitest.NewRepo(t)
	res := r.Anyone().Fails(1, "doctor")
	contains(t, "doctor", res.Stdout, "FAIL  workspace", "this repository has no carbon workspace", "fix: To start one:   carbon init")

	r = clitest.NewWorkspace(t)
	ada := r.Person("ada")
	ada.Join()
	res = ada.Must("doctor")
	contains(t, "doctor", res.Stdout, "WARN  trunk", "no trunk yet (no remote, no git config carbon.trunk): bootstrap mode", "you are ada")
}
