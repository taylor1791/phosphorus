package cli_test

// End-to-end journeys: each test is one realistic story driven only
// through the carbon command line, as different people, with `carbon check`
// run keyless (as CI would) wherever a pull request would be open or trunk
// would have moved.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/scope"
)

type jCheck struct {
	OK       bool
	Trunk    struct{ Ref, From, Mode string }
	Counts   struct{ Errors, Warnings, Info, Drops, Review int }
	Findings []struct {
		Severity, Rule, Scope, Secret, Device, Message, Banner string
		Strict                                                 bool
	}
	res *clitest.Result
}

// ci runs `carbon check --json` with no identity, as CI does, expects the
// exit code, and returns the parsed report.
func ci(t *testing.T, r *clitest.Repo, code int, args ...string) jCheck {
	t.Helper()
	res := r.Anyone().Fails(code, append([]string{"check", "--json"}, args...)...)
	var cj jCheck
	if err := json.Unmarshal([]byte(res.Stdout), &cj); err != nil {
		t.Fatalf("check --json: %v\n%s", err, res)
	}
	cj.res = res
	return cj
}

// rules returns the findings of a rule, as "severity scope secret device".
func (c jCheck) rules(rule string) []string {
	var out []string
	for _, f := range c.Findings {
		if f.Rule == rule {
			out = append(out, strings.Join(strings.Fields(f.Severity+" "+f.Scope+" "+f.Secret+" "+f.Device), " "))
		}
	}
	return out
}

func (c jCheck) has(t *testing.T, rule string, want ...string) {
	t.Helper()
	got := c.rules(rule)
	if len(got) == 0 {
		t.Fatalf("check has no %s finding\n%s", rule, c)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if strings.Contains(g, w) {
				found = true
			}
		}
		if !found {
			t.Fatalf("check %s findings %q lack %q\n%s", rule, got, w, c)
		}
	}
}

func (c jCheck) lacks(t *testing.T, rules ...string) {
	t.Helper()
	for _, rule := range rules {
		if got := c.rules(rule); len(got) > 0 {
			t.Fatalf("check has unexpected %s findings %q\n%s", rule, got, c)
		}
	}
}

// banner returns the rules of the findings check lists in its review banner.
func (c jCheck) banner() []string {
	var out []string
	for _, f := range c.Findings {
		if f.Banner != "" {
			out = append(out, f.Rule)
		}
	}
	return out
}

// clean asserts a check with no errors, no warnings and nothing to review.
func (c jCheck) clean(t *testing.T) {
	t.Helper()
	if !c.OK || c.Counts.Errors+c.Counts.Warnings+c.Counts.Review > 0 {
		t.Fatalf("check is not clean\n%s", c)
	}
}

func mustContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Fatalf("%s lacks %q:\n%s", what, sub, s)
		}
	}
}

func mustNotContain(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Fatalf("%s contains %q:\n%s", what, sub, s)
		}
	}
}

// Journey a: one developer adopts carbon in an empty repository.
func TestJourneyAdoption(t *testing.T) {
	r := clitest.NewRepo(t)
	ada := r.Person("ada")

	res := ada.Must("init")
	mustContain(t, "init", res.Stdout, "carbon.toml", "Next: carbon join")

	res = ada.Join()
	mustContain(t, "join", res.Stdout, "Joined team", "@engineering", "Fingerprint")
	mustNotContain(t, "join (bootstrap, already in a team)", res.Stdout, "ask to be added to a team")

	r.Write("services/api/main.go", "package main\n")
	res = ada.In("services/api").Must("init")
	mustContain(t, "init package", res.Stdout, "services/api/carbon.toml")
	r.Write("services/api/carbon.toml", `name = "api"

[secrets]
db_password = { description = "database password" }
token       = { description = "API token", generate = "random:16" }

[env]
DATABASE_URL = "postgres://api:${db_password}@localhost/api"
API_TOKEN    = "${token}"
`)

	// No trunk yet: check refuses without --bootstrap, and with it reports
	// what is missing.
	res = r.Anyone().Fails(1, "check")
	mustContain(t, "check without trunk", res.Stderr, "--bootstrap")
	cj := ci(t, r, 4, "--bootstrap")
	cj.has(t, "secret.unset", "api/dev db_password", "api/prod token")

	api := ada.In("services/api")
	res = api.Stdin("hunter2\n").Must("set", "db_password")
	mustContain(t, "set", res.Stdout, "Created the key for api/dev", "Sealed.")
	mustNotContain(t, "set output", res.Stdout+res.Stderr, "hunter2")
	api.Must("set", "token", "--generate")

	res = ada.In("services/api").Must("run", "--", "printenv", "DATABASE_URL")
	if res.Stdout != "postgres://api:hunter2@localhost/api\n" {
		t.Fatalf("run gave %q", res.Stdout)
	}
	res = api.Must("export", "--format", "json")
	var exp map[string]string
	if err := json.Unmarshal([]byte(res.Stdout), &exp); err != nil || exp["DATABASE_URL"] == "" || len(exp["API_TOKEN"]) != 22 {
		t.Fatalf("export: %v %v\n%s", err, exp, res)
	}

	// Still unset in staging and prod.
	cj = ci(t, r, 4, "--bootstrap")
	cj.has(t, "secret.unset", "api/staging", "api/prod")
	cj.lacks(t, "secret.unset dev")
	for _, env := range []string{"staging", "prod"} {
		api.Stdin("pw-"+env).Must("set", "db_password", "--env", env)
		api.Must("set", "token", "--generate", "--env", env)
	}
	cj = ci(t, r, 0, "--bootstrap")
	if cj.Trunk.Mode != "bootstrap" {
		t.Fatalf("trunk mode %q\n%s", cj.Trunk.Mode, cj)
	}
	cj.lacks(t, "secret.unset")

	// Commit to trunk and name it for this clone.
	r.Commit("adopt carbon")
	res = ada.Must("init", "--trunk", "main")
	mustContain(t, "init --trunk", res.Stdout, "git config carbon.trunk main")
	cj = ci(t, r, 0)
	if cj.Trunk.Mode != "trunk" || cj.Trunk.Ref != "refs/heads/main" {
		t.Fatalf("trunk %+v\n%s", cj.Trunk, cj)
	}
	cj.clean(t)

	// The reader still reads on trunk, now verified against trunk and pinned.
	if got := api.Must("get", "db_password", "--env", "prod").Stdout; got != "pw-prod" {
		t.Fatalf("get after adoption = %q", got)
	}
	res = ada.Must("status")
	mustContain(t, "status", res.Stdout, "You are ada", "Readable", "3 scopes")
}

// journeyWorld is a workspace adopted by ada alone (bootstrap: she joins
// @engineering, which reads every environment), with package checkout in
// services/checkout holding a value for every declared secret in every
// environment, committed to main, with main as this clone's trunk.
func journeyWorld(t *testing.T) (*clitest.Repo, *clitest.Person, string) {
	t.Helper()
	r := clitest.NewWorkspace(t)
	ada := r.Person("ada")
	ada.Join()
	co := "services/checkout"
	r.AddPackage(co, "checkout", `[secrets]
session_key = { description = "HMAC key", generate = "random:32" }
api_key     = { description = "payment API key" }

[env]
SESSION_KEY = "${session_key}"
API_KEY     = "${api_key}"
`)
	for _, env := range []string{"dev", "staging", "prod"} {
		ada.In(co).Must("set", "session_key", "--generate", "--env", env)
		ada.In(co).Stdin("ak-"+env).Must("set", "api_key", "--env", env)
	}
	r.Commit("adopt carbon")
	r.SetTrunk("main")
	ci(t, r, 0).clean(t)
	return r, ada, co
}

// Journey b: a new person is onboarded through two pull requests.
func TestJourneyOnboarding(t *testing.T) {
	r, ada, co := journeyWorld(t)
	lin := r.Person("lin")

	// lin joins and requests prod on a branch.
	r.Branch("lin-joins")
	res := lin.Join()
	mustContain(t, "join", res.Stdout, "Fingerprint", "pull request")
	res = lin.In(co).Must("request", "checkout", "--env", "prod", "--yes")
	mustContain(t, "request", res.Stdout, "lin", "carbon apply")
	r.Commit("lin joins, requests checkout/prod")
	lin.In(co).Fails(3, "get", "api_key", "--env", "prod")

	cj := ci(t, r, 0)
	cj.has(t, "policy.grant-proposed", "checkout/prod lin/laptop")
	cj.lacks(t, "key.new", "key.rotated", "slot.granted")
	if len(cj.banner()) != 0 {
		t.Fatalf("request branch has a key banner: %v\n%s", cj.banner(), cj)
	}
	r.Anyone().Must("check") // human output too

	// Merge. Trunk now names lin; the grant is pending.
	r.Checkout("main")
	r.Merge("lin-joins")
	cj = ci(t, r, 0)
	cj.has(t, "slot.pending-grant", "checkout/prod lin/laptop")
	ci(t, r, 4, "--strict")
	res = lin.Must("status")
	mustContain(t, "lin status", res.Stdout, "checkout/prod", "waiting for a reader")
	res = ada.Must("status")
	mustContain(t, "ada status", res.Stdout, "lin/laptop", "carbon apply")

	// ada applies on a branch off trunk.
	r.Branch("apply-lin")
	res = ada.Must("apply", "--yes")
	mustContain(t, "apply", res.Stdout, "lin/laptop", "checkout/prod")
	cj = ci(t, r, 0)
	cj.has(t, "slot.granted", "checkout/prod lin/laptop")
	cj.lacks(t, "slot.pending-grant")
	r.Anyone().Must("check")

	r.Checkout("main")
	r.Merge("apply-lin")
	if got := lin.In(co).Must("get", "api_key", "--env", "prod").Stdout; got != "ak-prod" {
		t.Fatalf("lin get = %q", got)
	}
	res = lin.In(co).Must("run", "--env", "prod", "--", "printenv", "API_KEY")
	if res.Stdout != "ak-prod\n" {
		t.Fatalf("lin run = %q", res.Stdout)
	}
	// lin still cannot read dev: never requested.
	lin.In(co).Fails(3, "get", "api_key", "--env", "dev")
	ci(t, r, 0).clean(t)
}

// String is the run and its findings, without the rule list.
func (c jCheck) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "$ carbon %s (exit %d) ok=%v trunk=%+v counts=%+v\n", strings.Join(c.res.Args, " "), c.res.Code, c.OK, c.Trunk, c.Counts)
	for _, f := range c.Findings {
		fmt.Fprintf(&b, "  %s[%s] %s %s %s: %s\n", f.Severity, f.Rule, f.Scope, f.Secret, f.Device, f.Message)
	}
	b.WriteString(c.res.Stderr)
	return b.String()
}

// Journey c: sam leaves. His removal is reviewed, a reader rotates, and
// what sam could have copied is listed until it is changed.
func TestJourneyOffboarding(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	ci(t, w.Repo, 0).clean(t)

	w.Branch("remove-sam")
	res := w.Ada.Must("remove", "sam", "--yes")
	mustContain(t, "remove", res.Stdout, "sam", "checkout/dev", "carbon apply")
	w.Commit("remove sam")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "policy.revoke-proposed", "checkout/dev sam/laptop", "checkout/staging sam/laptop")
	cj.lacks(t, "slot.pending-revocation", "key.rotated")

	w.Checkout("main")
	w.Merge("remove-sam")
	cj = ci(t, w.Repo, 0)
	cj.has(t, "slot.pending-revocation", "warning checkout/dev sam/laptop", "warning checkout/staging sam/laptop")
	ci(t, w.Repo, 4, "--strict").has(t, "slot.pending-revocation", "error checkout/dev sam/laptop")
	res = w.Lin.Must("status")
	mustContain(t, "lin status", res.Stdout, "revoke: sam/laptop", "carbon apply")

	// Removed readers cannot write, even before the rotation.
	w.Sam.In(co).Stdin("evil").Fails(3, "set", "webhook_secret", "--env", "dev")

	w.Branch("rotate")
	res = w.Lin.Must("apply", "--yes")
	mustContain(t, "apply", res.Stdout, "sam", "checkout/dev", "checkout/staging")
	// The rotation commit touches only the keys files: values stay where
	// they are (sam has seen them already) and open through the retired key.
	if got := w.Git("show", "--name-only", "--format=", "HEAD"); got != co+"/.carbon/dev.keys.toml\n"+co+"/.carbon/staging.keys.toml" {
		t.Fatalf("the rotation commit touched %q", got)
	}
	cj = ci(t, w.Repo, 0)
	cj.has(t, "key.rotated", "checkout/dev", "checkout/staging")
	cj.has(t, "debt.removal", "warning checkout/dev stripe_api_key")
	cj.lacks(t, "slot.pending-revocation", "key.changed")
	w.Checkout("main")
	w.Merge("rotate")
	preRotation := w.Git("rev-parse", "HEAD~1")

	// A new value after the rotation (set times have whole seconds; one in
	// the same second as the rotation counts as exposed).
	nextSecond()
	w.Lin.In(co).Stdin("sk_new").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("rotate stripe key at the source")
	w.Sam.In(co).Fails(3, "get", "stripe_api_key", "--env", "dev")
	// Even with the keys file from before the rotation (which still has a
	// slot for sam), sam cannot open the new value.
	keys := co + "/.carbon/dev.keys.toml"
	w.Write(keys, w.Git("show", preRotation+":"+keys)+"\n")
	res = w.Sam.In(co).Run("get", "stripe_api_key", "--env", "dev")
	if res.Code == 0 || strings.Contains(res.Stdout+res.Stderr, "sk_new") {
		t.Fatalf("sam read a value set after his removal:\n%s", res)
	}
	w.Git("checkout", "--", keys)

	// Debt: everything set before the removal, in the scopes sam read.
	res = w.Lin.Must("status", "--all")
	mustContain(t, "status debt", res.Stdout, "Rotate", "checkout/dev", "session_key", "sam removed")
	mustNotContain(t, "status debt", res.Stdout, "checkout/prod")
	cj = ci(t, w.Repo, 0, "--max-debt", "14d")
	cj.has(t, "debt.removal", "warning checkout/dev session_key", "warning checkout/staging stripe_api_key")
	for _, d := range cj.rules("debt.removal") {
		if strings.Contains(d, "checkout/dev stripe_api_key") || strings.Contains(d, "checkout/prod") {
			t.Fatalf("unexpected debt %q\n%s", d, cj)
		}
	}
	// Setting every value again clears it.
	nextSecond()
	for _, env := range []string{"dev", "staging"} {
		w.Lin.In(co).Must("set", "session_key", "--generate", "--env", env)
		w.Lin.In(co).Stdin("sk2").Must("set", "stripe_api_key", "--env", env)
		w.Lin.In(co).Stdin("wh2").Must("set", "webhook_secret", "--env", env)
	}
	w.Commit("rotate everything sam could read")
	ci(t, w.Repo, 0, "--max-debt", "14d").clean(t)
	res = w.Lin.Must("status", "--all")
	mustNotContain(t, "status after rotation", res.Stdout, "Rotate")
}

// nextSecond waits for the next whole second, so that a value set next is
// later than anything set so far (set times have whole seconds).
func nextSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)
}

// Journey d: someone who cannot read prod rotates a credential at its
// source and drops the new value; readers use it at once; apply promotes it.
func TestJourneyDrop(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"\n[env]\nWEBHOOK_SECRET = \"${webhook_secret}\"\n")
	setAll(t, w)
	ci(t, w.Repo, 0).clean(t)

	// ada reads dev but not prod.
	w.Branch("new-webhook-secret")
	w.Ada.In(co).Fails(3, "get", "webhook_secret", "--env", "prod")
	res := w.Ada.In(co).Stdin("wh_dropped").Must("set", "webhook_secret", "--env", "prod")
	mustContain(t, "drop", res.Stdout+res.Stderr, "drop", "Dropped.")
	mustNotContain(t, "drop", res.Stdout+res.Stderr, "wh_dropped")
	w.Commit("new webhook secret for prod")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "drop.pending", "checkout/prod webhook_secret")
	if b := cj.banner(); len(b) != 1 || b[0] != "drop.pending" {
		t.Fatalf("banner %v\n%s", b, cj)
	}
	res = w.Anyone().Must("check")
	mustContain(t, "check banner", res.Stdout, "TO REVIEW", "webhook_secret", "DROP")

	// Readers use the drop at once, on the branch.
	res = w.Lin.In(co).Must("run", "--env", "prod", "--", "printenv", "WEBHOOK_SECRET")
	if res.Stdout != "wh_dropped\n" {
		t.Fatalf("lin run = %q", res.Stdout)
	}
	res = w.Deploy.Must("run", "--package", "checkout", "--env", "prod", "--", "printenv", "WEBHOOK_SECRET")
	if res.Stdout != "wh_dropped\n" {
		t.Fatalf("deploy run = %q", res.Stdout)
	}
	res = w.Lin.Must("status")
	mustContain(t, "lin status", res.Stdout, "Drops", "checkout/prod", "webhook_secret")
	res = w.Lin.In(co).Must("ls", "--env", "prod")
	mustContain(t, "ls", res.Stdout, "webhook_secret", "drop")

	w.Checkout("main")
	w.Merge("new-webhook-secret")
	ci(t, w.Repo, 0).has(t, "drop.pending", "checkout/prod webhook_secret")

	w.Branch("promote")
	res = w.Lin.Must("apply", "--yes")
	mustContain(t, "apply", res.Stdout, "webhook_secret", "checkout/prod")
	cj = ci(t, w.Repo, 0)
	cj.lacks(t, "drop.pending", "key.changed", "secret.older-than-trunk")
	w.Checkout("main")
	w.Merge("promote")
	ci(t, w.Repo, 0).clean(t)
	res = w.Lin.In(co).Must("ls", "--env", "prod")
	mustContain(t, "ls after promote", res.Stdout, "webhook_secret")
	mustNotContain(t, "ls after promote", res.Stdout, "drop")
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "wh_dropped" {
		t.Fatalf("after promotion get = %q", got)
	}
	res = w.Lin.Must("status")
	mustNotContain(t, "status after promote", res.Stdout, "Drops")
}

// Journey e: ada's laptop is replaced. The old device id is removed and
// joined again with a new key before anyone applies; apply rotates, because
// the old key may be in someone else's hands.
func TestJourneyDeviceRekey(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	desk := w.Person("ada-desktop")
	desk.Must("join", "--person", "ada", "--device", "desktop")
	w.Commit("ada adds her desktop")
	setAll(t, w)
	ci(t, w.Repo, 0).clean(t)

	w.Branch("replace-laptop")
	res := desk.Must("remove", "ada/laptop", "--yes")
	mustContain(t, "remove device", res.Stdout, "ada/laptop")
	newLaptop := w.Person("ada-new-laptop")
	res = newLaptop.Must("join", "--person", "ada", "--device", "laptop")
	mustContain(t, "re-join", res.Stdout, "Fingerprint", "already names you")
	w.Commit("replace ada's laptop key")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "policy.revoke-proposed", "checkout/dev ada/laptop")
	cj.lacks(t, "slot.recipient", "slot.removed", "slot.rekeyed")

	w.Checkout("main")
	w.Merge("replace-laptop")
	cj = ci(t, w.Repo, 0)
	cj.has(t, "slot.rekeyed", "warning checkout/dev ada/laptop", "warning checkout/staging ada/laptop")
	ci(t, w.Repo, 4, "--strict")
	// The new laptop has no access until a reader applies; the old key
	// still opens the current key, which is why apply must rotate.
	newLaptop.In(co).Fails(3, "get", "stripe_api_key", "--env", "dev")
	res = w.Lin.Must("status")
	mustContain(t, "lin status", res.Stdout, "ada/laptop", "carbon apply")

	w.Branch("rotate-laptop")
	res = w.Lin.Must("apply", "--yes")
	mustContain(t, "apply", res.Stdout, "ada/laptop's key changed")
	cj = ci(t, w.Repo, 0)
	cj.has(t, "key.rotated", "checkout/dev", "checkout/staging")
	cj.lacks(t, "slot.rekeyed", "key.changed", "slot.recipient")
	cj.has(t, "debt.removal", "checkout/dev stripe_api_key")
	if !strings.Contains(w.Read(co+"/.carbon/dev.keys.toml"), `reason = "rekeyed ada/laptop"`) {
		t.Fatalf("keys file:\n%s", w.Read(co+"/.carbon/dev.keys.toml"))
	}
	w.Checkout("main")
	w.Merge("rotate-laptop")
	ci(t, w.Repo, 0).has(t, "debt.removal", "warning checkout/dev session_key")
	res = w.Lin.Must("status", "--all")
	mustContain(t, "status debt", res.Stdout, "Rotate", "ada/laptop's old key")

	nextSecond()
	w.Lin.In(co).Stdin("sk_after").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("new stripe key")
	if got := newLaptop.In(co).Must("get", "stripe_api_key", "--env", "dev").Stdout; got != "sk_after" {
		t.Fatalf("new laptop get = %q", got)
	}
	res = w.Ada.In(co).Run("get", "stripe_api_key", "--env", "dev")
	if res.Code == 0 || strings.Contains(res.Stdout+res.Stderr, "sk_after") {
		t.Fatalf("the old laptop key read a value set after the re-key:\n%s", res)
	}
	cj = ci(t, w.Repo, 0)
	for _, d := range cj.rules("debt.removal") {
		if strings.Contains(d, "checkout/dev stripe_api_key") {
			t.Fatalf("debt not cleared: %q\n%s", d, cj)
		}
	}
}

// Journey f: the attacks reviews found, end to end through check (CI) and
// through the commands a reader runs on the attacker's branch.
func TestJourneyAttacks(t *testing.T) {
	t.Run("forged keys file for an existing scope", func(t *testing.T) {
		w := clitest.Standard(t)
		co := w.PkgDir
		w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"\n[env]\nSTRIPE = \"${stripe_api_key}\"\n")
		setAll(t, w)
		w.Lin.In(co).Must("get", "stripe_api_key", "--env", "prod") // lin pins prod's key

		// ada cannot read prod. She replaces its key with one she made,
		// wrapped to every reader, and seals a value of her choosing.
		w.Branch("mallory")
		forgeKeys(t, w, "sk_mallory")
		w.Commit("carbon apply: rotate checkout/prod")
		cj := ci(t, w.Repo, 4)
		cj.has(t, "key.changed", "error checkout/prod")

		before := w.Read(keysFile) + w.Read(secretsFile)
		for _, args := range [][]string{
			{"get", "stripe_api_key", "--env", "prod"},
			{"run", "--env", "prod", "--", "printenv", "STRIPE"},
			{"export", "--env", "prod"},
		} {
			res := w.Lin.In(co).Fails(1, args...)
			mustContain(t, args[0], res.Stderr, "does not descend from trunk")
			mustNotContain(t, args[0], res.Stdout+res.Stderr, "sk_mallory")
		}
		res := w.Lin.In(co).Stdin("sk_real_new").Fails(1, "set", "stripe_api_key", "--env", "prod")
		mustContain(t, "set", res.Stderr, "does not descend from trunk")
		res = w.Lin.Fails(1, "apply", "--yes")
		mustContain(t, "apply", res.Stdout, "checkout/prod", "refused")
		if w.Read(keysFile)+w.Read(secretsFile) != before {
			t.Fatal("a reader command changed the forged scope")
		}
		// status predicts the refusal instead of listing prod as readable.
		res = w.Lin.Must("status")
		mustContain(t, "status", res.Stdout, "Refused", "checkout/prod", "does not follow from trunk")

		// A reviewer merges it anyway. Trunk now equals the forgery, so the
		// trunk check passes vacuously and check has nothing to compare;
		// lin's pin is what stops her.
		w.Checkout("main")
		w.Merge("mallory")
		ci(t, w.Repo, 4).lacks(t, "key.changed", "key.rotated") // only the dropped values show
		res = w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "prod")
		mustContain(t, "get after merge", res.Stderr, "was replaced", "carbon trust")
		mustNotContain(t, "get after merge", res.Stdout+res.Stderr, "sk_mallory")
		w.Lin.In(co).Stdin("x").Fails(1, "set", "stripe_api_key", "--env", "prod")
		res = w.Lin.Must("status")
		mustContain(t, "status after merge", res.Stdout, "Refused", "checkout/prod", "you pinned")
		// A fresh clone (or CI machine) has no pin: the documented limit.
		if got := w.Deploy.In(co).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_mallory" {
			t.Fatalf("deploy read %q", got)
		}
	})

	t.Run("forged first key of a new scope", func(t *testing.T) {
		w := clitest.Standard(t)
		w.AddPackage("services/billing", "billing", "[access]\nprod = [\"@payments\"]\n\n[secrets]\ntoken = {}\n")
		w.Commit("billing")
		// ada (not a reader of billing/prod) creates its key on a branch,
		// wrapped only to lin, so every slot rule holds: she keeps the key.
		w.Branch("billing-key")
		s, err := scope.Load(w.Path("services/billing"), "billing", "prod")
		if err != nil {
			t.Fatal(err)
		}
		o, err := s.Create(scopeDevices(t, w, "billing", "prod"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.Save(); err != nil {
			t.Fatal(err)
		}
		w.Commit("billing/prod key")
		cj := ci(t, w.Repo, 4) // billing's token is unset everywhere
		cj.has(t, "key.new", "billing/prod")
		cj.lacks(t, "slot.unbacked", "slot.recipient")
		found := false
		for _, b := range cj.banner() {
			found = found || b == "key.new"
		}
		if !found {
			t.Fatalf("key.new not in the banner\n%s", cj)
		}
		keys := w.Read("services/billing/.carbon/prod.keys.toml")
		res := w.Lin.Fails(1, "apply", "--yes")
		mustContain(t, "apply", res.Stdout, "billing/prod", "not on trunk")
		// lin cannot know who made the key, so she will not seal under it.
		res = w.Lin.In("services/billing").Stdin("tok_real").Fails(1, "set", "token", "--env", "prod")
		mustContain(t, "set", res.Stderr, "exists only on this branch", "carbon trust")
		if w.Read("services/billing/.carbon/prod.keys.toml") != keys || w.Read("services/billing/.carbon/prod.secrets.toml") != "" {
			t.Fatal("a reader command changed the forged scope")
		}
		res = w.Lin.Must("status")
		mustContain(t, "status", res.Stdout, "New keys", "billing/prod")
	})

	t.Run("relabelled slot", func(t *testing.T) {
		w := clitest.Standard(t)
		co := w.PkgDir
		setAll(t, w)
		desk := w.Person("ada-desk")
		desk.Must("join", "--person", "ada", "--device", "desk")
		w.Ada.Must("remove", "sam", "--yes")
		w.Commit("ada's desk; remove sam")
		// sam relabels his own slot as ada's new device, hoping a reviewer
		// sees a grant that policy backs.
		w.Branch("sam-relabel")
		w.Replace(co+"/.carbon/dev.keys.toml", `"sam/laptop"`, `"ada/desk"`)
		w.Commit("carbon apply: grant ada/desk")
		cj := ci(t, w.Repo, 4)
		cj.has(t, "slot.removed", "error checkout/dev sam/laptop")
		cj.has(t, "slot.recipient", "error checkout/dev ada/desk")
	})

	t.Run("rollback of the keys file by revert", func(t *testing.T) {
		w := clitest.Standard(t)
		co := w.PkgDir
		setAll(t, w)
		w.Ada.Must("remove", "sam", "--yes")
		w.Commit("remove sam")
		w.Lin.Must("apply", "--yes")
		ci(t, w.Repo, 0).lacks(t, "key.changed")

		w.Branch("revert-rotation")
		w.Git("revert", "--no-edit", "HEAD")
		cj := ci(t, w.Repo, 4)
		cj.has(t, "key.changed", "error checkout/dev")
		// A reader on that branch will not seal under the key sam holds.
		res := w.Lin.In(co).Stdin("sk_new").Fails(1, "set", "stripe_api_key", "--env", "dev")
		mustContain(t, "set", res.Stderr, "trunk retired", "git merge refs/heads/main")
		res = w.Lin.Fails(1, "apply", "--yes")
		mustContain(t, "apply", res.Stdout, "checkout/dev")
	})

	t.Run("identity variable in [env]", func(t *testing.T) {
		w := clitest.Standard(t)
		co := w.PkgDir
		setAll(t, w)
		w.Branch("exfiltrate")
		w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"\n[env]\nDEBUG_ID = \"${env:CARBON_IDENTITY}\"\n")
		w.Commit("debugging aid")
		cj := ci(t, w.Repo, 4)
		cj.has(t, "graph.forbidden-env", "error")
		res := w.Deploy.In(co).Fails(1, "run", "--env", "prod", "--", "printenv", "DEBUG_ID")
		mustNotContain(t, "run", res.Stdout+res.Stderr, "AGE-SECRET-KEY")
		res = w.Deploy.In(co).Fails(1, "export", "--env", "prod")
		mustNotContain(t, "export", res.Stdout+res.Stderr, "AGE-SECRET-KEY")
	})
}

// Journey g: the shapes a CI checkout takes. A pull request job checks
// out one commit, detached, with no remote-tracking refs; it must fetch
// trunk and name it.
func TestJourneyCIShapes(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"\n[env]\nSTRIPE = \"${stripe_api_key}\"\n")
	setAll(t, w)
	w.Branch("feature")
	w.Ada.In(co).Stdin("wh_new").Must("set", "webhook_secret", "--env", "prod") // a drop
	w.Commit("feature")
	head := w.Git("rev-parse", "HEAD")
	w.Checkout("main")

	// The CI workspace: one commit, detached, no remotes.
	ciDir := w.Path("../ci")
	w.Git("init", "-q", ciDir)
	w.Git("-C", ciDir, "fetch", "-q", "--no-tags", w.Dir, head)
	w.Git("-C", ciDir, "checkout", "-q", "--detach", "FETCH_HEAD")
	anyone := w.Anyone()
	res := anyone.In("../ci").Fails(1, "check")
	mustContain(t, "check without trunk", res.Stderr, "no trunk", "CARBON_TRUNK", "--bootstrap")

	// Remote-tracking refs, but neither origin/HEAD nor origin/main.
	w.Git("-C", ciDir, "remote", "add", "origin", w.Dir)
	w.Git("-C", ciDir, "fetch", "-q", "--no-tags", "origin", "feature:refs/remotes/origin/feature")
	res = anyone.In("../ci").Fails(1, "check")
	mustContain(t, "check with unresolvable trunk", res.Stderr, "git remote set-head origin -a", "CARBON_TRUNK")

	// The documented recipe: fetch the default branch and name it.
	w.Git("-C", ciDir, "fetch", "-q", "--no-tags", "origin", "main:refs/remotes/origin/main")
	res = anyone.In("../ci").With("CARBON_TRUNK=refs/remotes/origin/main").Must("check")
	mustContain(t, "check in CI", res.Stdout, "Compared with trunk: refs/remotes/origin/main at ", "(from CARBON_TRUNK)", "TO REVIEW", "webhook_secret", "check passed")
	// Drops are for review, not failures, even under --strict.
	anyone.In("../ci").With("CARBON_TRUNK=origin/main").Must("check", "--strict", "--max-debt", "1d")
	// Without the variable, the fetched origin/main is the remote default.
	anyone.In("../ci").Must("check")

	// A deploy job: a machine identity, the same checkout, trunk named.
	res = w.Deploy.In("../ci").With("CARBON_TRUNK=origin/main").Must("run", "--env", "prod", "--package", "checkout", "--", "printenv", "STRIPE")
	if res.Stdout != "sk_prod\n" {
		t.Fatalf("deploy run = %q", res.Stdout)
	}
	// A trunk name that does not resolve is an error, never a fallback.
	res = w.Deploy.In("../ci").With("CARBON_TRUNK=origin/nope").Fails(1, "run", "--env", "prod", "--package", "checkout", "--", "printenv", "STRIPE")
	mustNotContain(t, "deploy with bad trunk", res.Stdout, "sk_prod")
}

// Journey: a rotation leaves the secrets file alone. A branch cut before a
// removal adds a secret; the removal merges and a reader rotates on trunk;
// the old branch merges trunk with no conflict, and check flags its new
// value as unproven until a reader vouches for it.
func TestJourneyBranchCutBeforeARotation(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)

	w.Branch("api-token")
	w.Replace(co+"/carbon.toml", "[secrets]\n", "[secrets]\napi_token = { description = \"partner API token\" }\n")
	for _, env := range []string{"dev", "staging", "prod"} {
		w.Lin.In(co).Stdin("tok_"+env).Must("set", "api_token", "--env", env)
	}
	w.Commit("add api_token")
	ci(t, w.Repo, 0).lacks(t, "secret.stale-key")

	w.Checkout("main")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	secretsBefore := w.Read(co+"/.carbon/dev.secrets.toml") + w.Read(co+"/.carbon/staging.secrets.toml")
	w.Lin.Must("apply", "--yes")
	if got := w.Git("show", "--name-only", "--format=", "HEAD"); got != co+"/.carbon/dev.keys.toml\n"+co+"/.carbon/staging.keys.toml" {
		t.Fatalf("the rotation commit touched %q", got)
	}
	if stat := w.Git("diff", "--stat", "HEAD~1", "HEAD"); strings.Contains(stat, "secrets.toml") {
		t.Fatalf("rotation diff:\n%s", stat)
	}
	if w.Read(co+"/.carbon/dev.secrets.toml")+w.Read(co+"/.carbon/staging.secrets.toml") != secretsBefore {
		t.Fatal("the rotation changed a secrets file")
	}
	ci(t, w.Repo, 0).lacks(t, "secret.stale-key", "key.changed")
	// Everyone still reads the old values, carried under the retired key;
	// ls shows them as ordinary sealed values.
	if got := w.Ada.In(co).Must("get", "stripe_api_key", "--env", "dev").Stdout; got != "sk_dev" {
		t.Fatalf("ada get = %q", got)
	}
	res := w.Lin.In(co).Must("ls", "--env", "dev")
	mustNotContain(t, "ls", res.Stdout, "unproven", "stale")
	// A value set after the rotation is under the new key: sam cannot read it.
	nextSecond()
	w.Lin.In(co).Stdin("sk_new").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("new stripe key")
	res = w.Sam.In(co).Run("get", "stripe_api_key", "--env", "dev")
	if res.Code == 0 || strings.Contains(res.Stdout+res.Stderr, "sk_new") {
		t.Fatalf("sam read a value set after his removal:\n%s", res)
	}

	// The old branch merges trunk: no conflict in any secrets or keys file.
	w.Checkout("api-token")
	w.Merge("main")
	cj := ci(t, w.Repo, 0)
	cj.has(t, "secret.stale-key", "checkout/dev api_token", "checkout/staging api_token")
	for _, f := range cj.Findings {
		if f.Rule == "secret.stale-key" && f.Secret != "api_token" {
			t.Fatalf("a carried value is flagged: %+v", f)
		}
	}
	found := false
	for _, b := range cj.banner() {
		found = found || b == "secret.stale-key"
	}
	if !found {
		t.Fatalf("not in the banner\n%s", cj)
	}
	res = w.Lin.Must("status")
	mustContain(t, "status", res.Stdout, "Unproven", "api_token")
	// A reader vouches for it.
	res = w.Lin.Must("apply", "--yes", "--reseal-unproven")
	mustContain(t, "apply", res.Stdout, "api_token", "re-seals as trusted")
	ci(t, w.Repo, 0).lacks(t, "secret.stale-key")
	if got := w.Ada.In(co).Must("get", "api_token", "--env", "dev").Stdout; got != "tok_dev" {
		t.Fatalf("api_token = %q", got)
	}
	w.Checkout("main")
	w.Merge("api-token")
	cj = ci(t, w.Repo, 0)
	cj.lacks(t, "secret.stale-key", "key.changed", "secret.rolled-back")
	w.Sam.In(co).Fails(3, "get", "api_token", "--env", "dev")
}
