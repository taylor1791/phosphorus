package cli_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// setAll gives every declared checkout secret a value in every environment,
// as lin (who reads them all), and commits it to trunk.
func setAll(t *testing.T, w *clitest.World) {
	t.Helper()
	for _, env := range []string{"dev", "staging", "prod"} {
		w.Lin.In(w.PkgDir).Must("set", "session_key", "--generate", "--env", env)
		w.Lin.In(w.PkgDir).Stdin("sk_"+env).Must("set", "stripe_api_key", "--env", env)
		w.Lin.In(w.PkgDir).Stdin("wh_"+env).Must("set", "webhook_secret", "--env", env)
	}
	w.Commit("set every secret")
}

type checkJSON struct {
	OK       bool
	Trunk    struct{ Ref, From, Mode string }
	Counts   struct{ Errors, Warnings, Info, Drops, Review int }
	Findings []struct {
		Severity, Rule, Scope, Secret, Device, Message, Hint string
		Strict                                               bool
	}
	Rules []struct{ ID, Severity string }
}

func checkAsJSON(t *testing.T, res *clitest.Result) checkJSON {
	t.Helper()
	var cj checkJSON
	if err := json.Unmarshal([]byte(res.Stdout), &cj); err != nil {
		t.Fatalf("check --json: %v\n%s", err, res)
	}
	return cj
}

func hasRule(cj checkJSON, rule, sev string) bool {
	for _, f := range cj.Findings {
		if f.Rule == rule && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestCheckExitCodes(t *testing.T) {
	w := clitest.Standard(t)
	anyone := w.Anyone() // check never needs an identity

	// Nothing is set yet: every declared secret is unset in every environment.
	res := anyone.Fails(4, "check")
	contains(t, "check", res.Stdout, "error[secret.unset] checkout/prod:", "carbon set session_key --generate --package checkout --env prod", "check failed: 9 errors")
	cj := checkAsJSON(t, anyone.Fails(4, "check", "--json"))
	if cj.OK || cj.Counts.Errors != 9 || !hasRule(cj, "secret.unset", "error") || len(cj.Rules) == 0 {
		t.Fatalf("%+v", cj)
	}

	setAll(t, w)
	res = anyone.Must("check")
	contains(t, "check", res.Stdout, "check passed: 0 errors, 0 warnings.")
	anyone.Must("check", "--strict")
	if cj := checkAsJSON(t, anyone.Must("check", "--json")); !cj.OK || len(cj.Findings) != 0 {
		t.Fatalf("%+v", cj)
	}

	// A pending grant passes, except under --strict.
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam"}, "payments": {"lin", "ada"}})
	w.Commit("ada joins payments")
	res = anyone.Must("check")
	contains(t, "check", res.Stdout, "info[slot.pending-grant] checkout/prod:", "ada/laptop", "check passed: 0 errors, 0 warnings, 1 pending grant.")
	res = anyone.Fails(4, "check", "--strict")
	contains(t, "check --strict", res.Stdout, "error (--strict)[slot.pending-grant]")

	// A grant that merged policy does not back fails.
	w.Git("reset", "-q", "--hard", "HEAD~1")
	w.Branch("sneaky")
	grantSlot(t, w, "checkout", "prod", w.Lin, "lin/laptop", "sam/laptop")
	res = anyone.Fails(4, "check")
	contains(t, "check", res.Stdout, "error[slot.unbacked] checkout/prod:", "sam/laptop")

	// Usage errors.
	anyone.Fails(2, "check", "--max-debt", "two weeks")
}

func TestCheckListsDrops(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	w.Branch("ada-drop")
	w.Ada.In(w.PkgDir).Stdin("whsec_new").Must("set", "webhook_secret", "--env", "prod")
	res := w.Anyone().Must("check")
	contains(t, "check", res.Stdout, "!! 1 ITEM TO REVIEW", "checkout/prod   webhook_secret", "DROP", "1 item to review")
	if !strings.HasPrefix(res.Stdout, "Compared with trunk: main (from git config carbon.trunk)\n\n!!!!") {
		t.Fatalf("the trunk line and the review banner do not come first:\n%s", res.Stdout)
	}
	cj := checkAsJSON(t, w.Anyone().Must("check", "--json"))
	if cj.Counts.Drops != 1 || !hasRule(cj, "drop.pending", "info") {
		t.Fatalf("%+v", cj)
	}

	// Where drops are off, a drop fails the check.
	w.Replace(w.PkgDir+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`,
		`prod = { readers = ["@payments", "machine:deploy-checkout"], drops = false }`)
	res = w.Anyone().Fails(4, "check")
	contains(t, "check", res.Stdout, "DROP where drops are off (error)", "error[drop.forbidden] checkout/prod:")
}

func TestCheckListsNewScopeKeys(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	w.Branch("new-scope")
	w.AddPackage("services/search", "search", "[secrets]\nkey = {}\n")
	w.Lin.In("services/search").Stdin("k").Must("set", "key", "--env", "dev")
	res := w.Anyone().Fails(4, "check") // staging and prod are unset
	contains(t, "check", res.Stdout, "!!   search/dev", "NEW SCOPE KEY: confirm the author is a reader of search/dev")
	// Never a failure, even under --strict.
	cj := checkAsJSON(t, w.Anyone().Fails(4, "check", "--json", "--strict"))
	for _, f := range cj.Findings {
		if f.Rule == "key.new" && f.Severity != "info" {
			t.Fatalf("key.new is %s under --strict", f.Severity)
		}
	}
	if !hasRule(cj, "key.new", "info") || cj.Counts.Review != 1 {
		t.Fatalf("%+v", cj)
	}
	contains(t, "status", w.Lin.Must("status").Stdout, "New keys", "search/dev", "confirm its author is a reader of search/dev")
}

func TestCheckTrunk(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	cj := checkAsJSON(t, w.Anyone().Must("check", "--json"))
	if cj.Trunk.Ref != "main" || cj.Trunk.From != "git config carbon.trunk" || cj.Trunk.Mode != "trunk" {
		t.Fatalf("%+v", cj.Trunk)
	}
	// worktree mode, chosen per process: a warning.
	res := w.Anyone().With("CARBON_TRUNK=worktree").Must("check")
	contains(t, "check", res.Stdout, `Compared with trunk: none: the trunk is "worktree" (from CARBON_TRUNK)`, "warning[trunk.worktree]")
	// Remotes but no trunk: check cannot pass, and says what CI must do.
	w.Git("config", "--unset", "carbon.trunk")
	w.Git("update-ref", "refs/remotes/upstream/feature", "HEAD")
	res = w.Anyone().Fails(1, "check")
	contains(t, "stderr", res.Stderr, "cannot tell which branch is trunk", "In CI: set CARBON_TRUNK", "git config carbon.trunk <ref>")
	// An override naming a missing ref.
	res = w.Anyone().With("CARBON_TRUNK=origin/nope").Fails(1, "check")
	contains(t, "stderr", res.Stderr, "trunk origin/nope (from CARBON_TRUNK) does not exist", "In CI")
	// status carries on.
	contains(t, "status", w.Lin.Must("status").Stdout, "Trunk is unresolved")
}

func TestCheckCoverageAndUnused(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	w.AddPackage("services/db", "db", "[secrets]\npassword = {}\nunused_one = {}\n")
	w.Replace(w.PkgDir+"/carbon.toml", "webhook_secret = { description = \"Stripe webhook signing secret\" }\n",
		"webhook_secret = { description = \"Stripe webhook signing secret\" }\n\n[env]\nDATABASE_PASSWORD = \"${db.password}\"\n")
	for _, env := range []string{"dev", "staging", "prod"} {
		w.Lin.In("services/db").Stdin("pw").Must("set", "password", "--env", env)
		w.Lin.In("services/db").Stdin("x").Must("set", "unused_one", "--env", env)
	}
	res := w.Anyone().Fails(4, "check")
	contains(t, "check", res.Stdout, "error[access.coverage] checkout/prod: machine:deploy-checkout reads checkout/prod, which references db.password, but is not a reader of db/prod")
	if strings.Contains(res.Stdout, "secret.unused") {
		t.Fatal("--unused output without --unused")
	}
	res = w.Anyone().Fails(4, "check", "--unused")
	contains(t, "check --unused", res.Stdout, "info[secret.unused] db: db.unused_one is not referenced")
}

func TestCheckRotationDebt(t *testing.T) {
	w := clitest.Standard(t)
	setAll(t, w)
	// stripe_api_key in checkout/dev was set 30 days ago; sam was removed 20
	// days ago and a reader rotated the key.
	setOld(t, w, "checkout", "dev", "stripe_api_key", 30)
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin"}, "payments": {"lin"}})
	w.Commit("remove sam from engineering")
	rotateDaysAgo(t, w, "checkout", "dev", "removed sam", 20)
	w.Commit("apply")

	res := w.Anyone().Run("check")
	contains(t, "check", res.Stdout, "warning[debt.removal] checkout/dev: stripe_api_key in checkout/dev owes a rotation", "sam was removed")
	res = w.Anyone().Fails(4, "check", "--max-debt", "14d")
	contains(t, "check", res.Stdout, "error[debt.removal] checkout/dev:", "past --max-debt 14d")

	// status shows it to readers of the scope, and to anyone with --all.
	contains(t, "status", w.Lin.Must("status").Stdout, "Rotate", "checkout/dev", "stripe_api_key", "sam removed")
	res = w.Anyone().Must("status")
	if strings.Contains(res.Stdout, "Rotate") {
		t.Fatalf("debt shown without an identity or --all:\n%s", res.Stdout)
	}
	contains(t, "status --all", w.Anyone().Must("status", "--all").Stdout, "Rotate", "checkout/dev")
}

func TestWho(t *testing.T) {
	w := clitest.Standard(t)
	res := w.Anyone().Must("who", "checkout", "--env", "prod")
	contains(t, "who", res.Stdout,
		"lin                       laptop   via @payments",
		"machine:deploy-checkout            named in services/checkout/carbon.toml")
	if strings.Contains(res.Stdout, "ada") {
		t.Fatalf("ada does not read checkout/prod:\n%s", res.Stdout)
	}
	res = w.Anyone().Must("who", "checkout")
	contains(t, "who", res.Stdout, "checkout/dev   readers from carbon.toml", "  ada   laptop   via @engineering", "checkout/prod   readers from services/checkout/carbon.toml")
	var wj struct {
		Scopes []struct {
			Scope      string
			Principals []struct {
				Principal string
				Devices   []string
				Via       []string
			}
		}
	}
	if err := json.Unmarshal([]byte(w.Anyone().Must("who", "checkout", "--env", "prod", "--json").Stdout), &wj); err != nil {
		t.Fatal(err)
	}
	if len(wj.Scopes) != 1 || len(wj.Scopes[0].Principals) != 2 || wj.Scopes[0].Principals[0].Via[0] != "@payments" {
		t.Fatalf("%+v", wj)
	}
	res = w.Anyone().Fails(5, "who", "nope")
	contains(t, "who", res.Stderr, `no package named "nope"`, "Packages in this workspace: checkout.")
	w.Anyone().Fails(2, "who")
	w.Anyone().Fails(2, "who", "checkout", "--env", "qa")
}

func TestAccess(t *testing.T) {
	w := clitest.Standard(t)
	res := w.Anyone().Must("access", "lin")
	contains(t, "access", res.Stdout, "lin (laptop) reads 3 scopes:",
		"checkout/dev       laptop   via @engineering in carbon.toml",
		"checkout/prod      laptop   via @payments in services/checkout/carbon.toml",
		"lin is a member of @engineering and @payments.")
	res = w.Anyone().Must("access", "ada", "--env", "prod")
	contains(t, "access", res.Stdout, "ada (laptop) reads no scopes.", "carbon request")
	res = w.Anyone().Must("access", "machine:deploy-checkout")
	contains(t, "access", res.Stdout, "machine:deploy-checkout reads 1 scope:", "checkout/prod      named in services/checkout/carbon.toml")
	var aj struct {
		Principal string
		Scopes    []struct{ Scope string }
	}
	if err := json.Unmarshal([]byte(w.Anyone().Must("access", "sam", "--json").Stdout), &aj); err != nil || len(aj.Scopes) != 2 {
		t.Fatalf("%+v %v", aj, err)
	}
	w.Anyone().Fails(5, "access", "ghost")
	w.Anyone().Fails(5, "access", "machine:ghost")
	w.Anyone().Fails(2, "access", "@payments")
}

func TestStatusWithoutIdentity(t *testing.T) {
	w := clitest.Standard(t)
	res := w.Anyone().Must("status")
	contains(t, "status", res.Stdout, "No carbon identity on this device. Environment: dev.", "carbon join", "carbon status --all")
	res = w.Anyone().Must("status", "--env", "prod", "--json")
	var sj struct {
		Identity    *struct{}
		Environment string
	}
	if err := json.Unmarshal([]byte(res.Stdout), &sj); err != nil || sj.Identity != nil || sj.Environment != "prod" {
		t.Fatalf("%+v %v\n%s", sj, err, res.Stdout)
	}
	// An identity that is in no person file.
	stranger := w.Person("stranger")
	stranger.Must("join", "--person", "stranger", "--device", "laptop")
	w.Git("checkout", "--", ".")
	w.Git("clean", "-fdq")
	contains(t, "status", stranger.Must("status").Stdout, "is not in .carbon/people or .carbon/machines", "carbon join")
}

func TestStatusWithIdentity(t *testing.T) {
	w := clitest.Standard(t)
	contains(t, "status", w.Lin.Must("status").Stdout, "You are lin (laptop). Environment: dev.", "Readable   none yet")
	setAll(t, w)
	res := w.Lin.Must("status", "--env", "staging")
	contains(t, "status", res.Stdout, "You are lin (laptop). Environment: staging.", "Readable   3 scopes in dev, staging, prod")
	contains(t, "status", w.Deploy.Must("status").Stdout, "You are machine:deploy-checkout. Environment: dev.", "1 scope in prod")

	// sam is named for prod on this branch only: waiting, not merged.
	w.Replace(w.PkgDir+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`, `prod = ["@payments", "machine:deploy-checkout", "sam"]`)
	contains(t, "status", w.Sam.Must("status").Stdout, "Waiting", "checkout/prod   named on this branch, not merged to trunk yet")
	w.Commit("sam reads prod")
	contains(t, "status", w.Sam.Must("status").Stdout, "checkout/prod   merged; waiting for a reader to run `carbon apply`")
	// lin reads prod, so lin can grant it.
	contains(t, "status", w.Lin.Must("status").Stdout, "You can grant   pending: sam/laptop -> 1 scope   carbon apply")
	// ada cannot read prod, so ada cannot.
	if strings.Contains(w.Ada.Must("status").Stdout, "You can grant") {
		t.Fatal("ada offered a grant she cannot make")
	}

	// A drop in a scope lin reads.
	w.Ada.In(w.PkgDir).Stdin("whsec_new").Must("set", "webhook_secret", "--env", "prod")
	contains(t, "status", w.Lin.Must("status").Stdout, "Drops", "checkout/prod", "webhook_secret", "review, then carbon apply")
	var sj struct {
		Identity struct {
			Known  bool
			Person string
		}
		Readable []string
		Waiting  []struct{ Scope, Reason string }
		Grants   []struct {
			Kind, Device string
			Scopes       []string
		}
		Drops []struct{ Scope, Secret string }
	}
	if err := json.Unmarshal([]byte(w.Lin.Must("status", "--json").Stdout), &sj); err != nil {
		t.Fatal(err)
	}
	if !sj.Identity.Known || sj.Identity.Person != "lin" || len(sj.Readable) != 3 || len(sj.Grants) != 1 ||
		sj.Grants[0].Device != "sam/laptop" || len(sj.Drops) != 1 {
		t.Fatalf("%+v", sj)
	}
}

func TestGraph(t *testing.T) {
	w := clitest.Standard(t)
	w.AddPackage("services/db", "db", "[secrets]\npassword = {}\n[vars.host]\ndefault = \"db.internal\"\n")
	w.Replace(w.PkgDir+"/carbon.toml", "webhook_secret = { description = \"Stripe webhook signing secret\" }\n",
		"webhook_secret = { description = \"Stripe webhook signing secret\" }\n\n[env]\nDB = \"postgres://${db.host}/${db.password}?k=${session_key}\"\nX = \"${search.key}\"\n")
	res := w.Anyone().Must("graph")
	contains(t, "graph", res.Stdout, "digraph carbon {", `"checkout" -> "db" [label="host, password"];`,
		`"search" [style=dashed, color=red, label="search (missing)"];`, `"checkout" -> "search"`)
	if strings.Contains(res.Stdout, `"checkout" -> "checkout"`) {
		t.Fatal("a package's own names are not edges")
	}
	var g struct {
		Packages []string
		Edges    []struct {
			From, To string
			Names    []string
			Missing  bool
		}
	}
	if err := json.Unmarshal([]byte(w.Anyone().Must("graph", "--json").Stdout), &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Packages) != 2 || len(g.Edges) != 2 || g.Edges[0].To != "db" || !g.Edges[1].Missing {
		t.Fatalf("%+v", g)
	}
}

// Helpers that build repository states later commands (apply, remove)
// would create, through internal/scope directly.

func identities(t *testing.T, p *clitest.Person) []agewrap.Identity {
	t.Helper()
	b, err := os.ReadFile(p.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	ids, err := agewrap.ParseIdentityFile(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func scopeDevices(t *testing.T, w *clitest.World, pkg, env string, only ...string) []policy.Device {
	t.Helper()
	pol, err := policy.LoadWorktree(w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) > 0 {
		var out []policy.Device
		for _, d := range pol.AllDevices() {
			for _, id := range only {
				if d.ID == id {
					out = append(out, d)
				}
			}
		}
		return out
	}
	sa, err := pol.Scope(pkg, env)
	if err != nil {
		t.Fatal(err)
	}
	return sa.Devices
}

func openScope(t *testing.T, w *clitest.World, pkg, env string, as *clitest.Person, dev string) *scope.Opened {
	t.Helper()
	s, err := scope.Load(w.Path(w.PkgDir), pkg, env)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Open(identities(t, as), dev)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// grantSlot wraps a scope's key to devices, as `apply` would.
func grantSlot(t *testing.T, w *clitest.World, pkg, env string, as *clitest.Person, asDev string, devs ...string) {
	t.Helper()
	o := openScope(t, w, pkg, env, as, asDev)
	defer o.Close()
	if _, err := o.AddSlots(scopeDevices(t, w, pkg, env, devs...)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Save(); err != nil {
		t.Fatal(err)
	}
}

// setOld re-seals a value with a set time days ago, as lin.
func setOld(t *testing.T, w *clitest.World, pkg, env, name string, days int) {
	t.Helper()
	o := openScope(t, w, pkg, env, w.Lin, "lin/laptop")
	defer o.Close()
	if err := o.Seal(name, []byte("old-value"), time.Now().Add(-time.Duration(days)*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Save(); err != nil {
		t.Fatal(err)
	}
}

// rotateDaysAgo rotates a scope's key days ago, as lin, as `apply` would after a
// removal.
func rotateDaysAgo(t *testing.T, w *clitest.World, pkg, env, reason string, days int) {
	t.Helper()
	o := openScope(t, w, pkg, env, w.Lin, "lin/laptop")
	defer o.Close()
	if _, err := o.Rotate(scopeDevices(t, w, pkg, env), reason, time.Now().Add(-time.Duration(days)*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Save(); err != nil {
		t.Fatal(err)
	}
}
