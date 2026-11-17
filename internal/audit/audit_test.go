package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func TestCleanRepositoryHasNoFindings(t *testing.T) {
	f := newFx(t)
	rep := f.check(Options{Strict: true, Unused: true})
	if len(rep.Findings) != 0 {
		t.Fatalf("clean repo:\n%s", dump(rep))
	}
}

func TestRulesListEveryRuleOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] {
			t.Fatalf("rule %s listed twice", r.ID)
		}
		seen[r.ID] = true
	}
	if len(seen) != 37 {
		t.Fatalf("%d rules; update this test when adding one", len(seen))
	}
}

// Loading.

func TestConfigInvalid(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/bad", "name = \"bad\"\n[secrets]\nx = { nope = 1 }\n")
	rep := f.check(Options{})
	got := want(t, rep, RuleConfigInvalid, Error)
	if got.File != "svc/bad/carbon.toml" {
		t.Fatalf("file %q", got.File)
	}
	// The rest of the repository is still audited.
	none(t, rep, RuleSecretUnset)
}

func TestConfigLegacy(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/old", "name = \"old\"\n[push.db]\nvalue = \"x\"\n")
	want(t, f.check(Options{}), RuleConfigLegacy, Error)
}

func TestDuplicatePackage(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/app2", "name = \"app\"\n")
	want(t, f.check(Options{}), RuleDuplicatePackage, Error)
}

func TestNameInvalid(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/x", "name = \"Bad Name\"\n")
	want(t, f.check(Options{}), RuleNameInvalid, Error)
	f.addPackage("svc/x", "name = \"x\"\n[secrets]\n\"9lives\" = {}\n")
	want(t, f.check(Options{}), RuleNameInvalid, Error)
}

func TestNameReserved(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/x", "name = \"env\"\n")
	want(t, f.check(Options{}), RuleNameReserved, Error)
}

func TestStoreInvalid(t *testing.T) {
	f := newFx(t)
	f.write("svc/app/.carbon/dev.keys.toml", "scope = \"app/dev\"\ncurrent = 7\n")
	got := want(t, f.check(Options{}), RuleStoreInvalid, Error)
	if got.Scope != "app/dev" {
		t.Fatalf("scope %q", got.Scope)
	}
	// A keys file copied from another scope.
	f.git("checkout", "--", ".")
	f.write("svc/app/.carbon/dev.keys.toml", f.read("svc/app/.carbon/prod.keys.toml"))
	want(t, f.check(Options{}), RuleStoreInvalid, Error)
}

func TestTrunkUnreadable(t *testing.T) {
	f := newFx(t)
	good := f.read(".carbon/teams.toml")
	f.write(".carbon/teams.toml", "eng = 7\n")
	f.commit("break teams on trunk")
	f.write(".carbon/teams.toml", good)
	rep := f.check(Options{})
	want(t, rep, RuleTrunkUnreadable, Error)
	none(t, rep, RuleSlotPendingGrant)
}

func TestTrunkBootstrap(t *testing.T) {
	f := newFx(t)
	f.git("branch", "-m", "main", "work") // trunk "main" no longer exists
	rep := f.check(Options{})
	want(t, rep, RuleTrunkBootstrap, Info)
}

// The reference graph.

func TestGraphMissingPackage(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "[env]\n", "[env]\nDB = \"${db.password}\"\n")
	got := want(t, f.check(Options{}), RuleGraphMissingPkg, Error)
	if got.Package != "app" || !strings.Contains(got.Message, "${db.password}") {
		t.Fatalf("%+v", got)
	}
}

func TestGraphMissingName(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "[env]\n", "[env]\nX = \"${nothing}\"\n")
	want(t, f.check(Options{}), RuleGraphMissingName, Error)
}

func TestGraphPrivate(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/lib", "name = \"lib\"\n[secrets]\nk = { private = true }\n[env]\nK = \"${k}\"\n")
	f.replace("svc/app/carbon.toml", "[env]\n", "[env]\nK = \"${lib.k}\"\n")
	rep := f.check(Options{})
	got := want(t, rep, RuleGraphPrivate, Error)
	if got.Package != "app" {
		t.Fatalf("private flagged on %q, want the consumer", got.Package)
	}
	if len(rep.ByRule(RuleGraphPrivate)) != 1 {
		t.Fatalf("lib's own use of its private secret was flagged:\n%s", dump(rep))
	}
}

func TestGraphSecretAndVar(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "[secrets]\n", "[secrets]\nurl = {}\n")
	want(t, f.check(Options{}), RuleGraphSecretAndVar, Error)
}

func TestGraphVarUnset(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "default = \"http://localhost\"", "dev = \"http://localhost\"")
	rep := f.check(Options{})
	got := want(t, rep, RuleGraphVarUnset, Error)
	if got.Env != "prod" || len(rep.ByRule(RuleGraphVarUnset)) != 1 {
		t.Fatalf("want prod only:\n%s", dump(rep))
	}
}

func TestGraphCycle(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/a", "name = \"a\"\n[vars.x]\ndefault = \"1\"\n[env]\nY = \"${b.y}\"\n")
	f.addPackage("svc/b", "name = \"b\"\n[vars.y]\ndefault = \"1\"\n[env]\nX = \"${a.x}\"\n")
	got := want(t, f.check(Options{}), RuleGraphCycle, Error)
	if !strings.Contains(got.Message, "a, b") {
		t.Fatal(got.Message)
	}
}

// Declared versus stored.

func TestSecretUnset(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "[secrets]\n", "[secrets]\nsession = { generate = \"random:32\" }\n")
	rep := f.check(Options{})
	got := want(t, rep, RuleSecretUnset, Error)
	if got.Hint != "carbon set session --generate --package app --env dev" {
		t.Fatalf("hint %q", got.Hint)
	}
	// Every workspace environment counts.
	if n := len(rep.ByRule(RuleSecretUnset)); n != 2 {
		t.Fatalf("%d unset findings, want dev and prod", n)
	}
}

func TestSecretUndeclared(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "token = { description = \"API token\" }\n", "")
	f.replace("svc/app/carbon.toml", "TOKEN = \"${token}\"\n", "")
	want(t, f.check(Options{}), RuleSecretUndeclared, Error)
}

func TestSecretUnknownKey(t *testing.T) {
	f := newFx(t)
	o := f.open("app", "dev", "ada/laptop")
	f.replace("svc/app/.carbon/dev.secrets.toml", "key = \""+o.CurrentID()+"\"", "key = \"kzzzzz\"")
	want(t, f.check(Options{}), RuleSecretUnknownKey, Error)
}

func TestSecretStaleKey(t *testing.T) {
	f := newFx(t)
	secrets := f.read("svc/app/.carbon/dev.secrets.toml")
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.Rotate(f.devices("app", "dev"), "scheduled", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	f.write("svc/app/.carbon/dev.secrets.toml", secrets) // the old line, under the now retired key
	rep := f.check(Options{})
	want(t, rep, RuleSecretStaleKey, Warning)
	none(t, rep, RuleSecretUnknownKey)
}

func TestSecretUnused(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", "[secrets]\n", "[secrets]\nspare = {}\n")
	none(t, f.check(Options{}), RuleSecretUnused)
	got := want(t, f.check(Options{Unused: true}), RuleSecretUnused, Info)
	if got.Secret != "spare" {
		t.Fatal(got.Secret)
	}
}

// Slots and keys.

func TestSlotUnbacked(t *testing.T) {
	f := newFx(t)
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.AddSlots(f.devicesOf("machine:deploy")); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	got := want(t, f.check(Options{}), RuleSlotUnbacked, Error)
	if got.Device != "machine:deploy" || got.Scope != "app/dev" {
		t.Fatalf("%+v", got)
	}
	// Once committed to trunk without policy, it is a pending revocation.
	f.commit("slot on trunk")
	rep := f.check(Options{})
	none(t, rep, RuleSlotUnbacked)
	want(t, rep, RuleSlotPendingRevocation, Warning)
}

func TestSlotPendingRevocation(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\"]\nops = [\"lin\"]\n")
	f.commit("remove sam from eng")
	rep := f.check(Options{})
	got := want(t, rep, RuleSlotPendingRevocation, Warning)
	if got.Device != "sam/laptop" {
		t.Fatal(got.Device)
	}
	none(t, rep, RuleSlotUnbacked)
	// --strict makes it an error.
	got = want(t, f.check(Options{Strict: true}), RuleSlotPendingRevocation, Error)
	if !got.Strict {
		t.Fatal("not marked strict")
	}
}

func TestSlotPendingGrant(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/people/ada.toml", f.read(".carbon/people/ada.toml")+"desk = \""+f.key("ada/desk", agewrap.KindHybrid)+"\"\n")
	f.commit("ada adds a desk")
	rep := f.check(Options{})
	got := want(t, rep, RuleSlotPendingGrant, Info)
	if got.Device != "ada/desk" || got.Scope != "app/dev" {
		t.Fatalf("%+v", got)
	}
	if rep.Failed() {
		t.Fatalf("a pending grant failed the check:\n%s", dump(rep))
	}
	if !f.check(Options{Strict: true}).Failed() {
		t.Fatal("--strict did not fail on a pending grant")
	}
	// A grant named only on a branch is not pending: trunk policy decides.
	f.git("reset", "-q", "--hard", "HEAD~1")
	f.write(".carbon/people/ada.toml", f.read(".carbon/people/ada.toml")+"desk = \""+f.recs["ada/desk"]+"\"\n")
	none(t, f.check(Options{}), RuleSlotPendingGrant)
}

func TestSlotMalformed(t *testing.T) {
	f := newFx(t)
	keys := "svc/app/.carbon/dev.keys.toml"
	o := f.open("app", "dev", "ada/laptop")
	adaSlot := o.Keys.CurrentKey().Slots["ada/laptop"]
	f.replace(keys, adaSlot, "age1:bm90IGFuIGFnZSBmaWxl")
	got := want(t, f.check(Options{}), RuleSlotMalformed, Error)
	if got.Device != "ada/laptop" {
		t.Fatal(got.Device)
	}

	// An age file with two recipient stanzas.
	f.git("checkout", "--", ".")
	var buf bytes.Buffer
	r1, _ := age.ParseHybridRecipient(f.recs["ada/laptop"])
	r2, _ := age.ParseHybridRecipient(f.recs["sam/laptop"])
	w, err := age.Encrypt(&buf, r1, r2)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("x"))
	w.Close()
	f.replace(keys, adaSlot, agewrap.EncodeBlob(buf.Bytes()))
	got = want(t, f.check(Options{}), RuleSlotMalformed, Error)
	if !strings.Contains(got.Message, "2 recipient stanzas") {
		t.Fatal(got.Message)
	}
}

func TestSlotNotPQ(t *testing.T) {
	f := newFx(t)
	// lin's laptop slot in prod is wrapped to an X25519 key, then lin's
	// key becomes hybrid and prod requires post-quantum keys.
	f.write(".carbon/people/lin.toml", "[devices]\nlaptop = \""+f.key("lin/laptop", agewrap.KindX25519)+"\"\n")
	o := f.open("app", "prod", "machine:deploy")
	delete(o.Keys.CurrentKey().Slots, "lin/laptop")
	if _, err := o.AddSlots(f.devicesOf("lin/laptop")); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	f.write(".carbon/people/lin.toml", "[devices]\nlaptop = \""+f.key("lin/laptop", agewrap.KindHybrid)+"\"\n")
	f.replace("carbon.toml", `prod = ["@ops", "machine:deploy"]`, `prod = { readers = ["@ops", "machine:deploy"], require_pq = true }`)
	f.commit("require pq")
	rep := f.check(Options{})
	got := want(t, rep, RuleSlotNotPQ, Error)
	if got.Device != "lin/laptop" || got.Scope != "app/prod" {
		t.Fatalf("%+v", got)
	}
	none(t, rep, RuleDeviceNotPQ)
}

func TestDeviceNotPQ(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/machines/deploy.toml", "key = \""+f.key("machine:deploy", agewrap.KindX25519)+"\"\n")
	f.replace("carbon.toml", `prod = ["@ops", "machine:deploy"]`, `prod = { readers = ["@ops", "machine:deploy"], require_pq = true }`)
	f.commit("require pq with a classic machine key")
	rep := f.check(Options{})
	got := want(t, rep, RuleDeviceNotPQ, Error)
	if got.Device != "machine:deploy" {
		t.Fatal(got.Device)
	}
	// It is not also reported as a pending grant.
	for _, g := range rep.ByRule(RuleSlotPendingGrant) {
		if g.Device == "machine:deploy" {
			t.Fatalf("non-hybrid device reported as a pending grant:\n%s", dump(rep))
		}
	}
}

func TestKeyChangedByRotationWithoutRemoval(t *testing.T) {
	f := newFx(t)
	o := f.open("app", "prod", "lin/laptop")
	if _, err := o.Rotate(f.devices("app", "prod"), "just because", now); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	want(t, f.check(Options{}), RuleKeyChanged, Error)
}

func TestKeyChangedAllowedAfterRemoval(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\"]\nops = [\"lin\"]\n")
	f.commit("remove sam from eng")
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.Rotate(f.devices("app", "dev"), "removed sam", now); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	rep := f.check(Options{})
	none(t, rep, RuleKeyChanged)
	none(t, rep, RuleSlotPendingRevocation)
}

func TestKeyChangedInbox(t *testing.T) {
	f := newFx(t)
	o := f.open("app", "dev", "ada/laptop")
	f.replace("svc/app/.carbon/dev.keys.toml", "inbox = \""+o.Keys.CurrentKey().Inbox+"\"", "inbox = \""+f.recs["sam/laptop"]+"\"")
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "inbox") {
		t.Fatal(got.Message)
	}
}

func TestKeyChangedKeysFileDeleted(t *testing.T) {
	f := newFx(t)
	f.git("rm", "-q", "svc/app/.carbon/dev.keys.toml")
	want(t, f.check(Options{}), RuleKeyChanged, Error)
}

func TestKeyBehindTrunk(t *testing.T) {
	f := newFx(t)
	f.git("branch", "old")
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\"]\nops = [\"lin\"]\n")
	f.commit("remove sam")
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.Rotate(f.devices("app", "dev"), "removed sam", now); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	f.commit("apply")
	f.git("checkout", "-q", "old")
	rep := f.check(Options{})
	want(t, rep, RuleKeyBehindTrunk, Info)
	none(t, rep, RuleKeyChanged)
	none(t, rep, RuleSlotUnbacked)
}

func TestDropForbidden(t *testing.T) {
	f := newFx(t)
	f.replace("carbon.toml", `prod = ["@ops", "machine:deploy"]`, `prod = { readers = ["@ops", "machine:deploy"], drops = false }`)
	f.commit("drops off in prod")
	f.drop("app", "prod", "token")
	got := want(t, f.check(Options{}), RuleDropForbidden, Error)
	if got.Secret != "token" {
		t.Fatal(got.Secret)
	}
}

func TestDropPending(t *testing.T) {
	f := newFx(t)
	f.drop("app", "dev", "token")
	rep := f.check(Options{})
	got := want(t, rep, RuleDropPending, Info)
	if got.Secret != "token" || got.Scope != "app/dev" || got.Set == nil {
		t.Fatalf("%+v", got)
	}
	if rep.Failed() {
		t.Fatalf("a drop failed the check:\n%s", dump(rep))
	}
}

// Reader coverage.

func TestAccessCoverage(t *testing.T) {
	f := newFx(t)
	f.addPackage("svc/db", "name = \"db\"\n[access]\nprod = [\"@ops\"]\n[secrets]\npassword = {}\n")
	f.replace("svc/app/carbon.toml", "[env]\n", "[env]\nDB = \"${db.password}\"\n")
	rep := f.check(Options{})
	got := want(t, rep, RuleAccessCoverage, Error)
	if got.Device != "machine:deploy" || got.Scope != "app/prod" || len(rep.ByRule(RuleAccessCoverage)) != 1 {
		t.Fatalf("want only machine:deploy in app/prod:\n%s", dump(rep))
	}
	// Vars need no access.
	f.replace("svc/db/carbon.toml", "[secrets]\npassword = {}\n", "[vars.password]\ndefault = \"x\"\n")
	none(t, f.check(Options{}), RuleAccessCoverage)
}

// Rotation debt.

func TestDebtRemoval(t *testing.T) {
	f := newFx(t)
	removed := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\"]\nops = [\"lin\"]\n")
	f.commit("remove sam")
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.Rotate(f.devices("app", "dev"), "removed sam", removed); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	f.commit("apply")
	rep := f.check(Options{})
	got := want(t, rep, RuleDebtRemoval, Warning)
	if got.Debt == nil || got.Debt.Removed != "sam" || !got.Debt.Since.Equal(removed) || got.Debt.AgeDays != 11 {
		t.Fatalf("%+v", got.Debt)
	}
	// Older than --max-debt: an error.
	got = want(t, f.check(Options{MaxDebt: 10 * 24 * time.Hour}), RuleDebtRemoval, Error)
	if !got.Debt.Overdue {
		t.Fatal("not overdue")
	}
	if f.check(Options{MaxDebt: 14 * 24 * time.Hour}).Failed() {
		t.Fatal("debt younger than --max-debt failed the check")
	}

	// Setting a new value clears it.
	o = f.open("app", "dev", "ada/laptop")
	f.seal(o, "token", now)
	f.save(o.Scope)
	none(t, f.check(Options{}), RuleDebtRemoval)
}

func TestDebtRotateAfter(t *testing.T) {
	f := newFx(t)
	f.replace("svc/app/carbon.toml", `token = { description = "API token" }`, `token = { description = "API token", rotate_after = "10d" }`)
	rep := f.check(Options{})
	got := want(t, rep, RuleDebtRotateAfter, Warning)
	if got.Debt.AgeDays != 5 || !got.Debt.Since.Equal(t0.Add(10*24*time.Hour)) {
		t.Fatalf("%+v", got.Debt)
	}
	want(t, f.check(Options{MaxDebt: 4 * 24 * time.Hour}), RuleDebtRotateAfter, Error)
	none(t, f.check(Options{Now: t0.Add(9 * 24 * time.Hour)}), RuleDebtRotateAfter)
}

// Policy hygiene.

func TestPolicyUnknownReader(t *testing.T) {
	f := newFx(t)
	f.replace("carbon.toml", `dev = ["@eng"]`, `dev = ["@eng", "@ghosts", "machine:nope"]`)
	rep := f.check(Options{})
	want(t, rep, RulePolicyUnknownReader, Error)
	if n := len(rep.ByRule(RulePolicyUnknownReader)); n != 2 {
		t.Fatalf("%d findings:\n%s", n, dump(rep))
	}
}

func TestPolicyUnknownMember(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\", \"sam\", \"zed\"]\nops = [\"lin\"]\n")
	got := want(t, f.check(Options{}), RulePolicyUnknownMember, Warning)
	if !strings.Contains(got.Message, "zed") {
		t.Fatal(got.Message)
	}
}

func TestPolicyNoDevices(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/people/zoe.toml", "name = \"Zoe\"\n[devices]\n")
	want(t, f.check(Options{}), RulePolicyNoDevices, Warning)
}

func TestPolicyTrunkWorktree(t *testing.T) {
	f := newFx(t)
	f.replace("carbon.toml", `trunk = "main"`, `trunk = "worktree"`)
	f.commit("no protected trunk")
	rep := f.check(Options{})
	want(t, rep, RulePolicyTrunkWorktree, Warning)
	none(t, rep, RulePolicyTrunkChanged)
}

func TestPolicyTrunkChanged(t *testing.T) {
	f := newFx(t)
	// A branch points trunk at itself.
	f.git("checkout", "-q", "-b", "mine")
	f.replace("carbon.toml", `trunk = "main"`, `trunk = "mine"`)
	f.commit("I am trunk now")
	got := want(t, f.check(Options{}), RulePolicyTrunkChanged, Error)
	if !strings.Contains(got.Message, `"main"`) {
		t.Fatal(got.Message)
	}
	// Or at a ref that does not exist, to force the bootstrap exception.
	f.replace("carbon.toml", `trunk = "mine"`, `trunk = "nowhere"`)
	want(t, f.check(Options{}), RulePolicyTrunkChanged, Error)
	// Or at another branch whose own file still names main.
	f.git("branch", "other", "main")
	f.replace("carbon.toml", `trunk = "nowhere"`, `trunk = "other"`)
	want(t, f.check(Options{}), RulePolicyTrunkChanged, Error)

	// A change made on trunk itself is fine.
	f.git("checkout", "-q", "-f", "main")
	f.git("branch", "-m", "main", "trunk")
	f.replace("carbon.toml", `trunk = "main"`, `trunk = "trunk"`)
	f.commit("rename trunk")
	none(t, f.check(Options{}), RulePolicyTrunkChanged)
}

// helpers for the tests above

// devicesOf returns the named devices from every scope's policy.
func (f *fx) devicesOf(ids ...string) []policy.Device {
	f.t.Helper()
	var out []policy.Device
	for _, env := range []string{"dev", "prod"} {
		for _, d := range f.devices("app", env) {
			for _, id := range ids {
				if d.ID == id && !hasDevice(out, id) {
					out = append(out, d)
				}
			}
		}
	}
	if len(out) != len(ids) {
		f.t.Fatalf("devices %v not all named in policy", ids)
	}
	return out
}

// drop writes a drop to a scope's working-tree inbox, as a non-reader would.
func (f *fx) drop(pkg, env, name string) {
	f.t.Helper()
	s := f.load(pkg, env)
	inbox, err := scope.TrunkInbox(s.Keys, pkg, env)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := s.Drop(inbox, name, []byte("dropped"), now); err != nil {
		f.t.Fatal(err)
	}
	f.save(s)
}

func hasDevice(ds []policy.Device, id string) bool {
	for _, d := range ds {
		if d.ID == id {
			return true
		}
	}
	return false
}
