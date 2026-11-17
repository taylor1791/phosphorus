package audit

// Regression tests for the adversarial review of `carbon check`: a
// non-reader forging scope keys with public keys only (see forge_test.go),
// and a removed reader using a retired key they kept.

import (
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/store"
)

// removeSam takes sam out of eng on trunk (a merged removal, apply not run).
func removeSam(f *fx) {
	f.write(".carbon/teams.toml", "eng = [\"ada\", \"lin\"]\nops = [\"lin\"]\n")
	f.commit("remove sam")
}

// removeSamAndRotate merges sam's removal and ada's apply of app/dev to
// trunk. It returns the retired key id.
func removeSamAndRotate(t *testing.T, f *fx, at time.Time) string {
	t.Helper()
	removeSam(f)
	o := f.open("app", "dev", "ada/laptop")
	old := o.Keys.Current
	if _, err := o.Rotate(f.devices("app", "dev"), "removed sam", at); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	f.commit("apply")
	return old
}

// rotateDev rotates app/dev in the working tree as ada, like apply.
func rotateDev(t *testing.T, f *fx, reason string, at time.Time) {
	t.Helper()
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.Rotate(f.devices("app", "dev"), reason, at); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
}

func inBanner(t *testing.T, rep *Report, rule string) Finding {
	t.Helper()
	for _, fd := range rep.Findings {
		if fd.Rule == rule && fd.Banner != "" {
			return fd
		}
	}
	t.Fatalf("no banner item %s in:\n%s", rule, dump(rep))
	return Finding{}
}

// Finding 1: naming trunk's retired key as current, with a forged key, on a
// branch that already contains trunk (a rollback).
func TestForgedKeyUnderTrunksRetiredIDOnABranchOfTrunk(t *testing.T) {
	f := newFx(t)
	old := removeSamAndRotate(t, f, t0.Add(time.Hour))
	f.git("checkout", "-q", "-b", "evil")
	s := f.load("app", "dev")
	fg := forge(t, s, old, f.devices("app", "dev"), now)
	fg.sealAs(t, s, "token", "attacker", now)
	f.save(s)
	f.commit("evil")
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "rolled back") {
		t.Fatal(got.Message)
	}
}

// Finding 1: a branch that really is behind trunk, but rewrote its keys file.
func TestBehindBranchWithRewrittenKeysFile(t *testing.T) {
	f := newFx(t)
	f.git("branch", "old")
	old := f.load("app", "dev").Keys.Current
	removeSamAndRotate(t, f, t0.Add(time.Hour))
	f.git("checkout", "-q", "old")
	s := f.load("app", "dev")
	fg := forge(t, s, old, f.devices("app", "dev"), now)
	fg.sealAs(t, s, "token", "attacker", now)
	f.save(s)
	f.commit("evil")
	rep := f.check(Options{})
	got := want(t, rep, RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "changed since this branch's merge base") {
		t.Fatal(got.Message)
	}
	none(t, rep, RuleKeyBehindTrunk)
}

// Finding 1: no merge base to prove the keys file unchanged is never a pass.
func TestBehindBranchWithoutMergeBase(t *testing.T) {
	f := newFx(t)
	f.git("branch", "old")
	removeSamAndRotate(t, f, t0.Add(time.Hour))
	f.git("checkout", "-q", "old")
	f.git("checkout", "-q", "--orphan", "lone")
	f.commit("unrelated history")
	rep := f.check(Options{})
	want(t, rep, RuleKeyUnverified, Error)
	none(t, rep, RuleKeyBehindTrunk)
}

// Finding 1: `git revert` of the apply commit rolls the key back.
func TestRevertOfApplyIsARollback(t *testing.T) {
	f := newFx(t)
	removeSamAndRotate(t, f, t0.Add(time.Hour))
	f.git("checkout", "-q", "-b", "revert")
	f.git("revert", "--no-edit", "HEAD")
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "rolled back") {
		t.Fatal(got.Message)
	}
}

// Finding 2: a removal merged, apply not run: a forged key that does not
// retire trunk's key must not pass.
func TestRotationThatDoesNotRetireTrunksKey(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	f.git("checkout", "-q", "-b", "evil")
	s := f.load("app", "dev")
	fg := forge(t, s, "kevil1", f.devices("app", "dev"), now)
	fg.sealAs(t, s, "token", "attacker", t0)
	f.save(s)
	f.commit("evil")
	rep := f.check(Options{})
	got := want(t, rep, RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "not kept as a retired record") {
		t.Fatal(got.Message)
	}
	b := inBanner(t, rep, RuleKeyRotated)
	if !strings.Contains(b.Banner, "kevil1") {
		t.Fatal(b.Banner)
	}
}

// Finding 2: a legitimate rotation passes, and is still in the banner.
func TestRotationAfterRemovalIsInTheBanner(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	rotateDev(t, f, "removed sam", now)
	rep := f.check(Options{Strict: true})
	none(t, rep, RuleKeyChanged)
	got := inBanner(t, rep, RuleKeyRotated)
	if got.Severity != Info || got.Strict || !strings.Contains(got.Banner, `"removed sam"`) {
		t.Fatalf("%+v", got)
	}
}

func TestRotationWithAnExtraSlot(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	rotateDev(t, f, "removed sam", now)
	o := f.open("app", "dev", "ada/laptop")
	if _, err := o.AddSlots(f.devicesOf("machine:deploy")); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "machine:deploy") {
		t.Fatal(got.Message)
	}
}

func TestRotationThatRedatesAValue(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	rotateDev(t, f, "removed sam", now)
	f.replace("svc/app/.carbon/dev.secrets.toml", "set = 2026-11-01T00:00:00Z", "set = 2026-11-15T00:00:00Z")
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "set time") {
		t.Fatal(got.Message)
	}
}

func TestRotationThatDropsAValue(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	rotateDev(t, f, "removed sam", now)
	f.write("svc/app/.carbon/dev.secrets.toml", "")
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "vanished: token") {
		t.Fatal(got.Message)
	}
}

// Findings 2 and 6: retired records are append-only, and debt uses trunk's.
func TestRetiredRecordEditedToHideDebt(t *testing.T) {
	f := newFx(t)
	removeSamAndRotate(t, f, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	f.replace("svc/app/.carbon/dev.keys.toml", "retired = 2026-11-05T00:00:00Z", "retired = 2026-10-01T00:00:00Z")
	rep := f.check(Options{MaxDebt: 5 * 24 * time.Hour})
	want(t, rep, RuleKeyRetiredChanged, Error)
	got := want(t, rep, RuleDebtRemoval, Error)
	if !got.Debt.Since.Equal(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("debt counted from the edited record: %v", got.Debt.Since)
	}
}

func TestRetiredRecordDeleted(t *testing.T) {
	f := newFx(t)
	old := removeSamAndRotate(t, f, t0.Add(time.Hour))
	s := f.load("app", "dev")
	delete(s.Keys.Keys, old)
	f.save(s)
	rep := f.check(Options{})
	got := want(t, rep, RuleKeyRetiredChanged, Error)
	if !strings.Contains(got.Message, "deleted") {
		t.Fatal(got.Message)
	}
	// Debt is still read from trunk's keys file.
	want(t, rep, RuleDebtRemoval, Warning)
}

// Finding 4: a removed reader replaces a value with one sealed under the
// retired key they kept.
func TestRemovedReaderRollsBackAValue(t *testing.T) {
	f := newFx(t)
	samOld := f.open("app", "dev", "sam/laptop")
	removeSamAndRotate(t, f, t0.Add(48*time.Hour))
	f.git("checkout", "-q", "-b", "evil")
	if err := samOld.Seal("token", []byte("sam-value"), t0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sec := store.NewSecrets()
	sec.Entries["token"] = samOld.Secrets.Entries["token"]
	f.write("svc/app/.carbon/dev.secrets.toml", string(sec.Marshal()))
	rep := f.check(Options{})
	want(t, rep, RuleSecretRolledBack, Error)
	inBanner(t, rep, RuleSecretStaleKey)
}

// Finding 7: an older sealed line restored under the same key.
func TestOlderThanTrunk(t *testing.T) {
	f := newFx(t)
	oldLine := f.read("svc/app/.carbon/prod.secrets.toml")
	o := f.open("app", "prod", "lin/laptop")
	f.seal(o, "token", now)
	f.save(o.Scope)
	f.commit("lin sets token again")
	f.write("svc/app/.carbon/prod.secrets.toml", oldLine)
	rep := f.check(Options{})
	got := want(t, rep, RuleSecretOlderThanTrunk, Warning)
	if got.Banner == "" {
		t.Fatal("not in the banner")
	}
}

// Finding 8: inbox_sealed is compared too, and require_pq covers the inbox.
func TestInboxSealedChanged(t *testing.T) {
	f := newFx(t)
	dev := f.load("app", "dev").Keys.CurrentKey().InboxSealed
	prod := f.load("app", "prod").Keys.CurrentKey().InboxSealed
	f.replace("svc/app/.carbon/dev.keys.toml", dev, prod)
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "inbox") {
		t.Fatal(got.Message)
	}
}

func TestInboxNotPQ(t *testing.T) {
	f := newFx(t)
	inbox := f.load("app", "prod").Keys.CurrentKey().Inbox
	f.replace("carbon.toml", `prod = ["@ops", "machine:deploy"]`, `prod = { readers = ["@ops", "machine:deploy"], require_pq = true }`)
	f.replace("svc/app/.carbon/prod.keys.toml", inbox, f.key("classic", agewrap.KindX25519))
	f.commit("x25519 inbox on trunk")
	want(t, f.check(Options{}), RuleInboxNotPQ, Error)
}

// Finding 5: a new environment's keys on the branch that adds it.
func TestNewEnvironmentKeys(t *testing.T) {
	f := newFx(t)
	f.git("checkout", "-q", "-b", "evil")
	f.replace("carbon.toml", `environments = ["dev", "prod"]`, `environments = ["dev", "prod", "qa"]`)
	f.replace("carbon.toml", "[access]\n", "[access]\nqa = [\"@eng\"]\n")
	o := f.create("app", "qa")
	f.seal(o, "token", now)
	f.save(o.Scope)
	rep := f.check(Options{})
	inBanner(t, rep, RuleKeyNew)
	got := want(t, rep, RuleSlotUnbacked, Error)
	if !strings.Contains(got.Message, "before its policy merges") {
		t.Fatal(got.Message)
	}
}

// Finding 5: dropping an environment while keeping (forged) keys for it,
// then re-adding it, the reviewer's two-pull-request trick.
func TestEnvironmentRemovedThenReadded(t *testing.T) {
	f := newFx(t)
	f.git("checkout", "-q", "-b", "pr1")
	s := f.load("app", "prod")
	fg := forge(t, s, "kevil1", f.devices("app", "prod"), now)
	fg.sealAs(t, s, "token", "x", now)
	f.save(s)
	f.replace("carbon.toml", `environments = ["dev", "prod"]`, `environments = ["dev"]`)
	f.replace("carbon.toml", "prod = [\"@ops\", \"machine:deploy\"]\n", "")
	f.commit("pr1")
	want(t, f.check(Options{}), RuleKeyRemoved, Error)

	// Removing the scope deliberately: delete its files in the same change.
	f.git("rm", "-q", "svc/app/.carbon/prod.keys.toml", "svc/app/.carbon/prod.secrets.toml")
	f.commit("pr1: delete prod's files")
	rep := f.check(Options{})
	none(t, rep, RuleKeyRemoved)
	inBanner(t, rep, RuleScopeRemoved)

	// Merged; then a second change re-adds prod with keys.
	f.git("checkout", "-q", "main")
	f.git("merge", "-q", "--no-edit", "pr1")
	f.git("checkout", "-q", "-b", "pr2")
	f.write("carbon.toml", workspaceTOML)
	s = f.load("app", "prod")
	fg = forge(t, s, "kevil2", f.devices("app", "prod"), now)
	fg.sealAs(t, s, "token", "x", now)
	f.save(s)
	f.commit("pr2")
	rep = f.check(Options{})
	want(t, rep, RuleSlotUnbacked, Error)
	inBanner(t, rep, RuleKeyNew)
}

func TestStoreOrphan(t *testing.T) {
	f := newFx(t)
	f.write("svc/gone/.carbon/dev.keys.toml", f.read("svc/app/.carbon/dev.keys.toml"))
	f.write("svc/app/.carbon/qa.secrets.toml", "")
	rep := f.check(Options{})
	got := rep.ByRule(RuleStoreOrphan)
	if len(got) != 2 {
		t.Fatalf("want 2 orphans:\n%s", dump(rep))
	}
}

func TestSlotGranted(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/people/ada.toml", f.read(".carbon/people/ada.toml")+"desk = \""+f.key("ada/desk", agewrap.KindHybrid)+"\"\n")
	f.commit("ada adds a desk")
	o := f.open("app", "dev", "lin/laptop")
	if _, err := o.AddSlots(f.devicesOf("ada/desk")); err != nil {
		t.Fatal(err)
	}
	f.save(o.Scope)
	got := inBanner(t, f.check(Options{Strict: true}), RuleSlotGranted)
	if got.Device != "ada/desk" || got.Severity != Info {
		t.Fatalf("%+v", got)
	}
}

// Finding 10: tests the review found too weak.

func TestDropsOffOnTrunkCannotBeTurnedBackOnByABranch(t *testing.T) {
	f := newFx(t)
	f.replace("carbon.toml", `prod = ["@ops", "machine:deploy"]`, `prod = { readers = ["@ops", "machine:deploy"], drops = false }`)
	f.commit("drops off in prod")
	f.git("checkout", "-q", "-b", "evil")
	f.replace("carbon.toml", `drops = false`, `drops = true`)
	f.drop("app", "prod", "token")
	want(t, f.check(Options{}), RuleDropForbidden, Error)
}

func TestDebtFromTheEarliestRemoval(t *testing.T) {
	f := newFx(t)
	first := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	removeSamAndRotate(t, f, first)
	f.write(".carbon/teams.toml", "eng = [\"ada\"]\nops = [\"lin\"]\n")
	f.commit("remove lin from eng")
	rotateDev(t, f, "removed lin", time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC))
	f.commit("apply")
	got := want(t, f.check(Options{}), RuleDebtRemoval, Warning)
	if !got.Debt.Since.Equal(first) || got.Debt.Removed != "sam" {
		t.Fatalf("%+v", got.Debt)
	}
}

func TestSlotWithZeroStanzas(t *testing.T) {
	f := newFx(t)
	slot := f.load("app", "dev").Keys.CurrentKey().Slots["ada/laptop"]
	empty := agewrap.EncodeBlob([]byte("age-encryption.org/v1\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n0123456789abcdef"))
	f.replace("svc/app/.carbon/dev.keys.toml", slot, empty)
	got := want(t, f.check(Options{}), RuleSlotMalformed, Error)
	if got.Device != "ada/laptop" {
		t.Fatal(got.Device)
	}
}
