package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

// umGet reads a secret as p and returns its value and set time.
func umGet(t *testing.T, p *clitest.Person, pkg, env, name string) (string, string) {
	t.Helper()
	res := p.Must("get", name, "--package", pkg, "--env", env, "--json")
	var v struct {
		Value string `json:"value"`
		Set   string `json:"set"`
		Drop  bool   `json:"drop"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &v); err != nil {
		t.Fatalf("get --json: %v\n%s", err, res)
	}
	return v.Value, v.Set
}

func umHead(w *clitest.World) string { return w.Git("rev-parse", "HEAD") }

func umClean(t *testing.T, w *clitest.World) {
	t.Helper()
	if st := w.Git("status", "--porcelain"); st != "" {
		t.Fatalf("working tree changed:\n%s", st)
	}
}

// umSetAll seals one value in every environment of checkout, as lin (who
// reads them all), and commits.
func umSetAll(t *testing.T, w *clitest.World) {
	t.Helper()
	for _, env := range []string{"dev", "staging", "prod"} {
		w.Lin.In(w.PkgDir).Stdin("sk_"+env).Must("set", "stripe_api_key", "--env", env)
	}
	w.Commit("checkout secrets")
}

func TestApplyOnboardingDrill(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	umSetAll(t, w)

	// A new person joins on a branch and requests prod.
	nia := w.Person("nia")
	w.Branch("onboard-nia")
	join := nia.Join()
	fp := regexp.MustCompile(`Fingerprint\s+(\S+)`).FindStringSubmatch(join.Stdout)[1]
	res := nia.In(co).Must("request", "checkout", "--env", "prod", "--yes")
	contains(t, "request", res.Stdout, "nia", "pull request", "carbon apply")
	contains(t, "package file", w.Read(co+"/carbon.toml"),
		`prod = ["@payments", "machine:deploy-checkout", "nia"]`, "[secrets]\nsession_key    = {")
	// Requesting again changes nothing.
	res = nia.In(co).Must("request", "checkout", "--env", "prod", "--yes")
	contains(t, "request again", res.Stdout, "already reads")
	w.Commit("nia joins and requests checkout/prod")

	// Before the merge, apply grants nothing: policy on a branch is ignored.
	head := umHead(w)
	res = w.Lin.Must("apply", "--yes")
	contains(t, "apply on branch", res.Stdout, "Nothing to do")
	if strings.Contains(res.Stdout, "nia") || umHead(w) != head {
		t.Fatalf("apply on the branch granted from branch policy:\n%s", res)
	}
	umClean(t, w)

	w.Checkout("main")
	w.Merge("onboard-nia")

	// A non-reader running apply gets a report naming who can finish, and
	// changes nothing.
	head = umHead(w)
	res = nia.Fails(3, "apply", "--yes")
	contains(t, "non-reader apply", res.Stdout, "checkout/prod", "needs a reader", "nia/laptop", fp,
		"lin (laptop)", "machine:deploy-checkout")
	contains(t, "non-reader apply", res.Stderr, "carbon apply")
	if umHead(w) != head {
		t.Fatal("non-reader apply committed")
	}
	umClean(t, w)
	res = nia.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
	contains(t, "get before apply", res.Stderr, "has no slot yet", "carbon apply")

	// A current reader applies: the plan names nia's device and fingerprint.
	res = w.Lin.Must("apply", "--yes")
	contains(t, "apply", res.Stdout, "checkout/prod", "gains access", "nia/laptop", fp, "via nia", "Committed")
	files := w.Git("show", "--name-only", "--format=", "HEAD")
	if files != co+"/.carbon/prod.keys.toml" {
		t.Fatalf("apply committed %q", files)
	}
	contains(t, "commit message", w.Git("log", "-1", "--format=%B"), "carbon apply: grant 1", "checkout/prod: grant nia/laptop")
	umClean(t, w)

	if v, _ := umGet(t, nia, "checkout", "prod", "stripe_api_key"); v != "sk_prod" {
		t.Fatalf("nia reads %q", v)
	}

	// Idempotent.
	head = umHead(w)
	res = w.Lin.Must("apply", "--yes")
	contains(t, "second apply", res.Stdout, "Nothing to do")
	if umHead(w) != head {
		t.Fatal("second apply committed")
	}
	res = w.Lin.Must("apply", "--json")
	var plan struct {
		NothingToDo bool `json:"nothing_to_do"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &plan); err != nil || !plan.NothingToDo {
		t.Fatalf("json: %v\n%s", err, res)
	}
}

func TestApplyIgnoresBranchPolicyAdversarially(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	umSetAll(t, w)
	prodKeys := w.Read(co + "/.carbon/prod.keys.toml")

	// mallory pushes a branch that adds herself everywhere, opts the branch
	// out of trunk, and swaps lin's public key for her own.
	mal := w.Person("mallory")
	w.Branch("evil")
	mal.Join()
	malKey := regexp.MustCompile(`laptop = "(age1[^"]+)"`).FindStringSubmatch(w.Read(".carbon/people/mallory.toml"))[1]
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam", "mallory"}, "payments": {"lin", "mallory"}})
	w.Replace(co+"/carbon.toml", `"machine:deploy-checkout"]`, `"machine:deploy-checkout", "mallory"]`)
	linFile := w.Read(".carbon/people/lin.toml")
	w.Write(".carbon/people/lin.toml", regexp.MustCompile(`"age1[^"]+"`).ReplaceAllString(linFile, `"`+malKey+`"`))
	w.Commit("totally innocent")

	// lin (and the deploy machine) run apply on the branch: nothing is
	// granted, because trunk's policy is what counts.
	for _, p := range []*clitest.Person{w.Lin, w.Deploy} {
		res := p.Must("apply", "--yes")
		contains(t, "apply on evil branch", res.Stdout, "Policy from refs/heads/main at ", "Nothing to do")
	}
	unchanged := func() {
		t.Helper()
		if w.Read(co+"/.carbon/prod.keys.toml") != prodKeys {
			t.Fatal("keys changed")
		}
		umClean(t, w)
		mal.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
		mal.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	}
	unchanged()

	// A drop on this branch still goes to trunk's inbox: mallory cannot
	// redirect it, and lin reads it.
	mal.In(co).Stdin("dropped").Must("set", "webhook_secret", "--env", "prod")
	if v, _ := umGet(t, w.Lin, "checkout", "prod", "webhook_secret"); v != "dropped" {
		t.Fatal(v)
	}
	mal.Fails(3, "get", "webhook_secret", "--package", "checkout", "--env", "prod")
	w.Git("checkout", "--", co)

	// There is no trunk setting a branch could edit: the old one is an
	// error, not an opt-out.
	w.Replace("carbon.toml", "[workspace]\n", "[workspace]\ntrunk = \"worktree\"\n")
	w.Commit("opt out of trunk")
	res := w.Lin.Fails(1, "apply", "--yes")
	contains(t, "trunk setting", res.Stderr, "[workspace] trunk")
	w.Replace("carbon.toml", "trunk = \"worktree\"\n", "")
	w.Commit("undo")
	unchanged()

	// mallory replaces the prod keys file with a key she made, wrapped to
	// herself and to lin's real public key, holding a value of her choosing.
	// lin can open it, but it does not descend from trunk's key: apply
	// refuses the scope and get refuses to read it.
	devOf := func(id, file string) policy.Device {
		rec := regexp.MustCompile(`laptop = "(age1[^"]+)"`).FindStringSubmatch(file)[1]
		return policy.Device{ID: id, Recipient: rec, Kind: agewrap.RecipientKind(rec)}
	}
	forged, err := scope.Load(t.TempDir(), "checkout", "prod")
	if err != nil {
		t.Fatal(err)
	}
	fo, err := forged.Create([]policy.Device{
		devOf("lin/laptop", w.Git("show", "main:.carbon/people/lin.toml")),
		devOf("mallory/laptop", w.Read(".carbon/people/mallory.toml")),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fo.Seal("stripe_api_key", []byte("sk_mallory"), time.Now()); err != nil {
		t.Fatal(err)
	}
	w.Write(co+"/.carbon/prod.keys.toml", string(forged.Keys.Marshal()))
	w.Write(co+"/.carbon/prod.secrets.toml", string(forged.Secrets.Marshal()))
	w.Commit("rotate prod")
	forgedKeys := w.Read(co + "/.carbon/prod.keys.toml")
	res = w.Lin.Fails(1, "apply", "--yes", "--env", "prod")
	contains(t, "forged key", res.Stdout, "checkout/prod", "refused", "does not descend from trunk", "git checkout refs/heads/main -- "+co+"/.carbon/prod.keys.toml")
	if w.Read(co+"/.carbon/prod.keys.toml") != forgedKeys {
		t.Fatal("apply touched a refused scope")
	}
	umClean(t, w)
	res = w.Lin.Fails(1, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
	contains(t, "get forged", res.Stderr, "does not descend from trunk")
	if strings.Contains(res.Stdout, "sk_mallory") {
		t.Fatal("read a forged value")
	}
}

func TestApplyOffboardingDrill(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_dev").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev key")
	w.Ada.In(co).Stdin("wh_dev").Must("set", "webhook_secret", "--env", "dev")
	w.Lin.In(co).Stdin("sk_prod").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("secrets")
	// staging gets a key but no values yet: apply creates it.
	res := w.Lin.Must("apply", "--yes", "--env", "staging")
	contains(t, "create", res.Stdout, "create key", "sam/laptop")
	_, devSet := umGet(t, w.Ada, "checkout", "dev", "stripe_api_key")
	_, whSet := umGet(t, w.Lin, "checkout", "dev", "webhook_secret")

	// Branches cut before the rotation set new secrets.
	w.Branch("old-dev")
	w.Ada.In(co).Stdin("sess_dev").Must("set", "session_key", "--env", "dev")
	w.Commit("old branch sets session_key in dev")
	w.Checkout("main")
	w.Branch("old-staging")
	w.Ada.In(co).Stdin("sess_staging").Must("set", "session_key", "--env", "staging")
	w.Commit("old branch sets session_key in staging")
	w.Checkout("main")

	// Remove sam: plan, rotating scopes, and the debt.
	res = w.Ada.Must("remove", "sam", "--yes")
	contains(t, "remove", res.Stdout, ".carbon/people/sam.toml", "remove from @engineering",
		"checkout/dev", "checkout/staging", "stripe_api_key", "webhook_secret")
	if strings.Contains(res.Stdout, "checkout/prod") {
		t.Fatalf("prod listed though sam never read it:\n%s", res)
	}
	contains(t, "teams", w.Read(".carbon/teams.toml"), `engineering = ["ada", "lin"]`)
	if w.Read(".carbon/people/sam.toml") != "" {
		t.Fatal("person file kept")
	}
	w.Commit("remove sam")

	res = w.Lin.Must("apply", "--yes")
	contains(t, "apply", res.Stdout, "checkout/dev", "loses access", "sam/laptop", `reason "removed sam"`, "rotates")
	if strings.Contains(res.Stdout+res.Stderr+w.Git("log", "-1", "--format=%B"), "sk_dev") {
		t.Fatalf("a value leaked into output:\n%s", res)
	}
	contains(t, "keys", w.Read(co+"/.carbon/dev.keys.toml"), `reason = "removed sam"`, "retired = ")
	umClean(t, w)

	// sam's old identity cannot open the new key; the others can, and
	// every value is unchanged, with the same set time.
	w.Sam.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	for _, p := range []*clitest.Person{w.Ada, w.Lin} {
		if v, s := umGet(t, p, "checkout", "dev", "stripe_api_key"); v != "sk_dev" || s != devSet {
			t.Fatalf("%s: %q %s (want %s)", p.Name, v, s, devSet)
		}
		if v, s := umGet(t, p, "checkout", "dev", "webhook_secret"); v != "wh_dev" || s != whSet {
			t.Fatalf("%s: %q %s", p.Name, v, s)
		}
	}
	if v, _ := umGet(t, w.Lin, "checkout", "prod", "stripe_api_key"); v != "sk_prod" {
		t.Fatal(v)
	}
	w.Lin.Must("apply", "--yes") // idempotent
	contains(t, "after", w.Lin.Must("apply").Stdout, "Nothing to do")

	// A branch cut before the rotation merges and still reads: in staging
	// the rotation changed only the keys file, so git merges it cleanly.
	w.Merge("old-staging")
	if v, _ := umGet(t, w.Ada, "checkout", "staging", "session_key"); v != "sess_staging" {
		t.Fatal(v)
	}
	// sam, removed but still holding the old key, writes on the old branch
	// after the rotation: a value under a retired key, set after it retired.
	w.Checkout("old-dev")
	time.Sleep(1100 * time.Millisecond)
	// `set` refuses him now, so seal through the library, as a modified
	// client would.
	umSealAs(t, w, w.Sam, co, "dev", "session_key", "sess_from_sam")
	w.Commit("sam sets session_key after his removal")
	w.Checkout("main")

	// In dev every value line was re-sealed, so the branch's new line
	// conflicts (a known merge limit). carbon names the resolution; keeping
	// main's lines plus the branch's new line resolves it.
	dev := co + "/.carbon/dev.secrets.toml"
	mainDev := w.Read(dev)
	if _, err := tryGit(w, "merge", "-q", "--no-edit", "old-dev"); err == nil {
		t.Fatal("expected the known conflict between a rotation and an added secret")
	}
	res = w.Lin.Fails(1, "get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	contains(t, "conflict hint", res.Stderr, "keep the rotated side's lines", "add back each line the other side added")
	branchLine := regexp.MustCompile(`(?m)^session_key .*$`).FindString(w.Git("show", "old-dev:"+dev))
	w.Write(dev, branchLine+"\n"+mainDev)
	w.Git("add", dev)
	w.Git("commit", "-q", "--no-edit")
	if v, _ := umGet(t, w.Ada, "checkout", "dev", "session_key"); v != "sess_from_sam" {
		t.Fatal(v)
	}

	// The plan lists it as unproven, flagged as set after its key retired.
	// --yes does not vouch for it: it is listed and left alone.
	head := umHead(w)
	res = w.Lin.Must("apply", "--yes", "--env", "dev")
	contains(t, "unproven", res.Stdout, "leaves unproven", "session_key",
		"set after its key was retired (advisory: a forger can back-date)", "--reseal-unproven")
	if umHead(w) != head || !strings.Contains(w.Read(dev), "session_key = { key = \"") {
		t.Fatal("--yes re-sealed an unproven value")
	}
	res = w.Lin.Must("apply", "--reseal-unproven", "--dry-run", "--env", "dev")
	contains(t, "reseal plan", res.Stdout, "re-seals as trusted", "session_key")
	// Asking for it explicitly re-seals it under the current key.
	res = w.Lin.Must("apply", "--yes", "--reseal-unproven")
	contains(t, "re-seal", res.Stdout, "re-seals as trusted", "session_key", "Committed")
	contains(t, "after re-seal", w.Lin.Must("apply").Stdout, "Nothing to do")
	if strings.Contains(w.Lin.Must("apply").Stdout, "unproven") {
		t.Fatal("still unproven")
	}
	if v, _ := umGet(t, w.Lin, "checkout", "dev", "session_key"); v != "sess_from_sam" {
		t.Fatal(v)
	}
}

func TestApplyCreatesOnlyAsANamedDevice(t *testing.T) {
	w := clitest.Standard(t)
	// Nobody has set anything: every scope waits for its first key. ada
	// reads dev and staging but not prod.
	res := w.Ada.Fails(3, "apply", "--yes", "--env", "prod")
	contains(t, "ada", res.Stdout, "checkout/prod", "needs a reader", "may create its key", "lin (laptop)", "machine:deploy-checkout")
	umClean(t, w)
	res = w.Ada.Must("apply", "--yes", "--env", "dev")
	contains(t, "ada dev", res.Stdout, "create key", "Committed")
	res = w.Deploy.Must("apply", "--yes", "--env", "prod")
	contains(t, "machine prod", res.Stdout, "create key", "lin/laptop")
	if v := w.Read(w.PkgDir + "/.carbon/prod.keys.toml"); !strings.Contains(v, `"lin/laptop"`) {
		t.Fatal(v)
	}
}

// tryGit runs git in the repo and returns its error instead of failing.
func tryGit(w *clitest.World, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = w.Dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + w.Dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_AUTHOR_NAME=carbon test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=carbon test", "GIT_COMMITTER_EMAIL=test@example.com", "LC_ALL=C", "TZ=UTC"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestApplyRemoveOneDevice(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	desk := w.Person("ada-desk")
	desk.Must("join", "--person", "ada", "--device", "desk")
	w.Commit("ada's desk")
	w.Lin.In(co).Stdin("sk_dev").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev")
	_, set := umGet(t, w.Ada, "checkout", "dev", "stripe_api_key")
	umGet(t, desk, "checkout", "dev", "stripe_api_key")

	res := w.Lin.Must("remove", "ada/laptop", "--yes")
	contains(t, "remove device", res.Stdout, ".carbon/people/ada.toml", "delete device laptop", "checkout/dev", "stripe_api_key")
	if strings.Contains(w.Read(".carbon/people/ada.toml"), "laptop") {
		t.Fatal("device kept")
	}
	contains(t, "teams untouched", w.Read(".carbon/teams.toml"), `"ada"`)
	w.Commit("remove ada/laptop")
	res = w.Lin.Must("apply", "--yes")
	contains(t, "apply", res.Stdout, `reason "removed ada/laptop"`)
	w.Ada.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "dev")
	if v, s := umGet(t, desk, "checkout", "dev", "stripe_api_key"); v != "sk_dev" || s != set {
		t.Fatal(v, s)
	}

	// The only device left cannot be removed alone.
	res = w.Lin.Fails(2, "remove", "ada/desk", "--yes")
	contains(t, "last device", res.Stderr, "carbon remove ada")
	w.Lin.Fails(5, "remove", "nobody", "--yes")
	w.Lin.Fails(7, "remove", "sam")
}

func TestApplyDropDrill(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")

	// ada cannot read prod: her set is a drop, readable by lin at once.
	res := w.Ada.In(co).Stdin("whsec_1").Must("set", "webhook_secret", "--env", "prod")
	contains(t, "drop", res.Stdout, "Dropped")
	w.Commit("ada drops webhook_secret")
	v, set := umGet(t, w.Lin, "checkout", "prod", "webhook_secret")
	if v != "whsec_1" {
		t.Fatal(v)
	}
	w.Ada.Fails(3, "get", "webhook_secret", "--package", "checkout", "--env", "prod")

	// ada's apply cannot promote it; lin's does, keeping the set time.
	res = w.Ada.Fails(3, "apply", "--yes", "--package", "checkout", "--env", "prod")
	contains(t, "ada apply", res.Stdout, "promotes drop", "webhook_secret", "lin (laptop)")
	res = w.Lin.Must("apply", "--yes", "--env", "prod")
	contains(t, "apply", res.Stdout, "promotes drop", "webhook_secret", "Committed")
	contains(t, "secrets", w.Read(co+"/.carbon/prod.secrets.toml"), "webhook_secret = { key = ")
	if strings.Contains(w.Read(co+"/.carbon/prod.secrets.toml"), "drop =") {
		t.Fatal("still a drop")
	}
	res = w.Lin.Must("get", "webhook_secret", "--package", "checkout", "--env", "prod", "--json")
	contains(t, "promoted", res.Stdout, `"drop": false`, `"set": "`+set+`"`, `"value": "whsec_1"`)
	if w.Git("show", "--name-only", "--format=", "HEAD") != co+"/.carbon/prod.secrets.toml" {
		t.Fatal(w.Git("show", "--name-only", "--format=", "HEAD"))
	}
}

func TestApplyCommitsExactlyItsFiles(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")
	w.Ada.In(co).Stdin("whsec_1").Must("set", "webhook_secret", "--env", "prod")
	w.Commit("drop") // apply promotes only drops trunk has
	w.Lin.In(co).Stdin("sk_2").Must("set", "stripe_api_key", "--env", "prod")

	// A value set but not committed: apply would sweep it in, so it refuses.
	res := w.Lin.Fails(1, "apply", "--yes", "--env", "prod")
	contains(t, "dirty", res.Stderr, "uncommitted changes", "prod.secrets.toml", "--no-commit")
	// --no-commit writes and leaves the files unstaged.
	head := umHead(w)
	w.Lin.Must("apply", "--yes", "--no-commit", "--env", "prod")
	if umHead(w) != head {
		t.Fatal("--no-commit committed")
	}
	contains(t, "status", w.Git("status", "--porcelain"), "M "+co+"/.carbon/prod.secrets.toml")
	w.Commit("promoted by hand")

	// Unrelated staged and unstaged changes stay out of apply's commit.
	nia := w.Person("nia")
	nia.Join()
	w.Replace(co+"/carbon.toml", `"machine:deploy-checkout"]`, `"machine:deploy-checkout", "nia"]`)
	w.Commit("nia reads prod")
	w.Write("README", "staged\n")
	w.Git("add", "README")
	w.Write("notes.txt", "untracked\n")
	w.Write(co+"/carbon.toml", w.Read(co+"/carbon.toml")+"# unstaged edit\n")

	res = w.Lin.Must("apply", "--yes", "--env", "prod")
	if got := w.Git("show", "--name-only", "--format=", "HEAD"); got != co+"/.carbon/prod.keys.toml" {
		t.Fatalf("committed %q", got)
	}
	st := w.Git("status", "--porcelain")
	contains(t, "status", st, "A  README", "?? notes.txt", "M "+co+"/carbon.toml")
}

func TestApplyByMachineIdentity(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	nia := w.Person("nia")
	nia.Join()
	w.Replace(co+"/carbon.toml", `"machine:deploy-checkout"]`, `"machine:deploy-checkout", "nia"]`)
	w.Commit("nia reads prod")

	res := w.Deploy.Must("apply", "--yes", "--env", "prod")
	contains(t, "machine apply", res.Stdout, "nia/laptop", "Committed")
	if v, _ := umGet(t, nia, "checkout", "prod", "stripe_api_key"); v != "sk_1" {
		t.Fatal(v)
	}
}

func TestApplyRequirePQ(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	old := w.Person("old")
	old.Join("--x25519")
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`,
		`prod = { readers = ["@payments", "machine:deploy-checkout", "old"], require_pq = true }`)
	w.Commit("old reads prod, but prod requires post-quantum keys")
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod")

	res := w.Lin.Must("apply", "--yes", "--env", "prod")
	contains(t, "pq", res.Stdout, "Nothing to do", "not wrapped", "old/laptop", "post-quantum")
	if strings.Contains(w.Read(co+"/.carbon/prod.keys.toml"), "old/laptop") {
		t.Fatal("wrapped to an X25519 key under require_pq")
	}
}

func TestApplyStopsWhenKeysAreOutOfStep(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_dev").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("dev")
	w.Branch("behind")
	w.Checkout("main")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")

	// The branch has the old key; trunk rotated. apply must not rotate on
	// top of a key trunk no longer uses.
	w.Checkout("behind")
	keys := w.Read(co + "/.carbon/dev.keys.toml")
	res := w.Lin.Fails(1, "apply", "--yes")
	contains(t, "out of step", res.Stdout, "checkout/dev", "blocked", "differs from trunk", "git merge refs/heads/main")
	if w.Read(co+"/.carbon/dev.keys.toml") != keys {
		t.Fatal("keys changed")
	}
	w.Merge("main")
	contains(t, "after merge", w.Lin.Must("apply", "--env", "dev").Stdout, "Nothing to do")
}

func TestApplyTwoBranchesGrantDifferentPeople(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod")
	base := umHead(w)

	// Two policy changes from the same base: one names abe, the other nia.
	// (Each apply below sees a trunk that names only one of them, as when
	// two readers apply from different fetches of trunk.)
	abe, nia := w.Person("abe"), w.Person("nia")
	w.Branch("policy-abe")
	abe.Join()
	w.Replace(co+"/carbon.toml", `"machine:deploy-checkout"]`, `"machine:deploy-checkout", "abe"]`)
	w.Commit("abe")
	w.Git("checkout", "-q", "-b", "policy-nia", base)
	nia.Join()
	w.Replace(co+"/carbon.toml", `["@payments",`, `["nia", "@payments",`)
	w.Commit("nia")

	w.Git("checkout", "-q", "-B", "main", "policy-abe")
	w.Branch("grant-abe")
	w.Lin.Must("apply", "--yes", "--env", "prod")
	w.Git("checkout", "-q", "-B", "main", "policy-nia")
	w.Branch("grant-nia")
	w.Lin.Must("apply", "--yes", "--env", "prod")

	// Trunk gets both policies, then both grant branches: different slot
	// lines, so git merges them.
	w.Git("checkout", "-q", "-B", "main", base)
	w.Merge("policy-abe")
	// policy-nia touched the same access line; resolve by naming both.
	if _, err := tryGit(w, "merge", "-q", "--no-edit", "policy-nia"); err != nil {
		w.Git("checkout", "--theirs", ".carbon/people/nia.toml")
		w.Write(co+"/carbon.toml", strings.Replace(w.Git("show", "policy-abe:"+co+"/carbon.toml"),
			`["@payments",`, `["nia", "@payments",`, 1))
		w.Git("add", "-A")
		w.Git("commit", "-q", "--no-edit")
	}
	w.Merge("grant-abe")
	w.Merge("grant-nia")
	keys := w.Read(co + "/.carbon/prod.keys.toml")
	contains(t, "keys", keys, `"abe/laptop"`, `"nia/laptop"`)
	for _, p := range []*clitest.Person{abe, nia, w.Lin} {
		if v, _ := umGet(t, p, "checkout", "prod", "stripe_api_key"); v != "sk_1" {
			t.Fatal(p.Name, v)
		}
	}
	contains(t, "after", w.Lin.Must("apply", "--env", "prod").Stdout, "Nothing to do")
}

func TestRequest(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	// Comments and layout survive; dev has no package entry, so it starts
	// from the workspace default.
	w.Replace(co+"/carbon.toml", "[access]\n", "# Who reads checkout.\n[access]   # reviewed by @payments\n")
	w.Commit("comments")
	res := w.Ada.In(co).Must("request", "checkout", "--env", "staging", "--as", "machine:deploy-checkout", "--yes")
	contains(t, "request", res.Stdout, "workspace default", "@engineering, machine:deploy-checkout")
	contains(t, "file", w.Read(co+"/carbon.toml"),
		"# Who reads checkout.\n[access]   # reviewed by @payments\nprod = [\"@payments\", \"machine:deploy-checkout\"]\nstaging = [\"@engineering\", \"machine:deploy-checkout\"]\n\n[secrets]")

	// Long form.
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`,
		"prod = { readers = [\n  \"@payments\",\n  \"machine:deploy-checkout\", # deploys\n], drops = false }")
	res = w.Ada.In(co).Must("request", "checkout", "--env", "prod", "--yes", "--json")
	var r struct {
		Reader string   `json:"reader"`
		After  []string `json:"readers_after"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil || r.Reader != "ada" || len(r.After) != 3 {
		t.Fatalf("%v %+v", err, r)
	}
	contains(t, "long form", w.Read(co+"/carbon.toml"),
		"prod = { readers = [\n  \"@payments\",\n  \"machine:deploy-checkout\", # deploys\n  \"ada\",\n], drops = false }")

	// Errors.
	w.Ada.Fails(5, "request", "nope", "--yes")
	w.Ada.Fails(5, "request", "checkout", "--as", "@nope", "--yes")
	w.Ada.Fails(2, "request", "checkout", "--as", "Bad!", "--yes")
	w.Anyone().Fails(6, "request", "checkout", "--env", "dev", "--yes")
	w.Lin.Fails(7, "request", "checkout", "--env", "dev", "--as", "machine:deploy-checkout")
	// lin already reads dev through @engineering.
	contains(t, "already", w.Lin.Must("request", "checkout", "--env", "dev").Stdout, "already reads", "via @engineering")

	// A shape the editor will not touch: it says what to do by hand and
	// leaves the file alone.
	w.Write(co+"/carbon.toml", "name = \"checkout\"\naccess = { prod = [\"@payments\"] }\n[secrets]\nx = {}\n")
	before := w.Read(co + "/carbon.toml")
	res = w.Sam.Fails(1, "request", "checkout", "--env", "dev", "--as", "machine:deploy-checkout", "--yes")
	contains(t, "unsafe", res.Stderr, "cannot edit", "by hand", `dev = ["@engineering", "machine:deploy-checkout"]`)
	if w.Read(co+"/carbon.toml") != before {
		t.Fatal("file changed")
	}
}

func TestRemoveMachineAndAccessEntries(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Replace("carbon.toml", `prod = ["@engineering"]`, "prod = [\n  \"@engineering\",\n  \"sam\",   # on call\n]")
	w.Commit("sam on call")
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod")

	res := w.Lin.Must("remove", "machine:deploy-checkout", "--yes", "--json")
	var r struct {
		Rotate []string `json:"rotate"`
		Debt   []struct {
			Scope, Secret string
		} `json:"debt"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil || len(r.Rotate) != 1 || r.Rotate[0] != "checkout/prod" || r.Debt[0].Secret != "stripe_api_key" {
		t.Fatalf("%v %+v\n%s", err, r, res)
	}
	contains(t, "package", w.Read(co+"/carbon.toml"), `prod = ["@payments"]`)
	if w.Read(".carbon/machines/deploy-checkout.toml") != "" {
		t.Fatal("machine file kept")
	}

	w.Lin.Must("remove", "sam", "--yes")
	contains(t, "workspace", w.Read("carbon.toml"), "prod = [\n  \"@engineering\",\n]")
	w.Commit("remove")
	res = w.Lin.Must("apply", "--yes")
	contains(t, "apply", res.Stdout, `reason "removed machine:deploy-checkout"`)
	w.Deploy.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
}

func TestRename(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.AddPackage("services/web", "web", "[env]\nKEY = \"${checkout.stripe_api_key}\"\nLIT = \"$${checkout.x} ${checkout.session_key}\"\nOWN = \"${env:HOME}\"\n")
	w.Lin.In(co).Stdin("sk_dev").Must("set", "stripe_api_key", "--env", "dev")
	w.Lin.In(co).Stdin("sk_prod").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("prod key")
	w.Ada.In(co).Stdin("wh_prod").Must("set", "webhook_secret", "--env", "prod") // a drop
	w.Commit("values")
	_, set := umGet(t, w.Lin, "checkout", "prod", "stripe_api_key")

	// ada cannot read prod, so she cannot rename.
	res := w.Ada.Fails(3, "rename", "checkout", "shop", "--yes")
	contains(t, "non-reader", res.Stderr, "cannot rename checkout")
	w.Lin.Fails(2, "rename", "checkout", "env", "--yes")
	w.Lin.Fails(2, "rename", "checkout", "web", "--yes")

	w.Branch("rename")
	res = w.Lin.Must("rename", "checkout", "shop", "--yes")
	w.Commit("rename checkout to shop")
	contains(t, "rename", res.Stdout, "Renamed checkout to shop")
	if strings.Contains(res.Stdout+res.Stderr, "sk_") || strings.Contains(res.Stdout+res.Stderr, "wh_prod") {
		t.Fatalf("a value leaked into output:\n%s", res)
	}
	contains(t, "package", w.Read(co+"/carbon.toml"), "name = \"shop\"\n\n[access]")
	contains(t, "web", w.Read("services/web/carbon.toml"),
		`KEY = "${shop.stripe_api_key}"`, `LIT = "$${checkout.x} ${shop.session_key}"`, `OWN = "${env:HOME}"`)
	contains(t, "keys", w.Read(co+"/.carbon/prod.keys.toml"), `scope = "shop/prod"`)
	if v, s := umGet(t, w.Lin, "shop", "prod", "stripe_api_key"); v != "sk_prod" || s != set {
		t.Fatal(v, s)
	}
	if v, _ := umGet(t, w.Deploy, "shop", "prod", "stripe_api_key"); v != "sk_prod" {
		t.Fatal(v)
	}
	if v, _ := umGet(t, w.Lin, "shop", "prod", "webhook_secret"); v != "wh_prod" {
		t.Fatal(v)
	}
	if v, _ := umGet(t, w.Sam, "shop", "dev", "stripe_api_key"); v != "sk_dev" {
		t.Fatal(v)
	}
	// On the rename branch, before it merges, readers still verify the key
	// against trunk's file under the old name, and apply works.
	// Access still comes from checkout's trunk entry, not the workspace
	// default that an unknown package name would get.
	res = w.Lin.Must("apply", "--env", "prod", "--yes")
	// The drop rename re-sealed is not line for line on trunk, so it stays a
	// drop until the rename merges.
	contains(t, "apply on rename branch", res.Stdout, "renamed from checkout", "webhook_secret: not on trunk yet")
	if strings.Contains(res.Stdout, "gains access") || strings.Contains(res.Stdout, "loses access") {
		t.Fatalf("apply on the rename branch used the wrong policy:\n%s", res)
	}
	// A swapped keys file on the rename branch is still refused.
	other := w.Read(co + "/.carbon/dev.keys.toml")
	w.Write(co+"/.carbon/prod.keys.toml", strings.Replace(other, `"shop/dev"`, `"shop/prod"`, 1))
	res = w.Lin.Run("get", "stripe_api_key", "--package", "shop", "--env", "prod")
	if res.Code == 0 {
		t.Fatalf("a swapped keys file was read:\n%s", res)
	}
	w.Git("checkout", "--", co)

	w.Checkout("main")
	w.Merge("rename")
	if v, _ := umGet(t, w.Deploy, "shop", "prod", "stripe_api_key"); v != "sk_prod" {
		t.Fatal(v)
	}
}

// umCopyLine prepends a copy of the line for name, renamed to as: a value
// or drop moved to another name, which fails authentication.
func umCopyLine(w *clitest.World, file, name, as string) {
	sec := w.Read(file)
	for _, l := range strings.Split(sec, "\n") {
		if strings.HasPrefix(l, name+" ") {
			sec = strings.Replace(l, name, as, 1) + "\n" + sec
		}
	}
	w.Write(file, sec)
}

func TestApplyLeavesBadDropsAndRotates(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	umSetAll(t, w)
	w.Ada.In(co).Stdin("wh").Must("set", "webhook_secret", "--env", "prod")
	umCopyLine(w, co+"/.carbon/prod.secrets.toml", "webhook_secret", "session_key")
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`, `prod = ["@payments"]`)
	w.Commit("remove the deploy machine from prod; a bad drop")
	bad := regexp.MustCompile(`(?m)^session_key .*$`).FindString(w.Read(co + "/.carbon/prod.secrets.toml"))

	res := w.Lin.Must("apply", "--yes", "--env", "prod", "--dry-run")
	contains(t, "plan", res.Stdout, "leaves drop", "session_key", "promotes drop", "webhook_secret", `reason "removed machine:deploy-checkout"`)
	res = w.Lin.Must("apply", "--yes", "--env", "prod")
	contains(t, "apply", res.Stdout, "leaves drop", "session_key", "Committed")
	sec := w.Read(co + "/.carbon/prod.secrets.toml")
	if !strings.Contains(sec, bad) {
		t.Fatalf("the bad drop was changed:\n%s", sec)
	}
	contains(t, "commit", w.Git("log", "-1", "--format=%B"), "left drops that do not open: session_key")
	if v, _ := umGet(t, w.Lin, "checkout", "prod", "webhook_secret"); v != "wh" {
		t.Fatal(v)
	}
	w.Deploy.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
}

func TestApplyIsAllOrNothingPerScope(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	umSetAll(t, w)
	// A sealed value copied to another name fails authentication, which
	// stops prod's rotation.
	umCopyLine(w, co+"/.carbon/prod.secrets.toml", "stripe_api_key", "session_key")
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`, `prod = ["@payments", "nia"]`)
	nia := w.Person("nia")
	nia.Join()
	w.SetTeams(map[string][]string{"engineering": {"ada", "lin", "sam", "nia"}, "payments": {"lin"}})
	w.Commit("nia joins; a tampered value")
	prodKeys, prodSecrets := w.Read(co+"/.carbon/prod.keys.toml"), w.Read(co+"/.carbon/prod.secrets.toml")

	res := w.Lin.Fails(1, "apply", "--yes")
	contains(t, "apply", res.Stdout, "Failed in checkout/prod (unchanged)", "session_key", "Applied 2 scope(s)")
	if w.Read(co+"/.carbon/prod.keys.toml") != prodKeys || w.Read(co+"/.carbon/prod.secrets.toml") != prodSecrets {
		t.Fatal("the failed scope was changed")
	}
	if got := w.Git("show", "--name-only", "--format=", "HEAD"); got != co+"/.carbon/dev.keys.toml\n"+co+"/.carbon/staging.keys.toml" {
		t.Fatalf("committed %q", got)
	}
	if v, _ := umGet(t, nia, "checkout", "dev", "stripe_api_key"); v != "sk_dev" {
		t.Fatal(v)
	}
	nia.Fails(3, "get", "stripe_api_key", "--package", "checkout", "--env", "prod")
}
