package cli_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/clitest"
)

func TestMain(m *testing.M) { clitest.Main(m) }

func contains(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Fatalf("%s does not contain %q:\n%s", what, sub, s)
		}
	}
}

func TestInitWorkspaceThenPackage(t *testing.T) {
	r := clitest.NewRepo(t)
	any := r.Anyone()
	res := any.Must("init", "--trunk", "main", "--environments", "dev,prod")
	contains(t, "stdout", res.Stdout, "Created carbon.toml", "Created .carbon/teams.toml", "git config carbon.trunk main (this clone only)")
	contains(t, "carbon.toml", r.Read("carbon.toml"), `environments = ["dev", "prod"]`, `prod = ["@engineering"]`)
	if strings.Contains(r.Read("carbon.toml"), "trunk") {
		t.Fatal("init wrote a trunk setting")
	}
	if got := r.Git("config", "--local", "carbon.trunk"); got != "main" {
		t.Fatalf("carbon.trunk = %q", got)
	}
	contains(t, ".gitattributes", r.Read(".gitattributes"), "**/.carbon/*.keys.toml linguist-generated")

	any.Fails(2, "init")

	r.Write("services/billing/README", "x")
	res = any.In("services/billing").Must("init")
	contains(t, "stdout", res.Stdout, "Created services/billing/carbon.toml")
	contains(t, "package file", r.Read("services/billing/carbon.toml"), `name = "billing"`)
	any.In("services/billing").Fails(2, "init")

	r.Write("services/Web App/x", "")
	any.In("services/Web App").Must("init")
	contains(t, "package file", r.Read("services/Web App/carbon.toml"), `name = "web-app"`)

	any.Must("init", "--name", "root")
	contains(t, "root", r.Read("carbon.toml"), "name = \"root\"\n\n[workspace]")
	res = any.Must("ls", "--json")
	contains(t, "ls", res.Stdout, `"scope": "root/dev"`)
}

func TestLegacyRepositoryIsRefused(t *testing.T) {
	r := clitest.NewRepo(t)
	r.Write("carbon.toml", "name = \"svc\"\n[push.db]\nvalue = \"x\"\n")
	for _, args := range [][]string{{"init"}, {"ls"}, {"set", "x"}} {
		res := r.Anyone().Fails(1, args...)
		contains(t, "stderr", res.Stderr, "carbon 0.0.3", "carbon-migrate")
	}
}

func TestJoinPeopleDevicesMachines(t *testing.T) {
	r := clitest.NewWorkspace(t)
	ada := r.Person("ada")
	res := ada.Join()
	contains(t, "join", res.Stdout, "Created your identity", ".carbon/people/ada.toml", "Joined team", "@engineering", "Fingerprint")
	fp := regexp.MustCompile(`Fingerprint\s+([a-z]+-[a-z]+-[a-z]+-[a-z]+)`).FindStringSubmatch(res.Stdout)
	if fp == nil {
		t.Fatalf("no fingerprint:\n%s", res.Stdout)
	}
	person := r.Read(".carbon/people/ada.toml")
	contains(t, "person file", person, "[devices]\nlaptop = \"age1pq1")
	contains(t, "teams", r.Read(".carbon/teams.toml"), `engineering = ["ada"]`)

	// Joining again is idempotent and prints the same fingerprint.
	res = ada.Must("join")
	contains(t, "rejoin", res.Stdout, "already joined as ada/laptop", fp[1])

	// A second device for ada: another home, --x25519.
	ada2 := r.Person("ada-desk")
	ada2.Fails(2, "join", "--person", "ada", "--device", "laptop")
	ada2.Must("join", "--person", "ada", "--device", "desk", "--x25519")
	person = r.Read(".carbon/people/ada.toml")
	if !regexp.MustCompile(`desk = "age1[^p]`).MatchString(person) || !strings.Contains(person, "laptop = \"age1pq1") {
		t.Fatalf("person file:\n%s", person)
	}
	// Only the first person joins teams automatically.
	r.Person("lin").Join()
	contains(t, "teams", r.Read(".carbon/teams.toml"), `engineering = ["ada"]`)

	// A machine: the key goes to stdout once, the file holds the public key.
	res = r.Anyone().Must("join", "--machine", "deploy", "--description", "deploys")
	if !strings.HasPrefix(res.Stdout, "# created: ") || !strings.Contains(res.Stdout, "AGE-SECRET-KEY-PQ-1") {
		t.Fatalf("machine stdout:\n%s", res.Stdout)
	}
	contains(t, "stderr", res.Stderr, "CARBON_IDENTITY")
	contains(t, "machine file", r.Read(".carbon/machines/deploy.toml"), "description = \"deploys\"\nkey = \"age1pq1")
	r.Anyone().Fails(2, "join", "--machine", "deploy")

	// $USER is lower-cased and sanitised; an explicit --person must be valid.
	r.Person("Bad Name").Must("join", "--device", "x")
	contains(t, "person file", r.Read(".carbon/people/bad-name.toml"), "x = \"age1pq1")
	r.Person("other").Fails(2, "join", "--person", "Bad Name", "--device", "x")
}

func TestJoinWithPassphrase(t *testing.T) {
	r := clitest.NewWorkspace(t)
	lin := r.Person("lin")
	lin.Stdin("correct horse\n").Must("join", "--person", "lin", "--device", "laptop", "--passphrase")
	id := readFile(t, lin.IdentityFile())
	if !strings.HasPrefix(id, "-----BEGIN AGE ENCRYPTED FILE-----") || strings.Contains(id, "AGE-SECRET-KEY") {
		t.Fatalf("identity file is not encrypted:\n%s", id)
	}
	r.AddPackage("svc", "svc", "[secrets]\na = {}\n")
	// Without a terminal, carbon cannot ask for the passphrase.
	res := lin.In("svc").Stdin("v").Fails(6, "set", "a")
	contains(t, "stderr", res.Stderr, "passphrase-protected", "CARBON_IDENTITY")
}

func TestSingleUserBootstrap(t *testing.T) {
	r := clitest.NewWorkspace(t)
	ada := r.Person("ada")
	ada.Join()
	r.AddPackage("api", "api", "[secrets]\ndb_password = {}\ntoken = { generate = \"random:16\" }\n")

	res := ada.In("api").Stdin("hunter2\n").Must("set", "db_password")
	contains(t, "stderr", res.Stderr, "notice: this repository has no trunk yet", "reading policy from the working tree")
	contains(t, "stdout", res.Stdout, "Created the key for api/dev", "Sealed. Commit api/.carbon/dev.keys.toml and api/.carbon/dev.secrets.toml")
	if strings.Contains(res.Stdout+res.Stderr, "hunter2") {
		t.Fatal("value echoed")
	}
	res = ada.In("api").Must("get", "db_password")
	if res.Stdout != "hunter2" {
		t.Fatalf("get = %q", res.Stdout)
	}
	res = ada.In("api").Must("set", "token", "--generate")
	contains(t, "stdout", res.Stdout, "Generated 16 random bytes for api/dev token. Nobody has seen it.")
	tok := ada.In("api").Must("get", "token").Stdout
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(tok) {
		t.Fatalf("generated value %q is not 16 bytes of unpadded URL-safe base64", tok)
	}

	res = ada.In("api").Must("ls")
	contains(t, "ls", res.Stdout, "api/dev", "db_password   sealed", "token         sealed")
	var ls struct {
		Scope   string
		Secrets []struct{ Name, State string }
	}
	if err := json.Unmarshal([]byte(ada.In("api").Must("ls", "--json").Stdout), &ls); err != nil {
		t.Fatal(err)
	}
	if ls.Scope != "api/dev" || len(ls.Secrets) != 2 || ls.Secrets[0].State != "sealed" {
		t.Fatalf("ls --json = %+v", ls)
	}
	// Keys file is marked generated, files are deterministic text.
	contains(t, "keys", r.Read("api/.carbon/dev.keys.toml"), "scope = \"api/dev\"\ncurrent = \"k", "[keys.k", "\"ada/laptop\" = \"age1:")
}

func TestReadersAndNonReaders(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir

	// lin reads checkout/prod via @payments: the first set creates the key.
	res := w.Lin.In(co).Stdin("sk_live_1").Must("set", "stripe_api_key", "--env", "prod")
	contains(t, "stdout", res.Stdout, "Created the key for checkout/prod, wrapped to 2 device(s)")
	keys := w.Read(co + "/.carbon/prod.keys.toml")
	contains(t, "keys", keys, `"lin/laptop" = "age1:`, `"machine:deploy-checkout" = "age1:`)
	if strings.Contains(keys, "ada/laptop") || strings.Contains(keys, "sam/laptop") {
		t.Fatalf("non-readers got slots:\n%s", keys)
	}
	if got := w.Lin.In(co).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_live_1" {
		t.Fatalf("lin get = %q", got)
	}
	// The machine reads it with CARBON_IDENTITY, from anywhere via --package and -C.
	if got := w.Deploy.Must("--env", "prod", "get", "-C", co, "stripe_api_key").Stdout; got != "sk_live_1" {
		t.Fatalf("machine get = %q", got)
	}
	if got := w.Deploy.Must("get", "stripe_api_key", "--package", "checkout", "--env", "prod").Stdout; got != "sk_live_1" {
		t.Fatalf("machine get --package = %q", got)
	}

	// ada cannot read it; the error follows the design.
	res = w.Ada.In(co).Fails(3, "get", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr,
		"error: you cannot read checkout in prod",
		"checkout/prod is readable by @payments and machine:deploy-checkout.",
		"You are ada, a member of @engineering.",
		"To ask for access:   carbon request checkout --env prod")
	// The same as JSON.
	res = w.Ada.In(co).Fails(3, "get", "stripe_api_key", "--env", "prod", "--json")
	var je struct {
		Error struct {
			Code    int
			Message string
			Hint    string
		}
	}
	if err := json.Unmarshal([]byte(res.Stdout), &je); err != nil || je.Error.Code != 3 || !strings.Contains(je.Error.Hint, "carbon request") {
		t.Fatalf("json error %q: %v", res.Stdout, err)
	}
	// Someone with no identity at all.
	w.Anyone().In(co).Fails(6, "get", "stripe_api_key", "--env", "prod")
	// A person in policy whose device has no slot yet is told to wait for apply.
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`, `prod = ["@payments", "machine:deploy-checkout", "sam"]`)
	res = w.Sam.In(co).Fails(3, "get", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "no slot yet", "carbon apply")

	// Missing and undeclared secrets.
	w.Lin.In(co).Fails(5, "get", "webhook_secret", "--env", "prod")
	w.Lin.In(co).Stdin("x").Fails(5, "set", "undeclared", "--env", "prod")
	w.Lin.In(co).Stdin("").Fails(2, "set", "webhook_secret", "--env", "prod")
	w.Lin.Fails(5, "ls") // not inside a package
	w.Lin.Fails(5, "ls", "--package", "nope")
}

func TestDropByNonReaderThenReaderReads(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("sk_live_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("checkout/prod key")

	w.Branch("ada-webhook")
	res := w.Ada.In(co).Stdin("whsec_42\n").Must("set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "You cannot read checkout/prod, so this will be a drop: write-only for you.")
	contains(t, "stdout", res.Stdout, "Dropped. Readers can use it at once; `carbon check` will flag it for review.",
		"Commit services/checkout/.carbon/prod.secrets.toml")
	contains(t, "secrets", w.Read(co+"/.carbon/prod.secrets.toml"), "webhook_secret = { key = \"k", "drop = \"age1:")
	if strings.Contains(res.Stdout+res.Stderr, "whsec_42") {
		t.Fatal("value echoed")
	}
	w.Ada.In(co).Fails(3, "get", "webhook_secret", "--env", "prod")
	contains(t, "ls", w.Ada.In(co).Must("ls", "--env", "prod").Stdout, "webhook_secret   drop")
	w.Commit("ada drops webhook_secret")

	w.Checkout("main")
	w.Merge("ada-webhook")
	res = w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod")
	if res.Stdout != "whsec_42" {
		t.Fatalf("lin reads drop = %q", res.Stdout)
	}
	contains(t, "stderr", res.Stderr, "is a drop, not yet reviewed")
	if got := w.Deploy.In(co).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "whsec_42" {
		t.Fatalf("machine reads drop = %q", got)
	}
	// A reader's own set replaces the drop with a sealed value.
	w.Lin.In(co).Stdin("whsec_43").Must("set", "webhook_secret", "--env", "prod")
	contains(t, "ls", w.Lin.In(co).Must("ls", "--env", "prod").Stdout, "webhook_secret   sealed")
}

func TestDropUsesTrunkInboxNotTheBranch(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	keysFile := co + "/.carbon/prod.keys.toml"
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")
	trunkInbox := regexp.MustCompile(`inbox = "(age1pq1[^"]+)"`).FindStringSubmatch(w.Read(keysFile))[1]

	// ada, on a branch, swaps the inbox for a key she controls.
	w.Branch("swap")
	adaKey := regexp.MustCompile(`laptop = "(age1pq1[^"]+)"`).FindStringSubmatch(w.Read(".carbon/people/ada.toml"))[1]
	w.Replace(keysFile, trunkInbox, adaKey)
	w.Commit("swap inbox")

	// sam drops on that branch: the drop must go to trunk's inbox, not to
	// ada's key (proved below: lin opens it with trunk's inbox identity).
	w.Sam.In(co).Stdin("whsec_secret").Must("set", "webhook_secret", "--env", "prod")
	// Readers refuse the branch's swapped inbox loudly.
	res := w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "prod")
	contains(t, "stderr", res.Stderr, "inbox key was replaced")
	// Restoring the keys file from trunk lets lin read sam's drop: it was
	// written to trunk's inbox all along.
	w.Git("checkout", "main", "--", keysFile)
	if got := w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod").Stdout; got != "whsec_secret" {
		t.Fatalf("drop = %q", got)
	}
}

func TestBranchWithoutTrunkKey(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Branch("old")
	w.Checkout("main")
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key on trunk")
	w.Checkout("old")
	res := w.Ada.In(co).Stdin("x").Fails(1, "set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "has a key on trunk that this branch does not have", "git merge main")

	// The reverse: a key created on a branch, not on trunk; a non-reader
	// cannot drop to an inbox trunk does not have.
	w.Checkout("main")
	w.Branch("new-scope")
	w.Lin.In(co).Stdin("d").Must("set", "stripe_api_key", "--env", "staging")
	w.Sam.In(co).Stdin("d").Must("set", "webhook_secret", "--env", "staging") // sam reads staging: sealed
	// The deploy machine does not read staging, so its set would be a drop.
	res = w.Deploy.In(co).Stdin("x").Fails(1, "set", "session_key", "--env", "staging")
	contains(t, "stderr", res.Stderr, "has a key on this branch but not on trunk")
}

func TestDropsOff(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Replace(co+"/carbon.toml", `prod = ["@payments", "machine:deploy-checkout"]`,
		`prod = { readers = ["@payments", "machine:deploy-checkout"], drops = false }`)
	w.Commit("drops off in prod")
	w.Lin.In(co).Stdin("sk").Must("set", "stripe_api_key", "--env", "prod")
	res := w.Ada.In(co).Stdin("x").Fails(3, "set", "webhook_secret", "--env", "prod")
	contains(t, "stderr", res.Stderr, "drops are off", "carbon request checkout --env prod")
}

// The security properties, end to end through the files on disk.
func TestTamperingIsDetected(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	sec := co + "/.carbon/prod.secrets.toml"
	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Lin.In(co).Stdin("wh_1").Must("set", "webhook_secret", "--env", "prod")
	w.Lin.In(co).Stdin("dev_1").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("values")
	restore := func() { w.Git("checkout", "--", co) }
	line := func(file, name string) string {
		return regexp.MustCompile(`(?m)^` + name + ` = .*$`).FindString(w.Read(file))
	}

	t.Run("value moved to another name", func(t *testing.T) {
		defer restore()
		l := line(sec, "stripe_api_key")
		w.Replace(sec, line(sec, "webhook_secret"), strings.Replace(l, "stripe_api_key", "webhook_secret", 1))
		res := w.Lin.In(co).Fails(1, "get", "webhook_secret", "--env", "prod")
		contains(t, "stderr", res.Stderr, "failed authentication")
	})
	t.Run("value moved to another environment", func(t *testing.T) {
		defer restore()
		devSec := co + "/.carbon/dev.secrets.toml"
		w.Replace(devSec, line(devSec, "stripe_api_key"), line(sec, "stripe_api_key"))
		w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "dev")
	})
	t.Run("value moved to another package", func(t *testing.T) {
		defer restore()
		w.AddPackage("services/search", "search", "[secrets]\nstripe_api_key = {}\n")
		w.Lin.In("services/search").Stdin("s").Must("set", "stripe_api_key", "--env", "prod")
		other := "services/search/.carbon/prod.secrets.toml"
		w.Replace(other, line(other, "stripe_api_key"), line(sec, "stripe_api_key"))
		w.Lin.In("services/search").Fails(1, "get", "stripe_api_key", "--env", "prod")
	})
	t.Run("set time edited", func(t *testing.T) {
		defer restore()
		l := line(sec, "stripe_api_key")
		edited := regexp.MustCompile(`set = \d{4}`).ReplaceAllString(l, "set = 2099")
		w.Replace(sec, l, edited)
		w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "prod")
	})
	t.Run("ciphertext tampered", func(t *testing.T) {
		defer restore()
		l := line(sec, "stripe_api_key")
		i := strings.Index(l, "carbon1:") + 20
		c := "A"
		if l[i] == 'A' {
			c = "B"
		}
		w.Replace(sec, l, l[:i]+c+l[i+1:])
		w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "prod")
		// Other values in the scope are unaffected.
		w.Lin.In(co).Must("get", "webhook_secret", "--env", "prod")
	})
	t.Run("slot copied from another scope", func(t *testing.T) {
		defer restore()
		devKeys, prodKeys := co+"/.carbon/dev.keys.toml", co+"/.carbon/prod.keys.toml"
		adaDev := regexp.MustCompile(`(?m)^"ada/laptop" = .*$`).FindString(w.Read(devKeys))
		w.Replace(prodKeys, `"lin/laptop" = `, adaDev+"\n\"lin/laptop\" = ")
		res := w.Ada.In(co).Fails(1, "get", "stripe_api_key", "--env", "prod")
		contains(t, "stderr", res.Stderr, "failed authentication")
	})
	t.Run("conflict markers", func(t *testing.T) {
		defer restore()
		w.Write(sec, "<<<<<<< HEAD\n"+w.Read(sec)+"=======\n>>>>>>> other\n")
		res := w.Lin.In(co).Fails(1, "ls", "--env", "prod")
		contains(t, "stderr", res.Stderr, "prod.secrets.toml has unresolved git conflict markers", "keeping one side")
	})
}

func TestGlobalFlagsAndUsage(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Lin.In(co).Stdin("v").Must("--env", "staging", "set", "stripe_api_key")
	w.Lin.In(co).Must("get", "--env", "staging", "stripe_api_key")
	w.Lin.With("CARBON_ENV=staging").In(co).Must("get", "stripe_api_key")
	w.Lin.Must("-C", co, "get", "stripe_api_key", "--env=staging")

	res := w.Lin.Fails(2, "frobnicate")
	contains(t, "stderr", res.Stderr, `unknown command "frobnicate"`)
	w.Lin.Fails(2, "get")
	w.Lin.Fails(2, "get", "a", "b")
	w.Lin.Fails(2, "get", "x", "--bogus")
	w.Lin.Fails(2)
	w.Lin.In(co).Fails(2, "ls", "--env", "qa")
	contains(t, "help", w.Lin.Must("help", "set").Stdout, "Usage: carbon set <name>", "--generate")
	contains(t, "help", w.Lin.Must("set", "--help").Stdout, "Usage: carbon set <name>")
	contains(t, "version", w.Lin.Must("--version").Stdout, "carbon ")
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
