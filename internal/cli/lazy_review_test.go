package cli_test

import (
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/clitest"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

// samOldKey unwraps sam's slot from a keys file (as he would have before
// his removal) and returns the key id and key.
func samOldKey(t *testing.T, w *clitest.World, keysText, scopeName string) (string, *seal.Key) {
	t.Helper()
	ks, err := store.ParseKeys("k", []byte(keysText))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(w.Sam.IdentityFile())
	ids, err := agewrap.ParseIdentityFile(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := agewrap.OpenSlot(ks.CurrentKey().Slots["sam/laptop"], ids, scopeName, ks.Current)
	if err != nil {
		t.Fatal(err)
	}
	return ks.Current, k
}

// injectFakeRetired adds a fabricated retired record kfake whose successor is
// succ (sealed under succKey, or garbage when succKey is nil) carrying a line
// of the attacker's choosing for name, and writes that line.
func injectFakeRetired(t *testing.T, w *clitest.World, env, succ string, succKey *seal.Key, name, value string) {
	t.Helper()
	kf := w.PkgDir + "/.carbon/" + env + ".keys.toml"
	sf := w.PkgDir + "/.carbon/" + env + ".secrets.toml"
	ks, err := store.ParseKeys("k", []byte(w.Read(kf)))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.ParseSecrets("s", []byte(w.Read(sf)))
	if err != nil {
		t.Fatal(err)
	}
	fake, _ := seal.NewKey()
	fid := "kfake9"
	set := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	vad, _ := seal.ValueAD("checkout", env, name, fid, set)
	blob, _ := seal.Seal(fake, []byte(value), vad)
	e := store.Entry{Key: fid, Set: set, Value: blob}
	carried := []string{store.LineHash(name, e)}
	retired := set.Add(time.Hour)
	reason := "rekeyed sam/laptop"
	rad, _ := seal.RetiredAD("checkout", env, fid, succ, retired, reason, "", "", carried)
	var sealed string
	if succKey != nil {
		// the fake key's bytes: re-derive via Open of the blob is not
		// possible, so seal fresh bytes and re-seal the value under them.
		var raw [32]byte
		rand.Read(raw[:])
		fk, _ := seal.KeyFromBytes(raw[:])
		blob, _ = seal.Seal(fk, []byte(value), vad)
		e = store.Entry{Key: fid, Set: set, Value: blob}
		carried = []string{store.LineHash(name, e)}
		rad, _ = seal.RetiredAD("checkout", env, fid, succ, retired, reason, "", "", carried)
		sealed, _ = seal.Seal(succKey, raw[:], rad)
	} else {
		var raw [32]byte
		rand.Read(raw[:])
		k, _ := seal.NewKey()
		sealed, _ = seal.Seal(k, raw[:], rad)
	}
	ks.Keys[fid] = &store.Key{Created: set, Retired: retired, Reason: reason, Successor: succ, Sealed: sealed, Carried: carried}
	ss.Entries[name] = e
	w.Write(kf, string(ks.Marshal()))
	w.Write(sf, string(ss.Marshal()))
}

// Lazy-rotation review, finding 1: a removed reader who kept a retired key
// forges a retired record that "carries" his value. Readers refuse the
// scope, naming the record; check fails it as key.retired-added.
func TestForgedRetiredRecordCannotCarryAValue(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	devOld, devK := samOldKey(t, w, w.Read(co+"/.carbon/dev.keys.toml"), "checkout/dev")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")
	ci(t, w.Repo, 0)

	w.Branch("sam-pr")
	w.Replace(co+"/carbon.toml", "[secrets]\n", "[secrets]\npartner_url = { description = \"partner endpoint\" }\n")
	injectFakeRetired(t, w, "dev", devOld, devK, "partner_url", "https://evil.example/dev")
	prodKeys, _ := store.ParseKeys("k", []byte(w.Read(co+"/.carbon/prod.keys.toml")))
	injectFakeRetired(t, w, "prod", prodKeys.Current, nil, "partner_url", "x")
	w.Commit("add partner_url")

	cj := ci(t, w.Repo, 4)
	cj.has(t, "key.retired-added", "error checkout/dev", "error checkout/prod")
	res := w.Lin.In(co).Fails(1, "get", "partner_url", "--env", "dev")
	mustContain(t, "get", res.Stderr, "kfake9", "git checkout")
	mustNotContain(t, "get", res.Stdout+res.Stderr, "evil.example")
	// In prod the garbage record claims the current key's place, which
	// nobody else holds: it is on the chain but does not open, so what it
	// "carries" fails, and the rest of the scope still reads.
	res = w.Lin.In(co).Fails(1, "get", "partner_url", "--env", "prod")
	mustContain(t, "get prod", res.Stderr, "kfake9", "failed authentication")
	if got := w.Lin.In(co).Must("get", "stripe_api_key", "--env", "prod").Stdout; got != "sk_prod" {
		t.Fatalf("prod get = %q", got)
	}
	res = w.Lin.In(co).Must("ls", "--env", "dev")
	mustContain(t, "ls", res.Stdout, "partner_url", "unproven")

	// Merged anyway: trunk equals the forgery, but readers still refuse.
	w.Checkout("main")
	w.Merge("sam-pr")
	w.Lin.In(co).Fails(1, "get", "partner_url", "--env", "dev")
	res = w.Lin.In(co).Fails(1, "get", "stripe_api_key", "--env", "dev")
	mustContain(t, "get on trunk", res.Stderr, "kfake9")
}

// Finding 2: a carried line that trunk deleted, copied back, is not
// carried any more.
func TestResurrectedCarriedLineIsUnproven(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	w.Replace(co+"/carbon.toml", "[secrets]\n", "[secrets]\nold_token = { description = \"x\" }\n")
	setAll(t, w)
	for _, env := range []string{"dev", "staging", "prod"} {
		w.Lin.In(co).Stdin("tok_"+env).Must("set", "old_token", "--env", env)
	}
	w.Commit("old_token")
	devSecrets := w.Read(co + "/.carbon/dev.secrets.toml")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")
	w.Replace(co+"/carbon.toml", "old_token = { description = \"x\" }\n", "")
	for _, env := range []string{"dev", "staging", "prod"} {
		f := co + "/.carbon/" + env + ".secrets.toml"
		var keep []string
		for _, l := range strings.Split(w.Read(f), "\n") {
			if !strings.HasPrefix(l, "old_token") {
				keep = append(keep, l)
			}
		}
		w.Write(f, strings.Join(keep, "\n"))
	}
	w.Commit("drop old_token")
	ci(t, w.Repo, 0)
	w.Branch("sam")
	w.Replace(co+"/carbon.toml", "[secrets]\n", "[secrets]\nold_token = { description = \"x\" }\n")
	var line string
	for _, l := range strings.Split(devSecrets, "\n") {
		if strings.HasPrefix(l, "old_token") {
			line = l
		}
	}
	w.Write(co+"/.carbon/dev.secrets.toml", line+"\n"+w.Read(co+"/.carbon/dev.secrets.toml"))
	w.Commit("restore")
	cj := ci(t, w.Repo, 4) // old_token is unset in staging and prod
	cj.has(t, "secret.stale-key", "checkout/dev old_token")
	found := false
	for _, b := range cj.banner() {
		found = found || b == "secret.stale-key"
	}
	if !found {
		t.Fatalf("not in the banner\n%s", cj)
	}
}

// Finding 3: an honest edit on a branch cut before the rotation is told
// what happened and how to fix it, without an accusation.
func TestEditBeforeRotationGetsAFairMessage(t *testing.T) {
	w := clitest.Standard(t)
	co := w.PkgDir
	setAll(t, w)
	w.Branch("edit")
	nextSecond()
	w.Lin.In(co).Stdin("sk_dev_v2").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("new stripe key")
	w.Checkout("main")
	w.Ada.Must("remove", "sam", "--yes")
	w.Commit("remove sam")
	w.Lin.Must("apply", "--yes")
	w.Checkout("edit")
	w.Merge("main")
	res := w.Anyone().Fails(4, "check")
	mustContain(t, "check", res.Stdout, "secret.rolled-back", "cannot tell an edit made on a branch cut before the rotation",
		"Merge trunk and set it again: carbon set stripe_api_key --package checkout --env dev", "--reseal-unproven")
	mustNotContain(t, "check", res.Stdout, "only someone holding that key")
	nextSecond()
	w.Lin.In(co).Stdin("sk_dev_v2").Must("set", "stripe_api_key", "--env", "dev")
	w.Commit("set again under the new key")
	ci(t, w.Repo, 0).lacks(t, "secret.rolled-back")
}
