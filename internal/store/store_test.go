package store

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/config"
)

const secretsSample = `[session_key]
key = "k3f9q2"
set = 2026-11-02T17:04:11Z
value = "carbon1:9wN3"

[stripe_api_key]
key = "k1a8c0"
set = 2026-09-14T09:30:02Z
value = "carbon1:Qm7r"

[webhook_secret]
key = "k3f9q2"
set = 2026-11-10T08:12:40Z
drop = "age1:YWdl"
`

const keysSample = `scope = "checkout/prod"
current = "k3f9q2"

[keys.k1a8c0]
created = 2026-06-01T10:00:00Z
retired = 2026-11-02T17:04:11Z
reason = "removed sam"
successor = "k3f9q2"
sealed = "carbon1:Zk2p"
carried = ["sha256:6df86903b5b7351b0706576dc05f046e103145a5211d03c6c6d7f01c9512d29d"]
inbox_sealed = "carbon1:Old1"

[keys.k3f9q2]
created = 2026-11-02T17:04:11Z
inbox = "age1pq1x7c4"
inbox_sealed = "carbon1:Rb1v"

[keys.k3f9q2.slots]
"lin/laptop" = { to = "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", slot = "age1:YWdl1" }
"machine:deploy-checkout" = { to = "sha256:3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d", slot = "age1:YWdl2" }
`

func TestSecretsRoundTripIsByteIdentical(t *testing.T) {
	s, err := ParseSecrets("x", []byte(secretsSample))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Entries["webhook_secret"].IsDrop() || s.Entries["session_key"].IsDrop() {
		t.Fatal("drop detection")
	}
	if got := s.Entries["stripe_api_key"].Set; !got.Equal(time.Date(2026, 9, 14, 9, 30, 2, 0, time.UTC)) || got.Location() != time.UTC {
		t.Fatalf("set = %v", got)
	}
	if got := string(s.Marshal()); got != secretsSample {
		t.Fatalf("marshal:\n%s\nwant:\n%s", got, secretsSample)
	}
}

func TestKeysRoundTripIsByteIdentical(t *testing.T) {
	k, err := ParseKeys("x", []byte(keysSample))
	if err != nil {
		t.Fatal(err)
	}
	if k.CurrentKey().Slots["lin/laptop"] != "age1:YWdl1" || !k.Keys["k1a8c0"].IsRetired() {
		t.Fatalf("%+v", k)
	}
	if got := string(k.Marshal()); got != keysSample {
		t.Fatalf("marshal:\n%s\nwant:\n%s", got, keysSample)
	}
}

func TestRetiredKeyWithoutInboxSealedIsAccepted(t *testing.T) {
	src := strings.Replace(keysSample, "inbox_sealed = \"carbon1:Old1\"\n", "", 1)
	k, err := ParseKeys("x", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if string(k.Marshal()) != src {
		t.Fatal("round trip changed the file")
	}
}

func TestSecretsErrors(t *testing.T) {
	cases := map[string]string{
		"both":        `a = { key = "k00000", set = 2026-01-01T00:00:00Z, value = "carbon1:x", drop = "age1:y" }`,
		"neither":     `a = { key = "k00000", set = 2026-01-01T00:00:00Z }`,
		"no set":      `a = { key = "k00000", value = "carbon1:x" }`,
		"bad key":     `a = { key = "kX", set = 2026-01-01T00:00:00Z, value = "carbon1:x" }`,
		"offset":      `a = { key = "k00000", set = 2026-01-01T00:00:00+01:00, value = "carbon1:x" }`,
		"fraction":    `a = { key = "k00000", set = 2026-01-01T00:00:00.5Z, value = "carbon1:x" }`,
		"unknown":     `a = { key = "k00000", set = 2026-01-01T00:00:00Z, value = "carbon1:x", by = "me" }`,
		"bad name":    `1a = { key = "k00000", set = 2026-01-01T00:00:00Z, value = "carbon1:x" }`,
		"bad prefix":  `a = { key = "k00000", set = 2026-01-01T00:00:00Z, value = "age1:x" }`,
		"drop prefix": `a = { key = "k00000", set = 2026-01-01T00:00:00Z, drop = "carbon1:x" }`,
	}
	for name, src := range cases {
		if _, err := ParseSecrets("x", []byte(src+"\n")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeysErrors(t *testing.T) {
	mut := map[string][2]string{
		"current missing":     {`current = "k3f9q2"`, `current = "k999999"`},
		"current retired":     {`current = "k3f9q2"`, `current = "k1a8c0"`},
		"bad scope":           {`scope = "checkout/prod"`, `scope = "checkout"`},
		"retired with slots":  {"inbox_sealed = \"carbon1:Old1\"\n", "inbox_sealed = \"carbon1:Old1\"\ninbox = \"age1pq1x\"\n"},
		"no successor":        {`successor = "k3f9q2"`, `successor = "kzzzzz"`},
		"bad slot id":         {`"lin/laptop"`, `"lin"`},
		"slot without to":     {`to = "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", `, ""},
		"to not sha256":       {`to = "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"`, `to = "age1pq1x"`},
		"slot without blob":   {`, slot = "age1:YWdl1"`, ""},
		"bad slot blob":       {`"age1:YWdl1"`, `"carbon1:x"`},
		"unknown field":       {`reason = "removed sam"`, "reason = \"removed sam\"\nwho = \"x\""},
		"no inbox":            {"inbox = \"age1pq1x7c4\"\n", ""},
		"retire without time": {"retired = 2026-11-02T17:04:11Z\n", ""},
	}
	for name, m := range mut {
		src := strings.Replace(keysSample, m[0], m[1], 1)
		if src == keysSample {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseKeys("x", []byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConflictMarkers(t *testing.T) {
	src := "<<<<<<< HEAD\n" + secretsSample + "=======\n>>>>>>> other\n"
	var ce *config.ConflictError
	if _, err := ParseSecrets("p/.carbon/dev.secrets.toml", []byte(src)); !errors.As(err, &ce) || ce.Path != "p/.carbon/dev.secrets.toml" {
		t.Fatalf("secrets: %v", err)
	}
	if _, err := ParseKeys("k", []byte("<<<<<<< HEAD\n"+keysSample)); !errors.As(err, &ce) {
		t.Fatalf("keys: %v", err)
	}
}

func TestReadWriteFiles(t *testing.T) {
	dir := t.TempDir()
	if k, err := ReadKeys(KeysPath(dir, "dev")); k != nil || err != nil {
		t.Fatalf("missing keys file: %v %v", k, err)
	}
	if s, err := ReadSecrets(SecretsPath(dir, "dev")); err != nil || len(s.Entries) != 0 {
		t.Fatalf("missing secrets file: %v %v", s, err)
	}
	p := SecretsPath(dir, "dev")
	if p != filepath.Join(dir, ".carbon", "dev.secrets.toml") {
		t.Fatal(p)
	}
	if err := WriteFile(p, []byte(secretsSample)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	s, err := ReadSecrets(p)
	if err != nil || len(s.Entries) != 3 {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temporary files left behind: %v", ents)
	}
}

// Local date-times would be read in the machine's time zone; they are
// rejected whatever the zone is.
func TestLocalDateTimesRejected(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC // the zone in which they used to slip through
	defer func() { time.Local = saved }()
	for _, set := range []string{"2026-01-01T00:00:00", "2026-01-01"} {
		src := `a = { key = "kaaaaa", set = ` + set + `, value = "carbon1:x" }` + "\n"
		if _, err := ParseSecrets("x", []byte(src)); err == nil {
			t.Errorf("set = %s accepted", set)
		}
	}
	src := strings.Replace(keysSample, "created = 2026-06-01T10:00:00Z", "created = 2026-06-01T10:00:00", 1)
	if _, err := ParseKeys("x", []byte(src)); err == nil {
		t.Error("local created accepted")
	}
	if _, err := ParseSecrets("x", []byte("a = { key = \"kaaaaa\", set = 2026-01-01T00:00:00+00:00, value = \"carbon1:x\" }\n")); err != nil {
		t.Errorf("+00:00 offset rejected: %v", err)
	}
}

// Slots record the recipient they were wrapped to; the old bare-string form
// gets a clear error.
func TestSlotRecipientHash(t *testing.T) {
	k, err := ParseKeys("x", []byte(keysSample))
	if err != nil {
		t.Fatal(err)
	}
	if to := k.CurrentKey().SlotTo["lin/laptop"]; !strings.HasPrefix(to, "sha256:") || len(to) != 71 {
		t.Fatalf("SlotTo = %q", to)
	}
	old := regexp.MustCompile(`"lin/laptop" = \{[^}]*\}`).ReplaceAllString(keysSample, `"lin/laptop" = "age1:YWdl1"`)
	_, err = ParseKeys("x", []byte(old))
	if err == nil || !strings.Contains(err.Error(), "old slot format") {
		t.Fatalf("old form: %v", err)
	}
	var nk Key
	nk.SetSlot("a/b", "sha256:"+strings.Repeat("0", 64), "age1:x")
	if nk.Slots["a/b"] != "age1:x" || nk.SlotTo["a/b"] == "" {
		t.Fatal("SetSlot")
	}
}

// A retired key lists the line hashes of the entries it carried, sorted;
// the list is required, and LineHash is over the canonical one-line form.
func TestCarried(t *testing.T) {
	k, err := ParseKeys("x", []byte(keysSample))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSecrets("x", []byte(secretsSample))
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Keys["k1a8c0"].Carried; len(got) != 1 || got[0] != LineHash("stripe_api_key", s.Entries["stripe_api_key"]) {
		t.Fatalf("carried %v", got)
	}
	if string(k.Marshal()) != keysSample {
		t.Fatalf("round trip:\n%s", k.Marshal())
	}
	for name, src := range map[string]string{
		"missing":        strings.Replace(keysSample, "carried = [", "#carried = [", 1),
		"bad hash":       strings.Replace(keysSample, `carried = ["sha256:`, `carried = ["md5:`, 1),
		"on current key": strings.Replace(keysSample, "inbox = \"age1pq1x7c4\"\n", "inbox = \"age1pq1x7c4\"\ncarried = []\n", 1),
	} {
		if _, err := ParseKeys("x", []byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	empty := strings.Replace(keysSample, `carried = ["sha256:`, `carried = [] # "sha256:`, 1)
	if k, err := ParseKeys("x", []byte(empty)); err != nil || k.Keys["k1a8c0"].Carried == nil {
		t.Fatalf("empty carried: %v", err)
	}
}

// Chain follows predecessors back from the current key and rejects every
// record off it.
func TestChain(t *testing.T) {
	rec := func(succ, pred string) *Key {
		return &Key{Created: time.Unix(0, 0), Retired: time.Unix(1, 0), Reason: "r", Successor: succ, Predecessor: pred, Sealed: "carbon1:x", Carried: []string{}}
	}
	ks := &Keys{Scope: "a/dev", Current: "kccccc", Keys: map[string]*Key{
		"kccccc": {Created: time.Unix(0, 0), Inbox: "age1x", InboxSealed: "carbon1:x"},
		"kbbbbb": rec("kccccc", "kaaaaa"),
		"kaaaaa": rec("kbbbbb", ""),
	}}
	if c, err := ks.Chain(); err != nil || strings.Join(c, ",") != "kbbbbb,kaaaaa" {
		t.Fatalf("chain %v %v", c, err)
	}
	for name, extra := range map[string]*Key{
		"second claim on the current key":   rec("kccccc", ""),
		"claim on a key with a predecessor": rec("kbbbbb", ""),
		"claim on the first key":            rec("kaaaaa", ""),
	} {
		ks.Keys["kfake9"] = extra
		var ce *ChainError
		if _, err := ks.Chain(); !errors.As(err, &ce) || ce.ID != "kfake9" && ce.ID != "kbbbbb" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The writer emits tables; the reader takes the inline form too, and the
// carried hash is the same for either spelling.
func TestSecretsInlineFormStillParses(t *testing.T) {
	inline := `session_key = { key = "k3f9q2", set = 2026-11-02T17:04:11Z, value = "carbon1:9wN3" }
stripe_api_key = { key = "k1a8c0", set = 2026-09-14T09:30:02Z, value = "carbon1:Qm7r" }
webhook_secret = { key = "k3f9q2", set = 2026-11-10T08:12:40Z, drop = "age1:YWdl" }
`
	s, err := ParseSecrets("x", []byte(inline))
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Marshal()) != secretsSample {
		t.Fatalf("inline form did not rewrite as tables:\n%s", s.Marshal())
	}
	if got, want := EntryLine("stripe_api_key", s.Entries["stripe_api_key"]),
		`stripe_api_key = { key = "k1a8c0", set = 2026-09-14T09:30:02Z, value = "carbon1:Qm7r" }`; got != want {
		t.Fatalf("canonical line changed: %s", got)
	}
}
