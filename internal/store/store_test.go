package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/config"
)

const secretsSample = `session_key = { key = "k3f9q2", set = 2026-11-02T17:04:11Z, value = "carbon1:9wN3" }
stripe_api_key = { key = "k1a8c0", set = 2026-09-14T09:30:02Z, value = "carbon1:Qm7r" }
webhook_secret = { key = "k3f9q2", set = 2026-11-10T08:12:40Z, drop = "age1:YWdl" }
`

const keysSample = `scope = "checkout/prod"
current = "k3f9q2"

[keys.k1a8c0]
created = 2026-06-01T10:00:00Z
retired = 2026-11-02T17:04:11Z
reason = "removed sam"
successor = "k3f9q2"
sealed = "carbon1:Zk2p"
inbox_sealed = "carbon1:Old1"

[keys.k3f9q2]
created = 2026-11-02T17:04:11Z
inbox = "age1pq1x7c4"
inbox_sealed = "carbon1:Rb1v"

[keys.k3f9q2.slots]
"lin/laptop" = "age1:YWdl1"
"machine:deploy-checkout" = "age1:YWdl2"
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
