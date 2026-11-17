package agekey

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	id, rec, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Recipient([]byte(id))
	if err != nil || got != rec {
		t.Fatalf("Recipient = %q, %v; want %q", got, err, rec)
	}
	if !IsRecipient(rec) || IsRecipient(rec[:len(rec)-1]+"q") {
		t.Fatal("IsRecipient")
	}
}

// TestMatchesKeygen checks the derivation against rage-keygen or age-keygen,
// whichever is on PATH (0.0.3 created keys with rage-keygen).
func TestMatchesKeygen(t *testing.T) {
	var keygen string
	for _, k := range []string{"rage-keygen", "age-keygen"} {
		if p, err := exec.LookPath(k); err == nil {
			keygen = p
			break
		}
	}
	if keygen == "" {
		t.Skip("SKIPPED: neither rage-keygen nor age-keygen is on PATH")
	}
	file := filepath.Join(t.TempDir(), "key")
	if out, err := exec.Command(keygen, "-o", file).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", keygen, err, out)
	}
	want, err := exec.Command(keygen, "-y", file).Output()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	got, err := Recipient(data)
	if err != nil || got != strings.TrimSpace(string(want)) {
		t.Fatalf("Recipient = %q, %v; %s says %q", got, err, keygen, want)
	}
}

func TestRejectsOtherKeys(t *testing.T) {
	for _, in := range []string{"", "# only a comment\n", "AGE-PLUGIN-YUBIKEY-1QQQ\n", "AGE-SECRET-KEY-1QQQQ\n"} {
		if _, err := Recipient([]byte(in)); err == nil {
			t.Errorf("Recipient(%q) succeeded", in)
		}
	}
}
