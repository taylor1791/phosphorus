package agewrap

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/taylor1791/phosphorus/internal/seal"
)

func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }

var (
	ageOnce sync.Once
	ageBin  string
	ageErr  string
	ageDir  string
)

// ageCLI builds filippo.io/age/cmd/age (1.3+, for hybrid keys) once per test
// binary, or skips the test with the reason.
func ageCLI(t *testing.T) string {
	t.Helper()
	ageOnce.Do(func() {
		dir, err := os.MkdirTemp("", "carbon-age-cli-")
		if err != nil {
			ageErr = err.Error()
			return
		}
		ageDir = dir
		bin := filepath.Join(dir, "age")
		gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
		cmd := exec.Command(gobin, "build", "-o", bin, "filippo.io/age/cmd/age")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			ageErr = "building filippo.io/age/cmd/age failed: " + err.Error() + "\n" + string(out)
			return
		}
		ageBin = bin
	})
	if ageBin == "" {
		t.Skip("interop test skipped: " + ageErr)
	}
	return ageBin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if ageDir != "" {
		os.RemoveAll(ageDir)
	}
	os.Exit(code)
}

func writeIdentity(t *testing.T, kind Kind) (path string, id Identity) {
	t.Helper()
	secret, rec, err := GenerateIdentity(kind)
	if err != nil {
		t.Fatal(err)
	}
	data := IdentityFile(secret, rec, time.Now())
	path = filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := ParseIdentityFile(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	return path, ids[0]
}

func ageDecrypt(t *testing.T, bin, identity, blob string) []byte {
	t.Helper()
	raw, err := DecodeBlob(blob)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", "-i", identity)
	cmd.Stdin = bytes.NewReader(raw)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("age -d: %v\n%s", err, stderr.String())
	}
	return out
}

func ageEncrypt(t *testing.T, bin, recipient string, plaintext []byte) string {
	t.Helper()
	cmd := exec.Command(bin, "-r", recipient)
	cmd.Stdin = bytes.NewReader(plaintext)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("age -r: %v\n%s", err, stderr.String())
	}
	return EncodeBlob(out)
}

func TestInteropSlotAndDropOpenWithAgeCLI(t *testing.T) {
	bin := ageCLI(t)
	for _, kind := range []Kind{KindHybrid, KindX25519} {
		t.Run(string(kind), func(t *testing.T) {
			path, id := writeIdentity(t, kind)
			r, _ := ParseRecipient(id.Recipient)
			key, _ := seal.NewKey()
			slot, err := WrapSlot(r, "checkout/prod", "k3f9q2", key)
			if err != nil {
				t.Fatal(err)
			}
			got := ageDecrypt(t, bin, path, slot)
			want := SlotPayload{Scope: "checkout/prod", KeyID: "k3f9q2", Key: key}.Marshal()
			if !bytes.Equal(got, want) {
				t.Fatalf("age -d slot = %q, want %q", got, want)
			}

			d := Drop{Package: "checkout", Env: "prod", Name: "x", Set: time.Unix(1700000000, 0), Value: []byte("v")}
			drop, err := WriteDrop(r, d)
			if err != nil {
				t.Fatal(err)
			}
			if got := ageDecrypt(t, bin, path, drop); !bytes.Equal(got, d.Marshal()) {
				t.Fatalf("age -d drop = %q", got)
			}
		})
	}
}

func TestInteropAgeCLIFilesOpenInCarbon(t *testing.T) {
	bin := ageCLI(t)
	for _, kind := range []Kind{KindHybrid, KindX25519} {
		t.Run(string(kind), func(t *testing.T) {
			_, id := writeIdentity(t, kind)
			key, _ := seal.NewKey()
			payload := SlotPayload{Scope: "checkout/dev", KeyID: "kabcde", Key: key}.Marshal()
			slot := ageEncrypt(t, bin, id.Recipient, payload)
			got, err := OpenSlot(slot, []Identity{id}, "checkout/dev", "kabcde")
			if err != nil || *got != *key {
				t.Fatalf("OpenSlot of an age-CLI file: %v", err)
			}

			set := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			d := Drop{Package: "checkout", Env: "dev", Name: "token", Set: set, Value: []byte("from age")}
			drop := ageEncrypt(t, bin, id.Recipient, d.Marshal())
			v, err := OpenDrop(drop, []Identity{id}, Drop{Package: "checkout", Env: "dev", Name: "token", Set: set})
			if err != nil || string(v) != "from age" {
				t.Fatalf("OpenDrop of an age-CLI file: %q %v", v, err)
			}
		})
	}
}
