package migrate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBinaryEndToEnd runs the built carbon-migrate binary, not migrate.Run:
// flag parsing, exit codes and the process environment are all real.
func TestBinaryEndToEnd(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.tmp, "bin", "carbon-migrate")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, "./cmd/carbon-migrate")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building carbon-migrate: %v\n%s", err, out)
	}
	want, ok := f.oldValue("prd", "db", "password")
	if !ok {
		t.Fatal("fixture: no prd password")
	}
	exitCode := func(err error) int {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}

	// Dry run, from a subdirectory via -C.
	out, errOut, err := f.cmd(f.tmp, f.env, nil, bin, "-C", filepath.Join(f.root, "services"), "--carbon", f.carbon)
	if code := exitCode(err); code != ExitOK || !strings.Contains(out, "Dry run complete") {
		t.Fatalf("dry run: exit %d\n%s\n%s", code, out, errOut)
	}
	if st := f.git("status", "--porcelain"); st != "" {
		t.Fatalf("dry run changed the tree:\n%s", st)
	}

	// A usage error.
	if _, _, err := f.cmd(f.root, f.env, nil, bin, "stray-argument"); exitCode(err) != ExitUsage {
		t.Fatalf("stray argument: %v", err)
	}

	// --write, with carbon found on PATH this time.
	env := append([]string{}, f.env...)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + filepath.Dir(f.carbon) + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}
	out, errOut, err = f.cmd(f.root, env, nil, bin, "--write")
	if code := exitCode(err); code != ExitOK || !strings.Contains(out, "17 of 17 value(s) read back identical") {
		t.Fatalf("--write: exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out+errOut, want) {
		t.Error("the binary printed a secret value")
	}
	got, stderr, err := f.get1("", "db", "prd", "password")
	if err != nil || got != want {
		t.Fatalf("carbon get after the binary's migration: %v %s", err, stderr)
	}
	if f.exists(".carbon/registry.prd.yaml") || f.exists(".carbon/private-key.age") {
		t.Error("old files remain")
	}
}
