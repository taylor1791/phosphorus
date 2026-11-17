package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/resolve"
)

func TestMergeEnviron(t *testing.T) {
	res := &resolve.Result{Vars: []resolve.Var{{Name: "A", Value: []byte("new")}, {Name: "b", Value: []byte("x=y")}}}
	got := mergeEnviron([]string{"A=old", "a=lower", "B=upper", "PATH=/bin"}, res)
	if strings.Join(got, ";") != "a=lower;B=upper;PATH=/bin;A=new;b=x=y" {
		t.Fatalf("got %q", got)
	}
	if lookupIn(got, "PATH") != "/bin" || lookupIn(got, "b") != "x=y" || lookupIn(got, "nope") != "" {
		t.Fatal("lookupIn")
	}
}

func TestFindExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "tool")
	os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "data"), nil, 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)

	if p, err := findExecutable("tool", "relative:"+dir); err != nil || p != exe {
		t.Fatalf("PATH lookup: %q %v", p, err)
	}
	if p, err := findExecutable(exe, ""); err != nil || p != exe {
		t.Fatalf("path: %q %v", p, err)
	}
	for _, c := range []struct{ name, path, want string }{
		{"data", dir, "not in any directory on PATH"},
		{"sub", dir, "not in any directory on PATH"},
		{"tool", "", "PATH is empty"},
		{"tool", ".", "not in any directory on PATH"},
		{filepath.Join(dir, "data"), "", "is not executable"},
		{filepath.Join(dir, "sub"), "", "is a directory"},
		{filepath.Join(dir, "missing"), "", "does not exist"},
	} {
		_, err := findExecutable(c.name, c.path)
		e := AsError(err)
		if err == nil || !strings.Contains(strings.Join(e.Details, " "), c.want) || !strings.HasPrefix(e.Message, "command not found") {
			t.Errorf("%s in %q: %v %v", c.name, c.path, err, e.Details)
		}
	}
}
