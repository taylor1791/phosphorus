package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestFindCommandSkipsGlobalFlags(t *testing.T) {
	Register(&Command{Name: "zz test", Run: func(*Context) error { return nil }})
	defer delete(registry, "zz test")
	cases := []struct {
		args []string
		cmd  string
		rest []string
	}{
		{[]string{"set", "x"}, "set", []string{"x"}},
		{[]string{"--env", "prod", "set", "x"}, "set", []string{"--env", "prod", "x"}},
		{[]string{"-C", "dir", "--json", "get", "x", "--env=dev"}, "get", []string{"-C", "dir", "--json", "x", "--env=dev"}},
		{[]string{"zz", "test", "a"}, "zz test", []string{"a"}},
		{[]string{"--", "set"}, "", []string{"--", "set"}},
		{[]string{"nope"}, "", []string{"nope"}},
	}
	for _, c := range cases {
		cmd, rest := findCommand(c.args)
		name := ""
		if cmd != nil {
			name = cmd.Name
		}
		if name != c.cmd || strings.Join(rest, " ") != strings.Join(c.rest, " ") {
			t.Errorf("findCommand(%v) = %q %v, want %q %v", c.args, name, rest, c.cmd, c.rest)
		}
	}
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, IO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Cwd: t.TempDir()})
	return code, out.String(), errb.String()
}

func TestRunInterleavesFlagsAndChecksArgs(t *testing.T) {
	var got *Context
	Register(&Command{
		Name: "zz echo", MinArgs: 1, MaxArgs: -1,
		Flags: func(fs *flag.FlagSet) { fs.Bool("loud", false, "") },
		Run:   func(c *Context) error { got = c; return nil },
	})
	defer delete(registry, "zz echo")

	code, _, stderr := run(t, "--json", "zz", "echo", "a", "--loud", "--env", "prod", "b", "--", "c", "--d")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	loud := got.Bool("loud")
	if !got.Global.JSON || !loud || got.Global.Env != "prod" ||
		strings.Join(got.Args, ",") != "a,b,c,--d" || got.ArgsLenAtDash != 2 {
		t.Fatalf("parsed %+v args %v dash %d", got.Global, got.Args, got.ArgsLenAtDash)
	}
	if code, _, _ := run(t, "zz", "echo"); code != ExitUsage {
		t.Fatalf("missing arg: %d", code)
	}
	if code, _, _ := run(t, "zz", "echo", "a", "--quiet"); code != ExitUsage {
		t.Fatalf("unknown flag: %d", code)
	}
}

func TestErrorRendering(t *testing.T) {
	Register(&Command{Name: "zz fail", Run: func(c *Context) error {
		return Errorf(ExitNoAccess, "you cannot read checkout in prod").
			WithDetail("checkout/prod is readable by @payments.", "You are ada.").
			WithHint("To ask for access:   carbon request checkout --env prod")
	}})
	defer delete(registry, "zz fail")
	code, stdout, stderr := run(t, "zz", "fail")
	want := "error: you cannot read checkout in prod\n\n  checkout/prod is readable by @payments.\n  You are ada.\n\n  To ask for access:   carbon request checkout --env prod\n"
	if code != ExitNoAccess || stderr != want || stdout != "" {
		t.Fatalf("code %d stdout %q stderr:\n%s", code, stdout, stderr)
	}
	code, stdout, _ = run(t, "zz", "fail", "--json")
	if code != ExitNoAccess || !strings.Contains(stdout, `"code": 3`) || !strings.Contains(stdout, `"hint": "To ask for access`) {
		t.Fatalf("json: %s", stdout)
	}
}

func TestConfirmAndReadSecret(t *testing.T) {
	c := &Context{IO: IO{Stdin: strings.NewReader("y\n"), Stderr: &bytes.Buffer{}}}
	if err := c.Confirm("Apply?"); AsError(err).Code != ExitNotConfirmed {
		t.Fatalf("no terminal: %v", err)
	}
	c.Global.Yes = true
	if err := c.Confirm("Apply?"); err != nil {
		t.Fatal(err)
	}
	c.Global.Yes, c.StdinIsTerminal = false, true
	if err := c.Confirm("Apply?"); err != nil {
		t.Fatalf("yes on terminal: %v", err)
	}
	c.Stdin = strings.NewReader("n\n")
	if err := c.Confirm("Apply?"); AsError(err).Code != ExitNotConfirmed {
		t.Fatalf("no: %v", err)
	}

	for in, want := range map[string]string{"v\n": "v", "v\r\n": "v", "v\n\n": "v\n", "v": "v", "": ""} {
		c := &Context{IO: IO{Stdin: strings.NewReader(in)}}
		got, err := c.ReadSecret("x")
		if err != nil || string(got) != want {
			t.Errorf("ReadSecret(%q) = %q %v", in, got, err)
		}
	}
}

func TestSanitizeAndJoinAnd(t *testing.T) {
	for in, want := range map[string]string{"Ada": "ada", "MacBook-Pro.local": "macbook-pro-local", "  x y ": "x-y", "_a_": "a"} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q", in, got)
		}
	}
	if joinAnd([]string{"a", "b", "c"}) != "a, b, and c" || joinAnd([]string{"a", "b"}) != "a and b" {
		t.Error("joinAnd")
	}
}
