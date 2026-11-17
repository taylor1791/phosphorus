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

// Every command has a summary, a group, and a usage line naming each of its
// own flags; `carbon help` and `carbon <cmd> --help` work for each.
func TestHelpMatchesFlags(t *testing.T) {
	global := newFlagSet("global")
	addGlobalFlags(global, &Global{})
	for _, cmd := range Commands() {
		if cmd.Summary == "" || strings.Contains(cmd.Summary, "\n") {
			t.Errorf("%s: summary must be one line", cmd.Name)
		}
		if cmd.group() == "" {
			t.Errorf("%s: no help group", cmd.Name)
		}
		fs := newFlagSet(cmd.Name)
		if cmd.Flags != nil {
			cmd.Flags(fs)
		}
		usage := usageLine(cmd)
		fs.VisitAll(func(f *flag.Flag) {
			if f.Usage == "" || global.Lookup(f.Name) != nil {
				return
			}
			if !strings.Contains(usage, "--"+f.Name) && !strings.Contains(usage, "-"+f.Name+" ") {
				t.Errorf("%s: usage %q does not name its flag --%s", cmd.Name, usage, f.Name)
			}
		})
		for _, args := range [][]string{append(strings.Fields(cmd.Name), "--help"), append([]string{"help"}, strings.Fields(cmd.Name)...)} {
			code, out, _ := run(t, args...)
			if code != 0 || !strings.Contains(out, "Usage: "+usage) {
				t.Errorf("carbon %s: exit %d\n%s", strings.Join(args, " "), code, out)
			}
		}
	}
	code, out, _ := run(t, "help")
	for _, want := range []string{"Daily use:", "Access:", "Inspection:", "Setup:", "Exit codes:", "  4     check found errors"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("carbon help lacks %q:\n%s", want, out)
		}
	}
	code, _, errOut := run(t, "stauts")
	if code != ExitUsage || !strings.Contains(errOut, "Did you mean `carbon status`?") {
		t.Errorf("unknown command: exit %d\n%s", code, errOut)
	}
	if code, out, _ := run(t, "--version"); code != 0 || !strings.HasPrefix(out, "carbon ") {
		t.Errorf("--version: exit %d %q", code, out)
	}
}
