package tomledit

import (
	"errors"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Doc {
	t.Helper()
	d, err := Parse("test.toml", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, src)
	}
	return d
}

func p(s string) []string { return strings.Split(s, ".") }

func TestArrayAdd(t *testing.T) {
	cases := []struct {
		name, in, path, add, want string
	}{
		{"single line", "a = [\"x\", \"y\"]\n", "a", "z", "a = [\"x\", \"y\", \"z\"]\n"},
		{"single line trailing comma", "a = [\"x\", ]\n", "a", "z", "a = [\"x\", \"z\", ]\n"},
		{"empty", "a = []  # none yet\n", "a", "z", "a = [\"z\"]  # none yet\n"},
		{"literal strings", "a = ['x']\n", "a", "z", "a = ['x', \"z\"]\n"},
		{"in a table with comments",
			"# top\n[access]       # who reads\ndev = [\"@eng\"] # devs\nprod = [\"@sre\"]\n\n[secrets]\n",
			"access.prod", "lin",
			"# top\n[access]       # who reads\ndev = [\"@eng\"] # devs\nprod = [\"@sre\", \"lin\"]\n\n[secrets]\n"},
		{"multi-line with trailing comma",
			"team = [\n    \"ada\",  # first\n    \"lin\", # second\n]\nnext = 1\n", "team", "sam",
			"team = [\n    \"ada\",  # first\n    \"lin\", # second\n    \"sam\",\n]\nnext = 1\n"},
		{"multi-line without trailing comma",
			"team = [\n  \"ada\",\n  \"lin\"  # last\n]\n", "team", "sam",
			"team = [\n  \"ada\",\n  \"lin\",  # last\n  \"sam\"\n]\n"},
		{"multi-line closing on the last line",
			"team = [\n  \"ada\",\n  \"lin\"]\n", "team", "sam",
			"team = [\n  \"ada\",\n  \"lin\", \"sam\"]\n"},
		{"long form inline table",
			"[access]\nprod = { readers = [\"@sre\"], require_pq = true } # pq\n", "access.prod.readers", "machine:deploy",
			"[access]\nprod = { readers = [\"@sre\", \"machine:deploy\"], require_pq = true } # pq\n"},
		{"dotted key",
			"access.prod = [\"@sre\"]\nname = \"x\"\n", "access.prod", "ada",
			"access.prod = [\"@sre\", \"ada\"]\nname = \"x\"\n"},
		{"sub-table",
			"[access.prod]\nreaders = [\"@sre\"]\ndrops = false\n", "access.prod.readers", "ada",
			"[access.prod]\nreaders = [\"@sre\", \"ada\"]\ndrops = false\n"},
		{"quoted key",
			"[access]\n\"prod\" = [\"@sre\"]\n", "access.prod", "ada",
			"[access]\n\"prod\" = [\"@sre\", \"ada\"]\n"},
		{"CRLF", "a = [\"x\"]\r\nb = 1\r\n", "a", "z", "a = [\"x\", \"z\"]\r\nb = 1\r\n"},
		{"escaped string", "a = [\"x\\\"y\"]\n", "a", "z", "a = [\"x\\\"y\", \"z\"]\n"},
		{"string with brackets and hashes", "a = [\"]#[\", 'x,y']\n", "a", "z", "a = [\"]#[\", 'x,y', \"z\"]\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustParse(t, c.in)
			changed, err := d.ArrayAdd(p(c.path), c.add)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("not changed")
			}
			if got := string(d.Bytes()); got != c.want {
				t.Fatalf("got\n%q\nwant\n%q", got, c.want)
			}
			// Adding again is a no-op.
			changed, err = d.ArrayAdd(p(c.path), c.add)
			if err != nil || changed {
				t.Fatalf("second add: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestArrayRemove(t *testing.T) {
	cases := []struct {
		name, in, path, rm, want string
	}{
		{"first", "a = [\"x\", \"y\", \"z\"]\n", "a", "x", "a = [\"y\", \"z\"]\n"},
		{"middle", "a = [\"x\", \"y\", \"z\"]\n", "a", "y", "a = [\"x\", \"z\"]\n"},
		{"last", "a = [\"x\", \"y\", \"z\"] # c\n", "a", "z", "a = [\"x\", \"y\"] # c\n"},
		{"only", "a = [\"x\"]\n", "a", "x", "a = []\n"},
		{"only with trailing comma", "a = [ \"x\", ]\n", "a", "x", "a = [  ]\n"},
		{"twice", "a = [\"x\", \"y\", \"x\"]\n", "a", "x", "a = [\"y\"]\n"},
		{"multi-line with comment",
			"team = [\n  \"ada\", # first\n  \"sam\", # leaving\n  \"lin\",\n]\n", "team", "sam",
			"team = [\n  \"ada\", # first\n  \"lin\",\n]\n"},
		{"multi-line last without comma",
			"team = [\n  \"ada\",\n  \"sam\"\n]\n", "team", "sam",
			"team = [\n  \"ada\",\n]\n"},
		{"long form",
			"[access]\n# prod readers\nprod = { readers = [\"@sre\", \"sam\"], drops = false }\n", "access.prod.readers", "sam",
			"[access]\n# prod readers\nprod = { readers = [\"@sre\"], drops = false }\n"},
		{"dotted", "access.dev = [\"sam\", \"@eng\"]\n", "access.dev", "sam", "access.dev = [\"@eng\"]\n"},
		{"literal", "a = ['sam', 'x']\n", "a", "sam", "a = ['x']\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustParse(t, c.in)
			changed, err := d.ArrayRemove(p(c.path), c.rm)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("not changed")
			}
			if got := string(d.Bytes()); got != c.want {
				t.Fatalf("got\n%q\nwant\n%q", got, c.want)
			}
			changed, err = d.ArrayRemove(p(c.path), c.rm)
			if err != nil || changed {
				t.Fatalf("second remove: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestArrayRemoveMissing(t *testing.T) {
	d := mustParse(t, "a = [\"x\"]\n")
	if changed, err := d.ArrayRemove(p("b"), "x"); changed || err != nil {
		t.Fatalf("missing path: %v %v", changed, err)
	}
	if changed, err := d.ArrayRemove(p("a"), "y"); changed || err != nil {
		t.Fatalf("missing value: %v %v", changed, err)
	}
}

func TestRefusesUnsafeEdits(t *testing.T) {
	cases := []struct {
		name, in string
		op       func(d *Doc) error
	}{
		{"comment between inline elements", "a = [\"x\", # c\n \"y\"]\n", func(d *Doc) error {
			_, err := d.ArrayRemove(p("a"), "y")
			return err
		}},
		{"not a list", "a = \"x\"\n", func(d *Doc) error {
			_, err := d.ArrayAdd(p("a"), "y")
			return err
		}},
		{"array of tables", "[[a]]\nb = [\"x\"]\n", func(d *Doc) error {
			_, err := d.ArrayAdd(p("a.b"), "y")
			return err
		}},
		{"key inside inline table", "access = { prod = [\"x\"] }\n", func(d *Doc) error {
			_, err := d.RemoveKey(p("access.prod"))
			return err
		}},
		{"table from inline table", "access = { prod = [\"x\"] }\n", func(d *Doc) error {
			return d.SetKey(p("access"), "dev", []string{"y"})
		}},
		{"table from dotted keys", "access.prod = [\"x\"]\n", func(d *Doc) error {
			return d.SetKey(p("access"), "dev", []string{"y"})
		}},
		{"key shares a line", "[a]\nb = 1\n", func(d *Doc) error {
			// fabricate: two statements cannot share a line in valid TOML,
			// so test a key that already exists instead.
			return d.SetKey(p("a"), "b", 2)
		}},
		{"multi-line string element", "a = [\"\"\"x\"\"\"]\n", func(d *Doc) error {
			_, err := d.ArrayRemove(p("a"), "x")
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := mustParse(t, c.in)
			err := c.op(d)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %v", err)
			}
			if e.Manual == "" || !strings.Contains(e.Error(), "edit it by hand") {
				t.Fatalf("error does not say what to do by hand: %v", e)
			}
			if string(d.Bytes()) != c.in {
				t.Fatalf("document changed:\n%s", d.Bytes())
			}
		})
	}
}

func TestSetKeyAndTables(t *testing.T) {
	in := "name = \"checkout\"\n\n# Who reads this package.\n[access]\n\n# Declared secrets.\n[secrets]\nx = { description = \"d\" }\n"
	d := mustParse(t, in)
	if err := d.SetKey(p("access"), "prod", []string{"@payments", "lin"}); err != nil {
		t.Fatal(err)
	}
	want := "name = \"checkout\"\n\n# Who reads this package.\n[access]\nprod = [\"@payments\", \"lin\"]\n\n# Declared secrets.\n[secrets]\nx = { description = \"d\" }\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if err := d.SetKey(p("access"), "dev", []string{"ada"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(d.Bytes()), "prod = [\"@payments\", \"lin\"]\ndev = [\"ada\"]\n\n# Declared") {
		t.Fatalf("second key not after the first:\n%s", d.Bytes())
	}
	// Root keys go after the last root statement.
	if err := d.SetKey(nil, "extra", "v"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(d.Bytes()), "name = \"checkout\"\nextra = \"v\"\n\n# Who") {
		t.Fatalf("root key:\n%s", d.Bytes())
	}
	// A missing table is created at the end.
	d = mustParse(t, "name = \"x\"\n[secrets]\na = {}") // no trailing newline
	if err := d.SetKey(p("access"), "prod", []string{"lin"}); err != nil {
		t.Fatal(err)
	}
	if got, want := string(d.Bytes()), "name = \"x\"\n[secrets]\na = {}\n\n[access]\nprod = [\"lin\"]\n"; got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	// Quoted keys.
	if err := d.SetKey(p("access"), "odd key", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(d.Bytes()), "\"odd key\" = true\n") {
		t.Fatalf("quoted key:\n%s", d.Bytes())
	}
	// A sub-table header keeps the parent's keys above it.
	d = mustParse(t, "[access]\ndev = [\"a\"]\n\n[access.prod]\nreaders = [\"b\"]\n")
	if err := d.SetKey(p("access"), "staging", []string{"c"}); err != nil {
		t.Fatal(err)
	}
	if got, want := string(d.Bytes()), "[access]\ndev = [\"a\"]\nstaging = [\"c\"]\n\n[access.prod]\nreaders = [\"b\"]\n"; got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

func TestRemoveKey(t *testing.T) {
	in := "# person\nname = \"Sam\"\n\n[devices]\n# the laptop\nlaptop = \"age1aaa\" # main\nphone  = \"age1bbb\"\n"
	d := mustParse(t, in)
	ok, err := d.RemoveKey(p("devices.laptop"))
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if got, want := string(d.Bytes()), "# person\nname = \"Sam\"\n\n[devices]\n# the laptop\nphone  = \"age1bbb\"\n"; got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	ok, err = d.RemoveKey(p("devices.laptop"))
	if err != nil || ok {
		t.Fatalf("again: %v %v", ok, err)
	}
	// Multi-line values go with their key.
	d = mustParse(t, "a = [\n  \"x\",\n]\nb = 1\n")
	if _, err := d.RemoveKey(p("a")); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); got != "b = 1\n" {
		t.Fatalf("got %q", got)
	}
	// Dotted keys.
	d = mustParse(t, "access.prod = [\"x\"]\naccess.dev = [\"y\"]\n")
	if _, err := d.RemoveKey(p("access.prod")); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); got != "access.dev = [\"y\"]\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSetString(t *testing.T) {
	d := mustParse(t, "name = 'old' # the name\n[env]\nA = \"${old.x}\"\nB = { x = \"y\" }\n")
	if err := d.SetString(p("name"), "new"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetString(p("env.A"), "${new.x}"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetString(p("env.B.x"), "z"); err != nil {
		t.Fatal(err)
	}
	if got, want := string(d.Bytes()), "name = \"new\" # the name\n[env]\nA = \"${new.x}\"\nB = { x = \"z\" }\n"; got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	if err := d.SetString(p("env.C"), "x"); err == nil {
		t.Fatal("set a missing string")
	}
}

func TestReaders(t *testing.T) {
	d := mustParse(t, "[access]\ndev = [\"a\", \"b\"]\nprod = { readers = [\"c\"], require_pq = true }\n")
	if got := d.Kind("access", "dev"); got != "array" {
		t.Fatal(got)
	}
	if got := d.Kind("access", "prod"); got != "table" {
		t.Fatal(got)
	}
	if s, ok := d.Strings("access", "prod", "readers"); !ok || len(s) != 1 || s[0] != "c" {
		t.Fatal(s, ok)
	}
	if got := d.Keys("access"); strings.Join(got, ",") != "dev,prod" {
		t.Fatal(got)
	}
	if d.Kind("nope") != "" {
		t.Fatal("missing path has a kind")
	}
}

func TestCRLFIsPreserved(t *testing.T) {
	d := mustParse(t, "[access]\r\nprod = [\r\n  \"a\",\r\n  \"b\"\r\n]\r\n")
	if _, err := d.ArrayAdd(p("access.prod"), "sam"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetKey(p("access"), "dev", []string{"x"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetKey(p("secrets"), "k", "v"); err != nil {
		t.Fatal(err)
	}
	want := "[access]\r\nprod = [\r\n  \"a\",\r\n  \"b\",\r\n  \"sam\"\r\n]\r\ndev = [\"x\"]\r\n\r\n[secrets]\r\nk = \"v\"\r\n"
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(strings.ReplaceAll(want, "\r\n", ""), "\n") {
		t.Fatal("bare LF")
	}
	d = mustParse(t, "[access]\r\nprod = [\r\n  \"a\",\r\n  \"sam\",\r\n]\r\n")
	if _, err := d.ArrayRemove(p("access.prod"), "sam"); err != nil {
		t.Fatal(err)
	}
	if got := string(d.Bytes()); got != "[access]\r\nprod = [\r\n  \"a\",\r\n]\r\n" {
		t.Fatalf("%q", got)
	}
}

// Removing every occurrence is one operation: if one occurrence cannot be
// removed, none is.
func TestArrayRemoveIsAllOrNothing(t *testing.T) {
	in := "[access]\nprod = [\"\"\"sam\"\"\", 'sam', \"s\\u0061m\"]\n"
	d := mustParse(t, in)
	if _, err := d.ArrayRemove(p("access.prod"), "sam"); err == nil {
		t.Fatal("removed a multi-line string element")
	}
	if got := string(d.Bytes()); got != in {
		t.Fatalf("half-edited:\n%q", got)
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	if _, err := Parse("bad.toml", []byte("a = [")); err == nil {
		t.Fatal("parsed invalid TOML")
	}
}

func TestScannerHandlesEverything(t *testing.T) {
	// A file with every kind of value; adding to one list must leave the
	// rest byte-for-byte alone.
	in := `# header comment
title = "x" # trailing
multi = """
a "quoted" ] # not a comment
"""
lit = '''
also ] [ # not
'''
date = 1979-05-27 07:32:00Z
num = 1_000
float = 3.14
bool = true
nested = { a = { b = [1, 2] }, c = "}" }
arr_of_arr = [[1, 2], ["x"]]

[table."quoted.key"]
v = ["a"] # this one

[[products]]
name = "p"
`
	d := mustParse(t, in)
	if _, err := d.ArrayAdd([]string{"table", "quoted.key", "v"}, "b"); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(in, `v = ["a"] # this one`, `v = ["a", "b"] # this one`, 1)
	if got := string(d.Bytes()); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
