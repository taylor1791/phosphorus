package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Flags are parsed with the standard library's flag package, wrapped so that
// flags may come before or after the subcommand and between positionals,
// and "--name" and "-name" are both accepted. (pflag would pull in package
// net, which forces cgo on toolchains that default CGO_ENABLED=1.)

// parseInterspersed parses args with fs, allowing positionals and flags in
// any order. Everything after "--" is positional. It returns the
// positionals and how many came before "--" (-1 when there was none).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, int, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, -1, err
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" && !isFlagValue(fs, args, consumed-1) {
			dash := len(pos)
			return append(pos, rest...), dash, nil
		}
		if len(rest) == 0 {
			return pos, -1, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// parseUntilPositional parses flags up to the first positional or "--";
// everything from there on is positional, flags included. The dash index
// is 0 when "--" ended the flags, else -1.
func parseUntilPositional(fs *flag.FlagSet, args []string) ([]string, int, error) {
	if err := fs.Parse(args); err != nil {
		return nil, -1, err
	}
	rest := fs.Args()
	consumed := len(args) - len(rest)
	if consumed > 0 && args[consumed-1] == "--" && !isFlagValue(fs, args, consumed-1) {
		return rest, 0, nil
	}
	return rest, -1, nil
}

// isFlagValue reports whether args[i] is the value of a preceding
// non-boolean flag (as in "--env --").
func isFlagValue(fs *flag.FlagSet, args []string, i int) bool {
	if i == 0 {
		return false
	}
	prev := strings.TrimLeft(args[i-1], "-")
	if strings.Contains(prev, "=") || !strings.HasPrefix(args[i-1], "-") {
		return false
	}
	f := fs.Lookup(prev)
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !(ok && b.IsBoolFlag())
}

// Bool returns a boolean flag's value (false if the command has no such
// flag).
func (c *Context) Bool(name string) bool {
	if f := c.Flags.Lookup(name); f != nil {
		if g, ok := f.Value.(flag.Getter); ok {
			b, _ := g.Get().(bool)
			return b
		}
	}
	return false
}

// String returns a string flag's value ("" if the command has no such flag).
func (c *Context) String(name string) string {
	if f := c.Flags.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

// List returns a comma-separated string flag split into trimmed, non-empty
// items.
func (c *Context) List(name string) []string {
	var out []string
	for _, s := range strings.Split(c.String(name), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Changed reports whether a flag was given on the command line.
func (c *Context) Changed(name string) bool {
	set := false
	c.Flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// printFlags writes "  --name value   usage" lines, one per flag, skipping
// aliases (flags whose usage is empty).
func printFlags(w io.Writer, fs *flag.FlagSet) {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if f.Usage != "" {
			names = append(names, f.Name)
		}
	})
	sort.Strings(names)
	var rows [][]string
	for _, n := range names {
		f := fs.Lookup(n)
		dash := "--"
		if len(n) == 1 {
			dash = "-"
		}
		arg, usage := flag.UnquoteUsage(f)
		left := "  " + dash + n
		if arg != "" {
			left += " " + arg
		}
		if f.DefValue != "" && f.DefValue != "false" {
			usage += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		rows = append(rows, []string{left, usage})
	}
	Table(w, rows)
}
