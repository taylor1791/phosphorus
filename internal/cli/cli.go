// Package cli is carbon's command line. Each command lives in its own file
// and registers itself in init() with [Register], so commands can be added
// in parallel without editing a shared list. See docs/contributing.md.
//
// A command receives a [*Context]: parsed global flags, its own flags and
// positionals, stdio, and helpers to resolve the workspace, package,
// environment, policy, identities and scopes, to prompt, and to print human
// or JSON output. A command returns an error; return an [*Error] to choose
// the exit code, message, detail lines and hint.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Version is the carbon version, set at build time with
// -ldflags "-X github.com/taylor1791/phosphorus/internal/cli.Version=...".
var Version = "1.0.0-dev"

// Command is one carbon subcommand.
type Command struct {
	// Name is the command word, or two words for a subcommand ("env use").
	Name string
	// Usage is what follows the name in the usage line, e.g. "<name>".
	Usage string
	// Summary is one line for `carbon help`.
	Summary string
	// Help is the longer description for `carbon help <command>`.
	Help string
	// MinArgs and MaxArgs bound the positionals (after flags are removed).
	// MaxArgs < 0 means no upper bound. The zero value accepts none.
	MinArgs, MaxArgs int
	// Flags adds the command's own flags. Global flags are added for you.
	Flags func(fs *flag.FlagSet)
	// Run does the work.
	Run func(c *Context) error
	// Hidden commands are left out of `carbon help`.
	Hidden bool
	// StopAtPositional ends flag parsing at the first positional argument
	// (as well as at "--"), for commands such as run whose positionals are
	// another program's command line.
	StopAtPositional bool
}

var registry = map[string]*Command{}

// Register adds a command. It panics on a duplicate name, so a clash between
// two files shows up the first time any test runs.
func Register(c *Command) {
	if c.Name == "" || c.Run == nil {
		panic("cli.Register: command needs Name and Run")
	}
	if _, dup := registry[c.Name]; dup {
		panic("cli.Register: duplicate command " + c.Name)
	}
	registry[c.Name] = c
}

// Lookup returns a registered command.
func Lookup(name string) (*Command, bool) {
	c, ok := registry[name]
	return c, ok
}

// Commands returns every registered command, sorted by name.
func Commands() []*Command {
	out := make([]*Command, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Global holds the flags every command accepts, before or after the
// subcommand and interleaved with positionals.
type Global struct {
	Env     string // --env
	JSON    bool   // --json
	Yes     bool   // --yes
	Dir     string // -C
	NoColor bool   // --no-color
	Package string // --package
	Help    bool   // --help / -h
	Version bool   // --version
}

// global flags that take a value, for locating the command word.
var globalValueFlags = map[string]bool{"--env": true, "-env": true, "-C": true, "--C": true, "--chdir": true, "-chdir": true, "--package": true, "-package": true}

func addGlobalFlags(fs *flag.FlagSet, g *Global) {
	fs.StringVar(&g.Env, "env", "", "environment (default: CARBON_ENV, `carbon env use`, then default_environment)")
	fs.BoolVar(&g.JSON, "json", false, "print one JSON document on stdout")
	fs.BoolVar(&g.Yes, "yes", false, "do not ask for confirmation")
	fs.StringVar(&g.Dir, "C", "", "run as if started in `dir`")
	fs.StringVar(&g.Dir, "chdir", "", "")
	fs.BoolVar(&g.NoColor, "no-color", false, "do not use colour")
	fs.StringVar(&g.Package, "package", "", "package `name` (default: the nearest carbon.toml with a name)")
	fs.BoolVar(&g.Help, "help", false, "show help")
	fs.BoolVar(&g.Help, "h", false, "")
	fs.BoolVar(&g.Version, "version", false, "print the version")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// IO is the process environment a command runs in. Tests and Main fill it.
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	// Environ is the whole process environment ("K=V"), for `run` and to
	// tell an empty variable from an unset one. Nil means empty.
	Environ func() []string
	Cwd     string
	Now     func() time.Time
	// StdinIsTerminal reports whether prompts can be shown. Main sets it
	// from the real stdin.
	StdinIsTerminal bool
	// StdoutIsTerminal decides, for example, whether `get` appends a newline.
	StdoutIsTerminal bool
}

// Main runs carbon with the process's stdio and returns the exit code.
func Main(args []string) int {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitError
	}
	return Run(args, IO{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, Environ: os.Environ, Cwd: cwd, Now: time.Now,
		StdinIsTerminal:  isTerminal(os.Stdin),
		StdoutIsTerminal: isTerminal(os.Stdout),
	})
}

// Run parses args, runs the command, prints any error, and returns the exit
// code.
func Run(args []string, io IO) int {
	if io.Now == nil {
		io.Now = time.Now
	}
	if io.Getenv == nil {
		io.Getenv = func(string) string { return "" }
	}
	c := &Context{IO: io}
	err := c.dispatch(args)
	if err == nil {
		return ExitOK
	}
	e := AsError(err)
	c.printError(e)
	return e.Code
}

func (c *Context) dispatch(args []string) error {
	cmd, rest := findCommand(args)

	fs := newFlagSet("carbon")
	addGlobalFlags(fs, &c.Global)
	if cmd != nil && cmd.Flags != nil {
		cmd.Flags(fs)
	}
	parse := parseInterspersed
	if cmd != nil && cmd.StopAtPositional {
		parse = parseUntilPositional
	}
	pos, dash, err := parse(fs, rest)
	if err != nil {
		e := Errorf(ExitUsage, "%s", err)
		if cmd != nil {
			e.Hint = "Usage: " + usageLine(cmd) + "\nSee `carbon help " + cmd.Name + "`."
		} else {
			e.Hint = "See `carbon help`."
		}
		return e
	}
	c.Flags, c.Args, c.Command, c.ArgsLenAtDash = fs, pos, cmd, dash

	switch {
	case c.Global.Version:
		fmt.Fprintf(c.Stdout, "carbon %s\n", Version)
		return nil
	case cmd == nil && len(c.Args) > 0:
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown command %q", c.Args[0]),
			Hint: "See `carbon help` for the list of commands."}
	case cmd == nil:
		c.printHelp(c.Stdout, nil)
		if c.Global.Help {
			return nil
		}
		return &Error{Code: ExitUsage, Message: "no command given", silent: true}
	case c.Global.Help:
		c.printHelp(c.Stdout, cmd)
		return nil
	}
	if n := len(c.Args); n < cmd.MinArgs || (cmd.MaxArgs >= 0 && n > cmd.MaxArgs) {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("%s takes %s", cmd.Name, argCount(cmd)),
			Hint: "Usage: " + usageLine(cmd)}
	}
	if c.Global.Dir != "" {
		d := c.Global.Dir
		if !filepath.IsAbs(d) {
			d = filepath.Join(c.Cwd, d)
		}
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			return Errorf(ExitUsage, "-C %s: not a directory", c.Global.Dir)
		}
		c.Cwd = d
	}
	return cmd.Run(c)
}

// findCommand locates the command word(s) among args, skipping global
// flags and their values, and returns args without them.
func findCommand(args []string) (*Command, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return nil, args
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if globalValueFlags[a] {
				i++
			}
			continue
		}
		rest := append([]string(nil), args[:i]...)
		if i+1 < len(args) {
			if cmd, ok := registry[a+" "+args[i+1]]; ok {
				return cmd, append(rest, args[i+2:]...)
			}
		}
		if cmd, ok := registry[a]; ok {
			return cmd, append(rest, args[i+1:]...)
		}
		return nil, args
	}
	return nil, args
}

func usageLine(cmd *Command) string {
	s := "carbon " + cmd.Name
	if cmd.Usage != "" {
		s += " " + cmd.Usage
	}
	return s
}

func argCount(cmd *Command) string {
	switch {
	case cmd.MaxArgs == 0:
		return "no arguments"
	case cmd.MinArgs == cmd.MaxArgs:
		if cmd.MinArgs == 1 {
			return "exactly one argument"
		}
		return fmt.Sprintf("exactly %d arguments", cmd.MinArgs)
	case cmd.MaxArgs < 0:
		return fmt.Sprintf("at least %d arguments", cmd.MinArgs)
	}
	return fmt.Sprintf("%d to %d arguments", cmd.MinArgs, cmd.MaxArgs)
}

func (c *Context) printHelp(w io.Writer, cmd *Command) {
	if cmd != nil {
		fmt.Fprintf(w, "Usage: %s\n\n%s\n", usageLine(cmd), cmd.Summary)
		if cmd.Help != "" {
			fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(cmd.Help))
		}
		fmt.Fprint(w, "\nFlags:\n")
		printFlags(w, c.Flags)
		return
	}
	fmt.Fprint(w, "carbon: encrypted secrets for monorepos, stored in the repo.\n\nUsage: carbon <command> [flags]\n\nCommands:\n")
	var rows [][]string
	for _, cmd := range Commands() {
		if !cmd.Hidden {
			rows = append(rows, []string{"  " + cmd.Name, cmd.Summary})
		}
	}
	Table(w, rows)
	fmt.Fprint(w, "\nGlobal flags: --env <name>, --package <name>, --json, --yes, -C <dir>, --no-color\n")
	fmt.Fprint(w, "Run `carbon help <command>` for details.\n")
}

func init() {
	Register(&Command{
		Name:    "help",
		Usage:   "[command]",
		Summary: "Show help for carbon or a command",
		MaxArgs: 2,
		Run: func(c *Context) error {
			if len(c.Args) == 0 {
				c.printHelp(c.Stdout, nil)
				return nil
			}
			name := strings.Join(c.Args, " ")
			cmd, ok := registry[name]
			if !ok {
				return &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown command %q", name), Hint: "See `carbon help`."}
			}
			fs := newFlagSet(cmd.Name)
			addGlobalFlags(fs, &Global{})
			if cmd.Flags != nil {
				cmd.Flags(fs)
			}
			c.Flags = fs
			c.printHelp(c.Stdout, cmd)
			return nil
		},
	})
	Register(&Command{
		Name:    "version",
		Summary: "Print the carbon version",
		Run: func(c *Context) error {
			if c.JSON() {
				return c.WriteJSON(map[string]string{"version": Version})
			}
			fmt.Fprintf(c.Stdout, "carbon %s\n", Version)
			return nil
		},
	})
}
