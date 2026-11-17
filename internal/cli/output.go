package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/policy"
)

// Context is what a command runs with.
type Context struct {
	IO
	Global  Global
	Command *Command
	// Flags holds global and command flags. Read a command flag with
	// c.Bool("generate"), c.String("name") or c.List("environments").
	Flags *flag.FlagSet
	// Args are the positionals, flags removed.
	Args []string
	// ArgsLenAtDash is the number of positionals before "--", or -1.
	ArgsLenAtDash int

	ws *Workspace
	// Loaded once per command (see TrunkPolicy, WorktreePolicy, Identities).
	trunkPol *policy.Policy
	trunkErr error
	wtPol    *policy.Policy
	ids      []agewrap.Identity
	// sealing is set by commands that seal under an opened key (set,
	// edit): see checkPin.
	sealing bool
}

// JSON reports whether --json was given.
func (c *Context) JSON() bool { return c.Global.JSON }

// Printf writes human output to stdout. It writes nothing under --json, so
// a command can print progress and still emit one JSON document.
func (c *Context) Printf(format string, args ...any) {
	if !c.JSON() {
		fmt.Fprintf(c.Stdout, format, args...)
	}
}

// Notice writes a diagnostic line to stderr (also under --json).
func (c *Context) Notice(format string, args ...any) {
	fmt.Fprintf(c.Stderr, format, args...)
	if !strings.HasSuffix(format, "\n") {
		fmt.Fprintln(c.Stderr)
	}
}

// WriteJSON writes v as the command's one JSON document on stdout.
func (c *Context) WriteJSON(v any) error {
	enc := json.NewEncoder(c.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Output prints human output with fn, or v as JSON under --json.
func (c *Context) Output(v any, human func(w io.Writer)) error {
	if c.JSON() {
		return c.WriteJSON(v)
	}
	human(c.Stdout)
	return nil
}

// Table writes rows as aligned columns separated by at least three spaces.
// Trailing empty cells are dropped so lines have no trailing whitespace.
func Table(w io.Writer, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, r := range rows {
		for len(r) > 0 && r[len(r)-1] == "" {
			r = r[:len(r)-1]
		}
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
}

// jsonError is the --json shape of an error.
type jsonError struct {
	Error struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Details []string `json:"details,omitempty"`
		Hint    string   `json:"hint,omitempty"`
	} `json:"error"`
}

func (c *Context) printError(e *Error) {
	if e.silent {
		return
	}
	if c.JSON() {
		var je jsonError
		je.Error.Code, je.Error.Message, je.Error.Details, je.Error.Hint = e.Code, e.Message, e.Details, e.Hint
		c.WriteJSON(je)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "error: %s\n", e.Message)
	if len(e.Details) > 0 {
		b.WriteString("\n")
		for _, d := range e.Details {
			fmt.Fprintf(&b, "  %s\n", d)
		}
	}
	if e.Hint != "" {
		b.WriteString("\n")
		for _, l := range strings.Split(e.Hint, "\n") {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	io.WriteString(c.Stderr, b.String())
}
