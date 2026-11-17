package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/tomledit"
)

func init() {
	Register(&Command{
		Name:    "request",
		Group:   GroupAccess,
		Usage:   "<package> [--env <env>] [--as <reader>]",
		Summary: "Propose yourself as a reader of a package in policy",
		Help: `request edits the package's carbon.toml in the working tree to add you (your
person, from your identity) to its [access] entry for the environment, or
the reader given with --as (@team, person, or machine:name). If the package
has no entry for the environment, request creates one from the workspace
default plus you, so nobody who reads it today loses access.

It changes policy only, never keys. Open a pull request with the change;
once it merges, a current reader runs "carbon apply" to grant access.`,
		MinArgs: 1, MaxArgs: 1,
		Flags: func(fs *flag.FlagSet) {
			fs.String("as", "", "the reader to propose instead of yourself: @team, person, or machine:name")
		},
		Run: runRequest,
	})
}

type requestResult struct {
	Package   string   `json:"package"`
	Env       string   `json:"env"`
	Reader    string   `json:"reader"`
	File      string   `json:"file"`
	Changed   bool     `json:"changed"`
	Created   bool     `json:"created_entry"`
	Before    []string `json:"readers_before"`
	After     []string `json:"readers_after"`
	AlreadyBy string   `json:"already_via,omitempty"`
}

func runRequest(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	name := c.Args[0]
	pkg, ok := pkgs[name]
	if !ok {
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no package named %q", name),
			Hint: "Package names are the name = \"...\" lines in each carbon.toml."}
	}
	if pkg.File == config.FileName {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("%s is the workspace root, whose [access] is the default for every package", name),
			Details: []string{"Adding a reader there would grant every package that has no entry of its own."},
			Hint:    "If that is what you want, edit [access] in carbon.toml by hand and open a pull request."}
	}
	env, err := c.Environment(w)
	if err != nil {
		return err
	}
	wpol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}

	reader := c.String("as")
	if reader == "" {
		ids, err := c.Identities(true)
		if err != nil {
			return err
		}
		me := Me(wpol, ids)
		if len(me) == 0 {
			return &Error{Code: ExitNotFound, Message: "your identity is not in .carbon/people or .carbon/machines",
				Hint: "Add yourself first:   carbon join\nOr name the reader:   carbon request " + name + " --as <reader>"}
		}
		reader = me[0].Person
		if me[0].Machine {
			reader = me[0].ID
		}
	} else if err := config.CheckReader(reader); err != nil {
		return c.UsageErr("--as: %v", err)
	}
	if err := requestReaderExists(wpol, reader); err != nil {
		return err
	}

	sa, err := wpol.Scope(name, env)
	if err != nil {
		return err
	}
	res := requestResult{Package: name, Env: env, Reader: reader, File: pkg.File, Before: sa.Readers}
	if res.Before == nil {
		res.Before = []string{}
	}
	if via := requestAlreadyReads(wpol, sa, reader); via != "" {
		res.AlreadyBy, res.After = via, res.Before
		return c.Output(res, func(out io.Writer) {
			fmt.Fprintf(out, "%s already reads %s in %s (%s). Nothing to change.\n", reader, name, env, via)
			fmt.Fprintln(out, "If you cannot read it yet, ask a current reader to run:   carbon apply")
		})
	}

	abs := filepath.Join(w.Root, filepath.FromSlash(pkg.File))
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	doc, err := tomledit.Parse(pkg.File, data)
	if err != nil {
		return editErr(err)
	}
	switch doc.Kind("access", env) {
	case "array":
		_, err = doc.ArrayAdd([]string{"access", env}, reader)
	case "table":
		_, err = doc.ArrayAdd([]string{"access", env, "readers"}, reader)
	case "":
		readers := []string{}
		if wa, ok := w.Config.Access[env]; ok {
			readers = append(readers, wa.Readers...)
		}
		readers = append(readers, reader)
		res.Created = true
		err = doc.SetKey([]string{"access"}, env, readers)
	default:
		err = &tomledit.Error{File: pkg.File, Reason: "[access] " + env + " is neither a list nor a table",
			Manual: fmt.Sprintf("make it a list of readers that includes %q", reader)}
	}
	if err != nil {
		return editErr(err)
	}
	res.After = append(append([]string{}, res.Before...), reader)
	res.Changed = true

	if !c.JSON() {
		fmt.Fprintf(c.Stdout, "Plan: in %s, propose %s as a reader of %s in %s.\n\n", pkg.File, reader, name, env)
		Table(c.Stdout, [][]string{
			{"  readers now", requestList(res.Before)},
			{"  readers after", requestList(res.After)},
		})
		if res.Created {
			fmt.Fprintf(c.Stdout, "\n%s has no [access] entry for %s yet, so the new entry starts from the\nworkspace default and nobody who reads it today loses access.\n", name, env)
		}
		fmt.Fprintln(c.Stdout)
	}
	if err := c.Confirm("Edit " + pkg.File + "?"); err != nil {
		return err
	}
	if err := os.WriteFile(abs, doc.Bytes(), 0o644); err != nil {
		return err
	}
	return c.Output(res, func(out io.Writer) {
		fmt.Fprintf(out, "Edited %s: [access] %s now names %s.\n\n", pkg.File, env, requestList(res.After))
		fmt.Fprintln(out, "Next: open a pull request with this change. The package's code owners review it;")
		fmt.Fprintf(out, "once it merges, a current reader of %s runs `carbon apply` to grant access.\n", config.ScopeName(name, env))
	})
}

func requestList(rs []string) string {
	if len(rs) == 0 {
		return "(nobody)"
	}
	return strings.Join(rs, ", ")
}

// requestReaderExists checks that a reader names a team, person or machine
// in the working tree.
func requestReaderExists(pol *policy.Policy, reader string) error {
	kind, n, err := config.ParseReader(reader)
	if err != nil {
		return err
	}
	ok := false
	hint := "carbon join"
	switch kind {
	case config.ReaderTeam:
		_, ok = pol.Teams[n]
		hint = "Teams are listed in " + config.TeamsFile + "."
	case config.ReaderPerson:
		_, ok = pol.People[n]
		hint = "They join with:   carbon join --person " + n
	case config.ReaderMachine:
		_, ok = pol.Machines[n]
		hint = "Create it with:   carbon join --machine " + n
	}
	if !ok {
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s is not a %s in this workspace", reader, kind), Hint: hint}
	}
	return nil
}

// requestAlreadyReads says how reader already reads the scope, or "".
func requestAlreadyReads(pol *policy.Policy, sa *policy.ScopeAccess, reader string) string {
	for _, r := range sa.Readers {
		if r == reader {
			return "named in " + applyReadersFrom(sa)
		}
	}
	kind, n, _ := config.ParseReader(reader)
	if kind != config.ReaderPerson {
		return ""
	}
	devs := pol.PersonDevices(n)
	if len(devs) == 0 {
		return ""
	}
	var via []string
	for _, d := range devs {
		w, ok := sa.Why[d.ID]
		if !ok {
			return ""
		}
		via = w
	}
	return "via " + strings.Join(via, ", ")
}

// editErr turns a tomledit refusal into the design's error shape.
func editErr(err error) error {
	var te *tomledit.Error
	if errors.As(err, &te) {
		e := &Error{Code: ExitError, Message: fmt.Sprintf("cannot edit %s safely: %s", te.File, te.Reason),
			Details: []string{"carbon edits policy files without reformatting them, and this one has a shape it will not change automatically. Nothing was written."}, Err: err}
		if te.Manual != "" {
			e.Hint = fmt.Sprintf("Edit %s by hand: %s", te.File, te.Manual)
		}
		return e
	}
	return err
}
