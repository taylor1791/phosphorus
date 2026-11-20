package cli

import (
	"errors"
	"fmt"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/seal"
)

func init() {
	Register(&Command{
		Name:    "get",
		Group:   GroupDaily,
		Usage:   "<name> [--env <env>] [--package <name>]",
		Summary: "Print a secret's value",
		Help: `get decrypts one secret and writes its value to stdout, followed by a newline
only when stdout is a terminal. Drops and values under retired keys open
transparently; a note on stderr says so.`,
		MinArgs: 1, MaxArgs: 1,
		Run: runGet,
	})
}

type getResult struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Set   string `json:"set"`
	KeyID string `json:"key"`
	Drop  bool   `json:"drop"`
	Stale bool   `json:"stale"`
}

func runGet(c *Context) error {
	name := c.Args[0]
	if err := config.CheckSecretName(name); err != nil {
		return c.UsageErr("%v", err)
	}
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkg, err := c.Package(w)
	if err != nil {
		return err
	}
	env, err := c.Environment(w)
	if err != nil {
		return err
	}
	s, err := c.LoadScope(w, pkg, env)
	if err != nil {
		return err
	}
	if _, ok := s.Secrets.Entries[name]; !ok {
		e := &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s %s is not set", s.Name(), name)}
		if _, declared := pkg.Secrets[name]; declared {
			e.Hint = fmt.Sprintf("To set it:   carbon set %s --env %s", name, env)
		} else {
			e.Details = []string{fmt.Sprintf("%s does not declare %s either.", pkg.File, name)}
		}
		return e
	}
	o, err := c.OpenScope(w, pkg, s)
	if err != nil {
		return err
	}
	defer o.Close()
	v, err := o.Reveal(name)
	if errors.Is(err, scope.ErrNotFound) {
		return Errorf(ExitNotFound, "%s %s is not set", s.Name(), name)
	}
	if err != nil {
		return err
	}
	defer v.Zero()
	if v.Drop {
		c.Notice("note: %s is a drop, not yet reviewed; a reader's `carbon apply` promotes it.", name)
	} else if v.Stale {
		c.Notice("note: %s is unproven: it is under retired key %s, which does not record it as carried, so whoever wrote it held that key. `carbon apply --reseal-unproven` vouches for it.", name, v.KeyID)
	}
	if c.JSON() {
		return c.WriteJSON(getResult{Scope: s.Name(), Name: name, Value: string(v.Bytes),
			Set: seal.FormatTime(v.Set), KeyID: v.KeyID, Drop: v.Drop, Stale: v.Stale})
	}
	if _, err := c.Stdout.Write(v.Bytes); err != nil {
		return err
	}
	if c.StdoutIsTerminal {
		fmt.Fprintln(c.Stdout)
	}
	return nil
}
