package cli

import (
	"fmt"
	"io"

	"github.com/taylor1791/phosphorus/internal/seal"
)

func init() {
	Register(&Command{
		Name:    "ls",
		Group:   GroupDaily,
		Usage:   "[--env <env>] [--package <name>]",
		Summary: "List secret names and their state",
		Help: `ls lists the package's declared and stored secrets in one environment, with
no key needed. States: sealed (set by a reader), drop (in the inbox, not yet
reviewed), stale (under a retired key: the author is unproven, since a
removed reader may still hold that key), unset (declared, no value), and
undeclared (stored, not declared).`,
		Run: runLs,
	})
}

type lsEntry struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Declared bool   `json:"declared"`
	Stored   bool   `json:"stored"`
	Drop     bool   `json:"drop"`
	Private  bool   `json:"private"`
	// Unproven: under a retired key, so its author is not proven to be a
	// current reader. SetAfterRetired: and set after that key was retired.
	Unproven        bool   `json:"unproven"`
	SetAfterRetired bool   `json:"set_after_retired"`
	KeyID           string `json:"key,omitempty"`
	Set             string `json:"set,omitempty"`
}

type lsResult struct {
	Scope   string    `json:"scope"`
	HasKey  bool      `json:"has_key"`
	Secrets []lsEntry `json:"secrets"`
}

func runLs(c *Context) error {
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
	res := lsResult{Scope: s.Name(), HasKey: s.HasKey(), Secrets: []lsEntry{}}
	for _, st := range s.List(pkg.Secrets) {
		e := lsEntry{Name: st.Name, State: st.State(), Declared: st.Declared, Stored: st.Stored,
			Drop: st.Drop, Private: st.Private, KeyID: st.KeyID,
			Unproven: st.Unproven, SetAfterRetired: st.SetAfterRetired}
		if st.Stored {
			e.Set = seal.FormatTime(st.Set)
		}
		res.Secrets = append(res.Secrets, e)
	}
	return c.Output(res, func(out io.Writer) {
		if len(res.Secrets) == 0 {
			fmt.Fprintf(out, "%s declares no secrets.\n", s.Name())
			return
		}
		fmt.Fprintf(out, "%s\n\n", s.Name())
		rows := [][]string{{"NAME", "STATE", "SET", "KEY"}}
		for _, e := range res.Secrets {
			state := e.State
			if e.Unproven {
				state = "stale: retired key, author unproven"
				if e.SetAfterRetired {
					state += ", set after retirement"
				}
			}
			rows = append(rows, []string{e.Name, state, e.Set, e.KeyID})
		}
		Table(out, rows)
	})
}
