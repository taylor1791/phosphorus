package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
)

func init() {
	Register(&Command{
		Name:    "who",
		Group:   GroupInspection,
		Usage:   "<package> [--env <env>]",
		Summary: "Explain who reads a package, and through which rule",
		Help: `who lists the people and machines that policy names as readers of a
package, with their devices and the access entry that grants each one: a team
("via @payments") or a direct entry ("named in services/checkout/carbon.toml").
Without --env it shows every environment.

It reads policy from the working tree and needs no key. Policy is not access:
a reader gets a slot only after the policy merges and a reader runs
"carbon apply" (see carbon status and carbon check).`,
		MinArgs: 1, MaxArgs: 1,
		Run: runWho,
	})
	Register(&Command{
		Name:    "access",
		Group:   GroupInspection,
		Usage:   "<person|machine:name> [--env <env>]",
		Summary: "Explain what a person or machine reads, and through which rule",
		Help: `access is the reverse of "carbon who": every scope policy lets a person (all
of their devices) or a machine read, and the access entry that grants it.

It reads policy from the working tree and needs no key.`,
		MinArgs: 1, MaxArgs: 1,
		Run: runAccess,
	})
}

type whoPrincipal struct {
	Principal string   `json:"principal"`
	Machine   bool     `json:"machine"`
	Devices   []string `json:"devices"`
	// Via lists the access entries that grant it, e.g. "@payments" or
	// "machine:deploy-checkout".
	Via []string `json:"via"`
	// Skipped lists devices policy names that cannot hold a slot because
	// the scope requires post-quantum keys and theirs is not hybrid.
	Skipped []string `json:"skipped_not_pq,omitempty"`
	rule    string
}

type whoScope struct {
	Scope       string         `json:"scope"`
	Package     string         `json:"package"`
	Env         string         `json:"env"`
	Readers     []string       `json:"readers"`
	ReadersFrom string         `json:"readers_from"`
	RequirePQ   bool           `json:"require_pq"`
	Drops       bool           `json:"drops"`
	Principals  []whoPrincipal `json:"principals"`
	Unresolved  []string       `json:"unresolved,omitempty"`
}

// explainScope groups a scope's devices by person or machine.
func explainScope(sa *policy.ScopeAccess) whoScope {
	ws := whoScope{Scope: sa.Name(), Package: sa.Package, Env: sa.Env, Readers: sa.Readers,
		ReadersFrom: sa.ReadersFrom, RequirePQ: sa.RequirePQ, Drops: sa.Drops,
		Principals: []whoPrincipal{}, Unresolved: sa.Unresolved}
	if ws.Readers == nil {
		ws.Readers = []string{}
	}
	idx := map[string]int{}
	for _, d := range sa.Devices {
		key := d.Person
		if d.Machine {
			key = d.ID
		}
		i, ok := idx[key]
		if !ok {
			i = len(ws.Principals)
			idx[key] = i
			ws.Principals = append(ws.Principals, whoPrincipal{Principal: key, Machine: d.Machine, Devices: []string{}})
		}
		p := &ws.Principals[i]
		if !d.Machine {
			p.Devices = append(p.Devices, d.Device)
		}
		if sa.RequirePQ && !d.Hybrid() {
			p.Skipped = append(p.Skipped, d.ID)
		}
		for _, e := range sa.Why[d.ID] {
			if !containsString(p.Via, e) {
				p.Via = append(p.Via, e)
			}
		}
	}
	for i := range ws.Principals {
		ws.Principals[i].rule = ruleText(ws.Principals[i].Via, sa.ReadersFrom)
	}
	return ws
}

// ruleText renders the entries that grant access: "via @payments" for a
// team, "named in <file>" for a direct entry.
func ruleText(via []string, file string) string {
	var parts []string
	named := false
	for _, e := range via {
		if strings.HasPrefix(e, "@") {
			parts = append(parts, "via "+e)
		} else {
			named = true
		}
	}
	if named {
		parts = append(parts, "named in "+file)
	}
	return strings.Join(parts, ", ")
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// envsFor returns --env (validated) when given, else every environment.
func (c *Context) envsFor(w *Workspace) ([]string, error) {
	if c.Global.Env == "" {
		return w.Config.Environments, nil
	}
	env, err := c.Environment(w)
	if err != nil {
		return nil, err
	}
	return []string{env}, nil
}

func runWho(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}
	name := c.Args[0]
	if _, ok := pol.Packages[name]; !ok {
		e := Errorf(ExitNotFound, "no package named %q", name)
		if names := sortedNames(pol.Packages); len(names) > 0 {
			e.WithDetail("Packages in this workspace: " + strings.Join(names, ", ") + ".")
		}
		return e.WithHint("Package names come from `name` in each carbon.toml; see `carbon graph`.")
	}
	envs, err := c.envsFor(w)
	if err != nil {
		return err
	}
	var res []whoScope
	for _, env := range envs {
		sa, err := pol.Scope(name, env)
		if err != nil {
			return err
		}
		res = append(res, explainScope(sa))
	}
	return c.Output(map[string]any{"package": name, "scopes": res}, func(out io.Writer) {
		for i, ws := range res {
			indent := ""
			if len(res) > 1 {
				if i > 0 {
					fmt.Fprintln(out)
				}
				from := ws.ReadersFrom
				if from == "" {
					from = "no [access] entry"
				}
				fmt.Fprintf(out, "%s   readers from %s\n", ws.Scope, from)
				indent = "  "
			}
			printWhoScope(out, ws, indent)
		}
	})
}

func printWhoScope(out io.Writer, ws whoScope, indent string) {
	if len(ws.Principals) == 0 {
		fmt.Fprintf(out, "%snobody reads %s: [access] names no person or machine with a key.\n", indent, ws.Scope)
	}
	rows := [][]string{}
	for _, p := range ws.Principals {
		rule := p.rule
		if len(p.Skipped) > 0 {
			rule += fmt.Sprintf("; require_pq skips %s (not hybrid)", strings.Join(p.Skipped, ", "))
		}
		rows = append(rows, []string{indent + p.Principal, strings.Join(p.Devices, ", "), rule})
	}
	Table(out, rows)
	for _, u := range ws.Unresolved {
		fmt.Fprintf(out, "%swarning: %s names %s, which is not a team, person or machine with a file.\n", indent, ws.Scope, u)
	}
}

type accessScope struct {
	Scope   string   `json:"scope"`
	Package string   `json:"package"`
	Env     string   `json:"env"`
	Devices []string `json:"devices"`
	Via     []string `json:"via"`
	File    string   `json:"readers_from"`
	rule    string
}

type accessResult struct {
	Principal string        `json:"principal"`
	Machine   bool          `json:"machine"`
	Devices   []string      `json:"devices"`
	Teams     []string      `json:"teams"`
	Scopes    []accessScope `json:"scopes"`
}

func runAccess(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}
	who := c.Args[0]
	if strings.HasPrefix(who, "@") {
		return Errorf(ExitUsage, "access explains a person or a machine, not a team").
			WithHint("For a team, run `carbon access <member>` for a member, or see .carbon/teams.toml.")
	}
	res := accessResult{Principal: who, Devices: []string{}, Teams: []string{}, Scopes: []accessScope{}}
	if m, ok := strings.CutPrefix(who, config.MachinePrefix); ok {
		if _, found := pol.Machines[m]; !found {
			return Errorf(ExitNotFound, "no machine named %q", m).
				WithDetail("Machines are files in "+config.MachinesDir+"/.").
				WithHint("To create one:   carbon join --machine %s", m)
		}
		res.Machine = true
		res.Devices = append(res.Devices, who)
	} else {
		if _, found := pol.People[who]; !found {
			e := Errorf(ExitNotFound, "no person named %q", who)
			if names := sortedNames(pol.People); len(names) > 0 {
				e.WithDetail("People in this workspace: " + strings.Join(names, ", ") + ".")
			}
			return e.WithHint("People are files in %s/; to add yourself:   carbon join", config.PeopleDir)
		}
		for _, d := range pol.PersonDevices(who) {
			res.Devices = append(res.Devices, d.Device)
		}
		for _, t := range pol.TeamsOf(who) {
			res.Teams = append(res.Teams, "@"+t)
		}
	}
	envs, err := c.envsFor(w)
	if err != nil {
		return err
	}
	for _, sa := range pol.ScopesOf(who) {
		if !containsString(envs, sa.Env) {
			continue
		}
		as := accessScope{Scope: sa.Name(), Package: sa.Package, Env: sa.Env, Devices: []string{}, File: sa.ReadersFrom}
		for _, d := range sa.Devices {
			if d.ID != who && d.Person != who {
				continue
			}
			if !d.Machine {
				as.Devices = append(as.Devices, d.Device)
			}
			for _, e := range sa.Why[d.ID] {
				if !containsString(as.Via, e) {
					as.Via = append(as.Via, e)
				}
			}
		}
		var parts []string
		for _, e := range as.Via {
			if strings.HasPrefix(e, "@") {
				parts = append(parts, "via "+e)
			} else {
				parts = append(parts, "named")
			}
		}
		as.rule = strings.Join(parts, ", ") + " in " + sa.ReadersFrom
		res.Scopes = append(res.Scopes, as)
	}
	return c.Output(res, func(out io.Writer) {
		desc := who
		if !res.Machine {
			if len(res.Devices) > 0 {
				desc += " (" + strings.Join(res.Devices, ", ") + ")"
			} else {
				desc += " (no devices)"
			}
		}
		if len(res.Scopes) == 0 {
			fmt.Fprintf(out, "%s reads no scopes.\n", desc)
		} else {
			fmt.Fprintf(out, "%s reads %s:\n\n", desc, plural(len(res.Scopes), "scope"))
			rows := [][]string{}
			for _, s := range res.Scopes {
				rows = append(rows, []string{s.Scope, strings.Join(s.Devices, ", "), s.rule})
			}
			Table(out, rows)
		}
		if len(res.Teams) > 0 {
			fmt.Fprintf(out, "\n%s is a member of %s.\n", who, joinAnd(res.Teams))
		}
		if len(res.Scopes) == 0 {
			fmt.Fprintf(out, "\nTo ask for access:   carbon request <package> --env <env>\n")
		}
	})
}
