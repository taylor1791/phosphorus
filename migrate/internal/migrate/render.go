package migrate

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Render prints the plan. It never prints a secret value: copies are listed
// by scope and name only. Vars are printed, since they were plaintext in the
// 0.0.3 carbon.toml files already.
func (p *Plan) Render(w io.Writer, contents bool) {
	fmt.Fprintln(w, "Environments")
	for _, e := range p.Envs {
		from := "registry " + e.Reg.Label()
		def := ""
		if e.New == p.DefaultEnv {
			def = "  (default_environment)"
		}
		fmt.Fprintf(w, "  %-12s from %s%s\n", e.New, from, def)
	}
	if p.Trunk != "" {
		fmt.Fprintf(w, "  trunk: CARBON_TRUNK=%s for the carbon commands this run makes (nothing is written)\n", p.Trunk)
	} else {
		fmt.Fprintln(w, "  trunk: carbon chooses it (CARBON_TRUNK, git config carbon.trunk, else the remote default branch)")
	}

	fmt.Fprintln(w, "\nPeople (from sops `users` and registry recipients)")
	for _, per := range p.People {
		reads := strings.Join(per.Reads, ", ")
		if reads == "" {
			reads = "nothing yet"
		}
		me := ""
		if per.ID == p.Me {
			me = "  (you)"
		}
		fmt.Fprintf(w, "  %-16s %d device(s); reads %s%s\n", per.ID, len(per.Devices), reads, me)
	}

	fmt.Fprintln(w, "\nFiles to write")
	for _, f := range p.Files {
		fmt.Fprintf(w, "  %-8s %-40s %s\n", f.Action, f.Path, f.What)
	}

	fmt.Fprintf(w, "\nSecrets to copy with `carbon set` (%d values, never shown)\n", len(p.Copies))
	byScope := map[string][]string{}
	for _, c := range p.Copies {
		byScope[c.Scope()] = append(byScope[c.Scope()], c.Name)
	}
	scopes := make([]string, 0, len(byScope))
	for s := range byScope {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	for _, s := range scopes {
		names := byScope[s]
		sort.Strings(names)
		fmt.Fprintf(w, "  %-24s %s\n", s, strings.Join(names, ", "))
	}
	for _, c := range p.Copies {
		if strings.HasPrefix(c.Source, "carbon.toml") {
			fmt.Fprintf(w, "  note: %s %s comes from the %s\n", c.Scope(), c.Name, c.Source)
		}
	}

	fmt.Fprintln(w, "\nIdentity")
	switch p.IdentityAction {
	case "install":
		verb := "copy"
		if p.MoveKey {
			verb = "move"
		}
		fmt.Fprintf(w, "  %s %s -> %s (the age key is unchanged)\n", verb, p.KeyFile, p.IdentityPath)
	case "already-installed":
		fmt.Fprintf(w, "  %s already holds your key; nothing to install\n", p.IdentityPath)
		if p.MoveKey {
			fmt.Fprintf(w, "  remove %s once everything is verified\n", p.KeyFile)
		}
	case "conflict":
		fmt.Fprintf(w, "  %s holds a different key: blocked (see below)\n", p.IdentityPath)
	}

	fmt.Fprintln(w, "\nTo delete once every value has been written and read back")
	for _, d := range p.Deletes {
		fmt.Fprintf(w, "  %s\n", d)
	}
	if p.MoveKey {
		fmt.Fprintf(w, "  %s (after it is installed as your 1.0 identity)\n", p.KeyFile)
	}

	if contents {
		fmt.Fprintln(w, "\nNew file contents")
		for _, f := range p.Files {
			fmt.Fprintf(w, "\n  --- %s\n", f.Path)
			for _, l := range strings.Split(strings.TrimRight(string(f.Content), "\n"), "\n") {
				fmt.Fprintf(w, "  | %s\n", l)
			}
		}
	}

	p.RenderManual(w)
	if len(p.Blockers) > 0 {
		fmt.Fprintf(w, "\nBlocked: %d problem(s) must be fixed before --write\n", len(p.Blockers))
		for i, b := range p.Blockers {
			fmt.Fprintf(w, "  %d. %s\n", i+1, indentRest(b, "     "))
		}
	}
}

// RenderManual prints the items that need a person's decision.
func (p *Plan) RenderManual(w io.Writer) {
	if len(p.Manual) == 0 {
		fmt.Fprintln(w, "\nNeeds a manual choice: nothing")
		return
	}
	fmt.Fprintf(w, "\nNeeds a manual choice (%d)\n", len(p.Manual))
	for i, m := range p.Manual {
		fmt.Fprintf(w, "  %d. %s\n", i+1, indentRest(m, "     "))
	}
}

func indentRest(s, pad string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
}
