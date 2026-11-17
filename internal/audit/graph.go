package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
)

// Ref is one ${name} or ${pkg.name} reference in a package's [env] table.
type Ref struct {
	// Consumer is the package whose [env] table holds the reference.
	Consumer string
	// EnvKey is the process variable the template sets.
	EnvKey string
	// Provider is the package the name belongs to (Consumer for ${name}).
	Provider string
	Name     string
	// Text is the reference as written, e.g. "${db.password}".
	Text string
}

// Local reports whether the reference is to the consumer's own name.
func (r Ref) Local() bool { return r.Provider == r.Consumer }

// Refs returns every reference in a package's [env] table, ordered by
// process variable then position.
func Refs(p *config.Package) []Ref {
	var out []Ref
	for _, key := range sortedKeys(p.Env) {
		parts, err := config.ParseTemplate(p.Env[key])
		if err != nil {
			continue // the parser already refused the file
		}
		for _, part := range parts {
			r := part.Ref
			if r == nil {
				continue
			}
			switch r.Kind {
			case config.RefLocal:
				out = append(out, Ref{Consumer: p.Name, EnvKey: key, Provider: p.Name, Name: r.Name, Text: "${" + r.Name + "}"})
			case config.RefPackage:
				out = append(out, Ref{Consumer: p.Name, EnvKey: key, Provider: r.Package, Name: r.Name, Text: "${" + r.Package + "." + r.Name + "}"})
			}
		}
	}
	return out
}

// Edge is a dependency from one package to another.
type Edge struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Names []string `json:"names"`
	// Missing is set when To is not a package in the working tree.
	Missing bool `json:"missing,omitempty"`
}

// Graph is the package dependency graph built from [env] references.
type Graph struct {
	Packages []string `json:"packages"`
	Edges    []Edge   `json:"edges"`
}

// BuildGraph builds the dependency graph of pkgs. References to a package's
// own names are not edges.
func BuildGraph(pkgs map[string]*config.Package) *Graph {
	g := &Graph{Packages: sortedKeys(pkgs), Edges: []Edge{}}
	type key struct{ from, to string }
	names := map[key]map[string]bool{}
	for _, name := range g.Packages {
		for _, r := range Refs(pkgs[name]) {
			if r.Local() {
				continue
			}
			k := key{r.Consumer, r.Provider}
			if names[k] == nil {
				names[k] = map[string]bool{}
			}
			names[k][r.Name] = true
		}
	}
	for k, ns := range names {
		_, ok := pkgs[k.to]
		g.Edges = append(g.Edges, Edge{From: k.from, To: k.to, Names: sortedKeys(ns), Missing: !ok})
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}

// Cycles returns each set of packages that reference each other in a
// cycle (strongly connected components with more than one package), each
// sorted, ordered by first member.
func (g *Graph) Cycles() [][]string {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if !e.Missing {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	// Tarjan's algorithm.
	index, low := map[string]int{}, map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]string
	n := 0
	var visit func(v string)
	visit = func(v string) {
		index[v], low[v] = n, n
		n++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range adj[v] {
			if _, seen := index[w]; !seen {
				visit(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			if len(comp) > 1 {
				sort.Strings(comp)
				out = append(out, comp)
			}
		}
	}
	for _, p := range g.Packages {
		if _, seen := index[p]; !seen {
			visit(p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// DOT renders the graph in Graphviz DOT. Missing packages are dashed red
// nodes; edge labels list the names referenced.
func (g *Graph) DOT() string {
	var b strings.Builder
	b.WriteString("digraph carbon {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box];\n")
	for _, p := range g.Packages {
		fmt.Fprintf(&b, "  %s;\n", dotID(p))
	}
	missing := map[string]bool{}
	for _, e := range g.Edges {
		if e.Missing && !missing[e.To] {
			missing[e.To] = true
			fmt.Fprintf(&b, "  %s [style=dashed, color=red, label=%s];\n", dotID(e.To), dotID(e.To+" (missing)"))
		}
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&b, "  %s -> %s [label=%s];\n", dotID(e.From), dotID(e.To), dotID(strings.Join(e.Names, ", ")))
	}
	b.WriteString("}\n")
	return b.String()
}

func dotID(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// graphFindings checks references, names and cycles in the working tree.
func (s *State) graphFindings(unused bool) []Finding {
	var out []Finding
	pkgs := s.Worktree.Packages
	envs := s.Workspace.Environments
	referenced := map[string]map[string]bool{} // provider -> name
	varUnset := map[string]bool{}
	for _, name := range sortedKeys(pkgs) {
		p := pkgs[name]
		for _, n := range sortedKeys(p.Secrets) {
			if _, ok := p.Vars[n]; ok {
				out = append(out, Finding{Severity: Error, Rule: RuleGraphSecretAndVar, Package: p.Name, Secret: n, File: p.File,
					Message: fmt.Sprintf("%s declares %s both under [secrets] and as [vars.%s]; secrets and vars share one namespace.", p.File, n, n),
					Hint:    "Keep one of them in " + p.File + "."})
			}
		}
		for _, r := range Refs(p) {
			where := fmt.Sprintf("%s [env] %s references %s", p.File, r.EnvKey, r.Text)
			prov, ok := pkgs[r.Provider]
			if !ok {
				out = append(out, Finding{Severity: Error, Rule: RuleGraphMissingPkg, Package: p.Name, File: p.File,
					Message: fmt.Sprintf("%s, but there is no package named %s.", where, r.Provider),
					Hint:    fmt.Sprintf("Fix the reference, or create the package with `carbon init --name %s` in its directory.", r.Provider)})
				continue
			}
			if referenced[prov.Name] == nil {
				referenced[prov.Name] = map[string]bool{}
			}
			referenced[prov.Name][r.Name] = true
			decl, isSecret := prov.Secrets[r.Name]
			byEnv, isVar := prov.Vars[r.Name]
			switch {
			case !isSecret && !isVar:
				out = append(out, Finding{Severity: Error, Rule: RuleGraphMissingName, Package: p.Name, Secret: r.Name, File: p.File,
					Message: fmt.Sprintf("%s, but %s declares no secret or var named %s.", where, prov.Name, r.Name),
					Hint:    fmt.Sprintf("Declare it under [secrets] or [vars.%s] in %s, or fix the reference.", r.Name, prov.File)})
			case isSecret && decl.Private && !r.Local():
				out = append(out, Finding{Severity: Error, Rule: RuleGraphPrivate, Package: p.Name, Secret: r.Name, File: p.File,
					Message: fmt.Sprintf("%s, but %s.%s is private = true: only %s may use it.", where, prov.Name, r.Name, prov.Name),
					Hint:    fmt.Sprintf("Remove the reference, or have the owners of %s drop private = true.", prov.File)})
			case isVar && !isSecret:
				for _, env := range envs {
					_, hasEnv := byEnv[env]
					_, hasDefault := byEnv["default"]
					k := prov.Name + "\x00" + r.Name + "\x00" + env
					if hasEnv || hasDefault || varUnset[k] {
						continue
					}
					varUnset[k] = true
					out = append(out, Finding{Severity: Error, Rule: RuleGraphVarUnset, Scope: config.ScopeName(prov.Name, env),
						Package: prov.Name, Env: env, Secret: r.Name, File: prov.File,
						Message: fmt.Sprintf("[vars.%s] in %s has no value for %s and no default, and %s uses it (%s).", r.Name, prov.File, env, p.Name, r.Text),
						Hint:    fmt.Sprintf("Add %s = \"...\" (or default = \"...\") under [vars.%s] in %s.", env, r.Name, prov.File)})
				}
			}
		}
	}
	for _, cyc := range BuildGraph(pkgs).Cycles() {
		out = append(out, Finding{Severity: Error, Rule: RuleGraphCycle, Package: cyc[0],
			Message: fmt.Sprintf("Packages %s reference each other in a cycle.", strings.Join(cyc, ", ")),
			Hint:    "Break the cycle: move the shared secret into one package, or into a package of its own that the others reference."})
	}
	if unused {
		for _, name := range sortedKeys(pkgs) {
			p := pkgs[name]
			for _, n := range sortedKeys(p.Secrets) {
				if !referenced[name][n] {
					out = append(out, Finding{Severity: Info, Rule: RuleSecretUnused, Package: name, Secret: n, File: p.File,
						Message: fmt.Sprintf("%s.%s is not referenced by any [env] table.", name, n),
						Hint:    "Unreferenced secrets are legal; delete the declaration if nothing reads it (carbon get, export)."})
				}
			}
		}
	}
	return out
}
