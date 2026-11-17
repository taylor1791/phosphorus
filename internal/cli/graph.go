package cli

import (
	"io"

	"github.com/taylor1791/phosphorus/internal/audit"
)

func init() {
	Register(&Command{
		Name:    "graph",
		Summary: "Emit the package dependency graph as DOT",
		Help: `graph prints the dependency graph built from every package's [env] table,
in Graphviz DOT: an edge from a package to each package whose secrets or vars
it references, labelled with the names. A reference to a package that does
not exist is drawn as a dashed red node. Render it with, for example:

  carbon graph | dot -Tsvg > graph.svg

With --json, stdout is {"packages", "edges"}.`,
		Run: runGraph,
	})
}

func runGraph(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	g := audit.BuildGraph(pkgs)
	return c.Output(g, func(out io.Writer) { io.WriteString(out, g.DOT()) })
}
