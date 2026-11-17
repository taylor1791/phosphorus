// Command carbon-migrate migrates a repository from carbon 0.0.3 to Carbon
// 1.0. It is a dry run unless --write is given. See migrate/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/taylor1791/phosphorus/migrate/internal/migrate"
)

type pairs map[string]string

func (p pairs) String() string { return "" }

func (p pairs) Set(s string) error {
	old, new, ok := strings.Cut(s, "=")
	if !ok || new == "" {
		return fmt.Errorf("want <old>=<new>, got %q", s)
	}
	p[old] = new
	return nil
}

const usage = `carbon-migrate: migrate a repository from carbon 0.0.3 to Carbon 1.0

Usage:
  carbon-migrate [flags]            print the plan (dry run, changes nothing)
  carbon-migrate --write [flags]    perform it

Run it from inside the repository, as someone who can decrypt every 0.0.3
registry with .carbon/private-key.age. It needs sops (for the old registries)
and the Carbon 1.0 carbon binary (for the new values).

Flags:
`

func main() {
	fs := flag.NewFlagSet("carbon-migrate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	envNames, pkgNames := pairs{}, pairs{}
	var o migrate.Options
	fs.StringVar(&o.Dir, "C", ".", "run as if started in `dir`")
	fs.BoolVar(&o.Write, "write", false, "perform the migration (default: dry run)")
	fs.BoolVar(&o.Force, "force", false, "run even if the git working tree has uncommitted changes")
	fs.BoolVar(&o.Contents, "show-files", false, "print the new files' contents with --write too (dry runs always do)")
	fs.StringVar(&o.Carbon, "carbon", "", "path to the Carbon 1.0 `carbon` binary (default: from PATH)")
	fs.StringVar(&o.Sops, "sops", "", "path to `sops` (default: from PATH)")
	fs.StringVar(&o.DefaultEnv, "default-env", "dev", "environment `name` for the unnamed 0.0.3 default registry")
	fs.Var(envNames, "env-name", "rename a registry: `old=new` (repeatable)")
	fs.Var(pkgNames, "package-name", "rename a service: `old=new` (repeatable)")
	fs.StringVar(&o.Trunk, "trunk", "", "trunk `ref` for the workspace (default: origin's HEAD, else origin/main)")
	fs.StringVar(&o.Key, "key", "", "the 0.0.3 private key `file` (default: .carbon/private-key.age; only that one is moved)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(migrate.ExitUsage)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "carbon-migrate takes no arguments (got %q)\n", fs.Args())
		os.Exit(migrate.ExitUsage)
	}
	o.EnvNames, o.PackageNames = envNames, pkgNames
	o.Stdout, o.Stderr = os.Stdout, os.Stderr
	os.Exit(migrate.Run(o))
}
