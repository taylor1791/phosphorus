package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/resolve"
)

func init() {
	Register(&Command{
		Name:    "run",
		Group:   GroupDaily,
		Usage:   "[--env <env>] [--package <name>] [--] <command> [args...]",
		Summary: "Run a command with the package's environment",
		Help: `run resolves the package's [env] table, decrypting in memory, and replaces
itself with the command (execve): there is no shell in between, signals go
straight to the command, and the exit code is the command's. The command
gets carbon's own environment plus the resolved variables, which win on a
clash. Names are case-sensitive. Nothing is written to disk. With -C the
command starts in that directory.

carbon's own flags go before the command: everything from the first
argument that is not a flag on belongs to the command, so
"carbon run make -C build" passes -C build to make. "--" also ends
carbon's flags.`,
		MinArgs: 1, MaxArgs: -1,
		StopAtPositional: true,
		Run:              runRun,
	})
}

// execFn replaces the process. A variable so it can be swapped in tests.
var execFn = syscall.Exec

func runRun(c *Context) error {
	if c.ArgsLenAtDash > 0 {
		return c.UsageErr("unexpected %q before --", c.Args[0])
	}
	if c.JSON() {
		return c.UsageErr("run does not take --json: its output is the command's")
	}
	argv := c.Args
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
	res, err := c.resolvePackageEnv(w, pkg, env)
	if err != nil {
		return err
	}
	// The command never sees carbon's own identity variables.
	envv := mergeEnviron(gitx.ScrubbedEnviron(c.environ()), res)
	res.Zero()

	// The command starts where carbon was asked to work (-C), and a
	// relative command path is found from there.
	if err := os.Chdir(c.Cwd); err != nil {
		return Errorf(ExitError, "cannot change to %s: %v", c.Cwd, err)
	}
	path, err := findExecutable(argv[0], lookupIn(envv, "PATH"))
	if err != nil {
		return err
	}
	err = execFn(path, argv, envv)
	// execve returned, so the command did not start.
	return &Error{Code: ExitError, Message: fmt.Sprintf("cannot run %s", argv[0]),
		Details: []string{err.Error()}, Err: err}
}

// mergeEnviron returns parent with every resolved variable set, replacing
// any parent entry of the same (case-sensitive) name.
func mergeEnviron(parent []string, res *resolve.Result) []string {
	set := make(map[string]bool, len(res.Vars))
	for _, v := range res.Vars {
		set[v.Name] = true
	}
	out := make([]string, 0, len(parent)+len(res.Vars))
	for _, kv := range parent {
		name, _, _ := strings.Cut(kv, "=")
		if !set[name] {
			out = append(out, kv)
		}
	}
	for _, v := range res.Vars {
		out = append(out, v.Name+"="+string(v.Value))
	}
	return out
}

// lookupIn returns the first entry for name, which is the one getenv in
// the command (libc) will see.
func lookupIn(envv []string, name string) string {
	for _, kv := range envv {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// findExecutable resolves the command the way execvp would, using the PATH
// the command will see and the first match in PATH order. Relative (and
// empty) PATH entries are skipped, so a command is never picked up from the
// current directory by accident; the error says so when that is the only
// place it is.
func findExecutable(name, pathEnv string) (string, error) {
	hint := "Check the spelling, install it, or give its path (for example ./" + name + ")."
	if strings.Contains(name, "/") {
		hint = "Check the path, and that the file is executable."
	}
	notFound := func(details ...string) error {
		return &Error{Code: ExitError, Message: fmt.Sprintf("command not found: %s", name),
			Details: details, Hint: hint}
	}
	if strings.Contains(name, "/") {
		if err := checkExecutable(name); err != nil {
			return "", notFound(err.Error())
		}
		return name, nil
	}
	if name == "" {
		return "", notFound()
	}
	skipped, found := "", false
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			d := dir
			if d == "" {
				d = "."
			}
			if !found && checkExecutable(filepath.Join(d, name)) == nil {
				skipped, found = dir, true
			}
			continue
		}
		p := filepath.Join(dir, name)
		if checkExecutable(p) == nil {
			return p, nil
		}
	}
	if found {
		hint = "Give its path instead, for example:   " + filepath.Join(skipped, name)
		if skipped == "" || skipped == "." {
			hint = "Give its path instead:   ./" + name
		}
		return "", notFound(fmt.Sprintf("It is only in the relative PATH entry %q, which carbon skips so that a command is never taken from the current directory by accident.", skipped))
	}
	if pathEnv == "" {
		return "", notFound("PATH is empty.")
	}
	return "", notFound("It is not in any directory on PATH.")
}

func checkExecutable(p string) error {
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s does not exist", p)
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", p)
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", p)
	}
	return nil
}
