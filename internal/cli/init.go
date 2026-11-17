package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/store"
)

func init() {
	Register(&Command{
		Name:    "init",
		Usage:   "[--name <package>] [--trunk <ref>] [--environments dev,staging,prod]",
		Summary: "Create a workspace, or a package in the current directory",
		Help: `At the top of a repository with no carbon.toml, init creates the workspace:
carbon.toml, .carbon/teams.toml, and a .gitattributes line that marks keys
files as generated. Every environment is readable by @engineering, and,
until carbon is on trunk, the first person to run "carbon join" joins every
empty team.

Inside a workspace, init creates a package in the current directory. Its name
is --name, or the directory's name.

Trunk (where access policy and inbox keys are read from) is chosen per clone:
CARBON_TRUNK, then git config carbon.trunk, then the remote default branch.
--trunk <ref> runs "git config carbon.trunk <ref>" for this clone only.`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("name", "", "package name")
			fs.String("trunk", "", "set git config carbon.trunk for this clone (default: the remote default branch)")
			fs.String("environments", "dev,staging,prod", "environments, first is the default")
		},
		Run: runInit,
	})
}

type initResult struct {
	Created   []string `json:"created"`
	Workspace bool     `json:"workspace"`
	Package   string   `json:"package,omitempty"`
}

func runInit(c *Context) error {
	repo, err := gitx.Find(c.Cwd)
	if err != nil {
		return err
	}
	if err := checkLegacyUpward(c.Cwd, repo.Root); err != nil {
		return err
	}
	name := c.String("name")
	res := initResult{Created: []string{}}
	if trunk := c.String("trunk"); trunk != "" {
		if err := config.CheckTrunk(trunk); err != nil {
			return c.UsageErr("--trunk: %v", err)
		}
		if err := repo.ConfigSet(policy.TrunkConfigKey, trunk); err != nil {
			return err
		}
		res.Created = append(res.Created, fmt.Sprintf("git config %s %s (this clone only)", policy.TrunkConfigKey, trunk))
	}

	rootFile := filepath.Join(repo.Root, config.FileName)
	_, statErr := os.Stat(rootFile)
	if errors.Is(statErr, fs.ErrNotExist) {
		if err := initWorkspace(c, repo, &res); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	}

	w, err := c.Workspace()
	if err != nil {
		return err
	}
	atRoot := c.Cwd == w.Root
	if !atRoot || name != "" {
		if err := initPackage(c, w, name, &res); err != nil {
			return err
		}
	} else if !res.Workspace && c.String("trunk") == "" {
		return &Error{Code: ExitUsage, Message: "this repository already has a carbon workspace",
			Hint: "To create a package, run `carbon init` in its directory, or here with --name <package>."}
	}

	return c.Output(res, func(out io.Writer) {
		for _, f := range res.Created {
			fmt.Fprintf(out, "Created %s\n", f)
		}
		if res.Workspace {
			fmt.Fprintf(out, "\nNext: carbon join, then carbon init in each package that has secrets.\n")
		} else {
			fmt.Fprintf(out, "\nNext: declare secrets under [secrets], then carbon set <name>.\n")
		}
	})
}

func initWorkspace(c *Context, repo *gitx.Repo, res *initResult) error {
	envs := c.List("environments")
	if len(envs) == 0 {
		return c.UsageErr("--environments needs at least one name")
	}
	for _, e := range envs {
		if err := config.CheckName("environment", e); err != nil {
			return c.UsageErr("%v", err)
		}
	}
	quoted := make([]string, len(envs))
	var access strings.Builder
	for i, e := range envs {
		quoted[i] = config.Quote(e)
		fmt.Fprintf(&access, "%s = [\"@engineering\"]\n", e)
	}
	ws := fmt.Sprintf(`[workspace]
format = 1
environments = [%s]
default_environment = %s

# Default readers per environment. A package's own [access] replaces these.
# A reader is @team, person, or machine:name. The long form also takes
# require_pq and drops: prod = { readers = ["@sre"], require_pq = true }
[access]
%s`, strings.Join(quoted, ", "), quoted[0], access.String())
	if err := writeNew(filepath.Join(repo.Root, config.FileName), ws); err != nil {
		return err
	}
	res.Created = append(res.Created, config.FileName)

	teams := filepath.Join(repo.Root, filepath.FromSlash(config.TeamsFile))
	if _, err := os.Stat(teams); errors.Is(err, fs.ErrNotExist) {
		if err := writeNew(teams, "# Teams list people (files in .carbon/people). The first person to join joins every team.\nengineering = []\n"); err != nil {
			return err
		}
		res.Created = append(res.Created, config.TeamsFile)
	}
	added, err := ensureLine(filepath.Join(repo.Root, ".gitattributes"), store.GitAttributesLine)
	if err != nil {
		return err
	}
	if added {
		res.Created = append(res.Created, ".gitattributes entry for keys files")
	}
	res.Workspace = true
	return nil
}

var unsafeName = regexp.MustCompile(`[^a-z0-9_-]+`)

// SanitizeName lower-cases s and replaces characters a name cannot hold
// with '-', for default package, person and device names.
func SanitizeName(s string) string {
	s = unsafeName.ReplaceAllString(strings.ToLower(s), "-")
	return strings.TrimLeft(strings.TrimRight(s, "-_"), "-_")
}

func initPackage(c *Context, w *Workspace, name string, res *initResult) error {
	if name == "" {
		name = SanitizeName(filepath.Base(c.Cwd))
	}
	if err := config.CheckName("package", name); err != nil {
		return c.UsageErr("%v", err).WithHint("Pass a valid name with --name <package>.")
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	if p, ok := pkgs[name]; ok {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("package %q already exists in %s", name, p.File),
			Hint: "Choose another name with --name <package>."}
	}
	file := filepath.Join(c.Cwd, config.FileName)
	if c.Cwd == w.Root {
		// The root file is the workspace; make it a package too.
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if w.Config.Package != nil {
			return &Error{Code: ExitUsage, Message: fmt.Sprintf("the workspace root is already package %q", w.Config.Package.Name)}
		}
		data = append([]byte("name = "+config.Quote(name)+"\n\n"), data...)
		if err := os.WriteFile(file, data, 0o644); err != nil {
			return err
		}
		res.Created = append(res.Created, fmt.Sprintf("package %s in %s", name, config.FileName))
		res.Package = name
		return nil
	}
	if _, err := os.Stat(file); err == nil {
		return &Error{Code: ExitUsage, Message: w.Rel(file) + " already exists",
			Hint: "Add name = \"<package>\" to it to make it a package."}
	}
	body := fmt.Sprintf(`name = %s

# Who reads this package's secrets, per environment. Replaces the workspace
# default for the environments named here.
[access]

# Declared secrets: name = { description = "...", generate = "random:32", rotate_after = "90d" }
[secrets]

# What `+"`carbon run`"+` gives the process: NAME = "${secret}", "${pkg.secret}", "${env:VAR}"
[env]
`, config.Quote(name))
	if err := writeNew(file, body); err != nil {
		return err
	}
	res.Created = append(res.Created, w.Rel(file))
	res.Package = name
	return nil
}

// writeNew creates a file that must not exist yet (mode 0644).
func writeNew(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ensureLine appends line to a text file unless it is already there.
func ensureLine(path, line string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == line {
			return false, nil
		}
	}
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		data = append(data, '\n')
	}
	data = append(data, line+"\n"...)
	return true, os.WriteFile(path, data, 0o644)
}
