package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

func init() {
	Register(&Command{
		Name:    "env",
		Summary: "Show the current environment and where it comes from",
		Help: `env prints the environment carbon commands use here and which rule chose it:
--env, then CARBON_ENV, then "carbon env use" (stored per worktree in the
git directory), then the workspace's default_environment.`,
		Run: runEnv,
	})
	Register(&Command{
		Name:    "env use",
		Usage:   "<name> | --clear",
		Summary: "Pick the environment for this worktree",
		Help: `env use stores the environment for this worktree inside its git directory,
so it is per worktree and can never be committed. --env and CARBON_ENV
still override it. --clear goes back to default_environment.`,
		MaxArgs: 1,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("clear", false, "forget the stored environment")
		},
		Run: runEnvUse,
	})
}

type envResult struct {
	Environment  string   `json:"environment"`
	Source       string   `json:"source"` // flag, CARBON_ENV, env-use, default
	Environments []string `json:"environments"`
	Stored       string   `json:"stored,omitempty"`
	StoredFile   string   `json:"stored_file"`
	Default      string   `json:"default"`
}

func runEnv(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	file, err := EnvUseFile(w.Repo)
	if err != nil {
		return err
	}
	stored, err := ReadEnvUse(w.Repo)
	if err != nil {
		return err
	}
	res := envResult{Environments: w.Config.Environments, Stored: stored, StoredFile: file,
		Default: w.Config.DefaultEnvironment}
	var why string
	switch {
	case c.Global.Env != "":
		res.Environment, res.Source, why = c.Global.Env, "flag", "from --env"
	case c.Getenv("CARBON_ENV") != "":
		res.Environment, res.Source, why = c.Getenv("CARBON_ENV"), "CARBON_ENV", "from the CARBON_ENV variable"
	case stored != "":
		res.Environment, res.Source, why = stored, "env-use", "from `carbon env use`, stored in "+file
	default:
		res.Environment, res.Source, why = w.Config.DefaultEnvironment, "default", "the workspace's default_environment"
	}
	if !w.Config.HasEnvironment(res.Environment) {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown environment %q (%s)", res.Environment, why),
			Hint: "Environments in this workspace: " + strings.Join(w.Config.Environments, ", ") +
				"\nTo pick one for this worktree:   carbon env use <name>"}
	}
	return c.Output(res, func(out io.Writer) {
		fmt.Fprintf(out, "Environment: %s (%s)\n", res.Environment, why)
		if res.Source != "env-use" && stored != "" {
			fmt.Fprintf(out, "`carbon env use` stored %s for this worktree; it is overridden.\n", stored)
		}
		fmt.Fprintf(out, "Available:   %s\n", strings.Join(res.Environments, ", "))
	})
}

type envUseResult struct {
	Environment string `json:"environment"`
	File        string `json:"file"`
	Cleared     bool   `json:"cleared"`
}

func runEnvUse(c *Context) error {
	clearIt := c.Bool("clear")
	if clearIt == (len(c.Args) == 1) {
		return c.UsageErr("give an environment name, or --clear")
	}
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	file, err := EnvUseFile(w.Repo)
	if err != nil {
		return err
	}
	res := envUseResult{File: file, Cleared: clearIt}
	if clearIt {
		if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		res.Environment = w.Config.DefaultEnvironment
	} else {
		name := c.Args[0]
		if !w.Config.HasEnvironment(name) {
			return &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown environment %q", name),
				Hint: "Environments in this workspace: " + strings.Join(w.Config.Environments, ", ")}
		}
		if err := os.WriteFile(file, []byte(name+"\n"), 0o644); err != nil {
			return err
		}
		res.Environment = name
	}
	if c.Global.Env != "" {
		c.Notice("note: --env %s overrides this for the current command.", c.Global.Env)
	} else if v := c.Getenv("CARBON_ENV"); v != "" {
		c.Notice("note: CARBON_ENV=%s is set in your shell and overrides this until you unset it.", v)
	}
	return c.Output(res, func(out io.Writer) {
		if clearIt {
			fmt.Fprintf(out, "Cleared. This worktree uses the default environment, %s.\n", res.Environment)
			return
		}
		fmt.Fprintf(out, "This worktree now uses %s (stored in %s).\n", res.Environment, file)
	})
}
