package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func init() {
	Register(&Command{
		Name:    "edit",
		Usage:   "[--env <env>] [--package <name>]",
		Summary: "Bulk-edit the scope's secrets in $EDITOR",
		Help: `edit decrypts every declared secret of the package in the environment into a
temporary file, opens it in $VISUAL (else $EDITOR), and re-seals only the
values you changed: unchanged lines keep their set time. The file lives in
a private directory (mode 0700) that is removed afterwards, also when
something fails, together with any swap or backup file the editor made.

Each line is name = "value" (a TOML string). Uncomment an unset secret's
line to set it. Removing a line does not delete a secret, and names the
package does not declare are rejected. Needs read access.`,
		Run: runEdit,
	})
}

type editResult struct {
	Scope   string   `json:"scope"`
	Changed []string `json:"changed"`
	Files   []string `json:"files"`
}

func runEdit(c *Context) error {
	editor := c.Getenv("VISUAL")
	if strings.TrimSpace(editor) == "" {
		editor = c.Getenv("EDITOR")
	}
	argv := strings.Fields(editor)
	if len(argv) == 0 {
		return &Error{Code: ExitUsage, Message: "no editor: VISUAL and EDITOR are both unset",
			Hint: "Set one, for example:   export EDITOR=vi\nOr set values one at a time:   carbon set <name>"}
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
	o, err := c.OpenScope(w, pkg, s)
	if err != nil {
		return err
	}
	defer o.Close()

	names := make([]string, 0, len(pkg.Secrets))
	for n := range pkg.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	before := map[string][]byte{}
	defer func() {
		for _, v := range before {
			clear(v)
		}
	}()
	var doc bytes.Buffer
	defer func() { clear(doc.Bytes()) }()
	fmt.Fprintf(&doc, "# carbon edit: %s\n#\n", s.Name())
	doc.WriteString("# One secret per line: name = \"value\", a TOML string (\\n for a newline).\n")
	doc.WriteString("# Change a value to re-seal it; unchanged lines keep their set time.\n")
	doc.WriteString("# Uncomment an unset secret to set it. Removing a line deletes nothing.\n")
	doc.WriteString("# Save and quit to apply; quit without saving to change nothing.\n")
	notEditable := map[string]bool{}
	for _, n := range names {
		doc.WriteString("\n")
		if d := pkg.Secrets[n].Description; d != "" {
			fmt.Fprintf(&doc, "# %s\n", strings.ReplaceAll(d, "\n", " "))
		}
		v, err := o.Reveal(n)
		if errors.Is(err, scope.ErrNotFound) {
			fmt.Fprintf(&doc, "# %s = \"\"\n", n)
			continue
		}
		if err != nil {
			return err
		}
		before[n] = v.Bytes
		if !utf8.Valid(v.Bytes) {
			notEditable[n] = true
			fmt.Fprintf(&doc, "# %s is not UTF-8 text and cannot be edited here; use `carbon set %s`.\n", n, n)
			continue
		}
		if v.Drop {
			doc.WriteString("# (a drop, not yet reviewed; changing it seals your value instead)\n")
		}
		fmt.Fprintf(&doc, "%s = %s\n", n, config.Quote(string(v.Bytes)))
	}

	edited, err := c.editInTemp(argv, doc.Bytes())
	if err != nil {
		return err
	}
	defer clear(edited)

	after, err := parseEdited(edited)
	if err != nil {
		return err
	}
	defer func() {
		for k, v := range after {
			clear(v)
			delete(after, k)
		}
	}()
	var changed []string
	var problems []string
	for _, n := range sortedNames(after) {
		if _, ok := pkg.Secrets[n]; !ok {
			if _, isVar := pkg.Vars[n]; isVar {
				problems = append(problems, fmt.Sprintf("%s is a var, not a secret; edit [vars.%s] in %s.", n, n, pkg.File))
			} else {
				problems = append(problems, fmt.Sprintf("%s does not declare %s.", pkg.File, n))
			}
			continue
		}
		if notEditable[n] {
			problems = append(problems, fmt.Sprintf("%s is not text; set it with `carbon set %s`.", n, n))
			continue
		}
		old, had := before[n]
		nv := after[n]
		switch {
		case had && bytes.Equal(old, nv):
		case len(nv) == 0 && !had:
		case len(nv) == 0:
			problems = append(problems, fmt.Sprintf("%s is empty; carbon does not store empty values (restore the line to keep it).", n))
		default:
			changed = append(changed, n)
		}
	}
	if len(problems) > 0 {
		return &Error{Code: ExitUsage, Message: "nothing was saved: the edited file has problems",
			Details: problems,
			Hint:    "Declare new secrets under [secrets] first, then run `carbon edit` again."}
	}
	res := editResult{Scope: s.Name(), Changed: []string{}, Files: []string{}}
	if len(changed) > 0 {
		now := c.Now()
		for _, n := range changed {
			if err := o.Seal(n, after[n], now); err != nil {
				return err
			}
		}
		written, err := s.Save()
		if err != nil {
			return err
		}
		for _, f := range written {
			if f != s.KeysPath() {
				res.Files = append(res.Files, w.Rel(f))
			}
		}
		res.Changed = changed
	}
	return c.Output(res, func(out io.Writer) {
		if len(changed) == 0 {
			fmt.Fprintf(out, "No changes to %s.\n", s.Name())
			return
		}
		fmt.Fprintf(out, "Sealed %d changed secret(s) in %s: %s.\nCommit %s\n",
			len(changed), s.Name(), strings.Join(changed, ", "), joinAnd(res.Files))
	})
}

// editInTemp writes content to a file in a new private directory, runs the
// editor on it, and returns what the editor left. The directory is wiped
// and removed on every path out, including an interrupt during the editor.
func (c *Context) editInTemp(argv []string, content []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "carbon-edit-")
	if err != nil {
		return nil, err
	}
	defer wipeDir(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return nil, err
	}

	// The terminal sends an interrupt to the editor and to carbon alike.
	// Catch it so that carbon outlives the editor and removes the file.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.Env = gitx.ScrubbedEnviron(c.environ()) // the editor never sees CARBON_IDENTITY
	if c.JSON() {
		cmd.Stdout = c.Stderr
	}
	runErr := cmd.Run()
	select {
	case sig := <-sigs:
		return nil, Errorf(ExitError, "interrupted (%v); nothing was saved", sig)
	default:
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return nil, Errorf(ExitError, "the editor exited with status %d; nothing was saved", ee.ExitCode())
		}
		return nil, &Error{Code: ExitError, Message: fmt.Sprintf("cannot start the editor %q", argv[0]),
			Details: []string{runErr.Error()},
			Hint:    "Check VISUAL and EDITOR; the first word must be a program on PATH."}
	}
	return os.ReadFile(path)
}

// wipeDir overwrites every regular file under dir with zeros, then removes
// the directory. Best effort: the removal is what matters.
func wipeDir(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Size() > 0 {
			if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
				f.Write(make([]byte, fi.Size()))
				f.Close()
			}
		}
		return nil
	})
	os.RemoveAll(dir)
}

// parseEdited reads the edited file: a flat TOML table of strings.
func parseEdited(data []byte) (map[string][]byte, error) {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		// go-toml's message can quote the offending line, which may hold a
		// value: report only the position.
		msg := "it is not valid TOML"
		var de *toml.DecodeError
		if errors.As(err, &de) {
			row, col := de.Position()
			msg = fmt.Sprintf("line %d, column %d is not valid TOML", row, col)
		}
		return nil, &Error{Code: ExitUsage, Message: "nothing was saved: " + msg,
			Hint: "Each line must be name = \"value\". Run `carbon edit` again."}
	}
	out := map[string][]byte{}
	var bad []string
	for k, v := range raw {
		s, ok := v.(string)
		if !ok || !config.ValidSecretName(k) {
			bad = append(bad, k)
			continue
		}
		out[k] = []byte(s)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		for _, v := range out {
			clear(v)
		}
		return nil, &Error{Code: ExitUsage, Message: "nothing was saved: some lines are not name = \"value\"",
			Details: []string{"Not a secret name with a string value: " + strings.Join(bad, ", ")},
			Hint:    "Run `carbon edit` again."}
	}
	return out, nil
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
