package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/store"
)

func init() {
	Register(&Command{
		Name:    "edit",
		Group:   GroupDaily,
		Usage:   "[--allow-empty] [--env <env>] [--package <name>]",
		Summary: "Bulk-edit the scope's secrets in $EDITOR",
		Help: `edit decrypts every declared secret of the package in the environment into a
temporary file, opens it in $VISUAL (else $EDITOR), and re-seals only the
values you changed: unchanged lines keep their set time. The file lives in
a new private directory (mode 0700, under $XDG_RUNTIME_DIR when it is set)
that is wiped and removed afterwards, also when something fails or carbon
is told to stop. Swap or backup files the editor keeps elsewhere (for
example a central backup directory) are outside carbon's reach: configure
the editor not to keep them for this file.

Each line is name = "value" (a TOML string). Uncomment an unset secret's
line to set it. Removing a line does not delete a secret, and names the
package does not declare are rejected. A value that cannot be read (a
damaged drop, a retired key that does not open) is shown as a comment and
left alone.

As with carbon set, an empty value is refused unless --allow-empty is
given: then a line changed to name = "" stores the empty value, and so
does an unset secret's line uncommented as name = "". Without it, an
uncommented name = "" for an unset secret is ignored, and emptying a set
value saves nothing and says why.

When the editor exits, carbon reads the scope again and writes only the
secrets file, with only your changed values sealed under the scope's
current key: changes others made meanwhile are kept, and if one of them
touched a value you changed, nothing is saved. Needs read access.

The editor must wait until you close the file; for a GUI editor use its
wait flag, for example EDITOR="code --wait".`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("allow-empty", false, "store a value emptied in the editor instead of refusing it")
		},
		Run: runEdit,
	})
}

type editResult struct {
	Scope   string   `json:"scope"`
	Changed []string `json:"changed"`
	Files   []string `json:"files"`
}

func runEdit(c *Context) error {
	c.sealing = true
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
	doc, before, notEditable, err := editDocument(pkg, o)
	o.Close()
	defer func() {
		clear(doc)
		for _, v := range before {
			clear(v)
		}
	}()
	if err != nil {
		return err
	}
	// What each entry looked like when the file was written, to detect
	// changes made by others while the editor is open.
	loaded := map[string]store.Entry{}
	for n, e := range s.Secrets.Entries {
		loaded[n] = e
	}

	edited, err := c.editInTemp(argv, doc)
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
	allowEmpty := c.Bool("allow-empty")
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
		if why, ok := notEditable[n]; ok {
			problems = append(problems, fmt.Sprintf("%s cannot be edited here (%s); use `carbon set %s`.", n, why, n))
			continue
		}
		old, had := before[n]
		nv := after[n]
		switch {
		case had && bytes.Equal(old, nv):
		case len(nv) == 0 && !allowEmpty && !had:
		case len(nv) == 0 && !allowEmpty:
			problems = append(problems, fmt.Sprintf("%s is empty; an empty value is stored only with `carbon edit --allow-empty` (or restore the line to keep the value).", n))
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
		if err := saveEdits(c, w, pkg, env, loaded, changed, after); err != nil {
			return err
		}
		res.Files = append(res.Files, w.Rel(s.SecretsPath()))
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

// editDocument renders the file the editor sees. It returns the values it
// revealed and, for names that cannot be edited here, why.
func editDocument(pkg *config.Package, o *scope.Opened) ([]byte, map[string][]byte, map[string]string, error) {
	names := sortedNames(pkg.Secrets)
	before := map[string][]byte{}
	notEditable := map[string]string{}
	var doc bytes.Buffer
	fmt.Fprintf(&doc, "# carbon edit: %s\n#\n", o.Name())
	doc.WriteString("# One secret per line: name = \"value\", a TOML string (\\n for a newline).\n")
	doc.WriteString("# Change a value to re-seal it; unchanged lines keep their set time.\n")
	doc.WriteString("# Uncomment an unset secret to set it. Removing a line deletes nothing.\n")
	doc.WriteString("# Save and quit to apply; quit without saving to change nothing.\n")
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
			// A damaged drop or an unopenable retired key: show it, leave
			// it alone, and let the rest of the scope be edited.
			why := strings.ReplaceAll(err.Error(), "\n", " ")
			notEditable[n] = "it cannot be read: " + why
			fmt.Fprintf(&doc, "# %s cannot be read, so it is not editable here: %s\n", n, why)
			continue
		}
		before[n] = v.Bytes
		if !utf8.Valid(v.Bytes) {
			notEditable[n] = "it is not UTF-8 text"
			fmt.Fprintf(&doc, "# %s is not UTF-8 text and cannot be edited here; use `carbon set %s`.\n", n, n)
			continue
		}
		if v.Drop {
			doc.WriteString("# (a drop, not yet reviewed; changing it seals your value instead)\n")
		}
		fmt.Fprintf(&doc, "%s = %s\n", n, config.Quote(string(v.Bytes)))
	}
	return doc.Bytes(), before, notEditable, nil
}

// saveEdits reloads the scope from disk, opens it again (which checks its
// key against trunk again), refuses if anyone changed one of the edited
// names meanwhile, seals the changed values into the fresh copy and writes
// only the secrets file. The keys file is never written by edit.
func saveEdits(c *Context, w *Workspace, pkg *config.Package, env string, loaded map[string]store.Entry,
	changed []string, after map[string][]byte) error {
	s, err := c.LoadScope(w, pkg, env)
	if err != nil {
		return err
	}
	var moved []string
	for _, n := range changed {
		was, had := loaded[n]
		now, has := s.Secrets.Entries[n]
		same := was.Key == now.Key && was.Set.Equal(now.Set) && was.Value == now.Value && was.Drop == now.Drop
		if had != has || !same {
			moved = append(moved, n)
		}
	}
	if len(moved) > 0 {
		return &Error{Code: ExitError, Message: "nothing was saved: " + joinAnd(moved) + " changed on disk while the editor was open",
			Details: []string{"Someone (or something, such as a git checkout or `carbon set`) wrote " + w.Rel(s.SecretsPath()) + " meanwhile."},
			Hint:    "Run `carbon edit` again to edit the current values."}
	}
	o, err := c.OpenScope(w, pkg, s)
	if err != nil {
		return err
	}
	defer o.Close()
	now := c.Now()
	for _, n := range changed {
		if err := o.Seal(n, after[n], now); err != nil {
			return err
		}
	}
	return store.WriteFile(s.SecretsPath(), s.Secrets.Marshal())
}

// editTempBase is where the private directory goes: $XDG_RUNTIME_DIR (a
// per-user tmpfs on most Linux systems) when it is set and exists, else
// the system temporary directory.
func (c *Context) editTempBase() string {
	if d := c.Getenv("XDG_RUNTIME_DIR"); d != "" {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return ""
}

// quickExit is how soon an editor that changed nothing counts as one that
// did not wait for the user.
const quickExit = 500 * time.Millisecond

// editInTemp writes content to a file in a new private directory, runs the
// editor on it, and returns what the editor left. The directory is wiped
// and removed on every path out. An interrupt (^C) reaches the editor from
// the terminal; carbon ignores it and judges by the editor's exit status.
// SIGTERM or SIGHUP stops the editor and carbon, after cleaning up.
func (c *Context) editInTemp(argv []string, content []byte) ([]byte, error) {
	dir, err := os.MkdirTemp(c.editTempBase(), "carbon-edit-")
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

	// Caught, not ignored: an ignored signal would stay ignored in the
	// editor too.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Dir = c.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.Env = gitx.ScrubbedEnviron(c.environ()) // the editor never sees CARBON_IDENTITY
	if c.JSON() {
		cmd.Stdout = c.Stderr
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, &Error{Code: ExitError, Message: fmt.Sprintf("cannot start the editor %q", argv[0]),
			Details: []string{err.Error()},
			Hint:    "Check VISUAL and EDITOR; the first word must be a program on PATH."}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var stopped os.Signal
	var runErr error
wait:
	for {
		select {
		case sig := <-sigs:
			if sig == os.Interrupt {
				continue
			}
			if stopped == nil {
				stopped = sig
				cmd.Process.Signal(sig)
			}
		case runErr = <-done:
			break wait
		}
	}
	elapsed := time.Since(start)
	if stopped != nil {
		return nil, Errorf(ExitError, "stopped by %v; nothing was saved", stopped)
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return nil, Errorf(ExitError, "the editor exited with status %d; nothing was saved", ee.ExitCode())
		}
		return nil, AsError(runErr)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if elapsed < quickExit && bytes.Equal(out, content) {
		c.Notice("warning: the editor exited after %v without changing the file. If it opens a window and returns at once, make it wait, for example:   EDITOR=\"code --wait\"",
			elapsed.Round(time.Millisecond))
	}
	return out, nil
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
