package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/taylor1791/phosphorus/migrate/internal/agekey"
	"github.com/taylor1791/phosphorus/migrate/internal/legacy"
)

// Exit codes.
const (
	ExitOK      = 0
	ExitFailed  = 1
	ExitUsage   = 2
	ExitBlocked = 3
)

// Options configure a run.
type Options struct {
	Dir          string // any directory inside the repository
	Write        bool
	Force        bool
	Contents     bool // print the new files in the plan
	Carbon       string
	Sops         string
	DefaultEnv   string
	EnvNames     map[string]string
	PackageNames map[string]string
	Trunk        string
	Key          string // the 0.0.3 private key; default .carbon/private-key.age

	Stdout, Stderr io.Writer
	Environ        []string // the process environment; os.Environ() if nil
}

type runner struct {
	o       Options
	root    string
	environ []string
	tracked map[string]bool
	out     io.Writer
	errw    io.Writer

	// Undo state.
	modified        []string // tracked files changed or deleted
	created         []string // untracked files created
	untrackedEdited []string // untracked files overwritten (--force only)
	identityCreated string
	deletedOld      bool
}

func (r *runner) getenv(k string) string {
	for i := len(r.environ) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(r.environ[i], k+"="); ok {
			return v
		}
	}
	return ""
}

// Run performs a dry run or, with Write, the migration. It returns the exit
// code.
func Run(o Options) int {
	r := &runner{o: o, out: o.Stdout, errw: o.Stderr, environ: o.Environ}
	if r.environ == nil {
		r.environ = os.Environ()
	}
	code, err := r.run()
	if err != nil {
		fmt.Fprintf(r.errw, "error: %v\n", err)
	}
	return code
}

func (r *runner) git(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.root
	if r.root == "" {
		cmd.Dir = r.o.Dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (r *runner) run() (int, error) {
	top, err := r.git("rev-parse", "--show-toplevel")
	if err != nil {
		return ExitUsage, errors.New("carbon-migrate must run inside the git repository to migrate")
	}
	r.root = strings.TrimSpace(string(top))

	var blockers []string
	status, err := r.git("status", "--porcelain")
	if err != nil {
		return ExitFailed, err
	}
	if len(bytes.TrimSpace(status)) > 0 && !r.o.Force {
		blockers = append(blockers, "the working tree has uncommitted changes. Commit or stash them first, so that `git checkout` and `git clean` can undo the migration exactly (or pass --force).")
	}

	sops, err := findTool(r.o.Sops, "sops")
	if err != nil {
		return ExitUsage, fmt.Errorf("%v\n  carbon-migrate decrypts the 0.0.3 registries with sops. Install it, or pass --sops <path>.", err)
	}
	carbon, err := findTool(r.o.Carbon, "carbon")
	if err != nil {
		blockers = append(blockers, fmt.Sprintf("%v. carbon-migrate writes every secret with the Carbon 1.0 `carbon` command; put it on PATH or pass --carbon <path>.", err))
	}

	ls, err := r.git("ls-files", "-z", "--cached")
	if err != nil {
		return ExitFailed, err
	}
	r.tracked = map[string]bool{}
	for _, f := range strings.Split(string(ls), "\x00") {
		if f != "" {
			r.tracked[f] = true
		}
	}
	all, err := r.git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return ExitFailed, err
	}
	var files []string
	seen := map[string]bool{}
	for _, f := range strings.Split(string(all), "\x00") {
		if f == "" || seen[f] || path.Base(f) != legacy.ServiceFile {
			continue
		}
		seen[f] = true
		if _, err := os.Stat(filepath.Join(r.root, filepath.FromSlash(f))); err == nil {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	repo, err := legacy.Load(r.root, files)
	if err != nil {
		return ExitFailed, err
	}

	in := Input{
		Repo:          repo,
		Values:        map[string]legacy.Values{},
		DecryptErrors: map[string]string{},
		DefaultEnv:    r.o.DefaultEnv,
		EnvNames:      r.o.EnvNames,
		PackageNames:  r.o.PackageNames,
		Existing: func(p string) bool {
			_, err := os.Stat(filepath.Join(r.root, filepath.FromSlash(p)))
			return err == nil
		},
	}

	// The 0.0.3 key.
	keyPath := r.o.Key
	in.MoveKey = keyPath == ""
	if keyPath == "" {
		keyPath = filepath.Join(r.root, filepath.FromSlash(legacy.PrivateKeyFile))
		in.KeyFile = legacy.PrivateKeyFile
	} else {
		if abs, err := filepath.Abs(keyPath); err == nil {
			keyPath = abs
		}
		in.KeyFile = keyPath
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		blockers = append(blockers, fmt.Sprintf("cannot read the 0.0.3 private key %s (%v). Run carbon-migrate in the clone where you use carbon 0.0.3, or pass --key <path>.", in.KeyFile, err))
	} else {
		me, err := agekey.Recipient(keyData)
		if err != nil {
			blockers = append(blockers, fmt.Sprintf("%s: %v", in.KeyFile, err))
		}
		in.Me = me
		clear(keyData)
	}

	// Decrypt every registry.
	if in.Me != "" {
		for _, reg := range repo.Registries {
			if !reg.HasRegistry {
				continue
			}
			vals, err := legacy.Decrypt(sops, r.root, reg, keyPath, r.environ)
			if err != nil {
				in.DecryptErrors[reg.Name] = err.Error()
				continue
			}
			in.Values[reg.Name] = vals
		}
	}

	// Trunk: only an override for the carbon subprocesses.
	in.Trunk = r.o.Trunk

	// The 1.0 identity.
	in.IdentityPath = r.identityPath()
	if data, err := os.ReadFile(in.IdentityPath); err == nil {
		in.IdentityExists = true
		if rec, err := agekey.Recipient(data); err == nil {
			in.IdentityExisting = rec
		} else {
			in.IdentityExisting = "?"
		}
		clear(data)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ExitFailed, err
	}

	if data, err := os.ReadFile(filepath.Join(r.root, legacy.ServiceFile)); err == nil && !legacy.IsLegacyConfig(data) && bytes.Contains(data, []byte("[workspace]")) {
		in.RootWorkspace = true
	}
	if data, err := os.ReadFile(filepath.Join(r.root, ".gitattributes")); err == nil {
		in.GitAttributes = data
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ExitFailed, err
	}

	plan := Build(in)
	plan.Blockers = append(blockers, plan.Blockers...)
	if v := r.getenv("CARBON_IDENTITY"); v != "" {
		plan.Manual = append(plan.Manual, "CARBON_IDENTITY is set in your environment, and carbon prefers it to the identity file; unset it to use the migrated key.")
	}

	mode := "dry run: nothing will change; re-run with --write to migrate"
	if r.o.Write {
		mode = "migrating (--write)"
	}
	fmt.Fprintf(r.out, "carbon-migrate: %s in %s\n\n", mode, r.root)
	plan.Render(r.out, r.o.Contents || !r.o.Write)
	if len(plan.Blockers) > 0 {
		return ExitBlocked, nil
	}
	if !r.o.Write {
		fmt.Fprintln(r.out, "\nDry run complete. Nothing was changed. Re-run with --write to migrate.")
		return ExitOK, nil
	}
	if err := r.execute(plan, carbon, keyPath); err != nil {
		fmt.Fprintf(r.errw, "\nerror: %v\n", err)
		r.printUndo(r.errw, false)
		return ExitFailed, nil
	}
	return ExitOK, nil
}

func findTool(flagValue, name string) (string, error) {
	if flagValue != "" {
		if st, err := os.Stat(flagValue); err != nil || st.IsDir() {
			return "", fmt.Errorf("%s: no such program", flagValue)
		}
		return flagValue, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s is not on PATH", name)
	}
	return p, nil
}

// identityPath mirrors carbon's: CARBON_IDENTITY_FILE, else
// $XDG_CONFIG_HOME/carbon/identity, else ~/.config/carbon/identity.
func (r *runner) identityPath() string {
	if p := r.getenv("CARBON_IDENTITY_FILE"); p != "" {
		return p
	}
	base := r.getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(r.getenv("HOME"), ".config")
	}
	return filepath.Join(base, "carbon", "identity")
}

func (r *runner) abs(rel string) string { return filepath.Join(r.root, filepath.FromSlash(rel)) }

func (r *runner) recordWrite(rel string) {
	_, err := os.Stat(r.abs(rel))
	switch {
	case r.tracked[rel]:
		r.modified = appendOnce(r.modified, rel)
	case err == nil:
		r.untrackedEdited = appendOnce(r.untrackedEdited, rel)
	default:
		r.created = appendOnce(r.created, rel)
	}
}

func appendOnce(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// carbonEnv is the environment for carbon subprocesses: the caller's,
// without anything that would pick a different identity or environment.
func (r *runner) carbonEnv(identityFile string) []string {
	env := legacy.WithoutEnv(r.environ, "CARBON_IDENTITY", "CARBON_IDENTITY_FILE", "CARBON_ENV")
	if r.o.Trunk != "" {
		env = append(legacy.WithoutEnv(env, "CARBON_TRUNK"), "CARBON_TRUNK="+r.o.Trunk)
	}
	return append(env, "CARBON_IDENTITY_FILE="+identityFile)
}

func (r *runner) carbonCmd(carbon, identityFile string, stdin []byte, args ...string) ([]byte, string, error) {
	cmd := exec.Command(carbon, args...)
	cmd.Dir = r.root
	cmd.Env = r.carbonEnv(identityFile)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func (r *runner) execute(plan *Plan, carbon, keyPath string) error {
	out := r.out
	fmt.Fprintln(out, "\nWriting policy files")
	for _, f := range plan.Files {
		r.recordWrite(f.Path)
		p := r.abs(f.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.Content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f.Path, err)
		}
		fmt.Fprintf(out, "  %-8s %s\n", f.Action, f.Path)
	}

	dirs := map[string]string{}
	for _, pkg := range plan.Packages {
		dirs[pkg.Name] = pkg.Dir
	}
	fmt.Fprintf(out, "\nCopying %d secret value(s) with `carbon set` (values go over stdin only)\n", len(plan.Copies))
	noticed := false
	for i, c := range plan.Copies {
		for _, kind := range []string{"secrets", "keys"} {
			rel := path.Join(dirs[c.Package], ".carbon", c.Env+"."+kind+".toml")
			if _, err := os.Stat(r.abs(rel)); errors.Is(err, fs.ErrNotExist) {
				r.recordWrite(rel)
			}
		}
		stdin := stdinFor(c.value)
		args := []string{"set", c.Name, "--env", c.Env, "--package", c.Package}
		if c.value == "" {
			args = append(args, "--allow-empty")
		}
		_, stderr, err := r.carbonCmd(carbon, keyPath, stdin, args...)
		clear(stdin)
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
			return fmt.Errorf("`carbon set %s --env %s --package %s` refused (exit 3): your key is not a reader of %s in the policy carbon is using, and carbon 1.0 only lets a reader create a scope's first key. Check that %s lists you, and that carbon reads the working tree's policy (its notice says so); if trunk already has a 1.0 carbon.toml it reads trunk's instead.\n%s", c.Name, c.Env, c.Package, c.Scope(), "carbon.toml [access]", indentLines(stderr))
		}
		if err != nil {
			return fmt.Errorf("`carbon set %s --env %s --package %s` failed (%d of %d): %v\n%s", c.Name, c.Env, c.Package, i+1, len(plan.Copies), err, indentLines(stderr))
		}
		if !noticed && stderr != "" {
			fmt.Fprintf(out, "  carbon: %s\n", indentRest(stderr, "          "))
			noticed = true
		}
	}
	fmt.Fprintf(out, "  set %d value(s)\n", len(plan.Copies))

	idPath := plan.IdentityPath
	if plan.IdentityAction == "install" {
		if err := r.installIdentity(keyPath, idPath); err != nil {
			return err
		}
		fmt.Fprintf(out, "\nInstalled your key as the Carbon 1.0 identity %s\n", idPath)
	}

	fmt.Fprintf(out, "\nVerifying with `carbon get`, using %s\n", idPath)
	same, differ, failed := 0, []string{}, []string{}
	for _, c := range plan.Copies {
		got, stderr, err := r.carbonCmd(carbon, idPath, nil, "get", c.Name, "--env", c.Env, "--package", c.Package)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s %s: %s", c.Scope(), c.Name, firstLine(stderr)))
		} else if bytes.Equal(got, []byte(c.value)) {
			same++
		} else {
			differ = append(differ, c.Scope()+" "+c.Name)
		}
		clear(got)
	}
	fmt.Fprintf(out, "  %d of %d value(s) read back identical", same, len(plan.Copies))
	if len(differ) > 0 {
		fmt.Fprintf(out, "; %d differ", len(differ))
	}
	if len(failed) > 0 {
		fmt.Fprintf(out, "; %d could not be read", len(failed))
	}
	fmt.Fprintln(out)
	if len(differ)+len(failed) > 0 {
		var lines []string
		for _, d := range differ {
			lines = append(lines, "differs: "+d)
		}
		for _, f := range failed {
			lines = append(lines, "unreadable: "+f)
		}
		return fmt.Errorf("verification failed, so nothing old was deleted:\n%s", indentLines(strings.Join(lines, "\n")))
	}

	fmt.Fprintln(out, "\nDeleting the 0.0.3 registries and sops configs")
	r.deletedOld = true
	for _, d := range plan.Deletes {
		r.recordWrite(d)
		if err := os.Remove(r.abs(d)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("deleting %s: %w", d, err)
		}
		fmt.Fprintf(out, "  deleted  %s\n", d)
	}
	if plan.MoveKey {
		if err := os.Remove(keyPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing %s after installing it: %w", plan.KeyFile, err)
		}
		fmt.Fprintf(out, "  removed  %s (it is now %s)\n", plan.KeyFile, idPath)
	}

	plan.RenderManual(out)
	fmt.Fprintf(out, `
Migrated. %d secret value(s) were copied and every one reads back identical.

Next:
  1. Work through the manual items above (they are also comments in each carbon.toml).
  2. Review and commit:   git add -A && git commit -m "Migrate to Carbon 1.0"
  3. Open a pull request. Teammates keep their own .carbon/private-key.age until they
     move it to ~/.config/carbon/identity themselves (see migrate/README.md).
`, len(plan.Copies))
	r.printUndo(out, true)
	return nil
}

// stdinFor frames a value for `carbon set`, which strips one trailing "\n"
// or "\r\n" from stdin. A value that ends in "\n" gets one more so the strip
// removes only that; any other value is sent as is (adding "\n" to a value
// ending in "\r" would lose the "\r").
func stdinFor(v string) []byte {
	b := []byte(v)
	if strings.HasSuffix(v, "\n") {
		b = append(b, '\n')
	}
	return b
}

func (r *runner) installIdentity(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s appeared while migrating; carbon-migrate never overwrites an identity", to)
	}
	if err != nil {
		return err
	}
	r.identityCreated = to
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// printUndo prints the exact commands that return the repository (and the
// identity) to where it was before the run.
func (r *runner) printUndo(w io.Writer, done bool) {
	if len(r.modified)+len(r.created)+len(r.untrackedEdited) == 0 && r.identityCreated == "" {
		if !done {
			fmt.Fprintln(w, "Nothing was changed.")
		}
		return
	}
	if done {
		fmt.Fprintf(w, "\nTo undo the migration before you commit it, run from %s:\n", r.root)
	} else {
		if r.deletedOld {
			fmt.Fprintln(w, "\nThe old files were being deleted when this failed; git still has them.")
		} else {
			fmt.Fprintln(w, "\nNothing old was deleted: the registries, sops configs and your 0.0.3 key are untouched.")
		}
		fmt.Fprintf(w, "To get back to exactly where you started, run from %s:\n", r.root)
	}
	if len(r.modified) > 0 {
		fmt.Fprintf(w, "  git checkout -- %s\n", shellJoin(r.modified))
	}
	if len(r.created) > 0 {
		fmt.Fprintf(w, "  git clean -f -- %s\n", shellJoin(r.created))
	}
	if r.identityCreated != "" {
		if done && r.o.Key == "" {
			fmt.Fprintf(w, "  mv %s %s\n", shellQuote(r.identityCreated), shellQuote(legacy.PrivateKeyFile))
		} else {
			fmt.Fprintf(w, "  rm %s\n", shellQuote(r.identityCreated))
		}
	} else if done && r.o.Key == "" {
		fmt.Fprintf(w, "  cp %s %s\n", shellQuote(r.identityPath()), shellQuote(legacy.PrivateKeyFile))
	}
	for _, u := range r.untrackedEdited {
		fmt.Fprintf(w, "  # %s was not tracked by git (--force), so git cannot restore it\n", u)
	}
}

func shellJoin(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = shellQuote(x)
	}
	return strings.Join(q, " ")
}

func shellQuote(s string) string {
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@", r)) {
			safe = false
		}
	}
	if safe && s != "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func indentLines(s string) string {
	if s == "" {
		return ""
	}
	return "  " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ")
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}
