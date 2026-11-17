package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/pins"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func init() {
	Register(&Command{
		Name:    "doctor",
		Group:   GroupInspection,
		Summary: "Diagnose the local setup",
		Help: `doctor checks what commonly goes wrong, without needing access to any scope:
git, the repository and workspace, the trunk ref, your identity file (present,
readable, mode 0600, outside the repo), who it maps to in policy, the current
environment, and your slot in the current package's scope. Each problem
comes with the fix. It exits 1 if anything is broken; warnings do not fail.`,
		Run: runDoctor,
	})
}

// Check statuses.
const (
	checkOK   = "ok"
	checkInfo = "info"
	checkWarn = "warn"
	checkFail = "fail"
)

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

type doctorResult struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

type doctor struct {
	c   *Context
	res doctorResult
	ids []agewrap.Identity // parsed without a passphrase; nil if protected
}

// insideDir reports whether p (relative to cwd if not absolute) is inside
// root, after resolving symlinks in both. A name such as "..foo" is inside.
func insideDir(root, p, cwd string) bool {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		p = filepath.Join(r, filepath.Base(p))
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (d *doctor) add(name, status, msg, fix string) {
	d.res.Checks = append(d.res.Checks, doctorCheck{Name: name, Status: status, Message: msg, Fix: fix})
}

func (d *doctor) addErr(name string, err error) {
	e := AsError(err)
	msg := e.Message
	if len(e.Details) > 0 {
		msg += ": " + strings.Join(e.Details, " ")
	}
	d.add(name, checkFail, msg, e.Hint)
}

func runDoctor(c *Context) error {
	d := &doctor{c: c}
	d.run()
	d.res.OK = true
	for _, ch := range d.res.Checks {
		if ch.Status == checkFail {
			d.res.OK = false
		}
	}
	if err := c.Output(d.res, d.print); err != nil {
		return err
	}
	if !d.res.OK {
		return &Error{Code: ExitError, Message: "doctor found problems", silent: true}
	}
	return nil
}

func (d *doctor) print(out io.Writer) {
	labels := map[string]string{checkOK: "ok", checkInfo: "--", checkWarn: "WARN", checkFail: "FAIL"}
	width := 0
	for _, ch := range d.res.Checks {
		width = max(width, len(ch.Name))
	}
	indent := strings.Repeat(" ", 6+width+2)
	fails, warns := 0, 0
	for _, ch := range d.res.Checks {
		fmt.Fprintf(out, "%-4s  %-*s  %s\n", labels[ch.Status], width, ch.Name, ch.Message)
		if ch.Fix != "" {
			for i, l := range strings.Split(ch.Fix, "\n") {
				prefix := "fix: "
				if i > 0 {
					prefix = "     "
				}
				fmt.Fprintf(out, "%s%s%s\n", indent, prefix, l)
			}
		}
		switch ch.Status {
		case checkFail:
			fails++
		case checkWarn:
			warns++
		}
	}
	switch {
	case fails > 0:
		fmt.Fprintf(out, "\n%d problem(s), %d warning(s).\n", fails, warns)
	case warns > 0:
		fmt.Fprintf(out, "\nNo problems, %d warning(s).\n", warns)
	default:
		fmt.Fprintln(out, "\nNo problems found.")
	}
}

func (d *doctor) run() {
	c := d.c
	// git
	gitPath, err := exec.LookPath("git")
	if err != nil {
		d.add("git", checkFail, "git is not on PATH; carbon needs it for everything",
			"Install git and make sure `git --version` works in this shell.")
		return
	}
	if out, err := exec.Command(gitPath, "--version").Output(); err == nil {
		d.add("git", checkOK, strings.TrimSpace(string(out)), "")
	} else {
		d.add("git", checkFail, "`git --version` failed: "+err.Error(), "Reinstall git.")
		return
	}

	// repository and workspace
	w, err := c.Workspace()
	if err != nil {
		name := "workspace"
		if errors.Is(err, gitx.ErrNotRepo) {
			name = "repository"
		}
		d.addErr(name, err)
		d.identity(nil, nil)
		return
	}
	d.add("repository", checkOK, w.Root, "")
	d.add("workspace", checkOK, fmt.Sprintf("carbon.toml format %d, environments %s", w.Config.Format,
		strings.Join(w.Config.Environments, ", ")), "")
	if _, err := w.Packages(); err != nil {
		d.addErr("packages", err)
	}
	d.attributes(w)
	trunkPol := d.trunk(w)

	wpol, err := c.WorktreePolicy(w)
	if err != nil {
		d.addErr("policy", err)
	}
	me := d.identity(w, wpol)
	d.trunkIdentity(trunkPol, me)
	d.pins(w)
	env := d.environment(w)
	if env != "" && wpol != nil {
		d.scope(w, wpol, env, me)
	}
}

func (d *doctor) attributes(w *Workspace) {
	b, _ := os.ReadFile(filepath.Join(w.Root, ".gitattributes"))
	if !strings.Contains(string(b), "linguist-generated") || !strings.Contains(string(b), ".keys.toml") {
		d.add("gitattributes", checkWarn, "keys files are not marked generated, so reviews show every slot line",
			"Add this line to .gitattributes:   **/.carbon/*.keys.toml linguist-generated")
	}
}

// trunk reports where policy comes from and returns trunk policy (nil when
// it cannot be read).
func (d *doctor) trunk(w *Workspace) *policy.Policy {
	t, err := policy.ResolveTrunk(w.Repo, d.c.Getenv)
	if err != nil {
		d.addErr("trunk", err)
		return nil
	}
	pol, err := policy.LoadTrunkAt(w.Repo, t)
	if err != nil {
		d.addErr("trunk", err)
		return nil
	}
	// Later checks (the scope's trunk check) reuse it; doctor reports the
	// bootstrap state itself, so its notice is not printed.
	d.c.trunkPol = pol
	undo := "git config --unset " + policy.TrunkConfigKey
	if t.From == policy.TrunkFromEnv {
		undo = "unset " + policy.TrunkEnv
	}
	switch pol.Origin {
	case policy.OriginTrunk:
		id, _ := w.Repo.ResolveRef(pol.Ref)
		if len(id) > 10 {
			id = id[:10]
		}
		d.add("trunk", checkOK, fmt.Sprintf("%s (from %s) at %s; policy is read from it", t.Ref, t.From, id), "")
	case policy.OriginWorktreeTrunk:
		d.add("trunk", checkWarn, fmt.Sprintf("trunk is \"worktree\" (from %s): policy is read from the working tree, so access is not gated by review", t.From),
			"Use your protected branch instead:   "+undo+"\nor:   git config "+policy.TrunkConfigKey+" origin/main")
	case policy.OriginBootstrap:
		if t.From == policy.TrunkFromNone {
			d.add("trunk", checkWarn, "no trunk yet (no remote, no git config "+policy.TrunkConfigKey+"): bootstrap mode, policy comes from the working tree",
				"Once the workspace is on a remote:   git fetch\nOr name the trunk for this clone:   git config "+policy.TrunkConfigKey+" <ref>")
		} else {
			d.add("trunk", checkWarn, fmt.Sprintf("trunk %s (from %s) has no carbon.toml: bootstrap mode, policy comes from the working tree", t.Ref, t.From),
				"Merge the carbon workspace to trunk so that access is gated by review.")
		}
	}
	return pol
}

// identity checks the identity and returns the caller's devices in policy.
func (d *doctor) identity(w *Workspace, pol *policy.Policy) []policy.Device {
	c := d.c
	var data []byte
	source := "CARBON_IDENTITY"
	if v := c.Getenv("CARBON_IDENTITY"); v != "" {
		data = []byte(v)
		d.add("identity", checkInfo, "from the CARBON_IDENTITY variable (overrides any identity file)", "")
	} else {
		path := c.IdentityPath()
		source = path
		fi, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			d.add("identity", checkFail, "no identity at "+path,
				"Create one:   carbon join\nOr point CARBON_IDENTITY_FILE at an existing identity file.")
			return nil
		}
		if err != nil {
			d.add("identity", checkFail, "cannot stat "+path+": "+err.Error(), "Check the path and its permissions.")
			return nil
		}
		if fi.IsDir() {
			d.add("identity", checkFail, path+" is a directory, not an identity file", "Move it aside and run:   carbon join")
			return nil
		}
		if w != nil && insideDir(w.Root, path, c.Cwd) {
			d.add("identity", checkFail, "your private key "+path+" is inside the repository",
				"Move it out of the repository (for example to ~/.config/carbon/identity) and set CARBON_IDENTITY_FILE if needed.")
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			d.add("identity", checkFail, fmt.Sprintf("%s has mode %04o: other users can read your private key", path, perm),
				"Restrict it:   chmod 600 "+path)
		}
		data, err = os.ReadFile(path)
		if err != nil {
			d.add("identity", checkFail, "cannot read "+path+": "+err.Error(), "Fix its ownership and permissions:   chmod 600 "+path)
			return nil
		}
	}
	defer clear(data)
	if agewrap.IsEncryptedIdentityFile(data) {
		d.add("identity", checkInfo, source+" is passphrase-protected; who it maps to is not checked without the passphrase", "")
		return nil
	}
	ids, err := agewrap.ParseIdentityFile(data, nil)
	d.ids = ids
	if err != nil || len(ids) == 0 {
		why := "it holds no identity"
		if err != nil {
			why = err.Error()
		}
		d.add("identity", checkFail, "cannot parse "+source+": "+why,
			"Restore the file from your backup, or create a new one with `carbon join` and ask a reader to run `carbon apply`.")
		return nil
	}
	d.add("identity", checkOK, fmt.Sprintf("%s holds %d key(s)", source, len(ids)), "")
	for _, id := range ids {
		switch id.Kind {
		case agewrap.KindHybrid:
			d.add("key type", checkOK, "hybrid post-quantum (ML-KEM-768 + X25519)", "")
		case agewrap.KindX25519:
			fix := ""
			status := checkInfo
			if w != nil && anyRequirePQ(w.Config) {
				status = checkWarn
				fix = "Environments with require_pq = true will not wrap to this key. Create a hybrid device:   carbon join --device <name>"
			}
			d.add("key type", status, "X25519 (not post-quantum)", fix)
		case agewrap.KindPlugin:
			d.add("key type", checkInfo, "plugin (hardware) identity", "")
		}
	}
	if pol == nil {
		return nil
	}
	me := Me(pol, ids)
	if len(me) == 0 {
		fix := "Add yourself:   carbon join\nThen open a pull request with the new file and ask to be added to a team."
		if pol.Workspace != nil && len(pol.People) == 0 && len(pol.Machines) == 0 {
			fix = "Nobody has joined this workspace yet. Run:   carbon join"
		}
		d.add("who", checkFail, "your key is not in .carbon/people or .carbon/machines", fix)
		return nil
	}
	for _, dev := range me {
		msg := "you are " + dev.ID
		if !dev.Machine {
			msg = fmt.Sprintf("you are %s (device %s)", dev.Person, dev.Device)
			if teams := pol.TeamsOf(dev.Person); len(teams) > 0 {
				for i := range teams {
					teams[i] = "@" + teams[i]
				}
				msg += ", a member of " + joinAnd(teams)
			} else {
				msg += ", in no team"
			}
		}
		d.add("who", checkOK, msg, "")
	}
	return me
}

func anyRequirePQ(ws *config.Workspace) bool {
	for _, a := range ws.Access {
		if a.RequirePQ != nil && *a.RequirePQ {
			return true
		}
	}
	return false
}

// trunkIdentity warns when the caller's device is in the working tree but
// not on trunk yet: grants wait for that merge.
func (d *doctor) trunkIdentity(trunk *policy.Policy, me []policy.Device) {
	if trunk == nil || trunk.Origin != policy.OriginTrunk {
		return
	}
	for _, dev := range me {
		if _, ok := trunk.Identify(dev.Recipient); !ok {
			d.add("who", checkWarn, fmt.Sprintf("%s is not on trunk %s yet, so nobody can grant it access", dev.ID, trunk.Ref),
				"Open a pull request with your .carbon/people (or machines) file and get it merged.")
		}
	}
}

// environment reports the current environment and its source.
func (d *doctor) environment(w *Workspace) string {
	c := d.c
	env, why := c.Global.Env, "from --env"
	if env == "" {
		env, why = c.Getenv("CARBON_ENV"), "from CARBON_ENV"
	}
	if env == "" {
		stored, err := ReadEnvUse(w.Repo)
		if err != nil {
			d.addErr("environment", err)
			return ""
		}
		env, why = stored, "from `carbon env use`"
	}
	if env == "" {
		env, why = w.Config.DefaultEnvironment, "the default"
	}
	if !w.Config.HasEnvironment(env) {
		fix := "Pick one of " + strings.Join(w.Config.Environments, ", ") + ":   carbon env use <name>"
		if why == "from CARBON_ENV" {
			fix = "Unset it or set it to one of " + strings.Join(w.Config.Environments, ", ") + ":   unset CARBON_ENV"
		}
		d.add("environment", checkFail, fmt.Sprintf("%q (%s) is not an environment of this workspace", env, why), fix)
		return ""
	}
	d.add("environment", checkOK, fmt.Sprintf("%s (%s)", env, why), "")
	return env
}

// scope reports the caller's standing in the current package's scope,
// without opening it.
func (d *doctor) scope(w *Workspace, pol *policy.Policy, env string, me []policy.Device) {
	c := d.c
	if _, err := w.Packages(); err != nil {
		return
	}
	pkg, err := c.Package(w)
	if err != nil {
		if c.Global.Package != "" {
			d.addErr("package", err)
			return
		}
		d.add("package", checkInfo, "not inside a package (use --package <name> to check one)", "")
		return
	}
	s, err := c.LoadScope(w, pkg, env)
	if err != nil {
		d.addErr("scope", err)
		return
	}
	name := s.Name()
	if !s.HasKey() {
		d.add("scope", checkInfo, name+" has no key yet; the first `carbon set` creates it", "")
		return
	}
	ids := DeviceIDs(me)
	if d.ids != nil {
		// Really open it, and check its key against trunk, as a reader's
		// command would.
		o, err := s.Open(d.ids, ids...)
		switch {
		case err == nil:
			verr := c.VerifyTrunk(w, pkg, o)
			slot := o.Slot
			o.Close()
			if verr != nil {
				d.addErr("scope", verr)
				return
			}
			d.add("scope", checkOK, fmt.Sprintf("%s: your key opens it (slot %s) and it matches trunk", name, slot), "")
			d.drops(s)
			return
		case !errors.Is(err, scope.ErrNotReader):
			d.addErr("scope", err)
			return
		}
	} else {
		// Passphrase-protected: say what the keys file shows, unverified.
		for _, id := range s.SlotIDs() {
			for _, mine := range ids {
				if id == mine {
					d.add("scope", checkInfo, fmt.Sprintf("%s: there is a slot for %s (not opened: the identity is passphrase-protected)", name, id), "")
					d.drops(s)
					return
				}
			}
		}
	}
	if len(me) == 0 {
		return
	}
	sa, err := pol.Scope(pkg.Name, env)
	if err != nil {
		d.addErr("scope", err)
		return
	}
	if sa.Readable(ids...) {
		d.add("scope", checkWarn, fmt.Sprintf("%s: policy names you, but your device has no slot yet", name),
			"Ask a current reader to run:   carbon apply")
		return
	}
	d.add("scope", checkInfo, fmt.Sprintf("%s: you are not a reader (you can still drop values with `carbon set`)", name),
		fmt.Sprintf("To ask for access:   carbon request %s --env %s", pkg.Name, env))
}

func (d *doctor) drops(s *scope.Scope) {
	var names []string
	for _, n := range s.Secrets.Names() {
		if s.Secrets.Entries[n].IsDrop() {
			names = append(names, n)
		}
	}
	if len(names) > 0 {
		d.add("drops", checkInfo, fmt.Sprintf("%s has unreviewed drops: %s", s.Name(), strings.Join(names, ", ")),
			"Review them, then promote with:   carbon apply")
	}
}

// pins checks the per-clone file of the last scope key each reader
// verified. A corrupt file stops every reader command, so it is a failure.
func (d *doctor) pins(w *Workspace) {
	path, err := pins.Path(w.Repo)
	if err != nil {
		d.addErr("pins", err)
		return
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		d.add("pins", checkInfo, "no pinned scope keys yet ("+path+"); each scope is pinned the first time you read it", "")
		return
	}
	if _, err := d.c.LoadPins(w); err != nil {
		d.addErr("pins", err)
		return
	}
	d.add("pins", checkOK, path, "")
}
