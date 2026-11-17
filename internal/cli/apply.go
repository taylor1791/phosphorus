package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
)

func init() {
	Register(&Command{
		Name:    "apply",
		Usage:   "[--package <name>] [--env <env>] [--no-commit] [--dry-run]",
		Summary: "Apply merged policy: wrap, rotate, re-seal, promote drops",
		Help: `apply carries out the access policy merged to trunk, for every package in
every environment (or the ones named with --package and --env). Policy and
public keys are read from the trunk ref, never from the working tree, so a
branch cannot grant itself access. For each scope it:

  - creates the key of a scope that declares secrets and has none yet,
    wrapped to the devices trunk policy names (only if you are one of them);
  - adds a slot for each device trunk policy names that has none (a grant);
  - rotates the key when it has a slot for a device trunk policy no longer
    names: a new key and inbox, every value re-sealed keeping its set time,
    the old key retired with reason "removed <who>";
  - promotes drops to sealed values;
  - re-seals values under retired keys. Whoever wrote those held a retired
    key, which a removed reader may still hold, so the plan lists each one
    (marking any whose set time is after its key was retired); re-sealing
    vouches for them. --skip-unproven leaves them as they are.

Every scope's key is checked against trunk's before anything is done to it.
Drops that do not open are left as they are and reported.

It does what you can do (the scopes you can open) and reports the rest,
naming who can finish it. It prints the plan and asks for confirmation
(--yes skips it; --dry-run only prints it), then writes and commits exactly
the files it changed. --no-commit leaves them uncommitted.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("no-commit", false, "write the changes but do not commit them")
			fs.Bool("dry-run", false, "print the plan and change nothing")
			fs.Bool("skip-unproven", false, "leave values under retired keys as they are instead of re-sealing them")
		},
		Run: runApply,
	})
}

// applyGrant is a device that gains access.
type applyGrant struct {
	Device      string   `json:"device"`
	Fingerprint string   `json:"fingerprint"`
	Via         []string `json:"via,omitempty"`
}

// applyRotation describes a key rotation.
type applyRotation struct {
	From   string `json:"from"`
	To     string `json:"to,omitempty"` // known once applied
	Reason string `json:"reason"`
	Values int    `json:"values"`
}

// applyScope is the plan, and then the outcome, for one scope.
type applyScope struct {
	Scope   string `json:"scope"`
	Package string `json:"package"`
	Env     string `json:"env"`
	// Status: "planned" (you can do it), "applied", "needs-reader" (someone
	// else must), "blocked" (out of step or broken), "failed", or "ok"
	// (nothing to do, but something to report).
	Status  string         `json:"status"`
	Create  bool           `json:"create,omitempty"`
	Grant   []applyGrant   `json:"grant,omitempty"`
	Revoke  []string       `json:"revoke,omitempty"`
	Rotate  *applyRotation `json:"rotate,omitempty"`
	Promote []string       `json:"promote,omitempty"`
	// Unproven are entries under retired keys: whoever wrote them held that
	// key, which a removed reader may still. apply re-seals them under the
	// current key (vouching for them) unless SkipUnproven.
	Unproven     []applyStale `json:"unproven,omitempty"`
	SkipUnproven bool         `json:"skip_unproven,omitempty"`
	// BadDrops are drops that do not open; they are left exactly as they are.
	BadDrops  []string `json:"bad_drops,omitempty"`
	SkippedPQ []string `json:"skipped_pq,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	// Readers are who can finish a needs-reader scope: the holders of the
	// current key's slots.
	Readers []string `json:"readers,omitempty"`
	Problem string   `json:"problem,omitempty"`
	Fix     string   `json:"fix,omitempty"`
	Files   []string `json:"files,omitempty"`

	s        *scope.Scope
	opened   *scope.Opened
	sa       *policy.ScopeAccess
	eligible []policy.Device
	missing  []policy.Device
}

// applyStale is an entry under a retired key.
type applyStale struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	Set  string `json:"set"`
	Drop bool   `json:"drop,omitempty"`
	// SetAfterRetired: its set time is after its key was retired, so it was
	// written (or claims to be) by someone holding a retired key. Suspect.
	SetAfterRetired bool `json:"set_after_retired,omitempty"`
}

func (p *applyScope) hasWork() bool {
	return p.Create || len(p.Grant) > 0 || p.Rotate != nil || len(p.Promote) > 0 ||
		(len(p.Unproven) > 0 && !p.SkipUnproven)
}

func slicesContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

type applyResult struct {
	Policy      string        `json:"policy"`
	Scopes      []*applyScope `json:"scopes"`
	NothingToDo bool          `json:"nothing_to_do"`
	DryRun      bool          `json:"dry_run,omitempty"`
	Files       []string      `json:"files,omitempty"`
	Commit      string        `json:"commit,omitempty"`
}

func runApply(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	var names []string
	if p := c.Global.Package; p != "" {
		if _, ok := pkgs[p]; !ok {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no package named %q", p),
				Hint: "Check the name in the package's carbon.toml."}
		}
		names = []string{p}
	} else {
		for n := range pkgs {
			names = append(names, n)
		}
		sort.Strings(names)
	}
	envs := w.Config.Environments
	if e := c.Global.Env; e != "" {
		if !w.Config.HasEnvironment(e) {
			return &Error{Code: ExitUsage, Message: fmt.Sprintf("unknown environment %q", e),
				Hint: "Environments in this workspace: " + strings.Join(envs, ", ")}
		}
		envs = []string{e}
	}

	pol, err := c.TrunkPolicy(w)
	if err != nil {
		return err
	}
	ids, err := c.Identities(false)
	if err != nil {
		return err
	}
	prefer := DeviceIDs(Me(pol, ids))
	res := applyResult{Policy: applyPolicyLabel(pol), DryRun: c.Bool("dry-run")}
	defer func() {
		for _, p := range res.Scopes {
			if p.opened != nil {
				p.opened.Close()
			}
		}
	}()

	for _, name := range names {
		for _, env := range envs {
			p := c.planApplyScope(w, pol, pkgs[name], env, ids, prefer)
			if p != nil {
				res.Scopes = append(res.Scopes, p)
			}
		}
	}

	var doable, pending []*applyScope
	for _, p := range res.Scopes {
		switch p.Status {
		case "planned":
			doable = append(doable, p)
		case "needs-reader", "blocked", "refused":
			pending = append(pending, p)
		}
	}
	res.NothingToDo = len(doable) == 0 && len(pending) == 0

	if res.NothingToDo || res.DryRun || len(doable) == 0 {
		if err := c.Output(res, func(out io.Writer) { printApply(out, &res) }); err != nil {
			return err
		}
		if len(doable) == 0 && len(pending) > 0 && !res.DryRun {
			return applyNothingDoneErr(c, pending)
		}
		return nil
	}

	noCommit := c.Bool("no-commit")
	if !c.JSON() {
		printApply(c.Stdout, &res)
	}
	if !noCommit {
		if err := applyCheckClean(w, doable); err != nil {
			return err
		}
	}
	if err := c.Confirm(fmt.Sprintf("Apply this plan to %d scope(s)?", len(doable))); err != nil {
		return err
	}

	var written []string
	var log []string
	now := c.Now()
	failed := 0
	for _, p := range doable {
		files, lines, err := executeApplyScope(w, p, now)
		if err != nil {
			e := AsError(err)
			p.Status, p.Problem = "failed", e.Message
			if len(e.Details) > 0 && e.Details[0] != e.Message {
				p.Problem += " (" + e.Details[0] + ")"
			}
			p.Fix = "Nothing in this scope was changed. Fix the problem above and run `carbon apply` again."
			failed++
			continue
		}
		p.Status, p.Files = "applied", files
		written = append(written, files...)
		log = append(log, lines...)
	}
	res.Files = written

	if len(written) > 0 && !noCommit {
		msg := applyCommitMessage(doable, log)
		if err := w.Repo.Commit(msg, written...); err != nil {
			return &Error{Code: ExitError, Message: "the changes were written but could not be committed",
				Details: []string{firstLineOf(err.Error()), "Files: " + strings.Join(written, ", ")},
				Hint:    "Commit them yourself:   git commit -- " + strings.Join(written, " "), Err: err}
		}
		if out, err := w.Repo.Git("rev-parse", "--short", "HEAD"); err == nil {
			res.Commit = strings.TrimSpace(string(out))
		}
	}

	if err := c.Output(res, func(out io.Writer) { printApplyOutcome(out, &res, noCommit) }); err != nil {
		return err
	}
	if failed > 0 {
		return &Error{Code: ExitError, Message: fmt.Sprintf("%d scope(s) could not be applied; they were left unchanged", failed), silent: c.JSON()}
	}
	return nil
}

func firstLineOf(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

// applyPolicyLabel says where policy came from: "origin/main (remote
// default)", "main (git config carbon.trunk)", or the working tree.
func applyPolicyLabel(pol *policy.Policy) string {
	from := ""
	if pol.Trunk != nil {
		from = pol.Trunk.From
		if from == policy.TrunkFromRemote {
			from = "remote default"
		}
	}
	switch pol.Origin {
	case policy.OriginTrunk:
		if from == "" {
			return pol.Ref
		}
		return fmt.Sprintf("%s (%s)", pol.Ref, from)
	case policy.OriginWorktreeTrunk:
		return fmt.Sprintf("the working tree (trunk is \"worktree\", from %s)", from)
	}
	return "the working tree (carbon is not on trunk yet)"
}

// planApplyScope works out what apply would do in one scope, opening it
// when there is work. It returns nil when there is nothing to report.
func (c *Context) planApplyScope(w *Workspace, pol *policy.Policy, pkg *config.Package, env string, ids []agewrap.Identity, prefer []string) *applyScope {
	p := &applyScope{Scope: config.ScopeName(pkg.Name, env), Package: pkg.Name, Env: env, Status: "ok"}
	block := func(problem, fix string) *applyScope {
		p.Status, p.Problem, p.Fix = "blocked", problem, fix
		return p
	}
	// Trunk's keys file for the scope, and the name trunk policy knows the
	// package by: a package renamed on this branch is still the old name on
	// trunk, and its access is the old name's, not the workspace default.
	var tk *store.Keys
	policyName := pkg.Name
	if pol.Origin == policy.OriginTrunk {
		dir := pkg.Dir
		if tp, ok := pol.Packages[pkg.Name]; ok {
			dir = tp.Dir
		}
		var err error
		tk, err = scope.ReadKeysAt(w.Repo.Source(pol.Ref), dir, env)
		if err != nil {
			e := AsError(err)
			return block("cannot read the keys file on trunk: "+e.Message, "")
		}
		if _, known := pol.Packages[pkg.Name]; !known && tk != nil {
			if old, _, err := config.ParseScopeName(tk.Scope); err == nil && old != pkg.Name {
				if tp, ok := pol.Packages[old]; ok && tp.Dir == pkg.Dir {
					policyName = old
					p.Warnings = append(p.Warnings, fmt.Sprintf("renamed from %s on this branch; access comes from %s's entry on trunk until the rename merges", old, old))
				}
			}
		}
	}
	sa, err := pol.Scope(policyName, env)
	if err != nil {
		return block(err.Error(), "")
	}
	p.sa = sa
	for _, u := range sa.Unresolved {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s names %s, which is not a team, person or machine on %s", applyReadersFrom(sa), u, sourceName(pol)))
	}
	eligible, skipped := sa.Eligible()
	p.eligible = eligible

	s, err := scope.Load(w.Dir(pkg), pkg.Name, env)
	if err != nil {
		e := AsError(err)
		return block(e.Message, e.Hint)
	}
	p.s = s

	var outOfStep, outFix string
	if pol.Origin == policy.OriginTrunk {
		switch {
		case tk != nil && s.Keys == nil:
			return block(fmt.Sprintf("trunk %s has a key for %s that this branch does not have", pol.Ref, p.Scope),
				fmt.Sprintf("Bring this branch up to date first:   git merge %s", pol.Ref))
		case tk != nil && tk.Current != s.Keys.Current:
			// Decided after opening: a key that does not descend from
			// trunk's is refused; one that does is only out of step.
			outOfStep = fmt.Sprintf("the current key here (%s) differs from trunk's (%s): a rotation on this branch is not merged yet, or trunk rotated and this branch has not merged it",
				s.Keys.Current, tk.Current)
			outFix = fmt.Sprintf("Merge trunk into this branch (git merge %s) and keep trunk's keys file, or merge this branch to trunk first; then run `carbon apply` again. Applying now would rotate on top of a key trunk does not use.", pol.Ref)
		}
	}

	for _, d := range skipped {
		has := s.Keys != nil && s.Keys.CurrentKey().Slots[d.ID] != ""
		if has {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s holds a slot but its key is X25519 and %s requires post-quantum keys; `carbon check` fails until its key is replaced", d.ID, env))
		} else {
			p.SkippedPQ = append(p.SkippedPQ, d.ID)
		}
	}

	if s.Keys == nil {
		if len(pkg.Secrets) == 0 || len(eligible) == 0 {
			if len(p.Warnings) == 0 && len(p.SkippedPQ) == 0 {
				return nil
			}
			return p
		}
		p.Create = true
		p.missing = eligible
		p.Grant = applyGrants(sa, eligible)
		// Only a device trunk policy names for the scope may create its key.
		for _, d := range eligible {
			for _, id := range prefer {
				if d.ID == id {
					p.Status = "planned"
					return p
				}
			}
		}
		p.Status = "needs-reader"
		p.Problem = "only a device that trunk policy names for " + p.Scope + " may create its key"
		p.Readers = slotHolders(DeviceIDs(eligible))
		return p
	}

	diff := s.DiffSlots(sa.Devices)
	for _, d := range diff.Missing {
		if !sa.RequirePQ || d.Hybrid() {
			p.missing = append(p.missing, d)
		}
	}
	p.Grant = applyGrants(sa, p.missing)
	for _, name := range s.Secrets.Names() {
		if s.Secrets.Entries[name].IsDrop() {
			p.Promote = append(p.Promote, name)
		}
	}
	p.SkipUnproven = c.Bool("skip-unproven")
	for _, st := range s.StaleEntries() {
		p.Unproven = append(p.Unproven, applyStale{Name: st.Name, Key: st.KeyID, Set: seal.FormatTime(st.Set),
			Drop: st.Drop, SetAfterRetired: st.SetAfterRetired})
	}
	if len(diff.Extra) > 0 {
		p.Revoke = diff.Extra
		for _, d := range skipped {
			if s.Keys.CurrentKey().Slots[d.ID] != "" {
				p.Revoke = append(p.Revoke, d.ID)
			}
		}
		values := len(s.Secrets.Entries)
		if p.SkipUnproven {
			values -= len(p.Unproven)
		}
		p.Rotate = &applyRotation{From: s.Keys.Current, Reason: "removed " + removedWho(diff.Extra, s.SlotIDs(), sa),
			Values: values}
		if len(eligible) == 0 {
			return block(fmt.Sprintf("%s must rotate (%s), but trunk policy names nobody who could hold the new key", p.Scope, p.Rotate.Reason),
				"Name at least one reader for "+p.Scope+" in policy, merge it, and run `carbon apply` again.")
		}
	}
	if !p.hasWork() && outOfStep == "" {
		if len(p.Warnings) == 0 && len(p.SkippedPQ) == 0 && len(p.Unproven) == 0 {
			return nil
		}
		return p
	}

	o, err := s.Open(ids, prefer...)
	switch {
	case errors.Is(err, scope.ErrNotReader) && outOfStep != "":
		return block(outOfStep, outFix)
	case errors.Is(err, scope.ErrNotReader):
		p.Status = "needs-reader"
		// Who can finish it: the current key's readers that stay readers.
		var stay []string
		for _, id := range s.SlotIDs() {
			if sa.Names(id) {
				stay = append(stay, id)
			}
		}
		p.Readers = slotHolders(stay)
		return p
	case err != nil:
		e := AsError(err)
		return block(e.Message, e.Hint)
	}
	p.opened = o
	// Verify the key against trunk before doing anything with it.
	if pol.Origin == policy.OriginTrunk {
		if err := c.VerifyTrunk(w, pkg, o); err != nil {
			e := AsError(err)
			p.Status, p.Problem, p.Fix = "refused", e.Message, e.Hint
			if len(e.Details) > 0 {
				p.Problem += " (" + e.Details[0] + ")"
			}
			return p
		}
	}
	if outOfStep != "" {
		return block(outOfStep, outFix)
	}
	// Drops that do not open are left alone and reported, never fatal.
	var good []string
	for _, name := range p.Promote {
		v, err := o.Reveal(name)
		if err != nil {
			p.BadDrops = append(p.BadDrops, name)
			continue
		}
		v.Zero()
		good = append(good, name)
	}
	p.Promote = good
	if len(p.BadDrops) > 0 {
		var unproven []applyStale
		for _, u := range p.Unproven {
			if !slicesContains(p.BadDrops, u.Name) {
				unproven = append(unproven, u)
			}
		}
		p.Unproven = unproven
		if !p.hasWork() {
			p.Status = "ok"
			return p
		}
	}
	p.Status = "planned"
	return p
}

func applyReadersFrom(sa *policy.ScopeAccess) string {
	if sa.ReadersFrom != "" {
		return sa.ReadersFrom
	}
	return "policy"
}

func applyGrants(sa *policy.ScopeAccess, ds []policy.Device) []applyGrant {
	var out []applyGrant
	for _, d := range ds {
		out = append(out, applyGrant{Device: d.ID, Fingerprint: agewrap.Fingerprint(d.Recipient), Via: sa.Why[d.ID]})
	}
	return out
}

// removedWho names what a rotation removes: a person when all of their
// slots go and policy names none of their devices, else each device; and
// machines.
func removedWho(extra, slots []string, sa *policy.ScopeAccess) string {
	byPerson := map[string][]string{}
	var people, out []string
	for _, id := range extra {
		if strings.HasPrefix(id, config.MachinePrefix) {
			continue
		}
		person, _, _ := strings.Cut(id, "/")
		if _, ok := byPerson[person]; !ok {
			people = append(people, person)
		}
		byPerson[person] = append(byPerson[person], id)
	}
	sort.Strings(people)
	for _, person := range people {
		all := 0
		for _, id := range slots {
			if strings.HasPrefix(id, person+"/") {
				all++
			}
		}
		named := false
		for _, d := range sa.Devices {
			if d.Person == person {
				named = true
			}
		}
		if all == len(byPerson[person]) && !named {
			out = append(out, person)
		} else {
			out = append(out, byPerson[person]...)
		}
	}
	for _, id := range extra {
		if strings.HasPrefix(id, config.MachinePrefix) {
			out = append(out, id)
		}
	}
	return strings.Join(out, ", ")
}

// slotHolders groups slot ids by person: "lin (laptop, desk)",
// "machine:deploy".
func slotHolders(ids []string) []string {
	devs := map[string][]string{}
	var order, out []string
	for _, id := range ids {
		if strings.HasPrefix(id, config.MachinePrefix) {
			out = append(out, id)
			continue
		}
		person, dev, _ := strings.Cut(id, "/")
		if _, ok := devs[person]; !ok {
			order = append(order, person)
		}
		devs[person] = append(devs[person], dev)
	}
	var people []string
	for _, person := range order {
		people = append(people, fmt.Sprintf("%s (%s)", person, strings.Join(devs[person], ", ")))
	}
	sort.Strings(people)
	return append(people, out...)
}

// applyCheckClean refuses to commit when files apply would write already
// have uncommitted changes, which the commit would sweep in.
func applyCheckClean(w *Workspace, ps []*applyScope) error {
	var paths []string
	for _, p := range ps {
		paths = append(paths, w.Rel(p.s.KeysPath()), w.Rel(p.s.SecretsPath()))
	}
	out, err := w.Repo.Git(append([]string{"status", "--porcelain", "--untracked-files=all", "--"}, paths...)...)
	if err != nil {
		return err
	}
	var dirty []string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if len(line) > 3 {
			dirty = append(dirty, line[3:])
		}
	}
	if len(dirty) == 0 {
		return nil
	}
	return &Error{Code: ExitError, Message: "files that apply would commit have uncommitted changes",
		Details: append([]string{"apply commits exactly the files it changes; these changes would be swept into its commit:"}, dirty...),
		Hint:    "Commit them first (git commit -- <file>), or run:   carbon apply --no-commit"}
}

// executeApplyScope carries out one scope's plan in memory, then writes its
// two files. On any error nothing in the scope is written.
func executeApplyScope(w *Workspace, p *applyScope, now time.Time) ([]string, []string, error) {
	var lines []string
	o := p.opened
	switch {
	case p.Create:
		var err error
		if o, err = p.s.Create(p.eligible, now); err != nil {
			return nil, nil, err
		}
		p.opened = o
		lines = append(lines, fmt.Sprintf("%s: create key %s for %s", p.Scope, o.CurrentID(), strings.Join(DeviceIDs(p.eligible), ", ")))
	case p.Rotate != nil:
		from := o.CurrentID()
		// --skip-unproven: entries under retired keys stay as they are; the
		// retired chain still opens them after the rotation.
		held := map[string]store.Entry{}
		if p.SkipUnproven {
			for _, u := range p.Unproven {
				held[u.Name] = o.Secrets.Entries[u.Name]
				delete(o.Secrets.Entries, u.Name)
			}
		}
		to, bad, err := o.RotateSkippingBadDrops(p.eligible, p.Rotate.Reason, now)
		for name, e := range held {
			o.Secrets.Entries[name] = e
		}
		if err != nil {
			return nil, nil, err
		}
		for _, b := range bad {
			if !slicesContains(p.BadDrops, b) {
				p.BadDrops = append(p.BadDrops, b)
			}
		}
		p.Rotate.To = to
		lines = append(lines, fmt.Sprintf("%s: rotate %s -> %s (%s), re-seal %d value(s)", p.Scope, from, to, p.Rotate.Reason, p.Rotate.Values))
		if len(p.missing) > 0 {
			lines = append(lines, fmt.Sprintf("%s: grant %s", p.Scope, strings.Join(DeviceIDs(p.missing), ", ")))
		}
	default:
		added, err := o.AddSlots(p.missing)
		if err != nil {
			return nil, nil, err
		}
		if len(added) > 0 {
			lines = append(lines, fmt.Sprintf("%s: grant %s", p.Scope, strings.Join(added, ", ")))
		}
	}
	// Promote each drop that opens (PromoteAt clamps a future set time);
	// one that does not is left as it is and reported.
	var promoted []string
	for _, name := range o.Secrets.Names() {
		e := o.Secrets.Entries[name]
		if !e.IsDrop() || slicesContains(p.BadDrops, name) {
			continue
		}
		if p.SkipUnproven && e.Key != o.CurrentID() {
			continue
		}
		ok, err := o.PromoteAt(name, now)
		if err != nil {
			p.BadDrops = append(p.BadDrops, name)
			continue
		}
		if ok {
			promoted = append(promoted, name)
		}
	}
	if len(promoted) > 0 {
		lines = append(lines, fmt.Sprintf("%s: promote %s", p.Scope, strings.Join(promoted, ", ")))
	}
	if !p.SkipUnproven {
		r, err := o.RefreshDetailed()
		if err != nil {
			return nil, nil, err
		}
		var names []string
		for _, m := range r.Moved {
			names = append(names, m.Name)
		}
		for _, b := range r.SkippedDrops {
			if !slicesContains(p.BadDrops, b) {
				p.BadDrops = append(p.BadDrops, b)
			}
		}
		if len(names) > 0 {
			lines = append(lines, fmt.Sprintf("%s: re-seal %s under %s (unproven: written under a retired key)", p.Scope, strings.Join(names, ", "), o.CurrentID()))
		}
	}
	if len(p.BadDrops) > 0 {
		lines = append(lines, fmt.Sprintf("%s: left drops that do not open: %s", p.Scope, strings.Join(p.BadDrops, ", ")))
	}
	files, err := writeScopeFiles(p.s)
	if err != nil {
		return nil, nil, err
	}
	for i := range files {
		files[i] = w.Rel(files[i])
	}
	return files, lines, nil
}

// writeScopeFiles writes a scope's keys and secrets files, restoring the
// keys file if the secrets file cannot be written. It returns the paths
// whose content changed.
func writeScopeFiles(s *scope.Scope) ([]string, error) {
	type file struct {
		path string
		data []byte
	}
	var files []file
	files = append(files, file{s.KeysPath(), s.Keys.Marshal()})
	if _, err := os.Stat(s.SecretsPath()); len(s.Secrets.Entries) > 0 || err == nil {
		files = append(files, file{s.SecretsPath(), s.Secrets.Marshal()})
	}
	var written []string
	var undo []func()
	for _, f := range files {
		old, err := os.ReadFile(f.path)
		existed := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if existed && string(old) == string(f.data) {
			continue
		}
		if err := store.WriteFile(f.path, f.data); err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
			return nil, err
		}
		path := f.path
		if existed {
			undo = append(undo, func() { store.WriteFile(path, old) })
		} else {
			undo = append(undo, func() { os.Remove(path) })
		}
		written = append(written, f.path)
	}
	return written, nil
}

func applyCommitMessage(ps []*applyScope, log []string) string {
	var grants, rotations, creates, promotes, reseals int
	for _, p := range ps {
		if p.Status != "applied" {
			continue
		}
		grants += len(p.Grant)
		promotes += len(p.Promote)
		if !p.SkipUnproven {
			reseals += len(p.Unproven)
		}
		if p.Rotate != nil {
			rotations++
		}
		if p.Create {
			creates++
		}
	}
	var parts []string
	add := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", what, n))
		}
	}
	add(creates, "create")
	add(grants, "grant")
	add(rotations, "rotate")
	add(promotes, "promote")
	add(reseals, "re-seal")
	return "carbon apply: " + strings.Join(parts, ", ") + "\n\n" + strings.Join(log, "\n") + "\n"
}

func applyNothingDoneErr(c *Context, pending []*applyScope) error {
	needReader := false
	for _, p := range pending {
		if p.Status == "needs-reader" {
			needReader = true
		}
	}
	e := &Error{Code: ExitError, Message: "nothing was applied: the remaining work is blocked", silent: c.JSON()}
	if needReader {
		e.Code = ExitNoAccess
		e.Message = "nothing was applied: you cannot open the scopes that need it"
		e.Hint = "Ask one of the readers listed above to run:   carbon apply"
	}
	return e
}

func printApply(out io.Writer, res *applyResult) {
	fmt.Fprintf(out, "Policy from %s.\n", res.Policy)
	if res.NothingToDo {
		fmt.Fprintln(out, "Nothing to do: every scope matches policy.")
		for _, p := range res.Scopes {
			printApplyScope(out, p)
		}
		return
	}
	for _, p := range res.Scopes {
		printApplyScope(out, p)
	}
	fmt.Fprintln(out)
}

func printApplyScope(out io.Writer, p *applyScope) {
	head := p.Scope
	switch p.Status {
	case "needs-reader":
		head += "   (needs a reader; you cannot open it)"
	case "blocked":
		head += "   (blocked)"
	case "refused":
		head += "   (refused: key not from trunk)"
	case "failed":
		head += "   (failed; unchanged)"
	case "applied":
		head += "   (applied)"
	}
	fmt.Fprintf(out, "\n%s\n", head)
	var rows [][]string
	if p.Create {
		rows = append(rows, []string{"  create key", fmt.Sprintf("wrapped to %d device(s)", len(p.Grant))})
	}
	for _, g := range p.Grant {
		via := ""
		if len(g.Via) > 0 {
			via = "via " + strings.Join(g.Via, ", ")
		}
		rows = append(rows, []string{"  gains access", g.Device, g.Fingerprint, via})
	}
	for _, id := range p.Revoke {
		rows = append(rows, []string{"  loses access", id})
	}
	if p.Rotate != nil {
		to := "a new key"
		if p.Rotate.To != "" {
			to = p.Rotate.To
		}
		rows = append(rows, []string{"  rotates", fmt.Sprintf("%s -> %s, re-sealing %d value(s); reason %q", p.Rotate.From, to, p.Rotate.Values, p.Rotate.Reason)})
	}
	for _, n := range p.Promote {
		rows = append(rows, []string{"  promotes drop", n})
	}
	for _, u := range p.Unproven {
		what := "re-seals as trusted"
		if p.SkipUnproven {
			what = "leaves unproven"
		}
		note := fmt.Sprintf("under retired key %s, set %s; author unproven", u.Key, u.Set)
		if u.SetAfterRetired {
			note += "; SET AFTER ITS KEY WAS RETIRED"
		}
		if u.Drop {
			note = "drop " + note
		}
		rows = append(rows, []string{"  " + what, u.Name, note})
	}
	for _, n := range p.BadDrops {
		rows = append(rows, []string{"  leaves drop", n, "does not open; left as it is (ask its author to set it again)"})
	}
	for _, id := range p.SkippedPQ {
		rows = append(rows, []string{"  not wrapped", id, "X25519 key; " + p.Env + " requires post-quantum keys"})
	}
	for _, wn := range p.Warnings {
		rows = append(rows, []string{"  warning", wn})
	}
	if len(p.Readers) > 0 {
		rows = append(rows, []string{"  can finish it", strings.Join(p.Readers, ", ")})
	}
	if p.Problem != "" {
		rows = append(rows, []string{"  problem", p.Problem})
	}
	if p.Fix != "" {
		rows = append(rows, []string{"  fix", p.Fix})
	}
	Table(out, rows)
}

func printApplyOutcome(out io.Writer, res *applyResult, noCommit bool) {
	applied := 0
	var left []*applyScope
	for _, p := range res.Scopes {
		switch p.Status {
		case "applied":
			applied++
		case "needs-reader", "blocked", "refused", "failed":
			left = append(left, p)
		}
	}
	switch {
	case applied > 0 && res.Commit != "":
		fmt.Fprintf(out, "Applied %d scope(s). Committed %s: %s\n", applied, res.Commit, strings.Join(res.Files, ", "))
		fmt.Fprintln(out, "Next: push the commit and open a pull request; `carbon check` verifies it against trunk policy.")
	case applied > 0 && noCommit:
		fmt.Fprintf(out, "Applied %d scope(s). Not committed: %s\n", applied, strings.Join(res.Files, ", "))
	case applied > 0:
		fmt.Fprintf(out, "Applied %d scope(s); no file changed.\n", applied)
	}
	for _, p := range left {
		switch p.Status {
		case "needs-reader":
			fmt.Fprintf(out, "Left for a reader of %s: %s\n", p.Scope, strings.Join(p.Readers, ", "))
		case "failed":
			fmt.Fprintf(out, "Failed in %s (unchanged): %s\n", p.Scope, p.Problem)
		case "refused":
			fmt.Fprintf(out, "Refused %s: %s\n", p.Scope, p.Problem)
		default:
			fmt.Fprintf(out, "Blocked in %s: %s\n", p.Scope, p.Problem)
		}
	}
}
