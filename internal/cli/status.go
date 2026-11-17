package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/audit"
	"github.com/taylor1791/phosphorus/internal/policy"
)

func init() {
	Register(&Command{
		Name:    "status",
		Usage:   "[--all]",
		Summary: "What you can read, grant, and should rotate",
		Help: `status says who you are (from your identity's public key; nothing is
decrypted), the current environment, the scopes you can read, the scopes you
are waiting on, the grants and revocations you could apply, drops waiting to
be promoted, and rotation debt.

Drops and debt cover the scopes you can read; --all covers every scope. With
no identity on this device, status still works and shows less.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("all", false, "show drops and rotation debt in every scope")
		},
		Run: runStatus,
	})
}

type statusIdentity struct {
	// Known is false when the identity's key is in no person or machine
	// file.
	Known       bool     `json:"known"`
	Person      string   `json:"person,omitempty"`
	Machine     string   `json:"machine,omitempty"`
	Devices     []string `json:"devices"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type statusWait struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"` // "not-merged", "apply-pending", "not-pq"
	text   string
}

type statusGrant struct {
	Kind   string   `json:"kind"` // "grant" or "revoke"
	Device string   `json:"device"`
	Scopes []string `json:"scopes"`
}

type statusDrop struct {
	Scope  string `json:"scope"`
	Secret string `json:"secret"`
	Set    string `json:"set"`
	Reader bool   `json:"reader"`
}

type statusResult struct {
	Identity    *statusIdentity `json:"identity"`
	IdentityErr string          `json:"identity_error,omitempty"`
	Environment string          `json:"environment"`
	All         bool            `json:"all"`
	Readable    []string        `json:"readable"`
	Waiting     []statusWait    `json:"waiting"`
	Grants      []statusGrant   `json:"grants"`
	Drops       []statusDrop    `json:"drops"`
	// NewKeys are scopes with a key here and none on trunk: carbon cannot
	// prove a reader created them.
	NewKeys []string `json:"new_keys"`
	// Trunk is the trunk ref and where it came from, or why there is none.
	Trunk string       `json:"trunk"`
	Debt  []audit.Debt `json:"debt"`
}

func runStatus(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	env, err := c.Environment(w)
	if err != nil {
		return err
	}
	st, err := audit.Load(w.Repo, c.Getenv)
	if err != nil {
		return err
	}
	all := c.Bool("all")
	res := statusResult{Environment: env, All: all, Readable: []string{}, Waiting: []statusWait{},
		Grants: []statusGrant{}, Drops: []statusDrop{}, Debt: []audit.Debt{}, NewKeys: []string{}}
	if st.TrunkErr != nil {
		res.Trunk = "unresolved: " + st.TrunkErr.Error()
	} else {
		res.Trunk = describeTrunk(st).Describe
	}

	// Who you are. A missing identity is not an error here; one that
	// cannot be loaded is reported and status carries on without it.
	ids, err := c.Identities(false)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) || e.Code != ExitNoIdentity {
			return err
		}
		res.IdentityErr = e.Message
		ids = nil
	}
	var me []policy.Device
	if len(ids) > 0 {
		me = Me(st.Worktree, ids)
		si := &statusIdentity{Known: len(me) > 0, Devices: DeviceIDs(me)}
		if len(me) > 0 {
			if me[0].Machine {
				si.Machine = me[0].Device
			} else {
				si.Person = me[0].Person
			}
		}
		if ids[0].Recipient != "" {
			si.Fingerprint = agewrap.Fingerprint(ids[0].Recipient)
		}
		res.Identity = si
	}
	mine := DeviceIDs(me)

	readable := map[string]bool{}
	grants, revokes := map[string][]string{}, map[string][]string{}
	var grantOrder, revokeOrder []string
	for _, sf := range st.Scopes {
		if sf.Keys == nil {
			continue
		}
		slots := sf.Keys.CurrentKey().Slots
		has := false
		for _, id := range mine {
			if _, ok := slots[id]; ok {
				has = true
			}
		}
		if has {
			readable[sf.Name()] = true
			res.Readable = append(res.Readable, sf.Name())
		}
		wsa, _ := st.Worktree.Scope(sf.Package.Name, sf.Env)
		var tsa *policy.ScopeAccess
		if st.Trunk != nil {
			tsa, _ = st.Trunk.Scope(sf.Package.Name, sf.Env)
		}
		if !has && len(mine) > 0 && wsa != nil && wsa.Readable(mine...) {
			sw := statusWait{Scope: sf.Name()}
			switch {
			case tsa == nil || !tsa.Readable(mine...):
				sw.Reason, sw.text = "not-merged", "named on this branch, not merged to trunk yet"
			case tsa.RequirePQ && !anyHybrid(me):
				sw.Reason, sw.text = "not-pq", "requires post-quantum keys; yours is not hybrid (carbon join on a new device)"
			default:
				sw.Reason, sw.text = "apply-pending", "merged; waiting for a reader to run `carbon apply`"
			}
			res.Waiting = append(res.Waiting, sw)
		}
		if has && tsa != nil {
			eligible, _ := tsa.Eligible()
			for _, d := range eligible {
				if _, ok := slots[d.ID]; !ok {
					if _, seen := grants[d.ID]; !seen {
						grantOrder = append(grantOrder, d.ID)
					}
					grants[d.ID] = append(grants[d.ID], sf.Name())
				}
			}
			for _, id := range sortedNames(slots) {
				if !tsa.Names(id) {
					if _, seen := revokes[id]; !seen {
						revokeOrder = append(revokeOrder, id)
					}
					revokes[id] = append(revokes[id], sf.Name())
				}
			}
		}
	}
	for _, id := range grantOrder {
		res.Grants = append(res.Grants, statusGrant{Kind: "grant", Device: id, Scopes: grants[id]})
	}
	for _, id := range revokeOrder {
		res.Grants = append(res.Grants, statusGrant{Kind: "revoke", Device: id, Scopes: revokes[id]})
	}
	for _, sf := range st.Scopes {
		if !all && !readable[sf.Name()] {
			continue
		}
		for _, name := range sf.Secrets.Names() {
			if e := sf.Secrets.Entries[name]; e.IsDrop() {
				res.Drops = append(res.Drops, statusDrop{Scope: sf.Name(), Secret: name,
					Set: e.Set.Format("2006-01-02T15:04:05Z"), Reader: readable[sf.Name()]})
			}
		}
	}
	if st.TrunkIsReviewed() {
		for _, sf := range st.Scopes {
			if sf.Keys != nil && sf.TrunkKeys == nil && (all || readable[sf.Name()]) {
				res.NewKeys = append(res.NewKeys, sf.Name())
			}
		}
	}
	for _, d := range st.Debts(c.Now()) {
		if all || readable[d.Scope] {
			res.Debt = append(res.Debt, d)
		}
	}

	return c.Output(res, func(out io.Writer) { printStatus(out, res, w.Config.Environments) })
}

func anyHybrid(ds []policy.Device) bool {
	for _, d := range ds {
		if d.Hybrid() {
			return true
		}
	}
	return false
}

func printStatus(out io.Writer, res statusResult, envs []string) {
	var footer []string
	switch id := res.Identity; {
	case res.IdentityErr != "":
		fmt.Fprintf(out, "Your identity could not be loaded (%s). Environment: %s.\n", res.IdentityErr, res.Environment)
	case id == nil:
		fmt.Fprintf(out, "No carbon identity on this device. Environment: %s.\n", res.Environment)
		footer = append(footer, "To create one:   carbon join")
	case !id.Known:
		fmt.Fprintf(out, "Your identity (fingerprint %s) is not in .carbon/people or .carbon/machines. Environment: %s.\n", id.Fingerprint, res.Environment)
		footer = append(footer, "To add yourself:   carbon join")
	case id.Machine != "":
		fmt.Fprintf(out, "You are machine:%s. Environment: %s.\n", id.Machine, res.Environment)
	default:
		var devs []string
		for _, d := range id.Devices {
			_, dev, _ := strings.Cut(d, "/")
			devs = append(devs, dev)
		}
		fmt.Fprintf(out, "You are %s (%s). Environment: %s.\n", id.Person, strings.Join(devs, ", "), res.Environment)
	}
	fmt.Fprintln(out)

	var rows [][]string
	section := func(label string, lines [][]string) {
		for i, l := range lines {
			if i > 0 {
				label = ""
			}
			rows = append(rows, append([]string{label}, l...))
		}
	}
	if res.Identity != nil && res.Identity.Known {
		if len(res.Readable) == 0 {
			section("Readable", [][]string{{"none yet"}})
		} else {
			section("Readable", [][]string{{plural(len(res.Readable), "scope") + " in " + strings.Join(envsOf(res.Readable, envs), ", ")}})
		}
		var waits [][]string
		for _, wt := range res.Waiting {
			waits = append(waits, []string{wt.Scope, wt.text})
		}
		section("Waiting", waits)
		var grants [][]string
		for _, g := range res.Grants {
			verb := "pending"
			if g.Kind == "revoke" {
				verb = "revoke"
			}
			grants = append(grants, []string{fmt.Sprintf("%s: %s -> %s", verb, g.Device, plural(len(g.Scopes), "scope")), "carbon apply"})
		}
		section("You can grant", grants)
	}
	var drops [][]string
	for _, d := range res.Drops {
		next := "review, then a reader runs `carbon apply`"
		if d.Reader {
			next = "review, then carbon apply"
		}
		drops = append(drops, []string{d.Scope, d.Secret, "set " + d.Set + "; " + next})
	}
	section("Drops", drops)
	var keys [][]string
	for _, s := range res.NewKeys {
		keys = append(keys, []string{s, "new scope key, not on trunk", "confirm its author is a reader of " + s})
	}
	section("New keys", keys)
	var debt [][]string
	for _, d := range res.Debt {
		debt = append(debt, []string{d.Scope, d.Secret, d.Describe()})
	}
	section("Rotate", debt)
	if len(rows) == 0 {
		rows = append(rows, []string{"Nothing to do."})
	}
	Table(out, rows)
	if !res.All && (res.Identity == nil || !res.Identity.Known) {
		footer = append(footer, "Run `carbon status --all` for drops and rotation debt in every scope.")
	}
	if strings.HasPrefix(res.Trunk, "unresolved: ") {
		footer = append(footer, "Trunk is "+res.Trunk+"; grants and new scope keys are not shown. Fix: git fetch, or git config "+policy.TrunkConfigKey+" <ref>")
	}
	if len(footer) > 0 {
		fmt.Fprintln(out)
		for _, f := range footer {
			fmt.Fprintln(out, f)
		}
	}
}

// envsOf returns the environments of scope names, in workspace order.
func envsOf(scopes, envs []string) []string {
	has := map[string]bool{}
	for _, s := range scopes {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			has[s[i+1:]] = true
		}
	}
	var out []string
	for _, e := range envs {
		if has[e] {
			out = append(out, e)
		}
	}
	return out
}
