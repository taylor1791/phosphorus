package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/audit"
	"github.com/taylor1791/phosphorus/internal/pins"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func init() {
	Register(&Command{
		Name:    "status",
		Group:   GroupDaily,
		Usage:   "[--all] [--unlock]",
		Summary: "What you can read, grant, and should rotate",
		Help: `status says who you are (from your identity's public key), the current
environment, the scopes you can read, the scopes carbon would refuse to
open here (keys that do not follow from trunk's, or that replaced the key
you pinned), the scopes you are waiting on, the grants, revocations and
re-keys you could apply, drops waiting to be promoted, values under retired
keys (unproven), new scope keys not on trunk, and rotation debt. It reads
metadata only, except that for a scope whose key changed since you last
verified it, it unwraps the key (as get would) to check it against your
pin. A passphrase-protected identity is not decrypted unless --unlock is
given.

Drops and debt cover the scopes you can read; --all covers every scope. With
no identity on this device, status still works and shows less.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("all", false, "show drops and rotation debt in every scope")
			fs.Bool("unlock", false, "ask for the passphrase of a passphrase-protected identity")
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
	Kind   string   `json:"kind"` // "grant", "revoke", or "rekey" (the device's key changed)
	Device string   `json:"device"`
	Scopes []string `json:"scopes"`
}

type statusRefused struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
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
	// Refused are scopes you hold a slot in that carbon will not open
	// here: the keys differ from trunk's, or from the key you pinned.
	Refused []statusRefused `json:"refused"`
	// Unproven are values under a retired key: whoever wrote them held
	// that key, which a removed reader may still hold.
	Unproven []statusDrop `json:"unproven"`
	// PinsErr is set when this clone's pins file cannot be read.
	PinsErr string `json:"pins_error,omitempty"`
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
		Grants: []statusGrant{}, Drops: []statusDrop{}, Debt: []audit.Debt{}, NewKeys: []string{},
		Refused: []statusRefused{}, Unproven: []statusDrop{}}
	if st.TrunkErr != nil {
		res.Trunk = "unresolved: " + st.TrunkErr.Error()
	} else {
		res.Trunk = describeTrunk(st).Describe
	}

	// Who you are. A missing identity is not an error here; one that
	// cannot be loaded is reported and status carries on without it.
	// A passphrase-protected identity is only decrypted with --unlock, and
	// a wrong passphrase means "no usable identity", not an abort.
	var ids []agewrap.Identity
	if c.identityLocked() && !c.Bool("unlock") {
		res.IdentityErr = "it is passphrase-protected; `carbon status --unlock` asks for the passphrase"
	} else if ids, err = c.Identities(false); err != nil {
		res.IdentityErr = AsError(err).Message
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
	grants, revokes, rekeys := map[string][]string{}, map[string][]string{}, map[string][]string{}
	var grantOrder, revokeOrder, rekeyOrder []string
	// Key changes check rejects: readers refuse such a scope, or it is a
	// forgery that only the key would expose.
	suspect := map[string]string{}
	if st.TrunkIsReviewed() {
		for _, f := range st.Check(audit.Options{Now: c.Now()}).Findings {
			switch f.Rule {
			case audit.RuleKeyChanged, audit.RuleKeyRetiredChanged, audit.RuleKeyUnverified:
				if _, ok := suspect[f.Scope]; !ok {
					suspect[f.Scope] = f.Rule
				}
			}
		}
	}
	var verifyPin func(*audit.ScopeFiles, *scope.KeyPin) error
	if len(ids) > 0 {
		verifyPin = func(sf *audit.ScopeFiles, pin *scope.KeyPin) error {
			s, err := scope.Load(w.Dir(sf.Package), sf.Package.Name, sf.Env)
			if err != nil {
				return err
			}
			o, err := s.Open(ids, mine...)
			if err != nil {
				return err
			}
			defer o.Close()
			_, err = o.CheckPin(pin, sf.TrunkKeys)
			return err
		}
	}
	var pinFile *pins.File
	reader := ""
	if len(ids) > 0 {
		reader = pins.ReaderID(ids)
		if pf, err := c.LoadPins(w); err == nil {
			pinFile = pf
		} else {
			res.PinsErr = AsError(err).Message
		}
	}
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
			if why := statusRefusal(sf, st.TrunkIsReviewed(), pinFile, reader, suspect, verifyPin); why != "" {
				res.Refused = append(res.Refused, statusRefused{Scope: sf.Name(), Reason: why})
			} else {
				readable[sf.Name()] = true
				res.Readable = append(res.Readable, sf.Name())
			}
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
		if readable[sf.Name()] && tsa != nil {
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
				if d, named := tsa.Device(id); named && sf.Keys.CurrentKey().SlotTo[id] != d.RecipientHash() {
					if _, seen := rekeys[id]; !seen {
						rekeyOrder = append(rekeyOrder, id)
					}
					rekeys[id] = append(rekeys[id], sf.Name())
					continue
				}
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
	for _, id := range rekeyOrder {
		res.Grants = append(res.Grants, statusGrant{Kind: "rekey", Device: id, Scopes: rekeys[id]})
	}
	for _, sf := range st.Scopes {
		if !all && !readable[sf.Name()] {
			continue
		}
		for _, name := range sf.Secrets.Names() {
			e := sf.Secrets.Entries[name]
			if e.IsDrop() {
				res.Drops = append(res.Drops, statusDrop{Scope: sf.Name(), Secret: name,
					Set: e.Set.Format("2006-01-02T15:04:05Z"), Reader: readable[sf.Name()]})
			} else if sf.Keys != nil && (&scope.Scope{Keys: sf.Keys, Secrets: sf.Secrets}).IsUnproven(name, e) {
				res.Unproven = append(res.Unproven, statusDrop{Scope: sf.Name(), Secret: name,
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

// identityLocked reports whether the caller's identity (CARBON_IDENTITY or
// the identity file) is passphrase-encrypted, without decrypting it.
func (c *Context) identityLocked() bool {
	data := []byte(c.Getenv("CARBON_IDENTITY"))
	if len(data) == 0 {
		b, err := os.ReadFile(c.IdentityPath())
		if err != nil {
			return false
		}
		data = b
	}
	return agewrap.IsEncryptedIdentityFile(data)
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
		var refused [][]string
		for _, r := range res.Refused {
			refused = append(refused, []string{r.Scope, r.Reason})
		}
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
		section("Refused", refused)
		var grants [][]string
		for _, g := range res.Grants {
			line := fmt.Sprintf("pending: %s -> %s", g.Device, plural(len(g.Scopes), "scope"))
			switch g.Kind {
			case "revoke":
				line = fmt.Sprintf("revoke: %s -> rotate %s", g.Device, plural(len(g.Scopes), "scope"))
			case "rekey":
				line = fmt.Sprintf("rekey: %s's key changed -> rotate %s", g.Device, plural(len(g.Scopes), "scope"))
			}
			grants = append(grants, []string{line, "carbon apply"})
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
	var unproven [][]string
	for _, u := range res.Unproven {
		unproven = append(unproven, []string{u.Scope, u.Secret, "under a retired key, author unproven; carbon apply --reseal-unproven vouches for it"})
	}
	section("Unproven", unproven)
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
	if res.PinsErr != "" {
		footer = append(footer, "Your pins could not be read ("+res.PinsErr+"); refusals by pin are not shown.")
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

// statusRefusal says why carbon would refuse to open a scope you hold a
// slot in, judged without a key: the working tree's keys file does not
// descend from trunk's (the readers' trunk check), or its key is not the
// one you pinned in this clone. Both checks are completed with the key by
// the commands that open the scope; status only predicts them.
func statusRefusal(sf *audit.ScopeFiles, reviewed bool, pf *pins.File, reader string, suspect map[string]string, verifyPin func(*audit.ScopeFiles, *scope.KeyPin) error) string {
	if rule, ok := suspect[sf.Name()]; ok {
		return "its key does not follow from trunk's (carbon check: " + rule + "); restore it: git checkout <trunk> -- " + sf.KeysFile
	}
	keys, trunk := sf.Keys, sf.TrunkKeys
	behind := false
	if reviewed && trunk != nil {
		cur, tcur := keys.CurrentKey(), trunk.CurrentKey()
		tr, retiredOnTrunk := trunk.Keys[keys.Current]
		behind = retiredOnTrunk && tr.IsRetired()
		switch {
		case keys.Current == trunk.Current:
			if cur.Inbox != tcur.Inbox || cur.InboxSealed != tcur.InboxSealed {
				return "its inbox differs from trunk's (git checkout <trunk> -- " + sf.KeysFile + ")"
			}
		case behind:
		default:
			if r, ok := keys.Keys[trunk.Current]; !ok || !r.IsRetired() {
				return "its key does not descend from trunk's (git checkout <trunk> -- " + sf.KeysFile + ")"
			}
		}
	}
	if pf == nil || reader == "" {
		return ""
	}
	pin, ok := pf.Get(reader, sf.Name())
	if !ok || pin.KeyID == keys.Current || behind {
		return ""
	}
	if verifyPin != nil {
		// The key changed since you pinned it: check the chain with the key,
		// as the commands that open the scope will.
		if err := verifyPin(sf, pin); err == nil || !errors.Is(err, scope.ErrKeyReplaced) {
			return ""
		}
	} else if r, ok := keys.Keys[pin.KeyID]; ok && r.IsRetired() {
		return ""
	}
	return fmt.Sprintf("key %s replaced the key %s you pinned (git log -p -- %s; carbon trust)", keys.Current, pin.KeyID, sf.KeysFile)
}
