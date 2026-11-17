package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/store"
)

// Debt kinds.
const (
	DebtRemoval     = "removal"
	DebtRotateAfter = "rotate_after"
)

// Debt is one secret that owes a rotation.
type Debt struct {
	Scope   string    `json:"scope"`
	Package string    `json:"package"`
	Env     string    `json:"env"`
	Secret  string    `json:"secret"`
	Set     time.Time `json:"set"`
	Kind    string    `json:"kind"`
	// Removed is who may hold the retired key (see [Exposed]: removed
	// readers, and "<device>'s old key" for a re-keyed device), and Key
	// the retired key id, for a removal.
	Removed string `json:"removed,omitempty"`
	Key     string `json:"key,omitempty"`
	// RotateAfter is the declaration's rotate_after, for that kind.
	RotateAfter string `json:"rotate_after,omitempty"`
	// Since is when the debt began: the removal, or when rotate_after
	// elapsed. Debt age is measured from it.
	Since time.Time `json:"since"`
	// AgeDays is the whole days from Since to the time of the check.
	AgeDays int `json:"age_days"`
	// Overdue is set when the age exceeds --max-debt.
	Overdue bool `json:"overdue,omitempty"`
}

// Describe is a one-line account, as `carbon status` prints it.
func (d Debt) Describe() string {
	set := d.Set.Format("2006-01-02")
	if d.Kind == DebtRemoval {
		return fmt.Sprintf("set %s, %s removed %s", set, d.Removed, d.Since.Format("2006-01-02"))
	}
	return fmt.Sprintf("set %s, rotate_after %s elapsed %s", set, d.RotateAfter, d.Since.Format("2006-01-02"))
}

// RemovalPrefix starts the reason of a key retired by a removal.
const RemovalPrefix = "removed "

// RekeyPrefix starts the part of a reason that names devices whose key
// changed (the old key may be in someone else's hands).
const RekeyPrefix = "rekeyed "

// Exposed reads a retired key's reason, as `carbon apply` writes it
// ("removed sam", "removed sam, lin", "rekeyed ada/laptop", "removed sam,
// rekeyed ada/laptop"), and returns who may still hold the key: removed
// readers by name, and re-keyed devices as "<device>'s old key". ok is
// false for any other reason (free text), which owes no rotation.
func Exposed(reason string) (who string, ok bool) {
	var out []string
	mode := ""
	for _, part := range strings.Split(reason, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, RemovalPrefix):
			mode, part = "removed", strings.TrimPrefix(part, RemovalPrefix)
		case strings.HasPrefix(part, RekeyPrefix):
			mode, part = "rekeyed", strings.TrimPrefix(part, RekeyPrefix)
		}
		part = strings.TrimSpace(part)
		if mode == "" || part == "" {
			return "", false
		}
		if mode == "rekeyed" {
			part += "'s old key"
		}
		out = append(out, part)
	}
	return strings.Join(out, ", "), len(out) > 0
}

// Debts returns the rotation debt of every scope, measured at now: a value
// set no later than the retirement of a key whose reason is a removal or a
// re-key (debt from the earliest such retirement at or after it was set;
// set times have whole seconds, so a value set in the same second as the
// rotation counts as exposed), and a value older than its
// rotate_after (debt from when that elapsed). Retired keys are read from the
// working tree and trunk together, so deleting a retired key on a branch does
// not hide debt.
func (s *State) Debts(now time.Time) []Debt {
	var out []Debt
	for _, sf := range s.Scopes {
		// Trunk last, so its record wins over an edited one here.
		records := map[string]*store.Key{}
		for _, ks := range []*store.Keys{sf.Keys, sf.TrunkKeys} {
			if ks == nil {
				continue
			}
			for id, k := range ks.Keys {
				if k.IsRetired() {
					records[id] = k
				}
			}
		}
		retired := map[string]*store.Key{}
		for id, k := range records {
			if _, ok := Exposed(k.Reason); ok {
				retired[id] = k
			}
		}
		ids := sortedKeys(retired)
		for _, name := range sf.Secrets.Names() {
			e := sf.Secrets.Entries[name]
			d := Debt{Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env, Secret: name, Set: e.Set}
			var first *store.Key
			firstID := ""
			for _, id := range ids {
				k := retired[id]
				if !e.Set.After(k.Retired) && (first == nil || k.Retired.Before(first.Retired)) {
					first, firstID = k, id
				}
			}
			if first != nil {
				r := d
				r.Kind, r.Key, r.Since = DebtRemoval, firstID, first.Retired
				r.Removed, _ = Exposed(first.Reason)
				out = append(out, r)
			}
			if decl, ok := sf.Package.Secrets[name]; ok && decl.RotateAfter != "" {
				if dur, err := config.ParseDuration(decl.RotateAfter); err == nil && e.Set.Add(dur).Before(now) {
					r := d
					r.Kind, r.RotateAfter, r.Since = DebtRotateAfter, decl.RotateAfter, e.Set.Add(dur)
					out = append(out, r)
				}
			}
		}
	}
	for i := range out {
		out[i].AgeDays = int(now.Sub(out[i].Since) / (24 * time.Hour))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Secret < out[j].Secret
	})
	return out
}

func (s *State) debtFindings(now time.Time, max time.Duration) []Finding {
	var out []Finding
	for _, d := range s.Debts(now) {
		d := d
		age := now.Sub(d.Since)
		f := Finding{Severity: Warning, Scope: d.Scope, Package: d.Package, Env: d.Env, Secret: d.Secret, Debt: &d}
		if max > 0 && age > max {
			f.Severity, d.Overdue = Error, true
		}
		days := d.AgeDays
		switch d.Kind {
		case DebtRemoval:
			f.Rule = RuleDebtRemoval
			f.Message = fmt.Sprintf("%s in %s owes a rotation: set %s, before %s was removed on %s (%d days ago). They may hold a copy.",
				d.Secret, d.Scope, d.Set.Format("2006-01-02"), d.Removed, d.Since.Format("2006-01-02"), days)
		default:
			f.Rule = RuleDebtRotateAfter
			f.Message = fmt.Sprintf("%s in %s owes a rotation: set %s, older than its rotate_after = %q since %s (%d days ago).",
				d.Secret, d.Scope, d.Set.Format("2006-01-02"), d.RotateAfter, d.Since.Format("2006-01-02"), days)
		}
		if d.Overdue {
			f.Message += fmt.Sprintf(" That is past --max-debt %s.", formatDuration(max))
		}
		f.Hint = fmt.Sprintf("Change the credential at its source, then: carbon set %s --package %s --env %s", d.Secret, d.Package, d.Env)
		out = append(out, f)
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return fmt.Sprintf("%dh", d/time.Hour)
}
