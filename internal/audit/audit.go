// Package audit is carbon's keyless analysis of a whole repository: the
// reference graph, declared versus stored secrets, slots and keys compared
// with trunk, reader coverage of referenced scopes, rotation debt, and policy
// hygiene. `carbon check` prints its findings and `carbon status` reuses the
// pieces it needs.
//
// Nothing here loads an identity, opens a slot, or decrypts a value. Age
// files are inspected by their headers only, and every input is plaintext
// metadata that anyone with a copy of the repository can read.
//
// Rule ids are stable: scripts and CI configuration may depend on them. The
// list, with severities, is in [Rules].
package audit

import (
	"sort"
	"time"
)

// Severity is how bad a finding is.
type Severity string

const (
	// Error fails `carbon check`.
	Error Severity = "error"
	// Warning is reported; it fails `carbon check --strict`.
	Warning Severity = "warning"
	// Info is reported and never fails, except pending grants under
	// --strict.
	Info Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case Error:
		return 0
	case Warning:
		return 1
	}
	return 2
}

// Rule ids. Each names one rule; the severity is the default (see [Rules]).
const (
	// Loading.
	RuleConfigInvalid     = "config.invalid"
	RuleConfigLegacy      = "config.legacy"
	RuleDuplicatePackage  = "config.duplicate-package"
	RuleNameInvalid       = "name.invalid"
	RuleNameReserved      = "name.reserved"
	RuleStoreInvalid      = "store.invalid"
	RuleTrunkUnreadable   = "trunk.unreadable"
	RuleTrunkBootstrap    = "trunk.bootstrap"
	RuleTrunkWorktree     = "trunk.worktree"
	RuleGraphMissingPkg   = "graph.missing-package"
	RuleGraphMissingName  = "graph.missing-name"
	RuleGraphPrivate      = "graph.private"
	RuleGraphSecretAndVar = "graph.secret-and-var"
	RuleGraphVarUnset     = "graph.var-unset"
	RuleGraphCycle        = "graph.cycle"

	// Declared versus stored.
	RuleSecretUnset      = "secret.unset"
	RuleSecretUndeclared = "secret.undeclared"
	RuleSecretUnknownKey = "secret.unknown-key"
	RuleSecretStaleKey   = "secret.stale-key"
	RuleSecretStaleAfter = "secret.stale-after-retirement"
	RuleSecretUnused     = "secret.unused"

	// Slots and keys, compared with trunk.
	RuleSlotUnbacked          = "slot.unbacked"
	RuleSlotPendingRevocation = "slot.pending-revocation"
	RuleSlotPendingGrant      = "slot.pending-grant"
	RuleSlotMalformed         = "slot.malformed"
	RuleSlotNotPQ             = "slot.not-pq"
	RuleDeviceNotPQ           = "device.not-pq"
	RuleKeyChanged            = "key.changed"
	RuleKeyBehindTrunk        = "key.behind-trunk"
	RuleKeyNew                = "key.new"
	RuleDropForbidden         = "drop.forbidden"
	RuleDropPending           = "drop.pending"

	// Reader coverage.
	RuleAccessCoverage = "access.coverage"

	// Rotation debt.
	RuleDebtRemoval     = "debt.removal"
	RuleDebtRotateAfter = "debt.rotate-after"

	// Policy hygiene.
	RulePolicyUnknownReader = "policy.unknown-reader"
	RulePolicyUnknownMember = "policy.unknown-member"
	RulePolicyNoDevices     = "policy.no-devices"
)

// RuleInfo describes a rule for documentation and `carbon check --json`.
type RuleInfo struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
}

// Rules lists every rule with its default severity.
var Rules = []RuleInfo{
	{RuleConfigInvalid, Error, "a carbon.toml, person, machine or teams file does not parse"},
	{RuleConfigLegacy, Error, "a carbon.toml is a carbon 0.0.3 file"},
	{RuleDuplicatePackage, Error, "two carbon.toml files use the same package name"},
	{RuleNameInvalid, Error, "a package, secret, var, person, machine, team or [env] name is invalid"},
	{RuleNameReserved, Error, "a package uses a reserved name (carbon, env)"},
	{RuleStoreInvalid, Error, "a keys or secrets file does not parse or names the wrong scope"},
	{RuleTrunkUnreadable, Error, "policy or keys on the trunk ref cannot be read"},
	{RuleTrunkBootstrap, Info, "carbon is not on trunk yet; policy comes from the working tree"},
	{RuleTrunkWorktree, Warning, "the trunk is \"worktree\" (CARBON_TRUNK or git config): policy is never read from a reviewed ref"},
	{RuleGraphMissingPkg, Error, "an [env] reference names a package that does not exist"},
	{RuleGraphMissingName, Error, "an [env] reference names a secret or var that is not declared"},
	{RuleGraphPrivate, Error, "an [env] reference reads another package's private secret"},
	{RuleGraphSecretAndVar, Error, "a name is both a secret and a var in one package"},
	{RuleGraphVarUnset, Error, "a referenced var has no value (and no default) for an environment"},
	{RuleGraphCycle, Error, "packages reference each other in a cycle"},
	{RuleSecretUnset, Error, "a declared secret has no value in an environment (every workspace environment counts)"},
	{RuleSecretUndeclared, Error, "a stored value has no declaration"},
	{RuleSecretUnknownKey, Error, "a stored value names a key id the scope's keys file does not have"},
	{RuleSecretStaleKey, Warning, "a stored value is under a retired key: its author is unproven; `carbon apply` asks before re-sealing it"},
	{RuleSecretStaleAfter, Warning, "a value under a retired key claims a set time after that key was retired: suspect, review it like a drop"},
	{RuleSecretUnused, Info, "a secret no [env] table references (only with --unused)"},
	{RuleSlotUnbacked, Error, "a slot for a device trunk policy does not name, not on trunk: a grant merged policy does not back"},
	{RuleSlotPendingRevocation, Warning, "a slot for a device trunk policy no longer names; `carbon apply` rotates the key"},
	{RuleSlotPendingGrant, Info, "a device trunk policy names has no slot yet; `carbon apply` wraps it"},
	{RuleSlotMalformed, Error, "a slot is not an age file with exactly one recipient stanza"},
	{RuleSlotNotPQ, Error, "under require_pq, a slot's stanza is not the hybrid post-quantum type"},
	{RuleDeviceNotPQ, Error, "under require_pq, a device policy names has a key that is not hybrid"},
	{RuleKeyChanged, Error, "a scope key or inbox key differs from trunk's with no pending revocation to justify it"},
	{RuleKeyBehindTrunk, Info, "this branch still uses a key that trunk has retired; merge trunk"},
	{RuleKeyNew, Info, "a scope has a key in the working tree and none on trunk: confirm its author is a reader (never an error, even under --strict)"},
	{RuleDropForbidden, Error, "a drop in an environment where drops are off"},
	{RuleDropPending, Info, "a drop awaiting review and promotion by a reader"},
	{RuleAccessCoverage, Error, "a device reads a consumer scope but not a provider scope the consumer references"},
	{RuleDebtRemoval, Warning, "a value set before someone who could read it was removed (an error past --max-debt)"},
	{RuleDebtRotateAfter, Warning, "a value older than its rotate_after (an error past --max-debt)"},
	{RulePolicyUnknownReader, Error, "an access entry names no team, person or machine"},
	{RulePolicyUnknownMember, Warning, "a team lists a person with no person file"},
	{RulePolicyNoDevices, Warning, "a person file lists no devices"},
}

// Finding is one result. Fields that do not apply are empty.
type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	// Scope is "<package>/<env>" when the finding is about one scope.
	Scope   string `json:"scope,omitempty"`
	Package string `json:"package,omitempty"`
	Env     string `json:"env,omitempty"`
	Secret  string `json:"secret,omitempty"`
	Device  string `json:"device,omitempty"`
	// File is a slash path relative to the workspace root ("main:path"
	// for a file read from trunk).
	File string `json:"file,omitempty"`
	// Message says what is wrong and why.
	Message string `json:"message"`
	// Hint says what to do next, usually a command.
	Hint string `json:"hint,omitempty"`
	// Strict is set when --strict raised the severity to error.
	Strict bool `json:"strict,omitempty"`
	// Debt is set for rotation-debt findings.
	Debt *Debt `json:"debt,omitempty"`
	// Set is the stored entry's set time, for drop findings.
	Set *time.Time `json:"set,omitempty"`
}

// Report is the outcome of [State.Check].
type Report struct {
	Findings []Finding `json:"findings"`
}

// Count returns how many findings have severity s.
func (r *Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Failed reports whether any finding is an error.
func (r *Report) Failed() bool { return r.Count(Error) > 0 }

// ByRule returns the findings with the given rule id.
func (r *Report) ByRule(rule string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// Options control [State.Check].
type Options struct {
	// Now is the time debt is measured against.
	Now time.Time
	// MaxDebt turns rotation debt older than it into an error. Zero means
	// debt is always a warning.
	MaxDebt time.Duration
	// Strict raises warnings and pending grants to errors.
	Strict bool
	// Unused adds a finding for every secret no [env] table references.
	Unused bool
}

// Check runs every rule over the loaded state.
func (s *State) Check(opts Options) *Report {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	var fs []Finding
	fs = append(fs, s.loadFindings...)
	fs = append(fs, s.graphFindings(opts.Unused)...)
	fs = append(fs, s.storedFindings()...)
	fs = append(fs, s.slotFindings()...)
	fs = append(fs, s.coverageFindings()...)
	fs = append(fs, s.debtFindings(opts.Now, opts.MaxDebt)...)
	fs = append(fs, s.hygieneFindings()...)
	if opts.Strict {
		for i := range fs {
			f := &fs[i]
			if f.Severity == Warning || f.Rule == RuleSlotPendingGrant {
				f.Severity, f.Strict = Error, true
			}
		}
	}
	sortFindings(fs)
	return &Report{Findings: fs}
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Secret != b.Secret {
			return a.Secret < b.Secret
		}
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		return a.Message < b.Message
	})
}
