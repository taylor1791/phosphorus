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
	RuleStoreOrphan       = "store.orphan"
	RuleTrunkUnreadable   = "trunk.unreadable"
	RuleTrunkBootstrap    = "trunk.bootstrap"
	RuleTrunkWorktree     = "trunk.worktree"
	RuleGraphMissingPkg   = "graph.missing-package"
	RuleGraphMissingName  = "graph.missing-name"
	RuleGraphPrivate      = "graph.private"
	RuleGraphSecretAndVar = "graph.secret-and-var"
	RuleGraphVarUnset     = "graph.var-unset"
	RuleGraphCycle        = "graph.cycle"

	// Declared versus stored, and entries against trunk's.
	RuleSecretUnset          = "secret.unset"
	RuleSecretUndeclared     = "secret.undeclared"
	RuleSecretUnknownKey     = "secret.unknown-key"
	RuleSecretStaleKey       = "secret.stale-key"
	RuleSecretStaleAfter     = "secret.stale-after-retirement"
	RuleSecretRolledBack     = "secret.rolled-back"
	RuleSecretOlderThanTrunk = "secret.older-than-trunk"
	RuleSecretUnused         = "secret.unused"

	// Slots and keys, compared with trunk.
	RuleSlotUnbacked          = "slot.unbacked"
	RuleSlotPendingRevocation = "slot.pending-revocation"
	RuleSlotPendingGrant      = "slot.pending-grant"
	RuleSlotGranted           = "slot.granted"
	RuleSlotRemoved           = "slot.removed"
	RuleSlotRecipient         = "slot.recipient"
	RuleSlotRekeyed           = "slot.rekeyed"
	RuleSlotMalformed         = "slot.malformed"
	RuleSlotNotPQ             = "slot.not-pq"
	RuleDeviceNotPQ           = "device.not-pq"
	RuleInboxNotPQ            = "inbox.not-pq"
	RuleKeyChanged            = "key.changed"
	RuleKeyRetiredChanged     = "key.retired-changed"
	RuleKeyUnverified         = "key.unverified"
	RuleKeyRemoved            = "key.removed"
	RuleKeyBehindTrunk        = "key.behind-trunk"
	RuleKeyNew                = "key.new"
	RuleKeyRotated            = "key.rotated"
	RuleScopeRemoved          = "scope.removed"
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
	// Banner rules are listed at the top of `carbon check`: changes whose
	// author carbon cannot prove is a reader, which review must accept.
	Banner bool `json:"banner,omitempty"`
}

// Rules lists every rule with its default severity.
var Rules = []RuleInfo{
	{RuleConfigInvalid, Error, "a carbon.toml, person, machine or teams file does not parse", false},
	{RuleConfigLegacy, Error, "a carbon.toml is a carbon 0.0.3 file", false},
	{RuleDuplicatePackage, Error, "two carbon.toml files use the same package name", false},
	{RuleNameInvalid, Error, "a package, secret, var, person, machine, team or [env] name is invalid", false},
	{RuleNameReserved, Error, "a package uses a reserved name (carbon, env)", false},
	{RuleStoreInvalid, Error, "a keys or secrets file does not parse or names the wrong scope", false},
	{RuleStoreOrphan, Error, "a keys or secrets file belongs to no scope of the working tree", false},
	{RuleTrunkUnreadable, Error, "policy or keys on the trunk ref cannot be read", false},
	{RuleTrunkBootstrap, Info, "carbon is not on trunk yet; policy comes from the working tree", false},
	{RuleTrunkWorktree, Warning, "the trunk is \"worktree\" (CARBON_TRUNK or git config): policy is never read from a reviewed ref", false},
	{RuleGraphMissingPkg, Error, "an [env] reference names a package that does not exist", false},
	{RuleGraphMissingName, Error, "an [env] reference names a secret or var that is not declared", false},
	{RuleGraphPrivate, Error, "an [env] reference reads another package's private secret", false},
	{RuleGraphSecretAndVar, Error, "a name is both a secret and a var in one package", false},
	{RuleGraphVarUnset, Error, "a referenced var has no value (and no default) for an environment", false},
	{RuleGraphCycle, Error, "packages reference each other in a cycle", false},
	{RuleSecretUnset, Error, "a declared secret has no value in an environment (every workspace environment counts)", false},
	{RuleSecretUndeclared, Error, "a stored value has no declaration", false},
	{RuleSecretUnknownKey, Error, "a stored value names a key id the scope's keys file does not have", false},
	{RuleSecretStaleKey, Warning, "a stored value is under a retired key: its author is unproven; `carbon apply` asks before re-sealing it", true},
	{RuleSecretStaleAfter, Warning, "a value under a retired key claims a set time after that key was retired: suspect", true},
	{RuleSecretRolledBack, Error, "a value is under an older key than trunk's value for the same name: replaced by someone holding a retired key", false},
	{RuleSecretOlderThanTrunk, Warning, "a value under the same key as trunk's has an earlier set time: an older line restored", true},
	{RuleSecretUnused, Info, "a secret no [env] table references (only with --unused)", false},
	{RuleSlotUnbacked, Error, "a slot for a device trunk policy does not name, not on trunk: a grant merged policy does not back", false},
	{RuleSlotPendingRevocation, Warning, "a slot for a device trunk policy no longer names; `carbon apply` rotates the key", false},
	{RuleSlotPendingGrant, Info, "a device trunk policy names has no slot yet; `carbon apply` wraps it", false},
	{RuleSlotGranted, Info, "a named device gets a slot trunk does not have: confirm a current reader wrapped it", true},
	{RuleSlotRemoved, Error, "a slot on trunk's current key is removed or changed (blob or to) while the key is unchanged: slots are append-only until a rotation", false},
	{RuleSlotRecipient, Error, "a slot new relative to trunk records a `to` that is not the hash of its device's trunk policy key", false},
	{RuleSlotRekeyed, Warning, "a slot on trunk is wrapped to a key its device no longer has: a pending revocation; `carbon apply` rotates", false},
	{RuleSlotMalformed, Error, "a slot is not an age file with exactly one recipient stanza", false},
	{RuleSlotNotPQ, Error, "under require_pq, a slot's stanza is not the hybrid post-quantum type", false},
	{RuleDeviceNotPQ, Error, "under require_pq, a device policy names has a key that is not hybrid", false},
	{RuleInboxNotPQ, Error, "under require_pq, the scope's inbox key is not hybrid", false},
	{RuleKeyChanged, Error, "the scope key or inbox differs from trunk's in a way `carbon apply` never writes (rollback, unjustified or malformed rotation)", false},
	{RuleKeyRetiredChanged, Error, "a retired key record trunk has is changed or deleted (retired records are append-only)", false},
	{RuleKeyUnverified, Error, "the branch uses a key trunk retired and check cannot see the merge base to prove the keys file is unchanged", false},
	{RuleKeyRemoved, Error, "a keys file trunk has is gone while its scope exists, or stays while its scope was removed", false},
	{RuleKeyBehindTrunk, Info, "this branch still uses a key that trunk has retired and has not changed it; merge trunk", false},
	{RuleKeyNew, Info, "a scope has a key in the working tree and none on trunk: confirm its author is a reader (never raised by --strict)", true},
	{RuleKeyRotated, Info, "the scope key changed from trunk's: confirm the author is a current reader (never raised by --strict)", true},
	{RuleScopeRemoved, Info, "a scope with keys on trunk is removed together with its files", true},
	{RuleDropForbidden, Error, "a drop in an environment where drops are off", true},
	{RuleDropPending, Info, "a drop awaiting review and promotion by a reader", true},
	{RuleAccessCoverage, Error, "a device reads a consumer scope but not a provider scope the consumer references", false},
	{RuleDebtRemoval, Warning, "a value set before someone who could read it was removed (an error past --max-debt)", false},
	{RuleDebtRotateAfter, Warning, "a value older than its rotate_after (an error past --max-debt)", false},
	{RulePolicyUnknownReader, Error, "an access entry names no team, person or machine", false},
	{RulePolicyUnknownMember, Warning, "a team lists a person with no person file", false},
	{RulePolicyNoDevices, Warning, "a person file lists no devices", false},
}

// Banner reports whether findings of rule are listed in check's review
// banner.
func Banner(rule string) bool {
	for _, r := range Rules {
		if r.ID == rule {
			return r.Banner
		}
	}
	return false
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
	// Banner is the one-line review item for banner rules (see
	// [RuleInfo.Banner]); empty otherwise.
	Banner string `json:"banner,omitempty"`
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
	for i := range fs {
		if fs[i].Banner == "" && Banner(fs[i].Rule) {
			fs[i].Banner = bannerText(fs[i])
		}
	}
	sortFindings(fs)
	return &Report{Findings: fs}
}

func bannerText(f Finding) string {
	switch f.Rule {
	case RuleDropPending:
		return "DROP: confirm the value is wanted"
	case RuleDropForbidden:
		return "DROP where drops are off (error)"
	case RuleSecretStaleKey:
		return "UNDER A RETIRED KEY: author unproven"
	case RuleSecretStaleAfter:
		return "SUSPECT: set after its key was retired"
	case RuleSecretOlderThanTrunk:
		return "OLDER VALUE than trunk's restored"
	case RuleKeyNew:
		return "NEW SCOPE KEY: confirm the author is a reader of " + f.Scope
	case RuleSlotGranted:
		return "NEW SLOT for " + f.Device + ": confirm the author is a current reader of " + f.Scope
	case RuleScopeRemoved:
		return "SCOPE REMOVED with its keys"
	}
	return f.Rule
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
