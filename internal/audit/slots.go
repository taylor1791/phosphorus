package audit

import (
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/store"
)

// slotFindings applies docs/implementation.md "check rules for slots and
// keys": the working tree's keys files against trunk policy and trunk's
// keys files, plus drops.
//
// Where the contract leaves room, the choices are:
//
//   - With no reviewed trunk to compare with (bootstrap, trunk =
//     "worktree"), the working tree is the baseline: a slot policy does not
//     name is a pending revocation, never an unbacked grant, and key changes
//     are not compared.
//   - A slot is "on trunk" when trunk's keys file has the same line: the
//     same current key id, device and age file. A slot re-wrapped on a
//     branch is a new grant.
//   - A branch whose current key trunk has since retired is behind trunk
//     (key.behind-trunk); its unnamed slots are pending revocations that
//     merging trunk resolves.
//   - A pending revocation on trunk backs a rotation (a new current key id).
//     It does not back an inbox replaced under the same key id: carbon never
//     writes that, so it is always key.changed.
//   - Drops are forbidden when either trunk's policy or the working tree's
//     turns them off for the scope.
func (s *State) slotFindings() []Finding {
	var out []Finding
	tp := s.Trunk
	reviewed := s.TrunkIsReviewed()
	for _, sf := range s.Scopes {
		base := Finding{Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env}
		var sa *policy.ScopeAccess
		if tp != nil {
			sa, _ = tp.Scope(sf.Package.Name, sf.Env)
		}
		wsa, _ := s.Worktree.Scope(sf.Package.Name, sf.Env)

		// Drops.
		if !sf.BadSecrets {
			dropsOff := (sa != nil && !sa.Drops) || (wsa != nil && !wsa.Drops)
			for _, name := range sf.Secrets.Names() {
				e := sf.Secrets.Entries[name]
				if !e.IsDrop() {
					continue
				}
				f := base
				f.Secret, f.File = name, sf.SecretFile
				set := e.Set
				f.Set = &set
				if dropsOff {
					f.Severity, f.Rule = Error, RuleDropForbidden
					f.Message = fmt.Sprintf("%s in %s is a drop, and drops are off in %s (drops = false): a value written by someone who may not read the scope.", name, sf.Name(), sf.Name())
					f.Hint = fmt.Sprintf("Remove the line from %s, and ask a reader to set it: carbon set %s --package %s --env %s", sf.SecretFile, name, sf.Package.Name, sf.Env)
				} else {
					f.Severity, f.Rule = Info, RuleDropPending
					f.Message = fmt.Sprintf("%s in %s is a DROP, set %s: written to the inbox, possibly by someone who cannot read %s. Review it like code before merging.",
						name, sf.Name(), set.Format("2006-01-02T15:04:05Z"), sf.Name())
					f.Hint = "A reader of " + sf.Name() + " promotes it with `carbon apply` once it is accepted."
				}
				out = append(out, f)
			}
		}

		if sa == nil {
			continue
		}

		// require_pq: every named device must have a hybrid key.
		eligible, skipped := sa.Eligible()
		for _, d := range skipped {
			f := base
			f.Severity, f.Rule, f.Device = Error, RuleDeviceNotPQ, d.ID
			f.Message = fmt.Sprintf("%s requires post-quantum keys (require_pq), but policy names %s, whose key is %s.", sf.Name(), d.ID, d.Kind)
			f.Hint = fmt.Sprintf("%s joins again with a hybrid key (carbon join, without --x25519), or the device is removed: carbon remove %s", d.ID, d.ID)
			out = append(out, f)
		}

		if sf.BadKeys {
			continue
		}
		tk := sf.TrunkKeys
		if sf.Keys == nil {
			if reviewed && tk != nil {
				f := base
				f.Severity, f.Rule, f.File = Error, RuleKeyChanged, sf.KeysFile
				f.Message = fmt.Sprintf("%s has a keys file on trunk (current key %s) but not in the working tree: it was deleted.", sf.Name(), tk.Current)
				f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
			continue
		}
		cur := sf.Keys.CurrentKey()
		var trunkCur *store.Key
		if tk != nil {
			trunkCur = tk.CurrentKey()
		}
		behind := false
		if reviewed && tk != nil {
			if k, ok := tk.Keys[sf.Keys.Current]; ok && k.IsRetired() {
				behind = true
			}
		}

		for _, dev := range sortedKeys(cur.Slots) {
			blob := cur.Slots[dev]
			f := base
			f.Device, f.File = dev, sf.KeysFile
			types, err := agewrap.StanzaTypes(blob)
			switch {
			case err != nil:
				f.Severity, f.Rule = Error, RuleSlotMalformed
				f.Message = fmt.Sprintf("The slot for %s in %s is not a readable age file: %v.", dev, sf.Name(), err)
				f.Hint = "Restore the line from trunk, or delete it and let a reader run `carbon apply`."
				out = append(out, f)
			case len(types) != 1:
				f.Severity, f.Rule = Error, RuleSlotMalformed
				f.Message = fmt.Sprintf("The slot for %s in %s has %d recipient stanzas (%s); a slot must be wrapped to exactly one device.",
					dev, sf.Name(), len(types), strings.Join(types, ", "))
				f.Hint = "Delete the line and let a reader run `carbon apply` to wrap it again."
				out = append(out, f)
			case sa.RequirePQ && types[0] != agewrap.StanzaHybrid:
				f.Severity, f.Rule = Error, RuleSlotNotPQ
				f.Message = fmt.Sprintf("%s requires post-quantum keys, but the slot for %s is wrapped with %s, not %s.", sf.Name(), dev, types[0], agewrap.StanzaHybrid)
				f.Hint = "Give the device a hybrid key, then a reader runs `carbon apply`."
				out = append(out, f)
			}
			if sa.Names(dev) {
				continue
			}
			onTrunk := !reviewed || behind ||
				(tk != nil && tk.Current == sf.Keys.Current && trunkCur.Slots[dev] == blob)
			g := base
			g.Device, g.File = dev, sf.KeysFile
			if onTrunk {
				g.Severity, g.Rule = Warning, RuleSlotPendingRevocation
				g.Message = fmt.Sprintf("%s still has a slot in %s, but %s no longer names it: a pending revocation.", dev, sf.Name(), policyName(tp))
				g.Hint = "A reader of " + sf.Name() + " runs `carbon apply` to rotate the key; then rotate what " + dev + " could read (see carbon status --all)."
			} else {
				g.Severity, g.Rule = Error, RuleSlotUnbacked
				g.Message = fmt.Sprintf("%s has a slot for %s that %s does not name and trunk does not have: a grant that merged policy does not back.", sf.Name(), dev, policyName(tp))
				g.Hint = fmt.Sprintf("Remove the slot line from %s; to grant access, merge the policy change first (carbon request %s --env %s), then run `carbon apply`.", sf.KeysFile, sf.Package.Name, sf.Env)
			}
			out = append(out, g)
		}
		for _, d := range eligible {
			if _, ok := cur.Slots[d.ID]; ok {
				continue
			}
			f := base
			f.Severity, f.Rule, f.Device, f.File = Info, RuleSlotPendingGrant, d.ID, sf.KeysFile
			f.Message = fmt.Sprintf("%s names %s for %s, which has no slot yet: a pending grant.", policyName(tp), d.ID, sf.Name())
			f.Hint = "A reader of " + sf.Name() + " runs `carbon apply`."
			out = append(out, f)
		}

		if !reviewed || tk == nil {
			continue
		}
		f := base
		f.Severity, f.File = Error, sf.KeysFile
		switch {
		case sf.Keys.Current == tk.Current:
			if cur.Inbox != trunkCur.Inbox {
				f.Rule = RuleKeyChanged
				f.Message = fmt.Sprintf("The inbox key of %s (key %s) differs from trunk's. Drops would go to a key someone swapped on this branch.", sf.Name(), tk.Current)
				f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
		case behind:
			f.Severity, f.Rule = Info, RuleKeyBehindTrunk
			f.Message = fmt.Sprintf("%s uses key %s here, which trunk has retired (trunk's current key is %s).", sf.Name(), sf.Keys.Current, tk.Current)
			f.Hint = "Merge trunk: git merge " + tp.Ref
			out = append(out, f)
		case !hasPendingRevocation(trunkCur, sa):
			f.Rule = RuleKeyChanged
			f.Message = fmt.Sprintf("The scope key of %s changed (%s on trunk, %s here), but trunk's key had no pending revocation to justify a rotation.", sf.Name(), tk.Current, sf.Keys.Current)
			f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s. A rotation follows a removal merged to trunk (carbon remove, then carbon apply).", tp.Ref, sf.KeysFile)
			out = append(out, f)
		}
	}
	return out
}

// hasPendingRevocation reports whether key has a slot for a device policy
// does not name.
func hasPendingRevocation(key *store.Key, sa *policy.ScopeAccess) bool {
	for dev := range key.Slots {
		if !sa.Names(dev) {
			return true
		}
	}
	return false
}

func policyName(p *policy.Policy) string {
	switch p.Origin {
	case policy.OriginTrunk:
		return "trunk policy (" + p.Ref + ")"
	case policy.OriginBootstrap:
		return "policy (working tree; carbon is not on trunk yet)"
	}
	return "policy (working tree, trunk = \"worktree\")"
}
