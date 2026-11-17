package audit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/gitx"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/store"
)

// slotFindings applies docs/implementation.md "check rules for slots and
// keys": the working tree's keys files against trunk policy and trunk's
// keys files, plus drops.
//
// A keyless check cannot tell a rotation or a new key made by a reader from
// one forged by someone else: it cannot open anything. So it enforces every
// structural rule a legitimate `carbon apply` commit satisfies, and it puts
// every key change (new key, rotation, new slot, removed scope) in the review
// banner so none passes silently. The choices where the contract leaves room:
//
//   - With no reviewed trunk to compare with (bootstrap, "worktree"-trunk),
//     the working tree is the baseline: a slot policy does not name is a
//     pending revocation, never an unbacked grant, and key changes are not
//     compared.
//   - A slot is "on trunk" when trunk's keys file has the same line: the
//     same current key id, device and age file.
//   - A working tree whose current key trunk has retired is a rollback when
//     trunk's tip is an ancestor of HEAD; otherwise the branch is behind, and
//     its keys file must be unchanged since the merge base.
//   - A change of current key is a rotation, accepted only in the shape
//     `apply` writes after a merged removal (see rotationProblems).
//   - Retired records are append-only: every one trunk has must be present
//     and identical.
//   - Drops are forbidden when either trunk's policy or the working tree's
//     turns them off for the scope.
func (s *State) slotFindings() []Finding {
	var out []Finding
	tp := s.Trunk
	reviewed := s.TrunkIsReviewed()
	for _, sf := range s.Scopes {
		base := Finding{Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env}
		var sa *policy.ScopeAccess
		noEntry := false
		if tp != nil {
			var err error
			if sa, err = tp.Scope(sf.Package.Name, sf.Env); err != nil {
				// The environment is not in trunk's workspace: trunk names
				// nobody for this scope.
				sa = &policy.ScopeAccess{Package: sf.Package.Name, Env: sf.Env, Drops: true, Why: map[string][]string{}}
				noEntry = true
			}
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
				f.Severity, f.Rule, f.File = Error, RuleKeyRemoved, sf.KeysFile
				f.Message = fmt.Sprintf("%s has a keys file on trunk (current key %s) but not in the working tree: it was deleted while the scope still exists.", sf.Name(), tk.Current)
				f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
			continue
		}
		cur := sf.Keys.CurrentKey()
		if reviewed && tk == nil {
			f := base
			f.Severity, f.Rule, f.File = Info, RuleKeyNew, sf.KeysFile
			f.Message = fmt.Sprintf("NEW SCOPE KEY: %s has a key here (%s) and none on trunk. Only a reader may create one, but carbon cannot prove who did: confirm the author is a reader of %s.",
				sf.Name(), sf.Keys.Current, sf.Name())
			f.Hint = fmt.Sprintf("Check who committed %s against `carbon who %s --env %s` before merging.", sf.KeysFile, sf.Package.Name, sf.Env)
			out = append(out, f)
		}
		if sa.RequirePQ && agewrap.RecipientKind(cur.Inbox) != agewrap.KindHybrid {
			f := base
			f.Severity, f.Rule, f.File = Error, RuleInboxNotPQ, sf.KeysFile
			f.Message = fmt.Sprintf("%s requires post-quantum keys, but its inbox key (key %s) is not hybrid: drops to it are not post-quantum.", sf.Name(), sf.Keys.Current)
			f.Hint = "Restore the keys file from trunk; carbon always makes hybrid inbox keys."
			out = append(out, f)
		}
		var trunkCur *store.Key
		if tk != nil {
			trunkCur = tk.CurrentKey()
		}

		// The working tree's current key is one trunk has retired: a
		// rollback, or a branch that is behind trunk.
		behind, rolledBack := false, false
		if reviewed && tk != nil {
			if k, ok := tk.Keys[sf.Keys.Current]; ok && k.IsRetired() {
				f := base
				f.Severity, f.File = Error, sf.KeysFile
				state, detail := s.behindState(sf.KeysFile)
				rolledBack = state != behindOK // a retired key named as current, not accepted
				switch state {
				case behindRollback:
					f.Rule = RuleKeyChanged
					f.Message = fmt.Sprintf("The scope key of %s was rolled back to %s, which trunk retired (trunk's current key is %s). This branch already contains trunk, so it is not behind.", sf.Name(), sf.Keys.Current, tk.Current)
					f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s", tp.Ref, sf.KeysFile)
					out = append(out, f)
				case behindChanged:
					f.Rule = RuleKeyChanged
					f.Message = fmt.Sprintf("%s uses key %s, which trunk has retired, and its keys file changed since this branch's merge base with trunk. A branch that is behind trunk may not change a key trunk has retired.", sf.Name(), sf.Keys.Current)
					f.Hint = fmt.Sprintf("Merge trunk (git merge %s) and keep trunk's %s.", tp.Ref, sf.KeysFile)
					out = append(out, f)
				case behindUnknown:
					f.Rule = RuleKeyUnverified
					f.Message = fmt.Sprintf("%s uses key %s, which trunk has retired, and check cannot tell whether this branch changed it: %s.", sf.Name(), sf.Keys.Current, detail)
					f.Hint = fmt.Sprintf("Fetch more history (git fetch --unshallow, or a deeper fetch of %s), or merge trunk: git merge %s", tp.Ref, tp.Ref)
					out = append(out, f)
				default:
					behind = true
					f.Severity, f.Rule = Info, RuleKeyBehindTrunk
					f.Message = fmt.Sprintf("%s uses key %s here, which trunk has retired (trunk's current key is %s); its keys file is unchanged since the merge base.", sf.Name(), sf.Keys.Current, tk.Current)
					f.Hint = "Merge trunk: git merge " + tp.Ref
					out = append(out, f)
				}
			}
		}

		rotated := reviewed && tk != nil && !behind && !rolledBack && sf.Keys.Current != tk.Current
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
			onTrunk := tk != nil && tk.Current == sf.Keys.Current && trunkCur.Slots[dev] == blob &&
				trunkCur.SlotTo[dev] == cur.SlotTo[dev]
			// `to` is not authenticated: check it against the device's key
			// in trunk policy.
			if d, known := policyDevice(tp, dev); known && reviewed && !behind && cur.SlotTo[dev] != d.RecipientHash() {
				g := base
				g.Device, g.File = dev, sf.KeysFile
				if onTrunk {
					if sa.Names(dev) {
						g.Severity, g.Rule = Warning, RuleSlotRekeyed
						g.Message = fmt.Sprintf("The slot for %s in %s is wrapped to a key %s no longer has: the device's public key changed, so whoever holds the old key can still open %s. A pending revocation.", dev, sf.Name(), dev, sf.Name())
						g.Hint = "A reader of " + sf.Name() + " runs `carbon apply`, which rotates the key."
						out = append(out, g)
					}
				} else {
					g.Severity, g.Rule = Error, RuleSlotRecipient
					g.Message = fmt.Sprintf("The new slot for %s in %s says it is wrapped to %s, but %s's key in trunk policy hashes to %s: the label does not match the device.", dev, sf.Name(), cur.SlotTo[dev], dev, d.RecipientHash())
					g.Hint = "Delete the slot line; a reader runs `carbon apply` to wrap the key to the device's real key."
					out = append(out, g)
				}
			}
			if sa.Names(dev) {
				if reviewed && tk != nil && !onTrunk && !rotated && !behind {
					g := base
					g.Severity, g.Rule, g.Device, g.File = Info, RuleSlotGranted, dev, sf.KeysFile
					g.Message = fmt.Sprintf("NEW SLOT: %s gets a slot in %s that trunk does not have. Only a reader can wrap the key, but carbon cannot prove who did: confirm the author is a current reader of %s.", dev, sf.Name(), sf.Name())
					g.Hint = "This is what `carbon apply` writes for a pending grant; check who committed it."
					out = append(out, g)
				}
				continue
			}
			g := base
			g.Device, g.File = dev, sf.KeysFile
			if !reviewed || behind || onTrunk {
				g.Severity, g.Rule = Warning, RuleSlotPendingRevocation
				g.Message = fmt.Sprintf("%s still has a slot in %s, but %s no longer names it: a pending revocation.", dev, sf.Name(), policyName(tp))
				g.Hint = "A reader of " + sf.Name() + " runs `carbon apply` to rotate the key; then rotate what " + dev + " could read (see carbon status --all)."
			} else {
				g.Severity, g.Rule = Error, RuleSlotUnbacked
				if noEntry {
					g.Message = fmt.Sprintf("%s has a slot for %s, but trunk policy has no access entry for %s at all (its environment is not on trunk): a scope's keys cannot be created before its policy merges.", sf.Name(), dev, sf.Name())
					g.Hint = fmt.Sprintf("Merge the policy change (the environment and its [access] entry) first, then a reader creates the key; remove %s from this change.", sf.KeysFile)
				} else {
					g.Message = fmt.Sprintf("%s has a slot for %s that %s does not name and trunk does not have: a grant that merged policy does not back.", sf.Name(), dev, policyName(tp))
					g.Hint = fmt.Sprintf("Remove the slot line from %s; to grant access, merge the policy change first (carbon request %s --env %s), then run `carbon apply`.", sf.KeysFile, sf.Package.Name, sf.Env)
				}
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

		if !reviewed || tk == nil || behind || rolledBack {
			continue
		}
		// Retired records are append-only.
		for _, id := range tk.IDs() {
			tr := tk.Keys[id]
			if !tr.IsRetired() {
				continue
			}
			if wr, ok := sf.Keys.Keys[id]; !ok || !sameRecord(tr, wr) {
				what := "changed"
				if !ok {
					what = "deleted"
				}
				f := base
				f.Severity, f.Rule, f.File = Error, RuleKeyRetiredChanged, sf.KeysFile
				f.Message = fmt.Sprintf("Retired key %s of %s was %s here. Retired records are append-only: they keep old branches decrypting and date the removals that rotation debt is counted from.", id, sf.Name(), what)
				f.Hint = fmt.Sprintf("Restore it from trunk: git checkout %s -- %s", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
		}
		f := base
		f.Severity, f.File = Error, sf.KeysFile
		switch {
		case sf.Keys.Current == tk.Current:
			// Slots are append-only until a rotation.
			for _, dev := range sortedKeys(trunkCur.Slots) {
				blob, ok := cur.Slots[dev]
				if ok && blob == trunkCur.Slots[dev] && cur.SlotTo[dev] == trunkCur.SlotTo[dev] {
					continue
				}
				what := "changed"
				if !ok {
					what = "removed"
				}
				g := base
				g.Severity, g.Rule, g.Device, g.File = Error, RuleSlotRemoved, dev, sf.KeysFile
				g.Message = fmt.Sprintf("Trunk's slot for %s in %s (key %s) was %s here. Slots are append-only until a rotation: removing or relabelling one hides a device that can still open the key, so `carbon apply` would not rotate it away.", dev, sf.Name(), tk.Current, what)
				g.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s. To revoke a device, remove it from policy and let a reader run `carbon apply`.", tp.Ref, sf.KeysFile)
				out = append(out, g)
			}
			if cur.Inbox != trunkCur.Inbox || cur.InboxSealed != trunkCur.InboxSealed {
				f.Rule = RuleKeyChanged
				f.Message = fmt.Sprintf("The inbox key of %s (key %s) differs from trunk's. Drops would go to a key someone swapped on this branch.", sf.Name(), tk.Current)
				f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
		default:
			reason := ""
			if wr, ok := sf.Keys.Keys[tk.Current]; ok {
				reason = wr.Reason
			}
			r := base
			r.Severity, r.Rule, r.File = Info, RuleKeyRotated, sf.KeysFile
			r.Message = fmt.Sprintf("SCOPE KEY ROTATED: %s changes from key %s (trunk) to %s here, reason %q. Only a reader can rotate, but carbon cannot prove who did: confirm the author is a current reader of %s.",
				sf.Name(), tk.Current, sf.Keys.Current, reason, sf.Name())
			r.Hint = "This is what `carbon apply` writes after a removal merges; check who committed it."
			r.Banner = fmt.Sprintf("SCOPE KEY ROTATED %s -> %s (%q): confirm the author is a current reader of %s", tk.Current, sf.Keys.Current, reason, sf.Name())
			out = append(out, r)
			if probs := rotationProblems(sf, tk, sa, eligible); len(probs) > 0 {
				f.Rule = RuleKeyChanged
				f.Message = fmt.Sprintf("The scope key of %s changed (%s on trunk, %s here) in a way `carbon apply` never writes: %s.", sf.Name(), tk.Current, sf.Keys.Current, strings.Join(probs, "; "))
				f.Hint = fmt.Sprintf("Restore it: git checkout %s -- %s. A rotation follows a removal merged to trunk (carbon remove, then carbon apply by a current reader).", tp.Ref, sf.KeysFile)
				out = append(out, f)
			}
		}
	}
	out = append(out, s.removedFindings()...)
	return out
}

// rotationProblems lists how a change of current key differs from what
// `apply` writes for a merged removal. Empty means acceptable.
func rotationProblems(sf *ScopeFiles, tk *store.Keys, sa *policy.ScopeAccess, eligible []policy.Device) []string {
	var probs []string
	trunkCur := tk.CurrentKey()
	wt := sf.Keys
	cur := wt.CurrentKey()
	if !hasPendingRevocation(trunkCur, sa) {
		probs = append(probs, "trunk's key had no pending revocation to justify a rotation")
	}
	old, ok := wt.Keys[tk.Current]
	switch {
	case !ok || !old.IsRetired():
		probs = append(probs, fmt.Sprintf("trunk's key %s is not kept as a retired record", tk.Current))
	case old.Successor == "" || old.Reason == "" || old.Sealed == "":
		probs = append(probs, fmt.Sprintf("retired key %s lacks successor, reason or sealed", tk.Current))
	default:
		if !reaches(wt, tk.Current, wt.Current) {
			probs = append(probs, fmt.Sprintf("retired key %s does not lead to the current key %s", tk.Current, wt.Current))
		}
		if !old.Created.Equal(trunkCur.Created) || old.InboxSealed != trunkCur.InboxSealed {
			probs = append(probs, fmt.Sprintf("retired key %s does not keep trunk's created time and inbox_sealed", tk.Current))
		}
	}
	allowed := map[string]bool{}
	var mislabelled []string
	for _, d := range eligible {
		allowed[d.ID] = true
		if _, ok := cur.Slots[d.ID]; ok && cur.SlotTo[d.ID] != d.RecipientHash() {
			mislabelled = append(mislabelled, d.ID)
		}
	}
	if len(mislabelled) > 0 {
		probs = append(probs, "the new key's slots do not record the trunk policy key of: "+strings.Join(mislabelled, ", "))
	}
	var extra []string
	for _, dev := range sortedKeys(cur.Slots) {
		if !allowed[dev] {
			extra = append(extra, dev)
		}
	}
	if len(extra) > 0 {
		probs = append(probs, "the new key has slots trunk policy does not grant: "+strings.Join(extra, ", "))
	}
	if cur.Inbox == "" || cur.InboxSealed == "" {
		probs = append(probs, "the new key has no inbox")
	}
	if sf.TrunkSecrets != nil && !sf.BadSecrets {
		var gone, redated []string
		for _, name := range sf.TrunkSecrets.Names() {
			we, ok := sf.Secrets.Entries[name]
			switch {
			case !ok:
				gone = append(gone, name)
			case !we.Set.Equal(sf.TrunkSecrets.Entries[name].Set):
				redated = append(redated, name)
			}
		}
		if len(gone) > 0 {
			probs = append(probs, "values on trunk vanished: "+strings.Join(gone, ", "))
		}
		if len(redated) > 0 {
			probs = append(probs, "values changed their set time (a rotation re-seals, it does not re-date): "+strings.Join(redated, ", "))
		}
	}
	return probs
}

// policyDevice finds a device (person device or machine) by id in policy.
func policyDevice(p *policy.Policy, id string) (policy.Device, bool) {
	if p == nil {
		return policy.Device{}, false
	}
	for _, d := range p.AllDevices() {
		if d.ID == id {
			return d, true
		}
	}
	return policy.Device{}, false
}

// reaches reports whether following successors from id arrives at want.
func reaches(ks *store.Keys, id, want string) bool {
	for i := 0; i <= len(ks.Keys); i++ {
		if id == want {
			return true
		}
		k, ok := ks.Keys[id]
		if !ok || !k.IsRetired() {
			return false
		}
		id = k.Successor
	}
	return false
}

// sameRecord reports whether two key records are identical.
func sameRecord(a, b *store.Key) bool {
	if !a.Created.Equal(b.Created) || !a.Retired.Equal(b.Retired) || a.Reason != b.Reason ||
		a.Successor != b.Successor || a.Sealed != b.Sealed || a.InboxSealed != b.InboxSealed ||
		a.Inbox != b.Inbox || len(a.Slots) != len(b.Slots) {
		return false
	}
	for dev, blob := range a.Slots {
		if b.Slots[dev] != blob || a.SlotTo[dev] != b.SlotTo[dev] {
			return false
		}
	}
	return true
}

type behind int

const (
	behindOK behind = iota
	behindRollback
	behindChanged
	behindUnknown
)

// behindState classifies a working tree whose current key trunk retired.
func (s *State) behindState(keysFile string) (behind, string) {
	ref := s.Trunk.Ref
	anc, err := s.Repo.IsAncestor(ref, "HEAD")
	if err != nil {
		return behindUnknown, err.Error()
	}
	if anc {
		return behindRollback, ""
	}
	mb, err := s.Repo.MergeBase("HEAD", ref)
	if errors.Is(err, gitx.ErrNoMergeBase) {
		return behindUnknown, "this clone has no merge base of HEAD and " + ref + " (shallow clone or unrelated history)"
	}
	if err != nil {
		return behindUnknown, err.Error()
	}
	same, err := s.Repo.UnchangedSince(mb, keysFile)
	if err != nil {
		return behindUnknown, err.Error()
	}
	if !same {
		return behindChanged, ""
	}
	return behindOK, ""
}

// removedFindings reports scopes trunk has keys for that the working tree no
// longer has, and files that belong to no scope.
func (s *State) removedFindings() []Finding {
	var out []Finding
	still := map[string]bool{}
	for _, r := range s.Removed {
		f := Finding{Scope: r.Name(), Package: r.Package, Env: r.Env, File: r.TrunkFile}
		if r.StillHere {
			still[r.TrunkFile] = true
			f.Severity, f.Rule = Error, RuleKeyRemoved
			f.Message = fmt.Sprintf("%s is no longer a scope here (its package or environment was removed), but its keys file %s is still here. Keys for a scope trunk does not have cannot be checked, so they cannot stay.", r.Name(), r.TrunkFile)
			f.Hint = fmt.Sprintf("To remove the scope, delete its files in this same change: git rm %s and its secrets file. Otherwise keep the environment or package.", r.TrunkFile)
		} else {
			f.Severity, f.Rule = Info, RuleScopeRemoved
			f.Message = fmt.Sprintf("SCOPE REMOVED: %s and its keys file %s are removed in this change. Confirm that is intended: re-creating it later makes a new key, which must again be created by a reader.", r.Name(), r.TrunkFile)
			f.Hint = "Nothing to do if intended."
		}
		out = append(out, f)
	}
	for _, o := range s.Orphans {
		if still[o] {
			continue
		}
		out = append(out, Finding{Severity: Error, Rule: RuleStoreOrphan, File: o,
			Message: fmt.Sprintf("%s belongs to no scope: no package in that directory, or an environment the workspace does not have. carbon never checks it, so it cannot stay.", o),
			Hint:    "Delete it, or add the package or environment it belongs to (and let a reader create its key after the policy merges)."})
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
	return "policy (working tree; the trunk is \"worktree\")"
}
