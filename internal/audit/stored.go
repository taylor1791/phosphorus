package audit

import (
	"fmt"
	"time"

	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/store"
)

// storedFindings compares each scope's declarations with its secrets file.
// Every workspace environment counts: a package's [secrets] declares a
// value for each environment, because `carbon run` resolves the same [env]
// table in all of them.
func (s *State) storedFindings() []Finding {
	var out []Finding
	trunkRef := "<trunk>"
	if s.Trunk != nil && s.Trunk.Ref != "" {
		trunkRef = s.Trunk.Ref
	}
	for _, sf := range s.Scopes {
		if sf.BadSecrets {
			continue
		}
		p := sf.Package
		base := Finding{Scope: sf.Name(), Package: p.Name, Env: sf.Env}
		for _, name := range sortedKeys(p.Secrets) {
			if _, ok := sf.Secrets.Entries[name]; ok {
				continue
			}
			f := base
			f.Severity, f.Rule, f.Secret, f.File = Error, RuleSecretUnset, name, p.File
			f.Message = fmt.Sprintf("%s is declared in %s but has no value in %s.", name, p.File, sf.Name())
			gen := ""
			if p.Secrets[name].Generate != "" {
				gen = " --generate"
			}
			f.Hint = fmt.Sprintf("carbon set %s%s --package %s --env %s", name, gen, p.Name, sf.Env)
			out = append(out, f)
		}
		for _, name := range sf.Secrets.Names() {
			e := sf.Secrets.Entries[name]
			if _, ok := p.Secrets[name]; !ok {
				f := base
				f.Severity, f.Rule, f.Secret, f.File = Error, RuleSecretUndeclared, name, sf.SecretFile
				what := "no declaration"
				if _, isVar := p.Vars[name]; isVar {
					what = "no declaration under [secrets] (it is a var)"
				}
				f.Message = fmt.Sprintf("%s stores a value for %s, which has %s in %s.", sf.SecretFile, name, what, p.File)
				f.Hint = fmt.Sprintf("Declare it under [secrets] in %s, or delete its line from %s.", p.File, sf.SecretFile)
				out = append(out, f)
			}
			if !sf.BadKeys && sf.Keys == nil {
				f := base
				f.Severity, f.Rule, f.Secret, f.File = Error, RuleSecretUnknownKey, name, sf.SecretFile
				f.Message = fmt.Sprintf("The %s of %s names key %s, but %s has no keys file (%s).", kindOf(e.IsDrop()), name, e.Key, sf.Name(), sf.KeysFile)
				f.Hint = fmt.Sprintf("Merge trunk if the key is there, or set the value again: carbon set %s --package %s --env %s", name, p.Name, sf.Env)
				out = append(out, f)
			}
		}
		if sf.BadKeys || sf.Keys == nil {
			continue
		}
		out = append(out, againstTrunk(sf, base, trunkRef)...)
		sc := &scope.Scope{Package: p.Name, Env: sf.Env, Keys: sf.Keys, Secrets: sf.Secrets}
		for _, st := range sc.StaleEntries() {
			f := base
			f.Secret, f.File = st.Name, sf.SecretFile
			set := st.Set
			f.Set = &set
			kind := kindOf(st.Drop)
			switch {
			case !st.KeyKnown:
				f.Severity, f.Rule = Error, RuleSecretUnknownKey
				f.Message = fmt.Sprintf("The %s of %s names key %s, which %s does not have: nobody can open it.", kind, st.Name, st.KeyID, sf.KeysFile)
				f.Hint = fmt.Sprintf("Merge trunk if the key is there, or set the value again: carbon set %s --package %s --env %s", st.Name, p.Name, sf.Env)
			case st.SetAfterRetired:
				f.Severity, f.Rule = Warning, RuleSecretStaleAfter
				f.Message = fmt.Sprintf("SUSPECT: the %s of %s in %s is under key %s, retired %s, but claims it was set %s, after the retirement. Only someone holding the old key could write it, which includes whoever was removed; its author is unproven.",
					kind, st.Name, sf.Name(), st.KeyID, st.Retired.Format("2006-01-02T15:04:05Z"), st.Set.Format("2006-01-02T15:04:05Z"))
				f.Hint = fmt.Sprintf("Review it like a drop. If nobody on the team wrote it, delete the line from %s and set the value again; otherwise a reader vouches for it with `carbon apply --reseal-unproven`.", sf.SecretFile)
			default:
				f.Severity, f.Rule = Warning, RuleSecretStaleKey
				f.Message = fmt.Sprintf("The %s of %s in %s is under retired key %s, which does not list it as carried (it was written after the rotation): readers still open it, but its author is unproven (a removed reader may hold that key).", kind, st.Name, sf.Name(), st.KeyID)
				f.Hint = "A reader of " + sf.Name() + " vouches for it with `carbon apply --reseal-unproven`, or sets it again; `carbon apply` alone lists it and leaves it."
			}
			out = append(out, f)
		}
	}
	return out
}

// againstTrunk compares each entry with trunk's entry for the same name: one
// under an older key than trunk's is a rollback by someone holding a
// retired key (error); one under the same key with an earlier set time is an
// older line restored (warning, listed in the banner).
func againstTrunk(sf *ScopeFiles, base Finding, ref string) []Finding {
	if sf.TrunkSecrets == nil || sf.TrunkKeys == nil {
		return nil
	}
	if k, ok := sf.TrunkKeys.Keys[sf.Keys.Current]; ok && k.IsRetired() {
		return nil // behind trunk (or a rollback, reported as key.changed)
	}
	var out []Finding
	tk := sf.TrunkKeys
	for _, name := range sf.Secrets.Names() {
		we := sf.Secrets.Entries[name]
		te, ok := sf.TrunkSecrets.Entries[name]
		if !ok {
			continue
		}
		f := base
		f.Secret, f.File = name, sf.SecretFile
		set := we.Set
		f.Set = &set
		if sameCiphertext(we, te) && !we.Set.Equal(te.Set) {
			f.Severity, f.Rule = Error, RuleSecretRedated
			f.Message = fmt.Sprintf("%s in %s has trunk's ciphertext but a different set time (%s here, %s on trunk): the line was re-dated, not set again. A re-dated value no longer opens, and its rotation debt is hidden.",
				name, sf.Name(), we.Set.Format("2006-01-02T15:04:05Z"), te.Set.Format("2006-01-02T15:04:05Z"))
			f.Hint = fmt.Sprintf("Restore trunk's line: git checkout %s -- %s", ref, sf.SecretFile)
			out = append(out, f)
			continue
		}
		if we.Key == te.Key {
			if k, ok := tk.Keys[we.Key]; ok && k.IsRetired() && we != te {
				// Trunk's line is under a key trunk has retired (a value a
				// rotation carried): a different line there could only be
				// written by someone holding the retired key.
				f.Severity, f.Rule = Error, RuleSecretRolledBack
				f.Message = fmt.Sprintf("%s in %s was replaced under retired key %s: only someone holding that key, which may be a removed reader, can write there.", name, sf.Name(), we.Key)
				f.Hint = "Restore trunk's line for " + name + " in " + sf.SecretFile + "; a reader sets a new value with `carbon set` if it must change."
				out = append(out, f)
				continue
			}
			if we.Set.Before(te.Set) {
				f.Severity, f.Rule = Warning, RuleSecretOlderThanTrunk
				f.Message = fmt.Sprintf("OLDER VALUE: %s in %s is set %s here but %s on trunk, under the same key %s: an older line was restored. Anyone who once had the file can do that.",
					name, sf.Name(), we.Set.Format("2006-01-02T15:04:05Z"), te.Set.Format("2006-01-02T15:04:05Z"), we.Key)
				f.Hint = fmt.Sprintf("Keep trunk's line unless the rollback is intended: git checkout %s -- %s", ref, sf.SecretFile)
				out = append(out, f)
			}
			continue
		}
		wtRetired := false
		if k, ok := sf.Keys.Keys[we.Key]; ok && k.IsRetired() {
			wtRetired = true
		}
		if reaches(sf.Keys, we.Key, te.Key) || reaches(tk, we.Key, te.Key) || (wtRetired && te.Key == tk.Current) {
			f.Severity, f.Rule = Error, RuleSecretRolledBack
			f.Message = fmt.Sprintf("%s in %s is under key %s here, older than key %s that trunk's value uses: it was replaced by someone holding a retired key, which may be a removed reader.", name, sf.Name(), we.Key, te.Key)
			f.Hint = "Restore trunk's line for " + name + " in " + sf.SecretFile + "; a reader sets a new value with `carbon set` if it must change."
			out = append(out, f)
		}
	}
	return out
}

func kindOf(drop bool) string {
	if drop {
		return "drop"
	}
	return "value"
}

// sameCiphertext reports whether two entries carry the same sealed value
// or drop.
func sameCiphertext(a, b store.Entry) bool {
	return a.Value == b.Value && a.Drop == b.Drop && (a.Value != "" || a.Drop != "")
}

// ClockSkew is how far in the future a set time may be before check calls
// it an error (secret.future).
const ClockSkew = 10 * time.Minute

// futureFindings reports entries whose set time is in the future: set
// times are chosen by their writer, and a future one hides rotation debt.
func (s *State) futureFindings(now time.Time) []Finding {
	var out []Finding
	for _, sf := range s.Scopes {
		if sf.BadSecrets {
			continue
		}
		for _, name := range sf.Secrets.Names() {
			e := sf.Secrets.Entries[name]
			if !e.Set.After(now.Add(ClockSkew)) {
				continue
			}
			set := e.Set
			out = append(out, Finding{Severity: Error, Rule: RuleSecretFuture, Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env,
				Secret: name, File: sf.SecretFile, Set: &set,
				Message: fmt.Sprintf("The %s of %s in %s claims it was set %s, in the future. Set times are chosen by their writer; a future one hides rotation debt.",
					kindOf(e.IsDrop()), name, sf.Name(), e.Set.Format("2006-01-02T15:04:05Z")),
				Hint: fmt.Sprintf("Restore the line from trunk, or set the value again: carbon set %s --package %s --env %s", name, sf.Package.Name, sf.Env)})
		}
	}
	return out
}
