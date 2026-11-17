package audit

import (
	"fmt"

	"github.com/taylor1791/phosphorus/internal/scope"
)

// storedFindings compares each scope's declarations with its secrets file.
// Every workspace environment counts: a package's [secrets] declares a
// value for each environment, because `carbon run` resolves the same [env]
// table in all of them.
func (s *State) storedFindings() []Finding {
	var out []Finding
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
				f.Hint = fmt.Sprintf("Review it like a drop. If nobody on the team wrote it, delete the line from %s and set the value again; otherwise `carbon apply` asks before re-sealing it.", sf.SecretFile)
			default:
				f.Severity, f.Rule = Warning, RuleSecretStaleKey
				f.Message = fmt.Sprintf("The %s of %s in %s is under retired key %s: readers still open it, but its author is unproven (a removed reader may hold that key).", kind, st.Name, sf.Name(), st.KeyID)
				f.Hint = "A reader of " + sf.Name() + " runs `carbon apply`, which lists it and asks before re-sealing it under the current key."
			}
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
