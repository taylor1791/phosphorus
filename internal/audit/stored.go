package audit

import (
	"fmt"

	"github.com/taylor1791/phosphorus/internal/store"
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
			if sf.BadKeys {
				continue
			}
			kind := "value"
			if e.IsDrop() {
				kind = "drop"
			}
			var rec *store.Key
			if sf.Keys != nil {
				rec = sf.Keys.Keys[e.Key]
			}
			switch {
			case rec == nil:
				f := base
				f.Severity, f.Rule, f.Secret, f.File = Error, RuleSecretUnknownKey, name, sf.SecretFile
				if sf.Keys == nil {
					f.Message = fmt.Sprintf("The %s of %s names key %s, but %s has no keys file (%s).", kind, name, e.Key, sf.Name(), sf.KeysFile)
				} else {
					f.Message = fmt.Sprintf("The %s of %s names key %s, which %s does not have: nobody can open it.", kind, name, e.Key, sf.KeysFile)
				}
				f.Hint = fmt.Sprintf("Merge trunk if the key is there, or set the value again: carbon set %s --package %s --env %s", name, p.Name, sf.Env)
				out = append(out, f)
			case rec.IsRetired():
				f := base
				f.Severity, f.Rule, f.Secret, f.File = Warning, RuleSecretStaleKey, name, sf.SecretFile
				f.Message = fmt.Sprintf("The %s of %s is under retired key %s (%s still opens it through the retired chain).", kind, name, e.Key, sf.Name())
				f.Hint = "A reader of " + sf.Name() + " runs `carbon apply` to re-seal it under the current key."
				out = append(out, f)
			}
		}
	}
	return out
}
