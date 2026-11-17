package audit

import (
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
)

// coverageFindings checks that access is never implied by a reference: for
// every secret a consumer's [env] table takes from a provider package, each
// device that reads the consumer in an environment must also be named as a
// reader of the provider in that environment. Vars are plain text and need
// no access. Policy is the working tree's.
func (s *State) coverageFindings() []Finding {
	var out []Finding
	pol := s.Worktree
	for _, cname := range sortedKeys(pol.Packages) {
		consumer := pol.Packages[cname]
		secretsFrom := map[string]map[string]bool{} // provider -> secret names
		for _, r := range Refs(consumer) {
			prov, ok := pol.Packages[r.Provider]
			if !ok || r.Local() {
				continue
			}
			if _, isSecret := prov.Secrets[r.Name]; !isSecret {
				continue
			}
			if secretsFrom[r.Provider] == nil {
				secretsFrom[r.Provider] = map[string]bool{}
			}
			secretsFrom[r.Provider][r.Name] = true
		}
		for _, pname := range sortedKeys(secretsFrom) {
			names := sortedKeys(secretsFrom[pname])
			refs := make([]string, len(names))
			for i, n := range names {
				refs[i] = pname + "." + n
			}
			for _, env := range s.Workspace.Environments {
				csa, err := pol.Scope(cname, env)
				if err != nil {
					continue
				}
				psa, err := pol.Scope(pname, env)
				if err != nil {
					continue
				}
				for _, d := range csa.Devices {
					if psa.Names(d.ID) {
						continue
					}
					entry := d.Person
					if d.Machine {
						entry = d.ID
					}
					file := psa.ReadersFrom
					if file == "" {
						file = pol.Packages[pname].File
					}
					out = append(out, Finding{Severity: Error, Rule: RuleAccessCoverage,
						Scope: config.ScopeName(cname, env), Package: cname, Env: env, Device: d.ID, File: file,
						Message: fmt.Sprintf("%s reads %s, which references %s, but is not a reader of %s: `carbon run` would fail there. Access is never implied by a reference.",
							d.ID, config.ScopeName(cname, env), strings.Join(refs, ", "), config.ScopeName(pname, env)),
						Hint: fmt.Sprintf("Name %q (or a team it is in) under [access] %s in %s, or drop the reference.", entry, env, pol.Packages[pname].File)})
				}
			}
		}
	}
	return out
}
