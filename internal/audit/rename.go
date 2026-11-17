package audit

import (
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/store"
)

// renamedFrom reports whether the working tree's package p is trunk's
// package in the same directory under another name, which is what
// `carbon rename` writes (it never moves the directory): p's name is not on
// trunk, a trunk package lives in p's directory, and trunk's keys file
// there (tk) names that package. It returns the old name, or "". Readers
// accept the same case (scope/rename_verify.go).
func (s *State) renamedFrom(p *config.Package, env string, tk *store.Keys) string {
	if _, known := s.Trunk.Packages[p.Name]; known {
		return ""
	}
	for name, tp := range s.Trunk.Packages {
		if tp.Dir == p.Dir && tk.Scope == config.ScopeName(name, env) {
			return name
		}
	}
	return ""
}

// renameFinding compares a renamed scope with trunk's under the old name.
// Every value, drop and slot is re-sealed under the new name, so the
// ciphertext differs; everything else must not: the same current key id,
// the same keys with the same created, retired, reason and successor, the
// same slot devices with the same `to`, and the same secret names with the
// same key, set time and kind. Anything else is key.changed; a match is one
// scope.renamed banner item.
func renameFinding(sf *ScopeFiles, old string, tk *store.Keys, ts *store.Secrets) Finding {
	f := Finding{Scope: sf.Name(), Package: sf.Package.Name, Env: sf.Env, File: sf.KeysFile}
	if probs := renameProblems(sf, tk, ts); len(probs) > 0 {
		f.Severity, f.Rule = Error, RuleKeyChanged
		f.Message = fmt.Sprintf("%s is renamed from %s, but its keys or secrets differ from trunk's beyond the rename: %s.",
			sf.Name(), config.ScopeName(old, sf.Env), strings.Join(probs, "; "))
		f.Hint = "Redo the rename from trunk's files: git checkout <trunk> -- " + sf.KeysFile + " " + sf.SecretFile + ", then carbon rename."
		return f
	}
	f.Severity, f.Rule = Info, RuleScopeRenamed
	f.Message = fmt.Sprintf("RENAMED: %s is trunk's %s under a new name; every value and slot was re-sealed. carbon cannot open them to compare: confirm the author is a reader of %s.",
		sf.Name(), config.ScopeName(old, sf.Env), config.ScopeName(old, sf.Env))
	f.Hint = "Check who committed " + sf.KeysFile + " against `carbon who " + old + " --env " + sf.Env + "` on trunk."
	return f
}

func renameProblems(sf *ScopeFiles, tk *store.Keys, ts *store.Secrets) []string {
	wk := sf.Keys
	if wk == nil || sf.BadKeys || sf.BadSecrets {
		return []string{"its files here do not parse"}
	}
	var probs []string
	if wk.Current != tk.Current {
		probs = append(probs, fmt.Sprintf("current key %s, %s on trunk", wk.Current, tk.Current))
	}
	if len(wk.Keys) != len(tk.Keys) {
		probs = append(probs, fmt.Sprintf("%d keys, %d on trunk", len(wk.Keys), len(tk.Keys)))
	}
	for id, t := range tk.Keys {
		k, ok := wk.Keys[id]
		switch {
		case !ok:
			probs = append(probs, "key "+id+" is missing")
			continue
		case !k.Created.Equal(t.Created), !k.Retired.Equal(t.Retired), k.Reason != t.Reason, k.Successor != t.Successor:
			probs = append(probs, "key "+id+"'s record changed")
		}
		if len(k.Slots) != len(t.Slots) {
			probs = append(probs, "key "+id+" has other slots")
			continue
		}
		for dev, to := range t.SlotTo {
			if k.SlotTo[dev] != to {
				probs = append(probs, "the slot for "+dev+" changed")
			}
		}
	}
	trunkEntries := map[string]store.Entry{}
	if ts != nil {
		trunkEntries = ts.Entries
	}
	if len(sf.Secrets.Entries) != len(trunkEntries) {
		probs = append(probs, fmt.Sprintf("%d secrets, %d on trunk", len(sf.Secrets.Entries), len(trunkEntries)))
	}
	for name, te := range trunkEntries {
		we, ok := sf.Secrets.Entries[name]
		if !ok || we.Key != te.Key || !we.Set.Equal(te.Set) || we.IsDrop() != te.IsDrop() {
			probs = append(probs, name+" changed")
		}
	}
	return probs
}
