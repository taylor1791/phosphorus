package audit

import (
	"fmt"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
)

// hygieneFindings checks the working tree's policy files on their own:
// access entries that name nobody, team members and people without files or
// devices.
func (s *State) hygieneFindings() []Finding {
	var out []Finding
	pol := s.Worktree
	ws := s.Workspace

	checkAccess := func(file, pkg string, acc map[string]config.Access) {
		for _, env := range sortedKeys(acc) {
			for _, entry := range acc[env].Readers {
				kind, name, err := config.ParseReader(entry)
				known := err == nil
				if known {
					switch kind {
					case config.ReaderTeam:
						_, known = pol.Teams[name]
					case config.ReaderPerson:
						_, known = pol.People[name]
					case config.ReaderMachine:
						_, known = pol.Machines[name]
					}
				}
				if known {
					continue
				}
				f := Finding{Severity: Error, Rule: RulePolicyUnknownReader, Package: pkg, Env: env, File: file,
					Message: fmt.Sprintf("[access] %s in %s names %q, which is no %s in this repository: it grants nothing.", env, file, entry, readerKindWord(kind)),
					Hint:    fmt.Sprintf("Fix the entry in %s, or add the %s (carbon join).", file, readerKindWord(kind))}
				if pkg != "" {
					f.Scope = config.ScopeName(pkg, env)
				}
				out = append(out, f)
			}
		}
	}
	checkAccess(config.FileName, "", ws.Access)
	for _, name := range sortedKeys(pol.Packages) {
		p := pol.Packages[name]
		checkAccess(p.File, p.Name, p.Access)
	}

	for _, team := range sortedKeys(pol.Teams) {
		for _, m := range pol.Teams[team] {
			if _, ok := pol.People[m]; ok {
				continue
			}
			out = append(out, Finding{Severity: Warning, Rule: RulePolicyUnknownMember, File: config.TeamsFile,
				Message: fmt.Sprintf("Team @%s lists %s, who has no person file (%s): it grants them nothing.", team, m, config.PersonFile(m)),
				Hint:    fmt.Sprintf("%s runs `carbon join`, or remove them from %s.", m, config.TeamsFile)})
		}
	}
	for _, id := range sortedKeys(pol.People) {
		if len(pol.People[id].Devices) == 0 {
			out = append(out, Finding{Severity: Warning, Rule: RulePolicyNoDevices, File: config.PersonFile(id),
				Message: fmt.Sprintf("%s lists no devices, so %s can read nothing.", config.PersonFile(id), id),
				Hint:    id + " runs `carbon join` on their device, or the file is removed: carbon remove " + id})
		}
	}

	return out
}

func readerKindWord(k config.ReaderKind) string {
	switch k {
	case config.ReaderTeam:
		return "team"
	case config.ReaderMachine:
		return "machine"
	case config.ReaderPerson:
		return "person"
	}
	return "team, person or machine"
}

// keyChangeFindings compares the working tree's people and machines with
// trunk's. A changed public key for an existing device or machine, and a
// new device of an existing person, are the most dangerous policy edits:
// once merged, apply wraps keys to them. Both go in the review banner with
// the new key's fingerprint, which the reviewer confirms with its owner.
func (s *State) keyChangeFindings() []Finding {
	if !s.TrunkIsReviewed() {
		return nil
	}
	var out []Finding
	tp, wp := s.Trunk, s.Worktree
	add := func(rule, dev, file, rec, msg string) {
		out = append(out, Finding{Severity: Info, Rule: rule, Device: dev, File: file,
			Message: fmt.Sprintf(msg, dev, agewrap.Fingerprint(rec)),
			Hint:    "Confirm the fingerprint with " + dev + "'s owner over a channel you trust before merging."})
	}
	for _, id := range sortedKeys(wp.People) {
		before, ok := tp.People[id]
		if !ok {
			continue
		}
		for _, dev := range sortedKeys(wp.People[id].Devices) {
			rec := wp.People[id].Devices[dev]
			old, had := before.Devices[dev]
			switch {
			case !had:
				add(RulePolicyDeviceAdded, id+"/"+dev, config.PersonFile(id), rec,
					"NEW DEVICE %s for an existing person, fingerprint %s. Once merged, apply gives it every scope the person reads.")
			case old != rec:
				add(RulePolicyDeviceKeyChanged, id+"/"+dev, config.PersonFile(id), rec,
					"KEY CHANGED for %s: new fingerprint %s. Once merged, apply rotates its scopes and gives the new key access.")
			}
		}
	}
	for _, id := range sortedKeys(wp.Machines) {
		if before, ok := tp.Machines[id]; ok && before.Key != wp.Machines[id].Key {
			add(RulePolicyDeviceKeyChanged, "machine:"+id, config.MachineFile(id), wp.Machines[id].Key,
				"KEY CHANGED for %s: new fingerprint %s. Once merged, apply rotates its scopes and gives the new key access.")
		}
	}
	return out
}
