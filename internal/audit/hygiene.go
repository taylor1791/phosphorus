package audit

import (
	"fmt"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
)

// hygieneFindings checks the working tree's policy files on their own:
// access entries that name nobody, team members and people without files or
// devices, and the trunk setting.
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

	if ws.TrunkIsWorktree() || (s.Trunk != nil && s.Trunk.Origin == policy.OriginWorktreeTrunk) {
		out = append(out, Finding{Severity: Warning, Rule: RulePolicyTrunkWorktree, File: config.FileName,
			Message: `trunk = "worktree": policy is read from whatever is checked out, never from a reviewed ref, so any branch can grant itself access when a reader runs carbon apply.`,
			Hint:    `Protect a trunk branch and set trunk = "<ref>" in carbon.toml (for example "origin/main").`})
	}
	out = append(out, s.trunkChanged()...)
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

// trunkChanged compares the working tree's trunk setting with trunk's own.
// A branch must not repoint the trunk ref (docs/deviations.md, decision 3),
// so every ref that could be trunk is asked what it says:
//
//   - the ref the working tree names;
//   - the remote's default branch (refs/remotes/origin/HEAD), if any;
//   - every other value `trunk` had in carbon.toml in HEAD's history, if
//     that ref exists and its own carbon.toml still names itself: it is the
//     trunk this branch was cut from, and it has not moved.
//
// The last catches a branch that names itself, or a ref that does not
// exist (which would otherwise put carbon in bootstrap mode). A shallow
// clone has less history to compare with.
func (s *State) trunkChanged() []Finding {
	var out []Finding
	mine := s.Workspace.Trunk
	seen := map[string]bool{}
	report := func(ref, theirs string) {
		if theirs == mine || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, Finding{Severity: Error, Rule: RulePolicyTrunkChanged, File: config.FileName,
			Message: fmt.Sprintf("carbon.toml here says trunk = %q, but %s's own carbon.toml says trunk = %q. A branch must not repoint the trunk ref: policy and inbox keys are read from it.", mine, ref, theirs),
			Hint:    fmt.Sprintf("Restore trunk = %q in carbon.toml; change trunk only in a commit made on trunk itself.", theirs)})
	}
	if s.trunkWorkspace != nil {
		report(mine, s.trunkWorkspace.Trunk)
	}
	// An unreadable default branch is not this rule's business, so errors
	// here are ignored.
	if b, err := s.Repo.Git("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"); err == nil {
		ref := strings.TrimSpace(string(b))
		if safeRef(ref) && ref != mine {
			if ws, err := config.LoadWorkspace(s.Repo.Source(ref)); err == nil {
				report(ref, ws.Trunk)
			}
		}
	}
	for _, v := range s.historicalTrunks() {
		if v == mine || v == config.TrunkWorktree || seen[v] || !safeRef(v) {
			continue
		}
		if ok, err := s.Repo.RefExists(v); err != nil || !ok {
			continue
		}
		if ws, err := config.LoadWorkspace(s.Repo.Source(v)); err == nil && ws.Trunk == v {
			report(v, v)
		}
	}
	return out
}

// historicalTrunks returns the distinct values of trunk in the root
// carbon.toml across the last commits of HEAD that changed it.
func (s *State) historicalTrunks() []string {
	b, err := s.Repo.Git("log", "-n", "100", "--format=%H", "HEAD", "--", config.FileName)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range strings.Fields(string(b)) {
		data, err := s.Repo.Git("show", c+":"+config.FileName)
		if err != nil {
			continue
		}
		ws, _, err := config.ParseFile(config.FileName, data)
		if err != nil || ws == nil || seen[ws.Trunk] {
			continue
		}
		seen[ws.Trunk] = true
		out = append(out, ws.Trunk)
	}
	return out
}
