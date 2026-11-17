// Package policy turns access lists into devices: for a scope (a package in
// an environment) it says which person devices and machines read it, with
// which public keys, and through which rule.
//
// Policy is loaded from a [config.Source]. [LoadTrunk] implements the trunk
// rules from docs/implementation.md: read the trunk ref, fall back to the
// working tree when carbon is not on trunk yet (bootstrap), and read the
// working tree always when the trunk is "worktree" (CARBON_TRUNK or git
// config carbon.trunk; see ResolveTrunk).
package policy

import (
	"fmt"
	"os"
	"sort"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/gitx"
)

// Origin says where a policy was read from.
type Origin string

const (
	// OriginTrunk: read from the trunk ref.
	OriginTrunk Origin = "trunk"
	// OriginBootstrap: the trunk ref is missing or has no root carbon.toml,
	// so policy was read from the working tree.
	OriginBootstrap Origin = "bootstrap"
	// OriginWorktreeTrunk: the trunk is "worktree" (from CARBON_TRUNK or git
	// config only; never from the working tree file).
	OriginWorktreeTrunk Origin = "trunk-is-worktree"
	// OriginWorktree: read from the working tree on purpose (who, access,
	// status, run, ...).
	OriginWorktree Origin = "worktree"
)

// Policy is the people, machines, teams, workspace and packages at one
// source.
type Policy struct {
	Origin Origin
	// Ref is the trunk ref when Origin is OriginTrunk, or OriginBootstrap with
	// a ref that has no carbon.toml.
	Ref string
	// Notice is a line for stderr when trunk policy fell back to the working
	// tree (bootstrap); empty otherwise.
	Notice string
	// Trunk is how the trunk ref was chosen; nil for working-tree loads.
	Trunk *Trunk

	Workspace *config.Workspace
	Packages  map[string]*config.Package
	People    map[string]*config.Person
	Machines  map[string]*config.Machine
	Teams     config.Teams
}

// Load reads policy from src.
func Load(src config.Source) (*Policy, error) {
	ws, err := config.LoadWorkspace(src)
	if err != nil {
		return nil, err
	}
	p := &Policy{Origin: OriginWorktree, Workspace: ws}
	if p.Packages, err = config.LoadPackages(src, ws); err != nil {
		return nil, err
	}
	if p.People, err = config.LoadPeople(src); err != nil {
		return nil, err
	}
	if p.Machines, err = config.LoadMachines(src); err != nil {
		return nil, err
	}
	if p.Teams, err = config.LoadTeams(src); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadWorktree reads policy from the working tree at root.
func LoadWorktree(root string) (*Policy, error) {
	return Load(config.DirSource{Root: root})
}

// LoadTrunk reads policy the way commands that grant or encrypt must: from
// the trunk ref chosen by [ResolveTrunk] (CARBON_TRUNK, git config
// carbon.trunk, the remote default branch), with the bootstrap and
// "worktree" cases of [LoadTrunkAt]. worktree is unused and kept for
// compatibility: nothing in the working tree chooses the trunk.
func LoadTrunk(repo *gitx.Repo, worktree *config.Workspace) (*Policy, error) {
	return LoadTrunkWith(repo, os.Getenv)
}

// Device is one public key that can hold a slot.
type Device struct {
	// ID is the slot name: "<person>/<device>" or "machine:<name>".
	ID        string
	Person    string // empty for machines
	Device    string // device name, or the machine name
	Machine   bool
	Recipient string
	Kind      agewrap.Kind
}

// Hybrid reports whether the device's key is post-quantum hybrid.
func (d Device) Hybrid() bool { return d.Kind == agewrap.KindHybrid }

// RecipientHash is the `to` a slot for this device must carry
// (agewrap.RecipientHash of its recipient).
func (d Device) RecipientHash() string { return agewrap.RecipientHash(d.Recipient) }

// PersonDevices returns a person's devices sorted by id.
func (p *Policy) PersonDevices(person string) []Device {
	pr, ok := p.People[person]
	if !ok {
		return nil
	}
	var out []Device
	for _, name := range sortedKeys(pr.Devices) {
		rec := pr.Devices[name]
		out = append(out, Device{ID: config.DeviceID(person, name), Person: person, Device: name,
			Recipient: rec, Kind: agewrap.RecipientKind(rec)})
	}
	return out
}

// MachineDevice returns a machine's device.
func (p *Policy) MachineDevice(name string) (Device, bool) {
	m, ok := p.Machines[name]
	if !ok {
		return Device{}, false
	}
	return Device{ID: config.MachineID(name), Device: name, Machine: true,
		Recipient: m.Key, Kind: agewrap.RecipientKind(m.Key)}, true
}

// AllDevices returns every person device and machine, sorted by id.
func (p *Policy) AllDevices() []Device {
	var out []Device
	for _, person := range sortedKeys(p.People) {
		out = append(out, p.PersonDevices(person)...)
	}
	for _, m := range sortedKeys(p.Machines) {
		d, _ := p.MachineDevice(m)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Identify finds the device whose public key is recipient.
func (p *Policy) Identify(recipient string) (Device, bool) {
	if recipient == "" {
		return Device{}, false
	}
	for _, d := range p.AllDevices() {
		if d.Recipient == recipient {
			return d, true
		}
	}
	return Device{}, false
}

// TeamsOf returns the teams that list person, sorted.
func (p *Policy) TeamsOf(person string) []string {
	var out []string
	for _, t := range sortedKeys(p.Teams) {
		for _, m := range p.Teams[t] {
			if m == person {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// ScopeAccess is the resolved access for one scope.
type ScopeAccess struct {
	Package, Env string
	// Readers is the effective access list; ReadersFrom the file that set
	// it (empty if no file names this environment).
	Readers     []string
	ReadersFrom string
	RequirePQ   bool
	Drops       bool
	// PackageKnown is false when the package is not in this policy (for
	// example a package that is not on trunk yet). The workspace's access
	// then applies.
	PackageKnown bool
	// Devices are the devices that read the scope, sorted by id.
	Devices []Device
	// Why maps a device id to the access-list entries that grant it, in
	// list order: "@payments", "lin", "machine:deploy-checkout".
	Why map[string][]string
	// Unresolved lists entries that name no team, person or machine, and
	// team members with no person file, as "@team", "ada", "machine:x",
	// or "@team: ada".
	Unresolved []string
}

// Scope returns the access for pkg in env.
func (p *Policy) Scope(pkg, env string) (*ScopeAccess, error) {
	if !p.Workspace.HasEnvironment(env) {
		return nil, fmt.Errorf("environment %q is not one of %v", env, p.Workspace.Environments)
	}
	cp, known := p.Packages[pkg]
	r := p.Workspace.ResolveAccess(cp, env)
	sa := &ScopeAccess{
		Package: pkg, Env: env,
		Readers: r.Readers, ReadersFrom: r.ReadersFrom,
		RequirePQ: r.RequirePQ, Drops: r.Drops,
		PackageKnown: known,
		Why:          map[string][]string{},
	}
	byID := map[string]Device{}
	grant := func(d Device, entry string) {
		byID[d.ID] = d
		for _, e := range sa.Why[d.ID] {
			if e == entry {
				return
			}
		}
		sa.Why[d.ID] = append(sa.Why[d.ID], entry)
	}
	for _, entry := range r.Readers {
		kind, name, err := config.ParseReader(entry)
		if err != nil {
			sa.Unresolved = append(sa.Unresolved, entry)
			continue
		}
		switch kind {
		case config.ReaderTeam:
			members, ok := p.Teams[name]
			if !ok {
				sa.Unresolved = append(sa.Unresolved, entry)
				continue
			}
			for _, m := range members {
				if _, ok := p.People[m]; !ok {
					sa.Unresolved = append(sa.Unresolved, entry+": "+m)
					continue
				}
				for _, d := range p.PersonDevices(m) {
					grant(d, entry)
				}
			}
		case config.ReaderPerson:
			if _, ok := p.People[name]; !ok {
				sa.Unresolved = append(sa.Unresolved, entry)
				continue
			}
			for _, d := range p.PersonDevices(name) {
				grant(d, entry)
			}
		case config.ReaderMachine:
			d, ok := p.MachineDevice(name)
			if !ok {
				sa.Unresolved = append(sa.Unresolved, entry)
				continue
			}
			grant(d, entry)
		}
	}
	for _, id := range sortedKeys(byID) {
		sa.Devices = append(sa.Devices, byID[id])
	}
	return sa, nil
}

// Name returns "<package>/<env>".
func (s *ScopeAccess) Name() string { return config.ScopeName(s.Package, s.Env) }

// Names reports whether the scope's policy names device id.
func (s *ScopeAccess) Names(id string) bool {
	_, ok := s.Why[id]
	return ok
}

// Device returns the named device.
func (s *ScopeAccess) Device(id string) (Device, bool) {
	for _, d := range s.Devices {
		if d.ID == id {
			return d, true
		}
	}
	return Device{}, false
}

// Eligible splits Devices into those that may hold a slot and, under
// require_pq, those skipped because their key is not hybrid.
func (s *ScopeAccess) Eligible() (ok, skipped []Device) {
	for _, d := range s.Devices {
		if s.RequirePQ && !d.Hybrid() {
			skipped = append(skipped, d)
			continue
		}
		ok = append(ok, d)
	}
	return ok, skipped
}

// Readable reports whether any of the given device ids reads the scope.
func (s *ScopeAccess) Readable(ids ...string) bool {
	for _, id := range ids {
		if s.Names(id) {
			return true
		}
	}
	return false
}

// Scopes returns the access for every package in every environment,
// ordered by package then environment (in workspace order).
func (p *Policy) Scopes() []*ScopeAccess {
	var out []*ScopeAccess
	for _, pkg := range sortedKeys(p.Packages) {
		for _, env := range p.Workspace.Environments {
			sa, err := p.Scope(pkg, env)
			if err == nil {
				out = append(out, sa)
			}
		}
	}
	return out
}

// ScopesOf returns the scopes a principal reads, where principal is a
// person id or "machine:<name>". For each, Why holds the entries that
// grant each of the principal's devices.
func (p *Policy) ScopesOf(principal string) []*ScopeAccess {
	var out []*ScopeAccess
	for _, sa := range p.Scopes() {
		for _, d := range sa.Devices {
			if d.ID == principal || d.Person == principal {
				out = append(out, sa)
				break
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
