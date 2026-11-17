package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/seal"
	"github.com/taylor1791/phosphorus/internal/store"
	"github.com/taylor1791/phosphorus/internal/tomledit"
)

func init() {
	Register(&Command{
		Name:    "remove",
		Group:   GroupAccess,
		Usage:   "<person | person/device | machine:name>",
		Summary: "Remove a person, device, or machine from policy",
		Help: `remove edits policy in the working tree. For a person it deletes
.carbon/people/<person>.toml and every team and [access] entry naming them,
in the workspace file, the teams file and every package file. For a device
it deletes that one line of the person file. For a machine it deletes
.carbon/machines/<name>.toml and every [access] entry naming it.

It prints the plan, the scopes whose keys rotate once the change merges and
a reader runs "carbon apply", and the secrets that will then owe a rotation
at their source: revoking access cannot un-share what was already read.`,
		MinArgs: 1, MaxArgs: 1,
		Run: runRemove,
	})
}

type removeEdit struct {
	File    string   `json:"file"`
	Delete  bool     `json:"delete,omitempty"`
	Changes []string `json:"changes"`

	data []byte
}

type removeDebt struct {
	Scope  string `json:"scope"`
	Secret string `json:"secret"`
	Set    string `json:"set"`
}

type removeResult struct {
	Target  string        `json:"target"`
	Kind    string        `json:"kind"` // person, device, machine
	Devices []string      `json:"devices"`
	Edits   []*removeEdit `json:"edits"`
	Rotate  []string      `json:"rotate"`
	Debt    []removeDebt  `json:"debt"`
}

func runRemove(c *Context) error {
	target := c.Args[0]
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	res := removeResult{Target: target, Edits: []*removeEdit{}, Rotate: []string{}, Debt: []removeDebt{}}

	// Which file goes or shrinks, and which access entries to drop.
	var reader string     // the access-list entry to remove
	var slotPrefix string // slot ids to rotate away start with this (or equal it)
	switch {
	case strings.HasPrefix(target, config.MachinePrefix):
		name := strings.TrimPrefix(target, config.MachinePrefix)
		if err := config.CheckName("machine", name); err != nil {
			return c.UsageErr("%v", err)
		}
		if _, ok := pol.Machines[name]; !ok {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no machine named %s", name),
				Hint: "Machines are the files in " + config.MachinesDir + "."}
		}
		res.Kind, reader, slotPrefix = "machine", target, target
		res.Devices = []string{target}
		res.Edits = append(res.Edits, &removeEdit{File: config.MachineFile(name), Delete: true, Changes: []string{"delete the machine"}})
	case strings.Contains(target, "/"):
		person, dev, _ := strings.Cut(target, "/")
		if err := config.CheckName("person", person); err != nil {
			return c.UsageErr("%v", err)
		}
		if err := config.CheckName("device", dev); err != nil {
			return c.UsageErr("%v", err)
		}
		p, ok := pol.People[person]
		if !ok {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no person named %s", person), Hint: "People are the files in " + config.PeopleDir + "."}
		}
		if _, ok := p.Devices[dev]; !ok {
			var devs []string
			for d := range p.Devices {
				devs = append(devs, d)
			}
			sort.Strings(devs)
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s has no device named %s", person, dev),
				Details: []string{fmt.Sprintf("%s's devices: %s.", person, strings.Join(devs, ", "))}}
		}
		if len(p.Devices) == 1 {
			return &Error{Code: ExitUsage, Message: fmt.Sprintf("%s is %s's only device", dev, person),
				Details: []string{"A person with no device cannot read anything, but would stay in teams and access lists."},
				Hint:    "To remove the person:   carbon remove " + person}
		}
		res.Kind, slotPrefix = "device", target
		res.Devices = []string{target}
		file := config.PersonFile(person)
		doc, err := removeLoad(w, file)
		if err != nil {
			return err
		}
		if _, err := doc.RemoveKey([]string{"devices", dev}); err != nil {
			return editErr(err)
		}
		res.Edits = append(res.Edits, &removeEdit{File: file, Changes: []string{"delete device " + dev}, data: doc.Bytes()})
	default:
		if err := config.CheckName("person", target); err != nil {
			return c.UsageErr("%v", err).WithHint("Usage: carbon remove <person | person/device | machine:name>")
		}
		if _, ok := pol.People[target]; !ok {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no person named %s", target),
				Hint: "People are the files in " + config.PeopleDir + "; machines are removed as machine:<name>."}
		}
		res.Kind, reader, slotPrefix = "person", target, target+"/"
		res.Devices = DeviceIDs(pol.PersonDevices(target))
		res.Edits = append(res.Edits, &removeEdit{File: config.PersonFile(target), Delete: true, Changes: []string{"delete the person"}})
		if len(pol.TeamsOf(target)) > 0 {
			doc, err := removeLoad(w, config.TeamsFile)
			if err != nil {
				return err
			}
			var changes []string
			for _, team := range pol.TeamsOf(target) {
				if _, err := doc.ArrayRemove([]string{team}, target); err != nil {
					return editErr(err)
				}
				changes = append(changes, "remove from @"+team)
			}
			res.Edits = append(res.Edits, &removeEdit{File: config.TeamsFile, Changes: changes, data: doc.Bytes()})
		}
	}

	// Access entries in the workspace file and every package file.
	if reader != "" {
		files := []string{config.FileName}
		for _, p := range pkgs {
			if p.File != config.FileName {
				files = append(files, p.File)
			}
		}
		sort.Strings(files[1:])
		for _, f := range files {
			doc, err := removeLoad(w, f)
			if err != nil {
				return err
			}
			var changes []string
			for _, env := range doc.Keys("access") {
				path := []string{"access", env}
				if doc.Kind(path...) == "table" {
					path = append(path, "readers")
				}
				changed, err := doc.ArrayRemove(path, reader)
				if err != nil {
					return editErr(err)
				}
				if changed {
					changes = append(changes, fmt.Sprintf("remove %s from [access] %s", reader, env))
				}
			}
			if len(changes) > 0 {
				res.Edits = append(res.Edits, &removeEdit{File: f, Changes: changes, data: doc.Bytes()})
			}
		}
	}

	// Scopes whose current key has a slot for a removed device rotate.
	var names []string
	for n := range pkgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := pkgs[n]
		for _, env := range w.Config.Environments {
			keys, err := store.ReadKeys(store.KeysPath(w.Dir(p), env))
			if err != nil {
				return err
			}
			if keys == nil {
				continue
			}
			hit := false
			for id := range keys.CurrentKey().Slots {
				if id == slotPrefix || (strings.HasSuffix(slotPrefix, "/") && strings.HasPrefix(id, slotPrefix)) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			sc := config.ScopeName(n, env)
			res.Rotate = append(res.Rotate, sc)
			secrets, err := store.ReadSecrets(store.SecretsPath(w.Dir(p), env))
			if err != nil {
				return err
			}
			for _, name := range secrets.Names() {
				res.Debt = append(res.Debt, removeDebt{Scope: sc, Secret: name, Set: seal.FormatTime(secrets.Entries[name].Set)})
			}
		}
	}

	if !c.JSON() {
		removePrintPlan(c.Stdout, &res)
	}
	if err := c.Confirm("Remove " + target + " from policy?"); err != nil {
		return err
	}
	for _, e := range res.Edits {
		abs := filepath.Join(w.Root, filepath.FromSlash(e.File))
		if e.Delete {
			if err := os.Remove(abs); err != nil {
				return err
			}
			continue
		}
		if err := os.WriteFile(abs, e.data, 0o644); err != nil {
			return err
		}
	}
	return c.Output(res, func(out io.Writer) {
		fmt.Fprintf(out, "Removed %s from policy in the working tree.\n\n", target)
		fmt.Fprintln(out, "Next: open a pull request with this change. Once it merges, a reader of each")
		fmt.Fprintln(out, "scope above runs `carbon apply`, which rotates its key. Then rotate the listed")
		fmt.Fprintln(out, "secrets at their source and `carbon set` the new values.")
	})
}

func removeLoad(w *Workspace, file string) (*tomledit.Doc, error) {
	data, err := os.ReadFile(filepath.Join(w.Root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	doc, err := tomledit.Parse(file, data)
	if err != nil {
		return nil, editErr(err)
	}
	return doc, nil
}

func removePrintPlan(out io.Writer, res *removeResult) {
	fmt.Fprintf(out, "Plan: remove %s %s (%s) from policy.\n\n", res.Kind, res.Target, strings.Join(res.Devices, ", "))
	var rows [][]string
	for _, e := range res.Edits {
		for i, ch := range e.Changes {
			f := e.File
			if i > 0 {
				f = ""
			}
			rows = append(rows, []string{"  " + f, ch})
		}
	}
	Table(out, rows)
	if len(res.Rotate) == 0 {
		fmt.Fprintf(out, "\nNo scope has a slot for %s, so no key will rotate.\n", res.Target)
	} else {
		fmt.Fprintf(out, "\nOnce this merges and a reader runs `carbon apply`, these keys rotate:\n")
		for _, s := range res.Rotate {
			fmt.Fprintf(out, "  %s\n", s)
		}
	}
	if len(res.Debt) > 0 {
		fmt.Fprintf(out, "\n%s could read these secrets; rotate each at its source, then `carbon set` it:\n", res.Target)
		var rows [][]string
		for _, d := range res.Debt {
			rows = append(rows, []string{"  " + d.Scope, d.Secret, "set " + d.Set})
		}
		Table(out, rows)
	}
	fmt.Fprintln(out)
}
