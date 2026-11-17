package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/tomledit"
)

func init() {
	Register(&Command{
		Name:    "rename",
		Usage:   "<old-package> <new-package>",
		Summary: "Rename a package and re-seal its secrets under the new name",
		Help: `Values, drops and keys are bound to the package's name, so renaming a package
re-seals them. rename needs you to read every environment of the package
that has a key. It re-seals every value and drop (keeping set times),
re-wraps the slots to the same devices (public keys from trunk policy),
updates name in the package's carbon.toml, the scope line of each keys
file, and ${old.x} references in other packages' [env] tables.

The package directory stays where it is; move it with git mv if you like.`,
		MinArgs: 2, MaxArgs: 2,
		Run: runRename,
	})
}

type renameScope struct {
	Scope  string   `json:"scope"`
	Values int      `json:"values"`
	Files  []string `json:"files"`

	opened *scope.Opened
}

type renameRef struct {
	File string `json:"file"`
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

type renameResult struct {
	From   string         `json:"from"`
	To     string         `json:"to"`
	File   string         `json:"file"`
	Scopes []*renameScope `json:"scopes"`
	Refs   []renameRef    `json:"references"`
	Files  []string       `json:"files"`
}

func runRename(c *Context) error {
	oldName, newName := c.Args[0], c.Args[1]
	if err := config.CheckName("package", newName); err != nil {
		return c.UsageErr("%v", err)
	}
	for _, r := range config.ReservedPackageNames {
		if newName == r {
			return c.UsageErr("%q is a reserved package name", newName)
		}
	}
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkgs, err := w.Packages()
	if err != nil {
		return err
	}
	pkg, ok := pkgs[oldName]
	if !ok {
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no package named %q", oldName),
			Hint: "Package names are the name = \"...\" lines in each carbon.toml."}
	}
	if other, ok := pkgs[newName]; ok {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("package %q already exists in %s", newName, other.File)}
	}
	res := renameResult{From: oldName, To: newName, File: pkg.File, Scopes: []*renameScope{}, Refs: []renameRef{}}

	// Open every scope that has a key; all of them, or nothing happens.
	var toOpen []*scope.Scope
	for _, env := range w.Config.Environments {
		s, err := c.LoadScope(w, pkg, env)
		if err != nil {
			return err
		}
		if s.HasKey() {
			toOpen = append(toOpen, s)
		}
	}
	defer func() {
		for _, rs := range res.Scopes {
			if rs.opened != nil {
				rs.opened.Close()
			}
		}
	}()
	if len(toOpen) > 0 {
		pol, err := c.TrunkPolicy(w)
		if err != nil {
			return err
		}
		devices := pol.AllDevices()
		known := map[string]bool{}
		for _, d := range devices {
			known[d.ID] = true
		}
		for _, s := range toOpen {
			o, err := c.OpenScope(w, pkg, s)
			if err != nil {
				if e := AsError(err); e.Code == ExitNoAccess {
					e.Message = fmt.Sprintf("you cannot read %s, so you cannot rename %s", s.Name(), oldName)
					e.Details = append([]string{"rename re-seals every environment that has a key, so it needs a reader of each."}, e.Details...)
					e.Hint = "Ask someone who reads every environment of " + oldName + " to run:   carbon rename " + oldName + " " + newName
					return e
				}
				return err
			}
			res.Scopes = append(res.Scopes, &renameScope{Scope: s.Name(), Values: len(s.Secrets.Entries), opened: o})
			for _, id := range s.SlotIDs() {
				if !known[id] {
					return &Error{Code: ExitError, Message: fmt.Sprintf("%s has a slot for %s, which trunk policy does not name", s.Name(), id),
						Details: []string{"rename re-wraps each slot to the same device, and needs its public key from trunk."},
						Hint:    "Run `carbon apply` first (it rotates the slot away), then rename."}
				}
			}
		}
		for _, rs := range res.Scopes {
			if err := rs.opened.Rename(newName, devices); err != nil {
				return err
			}
		}
	}

	// Policy edits: the package's name, and references in [env] tables.
	edits := map[string]*tomledit.Doc{}
	load := func(file string) (*tomledit.Doc, error) {
		if d, ok := edits[file]; ok {
			return d, nil
		}
		d, err := removeLoad(w, file)
		if err == nil {
			edits[file] = d
		}
		return d, err
	}
	doc, err := load(pkg.File)
	if err != nil {
		return err
	}
	if err := doc.SetString([]string{"name"}, newName); err != nil {
		return editErr(err)
	}
	var names []string
	for n := range pkgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := pkgs[n]
		var keys []string
		for k := range p.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			to, changed := renameTemplate(p.Env[k], oldName, newName)
			if !changed {
				continue
			}
			d, err := load(p.File)
			if err != nil {
				return err
			}
			if err := d.SetString([]string{"env", k}, to); err != nil {
				return editErr(err)
			}
			res.Refs = append(res.Refs, renameRef{File: p.File, Key: k, From: p.Env[k], To: to})
		}
	}

	if !c.JSON() {
		fmt.Fprintf(c.Stdout, "Plan: rename package %s to %s.\n\n", oldName, newName)
		var rows [][]string
		rows = append(rows, []string{"  " + pkg.File, fmt.Sprintf("name = %q", newName)})
		for _, rs := range res.Scopes {
			rows = append(rows, []string{"  " + rs.Scope, fmt.Sprintf("re-seal %d value(s), re-wrap %d slot(s), keeping set times", rs.Values, len(rs.opened.SlotIDs()))})
		}
		for _, r := range res.Refs {
			rows = append(rows, []string{"  " + r.File, fmt.Sprintf("[env] %s = %q", r.Key, r.To)})
		}
		Table(c.Stdout, rows)
		fmt.Fprintln(c.Stdout)
	}
	if err := c.Confirm(fmt.Sprintf("Rename %s to %s?", oldName, newName)); err != nil {
		return err
	}

	var files []string
	for _, rs := range res.Scopes {
		written, err := writeScopeFiles(rs.opened.Scope)
		if err != nil {
			return err
		}
		for _, f := range written {
			rs.Files = append(rs.Files, w.Rel(f))
		}
		files = append(files, rs.Files...)
	}
	var editFiles []string
	for f := range edits {
		editFiles = append(editFiles, f)
	}
	sort.Strings(editFiles)
	for _, f := range editFiles {
		if err := os.WriteFile(filepath.Join(w.Root, filepath.FromSlash(f)), edits[f].Bytes(), 0o644); err != nil {
			return err
		}
		files = append(files, f)
	}
	res.Files = files
	return c.Output(res, func(out io.Writer) {
		fmt.Fprintf(out, "Renamed %s to %s. Changed %s.\n\n", oldName, newName, strings.Join(files, ", "))
		fmt.Fprintln(out, "Next: commit these files together and open a pull request.")
	})
}

// renameTemplate rewrites ${old.x} references in an [env] template.
func renameTemplate(tmpl, oldName, newName string) (string, bool) {
	parts, err := config.ParseTemplate(tmpl)
	if err != nil {
		return tmpl, false
	}
	changed := false
	var b strings.Builder
	for _, p := range parts {
		if p.Ref == nil {
			b.WriteString(strings.ReplaceAll(p.Literal, "$", "$$"))
			continue
		}
		switch p.Ref.Kind {
		case config.RefLocal:
			fmt.Fprintf(&b, "${%s}", p.Ref.Name)
		case config.RefPackage:
			pkg := p.Ref.Package
			if pkg == oldName {
				pkg, changed = newName, true
			}
			fmt.Fprintf(&b, "${%s.%s}", pkg, p.Ref.Name)
		case config.RefEnv:
			fmt.Fprintf(&b, "${env:%s}", p.Ref.Name)
		case config.RefCarbonEnv:
			b.WriteString("${carbon.env}")
		}
	}
	return b.String(), changed
}
