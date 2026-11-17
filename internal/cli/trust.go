package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/taylor1791/phosphorus/internal/pins"
	"github.com/taylor1791/phosphorus/internal/scope"
	"github.com/taylor1791/phosphorus/internal/seal"
)

func init() {
	Register(&Command{
		Name:    "trust",
		Usage:   "[<package>] [--env <env>]",
		Summary: "Accept a scope's current key after it was replaced",
		Help: `carbon remembers, per identity and per clone, the last key it verified for
each scope. If a scope's key is replaced by someone who did not hold the
previous key, readers refuse it. When the change is known to be legitimate
(for example the scope was deliberately re-created), trust shows the pinned
and current keys and the commit that last changed the keys file, asks for
confirmation, and pins the current key.

The current key must still be readable by you and must pass the trunk check.`,
		MaxArgs: 1,
		Run:     runTrust,
	})
}

type trustResult struct {
	Scope    string `json:"scope"`
	Previous string `json:"previous_key,omitempty"`
	KeyID    string `json:"key"`
	Changed  bool   `json:"changed"`
}

func runTrust(c *Context) error {
	if len(c.Args) == 1 {
		c.Global.Package = c.Args[0]
	}
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	pkg, err := c.Package(w)
	if err != nil {
		return err
	}
	env, err := c.Environment(w)
	if err != nil {
		return err
	}
	s, err := c.LoadScope(w, pkg, env)
	if err != nil {
		return err
	}
	if !s.HasKey() {
		return Errorf(ExitNotFound, "%s has no key yet; there is nothing to trust", s.Name())
	}
	ids, err := c.Identities(true)
	if err != nil {
		return err
	}
	wpol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}
	me := Me(wpol, ids)
	o, err := s.Open(ids, DeviceIDs(me)...)
	if errors.Is(err, scope.ErrNotReader) {
		return c.NoAccessErr(wpol, pkg.Name, env, me, s.SlotIDs())
	}
	if err != nil {
		return err
	}
	defer o.Close()
	if _, err := c.verifyTrunkKeys(w, pkg, o); err != nil {
		return err
	}
	f, err := c.LoadPins(w)
	if err != nil {
		return err
	}
	reader := pins.ReaderID(ids)
	pin, _ := f.Get(reader, s.Name())
	cur := o.CurrentPin()
	res := trustResult{Scope: s.Name(), KeyID: cur.KeyID, Changed: pin == nil || *pin != cur}
	if pin != nil {
		res.Previous = pin.KeyID
	}
	if !res.Changed {
		return c.Output(res, func(out io.Writer) {
			fmt.Fprintf(out, "Key %s for %s is already trusted.\n", cur.KeyID, s.Name())
		})
	}

	rec := s.Keys.CurrentKey()
	rel := w.Rel(s.KeysPath())
	last := "unknown"
	if out, err := w.Repo.Git("log", "-1", "--format=%h %an, %ad: %s", "--date=short", "--", rel); err == nil && len(out) > 0 {
		last = strings.TrimSpace(string(out))
	}
	pinned := "none"
	if pin != nil {
		pinned = fmt.Sprintf("%s  fingerprint %s…", pin.KeyID, pin.Fingerprint[:16])
	}
	rows := [][]string{
		{"Scope", s.Name()},
		{"Pinned", pinned},
		{"Current", fmt.Sprintf("%s  fingerprint %s…  created %s", cur.KeyID, cur.Fingerprint[:16], seal.FormatTime(rec.Created))},
		{"Slots", strings.Join(s.SlotIDs(), ", ")},
		{"Last change", last},
	}
	Table(c.Stderr, rows)
	fmt.Fprintf(c.Stderr, "\nTrust this key only if you know why it changed (see: git log -p -- %s).\n", rel)
	if err := c.Confirm(fmt.Sprintf("Trust key %s for %s?", cur.KeyID, s.Name())); err != nil {
		return err
	}
	f.Set(reader, s.Name(), cur)
	if err := f.Save(); err != nil {
		return err
	}
	return c.Output(res, func(out io.Writer) {
		fmt.Fprintf(out, "Trusted key %s for %s.\n", cur.KeyID, s.Name())
	})
}
