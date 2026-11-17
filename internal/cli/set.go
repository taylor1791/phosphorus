package cli

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/scope"
)

func init() {
	Register(&Command{
		Name:    "set",
		Group:   GroupDaily,
		Usage:   "<name> [--generate] [--allow-empty] [--env <env>] [--package <name>]",
		Summary: "Seal a secret, or drop one into the inbox",
		Help: `set reads the value from a hidden prompt, or from stdin when stdin is not a
terminal (one trailing newline is stripped). It never takes the value as an
argument. --generate makes random bytes instead (generate = "random:<n>" in
the declaration, 32 by default) and nobody sees them. An empty value is
refused unless --allow-empty is given.

If you read the scope, the value is sealed under its key. If you cannot, it
becomes a drop: encrypted to the scope's inbox key from trunk, readable by
readers at once, and promoted to a sealed value by their next "carbon apply".
The first set in a scope creates its key, wrapped to the devices that trunk
policy names.`,
		MinArgs: 1, MaxArgs: 1,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("generate", false, "generate a random value instead of reading one")
			fs.Bool("allow-empty", false, "store an empty value instead of refusing it")
		},
		Run: runSet,
	})
}

type setResult struct {
	Scope      string   `json:"scope"`
	Name       string   `json:"name"`
	Mode       string   `json:"mode"` // "sealed" or "dropped"
	KeyID      string   `json:"key"`
	CreatedKey bool     `json:"created_key"`
	Generated  bool     `json:"generated"`
	Reader     bool     `json:"reader"`
	Files      []string `json:"files"`
}

func runSet(c *Context) error {
	c.sealing = true
	name := c.Args[0]
	if err := config.CheckSecretName(name); err != nil {
		return c.UsageErr("%v", err)
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
	decl, declared := pkg.Secrets[name]
	if _, isVar := pkg.Vars[name]; isVar {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("%s is a var in %s, not a secret", name, pkg.File),
			Hint: "Vars are plain text: edit [vars." + name + "] in " + pkg.File + "."}
	}
	if !declared {
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s declares no secret %s", pkg.Name, name),
			Hint: fmt.Sprintf("Declare it in %s first:\n\n  [secrets]\n  %s = { description = \"...\" }", pkg.File, name)}
	}
	generate := c.Bool("generate")

	s, err := c.LoadScope(w, pkg, env)
	if err != nil {
		return err
	}
	res := setResult{Scope: s.Name(), Name: name, Generated: generate}

	// Decide how the value will be stored before asking for it.
	var opened *scope.Opened
	var inbox scope.Inbox
	ids, err := c.Identities(false)
	if err != nil {
		return err
	}
	if s.HasKey() {
		if ids != nil {
			wpol, err := c.WorktreePolicy(w)
			if err != nil {
				return err
			}
			opened, err = s.Open(ids, DeviceIDs(Me(wpol, ids))...)
			if err != nil && !errors.Is(err, scope.ErrNotReader) {
				return err
			}
			if opened != nil {
				if err := c.VerifyTrunk(w, pkg, opened); err != nil {
					opened.Close()
					return err
				}
				if err := c.stillNamed(w, pkg.Name, env, ids); err != nil {
					opened.Close()
					return err
				}
			}
		}
		if opened == nil {
			if inbox, err = c.dropTarget(w, s, pkg, env); err != nil {
				return err
			}
			if !c.JSON() {
				c.Notice("You cannot read %s, so this will be a drop: write-only for you.", s.Name())
			}
		}
	} else {
		pol, err := c.TrunkPolicy(w)
		if err != nil {
			return err
		}
		if tk, err := c.TrunkKeys(w, pol, pkg, env); err != nil {
			return err
		} else if tk != nil {
			return &Error{Code: ExitError, Message: fmt.Sprintf("%s has a key on trunk that this branch does not have", s.Name()),
				Hint: fmt.Sprintf("Bring this branch up to date first, for example:   git merge %s", pol.Ref)}
		}
		devices, err := scopeDevices(c, pol, pkg.Name, env)
		if err != nil {
			return err
		}
		// Only a device that policy names may create the key, so that the
		// first key, like every sealed value, comes from a reader.
		for _, id := range ids {
			for _, d := range devices {
				if id.Recipient != "" && d.Recipient == id.Recipient {
					res.Reader = true
				}
			}
		}
		if !res.Reader {
			sa, _ := pol.Scope(pkg.Name, env)
			readers := "the readers in its [access] entry"
			if sa != nil && len(sa.Readers) > 0 {
				readers = joinAnd(sa.Readers)
			}
			return &Error{Code: ExitNoAccess,
				Message: fmt.Sprintf("nobody has created the key for %s yet, and you cannot read it", s.Name()),
				Details: []string{"Only a reader may create a scope's key, so that every sealed value proves a reader wrote it."},
				Hint:    fmt.Sprintf("A reader must create it, with `carbon set` or `carbon apply`: any of %s.", readers)}
		}
		if opened, err = s.Create(devices, c.Now()); err != nil {
			return err
		}
		res.CreatedKey = true
	}
	if opened != nil {
		defer opened.Close()
		if !res.CreatedKey {
			res.Reader = true
		}
	}

	value, err := c.secretValue(s.Name(), name, decl, generate, c.Bool("allow-empty"))
	if err != nil {
		return err
	}
	defer clear(value)

	now := c.Now()
	if opened != nil {
		err = opened.Seal(name, value, now)
		res.Mode, res.KeyID = "sealed", opened.CurrentID()
	} else {
		err = s.Drop(inbox, name, value, now)
		res.Mode, res.KeyID = "dropped", inbox.KeyID
	}
	if err != nil {
		return err
	}
	written, err := s.Save()
	if err != nil {
		return err
	}
	if res.CreatedKey {
		if err := c.RecordPin(w, opened, ids); err != nil {
			return err
		}
	}
	for _, f := range written {
		if f == s.KeysPath() && !res.CreatedKey {
			continue
		}
		res.Files = append(res.Files, w.Rel(f))
	}

	return c.Output(res, func(out io.Writer) {
		if res.CreatedKey {
			fmt.Fprintf(out, "Created the key for %s, wrapped to the %s that policy names.\n",
				s.Name(), plural(len(s.SlotIDs()), "device"))
		}
		commit := "Commit " + joinAnd(res.Files)
		switch {
		case res.Mode == "dropped":
			fmt.Fprintf(out, "Dropped. Readers can use it at once; `carbon check` will flag it for review.\n%s\n", commit)
		case generate:
			fmt.Fprintf(out, "Generated %d random bytes for %s %s. Nobody has seen it.\n%s\n", generatedBytes(decl), s.Name(), name, commit)
		default:
			fmt.Fprintf(out, "Sealed. %s\n", commit)
		}
	})
}

// dropTarget checks that drops are allowed and returns trunk's inbox.
func (c *Context) dropTarget(w *Workspace, s *scope.Scope, pkg *config.Package, env string) (scope.Inbox, error) {
	pol, err := c.TrunkPolicy(w)
	if err != nil {
		return scope.Inbox{}, err
	}
	sa, err := pol.Scope(pkg.Name, env)
	if err != nil {
		return scope.Inbox{}, err
	}
	name := config.ScopeName(pkg.Name, env)
	if !sa.Drops {
		wpol, _ := c.WorktreePolicy(w)
		e := &Error{Code: ExitNoAccess, Message: fmt.Sprintf("you cannot read %s, and drops are off there", name),
			Details: []string{"drops = false in the [access] entry for " + env + "."}}
		if wpol != nil {
			ne := c.NoAccessErr(wpol, pkg.Name, env, nil, nil)
			e.Details = append(e.Details, ne.Details[:1]...)
		}
		e.Hint = fmt.Sprintf("Ask a reader to set it, or ask for access:   carbon request %s --env %s", pkg.Name, env)
		return scope.Inbox{}, e
	}
	keys, err := c.TrunkKeys(w, pol, pkg, env)
	if err != nil {
		return scope.Inbox{}, err
	}
	if keys == nil {
		return scope.Inbox{}, &Error{Code: ExitError,
			Message: fmt.Sprintf("%s has a key on this branch but not on trunk", name),
			Details: []string{"A drop goes to the inbox key on trunk, so that a key swapped on a branch is never used."},
			Hint:    "Merge the branch that created the scope first, or ask one of its readers to set the value."}
	}
	// A working tree that already retired trunk's current key means the local
	// trunk ref is behind: its inbox is one readers may no longer use.
	if pol.Origin == policy.OriginTrunk && s.Keys != nil {
		if r, ok := s.Keys.Keys[keys.Current]; ok && r.IsRetired() {
			return scope.Inbox{}, &Error{Code: ExitError,
				Message: fmt.Sprintf("your copy of trunk (%s) is behind this branch for %s", pol.Ref, name),
				Details: []string{fmt.Sprintf("Trunk's current key %s is retired in %s.", keys.Current, w.Rel(s.KeysPath()))},
				Hint:    "Update it, then try again:   git fetch"}
		}
	}
	inbox, err := scope.TrunkInbox(keys, pkg.Name, env)
	if err != nil {
		return scope.Inbox{}, err
	}
	return inbox, nil
}

// scopeDevices returns the devices that may hold a slot for a new scope key,
// warning about require_pq skips and unresolved readers.
func scopeDevices(c *Context, pol *policy.Policy, pkg, env string) ([]policy.Device, error) {
	sa, err := pol.Scope(pkg, env)
	if err != nil {
		return nil, err
	}
	for _, u := range sa.Unresolved {
		c.Notice("warning: %s names %s, which is not a team, person or machine; skipped.", sa.Name(), u)
	}
	ok, skipped := sa.Eligible()
	for _, d := range skipped {
		c.Notice("warning: %s requires post-quantum keys; skipped %s, whose key is X25519.", sa.Name(), d.ID)
	}
	if len(ok) == 0 {
		return nil, &Error{Code: ExitNoAccess, Message: fmt.Sprintf("nobody can read %s yet, so carbon cannot create its key", sa.Name()),
			Details: []string{fmt.Sprintf("Policy on %s names no device for %s.", sourceName(pol), sa.Name())},
			Hint:    "Add readers under [access] (and people under .carbon/people), merge to trunk, and try again."}
	}
	return ok, nil
}

func sourceName(pol *policy.Policy) string {
	if pol.Origin == policy.OriginTrunk {
		return "trunk " + pol.Ref
	}
	return "the working tree"
}

func generatedBytes(decl config.Secret) int {
	if decl.Generate != "" {
		if n, err := config.ParseGenerate(decl.Generate); err == nil {
			return n
		}
	}
	return 32
}

// secretValue returns the value to store: generated, or read from the
// hidden prompt / stdin.
func (c *Context) secretValue(scopeName, name string, decl config.Secret, generate, allowEmpty bool) ([]byte, error) {
	if generate {
		raw := make([]byte, generatedBytes(decl))
		defer clear(raw)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		out := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
		base64.RawURLEncoding.Encode(out, raw)
		return out, nil
	}
	v, err := c.ReadSecret(fmt.Sprintf("Value for %s %s (hidden): ", scopeName, name))
	if err != nil {
		return nil, err
	}
	if len(v) == 0 && !allowEmpty {
		return nil, &Error{Code: ExitUsage, Message: "the value is empty; nothing was stored",
			Hint: fmt.Sprintf("Pipe the value in (printf %%s \"$VALUE\" | carbon set %s), type it at the prompt, or pass --allow-empty to store an empty value.", name)}
	}
	if v == nil {
		v = []byte{}
	}
	return v, nil
}

// stillNamed refuses a caller whose slot still opens the key but whom the
// policy in effect (trunk, or the working tree in bootstrap and worktree
// mode) no longer names for the scope: a removed reader, before the
// rotation, must not write values that later look reader-made. They may
// not drop either; they simply cannot set.
func (c *Context) stillNamed(w *Workspace, pkg, env string, ids []agewrap.Identity) error {
	pol, err := c.TrunkPolicy(w)
	if err != nil {
		return err
	}
	sa, err := pol.Scope(pkg, env)
	if err != nil {
		return err
	}
	if sa.Readable(DeviceIDs(Me(pol, ids))...) {
		return nil
	}
	name := sa.Name()
	where := "trunk policy"
	if pol.Origin != policy.OriginTrunk {
		where = "policy"
	}
	return &Error{Code: ExitNoAccess,
		Message: fmt.Sprintf("%s no longer names you for %s", where, name),
		Details: []string{
			"Your device still holds a slot for the current key, but access was removed; the key will be rotated by the next `carbon apply`.",
			"Values you seal now would look as if a reader wrote them, so carbon refuses.",
		},
		Hint: fmt.Sprintf("To ask for access again:   carbon request %s --env %s", pkg, env)}
}
