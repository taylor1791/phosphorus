package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/taylor1791/phosphorus/internal/agewrap"
	"github.com/taylor1791/phosphorus/internal/config"
	"github.com/taylor1791/phosphorus/internal/policy"
	"github.com/taylor1791/phosphorus/internal/store"
)

func init() {
	Register(&Command{
		Name:    "join",
		Group:   GroupAccess,
		Usage:   "[--person <name>] [--device <name>] [--x25519] [--passphrase] | --machine <name> [--description <text>]",
		Summary: "Create an identity and add its public key to the repo",
		Help: `join creates this device's identity under ~/.config/carbon/identity (or
reuses it: one identity serves every repo on the device) and adds its public
key to .carbon/people/<person>.toml. A second device adds a key to the same
person. Open a pull request with the change and confirm the fingerprint with
a reviewer over a channel you trust.

join --machine <name> writes .carbon/machines/<name>.toml and prints the
machine's private key once, on stdout, for your CI secret store. Nothing is
kept on this device. CI supplies it as CARBON_IDENTITY.

Keys are hybrid post-quantum by default; --x25519 makes a classic key.
--passphrase encrypts the identity file; carbon then asks for the passphrase
when it needs the key (or reads it from stdin when there is no terminal).`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("person", "", "person name (default: $USER, lower-cased)")
			fs.String("device", "", "device name (default: the short hostname)")
			fs.String("machine", "", "create a machine identity with this name instead")
			fs.String("description", "", "machine description")
			fs.Bool("x25519", false, "generate a classic X25519 key instead of a hybrid one")
			fs.Bool("passphrase", false, "encrypt the identity file with a passphrase")
		},
		Run: runJoin,
	})
}

type joinResult struct {
	Person      string   `json:"person,omitempty"`
	Device      string   `json:"device,omitempty"`
	Machine     string   `json:"machine,omitempty"`
	Recipient   string   `json:"recipient"`
	Fingerprint string   `json:"fingerprint"`
	Identity    string   `json:"identity_file,omitempty"`
	Created     bool     `json:"created_identity"`
	PublicFile  string   `json:"public_file"`
	Already     bool     `json:"already_joined,omitempty"`
	Teams       []string `json:"joined_teams,omitempty"`
	// Reads is how many scopes working-tree policy names this person for.
	Reads int `json:"policy_scopes"`
	// Next is the next step, as printed.
	Next string `json:"next,omitempty"`
	// PrivateKey is set for --machine only: the identity to store in CI.
	PrivateKey string `json:"private_key,omitempty"`
}

func keyKind(c *Context) agewrap.Kind {
	if x := c.Bool("x25519"); x {
		return agewrap.KindX25519
	}
	return agewrap.KindHybrid
}

func runJoin(c *Context) error {
	w, err := c.Workspace()
	if err != nil {
		return err
	}
	if m := c.String("machine"); m != "" {
		return joinMachine(c, w, m)
	}
	pol, err := c.WorktreePolicy(w)
	if err != nil {
		return err
	}
	res := joinResult{}

	// 1. This device's identity: reuse, or create.
	ids, err := c.Identities(false)
	if err != nil {
		return err
	}
	if ids != nil {
		if pp := c.Bool("passphrase"); pp {
			c.Notice("notice: you already have an identity; --passphrase applies only when join creates one.")
		}
		res.Recipient = ids[0].Recipient
		if res.Recipient == "" {
			return &Error{Code: ExitNoIdentity, Message: "cannot tell the public key of your identity",
				Details: []string{"Plugin identity files need a \"# public key: age1...\" comment."},
				Hint:    "Add the comment to " + c.IdentityPath() + ", then run carbon join again."}
		}
		if d, ok := pol.Identify(res.Recipient); ok {
			res.Already = true
			if d.Machine {
				res.Machine = d.Device
			} else {
				res.Person, res.Device = d.Person, d.Device
			}
			res.Fingerprint = agewrap.Fingerprint(res.Recipient)
			return c.Output(res, func(out io.Writer) {
				fmt.Fprintf(out, "You have already joined as %s.\nFingerprint   %s\n", d.ID, res.Fingerprint)
			})
		}
	}

	person := c.String("person")
	if person == "" {
		person = SanitizeName(c.Getenv("USER"))
	}
	if err := config.CheckName("person", person); err != nil {
		return c.UsageErr("%v", err).WithHint("Pass your name with --person <name>.")
	}
	device := c.String("device")
	if device == "" {
		h, _ := os.Hostname()
		h, _, _ = strings.Cut(h, ".")
		device = SanitizeName(h)
	}
	if err := config.CheckName("device", device); err != nil {
		return c.UsageErr("%v", err).WithHint("Name this device with --device <name>.")
	}
	if p, ok := pol.People[person]; ok {
		if _, taken := p.Devices[device]; taken {
			return &Error{Code: ExitUsage, Message: fmt.Sprintf("%s already has a device named %s", person, device),
				Details: []string{"It has a different public key than your identity."},
				Hint:    fmt.Sprintf("Name this device:   carbon join --person %s --device <name>", person)}
		}
	}
	if ids == nil {
		path, rec, err := createIdentity(c)
		if err != nil {
			return err
		}
		res.Created, res.Identity, res.Recipient = true, path, rec
	} else {
		res.Identity = c.IdentityPath()
		if c.Getenv("CARBON_IDENTITY") != "" {
			res.Identity = "CARBON_IDENTITY"
		}
	}

	// 2. The person file.
	firstPerson := len(pol.People) == 0
	p := pol.People[person]
	if p == nil {
		p = &config.Person{ID: person, Devices: map[string]string{}}
	}
	p.Devices[device] = res.Recipient
	file := config.PersonFile(person)
	if err := store.WriteFile(filepath.Join(w.Root, filepath.FromSlash(file)), config.MarshalPerson(p)); err != nil {
		return err
	}
	res.Person, res.Device, res.PublicFile = person, device, file
	res.Fingerprint = agewrap.Fingerprint(res.Recipient)

	// 3. The first person in a new workspace joins every empty team, so
	// that a single developer can init, join and set. Only while carbon is
	// not adopted on trunk (bootstrap): afterwards team membership is a
	// reviewed change, never a side effect of joining.
	bootstrap := false
	if firstPerson && len(pol.Teams) > 0 {
		tp, err := c.TrunkPolicy(w)
		if err != nil {
			return err
		}
		bootstrap = tp.Origin == policy.OriginBootstrap
	}
	if bootstrap {
		var joined []string
		for t, members := range pol.Teams {
			if len(members) == 0 {
				pol.Teams[t] = []string{person}
				joined = append(joined, t)
			}
		}
		if len(joined) > 0 {
			sort.Strings(joined)
			if err := store.WriteFile(filepath.Join(w.Root, filepath.FromSlash(config.TeamsFile)), config.MarshalTeams(pol.Teams)); err != nil {
				return err
			}
			res.Teams = joined
		}
	}

	// What comes next depends on whether policy already names this person
	// (a bootstrap team, or a new device of a reader) and on whether there
	// is a reviewed trunk.
	if after, err := policy.LoadWorktree(w.Root); err == nil {
		res.Reads = len(after.ScopesOf(person))
	}
	res.Next = joinNext(bootstrap && len(res.Teams) > 0, firstPerson, res.Reads)

	return c.Output(res, func(out io.Writer) {
		var rows [][]string
		if res.Created {
			rows = append(rows, []string{"Created your identity", tildePath(c, res.Identity), "(device: " + device + ")"})
		} else {
			rows = append(rows, []string{"Using your identity", tildePath(c, res.Identity), "(device: " + device + ")"})
		}
		rows = append(rows, []string{"Added your public key", file})
		for _, t := range res.Teams {
			rows = append(rows, []string{"Joined team", "@" + t, "(first person in this workspace)"})
		}
		rows = append(rows, []string{"Fingerprint", res.Fingerprint})
		Table(out, rows)
		fmt.Fprintf(out, "\n%s\n", res.Next)
	})
}

// joinNext is the next-step text after join.
func joinNext(bootstrapTeams, firstPerson bool, reads int) string {
	switch {
	case bootstrapTeams:
		return "You read every environment those teams are granted, because carbon is not on trunk yet.\n" +
			"Next: carbon init in each package directory, declare its secrets, then carbon set <name>.\n" +
			"Commit the carbon files to trunk when ready; from then on access changes go through review."
	case reads > 0:
		return fmt.Sprintf("Policy already names you for %s, so no access change is needed.\n", plural(reads, "scope")) +
			"Next: open a pull request with this change. Once it merges, a current reader runs\n" +
			"`carbon apply` to wrap those scopes' keys to this device."
	case firstPerson:
		return "Next: add yourself to a team in .carbon/teams.toml or to an [access] list, then commit."
	}
	return "Next: open a pull request with this change and ask to be added to a team\n" +
		"(or run `carbon request <package> --env <env>` on the same branch).\n" +
		"Access starts once it merges and a current reader runs `carbon apply`."
}

// createIdentity writes a new identity file (mode 0600, directory 0700),
// passphrase-encrypted with --passphrase. It never overwrites a file.
func createIdentity(c *Context) (string, string, error) {
	path := c.IdentityPath()
	secret, rec, err := agewrap.GenerateIdentity(keyKind(c))
	if err != nil {
		return "", "", err
	}
	data := agewrap.IdentityFile(secret, rec, c.Now())
	defer clear(data)
	if pp := c.Bool("passphrase"); pp {
		pass, err := c.ReadPassphrase("Passphrase for your new identity: ", true)
		if err != nil {
			return "", "", err
		}
		enc, err := agewrap.EncryptIdentityFile(data, pass)
		if err != nil {
			return "", "", err
		}
		data = enc
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return "", "", &Error{Code: ExitNoIdentity, Message: path + " exists but could not be used"}
	}
	if err != nil {
		return "", "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", "", err
	}
	return path, rec, f.Close()
}

func tildePath(c *Context, p string) string {
	if home := c.Getenv("HOME"); home != "" {
		if rest, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
			return "~/" + filepath.ToSlash(rest)
		}
	}
	return p
}

func joinMachine(c *Context, w *Workspace, name string) error {
	if err := config.CheckName("machine", name); err != nil {
		return c.UsageErr("%v", err)
	}
	file := config.MachineFile(name)
	abs := filepath.Join(w.Root, filepath.FromSlash(file))
	if _, err := os.Stat(abs); err == nil {
		return &Error{Code: ExitUsage, Message: fmt.Sprintf("machine %s already exists in %s", name, file),
			Hint: fmt.Sprintf("To replace its key, remove it first:   carbon remove machine:%s", name)}
	}
	secret, rec, err := agewrap.GenerateIdentity(keyKind(c))
	if err != nil {
		return err
	}
	desc := c.String("description")
	if err := store.WriteFile(abs, config.MarshalMachine(&config.Machine{ID: name, Description: desc, Key: rec})); err != nil {
		return err
	}
	identity := string(agewrap.IdentityFile(secret, rec, c.Now()))
	res := joinResult{Machine: name, Recipient: rec, Fingerprint: agewrap.Fingerprint(rec), PublicFile: file, PrivateKey: identity}
	if c.JSON() {
		return c.WriteJSON(res)
	}
	// stdout carries only the private key, so `> key.txt` captures it.
	fmt.Fprint(c.Stdout, identity)
	Table(c.Stderr, [][]string{
		{"Added machine", file},
		{"Fingerprint", res.Fingerprint},
	})
	fmt.Fprintf(c.Stderr, "\nThe private key above is shown once and not stored. Put it in your CI secret\nstore and expose it to the job as CARBON_IDENTITY.\nNext: add machine:%s to the [access] lists it needs and open a pull request.\n", name)
	return nil
}
