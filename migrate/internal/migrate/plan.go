// Package migrate turns a carbon 0.0.3 repository into a Carbon 1.0
// workspace: it plans the change (the dry run), writes the policy files,
// copies every secret through `carbon set`, verifies it with `carbon get`,
// moves the private key, and only then deletes the old registries.
package migrate

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/taylor1791/phosphorus/migrate/internal/legacy"
)

// GitAttributesLine is the line `carbon init` adds to .gitattributes.
const GitAttributesLine = "**/.carbon/*.keys.toml linguist-generated"

// Input is everything the planner needs. It is pure data so the planner can
// be tested without sops or git.
type Input struct {
	Repo *legacy.Repo
	// Values holds each registry's decrypted content by old registry name.
	// A registry missing here could not be decrypted; DecryptErrors says why.
	Values        map[string]legacy.Values
	DecryptErrors map[string]string

	DefaultEnv   string            // name for the unnamed registry ("dev")
	EnvNames     map[string]string // old registry name -> environment
	PackageNames map[string]string // old service name -> package name
	Trunk        string

	// Me is the recipient of the 0.0.3 key running the migration.
	Me string
	// KeyFile is the 0.0.3 key (slash path relative to the root when it is
	// the repository's .carbon/private-key.age, else absolute).
	KeyFile string
	// MoveKey is true when KeyFile is the repository's own key and should be
	// moved to the 1.0 identity path.
	MoveKey bool
	// IdentityPath is where carbon 1.0 looks for the identity.
	IdentityPath string
	// IdentityExisting is the recipient of an identity already at
	// IdentityPath ("" when there is none; "?" when it cannot be read).
	IdentityExisting string
	IdentityExists   bool

	// Existing reports whether a slash path exists in the working tree.
	Existing func(string) bool
	// GitAttributes is the current .gitattributes content (nil if absent).
	GitAttributes []byte
	// TrunkRootLegacy is true when the trunk ref has a 0.0.3 root carbon.toml.
	TrunkRootLegacy bool
	// RootWorkspace is true when the root carbon.toml is already a 1.0
	// workspace file.
	RootWorkspace bool
}

// Env maps an old registry to a 1.0 environment.
type Env struct {
	Old string
	New string
	Reg *legacy.Registry
}

// Person is a person file to write.
type Person struct {
	ID      string
	Name    string
	Devices map[string]string // device -> recipient
	Reads   []string          // environments
}

// Package is a 1.0 package converted from a 0.0.3 service.
type Package struct {
	Svc     *legacy.Service
	Name    string
	File    string
	Dir     string
	Secrets map[string]bool
	Vars    map[string]map[string]string // var -> env|"default" -> value
	Env     map[string]string            // [env] key -> template
	Notes   []string                     // written as comments in the file
	// keyNames maps a 0.0.3 push key to its 1.0 secret or var name.
	keyNames map[string]string
	isSecret map[string]bool
}

// Copy is one secret value to pipe into `carbon set`.
type Copy struct {
	Package string
	Env     string
	Name    string
	// Source describes where the value came from, for the plan.
	Source string
	value  string
}

// Scope renders "<package>/<env>".
func (c Copy) Scope() string { return c.Package + "/" + c.Env }

// FileChange is one file carbon-migrate writes.
type FileChange struct {
	Path    string // slash path relative to the root
	Content []byte
	Action  string // "create", "rewrite", "append"
	What    string
}

// Plan is the full migration.
type Plan struct {
	Envs       []Env
	DefaultEnv string
	Trunk      string
	People     []*Person
	Packages   []*Package
	Files      []FileChange
	Copies     []Copy
	Deletes    []string // old registry and sops files
	// Identity handling.
	KeyFile        string
	MoveKey        bool
	IdentityPath   string
	IdentityAction string // "install", "already-installed", "leave"
	Me             string // person id of the migrator, if known
	Manual         []string
	Blockers       []string
}

// Value returns the plaintext of a copy. It is only ever piped to carbon.
func (c Copy) Value() string { return c.value }

type planner struct {
	in   Input
	p    *Plan
	envs []Env
	pkgs map[string]*Package // by old service name
	// hasValue[pkg][name][env] records that a value or var exists, for the
	// pull-default notes.
	hasValue map[string]map[string]map[string]bool
}

// Build plans the migration. It never fails: problems that stop a --write
// are Blockers, and choices it cannot make are Manual items.
func Build(in Input) *Plan {
	pl := &planner{in: in, p: &Plan{}, pkgs: map[string]*Package{}, hasValue: map[string]map[string]map[string]bool{}}
	pl.build()
	return pl.p
}

func (pl *planner) block(format string, a ...any) {
	pl.p.Blockers = append(pl.p.Blockers, fmt.Sprintf(format, a...))
}
func (pl *planner) manual(format string, a ...any) {
	pl.p.Manual = append(pl.p.Manual, fmt.Sprintf(format, a...))
}

func (pl *planner) build() {
	in, p := pl.in, pl.p
	if in.RootWorkspace {
		pl.block("the root carbon.toml already has a [workspace] table: this repository looks migrated already.")
	}
	if len(in.Repo.Services) == 0 {
		pl.block("no carbon 0.0.3 carbon.toml (a service file with name, [push], [pull] or [derive]) was found.")
	}
	if len(in.Repo.Registries) == 0 {
		pl.block("no registries were found under .carbon/ (registry*.yaml, sops*.yaml).")
	}
	pl.planEnvs()
	pl.planPeople()
	pl.planPackages()
	pl.planOrphans()
	pl.planTrunk()
	pl.planIdentity()
	for _, e := range pl.envs {
		if e.Reg.HasRegistry {
			p.Deletes = append(p.Deletes, e.Reg.RegistryFile)
		}
		if e.Reg.HasSops {
			p.Deletes = append(p.Deletes, e.Reg.SopsFile)
		}
	}
	pl.planFiles()
}

func (pl *planner) planEnvs() {
	in, p := pl.in, pl.p
	defaultEnv := in.DefaultEnv
	if defaultEnv == "" {
		defaultEnv = "dev"
	}
	seen := map[string]string{}
	for _, r := range in.Repo.Registries {
		name := r.Name
		if n, ok := in.EnvNames[r.Name]; ok {
			name = n
		} else if r.Name == "" {
			name = defaultEnv
		}
		switch {
		case !validName(name):
			pl.block("registry %s cannot be the environment %q: environment names are lower-case letters, digits, '-' and '_'. Choose one with --env-name %s=<name>.", r.Label(), name, r.Name)
		case name == "default":
			pl.block(`registry %s cannot be the environment "default", which 1.0 reserves in [vars]. Choose another with --env-name %s=<name>.`, r.Label(), r.Name)
		}
		if prev, ok := seen[name]; ok {
			pl.block("registries %s and %s would both become environment %q. Rename one with --default-env or --env-name.", prev, r.Label(), name)
		}
		seen[name] = r.Label()
		pl.envs = append(pl.envs, Env{Old: r.Name, New: name, Reg: r})
		if !r.HasRegistry {
			pl.manual("registry %s has %s but no %s: nobody ever pushed to it, so environment %s starts empty.", r.Label(), r.SopsFile, r.RegistryFile, name)
		} else if msg, bad := in.DecryptErrors[r.Name]; bad {
			pl.block("cannot decrypt %s with your 0.0.3 key, so its values cannot be copied. Run carbon-migrate as someone who can read every registry (or have one of them run `carbon rekey %s` with 0.0.3 first).\n%s", r.RegistryFile, r.Name, msg)
		}
	}
	// The unnamed registry first, then by name (Registries is sorted that way).
	p.Envs = pl.envs
	for _, e := range pl.envs {
		if e.Old == "" {
			p.DefaultEnv = e.New
		}
	}
	if p.DefaultEnv == "" && len(pl.envs) > 0 {
		p.DefaultEnv = pl.envs[0].New
	}
}

func (pl *planner) envLabel(e Env) string {
	if e.Old == e.New {
		return e.New
	}
	return fmt.Sprintf("%s (was registry %s)", e.New, e.Reg.Label())
}

// planPeople turns sops `users` and recipients into people files. A person
// reads an environment when the registry is actually wrapped to one of their
// keys; a key that only requested access is listed for a manual decision.
func (pl *planner) planPeople() {
	p := pl.p
	keyName := map[string]string{}
	var order []string
	addKey := func(key, name string) {
		if _, ok := keyName[key]; !ok {
			keyName[key] = name
			order = append(order, key)
		} else if keyName[key] == "" && name != "" {
			keyName[key] = name
		}
	}
	for _, e := range pl.envs {
		for _, u := range e.Reg.Users {
			if u.Key == "" {
				continue
			}
			if prev, ok := keyName[u.Key]; ok && prev != "" && prev != u.Name {
				pl.manual("key %s is recorded as both %q and %q; it was given to %q.", short(u.Key), prev, u.Name, prev)
				continue
			}
			addKey(u.Key, u.Name)
		}
	}
	for _, e := range pl.envs {
		for _, k := range e.Reg.Granted {
			addKey(k, "")
		}
		for _, k := range e.Reg.Requested {
			addKey(k, "")
		}
	}
	byID := map[string]*Person{}
	keyPerson := map[string]*Person{}
	unknown := 0
	for _, k := range order {
		name := keyName[k]
		var id string
		if name == "" {
			unknown++
			id = fmt.Sprintf("unknown-%d", unknown)
			pl.manual("key %s can read or asked to read a registry but no `users` entry names it. It became person %s (.carbon/people/%s.toml); rename the file to the person it belongs to.", short(k), id, id)
		} else {
			id = slugName(name)
			if id != name {
				pl.manual("user %q became person %q (person names are lower-case letters, digits, '-' and '_').", name, id)
			}
			if name == "Enter your name" {
				pl.manual("person %q comes from a 0.0.3 request made without $USER; rename .carbon/people/%s.toml to the real person.", id, id)
			}
		}
		per, ok := byID[id]
		if !ok {
			per = &Person{ID: id, Name: name, Devices: map[string]string{}}
			byID[id] = per
			p.People = append(p.People, per)
		}
		dev := "migrated"
		if n := len(per.Devices); n > 0 {
			dev = fmt.Sprintf("migrated-%d", n+1)
		}
		per.Devices[dev] = k
		keyPerson[k] = per
		if k == pl.in.Me {
			p.Me = id
		}
	}
	for _, e := range pl.envs {
		granted := e.Reg.Granted
		if !e.Reg.HasRegistry {
			granted = e.Reg.Requested
		}
		readers := map[string]bool{}
		for _, k := range granted {
			readers[keyPerson[k].ID] = true
		}
		for _, per := range p.People {
			if readers[per.ID] {
				per.Reads = append(per.Reads, e.New)
			}
		}
		g := map[string]bool{}
		for _, k := range granted {
			g[k] = true
		}
		for _, k := range e.Reg.Requested {
			if !g[k] {
				pl.manual("%s requested access to registry %s but was never granted it (no `carbon rekey`), so they are not a reader of %s. To grant it, add %q to [access] %s in carbon.toml after merging and run `carbon apply`.", keyPerson[k].ID, e.Reg.Label(), e.New, keyPerson[k].ID, e.New)
			}
		}
	}
	sort.Slice(p.People, func(i, j int) bool { return p.People[i].ID < p.People[j].ID })
	if pl.in.Me != "" && p.Me == "" {
		pl.block("your 0.0.3 key (%s) is not a recipient of any registry, so you cannot copy the values.", short(pl.in.Me))
	}
	if p.Me != "" {
		for _, e := range pl.envs {
			if !e.Reg.HasRegistry {
				continue
			}
			reads := false
			for _, env := range byID[p.Me].Reads {
				if env == e.New {
					reads = true
				}
			}
			if !reads {
				if _, bad := pl.in.DecryptErrors[e.Old]; !bad {
					pl.block("your key is not a recipient of %s, so `carbon get` could not verify environment %s.", e.Reg.RegistryFile, e.New)
				}
			}
		}
	}
}

func (pl *planner) planPackages() {
	in := pl.in
	byName := map[string][]*legacy.Service{}
	for _, s := range in.Repo.Services {
		byName[s.Name] = append(byName[s.Name], s)
	}
	pkgNames := map[string]string{}
	for _, s := range in.Repo.Services {
		if dup := byName[s.Name]; len(dup) > 1 {
			if dup[0] == s {
				var files []string
				for _, d := range dup {
					files = append(files, d.File)
				}
				pl.block("service name %q is used by %s; 0.0.3 `check` rejects this and 1.0 needs unique package names. Rename all but one first.", s.Name, strings.Join(files, " and "))
			}
			continue
		}
		name := s.Name
		if n, ok := in.PackageNames[s.Name]; ok {
			name = n
		} else if !validName(name) {
			name = slugName(name)
			pl.manual("service %q became package %q (package names are lower-case letters, digits, '-' and '_'). Pass --package-name %s=<name> to choose another.", s.Name, name, s.Name)
		}
		if !validName(name) {
			pl.block("package name %q (service %q) is not valid; choose one with --package-name %s=<name>.", name, s.Name, s.Name)
		}
		if reservedPackages[name] {
			pl.block("package name %q (service %q) is reserved in 1.0; choose another with --package-name %s=<name>.", name, s.Name, s.Name)
		}
		if prev, ok := pkgNames[name]; ok {
			pl.block("services %q and %q would both become package %q; use --package-name.", prev, s.Name, name)
		}
		pkgNames[name] = s.Name
		for _, seg := range strings.Split(s.Dir, "/") {
			if strings.HasPrefix(seg, ".") && seg != "." || seg == "node_modules" {
				pl.block("service %q lives in %s, inside a directory carbon 1.0 does not search (it skips dot-directories and node_modules). Move it first, e.g. `git mv %s <new dir>`, commit, and re-run.", s.Name, s.File, s.Dir)
				break
			}
		}
		pl.pkgs[s.Name] = &Package{
			Svc: s, Name: name, File: s.File, Dir: s.Dir,
			Secrets: map[string]bool{}, Vars: map[string]map[string]string{}, Env: map[string]string{},
			keyNames: map[string]string{}, isSecret: map[string]bool{},
		}
	}
	// Pushes first, so pulls and derives can refer to them.
	for _, s := range in.Repo.Services {
		if pkg := pl.pkgs[s.Name]; pkg != nil && pkg.Svc == s {
			pl.planPush(pkg)
		}
	}
	for _, s := range in.Repo.Services {
		if pkg := pl.pkgs[s.Name]; pkg != nil && pkg.Svc == s {
			pl.planPulls(pkg)
			pl.planDerives(pkg)
			pl.planServiceNotes(pkg)
			pl.p.Packages = append(pl.p.Packages, pkg)
		}
	}
}

func (pl *planner) markValue(pkg, name, env string) {
	if pl.hasValue[pkg] == nil {
		pl.hasValue[pkg] = map[string]map[string]bool{}
	}
	if pl.hasValue[pkg][name] == nil {
		pl.hasValue[pkg][name] = map[string]bool{}
	}
	pl.hasValue[pkg][name][env] = true
}

// pushTemplate resolves a 0.0.3 push value the way `push` does: only
// {{carbon.registry}} is substituted, with the old registry name.
func pushTemplate(v, registry string) string {
	return strings.ReplaceAll(v, "{{carbon.registry}}", registry)
}

func (pl *planner) noteBoth(pkg *Package, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	pkg.Notes = append(pkg.Notes, msg)
	pl.manual("%s: %s", pkg.File, msg)
}

func (pl *planner) planPush(pkg *Package) {
	s := pkg.Svc
	used := map[string]string{}
	for _, key := range s.PushKeys() {
		name := key
		if !validSecret(name) {
			name = slugSecret(key)
			pl.noteBoth(pkg, "push key %q became %q (secret and var names are letters, digits and '_').", key, name)
		}
		if prev, ok := used[name]; ok {
			pl.block("%s: push keys %q and %q would both become %q.", s.File, prev, key, name)
			continue
		}
		used[name] = key
		pkg.keyNames[key] = name
		exprs := s.Push[key]
		isSecret := false
		for _, e := range exprs {
			if e.HasCommand() {
				isSecret = true
			}
		}
		pkg.isSecret[key] = isSecret
		if isSecret {
			pl.planSecret(pkg, key, name, exprs)
		} else {
			pl.planVar(pkg, key, name, exprs)
		}
	}
}

func (pl *planner) planSecret(pkg *Package, key, name string, exprs []legacy.Expr) {
	s := pkg.Svc
	pkg.Secrets[name] = true
	var unset []string
	for _, e := range pl.envs {
		vals := pl.in.Values[e.Old]
		if v, ok := vals.Get(s.Name, key); ok {
			if v == "" {
				pl.noteBoth(pkg, "secret %s is empty in %s; carbon 1.0 refuses empty values, so it was not copied.", name, e.New)
				unset = append(unset, e.New)
				continue
			}
			pl.p.Copies = append(pl.p.Copies, Copy{Package: pkg.Name, Env: e.New, Name: name,
				Source: fmt.Sprintf("registry %s, %s.%s", e.Reg.Label(), s.Name, key), value: v})
			pl.markValue(pkg.Name, name, e.New)
			continue
		}
		sel, err := legacy.Select(exprs, e.Old)
		if err == nil && sel.Value != nil {
			v := pushTemplate(*sel.Value, e.Old)
			if v != "" {
				pl.p.Copies = append(pl.p.Copies, Copy{Package: pkg.Name, Env: e.New, Name: name,
					Source: fmt.Sprintf("carbon.toml static value for registry %s (never pushed there)", e.Reg.Label()), value: v})
				pl.markValue(pkg.Name, name, e.New)
				continue
			}
		}
		unset = append(unset, e.New)
	}
	if len(unset) > 0 {
		pl.noteBoth(pkg, "secret %s was never pushed in %s, so it has no value there; set one with `carbon set %s --env <env> --package %s`.", name, strings.Join(unset, ", "), name, pkg.Name)
	}
}

func (pl *planner) planVar(pkg *Package, key, name string, exprs []legacy.Expr) {
	s := pkg.Svc
	byEnv := map[string]string{}
	for _, e := range pl.envs {
		sel, err := legacy.Select(exprs, e.Old)
		if err != nil {
			pl.noteBoth(pkg, "push %s has no value in %s: %v.", key, e.New, err)
			continue
		}
		if sel.Value == nil {
			pl.noteBoth(pkg, "push %s in %s has neither value nor command; nothing to migrate.", key, e.New)
			continue
		}
		v := pushTemplate(*sel.Value, e.Old)
		if strings.Contains(*sel.Value, "{{carbon.registry}}") && e.Old != e.New {
			pl.noteBoth(pkg, "var %s used {{carbon.registry}}, which was %q for registry %s; the migrated value keeps %q, not the new name %q.", name, e.Old, e.Reg.Label(), e.Old, e.New)
		}
		if strings.Contains(v, "{{env.") {
			pl.noteBoth(pkg, "var %s contains {{env.…}}, which 0.0.3 push never resolved; it is kept literally.", name)
		}
		if reg, ok := pl.in.Values[e.Old].Get(s.Name, key); ok && reg != v {
			pl.noteBoth(pkg, "var %s in %s differs from the value in registry %s; the var uses carbon.toml (what the next 0.0.3 push would have written). Check consumers before merging.", name, e.New, e.Reg.Label())
		}
		byEnv[e.New] = v
		pl.markValue(pkg.Name, name, e.New)
	}
	if len(byEnv) == 0 {
		return
	}
	// Collapse to `default` when every environment has the same value.
	if len(byEnv) == len(pl.envs) {
		first, same := "", true
		i := 0
		for _, v := range byEnv {
			if i == 0 {
				first = v
			} else if v != first {
				same = false
			}
			i++
		}
		if same {
			byEnv = map[string]string{"default": first}
		}
	}
	pkg.Vars[name] = byEnv
}

// ref returns the [env] reference to a 0.0.3 pull target from pkg.
func (pl *planner) ref(from *Package, service, key string) (string, *Package, string, error) {
	target, ok := pl.pkgs[service]
	if !ok {
		return "", nil, "", fmt.Errorf("service %q has no carbon.toml", service)
	}
	name, ok := target.keyNames[key]
	if !ok {
		return "", nil, "", fmt.Errorf("service %q does not push %q", service, key)
	}
	if target == from {
		return "${" + name + "}", target, name, nil
	}
	return "${" + target.Name + "." + name + "}", target, name, nil
}

func (pl *planner) envKey(pkg *Package, what, k string) string {
	if validSecret(k) {
		return k
	}
	n := slugSecret(k)
	pl.noteBoth(pkg, "%s %q became [env] key %q (process variable names are letters, digits and '_'); the program now sees %s.", what, k, n, n)
	return n
}

func (pl *planner) planPulls(pkg *Package) {
	s := pkg.Svc
	for _, local := range s.PullKeys() {
		pull := s.Pull[local]
		if pull.Service == "" {
			pl.noteBoth(pkg, "pull %s names no service; 0.0.3 ignored it in check and failed in pull. Not migrated.", local)
			continue
		}
		ref, target, tname, err := pl.ref(pkg, pull.Service, pull.Name)
		if err != nil {
			if pull.Default != nil {
				pl.noteBoth(pkg, "pull %s: %v, so 0.0.3 always used its default. 1.0 has no defaults: declare a secret or var for it and reference that in [env].", local, err)
			} else {
				pl.noteBoth(pkg, "pull %s: %v (0.0.3 `check` reports this too). Not migrated.", local, err)
			}
			continue
		}
		key := pl.envKey(pkg, "pull", local)
		pkg.Env[key] = ref
		if pull.Default == nil {
			continue
		}
		var missing []string
		for _, e := range pl.envs {
			if !pl.hasValue[target.Name][tname][e.New] && !hasDefaultVar(target, tname) {
				missing = append(missing, e.New)
			}
		}
		where := "it has a value in every environment, so the default only mattered for new environments"
		if len(missing) > 0 {
			where = "it has no value in " + strings.Join(missing, ", ")
		}
		switch {
		case pull.Default.HasCommand():
			pl.noteBoth(pkg, "pull %s had a default command (%s); 1.0 runs no commands. Choose: add generate = \"random:32\" to the declaration of %s in %s and run `carbon set %s --generate --env <env> --package %s`, or set it once with `carbon set`. Today %s.",
				local, *pull.Default.Command, tname, target.File, tname, target.Name, where)
		case pull.Default.Value != nil:
			pl.noteBoth(pkg, "pull %s had a default value; 1.0 has no defaults. Today %s.", local, where)
		}
	}
}

func hasDefaultVar(p *Package, name string) bool {
	_, ok := p.Vars[name]["default"]
	return ok
}

// convertTemplate rewrites a 0.0.3 derive value as a 1.0 [env] template.
func (pl *planner) convertTemplate(pkg *Package, derive, v string, envs []Env) string {
	var b strings.Builder
	for len(v) > 0 {
		i := strings.Index(v, "{{")
		if i < 0 {
			b.WriteString(strings.ReplaceAll(v, "$", "$$"))
			break
		}
		b.WriteString(strings.ReplaceAll(v[:i], "$", "$$"))
		v = v[i:]
		j := strings.Index(v, "}}")
		if j < 0 {
			b.WriteString(strings.ReplaceAll(v, "$", "$$"))
			break
		}
		token, inner := v[:j+2], v[2:j]
		v = v[j+2:]
		switch {
		case strings.HasPrefix(inner, "pull."):
			local := strings.TrimPrefix(inner, "pull.")
			pull, ok := pkg.Svc.Pull[local]
			if !ok || pull.Service == "" {
				pl.noteBoth(pkg, "derive %s references %s but there is no such pull; kept literally (0.0.3 left it verbatim too).", derive, token)
				b.WriteString(strings.ReplaceAll(token, "$", "$$"))
				continue
			}
			ref, _, _, err := pl.ref(pkg, pull.Service, pull.Name)
			if err != nil {
				pl.noteBoth(pkg, "derive %s references %s, whose pull did not migrate (%v); kept literally.", derive, token, err)
				b.WriteString(strings.ReplaceAll(token, "$", "$$"))
				continue
			}
			b.WriteString(ref)
		case strings.HasPrefix(inner, "env."):
			name := strings.TrimPrefix(inner, "env.")
			if !validSecret(name) {
				pl.noteBoth(pkg, "derive %s references %s, which 1.0 cannot express as ${env:…}; kept literally.", derive, token)
				b.WriteString(strings.ReplaceAll(token, "$", "$$"))
				continue
			}
			b.WriteString("${env:" + name + "}")
		case inner == "carbon.registry":
			b.WriteString("${carbon.env}")
			for _, e := range envs {
				if e.Old != e.New {
					pl.noteBoth(pkg, "derive %s used {{carbon.registry}}, which was %q in registry %s and is now %q (${carbon.env}).", derive, e.Old, e.Reg.Label(), e.New)
				}
			}
		default:
			b.WriteString(strings.ReplaceAll(token, "$", "$$"))
		}
	}
	return b.String()
}

func (pl *planner) planDerives(pkg *Package) {
	s := pkg.Svc
	for _, d := range s.DeriveKeys() {
		exprs := s.Derive[d]
		key := pl.envKey(pkg, "derive", d)
		if _, ok := s.Pull[d]; ok {
			pl.noteBoth(pkg, "%s is both a pull and a derive; 0.0.3 let the derive win, and so does the migration.", d)
		}
		chosen := map[int][]Env{}
		var failed []string
		for _, e := range pl.envs {
			i, err := legacy.SelectIndex(exprs, e.Old)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s (%v)", e.New, err))
				continue
			}
			chosen[i] = append(chosen[i], e)
		}
		if len(failed) > 0 {
			pl.noteBoth(pkg, "derive %s fails in 0.0.3 for %s.", d, strings.Join(failed, "; "))
		}
		if len(chosen) == 0 {
			continue
		}
		for i := range chosen {
			if exprs[i].Value == nil {
				pl.noteBoth(pkg, "derive %s has a variant with no value (0.0.3 derives ignore commands); not migrated.", d)
				delete(chosen, i)
			}
		}
		if len(chosen) == 0 {
			continue
		}
		if len(chosen) == 1 {
			for i, envs := range chosen {
				pkg.Env[key] = pl.convertTemplate(pkg, d, *exprs[i].Value, envs)
			}
			continue
		}
		// Different variants per environment. [env] is one template for
		// every environment, but [vars] is per environment, so variants
		// that are plain text become a var.
		literal := true
		for i := range chosen {
			if strings.Contains(*exprs[i].Value, "{{") {
				literal = false
			}
		}
		if literal {
			varName := key
			for n := 2; pkg.Secrets[varName] || pkg.Vars[varName] != nil || pkg.keyNamesHas(varName); n++ {
				varName = fmt.Sprintf("%s_%d", key, n)
			}
			byEnv := map[string]string{}
			for i, envs := range chosen {
				for _, e := range envs {
					byEnv[e.New] = *exprs[i].Value
				}
			}
			pkg.Vars[varName] = byEnv
			pkg.Env[key] = "${" + varName + "}"
			continue
		}
		// Not expressible: keep the default environment's variant.
		var keep int = -1
		var others []string
		for i, envs := range chosen {
			for _, e := range envs {
				if e.New == pl.p.DefaultEnv {
					keep = i
				}
			}
		}
		if keep < 0 {
			for i := range chosen {
				if keep < 0 || i < keep {
					keep = i
				}
			}
		}
		for i, envs := range chosen {
			if i == keep {
				continue
			}
			var names []string
			for _, e := range envs {
				names = append(names, e.New)
			}
			others = append(others, fmt.Sprintf("%s: %q", strings.Join(names, ","), *exprs[i].Value))
		}
		sort.Strings(others)
		pkg.Env[key] = pl.convertTemplate(pkg, d, *exprs[keep].Value, chosen[keep])
		pl.noteBoth(pkg, "derive %s differs per registry and uses templates, which 1.0 [env] cannot vary by environment. It was migrated with the %s variant; the others were %s. Split it into a var per environment, or use ${env:…}.",
			d, pl.envNames(chosen[keep]), strings.Join(others, "; "))
	}
}

func (pkg *Package) keyNamesHas(n string) bool {
	for _, v := range pkg.keyNames {
		if v == n {
			return true
		}
	}
	return false
}

func (pl *planner) envNames(envs []Env) string {
	var n []string
	for _, e := range envs {
		n = append(n, e.New)
	}
	return strings.Join(n, ", ")
}

func (pl *planner) planServiceNotes(pkg *Package) {
	s := pkg.Svc
	if s.HasRegistry {
		pl.noteBoth(pkg, "[registry] (current/use) was dropped: 1.0 picks the environment per worktree with `carbon env use <env>`, CARBON_ENV or --env.")
	}
	out := path.Join(s.Dir, s.OutFile)
	if pl.in.Existing != nil && pl.in.Existing(out) {
		pl.noteBoth(pkg, "%s is a plaintext file written by 0.0.3 `pull`. 1.0 `carbon run` needs no file; delete it (`carbon export` writes one when a tool needs it).", out)
	} else if s.HasFile {
		pl.noteBoth(pkg, "file = %q was dropped: 1.0 injects variables with `carbon run`, or writes a file with `carbon export`.", s.OutFile)
	}
	// expect_unused needs nothing: unreferenced secrets are legal in 1.0.
}

// planOrphans lists registry values that no carbon.toml pushes any more.
func (pl *planner) planOrphans() {
	for _, e := range pl.envs {
		vals := pl.in.Values[e.Old]
		for _, svc := range sortedKeys(vals) {
			pkg := pl.pkgs[svc]
			for _, key := range sortedKeys(vals[svc]) {
				if pkg != nil {
					if _, ok := pkg.keyNames[key]; ok {
						continue
					}
				}
				pl.manual("registry %s holds %s.%s, which no carbon.toml pushes; it was NOT migrated and is deleted with the registry. If it is still needed, declare it and `carbon set` it before merging (`git show HEAD:%s` keeps the old encrypted file).", e.Reg.Label(), svc, key, e.Reg.RegistryFile)
			}
		}
	}
}

func (pl *planner) planTrunk() {
	pl.p.Trunk = pl.in.Trunk
	if pl.in.TrunkRootLegacy && pl.in.Trunk != "worktree" {
		pl.block("trunk %s has a carbon 0.0.3 carbon.toml at the root, and carbon 1.0 reads policy from trunk's root carbon.toml, so `carbon set` would stop on it. Re-run with --trunk worktree (policy is then read from the working tree), and set trunk back to %q once this branch has merged.", pl.in.Trunk, pl.in.Trunk)
	}
}

func (pl *planner) planIdentity() {
	in, p := pl.in, pl.p
	p.KeyFile, p.MoveKey, p.IdentityPath = in.KeyFile, in.MoveKey, in.IdentityPath
	switch {
	case !in.IdentityExists:
		p.IdentityAction = "install"
	case in.IdentityExisting == in.Me && in.Me != "":
		p.IdentityAction = "already-installed"
	default:
		p.IdentityAction = "conflict"
		pl.block("a carbon 1.0 identity already exists at %s and it is a different key from your 0.0.3 key. carbon-migrate never overwrites an identity. Either move it aside (if nothing else uses it), or run with CARBON_IDENTITY_FILE=<another path> and point carbon at that path afterwards, or migrate as a teammate who has no 1.0 identity yet.", in.IdentityPath)
	}
}

// planFiles renders every file.
func (pl *planner) planFiles() {
	in, p := pl.in, pl.p
	var root *Package
	for _, pkg := range p.Packages {
		if pkg.File == "carbon.toml" {
			root = pkg
		}
	}
	ws := renderWorkspace(p)
	if root != nil {
		p.Files = append(p.Files, FileChange{Path: "carbon.toml", Action: "rewrite",
			What: "workspace and package " + root.Name, Content: renderPackage(root, ws)})
	} else {
		action := "create"
		if in.Existing != nil && in.Existing("carbon.toml") {
			action = "rewrite"
		}
		p.Files = append(p.Files, FileChange{Path: "carbon.toml", Action: action, What: "workspace", Content: []byte(ws)})
	}
	for _, per := range p.People {
		path := ".carbon/people/" + per.ID + ".toml"
		p.Files = append(p.Files, FileChange{Path: path, Action: "create", What: "person " + per.ID, Content: renderPerson(per)})
	}
	for _, pkg := range p.Packages {
		if pkg == root {
			continue
		}
		p.Files = append(p.Files, FileChange{Path: pkg.File, Action: "rewrite", What: "package " + pkg.Name, Content: renderPackage(pkg, "")})
	}
	if !strings.Contains(string(in.GitAttributes), GitAttributesLine) {
		content := string(in.GitAttributes)
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += GitAttributesLine + "\n"
		action := "append"
		if in.GitAttributes == nil {
			action = "create"
		}
		p.Files = append(p.Files, FileChange{Path: ".gitattributes", Action: action, What: "mark keys files generated", Content: []byte(content)})
	}
	for _, f := range p.Files {
		if strings.HasSuffix(f.Path, ".toml") {
			var m map[string]any
			if err := toml.Unmarshal(f.Content, &m); err != nil {
				pl.block("internal error: generated %s is not valid TOML: %v", f.Path, err)
			}
		}
	}
}

func renderWorkspace(p *Plan) string {
	var b strings.Builder
	b.WriteString("[workspace]\nformat = 1\n")
	var envs []string
	for _, e := range p.Envs {
		envs = append(envs, quote(e.New))
	}
	fmt.Fprintf(&b, "environments = [%s]\n", strings.Join(envs, ", "))
	fmt.Fprintf(&b, "default_environment = %s\n", quote(p.DefaultEnv))
	fmt.Fprintf(&b, "trunk = %s\n\n[access]\n", quote(p.Trunk))
	for _, e := range p.Envs {
		var readers []string
		for _, per := range p.People {
			for _, r := range per.Reads {
				if r == e.New {
					readers = append(readers, quote(per.ID))
				}
			}
		}
		fmt.Fprintf(&b, "%s = [%s]\n", tomlKey(e.New), strings.Join(readers, ", "))
	}
	return b.String()
}

func renderPerson(per *Person) []byte {
	var b strings.Builder
	if per.Name != "" {
		fmt.Fprintf(&b, "name = %s\n\n", quote(per.Name))
	}
	b.WriteString("[devices]\n")
	for _, d := range sortedKeys(per.Devices) {
		fmt.Fprintf(&b, "%s = %s\n", tomlKey(d), quote(per.Devices[d]))
	}
	return []byte(b.String())
}

func renderPackage(pkg *Package, workspace string) []byte {
	var b strings.Builder
	b.WriteString("# Migrated from carbon 0.0.3 by carbon-migrate.\n")
	for _, n := range pkg.Notes {
		b.WriteString(comment("carbon-migrate: ", n))
	}
	fmt.Fprintf(&b, "name = %s\n", quote(pkg.Name))
	if workspace != "" {
		b.WriteString("\n")
		b.WriteString(workspace)
	}
	if len(pkg.Secrets) > 0 {
		b.WriteString("\n[secrets]\n")
		for _, s := range sortedKeys(pkg.Secrets) {
			fmt.Fprintf(&b, "%s = {}\n", tomlKey(s))
		}
	}
	for _, v := range sortedKeys(pkg.Vars) {
		fmt.Fprintf(&b, "\n[vars.%s]\n", tomlKey(v))
		for _, e := range sortedKeys(pkg.Vars[v]) {
			fmt.Fprintf(&b, "%s = %s\n", tomlKey(e), quote(pkg.Vars[v][e]))
		}
	}
	if len(pkg.Env) > 0 {
		b.WriteString("\n[env]\n")
		for _, k := range sortedKeys(pkg.Env) {
			fmt.Fprintf(&b, "%s = %s\n", tomlKey(k), quote(pkg.Env[k]))
		}
	}
	return []byte(b.String())
}

func short(key string) string {
	if len(key) > 16 {
		return key[:12] + "…" + key[len(key)-4:]
	}
	return key
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
