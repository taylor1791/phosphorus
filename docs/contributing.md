# Contributing to carbon

Read `docs/design.md` (what and why), `docs/implementation.md` (the contract),
`docs/deviations.md` (where the code differs), and `docs/format.md`.

## Toolchain

```sh
nix shell nixpkgs#go nixpkgs#git -c go vet ./...
nix shell nixpkgs#go nixpkgs#git -c go test ./...
```

Both must pass before a hand-off. Tests that build binaries (`carbon` in
`internal/clitest`, `age` in the interop tests) set `CGO_ENABLED=0`
themselves. To build carbon by hand: `CGO_ENABLED=0 go build ./cmd/carbon`.

## Packages

| Package | Use it for |
|---|---|
| `internal/scope` | Everything about a scope's keys and values: `Load`, `Create`, `Open`, `Reveal`/`RevealAll`, `Seal`, `Drop`, `AddSlots`, `DiffSlots`, `Rotate`/`RotateSkippingBadDrops`, `Promote(At)`/`PromoteDrops(At)`, `Refresh`/`RefreshDetailed`, `StaleEntries`, `VerifyTrunk`, `TrunkInbox`, `ReadKeysAt`, `List` |
| `internal/policy` | Who reads a scope: `LoadTrunk`/`LoadTrunkWith` (apply, drops, scope creation, check's slot rules; `Policy.Trunk` says which ref and from where, see `ResolveTrunk`), `LoadWorktree` (who, access, status, run), `Policy.Scope` (devices, `Why`, `Unresolved`, `RequirePQ`, `Drops`, `Eligible`), `Scopes`, `ScopesOf`, `Identify`, `TeamsOf` |
| `internal/config` | Parsing people-written files, names, `ParseTemplate`, `ParseDuration`, `ParseGenerate`, `Quote`, writers for people/machines/teams |
| `internal/store` | Parsing and writing secrets/keys files (rarely needed directly; `scope` wraps it) |
| `internal/agewrap` | age: recipients, identities, slots, drops, `StanzaTypes` (for `check`), `Fingerprint` |
| `internal/seal` | Sealed blobs and associated data (only `scope` should call it) |
| `internal/gitx` | git plumbing: `Repo.Source(ref)`, `RefExists`, `IsIgnored`, `Commit`, `GitDir`, `ConfigGet`; `ScrubbedEnviron` for any subprocess (the child of `run`) |

`apply` is orchestration over these: for each scope, `policy.LoadTrunk` →
`Policy.Scope` → `Scope.Open` → `Opened.VerifyTrunk(trunk keys)` →
`Scope.DiffSlots`; if `Extra` is non-empty, `Opened.RotateSkippingBadDrops`
with `reason = "removed <who>"`; else `Opened.AddSlots(Missing)`; then
`PromoteDropsAt(now)`; show `Scope.StaleEntries()` in the plan (values under
retired keys have an unproven author) before `RefreshDetailed`; report skipped
drops; `Scope.Save`; `Repo.Commit` with exactly the written paths.

## Adding a command

Create `internal/cli/<command>.go`. Do not edit a shared list.

```go
package cli

import "flag"

func init() {
	Register(&Command{
		Name:    "who",              // or "env use" for a subcommand
		Usage:   "<package> [--env <env>]",
		Summary: "Explain who reads a package, and through which rule",
		Help:    "Longer text for `carbon help who`.",
		MinArgs: 1, MaxArgs: 1,      // the zero value accepts no positionals; MaxArgs -1 = unlimited
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("all", false, "every environment")
		},
		Run: runWho,
	})
}

func runWho(c *Context) error {
	w, err := c.Workspace()        // finds the repo root carbon.toml; 0.0.3 and conflict checks included
	if err != nil {
		return err                 // internal errors are mapped to exit codes by AsError
	}
	env, err := c.Environment(w)   // --env, CARBON_ENV, `carbon env use`, default_environment
	...
	all := c.Bool("all")           // c.String, c.List, c.Changed for other flags
	return c.Output(result, func(out io.Writer) { Table(out, rows) })
}
```

Global flags (`--env`, `--package`, `--json`, `--yes`, `-C`, `--no-color`) are
parsed for you, before or after the command and between positionals, and are
in `c.Global`. Positionals are `c.Args`; `c.ArgsLenAtDash` says where `--`
was (for `run`).

### Helpers on `*Context`

| Helper | What it does |
|---|---|
| `Workspace()` | The workspace (`Root`, `Repo`, `Config`, `Packages()`, `Dir(pkg)`, `Rel(path)`) |
| `Package(w)` | `--package`, else the nearest named `carbon.toml` (exit 5 if none) |
| `Environment(w)` | Resolved and validated environment (exit 2 if unknown) |
| `TrunkPolicy(w)` / `WorktreePolicy(w)` | Policy per the trunk rules; prints the bootstrap notice |
| `TrunkKeys(w, pol, pkg, env)` | A scope's keys file at trunk (or the working tree under the exceptions) |
| `Identities(required)` | The caller's identities (`CARBON_IDENTITY`, `CARBON_IDENTITY_FILE`, XDG path; exit 6) |
| `LoadScope(w, pkg, env)` / `OpenScope(w, pkg, s)` | Load a scope; open it, turning "not a reader" into the design's exit-3 error, then `VerifyTrunk` |
| `VerifyTrunk(w, pkg, opened)` | Check an opened scope against trunk's keys file; call it on every path that opens a scope without `OpenScope` |
| `NoAccessErr(pol, pkg, env, me, slots)` | The "you cannot read X in Y" error with readers and the next command |
| `Me(pol, ids)`, `DeviceIDs(ds)` | Which devices the caller's identities are |
| `Confirm(question)` | y/N on the terminal; `--yes` skips; no terminal → exit 7. Print the plan first |
| `ReadSecret(prompt)` | Hidden prompt on a terminal, else stdin minus one trailing newline |
| `ReadPassphrase(prompt, confirm)` | Hidden passphrase prompt (stdin line without a terminal) |
| `Output(v, human)`, `WriteJSON(v)`, `Printf`, `Notice`, `Table` | stdout is human text or one JSON document; diagnostics go to stderr via `Notice` |
| `EnvUseFile(repo)`, `ReadEnvUse(repo)` | Where `carbon env use` stores the worktree environment |

### Errors

Return `*Error` to choose the exit code and text: what happened (`Message`),
why (`Details`), the next command (`Hint`).

```go
return Errorf(ExitNotFound, "no package named %q", name).
	WithDetail("Packages are carbon.toml files with a name.").
	WithHint("To create one:   carbon init --name %s", name)
```

Exit codes: `ExitOK` 0, `ExitError` 1, `ExitUsage` 2, `ExitNoAccess` 3,
`ExitCheckFailed` 4, `ExitNotFound` 5, `ExitNoIdentity` 6, `ExitNotConfirmed`
7. Never put a secret value in an error, a log line, or a process argument.
Zero value buffers with `clear` (and `Value.Zero`, `Opened.Close`) when done.

## Writing a CLI test

CLI tests drive the built binary through `internal/clitest`, in a temporary
git repository, with a temporary `HOME`/`XDG_CONFIG_HOME` per person.

```go
package cli_test   // TestMain(m) { clitest.Main(m) } is in commands_test.go

func TestWho(t *testing.T) {
	w := clitest.Standard(t) // ada, lin, sam, machine:deploy-checkout, package checkout; committed to main
	co := w.PkgDir           // "services/checkout"

	w.Lin.In(co).Stdin("sk_1").Must("set", "stripe_api_key", "--env", "prod")
	w.Commit("key")                      // trunk is "main" (git config carbon.trunk); Branch, Checkout, Merge, Git also exist

	res := w.Ada.In(co).Fails(3, "get", "stripe_api_key", "--env", "prod")
	if !strings.Contains(res.Stderr, "carbon request checkout --env prod") { t.Fatal(res) }

	got := w.Deploy.Must("get", "stripe_api_key", "--package", "checkout", "--env", "prod").Stdout
	_ = got
}
```

- `clitest.NewRepo(t)` is an empty repo with no remote and no `carbon.trunk`:
  the bootstrap case. `clitest.NewWorkspace(t)` adds `carbon init`,
  uncommitted. `clitest.Standard(t)` commits to `main` and runs
  `git config carbon.trunk main` (trunk mode). `r.SetTrunk(ref)` sets it;
  `p.With("CARBON_TRUNK=...")` overrides it for one run.
- `r.Person("ada").Join()` joins as `ada/laptop`; `r.Machine("name")` returns a
  runner carrying the private key in `CARBON_IDENTITY`; `r.Anyone()` has no
  identity.
- `p.Run`, `p.Must`, `p.Fails(code, ...)`; chain `p.In(dir)`, `.Stdin(s)`,
  `.With("K=V")`. A `*Result` has `Stdout`, `Stderr`, `Code`, and prints the
  whole run when a check fails.
- `r.Write`, `r.Read`, `r.Replace`, `r.SetTeams`, `r.AddPackage`, `r.Commit`.

Values must go in on stdin, never as arguments.
