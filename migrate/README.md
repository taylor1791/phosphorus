# carbon-migrate

`carbon-migrate` moves a repository from carbon 0.0.3 (the nushell script over
sops and rage) to Carbon 1.0, in place, on one branch. It is a separate tool so
that the `carbon` binary carries no sops or 0.0.3 knowledge.

It talks to Carbon 1.0 only through its public command line (`carbon set` and
`carbon get`) and to 0.0.3 only through its files and `sops`. It never runs a
`command` from a 0.0.3 `carbon.toml`.

## Running it

You need:

- the Carbon 1.0 `carbon` binary (on `PATH`, or `--carbon <path>`);
- `sops` (on `PATH`, or `--sops <path>`);
- `git`, and a clean working tree;
- the 0.0.3 key `.carbon/private-key.age`, and that key must be able to
  decrypt every registry. Run it as someone who reads them all.

Run it on a branch off trunk, first without `--write` (a dry run that prints
the full plan, including every new file, and changes nothing), then with
`--write`. It does not commit; review the result and commit it yourself. The
tests exercise exactly this flow: a 0.0.3 repository on `origin/main`, a
branch, a dry run, `--write`.

Build it with `CGO_ENABLED=0 go build ./cmd/carbon-migrate` from this
directory.

| Flag | Meaning |
| --- | --- |
| `--write` | Perform the migration. Without it nothing is changed. |
| `--default-env <name>` | Environment name for the unnamed default registry (default `dev`). |
| `--env-name old=new` | Rename a registry on the way (repeatable), e.g. `--env-name prd=prod`. |
| `--package-name old=new` | Rename a service (repeatable). Needed for names 1.0 rejects or reserves (`carbon`, `env`). |
| `--keep-recipient <name-or-key>` | Carry over the access of a key that is a pending 0.0.3 removal (see below). Repeatable. |
| `--trunk <ref>` | Set `CARBON_TRUNK=<ref>` for the `carbon` commands this run makes, and nothing else; no file or git config is written. Default: carbon's own choice. |
| `--key <file>` | Use a 0.0.3 key from elsewhere. It is copied to the 1.0 identity path; only the repository's own `.carbon/private-key.age` is ever removed. |
| `--force` | Run on a dirty working tree. Rollback by git is then no longer exact. |
| `--show-files` | Also print the new files' contents during `--write` (a dry run always does). |
| `-C <dir>` | Run as if started in `<dir>`. |

Exit codes: 0 done (or dry run printed), 1 failed part-way (the rollback
commands are printed), 2 usage, 3 blocked (the plan lists what to fix; nothing
was changed).

## What it does

1. **Reads** every 0.0.3 `carbon.toml` (tracked or untracked, not ignored),
   every `.carbon/sops*.yaml`, and decrypts every `.carbon/registry*.yaml` with
   `sops` and your 0.0.3 key. Plaintext stays in memory and goes to `carbon`
   over stdin; it is never printed, logged, put in an argument, or written to
   disk. A `carbon.toml` that already has Carbon 1.0 keys (`[workspace]`,
   `[secrets]`, `[vars]`, `[env]`, `[access]`) is never rewritten: the run is
   blocked and the file named.
2. **Writes** the 1.0 policy files:
   - `carbon.toml` at the root: `[workspace]` with one environment per
     registry, and `[access]` naming, per environment, exactly the people
     whose keys could read that registry (below). If the root was itself a
     0.0.3 service, the workspace and that package share the file. No `trunk`
     is written: carbon chooses trunk from `CARBON_TRUNK`, then
     `git config carbon.trunk`, then the remote default branch.
   - `.carbon/people/<person>.toml` for the keys in the old setup (below).
     Keys move over unchanged.
   - each service's `carbon.toml`, rewritten as a 1.0 package (table below),
     with a `# carbon-migrate:` comment for each item that needs a decision.
   - the `.gitattributes` line `carbon init` adds for keys files.
3. **Copies** every secret value with `carbon set <name> --env <env> --package
   <pkg>`, the value on stdin (`--allow-empty` for an empty value). The first
   set in each scope creates its key, wrapped to every reader's device. On the
   cutover branch trunk still holds the 0.0.3 files, which carbon treats as
   "not adopted on trunk yet": it reads the policy just written in the working
   tree and prints a notice saying so. Carbon 1.0 lets only a device that
   policy names as a reader create a scope's first key, so you must be a
   reader of every environment that gets values; the plan blocks, naming the
   registry, when you are not.
4. **Moves** `.carbon/private-key.age` to the 1.0 identity path
   (`$CARBON_IDENTITY_FILE`, else `$XDG_CONFIG_HOME/carbon/identity`, else
   `~/.config/carbon/identity`), mode 0600, unchanged. It never overwrites an
   identity: if a different key is already there it stops before changing
   anything. If that path is the 0.0.3 key file itself (or a link to it), or
   lies inside the repository, it also stops before changing anything: the
   1.0 identity must live outside the repository.
5. **Verifies**: runs `carbon get` for every copied secret, using the moved
   identity, and compares it byte for byte with the value from the old
   registry. It reports counts only.
6. **Deletes** the old registries and sops configs, and then the old key —
   only after every value was written and read back identical.

It prints every item that needs a manual choice, before and after.

### Who reads what

Access is decided per key, from the registries alone. A key reads an
environment when that registry is encrypted to it (a sops recipient) **and**
it is still in the registry's sops creation rule. The final plan is checked
against this: if any device would read an environment whose registry was not
encrypted to it, the run is blocked.

- Keys recorded under one `users` name become devices of one person only when
  they read exactly the same environments. Otherwise each access set becomes
  its own person (`alice`, `alice-2`, ...). Every merge and split is listed.
- A key in the creation rule that the registry is not encrypted to (access
  requested, never granted with `carbon rekey`) gets a person file and no
  access.
- A key the registry is still encrypted to but that was removed from the
  creation rule is a **pending removal** (someone edited `sops.yaml` and never
  ran `carbon rekey`). It gets no access. Either run 0.0.3 `carbon rekey` first
  to complete the removal, or pass `--keep-recipient <name-or-key>` to carry
  its access over.
- A recipient no `users` entry names becomes `unknown-N` with exactly the
  access it had. Find out whose key it is before merging.

### Mapping

| 0.0.3 | 1.0 |
| --- | --- |
| Registry `""` (default) | Environment `dev`, or `--default-env` |
| Registry `prd` | Environment `prd`, or `--env-name prd=<name>` |
| `users` and recipients in `sops*.yaml` | `.carbon/people/*.toml` and `[access]`, as above |
| Service `name` | Package `name` |
| `[push.x]` static `value`, or `registry_pattern` variants of values | `[vars.x]`, one entry per environment (`default` when all are equal) |
| `[push.x]` with a `command` (in any variant) | `[secrets] x = {}`, value copied from each registry |
| `[pull.x] service = "db", name = "y"` | `[env] x = "${db.y}"` (`"${y}"` when a service pulls from itself) |
| `[derive.X] value = "…{{pull.x}}…{{env.H}}…{{carbon.registry}}"` | `[env] X = "…${db.y}…${env:H}…${carbon.env}"` |
| `[derive.X]` variants that are plain text | `[vars.X]` per environment and `[env] X = "${X}"` |
| `expect_unused` | Dropped; unreferenced secrets are legal |
| `[registry]`, `file` | Dropped (listed) |

How patterns are evaluated: for each environment, `registry_pattern` is
matched (an unanchored regular expression) against the **old** registry name —
the empty string for the default registry — exactly as 0.0.3's
`find_expression` does: exactly one matching pattern wins; with none, the single
variant without a pattern; two matching patterns, or two without a pattern, is
an error in 0.0.3, so that environment gets no value and the item is listed.
`{{carbon.registry}}` in a static push value is likewise expanded with the old
name, so the var holds what 0.0.3 published (listed when the name changed).

A `{{pull.x}}` in a derive becomes the pull's own reference (`${db.y}`), not
`${x}`: in 1.0 `${x}` means this package's secret or var, and `[env]` entries
cannot reference each other. Two pull or derive names that would become the
same `[env]` key block the run, as two push keys that become one name do.

## Manual choices it lists

- **Pull defaults.** A `default` with a `command` has no 1.0 equivalent:
  choose `generate = "random:<n>"` on the provider's declaration (then
  `carbon set <name> --generate`) or a one-time `carbon set`. It says in which
  environments the provider has no value today. A `default` with a `value` is
  dropped the same way.
- **Derives that vary per registry and use templates.** `[env]` is one
  template for every environment, so the default environment's variant is
  kept and the others are shown.
- **Secrets never pushed in some registry**: declared, but unset there.
- **Registry entries no `carbon.toml` pushes** any more: not migrated, and
  deleted with the registry (git history still has them, encrypted).
- **People**: merges, splits, pending removals, never-granted requests and
  unnamed keys (above).
- **Renames**: service, push key, and pull/derive names that 1.0's name rules
  reject are rewritten (`api-token` → `api_token`). A process variable name
  that changes is something the program must be told about.
- **`{{carbon.registry}}`** where the registry was renamed (the default
  registry was `""` and is now `dev`).
- **`[registry]` and `file`**: dropped. In the design, 1.0 picks the
  environment with `--env`, `CARBON_ENV` or `carbon env use`, and writes files
  with `carbon export`.
- **Plaintext `.environment.json`** files left by 0.0.3 `pull`: delete them.

Blockers (nothing is changed until they are fixed): a dirty tree, a registry
your key cannot decrypt, an identity path that holds a different key, is the
0.0.3 key itself, or lies inside the repository, a `carbon.toml` with 1.0
keys, a service in a dot-directory or `node_modules`, duplicate or reserved
package names, names that collide after renaming, environment names 1.0
rejects, an environment you would not be a reader of, and a plan that would
give any key access it did not have.

## Limits

- **Rotation-debt history starts at the migration.** Every value is set anew,
  so its `set` time is the migration time; 0.0.3 kept no history of who could
  read a value before, and the migration cannot recreate it.
- **Services under dot-directories or `node_modules` are blocked.** Carbon 1.0
  does not look for packages there, so such a service must be moved (with
  `git mv`, committed) before migrating.
- **Only native X25519 age keys are handled.** A 0.0.3 key file that holds
  anything else (a plugin identity, an encrypted identity) is blocked.
- **The sops configs are read with a small parser** for the YAML nushell
  writes, not a general YAML parser.
- Teammates' keys are carried over and their access is checked by the tests
  through `carbon get` with their key file, but carbon-migrate does not move
  their keys for them (below).

## Rolling back

Before `--write` finishes, nothing old is deleted. If any step fails, it stops
and prints the exact commands that return the repository to where it was: a
`git checkout --` of the files it changed or deleted, a `git clean -f --` of
the files it created, and an `rm` of the identity it installed, if any. The
tests run those printed commands after a failure while setting values, while
verifying and while deleting, and check that the tree is clean and the
identity gone.

After a successful run it prints the same kind of commands, plus moving the
identity back to `.carbon/private-key.age`. That success path is not covered
by a test; check the printed commands before running them.

## After the migration

Once the branch merges, trunk has the 1.0 workspace, and carbon reads policy
from trunk as it documents (docs/implementation.md, "Trunk").

Each teammate's age key is already a device in `.carbon/people/<them>.toml`
with a slot in every scope they could read. Carbon looks for their identity
where docs/implementation.md ("Identities") says: `CARBON_IDENTITY`,
`CARBON_IDENTITY_FILE`, else `$XDG_CONFIG_HOME/carbon/identity` (default
`~/.config/carbon/identity`). Their 0.0.3 `.carbon/private-key.age` holds the
same key, so making that file their identity file (or pointing
`CARBON_IDENTITY_FILE` at a copy outside the repository) is all it takes;
`carbon get` and `carbon ls` then work for them.

## Tests

The exit test builds a real 0.0.3 repository with the real 0.0.3 script
(`internal/migrate/testdata/carbon-0.0.3`, a verbatim copy of carbon 0.0.3)
under nushell, sops and rage — three users, three registries, pushes, a
`rekey`, a pending request, a `pull`, an empty value, a 0.0.3 service at the
root — pushes it to a bare `origin` (so trunk is `origin/main` with the 0.0.3
files) and migrates on a branch, as a real cutover would. It reads the
expected values back with 0.0.3's own `carbon read`, migrates, and checks
that every value reads back identical through 1.0 `carbon get`, that the
policy files parse (for go-toml and for `carbon ls`), that access carried
over, and that the old files are gone.

Other fixture tests cover: the dry run, the dirty-tree gate, the identity
guards (a different key, the key file itself, a symlink to it), failures while
setting, verifying and deleting with the printed undo, `--env-name`,
`--package-name`, `--key`, a real sops decrypt failure, keys that share a
`users` name, a pending removal with and without `--keep-recipient`, awkward
values (newlines, CR, control characters, 96 KB), and the built
`carbon-migrate` binary end to end.

The 0.0.3 script needs nushell 0.116 (the version its flake pins; 0.108 cannot
parse it). From this directory:

```console
nix shell nixpkgs#go nixpkgs#git nixpkgs#sops nixpkgs#age \
  github:NixOS/nixpkgs/d4f25a3e562008648d45bcf2d70bcc7422cad84e#nushell \
  -c go test ./...
```

`rage-keygen` must also be on `PATH`. Without `sops`, `nu` or `rage-keygen`
the fixture tests skip with a message saying so, unless
`CARBON_MIGRATE_REQUIRE_FIXTURE=1` is set, in which case they fail (for CI).
The unit tests always run. The tests build `carbon` from the parent module
with `CGO_ENABLED=0`.
