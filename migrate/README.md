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

```console
$ cd my-monorepo
$ git switch -c carbon-1.0
$ carbon-migrate                 # dry run: prints the full plan, changes nothing
$ carbon-migrate --write         # performs it
$ git add -A && git commit -m "Migrate to Carbon 1.0"
```

Build it with `CGO_ENABLED=0 go build ./cmd/carbon-migrate` from this
directory.

| Flag | Meaning |
| --- | --- |
| `--write` | Perform the migration. Without it nothing is changed. |
| `--default-env <name>` | Environment name for the unnamed default registry (default `dev`). |
| `--env-name old=new` | Rename a registry on the way (repeatable), e.g. `--env-name prd=prod`. |
| `--package-name old=new` | Rename a service (repeatable). Needed for names 1.0 rejects or reserves (`carbon`, `env`). |
| `--trunk <ref>` | The workspace's `trunk` (default: origin's HEAD, else `origin/main`). |
| `--key <file>` | Use a 0.0.3 key from elsewhere. Only the repository's own `.carbon/private-key.age` is moved. |
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
   disk.
2. **Writes** the 1.0 policy files:
   - `carbon.toml` at the root: `[workspace]` with one environment per
     registry and `[access]` listing, per environment, the people the registry
     is actually encrypted to. If the root was itself a 0.0.3 service, the
     workspace and that package share the file.
   - `.carbon/people/<person>.toml` for every key in the old setup: each sops
     `users` entry, plus any recipient nobody named (as `unknown-N`). Keys move
     over unchanged as a device named `migrated`.
   - each service's `carbon.toml`, rewritten as a 1.0 package (table below),
     with a `# carbon-migrate:` comment for each item that needs a decision.
   - the `.gitattributes` line `carbon init` adds for keys files.
3. **Copies** every secret value with `carbon set <name> --env <env> --package
   <pkg>`, the value on stdin. The first set in each scope creates its key,
   wrapped to every reader's device, so access carries over without
   `carbon apply`.
4. **Moves** `.carbon/private-key.age` to the 1.0 identity path
   (`$CARBON_IDENTITY_FILE`, else `$XDG_CONFIG_HOME/carbon/identity`, else
   `~/.config/carbon/identity`), mode 0600, unchanged. It never overwrites an
   identity: if a different key is already there it stops before changing
   anything and explains your options. If the same key is there, it is left.
5. **Verifies**: runs `carbon get` for every copied secret, using the moved
   identity, and compares it byte for byte with the value from the old
   registry. It reports counts only.
6. **Deletes** the old registries and sops configs, and then the old key —
   only after every value was written and read back identical.

It prints every item that needs a manual choice, before and after.

### Mapping

| 0.0.3 | 1.0 |
| --- | --- |
| Registry `""` (default) | Environment `dev`, or `--default-env` |
| Registry `prd` | Environment `prd`, or `--env-name prd=<name>` |
| `users` and recipients in `sops*.yaml` | `.carbon/people/*.toml`; the registry's actual recipients become `[access]` readers |
| Service `name` | Package `name` |
| `[push.x]` static `value`, or `registry_pattern` variants of values | `[vars.x]`, one entry per environment (`default` when all are equal) |
| `[push.x]` with a `command` (in any variant) | `[secrets] x = {}`, value copied from each registry |
| `[pull.x] service = "db", name = "y"` | `[env] x = "${db.y}"` (`"${y}"` when a service pulls from itself) |
| `[derive.X] value = "…{{pull.x}}…{{env.H}}…{{carbon.registry}}"` | `[env] X = "…${db.y}…${env:H}…${carbon.env}"` |
| `[derive.X]` variants that are plain text | `[vars.X]` per environment and `[env] X = "${X}"` |
| `expect_unused` | Dropped; unreferenced secrets are legal |
| `[registry]`, `file` | Dropped (listed); use `carbon env use`, `carbon export` |

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
cannot reference each other.

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
  deleted with the registry (`git show HEAD:.carbon/registry*.yaml` still has
  them, encrypted).
- **Access requested but never granted** (a key in the sops creation rule that
  the registry is not encrypted to): the person file is written, but they are
  not a reader.
- **Renames**: service, push key, and pull/derive names that 1.0's name rules
  reject are rewritten (`api-token` → `api_token`). A process variable name
  that changes is something the program must be told about.
- **`{{carbon.registry}}`** where the registry was renamed (the default
  registry was `""` and is now `dev`).
- **Plaintext `.environment.json`** files left by 0.0.3 `pull`: delete them.
- Empty secret values (1.0 refuses them) and anything 0.0.3 itself rejected.

Blockers (nothing is changed until they are fixed): a dirty tree, a registry
your key cannot decrypt, a different identity already installed, a service in
a dot-directory or `node_modules` (1.0 does not look there; `git mv` it
first), duplicate or reserved package names, environment names 1.0 rejects,
and a trunk whose root `carbon.toml` is a 0.0.3 file (see below).

## Rolling back

Before `--write` finishes, nothing old is deleted. If any step fails, it stops
and prints the exact commands that return the repository to where it was, for
example:

```console
git checkout -- services/api/carbon.toml services/db/carbon.toml
git clean -f -- carbon.toml .carbon/people/alice.toml services/db/.carbon/dev.secrets.toml …
rm ~/.config/carbon/identity      # only if it installed one
```

After a successful run it prints the same kind of commands, which also bring
back the deleted registries (`git checkout`) and put the key back
(`mv ~/.config/carbon/identity .carbon/private-key.age`). Once committed,
`git revert` the migration commit and move the key back the same way.

## For teammates

The person who ran the migration is done. Everyone else, after the branch
merges, moves their own key once:

```console
mkdir -p ~/.config/carbon && mv .carbon/private-key.age ~/.config/carbon/identity
```

Their access is already in place: their key is a device in
`.carbon/people/<them>.toml` and has a slot in every scope they could read.

## Trunk with a 0.0.3 root `carbon.toml`

Carbon 1.0 reads policy from trunk's root `carbon.toml`. If trunk's root file
is a 0.0.3 service, every `carbon set` stops on it, so `carbon-migrate`
refuses. Run with `--trunk worktree`, merge, then set `trunk` back to your
real trunk ref in a follow-up change.

## Tests

The exit test builds a real 0.0.3 repository with the real 0.0.3 script
(`internal/migrate/testdata/carbon-0.0.3`, a verbatim copy of carbon 0.0.3)
under nushell, sops and rage — three users, three registries, pushes, a
`rekey`, a pending request, a `pull` — reads the expected values back with
0.0.3's own `carbon read`, migrates, and checks that every value reads back
identical through 1.0 `carbon get`, that the policy files parse (for go-toml
and for `carbon ls`), that access carried over, and that the old files are
gone. Other tests cover the dry run, the dirty-tree gate, the identity guard,
and a failure part-way followed by running the printed rollback commands.

The 0.0.3 script needs nushell 0.116 (the version its flake pins; 0.108 cannot
parse it). From this directory:

```console
nix shell nixpkgs#go nixpkgs#git nixpkgs#sops nixpkgs#age \
  github:NixOS/nixpkgs/d4f25a3e562008648d45bcf2d70bcc7422cad84e#nushell \
  -c go test ./...
```

`rage-keygen` must also be on `PATH`. Without `sops`, `nu` or `rage-keygen`
the fixture tests skip with a message saying so; the unit tests still run.
The tests build `carbon` from the parent module with `CGO_ENABLED=0`.
