# Deviations from the implementation contract

Each entry says what differs from `docs/implementation.md` and why.

## Deviations

1. **Retired keys keep `inbox_sealed`** (now written into the contract). A
   drop written on a branch cut before a rotation names the old key's inbox;
   without the old inbox identity no reader could open it after the merge.
   It reveals nothing new: anyone who could unseal it already held the old
   key. `store` accepts retired records with or without it.
2. **No `github.com/spf13/pflag`.** pflag imports `net`, and nixpkgs' Go
   defaults to `CGO_ENABLED=1` without a C compiler, so `go test ./...` failed
   to build `internal/cli`. Flags use the standard `flag` package behind a
   small wrapper (`internal/cli/flags.go`) that interleaves flags and
   positionals and honours `--`. `--name` and `-name` are both accepted.
3. **`--package` is a global flag**, accepted like `--env`. The contract names
   it only under package resolution.
4. **`go.mod` has `tool filippo.io/age/cmd/age`.** The interop tests build the
   real age CLI; the tool directive keeps its go.sum entries, which brings
   `filippo.io/edwards25519` and `filippo.io/nistec` into go.mod as indirect
   requirements. They are age's own dependencies and are not linked into
   `carbon`.
5. **Module versions are pinned to what age v1.3.2 requires**
   (`golang.org/x/crypto` v0.55.0, `x/term` v0.45.0, `x/sys` v0.47.0): newer
   x/crypto requires Go 1.26, and the contract says Go 1.25.
6. **`--json` errors** are `{"error": {"code", "message", "details", "hint"}}`:
   `code` is the numeric exit code and `details` was added for the detail
   lines.

## Decisions where the contract is silent or ambiguous

1. **Plugin recipients run a program.** The contract accepts plugin recipients
   through `filippo.io/age/plugin`, which runs `age-plugin-<name>` from PATH;
   the brief also says git is the only external program. Plugins are
   supported as the contract says, and are only ever run when a plugin
   recipient or identity is used. `scope.Open` never asks a plugin identity to
   try slots other than the caller's own.
2. **The workspace root is the git repository root.** Trunk reads use
   repository-relative paths, so a workspace in a subdirectory would not line
   up.
3. **Trunk is chosen per clone** (see the contract's Trunk section):
   `CARBON_TRUNK`, then git config `carbon.trunk`, then the remote default
   branch. `[workspace] trunk` was removed and is now an error; this replaces
   the design's `trunk = "origin/main"` line. `carbon init --trunk <ref>` runs
   `git config carbon.trunk <ref>` for that clone and says so.
4. **A package that is not on trunk yet** uses the workspace's trunk access
   for its environments (`policy.ScopeAccess.PackageKnown` is false). Package
   access entries count only once reviewed and merged.
5. **Bootstrap and `worktree`-trunk drops** use the working tree's keys
   file for the inbox, since there is no trunk to read.
6. **Branch and trunk out of step.** `set` refuses to create a key when trunk
   already has one for the scope ("merge trunk first"), and a non-reader
   cannot drop into a scope whose key exists only on the branch, or when the
   branch has already retired trunk's current key (local trunk is stale).
7. **Scope creation** is refused unless the caller's identity is one of the
   devices policy names (finding from review: a non-reader could otherwise
   make a key and seal values no reader wrote). It wraps to those devices, skipping
   non-hybrid devices under `require_pq` and access entries that name no team,
   person or machine, each with a warning. With no device left it refuses.
8. **`set` needs a declaration** in `[secrets]` (exit 5) and refuses an empty
   value; a name that is a var is a usage error.
9. **`init`** writes every environment as readable by `@engineering` and an
   empty `engineering` team. The first person to `join` a workspace with no
   people joins every empty team, so one developer can `init`, `join`, `set`,
   but only while carbon is not adopted on trunk (bootstrap); afterwards team
   membership is a reviewed change.
10. **`join`** reuses an existing identity (one per device) and is idempotent.
    `--passphrase` reads the passphrase from stdin when there is no terminal.
    A passphrase-protected identity cannot be used without a terminal (exit 6;
    CI should use `CARBON_IDENTITY`).
11. **`get`** writes the raw value, with a trailing newline only when stdout is
    a terminal.
12. **Conflict markers** are detected in every file carbon parses (including
    `carbon.toml` and people files), not only keys and secrets files.
13. **`DirSource.Find` skips** directories whose name starts with `.` and
    `node_modules` when looking for package files, in the working tree and at
    a ref alike.

14. **Promotion clamps `set`.** A drop's set time is chosen by its writer; at
    promotion a set time later than now becomes now (`PromoteAt`).
15. **Strict base64 and offset date-times.** Blobs and payload fields use
    canonical, line-break-free base64. `set`, `created` and `retired` must be
    offset date-times (`...Z`); TOML local date-times are rejected rather than
    read in the machine's time zone.

## Limits

- **carbon cannot prove who generated a scope's first key.** A keys file is
  only as trustworthy as the review that merged it. A new keys file in a pull
  request is a trusted act to review, like a drop; `check` lists new scope
  keys.
- **Pins protect only readers who opened the scope before in this clone.**
  A new clone, or a CI job with a fresh checkout (machines usually are), has
  no pins and trusts the first key it sees. A pin also cannot detect a forged
  rotation by a removed reader who still holds the previous key: that key is
  in the chain and matches the pin. For that, key-changing commits must be
  authored by a current reader, which `check` flags for review.
- **A value under a retired key** proves only that its writer held that key,
  which a removed reader still may. Readers can still open it (old branches
  must merge), `ls` marks it "author unproven", and `apply` should list such
  values for confirmation before re-sealing them.

## carbon-migrate

Where the design's migration table (design.md, "Migration from 0.0.3 and
rollout") was not enough. Details are in `migrate/README.md`.

1. **`{{pull.x}}` becomes the pull's reference, not `${x}`.** The table maps
   `{{pull.x}}` to `${x}`, but in 1.0 `${x}` is this package's secret or var
   and `[env]` entries cannot reference each other, so a derive gets the
   pull's target: `{{pull.db_password}}` becomes `${db.password}`.
2. **`registry_pattern` keeps 0.0.3's precedence**, which is not
   first-match-wins: exactly one matching pattern wins, otherwise the single
   variant without a pattern, and two matches is an error in 0.0.3 (so that
   environment gets no value and the item is listed). Patterns are matched
   against the old registry name, `""` for the default registry.
3. **A push key with a `command` in any variant is a secret** in every
   environment; its values come from the registries. A key whose variants are
   all static values is a var.
4. **Derives whose variants are plain text become a var** per environment plus
   `[env] X = "${X}"`; variants with templates cannot vary by environment in
   1.0 and are listed for a manual choice.
5. **Access is per key: a recipient of the registry that is still in its
   creation rule.** A key that requested access but was never rekeyed gets a
   person file and no access; a recipient removed from the creation rule (a
   pending 0.0.3 removal) gets none unless `--keep-recipient` names it. Keys
   sharing a `users` name are one person only when they read the same
   environments, otherwise `alice`, `alice-2`, ... A final check blocks any
   plan that would let a device read an environment whose registry was not
   encrypted to it.
6. **Values are piped to `carbon set` and must round-trip `carbon get` before
   anything old is deleted**; the identity is installed before verification
   so the check also proves the moved key works.
7. **Package discovery still skips dot-directories.** A 0.0.3 service under
   one (`.carbon/svc` was 0.0.3's own example) is a blocker that asks the user
   to `git mv` it. Walking other dot-directories in the working tree would
   reach ignored caches (`.venv`, `.direnv`, `.cache`) whose stray
   `carbon.toml` would break every command, and the trunk side, which sees only
   tracked files, would disagree with the working tree.
