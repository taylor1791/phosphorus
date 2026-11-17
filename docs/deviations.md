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
16. **`export -o` outside the repository** is allowed: git cannot commit
    it, which is what the "not ignored" rule protects against (deploys
    write to paths such as `/run/secrets`). Inside the work tree the path
    must be ignored by `git check-ignore`; a tracked file never is. The
    temporary file is made in the git directory (never added by git) and
    renamed onto the target, which replaces a symlink rather than writing
    through it; across filesystems the target is written directly, 0600,
    never through a symlink. `export --format json` refuses a value that is
    not UTF-8.
17. **dotenv quoting** in `export` targets Node dotenv (v16+) and
    python-dotenv: a value of only `[A-Za-z0-9_./:@%+,=-]` is bare; a value
    with no single quote, newline or carriage return that does not end in a
    backslash is single-quoted (literal in both); anything else is
    double-quoted with `\\ \" \n \r` escaped. Known limits: python-dotenv
    reads `\\` inside single quotes as one backslash; Node dotenv keeps `\"`
    and `\\` inside double quotes as written; python-dotenv interpolates
    `${NAME}` unless loaded with `interpolate=False`. A value with a NUL byte
    is refused by `run` and `export` alike.
18. **Resolution errors** (`run`, `export`): an unknown package, undeclared
    name or unset secret exits 5; a reference to another package's
    `private = true` secret exits 3; an unset `${env:NAME}`, a var with no
    value for the environment, or a name that is both secret and var exits
    1. `${env:CARBON_IDENTITY}` and `${env:CARBON_IDENTITY_FILE}` are
    refused (exit 1) whether set or not: the identity never leaves carbon. A
    scope with no key yet makes its references "not set" (exit 5). `run`'s
    "command not found" exits 1.
19. **`edit`** lists declared secrets only; removing a line deletes
    nothing; an empty value is refused for a set secret and ignored for an
    unset one; values that are not UTF-8, or that cannot be revealed, are
    shown as a comment and cannot be edited there. A drop that is not
    changed stays a drop. After the editor exits, the scope is reloaded,
    re-opened and re-checked against trunk; the changed names are sealed
    into that fresh copy and only the secrets file is written (never the
    keys file). If another writer changed one of the edited names
    meanwhile, nothing is saved. ^C goes to the editor and carbon judges by
    its exit status; SIGTERM and SIGHUP stop the editor and clean up.
20. **`env use --clear`** removes the stored environment.
21. **`run` stops reading its own flags at the command**: everything from
    the first positional argument on (or after `--`) is the command line,
    so `carbon run make -C build` passes `-C build` to make. The command
    starts in the `-C` directory. PATH lookup skips relative and empty
    entries and says so when that is the only place the command is.
22. **One snapshot per command.** A command reads trunk policy, working-tree
    policy and the identity once (`Context` caches them), and every file at
    a ref through one `git cat-file --batch` (`gitx.Repo.CacheSources`, set
    for the CLI's repository). The bootstrap notice is printed once.

## Limits

- **carbon cannot prove who generated a scope's first key.** A keys file is
  only as trustworthy as the review that merged it. A new keys file in a pull
  request is a trusted act to review, like a drop; `check` lists new scope
  keys.
- **A value under a retired key** proves only that its writer held that key,
  which a removed reader still may. Readers can still open it (old branches
  must merge), `ls` marks it "author unproven", and `apply` should list such
  values for confirmation before re-sealing them.
