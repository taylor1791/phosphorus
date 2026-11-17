# Deviations from the implementation contract

Each entry says what differs from `docs/implementation.md` and why.

## Deviations

1. **Retired keys keep `inbox_sealed`.** The contract says a retired key keeps
   no inbox fields. A drop written on a branch cut before a rotation names the
   old key's inbox; without the old inbox identity no reader could open it
   after the merge, which breaks the design's promise that such branches still
   merge and decrypt. Rotation therefore keeps `inbox_sealed` (sealed under
   the old key, authenticated with the old key id) and drops `inbox` and the
   slots. It reveals nothing new: anyone who could unseal it already held the
   old key. `store` accepts retired records with or without it.
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
3. **The trunk ref name is read from the working tree's `carbon.toml`**, but
   `trunk = "worktree"` only takes effect when trunk's own workspace file says
   so (or carbon is not on trunk yet). A branch cannot opt out of trunk policy
   by editing its copy; it could name another ref, which `check` should flag.
4. **A package that is not on trunk yet** uses the workspace's trunk access
   for its environments (`policy.ScopeAccess.PackageKnown` is false). Package
   access entries count only once reviewed and merged.
5. **Bootstrap and `trunk = "worktree"` drops** use the working tree's keys
   file for the inbox, since there is no trunk to read.
6. **Branch and trunk out of step.** `set` refuses to create a key when trunk
   already has one for the scope ("merge trunk first"), and a non-reader
   cannot drop into a scope whose key exists only on the branch.
7. **Scope creation** wraps to the devices trunk policy names, skipping
   non-hybrid devices under `require_pq` and access entries that name no team,
   person or machine, each with a warning. With no device left it refuses.
8. **`set` needs a declaration** in `[secrets]` (exit 5) and refuses an empty
   value; a name that is a var is a usage error.
9. **`init`** writes every environment as readable by `@engineering` and an
   empty `engineering` team. The first person to `join` a workspace with no
   people joins every empty team, so one developer can `init`, `join`, `set`.
   `--trunk` defaults to origin's HEAD, else `origin/main`.
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
