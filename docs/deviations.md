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

## User management (apply, request, remove, rename)

14. **The trunk name comes from trunk.** `policy.LoadTrunk` used the
    working tree's `trunk` value and honoured `trunk = "worktree"` before
    reading trunk, so a branch could opt itself out of trunk policy (the
    old unit test passed a workspace with the name already restored). Now
    the first of `origin/HEAD`, `origin/main`, `origin/master`, `main`,
    `master` that has a workspace file supplies the trunk name. `apply`
    also refuses when the working tree names a trunk that trunk's own file
    does not. A repository whose trunk is none of those refs, and a branch
    that pushes a ref naming itself as trunk, are not covered.
15. **`apply` creates keys**, as the contract's Creation bullet says: a
    scope whose package declares secrets, with no key on the branch or on
    trunk, gets one wrapped to the eligible devices trunk policy names.
    Anyone may do this, so a non-reader's `apply` can still have work.
    Two branches that both create the same scope conflict on its keys file.
16. **`apply` scope filters** are `--package` and `--env` only (both
    global flags); `CARBON_ENV` and `carbon env use` do not narrow it.
    `--dry-run` prints the plan and changes nothing.
17. **`apply` exit codes.** Nothing to do: 0. Work done, other scopes left
    for someone else: 0, with the rest reported. Nothing the caller could
    do but work pending: 3 if any scope needs a reader, else 1. A scope
    that fails is left untouched, the others are committed, and the exit
    is 1.
18. **`apply` and uncommitted files.** Without `--no-commit`, it refuses
    (before asking) when a keys or secrets file of a scope it would change
    has uncommitted changes, since its commit would include them. It
    commits with `git commit -- <paths>`, so other staged changes stay
    staged.
19. **Out of step with trunk.** A scope is skipped with a fix when trunk
    has a key and the working tree has none or a different `current`. A
    key that exists only on the branch (created there) is applied to.
20. **`require_pq`.** Non-hybrid devices are never wrapped to; they are
    reported. An existing non-hybrid slot is not rotated away by itself
    (it is reported as a `check` failure), but a rotation for another
    reason wraps only to hybrid devices.
21. **Rotation reason.** `removed <who>` names a person when all of their
    slots go and the scope no longer names any of their devices, else each
    device (`ada/laptop`), and machines as `machine:<name>`.
22. **`request`** refuses the root package (its `[access]` is the default
    for every package). It proposes the caller's person, or
    `machine:<name>` for a machine identity. It reports "already reads"
    when the reader is named or reaches the scope through a team.
23. **`remove`** refuses to remove a person's only device (that would
    leave a person in every list who reads nothing); remove the person.
24. **`rename`** needs a reader of every environment that has a key,
    re-wraps each slot to the public key trunk policy has for that device
    id (and refuses if trunk has none: run `apply` first), keeps values
    under the key they were sealed with, and does not commit.
25. **tomledit** appends to lists (it does not sort), deletes a list
    element's whole line when it has one, and refuses, with what to edit
    by hand, inline tables it would have to restructure, arrays of tables,
    and comments between inline elements.

## Known gaps found while writing the drills

- **A branch cut before a rotation that adds a secret conflicts** in the
  secrets file when the rotated scope already had values: the rotation
  re-seals every line, so git sees the new line inside a changed region.
  The resolution is mechanical (keep trunk's lines plus the branch's new
  line), and the value then opens through the retired key. The design's
  merge table says it merges; it does only when the scope's secrets file
  was empty or untouched by the rotation. A merge driver would close this.
- **Two branches granting different people** merge only when their slot
  lines are not inserted at the same place in the sorted list, and only
  if neither apply also wrapped the other's person: on a linear trunk,
  the later apply sees both grants in policy and wraps both, so the
  earlier person's line conflicts (either side is valid).
