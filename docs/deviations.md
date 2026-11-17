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
16. **`check`: which environments count.** A declared secret with no value
    in any workspace environment is an error (`secret.unset`): `run`
    resolves the same `[env]` table in every environment. A referenced var
    with no value and no `default` for an environment is an error too.
17. **`check`: slot rules without a reviewed trunk.** Under bootstrap and
    `worktree` trunk the working tree is the baseline: an unnamed slot is a
    pending revocation, never an unbacked grant, and key changes are not
    compared. `check` refuses to run at all when no trunk ref can be chosen
    (no remote-tracking refs, no override; a CI checkout of one commit looks
    like that) unless `--bootstrap` is given; a resolved trunk ref without a
    `carbon.toml` stays an automatic bootstrap. With remotes but no
    resolvable trunk, `check` fails (exit 1) with what CI must set; `status`
    carries on.
18. **`check`: the shape of a key change.** The contract excuses a changed
    `current` or `inbox` when trunk's key had a pending revocation. `check`
    reads that as excusing a rotation exactly as `apply` writes it: trunk's
    current key kept as a retired record (successor, reason, sealed, and
    trunk's `created` and `inbox_sealed`) whose successors lead to the new
    current key; the new key's slots only for devices trunk policy grants,
    each `to` the hash of that device's trunk policy key; an inbox; and every
    value trunk has still present with trunk's `set` time. Anything else is
    `key.changed`. With the same `current`, `inbox` and `inbox_sealed` must
    equal trunk's and trunk's slots may not be removed or changed
    (`slot.removed`). A working tree whose current key trunk retired is a
    rollback (error) when trunk's tip is an ancestor of HEAD; otherwise it is
    behind trunk only if its keys file is unchanged since the merge base, and
    an unprovable merge base is an error (`key.unverified`). Retired records
    trunk has are append-only (`key.retired-changed`). Drops are forbidden
    when either trunk's or the working tree's policy turns them off.
19. **Rotation debt** reads retired keys from the working tree and trunk
    together, trunk's record winning, so editing or deleting a retired key on
    a branch does not hide debt; debt from a removal counts from the earliest
    removal after the value was set.
20. **`check`: scopes across trunk and the working tree.** A scope in an
    environment trunk does not have gets every slot reported as unbacked
    (its keys cannot be created before its policy merges), plus `key.new`.
    A keys or secrets file that belongs to no working-tree scope is
    `store.orphan`. A scope trunk has keys for that the working tree no
    longer has is `key.removed` (error) while its keys file is still here,
    and `scope.removed` (banner) once the change deletes its files too. So
    removing an environment while keeping forged keys for it fails, and
    re-adding it later meets the new-environment rule: the review's
    two-pull-request trick reduces to `key.new`, which is in the banner.
21. **`status`** does not decrypt a passphrase-protected identity unless
    `--unlock` is given; a wrong passphrase is "no usable identity", not an
    abort.

## Limits

- **A keyless check cannot tell a reader's key change from a forged one.**
  `check` opens nothing, so a rotation or a new scope key made by a reader
  looks the same as one made by someone else with public keys only. It
  enforces every structural rule a legitimate `apply` commit satisfies, and
  lists every key change (new key, rotation, new slot, removed scope), every
  drop, and every value under a retired or older key in a banner so none
  passes silently. A passing check on a change to keys files is not "safe to
  merge without review": its author must be a current reader of the scope.

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
