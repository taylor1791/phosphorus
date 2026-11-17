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
- **A value under a retired key** proves only that its writer held that key,
  which a removed reader still may. Readers can still open it (old branches
  must merge), `ls` marks it "author unproven", and `apply` lists each such
  value by name before re-sealing it (see 22 below).

## User management: decisions (apply, request, remove, rename)

16. **`apply` creates keys** for scopes whose package declares secrets and
    that have no key on the branch or on trunk, wrapped to the eligible
    devices trunk policy names, but only when the caller is one of those
    devices (as for `set`). Otherwise the scope is reported as waiting for
    one of them. Two branches that both create the same scope conflict on
    its keys file.
17. **`apply` scope filters** are `--package` and `--env` only (both global
    flags); `CARBON_ENV` and `carbon env use` do not narrow it. `--dry-run`
    prints the plan and changes nothing. The plan header says where policy
    came from: `main (git config carbon.trunk)`, `origin/main (remote
    default)`, or the working tree.
18. **`apply` exit codes.** Nothing to do: 0. Work done, other scopes left
    for someone else: 0, with the rest reported. Nothing the caller could do
    but work pending: 3 if any scope needs a reader, else 1. A scope that
    fails is left untouched, the others are committed, and the exit is 1.
19. **`apply` and uncommitted files.** Without `--no-commit`, it refuses
    (before asking) when a keys or secrets file of a scope it would change
    has uncommitted changes, since its commit would include them. It commits
    with `git commit -- <paths>`, so other staged changes stay staged.
20. **`apply` against trunk, one rule.** For each scope with a key, when
    trunk has a keys file:
    - trunk has a key and the branch has none: *blocked* (merge trunk);
    - the caller can open the scope: `VerifyTrunk` runs before anything
      else. A key that does not descend from trunk's is *refused* (fix:
      restore the keys file from trunk). A key that descends from trunk's
      but whose `current` differs (this branch rotated, or trunk rotated and
      this branch has not merged it) is *blocked* as out of step: apply does
      not rotate on top of a key trunk does not use;
    - the caller cannot open it and `current` differs: *blocked*.
    A key that exists only on the branch is applied to.
21. **Drops that do not open** are never fatal: rotation uses
    `RotateSkippingBadDrops`, promotion skips them, and each is named in the
    plan ("leaves drop") and the commit message. Promotion uses `PromoteAt`,
    so a future set time becomes now.
22. **Unproven values.** Every entry under a retired key is listed by name
    in the plan ("re-seals as trusted"), with its key and set time, and
    flagged when its set time is after its key was retired. Confirming (or
    `--yes`) re-seals them under the current key, including during a
    rotation. `--skip-unproven` leaves them, and stale drops, as they are
    (a rotation keeps them under their old key ids; the chain still opens
    them).
23. **`require_pq`.** Non-hybrid devices are never wrapped to; they are
    reported. An existing non-hybrid slot is not rotated away by itself (it
    is reported as a `check` failure), but a rotation for another reason
    wraps only to hybrid devices.
24. **Rotation reason.** `removed <who>` names a person when all of their
    slots go and the scope no longer names any of their devices, else each
    device (`ada/laptop`), and machines as `machine:<name>`. "Can finish
    it" lists only current readers who stay readers.
25. **`request`** refuses the root package (its `[access]` is the default
    for every package). It proposes the caller's person, or
    `machine:<name>` for a machine identity, and reports "already reads"
    when the reader is named or reaches the scope through a team. A missing
    entry is created from the workspace default plus the reader.
26. **`remove`** refuses to remove a person's only device (that would leave
    a person in every list who reads nothing); remove the person instead.
27. **`rename`** needs a reader of every environment that has a key,
    re-wraps each slot to the public key trunk policy has for that device id
    (refusing if trunk has none: run `apply` first), keeps values under the
    key they were sealed with, and does not commit. Until it merges:
    - readers verify the branch's keys against trunk's file in the same
      directory, which still names the old package. `VerifyTrunk` accepts a
      different package name only when the opened keys unseal trunk's
      `inbox_sealed` under the old name (`scope/rename_verify.go`), which
      proves they are trunk's keys; the environment must match;
    - `apply` takes the scope's access from the old name's trunk entry, not
      the workspace default that an unknown package name would get;
    - non-readers cannot drop into it (trunk's inbox is bound to the old
      name);
    - moving the directory in the same change would leave nothing on trunk
      to verify against, so `rename` tells people to move it separately.
28. **tomledit** appends to lists (it does not sort), deletes a list
    element's whole line when it has one, and refuses, with what to edit by
    hand, inline tables it would have to restructure, arrays of tables, and
    comments between inline elements.

## Known merge limits

- **A rotation and a branch that adds or changes a secret in the same
  scope conflict.** A rotation re-seals every line of the scope's secrets
  file, so any line another branch (cut before the rotation) added or
  changed lands inside a changed region and git reports a conflict. The
  design's merge table says such a branch merges; it does so cleanly only
  when the rotation did not touch the secrets file (the scope had no values
  yet). Resolution: keep the rotated side's lines, then add back each line
  the other side added or changed, exactly as written there. Each line is
  self-contained: the added value still opens through the retired key, and
  the next `carbon apply` lists it as unproven and re-seals it. The
  conflict-marker error for a secrets file prints this resolution.
- **Two concurrent applies can conflict on a slot line.** Two branches that
  grant different devices merge cleanly when their new slot lines land at
  different places in the sorted list. They conflict when both insert at
  the same place, or when both wrap the same device. The latter is the
  common case on a linear trunk: the later apply sees every grant merged
  so far and also wraps the person the earlier, unmerged apply granted.
  Either side's line is valid (both wrap the same key to the same device);
  keep either. The conflict-marker error for a keys file says so. Two
  branches that both rotate the same key conflict on `current`: keep one
  side's keys and secrets files and run `carbon apply` to rotate again.
