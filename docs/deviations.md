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
    for the CLI's repository). `gitx.Find` asks one `rev-parse` for the top
    level, git directory and common directory, and `GitDir`/`CommonDir`
    remember them. The bootstrap notice is printed once.
23. **`check`: which environments count.** A declared secret with no value
    in any workspace environment is an error (`secret.unset`): `run`
    resolves the same `[env]` table in every environment. A referenced var
    with no value and no `default` for an environment is an error too.
24. **`check`: slot rules without a reviewed trunk.** Under bootstrap and
    `worktree` trunk the working tree is the baseline: an unnamed slot is a
    pending revocation, never an unbacked grant, and key changes are not
    compared. `check` refuses to run at all when no trunk ref can be chosen
    (no remote-tracking refs, no override; a CI checkout of one commit looks
    like that) unless `--bootstrap` is given; a resolved trunk ref without a
    `carbon.toml` stays an automatic bootstrap. With remotes but no
    resolvable trunk, `check` fails (exit 1) with what CI must set; `status`
    carries on.
25. **`check`: the shape of a key change.** The contract excuses a changed
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
26. **Rotation debt** reads retired keys from the working tree and trunk
    together, trunk's record winning, so editing or deleting a retired key on
    a branch does not hide debt; debt from a removal counts from the earliest
    removal after the value was set.
27. **`check`: scopes across trunk and the working tree.** A scope in an
    environment trunk does not have gets every slot reported as unbacked
    (its keys cannot be created before its policy merges), plus `key.new`.
    A keys or secrets file that belongs to no working-tree scope is
    `store.orphan`. A scope trunk has keys for that the working tree no
    longer has is `key.removed` (error) while its keys file is still here,
    and `scope.removed` (banner) once the change deletes its files too. So
    removing an environment while keeping forged keys for it fails, and
    re-adding it later meets the new-environment rule: the review's
    two-pull-request trick reduces to `key.new`, which is in the banner.
28. **`status`** does not decrypt a passphrase-protected identity unless
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
    for someone else: 0, with the rest reported. A scope that is refused or
    blocked for a reason that could be tampering (marked `suspect` in
    `--json`: a key not from trunk, a key not on trunk, a rotation from
    files that differ from trunk's, a rename plus move) makes the command
    exit 1 whatever else it applied, `--dry-run` included. Otherwise,
    nothing the caller could do but work pending: 3 if any scope needs a
    reader, else 1. A scope that fails is left untouched, the others are
    committed, and the exit is 1.
19. **`apply` and git.** Without `--no-commit`, it refuses (before asking)
    when a keys or secrets file of a scope it would change has uncommitted
    changes, since its commit would include them, and refuses on a detached
    HEAD (such a commit belongs to no branch and is easily lost). It commits
    with `git --literal-pathspecs commit --no-verify -- <paths>` and
    `-c core.hooksPath=/dev/null`, so other staged changes stay staged,
    paths are never globs, and no hook runs: a reader applying on someone
    else's branch must not run hook code that branch configured
    (`gitx.Repo.Commit`). The commit is reviewed like any access change;
    `carbon check` lists its key changes for the reviewer.
20. **`apply` against trunk, one rule.** For each scope with a key, when
    trunk is a ref:
    - trunk has a key and the branch has none: *blocked* (merge trunk);
    - trunk has no keys file but the branch does: *blocked*, suspect ("not
      on trunk yet; merge the change that created it first"). When neither
      the package name nor its directory is on trunk (a new package, or a
      rename and a move in one change) the message says so and asks to
      split the rename and the move. Keys created by the same apply run are
      the only exception;
    - the caller can open the scope: `VerifyTrunk` runs before anything
      else. A key that does not descend from trunk's is *refused* (fix:
      restore the keys file from trunk). A key that descends from trunk's
      but whose `current` differs (this branch rotated, or trunk rotated and
      this branch has not merged it) is *blocked* as out of step: apply does
      not rotate on top of a key trunk does not use;
    - the caller cannot open it and `current` differs: *blocked*;
    - a rotation runs only when the scope's keys and secrets files are
      byte-identical to trunk's; otherwise *blocked*, suspect: a value added
      on the branch under the still-current key could come from the reader
      being removed, and the rotation would re-seal it as trusted. Grants
      and drop promotion without a rotation are unaffected.
21. **Drops that do not open** are never fatal: rotation uses
    `RotateSkippingBadDrops`, promotion skips them, and each is named in the
    plan ("leaves drop") and the commit message. Promotion uses `PromoteAt`,
    so a future set time becomes now.
22. **Unproven values.** Every entry under a retired key is listed by name
    in the plan, with its key and set time, and marked when its set time is
    after its key was retired (advisory only: a forger can back-date). By
    default, with or without `--yes`, they and stale drops are left as they
    are (a rotation keeps them under their old key ids; the chain still
    opens them). `--reseal-unproven` re-seals them under the current key,
    which vouches for them; they are then listed as "re-seals as trusted"
    in the plan being confirmed.
23. **`require_pq`.** Non-hybrid devices are never wrapped to; they are
    reported. An existing non-hybrid slot is not rotated away by itself (it
    is reported as a `check` failure), but a rotation for another reason
    wraps only to hybrid devices.
24. **Rotation reason.** `removed <who>` names a person when all of their
    slots go and the scope no longer names any of their devices, else each
    device (`ada/laptop`), and machines as `machine:<name>`. A device whose
    slot records (`to`) a different public key than trunk lists for it now
    (a relabelled slot, or a device removed and re-joined under the same
    id) is rotated too: the plan says "<device>'s key changed" with the new
    key's fingerprint and the old slot's short hash, and the reason adds
    `rekeyed <device>` (`removed sam, rekeyed ada/laptop`, or `rekeyed
    ada/laptop` alone). Whatever computes rotation debt should treat
    `rekeyed` like `removed`. "Can finish it" lists only current readers who
    stay readers. After a rotation or creation is saved, apply records the
    caller's pin for the new key (`RecordPin`); a scope the pin check
    refuses is a refused scope (exit 1).
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
    key they were sealed with, and does not commit. It prepares every file
    in memory and writes them all or none (a failed write restores the
    files already written). Slots are written with their `to` hash and
    every reader's pin moves to the new scope name (`RenamePins`). If any
    slot records a different key than trunk lists for its device, rename
    stops and names each such device with the new key's fingerprint:
    re-wrapping would record the new key and hide that the old one still
    holds the scope key, so no rotation would ever follow. Run `apply`
    first. Until it merges:
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
    comments between inline elements. Every operation is all or nothing,
    and inserted lines use the file's own line ending (CRLF files stay
    CRLF).

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
