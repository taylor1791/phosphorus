# Deviations, decisions and limits

This file goes with `docs/implementation.md` (the contract). "Deviations"
says where the code differs from the contract as first written, and why.
"Decisions" records what the code does where the contract was silent or
ambiguous. "carbon-migrate" covers the migration tool. "Limits" and "Known
merge limits" say what carbon does not protect against or handle on its
own. Each section is numbered from 1.

## Deviations

1. **Retired keys keep `inbox_sealed`** (now in the contract). A drop written
   on a branch cut before a rotation names the old key's inbox; without the
   old inbox identity no reader could open it after the merge. It reveals
   nothing new: anyone who could unseal it already held the old key. `store`
   accepts retired records with or without it.
2. **No `github.com/spf13/pflag`.** pflag imports `net`, and nixpkgs' Go
   defaults to `CGO_ENABLED=1` without a C compiler, so `go test ./...` failed
   to build `internal/cli`. Flags use the standard `flag` package behind a
   small wrapper (`internal/cli/flags.go`) that interleaves flags and
   positionals and honours `--`. `--name` and `-name` are both accepted.
3. **`--package` is a global flag** (now in the contract), accepted like
   `--env`. The contract first named it only under package resolution.
4. **`go.mod` has `tool filippo.io/age/cmd/age`.** The interop tests build the
   real age CLI; the tool directive keeps its go.sum entries, which brings
   `filippo.io/edwards25519` and `filippo.io/nistec` into go.mod as indirect
   requirements. They are age's own dependencies and are not linked into
   `carbon`.
5. **Module versions are pinned to what age v1.3.2 requires**
   (`golang.org/x/crypto` v0.55.0, `x/term` v0.45.0, `x/sys` v0.47.0): newer
   x/crypto requires Go 1.26, and the contract says Go 1.25.
6. **`--json` errors** are `{"error": {"code", "message", "details", "hint"}}`
   (now in the contract): `code` is the numeric exit code and `details` was
   added for the detail lines.
7. **`[workspace] trunk` was removed.** The design's `trunk = "origin/main"`
   line let a commit choose the trunk it is checked against. Trunk is now
   chosen per clone (the contract's Trunk section): `CARBON_TRUNK`, then git
   config `carbon.trunk`, then the remote default branch. A workspace file
   that still has `trunk` is an error. `carbon init --trunk <ref>` runs
   `git config carbon.trunk <ref>` for that clone and says so.
8. **Keys files are not marked generated** (now in the contract). The
   contract first had `init` add `**/.carbon/*.keys.toml linguist-generated`
   to `.gitattributes`. That collapsed keys files in review tools and hid
   which key and slot lines changed, which is exactly what a reviewer must
   see. `init` and `carbon-migrate` no longer write the line, and `doctor`
   no longer asks for it. A repository that already has it should delete it.
9. **A rotation does not re-seal values** (now in the contract). The design
   and the contract first had a rotation re-seal every value under the new
   key, keeping its set time. A removed reader has already seen every
   existing value, so that protected nothing, and because it rewrote every
   line of the secrets file, every rotation conflicted in git with any
   branch that added or changed a secret in the scope. A rotation now makes
   the new key and inbox, wraps the key to the remaining readers, retires
   the old key sealed under the new one, and leaves the secrets file byte
   for byte as it was: existing values and drops stay under the old key id
   and open through the retired chain, and a rotation commit changes only
   the keys file (unless the same `apply` promotes drops). It opens no
   value, so a value that does not open no longer stops it. To keep
   telling values the rotation left in place from values written later
   with the retired key, the retired record has a required `carried` list,
   the line hashes of every entry under the key when it was retired; its
   digest is the last line of the retired `sealed` blob's associated data,
   so it cannot be edited without breaking the chain. Entries under a
   retired key that it carries are ordinary; the others are unproven
   (Decisions 46). Rotation debt still lists every value set before the
   removal (17).

   A `carried` list made a retired record worth forging. Readers first
   walked every record that reached the current key through successors, so
   a removed reader who kept retired key K1 could add a record of his own,
   with K1 as successor, sealed under K1, whose `carried` vouched for a
   value of his choosing. Each retired record now also names its
   `predecessor` (the key it replaced; absent for a scope's first key),
   written at retirement and bound in the `sealed` blob's associated data
   (the line before the carried digest, `-` for none). The records must
   form one chain back from the current key (`store.Keys.Chain`): at most
   one record names the current key as successor, and from each record the
   next is the one its `predecessor` names, which must name it as
   successor. Readers refuse the whole scope (`ErrTampered`, naming the
   record and the fix) when any retired record is off that chain, rather
   than ignore it, then unseal the chain in order, so every link is
   authenticated in both directions; a link that fails makes it and every
   older key unavailable and the rest reads. `carried` counts only for
   records on the chain that opened. `check`, which holds no key, refuses
   any added retired record but the one a rotation writes (31).

## Decisions

### Workspace, trunk and files

1. **Plugin recipients run a program.** The contract accepts plugin recipients
   through `filippo.io/age/plugin`, which runs `age-plugin-<name>` from PATH;
   the brief also says git is the only external program. Plugins are
   supported as the contract says, and are only ever run when a plugin
   recipient or identity is used. `scope.Open` never asks a plugin identity to
   try slots other than the caller's own.
2. **The workspace root is the git repository root.** Trunk reads use
   repository-relative paths, so a workspace in a subdirectory would not line
   up.
3. **A package that is not on trunk yet** uses the workspace's trunk access
   for its environments (`policy.ScopeAccess.PackageKnown` is false). Package
   access entries count only once reviewed and merged.
4. **Bootstrap and `worktree`-trunk drops** use the working tree's keys
   file for the inbox, since there is no trunk to read.
5. **Conflict markers** are detected in every file carbon parses (including
   `carbon.toml` and people files), not only keys and secrets files.
6. **`DirSource.Find` skips** directories whose name starts with `.` and
   `node_modules` when looking for package files, in the working tree and at
   a ref alike.
7. **Strict base64 and offset date-times.** Blobs and payload fields use
   canonical, line-break-free base64. `set`, `created` and `retired` must be
   offset date-times (`...Z`); TOML local date-times are rejected rather than
   read in the machine's time zone.
8. **One snapshot per command.** A command reads trunk policy, working-tree
   policy and the identity once (`Context` caches them), and every file at
   a ref through one `git cat-file --batch` (`gitx.Repo.CacheSources`, set
   for the CLI's repository). `gitx.Find` asks one `rev-parse` for the top
   level, git directory and common directory, and `GitDir`/`CommonDir`
   remember them. The bootstrap notice is printed once.
9. **tomledit** appends to lists (it does not sort), deletes a list
   element's whole line when it has one, and refuses, with what to edit by
   hand, inline tables it would have to restructure, arrays of tables, and
   comments between inline elements. Every operation is all or nothing,
   and inserted lines use the file's own line ending (CRLF files stay
   CRLF).
10. **Trunk is a branch and a commit, never a tag.** git resolves a short
    name through `refs/tags/` before `refs/heads/` and `refs/remotes/`, and
    CI fetches tags, so a pushed tag named `main` or `origin/main` stood in
    for trunk and `apply` granted from the tag's policy. Trunk is now
    resolved once per command to a full branch refname and its commit
    (`policy.ResolveTrunk`, `gitx.Repo.ResolveBranchRef`; rules in the
    contract's Trunk section). A short name is looked up only as
    `refs/remotes/<name>` and `refs/heads/<name>`; when both exist carbon
    asks for the full ref rather than guess which one is trunk.
    `refs/tags/...` and every other `refs/` namespace are refused.
    Reads use the resolved commit (`Policy.At()`), so a fetch that moves the
    ref during a command cannot mix two trunks in one run. Output shows the
    full ref and the short commit (`refs/remotes/origin/main at 3f9c2a1`) so
    a reviewer of a CI log can see exactly what was compared.
11. **Symbolic links are refused.** A package whose `.carbon` directory was
    a symbolic link made `set` write the scope's key files outside the
    repository, and a symlinked `carbon.toml` or keys file was read from
    wherever it pointed. Every command now refuses a link in the path of a
    working-tree `carbon.toml`, the root `.carbon` policy files, a package's
    `.carbon` directory and the scope files in it, with an error naming the
    path (`config.NoSymlinks`, `config.NoSymlinkFile`). Only components
    below the workspace root are checked; the root itself may be reached
    through a link. `check` reads with `DirSource.SkipSymlinks`, reports
    each link as `file.symlink` (error) and judges the rest; a symlinked
    root `carbon.toml` leaves no workspace to judge, so `check` stops with
    the error.

### Scope keys, sealing and pins

12. **Scope creation** (only by a reader, as the contract says) wraps the new
    key to the devices policy names, skipping non-hybrid devices under
    `require_pq` and access entries that name no team, person or machine,
    each with a warning. With no device left it refuses. The reason for the
    reader-only rule: a non-reader could otherwise make a key and seal values
    no reader wrote.
13. **Branch and trunk out of step.** `set` refuses to create a key when
    trunk already has one for the scope ("merge trunk first"), and a
    non-reader cannot drop into a scope whose key exists only on the branch,
    or when the branch has already retired trunk's current key (local trunk
    is stale: `git fetch`).
14. **No sealing under a key trunk retired.** `set` and `edit` refuse (exit
    1) when trunk lists the working tree's current key as retired: the branch
    is behind trunk, or reverted a rotation. A value sealed under a retired
    key is readable by whoever it was retired from. The fix is to merge
    trunk. Reading is unchanged (`VerifyTrunk` with `Context.sealing`).
15. **No trust on first use for a key that exists only on this branch.**
    When trunk is a reviewed ref and has no keys file for the scope, a reader
    with no pin for it may read, but nothing is pinned, and `set` and `edit`
    refuse to seal: whoever created the key could read what is set. The
    reader who created the key pinned it at creation and can seal; anyone
    else needs `carbon trust` (after checking who committed the keys file)
    or the key merged to trunk (`checkPin`).
16. **Promotion clamps `set`.** A drop's set time is chosen by its writer; at
    promotion a set time later than now becomes now (`PromoteAt`).
17. **Rotation debt** reads retired keys from the working tree and trunk
    together, trunk's record winning, so editing or deleting a retired key on
    a branch does not hide debt. A retired key's reason counts if it names a
    removal or a re-key, in every form `apply` writes (`removed sam`,
    `removed sam, lin`, `rekeyed ada/laptop`, `removed sam, rekeyed
    ada/laptop`; `audit.Exposed`); a re-keyed device is reported as
    "<device>'s old key". Debt counts from the earliest such retirement at or
    after the value was set. A value whose set time equals the retirement
    time counts (set <= retired): set times are whole seconds, so a value set
    in the same second as the rotation may have been readable with the old
    key. A line whose ciphertext is unchanged from trunk's takes trunk's set
    time for debt, so re-dating it on a branch hides nothing (`check` also
    reports it as `secret.redated`). A rotation does not re-seal anything,
    so a value that owes a rotation stays under the retired key id until it
    is set again; setting a new value (under the current key, with a later
    set time) clears the debt.

### set, get, edit, run, export

18. **`set` needs a declaration** in `[secrets]` (exit 5) and refuses an empty
    value unless `--allow-empty` is given; a name that is a var is a usage
    error. A stored empty value is set for `run`, `export` and `check`.
19. **`get`** writes the raw value, with a trailing newline only when stdout is
    a terminal.
20. **`edit`** lists declared secrets only; removing a line deletes nothing.
    `--allow-empty` means what it means for `set`: without it, emptying a set
    value saves nothing and names the flag, and an uncommented `name = ""`
    for an unset secret is ignored; with it, both store the empty value.
    Values that are not UTF-8, or that cannot be revealed, are shown as a
    comment and cannot be edited there. A drop that is not changed stays a
    drop. After the editor exits, the scope is reloaded, re-opened and
    re-checked against trunk; the changed names are sealed into that fresh
    copy and only the secrets file is written (never the keys file). If
    another writer changed one of the edited names meanwhile, nothing is
    saved. ^C goes to the editor and carbon judges by its exit status;
    SIGTERM and SIGHUP stop the editor and clean up.
21. **`export -o` outside the repository** is allowed: git cannot commit
    it, which is what the "not ignored" rule protects against (deploys
    write to paths such as `/run/secrets`). Inside the work tree the path
    must be ignored by `git check-ignore`; a tracked file never is. The
    temporary file is made in the git directory (never added by git) and
    renamed onto the target, which replaces a symlink rather than writing
    through it; across filesystems the target is written directly, 0600,
    never through a symlink. `export --format json` refuses a value that is
    not UTF-8.
22. **dotenv quoting** in `export` targets Node dotenv (v16+) and
    python-dotenv: a value of only `[A-Za-z0-9_./:@%+,=-]` is bare; a value
    with no single quote, newline or carriage return that does not end in a
    backslash is single-quoted (literal in both); anything else is
    double-quoted with `\\ \" \n \r` escaped. Known limits: python-dotenv
    reads `\\` inside single quotes as one backslash; Node dotenv keeps `\"`
    and `\\` inside double quotes as written; python-dotenv interpolates
    `${NAME}` unless loaded with `interpolate=False`. A value with a NUL byte
    is refused by `run` and `export` alike.
23. **Resolution errors** (`run`, `export`): an unknown package, undeclared
    name or unset secret exits 5; a reference to another package's
    `private = true` secret exits 3; an unset `${env:NAME}`, a var with no
    value for the environment, or a name that is both secret and var exits
    1. `${env:CARBON_IDENTITY}` and `${env:CARBON_IDENTITY_FILE}` are
    refused (exit 1) whether set or not: the identity never leaves carbon
    (`check` reports them as `graph.forbidden-env`). A scope with no key yet
    makes its references "not set" (exit 5). `run`'s "command not found"
    exits 1.
24. **`run` stops reading its own flags at the command**: everything from
    the first positional argument on (or after `--`) is the command line,
    so `carbon run make -C build` passes `-C build` to make. The command
    starts in the `-C` directory. PATH lookup skips relative and empty
    entries and says so when that is the only place the command is.
25. **`env use --clear`** removes the stored environment.

### init, join, help

26. **`init`** writes every environment as readable by `@engineering` and an
    empty `engineering` team. The first person to `join` a workspace with no
    people joins every empty team, so one developer can `init`, `join`, `set`,
    but only while carbon is not adopted on trunk (bootstrap); afterwards team
    membership is a reviewed change.
27. **`join`** reuses an existing identity (one per device) and is idempotent.
    `--passphrase` reads the passphrase from stdin when there is no terminal.
    A passphrase-protected identity cannot be used without a terminal (exit 6;
    CI should use `CARBON_IDENTITY`). It prints a next step that fits the
    situation: under bootstrap, the first person (already in the teams) is
    told to `init` packages and `set` secrets; a person policy already names
    (for example on a new device) is told to open a pull request and wait for
    a reader's `apply`; a newcomer is told to ask to be added to a team or
    run `carbon request`.
28. **`carbon help`** groups commands (Daily use, Access, Inspection, Setup)
    by the `Group` field each command registers, shows each command's own
    flags apart from the global flags, and prints the exit-code table. An
    unknown command suggests the nearest command name. `carbon version` and
    `--version` print `cli.Version` (see the contract's command line
    conventions).

### check and status

29. **`check`: which environments count.** A declared secret with no value
    in any workspace environment is an error (`secret.unset`): `run`
    resolves the same `[env]` table in every environment. A referenced var
    with no value and no `default` for an environment is an error too. A
    stored empty value is set.
30. **`check` without a reviewed trunk.** Under bootstrap and `worktree`
    trunk the working tree is the baseline: an unnamed slot is a pending
    revocation, never an unbacked grant, and key changes are not compared.
    `check` never bootstraps by itself: it exits 1 unless `--bootstrap` is
    given when no trunk ref can be chosen (no remote-tracking refs, no
    override; a CI checkout of one commit looks like that), when the trunk
    ref has no root `carbon.toml`, and when trunk's root `carbon.toml` is a
    carbon 0.0.3 file (the carbon-migrate cutover). Before, a resolved trunk
    without a carbon 1.0 `carbon.toml` was an automatic bootstrap, so
    pointing `CARBON_TRUNK` at the wrong branch, or one without carbon, made
    `check` compare a branch with itself and pass any forged key. Other
    commands keep the automatic bootstrap and print its notice. With remotes but no resolvable trunk, `check` fails (exit
    1) with what CI must set; `status` carries on.
31. **`check`: the shape of a key change.** The contract excuses a changed
    `current` or `inbox` when trunk's key had a pending revocation. `check`
    reads that as excusing a rotation exactly as `apply` writes it; the
    resulting rules are now in the contract (`key.changed`,
    `key.retired-changed`, `key.unverified`, `key.behind-trunk`). A pending
    revocation includes a slot whose `to` no longer matches its device's
    trunk policy key (a re-keyed device, `hasPendingRevocation`); before
    that, `apply`'s re-key rotation failed `check` with `key.changed`. The
    retired record's `reason` feeds rotation debt, so `check` no longer
    accepts any text there: the code that builds it moved from `apply` to
    `scope.RotationReason`, and `check` recomputes it from trunk's key and
    trunk policy and requires the record to say exactly that
    (`key.changed` otherwise), so a rotation cannot name the wrong person
    and leave the real removal without debt. Since a rotation leaves the
    secrets file as it is (Deviations 9), a change of `current` must keep
    every entry trunk has byte-identical, except one set again under the new
    current key, and the new retired record's `carried` must be exactly the
    line hashes of trunk's entries under the retired id, recomputed from
    trunk's secrets file (`key.changed` otherwise): leaving one out would
    make a legitimate value look unproven, adding one would vouch for a line
    nobody carried. The new retired record's `predecessor` must be what
    trunk's chain implies (the newest record on trunk's chain, or none), and
    the working tree's chain must be valid: linear, with no stray records
    (`key.changed` otherwise). Retired records, `predecessor` and `carried`
    included, are append-only (`key.retired-changed`), and a retired record
    trunk does not have, other than the one the rotation writes, is
    `key.retired-added` (error); a new scope key may have none. A retired
    record decides which values count as carried, and `check` cannot open
    one, so it does not judge whether an added one is genuine: it refuses
    it. A line that differs from trunk's under the same key, which trunk has
    retired, is `secret.rolled-back` (error). Its message does not accuse
    anyone: such a line is either an edit made on a branch cut before the
    rotation or a value forged by someone who kept the key, and carbon
    cannot tell which; the fix is to merge trunk and `carbon set` it again
    (or `carbon apply --reseal-unproven` by a reader, if the value is known
    good). `check` also counts an entry under a retired key as carried only
    if trunk has the identical line for that name: a carried line copied
    back after trunk deleted it is `secret.stale-key` (warning, banner),
    although its hash is in a `carried` list (46).
32. **`check`: scopes across trunk and the working tree.** Scopes are the
    union of both sides (rules in the contract: `key.new`, `key.removed`,
    `scope.removed`, `store.orphan`). The reason for `key.removed`: removing
    an environment while keeping forged keys for it fails, and re-adding it
    later meets the new-environment rule (every slot unbacked until its
    policy merges), so the two-pull-request trick reduces to `key.new`,
    which is in the banner.
33. **`check`: proposed policy changes.** `policy.grant-proposed` and
    `policy.revoke-proposed` (info, never raised by `--strict`) list what the
    working tree's policy adds, or removes or re-keys, relative to trunk's
    for a scope that has a key, so a `request` or `remove` pull request shows
    the grant or rotation it leads to. A device that is already a pending
    grant or revocation against trunk is not repeated.
34. **`check`: `graph.forbidden-env`** (error) is an `[env]` template that
    references `${env:CARBON_IDENTITY}` or `${env:CARBON_IDENTITY_FILE}`,
    which `run` and `export` refuse anyway (23).
35. **`status`** lists, besides readable scopes, waits, grants, revocations,
    drops, new scope keys and rotation debt:
    - "Refused": scopes the caller holds a slot in that readers would refuse.
      Keys that do not follow from trunk's are judged keylessly (inbox
      differs, key does not descend) and from `check`'s `key.changed`,
      `key.retired-changed` and `key.unverified`. A key that replaced the
      caller's pin is found by unwrapping the key, as `get` would, but only
      for a scope whose key id changed since it was pinned; otherwise
      `status` decrypts nothing;
    - re-keyed devices as pending rotations (`rekey`);
    - unproven values (under a retired key that does not carry them, or an
      unknown key) as "Unproven". Values a rotation carried are not listed
      beyond rotation debt.

    It does not decrypt a passphrase-protected identity unless `--unlock` is
    given; a wrong passphrase is "no usable identity", not an abort.
36. **`check`: re-dated and future-dated lines.** A line's set time is
    chosen by its writer and is what rotation debt counts from. Changing
    it while keeping the ciphertext hid the value's debt and passed `check`
    silently. Now a value with trunk's ciphertext and a different set time
    is `secret.redated` (error), any entry set more than 10 minutes in the
    future is `secret.future` (error; the allowance, `audit.ClockSkew`, is
    for clocks that disagree between machines), and debt uses trunk's set
    time for a line whose ciphertext is trunk's (17).
37. **`check`: a rename.** A rename done as documented (51) failed
    `check` with `key.removed`, `key.new` and `trunk.unreadable`. `check` now
    recognises the case readers accept: the package keeps its directory,
    its new name is not on trunk, and trunk's keys file there names the old
    package (`audit/rename.go`). Every value and slot was re-sealed under
    the new name and `check` holds no key, so it compares structure only
    (rules in the contract), including that each entry is still carried or
    still unproven, and reports one `scope.renamed` banner item per
    scope; any other difference is `key.changed`. A rename and a move in
    one change is not recognised and fails as before.
38. **`check`: changed device keys and new devices.** Replacing the public
    key of an existing person device or machine, or adding a device to an
    existing person, gives that key access once a reader applies, but
    `check` listed neither: a reviewer saw only a changed line in a people
    file. Both are now banner items, `policy.device-key-changed` and
    `policy.device-added` (info, never raised by `--strict`, since both are
    routine), with the new key's four-word fingerprint, which the reviewer
    confirms with the device's owner over another channel. A new person is
    a new file; once access names them, `policy.grant-proposed` lists them.

### User management (apply, request, remove, rename)

39. **`apply` creates keys** for scopes whose package declares secrets and
    that have no key on the branch or on trunk, wrapped to the eligible
    devices trunk policy names, but only when the caller is one of those
    devices (as for `set`). Otherwise the scope is reported as waiting for
    one of them. Two branches that both create the same scope conflict on
    its keys file.
40. **`apply` scope filters** are `--package` and `--env` only (both global
    flags); `CARBON_ENV` and `carbon env use` do not narrow it. `--dry-run`
    prints the plan and changes nothing. The plan header says where policy
    came from: the full trunk ref and short commit with its source
    (`refs/remotes/origin/main at 3f9c2a1 (remote default)`), or the
    working tree.
41. **`apply` exit codes.** Nothing to do: 0. Work done, other scopes left
    for someone else: 0, with the rest reported. A scope that is refused or
    blocked for a reason that could be tampering (marked `suspect` in
    `--json`: a key not from trunk, a key not on trunk, a rotation from
    files that differ from trunk's, a rename plus move) makes the command
    exit 1 whatever else it applied, `--dry-run` included. Otherwise,
    nothing the caller could do but work pending: 3 if any scope needs a
    reader, else 1. A scope that fails is left untouched, the others are
    committed, and the exit is 1.
42. **`apply` and git.** Without `--no-commit`, it refuses (before asking)
    when a keys or secrets file of a scope it would change has uncommitted
    changes, since its commit would include them, and refuses on a detached
    HEAD (such a commit belongs to no branch and is easily lost). It commits
    with `git --literal-pathspecs commit --no-verify -- <paths>` and
    `-c core.hooksPath=/dev/null`, so other staged changes stay staged,
    paths are never globs, and no hook runs: a reader applying on someone
    else's branch must not run hook code that branch configured
    (`gitx.Repo.Commit`). The commit is reviewed like any access change;
    `carbon check` lists its key changes for the reviewer.
43. **`apply` against trunk, one rule.** For each scope with a key, when
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
      being removed, and the rotation would record it as carried, vouching
      for it. Grants and drop promotion without a rotation are unaffected.
      The plan says the rotation leaves values where they are; it re-seals
      nothing (Deviations 9).
44. **Values and drops that do not open** never stop a rotation, which
    opens no value. Promotion and `--reseal-unproven` skip a drop that does
    not open, and each is named in the plan ("leaves drop") and the commit
    message; a sealed value that does not open stops `--reseal-unproven`
    for its scope. Promotion uses `PromoteAt` (16).
45. **`apply` promotes only drops that trunk has, line for line.** `apply`
    on an unmerged branch promoted a drop that existed only there, which
    turned an unreviewed value into a sealed one and took it out of
    `check`'s banner. When trunk is a ref, a drop is promoted only when
    trunk's secrets file has the identical line (same name, key, set time
    and drop); every other drop is left as a drop and listed in the plan as
    "not on trunk yet; left as a drop" (`DropsNotOnTrunk`). A drop that
    `rename` re-sealed differs from trunk's line, so it stays a drop until
    the rename merges. Under bootstrap and `worktree` trunk there is no
    reviewed line to compare with, and drops are promoted as before. A drop
    under a retired key that the key carries is promoted like any other; an
    unproven drop is promoted only with `--reseal-unproven` (46).
46. **Unproven values.** An entry under a retired key is *carried* when the
    key is on the scope's chain (Deviations 9) and the entry's line hash is
    in that key's `carried` list, and *unproven* otherwise; an entry under
    an unknown key id is unproven too (`scope.IsUnproven`; the same
    definition in `ls`, `status`, `check`, `apply` and `get`). A reader that
    opened the scope also requires the record to have opened
    (`scope.Opened.IsUnproven`). `check` adds a keyless rule of its own: an
    entry counts as carried only if trunk has the identical line for that
    name (31); `ls`, `status` and `apply` use the keys file only. Carried
    entries are ordinary and `apply` leaves them alone. Every unproven entry
    is listed by name in the plan, with its key and set time, and marked
    when its set time is after its key was retired (advisory only: a forger
    can back-date). By default, with or without `--yes`, unproven values and
    drops are left as they are (the chain still opens them).
    `--reseal-unproven` re-seals only the unproven entries under the current
    key (`scope.Opened.ResealUnproven`), which vouches for them; they are
    then listed as "re-seals as trusted" in the plan being confirmed.
47. **`require_pq`.** Non-hybrid devices are never wrapped to; they are
    reported. An existing non-hybrid slot is not rotated away by itself (it
    is reported as a `check` failure), but a rotation for another reason
    wraps only to hybrid devices.
48. **Rotation reason.** `removed <who>` names a person when all of their
    slots go and the scope no longer names any of their devices, else each
    device (`ada/laptop`), and machines as `machine:<name>`. A device whose
    slot records (`to`) a different public key than trunk lists for it now
    (a relabelled slot, or a device removed and re-joined under the same
    id) is rotated too: the plan says "<device>'s key changed" with the new
    key's fingerprint and the old slot's short hash, and the reason adds
    `rekeyed <device>` (`removed sam, rekeyed ada/laptop`, or `rekeyed
    ada/laptop` alone). Rotation debt counts both (17), and `check` accepts
    both as justifying the rotation (31). "Can finish it" lists only current
    readers who stay readers. After a rotation or creation is saved, apply
    records the caller's pin for the new key (`RecordPin`); a scope the pin
    check refuses is a refused scope (exit 1).
49. **`request`** refuses the root package (its `[access]` is the default
    for every package). It proposes the caller's person, or
    `machine:<name>` for a machine identity, and reports "already reads"
    when the reader is named or reaches the scope through a team. A missing
    entry is created from the workspace default plus the reader.
50. **`remove`** refuses to remove a person's only device (that would leave
    a person in every list who reads nothing); remove the person instead.
51. **`rename`** needs a reader of every environment that has a key,
    re-wraps each slot to the public key trunk policy has for that device id
    (refusing if trunk has none: run `apply` first), keeps values under the
    key they were sealed with, rewrites each retired key's `carried` list to
    the re-sealed lines (so each entry stays carried or unproven, and the
    retired `sealed` blob is re-sealed with the new digest), and does not
    commit. It prepares every file
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
      name), and a drop `rename` re-sealed stays a drop (45);
    - `check` reports each scope as `scope.renamed` in the banner when its
      structure matches trunk's under the old name (37);
    - moving the directory in the same change would leave nothing on trunk
      to verify against, so `rename` tells people to move it separately.

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

## Limits

What carbon does not protect against. Review of who authored a change is
the defence for most of them.

1. **A keyless check cannot tell a reader's key change from a forged one.**
   `check` opens nothing, so a rotation or a new scope key made by a reader
   looks the same as one made by someone else with public keys only. It
   enforces every structural rule a legitimate `apply` commit satisfies, and
   lists every key change (new key, rotation, new slot, renamed or removed
   scope), every changed device key and new device, every drop, every
   unproven value (under a retired key that does not carry it) and every
   value under an older key than trunk's in a banner so none passes
   silently. A passing check on a change to keys files is not "safe to
   merge without review", and neither is an `apply` commit: the author of
   every key-changing commit must be a current reader of the scope.
2. **A forged rotation by a removed reader is not detected.** A reader
   removed from policy still holds the scope key they had. With it they can
   write a rotation that is structurally valid (`check` passes it once their
   removal is a pending revocation, and can only list it in the banner as
   `key.rotated`), and that every reader's pin accepts, because the previous
   key is in the chain and matches the pin. The defence is review: a
   key-changing commit must be authored by a current reader.
3. **Pins protect only readers who opened the scope before, in this clone,
   with this identity.** Pins are per clone and per reader identity. A fresh
   clone, or a CI job with a fresh checkout (machines usually are), has no
   pins and trusts the first key it sees (trust on first use, unless the key
   exists only on the branch; see Decisions 15). A second identity in the
   same clone, or the same person in another clone, has its own pins.
4. **A scope's first key is trusted on review.** carbon cannot prove that a
   reader created it. A keys file is only as trustworthy as the review that
   merged it; a new keys file in a pull request is a trusted act to review,
   like a drop, and `check` lists it as `key.new`.
5. **An unproven value** (under a retired key that does not carry it)
   proves only that its writer held that key, which a removed reader still
   may. Values a rotation left in place are carried: the retired record
   lists their line hashes and authenticates the list, so a line written
   later under the retired key is told apart from them. A retired key does
   not let its holder forge a record that carries a value: the chain is
   authenticated backwards, readers refuse a stray record, and `check`
   refuses an added one (Deviations 9). Readers can still
   open an unproven value (old branches must merge), `ls` marks it "author
   unproven", `status` lists it under "Unproven", `check` lists it in the
   banner, and `apply` lists it and leaves it as it is unless
   `--reseal-unproven` is given (Decisions 46). A carried line replaced
   with another line under the same retired key is `secret.rolled-back`
   (error). Its set time is chosen by its writer, so the "set after its key
   was retired" mark is advisory: `check` refuses only a set time more than
   10 minutes in the future (`secret.future`) and a re-dated trunk line
   (`secret.redated`).
6. **Slot `to` hashes are not authenticated by cryptography.** `check`
   protects them structurally (the contract's slot rules); a reader's
   `apply` treats a mismatch as a re-key and rotates.
7. **`check` is only as strong as the CI that runs it.** On trunk itself
   `check` compares trunk with itself, so a direct push to trunk bypasses
   it. The workflow that runs `check` is the pull request's own copy, so a
   contributor who can edit it in their pull request can skip `check`. Both
   are repository settings carbon cannot see; what to protect is in
   `docs/threat-model.md` ("The root of trust") and `docs/ci.md`.

## Known merge limits

1. **Two concurrent applies can conflict on a slot line or on `current`.**
   Two branches that grant different devices merge cleanly when their new
   slot lines land at different places in the sorted list. They conflict
   when both insert at the same place, or when both wrap the same device.
   The latter is the common case on a linear trunk: the later apply sees
   every grant merged so far and also wraps the person the earlier,
   unmerged apply granted. Either side's line is valid (both wrap the same
   key to the same device); keep either. The conflict-marker error for a
   keys file says so. Two branches that both rotate the same key conflict
   in the keys file: keep either side's whole keys file and run `carbon
   apply` to rotate again. A rotation leaves the secrets file as it is, so
   it does not conflict there; but a value the other side set under its own
   new key then names a key the kept file does not have
   (`secret.unknown-key`) and must be set again.

A rotation no longer conflicts with a branch that adds or changes a secret
(Deviations 9): it changes only the keys file, so a branch cut before the
rotation merges with no conflict in the secrets or keys file. Its new line
is under the retired key and not carried by it, so it is unproven: `check`
lists it in the banner (`secret.stale-key`), and it stays so until a reader
runs `carbon apply --reseal-unproven` or someone sets it again after merging
trunk. A line that replaces trunk's line under the same retired key is
`secret.rolled-back` (error), so a changed secret must be set again after
merging trunk. `set`
and `edit` refuse to seal on a branch whose current key trunk has retired
(Decisions 14), so that branch must merge trunk before it can set or edit
secrets in the scope. The conflict-marker error for a secrets file now
covers only both sides setting the same secret (keep either line).
