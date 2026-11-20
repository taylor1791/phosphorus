# Carbon 1.0 implementation contract

`docs/design.md` says what Carbon does and why. This file pins down everything
the design leaves open, so that code written in parallel agrees. Where the two
disagree, the design wins on intent and this file wins on detail. If you must
deviate from this file, write the deviation and the reason in
`docs/deviations.md`; do not deviate silently.

## Toolchain

- Go 1.25. Not installed globally: run everything as
  `nix shell nixpkgs#go -c go ...` (add `nixpkgs#git` etc. as needed).
- `flake.nix` at the repo root has a dev shell (`nix develop`: go, git, age,
  sops) and a package `carbon` built with `CGO_ENABLED=0`.
- Module path `github.com/taylor1791/phosphorus`. Binary `carbon` at
  `cmd/carbon`.
- Allowed dependencies: `filippo.io/age` (v1.3.2 or later; hybrid keys need
  1.3), `golang.org/x/crypto`, `golang.org/x/term`, `golang.org/x/sys`,
  `github.com/pelletier/go-toml/v2`, `github.com/spf13/pflag`. Anything else
  needs a line in `docs/deviations.md`.
- Never shell out to `age`, `sops`, or a shell. The only external program
  `carbon` runs is `git` (and the user's command in `run`, `$EDITOR` in `edit`).
- Config is data. Nothing in any TOML file is ever executed.
- Secret values are never logged, never put in error messages, never passed as
  process arguments, and never written to disk except by `export` and `edit`.
- `CARBON_IDENTITY` and `CARBON_IDENTITY_FILE` are removed from the environment
  of every subprocess carbon starts (`gitx.ScrubbedEnviron`), including the
  child of `run`.

## Names

| Thing | Pattern |
|---|---|
| package, environment, person, device, machine, team | `[a-z0-9][a-z0-9_-]*` |
| secret, var | `[A-Za-z_][A-Za-z0-9_]*` |
| `[env]` key (process variable) | `[A-Za-z_][A-Za-z0-9_]*`, case-sensitive |
| key id | `k` followed by 5 characters of `[a-z0-9]`, unique within a scope's history |

Reserved package names: `carbon`, `env`. A scope is written `<package>/<env>`.
A device is written `<person>/<device>`; a machine is written `machine:<name>`.
Secrets and vars share one namespace inside a package; a name in both is a
`check` error.

## Files people write

### Workspace `carbon.toml` (repo root)

```toml
[workspace]
format = 1
environments = ["dev", "staging", "prod"]
default_environment = "dev"

[access]
dev  = ["@engineering"]                                        # short form
prod = { readers = ["@sre"], require_pq = true, drops = false } # long form
```

An `[access]` value is a list of readers, or a table with `readers` and the
optional booleans `require_pq` (default false) and `drops` (default true).
A reader is `@team`, `person`, or `machine:name`.

The root file may also be a package (it then has `name`).

A file with a `[push]` or `[pull]` table is a carbon 0.0.3 file: every command
stops with an error that points at `carbon-migrate`.

### Package `carbon.toml`

```toml
name = "checkout"

[access]                     # per environment, replaces the workspace entry
prod = ["@payments", "machine:deploy-checkout"]

[secrets]
session_key    = { description = "...", generate = "random:32" }
stripe_api_key = { description = "...", rotate_after = "90d", private = true }

[vars.public_url]            # env -> string, optional "default" key
dev  = "http://localhost:3000"
prod = "https://checkout.example.com"

[env]
SESSION_KEY  = "${session_key}"
DATABASE_URL = "postgres://checkout:${db.password}@${db.host}:5432/checkout"
AWS_PROFILE  = "${env:AWS_PROFILE}"
```

Package access for an environment: if the package names the environment in
`[access]`, its `readers` replace the workspace's. `require_pq` and `drops`
are inherited from the workspace unless the package's long form sets them.

Durations are `<n>d` or `<n>h`. `generate` is `random:<bytes>`; the generated
value is the bytes in unpadded URL-safe base64.

Templates: `${name}` is this package's secret or var; `${pkg.name}` is another
package's (refused if that secret is `private = true`); `${env:NAME}` is the
calling process's environment (an error if unset); `${carbon.env}` is the
environment name; `$$` is a literal `$`. Anything else after `$` is an error.

### People, machines, teams

```toml
# .carbon/people/ada.toml
name = "Ada Okafor"
[devices]
laptop = "age1pq1..."

# .carbon/machines/deploy-checkout.toml
description = "checkout deploy job"
key = "age1pq1..."

# .carbon/teams.toml
engineering = ["ada", "lin"]
```

A team lists people only. A person reader means all of that person's devices.

## Files carbon writes

Written by a deterministic writer: keys sorted, one logical item per line, LF
endings, a trailing newline. Read back strictly (unknown keys are errors).
Nothing marks keys files as generated (no `linguist-generated` line in
`.gitattributes`): review tools must show which key and slot lines changed.

### `<package dir>/.carbon/<env>.secrets.toml`

```toml
session_key = { key = "k3f9q2", set = 2026-11-02T17:04:11Z, value = "carbon1:..." }
webhook_secret = { key = "k3f9q2", set = 2026-11-10T08:12:40Z, drop = "age1:..." }
```

Exactly one of `value` or `drop`. `set` is UTC, whole seconds.

### `<package dir>/.carbon/<env>.keys.toml`

```toml
scope = "checkout/prod"
current = "k3f9q2"

[keys.k3f9q2]
created = 2026-11-02T17:04:11Z
inbox = "age1pq1..."
inbox_sealed = "carbon1:..."

[keys.k3f9q2.slots]
"lin/laptop" = { to = "sha256:...", slot = "age1:..." }
"machine:deploy-checkout" = { to = "sha256:...", slot = "age1:..." }

[keys.k1a8c0]
created = 2026-06-01T10:00:00Z
retired = 2026-11-02T17:04:11Z
reason = "removed sam"
successor = "k3f9q2"
sealed = "carbon1:..."
carried = ["sha256:...", "sha256:..."]
```

A retired key keeps no slots and no `inbox`; it may keep `inbox_sealed` so
that drops written to its inbox on older branches still open. A retired
key has a required `carried` list, written on one line after `sealed`
(`store.Key.Carried`): sorted, without repeats, each element `sha256:` and
the hex SHA-256 of the canonical secrets-file line of an entry that was
under that key when it was retired, exactly as the deterministic writer
emits it (`<name> = { key = "<id>", set = <time>, value = "<blob>" }`, or
`drop =`), without the trailing newline (`store.EntryLine`,
`store.LineHash`). Only entries whose `key` is the retired id are listed;
the list may be empty. The strict reader refuses a retired key without
`carried` and a current key with one. `carried` is authenticated by the
retired `sealed` blob (Encodings). `reason` is
what `apply` rotated for: `removed <who>` for a removal, `rekeyed <device>`
for a device whose public key changed, or both (`removed sam, rekeyed
ada/laptop`), each list comma-separated when several. The code that builds
it is `scope.RotationReason`, shared by `apply` and `check`; `check`
requires a rotation's reason to be exactly what it computes from trunk's
key and trunk policy.

## Symbolic links

carbon never reads or writes its files through a symbolic link: one
committed to the repository could point anywhere on the machine of whoever
runs carbon. Every command refuses, with an error that names the path, a
symbolic link anywhere in the path of a `carbon.toml` read from the working
tree (`config.DirSource`, `config.NoSymlinks`: each component under the
workspace root is checked with `lstat`), of the root `.carbon/` policy files
(people, machines, teams), of a package's `.carbon/` directory, and of the
scope files in it (for a keys or secrets file, the file and its `.carbon`
directory; `config.NoSymlinkFile`, on read and on write). `check` reports
each such link as `file.symlink` (**error**) and does not read through it;
a symlinked root `carbon.toml` stops `check` with an error, since there is
no workspace to judge.

## Encodings

Base64 here always means standard alphabet without padding, strict: unused
trailing bits are zero and the text has no line breaks. Decoders reject
anything else, so each blob has exactly one encoding.

### Sealed blob: `carbon1:<base64(nonce || ciphertext)>`

XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305.NewX`), 24 random
nonce bytes from `crypto/rand`, 32-byte scope key. The associated data is the
UTF-8 of the lines below joined with `\n` (no trailing newline). Names cannot
contain newlines, so the encoding is unambiguous.

| Blob | Key | Plaintext | Associated data lines |
|---|---|---|---|
| secret value | scope key `<key id>` | the value bytes | `carbon/v1/value`, package, env, secret name, key id, set time |
| `inbox_sealed` | scope key `<key id>` | the inbox identity string | `carbon/v1/inbox`, package, env, key id |
| retired `sealed` | the successor key | the retired key's 32 bytes | `carbon/v1/retired`, package, env, retired key id, successor key id, retired time, reason, carried digest |

Times in associated data are RFC 3339 UTC with whole seconds, e.g.
`2026-11-02T17:04:11Z`. The carried digest (`seal.CarriedDigest`) is the
hex SHA-256 of the retired record's `carried` elements, as written, joined
with `\n` (no trailing newline); an empty list hashes the empty string.
A reader walking the retired chain therefore rejects an edited `carried`
list as tampering (`ErrTampered`).

### Slot: `{ to = "sha256:<hex>", slot = "age1:<base64(age file)>" }`

One line per slot, an inline table with both fields required. `to` is
`sha256:` and the hex SHA-256 of the recipient string the slot was wrapped to,
exactly as written in the people or machine file (`agewrap.RecipientHash`,
`policy.Device.RecipientHash`). It is not authenticated by cryptography;
`check` protects it: a slot on trunk's current key may not be removed or
altered while `current` is unchanged, and a new slot's `to` must equal the
hash of trunk policy's key for that device. `apply` treats a slot whose `to`
differs from the device's current policy key as a revocation and a grant
(`SlotDiff.Rekeyed`): it rotates. A bare-string slot (the earlier form) is a
parse error.

`slot` is a binary age file encrypted to exactly one recipient. Plaintext:

```
carbon/v1/slot
<package>/<env>
<key id>
<base64 of the 32-byte scope key>
```

(each line ends with `\n`). On open, the scope and key id must match the file
it came from.

### Drop: `age1:<base64(age file)>`

A binary age file encrypted to the scope's current inbox recipient. Plaintext:

```
carbon/v1/drop
<package>
<env>
<secret name>
<set time>
<base64 of the value>
```

On open, package, env, name and set time must match the line it sits on.

### Inbox key

A hybrid age key pair generated with each scope key. The public half is
`inbox`; the identity string is sealed as `inbox_sealed`. Every time a reader
opens a scope key, carbon unseals `inbox_sealed`, derives its recipient, and
fails loudly if it differs from `inbox`.

## Identities

- `carbon join` generates a hybrid identity (`age.GenerateHybridIdentity`) by
  default; `--x25519` generates a classic one. It writes
  `$XDG_CONFIG_HOME/carbon/identity` (default `~/.config/carbon/identity`),
  mode 0600, in age identity-file format. `--passphrase` stores it as a
  scrypt-encrypted age file; carbon then prompts when it needs the key.
- `CARBON_IDENTITY` holds identity file *content* and overrides the file.
  `CARBON_IDENTITY_FILE` overrides the path.
- Who you are is derived: carbon computes the recipient of each loaded
  identity and looks it up in the people and machine files. Nothing about the
  person is stored beside the key.
- X25519 recipients (`age1...`) and identities are accepted everywhere.
  Plugin recipients (`age1<plugin>1...`) are accepted through
  `filippo.io/age/plugin`; they are untested without hardware and that is
  stated in the README.
- Fingerprint: four words chosen by the first 44 bits of SHA-256 of the
  recipient string, 11 bits each, from an embedded 2048-word list.
- `join` defaults: person = `--person` or lower-cased `$USER`; device =
  `--device` or the short hostname, lower-cased and sanitised. A second `join`
  for an existing person adds a device. `join --machine <name>` writes the
  machine file and prints the private key once, to stdout, and stores nothing.

## Trunk

Policy (workspace and package `[access]`, people, machines, teams) and inbox
public keys are read from the trunk commit with `git ls-tree` and
`git cat-file`, never from the working tree, in these commands: `apply`, the
drop path of `set`, scope creation, the trunk check every reader runs (below),
and the slot checks in `check`.

**Choosing the ref.** Nothing a commit can change chooses the trunk. In order:

1. the environment variable `CARBON_TRUNK` (a branch ref, or `worktree`);
2. the clone's local git config `carbon.trunk` (a branch ref, or `worktree`);
3. the remote default branch: the target of `refs/remotes/origin/HEAD`, else
   `refs/remotes/origin/main`, else `refs/remotes/origin/master`, whichever
   exists first, always as the full ref.

carbon never writes git config itself (`carbon init --trunk <ref>` runs
`git config carbon.trunk <ref>` because the user asked). A ref name must
match `[A-Za-z0-9][A-Za-z0-9._/-]*`, must not be `HEAD`, must not contain
`@`, `:` or `..`, and must not end in `/` or `.lock`; `worktree` is the one
special word. `[workspace] trunk` no longer exists: a workspace file that has
it is an error telling the user to delete it and use git config or
`CARBON_TRUNK`.

**Resolving the ref: a branch and a commit, never a tag.** Once per command,
trunk is resolved to a full branch refname and the commit it points to
(`policy.ResolveTrunk`, `gitx.Repo.ResolveBranchRef`, one git process).
git's own lookup tries `refs/tags/<x>` before `refs/heads/<x>` and
`refs/remotes/<x>`, and CI usually fetches tags, so a pushed tag named
`main` or `origin/main` would otherwise stand in for trunk. A configured
value (1 or 2) is either:

- a full ref under `refs/remotes/` or `refs/heads/`, used as is; or
- a short name, looked up as exactly `refs/remotes/<name>` and
  `refs/heads/<name>`. If both exist it is an error asking for the full ref.

A value under `refs/tags/` or any other `refs/` namespace is refused. A ref
that does not point at a commit does not resolve. Every read of trunk in the
command uses the resolved commit (`Trunk.Commit`, `Policy.At()`), not the
ref name. `policy.Trunk` records the full ref, the name as configured, the
commit and where it came from (env, git config, remote default, none).
`check`'s first line, `apply`'s plan header, `doctor` and `status` show
trunk as the full ref and the short commit:
`refs/remotes/origin/main at 3f9c2a1`. `check --json` reports it as
`trunk.ref` and `trunk.commit`. CI should set
`CARBON_TRUNK=refs/remotes/origin/main` (the full ref of its protected
branch) and fetch it.

**Errors, never fallbacks.** An override (1 or 2) that does not resolve, or
that is ambiguous, is an error. A remote default that points nowhere is an
error. If the repository has remote-tracking refs but none of rule 3's
candidates and no override, that is an error whose hint is
`git remote set-head origin -a`, `git fetch`, or
`git config carbon.trunk <ref>`.

Two documented exceptions read policy from the working tree:

1. **Bootstrap.** The chosen ref resolves but has no root `carbon.toml`, or its
   root `carbon.toml` parses and has no `workspace` key at all (a carbon 0.0.3
   service: carbon 1.0 is not adopted on trunk yet, the carbon-migrate cutover
   branch; a root with `[workspace]` is loaded as usual, so a stray `[push]` or
   `[pull]` there is still the legacy error), or no ref can be chosen
   because the repository has no remote-tracking refs and no override (a
   brand-new local repository). Every command except `check` then reads
   policy from the working tree and prints a one-line notice. `check` never
   bootstraps by itself: in each of these cases it exits 1 unless
   `--bootstrap` is given (see the `check` rules). A 0.0.3 file in the
   working tree is still the error that points at carbon-migrate.
2. **No protected trunk.** `worktree` from `CARBON_TRUNK` or git config reads
   policy from the working tree always. `check` reports this as a warning.

**Readers check the keys file against trunk.** After opening a scope, every
command that reads or seals (`get`, `run`, `export`, `set`, `edit`, `apply`,
`rename`) compares the working tree's keys file with trunk's for that scope,
when trunk is a ref and has one (`scope.Opened.VerifyTrunk`):

- same `current` id: the working tree's `inbox` and `inbox_sealed` for it must
  equal trunk's;
- the working tree's current key is a key trunk has retired (the branch is
  behind, or reverted a rotation): accepted for reading, and when trunk's
  record keeps `inbox_sealed` the opened key must unseal it. `set` and `edit`
  refuse to seal under it (exit 1): a value sealed under a retired key is
  readable by whoever it was retired from. The fix is to merge trunk;
- trunk's current key is a retired key in the working tree's chain that opened,
  and that key unseals trunk's `inbox_sealed` for that id to trunk's `inbox`
  (the branch rotated past trunk, by someone who held trunk's key): accepted;
- otherwise the command refuses: the scope's key on this branch does not
  descend from trunk's (fix: `git checkout <trunk> -- <keys file>`, or merge
  trunk).

**Readers pin the key they verified.** Once a forged keys file is merged,
trunk equals the forgery and the trunk check passes vacuously. So each clone
remembers, per reader identity, the last key it verified for each scope, in
`<git common dir>/carbon/pins.toml` (shared by the clone's worktrees, never in
the work tree, mode 0600):

```toml
[readers.<first 16 bytes of SHA-256 over the reader's sorted public keys, hex>]
"checkout/prod" = { key = "k3f9q2", fingerprint = "<hex SHA-256 of "carbon/v1/pin\n" || key>" }
```

After the trunk check, on every reader path (`scope.Opened.CheckPin`):

- no pin: pin the current key (trust on first use), with one exception.
  When trunk is a reviewed ref and has no keys file for the scope (the key
  exists only on this branch), carbon cannot tell whether a reader created
  it: the reader may read, nothing is pinned, and `set` and `edit` refuse to
  seal (exit 1) until the reader has a pin for the key or the key is on
  trunk. The reader who created it has a pin; anyone else gets one only with
  `carbon trust`;
- pinned id is the current id: the fingerprints must match;
- pinned id is a retired key that opened through the chain: its fingerprint
  must match the pin, then the pin moves to the current key;
- pinned id not in the chain: accepted, pin unchanged, only when trunk lists
  the working tree's current key as retired (the branch is behind);
- otherwise refuse (exit 1): the key was replaced by someone who did not hold
  the previous key, or the pin is stale. Fixes: `git log -p -- <keys file>`,
  or `carbon trust <package> --env <env>`, which shows the pinned and current
  keys and the last commit to the keys file, asks for confirmation, and
  re-pins.

A key the caller creates (`set`, `apply`) or rotates (`apply`, after saving)
is pinned by the caller. `rename` moves pins to the new scope name. A corrupt
pins file is an error that names the file; deleting it re-pins on next use.
Pins are per clone and per reader identity; what they do not protect is in
`docs/deviations.md` under Limits.

The drop path of `set` also refuses when the working tree lists trunk's
current key as retired (the local trunk ref is behind: `git fetch`).

`status` reads trunk's keys files and runs `check`'s key rules to list the
scopes a reader would refuse; for a scope whose key id changed since the
caller pinned it, it unwraps the key to run the pin check. Everything else
(`who`, `access`, the rest of `status`, `run`'s environment, the graph
checks) reads the working tree.

## Scope lifecycle

- **Creation.** A scope gets its first key when a reader first runs `set` in
  it (or `apply` finds a scope with declared secrets and no key). Only a device
  that trunk policy names for the scope may create it (bootstrap and
  `worktree`: working-tree policy); anyone else gets an error naming the
  readers who can. carbon generates the key and inbox pair and wraps the key to
  every device that policy names. carbon cannot prove who generated a
  scope's first key: a new keys file in a pull request is a trusted act to
  review, like a drop, and `check` lists it (`key.new`).
- **Grant.** `apply`, run by a reader, adds a slot for each device trunk policy
  names that has none.
- **Removal.** When the current key has a slot for a device trunk policy no
  longer names, or a slot whose `to` is not the hash of the device's
  current policy key (re-keyed device), `apply` rotates
  (`scope.Opened.Rotate`): new key and inbox pair, slots for the readers
  that remain, and the old key retired and sealed under the new one with a
  reason naming the removals and re-keys (`removed sam`, `rekeyed
  ada/laptop`, `removed sam, rekeyed ada/laptop`) and a `carried` list of
  every entry under it. **A rotation does not touch the secrets file**: it
  re-seals nothing and opens no value, so a value that does not open does
  not stop it. Existing values and drops stay under the old key id (drops
  in the old inbox) and open through the retired chain. A removed reader
  has seen those values already, so re-sealing them would protect nothing;
  rotation debt lists them. New values are sealed under the new current key
  by `set`, `edit` and drop promotion. A rotation commit changes only the
  keys file, unless the same `apply` also promotes drops.
- **Removed readers cannot write.** `set` refuses (exit 3) when the policy in
  effect no longer names the caller's device for the scope, even while its
  slot still opens the key before the rotation.
- **Drops.** `set` by a non-reader writes a drop to the trunk inbox key.
  Readers open drops transparently in `get`, `run`, `export`. `apply` promotes
  a drop to a sealed value, keeping its `set` time unless that is later
  than now (a dropper chooses it), in which case it becomes now. When trunk
  is a ref, `apply` promotes only a drop whose line is on trunk: trunk's
  secrets file for the scope has the identical entry (same name, `key`,
  `set` and `drop`). Any other drop has not been reviewed; promoting it
  would take it out of `check`'s banner, so `apply` leaves it as a drop and
  lists it in the plan as "not on trunk yet; left as a drop"
  (`DropsNotOnTrunk`). A drop that `carbon rename` re-sealed differs from
  trunk's line, so it stays a drop until the rename merges. Under bootstrap
  and `worktree` trunk every drop that opens is promoted. A drop under a
  retired key that the key carries is promoted like any other (sealed under
  the current key); an unproven drop is promoted only with
  `--reseal-unproven`. Promotion seals under the current key.
- **Old keys (the chain rule).** A value whose `key` is a retired id is opened
  by walking the retired chain from the current key: each retired key is
  unsealed by its `successor`, which must itself be the current key or an
  opened retired key, with the record's `carried` digest in the associated
  data. A retired `inbox_sealed` that fails to open is tampering, and drops
  under it report it.
- **Carried and unproven entries.** An entry under a retired key is
  *carried* when its line hash (`store.LineHash`) is in that key's `carried`
  list, and *unproven* otherwise; an entry under a key id the keys file does
  not have is unproven too (`scope.IsUnproven`, `scope.StaleEntries`; `ls`,
  `status`, `check`, `apply` and `get` all use this definition). A carried
  entry is an ordinary value or drop that a rotation left in place: `ls`
  shows it as sealed (its KEY column shows the old id), `get` and `run` open
  it without a note, and `status` and `check` say nothing about it beyond
  rotation debt. An unproven entry was written after the rotation by
  someone holding the retired key, which a removed reader still may: `ls`
  marks it "stale: retired key, author unproven", `get` prints a note,
  `status` lists it under "Unproven", `check` warns
  (`secret.stale-key`, `secret.stale-after-retirement`), and `apply` lists
  it and leaves it as it is. Only `apply --reseal-unproven` re-seals
  unproven entries under the current key (`scope.Opened.ResealUnproven`),
  which vouches for them; carried entries are never re-sealed. A drop that
  does not open never blocks promotion or `--reseal-unproven`: it is left
  as it is and reported.
- **Rotation debt.** A secret owes a rotation when its `set` time is at or
  before (`set <= retired`; both are whole seconds) the `retired` time of a
  key whose reason names a removal or a re-key, in any form `apply` writes
  (`audit.Exposed`), or when it is older than its `rotate_after`. Retired
  records are read from trunk and the working tree together, trunk's record
  winning. An entry whose ciphertext (`value` or `drop`) is unchanged from
  trunk's line for the same name is trunk's value: its debt uses trunk's
  `set` time, whatever the line claims, so re-dating a line cannot hide
  debt. A value that owes a rotation stays under the retired key id, since
  a rotation does not re-seal it; debt clears when a new value is set
  (under the current key, with a later `set` time).
- **Conflicts.** If a keys or secrets file contains git conflict markers,
  every command stops with an error that names the file and the fix.

## `check` rules for slots and keys

`check` needs no identity, and therefore cannot tell a key change made by a
reader from one forged with public keys only. It enforces every structural
rule a legitimate `apply` commit satisfies, and lists every key change in a
review banner (below). A passing check on a change to keys files is not "safe
to merge without review": its author must be a current reader. No commit
that changes a keys file, `apply`'s included, is exempt from review. What
this leaves open is in `docs/deviations.md` under Limits.

Trunk: as chosen and resolved in the Trunk section; `check` compares with
the resolved commit. `check` never bootstraps without `--bootstrap`: with
no trunk ref at all (no remote refs, no override), with a trunk ref that has
no root `carbon.toml`, or with a trunk whose root `carbon.toml` is a carbon
0.0.3 file (the carbon-migrate cutover), it exits 1 with what to set,
unless `--bootstrap` is given. Without that rule a trunk pointed at the
wrong branch would make `check` judge every keys file by itself and pass a
forged key.

Scopes are the union of trunk's and the working tree's packages ×
environments. For each scope it compares the working tree with trunk:

- A slot whose device trunk policy names: fine. If the slot is new relative
  to trunk it is listed in the banner (`slot.granted`), and its `to` must be
  the hash of that device's trunk policy key (`slot.recipient`, **error**).
- A slot whose device trunk policy does not name, and which is not on trunk
  (the identical line, `to` included): **error** (`slot.unbacked`). In an
  environment trunk has no access entry for, every slot is unbacked: a
  scope's keys cannot be created before its policy merges.
- A slot whose device trunk policy does not name, and which is on trunk:
  **pending revocation**, a warning (an error under `--strict`). A slot on
  trunk whose `to` no longer matches its device's trunk policy key: the key
  changed, a pending revocation (`slot.rekeyed`, warning).
- A device trunk policy names that has no slot: **pending grant**, reported,
  not a failure (an error under `--strict`).
- When trunk is a reviewed ref and the scope has a key, what the working
  tree's policy changes relative to trunk's: a device it adds is
  `policy.grant-proposed`, a device it removes or gives a new key is
  `policy.revoke-proposed`. Both are info, never raised by `--strict`, so a
  `request` or `remove` pull request shows the grant or rotation it leads
  to. Policy on a branch grants nothing until it is on trunk.
- When trunk is a reviewed ref, the working tree's people and machine files
  against trunk's: a changed public key for an existing person device or
  machine is `policy.device-key-changed`, and a new device for an existing
  person is `policy.device-added`. Both are info, in the banner with the new
  key's four-word fingerprint (to confirm with its owner), and never raised
  by `--strict`. Once merged, `apply` rotates for the changed key and wraps
  scope keys to the new one or to the new device.
- Same `current` as trunk: `inbox` and `inbox_sealed` must equal trunk's, and
  every slot of trunk's current key must be present and identical
  (`slot.removed`): slots are append-only until a rotation. **errors**.
- A different `current`: a rotation, always in the banner (`key.rotated`,
  info, never raised by `--strict`). It is acceptable only if trunk's current
  key had a pending revocation (a slot for a device trunk policy no longer
  names, or a slot whose `to` no longer matches its device's trunk policy
  key: a re-keyed device); trunk's current key is kept as a retired
  record (successor, reason, sealed, trunk's `created` and `inbox_sealed`)
  whose successors reach the new current key; that record's `reason` is
  exactly what `apply` writes, recomputed from trunk's key and trunk policy
  (`scope.RotationReason`); the new key's slots are only
  for devices trunk policy grants, each `to` that device's key hash; it has an
  inbox; every secrets-file entry trunk has is still present and
  byte-identical, except an entry set again under the new current key (an
  ordinary new value); and the new retired record's `carried` is exactly
  the line hashes of trunk's entries under the retired id, recomputed from
  trunk's secrets file (`scope.CarriedBy`). Otherwise **error**
  (`key.changed`).
- `current` is a key trunk has retired: if trunk's tip is an ancestor of HEAD
  it is a rollback, **error**; otherwise the branch is behind and its keys
  file must be unchanged since the merge base (**error** if changed, **error**
  `key.unverified` if the merge base cannot be computed); unchanged is
  `key.behind-trunk`, info.
- Every retired record trunk has is present and identical, `carried`
  included: **error** (`key.retired-changed`) otherwise.
- A keys file only in the working tree: `key.new`, banner. A keys file trunk
  has that is gone while the scope exists, or that stays while its package or
  environment was removed: **error** (`key.removed`); removed together with
  its scope: `scope.removed`, banner. A keys or secrets file that belongs to
  no working-tree scope: **error** (`store.orphan`).
- A rename, as `carbon rename` writes it (`audit/rename.go`): the package
  keeps its directory, the working tree's package name is not on trunk, and
  trunk's keys file in that directory names the old package. Every value,
  drop and slot was re-sealed under the new name, and each retired key's
  `carried` list rewritten to the new lines (so every entry keeps its
  carried or unproven status), so `check` compares the scope with trunk's
  under the old name structurally: the same `current` id; the same key ids
  with unchanged `created`, `retired`, `reason` and `successor`; for each
  key the same slot devices with the same `to`; the same secret names, each
  with the same `key`, `set` time, kind (value or drop) and carried status.
  A match is one `scope.renamed` per scope (info, banner, never
  raised by `--strict`) in place of `key.removed`, `key.new` and
  `trunk.unreadable`; any structural difference is **error**
  (`key.changed`). A renamed scope skips the other comparisons with trunk
  in this list.
- A slot whose age file does not parse or has a recipient-stanza count other
  than one: **error**. `require_pq` scopes: a slot whose stanza type is not the
  hybrid type, a named device whose public key is not hybrid, or an inbox key
  that is not hybrid: **error**.
- A value under an older key than trunk's value for the same name, or a
  line that differs from trunk's under a key trunk has retired (a carried
  value replaced: only someone holding the retired key can write there):
  **error** (`secret.rolled-back`). Under the same current key with an
  earlier `set`: warning, banner (`secret.older-than-trunk`). An unproven
  entry (under a retired key that does not carry it): warning, banner
  (`secret.stale-key`, or `secret.stale-after-retirement` when set after the
  retirement). A carried entry is not reported. An entry under a key id the
  keys file does not have: **error** (`secret.unknown-key`).
- A value with trunk's ciphertext for the same name but a different `set`
  time: **error** (`secret.redated`). The line was re-dated, not set again;
  it no longer opens (the set time is in its associated data), and the new
  time would hide its rotation debt.
- Any entry, value or drop, whose `set` time is more than 10 minutes
  (`audit.ClockSkew`) after now: **error** (`secret.future`). Set times are
  chosen by their writer, and a future one hides rotation debt.
- A drop in an environment where drops are off (in trunk's policy or the
  working tree's): **error**. Any other drop: listed in the banner, not a
  failure.

The remaining rules (graph, declared-versus-stored, reader coverage of
referenced scopes, debt) are in the design under CI, with these additions:

- An `[env]` template that references `${env:CARBON_IDENTITY}` or
  `${env:CARBON_IDENTITY_FILE}`: **error** (`graph.forbidden-env`); `run`
  and `export` refuse it too.
- A stored empty value counts as set (`secret.unset` does not fire), as it
  does for `run` and `export`.
- A symbolic link at a `carbon.toml`, a `.carbon` directory, or a file in
  one: **error** (`file.symlink`), not read through (see Symbolic links).
- Rotation debt (`debt.removal`, `debt.rotate-after`) follows the rule in
  Scope lifecycle.

## Command line conventions

- Global flags, accepted before or after the subcommand and interleaved with
  positionals: `--env <name>`, `--package <name>`, `--json`, `--yes`,
  `-C <dir>`, `--no-color`, `--help`/`-h`, `--version`.
- `carbon help` lists commands in groups (Daily use, Access, Inspection,
  Setup; each command's `Group` field), and prints the global flags and the
  exit-code table. `carbon help <command>` shows that command's own flags
  apart from the global ones. An unknown command is a usage error that
  suggests the nearest command name. `carbon version` and `--version` print
  `cli.Version`: `1.0.0-dev` unless set with
  `-ldflags "-X github.com/taylor1791/phosphorus/internal/cli.Version=..."`;
  a `go install ...@vX` build reports its module version.
- Environment resolution: `--env`, then `CARBON_ENV`, then `carbon env use`
  (stored in the worktree's git dir as `carbon-env`), then
  `default_environment`.
- Package resolution: `--package <name>` or the nearest `carbon.toml` with a
  `name` at or above the current directory.
- Human output on stdout, diagnostics on stderr. With `--json`, stdout is one
  JSON document and an error is
  `{"error": {"code", "message", "details", "hint"}}`.
- Errors say what happened, why, and the next command (see the design's
  example). An error type carries a code, a message, detail lines and a hint.
- Exit codes: 0 success; 1 unexpected error; 2 usage; 3 no access to a scope;
  4 `check` found errors; 5 package, secret or person not found; 6 no usable
  identity; 7 not confirmed. `run` execs the command, so its exit code is the
  command's.
- Commands that change access (`apply`, `remove`, `request`, `rename`) print a
  plan and ask for confirmation. `--yes` skips the prompt. Without a terminal
  and without `--yes` they exit 7.
- `run` replaces the carbon process with the command (`execve`), with no shell.
- `set` reads the value from a hidden prompt on a terminal, otherwise from
  stdin (one trailing newline is stripped). Never from an argument. An empty
  value is refused unless `--allow-empty` is given.
- `edit --allow-empty` means the same. Without it, emptying a set value saves
  nothing and names the flag, and an uncommented `name = ""` for an unset
  secret is ignored; with it, both store the empty value. `run`, `export`
  and `check` treat a stored empty value as set.
- `export` writes mode 0600 and refuses a path git does not ignore; `-` means
  stdout. Formats: `dotenv`, `json`.
- `apply` writes its changes and commits exactly the files it changed, with a
  message that lists what it did. `--no-commit` leaves them unstaged.

## Layout

```
cmd/carbon/            main, nothing else
internal/cli/          one file per command; each registers itself in init()
internal/audit/        check, status and debt rules (no identity needed)
internal/pins/         the per-clone pins file
internal/resolve/      [env] template resolution for run and export
internal/tomledit/     line-preserving edits to people-written TOML
internal/seal/         sealed blobs
internal/agewrap/      slots, drops, recipients, identities, fingerprints
internal/store/        secrets and keys files: parse, deterministic write
internal/config/       workspace, package, people, machines, teams
internal/policy/       access lists to devices, at a ref or in the worktree
internal/gitx/         git plumbing
internal/scope/        scope keys: create, open, rotate, seal, drops, chain
internal/clitest/      helpers for CLI tests: temp git repo, people, run carbon
docs/format.md         the published format, enough to decrypt without carbon
testdata/vectors/      test vectors for the format
tools/decrypt.py       reference decryptor
migrate/               carbon-migrate: its own Go module, uses only the CLI
```

Each command lives in its own file and registers itself, with a `Group` that
places it in `carbon help`, so parallel work adds files and does not edit a
shared list.

## Tests

- Unit tests beside each package.
- CLI tests drive the built binary in a temporary git repository with a
  temporary `HOME`/`XDG_CONFIG_HOME`, through `internal/clitest`. Nothing
  touches the developer's real config or repo.
- Interop tests: a slot and a drop written by carbon open with the real `age`
  command, and a file written by `age` opens in carbon. The `age` binary must
  be 1.3 or later for hybrid keys; build it with
  `go build filippo.io/age/cmd/age` inside the test, or skip with a clear
  message if that fails.
- `go vet ./...` and `go test ./...` must pass before any hand-off.
