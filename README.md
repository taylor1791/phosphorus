Carbon
======

Carbon keeps a monorepo's secrets encrypted inside the repository, next to
the code that uses them. Access is granted per package per environment,
written as plain TOML that is reviewed like code, and enforced by
encryption: a person reads a scope only if its key is wrapped to one of
their devices. There is no server: carbon is one Go binary plus git, and it
works offline.

The design is in
[docs/design.md](docs/design.md).
The proof of concept this replaces is [carbon 0.0.3](https://github.com/taylor1791/carbon).

## Status

**Pre-release. Carbon 1.0 has not been audited by a person.** The code was
written and adversarially reviewed by AI agents (Claude) working from the
design; those reviews found and fixed real security bugs, which is a reason
to expect more. No human has yet reviewed the cryptographic code or the
format. Do not rely on it for secrets whose disclosure you could not
survive until it has had an independent review.

- Hardware and plugin identities (`age1yubikey1…`, `age1se1…`, TPM) are
  accepted through the age plugin protocol but are **untested**.
- There are no tagged releases, signed binaries, or Homebrew package yet.
- The command line and the file format may still change before 1.0.

## Install

Carbon needs Go 1.25 or later to build, and git at runtime.

```sh
CGO_ENABLED=0 go install github.com/taylor1791/phosphorus/cmd/carbon@latest
```

From source:

```sh
git clone https://github.com/taylor1791/phosphorus
cd phosphorus
CGO_ENABLED=0 go build -o carbon ./cmd/carbon
./carbon version
```

`CGO_ENABLED=0` gives a static binary and avoids needing a C compiler. With
Nix: `nix build` builds it, and `nix develop` gives a shell with go, git,
age and sops.

## Quick start

One person, a new repository, two environments. This is a real session,
trimmed; your fingerprint and key ids will differ.

```console
$ git init -q -b main shop && cd shop
$ carbon init --environments dev,prod
Created carbon.toml
Created .carbon/teams.toml

Next: carbon join, then carbon init in each package that has secrets.

$ carbon join --device laptop
notice: this repository has no trunk yet (no remote and no carbon.trunk); reading policy from the working tree until carbon is on trunk.
Created your identity   ~/.config/carbon/identity   (device: laptop)
Added your public key   .carbon/people/ada.toml
Joined team             @engineering   (first person in this workspace)
Fingerprint             bike-three-dream-cancel

You read every environment those teams are granted, because carbon is not on trunk yet.
Next: carbon init in each package directory, declare its secrets, then carbon set <name>.
Commit the carbon files to trunk when ready; from then on access changes go through review.

$ mkdir -p services/api && cd services/api
$ carbon init
Created services/api/carbon.toml
```

Declare the package's secrets and the environment its process gets, in
`services/api/carbon.toml`:

```toml
name = "api"

[secrets]
db_password = { description = "Postgres password" }
session_key = { description = "Cookie signing key", generate = "random:32" }

[env]
DATABASE_URL = "postgres://api:${db_password}@localhost:5432/api"
SESSION_KEY  = "${session_key}"
```

Set the values. They come from a hidden prompt or stdin, never from an
argument.

```console
$ printf %s "correct-horse" | carbon set db_password
Created the key for api/dev, wrapped to the 1 device that policy names.
Sealed. Commit services/api/.carbon/dev.keys.toml and services/api/.carbon/dev.secrets.toml

$ carbon set session_key --generate
Generated 32 random bytes for api/dev session_key. Nobody has seen it.
Commit services/api/.carbon/dev.secrets.toml

$ carbon ls
api/dev

NAME          STATE    SET                    KEY
db_password   sealed   2026-11-17T05:09:26Z   k59thq
session_key   sealed   2026-11-17T05:09:26Z   k59thq

$ carbon run -- printenv DATABASE_URL
postgres://api:correct-horse@localhost:5432/api
```

`check` is the CI gate. Before the repository has a trunk it needs
`--bootstrap`, and it insists that every declared secret has a value in
every environment:

```console
$ carbon check --bootstrap
...
error[secret.unset] api/prod: db_password is declared in services/api/carbon.toml but has no value in api/prod.
    carbon set db_password --package api --env prod
...
check failed: 2 errors, 0 warnings.

$ printf %s "prod-horse" | carbon set db_password --env prod
$ carbon set session_key --generate --env prod
```

Commit, and tell this clone which branch is trunk. `git config` is local to
this clone and is never committed; it is needed here only because the
repository has no remote yet. Once you push and others clone, carbon uses
the remote's default branch (`refs/remotes/origin/main`), and you should
remove the setting: `git config --unset carbon.trunk`.

```console
$ cd ../.. && git add -A && git commit -qm "Adopt carbon"
$ git config carbon.trunk main
$ carbon check
Compared with trunk: refs/heads/main at 300eac5 (from git config carbon.trunk)

check passed: 0 errors, 0 warnings.

$ carbon status
You are ada (laptop). Environment: dev.

Readable   2 scopes in dev, prod
```

From here on, access changes go through pull requests, as below.

## How access works

A **scope** is one package in one environment, and has its own key.
**Policy** says who may read each scope: the `[access]` table of the root
`carbon.toml` (the default for every package) or of a package's
`carbon.toml`, naming teams (`@payments`), people (`ada`) and machines
(`machine:deploy-checkout`). People are files in `.carbon/people/` with a
public key per device, written by `carbon join`; teams are
`.carbon/teams.toml`.

**Trunk** is the branch whose files have been reviewed: the remote default
branch, or what `CARBON_TRUNK` or `git config carbon.trunk` name, always
resolved to a branch (never a tag). Carbon reads policy and public keys from
trunk, never from your working tree, when it grants access. A branch cannot
grant itself anything, provided nobody can push to trunk without review.

Access changes in two steps:

1. Policy changes in a pull request: `carbon join` (a new person or
   device), `carbon request <package> --env <env>` (ask for a scope),
   `carbon remove <person>` (offboard). Code owners review and merge it.
2. After it merges, any current reader of the scope runs **`carbon apply`**.
   It wraps the scope key to new readers, rotates the key when someone was
   removed or a device's key changed, and promotes drops. It commits
   exactly the files it changed. That commit is reviewed too: `check`
   lists it in its banner, and the reviewer confirms the author is a
   current reader.

Anyone can add a secret to a scope they cannot read: `carbon set` then
writes a **drop**, encrypted to the scope's inbox key. Readers can use it at
once; `check` lists it for review; the next `apply` seals it.

## Commands

| Command | Purpose | Needs read access |
|---|---|---|
| `carbon run -- <cmd>` | Run a command with the package's `[env]`, decrypted in memory | Yes |
| `carbon set <name>` | Seal a secret, or drop one into the inbox | No |
| `carbon get <name>` | Print a secret's value | Yes |
| `carbon edit` | Bulk-edit a scope's secrets in `$EDITOR` | Yes |
| `carbon ls` | List secret names and their state | No |
| `carbon export` | Write resolved values to an ignored file (dotenv or JSON) | Yes |
| `carbon env` / `env use <name>` | Show or pick the environment for this worktree | No |
| `carbon status` | What you can read, grant, and should rotate | No |
| `carbon join` | Create an identity and add its public key (`--machine` for CI) | No |
| `carbon request <package>` | Propose yourself (or `--as` a reader) in policy | No |
| `carbon apply` | Carry out merged policy: wrap, rotate, promote drops | Yes |
| `carbon remove <who>` | Remove a person, device or machine from policy | No |
| `carbon trust <package>` | Accept a scope key that replaced the one you verified | Yes |
| `carbon check` | Validate graph, policy and keys without a key; the CI gate | No |
| `carbon who <package>` / `access <who>` | Explain who reads what, and through which rule | No |
| `carbon graph` | The package dependency graph, as DOT | No |
| `carbon doctor` | Diagnose the local setup | No |
| `carbon init` | Create a workspace or a package | No |
| `carbon rename <old> <new>` | Rename a package, re-sealing its secrets | Yes |

`carbon help` lists them with their exit codes; `carbon <command> --help`
explains each. Every command takes `--json`.

## CI and deploys

Run `carbon check` on every pull request and push, with trunk fetched and
named in full: `CARBON_TRUNK=refs/remotes/origin/main`. Forbid direct pushes
to trunk (on trunk, `check` compares trunk with itself), and protect
`.github/workflows/` and `CODEOWNERS`: the workflow that runs `check` comes
from the pull request being checked. Deploy secrets belong in a GitHub
Environment restricted to the default branch, and CI must check the merge
result of a pull request, not the branch alone. Deploy jobs use a machine identity
(`carbon join --machine <name>`), supplied as `CARBON_IDENTITY`, and run
`carbon run --env prod -- ./deploy`. [docs/ci.md](docs/ci.md) has a GitHub
Actions example and explains the review banner, `--strict` and
`--max-debt`.

## Migrating from carbon 0.0.3

`carbon` refuses a 0.0.3 repository and points at `carbon-migrate`, a
separate tool that converts the files and re-seals every value through the
`carbon` command line. See [migrate/README.md](migrate/README.md).

## Security model

Encryption protects secrets from everyone who cannot change trunk; review
protects trunk. Values are sealed with XChaCha20-Poly1305 under a 32-byte
key per scope, and each scope key is wrapped with age to each reader
device, hybrid post-quantum (ML-KEM-768 with X25519) by default. CI checks
everything it can without a key, and every reader command checks the
scope's keys against trunk's and against the key it last verified in this
clone (its pin) before using it.

What carbon does not protect against, stated plainly:

- **A keyless check cannot tell a reader's key change from a forged one.**
  New scope keys, rotations and new slots pass `check` when well formed;
  they are listed in a banner, and a person must confirm the author is a
  current reader.
- **A removed reader who kept the previous key can forge a rotation** that
  passes `check` and the pins. Only review of the commit's author catches
  it.
- **A scope's first key is trusted on review.** Whoever made it can read
  what is later set in the scope.
- **Pins do not protect fresh clones or CI jobs**, which trust the first
  key they see on trunk.
- **Rotation does not un-share.** A removed person keeps what they could
  read; carbon lists those secrets as rotation debt, to be changed at their
  source.
- **Names, readers and set times are not secret**, and git history is
  permanent.

[docs/threat-model.md](docs/threat-model.md) has the full adversary table
and limits.

## Known issues

These came out of the final review and are not fully closed:

- **CI protection is outside carbon.** `check` is only a gate if trunk
  cannot be pushed to directly, the workflow that runs it cannot be edited
  by the pull request it judges, and deploy secrets are released only to
  the default branch (a GitHub Environment with a deployment branch
  policy). carbon cannot verify any of these; [docs/ci.md](docs/ci.md)
  says how to set them up.
- **A rename and a directory move in one change is not recognised.**
  `check`, `apply` and readers accept a `carbon rename` only while the
  package stays in its directory; move it in a separate pull request.
  For a renamed scope `check` compares structure only (key ids, slot
  devices and their recorded keys, names and set times), because every
  ciphertext changes; the banner asks the reviewer to confirm the author.
- **Set times are chosen by their writer.** `check` rejects a re-dated line
  (`secret.redated`) and any set time more than ten minutes in the future
  (`secret.future`), and debt uses trunk's set time for an unchanged line,
  but a reader can still seal a new value with a back-dated set time.
- **A symbolic link as the root `carbon.toml`** stops every command,
  `check` included, with an error rather than a finding; links in package
  files and `.carbon` directories are findings.
- **Trunk names that are both a local and a remote-tracking branch** (a
  local branch called `origin/main`) are refused until you name the full
  ref.

## Recovering a secret without carbon

Every secret can be decrypted with the stock `age` CLI (1.3 or later for
hybrid keys) and a short Python script: [docs/format.md](docs/format.md)
specifies the format, `tools/decrypt.py` is the reference decryptor, and
`testdata/vectors/` has test vectors.

## FAQ

### Which age implementation does Carbon use, and why is Carbon written in Go?

Carbon is written in Go and links [`filippo.io/age`](https://filippo.io/age),
the reference implementation of age, as a library. It does not shell out to an
`age` binary, and it does not use sops or rage. You do not need age installed
to run Carbon.

The language follows from that choice, not the other way round. Carbon wraps
every key with age, so it uses the implementation that defines the format:

- **It is stable.** `filippo.io/age` has been at 1.x since 2021. The Rust `age`
  crate (the library behind rage) describes every release before 1.0.0 as beta
  in its [changelog](https://github.com/str4d/rage/blob/main/age/CHANGELOG.md);
  the latest is 0.12.1.
- **It has post-quantum keys today.** Wrapped keys live in git history forever,
  so they should survive a future quantum computer. Go age has had native
  hybrid recipients (ML-KEM-768 with X25519, `age1pq1...`) since
  [v1.3.0](https://github.com/FiloSottile/age/releases/tag/v1.3.0), released
  2025-12-27. In Rust the same recipient is a draft pull request,
  [str4d/rage#632](https://github.com/str4d/rage/pull/632), targeted at
  rage 0.13.0 and not yet released.

Checked on 2026-11-15. The keys Carbon wraps are standard age files, so any
age implementation that supports the recipient type can open them. For hybrid
keys that excludes rage until the pull request above is released.

### Why does carbon need to know trunk?

Because a branch must not be able to grant itself access. If carbon read
policy from your working tree, anyone could add their name to an access
list on a branch and ask a reader to run `apply` there. So `apply` reads
policy and public keys from trunk, `check` compares every keys file with
trunk's, and readers refuse a key that does not descend from trunk's.

Trunk is chosen by the clone, not by a file carbon reads from the
repository: `CARBON_TRUNK`, else `git config carbon.trunk`, else the remote
default branch, always resolved to a branch ref, never a tag. In CI, set
`CARBON_TRUNK=refs/remotes/origin/main` and fetch that ref; if carbon cannot
find trunk it stops rather than guess. In CI the variable is set by the
workflow file, which the pull request under test can change: protect
`.github/workflows/` with CODEOWNERS or run `check` as a required workflow
from a repository ruleset (see docs/ci.md). A repository with no protected branch can set
`carbon.trunk` to `worktree`, and `check` warns that nothing is then
reviewed.

### What happens to existing secrets when someone is removed?

`apply` rotates the scope key: a new key and inbox, wrapped to the readers
who remain, with the old key retired and sealed under the new one. It does
not touch the secrets file. The person removed has already seen every
existing value, so re-sealing them would protect nothing; they stay under
the old key id and keep opening through the retired key. A rotation commit
changes only the keys file, so a branch cut before the removal that added
or changed a secret merges without a conflict. An added secret is then
reported as unproven (below); a changed one is under a key trunk has
retired and differs from trunk's line, so `check` fails it
(`secret.rolled-back`) until you merge trunk and set it again.

What protects you is changing the credentials themselves: every value set
before the removal owes a rotation (`carbon status`, `carbon check --max-debt`)
until someone sets it again, which seals it under the new key. Values set
after the rotation are under the new key, which the removed person never
had.

The retired key records which lines it carried at the rotation. A value
added under it later (for example on that old branch) is not among them,
so carbon reports it as unproven (below).

Two branches that both ran `apply` can still conflict in a keys file: on a
slot line (keep either, both wrap the same key) or, if both rotated, on
`current` (keep one side's whole keys file and run `apply` again; a value the
other side set under its own new key must then be set again).

### What is a drop?

A value set by someone who cannot read the scope. `carbon set` encrypts it
to the scope's inbox key, which only readers can open, and stores it marked
as a drop. Readers can use it at once; `check` lists it in its review
banner, because carbon cannot tell who wrote it; the next `carbon apply` by
a reader seals it as an ordinary value. An environment can refuse drops with
`drops = false` in its `[access]` entry.

### What does "unproven" mean?

A value stored under a retired scope key that the key's record does not
list as carried: it was written after the rotation, usually on a branch
cut before it. (Values that were under the key when it was retired are
carried and are ordinary values.) Writing it needed the retired key, which
the person whose removal caused the rotation may still hold, so carbon
cannot say a current reader wrote it. `ls` and `status` mark
it, `check` lists it in the banner, and `apply` leaves it as it is unless
you pass `--reseal-unproven`, which re-seals it under the current key and so
vouches for it. Carbon also refuses to seal a new value under a key trunk
has retired: merge trunk first.

### What is the pin, and what does `carbon trust` do?

Each clone remembers, per identity, the last key it verified for each scope
(in `.git/carbon/pins.toml`, outside the work tree). If a scope's key is
later replaced by one that does not follow from the pinned key (for example
a forged key that was merged), reader commands refuse it. A legitimate
rotation is followed automatically, because the keys file keeps the old key
sealed under the new one.

`carbon trust <package> --env <env>` shows the pinned and current keys and
the commit that last changed the keys file, asks for confirmation, and pins
the current key. Use it only when you know why the key changed (for example
a scope was deliberately re-created), or to accept a new scope's key on a
branch before it merges. Pins do not help a fresh clone or a CI job, which
have none.
