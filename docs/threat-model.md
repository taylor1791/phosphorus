# Carbon threat model

This restates the design's threat model (`docs/design.md`, "Threat model")
with what was learned while building and reviewing carbon 1.0. Where the two
differ, this page is current. Carbon has not had an external security
review.

## The root of trust

**Trunk is the root of trust.** Trunk is the branch whose policy and keys
files have been reviewed: the remote default branch, unless a clone or a CI
job names another with `CARBON_TRUNK` or `git config carbon.trunk`. Nothing
a commit can change chooses it. carbon resolves it, once per command, to a
full branch ref (`refs/remotes/...` or `refs/heads/...`) and that ref's
commit, and reads everything from the commit; it never resolves trunk to a
tag, so a pushed tag named `main` or `origin/main` cannot stand in for it.

Encryption protects secrets from everyone who cannot change trunk. Review
protects trunk. So the protections below assume these things you have to
provide:

- **No direct pushes to trunk.** Branch protection (or a ruleset) that
  requires a reviewed pull request for every change to trunk, with no
  bypass. On trunk itself `check` compares trunk with itself, so a commit
  pushed straight to trunk is never checked against anything.
- **Branch protection and CODEOWNERS** on `carbon.toml`, `.carbon/` and
  every package's `carbon.toml` and `.carbon/`, so that access lists, people,
  machines, teams and keys files change only through a review by their
  owners.
- **Protected CI definitions.** The workflow that runs `check` on a pull
  request is that pull request's own copy, so a contributor who can edit it
  can make `check` pass. Put `.github/workflows/**` and `CODEOWNERS` itself
  under CODEOWNERS with review required, or run `check` from a repository
  ruleset's required workflow that the pull request cannot change.
- **`carbon check` as a required status check**, with trunk fetched and
  named by its full ref (`CARBON_TRUNK=refs/remotes/origin/main`; see
  [ci.md](ci.md)). `check` exits 1 rather than compare a branch with itself
  when trunk has no carbon workspace; `--bootstrap` belongs only on the
  change that adopts carbon.
- **Deploy identities only for trunk.** A machine identity that deploys
  belongs in a GitHub Environment secret whose deployment-branch policy
  allows only the default branch. A workflow `if:` condition protects
  nothing: a pull request can change it, and any job that can read the
  secret can print it.

## What each adversary gets

| Adversary | What they get | Why, and what limits it |
|---|---|---|
| Anyone with a copy of the repository and no key | Package names, secret names, reader lists, set times. No values. | Metadata is plaintext by design, so that reviews work. Values and scope keys are encrypted. |
| A contributor who can push branches but reads no scope | Nothing readable from a scope that already has a key. They cannot forge a sealed value or wrap a key to themselves. | Both need the scope key. `apply` reads policy only from trunk. A keys file they forge on a branch fails `check` (`key.changed`, `slot.unbacked`, `slot.removed`), and every reader command (`get`, `run`, `export`, `set`, `edit`, `apply`) refuses a key that does not descend from trunk's. Re-dating a value's set time, or setting one in the future, fails `check` (`secret.redated`, `secret.future`). A symbolic link committed in place of a carbon file or `.carbon` directory is refused by every command and fails `check` (`file.symlink`). |
| The same contributor, pushing a tag named like trunk (`main`, `origin/main`) | Nothing. | Trunk resolves only to a branch ref under `refs/remotes/` or `refs/heads/`, never to a tag, and a configured `refs/tags/...` is refused. |
| The same contributor, editing the CI workflow in their pull request | A passing `check` on a forged keys file or policy change, unless workflows are protected. | The workflow that runs on a pull request is its own copy. Protect `.github/workflows/**` and `CODEOWNERS` (see the root of trust); reviewers who rely on a green check are otherwise relying on the author. |
| The same contributor, proposing a drop | A value of their choosing in a scope, if the pull request is merged. | A drop is marked, listed in `check`'s banner, and reviewed like code. `apply` promotes a drop only once trunk has the identical line, so a reader's `apply` on the unmerged branch leaves it a drop. Environments can turn drops off (`drops = false`). Readers do use a drop at once, on the branch, before review: treat a drop like any unreviewed code you run. |
| The same contributor, replacing a reader's device key or adding a device to a reader's person file | If the pull request is merged and a reader applies: everything that person reads. | `check` lists both in the banner (`policy.device-key-changed`, `policy.device-added`) with the new key's four-word fingerprint; the reviewer confirms it with the device's owner over another channel. |
| The same contributor, creating the **first** key of a scope (a new package or environment) on a branch | If the pull request is merged: every value later set in that scope. | Carbon cannot prove who made a scope's first key. `check` lists it as `NEW SCOPE KEY` in the banner; the reviewer must confirm the author is a reader. Before merge, readers will not seal under a key that exists only on someone else's branch (unless they run `carbon trust`), and `apply` will not touch it. |
| Someone who can merge to trunk without review, or push to trunk directly | Whatever they merge or push: a forged key or policy then *is* trunk. | This is the root of trust. `check` does not stop a direct push: on trunk it compares trunk with itself. Forbid direct pushes and bypasses. A reader who opened the scope before in the same clone refuses a key that replaced the one they pinned (`carbon trust` to accept it after investigating). New clones and CI jobs have no pins and accept it. |
| A workflow on another branch that can read a deploy machine's identity | Everything that machine reads. | Keep deploy identities in a GitHub Environment secret with a deployment-branch policy limited to the default branch; an `if:` condition in the workflow protects nothing. |
| A current reader | Everything in their scopes, and the ability to copy it anywhere. | Not preventable by any design. Scopes keep the blast radius small, and git records who granted what. |
| A removed reader, or a stolen device, before the rotation is applied | Everything the device could read until a reader runs `apply` after the removal merges. | `carbon remove` changes policy; the key rotates only when a reader applies it. `check` warns about the pending revocation (an error under `--strict`). A removed reader cannot `set` once the removal is on trunk. |
| A removed reader after the rotation | Every value set before the rotation, from git history. | Keys rotate, so values set afterwards are safe. A rotation does not re-seal existing values: they stay under the retired key, because the removed reader has seen them already and re-sealing would protect nothing. Rotation debt (`carbon status`, `check --max-debt`) lists every secret to change at its source; `check` requires a rotation's recorded reason to be the one `apply` computes from trunk, and counts debt from trunk's set time for a value whose line is unchanged from trunk, so neither can be edited to hide debt. Carbon never seals a new value under a key trunk has retired: `set` and `edit` on a branch that is behind (or that reverted a rotation) refuse until trunk is merged. |
| A removed reader who writes a value under the retired key they kept | A value of their choosing under that key, if it is merged. | The retired record lists, as `carried`, the line hash of every entry under the key when it was retired, and the list is authenticated (its digest is in the retired `sealed` blob's associated data, so readers reject an edited list). A line written later under the retired key is not carried: it is unproven, `ls`, `status` and `check`'s banner (`secret.stale-key`, `secret.stale-after-retirement`) mark it, and `apply` re-seals it only with `--reseal-unproven`. Replacing a carried line is `secret.rolled-back` (error); a rotation commit that changes trunk's secrets-file lines or carries other lines than trunk's fails `check` (`key.changed`). |
| A removed reader who still has the previous key and can get a commit merged | A **forged rotation**: a new key of their own, structurally identical to what `apply` writes. | Keyless `check` cannot tell it from a real rotation, and readers' pins accept it (the previous key is in the chain). `check` lists every rotation in the banner (`key.rotated`); the defence is a reviewer confirming the author of a key-changing commit is a current reader. |
| Someone holding a stolen identity file | Whatever that device can read. | A passphrase on the identity file (`carbon join --passphrase`) stops this. `carbon remove ada/laptop`, merged and applied, rotates the affected scopes. Hardware and plugin identities are supported by the format but untested. |
| Malware running as the developer | Whatever the developer can read. | Out of scope. `run` passes secrets only to the child process and writes nothing to disk; `export` writes only where asked. |
| A tampered `carbon` binary | Everything the user decrypts with it. | Build from source you have reviewed, or a pinned version; there are no signed releases yet. The format can be read without the binary (`docs/format.md`, `tools/decrypt.py`). |

## Limits

These are the things carbon does not protect against. They follow from the
choices that make it work offline, without a server, on ordinary branches.

- **`check` holds no key.** It cannot open a slot, so it cannot tell a
  reader's key change from one forged with public keys only. It enforces
  every structural rule a legitimate `apply` commit satisfies and lists
  every key change, every drop and every unproven value (under a retired
  key that does not carry it) in its review banner. A passing `check` on a
  change to keys files is not safe to merge without review.
- **`check` is only as strong as the CI around it.** It does not run
  against anything on a direct push to trunk (trunk compared with itself),
  and a pull request that can edit the workflow running it can skip it.
  Forbidding direct pushes and protecting `.github/workflows/**` and
  `CODEOWNERS` are repository settings carbon cannot see or enforce.
- **A forged rotation by a removed reader** who kept the previous scope key
  passes `check` and the readers' pins (see the table). Only review of who
  authored the commit catches it.
- **A scope's first key is trusted on review.** Whoever made it can read
  everything later sealed under it.
- **Pins protect only clones that have opened the scope before.** A new
  clone, a new identity, or a CI job with a fresh checkout trusts the first
  key it sees on trunk. Pins live in the clone's git directory, per
  identity.
- **An unproven value proves only that its writer held a retired key**,
  which a removed reader may still hold. Values a rotation left in place
  are distinguishable: the retired record's authenticated `carried` list
  names them, and they are ordinary values. A line under a retired key
  that it does not carry is unproven: `ls`, `status` and `check` mark it;
  `apply` lists it and re-seals it only with `--reseal-unproven`.
- **A drop's author is whoever git says.** The drop box trades the
  guarantee that every value came from a reader for the ability to add a
  secret without one. The marker and review are the compensating control.
- **Withholding is possible.** Anyone who can merge can delete a value or a
  slot. That is a visible diff and usually a failing `check`, not a
  disclosure.
- **Rotation does not un-share.** A removed person keeps what they could
  read. A rotation does not re-seal existing values; they stay under the
  retired key until set again. Rotation debt is the list of credentials to
  change at their source; carbon cannot change them for you.
- **Git history is permanent.** Ciphertext committed today can be attacked
  with tomorrow's tools. New identities and every inbox key are hybrid
  post-quantum (ML-KEM-768 with X25519) by default; X25519 keys are still
  accepted unless an environment sets `require_pq = true`.
- **Metadata is public to anyone with the repository**: names, readers and
  set times.

## Operational limits that touch security

- **Concurrent applies conflict.** Two branches that each run `apply` can
  conflict on a slot line (keep either: both wrap the same key) or, if both
  rotate, in the keys file (keep either side's whole keys file, then apply
  again; a value the other side set under its own new key then names an
  unknown key and must be set again).
- **A rotation no longer conflicts with a branch that added a secret.** A
  rotation changes only the keys file. The branch's new line merges under
  the retired key, is not carried, and is unproven until a reader runs
  `carbon apply --reseal-unproven` or someone sets it again after merging
  trunk.
- **Grants wait for a reader.** Access starts only when a current reader
  runs `apply` after the policy change merges. There is no bot that does
  this yet.
