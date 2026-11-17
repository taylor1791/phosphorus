# Carbon threat model

This restates the design's threat model (`docs/design.md`, "Threat model")
with what was learned while building and reviewing carbon 1.0. Where the two
differ, this page is current. Carbon has not had an external security
review.

## The root of trust

**Trunk is the root of trust.** Trunk is the branch whose policy and keys
files have been reviewed: the remote default branch, unless a clone or a CI
job names another with `CARBON_TRUNK` or `git config carbon.trunk`. Nothing
a commit can change chooses it.

Encryption protects secrets from everyone who cannot change trunk. Review
protects trunk. So the protections below assume two things you have to
provide:

- **Branch protection and CODEOWNERS** on `carbon.toml`, `.carbon/` and
  every package's `carbon.toml` and `.carbon/`, so that access lists, people,
  machines, teams and keys files change only through a review by their
  owners.
- **`carbon check` as a required status check**, with trunk fetched and
  named (see [ci.md](ci.md)).

## What each adversary gets

| Adversary | What they get | Why, and what limits it |
|---|---|---|
| Anyone with a copy of the repository and no key | Package names, secret names, reader lists, set times. No values. | Metadata is plaintext by design, so that reviews work. Values and scope keys are encrypted. |
| A contributor who can push branches but reads no scope | Nothing readable from a scope that already has a key. They cannot forge a sealed value or wrap a key to themselves. | Both need the scope key. `apply` reads policy only from trunk. A keys file they forge on a branch fails `check` (`key.changed`, `slot.unbacked`, `slot.removed`), and every reader command (`get`, `run`, `export`, `set`, `edit`, `apply`) refuses a key that does not descend from trunk's. |
| The same contributor, proposing a drop | A value of their choosing in a scope, if the pull request is merged. | A drop is marked, listed in `check`'s banner, and reviewed like code. Environments can turn drops off (`drops = false`). Readers do use a drop at once, on the branch, before review: treat a drop like any unreviewed code you run. |
| The same contributor, creating the **first** key of a scope (a new package or environment) on a branch | If the pull request is merged: every value later set in that scope. | Carbon cannot prove who made a scope's first key. `check` lists it as `NEW SCOPE KEY` in the banner; the reviewer must confirm the author is a reader. Before merge, readers will not seal under a key that exists only on someone else's branch (unless they run `carbon trust`), and `apply` will not touch it. |
| Someone who can merge to trunk without review | Whatever they merge: a forged key or policy then *is* trunk. | This is the root of trust. A reader who opened the scope before in the same clone refuses a key that replaced the one they pinned (`carbon trust` to accept it after investigating). New clones and CI jobs have no pins and accept it. |
| A current reader | Everything in their scopes, and the ability to copy it anywhere. | Not preventable by any design. Scopes keep the blast radius small, and git records who granted what. |
| A removed reader, or a stolen device, before the rotation is applied | Everything the device could read until a reader runs `apply` after the removal merges. | `carbon remove` changes policy; the key rotates only when a reader applies it. `check` warns about the pending revocation (an error under `--strict`). A removed reader cannot `set` once the removal is on trunk. |
| A removed reader after the rotation | Every value set before the rotation, from git history. | Keys rotate, so values set afterwards are safe. Rotation debt (`carbon status`, `check --max-debt`) lists every secret to change at its source. Carbon never seals a new value under a key trunk has retired: `set` and `edit` on a branch that is behind (or that reverted a rotation) refuse until trunk is merged. |
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
  every key change, every drop and every value under a retired key in its
  review banner. A passing `check` on a change to keys files is not safe to
  merge without review.
- **A forged rotation by a removed reader** who kept the previous scope key
  passes `check` and the readers' pins (see the table). Only review of who
  authored the commit catches it.
- **A scope's first key is trusted on review.** Whoever made it can read
  everything later sealed under it.
- **Pins protect only clones that have opened the scope before.** A new
  clone, a new identity, or a CI job with a fresh checkout trusts the first
  key it sees on trunk. Pins live in the clone's git directory, per
  identity.
- **A value under a retired key proves only that its writer held that
  key**, which a removed reader may still hold. `ls` and `status` mark such
  values unproven; `apply` lists them and re-seals them only with
  `--reseal-unproven`.
- **A drop's author is whoever git says.** The drop box trades the
  guarantee that every value came from a reader for the ability to add a
  secret without one. The marker and review are the compensating control.
- **Withholding is possible.** Anyone who can merge can delete a value or a
  slot. That is a visible diff and usually a failing `check`, not a
  disclosure.
- **Rotation does not un-share.** A removed person keeps what they could
  read. Rotation debt is the list of credentials to change at their
  source; carbon cannot change them for you.
- **Git history is permanent.** Ciphertext committed today can be attacked
  with tomorrow's tools. New identities and every inbox key are hybrid
  post-quantum (ML-KEM-768 with X25519) by default; X25519 keys are still
  accepted unless an environment sets `require_pq = true`.
- **Metadata is public to anyone with the repository**: names, readers and
  set times.

## Operational limits that touch security

- **Concurrent applies conflict.** Two branches that each run `apply` can
  conflict on a slot line (keep either: both wrap the same key) or, if both
  rotate, on `current` (keep one side's keys and secrets files, then apply
  again).
- **A rotation conflicts with a branch that added a secret** in the same
  scope, because a rotation re-seals every line. Resolve by keeping the
  rotated lines and adding back the other side's lines; the next `apply`
  lists them as unproven.
- **Grants wait for a reader.** Access starts only when a current reader
  runs `apply` after the policy change merges. There is no bot that does
  this yet.
