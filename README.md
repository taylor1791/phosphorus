Carbon
======

Encrypted secrets for monorepos, stored in the repo, with access granted per
package per environment. No server.

**Status: design.** Nothing here is implemented yet. The design is in
[Carbon 1.0: in-repo secrets for monorepos](https://claude.ai/artifact/B9zrmkcLN9zsZUHZGZu1TX).
The proof of concept this replaces is [carbon 0.0.3](https://github.com/taylor1791/carbon).

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
