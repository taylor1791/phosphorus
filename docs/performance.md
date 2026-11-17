# Performance

## Goal 8: `carbon run` adds under 50 ms for a package with 100 secrets

Measured by `TestRunOverhead` in `internal/cli/perf_test.go`:

```sh
nix shell nixpkgs#go nixpkgs#git -c go test -count=1 -v ./internal/cli -run TestRunOverhead
```

What it measures, from process start to the exec of the command:

- a package with 100 declared secrets, all set, and an `[env]` table that
  references every one of them;
- every person has a hybrid (ML-KEM-768 + X25519) identity, and the caller
  reads through its hybrid identity file;
- trunk is configured (`git config carbon.trunk main`) and has every
  scope's key, so `run` also checks each key against trunk's, as it does in
  a real clone;
- `carbon run -- childhelper exit` against `childhelper exit` started
  directly, alternating, 40 rounds each after 3 warm-up rounds, from the
  test process with `os/exec`. The overhead is the difference of the
  medians, so process start-up of the command itself is not counted.

Everything `run` does is inside the number: finding the repository and the
git directory, choosing the trunk, reading trunk policy and trunk's keys
files, parsing the workspace, packages and people (in the working tree and
at trunk), loading the identity, opening each scope (one hybrid age slot and
the inbox check), checking each key against trunk, decrypting the values,
building the environment and `execve`.

The test asserts no threshold, so a slow or loaded machine cannot make the
suite fail. It does check that the command received every value.

Three setups:

- **small**: 6 people, 1 package, 1 scope opened, 100 values;
- **monorepo, 1 scope**: 30 people, 10 packages, 1 scope opened, 100 values;
- **monorepo, 3 scopes**: 30 people, 10 packages, and the `[env]` table also
  references two secrets in each of two other packages: 3 scopes opened,
  104 values.

### Result

The numbers include the per-clone key pin (`<git common dir>/carbon/pins.toml`):
each opened scope's key is compared with the reader's pin, read from that
file. After the warm-up rounds the pins exist, so the timed runs read the
file and do not write it (the first read of a scope writes it once).

Intel Core i7-10750H (12 threads), Linux 6.12, Go 1.25.4, 16 Nov 2026,
three runs (the third monorepo-1-scope run was on a busy machine: p90
31 ms):

| Setup | `carbon run -- cmd` median | `cmd` median | Overhead |
|---|---|---|---|
| small | 11.70 / 12.68 / 11.63 ms | 0.83 / 0.85 / 0.80 ms | 10.9 / 11.8 / 10.8 ms |
| monorepo, 1 scope | 15.65 / 15.96 / 20.97 ms | 0.79 / 0.79 / 0.93 ms | 14.9 / 15.2 / 20.1 ms |
| monorepo, 3 scopes | 17.65 / 17.89 / 18.96 ms | 0.80 / 0.81 / 0.82 ms | 16.8 / 17.1 / 18.1 ms |

`carbon run` adds 11 to 18 ms (20 ms on the busy run), under the 50 ms
goal.

### How the cost scales

- **git processes are constant: 5 per `run`**, however many scopes are
  opened and however many people, machines and packages there are: one
  `rev-parse` for the top level, git directory and common directory, then
  `config --get carbon.trunk`, `rev-parse --verify` of the trunk ref, one
  `ls-tree` of trunk, and one `cat-file --batch` that serves every file
  read at trunk. `TestRunGitProcessCount` fails if a second scope adds a
  process, if more than one `cat-file` starts, or if a run with nine people
  takes more than 6. They are most of the fixed cost: about 1.3 ms each
  here.
- **The pin file** is read once per opened scope (a small local file), and
  written only when a scope's pin moves.
- **People, machines and packages** are parsed twice (working tree and
  trunk), in process: going from 6 people and 1 package to 30 people and 10
  packages added about 3 to 4 ms.
- **Each additional scope** costs one slot unwrap with the caller's own
  device (other slots are not tried), the inbox check, the trunk comparison
  and its values: about 1 to 1.5 ms each here.
- **Each value** is one XChaCha20-Poly1305 open: negligible next to the
  above.

### History

Before the trunk check (bootstrap mode, no trunk to read), the small setup
measured 6.0 to 7.3 ms. The first version of the trunk check reloaded trunk
policy for every scope and started one `git cat-file` per file read at
trunk (18 git processes for one scope, 34 for two); the small setup then
measured 22.5 to 22.9 ms. Caching trunk policy, working-tree policy and the
identity once per command, reading trunk files through one
`git cat-file --batch`, and asking `rev-parse` for all three directories at
once brought it to the numbers above.
