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

Intel Core i7-10750H (12 threads), Linux 6.12, Go 1.25.4, 16 Nov 2026. Two
runs (a third, on a busy machine, gave the same small number and noisier
monorepo numbers):

| Setup | `carbon run -- cmd` median | `cmd` median | Overhead |
|---|---|---|---|
| small | 13.48 / 12.21 ms | 0.86 / 0.79 ms | 12.6 / 11.4 ms |
| monorepo, 1 scope | 16.08 / 16.22 ms | 0.77 / 0.80 ms | 15.3 / 15.4 ms |
| monorepo, 3 scopes | 19.53 / 18.06 ms | 0.83 / 0.80 ms | 18.7 / 17.3 ms |

`carbon run` adds 11 to 19 ms, under the 50 ms goal; p90 was under 22 ms.

### How the cost scales

- **git processes are constant: 6 per `run`**, however many scopes are
  opened and however many people, machines and packages there are:
  `rev-parse --show-toplevel`, `rev-parse --absolute-git-dir` (for
  `carbon env use`), `config --get carbon.trunk`, `rev-parse --verify` of
  the trunk ref, one `ls-tree` of trunk, and one `cat-file --batch` that
  serves every file read at trunk. `TestRunGitProcessCount` fails if a
  second scope or more people add a process. They are most of the fixed
  cost: about 1.3 ms each here.
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
identity once per command, and reading trunk files through one
`git cat-file --batch`, brought it to the numbers above.
