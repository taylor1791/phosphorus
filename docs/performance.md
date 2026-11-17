# Performance

## Goal 8: `carbon run` adds under 50 ms for a package with 100 secrets

Measured by `TestRunOverhead` in `internal/cli/perf_test.go`:

```sh
nix shell nixpkgs#go nixpkgs#git -c go test -count=1 -v ./internal/cli -run TestRunOverhead
```

What it measures, from process start to the exec of the command:

- a workspace with six people, each with a hybrid (ML-KEM-768 + X25519)
  identity, and a package with 100 declared secrets, all set, and an
  `[env]` table that references every one of them;
- the caller reads the scope through its hybrid identity file;
- `carbon run -- childhelper exit` against `childhelper exit` started
  directly, alternating, 40 rounds each after 3 warm-up rounds, from the
  test process with `os/exec`. The overhead is the difference of the
  medians, so process start-up of the command itself is not counted.
- trunk is configured (`git config carbon.trunk main`) and has the scope's
  key, so `run` also checks the working tree's key against trunk's, as it
  does in a real clone.

Everything `run` does is inside the number: finding the repository and the
git directory, choosing the trunk, reading trunk policy and trunk's keys
file, parsing the workspace, packages and people, loading the identity,
opening the scope (one hybrid age slot, the inbox check), verifying the key
against trunk, decrypting 100 values, building the environment and `execve`.

The test asserts no threshold, so a slow or loaded machine cannot make the
suite fail. It does check that the command received all 100 values.

### Result

Intel Core i7-10750H (12 threads), Linux 6.12, Go 1.25.4, 16 Nov 2026,
three runs each.

With trunk configured (the normal case, since the trunk check was added):

| Run | `carbon run -- cmd` median | `cmd` median | Overhead |
|---|---|---|---|
| 1 | 23.51 ms | 0.81 ms | 22.70 ms |
| 2 | 23.69 ms | 0.83 ms | 22.86 ms |
| 3 | 23.36 ms | 0.82 ms | 22.54 ms |

Before the trunk check, in bootstrap mode (no trunk to read):

| Run | `carbon run -- cmd` median | `cmd` median | Overhead |
|---|---|---|---|
| 1 | 6.75 ms | 0.78 ms | 5.98 ms |
| 2 | 8.22 ms | 0.90 ms | 7.32 ms |
| 3 | 7.11 ms | 0.82 ms | 6.29 ms |

`carbon run` adds about 23 ms, under the 50 ms goal; p90 was under 26 ms.
Almost all of the difference from bootstrap mode is git processes: reading
policy and the keys file at trunk starts one `git cat-file` per file
(`gitx.RefSource.ReadFile`), so the cost grows with the number of people,
machine and package files. Reading them with one `git cat-file --batch`
would remove most of it.
