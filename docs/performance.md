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

Everything `run` does is inside the number: finding the repository and the
git directory (two `git` processes), parsing the workspace, packages and
people, loading the identity, opening the scope (one hybrid age slot, the
inbox check), decrypting 100 values, building the environment and
`execve`.

The test asserts no threshold, so a slow or loaded machine cannot make the
suite fail. It does check that the command received all 100 values.

### Result

Intel Core i7-10750H (12 threads), Linux 6.12, Go 1.25.4, 16 Nov 2026,
three runs:

| Run | `carbon run -- cmd` median | `cmd` median | Overhead |
|---|---|---|---|
| 1 | 6.75 ms | 0.78 ms | 5.98 ms |
| 2 | 8.22 ms | 0.90 ms | 7.32 ms |
| 3 | 7.11 ms | 0.82 ms | 6.29 ms |

`carbon run` adds about 6 to 7 ms, well under the 50 ms goal. The p90 of
`carbon run` was under 11 ms in every run.
