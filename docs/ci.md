# Carbon in CI and deploys

Two jobs use carbon in CI:

- **`carbon check`** on every pull request and every push to trunk. It needs
  no identity and no secret. It is the gate.
- **A deploy job** that reads secrets with a machine identity and runs the
  deploy with them.

Neither protects anything unless the repository is set up so that trunk
changes only through review. See [What CI must protect](#what-ci-must-protect)
first.

## What CI must protect

Carbon's root of trust is trunk: the branch whose policy and keys files
have been reviewed. CI can only uphold that if:

- **Nobody can push to trunk directly.** On trunk itself, `check` compares
  trunk with itself, so a direct push of a forged key or policy passes it.
  Require pull requests and reviews for the default branch (branch
  protection or a repository ruleset), for administrators too.
- **The workflow cannot be changed by the pull request it judges.** A
  `pull_request` workflow runs the pull request's own copy of
  `.github/workflows/`, so a branch can edit the `check` job to do nothing
  and still report success. Protect `.github/workflows/**` and
  `CODEOWNERS` itself with CODEOWNERS entries that require review by
  people you trust, or run `check` as a required workflow from a
  repository ruleset, which a pull request cannot edit.
- **Carbon's files are owned.** CODEOWNERS for `carbon.toml`, `.carbon/`,
  and every package's `carbon.toml` and `.carbon/`, so that access lists,
  people, machines, teams and keys files are reviewed by their owners.

## Running `carbon check`

`check` compares the working tree with **trunk**. It must know which ref
that is, and the ref must exist in the CI clone. Carbon chooses trunk as
follows; no file in the repository can choose it (but see above: the CI
workflow that sets it is a file, and must be protected):

1. the environment variable `CARBON_TRUNK`;
2. the clone's git config `carbon.trunk`;
3. the remote default branch: the target of `refs/remotes/origin/HEAD`,
   else `refs/remotes/origin/main`, else `refs/remotes/origin/master`.

A configured trunk is resolved to a branch, never a tag: either a full ref
under `refs/remotes/` or `refs/heads/`, or a short name that is looked up as
exactly `refs/remotes/<name>` and `refs/heads/<name>` (if both exist, carbon
asks for the full ref). In CI, use the full ref:
`CARBON_TRUNK=refs/remotes/origin/main`. `check` prints the ref and commit
it compared with on its first line.

A CI checkout usually has no trunk: `actions/checkout` fetches one commit,
detached, with no `origin/HEAD`. So set `CARBON_TRUNK` and fetch that ref.
If `check` cannot find trunk it exits 1 and says what to set; it never
falls back to judging a branch by its own files. If trunk has no carbon
workspace yet, `check` also exits 1 unless `--bootstrap` is given.

`check` also needs history back to the merge base with trunk in one case: a
branch that still uses a key trunk has since rotated. With a shallow clone
it cannot prove the branch only fell behind, and fails with
`key.unverified`. `fetch-depth: 0` avoids that.

### GitHub Actions

```yaml
# .github/workflows/carbon.yml
name: carbon
on:
  pull_request:
  push:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # all branches and history: origin/main and the merge base
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Install carbon
        run: go install github.com/taylor1791/phosphorus/cmd/carbon@<version>
        env:
          CGO_ENABLED: "0"
      - name: carbon check
        run: carbon check --max-debt 30d
        env:
          CARBON_TRUNK: refs/remotes/origin/${{ github.event.repository.default_branch }}
```

Pin `<version>` to a release you have reviewed (there are no releases yet;
see the README's status). If you prefer a shallow clone, fetch trunk
explicitly before `check`:

```sh
git fetch --no-tags origin main:refs/remotes/origin/main
CARBON_TRUNK=refs/remotes/origin/main carbon check
```

Make the `check` job a required status check.

### Reading the output

```text
Compared with trunk: refs/remotes/origin/main at 3f9c2a1 (from CARBON_TRUNK)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! 1 ITEM TO REVIEW: drops, key changes and values under retired keys.
!! check cannot open anything, so it cannot tell a reader's change from a
!! forged one: confirm each author is a current reader before merging.
!!
!!   checkout/prod   webhook_secret   set 2026-11-17T04:28:52Z   DROP: confirm the value is wanted
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

check passed: 0 errors, 0 warnings, 1 item to review.
```

The first line names the trunk ref and commit it compared against. Check it
once when you set the job up.

**The banner** lists changes that `check` cannot judge, because judging them
needs a key or a person, and `check` holds neither:

| Banner item | What to confirm before merging |
|---|---|
| `DROP` | Someone, possibly not a reader, put this value in the scope. Is it wanted? |
| `NEW SCOPE KEY` | A scope got its first key. Only a reader of that scope should have made it: check who committed the keys file against `carbon who <package> --env <env>`. Whoever made it can read everything later set in the scope. |
| `KEY ROTATED` | The scope key changed. This is what `carbon apply` writes after a removal or a re-key, but someone who still holds the previous key (including the person just removed) can write the same thing. Confirm the author is a current reader. |
| `NEW SLOT for <device>` | A device was given the scope key. Policy on trunk names it; confirm a current reader wrapped it (`carbon apply`). |
| `RENAMED` | A package was renamed (`carbon rename`) and every value re-sealed. Confirm the author is a reader of the scope. |
| `KEY CHANGED for <device>` | The public key of an existing device or machine was replaced. Once merged and applied, the new key reads everything that device read. Confirm the printed fingerprint with the device's owner over a channel you trust. |
| `NEW DEVICE <device>` | A device was added to an existing person: once applied it reads everything the person reads. Confirm the fingerprint with them. |
| `UNDER A RETIRED KEY` / `SUSPECT` | A value sealed under a retired key: whoever wrote it held that key, which a removed reader may still hold. |
| `OLDER VALUE` | A value was replaced by an older line. |
| `SCOPE REMOVED` | A scope and its keys were deleted together. |

A passing `check` with items in the banner is **not** "safe to merge without
review". `check` enforces every structural rule a legitimate change
satisfies; the banner is what is left for a person. A pull request that
changes only keys files (an `apply` commit) still needs a reviewer who
confirms its author is a current reader of each scope it touches.

**Errors** fail the job (exit 4). **Warnings** are reported and pass,
unless `--strict`. **Notes** are informational: pending grants (a device
trunk policy names that has no slot yet: a reader runs `carbon apply`), and
what a pull request's policy proposes (`policy.grant-proposed`,
`policy.revoke-proposed`).

### Flags

| Flag | Effect |
|---|---|
| `--strict` | Every warning becomes an error, and so does every pending grant. Warnings include pending revocations and re-keyed slots, rotation debt (all of it, not only debt past `--max-debt`), values under retired keys, older values restored over trunk's, team members without a person file, and a `worktree` trunk. Notes never fail, including the banner's drops, new keys, rotations, renames and key changes, and policy proposals. A pull request that only changes policy is not failed by its own change (its grants are not pending until it merges); on trunk, `--strict` fails until a reader has applied every merged change. |
| `--max-debt 30d` | Rotation debt older than this fails the job. Debt is a secret set before someone who could read it was removed or re-keyed, or older than its `rotate_after`. It clears when the secret is set again. |
| `--unused` | Also list secrets that no `[env]` table references. |
| `--json` | One JSON document on stdout: `ok`, `trunk` (`ref`, `commit`, `from`, `mode`), `counts`, `findings` (each with a stable `rule` id) and `rules`. |
| `--bootstrap` | Check the working tree against itself when trunk has no carbon workspace (a new repository, or the carbon-migrate cutover). `check` never does this without the flag. Never in CI once carbon is on trunk. |

Exit codes: 0 passed, 4 check found errors, 1 carbon could not run the
check (for example no trunk), 2 bad flags. `carbon help` lists them all.

## Deploys with a machine identity

A machine is an identity with one public key, written to
`.carbon/machines/<name>.toml`. It reads only the scopes whose access lists
name it.

1. Create it, on a branch, writing the private key outside the repository:

   ```sh
   key=$(mktemp)
   carbon join --machine deploy-checkout --description "checkout deploy job" > "$key"
   ```

   This prints the private key once, on stdout, and stores nothing. Put the
   content of `$key` in your CI secret store (below), then delete it:
   `rm "$key"`.

2. Name it in the access list of each scope it deploys, in the package's
   `carbon.toml`:

   ```toml
   [access]
   prod = ["@payments", "machine:deploy-checkout"]
   ```

   (or run `carbon request checkout --env prod --as machine:deploy-checkout`).
   Open a pull request with both files.

3. After it merges, a current reader of each scope runs `carbon apply` and
   opens a pull request with the commit it makes. Until then the machine
   has no slot and its deploy fails with exit 3.

4. Store the key so that only trunk's deploy job can read it. In GitHub,
   create an **Environment** (Settings, Environments), for example `prod`,
   with a **deployment branch policy** that allows only the default branch,
   and add the key there as an environment secret,
   `CARBON_IDENTITY_DEPLOY_CHECKOUT`. A job gets environment secrets only
   when it names the environment and runs from an allowed branch.

   An `if: github.ref == 'refs/heads/main'` condition on its own protects
   nothing: any branch can edit the workflow file, drop the condition, and
   read a repository-level secret. The deployment branch policy is enforced
   by GitHub, outside the workflow.

   ```yaml
   deploy:
     runs-on: ubuntu-latest
     environment: prod          # its secrets are released only to the default branch
     steps:
       - uses: actions/checkout@v4
         with:
           fetch-depth: 0
       - uses: actions/setup-go@v5
         with:
           go-version: "1.25"
       - run: go install github.com/taylor1791/phosphorus/cmd/carbon@<version>
         env:
           CGO_ENABLED: "0"
       - name: Deploy
         run: carbon run --env prod --package checkout -- ./deploy.sh
         env:
           CARBON_IDENTITY: ${{ secrets.CARBON_IDENTITY_DEPLOY_CHECKOUT }}
           CARBON_TRUNK: refs/remotes/origin/main
   ```

`carbon run` resolves the package's `[env]` table, decrypts in memory, and
replaces itself with the command. Nothing is written to disk, and
`CARBON_IDENTITY` is removed from the command's environment. For a tool
that needs a file, use
`carbon export --env prod --package checkout --format dotenv -o /run/secrets/checkout.env`
(mode 0600; inside the repository the path must be ignored by git).

Like every reader command, the deploy compares the scope's keys file with
trunk's and refuses a key that does not descend from it, so `CARBON_TRUNK`
must name a fetched ref here too.

**What a fresh CI machine does not get.** A person's clone remembers the
last key it verified for each scope (its pin), and refuses a key that
replaced it. A CI job starts from a fresh checkout every time, so it has no
pins: it trusts whatever key trunk has. Its protection is that trunk is
reviewed. See [threat-model.md](threat-model.md).

To rotate a machine's key, remove it (`carbon remove machine:deploy-checkout`),
join it again with a new key, merge, and let a reader apply: the scopes it
read rotate, and the secrets it could read owe a rotation at their source.
