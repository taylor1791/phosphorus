# Carbon in CI and deploys

Two jobs use carbon in CI:

- **`carbon check`** on every pull request and every push to trunk. It needs
  no identity and no secret. It is the gate.
- **A deploy job** that reads secrets with a machine identity and runs the
  deploy with them.

## Running `carbon check`

`check` compares the working tree with **trunk**: the ref whose policy and
keys files have been reviewed. It must know which ref that is, and the ref
must exist in the CI clone. Carbon chooses trunk as follows, and never from
a file a commit can change:

1. the environment variable `CARBON_TRUNK` (a ref such as `origin/main`);
2. the clone's git config `carbon.trunk`;
3. the remote default branch (`origin/HEAD`, else `origin/main`, else
   `origin/master`).

A CI checkout usually has none of these: `actions/checkout` fetches one
commit, detached, with no `origin/HEAD`. So set `CARBON_TRUNK` and fetch
that ref. If `check` cannot find a trunk it exits 1 and says what to set;
it never falls back to judging a branch by its own files.

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
          CARBON_TRUNK: origin/${{ github.event.repository.default_branch }}
```

Pin `<version>` to a release you have reviewed (there are no releases yet;
see the README's status). If you prefer a shallow clone, fetch trunk
explicitly before `check`:

```sh
git fetch --no-tags origin main:refs/remotes/origin/main
CARBON_TRUNK=origin/main carbon check
```

Make the `check` job a required status check, and protect `carbon.toml`,
`.carbon/` and every package's `carbon.toml` and `.carbon/` with
CODEOWNERS, so that access changes and keys files are reviewed by the
people who own them.

### Reading the output

```text
Compared with trunk: origin/main (from CARBON_TRUNK)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! 1 ITEM TO REVIEW: drops, key changes and values under retired keys.
!! check cannot open anything, so it cannot tell a reader's change from a
!! forged one: confirm each author is a current reader before merging.
!!
!!   checkout/prod   webhook_secret   set 2026-11-17T04:28:52Z   DROP: confirm the value is wanted
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

check passed: 0 errors, 0 warnings, 1 item to review.
```

The first line names the trunk it compared against. Check it once when you
set the job up.

**The banner** lists changes that `check` cannot judge, because judging them
needs a key and `check` holds none:

| Banner item | What to confirm before merging |
|---|---|
| `DROP` | Someone, possibly not a reader, put this value in the scope. Is it wanted? |
| `NEW SCOPE KEY` | A scope got its first key. Only a reader of that scope should have made it: check who committed the keys file against `carbon who <package> --env <env>`. Whoever made it can read everything later set in the scope. |
| `KEY ROTATED` | The scope key changed. This is what `carbon apply` writes after a removal or a re-key, but someone who still holds the previous key (including the person just removed) can write the same thing. Confirm the author is a current reader. |
| `NEW SLOT for <device>` | A device was given the scope key. Policy on trunk names it; confirm a current reader wrapped it (`carbon apply`). |
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
policy names that has no slot yet: a reader runs `carbon apply`), and what
a pull request's policy proposes (`policy.grant-proposed`,
`policy.revoke-proposed`).

### Flags

| Flag | Effect |
|---|---|
| `--strict` | Warnings, pending grants and pending revocations fail too. Drops, new keys and rotations are for review and never fail under `--strict`. Useful on trunk, to keep access applied; on pull requests it fails every policy change until someone applies it. |
| `--max-debt 30d` | Rotation debt older than this fails the job. Debt is a secret set before someone who could read it was removed or re-keyed, or older than its `rotate_after`. It clears when the secret is set again. |
| `--unused` | Also list secrets that no `[env]` table references. |
| `--json` | One JSON document on stdout: `ok`, `trunk`, `counts`, `findings` (each with a stable `rule` id) and `rules`. |
| `--bootstrap` | Allow a check with no trunk at all. Only for a brand-new repository before its first push; never in CI. |

Exit codes: 0 passed, 4 check found errors, 1 carbon could not run the
check (for example no trunk), 2 bad flags. `carbon help` lists them all.

## Deploys with a machine identity

A machine is an identity with one public key, written to
`.carbon/machines/<name>.toml`. It reads only the scopes whose access lists
name it.

1. Create it, on a branch:

   ```sh
   carbon join --machine deploy-checkout --description "checkout deploy job" > key.txt
   ```

   This prints the private key once, on stdout, and stores nothing.
   Put the content of `key.txt` in your CI secret store (for example a
   GitHub Actions secret named `CARBON_IDENTITY_DEPLOY_CHECKOUT`), then
   delete the file.

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

4. The deploy job supplies the key as `CARBON_IDENTITY` and runs the deploy
   through carbon:

   ```yaml
   deploy:
     runs-on: ubuntu-latest
     if: github.ref == 'refs/heads/main'
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
           CARBON_TRUNK: origin/main
   ```

`carbon run` resolves the package's `[env]` table, decrypts in memory, and
replaces itself with the command. Nothing is written to disk, and
`CARBON_IDENTITY` is removed from the command's environment. For a tool
that needs a file, use
`carbon export --env prod --package checkout --format dotenv -o /run/secrets/checkout.env`
(mode 0600; inside the repository the path must be ignored by git).

Like every reader command, the deploy compares the scope's keys file with
trunk's and refuses a key that does not descend from it, so `CARBON_TRUNK`
must name a fetched ref here too. Run deploys only from trunk (the `if:`
above), so the machine reads reviewed files.

**What a fresh CI machine does not get.** A person's clone remembers the
last key it verified for each scope (its pin), and refuses a key that
replaced it. A CI job starts from a fresh checkout every time, so it has no
pins: it trusts whatever key trunk has. Its protection is that trunk is
reviewed. See [threat-model.md](threat-model.md).

To rotate a machine's key, remove it (`carbon remove machine:deploy-checkout`),
join it again with a new key, merge, and let a reader apply: the scopes it
read rotate, and the secrets it could read owe a rotation at their source.
