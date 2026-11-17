# Carbon format, version 1

This page is enough to decrypt every carbon secret without the `carbon`
binary: you need the stock `age` CLI (1.3 or later for hybrid keys) and
`tools/decrypt.py` (about 40 lines of Python with PyNaCl). Test vectors are in
`testdata/vectors/`.

## Keys

| Thing | What it is | Where |
|---|---|---|
| Identity | An age key pair, hybrid (`age1pq1…`) or X25519 (`age1…`) | Private: `~/.config/carbon/identity`. Public: `.carbon/people/*.toml`, `.carbon/machines/*.toml` |
| Scope key | 32 random bytes, id `k` + 5 of `[a-z0-9]`, one current per scope (package + environment) | Only inside slots and retired records |
| Slot | An age file to one device, carrying the scope key | `keys.toml`, `[keys.<id>.slots]` |
| Sealed value | XChaCha20-Poly1305 under a scope key | `secrets.toml`, `value` |
| Inbox | A hybrid age key pair made with each scope key; the private half is sealed under the scope key | `keys.toml`, `inbox` and `inbox_sealed` |
| Drop | An age file to the inbox, carrying one value | `secrets.toml`, `drop` |
| Retired key | An old scope key sealed under its successor | `keys.toml`, `[keys.<old id>]` with `sealed` |

Base64 is always the standard alphabet **without padding**. Times are RFC 3339
UTC with whole seconds, e.g. `2026-11-02T17:04:11Z`.

## Files

`<package dir>/.carbon/<env>.secrets.toml`, one line per secret:

```toml
stripe_api_key = { key = "k3f9q2", set = 2026-09-14T09:30:02Z, value = "carbon1:…" }
webhook_secret = { key = "k3f9q2", set = 2026-11-10T08:12:40Z, drop = "age1:…" }
```

`key` is the id of the scope key the value is sealed under, or whose inbox the
drop was written to. `set` is authenticated: editing it breaks decryption.

`<package dir>/.carbon/<env>.keys.toml`:

```toml
scope = "checkout/prod"
current = "k3f9q2"

[keys.k3f9q2]
created = 2026-11-02T17:04:11Z
inbox = "age1pq1…"
inbox_sealed = "carbon1:…"

[keys.k3f9q2.slots]
"lin/laptop" = "age1:…"
"machine:deploy-checkout" = "age1:…"

[keys.k1a8c0]
created = 2026-06-01T10:00:00Z
retired = 2026-11-02T17:04:11Z
reason = "removed sam"
successor = "k3f9q2"
sealed = "carbon1:…"
inbox_sealed = "carbon1:…"   # optional; lets drops written before the rotation open
```

## Sealed blob: `carbon1:<base64(nonce ‖ ciphertext)>`

XChaCha20-Poly1305 (24-byte random nonce, 16-byte tag appended to the
ciphertext), key = the 32-byte scope key. The associated data is these lines
joined with `\n`, no trailing newline:

| Blob | Key | Plaintext | Associated data lines |
|---|---|---|---|
| `value` | scope key `key` | the value bytes | `carbon/v1/value`, package, env, secret name, key id, set time |
| `inbox_sealed` | that key | the inbox identity string (`AGE-SECRET-KEY-PQ-1…`) | `carbon/v1/inbox`, package, env, key id |
| retired `sealed` | the successor key | the retired key's 32 bytes | `carbon/v1/retired`, package, env, retired key id, successor key id, retired time, reason |

Package is the package's `name` (not its path); env is the environment name.

## Slot: `age1:<base64(age file)>`

A binary age file with exactly one recipient stanza. Its plaintext is four
lines, each ending in `\n`:

```
carbon/v1/slot
<package>/<env>
<key id>
<base64 of the 32-byte scope key>
```

A reader must check that lines 2 and 3 match the keys file the slot came from.

## Drop: `age1:<base64(age file)>`

A binary age file to the inbox recipient of key `key`. Plaintext, six lines,
each ending in `\n`:

```
carbon/v1/drop
<package>
<env>
<secret name>
<set time>
<base64 of the value>
```

A reader must check that lines 2–5 match the line the drop sits on, and should
check that `inbox` is the recipient of the identity sealed in `inbox_sealed`
(carbon refuses the scope otherwise).

## Decrypting without carbon

From the repository root, with your identity file in `$ID`. The worked
example uses `testdata/vectors/scope`, whose test identities are committed
(`identity-x25519.txt`, `identity-hybrid.txt`); replace paths for a real repo.

```sh
K=testdata/vectors/scope/.carbon/prod.keys.toml
S=testdata/vectors/scope/.carbon/prod.secrets.toml
ID=testdata/vectors/scope/identity-hybrid.txt

# 1. Your slot -> the scope key.
SLOT=$(sed -n 's|^"test/hybrid" = "\(.*\)"$|\1|p' $K)
python3 tools/decrypt.py unwrap "$SLOT" | age -d -i $ID > slot.txt
KID=$(sed -n 3p slot.txt); KEY=$(sed -n 4p slot.txt)

# 2. A sealed value (associated data: purpose, package, env, name, key id, set).
python3 tools/decrypt.py open "$KEY" "carbon1:…the value field…" \
  carbon/v1/value checkout prod stripe_api_key "$KID" 2026-09-14T09:30:02Z

# 3. A drop: unseal the inbox identity of key $KID, then use stock age.
python3 tools/decrypt.py open "$KEY" "carbon1:…inbox_sealed of $KID…" \
  carbon/v1/inbox checkout prod "$KID" > inbox.txt
python3 tools/decrypt.py unwrap "age1:…the drop field…" | age -d -i inbox.txt
# line 6 of the output is the value in unpadded base64

# 4. A value under a retired key k_old: unseal k_old with its successor first.
OLDKEY=$(python3 tools/decrypt.py open "$KEY" "carbon1:…sealed of k_old…" \
  carbon/v1/retired checkout prod k_old "$KID" <retired time> "<reason>" | base64 -w0)
python3 tools/decrypt.py open "$OLDKEY" "carbon1:…" carbon/v1/value checkout prod <name> k_old <set time>
```

A chain of several retired keys is walked the same way, one successor at a
time.

## Test vectors

- `testdata/vectors/sealed.json`: fixed key, nonce, associated data,
  plaintext and expected blob for each sealed-blob kind. Regenerate with
  `go run ./tools/genvectors`, which does not use carbon's own code. Check with
  `python3 tools/decrypt.py vectors testdata/vectors/sealed.json`; the Go test
  is `internal/seal` `TestVectors`.
- `testdata/vectors/scope/`: a complete `checkout/prod` scope with an X25519
  and a hybrid slot, two sealed values, a drop, a retired key, and a value still
  under it. `expected.json` lists the plaintexts. The Go test is
  `internal/scope` `TestExampleScopeVector` (regenerate with `-update`).
