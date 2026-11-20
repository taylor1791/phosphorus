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

Base64 is always the standard alphabet **without padding**, canonical (unused
trailing bits are zero) and without line breaks; carbon rejects anything else. Times are RFC 3339
UTC with whole seconds, e.g. `2026-11-02T17:04:11Z`.

## Files

`<package dir>/.carbon/<env>.secrets.toml`, one line per secret:

```toml
stripe_api_key = { key = "k3f9q2", set = 2026-09-14T09:30:02Z, value = "carbon1:…" }
webhook_secret = { key = "k3f9q2", set = 2026-11-10T08:12:40Z, drop = "age1:…" }
```

`key` is the id of the scope key the value is sealed under, or whose inbox the
drop was written to. For a `value`, `set` is part of the associated data:
editing it breaks decryption. For a `drop`, the set time is inside the
encrypted payload and a reader compares it with the line after decrypting;
it is not authenticated as associated data, and whoever wrote the drop
chose it.

`<package dir>/.carbon/<env>.keys.toml`:

```toml
scope = "checkout/prod"
current = "k3f9q2"

[keys.k3f9q2]
created = 2026-11-02T17:04:11Z
inbox = "age1pq1…"
inbox_sealed = "carbon1:…"

[keys.k3f9q2.slots]
"lin/laptop" = { to = "sha256:…", slot = "age1:…" }
"machine:deploy-checkout" = { to = "sha256:…", slot = "age1:…" }

[keys.k1a8c0]
created = 2026-06-01T10:00:00Z
retired = 2026-11-02T17:04:11Z
reason = "removed sam"
successor = "k3f9q2"
predecessor = "k0b2z7"       # absent when k1a8c0 was the scope's first key
sealed = "carbon1:…"
carried = ["sha256:…", "sha256:…"]
inbox_sealed = "carbon1:…"   # optional: k1a8c0's own inbox identity, still sealed under k1a8c0,
                             # so drops written to its inbox open once the chain opens k1a8c0

[keys.k0b2z7]
created = 2026-01-12T09:00:00Z
retired = 2026-06-01T10:00:00Z
reason = "rekeyed ada/laptop"
successor = "k1a8c0"
sealed = "carbon1:…"
carried = []
```

A rotation does not touch the secrets file: values and drops written under
a key stay under its id after it is retired and open through the chain of
retired keys.

`predecessor`, written after `successor`, is the id of the key the retired
key replaced: the newest retired record at the moment it was retired. It is
absent for a scope's first key and never present on the current key; it may
not name the record itself. The retired records form one chain back from
the current key, and a reader must check its structure before using any
of them:

1. At most one retired record names the current key as `successor`; it is the
   newest record on the chain. Two or more is an error.
2. From each record on the chain, the next is the record its `predecessor`
   names, which must exist, be retired and name it as `successor`. The
   chain ends at a record without `predecessor`.
3. Any other retired record (one claiming a chain key as `successor`, or one
   the walk never reaches) is an error naming that record. carbon refuses
   the whole scope; it never ignores a stray record. The fix is to restore
   the keys file from trunk (`git checkout <trunk> -- <keys file>`).

A reader then unseals the chain in order, each record under the key after it
(the first under the current key). Because `predecessor` and `carried` are in
the associated data, every link is authenticated in both directions. A record
that fails to open makes it and every older key unavailable; values under
them fail, and the rest of the scope reads. In particular, a single record
claiming the current key as `successor` in a scope whose current key is its
first is structurally on the chain; it cannot be forged without the current
key, so it fails to open, and only the values it would carry fail.

`carried` lists, sorted, `sha256:` and the hex SHA-256 of the canonical line
(below) of each entry that was under the key when it was retired. A line under
a retired key that is not listed was written after the rotation, by someone
who held the retired key: carbon calls it unproven. `carried` counts only for
records on the chain, and, for a reader holding a key, only for records
that opened, which authenticates them (the list's digest is in the `sealed`
blob's associated data, below).

**Canonical line.** The hash is SHA-256 over the line exactly as carbon's
deterministic writer emits it, without the trailing newline:

```
<name> = { key = "<key id>", set = <set time>, value = "<carbon1: blob>" }
<name> = { key = "<key id>", set = <set time>, drop = "<age1: blob>" }
```

with single spaces exactly as shown, `<set time>` in RFC 3339 UTC with whole
seconds (`2026-11-02T17:04:11Z`), and the strings in TOML basic-string
quoting (`"` and `\` escaped as `\"` and `\\`; carbon's ids and blobs never
need escaping). The secrets-file reader does not reject other TOML spellings
of the same entry (extra spaces, a different key order, a literal string).
Every consumer (carbon's rotation, readers, `check`, `ls`, `status`,
`apply`) parses the entry and hashes its canonical re-emission, so the hash
depends only on the entry's name, `key`, `set` and `value` or `drop`, never on
how the line is formatted on disk. An independent tool must do the same.

## Sealed blob: `carbon1:<base64(nonce ‖ ciphertext)>`

XChaCha20-Poly1305 (24-byte random nonce, 16-byte tag appended to the
ciphertext), key = the 32-byte scope key. The associated data is these lines
joined with `\n`, no trailing newline:

| Blob | Key | Plaintext | Associated data lines |
|---|---|---|---|
| `value` | scope key `key` | the value bytes | `carbon/v1/value`, package, env, secret name, key id, set time |
| `inbox_sealed` | that key | the inbox identity string (`AGE-SECRET-KEY-PQ-1…`) | `carbon/v1/inbox`, package, env, key id |
| retired `sealed` | the successor key | the retired key's 32 bytes | `carbon/v1/retired`, package, env, retired key id, successor key id, retired time, reason, predecessor key id (`-` for none), carried digest |

Package is the package's `name` (not its path); env is the environment name.
The carried digest is the hex SHA-256 of the retired record's `carried`
elements, as written, joined with `\n` (no trailing newline); an empty list
hashes the empty string (`e3b0c442…b855`).

## Slot: `{ to = "sha256:<hex>", slot = "age1:<base64(age file)>" }`

Each slot line records `to`, the SHA-256 (hex, prefixed `sha256:`) of the
recipient string the slot was wrapped to, exactly as written in the person's
or machine's file, so a key change or a relabelled line is visible. `to` is
not authenticated by cryptography: `carbon check` protects it against trunk
(a slot on trunk's current key may not be removed or altered while `current`
is unchanged, and a new slot's `to` must equal the hash of trunk policy's
key for that device).

`slot` is a binary age file with exactly one recipient stanza. Its plaintext is four
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
SLOT=$(sed -n 's|^"test/hybrid" = { to = "[^"]*", slot = "\(.*\)" }$|\1|p' $K)
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
#    The last two associated data lines are k_old's predecessor ("-" if it has
#    none) and the digest of k_old's carried list.
DIGEST=$(printf '%s' "sha256:…first…"$'\n'"sha256:…second…" | sha256sum | cut -d' ' -f1)
#    (macOS: shasum -a 256; for an empty carried list use printf '' instead)
OLDKEY=$(python3 tools/decrypt.py open "$KEY" "carbon1:…sealed of k_old…" \
  carbon/v1/retired checkout prod k_old "$KID" <retired time> "<reason>" <predecessor or -> "$DIGEST" | base64 | tr -d '\n=')
# (base64 without line breaks or padding, which is what decrypt.py expects as a key)
python3 tools/decrypt.py open "$OLDKEY" "carbon1:…" carbon/v1/value checkout prod <name> k_old <set time>
```

A chain of several retired keys is walked the same way, one successor at a
time, from the current key back along `predecessor`. Check the chain's
structure (above) first: a stray retired record is a reason to distrust the
keys file, not one to skip.

## Test vectors

- `testdata/vectors/sealed.json`: fixed key, nonce, associated data,
  plaintext and expected blob for each sealed-blob kind. Regenerate with
  `go run ./tools/genvectors > testdata/vectors/sealed.json`, which does not
  use carbon's own code. Check with
  `python3 tools/decrypt.py vectors testdata/vectors/sealed.json`; the Go test
  is `internal/seal` `TestVectors`.
- `testdata/vectors/scope/`: a complete `checkout/prod` scope with an X25519
  and a hybrid slot, two sealed values, a drop, a retired key that carries one of
  them, and an unproven value under it (from a branch, not carried).
  `expected.json` lists the plaintexts. The Go test is
  `internal/scope` `TestExampleScopeVector` (regenerate with `-update`).
