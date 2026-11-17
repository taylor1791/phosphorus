#!/usr/bin/env python3
"""Reference decryptor for carbon's format (docs/format.md). Needs PyNaCl.

  decrypt.py unwrap 'age1:...'            binary age file on stdout, for `age -d`
  decrypt.py open KEY 'carbon1:...' AD... plaintext on stdout; KEY is the base64
                                          scope key (line 4 of a slot), AD the
                                          associated-data lines, purpose first
  decrypt.py vectors FILE.json            check testdata/vectors/sealed.json
"""
import base64, binascii, json, sys
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_open


def b64(s):  # standard alphabet, padding optional
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def open_sealed(key, blob, ad_lines):
    if not blob.startswith("carbon1:"):
        raise ValueError("not a carbon1: blob")
    raw = b64(blob[len("carbon1:"):])
    nonce, ct = raw[:24], raw[24:]
    return xchacha_open(ct, "\n".join(ad_lines).encode(), nonce, key)


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "unwrap" and len(argv) == 3 and argv[2].startswith("age1:"):
        sys.stdout.buffer.write(b64(argv[2][len("age1:"):]))
    elif cmd == "open" and len(argv) >= 5:
        sys.stdout.buffer.write(open_sealed(b64(argv[2]), argv[3], argv[4:]))
    elif cmd == "vectors" and len(argv) == 3:
        purpose = {"value": "carbon/v1/value", "inbox": "carbon/v1/inbox", "retired": "carbon/v1/retired"}
        for v in json.load(open(argv[2]))["vectors"]:
            ad = [purpose[v["kind"]]] + v["ad_fields"]
            assert "\n".join(ad) == v["associated_data"], v["name"]
            pt = open_sealed(binascii.unhexlify(v["key_hex"]), v["blob"], ad)
            assert pt.hex() == v["plaintext_hex"], v["name"]
            print("ok", v["name"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
