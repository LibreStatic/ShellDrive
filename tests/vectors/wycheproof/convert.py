"""Converts Wycheproof JSON test vectors into the compact line format read by sd-test-crypto.

Usage: python -I convert.py <dir with the downloaded *.json> <output dir>

Output: one test per line, space-separated fields, hex strings ("-" for empty), result is
v (valid), i (invalid) or a (acceptable). Lines starting with '#' are comments.
  aes_gcm / chacha20_poly1305: tcId key iv aad msg ct tag result   (96-bit IV, 128-bit tag only)
  ed25519:                     tcId pk msg sig result
  x25519:                      tcId public private shared result flags(comma list)
  hmac_sha256 / hmac_sha512:   tcId key msg tag result             (tag may be truncated)
"""
import json
import os
import sys

R = {"valid": "v", "invalid": "i", "acceptable": "a"}


def h(s):
    return s if s else "-"


def load(src, name):
    with open(os.path.join(src, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def write(dst, name, d, lines, skipped):
    with open(os.path.join(dst, name + ".txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("# %s, Wycheproof %s (%d tests, %d converted, %d skipped)\n"
                % (d["algorithm"], name, d["numberOfTests"], len(lines), skipped))
        for ln in lines:
            f.write(ln + "\n")


def aead(src, dst, name):
    d = load(src, name)
    out, skipped = [], 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            if g["ivSize"] != 96 or g["tagSize"] != 128:
                skipped += 1
                continue
            out.append(" ".join([str(t["tcId"]), h(t["key"]), h(t["iv"]), h(t["aad"]), h(t["msg"]),
                                 h(t["ct"]), h(t["tag"]), R[t["result"]]]))
    write(dst, name, d, out, skipped)


def ed25519(src, dst):
    d = load(src, "ed25519_test")
    out = []
    for g in d["testGroups"]:
        pk = g["publicKey"]["pk"]
        for t in g["tests"]:
            out.append(" ".join([str(t["tcId"]), h(pk), h(t["msg"]), h(t["sig"]), R[t["result"]]]))
    write(dst, "ed25519_test", d, out, 0)


def x25519(src, dst):
    d = load(src, "x25519_test")
    out = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            out.append(" ".join([str(t["tcId"]), h(t["public"]), h(t["private"]), h(t["shared"]),
                                 R[t["result"]], ",".join(t["flags"]) or "-"]))
    write(dst, "x25519_test", d, out, 0)


def hmac(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            out.append(" ".join([str(t["tcId"]), h(t["key"]), h(t["msg"]), h(t["tag"]), R[t["result"]]]))
    write(dst, name, d, out, 0)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    aead(src, dst, "aes_gcm_test")
    aead(src, dst, "chacha20_poly1305_test")
    ed25519(src, dst)
    x25519(src, dst)
    hmac(src, dst, "hmac_sha256_test")
    hmac(src, dst, "hmac_sha512_test")


if __name__ == "__main__":
    main()
