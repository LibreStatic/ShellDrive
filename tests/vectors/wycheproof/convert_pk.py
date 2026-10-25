"""Converts the public-key Wycheproof suites into the compact line format read by sd-test-crypto-pk.

Usage: python -I convert_pk.py <dir with the downloaded *.json> <output dir>

Hex strings ("-" for empty), result v (valid) / i (invalid) / a (acceptable), '#' lines are comments.
  ecdsa_*_p1363:     K curve hash pub          then  T tcId result msg sig        (sig = r || s)
  ecdh_*_ecpoint:    T tcId result public private shared flags(comma list)
  rsa_signature_*:   K bits hash n e           then  T tcId result msg sig
  rsa_pkcs1_*_sig_gen: K bits hash n e d       then  T tcId result msg sig
  hmac_sha1:         tcId key msg tag result   (same as convert.py's hmac files)
Hash names: sha1, sha224, sha256, sha384, sha512 (the test skips the ones sd_crypto lacks).
"""
import json
import os
import sys

R = {"valid": "v", "invalid": "i", "acceptable": "a"}
HASH = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}
CURVE = {"secp256r1": "256", "secp384r1": "384", "secp521r1": "521"}


def hx(s):
    return s if s else "-"


def load(src, name):
    with open(os.path.join(src, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def write(dst, name, d, lines):
    with open(os.path.join(dst, name + ".txt"), "w", encoding="ascii", newline="\n") as f:
        f.write("# %s, Wycheproof %s (%d tests)\n" % (d["algorithm"], name, d["numberOfTests"]))
        for ln in lines:
            f.write(ln + "\n")


def ecdsa(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        k = g["publicKey"]
        out.append("K %s %s %s" % (CURVE[k["curve"]], HASH[g["sha"]], k["uncompressed"]))
        for t in g["tests"]:
            out.append("T %d %s %s %s" % (t["tcId"], R[t["result"]], hx(t["msg"]), hx(t["sig"])))
    write(dst, name, d, out)


def ecdh(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            out.append("T %d %s %s %s %s %s" % (t["tcId"], R[t["result"]], hx(t["public"]), hx(t["private"]),
                                                hx(t["shared"]), ",".join(t["flags"]) or "-"))
    write(dst, name, d, out)


def rsa_verify(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        k = g["publicKey"]
        out.append("K %d %s %s %s" % (g["keySize"], HASH[g["sha"]], k["modulus"], k["publicExponent"]))
        for t in g["tests"]:
            out.append("T %d %s %s %s" % (t["tcId"], R[t["result"]], hx(t["msg"]), hx(t["sig"])))
    write(dst, name, d, out)


def rsa_sign(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        k = g["privateKey"]
        out.append("K %d %s %s %s %s" % (g["keySize"], HASH[g["sha"]], k["modulus"], k["publicExponent"],
                                         k["privateExponent"]))
        for t in g["tests"]:
            out.append("T %d %s %s %s" % (t["tcId"], R[t["result"]], hx(t["msg"]), hx(t["sig"])))
    write(dst, name, d, out)


def hmac(src, dst, name):
    d = load(src, name)
    out = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            out.append(" ".join([str(t["tcId"]), hx(t["key"]), hx(t["msg"]), hx(t["tag"]), R[t["result"]]]))
    write(dst, name, d, out)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    for c, hs in (("256", ("256", "512")), ("384", ("384", "512")), ("521", ("512",))):
        for hh in hs:
            ecdsa(src, dst, "ecdsa_secp%sr1_sha%s_p1363_test" % (c, hh))
    for c in ("256", "384", "521"):
        ecdh(src, dst, "ecdh_secp%sr1_ecpoint_test" % c)
    for bits, hs in ((2048, ("256", "384", "512")), (3072, ("256", "512")), (4096, ("256", "512")),
                     (8192, ("256", "512"))):
        for hh in hs:
            rsa_verify(src, dst, "rsa_signature_%d_sha%s_test" % (bits, hh))
    for bits in (1024, 1536, 2048, 3072, 4096):
        rsa_sign(src, dst, "rsa_pkcs1_%d_sig_gen_test" % bits)
    hmac(src, dst, "hmac_sha1_test")


if __name__ == "__main__":
    main()
