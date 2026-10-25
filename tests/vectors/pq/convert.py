# Converts the downloaded M2 symmetric/PQ test vectors (see PROVENANCE.md in this directory) into
# the compact line format read by tests/unit/sd_crypto_pq: one case per line, space-separated hex
# fields, "-" for an empty field, "#" comments. Our own script; data only.
#
#   python -I tests/vectors/pq/convert.py <download dir> tests/vectors/pq
#
# <download dir> holds the Wycheproof JSON files, acvp/keygen.json and acvp/encdec.json, the
# blake2b-kat.txt file and the unzipped CAVP archives under x/<archive name>/.
import hashlib
import json
import os
import sys


def h(s):
    return s.lower() if s else "-"


def rsp_records(path):
    """Yields (section, dict) for every record of a CAVP .rsp file."""
    section, cur = "", {}
    for line in open(path, encoding="ascii", errors="replace"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            if cur:
                yield section, cur
                cur = {}
            if "=" not in line:
                section = line[1:-1]
            else:
                k, v = line[1:-1].split("=", 1)
                cur = {}
                section_kv[k.strip()] = v.strip()
            continue
        if not line or line.startswith("#"):
            if cur:
                yield section, cur
                cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    if cur:
        yield section, cur


section_kv = {}


def write(out_dir, name, header, lines):
    with open(os.path.join(out_dir, name), "w", encoding="ascii", newline="\n") as f:
        f.write("# " + header + "\n")
        for l in lines:
            f.write(l + "\n")
    print("%s: %d cases" % (name, len(lines)))


def sha3(src, out):
    x = os.path.join(src, "x")
    for bits in (256, 512):
        lines = []
        for _, r in rsp_records(os.path.join(x, "sha-3bytetestvectors", "SHA3_%dShortMsg.rsp" % bits)):
            if "Len" in r:
                n = int(r["Len"])
                msg = r["Msg"][: n // 4]
                lines.append("%s %s" % (h(msg), r["MD"]))
        write(out, "sha3_%d_short.txt" % bits, "NIST CAVP SHA3VS SHA3_%dShortMsg.rsp: msg md" % bits, lines)
        seed, lines = None, []
        for _, r in rsp_records(os.path.join(x, "sha-3bytetestvectors", "SHA3_%dMonte.rsp" % bits)):
            if "Seed" in r:
                seed = r["Seed"]
            if "MD" in r:
                lines.append("%s %s" % (r["COUNT"], r["MD"]))
        # self-check of the Monte procedure against Python's hashlib (an independent implementation)
        md = bytes.fromhex(seed)
        for i in range(2):
            for _ in range(1000):
                md = hashlib.new("sha3_%d" % bits, md).digest()
            assert md.hex() == lines[i].split()[1]
        write(out, "sha3_%d_monte.txt" % bits,
              "NIST CAVP SHA3VS SHA3_%dMonte.rsp: count md (seed line first)" % bits, ["seed " + seed] + lines)
    for bits in (128, 256):
        lines = []
        for _, r in rsp_records(os.path.join(x, "shakebytetestvectors", "SHAKE%dShortMsg.rsp" % bits)):
            if "Len" in r:
                n = int(r["Len"])
                lines.append("%s %s" % (h(r["Msg"][: n // 4]), r["Output"]))
        for i, (_, r) in enumerate(rsp_records(os.path.join(x, "shakebytetestvectors", "SHAKE%dVariableOut.rsp" % bits))):
            if "Outputlen" in r and i % 5 == 0:
                assert int(r["Outputlen"]) % 8 == 0
                lines.append("%s %s" % (h(r["Msg"]), r["Output"]))
        write(out, "shake%d.txt" % bits,
              "NIST CAVP SHAKEVS SHAKE%dShortMsg.rsp + every 5th case of SHAKE%dVariableOut.rsp: msg output" % (bits, bits), lines)


def cbc(src, out):
    x = os.path.join(src, "x")
    lines = []
    for kl in (128, 192, 256):
        for kind in ("GFSbox", "KeySbox"):
            for sec, r in rsp_records(os.path.join(x, "KAT_AES", "CBC%s%d.rsp" % (kind, kl))):
                if "KEY" in r:
                    lines.append("%d %s %s %s %s" % (sec == "ENCRYPT", r["KEY"], r["IV"], r["PLAINTEXT"], r["CIPHERTEXT"]))
        for sec, r in rsp_records(os.path.join(x, "aesmmt", "CBCMMT%d.rsp" % kl)):
            if "KEY" in r:
                lines.append("%d %s %s %s %s" % (sec == "ENCRYPT", r["KEY"], r["IV"], r["PLAINTEXT"], r["CIPHERTEXT"]))
    write(out, "aes_cbc_cavp.txt", "NIST CAVP AESAVS CBC KAT (GFSbox, KeySbox) + MMT: enc key iv pt ct",
          lines)
    lines = []
    for f in ("TCBCinvperm", "TCBCpermop", "TCBCsubtab", "TCBCvarkey", "TCBCvartext"):
        for sec, r in rsp_records(os.path.join(x, "KAT_TDES", "KAT_TDES", f + ".rsp")):
            if "KEYs" in r:
                k = r["KEYs"] * 3
                lines.append("%d %s %s %s %s" % (sec == "ENCRYPT", k, r["IV"], r["PLAINTEXT"], r["CIPHERTEXT"]))
    for f in ("TCBCMMT2", "TCBCMMT3"):
        for sec, r in rsp_records(os.path.join(x, "tdesmmt", f + ".rsp")):
            if "KEY1" in r:
                k = r["KEY1"] + r["KEY2"] + r["KEY3"]
                lines.append("%d %s %s %s %s" % (sec == "ENCRYPT", k, r["IV"], r["PLAINTEXT"], r["CIPHERTEXT"]))
    for f in ("TECBMMT2", "TECBMMT3"):
        for sec, r in rsp_records(os.path.join(x, "tdesmmt", f + ".rsp")):
            if "KEY1" in r:
                k = r["KEY1"] + r["KEY2"] + r["KEY3"]
                lines.append("%d %s - %s %s" % (sec == "ENCRYPT", k, r["PLAINTEXT"], r["CIPHERTEXT"]))
    write(out, "tdes_cavp.txt",
          "NIST CAVP TDESVS CBC KAT (invperm, permop, subtab, varkey, vartext; keying option 3 as K||K||K) + "
          "CBC/ECB MMT (options 1 and 2): enc key iv(- = ECB) pt ct", lines)


def mlkem(src, out):
    kg = json.load(open(os.path.join(src, "acvp", "keygen.json"), encoding="utf-8"))
    lines = []
    for g in kg["testGroups"]:
        if g["parameterSet"] == "ML-KEM-768":
            for t in g["tests"]:
                lines.append("%s %s %s %s" % (h(t["d"]), h(t["z"]), h(t["ek"]), h(t["dk"])))
    write(out, "mlkem768_acvp_keygen.txt", "NIST ACVP ML-KEM-keyGen-FIPS203 internalProjection, ML-KEM-768: d z ek dk",
          lines)
    ed = json.load(open(os.path.join(src, "acvp", "encdec.json"), encoding="utf-8"))
    enc, dec, chk = [], [], []
    for g in ed["testGroups"]:
        if g["parameterSet"] != "ML-KEM-768":
            continue
        for t in g["tests"]:
            if g["function"] == "encapsulation":
                enc.append("%s %s %s %s" % (h(t["ek"]), h(t["m"]), h(t["c"]), h(t["k"])))
            elif g["function"] == "decapsulation":
                dec.append("%s %s %s" % (h(t["dk"]), h(t["c"]), h(t["k"])))
            elif g["function"] == "encapsulationKeyCheck":
                chk.append("ek %d %s" % (t["testPassed"], h(t["ek"])))
            elif g["function"] == "decapsulationKeyCheck":
                chk.append("dk %d %s" % (t["testPassed"], h(t["dk"])))
    write(out, "mlkem768_acvp_encap.txt", "NIST ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-768 encapsulation: ek m c k", enc)
    write(out, "mlkem768_acvp_decap.txt",
          "NIST ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-768 decapsulation (incl. modified ciphertexts): dk c k", dec)
    write(out, "mlkem768_acvp_keycheck.txt",
          "NIST ACVP ML-KEM-encapDecap-FIPS203, ML-KEM-768 key checks: ek|dk passed key", chk)

    def wp(name):
        return json.load(open(os.path.join(src, name), encoding="utf-8"))

    lines = []
    for g in wp("mlkem_768_test.json")["testGroups"]:
        for t in g["tests"]:
            lines.append("%d %s %s %s %s %s" % (t["tcId"], t["result"], h(t.get("seed")), h(t.get("ek")), h(t.get("c")), h(t.get("K"))))
    write(out, "wycheproof_mlkem768.txt", "Wycheproof mlkem_768_test.json: tcId result seed(d||z) ek c K", lines)
    lines = []
    for g in wp("mlkem_768_encaps_test.json")["testGroups"]:
        for t in g["tests"]:
            lines.append("%d %s %s %s %s %s" % (t["tcId"], t["result"], h(t.get("m")), h(t.get("ek")), h(t.get("c")), h(t.get("K"))))
    write(out, "wycheproof_mlkem768_encaps.txt", "Wycheproof mlkem_768_encaps_test.json: tcId result m ek c K", lines)
    lines = []
    for g in wp("mlkem_768_keygen_seed_test.json")["testGroups"]:
        for t in g["tests"]:
            lines.append("%d %s %s %s" % (t["tcId"], h(t["seed"]), h(t["ek"]), h(t["dk"])))
    write(out, "wycheproof_mlkem768_keygen.txt", "Wycheproof mlkem_768_keygen_seed_test.json: tcId seed(d||z) ek dk",
          lines)
    lines = []
    for g in wp("mlkem_768_semi_expanded_decaps_test.json")["testGroups"]:
        for t in g["tests"]:
            lines.append("%d %s %s %s %s" % (t["tcId"], t["result"], h(t.get("dk")), h(t.get("c")), h(t.get("K"))))
    write(out, "wycheproof_mlkem768_decaps.txt",
          "Wycheproof mlkem_768_semi_expanded_decaps_test.json: tcId result dk c K", lines)


def blake2b(src, out):
    lines, cur = [], {}
    for line in open(os.path.join(src, "blake2b-kat.txt"), encoding="ascii"):
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            cur[k] = v.strip()
            if k == "hash":
                lines.append("%s %s %s" % (h(cur["in"]), h(cur["key"]), cur["hash"]))
                cur = {}
    write(out, "blake2b_kat.txt", "BLAKE2 reference KAT blake2b-kat.txt (keyed, 64-byte key and output): in key hash",
          lines)


def main():
    src, out = sys.argv[1], sys.argv[2]
    sha3(src, out)
    cbc(src, out)
    mlkem(src, out)
    blake2b(src, out)


main()
