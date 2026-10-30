"""Independent public-key reference for sd_crypto's arithmetic cross-checks (01 Â§2.7.4).

Our own deliberately simple code on Python integers, written separately from src/sd_crypto (different
representation, textbook algorithms): square-and-multiply, extended Euclid, affine elliptic-curve formulas,
RFC 6979 with Python's hmac/hashlib, RSA key generation with Miller-Rabin and PKCS#1 v1.5 (RFC 8017 Â§9.2).

It also extracts the published vectors of RFC 6979 A.2.5-A.2.7, RFC 5903 Â§8 and RFC 3526 Â§2/Â§4 from the RFC
texts and checks every extracted value against this reference before writing it out.

Run (from the repository root; the RFC texts are inputs, not committed):
    python -I tests/vectors/refimpl/pk_ref.py <rfc5903.txt> <rfc6979.txt> <rfc3526.txt> tests/vectors
Writes refimpl/bn_random.txt, refimpl/ec_random.txt, refimpl/rsa_keys.txt, refimpl/dh_gex.txt,
rfc/rfc6979_ecdsa.txt, rfc/rfc5903_ecdh.txt. Deterministic (fixed seeds). The 16384-bit RSA key takes
several minutes.
"""
import hashlib
import hmac
import os
import random
import re
import sys

RNG = random.Random(20261025)

# ---------------------------------------------------------------- integers


def modexp(b, e, m):
    r, b = 1 % m, b % m
    while e:
        if e & 1:
            r = r * b % m
        b = b * b % m
        e >>= 1
    return r


def egcd_inv(a, m):
    """a^-1 mod m or None (extended Euclid)."""
    r0, r1, s0, s1 = m, a % m, 0, 1
    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
    if r0 != 1:
        return None
    return s0 % m


SMALL_PRIMES = [p for p in range(3, 8192, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def is_prime(n, rounds=24, rng=RNG):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for p in SMALL_PRIMES[:200]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = modexp(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def h(x, nbytes=None):
    if nbytes is None:
        nbytes = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(nbytes, "big").hex()


# ---------------------------------------------------------------- RFC text helpers

HEXLINE = re.compile(r"^\s+[0-9A-Fa-f]{4,8}( [0-9A-Fa-f]{4,8})*\s*$")


def hex_after(lines, i):
    out = []
    while i < len(lines) and not HEXLINE.match(lines[i]):
        i += 1
    while i < len(lines) and HEXLINE.match(lines[i]):
        out.append(lines[i].replace(" ", "").strip())
        i += 1
    return int("".join(out), 16)


def section(lines, title):
    return next(i for i, ln in enumerate(lines) if ln.startswith(title) and ".." not in ln)


def read_lines(path):
    return open(path, encoding="ascii", errors="replace").read().splitlines()


# ---------------------------------------------------------------- elliptic curves (affine)


class Curve:
    def __init__(self, name, p, b, n, gx, gy, hashname):
        self.name, self.p, self.b, self.n, self.g, self.hashname = name, p, b, n, (gx, gy), hashname
        self.flen = (p.bit_length() + 7) // 8
        self.qlen = n.bit_length()

    def on_curve(self, P):
        x, y = P
        return (y * y - (x ** 3 - 3 * x + self.b)) % self.p == 0

    def add(self, A, B):
        p = self.p
        if A is None:
            return B
        if B is None:
            return A
        if A[0] == B[0]:
            if (A[1] + B[1]) % p == 0:
                return None
            lam = (3 * A[0] * A[0] - 3) * egcd_inv(2 * A[1], p) % p
        else:
            lam = (B[1] - A[1]) * egcd_inv(B[0] - A[0], p) % p
        x = (lam * lam - A[0] - B[0]) % p
        return (x, (lam * (A[0] - x) - A[1]) % p)

    def mul(self, k, P):
        R, Q = None, P
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    def enc(self, P):
        return "04" + h(P[0], self.flen) + h(P[1], self.flen)


def load_curves(rfc5903):
    lines = read_lines(rfc5903)
    out = {}
    for name, sect, hn in (("P-256", "3.1.", "sha256"), ("P-384", "3.2.", "sha384"), ("P-521", "3.3.", "sha512")):
        s = next(i for i, ln in enumerate(lines) if ln.startswith(sect) and "Random ECP Group" in ln and ".." not in ln)
        def val(label):
            i = next(j for j in range(s, len(lines)) if lines[j].strip() == label)
            return hex_after(lines, i + 1)
        c = Curve(name, val("Group Prime/Irreducible Polynomial:"), val("Group Curve b:"), val("Group Order:"),
                  val("gx:"), val("gy:"), hn)
        assert c.on_curve(c.g) and c.mul(c.n, c.g) is None
        out[name] = c
    return out


def bits2int(c, b):
    v = int.from_bytes(b, "big")
    blen = 8 * len(b)
    return v >> (blen - c.qlen) if blen > c.qlen else v


def rfc6979_sign(c, hashname, x, digest, extra=b""):
    hl = hashlib.new(hashname).digest_size
    rl = (c.qlen + 7) // 8
    xo = x.to_bytes(rl, "big")
    ho = (bits2int(c, digest) % c.n).to_bytes(rl, "big")
    V, K = b"\x01" * hl, b"\x00" * hl
    K = hmac.new(K, V + b"\x00" + xo + ho + extra, hashname).digest()
    V = hmac.new(K, V, hashname).digest()
    K = hmac.new(K, V + b"\x01" + xo + ho + extra, hashname).digest()
    V = hmac.new(K, V, hashname).digest()
    e = bits2int(c, digest) % c.n
    while True:
        T = b""
        while len(T) < rl:
            V = hmac.new(K, V, hashname).digest()
            T += V
        k = bits2int(c, T[:rl])
        if 1 <= k < c.n:
            R = c.mul(k, c.g)
            r = R[0] % c.n
            s = egcd_inv(k, c.n) * (e + r * x) % c.n
            if r and s:
                return k, r, s
        K = hmac.new(K, V + b"\x00", hashname).digest()
        V = hmac.new(K, V, hashname).digest()


def ecdsa_verify(c, Q, digest, r, s):
    if not (1 <= r < c.n and 1 <= s < c.n):
        return False
    w = egcd_inv(s, c.n)
    e = bits2int(c, digest) % c.n
    X = c.add(c.mul(e * w % c.n, c.g), c.mul(r * w % c.n, Q))
    return X is not None and X[0] % c.n == r


# ---------------------------------------------------------------- outputs


def gen_bn(path):
    rng = random.Random(7748)
    lines = ["# sd_bn cross-check vectors from pk_ref.py (seed 7748). Hex big-endian.",
             "# x mod base exp expected   (modexp)",
             "# i mod a expected|-        (inverse, odd mod)",
             "# r mod a expected          (reduction, any mod)",
             "# m a b expected            (product)"]
    sizes = [1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 521, 1024, 1536, 2048,
             3072, 4096]

    def rnd(bits):
        return rng.getrandbits(bits) | (1 << (bits - 1)) if bits > 0 else 0

    for bits in sizes:
        for t in range(6 if bits <= 1024 else 2):
            if bits < 2:
                continue
            m = rnd(bits) | 1
            if t == 1:
                m = (1 << bits) - 1                          # all ones: maximal carries
            if t == 2 and bits > 2:
                m = (1 << (bits - 1)) + 1                    # minimal top
            m |= 1
            if m < 3:
                m = 3
            base = [0, 1, m - 1, m, m + 1, rng.randrange(m), rng.getrandbits(2 * bits)][t % 7] if t < 6 else rng.randrange(m)
            if t == 5:
                base = (1 << bits) - 1
            ebits = [1, 2, 17, 64, bits, 2 * bits][t]
            e = [0, 1, rng.getrandbits(ebits), (1 << ebits) - 1, rng.getrandbits(ebits), rng.getrandbits(ebits)][t]
            lines.append("x %s %s %s %s" % (h(m), h(base), h(e), h(modexp(base, e, m), (m.bit_length() + 7) // 8)))
            a = [0, 1, m - 1, rng.randrange(m), rng.randrange(m), m - 2][t]
            inv = egcd_inv(a, m)
            lines.append("i %s %s %s" % (h(m), h(a, (m.bit_length() + 7) // 8),
                                         "-" if inv is None else h(inv, (m.bit_length() + 7) // 8)))
            md = rnd(bits)
            av = rng.getrandbits(rng.randrange(1, 3 * bits + 2))
            lines.append("r %s %s %s" % (h(md), h(av), h(av % md, (md.bit_length() + 7) // 8)))
            a, b = rnd(bits), rng.getrandbits(rng.randrange(1, 2 * bits + 1))
            if t == 1:
                a, b = (1 << bits) - 1, (1 << bits) - 1
            lines.append("m %s %s %s" % (h(a), h(b), h(a * b)))
    # inverses with a common factor
    for _ in range(4):
        f = rng.getrandbits(64) | 1
        m = (rng.getrandbits(512) | 1) * f
        a = rng.getrandbits(400) * f % m
        lines.append("i %s %s %s" % (h(m), h(a, (m.bit_length() + 7) // 8), "-"))
    write(path, lines)


def gen_ec(path, curves):
    rng = random.Random(6979)
    lines = ["# NIST curve cross-check vectors from pk_ref.py (seed 6979), affine textbook arithmetic.",
             "# M curve k point result|-      scalar multiplication (k big-endian, field_len bytes)",
             "# A curve P Q result|-          complete addition",
             "# D curve P result              doubling",
             "# S curve hash d digest r s     deterministic ECDSA (RFC 6979, no extra data)"]
    for name, c in curves.items():
        cid = name[2:]
        n = c.n
        top = 1 << (4 * ((c.qlen + 3) // 4))                 # scalars the 4-bit windows cover
        scalars = [1, 2, 3, 15, 16, 17, n - 1, n - 2, n - 3, n // 2, (n + 1) // 2, (1 << (c.qlen - 1)),
                   top - 1, n, n + 1, 2 * n - 1]
        scalars += [rng.randrange(1, n) for _ in range(20)]
        pts = [c.g, c.mul(rng.randrange(1, n), c.g)]
        for P in pts:
            for k in scalars:
                if k >= top:
                    continue
                R = c.mul(k % n, P) if k % n else None
                lines.append("M %s %s %s %s" % (cid, h(k, c.flen), c.enc(P), c.enc(R) if R else "-"))
        for _ in range(8):
            P = c.mul(rng.randrange(1, n), c.g)
            Q = c.mul(rng.randrange(1, n), c.g)
            lines.append("A %s %s %s %s" % (cid, c.enc(P), c.enc(Q), c.enc(c.add(P, Q))))
            lines.append("A %s %s %s %s" % (cid, c.enc(P), c.enc(P), c.enc(c.add(P, P))))
            negP = (P[0], (-P[1]) % c.p)
            lines.append("A %s %s %s -" % (cid, c.enc(P), c.enc(negP)))
            lines.append("D %s %s %s" % (cid, c.enc(P), c.enc(c.add(P, P))))
        for hn in ("sha1", "sha256", "sha384", "sha512"):
            for _ in range(5):
                d = rng.randrange(1, n)
                dig = hashlib.new(hn, rng.getrandbits(256).to_bytes(32, "big")).digest()
                k, r, s = rfc6979_sign(c, hn, d, dig)
                lines.append("S %s %s %s %s %s %s" % (cid, hn, h(d, c.flen), dig.hex(), h(r, c.flen), h(s, c.flen)))
    write(path, lines)


DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rand_prime(bits, rng, cond=lambda p: True):
    while True:
        p = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if any(p % q == 0 for q in SMALL_PRIMES[:400]):
            continue
        if cond(p) and is_prime(p, 12, rng):
            return p


def gen_rsa(path):
    rng = random.Random(8017)
    lines = ["# RSA keys and PKCS#1 v1.5 signatures from pk_ref.py (seed 8017).",
             "# K bits n e d p q iqmp      (hex big-endian)",
             "# S hash digest signature    (signature with the preceding key)"]
    shapes = [(1024, 3, 512, 512), (1536, 65537, 700, 836), (2048, 65537, 1024, 1024), (3072, 65537, 1536, 1536),
              (4095, 17, 2047, 2048), (8192, 65537, 4096, 4096), (16384, 65537, 8192, 8192)]
    for bits, e, pb, qb in shapes:
        while True:
            p = rand_prime(pb, rng, lambda x: (x - 1) % e != 0)
            q = rand_prime(qb, rng, lambda x: (x - 1) % e != 0)
            n = p * q
            if p != q and n.bit_length() == bits:
                break
        if bits == 1536:
            p, q = min(p, q), max(p, q)     # p < q: q mod p reduction path
        lam = (p - 1) * (q - 1) // egcd_gcd(p - 1, q - 1)
        d = egcd_inv(e, lam)
        lines.append("K %d %s %s %s %s %s %s" % (bits, h(n), h(e), h(d), h(p), h(q), h(egcd_inv(q, p))))
        k = (bits + 7) // 8
        for hn in ("sha1", "sha256", "sha384", "sha512"):
            dig = hashlib.new(hn, rng.getrandbits(128).to_bytes(16, "big")).digest()
            t = DIGEST_INFO[hn] + dig
            em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
            s = modexp(int.from_bytes(em, "big"), d, n)
            assert modexp(s, e, n) == int.from_bytes(em, "big")
            lines.append("S %s %s %s" % (hn, dig.hex(), h(s, k)))
        print("rsa", bits, "done", flush=True)
    write(path, lines)


def egcd_gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def gen_dh(path, rfc3526):
    rng = random.Random(4419)
    lines = ["# Group-exchange validation cases from pk_ref.py (seed 4419).",
             "# G expect p g      expect: ok | crypto (not a safe prime / bad g) ; hex big-endian",
             "# RFC 3526 groups 5 (1536) and 15 (3072): safe primes that are not in sd_crypto's known-group table."]
    l = read_lines(rfc3526)
    for nb, k in ((1536, 741804), (3072, 1690314)):
        i = next(j for j, ln in enumerate(l) if re.search(r"prime is: 2\^%d - " % nb, ln))
        p = hex_after(l, i + 1)
        assert p == 2 ** nb - 2 ** (nb - 64) - 1 + 2 ** 64 * (pi_fixed(nb - 130) + k)
        assert is_prime(p, 4) and is_prime((p - 1) // 2, 4)
        lines.append("G ok %s 02" % h(p))
        lines.append("G ok %s 05" % h(p))
        lines.append("G crypto %s %s" % (h(p), h(p - 1)))
        lines.append("G crypto %s 01" % h(p))
        lines.append("G crypto %s %s" % (h(p + 4), "02"))   # p + 4 is 3 mod 4 and composite
    # a prime p = 3 mod 4 whose (p-1)/2 is composite but has no factor below 8192 (reaches Miller-Rabin)
    while True:
        p = rand_prime(2048, rng, lambda x: x % 4 == 3)
        q = (p - 1) // 2
        if all(q % s for s in SMALL_PRIMES) and all(p % s > 1 for s in SMALL_PRIMES) and not is_prime(q, 8, rng):
            break
    lines.append("G crypto %s 02" % h(p))
    # a composite p = 3 mod 4 that survives trial division (product of two 1024-bit primes)
    while True:
        a = rand_prime(1024, rng)
        b = rand_prime(1024, rng)
        p = a * b
        if p % 4 == 3 and all(p % s > 1 for s in SMALL_PRIMES) and all(((p - 1) // 2) % s for s in SMALL_PRIMES):
            break
    lines.append("G crypto %s 02" % h(p))
    # p = 2q + 1 with q prime but p composite, no factor below 8192 (reaches the Pocklington check)
    while True:
        q = rand_prime(2047, rng)
        p = 2 * q + 1
        if all(p % s > 1 for s in SMALL_PRIMES) and not is_prime(p, 8, rng):
            break
    lines.append("G crypto %s 02" % h(p))
    write(path, lines)


def arctan_inv(x, bits):
    one = 1 << bits
    term = one // x
    total, k, sign, x2 = term, 1, -1, x * x
    while term:
        term //= x2
        total += sign * (term // (2 * k + 1))
        sign, k = -sign, k + 1
    return total


def pi_fixed(bits):
    g = bits + 64
    return (16 * arctan_inv(5, g) - 4 * arctan_inv(239, g)) >> 64


def extract_6979(path, rfc6979, curves):
    l = read_lines(rfc6979)
    lines = ["# RFC 6979 A.2.5-A.2.7 (P-256/384/521), checked against pk_ref.py. SHA-224 cases are left out",
             "# (sd_crypto has no SHA-224).",
             "# curve x Ux Uy hash message k r s"]
    for sect, name in (("A.2.5.", "P-256"), ("A.2.6.", "P-384"), ("A.2.7.", "P-521")):
        c = curves[name]
        s = section(l, sect)
        end = next((i for i in range(s + 1, len(l)) if re.match(r"^A\.\d", l[i])), len(l))

        def val(label, start):
            i = next(j for j in range(start, end) if re.match(r"^\s+%s = " % label, l[j]))
            parts = [l[i].split("=")[1].strip()]
            j = i + 1
            while j < end and re.match(r"^\s+[0-9A-F]+\s*$", l[j]):
                parts.append(l[j].strip())
                j += 1
            return int("".join(parts), 16), j
        x, i = val("x", s)
        ux, i = val("Ux", i)
        uy, i = val("Uy", i)
        assert c.mul(x, c.g) == (ux, uy)
        j = i
        while True:
            m = next((k for k in range(j, end) if re.search(r'With SHA-(\d+), message = "(\w+)":', l[k])), None)
            if m is None:
                break
            hm = re.search(r'With SHA-(\d+), message = "(\w+)":', l[m])
            hn, msg = "sha" + hm.group(1), hm.group(2)
            k, j = val("k", m)
            r, j = val("r", j)
            sv, j = val("s", j)
            if hn == "sha224":
                continue
            dig = hashlib.new(hn, msg.encode()).digest()
            assert rfc6979_sign(c, hn, x, dig) == (k, r, sv), (name, hn, msg)
            lines.append("%s %s %s %s %s %s %s %s %s" % (name[2:], h(x, c.flen), h(ux, c.flen), h(uy, c.flen), hn,
                                                        msg.encode().hex(), h(k, c.flen), h(r, c.flen), h(sv, c.flen)))
    write(path, lines)


def extract_5903(path, rfc5903, curves):
    l = read_lines(rfc5903)
    lines = ["# RFC 5903 Section 8 ECDH test vectors, checked against pk_ref.py.",
             "# curve i gix giy r grx gry girx giry"]
    for sect, name in (("8.1.", "P-256"), ("8.2.", "P-384"), ("8.3.", "P-521")):
        c = curves[name]
        s = next(i for i, ln in enumerate(l) if ln.startswith(sect) and "Random ECP Group" in ln and ".." not in ln)
        vals = {}
        for lab in ("i:", "gix:", "giy:", "r:", "grx:", "gry:", "girx:", "giry:"):
            i = next(j for j in range(s, len(l)) if l[j].strip() == lab)
            vals[lab] = hex_after(l, i + 1)
        assert c.mul(vals["i:"], c.g) == (vals["gix:"], vals["giy:"])
        assert c.mul(vals["r:"], c.g) == (vals["grx:"], vals["gry:"])
        assert c.mul(vals["i:"], (vals["grx:"], vals["gry:"])) == (vals["girx:"], vals["giry:"])
        lines.append(" ".join([name[2:]] + [h(vals[k], c.flen) for k in
                                            ("i:", "gix:", "giy:", "r:", "grx:", "gry:", "girx:", "giry:")]))
    write(path, lines)


def write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def main():
    rfc5903, rfc6979, rfc3526, out = sys.argv[1:5]
    only = sys.argv[5:]
    curves = load_curves(rfc5903)
    jobs = {
        "rfc": lambda: (extract_6979(os.path.join(out, "rfc", "rfc6979_ecdsa.txt"), rfc6979, curves),
                        extract_5903(os.path.join(out, "rfc", "rfc5903_ecdh.txt"), rfc5903, curves)),
        "bn": lambda: gen_bn(os.path.join(out, "refimpl", "bn_random.txt")),
        "ec": lambda: gen_ec(os.path.join(out, "refimpl", "ec_random.txt"), curves),
        "dh": lambda: gen_dh(os.path.join(out, "refimpl", "dh_gex.txt"), rfc3526),
        "rsa": lambda: gen_rsa(os.path.join(out, "refimpl", "rsa_keys.txt")),
    }
    for name, fn in jobs.items():
        if not only or name in only:
            fn()
            print(name, "written", flush=True)


if __name__ == "__main__":
    main()
