"""Generates pk_consts.inc: the RFC 2409 / RFC 3526 MODP primes and the NIST P-256/384/521 constants in the
limb form used by bn.c and ec_p.c (32-bit and 64-bit limbs, Montgomery constants precomputed).

Run by hand; the output is committed:
    python -I gen_pk_consts.py <rfc2409.txt> <rfc3526.txt> <rfc5903.txt> pk_consts.inc

Data sources are the specifications themselves (decisions.md D1: numbers, not code):
  - MODP primes: the hexadecimal values printed in RFC 2409 Section 6.2 and RFC 3526 Sections 3, 5, 7.
    Each one is also recomputed from its defining formula 2^n - 2^(n-64) - 1 + 2^64 * ([2^(n-130) pi] + k)
    with pi computed here (Machin's formula), and checked to be a safe prime (Miller-Rabin on p and
    (p-1)/2) with generator 2.
  - Curves: p, b, order n, gx, gy as printed in RFC 5903 Section 3 (identical to FIPS 186-4 D.1.2).
    Checked here: p and n prime (Miller-Rabin), p matches the generalized-Mersenne formula, G on
    y^2 = x^3 - 3x + b, and n*G = O (affine double-and-add).
"""
import random
import re
import sys

RNG = random.Random(5903)


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = RNG.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def arctan_inv(x, bits):
    """atan(1/x) * 2^bits, truncated (Taylor series in fixed point)."""
    one = 1 << bits
    term = one // x
    total, k, sign, x2 = term, 1, -1, x * x
    while term:
        term //= x2
        total += sign * (term // (2 * k + 1))
        sign, k = -sign, k + 1
    return total


def pi_fixed(bits):
    """floor(pi * 2^bits), with 64 guard bits."""
    g = bits + 64
    return (16 * arctan_inv(5, g) - 4 * arctan_inv(239, g)) >> 64


def modp_formula(n, k):
    return 2**n - 2**(n - 64) - 1 + 2**64 * (pi_fixed(n - 130) + k)


def hex_blocks_after(lines, start):
    out, i = [], start
    while i < len(lines) and not re.match(r"^\s+[0-9A-F]{4,8}( [0-9A-F]{4,8})*\s*$", lines[i]):
        i += 1
    while i < len(lines) and re.match(r"^\s+[0-9A-F]{4,8}( [0-9A-F]{4,8})*\s*$", lines[i]):
        out.append(lines[i].replace(" ", "").strip())
        i += 1
    return int("".join(out), 16)


def rfc_modp(path, nbits, k):
    lines = open(path, encoding="ascii", errors="replace").read().splitlines()
    pat = re.compile(r"prime is:? 2\^%d - 2 ?\^%d - 1 \+ 2\^64 \* \{ \[2\^%d pi\] \+ %d \}"
                     % (nbits, nbits - 64, nbits - 130, k))
    for i, ln in enumerate(lines):
        if pat.search(ln):
            return hex_blocks_after(lines, i + 1)
    raise SystemExit("prime %d not found in %s" % (nbits, path))


def rfc5903_curve(path, section_title):
    lines = open(path, encoding="ascii", errors="replace").read().splitlines()
    start = next(i for i, ln in enumerate(lines)
                 if ln.startswith(section_title) and "Random ECP Group" in ln and ".." not in ln)
    vals = {}
    for label, key in (("Group Prime/Irreducible Polynomial:", "p"), ("Group Curve b:", "b"),
                       ("Group Order:", "n"), ("gx:", "gx"), ("gy:", "gy")):
        i = next(j for j in range(start, len(lines)) if lines[j].strip() == label)
        vals[key] = hex_blocks_after(lines, i + 1)
    return vals


def ec_mul_affine(k, P, p):
    def add(A, B):
        if A is None:
            return B
        if B is None:
            return A
        if A[0] == B[0]:
            if (A[1] + B[1]) % p == 0:
                return None
            lam = (3 * A[0] * A[0] - 3) * pow(2 * A[1], p - 2, p) % p
        else:
            lam = (B[1] - A[1]) * pow(B[0] - A[0], p - 2, p) % p
        x = (lam * lam - A[0] - B[0]) % p
        return (x, (lam * (A[0] - x) - A[1]) % p)
    R = None
    for bit in bin(k)[2:]:
        R = add(R, R)
        if bit == "1":
            R = add(R, P)
    return R


def limbs(x, w, n):
    return [(x >> (w * i)) & ((1 << w) - 1) for i in range(n)]


def c_array(name, vals, w):
    fmt = "0x%016xull" if w == 64 else "0x%08xu"
    per = 4 if w == 64 else 6
    body = []
    for i in range(0, len(vals), per):
        body.append("  " + ", ".join(fmt % v for v in vals[i:i + per]) + ",")
    return "static const sd_bn_limb %s[%d] = {\n%s\n};\n" % (name, len(vals), "\n".join(body))


def mont_set(prefix, m, w):
    n = (m.bit_length() + w - 1) // w
    R = 1 << (w * n)
    m0i = (-pow(m, -1, 1 << w)) % (1 << w)
    out = c_array(prefix, limbs(m, w, n), w)
    out += c_array(prefix + "_r2", limbs(R * R % m, w, n), w)
    out += c_array(prefix + "_one", limbs(R % m, w, n), w)
    out += "#define %s_M0I 0x%x%s\n" % (prefix.upper(), m0i, "ull" if w == 64 else "u")
    return out, n, R


def main():
    rfc2409, rfc3526, rfc5903, outp = sys.argv[1:5]
    groups = [(1024, 129093, rfc2409), (2048, 124476, rfc3526), (4096, 240904, rfc3526),
              (8192, 4743158, rfc3526)]
    out = ["/* Generated by gen_pk_consts.py from RFC 2409, RFC 3526 and RFC 5903 (see the script). Do not edit. */\n"]
    for nbits, k, path in groups:
        printed = rfc_modp(path, nbits, k)
        if printed != modp_formula(nbits, k):
            raise SystemExit("MODP %d: printed value differs from the pi formula" % nbits)
        if printed.bit_length() != nbits or not is_probable_prime(printed, 8) or \
                not is_probable_prime((printed - 1) // 2, 8):
            raise SystemExit("MODP %d is not a safe prime of the right size" % nbits)
        if pow(2, (printed - 1) // 2, printed) not in (1, printed - 1):
            raise SystemExit("MODP %d: generator check failed" % nbits)
        b = printed.to_bytes(nbits // 8, "big")
        rows = ["  " + ", ".join("0x%02x" % x for x in b[i:i + 16]) + "," for i in range(0, len(b), 16)]
        out.append("static const uint8_t k_modp_%d[%d] = {\n%s\n};\n" % (nbits, nbits // 8, "\n".join(rows)))

    curves = [("p256", "3.1.", 2**256 - 2**224 + 2**192 + 2**96 - 1),
              ("p384", "3.2.", 2**384 - 2**128 - 2**96 + 2**32 - 1),
              ("p521", "3.3.", 2**521 - 1)]
    for w in (64, 32):
        out.append("\n#if SD_BN_LIMB_BITS == %d\n" % w)
        for name, sect, pform in curves:
            c = rfc5903_curve(rfc5903, sect)
            p, b, n, gx, gy = c["p"], c["b"], c["n"], c["gx"], c["gy"]
            if w == 64:
                if p != pform or not is_probable_prime(p) or not is_probable_prime(n):
                    raise SystemExit("%s: p or n check failed" % name)
                if (gy * gy - (gx ** 3 - 3 * gx + b)) % p != 0:
                    raise SystemExit("%s: G not on the curve" % name)
                if ec_mul_affine(n, (gx, gy), p) is not None:
                    raise SystemExit("%s: n*G != O" % name)
            txt, nl, R = mont_set("k_%s_p" % name, p, w)
            out.append(txt)
            txt, nl2, R2 = mont_set("k_%s_n" % name, n, w)
            if nl2 != nl:
                raise SystemExit("limb counts differ")
            out.append(txt)
            out.append(c_array("k_%s_b_m" % name, limbs(b * R % p, w, nl), w))
            out.append(c_array("k_%s_b3_m" % name, limbs(3 * b * R % p, w, nl), w))
            out.append(c_array("k_%s_gx_m" % name, limbs(gx * R % p, w, nl), w))
            out.append(c_array("k_%s_gy_m" % name, limbs(gy * R % p, w, nl), w))
            # Plain (normal-form) b, G for the NIST field code of ec_p.c (the reductions work on normal form).
            out.append(c_array("k_%s_b" % name, limbs(b, w, nl), w))
            out.append(c_array("k_%s_gx" % name, limbs(gx, w, nl), w))
            out.append(c_array("k_%s_gy" % name, limbs(gy, w, nl), w))
            out.append("#define K_%s_LIMBS %d\n" % (name.upper(), nl))
        out.append("#endif\n")
    with open(outp, "w", encoding="ascii", newline="\n") as f:
        f.write("".join(out))


if __name__ == "__main__":
    main()
