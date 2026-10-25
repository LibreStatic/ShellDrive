# Writes PuTTY PPK v3 fixtures (aes256-cbc, Argon2id/Argon2i/Argon2d) from an unencrypted OpenSSH
# Ed25519 private key, for the PPK v3 key-derivation cross-check in tests/unit/sd_crypto_pq.
# puttygen is not available on the build machine, so this is our own deliberately simple reference
# (PuTTY manual Appendix C, RFC 9106, FIPS 197): pure-Python Argon2 on top of hashlib.blake2b and a
# textbook AES-256 encryptor. Both are self-checked against the RFC 9106 section 5 tags and FIPS 197
# C.3 before anything is written. Test-only code, never shipped.
#
#   ssh-keygen -t ed25519 -N "" -C "sd_crypto ppk fixture" -f <tmp>/k
#   python -I tests/vectors/pq/ppk_fixture.py <tmp>/k tests/vectors/pq
import base64
import hashlib
import hmac
import os
import struct
import sys

M64 = (1 << 64) - 1


# ---- Argon2 (RFC 9106) ----

def blake2b_long(out_len, data):
    pre = struct.pack("<I", out_len) + data
    if out_len <= 64:
        return hashlib.blake2b(pre, digest_size=out_len).digest()
    v = hashlib.blake2b(pre, digest_size=64).digest()
    out = v[:32]
    left = out_len - 32
    while left > 64:
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
        left -= 32
    return out + hashlib.blake2b(v, digest_size=left).digest()


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def gb(v, a, b, c, d):
    def f(x, y):
        return (x + y + 2 * (x & 0xffffffff) * (y & 0xffffffff)) & M64
    v[a] = f(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = f(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = f(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = f(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 63)


def perm(v, idx):
    w = [v[i] for i in idx]
    for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                       (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
        gb(w, a, b, c, d)
    for k, i in enumerate(idx):
        v[i] = w[k]


def compress(x, y):
    r = [a ^ b for a, b in zip(x, y)]
    z = list(r)
    for i in range(8):
        perm(z, list(range(16 * i, 16 * i + 16)))
    for i in range(8):
        perm(z, [2 * i + 16 * j + k for j in range(8) for k in (0, 1)])
    return [a ^ b for a, b in zip(z, r)]


def argon2(typ, password, salt, t, m, p, tag_len, secret=b"", ad=b""):
    def le(x):
        return struct.pack("<I", x)
    h0 = hashlib.blake2b(le(p) + le(tag_len) + le(m) + le(t) + le(0x13) + le(typ) + le(len(password)) + password +
                         le(len(salt)) + salt + le(len(secret)) + secret + le(len(ad)) + ad, digest_size=64).digest()
    seg = m // (4 * p)
    q = 4 * seg
    mm = q * p
    B = [[None] * q for _ in range(p)]
    for l in range(p):
        for i in (0, 1):
            b = blake2b_long(1024, h0 + le(i) + le(l))
            B[l][i] = list(struct.unpack("<128Q", b))
    zero = [0] * 128
    for r in range(t):
        for s in range(4):
            for l in range(p):
                indep = typ == 1 or (typ == 2 and r == 0 and s < 2)
                start = 2 if (r == 0 and s == 0) else 0
                counter, addr = 0, None
                for i in range(start, seg):
                    j = s * seg + i
                    prev = B[l][j - 1] if j > 0 else B[l][q - 1]
                    if indep:
                        if i == start or i % 128 == 0:
                            counter += 1
                            z = [r, l, s, mm, t, typ, counter] + [0] * 121
                            addr = compress(zero, compress(zero, z))
                        rnd = addr[i % 128]
                    else:
                        rnd = prev[0]
                    j1, j2 = rnd & 0xffffffff, rnd >> 32
                    rl = l if (r == 0 and s == 0) else j2 % p
                    if r == 0:
                        area = s * seg + i - 1 if rl == l else s * seg - (1 if i == 0 else 0)
                    else:
                        area = q - seg + i - 1 if rl == l else q - seg - (1 if i == 0 else 0)
                    x = (j1 * j1) >> 32
                    y = (area * x) >> 32
                    rel = area - 1 - y
                    sp = (s + 1) * seg if (r != 0 and s != 3) else 0
                    ref = B[rl][(sp + rel) % q]
                    nb = compress(prev, ref)
                    if r != 0:
                        nb = [a ^ b for a, b in zip(nb, B[l][j])]
                    B[l][j] = nb
    c = B[0][q - 1]
    for l in range(1, p):
        c = [a ^ b for a, b in zip(c, B[l][q - 1])]
    return blake2b_long(tag_len, struct.pack("<128Q", *c))


def argon2_selftest():
    tags = {
        0: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        1: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        2: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    }
    for typ, tag in tags.items():
        got = argon2(typ, b"\x01" * 32, b"\x02" * 16, 3, 32, 4, 32, b"\x03" * 8, b"\x04" * 12)
        assert got.hex() == tag, (typ, got.hex())


# ---- AES-256 encryption (FIPS 197), S-box from the GF(2^8) inverse and the affine map ----

def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 0xff
        b >>= 1
    return r


SBOX = []
for _x in range(256):
    _inv = next((y for y in range(1, 256) if gmul(_x, y) == 1), 0) if _x else 0
    _s = 0x63
    for _k in range(5):
        _s ^= ((_inv << _k) | (_inv >> (8 - _k))) & 0xff
    SBOX.append(_s)


def aes256_expand(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = gmul(rcon, 2)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(15)]


def aes_encrypt_block(rk, blk):
    s = [a ^ b for a, b in zip(blk, rk[0])]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]       # ShiftRows (column-major state)
        if r != 14:
            n = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                n += [gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3), gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)]
            s = n
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def aes256_cbc_encrypt(key, iv, data):
    rk, out, prev = aes256_expand(key), b"", iv
    for i in range(0, len(data), 16):
        prev = aes_encrypt_block(rk, [a ^ b for a, b in zip(data[i:i + 16], prev)])
        out += prev
    return out


def aes_selftest():
    rk = aes256_expand(bytes(range(32)))
    assert aes_encrypt_block(rk, list(bytes.fromhex("00112233445566778899aabbccddeeff"))).hex() == \
        "8ea2b7ca516745bfeafc49904b496089"


# ---- PPK v3 ----

def sstr(b):
    return struct.pack(">I", len(b)) + b


def mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big") if n else b""
    return sstr(b)


def read_openssh_ed25519(path):
    lines = open(path).read().strip().splitlines()
    blob = base64.b64decode("".join(lines[1:-1]))
    assert blob.startswith(b"openssh-key-v1\0")
    pos = len(b"openssh-key-v1\0")

    def get():
        nonlocal pos
        n = struct.unpack(">I", blob[pos:pos + 4])[0]
        v = blob[pos + 4:pos + 4 + n]
        pos += 4 + n
        return v
    assert get() == b"none" and get() == b"none"
    get()
    pos += 4
    pub_blob = get()
    priv = get()
    pos2 = 8
    def pget():
        nonlocal pos2
        n = struct.unpack(">I", priv[pos2:pos2 + 4])[0]
        v = priv[pos2 + 4:pos2 + 4 + n]
        pos2 += 4 + n
        return v
    assert pget() == b"ssh-ed25519"
    pub = pget()
    sk = pget()
    assert len(pub) == 32 and len(sk) == 64 and sk[32:] == pub
    return pub_blob, sk[:32]


def b64lines(b):
    s = base64.b64encode(b).decode()
    return [s[i:i + 64] for i in range(0, len(s), 64)]


def write_ppk(path, flavour, typ, mem, passes, par, passphrase, pub_blob, seed, salt, pad):
    alg, enc, comment = "ssh-ed25519", "aes256-cbc", "sd_crypto ppk v3 fixture (%s)" % flavour
    priv = mpint(int.from_bytes(seed, "little"))
    priv += pad[: (-len(priv)) % 16]
    km = argon2(typ, passphrase, salt, passes, mem, par, 80)
    key, iv, mackey = km[:32], km[32:48], km[48:]
    ct = aes256_cbc_encrypt(key, iv, priv)
    mac = hmac.new(mackey, sstr(alg.encode()) + sstr(enc.encode()) + sstr(comment.encode()) + sstr(pub_blob) +
                   sstr(priv), hashlib.sha256).hexdigest()
    pl, kl = b64lines(pub_blob), b64lines(ct)
    out = ["PuTTY-User-Key-File-3: " + alg, "Encryption: " + enc, "Comment: " + comment,
           "Public-Lines: %d" % len(pl)] + pl + [
        "Key-Derivation: " + flavour, "Argon2-Memory: %d" % mem, "Argon2-Passes: %d" % passes,
        "Argon2-Parallelism: %d" % par, "Argon2-Salt: " + salt.hex(), "Private-Lines: %d" % len(kl)] + kl + [
        "Private-MAC: " + mac]
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")


def main():
    argon2_selftest()
    aes_selftest()
    pub_blob, seed = read_openssh_ed25519(sys.argv[1])
    out = sys.argv[2]
    pp = b"correct horse battery staple"
    for flavour, typ, mem, passes, par in (("Argon2id", 2, 1024, 2, 1), ("Argon2i", 1, 512, 3, 2),
                                           ("Argon2d", 0, 256, 1, 1)):
        write_ppk(os.path.join(out, "ed25519_ppk3_%s.ppk" % flavour.lower()), flavour, typ, mem, passes, par, pp,
                  pub_blob, seed, os.urandom(16), os.urandom(16))
        print("wrote", flavour)


main()
