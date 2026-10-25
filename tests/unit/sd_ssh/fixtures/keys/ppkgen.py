#!/usr/bin/env python3
"""Reference PuTTY PPK v2/v3 writer for the sd_ssh key fixtures (test material only, D21).

Written from the PPK format description (PuTTY documentation, appendix C) because puttygen is not
available on the fixture machine. Argon2 (RFC 9106) is implemented here in pure Python and checked
against the RFC test vectors before use (--selftest runs only that).

usage: ppkgen.py <2|3> <passphrase|none> <openssh-private-key> <out.ppk>
                 [--kdf Argon2id|Argon2i|Argon2d] [--mem KiB] [--passes N] [--lanes N]
       ppkgen.py --selftest
"""
import base64
import hashlib
import hmac
import os
import struct
import sys

M64 = (1 << 64) - 1


# ---- Argon2 (RFC 9106, version 0x13) ----

def _le32(x):
    return struct.pack('<I', x)


def _hprime(outlen, data):
    if outlen <= 64:
        return hashlib.blake2b(_le32(outlen) + data, digest_size=outlen).digest()
    r = (outlen + 31) // 32 - 2
    v = hashlib.blake2b(_le32(outlen) + data, digest_size=64).digest()
    out = v[:32]
    for _ in range(2, r + 1):
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
    out += hashlib.blake2b(v, digest_size=outlen - 32 * r).digest()
    return out


def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def _gb(v, a, b, c, d):
    va, vb, vc, vd = v[a], v[b], v[c], v[d]
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd = _rotr(vd ^ va, 32)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb = _rotr(vb ^ vc, 24)
    va = (va + vb + 2 * (va & 0xFFFFFFFF) * (vb & 0xFFFFFFFF)) & M64
    vd = _rotr(vd ^ va, 16)
    vc = (vc + vd + 2 * (vc & 0xFFFFFFFF) * (vd & 0xFFFFFFFF)) & M64
    vb = _rotr(vb ^ vc, 63)
    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _p(v):
    _gb(v, 0, 4, 8, 12); _gb(v, 1, 5, 9, 13); _gb(v, 2, 6, 10, 14); _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15); _gb(v, 1, 6, 11, 12); _gb(v, 2, 7, 8, 13); _gb(v, 3, 4, 9, 14)


def _g(x, y):
    r = [a ^ b for a, b in zip(x, y)]
    q = list(r)
    for i in range(8):                      # rows: 16 consecutive words
        row = q[16 * i:16 * i + 16]
        _p(row)
        q[16 * i:16 * i + 16] = row
    for i in range(8):                      # columns: register i of every row (2 words each)
        idx = []
        for k in range(8):
            idx += [16 * k + 2 * i, 16 * k + 2 * i + 1]
        col = [q[j] for j in idx]
        _p(col)
        for j, val in zip(idx, col):
            q[j] = val
    return [a ^ b for a, b in zip(q, r)]


def _block(b):
    return list(struct.unpack('<128Q', b))


def _bytes(w):
    return struct.pack('<128Q', *w)


def argon2(typ, password, salt, passes, mem_kib, lanes, outlen, secret=b'', ad=b''):
    """typ: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id."""
    h0 = hashlib.blake2b(
        _le32(lanes) + _le32(outlen) + _le32(mem_kib) + _le32(passes) + _le32(0x13) + _le32(typ) +
        _le32(len(password)) + password + _le32(len(salt)) + salt + _le32(len(secret)) + secret +
        _le32(len(ad)) + ad, digest_size=64).digest()
    mp = 4 * lanes * (mem_kib // (4 * lanes))
    q = mp // lanes
    seg = q // 4
    B = [[None] * q for _ in range(lanes)]
    for i in range(lanes):
        B[i][0] = _block(_hprime(1024, h0 + _le32(0) + _le32(i)))
        B[i][1] = _block(_hprime(1024, h0 + _le32(1) + _le32(i)))
    zero = [0] * 128
    for r in range(passes):
        for s in range(4):
            for lane in range(lanes):
                indep = typ == 1 or (typ == 2 and r == 0 and s < 2)
                addr = None
                counter = [0]
                start = 2 if (r == 0 and s == 0) else 0

                def next_addr():
                    counter[0] += 1
                    z = [r, lane, s, mp, passes, typ, counter[0]] + [0] * 121
                    return _g(zero, _g(zero, z))
                if indep:
                    addr = next_addr()
                for j in range(start, seg):
                    col = s * seg + j
                    prev = col - 1 if col > 0 else q - 1
                    if indep:
                        if j % 128 == 0 and j != 0:
                            addr = next_addr()
                        word = addr[j % 128]
                    else:
                        word = B[lane][prev][0]
                    j1 = word & 0xFFFFFFFF
                    j2 = word >> 32
                    ref_lane = lane if (r == 0 and s == 0) else j2 % lanes
                    if ref_lane == lane:
                        area = (s * seg + j - 1) if r == 0 else (q - seg + j - 1)
                    else:
                        area = (s * seg - (1 if j == 0 else 0)) if r == 0 else (q - seg - (1 if j == 0 else 0))
                    x = (j1 * j1) >> 32
                    y = (area * x) >> 32
                    zz = area - 1 - y
                    begin = 0 if r == 0 else ((s + 1) * seg) % q
                    ref = (begin + zz) % q
                    new = _g(B[lane][prev], B[ref_lane][ref])
                    if r > 0:
                        new = [a ^ b for a, b in zip(new, B[lane][col])]
                    B[lane][col] = new
    c = B[0][q - 1]
    for i in range(1, lanes):
        c = [a ^ b for a, b in zip(c, B[i][q - 1])]
    return _hprime(outlen, _bytes(c))


def selftest():
    p, s, k, x = b'\x01' * 32, b'\x02' * 16, b'\x03' * 8, b'\x04' * 12
    vectors = {
        0: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
        1: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
        2: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
    }
    for t, want in vectors.items():
        got = argon2(t, p, s, 3, 32, 4, 32, k, x).hex()
        if got != want:
            raise SystemExit('argon2 type %d self-test failed: %s' % (t, got))


# ---- SSH encodings ----

def sstr(b):
    return struct.pack('>I', len(b)) + b


def mpint(n):
    if n == 0:
        return sstr(b'')
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return sstr(b)


def key_blobs(path):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_ssh_private_key(open(path, 'rb').read(), password=None)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        alg = 'ssh-ed25519'
        pubblob = sstr(alg.encode()) + sstr(pub)
        # PuTTY: the seed as a little-endian integer without its high zero bytes
        n = int.from_bytes(seed, 'little')
        le = n.to_bytes((n.bit_length() + 7) // 8, 'little')
        privblob = sstr(le)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        bits = key.curve.key_size
        curve = {256: 'nistp256', 384: 'nistp384', 521: 'nistp521'}[bits]
        alg = 'ecdsa-sha2-' + curve
        q = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        pubblob = sstr(alg.encode()) + sstr(curve.encode()) + sstr(q)
        privblob = mpint(key.private_numbers().private_value)
    elif isinstance(key, rsa.RSAPrivateKey):
        nums = key.private_numbers()
        alg = 'ssh-rsa'
        pubblob = sstr(alg.encode()) + mpint(nums.public_numbers.e) + mpint(nums.public_numbers.n)
        privblob = mpint(nums.d) + mpint(nums.p) + mpint(nums.q) + mpint(nums.iqmp)
    else:
        raise SystemExit('unsupported key type')
    return alg, pubblob, privblob


def b64lines(b):
    s = base64.b64encode(b).decode()
    return [s[i:i + 64] for i in range(0, len(s), 64)]


def aes256_cbc(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def main(argv):
    if argv[1:] == ['--selftest']:
        selftest()
        print('argon2 self-test ok')
        return
    ver, pw, src, out = int(argv[1]), argv[2], argv[3], argv[4]
    opts = dict(zip(argv[5::2], argv[6::2]))
    kdf = opts.get('--kdf', 'Argon2id')
    mem = int(opts.get('--mem', '4096'))
    passes = int(opts.get('--passes', '1'))
    lanes = int(opts.get('--lanes', '1'))
    enc = pw != 'none'
    passphrase = pw.encode() if enc else b''
    alg, pub, priv = key_blobs(src)
    comment = 'ppk-' + os.path.basename(out)
    encname = 'aes256-cbc' if enc else 'none'
    if enc:
        padlen = (-len(priv)) % 16
        if ver == 2:
            priv = priv + hashlib.sha1(priv).digest()[:padlen]   # PuTTY v2 pads with SHA-1 of the blob
        else:
            priv = priv + os.urandom(padlen)
    lines = ['PuTTY-User-Key-File-%d: %s' % (ver, alg), 'Encryption: ' + encname, 'Comment: ' + comment]
    pl = b64lines(pub)
    lines += ['Public-Lines: %d' % len(pl)] + pl
    if ver == 2:
        if enc:
            ck = (hashlib.sha1(b'\0\0\0\0' + passphrase).digest() + hashlib.sha1(b'\0\0\0\1' + passphrase).digest())[:32]
            cpriv = aes256_cbc(ck, b'\0' * 16, priv)
        else:
            cpriv = priv
        mackey = hashlib.sha1(b'putty-private-key-file-mac-key' + passphrase).digest()
        mac_alg = hashlib.sha1
    else:
        if enc:
            salt = os.urandom(16)
            typ = {'Argon2d': 0, 'Argon2i': 1, 'Argon2id': 2}[kdf]
            okm = argon2(typ, passphrase, salt, passes, mem, lanes, 80)
            ck, iv, mackey = okm[:32], okm[32:48], okm[48:80]
            cpriv = aes256_cbc(ck, iv, priv)
            lines += ['Key-Derivation: ' + kdf, 'Argon2-Memory: %d' % mem, 'Argon2-Passes: %d' % passes,
                      'Argon2-Parallelism: %d' % lanes, 'Argon2-Salt: ' + salt.hex()]
        else:
            cpriv = priv
            mackey = b''
        mac_alg = hashlib.sha256
    macdata = sstr(alg.encode()) + sstr(encname.encode()) + sstr(comment.encode()) + sstr(pub) + sstr(priv)
    mac = hmac.new(mackey, macdata, mac_alg).hexdigest()
    prl = b64lines(cpriv)
    lines += ['Private-Lines: %d' % len(prl)] + prl + ['Private-MAC: ' + mac]
    with open(out, 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] != '--selftest':
        selftest()
    main(sys.argv)
