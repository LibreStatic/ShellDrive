#!/usr/bin/env python3
"""Converts an unencrypted OpenSSH v1 private key into an unencrypted PuTTY PPK (v3 or v2) file.

Test fixture helper (decisions.md D21: test infrastructure only). Python stdlib only, so it cannot write
encrypted PPK files (v3 needs Argon2, v2 needs AES); fixture.sh uses puttygen for those when it is installed.

  python3 -I ppk.py [--v2] <openssh-private-key> <out.ppk>

Format (docs/design/01-ssh-sftp-crypto.md "PuTTY PPK v2 and v3"): public blob = the OpenSSH public key blob;
private blob: rsa = mpint d, p, q, iqmp; ssh-ed25519 = string seed(32); ecdsa = mpint d. For "Encryption: none"
v3 uses HMAC-SHA-256 with an empty key, v2 HMAC-SHA1 keyed with SHA1("putty-private-key-file-mac-key").
"""
import base64
import hashlib
import hmac
import struct
import sys


def read_string(buf, off):
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    if off + n > len(buf):
        raise ValueError("truncated")
    return buf[off:off + n], off + n


def ssh_string(b):
    return struct.pack(">I", len(b)) + b


def parse_openssh(text):
    lines = [l.strip() for l in text.splitlines()]
    if "-----BEGIN OPENSSH PRIVATE KEY-----" not in lines:
        raise ValueError("not an OpenSSH v1 private key")
    body = "".join(lines[lines.index("-----BEGIN OPENSSH PRIVATE KEY-----") + 1:
                         lines.index("-----END OPENSSH PRIVATE KEY-----")])
    raw = base64.b64decode(body)
    magic = b"openssh-key-v1\0"
    if not raw.startswith(magic):
        raise ValueError("bad magic")
    off = len(magic)
    cipher, off = read_string(raw, off)
    kdf, off = read_string(raw, off)
    _, off = read_string(raw, off)
    if cipher != b"none" or kdf != b"none":
        raise ValueError("encrypted OpenSSH keys are not supported")
    (nkeys,) = struct.unpack(">I", raw[off:off + 4])
    off += 4
    if nkeys != 1:
        raise ValueError("expected exactly one key")
    pub_blob, off = read_string(raw, off)
    priv, off = read_string(raw, off)
    c1, c2 = struct.unpack(">II", priv[:8])
    if c1 != c2:
        raise ValueError("check bytes differ")
    p = 8
    ktype, p = read_string(priv, p)
    if ktype == b"ssh-ed25519":
        _, p = read_string(priv, p)                 # public point
        sk, p = read_string(priv, p)                # seed || public
        priv_blob = ssh_string(sk[:32])
    elif ktype == b"ssh-rsa":
        fields = []
        for _ in range(6):                          # n, e, d, iqmp, p, q (raw SSH mpints)
            v, p = read_string(priv, p)
            fields.append(ssh_string(v))
        n, e, d, iqmp, pp, q = fields
        priv_blob = d + pp + q + iqmp
    elif ktype.startswith(b"ecdsa-sha2-"):
        _, p = read_string(priv, p)                 # curve name
        _, p = read_string(priv, p)                 # Q
        d, p = read_string(priv, p)
        priv_blob = ssh_string(d)
    else:
        raise ValueError("unsupported key type %r" % ktype)
    comment, p = read_string(priv, p)
    return ktype.decode(), pub_blob, priv_blob, comment.decode("utf-8", "replace")


def b64_lines(b):
    s = base64.b64encode(b).decode()
    return [s[i:i + 64] for i in range(0, len(s), 64)]


def write_ppk(alg, pub_blob, priv_blob, comment, version):
    enc = "none"
    mac_data = ssh_string(alg.encode()) + ssh_string(enc.encode()) + ssh_string(comment.encode()) + \
        ssh_string(pub_blob) + ssh_string(priv_blob)
    if version == 3:
        mac = hmac.new(b"", mac_data, hashlib.sha256).hexdigest()
    else:
        mac = hmac.new(hashlib.sha1(b"putty-private-key-file-mac-key").digest(), mac_data, hashlib.sha1).hexdigest()
    pub_l, priv_l = b64_lines(pub_blob), b64_lines(priv_blob)
    out = ["PuTTY-User-Key-File-%d: %s" % (version, alg), "Encryption: " + enc, "Comment: " + comment,
           "Public-Lines: %d" % len(pub_l)] + pub_l + ["Private-Lines: %d" % len(priv_l)] + priv_l + \
          ["Private-MAC: " + mac]
    return "\r\n".join(out) + "\r\n"


def main(argv):
    version = 3
    args = argv[1:]
    if args and args[0] == "--v2":
        version, args = 2, args[1:]
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(args[0], "r", encoding="ascii") as f:
        alg, pub_blob, priv_blob, comment = parse_openssh(f.read())
    with open(args[1], "w", encoding="ascii", newline="") as f:
        f.write(write_ppk(alg, pub_blob, priv_blob, comment, version))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
