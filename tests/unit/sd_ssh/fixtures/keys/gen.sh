#!/bin/sh
# Regenerates the key fixtures of test_keyfile_formats.c / test_auth_interop.c (test material only,
# decisions.md D21). Run inside WSL from any directory: sh tests/unit/sd_ssh/fixtures/keys/gen.sh
# Needs ssh-keygen (OpenSSH 9.x), openssl (3.x) and python3 (for ppkgen.py, our PPK reference writer).
# Passphrase of every encrypted file: "correct horse".
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
P="correct horse"
cd "$T"
k() { ssh-keygen -q "$@"; }
# OpenSSH v1, every key type, plain and encrypted
k -t ed25519 -N '' -C sd-ed25519 -f ossh_ed25519
k -t ecdsa -b 256 -N '' -C sd-p256 -f ossh_p256
k -t ecdsa -b 384 -N '' -C sd-p384 -f ossh_p384
k -t ecdsa -b 521 -N '' -C sd-p521 -f ossh_p521
k -t rsa -b 2048 -N '' -C sd-rsa2048 -f ossh_rsa2048
k -t rsa -b 1024 -N '' -C sd-rsa1024 -f ossh_rsa1024
k -t rsa -b 3072 -N "$P" -C sd-rsa3072-enc -f ossh_rsa3072_enc
k -t ecdsa -b 384 -N "$P" -C sd-p384-enc -f ossh_p384_enc
k -t ed25519 -N "$P" -Z aes256-gcm@openssh.com -C gcm -f ossh_ed25519_gcm
k -t ed25519 -N "$P" -Z chacha20-poly1305@openssh.com -C chacha -f ossh_ed25519_chacha
k -t ecdsa -b 256 -N "$P" -Z aes128-cbc -C cbc -f ossh_p256_cbc
k -t ed25519 -N "$P" -Z aes192-ctr -C ctr192 -f ossh_ed25519_ctr192
# PEM (PKCS#1 / SEC1) and PKCS#8 written by ssh-keygen
k -t rsa -b 2048 -N '' -m PEM -C pem-rsa -f pem_rsa
k -t ecdsa -b 256 -N '' -m PEM -C pem-p256 -f pem_p256
k -t rsa -b 2048 -N "$P" -m PEM -C pem-rsa-enc -f pem_rsa_enc
k -t ecdsa -b 521 -N "$P" -m PEM -C pem-p521-enc -f pem_p521_enc
k -t rsa -b 2048 -N '' -m PKCS8 -C p8-rsa -f p8_rsa
k -t ecdsa -b 384 -N '' -m PKCS8 -C p8-p384 -f p8_p384
k -t rsa -b 2048 -N "$P" -m PKCS8 -C p8-rsa-enc -f p8_rsa_enc
k -t ecdsa -b 256 -N "$P" -m PKCS8 -C p8-p256-enc -f p8_p256_enc
# other encryptions with openssl: legacy DEK-Info AES-256 / 3DES, PBES2 with 3DES + hmacWithSHA1,
# AES-192 + hmacWithSHA512, Ed25519 PKCS#8, and the unsupported scrypt / PBES1 / DSA
openssl rsa -in pem_rsa -traditional -aes256 -passout "pass:$P" -out pem_rsa_aes256 2>/dev/null
openssl ec -in pem_p256 -des3 -passout "pass:$P" -out pem_p256_des3 2>/dev/null
openssl pkcs8 -topk8 -in pem_rsa -v2 des3 -v2prf hmacWithSHA1 -passout "pass:$P" -out p8_rsa_des3_sha1
openssl pkcs8 -topk8 -in pem_p256 -v2 aes-192-cbc -v2prf hmacWithSHA512 -passout "pass:$P" -out p8_p256_aes192_sha512
openssl genpkey -algorithm ed25519 -out p8_ed25519 2>/dev/null
openssl pkcs8 -topk8 -in p8_ed25519 -v2 aes-256-cbc -passout "pass:$P" -out p8_ed25519_enc
openssl pkcs8 -topk8 -in pem_p256 -scrypt -passout "pass:$P" -out p8_scrypt
openssl pkcs8 -topk8 -in pem_p256 -v1 PBE-SHA1-3DES -passout "pass:$P" -out p8_pbes1 2>/dev/null
openssl dsaparam -genkey -noout -out pem_dsa 1024 2>/dev/null
# PuTTY PPK v2/v3 from the OpenSSH keys (ppkgen.py writes them as PuTTY does)
python3 "$HERE/ppkgen.py" 2 none ossh_ed25519 ppk2_ed25519
python3 "$HERE/ppkgen.py" 2 "$P" ossh_rsa2048 ppk2_rsa_enc
python3 "$HERE/ppkgen.py" 3 none ossh_p256 ppk3_p256
python3 "$HERE/ppkgen.py" 3 "$P" ossh_ed25519 ppk3_ed25519_enc
python3 "$HERE/ppkgen.py" 3 "$P" ossh_rsa2048 ppk3_rsa_enc --kdf Argon2i --lanes 2
python3 "$HERE/ppkgen.py" 3 "$P" ossh_p521 ppk3_p521_enc --kdf Argon2d
# user certificates from a test CA
k -t ed25519 -N '' -C sd-test-ca -f ca
k -s ca -I sd-ed25519-cert -n "$(id -un)",other -V -1d:+3650d ossh_ed25519.pub
k -s ca -I sd-p256-cert -n "$(id -un)" -V -1d:+3650d ossh_p256.pub
k -s ca -I sd-rsa-cert -n "$(id -un)" -V -1d:+3650d ossh_rsa2048.pub
cp ossh_p384.pub ossh_p384_exp.pub
k -s ca -I sd-expired -n "$(id -un)" -V 20200101:20200102 ossh_p384_exp.pub
cp ossh_p521.pub ossh_p521_host.pub
k -s ca -h -I sd-host -n host.example -V -1d:+3650d ossh_p521_host.pub
rm -f ossh_p384_exp.pub ossh_p521_host.pub
cp ossh_p384 ossh_p384_exp
cp ossh_p521 ossh_p521_host
rm -f "$HERE"/ossh_* "$HERE"/pem_* "$HERE"/p8_* "$HERE"/ppk[23]_* "$HERE"/ca "$HERE"/ca.pub
cp ossh_* pem_* p8_* ppk[23]_* ca ca.pub "$HERE/"
cd /
rm -rf "$T"
echo "fixtures written to $HERE"
