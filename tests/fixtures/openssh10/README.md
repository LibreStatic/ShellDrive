# OpenSSH 10.x build for the M2 interop fixtures

`build.sh` fetches the official OpenSSH portable release from `cdn.openbsd.org`, verifies it and builds it into
`~/.local/state/shelldrive-fixtures/openssh-<version>/` inside WSL (symlink `.../openssh10`). Test infrastructure
only (decisions.md D21): nothing of it ships, nothing is installed system-wide, no sudo.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\openssh10\build.ps1          # idempotent, ~1 min
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\openssh10\build.ps1 -Force   # rebuild
```

- **Version:** 10.6p1 (released 2026-10-06). Bump `VERSION` and `SHA256_B64` in `build.sh` together.
- **Verification**, both mandatory before extraction: the GPG signature (`.asc`) against `RELEASE_KEY.asc` from the
  same CDN, imported into a private `GNUPGHOME` (`.../build/gnupg`; the user's keyring is untouched) and pinned to
  fingerprint `7168B983815A5EEF59A4ADFD2A3F414E736060BA` (Damien Miller); and the SHA-256 published in the release
  notes (`https://www.openssh.com/txt/release-10.6`, base64).
- **Configure:** `--without-pam --without-selinux --without-kerberos5`, privsep path and sysconfdir inside the
  prefix, linked against Ubuntu's OpenSSL 3.0.13 and zlib (`libssl-dev` and `zlib1g-dev` are installed).
  Because there is no PAM, `UsePAM` is not a valid option in configs for this build.
- **Capabilities** (`ssh -Q`): KEX `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`,
  `sntrup761x25519-sha512(@openssh.com)`, curve25519, ECDH P-256/384/521, DH group1/14/16/18 and GEX; ciphers
  chacha20-poly1305, AES-GCM/CTR/CBC, 3des-cbc; MACs SHA-1/SHA-2/MD5/UMAC incl. EtM; keys ed25519, ECDSA,
  RSA, `ssh-mldsa44-ed25519`, sk-*, all certificate variants. No `ssh-dss` (removed in 10.0).
- **No-OpenSSL fallback:** if the dev headers are missing (or `SD_OSSH_WITHOUT_OPENSSL=1`), `build.sh` uses
  `--without-openssl`. Per the OpenSSH docs that build keeps only the internal crypto: ed25519 keys (no RSA/ECDSA),
  curve25519 / sntrup761 / mlkem768x25519 KEX, chacha20-poly1305 and aes-ctr, HMAC-SHA1/SHA2 and UMAC. It was not
  needed (and not exercised) here.
- Logs: `.../shelldrive-fixtures/build/{configure,make,install}.log`.
