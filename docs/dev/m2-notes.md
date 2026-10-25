# M2 implementation notes

Working notes for the M2 milestone (`docs/design/00-integration-review.md` §6, M2 row). Each area owner appends
a section; keep sections self-contained.

## Interop fixtures and the matrix runner (fixtures)

Test infrastructure only (decisions.md D21): OpenSSH, Python proxies and every config below run inside WSL as
the normal WSL user, never as root, and nothing of it ships. The system sshd, `/etc/ssh`, `~/.ssh` and the
user's GnuPG keyring are never touched. State lives in `~/.local/state/shelldrive-fixtures/` inside WSL; the
client material the Windows tests need is copied to `tests/fixtures/matrix/state/` (gitignored).

### Quick start

```powershell
# once (about 1 minute): fetch, verify (GPG + published SHA-256) and build OpenSSH 10.x into the user prefix
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\openssh10\build.ps1
# start everything (idempotent), run the interop set per server, print the matrix, stop what it started
powershell -NoProfile -ExecutionPolicy Bypass -File tests\interop\run-matrix.ps1 -BuildDir build\<dir>
# or drive the fixtures by hand
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\matrix\ctl.ps1 start      # stop | status | ...
```

From WSL: `sh tests/fixtures/matrix/fixture.sh start|stop|status|...`.

### Instances

All listen on `127.0.0.1` (Windows localhost relay) **and** the WSL VM address (`direct_host`, NAT mode), except
the jump-only hosts, which listen on `127.0.0.2` inside WSL only (not reachable from Windows, so a test can prove
the jump was used). Prefer `direct_host`: the localhost relay can wedge for a port (m1-notes.md).

| Name | Port | Server | Purpose |
|------|------|--------|---------|
| `modern` | 2222 | OpenSSH 9.6p1 (Ubuntu) | existing M1 fixture (`tests/fixtures/wsl-sshd`, unchanged) |
| `ossh10` | 2230 | OpenSSH 10.x (own build) | `mlkem768x25519-sha256` first, ed25519 + ECDSA P-256 + RSA-3072 host keys |
| `ossh10pq` | 2239 | OpenSSH 10.x | **only** `mlkem768x25519-sha256` (a client without it fails KEX) |
| `legacy` | 2231 | OpenSSH 9.6p1 | legacy only: 3des-cbc, aes*-cbc, hmac-sha1(-96), hmac-md5(-96), dh-group1/14-sha1, dh-gex-sha1/-sha256, ssh-rsa (SHA-1) and ssh-dss host keys |
| `legacy3des` | 2238 | OpenSSH 9.6p1 | exactly one choice each: 3des-cbc, hmac-sha1, diffie-hellman-group14-sha1, ssh-rsa |
| `bastion1` | 2232 | OpenSSH 9.6p1 | jump host, `PermitOpen 127.0.0.1:* 127.0.0.2:*` |
| `bastion2` | 2233 on 127.0.0.2 | OpenSSH 10.x | second jump host (3-hop chains) |
| `target` | 2234 on 127.0.0.2 | OpenSSH 10.x | jump target; accepts the PPK keys |
| `cert` | 2235 | OpenSSH 9.6p1 | user certificates only (`TrustedUserCAKeys`, `AuthorizedKeysFile none`, `RevokedKeys` KRL) + host certificate from a test host CA |
| `rotate` | 2236 | OpenSSH 10.x | host-key rotation for UpdateHostKeys / `hostkeys-00@openssh.com` |
| `otp` | 2237 | OpenSSH 9.6p1 + PAM | publickey + keyboard-interactive TOTP bastion; **needs a one-time sudo step**, see below |
| HTTP proxy | 2280 / 2281 | Python stdlib | CONNECT, open / Basic auth |
| SOCKS5 proxy | 2290 / 2291 | Python stdlib | CONNECT, no auth / RFC 1929 user+password |

Details per instance (exact algorithm lists, keys, certificates): `tests/fixtures/matrix/README.md`. OpenSSH 10.6p1
build and its capabilities: `tests/fixtures/openssh10/README.md`. `ctl.ps1 selftest` checks every instance with the
stock OpenSSH clients (53 checks, about 10 s; all pass, OTP and PPK-via-puttygen skipped until the sudo steps).

### Environment for tests

`tests/fixtures/matrix/state/endpoints.env` (written on every start/stop, `KEY=value`, Windows paths) holds the
global variables; `run-matrix.ps1` exports all of them and points `SD_IT_ENV_FILE` at the file, so a test can
also read it directly when run outside the runner. Only running instances are listed.

| Variable | Meaning |
|----------|---------|
| `SD_IT_USER`, `SD_IT_WIN_HOST`, `SD_IT_DIRECT_HOST` | login user; host to use from Windows (direct address, else `127.0.0.1`) |
| `SD_IT_KNOWN_HOSTS` | OpenSSH `known_hosts` with every instance under the names a client uses (`[host]:port`), `@cert-authority` line for `cert`, `rotate` with key A only |
| `SD_IT_KEY_{ED25519,ECDSA,RSA,ED25519_ENC}`, `SD_IT_KEY_PASSPHRASE` | OpenSSH private keys (the `_ENC` one with the passphrase) |
| `SD_IT_KEY_{ED25519,RSA,ECDSA}_PPK3`, `SD_IT_KEY_ED25519_PPK2` | the same keys as unencrypted PPK v3 / v2; `SD_IT_KEY_ED25519_PPK3_ARGON2ID`, `SD_IT_KEY_RSA_PPK2_AES` only with puttygen |
| `SD_IT_CERT_{ED25519,RSA,ECDSA}` | valid user certificates for the keys above |
| `SD_IT_CERT_{EXPIRED,WRONGPRINC,REVOKED}` + `_KEY` | negative certificates and their own keys |
| `SD_IT_USER_CA`, `SD_IT_HOST_CA` | CA public keys (`type base64`) |
| `SD_IT_<INSTANCE>_{HOST,PORT,HOSTKEYS}` | per instance (`MODERN`, `OSSH10`, `OSSH10PQ`, `LEGACY`, `LEGACY3DES`, `BASTION1`, `BASTION2`, `TARGET`, `CERT`, `ROTATE`, `OTP`); `HOSTKEYS` = `type base64` entries separated by `;`, preferred first |
| `SD_IT_ROTATE_MODE`, `SD_IT_ROTATE_HOSTKEY_A`, `SD_IT_ROTATE_HOSTKEY_B` | rotation state; change it with `wsl.exe -e sh $env:SD_IT_FIXTURE_SH rotate a\|ab\|ba\|b` (restarts the instance, about 0.5 s) |
| `SD_IT_OTP_SECRET`, `SD_IT_OTP_METHODS` | base32 TOTP secret (RFC 6238, SHA-1, 30 s, 6 digits) and the instance's `AuthenticationMethods` |
| `SD_IT_PROXY_{HTTP,HTTP_AUTH,SOCKS5,SOCKS5_AUTH,SQUID,DANTE}` + `_LOG` | `host:port` of each running proxy and its request log |
| `SD_IT_PROXY_USER`, `SD_IT_PROXY_PASS` | proxy credentials (`sdproxy` / `shelldrive-proxy-pass`) |
| `SD_IT_FIXTURE_SH` | WSL path of `fixture.sh` (rotation, `otp-code`) |

Per-row variables (`SD_IT_SERVER`, `SD_IT_HOST`, `SD_IT_PORT`, `SD_IT_KEY`, `SD_IT_CERT`, `SD_IT_JUMP`,
`SD_IT_PROXY`, `SD_IT_EXPECT_KEX`, `SD_IT_EXPECT_LEGACY`, `SD_IT_OTP`, `SD_IT_FEATURES`), the row list and the
`srv_<row>` / `srv_all` CTest label convention: `tests/interop/README.md`. A test that writes one generic "connect
with the row's recipe" routine gets every row (servers, jumps, proxies, the demo path) without per-server code.

Fault injection on any instance: `tests/fixtures/wsl-sshd/ctl.sh <cmd> <instance>` (new optional second argument;
without it the M1 fixture, as before).

### Needs sudo (asked of the user, not done)

| For | Command |
|-----|---------|
| `otp` instance (TOTP keyboard-interactive; the "OTP keeps the pool at 1" and demo checks) | `sudo apt install libpam-google-authenticator` plus `/etc/pam.d/shelldrive-otp` exactly as printed by `fixture.sh otp-pam` (sshd itself stays unprivileged) |
| Squid / Dante rows | `sudo apt install squid dante-server` (both then run unprivileged from `fixture.sh`; the services can stay disabled) |
| encrypted PPK fixtures (v3 Argon2id, v2 AES) and the PPK cross-check | `sudo apt install putty-tools` |

### Gaps

- OTP login is untested end to end until the sudo step: the PAM service name being the program name (`__progname`,
  OpenSSH's default) is expected but not observed; the unprivileged sshd does start the PAM kbdint device.
- No scripted/fake SSH server exists in the repo's tests (sd_ssh unit tests have none), so there is no
  OTP fallback without PAM.
- Squid and Dante configs are written but never run here. Dante unprivileged cannot do username auth.
- Encrypted PPK fixtures need puttygen; the unencrypted PPK v3/v2 files come from our own stdlib writer
  (`ppk.py`) and are not cross-checked by PuTTY until `putty-tools` is installed.
- Windows-side matrix run against real ShellDrive interop tests not yet done: none carries `srv_*` labels yet; the
  runner was validated with a throwaway CTest project (all rows, skip/pass mapping, start/stop bookkeeping).

## Symmetric and post-quantum primitives in sd_crypto (pq)

API: `src/sd_crypto/include/sd_crypto/sd_crypto_pq.h` (included by `sd_crypto.h`); sources in
`src/sd_crypto/sources_pq.cmake`; tests `tests/unit/sd_crypto_pq` (`unit.crypto_pq`); vectors and provenance in
`tests/vectors/pq/`.

- SHA3-256/512, SHAKE128/256 (`sha3.c`): 64-bit lanes, constant rotations only (no runtime helper on x86).
- ML-KEM-768 (`mlkem.c`): keygen/encaps/decaps plus `_derand` variants for KATs and the mock server; ek modulus
  check in encaps, dk hash check in decaps (`SD_E_CRYPTO`), implicit rejection by constant-time compare and
  masked select. Compression uses a 32x32->64 multiply by ceil(2^35/q) (exact for inputs < 2^24).
- `mlkem768x25519-sha256` combiner (`mlkem_hybrid.c`): `sd_mlkem768x25519_client_init/finish` and
  `sd_mlkem768x25519_server`; K = SHA-256(K_PQ || K_CL), sd_ssh encodes K as an SSH string.
- BLAKE2b (`blake2b.c`), Argon2d/i/id v0x13 (`argon2.c`, VirtualAlloc, caps 1 GiB / 1000 passes / 255 lanes,
  optional cancel flag checked per segment).
- 3DES (`des3.c`): S-boxes as one 64-leaf boolean multiplexer network over nibble-packed selector words (the
  leaves are public constants generated by `des3_gen_tables.py`); no secret-indexed table or secret shift.
  Packet names `aes128/192/256-cbc` and `3des-cbc` in `pktcipher.c` (`SD_PC_CBC | SD_PC_LEGACY`, chaining value
  kept across `sd_pktcipher_crypt` calls); `sd_cipher_oneshot` also takes `3des-cbc` / `DES-EDE3-CBC`.
  AES-CBC packets use the own bitsliced core only (CNG has no ECB-decrypt hook in `aes_cng.c`).
- Packet MACs `hmac-sha1(-etm)` need only `SD_HASH_SHA1` in `sd_hmac_*` (sd_crypto_pk.h); nothing pq-specific.
- Constant-time gate: `sha3 mlkem des3 blake2b argon2` are in `SD_CT_SOURCES` (tools/sd-isacheck). Argon2d and
  the data-dependent half of Argon2id index memory by data by design.
- PPK v3 fixtures are written by our Python reference (`tests/vectors/pq/ppk_fixture.py`) because puttygen is not
  installed; replace them with puttygen output when available.
- CNG differential: AES-CBC and 3DES-CBC everywhere CNG exists; ML-KEM-768 against `BCRYPT_MLKEM_ALGORITHM`
  where bcrypt.dll provides it (seed import, ek export compare, cross encaps/decaps, tampered ciphertext).
## Matrix-driven transport interop (backend, M2 order step 2)

`tests/unit/sd_ssh/test_interop_m2.c` (`sd-test-ssh-interop-m2`) consumes the row recipe of
`run-matrix.ps1` (every `SD_IT_*` variable; `tests/interop/README.md`); plain `ctest` skips it with
77. One generic `mx_connect` builds whatever the row describes (server, `SD_IT_JUMP` hops,
`SD_IT_PROXY` with Basic / RFC 1929 credentials, `SD_IT_CERT`, OTP) so the same tests cover every
row without per-server code. Entry points and their labels:

| CTest entry | Labels | What it proves |
|---|---|---|
| `interop.ssh_matrix_connect` | `srv_all` | connect + exec over the row recipe; negotiated KEX vs `SD_IT_EXPECT_KEX`, legacy mask vs `SD_IT_EXPECT_LEGACY`, strict KEX, zero host-key prompts (the fixture known_hosts decides every hop, host certificates via `@cert-authority` on `cert`), TOTP kbdint on `otp`/`demo` |
| `interop.ssh_matrix_kex` | `srv_modern;srv_ossh10;srv_ossh10pq;srv_legacy;srv_legacy3des;srv_cert` | walks KEX × host-key combinations with `algos.disabled` lists: mlkem768x25519-sha256, curve25519-sha256, ECDH P-256, rsa-sha2-512 host keys; the legacy DH set (gex-sha256, group14-sha1, gex-sha1, group1-sha1) with ssh-rsa; 3des-cbc on `legacy3des`; the host-certificate host-key algorithm on `cert` |
| `interop.ssh_matrix_pq` | `srv_ossh10pq` | without ML-KEM in the offer KEX fails (`SD_E_KEX_FAILED`) |
| `interop.ssh_matrix_update` | `srv_rotate` | `hostkeys-00@openssh.com` announcement with proof, `sd_known_hosts_apply_hostkeys`, server rotated to B only, reconnect authenticates with the learned key; leaves the fixture in mode `ab` (RESOURCE_LOCK `wsl_rotate_fixture`) |

TOTP is computed in-process (RFC 6238 over `SD_IT_OTP_SECRET`; the secret is never printed) with
`sd_hmac(SD_HASH_SHA1)`; later kbdint rounds use the next 30 s step. State of the full run
(2026-10-25, `x64-modern` Release, fixtures per the table in this file): every entry passes on every
row whose fixtures are up, including the demo row (SOCKS5 auth proxy -> OTP bastion -> target, PPK
v3 key, ML-KEM). Squid/Dante rows stay fixture-down as before.

Fix to the runner: the per-row ctest invocation now runs with `$ErrorActionPreference = 'Continue'`
(Windows PowerShell 5.1 turns native stderr into error records; with 'Stop' the script aborted at
the first failing row instead of collecting the table).

Dev helper `build/run-row.sh` (untracked, build dir) runs one sub-test for one row by hand with the
same variables the runner sets.
