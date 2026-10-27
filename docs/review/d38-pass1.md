# D38 external crypto review, pass 1: review package

Status: **preparation only**. This package prepares the human crypto and protocol review required by
decisions.md D38 (pass 1 at the end of M2). It does not replace that review, it does not close any
finding, and nothing in it is a security conclusion. Every "to verify" item is a lead for the reviewer.

- Date: 2026-10-27
- Commit under review: `147ca33` on branch `wip/m2-backend` (working tree had only the untracked `Testing/` folder, not touched)
- Scope: `src/sd_crypto` (public-key, symmetric and post-quantum parts) and `src/sd_ssh` (the `transport`, `auth`
  and `connect` area lists plus the connection and KEX core in the main list)
- No product code was changed. Build outputs live in `build/x64-analysis` and `build/x86-ia32` only.

Conventions: paths are repository-relative; `file:line` points at the current tree. Line counts are `wc -l`.
Spec references are taken from each file's header comment and from `docs/design/01-ssh-sftp-crypto.md`.

---

## 1. Scope

### 1.1 `src/sd_crypto` (8058 lines in the folder excluding `include/`; plus 474 lines of public headers)

Lists: `CMakeLists.txt` (main list), `sources_pk.cmake` (public-key area, 11 lines), `sources_pq.cmake`
(symmetric and post-quantum area, 14 lines). The public headers under `include/sd_crypto/` are listed below.

**Core and infrastructure**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `ct.c` | 76 | constant-time helpers: masks, select, cswap, cmov, `sd_ct_memeq` | 01 §2.4 rules 2, 7 |
| `sd_ct64.h` | 91 | 64-bit primitives allowed in constant-time code on 32-bit targets | 01 §2.3, §2.4.3; TM-R02 |
| `init.c` | 106 | `sd_crypto_init`, capability detection, OS RNG (BCryptGenRandom, RtlGenRandom) | 01 §2.2, §2.3 |
| `crypto_internal.h` | 121 | private interfaces shared with tests | n/a |
| `include/sd_crypto/sd_crypto.h` | 125 | public API (symmetric, hash, RNG) | n/a |
| `include/sd_crypto/sd_ct.h` | 23 | public constant-time helper API | 01 §2.4 |
| `include/sd_crypto/sd_crypto_pk.h` | 202 | public API, public-key area | n/a |
| `include/sd_crypto/sd_crypto_pq.h` | 124 | public API, symmetric and PQ area | n/a |

**Hashes, MACs, KDFs**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `hash.c` | 361 | SHA-256/384/512, HMAC, PBKDF2 | FIPS 180-4; RFC 2104; FIPS 198-1; RFC 8018 §5.2 |
| `sha1.c` | 107 | SHA-1, legacy only (ssh-rsa, hmac-sha1, `*-sha1` KEX, hashed known_hosts) | FIPS 180-4 §6.1 |
| `sha3.c` | 225 | SHA3-256/512, SHAKE128/256 | FIPS 202 |
| `blake2b.c` | 146 | BLAKE2b (used by Argon2) | RFC 7693 |
| `argon2.c` | 284 | Argon2d/i/id, v0x13, for PuTTY PPK v3 | RFC 9106 |
| `bcrypt_pbkdf.c` | 159 | bcrypt_pbkdf for OpenSSH key files | OpenSSH PROTOCOL.key; Provos-Mazieres 1999 |
| `sha2_consts.inc` | 57 | generated SHA-2 constants (data) | FIPS 180-4 §4.2.2, §5.3 |
| `gen_sha2_consts.py` | 40 | generator for `sha2_consts.inc` (run by hand) | FIPS 180-4 |
| `blowfish_pi.inc` | 179 | generated Blowfish initial state (data) | Schneier 1993 |
| `gen_blowfish_pi.py` | 33 | generator for `blowfish_pi.inc` | Schneier 1993 |

**Symmetric ciphers and packet protection**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `aes_ct.c` | 399 | bitsliced AES, table-free, constant time | FIPS 197; SP 800-38A (CBC, CTR) |
| `aes_cng.c` | 204 | AES via CNG (CTR keystream, GCM); also the differential reference | FIPS 197; SP 800-38D |
| `gcm.c` | 256 | AES-GCM (own) and constant-time GHASH | SP 800-38D |
| `chacha_poly.c` | 179 | ChaCha20 and Poly1305 | RFC 8439 §2.1-§2.5; OpenSSH chacha20-poly1305 |
| `des3.c` | 209 | DES and 3DES-EDE, bitsliced multiplexer network, legacy | FIPS 46-3; SP 800-67 Rev. 2 |
| `des3_internal.h` | 19 | private 3DES interface | n/a |
| `des3_tables.inc` | 96 | generated multiplexer constants (data) | FIPS 46-3 |
| `des3_gen_tables.py` | 129 | generator for `des3_tables.inc` | FIPS 46-3 |
| `pktcipher.c` | 339 | SSH packet cipher objects (CBC, CTR, GCM, ChaCha20-Poly1305) and the key-file cipher | RFC 4253 §6.3-§6.4; RFC 4344; RFC 5647 as profiled by OpenSSH; OpenSSH PROTOCOL.chacha20poly1305 |

**Public-key arithmetic (`sources_pk.cmake`)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `bn.c` | 604 | multiprecision: Montgomery, constant-time modexp and modinv, public `sd_bn` API | HAC §14.4, §14.6 (cited in header) |
| `pk_internal.h` | 89 | `sd_mp_*` interface (public limb count, constant-time contract) | n/a |
| `pk_consts.inc` | 403 | generated MODP primes and NIST P-256/384/521 constants (data) | RFC 2409 §6.2; RFC 3526; RFC 5903 |
| `gen_pk_consts.py` | 197 | generator for `pk_consts.inc` (run by hand, inputs are the RFC texts) | as above |
| `curve25519.c` | 787 | GF(2^255-19), X25519 and Ed25519 | RFC 7748; RFC 8032 |
| `ec_p.c` | 693 | ECDH and ECDSA on P-256/384/521 | FIPS 186-4; SEC 1 v2; RFC 5656; RFC 5903 and RFC 6979 (vectors only) |
| `rsa.c` | 435 | RSA PKCS#1 v1.5 sign and verify, blinding, CRT, verify-after-sign | RFC 8017 §8.2, §9.2; RFC 4253 (ssh-rsa); RFC 8332 |
| `dh.c` | 198 | finite-field DH for SSH | RFC 4253 §8; RFC 4419; RFC 3526 |
| `dh_gex.c` | 176 | group-exchange group validation (public data, variable time) | RFC 4419 §3; RFC 8270; HAC §4.24, §4.40 |

**Post-quantum (`sources_pq.cmake`)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `mlkem.c` | 516 | ML-KEM-768 keygen, encaps, decaps (implicit rejection) | FIPS 203 |
| `mlkem_hybrid.c` | 83 | `mlkem768x25519-sha256` combiner | draft-ietf-sshm-mlkem-hybrid-kex |

### 1.2 `src/sd_ssh` (14162 lines of `*.c` and `*.h`; plus 720 lines of public headers in `include/sd_ssh/`)

Lists: `sources_transport.cmake` (9 lines), `sources_auth.cmake` (17 lines), `sources_connect.cmake` (10 lines).
The main list in `CMakeLists.txt` also holds the KEX, packet, negotiation, known_hosts, user-auth and
key-file-OpenSSH units. They carry the same trust-relevant logic, so they are included here (marked "main").

**Transport (`sources_transport.cmake`, plus main list)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `kex.c` | 656 | KEX state machine, host-key check, strict KEX, rekey, restricted re-key (main) | RFC 4253 §7-§9; RFC 4419; strict KEX (01 §4.2) |
| `kex_methods.c` | 321 | KEX methods: curve25519, ECDH, DH, GEX, mlkem768x25519 | RFC 4253 §8; RFC 4419; RFC 5656; RFC 8268; RFC 8731; draft-ietf-sshm-mlkem-hybrid-kex |
| `kex_internal.h` | 65 | KEX method interface | n/a |
| `negotiate.c` | 490 | algorithm lists, KEXINIT encode and parse, negotiation, legacy classes, identification line (main) | RFC 4253 §4.2, §7; TM-R01, TM-R04 |
| `packet.c` | 206 | binary packet protocol, HMAC for non-AEAD ciphers, encrypt-then-MAC (main) | RFC 4253 §6; OpenSSH PROTOCOL (EtM) |
| `known_hosts.c` | 1274 | known_hosts stores, lookup, TOFU restrictions (main) | OpenSSH sshd(8) known_hosts format; TM-R04, TM-R06, TM-R07 |
| `known_hosts_internal.h` | 35 | known_hosts helpers | n/a |
| `known_hosts_live.c` | 461 | live read-only sources (OpenSSH file, PuTTY registry) and their ACL checks | 01 §7.2, §7.3; TM-R06 |
| `hostkey_verify.c` | 383 | host key blobs, signature verification over H, OpenSSH host certificates | RFC 4253 §6.6; RFC 5656; RFC 8332; RFC 8709; OpenSSH PROTOCOL.certkeys |
| `hostkey_internal.h` | 80 | host key and certificate interface | n/a |
| `hostkey_update.c` | 556 | UpdateHostKeys client: announcements, proofs, restricted re-key collection | OpenSSH hostkeys-00@openssh.com, hostkeys-prove-00@openssh.com; 01 §7.5 |
| `transport_internal.h` | 58 | transport state shared by kex.c and hostkey_update.c | n/a |

**Connection core (main list)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `conn.c` | 1550 | connection object, I/O thread, transport dispatch, timers | RFC 4253 §4.2, §11, §12 |
| `conn_internal.h` | 463 | per-hop connection state | n/a |
| `channel.c` | 476 | session channels, window flow control, EOF and CLOSE | RFC 4254 §5-§6 |
| `crypto_init.c` | 29 | sd_crypto init and random source for sd_ssh | n/a |
| `base64.c` | 99 | base64 for key files and known_hosts (not constant time, public data only) | RFC 4648 |
| `prompt.c` | 233 | prompt objects and their two-reference lifetime; answer from store (TM-R05) | 01 §6.7 |
| `seccache.c` | 131 | reconnect secret cache, encrypted in process memory | 01 §7.4, §8; TM-R05 |
| `ssh_internal.h` | 235 | shared private declarations | n/a |

**Authentication (`sources_auth.cmake`, plus main list)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `auth.c` | 1190 | user auth: none, publickey, keyboard-interactive, password and password change (main) | RFC 4252; RFC 4256; RFC 8332; 01 §6.1-§6.4 |
| `auth_cfg.c` | 106 | per-hop authentication configuration copies | 01 §6.2, §9 |
| `keyfile.c` | 220 | key objects, format detection, signing dispatch, serializer | 01 §6.6 |
| `keyfile_internal.h` | 126 | key file units interface | n/a |
| `keyfile_sign.c` | 283 | key consistency checks, publickey signatures | RFC 8332; RFC 5656; RFC 8709 |
| `keyfile_cert.c` | 224 | OpenSSH certificates and RFC 4716 public key files | OpenSSH PROTOCOL.certkeys; RFC 4716 |
| `keyfile_der.c` | 135 | strict DER reader (single-byte tags, minimal lengths, depth <= 8) | ITU-T X.690 (DER subset) |
| `keyfile_pem.c` | 580 | PEM keys: PKCS#1, SEC1, PKCS#8, PBES2, legacy DEK-Info | RFC 8017 App. A; RFC 5915; RFC 5208; RFC 5958; RFC 8018; OpenSSL legacy PEM |
| `keyfile_ppk.c` | 326 | PuTTY PPK v2 and v3 | PuTTY PPK format; RFC 2104; RFC 9106 |
| `keyfile_openssh.c` | 390 | OpenSSH v1 key files, bcrypt_pbkdf, AES and ChaCha (main) | OpenSSH PROTOCOL.key |
| `keyfile_dpapi.c` | 149 | DPAPI-kept SDKEY1 images | 03 §4.4 (CryptProtectData) |
| `agent.c` | 160 | agent protocol client, reply cap | draft-miller-ssh-agent |
| `agent_internal.h` | 36 | agent interface | n/a |
| `agent_pageant.c` | 188 | Pageant client (WM_COPYDATA, file mapping); owner check | PuTTY Pageant protocol; TM-R08 |
| `agent_pipe.c` | 188 | OpenSSH agent pipe client; owner check | draft-miller-ssh-agent; TM-R08 |

**Connect (`sources_connect.cmake`, plus main list)**

| File | Lines | Purpose | Spec |
|---|---:|---|---|
| `jump_chain.c` | 360 | ProxyJump chains, direct-tcpip tunnels between hops | 01 §5.1, §3.3; RFC 4254 §7 |
| `proxy_conn.c` | 492 | per-hop proxy glue: SSPI on workers, prompts, reconnect cache | 01 §5.2, D20; TM-R10 |
| `proxy_internal.h` | 131 | proxy client interface | n/a |
| `proxy_http.c` | 550 | HTTP CONNECT client | RFC 9110 §9.3.6 |
| `proxy_socks5.c` | 165 | SOCKS5 client, username/password | RFC 1928; RFC 1929 |
| `proxy_sspi.c` | 132 | SSPI Negotiate and NTLM tokens for proxies | RFC 4559; MS-NLMP; TM-R10 |
| `proxy_system.c` | 230 | system proxy resolution (WinHTTP) and the SSPI decision | 01 §5.2, D20; TM-R10 |

---

## 2. Suggested review order and highest-risk spots

### 2.1 Order

1. **Primitives every packet depends on**: `ct.c`, `sd_ct64.h`, `aes_ct.c`, `gcm.c`, `chacha_poly.c`.
2. **Packet protection**: `pktcipher.c` (AEAD open, ordering), `packet.c` (MAC, length check).
3. **Key exchange**: `kex.c`, `negotiate.c`, `kex_methods.c`, then the arithmetic they call: `curve25519.c`,
   `ec_p.c`, `dh.c`, `dh_gex.c`, `bn.c`.
4. **Host-key trust**: `hostkey_verify.c`, `known_hosts.c`, `known_hosts_live.c`, `hostkey_update.c`,
   and the hostkey branch of `kex.c`.
5. **ML-KEM**: `mlkem.c`, `mlkem_hybrid.c`.
6. **Key-file parsers and KDFs**: `keyfile_der.c`, `keyfile_pem.c`, `keyfile_openssh.c`, `keyfile_ppk.c`,
   `argon2.c`, `bcrypt_pbkdf.c`, `des3.c`, `rsa.c` (private operation).
7. **Authentication and secrets**: `auth.c`, `prompt.c`, `keyfile_sign.c`, `agent_*.c`, `seccache.c`.
8. **Proxies (TM-R10)**: `proxy_conn.c`, `proxy_system.c`, `proxy_sspi.c`, `proxy_http.c`, `proxy_socks5.c`.
9. **Remaining hashes and RNG**: `hash.c`, `sha1.c`, `sha3.c`, `blake2b.c`, `init.c`.

### 2.2 Highest-risk spots (to verify, not verdicts)

**Constant-time code**

- `ct.c:58` `sd_ct_cmov`, `ct.c:68` `sd_ct_memeq`. Every tag or MAC comparison goes through `sd_ct_memeq`
  (`gcm.c:188`, `pktcipher.c:263` and `:283`, `packet.c:182` and `:190`, `keyfile_openssh.c:259`,
  `keyfile_ppk.c:314`, `mlkem.c:498` and `:511`, `rsa.c:429`). Check the value barrier and the absence of an
  early exit.
- `curve25519.c:403` `x25519_ladder`, `:450-467` `sd_x25519` (clamping, then the all-zero output rejection),
  `:535` `ge_scalarmult` (Ed25519 secret scalar), `:620` and `:647` `sc_reduce` and `sc_muladd` on secret data.
- `ec_p.c:183` `pt_mul` (scalar multiplication), `:294` `scalar_mul`, `:347` `drbg_nonce` (nonce generation,
  check it is not reachable with a weak source), `:516` `sd_ecdh` (peer point validated by `decode_point`
  at `:527` before any secret work).
- `ec_p.c:605` `parse_scalar_vt` is variable time. It is called only on signature components (`:627`), which
  are public. Confirm no secret parses through it.
- `rsa.c:92` `rsa_private` (blinding, CRT, Garner recombination, verify-after-sign at `:429`).
- `dh.c:166` `sd_dh_compute`: peer range check (`1 < f < p-1`, at `:189`), then the constant-time
  modexp of `bn.c:276` `sd_mp_modexp_ct`. `bn.c:335` `sd_mp_modinv_ct` must use a fixed iteration count.
- `gcm.c:20-42` (`bmul32`, `clmul64`, `gf128_mul`): carry-less products emulated with integer multiplies. Each
  product must stay a 32x32->64 `SD_MUL32`.
- `mlkem.c:486-516` `sd_mlkem768_decaps`: implicit rejection with `sd_ct_cmov` at `:513`. The hash check at
  `:498` runs on public data (`H(ek)`), and the error path zeroes `ss`.
- `aes_ct.c` (whole file) and `des3.c` (multiplexer network, header lines 1-20): bitsliced cores.
- `argon2.c` (header): Argon2d and the data-dependent half of Argon2id index memory by the passphrase. This is
  by design (RFC 9106), but it is a side channel the reviewer should accept or reject explicitly.

**Key parsing**

- `keyfile_der.c:1-135`: strict DER, depth limit 8, rejects BER forms.
- `keyfile_pem.c` (580 lines): PBES2 (RFC 8018) and the legacy `DEK-Info` path (EVP_BytesToKey with MD5, one
  iteration). Review the padding checks and the failure paths for oracle behaviour.
- `keyfile_openssh.c:14` `KEY_MAX_ROUNDS` is 1024. Check `:289-296` (rounds, salt, length checks) and the
  consistency of the two check integers.
- `keyfile_ppk.c:288-314`: v2 MAC key (SHA-1) and v3 MAC key (Argon2 output, `:296` empty key for
  unencrypted v3), then the MAC comparison at `:314`.
- `keyfile_sign.c:43`: public-key consistency check between the private and public parts.

**Key exchange**

- `negotiate.c:312` (host-key list restricted to stored types, TM-R04), `:337` (Terrapin-aware cipher and MAC
  lists, TM-R01). Check the strict-KEX constants at `negotiate.c:66-67` and `ssh_legacy_mask_for` at `:164`.
- `kex.c:192` `on_kexinit`: confirm the KEXINIT we send is built only after the server KEXINIT arrived (TM-R01).
- `kex.c:269` `on_reply`: the server values are validated, then the signature over H is verified
  (`ssh_hostkey_verify_kex` call at `:305`), and only after that are keys derived (`:327-332`).
  This ordering is correct on reading and must stay so.
- `kex.c:343-349`: the branch for a restricted re-key (`k->fetch`) accepts a host key of another type on its
  signature alone and only records it for the UpdateHostKeys review (`hostkey_update.c:397-410`). Confirm
  that this branch never changes `c->hostkey`, never writes a store, and never grants trust.
- `kex.c:349` (non-initial, non-fetch rekey): a rekey that presents a different host key fails with
  `SD_E_HOSTKEY_MISMATCH` (`memcmp` on the stored key; public data).
- `kex.c:513-536`: `hostkey_ok`, `hostkey_is_pinned`, `accept_pinned` (TM-R05: no stored secrets after a fresh
  acceptance).

**Packet protection**

- `packet.c:164`: length check before any MAC work. `packet.c:176-190`: receive path with the MAC compared at
  `:182` (encrypt-then-MAC) and `:190` (MAC-then-encrypt). Check which branch runs for which MAC, and that no
  payload is released before the comparison.
- `pktcipher.c:259-268` `gcm_open_own`: the tag is checked (`:263`) before the in-place decryption.
- `pktcipher.c:271-298` `sd_pktcipher_open`: the ChaCha20-Poly1305 path checks the tag (`:283`) before
  decrypting (`:287`). The CNG path (`:290-293`) passes the buffer to `sd_cng_gcm` for in-place decryption.
  **To verify**: CNG must not leave released plaintext in the buffer on a tag mismatch, or the caller must
  discard the buffer on `SD_E_CRYPTO`.
- `pktcipher.c:297`: `gcm_next_iv` runs on the failure path too (GCM only; the ChaCha20-Poly1305 path derives
  its nonce from the sequence number and returns before it). The caller must treat `SD_E_CRYPTO` as fatal
  for the connection (to verify).

**Host-key verification**

- `hostkey_verify.c:92` `ssh_pubkey_verify` (the `allow_sha1` flag), `:242` `ssh_cert_check_host` (validity
  window with a 300 s tolerance at `:277`), `:338` `ssh_hostkey_verify_kex`.
- `known_hosts.c:303`, `:314`, `:466`: wildcard entries never produce a MATCH in live sources (TM-R06).
- `known_hosts.c:425`: a CA is trusted for a name but the certificate did not validate: no TOFU path (TM-R04).
- `known_hosts.c:69-81`: hashed names (HMAC-SHA1 compare, public data).
- `known_hosts_live.c:18`: the security descriptor check of a live source (TM-R06). Review the reparse-point and
  FAT cases (TST-14).
- `hostkey_update.c:397-410`: fetched keys are collected, never stored (see `kex.c:345-349` above).

**Authentication and secrets**

- `auth.c:200` `may_autofill` (passphrases are not affected by TM-R05).
- `auth.c:1153`: the two typed new passwords are compared with `memcmp`. This is user-typed data, so the timing
  channel is small, but it is not constant time. Note it.
- `auth.c:261`, `:322`, `:412`, `:649`, `:1103`: key identity matches on public blobs (public data).
- `prompt.c:169`: `SD_ANSWER_FROM_STORE` is refused when `hostkey_just_accepted` is set (TM-R05).
- `seccache.c:1`: secrets kept encrypted in process memory (CryptProtectMemory or RtlEncryptMemory). Check
  the fallback when neither is available (the test skips without them).
- `agent_pipe.c` (TM-R08 owner check before any write) and `agent_pageant.c:91` (window owner must run as us
  with integrity at least ours).
- `proxy_conn.c:110` (`sspi_allowed` only for an explicitly configured proxy), `:430` (the SPN is the configured
  host name, never a name from the proxy reply), `proxy_system.c:224` (the SSPI decision for discovered proxies).

---

## 3. Test evidence

### 3.1 Suites that cover each area

| Area | Suite (CTest name) | Source | Tests |
|---|---|---|---:|
| Symmetric, hash, curve, CNG differential, KATs | `unit.crypto` | `tests/unit/sd_crypto/` | 37 |
| Public key (SHA-1, bn, RSA, DH, ECDSA/ECDH, CNG) | `unit.crypto_pk` | `tests/unit/sd_crypto_pk/` | 26 |
| SHA-3, ML-KEM, KDFs (Argon2, PPK v3, BLAKE2b), CBC and 3DES | `unit.crypto_pq` | `tests/unit/sd_crypto_pq/` | 21 |
| sd_ssh parsing, negotiation, packet, known_hosts, key files, proxy decision | `unit.ssh` | `tests/unit/sd_ssh/` (main.c list) | 31 |
| Key formats, agents, user auth flow | `unit.ssh_auth` | `tests/unit/sd_ssh/tests_auth.cmake` | 19 |
| Live sshd fixture (WSL): KEX, host keys, reconnect, keepalive | `interop.ssh` | `tests/unit/sd_ssh/test_interop.c` | 12 |
| SFTP over sd_ssh: reconnect, pool, striping, sshd kill | `interop.sftp_ssh` | `tests/unit/sd_sftp/test_ssh_interop.c` | 9 |
| Constant-time helper-call gate (x86) | `isacheck.ct_sd_crypto` | `tools/sd-isacheck` | 1 |
| Matrix interop (srv_* rows) | `interop.ssh_matrix_*` (label `matrix`) | `test_interop_m2.c` | excluded in this pass |

Counts are the number of registered test cases in each suite (`SD_TEST` or `SD_TEST_ENTRY`).

### 3.2 Reproduce

Tools: CMake and CTest from the Visual Studio 2022 Build Tools, placed on PATH:
`<VS BuildTools>\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`.

```bash
# x64 analysis flavour (Debug). The preset is named x64-analysis (there is no x64-analysis-debug preset).
cmake --build --preset x64-analysis
ctest --preset x64-analysis -R "crypto|ssh" -LE "matrix|bench" --output-on-failure

# x86 IA32 flavour (Release). unit.crypto_pk takes about 80 s here; on x86 Debug it takes about 30 min.
cmake --build --preset x86-ia32
ctest --preset x86-ia32 -R "crypto|ssh" -LE "matrix|bench" --output-on-failure

# Gates on x86-ia32 (ISA audit, constant-time gate, import floors)
ctest --preset x86-ia32 -R "isacheck|importcheck|cpucheck" --output-on-failure
```

Interop tests (`interop.ssh`, `interop.sftp_ssh`) need the WSL sshd fixture (`tests/fixtures/wsl-sshd`). Without
it they report "skipped" (exit 77). Both ran against the fixture in this pass.

### 3.3 Results (2026-10-27)

**x64-analysis, Debug** (`ctest --preset x64-analysis -R "crypto|ssh" -LE "matrix|bench"`): **7 of 7 passed.**

| Test | Result | Time |
|---|---|---:|
| unit.crypto | pass | 6.2 s |
| unit.crypto_pq | pass | 3.8 s |
| unit.ssh | pass | 9.0 s |
| interop.ssh | pass | 11.8 s |
| unit.ssh_auth | pass | 33.0 s |
| interop.sftp_ssh | pass | 77.8 s |
| unit.crypto_pk | pass | 143.9 s |

**x86-ia32, Release** (same filter): **7 of 8 passed on the batch run.** `interop.sftp_ssh` failed on that run
and passed on an immediate rerun (see finding F-3). The eighth test, `isacheck.ct_sd_crypto`, passed.

| Test | Result (batch run) | Result (rerun or verbose run) |
|---|---|---|
| isacheck.ct_sd_crypto | pass | - |
| unit.crypto | pass | pass, 37 of 37 cases OK |
| unit.crypto_pq | pass | pass, 21 of 21 cases OK |
| unit.ssh | pass | pass, 31 of 31 cases OK |
| interop.ssh | pass | - |
| unit.ssh_auth | pass | pass, 19 of 19 cases OK |
| interop.sftp_ssh | **FAIL** | pass on rerun (74.2 s) |
| unit.crypto_pk | pass (84.6 s) | pass, 26 of 26 cases OK |

The verbose run of the five `unit.*` suites on x86-ia32 printed no "[ FAIL ]" line and no "[skip]" line.
The only skip inside a passing test is the RSA SHA-224 Wycheproof group, which is printed with its reason
(`tests/unit/sd_crypto_pk/test_rsa.c:106, :134`).

Gate runs (x86-ia32): `ctest --preset x86-ia32 -R "isacheck|importcheck|cpucheck"`: **16 of 16 passed**,
including `isacheck.selftest`, `isacheck.detects_sse2`, `isacheck.detects_ct_helper_call`,
`isacheck.shelldrive`, `isacheck.shelldrive-host`, `importcheck.shelldrive`, `importcheck.shelldrive-host`,
`importcheck.detects_post_xp_import`, `importcheck.maps_winsock_ordinals`, `cpucheck.refuses_without_sse2`.

Not run in this pass: the `matrix` rows (`interop.ssh_matrix_*`), which are excluded by the requested filter
and need `tests/interop/run-matrix.ps1` (handoff item 1). The `bench` label is excluded too.

---

## 4. Constant-time gate and XP import floor

### 4.1 Constant-time helper-call gate (TST-03, TM-R02)

Command (the same invocation as `sd_crypto_ctcheck` and `isacheck.ct_sd_crypto`, run directly on
`build/x86-ia32`):

```bash
build/x86-ia32/bin/Release/sd-isacheck.exe --ct-lib build/x86-ia32/lib/Release/sd_crypto.lib --config Release \
  --ct-member aes_ct.obj --ct-member ct.obj --ct-member curve25519.obj --ct-member gcm.obj \
  --ct-member chacha_poly.obj --ct-member hash.obj --ct-member sha3.obj --ct-member mlkem.obj \
  --ct-member des3.obj --ct-member blake2b.obj --ct-member argon2.obj --ct-member bn.obj \
  --ct-member rsa.obj --ct-member dh.obj --ct-member ec_p.obj --ct-member sha1.obj
```

**Result: exit 0, no output (the tool prints only on a violation).** The 16 objects are the `SD_CT_SOURCES`
list of `tools/sd-isacheck/CMakeLists.txt`. The gate reports a missing member as an error, so all 16 were read.

Negative self-test `isacheck.detects_ct_helper_call`: passes (the fixture's 64x64 multiply must be reported).

Scope of the gate (what it does not do): per `docs/dev/m1-notes.md` and 01 §2.7.5, the gate checks only
calls to compiler helpers and calls outside the allow-list. The conditional-branch, `div`/`idiv`,
*Pass 3 (section 9):* the conditional-branch and DIV/IDIV checks are implemented, and a dudect-style harness is in the tree (`tests/ct`). The text below describes the pass 2 state.

secret-indexed memory-operand, and 64x64-multiply-sequence checks are **not implemented**. dudect
(high-word-zero classes) is **not in the tree** (no test or tool contains "dudect"). The SSE2 flavour and ARM32
are not gated in this pass. See F-5.

### 4.2 ISA audit and XP import floor (x86-ia32)

`sd-isacheck --floor ia32 --allow tools/sd-isacheck/crt-allow.txt build/x86-ia32/bin/Release/<exe>` exits 0 for
`shelldrive.exe` and `shelldrive-host.exe`. The build also runs it as a post-build step (build log: "ISA audit of
shelldrive (x86-ia32)"), and the CTest `isacheck.shelldrive` and `isacheck.shelldrive-host` pass.

Import floor: the post-build step runs
`sd-importcheck --floor tests/os-imports/xp-sp3-x86.txt --subsystem 5.01 --forbid-cfg --require-safeseh`
on both executables. CTest `importcheck.shelldrive` and `importcheck.shelldrive-host` pass; the negative test
`importcheck.detects_post_xp_import` (a fixture importing `GetTickCount64`) is rejected as required.
`sd_ssh` and `sd_crypto` are static libraries; their Vista-or-later APIs (CNG, `CryptProtectMemory`,
WinHTTP, SSPI) are resolved at run time through `sd_platform_resolve` as 01 §5.2 and §6 require.

---

## 5. TST and TM-R mapping

Status key: **Covered** (executed and passing, in this pass); **Partial** (some of the requirement is executed);
**Gap** (no executed test); **Not run** (test exists, not run in this pass); **Out of scope** (UI, installer or
other module, listed for completeness).

### 5.1 TST requirements (05-threat-model.md §7; crypto and SSH rows)

| TST | M / P | Requirement (short) | Evidence (suite, test, file) | Status |
|---|---|---|---|---|
| TST-01 | M0 / P1 | every 01 §12.2 fuzz target present (5 min per PR), WinAFL on x64-xp and x86 | 13 harnesses in `tests/fuzz/harness` (json, ini, utf_names, text_sanitize, keyfile, known_hosts, cert, kexinit, sftp_reply, wd_http, wd_xml, state, manifest), replay in `ctest -L fuzz` (x64-modern and x86-fuzz, pass), libFuzzer 13 x 150 s on x86-fuzz (no crash). Not present: packet, kex reply, userauth, channel, agent, proxy, putty, mlkem, field/bn differential, `.sdmount`, keyset, WinAFL. Section 9 | **Partial** |
| TST-02 | M1 / P1 | fuzzing of shared parsers (`fuzz_text_sanitize` and others) | `fuzz_text_sanitize`, `fuzz_utf_names` (TM-R09, TM-R11 invariants), `fuzz_json` (IPC), `fuzz_ini` (sd_ini, profiles), `fuzz_state` (snapshot reader), `fuzz_manifest`, `fuzz_wd_http`, `fuzz_wd_xml`: all in the replay and libFuzzer runs of section 9. `.sdmount` parser and method dispatch not fuzzed | **Partial** |
| TST-03 | M0 / P1 | constant-time gate on x86-ia32, x86-sse2, arm32: no `_all*`/`__rt_*` calls, no branch, div or 64x64 multiply in CT code; dudect from M1 | `isacheck.ct_sd_crypto` on x86-ia32 (16 objects) now also reports DIV/IDIV and forward conditional branches in `*_ct*` functions (reviewed allow list, `tools/sd-isacheck/ct-branch-allow.txt`); dudect-style harness `tests/ct` run once (|t| max 2.31, section 9). Not done: secret-indexed operands, 64x64 sequence, x86-sse2 and ARM32 runs, high-word classes, 10^6 samples | **Partial** |
| TST-04 | M0 / P1 | KAT, Wycheproof and CNG differential per primitive; negatives (all-zero X25519, invalid ECDH point, non-canonical Ed25519 S, tag bit flips, no release before MAC) | KAT and Wycheproof: `unit.crypto`, `unit.crypto_pk`, `unit.crypto_pq` pass. Non-canonical S: `ed25519_rejects_noncanonical_s` (`test_curve.c`). GCM tag bit flip: `test_sym.c:187-189`. Invalid ECDH point: `wycheproof_ecdh`. All-zero X25519: code at `curve25519.c:450-467`, test assertion to confirm in `wycheproof_x25519`. Release-before-MAC: `tr_packet_cbc_mac_failure_discards` (unit.ssh_transport, pass, F-1) and `gcm_pkt_roundtrip` (`test_sym.c:409-410`, both backends, no plaintext on a tag mismatch; F-7); by inspection `pktcipher.c:263`, `:283` | **Partial** |
| TST-05 | M0 / P1 | name mapping (sd_vfs, sd_sftp dirents) | outside crypto and SSH | **Out of scope** |
| TST-07 | M2 / P2 | symlink tests on the WSL fixture | sd_sftp / sd_vfs | **Out of scope** here |
| TST-11 | M0 / P1 | host-key negatives: mismatch blocks; NEW_TYPE fails without prompt (TM-R04); no stored password after remove+TOFU (TM-R05); reconnect with changed key never prompts | `ssh_kh_stored_types_for_tmr04`, `ssh_lists_hostkey_restricted_to_stored_types` (unit.ssh); `interop_mismatch_blocks`, `interop_stored_type_restriction`, `interop_reconnect_host_key_mismatch`, `interop_reconnect_secret_cache` (interop.ssh, pass); `SD_ANSWER_FROM_STORE` check in `test_conn.c`. NEW_TYPE rows of the matrix: Not run | **Partial** |
| TST-12 | M2 / P1 | Terrapin: test-only prefix-truncation MITM against a non-strict server; TM-R01 result | list construction only: `ssh_lists_terrapin_drops_chacha_without_strict`, `ssh_lists_terrapin_exposed_only_chacha` (unit.ssh). No MITM test exists in the tree (no test contains a prefix-truncation harness) | **Gap** (MITM); list level Covered |
| TST-13 | M2 / P1 | legacy policy matrix on lab servers (allow/warn/ask/refuse, GEX < 2048 ranked last) | list level: `ssh_lists_fallback_ranks_aes_first`, `ssh_negotiate_reports_category` (unit.ssh, pass). Lab rows `interop.ssh_matrix_kex` (`srv_legacy`, `srv_legacy3des`) | **Not run** (matrix) |
| TST-14 | M2 / P2 | live sources: writable-by-others and reparse-point files skipped (`SD_KH_SRC_INSECURE`); wildcard-only lines never MATCH; mismatch in a source blocks | source states and wildcard rule in unit.ssh (`ssh_kh_*`, `test_known_hosts.c`, pass). The ACL-skip cases (`tr_kh_live_source_insecure_is_skipped`, `tr_kh_live_openssh_source`) are in unbuilt files (F-1) | **Partial** |
| TST-15 | M2 / P1 | UpdateHostKeys negatives (unproven key, proof over another session id, `ssh-rsa` legacy proof, announcement after TOFU, wildcard, secondary member) | `tr_kh_apply_hostkeys_and_remove_key` (unit.ssh_transport, pass, F-1); `interop.ssh_matrix_update` (matrix, not run) | **Partial** (unit negatives executed; matrix not run) |
| TST-16 | M2 / P2 | pool: DNS round robin to two servers with different keys or homes | no DNS round-robin test. Pool admission and striping: `m2_pool_admits_members`, `m2_pool_interactive_stays_at_one`, `m2_striping_end_to_end`, `m2_striping_member_lost_mid_transfer` (interop.sftp_ssh, pass on rerun) | **Partial** |
| TST-17 | M2 / P2 | agent squatting: second user creates the agent pipe; Pageant class from low-IL or another user's process; client refuses both | `test_agent.c` (4 tests, fake agents; owner check of TM-R08 in code, `agent_pipe.c`, `agent_pageant.c:91`). No squatting scenario in any executed test | **Gap** (squat) |
| TST-18 | M2 / P1 | proxy NTLM harvesting: `407 NTLM` without SSPI configured; WPAD-discovered proxy; no SSPI token unless TM-R10 holds; Squid Kerberos in the lab | decision only: `ssh_proxy_system_decision`, `ssh_proxy_system_policy_boundary` (unit.ssh, pass). No executed test mentions a 407 challenge (the only `407` hits in `tests/unit/sd_ssh` are in the unbuilt `test_kex.c`). Lab proxies not run | **Partial** |
| TST-19 | M0/M5 | Dokany isolation | sd_dokan | **Out of scope** |
| TST-30 | M0 / P2 | release binaries contain no `none` cipher, no fuzz hooks, no test MITM or mock code | No scan script. The EC test hooks are gated (`SD_EC_TEST_HOOKS`, F-6) and absent from the product objects, library and binaries (`dumpbin`, pass 2, section 8). The `none` cipher, fuzz and MITM checks are not scanned | **Partial** |
| TST-33 | M2 / P1 | external review pass 1 findings closed before any public beta | this package. The review itself is the human's | **Open** (human) |

### 5.2 TM-R items about crypto and SSH (05-threat-model.md §8)

| TM-R | Recommendation (short) | Evidence | Status |
|---|---|---|---|
| TM-R01 | send our KEXINIT only after the server's has arrived; Terrapin-aware lists (01 §4.2, §4.3) | list construction: `ssh_lists_terrapin_*` (unit.ssh). Send-order: `kex.c:192`, `negotiate.c:337` (by code). The interop check of TST-12 is a Gap | **Partial** |
| TM-R02 | no `_allmul`/`_aull*`/`__rt_*` helper in CT code; allow-list of calls | `isacheck.ct_sd_crypto` and `isacheck.detects_ct_helper_call` pass on x86-ia32. The call allow-list is in the gate design; the branch and div checks are not | **Covered** for helper calls; **Partial** overall |
| TM-R04 | when any key is stored for the name, NEW_TYPE fails without prompt | `ssh_lists_hostkey_restricted_to_stored_types`, `ssh_kh_stored_types_for_tmr04` (unit.ssh, pass); `interop_stored_type_restriction` (interop.ssh, pass); `known_hosts.c:425` | **Covered** (unit and one live row) |
| TM-R05 | no stored secrets, cache or kbd-int answer after a fresh acceptance | `SD_ANSWER_FROM_STORE` in `test_conn.c`; `interop_reconnect_secret_cache`, `interop_reconnect_host_key_mismatch` (pass); `prompt.c:169`, `kex.c:513-536` by code | **Partial** |
| TM-R06 | live sources read only with a user-only DACL; wildcard never MATCHes in a live source | wildcard rule: `ssh_kh_*` (unit.ssh). ACL: `known_hosts_live.c:18` by code; its tests run in unit.ssh_transport (F-1, pass 2) | **Partial** |
| TM-R07 | protected per-user DACL on `%APPDATA%\LibreStatic\ShellDrive\` | installer and store folder setup, not in sd_ssh tests | **Out of scope** here (UI or installer) |
| TM-R08 | agent: pipe owner must be LocalSystem or our SID; Pageant window owner must be us | fake-agent tests in `test_agent.c` (owner = our SID); no squat test | **Partial** |
| TM-R09 | sanitize server text and host names (bidi, controls) | `sd_base/test_utf.c`, `sd_ssh/test_auth_flow.c` (unit); fuzz target missing (TST-02) | **Partial** |
| TM-R10 | SSPI to a proxy only when configured explicitly or policy allows | `ssh_proxy_system_decision`, `ssh_proxy_system_policy_boundary` (unit.ssh, pass); no 407 test (TST-18) | **Partial** |

TM-R03 (TOFU dialog without a default button) and the UI parts of TM-R09 are UI, outside this package.

---

## 6. Open findings

Each item is a lead for the reviewer. Severity is not assigned here; it is for the reviewer to assign.

**F-1. Three test sources are never built or run (KEX, packet, certificate, host-key and known_hosts tests).**
`tests/unit/sd_ssh/test_kex.c` (15 `tr_*` tests), `test_kex_main.c` (a runner with 22 declarations) and
`test_known_hosts_m2.c` (7 `tr_kh_*` tests) have no entry in any CMake file (a search of all `CMakeLists.txt`
and `*.cmake` files for `test_kex` and `known_hosts_m2` finds nothing; `tests/unit/sd_ssh/` holds only
`tests_auth.cmake`). They have been in the tree since commit `0026b66`.
Unexecuted tests include `tr_kex_rejects_bad_server_values`, `tr_hostkey_signatures`,
`tr_cert_parse_and_host_checks`, `tr_packet_cbc_mac_failure_discards`, `tr_lists_terrapin_cbc_without_etm`,
`tr_kh_live_source_insecure_is_skipped`, `tr_kh_apply_hostkeys_and_remove_key`. Their coverage of KEX and
host-key negatives is therefore **not** part of the evidence in section 3. Whether they compile and pass is
unknown. `test_kex.c:794` also says "aes128-cbc not provided by sd_crypto yet", but `pktcipher.c:27` provides it,
so that skip message is stale.

*Resolved in pass 2.* The three sources are built as `unit.ssh_transport` (`tests/unit/sd_ssh/CMakeLists.txt:59`,
`test_kex_main.c`, `test_kex.c`, `test_known_hosts_m2.c`). The target builds warning-free on x64-modern, x64-analysis
and x86-ia32, and `ctest -R "ssh|crypto"` runs it (see section 8). The `tr_*` tests named
above are executed by that run. The stale skip message at `test_kex.c:794` is still there and is harmless.

**F-2. The `x64-analysis` build is red.** `cmake --build --preset x64-analysis` exits 1: MSVC C2220 at
`apps/shelldrive/cli_cmds2.c:736` ("the following warning is treated as an error"), caused by warning
C6262 (function uses 19740 bytes of stack) at `apps/shelldrive/cli_cmds2.c:662`. This blocks the `shelldrive`
targets and `sd-test-cli`. The crypto and SSH test executables did build, and the tests in section 3.3 ran against
them. `docs/dev/m2-notes.md` (section "x64-analysis brought back to green") records the preset as green, so
this is a regression since that note. Outside the crypto and SSH scope; not fixed here.

*Resolved in pass 2.* `cli_cmds2.c` now allocates the collected rows on the heap (`hk_list_cmd`, `sd_calloc`, with the
comment at line 659 on C6262). `cmake --build --preset x64-analysis` exits 0 with no warning (section 8).

**F-3. `interop.sftp_ssh` failed once on x86-ia32 Release and passed on rerun.** The failing run printed:
`m1_kill_sshd_during_pipelined_write` failed a remote hash check (`tests/unit/sd_sftp/test_ssh_interop.c:622`,
`remote_sha` of `/write.bin`); `m1_frozen_link_liveness_probe` failed (`test_ssh_interop.c:662` and `:667`,
`SD_E_TIMEOUT` expected); then the process died with `FATAL: unhandled exception 0xc0000005` during
`m2_pool_admits_members`. The rerun (`ctest --preset x86-ia32 -R "^interop.sftp_ssh$"`) passed in 74 s, and the
x64-analysis run passed. Not reproduced, and not explained. Both the test that kills and restarts the WSL sshd
and the `interop.ssh` suite use the same fixture (`RESOURCE_LOCK wsl_sshd_fixture`). Another agent may have used
the fixture during the first run; this was not checked. A data-integrity mismatch and an access violation are
both worth a targeted run with the fixture idle, and a dump if it recurs.

**F-4. No fuzz targets exist.** None of the 01 §12.2 targets (`fuzz_packet`, `fuzz_kexinit`, `fuzz_kex_reply`,
`fuzz_userauth`, `fuzz_keyfile_*`, `fuzz_known_hosts`, `fuzz_proxy_*`, `fuzz_mlkem`, `fuzz_field25519`, and the
others) is in the tree. TST-01 and TST-02 are open. This matters for the parsers listed in section 2.2.

**F-5. The constant-time gate is partial.** Only the helper-call part of TST-03 is implemented (section 4.1).
Missing: the conditional-branch, `div`, secret-indexed-operand and 64x64-sequence checks (`docs/dev/m1-notes.md`
says "not done yet"), dudect (absent), and the SSE2 and ARM32 runs of the gate. The gate checks Release objects
only, by design (`sd-isacheck.c:723`).

**F-6. Test-only entry points are in the product library.** `src/sd_crypto/ec_p.c:646-681` defines
`sd_ec_test_mul`, `sd_ec_test_add` and `sd_ec_test_dbl`, unguarded by a build macro; they are declared in
`src/sd_crypto/pk_internal.h:84-87`. They are internal, and the linker may drop them from executables, but
TST-30 asks that release binaries carry no test-only code. A release-binary scan does not exist (TST-30 gap).
Recommend a reviewer decision on guarding them.

*Resolved in pass 2.* The hooks are now compiled only inside `#ifdef SD_EC_TEST_HOOKS` in `ec_p.c` and are reached
only through `tests/unit/sd_crypto_pk/ec_test_hooks.c`, which defines that macro and includes `ec_p.c`. Evidence
(MSVC 14.44 `dumpbin`, x64-modern Debug build tree): `ec_p.obj`, `sd_crypto.lib`, `shelldrive.exe`,
`shelldrive-host.exe` and `shelldrive-ui.exe` carry no `sd_ec_test_*` symbol (`/symbols` and `/exports`, and no
match in the bytes); `ec_test_hooks.obj` carries 9 matches, so the search itself works. Only the TST-30 scan remains
open as a standing check.

**F-7. CNG path of packet decryption (to verify).** `src/sd_crypto/pktcipher.c:290-293` decrypts in place with
CNG before any caller-visible check. The own-code path checks the tag first (`:263`). Confirm that after
`SD_E_CRYPTO` the buffer is never used, or wipe it. TST-04 says "decryption output never released before MAC".

*Resolved in pass 2.* On the CNG path `sd_cng_gcm` (`src/sd_crypto/aes_cng.c:131-140`) zeroes the output buffer
whenever `BCryptDecrypt` or the tag check fails, so no plaintext remains in the caller's buffer. The own path
(`gcm_open_own`) checks the tag before it decrypts. `gcm_pkt_roundtrip` (`tests/unit/sd_crypto/test_sym.c:409-410`)
runs both backends (`pktcipher_aes_gcm`, `pktcipher_own_backend`) and checks that a tag mismatch releases no
plaintext.

**F-8. Restricted re-key branch (to verify).** `src/sd_ssh/kex.c:343-349` (the `k->fetch` branch) completes a re-key
with a host key of another type, verified only by its signature over H, and records it for the UpdateHostKeys
review (`hostkey_update.c:397-410`). This is the design of TM-R04 and 01 §4.3. Confirm that no path lets the
collected key reach `c->hostkey`, the pinned key or a store without the review step.

*Resolved in pass 2.* The fetch branch only collects the key: `ssh_hku_on_fetch_key` (`hostkey_update.c:397-410`)
records the plain key in the review list (`u->got`) and never writes `c->hostkey`. `kex.c` sets `hostkey_ok` and
sends NEWKEYS, so the connection keeps its pinned key. `tr_fetch_key_never_becomes_pinned`
(`tests/unit/sd_ssh/test_kex.c:840`, unit.ssh_transport) checks that the pinned blob is unchanged after a fetch
re-key that signs with another key.

**F-9. GCM state advances on a tag failure (to verify, low).** `pktcipher.c:297` runs `gcm_next_iv` even when the
tag check failed. This is harmless if every caller treats `SD_E_CRYPTO` as fatal. Confirm.

*Resolved in pass 2.* `sd_pktcipher_open` now sets a sticky `failed` flag on any tag failure and returns
`SD_E_CRYPTO` for every later record of that stream, so the counter cannot be used out of step. The same test
(`gcm_pkt_roundtrip`, `test_sym.c:413-414`) checks that a valid record after a failure is refused.

**F-10. Non-constant-time comparison of user-typed passwords (low).** `src/sd_ssh/auth.c:1153` compares the two
typed new passwords with `memcmp`. Keep this in the reviewer's list; the channel is small.

**F-11. Argon2d and Argon2id data-dependent indexing (by design, to accept).** `src/sd_crypto/argon2.c` header.
PPK v3 keys derived with Argon2d or the second half of Argon2id index memory by the passphrase. The reviewer
should record the acceptance explicitly.

**F-12. Pool DNS round robin is untested (TST-16).** Pool admission and striping have tests; the DNS case does not.

**F-13. Proxy and agent squatting have no executed test (TST-17, TST-18, TM-R08, TM-R10).** Decision logic is
covered by unit tests. The attack scenarios are not run in this pass, and the lab proxies were not run.

**F-14. Matrix interop not run here.** The `matrix` rows (TST-13, TST-15, TM-R01 interop, legacy and NEW_TYPE rows
of TST-11) need `tests/interop/run-matrix.ps1` (handoff item 1). They are the strongest evidence for the
legacy policy and host-key rows and must be run before pass 1 relies on them.

**F-15. No TODO or FIXME markers in the scope.** A search of the scope for `TODO`, `FIXME`, `XXX` and `HACK`
found no markers (the only matches are the phrases "not yet valid" in certificate messages).

**F-16. Skipped tests.** In the verbose unit run, no `[skip]` line appears in the unit suites. The interop suites skip with exit 77 when
the fixture is absent. The RSA SHA-224 Wycheproof cases are skipped with a written reason
(`test_rsa.c:106, :134`), which satisfies 01 §2.7.2. SSH does not use SHA-224.

---

## 7. What this package does not cover

- The human review itself, and the closure of any finding.
- Matrix interop and the lab proxies (section 3.3 and F-14).
- The x86-sse2 and ARM32 constant-time runs, and the x64-xp and x64-modern builds.
- sd_sftp, sd_vfs, sd_dokan and the UI, except where sd_ssh tests exercise them.
- Build-log details beyond the outcomes quoted above.

---

## 8. Pass 2: fixes and evidence (2026-10-27)

Re-run after the first fixes of the package (commit `3185a54`) and the test-process isolation work. Commands and
outcomes; nothing here closes a finding for the human reviewer.

| Check | Command | Outcome |
|---|---|---|
| x64-analysis, Debug, crypto and SSH | `ctest --preset x64-analysis -R "ssh\|crypto" -LE "matrix\|bench\|interop"` | 6 of 6 passed (`unit.crypto`, `unit.crypto_pq`, `unit.ssh`, `unit.ssh_transport`, `unit.ssh_auth`, `unit.crypto_pk`) |
| x64-analysis build | `cmake --build --preset x64-analysis` | exit 0, no warning (F-2 closed) |
| x86-ia32, Release, crypto and SSH | `ctest --preset x86-ia32 -R "ssh\|crypto" -LE "matrix\|bench\|interop"` | 7 of 7 passed (adds `isacheck.ct_sd_crypto`) |
| x86-ia32 Release build | `cmake --build build/x86-ia32 --config Release` | exit 0, no warning |
| x64-xp, Release build | `cmake --build build/x64-xp --config Release` | exit 0, no warning; the manifests of the XP flavour carry no `longPathAware` and no `dpiAwareness` (81010002 gone) |
| x64-modern, Debug, full non-matrix suite | `ctest --preset x64-modern-debug -LE "matrix\|bench\|interop"` | 46 of 47 in the run that counted; the one failure was `unit.vfs` (see below). `unit.vfs` alone passed in 5 of 5 reruns. The new `apps.no_leftover_processes` passed |

Named `tr_*` tests from F-1 and F-8 were run directly on x86-ia32 Release (`sd-test-ssh_transport.exe`): 23 of 23
passed, including `tr_packet_cbc_mac_failure_discards`, `tr_kh_live_source_insecure_is_skipped`,
`tr_kh_apply_hostkeys_and_remove_key` and `tr_fetch_key_never_becomes_pinned`.

Intermittent failure seen in pass 2 (not in the D38 scope, not changed): `unit.vfs`, check
`fake_open_handles(f.s) == 0` at `tests/unit/sd_vfs/test_vfs_ops.c:151`, right after `vclose`. The fake session's
handle close can still be in flight when the count is read. It failed once under `-j 4` load and passed on five
standalone reruns. The owner of sd_vfs should wait for the close before the check.

### 8.1 Resolution of the findings

- **F-1** resolved: the three sources are built as `unit.ssh_transport` and run (see above).
- **F-2** resolved: `cli_cmds2.c` uses a heap copy for the collected rows; `x64-analysis` builds without C2220/C6262.
- **F-6** resolved: EC test hooks exist only under `SD_EC_TEST_HOOKS`. `dumpbin /symbols` and `/exports` on
  `ec_p.obj`, `sd_crypto.lib`, `shelldrive.exe`, `shelldrive-host.exe` and `shelldrive-ui.exe` (x64-modern Debug
  tree) show no `sd_ec_test_*` symbol, and the byte search finds none. The test-hook object `ec_test_hooks.obj`
  shows nine matches, so the search works.
- **F-7** resolved: CNG failure zeroes the output (`aes_cng.c:131-140`); tested by `gcm_pkt_roundtrip`.
- **F-8** resolved: the fetch branch collects the key for review only; `tr_fetch_key_never_becomes_pinned` checks
  the pinned key is unchanged and the collected key is the one the server sent.
- **F-9** resolved: `sd_pktcipher_open` keeps a sticky failure; tested by `gcm_pkt_roundtrip`.

## 9. Pass 3: fuzz targets and constant-time checks (F-4, F-5)

Scope: F-4 (no fuzz targets) and F-5 (constant-time gate partial), with TST-01, TST-02 and TST-03. F-3 (the interop
flake) is not in this pass. Commands were run on 2026-10-27 at commit `c80ea7d` plus this change (uncommitted). Nothing
here closes a finding for the human reviewer.

### 9.1 What was built

- **Harnesses:** 13 targets in `tests/fuzz/harness/` (see the TST-01 row). Each defines `sd_fuzz_one`, and each is
  built twice: a replay driver `sd-fuzz-<t>.exe` (always: corpus plus 4000 deterministic mutations, or 200 for
  `keyfile`) and a libFuzzer driver `sd-fuzz-<t>-libfuzzer.exe` (`-DSD_FUZZ=ON`, preset `x86-fuzz`). Seeds are
  hand-written, or copies of our own `tests/unit/sd_ssh/fixtures` keys and known_hosts lines.
- **libFuzzer on this host:** works on the x86 (Win32) v143 build with `/fsanitize=fuzzer /fsanitize=address /MD`.
  The x64 runtime is not installed in this Visual Studio (`clang_rt.asan_static_runtime_thunk-x86_64.lib` is missing),
  so the x64 libFuzzer build cannot link here. `docs/dev/m6-notes.md` lists the component to install.
- **CT gate:** `tools/sd-isacheck` now classifies conditional branches and DIV/IDIV, and checks the functions named
  `*_ct_*`, `*_ct` and `sd_ct_*` in the constant-time objects of sd_crypto (`--ct-allow` list with reasons).
- **Timing harness:** `tests/ct/ct_dudect.c` (`SD_CT_TIMING=ON` only, label `ct`): Welch t-test, two input classes,
  cycle counter, 99.5th-percentile cropping, for X25519, Ed25519 signing, AES-CTR, the MAC compare (`sd_ct_memeq`) and
  RSA-1024 `sd_bn_ct_modexp`.

### 9.2 Replay and libFuzzer results

| Check | Command | Outcome |
|---|---|---|
| Replay, x86-fuzz (Debug, ASan) | `ctest --preset x86-fuzz -L fuzz` | 13 of 13 pass, about 20 s (keyfile 16 s) |
| Replay, x64-modern (Debug) | `ctest --test-dir build/x64-modern -C Debug -L fuzz` | 13 of 13 pass, 1.8 s |
| libFuzzer campaign | `sd-fuzz-<t>-libfuzzer.exe <scratch copy> -max_total_time=150 -timeout=20`, 13 targets | 13 runs finished, about 29.5 million executions in total, no crash, no timeout, no ASan report |
| `unit.config` (sd_config, after the fix) | `ctest --test-dir build/x64-modern -C Debug -R unit.config` | pass |

Executions per target in the campaign (150 s): cert 7.30 M, kexinit 4.90 M, manifest 4.41 M, wd_http 3.53 M,
utf_names 1.47 M, text_sanitize 1.41 M, json 1.32 M, wd_xml 1.19 M, sftp_reply 1.17 M, known_hosts 1.05 M, ini 0.97 M,
state 0.75 M, keyfile 0.03 M (KDF cost per input).

### 9.3 Findings and fixes

**Fuzz-1. Heap use-after-free in the INI reader (fixed).** `src/sd_config/ini.c`, the error path of `sd_ini_parse`
(before the fix at lines 299-304). The reader converts input that is not UTF-8 from the ANSI code page into a heap
buffer `conv` and points `data` at it. On a line that contains a NUL, or that fails to parse, the error path called
`sd_free(conv)` and then ran `memchr(data + pos, 0, n)` to choose the error code, which read freed memory (ASan:
heap-use-after-free, READ of size 2, in `sd_ini_parse`, reported by the replay driver on its first run with 4000
mutations). Root cause: the error code was computed after the buffer it points into had been released. Fix: decide the
error code before `sd_free(conv)` (`has_nul`). Impact: an INI file (profile, settings or override) that is not UTF-8
and has a NUL in a line caused a read of freed heap memory in the agent or the shell. Regression:
`tests/fuzz/corpus/ini/regress_ansi_nul_line` (`[s]`, a 0xE9 byte, `=`, NUL, `x`) runs in `fuzz.ini` on every run.

**Fuzz-2. Name mapping: spec and gate disagree (no product change; reviewer decision).** `sd_name_to_wide` accepts remote
bytes 0x00 and 0x2F, and `sd_name_from_wide` refuses them with `SD_E_INVALID_NAME` (`src/sd_base/utf.c:235`; the
component invariant of TM-R11 and 01 section 10.7). 01 section 10.7 also says the round trip "is exact for every byte
string". Both cannot hold. The harness asserts the component invariant: the round trip is exact for every string
without NUL or `/`, and otherwise `sd_name_from_wide` refuses with `SD_E_INVALID_NAME`. No output may contain NUL or `/`.
The spec sentence should say "every byte string that is a valid component". The reviewer decides whether the spec or
the mapping changes.

**Open, not a crash.** `fuzz.keyfile` costs seconds per KDF-protected input under ASan (Debug, x86). No bound on KDF
work for a crafted key file was checked (the OpenSSH bcrypt rounds, the PPK v3 Argon2 memory and passes). 01 section
12.2 asks for KDF rounds to be clamped in fuzz builds; the product has no such clamp, and the harness only limits the
mutation count. Reviewer item: confirm the upper bounds for bcrypt rounds and Argon2 cost in the key loaders.

### 9.4 Constant-time gate (F-5)

Objects: the 16 `SD_CT_SOURCES` of sd_crypto, Release, x86-ia32 (`build/x86-ia32/lib/Release/sd_crypto.lib`).

| Step | Result |
|---|---|
| New rules, no allow list | DIV/IDIV: none. Forward conditional branches: 57. Most are loop-entry guards of `for` loops with public bounds (`sd_ct_memeq`, `sd_ct_cmov`, `sd_ct_cswap_*`, most of `bn.obj`); the rest are argument and size checks |
| Loop-entry guard rule (a forward branch that skips a loop whose back-edge lies inside the skipped region is accepted) | 28 violations, all in six functions |
| Six reviewed functions in `tools/sd-isacheck/ct-branch-allow.txt`: `sd_bn_ct_mul`, `sd_bn_ct_mod`, `sd_bn_ct_modexp` (argument and size checks on public lengths), `sd_mp_modexp_ct` (`if (bit + 4 > ebits)`, public window position), `sd_aes_sbox_ct` (`if (inverse)`, public direction), `sd_bn_ct_modinv` (`if (!ok)`, invertibility) | 0 violations; gate exits 0 |

Negative fixtures (`tools/sd-isacheck/fixtures/ct_fixture.c`, names with `_ct_`): `isacheck.detects_ct_forward_branch`
and `isacheck.detects_ct_div`. Selftest with 13 branch-class vectors: `isacheck.selftest`. Run on x86-ia32 Release,
these pass with the gate: `isacheck.selftest`, `isacheck.ct_sd_crypto`, `isacheck.detects_ct_forward_branch`,
`isacheck.detects_ct_div`, `isacheck.detects_ct_helper_call`, `isacheck.detects_sse2`, `isacheck.sse2_floor_accepts_sse2`,
`cpucheck.starts_with_sse2`, `isacheck.entry_thunk_is_ia32` (9 of 9). The app ISA audits (`isacheck.shelldrive` and the
others) need the application binaries, which were not built in this pass, so they were not run.

Limits (for the reviewer): the loop-guard rule cannot tell a public loop bound from a secret one, and an allow-list
entry exempts a whole function, so a new branch on secret data inside one of the six functions is not caught. The
reason on each allow-list line is the review record. Still missing: secret-indexed memory operands, the 64x64 multiply
sequence check (only the helper-call form is checked), and the ARM32 gate.

**x86-sse2 run (v141_xp, `/arch:SSE2`), 2026-10-27.** The gate first failed on four forward branches that the ia32
objects do not have. The disassembly (`dumpbin -disasm`, from MSVC 14.44 `Hostx64\x86`, which ships `msvcdis140.dll`;
the 14.16 copy in the same tree does not) shows that all four are vectorizer code, emitted around the loops that take
a secret mask. None tests the mask or any secret value:

| Function (object) | Branch | What it tests |
|---|---|---|
| `sd_ct_cswap_u32` (ct.obj) `+0x3e -> +0x4a` | `cmp edx,eax; ja` after `lea eax,[edi+eax*4]` | Overlap of `a` and `b` (`b > &a[n-1]`). Pointers and public `n`. |
| `sd_ct_cswap_u64` (ct.obj) `+0x58 -> +0x5e` | `cmp esi,eax; ja`, with `esi` = `b` and `eax` = `&a[n-1]` | Same overlap check for the 64-bit form. |
| `sd_ct_cmov` (ct.obj) `+0x51 -> +0x60` | `cmp edx,eax; ja` (`dst` against `src + n - 1`) | Overlap of `dst` and `src`. Pointers and public `n`. |
| `sd_mp_modinv_ct` (bn.obj) `+0x74 -> +0x7a` | `cmp edi,eax; ja` (`x1` against `&x2[n-1]`) | Overlap of the `x1` and `x2` zeroing loop `x1[i] = x2[i] = 0`. Work-buffer offsets for public `n`. |

The masks reach only `pand`/`pxor`. The `cmp n, 64` (cmov) and `cmp esi, 4` / `cmp ebx, 2` (cswap) guards that
come before the vector body test public lengths. Those guards were not reported, because each skips a loop whose
back-edge is inside the skipped region.

Fix (source, not allow-list): `SD_CT_NO_VECTOR` (`src/sd_crypto/sd_ct64.h`, expands to `__pragma(loop(no_vector))` on
MSVC) before the four loops above (`ct.c`: `sd_ct_cswap_u32`, `sd_ct_cswap_u64`, `sd_ct_cmov`; `bn.c`:
`sd_mp_modinv_ct` zeroing loop). The loops keep one scalar body per element, and the re-disassembly of `ct.obj` and
`bn.obj` has no overlap or length branches left in those functions. The allow list is unchanged. Gate results after
the fix: x86-sse2 `sd_crypto_ctcheck` and x86-ia32 `sd_crypto_ctcheck` both exit 0 with no violation. The vector
speed of the cswap and cmov paths is given up; they run on fixed-size field elements (X25519, 10 limbs) and on
MLKEM/RSA-size buffers, so the cost is small and was not measured.

`ctest --preset x86-sse2 -R "crypto|isacheck"` after the fix: 17 of 17 pass (unit.crypto_pk 75 s, unit.crypto 2.9 s,
unit.crypto_pq 1.6 s, `isacheck.ct_sd_crypto` and the other isacheck tests).

Still open for this flavour: the ARM32 gate, and the x86-sse2 timing run (9.5).

### 9.5 Timing harness (TST-03, dudect-style)

Run once: `build/x86-ia32/bin/Release/sd-ct-dudect.exe` (x86-ia32 Release, default samples: 20000 per primitive, 4000
for RSA), on the development host, with the other jobs idle.

| Primitive | Samples used | max abs t | Verdict at this size (threshold 4.5) |
|---|---|---|---|
| X25519 scalar multiplication (fixed vs random scalar) | 19901 | 0.76 | no leak detected |
| Ed25519 signing (fixed vs random seed) | 19901 | 2.05 | no leak detected |
| AES-CTR (fixed vs random key) | 19901 | 0.42 | no leak detected |
| MAC compare, `sd_ct_memeq` (equal vs one-byte difference) | 19901 | 0.63 | no leak detected |
| RSA-1024 `sd_bn_ct_modexp` (all-ones vs random exponent) | 3981 | 2.31 | no leak detected |

Harness note: the first MAC run gave |t| = 26.0 because the two classes performed different stores in preparation
(class 1 flipped a byte). The harness now has both classes perform the same store and differ only in the value; two
later runs gave 0.79 and 0.74. The 26.0 was a harness artifact, not a finding about `sd_ct_memeq`. It is recorded so
that a new class does not repeat the asymmetry. `X25519` still prepares its inputs with `memset` in class 0 and
`rng_fill` in class 1 (different store patterns). Its t is small, but the rule applies to any new class.

Not done, required by 01 section 2.4 rule 9 and TST-03: 10^6 to 10^7 samples per class; the high-word-zero and
all-ones classes on the 32-bit flavours; GHASH, Poly1305, DH, ML-KEM decapsulation, ECDSA and the RSA CRT paths;
x86-sse2, x64 and ARM64 runs; the nightly `ct.yml` job on the lab machine. Five primitives at 2 x 10^4 samples show
only that no leak appears at this size.

### 9.6 Resolution of the findings

- **F-4 (no fuzz targets):** partly resolved. 13 of the listed targets exist, with a replay driver in every run and a
  libFuzzer driver on the x86 fuzz build. One finding fixed (Fuzz-1). Still open: the rest of the 01 section 12.2 list
  (`docs/dev/m6-notes.md` lists it), the x64 libFuzzer runtime on this host, WinAFL, and the nightly `fuzz.yml` job.
- **F-5 (constant-time gate partial):** partly resolved. The DIV/IDIV and forward-branch rules are in the gate, with a
  reviewed allow list; a dudect-style harness exists and was run once with no leak at this sample size. Still open:
  the secret-index and 64x64 checks, the x86-sse2 and ARM32 runs, the sample sizes, the high-word classes, and nightly CI.
