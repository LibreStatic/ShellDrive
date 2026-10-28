# 01 - SSH, SFTP and crypto core (`sd_crypto`, `sd_ssh`, `sd_sftp`)

Status: design (M7: `zlib@openssh.com` implemented, section 4.7; adaptive channel windows implemented, section 4.8; docs/dev/m7-notes.md), updated to the accepted decisions of 2026-10-24 (`decisions.md`, which wins over this document
where they differ) and to the resolutions of `00-integration-review.md` that concern this module. Threat-model
integration 2026-10-24: the recommendations of `05-threat-model.md` §8 that target this module (`TM-Rxx`, as
accepted by decisions.md D33-D39) are applied in place; each change cites its `TM-R` and threat (`T-xx`) ids, the
security tests (`TST-xx`, 05 §7) are mapped in section 12.4, and section 17 lists them. M7 (section 2.8.2): the P-256, P-384 and P-521 field multiplication uses the NIST reductions
(FIPS 186-4 D.2 for P-256 and P-384, a Mersenne-type fold for P-521) on normal-form elements; the scalar field stays
Montgomery.
Scope: the three protocol and crypto modules under the mount backends. The filesystem layer (`sd_vfs`), the
WebDAV and Dokany backends, the UI, credential storage and the installer are designed elsewhere. They only use the
public APIs in sections 9 and 10 (`sd_sftp.h`, plus the few `sd_ssh.h` types it re-exports).

Inputs: `docs/requirements.md`, `AGENTS.md`, `docs/design/decisions.md`, `docs/design/00-integration-review.md`.
Decision ids written `D<n>` in the table below are local to this document; ids of the project-wide decision record
are written `decisions.md D<n>`.

---

## 0. Summary of decisions

| # | Decision |
|---|----------|
| D1 | One **I/O thread per connection chain** (target host plus all ProxyJump hops), running an event loop on non-blocking Winsock sockets with `WSAEventSelect` and `WaitForMultipleObjects`. No IOCP. CPU-heavy or blocking work (key decryption KDFs, agent IPC, DNS) runs on short-lived worker threads (`QueueUserWorkItem`, XP+). |
| D2 | All public APIs are **asynchronous with completion callbacks** that run on the connection's I/O thread. Each callback is invoked exactly once when submission returned `SD_OK`, and never from inside the submitting call. Sync wrappers exist for the CLI and tools. |
| D3 | Crypto dispatch: **CNG where it implements the exact construction we need and is present on that OS version** (AES, 3DES, ECDSA/ECDH, RSA), otherwise our own constant-time C. XP always uses our own code; CryptoAPI is only used for the RNG on XP. Hashes and HMAC are always our own code, and CNG serves only as a differential-test reference for them (decisions.md D2). X25519, Ed25519, ChaCha20-Poly1305@openssh, finite-field DH, ML-KEM, SHA-3/SHAKE, bcrypt-pbkdf, Argon2, Blowfish and BLAKE2b are always our own code (section 2.2 has the reasons). |
| D4 | Algorithm preference: modern algorithms first, legacy enabled by default but always last, with a UI warning only (decisions.md D33; threat-model TM-Q01 is not adopted). Every session exposes a `legacy_mask` bit set for UI warnings, including a Terrapin-exposure bit, and can hold the connection before userauth for a legacy acknowledgement (`SD_PROMPT_LEGACY_ACK`) when a profile or policy sets `ask`. |
| D5 | Strict KEX (`kex-strict-c-v00@openssh.com`) and `ext-info-c` are always offered. Our KEXINIT is sent **after the server's KEXINIT has arrived**, so the cipher and MAC lists can avoid the Terrapin-affected combinations when the server lacks strict KEX (decisions.md D34, TM-R01, section 4.3), and the host-key list can be restricted to the key types already stored for the host (TM-R04, section 4.3). `mlkem768x25519-sha256` (the OpenSSH 10 default) ships in v1, milestone **M2**, with our own ML-KEM-768 and SHA-3/SHAKE (decisions.md D15). `sntrup761x25519` is not planned. |
| D6 | Compression: v1 ships `none` only. `zlib@openssh.com` (delayed, post-auth) comes later with our own inflate/deflate, off by default. Plain pre-auth `zlib` is never offered. |
| D7 | `sd_sftp` speaks SFTP v3 as OpenSSH implements it, with the listed extensions. Paths are **raw wire bytes** (normally UTF-8, NUL-terminated). Lossless byte<->UTF-16 helpers map invalid bytes into a reserved private-use range (U+F780..U+F7FF). |
| D8 | Every SSH connection of a session carries **two SFTP channels by default: a "meta" channel (path operations, directories, attribute-only opens) and a "bulk" channel (data handles)**, auto-degrading to one channel with a meta-first scheduler (decisions.md D19). A file handle is bound to one channel. Ordering is guaranteed only per handle (per byte range for striped handles, section 10.9). |
| D9 | Reconnection: `sd_sftp_session` is a stable object that survives reconnects. It runs the backoff loop itself, using a policy the caller supplies, **per connection** of its pool. Handles become *stale* and are revived explicitly by the VFS with `sd_sftp_file_reopen()`, which uses open parameters stored in the handle. |
| D10 | Host keys: an **ordered store list**: the machine store (read-only for users), the user store (read-write), plus the live read-only sources `~/.ssh/known_hosts` and the PuTTY registry, on by default (decisions.md D7). A matching key from a live source is copied into the user store with a source comment. Our entries are written plain (decisions.md D8). A mismatch in any source blocks; there is no "accept anyway" path in the protocol layer. Live sources are honored only when no other user can write them, and wildcard-only lines from them never produce a match (TM-R06). `sd_known_hosts` owns all `known_hosts` file I/O and locking. |
| D11 | Parsers (packets, keys, known_hosts, SFTP replies, agent replies, proxy replies) are portable C with no `windows.h` and use one bounded reader type. They are fuzzed with libFuzzer (clang-cl on Windows; an optional Linux fuzz job is test infrastructure only, decisions.md D21). |
| D12 | DSA (`ssh-dss`), hostbased auth, agent forwarding, X11/port forwarding (other than the internal direct-tcpip used for ProxyJump), UMAC, Ed448, FIDO `sk-*` key files, SSH-1, SOCKS4 and **ProxyCommand** are out of scope. Agent-held keys of unknown types are passed through opaquely. |
| D13 | **Zero third-party code, crypto included** (decisions.md D1). Field arithmetic for curve25519 and P-256/384/521, the bignum, ML-KEM, SHA-3 and everything else are ours. Papers, RFCs and specifications may be read; no code is copied or vendored. Correctness and side-channel resistance are established by the verification strategy in section 2.7, which ends in an external cryptographic review in two passes: pass 1 at the end of M2, pass 2 before 1.0 (decisions.md D38). |
| D14 | **Connection pool per mount** (decisions.md D18): 1..4 SSH connections, default 1. Extra connections are opened only when every hop authenticated non-interactively. Metadata stays on the primary connection; bulk transfers of opted-in handles are striped across connections. The pool is invisible to callers except through options, statistics and the striping flag (section 10.9). |
| D15 | **HTTP CONNECT and SOCKS5 proxies** per profile and per ProxyJump hop, with our own minimal clients, optional proxy authentication (HTTP Basic, optional NTLM/Negotiate via SSPI; SOCKS5 username/password) and the system proxy as an opt-in source (decisions.md D20). No ProxyCommand. |
| D16 | **UpdateHostKeys** (`hostkeys-00@openssh.com` + `hostkeys-prove-00@openssh.com`) in v1: new host keys are learned only when proven over a connection authenticated with an already-trusted key, and never written to the machine store without admin policy (decisions.md D16). |
| D17 | Per-request deadlines are always set, **by the caller** (`sd_vfs` passes 25 s for Dokany and 50 s for WebDAV, 02 §5.7); `default_timeout_ms` (30 s) applies only to callers that pass none (CLI, tools), and any request timeout triggers an immediate liveness probe, so a dead link is reported inside Dokany's 30 s request timeout (review C16). |
| D18 | x86 ships two builds (decisions.md D4): `x86-ia32` (`/arch:IA32`, no SSE2) and `x86-sse2`. All crypto has portable scalar paths that never need SSE2; vector and instruction-set fast paths and their runtime detection exist only in the `x86-sse2`, x64 and ARM builds. |

All decisions are accepted. The record is `decisions.md`; the integration changes applied here are listed in
section 17.

---

## 1. Module layout and dependencies

The shared layers are defined by the integration review (C39, §5) and owned by the build design (04); this module
uses them and does not define its own copies.

```
sd_base      (no windows.h, fuzzable)
  sd_buf.h       bounded reader / growable writer (section 12)
  sd_err.h       neutral error enum (section 10.2) + the generated master tables (sd_err -> name, review §4)
  sd_utf.h       UTF-8 <-> UTF-16 conversion, incl. the stage-1 lossless name mapping (section 10.7)
  checked size arithmetic, sd_mem allocation hooks (failure injection)
sd_platform  (Win32)
  sd_alloc / sd_free (process heap), sd_secbuf (zeroized, VirtualLock best effort)
  sd_platform_resolve()   post-XP API resolution, modules loaded by full System32 path
  threads, critical sections, events, interlocked once, 64-bit tick (XP-safe)
  sd_log(level, component, mount_id, fmt, ...)   English only, restricted format language, no secrets

sd_crypto  -> sd_base, sd_platform
sd_ssh     -> sd_crypto, sd_base, sd_platform, ws2_32 (static import, XP-safe exports only), advapi32, user32 (Pageant)
sd_sftp    -> sd_ssh, sd_base, sd_platform
```

Source tree (04 §4 layout): `src/sd_crypto/`, `src/sd_ssh/`, `src/sd_sftp/` (each with `include/<module>/`),
`tests/unit/<module>/`, `tests/vectors/` (RFC, NIST and Wycheproof data), `tests/fuzz/<target>/`,
`tests/integration/`. There is **no** `third_party/` directory for these modules: they contain zero third-party
code (D13).

`sd_ssh` keeps the key-file parsers and the `known_hosts` code in translation units without transport
dependencies, because the CLI and UI link only those parts (review §5; enforced by a link test).

Every function newer than XP SP3 (all of `bcrypt.dll`, `CryptProtectMemory`, `IdnToAscii`, `GetTickCount64`, the
optional WinHTTP proxy-discovery calls, ...) is resolved at runtime through **`sd_platform_resolve()`**, which loads
the module by **full System32 path** (`GetSystemDirectoryW` + name) and caches the result. This prevents DLL planting
without needing `LOAD_LIBRARY_SEARCH_SYSTEM32`, which XP lacks and Win7 only has with KB2533623. The import audit of
04 §2.4 enforces that nothing post-XP is imported statically.

**C dialect.** All code compiles with v141_xp and with v143 `/std:c11` (04 §2.3). Forbidden: VLAs, `_Generic`,
`<stdatomic.h>`, `<threads.h>`, `_Thread_local` and direct `_Alignas`; atomics use `Interlocked*` only, alignment
uses `SD_ALIGN(n)`, static checks use `SD_STATIC_ASSERT`. Fixed-size crypto contexts and limb arrays are sized by
compile-time constants, never by run-time lengths on the stack.

---

## 2. `sd_crypto`

### 2.1 Algorithm inventory (what SSH needs)

| Use | Algorithms | Primitives |
|-----|------------|------------|
| KEX | mlkem768x25519-sha256 (M2), curve25519-sha256(+@libssh.org), ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256/sha1, diffie-hellman-group1/14-sha1, group14-sha256, group16-sha512, group18-sha512 | X25519, P-256/384/521 ECDH, mod-exp up to 8192 bits, SHA-1/256/384/512, ML-KEM-768 + SHA3-256/512, SHAKE128/256 (M2) |
| Host/user keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-256/512, ssh-rsa, and their -cert-v01@openssh.com variants | Ed25519 (SHA-512), ECDSA, RSA PKCS#1 v1.5 sign/verify |
| Ciphers | chacha20-poly1305@openssh.com, aes128/256-gcm@openssh.com, aes128/192/256-ctr, aes128/192/256-cbc, 3des-cbc | ChaCha20 (DJB 64-bit nonce variant), Poly1305, AES, GHASH, DES/3DES |
| MACs | hmac-sha2-256/512(-etm@openssh.com), hmac-sha1(-etm@openssh.com) | HMAC |
| Key files | OpenSSH v1 (bcrypt-pbkdf + aes256-ctr and the other ciphers above), PEM PKCS#1/SEC1 (legacy `DEK-Info` encryption), PKCS#8 (PBES2), PPK v2/v3 | bcrypt-pbkdf (Blowfish + SHA-512), MD5 (EVP_BytesToKey), PBKDF2-HMAC-SHA1/SHA2, Argon2i/d/id (BLAKE2b), AES-CBC/CTR, 3DES-CBC, ASN.1 DER parsing (in sd_ssh) |
| Misc | fingerprints, known_hosts hashing, release signatures (shared with the updater) | SHA-256, MD5 (legacy display), HMAC-SHA1, Ed25519 verify |
| Randomness | everything | OS CSPRNG |

### 2.2 Implementation and dispatch per primitive

Legend: **own** = our C code; **CNG** = `bcrypt.dll`; **CAPI** = CryptoAPI / advapi32.

| Primitive | XP SP3 | Vista / 7 / 8.0 | 8.1+ / 10 / 11 | Notes |
|-----------|--------|-----------------|----------------|-------|
| CSPRNG | `RtlGenRandom` (advapi32 `SystemFunction036`), fallback `CryptGenRandom` (PROV_RSA_FULL, VERIFYCONTEXT) | `BCryptGenRandom` with an opened `BCRYPT_RNG_ALGORITHM` handle (Vista); `BCRYPT_USE_SYSTEM_PREFERRED_RNG` on Win7+ | same | No user-space DRBG of our own. Each connection keeps a 256-byte refill buffer for padding bytes. An RNG failure is fatal for that connection (`SD_E_CRYPTO`), never silently degraded. |
| SHA-1/256/384/512, MD5 | own | own | own | Always own code (decisions.md D2). Hashes have no secret-dependent timing and our code is as good as CNG's. CNG adds per-call overhead on the per-packet MAC path (no reusable hash objects before Win8). Optional SHA-NI (`x86-sse2`, x64) / ARMv8 SHA1/SHA2 fast paths. CNG is the reference in differential tests only. |
| HMAC | own | own | own | On top of our hashes (decisions.md D2). MAC compare is constant time. |
| SHA3-256/512, SHAKE128/256 (M2) | own | own | own | Keccak-f[1600] written from FIPS 202. Needed for ML-KEM. 64-bit lanes; on 32-bit targets the compiler splits lane operations (no bit interleaving in v1; measured before optimizing). |
| AES block / CBC / ECB | own | CNG (`BCRYPT_AES_ALGORITHM`, CBC/ECB) | CNG | Own: AES-NI path (`x86-sse2`/x64 only, CPUID.1:ECX.25; ARMv8-CE on ARM64) or constant-time **bitsliced** AES, our own implementation of the published bitslicing technique (Käsper-Schwabe) with a gate-level S-box circuit from the literature (Boyar-Peralta); 64-bit slices on x64/ARM64, 32-bit slices on x86/ARM32. The own path is also used on Vista+ if CNG fails. |
| AES-CTR | own | CNG ECB over batched counter blocks (up to 4 KiB per call), XORed by us | same | CNG has no CTR mode. If AES-NI or ARMv8-CE is present, the own HW path wins (one less copy). Rule: own HW > CNG > own bitsliced. |
| AES-GCM | own (AES-NI + PCLMULQDQ, or bitsliced AES + constant-time GHASH that emulates carry-less multiplication with integer multiplies on masked, spaced-out bits, a technique described in public constant-time write-ups) | CNG `BCRYPT_CHAIN_MODE_GCM` (Vista SP1+), per-packet nonce in `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` | CNG | RFC 5647 / OpenSSH framing: 4-byte packet length is AAD, 12-byte nonce = 4-byte fixed + 8-byte invocation counter, incremented after every packet. |
| ChaCha20-Poly1305@openssh | own | own | own | CNG has `CHACHA20_POLY1305` on Win10+, but it is the RFC 8439 AEAD (96-bit nonce, AEAD padding) and cannot express the OpenSSH construction (two keys, 64-bit sequence-number nonce, separately encrypted length, Poly1305 key from block 0, MAC over the encrypted length and ciphertext). Scalar path everywhere (the only path in `x86-ia32`). Vector paths: SSE2/SSSE3 (`x86-sse2`, x64), NEON (ARM32/ARM64), optional AVX2 when the OS has enabled AVX state (`XGETBV`). Poly1305: 26-bit limbs on 32-bit targets, 44-bit limbs with 128-bit products on 64-bit targets. |
| 3DES-CBC | own (constant-time bitsliced DES, from the published bitslice technique; no S-box tables) | CNG `BCRYPT_3DES_ALGORITHM` | CNG | Legacy. |
| X25519 | own | own | own | CNG has curve25519 on Win10, but only through `BCRYPT_KDF_RAW_SECRET` (8.1+, little-endian output). One own code path is simpler and is constant time. Own field arithmetic (section 2.8). Win10+ CNG X25519 is a differential-test reference. |
| Ed25519 | own | own | own | Not in CNG. Sign is constant time; verify is variable time (public data). Strict decoding: reject non-canonical S (S >= L) and non-canonical point encodings, use cofactorless verification (matches OpenSSH). Own field and group arithmetic (section 2.8). |
| ECDH P-256/384/521 | own | own | CNG (`BCRYPT_ECDH_P*`, `BCRYPT_KDF_RAW_SECRET`, reverse LE -> BE) | Raw secret is unsupported on Vista-8.0 (documented as 8.1+). Own: our own Montgomery field engine (section 2.8), complete Renes-Costello-Batina formulas, fixed-window constant-time scalar multiplication, point validation on input. |
| ECDSA P-256/384/521 sign | own | CNG (`BCryptSignHash`; we hash, CNG returns r\|\|s, we re-encode as SSH mpints) | CNG | Own: RFC 6979 deterministic nonce, hedged with 32 random bytes; constant-time scalar inversion (Fermat) in the scalar field of section 2.8. |
| ECDSA verify | own | CNG | CNG | Own path is variable time (public inputs). |
| RSA PKCS#1 v1.5 sign | own | CNG (`BCRYPT_RSAFULLPRIVATE_BLOB` import, `BCRYPT_PAD_PKCS1`, SHA1/256/512 OIDs) | CNG | Own: constant-time Montgomery mod-exp, CRT, base blinding, verify-after-sign (fault-attack check). Keys 1024..16384 bits (CNG maximum is also 16384). |
| RSA verify | own | CNG | CNG | Own: variable-time mod-exp with e (public). Reject e < 3 or even. |
| Finite-field DH (group1/14/16/18, GEX) | own | own | own | CNG DH tops out at 4096 bits (group18 is 8192) and needs `BCRYPT_KDF_RAW_SECRET` (8.1+). Our RSA bignum already covers this. Private exponent = 2 x security strength (e.g. 512 bits for group16/18). Constant-time mod-exp. |
| ML-KEM-768 (M2) | own | own | own | FIPS 203, written from the standard (section 2.8.4). Own code is required for XP-Win11 23H2 anyway, so it is the only production path; CNG `ML-KEM` (Win11 24H2+) serves as a differential-test reference. |
| bcrypt-pbkdf | own | own | own | Blowfish (`eksblowfish` with bcrypt_hash) + SHA-512, written from the spec description. |
| PBKDF2 | own | own | own | `BCryptDeriveKeyPBKDF2` (Win7+) brings nothing here. |
| Argon2 i/d/id + BLAKE2b | own | own | own | RFC 9106. Memory comes from `VirtualAlloc`, capped (section 7.4). Runs on a worker thread. |

Runtime dispatch is implemented as a `const` vtable per primitive. `sd_crypto_init()` selects the vtables once, from
CPU features and OS capabilities. CNG probing does not trust the OS version: it opens the provider and sets the
chaining mode, and only a success enables the CNG path. Profiles can force `own` (setting `crypto_backend=own`), for
diagnostics and for tests that want to exercise the own code on modern OSes.

**RNG notes (T-05).** The published analysis of the Windows 2000 generator, which Microsoft acknowledged also applies
to XP, found per-process state in user mode with weak forward security (ePrint 2007/419); Microsoft is reported to
have fixed it in XP SP3, our floor, which is a lab verification item (section 15). The design does not depend on that
fix for long-term keys: Ed25519 signatures are deterministic and ECDSA nonces are RFC 6979 hedged, so a repeated or
predictable RNG output cannot leak a private key through a signature. Ephemeral KEX keys and padding do depend on the
RNG. We therefore (a) draw every ephemeral KEX secret, ML-KEM seed and hedging input directly from the OS RNG at the
moment it is used, never from the per-connection padding buffer or any other pre-filled buffer; (b) refill the padding buffer only from the OS RNG; (c) keep no RNG state of our own that
could be duplicated. The residual case, restoring a snapshot of a running VM so that a process repeats RNG output, is
documented in the admin guide (00 §4 "User documentation"); it is not detectable from inside the process.

### 2.3 CPU feature detection

| Arch | Feature | Detection |
|------|---------|-----------|
| x86 `x86-ia32` build | none | **No runtime detection and no vector code at all.** The build is `/arch:IA32` for Pentium Pro/III/Athlon XP class CPUs without SSE2 (decisions.md D4); every primitive uses its portable scalar path, and no translation unit with SSE/AES-NI/SHA-NI intrinsics is linked. |
| x86 `x86-sse2` build, x64 | SSE2 | baseline of the build (`/arch:SSE2`; architectural on x64), not detected. The setup stub only installs `x86-sse2` when `PF_XMMI64_INSTRUCTIONS_AVAILABLE` is present. |
| x86 `x86-sse2` build, x64 | SSSE3, AES-NI, PCLMULQDQ | CPUID.1:ECX bits 9, 25, 1 |
| x86 `x86-sse2` build, x64 | SHA-NI | CPUID.(7,0):EBX bit 29 |
| x86 `x86-sse2` build, x64 | AVX2 | CPUID.1:ECX.OSXSAVE (bit 27) and `_xgetbv(0) & 6 == 6`, then CPUID.(7,0):EBX bit 5. On XP the XGETBV check fails, so AVX2 stays off, which is correct because XP does not save YMM state. |
| ARM64 | NEON | always present |
| ARM64 | AES/PMULL/SHA1/SHA256 | `IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE /*30*/)`. There is no PF flag for SHA-512, so it stays scalar (same as PuTTY). |
| ARM32 | NEON | always present on Windows RT / IoT ARM32. No crypto extensions are assumed. |

The `x86-sse2` and x64 builds use `__cpuid`/`_xgetbv` intrinsics, available in the v141_xp toolset. Intrinsic code
for AES-NI/SHA-NI/AVX2 lives in separate translation units, so baseline code never contains newer instructions; MSVC
compiles intrinsics without arch switches. Those translation units are excluded from the `x86-ia32` build by CMake
(not by `#ifdef` on the target), and the import/disassembly check of the IA32 build fails if any SSE/SSE2 instruction
appears in `sd_crypto`. Scalar code must therefore never assume SSE2, and no crypto code uses floating point. On the
32-bit targets (`x86-ia32`, `x86-sse2`, ARM32), constant-time code does its 64-bit arithmetic only through our own
primitives in `sd_ct64.h` and never through the compiler's runtime helpers (rule 2.4.3, TM-R02); code that handles
only public data may use ordinary 64-bit C arithmetic.

The setup stub's `sd_stubcore` (SHA-256/512 and Ed25519 verify, review C35) is built from the same sources as the
`x86-ia32` flavour of `sd_crypto`, so there is a single IA32 code path to test.

AES ordering in the cipher list (section 4.3) depends on the result: with hardware AES, `aes256-gcm` is ranked above
`chacha20-poly1305`; otherwise ChaCha20 comes first (always ChaCha20 first in `x86-ia32`).

### 2.4 Constant-time rules (normative for all own code that handles secrets)

1. No branch, loop bound or memory index may depend on secret data. This covers private scalars and exponents, key
   bytes, plaintext before MAC verification, padding bytes, and MAC/tag comparison.
2. Selections use mask arithmetic (`sd_ct_select_u32/u64`, `sd_ct_cswap`). The mask goes through a value barrier
   (inline `volatile` read or an empty `__asm` on x86 MSVC) so MSVC cannot turn it into `cmov`-less branches.
   Reviewers check the disassembly of `ct_*` helpers on all four architectures (CI keeps a `dumpbin /disasm` snapshot).
3. **Multiplication, shifts, division and comparisons on 32-bit targets (TM-R02, T-03).** The earlier assumption
   that MSVC's `_allmul` is constant time is withdrawn: the MSVC helper for 64-bit multiplication on 32-bit x86 takes
   a shortcut when the high words are zero or all ones (BearSSL constant-time multiplication survey). Rules for
   every function that touches secrets on `x86-ia32`, `x86-sse2` and ARM32:
   - Products are built only from 32x32->64 multiplications: `__emulu` on x86, `_arm_umull` (or a 32-bit by 32-bit
     `(uint64_t)` product that the compiler emits as a single `UMULL`, which the disassembly check confirms) on
     ARM32. A 64x64 product is assembled from 32x32 pieces in our own `sd_ct64.h` primitives (`sd_mul64_lo`,
     `sd_mul64_wide`); writing `uint64_t * uint64_t` in constant-time code is forbidden on these targets.
   - Shifts of 64-bit values: shifts by a compile-time constant (which the compiler inlines as `SHLD`/`SHRD` or
     `LSL`/`ORR` sequences) are allowed; shifts by a run-time count use our own `sd_shl64_pub`/`sd_shr64_pub`, whose
     count must be public; shifts by a secret count are forbidden (rule 1).
   - No division or modulo on secrets at all; reductions use multiply-and-shift or Barrett/Montgomery code.
   - 64-bit comparisons in constant-time code use the `sd_ct_*` mask functions (borrow of a subtraction), never
     `<`, `==` or `!= 0` on `uint64_t`, which MSVC compiles into branches on 32-bit targets.
   - **No call to any compiler runtime helper** from constant-time code: none of `_allmul`, `_alldiv`, `_aulldiv`,
     `_allrem`, `_aullrem`, `_alldvrm`, `_aulldvrm`, `_allshl`, `_allshr`, `_aullshr` (x86), nor the `__rt_*`
     division and shift helpers (ARM32). This is stricter than TM-R02's minimum (which tolerates helper shifts by
     public counts) so that the disassembly check can be a simple "no helper call" rule.
   - 32x32->64 `MUL` is constant time on the P6 family (Pentium Pro to Pentium III) and AMD K7, the `x86-ia32`
     floor, and on every SSE2-class x86 CPU; `UMULL` timing on the Cortex-A cores of Windows ARM32 devices is
     confirmed by dudect on the ARM32 lab device **[verify]**.
   On x64, `_umul128`/`__umulh` are used; on ARM64, `__umulh` and 64-bit `MUL`, which are constant time on the
   supported CPUs.
4. No table lookups indexed by secrets. AES without HW is bitsliced; DES uses the constant-time variant. S-box tables
   are allowed only in non-secret contexts.
5. Decoding of secret values (base64 of private keys, hex) is constant time with respect to the data. Lengths are
   public.
6. Big-number code distinguishes `ct` (fixed limb count, fixed iteration count) from `vt` (public inputs only) APIs by
   name, and the type system keeps them apart (`sd_bn_ct_*` vs `sd_bn_vt_*`).
7. Tag/MAC checks use `sd_ct_memeq`. Decryption output is not released to callers before verification (AEAD and ETM).
8. Secrets are zeroized on free (`sd_secure_zero` = `SecureZeroMemory`-equivalent volatile loop, so it does not depend
   on the CRT). **Stack hygiene (TM-R30, T-57):** functions that hold secrets in locals (key schedules, KDF and hash
   state over secrets, expanded private scalars, password and passphrase copies, prompt answers being forwarded)
   wipe those locals with `sd_secure_zero` before every return, including error paths; large secret state lives in
   `sd_secbuf`, not on the stack. SSH I/O threads and KDF work items mark themselves with `sd_dump_mark_sensitive()`
   (the `sd_platform` secret-thread registry; I/O threads for their lifetime, pool threads for the duration of the
   work item), so the crash handler
   of 03 §10.4 can leave their stacks out of minidumps (section 12.1).
9. Validation: a dudect-style statistical test (Welch t-test over 10^6-10^7 runs, two input classes) runs in nightly CI
   on x64, ARM64, `x86-sse2` and `x86-ia32` builds (ARM32 on the lab device) for X25519, Ed25519 sign, ECDSA sign,
   ECDH, RSA private ops, DH, ML-KEM decapsulation, AES bitsliced, GHASH, Poly1305 and MAC compare (section 2.7.5).
   On 32-bit flavours the input classes include operands whose high words are zero or all ones (TST-03).

### 2.5 Code provenance policy (D13, decisions.md D1)

**Rule: zero third-party code, crypto included.** Nothing in `sd_crypto`, `sd_ssh` or `sd_sftp` is vendored, copied,
translated line by line or generated by a third-party tool (this rules out, for example, fiat-crypto output,
Monocypher, BearSSL, TweetNaCl, ref10, PQClean/mlkem-native and the BLAKE2/Argon2 reference code). Requirements
amendment A6 is replaced by "no exception".

What may be used:
- **Specifications and papers may be read:** RFCs, FIPS/NIST publications, IETF drafts, OpenSSH `PROTOCOL*`
  documents, the PuTTY manual's PPK and Pageant appendices, and academic papers describing algorithms, formulas
  and constant-time techniques. Designs taken from papers are cited in a comment at the top of the file.
- **Behavioural knowledge** (quirk lists, interop observations) is allowed; code is not.
- **Test-only data:** Wycheproof vectors (Apache-2.0), RFC vectors and NIST CAVP/ACVP vectors are data in
  `tests/vectors/`, never code.
- **Test peers:** OpenSSH and other servers as interop fixtures, and `ssh-keygen`/`puttygen`/`openssl` to generate key
  fixtures. They run in CI or the lab only and never ship (decisions.md D21).
- **CNG** as a production backend where section 2.2 says so, and as a differential-test reference.

OpenSSL, LibreSSL, libsodium, libssh, libssh2 and OpenSSH source are never ported. bcrypt-pbkdf and Blowfish are
written from the algorithm descriptions (about 150 lines on top of Blowfish).

The cost of this rule is that every primitive, including all field and big-number arithmetic, is first-party code.
Section 2.8 designs that arithmetic, and section 2.7 defines how it is verified.

### 2.6 Public API sketch (`sd_crypto.h`, internal to the core modules)

```c
/* Capabilities, computed once. */
enum {
  SD_CPU_SSE2 = 1u<<0, SD_CPU_SSSE3 = 1u<<1, SD_CPU_AESNI = 1u<<2, SD_CPU_PCLMUL = 1u<<3,
  SD_CPU_SHANI = 1u<<4, SD_CPU_AVX2 = 1u<<5, SD_CPU_NEON = 1u<<6, SD_CPU_ARMV8_CRYPTO = 1u<<7
};
enum {
  SD_OS_CNG = 1u<<0, SD_OS_CNG_GCM = 1u<<1, SD_OS_CNG_RAW_SECRET = 1u<<2, SD_OS_CNG_MLKEM = 1u<<3
};
typedef struct sd_crypto_caps { uint32_t cpu, os; } sd_crypto_caps;

sd_err sd_crypto_init(uint32_t flags);          /* idempotent, thread-safe (interlocked once; no InitOnce on XP) */
const sd_crypto_caps *sd_crypto_caps_get(void);
sd_err sd_random(void *buf, size_t len);        /* fails only if the OS RNG fails */

/* Hash / HMAC: fixed-size contexts, no allocation. */
typedef enum sd_hash_alg { SD_HASH_MD5, SD_HASH_SHA1, SD_HASH_SHA256, SD_HASH_SHA384, SD_HASH_SHA512 } sd_hash_alg;
typedef struct sd_hash_ctx { sd_hash_alg alg; uint64_t opaque[28]; } sd_hash_ctx;
void   sd_hash_init(sd_hash_ctx *c, sd_hash_alg alg);
void   sd_hash_update(sd_hash_ctx *c, const void *p, size_t n);
void   sd_hash_final(sd_hash_ctx *c, uint8_t *out);           /* zeroizes c */
size_t sd_hash_len(sd_hash_alg alg);
typedef struct sd_hmac_ctx { sd_hash_ctx inner, outer; } sd_hmac_ctx;
void   sd_hmac_init(sd_hmac_ctx *c, sd_hash_alg alg, const void *key, size_t klen);
void   sd_hmac_update(sd_hmac_ctx *c, const void *p, size_t n);
void   sd_hmac_final(sd_hmac_ctx *c, uint8_t *out);
void   sd_hmac_reset(sd_hmac_ctx *c);                          /* reuse same key (per packet) */

/* SSH packet protection: one object per direction, created by sd_ssh after NEWKEYS. */
typedef struct sd_pktcipher sd_pktcipher;
typedef struct sd_pktcipher_info {
  const char *ssh_name; uint8_t key_len, iv_len, block_len, tag_len;
  uint32_t flags;      /* SD_PC_AEAD, SD_PC_LEN_ENCRYPTED (chacha), SD_PC_LEGACY, SD_PC_CBC */
} sd_pktcipher_info;
const sd_pktcipher_info *sd_pktcipher_find(const char *ssh_name);
sd_err sd_pktcipher_new(const sd_pktcipher_info *i, int encrypt, const uint8_t *key, const uint8_t *iv,
                        sd_pktcipher **out);
/* Non-AEAD: in-place encrypt/decrypt of whole blocks. */
sd_err sd_pktcipher_crypt(sd_pktcipher *c, uint8_t *buf, size_t len);
/* AEAD (GCM, chacha): seal/open a full packet (len field + payload) in place; seq = SSH sequence number. */
sd_err sd_pktcipher_seal(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, uint8_t *tag);
sd_err sd_pktcipher_open(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, const uint8_t *tag);
/* chacha only: decrypt the 4-byte length without authenticating it (as specified by OpenSSH). */
sd_err sd_pktcipher_peek_len(sd_pktcipher *c, uint32_t seq, const uint8_t enc_len[4], uint32_t *len);
void   sd_pktcipher_free(sd_pktcipher *c);                     /* zeroizes */

/* Generic block cipher (key files): AES-CBC/CTR, 3DES-CBC, Blowfish-ECB (bcrypt only). */
sd_err sd_cipher_oneshot(const char *ssh_or_pem_name, int encrypt, const uint8_t *key, const uint8_t *iv,
                         uint8_t *buf, size_t len);

/* Asymmetric primitives on raw encodings; SSH wire encoding is done in sd_ssh. */
sd_err sd_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);  /* rejects all-zero out */
sd_err sd_x25519_base(uint8_t pub[32], const uint8_t scalar[32]);
sd_err sd_ed25519_pub_from_seed(uint8_t pub[32], const uint8_t seed[32]);
sd_err sd_ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t pub[32], const void *m, size_t n);
sd_err sd_ed25519_verify(const uint8_t sig[64], const uint8_t pub[32], const void *m, size_t n);

typedef enum sd_curve { SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521 } sd_curve;
typedef struct sd_ec_key sd_ec_key;   /* may wrap a CNG BCRYPT_KEY_HANDLE */
sd_err sd_ec_generate(sd_curve c, sd_ec_key **out);
sd_err sd_ec_import(sd_curve c, const uint8_t *pub_uncompressed, size_t publen,
                    const uint8_t *priv, size_t privlen /* 0 = public only */, sd_ec_key **out);
sd_err sd_ec_export_pub(const sd_ec_key *k, uint8_t *out, size_t *len);        /* 04||X||Y */
sd_err sd_ecdh(const sd_ec_key *mine, const uint8_t *peer_pub, size_t len, uint8_t *secret_x, size_t *slen);
sd_err sd_ecdsa_sign(const sd_ec_key *k, const uint8_t *digest, size_t dlen, uint8_t *r, uint8_t *s); /* fixed width */
sd_err sd_ecdsa_verify(const sd_ec_key *k, const uint8_t *digest, size_t dlen,
                       const uint8_t *r, size_t rlen, const uint8_t *s, size_t slen);
void   sd_ec_free(sd_ec_key *k);

typedef struct sd_rsa_key sd_rsa_key; /* n,e[,d,p,q,dp,dq,qinv]; may wrap CNG */
sd_err sd_rsa_import(const sd_rsa_import_params *p, sd_rsa_key **out); /* big-endian components */
sd_err sd_rsa_pkcs1_sign(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest, uint8_t *sig, size_t *siglen);
sd_err sd_rsa_pkcs1_verify(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest,
                           const uint8_t *sig, size_t siglen);
uint32_t sd_rsa_bits(const sd_rsa_key *k);
void   sd_rsa_free(sd_rsa_key *k);

/* Finite-field DH over a given group (well-known or GEX-supplied). */
typedef struct sd_dh sd_dh;
sd_err sd_dh_new(const uint8_t *p, size_t plen, const uint8_t *g, size_t glen, uint32_t priv_bits, sd_dh **out);
sd_err sd_dh_public(sd_dh *d, uint8_t *e, size_t *elen);
sd_err sd_dh_compute(sd_dh *d, const uint8_t *f, size_t flen, uint8_t *k, size_t *klen); /* checks 1 < f < p-1 */
void   sd_dh_free(sd_dh *d);
const uint8_t *sd_dh_group_modp(int rfc3526_id, size_t *plen); /* 2 (group1, RFC 2409), 14, 16, 18 */

/* KDFs. All may take long: never call them on an I/O thread. */
sd_err sd_bcrypt_pbkdf(const void *pass, size_t plen, const uint8_t *salt, size_t slen, uint32_t rounds,
                       uint8_t *out, size_t outlen);
sd_err sd_pbkdf2_hmac(sd_hash_alg h, const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                      uint32_t iters, uint8_t *out, size_t outlen);
typedef enum sd_argon2_type { SD_ARGON2D = 0, SD_ARGON2I = 1, SD_ARGON2ID = 2 } sd_argon2_type;
sd_err sd_argon2(sd_argon2_type t, uint32_t mem_kib, uint32_t passes, uint32_t lanes,
                 const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                 uint8_t *out, size_t outlen, volatile LONG *cancel /* optional */);
sd_err sd_evp_bytes_to_key_md5(const void *pass, size_t plen, const uint8_t salt[8],
                               uint8_t *key, size_t klen);    /* legacy PEM, 1 iteration */

/* M2: SHA-3 / SHAKE (FIPS 202). Fixed-size context, no allocation. */
typedef struct sd_keccak_ctx { uint64_t a[25]; uint32_t rate, pos; uint8_t pad, squeezing; } sd_keccak_ctx;
void sd_sha3_256(uint8_t out[32], const void *p, size_t n);
void sd_sha3_512(uint8_t out[64], const void *p, size_t n);
void sd_shake_init(sd_keccak_ctx *c, int bits /* 128 | 256 */);
void sd_shake_absorb(sd_keccak_ctx *c, const void *p, size_t n);
void sd_shake_squeeze(sd_keccak_ctx *c, uint8_t *out, size_t n);  /* zeroize with sd_secure_zero when done */

/* M2: ML-KEM-768 (FIPS 203). The client needs keypair + decaps; encaps exists for the test-only mock server,
   the KAT harness and differential tests. Decaps uses implicit rejection and never reports a decryption failure. */
sd_err sd_mlkem768_keypair(uint8_t pk[1184], uint8_t sk[2400]);
sd_err sd_mlkem768_encaps(uint8_t ct[1088], uint8_t ss[32], const uint8_t pk[1184]); /* checks pk modulus */
sd_err sd_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400]);
```

All functions are reentrant. Objects are not shared between threads without external locking; each connection owns
its keys and cipher objects.

### 2.7 Verification strategy (compensates for D13)

Because no verified third-party arithmetic is used, correctness and constant-time behaviour rest on six layers.
None of them is optional for a primitive to ship; the CI job `crypto-verify` reports which layers each primitive
has passed.

#### 2.7.1 Known-answer vectors (every PR, every build flavour)

| Primitive | Vectors |
|-----------|---------|
| SHA-1/2, HMAC | FIPS 180-4 examples, NIST CAVP SHAVS (short/long/Monte), RFC 2202, RFC 4231; MD5: RFC 1321 |
| AES modes | FIPS 197, SP 800-38A (CBC, CTR), GCM spec vectors + Wycheproof `aes_gcm_test.json`, `aes_cbc_pkcs5_test.json` (no padding variant) |
| 3DES | NIST SP 800-67 / CAVP TDES MMT |
| ChaCha20 / Poly1305 | RFC 8439 sections 2.x, Wycheproof `chacha20_poly1305_test.json` (primitive level); OpenSSH construction: vectors produced by our harness and cross-checked against an OpenSSH peer in interop tests |
| X25519 | RFC 7748 (incl. 1 / 1000 iterations), Wycheproof `x25519_test.json` (low-order points -> must fail) |
| Ed25519 | RFC 8032 section 7.1, Wycheproof `ed25519_test.json` (malleability, non-canonical) |
| ECDSA / ECDH | NIST CAVP SigGen/SigVer/KAS-ECC-CDH, Wycheproof `ecdsa_secp{256,384,521}r1_sha{256,384,512}_test.json` (we accept P1363 r\|\|s after SSH decoding), `ecdh_secp*_test.json`; RFC 6979 A.2.5-7 |
| RSA | Wycheproof `rsa_signature_*`, `rsa_pkcs1_*_test.json`; NIST CAVP SigGen15/SigVer15 |
| DH | RFC 3526/2409 groups (hash-checked constants), self-consistency, invalid public values (0, 1, p-1, p) |
| bcrypt-pbkdf | vectors produced by ssh-keygen-generated key files in `tests/fixtures/keys` + published bcrypt_pbkdf test vectors |
| PBKDF2 | RFC 6070 (SHA-1), RFC 7914 section 11 (PBKDF2-HMAC-SHA256) |
| Argon2 / BLAKE2b | RFC 9106 section 5, RFC 7693 Appendix A, BLAKE2 KAT files |
| SHA-3 / SHAKE (M2) | FIPS 202 examples, NIST CAVP SHA3VS/SHAKEVS (short, long, Monte, variable output) |
| ML-KEM (M2) | FIPS 203 ACVP keyGen/encapDecap vectors, Wycheproof ML-KEM where available, including modulus-check failures and implicit-rejection cases |
| KEX end-to-end | RFC 8731 example, `mlkem768x25519-sha256` transcripts, transcripts captured from OpenSSH `-vvv` sessions with fixed test keys |
| Key files | fixtures generated by ssh-keygen (all types, all ciphers, rounds 1/16/64), puttygen (ppk v2, v3 Argon2id/i/d, none/aes256-cbc), openssl (PKCS#1, SEC1, PKCS#8 PBES2 variants, legacy DEK-Info) |

KATs run on every build flavour (`x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, ARM32, ARM64) and, where the CPU has
them, with each fast path forced on and off, so the scalar path is always covered.

#### 2.7.2 Wycheproof

All applicable Wycheproof suites (X25519 incl. low-order and twist points, Ed25519 malleability, ECDSA/ECDH
P-256/384/521 incl. invalid points and edge-case scalars, RSA PKCS#1 v1.5, AES-GCM/CBC, ChaCha20-Poly1305 primitive
level, ML-KEM) run on every PR. A Wycheproof test that is skipped needs a written reason in the test file.

#### 2.7.3 Differential testing against CNG (CI, Win10/11 runners; Vista/7/8.1 in the lab)

Own vs CNG on random and edge-case inputs, 10^5 iterations per primitive per run, 10^7 nightly: SHA-1/2 and HMAC
(decisions.md D2), AES-ECB/CBC/CTR/GCM, 3DES, ECDH and ECDSA P-256/384/521 (sign with ours, verify with CNG and vice
versa), RSA PKCS#1 v1.5 up to 16384 bits, DH up to 4096 bits, X25519 (`BCRYPT_KDF_RAW_SECRET`, Win10+) and ML-KEM
(Win11 24H2+ runners or lab). The `crypto_backend=own` switch lets the whole interop suite run twice.

#### 2.7.4 Arithmetic cross-checks (independent reference)

- A deliberately simple, slow, test-only big-integer implementation (`tests/unit/sd_crypto/refbn.c`, byte-array
  schoolbook multiplication and long division, written separately from section 2.8 and with a different
  representation) checks every field and bignum operation: random inputs plus edge values (0, 1, p-1, p, p+1,
  2^k-1 at every limb boundary, values that maximize every carry chain).
- Debug and test builds compile limb-bound assertions: every field function documents its input and output limb
  bounds in a comment, and the assertion build checks them on each call.
- Group-law properties are tested on random points: `[a]([b]P) == [ab]P`, `[n]P == O`, complete formulas give the
  same results as textbook affine formulas, ladder results equal double-and-add results.
- Fuzz-differential targets (`fuzz_field25519`, `fuzz_fieldp`, `fuzz_bn_modexp`) feed libFuzzer bytes into our
  arithmetic and into `refbn` and assert equality.

#### 2.7.5 Constant-time checks

- dudect-style Welch t-tests (rule 2.4.9) nightly on x64, ARM64, `x86-sse2` and `x86-ia32` (the IA32 build runs on
  the x64 runners).
- A disassembly check (`dumpbin /disasm` of the release objects, all flavours) asserts that no conditional branch,
  no `div`/`idiv`/`sdiv`/`udiv` and no secret-indexed memory operand appears in functions named `*_ct_*`, in the
  field and scalar arithmetic, in the Montgomery ladder, in `sd_bn_ct_*`, in the bitsliced AES/DES, GHASH,
  Poly1305 and Keccak code and in ML-KEM decapsulation. **Since TM-R02 it also follows calls:** on `x86-ia32`,
  `x86-sse2` and ARM32 it fails on any call from those functions to a compiler runtime helper (the `_all*`/`_aull*`
  list of rule 2.4.3, `__rt_*` on ARM32) or to any function outside an allow-list of our own constant-time
  primitives (`sd_ct64.h`, `sd_ct_*`), and it fails if a 64x64 multiply sequence appears where rule 2.4.3 requires
  32x32 pieces. The check is part of the M0 gate (TST-03) and runs as `tools/sd-ctcheck` in the `build` job of
  04 §11.2. The snapshot is kept in CI and diffs are reviewed.
- Every compiler or toolset change (v141_xp, v143) reruns both checks before it is merged.

#### 2.7.6 Interop and external review

- Interop against real servers (section 12.3), including OpenSSH 10 with `mlkem768x25519-sha256`.
- Every change to `src/sd_crypto/` needs two reviewers.
- An **external cryptographic review in two passes** (decisions.md D38, replacing the single M6 review; T-04),
  budgeted:
  - **Pass 1, at the end of M2**, covers everything of this module that exists then: all of `sd_crypto` (section
    2.8 arithmetic, the `sd_ct64.h`/`sd_ct_*` helpers and rule 2.4 compliance on every flavour, ML-KEM, the RSA/DH
    bignum, the key-file KDFs, packet protection, the RNG use of section 2.2) and all of `sd_ssh` that handles
    secrets or trust (KEX and the TM-R01 list construction, host-key verification and the TM-R04 restriction,
    userauth, agent clients, the reconnect cache). Findings rated high or critical are fixed before any build leaves
    the named testers; **no public beta is published before pass 1 is complete** and its blocking findings are
    closed (release gating is 04's, together with TM-R38).
  - **Pass 2, before 1.0** (M6), covers every change to those areas since pass 1, the fast paths added later
    (AES-NI, SHA-NI, AVX2, NEON, ARMv8 crypto), the ARM32/ARM64 paths and the open findings of pass 1. Findings block
    the 1.0 release until resolved or explicitly accepted (TST-33).

### 2.8 Own field, group and big-number arithmetic (D13)

All arithmetic is written from the papers and standards cited in each file. Limb sizes depend on the target: 32-bit
limbs with 64-bit products (`__emulu` / `_arm_umull` through `sd_ct64.h`, rule 2.4.3) on `x86-ia32`, `x86-sse2`
and ARM32; 64-bit limbs with 128-bit products
(`_umul128`/`__umulh` on x64, `__umulh` on ARM64) on 64-bit targets. Both variants share the API and are both built
and tested on x64 runners (the 32-bit variant in a test configuration). No variable-length arrays: every limb
count is a compile-time constant per field or a fixed maximum for the bignum.

#### 2.8.1 GF(2^255-19) (X25519, Ed25519)

- Representation: unsaturated limbs, radix 2^25.5 (10 limbs alternating 26/25 bits) on 32-bit targets, radix 2^51
  (5 limbs) on 64-bit targets. Additions are lazy within documented bounds; multiplication and squaring fold the
  high half with the factor 19 and finish with one carry chain.
- Inversion: Fermat (x^(p-2)) with a fixed addition chain. Square root for point decoding: x^((p+3)/8) plus the
  sqrt(-1) correction, as specified in RFC 8032.
- Canonical encoding: a final constant-time "freeze" (conditional subtraction of p by mask). Decoding of
  public values rejects non-canonical encodings where RFC 8032 requires it, and masks bit 255 for X25519 (RFC 7748).
- X25519: RFC 7748 Montgomery ladder over 255 fixed iterations with mask-based conditional swaps, scalar clamping,
  rejection of an all-zero result.
- Ed25519: extended twisted Edwards coordinates with the Hisil-Wong-Carter-Dawson formulas. Fixed-base
  multiplication for signing uses a precomputed table of multiples of the base point with signed radix-16 digits;
  **every table lookup scans the whole row with masks**. Verification uses a variable-time double-scalar
  multiplication (public inputs). Scalars mod L: constant-time Barrett reduction of the 512-bit hash, schoolbook
  multiply-add for S.

#### 2.8.2 NIST P-256 / P-384 / P-521 (ECDH, ECDSA)

- **Field arithmetic** (M7): a fixed limb count per curve. Per curve and limb size, chosen at compile time, the field
  uses either the NIST reduction (normal form: schoolbook product, then FIPS 186-4 D.2 folds for P-256 and P-384 or
  the Mersenne-type fold 2^521 = 1 for P-521, run on 32-bit words so both limb sizes share the code) or the
  Montgomery CIOS path (`sd_mp_montmul`). Measured selection: P-521 NIST, P-256 and P-384 Montgomery (docs/dev/
  m7-notes.md). Signed 64-bit column sums, constant shifts and masked conditional subtractions only in the NIST
  reduction: no secret-dependent branch, index or division. Both paths are tested on every curve. The scalar field
  (group order n) stays on the Montgomery engine.
- The scalar field (group order n) uses the same engine, for ECDSA nonce inversion (Fermat) and signature
  arithmetic.
- Points: projective coordinates with the complete addition and doubling formulas of Renes-Costello-Batina for
  a = -3, so there are no exceptional cases to branch on. Scalar multiplication: fixed 4-bit (P-256/384) or 5-bit
  windows with a constant-time scan of the precomputed table and a fixed number of iterations. Verification:
  variable-time interleaved wNAF (public inputs).
- Input validation: coordinates < p, point on the curve, not the point at infinity; ECDH rejects invalid peer points
  before any secret-dependent work.

#### 2.8.3 Big numbers for RSA and finite-field DH (`sd_bn`)

- Fixed-capacity numbers (up to 16384 bits: 512 32-bit or 256 64-bit limbs) with an explicit used-length that is
  public. The `sd_bn_ct_*` / `sd_bn_vt_*` naming rule (2.4.6) separates constant-time from public-input code.
- Montgomery multiplication (CIOS), constant-time modular exponentiation with a fixed 4- or 5-bit window, a
  constant-time table scan and a fixed number of squarings per window, independent of the exponent value.
- RSA private operations: CRT with base blinding and verify-after-sign. dp, dq and qinv for OpenSSH v1 and PPK
  keys are computed at import with a constant-time reduction (bit-serial shift-and-conditional-subtract over the
  public bit length) and a constant-time inversion; there is no division on secrets.
- Public operations (RSA verify with e, DH group checks, GEX range checks) use the `vt` API.

#### 2.8.4 ML-KEM-768 (FIPS 203)

- Polynomials over Z_q, q = 3329, n = 256, in 16-bit coefficients; NTT and inverse NTT with Montgomery and Barrett
  reductions in 32-bit arithmetic (no division, no secret-dependent branches).
- Sampling: SHAKE128 rejection sampling for the matrix A (public data, variable time allowed), centered binomial
  noise from SHAKE256 (constant time).
- Compression and decompression with constant-time arithmetic (multiply-and-shift, never `/` or `%` on
  coefficients).
- Decapsulation: re-encryption and constant-time comparison of the ciphertext, then a constant-time selection
  between the real shared secret and the implicit-rejection secret. The encapsulation-key modulus check and the
  decapsulation-key hash check of FIPS 203 are performed.
- The hybrid combination for SSH (section 4.2) lives in `sd_ssh`; `sd_crypto` exposes only the KEM.

---

## 3. Networking and threading model (`sd_ssh` foundation)

### 3.1 Threading decision (D1)

- **One I/O thread per connection chain.** A chain is the TCP connection to the first hop plus every nested SSH
  connection tunneled through direct-tcpip channels, plus the SFTP channels on the final hop. All protocol state of a
  chain is touched only by its I/O thread, so the state machine itself needs no locks.
- Event loop per thread: `WaitForMultipleObjects({sock_event, cmd_event}, timeout = next timer)`. `sock_event` comes
  from `WSAEventSelect(sock, ev, FD_READ|FD_WRITE|FD_CLOSE|FD_CONNECT)`. `cmd_event` is auto-reset and signaled when
  another thread pushes a command (a submitted SFTP request, prompt answer, close, ...) into the chain's MPSC queue
  (a critical section plus an intrusive list).
- Why not IOCP: a typical deployment has 1-20 mounts. Throughput is bound by crypto and per-packet work, not by
  syscall count. A single-threaded state machine per chain is much easier to get right, and the same code works on XP.
  (IOCP is available on XP, but it would add cross-thread state ownership with no gain.) If a future service mode
  needs hundreds of chains, the loop can be hosted on a small pool of threads, each serving N chains with
  `WSAEventSelect` (up to 31 chains per thread under the 64-handle limit). The state machine code does not change.
- Worker threads (via `QueueUserWorkItem(WT_EXECUTELONGFUNCTION)`, XP+) for blocking or slow work, each of which posts
  its result back as a command:
  - DNS resolution (`GetAddrInfoW`)
  - private key file loading + KDF (bcrypt-pbkdf, Argon2 up to seconds)
  - agent IPC (Pageant `SendMessage` can block indefinitely while Pageant asks for a passphrase; named pipe I/O)
  - known_hosts file I/O and lookups (review §4.1 rule 7; never on an I/O thread), including the stored-key-type
    lookup that shapes the host-key list (section 4.3, TM-R04), which starts in parallel with the TCP connect
  - system proxy discovery (WinHTTP, section 5.2), SSPI proxy-authentication token generation
  - RSA private-key operations > 4096 bits on slow CPUs (only if measured to exceed 50 ms)
- Prompt callbacks (host key, passwords) are **asynchronous** (section 6.7). The I/O thread keeps servicing keepalives
  of outer hops while a user stares at a dialog. The host's `on_prompt` implementation only enqueues to its IPC
  thread and never writes a pipe on the I/O thread (review §4.1 rule 4).
- **Connection pool (D14):** each pool member is a complete chain with its **own** I/O thread, so bulk crypto of a
  mount runs on up to four cores. Members share nothing but the session's request router, its secret cache and the
  `sd_known_hosts` object (both thread-safe). Section 10.9 has the details.
- The host-process threads around these (main/control thread, IPC thread, Dokany and WebDAV pools, vfs background
  thread, logger) follow the cross-module rules of review §4.1. The ones that bind this module are restated in
  section 10.8.

### 3.2 Winsock usage

- `WSAStartup(MAKEWORD(2,2))` once per process (refcounted in `sd_ssh_global_init`).
- Name resolution: `GetAddrInfoW` / `FreeAddrInfoW`. Microsoft documents them for XP (the sample requires XP SP2,
  `APPVER=5.02`); XP SP3 is our floor, so they are linked statically. `AI_ADDRCONFIG`, `AI_V4MAPPED` and `AI_ALL` are
  Vista+ and are only set when the OS is Vista+. `getaddrinfo` (ANSI) is never used.
- IDN: Win8+ `GetAddrInfoW` punycodes by itself. On Vista/7 we call `IdnToAscii` (normaliz.dll) first; on XP we pass
  the name unchanged and fail with `SD_E_DNS` if it is non-ASCII and unresolvable.
- IPv6 on XP works only when the user has installed the IPv6 stack (`netsh interface ipv6 install`). Otherwise
  `GetAddrInfoW` returns no AAAA results, and `socket(AF_INET6)` fails with `WSAEAFNOSUPPORT`. We skip that address.
  IPv6 literals (`[fe80::1%4]:22`) are parsed by our own parser and validated with `GetAddrInfoW(AI_NUMERICHOST)`,
  since `inet_pton` is Vista+.
- Connect: non-blocking `connect` + `FD_CONNECT`, in a simplified Happy Eyeballs (RFC 8305): addresses interleaved by
  family, the next attempt starts 250 ms after the previous one if still pending, at most 2 attempts in parallel,
  first success wins. Connect timeout default 15 s for the whole attempt, including the proxy handshake when a proxy
  is configured. With a proxy, the TCP connection goes to the proxy's addresses and the target name is resolved by
  the proxy (section 5.2).
- Socket options: `TCP_NODELAY=1`; `SO_KEEPALIVE` + `SIO_KEEPALIVE_VALS` (60 s idle, 10 s interval; XP+). On XP we set
  `SO_RCVBUF`/`SO_SNDBUF` to 512 KiB, since XP has no receive-window autotuning; on Vista+ we leave the defaults so
  autotuning stays active. Sockets are created with `WSA_FLAG_NO_HANDLE_INHERIT` when available (Win7 SP1+), otherwise
  `SetHandleInformation(HANDLE_FLAG_INHERIT, 0)`.
- Reads: up to 64 KiB per `recv` into the chain's input buffer, until `WSAEWOULDBLOCK`. Writes: `send` from the output
  ring. On `WSAEWOULDBLOCK` we wait for `FD_WRITE`. `FD_WRITE` is edge-triggered, so the loop must keep calling `send`
  until it would block.
- Time: the 64-bit monotonic tick of `sd_platform` (`GetTickCount64` through `sd_platform_resolve` on Vista+, or
  `GetTickCount` with wrap tracking on XP).
- Service context: name resolution and connects in the system service run without impersonation (global mounts are
  machine-level). User mounts run in the user's process.
- No listening sockets: `sd_ssh` only makes outbound connections (no port forwarding, D12), so the
  `SO_EXCLUSIVEADDRUSE` rule of TM-R17 (a) has nothing to apply to in this module; it binds 02's loopback listener.

### 3.3 Transport abstraction (enables ProxyJump)

```c
typedef struct sd_stream_vt {
  sd_err (*write)(void *s, const uint8_t *p, size_t n, size_t *accepted); /* never blocks */
  void   (*want_write)(void *s, int on);       /* ask for an on_writable callback */
  void   (*close)(void *s);
} sd_stream_vt;
typedef struct sd_stream_sink {                /* implemented by sd_ssh transport */
  void (*on_data)(void *ctx, const uint8_t *p, size_t n);
  void (*on_writable)(void *ctx);
  void (*on_closed)(void *ctx, sd_err why);
} sd_stream_sink;
```

There are two base implementations: the TCP socket stream, and the direct-tcpip channel stream of an outer SSH
connection. On top of either, an optional **proxy filter stream** (HTTP CONNECT or SOCKS5, section 5.2) runs its
handshake and then becomes transparent. All of them run on the same I/O thread. The SSH transport (section 4)
consumes an `sd_stream` and does not know which one it has.

---

## 4. `sd_ssh` transport layer (RFC 4253 + OpenSSH extensions)

### 4.1 State machine

```
            +--------------+   TCP/stream up     +---------------+
  start --> |  CONNECTING  | ------------------> | VERSION_XCHG  |  send "SSH-2.0-ShellDrive_<ver>\r\n"
            +--------------+                     +---------------+  read lines until "SSH-2.0-"/"SSH-1.99-"
                                                         |
                                                         v
            +-----------------------------------------------------------+
            | KEX (initial)                                             |
            |  KEXINIT_WAIT (server's KEXINIT + stored key types;       |
            |  TM-R01/R04) -> build lists -> KEXINIT_SENT/BOTH          |
            |  -> KEX_METHOD_RUNNING                                    |
            |  -> NEWKEYS_SENT/RECV -> keys active, (strict: seq=0)     |
            +-----------------------------------------------------------+
                                                         |
                                                         v
                                   [LEGACY_ACK_WAIT]  only if legacy policy = ask and
                                                         |  legacy_mask & ~SD_LEGACY_MAC_NON_ETM != 0
                                                         v
                                   SERVICE_REQUEST "ssh-userauth" -> ACCEPT
                                                         |
                                                         v
                                   USERAUTH (section 6) ---- failure ----> DISCONNECTING
                                                         | success
                                                         v
                                   CONNECTED: channels, global requests, keepalive
                                     ^          |  KEXINIT from either side, or rekey limits
                                     +-- REKEY -+  (sub-state; channel data queued, not sent)
                                                         |
                                   DISCONNECTING (send DISCONNECT, flush <= 1 s) -> CLOSED
```

Rules:

- **Version exchange:** our identification string is `SSH-2.0-ShellDrive_<major>.<minor>` (no comments). Before the
  server's identification line we accept up to 64 KiB / 1024 lines of pre-banner text, logged at debug level, and
  lines must end in CRLF or LF. The identification line may be at most 255 bytes. `SSH-1.99-` counts as SSH-2. The
  server software version (the text after `SSH-2.0-`) is saved for quirk detection (section 4.9).
- **Packets:** inbound packet_length <= 256 KiB (OpenSSH's maximum), and must be a block multiple (or a multiple of 8
  for AEAD/ETM, with the length excluded as the spec says). Padding must be 4..255 bytes. Outbound padding is random
  bytes, at least 4, plus a random extra so the total is a block multiple. Outbound packet size is bounded by the
  channel peer's max packet + 64.
- **Decryption failure handling (CBC with a non-ETM MAC):** following the Albrecht et al. countermeasure, an invalid
  length or a MAC failure makes us keep reading and discarding up to `256 KiB - already_read` bytes, then disconnect
  with `MAC_ERROR`, so the length check does not leak through timing. ETM and AEAD fail immediately.
- **Sequence numbers** are uint32 and wrap. With strict KEX, a wrap during the initial KEX is fatal. Without strict
  KEX, the transport forces a rekey before 2^31 packets.
- **Message gating:** before the first NEWKEYS only transport messages 1-4 and 20-49 are accepted. Under strict KEX,
  *any* message other than KEXINIT/KEX method/NEWKEYS/DISCONNECT is fatal, and KEXINIT must be the first message.
  Userauth messages (50-79) are accepted only in USERAUTH. Connection messages (80-127) are accepted only after
  USERAUTH_SUCCESS.
- **Legacy acknowledgement (review C21):** after the first NEWKEYS of a hop and before SERVICE_REQUEST, if the hop's
  `legacy_policy` is `ask` and any warning bit of `legacy_mask` is set, the transport raises `SD_PROMPT_LEGACY_ACK`
  (section 6.7) and holds. `ACCEPT` continues; `REJECT` or cancel disconnects with `SD_E_LEGACY_REJECTED`. Bits that
  only become known later (`USERAUTH_SHA1`, a short user RSA key) are reported through `on_negotiated` but never
  hold the connection. Policy `refuse` removes legacy algorithms from our KEXINIT, `warn` and `allow` never hold.
  The host may answer the prompt itself from the profile's `legacy_accepted` hash (03 §7.6).
- `SSH_MSG_IGNORE` and `DEBUG` are dropped (DEBUG is logged when `always_display`). Unknown message numbers get
  `SSH_MSG_UNIMPLEMENTED`. If the server sends `UNIMPLEMENTED` for our keepalive global request, that counts as
  liveness.

### 4.2 Key exchange

- **KEXINIT order (TM-R01, decisions.md D34; TM-R04).** For the initial KEX we send our KEXINIT only after the
  server's KEXINIT has arrived and the stored-key-type lookup (section 4.3) has completed. RFC 4253 allows either
  order, and servers send theirs right after the identification line (usually in the same segment), so the cost is
  at most half an RTT. Our lists are then built for this connection from the server's lists (section 4.3). If no
  server KEXINIT arrives within 3 s of the server's identification line (a server that waits for the client first),
  we send our KEXINIT with the **fallback lists**: the stored-key-type restriction applies as usual, the AES-GCM and
  AES-CTR ciphers are ranked above `chacha20-poly1305@openssh.com`, and the exposure is evaluated after negotiation
  as in section 4.3; the event is logged once (`kexinit_wait_timeout`). The wait counts against
  `connect_timeout_ms`. Rekeys send KEXINIT at once with the lists fixed at the initial KEX (strict status does not
  change within a connection).
- The server's KEXINIT, including its `kex-strict-s-v00@openssh.com` marker, is part of the exchange hash H that
  the host key signs, so an active attacker without the host key cannot strip the marker to steer our list
  construction: any change to either KEXINIT makes the signature check fail.
- We never set `first_kex_packet_follows`. If the server sets it and its guess was wrong, we discard its next KEX
  method packet (RFC 4253 section 7).
- We always offer `ext-info-c` and `kex-strict-c-v00@openssh.com`, **only in the first KEXINIT** (OpenSSH semantics).
  Strict mode is active when the server's first KEXINIT lists `kex-strict-s-v00@openssh.com`. It then:
  (a) requires KEXINIT as the server's first packet;
  (b) aborts on any non-KEX message during the initial KEX;
  (c) resets the send sequence number to 0 after sending each NEWKEYS, and the receive sequence number after receiving
  each NEWKEYS, on every KEX (initial and rekeys).
- Exchange hash and keys follow RFC 4253 section 7.2: `K1 = HASH(K || H || X || session_id)`, extended by
  `HASH(K || H || K1 || ...)`. K is encoded as an **mpint** for DH, ECDH and curve25519. RFC 8731: the 32 bytes of the
  X25519 output are read as a big-endian unsigned number. For `mlkem768x25519-sha256`, K is encoded as a **string**:
  `SHA-256(mlkem_ss || x25519_ss)`, with client init = ML-KEM pk (1184) || X25519 pk (32) and server reply =
  ciphertext (1088) || X25519 pk (32).
- `session_id` = H of the first KEX and never changes.
- Methods:
  - curve25519-sha256 / @libssh.org: reject an all-zero shared secret.
  - ecdh-sha2-nistp*: validate the peer point (on curve, not infinity, coordinates < p).
  - diffie-hellman-groupN: fixed groups from RFC 2409/3526.
  - diffie-hellman-group-exchange-*: request `min=2048, n=4096, max=8192`. If the profile allows legacy and the server
    answers with 1024..2047 bits, we accept and set `SD_LEGACY_DH_SMALL` (the default policy `warn` allows it,
    decisions.md D33; the 2048-bit floor proposed by TM-Q01 is not adopted, T-02 stays a documented residual
    risk); below 1024 we always fail. Check that p is
    odd and has the advertised size, and that `1 < g < p-1`. No primality test, which matches common clients; this is
    an accepted risk because the host key signature authenticates the group.
- The host key signature over H is verified with the negotiated host key algorithm. For RSA, `rsa-sha2-256/512` vs
  `ssh-rsa` selects the hash. The **host key verification decision** (section 7) completes before we send NEWKEYS. We
  hold the state machine (async prompt), and the server's KEX timeout (OpenSSH LoginGraceTime 120 s) is the upper
  bound. The UI is told the deadline.

### 4.3 Algorithm negotiation and ordering (D4)

Client preference lists (first match in our list wins, per RFC 4253):

```
kex:      mlkem768x25519-sha256 (from M2), curve25519-sha256, curve25519-sha256@libssh.org,
          ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521,
          diffie-hellman-group-exchange-sha256, diffie-hellman-group16-sha512,
          diffie-hellman-group18-sha512, diffie-hellman-group14-sha256,
          [legacy] diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha1, diffie-hellman-group1-sha1,
          ext-info-c, kex-strict-c-v00@openssh.com
hostkey:  ssh-ed25519-cert-v01@openssh.com, ecdsa-sha2-nistp256-cert-v01@openssh.com,
          ecdsa-sha2-nistp384-cert-v01@openssh.com, ecdsa-sha2-nistp521-cert-v01@openssh.com,
          rsa-sha2-512-cert-v01@openssh.com, rsa-sha2-256-cert-v01@openssh.com,
          ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521,
          rsa-sha2-512, rsa-sha2-256,
          [legacy] ssh-rsa-cert-v01@openssh.com, ssh-rsa
cipher:   chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com,
          aes256-ctr, aes192-ctr, aes128-ctr,
          [legacy] aes256-cbc, aes192-cbc, aes128-cbc, 3des-cbc
          (with hardware AES: the two GCM entries move above chacha20-poly1305)
mac:      hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha2-512,
          [legacy] hmac-sha1-etm@openssh.com, hmac-sha1
comp:     zlib@openssh.com, none   (zlib@openssh.com only when the profile sets connection.compression = yes; otherwise none)
```

The lists above are the static preference order. For each connection the transport derives the lists it actually
sends from them, after the server's KEXINIT (section 4.2), with the host-key and Terrapin rules below.

- **Host key list restricted to stored key types (TM-R04, T-09).** Before KEXINIT, `sd_known_hosts_stored_types()`
  (section 7.2) reports which key types are stored for `lookup_name` in any store or enabled live source, counting
  only entries that could produce `SD_HK_MATCH` (not `@revoked` lines, not wildcard-only lines from live sources,
  TM-R06), and whether a matching `@cert-authority` line exists.
  - If any plain key is stored, our host-key list contains **only** the algorithms of those key types (an `ssh-rsa`
    key maps to `rsa-sha2-512`, `rsa-sha2-256` and, as legacy and last, `ssh-rsa`), plus their
    `-cert-v01@openssh.com` variants when a matching `@cert-authority` exists, in the static order.
  - If only `@cert-authority` lines match, the list contains only the `-cert-v01@openssh.com` algorithms.
  - If nothing is stored, the full list is sent (first contact, `SD_HK_NEW`).
  A man in the middle without the host key can therefore no longer turn a known host into a TOFU-style "new key
  type" prompt by offering only an unstored type: if the server shares none of the stored types, negotiation fails
  and the connection ends with `SD_E_HOSTKEY_TYPE_UNAVAILABLE` (`host_key_type_unavailable`), which points the user
  to the host key manager instead of prompting. This applies equally to automatic reconnects (section 8) and pool
  members (section 10.9). New key types for a known host are learned only through UpdateHostKeys (section 7.5) or
  an explicit "add a key of another type" action in the host key manager (03 §5.2, §6.1 `hostkey add
  --from-server`). That action connects normally (stored types only, so the server is verified as `SD_HK_MATCH`
  against a stored key; a mismatch fails as usual) and then calls `sd_ssh_conn_fetch_hostkeys()` (section 9)
  **inside that verified connection**: keys the server announced with `hostkeys-00@openssh.com` are proven with
  `hostkeys-prove-00@openssh.com` (section 7.5, regardless of `update_host_keys`); for a requested type that was
  not announced, `sd_ssh` starts a re-key whose host-key list contains only that type, so the server signs the
  exchange hash with the new key inside the already authenticated transport. The proven keys are returned to the
  host for confirmation; nothing is stored by `sd_ssh`. A full, unrestricted host-key list is sent only when no
  key of any type is stored (`SD_HK_NEW`, plain TOFU). The host never calls it for reconnects, pool members or
  the service; the re-key variant is a lab item for servers that refuse a host-key algorithm change on re-key
  (section 15).
  **Status (M5 part 8, 2026-10-28).** Built. The host-key mount (`sd_mount`, `hostkey_fetch`, 03 §6.1) connects with
  the profile's own authentication and prompts, offers the stored types only, and calls `sd_ssh_conn_fetch_hostkeys()`
  inside that verified connection with the default type list (or `--type`). A first contact (no stored key) is not
  fetched: the presented key is taken with `ACCEPT_ONCE`, nothing is stored, and the result is that one key with
  `verified = 0`. Interop: `interop_hostkeys_fetch_none_offered` and `interop_hostkeys_fetch_first_contact_refused`
  (`test_interop.c`; they skip without a fixture state directory in the worktree, see m5-notes part 8). The re-key
  variant against a server that offers the type is still a lab item (section 15).
- Profiles can remove algorithms (for example "disable legacy") but cannot reorder legacy above modern. If the profile
  disables legacy and negotiation fails, the error says which category had no overlap, so the UI can offer to
  re-enable legacy for this profile.
- **Cipher and MAC selection after the server's KEXINIT (Terrapin, TM-R01, decisions.md D34, T-01).** Terrapin breaks
  `chacha20-poly1305@openssh.com` on every connection without strict KEX, exploits CBC with an `-etm` MAC with a
  limited success rate, and affects CTR with an `-etm` MAC only in theory (the attack fails at the application
  layer). The practical damage for us is a dropped `EXT_INFO`, which loses `server-sig-algs` (section 4.5). So:
  1. If the server's KEXINIT lists `kex-strict-s-v00@openssh.com`, strict mode is active and the static lists are
     sent unchanged (including the hardware-AES ordering).
  2. Otherwise, for each direction, the transport computes which cipher/MAC pairs the server's lists allow and
     treats chacha20-poly1305 and CBC with an `-etm` MAC as affected. If an unaffected pair exists,
     `chacha20-poly1305@openssh.com` is removed from our cipher list, which makes AES-GCM, then AES-CTR, the choice
     (first match in our list); and if the resulting cipher is CBC (legacy, only when the server offers neither GCM
     nor CTR), the `-etm` MACs are removed from our MAC list for that direction, so CBC runs with a non-ETM MAC and
     the Albrecht countermeasure of section 4.1. Legacy algorithms stay ranked last throughout (D4, TST-13).
  3. If no unaffected pair exists (the server offers only chacha20-poly1305, or only CBC together with only `-etm`
     MACs), the static lists are sent, the connection proceeds and `SD_LEGACY_TERRAPIN_EXPOSED` is set, which the UI
     shows with its own warning (decisions.md D34). With `refuse_terrapin_exposed = yes` (default `no`, 03 §3.4.1)
     the transport instead disconnects before sending KEXINIT, with `SD_E_KEX_FAILED` and the reason
     `terrapin_exposed` in the log.
  Because the decision is made before our KEXINIT is sent, there is no reconnect dance and no user action. With the
  fallback lists of section 4.2 (no server KEXINIT within 3 s), the same exposure evaluation runs on the negotiated
  result.
- **`legacy_mask`** (exposed in `sd_ssh_negotiated`, section 9):

```c
enum {
  SD_LEGACY_KEX_SHA1       = 1u<<0,  /* group1/group14-sha1/gex-sha1 */
  SD_LEGACY_DH_1024        = 1u<<1,  /* group1 */
  SD_LEGACY_DH_SMALL       = 1u<<2,  /* GEX group < 2048 */
  SD_LEGACY_CIPHER_CBC     = 1u<<3,
  SD_LEGACY_CIPHER_3DES    = 1u<<4,
  SD_LEGACY_MAC_SHA1       = 1u<<5,
  SD_LEGACY_MAC_NON_ETM    = 1u<<6,  /* informational only, not a warning by itself */
  SD_LEGACY_HOSTKEY_SHA1   = 1u<<7,  /* ssh-rsa host key signature */
  SD_LEGACY_USERAUTH_SHA1  = 1u<<8,  /* we signed with ssh-rsa */
  SD_LEGACY_RSA_SHORT      = 1u<<9,  /* any RSA key < 2048 bits (host or user) */
  SD_LEGACY_NO_STRICT_KEX  = 1u<<10, /* server lacks kex-strict-s */
  SD_LEGACY_TERRAPIN_EXPOSED = 1u<<11 /* no strict KEX AND (chacha20-poly1305 OR CBC+ETM) */
};
```

  The UI warns when any bit except `MAC_NON_ETM` is set (warning only by default, decisions.md D33).
  `TERRAPIN_EXPOSED` has its own message; since TM-R01 it is set only when the server offers no unaffected
  cipher/MAC pair (rule 3 above) or when the fallback lists negotiated an affected pair. The earlier "drop and
  reconnect once without the exposed ciphers" behaviour of `refuse_terrapin_exposed` is replaced by the pre-KEXINIT
  decision above (with the fallback lists, `refuse_terrapin_exposed` disconnects right after negotiation).

### 4.4 Rekeying

- We start a rekey when either direction has carried **1 GiB** since the last KEX, after **1 hour**, or before the
  sequence number would wrap. 3DES uses 1 GiB too (OpenSSH uses the same limit for 64-bit-block ciphers). Profile
  overrides are allowed within [16 MiB, 4 GiB] / [5 min, 24 h].
- We respond to a server KEXINIT at any time after the initial KEX.
- While a rekey is in progress, the outbound side sends only transport messages. Channel data and requests stay queued
  in per-channel queues, and window accounting continues. Inbound non-KEX messages are still processed unless strict
  rules apply, which only restrict the initial KEX.
- Host key during a rekey: it must be **identical** to the session's verified host key (same blob). A different key is
  a fatal `SD_E_HOSTKEY_MISMATCH`, as in PuTTY and OpenSSH.

### 4.5 ext-info (RFC 8308)

- Accept `SSH_MSG_EXT_INFO` (7) as the first packet after the server's first NEWKEYS, and again immediately before
  USERAUTH_SUCCESS (both are allowed by RFC 8308).
- Understood extensions:
  - `server-sig-algs`: selects the RSA user-auth signature algorithm (rsa-sha2-512 > rsa-sha2-256 > ssh-rsa).
  - `publickey-hostbound@openssh.com`: recorded, unused (only matters for agent forwarding).
  - `ping@openssh.com`: recorded, unused in v1.
  - `no-flow-control`: recorded, ignored; we always use windows.
  - `delay-compression`: n/a while we support only `none`.
- If `server-sig-algs` is absent: when the server version is OpenSSH >= 7.2 (sha2 support predates ext-info in some
  builds), try rsa-sha2-512 first; otherwise use ssh-rsa (legacy bit) first and fall back on failure. A failed RSA
  signature attempt with one algorithm is retried with the next one.

### 4.6 Keepalive and liveness

- Every `keepalive_interval` (default 15 s) **without inbound traffic**, send `SSH_MSG_GLOBAL_REQUEST
  "keepalive@openssh.com" want_reply=1`. Any reply (SUCCESS, FAILURE or UNIMPLEMENTED) resets the counter. After
  `keepalive_max_missed` (default 3) unanswered requests, the connection is declared dead with `SD_E_TIMEOUT`.
  This background detection (up to 45 s) covers idle links only.
- **Liveness probe on request timeout (D17, review C16, 02 R15):** when any SFTP request on a connection hits its
  deadline, that request completes with `SD_E_TIMEOUT` at once, and the connection sends an **immediate**
  `keepalive@openssh.com` probe (unless one is already outstanding). The connection is declared dead
  (`SD_E_TIMEOUT`, which leads to `DISCONNECTED` and the reconnect path) if **no inbound bytes at all** arrive
  within the probe window `min(5 s, max(1 s, 3 x srtt))`. Any inbound traffic, not only the probe reply, counts as
  liveness, so a slow link that is still draining megabytes of read replies is not torn down. With `sd_vfs`'s 25 s
  Dokany deadline, the timed-out request is reported at 25 s and a dead connection is known by 30 s at the latest.
- Global requests and other transport/connection-level messages are queued **ahead of channel data** in the
  connection's output scheduler, so a probe is never stuck behind a bulk write. During a rekey the probe waits for
  NEWKEYS, and the probe window starts when it is actually sent.
- Each hop of a chain runs its own keepalive. A dead inner hop does not imply a dead outer hop, which allows partial
  reconnect (section 8).
- TCP keepalive (section 3.2) is a second line of defense for idle links behind NAT.
- RTT estimation: every keepalive/probe round trip and every meta-channel request issued while that channel had
  nothing else in flight gives an RTT sample (RFC 6298 style smoothing: `srtt`, `rttvar`). These feed the probe
  window, window growth (section 4.8) and the statistics of section 10.4.
- Inbound `keepalive@openssh.com` and other unknown global requests from the server get REQUEST_FAILURE if
  want_reply. `hostkeys-00@openssh.com` is handled as described in section 7.5.

### 4.7 Compression (D6)

v1 offers only `none`. After 1.0 (milestone M7), `zlib@openssh.com` (activated after USERAUTH_SUCCESS) are offered first when the profile sets `connection.compression = yes` (default `no`); otherwise only `none` is offered. The client list order decides (RFC 4253 7.1), so `none` ahead of `zlib@openssh.com` would never select compression: the list puts zlib first, as OpenSSH does with `Compression yes`. (M7 implemented; deviation from the earlier "none, then zlib" wording, recorded in docs/dev/m7-notes.md.) It needs our own RFC 1950/1951
inflate/deflate, roughly 1500 lines, fuzzed: inflate with a 32 KiB window, deflate with fixed/dynamic Huffman and a
modest hash-chain LZ77, Z_PARTIAL_FLUSH (sync flush) per packet, and context kept across packets. Decompressed size per
packet is capped at 256 KiB (zip-bomb guard). Plain `zlib` (pre-auth) is never offered because it adds pre-auth attack
surface.

### 4.8 Channels, flow control and multiplexing

- Channel table per connection: local ids from a free list (max 64 per connection). Each channel has state
  `OPENING -> OPEN -> (EOF_SENT|EOF_RECV)* -> CLOSE_SENT/CLOSE_RECV -> CLOSED`. A local id is reused only after both
  sides have sent CLOSE.
- Channel types used: `session` (with `subsystem "sftp"`, want_reply=1), `direct-tcpip` (host, port,
  originator `127.0.0.1`, port 0) for ProxyJump and for proxies behind a jump hop, and, only when a profile sets
  `identity_probe = exec` (decisions.md D10), one short-lived `session` channel with `exec` (section 10.3). Inbound CHANNEL_OPEN requests from the server (forwarded agent, X11,
  forwarded-tcpip) are refused with `ADMINISTRATIVELY_PROHIBITED`.
- Receive window: initial **2 MiB**, max packet **32768**. 32768 is the RFC 4254 minimum every server accepts, and
  SFTP messages bigger than that simply span several CHANNEL_DATA messages. WINDOW_ADJUST is sent when the consumer has
  freed >= half of the window. Adaptive growth (post-1.0, M7): an RTT epoch in which the peer delivered at least half
  of the window counts as window-limited (the bandwidth-delay form of "the sender stalled": consumers free data at once,
  so the allowance itself never reaches zero); two such epochs in a row double the window, up to 16 MiB per channel and
  32 MiB summed over the channels of one connection. RTT is measured as described in section 4.6; before the first
  sample it is taken as 500 ms. The window never shrinks.
- Send side: we respect the peer's window and max packet. Each channel has a send queue. The connection-level scheduler
  round-robins channels with data, sending at most one max-packet per turn, so a bulk write on one SFTP channel cannot
  starve another channel or a nested hop.
- Consumers get data through `on_data(ctx, p, n)` and **must** call `sd_ssh_channel_consumed(ch, n)` when they have
  processed it. sd_sftp consumes immediately after copying into its reassembly buffer, so windows reopen at once.
- `EXTENDED_DATA` (stderr) is logged (first 4 KiB). `exit-status` / `exit-signal` are logged. EOF/CLOSE are delivered
  to the consumer.
- Multiplexing: the meta and bulk SFTP channels (D8) and the direct-tcpip channels of nested hops share one
  connection. OpenSSH `MaxSessions` (default 10) limits session channels. If opening the bulk channel fails (for
  example `MaxSessions 1`), sd_sftp continues with one channel and serves its meta queue first (section 10.5).

### 4.9 Server quirks table

The quirks table is keyed on the server version string, plus features detected at runtime. It is applied only where
needed.

| Quirk | Detection | Effect |
|-------|-----------|--------|
| OpenSSH SFTP `SYMLINK` argument order (targetpath and linkpath swapped vs draft) | version contains `OpenSSH`, or the SFTP server announces any `@openssh.com` extension; profile override | sd_sftp swaps the arguments |
| Missing ext-info but rsa-sha2 supported | OpenSSH >= 7.2 | try rsa-sha2-512 first |
| Servers that disconnect on unknown global requests | (none known today; list maintained) | keepalive via `SSH_MSG_IGNORE` (no liveness detection; relies on TCP keepalive) |
| Short reads not at EOF | always assumed possible | sd_sftp reissues the remainder (section 10.5) |
| Windows drive-letter paths (`/C:/Users/...`) | version contains `OpenSSH_for_Windows`, or `realpath(".")` matches `/[A-Za-z]:/` | `SD_SFTP_QUIRK_WIN_DRIVE_PATHS` in `server_info.quirks` (02 R12); paths are still passed through unchanged |

---

## 5. ProxyJump with N hops, and network proxies

### 5.1 ProxyJump

- `sd_ssh_config.hops[0..n-1]`: hop 0 is reached over TCP (optionally through a proxy, section 5.2). Hop i (i >= 1) is reached through a direct-tcpip channel on
  hop i-1 to `(hops[i].host, hops[i].port)`. The last hop is the SFTP target. N <= 8.
- Every hop has its **own** user, auth configuration, algorithm preferences (defaulting to the profile's), and host
  key verification against the hostname as configured for that hop (`[host]:port` when the port is not 22). Name
  resolution of hop i >= 1 happens on hop i-1's server.
- All hops run on the chain's single I/O thread, and nested transports are `sd_stream`s (section 3.3).
- Prompts and events carry `hop_index` and the hop's host name, so the UI can say "jump host bastion.example.com asks
  for an OTP".
- Failure at hop k returns the error with `hop_index = k`. Outer hops stay up while inner hops retry.
- Reconnect (section 8) rebuilds from the **innermost hop that is still alive**. If hop 0 died, everything is rebuilt.
- Throughput note: data to the target is encrypted once per hop on our side (nested). This is accepted. CPU cost
  scales with N.
- Connection pool (D14): every pool member builds its own complete chain, re-authenticating every hop. Members are
  opened only if every hop of the primary chain authenticated non-interactively (section 10.9), so this never
  causes an extra OTP prompt on a bastion.

### 5.2 HTTP CONNECT and SOCKS5 proxies (D15, decisions.md D20)

**Scope.** A proxy can be set per profile (applies to hop 0) and per ProxyJump hop. Supported: HTTP CONNECT
(HTTP/1.1) and SOCKS5 (RFC 1928). Not supported: SOCKS4/4a, HTTPS-to-proxy (TLS to the proxy itself), and
**ProxyCommand** (it would mean spawning arbitrary commands; decided out). Both clients are our own minimal code in
`sd_ssh` (`src/sd_ssh/proxy_http.c`, `proxy_socks5.c`), implemented as a filter `sd_stream` (section 3.3) that runs a
handshake, then passes bytes through untouched. The SSH layer above still authenticates the server by its host key,
so a proxy can deny service or observe metadata (target name, timing, volume) but cannot read or alter the session.

**Placement per hop.** For hop 0 the TCP connection goes to the proxy, and the proxy is asked to connect to hop 0. For
a hop i >= 1 with a proxy, the direct-tcpip channel on hop i-1 is opened to the **proxy's** address (resolved by hop
i-1's server), and the proxy handshake runs over that channel to reach hop i. This lets a profile express "bastion,
then the corporate proxy inside the bastion's network, then the target".

**HTTP CONNECT.**
- Request: `CONNECT <host>:<port> HTTP/1.1`, `Host: <host>:<port>`, `User-Agent: ShellDrive/<ver>`, and
  `Proxy-Authorization` when authenticating. IPv6 literals in brackets, IDN names in punycode (section 3.2).
- Response: status line and headers are read with a bounded line reader (16 KiB total, 100 header lines). Any 2xx
  establishes the tunnel. Bytes after the header terminator in the same read belong to the SSH stream and are
  passed up (the server banner can arrive in the same segment). Chunked or bodied 2xx responses are a protocol
  error.
- `407`: authenticate per `Proxy-Authenticate` and the profile's allowed schemes: **Basic** (RFC 7617; credentials
  from `SD_PROMPT_PROXY_PASSWORD`, UTF-8), and optionally **Negotiate/NTLM through SSPI** (`secur32.dll`, XP+,
  resolved through `sd_platform_resolve`; `AcquireCredentialsHandleW` with the current logon credentials,
  `InitializeSecurityContextW` rounds on a worker thread). If the proxy closes the connection between rounds
  (`Connection: close`), the TCP connection is reopened for the next round. At most 3 authentication rounds. SSPI
  is restricted by the rules below (TM-R10).
- **SSPI restrictions (TM-R10, T-20, T-22).** The proxy connection is plain TCP, so whoever answers `407` (an
  on-path attacker, or a proxy found through WPAD/PAC) could otherwise collect a NetNTLMv2 response for offline
  cracking or relay. Therefore:
  - SSPI is used only towards a proxy whose host was configured explicitly: in the profile (`proxy` / `proxy.K`),
    by machine policy (`ProxyServer`, 03 §3.5), or as a static entry of the system proxy configuration. It is never
    used towards a proxy obtained through automatic detection (WPAD) or a PAC script (the resolved proxy's origin
    is `SD_PROXY_ORIGIN_DISCOVERED`) unless machine policy `AllowSystemProxySspi = 1` is set (03 §3.5, §3.8;
    passed as `sd_proxy_cfg.allow_discovered_sspi`). Without it, a `407` that offers only Negotiate/NTLM fails with
    `SD_E_PROXY_AUTH` and a log hint naming the policy.
  - `SD_PROXY_AUTH_SSPI_KERBEROS` (profile `proxy_auth = auto`) uses the Negotiate package restricted to Kerberos:
    `AcquireCredentialsHandleW("Negotiate")` with a `SEC_WINNT_AUTH_IDENTITY_EX` whose `PackageList` is `"!ntlm"`
    (current logon credentials, no explicit user). A proxy that offers only `NTLM`, or a Negotiate exchange that
    would fall back to NTLM, is not answered. NTLM (bare `NTLM` scheme or Negotiate with NTLM fallback) is used only
    with `SD_PROXY_AUTH_SSPI` (profile `proxy_auth = negotiate`).
  - The SSPI target name is `HTTP/<proxy host>` as configured, never a name taken from the proxy's reply.
  - Whether the `PackageList` restriction works through Negotiate on XP SP3 is a lab item (section 15); if it does
    not, `auto` on XP offers no SSPI at all and `negotiate` is required.
- Other status codes fail with `SD_E_PROXY` (status code and reason text in the log, sanitized).
- Basic credentials cross the network in clear text to the proxy; the host warns (`warning proxy_cleartext`,
  03 §3.8), and a profile can exclude Basic with `proxy_auth = negotiate|none`.

**SOCKS5.**
- Greeting offers `00` (no auth) and, if configured, `02` (username/password, RFC 1929). GSSAPI (`01`) is not
  offered. Username and password are at most 255 bytes each (UTF-8); the password comes from
  `SD_PROMPT_PROXY_PASSWORD`.
- `CONNECT` with ATYP `03` (domain name, the proxy resolves it; default) or, with `remote_dns = 0` or a literal
  address, ATYP `01`/`04`. An authentication failure (no acceptable method, or an RFC 1929 status other than 0) is
  `SD_E_PROXY_AUTH`; every other failure reply is `SD_E_PROXY`, with the reply code logged.

**Credentials.** Proxy passwords are requested with `SD_PROMPT_PROXY_PASSWORD` (carrying proxy host, port, user and
`may_autofill`), so the host answers from Credential Manager without UI where it can. They are cached for reconnect
under the same rules as SSH passwords (section 7.4). In the service context SSPI uses the machine account, and
proxies that need interactive credentials are unavailable to service profiles unless the password is stored.

**System proxy (opt-in source).** `sd_ssh` is the only component that resolves the system proxy (03 §3.8 only
selects `proxy = system` and passes the policy verdict down), because the resolution must be repeated on every
reconnect, which `sd_sftp` drives. The opt-in is enforced in the connect path (01 §5.2, TM-R10): the system proxy
is used only when the profile opts in (`kind = SD_PROXY_SYSTEM`) **and** policy `AllowSystemProxy` allows it —
`AllowSystemProxy = 0` refuses the opt-in with `SD_E_PROXY` at connect creation, before any resolution
(`fallback_direct` does not rescue it: the policy forbids the source, not the destination). The per-resolution
decision (use the resolved proxy / connect directly / refuse) and the SSPI verdict of the TM-R10 rules above live
in one pure function that the unit tests drive without WinHTTP. `kind = SD_PROXY_SYSTEM` resolves the proxy on a
worker thread at each connect:
WinHTTP (`winhttp.dll` through `sd_platform_resolve`) `WinHttpGetIEProxyConfigForCurrentUser` in user processes,
`WinHttpGetDefaultProxyConfiguration` (the `netsh winhttp` setting) in the service. A `socks=` entry selects SOCKS5,
otherwise the `https=` or generic entry selects HTTP CONNECT; the bypass list (including `<local>`) is honored. If the
configuration uses automatic detection or a PAC URL, `WinHttpGetProxyForUrl` is called with the synthetic URL
`https://<host>:<port>/`. Discovery failure falls back to a direct connection only when the profile says
`proxy_fallback_direct = yes` (default no). The resolved proxy is logged at info level together with its origin:
a static entry of the configuration counts as configured, a result of automatic detection or a PAC script is
marked `SD_PROXY_ORIGIN_DISCOVERED`, which disables SSPI towards it per the TM-R10 rules above. A discovered proxy
cannot read or alter the SSH session (host-key verification still applies), so the remaining exposure is metadata
and denial of service (T-22).

**Errors and timeouts.** The handshake counts against `connect_timeout_ms`. Errors carry the hop index; proxy
failures are not retried within one connect attempt, and reconnect backoff applies as usual.

---

## 6. Authentication

### 6.1 Flow

1. `SERVICE_REQUEST ssh-userauth`, then `USERAUTH_REQUEST method "none"`. This learns the allowed methods and may
   succeed outright. Any `USERAUTH_BANNER` (UTF-8, sanitized as below, max 16 KiB) is delivered to the banner
   callback.

   **Server-text sanitization (TM-R09, T-18).** Every string that comes from a server, hop or proxy and can reach a
   user (banner, kbd-interactive name, instruction and prompt texts, `DEBUG` messages, disconnect and proxy reason
   texts, SFTP `server_message`) goes through one function, `sd_text_sanitize_server()` in `sd_utf.h`: invalid UTF-8
   becomes U+FFFD; C0 controls except CR/LF/TAB, DEL and C1 controls are removed; **bidi controls** (U+202A-U+202E,
   U+2066-U+2069, U+200E, U+200F, U+061C) and **zero-width and invisible characters** (U+200B-U+200D, U+2060,
   U+FEFF, U+180E) are removed. Host names that sd_ssh puts into prompts and events (`host`, `via_host`, proxy
   host) are passed through `sd_text_sanitize_host()`, which applies the same removals and, for names that are not
   ASCII, also supplies the punycode form so the UI can show both. Rendering the hop host outside the server-text
   area is the UI's part (03 §2.5).
2. Method order, filtered by the server's "can continue" list and by the profile:
   **publickey** (section 6.2 order), then **keyboard-interactive**, then **password**. `hostbased` is not implemented
   (D12).
3. Partial success (multi-factor, e.g. `publickey,keyboard-interactive`): continue with the newly allowed methods and
   never re-try a method that already gave partial success.
4. Give up when all candidates are exhausted, when the user cancels a prompt, or after 3 failed password /
   keyboard-interactive rounds. The result is `SD_E_AUTH_FAILED` plus the list of methods the server still offered.
5. `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` (60) leads to a "new password" prompt (old + new + confirm) and
   `password` with `change=TRUE`.

### 6.2 Public key auth

- Candidate order (each candidate = key or certificate):
  1. Identities explicitly configured in the profile (files, in-memory blobs such as DPAPI-kept keys, or agent keys
     selected by fingerprint; section 9), in profile order.
     For each key, the certificate goes first (if `<file>-cert.pub` exists or the agent returns a cert), then the
     plain key.
  2. If the profile does not set `identities_only`: remaining agent keys, Pageant first, then the Windows OpenSSH
     agent, deduplicated by public blob.
  - **`identities_only` default (decisions.md D37, TM-Q07, T-15).** When a hop's profile configures at least one
    identity, the host passes `identities_only = 1` for that hop unless the profile explicitly sets
    `identities_only = no`; only the configured keys (and their certificates) are offered, and agent keys are used
    only when selected by fingerprint (`SD_ID_AGENT_KEY`). Hops without a configured identity keep offering agent
    keys. This stops every hop and server from learning all public keys held in Pageant or ssh-agent.
  - The limit is 6 attempts per connection by default (OpenSSH MaxAuthTries). With many agent keys, servers otherwise
    disconnect with "Too many authentication failures". The UI suggests `identities_only` when this happens.
- For every candidate: send the query without signature first (`PK_OK` expected), then the signed request. This avoids
  passphrase prompts and agent confirmations for keys the server would reject.
- Signed data: `string session_id || byte 50 || string user || string "ssh-connection" || string "publickey" ||
  bool TRUE || string alg || string pubkey_or_cert_blob`.
- Algorithm names: Ed25519 `ssh-ed25519`; ECDSA `ecdsa-sha2-nistpNNN`; RSA per section 4.5 selection; certificates
  use the `-cert-v01@openssh.com` names (`rsa-sha2-512-cert-v01@openssh.com`, etc.).
- File keys: loaded and decrypted on a worker thread (section 7.4). If the key is encrypted, the passphrase prompt is
  issued (async), up to 3 tries. The caller can answer from Credential Manager without showing UI (the prompt carries
  `key_fingerprint` and `key_path` for lookup).
- RSA keys < 1024 bits are rejected. 1024..2047 bits set `SD_LEGACY_RSA_SHORT`.

### 6.3 OpenSSH user certificates

- Supported: `ssh-ed25519-cert-v01@openssh.com`, `ecdsa-sha2-nistp{256,384,521}-cert-v01@openssh.com`,
  `ssh-rsa-cert-v01@openssh.com` (sent as `rsa-sha2-256/512-cert-v01@openssh.com` if the server allows).
- Client side we parse the certificate only to (a) pair it with its private key (embedded public key == key's public
  key), (b) show validity, principals and key id in the UI and logs, and (c) skip expired certificates before trying
  them. The server enforces everything else.
- Certificate parser (shared with host certs): nonce, type-specific public key, serial, type (1 = user, 2 = host),
  key id, valid principals (list), valid_after/valid_before (uint64; 0xFFFFFFFFFFFFFFFF = forever), critical options,
  extensions, reserved, signature key, signature. The signature is over everything up to and including the signature
  key.

### 6.4 Keyboard-interactive and password

- keyboard-interactive: `USERAUTH_INFO_REQUEST` gives name, instruction, and N prompts with an echo flag. That is
  turned into one async `SD_PROMPT_KBDINT` callback carrying all prompts. Zero-prompt rounds are answered immediately
  (common for "press enter"). Prompts with "OTP"-like texts are not special-cased: the UI decides whether it may
  auto-fill from Credential Manager. The prompt flag `may_autofill = (nprompts == 1 && !echo && round == 0 &&
  !hostkey_just_accepted)` hints that the stored password may be used. OTP rounds never auto-fill. All texts are
  sanitized (section 6.1).
- **No stored secrets right after a fresh host-key acceptance (TM-R05, T-10).** If the host key of any hop of this
  connection was accepted by TOFU (`ACCEPT_AND_STORE`) or `ACCEPT_ONCE` during this connection (including the
  "remove old key and reconnect" flow of 03 §5.4, which is exactly what a MITM provokes), then for every prompt raised
  after that acceptance on this connection, whatever its hop: password, new-password and kbd-interactive prompts (and
  `SD_PROMPT_PROXY_PASSWORD` prompts of legs tunneled through that hop) carry `hostkey_just_accepted = 1` and
  `may_autofill = 0`; the reconnect secret cache (section 7.4) is neither read nor written for them; and
  `sd_prompt_answer_ex` rejects answers flagged `SD_ANSWER_FROM_STORE` for those prompts with `SD_E_INVALID_PARAM`,
  so a host bug cannot send a stored secret. The UI shows the prompt with a note that this server's identity was
  just accepted (03 §2.5, §4.2). Key-file passphrase prompts are unaffected (the passphrase never leaves the
  machine, and a public-key signature is bound to the session id). The next connection, verified as `SD_HK_MATCH`
  against the now-stored key, behaves normally. Because such a connection is interactive, it never admits pool
  members (section 10.9).
- password: one prompt. All strings are UTF-8 on the wire. Responses are UTF-8, held in secret buffers, zeroized after
  sending.

### 6.5 Agent clients

Both agents speak the SSH agent protocol (draft-miller-ssh-agent): `REQUEST_IDENTITIES` (11) -> `IDENTITIES_ANSWER`
(12); `SIGN_REQUEST` (13, flags: `SSH_AGENT_RSA_SHA2_256 = 2`, `SSH_AGENT_RSA_SHA2_512 = 4`) -> `SIGN_RESPONSE` (14) or
`FAILURE` (5). Reply size is capped at 256 KiB, and replies are parsed with the bounded reader. Keys of unknown types
(e.g. `sk-ssh-ed25519@openssh.com`) are offered to the server as opaque blobs with their own algorithm name. We do not
need to understand a signature to forward it.

All agent I/O runs on worker threads. Requests time out after 120 s, because agents may wait for user confirmation.

**Agent authenticity checks (TM-R08, T-16, T-17).** Before the first request of a connection to either agent, the
client verifies that the agent runs as the right principal; a failed check means "agent unavailable" for this
connection, logged once with `warning agent_untrusted` (agent kind, owner SID found), and no request is sent. The
token and owner checks use the same helper as 03 §2.2 uses for our own pipes, `sd_pipe_verify_server()` in
`sd_platform`.

**Pageant (XP+):**
1. `hwnd = FindWindowW(L"Pageant", L"Pageant")`. No window means no Pageant. **Check (TM-R08):**
   `GetWindowThreadProcessId(hwnd)` gives the owning process; `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
   (Vista+; `PROCESS_QUERY_INFORMATION` on XP) and `OpenProcessToken(TOKEN_QUERY)` must succeed, the token user SID
   must equal ours, and on Vista+ its integrity level must be at least ours (`TokenIntegrityLevel`). A window
   registered by a lower-integrity process, by another user's process started with `runas`, or by a process we
   cannot open is refused. The check runs again whenever `FindWindowW` returns a different `hwnd`.
2. Mapping name `"PageantRequest%08x"` (current thread id, ANSI). `CreateFileMappingA(INVALID_HANDLE_VALUE, &sa,
   PAGE_READWRITE, 0, AGENT_MAX_MSGLEN, name)` with a security descriptor whose **owner is the current user SID**
   (from the process token). Pageant checks the owner, and refuses otherwise. `AGENT_MAX_MSGLEN` = 256 KiB. Old
   Pageant builds used 8 KiB and only read their limit; requests are always far below 8 KiB.
3. Write `uint32 len || message` into the view. Call `SendMessageTimeoutW(hwnd, WM_COPYDATA, 0, &cds,
   SMTO_ABORTIFHUNG, 120000, &res)` with `cds.dwData = 0x804e50ba` (AGENT_COPYDATA_ID) and `cds.lpData` = mapping
   name, NUL-terminated.
4. If the call succeeds and returns nonzero, the reply is in the view as `uint32 len || message`. Its length is
   checked against the mapping size.
- Pageant runs on the user's desktop. The **system service** (global mounts) cannot reach it (different session).
  No agent of any kind is used in the service context (decisions.md D17): the agent options are rejected for service
  profiles, and the service authenticates with its own DPAPI-protected keys passed as `SD_ID_BLOB` (section 9).

**Windows OpenSSH agent (Windows 10 1803+):**
- Pipe `\\.\pipe\openssh-ssh-agent`, or `SSH_AUTH_SOCK` if it names a `\\.\pipe\...` path.
  `CreateFileW(GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING, FILE_FLAG_OVERLAPPED)`, with
  `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` so the agent cannot impersonate us. Messages are `uint32 len ||
  body`. Overlapped I/O with a timeout. `ERROR_FILE_NOT_FOUND` / `ERROR_PIPE_BUSY` mean the agent is unavailable or
  busy (one retry after `WaitNamedPipeW(2 s)`).
- **Check (TM-R08, `sd_pipe_verify_server`):** after `CreateFileW` and before writing anything, `GetSecurityInfo(SE_KERNEL_OBJECT,
  OWNER_SECURITY_INFORMATION)` on the pipe handle must report owner `S-1-5-18` (LocalSystem, the `ssh-agent`
  service) for the default pipe name, or our own user SID when `SSH_AUTH_SOCK` names a different pipe; in addition
  `GetNamedPipeServerProcessId` gives the server process, whose token user must be SYSTEM (default pipe) or ours
  (user pipe). This defeats pipe squatting by another local user while the `ssh-agent` service is stopped (T-17).
- On XP/Vista/7 this agent is not probed.

### 6.6 Private key file parsers (in sd_ssh, `src/sd_ssh/keyfile_*.c`)

All parsers take `(bytes, len)`, never paths; file reading is done by the caller on a worker thread. All return
`sd_ssh_key` (public + private parts in secret buffers) or a precise error: `SD_E_KEY_FORMAT`,
`SD_E_KEY_UNSUPPORTED` (with the algorithm name), `SD_E_BAD_PASSPHRASE`, `SD_E_KEY_PASSPHRASE_REQUIRED`. Format
detection uses the first non-blank line.

**OpenSSH v1 (`-----BEGIN OPENSSH PRIVATE KEY-----`):**
- Base64 body. Magic `"openssh-key-v1\0"`, then `string ciphername` (`none`, `aes256-ctr` default, and any of
  `aes{128,192,256}-{ctr,cbc}`, `aes{128,256}-gcm@openssh.com`, `chacha20-poly1305@openssh.com`), then `string
  kdfname` (`none`/`bcrypt`), `string kdfoptions` (`string salt, uint32 rounds`), `uint32 nkeys` (must be 1), `string
  pubkey` x nkeys, and `string encrypted`.
- KDF: `bcrypt_pbkdf(pass, salt, rounds, key || iv)`. For AEAD ciphers the tag follows the encrypted string (OpenSSH
  format). Rounds are capped at 1024; above that we fail with `SD_E_KEY_UNSUPPORTED`.
- Decrypted: `uint32 check1 == check2` (a mismatch means `SD_E_BAD_PASSPHRASE`), then the key: type string +
  type-specific fields:
  - ed25519: `string pub(32) string priv(64 = seed||pub)`
  - ecdsa: `string curve, string Q, mpint d`
  - rsa: `mpint n, e, d, iqmp, p, q`; we compute dp and dq
  - certificates: `string cert blob` + private part
- Then `string comment`, then padding 1,2,3,... (verified).
- The embedded private key must match the public blob.

**PEM (RFC 7468 armor):**
- `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1, with named-curve OIDs for P-256/384/521 only), `PRIVATE KEY`
  (PKCS#8 unencrypted: rsaEncryption, id-ecPublicKey + curve, id-Ed25519 1.3.101.112 per RFC 8410),
  `ENCRYPTED PRIVATE KEY` (PKCS#8 PBES2).
- Legacy OpenSSL encryption headers `Proc-Type: 4,ENCRYPTED` + `DEK-Info: <ALG>,<hex IV>` for `AES-128-CBC`,
  `AES-192-CBC`, `AES-256-CBC`, `DES-EDE3-CBC`. Key = EVP_BytesToKey(MD5, salt = first 8 bytes of IV, 1 iteration).
  PKCS#7 padding is checked after decryption: a bad pad means `SD_E_BAD_PASSPHRASE`, but only if the DER parse also
  fails, to avoid a padding oracle that matters for files anyway.
- PBES2: PBKDF2 with PRF hmacWithSHA1/SHA224/SHA256/SHA384/SHA512 and iterations <= 10,000,000; encryption scheme
  aes128/192/256-CBC or des-ede3-cbc. **Not supported:** scrypt (OpenSSL `-scrypt`), PBES1 (`pbeWithMD5AndDES` and
  others), and PKCS#12 PBE. These fail with a clear `SD_E_KEY_UNSUPPORTED` message.
- DER parser: our own minimal strict DER (definite lengths only, max depth 8, integer canonical checks; BER
  indefinite lengths are rejected).
- `DSA PRIVATE KEY` gives `SD_E_KEY_UNSUPPORTED("ssh-dss")`.

**PuTTY PPK v2 and v3:**
- Line-based header:
  - `PuTTY-User-Key-File-<2|3>: <alg>`
  - `Encryption: none|aes256-cbc`
  - `Comment: ...`
  - `Public-Lines: N` + base64 (SSH public blob)
  - v3 with encryption: `Key-Derivation: Argon2id|Argon2i|Argon2d`, `Argon2-Memory: <KiB>`, `Argon2-Passes: n`,
    `Argon2-Parallelism: n`, `Argon2-Salt: <hex>`
  - `Private-Lines: N` + base64
  - `Private-MAC: <hex>`
- Header lines are limited to 256 KiB in total and each base64 section to 64 KiB. Unknown header lines are an error,
  which matches PuTTY's strictness.
- **v2:**
  - cipher key = `SHA1(00 00 00 00 || pass) || SHA1(00 00 00 01 || pass)`, first 32 bytes; IV = 16 zero bytes;
    AES-256-CBC, no padding check.
  - MAC key = `SHA1("putty-private-key-file-mac-key" || pass)`; pass is empty for unencrypted files.
  - MAC = HMAC-SHA1 over `string alg || string encryption || string comment || string public_blob ||
    string private_blob(decrypted, with padding)`.
- **v3:**
  - `Argon2(type, mem, passes, parallelism, pass, salt) -> 80 bytes` = cipher key (32) || IV (16) || MAC key (32).
  - MAC = HMAC-SHA-256 over the same fields as v2. For `Encryption: none`, the MAC key is empty and no Argon2 runs.
- The MAC is compared in constant time. A mismatch on an encrypted file means `SD_E_BAD_PASSPHRASE`, otherwise
  `SD_E_KEY_FORMAT`.
- Private blob per algorithm:
  - rsa: `mpint d, p, q, iqmp`
  - ed25519: `string priv(32)` (the seed)
  - ecdsa: `mpint d`
- Resource limits: Argon2 memory <= 1 GiB and passes <= 1000; otherwise `SD_E_KEY_UNSUPPORTED`. On x86 the allocation
  may fail with large values and then gives `SD_E_NO_MEMORY` and a clear message. Argon2 runs on the worker thread and
  can be cancelled.

**Public key files:**
- OpenSSH one-line format (`type base64 comment`).
- RFC 4716 (`---- BEGIN SSH2 PUBLIC KEY ----`, with header continuation lines).
- `*-cert.pub`.

**Helpers for the credential store (review C22).** The UI, CLI and host need to inspect and re-store keys without
decrypting them on the I/O path:

```c
typedef struct sd_ssh_key_probe_info {
  char type[48];                  /* "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", ... */
  uint32_t bits;
  int encrypted;                  /* passphrase required to use it */
  uint8_t pub_blob[1024]; size_t pub_len;
  char fp_sha256[64];             /* "SHA256:..." */
  int format;                     /* SD_KEYFMT_OPENSSH | _PEM | _PKCS8 | _PPK2 | _PPK3 */
} sd_ssh_key_probe_info;
/* No KDF runs; safe on any thread. Encrypted PEM/PKCS#8 files without a public part report pub_len = 0. */
sd_err sd_ssh_key_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);
/* Serialize a decrypted key as an unencrypted OpenSSH v1 file into a secret buffer, for DPAPI storage
   (03 identity_store). The caller protects the result; we never write it to disk. */
sd_err sd_ssh_key_serialize_openssh(const sd_ssh_key *k, sd_secbuf **out);
```

### 6.7 Prompt and callback model (UI-agnostic)

```c
typedef enum sd_prompt_kind {
  SD_PROMPT_HOSTKEY,          /* section 7 */
  SD_PROMPT_PASSWORD, SD_PROMPT_NEW_PASSWORD, SD_PROMPT_KBDINT, SD_PROMPT_KEY_PASSPHRASE,
  SD_PROMPT_LEGACY_ACK,       /* section 4.1; answered with sd_prompt_answer_ack(); carries legacy_mask + names */
  SD_PROMPT_PROXY_PASSWORD    /* section 5.2; proxy host/port/user in the info */
} sd_prompt_kind;             /* UpdateHostKeys is an event (SD_HKEV_ANNOUNCED, section 7.5), not a prompt */

typedef struct sd_prompt sd_prompt;   /* opaque, owned by sd_ssh until answered/cancelled */

typedef struct sd_prompt_item { const char *text; int echo; } sd_prompt_item;   /* UTF-8, sanitized */
typedef struct sd_auth_prompt_info {
  sd_prompt_kind kind;
  uint32_t hop_index; const char *host; const char *user;       /* UTF-8 */
  const char *name, *instruction;                               /* kbd-int; may be "" */
  const sd_prompt_item *items; uint32_t item_count;
  uint32_t round;            /* 0-based count of rounds of this kind */
  int may_autofill;          /* hint: a stored secret is plausible for this prompt; 0 if hostkey_just_accepted */
  int hostkey_just_accepted; /* TM-R05: a hop key was TOFU/once-accepted in this connection; stored secrets and the
                                reconnect cache must not answer; SD_ANSWER_FROM_STORE answers are rejected */
  int is_reconnect;          /* prompt raised during automatic reconnection */
  int is_pool_member;        /* raised by a secondary pool connection: answer from stored secrets or cancel,
                                never show UI (section 10.9) */
  const char *key_path; const char *key_fingerprint;            /* passphrase prompts */
  const char *proxy_host; uint16_t proxy_port;                  /* SD_PROMPT_PROXY_PASSWORD */
  uint32_t legacy_mask; const char *legacy_names;               /* SD_PROMPT_LEGACY_ACK: comma list, e.g. "3des-cbc" */
  uint64_t deadline_tick_ms; /* best-effort server timeout */
} sd_auth_prompt_info;

/* Answer from ANY thread, exactly once; or cancel. Responses are copied into secret buffers.
   SD_ANSWER_FROM_STORE tells sd_ssh the answer came from Credential Manager/DPAPI/the reconnect cache without user
   interaction; it is what makes an authentication "non-interactive" for the pool rule (section 10.9). It is refused
   with SD_E_INVALID_PARAM on prompts with hostkey_just_accepted = 1 (section 6.4, TM-R05). */
enum { SD_ANSWER_FROM_STORE = 1u<<0 };
sd_err sd_prompt_answer(sd_prompt *p, uint32_t n, const char *const *utf8_responses);
sd_err sd_prompt_answer_ex(sd_prompt *p, uint32_t n, const char *const *utf8_responses, uint32_t answer_flags);
sd_err sd_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d);
sd_err sd_prompt_answer_ack(sd_prompt *p, int accept);   /* LEGACY_ACK */
sd_err sd_prompt_cancel(sd_prompt *p);
```

Callbacks are invoked on the I/O thread and **must return quickly**. They may answer synchronously inside the
callback, but must not block there. The CLI reads the console on its own thread and calls `sd_prompt_answer` from
there. If a connection dies, any outstanding prompt is invalidated: answering it returns
`SD_E_CANCELLED`. The UI is also notified through a `prompt_withdrawn` callback so it can close the dialog.

---

## 7. Host key verification and `known_hosts`

### 7.1 Verification flow

After KEX method completion and signature check, sd_ssh calls `sd_known_hosts_check()` (in-process, on a worker
thread) for `(lookup_name, host_key_blob)`:

| Result | Meaning | Action |
|--------|---------|--------|
| `SD_HK_MATCH` | Exact key in one of our stores, or in a live read-only source (which is then copied into the user store) | proceed; `on_hostkey_ok` event (no prompt). The result records which store matched (needed by section 7.5) |
| `SD_HK_MATCH_CA` | Host certificate valid and signed by an `@cert-authority` for the name | proceed |
| `SD_HK_NEW` | No key of any type for this name | `SD_PROMPT_HOSTKEY` with fingerprints. Decisions: `REJECT`, `ACCEPT_ONCE`, `ACCEPT_AND_STORE` |
| `SD_HK_NEW_TYPE` | Name known, but only with other key types we did not negotiate | **fail without a prompt** with `SD_E_HOSTKEY_TYPE_UNAVAILABLE` (TM-R04, T-09). With the host-key list restricted to stored types (section 4.3) this cannot result from negotiation; it can only occur through a race with a concurrent store change, and is treated the same way. It never becomes a prompt; new types are added only through `sd_ssh_conn_fetch_hostkeys()` inside a verified connection (section 4.3) or UpdateHostKeys (section 7.5) |
| `SD_HK_MISMATCH` | A key of the same type exists and differs | **fail** with `SD_E_HOSTKEY_MISMATCH`. An informational callback carries old and new fingerprints and the file/line of the old entry. No accept path. The UI may offer a separate "remove old key" action outside the connection |
| `SD_HK_REVOKED` | Key or signing CA appears under `@revoked` | fail `SD_E_HOSTKEY_REVOKED` |

`lookup_name` = hostname as configured (lowercased ASCII; IDN in punycode form), or `[host]:port` when the port is
not 22. If the profile sets `host_key_alias`, that is used instead. IP addresses are not checked separately (OpenSSH
`CheckHostIP no` default).

Host certificate validation for `SD_HK_MATCH_CA`:
- cert type is host (2);
- `lookup_name` (without port brackets) is in the principals; an empty principal list is **rejected** (OpenSSH
  accepts it with a warning; we reject);
- `valid_after <= now < valid_before`, with 5 minutes of clock skew allowed;
- no unknown critical options;
- the signature is valid with the CA key, and the CA matches an `@cert-authority` line for a pattern that matches the
  name;
- neither the CA nor the key is `@revoked`.

If cert validation fails but the plain key embedded in the cert is known, the result is `MATCH`, as in OpenSSH.

Fingerprints shown: `SHA256:<base64 no padding>` (primary), and `MD5:xx:xx:...` (secondary, for users comparing with
old PuTTY output). Key type and bit size are shown too. For hop i >= 1 the host-key prompt also carries `via_host`,
the sanitized host name of hop i-1, so the dialog can say "reached through jump host <hop i-1>" (TM-R03, T-08,
T-19; dialog behaviour is 03 §5.2).

Answering `ACCEPT_ONCE` or `ACCEPT_AND_STORE` marks the connection as `hostkey_just_accepted` for the rest of its
lifetime (TM-R05, section 6.4).

### 7.2 known_hosts stores (D10, review C19)

`sd_known_hosts` is the **only** component that reads, writes and locks `known_hosts` files. The host, UI and CLI
use this API (the CLI and UI link it without the transport, section 1); 03's config lock is not used for these
files. Lookups and writes run on worker items, never on an I/O or Dokany thread.

```c
typedef enum sd_kh_store_kind {
  SD_KH_STORE_MACHINE,     /* %ProgramData%\LibreStatic\ShellDrive\known_hosts */
  SD_KH_STORE_USER,        /* %APPDATA%\LibreStatic\ShellDrive\known_hosts */
  SD_KH_SRC_OPENSSH,       /* live read-only source: %USERPROFILE%\.ssh\known_hosts (+ known_hosts2) */
  SD_KH_SRC_PUTTY          /* live read-only source: HKCU\...\PuTTY\SshHostKeys */
} sd_kh_store_kind;
typedef struct sd_kh_store {
  sd_kh_store_kind kind;
  const wchar_t *path;     /* files; NULL = default path for the kind */
  int writable;            /* 0 for live sources always; machine store writable only in the service/admin */
} sd_kh_store;

typedef struct sd_known_hosts sd_known_hosts;   /* thread-safe; shared by all connections in a process */
/* stores[] is ordered: lookup goes machine -> user -> live sources. @revoked in any store wins; otherwise any
   MISMATCH wins over MATCH (decisions.md D7); MATCH/MATCH_CA records the first store that matched. */
sd_err sd_known_hosts_open(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out);
sd_err sd_known_hosts_check(sd_known_hosts *kh, const char *lookup_name, const uint8_t *blob, size_t len,
                            uint64_t now_unix, sd_hk_result *res);   /* res->store = store that decided */
sd_err sd_known_hosts_add(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                          const uint8_t *blob, size_t len, const char *comment);
sd_err sd_known_hosts_remove(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const char *key_type /* NULL=all */);
sd_err sd_known_hosts_import(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_store_kind target,
                             sd_kh_import_report *rep);              /* one-shot copy (wizard, "import to machine") */
/* TM-R04: key types that could MATCH for lookup_name (no @revoked lines, no wildcard-only lines from live sources),
   plus whether a matching @cert-authority exists. Worker thread; used before KEXINIT (section 4.3). */
typedef struct sd_kh_types { uint32_t count; char type[8][48]; int has_ca; } sd_kh_types;
sd_err sd_known_hosts_stored_types(sd_known_hosts *kh, const char *lookup_name, sd_kh_types *out);
/* TM-R06: per live source, whether it is in use or skipped (and why), for the host's warnings and diagnostics. */
typedef enum { SD_KH_SRC_OK, SD_KH_SRC_ABSENT, SD_KH_SRC_DISABLED, SD_KH_SRC_INSECURE } sd_kh_src_state;
sd_err sd_known_hosts_source_state(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_src_state *state,
                                   wchar_t *detail_sid, size_t detail_cap);   /* INSECURE: a SID that may write */
void   sd_known_hosts_close(sd_known_hosts *kh);
```

- **Store list.** User processes open `{MACHINE, read-only}`, `{USER, read-write}` and the enabled live sources.
  The service opens `{MACHINE, read-write}` only. The machine file's ACL is SYSTEM + Administrators write, Users read.
- **Live read-only sources**, enabled by default (decisions.md D7): `%USERPROFILE%\.ssh\known_hosts` (and
  `known_hosts2` if present), and the PuTTY registry (current user only). On `MATCH` from a source, the entry is
  copied into the **user** store with the end-of-line comment `# imported-from=openssh added=<date>` or
  `# imported-from=putty added=<date>` (comment formats are 03 §5.1's). A `MISMATCH` in **any** store or source
  blocks (decisions.md D7): every store and enabled source is consulted, and an exact match in one store never
  overrides a mismatching key of the same type in another. `res` reports the mismatching store and line so the UI
  can offer removal (our stores) or "stop using this source" (live sources, 03 §5.4).
- **Live-source integrity (TM-R06, T-11).** A live source is read only if nobody but the user, SYSTEM and
  Administrators can change it. For `.ssh\known_hosts` (and `known_hosts2`) the file is opened with
  `FILE_FLAG_OPEN_REPARSE_POINT` (a reparse point is refused) and `GetSecurityInfo` on **the opened handle** must
  show an owner among those three and a DACL that grants `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `WRITE_DAC`,
  `WRITE_OWNER` or `DELETE` to no other SID; the `.ssh` directory gets the same check for `FILE_ADD_FILE`,
  `FILE_DELETE_CHILD`, `WRITE_DAC` and `WRITE_OWNER`, since a writable directory allows replacing the file. A
  volume without persistent ACLs (`FILE_PERSISTENT_ACLS` absent, for example FAT on a stick) fails the check. For
  the PuTTY source the same rule applies to the DACL of the `SshHostKeys` registry key (`KEY_SET_VALUE`,
  `KEY_CREATE_SUB_KEY`, `WRITE_DAC`, `WRITE_OWNER`). A source that fails is skipped entirely (it yields neither
  MATCH nor MISMATCH) and reported as `SD_KH_SRC_INSECURE`, which the host shows as `warning hostkey_source_insecure`
  (03 §5.1). The check is repeated whenever the source is reloaded.
- **Wildcard-only lines (TM-R06).** In live sources, a line whose positive host patterns consist only of `*`, `?`
  and `.` (for example `*`, `*.*`, `?*`), with or without a `[...]:port` wrapper, is ignored for MATCH and for the
  stored-type list of section 4.3; it still counts for MISMATCH and `@revoked`. Such lines in our own stores are
  honored (only an administrator or the user can write them).
- **Parsing** (each line, max 64 KiB; invalid lines are skipped, logged with file:line, and kept verbatim on rewrite):
  - optional marker `@cert-authority` | `@revoked`
  - host patterns, comma-separated: literal names; `*` and `?` wildcards; `!` negation (a negated match vetoes the
    line); `[host]:port`; hashed `|1|base64(salt20)|base64(HMAC-SHA1(key = salt, msg = lookup_name))`. A hashed entry
    is compared against `lookup_name` (and `[host]:port` form).
  - key type, base64 blob (the type inside the blob must equal the line's type), optional comment.
  - Unknown key types (e.g. `ssh-dss`, `sk-*`, `ssh-ed448`) are kept, and still count for NEW_TYPE detection.
- **Writing:** we append to the target store, and rewrite it only for `remove` and for section 7.5 updates. Each
  write goes to a temp file in the same directory, followed by `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_WRITE_THROUGH)` (XP+). Cross-process serialization uses a named mutex
  `Local\com.librestatic.shelldrive.known_hosts.<hash of path>` (`Global\` for the ProgramData file). The in-memory cache is reloaded
  when the file's last-write time changes. Entries are always written **plain** (decisions.md D8; the files are
  ACL-protected). Hashed entries from other tools are still read and matched.
- **ACLs on write (TM-R07, T-13).** Because `MoveFileExW` keeps the security descriptor of the temp file, the temp
  file is created with an explicit protected DACL in the same `CreateFileW` call: for the user store the user and
  SYSTEM only (TM-R07; the folder ACLs are 03 §3.2's), for the machine store SYSTEM and Administrators full control
  and Users read. A store file found with a DACL that lets other users write it is still read (it is ours) but logged
  as a warning and rewritten with the correct DACL on the next write.

### 7.3 PuTTY `SshHostKeys` import

Location: `HKCU\Software\SimonTatham\PuTTY\SshHostKeys`, REG_SZ values.
- **Value name:** `<keytype>@<port>:<host>`. PuTTY escapes it: each character in `' '`, `*`, `?`, `%`, `~`, control
  characters, and a leading `.`, is written as `%XX` (uppercase hex). We undo the escaping, then
  `lookup_name = (port == 22) ? host : "[host]:port"`.
- **Value data:** comma-separated fields. Numbers are lowercase hex with a `0x` prefix, big-endian magnitude.

| PuTTY keytype | Data | Conversion to SSH blob |
|---------------|------|------------------------|
| `rsa2` | `0x<e>,0x<n>` | `string "ssh-rsa" || mpint e || mpint n` |
| `ssh-ed25519` | `0x<x>,0x<y>` (affine point) | 32 bytes = y little-endian (padded to 32), bit 255 set to `x & 1`; blob `string "ssh-ed25519" || string pk32` |
| `ecdsa-sha2-nistp256/384/521` | `nistpNNN,0x<x>,0x<y>` | Q = `04 || X || Y`, each left-padded to field size (32/48/66). Blob `string type || string "nistpNNN" || string Q`. The point is validated on the curve. |
| `dss`, `rsa` (SSH-1), `ssh-ed448` | | skipped (unsupported types), counted in the import report |

Imported keys are validated (RSA n >= 1024 bits, ed25519 point decodes, EC point on curve). Malformed entries are
reported, not fatal. A host that PuTTY reached through its own proxy settings is imported under the name PuTTY stored.
The import runs in the user's context only. The service cannot see the user's HKCU, so the user app offers "import
into machine store" for administrators.

### 7.4 Key loading resource rules

- Key file size <= 1 MiB.
- Argon2 memory <= 1 GiB and passes <= 1000. bcrypt-pbkdf rounds <= 1024. PBKDF2 iterations <= 10^7.
- KDFs run on a worker thread, with a cancel flag checked between blocks.
- Decrypted private key material lives in `sd_secbuf` (heap, zeroized on free, `VirtualLock` best-effort for buffers
  >= 4 KiB). Memory hygiene limits (T-56): `VirtualLock` keeps pages out of the pagefile only while the process runs
  and does not keep them out of `hiberfil.sys`; session keys and decrypted private keys necessarily stay in plain
  process memory for the session lifetime. The admin guide therefore recommends full-disk encryption where keys are
  kept (TM-R31, owned by 03 §10 and the user documentation). Secrets on stacks follow rule 2.4.8 (TM-R30).
- **Reconnect secret cache (review C20): `sd_ssh` is its only owner.** When the profile sets
  `cache_secrets_for_reconnect`, decrypted keys, the password and proxy passwords are kept per session (shared by
  the pool members of that session) for the session lifetime. The cache is protected with
  `CryptProtectMemory(SAME_PROCESS)` on Vista+ (through `sd_platform_resolve`), and with `RtlEncryptMemory` (advapi32
  `SystemFunction040`) on XP. The host does not keep a second cache: when the cache cannot answer, it answers
  `is_reconnect` prompts from Credential Manager/DPAPI with `SD_ANSWER_FROM_STORE`. The cache is not used on a
  connection marked `hostkey_just_accepted` (TM-R05, section 6.4).

### 7.5 UpdateHostKeys (`hostkeys-00@openssh.com`, D16)

OpenSSH servers announce all their host keys after authentication with the global request
`hostkeys-00@openssh.com` (want_reply = 0, a list of public key blobs). We use it to learn rotated keys safely.

Preconditions, all required; otherwise the announcement is logged and ignored:
1. The hop's profile setting `update_host_keys` is `ask` (default for user mounts, 03 §3.4.1) or `yes`; `no`
   (the service default unless policy `UpdateHostKeys = 2`) ignores announcements.
2. The connection's host key was verified as `SD_HK_MATCH` against a key that was **already trusted before this
   connection** (machine store, user store or a live source). Not after `ACCEPT_ONCE` or a TOFU accept in this
   connection, and not `SD_HK_MATCH_CA` (certificate-verified hosts are managed through their CA).
3. The lookup name has no wildcard-only match: the trusted entry must name the host (or its `host_key_alias`)
   explicitly, so a pattern line is never extended.
4. At most one announcement per connection is processed; at most 16 keys; duplicates and unsupported key types are
   ignored. Only the primary connection of a pool processes it.

Procedure (on the I/O thread, with the `known_hosts` work on a worker item):
1. Classify the announced keys against the stores: already known, new, and known keys of this host that were **not**
   announced.
2. If there are new keys, send `hostkeys-prove-00@openssh.com` (want_reply = 1) listing exactly the new blobs. The
   reply holds one signature per key over `string "hostkeys-prove-00@openssh.com" || string session_id || string
   key_blob`. Each signature is verified with the corresponding new key (RSA: `rsa-sha2-512`/`rsa-sha2-256`;
   `ssh-rsa` only if legacy is allowed). A missing, malformed or failing signature rejects the **whole** update.
3. **`sd_ssh` never writes a store by itself** (03 §12.1). It raises `on_hostkey_event` with `SD_HKEV_ANNOUNCED`
   (not a prompt: the mount never waits for it) carrying the lookup name, the **target store** (below), the proven
   keys to add (blobs + fingerprints) and the removal candidates (keys stored for this host in the target store
   that the server no longer announces; only listed when the key that authenticated this connection is in the
   announced set). The host applies the result through `sd_known_hosts_add`/`_remove` (comment
   `# updated-by=hostkeys-00 added=<date>`): with `yes` it adds the proven keys at once; with `ask` it keeps the
   announcement for the review dialog (03 §5.6). Removals are never automatic; they need the review.
4. **Target store.** The store whose entry authenticated this connection: the user store for user processes (an
   entry found in a live source was already copied there by section 7.2). If the trusted entry is in the
   **machine** store, user processes only report it (the announcement is informational; the machine store is
   read-only for them), and the service applies it only when the machine policy `UpdateHostKeys = 2` is set
   (03 §3.5); otherwise an elevated admin applies it (03 §5.6). Live sources are never modified.

```c
typedef enum { SD_HKEV_MISMATCH, SD_HKEV_REVOKED, SD_HKEV_ANNOUNCED } sd_hkev_kind;
typedef struct sd_hk_key { const uint8_t *blob; size_t len; const char *type, *fp_sha256; } sd_hk_key;
typedef struct sd_hostkey_event {
  sd_hkev_kind kind; uint32_t hop_index; const char *lookup_name;
  sd_kh_store_kind store; const wchar_t *path; uint32_t line;   /* MISMATCH/REVOKED: where the old entry is;
                                                                    ANNOUNCED: target store */
  const sd_hk_key *old_key, *new_key;                            /* MISMATCH */
  const sd_hk_key *add; uint32_t add_count;                      /* ANNOUNCED: proven keys */
  const sd_hk_key *remove; uint32_t remove_count;                /* ANNOUNCED: removal candidates */
} sd_hostkey_event;                                              /* pointers valid during the callback only */
```

### 7.6 Responsibility summary

- `sd_ssh` / `sd_known_hosts`: all `known_hosts` I/O, locking, matching, imports (review C19), and the
  UpdateHostKeys proof check; the resulting writes are requested by the host through `sd_known_hosts` (section 7.5).
- `sd_ssh`: the reconnect secret cache (review C20).
- The host (03): store-list configuration, policy, prompts, Credential Manager/DPAPI answers.

---

## 8. Reconnect support (what sd_ssh/sd_sftp expose)

The SSH layer is stateless across reconnects except for:
- the **verified host key blob per hop**. A changed key on reconnect goes through the full verification again; a
  mismatch makes the session FAILED (no silent acceptance). The host-key list of a reconnect is restricted to the
  stored types like any connection (TM-R04), so a reconnect never raises a "new key type" prompt; `NEW_TYPE` and
  `SD_E_HOSTKEY_TYPE_UNAVAILABLE` make the session FAILED. A plain `SD_HK_NEW` during a reconnect is possible only if
  the key was removed from every store meanwhile, and its prompt carries `is_reconnect = 1` (TST-11);
- **cached secrets**, only if the profile allows (section 7.4): the password, proxy passwords and decrypted keys.
  Keyboard-interactive answers are never cached. A server that requires an OTP on every login therefore needs user
  interaction on reconnect. The prompt carries `is_reconnect = 1`, and the session state becomes `AUTH_REQUIRED`
  instead of looping.
- **Per connection:** each pool member (section 10.9) has its own reconnect state and backoff. Losing the primary
  connection is a session-level disconnect; losing a secondary is not.

The SFTP-level contract (handles, generations, stale handles) is in section 10.6.

---

## 9. `sd_ssh` public API (consumed by sd_sftp and the connection manager)

```c
typedef struct sd_ssh_conn sd_ssh_conn;       /* a chain: hops + final connection */
typedef struct sd_ssh_channel sd_ssh_channel;

typedef struct sd_ssh_identity {
  enum { SD_ID_FILE, SD_ID_AGENT_KEY, SD_ID_BLOB } kind;
  const wchar_t *path;            /* SD_ID_FILE */
  const char *agent_fingerprint;  /* SD_ID_AGENT_KEY, "SHA256:..." */
  const uint8_t *blob; size_t blob_len;  /* SD_ID_BLOB: key file bytes (e.g. DPAPI-unprotected by the host, or a
                                            service key); deep-copied into a secret buffer at conn_create */
  const char *label;              /* SD_ID_BLOB: shown in passphrase prompts instead of key_path */
} sd_ssh_identity;                /* passphrases for encrypted blobs come through SD_PROMPT_KEY_PASSPHRASE */

typedef struct sd_ssh_auth_cfg {
  const char *user;                              /* UTF-8 */
  const sd_ssh_identity *identities; uint32_t identity_count;
  uint32_t methods;        /* SD_AUTH_PUBLICKEY|SD_AUTH_KBDINT|SD_AUTH_PASSWORD */
  uint32_t agents;         /* SD_AGENT_PAGEANT|SD_AGENT_OPENSSH; must be 0 in the service context (D17) */
  int identities_only;     /* host passes 1 when the hop configures an identity, unless the profile says no
                              (decisions.md D37, section 6.2) */
  int cache_secrets_for_reconnect;
} sd_ssh_auth_cfg;

typedef enum sd_proxy_kind { SD_PROXY_NONE, SD_PROXY_HTTP, SD_PROXY_SOCKS5, SD_PROXY_SYSTEM } sd_proxy_kind;
enum { SD_PROXY_AUTH_BASIC = 1u<<0,
       SD_PROXY_AUTH_SSPI = 1u<<1,               /* Negotiate incl. NTLM fallback, and bare NTLM */
       SD_PROXY_AUTH_USERPASS = 1u<<2,
       SD_PROXY_AUTH_SSPI_KERBEROS = 1u<<3 };    /* Negotiate restricted to Kerberos (TM-R10) */
typedef enum sd_proxy_origin { SD_PROXY_ORIGIN_CONFIGURED,   /* profile, policy ProxyServer, static system entry */
                               SD_PROXY_ORIGIN_DISCOVERED    /* WPAD / PAC result (set by sd_ssh) */ } sd_proxy_origin;
typedef struct sd_proxy_cfg {                    /* section 5.2 */
  sd_proxy_kind kind;
  const wchar_t *host; uint16_t port;            /* HTTP / SOCKS5 */
  uint32_t auth;                                 /* allowed schemes; 0 = none */
  int allow_discovered_sspi;                     /* machine policy AllowSystemProxySspi = 1 (TM-R10); default 0 */
  int allow_system;                              /* machine policy AllowSystemProxy = 1 lets proxy = system
                                                    resolve; 0 (default) refuses the opt-in (TM-R10) */
  const char *user;                              /* UTF-8; password via SD_PROMPT_PROXY_PASSWORD */
  int remote_dns;                                /* SOCKS5: send the name (default 1) */
  int fallback_direct;                           /* SD_PROXY_SYSTEM: connect directly if discovery fails (0) */
} sd_proxy_cfg;

typedef enum sd_legacy_policy { SD_LEGACY_ALLOW, SD_LEGACY_WARN, SD_LEGACY_ASK, SD_LEGACY_REFUSE } sd_legacy_policy;
typedef enum sd_hku_mode { SD_HKU_YES, SD_HKU_ASK, SD_HKU_NO } sd_hku_mode;   /* section 7.5 */

typedef struct sd_ssh_hop {
  const wchar_t *host; uint16_t port;            /* host as typed; IDN allowed */
  const char *host_key_alias;                    /* optional */
  sd_ssh_auth_cfg auth;
  sd_proxy_cfg proxy;                            /* how this hop is reached; kind NONE = directly */
  sd_hku_mode update_host_keys;                  /* default SD_HKU_ASK (03 §3.4.1); SD_HKU_NO in the service
                                                    unless policy UpdateHostKeys = 2 */
} sd_ssh_hop;

typedef struct sd_ssh_algo_cfg {
  sd_legacy_policy legacy_policy;    /* default SD_LEGACY_WARN; REFUSE removes legacy algorithms */
  int refuse_terrapin_exposed;       /* default 0: connect with TERRAPIN_EXPOSED when the server offers no unaffected
                                        cipher/MAC pair; 1: fail before KEXINIT instead (section 4.3, TM-R01) */
  const char *disabled;              /* comma list of algorithm names to remove; may be NULL */
  int crypto_backend;                /* 0 auto, 1 own */
} sd_ssh_algo_cfg;

enum { SD_SSH_CFG_POOL_MEMBER = 1u<<0 };   /* set by sd_sftp for secondary connections (section 10.9) */

typedef struct sd_ssh_config {
  uint32_t struct_size;              /* versioning */
  const sd_ssh_hop *hops; uint32_t hop_count;    /* 1..8, last = target */
  sd_ssh_algo_cfg algos;
  sd_known_hosts *known_hosts;
  uint32_t connect_timeout_ms;       /* 15000 if 0; the host passes the profile's connect_timeout (03: 20 s);
                                        includes proxy handshakes */
  uint32_t keepalive_interval_ms;    /* 15000 */
  uint32_t keepalive_max_missed;     /* 3 */
  uint64_t rekey_bytes;              /* 1 GiB */
  uint32_t rekey_seconds;            /* 3600 */
  int address_family;                /* AF_UNSPEC / AF_INET / AF_INET6 */
  uint32_t flags;                    /* SD_SSH_CFG_* */
} sd_ssh_config;

typedef struct sd_ssh_negotiated {
  uint32_t hop_index;
  const char *kex, *hostkey, *cipher_c2s, *cipher_s2c, *mac_c2s, *mac_s2c, *comp_c2s, *comp_s2c;
  const char *server_version;        /* e.g. "OpenSSH_9.9p1 Debian-3" */
  const char *hostkey_fp_sha256;
  int strict_kex;
  uint32_t legacy_mask;              /* section 4.3 */
} sd_ssh_negotiated;

typedef struct sd_ssh_callbacks {
  void *ctx;
  void (*on_prompt)(void *ctx, sd_prompt *p, const sd_auth_prompt_info *auth, const sd_hostkey_prompt_info *hk);
  void (*on_prompt_withdrawn)(void *ctx, sd_prompt *p);
  void (*on_banner)(void *ctx, uint32_t hop, const char *utf8);
  void (*on_negotiated)(void *ctx, const sd_ssh_negotiated *n);           /* once per hop per KEX */
  void (*on_hostkey_event)(void *ctx, const sd_hostkey_event *e);         /* mismatch/revoked details;
                                                                             SD_HKEV_ANNOUNCED (section 7.5) */
  void (*on_log)(void *ctx, int level, const char *msg);  /* optional; English, no secrets. Logging goes to
                                                             sd_log (component ssh/sftp/crypto) in any case;
                                                             this is a thin per-connection adapter (review §4) */
} sd_ssh_callbacks;

/* Lifecycle (all non-blocking; completion via callback on the chain's I/O thread). */
typedef void (*sd_ssh_done_cb)(void *ctx, sd_err err, uint32_t failed_hop);
sd_err sd_ssh_global_init(void);
sd_err sd_ssh_conn_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out); /* deep-copies cfg */
sd_err sd_ssh_conn_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
sd_err sd_ssh_conn_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
void   sd_ssh_conn_destroy(sd_ssh_conn *c);     /* must not be called on its own I/O thread */
int    sd_ssh_conn_is_io_thread(const sd_ssh_conn *c);

/* After a successful connect: how every hop authenticated. noninteractive = 1 when no prompt was shown to a user on
   any hop (keys without passphrase, agents, DPAPI blobs, answers flagged SD_ANSWER_FROM_STORE, the reconnect cache).
   It gates the connection pool (section 10.9). */
typedef struct sd_ssh_auth_info { int noninteractive; uint32_t methods_used; } sd_ssh_auth_info;
sd_err sd_ssh_conn_auth_info(const sd_ssh_conn *c, sd_ssh_auth_info *out);

/* Liveness probe and RTT (sections 4.6, 10.4); I/O thread only. */
void   sd_ssh_conn_probe(sd_ssh_conn *c);
void   sd_ssh_conn_rtt(const sd_ssh_conn *c, uint32_t *srtt_ms, uint32_t *rttvar_ms);

/* TM-R04 explicit "add a key of another type" (section 4.3): only on a connection whose hop key verified as
   SD_HK_MATCH against a key trusted before this connection. types = NULL fetches every announced key. Announced
   keys are proven with hostkeys-prove-00; a requested type that was not announced is obtained by a re-key
   restricted to that type. done receives the proven keys (sd_hk_key array, valid during the callback); fails with
   SD_E_HOSTKEY_TYPE_UNAVAILABLE when the server has no such key. Never writes a store. */
typedef void (*sd_ssh_hostkeys_cb)(void *ctx, sd_err e, const sd_hk_key *keys, uint32_t count);
sd_err sd_ssh_conn_fetch_hostkeys(sd_ssh_conn *c, uint32_t hop_index, const char *const *types, uint32_t ntypes,
                                  sd_ssh_hostkeys_cb done, void *ctx);

/* Status (M5 part 8, 2026-10-28): built and used by the per-user `hostkey add --from-server` (sd_mount hostkey
   mount, docs/dev/m5-notes.md part 7); tested by interop_hostkeys_fetch_* against the WSL fixture. */

/* Channels (used by sd_sftp; consumer callbacks run on the I/O thread). */
typedef struct sd_ssh_channel_sink {
  void (*on_open)(void *ctx, sd_err err);
  void (*on_data)(void *ctx, const uint8_t *p, size_t n);    /* call sd_ssh_channel_consumed() later */
  void (*on_writable)(void *ctx);
  void (*on_eof)(void *ctx);
  void (*on_closed)(void *ctx, sd_err why);
} sd_ssh_channel_sink;
sd_err sd_ssh_channel_open_subsystem(sd_ssh_conn *c, const char *name, const sd_ssh_channel_sink *s, void *ctx,
                                     sd_ssh_channel **out);
/* Only for identity_probe = exec (decisions.md D10): fixed command strings chosen by sd_sftp, never user input. */
sd_err sd_ssh_channel_open_exec(sd_ssh_conn *c, const char *command, const sd_ssh_channel_sink *s, void *ctx,
                                sd_ssh_channel **out);
sd_err sd_ssh_channel_write(sd_ssh_channel *ch, const uint8_t *p, size_t n, size_t *accepted); /* I/O thread only */
void   sd_ssh_channel_consumed(sd_ssh_channel *ch, size_t n);
size_t sd_ssh_channel_send_space(const sd_ssh_channel *ch);   /* bytes we may queue without exceeding limits */
void   sd_ssh_channel_close(sd_ssh_channel *ch);
/* Run fn on the chain's I/O thread (used by sd_sftp to hop from caller threads). */
sd_err sd_ssh_conn_post(sd_ssh_conn *c, void (*fn)(void *), void *arg);
```

---

## 10. `sd_sftp` - public API for the filesystem layer (the contract)

### 10.1 Protocol profile

- SFTP **version 3** (draft-ietf-secsh-filexfer-02), as implemented by OpenSSH `sftp-server`. We send
  `SSH_FXP_INIT(3)` and require `SSH_FXP_VERSION(3)`. Any other version (lower, or a non-conforming higher one) fails
  with `SD_E_PROTOCOL`, and the version number is logged.
- Packet limits: outgoing SFTP packets <= `max-packet-length` from `limits@openssh.com` if known, otherwise 34000
  bytes. Inbound packets are accepted up to 256 KiB + 13 (header + 256 KiB data); bigger is `SD_E_PROTOCOL`.
- Read/write chunk size: `min(limits.max-read-length or 32768, 255 KiB)` and
  `min(limits.max-write-length or 32768, 255 KiB)`. Without `limits@openssh.com` we use 32 KiB, which every server
  handles.
- Extensions recognized in `SSH_FXP_VERSION` (by name and version string). **All** announced extensions, including
  unknown ones, are also kept as a raw name/version list in `server_info.ext_list` (02 R12), and
  `sd_sftp_has_ext(session, SD_SFTP_EXT_*)` answers capability queries (02 R3):

| Extension | Version | Use |
|-----------|---------|-----|
| `posix-rename@openssh.com` | 1 | atomic replace-rename |
| `statvfs@openssh.com`, `fstatvfs@openssh.com` | 2 | free space |
| `hardlink@openssh.com` | 1 | hard links |
| `fsync@openssh.com` | 1 | flush |
| `lsetstat@openssh.com` | 1 | setstat without following symlinks |
| `limits@openssh.com` | 1 | queried right after INIT. Reply: uint64 max-packet-length, max-read-length, max-write-length, max-open-handles; 0 = unknown |
| `expand-path@openssh.com` | 1 | `~` expansion (NAME reply) |
| `copy-data` | 1 | server-side copy: `string read-handle, uint64 read-offset, uint64 length (0 = to EOF), string write-handle, uint64 write-offset` |
| `home-directory` | 1 | `string username` -> NAME |
| `users-groups-by-id@openssh.com` | 1 | request `string uids (packed uint32[]), string gids (packed uint32[])` -> EXTENDED_REPLY `string usernames (packed string[]), string groupnames (packed string[])`; empty string = unknown id |

- Attribute flags: SIZE 0x1, UIDGID 0x2, PERMISSIONS 0x4, ACMODTIME 0x8, EXTENDED 0x80000000. Times are uint32 seconds
  (unsigned, valid until 2106). Extended attribute pairs are parsed and passed through in the completion (02 R10;
  section 10.3); at most 64 pairs, 64 KiB total.
- Open pflags: READ 0x1, WRITE 0x2, APPEND 0x4, CREAT 0x8, TRUNC 0x10, EXCL 0x20.
- Handles are opaque strings, max 256 bytes (draft). Longer handles are `SD_E_PROTOCOL`.

### 10.2 Error enum (`sd_err.h`, shared by all core modules)

These names are **canonical** for the project (review C13): `sd_err` lives in `sd_base`, 02 uses these names, and
the master tables generated from one source in `sd_base` (`sd_err` -> name; review §4) are checked by a unit test that
covers every value. The mapping `sd_err` -> `sd_vfs_status` -> NTSTATUS/HTTP belongs to 02, and `sd_err` -> IPC code ->
exit code to the host (03); neither is defined here.

```c
typedef enum sd_err {
  SD_OK = 0,
  /* filesystem-ish results */
  SD_E_EOF,               SD_E_NOT_FOUND,         SD_E_ACCESS_DENIED,    SD_E_EXISTS,
  SD_E_NOT_EMPTY,         SD_E_NOT_A_DIRECTORY,   SD_E_IS_A_DIRECTORY,   SD_E_NO_SPACE,
  SD_E_QUOTA,             SD_E_READ_ONLY,         SD_E_INVALID_NAME,     SD_E_NAME_TOO_LONG,
  SD_E_LINK_LOOP,         SD_E_LOCK_CONFLICT,     SD_E_INVALID_PARAM,    SD_E_UNSUPPORTED,
  SD_E_FAILURE,           /* remote generic failure, no better information */
  /* session / transport */
  SD_E_DISCONNECTED,      SD_E_STALE_HANDLE,      SD_E_TIMEOUT,          SD_E_CANCELLED,
  SD_E_PROTOCOL,          SD_E_BUSY,              SD_E_WOULD_DEADLOCK,   SD_E_SHUTDOWN,
  SD_E_DNS,               SD_E_CONN_REFUSED,      SD_E_NET_UNREACHABLE,  SD_E_KEX_FAILED,
  SD_E_HOSTKEY_REJECTED,  SD_E_HOSTKEY_MISMATCH,  SD_E_HOSTKEY_REVOKED,  SD_E_HOSTKEY_TYPE_UNAVAILABLE, /* TM-R04 */
  SD_E_AUTH_FAILED,
  SD_E_AUTH_REQUIRED,     /* reconnect needs user input */
  SD_E_LEGACY_REJECTED,   /* legacy acknowledgement refused (section 4.1) */
  SD_E_PROXY,             SD_E_PROXY_AUTH,        /* section 5.2 */
  SD_E_POOL_ABANDONED,    /* pool member given up for the generation (section 10.9) */
  /* local */
  SD_E_NO_MEMORY,         SD_E_CRYPTO,            SD_E_KEY_FORMAT,       SD_E_KEY_UNSUPPORTED,
  SD_E_BAD_PASSPHRASE,    SD_E_KEY_PASSPHRASE_REQUIRED, SD_E_INTERNAL,
  /* WebDAV (02 §7.4, TM-R19): no SSPI, so the redirector cannot authenticate; the host may ask for token-only */
  SD_WD_E_AUTH_UNAVAILABLE
} sd_err;
const char *sd_err_name(sd_err e);   /* stable English identifier for logs/JSON, e.g. "not_found" */
```

`sd_err_name` produces the IPC spellings of 03 (review C25): `SD_E_HOSTKEY_*` -> `host_key_rejected`,
`host_key_mismatch`, `host_key_revoked`, `host_key_type_unavailable` (new with TM-R04; 03 still has to add it to its
IPC error and exit-code tables); `SD_E_DNS` -> `dns_failed`; `SD_E_AUTH_REQUIRED` -> `prompt_required`;
`SD_E_PROXY` -> `proxy_connect_failed`; `SD_E_PROXY_AUTH` -> `proxy_auth_failed`; `SD_E_LEGACY_REJECTED` ->
`legacy_refused` (03 §6.2 exit codes 16 and 15); `SD_WD_E_AUTH_UNAVAILABLE` -> `auth_unavailable` (03 §6.2 exit code 4);
all others are the lowercase enum name without the `SD_E_` prefix.

SFTP status to `sd_err` (v3 codes, plus higher codes some servers send anyway):

| SFTP status | sd_err |
|-------------|--------|
| 0 OK | SD_OK |
| 1 EOF | SD_E_EOF |
| 2 NO_SUCH_FILE, 10 NO_SUCH_PATH | SD_E_NOT_FOUND |
| 3 PERMISSION_DENIED, 22 CANNOT_DELETE | SD_E_ACCESS_DENIED |
| 4 FAILURE | SD_E_FAILURE (refined, see below) |
| 5 BAD_MESSAGE | SD_E_PROTOCOL |
| 6 NO_CONNECTION, 7 CONNECTION_LOST | SD_E_DISCONNECTED |
| 8 OP_UNSUPPORTED | SD_E_UNSUPPORTED |
| 9 INVALID_HANDLE | SD_E_STALE_HANDLE |
| 11 FILE_ALREADY_EXISTS | SD_E_EXISTS |
| 12 WRITE_PROTECT | SD_E_READ_ONLY |
| 14 NO_SPACE_ON_FILESYSTEM | SD_E_NO_SPACE |
| 15 QUOTA_EXCEEDED | SD_E_QUOTA |
| 17 LOCK_CONFLICT, 25 BYTE_RANGE_LOCK_CONFLICT | SD_E_LOCK_CONFLICT |
| 18 DIR_NOT_EMPTY | SD_E_NOT_EMPTY |
| 19 NOT_A_DIRECTORY | SD_E_NOT_A_DIRECTORY |
| 20 INVALID_FILENAME | SD_E_INVALID_NAME |
| 21 LINK_LOOP | SD_E_LINK_LOOP |
| 23 INVALID_PARAMETER, 16 UNKNOWN_PRINCIPAL, 31/32 OWNER/GROUP_INVALID | SD_E_INVALID_PARAM |
| 24 FILE_IS_A_DIRECTORY | SD_E_IS_A_DIRECTORY |
| anything else | SD_E_FAILURE |

**Error refinement** (`SD_SFTP_OPT_REFINE_ERRORS`, default on). v3 servers (OpenSSH) report EEXIST, ENOTEMPTY,
ENOTDIR, EISDIR and ENOSPC all as FAILURE. **sd_sftp is the only layer that refines** (review C14): `sd_vfs` maps the
refined codes and issues no probes of its own (02 keeps one mapping rule only: rename-with-replace onto a non-empty
directory is `STATUS_ACCESS_DENIED`). sd_sftp refines with one extra round trip, on the meta channel, only when the
result is `SD_E_FAILURE`:

| Operation | Probe | Refined result |
|-----------|-------|----------------|
| mkdir, symlink, hardlink, open(CREAT\|EXCL), rename without overwrite | LSTAT target exists | SD_E_EXISTS |
| rmdir | LSTAT: not a directory -> SD_E_NOT_A_DIRECTORY; otherwise OPENDIR+READDIR finds an entry other than `.`/`..` | SD_E_NOT_EMPTY |
| remove | LSTAT is a directory | SD_E_IS_A_DIRECTORY |
| opendir | LSTAT is not a directory | SD_E_NOT_A_DIRECTORY |
| write, fsync, close-after-write | STATVFS shows bavail == 0 (if extension present) | SD_E_NO_SPACE |

The raw status code and server message are always available in the completion for logging.

### 10.3 Types

```c
typedef struct sd_sftp_session sd_sftp_session;
typedef struct sd_sftp_file    sd_sftp_file;    /* file or directory handle; refcounted, survives reconnect */
typedef struct sd_sftp_req     sd_sftp_req;     /* in-flight request token for cancellation */

enum { SD_SFTP_ATTR_SIZE = 0x1, SD_SFTP_ATTR_UIDGID = 0x2, SD_SFTP_ATTR_PERM = 0x4, SD_SFTP_ATTR_TIMES = 0x8,
       SD_SFTP_ATTR_EXTENDED = 0x80000000u };
typedef struct sd_sftp_extattr { const char *type; uint32_t type_len; const uint8_t *data; uint32_t data_len; }
        sd_sftp_extattr;
typedef struct sd_sftp_attrs {
  uint32_t valid;          /* SD_SFTP_ATTR_* */
  uint64_t size;
  uint32_t uid, gid;
  uint32_t perm;           /* POSIX mode incl. S_IFMT type bits (0170000) */
  int64_t  atime, mtime;   /* Unix seconds; wire is uint32 */
  /* Extended pairs (02 R10): valid only inside the completion callback that delivered them; NULL/0 in every
     stored copy (sd_sftp_file_info, caches). Copy what you need. */
  const sd_sftp_extattr *ext; uint32_t ext_count;
} sd_sftp_attrs;
/* Type helpers on perm: */
#define SD_SFTP_IS_DIR(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0040000u))
#define SD_SFTP_IS_LNK(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0120000u))
#define SD_SFTP_IS_REG(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0100000u))

typedef struct sd_sftp_dirent {
  const char *name;       uint32_t name_len;      /* raw bytes, NUL-terminated copy; enforced by sd_sftp (TM-R12):
                                                     never empty, never contains '/' or NUL, never "." or ".." */
  const char *longname;   uint32_t longname_len;  /* ls -l style; may be "" */
  sd_sftp_attrs attrs;
} sd_sftp_dirent;

typedef struct sd_sftp_statvfs {
  uint64_t bsize, frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag, namemax;
} sd_sftp_statvfs;       /* flag: 0x1 ST_RDONLY, 0x2 ST_NOSUID */

typedef struct sd_sftp_limits {
  uint64_t max_packet, max_read, max_write, max_open_handles;   /* effective values in use; never 0 */
} sd_sftp_limits;

enum {  /* server capability bits */
  SD_SFTP_EXT_POSIX_RENAME = 1u<<0, SD_SFTP_EXT_STATVFS = 1u<<1, SD_SFTP_EXT_FSTATVFS = 1u<<2,
  SD_SFTP_EXT_HARDLINK = 1u<<3, SD_SFTP_EXT_FSYNC = 1u<<4, SD_SFTP_EXT_LSETSTAT = 1u<<5,
  SD_SFTP_EXT_LIMITS = 1u<<6, SD_SFTP_EXT_EXPAND_PATH = 1u<<7, SD_SFTP_EXT_COPY_DATA = 1u<<8,
  SD_SFTP_EXT_HOME_DIRECTORY = 1u<<9, SD_SFTP_EXT_USERS_GROUPS_BY_ID = 1u<<10
};
enum { SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER = 1u<<0, SD_SFTP_QUIRK_WIN_DRIVE_PATHS = 1u<<1 };

/* Remote identity hooks (02 R13, decisions.md D10). sd_sftp reports what it learned; sd_vfs confirms the uid and
   learns the primary gid from the attributes of the first file or directory it creates (its own completion), and
   applies 02's "g|o writable" rule for unknown supplementary groups. */
enum { SD_SFTP_ID_HOME_OWNER = 1, SD_SFTP_ID_EXEC = 2 };
typedef struct sd_sftp_identity {
  uint32_t source;              /* 0 = unknown, SD_SFTP_ID_HOME_OWNER, SD_SFTP_ID_EXEC */
  uint32_t uid, gid;            /* home owner uid/gid, or `id -u` + first of `id -G` */
  const uint32_t *gids; uint32_t gid_count;   /* supplementary gids, only with SD_SFTP_ID_EXEC (max 64) */
} sd_sftp_identity;

typedef struct sd_sftp_ext_entry { const char *name; const char *version; } sd_sftp_ext_entry;

typedef struct sd_sftp_server_info {
  uint32_t generation;          /* increments on every successful (re)connect, starts at 1 */
  uint32_t version;             /* 3 */
  uint32_t ext;                 /* SD_SFTP_EXT_* (known extensions) */
  const sd_sftp_ext_entry *ext_list; uint32_t ext_count;   /* every announced extension, raw (02 R12) */
  sd_sftp_limits limits;
  uint32_t channels;            /* SFTP channels open on the primary connection (1 or 2) */
  uint32_t connections;         /* pool members currently READY, incl. the primary (section 10.9) */
  uint32_t quirks;              /* SD_SFTP_QUIRK_* in effect */
  const char *home;             /* realpath(".") at connect; raw bytes */
  sd_sftp_identity identity;    /* section 11 startup step 5 */
  const sd_ssh_negotiated *ssh; /* target hop: server version, host key fingerprint, legacy_mask */
} sd_sftp_server_info;          /* pointers valid until the next state change event */

int sd_sftp_has_ext(const sd_sftp_session *s, uint32_t ext_bit);   /* current generation; 0 when not READY */
```

### 10.4 Session lifecycle, state and events

```c
typedef enum sd_sftp_state {
  SD_SFTP_ST_IDLE, SD_SFTP_ST_CONNECTING, SD_SFTP_ST_READY,
  SD_SFTP_ST_DISCONNECTED,      /* transient; reconnect pending per policy */
  SD_SFTP_ST_RECONNECT_WAIT,    /* backoff timer running */
  SD_SFTP_ST_AUTH_REQUIRED,     /* reconnect needs user interaction (prompt outstanding) */
  SD_SFTP_ST_FAILED,            /* permanent: host key mismatch/revoked, auth failure, policy give-up */
  SD_SFTP_ST_CLOSED
} sd_sftp_state;

typedef struct sd_sftp_reconnect_policy {
  int enabled;                  /* default 1 */
  uint32_t initial_delay_ms;    /* 1000 */
  uint32_t max_delay_ms;        /* 60000; exponential x2 with +/-20% jitter */
  uint32_t max_attempts;        /* 0 = unlimited */
} sd_sftp_reconnect_policy;

typedef struct sd_sftp_options {
  uint32_t struct_size;
  uint32_t channels;            /* per connection: 2 (meta + bulk, default) or 1; auto-degrades to 1 */
  uint32_t connections;         /* pool size 1..4, default 1 (section 10.9) */
  uint32_t stripe_bytes;        /* striping unit, default 1 MiB, multiple of the chunk size */
  uint32_t max_inflight_reqs;   /* per channel, default 64 */
  uint32_t max_inflight_bytes;  /* per channel, default 8 MiB */
  uint32_t max_queued_reqs;     /* per session, default 4096; beyond it submission returns SD_E_BUSY (02 R5) */
  uint32_t flags;               /* SD_SFTP_OPT_REFINE_ERRORS (default on), SD_SFTP_OPT_SYMLINK_ORDER_DRAFT,
                                   SD_SFTP_OPT_SYMLINK_ORDER_OPENSSH (forced quirk),
                                   SD_SFTP_OPT_IDENTITY_EXEC (identity_probe = exec, default off) */
  sd_sftp_reconnect_policy reconnect;
  uint32_t default_timeout_ms;  /* per request when the caller passes none; default 30000, never 0 (D17) */
} sd_sftp_options;

typedef struct sd_sftp_event {
  enum { SD_SFTP_EV_STATE, SD_SFTP_EV_READY_INFO, SD_SFTP_EV_POOL } type;
  sd_sftp_state state;  sd_err reason;  uint32_t failed_hop;
  uint32_t retry_in_ms;                 /* RECONNECT_WAIT */
  const sd_sftp_server_info *info;      /* READY_INFO */
  uint32_t member, connections;         /* POOL: member index that changed, members READY now (informational) */
} sd_sftp_event;

/* Statistics (02 R16): smoothed values per connection and for the whole session. Cheap; any thread. */
typedef struct sd_sftp_conn_stats {
  uint32_t srtt_ms, rttvar_ms;          /* RFC 6298-style, section 4.6 */
  uint64_t rx_bps, tx_bps;              /* payload bytes/s, EWMA over ~2 s */
  uint64_t rx_total, tx_total;          /* SFTP payload bytes this generation */
  uint32_t inflight_reqs, queued_reqs;
  int      ready;
} sd_sftp_conn_stats;
typedef struct sd_sftp_stats {
  sd_sftp_conn_stats total;             /* srtt of the primary; rates and counts summed */
  sd_sftp_conn_stats conn[4];           /* [0] = primary */
  uint32_t conn_count;
} sd_sftp_stats;
sd_err sd_sftp_session_stats(const sd_sftp_session *s, sd_sftp_stats *out);
typedef void (*sd_sftp_event_cb)(void *ctx, const sd_sftp_event *ev);

sd_err sd_sftp_session_create(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb,
                              const sd_sftp_options *opt, sd_sftp_event_cb ev, void *ev_ctx,
                              sd_sftp_session **out);
sd_err sd_sftp_session_start(sd_sftp_session *s);           /* async; progress via events */
sd_err sd_sftp_session_reconnect_now(sd_sftp_session *s);   /* skip backoff (e.g. network came back) */
sd_err sd_sftp_session_close(sd_sftp_session *s);           /* async; completes in-flight with SD_E_SHUTDOWN, then CLOSED */
void   sd_sftp_session_destroy(sd_sftp_session *s);         /* after CLOSED; never on the I/O thread */
sd_sftp_state sd_sftp_session_state(const sd_sftp_session *s);
uint32_t sd_sftp_session_generation(const sd_sftp_session *s);
sd_err sd_sftp_session_info(sd_sftp_session *s, sd_sftp_server_info *copy_out, char *home_buf, size_t home_len);
int    sd_sftp_session_is_io_thread(const sd_sftp_session *s);
```

Event ordering on disconnect: (1) `EV_STATE(DISCONNECTED, reason)`, (2) completions of **all** in-flight requests with
`SD_E_DISCONNECTED`, (3) every open `sd_sftp_file` is marked stale, (4) `EV_STATE(RECONNECT_WAIT)`, and later
`CONNECTING`, then `READY` + `EV_READY_INFO` with the new `generation`. The server info (extensions, limits, home) may
differ after a reconnect (for example after a server upgrade), so the VFS must re-read it on `READY_INFO`.

Session state is the state of the **primary** connection. Secondary pool members coming and going produce only
`EV_POOL` events (section 10.9). State and pool events are delivered on the primary's I/O thread.

### 10.5 Requests

Common rules:
- Every submit function returns `sd_err`. `SD_OK` means **the callback will be called exactly once**. Any other value
  means it will never be called. Submission never calls the callback synchronously.
- Submitting while the state is not READY returns `SD_E_DISCONNECTED` immediately, unless the request has
  `SD_SFTP_REQ_WAIT_READY`. Such a request is then queued until READY or until its timeout (`timeout_ms`, required > 0
  with this flag) expires with `SD_E_TIMEOUT`. Writes may be queued with WAIT_READY only on a handle that is not
  stale. In practice the VFS uses WAIT_READY for metadata and reads during short outages, and does not use it for
  writes ("writes fail cleanly").
- Paths are NUL-terminated raw byte strings (UTF-8 on all normal servers). Absolute paths are recommended; relative
  paths resolve against the server's default directory. sd_sftp does no normalization except refusing embedded NULs
  (impossible in C strings anyway) and paths > 64 KiB.
- `sd_sftp_reqopt` (optional, may be NULL): `{ uint32_t flags; uint32_t timeout_ms; sd_sftp_req **token_out; }`.
- **Directory entries from the server are untrusted (TM-R12, T-24).** `readdir` drops, before the completion,
  every entry whose name is empty, contains `/` or NUL, or is the server's own `.` or `..` (`sd_vfs` adds its own,
  02 §6.5); `dropped` in the completion counts them and sd_sftp logs the first occurrence per directory handle at
  warning level (name escaped, path at debug level only, TM-R31). The `rmdir` refinement probe (section 10.2) applies
  the same rule. Duplicate raw names across batches and names that collide after stage 2 are handled by `sd_vfs`
  (keep the first; `~cN` rule, 02 §1.3, §6.5), because only it holds the whole listing. Names returned by
  `realpath`, `readlink`, `expand-path` and `home-directory` are paths, not components, and are passed through.
- **Deadlines (D17, 02 R15):** every request has one, set by the caller. `timeout_ms = 0` means
  `default_timeout_ms` (30 s; CLI and tools). `sd_vfs` always passes its own: 25 s for the Dokany backend and 50 s
  for WebDAV (below the redirector's 60 s), split across the round trips of one vfs operation (02 §5.7). The deadline covers queueing
  and the round trip. Expiry completes the request with `SD_E_TIMEOUT` (`maybe_executed` set if it was sent), discards
  a late reply, and triggers the liveness probe of section 4.6; the connection is torn down only if the probe
  fails.
- **Request classes (D8, review C17, 02 R14):** path operations (stat, lstat, setstat, mkdir, rmdir, remove, rename,
  readlink, symlink, hardlink, realpath, expand-path, home-directory, statvfs, names-by-id), `opendir`/`readdir` and
  opens flagged `SD_SFTP_REQ_CLASS_META` go to the **meta** channel of the primary connection. Other opens bind
  their handle to the **bulk** channel. With only one channel, the scheduler serves the meta queue before the bulk
  queue at every turn, so a `stat` waits for at most one in-flight bulk chunk to be sent, not for megabytes.
- **Chunk guarantee (review C15):** a `read`/`write` with `len <= limits.max_read`/`max_write` (and, on a striped
  handle, not crossing a stripe boundary) becomes exactly one wire request, plus at most a reissue of the remainder
  after a short non-EOF read. Larger calls are still split, pipelined and reassembled, but `sd_vfs` issues
  chunk-sized calls itself.

```c
typedef struct sd_sftp_completion {
  sd_err   err;
  uint32_t sftp_status;          /* raw status code if a STATUS reply was received, else UINT32_MAX */
  const char *server_message;    /* UTF-8 (sanitized), may be ""; valid during the callback only */
  int      maybe_executed;       /* 1 if err==DISCONNECTED/TIMEOUT/CANCELLED and the request was sent:
                                    a mutating op might have happened on the server */
  int      session_ready;        /* 1 if err==DISCONNECTED came from losing a secondary pool member while the
                                    session itself stayed READY (section 10.9) */
  union {
    struct { sd_sftp_file *file; sd_sftp_attrs attrs; } open;   /* caller owns one reference */
    struct { uint32_t bytes; int eof; } read;                   /* contiguous bytes from offset */
    struct { uint32_t bytes; } write;                           /* contiguous bytes acknowledged */
    struct { sd_sftp_attrs attrs; } stat;
    struct { const sd_sftp_dirent *ents; uint32_t count; int eof;
             uint32_t dropped; } readdir;                       /* entries removed by the TM-R12 rules */
    struct { const char *path; uint32_t len; sd_sftp_attrs attrs; } name;  /* realpath/readlink/expand/home */
    struct { sd_sftp_statvfs v; } statvfs;
    struct { const char *const *users; const char *const *groups; uint32_t nu, ng; } ids;
    struct { uint64_t bytes; } copy;
  } u;
} sd_sftp_completion;
typedef void (*sd_sftp_cb)(void *ctx, const sd_sftp_completion *c);

typedef struct sd_sftp_reqopt { uint32_t flags; uint32_t timeout_ms; sd_sftp_req **token_out; } sd_sftp_reqopt;
enum { SD_SFTP_REQ_WAIT_READY = 1u<<0, SD_SFTP_REQ_NO_REFINE = 1u<<1,
       SD_SFTP_REQ_CLASS_META = 1u<<2 };   /* open: bind the handle to the meta channel (attribute-only opens) */

/* Files and directories. Bits >= 1u<<24 are local to sd_sftp and never sent on the wire. */
enum { SD_SFTP_O_READ = 0x1, SD_SFTP_O_WRITE = 0x2, SD_SFTP_O_APPEND = 0x4,
       SD_SFTP_O_CREAT = 0x8, SD_SFTP_O_TRUNC = 0x10, SD_SFTP_O_EXCL = 0x20,
       SD_SFTP_O_STRIPED = 1u<<24 };       /* bulk striping across the pool (section 10.9) */
sd_err sd_sftp_open(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                    sd_sftp_file *same_channel_as /* NULL or a file for copy-data affinity */,
                    const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);   /* OPEN + FSTAT: attrs returned */
sd_err sd_sftp_opendir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_close(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx); /* releases the caller's ref */
void   sd_sftp_file_addref(sd_sftp_file *f);
void   sd_sftp_file_release(sd_sftp_file *f);   /* last ref on an open handle sends CLOSE in background */

/* Data. buf must stay valid and untouched until the callback. len may exceed the chunk size:
   sd_sftp splits, pipelines and reassembles. read completes with the contiguous prefix read
   (eof=1 if EOF was hit); short non-EOF replies are reissued for the remainder. */
sd_err sd_sftp_read (sd_sftp_file *f, uint64_t off, void *buf, uint32_t len,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_write(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_readdir(sd_sftp_file *dir, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx); /* one server batch */
sd_err sd_sftp_fstat(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fsync(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);   /* UNSUPPORTED w/o ext */
sd_err sd_sftp_fstatvfs(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_copy_data(sd_sftp_file *src, uint64_t src_off, uint64_t len, sd_sftp_file *dst, uint64_t dst_off,
                         const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);  /* same channel required */

/* Paths */
sd_err sd_sftp_stat    (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_lstat   (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_setstat (sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, int no_follow /* lsetstat */,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_mkdir   (sd_sftp_session *s, const char *path, const sd_sftp_attrs *a,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_rmdir   (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_remove  (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
enum { SD_SFTP_RENAME_OVERWRITE = 1u<<0 };   /* needs posix-rename; else SD_E_UNSUPPORTED (VFS decides fallback) */
sd_err sd_sftp_rename  (sd_sftp_session *s, const char *from, const char *to, uint32_t flags,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_readlink(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_symlink (sd_sftp_session *s, const char *link_path, const char *target,  /* quirk handled inside */
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_hardlink(sd_sftp_session *s, const char *existing, const char *new_link,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_realpath(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_expand_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_home_directory(sd_sftp_session *s, const char *user, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_statvfs (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_names_by_id(sd_sftp_session *s, const uint32_t *uids, uint32_t nu, const uint32_t *gids, uint32_t ng,
                           const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);  /* results cached per generation */

/* Cancellation: completes the request with SD_E_CANCELLED as soon as possible. After that completion
   sd_sftp guarantees it will not touch the caller's buffer again (late replies are discarded).
   A cancelled OPEN whose reply later succeeds is closed automatically. */
sd_err sd_sftp_cancel(sd_sftp_req *r);

/* Sync wrappers (CLI/tools). Return SD_E_WOULD_DEADLOCK if called on the I/O thread. */
sd_err sd_sftp_stat_sync(sd_sftp_session *s, const char *path, sd_sftp_attrs *out, uint32_t timeout_ms);
sd_err sd_sftp_read_sync(sd_sftp_file *f, uint64_t off, void *buf, uint32_t len, uint32_t *got, uint32_t timeout_ms);
/* ... one per async call, generated by macro from the async version ... */
```

Pipelining and windowing:
- Each SFTP channel keeps up to `max_inflight_reqs` (64) requests and `max_inflight_bytes` (8 MiB of requested read
  data, or of write payload) outstanding. Excess requests wait in a per-channel FIFO (only descriptors are queued,
  never copies of the data). The FIFOs of a session hold at most `max_queued_reqs` descriptors in total; a submission
  beyond that returns `SD_E_BUSY` and the callback is not called (02 R5). With 32 KiB chunks this gives 2 MiB in flight per channel (enough for ~160 Mbit/s at
  100 ms RTT); with 255 KiB chunks (OpenSSH `limits`), 8 MiB.
- A large `sd_sftp_read` is split into chunks. All of them are issued subject to the limits, and the request completes
  when every chunk is resolved. If a chunk comes back short (not EOF), the remainder is reissued. If a chunk hits
  EOF, later chunks are allowed to complete and are ignored. The reported `bytes` is the contiguous prefix.
- Write data is copied directly from the caller's buffer into SSH channel packets when window space exists (no
  intermediate copy). The caller's buffer must remain valid until completion.
- Fairness across channels and files: the scheduler round-robins between files with pending requests, so one large
  sequential read cannot block a stat on the same channel for more than one chunk.

Channel assignment and ordering (D8):
- `opendir` and `SD_SFTP_REQ_CLASS_META` opens bind the handle to the meta channel; other opens bind it to the bulk
  channel, or to the channel of `same_channel_as`, which copy-data requires because handles are per-channel. Path
  operations go to the meta channel. All of this is on the primary connection; only striped handles use other pool
  members (section 10.9).
- **Guarantee:** requests on the same `sd_sftp_file` are sent in submission order on one channel. The servers we
  target (OpenSSH processes requests sequentially per channel) execute them in order. For striped handles the
  guarantee holds per stripe (per byte range), plus the barriers of section 10.9. No ordering is guaranteed between
  different files or path operations. A caller that needs "write A then rename A" must wait for the write
  completion first. `sd_sftp_close` is queued behind earlier requests on that handle.

### 10.6 Reconnect contract for the VFS

State the VFS can rely on:
- `sd_sftp_session *` is stable across reconnects. `generation` increments on every successful connect.
- Every `sd_sftp_file` stores: the path as opened (raw bytes, as given by the caller), the open flags, the generation
  it was opened in, whether it is a directory, the channel group, and the attributes from its open/last fstat.
  Accessors:

```c
typedef struct sd_sftp_file_info {
  const char *path; uint32_t oflags; int is_dir; uint32_t generation; int stale; sd_sftp_attrs attrs_at_open;
} sd_sftp_file_info;
sd_err sd_sftp_file_get_info(sd_sftp_file *f, sd_sftp_file_info *out); /* path valid while caller holds a ref */
void  *sd_sftp_file_user(sd_sftp_file *f); void sd_sftp_file_set_user(sd_sftp_file *f, void *p); /* VFS cookie */

/* Re-open a stale handle in the current generation:
   - files: OPEN(path, oflags & ~(CREAT|TRUNC|EXCL)) + FSTAT; directories: OPENDIR (listing restarts at the beginning)
   - completion u.open.attrs holds the fresh attributes; the VFS compares size/mtime with its cache and decides
     whether the file changed underneath (policy is the VFS's)
   - on success the same sd_sftp_file object becomes non-stale; on failure it stays stale */
sd_err sd_sftp_file_reopen(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
```

- Operations on a stale handle fail immediately with `SD_E_STALE_HANDLE`, except `close`/`release`, which succeed
  locally.
- Requests in flight at disconnect complete with `SD_E_DISCONNECTED`. `maybe_executed = 1` marks mutating requests
  (write, setstat, rename, remove, mkdir, rmdir, symlink, hardlink, copy-data, fsync) that were already sent. The VFS
  must treat their effect as unknown: re-stat after reconnect, never blindly retry a rename.
- Writes are never replayed by sd_sftp. Re-opening a handle that had `O_WRITE` is allowed; whether buffered dirty data
  is re-sent is the VFS's decision (write-through by default, write-behind with grace retransmit as a profile
  opt-in; decisions.md D9). The requirements say writes fail cleanly while disconnected.
- Pool members (section 10.9): losing the primary is the disconnect described above and also closes every secondary;
  they are re-established in the background after the next READY. Losing a secondary keeps the session READY and
  its handles valid; only that member's in-flight requests are affected.
- After `READY_INFO`, the VFS re-reads `server_info` (limits and extensions may change) and should invalidate cached
  uid/gid name maps (`names_by_id` caches are per generation).
- Permanent failures (`FAILED`, `AUTH_REQUIRED`) stop the reconnect loop. `sd_sftp_session_reconnect_now()` restarts
  it after the user has fixed the cause (for example by answering an auth prompt or removing a stale host key).

### 10.7 Filename encoding (D7)

The wire format is bytes. sd_sftp passes bytes through unchanged. The name mapping has two stages (review C23):
**stage 1** is defined here (bytes <-> UTF-16, lossless); **stage 2** belongs to 02 and is applied per path component
on top of stage 1 (U+F000+c for Windows-reserved characters, trailing dot/space mapping, case handling). A profile's
`remote_charset` replaces stage 1 only. Stage-1 helpers (in `sd_utf.h`, `sd_base`, used by the VFS and the WebDAV
layer):

```c
/* Remote bytes -> UTF-16 (lossless). Valid UTF-8 decodes normally, EXCEPT:
   - each byte of an invalid sequence (bad lead, truncated, overlong, surrogate code point
     U+D800..DFFF, > U+10FFFF) maps to U+F700 + byte (U+F780..U+F7FF);
   - a VALID UTF-8 sequence that encodes a code point in U+F780..U+F7FF is also escaped byte-wise
     (each of its 3 bytes maps to U+F7xx), so the mapping is a bijection.
   UTF-16 -> remote bytes: U+F780..U+F7FF -> the single byte (cp - 0xF700); everything else -> UTF-8;
   unpaired UTF-16 surrogates -> SD_E_INVALID_NAME. */
sd_err sd_name_to_wide(const char *bytes, uint32_t len, wchar_t *out, uint32_t cap, uint32_t *out_len);
sd_err sd_name_from_wide(const wchar_t *w, uint32_t len, char *out, uint32_t cap, uint32_t *out_len);
```

- The round trip is exact for every byte string, and the output is always well-formed UTF-16. That matters for
  WebDAV/HTTP, which cannot carry lone surrogates.
- **Component invariant (TM-R11, T-23).** Both helpers work on one path component. The composed mapping (02's stage
  2 inverse, then `sd_name_from_wide`) must never produce a component that contains the byte `/` (0x2F) or NUL, or
  that equals `.` or `..`. Stage 1 enforces its share: `sd_name_from_wide` fails with `SD_E_INVALID_NAME` if its
  output would contain 0x00 or 0x2F (input U+0000 or U+002F; the escape range U+F780..U+F7FF only produces bytes
  0x80..0xFF), and `sd_name_component_check()` (same header) rejects empty, `.` and `..` components. 02's stage-2
  inverse maps back only the code points its forward map produces (TM-R11 in 02 §1.2), so U+F000 and U+F02F can no
  longer become NUL or `/`; `sd_vfs` calls the component check after both stages.
- The range U+F780..U+F7FF does not collide with stage 2's U+F000+c range for Windows-reserved ASCII characters
  (`\ : * ? " < > |`, controls), so the two stages compose without ambiguity.
- No Unicode normalization (NFC/NFD) is applied. Names from macOS servers keep their NFD form.
- Text that is not a filename (server messages, banners, `longname`) is decoded as UTF-8, with invalid bytes replaced
  by U+FFFD, and sanitized with `sd_text_sanitize_server()` (control, bidi and zero-width characters removed,
  section 6.1, TM-R09).

### 10.8 Threading guarantees (summary)

1. All `sd_sftp_*` functions are thread-safe and non-blocking (except `*_sync`, `destroy`). Callers on any thread may
   submit concurrently. Internally, submissions are posted to the I/O thread of the connection that will carry them.
2. With a pool of 1 (the default), callbacks and events of one session run **on that session's I/O thread,
   serialized**, never concurrently with each other. With a larger pool, completions of requests carried by a
   secondary member run on **that member's** I/O thread, so completions of one session **may run concurrently**;
   completions of one request are still delivered exactly once, and state/pool events stay on the primary's
   thread. A striped request split across members completes on the thread that resolves its last part. No callback
   is ever invoked re-entrantly from within a submit call.
3. Inside a callback, the caller may submit further requests, call `cancel`, `addref`/`release`, and `session_close`.
   It must not call `*_sync`, `destroy` or anything that blocks: no waiting on locks held by threads that wait for
   sd_sftp completions. Callbacks should finish in under 1 ms. Heavy work belongs on the VFS's own threads.
   Following review §4.1 rule 1, a completion either fills the waiter's result block and calls `SetEvent`, or pushes
   the completion to the VFS background queue; it never takes a node or cache lock.
4. Pointers inside a completion are valid only during the callback. Copy what you need.
5. The read buffer is written only on I/O threads, and never after the request's completion has been delivered.
6. sd_sftp never calls back while holding one of its own locks (02 R18), and callers must not hold their own locks
   across a submission (review §4.1 rule 2).
7. `sd_sftp_session_destroy` waits for every I/O thread of the session to exit. Calling it on an I/O thread returns
   without destroying anything and logs an internal error (debug builds assert). `*_sync` wrappers,
   `sd_sftp_session_close` followed by `destroy`, and anything that waits on sd_sftp may be called only from the
   host control thread or CLI threads, **never from Dokany callbacks (including `Unmounted`), WebDAV workers or I/O
   threads** (review C33, §4.1 rule 3). The host's `Unmounted` handler only posts to its control thread.

### 10.9 Connection pool and bulk striping (D14, decisions.md D18)

(The NTSTATUS/HTTP mapping hints that used to be in this document are superseded by 02's normative
`sd_err` -> NTSTATUS/HTTP table, review C24.)

**What the VFS sees.** One `sd_sftp_session` per mount, whatever the pool size. `sd_sftp_options.connections`
(profile key `connections`, 1..4, default 1) is the *target* pool size; `server_info.connections` and
`sd_sftp_session_stats()` report the actual one. The only API surface specific to the pool is:
- `SD_SFTP_O_STRIPED` on `sd_sftp_open`: opt a data handle into striping (the VFS uses it for large sequential
  transfers, for example a copy or read-ahead stream; never for small or random-access files);
- `EV_POOL` events (informational), per-member statistics, and `session_ready` in completions;
- concurrency of completions (section 10.8 item 2).
Everything else (metadata, directory listings, ordinary handles) runs on the primary connection, exactly as with a
pool of 1.

**Admission rule (non-interactive authentication only).** After the primary connection is READY, sd_sftp reads
`sd_ssh_conn_auth_info()`. Secondary members are opened only if `noninteractive` is set, that is, on every hop no
prompt was shown to a user: keys without passphrase, agent keys, DPAPI blobs, cached secrets, or answers flagged
`SD_ANSWER_FROM_STORE`. Otherwise the pool stays at 1 for this generation and a log line says why. Secondaries are
created with `SD_SSH_CFG_POOL_MEMBER`, which makes `sd_ssh`:
- use the session's reconnect secret cache first;
- raise password/passphrase/proxy prompts with `is_pool_member = 1`, which the host must answer from stored secrets
  or cancel, never with UI; keyboard-interactive rounds with `may_autofill = 0` are cancelled without a callback;
- accept the host key only as `SD_HK_MATCH`/`SD_HK_MATCH_CA` without a prompt, with the host-key list restricted to
  the stored types (section 4.3, TM-R04). `NEW`/`NEW_TYPE`/`SD_E_HOSTKEY_TYPE_UNAVAILABLE` drops the member.
  `MISMATCH`/`REVOKED` drops the member, raises the normal host-key event and disables the pool for the session
  lifetime (it never fails the already-verified primary);
- skip banners, the legacy acknowledgement (the primary already passed it; a member negotiating a different legacy
  set is dropped) and UpdateHostKeys processing.
A member must also reach **the same server** as the primary: its target host key fingerprint and its
`realpath(".")` must equal the primary's (DNS round robin or a load balancer could otherwise mix servers, 02 §5.6).
A mismatch drops the member, is logged once, and stops further admissions for the generation.
Each member is a complete chain with its own I/O thread (ProxyJump hops and proxies included, sections 5.1-5.2). Members
are opened one at a time, 500 ms apart, so servers with `MaxStartups` limits or connection-rate bans are not hit
with bursts; a member refused by the server is retried with backoff and abandoned for the generation after 3
failures.

**Channels per member.** The primary has the meta and bulk channels (D8). A secondary opens **one bulk channel**
only (decisions.md D19), since metadata never goes there; its startup is INIT, VERSION, `limits` and the
`realpath(".")` check above.

**Transport view.** A pool transport reports `SD_SFTP_TP_POOL` and exposes every channel through the
`sd_sftp_transport` stream vtable: idx 0 is the meta channel, idx 1 the primary's bulk channel, idx 2..4 are pool
members 1..3. `open_stream`/`write_stream`/`consumed_stream` delegate idx 0..1 to the plain implementation and
serve idx 2..4 through per-member queues (received bytes are credited back to the member only once the session has
consumed them; writes queue bounded and are pumped on the member's own thread). `notify_ready` starts the
admissions of a generation and re-admits every member after a reconnect; `member_stats` writes `out[idx - 1]` for
every admitted member (member 1 is `out[0]`; the primary's own statistics are the session's `conn[0]`) and reports
their number in `*count`.

**Striping.** A striped handle is opened on the primary's bulk channel first (with the caller's flags, so `CREAT`,
`TRUNC` and `EXCL` take effect exactly once). `APPEND` handles, directories and meta handles are never striped (the
flag is ignored); with no live member the handle is simply served by the primary. Sub-handles on the secondaries
are opened lazily, on first use of a unit routed to that member, with
`oflags & ~(CREAT|TRUNC|EXCL|APPEND|STRIPED)`: the primary's OPEN already did the create/truncate, and the last two
bits are ours (wire pflags are masked to the protocol's 6 bits anyway). A member whose sub-open cannot be sent or
is refused falls back to the primary; the next barrier drops it from the routing. Striped requests run in their own
queue class `Q_STRIPE` beside the meta/bulk queues of section 10.5, and barrier wires carry the dedicated phase
`PH_STRIPED`, so their replies settle the barrier instead of the data path (both are internal, section 11). Routing:
- the file is divided into `stripe_bytes` units (option `stripe_bytes`, default 1 MiB, normalised at open time to
  the smaller of the negotiated `max_read`/`max_write` limits with a 512-byte floor, so one unit never exceeds what
  a single request may carry); unit `k = offset / stripe_bytes` goes to `route_map[k % route_n]`, a per-handle table
  listing the primary and every member whose sub-handle is open. The table is recomputed only at quiescent points -
  the FSTAT that completes the open and every completed barrier - so **requests that touch the same byte range
  always travel on the same connection, in submission order**;
- requests crossing a unit boundary are split at the boundary; every piece parks behind the member channel's limits
  (`max_inflight_reqs`, the channel output high water, `max_inflight_bytes`), never the whole request queue;
- `fstat`, `fsetstat` (including truncate), `fsync`, `fstatvfs` and `close` are **barriers**: they wait until the
  handle has no data wire in flight and no sub-open pending, then run on the primary handle and on every open
  sub-handle (`fstat`/`fsetstat`/`fstatvfs` need only the primary; `fsync` and `close` also go to every sub-handle
  that was opened). The barrier completes when all its wires have settled, first error wins, and its completion is
  the route-table recompute of the first bullet;
- `copy-data` is never striped (it uses the primary handle); `same_channel_as` refers to the primary sub-handle;
- `max-open-handles` is tracked per member, since each member is its own server process.

**Per-connection reconnect.** Each member has its own backoff loop (`reconnect` policy, at most once per 5 s per
member) that runs only while the session is READY.
- Losing a **secondary**: the session stays READY. Its in-flight **reads** are reissued on the primary handle
  transparently (reads are idempotent). Its in-flight **writes** complete with `SD_E_DISCONNECTED`,
  `maybe_executed = 1` and `session_ready = 1`, and are never replayed: the VFS may resubmit them at once on the
  same handle (it remains valid), in line with its write-mode rules; the write's wires on the surviving channels
  stay in the table, so their late acknowledgements are discarded instead of surfacing as protocol errors. Its
  sub-handles are released without a CLOSE (they died with the connection), a sub-open still on its wire fails with
  `SD_E_DISCONNECTED`, and a barrier wire it already carried counts as settled (the handle died with it). Until the
  handle's next quiescent point, the lost member's units go to the primary; then routing is recomputed over the live
  members.
- Losing the **primary**: this is the session-level disconnect of section 10.6. All secondaries are closed with it,
  all handles (including sub-handles) go stale, and after the next READY the members are re-admitted under the rule
  above.

**Limits and cost.** Every member is a full SSH session on the server (one more login, one more `sftp-server`
process, more audit-log lines), so the default stays 1 and policy can cap the value. Throughput gains come from
using several cores for crypto and several TCP windows; on a single fast connection with AES-NI the gain is small.

---

## 11. Internal structure of sd_sftp

- Per channel: an input reassembly buffer (grows up to 256 KiB + 13), an output encoder writing directly into
  channel packets, a request table keyed by request id (uint32, monotonically increasing per channel, skipping ids
  still in use after wrap), a pending FIFO and an in-flight counter.
- The reply dispatcher validates `id`, matches it to the request, and checks the reply type against the expected set
  for that request kind. A mismatch is `SD_E_PROTOCOL`, after which the channel is closed and the session reconnects.
  An unknown id is also `SD_E_PROTOCOL`.
- Startup per channel (primary connection: meta = channel 0, bulk = channel 1):
  1. `INIT(3)`
  2. `VERSION` + extensions
  3. `limits@openssh.com`, if offered
  4. on the meta channel only, `realpath(".")` for home, then `STAT` of home: its owner uid/gid fill
     `server_info.identity` with `SD_SFTP_ID_HOME_OWNER` (decisions.md D10), and the path selects quirks (section 4.9)
  5. only with `SD_SFTP_OPT_IDENTITY_EXEC` (profile `identity_probe = exec`, off by default): one `exec` channel
     running the fixed command `id -u; id -G`, stdout capped at 4 KiB, 5 s timeout; decimal parse into
     `identity` with `SD_SFTP_ID_EXEC`. Any failure (refused exec, `ForceCommand internal-sftp`, garbage) is
     logged at debug level and ignored. It runs once per generation and never delays READY by more than its timeout
  6. READY when both channels are up, or when the meta channel is up and the bulk channel failed (degraded to one
     channel with the meta-first scheduler). Pool members start afterwards (section 10.9)
- Users/groups cache: `uid -> name`, `gid -> name`, for display only (never for access decisions). Requests are
  batched (up to 64 ids per request) and filled from `longname` parsing when the extension is missing (best effort:
  the third and fourth fields of an `ls -l` line).
- Per-session request router: maps each request to a member and channel (section 10.5 classes, section 10.9
  striping), owns the `max_queued_reqs` budget, and holds the per-connection RTT/throughput meters of section 10.4.
- Handle limit: if `max-open-handles` is known, opens beyond the limit are queued, not failed. The VFS should close
  handles promptly. Directory listing helpers close their handle themselves.

---

## 12. Memory and safety practices for parsers

### 12.1 Bounded reader / writer (sd_buf)

```c
typedef struct sd_rd { const uint8_t *p; size_t n; int err; } sd_rd;    /* sticky error */
void     sd_rd_init(sd_rd *r, const void *p, size_t n);
uint8_t  sd_rd_u8(sd_rd *r);
uint32_t sd_rd_u32(sd_rd *r);
uint64_t sd_rd_u64(sd_rd *r);
int      sd_rd_bool(sd_rd *r);
sd_span  sd_rd_string(sd_rd *r, size_t max_len);          /* view into the buffer; len checked against n and max */
sd_span  sd_rd_mpint(sd_rd *r, size_t max_bytes);         /* rejects non-canonical (leading 00 not needed, negative) */
sd_span  sd_rd_name_list(sd_rd *r, size_t max_len);       /* validates ASCII, no empty names, no NUL */
sd_rd    sd_rd_sub(sd_rd *r, size_t max_len);             /* string as nested reader */
int      sd_rd_done(const sd_rd *r);                      /* !err && n == 0 (trailing garbage = error) */

typedef struct sd_wr { uint8_t *p; size_t len, cap, max; int err; } sd_wr;  /* growable, hard max, sticky OOM */
void sd_wr_u32(sd_wr *w, uint32_t v); void sd_wr_string(sd_wr *w, const void *p, size_t n); /* ... */
```

Rules:
- On error, reads return zero/empty values and set `err`. Callers check once at the end (`sd_rd_done`) before acting
  on any value, which removes most bounds-check bugs. No parser touches raw pointers except through `sd_rd`.
- Every length field gets a semantic maximum: name-lists 64 KiB, KEXINIT 64 KiB, host key blob 16 KiB, signature 16
  KiB, mpint 2050 bytes (16384-bit RSA + sign), SFTP names 64 KiB, handles 256 bytes, extension count 64.
- Checked size arithmetic helpers (`sd_add_ovf`, `sd_mul_ovf`). Allocation sizes are computed only through them.
- Strings from the network are never used as format strings, and are length-bounded before logging (512 bytes,
  escaped, with the TM-R09 removals of section 6.1). Remote paths and file names are logged at debug level only,
  except inside error records (TM-R31, T-58; the log policy itself is 03 §10.1's).
- Allocations go through `sd_alloc` (`sd_platform`), with a failure-injection hook for tests. Every allocation
  failure is `SD_E_NO_MEMORY`, never a crash. Memory is never freed across a public API boundary: every API that
  returns memory has its own free function. Large buffers (Argon2) use `VirtualAlloc`.
- Packet input buffer: one per connection, capped at 256 KiB + MAC + 64. A larger length field means disconnect.
- Proxy handshakes (section 5.2) use the same bounded reader: HTTP response headers <= 16 KiB / 100 lines, SOCKS5
  replies validated field by field.
- Compiler/linker flags: **04 §3.2 is normative** for every flavour (review C36). For this module that means `/GS`,
  `/W4 /WX`, `/DYNAMICBASE /NXCOMPAT`, `/SAFESEH` on x86, `/HIGHENTROPYVA` on 64-bit; `/sdl` and `/guard:cf` only on
  v143 targets (`x64-modern`, ARM32, ARM64; decisions.md D28); no `/guard:cf` on v141_xp builds until lab-verified;
  `/arch:IA32` vs `/arch:SSE2` per x86 flavour (decisions.md D4). The code must stay CET shadow-stack compatible for
  `x64-modern` (no inline assembly on x64, no non-standard returns). `/analyze` runs in CI with SAL annotations on the
  public APIs.
- Secret handling: `sd_secbuf` for passwords, passphrases, private keys and session keys. Zeroized on free; never
  logged. Debug logs print fingerprints, never key material. Stack locals holding secrets are wiped before return
  (rule 2.4.8). **Crash dumps (TM-R30, T-57):** every chain I/O thread registers itself for its lifetime, and every
  KDF, key-loading and agent work item for its duration, through `sd_dump_mark_sensitive()` (the `sd_platform`
  secret-thread registry); the host's `MiniDumpCallback` (03 §10.4) always omits the stacks of registered threads
  (there is no option to include them, decisions.md D43).
  sd_* modules never write dumps themselves.

### 12.2 Fuzzing plan

Parsers are portable C without `windows.h` (D11), so the same harness builds on Windows (clang-cl
`-fsanitize=fuzzer,address`, or MSVC `/fsanitize=fuzzer /fsanitize=address`, x64) and in the optional Linux fuzz job
with clang + ASan/UBSan/MSan (decisions.md D21: test infrastructure only, nothing of it ships).

| Target | Input |
|--------|-------|
| `fuzz_packet` | transport packet stream through decrypt-none -> message dispatcher, with a state machine stub per state |
| `fuzz_kexinit` | KEXINIT parsing + negotiation against our lists |
| `fuzz_kex_reply` | KEX_ECDH/DH/GEX replies, incl. host key blob + signature parse |
| `fuzz_userauth` | INFO_REQUEST, BANNER, FAILURE, PK_OK |
| `fuzz_channel` | channel messages with window arithmetic invariants asserted |
| `fuzz_sftp_reply` | SFTP reply stream reassembly + all reply types + EXTENDED_REPLY decoding |
| `fuzz_attrs` | ATTRS incl. extended pairs |
| `fuzz_keyfile_openssh`, `fuzz_keyfile_pem`, `fuzz_keyfile_ppk`, `fuzz_der` | key files (KDF rounds clamped in fuzz builds) |
| `fuzz_cert` | OpenSSH certificate blobs |
| `fuzz_known_hosts` | known_hosts lines + lookup |
| `fuzz_putty_hostkey` | PuTTY registry value names + data |
| `fuzz_agent_reply` | agent IDENTITIES_ANSWER / SIGN_RESPONSE |
| `fuzz_utf_names` | byte <-> UTF-16 round trip (asserts bijection, and that `sd_name_from_wide` never emits `/` or NUL, TM-R11) |
| `fuzz_text_sanitize` | `sd_text_sanitize_server`/`_host`: output never contains controls, bidi or zero-width characters (TM-R09) |
| `fuzz_proxy_http`, `fuzz_proxy_socks5` | proxy handshake replies (status line, headers, 407 rounds, SOCKS5 method/auth/connect replies) |
| `fuzz_hostkeys` | `hostkeys-00` announcements and `hostkeys-prove-00` replies |
| `fuzz_mlkem` | ML-KEM ciphertexts and encapsulation keys (decaps never crashes; implicit rejection holds) |
| `fuzz_field25519`, `fuzz_fieldp`, `fuzz_bn_modexp` | differential against the test-only reference bignum (section 2.7.4) |
| `fuzz_inflate` | zlib@openssh decompression (M7) |

- Seed corpora: captures from interop runs (with keys from fixtures), plus the fixtures directory.
- CI: each target runs 5 minutes on every PR touching `src/sd_ssh|sd_sftp|sd_crypto`, and 1 hour nightly. The corpus is kept
  in a separate repository branch. Crashes become regression tests under `tests/regress/`.
- WinAFL (DynamoRIO instrumentation) runs as a nightly black-box fuzzer of the **real binaries**: the `x64-xp`
  build from M0 and both x86 v141_xp builds (`x86-ia32`, `x86-sse2`) from M1 (TST-01), using a test-mode driver
  that feeds a socket replay file. This catches issues that only appear with
  the shipping compiler/toolset.
- Differential fuzzing of crypto: own vs CNG (section 2.7.3) and own arithmetic vs the independent test-only reference
  (section 2.7.4). No third-party crypto library is built, even for tests (D13).
- Stateful protocol fuzzing: an in-process mock SSH server (test-only, uses our own crypto) mutates messages
  mid-session (after KEX), with the encryption layer set to `none` in a fuzz build flag. That flag is compiled out of
  release builds, and the release-binary check (TST-30) fails if the `none` cipher, fuzz hooks or test-only MITM
  code appear in any shipped binary (T-06).

### 12.3 Interop test matrix

Servers: OpenSSH 7.4 / 8.x / 9.x / 10.x (strict-kex, mlkem), Win32-OpenSSH, Dropbear (with OpenSSH sftp-server),
ProFTPD mod_sftp, Bitvise SSH Server, Apache MINA SSHD, AsyncSSH, Paramiko, Synology/QNAP firmware (lab), Cisco/legacy
(3des/group1 via an old OpenSSH build).

Proxies: Squid (HTTP CONNECT with Basic and with Negotiate/NTLM against a lab domain), Dante (SOCKS5 with and
without username/password), and the WinHTTP system-proxy paths (static, PAC, WPAD) in the lab. Pool: OpenSSH with
`MaxStartups`/`MaxSessions 1` variants to check admission, the bulk-channel degrade and member backoff.

CI infrastructure (decisions.md D21): a WSL sshd fixture on the Windows runners plus Win32-OpenSSH sshd locally;
exotic servers in the self-hosted lab; an optional Linux fuzz job. All of it is test infrastructure and never ships.

### 12.4 Security tests from the threat model

The tests of 05 §7 that exercise this module, with the milestone that must pass them (P1 blocks the milestone demo,
P2 the next milestone, P3 1.0). They are test-only code; the Terrapin MITM proxy and the mock servers never ship
(TST-30).

| Test | M | P | What it checks here | Design refs |
|------|---|---|---------------------|-------------|
| TST-01 | M0 | P1 | every 12.2 fuzz target of the M0 parsers present on day one (5 min per PR); WinAFL on `x64-xp` from M0, x86 from M1 | T-06; 12.2 |
| TST-02 | M1 | P1 | fuzzing of shared parsers this module feeds (stage-1 name helpers, `fuzz_text_sanitize`) | T-37; 10.7, 6.1 |
| TST-03 | M0 | P1 | disassembly check: no `_all*`/`_aull*`/`__rt_*` helper call, no 64x64 multiply, no branch or `div` in constant-time code on `x86-ia32`, `x86-sse2`, ARM32; dudect with high-word-zero/all-ones classes on 32-bit flavours (from M1) | T-03; TM-R02, 2.4, 2.7.5 |
| TST-04 | M0 | P1 | KAT/Wycheproof/CNG differential per primitive plus negative transcripts: all-zero X25519 output, invalid ECDH points, non-canonical Ed25519 S, Poly1305/GCM tag bit flips, no decryption output before MAC | T-04; 2.7 |
| TST-05 | M0 | P1 | stage-1 part: `sd_name_from_wide` never yields `/` or NUL; `sd_name_component_check` rejects empty, `.`, `..`; mock-server dirents with `/`, NUL, `.`, `..`, empty names and 64 KiB names are dropped and counted | T-23, T-24; TM-R11, TM-R12, 10.5, 10.7 |
| TST-08 | M1 | P2 | mock-server DoS corpus at the sd_sftp level (READDIR without EOF, huge counts, 2^64-1 sizes, drip-fed replies): deadlines fire, memory stays bounded by the packet and queue caps; the per-listing caps are 02's (TM-R16) | T-30; 10.5, 12.1 |
| TST-11 | M0 | P1 | mismatch blocks (M0); NEW_TYPE for a known host fails with `host_key_type_unavailable` and no prompt, including on reconnect and for pool members (M0 for the types that exist, ed25519 vs ecdsa in M2); after "remove old key + TOFU" no stored password, kbd-int answer or cache entry is sent and `SD_ANSWER_FROM_STORE` is rejected (M2) | T-08, T-09, T-10; TM-R04, TM-R05, 4.3, 6.4, 7.1, 8 |
| TST-12 | M2 | P1 | Terrapin interop with a test-only prefix-truncation MITM against a non-strict server: with TM-R01 the connection uses GCM/CTR (or CBC with a non-ETM MAC) and survives the attack attempt, or reports `TERRAPIN_EXPOSED` when only affected pairs exist, or fails with `refuse_terrapin_exposed`; with strict KEX the injection is fatal; the 3 s fallback path is covered with a server that waits for the client KEXINIT | T-01; TM-R01, 4.2, 4.3 |
| TST-13 | M2 | P1 | legacy matrix on lab servers (3DES, group1, small GEX, old OpenSSH): `allow`/`warn`/`ask`/`refuse` behave as documented, `warn` is the default and never holds (D33), no legacy algorithm is chosen when a modern one is offered in that category, also with the TM-R01 per-connection lists; GEX 1024-2047 is accepted with `SD_LEGACY_DH_SMALL` (TM-Q01 floor not adopted) | T-02; 4.2, 4.3 |
| TST-14 | M2 | P2 | live sources: a `known_hosts` (or `.ssh` folder, or PuTTY key) writable by another user, a reparse point and a FAT copy are skipped with `SD_KH_SRC_INSECURE`; wildcard-only lines yield no MATCH and no stored type but still MISMATCH; a mismatch in a source blocks | T-11; TM-R06, 7.2 |
| TST-15 | M2 | P1 | UpdateHostKeys negatives: unproven key, proof over another session id, `ssh-rsa` proof with legacy refused, announcement after TOFU/once, wildcard entry, secondary pool member | T-12; 7.5 |
| TST-16 | M2 | P2 | pool: DNS round robin to two servers with different keys or homes; member dropped, pool disabled, primary unaffected | T-14; 10.9 |
| TST-17 | M2 | P2 | agent squatting: a second user creates `\\.\pipe\openssh-ssh-agent`; a `Pageant` window class registered by a low-IL process and by another user's `runas` process; the client sends nothing to either and logs `agent_untrusted` | T-16, T-17; TM-R08, 6.5 |
| TST-18 | M2 | P1 | proxy NTLM harvesting: a test proxy answering `407 NTLM` and `407 Negotiate` (NTLM fallback) with `proxy_auth = auto`; a WPAD/PAC-discovered proxy without `AllowSystemProxySspi`; no SSPI token leaves in either case; Squid Kerberos in the lab domain still works with `auto`, NTLM with `negotiate`; XP `PackageList` behaviour recorded | T-20, T-22; TM-R10, 5.2 |
| TST-28 | M3 | P2 | dump hygiene: crash during a password prompt, during KEX and during a KDF with a known test password and key; the dump contains neither (registered thread stacks omitted, stack locals wiped) | T-57; TM-R30, 2.4.8, 12.1 |
| TST-30 | M0 | P2 | release binaries contain no `none` cipher, no fuzz hooks, no test MITM or mock-server code | T-06; 12.2 |
| TST-33 | M2 / M6 | P1 | external crypto review: pass 1 findings closed before any public beta (end of M2), pass 2 before 1.0 (decisions.md D38) | T-04; 2.7.6 |

---

## 13. Milestones (mapped onto the project milestones of review §6)

This module no longer has its own M1-M3; its work is scheduled inside the cross-project milestones.

| Milestone | Content for sd_crypto / sd_ssh / sd_sftp |
|-----------|-------------------------------------------|
| M0 - x64 Win10 vertical slice | `sd_base`/`sd_platform` consumers, RNG, SHA-2/HMAC, AES (own + CNG), ChaCha20-Poly1305@openssh, **own GF(2^255-19) arithmetic**, X25519, Ed25519. KAT + Wycheproof + CNG differential harness (section 2.7) from day one. Transport with curve25519, strict KEX, ext-info; password and Ed25519 key files (unencrypted and bcrypt); `known_hosts` TOFU (user store). SFTP core ops, pipelining, one channel. Fuzz targets for all of the above. Threat-model items: KEXINIT after the server's KEXINIT with the TM-R01 list construction and the 3 s fallback, host-key list restricted to stored types (TM-R04) with `SD_E_HOSTKEY_TYPE_UNAVAILABLE`, `sd_ct64.h` and the call-following disassembly check (TM-R02), stack wiping (rule 2.4.8), `sd_text_sanitize_*` (TM-R09), stage-1 component invariant and dirent dropping (TM-R11, TM-R12), user-store DACL on write (TM-R07); TST-01, -03, -04, -05, -11 (mismatch, NEW_TYPE), -30. |
| M1 - Resilience and WebDAV | Reconnect (sections 8, 10.6), per-request deadlines + liveness probe (D17), meta/bulk channels and the meta-first scheduler (D8), `max_queued_reqs`, R10 extended attributes, R12 server identity, R13 identity hooks (home owner; `identity_probe = exec`), R16 statistics. `x86-ia32` and `x86-sse2` builds green (D18), dudect on all x86 flavours with the TM-R02 input classes (TST-03); WinAFL on both x86 builds (TST-01); TST-02 (sanitizer, names), TST-08. |
| M2 - Authentication breadth | Own Montgomery field engine and `sd_bn` (section 2.8); ECDSA/ECDH P-256/384/521, RSA, DH/GEX; **SHA-3/SHAKE, ML-KEM-768 and `mlkem768x25519-sha256`** (decisions.md D15); legacy algorithms, `legacy_mask`, `SD_PROMPT_LEGACY_ACK`, Terrapin policy; kbd-interactive/OTP, password change; PEM/PKCS#8, PPK v2/v3 (Argon2); certificates (user + host CA); Pageant + OpenSSH agent; ProxyJump N hops; **HTTP CONNECT / SOCKS5 proxies, proxy auth, system proxy** (D15); `SD_ID_BLOB`, key probe/serializer; `known_hosts` store list + live sources (D10); **UpdateHostKeys** (D16); **connection pool and striping** (D14), which needs the stored-secret paths of this milestone. Interop matrix job incl. proxies and OpenSSH 10. Threat-model items: no stored secrets after a fresh host-key acceptance (TM-R05), live-source ACL and wildcard rules (TM-R06), agent authenticity checks (TM-R08), proxy SSPI restrictions (TM-R10), `identities_only` default (decisions.md D37), `via_host` in host-key prompts (TM-R03 support), `sd_ssh_conn_fetch_hostkeys` (TM-R04 "add key"); TST-11 (re-TOFU), -12 to -18. **External crypto review pass 1 at the end of M2** (decisions.md D38, section 2.7.6); no public beta before its blocking findings are closed. |
| M3-M5 | No new protocol scope. Support for the UI (prompt kinds, events), service context (machine store, DPAPI service keys, no agents), and fixes from interop and lab runs, including fixes from review pass 1. M3: secret-thread registry hooks for the host's minidump callback (TM-R30) and TST-28. |
| M6 - Architectures, performance, 1.0 RC | SHA-NI / AES-NI / ARMv8 fast paths tuned, ARM64 and ARM32 (best effort) crypto paths (dudect and disassembly checks on ARM32 included, TM-R02), striping and pool performance against 02 §11 targets, nightly fuzzing at scale, **external crypto review pass 2** (section 2.7.6, decisions.md D38) with findings closed before 1.0 (TST-33). |
| M7 - Post-1.0 | `zlib@openssh.com`, adaptive channel windows, Solinas-specialized NIST reductions, optional bit-interleaved Keccak for 32-bit targets. |

---

## 14. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Bugs in our own crypto, including field and bignum arithmetic, with no verified third-party code to lean on (D13) | security | the six verification layers of section 2.7 (KATs, Wycheproof, CNG differential, independent reference arithmetic + fuzz-differential, dudect + disassembly checks, interop) gated per primitive; two-person review; external review in two passes, end of M2 and before 1.0, no public beta before pass 1 (decisions.md D38, T-04) |
| Side channels in own code (MSVC optimizes masks into branches; compiler runtime helpers such as `_allmul` are variable time on 32-bit targets, T-03) | key leakage | value barriers; own `sd_ct64.h` 32x32-based primitives and a ban on runtime-helper calls in constant-time code (TM-R02); call-following disassembly checks on every flavour incl. `x86-ia32` and ARM32; dudect on x64/ARM64/x86 (ARM32 in the lab) with high-word-zero classes; prefer CNG on Vista+ for long-term keys where section 2.2 allows |
| Terrapin on servers without strict KEX (T-01) | dropped `EXT_INFO`, SHA-1 user signatures | cipher/MAC lists built after the server's KEXINIT (TM-R01, decisions.md D34); exposure flag and warning only when the server offers nothing unaffected |
| Host-key downgrade to a prompt or auto-sent secrets (T-09, T-10) | MITM gains a password | host-key list restricted to stored types, `NEW_TYPE` fails without a prompt (TM-R04); no stored secrets after a fresh acceptance (TM-R05) |
| Spoofed agents, harvested proxy credentials (T-16, T-17, T-20) | stalled or observed signing, NetNTLMv2 leak | owner/SID/integrity checks before any agent request (TM-R08); SSPI only to configured proxies and Kerberos-only by default (TM-R10) |
| Waiting for the server's KEXINIT stalls with servers that wait for the client first | connect delay | 3 s fallback with Terrapin-aware ordering (section 4.2); interop matrix covers it |
| Schedule: writing P-curve, RSA and ML-KEM arithmetic ourselves moves work into M2 | delay | generic Montgomery engine shared by P-curves, scalar fields and `sd_bn`; specialized reductions deferred to M7 |
| XP performance (no AES-NI, x86 bignum; `x86-ia32` without any vector path): RSA-4096 sign ~100-200 ms, Argon2 on 2006-era CPUs takes seconds | UX | work runs on worker threads; prefer ed25519; ChaCha20 first without hardware AES; cache decrypted keys per session when allowed |
| CNG behaviour differences across versions (GCM on Vista SP1, raw secret 8.1+, blob formats) | interop failures on specific OS builds | capability probing instead of version checks; CI on Win7/8.1/10/11 VMs; fallback to own code on any CNG error during probe |
| SFTP server diversity (symlink order, short reads, FAILURE-for-everything, max handles, odd limits) | wrong semantics | quirks table; refinement probes; interop matrix |
| Pageant variants (deferred decryption blocks for long; older builds with 8 KiB limit; SID checks) | auth hangs/failures | agent I/O on workers with timeouts; small requests; clear errors |
| Reconnect semantics for mutating ops (`maybe_executed`), now also per pool member | data inconsistency | explicit flags (`maybe_executed`, `session_ready`), never auto-replay writes; VFS re-stats |
| Connection pool: extra logins trigger server rate limits (`MaxStartups`, fail2ban), audit noise, `MaxSessions` | members refused, user's IP banned | default 1, staggered member opens, backoff and abandonment after 3 failures, admission only with non-interactive auth, policy cap |
| Concurrent completions with pool > 1 expose VFS races that never show with one I/O thread | data corruption, deadlocks | review §4.1 rule 1 (no locks in completions); 02's mock-`sd_sftp` conformance suite runs with a simulated pool of 4 |
| Proxy diversity (NTLM connection reuse, PAC/WPAD, IE `socks=` historically meaning SOCKS4) | connect failures behind corporate proxies | lab matrix (Squid, Dante, PAC/WPAD); explicit per-profile proxy always available; clear `SD_E_PROXY*` errors with status codes |
| UpdateHostKeys adds trust data (automatically with `update_host_keys = yes`) | a bug could weaken host verification | strict preconditions (section 7.5), whole-update rejection on any bad proof, removals only after user review, never the machine store without policy, `ask` default per profile, fuzzed parser |
| Post-quantum: OpenSSH 10.1+ clients warn on non-PQ KEX, and server-side policies may follow | future interop | `mlkem768x25519-sha256` in M2, first in our KEX list |

---

## 15. Open questions

All earlier user decisions are resolved by `decisions.md` (D1, D2, D7, D8, D15-D21; see section 17). What remains are
lab verifications and details for the implementers:

1. **Lab:** NTLM/Negotiate proxy authentication through SSPI on XP SP3 (connection-based auth over our socket),
   and whether any target proxy needs `Proxy-Connection: keep-alive` for it.
2. **Lab:** what the IE/WinHTTP `socks=` entry means on each OS (SOCKS4 vs SOCKS5). If it is SOCKS4 in practice, the
   system-proxy source ignores it and logs a hint to configure SOCKS5 explicitly.
3. **Interop:** which signature algorithm OpenSSH uses for RSA keys in `hostkeys-prove-00` replies across 7.x-10.x,
   to confirm the acceptance rule of section 7.5.
4. **Measurement:** default `stripe_bytes` (1 MiB) and the gain of pool sizes 2-4 on the 02 §11 setups, before M6
   fixes the recommended values in the UI.
5. **Lab (T-05):** confirm that XP SP3's `RtlGenRandom` contains the fix for the generator weaknesses published for
   Windows 2000/XP (ePrint 2007/419); record the result in the admin guide.
6. **Lab (TM-R10):** whether a Negotiate `PackageList` of `"!ntlm"` restricts SSPI to Kerberos on XP SP3, Vista and
   7 (section 5.2).
7. **Lab (TM-R02):** dudect of `UMULL`-based field code on the ARM32 lab device, to confirm constant-time 32x32
   multiplication on the Cortex-A cores of Windows ARM32 hardware.
8. **Interop (TM-R01):** whether any server in the matrix waits for the client's KEXINIT before sending its own, and
   whether 3 s is the right fallback delay.
9. **Interop (TM-R04 "add key"):** which servers (OpenSSH 7.x-10.x, Dropbear, Bitvise, ProFTPD mod_sftp) accept a
   client-initiated re-key whose host-key list differs from the first KEX, for the not-announced case of
   `sd_ssh_conn_fetch_hostkeys()` (section 4.3); servers that refuse it are covered only through `hostkeys-00`.

---

## 16. What other teams must know (interface summary)

- **sd_vfs / WebDAV / Dokany (02):**
  - Use `sd_sftp.h` only. `sd_err` names in section 10.2 are canonical; the NTSTATUS/HTTP mapping is yours.
  - sd_sftp refines `SD_E_FAILURE`; do not probe again (review C14).
  - Always pass a deadline (`timeout_ms`): 25 s on Dokany, 50 s on WebDAV. A timeout triggers a liveness probe, and
    a dead link surfaces as `SD_E_DISCONNECTED` events within the Dokany deadline.
  - Issue reads/writes of at most `max_read`/`max_write`: each is exactly one wire request (review C15).
  - Metadata automatically goes to the meta channel; use `SD_SFTP_REQ_CLASS_META` for attribute-only opens.
  - `SD_E_BUSY` means the session queue budget is full: back off and resubmit.
  - With `connections > 1`, completions can run concurrently on several I/O threads; follow review §4.1 rule 1.
    Use `SD_SFTP_O_STRIPED` only for large sequential transfers; `fstat`/`fsetstat`/`fsync`/`close` on such handles
    are barriers. A write that fails with `session_ready = 1` may be resubmitted at once on the same handle.
  - Never call `*_sync`, `close`+`destroy` or anything blocking from Dokany callbacks (including `Unmounted`) or
    WebDAV workers (review C33).
  - Callbacks run on I/O threads: keep them short, never block.
  - Paths are raw bytes; use `sd_name_to_wide`/`sd_name_from_wide` (stage 1) and apply your stage 2 per component.
    Your stage-2 inverse must map back only the code points the forward map produces, and every component must pass
    `sd_name_component_check` after both stages (TM-R11).
  - `readdir` already drops empty, `/`/NUL-containing and `.`/`..` names (`dropped` counts them); duplicates and
    stage-2 collisions are yours (TM-R12).
  - Ordering is guaranteed only per handle (per byte range when striped).
  - Handles go stale on reconnect: call `sd_sftp_file_reopen()`, compare the returned attrs, and honor
    `maybe_executed`.
  - Re-read `server_info` on every `READY_INFO`; `identity` gives the home owner (and exec results if enabled);
    confirm the uid/primary gid from the first file you create (decisions.md D10).
  - `sd_sftp_session_stats()` gives RTT and throughput for read-ahead sizing (02 R16).
  - `SD_SFTP_RENAME_OVERWRITE` returns `SD_E_UNSUPPORTED` without posix-rename; the fallback is your decision.
- **Host / UI / CLI / tray (03):**
  - Prompts are asynchronous objects (`sd_prompt`), answered from any thread; `on_prompt` only enqueues.
  - New prompt kinds: `LEGACY_ACK` (hold before userauth when policy is `ask`) and `PROXY_PASSWORD`. Answers from
    Credential Manager/DPAPI must carry `SD_ANSWER_FROM_STORE`; prompts with `is_pool_member = 1` must never show
    UI (answer from stored secrets or cancel; 03 maps a cancelled member to `warning pool_limited`).
  - Host key mismatch has no accept path. UpdateHostKeys arrives as the event `SD_HKEV_ANNOUNCED` (proven additions,
    removal candidates, target store); the host applies it with `sd_known_hosts_add`/`_remove` (03 §5.6,
    IPC `hostkeys.announced`).
  - Threat-model changes that need 03 (TM-R03/R04/R05/R06/R08/R09/R10, decisions.md D37): the new error
    `host_key_type_unavailable` (IPC code, exit code, message pointing to the host key manager); an "add a key of
    another type" action in the host key manager that calls `sd_ssh_conn_fetch_hostkeys()` inside a verified
    connection (03 §6.1 `hostkey add --from-server`); prompts with
    `hostkey_just_accepted = 1` are never answered from Credential Manager and show the "identity was just accepted"
    note; the host-key dialog uses `via_host` ("reached through jump host ..."); warnings
    `hostkey_source_insecure` (from `sd_known_hosts_source_state`) and `agent_untrusted`; server text arrives
    sanitized but the hop host must still be rendered outside the server-text area; `identities_only` defaults to
    yes when a hop configures an identity; machine policy `AllowSystemProxySspi` (default 0) feeds
    `sd_proxy_cfg.allow_discovered_sspi`.
  - `legacy_mask` bits drive the warnings (TERRAPIN has its own text); derive per-algorithm flags from the
    negotiated names plus the mask.
  - Prompts carry `hop_index` for ProxyJump.
  - `sd_err_name` already uses your IPC spellings (`host_key_*`, `dns_failed`, `prompt_required`,
    `proxy_connect_failed`, `proxy_auth_failed`, `legacy_refused`); the `sd_err` -> IPC -> exit-code table is yours.
  - The user-visible strings are yours to localize. sd_* returns only enum codes plus English diagnostics for logs.
  - Profile keys this module consumes, for 03's single schema table (review C46): `channels` (1-2), `connections`
    (1-4), `identities_only`, `cache_secrets_for_reconnect`, `refuse_terrapin_exposed`, `crypto_backend`,
    `legacy_algorithms` (`allow|warn|ask|refuse` -> `SD_LEGACY_ALLOW|WARN|ASK|REFUSE`), `host_key_alias`,
    `update_host_keys` (`ask|yes|no` -> `sd_hku_mode`), `identity_probe` (`owner|exec`; `exec` sets
    `SD_SFTP_OPT_IDENTITY_EXEC`), `keepalive`, `connect_timeout`, `connection.compression` (`yes|no`, default `no`; sets `SD_SSH_CFG_COMPRESS`). Proxies use 03's per-leg keys (03 §3.8): `proxy` /
    `proxy.K` (spec `none|system|http://[user@]host[:port]|socks5://[user@]host[:port]`) for leg K, which is
    `hops[K-1].proxy`; `sd_mount` parses the spec into `sd_proxy_cfg` (kind, host, port, user; `remote_dns` always
    1, 03 uses socks5h semantics). `proxy_auth` maps `auto` -> `BASIC|SSPI_KERBEROS` (TM-R10: Negotiate restricted
    to Kerberos), `basic` -> `BASIC`, `negotiate` -> `SSPI` (Kerberos with NTLM fallback, bare NTLM), `none` -> 0; SOCKS5 sets `USERPASS` when a user is given. `proxy_fallback_direct` (`no`) applies to
    `system`. Plus the known_hosts live-source switches (`[hostkeys] openssh_source`, `putty_source`; default on;
    policy `DisableKnownHostsSources`) and the policy `UpdateHostKeys` (03 §3.5; `2` lets the service update the
    machine store).
- **Credentials (03 §4):** password and passphrase prompts carry `key_fingerprint`/`key_path`/`host`/`user`/
  `may_autofill`, so Credential Manager lookups can answer without UI. OTP rounds never auto-fill. `sd_ssh` owns the
  reconnect cache; the host keeps none of its own (review C20). DPAPI-kept keys are passed as `SD_ID_BLOB`;
  `sd_ssh_key_probe` and `sd_ssh_key_serialize_openssh` support the import flow (review C22).
- **known_hosts (03 §5):** use `sd_known_hosts` for every read/write; pass the ordered store list (machine, user,
  live sources). Entries are written plain.
- **Service:** no agents in service context (decisions.md D17); DPAPI service keys as `SD_ID_BLOB`. The machine
  known_hosts lives in `%ProgramData%\LibreStatic\ShellDrive\known_hosts`; the service is the only writer. The system proxy in
  the service is the WinHTTP machine setting.
- **Build (04):** two x86 crypto flavours (`x86-ia32` without any vector code, `x86-sse2`), `x64-modern` with CFG/CET,
  flags per 04 §3.2. `sd_stubcore` reuses the `x86-ia32` sources for SHA-2 and Ed25519 verify. No `third_party/`
  for these modules. CI runs the call-following disassembly check of section 2.7.5 on `x86-ia32`, `x86-sse2` and
  ARM32 objects as an M0 gate (TM-R02, TST-03), WinAFL on `x64-xp` from M0 (TST-01), and the release-binary check
  (TST-30). Release gating: no public beta before external review pass 1 is closed (decisions.md D38).
- **Crash handling (03 §10.4):** the `MiniDumpCallback` consults the `sd_platform` secret-thread registry
  (`sd_dump_mark_sensitive()`) and always omits registered threads' stacks (TM-R30, decisions.md D43).
- **Updater:** reuse `sd_ed25519_verify` + SHA-512 from sd_crypto for release signatures.

---

## 17. Changelog: integrated decisions

Applied on 2026-10-24 from `decisions.md` and `00-integration-review.md`:

- **decisions.md:** D1 (zero third-party code; sections 2.2, 2.5, own arithmetic 2.8, verification 2.7, D13), D2
  (own hashes/HMAC, CNG reference only; 2.2), D4 (`x86-ia32` + `x86-sse2`, scalar paths without SSE2, runtime
  detection only in SSE2/x64/ARM builds; 2.3, D18), D7 (live read-only sources on by default; 7.2), D8 (plain
  `known_hosts`; 7.2), D9 (write-through default noted; 10.6), D10 (uid/gid hooks without exec, optional exec probe;
  10.3, 11), D15 (ML-KEM-768 hybrid + SHA-3/SHAKE in M2; 2.x, 4.3, 13), D16 (UpdateHostKeys; 7.5), D17 (no agents
  in the service; 6.5), D18 (connection pool + striping; 10.9, D14), D19 (meta + bulk channels; 4.8, 10.5, D8),
  D20 (HTTP CONNECT / SOCKS5 proxies, proxy auth, system proxy, no ProxyCommand; 5.2, D15), D21 (Linux and
  OpenSSH as test infrastructure only; 12.2, 12.3), D28 (`x64-modern` flags; 12.1).
- **Review conflicts:** C13 (canonical error names), C14 (refinement only in sd_sftp), C15 (one wire request per
  chunk-sized call), C16 (deadlines + liveness probe; 4.6, 10.5), C17 (request classes), C18 (identity, exec
  channel), C19 (store list, sole owner of known_hosts I/O), C20 (sole owner of the reconnect cache), C21
  (`SD_PROMPT_LEGACY_ACK`), C22 (`SD_ID_BLOB`, key probe, serializer), C23 (stage-1/stage-2 name mapping), C24
  (mapping hints removed, 02 normative), C25 (`sd_err_name` spellings), C33 (no destroy/sync from Dokany
  callbacks), C34/C35 (x86 floor per D4, `sd_stubcore`), C36 (04 §3.2 flags normative), C37 (per D1), C39 (`sd_base` /
  `sd_platform`, `sd_platform_resolve`), C40 (04 layout), C46 (profile keys listed for 03's schema).
- **02 requirements:** R3 (`sd_sftp_has_ext`), R5 (`max_queued_reqs`, `SD_E_BUSY`), R10 (extended attribute
  pairs), R12 (raw extension list, Windows-path quirk), R13 (identity hooks), R14 (meta/bulk), R15 (deadlines,
  probe), R16 (`sd_sftp_session_stats`), R18 (no callbacks under locks). R1, R2, R4, R6-R9, R11, R17 were already met.
- **Review §4.1 threading rules** 1-4 and 7 restated in sections 3.1, 7.2 and 10.8; review §6 milestones adopted
  in section 13.
- Removed: the vendoring plan (fiat-crypto, Monocypher, BearSSL, PQClean/mlkem-native), the 01-local milestones
  M1-M3, the hashed-`known_hosts` option, `default_timeout_ms = 0`, the `allow_legacy` flag (replaced by
  `legacy_policy`), the informative NTSTATUS/HTTP table, and all `[USER DECISION]` markers and resolved open
  questions.
- Final reconciliation 2026-10-24: 7.2 now follows D7 strictly (a mismatch in any store or source blocks; the "our
  stores win" exception is gone) and uses 03's source-comment format; 7.5 UpdateHostKeys is an event
  (`SD_HKEV_ANNOUNCED`), `sd_ssh` never writes a store itself, removals need review, default `ask`, machine store
  only under policy `UpdateHostKeys = 2` (03 §3.5; `UpdateHostKeysMachine` and `SD_PROMPT_HOSTKEY_UPDATE` removed);
  `sd_err_name` spellings `proxy_connect_failed` / `legacy_refused` (03 §6.2); system-proxy resolution stated as
  owned by `sd_ssh`; Basic proxy auth excluded per profile via `proxy_auth`, not by a policy; deadlines are set by
  the caller (30 s default only for callers passing none); pool members must match the primary's host key and
  home and open a bulk channel only (D19); section 16 maps 03's profile keys (`identity_probe = owner|exec`,
  per-leg `proxy`/`proxy.K`, `proxy_auth`, `proxy_fallback_direct`, `legacy_algorithms` -> `legacy_policy`).

### Threat-model integration 2026-10-24

Applied from `05-threat-model.md` §8 as accepted by decisions.md D33-D39:

- **TM-R01** (decisions.md D34; T-01): KEXINIT sent after the server's KEXINIT; per-connection cipher/MAC lists
  avoid chacha20-poly1305 and CBC+ETM without strict KEX, preferring AES-GCM then AES-CTR; exposure flag and warning
  only when nothing unaffected is offered; `refuse_terrapin_exposed` now fails before KEXINIT instead of
  reconnecting; 3 s fallback lists (0 D5, 4.1, 4.2, 4.3, 9, 13, 14).
- **TM-R02** (T-03): `_allmul` assumption withdrawn; `sd_ct64.h` 32x32-based multiplication and own 64-bit shift
  and comparison primitives; no compiler runtime helper calls in constant-time code on 32-bit targets; call-following
  disassembly check; dudect high-word classes (2.3, 2.4 rule 3, 2.4 rule 9, 2.7.5, 2.8, 14).
- **TM-R03** (support only; T-08, T-19): `via_host` in host-key prompts (7.1); the dialog itself is 03's.
- **TM-R04** (T-09): host-key list restricted to stored types, `SD_HK_NEW_TYPE` fails with
  `SD_E_HOSTKEY_TYPE_UNAVAILABLE`, `sd_known_hosts_stored_types`, `sd_ssh_conn_fetch_hostkeys` (0 D5, 3.1, 4.3,
  7.1, 7.2, 8, 9, 10.2, 10.9).
- **TM-R05** (T-10): `hostkey_just_accepted`, no autofill, no reconnect cache, `SD_ANSWER_FROM_STORE` rejected (6.4,
  6.7, 7.1, 7.4).
- **TM-R06** (T-11): live-source ACL checks on the opened handle and wildcard-only lines ignored for MATCH;
  `sd_known_hosts_source_state` (0 D10, 7.2).
- **TM-R07** (part that needs 01; T-13): store temp files created with the protected DACL so `MoveFileExW` keeps
  it (7.2).
- **TM-R08** (T-16, T-17): Pageant process SID/integrity check, OpenSSH agent pipe owner and server-process check
  (6.5).
- **TM-R09** (T-18): `sd_text_sanitize_server`/`_host` remove bidi and zero-width characters (6.1, 6.4, 10.7, 12.1,
  12.2).
- **TM-R10** (T-20, T-22): SSPI only to configured proxies, never to WPAD/PAC results without
  `AllowSystemProxySspi`; `auto` is Kerberos-only; NTLM only with `negotiate` (5.2, 9, 16).
- **TM-R11** (part in 01; T-23): stage-1 component invariant and `sd_name_component_check` (10.7).
- **TM-R12** (part in 01; T-24): `readdir` drops invalid and dot entries and counts them (10.3, 10.5).
- **TM-R30** (part in 01; T-57): stack wiping of secrets and the secret-thread registry for minidumps (2.4 rule 8,
  12.1).
- **TM-R31** (part in 01; T-56, T-58): remote paths logged at debug level only except in error records; memory
  limits documented (7.4, 12.1).
- **decisions.md D33** (T-02): legacy stays enabled by default, ranked last, warning only; TM-Q01 (ask, 2048-bit GEX
  floor) not adopted (0 D4, 4.2, 4.3).
- **decisions.md D37** (TM-Q07, T-15): `identities_only = yes` by default when a hop configures an identity (6.2, 9).
- **decisions.md D38** (TM-Q09, T-04): external crypto review in two passes, no public beta before pass 1 (0 D13,
  2.7.6, 13, 14).
- T-05 (RNG on XP, no TM-R): ephemeral secrets drawn from the OS RNG at use, lab item for the XP SP3 fix (2.2, 15).
- TM-R17 (a) checked: this module has no listening sockets (3.2).
- Security tests TST-01 to -05, -08, -11 to -18, -28, -30 and -33 mapped in section 12.4 and the milestones of
  section 13; open lab items 5-8 added to section 15.
- Not applied here (owned by other documents): TM-R03 dialog and CLI defaults, TM-R07 folder ACLs, TM-R11 stage-2
  inverse, TM-R12 duplicates/collisions and WebDAV decoding, TM-R13 to TM-R29, TM-R30 dump callback, TM-R31 log
  policy and admin guide, TM-R32 to TM-R39.
- Final reconciliation (threat model) 2026-10-24: TM-R04 "add key" now works inside a verified connection through
  `sd_ssh_conn_fetch_hostkeys()` (`hostkeys-prove-00` for announced keys, else a re-key restricted to the requested
  type; 4.3, 7.1, 9; `SD_SSH_CFG_HOSTKEY_ANY_TYPE` removed; lab item 9 in 15); `hostkey_just_accepted` is the one
  name for TM-R05 (03 uses it too) and also covers proxy-password prompts of tunneled legs (6.4); dump hooks named
  `sd_dump_mark_sensitive()` and stacks are always omitted (D43, no `--include-secret-stacks`; 2.4, 12.1, 16);
  agent checks use `sd_pipe_verify_server()` (6.5); disassembly check runs as `tools/sd-ctcheck` (2.7.5).

LibreStatic naming (D45) 2026-10-24: known_hosts store paths under `%APPDATA%`/`%ProgramData%\LibreStatic\ShellDrive`
and the lock object `Local\|Global\com.librestatic.shelldrive.known_hosts.<hash>` (§7.2, §16).
