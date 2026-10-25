# Hand-off: backend-only milestones

Date: 2026-10-25. Repo `github.com/LibreStatic/ShellDrive`, branch `main` at `7234b13` plus uncommitted M2 work
(see "State of M2"). This document hands off the milestones that contain no GUI work. Milestones that contain GUI
(M3, M4, M5, M6, M7) stay with the lead session, which designs the UI; their backend parts are listed at the end
so that the two tracks don't collide.

## Scope of this hand-off

| Milestone | What remains | Owner after hand-off |
|---|---|---|
| M1 (remainder) | Lab acceptance on XP SP3 x86 (incl. the Pentium III `x86-ia32` VM under QEMU) and Windows 7 SP1 x86/x64; WebDAV with sshd killed mid-copy; LibreOffice opening files over WebDAV (needs the TM-R19 token-only mode, 02 §7) | backend |
| M2 (all) | Everything in 00 §6 M2 row, its demoable outcome and the crypto review gate (D38) | backend |

## Rules (read first)

- `AGENTS.md`: English for code, comments, logs, docs and commits; user-facing strings in the six locales with the
  registers given there; full CLDR plurals.
- Commits: author **and** committer `FacuM <facumo.fm@gmail.com>`; never add `Co-Authored-By` or any AI/tool
  attribution (commit messages and PR bodies).
- `docs/design/decisions.md` is authoritative (D1–D46). Highlights for backend work: D1 zero third-party code,
  crypto included (specs only); D2 hashes are ours; D4 two x86 flavours; D15 ML-KEM in v1; D16 UpdateHostKeys;
  D17 no agents in the service; D18 pool only with non-interactive auth; D19 extra pool members bulk-only;
  D20 HTTP CONNECT + SOCKS5, no ProxyCommand; D33 legacy algorithms enabled, ranked last, warning only;
  D34 Terrapin cipher choice after the server's KEXINIT; D37 `identities_only`; D38 review gate; D45 names.
- Precedence when docs disagree: `decisions.md` → `00-integration-review.md` resolutions → owning design doc
  (01 SSH/SFTP/crypto, 02 filesystem, 03 apps, 04 build) → `05-threat-model.md` TM-R as applied.
- Verification is local: `powershell -ExecutionPolicy Bypass -File tools\ci-local.ps1 [-Clean]` runs x64-modern,
  x64-xp, x86-ia32, x86-sse2 and x64-analysis (Release + Debug), fails on any warning or skipped interop test
  (x86 `dokany.*` skips under WOW64 are expected). GitHub CI (`.github/workflows/ci.yml`) is free now that the repo
  is public, but it cannot run interop, WebDAV or Dokany tests.
- Parallel work inside one module uses per-area source lists: `src/sd_ssh/sources_{transport,auth,connect}.cmake`
  and `src/sd_crypto/sources_{pk,pq}.cmake` (`list(APPEND SD_SSH_SOURCES ...)`). Keep that split.
- Never run `wsl --shutdown` while fixtures or other WSL work run. The Windows→WSL `localhost:2222` relay may be
  wedged after sshd kills; tests use the fixture's `direct_host` (`tests/fixtures/*/state/env`).

## Environment on the dev machine

- VS 2022 Build Tools 17.14 (v143, v141 + v141_xp, ARM/ARM64 compilers, CMake), SDK 10.0.26100 and 7.1A.
- Dokany 2.3.1 installed (driver running); WebClient service available (trigger-start).
- QEMU 11.1 (`C:\Program Files\qemu`, supports `-cpu pentium3`); LibreOffice 26.8.1; Hyper-V enabled.
- WSL Ubuntu 24.04 with `libpam-google-authenticator` + `/etc/pam.d/shelldrive-otp`, `squid`, `dante-server`,
  `putty-tools` installed by the user.
- Fixtures (`docs/dev/m2-notes.md` §"Interop fixtures"): OpenSSH 10.6p1 built in a user prefix (GPG-verified),
  instances `modern` 2222, `ossh10` 2230, `ossh10pq` 2239, `legacy` 2231, `legacy3des` 2238, `bastion1` 2232,
  `bastion2` 127.0.0.2:2233, `target` 127.0.0.2:2234, `cert` 2235, `rotate` 2236, `otp` 2237; Python HTTP proxies
  2280/2281 (Basic) and SOCKS5 2290/2291 (RFC 1929). Endpoints in `tests/fixtures/matrix/state/endpoints.env`
  (`SD_IT_*`; never log `SD_IT_OTP_SECRET`). TOTP code: `sh tests/fixtures/matrix/fixture.sh otp-code` in WSL.
  Matrix runner: `tests/interop/run-matrix.ps1 -BuildDir <dir>` (tests opt in with `srv_<row>`/`srv_all` labels;
  no ShellDrive test carries them yet). Squid/Dante rows are configured but have never been run.
- Lab harness for M1 remainder: `tests/lab/` (Hyper-V `New-LabVM.ps1`/`Restore-LabVM.ps1`, QEMU
  `qemu/Start-QemuPentium3.ps1`, payload ISO builder, COM1 reader, in-guest smoke scripts). Waiting on licensed
  XP SP3 x86 and Windows 7 SP1 x86/x64 images from the user.

## State of M2 (uncommitted in the working tree)

Six area agents were stopped mid-work on 2026-10-25. The tree builds warning-free on x64-modern; ctest: 31/34
pass, failures listed per area. Each area's notes (if written) are in `docs/dev/m2-notes.md`.

| Area | Files | State |
|---|---|---|
| fixtures | `tests/fixtures/{matrix,openssh10,transport}/`, `tests/interop/`, `wsl-sshd/ctl.*` | **Done** (self-test 53/53 + OTP live). |
| crypto `pq` | `src/sd_crypto/{sha3,mlkem,mlkem_hybrid,blake2b,argon2,des3}.c`, `pktcipher.c` edits, `sd_crypto_pq.h`, `tests/unit/sd_crypto_pq/` | Near done: `unit.crypto_pq` passes; its last step was re-running the full suite. Check x86-ia32 CT gate and throughput numbers. |
| crypto `pk` | `src/sd_crypto/{bn,rsa,dh,dh_gex,ec_p,sha1}.c`, `pk_*`, `sd_crypto_pk.h`, `tests/unit/sd_crypto_pk/` | Mostly done. `unit.crypto_pk` fails `rsa_reference_keys`, `cng_diff_rsa` (RSA private-key path) and `bench_pk_throughput`. It was about to register its tests in `tests/CMakeLists.txt` (already registered). |
| ssh `transport` | `kex.c`, `kex_methods.c`, `negotiate.c`, `packet.c`, `known_hosts*.c`, `hostkey_{verify,update}.c` | Mid-work: was writing the interop tests. `unit.ssh` fails `ssh_conn_config_validation` (3 checks) — likely a config struct change from `connect`. |
| ssh `auth` | `auth.c`, `auth_cfg.c`, `keyfile*.c`, `agent*.c`, `sd_agent.h`, `tests/unit/sd_ssh/test_{keyfile_formats,auth_flow,agent}*.c` | Mid-work: 7 of 19 `unit.ssh_auth` tests fail; most depend on RSA (`pk`), plus password change, kbd-interactive OTP rounds and the fake agent pipe. OTP fixture was handed to it but not used yet. |
| ssh `connect` | `conn.c`, `channel.c`, `jump_chain.c`, `proxy_{conn,http,socks5}.c` | Mid-work: jump chain and proxies written; was starting the **pool in sd_sftp** (not begun in files). No pool, striping or OTP-keeps-pool-at-1 test yet. |
| apps (backend parts) | `src/sd_secret/`, `src/sd_config/{import.c,profile_m2.c,sd_import.h}`, `src/sd_mount/*`, `apps/shelldrive-host/agent.c` | Mid-work: secrets, importers and profile keys written (`unit.secret`, `unit.config` pass); was updating `mount_real.c` and the fake backend. CLI commands (`profile import`, `hostkey …`, `--jump`, `--proxy`, `--connections`, kbd-interactive console prompts, UpdateHostKeys review) not done. |

### Suggested order

1. Fix RSA in `pk` (unblocks most `auth` failures), then `unit.ssh` config validation.
2. Finish `transport` interop: every KEX × host-key alg against `modern`, `ossh10`, `ossh10pq`
   (`mlkem768x25519-sha256`), `legacy`/`legacy3des` (warning fires), `cert` (host CA, revoked/expired),
   `rotate` (hostkeys-00 learned after review).
3. Finish `auth`: all key types/formats incl. encrypted PPK v3 cross-checked with `puttygen`, user certificates
   against `cert`, kbd-interactive OTP against `otp`, password change (unit, fake server), Pageant and OpenSSH
   agent clients (fake servers + real `ssh-agent` service if running; don't change its state).
4. `connect`: pool 1–4 with `SD_SFTP_O_STRIPED` + barriers in `src/sd_sftp/`, vfs side per 02 §5.6, the 2FA rule
   (prove with `otp`), 2- and 3-hop jumps, a jump through SOCKS5 with auth, HTTP CONNECT with Basic, system proxy
   opt-in, TM-R10 SSPI rules; pool speed-up numbers on a 1 GiB copy.
5. `apps` backend: finish `sd_mount` mapping and the CLI commands listed above with l10n; tag interop tests with
   `srv_*` labels and make `run-matrix.ps1` the M2 acceptance driver.
6. Integration + `tools\ci-local.ps1 -Clean` green on all five presets; write `docs/dev/m2-acceptance.md`
   (no local user names or profile paths) covering the M2 demoable outcome in 00 §6.
7. Gate D38: prepare the external crypto review pass 1 package (scope: all of `sd_crypto` and `sd_ssh`, test
   evidence, CT-gate output, threat-model TST mapping). No public beta before it closes.

## Backend parts of mixed milestones (coordinate with the lead before starting)

The lead session owns M3–M7 because each contains GUI. These pieces are pure backend and can be handed over later
on request: M4 setup stub/CAB/MSI authoring/updater core (not its UI), M5 service and the global WebDAV spike (not
the admin prompt UI), M6 ARM64/ARM32 builds, fast paths, performance and review pass 2 (not shell DLLs or the
modern menu), M7 `zlib@openssh.com`, adaptive windows, NIST reductions.
