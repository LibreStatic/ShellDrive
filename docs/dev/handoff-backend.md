# Hand-off: all backend work, M1–M7

Date: 2026-10-25. Repo `github.com/LibreStatic/ShellDrive`. Backend work continues on branch `wip/m2-backend`
(this document lives there); `main` stays clean for the frontend track. This hand-off covers **every backend item
of every milestone** in `docs/design/00-integration-review.md` §6. Frontend (GUI) work is handed off separately to
the lead session, which validates and implements it.

## Boundary between the two tracks

| Backend (this hand-off) | Frontend (other hand-off) |
|---|---|
| All libraries: `sd_base`, `sd_platform`, `sd_crypto`, `sd_ssh`, `sd_sftp`, `sd_vfs`, `sd_dokan`, `sd_webdav`, `sd_ipc`, `sd_config`, `sd_secret`, `sd_mount`, `sd_l10n` runtime | `shelldrive-ui.exe`: tray, main window, generated dialogs, prompt dialogs, host-key manager, logs viewer, first-run wizard, notifications |
| `shelldrive-host.exe` (agent and service modes), the CLI `shelldrive.exe` and its strings | `shelldrive-shellext.dll`: context menus, Explorer integration, Network locations, drive labels/icons, Windows 11 modern menu (`IExplorerCommand` + sparse MSIX contents) |
| IPC protocol, events and the shell-extension state snapshot **producer** | IPC/snapshot **consumers** in the UI and the shell extension |
| Setup stub engine, CAB payloads, MSI authoring, installer hooks, updater engine, ADMX/ADML generation, signing and release pipeline | Setup UI pages (incl. the D36 Dokany option page), updater consent UI, admin prompt UI |
| Build system, flavours, CI, local CI, lab, fuzzing, performance, crypto reviews | GUI string catalogs (their own l10n domain), accessibility, DPI, visual verification |

Contracts both tracks depend on are owned by backend and must be documented before frontend consumes them:
the IPC methods/events (03 §2), the snapshot layout (03 §8), the profile schema (03 §3.4.1) and policies (03 §3.5),
prompt kinds and their fields (01 §8, 03 §2.5), and error/exit codes (`sd_err`, 03 §7). Any change to these goes
into the owning design doc and `docs/dev/m*-notes.md` in the same commit.

## Rules (read first)

- `AGENTS.md`: English for code, comments, logs, docs and commits; user-facing strings in the six locales with the
  registers given there; full CLDR plurals.
- Commits: author **and** committer `FacuM <facumo.fm@gmail.com>`; never add `Co-Authored-By` or any AI/tool
  attribution (commit messages and PR bodies).
- `docs/design/decisions.md` is authoritative (D1–D46). Backend highlights: D1 zero third-party code, crypto
  included (specs only); D2 hashes are ours; D4 two x86 flavours; D6 service on by default per machine; D9
  write-through default; D11 global WebDAV spike; D15 ML-KEM in v1; D16 UpdateHostKeys; D17 no agents in the
  service; D18 pool only with non-interactive auth; D19 extra pool members bulk-only; D20 HTTP CONNECT + SOCKS5,
  no ProxyCommand; D28 x64-modern flavour; D31 ARM32 MSI; D32 Dokany packaging; D33 legacy enabled, warning only;
  D34 Terrapin cipher choice; D35 no implicit `service_access`; D36 Dokany install option; D37 `identities_only`;
  D38 review gate; D42 two signing sessions; D45 LibreStatic names; D46 public repo.
- Precedence: `decisions.md` → `00-integration-review.md` resolutions → owning design doc (01 SSH/SFTP/crypto,
  02 filesystem, 03 apps, 04 build) → `05-threat-model.md` TM-R as applied.
- Verification is local: `powershell -ExecutionPolicy Bypass -File tools\ci-local.ps1 [-Clean]` (x64-modern,
  x64-xp, x86-ia32, x86-sse2, x64-analysis; Release + Debug; fails on any warning or skipped interop test; x86
  `dokany.*` skips under WOW64 are expected). GitHub CI is free (public repo) but cannot run interop/WebDAV/Dokany.
- Per-area source lists in `src/sd_ssh/sources_{transport,auth,connect}.cmake` and
  `src/sd_crypto/sources_{pk,pq}.cmake` keep parallel work out of shared files.
- Never run `wsl --shutdown` while fixtures run. Tests use the fixtures' `direct_host` because the Windows→WSL
  `localhost:2222` relay can wedge after sshd kills.

## Environment on the dev machine

- VS 2022 Build Tools 17.14 (v143, v141 + v141_xp, ARM/ARM64 compilers, CMake), SDK 10.0.26100 and 7.1A.
  Not installed yet: SDK 10.0.22621 (needed for the ARM32 flavour, 04 §1.1), WiX 3.14.1, Windows ADK (oscdimg).
- Dokany 2.3.1 x64 installed; WebClient available (trigger-start); Hyper-V enabled; QEMU 11.1
  (`C:\Program Files\qemu`, `-cpu pentium3`); LibreOffice 26.8.1.
- WSL Ubuntu 24.04: `libpam-google-authenticator` + `/etc/pam.d/shelldrive-otp`, `squid`, `dante-server`,
  `putty-tools` (installed by the user).
- Fixtures (`docs/dev/m2-notes.md`): OpenSSH 10.6p1 (GPG-verified, user prefix); instances `modern` 2222, `ossh10`
  2230, `ossh10pq` 2239, `legacy` 2231, `legacy3des` 2238, `bastion1` 2232, `bastion2` 127.0.0.2:2233, `target`
  127.0.0.2:2234, `cert` 2235, `rotate` 2236, `otp` 2237; Python HTTP 2280/2281 and SOCKS5 2290/2291. Endpoints in
  `tests/fixtures/matrix/state/endpoints.env` (`SD_IT_*`; never log `SD_IT_OTP_SECRET`); TOTP via
  `sh tests/fixtures/matrix/fixture.sh otp-code` in WSL; matrix runner `tests/interop/run-matrix.ps1`.
  Squid/Dante rows are configured but never run. On `main`, fixture state dirs are excluded via `.git/info/exclude`.
- Lab (`tests/lab/`): Hyper-V and QEMU scripts, payload ISO builder, COM1 reader, in-guest smoke scripts. Waiting
  on licensed XP SP3 x86 and Windows 7 SP1 x86/x64 images from the user.

## Done so far (on `main`)

M0 complete (`docs/dev/m0-acceptance.md`). M1 code complete with Windows 11 acceptance (`docs/dev/m1-acceptance.md`):
reconnect, meta/bulk channels, caches and read-ahead, write-behind opt-in, `sd_webdav`, x86 flavours,
`sd-isacheck`, lab harness. GitHub CI green on five presets.

## Backend work by milestone

### M1 — remainder

- Lab acceptance (00 §6): XP SP3 x86 (`x86-ia32` on the QEMU Pentium III VM, `x86-sse2` elsewhere) and Windows 7
  SP1 x86/x64, WebDAV mount + file ops + Office/LibreOffice pattern, via `tests/lab/`.
- WebDAV with sshd killed mid-copy (not yet tested).
- TM-R19 token-only WebDAV mode + WinHTTP self-test, so non-redirector clients (LibreOffice opening files) work;
  policy `AllowWebDavTokenOnly` (03 §3.5).
- Replacing MOVE drops the destination lock (final UNLOCK gets 409): decide and fix per 02 §7.
- Document/mitigate the redirector's ~60 s negative cache after a failed lookup.
- sd_vfs offline waits: switch from 50 ms polling to `SD_SFTP_REQ_WAIT_READY` (needs a cancel path).
- TM-R17 watchers for long-running clients (crash filter and stop cleanup already done).

### M2 — all of it (in progress, uncommitted state committed on this branch)

Scope per 00 §6 M2 row, its demoable outcome and gate D38. State when the area agents were stopped (tree builds
warning-free on x64-modern; ctest 31/34):

| Area | Files | State |
|---|---|---|
| fixtures | `tests/fixtures/{matrix,openssh10,transport}/`, `tests/interop/`, `wsl-sshd/ctl.*` | Done (self-test 53/53, OTP live). |
| crypto `pq` | `src/sd_crypto/{sha3,mlkem,mlkem_hybrid,blake2b,argon2,des3}.c`, `pktcipher.c`, `sd_crypto_pq.h`, `tests/unit/sd_crypto_pq/` | Near done: tests pass; re-run full suite, x86-ia32 CT gate, throughput. |
| crypto `pk` | `src/sd_crypto/{bn,rsa,dh,dh_gex,ec_p,sha1}.c`, `pk_*`, `sd_crypto_pk.h`, `tests/unit/sd_crypto_pk/` | RSA private-key path fails (`rsa_reference_keys`, `cng_diff_rsa`); `bench_pk_throughput` fails. |
| ssh `transport` | `kex*.c`, `negotiate.c`, `packet.c`, `known_hosts*.c`, `hostkey_{verify,update}.c` | Interop tests not written; `unit.ssh` `ssh_conn_config_validation` fails (3 checks). |
| ssh `auth` | `auth*.c`, `keyfile*.c`, `agent*.c`, `sd_agent.h` | 7/19 `unit.ssh_auth` fail (mostly RSA; also password change, kbd-interactive rounds, fake agent pipe). |
| ssh `connect` | `conn.c`, `channel.c`, `jump_chain.c`, `proxy_*.c` | Jump chain and proxies written; pool + `SD_SFTP_O_STRIPED` in `src/sd_sftp/` not started. |
| apps backend | `src/sd_secret/`, `src/sd_config/{import.c,profile_m2.c}`, `src/sd_mount/*`, `apps/shelldrive-host/agent.c` | Secrets, importers, profile keys done; `sd_mount` mapping half done; CLI commands not done. |

Order: (1) fix RSA, then config validation; (2) transport interop over every KEX × host-key alg on `modern`,
`ossh10`, `ossh10pq`, `legacy`, `legacy3des`, `cert`, `rotate`; (3) auth: all key types/formats (encrypted PPK v3
cross-checked with `puttygen`), user certs on `cert`, OTP on `otp`, password change, Pageant/OpenSSH agent clients;
(4) connect: pool 1–4 with striping and barriers, vfs side (02 §5.6), the 2FA rule proved on `otp`, 2/3-hop jumps,
jump via SOCKS5 with auth, HTTP CONNECT with Basic, system proxy opt-in, TM-R10; pool speed-up on 1 GiB;
(5) `sd_mount` mapping + CLI (`profile import putty|ssh-config`, `hostkey list|import|remove|accept-announced`,
`--jump`, `--proxy`, `--connections`, kbd-interactive console prompts, password change, proxy credentials,
UpdateHostKeys review) with l10n; tag interop tests `srv_*` and drive acceptance with `run-matrix.ps1`;
(6) `ci-local -Clean` green, `docs/dev/m2-acceptance.md`; (7) D38 review pass 1 package (all of `sd_crypto` and
`sd_ssh`, test evidence, CT-gate output, TST mapping). **No public beta before pass 1 closes.**

### M3 — backend parts

- IPC surface the UI needs (03 §2): profile CRUD, mount/unmount/list/status, subscription to `mount.state`,
  `warning` (incl. `write_failed`), prompt events and `prompt.answer` from the UI, log query, settings read/write,
  host-key store operations incl. UpdateHostKeys review data. Version the protocol; document every method.
- Prompt broker in the agent: route to CLI → tray/UI → launch UI → queue (03 §2.5), with timeouts.
- State snapshot producer for the shell extension (03 §8): shared section layout, owner/integrity checks
  (TM-R26), update on every state change, versioned with one-version skew tolerance.
- Host-side data the shell integration needs: per-mount drive label/icon values written by the host per 03 §8
  (the frontend defines the visuals), stable targets for Network locations (02 §10.3).
- l10n tooling: `sdl10n` register lint, `qps` pseudo-locale generation, CLI catalog complete in six locales.

### M4 — backend parts

- Setup stub engine (04 §6): built from `x86-ia32`, CAB payload extraction via `cabinet.dll`, flavour selection by
  CPU and OS (`x86-ia32`/`x86-sse2`, `x64-xp`/`x64-modern`, ARM64; ARM32 own EXE), per-user/per-machine/portable,
  two-stage elevation and `%ProgramData%\LibreStatic` checks (TM-R33/R34), KnownDLLs-only imports.
- Six flavours in CI and local CI, incl. `x64-modern` (v143, CFG/CET) and `arm32` (needs SDK 10.0.22621).
- WiX 3.14 MSIs per flavour incl. ARM32 (D31), language transforms for every LCID (C43), service installed and on
  per machine (D6), `ENABLELINKEDCONNECTIONS` (D24), `DOKANY` property (D36), `REMOVESECRETS`, Dokany chaining after
  the `dokan2.dll` VC++ dependency check (C31, D32), repair-safe custom actions (TM-R35), `DEFAULTPROFILES`.
- Installer hooks run through `shelldrive-host.exe` (`webdav-tune`, `programdata-secure`, `user-cleanup`,
  `modern-menu` registration, `signal-shutdown`); upgrade with running processes (C3, C4).
- Updater engine (04 §9): signed manifest + keyset with offline root keys (TM-R37), per-channel anti-rollback,
  expiry, HTTPS then the static HTTP mirror (D30), staging, apply, `--selftest`, rollback. The consent UI is
  frontend; the engine exposes it over IPC.
- ADMX/ADML generated from the policy table (03 §3.5); sparse MSIX **build switch and packaging** (D27; its
  contents are frontend); reproducible-build check (`/Brepro`, double build); release pipeline with two offline
  signing sessions (D42), pinned Actions, maintainer rebuild (TM-R39).

### M5 — backend parts

- Global WebDAV spike first (D11, 02 §7.7): mechanisms `system`/`link` per OS, go/no-go recorded, `attach` fallback.
- `ShellDriveSvc`: Dokany global mounts, service-hosted WebDAV per the spike, `service_access`/`service_access_write`
  with no implicit default (D35), machine stores and secrets (SYSTEM DPAPI), no agents (D17), service pipe quotas
  (TM-R25), admin-only prompt routing (the admin UI is frontend), `hostkey add --from-server`, machine-store
  UpdateHostKeys only under policy, fast user switching/RDP, `--elevated-view`, `EnableLinkedConnections` diag/fix,
  threat-model review (05 §4).

### M6 — backend parts

- ARM64 native host and libraries, Dokany ARM64; ARM32 per D5; SHA-NI/AES-NI/ARMv8 fast paths (never in
  `x86-ia32`); 02 §11 performance targets with write mode stated, `shelldrive diag bench`; pool tuning; nightly
  fuzzing; external crypto review pass 2 with findings closed (TST-33); Authenticode via SignPath Foundation or
  Certum OSS (D29); `x64-modern` CFG/CET checks; admin/CLI documentation; lab smoke green on every VM (04 §11.4).
- The ARM64/x86/x64 shell DLLs and the modern menu are frontend.

### M7 — backend parts (post-1.0)

- `zlib@openssh.com`, adaptive channel windows, specialized NIST reductions, symlink reparse points only if an
  official signed Dokany gains an FSCTL callback (D12). The modern menu fallback is frontend.

## Handing results back

Per milestone: green `tools\ci-local.ps1 -Clean`, an acceptance doc in `docs/dev/` (no local user names or
profile paths), notes in `docs/dev/m*-notes.md`, and every contract change the frontend depends on listed under a
"Contract changes" heading there.
