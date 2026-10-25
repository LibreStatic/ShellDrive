# 00 — Integration review of designs 01–04

> **Status: Decisions resolved on 2026-10-24 — see [`decisions.md`](decisions.md), which overrides the
> recommendations below.** The resolutions and decisions have been folded into 01–04 and reconciled across them
> (§8). Sections 2–3 and 7 are kept as the historical record; where a resolution there was changed by a decision,
> §8 says so. §6 (milestones) is current.

Status: review, not a design. Inputs: `docs/requirements.md`, `AGENTS.md`, `01-ssh-sftp-crypto.md`,
`02-filesystem.md`, `03-apps-platform.md`, `04-build-install-update.md`. The four designs are not edited;
every resolution below is a proposal to be applied to them once the user approves the decisions in the last
section. Section references like "01 §10.5" point into those documents.

---

## 1. Summary

The four designs are individually thorough and mostly compatible. They agree on the large structure:
static-library modules in plain C, one long-lived host process per user session plus an optional
LocalSystem service, `sd_sftp` as the only contract between protocol and filesystem, Dokany 2.x
(min 2.1.0, pinned 2.3.1) loaded dynamically from System32, WebDAV over loopback as the driverless
fallback, our own ed25519-signed update manifest, and runtime resolution of every post-XP API.

The integration problems fall into six groups:

1. **Naming and packaging drift between 03 and 04.** Binary count and names, the service binary, the shell
   DLL name and replacement strategy, the shutdown signal, CLI subcommands that 04 and 02 call but 03 does
   not define, service default (on in 04, off in 03), and where update settings live (registry in 04,
   `settings.ini` in 03).
2. **The `sd_sftp` contract (01 §10) against 02's R1–R18.** 11 items are met, 5 partly met, 2 missing
   (R13 remote identity, R16 RTT export). The real gaps are a metadata/bulk channel split (R14), a default
   per-request timeout with a liveness probe (R15), and uid/gid discovery. 01 has no exec channel, and
   using one is questionable anyway.
3. **Responsibilities claimed twice.** Error refinement for `SSH_FX_FAILURE` (01 and 02), `known_hosts` file I/O
   and locking (01 and 03), the reconnect password cache (01 and 03), the lossless name mapping
   (01 and 02), and the memory cache budget (global in 02, per profile in 03).
4. **WebDAV security and global mounts.** 03 asks for Basic-auth bearer credentials and LocalSystem WebDAV
   mappings. 02 rejects Basic and shows that a LocalSystem WebDAV mapping is not a real global drive.
   04 still mentions tuning "basic-auth level". Proposed resolution: global drives use Dokany only, and
   WebDAV keeps Negotiate plus the path token.
5. **Hard-constraint and build-rule tensions.** 01 wants to vendor fiat-crypto/Monocypher, while 04 says
   "zero third-party source shipped". 01 assumes x86 CPUs without SSE2, while 04 builds `/arch:SSE2`. 01 plans
   `/guard:cf` on XP builds, which 04 forbids. 04 links SSE2-compiled `sd_crypto` into an `/arch:IA32`
   setup stub. It is unclear whether the Dokany MSI alone carries its VC++ runtime.
6. **Requirements that the designs showed to be wrong or infeasible.** Symlink reparse points cannot be
   built on unmodified Dokany. WebClient has been deprecated since 2023 and is not "always available".
   "Global drives before logon" cannot work over WebDAV. "Basic auth over plain http" is rejected on
   security grounds. "Add network location" entries are not designed. ARM32 has almost no usable mount
   backend. Section 3 proposes amended wording.

No document covers the module dependency graph, a shared `sd_base`/`sd_platform` layer with logging and
allocation rules, the host-process threading model, the module that turns a profile into a running mount, or a
cross-project milestone plan. Sections 4–6 propose them.

---

## 2. Conflicts

Severity: **H** = blocks implementation or breaks a hard constraint; **M** = will cause rework or a
user-visible defect if left open; **L** = naming or cosmetics.

### 2.1 Processes, binaries, naming

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C1 | 03 §1.1, 04 §4 | 03 has 4 binaries: `shelldrive.exe`, `shelldrive-host.exe` (agent **and** service), `shelldrive-ui.exe`, `shelldrive-shell.dll`. 04 has 5: separate `shelldrive-agent.exe` and `shelldrive-svc.exe`, and `shelldrive-shellext.dll`. | Adopt 03's single host binary (`shelldrive-host.exe agent|service`), which halves size and signing work. Adopt 04's DLL name `shelldrive-shellext.dll`. 04's `apps/` becomes `shelldrive/`, `shelldrive-host/`, `shelldrive-ui/`, `shelldrive-shellext/`, `shelldrive-setup/`. | M |
| C2 | 04 §6.9, §8.3, §9.6, §14 | 04 refers to `shelldrive-svc`, `shelldrive-agent.exe --selftest` and `shelldrive.exe selftest --json`. 03 defines none of these. | Service name `ShellDriveSvc`, binary `shelldrive-host.exe service`. Health check is `shelldrive-host.exe --selftest` (exit 0). Smoke tests use `shelldrive selftest --json`, a new CLI command (C7). | M |
| C3 | 04 §6.9, §14; 03 §2.4, §2.2, §12.3 | Shutdown signal: 04 uses `Global\com.librestatic.shelldrive.Shutdown.<SID>` (plus a `Local\` fallback on XP). 03 uses IPC `agent.shutdown`, and its uninstall step "enumerate pipes as admin" contradicts 03's own agent pipe DACL, which grants access only to the user. | Each agent creates `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>` (manual-reset) with DACL `user, SY, BA: EVENT_MODIFY_STATE|SYNCHRONIZE` and waits on it. Per-user setup signals the events for its own SID. Elevated setup finds running `shelldrive-host.exe` processes (Toolhelp32 + `OpenProcessToken`, XP+), derives SID/session and signals each event. Restart Manager stays the fallback. Drop the `Local\` fallback because `Global\` works on XP. Add the event to 03 §2.1. | M |
| C4 | 03 §8.5, 04 §6.9 | Shell DLL update: 03 keeps a fixed name and uses `MOVEFILE_DELAY_UNTIL_REBOOT`. 04 uses a versioned directory `shellext\<version>\` and rewrites `InprocServer32`. | Adopt 04 (no reboot). | L |
| C5 | 04 §14, 03 §1.6 | 04 requires "shell extension IPC tolerates N±1", but 03's shell extension has no IPC. It reads a shared-memory snapshot and launches `shelldrive-ui.exe --action`. | Restate as: the `Local\com.librestatic.shelldrive.state.<SID>` layout is versioned and **architecture-independent** (fixed-width fields, no pointers; x86 DLLs in WOW64 read a section written by an x64 or ARM64 host), and `--action` verbs are additive only. | M |
| C6 | 04 §8.3 (`Service` default on), 03 §1.3 (checkbox default off) | Service default. | Default **off** in both the EXE and the MSI (`Service` feature level 2, enabled with `ADDLOCAL`). A LocalSystem process with a network stack should be opt-in. | M |
| C7 | 02 §4.1, §7.2, §11; 04 §9.1, §14; 03 §6.1 | CLI commands requested by other designs but missing from 03: `refresh <drive>[\path]`, `bench`, `stats` (02); `admin webclient-enable` (02, duplicates 03's `diag --fix webclient`); `update check|apply [--manifest]`, `selftest`, `--installer-hook webdav-tune --apply|--revert`, `diag collect` (04; 03 has `diag --bundle`). | Add to 03 §6.1: `refresh`, `update check|apply`, `selftest`, `diag bench` (developer/support), and `stats` as `status --stats`. Map `admin webclient-enable` to `diag --fix webclient` and `diag collect` to `diag --bundle`. Add `--installer-hook` as a hidden command. Add matching IPC methods: `refresh`, `update.check`, `update.apply`, event `update.available`, and `profile.test` (for the "Test connection" button in 03 §7.5). | M |
| C8 | 03 §3.4/§3.5, 04 §8.4/§9 | Update and policy storage: 04 uses `HKLM\Software\LibreStatic\ShellDrive\Update\Enabled`, `HKCU\...\Update\ManifestUrl` and `LastSerial` in the registry, plus `Policies\LibreStatic\ShellDrive\Update\...`. 03 uses `settings.ini [update] check` and the policy value `DisableUpdateCheck`. Portable mode forbids registry writes. | 03 owns the schema. Settings go in `settings.ini [update] enabled, channel, manifest_url`, and `last_serial` goes in the `state\` directory. MSI properties (`UPDATECHECK`, `UPDATEURL`) write the machine `settings.ini`. Policies live in one key, `Policies\ShellDrive`, with values `DisableUpdateCheck`, `UpdateChannel`, `UpdateUrl`, listed once in 03 §3.5. Intune detection keeps `HKLM\Software\LibreStatic\ShellDrive\Version`, written by the MSI only. | M |
| C9 | 04 §8.4, 03 §3.2/§3.4 | `DEFAULTPROFILES` copies a `.sdp` file to `LibreStatic\ShellDrive\defaults\`. 03 instead puts machine profiles in `%ProgramData%\LibreStatic\ShellDrive\profiles\*.ini` with `scope = users`. | `DEFAULTPROFILES` points to a folder of `.ini` profiles that the MSI copies into `%ProgramData%\LibreStatic\ShellDrive\profiles\`. Drop `.sdp` and `defaults\`. | L |
| C10 | 04 §6.6, §6.3; 03 §8.1/§8.4/§13.2 | 04 registers "shell namespace entries (This PC, Add network location)". 03 rejects a namespace extension and has no Network Shortcuts in v1. | Registry tables contain only: the context-menu handler (Drive, Directory, `*`, This PC CLSID), Approved, the `.sdmount` ProgID, App Paths and Run keys. Link to the requirement gap G1. | M |
| C11 | 04 §8.3, 03 §1.2 | 04's MSI feature `Autostart` writes HKLM Run → agent for every user. 03 uses HKCU Run only when needed, plus a separate tray key. | HKLM Run starts `shelldrive-host.exe agent --logon --if-needed`, which exits at once if the user has no autostart profiles and no tray. The HKCU keys stay for per-user installs. The mutex prevents double start. | L |
| C12 | 02 §4.2, 03 §3.2 | Cache paths: 02 uses `<LocalAppData>\LibreStatic\ShellDrive\Cache\<guid>` and `%ProgramData%\LibreStatic\ShellDrive\Cache\`. 03 uses `...\cache\` and `%ProgramData%\LibreStatic\ShellDrive\service\cache\`. | 03 wins (it passes `disk_cache_dir` into `sd_vfs`, see 03 §12.2). | L |

### 2.2 Protocol/filesystem contract

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C13 | 02 §5.1, §9 vs 01 §10.2 | Name mismatch: 02 uses `SD_SFTP_E_CONNECTION_LOST`, `_INVALID`, `_AGAIN`, `_EOF` and states CONNECTED/LOST/RECONNECTING/RECONNECTED. 01 defines `SD_E_DISCONNECTED`, `SD_E_INVALID_PARAM`, `SD_E_EOF` and `SD_SFTP_ST_*`. | 01's names are canonical; 02 is renamed. 02 adds an explicit `sd_err → sd_vfs_status` table to `sd_vfs`. | L |
| C14 | 01 §10.2 (refinement probes), 02 §8 (vfs disambiguation) | `SSH_FX_FAILURE` is refined twice, which doubles the extra round trips. | `sd_sftp` refines (`SD_SFTP_OPT_REFINE_ERRORS`, on). `sd_vfs` maps refined codes only and does no probes of its own. 02 keeps one rule only: `RENAME` with replace onto a non-empty directory → `STATUS_ACCESS_DENIED`. | M |
| C15 | 02 R4 vs 01 §10.5 | 02 wants oversize requests rejected ("vfs owns chunking"). 01 splits, pipelines and reassembles. | Keep 01's behaviour (harmless). `sd_vfs` issues ≤ `max_read`/`max_write` chunks itself and gets exactly one wire request per call. 01 documents that guarantee. | L |
| C16 | 02 R15, 01 §10.4 | 01 defaults to `default_timeout_ms = 0` (none); a dead link is detected only by keepalive after 15 s × 3 = 45 s. 02 needs a 30 s default and a liveness probe on timeout, and Dokany's request timeout is 30 s. | `sd_vfs` passes `timeout_ms` per request (25 s for Dokany, 50 s for WebDAV, below the redirector's 60 s). 01 adds: on any request timeout, send an immediate `keepalive@openssh.com` and declare the connection dead if it is unanswered within `min(5 s, 3 × srtt)`. | H |
| C17 | 02 R14, 01 D8/§10.5 | 01 assigns handles to the least-loaded channel. A `stat` can wait behind up to 8 MiB of reads on the same channel, about 0.7 s at 100 Mbit/s. | 01 adds a request class: channel 0 = "meta" (path ops, opendir/readdir, attribute-only opens), channels 1..n-1 = "bulk" (data handles). With 1 channel the meta queue is served first by the scheduler. | M |
| C18 | 02 R13 vs 01 (no exec API), 02 Q9 | uid/gid discovery through an `id -u; id -G` exec channel. It fails on `ForceCommand internal-sftp` servers, runs login scripts, writes audit-log noise, and 01 has no exec channel. | Default: no exec. Learn the uid from the owner of `realpath(".")`, then confirm it from the attributes of the first file or directory we create (definitive uid plus primary gid). Unknown supplementary groups use 02's "g\|o writable" rule. Optional profile setting `identity_probe = exec` (off) needs `sd_ssh_channel_open_exec()` in 01. `users-groups-by-id` is used for names only. | M |
| C19 | 01 §7.2, 03 §5.1/§12.1 | `known_hosts`: 01 does file I/O, a named mutex, a single store plus live read-only sources (OpenSSH, PuTTY) **copied into our file on match**. 03 wants parse/serialize without I/O, its own config lock, machine-store-then-user-store lookup, and "nothing imported silently". | `sd_known_hosts` keeps I/O (it already runs on a worker thread) but takes an **ordered store list**: `{machine, read-only for users}`, `{user, read-write}`, plus optional live sources. Locking uses 01's named mutex, and 03's config lock is not used for `known_hosts`. Whether live sources are on by default is decision D7. | M |
| C20 | 01 §7.4/§8, 03 §4.6 | Both cache the password and decrypted keys for reconnect. 03 is unsure about `CryptProtectMemory` on XP. | `sd_ssh` owns the cache (`cache_secrets_for_reconnect`; `CryptProtectMemory` on Vista+, `RtlEncryptMemory` on XP, per 01). The host answers `is_reconnect` prompts from Credential Manager/DPAPI. 03 drops its own cache, which closes 03 Q7. | L |
| C21 | 03 §2.5/§7.6, 01 §6.7/§9 | 03's `legacy_ack` prompt must hold the connection **before userauth**. 01 has no such prompt and only reports `on_negotiated` (with a bitmask, not the per-algorithm flags 03 assumes). | 01 adds `SD_PROMPT_LEGACY_ACK`, raised after NEWKEYS and before SERVICE_REQUEST when `legacy_mask & ~MAC_NON_ETM` is set and the profile says `ask`. 03 derives per-algorithm flags from names plus the mask. | M |
| C22 | 03 §4.4/§2.6, 01 §9 | DPAPI-stored keys (`identity_store`) and service keys are in memory, but `sd_ssh_identity` takes only a file path or an agent fingerprint. 03 also needs a "needs passphrase / fingerprint" pre-check and an unencrypted OpenSSH serializer. | 01 adds `SD_ID_BLOB` (bytes plus an optional passphrase callback), `sd_ssh_key_probe(bytes) → {type, pub blob, fp, encrypted}`, and `sd_ssh_key_serialize_openssh(key, no cipher)`. | M |
| C23 | 01 §10.7, 02 §1.2 | Both specify the U+F780..U+F7FF mapping. Only 01 escapes valid UTF-8 for U+F780..F7FF (bijection). | Use 01's `sd_name_to_wide/from_wide` as stage 1. 02's U+F000+c reserved-character mapping and the trailing dot/space mapping are stage 2, applied per component. `remote_charset` replaces stage 1 only. | L |
| C24 | 01 §10.9, 02 §8 | NTSTATUS/HTTP hints differ (STALE → `UNEXPECTED_NETWORK_ERROR`/503 in 01 vs `FILE_INVALID`/409 in 02; QUOTA → `QUOTA_EXCEEDED` vs `DISK_QUOTA_EXCEEDED`). | 02 is normative, as 01 itself says. Delete the table in 01 §10.9 or mark it superseded. | L |
| C25 | 01 §10.2 `sd_err_name`, 03 §2.3/§6.2 | IPC/JSON error codes (`host_key_mismatch`, `dns_failed`, `prompt_required`) and the names `sd_err_name` would generate (`hostkey_mismatch`, `dns`) do not match, and nothing maps them to exit codes. | One table in the host (`sd_err` → IPC code → exit code). `sd_err_name` produces 03's spellings: `host_key_*`, `dns_failed`, `auth_required → prompt_required`. | M |

### 2.3 WebDAV, service, Explorer

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C26 | 03 §12.2 vs 02 §7.4/D9 | 03 asks for a per-mount **Basic** username/password for elevated attach. 02 rejects Basic over http, because it needs `BasicAuthLevel=2` machine-wide. | No Basic. Elevated attach works with 02's design as is: the linked elevated token has the **same user SID**, so the Negotiate SID check passes, and the path token is the per-mount secret. `mount.attach_info` returns only the UNC with the token. | H |
| C27 | 03 §1.3/§1.8 vs 02 §7.7/D14 | 03 has the LocalSystem service map global WebDAV drives with `WNetAddConnection2`. 02 shows this gives no real global drive (the redirector session belongs to SYSTEM, nothing exists pre-logon) and proposes a per-user attach. That needs an agent→service call, which 03 §2.6 forbids ("agent does not proxy"). | v1: **global drives use Dokany only** (02 D14). Service profiles with `backend = webdav` are rejected at save. Per-user attach of a service-hosted WebDAV server is deferred (decision D11). | H |
| C28 | 04 §8.3, 02 §7.1/§7.4 | 04's MSI custom action tunes "file size limit, **basic-auth level**". 02 never touches `BasicAuthLevel`. | `WEBDAV_TUNING` sets only `FileSizeLimitInBytes=0xFFFFFFFF` and `FileAttributesLimitInBytes=100000000`, records the original values and restores them on uninstall. Per-user setup skips it (no HKLM access) and shows how to apply it. | M |
| C29 | 03 §3.4 (`symlinks = follow \| reparse`; reparse forces Dokany) vs 02 §6.9 | Reparse points cannot be built on unmodified Dokany 2.3.1. | Profile values `follow \| hide`. `reparse` is reserved and rejected with a clear error. Requirement amendment A3. | M |
| C30 | 03 §12.2 (readable profile slug in the UNC) vs 02 §7.3 (`/s-<token>`) | The slug was needed only to label global WebDAV drives, which C27 removes. | Keep `/s-<token>/`. Per-user labels come from `_LabelFromReg` (02 §7.3 and 03 §8.3 agree; fix the example key in 03, which uses `m-3`). | L |
| C31 | 02 §6.1 (embed `DokanSetup_redist` bundle) vs 04 §7.3 (embed `Dokan_<arch>.msi` only) | If `dokan2.dll` 2.3.1 needs the VC++ runtime, an MSI-only install leaves it unloadable. | Lab check, first week of M4: `dumpbin /dependents dokan2.dll` for every architecture. If it depends on `vcruntime140*.dll`, embed the upstream `DokanSetup.exe` bundle unmodified in the offline EXEs and keep the MSIs for GPO/Intune, documenting that the VC++ redist is a prerequisite there. | H |
| C32 | 02 §6.1/§6.3 vs 04 §7.2/§7.3 | Win7 SHA-2 detection (02: `Win32_QuickFixEngineering` or `ci.dll`; 04: `WinVerifyTrust` on the catalog, then `ci.dll`) and the 2.0.x upgrade offer (02 offers our installer, but upstream 2.3 refuses when a third-party driver exists). | 04's detection and decision table are normative. 02 §6.3 refers to it. The runtime probe (`DokanDriverVersion() != 0`) stays the final authority. | L |
| C33 | 02 §6.5 `Unmounted` → "stop the profile"; 01 §9/§10.4 | Destroying the session from inside Dokany's `Unmounted` callback (or calling `DokanCloseHandle` there) deadlocks: Dokany waits for its callbacks, and `sd_sftp_session_destroy` waits for the I/O thread. | `Unmounted` only posts a message to the host's control thread, which runs quiesce → `sd_sftp_session_close` → destroy. | H |

### 2.4 Build, dialect, crypto

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C34 | 01 §2.3 (scalar baseline, "CPUs without SSE2 must work"), 04 §3.2 (`/arch:SSE2`; setup refuses pre-SSE2) | x86 CPU floor. | Decision D4. Recommended: SSE2 (04). 01 then drops the non-SSE2 claim but keeps scalar paths for ARM and as reference. | M |
| C35 | 04 §6.1 (stub `/arch:IA32`, links `sd_platform` + `sd_crypto`) | Code compiled with `/arch:SSE2` can use SSE2 in any function, so the stub could crash before its CPU check if it links the SSE2 libraries. | Build the subset the stub needs (`sd_platform` minimal, SHA-256/512, Ed25519 verify, CAB/FDI glue) a second time as an `/arch:IA32` object library `sd_stubcore`. CI runs the stub under SDE or a non-SSE2 VM profile. | M |
| C36 | 01 §12.1 (`/guard:cf` "harmless on XP", `/sdl`), 04 §3.2 | 04 disables `/guard:cf` on v141_xp until lab-verified, and `/sdl` is v143-only. | 04 §3.2 is normative for all flags. 01 §12.1 refers to it. | L |
| C37 | 01 §2.5 (vendor fiat-crypto, optionally Monocypher/BearSSL parts), 04 §4 ("Shipped code: zero third-party source"), requirements ("crypto … our own code") | Policy conflict touching a hard constraint. | Decision D1. Recommended: allow **only** fiat-crypto's generated field arithmetic (formally verified, MIT/Apache/BSD-1, not an SSH/TLS stack, not Unix code) in `third_party/fiat-crypto/` with `PROVENANCE.md`; write everything else. Amend 04 §4 and requirements wording (A6). | H |
| C38 | 02 §6.2 ("MIT-licensed header parts" of `dokan.h`), 04 §4 (headers are LGPL) | Licence of the Dokany declarations we compile against. | Write our own minimal declarations of the `DOKAN_*` ABI in `src/sd_dokan/dokan_abi.h`, frozen at 2.3.1, with a notice. This keeps the tree MIT-only. No upstream header file is copied. | L |
| C39 | 01 §1 (`sd_base`: buf, err, mem, log, utf, thread; full-System32 `GetProcAddress`), 04 §2.4/§4 (`sd_platform`, `sd_platform_resolve`, `sd_alloc` wrapping `HeapAlloc`), 03 (`sd_log`, `sd_json`, `sd_ini`, `sd_config`...) | Three names for the shared base, and two resolution helpers. | Split into **`sd_base`** (no `windows.h`, fuzzable: `sd_buf`, `sd_err`, `sd_utf`, `sd_json`, `sd_ini`, checked arithmetic, `sd_mem` through hooks) and **`sd_platform`** (Win32: allocator, `sd_platform_resolve` loading by full System32 path, threads/locks/once, 64-bit tick, paths/portable detection, `sd_log`). See §4. | M |
| C40 | 01 §1 source tree `src/crypto` …, 04 §4 `src/sd_crypto` …; 01 `PROVENANCE.md`, 04 `README.md` in `third_party/` | Layout. | 04's layout. Third-party directories carry both files (README for the user, PROVENANCE for audit). | L |

### 2.5 Localization and installer strings

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C41 | 03 §9.1, 04 §4/§8.3 | 04 maintains `.wxl` files by hand and has "shared string tables per locale (format: UI doc)". 03 generates everything from PO via `tools/sdl10n`. | PO is the only source. `sdl10n` emits C tables (apps, setup stub, `uninstall.exe`), STRINGTABLEs (service description, ProgID), `.wxl` and ADML. The setup stub uses the `installer` domain and 03 §9.3 language resolution. | M |
| C42 | 04 §6.5 (`/lang=pt`), 03 §2.7/§9.3 (`pt-BR`) | Language codes. | Canonical codes `en es fr pt-BR it de`. `pt` is accepted as an alias. | L |
| C43 | 04 §8.3 (`TRANSFORMS=:3082`), AGENTS.md (Rioplatense voseo) | Embedded MSI language transforms are applied only on an exact LCID match, so es-AR/es-MX/es-US users would get English. The tag 3082 (es-ES) also does not match the voseo text. | Embed the same `es` transform under 11274 (es-AR), 3082, 2058 (es-MX), 21514 (es-US) and 1034, and the `pt-BR` transform under 1046 and 2070. The setup EXE always passes `TRANSFORMS` explicitly from its own language resolution. | M |
| C44 | 03 §9.1 vs §10.3 | 03 lists the Event Log message file both among the localized Windows-loaded resources and as "English only". | Event Log messages count as logs (AGENTS.md: logs stay English), so English only. The service display name and description are localized (indirect string on Vista+, set by the service with `ChangeServiceConfig2`, since 04's MSI `Description` is static per install language). | L |
| C45 | 02 §5.2/§6.5 (volume label suffix "(offline)"), 02 §4.4 (write-behind failure "raised to the tray") | User-visible text produced inside `sd_vfs`, plus a notification type 03 §7.7 lacks. | The host passes the localized suffix to `sd_vfs` (service: machine default language). 03 adds notification `write_failed` (always on, cannot be disabled, mirrored in the event list) and IPC warning code `write_failed`. | M |

### 2.6 Profile schema

| id | docs | issue | proposed resolution | sev |
|---|---|---|---|---|
| C46 | 03 §3.4 vs 02 §8 `sd_vfs_options`, §4.2 | 03 keeps per-profile `read_cache_memory` while 02 has one global memory budget. 03's example sets `read_cache_disk = 512M` while 02 defaults to off (the cache holds plaintext copies). Key names differ (`metadata_ttl` vs `attr_ttl`). Many 02 options have no profile key: `case`, `remote_case`, `umask`, `map_readonly`, `show_special`, `allow_system`, `write_through`, `fsync_on_flush`, `offline_wait`, `reconnect_grace`, `remote_charset`, `strict_acl`, `atomic_put`, `offline_hint_over_mb`, `neg_ttl`. 01 options are missing as well: `channels`, `refuse_terrapin_exposed`, `crypto_backend`, `identities_only`, `cache_secrets_for_reconnect`. | 03 owns one profile schema table that lists every key, its default, the module that consumes it, and whether policy can lock it. The memory budget is global (`settings.ini [cache] memory`). The disk cache is per profile, default 0. | M |

---

## 3. Requirement coverage gaps and amendments

### 3.1 `sd_sftp` against 02's R1–R18

| R | Status | Notes / missing piece |
|---|---|---|
| R1 async submission, callbacks off-thread, never inline | **met** | 01 D2, §10.8. The completion "thread" is the chain's single I/O thread. |
| R2 operation set incl. symlink quirk | **met** | |
| R3 extensions + capability query | **met** | Query is `server_info.ext` from `EV_READY_INFO` rather than `sd_sftp_has_ext()`. A one-line helper can be added. |
| R4 limits | **partly** | Values exposed. Chunking ownership differs (C15). |
| R5 ≥ 64 in flight, bounded queue | **partly** | 64/8 MiB per channel. The pending FIFO has no cap: add `max_queued_reqs` and return `SD_E_BUSY` beyond it. |
| R6 read into caller buffer, EOF distinct | **met** | |
| R7 neutral errors + raw server code + message | **met** | Names differ (C13). |
| R8 state events, prompt completion of all requests | **met** | Detection latency is the issue (C16). |
| R9 generations, stale handles fail locally, wait-ready | **met** | `SD_SFTP_REQ_WAIT_READY` stands in for `wait_connected()`. |
| R10 full ATTRS, 64-bit times, extended pairs | **partly** | Extended pairs are parsed and **dropped**. Expose them as an optional array in the completion. |
| R11 raw byte names | **met** | |
| R12 server identity + quirk flags | **partly** | Extension names/versions beyond the known set and an `OpenSSH_for_Windows` `/C:/` path quirk flag are missing. |
| R13 remote uid/gids | **missing** | C18. |
| R14 meta/bulk channels or priority | **partly** | C17. |
| R15 cancel + per-request deadline + health check | **partly** | No default and no liveness probe (C16). |
| R16 RTT and throughput estimates | **missing** | 01 measures RTT internally. Export `srtt_ms`, `rttvar_ms`, `rx_bps`, `tx_bps` through `sd_sftp_session_stats()`. |
| R17 statvfs 64-bit | **met** | |
| R18 XP sync, no callbacks under locks | **met** | |

### 3.2 Other uncovered requirement items

| id | requirement | gap | proposal |
|---|---|---|---|
| G1 | "entries in This PC / Add network location" | 03 covers drives in This PC and a This PC context menu, but no "Add network location" or Network Shortcuts entry (03 §13.2 Q1). | Decision D14. |
| G2 | "Writes fail cleanly while disconnected" | 02's write-behind acknowledges `WriteFile` before the server does. A disconnect followed by Dokany's `void Cleanup` can lose data that the application believes was written; the only signal is a tray message. | Keep write-behind with 02's mitigations, add C45's `write_failed` notification, and amend the requirement (A5). Decision D9. |
| G3 | "Self-installing … universal with an x86 stub" vs ARM32 | The universal stub cannot serve ARM32 (04 is aware). ARM32 also has almost no backend: no Dokany, IoT Core lacks WebClient, Windows RT runs no third-party desktop code, and Windows 11 24H2 dropped ARM32 apps. | Decision D5. Amendment A7. |
| G4 | "Map POSIX permissions and uid/gid to … ACLs" | Owner SID mapping depends on knowing our uid (C18). | Covered once C18 lands. |
| G5 | "UI warns when a session negotiates a legacy algorithm" | 03 `legacy_algorithms = allow` shows no UI. | Acceptable as an explicit per-profile opt-out. Default `warn`. Policy can forbid `allow`. |
| G6 | "Import already-trusted keys from PuTTY and `known_hosts`" | 01 does live auto-copy, 03 does explicit wizard import. | C19 and decision D7. |

### 3.3 Proposed amendments to `requirements.md`

- **A1 (WebDAV availability).** Replace "always available, no driver" with "no driver; available where the
  Windows WebClient (WebDAV redirector) feature is present and not disabled. WebClient has been deprecated since
  November 2023, so Dokany is the primary backend on Windows 7 SP1+."
- **A2 (redirector auth quirk).** Replace "basic auth over plain http to localhost" with "authentication on
  loopback: Negotiate/NTLM via SSPI plus a per-mount path token; `BasicAuthLevel` is never changed."
- **A3 (symlinks).** "Symlinks: follow them or hide them (both backends). Exposing them as reparse points is
  deferred until Dokany ships an FSCTL callback in an official signed release."
- **A4 (global drives).** "Also a system service that can mount global drives visible to all users and
  available before logon (Dokany backend only)."
- **A5 (writes).** "Operations started while disconnected fail immediately. Data accepted before a disconnect is
  retransmitted after a reconnect within a grace period if the remote file is unchanged; otherwise the loss is
  reported to the user. There is no offline write queue."
- **A6 (own code).** After the hard-constraint line, add: "Exception: formally verified, generated field
  arithmetic (fiat-crypto) may be vendored with provenance; all protocol and other crypto code is ours."
  (Only if D1 is accepted.)
- **A7 (ARM32).** "ARM32: built in CI; supported only as CLI + agent with the WebDAV backend where WebClient
  exists (best effort, no installer support guarantee)." Alternatively drop ARM32 (D5).
- **A8 (x86 CPU floor).** "x86 requires SSE2." (If D4 is accepted.)
- **A9 (localization).** In AGENTS.md, replace "defined in `docs/design/` once approved" with a pointer to
  03 §9 (PO → generated tables, `sdl10n` completeness check).

---

## 4. Uncovered topics

| Topic | Why it matters | Proposal (owner) |
|---|---|---|
| **Module dependency graph** | Link order, test isolation, keeping the shell DLL and setup stub small. | §5 (all; enforced by a CMake check that a module links only declared dependencies). |
| **`sd_base` / `sd_platform` contents** | 01 "assumes" a base module; 03 and 04 assume others. | C39. Owner: the 04 team (build), API review by 01 and 03. |
| **Memory allocation policy** | `/MT` gives every DLL its own CRT heap (04 §2.4). 01 wants failure injection. 02 sizes caches. | All modules allocate through `sd_alloc`/`sd_free` (process heap, `HeapAlloc`), plus `sd_secbuf` for secrets (zeroized, `VirtualLock` best effort). A test hook injects failures. Memory is never freed across a public API boundary: every API that returns memory provides its own free function. Large buffers (cache blocks, Argon2) use `VirtualAlloc`. Memory per mount is budgeted (02 ≤ 20 MB) and counted by `sd_alloc` tags, reported in `status`. |
| **Shared logging API** | 01 `on_log` per connection, 03 `sd_log` with a logger thread, 02 unspecified. | `sd_log(level, component, mount_id, fmt, ...)` in `sd_platform`, using a restricted format language with no `%s` for secrets (03 §10.1). 01's `on_log` callback becomes a thin adapter. Sinks: file, debugger, ETW (Vista+), and an IPC `log` topic. Components are a fixed English enum (`ssh sftp crypto vfs dav dokan ipc ui cfg upd setup`). |
| **Profile → running mount orchestration** | Nobody owns "resolve profile + secrets + known_hosts + policy → `sd_ssh_config` → `sd_sftp_session` → `sd_vfs` → backend → IPC state". | A new host-internal module **`sd_mount`** (owner: 03) that holds the state machine (`connecting / authenticating / mounted / offline / auth_required / failed / unmounting`), maps `sd_sftp` events to `mount.state`, routes prompts, and owns drive-letter selection and the stale-mapping cleanup at start. |
| **Host-process threading model** | 01: one I/O thread per chain plus worker items. 02: Dokany pool, WebDAV pool (8–32), timer queue. 03: hidden window, IPC completion routines, logger thread. No one checks how they combine. | Host threads: (1) the main thread runs the hidden window, WTS/power/end-session messages, and the `sd_mount` control queue; (2) the IPC server thread (alertable); (3) one I/O thread per SSH chain; (4) the Dokany pool and the WebDAV pool; (5) the vfs background thread (timer queue); (6) the logger thread; (7) `QueueUserWorkItem` for KDFs, DNS and file I/O. Rules in §4.1. |
| **What a FAILED mount looks like** | 01/02 define FAILED and AUTH_REQUIRED, and 03 times out queued prompts after 10 min. Whether the drive letter stays mapped is not stated. | The drive stays mapped in an offline state. Cached reads work, everything else returns `DISCONNECTED`. The tray offers Reconnect. Only the user or a policy unmounts. |
| **Error-code master table** | `sd_err` → `sd_vfs_status` → NTSTATUS/HTTP, and `sd_err` → IPC code → exit code. | C13 and C25: one generated table in `sd_base`, checked by a unit test that covers every enum value. |
| **XML parser for WebDAV bodies** | 02 uses PROPFIND/PROPPATCH/LOCK bodies, and 04 fuzzes "XML body parser", but no design specifies one. | A minimal XML 1.0 non-validating parser in `sd_webdav` (no DTD, no external entities, namespaces, depth ≤ 32, body ≤ 1 MiB). Fuzzed. |
| **Config format versioning and migration** | 03 has `format = 1` per profile. Settings, the state snapshot, the IPC proto and the update manifest each version separately (04 §12.1). | One registry of format versions in `docs/` with an upgrade rule: newer files open read-only. |
| **Threat model** | Each document secures its own surface (pipes, loopback DAV, Dokany requestor checks, update signatures, DPAPI). No single list of assets, attackers and trust boundaries exists. | A short `docs/design/05-threat-model.md` before M5 (service), reviewed together with the external crypto review that 01 already budgets. |
| **Test strategy for `sd_vfs` without a kernel** | 04 tests Dokany only in the lab or optionally in CI. | `sd_vfs` gets an in-process mock `sd_sftp` (a fake server over a temporary directory) and a backend-neutral conformance suite (create dispositions, share modes, delete pending, rename, reconnect), run in `sd-test-vfs.exe` on every PR on every architecture. |
| **Pseudo-locale for layout tests** | 03's generated dialogs must not clip German/French text. | A build-only `qps` pseudo-locale (accented, +40 % length), never shipped and not counted as a language under AGENTS.md. |
| **User documentation** | Only design documents exist. | README plus an admin guide (GPO, MSI properties, service profiles, `EnableLinkedConnections`, WebDAV tuning) in M6. |

### 4.1 Cross-module threading rules (deadlock review)

1. **Completions never take `node.lock` or a cache shard lock.** An `sd_sftp` callback either fills the
   waiter's result block and calls `SetEvent`, or, for read-ahead and write-behind acknowledgements, which have
   no waiter, pushes the completion to the vfs background queue. All node and cache mutation happens on vfs
   threads. (02 §5.4 currently lets completions take "short locks". A Dokany thread copying a 256 KiB block
   under a shard lock would then stall the whole SSH chain, crypto and keepalive included.)
2. **No vfs lock is held across `sd_sftp_*` submission.** Submission is non-blocking, but the rule removes any
   lock-order dependency on 01's internal queue lock. 02's lock order then ends at the cache shard lock.
3. **`*_sync` wrappers, `sd_sftp_session_destroy` and `DokanCloseHandle`** may be called only from the host
   control thread or CLI threads, never from Dokany callbacks, WebDAV workers or I/O threads (C33).
4. **Prompt callbacks** (`on_prompt`) only enqueue to the IPC thread. Pipe writes never happen on an I/O
   thread, because a slow or hung UI client would stall keepalives.
5. **WebDAV pool sizing.** Streaming GET/PUT workers wait on backpressure. Reserve at least 2 workers for
   PROPFIND/OPTIONS/LOCK, so the redirector's 60 s `SendReceiveTimeout` never trips because of large
   transfers.
6. **Dokany request timeout.** Every vfs wait uses a deadline below 30 s and calls `DokanResetTimeout` only on
   progress (02 §6.6). Combined with C16, a dead link surfaces as `TIMEOUT`/`DISCONNECTED` within the
   Dokany deadline.
7. **Known_hosts and credential lookups** run on worker items, never on I/O or Dokany threads.

---

## 5. Proposed module dependency graph

Static libraries (`src/<module>`). Arrows mean "depends on". Apps link only what is listed.

```
                      sd_base  (no windows.h: buf, err+tables, utf/name map, json, ini, checked math, mem hooks)
                         ^
                      sd_platform  (Win32: alloc, resolve(System32), threads/locks/once, tick, paths,
                         ^           portable detection, sd_log + sinks, secbuf)
          +--------------+--------------------+-------------------+------------------+
          |              |                    |                   |                  |
      sd_crypto       sd_l10n             sd_config            sd_ipc            sd_import
      (own+CNG)    (catalog+format)    (ini profiles,       (pipes, json,     (PuTTY sessions,
          ^                              policies, schema)    auth checks)      ssh_config)
          |                                  ^                    ^                  |
       sd_ssh  (transport, auth, agents, keyfiles, known_hosts, ProxyJump)          |
          ^                                  |                    |                  |
       sd_sftp                               |                    |                  |
          ^                                  |                    |                  |
       sd_vfs  (nodes, caches, share modes, reconnect, error map) |                  |
          ^           ^                      |                    |                  |
      sd_webdav    sd_dokan                  |                    |                  |
      (http, xml,  (dynamic dokan2.dll)      |                    |                  |
       sspi, wnet)    ^                      |                    |                  |
          ^           |                      |                    |                  |
          +-----+-----+                      |                    |                  |
                |                            |                    |                  |
             sd_mount (host only: profile -> session -> vfs -> backend; prompts; letters)
                |                            |                    |                  |
                +--------------+-------------+--------------------+                  |
                               |                                                    |
   shelldrive-host.exe  = sd_mount + all of the above + sd_secret + sd_update
   shelldrive.exe (CLI) = sd_ipc, sd_config, sd_import, sd_l10n, sd_secret, sd_ssh[keyfile+known_hosts only]
   shelldrive-ui.exe    = sd_ipc, sd_config, sd_import, sd_l10n, sd_secret, sd_ssh[keyfile+known_hosts only]
   shelldrive-shellext  = sd_platform[min], sd_l10n[shell domain]   (no crypto, no IPC client, no threads)
   setup / uninstall    = sd_stubcore (/arch:IA32: platform-min, SHA-2, Ed25519 verify, FDI), sd_l10n[installer]
   tools/sd-release     = sd_crypto (Ed25519 sign), sd_ssh keyfile parser (signing key as OpenSSH key file)
```

- `sd_secret` (Credential Manager plus DPAPI files, 03 §4) depends on `sd_platform` only.
- `sd_update` (manifest parse/verify, WinHTTP fetch, staging) depends on `sd_crypto` (verify only) and
  `sd_platform`. It runs in the host (03/04 agree the agent owns updates).
- The CLI and UI link the key-file parser and the `known_hosts` code from `sd_ssh`. Static linking pulls only the
  referenced objects, but `sd_ssh` must keep those files free of transport dependencies (separate translation
  units, enforced by a link test).

---

## 6. Milestones

Each milestone ends with a recorded demo on the named systems and a green CI. 01 §13 maps its module work onto
these milestones. Rewritten on 2026-10-24 for `decisions.md`: everything decided "in v1" is placed in M0–M6;
M7 holds only post-1.0 work.

| M | Scope | Demoable outcome |
|---|---|---|
| **M0 — x64 Win10 vertical slice** | Repo layout, CMake presets (`x64-xp`, `x64-modern`, `x64-analysis`), `sd_base`/`sd_platform`, import audit, unit harness, CI build+unit. `sd_crypto` minimum, all own code (D1, D2): SHA-2, HMAC, own GF(2^255-19) field, X25519, Ed25519, ChaCha20-Poly1305@openssh, AES-CTR/GCM (own + CNG), RNG; KAT, Wycheproof and CNG differential harness from day one. `sd_ssh`: curve25519 KEX, strict KEX, ext-info, password + Ed25519 key file (unencrypted and bcrypt), `known_hosts` TOFU (user store, plain entries, D8). `sd_sftp`: 1 channel, core ops, pipelining, caller deadlines. `sd_vfs` (memory cache, no disk tier, symlinks `follow_inside` by default (D40), write-through, D9), `sd_dokan`. Host + CLI with `mount/unmount/list` over IPC and console prompts. `sdl10n` with `en` plus stub catalogs (full CLDR plural categories, D26) that fail the build until complete. | On Windows 10 x64 with Dokany 2.3.1: `shelldrive mount --host user@<WSL sshd>` → `Z:` in Explorer. Copy a 1 GiB file in and out with matching SHA-256. Explorer browse, rename, delete. TOFU prompt then mismatch block. |
| **M1 — Resilience and WebDAV** | Reconnect (01 §10.6, 02 §5), deadlines + liveness probe (C16), meta/bulk channels (C17, D19), write-behind as profile opt-in with sticky errors, grace retransmit and `write_failed` (D9), metadata TTLs, disk cache tier, identity without exec (D10). `sd_webdav` (Negotiate + path token, PROPFIND/PUT/LOCK, XML parser) and WebClient start. **Both x86 presets, `x86-ia32` and `x86-sse2` (D4)**, `sd-isacheck`; XP SP3 (incl. the non-SSE2 QEMU VM) and Win7 lab VMs; smoke harness over COM1. | Kill and restart sshd during a copy: reads continue from cache, writes fail cleanly, the mount recovers. Same mount through WebDAV on XP SP3 x86 (`x86-ia32` on the Pentium III VM, `x86-sse2` elsewhere) and Windows 7. Office opens and saves a .docx over WebDAV with locks. |
| **M2 — Authentication breadth and transport** | Own P-256/384/521 and `sd_bn`; ECDSA/RSA/DH/GEX; **SHA-3/SHAKE, ML-KEM-768 and `mlkem768x25519-sha256` (D15)**; legacy algorithms plus `legacy_mask` and `legacy_ack`, Terrapin policy; kbd-interactive/OTP, password change, PEM/PKCS#8, PPK v2/v3 (Argon2), certificates (user + host CA), Pageant + OpenSSH agent, ProxyJump N hops, **HTTP CONNECT / SOCKS5 proxies per leg with proxy auth and the opt-in system proxy (D20)**, Credential Manager + DPAPI fallback, DPAPI-kept keys (C22), PuTTY/OpenSSH importers, `known_hosts` store list with live OpenSSH/PuTTY sources (C19, D7), **UpdateHostKeys (D16)**, **connection pool 1–4 with bulk striping (D18)**. Interop matrix job incl. OpenSSH 10, Squid/Dante proxies. **Gate: external crypto review pass 1 at the end of M2 (all SSH + crypto code, D38); no public beta before it is closed.** | A two-hop ProxyJump through a SOCKS5 proxy with an OTP on the bastion and a PPK v3 key at the target, negotiating `mlkem768x25519-sha256` with no warning. Reconnect without prompting from cached secrets. A legacy 3DES server triggers the warning. A rotated host key is learned through `hostkeys-00` after review. `connections = 4` speeds up a large copy, and an OTP server keeps the pool at 1. |
| **M3 — UI, Explorer, full localization** | Tray, main window, generated dialogs, prompt dialogs, host key manager (incl. UpdateHostKeys review), logs viewer, first-run wizard, shell extension (x64 + x86), state snapshot, drive labels/icons, notifications incl. `write_failed`, **Network locations ("Add network location" entries, D14)**, the `IExplorerCommand` handler for the Windows 11 modern menu (D27; shipping depends on the certificate, M6). All 6 locales complete with full CLDR plurals (D26), register lint, `qps` pseudo-locale. Accessibility pass. | Full GUI flow in Spanish (voseo) and German at 150 % DPI on Windows 11: create a profile, mount from the This PC context menu, the profile appears under "Network locations", offline tray state, unmount from the drive context menu, 32-bit app file dialog shows the menu. |
| **M4 — Packaging and updates** | Setup stub from the `x86-ia32` preset, CAB payloads, per-user/per-machine/portable, **six flavours (`x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, `arm32`, `arm64`) and stub selection by CPU and OS (D4, D28)**, WiX MSIs per flavour incl. **ARM32 MSI (D31, best effort per D5)**, language transforms (C43), service installed and enabled by default per machine (D6), `ENABLELINKEDCONNECTIONS` (D24), Dokany chaining per the VC++ check (C31, D32), `webdav-tune` and the other installer hooks, upgrade with running processes (C3, C4), signed manifest, static HTTP mirror (D30), updater UI, rollback, ADMX/ADML for every 03 §3.5 policy, sparse MSIX build switch (D27), reproducible-build check. | On a clean Windows 10 and XP SP3: install from the universal EXE (the stub picks `x64-modern` resp. `x86-ia32`/`x86-sse2`), then auto-update from 1.0.0-beta.1 to beta.2 through the HTTP mirror after consent, while a drive is mounted. GPO-style MSI install with `DEFAULTPROFILES`. ARM32 MSI installs CLI + agent on Windows 10 on ARM (best effort). |
| **M5 — Service, sessions, elevation** | **Starts with the global WebDAV lab spike (D11, 02 §7.7): mechanisms `system`/`link` on every listed OS, go/no-go recorded per OS within the first weeks of M5; no-go OSes use the per-user `attach` fallback.** `ShellDriveSvc`: Dokany global mounts (primary path), service-hosted WebDAV per the spike, `service_access` checks, machine stores and secrets, no agents (D17), admin-only prompts, `hostkey add --from-server`, machine-store UpdateHostKeys under policy, fast user switching/RDP, elevated view (WebDAV attach), `EnableLinkedConnections` diag/fix, threat-model review (§4). | Windows Server 2022 with Secure Boot: a global Dokany drive exists at boot and is visible to two RDP users with group-based access. A global WebDAV drive on XP SP3 (or the OS the spike passed) and an `attach`-mode drive on a no-go OS. A non-admin cannot answer a service prompt. An elevated `cmd` sees a WebDAV drive after `--elevated-view`. |
| **M6 — Architectures, performance, 1.0 RC** | ARM64 (native host, ARM64 + x86 + x64 shell DLLs, Dokany ARM64), ARM32 per D5, SHA-NI/AES-NI/ARMv8 fast paths (SSE2 and later only in `x86-sse2`, x64, ARM), 02 §11 performance targets on L/W setups (write mode stated per target), pool tuning, fuzzing at nightly scale, external crypto review pass 2 (D1, D38) with findings closed (TST-33), Authenticode via SignPath Foundation or Certum OSS (D29) and **the sparse-MSIX modern menu if the certificate exists (D27)**, `x64-modern` CFG/CET checks, user and admin docs. | `shelldrive diag bench` report meets 02 §11 on x64 and ARM64. Lab smoke green on every VM in 04 §11.4. A signed RC published to the beta channel, with the Windows 11 modern menu if signed. |
| **M7 — Post-1.0** | `zlib@openssh.com`, adaptive channel windows, specialized NIST reductions, the modern context menu if 1.0 shipped without a certificate (D27), symlink reparse points revisited (D12, only if an official signed Dokany gains an FSCTL callback). | — |

**Security tests (05 §7)** are part of each milestone; P1 tests block that milestone's demo, P2 the next
milestone, P3 1.0: M0 TST-01, -03, -04, -05, -11 (mismatch, NEW_TYPE), -19 (Dokany part), -30; M1 TST-02, -06,
-08, -09, -10, -22; M2 TST-07, -11 (re-TOFU), -12 to -18; M3 TST-20, -21, -24, -28; M4 TST-27, -29, -31, -32;
M5 TST-19, -23, -25, -26 and the threat-model review; M6 TST-33. **Release gates (D38, 04 §12.3):** builds before
pass 1 go only to named testers; public betas need pass 1 closed and Authenticode (TM-R38); 1.0 needs pass 2.

---

## 7. Decisions for the user

Merged from 01 §15, 02 §13, 03 §13.2, 04 §15 and this review. Items that are lab tests rather than decisions
(02 Q2–Q5, Q10; 03 Q6–Q7; 04 Q2, Q3, Q6) are left to the verification matrices. Each decision lists the
recommended option first.

**Resolved 2026-10-24.** The final answers are recorded in [`decisions.md`](decisions.md) (D1–D32), which
overrides the "Recommendation" column below.

| # | Decision | Options | Recommendation (superseded by `decisions.md`) |
|---|---|---|---|
| D1 | Third-party crypto source (01 §2.5 vs 04 §4, hard constraint) | (a) vendor fiat-crypto field arithmetic only; (b) also Monocypher/BearSSL fragments; (c) zero vendored code | **(a)**, with provenance and requirement amendment A6 |
| D2 | Hashes/HMAC always own code, CNG for AES/ECDSA/RSA where present (01 Q2) | (a) as proposed; (b) CNG hashes on Vista+ | **(a)**; CNG remains the differential-test reference |
| D3 | Binary set and names (C1) | (a) 4 binaries: `shelldrive.exe`, `shelldrive-host.exe` (agent+service), `shelldrive-ui.exe`, `shelldrive-shellext.dll`; (b) 04's 5 binaries | **(a)** |
| D4 | x86 CPU floor (C34) | (a) SSE2 required; (b) support pre-SSE2 (`/arch:IA32` everywhere) | **(a)** |
| D5 | ARM32 support level (G3, 04 R2) | (a) CI build + best-effort CLI/agent/WebDAV, no promises, drop when it breaks; (b) full support; (c) drop now | **(a)**, with amendment A7 |
| D6 | Service install default (C6) | (a) off, opt-in; (b) on | **(a)** |
| D7 | `known_hosts` trust sources (C19, G6) | (a) `~/.ssh/known_hosts` and PuTTY as live read-only sources, on by default, matches copied to our file with a source comment; (b) explicit wizard/CLI import only | **(a)**; mismatches in any source still block |
| D8 | `known_hosts` entries plain or hashed (01 Q3) | (a) plain (file is ACL-protected); (b) hashed | **(a)** |
| D9 | Write-behind default (G2) | (a) write-behind with 16 MiB window, grace retransmit, `write_failed` notification, amendment A5; (b) write-through by default | **(a)**; `write_through` per profile |
| D10 | uid/gid discovery (C18, 02 Q9) | (a) no exec; owner of home + first created file; optional `identity_probe = exec`; (b) exec `id` by default | **(a)** |
| D11 | Global mounts with WebDAV (C27, 02 Q11) | (a) Dokany-only global drives in v1, WebDAV attach later; (b) agent attaches a service-hosted WebDAV server at logon in v1 | **(a)**, amendment A4 |
| D12 | Symlink reparse points (02 Q1) | (a) defer and propose an FSCTL callback upstream; (b) drop permanently | **(a)**, amendment A3 |
| D13 | Requirement amendments A1–A9 (§3.3) | accept / edit | **accept** |
| D14 | "Add network location" / Network Shortcuts (03 Q1, G1) | (a) not in v1; drives in This PC + This PC menu satisfy the intent; revisit in M7; (b) build in v1 | **(a)**, and amend the requirement to "drives in This PC; This PC context menu" |
| D15 | Post-quantum KEX scope (01 Q5) | (a) ML-KEM hybrid after 1.0 (M7), no sntrup761; (b) in M2 | **(a)**, revisit if target servers start warning or refusing |
| D16 | UpdateHostKeys `hostkeys-00@openssh.com` (01 Q6) | (a) later; (b) v1 | **(a)** |
| D17 | Agents in the service context (01 Q7) | (a) no agents; DPAPI service keys only; (b) allow | **(a)** |
| D18 | Parallel SSH connections per mount (01 Q8) | (a) no in v1; (b) yes | **(a)** |
| D19 | SFTP channels per mount (01 Q9, 02 R14) | (a) 2 (meta + bulk, C17), auto-degrade to 1; (b) 1 | **(a)** |
| D20 | HTTP/SOCKS proxy, ProxyCommand (01 Q10) | (a) out of scope for v1; (b) in scope | **(a)** |
| D21 | Linux CI for fuzzing and Linux SSH interop servers (01 Q4, 04 §11.3) | (a) WSL fixture on Windows runners + self-hosted lab for exotic servers, optional Linux fuzz job; (b) Windows only | **(a)** (test infrastructure only, nothing ships) |
| D22 | `FILE_ATTRIBUTE_OFFLINE` thumbnail suppression on WebDAV (02 Q6) | (a) profile option, default off; (b) drop | **(a)** |
| D23 | Dokany volume file system name (02 Q7) | (a) `NTFS` by default, configurable; (b) an honest name | **(a)**, pending the compatibility test list |
| D24 | `EnableLinkedConnections` in corporate MSI (03 Q3) | (a) MSI property, default 0; (b) default 1 | **(a)** |
| D25 | Per-user overrides of `scope = users` templates (03 Q4) | (a) target and autostart only; (b) none; (c) all | **(a)** |
| D26 | Plural categories (03 Q5) | (a) `one/other` only, confirm with translators; (b) full CLDR | **(a)** |
| D27 | Windows 11 modern context menu via sparse MSIX (03 Q2, 04 Q5) | (a) after a code-signing certificate exists (M7); (b) v1 | **(a)** |
| D28 | Second x64 flavour built with v143 (CFG/CET) (04 Q1) | (a) decide after 1.0; (b) ship in 1.0 | **(a)** |
| D29 | Code-signing certificate source (04 §10, R4) | (a) SignPath Foundation once the repo is public, else Certum OSS; (b) commercial OV | **(a)**; obtain before public 1.0 (Smart App Control) |
| D30 | HTTP mirror for updates (04 R7) | (a) static object storage with plain HTTP, no forced redirect; (b) self-hosted server | **(a)** |
| D31 | Standalone ARM32 MSI (04 Q4) | (a) no; (b) yes | **(a)** |
| D32 | Dokany redistributable form (C31) | (a) MSIs if `dokan2.dll` has no VC++ dependency, otherwise the upstream `DokanSetup.exe` bundle in offline EXEs; (b) always the bundle | **(a)** after the dependency check |

---

## 8. Reconciliation status

Final cross-document reconciliation, 2026-10-24. Precedence used: `decisions.md` > this review's resolutions >
the owning document (01: SSH/SFTP/crypto/known_hosts I/O; 02: VFS/WebDAV/Dokany; 03: processes/IPC/profiles/
UI/l10n/policies; 04: build/install/update/CI). Each document's changelog has a "Final reconciliation" entry.

**Resolutions of §2–§3 changed by decisions** (the documents follow the decision):
C6 → D6 (service on by default per machine, never per user); C16 → deadlines are always set by the caller
(25 s Dokany, 50 s WebDAV; 30 s only for callers that pass none); C18 → D10; C27 → D11 (global WebDAV drives
attempted via `system`/`link` mapping, per-user `attach` fallback; service profiles with `backend = webdav` are
accepted); C29 → D12; C34/C35 → D4 (two x86 flavours, stub from `x86-ia32`); C37 → D1 (no exception; A6
dropped); G1 → D14 (Network locations in v1); amendments A3, A4, A5, A8 as rewritten by D12, D11, D9, D4. The
§3.1 R1–R19 gaps are all met by 01 §10 (02 §9 records where).

**Fixed in this pass**
- 00 §6: milestones rewritten for D4, D14–D16, D18, D20, D27, D28, D31, D11 (spike at the start of M5).
- 01 ↔ 03 known_hosts: any mismatch blocks (D7, 01 §7.2); one source-comment format (03 §5.1).
- 01 ↔ 03 UpdateHostKeys: an event (`SD_HKEV_ANNOUNCED`), never a prompt; `sd_ssh` never writes stores itself;
  default `ask`; removals only after review; machine store only with policy `UpdateHostKeys = 2`
  (`UpdateHostKeysMachine` dropped).
- 01 ↔ 02 pool: one `sd_sftp_session` per mount; extra connections open a bulk channel only (D19); striping
  and sub-handles inside `sd_sftp` (`SD_SFTP_O_STRIPED`); `session_ready` resubmission; primary loss closes all
  members; same host key + home required of members; `exec` identity probe inside `sd_sftp`.
- 01 ↔ 03 profile keys: `identity_probe = owner|exec`, per-leg `proxy`/`proxy.K` spec and `proxy_auth` mapping,
  `proxy_fallback_direct` added to 03's schema, `legacy_algorithms` → `legacy_policy`, `sd_err_name` spellings
  `proxy_connect_failed` / `legacy_refused`; system-proxy resolution owned by `sd_ssh`.
- 02 ↔ 03: `service_access` (default `BUILTIN\Users`) replaces "allowed group / Authenticated Users";
  `webdav_global_mode = auto|system|link|attach`.
- 03 ↔ 04: installer hooks are 03's set (`webdav-tune`, `user-cleanup`, `modern-menu`, `signal-shutdown`), run as
  `shelldrive-host.exe --installer-hook`; Network Shortcuts marker `[ShellDrive] profile=` with no list file;
  sparse-package registration per user by the agent on per-machine installs; ADMX table covers every 03 §3.5
  policy; 04 §8.5 no longer says global drives need Dokany.
- ARM32 minimum OS aligned with `decisions.md` in 02 §10.2 and 04 §1.1.
- Verified consistent, no change needed: binary names (D3), `ShellDriveSvc`, shutdown event
  `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>` without `Local\` fallback, `shelldrive-host.exe --selftest`,
  `settings.ini [update]` + `state\update.ini`, `DEFAULTPROFILES` as a folder of `.ini` profiles, no Basic auth on
  WebDAV, pipe names, Dokany 2.3.1 (min 2.1.0), the six flavour names, 04 §3.2 two x86 flavours, `symlinks =
  follow | hide`, global memory budget.

**Still open** (lab verification, by design not decided on paper)
- D11 global WebDAV spike per OS (02 §7.7, G1–G6), early M5.
- C31/D32 `dokan2.dll` VC++ dependency check, first week of M4.
- Dokany 2.3.1 cached-write path vs the write-through guarantee (02 §4.4), and Dokany default timeout.
- SSE2 MSI launch condition via `FeatureSet` (04 §8.2); v141 CRT start-up on a non-SSE2 CPU (04 §3.2).
- Sparse package: all-user provisioning and the `Drive` item type (03 §8.6); Network-location folder-shortcut
  behaviour on XP/7/10/11 (03 §8.7); XP ARP listing of HKCU entries (04 §6.7).
- Proxies: NTLM/Negotiate over SSPI on XP, meaning of IE `socks=` entries (01 §15, 03 §3.8); PuTTY value names.
- ~~Not yet written: `05-threat-model.md`~~ — written; see below.

**Final reconciliation (threat model) 2026-10-24.** `05-threat-model.md` exists; the user decided TM-Q01–Q09 and
TM-R01–R39 in `decisions.md` D33–D43, and 01–05 apply them (05 §11 lists where each TM-R lives). Cross-document
names fixed in this pass: `hostkey_just_accepted` (01/03, replaces 03's `trust_fresh`); explicit "add key" through
`sd_ssh_conn_fetch_hostkeys()` inside a verified connection (01 §4.3, 03 §6.1; `SD_SSH_CFG_HOSTKEY_ANY_TYPE`
dropped); `identities_only = yes|no` with D37 default (03 `auto` dropped); `security.trust = untrusted|trusted`,
default `untrusted` (D41, 02 §4.5, 03 §3.4.1); `symlinks` default `follow_inside` for every profile (D40);
`mark_of_the_web` default `off` and independent of trust; `sd_dump_mark_sensitive()` and no
`--include-secret-stacks` (D43); `sd_pipe_verify_server` (TM-R08); updater state files `last_serial.<channel>`,
`last_verified.<channel>`, `keyset`, cached `dokany-deny` list (03 §3.2, 04 §9.2; `state\update.ini` and the
"verified" `symlinks = follow | hide` above are superseded); machine `[backend] dokany = yes|no` from `DOKANY=0`
(02 §10.1, 03 §3.4, 04 §8.4); hook `programdata-secure` in 03 §6.1; `webdav-tune` originals in
`service\state\webdav-tune.ini`; `sd-ctcheck` CI gate (TST-03); D42 two signing sessions (04 §12.3); `service_access`
required with no default (D35; the `BUILTIN\Users` default above is superseded).

LibreStatic naming (D45) 2026-10-24: registry, folder, pipe and kernel-object names quoted in C3, C5, C8, C9, C12
and the verification notes now use `LibreStatic\ShellDrive` paths and `com.librestatic.shelldrive.*` object names.
