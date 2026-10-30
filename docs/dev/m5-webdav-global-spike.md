# M5 spike: global WebDAV drives (D11)

Status: decided on 2026-10-27 from the lab that this machine can provide (Windows 11 IoT Enterprise LTSC 2024,
build 26100, one standard user, non-elevated). The spike was run as the design asks in 02 §7.7 ("Lab spike (early M5,
go/no-go per OS)"), but most of its criteria need a LocalSystem process, a second logon session and other OS
versions, which this run could not reach. The result is therefore mostly a **no-go for now** plus the mechanism
decision logic that lets the lab flip a cell to GO later without code changes to the policy.

Related: `docs/design/02-filesystem.md` §7.7, `docs/design/03-apps-platform.md` §1.3 and §1.7, `docs/design/decisions.md`
D11, D17, D24, D35, `docs/dev/m5-notes.md`.

## Verification legend

- **[V]** verified by an experiment on this machine (Windows 11, 10.0.26100, session 1, standard user). Each one names its probe.
- **[U]** unverified. The statement comes from documentation, from the redirector model or from reasoning. A lab run can confirm or refute it.
- **[D]** a design statement from 02 §7.7 or 03 §1.3 that this spike did not test.

## 1. Summary and go/no-go

| Mechanism | What it is | Decision | Reason |
|---|---|---|---|
| `system` (02 §7.7 A) | `WNetAddConnection2W` by the LocalSystem service | **No-go** on XP/2003, Vista/7, 8/8.1, 10/11 | The mapping lives in the SYSTEM logon session, so user accesses travel on the service's connection and the server sees the service identity, not the user (G2 fails by reasoning [U]). Nothing in this spike could make it pass. |
| `link` (02 §7.7 B) | Global DOS device `\GLOBAL??\X:` on the raw target `\Device\Mup\localhost@PORT\DavWWWRoot\s-<token>`, defined by the service | **No-go for v1, candidate for the lab** on every family | Identity is the right shape by design [D], and the session-local form is accepted without elevation [V]. The part that matters, a global definition made by LocalSystem that every session sees (G1, G3, G5), needs a LocalSystem process and a second logon session. Not testable here. |
| `attach` (02 §7.7 fallback) | No drive before logon. Each user's agent maps the UNC returned by the service in its own logon session | **Go as the fallback on every family**, conditional on the service-side method and the per-user identity lab (G2, G7) | The per-user mapping path is the one already used for per-user mounts (`sd_webdav_map`, 02 §7.3). The service half (`mount.attach_info` for global profiles) is not in this build. |
| `refuse` | The mount fails with a stable IPC code | Used when the table, the policy or the service state rules the others out | See section 5. |

Consequences for the design:

- `webdav_global_mode = auto` resolves to **attach on every OS** until a lab run changes a cell. 03 §1.3 said "until then
  `auto` means `system` on XP/2003 only". That line is **superseded**: the spike gives no evidence for `system` on XP
  and the G2 reasoning argues against it. Dokany remains the pre-logon and primary path (D11).
- An explicit `system` or `link` for a cell that is not GO is **refused**, it does not degrade to attach. An admin who
  asked for a mechanism gets an error, not a silently different mechanism.
- Pre-logon availability (G6) is not promised for any WebDAV global drive. Only Dokany global drives are available before logon.
- `attach` requires the per-user identity test (two standard users, each mapping the other's UNC) on each OS family
  before the service-side method ships. That is G2 and TM-R18 (02 §7.4, §7.7).

## 2. What was run

| Probe | Where | Result |
|---|---|---|
| Elevation of the probe process (`GetTokenInformation(TokenElevation)`) and the PowerShell `WindowsPrincipal.IsInRole(Administrators)` check | this machine | [V] not elevated; the probe refuses to run in an elevated token and did not |
| OS and session (`RtlGetVersion`, `ProcessIdToSessionId`, token LUID) | `docs/dev/m5-spike/gw_dosdev_probe.c` | [V] 10.0 build 26100, session 1, logon session LUID `0x967f4` |
| `DefineDosDeviceW` in the caller's own logon session with the mechanism-B target form, `QueryDosDeviceW`, removal, query again | same probe, case A | [V] define ok, query returns the raw `\Device\Mup\localhost@1\DavWWWRoot\s-…`, removal ok, the name is then not defined. Session-local definitions need no elevation. |
| `DefineDosDeviceW` with a `Global\` name as a standard user | same probe, case B | [V] **denied, error 5 (ERROR_ACCESS_DENIED)**. No link was created, so nothing had to be removed. |
| WebClient service state (read-only `Get-Service`) | this machine | [V] `Running`, start type `Manual` |
| `EnableLinkedConnections` under `HKLM\...\Policies\System` (read-only) | this machine | [V] value absent (default 0, as D24 expects) |
| Unit tests of the decision logic and of the attach seam (`tests/unit/sd_svc/test_gw.c`) | the build | [V] see section 7 |

Not run, and why: a LocalSystem process or service (forbidden by the task, needs elevation); a mapping of a real
WebDAV server (no admin rights, and a persistent mapping was forbidden); a second logon session or a second user
(needs an account and a fast-user-switch or RDP session); XP, Vista, 7, 8.1, Server 2008 R2, 2012 R2, 2016 and later.

The probe source is `docs/dev/m5-spike/gw_dosdev_probe.c`. It is not part of any build target. Its binary is under
`build/spike/` and was not committed.

## 3. Per mechanism and OS family

Column meanings: **visibility** is how a drive made by the service shows up in user sessions; **redirector** the
constraints of the WebDAV redirector that apply; **identity** what the WebDAV server sees as the caller (G2).

### 3.1 `system`: service maps the drive as LocalSystem

| OS family | Visibility | Redirector constraints | Identity (G2) | Status |
|---|---|---|---|---|
| XP / Server 2003 | 02 §7.7 and D11 expect the LocalSystem mapping to be global on XP/2003 [D]. Not verified. | WebClient on XP is user-mode under WinINet (02 §7.1) [D]. The mapping is created by the service in its own context [D]. | Accesses from user sessions would go through the SYSTEM connection, so the server sees the service identity, not the user [U, reasoning]. The 02 §7.7 open question is exactly this. | NO-GO (UNVERIFIED cell, reasoned to fail G2). |
| Vista / 7 | A mapping made in the SYSTEM logon session (LUID `0x3e7`) is not in the user logon sessions' DOS device maps. It is not visible in user sessions unless it also lands in `\GLOBAL??` [U]. | WebClient is trigger-started on 7 (02 §7.1) [D]. | Same as XP, the service identity [U]. | NO-GO. |
| 8 / 8.1 | As Vista/7 [U]. | WebClient is deprecated since November 2023 and not started by default (02 §7.1, Microsoft deprecated features) [D]. | As above [U]. | NO-GO. |
| 10 / 11 | As Vista/7 [U]. The probe confirmed the session-0 and per-LUID split only indirectly: a standard user cannot define a `Global\` name [V], so a global definition needs the service. | WebClient is trigger-start and not started by default [D]; this machine has it running (V). | As above [U]. | NO-GO. |

### 3.2 `link`: service defines a global DOS device on the UNC

| OS family | Visibility | Redirector constraints | Identity (G2) | Status |
|---|---|---|---|---|
| XP / Server 2003 | A global link (`Global\X:`) would be in `\GLOBAL??`, which every session sees unless a per-LUID entry shadows the letter [U]. The XP form of the raw target (`\Device\Mup\…` with the http form) is not verified (02 §7.7 says verify) [U]. | Each user's first access creates the implicit connection through `\Device\Mup` in that user's logon session [D]. | Designed to be per user [D]: the connection carries the accessing user's default credentials and SSPI sees that SID. | UNVERIFIED. Not chosen. |
| Vista / 7 | Session-local raw define accepted without elevation [V]. Global define denied to a standard user [V], so only the service can make it. Global visibility to other sessions: [U]. | Explorer may show the drive as "Disconnected network drive" or without a label; users cannot disconnect it, only the service can remove it [D]. | Per user [D]. Expected to pass, not measured. | UNVERIFIED. Not chosen. |
| 8 / 8.1 | As Vista/7 [U]. WebClient deprecated (section 3.1). | As Vista/7 [D]. | Per user [D]. | UNVERIFIED. Not chosen. |
| 10 / 11 | As Vista/7. Session-local define and global denial verified on this machine [V]. Global visibility, LocalSystem define and per-user identity not measured [U]. | As Vista/7. WebClient is running here, which is the state NTLM coercion (TM-R21) needs; it stays a Dokany-first machine. | Per user [D]. | UNVERIFIED. Not chosen. |

### 3.3 `attach`: per-user mapping at logon

| OS family | Visibility | Redirector constraints | Identity (G2) | Status |
|---|---|---|---|---|
| XP / Server 2003 | The agent maps the UNC in its own logon session (`WNetAddConnection2W`, http form, provider Web Client Network). Visible to that session only, the same as any per-user mapping [D]. | Same as the existing per-user path, which 02 §7.1 covers [D]. | The user's own token, checked by the service's Negotiate SID check [D]. | GO as fallback, conditional on the service method and the G2 test. |
| Vista / 7 | Same, with the UNC form `\\localhost@PORT\DavWWWRoot\s-<token>` [D]. Not visible before logon [D]. | Same [D]. | Same [D]. | GO as fallback, conditional. |
| 8 / 8.1 | Same [D]. WebClient is not started by default; the mapping starts it (02 §7.2) [D]. | Same [D]. | Same [D]. | GO as fallback, conditional. |
| 10 / 11 | Same [D]. The mapping path itself is the one `sd_webdav_map` uses for per-user mounts, which the test suite covers in-process [V for the decision and the seam, see section 7]. | Same [D]. | Same [D]. | GO as fallback, conditional. |

Elevated sessions (03 §1.7.2): an attach mapping is per logon session, so the elevated token of the same user does not
see it unless `EnableLinkedConnections` is set or the elevated CLI attaches it itself (`--elevated-view`, 03 §1.7.2).
That is the same behavior as any per-user WebDAV mount [D].

## 4. Redirector and platform constraints that shape every choice

- **WebClient must run in the user's session for attach and in the service for link/system.** The read-only query
  (`sd_webdav_query_client`) is the only thing a service decision may do before it starts WebClient (02 §7.2, TM-R21).
  This machine has WebClient running with Manual start [V].
- **Credentials and SSPI from session 0.** The service accepts Negotiate contexts under its own account
  (`AcceptSecurityContext` with the service credentials) and reads `TokenUser` from the result. It never impersonates
  the caller. This is the design of 02 §7.7 [D]. Not run here: the probe is not LocalSystem.
- **Per-logon-session drive letters.** A mapping and a DOS device are per logon session (LUID). A global DOS device
  is the only object here that crosses sessions, and it needs `SeCreateGlobalPrivilege` (the `Global\` denial in
  section 2 is the observed side of that rule) [V for the denial, D for the privilege reason].
- **`EnableLinkedConnections`**: off on this machine (absent) [V]. It concerns elevated tokens of the same user, not
  other users, so it does not change the global decision. Its effect on a global `\GLOBAL??` link is not known [U].
- **Explorer and labels.** `_LabelFromReg` is per user (02 §7.3). A global link has no label for users who did not
  write one [D].
- **Stale mappings (TM-R17).** A global link or system mapping survives a service crash until the service restarts
  and removes it (02 §7.7 crash filter). Only the service can remove a link, so the service's start-up cleanup is
  mandatory for both mechanisms. Attach mappings are per user and are cancelled by the agent's watchers (02 §7.3).

## 5. Decision logic (implemented in this change)

`apps/shelldrive-host/svc_gw.c` chooses the mechanism from four inputs, in this order:

1. token-only requested → refuse (`usage`). TM-R19 forbids token-only for every global mount.
2. `webdav_global_mode` not one of `auto`, `system`, `link`, `attach` → refuse (`usage`).
3. service core not running → refuse (`backend_unavailable`).
4. OS family unknown (not 5.1/5.2, 6.0/6.1, 6.2/6.3, 10.0) → refuse (`backend_unavailable`).
5. WebClient missing, disabled or unknown → refuse (`backend_unavailable` / `webclient_disabled`). Stopped is allowed: the mount starts it (02 §7.2).
6. Mode: `system` or `link` for a cell that is not GO → refuse with the reason naming it. `attach` → attach. `auto` → system if its cell is GO, else link if its cell is GO, else attach.

The compiled table (`svc_gw_compiled_table`) has every cell UNVERIFIED, so no shipped build chooses system or link.
A lab run changes a cell from UNVERIFIED to GO only with a note in this report and the G1 to G7 evidence it relies on.
Tests inject tables to show that GO cells are chosen in the right order and NOGO cells never are.

The attach seam (`svc_gw_attach.c`) validates the remote name the service returns (`\\localhost@PORT\DavWWWRoot\s-<26 base32>`
for Vista+, `http://localhost:PORT/s-<26>` for XP) and maps it through an injectable `add`/`cancel` pair. The real pair
calls `WNetAddConnection2W` and `WNetCancelConnection2W` without `CONNECT_UPDATE_PROFILE`. The tests use a fake pair only.

Not wired: `service.c` still refuses WebDAV for global profiles (`svc_validate_profile`, D11 text), and the service has
no `mount.attach_info` for global profiles yet. Wiring is the next step after the lab criteria for attach are in place.

## 6. Security implications

- **Who can reach a global export.** For `link` and `system` the path token is not a secret: it is in every user's
  `QueryDosDevice` and the `net use` output (02 §7.3, §7.7). The barrier is the SSPI check against `service_access`
  (G7). A local user outside the list gets `403`, not data. This must be tested with a second user (lab).
- **Token-only is never used for global mounts.** `wd_tokenonly.c` already refuses a global mount (TM-R19) and the
  new decision refuses it first. A global mount that asked for it gets a `usage` refusal.
- **Session-0 callers.** Processes other than SYSTEM in session 0 are refused, and SYSTEM only with `allow_system` (02
  §7.7). Not changed here.
- **Browser and drive-by requests** are blocked by the Origin and Sec-Fetch checks before authentication (02 §7.3). Not changed here.
- **WebClient running.** A running WebClient turns NTLM coercion into HTTP (TM-R21, 02 §7.2). `link` and `system` need it
  running on the machine that serves the drive. On domain-joined machines with Dokany, the admin guide recommends
  Dokany and a disabled WebClient (03 §10.5). The decision refuses on `disabled` but does not start WebClient itself.
- **Attach** gives each user a mapping only after the service has returned the UNC for a profile that user may use.
  A user who is not in `service_access` cannot get the UNC from the service (the method is admin-only or list-filtered
  in the service, not built yet).
- **Mapping cleanup.** Crash, watcher and start-up cleanup rules of 02 §7.3 apply to every mechanism. For global
  mechanisms the service removes its own link or mapping before binding (TM-R17 d).

## 7. Tests and verification

| Check | Result |
|---|---|
| `x64-modern-debug`, `ctest -LE "matrix|bench|repro"` | 79 of 79 passed |
| `x64-xp-debug`, same | 79 of 79 passed |
| `sd-test-svc.exe` (`unit.svc`), `x64-modern` | 42 tests, 0 failed (28 existing, 14 new in `test_gw.c`) |
| Compiler warnings, `x64-modern` Debug build | 0 (`C4996` on `wcsncpy` was fixed in this change) |
| Probe, standard user | section 2 |

Result block (filled from the build log of this change):

| Preset | Build | ctest (`-LE "matrix|bench|repro"`) |
|---|---|---|
| `x64-modern-debug` | clean, 0 warnings | 79 of 79 passed |
| `x64-xp-debug` | clean, 0 warnings | 79 of 79 passed |

## 8. What is unverified

- Every statement about LocalSystem mappings and global links in section 3 that is not marked [V].
- XP-specific forms: `\Device\Mup` as a raw global target on XP, the http form under LocalSystem, and XP's visibility rule.
- Global visibility of a session-local definition made by LocalSystem, in every logon session, including RDP,
  fast user switching and elevated tokens.
- G2 (identity per user, no connection sharing across logon sessions) on any OS, for `attach` too (TM-R18 test, 02 §7.4).
- G3 (WebClient and service restart, sleep/resume), G5 (copy 1 GiB with matching SHA-256, Office save with locks,
  two users), G7 (negative access, membership change within 60 s). None was run.
- G6 (access before logon). Not claimed for any WebDAV global mode.
- Whether a standard user on this machine can do anything else with `\GLOBAL??` that matters (not tested beyond the `Global\` denial).
- The Windows 8/8.1, 7 and Server versions of section 3: no machine.

## 9. Lab plan to flip a cell

Run on each OS family (XP SP3 x86, Vista SP2, 7 SP1 x86 and x64, 8.1, 10 22H2, 11 24H2+, Server 2008 R2, 2012 R2, 2016,
2019, 2022, 2025, 02 §7.7 list), with a LocalSystem test service, two standard users, one admin and RDP:

1. `link`: service defines `Global\X:` on the raw target. Check G1 from console, RDP and fast user switching, then G2
   (both users, TokenUser per session), G3 (restart WebClient and the service), G5 and G7.
2. `system`: same criteria, plus a check of whether the server sees the service identity for user accesses (expected: yes, which means no-go).
3. `attach`: two users map each other's UNC with the right token and must fail SSPI (TM-R18). Then G5 and G7 on each OS.

When a cell passes G1 to G5 and G7, change the table entry from UNVERIFIED to GO in `svc_gw.c`, add the evidence here,
and add a test row in `test_gw.c`.
