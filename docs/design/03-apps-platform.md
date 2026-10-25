# 03 — Applications and platform integration

Status: proposed design, revised to apply `decisions.md` (D1–D32) and the conflict resolutions of
`00-integration-review.md` (see the changelog at the end). Where this document and `decisions.md` disagree,
`decisions.md` wins. Scope: everything around the SSH/SFTP/crypto core (`sd_crypto`, `sd_ssh`, `sd_sftp`,
see 01) and the filesystem layer (`sd_vfs`, `sd_webdav`, `sd_dokan`, see 02): processes, IPC, configuration,
credentials, host key storage, CLI, tray and main window, Explorer integration, localization, logging and
diagnostics. Build, installer, updater and CI are designed in 04; this document lists what they must provide.

Conventions: "XP" means Windows XP SP3 x86. "Vista+" includes Server 2008+. Every Vista+ API is resolved with
`GetProcAddress` at runtime unless stated otherwise; the binaries must load on XP without missing imports.
Platform facts that drove a decision are cited inline; facts we could not verify in a primary source are marked
**[verify]** and collected in the test matrix (section 13.3).

---

## 1. Process architecture

### 1.1 Binaries

| Binary | Subsystem | Runs as | Purpose |
|---|---|---|---|
| `shelldrive.exe` | console | the invoking user (any token) | CLI. Thin client of the agent/service. Can edit configuration offline. |
| `shelldrive-host.exe` | GUI (no visible window) | user (`agent` mode) or LocalSystem (`service` mode) | Owns SSH sessions and mounts. The only binary that links `sd_ssh`, `sd_sftp`, `sd_crypto`, `sd_vfs`, `sd_webdav`, `sd_dokan`. |
| `shelldrive-ui.exe` | GUI | the interactive user, never elevated by default | Tray icon, main window (connection manager), prompt dialogs, first-run/import wizard, settings. |
| `shelldrive-shellext.dll` | DLL | loaded into Explorer and file dialogs | Context menu handler (`IShellExtInit` + `IContextMenu`; `IExplorerCommand` for the Windows 11 modern menu, 8.6). No crypto, no IPC client, no CRT-heavy code. |

These are the only four binaries (D3). There is no separate agent or service executable: the service is
`ShellDriveSvc` = `shelldrive-host.exe service` and the agent is `shelldrive-host.exe agent` (C1, C2). Health check
for installers and the updater: `shelldrive-host.exe --selftest` (loads every module, resolves runtime imports,
opens and parses the configuration, exits 0 when healthy; no network). Smoke tests use the CLI command
`shelldrive selftest --json` (6.1), which runs the same checks in the CLI and asks the running agent (if any) for
its own `--selftest` result over IPC.

Why these four and not one:

- **CLI must be a console binary, the rest must not.** A GUI-subsystem CLI cannot write to the parent console
  reliably; a console-subsystem agent flashes a console window at logon. Hence at least two executables.
- **Agent separate from UI.** Mounts must survive a UI crash, a UI restart after a language change, and must
  work with no UI at all (Server Core, IoT, CLI-only users, ARM32 IoT images without Explorer). The long-lived
  process also has the smallest attack surface: no rich edit controls, no shell dialogs, no COM.
- **Agent and service share one binary** (`shelldrive-host.exe agent` / `shelldrive-host.exe service`): both need
  the full protocol and filesystem stack; one binary halves the size of the install and the signing work. The mode
  is chosen by the first argument; `service` mode refuses to run unless started by the SCM
  (`StartServiceCtrlDispatcherW` fails with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`).
- **UI does not link the SSH stack.** It talks to the agent over IPC. It links `sd_base` (`sd_json`, `sd_ini`,
  `sd_utf`), `sd_platform` (`sd_log`, allocator, runtime resolution), `sd_config`, `sd_import`, `sd_l10n`,
  `sd_ipc`, `sd_secret` and the key-file and known_hosts translation units from `sd_ssh` (no transport, no crypto
  beyond SHA-256 for fingerprints, which `sd_crypto` exposes as a standalone object file). Module names follow the
  review's split into `sd_base` (no `windows.h`) and `sd_platform` (Win32) (C39); the dependency graph is
  `00-integration-review.md` §5.

### 1.2 The agent (`shelldrive-host.exe agent`)

- **One agent per (user SID, Terminal Services session ID).** Identity is enforced by the pipe name (2.1) and a
  session-local mutex `Local\ShellDrive.agent.<SID>`. `Local\` objects are per session on XP and later, so the
  mutex alone gives the per-session uniqueness; the SID in the name guards against the rare case of a different user
  in the same session (`runas` in the same desktop).
- **Always runs with the non-elevated (filtered) token** on Vista+ when the user is a split-token administrator.
  Drive letters are bound to the logon session LUID of the token that creates them (WNet drive letters are tracked
  per AuthenticationID —
  [WNetAddConnection2](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w)),
  and the filtered token is the one Explorer runs with. A mount created by an elevated agent would be invisible to
  Explorer. See 1.7 for how an elevated client starts the agent unelevated.
- **Start:** (a) per-user installs: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ShellDriveAgent =
  "<path>\shelldrive-host.exe" agent --logon` when at least one profile has `autostart = logon` or the user enabled
  "Start ShellDrive at sign-in"; per-machine installs: one HKLM Run value written by the MSI `Autostart` feature,
  `"<path>\shelldrive-host.exe" agent --logon --if-needed`, which exits at once when the user has no autostart
  profile (own or `scope = users` template), no Network location entry to maintain (8.7) and no tray enabled; the
  session mutex prevents a double start when both keys exist (C11); (b) on demand by the CLI, UI or shell extension when the pipe does not exist
  (spawned with `CreateProcessW`, `DETACHED_PROCESS`, inheriting no handles; the client then waits on the named
  event `Local\ShellDrive.agent.ready.<SID>` for up to 10 s).
- **Stop:** when the logon session ends (`WM_QUERYENDSESSION`/`WM_ENDSESSION` on a hidden top-level window; a
  message-only window does not receive these broadcasts), on `agent.shutdown` IPC (used by `shelldrive agent stop`),
  when its **shutdown event** is signaled (below; used by setup and the updater), or after it has been idle (no
  mounts, no connected clients) for 5 minutes when it was started on demand. An agent started with `--logon` stays
  resident so that tray state and autostart remounts work.
- **Shutdown event (C3):** at start each agent creates the manual-reset event
  `Global\ShellDrive.agent.shutdown.<UserSidString>.<SessionId>` with the DACL
  `D:P(A;;0x00100002;;;<UserSID>)(A;;0x00100002;;;SY)(A;;0x00100002;;;BA)` (`EVENT_MODIFY_STATE | SYNCHRONIZE`
  for the user, SYSTEM and Administrators) and waits on it in the main thread's `MsgWaitForMultipleObjects` loop.
  `Global\` events work on XP and need no `SeCreateGlobalPrivilege` (that privilege applies to file mappings and
  symbolic links only), so there is no `Local\` fallback. If `CreateEventW` returns an existing object whose owner
  is not the user or SYSTEM (squatting), the agent logs an error and runs without the event; setup then falls back
  to Restart Manager. The UI and long-running CLI commands (`logs --follow`, `mount` waiting for completion) open the
  same event with `SYNCHRONIZE` and exit cleanly within 15 s when it is signaled. How setup finds and signals the
  events is in 12.3; it does not need to connect to the agent pipe, whose DACL admits only the user (2.2).
- **Shutdown sequence:** stop accepting new file operations, flush in-flight writes (bounded 10 s total), unmap
  drives (`WNetCancelConnection2W` with `fForce = TRUE` for WebDAV; `DokanRemoveMountPoint` for Dokany), close SSH
  sessions, remove Explorer label/icon registry entries it created (8.3), delete the shared-memory snapshot.
- **Session events:** `WTSRegisterSessionNotification` (XP+) on the hidden window. On `WTS_SESSION_LOCK` and
  `WTS_REMOTE_DISCONNECT`/`WTS_CONSOLE_DISCONNECT` mounts stay up, but new interactive prompts are queued instead of
  displayed (1.7.4). On `WTS_SESSION_UNLOCK`/`*_CONNECT` the queue is released.
- **Power events:** `WM_POWERBROADCAST` `PBT_APMSUSPEND` tells `sd_vfs` to mark sessions as suspended (no
  keepalive storm); `PBT_APMRESUMEAUTOMATIC` triggers an immediate reconnect attempt instead of waiting for backoff.
- **Network changes:** `NotifyAddrChange` (iphlpapi, XP+) triggers a reconnect probe.

### 1.3 The service (`ShellDriveSvc`, `shelldrive-host.exe service`)

- **Enabled by default on per-machine installs (D6).** The per-machine EXE shows the option "Install the
  ShellDrive service for drives shared by all users" **checked**; the MSI installs the `Service` feature by default
  and keeps a public property/feature selection to turn it off for corporate deployments (names owned by 04 §8.3/§8.4).
  **Per-user installs never install a service**, and portable mode never does. `shelldrive service install |
  uninstall` (elevated) adds or removes it later on per-machine installs.
- With no `scope = service` profile the service is idle: it holds the service pipe (so admins can add global
  profiles and pin host keys), opens no network connection, hosts no WebDAV listener and loads no Dokany code. This
  keeps the cost of the on-by-default LocalSystem process to one idle thread and one pipe.
- Runs as **LocalSystem**, `SERVICE_WIN32_OWN_PROCESS`, start type `SERVICE_AUTO_START` (not delayed: pre-logon
  Dokany mounts must exist before the first user logs on). Dependency: `Tcpip` only. It does not
  declare a dependency on `WebClient` (which is demand/trigger start and may be disabled); it starts `WebClient`
  itself through the SCM when a WebDAV-backed global profile is mounted (1.8), and the Dokany service when needed.
- Display name and description are localized: indirect strings `@<path>\shelldrive-host.exe,-<id>` on Vista+, set by
  the service itself at first start with `ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION)`, because the MSI's
  `Description` is static per install language (C44). XP shows the English plain string.
- Recovery: restart after 5 s, 30 s, then every 5 min (`ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)`,
  XP+).
- Accepts `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_SHUTDOWN` (XP), `SERVICE_CONTROL_PRESHUTDOWN` (Vista+, preferred,
  gives time to flush), `SERVICE_CONTROL_POWEREVENT`, `SERVICE_CONTROL_SESSIONCHANGE` (to know which sessions have an
  admin UI that can answer prompts, 2.6).
- Owns **global mounts only**: profiles in the machine store with `scope = service`. It never mounts per-user
  profiles and never impersonates users to mount on their behalf (keeps the trust model simple: a user's secrets
  never leave the user's own processes).
- **Global visibility, Dokany (primary path):** the service mounts without `DOKAN_OPTION_CURRENT_SESSION` (that flag
  means "mount the drive on current session only" —
  [dokan.h](https://github.com/dokan-dev/dokany/blob/master/dokan/dokan.h)), so the volume is global and exists
  before logon. Global drives use Dokany whenever it is available (amendment A4 as rewritten by D11).
- **Global visibility, WebDAV (attempted, D11):** for `scope = service` profiles that end up on WebDAV (no Dokany, or
  `backend = webdav`), the service hosts the WebDAV server in its own process and uses one of two modes, chosen per
  OS by the M5 lab spike (go/no-go recorded in a compiled-in OS table, overridable by
  `settings.ini [service] webdav_global_mode = auto | system | link | attach`; the mechanisms are specified in
  02 §7.7):
  - `system`: the service itself maps the drive with `WNetAddConnection2W` as LocalSystem. A LocalSystem mapping is
    documented as visible to all logon sessions on XP/2003
    ([WNetAddConnection2](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w));
    02 §7.7 argues it is not a real global drive on Vista+ (the redirector session belongs to SYSTEM). The spike
    decides per OS; until then `auto` means `system` on XP/2003 only.
  - `link` (02 §7.7 mechanism B, candidate for Vista+): the service creates a global DOS device link
    (`DefineDosDeviceW(DDD_RAW_TARGET_PATH, "Global\\Z:", "\\Device\\Mup\\localhost@PORT\\DavWWWRoot\\s-<token>")`)
    and no redirector connection of its own, so each user's first access authenticates as that user. Used only
    where the spike passes.
  - `attach` (fallback, every OS where both `system` and `link` are no-go): no drive exists before logon. Each user's agent, at logon
    and whenever the service announces a new global WebDAV mount, calls the service's read-only method
    `mount.attach_info` (2.4) and maps the returned UNC in the user's own logon session with the user's own token. The
    service's WebDAV server authenticates the user with Negotiate (02 §7.4) and checks the user SID against the
    profile's `service_access` list (3.4); the per-mount path token is the second factor (C26). This is the one
    agent → service call that changes state in the agent's own session; it is a read of attach data, so the rule
    "the agent does not proxy commands to the service" (2.6) still holds.
  Pre-logon availability is promised only for Dokany global drives; the UI and `shelldrive status --machine` say
  "available after sign-in" for WebDAV global drives in `attach` mode.
- Session 0 isolation (Vista+): the service has no access to any user desktop. On XP the service also runs in
  session 0, which is the first console user's session, but we **design as if session 0 isolation exists on XP
  too**: no `SERVICE_INTERACTIVE_PROCESS`, no windows, no message boxes. One code path, no XP-only UI.

### 1.4 The UI (`shelldrive-ui.exe`)

- One instance per (user, session): mutex `Local\ShellDrive.ui.<SID>`; a second launch forwards its command line
  to the first via `WM_COPYDATA` to a window with a private class name and exits.
- Modes: `--tray` (tray icon, main window hidden; launched by `HKCU\...\Run\ShellDriveTray` if enabled),
  default (open main window), `--prompt-host` (started by the agent when a prompt needs a UI and none is
  connected; shows only the prompt then stays as a tray if the user's setting says so), `--action <verb> <target>`
  (used by the shell extension: unmount, reconnect, mount, show), `--elevated-admin` (re-launched with `runas` to
  answer service prompts or edit machine profiles; exits when done).
- Always connects to its session's agent (starting it if needed) and, if the service is installed, to the service
  pipe for read-only status of global mounts.
- Not running is a supported state: everything still works from the CLI.

### 1.5 The CLI (`shelldrive.exe`)

- Connects to the agent of the current (SID, session); `--machine` targets the service instead.
- Commands that only edit files (`profile add/edit/remove/import`, `hostkey import/remove`, `settings`) work
  without an agent: they use `sd_config` directly under the configuration lock (3.6), and the agent picks up changes
  through directory change notifications.
- If the CLI runs elevated and no agent exists, it starts the agent **unelevated** (1.7.2).
- Answers prompts on the console when it has an interactive console (`--prompt auto`, the default), see 2.5.

### 1.6 The shell extension (`shelldrive-shellext.dll`)

- In-process COM server, apartment threaded. Loaded by Explorer and by every process that shows common file
  dialogs, so it must be tiny, never block, never crash its host, and never call into the network.
- It reads mount state from a per-session read-only shared-memory snapshot published by the agent
  (`Local\ShellDrive.state.<SID>`, 8.2) and performs actions by launching `shelldrive-ui.exe --action ...`. It does
  not speak the IPC protocol and does not start the agent itself (the UI does).
- Compatibility across versions (C5): there is no IPC to version. Instead the snapshot layout carries a version
  field, is **architecture-independent** (fixed-width little-endian fields, offsets instead of pointers, UTF-16
  strings in fixed-size slots), so an x86 DLL under WOW64 reads a section written by an x64 or ARM64 host, and a DLL
  of version N±1 reads what it understands and ignores the rest. `--action` verbs are additive only: a verb is
  never removed or given a new meaning.
- One DLL per architecture; details in 8.5.

### 1.7 Logon sessions, elevation and Terminal Services sessions

#### 1.7.1 The facts that shape the design

1. Drive letters live in the DOS device map of a **logon session (LUID)**, not of a TS session and not of a user.
2. With UAC on, a split-token administrator has **two linked logon sessions**; drive-letter links are specific to a
   logon session and not shared between them unless `EnableLinkedConnections` is set, which makes the system write
   the links to both linked sessions
   ([Microsoft Learn: mapped drives not available from an elevated prompt](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)).
   The value is `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections`
   (REG_DWORD 1) and needs a restart **[verify path wording against the article]**.
3. Dokany mounts made with `DOKAN_OPTION_CURRENT_SESSION` are reported missing in elevated processes of the same
   user ([Cryptomator forum report](https://community.cryptomator.org/t/drive-not-mounted-for-uac-admin/3119)); without
   the flag the mount is visible to everyone, which is unacceptable for per-user mounts.
4. A LocalSystem mapping is global (1.3).
5. Named pipe names are **machine-global**, not per session; mutexes/events under `Local\` are per TS session.

#### 1.7.2 Elevated vs. non-elevated visibility: decision

- The agent always runs unelevated, so mounts appear in Explorer and in every unelevated program.
- If a client (CLI or UI) is elevated and finds no agent, it starts the agent **through Explorer** so it inherits
  the unelevated token: `IShellWindows::FindWindowSW(SWC_DESKTOP)` → `IShellBrowser` → desktop `IShellView` →
  `IShellFolderViewDual::get_Application` → `IShellDispatch2::ShellExecute` (the documented-by-example technique for
  launching unelevated from an elevated process; works Vista+). If there is no Explorer shell (Server Core, custom
  shell), the client refuses with exit code 9 and a localized hint, unless `--allow-elevated-agent` is passed.
- The agent inspects each client's token (`ImpersonateNamedPipeClient` → `OpenThreadToken` →
  `GetTokenInformation(TokenElevationType)`, Vista+). If the client is elevated and `EnableLinkedConnections` is not
  set, every mount reply carries the warning `elevated_view_missing` and the CLI prints a localized explanation.
- **Elevated view on request (`--elevated-view`, WebDAV backend only):** after the agent mounts, an elevated CLI
  calls `mount.attach_info`, receives the local WebDAV UNC including the per-mount path token (`/s-<token>/`, 02
  §7.3), and calls `WNetAddConnection2W` itself with no credentials. No Basic credential exists (C26): the linked
  elevated token has the **same user SID**, so the server's Negotiate SID check passes, and the path token is the
  per-mount secret. The call creates the same drive letter in the elevated logon session pointing at the
  agent's WebDAV server. When the agent unmounts, the elevated mapping goes stale (the server rejects it) until
  the elevated CLI removes it or the session ends; `shelldrive unmount` run elevated removes both. This is opt-in
  because of that wart.
- **System-wide fix offered, never applied silently:** the per-machine installer shows an unchecked option "Make
  ShellDrive drives visible to programs run as administrator" that sets `EnableLinkedConnections`; the MSI exposes
  it as the public property `ENABLELINKEDCONNECTIONS`, **default 0** (D24), so corporate deployments opt in
  explicitly; `shelldrive diag` reports
  its state and `shelldrive diag --fix linked-connections` (elevated) sets it after a confirmation prompt. The UI
  settings page shows the state and a button that relaunches elevated to change it. A restart is required and we
  say so.
- Dokany per-user mounts use `DOKAN_OPTION_CURRENT_SESSION`. Whether `EnableLinkedConnections` also mirrors Dokany
  mount points is unknown **[verify]**; if not, Dokany drives are invisible to elevated programs and the UI says so
  in the profile's backend help text.

#### 1.7.3 Fast user switching and RDP

- Each TS session gets its own agent and UI. The pipe name includes the session ID, so two sessions of the same
  user (console + RDP on Server, or `fSingleSessionPerUser = 0`) get two agents with independent mounts and the same
  profile files. Autostart profiles mount in every session the user logs on to; a profile can restrict this with
  `autostart_sessions = console | remote | any` (default `any`).
- XP fast user switching uses the same TS session machinery, so the same design applies unchanged.
- A disconnected RDP session keeps its mounts (the user's programs may still be running); prompts are queued.
- On the service side, `SERVICE_CONTROL_SESSIONCHANGE` maintains the list of sessions with a connected admin UI.

#### 1.7.4 Prompts while locked or disconnected

Prompts raised while the session is locked or disconnected are queued (max 16, oldest first, each with a deadline,
default 10 minutes for reconnect-triggered prompts and 2 minutes for user-initiated mounts). The UI is not launched
on the secure desktop or on a disconnected session. When the deadline passes the operation fails with
`prompt_unavailable`.

### 1.8 Startup sequences

**User logon:** `Run\ShellDriveAgent` starts the agent → agent loads settings and profiles, publishes the pipe and
ready event → mounts profiles with `autostart = logon` in parallel (each with its own reconnect backoff; a missing
password raises a prompt that waits for the UI) → `Run\ShellDriveTray` starts the UI → UI subscribes to events and
receives any queued prompts.

**Boot:** SCM starts `ShellDriveSvc` → service loads machine profiles with `scope = service`, verifies each is
non-interactive capable (2.6) → starts Dokany (and WebClient for `system`- and `link`-mode WebDAV profiles) as needed → mounts
global drives (WebDAV profiles in `attach` mode only start their WebDAV listener; the drive appears when a user's
agent attaches, 1.3) → logs result to the Event Log.

**User logon with global WebDAV drives in `attach` mode:** the agent connects to the service pipe, lists global
mounts, and for each WebDAV one whose `service_access` admits the user calls `mount.attach_info` and maps the UNC
non-persistently in its own logon session (letter chosen by the profile; a conflict with a per-user drive is
reported, the global drive wins). On logoff the mapping disappears with the logon session.

**Ad-hoc mount from Explorer:** user right-clicks "This PC" → "Mount with ShellDrive" → profile → shell extension
runs `shelldrive-ui.exe --action mount <profile-id>` → UI starts the agent if needed → `mount` → prompts appear in
the UI → on success the UI opens the drive in Explorer if the user asked to.

### 1.9 Portable mode

Enabled when a file named `shelldrive.portable` exists next to the executables. Then:

- Configuration, known_hosts, logs and cache live in `.\data\` next to the binaries (subfolders as in 3.2).
- No Run keys, no service, no shell extension, no Network location entries (8.7), no Explorer icon/label registry
  writes unless the user opts in from settings (per-user `HKCU\Software\Classes` registration of the shell extension
  is possible but off by default). No registry writes at all otherwise: update settings and state live in
  `settings.ini` and `state\` (3.4, C8).
- Secrets still go to Credential Manager/DPAPI of the current machine and user (DPAPI blobs do not travel with the
  USB stick — documented in the UI; a portable install on another PC asks for passwords again).

### 1.10 Architecture matrix

| Arch | host | CLI | UI | shell DLLs installed | Notes |
|---|---|---|---|---|---|
| x86 (XP+) | x86 | x86 | x86 | x86 | |
| x64 | x64 | x64 | x64 | x64 + x86 (WOW64 file dialogs) | same CLSID in both registry views |
| ARM64 | ARM64 | ARM64 | ARM64 | ARM64 + x86 + x64 (x64 only on Windows 11, which emulates x64) | |
| ARM32 | ARM | ARM | — | none | Best effort (D5): CLI + agent with the WebDAV backend only; no UI, no service, no shell extension. Windows RT will not run third-party desktop code; IoT images have no Explorer. Dropped if the toolchain breaks. |

Build flavours (D4, D28) do not change this design: `x86-ia32` and `x86-sse2` ship the same four binaries (the
shell DLL installed for WOW64 on x64/ARM64 is the `x86-sse2` build), and `x64-xp` / `x64-modern` differ only in
toolset and hardening flags (04 §3.2). The state snapshot (1.6) and IPC are identical across flavours.

### 1.11 Mount orchestration in the host (`sd_mount`)

`sd_mount` is a host-only module owned by this design (review §4). It turns a profile into a running mount:
resolve profile + overrides + policy → secrets (4) → known_hosts store list (5.1) → proxy legs (3.8) →
`sd_ssh_config` per hop → connection pool (3.4 `connections`) → `sd_sftp_session` → `sd_vfs` → backend
(`sd_dokan` or `sd_webdav`) → IPC state, snapshot, labels, icons and Network location entry.

- **State machine:** `connecting / authenticating / mounted / offline / auth_required / failed / unmounting`, mapped
  from `sd_sftp` events to the IPC `mount.state` event (2.4). A `failed` or `offline` mount keeps its drive letter in
  an offline state: cached reads work, everything else returns `DISCONNECTED`, the tray offers Reconnect; only the
  user or a policy unmounts (review §4).
- **Threads (review §4, §4.1):** the main thread runs the hidden window, WTS/power/end-session messages, the
  shutdown event wait and the `sd_mount` control queue; one IPC server thread (alertable); one I/O thread per SSH
  chain (01); the Dokany and WebDAV pools (02); the vfs background thread; the logger thread; `QueueUserWorkItem`
  for KDFs, DNS, system-proxy resolution, known_hosts and credential lookups. Prompt callbacks only enqueue to the
  IPC thread. Dokany's `Unmounted` callback only posts a message to the control thread, which then runs quiesce →
  `sd_sftp_session_close` → destroy (C33); `*_sync` wrappers, `sd_sftp_session_destroy` and `DokanCloseHandle` are
  called only from the control thread.
- **Error table (C25):** one generated table in `sd_base` maps every `sd_err` to an IPC error `code` (6.2 spellings:
  `host_key_*`, `dns_failed`, `prompt_required`, …) and a CLI exit code; a unit test covers every enum value.
- Drive-letter selection (3.4) and the stale-mapping/label/Network location reconciliation at start are part of
  `sd_mount`.

---

## 2. IPC

### 2.1 Endpoints

| Endpoint | Server | Name |
|---|---|---|
| Agent control pipe | agent | `\\.\pipe\ShellDrive.agent.<UserSidString>.<SessionId>` |
| Service control pipe | service | `\\.\pipe\ShellDrive.service` |
| Agent ready event | agent | `Local\ShellDrive.agent.ready.<UserSidString>` |
| Agent shutdown event (manual reset, 1.2) | agent | `Global\ShellDrive.agent.shutdown.<UserSidString>.<SessionId>` |
| State snapshot (read-only shared memory) | agent | `Local\ShellDrive.state.<UserSidString>` |
| UI forwarding | UI | `WM_COPYDATA` to window class `ShellDrive.UI.<UserSidString>` (same session only) |

`<UserSidString>` from `ConvertSidToStringSidW` (XP+), session ID from `ProcessIdToSessionId` (XP+).

### 2.2 Security

Server side:

- Pipes created with an explicit security descriptor (SDDL via `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
  XP+):
  - Agent: `O:<UserSID>D:P(D;;GA;;;NU)(A;;GRGW;;;<UserSID>)` — owner is the user, only the user may connect,
    network logons explicitly denied. No ACE for SYSTEM, Administrators or `ALL APPLICATION PACKAGES`: AppContainer
    and other users cannot connect. The default medium mandatory label blocks low-integrity processes (protected-mode
    browsers) from writing on Vista+.
  - Service: `O:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` — interactive users may connect for
    read-only methods; every mutating method is authorized per call (below).
- `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance (XP SP2+): if it fails with `ERROR_ACCESS_DENIED` someone
  squatted the name; the server logs an error and exits (agent) or fails to start (service).
- `PIPE_REJECT_REMOTE_CLIENTS` on Vista+ (resolved at runtime; the flag is simply omitted on XP, where the deny-NU
  ACE does the job).
- Authorization per request: the server impersonates (`ImpersonateNamedPipeClient`), opens the thread token and
  checks: agent — token user SID equals the agent's user SID; service — mutating methods require membership in
  `BUILTIN\Administrators` with an **elevated** token (`CheckTokenMembership`, which on Vista+ treats the filtered
  token's deny-only Administrators group as non-member, so this naturally requires elevation).
- Request size cap 1 MiB, at most 32 concurrent client instances per server, per-client idle timeout 10 min for
  non-subscribed connections.

Client side (anti-spoofing; important because pipe names are global and predictable):

- After `CreateFileW`, the client reads the pipe's owner with `GetSecurityInfo(SE_KERNEL_OBJECT,
  OWNER_SECURITY_INFORMATION)` and requires owner == own user SID (agent) or `S-1-5-18` (service). A different
  non-admin user cannot set an owner other than themselves, so this works on XP.
- On Vista+ it additionally uses
  [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)
  (Vista+) to check that the server process runs in the client's session (agent) and that its image path is our
  `shelldrive-host.exe` (logged, not enforced, to keep portable mode working).
- `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` on `CreateFileW` so a spoofed server cannot impersonate the
  client at more than identification level.
- Secrets (passwords, passphrases, prompt responses) are sent only after these checks.

### 2.3 Framing and encoding

- `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE`, overlapped I/O, one IOCP-free completion-routine loop per server.
- **One pipe message = one UTF-8 JSON object.** No length prefix needed (message mode preserves boundaries); messages
  over 64 KiB are read with `ERROR_MORE_DATA` continuation.
- Why JSON and not a binary TLV: the CLI's `--json` output, the diagnostics bundle and test harnesses reuse the
  same encoding; debugging with a pipe sniffer is trivial; traffic is tiny. We need a small JSON reader/writer
  anyway (~700 lines, `sd_json`, no allocations beyond an arena per message). Keys are ASCII, English, snake_case.
- **Versioning:** the first message from the client is `hello`:
  `{"type":"hello","proto":1,"min_proto":1,"client":"cli","client_version":"1.2.0","lang":"es","caps":["prompts.console"]}`.
  The server replies with the chosen `proto` (highest common) or an error `proto_unsupported` (CLI exit code 14).
  Additive changes (new optional fields, new methods, new events) do not bump `proto`; receivers ignore unknown
  fields. Removing or changing the meaning of a field bumps `proto`; servers support N and N-1.

Message kinds:

```
request : {"type":"req","id":7,"method":"mount","params":{...}}
response: {"type":"res","id":7,"result":{...}}                 | {"type":"res","id":7,"error":{"code":"auth_failed","detail":"...","exit_code":4}}
event   : {"type":"evt","event":"mount.state","data":{...}}    (only after "subscribe")
```

Error `code` strings are stable English identifiers; `detail` is English (for logs). Clients localize by `code`.

### 2.4 Methods and events (proto 1)

| Method | Agent | Service | Notes |
|---|---|---|---|
| `hello` | x | x | version negotiation |
| `subscribe` `{topics:[...]}` | x | x | topics: `mount`, `prompt`, `log`, `warning`, `config` |
| `mount` `{profile_id \| adhoc:{...}, overrides, prompt_mode}` | x | x (admin) | returns `mount_id` immediately; completion via `mount.state` event or `wait:true` |
| `unmount` `{mount_id \| target, force}` | x | x (admin) | |
| `list` | x | x | mounts with state, backend, target, negotiated algorithm summary, warnings |
| `status` `{mount_id, stats}` | x | x | detailed: reconnect count, cache stats, last error, pool size and `pool_limited` reason, proxy legs in use; `stats:true` adds `sd_vfs_stats` and `sd_sftp_session_stats` (RTT, throughput) |
| `refresh` `{mount_id \| target, path}` | x | x (admin) | drops metadata TTLs for a subtree (02 §4.1) |
| `profile.test` `{profile_id \| adhoc:{...}}` | x | x (admin) | connect + auth + `realpath` without mounting ("Test connection", 7.5); prompts route as for `mount` |
| `mount.attach_info` `{mount_id}` | x | x (read-only) | agent: elevated-view support (1.7.2). Service: global WebDAV drives in `attach` mode (1.3); returned only when the caller's SID is in the profile's `service_access`. WebDAV only; returns the UNC with the path token, never a credential |
| `hostkey.announced.accept` `{announce_id, add[], remove[]}` | x | x (admin, elevated) | applies an UpdateHostKeys announcement (5.6) |
| `update.check` `{manifest?}` / `update.apply` `{version}` | x | — | update flow owned by the agent (04 §9); `manifest` is the developer override of `update check --manifest` |
| `selftest` | x | x | same checks as `shelldrive-host.exe --selftest`, as JSON |
| `prompt.answer` `{prompt_id, action, responses[], save}` | x | x (admin, elevated) | first answer wins |
| `cache.clear` `{profile_id \| all}` | x | x (admin) | |
| `config.reload` | x | x (admin) | normally automatic |
| `secret.set` / `secret.delete` `{target, kind, value}` | — | x (admin) | service secrets are write-only over IPC (4.5) |
| `hostkey.trust` `{host, port, key}` | — | x (admin) | machine known_hosts edits by the service |
| `log.tail` `{lines, follow}` | x | x (admin) | follow streams `log` events |
| `diag.collect` | x | x (admin) | returns a JSON report (10.5) |
| `agent.shutdown` `{unmount:true}` | x | — | |

Events: `mount.state {mount_id, state: connecting|authenticating|mounted|offline|auth_required|failed|unmounting|unmounted, error?}`,
`prompt.request`, `prompt.closed {prompt_id, reason: answered|cancelled|timeout}`,
`warning {code:"legacy_algorithms"|"elevated_view_missing"|"write_failed"|"pool_limited"|"proxy_cleartext"|..., mount_id, data}`,
`hostkeys.announced {announce_id, mount_id, host, port, add:[{type, fp}], remove:[{type, fp}]}` (5.6),
`update.available {version, notes_url}`, `config.changed`, `log {line}`. Topics gain `hostkeys` and `update`.

`write_failed` (C45) is raised when data acknowledged to an application under write-behind could not be written
(02 §4.4); it is always delivered, cannot be disabled and is mirrored in the event list (7.7).

### 2.5 Prompt routing

`sd_ssh` authentication and host key verification call back into the host with a prompt request and must accept an
**asynchronous** answer (the callback returns "pending"; the host later completes it). Requirement to 01, see 12.1.

Prompt kinds: `hostkey_unknown`, `password`, `passphrase`, `kbdint` (name, instruction, N prompts each with echo
flag), `password_change` (SSH_MSG_USERAUTH_PASSWD_CHANGEREQ), `legacy_ack` (only when the profile says
`legacy_algorithms = ask`; raised by 01 as `SD_PROMPT_LEGACY_ACK` after NEWKEYS and before SERVICE_REQUEST, C21),
`proxy_password` (HTTP Basic or SOCKS5 username/password for a proxy leg with no saved secret, 3.8). A **changed**
host key is never a prompt: it is a hard failure with a notification that leads the user to the host key manager
(5.4). Prompts are raised only for the **primary** connection of a mount; secondary pool connections never prompt
(3.4 `connections`).

```
{"type":"evt","event":"prompt.request","data":{
  "prompt_id":"p-12","kind":"kbdint","mount_id":"m-3","profile_id":"web","profile_name":"Web server",
  "host":"example.org","port":22,"user":"deploy","hop":1,"hops":2,
  "kbdint":{"name":"","instruction":"","prompts":[{"text":"Verification code: ","echo":false}]},
  "can_save":false,"deadline_ms":120000}}
```

Prompt text that comes from the server (`kbdint` texts, banners) is displayed verbatim, marked visually as coming
from the server, and sanitized (control characters stripped, length capped at 2 KiB per field).

**Agent routing order** (first that applies):

1. The client that initiated the operation, if it declared `prompts.console` in `hello` and is still connected
   (CLI on an interactive console with `--prompt auto|console`). The CLI reads input with `ReadConsoleW` and echo
   disabled via `SetConsoleMode`.
2. All UI clients in the agent's session subscribed to `prompt` (normally exactly one tray).
3. If none, and the session is active (not locked/disconnected), the agent launches `shelldrive-ui.exe
   --prompt-host` in its own session (`CreateProcessW`, same token) and the prompt is delivered when it subscribes.
4. Otherwise queue (1.7.4). If `prompt_mode = none` (CLI `--prompt none`, scripts) the operation fails immediately
   with `prompt_required` (exit code 4 for auth, 5 for unknown host key).

Several clients may display the same prompt; the first `prompt.answer` wins and the others receive
`prompt.closed`. Secrets in answers are wiped (`SecureZeroMemory`) after being handed to `sd_ssh`.

**ProxyJump:** each hop prompts separately; the prompt carries `hop`/`hops` and the hop's host so the dialog says
"Jump host 1 of 2: bastion.example.org".

### 2.6 Service prompts and service/agent cooperation

The service cannot show UI. Rules:

1. **Profiles with `scope = service` must be non-interactive capable**, validated when saved and at service start:
   the host key of every hop is in the machine known_hosts, and the authentication method is publickey with a
   key stored in the service secret store or an unencrypted key file readable only by SYSTEM/Administrators, or
   password stored in the service secret store. `kbdint` and agent (Pageant/OpenSSH agent) are not allowed for
   service profiles (no agent exists pre-logon; D17). Proxy legs need either no authentication, Negotiate/NTLM
   (machine account, via SSPI) or a proxy secret in the service secret store; `proxy = system` reads the WinHTTP
   machine configuration (3.8). `backend = webdav` is accepted (D11, 1.3) but the UI states that the drive appears
   only after sign-in where the OS uses `attach` mode. A profile failing validation is refused with a precise error.
2. **Trust on first use does not exist for the service.** Admins pin keys when creating the profile: the UI/CLI
   (elevated) calls `shelldrive hostkey add --machine --from-server host[:port]`, which connects through the
   service, shows the fingerprint and asks for confirmation (optionally `--expect SHA256:...` for scripted
   deployment, where a mismatch fails).
3. **If a prompt is nevertheless needed at runtime** (password changed on the server, new hop added), the service
   fails the mount, writes an Event Log warning (10.3) and publishes a `prompt.request` to service-pipe subscribers.
   Only **elevated** admin clients may answer (2.2). The agent's UI in each session subscribes to the service pipe
   read-only; if the logged-on user is an administrator (checked via the linked token,
   `GetTokenInformation(TokenLinkedToken)`, Vista+; group membership on XP), the tray shows "A global ShellDrive drive
   needs attention". Clicking it relaunches `shelldrive-ui.exe --elevated-admin` with the UAC prompt, which then
   answers the service prompt. Non-elevated answers are rejected on purpose: otherwise any medium-integrity program
   could inject trust into the SYSTEM-level mount.
4. We do not use `WTSSendMessage` to pop message boxes into user sessions (noisy, no input, wrong session
   heuristics); notifications go through the tray of admin users and the Event Log.

Agent ↔ service cooperation is deliberately thin:

- The agent connects to the service pipe (when present) to list global mounts and their letters. It refuses to
  mount a per-user drive on a letter used by a global mount (the per-session device map would shadow the global
  letter only for that user, which is confusing). Auto letter selection skips them.
- The agent does not proxy commands to the service; elevated clients talk to the service directly. The only
  agent → service call besides listing is `mount.attach_info` for global WebDAV drives in `attach` mode (1.3),
  made with the agent's own (user) identity.
- The service never starts agents (the Run key does). Rejected alternative: service launches agents with
  `WTSQueryUserToken` + `CreateProcessAsUserW` — makes the service mandatory and puts user-session lifecycle into a
  SYSTEM process for no gain.

### 2.7 Header sketch

```c
/* sd_ipc.h — shared by host, CLI, UI. No allocations visible to callers beyond sd_json arenas. */
#define SD_IPC_PROTO        1
#define SD_IPC_MIN_PROTO    1
#define SD_IPC_MAX_MESSAGE  (1u << 20)

typedef enum sd_ipc_endpoint { SD_IPC_AGENT, SD_IPC_SERVICE } sd_ipc_endpoint;

typedef struct sd_ipc_conn sd_ipc_conn;           /* opaque */
typedef struct sd_json     sd_json;               /* from sd_json.h */

typedef struct sd_ipc_hello {
    const char *client_kind;                      /* "cli", "ui", "shellext" */
    const char *lang;                             /* "en","es","fr","pt-BR","it","de" */
    unsigned    caps;                             /* SD_IPC_CAP_PROMPTS_CONSOLE, ... */
} sd_ipc_hello;

/* Connects, verifies the server owner SID (and PID/session on Vista+), performs hello.
   start_if_missing: spawn the agent (unelevated if the caller is elevated, see design 1.7.2). */
int  sd_ipc_connect(sd_ipc_endpoint ep, const sd_ipc_hello *hello, int start_if_missing,
                    DWORD timeout_ms, sd_ipc_conn **out);
int  sd_ipc_call(sd_ipc_conn *c, const char *method, const sd_json *params,
                 DWORD timeout_ms, sd_json **result, sd_ipc_error *err);
int  sd_ipc_next_event(sd_ipc_conn *c, DWORD timeout_ms, sd_json **event);   /* after subscribe */
HANDLE sd_ipc_event_handle(sd_ipc_conn *c);       /* signaled when an event is readable (UI message loop) */
void sd_ipc_close(sd_ipc_conn *c);

/* Server side (host only). */
typedef int (*sd_ipc_handler)(void *ctx, sd_ipc_client *client, const char *method,
                              const sd_json *params, sd_json_writer *result, sd_ipc_error *err);
int  sd_ipc_server_start(sd_ipc_endpoint ep, sd_ipc_handler h, void *ctx, sd_ipc_server **out);
int  sd_ipc_client_is_elevated(sd_ipc_client *client);   /* via impersonation; 0 on XP */
int  sd_ipc_client_is_admin(sd_ipc_client *client);      /* elevated + BUILTIN\Administrators */
void sd_ipc_broadcast(sd_ipc_server *s, const char *topic, const sd_json *event);
```

---

## 3. Configuration

### 3.1 Decisions

- **Own INI-like text files, UTF-8, one file per profile**, parsed by our `sd_ini` (~400 lines). Not the registry:
  files can be copied, diffed, backed up, deployed by MSI/GPO file preferences, and they work identically in
  portable mode. Not JSON: users and admins edit these by hand; INI allows comments and is forgiving. JSON stays
  for machine-to-machine (IPC, `--json`).
- One file per profile gives atomic per-profile writes, trivial import/export (`.ini` is the export format) and
  simple machine deployment (drop a file).
- **Group Policy** uses the registry, because that is what ADMX templates write: `HKLM\SOFTWARE\Policies\ShellDrive`
  and `HKCU\Software\Policies\ShellDrive` (one key each, no subkeys such as `\Update`). Policies override files; the
  UI greys out policy-controlled settings and says why.
- **This document owns the settings schema, including update settings (C8).** Update settings live in
  `settings.ini [update]`, not in `HKLM|HKCU\Software\ShellDrive\Update\*`; the last accepted manifest serial lives
  in `state\update.ini`. MSI properties (`UPDATECHECK`, `UPDATEURL`, `ENABLELINKEDCONNECTIONS`, …) are applied by
  writing the machine `settings.ini` (or, for `EnableLinkedConnections`, the Windows value itself). The only
  non-policy registry value of ours is `HKLM\Software\ShellDrive\Version`, written by the MSI for Intune detection
  and never read by the apps.

### 3.2 Locations

Paths come from `SHGetFolderPathW` (XP+), never from Known Folder APIs (Vista+).

| What | Per user | Machine |
|---|---|---|
| Settings | `%APPDATA%\ShellDrive\settings.ini` | `%ProgramData%\ShellDrive\settings.ini` (defaults for all users + service settings) |
| Profiles | `%APPDATA%\ShellDrive\profiles\*.ini` | `%ProgramData%\ShellDrive\profiles\*.ini` (also the target of the MSI `DEFAULTPROFILES` folder copy, C9) |
| Overrides of machine templates | `%APPDATA%\ShellDrive\overrides\<profile id>.ini` (3.4) | — |
| known_hosts | `%APPDATA%\ShellDrive\known_hosts` | `%ProgramData%\ShellDrive\known_hosts` |
| Protected keys | `%APPDATA%\ShellDrive\keys\<id>.sdkey` | `%ProgramData%\ShellDrive\service\keys\<id>.sdkey` |
| Fallback secrets | `%APPDATA%\ShellDrive\secrets\<hash>.sdsec` (4.3) | `%ProgramData%\ShellDrive\service\secrets\<hash>.sdsec` |
| Cache | `%LOCALAPPDATA%\ShellDrive\cache\` | `%ProgramData%\ShellDrive\service\cache\` |
| Logs, dumps | `%LOCALAPPDATA%\ShellDrive\logs\` | `%ProgramData%\ShellDrive\logs\` |
| Runtime state (incl. `update.ini` with `last_serial`, `explorer.ini`, `menu.cache`) | `%LOCALAPPDATA%\ShellDrive\state\` | `%ProgramData%\ShellDrive\service\state\` (machine `update.ini` written by elevated setup) |
| Network location entries (8.7) | `CSIDL_NETHOOD` (`%APPDATA%\Microsoft\Windows\Network Shortcuts` on Vista+, `%USERPROFILE%\NetHood` on XP) | — |
| Network location placeholders (8.7) | `%LOCALAPPDATA%\ShellDrive\places\<profile id>\` | — |

`%APPDATA%` = `CSIDL_APPDATA` (roams; profiles and known_hosts should follow the user). `%LOCALAPPDATA%` =
`CSIDL_LOCAL_APPDATA`. `%ProgramData%` = `CSIDL_COMMON_APPDATA` (on XP `All Users\Application Data`).

Machine directory ACLs (set by the installer, re-applied by the service at start if wrong), as SDDL with
inheritance:

- `ShellDrive\`, `profiles\`, `known_hosts`, `settings.ini`: `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)`
  — users can read machine profiles (they may use `scope = users` templates) but not change them.
- `service\` and below: `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`; `service\secrets\` and `service\keys\`:
  `D:PAI(A;OICI;FA;;;SY)` only (admins can still take ownership, which is accepted: admins are trusted).
- `logs\`: SYSTEM and Administrators full; users none (logs contain host names of global mounts).

Per-user `keys\` and `secrets\` get an explicit protected DACL (user + SYSTEM) at creation, in case `%APPDATA%` was
redirected to a share with loose ACLs.

### 3.3 File format (`sd_ini` grammar)

- UTF-8 without BOM on write; a UTF-8 BOM is accepted on read. If a file is not valid UTF-8 (e.g. saved as ANSI
  by XP Notepad), it is decoded with the ANSI code page and a warning is logged; the next write converts it.
- Lines: `[section]`, `key = value`, comments starting with `;` or `#` at line start. Keys are ASCII lowercase
  `[a-z0-9_.]`. Values are trimmed; a value in double quotes keeps whitespace and supports `\"`, `\\`, `\n`.
- Lists are comma-separated. Booleans: `yes/no/true/false/1/0`. Durations: integer + `ms|s|m|h`. Sizes:
  integer + `K|M|G`.
- Path values expand `%VAR%` (`ExpandEnvironmentStringsW`) and a leading `~\`/`~/` (user profile). Nothing else is
  expanded.
- Unknown sections/keys are **preserved** on rewrite (round-trip, including comments), so newer versions and hand
  edits survive older writers.
- `format = 1` in `[profile]`; a newer `format` is opened read-only with a warning.

### 3.4 Profile model

```ini
; %APPDATA%\ShellDrive\profiles\web-server.ini
[profile]
format = 1
id = 7f3c2a90d1e44b6c9a0e5b21c4d7f8aa      ; 128-bit random, stable across renames
name = Web server                           ; display name, unique (case-insensitive) per scope
host = example.org                          ; DNS name, IPv4 or IPv6 literal
port = 22
user = deploy
remote_path = /var/www                      ; empty = login directory
scope = user                                ; user | users (machine template mounted by each user's agent) | service

[auth]
methods = publickey, keyboard-interactive, password   ; order of attempts
identity = ~\.ssh\id_ed25519                ; OpenSSH, PEM/PKCS#8 or .ppk; may repeat as identity.2, identity.3
identity_store = 2b9e...                    ; id of a DPAPI-protected key in keys\ (4.4); alternative to identity
certificate = ~\.ssh\id_ed25519-cert.pub
agent = auto                                ; auto | pageant | openssh | none
save_password = yes                         ; allow saving password/passphrase to Credential Manager

[proxy]
jump = bastion, admin@10.0.0.5:2222         ; ordered hops: profile names/ids or user@host[:port]
proxy = socks5://alice@socks.corp:1080      ; leg 1: this machine -> first host (bastion); none | system | http://… | socks5://…
proxy.3 = http://10.0.0.1:3128              ; leg 3: hop 2 -> target, tunneled through hop 2 (3.8)

[connection]
connections = 1                             ; SSH connection pool size 1..4 (D18); >1 only with non-interactive auth
channels = 2                                ; SFTP channels per connection: 2 = meta + bulk, auto-degrades to 1 (D19)

[mount]
target = auto                               ; auto | X: | C:\Mounts\web (folder: Dokany only)
backend = auto                              ; auto | webdav | dokany
read_only = no
write_mode = through                        ; through (default, D9) | behind
label = Web server                          ; Explorer label; default = name
symlinks = follow                           ; follow | hide  (reparse is reserved and rejected, D12)
hide_dotfiles = yes
exec_hint = yes                             ; +x mapping hint (see 02)
autostart = no                              ; no | logon | boot (boot requires scope = service)
autostart_sessions = any                    ; any | console | remote
open_after_mount = no
network_location = yes                      ; entry under "Network locations" in This PC (8.7, D14)

[cache]
attr_ttl = 30s
dir_ttl = 30s
neg_ttl = 10s
disk = 0                                    ; per-profile disk cache size; 0 (default) disables it (plaintext copies)

[security]
legacy_algorithms = warn                    ; allow | warn | ask | refuse  (policy can force refuse)
legacy_accepted = sha256:4f1c...            ; hash of the last accepted legacy algorithm set (7.6)
host_key_alias =                            ; known_hosts lookup name override (like OpenSSH HostKeyAlias)
update_host_keys = ask                      ; ask | yes | no  (UpdateHostKeys, 5.6)
keepalive = 15s
connect_timeout = 20s
```

The memory cache is **one global budget** (`settings.ini [cache] memory`, 02 §4.2), not a profile key (C46).

#### 3.4.1 Profile schema (normative)

One table lists every profile key (C46). "Lock" names the policy value (3.5) that can force or limit the key;
machine templates (`scope = users`) lock every key except the overrides below. Consumer: the module that receives
the value from `sd_mount`.

| Section.key | Values (default) | Consumer | Lock |
|---|---|---|---|
| `profile.format` | `1` | `sd_config` | — |
| `profile.id`, `profile.name`, `profile.scope` | id, name, `user \| users \| service` | `sd_config` | — |
| `profile.host`, `profile.port`, `profile.user`, `profile.remote_path` | (—, `22`, —, login dir) | `sd_ssh` / `sd_vfs` | — |
| `profile.service_access` | SID list (`S-1-5-32-545`, Users); `scope = service` only | `sd_webdav` (global attach, 1.3), Dokany SD synthesis (02 §3) | — |
| `auth.methods` | list (`publickey, keyboard-interactive, password`) | `sd_ssh` | — |
| `auth.identity`, `auth.identity.N`, `auth.identity_store`, `auth.certificate` | paths / key id | `sd_mount` → `sd_ssh` (`SD_ID_BLOB` for stored keys, C22) | — |
| `auth.agent` | `auto \| pageant \| openssh \| none` (`auto`; forced `none` for service) | `sd_ssh` | — |
| `auth.identities_only` | bool (`no`) | `sd_ssh` | — |
| `auth.save_password` | bool (`yes`) | UI / `sd_secret` | `DisableCredentialSaving` |
| `auth.cache_secrets_for_reconnect` | bool (`yes`) | `sd_ssh` (owns the reconnect cache, C20) | — |
| `proxy.jump` | hop list (empty; ≤ 8 hops) | `sd_mount` | — |
| `proxy.proxy`, `proxy.proxy.N` | `none \| system \| http://[user@]host:port \| socks5://[user@]host:port` (`none`) | `sd_mount` → `sd_ssh` (3.8) | `ProxyServer` |
| `proxy.proxy_auth`, `proxy.proxy_auth.N` | `auto \| basic \| negotiate \| none` (`auto`, HTTP only) | `sd_ssh` (`sd_proxy_cfg.auth`: `BASIC\|SSPI`, `BASIC`, `SSPI`, 0; 01 §16) | — |
| `proxy.proxy_fallback_direct`, `proxy.proxy_fallback_direct.N` | bool (`no`); only for `proxy = system` | `sd_ssh` (01 §5.2) | `AllowSystemProxy` |
| `connection.connections` | `1..4` (`1`) | `sd_sftp` pool (`sd_sftp_options.connections`, D18, 01 §10.9) | — |
| `connection.channels` | `1 \| 2` (`2`) | `sd_sftp` (D19) | — |
| `mount.target`, `mount.backend` | (`auto`, `auto`) | `sd_mount` | `AllowedBackends` |
| `mount.read_only` | bool (`no`) | `sd_vfs` | — |
| `mount.write_mode` | `through \| behind` (`through`, D9) | `sd_vfs` (`write_mode`; `wb_window` 16 MiB node / 64 MiB mount for `behind`) | `ForceWriteThrough` |
| `mount.fsync_on_flush` | bool (`yes`) | `sd_vfs` | — |
| `mount.atomic_put` | bool (`no`) | `sd_webdav` | — |
| `mount.label`, `mount.hide_dotfiles`, `mount.exec_hint` | (name, `yes`, `yes`) | `sd_vfs` / backends | — |
| `mount.symlinks` | `follow \| hide` (`follow`); `reparse` reserved, rejected with `symlinks_reparse_unsupported` | `sd_vfs` | — |
| `mount.case`, `mount.remote_case` | `insensitive \| sensitive` (`insensitive`); `auto \| sensitive \| insensitive` (`auto`) | `sd_vfs` | — |
| `mount.remote_charset` | code page (empty = UTF-8) | `sd_vfs` (stage 1 of the name map, C23) | — |
| `mount.umask`, `mount.map_readonly`, `mount.show_special`, `mount.allow_system`, `mount.strict_acl` | (`022`, `yes`, `no`, `yes`, `no`) | `sd_vfs` | — |
| `mount.identity_probe` | `owner \| exec` (`owner`, D10) | `sd_sftp` (`exec` sets `SD_SFTP_OPT_IDENTITY_EXEC`, 01 §11) → `sd_vfs` via `server_info.identity` (02 §3.4) | — |
| `mount.fs_name` | string (`NTFS`, D23) | `sd_dokan` (`sd_vfs_options.volume_fs_name`) | — |
| `mount.offline_hint_over_mb` | integer MB (`0` = off, D22) | `sd_webdav` | — |
| `mount.offline_wait`, `mount.reconnect_grace` | (`3s`, `60s`) | `sd_vfs` | — |
| `mount.autostart`, `mount.autostart_sessions` | (`no`, `any`) | `sd_mount` | — |
| `mount.open_after_mount`, `mount.network_location` | (`no`, `yes`; `network_location` ignored for `scope = service`) | UI / `sd_mount` (8.7) | — |
| `cache.attr_ttl`, `cache.dir_ttl`, `cache.neg_ttl`, `cache.open_revalidate` | (`30s`, `30s`, `10s`, `1s`) | `sd_vfs` | — |
| `cache.disk` | size (`0`) | `sd_vfs` (`disk_cache_mb`, dir from 3.2) | — |
| `cache.max_readahead` | size (`8M`) | `sd_vfs` | — |
| `security.legacy_algorithms` | `allow \| warn \| ask \| refuse` (`warn`) | `sd_ssh` (`legacy_policy` = `SD_LEGACY_ALLOW\|WARN\|ASK\|REFUSE`) + UI (7.6) | `LegacyAlgorithms` |
| `security.legacy_accepted`, `security.host_key_alias` | hash, name | UI / `sd_ssh` | — |
| `security.refuse_terrapin_exposed` | bool (`no`) | `sd_ssh` | — |
| `security.crypto_backend` | `auto \| own` (`auto`) | `sd_crypto` | — |
| `security.update_host_keys` | `ask \| yes \| no` (`ask`; service: `no` unless policy) | `sd_ssh` + host (5.6) | `UpdateHostKeys` |
| `security.keepalive`, `security.connect_timeout` | (`15s`, `20s`) | `sd_ssh` | — |

Keys renamed by this revision are read under their old names once and rewritten (`metadata_ttl` → `attr_ttl`,
`directory_ttl` → `dir_ttl`, `read_cache_disk` → `disk`; `read_cache_memory` is ignored with a log line).

Semantics owned by this layer:

- **ProxyJump** entries resolve first to profiles in the same scope (by name, then id), else are parsed as
  `[user@]host[:port]` and inherit `[auth]` from the profile that references them. Cycles and chains longer than 8
  hops are rejected at save time. Each hop has its own host key verification.
- **Backend `auto`:** Dokany if the Dokany runtime is installed in a supported version, OS ≥ 7 SP1, arch ≠ ARM32;
  forced to Dokany when `target` is a folder; otherwise WebDAV where the WebClient feature is present and not
  disabled (amendment A1: WebClient is deprecated since November 2023 and not always available). Forcing an unavailable
  backend fails with `backend_unavailable` (exit 11) — no silent fallback when forced.
- **Target `auto`:** first free letter from Z: downward, skipping letters in use in this logon session, letters of
  global mounts, letters with remembered persistent connections (`WNetOpenEnum(RESOURCE_REMEMBERED)`), and A:/B:.
  Folder targets must be empty directories on a local NTFS volume (validated at mount).
- Scope `users`: machine-provided template; each user's agent mounts it with the user's own credentials and
  known_hosts. **Per-user overrides are limited to `mount.target`, `mount.autostart` and
  `mount.autostart_sessions` (D25)**, plus hiding the template. They are stored in
  `%APPDATA%\ShellDrive\overrides\<profile id>.ini` (`[override] target, autostart, autostart_sessions, hidden`);
  any other key in that file is ignored with a log line. The profile editor shows a template read-only except the
  Drive letter/folder and autostart controls.
- **Write mode (D9):** `through` (default): every write is acknowledged by the server before it completes for the
  application, so errors reach the application directly. `behind`: write-behind with a 16 MiB window per file,
  60 s grace retransmit after reconnect and the always-on `write_failed` notification (02 §4.4, C45). The Drive page
  explains the trade-off (7.5).
- **Connection pool (D18):** `connections = N` (1–4) opens up to N−1 extra SSH connections after the primary one
  is mounted. Bulk transfers are striped across connections by 02/01; metadata stays on the primary; each
  connection reconnects on its own. **2FA rule:** extra connections are opened only when every hop of the primary
  connection authenticated without user interaction, that is with a key (file without passphrase, DPAPI-kept key,
  agent, or a passphrase from Credential Manager / the DPAPI store / `sd_ssh`'s reconnect cache) or a password
  from Credential Manager / the DPAPI store / the reconnect cache. If any hop needed a `kbdint` round that was not
  auto-answered (4.2), or any prompt was shown, the pool stays at 1. If a secondary connection's server asks for
  anything that would need a prompt, that connection is abandoned (never prompted), the pool stays at the size
  reached, and the mount reports `warning pool_limited` with reason `interactive_auth`. The profile editor shows
  "Extra connections are used only when signing in needs no typing (for example with a key)."

Global settings (`settings.ini`): `[ui] language, start_tray, notify_*`, `[agent] start_at_logon, idle_exit`,
`[log] level, max_size, max_files, etw`, `[cache] memory` (global memory budget, C46), `[defaults] backend,
legacy_algorithms, write_mode, proxy, ...` (defaults for new profiles), `[credentials] persist = local |
enterprise`, `[hostkeys] openssh_source = yes, putty_source = yes` (5.1), `[update] enabled = yes|no, channel =
stable|beta, manifest_url =` (C8; consumed by the updater in the agent, 04 §9), `[service] webdav_global_mode =
auto|system|link|attach` (machine file only, 1.3), `[explorer] modern_menu = auto|off` (8.6). `last_serial` is not a
setting: it is state (`state\update.ini`). The MSI properties `UPDATECHECK` and `UPDATEURL` write
`[update] enabled` and `manifest_url` of the machine `settings.ini`; per-user values override machine values
unless a policy is set.

### 3.5 Group Policy values (registry, read-only for us)

All values live in the single key `HKLM|HKCU\Software\Policies\ShellDrive` (HKLM wins), listed here once (C8):
`LegacyAlgorithms` (0 allow, 1 warn, 2 refuse), `AllowUserProfiles`, `AllowAdHocMounts`, `AllowedBackends`
(`webdav,dokany`), `DisableCredentialSaving`, `StrictHostKeyChecking` (1 = no TOFU, only machine known_hosts),
`DisableKnownHostsSources` (1 = do not read `~/.ssh/known_hosts` or PuTTY), `UpdateHostKeys` (0 never, 1 ask,
2 accept proven keys; for the service, 2 is the only way to let it update the machine store), `ForceWriteThrough`
(1 = `write_mode = behind` refused), `ProxyServer` (a proxy spec forced as leg 1 for every profile),
`AllowSystemProxy`, `UILanguage`, `DisableUpdateCheck`, `UpdateChannel`, `UpdateUrl`, `HideTrayIcon`,
`DisableNetworkLocations`, `DisableModernContextMenu`. ADMX/ADML produced by 04, localized from our catalogs
(`sdl10n` emits the ADML, C41).

### 3.6 Concurrency

All writers (agent, UI, CLI) use `sd_config_lock()`: `LockFileEx` exclusive on `ShellDrive\config.lock`. Writes go
to `name.ini.tmp` then `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. The agent watches the
directories with `FindFirstChangeNotificationW` and reloads changed profiles (debounced 500 ms). A profile change
does not affect a live mount until it is remounted, except `read_only` going to yes (applied immediately) and
cache TTLs. `known_hosts` files are **not** covered by the config lock: `sd_known_hosts` (01 §7.2) owns their I/O
and serializes writers with its own named mutex (C19).

### 3.7 Importers (`sd_import`)

Both importers produce a list of candidate profiles shown in a preview (UI wizard page or CLI table) before
anything is written. Duplicates (same host/port/user as an existing profile) are flagged and unchecked by default.

**PuTTY sessions** — `HKCU\Software\SimonTatham\PuTTY\Sessions\<name>`, where `<name>` is URL-escaped (`%20`
etc., decoded). Values read: `HostName`, `PortNumber`, `UserName`, `Protocol` (only `ssh` imported),
`PublicKeyFile` → `identity`, `DetachedCertificate` → `certificate`, `ProxyMethod`/`ProxyHost`/`ProxyPort`/
`ProxyUsername` → one `jump` hop when the proxy type is "SSH" (PuTTY 0.77+), `proxy = socks5://…` for SOCKS 5,
`proxy = http://…` for HTTP; SOCKS 4, Telnet and local-command proxies are skipped with a note (no ProxyCommand,
D20). A PuTTY proxy password is never imported (PuTTY stores it in clear; the user is asked on first use).
`HostName` of the form `user@host` is split. `Default Settings` provides defaults for missing values. Values are
REG_SZ written by PuTTY in the ANSI code page; reading them with `RegQueryValueExW` converts correctly.
**[verify value names and ProxyMethod numbering against PuTTY `settings.c`]**

**OpenSSH `ssh_config`** — `%USERPROFILE%\.ssh\config` (or a path given). Supported keywords: `Host`, `HostName`,
`User`, `Port`, `IdentityFile`, `ProxyJump`, `CertificateFile`. Semantics follow OpenSSH: first obtained value
wins, `Host` sections apply in file order, wildcard sections (`Host *`, `Host *.corp`) are not imported as
profiles but contribute defaults to the literal hosts they match; negated patterns (`!pattern`) are honored.
`IdentityFile` tokens `%d %u %h %r %%` and `~` are expanded; multiple `IdentityFile` lines become `identity`,
`identity.2`, …. `ProxyJump` aliases that match another imported `Host` become references to that profile;
`ProxyJump none` clears. `Match`, `Include`, `ProxyCommand` (not supported, D20) and every other keyword are
listed in the import report as "not imported" (no silent loss). Each literal `Host` alias becomes one profile (a
`Host a b` line yields two).

### 3.8 Proxies (D20)

HTTP CONNECT and SOCKS5 proxies are supported per profile and per ProxyJump hop. **There is no ProxyCommand.**
The protocol clients (HTTP CONNECT, SOCKS5 with RFC 1929 username/password, SSPI Negotiate/NTLM for HTTP) live in
`sd_ssh`'s transport (requirement in 12.1), and so does system-proxy resolution, because it must be redone on every
reconnect (01 §5.2); this layer owns configuration, policy, secrets and prompts, and passes `proxy = system`
through as `SD_PROXY_SYSTEM`.

- **Legs.** A chain `[hop 1 … hop N, target]` has N+1 legs; leg k reaches host k. Leg 1 starts on this machine;
  leg k > 1 is a `direct-tcpip` channel through hop k−1. `proxy` (= `proxy.1`) sets leg 1, `proxy.K` sets leg K.
  A proxy on leg k > 1 means: open `direct-tcpip` to the proxy through hop k−1, then speak CONNECT/SOCKS5 inside
  that channel. When a hop is given as a profile reference, that profile's own `proxy` is **not** used (the UI
  shows a note), so a chain has exactly one place where each leg is configured.
- **Spec syntax:** `none`, `system`, `http://[user@]host[:port]` (default port 8080), `socks5://[user@]host[:port]`
  (default 1080). `socks5h` semantics are always used: the target name is sent to the proxy for resolution
  (address type 3), so internal names resolve on the proxy side. No password in the spec; the parser rejects
  `user:pass@`.
- **HTTP auth:** `proxy_auth = auto` tries without credentials, then on `407` uses `Negotiate`/`NTLM` via SSPI with
  the caller's logon credentials if offered (service: machine account), else `Basic` with the configured user and
  the saved secret or a `proxy_password` prompt. `basic` and `negotiate` force one scheme; `none` never answers a
  `407`.
- **System proxy (opt-in only).** `proxy = system` makes `sd_ssh` read the WinHTTP/WinINet configuration: agent —
  `WinHttpGetIEProxyConfigForCurrentUser` (XP SP1+), with WPAD/PAC through `WinHttpGetProxyForUrl` for the
  pseudo-URL `https://<host>:<port>/` (so PAC rules written for CONNECT apply); service —
  `WinHttpGetDefaultProxyConfiguration` (`netsh winhttp`). A `socks=` entry selects SOCKS, otherwise the HTTPS (then
  HTTP) proxy is used for CONNECT; the bypass list is honored; "direct" means no proxy. `system` is never the
  default; policy `AllowSystemProxy = 0` forbids it. **[verify that IE `socks=` entries mean SOCKS4 vs SOCKS5 in
  practice; we only speak SOCKS5]**. Resolution runs on a worker item and is re-done on every (re)connect.
- **Secrets:** proxy passwords live in Credential Manager like SSH passwords (4.1), target
  `ShellDrive:proxy:<http|socks5>:<user>@<proxyhost>:<port>`; service proxy secrets in the service secret store.
- **Clear-text warning:** HTTP Basic and SOCKS5 username/password send the proxy password unencrypted to the proxy.
  The profile editor shows "This proxy receives your proxy password unencrypted." and the mount raises `warning
  proxy_cleartext` once per (profile, proxy). SSH traffic itself stays end-to-end encrypted.
- **Status:** `status` and the main window show each leg's proxy ("via socks.corp:1080").

---

## 4. Credentials and secrets

### 4.1 What is stored where

| Secret | Store | Notes |
|---|---|---|
| User password for user@host:port | Credential Manager, `CRED_TYPE_GENERIC` | shared by all profiles with the same user/host/port |
| Passphrase of a key file | Credential Manager, `CRED_TYPE_GENERIC` | keyed by the public key fingerprint, survives moving the file |
| Private key "kept by ShellDrive" | DPAPI file `keys\<id>.sdkey` | user-scope DPAPI |
| Keyboard-interactive answers | never stored | exception: single non-echo prompt matching "password" (4.2) |
| Proxy password (HTTP Basic, SOCKS5) | Credential Manager, `CRED_TYPE_GENERIC` | target `ShellDrive:proxy:…` (3.8); service: service store |
| Service secrets | DPAPI files under `service\` | SYSTEM user-scope DPAPI (4.5) |
| WebDAV per-mount path token | memory only | random per mount, part of the UNC (`/s-<token>/`, 02 §7.3); no Basic credential (C26) |

### 4.2 Credential Manager

APIs: `CredWriteW`, `CredReadW`, `CredDeleteW`, `CredEnumerateW`, `CredFree`, `CredGetSessionTypes` — all XP+
(`CREDENTIAL` minimum client is XP —
[CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)).

- **Type `CRED_TYPE_GENERIC`, never `CRED_TYPE_DOMAIN_PASSWORD`**: for domain passwords the blob "can only be read
  by the authentication packages" and NTLM/Kerberos/Negotiate would try to use the credential for that target
  ([CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)). Generic
  credentials are readable by the owning user's processes, which is what we need.
- **Target names** (TargetName is case-insensitive per the same page, but Unix user names are case-sensitive, so
  uppercase ASCII letters in the user part are escaped as `%XX`; hosts are lowercased; IPv6 in brackets):
  - `ShellDrive:password:<user>@<host>:<port>`
  - `ShellDrive:passphrase:SHA256:<base64 fingerprint of the public key>`
  - `ShellDrive:proxy:<http|socks5>:<user>@<proxyhost>:<port>` (3.8)
  - `UserName` = remote user (informational), `Comment` = localized "Saved by ShellDrive for <profile name>"
    (visible in the Windows Credential Manager UI, so it is user-facing text), `TargetAlias` unused, no attributes.
- **Blob:** UTF-16LE secret without terminator. The documented maximum is `CRED_MAX_CREDENTIAL_BLOB_SIZE`
  (5*512 bytes) on current Windows; older SDK headers (XP era) define 512 bytes **[verify on XP]**, so we cap Credential
  Manager blobs at 512 bytes (256 UTF-16 code units). Longer secrets go to the DPAPI fallback (4.3).
- **Persistence:** `CRED_PERSIST_LOCAL_MACHINE` by default. `CRED_PERSIST_ENTERPRISE` only when the user turns on
  "Roam saved passwords with my profile" (settings), because it puts SSH passwords on every machine the roaming
  profile touches. Both values are **not supported on XP Home and Vista Home Basic/Home Premium/Starter**
  ([CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)); we call
  `CredGetSessionTypes(CRED_TYPE_MAXIMUM, ...)` (only entries up to `CRED_TYPE_GENERIC` are inspected) and if the
  maximum persistence for generic credentials is below `CRED_PERSIST_LOCAL_MACHINE`, we use the DPAPI fallback.
- **Keyboard-interactive password:** when a kbdint round has exactly one prompt, non-echo, whose text matches
  `password` (case-insensitive, also the localized PAM forms "Passwort", "contraseña", "mot de passe", "senha",
  "password") and the user ticked "Save", the answer is stored under the `password` target and auto-answers that
  shape of round next time. OTP prompts never match and are never stored.
- `DisableCredentialSaving` policy hides every "Save" checkbox.
- Credentials are removed when the user deletes the last profile that references them (asked in the delete dialog)
  and by `shelldrive credential remove`.

### 4.3 DPAPI fallback secret files

`CryptProtectData` / `CryptUnprotectData` (Windows 2000+), user scope, `CRYPTPROTECT_UI_FORBIDDEN`,
`pOptionalEntropy` = UTF-8 `"ShellDrive/secret/v1/" + target name`. File `secrets\<hex SHA-256 of target>.sdsec`:
magic `SDSEC1\0\0`, u32 version, u32 blob length, DPAPI blob. Same target naming as 4.2, so `shelldrive credential`
treats both stores uniformly (`sd_secret` API below).

### 4.4 DPAPI-protected private keys

When importing a key the user can choose "Keep a protected copy in ShellDrive" (no passphrase prompt afterwards,
protected by the Windows logon): the key is decrypted once (passphrase prompt), re-serialized in OpenSSH format
without encryption, and stored as `keys\<id>.sdkey` = magic `SDKEY1\0\0` + metadata (key type, public key blob,
comment) in clear + `CryptProtectData` blob of the private part, entropy `"ShellDrive/key/v1/" + id`,
`szDataDescr` = profile name. The public part in clear lets the UI list keys without decrypting. Caveat surfaced in
the UI: an administrator *reset* (not a user change) of the Windows password makes user DPAPI data unrecoverable;
the original key file remains the user's backup.

### 4.5 Service-owned secrets

- Admins send secrets to the service over its pipe (`secret.set`, elevated only). The service encrypts with
  `CryptProtectData` **in its own LocalSystem user scope (no `CRYPTPROTECT_LOCAL_MACHINE`)**, so only code running
  as SYSTEM can decrypt. Files under `service\secrets\` and `service\keys\` with SYSTEM-only ACLs.
- Rejected: `CRYPTPROTECT_LOCAL_MACHINE`. Machine-scope blobs can be decrypted by any process on the machine, so
  protection would rest entirely on the file ACL; SYSTEM user scope adds a second barrier at no cost.
- Rejected: Credential Manager as SYSTEM. Works, but is invisible/unmanageable for admins and has the 512-byte
  constraint on XP; files are easier to back up and to wipe on uninstall.
- Secrets are write-only over IPC: there is no method to read them back.

### 4.6 In-memory handling

Secrets live in `sd_secret_buf` (locked with `VirtualLock` where the quota allows, wiped with `SecureZeroMemory`
on free). The host keeps **no** reconnect cache of its own (C20): `sd_ssh` owns it (`cache_secrets_for_reconnect`,
profile key `auth.cache_secrets_for_reconnect`; `CryptProtectMemory` on Vista+, `RtlEncryptMemory` on XP, 01 §7.4/§8).
The host answers `is_reconnect` prompts from Credential Manager/DPAPI only; if nothing is saved and the cache is
off, reconnect raises a normal prompt.

```c
/* sd_secret.h */
typedef enum sd_secret_kind { SD_SECRET_PASSWORD, SD_SECRET_PASSPHRASE, SD_SECRET_PROXY } sd_secret_kind;
typedef enum sd_secret_scope { SD_SECRET_USER, SD_SECRET_SERVICE } sd_secret_scope;

/* target: "user@host:port" for passwords, "SHA256:..." for passphrases,
   "<http|socks5>:user@proxyhost:port" for proxy passwords (escaping done inside). */
int  sd_secret_get(sd_secret_scope s, sd_secret_kind k, const wchar_t *target, sd_secret_buf **out);
int  sd_secret_put(sd_secret_scope s, sd_secret_kind k, const wchar_t *target,
                   const wchar_t *display_name, const sd_secret_buf *value);   /* picks CredMan or DPAPI file */
int  sd_secret_delete(sd_secret_scope s, sd_secret_kind k, const wchar_t *target);
int  sd_secret_enum(sd_secret_scope s, sd_secret_enum_cb cb, void *ctx);       /* targets only, never values */
void sd_secret_buf_free(sd_secret_buf *b);                                     /* wipes */
```

---

## 5. Host keys (storage and UX)

**Ownership (C19):** `sd_known_hosts` in `sd_ssh` (01 §7.2) owns parsing, lookup, **file I/O and locking** (its
named mutex, on a worker thread). This layer does no known_hosts file I/O of its own: it decides which stores and
sources are passed in, in which order, and owns the UX. The CLI and UI link the same `sd_known_hosts` translation
units for the host key manager and `hostkey` commands, so every writer goes through one implementation and one
mutex.

### 5.1 Stores, sources and lookup

`sd_mount` opens `sd_known_hosts` with an **ordered store list**:

| Order | Store | Access | Agent | Service |
|---|---|---|---|---|
| 1 | Machine `%ProgramData%\ShellDrive\known_hosts` | read-only for users, read-write for elevated admins/service | yes | yes (only store) |
| 2 | User `%APPDATA%\ShellDrive\known_hosts` | read-write | yes | — |
| 3 | `%USERPROFILE%\.ssh\known_hosts` (and `known_hosts2`) | live, read-only source | yes, default on (D7) | — |
| 4 | PuTTY `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` | live, read-only source | yes, default on (D7) | — |

- **Live sources (D7):** sources 3 and 4 are consulted on every lookup (no wizard step needed). A match in a source
  is **copied into the user store** with an end-of-line source comment (`# imported-from=openssh` /
  `# imported-from=putty`, plus `added=<date>`), so later lookups no longer depend on the source. A **mismatch in
  any store or source blocks** the connection (5.4); a key that matches one store does not override a mismatching
  key of the same type in another. Settings `[hostkeys] openssh_source`, `putty_source` (both `yes`) and the policy
  `DisableKnownHostsSources` turn the sources off. The service never uses live sources (no user profile; PuTTY is
  HKCU).
- A `@revoked` line in any store wins. A `@cert-authority` line is honored (host certificates, 01 §7.1).
- `StrictHostKeyChecking` policy: unknown keys are rejected for users too (no TOFU); only the machine store counts
  and live sources are ignored.
- **Plain entries (D8):** host names are written in OpenSSH form (`host` for port 22, `[host]:port` otherwise),
  never hashed (the file is ACL-protected and readable entries help support); hashed entries from other tools are
  read fine.
- Each line we write gets an end-of-line comment: `# added=2026-10-24 by=shelldrive`, `# imported-from=putty`,
  `# imported-from=openssh` or `# updated-by=hostkeys-00 added=…` (5.6).
- The store key for jump hops and aliases is `host_key_alias` if set, else the hop's host/port.

### 5.2 First-connection (TOFU) dialog

Content: profile name, host and port (and hop N of M), key type, SHA-256 fingerprint in OpenSSH form
(`SHA256:...`) in a read-only, selectable edit control, an expandable "More" with MD5 fingerprint (for comparison
with old servers) and the full public key. Text explains in plain language how to check the fingerprint with the
server admin. Buttons: **Trust and connect** (standard default button; all information is on screen, so Enter
accepts), **Connect once** (not saved), **Cancel**. If the
same host is known with a *different key type* only (server added a new key type), the dialog says so; it is still
a TOFU prompt for the new type.

### 5.3 CLI equivalent

```
The authenticity of host 'example.org' (port 22) can't be established.
ED25519 key fingerprint: SHA256:4bWb...  
Trust this key? [y]es, [o]nce, [n]o:
```
Localized; the y/o/n letters are localized too (they are in the catalog, with a translator note).

### 5.4 Changed key

Hard block: mount fails with `host_key_mismatch` (exit 6), a notification "The identity of example.org has changed.
ShellDrive stopped the connection." opening a details dialog that shows old and new fingerprints, the store and line
where the old key lives, and a **Manage host keys…** button. No "connect anyway". To accept the new key the user
removes the old one in the host key manager (confirmation dialog warns about MITM) and reconnects (TOFU again).
When the old key lives in a live read-only source (`~/.ssh/known_hosts` or PuTTY), ShellDrive cannot remove it;
the dialog names the file and line (or the PuTTY registry value) and offers **Open file location** and "Stop
using keys from this source" (turns the source off in settings), because a mismatch in any source blocks (D7).

### 5.5 Import flow

Host keys from `~/.ssh/known_hosts` and PuTTY need no import: they are live sources (5.1, D7) and each match is
copied into the user store with its source comment the first time it is used. The first-run wizard page "Import
existing settings" (also File → Import) therefore says "ShellDrive also trusts the host keys you already accepted
in PuTTY and OpenSSH. You can turn this off in Settings." and offers:

- PuTTY sessions and `~/.ssh/config` (3.7) as profile candidates.
- An optional bulk copy of host keys, for users who want them in the ShellDrive store now (for example before
  uninstalling PuTTY) or from a user-chosen `known_hosts` file that is not a live source.

The bulk copy shows a checklist grouped by source with counts ("PuTTY: 12 host keys, 5 sessions"). Host keys
conflicting with existing entries or with each other are shown with a warning icon and unchecked by default.
CLI: `shelldrive hostkey import --from putty|openssh [FILE] [--dry-run]` (one-shot copy, `sd_known_hosts_import`).

### 5.6 Host key rotation (UpdateHostKeys, D16)

`sd_ssh` supports `hostkeys-00@openssh.com` with `hostkeys-prove-00@openssh.com` (01). Rules enforced there and
here:

- An announcement is considered only when the connection's host key was verified as `MATCH` against a **stored**
  key (not "Connect once", not a CA match, not a key that was just accepted by TOFU in the same connection) and
  user authentication has completed.
- Only keys the server **proves** (`hostkeys-prove-00` signatures valid) are candidates for addition. Keys stored
  for the host but absent from the announcement are candidates for removal; they are never removed automatically.
- `security.update_host_keys` (policy `UpdateHostKeys`):
  - `ask` (default for user mounts): `sd_mount` raises the IPC event `hostkeys.announced`; the tray shows the
    notification "example.org offered new host keys. Review" (once per host and announced key set). The review
    dialog lists keys to add (type, SHA-256 fingerprint, "proven by the server") checked, and keys no longer
    offered unchecked ("Remove keys the server no longer uses"), with **Apply** and **Not now**. Apply calls
    `hostkey.announced.accept`. Nothing changes until the user applies. The announcement is not a prompt: the mount
    is already up and never waits for it.
  - `yes`: proven new keys are appended to the store that holds the verifying key (user store; machine store only
    as below) with the comment `# updated-by=hostkeys-00`, and an informational notification "ShellDrive saved new
    host keys for example.org." (default on, can be turned off). Removals still need the review dialog.
  - `no`: announcements are logged at info and ignored.
- **Machine store:** never updated from a user's connection. The service updates the machine store only when the
  policy `UpdateHostKeys = 2` is set; otherwise it writes Event Log warning 2300 and publishes `hostkeys.announced`
  on the service pipe, and an elevated admin can apply it from the "A global ShellDrive drive needs attention"
  flow (2.6) or `shelldrive hostkey list --announced --machine` / `hostkey accept-announced <id> --machine`.
- If the verifying key matched a live read-only source only (it was just copied, 5.1), additions go to the user
  store; removals of source keys are impossible and are not offered.
- CLI: `shelldrive hostkey list --announced` shows pending announcements; `hostkey accept-announced <id> [--add-only]`
  applies one.

---

## 6. CLI

### 6.1 Command set

```
shelldrive mount <profile> [--target X:|PATH] [--backend auto|webdav|dokany] [--read-only]
                 [--prompt auto|console|gui|none] [--elevated-view] [--no-wait] [--open]
shelldrive mount --host [user@]host[:port] [--path /remote] [--identity FILE] [--jump SPEC] [--proxy SPEC]
                 [--write-mode through|behind] [--connections N] [--save NAME] ...
shelldrive unmount <profile|X:|PATH> | --all [--force]
shelldrive list                                   mounts in this session (+ global mounts, marked)
shelldrive status [<profile|X:>] [--stats]        --stats: sd_vfs/sd_sftp counters (02 §11)
shelldrive refresh <X:|PATH>[\sub\path]           drop metadata TTLs for a subtree (02 §4.1)
shelldrive profile list | show <p> | add <name> [options] | edit <p> [options] | remove <p> [--keep-credentials]
                   | rename <p> <new> | export <p> [FILE] | import --from putty|openssh|file [FILE] [--dry-run]
                   | test <p>                     connect + auth + realpath, no mount
shelldrive credential set <profile|--target T|--proxy SPEC> [--stdin] | remove <...> | list
shelldrive hostkey list [host] [--announced] | add --from-server host[:port] [--expect SHA256:...]
                   | remove <host[:port]> [--type T] | import --from putty|openssh [FILE] [--dry-run]
                   | accept-announced <id> [--add-only]
shelldrive location add <profile> | remove <profile> | repair     Network location entries (8.7)
shelldrive service install | uninstall | start | stop | status
shelldrive cache clear [<profile>|--all]
shelldrive logs [--component agent|service|ui] [--lines N] [--follow] [--path]
shelldrive diag [--check] [--bundle FILE.zip [--include-dumps] [--anonymize]] [--fix linked-connections|webclient]
shelldrive diag bench <X:> [--scenario NAME] [--json]           developer/support benchmark (02 §11)
shelldrive update check [--manifest PATH|URL] | apply [--version V]
shelldrive selftest [--json]                      exit 0 = healthy (smoke tests, 04 §11)
shelldrive agent start | stop | status
shelldrive settings get <key> | set <key> <value>
shelldrive version
shelldrive help [command]
```

Aliases kept so that other designs' wording works (C7): `shelldrive bench …` = `diag bench …`,
`shelldrive stats <X:>` = `status <X:> --stats`, `shelldrive admin webclient-enable` = `diag --fix webclient`,
`shelldrive diag collect` = `diag --bundle` (default file name in the current directory). Aliases are not listed in
`help` except under the command they map to.

**Installer hooks (hidden, not in `help`, not localized):** `--installer-hook <name> --apply|--revert
[--log FILE]`, idempotent, each with a rollback counterpart. The same code is reachable as
`shelldrive.exe --installer-hook …` (scripts, support) and `shelldrive-host.exe --installer-hook …`; setup, the
uninstaller and MSI custom actions always call **`shelldrive-host.exe`**, which is GUI-subsystem, so no console
window appears (04 §8.3). The hook names are fixed here and used unchanged by 04:

| Hook | Effect |
|---|---|
| `webdav-tune` | sets `FileSizeLimitInBytes=0xFFFFFFFF` and `FileAttributesLimitInBytes=100000000` under the WebClient parameters, records the originals in `%ProgramData%\ShellDrive\service\state\webdav-tune.ini`, restores them on `--revert`; never touches `BasicAuthLevel` (C28). Per-machine only. |
| `user-cleanup` | for the current user: removes Network location entries (8.7), `HKCU` Run/tray keys, label/icon keys from `state\explorer.ini`, per-user shell registration. Per-user uninstall runs it; per-machine uninstall runs it for the invoking user. |
| `modern-menu` | registers (`--apply`, current user) or removes (`--revert`; elevated: for all users with `RemoveForAllUsers`) the sparse package for the Windows 11 menu (8.6). No-op when no signed package is present or the OS is older than build 22000. |
| `signal-shutdown` | signals the shutdown events of every running agent it may open (12.3). |

Exit codes of hooks: 0 success, 1 failure (details in the log, English). `--selftest` of the host is a separate
flag of `shelldrive-host.exe`, not a hook.

Global options: `--json`, `--quiet`, `--verbose`, `--machine` (operate on machine scope through the service;
requires elevation), `--lang <code>`, `--output-encoding auto|utf8|utf16|ansi|oem`, `--no-color` (we print no
colors by default on XP; on Windows 10+ only if `ENABLE_VIRTUAL_TERMINAL_PROCESSING` can be set).

Argument parsing: our own parser over `GetCommandLineW()` that follows the MSVC CRT quoting rules (no shell32
`CommandLineToArgvW` dependency). Options accept `--opt value` and `--opt=value`. Secrets are never accepted as
plain arguments (they would appear in process listings): `--stdin` or an interactive prompt.

Elevation (`update apply` is the exception: it never needs an elevated CLI, because the agent launches setup with
`runas` for per-machine installs, 04 §9.6): commands needing admin (`--machine`, `service *`, `diag --fix`) on
Vista+ without elevation exit with
code 9 and a localized hint; they do not self-elevate (a new elevated console would lose output and break scripts).
On XP the check is plain group membership.

### 6.2 Exit codes

| Code | Meaning | JSON `error.code` examples |
|---|---|---|
| 0 | success | |
| 1 | generic failure | `internal`, `io_error` |
| 2 | usage error | `usage` |
| 3 | not found (profile, mount, host key) | `profile_not_found`, `mount_not_found` |
| 4 | authentication failed or required | `auth_failed`, `prompt_required` |
| 5 | host key unknown and not accepted | `host_key_unknown`, `host_key_rejected` |
| 6 | host key mismatch | `host_key_mismatch` |
| 7 | network / connection failure | `connect_failed`, `dns_failed`, `disconnected` |
| 8 | agent/service unavailable | `agent_unavailable`, `service_not_installed` |
| 9 | elevation or permission required | `elevation_required`, `access_denied` |
| 10 | conflict | `target_in_use`, `already_mounted` |
| 11 | backend unavailable | `backend_unavailable`, `webclient_disabled` |
| 12 | timeout | `timeout` |
| 13 | cancelled by user | `cancelled` |
| 14 | protocol / version mismatch | `proto_unsupported` |
| 15 | refused by policy | `policy_denied`, `legacy_refused` |
| 16 | proxy failure | `proxy_connect_failed`, `proxy_auth_failed`, `proxy_unsupported` |
| 17 | self-test or update verification failed | `selftest_failed`, `update_verify_failed` |

The mapping `sd_err` → IPC `code` → exit code is one generated table (1.11, C25); `sd_err_name` produces exactly the
spellings above (`host_key_*`, `dns_failed`, and `auth_required` maps to `prompt_required`).

### 6.3 JSON output

`--json` prints exactly one JSON object to stdout and nothing else on stdout (prompts and progress go to stderr or
the console handle):

```json
{"ok":true,"result":{"mounts":[{"mount_id":"m-3","profile":"web-server","target":"W:","backend":"webdav",
 "state":"mounted","read_only":false,"warnings":[{"code":"legacy_algorithms","algorithms":["hmac-sha1"]}]}]}}
{"ok":false,"error":{"code":"host_key_mismatch","detail":"stored ssh-ed25519 key differs","exit_code":6}}
```

`logs --follow --json` emits JSON Lines (one object per line). JSON keys and `detail` are English; JSON is always
UTF-8 regardless of `--output-encoding`.

### 6.4 Console output encoding (XP..11)

- If `GetConsoleMode(hStdOut)` succeeds, stdout is a real console: write with **`WriteConsoleW`** (XP+), which
  bypasses the code page entirely. Same for stderr.
- Otherwise output is redirected (file/pipe): encode as **UTF-8 without BOM** by default (what PowerShell 7, Git
  tools and most CI log collectors expect). `--output-encoding` or `SHELLDRIVE_OUTPUT_ENCODING` overrides:
  `utf16` (UTF-16LE with BOM, for `cmd /u`-style consumers), `ansi` (`GetACP`), `oem` (`GetConsoleOutputCP`,
  falling back to `GetOEMCP`, for legacy batch files that parse output with `for /f`).
- Never call `SetConsoleOutputCP`: it changes the code page of the shared console for the parent shell too.
- Input prompts: `ReadConsoleW` with `ENABLE_ECHO_INPUT` cleared for secrets; if stdin is not a console and
  `--stdin` was given, read UTF-8 from stdin up to the first newline.
- XP note: raster console fonts cannot show every character; Latin text of our six languages is covered by the
  default OEM fonts, so no special handling.

### 6.5 Help localization

`--help` texts are catalog entries (9) in the `cli` domain: one summary per command, one line per option, generated
usage synopsis (option names and syntax are not translated). Help wraps at the console width
(`GetConsoleScreenBufferInfo`, 80 when redirected). Language selection for the CLI: `--lang`, then
`SHELLDRIVE_LANG`, then `settings.ini`, then the user's UI language (9.3).

---

## 7. Tray app and main window

### 7.1 Toolkit rules

- Pure Win32 + common controls v6 (ListView, TreeView, Toolbar, Tab, PropertySheet, Link control `SysLink` (v6,
  XP+), tooltips) via the application manifest dependency on `Microsoft.Windows.Common-Controls` 6.0.0.0 — works on
  XP. No MFC/ATL/WTL/WinRT/XAML islands.
- `InitCommonControlsEx` with exactly the classes used.
- Manifest also declares `supportedOS` GUIDs (Vista through 10/11), `requestedExecutionLevel asInvoker`, DPI
  settings (7.3), `activeCodePage` **not** set (we are UTF-16 internally; it would also be ignored before 1903).
- **Dialogs are in-memory `DLGTEMPLATEEX` generated from declarative C tables** (control kind, string id, layout
  constraints), followed by a layout pass that measures the localized text (`DrawTextW(DT_CALCRECT)`) with the
  dialog font at the current DPI and positions controls in rows/columns. No `.rc` DIALOG resources. Reasons: German
  and French strings are 30–40% longer than English and fixed dialog units clip them; one template works for six
  languages and every DPI; still uses the dialog manager so `IsDialogMessage` keyboard navigation, default buttons
  and mnemonics work for free. Property sheet pages use `PSP_DLGINDIRECT` with the same generator.
- Font: `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)` message font (Segoe UI on Vista+, Tahoma on XP), scaled
  per DPI (`SystemParametersInfoForDpi` on 10 1607+ via `GetProcAddress`).

### 7.2 Tray

- `Shell_NotifyIconW`; `NOTIFYICONDATAW` size chosen at runtime: `NOTIFYICONDATAW_V2_SIZE` on XP,
  `NOTIFYICONDATAW_V3_SIZE` on Vista+ (V3 adds `guidItem`/`hBalloonIcon`), `NIM_SETVERSION` with
  `NOTIFYICON_VERSION` on XP and `NOTIFYICON_VERSION_4` on Vista+. We identify the icon by `uID`, not `guidItem`
  (a GUID is bound to the executable path and breaks portable copies).
- Re-add on `RegisterWindowMessageW(L"TaskbarCreated")` (Explorer restarts).
- Icon states (each a distinct shape, not only color): idle (no mounts), connected, reconnecting (badge with
  arrows), warning (legacy algorithms or partial failure), error. Light/dark taskbar variants on 10+ (read
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme`); the classic variant on
  XP/7. Icons from a multi-size `.ico` (16/20/24/32/40/48) chosen with `LoadIconWithScaleDown` (Vista+, runtime) or
  `LoadImageW` with `SM_CXSMICON`.
- Tooltip: "ShellDrive — 2 drives connected" (plural-aware).
- Left click / Enter: open main window. Right click / Shift+F10 / Apps key (`WM_CONTEXTMENU` with
  `NOTIFYICON_VERSION_4`, `WM_RBUTTONUP` on XP): menu with one item per profile (check mark when mounted; submenu:
  Mount/Unmount, Open, Reconnect, Edit), separator, "Mount another…", "Open ShellDrive", "Settings", "Exit tray" (keeps
  mounts, agent keeps running), "Disconnect all and exit".
- `SetForegroundWindow` before `TrackPopupMenu` and `PostMessage(WM_NULL)` after (classic tray menu dismissal fix).

### 7.3 DPI awareness XP..11

- Manifest: `<dpiAware>true</dpiAware>` plus `<dpiAwareness>PerMonitorV2, PerMonitor</dpiAwareness>`. `dpiAware`
  is read from Vista on and only means system awareness; `dpiAwareness` is read from Windows 10 1607 on, takes an
  ordered fallback list, and makes `dpiAware` ignored; Microsoft recommends the manifest over API calls
  ([Setting the default DPI awareness](https://learn.microsoft.com/en-us/windows/win32/hidpi/setting-the-default-dpi-awareness-for-a-process)).
  PerMonitorV2 needs 1703; on 1607 the fallback `PerMonitor` applies.
- XP: system DPI (the OS has no virtualization; we read `GetDeviceCaps(LOGPIXELSX)` and scale everything
  ourselves, which the layout engine already does). Vista/7/8: system aware via the manifest. 8.1: system aware
  (we do not implement PMv1 on 8.1; its `WM_DPICHANGED` without non-client scaling is not worth the code).
  10 1703+: PMv2.
- Runtime DPI helpers resolved by `GetProcAddress`: `GetDpiForWindow` (1607), `GetSystemMetricsForDpi`,
  `SystemParametersInfoForDpi`, `AdjustWindowRectExForDpi`. Fallback: system DPI.
- `WM_DPICHANGED`: apply the suggested rect, rebuild fonts and image lists, re-run the layout pass. Under PMv2 the
  dialog manager scales dialog child windows automatically; our layout pass then re-measures text.
- No `SetProcessDpiAwareness*` calls except in tests.
- Shell extension: runs with the host's awareness; it scales menu bitmaps with `GetDpiForWindow(hwndOwner)` when
  available.

### 7.4 Dark mode

- v1 follows the system for what Windows supports documentedly and stays light elsewhere:
  - Title bar: `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE = 20, TRUE)` when apps use dark theme
    (`AppsUseLightTheme = 0`) — documented as supported from Windows 11 build 22000
    ([DWMWINDOWATTRIBUTE](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute));
    we only call it on build ≥ 22000 (it is known to work on late Windows 10 builds, but undocumented there).
  - Tray icon variant follows `SystemUsesLightTheme` (7.2).
- We do **not** use the undocumented uxtheme ordinals (`SetPreferredAppMode`, `AllowDarkModeForWindow`) or the
  `DarkMode_Explorer` theme class names: they changed between builds and would be a maintenance risk. Client areas
  use system colors (`GetSysColor`), so High Contrast themes (including dark High Contrast) render correctly. Revisit
  if Microsoft documents a Win32 dark mode for common controls.

### 7.5 Main window (connection manager)

- Toolbar (with text labels, not icon-only): New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs.
- ListView (report view, groups "My connections" / "Provided by your organization" / "Global drives" using
  ListView groups, v6 XP+): columns Name, Server, Drive/Folder, Backend, Status, Security. Status and Security show
  icon **and** text ("Connected", "Reconnecting (3)", "Legacy encryption").
- Status bar: agent state ("ShellDrive is running", "Agent not running — Start").
- Double-click/Enter: mount, or open in Explorer if mounted. Delete key: delete with confirmation.
- Profile editor: property sheet with pages General (name, host, port, user, remote path), Authentication (methods,
  key file with "Browse…", "Keep a protected copy", certificate, agent, saved password management), Connection
  (jump hosts as an ordered list with Add/Up/Down/Remove; a **Proxy** column per leg with an editor offering "No
  proxy", "Use the system proxy settings", "HTTP proxy", "SOCKS5 proxy", host, port, user name, authentication and
  "Save proxy password"; keepalive, timeouts; "Parallel connections" spin box 1–4 with the 2FA note from 3.4),
  Drive (target, backend with availability text, read-only, **Writes**: "Wait for the server to confirm each write
  (safer)" (default) / "Write in the background (faster; if the connection drops, recent changes can be lost and
  ShellDrive tells you)", label, symlinks "Follow"/"Hide", dot-files, autostart, "Show in This PC under Network
  locations"), Cache (TTLs, disk cache size, default off), Security (legacy algorithm policy, host key alias, "When
  the server offers new host keys": Ask me / Save them automatically / Ignore, show stored host keys).
  "Test connection" runs `profile.test` (connect + auth + `realpath`, no mount). For `scope = users` templates
  every control is read-only except target and autostart (D25).
- Host key manager: ListView (host, port, type, fingerprint, store user/machine, source: "ShellDrive", "Copied
  from PuTTY", "Copied from OpenSSH", "Updated by server"), Remove, Import, Copy fingerprint, and a "Pending
  updates from servers" group for `hostkeys.announced` items (5.6). Live-source keys not yet copied are not listed
  (they are read on demand); a note says which sources are active. Machine entries are read-only unless elevated
  ("Edit machine keys…" relaunches elevated).
- Logs viewer: read-only multiline edit with the last 2000 lines from `log.tail`, filter by level, "Open log
  folder", "Create diagnostic bundle…".
- Settings: language (with "System default"), start at sign-in (agent / tray separately), notifications per type,
  default backend, default write mode, credential roaming, memory cache budget, "Trust host keys accepted in
  PuTTY" / "Trust host keys accepted in OpenSSH" (5.1), updates (check automatically, channel), linked connections
  status + "Change…" (elevated), WebClient status, Windows 11 menu status (8.6).
- First-run wizard (`PropertySheet` with `PSH_WIZARD97`, XP+): welcome, import (5.5), create first profile, finish.

### 7.6 Legacy algorithm warning UX

`sd_ssh` reports the negotiated kex, host key, cipher and MAC per direction plus a `legacy_mask` bitmask
(`on_negotiated`, 01 §6.7/§9). The host derives the per-algorithm `legacy` flags from the algorithm names and the
mask (C21); the `ask` prompt is 01's `SD_PROMPT_LEGACY_ACK`.

- Policy per profile (`legacy_algorithms`) and global policy override:
  - `allow`: no UI, logged at info.
  - `warn` (default): mount proceeds; notification once per (host, algorithm set) — "Connected to example.org using
    outdated security (3des-cbc, hmac-sha1). The connection works but is easier to attack. Details". The ListView
    Security column shows the warning; the Details dialog lists each negotiated algorithm with category, whether it
    is legacy and a one-line reason, plus buttons **Don't warn again for this server** (stores
    `legacy_accepted = sha256(<sorted algorithm list>)`; a *different* legacy set warns again),
    **Refuse outdated algorithms for this server** (sets `refuse`, offers to reconnect) and **Close**.
  - `ask`: a `legacy_ack` prompt blocks the connection before authentication (so no password is sent over the weak
    channel until the user agrees).
  - `refuse`: legacy algorithms are removed from the offer (passed to `sd_ssh` as a filter); negotiation failure →
    `legacy_refused` (exit 15) with a message naming what the server offered.
- CLI: a localized warning line on stderr ("Warning: example.org uses outdated algorithms: hmac-sha1.") and the
  `warnings` array in JSON. Service: Event Log warning once per mount.

### 7.7 Notifications

Balloon tips via `NIF_INFO` (XP+; Windows 10+ shows them as toasts automatically; real toasts with
`ToastNotificationManager` are out of scope). `NIIF_USER` + `hBalloonIcon` on Vista+, `NIIF_WARNING/ERROR/INFO`
on XP. `NIIF_RESPECT_QUIET_TIME` on 7+. At most one balloon per (mount, event type) per 60 s; queued otherwise.
Click on the balloon (`NIN_BALLOONUSERCLICK`) opens the relevant dialog. Events and defaults: connection lost
(on), reconnected (on), mount failed (on), mounted (off), legacy algorithms (on), host key changed (always, cannot be
disabled), **write failed** (`write_failed`, always, cannot be disabled, C45: "Changes to report.docx on W: could not
be saved because the connection to example.org was lost."), server offered new host keys (on, 5.6), new host keys
saved automatically (on), proxy sends password unencrypted (on, once per profile and proxy), extra connections not
used because signing in needs typing (off), service needs attention (admins, on), update available (on; 04 decides
content). Every notification is also recorded in the main window's event list so nothing exists only as a
transient balloon.

---

## 8. Explorer integration

### 8.1 What appears where

- **Mapped drives appear in "This PC"/"My Computer" by themselves.** WebDAV mounts appear as network drives;
  Dokany mounts as whatever device type 02 chooses. We use non-persistent mappings only (no
  `CONNECT_UPDATE_PROFILE`): a remembered connection would make Windows try to reconnect at logon before the agent
  runs and show "Could not reconnect all network drives". Requirement to 02.
- "Mount with ShellDrive" is offered on the This PC/My Computer item's context menu (submenu with profiles) and as
  the default verb of `.sdmount` files (a one-line file `profile = <id>` the user can put on the desktop; static
  verb `HKCR\ShellDrive.Mount\shell\open\command = "shelldrive-ui.exe" --action mount-file "%1"`, no handler code).
- **"Add network location" entries (D14, v1, milestone M3):** each per-user profile with `network_location = yes`
  gets a Network Shortcuts entry, shown in This PC under "Network locations" (Vista+) and in My Network Places
  (XP). It opens the drive when mounted and mounts it when not (8.7).
- Registry written by setup (C10): only the context-menu handler (Drive, Directory, `*`, This PC CLSID), the
  Approved list, the `.sdmount` ProgID, App Paths and Run keys. No shell namespace entries (8.4). Network location
  entries are files in the user profile, created by the agent, not by setup.

### 8.2 Context menu handler

- `IShellExtInit` + `IContextMenu` (both XP+). No `IContextMenu3`/owner draw: on Vista+ menu icons via
  `MENUITEMINFOW.hbmpItem` with a 32-bpp premultiplied DIB; on XP no icons.
- Registered for:
  - `HKCR\Drive\shellex\ContextMenuHandlers\ShellDrive`: on ShellDrive drives only — Unmount, Reconnect, Open in
    ShellDrive, Copy remote path (`sftp://user@host:port/path`).
  - `HKCR\Directory\shellex\ContextMenuHandlers\ShellDrive` and `HKCR\*\shellex\...`: inside ShellDrive drives
    only — Copy remote path.
  - `HKCR\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shellex\ContextMenuHandlers\ShellDrive` (This PC):
    "Mount with ShellDrive ▸ <profiles>", "Open ShellDrive".
- `QueryContextMenu` must return within microseconds: it maps `Local\ShellDrive.state.<SID>` (a read-only section
  the agent rewrites with a sequence counter; content: version, seq, array of {target, profile id, profile name,
  state, remote URL}) and reads profile names for the This PC submenu from a small cache file
  `%LOCALAPPDATA%\ShellDrive\state\menu.cache` written by the agent/UI. It never opens the pipe, never touches the
  network, never loads profile files. If the section is missing, drives get no items and the This PC submenu shows
  profiles from the cache with "ShellDrive is not running" items still working (the UI starts the agent).
- `InvokeCommand` launches `shelldrive-ui.exe --action <verb> <args>` with `CreateProcessW` (full path from our
  own registry key, quoted) and returns. Errors are shown by the UI, localized.
- Verb strings come from the catalog (`shell` domain, 9); language from settings or the user UI language.
- On Windows 11 the classic items appear under "Show more options". The modern top-level menu (8.6) ships in v1
  when the code-signing certificate exists in time (D27); otherwise 1.0 has the classic menu only and the modern
  one lands in 1.x.
- Robustness: no exception filters installed in the host, `__try/__except` only around our entry points, no
  static CRT state that blocks `DllCanUnloadNow`, no threads created.

### 8.3 Drive labels and icons

Written by whoever owns the mount (agent for per-user, service for global), removed on unmount, and reconciled at
start (stale entries listed in `state\explorer.ini`), followed by `SHChangeNotify(SHCNE_UPDATEITEM | SHCNE_RENAMEFOLDER
as appropriate, SHCNF_PATHW, L"X:\\")`.

- **Labels, WebDAV:** Explorer shows `DavWWWRoot (\\localhost@port)` by default. We set
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\<key>\_LabelFromReg` (REG_SZ) where `<key>`
  is the UNC with `\` replaced by `#` (e.g. `##localhost@53122#DavWWWRoot#s-<token>`, path per 02 §7.3)
  **[verify XP and 11 behavior]**. The UNC keeps the opaque `/s-<token>/` component; no readable slug is added (C30).
  Global WebDAV drives in `attach` mode (1.3) are mapped by each user's agent, which writes the same per-user key.
  In `system` mode the service cannot write other users' keys, so those drives show the default label.
- **Labels, Dokany:** the volume label returned by the `GetVolumeInformation` callback (02 takes the label from the
  profile).
- **Icons, per user:** `HKCU\Software\Classes\Applications\Explorer.exe\Drives\<Letter>\DefaultIcon =
  "<path>\shelldrive-ui.exe",-<id>` (community-documented
  [per-user drive icon key](https://www.elevenforum.com/t/change-icon-of-drive-in-windows-11.16591/); **[verify on
  7/10/11; not expected on XP]**). Where it does not work the drive keeps the standard network drive icon — acceptable.
- **Icons, global drives:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\<Letter>\DefaultIcon`
  (Microsoft-documented machine-wide drive icon —
  [Customizing Icons](https://msdn2.microsoft.com/en-us/library/bb776856(v=vs.85))), written only by the service for
  letters it owns, because the HKLM key applies to that letter for every user.

### 8.4 Shell namespace extension: not implemented

A namespace extension (our own node under This PC with browsable folders) is rejected:

- It duplicates the filesystem layer at the shell level, and only Explorer would see it — no `cmd`, no
  applications, no file dialogs of non-shell-aware programs. The whole point of ShellDrive is a real drive letter.
- `IShellFolder`/`IShellView` implementations are large, version-sensitive (XP vs Vista+ property system, Windows 11
  changes), and run inside Explorer where a bug takes down the desktop.
- The real drive already gets label, icon and context menu, which covers the visible benefits.
- A *non-browsable* junction under This PC that only lists profiles could be added later as a pure launcher; not
  in v1.

### 8.5 Architectures and registration

- Per arch: x86 on x86; x64 + x86 on x64 (same CLSID registered in both registry views with `KEY_WOW64_32KEY`, the
  x86 DLL in `Program Files (x86)` or a `x86\` subfolder); ARM64 + x86 + x64 on ARM64 (x64 only on Windows 11).
  Missing the x86 DLL means our menu items silently vanish in 32-bit apps' file dialogs.
- Registration by the installer in HKLM (`HKLM\Software\Classes`), plus
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved` (needed where
  `EnforceShellExtensionSecurity` is set). Per-user/portable: `HKCU\Software\Classes` (works on XP and later unless
  that policy is set). `ThreadingModel = Apartment`.
- **Updates without reboot (C4):** each version is installed into its own directory `shellext\<version>\` (per
  arch), and setup rewrites `InprocServer32` to the new path. Running Explorers keep the old DLL loaded until they
  restart; new processes load the new one. Old version directories are deleted at the next agent start once no
  process has them loaded (delete failure = still loaded, retried later). No `MOVEFILE_DELAY_UNTIL_REBOOT`.
  Both versions read the same snapshot layout (1.6).

### 8.6 Windows 11 modern context menu (D27, conditional on the certificate)

The Windows 11 top-level menu shows only `IExplorerCommand` handlers registered by a package with identity. We use a
**sparse package** (package with external location): a small signed MSIX that contains only the manifest and
logos, and points to the already installed files.

- **Ships in v1 only if** the code-signing certificate (D29) exists before the release; the package must be signed
  with a certificate whose subject equals the manifest `Publisher`, and Windows refuses unsigned or untrusted
  packages. Without it, 1.0 ships the classic menu only (8.2) and the modern menu lands in 1.x with no other change.
- **Package:** `ShellDrive.ShellExt.msix` built by 04, installed next to the binaries. Manifest essentials:
  `Identity Name="ShellDrive.ShellExt"`, `uap10:AllowExternalContent="true"`, `TargetDeviceFamily
  Name="Windows.Desktop" MinVersion="10.0.22000.0"`, `uap10:TrustLevel="mediumIL"` and
  `uap10:RuntimeBehavior="win32App"` on an application entry for `shelldrive-ui.exe`; extensions
  `com:Extension Category="windows.comServer"` (`com:SurrogateServer` → `com:Class Id="{modern CLSID}"
  Path="shellext\<version>\shelldrive-shellext.dll" ThreadingModel="STA"`) and `desktop4:Extension
  Category="windows.fileExplorerContextMenus"` with `desktop5:ItemType Type="Directory"` and `Type="*"` (and
  `Directory\Background`) referencing the CLSID by `desktop5:Verb`. **[verify whether a `Drive` item type is
  honored; if not, drive-root items stay in the classic menu]**. The This PC menu stays classic.
- **Handler:** the same `shelldrive-shellext.dll` exports a second CLSID implementing `IExplorerCommand` (+
  `IEnumExplorerCommand` for the "ShellDrive" submenu, `IObjectWithSite`). `GetState` uses the same shared-memory
  snapshot (1.6) and hides itself outside ShellDrive drives; `Invoke` launches `shelldrive-ui.exe --action`, like
  `InvokeCommand`. The classic `IContextMenu` handler checks for the modern registration and, on build ≥ 22000 with
  the package registered, suppresses the duplicate items under "Show more options".
- **Registration (04 §10.1):** per-user installs register the package for the current user at install time;
  per-machine installs do not register it from the MSI (no SYSTEM-context custom action): each user's agent
  registers it for its user at its first start after an install or update (`AddPackageByUriAsync` with
  `ExternalLocationUri` = install dir, idempotent version compare). **[verify whether sparse packages can be
  provisioned for all users with `ProvisionPackageForAllUsersAsync`; if so, that becomes an optimization]**.
  Per-machine uninstall removes it for all users. All of this is the code of the hidden hook
  `--installer-hook modern-menu --apply|--revert` (6.1), which resolves the WinRT `PackageManager` at runtime and is
  a no-op before build 22000. Each shell DLL update re-registers the package because the DLL path contains the
  version. Policy `DisableModernContextMenu` and `[explorer] modern_menu = off` keep the classic menu only.
- **Portable mode:** never registered (package identity is bound to the install path).

### 8.7 Network locations (D14)

Windows stores "Add network location" entries as **folder shortcuts** in the user's NetHood folder:
`SHGetFolderPathW(CSIDL_NETHOOD)` returns `%APPDATA%\Microsoft\Windows\Network Shortcuts` on Vista+ and
`%USERPROFILE%\NetHood` on XP ("My Network Places"). Each entry is a folder with the read-only attribute
containing a `target.lnk` (shell link to the target) and a hidden + system `desktop.ini`:

```ini
[.ShellClassInfo]
CLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}
Flags=2
[ShellDrive]
profile=7f3c2a90d1e44b6c9a0e5b21c4d7f8aa
```

`{0AFACED1-E828-11D1-9187-B532F1E9575D}` is the shell's "Folder Shortcut" class, known from Windows 2000 to 11
([winshl-kb](https://winshl-kb.readthedocs.io/en/latest/sources/shell-folders/0afaced1-e828-11d1-9187-b532f1e9575d.html));
without the folder's read-only attribute Explorer ignores `desktop.ini`. Explorer ignores the extra `[ShellDrive]`
section, which we use to recognize our entries. **[verify on XP SP3, 7, 10 and 11: entry shown, opens the target,
`CLSID2` vs `CLSIDFolder` key name]**

Design:

- **Owner:** the user's agent (per-user and `scope = users` profiles with `network_location = yes`; never service
  profiles, never in portable mode, never when policy `DisableNetworkLocations = 1`). The folder name is the
  profile display name, made a valid file name (reserved characters replaced by `_`, trailing dots and spaces
  trimmed, ` (2)` suffix on collision with a foreign entry). Icon: `IconResource=<path>\shelldrive-ui.exe,-<id>`
  in `[.ShellClassInfo]` **[verify that folder shortcuts honor it; otherwise the target's icon is shown]**.
- **Target while unmounted:** `target.lnk` points to the placeholder folder
  `%LOCALAPPDATA%\ShellDrive\places\<profile id>\`, which contains one file `Connect to <name>.sdmount`
  (`profile = <id>`, the existing `.sdmount` verb, 8.1). Double-click mounts through
  `shelldrive-ui.exe --action mount-file` and opens the drive. A placeholder is used instead of a link to
  `shelldrive-ui.exe` because a Network location must be a folder to look like one, and a folder shortcut to a
  missing drive letter shows an error.
- **Target while mounted:** the agent rewrites `target.lnk` (`IShellLinkW` + `IPersistFile`, written to a temp name
  and moved over) to the mount root (`X:\` or the NTFS folder), then sends `SHChangeNotify(SHCNE_UPDATEDIR,
  SHCNF_PATHW, <NetHood path>)`. On unmount it points back to the placeholder. **[verify that open Explorer
  windows re-resolve the folder shortcut after the update]**
- **Lifecycle:** created when a profile is saved with `network_location = yes` or at agent start; renamed with the
  profile; removed when the profile is deleted or the option is turned off. Agent start reconciles: every NetHood
  folder whose `desktop.ini` has a `[ShellDrive] profile=` that no longer exists (or is hidden/disabled) is deleted;
  missing entries are recreated. Entries without our section are never touched. `shelldrive location add | remove
  | repair` does the same from the CLI (works without an agent, under the config lock).
- **Uninstall:** per-user uninstall and the invoking user of a per-machine uninstall run
  `--installer-hook user-cleanup`. Other users of a per-machine install keep inert entries pointing at their
  placeholder folder; the `.sdmount` file then has no handler. This is documented in the admin guide.
- **Not done:** no entries in the machine-wide `All Users` NetHood (it does not exist on Vista+), no namespace
  extension (8.4).

---

## 9. Localization

### 9.1 Decision: our own message catalog compiled into each binary

Authoring format: **gettext PO files** `locale/<lang>/<domain>.po` with `msgctxt` = stable symbolic ID,
`msgid` = English source, `msgid_plural`, `msgstr[n]`, translator comments `#.`. The English `en` file is the source
of truth; the other five are translations. A build tool `tools/sdl10n` (C, built for the build host) validates and
compiles them into a generated C source per domain (`sd_l10n_<domain>.c`): for each language a table of UTF-8
strings indexed by an enum generated into `sd_l10n_ids.h`. The tables are compiled into the binaries that use the
domain. Domains: `common`, `cli`, `ui`, `shell`, `svc`, `installer`.

**PO is the only source of user-facing text (C41).** `sdl10n` emits: the C tables (apps, setup stub,
`uninstall.exe`; the stub uses the `installer` domain and the language resolution of 9.3), the per-language
`STRINGTABLE` blocks below, the WiX `.wxl` files for the MSI and its language transforms, and the ADML files for the
ADMX template. Nothing is maintained by hand in `.wxl` or ADML. Canonical language codes are `en es fr pt-BR it de`;
`pt` is accepted as an alias of `pt-BR` everywhere a code is typed (`--lang`, `/lang=`, settings, policy) (C42).
The MSI embeds the `es` transform under LCIDs 11274 (es-AR), 3082, 2058 (es-MX), 21514 (es-US) and 1034, and the
`pt-BR` transform under 1046 and 2070; the setup EXE always passes `TRANSFORMS` explicitly from its own language
resolution (C43, packaging in 04). A build-only pseudo-locale `qps` (accented, +40 % length) exists for layout
tests; it is never shipped and is not a supported language.

Why not the alternatives:

- **Per-language STRINGTABLE/DIALOG resources in the .exe:** no plural support; `LoadStringW` picks the language
  from the thread UI language, which XP cannot set to an arbitrary language (`SetThreadUILanguage` on XP only
  accepts 0 and actually changes the thread locale —
  [SetThreadUILanguage](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-setthreaduilanguage)),
  so we would have to walk resources with `FindResourceExW` ourselves anyway; DIALOG templates per language
  multiply layout maintenance by six and break with long German strings.
- **Satellite resource DLLs (MUI):** the MUI resource loader is Vista+, extra files complicate portable mode and the
  universal installer, and they still lack plurals.
- **Our catalog** gives plurals, named placeholders, a build-time completeness check (AGENTS.md: "A string is not done
  until every locale has it" — enforced by the build), identical behavior XP..11, and one mechanism for CLI, UI,
  shell extension, service and installer. Cost: ~150–250 KB of UTF-8 text across six languages, acceptable.

Exception — strings Windows itself loads from our files: the service display name/description
(`@<path>,-<id>` indirect strings, Vista+, set by the service with `ChangeServiceConfig2W`, 1.3), the
`MUIVerb`/`FriendlyTypeName` of the `.sdmount` file type. (The sparse package manifest, 8.6, carries only the
product name "ShellDrive", which is not translated; its menu texts come from our catalog at run time through
`IExplorerCommand::GetTitle`.) For these the tool also emits small per-language `STRINGTABLE` blocks
(`LANG_*`/`SUBLANG_*`) into `shelldrive-host.exe`/`shelldrive-ui.exe` resources, from the same PO files; on XP the
English plain string is used. The **Event Log message file is English only** (Event Log messages are logs under
AGENTS.md, C44; 10.3). The installer (MSI) consumes `.wxl` files generated from the `installer` domain (04).

### 9.2 Build-time checks (fail the build)

Missing translation in any locale; `msgstr` placeholders not equal to the `msgid` placeholder set; plural entry
missing any `msgstr[n]` the language's category list requires (9.4: three forms for es/fr/it/pt-BR, two for en/de);
a `Plural-Forms` header that differs from the canonical one in 9.4; mnemonic `&` duplicated within one dialog/menu for the same language (dialog tables declare
which IDs share a mnemonic scope); string longer than a declared hard limit (tray tooltip 127 chars incl. NUL, balloon
title 63, balloon text 255 — `NOTIFYICONDATAW` field sizes); invalid UTF-8; fuzzy entries.

Register (AGENTS.md) is a review rule enforced by a glossary and a lint: `es` voseo (lint flags `tú`-forms of common
imperatives like "elige", "haz clic" and the `usted` forms "elija", "haga"), `fr` vous, `pt-BR`, `de`/`it` informal
imperative (lint flags `Sie`/`Lei` imperative patterns). The lint is heuristic and warns; reviewers decide.

### 9.3 Language selection

Order: `--lang` (CLI) → `SHELLDRIVE_LANG` (CLI) → policy `UILanguage` → `settings.ini [ui] language` →
`GetUserDefaultUILanguage()` (Windows 2000+) → `en`. Typed codes accept `pt` as an alias of `pt-BR` (C42).
Mapping of Windows languages by primary language: `es-*` → `es`, `fr-*` → `fr`,
`pt-*` → `pt-BR` (pt-PT users get Brazilian Portuguese; documented), `it-*`, `de-*`, everything else → `en`. The
chosen language is stored per process at startup; the UI re-creates its windows on change. The agent and service do
not localize (they produce codes; clients localize), except (a) service-user-visible strings in the `svc` domain,
which use the machine default language (`GetSystemDefaultUILanguage`), and (b) user-visible text that `sd_vfs`
shows inside the filesystem, such as the volume label suffix " (offline)": the host passes the localized suffix to
`sd_vfs` (agent: the user's language; service: the machine default language) (C45). We never call `SetThreadUILanguage` for our own
strings. System error texts (`FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM)`) come in the OS language and are shown
only as secondary detail under our localized message.

### 9.4 Plural rules

**Full CLDR plural categories (D26).** The catalog format and `sdl10n` support all six CLDR categories
(`zero`, `one`, `two`, `few`, `many`, `other`); each language declares its ordered category list, and every plural
entry must provide exactly one form per category of that list. Counts are integers only (we never pluralize
fractions, so CLDR operands reduce to `n = i`, `v = 0`, `e = 0`). Rules for our six locales (CLDR cardinal rules):

| Language | Categories (PO index order) | Rule (integers) | PO `Plural-Forms` (canonical) |
|---|---|---|---|
| en, de | `one`, `other` | one: n = 1 | `nplurals=2; plural=(n != 1);` |
| es, it | `one`, `many`, `other` | one: n = 1; many: n ≠ 0 and n mod 1 000 000 = 0 | `nplurals=3; plural=(n == 1 ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);` |
| fr, pt-BR | `one`, `many`, `other` | one: n = 0 or n = 1; many: n ≠ 0 and n mod 1 000 000 = 0 | `nplurals=3; plural=((n == 0 \|\| n == 1) ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);` |

The `many` form is the one CLDR uses for large round numbers ("1 000 000 de archivos", "1 000 000 de fichiers",
"1 000 000 di file", "1.000.000 de arquivos"). Translators must write it; the build fails if it is missing, and the
PO header must equal the canonical expression above. `sdl10n` maps each `msgstr[n]` to its category by the list
above and emits a per-entry form table; `sd_l10n.c` holds the category functions (one small function per language,
table-driven, unit-tested against CLDR sample values including 0, 1, 2, 5, 1 000 000 and 2 000 000). Adding a
language (AGENTS.md) means adding its category list and rule from CLDR; `zero`, `two` and `few` are already
supported by the format even though none of the current six uses them. English source entries declare `one` and
`other`; `msgid`/`msgid_plural` stay the English one/other forms.

### 9.5 Placeholders and formatting

Our own formatter, not `FormatMessage` (whose `%1!s!` inserts are positional only, need `va_list` or arrays with
format-specifier risk, and have no plural support).

- Named placeholders: `"Mounted {profile} on {target}."`; `{count}` with plural selection by the argument named in
  the entry's `#, plural-arg` flag (default `count`). Escaping: `{{` and `}}`.
- Typed arguments: string, integer (formatted with `GetNumberFormatW(LOCALE_USER_DEFAULT)`, XP+, so thousand
  separators follow the user's regional settings), size (our helper; unit names are catalog entries since French uses
  "Mo"/"Go"), duration, date/time (`GetDateFormatW`/`GetTimeFormatW`, user locale).
- Missing/extra arguments are a debug assertion and render `{name}` literally in release.

```c
/* sd_l10n.h */
typedef enum sd_lang { SD_LANG_EN, SD_LANG_ES, SD_LANG_FR, SD_LANG_PT_BR, SD_LANG_IT, SD_LANG_DE, SD_LANG_COUNT } sd_lang;

typedef enum sd_arg_type { SD_ARG_STR, SD_ARG_INT, SD_ARG_SIZE, SD_ARG_DURATION_MS, SD_ARG_FILETIME } sd_arg_type;
typedef struct sd_arg { const char *name; sd_arg_type type; union { const wchar_t *s; long long i; FILETIME t; } v; } sd_arg;

sd_lang        sd_l10n_init(const wchar_t *override_code);     /* resolves 9.3 order */
const wchar_t *sd_l10n_get(sd_msg_id id);                       /* cached UTF-16, never NULL (falls back to en) */
int            sd_l10n_format(wchar_t *buf, size_t cch, sd_msg_id id, const sd_arg *args, size_t nargs);
wchar_t       *sd_l10n_format_alloc(sd_msg_id id, const sd_arg *args, size_t nargs);
#define SD_S(n, val)  { (n), SD_ARG_STR, { .s = (val) } }
#define SD_I(n, val)  { (n), SD_ARG_INT, { .i = (val) } }
```

---

## 10. Logging and diagnostics

### 10.1 Log files

- Locations from 3.2. Files: `agent-s<session>.log`, `ui.log`, `cli.log` (only with `--verbose` or `log.level =
  debug`), `service.log`.
- Format: one UTF-8 line per record: `2026-10-24T18:03:11.482Z 4412 7720 INFO  ssh  [m-3] kex done kex=curve25519-sha256 cipher=chacha20-poly1305@openssh.com`
  (UTC ISO 8601, pid, tid, level, component, optional mount id, English message, `key=value` fields).
- Levels: error, warn, info (default), debug, trace (trace includes protocol message types, never payloads).
- Rotation by size: 5 MiB per file, 5 generations (`.1` … `.5`), checked on write; configurable. Writes are
  serialized through one logger thread per process with a lock-free queue; the queue drops (and counts) debug/trace
  records under pressure, never error/warn.
- **Redaction rules (enforced by API, not by convention):** the logger has no format specifier for secrets;
  `sd_secret_buf` cannot be printed; kbdint responses, passwords, passphrases, private keys, proxy passwords and WebDAV path tokens are
  never logged. Host names, user names and remote paths are logged (needed for support); `diag --bundle` offers
  "Anonymize host and user names" (replaced by stable hashes).
- `OutputDebugStringW` sink at debug level when a debugger is attached (`IsDebuggerPresent`).

### 10.2 ETW (optional, Vista+)

`sd_log` has a sink interface. An ETW sink registers a provider with `EventRegister` (advapi32, Vista+, resolved at
runtime) and writes manifest-free events with `EventWrite` (UTF-8 string payload + level + component keyword). It is
off unless `log.etw = yes`; useful for enterprise tracing with WPR/`logman`. Not available on XP, not required for
v1.0 (can ship in v1.x without format changes).

### 10.3 Event Log (service only)

- Source `ShellDrive` under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ShellDrive`,
  `EventMessageFile = <path>\shelldrive-host.exe`, `TypesSupported = 7`. Registered by the installer/`service install`.
- One message table (`.mc` compiled by `mc.exe`), **English only**, few event IDs, each with `%1`… inserts:
  1000 service started, 1001 stopped, 1100 global drive mounted (`%1` profile, `%2` target, `%3` host),
  1101 unmounted, 2100 mount failed (`%1` profile, `%2` code, `%3` detail), 2101 reconnecting, 2200 legacy algorithms
  negotiated, 3000 host key mismatch (`%1` host, `%2` expected fingerprint, `%3` received fingerprint), 3001 prompt
  required (needs an administrator), 3100 configuration invalid, 2300 server announced new host keys (`%1` host,
  `%2` added fingerprints, `%3` removed fingerprints; 5.6), 2301 host keys updated by policy, 2400 global WebDAV drive
  waiting for user sign-in (`attach` mode, 1.3). `ReportEventW` (XP+).
- The agent does not write to the Event Log (users cannot register sources; its file log is enough).

### 10.4 Crash dumps

- Each of host, UI and CLI installs `SetUnhandledExceptionFilter` at startup (never the shell extension, which
  lives in someone else's process).
- `dbghelp.dll` is loaded at startup **from System32 by full path** (DLL hijack protection; XP ships a dbghelp with
  `MiniDumpWriteDump`), and a dedicated dump thread with its own stack is created and parked on an event. On
  crash the filter passes `EXCEPTION_POINTERS` and the faulting thread id to that thread and waits. Microsoft
  recommends a separate process when possible and a dedicated thread otherwise
  ([MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump));
  we choose the dedicated thread because spawning a process from a crashed process with a possibly corrupt heap is
  less reliable on XP, and it is one code path.
- Dump type: `MiniDumpNormal | MiniDumpWithThreadInfo` (the latter only if `ImagehlpApiVersion` reports a dbghelp
  that knows it) — **no full memory and no indirectly referenced memory**, to keep secrets out of dumps.
- Files: `logs\crash\<binary>-<yyyymmdd-hhmmss>-<pid>.dmp`, keep the newest 5. Never uploaded automatically; the
  next UI start shows "ShellDrive closed unexpectedly. Create a diagnostic bundle?".
- Windows Error Reporting LocalDumps (Vista SP1+) is documented for admins as an alternative for full dumps.

### 10.5 `shelldrive diag`

`diag --check` runs and prints (localized; `--json` for machines) checks: agent and service status and versions;
backend availability (Dokany driver/runtime version, WebClient service start type and state, WebDAV registry values
`FileSizeLimitInBytes` and `FileAttributesLimitInBytes` as reported by 02's checker; `BasicAuthLevel` is reported
read-only and never changed, C28); `EnableLinkedConnections` state and whether the current user is a split-token
admin; service installed/running and its global WebDAV mode (1.3); free drive letters; configuration parse errors;
known_hosts parse errors and active live sources; system proxy configuration as `proxy = system` would resolve it;
Network location entries in sync (8.7); Windows 11 menu package registered (8.6); clock skew hint; OS version,
architecture and build flavour. `--fix webclient` (elevated) sets WebClient to manual start and starts
it; `--fix linked-connections` as in 1.7.2. Every fix asks for confirmation unless `--yes`.

`diag --bundle FILE.zip` writes a stored (uncompressed) ZIP — trivial writer, no zlib dependency — with logs,
crash dump list (dumps only if `--include-dumps`), redacted configuration (secrets never exist in config; host/user
anonymized on request), `diag --check` JSON, the latest setup and update logs (04 §13), and versions. The user
attaches it manually; nothing is sent. `diag collect` is an alias (6.1).

`diag bench <X:>` runs 02 §11's harness (plain Win32 file APIs on the mounted drive, both backends) and prints a
localized summary, or JSON with English keys under `--json`. `status --stats` prints `sd_vfs_stats` and the
`sd_sftp_session_stats` RTT/throughput figures.

---

## 11. Accessibility

- Standard controls only (no custom-drawn controls in v1), so MSAA (XP) and UI Automation proxies (Vista+) expose
  them without extra code. If a custom control is ever added it must answer `WM_GETOBJECT`.
- Every input has a preceding static label with a mnemonic (`&`), so screen readers pick up the name and keyboard
  users can jump; tab order follows visual order (generated from the layout table); dialogs work with
  `IsDialogMessage`; default and cancel buttons are set; Escape closes.
- All functions reachable by keyboard: toolbar commands have menu equivalents and accelerators; ListView supports
  Apps key/Shift+F10 context menus; tray icon reachable with Win+B and operated with Enter/Apps key.
- Status never only by color or icon: always text too (ListView columns, tray tooltip).
- High Contrast: detect with `SystemParametersInfoW(SPI_GETHIGHCONTRAST)`, use `GetSysColor` brushes, monochrome
  tray icons in High Contrast, re-render on `WM_SYSCOLORCHANGE`/`WM_THEMECHANGED`/`WM_SETTINGCHANGE`.
- Text scaling: layout is measured from the actual font, so the Windows 10+ "Make text bigger" setting and large
  DPI work; no clipped text (layout pass enforces minimum sizes).
- Fingerprints and server-provided prompt texts are in read-only edit controls (selectable, readable by screen
  readers, copyable).
- Notifications are mirrored in the main window event list (7.7) so they are not missed; balloons never carry the
  only copy of an error.
- Timeouts on prompts are generous (2 min default) and the dialog shows the remaining time only as text that
  screen readers do not re-announce every second (updated every 15 s).

---

## 12. Requirements on other teams

### 12.1 To `sd_ssh` / `sd_sftp` / `sd_crypto` (01)

- Asynchronous auth/host-key callbacks: the callback receives a prompt object and a completion handle; it may
  complete later from another thread; cancellation supported; deadline handled by the host.
- Negotiation result with `legacy_mask` (`on_negotiated`) and an algorithm filter input (for `refuse`);
  `SD_PROMPT_LEGACY_ACK` after NEWKEYS and before SERVICE_REQUEST when `legacy_mask & ~MAC_NON_ETM` is set and the
  profile says `ask` (C21).
- `sd_known_hosts` owns known_hosts I/O and locking (C19) and takes an **ordered store list** (machine read-only for
  users, user read-write) plus the live sources OpenSSH and PuTTY (on by default, D7); a match in a source is copied
  into the user store with a source comment; a mismatch in **any** store or source blocks (D7; met in 01 §7.2); entries written plain (D8); `@revoked`, `@cert-authority`, hashed hosts read.
  The known_hosts and key-file translation units must link into the CLI/UI without the transport.
- UpdateHostKeys (D16): `hostkeys-00@openssh.com` + `hostkeys-prove-00@openssh.com`; deliver proven additions and
  absent keys to the host as an event, only on connections whose host key matched a stored key; never write to a
  store by itself (the host applies, 5.6). Met in 01 §7.5: `on_hostkey_event` with `SD_HKEV_ANNOUNCED` (proven
  keys, removal candidates, target store); `sd_mount` turns it into IPC `hostkeys.announced`.
- `SD_ID_BLOB` (key bytes + optional passphrase callback), `sd_ssh_key_probe(bytes) → {type, pub blob, fp,
  encrypted}`, `sd_ssh_key_serialize_openssh(key, no cipher)` (C22, for 4.4 and service keys).
- Reconnect secret cache owned by `sd_ssh` (`cache_secrets_for_reconnect`, C20).
- Proxies (D20): HTTP CONNECT (Basic; Negotiate/NTLM via SSPI, optional) and SOCKS5 (no auth or RFC 1929) as a
  transport stage for leg 1 and inside a `direct-tcpip` channel for later legs (3.8); a `proxy_password` prompt
  through the same asynchronous prompt mechanism; error codes for 6.2 exit 16. No ProxyCommand.
- Connection pool (D18): up to 4 connections per mount. Met in 01 §10.9: `sd_sftp` opens the extra connections
  itself (`sd_sftp_options.connections`) and applies the 2FA rule from `sd_ssh_conn_auth_info().noninteractive`;
  prompts of secondary connections carry `is_pool_member = 1`, and `sd_mount` answers them only from stored
  secrets (`SD_ANSWER_FROM_STORE`) or cancels them, which drops the member (reported as `warning pool_limited`,
  reason `interactive_auth`). Pool changes arrive as `SD_SFTP_EV_POOL`. `sd_sftp` stripes `SD_SFTP_O_STRIPED`
  handles across connections; metadata stays on the primary (01 §10.9, 02 §5.6).
- `sd_ssh_channel_open_exec()` for the optional `identity_probe = exec` (D10). Met: `sd_sftp` runs the probe
  itself when `SD_SFTP_OPT_IDENTITY_EXEC` is set (01 §11).
- Proxy transport (D20): met in 01 §5.2 (per-hop `sd_proxy_cfg`, leg K = `hops[K-1].proxy`, `SD_PROMPT_PROXY_PASSWORD`,
  `SD_E_PROXY` → `proxy_connect_failed`, `SD_E_PROXY_AUTH` → `proxy_auth_failed`, exit 16; system-proxy resolution
  inside `sd_ssh`).
- `sd_err_name` spellings as in 6.2 (C25); `sd_sftp_session_stats()` with `srtt_ms`, `rttvar_ms`, `rx_bps`,
  `tx_bps` for `status --stats`.
- SHA-256 and base64 usable standalone by UI/CLI (fingerprints) without linking the rest.
- Pageant client usable from a process with no window (`SendMessage` WM_COPYDATA with NULL sender).

### 12.2 To `sd_vfs` / `sd_webdav` / `sd_dokan` (02)

- Mount API taking a resolved profile and returning state changes as callbacks (mapped by us to `mount.state`).
- WebDAV: Negotiate with the SID check plus the per-mount path token `/s-<token>/` (02 §7.3/§7.4); **no Basic
  credential** (C26); `mount.attach_info` data = the UNC with the token; non-persistent `WNetAddConnection2W`;
  mapping performed in the token of whoever attaches (agent, elevated CLI, or a user's agent for a service-hosted
  global drive). For service-hosted servers (D11): accept a list of allowed user/group SIDs (`service_access`) in
  the Negotiate check, and the lab spike of `system` and `link` mapping per OS (1.3, 02 §7.7).
- Write mode per profile (D9): `write_through` default on; write-behind only when the profile says `behind`; raise
  `write_failed` to the host (C45). Accept the localized offline label suffix from the host (C45).
- Dokany: `DOKAN_OPTION_CURRENT_SESSION` for agent mounts, global for service mounts; volume label from the profile;
  file system name from `fs_name` (D23). The `Unmounted` callback only notifies the host (C33).
- Every profile key of 3.4.1 consumed by 02 under the names listed there (C46).
- A backend availability probe used by `backend = auto`, `diag` and the UI (Dokany version; WebClient state and
  registry values).
- Cache clear per profile; cache directory passed in by us (3.2).
- Status (reconciled 2026-10-24): met in 02 — `service_access` SID check for service-hosted servers (02 §7.4,
  §7.7), mechanisms `system`/`link`/`attach` with the M5 go/no-go (02 §7.7), one `sd_sftp_session` per mount for
  any pool size (02 §5.6, `sd_vfs_mount`), `write_mode`, `volume_fs_name`, `offline_label_suffix`, `symlinks =
  follow | hide` only (02 §6.9), one global memory budget (02 §4.2).

### 12.3 To build / installer / updater / CI (04)

- Four binaries per arch (1.1, 1.10, D3), shell DLL in two or three arches, manifests as in 7.1/7.3; service
  `ShellDriveSvc` = `shelldrive-host.exe service`; health check `shelldrive-host.exe --selftest`; smoke tests
  `shelldrive selftest --json` (C2).
- Installer options: start at sign-in (Run keys; HKLM Run with `--if-needed` on per-machine installs, C11), install
  service (**checked** on per-machine installs, absent on per-user installs, MSI feature on by default with a way to
  turn it off, D6), `EnableLinkedConnections` (unchecked, explained; MSI property `ENABLELINKEDCONNECTIONS`,
  default 0, D24), shell extension registration incl. Approved list and both registry views, versioned
  `shellext\<version>\` directories with `InprocServer32` rewrite (C4), Event Log source, machine directory ACLs
  (3.2), `.sdmount` file type, `DEFAULTPROFILES` = a folder of `.ini` profiles copied to
  `%ProgramData%\ShellDrive\profiles\` (C9), `UPDATECHECK`/`UPDATEURL` written to the machine `settings.ini` (C8).
- Custom actions only through the hidden hooks of 6.1 (`webdav-tune`, `user-cleanup`, `modern-menu`,
  `signal-shutdown`).
- Windows 11 sparse package `ShellDrive.ShellExt.msix`, built and signed only when the certificate exists (D27, 8.6).
- `tools/sdl10n` integrated in the build; PO completeness (all CLDR plural forms, D26) is a build failure; C tables,
  STRINGTABLEs, `.wxl` and ADML generated from PO (C41).
- **Stopping agents for upgrade/uninstall (C3):** setup signals
  `Global\ShellDrive.agent.shutdown.<SID>.<SessionId>` (1.2). Per-user setup signals the events for its own SID
  (it can open them: the user has `EVENT_MODIFY_STATE`). Elevated setup enumerates running `shelldrive-host.exe`
  processes (Toolhelp32 + `OpenProcessToken`, XP+), derives SID and session ID from each token and signals each
  event; Administrators and SYSTEM are in the event DACL. It then waits up to 15 s per agent and falls back to
  Restart Manager (Vista+) or a "close ShellDrive" message. Setup never connects to agent pipes (their DACL admits
  only the user, 2.2). The service is stopped through the SCM.
- Uninstall also removes registry entries we create, runs `user-cleanup` for the invoking user, unregisters the
  sparse package, optionally removes user data (asked), and removes service secrets.
- Portable ZIP contains `shelldrive.portable`.

---

## 13. Risks and open questions

### 13.1 Risks

1. **WebDAV redirector and elevated/linked sessions.** The elevated-view attach is a workaround with a stale-drive
   wart; real fix requires a system setting the user must accept and a reboot.
2. **Global WebDAV drives (D11)**: `system` mode relies on behavior documented only for XP/2003 (1.3). The M5 lab
   spike decides per OS; where it is no-go, `attach` mode gives per-user drives after sign-in only. Dokany stays
   the primary path for global drives.
3. **Dokany current-session semantics vs. linked tokens** unknown (1.7.2).
4. **Shell extension in third-party processes**: any crash or hang is blamed on us; mitigated by the no-IPC,
   shared-memory-only design. x86 DLL on x64 must not be forgotten.
5. **Credential Manager limits on XP/Home SKUs**: handled by DPAPI fallback, but two stores means two code paths to
   test.
6. **Named pipe squatting on XP** is detected only by owner check; a malicious process running as the same user can
   always impersonate the agent — accepted (same-user code is inside the trust boundary).
7. **In-memory secret cache for reconnection** (owned by `sd_ssh`, C20) extends secret lifetime; mitigated by
   encrypted memory and the per-profile `cache_secrets_for_reconnect = no` option (then reconnect prompts).
8. **Code-generated dialogs** cost an initial layout engine (~1500 lines) but remove six-fold DIALOG maintenance.
9. **Windows 11 modern context menu** depends on the certificate arriving in time (D27); without it 1.0 users must
   use "Show more options".
10. **Per-user drive icon key** is community-documented only.
11. **Live known_hosts sources block on stale entries** (D7): an outdated key in `~/.ssh/known_hosts` or PuTTY blocks
    the connection although the ShellDrive store was fixed; mitigated by the dialog in 5.4 that names the source and
    lets the user turn it off.
12. **Network location entries** (8.7) rely on the folder-shortcut format, which is not formally documented; the
    format has been stable since Windows 2000 but needs the lab checks in 13.3.
13. **Service enabled by default** (D6) adds an always-running LocalSystem process on per-machine installs; mitigated
    by the idle mode (1.3: no network, no listener without service profiles) and the threat-model review in M5.
14. **Proxy credentials in clear** to HTTP Basic / SOCKS5 proxies; mitigated by the warning in 3.8 and by preferring
    Negotiate when the proxy offers it.

### 13.2 Open questions

1. Verify PuTTY value names (`DetachedCertificate`, `ProxyMethod` numbering) and XP `CRED_MAX_CREDENTIAL_BLOB_SIZE`
   (lab check).

Resolved by `decisions.md`: Network Shortcuts in v1 (D14, 8.7); sparse MSIX modern menu (D27, 8.6);
`ENABLELINKEDCONNECTIONS` default 0 (D24); template overrides limited to target and autostart (D25); full CLDR
plurals (D26, 9.4); `CryptProtectMemory` on XP is moot because `sd_ssh` owns the reconnect cache (C20).

### 13.3 Verification matrix (to run on real systems before implementation freeze)

| Fact | XP SP3 | 7 SP1 | 10 22H2 | 11 24H2 |
|---|---|---|---|---|
| LocalSystem WNet mapping visible to all sessions (D11 spike, M5 go/no-go) | doc + test | test | test | test |
| User attach of a service-hosted WebDAV server (Negotiate as user, `service_access`) | test | test | test | test |
| Network location folder shortcut (`CLSID2`, read-only folder) shown and opens target | test | test | test | test |
| Rewritten `target.lnk` picked up by open Explorer windows | test | test | test | test |
| Sparse package registration + modern menu items (Directory, `*`, drive root) | — | — | — | test |
| Shutdown event signaled by elevated setup across sessions | test | test | test | test |
| `WinHttpGetIEProxyConfigForCurrentUser` / PAC for `https://host:port/` pseudo-URL; `socks=` semantics | test | test | test | test |
| `EnableLinkedConnections` mirrors WebDAV drive / Dokany mount | n/a | test | test | test |
| Dokany `CURRENT_SESSION` invisible to elevated token | n/a | test | test | test |
| `_LabelFromReg` for `##localhost@port#DavWWWRoot#…` | test | test | test | test |
| HKCU `Applications\Explorer.exe\Drives` icon | test | test | test | test |
| `CRED_PERSIST_LOCAL_MACHINE` on Home SKUs → fallback path taken | Home: test | n/a | test | test |
| Credential blob 512 vs 2560 bytes | test | test | — | — |
| Owner check rejects pipe squatted by another user | test | test | test | test |
| PMv2 + generated dialogs at 100/150/200% mixed monitors | — | — | test | test |
| x86 shell DLL appears in 32-bit file dialogs on x64/ARM64 | — | test | test | test |

### 13.4 Platform facts used (sources)

| Fact | Source |
|---|---|
| `CREDENTIAL`/Cred* APIs from XP; domain password blobs readable only by auth packages; LOCAL_MACHINE/ENTERPRISE unsupported on XP Home and Vista Home/Starter; blob max 5*512 (current docs) | [CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw) |
| `SetThreadUILanguage` on XP accepts only 0 and changes the thread locale | [SetThreadUILanguage](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-setthreaduilanguage) |
| WNet drives tracked per logon session LUID; LocalSystem mapping visible to all sessions (XP/2003 note) | [WNetAddConnection2](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w) |
| Linked logon sessions under UAC; `EnableLinkedConnections` | [Microsoft Learn troubleshooting article](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command) |
| `DOKAN_OPTION_CURRENT_SESSION` = mount on current session only; elevated visibility reports | [dokan.h](https://github.com/dokan-dev/dokany/blob/master/dokan/dokan.h), [Cryptomator forum](https://community.cryptomator.org/t/drive-not-mounted-for-uac-admin/3119) |
| `GetNamedPipeServerProcessId` Vista+ | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid) |
| `dpiAware` (Vista+) vs `dpiAwareness` (10 1607+), manifest preferred | [Setting the default DPI awareness](https://learn.microsoft.com/en-us/windows/win32/hidpi/setting-the-default-dpi-awareness-for-a-process) |
| `DWMWA_USE_IMMERSIVE_DARK_MODE` = 20, documented from Windows 11 22000 | [DWMWINDOWATTRIBUTE](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute) |
| `MiniDumpWriteDump`: prefer separate process, else dedicated thread | [MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) |
| Machine-wide `DriveIcons\<letter>\DefaultIcon` | [Customizing Icons](https://msdn2.microsoft.com/en-us/library/bb776856(v=vs.85)) |
| Per-user drive icon key (community) | [Elevenforum guide](https://www.elevenforum.com/t/change-icon-of-drive-in-windows-11.16591/) |
| Folder Shortcut class `{0AFACED1-E828-11D1-9187-B532F1E9575D}` (Windows 2000–11); Network locations = folder with `desktop.ini` + `target.lnk`, read-only attribute required | [winshl-kb](https://winshl-kb.readthedocs.io/en/latest/sources/shell-folders/0afaced1-e828-11d1-9187-b532f1e9575d.html), [Elevenforum thread](https://www.elevenforum.com/t/is-there-a-way-to-use-a-command-to-add-a-network-location-not-drive.48885/latest), [Wikipedia: Shortcut (computing)](https://en.wikipedia.org/wiki/Shortcut_(computing)) |
| CLDR cardinal plural rules (es/it/fr/pt `many` for multiples of 1 000 000) | [Unicode CLDR language plural rules](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html) |

APIs stated as XP+ without a link above (`CredGetSessionTypes`, `CryptProtectData`, `WTSRegisterSessionNotification`,
`ProcessIdToSessionId`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `SHGetFolderPathW`,
`Shell_NotifyIconW` with `NIF_INFO`, `WriteConsoleW`, `GetUserDefaultUILanguage`, `GetNumberFormatW`,
`NotifyAddrChange`, `ReportEventW`) are standard Windows 2000/XP APIs per their SDK reference pages; Vista+ items
(`PIPE_REJECT_REMOTE_CLIENTS`, `TokenElevationType`, `TokenLinkedToken`, `EventRegister`,
`SERVICE_CONTROL_PRESHUTDOWN`, `LoadIconWithScaleDown`) are resolved at runtime or used only when the OS version
allows.

---

## Changelog: integrated decisions

Applied on 2026-10-24 from `decisions.md` and `00-integration-review.md`.

- **Decisions:** D3 (four binaries, `shelldrive-shellext.dll`), D5 (ARM32 row), D6 (service on by default for
  per-machine installs, idle mode), D7 (live OpenSSH/PuTTY sources, copy on match, any mismatch blocks), D8 (plain
  entries), D9 (`write_mode`, default `through`), D10 (`identity_probe`), D11 (service-hosted WebDAV, `system` /
  `attach` modes, lab spike), D12 (`symlinks = follow | hide`), D14 (Network locations, 8.7), D16 (UpdateHostKeys
  UX, 5.6), D17 (no agents for the service), D18 (connection pool and 2FA rule), D19 (`channels`), D20 (HTTP CONNECT
  / SOCKS5 per leg, system proxy opt-in, proxy secrets in Credential Manager, no ProxyCommand), D22
  (`offline_hint_over_mb`), D23 (`fs_name`), D24 (`ENABLELINKEDCONNECTIONS` default 0), D25 (template overrides),
  D26 (full CLDR plurals, `many` for es/fr/it/pt-BR), D27 (sparse-package modern menu, conditional on the
  certificate), D4/D28 (flavour note in 1.10), A1/A2/A3/A4/A5 wording reflected where 03 is affected.
- **Conflict resolutions:** C1, C2, C3 (shutdown event, setup no longer uses agent pipes), C4, C5, C6 (superseded by
  D6), C7 (CLI commands, aliases, hidden installer hooks, IPC methods), C8 (update settings in `settings.ini`,
  single policy key), C9, C10, C11, C12 (unchanged, 03 paths), C19 (known_hosts I/O owned by `sd_known_hosts`),
  C20, C21, C22, C25, C26, C27 (superseded by D11), C28, C29, C30, C33, C39, C41, C42, C43, C44, C45, C46 (profile
  schema table, global memory budget, disk cache default 0); review §4 (`sd_mount`, threading, failed-mount
  behaviour, error table, `qps` pseudo-locale).
- **Removed open questions:** former 13.2 items 1–5 and 7.
- Final reconciliation 2026-10-24: global WebDAV modes gain `link` (02 §7.7 mechanism B; `webdav_global_mode =
  auto|system|link|attach`, 1.3, 1.8, 3.4, 12.2); system-proxy resolution moved to `sd_ssh` (3.8, 01 §5.2); schema
  adds `proxy.proxy_fallback_direct`, names the consumers' fields (`legacy_policy`, `sd_proxy_cfg.auth`,
  `sd_sftp_options.connections`, `SD_SFTP_OPT_IDENTITY_EXEC`, `volume_fs_name`, `write_mode`); installer hooks are
  called through `shelldrive-host.exe` (GUI subsystem) with 03's names, adopted by 04 (6.1); sparse-package
  registration aligned with 04 §10.1 (per-user agent registration on per-machine installs, 8.6); 12.1/12.2 now
  record where 01/02 meet each requirement (known_hosts D7, UpdateHostKeys event, pool, exec probe, proxies,
  `service_access`).
