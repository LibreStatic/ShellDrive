# 03 — Applications and platform integration

Status: proposed design, revised to apply `decisions.md` (D1–D39), the conflict resolutions of
`00-integration-review.md` and the threat model's recommended changes (`05-threat-model.md` §8, `TM-Rxx`, as
adjusted by D33–D39; see the changelog at the end). Where this document and `decisions.md` disagree,
`decisions.md` wins. Threat ids (`T-xx`) and security tests (`TST-xx`) refer to 05. Scope: everything around the SSH/SFTP/crypto core (`sd_crypto`, `sd_ssh`, `sd_sftp`,
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
  session-local mutex `Local\com.librestatic.shelldrive.agent.<SID>`. `Local\` objects are per session on XP and later, so the
  mutex gives the per-session uniqueness; the SID in the name guards against the rare case of a different user
  in the same session (`runas` in the same desktop). The mutex, the ready event and the snapshot section are
  created with the explicit owner and DACL of 2.2 "Named kernel objects" (TM-R26, T-47); a pre-existing object with
  a foreign owner is treated as squatting (log, run without the object, tray warning `named_object_squatted`).
  The pipe's `FILE_FLAG_FIRST_PIPE_INSTANCE` (2.2) remains the authoritative uniqueness check, so a squatted mutex
  costs only the double-start optimization.
- **Stale mappings at start (TM-R17 d):** before binding its WebDAV listener the agent enumerates the connections of
  its logon session (`WNetOpenEnum(RESOURCE_CONNECTED)`) and cancels every `\\localhost@<port>\DavWWWRoot\s-…`
  mapping it did not create in this process (they belong to a dead agent; their port may now be anyone's), then
  reconciles labels, icons and Network location entries (1.11).
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
  event `Local\com.librestatic.shelldrive.agent.ready.<SID>` for up to 10 s).
- **Stop:** when the logon session ends (`WM_QUERYENDSESSION`/`WM_ENDSESSION` on a hidden top-level window; a
  message-only window does not receive these broadcasts), on `agent.shutdown` IPC (used by `shelldrive agent stop`),
  when its **shutdown event** is signaled (below; used by setup and the updater), or after it has been idle (no
  mounts, no connected clients) for 5 minutes when it was started on demand. An agent started with `--logon` stays
  resident so that tray state and autostart remounts work.
- **Shutdown event (C3):** at start each agent creates the manual-reset event
  `Global\com.librestatic.shelldrive.agent.shutdown.<UserSidString>.<SessionId>` with the DACL
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

**M5 decisions (part 1, implemented; details in `docs/dev/m5-notes.md`).**

- One core, `svc_run`, runs under the SCM (`shelldrive-host.exe service`) and in the console
  (`service-debug`, Ctrl+C stops it). The SCM handler accepts stop, shutdown and pre-shutdown, logs power and session
  changes without acting on them, and reports `SERVICE_RUNNING` once the control pipe listens.
- The service logs to `<machine root>\logs\service.log`. Its console and SCM text is localized in the `svc` domain
  (03 §9.1); its log lines and codes stay English.
- Global mounts are Dokany only in this part. Startup creates the machine folders with the DACLs of 3.2 when they
  are missing and refuses the whole tree (idle service) when a folder is a reparse point. Existing folders are not
  re-ACLed and their owner is not checked yet (left, 3.2).
- A `scope = service` profile is loaded only when it validates: a user is named, `auth.agent` is not `pageant` or
  `openssh` (D17), `kbdint` is not offered, no jump hosts or proxies (not in this part), no WebDAV backend (D11), and
  every `service_access` entry resolves. Other machine profiles load without a warning.

### 1.4 The UI (`shelldrive-ui.exe`)

- One instance per (user, session): mutex `Local\com.librestatic.shelldrive.ui.<SID>` (explicit DACL as in 2.2, TM-R26); a second
  launch forwards its command line to the first via `WM_COPYDATA` to a window with a private class name and exits.
- **`WM_COPYDATA` validation (TM-R26, T-48):** the receiving window takes the sender from `wParam`
  (`GetWindowThreadProcessId` → `OpenProcess(PROCESS_QUERY_INFORMATION` on XP, `PROCESS_QUERY_LIMITED_INFORMATION`
  on Vista+) → `OpenProcessToken`) and accepts the message only if the sender's token user SID equals ours and its
  integrity level is ≥ ours (Vista+). The payload is a versioned, length-checked UTF-16 argument vector; only the
  documented verbs of `--action` (mount, mount-file, unmount, reconnect, show) and the plain "show main window"
  request are accepted, each with its fixed argument shape (profile id = 32 hex, drive `X:` or an absolute path);
  everything else is dropped and logged at warn.
- **Agent watch (TM-R17 c, e):** the UI holds a `SYNCHRONIZE` handle to its agent's process (the server PID from
  `GetNamedPipeServerProcessId` on Vista+, from the `server_pid` field of the `hello` reply on XP, whose process
  token must carry our SID). When the process ends without a prior `agent.shutdown`/shutdown-event sequence, the UI
  cancels every mapping of that agent (`\\localhost@<port>` targets it learned from `list`) with
  `WNetCancelConnection2W(…, TRUE)` and notifies "ShellDrive stopped unexpectedly. Its drives were disconnected to
  protect your files." Long-running CLI commands (`mount --wait`, `logs --follow`) do the same. Elevated-view
  mappings live in the elevated logon session, which the unelevated UI cannot touch; they are covered by the
  elevated watcher of 1.7.2.
- Modes: `--tray` (tray icon, main window hidden; launched by `HKCU\...\Run\ShellDriveTray` if enabled),
  default (open main window), `--prompt-host` (started by the agent when a prompt needs a UI and none is
  connected; shows only the prompt then stays as a tray if the user's setting says so), `--action <verb> <target>`
  (used by the shell extension: unmount, reconnect, mount, show), `--elevated-admin` (re-launched with `runas` to
  answer service prompts or edit machine profiles; exits when done).
- **A prompt host never starts an agent (M3, 2.5 step 3).** `--prompt-host` connects to the agent of its session
  without starting one. It exits when the agent cannot be reached (after the connect timeout) and when its connection
  to the agent ends, because the agent that launched it is then gone. Without this rule a stray prompt host would start
  the default-instance agent of the user.
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
  (`Local\com.librestatic.shelldrive.state.<SID>`, 8.2) and performs actions by launching `shelldrive-ui.exe --action ...`. It does
  not speak the IPC protocol and does not start the agent itself (the UI does).
- **The snapshot is untrusted input to Explorer (TM-R26, T-47, T-60).** The DLL maps the section only if its owner
  (`GetSecurityInfo(SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)`) is the current
  user's SID and its mandatory label is absent (= medium) or ≥ medium; otherwise it behaves as if the section did not
  exist. Every offset and length in the snapshot (and in `menu.cache`, 8.2) is bounds-checked against the mapped
  size before use, string slots are length-limited and need not be NUL-terminated, and a seqlock retry is bounded
  (3 tries, then "no data"). AppContainer processes cannot squat it: their named objects are redirected to a
  per-package namespace; low-integrity processes can create objects in `Local\` and are caught by the label check.
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
  because of that wart. **Elevated watcher (TM-R17 e, T-40):** after mapping, the elevated CLI starts a detached
  copy of itself in the hidden mode `--watch-elevated-view <agent pid> <letter>` (not in `help`, `DETACHED_PROCESS`,
  elevated token inherited) that holds a `SYNCHRONIZE` handle to the agent process and polls the mount
  through `list` every 30 s; when the agent exits or the mount is gone it cancels the elevated mapping with
  `WNetCancelConnection2W(…, TRUE)` and exits. A stale elevated mapping therefore never points at a port that another
  user could bind.
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
- **Volumes without ACLs (TM-R29, T-55, T-59):** at start the host checks `GetVolumeInformationW` flags of the
  volumes holding `data\` and the cache directory. Without `FILE_PERSISTENT_ACLS` (FAT, exFAT, most sticks) the disk
  cache is refused (`cache.disk` treated as 0, `warning disk_cache_refused`), and the UI shows once per medium
  (remembered by volume serial in `data\state\portable.ini`): "This drive has no file permissions. Anyone who gets
  this drive can read your profile list and change trusted host keys." The same disk-cache rule applies to an
  installed copy whose `%LOCALAPPDATA%` cache directory sits on such a volume.

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
| Agent control pipe | agent | `\\.\pipe\com.librestatic.shelldrive.agent.<UserSidString>.<SessionId>` |
| Service control pipe | service | `\\.\pipe\com.librestatic.shelldrive.service` |
| Agent ready event | agent | `Local\com.librestatic.shelldrive.agent.ready.<UserSidString>` |
| Agent shutdown event (manual reset, 1.2) | agent | `Global\com.librestatic.shelldrive.agent.shutdown.<UserSidString>.<SessionId>` |
| State snapshot (read-only shared memory) | agent | `Local\com.librestatic.shelldrive.state.<UserSidString>` |
| UI instance mutex | UI | `Local\com.librestatic.shelldrive.ui.<UserSidString>` (held while a UI runs; the agent starts a UI only when it is free) |
| UI forwarding | UI | `WM_COPYDATA` to window class `com.librestatic.shelldrive.ui.<UserSidString>` (same session only) |

`<UserSidString>` from `ConvertSidToStringSidW` (XP+), session ID from `ProcessIdToSessionId` (XP+).

**Object scope rule (M3).** D45 fixes the name prefix `com.librestatic.shelldrive.` but not the namespace. Objects
that exist once per logon session use `Local\`: the agent mutex, the agent ready event, the UI mutex and the state
section. A second logon session of the same user therefore has its own instances. Objects that are machine-wide use
`Global\`; the agent shutdown event is the only one, and it carries the session id in its name so that the installer
and the service can signal one session's agent. `sd_ipc_object_name` produces these names; the state section is
created and opened with `sd_ipc_state_create` and `sd_ipc_state_open` (file mapping, 8.2.1).


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
- **Refused client tokens (both servers, T-45, T-46):** `OpenThreadToken` failure, an anonymous or
  identification-level impersonation that cannot be opened, an integrity level below medium (Vista+,
  `TokenIntegrityLevel`) and an AppContainer token (`TokenIsAppContainer`, Windows 8+, resolved at runtime) are
  refused at `hello` with `access_denied` and the instance is closed. Deny is the default on every error path.
- **Service pipe quotas (TM-R25, T-46).** The service pipe is pre-authentication SYSTEM attack surface for every
  interactive user, so it is rationed:
  - At most **4 concurrent instances per client user SID** (checked at `hello`; the 5th is closed with
    `too_many_connections`), and **2 of the 32 instances are reserved** for elevated administrators: once 30
    instances are in use, a new client that is not an elevated admin is closed at `hello`. The listener always keeps
    one pending instance so that an admin can reach `hello`.
  - Clients that are not elevated admins: request cap **64 KiB** (instead of 1 MiB), at most 10 requests per second
    per connection (excess requests get `rate_limited`), idle timeout **60 s** for non-subscribed connections, and
    at most one subscription per connection. A connection that sends malformed JSON is closed.
  - JSON parsing (`sd_json`) and method dispatch for the service are fuzz targets (TST-02).
- **What non-admins may see on the service pipe (TM-R25):** `list` returns, for global mounts whose
  `service_access` admits the caller, only `letter`, `label` and `state`; for every other global mount only its
  letter in `reserved_letters` (the letter is visible system-wide anyway and the agent needs it to avoid conflicts,
  2.6). Host, user, remote path, proxy legs, algorithms and last error are returned only to elevated admins.
  `status` details, `log.tail`, `diag.collect` and the topics `prompt`, `log` and `hostkeys` are elevated-admin
  only (`access_denied` otherwise). Non-admins may subscribe to `mount` and `warning` (filtered the same way) and to
  `attention` (2.6 rule 3).
- **Named kernel objects (TM-R26, T-47).** The agent creates `Local\com.librestatic.shelldrive.agent.<SID>` (mutex),
  `Local\com.librestatic.shelldrive.agent.ready.<SID>` (event) and `Local\com.librestatic.shelldrive.state.<SID>` (section), and the UI creates
  `Local\com.librestatic.shelldrive.ui.<SID>`, each with `O:<UserSID>D:P(A;;GA;;;<UserSID>)(A;;GA;;;SY)` and, on Vista+, the
  explicit label `S:(ML;;NW;;;ME)` (XP has no labels). Readers open the section with `FILE_MAP_READ` only. If `Create*W` reports `ERROR_ALREADY_EXISTS`, the creator reads the owner: our SID means a second
  instance of ours (normal); any other owner, or a label below medium, is squatting: the agent logs an error, runs
  without that object (no snapshot: the shell extension shows no drive items; no ready event: clients fall back to
  polling the pipe for 10 s) and the UI shows the warning "Another program is interfering with ShellDrive in this
  session. Drive menus in Explorer are turned off." Readers (CLI/UI waiting on the ready event, the shell DLL) apply
  the same owner and label checks before trusting an object.
- **Shared server-verification helper:** the client-side checks below are one function, `sd_pipe_verify_server(h,
  expected_owner_sid, flags)` in `sd_platform`, which 01 §6.5 also uses for the OpenSSH agent pipe (TM-R08: owner
  `S-1-5-18` for the default `openssh-ssh-agent` pipe, or our SID for a user pipe named by `SSH_AUTH_SOCK`).

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

Every request is `{"type":"req","id":n,"method":...,"params":{...}}`. Unknown request fields are ignored; unknown reply
fields and events are ignored by clients (2.3). Errors are `{"code","detail","exit_code"}` with the codes of 6.2 and the
IPC-only codes of the table below. `busy` (`SD_E_BUSY`) is exit 8 (6.2) and carries the IPC codes `too_many_connections`
and `rate_limited`; exit 10 is `conflict`, never busy. Unknown methods answer `usage` (exit 2). Methods marked **M4/M5** are not
implemented in M3 and are not listed in `hello` `features` (2.8).

| Method | Agent | Service | Access and notes |
|---|---|---|---|
| `hello` | x | x | version negotiation; the reply carries `features` (2.8) |
| `subscribe {topics}` | x | x | topic names must match `[a-z0-9._-]`, at most 23 bytes; invalid names are dropped from the reply, valid unknown names are kept. `prompt` needs cap `prompts.ui` to receive `prompt.request` (2.5). On the service `prompt`, `log` and `hostkeys` need an elevated admin (2.2, TM-R25) |
| `mount {profile \| adhoc:{...}, target?, backend?, prompt_mode?}` | x | x (admin, M5) | returns `mount_id` at once; completion through `mount.state`. `wait` is not implemented |
| `unmount {mount_id \| target \| profile \| all, force?}` | x | x (admin, M5) | `force` (M3, first unmount of the mount): the write-behind drain gets no budget, data still queued is reported as `write_failed` (02 §4.4). Test mounts (`profile.test`) are never unmounted |
| `list` | x | x | `mounts` (write_mount_json) and `warnings`: the recent warning codes of this agent, oldest first, at most 32, `{code, mount_id?}`. Service: filtered for non-admins (2.2) |
| `status {mount_id \| target, stats?}` | x | x (admin, M5) | the list object of the mount, `last_error {code, detail}` when failed or offline, and `proxy_legs` (`[{hop, kind, host, port}]`, no credentials). `stats: true` (M3) adds `stats`: `session` (srtt, rttvar, rx/tx rates and totals, inflight, queued, channels, generation, reconnect attempts), `pool` (`ready`, `wanted`, `members[]` with one entry per SFTP connection), `cache` (hits, misses, bytes, write_failed, `write_behind_bytes`, reconnects). Pool limits are still M4 |
| `refresh {mount_id \| target, path}` | x | x (admin, M5) | M3 (agent): drops the attribute and listing caches under `path` (`""` or `"/"` = the whole mount). `not_mounted` (exit 3) before MOUNTED |
| `profile.test {profile_id \| adhoc}` | x | x (admin, M5) | M3 (agent): connect, authenticate and realpath of `remote_path`, no drive, no vfs. The prompts go through the normal broker. The reply is deferred until the test ends (`sd_ipc_defer`). Result: `{profile, host, port, user, remote_path, hostkey_fingerprint, server_version, algorithms{kex, hostkey, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c}, legacy, hops}` |
| `mount.attach_info {mount_id \| target}` | x | x (M5) | M3 (agent): `backend`, `state`, `mounted` and, for WebDAV, `webdav {host, port, unc_root, xp_url}` with the loopback port and the share root only (`\\localhost@<port>\DavWWWRoot`). The export token (`s-<token>`) is never returned; never a credential |
| `cache.clear {profile_id \| mount_id \| target \| all, force?}` | x | x (admin, M5) | M3 (agent): drops the memory blocks and the disk-tier files of the matching mounts. While write-behind data is queued on one of them the whole request is refused with `write_behind_pending` (busy, exit 8) unless `force`; queued data is never dropped by a clear |
| `config.reload {scope?}` | x (user) | x (admin, M5) | reloads `settings.ini` and counts the profiles. Reply `{profiles:{loaded, errors:[]}, settings: "reloaded"\|"unchanged", restart_required:[]}`. `scope: "machine"` on the agent is `unsupported`. `restart_required` is empty in M3 |
| `prompt.answer {prompt_id, action, responses?, save?, save_comment?}` | x | x (admin, elevated, M5) | `action` accept, once, answer, reject or cancel. The first accepted answer wins; a second answer, or one for a prompt that is not open, is `not_found` (2.5) |
| `prompt.list` | x | x (admin, M5) | `{prompts:[{prompt_id, mount_id, profile_id, kind, queued, deadline_ms}]}`, `deadline_ms` is the time left |
| `log.tail {lines?, cursor?, level?, component?, follow?}` | x | x (admin, M5) | the ring of 4096 records (2.4.1). `follow: true` is `unsupported` in M3 (the `log` topic is M4) |
| `selftest` | x | x | `{healthy, checks:[{name, result: pass\|fail\|skip, code?, detail}]}`; the CLI maps `healthy: false` to exit 17 |
| `diag.collect` | x | x (admin, M5) | M4 (10.5) |
| `agent.shutdown {unmount?}` | x | — | stops the agent; every mount is unmounted (1.2) |
| `hostkey.announced.list` | x | x (admin, M5) | `{announcements:[{id, mount_id, host, lookup_name, hop, add, remove}]}` |
| `hostkey.announced.accept {id, add_only}` | x | x (admin, elevated, M5) | applies an announcement (5.6). The argument shape is `{id, add_only}` (`add_only: true` skips the removals) |
| `update.check`, `update.apply` | x | — | M4 (the updater engine, 04 §9). Settings shows the update group disabled while `update.check` is missing from `features` |
| `secret.set`, `secret.delete` | — | x (admin, elevated) | M5 (4.5): in M3 machine passwords are CLI-only |

Not on the pipe, by design: profile create/edit/delete, settings and overrides (direct `sd_config` writes under
`sd_config_lock`, 3.6), host-key store list, import and remove (direct `sd_known_hosts`, 5.0), and `hostkey.trust`
(dropped: machine store writes are direct and elevated).

Events (`{"type":"evt","event":<name>,"data":{...}}`, after `subscribe`; the topic is in brackets):

| Event | Topic | Data | When |
|---|---|---|---|
| `mount.state` | [mount] | `mount_id, state, target, error?{code, detail, exit_code, host?, stored_type?, stored_fp?, offered_type?, offered_fp?, store_path?, store_line?}, connection{...}` | every mount state change and connection sub-state change (connecting, mounted, offline, reconnect attempts) |
| `prompt.request` | [prompt] | `prompt_id, mount_id, profile_id, profile_name, kind, host, port, user, hop, hops, via_host?, is_reconnect, hostkey_just_accepted, can_save, queued, deadline_ms`, and the kind-specific objects of 2.5 | a prompt is routed (2.5); again, with `queued: true`, when a UI subscribes and drains the queue |
| `prompt.closed` | [prompt] (and the initiator) | `prompt_id, mount_id, reason: answered\|cancelled\|timeout\|superseded, answered_by?: cli\|ui` | the prompt leaves the open or queued state (2.5); once per recipient |
| `warning` | [warning], and [mount] (proto 1) | `code, mount_id?, data` (codes of 2.4 and 7.6) | a warning is raised. The copy on [mount] stays through proto 1 (2.8) |
| `hostkeys.announced` | [hostkeys], and [mount] (proto 1) | as 5.6 | an UpdateHostKeys announcement is ready for review |
| `attention` | [attention] (service) | `{count}` | 2.6 rule 3 |
| `config.changed` | — (every client that completed hello) | `{what: "settings" \| "profiles", ids?}` | M3: the profiles folder or `settings.ini` changed. One event per debounced batch (500 ms of quiet). `ids` (profiles only) are the profile ids of the changed files that still exist. Nothing is reloaded in flight: clients call `config.reload` |
| `agent.stopping` | — (every client that completed hello) | `{reason: "request" \| "event" \| "idle"}` | M3: the shutdown sequence starts |
| `log`, `update.*` | — | — | M4 (`follow`, the updater) |

`write_failed` (C45) is raised when data acknowledged to an application under write-behind could not be written
(02 §4.4); it is always delivered, cannot be disabled and is mirrored in the event list (7.7).

#### 2.4.1 Log ring and `log.tail` cursor

The agent keeps the last 4096 log records in memory (about 4.5 MiB at most), fed from an `sd_log` sink, so each record is
already formatted and redacted (10.1). A record is `{seq, time, level, component, mount_id?, text}`; `text` is at most 1 KiB.
The cursor is `"<pid hex>.<boot tick hex>.<seq dec>"`. Without a cursor `log.tail` returns the last `lines` matching records.
With a cursor it returns the records after `seq`, and `reset: true` with `dropped` = the number of records lost when the cursor is
older than the ring, or when it names another agent process (a foreign or malformed cursor starts at the oldest record). The reply
cursor is the position to resume from.

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
  "can_save":false,"hostkey_just_accepted":false,"deadline_ms":120000}}
```

Prompt text that comes from the server (`kbdint` texts, banners) is displayed verbatim, marked visually as coming
from the server, and sanitized: control characters stripped, **bidi controls (U+202A–U+202E, U+2066–U+2069,
U+200E, U+200F) and zero-width characters (U+200B–U+200D, U+2060, U+FEFF) removed** (TM-R09, T-18), length capped
at 2 KiB per field. Host names, user names and profile names shown in any prompt or notification get the same
bidi/zero-width stripping. The hop's host (and "Jump host N of M") is rendered by our own label **outside** the
server-text box, so server text can never pose as the host line.

**Fresh trust (TM-R05, T-10).** If the host key of any hop of the current connection was accepted by TOFU or
"Connect once" during this connection (including after "remove old key and reconnect", 5.4), the connection is
`hostkey_just_accepted`. For such a connection `sd_mount` does **not** answer secrets that would be sent through the freshly
trusted hop from Credential Manager, the DPAPI store or the reconnect cache: `password` and `kbdint` prompts of that
hop and of every later hop, and `proxy_password` prompts of legs tunneled through it (`sd_ssh` applies the same rule
to its reconnect cache, 12.1). Key passphrases may still be filled from the store: they decrypt a local key and
never reach the server. The prompt is shown to the user with `hostkey_just_accepted: true`,
and the dialog adds "You just accepted this server's identity. ShellDrive did not send your saved password
automatically." with the saved value not pre-filled. Pool members are not opened for a `hostkey_just_accepted` connection
(the pool stays at 1 until the next connection, which then verifies the stored key normally). The flag ends with the
connection: a later reconnect that matches the now stored key behaves normally.

**Agent routing (M3).** The agent keeps a record for every prompt from the moment sd_mount raises it until its
`prompt.closed`. Each record is routed as follows:

1. The initiator, when it is still connected and declared `prompts.console` or `prompts.ui` in `hello` (a CLI on an
   interactive console with `--prompt auto|console`). Delivery is `sd_ipc_send_to`. The CLI reads input with `ReadConsoleW`
   and echo disabled via `SetConsoleMode`.
2. Every client subscribed to `prompt` with cap `prompts.ui`, except the initiator of step 1, so that no client receives
   the same event twice. The broadcast returns `delivered`, the number of recipients queued.
3. If `delivered` is 0 and no UI runs (the UI mutex `Local\com.librestatic.shelldrive.ui.<SID>` is not held), the agent
   starts `shelldrive-ui.exe --prompt-host` from its own directory with its own token, at most once per 30 s. The prompt
   host connects to this agent only and never starts one (1.4). Test builds of the agent start no UI unless
   `SHELLDRIVE_TEST_UI_LAUNCH=1` (tests/apps set it to 0). Session
   lock state is not probed in M3 (a UI started while locked waits for its first subscription). A missing executable
   is not an error.
4. The prompt is queued. The queue holds 16 prompts; a 17th evicts the oldest queued one, which is rejected with
   `prompt.closed` reason `superseded` and fails its mount with `prompt_unavailable`.

When a client subscribes to `prompt` with `prompts.ui`, every queued prompt is sent to it first, oldest first, with
`queued: true` and the remaining `deadline_ms`; each becomes open. No prompt is sent twice to one client. A
`prompt_mode = none` mount (CLI `--prompt none`, scripts, clients without a prompt capability) fails at once with
`prompt_required` (exit 4), or `host_key_unknown` (exit 5) for a host key.

Accounting: `delivered` counts queued sends. A recipient that disconnects after it was counted but before the pipe
thread writes never answers, and the deadline covers it. Enqueueing never blocks the agent.

**Deadlines.** 120 000 ms for user-initiated operations and 600 000 ms for prompts raised by a reconnect (1.7.4). The
deadline is an absolute tick kept by the agent; the control thread checks it once a second, so an expired prompt is
rejected within about 1 s. Clients receive the remaining time as `deadline_ms`. There is no per-profile override in M3.

**Answers and closing.** The first accepted `prompt.answer` wins. The agent sets the close reason before it hands the
answer to sd_mount, so `prompt.closed` carries the right reason:

| Reason | Set when | Mount outcome | `answered_by` |
|---|---|---|---|
| `answered` | a `prompt.answer` with action accept, once, answer or reject was accepted (a rejection is an answer) | continues, or fails with the sd_mount error (`host_key_rejected`, `prompt_required`, ...) | `cli` or `ui`, from the hello `client` |
| `cancelled` | `prompt.answer` with action cancel; the mount is unmounted; the initiator disconnected with no prompt-capable UI subscribed (below); a prompt the agent did not answer was closed by sd_mount | exit 13 (`cancelled`) | — |
| `timeout` | the deadline passed | `prompt_unavailable` (exit 4) | — |
| `superseded` | evicted from the queue (16 entries) | `prompt_unavailable` | — |

Clients treat an unknown reason as `cancelled`. `prompt.closed` goes to the initiator once and to the UI subscribers
of `prompt` except the initiator.

**Initiator disconnect (M3 lead decision, 2026-10-27).** When the initiator of a mount disconnects, its prompts are cancelled
only if no client with `prompts.ui` is subscribed to `prompt`. Otherwise the mount keeps routing its prompts to that UI,
so a tray restart does not kill a mount.

**ProxyJump:** each hop prompts separately; the prompt carries `hop`/`hops` and the hop's host so the dialog says
"Jump host 1 of 2: bastion.example.org". For hop i ≥ 1 (and the target behind jump hosts) prompts and the host key
dialog also say "Reached through jump host <hop i−1 host>" (TM-R03, T-19), because that hop chose where the
connection really went.

### 2.6 Service prompts and service/agent cooperation

The service cannot show UI. Rules:

1. **Profiles with `scope = service` must be non-interactive capable**, validated when saved and at service start:
   the host key of every hop is in the machine known_hosts, and the authentication method is publickey with a
   key stored in the service secret store or an unencrypted key file readable only by SYSTEM/Administrators, or
   password stored in the service secret store. **Key files are read safely (TM-R27, T-51):** the service accepts
   only paths under `%ProgramData%\LibreStatic\ShellDrive\service\` or paths whose every component is owned by SYSTEM or
   Administrators and not writable by others; it opens the file with `FILE_FLAG_OPEN_REPARSE_POINT` and refuses it if
   the file or any path component is a reparse point (each component is opened the same way); owner and DACL are
   checked **on the opened handle** (`GetSecurityInfo(SE_FILE_OBJECT…)` via the handle) and the bytes are read from
   that same handle, so there is no check-then-open gap. The service never reads HKCU, user profile paths or paths
   with `~\` or user environment variables (only `%ProgramData%`, `%ProgramFiles%`, `%SystemRoot%` expand in machine
   profiles). The same rules apply to `certificate` files and to machine profiles, `known_hosts` and `settings.ini`
   it loads. `kbdint` and agent (Pageant/OpenSSH agent) are not allowed for
   service profiles (no agent exists pre-logon; D17). Proxy legs need either no authentication, Negotiate/NTLM
   (machine account, via SSPI) or a proxy secret in the service secret store; `proxy = system` reads the WinHTTP
   machine configuration (3.8). `backend = webdav` is accepted (D11, 1.3) but the UI states that the drive appears
   only after sign-in where the OS uses `attach` mode. A profile failing validation is refused with a precise error.
2. **Trust on first use does not exist for the service.** Admins pin keys when creating the profile: the UI/CLI
   (elevated) calls `shelldrive hostkey add --machine --from-server host[:port]`, which connects through the
   service, shows the fingerprint and asks for confirmation (optionally `--expect SHA256:...` for scripted
   deployment, where a mismatch fails).
3. **If a prompt is nevertheless needed at runtime** (password changed on the server, new hop added), the service
   fails the mount, writes an Event Log warning (10.3) and publishes a `prompt.request` to service-pipe subscribers
   of the `prompt` topic, which only elevated admins may hold (TM-R25). Only **elevated** admin clients may answer
   (2.2). The agent's UI in each session subscribes to the service pipe read-only, to the content-free `attention`
   topic (a count of mounts waiting for an administrator); if the logged-on user is an administrator (checked via
   the linked token, `GetTokenInformation(TokenLinkedToken)`, Vista+; group membership on XP), the tray shows "A
   global ShellDrive drive needs attention". Clicking it relaunches `shelldrive-ui.exe --elevated-admin` with the UAC prompt, which then
   answers the service prompt. Non-elevated answers are rejected on purpose: otherwise any medium-integrity program
   could inject trust into the SYSTEM-level mount.
4. We do not use `WTSSendMessage` to pop message boxes into user sessions (noisy, no input, wrong session
   heuristics); notifications go through the tray of admin users and the Event Log.

Agent ↔ service cooperation is deliberately thin:

- The agent connects to the service pipe (when present) to list global mounts and their letters (for mounts the
  user is not in `service_access` for, only the letter, `reserved_letters`, 2.2). It refuses to
  mount a per-user drive on a letter used by a global mount (the per-session device map would shadow the global
  letter only for that user, which is confusing). Auto letter selection skips them.
- The agent does not proxy commands to the service; elevated clients talk to the service directly. The only
  agent → service call besides listing is `mount.attach_info` for global WebDAV drives in `attach` mode (1.3),
  made with the agent's own (user) identity.
- The service never starts agents (the Run key does). Rejected alternative: service launches agents with
  `WTSQueryUserToken` + `CreateProcessAsUserW` — makes the service mandatory and puts user-session lifecycle into a
  SYSTEM process for no gain.

**M5 decisions (part 1, implemented; details in `docs/dev/m5-notes.md`).**

- Admin methods (`mount`, `unmount`, `secret.set`, `secret.delete`, `prompt.list`, `prompt.answer`, `config.reload`,
  and `status` details) need an elevated administrator (`sd_ipc_client_is_admin`). Topics `prompt`, `log` and
  `hostkeys` are refused to other clients at subscribe time (`access_denied`, the whole request). `list` and `status`
  answer every client, filtered by `service_access` (2.2): the letter for everyone, state for members and admins, the
  rest in `reserved_letters`.
- Routing of a service prompt (2.6 rule 3): a password or passphrase prompt goes to an elevated admin that subscribed
  to `prompt` with `prompts.ui`, and is rejected after 120 s without an answer. With no such admin the mount fails
  with `prompt_unavailable`. A host-key prompt is never routed: the mount fails with `host_key_unknown` (2.6 rule 2).
- A service mount never saves a secret it was given. Service secrets are DPAPI files under `service\secrets\` (4.5),
  written through `sd_secret` with the service scope; the user scope is never read by the service.
- The volume descriptor of a global mount (02 §6.4) encodes `service_access` (read/traverse) and
  `service_access_write` (full control), with SYSTEM and Administrators in full. This is the only per-drive
  enforcement in this part; the per-request check in `sd_vfs` is left.

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

### 2.8 Versioning and features (M3)

- **Proto stays 1.** M3 changes are additive in the sense of 2.3: new methods, optional request fields, reply fields,
  events, topics, `features` strings, error codes and `prompt.closed` reasons, and `prompt.request` fields (`profile_id`,
  `queued`). Behaviour changes without a wire change: prompts are queued instead of rejected, deadlines are enforced,
  `prompt.closed` carries real reasons, the initiator is not sent a duplicate, and `mount` copies of warnings are kept.
  Clients treat unknown `prompt.closed` reasons as `cancelled` and unknown error codes as exit 1.
- **Features.** The `hello` reply carries `features: [...]` with the names this build implements: the methods `status`,
  `config.reload`, `log.tail`, `selftest`, `prompt.list` and the behaviour `prompt.queued`. M3 adds the methods `refresh`,
  `cache.clear`, `profile.test` and `mount.attach_info`, the status details `status.stats` and `status.proxy_legs`, and
  the events `config.changed` and `agent.stopping` (listed as names, as the others). Still planned: `diag.collect`,
  `update.check`, `log.follow` and the `log` topic (M4). A client calls a method only if its name is listed and degrades
  otherwise (the Logs viewer shows
  that the agent is too old for log viewing without `log.tail`).
- **Skew.** A server supports proto N and N-1 (2.3). An M3 UI talking to an M2 agent gets `features` without the M3 names
  and degrades. An M2 UI talking to an M3 agent is unaffected: it ignores unknown events, and its `mount`-topic warnings
  still arrive.
- **Deprecation.** The `mount` copies of `warning` and `hostkeys.announced` are removed at proto 2.
- **Shell extension and `--action`.** No IPC. The snapshot layout skew rules are in 8.2.1; `--action` verbs are additive
  only (1.6).

---

## 3. Configuration

### 3.1 Decisions

- **Own INI-like text files, UTF-8, one file per profile**, parsed by our `sd_ini` (~400 lines). Not the registry:
  files can be copied, diffed, backed up, deployed by MSI/GPO file preferences, and they work identically in
  portable mode. Not JSON: users and admins edit these by hand; INI allows comments and is forgiving. JSON stays
  for machine-to-machine (IPC, `--json`).
- One file per profile gives atomic per-profile writes, trivial import/export (`.ini` is the export format) and
  simple machine deployment (drop a file).
- **Group Policy** uses the registry, because that is what ADMX templates write: `HKLM\SOFTWARE\Policies\LibreStatic\ShellDrive`
  and `HKCU\Software\Policies\LibreStatic\ShellDrive` (one key each, no subkeys such as `\Update`). Policies override files; the
  UI greys out policy-controlled settings and says why.
- **This document owns the settings schema, including update settings (C8).** Update settings live in
  `settings.ini [update]`, not in `HKLM|HKCU\Software\LibreStatic\ShellDrive\Update\*`; the last accepted manifest serial lives
  in `state\last_serial.<channel>` (3.4). MSI properties (`UPDATECHECK`, `UPDATEURL`, `ENABLELINKEDCONNECTIONS`, …) are applied by
  writing the machine `settings.ini` (or, for `EnableLinkedConnections`, the Windows value itself). The only
  non-policy registry value of ours is `HKLM\Software\LibreStatic\ShellDrive\Version`, written by the MSI for Intune detection
  and never read by the apps.

### 3.2 Locations

Paths come from `SHGetFolderPathW` (XP+), never from Known Folder APIs (Vista+).

| What | Per user | Machine |
|---|---|---|
| Settings | `%APPDATA%\LibreStatic\ShellDrive\settings.ini` | `%ProgramData%\LibreStatic\ShellDrive\settings.ini` (defaults for all users + service settings) |
| Profiles | `%APPDATA%\LibreStatic\ShellDrive\profiles\*.ini` | `%ProgramData%\LibreStatic\ShellDrive\profiles\*.ini` (also the target of the MSI `DEFAULTPROFILES` folder copy, C9) |
| Overrides of machine templates | `%APPDATA%\LibreStatic\ShellDrive\overrides\<profile id>.ini` (3.4) | — |
| known_hosts | `%APPDATA%\LibreStatic\ShellDrive\known_hosts` | `%ProgramData%\LibreStatic\ShellDrive\known_hosts` |
| Protected keys | `%APPDATA%\LibreStatic\ShellDrive\keys\<id>.sdkey` | `%ProgramData%\LibreStatic\ShellDrive\service\keys\<id>.sdkey` |
| Fallback secrets | `%APPDATA%\LibreStatic\ShellDrive\secrets\<hash>.sdsec` (4.3) | `%ProgramData%\LibreStatic\ShellDrive\service\secrets\<hash>.sdsec` |
| Cache | `%LOCALAPPDATA%\LibreStatic\ShellDrive\cache\` | `%ProgramData%\LibreStatic\ShellDrive\service\cache\` |
| Logs, dumps | `%LOCALAPPDATA%\LibreStatic\ShellDrive\logs\` | `%ProgramData%\LibreStatic\ShellDrive\logs\` |
| Runtime state (`explorer.ini`, `menu.cache`; updater state `last_serial.<channel>`, `last_verified.<channel>`, `keyset`, cached `dokany-deny` list, 04 §9.2/§9.3) | `%LOCALAPPDATA%\LibreStatic\ShellDrive\state\` | updater state: `%ProgramData%\LibreStatic\ShellDrive\state\` (written by elevated setup, readable by users); service runtime state: `%ProgramData%\LibreStatic\ShellDrive\service\state\` |
| Network location entries (8.7) | `CSIDL_NETHOOD` (`%APPDATA%\Microsoft\Windows\Network Shortcuts` on Vista+, `%USERPROFILE%\NetHood` on XP) | — |
| Network location placeholders (8.7) | `%LOCALAPPDATA%\LibreStatic\ShellDrive\places\<profile id>\` | — |

`%APPDATA%` = `CSIDL_APPDATA` (roams; profiles and known_hosts should follow the user). `%LOCALAPPDATA%` =
`CSIDL_LOCAL_APPDATA`. `%ProgramData%` = `CSIDL_COMMON_APPDATA` (on XP `All Users\Application Data`).

Machine directory ACLs (set by the installer, re-applied by the service at start if wrong), as SDDL with
inheritance:

- `LibreStatic\` (vendor folder, shared with other LibreStatic products; created by setup if missing, never removed
  while non-empty): `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)`.
- `LibreStatic\ShellDrive\`, `profiles\`, `known_hosts`, `settings.ini`: `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)`
  — users can read machine profiles (they may use `scope = users` templates) but not change them.
- `service\` and below: `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`; `service\secrets\` and `service\keys\`:
  `D:PAI(A;OICI;FA;;;SY)` only (admins can still take ownership, which is accepted: admins are trusted).
- `logs\`: SYSTEM and Administrators full; users none (logs contain host names of global mounts).

Before re-applying machine ACLs, the service (and elevated setup, 04 §6.4) checks the **owner** of the vendor
folder `%ProgramData%\LibreStatic` (D45; any standard user could pre-create it), of
`%ProgramData%\LibreStatic\ShellDrive` and of each subfolder, opening every component with `FILE_FLAG_OPEN_REPARSE_POINT` and
following no reparse point (TM-R34, T-63). If an owner is not SYSTEM or Administrators, or a component is a reparse
point, the service does not "fix" the ACL and does not load anything from that tree (machine profiles,
`known_hosts`, `settings.ini`, service keys and secrets): it logs Event 3102 (10.3) and
stays idle until an elevated setup or `shelldrive service repair-data` (elevated) renames the folder aside and
recreates it (04 §6.4). Content of a renamed folder is never imported. Setup creates `%ProgramData%\LibreStatic\ShellDrive`
(or resets it this way) with the DACLs above before it writes anything there: the elevated setup EXE itself
(04 §6.4), and the `programdata-secure` hook (6.1) for MSI installs that bypass the EXE (04 §8.3).

Per-user data gets an explicit protected DACL `D:P(A;OICI;FA;;;<UserSID>)(A;OICI;FA;;;SY)` at creation, in case
`%APPDATA%` was redirected to a share with loose ACLs or a tool created the folder with inherited ACLs (TM-R07,
T-13): `%APPDATA%\LibreStatic\ShellDrive\` itself, `profiles\`, `overrides\`, `keys\`, `secrets\` and `known_hosts`, and
`%LOCALAPPDATA%\LibreStatic\ShellDrive\` (`cache\`, `logs\`, `state\`, `places\`, which holds the `menu.cache` the shell
extension reads, 8.2). When the agent finds an existing per-user folder whose DACL grants write to anyone other
than the user, SYSTEM or Administrators, it re-applies the protected DACL (it owns the folder) and logs a warning;
if it is not the owner, it logs an error and the UI shows "ShellDrive's settings folder can be changed by other
users." with a link to the admin guide. Portable mode skips this on volumes without ACLs (1.9).

### 3.3 File format (`sd_ini` grammar)

- UTF-8 without BOM on write; a UTF-8 BOM is accepted on read. If a file is not valid UTF-8 (e.g. saved as ANSI
  by XP Notepad), it is decoded with the ANSI code page and a warning is logged; the next write converts it.
- Lines: `[section]`, `key = value`, comments starting with `;` or `#` at line start. Keys are ASCII lowercase
  `[a-z0-9_.]`. Values are trimmed; a value in double quotes keeps whitespace and supports `\"`, `\\`, `\n`.
- Lists are comma-separated. Booleans: `yes/no/true/false/1/0`. Durations: integer + `ms|s|m|h`. Sizes:
  integer + `K|M|G`.
- Path values expand `%VAR%` (`ExpandEnvironmentStringsW`) and a leading `~\`/`~/` (user profile). Nothing else is
  expanded. In the service, `~\` and every variable other than `%ProgramData%`, `%ProgramFiles%` and
  `%SystemRoot%` make the value invalid (TM-R27, 2.6 rule 1).
- Unknown sections/keys are **preserved** on rewrite (round-trip, including comments), so newer versions and hand
  edits survive older writers.
- `format = 1` in `[profile]`; a newer `format` is opened read-only with a warning.

### 3.4 Profile model

```ini
; %APPDATA%\LibreStatic\ShellDrive\profiles\web-server.ini
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
;identities_only = yes                      ; yes | no; unset = yes when an identity is configured (D37)
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
symlinks = follow_inside                    ; follow_inside (default, D40) | follow | hide  (reparse reserved, D12; TM-R13)
shell_active_files = block                  ; show | block (default from security.trust: untrusted -> block, trusted -> show; D41)
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
trust = untrusted                           ; untrusted (default) | trusted  (gates shell-active files; D41, TM-R14)
legacy_algorithms = warn                    ; allow | warn | ask | refuse  (policy can force refuse; D33)
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
| `profile.service_access` | SID list, **no default: required** for `scope = service` (D35, TM-R24); `scope = service` only | `sd_webdav` (global attach, 1.3), Dokany SD synthesis (02 §3, §6.4), vfs access check | — |
| `profile.service_access_write` | SID list (empty = read-only for every non-admin, D35); must be a subset of `service_access` | Dokany volume SD (write ACEs), `sd_vfs` per-request check, `sd_webdav` (02 §6.4, §7.7) | — |
| `auth.methods` | list (`publickey, keyboard-interactive, password`) | `sd_ssh` | — |
| `auth.identity`, `auth.identity.N`, `auth.identity_store`, `auth.certificate` | paths / key id | `sd_mount` → `sd_ssh` (`SD_ID_BLOB` for stored keys, C22) | — |
| `auth.agent` | `auto \| pageant \| openssh \| none` (`auto`; forced `none` for service) | `sd_ssh` | — |
| `auth.identities_only` | `yes \| no` (unset: `yes` when the profile or hop profile sets `identity`, `identity_store` or `agent_keys`, else `no`; D37, TM-Q07; an explicit `no` turns it off) | `sd_mount` resolves to a bool → `sd_ssh` (`sd_ssh_config` hop `identities_only`, 01 §6.2) | — |
| `auth.agent_keys` | list of `SHA256:` fingerprints (empty) | `sd_mount` → `sd_ssh`: agent keys offered when `identities_only` is on, besides agent keys whose public key equals a configured identity | — |
| `auth.save_password` | bool (`yes`) | UI / `sd_secret` | `DisableCredentialSaving` |
| `auth.cache_secrets_for_reconnect` | bool (`yes`, TM-Q08 kept; never filled or used on a `hostkey_just_accepted` connection, TM-R05, 4.6) | `sd_ssh` (owns the reconnect cache, C20) | — |
| `proxy.jump` | hop list (empty; ≤ 8 hops) | `sd_mount` | — |
| `proxy.proxy`, `proxy.proxy.N` | `none \| system \| http://[user@]host:port \| socks5://[user@]host:port` (`none`) | `sd_mount` → `sd_ssh` (3.8) | `ProxyServer` |
| `proxy.proxy_auth`, `proxy.proxy_auth.N` | `auto \| basic \| negotiate \| none` (`auto`, HTTP only; `auto` = Basic or Kerberos-only Negotiate, NTLM only with `negotiate`; SSPI never to a WPAD/PAC-discovered proxy, TM-R10, 3.8) | `sd_ssh` (`sd_proxy_cfg.auth`: `BASIC\|SSPI_KERBEROS`, `BASIC`, `SSPI`, 0; 01 §5.2, §16) | `AllowSystemProxySspi` |
| `proxy.proxy_fallback_direct`, `proxy.proxy_fallback_direct.N` | bool (`no`); only for `proxy = system` | `sd_ssh` (01 §5.2) | `AllowSystemProxy` |
| `connection.connections` | `1..4` (`1`) | `sd_sftp` pool (`sd_sftp_options.connections`, D18, 01 §10.9) | — |
| `connection.channels` | `1 \| 2` (`2`) | `sd_sftp` (D19) | — |
| `mount.target`, `mount.backend` | (`auto`, `auto`) | `sd_mount` | `AllowedBackends` |
| `mount.read_only` | bool (`no`) | `sd_vfs` | — |
| `mount.write_mode` | `through \| behind` (`through`, D9) | `sd_vfs` (`write_mode`; `wb_window` 16 MiB node / 64 MiB mount for `behind`) | `ForceWriteThrough` |
| `mount.fsync_on_flush` | bool (`yes`) | `sd_vfs` | — |
| `mount.atomic_put` | bool (`no`) | `sd_webdav` | — |
| `mount.label`, `mount.hide_dotfiles`, `mount.exec_hint` | (name, `yes`, `yes`) | `sd_vfs` / backends | — |
| `mount.symlinks` | `follow_inside \| follow \| hide` (`follow_inside` for every profile, D40, TM-R13); `reparse` reserved, rejected with `symlinks_reparse_unsupported` | `sd_vfs` (02 §6.9) | — |
| `mount.shell_active_files` | `show \| block` (`block` when `security.trust = untrusted`, the default, `show` when `trusted`; blocks opening for every process, D41, TM-R14) | `sd_vfs` / backends (02 §4.1, §6.4) | — |
| `mount.mark_of_the_web` | `off \| internet` (`off`; opt-in per profile, not derived from `security.trust`, which D41 ties to shell-active files only; Dokany only, enabled after TST-21, TM-R15) | `sd_dokan` (02 §1.1, §6.4) | — |
| `mount.case`, `mount.remote_case` | `insensitive \| sensitive` (`insensitive`); `auto \| sensitive \| insensitive` (`auto`) | `sd_vfs` | — |
| `mount.remote_charset` | code page name (empty or `utf-8` = UTF-8; `cp` + number or a number otherwise, 1 to 31 characters of letters, digits, `.`, `_`, `-`) (M3: parsed only; the vfs refuses any code page other than UTF-8, so the key has no effect yet) | `sd_vfs` (stage 1 of the name map, C23) | — |
| `mount.umask`, `mount.map_readonly`, `mount.show_special`, `mount.allow_system`, `mount.strict_acl` | (`022`, `yes`, `no`, `yes`, `no`); `umask` is octal `001` to `777` (`000` is refused: the vfs reads 0 as the default 022) | `sd_vfs` (`allow_system` is M5, parsed only; `strict_acl` parsed only, no consumer yet) | — |
| `mount.identity_probe` | `owner \| exec` (`owner`, D10) | `sd_sftp` (`exec` sets `SD_SFTP_OPT_IDENTITY_EXEC`, 01 §11) → `sd_vfs` via `server_info.identity` (02 §3.4) | — |
| `mount.fs_name` | string (`NTFS`, D23) | `sd_dokan` (`sd_vfs_options.volume_fs_name`) | — |
| `mount.offline_hint_over_mb` | integer MB (`0` = off, D22) | `sd_webdav` | — |
| `mount.offline_wait`, `mount.reconnect_grace` | (`3s`, `60s`) | `sd_vfs` | — |
| `mount.autostart` | `no \| logon \| boot` (`no`; `boot` is valid only with `scope = service`, otherwise `mount.autostart` is the bad key; `logon` mounts when the agent starts, D25/03 §1.2; `boot` is applied by the service, M5) | agent (`sd_mount`), 03 §1.2 | — |
| `mount.autostart_sessions` | `any \| console \| remote` (`any`); checked against the session of the agent at its start | agent (`sd_mount`) | — |
| `mount.open_after_mount`, `mount.network_location` | (`no`, `yes`; `network_location` ignored for `scope = service`); `open_after_mount` opens the drive root once, after the first MOUNTED of a user-initiated mount, never on a reconnect or a logon mount | agent / UI, `sd_mount` (8.7) | — |
| `cache.attr_ttl`, `cache.dir_ttl`, `cache.neg_ttl` | durations (`30s`, `30s`, `10s`); `0` is refused (the vfs reads 0 as the default), range 1 ms to 1 h. Legacy names `metadata_ttl`, `directory_ttl` are read once | `sd_vfs` | — |
| `cache.open_revalidate` | duration (`1s`) or `never`; `0` is refused, `never` = revalidate on every open (vfs `-1`) | `sd_vfs` | — |
| `cache.max_readahead` | size (`8M`), 64 KiB to 1 GiB; `0` is refused (the vfs reads 0 as the default) | `sd_vfs` | — |
| `cache.disk` | size (`0`) | `sd_vfs` (`disk_cache_mb`, dir from 3.2) | — |
| `cache.max_readahead` | size (`8M`) | `sd_vfs` | — |
| `security.trust` | `untrusted \| trusted` (`untrusted`, D41) | `sd_mount`: selects the default of `shell_active_files` (D41, TM-R14) | — |
| `security.legacy_algorithms` | `allow \| warn \| ask \| refuse` (`warn`: enabled, ranked last, warning only, D33) | `sd_ssh` (`legacy_policy` = `SD_LEGACY_ALLOW\|WARN\|ASK\|REFUSE`) + UI (7.6) | `LegacyAlgorithms` |
| `security.legacy_accepted`, `security.host_key_alias` | hash, name | UI / `sd_ssh` | — |
| `security.refuse_terrapin_exposed` | bool (`no`; with TM-R01/D34 only servers that offer nothing but affected ciphers are "exposed") | `sd_ssh` (01 §4.2) | — |
| `security.crypto_backend` | `auto \| own` (`auto`) | `sd_crypto` | — |
| `security.update_host_keys` | `ask \| yes \| no` (`ask`; service: `no` unless policy) | `sd_ssh` + host (5.6) | `UpdateHostKeys` |
| `security.keepalive`, `security.connect_timeout` | (`15s`, `20s`) | `sd_ssh` | — |

Keys renamed by this revision are read under their old names once and rewritten (`metadata_ttl` → `attr_ttl`,
`directory_ttl` → `dir_ttl`, `read_cache_disk` → `disk`; `read_cache_memory` is ignored with a log line).

Semantics owned by this layer:

- **Who may use a global drive (D35, TM-R24, T-43).** `service_access` has no implicit default. The profile editor
  (elevated) shows the "Who can use this drive" list **empty** with quick-add buttons ("All users of this computer",
  "Administrators", "Choose users or groups…" through the object picker `DsObjectPicker`, falling back to a typed
  account name on XP workgroups) and refuses to save a `scope = service` profile until the list has at least one
  entry; `shelldrive profile add --machine --scope service` requires `--access SID|NAME[,…]` (exit 2 otherwise). A
  second list "Who can change files" fills `service_access_write`, empty by default, with the note "People not in
  this list can only read." `BUILTIN\Administrators` always gets write in both the volume SD and the vfs check
  (which, with UAC, means elevated processes of admins who are in `service_access`), so the two agree (02 §6.4). A machine profile deployed by file
  (`DEFAULTPROFILES`, MSI) without `service_access` fails validation with `service_access_required` (Event 3100) and
  is not mounted. Every mutating operation through a global drive (create, write-close, rename, delete, set
  attributes) is recorded at info in the Event Log as Event 1200 (`%1` profile, `%2` user SID, `%3` account name,
  `%4` operation, `%5` remote path), coalesced per (user, operation, path) per 60 s, so changes can be attributed
  although the server sees only the service account (repudiation). The Application log is readable by local users;
  members of `service_access` can see those paths anyway, and the admin guide says so.
- **Identity selection (D37, TM-Q07, T-15).** With `identities_only` resolved to `yes`, `sd_ssh` offers only the
  configured identities (files, `identity_store` keys and their certificates) and agent keys whose public key
  equals one of them or whose fingerprint is in `agent_keys`; other agent keys are never offered to that hop or
  target. The editor shows "Offer only the selected keys (recommended)" checked as soon as a key is chosen; the
  "Too many authentication failures" hint of 01 §6.2 then no longer applies. Profiles without any identity keep
  `no`, so agent-only users are unaffected.
- **Symlinks (D40, TM-R13, T-26).** `follow_inside` is the default for every profile (links that resolve outside
  the mount root appear dangling); when `follow` is chosen the editor explains: "Links can lead outside the remote
  folder; the folder is not a boundary."
- **Server trust (D41, TM-R14, TM-R15, T-28, T-29).** Profiles are `security.trust = untrusted` by default, which
  blocks opening shell-active files (`.library-ms`, `.searchConnector-ms`, `.url`, `.lnk`, `.scf`, remote-icon
  `desktop.ini`; final list after TST-20) for every process. The Security page has "I trust the files on this
  server" (unchecked; sets `trusted`, which allows them). `shell_active_files` can still be set individually on the
  Drive page. "Mark files as downloaded from the Internet" (`mark_of_the_web`, after TST-21) is a separate opt-in.
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
  `%APPDATA%\LibreStatic\ShellDrive\overrides\<profile id>.ini` (`[override] target, autostart, autostart_sessions, hidden`);
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
`[log] level, max_size, max_files, etw, privacy = standard|strict` (10.1, TM-R31), `[cache] memory` (global memory budget, C46), `[defaults] backend,
legacy_algorithms, write_mode, proxy, ...` (defaults for new profiles), `[credentials] persist = local |
enterprise`, `[hostkeys] openssh_source = yes, putty_source = yes` (5.1), `[update] enabled = yes|no, channel =
stable|beta, manifest_url =` (C8; consumed by the updater in the agent, 04 §9), `[service] webdav_global_mode =
auto|system|link|attach` (machine file only, 1.3), `[explorer] modern_menu = auto|off` (8.6). `last_serial` is not a
setting: it is state in `state\`, kept **per channel** as `last_serial.<channel>` (`last_serial.stable`,
`last_serial.beta`, TM-R37, 04 §9.2), next to `last_verified.<channel>` (time of the last verified manifest, for the
staleness warning of 7.7, TM-R36), `keyset` (highest accepted key set, 04 §9.3) and the cached `dokany-deny` list
(04 §9.2). `[backend] dokany = yes|no` (machine file only; `no` is written by the MSI property `DOKANY=0` and
makes `backend = auto` resolve to WebDAV, 04 §8.4, D36). The MSI properties `UPDATECHECK` and `UPDATEURL` write
`[update] enabled` and `manifest_url` of the machine `settings.ini`; per-user values override machine values
unless a policy is set.

### 3.5 Group Policy values (registry, read-only for us)

All values live in the single key `HKLM|HKCU\Software\Policies\LibreStatic\ShellDrive` (HKLM wins), listed here once (C8):
`LegacyAlgorithms` (0 allow, 1 warn, 2 refuse), `AllowUserProfiles`, `AllowAdHocMounts`, `AllowedBackends`
(`webdav,dokany`), `DisableCredentialSaving`, `StrictHostKeyChecking` (1 = no TOFU, only machine known_hosts),
`DisableKnownHostsSources` (1 = do not read `~/.ssh/known_hosts` or PuTTY), `UpdateHostKeys` (0 never, 1 ask,
2 accept proven keys; for the service, 2 is the only way to let it update the machine store), `ForceWriteThrough`
(1 = `write_mode = behind` refused), `ProxyServer` (a proxy spec forced as leg 1 for every profile),
`AllowSystemProxy`, `AllowSystemProxySspi` (0 default: SSPI is never answered to a proxy that came from `proxy = system`,
WPAD or PAC; 1 lifts that restriction, the scheme rules of 3.8 still apply; TM-R10), `AllowWebDavTokenOnly` (1 default; 0 forbids the
token-only WebDAV fallback, 02 §7.4, TM-R19; the answer is asked per enable, there is no profile key), `UILanguage`, `DisableUpdateCheck`, `UpdateChannel`, `UpdateUrl`,
`HideTrayIcon`, `DisableNetworkLocations`, `DisableModernContextMenu`, `LogPrivacy` (0 standard, 1 strict; 10.1,
TM-R31). ADMX/ADML produced by 04 (target namespace `com.librestatic.shelldrive.policies`, D45), localized from our catalogs
(`sdl10n` emits the ADML, C41).

Implementation (M4, branch `wip/m4-admx`). The table above is one machine-readable file, `res/policy/policies.txt`
(an `@key` line, then one line per value: name, class, type, params, supported, category). Three consumers read it:
- `tools/sd-admxgen` (C, build-time, no third-party code) writes `ShellDrive.admx`, one `ShellDrive.adml` per culture
  (en-US, es-ES, fr-FR, pt-BR, it-IT, de-DE) and two headers: the `sd_policy_id` enum and the name, kind, registry type
  and range table. Texts come from the `policy` domain, `l10n/policy/<lang>.po`, which `sdl10n --check` validates
  (complete in six locales, no plurals). Types: `boolean` (REG_DWORD 1/0), `enum` (REG_DWORD when every value is
  decimal, REG_SZ otherwise), `text` (REG_SZ with a maximum length), `decimal` (REG_DWORD with min and max; the table
  has no decimal policy yet). `supportedOn` is `xp` (Windows XP SP3 or later) or `win11`. Categories sit under
  LibreStatic > ShellDrive.
- `src/sd_policy` reads the values (HKLM first, then HKCU) by the generated names and types only. `UILanguage` and
  `DisableNetworkLocations` are read through it.
- `tests/policy` checks the output offline: `check-admx.ps1` (well-formedness, references, unique ids, table against
  ADMX and ADML, all six cultures) and `check-raw-reads.ps1` (fails when a source reads the key or a value name
  directly).
Deviation from C41's wording: `sd-admxgen` produces the ADML from the policy catalogs, while `sdl10n` keeps its
completeness and register checks on the same domain. Enum items are catalog keys `policy.<name>.opt.<value>`. All msgctxt
keys are lower case, because sdl10n accepts `[a-z0-9_.-]` only.

### 3.6 Concurrency

All writers (agent, UI, CLI) use `sd_config_lock()`: `LockFileEx` exclusive on `LibreStatic\ShellDrive\config.lock`. Writes go
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
`User`, `Port`, `IdentityFile`, `IdentitiesOnly`, `ProxyJump`, `CertificateFile`. `IdentitiesOnly yes|no` becomes
`identities_only = yes|no`; when it is absent the key stays unset (D37 default), so an imported profile with an
`IdentityFile` offers only that key, unlike OpenSSH's own default; the import preview says so in the profile's
note column. PuTTY sessions with a `PublicKeyFile` get the same unset default. Semantics follow OpenSSH: first obtained value
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
- **HTTP auth (TM-R10, T-20):** `proxy_auth = auto` tries without credentials, then on `407` uses `Negotiate`
  via SSPI **restricted to Kerberos** (package list excluding NTLM through `SEC_WINNT_AUTH_IDENTITY_EX`) with the
  caller's logon credentials if offered (service: machine account), else `Basic` with the configured user and the
  saved secret or a `proxy_password` prompt. A `407` offering only `NTLM` is answered only with `proxy_auth =
  negotiate`, which allows Negotiate with NTLM fallback and plain NTLM. SSPI (any package) is used only for a proxy
  configured explicitly in the profile or by policy `ProxyServer`, never for one obtained from `proxy = system`,
  WPAD or PAC unless policy `AllowSystemProxySspi = 1`; otherwise such a `407` falls through to `Basic` (if a user
  is configured) or fails with `proxy_auth_failed` and the hint "This proxy asked for your Windows sign-in.
  ShellDrive only sends it to proxies you set up yourself." `basic` forces Basic; `none` never answers a `407`.
- **System proxy (opt-in only).** `proxy = system` makes `sd_ssh` read the WinHTTP/WinINet configuration: agent —
  `WinHttpGetIEProxyConfigForCurrentUser` (XP SP1+), with WPAD/PAC through `WinHttpGetProxyForUrl` for the
  pseudo-URL `https://<host>:<port>/` (so PAC rules written for CONNECT apply); service —
  `WinHttpGetDefaultProxyConfiguration` (`netsh winhttp`). A `socks=` entry selects SOCKS, otherwise the HTTPS (then
  HTTP) proxy is used for CONNECT; the bypass list is honored; "direct" means no proxy. `system` is never the
  default; policy `AllowSystemProxy = 0` forbids it. **[verify that IE `socks=` entries mean SOCKS4 vs SOCKS5 in
  practice; we only speak SOCKS5]**. Resolution runs on a worker item and is re-done on every (re)connect.
- **Secrets:** proxy passwords live in Credential Manager like SSH passwords (4.1), target
  `com.librestatic.shelldrive:proxy:<http|socks5>:<user>@<proxyhost>:<port>`; service proxy secrets in the service secret store.
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
| Proxy password (HTTP Basic, SOCKS5) | Credential Manager, `CRED_TYPE_GENERIC` | target `com.librestatic.shelldrive:proxy:…` (3.8); service: service store |
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
  - `com.librestatic.shelldrive:password:<user>@<host>:<port>`
  - `com.librestatic.shelldrive:passphrase:SHA256:<base64 fingerprint of the public key>`
  - `com.librestatic.shelldrive:proxy:<http|socks5>:<user>@<proxyhost>:<port>` (3.8)
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
`pOptionalEntropy` = UTF-8 `"com.librestatic.shelldrive/secret/v1/" + target name`. File `secrets\<hex SHA-256 of target>.sdsec`:
magic `SDSEC1\0\0`, u32 version, u32 blob length, DPAPI blob. Same target naming as 4.2, so `shelldrive credential`
treats both stores uniformly (`sd_secret` API below).

### 4.4 DPAPI-protected private keys

When importing a key the user can choose "Keep a protected copy in ShellDrive" (no passphrase prompt afterwards,
protected by the Windows logon): the key is decrypted once (passphrase prompt), re-serialized in OpenSSH format
without encryption, and stored as `keys\<id>.sdkey` = magic `SDKEY1\0\0` + metadata (key type, public key blob,
comment) in clear + `CryptProtectData` blob of the private part, entropy `"com.librestatic.shelldrive/key/v1/" + id`,
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
- Secrets are deleted when the last service profile referencing them is removed, and at uninstall (4.7).

### 4.6 In-memory handling

Secrets live in `sd_secret_buf` (locked with `VirtualLock` where the quota allows, wiped with `SecureZeroMemory`
on free). The host keeps **no** reconnect cache of its own (C20): `sd_ssh` owns it (`cache_secrets_for_reconnect`,
profile key `auth.cache_secrets_for_reconnect`; `CryptProtectMemory` on Vista+, `RtlEncryptMemory` on XP, 01 §7.4/§8).
The host answers `is_reconnect` prompts from Credential Manager/DPAPI only; if nothing is saved and the cache is
off, reconnect raises a normal prompt.

**Reconnect secret caching rules (TM-R05, TM-Q08, T-10, T-56).** The cache stays on by default; these rules bound
it:

1. A secret enters the cache only after the server accepted it (authentication success) on a connection whose host
   keys all verified as `MATCH`/`MATCH_CA` against stored keys. Secrets typed on a `hostkey_just_accepted` connection (2.5)
   are not cached; the next connection, which verifies the now stored key, may cache them.
2. A cached secret is used only for the same (hop, user, host, port, host key fingerprint) it was accepted for, and
   only while the mount exists; a reconnect that meets a different or newly trusted host key gets no cached or
   stored secret (5.4: a changed key is a hard failure anyway).
3. The cache entry of a mount is wiped when the mount is unmounted, when its profile is edited or deleted, at
   logoff and on `cache.clear`.
4. OTP and other `kbdint` answers that did not match the password shape of 4.2 are never cached.
5. With `cache_secrets_for_reconnect = no`, reconnect uses only saved secrets or prompts (`is_reconnect`), as above.

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

### 4.7 Secrets at uninstall (TM-R28, T-54)

- **Per-machine uninstall** removes `%ProgramData%\LibreStatic\ShellDrive\service\secrets\` and `service\keys\` **by default**
  (MSI property `REMOVESECRETS=1` default, EXE checkbox "Remove the service's saved passwords and keys" checked;
  04 §6.7, §8.4). Machine profiles, `known_hosts` and settings still follow `REMOVEDATA` (default keep). Files are
  overwritten with zeros before deletion where the volume allows it (best effort; SSDs give no guarantee, so the
  admin guide points to full-disk encryption, TM-R31).
- **Every uninstall** (per-user, per-machine, ARP, `msiexec /x`, SYSTEM/Intune) deletes the cache directories
  (`%LOCALAPPDATA%\LibreStatic\ShellDrive\cache\` of the invoking user, `service\cache\`); they hold plaintext copies of remote
  files.
- The invoking user's per-user secrets (Credential Manager targets `com.librestatic.shelldrive:*`, `secrets\`, `keys\`) are removed
  by `--installer-hook user-cleanup --secrets` when "Also remove my settings" is checked. Other users' Credential
  Manager entries and profile folders cannot be cleaned by setup (their profiles and credential sets are not
  loaded, and no ShellDrive code runs for them after uninstall). This residue is listed in the summary and the admin
  guide gives the per-user commands (`cmdkey /list` filtered on `com.librestatic.shelldrive:`, and the folders of 3.2).
- The uninstall summary (EXE final page, MSI log, `uninstall.exe /quiet` log) lists what was kept: profiles,
  `known_hosts`, per-user data of other users.

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
| 1 | Machine `%ProgramData%\LibreStatic\ShellDrive\known_hosts` | read-only for users, read-write for elevated admins/service | yes | yes (only store) |
| 2 | User `%APPDATA%\LibreStatic\ShellDrive\known_hosts` | read-write | yes | — |
| 3 | `%USERPROFILE%\.ssh\known_hosts` (and `known_hosts2`) | live, read-only source | yes, default on (D7) | — |
| 4 | PuTTY `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` | live, read-only source | yes, default on (D7) | — |

- **Live sources (D7):** sources 3 and 4 are consulted on every lookup (no wizard step needed). A match in a source
  is **copied into the user store** with an end-of-line source comment (`# imported-from=openssh` /
  `# imported-from=putty`, plus `added=<date>`), so later lookups no longer depend on the source. A **mismatch in
  any store or source blocks** the connection (5.4); a key that matches one store does not override a mismatching
  key of the same type in another. Settings `[hostkeys] openssh_source`, `putty_source` (both `yes`) and the policy
  `DisableKnownHostsSources` turn the sources off. The service never uses live sources (no user profile; PuTTY is
  HKCU).
- **Live-source checks on every read (TM-R06, T-11; performed inside `sd_known_hosts`, 01 §7.2, which owns the I/O;
  this layer owns the warning and UX).** Before each read of `~/.ssh/known_hosts`/`known_hosts2`, the
  file is opened and its DACL and owner are checked **on the handle** (`GetSecurityInfo`): it is used only if no ACE
  grants write (`FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`, `GENERIC_WRITE`/`ALL`) to
  anyone but the user, SYSTEM and Administrators, and the owner is one of them; the parent `.ssh` folder gets the same
  check (a writable folder allows replacing the file). For PuTTY, the `SshHostKeys` key's DACL is checked the same
  way (`RegGetKeySecurity`). A source that fails is skipped for that lookup (neither MATCH nor MISMATCH counted), the
  mount carries `warning hostkey_source_insecure` (once per source per agent run, notification on, Settings shows the
  source as "Ignored: other users can change this file") and `diag --check` lists it. On volumes without ACLs (FAT)
  the source is skipped the same way. Lines whose host pattern consists only of wildcards (`*`, `*.*`, `?*` and
  similar, after stripping `!` negations) are **ignored for MATCH** from live sources but still count for MISMATCH,
  so a planted catch-all line can block but never grant trust. Our own stores are not subject to the wildcard rule
  (admins may deliberately use patterns in the machine store).
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

Content: profile name, host and port (and hop N of M, with "Reached through jump host <host>" for hop i ≥ 1 and for
a target behind jump hosts, 2.5), key type, SHA-256 fingerprint in OpenSSH form (`SHA256:...`) in a read-only,
selectable edit control, an expandable "More" with MD5 fingerprint (for comparison with old servers) and the full
public key. Text explains in plain language how to check the fingerprint with the server admin. Host and profile
names are shown after bidi/zero-width stripping (TM-R09). Buttons: **Trust and connect**, **Connect once** (not
saved), **Cancel**. **There is no default button (TM-R03, T-08):** the dialog sets `DM_SETDEFID` to none and initial
focus on the fingerprint edit control, so Enter does nothing until the user has moved focus to a button; Escape
cancels. (This is the one dialog where 11's "default button" rule is deliberately not followed.)

**Known host, other key type (TM-R04, T-09).** When any key is stored for the lookup name (any store or live source,
including `@cert-authority` lines that match), `sd_mount` passes 01 the list of stored key types and `sd_ssh` offers
only those types (plus their certificate variants) in the host-key algorithm list. A server that offers none of
them fails with `host_key_type_unavailable` (exit 6); there is **no** TOFU prompt and the dialog is never shown with
"first contact" wording for a host that has keys of other types. The failure notification reads "example.org did
not offer the type of key ShellDrive knows for it (stored: ED25519). ShellDrive stopped the connection." with
**Manage host keys…**, where the user can explicitly add a key of another type (6.1 `hostkey add --from-server`,
verified inside a connection authenticated with the stored key). The details dialog lists stored types and
fingerprints next to what the server offered, so a key type change is always visible. New types are otherwise
learned only through UpdateHostKeys (5.6). Automatic reconnects follow the same rule (no prompt, hard failure).

### 5.3 CLI equivalent

```
The authenticity of host 'example.org' (port 22) can't be established.
Reached through jump host 'bastion.example.org'.
ED25519 key fingerprint: SHA256:4bWb...  
Trust this key? [y]es, [o]nce, [N]o:
```
Localized; the y/o/n letters are localized too (they are in the catalog, with a translator note). The "Reached
through" line appears only for hop i ≥ 1. **The default answer is "no" (TM-R03):** an empty line, EOF or any input
other than the yes/once letters (or the full words) rejects the key (exit 5, `host_key_rejected`).

### 5.4 Changed key

Hard block: mount fails with `host_key_mismatch` (exit 6), a notification "The identity of example.org has changed.
ShellDrive stopped the connection." opening a details dialog that shows old and new fingerprints, the store and line
where the old key lives, and a **Manage host keys…** button. No "connect anyway". To accept the new key the user
removes the old one in the host key manager (confirmation dialog warns about MITM) and reconnects (TOFU again).
That reconnect is `hostkey_just_accepted` (2.5, TM-R05): saved passwords are not sent automatically, the user types them.
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
  key (not "Connect once", not a CA match, not a key that was just accepted by TOFU in the same connection, that is
  never on a `hostkey_just_accepted` connection, 2.5) and user authentication has completed. The review dialog shows, per
  key, its type next to the stored types ("New key type: ECDSA; stored: ED25519"), so a type change is explicit.
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
shelldrive hostkey list [host] [--announced] | add --from-server host[:port] [--type T] [--expect SHA256:...]
                   | remove <host[:port]> [--type T] | import --from putty|openssh [FILE] [--dry-run]
                   | accept-announced <id> [--add-only]
shelldrive location add <profile> | remove <profile> | repair     Network location entries (8.7)
shelldrive service install | uninstall | start | stop | status | repair-data     (repair-data: 3.2, TM-R34)
shelldrive cache clear [<profile>|X:|mount-id] | --all [--force]     --force: clear although write-behind data is queued (kept)
shelldrive logs [--component agent|service|ui] [--lines N] [--follow] [--path]
shelldrive diag [--check] [--bundle FILE.zip [--include-dumps] [--no-anonymize]] [--fix linked-connections|webclient]
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
`shelldrive diag collect` = `diag --bundle` (default file name in the current directory); `diag --bundle
--anonymize` is still accepted and is the default (TM-R31). Aliases are not listed in `help` except under the
command they map to.

`hostkey add --from-server` without `--machine` is the explicit "add key" action of the host key manager for the
user store (TM-R04): it connects offering only the stored key types, so the server is verified against a stored key
(a mismatch fails as in 5.4), then obtains the server's other host keys (or only `--type T`) **inside that verified
connection**, through `hostkeys-prove-00@openssh.com` when the server announced them, otherwise through a re-key
restricted to the requested type (requirement in 12.1), and shows them for confirmation ("example.org also has an
ECDSA key. Add it?"). For a host with no stored key it behaves as a plain TOFU (5.2). It is how a new key type is
learned when the server does not announce it through UpdateHostKeys.

**Installer hooks (hidden, not in `help`, not localized):** `--installer-hook <name> --apply|--revert
[--log FILE]`, idempotent, each with a rollback counterpart. The same code is reachable as
`shelldrive.exe --installer-hook …` (scripts, support) and `shelldrive-host.exe --installer-hook …`; setup, the
uninstaller and MSI custom actions always call **`shelldrive-host.exe`**, which is GUI-subsystem, so no console
window appears (04 §8.3). The hook names are fixed here and used unchanged by 04:

| Hook | Effect |
|---|---|
| `webdav-tune` | sets `FileSizeLimitInBytes=0xFFFFFFFF` and `FileAttributesLimitInBytes=100000000` under the WebClient parameters, records the originals in `%ProgramData%\LibreStatic\ShellDrive\service\state\webdav-tune.ini`, restores them on `--revert`; never touches `BasicAuthLevel` (C28). Per-machine only. |
| `user-cleanup` | for the current user: removes Network location entries (8.7), `HKCU` Run/tray keys, label/icon keys from `state\explorer.ini`, per-user shell registration and the cache directory (TM-R28); with `--secrets` also the `com.librestatic.shelldrive:*` Credential Manager targets, `keys\` and `secrets\` (4.7). Per-user uninstall runs it; per-machine uninstall runs it for the invoking user. |
| `modern-menu` | registers (`--apply`, current user) or removes (`--revert`; elevated: for all users with `RemoveForAllUsers`) the sparse package for the Windows 11 menu (8.6). No-op when no signed package is present or the OS is older than build 22000. |
| `signal-shutdown` | signals the shutdown events of every running agent it may open (12.3). |
| `programdata-secure` | per-machine only, runs as SYSTEM: the owner/reparse-point check of 3.2 on `%ProgramData%\LibreStatic`, `%ProgramData%\LibreStatic\ShellDrive` and its subfolders; a foreign-owned folder or a reparse point is renamed aside (`LibreStatic.untrusted-<n>` or `ShellDrive.untrusted-<n>`, never imported) and the tree is created fresh with the 3.2 DACLs; correct folders only get their DACLs re-applied. Reads no file content. Used by MSI installs that do not go through the setup EXE (04 §8.3, TM-R34); `--revert` is a no-op. |

Exit codes of hooks: 0 success, 1 failure (details in the log, English). `--selftest` of the host is a separate
flag of `shelldrive-host.exe`, not a hook.

**Hooks running as SYSTEM (TM-R35, T-64):** when the hook host's token is LocalSystem (MSI deferred `NoImpersonate`
custom actions, Intune), it loads no user configuration (no `%APPDATA%`, no HKCU, no per-user `settings.ini`),
resolves no environment-relative or user-writable path (only `%SystemRoot%`, `%ProgramFiles%` and the
admin-owned `%ProgramData%\LibreStatic\ShellDrive` checked as in 3.2), opens no window and starts no child process, and writes
its log only under `%ProgramData%\LibreStatic\ShellDrive\logs\`. `user-cleanup` and `modern-menu --apply` refuse to run as
SYSTEM. Which hooks run during repair is decided by 04 §8.3 (only the idempotent `webdav-tune` and
`programdata-secure`, which reads no content).

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
| 2 | usage error | `usage`, `service_access_required` |
| 3 | not found (profile, mount, host key) | `profile_not_found`, `mount_not_found`, `not_mounted` (refresh of a drive without a file system) |
| 4 | authentication failed or required | `auth_failed`, `prompt_required`, `auth_unavailable` (no SSPI for WebDAV; 02 §7.4), `token_only_refused` (token-only WebDAV not confirmed; TM-R19) |
| 5 | host key unknown and not accepted | `host_key_unknown`, `host_key_rejected` |
| 6 | host key mismatch, or no stored key type offered by a known host | `host_key_mismatch`, `host_key_type_unavailable` (TM-R04) |
| 7 | network / connection failure | `connect_failed`, `dns_failed`, `disconnected` |
| 8 | agent/service unavailable, or busy (`SD_E_BUSY`) | `agent_unavailable`, `service_not_installed`, `busy`, `write_behind_pending` (cache clear with queued writes), `too_many_connections`, `rate_limited` (TM-R25) |
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
  ShellDrive tells you)", label, symlinks "Stay inside the remote folder" (default)/"Follow"/"Hide", dot-files, autostart, "Show in This PC under Network
  locations", "Block opening shortcut and library files from this server in Explorer", "Mark files as downloaded
  from the Internet"), Cache (TTLs, disk cache size, default off), Security ("I trust the files on this server",
  legacy algorithm policy, host key alias, "When the server offers new host keys": Ask me / Save them automatically
  / Ignore, show stored host keys). Authentication has "Offer only the selected keys (recommended)" (D37). For
  `scope = service` profiles the General page has the required "Who can use this drive" and the optional "Who can
  change files" lists (3.4.1, D35).
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
  PuTTY" / "Trust host keys accepted in OpenSSH" (5.1, with the "Ignored: other users can change this file" state of
  TM-R06), updates (check automatically, channel), linked connections status + "Change…" (elevated), WebClient
  status, Windows 11 menu status (8.6), "Keep host names and file paths out of log files" (`[log] privacy =
  strict`, 10.1).
- **Token-only WebDAV fallback (TM-R19, 02 §7.4):** never switched on automatically. When 02 reports that the
  redirector cannot authenticate, the UI asks every time: "Windows could not sign in to ShellDrive's local file
  server. Continue with a less protected connection? Other programs that learn the drive's address can then read
  your files." (**Continue**, **Cancel**; no default button). The question is not offered, and the mount fails with
  `policy_denied`, on Remote Desktop Session Hosts, when more than one interactive session is active, or with policy
  `AllowWebDavTokenOnly = 0`.
  **Implementation status (r10):** the question is the prompt kind `webdav_token_only` (sd_mount
  `SD_MP_WEBDAV_TOKEN_ONLY`) routed through the normal prompt broker: the CLI answers y/N (default no), the UI
  dialog has Continue (accept) and Cancel (reject) with no default button. The answer applies to that enable only
  and is not stored; there is no profile key for it. A rejected question fails the mount with IPC code
  `token_only_refused`. The environment refusals (RDSH, several sessions, policy, global mount) come from
  `sd_webdav` as `SD_E_ACCESS_DENIED`; they are not yet mapped to `policy_denied` as this section asks. The trigger
  is currently the no-SSPI case only (02 §7.4).
- First-run wizard (`PropertySheet` with `PSH_WIZARD97`, XP+): welcome, import (5.5), create first profile, finish.
  The finish page and the admin guide recommend full-disk encryption (BitLocker/device encryption) when keys are
  kept by ShellDrive or the disk cache is turned on, and explain that saved passwords are only as safe as the
  Windows password (TM-R31, T-53, T-56, T-73).

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
- **Defaults stay as decided (D33):** legacy algorithms (including `diffie-hellman-group1-sha1` and GEX groups below
  2048 bits) remain enabled, ranked last, with `warn` as the default; the threat model's `ask` default and 2048-bit
  floor (TM-Q01) were rejected. Profiles and policy can still choose `ask` or `refuse`.
- **Terrapin (D34, TM-R01, T-01):** `sd_ssh` chooses the cipher after seeing the server's KEXINIT and avoids
  `chacha20-poly1305@openssh.com` and CBC + `*-etm` MACs when the server lacks strict KEX. If the server offers only
  affected combinations, the connection proceeds (unless `refuse_terrapin_exposed = yes`) and the mount carries
  `warning terrapin_exposed`, shown like a legacy warning: "The connection to example.org is open to a known attack
  (Terrapin) because the server is out of date. Ask the server's administrator to update OpenSSH." The Security
  column and the Details dialog show it; `legacy_accepted` does not silence it.

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
content), update information is stale (on: "ShellDrive could not check for updates for {days} days." plural-aware,
shown when the last verified manifest is older than 14 days, TM-R36), connection open to the Terrapin attack (on,
once per host), known_hosts source ignored because other users can change it (on, TM-R06), agent stopped
unexpectedly and drives disconnected (always, TM-R17), interference with ShellDrive's session objects (always,
TM-R26), disk cache refused on a volume without permissions (on, TM-R29). Every notification is also recorded in the main window's event list so nothing exists only as a
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
  verb `HKCR\LibreStatic.ShellDrive.Mount\shell\open\command = "shelldrive-ui.exe" --action mount-file "%1"`, no handler code).
- **`.sdmount` grammar (TM-R32, T-61):** the file is at most 4 KiB of UTF-8 (BOM allowed) and contains exactly one
  non-comment line `profile = <32 lowercase hex>` naming an **existing** profile visible to the user (own or
  `scope = users` template). Any other key, a second `profile` line, a missing or unknown profile id makes the file
  invalid: the UI shows "This file does not refer to one of your ShellDrive connections." and does nothing. Host
  names, users, paths or options are never read from the file, so a file can only start a mount the user already
  configured. If the file carries Mark-of-the-Web (`:Zone.Identifier` stream with `ZoneId` ≥ 3, read with
  `CreateFileW` on `<file>:Zone.Identifier`; absent stream = no mark), the UI asks first: "This file came from
  another computer. Connect to {profile}?" (**Connect**, **Cancel**; no default button), and never opens the drive
  automatically afterwards. Placeholder files we create (8.7) carry no mark.
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
- `QueryContextMenu` must return within microseconds: it maps `Local\com.librestatic.shelldrive.state.<SID>` (a read-only section
  the agent rewrites with a sequence counter; content: version, seq, array of {target, profile id, profile name,
  state, remote URL}) and reads profile names for the This PC submenu from a small cache file
  `%LOCALAPPDATA%\LibreStatic\ShellDrive\state\menu.cache` written by the agent/UI. It never opens the pipe, never touches the
  network, never loads profile files. Both inputs are untrusted (TM-R26): the section is used only after the owner
  and label checks of 1.6, `menu.cache` only if its owner is the user (folder DACL from 3.2), and every offset,
  length and count in either is bounds-checked against the mapped/read size (size caps: section 256 KiB,
  `menu.cache` 64 KiB, at most 256 entries). The parser is a fuzz target run inside a test host and, in the lab,
  inside Explorer (TST-02, TST-24). If the section is missing, drives get no items and the This PC submenu shows
  profiles from the cache with "ShellDrive is not running" items still working (the UI starts the agent).
- `InvokeCommand` launches `shelldrive-ui.exe --action <verb> <args>` with `CreateProcessW` (full path from our
  own registry key, quoted) and returns. Errors are shown by the UI, localized.
- Verb strings come from the catalog (`shell` domain, 9); language from settings or the user UI language.
- On Windows 11 the classic items appear under "Show more options". The modern top-level menu (8.6) ships in v1
  when the code-signing certificate exists in time (D27); otherwise 1.0 has the classic menu only and the modern
  one lands in 1.x.
- Robustness: no exception filters installed in the host, `__try/__except` only around our entry points, no
  static CRT state that blocks `DllCanUnloadNow`, no threads created.

#### 8.2.1 State section layout v1 (M3, specification)

The section `Local\com.librestatic.shelldrive.state.<UserSidString>` is written only by the agent. It is created by
`sd_ipc_state_create` (256 KiB, `PAGE_READWRITE`, the owner and label DACL of 2.2) and read by the shell extension through
`sd_ipc_state_open` with `FILE_MAP_READ | READ_CONTROL` [verify on XP, 7 and 10/11: a reader that cannot read the owner fails
closed]. This section specifies the binary layout; the codec and the agent producer are `sd_state` and the host's state producer (M3, decisions in 8.8). This binary layout supersedes the content summary given in 1.6 and 8.2.

Header, 64 bytes. Integers are little-endian with fixed width; there are no pointers. Strings are UTF-16LE in fixed slots,
measured in code units; a string is NUL-terminated when it fits, and a full slot without NUL means the slot length.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | u32 | `magic` | `0x54534453` (bytes "SDST") |
| 4 | u16 | `layout_version` | `1` |
| 6 | u16 | `header_size` | `64` |
| 8 | u32 | `total_size` | `header_size + entry_count * entry_size`, at most 262144 |
| 12 | u32 | `entry_size` | `1792` |
| 16 | u32 | `entry_count` | 0 to 128 |
| 20 | u32 | `seq` | seqlock counter: even when stable, odd while a write is in progress |
| 24 | u32 | `writer_pid` | agent process id (diagnostics only) |
| 28 | u32 | `writer_session` | session id (diagnostics only) |
| 32 | u64 | `published_filetime` | FILETIME (UTC) of the last completed publish |
| 40 | u32 | `flags` | bit 0: the agent is shutting down (entries are advisory) |
| 44 | u32 | `max_entries` | `128` (informational) |
| 48 | 16 B | reserved | zero |

Entry *i* starts at `64 + i * 1792`:

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | u32 | `flags` | bit 0 IN_USE, bit 1 GLOBAL, bit 2 READ_ONLY, bit 3 HAS_REMOTE_URL, bit 4 TRUNCATED, bit 5 NEEDS_ADMIN, bit 6 NETWORK_LOCATION; other bits zero |
| 4 | u32 | `state` | 0 unknown, 1 connecting, 2 authenticating, 3 mounted, 4 offline, 5 auth_required, 6 failed, 7 unmounting, 8 unmounted; other values read as 0 |
| 8 | u32 | `backend` | 0 unknown, 1 webdav, 2 dokany; other values read as 0 |
| 12 | u32 | `mount_num` | agent-local number; 0 for global entries |
| 16 | u16 | `letter` | `'A'`..`'Z'` for a drive letter, else 0 |
| 18 | u16 | reserved | 0 |
| 20 | u32 | reserved | 0 |
| 24 | WCHAR[32] | `mount_id` | e.g. `m-3` |
| 88 | WCHAR[32] | `profile_id` | 32 lowercase hex digits; empty for ad hoc mounts and for global entries the caller may not see |
| 152 | WCHAR[128] | `profile_name` | display name |
| 408 | WCHAR[260] | `target` | `X:`, a folder path, or the WebDAV UNC |
| 928 | WCHAR[64] | `label` | drive label as Explorer shows it |
| 1056 | WCHAR[320] | `remote_url` | `sftp://user@host:port/path`; never credentials |
| 1696 | 96 B | reserved | zero |

Global entries (service-owned, GLOBAL) carry only `letter`, `label`, `state` and `flags` when the caller is not in
`service_access`; the shell extension offers "Open" only for them, never unmount (2.2).

Writer rules (agent): one writer, under the agent's state lock. A publish sets `seq` odd (`InterlockedIncrement`) with a
full barrier, writes the entries and header fields, sets a full barrier and makes `seq` even again. Publish on every
`mount.state`, on mount add or remove, on a profile label change, on a change of the global view (at most every 30 s) and,
empty with bit 0 set, at shutdown. Strings longer than their slot are cut and set TRUNCATED. Secrets, passwords, prompt
text and host key material are never written; `remote_url` has the path only.

Reader rules (shell extension, inside `QueryContextMenu`, never the network): open, verify the owner and label on the
handle (failure is "no data"), map read-only, then up to three tries of: read `seq` (retry if odd), copy the header and
`total_size` bytes into a local buffer, read `seq` again (retry if it changed). After three failures there are no drive
items. Entries are parsed from the local copy and validated (magic, `layout_version` 1 or 2, `header_size` ≥ 64,
`entry_size` ≥ 1792 and a multiple of 8 and at most 4096, `entry_count` ≤ 128, `total_size` consistent and at most 256 KiB;
per entry: IN_USE, `state` ≤ 8, `backend` ≤ 2, `letter` valid, strings valid UTF-16, `profile_id` is 32 hex digits or
empty). A bad header means no data; a bad entry is dropped. Bidi and zero-width characters are stripped before display
(2.5). Actions pass only `--action <verb> <profile_id>` or `--action <verb> <letter>`, never a target or URL, and the UI
checks them again (1.4).

Version skew: a reader of layout N accepts N-1 and N+1 (where it can read the v1 fields at their v1 offsets; a v2 may only
add fields in reserved areas or after the entry tail). A non-additive change needs a new magic and a `.v2` section name.
The DLL reads the same layout on every architecture (fixed widths, no pointers).

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
  with a certificate whose subject equals the manifest `Publisher` (`PublisherDisplayName="LibreStatic"`, D45), and Windows refuses unsigned or untrusted
  packages. Without it, 1.0 ships the classic menu only (8.2) and the modern menu lands in 1.x with no other change.
- **Package:** `ShellDrive.ShellExt.msix` built by 04, installed next to the binaries. Manifest essentials:
  `Identity Name="com.librestatic.shelldrive.shellext"`, `uap10:AllowExternalContent="true"`, `TargetDeviceFamily
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
  `%LOCALAPPDATA%\LibreStatic\ShellDrive\places\<profile id>\`, which contains one file `Connect to <name>.sdmount`
  (`profile = <id>`, the existing `.sdmount` verb and its strict grammar, 8.1). Double-click mounts through
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

#### 8.8 M3 implementation decisions (producer and Explorer data)

Written with the M3 agent package (`src/sd_state`, `apps/shelldrive-host/state_producer.c`, `explorer_data.c`).
Where 8.2.1 is silent or ambiguous, the choice below applies; each open point is marked [verify] or [open].

- **Module.** `sd_state` (codec and section helpers) depends on sd_base, sd_platform and sd_ipc only. The codec works
  on any byte buffer; `sd_state_read_section` opens, maps read-only, copies and unmaps within one call and keeps no
  handle, so the shell DLL can call it from `QueryContextMenu`.
- **Header and entry base.** Entries start at `header_size` (64 for layout 1). A reader accepts `header_size` of 64 or
  more, `entry_size` from 1792 to 4096 in multiples of 8, `entry_count` up to 128, and `total_size` equal to
  `header_size + entry_count * entry_size` and at most 256 KiB and the mapped size. Any other header value is "no data".
- **Entries.** An entry without IN_USE, with a letter other than 0 or `A`..`Z`, with an unpaired surrogate in a string,
  or with a `profile_id` that is neither empty nor 32 lowercase hex digits is dropped (the others stay). An out-of-range
  `state` or `backend` reads as unknown (0) and keeps the entry. Unknown flag bits are ignored.
- **Strings.** A string of at most the slot length fits (a full slot without NUL is the slot length, 8.2.1). A longer
  one is cut by the producer with `sd_state_set_string` to slot length minus one unit, never inside a surrogate pair,
  NUL-terminated, and the entry gets TRUNCATED. The codec never splits a string itself: the decoded struct has no
  room for a string longer than its slot.
- **Writer seqlock.** A stale odd `seq` (a writer that died mid-write) is made even before the next publish. The section
  is created before the pipe and the ready event exist, so a client never sees "no section" for a running agent.
- **Publish triggers.** Start (empty), every `mount.state` (through the state callback), the add of a mount (state
  CONNECTING), the removal of a mount (finished or never started), and shutdown (empty with bit 0 set). Warnings do
  **not** trigger a publish: the layout has no warning field, so a warning cannot change what the entry shows. Labels
  are read when a mount starts, so a profile label change needs no publish. [open] A warning count would need a
  layout change (v2 field in the reserved area) and is not made here.
- **Remote URL.** `sftp://user@host:port/path`, IPv6 literals in brackets, path only. Passwords and key material never
  reach the section (8.2.1).
- **Drive present.** An entry's drive is "present" in `mounted`, `offline` and `auth_required`. Icons and the Network
  location target follow this flag; no other state maps a drive.
- **Drive icons (8.3).** Per user: `HKCU\Software\Classes\Applications\Explorer.exe\Drives\<Letter>\DefaultIcon` =
  `"<install dir>\shelldrive-ui.exe",-1`, written when the drive becomes present and removed when it stops being
  present. Removal happens only when the value still starts with our binary path. The letters written are listed in
  `%LOCALAPPDATA%\LibreStatic\ShellDrive\state\explorer.ini` (`[icons] letters = ...`) and removed at the next start
  and at shutdown (crash cleanup). Icon index 1 refers to an icon resource of `shelldrive-ui.exe` that the repository
  does not contain yet [open]: until it is added Explorer shows the generic network drive icon. Global drives
  (`HKLM DriveIcons`) belong to the service (M5) and are not written.
- **SHChangeNotify.** `SHCNE_DRIVEADD` and `SHCNE_UPDATEITEM` (on `X:\`) when a drive becomes present,
  `SHCNE_DRIVEREMOVED` when it stops, `SHCNE_UPDATEDIR` on the NetHood folder after a Network location changes.
- **Labels (8.3).** The host writes no label value. The WebDAV label is written by `sd_webdav_map` (`_LabelFromReg`,
  MountPoints2), and the Dokany label is the volume label; a second writer would duplicate the first.
- **Network locations (8.7).** Profile key `mount.network_location` (default `yes`, 3.4.1) is parsed and written back
  only when it is off or already present. Entry folders are named after the profile (reserved characters and control
  characters become `_`, trailing dots and spaces are trimmed, an empty name becomes `ShellDrive`); a name collision
  with a foreign folder gets ` (2)`, ` (3)` and so on. Placeholder files live in
  `%LOCALAPPDATA%\LibreStatic\ShellDrive\places\<id>\Connect to <name>.sdmount`. `target.lnk` is written through
  `IShellLinkW` and `IPersistFile::Save` to a temp file that is moved over the old link.
- **Start reconciliation (8.7 lifecycle).** Agent start deletes every NetHood folder with a `[ShellDrive] profile=` marker
  whose profile is gone or no longer asks for a Network location, and recreates the folders that are missing. Folders
  without the marker are never touched. The policy `DisableNetworkLocations` (HKLM wins over HKCU) turns the feature off.
- **Not done in M3 (8.7).** No hook at profile save (creation is at agent start only), no `shelldrive location add |
  remove | repair` command, no `scope = service` handling (the profile model has no `scope` key yet), no portable-mode
  check (the agent does not know yet whether it runs portable), no per-user protected DACL on the placeholder and state
  folders (3.2 asks for one) [open].
- **Test isolation.** Test builds (`SD_HOST_TEST_HOOKS`) write icons and Network locations only when
  `SHELLDRIVE_TEST_EXPLORER_KEY` and `SHELLDRIVE_TEST_NETHOOD` name test locations; the test placeholders then go under the
  test configuration root. Without them a test build writes nothing to the user's keys or folders.
- **[verify] on lab machines:** (1) `desktop.ini` honoured with the read-only folder attribute on XP, 7, 10 and 11, and
  the `CLSID2` key name (8.7); (2) `target.lnk` re-resolved by open Explorer windows after MoveFileEx (8.7); (3) the
  drive icon key on 7, 10 and 11 (8.3); (4) `SHChangeNotify` refresh of `This PC` after DRIVEADD and DRIVEREMOVED.

---

## 9. Localization

### 9.1 Decision: our own message catalog compiled into each binary

Authoring format: **gettext PO files** `l10n/<domain>/<lang>.po` with `msgctxt` = stable symbolic ID,
`msgid` = English source, `msgid_plural`, `msgstr[n]`, translator comments `#.`. The English `en` file is the source
of truth; the other five are translations. A build tool `tools/sdl10n` (C, built for the build host) validates and
compiles them into a generated C source per catalog, one catalog per binary's domain set (`sd_l10n_<catalog>.c`, in the
build tree under `generated/l10n/<config>/`): for each language a table of UTF-8
strings indexed by an enum generated into `sd_l10n_ids.h`. The tables are compiled into the binaries that use the
domain. Domains: `common`, `cli`, `ui`, `shell`, `svc`, `installer`.

**PO is the only source of user-facing text (C41).** `sdl10n` emits: the C tables (apps, setup stub,
`uninstall.exe`; the stub uses the `installer` domain and the language resolution of 9.3), the per-language
`STRINGTABLE` blocks below, the WiX `.wxl` files for the MSI and its language transforms, and the ADML files for the
ADMX template. Nothing is maintained by hand in `.wxl` or ADML. Canonical language codes are `en es fr pt-BR it de`;
`pt` is accepted as an alias of `pt-BR` everywhere a code is typed (`--lang`, `/lang=`, settings, policy) (C42).
The MSI embeds the `es` transform under LCIDs 11274 (es-AR), 3082, 2058 (es-MX), 21514 (es-US) and 1034, and the
`pt-BR` transform under 1046 and 2070; the setup EXE always passes `TRANSFORMS` explicitly from its own language
resolution (C43, packaging in 04). A build-only pseudo-locale `qps-ploc` exists for layout tests. `sdl10n --qps`
generates it from the English entries (accented letters, `[` `]` brackets, `~` padding to +40 % length; placeholders,
`{{`/`}}` escapes and the letter after an `&` mnemonic are kept), so GUI truncation shows up in a Debug build. CMake
passes `--qps` only for Debug configurations when `SD_L10N_QPS` is ON (the default); Release tables never contain it.
The runtime selects it only with `--lang`/`SHELLDRIVE_LANG` `qps-ploc` and only when the catalog carries the table.
It is never shipped and is not a supported language.

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
a `Plural-Forms` header that differs from the canonical one in 9.4; invalid UTF-8; fuzzy entries. `sdl10n` also runs
these checks (fixtures in `tests/l10n/fixtures`):

- **Register (lint, error).** A translation uses a word of the wrong register (AGENTS.md). Rules are word lists in
  `sdl10n.c` (`k_reg_*`), kept conservative: `es` (voseo) flags `usted`, `ustedes`, `tú` and the usted imperatives
  `elija`, `seleccione`, `haga`, `ingrese`, `intente`, `verifique`, `introduzca`, plus tú imperatives at the start of a
  sentence (`elige`, `haz`, `pulsa`, `introduce`, `selecciona`, `ingresa`); `fr` (vous) flags `tu`, `ton`, `ta`, `tes`
  and tú imperatives at the start of a sentence (`sélectionne`, `saisis`, `clique`, `choisis`, `ouvre`, `tape`,
  `vérifie`); `de` (Sie) flags the capitalized `Sie`, `Ihr`, `Ihre`, `Ihrem`, `Ihren`, `Ihrer`, `Ihres`, `Ihnen`
  (lowercase `sie` and `ihr` are fine); `it` (informal) flags the capitalized `Lei` and the formal imperatives
  `prema`, `selezioni`, `inserisca`, `verifichi`, `scelga`, `digiti`, `immetta`. `en` and `pt-BR` have no rules.
  Words match ASCII-case-insensitively unless listed capitalized; text inside `{placeholders}` is skipped. A
  translator comment `#. sdl10n:register-ok` on the entry opts it out. The lists are heuristics; reviewers decide
  whatever they miss, and a list change needs a fixture.
- **Mnemonics.** A translation drops the `&X` mnemonic that the English source has (error). A *mnemonic group* is the
  set of entries whose msgctxt has the same prefix up to its last `.` (`menu.file.open` and `menu.file.save` share
  `menu.file`; msgctxts without a dot share the group ""). Within one group and one language, a letter used twice in
  one string, or by two entries, is a warning. `&&` is a literal ampersand and does not count. Groups replace the
  earlier "dialog tables declare their scope" idea: name the entries of one dialog or menu with one prefix.
- **Length.** `#. sdl10n:maxlen=N` on the en entry limits each translation (and the English text) to N-1 UTF-16 units,
  because N is the buffer size including the terminating NUL, as in the `NOTIFYICONDATAW` field sizes (tray tooltip
  127, balloon title 63, balloon text 255). A longer translation is an error.

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

### 9.6 Strings added by the threat-model integration

New user-facing strings (English source shown; symbolic ids are the PO `msgctxt`). Like every catalog entry they
must exist in all six locales (en, es, fr, pt-BR, it, de) with the registers of AGENTS.md before the milestone that
ships them; `sdl10n` fails the build otherwise (9.2). Placeholders are named; `{days}` and `{count}` entries are
plural entries with every CLDR form of 9.4. Log lines, Event Log messages and JSON codes stay English.

| Id (domain) | English source | Where |
|---|---|---|
| `hk.no_default_hint` (ui) | Choose a button to continue. | 5.2, 11 |
| `hk.via_jump` (common) | Reached through jump host {host}. | 2.5, 5.2, 5.3 |
| `hk.type_unavailable` (common) | {host} did not offer the type of key ShellDrive knows for it (stored: {types}). ShellDrive stopped the connection. | 5.2 |
| `hk.add_other_type` (ui, cli) | {host} also has a {type} key. Add it? | 6.1 |
| `hk.source_insecure` (common) | Ignored: other users can change this file. | 5.1, 7.5 |
| `prompt.hostkey_just_accepted` (ui, cli) | You just accepted this server's identity. ShellDrive did not send your saved password automatically. | 2.5 |
| `warn.terrapin` (common) | The connection to {host} is open to a known attack (Terrapin) because the server is out of date. Ask the server's administrator to update OpenSSH. | 7.6 |
| `warn.agent_died` (ui) | ShellDrive stopped unexpectedly. Its drives were disconnected to protect your files. | 1.4 |
| `warn.objects_squatted` (ui) | Another program is interfering with ShellDrive in this session. Drive menus in Explorer are turned off. | 2.2 |
| `warn.no_acl_medium` (ui) | This drive has no file permissions. Anyone who gets this drive can read your profile list and change trusted host keys. | 1.9 |
| `warn.data_dir_loose` (ui) | ShellDrive's settings folder can be changed by other users. | 3.2 |
| `warn.update_stale` (ui, plural `days`) | ShellDrive could not check for updates for {days} day. / … for {days} days. | 7.7 |
| `proxy.sspi_refused` (common) | This proxy asked for your Windows sign-in. ShellDrive only sends it to proxies you set up yourself. | 3.8 |
| `webdav.token_only_ask` (ui) | Windows could not sign in to ShellDrive's local file server. Continue with a less protected connection? Other programs that learn the drive's address can then read your files. | 7.5 |
| `sdmount.invalid` (ui) | This file does not refer to one of your ShellDrive connections. | 8.1 |
| `sdmount.motw_ask` (ui) | This file came from another computer. Connect to {profile}? | 8.1 |
| `editor.trust_trusted` (ui) | I trust the files on this server | 3.4.1, 7.5 |
| `editor.symlinks_inside` (ui) | Stay inside the remote folder | 3.4.1, 7.5 |
| `warn.agent_untrusted` (common) | ShellDrive did not use your SSH agent because it is not running under your account. | 2.4 |
| `editor.block_shell_files` (ui) | Block opening shortcut and library files from this server in Explorer | 7.5 |
| `editor.motw` (ui) | Mark files as downloaded from the Internet | 7.5 |
| `editor.identities_only` (ui) | Offer only the selected keys (recommended) | 3.4.1 |
| `editor.symlinks_follow_note` (ui) | Links can lead outside the remote folder; the folder is not a boundary. | 3.4.1 |
| `editor.service_access` (ui) | Who can use this drive | 3.4.1 |
| `editor.service_access_required` (ui, cli) | Choose who can use this drive before saving. | 3.4.1 |
| `editor.service_access_write` (ui) | Who can change files | 3.4.1 |
| `editor.read_only_note` (ui) | People not in this list can only read. | 3.4.1 |
| `settings.log_privacy` (ui) | Keep host names and file paths out of log files | 7.5, 10.1 |
| `diag.anonymize` (ui) | Hide server names and file paths | 10.5 |
| `diag.webclient_domain` (cli, ui) | WebClient is running on a domain-joined computer. If every connection uses Dokany, consider disabling it. | 10.5 |
| `wizard.fde_note` (ui) | Saved passwords and keys are only as safe as your Windows password. Turn on BitLocker or device encryption if you keep keys in ShellDrive or use the disk cache. | 7.5 |
| `installer.dokany_option` (installer) | Installs Dokany, a signed file system driver from another project. Without it ShellDrive uses the slower WebDAV connection. | 12.3 (D36) |
| `installer.remove_service_secrets` (installer) | Remove the service's saved passwords and keys | 4.7 |
| `cli.hostkey_default_no` (cli) | Trust this key? [y]es, [o]nce, [N]o: | 5.3 |

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
  never logged.
- **Privacy of names and paths (TM-R31, T-58).** Log fields are typed: `host`, `user` and `rpath` (remote path)
  fields go through the logger's privacy filter instead of being formatted as plain strings.
  - `[log] privacy = standard` (default): host and user names are logged (needed for support); **remote paths are
    logged only at debug and trace level**, except in error records (a failed operation names its path), so the
    default info log does not accumulate file names.
  - `[log] privacy = strict` (setting, or policy `LogPrivacy = 1`): host names, user names and remote paths are
    replaced in every record, error records included, by stable short hashes (`h:3f9a1c`, HMAC-SHA-256 with a random
    per-installation key kept in `state\log.key`, so the same host maps to the same hash within one machine but
    hashes cannot be compared across machines). The UI and `diag --check` show which mode is active.
  - `diag --bundle` **anonymizes by default** (host, user names and remote paths replaced by stable hashes in logs,
    configuration and `diag --check` output); `--no-anonymize` (CLI) or unchecking "Hide server names and file
    paths" (UI, checked by default) opts out.
  - The Event Log follows the same rule for remote paths except Event 1200, whose purpose is attribution (3.4.1).
- `OutputDebugStringW` sink at debug level when a debugger is attached (`IsDebuggerPresent`).

### 10.2 ETW (optional, Vista+)

`sd_log` has a sink interface. An ETW sink registers the provider `com.librestatic.shelldrive` (provider GUID
derived from that name with the standard EventSource name hash, so it is stable and needs no manifest) with `EventRegister` (advapi32, Vista+, resolved at
runtime) and writes manifest-free events with `EventWrite` (UTF-8 string payload + level + component keyword). It is
off unless `log.etw = yes`; useful for enterprise tracing with WPR/`logman`. Not available on XP, not required for
v1.0 (can ship in v1.x without format changes).

### 10.3 Event Log (service only)

- Source `ShellDrive` under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ShellDrive` (the source
  name stays the readable product name, D45; the publisher `LibreStatic` appears through the message file's version
  resource `CompanyName`),
  `EventMessageFile = <path>\shelldrive-host.exe`, `TypesSupported = 7`. Registered by the installer/`service install`.
- One message table (`.mc` compiled by `mc.exe`), **English only**, few event IDs, each with `%1`… inserts:
  1000 service started, 1001 stopped, 1100 global drive mounted (`%1` profile, `%2` target, `%3` host),
  1101 unmounted, 2100 mount failed (`%1` profile, `%2` code, `%3` detail), 2101 reconnecting, 2200 legacy algorithms
  negotiated, 3000 host key mismatch (`%1` host, `%2` expected fingerprint, `%3` received fingerprint), 3001 prompt
  required (needs an administrator), 3100 configuration invalid, 2300 server announced new host keys (`%1` host,
  `%2` added fingerprints, `%3` removed fingerprints; 5.6), 2301 host keys updated by policy, 2400 global WebDAV drive
  waiting for user sign-in (`attach` mode, 1.3), 1200 change through a global drive (info; `%1` profile, `%2` user
  SID, `%3` account name, `%4` operation, `%5` remote path; coalesced per 60 s; D35/TM-R24), 3101 service pipe client
  refused or over quota (warning, at most once per SID per 10 min; `%1` SID, `%2` reason; TM-R25), 3102 untrusted
  data folder or service input refused (`%1` path, `%2` reason: `owner`, `reparse_point`, `acl`; TM-R27, TM-R34).
  `ReportEventW` (XP+).
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
- **Secret-bearing stacks are left out (TM-R30, T-57).** A normal minidump still holds every thread's stack, so
  `MiniDumpWriteDump` gets a `MINIDUMP_CALLBACK_INFORMATION` whose callback answers `IncludeThreadCallback` with
  "exclude" for threads marked sensitive and, in `ThreadCallback`, strips the stack (`ThreadWriteStack` flag
  cleared) of the faulting thread if it is sensitive. Sensitive are: SSH I/O threads (01), worker items while they run a KDF
  or private-key operation (they set a thread-local "sensitive" mark through `sd_dump_mark_sensitive()` for the
  duration), the IPC thread while it holds a prompt answer, the UI thread while a password, passphrase or kbdint
  dialog is open, and the CLI's console-reading thread while reading a secret. The faulting thread is always kept,
  with its stack unless it is sensitive (then only registers and context remain); a log line names the dropped
  threads. There is no option to include those stacks (decisions.md D43: crash dumps never contain
  secret-bearing stacks). Code that handles secrets wipes its stack buffers before returning
  (01 §2.4 rule 8, applies to our prompt handling as well).
- **Order after a crash:** write our dump → in the agent, cancel this process's WebDAV mappings
  (`WNetCancelConnection2W(…, TRUE)` for every mapping it created; TM-R17 b) → `TerminateProcess(GetCurrentProcess(),
  …)`. The filter never returns `EXCEPTION_CONTINUE_SEARCH`, so Windows Error Reporting does not collect a second,
  possibly larger report or send it according to WER consent settings. If the dump thread does not answer within
  10 s, the filter still cancels the mappings and terminates.
- Files: `logs\crash\<binary>-<yyyymmdd-hhmmss>-<pid>.dmp`, keep the newest 5. Never uploaded automatically; the
  next UI start shows "ShellDrive closed unexpectedly. Create a diagnostic bundle?".
- Windows Error Reporting LocalDumps (Vista SP1+) can be configured by admins for full dumps; the admin guide warns
  that full dumps of ShellDrive contain session keys and passwords and must be handled as secrets.

### 10.5 `shelldrive diag`

`diag --check` runs and prints (localized; `--json` for machines) checks: agent and service status and versions;
backend availability (Dokany driver/runtime version, WebClient service start type and state, WebDAV registry values
`FileSizeLimitInBytes` and `FileAttributesLimitInBytes` as reported by 02's checker; `BasicAuthLevel` is reported
read-only and never changed, C28); `EnableLinkedConnections` state and whether the current user is a split-token
admin; service installed/running and its global WebDAV mode (1.3); free drive letters; configuration parse errors;
known_hosts parse errors and active live sources; system proxy configuration as `proxy = system` would resolve it;
Network location entries in sync (8.7); Windows 11 menu package registered (8.6); clock skew hint; OS version,
architecture and build flavour. **Security notes (TM-R06, TM-R21, TM-R23, TM-R29, TM-R31, TM-R34):** live
known_hosts sources ignored as insecure; per-user or machine data folders with loose ACLs or a foreign owner; a
Dokany version on the signed `dokany-deny` list (02 §6.3; the backend is then disabled and `backend = auto` picks
WebDAV, with `warning dokany_denied`); disk cache on a volume without ACLs; log privacy mode; and, on domain-joined
machines, "WebClient is running" with the advice to set it to disabled where Dokany covers every profile
(`AllowedBackends = dokany`, admin guide). `--fix webclient` (elevated) sets WebClient to manual start and starts
it; it refuses (exit 15, `policy_denied`) when `AllowedBackends` excludes WebDAV, and warns on domain-joined
machines. The host never starts WebClient for a profile that resolved to Dokany (TM-R21, 1.3). `--fix
linked-connections` as in 1.7.2. Every fix asks for confirmation unless `--yes`.

`diag --bundle FILE.zip` writes a stored (uncompressed) ZIP — trivial writer, no zlib dependency — with logs,
crash dump list (dumps only if `--include-dumps`, with a warning that dumps may contain file contents and names),
redacted configuration (secrets never exist in config; host, user names and remote paths **anonymized by default**,
`--no-anonymize` to opt out, TM-R31), `diag --check` JSON, the latest setup and update logs (04 §13), and versions. The user
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
  `IsDialogMessage`; default and cancel buttons are set; Escape closes. Exception: trust decisions (host key
  dialog 5.2, token-only fallback 7.5, Mark-of-the-Web `.sdmount` question 8.1) have **no default button**
  (TM-R03); keyboard users reach the buttons with Tab or their mnemonics, and the dialog text says so for screen
  readers ("Choose a button to continue").
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
- Reconnect secret cache owned by `sd_ssh` (`cache_secrets_for_reconnect`, C20), following the rules of 4.6
  (TM-R05): never filled from or used on a connection where any hop's key was accepted by TOFU or "Connect once";
  bound to (hop, user, host, port, host key fingerprint). `sd_ssh` reports per hop whether the key was
  just accepted (`hostkey_just_accepted` in `sd_auth_prompt_info` and the connection result) so `sd_mount` can apply 2.5.
- **Host key type restriction (TM-R04; 01 §4.3/§7.1 own the mechanism):** `sd_ssh_config` takes the list of key
  types stored for each hop's lookup name (from every store and live source, including `@cert-authority` matches);
  when non-empty, only those types and their certificate variants are offered, and a server that offers none fails
  with `SD_E_HOSTKEY_TYPE_UNAVAILABLE` (→ `host_key_type_unavailable`) instead of `SD_HK_NEW_TYPE`. For the explicit
  "add key" action (6.1) `sd_ssh` provides a way to obtain and verify another host key type inside an already
  verified connection (`hostkeys-prove-00` for announced keys, else a re-key restricted to that type).
- **Terrapin (D34, TM-R01):** our KEXINIT is sent after the server's; without strict KEX the affected ciphers are
  removed for that connection; `on_negotiated` reports `terrapin_exposed` when only affected combinations remained.
- **Identities only (D37):** `sd_ssh_config.identities_only` plus the list of allowed agent key fingerprints
  (`auth.agent_keys` and the public keys of configured identities).
- **Proxy SSPI (TM-R10):** `sd_proxy_cfg` distinguishes `SSPI_KERBEROS` (Negotiate without NTLM) from `SSPI`
  (Negotiate/NTLM) and carries whether the proxy came from `proxy = system`/WPAD/PAC, in which case SSPI is not
  used unless the host passes `allow_system_sspi` (policy `AllowSystemProxySspi`).
- **Sanitization (TM-R09):** server text and host names handed to prompts are stripped of bidi and zero-width
  characters (2.5), in addition to control characters.
- **Dumps (TM-R30):** I/O threads and KDF/private-key work mark themselves with `sd_dump_mark_sensitive()` (an
  `sd_platform` hook) and wipe secret stack buffers before return (01 §2.4 rule 8).
- **Agent pipes (TM-R08):** 01 §6.5 uses `sd_pipe_verify_server` (2.2) for the OpenSSH agent pipe and checks the
  Pageant window's process token (user SID equal to ours, integrity ≥ ours).
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
- Threat-model keys consumed by 02 (C46 names): `service_access_write` and the read-only default for non-admins
  in the volume SD and the vfs check (D35, TM-R24); `symlinks = follow_inside` (TM-R13); `shell_active_files`
  (TM-R14); `mark_of_the_web` after TST-21 (TM-R15); the token-only fallback reported to the host as a question,
  never switched on by 02 itself, plus `AllowWebDavTokenOnly` (TM-R19); a mutating-operation callback (user SID,
  operation, path) for Event 1200 on global mounts (TM-R24); `SO_EXCLUSIVEADDRUSE` on every listener (TM-R17 a); the
  `dokany-deny` verdict exposed through the backend availability probe (TM-R23).
- Status (reconciled 2026-10-24): met in 02 — `service_access` SID check for service-hosted servers (02 §7.4,
  §7.7), mechanisms `system`/`link`/`attach` with the M5 go/no-go (02 §7.7), one `sd_sftp_session` per mount for
  any pool size (02 §5.6, `sd_vfs_mount`), `write_mode`, `volume_fs_name`, `offline_label_suffix`, `symlinks =
  follow_inside | follow | hide` (02 §6.9, D40), one global memory budget (02 §4.2).

### 12.3 To build / installer / updater / CI (04)

- Four binaries per arch (1.1, 1.10, D3), shell DLL in two or three arches, manifests as in 7.1/7.3; service
  `ShellDriveSvc` = `shelldrive-host.exe service`; health check `shelldrive-host.exe --selftest`; smoke tests
  `shelldrive selftest --json` (C2).
- Installer options: start at sign-in (Run keys; HKLM Run with `--if-needed` on per-machine installs, C11), install
  service (**checked** on per-machine installs, absent on per-user installs, MSI feature on by default with a way to
  turn it off, D6), **install Dokany** as an explicit option (D36, TM-Q06; 7 SP1+, **pre-checked**, with the text
  "Installs Dokany, a signed file system driver from another project. Without it ShellDrive uses the slower WebDAV
  connection." and unchecking leaving WebDAV only; mirrored by the MSI property `DOKANY=1|0` and the EXE switch
  `/dokany=auto|install|skip`, owned by 04 §6.3/§6.5/§8.4; `DOKANY=0` writes `[backend] dokany = no`, 3.4); after install, the UI Settings page and `diag --check` show whether Dokany is present and
  how to add it later, `EnableLinkedConnections` (unchecked, explained; MSI property `ENABLELINKEDCONNECTIONS`,
  default 0, D24), shell extension registration incl. Approved list and both registry views, versioned
  `shellext\<version>\` directories with `InprocServer32` rewrite (C4), Event Log source, machine directory ACLs
  (3.2), `.sdmount` file type, `DEFAULTPROFILES` = a folder of `.ini` profiles copied to
  `%ProgramData%\LibreStatic\ShellDrive\profiles\` (C9), `UPDATECHECK`/`UPDATEURL` written to the machine `settings.ini` (C8).
- Custom actions only through the hidden hooks of 6.1 (`webdav-tune`, `user-cleanup`, `modern-menu`,
  `signal-shutdown`).
- Windows 11 sparse package `ShellDrive.ShellExt.msix`, built and signed only when the certificate exists (D27, 8.6).
- `tools/sdl10n` integrated in the build; PO completeness (all CLDR plural forms, D26) is a build failure; C tables,
  STRINGTABLEs, `.wxl` and ADML generated from PO (C41).
- **Stopping agents for upgrade/uninstall (C3):** setup signals
  `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>` (1.2). Per-user setup signals the events for its own SID
  (it can open them: the user has `EVENT_MODIFY_STATE`). Elevated setup enumerates running `shelldrive-host.exe`
  processes (Toolhelp32 + `OpenProcessToken`, XP+), derives SID and session ID from each token and signals each
  event; Administrators and SYSTEM are in the event DACL. It then waits up to 15 s per agent and falls back to
  Restart Manager (Vista+) or a "close ShellDrive" message. Setup never connects to agent pipes (their DACL admits
  only the user, 2.2). The service is stopped through the SCM.
- Uninstall also removes registry entries we create, runs `user-cleanup` for the invoking user (with `--secrets`
  when user data removal was chosen), unregisters the sparse package, optionally removes user data (asked), removes
  service secrets and keys **by default** (`REMOVESECRETS=1`, TM-R28, 4.7), deletes every cache directory, and lists
  what was kept in its summary.
- Setup checks the owner of `%ProgramData%\LibreStatic\ShellDrive` before use and renames a foreign-owned folder aside
  (TM-R34, 04 §6.4); 03 §3.2 gives the service-side behaviour and `service repair-data`.
- Hooks run as SYSTEM obey 6.1 "Hooks running as SYSTEM" (TM-R35); repair conditions are 04's.
- The updater stores `last_serial.<channel>`, `last_verified.<channel>`, `keyset` and the cached `dokany-deny`
  list in `state\` (3.2, 3.4, TM-R36, TM-R37) and raises `update.stale` after 14 days without a verified manifest.
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
6. **Named pipe and named object squatting on XP** is detected only by owner checks (2.2, TM-R26); a malicious
   process running as the same user can always impersonate the agent — accepted (same-user code is inside the trust
   boundary). Squatting by another user or a low-IL process degrades to a warning and missing Explorer menus (DoS
   only).
7. **In-memory secret cache for reconnection** (owned by `sd_ssh`, C20) extends secret lifetime; mitigated by
   encrypted memory, the caching rules of 4.6 (TM-R05: never after fresh trust, bound to the verified host key) and
   the per-profile `cache_secrets_for_reconnect = no` option (then reconnect prompts).
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
    by the idle mode (1.3: no network, no listener without service profiles) and the service pipe quotas and
    filtering of 2.2 (TM-R25; 05 TM-Q04 keeps the decision on that condition).
14. **Proxy credentials in clear** to HTTP Basic / SOCKS5 proxies; mitigated by the warning in 3.8 and by preferring
    Negotiate when the proxy offers it (Kerberos only unless `proxy_auth = negotiate`, TM-R10).
15. **Global drives need an explicit access list** (D35): deployments that relied on "all users" must now say so in
    the profile; a file-deployed profile without `service_access` is not mounted (Event 3100). Admin guide and the
    MSI `DEFAULTPROFILES` documentation (04) must state it.
16. **Strict owner checks can refuse legitimate setups** (TM-R06, TM-R07, TM-R27, TM-R34): Cygwin/MSYS-created
    `.ssh` folders with POSIX-style ACLs, redirected folders on shares whose ACLs we cannot read, admin-created data
    folders owned by a specific admin account (accepted: Administrators members are allowed owners). Each refusal
    names the path and the reason in the UI or Event Log; TST-14, TST-25 and TST-29 cover the common cases.
17. **Legacy algorithms on by default** (D33) remain the weakest default against legacy-only servers (05 T-02); the
    warning UX of 7.6 is the only mitigation by decision.

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
| Low-IL process creating `Local\com.librestatic.shelldrive.state.<SID>` first gets a Low label; AppContainer creation is redirected (TM-R26) | n/a | test | test | test |
| `GetWindowThreadProcessId` + token check of a `WM_COPYDATA` sender from another user (`runas`) in the same desktop | test | test | test | test |
| `MiniDumpWriteDump` callback excludes threads and strips the faulting thread's stack with the XP dbghelp | test | test | test | test |
| `SEC_WINNT_AUTH_IDENTITY_EX` package list `Kerberos` (no NTLM) honored by Negotiate to an HTTP proxy | test | test | test | test |
| `:Zone.Identifier` readable on a downloaded `.sdmount` (NTFS; absent on FAT) | test | test | test | test |
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

### 13.5 Security tests for this layer (05 §7)

The tests are defined in 05 §7 with milestone and priority; this table lists the ones that exercise 03 and what
they must show here. P1 blocks the milestone demo.

| Test | M | P | What it checks in 03 | TM-R |
|---|---|---|---|---|
| TST-02 | M1 (importers M2) | P1 | fuzzing of `sd_json` + agent/service dispatch, `sd_ini` (profiles, settings, overrides), the shell DLL snapshot and `menu.cache` readers, the `.sdmount` parser, `ssh_config`/PuTTY importers | R25, R26, R32 |
| TST-10 | M1 | P1 | agent killed with a mapped WebDAV drive: mapping cancelled by the crash filter or the UI/CLI watcher within 5 s; stale mappings removed at the next agent start; elevated watcher removes the elevated view | R17 |
| TST-11 | M0/M2 | P1 | known host without the offered type → `host_key_type_unavailable`, no dialog; TOFU dialog without default button and CLI default "no"; after "remove old key + TOFU" no saved password is sent and nothing is cached | R03, R04, R05 |
| TST-14 | M2 | P2 | live source writable by another user ignored with `hostkey_source_insecure`; wildcard-only lines never MATCH; mismatch still blocks | R06 |
| TST-17 | M2 | P2 | `sd_pipe_verify_server` refuses a squatted `openssh-ssh-agent` pipe | R08 |
| TST-18 | M2 | P1 | no SSPI token to a WPAD/system proxy or to an NTLM-only `407` with `proxy_auth = auto` | R10 |
| TST-20/21 | M3 | P1/P2 | `shell_active_files = block` for default (`untrusted`) profiles, `show` for `trusted`; `mark_of_the_web` on/off | R14, R15 (D41) |
| TST-23 | M5 | P1 | service pipe: per-SID quota, 2 reserved admin instances under exhaustion, 64 KiB cap and rate limit for non-admins, low-IL/AppContainer/anonymous refused, `prompt`/`log`/`hostkeys` and `status` details refused to non-admins, filtered `list`, `attention` content-free | R25 |
| TST-24 | M3 | P1 | foreign-owned or Low-labelled snapshot, ready event, mutex and UI mutex: agent warns and runs without them, shell DLL ignores them; `WM_COPYDATA` from another user's window rejected | R26 |
| TST-25 | M5 | P1 | service key file swapped through a junction, user-writable key file or folder, `~\`/user variables in machine profiles → refused, Event 3102 | R27 |
| TST-26 | M5 | P1 | `service_access` required at save and for deployed files; non-admins read-only unless in `service_access_write`; Event 1200 per change | R24 (D35) |
| TST-27 | M4 | P2 | uninstall residue: service secrets/keys and caches gone by default; summary lists what was kept | R28 |
| TST-28 | M3 | P2 | dumps taken during a password prompt, KEX and KDF contain neither the test password nor key bytes; WER not invoked | R30 |
| TST-29 | M4 | P1 | foreign-owned `%ProgramData%\LibreStatic\ShellDrive`: service stays idle, `service repair-data` recovers; hooks as SYSTEM touch no user-writable path | R34, R35 |
| (03-local) | M1 | P2 | log privacy: no remote path at info in `standard`; no host/user/path in `strict`; bundle anonymized by default | R31 |
| (03-local) | M2 | P2 | portable mode on FAT: disk cache refused, one-time warning | R29 |
| (03-local) | M2 | P2 | prompts with bidi/zero-width characters in kbdint text and host names render stripped; hop host outside the server box | R09 |

Milestone placement follows 00 §6 and 05 §7: R17, R25's fuzzing part, R31 land with M1 (agent, WebDAV, logging);
R03–R06, R08–R10, R29 with M2 (SSH stack and importers); R14/R15 UX, R26, R30, R32 with M3 (Explorer
integration, UI); R28, R34, R35 with M4 (installer); R24/D35, R25 quotas, R27 with M5 (service and global drives).

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

## Changelog: threat-model integration 2026-10-24

Applied from `05-threat-model.md` §8 as adjusted by `decisions.md` D33–D39 (D39: all TM-R accepted except as
changed by D33).

- **TM-R01 / D34:** Terrapin handled by cipher choice after the server's KEXINIT; `warning terrapin_exposed`, UX in
  7.6; `refuse_terrapin_exposed` stays `no` (3.4.1, 12.1).
- **TM-R03:** no default button in the TOFU dialog, CLI default "no", "Reached through jump host" for inner hops
  (2.5, 5.2, 5.3; accessibility exception in 11).
- **TM-R04:** stored key types restrict the offered host-key algorithms; `host_key_type_unavailable` (exit 6)
  instead of a NEW_TYPE prompt; explicit "add key" through `hostkey add --from-server` inside a verified connection;
  type changes always shown (5.2, 5.6, 6.1, 6.2, 12.1). Coordinated with 01 §4.3/§7.1.
- **TM-R05 / TM-Q08:** `hostkey_just_accepted` connections never auto-answer server-bound secrets; reconnect secret caching
  rules (2.5, 4.6, 5.4, 12.1).
- **TM-R06 / D7:** live-source DACL/owner checks on every read, wildcard-only lines never MATCH,
  `warning hostkey_source_insecure` (5.1, 7.5, 10.5).
- **TM-R07:** protected per-user DACL on all of `%APPDATA%\LibreStatic\ShellDrive` and `%LOCALAPPDATA%\LibreStatic\ShellDrive` (3.2).
- **TM-R08:** shared `sd_pipe_verify_server` helper for 01's agent pipe checks (2.2, 12.1).
- **TM-R09:** bidi/zero-width stripping; hop host outside the server-text box (2.5).
- **TM-R10:** Kerberos-only Negotiate for `proxy_auth = auto`, no SSPI to discovered proxies, policy
  `AllowSystemProxySspi` (3.4.1, 3.5, 3.8, 12.1).
- **TM-R13, TM-R14, TM-R15:** profile keys `symlinks = follow_inside`, `shell_active_files`, `mark_of_the_web`,
  `security.trust` with defaults and editor UX (3.4, 3.4.1, 7.5, 12.2).
- **TM-R17 (b–e):** crash filter cancels mappings, UI/CLI agent watch, stale-mapping cleanup at agent start,
  elevated-view watcher (1.2, 1.4, 1.7.2, 10.4); (a) is 02's (12.2).
- **TM-R19 (03 part):** policy `AllowWebDavTokenOnly`, per-time confirmation dialog (3.5, 7.5).
- **TM-R21:** WebClient never started for Dokany profiles; `diag` security note on domain machines (10.5).
- **TM-R23 (03 part):** `dokany_denied` warning and `diag` report (2.4, 10.5).
- **TM-R24 / D35:** `service_access` required with no default, `service_access_write` (non-admins read-only by
  default), Event 1200 attribution (3.4.1, 7.5, 10.3, 12.2); replaces the `BUILTIN\Users` default.
- **TM-R25:** service pipe per-SID quota 4, two reserved admin instances, non-admin request cap/rate limit/idle
  timeout, low-IL/AppContainer/anonymous refusal, admin-only topics and details, filtered `list`, `attention` topic
  (2.2, 2.4, 2.6, 6.2, 10.3).
- **TM-R26:** explicit DACL/label on mutex, ready event, snapshot section and UI mutex, squatting handling, owner and
  label checks plus bounds checks in the shell DLL, `WM_COPYDATA` sender and verb validation (1.2, 1.4, 1.6, 2.2,
  8.2).
- **TM-R27:** service key files and machine inputs opened without reparse points and checked on the handle; no user
  paths or variables (2.6, 3.3).
- **TM-R28:** service secrets and keys removed by default at per-machine uninstall, caches always, summary of kept
  data (4.5, 4.7, 6.1, 12.3).
- **TM-R29:** no disk cache on volumes without persistent ACLs; portable-media warning (1.9).
- **TM-R30:** dump callback drops sensitive stacks (no `--include-secret-stacks`, decisions.md D43), no WER after our dump (10.4, 12.1).
- **TM-R31:** remote paths at debug only, `[log] privacy = strict` / policy `LogPrivacy`, `diag --bundle`
  anonymizes by default (`--no-anonymize`), full-disk-encryption note in the first-run wizard (3.4, 3.5, 6.1, 7.5,
  10.1, 10.5).
- **TM-R32:** strict `.sdmount` grammar and Mark-of-the-Web confirmation (8.1, 8.7).
- **TM-R34 (03 part):** service checks the data-folder owner, stays idle on a foreign owner, `service repair-data`
  (3.2, 6.1, 12.3).
- **TM-R35 (03 part):** behaviour of hooks running as SYSTEM (6.1).
- **TM-R36, TM-R37 (03 part):** `update.stale` notification, `last_serial.<channel>`, `last_verified.<channel>`, `keyset` and the cached
  `dokany-deny` list in `state\` (2.4, 3.2, 3.4, 7.7, 12.3).
- **D33:** legacy algorithms stay enabled with `warn` (TM-Q01 rejected, 7.6). **D36:** Dokany as a pre-checked
  explicit setup option (12.3). **D37:** `identities_only` defaults to `yes` when an identity is configured (key unset),
  `agent_keys`, `IdentitiesOnly` import (3.4, 3.4.1, 3.7, 12.1).
- New strings listed in 9.6 (all six locales required); new verification rows in 13.3; risks 6, 7, 13–17 in 13.1;
  security test mapping and milestones in 13.5.
- Not applicable to 03 (owned elsewhere): TM-R02, R11, R12, R16, R18, R20, R22, R33, R38, R39, and the 02/04 parts
  of R17, R19, R23, R34–R37.
- Final reconciliation (threat model) 2026-10-24: `trust_fresh` renamed `hostkey_just_accepted` (01's name;
  2.5, 3.4.1, 4.6, 5.4, 5.6, 9.6, 12.1); `identities_only = yes|no`, unset = D37 default (`auto` removed; 3.4,
  3.4.1, 3.7); `security.trust = untrusted|trusted`, default `untrusted` (D41), gating `shell_active_files` for every
  process; `mark_of_the_web` default `off`, no longer derived from trust; `symlinks` default `follow_inside` for
  every profile (D40); editor texts and strings `editor.trust_trusted`, `editor.symlinks_inside`,
  `warn.agent_untrusted`; `warning agent_untrusted` (2.4); `--include-secret-stacks` removed (D43, 10.4);
  `programdata-secure` hook and repair note (6.1); setup creates/resets `%ProgramData%\LibreStatic\ShellDrive` (3.2); updater
  state files `last_serial.<channel>`, `last_verified.<channel>`, `keyset`, cached `dokany-deny` list, machine
  updater state in `%ProgramData%\LibreStatic\ShellDrive\state\` (3.2, 3.4, 12.3); `[backend] dokany` (3.4); Dokany option
  names `DOKANY`, `/dokany=` (12.3).

LibreStatic naming (D45) 2026-10-24: pipes `\\.\pipe\com.librestatic.shelldrive.*`, kernel objects and the snapshot
section `Local\|Global\com.librestatic.shelldrive.*`, window class `com.librestatic.shelldrive.ui.<SID>` (1.2, 1.4, 2.1, 2.2);
registry `SOFTWARE\LibreStatic\ShellDrive` and `SOFTWARE\Policies\LibreStatic\ShellDrive` (3.5); folders under
`%APPDATA%`/`%LOCALAPPDATA%`/`%ProgramData%\LibreStatic\ShellDrive`, with the `%ProgramData%\LibreStatic` vendor folder
owner-checked and given its own DACL (3.2, 6.1); Credential Manager prefix `com.librestatic.shelldrive:` and DPAPI
entropy strings `com.librestatic.shelldrive/...` (3.8, 4.2-4.4); ProgID `LibreStatic.ShellDrive.Mount` (8.1); MSIX
identity `com.librestatic.shelldrive.shellext`, `PublisherDisplayName` `LibreStatic` (8.6); ADMX namespace
`com.librestatic.shelldrive.policies` (3.5); ETW provider `com.librestatic.shelldrive` (10.2); Event Log source stays
`ShellDrive` (10.3).

## Changelog: M3 IPC, prompt routing and snapshot contracts (2026-10-27)

- Object scope rule: `Local\` for per-session objects (agent mutex and ready event, UI mutex, state section), `Global\`
  for machine objects (2.1). The UI mutex and the state section are new named objects (`SD_IPC_OBJ_UI_MUTEX`,
  `SD_IPC_OBJ_STATE`).
- Prompt routing: initiator, then UI subscribers with delivery accounting, a 16-entry queue drained on subscribe,
  enforced deadlines (120 s, 600 s on reconnect) and the four `prompt.closed` reasons (2.5).
- Initiator disconnect cancels its prompts only when no UI is subscribed to `prompt` (2.5).
- Methods: `hostkey.announced.accept` takes `{id, add_only}`; `status`, `config.reload`, `log.tail`, `selftest` and
  `prompt.list` are in M3; `refresh`, `profile.test`, `mount.attach_info`, `cache.clear`, `diag.collect`, `update.*` and
  `secret.*` are planned for later milestones (2.4).
- Snapshot section layout v1 specified in 8.2.1; the agent producer and the Explorer data (drive icons, Network
  locations) are in M3 (8.8). The shell DLL reader is a later package.

## Changelog: M3 profile keys and CLI (2026-10-27)

- 3.4.1 audit: every key the M3 backend review listed exists in the table under the name given (none is misspelled).
  The keys are now parsed and validated in `src/sd_config/profile_m3.c`. Applied: `mount.shell_active_files` (derived
  from `security.trust`), `mount.hide_dotfiles`, `mount.show_special`, `mount.case`, `mount.remote_case`,
  `mount.umask`, `mount.map_readonly`, `mount.fsync_on_flush`, `mount.fs_name`, `mount.identity_probe`,
  `cache.attr_ttl`, `cache.dir_ttl`, `cache.neg_ttl`, `cache.open_revalidate`, `cache.max_readahead`,
  `mount.autostart`, `mount.autostart_sessions`, `mount.open_after_mount`. Parsed only (no consumer or refused by the
  consumer, listed in docs/dev/m3-notes.md): `mount.exec_hint`, `mount.atomic_put`, `mount.strict_acl`,
  `mount.remote_charset`, `mount.mark_of_the_web`, `mount.offline_hint_over_mb`, `security.crypto_backend`.
  M5 (parsed and validated only): `profile.scope`, `profile.service_access`, `profile.service_access_write`,
  `mount.allow_system`.
- Spec issues fixed in 3.4.1: the value sets of `mount.autostart` (`no | logon | boot`, `boot` only for
  `scope = service`) and `mount.autostart_sessions` (`any | console | remote`) were missing; `cache.open_revalidate`
  accepts `never` (the vfs value -1); a zero TTL, read-ahead size or umask is refused, because the vfs reads 0 as
  its default and cannot express "off"; `mount.remote_charset` and `mount.mark_of_the_web` are refused by the vfs
  until a later milestone, so they are parsed only.
- Default change: `mount.hide_dotfiles`, `mount.map_readonly` and `mount.fsync_on_flush` now reach the vfs with their
  3.4.1 defaults (`yes`). The agent passed FALSE before M3, so dot files are hidden by default from this build on.
- 6.1: the profile test command is `shelldrive profile test <p>` (the table of 3.4.1 and 6.1 list it under `profile`;
  there is no top-level `test`). `cache clear` takes `<profile>|X:|mount-id` or `--all`, and `--force`.
  `mount --open` is listed in the command line and implemented (it sends `open` to the agent).
- 6.2: exit 3 has `not_mounted` (refresh of a drive without a file system) and exit 8 has `write_behind_pending`.
