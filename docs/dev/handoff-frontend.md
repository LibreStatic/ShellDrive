# Hand-off: frontend (shelldrive-ui, shell extension)

Branch `wip/r14-ui`, audit of 2026-10-28. Compared: `docs/design/03-apps-platform.md` §5 (host keys), §7 (tray, main
window, prompts, notifications), §8 (Explorer), §2.4 (IPC) and `docs/dev/m3-notes.md`, `m4-notes.md`, `m5-notes.md`
against `apps/shelldrive-ui` and `apps/shelldrive-shellext`. Each item names the spec and the backend it needs
("backend ok" = the IPC method or CLI verb exists on this branch; "backend missing" = it does not).

## What is in (verified in the code)

Tray with icon states, rate-limited and queued balloons (7.7); main window with a mount list, New/Edit/Delete/
Duplicate/Import/Quick mount; profile editor (property sheet, all modes); import dialog (PuTTY, ssh config); first-run
wizard; prompt host (`prompts.ui`) with every prompt kind including `webdav_token_only` (Continue / Cancel, no default
button, 7.5); admin attention watch and `--elevated-admin` answering service prompts (2.6 rule 3); host key manager
with Known keys and Announced keys tabs; Logs viewer (`log.tail`); Settings (language, backend, cache, notify, logon,
update group); About; update flow (`update.check`, `update.apply`); dark title bar; DPI handling; `.sdmount` verb;
Explorer context menu (Open, Unmount, Reconnect) on drives.

## Defect found and fixed in this pass

- `ui_ipc.c`: the request queue kept the method name in `char method[24]` and refused names with `>= 24`
  characters. `hostkey.announced.accept` is exactly 24, so the **Add keys / Add and remove** buttons of the Announced
  keys tab could never send their request (they showed "The request could not be sent to the agent"). The buffer is
  32 bytes now.

## Prioritized gaps

Priority 1: the user can not do it at all, and the backend exists.

1. **Host key manager: "Add key from server..."** - DONE in this pass (see "Implemented"). Spec 5.2 (Manage host
   keys... for a key of another type), 6.1 `hostkey add --from-server`, 7.5. IPC `hostkey.add` then
   `hostkey.announced.accept {id, add_only: true}`. Backend ok for the IPC and the user store; the real connect is
   still `SD_E_UNSUPPORTED` ("not_implemented", m5-notes Part 6, blocked on the authentication question), so the
   dialog ends with a message saying so until that lands. Nothing in the UI changes when it does.
2. **Service status and repair page for admins.** Spec 7.5 Settings ("linked connections status", "WebClient
   status", service state) and 1.3. There is no UI for the service at all except the attention prompts. Backend: the
   CLI verbs `shelldrive service status [--json]` and `service repair-data [--json]` (m5-notes Part 3, exit 9 without
   elevation). There is no IPC method for either: `status` queries the SCM and `repair-data` works on the machine
   folder from an elevated process. The UI should run the CLI elevated (the `--elevated-admin` relaunch path, `runas`
   on Vista+) and read its JSON, or link the same SCM code. Needs a decision: shell out to `shelldrive.exe` or share
   the code in a library. Install, uninstall, start and stop are CLI verbs too (`service install` etc.).
3. **Settings: the 7.5 list.** PARTLY DONE (round 15, branch `wip/r15-uisettings`). The window now has the tabs
   General, Security and Updates. Done, all with a backend: "Trust host keys accepted in PuTTY" and "... in OpenSSH"
   (`[hostkeys] putty_source`, `openssh_source`), with the "Ignored: other users can change this file." note read from
   `sd_known_hosts_source_state` (TM-R06) and locked and unchecked when policy `DisableKnownHostsSources = 1`;
   "Roam saved passwords with my profile" (`[credentials] persist = enterprise`); the WebClient service state as a
   read-only line (`sd_webdav_query_client`, never changes the service); language locked read-only by policy
   `UILanguage`. Only changed values are written (`ui_settings_changed`), locked fields are never rewritten, and the
   agent is asked for `config.reload` only after a write. Model and tests: `ui_settings_model.c`,
   `tests/ui/test_settings.c`, smoke `ui_settings_security_smoke` in `--test-windows`.
   **Backend done in round 17 (branch `wip/r17-settingsbe`, item 3):** the four backend keys below are parsed,
   validated, saved and consumed; their Settings controls are still to be added (see the list after them).
   - Default write mode `[defaults] write_mode = through | behind`: `sd_settings.default_write_mode`. A profile without
     `mount.write_mode` takes it (`sd_profile.write_mode_set` = 0); the agent and the service resolve the effective mode
     with `sd_profile_effective_write_mode`, and policy `ForceWriteThrough` clamps a default to through and refuses an
     explicit behind (`SD_E_ACCESS_DENIED`, mount fails with `policy_denied`). The profile editor sets the key on edit.
   - `[log] privacy = standard | strict` (policy `LogPrivacy` overrides the file): `sd_settings.log_privacy`; the agent
     applies it with `sd_log_set_privacy` (typed fields `%Hs`, `%Us`, `%Rs`, HMAC key in `state\log.key`).
   - `[ui] notify_<kind>` per notification type (15 kinds, 03 §7.7 defaults) under the `[ui] notify` master:
     `sd_settings.notify_kind[]`, `sd_settings_notify_on`. The tray gates its balloons by kind (`ui_tray_notify_wanted`).
   - `[agent] start_at_logon`: `sd_settings.agent_start_at_logon`. The Settings save writes or removes the agent's HKCU
     Run value `ShellDriveAgent` (`agent_run_set`) when `sd_settings_agent_run_wanted` says so (the key or a profile
     with autostart = logon). The tray Run value `ShellDriveTray` is unchanged.
   **Still open (frontend or follow-up):**
   - DONE in round 18 (branch `wip/r18-uisettings2`): Settings controls for the four keys above. General has "Start the
     ShellDrive agent at sign-in" and the "Default for writes" list; Security has the log privacy checkbox; the new
     Notifications tab has one switch per kind under the master switch (disabled, not cleared, while the master is off).
     Policy locks `ForceWriteThrough` (UI_SET_F_WRITE) and `LogPrivacy` (UI_SET_F_PRIVACY) show the enforced value
     read-only with "Managed by your organization." and are never written. The profile editor's Writes list shows the
     effective default for a profile without `mount.write_mode` (`ui_pform_write_mode_shown`) and leaves the key absent
     unless the user changes the list; under `ForceWriteThrough` it is read-only.
   - The log call sites still print host, user and path with `%s`: they must move to `%Hs`, `%Us`, `%Rs` before strict
     privacy covers the whole log (about 100 sites in agent, sd_ssh, sd_sftp, sd_vfs).
   - Balloons for connection lost, reconnected, mount failed, mounted, proxy password, pool limit and disk cache are
     not emitted by the tray yet; their switches are read and take effect when the balloons exist.
   - Windows 11 menu status and `[explorer] modern_menu = auto|off` (8.6): there is no registration query and no
     `sd_settings` field (policy `DisableModernContextMenu` is not read by anything either).
   - Linked connections status and "Change..." (8.7): needs a system query helper and an elevated change path.
   - Credential roaming is not locked by any policy (none is defined); the control is always editable.

2. **Service status and repair page for admins. Done in round 15** (branch `wip/r15-uisvc`). Decision: the UI does not
   shell out to `shelldrive.exe`. The service pipe has two new methods, `service.status` (any client) and
   `service.repair_data` (elevated administrators only), both on the code of the CLI verbs (`svc_status.c`,
   `svc_scm.c`, `svc_repair.c`; the CLI output is unchanged). The Service page (`ui_service.c`, model
   `ui_service_model.c`) is under Tools and the tray menu: it reads the SCM read-only for the install state and, when
   the service runs, `service.status` for the machine data folder, global drives, open prompts and loaded profiles.
   **Repair data...** is enabled for administrators only, carries the UAC shield on Vista+ when this process is not
   elevated (a click offers `--elevated-service`, which reopens the page alone in an elevated process), asks for
   confirmation with the safe button as the default, and runs through `service.repair_data` (or in process when the
   service is not running). Details: the last section of m5-notes ("Service page: service.status and service.repair_data"). Still open on this item: install, uninstall, start and stop are
   CLI verbs only (the page shows the state, it does not change it), and the WebClient and linked-connections status
   of 7.5 (item 3).
3. **Settings is missing most of the 7.5 list.** Backend for the default write mode, log privacy, per-type notify and
   the agent's start at sign-in is DONE in round 17 (the Settings controls are still open, see below). Present: language, backend, cache budget, notify, start at sign-in,
   updates. Missing: default write mode, credential roaming, "Trust host keys accepted in PuTTY / OpenSSH" with the
   "Ignored: other users can change this file" state (5.1, TM-R06), "Keep host names and file paths out of log
   files" (`[log] privacy = strict`, 10.1), WebClient status, Windows 11 menu status (8.6), linked connections
   (8.7), start tray and agent separately. Backend ok for all that are `settings.ini` keys (direct `sd_config` writes,
   3.6); WebClient/linked-connections status need system queries (backend missing for a shared helper).
4. **Changed key and wrong key type notifications. DONE in round 16** (branch `wip/r16-uihk`, see "Round 16" below). Original text: **Changed key and wrong key type notifications do not lead to the host key manager.** Spec 5.2 and 5.4: the
   `host_key_mismatch` details dialog (old and new fingerprint, store and line of the old key, **Manage host
   keys...**, **Open file location**, "Stop using keys from this source") and the `host_key_type_unavailable`
   notification with **Manage host keys...** (stored vs offered types). The prompt dialog for `hostkey_changed` has
   only Close. Backend ok: `mount.state` carries `error{host_key_*, stored_type, stored_fp, offered_type, offered_fp,
   store_path, store_line}` (2.4). The balloon click (`NIN_BALLOONUSERCLICK`) should open the details dialog.

Priority 2: spec features with a backend, larger.

5. **Main window layout of 7.5. MOSTLY DONE in round 16** (toolbar, groups, Security column, details dialog; the rest is under "Backend missing" below). Original text: **Main window layout of 7.5**: toolbar with text labels (New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs);
   ListView groups (My connections / Provided by your organization / Global drives); columns Server, Drive/Folder,
   Backend, Status, **Security** (icon and text: legacy encryption, Terrapin); status bar with "Agent not running -
   Start". Today: plain push buttons, columns Name/Drive/State/Backend/Server, no Security column. Backend ok:
   `list` (`warnings`, mount objects), `scope`/`users` templates from `sd_config`. The legacy and Terrapin details dialog
   (7.6, buttons "Don't warn again", "Refuse outdated algorithms") is missing; backend ok (`warning` events, profile
   keys `legacy_accepted`, `legacy_algorithms`).
6. **Event list in the main window** (7.7: "every notification is also recorded in the main window's event list").
   No such list exists. Backend ok (events already reach the UI).
7. **Host key manager details**: source column wording ("ShellDrive", "Copied from PuTTY", "Copied from OpenSSH",
   "Updated by server" from the `# updated-by` comment), Copy fingerprint, the note listing the active live sources,
   machine entries read-only unless elevated with "Edit machine keys..." relaunching elevated. Today the source is
   only Machine / User. Backend ok for the store reads; machine writes (`hostkey add --machine`,
   `accept-announced --machine`) are exit 1 / "not part of this build" in the CLI (backend missing).
8. **Logs viewer**: "Open log folder" and "Create diagnostic bundle..." (`diag.collect` is M4 in 2.4; the CLI has
   `shelldrive diag`). Level filter and search are in. Backend: CLI `diag` ok, IPC `diag.collect` not in `features`.
9. **Token-only WebDAV question wording and refusals** (7.5): the dialog exists; the environment refusals
   (RDSH, several sessions, policy `AllowWebDavTokenOnly = 0`) still come as `access_denied`, not `policy_denied`
   (m5 notes), so the UI cannot explain which one applied. Backend missing (code mapping in `sd_webdav`/agent).
10. **Per-request access (M5) and service profiles in the editor**: `scope = service` General page ("Who can use this
    drive", "Who can change files", 3.4.1) and the read-only `scope = users` templates. Check `ui_profile_model.c`
    against 3.4.1; the machine profile loading and mounts are backend ok (`service list|mount|unmount`), but the UI
    never talks to the service pipe except for prompts and attention. Needs a decision on what the UI shows for service
    mounts ("Global drives" group).

Priority 3: Explorer integration (8).

11. **Shell extension.** PARTLY DONE (round 16, branch `wip/r16-shellext`; round 17, branch `wip/r17-menucache`: the
    backend items below are done). Done: **Copy remote path** on drive roots
    and on files and folders inside a ShellDrive drive (state entry `remote_url`, percent-encoded relative path, copied
    to the clipboard in process), the This PC class (`SHX_CLSID_COMPUTER_MENU`: **Mount with ShellDrive** submenu from
    `menu.cache` and **Open ShellDrive**), and the Directory, `*` and This PC registrations (per-user path in
    `DllRegisterServer`). Pure helpers and tests: `shellext_model.c`, `tests/shellext/test_shellext_model.c`. The format of
    `menu.cache` is specified in 03 8.2.2. **Backend, done in round 17:**
    - The writer of `menu.cache` is `src/sd_config/menucache.c` (format and sanitizing in `menucache_format.c`). Every
      `sd_profile_save` and `sd_profile_delete` rewrites the file under `config.lock` (CLI, UI and agent alike; an
      import rewrites it once after its saves), it is replaced atomically through a temporary file in the same folder,
      and the agent refreshes it at start. Tests: `tests/unit/sd_config/test_config_menucache.c` and the round trip
      through the shell extension's parser in `tests/shellext/test_shellext_model.c`.
    - `state_producer.c` already copies `remote_url` and the codec sets `HAS_REMOTE_URL`; Copy remote path appears only
      for entries that carry it (global drives of callers outside `service_access` do not).
    - The installer registers the This PC class, the Drive, Directory and `*` handlers and the Approved entries
      (`packaging/registration.txt`, feature `shellext`, in the MSI's ShellExt feature and in the per-user setup). Checked
      by `tests/msi` (`sd-test-msi tables`). **Open:** the x64 package registers only the 64-bit view, so 32-bit
      applications do not get the menu there (03 8.5 wants both views; the x86 DLL is not in the x64 package).
    - **Open:** per-user removal does not delete the empty CLSID and `InprocServer32` parents (the table removes only
      keys whose name contains ShellDrive); the MSI does not have this problem.
    Still missing: drive labels and icons (8.3), Windows 11 modern menu (8.6, needs the certificate), network
    locations (8.7). The UI verbs used are `--action mount <profile id>`, `show`, `open|unmount|reconnect X:`, all
    existing in `ui_wire.c`; no new IPC method was needed (the DLL never opens the pipe, 8.2).
12. **`.sdmount` MOTW check and error text** are in `main.c` (`--action mount-file`); the shell association
    registration belongs to the installer (not audited).

Not audited: accessibility pass (11), the installer pages, Group Policy display (3.5), the `qps-ploc` rendering of the
new dialogs in the lab, XP behaviour of anything (no lab).

## Implemented in this pass

### Host key manager: "Add key from server..."

- Known keys tab, new button (enabled while the agent is up). It opens a small dialog (generated template,
  `ui_dlg`, measured text) asking for `host`, `host:port`, `[v6]` or `[v6]:port` (ASCII; an IDN is typed as `xn--`).
  Parsing, the known_hosts lookup name (`host` or `[host]:port`) and the `hostkey.add` request are the pure functions
  `ui_hk_target_parse` and `ui_hk_add_params`.
- The call runs on the IPC thread (`UI_IPC_HK_ADD`, 60 s timeout; other calls queue behind it). The reply is read by
  `ui_hk_offer_parse`: keys (type and SHA-256 fingerprint), `verified`, the announcement `id`. Text is reduced to
  printable ASCII.
- The review dialog: first contact (`verified: false`) gets the 5.2 wording ("no key stored ... compare the
  fingerprint with the one the administrator gave you"); a verified host gets the plural "also has N other host
  key(s)". The keys are in a read-only, selectable edit control. Buttons **Add** and **Don't add**; **Don't add** is
  the default button (TM-R03; Enter never adds a key).
- **Add** calls `hostkey.announced.accept {id, add_only: true}` (the CLI's `hk_accept_offer` flow), then the Known keys
  list is read again. **Don't add** leaves the offer in the Announced keys tab (m5-notes Part 6: there is no reject
  method), and says so in the status line.
- Failures: agent down, busy, `not_implemented` (the current real backend: a message box saying this version cannot
  collect keys yet), `host_key_mismatch`, anything else with the error name.
- Strings: 19 new `ui.hostkeys.*` entries in all six locales (one plural, `ui.hostkeys.add.review_verified`, with
  the full forms each locale uses). Mnemonics of the `ui.hostkeys.add` group are unique in every locale (en S L C K A D,
  es S B C V A N, fr S R A C J N, pt-BR S P C V A N, it S R A V G N, de S U B C H N).
- Tests: `tests/ui/test_hostkeys.c` (6 new model tests: target forms and refusals, request JSON round trip through
  `sd_json_parse`, offer parsing including degenerate replies, failure classes); `--test-windows` builds both dialog
  templates and checks them with `ui_dlg_parse_check` (`ui_hostkeys_dialogs_smoke`).

### Not done, with reasons

- Items 2-12 above. Item 2 (service page) needs the CLI-vs-library decision and an elevated relaunch design; item 4
  needs the `mount.state` error path through the tray, which is a larger change than one pass should do blind.
- Real-agent end to end of the new dialog: not run (no real agent, and the real connect is not built yet; the fake
  backend of `tests/apps` answers `hostkey.add` for the CLI smoke tests, not for the UI).

## Round 16 (branch `wip/r16-uihk`): changed key, wrong key type and the main window

### Changed host key and wrong key type (03 5.4, TM-R04)

- `ui_app_on_event` passes every `mount.state` event that carries an `error` to `ui_hkissue_on_mount_state`
  (`ui_hkissue.c`, pure model `ui_hkissue_model.c`). `host_key_mismatch` raises the balloon "The identity of {host} has
  changed. ShellDrive stopped the connection." and `host_key_type_unavailable` the balloon of 5.2. Both are always
  shown (7.7: they ignore the notifications switch) and rate limited like the others (60 s per host and kind).
- A click on the changed-key balloon opens the details dialog: old and new key (type and SHA-256 fingerprint in a
  read-only, selectable edit control), where the old key lives (store and line, or the file, or the PuTTY registry),
  and what to do about it. **There is no accept or "connect anyway" button** (5.4). Buttons: **Manage host keys...**
  (opens the manager with the first key of the host selected, `ui_hostkeys_open_for`), **Open file location** (OpenSSH
  and other files only; the path must be an absolute drive or UNC path without quotes or control characters), **Stop
  using keys from this source** (OpenSSH and PuTTY only: asks, then writes `[hostkeys] openssh_source|putty_source = no`
  and sends `config.reload`) and **Close** (the default button). To accept the new key the user removes the old one in
  the manager; its removal confirmation now also says that an unexpected change can mean interception (5.4).
- The store of the old key is inferred from `store_path` (`ui_hki_classify`): empty or the PuTTY subkey is PuTTY, the
  user's own `known_hosts` is ShellDrive's list, `...\LibreStatic\ShellDrive\known_hosts` otherwise is the machine list,
  `known_hosts`, `known_hosts2` and `ssh_known_hosts` are OpenSSH, anything else is a plain file.
- A click on the wrong-key-type balloon opens the host key manager (with the host selected), where **Add key from
  server...** (round 14) adds a key of another type. A details dialog with stored and offered types is not built:
  the agent does not report them (see below).
- Tests: `tests/ui/test_hkissue.c` (7 tests), smoke `ui_hkissue_smoke` in `--test-windows` (the dialog template for
  every source of the old key, with and without Open and Stop).

### Main window (03 7.5, 7.6)

- A real toolbar with text labels (New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs) replaces the push buttons;
  it wraps when the window is narrow. Duplicate, Quick mount, Import, Refresh and **Security details...** moved to a new
  Connection menu.
- The list has the columns Name, Server, Drive, Backend, Status, Security. Status and Security show a small icon (drawn in
  code, `ui_icon.c`) and text; "Reconnecting ({attempt})" is shown while `connection.session` is `reconnect_wait` with
  an attempt number (`list` and `mount.state` carry the `connection` object).
- Rows are in ListView groups: My connections, Provided by your organization, Global drives (`LVM_ENABLEGROUPVIEW`,
  comctl32 v6, XP and later; the group structure is spelled in its XP layout, and if the message fails the list stays
  flat). The group comes from the profile scope.
- Security column: from `list.warnings` (code and `mount_id`) and from `warning` events (`legacy_algorithms`,
  `terrapin_exposed`); text "Legacy encryption", "Open to the Terrapin attack" or both.
- Details dialog (`ui_secdlg.c`, Connection menu and a click on a legacy or Terrapin balloon): the Terrapin text of 7.6,
  the outdated algorithms with category, name and a one-line reason, **Don't warn again for this server** (stores
  `legacy_accepted = sha256:<sorted list>` in the profile and reloads the agent; a different set warns again; Terrapin is
  never silenced), **Refuse outdated algorithms for this server** (sets `legacy_algorithms = refuse`, offers to
  reconnect: unmounts, and mounts the profile again on the `unmounted` event) and **Close**.
- Model: `ui_mainview_model.c`; tests `tests/ui/test_mainview.c` (7 tests); `--test-window` checks the toolbar commands,
  six columns, the image list and the menu items; `--test-windows` runs `ui_secdlg_smoke`.
- Strings: 52 new entries in all six locales (`ui.main.*`, `ui.menu.connection|security`, `ui.hki.*`, `ui.secdlg.*`);
  mnemonics unique inside `ui.hki` and `ui.secdlg` in every locale.

### Backend missing (not invented in the UI)

- DONE (round 17, branch `wip/r17-uidata`) `host_key_type_unavailable`: `mount.state` error has `host`, `lookup_name`,
  `stored_types` and `offered_types` (arrays; `stored_type` is the comma-joined list) and `offered_type`/`offered_fp` when the
  server presented a key. **Not sent: fingerprints of the stored keys** (`sd_kh_types` holds type names only), so the 5.2
  dialog can list stored types next to the offered ones but not stored fingerprints.
- DONE (round 17) `host_key_mismatch`: `error.store_kind` (`machine`, `user`, `openssh`, `putty`) next to `store_path` and
  `store_line`, plus `lookup_name`. PuTTY now reports `store_path` "" and `store_line` 0, as the `sd_hk_result` comment says
  (`known_hosts.c` `loc_to_res`). The UI still accepts the old subkey value for other builds.
- DONE (round 17) Legacy and Terrapin in `list`: each mount has `legacy` (bool), `legacy_algorithms` (`[{category, name}]`),
  `terrapin_exposed` (current connection, from `sd_mount_get_security`, not the ring). The `warnings` ring drops a mount's
  entries when the mount is destroyed. The UI can stop deriving categories from names.
- DONE (round 17) Groups, backend side: `list` mounts have `scope` (`user`, `machine_template`, `global`). **Still open:**
  `sd_profile_enum` reads the per-user store only, so machine templates and service profiles are not enumerated for the UI
  ("Provided by your organization" and "Global drives" stay empty).
- DONE (round 17, backend) "Agent not running - Start": `sd_ipc_connect_agent_or_start` (`src/sd_ipc`) starts and connects
  like the CLI's `connect_agent`. **Still open (UI):** the status bar must call it on the Start action.
- Still open: the event list of 7.7 (item 6), the other host key manager details (item 7), Logs viewer extras (item 8).

## Round 17 (branch `wip/r17-uiev`): event list, reject and host key details

- **Decline = reject (item 1).** "Don't add" in the review of **Add key from server...** now sends `hostkey.announced.reject {id}`
  (`UI_IPC_HK_REJECT`, request built by `ui_hk_reject_params`), so a declined offer leaves the Announced keys tab; the tab also has
  a **Dismiss offer** button for the selected announcement (7.5 does not name it, it follows the CLI answer "no" of 6.1). The
  status line says whether the offer was dropped; an agent without the method leaves the offer listed and the status line shows the
  error name.
- **Event list (item 6, 7.7).** Tools menu and tray menu **Events...** open `ui_events.c`: a list (time, drive or server, kind, text),
  a search box, **Copy list** (tab separated, the rows that match) and **Clear list**. The record is kept for the life of the
  process (`ui_events_model.c`: ring of 200, oldest dropped first; sequence numbers never reused) and does not depend on the
  window being open. What is recorded: every change of state of a drive and every failed mount with its error code (`mount.state`,
  `main.c`), and every notification of the tray (`ui_tray.c`: warnings, host key changed, wrong key type, new keys offered, prompt
  timeout, update available), also when the notifications switch is off. Kinds: Drive, Host key, Warning, Error, Information.
  It is its own window (the main window has no room left; 7.7 only says "the main window's event list").
- **Host key details (item 7).** Under the Known keys list a read-only pane shows the selected key: host, port, key type, SHA256
  fingerprint, store and line in its file (`ui_hk_row_details`); **Copy fingerprint** copies the fingerprint.
- **Logs viewer (item 8).** Level filter, search, Copy selection and Open log folder were already in. Not built: the privacy note
  (no `[log] privacy` setting yet) and **Create diagnostic bundle...** (no `diag.collect` in `features`).
- Strings: 33 new entries in all six locales (`ui.events.*`, `ui.menu.events`, `ui.hostkeys.*`; one plural,
  `ui.events.status_count`). `ui.hostkeys.add.declined` lost its sentence about the Announced keys tab (the offer is dropped now).
  The new windows use no mnemonics.
- Tests: `tests/ui/test_events.c` (5), `hk_reject_params_json` and `hk_row_details_follow_the_row` in `test_hostkeys.c`; the
  `ui_events` window is created, filled, searched and cleared in `--test-windows`.

### Backend missing (round 17)

- Host key manager: the source wording of 7.5 ("Copied from PuTTY", "Copied from OpenSSH", "Updated by server") and the details
  "comment" and "added date" need `sd_known_hosts_list_all` to return the line's trailing comment (`# updated-by=... added=...`) and
  its origin; the MD5 fingerprint needs an MD5 in `sd_crypto`. "Edit machine keys..." (elevated relaunch) needs the machine writes
  of the CLI (`hostkey add --machine`), which are still "not part of this build".
- `hostkey.announced.reject` is on the agent and the service; the UI uses the agent only.
- Event list: the agent has no event history; the list starts when the UI starts. A `mount.state` event does not say why a drive
  reconnected, so the text is the new state.
- Logs viewer: `[log] privacy` and `diag.collect`.


## Round 18 (branch `wip/r18-uiconsume`): the UI consumes the round 17 agent data

- **Wrong key type details dialog (5.2).** A click on the balloon of `host_key_type_unavailable` opens a dialog (`ui_hkissue.c`,
  `build_type_dialog`): the key types stored for the name, the host key algorithms the server offered (`offered_types`) and, when
  the server presented a key, its type and SHA-256 fingerprint (`offered_type`, `offered_fp`). Buttons **Manage host keys...**
  (manager with the host selected), **Add key from server...** (opens the manager and starts the add dialog prefilled with
  `lookup_name`, else the host: `ui_hostkeys_add_for`) and **Close** (default). The balloon names the stored types from
  `stored_types[]`. **Not shown: fingerprints of the stored keys** (the agent has none, see round 17).
- **`store_kind` (item 2).** `ui_hki_source_of` uses `error.store_kind` (`machine`, `user`, `openssh`, `putty`); the path
  classification (`ui_hki_classify`) is only the fallback for an agent or an unknown token without it.
- **Security column and groups from `list` (item 3).** `ui_mv_security_from_mount` reads `legacy`, `legacy_algorithms[{category,
  name}]` and `terrapin_exposed` of each mount (the current connection); `ui_mount` keeps the names and their categories
  (`algo_cat`), so the Security column and the legacy/Terrapin dialog work after a UI restart, "Don't warn again" included. The
  dialog shows the category the agent sent; the reason line is still derived from the name. A mount without those fields (older
  agent) still gets its bits from the `warnings` ring and from warning events. When the fields are there they replace the bits
  the UI had accumulated, so a mount that reconnected without the outdated algorithm stops showing it after the next `list`.
  `scope` (`user`, `machine_template`, `global`) puts a mount in My connections, Provided by your organization or Global drives
  (`ui_mv_scope_of_token`); a mount without a profile in the user's store (the other two groups) is a row of its own.
- **"Agent not running - Start" (item 4).** The status bar reads "ShellDrive is not running. Click here to start it."; a click
  (`NM_CLICK`) calls `ui_ipc_start_agent`, which wakes the IPC thread to connect with `sd_ipc_connect_agent_or_start`. The status
  line says "Starting ShellDrive...", a failed start shows the error name, and a started agent is the usual state change. A
  prompt host never starts the agent (1.4). There is no keyboard path yet (the status bar is not focusable).
- **Notices of 7.7 (item 5), `ui_notice_model.c` + `ui_tray_notice`.** Derived from what the agent sends: `mount.state`
  (mounted -> offline = connection lost, offline -> mounted = reconnected, other -> mounted = mounted, -> failed = mount failed;
  a host key error keeps its own always-on balloon), `warning` codes `proxy_cleartext` (once per profile and proxy per UI run),
  `pool_limited` and `disk_cache_refused`, `hostkeys.announced` with `applied = true` (host keys saved; before this the UI said
  "offered new host keys" for them) and the service `attention` count going up (administrators; the text is the tray menu's plural
  item and a click opens the administrator window). Each is recorded in the event list always and shown as a balloon only when
  `[ui] notify` and the kind's `notify_<kind>` allow it, with the 60 s rate limit per (drive, kind). A change that has a notice is
  recorded by the notice (not twice as a plain state entry).
- Strings: `ui.notice.*` (8), `ui.hki.type_*`, `ui.hki.line_*_types`, `ui.hki.types_none`, `ui.hki.btn_add`,
  `ui.status.agent_starting|agent_start_failed` in six locales; `ui.status.agent_down` now says to click. Mnemonics of `ui.hki`
  are unique in every locale (`btn_add`: A, G, A, A, V, H for en, es, fr, pt-BR, it, de).
- Tests: `tests/ui/test_notice.c` (5), `test_hkissue.c` (+4), `test_mainview.c` (+3); `ui_hkissue_smoke` builds the new dialog in
  `--test-windows`.

### Backend missing (round 18)

Round 19 (branch `wip/r19-smallfix`) closed these: `proxy_cleartext` maps to the proxy password kind
(`sd_notify_kind_from_code`); the main window lists machine templates (read-only: no Edit, Duplicate or Delete; Mount works
through `sd_profile_find_mountable`); `ssh_log` formats with its level (`sd_log_format_level`); `warning
hostkey_source_insecure` is sent once per live source and run; `mount.state` carries `reason` while a reconnect runs. Still
open: no balloon for `hostkey_source_insecure` (the UI kind `notify_hostkeys_source` has no text yet), and the event list does
not show `reason`. The `update_stale` warning item stays open.

- The settings backend maps the code `proxy_password` to its switch, but the agent raises `proxy_cleartext`; the UI accepts
  both. `sd_notify_kind_from_code` should learn `proxy_cleartext`.
- Every kind of item 5 has a triggering event. Not emitted by the agent: `hostkey_source_insecure` (kind `notify_hostkeys_source`,
  no code path sends it) and `update_stale` as a `warning` (it is an `update.*` event). No event says why a drive reconnected
  (the UI only sees offline -> mounted).
- `sd_profile_enum` still reads the per-user store: org and global profiles appear as rows only while mounted (their group now
  comes from `scope`), and cannot be listed before a mount.
- Stored key fingerprints for the type dialog (see round 17).
