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
   **Still missing, shown nowhere until the backend exists (backend missing):**
   - Default write mode (`[defaults] write_mode`): `sd_settings` has no field, `sd_settings_from_ini` does not parse it,
     new profiles do not take it. Policy `ForceWriteThrough` exists, but nothing reads the default to lock.
   - "Keep host names and file paths out of log files" (`[log] privacy = strict`, policy `LogPrivacy`): no field in
     `sd_settings`, `sd_log` does not read it.
   - Windows 11 menu status and `[explorer] modern_menu = auto|off` (8.6): there is no registration query and no
     `sd_settings` field (policy `DisableModernContextMenu` is not read by anything either).
   - Notifications per type (`[ui] notify_*`) and "start tray and agent separately" (`[agent] start_at_logon`): only
     the single `[ui] notify` and the tray Run key are parsed.
   - Linked connections status and "Change..." (8.7): needs a system query helper and an elevated change path.
   - Credential roaming is not locked by any policy (none is defined); the control is always editable.
   To add one of these, give `sd_settings` the field (parse and save in `src/sd_config/profile.c`), make the agent or
   `sd_log` read it, then add a field to `ui_settings_model` with its lock bit.

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
3. **Settings is missing most of the 7.5 list.** Present: language, backend, cache budget, notify, start at sign-in,
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

11. **Shell extension.** PARTLY DONE (round 16, branch `wip/r16-shellext`). Done: **Copy remote path** on drive roots
    and on files and folders inside a ShellDrive drive (state entry `remote_url`, percent-encoded relative path, copied
    to the clipboard in process), the This PC class (`SHX_CLSID_COMPUTER_MENU`: **Mount with ShellDrive** submenu from
    `menu.cache` and **Open ShellDrive**), and the Directory, `*` and This PC registrations (per-user path in
    `DllRegisterServer`). Pure helpers and tests: `shellext_model.c`, `tests/shellext/test_shellext_model.c`. The format of
    `menu.cache` is specified in 03 8.2.2. **Backend missing:**
    - The writer of `menu.cache` (agent or UI): nothing creates the file yet, so the submenu shows the disabled "No
      connections set up" item. Write it atomically, in the 8.2.2 format, on every profile add, rename and delete.
    - `state_producer.c` already copies `remote_url` and the codec sets `HAS_REMOTE_URL`; Copy remote path appears only
      for entries that carry it (global drives of callers outside `service_access` do not).
    - The installer must register the new class (`{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}`) under the This PC CLSID
      key and the Approved list, and the path class under Directory and `*` (HKLM), like the per-user code does.
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

- `host_key_type_unavailable`: the `mount.state` error has only `code`, `detail` and `exit_code`. It has no `host`, no stored
  or offered key types and no fingerprints (agent.c writes them only for `SD_E_HOSTKEY_MISMATCH`). The UI uses the host of
  the mount and names the stored type only if the agent sends `stored_type`; the 5.2 details dialog that lists stored
  types next to the offered ones cannot be built until it does.
- `host_key_mismatch`: the error has `store_path` and `store_line` but no store kind. For PuTTY `store_path` is the registry
  subkey (`known_hosts.c` default_path), while the `sd_hk_result` comment says it is empty; the UI accepts both.
- Legacy and Terrapin: `list` mounts have no security flags and no algorithm names. The `warnings` ring holds the last 32
  warnings of all mounts and nothing removes a mount's entries. The algorithm names come only from the `legacy_algorithms`
  warning event, so a UI that starts after the warning shows the Security column but cannot list the algorithms (the dialog
  says so, and "Don't warn again" is off then). The categories and reasons of the algorithms are derived from their names in
  the UI. A `list` field with the negotiated algorithms and the `legacy` flag (as `profile.test` already returns) would fix it.
- Groups: `list` mounts have no `scope`, and `sd_profile_enum` reads the per-user store only, so no machine template
  (`scope = users`) or service profile reaches the list. "Provided by your organization" and "Global drives" are ready
  (`ui_mv_group_of_scope`) but stay empty until the profile enumeration and the service mounts exist.
- Status bar "Agent not running - Start": no component has a helper that starts the agent (03 1.4 says the UI does). The status
  bar shows the text only.
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

