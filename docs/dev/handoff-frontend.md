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
3. **Settings is missing most of the 7.5 list.** Present: language, backend, cache budget, notify, start at sign-in,
   updates. Missing: default write mode, credential roaming, "Trust host keys accepted in PuTTY / OpenSSH" with the
   "Ignored: other users can change this file" state (5.1, TM-R06), "Keep host names and file paths out of log
   files" (`[log] privacy = strict`, 10.1), WebClient status, Windows 11 menu status (8.6), linked connections
   (8.7), start tray and agent separately. Backend ok for all that are `settings.ini` keys (direct `sd_config` writes,
   3.6); WebClient/linked-connections status need system queries (backend missing for a shared helper).
4. **Changed key and wrong key type notifications do not lead to the host key manager.** Spec 5.2 and 5.4: the
   `host_key_mismatch` details dialog (old and new fingerprint, store and line of the old key, **Manage host
   keys...**, **Open file location**, "Stop using keys from this source") and the `host_key_type_unavailable`
   notification with **Manage host keys...** (stored vs offered types). The prompt dialog for `hostkey_changed` has
   only Close. Backend ok: `mount.state` carries `error{host_key_*, stored_type, stored_fp, offered_type, offered_fp,
   store_path, store_line}` (2.4). The balloon click (`NIN_BALLOONUSERCLICK`) should open the details dialog.

Priority 2: spec features with a backend, larger.

5. **Main window layout of 7.5**: toolbar with text labels (New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs);
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

11. **Shell extension covers drives only.** `shellext_com.c` has `Open`, `Unmount`, `Reconnect` (8.2 first bullet).
    Missing: **Copy remote path** (drives, directories and files inside a ShellDrive drive; needs the snapshot's remote
    URL), the This PC handler (**Mount with ShellDrive** submenu from `menu.cache`, **Open ShellDrive**), the
    Directory and `*` registrations, drive labels and icons (8.3), Windows 11 modern menu (8.6, needs the certificate),
    network locations (8.7). Backend ok for the snapshot section; the writer of `menu.cache` was not looked for in
    this audit.
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
