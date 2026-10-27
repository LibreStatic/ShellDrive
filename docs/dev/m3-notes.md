# M3 notes: IPC contract, prompt routing and the agent methods (WP-A, part 1)

The wire contract is merged into `docs/design/03-apps-platform.md` (§2.1, §2.4, §2.4.1, §2.5, §2.8, §8.2.1). This note
records what changed in the code, what was decided, and what is still open.

## Contract changes

Each item is in the code of this package (sd_ipc, the agent) unless marked otherwise.

- sd_ipc: `sd_ipc_broadcast_count` returns the number of recipients queued, filtered by capability and an excluded
  client. `sd_ipc_broadcast` stays as a void wrapper.
- sd_ipc: `sd_ipc_topic_subscribers` counts hello-completed subscribers of a topic with a capability filter.
- sd_ipc: `subscribe` validates topic names (`[a-z0-9._-]`, at most 23 bytes). Invalid names are dropped from the reply;
  valid unknown names are kept, as before. `on_subscribe` hook in `sd_ipc_server_cfg` runs once per accepted new topic.
- sd_ipc: the hello reply carries `features` from `sd_ipc_server_cfg.features`. The client side exposes
  `sd_ipc_conn_has_feature`. `sd_ipc_client_kind` returns the hello `client` of a connected client.
- sd_ipc: named objects `SD_IPC_OBJ_UI_MUTEX` (`Local\com.librestatic.shelldrive.ui.<SID>`, mutex) and
  `SD_IPC_OBJ_STATE` (`Local\com.librestatic.shelldrive.state.<SID>`, file mapping of 256 KiB). The state section has
  `sd_ipc_state_create` / `sd_ipc_state_open`; both verify the owner and label on the handle and fail closed.
  `sd_ipc_state_open` uses `FILE_MAP_READ | READ_CONTROL`, marked [verify] on XP and 7 (lead decision 2).
- sd_ipc: exit code `secret_not_found` (3) added to the table. `busy` (`SD_E_BUSY`) is exit 8 (03 §6.2, the code that
  `sd_ipc` already maps; existing replies do not move). Exit 10 is `conflict`. The earlier note that proposed 10 is resolved.
- Prompt routing (agent): initiator, then UI subscribers of `prompt` with `prompts.ui`, excluding the initiator (no
  duplicate event). Delivery accounting uses the count of `sd_ipc_broadcast_count`. With no recipient the agent starts
  `shelldrive-ui.exe --prompt-host` (rate-limited to once per 30 s, skipped while the UI mutex is held, a missing
  executable is not an error) and queues the prompt.
- Queue: 16 prompts. The oldest queued prompt is evicted with `prompt.closed` reason `superseded`. A UI that subscribes
  to `prompt` receives the queue oldest first, with `queued: true` and the remaining `deadline_ms`.
- Deadlines: 120 s, or 600 s for a reconnect. A 1 s sweep on the control thread rejects expired prompts with reason
  `timeout` and fails the mount with `prompt_unavailable` (exit 4).
- `prompt.closed` reasons: `answered` (with `answered_by` `cli` or `ui`), `cancelled`, `timeout`, `superseded`. The
  reason is set before the answer reaches sd_mount, so the existing sd_mount callback is unchanged (no change to
  `on_prompt_closed`'s signature was needed).
- Initiator disconnect (lead decision 5): the initiator's prompts are cancelled only when no client with `prompts.ui` is
  subscribed to `prompt`. Otherwise the mount keeps routing to that UI.
- Warnings: `list` gains a `warnings` array (recent warning codes, at most 32). The `mount` copies of `warning` and
  `hostkeys.announced` stay through proto 1 (lead decision 6).
- Methods added: `status` (without `stats`), `config.reload` (user scope), `log.tail` (without `follow`), `selftest`,
  `prompt.list`. `prompt.answer` now takes the answering client's kind into `answered_by`.
- `log.tail`: a ring of 4096 records (about 4.5 MiB), fed by an `sd_log` sink. The cursor is
  `"<pid hex>.<boot tick hex>.<seq dec>"` with `reset` and `dropped` (lead decision 12).
- Test hooks (only in `SD_HOST_TEST_HOOKS` builds): `SHELLDRIVE_TEST_PROMPT_MS`,
  `SHELLDRIVE_TEST_RECONNECT_PROMPT_MS`, `SHELLDRIVE_TEST_PROMPT_QUEUE_MAX` and `SHELLDRIVE_TEST_PROMPT_NO_ROUTE`
  (prompts are queued even when a client could take them, which makes the queue tests deterministic).
  `SHELLDRIVE_TEST_UI_LAUNCH` (default 0 in test builds, `1` enables the launch): the agent starts no prompt UI unless
  it is set. Every test that runs an agent sets it to `0`, so a test run never leaves a `shelldrive-ui.exe` behind.
- Features advertised by this build: `status`, `config.reload`, `log.tail`, `selftest`, `prompt.list`,
  `prompt.queued`.

## Left for later milestones

Not implemented in this package, and not advertised in `features`:

- `refresh` and `cache.clear`: need a VFS metadata-cache and a disk-cache clear entry point (not in `sd_mount`).
- `profile.test`: needs the `test_only` option of `sd_mount` (dependency D-c).
- `mount.attach_info`: needs the WebDAV UNC from `sd_webdav`. Service side is M5.
- `diag.collect`: M4 (10.5).
- `status` details: `stats` (sd_vfs and sd_sftp counters) and `proxy_legs` (the chain is freed after `sd_mount_create`).
- `unmount {force}`: accepted and ignored; the write-behind flush bypass needs an sd_mount entry point.
- `log.tail {follow}` and the `log` topic: M4. `config.changed` and `agent.stopping`: M4.
- `update.check` / `update.apply`: M4 (decision 10). `secret.set` / `secret.delete`: M5 (decision 4).
- Session lock state is not probed before a UI launch (the UI would start while locked and wait for a subscription).
- `config.reload` returns `restart_required: []`; the restart-required keys are not computed yet (decision 9 lists them).
- Snapshot producer (`sd_state` writer, section 8.2.1): the layout is specified, the writer is a later package.
- Service side of prompts (`prompt.answer` for the service, `prompt.list` for admins) and `hostkey.announced.list` on the
  service: M5.

## Tests

- `tests/unit/sd_ipc`: `test_ipc_m3.c` covers topic validation and the subscribe reply, `features` in hello, the
  `on_subscribe` hook, broadcast counts with capability filter and exclusion, per-topic subscriber counts, the new object
  names and the state section create/open with owner checks.
- `tests/apps`: `test_agent_m3.c` runs the agent over the real pipe, against the scripted fake backend:
  UI-only prompts (one copy each, answered by the UI), prompt deadline (injected to 1.5 s), queue eviction and drain on
  subscribe, the initiator-disconnect rule (both branches), and the new methods (selftest, status, config.reload,
  log.tail cursors, list warnings, prompt.list, hello features).
- The CLI is unchanged. Its replies gained only additive fields (`queued`, `deadline_ms` on `prompt.request`,
  `warnings` on `list`, `features` on hello), which the CLI ignores.

## Shell extension (`shelldrive-shellext.dll`, 03 §1.6, §8.2, §8.5)

Code: `apps/shelldrive-shellext/` (COM server, reader, registration), tests: `tests/shellext/`. Strings: `l10n/shell/*.po`.

### What works

- Classic context menu handler (`IShellExtInit` + `IContextMenu`, no `IContextMenu3`, no icons) for drive roots (`X:\`)
  that are ShellDrive mounts in the snapshot. One selected drive root only; any other selection gets no items.
- Items: **Open in ShellDrive** (every entry), **Unmount** (per-user entries not unmounting or unmounted), **Reconnect**
  (per-user entries offline, auth required or failed). Global entries (`GLOBAL` flag) get Open only (8.2.1).
- `GetCommandString`: `GCS_VERBA/W` (machine names `shelldrive.open|unmount|reconnect`), `GCS_HELPTEXTA/W` (catalog
  `shell.help.*`), `GCS_VALIDATEA/W`. The `GCS_*` constants are compared in their ANSI form: with `UNICODE` defined the SDK
  maps `GCS_VERB` to `GCS_VERBW`, so comparing against `GCS_VERB` silently matches nothing.
- `InvokeCommand` accepts a resource offset (`MAKEINTRESOURCE`) or an ANSI verb string naming one of our items (case
  insensitive). It starts `"<dll dir>\shelldrive-ui.exe" --action <open|unmount|reconnect> <X:>` with `CreateProcessW`,
  closes the handles and returns. It never waits and never calls the network or the IPC pipe.
- Registration (`DllRegisterServer` / `DllUnregisterServer`), per user only, under HKCU: `Software\Classes\CLSID\{clsid}`
  (+ `InprocServer32`, `ThreadingModel = Apartment`), `Software\Classes\Drive\shellex\ContextMenuHandlers\ShellDrive`, and
  the `Shell Extensions\Approved` value. Unregister deletes the leaves; shared parents are deleted only when empty.
- Exports: `DllGetClassObject`, `DllCanUnloadNow` (object and lock counts, interlocked), `DllRegisterServer`,
  `DllUnregisterServer` (`shelldrive-shellext.def`). `DllMain` only stores the module handle and disables thread calls.
- Built with `sd_add_dll` (version resource, import audit, ISA audit). Built and tested on x64-modern, x64-xp (Debug),
  x86-ia32 (Release) and x64-analysis: zero warnings, `ctest -R "shellext|l10n|importcheck"` green everywhere.

### Snapshot reader (`shellext_snapshot.c`, interface `shx_snapshot_read(entries, max) -> count`)

- Thin reader of the section layout v1 (03 §8.2.1), written so the lead can replace it with `sd_state`: the rest of the DLL
  only sees `shx_entry` and the count.
- Production open: `sd_ipc_state_open` (fixed name, owner and label checked there, fail closed).
- Seqlock: up to three tries of {read seq (odd = retry), copy the header and `total_size` bytes into a heap buffer, read seq
  again (changed = retry)}. Everything after the copy works on the copy only, so a concurrent writer can never change what is
  parsed. Three failures, a bad header, or a stable bad header are all "no data" (0 entries).
- Validation as in 8.2.1: magic, layout 1 or 2, `header_size >= 64` and not past `total_size`, `total_size` at most 256 KiB
  and equal to `header_size + entry_count * entry_size`, `entry_size` in [1792, 4096] and a multiple of 8, `entry_count <= 128`.
  Per entry: IN_USE set, no bits above 6, letter `A`..`Z` or 0, well-formed UTF-16 in every string slot (no unpaired
  surrogate), `profile_id` empty or 32 hex digits. A bad entry is dropped; unknown `state` and `backend` values read as 0.
- Not done in the reader: bidi and zero-width stripping (no string is displayed by the menu yet), `NEEDS_ADMIN` handling.

### Test hooks (compiled only with `SD_SHELLEXT_TEST`, never in the shipping DLL)

- `SHELLDRIVE_TEST_STATE_NAME`: section name to open instead of the state section. The test variant applies the same owner
  and label checks itself (`GetSecurityInfo` on the handle, mandatory label at least medium).
- `SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE`: when set, `InvokeCommand` writes the UTF-16 command line to this file instead of
  starting `shelldrive-ui.exe`.
- `sd-test-shellext-dll` is the same source built with the define (`shelldrive-shellext-test.dll`); `sd-test-shellext`
  compiles the reader too and loads that DLL from its own directory.

### Tests (`tests/shellext/test_shellext.c`, 17 cases, `unit.shellext`)

- Reader: valid entries and capacity, bad entries dropped one by one, bad headers (nine variants), odd seq (no data),
  missing section, low mandatory label refused, 400 randomly corrupted images (bounded result, no fault).
- COM through the DLL: exports, class factory arguments, items for a mounted drive (ids and texts), failed drive (three
  items, `GetCommandString` in all forms, `E_INVALIDARG` out of range), global drive (Open only), other selections and
  `CMF_DEFAULTONLY` (no items), corrupt snapshot (no items), `InvokeCommand` command lines (resource offset and string
  verb; unknown verb and out of range launch nothing), unload and lock counting.
- Registration: `RegOverridePredefKey` redirects HKCU to a temporary key for the test; the real HKCU keys are checked for
  unchanged existence before and after, the temporary tree is removed.

### Decisions

- The menu shows only what the snapshot says. Reading the section is the only input; nothing is read from the pipe, the
  network or profile files, so the 8.2 "never touches the network" rule holds by construction.
- Explorer-facing code runs under `__try` only in the snapshot read (`sx_fault_filter` catches access violation and in-page
  error, nothing else). COM entry points are plain code.
- Language: `sd_l10n_init(catalog, NULL)` once per process, on first `Initialize` (policy `UILanguage`, then the Windows UI
  language). A second thread waits up to one second for the first to finish. The `settings.ini` language is not read here.
- Global vtables and the factory are static and writable (the SDK declares `lpVtbl` non-const); the factory has no reference
  count of its own.
- Verb strings for `--action` are the names the UI grammar uses; GCS verb names are `shelldrive.*` ASCII identifiers.

### Open items

- **UI grammar:** `apps/shelldrive-ui/ui_wire.c` does not accept `--action open <X:>` yet (its documented verbs are mount,
  mount-file, unmount, reconnect, show). The DLL sends `open E:` for the Open item, so until the UI accepts it the item does
  nothing. This is an additive UI change for the UI package (03 §1.4, §8.2.1).
- **Not implemented from 8.2:** Copy remote path (drive, directory, `*`); the Directory, `*` and This PC registrations;
  "Mount with ShellDrive" under This PC (needs `menu.cache`); menu icons (`hbmpItem`, Vista+).
- **`.sdmount` verb:** the Mount item for `.sdmount` files is the static `HKCR\LibreStatic.ShellDrive.Mount` verb of 8.1, not
  a handler item; no code here (the doc does not list `.sdmount` among the handler registrations).
- **8.6 (IExplorerCommand):** not implemented, as instructed.
- **Architectures (8.5):** registration writes the native view of HKCU only. An x86 DLL on x64 needs the same registration
  in the 32-bit view (`KEY_WOW64_32KEY` / `Software\Classes\Wow6432Node`); the x86 DLL is built and tested but not registered
  by these functions on WOW64.
- **Approved list:** written under HKCU, which is the per-user place. Whether Explorer honours the per-user list under
  `EnforceShellExtensionSecurity` is [verify on Windows 10 and 11]; the installer writes the HKLM list (04).
- **Import floors:** `DisableThreadLibraryCalls`, `ReleaseStgMedium`, `DragQueryFileW` and `InsertMenuItemW` appended to
  `tests/os-imports/xp-sp2-x64.txt` and `xp-sp3-x86.txt` (documentation only, pending the XP lab capture, 04 §11.4). The
  win10 list is whole-DLL and needed no change.
- **Label check in production (TM-R26):** the production open is `sd_ipc_state_open`. Its `ipc_verify_object_owner` checks
  the label only on Vista and later, and when `GetSecurityInfo` refuses the label it falls back to the owner alone. The test
  path applies the stricter rule (label must be absent or at least medium, no fallback). Lead to decide whether
  `sd_ipc` should fail closed when the label cannot be read.
- **Error UI:** a failed launch returns `E_FAIL` to Explorer and shows nothing; the UI's own error path is not reached.
- **Lab:** not run in Explorer. The behaviour inside a real Explorer (menu placement on Windows 11, the classic submenu, drive
  roots only) is untested here and belongs to TST-24.
- **Registry:** nothing was registered in the real registry and Explorer was not restarted; only the redirected test
  registration ran.
