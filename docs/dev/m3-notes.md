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

### Contract changes (M3 snapshot producer and Explorer data, WP-A part 2)

- New module `sd_state` (`src/sd_state`): layout v1 codec (encode, copy-then-validate decode), the section writer and
  `sd_state_read_section` (8.2.1, 8.8). Depends on sd_base, sd_platform and sd_ipc only, so the shell DLL can link it.
- Agent: the snapshot section is created before the pipe accepts clients, published on every mount add, state change
  and removal, and emptied with the shutdown flag at exit (`state_producer.c`). Warnings do not publish (no field).
- Agent: drive icons per user (`HKCU\Software\Classes\Applications\Explorer.exe\Drives\<L>\DefaultIcon`), listed in
  `state\explorer.ini`; SHChangeNotify on present changes; Network location folders in NetHood with `desktop.ini`
  `[ShellDrive] profile=` marker and `target.lnk` (`explorer_data.c`, 8.3, 8.7). Labels are not written here (WebDAV
  label stays in `sd_webdav_map`).
- sd_config: profile key `mount.network_location` is parsed (default `yes`, 3.4.1 table) and written back only when set
  to `no` or already present. The table already listed it; the parser did not read it before.
- Floor lists: `GetFileSize`, `FindFirstFileW`, `GetPrivateProfileStringW` and `WritePrivateProfileStringW` added to
  `tests/os-imports/xp-sp2-x64.txt` and `xp-sp3-x86.txt` (XP-era APIs the agent now imports; the lists are per-function
  reviews, so this is the review entry).
- Test hooks (SD_HOST_TEST_HOOKS builds only): `SHELLDRIVE_TEST_UI_LAUNCH` (0 by default: no `shelldrive-ui.exe` launch),
  `SHELLDRIVE_TEST_EXPLORER_KEY` and `SHELLDRIVE_TEST_NETHOOD` (test locations for icons and Network locations).

### Contract changes (M3 agent methods, WP-A part 3)

Implemented in this package and advertised in `features`: `refresh`, `cache.clear`, `profile.test`, `mount.attach_info`,
the status details `status.stats` and `status.proxy_legs`, and the events `config.changed` and `agent.stopping` (03 §2.4,
§2.8). The table rows of 2.4 say what each returns.

- sd_vfs: `sd_vfs_write_behind_bytes` (queued write-behind bytes), `sd_vfs_cache_clear(v, disk_too)` (this mount's memory
  blocks; the disk tier through `vfs_disk_clear`, which skips entries in use). A clear never drops queued write-behind data.
- sd_mount: `sd_mount_refresh`, `sd_mount_cache_clear(m, disk_too, force)` (`SD_E_BUSY` while write-behind data is queued,
  unless forced), `sd_mount_get_stats` (session, vfs, pool members, write-behind bytes), `sd_mount_get_attach` (backend,
  drive, WebDAV loopback port), `sd_mount_stop_ex(m, force)` (a forced stop gives the write-behind drain no budget: what is
  queued is reported as `write_failed`), and `sd_mount_get_probe` for the `test_only` mount of `sd_mount_params`.
  `profile.test` is the `test_only` mount: connect, authenticate, realpath of `remote_path` (`session_probe`), then
  UNMOUNTED with a probe. No vfs, no drive. `sd_mount_backend` has seven new pointers at the end (NULL-tolerant).
  Stats and cache calls count themselves in `m->readers`; the control thread drains them before it frees the session or the
  vfs (no backend call runs under `m->lock`).
- sd_mount: the proxy hops of the chain are copied by the host before `sd_mount_create` (`host_leg`), so `status` reports
  them without the hops being kept.
- sd_ipc: `sd_ipc_defer(client, &id)` inside a handler makes the pipe thread send no reply; `sd_ipc_reply_deferred` sends
  it later from any thread (`profile.test` runs for seconds, prompts included). `sd_ipc_broadcast_all` sends an event to
  every client that completed hello (`config.changed`, `agent.stopping`); the topic `*` is not a valid topic name, so no
  subscription matches it.
- sd_ipc, TM-R26 (lead decision): `ipc_verify_object_owner` fails closed on Vista+ when the label cannot be read; there is
  no owner-only fallback. XP keeps the owner check alone. The decision is `ipc_owner_decision` (exposed as
  `sd_ipc_test_owner_decision` for the unit test).
- Exit codes: `not_mounted` (3) and `write_behind_pending` (8, busy). Clients that do not know these codes exit 1 (the
  table of 6.2 needs the two rows; the CLI mapping and its localized texts are the CLI package's job, see below).
- Agent: `unmount {force}` applies to the first unmount of a mount (a second request does not re-stop it). Test mounts
  are not in `list`, `status`, `unmount`, the snapshot, Explorer data or `mount.state`; their warnings still go to `warning`.
- `config.changed` (`apps/shelldrive-host/config_watch.c`): one thread, two overlapped `ReadDirectoryChangesW` watches
  (the config root for `settings.ini` and the creation of the profiles folder, the profiles folder for `*.ini`), one stop
  event, 500 ms debounce, XP-compatible (no post-XP import). `ids` are read from the changed files with
  `sd_profile_load_file`; a removed profile is not named. Nothing is reloaded in flight.
- `agent.stopping {reason}`: `request` (`agent.shutdown`), `event` (the shutdown event) or `idle`. It goes out at the start
  of the shutdown sequence, after the watch stops; the agent then waits 100 ms so the pipe thread writes it (there is no flush
  call in sd_ipc).
- `status {stats: true}` returns `stats.session` (srtt, rates, byte totals, inflight, queued, channels, generation, reconnect
  attempts), `stats.pool` (`ready`, `wanted`, `members[]` per SFTP connection), `stats.cache` (vfs hits, misses, bytes,
  write_failed, write_behind_bytes, reconnects). The counters are per mount; the process-wide memory tier is not included.

## Left for later milestones

Not implemented in this package, and not advertised in `features`:

- `diag.collect`: M4 (10.5). Not started: the anonymization rules (10.5) and the bundle layout need the lead's review first.
- `log.tail {follow}` and the `log` topic: M4 (2.4.1). `follow: true` stays `unsupported`.
- `mount.attach_info` WebDAV port is read from the fake in the tests; the real `sd_webdav_mount_port` path is not exercised
  by the harness (lab: a WebDAV mount with the WebClient service).
- Service side of `refresh`, `cache.clear`, `profile.test`, `mount.attach_info` and `status stats`: M5 (the service
  mutating methods need the elevated admin check; the non-admin list rules of 2.2 apply to them).
- CLI: done in the M3 profile-keys package (see the section "M3 profile keys, CLI and autostart" below).
- `update.check` / `update.apply`: M4 (decision 10). `secret.set` / `secret.delete`: M5 (decision 4).
- Session lock state is not probed before a UI launch (the UI would start while locked and wait for a subscription).
- `config.reload` returns `restart_required: []`; the restart-required keys are not computed yet (decision 9 lists them).
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
- `tests/unit/sd_state`: round trip, truncation (cut and surrogate-safe), the seqlock reader under a live writer thread
  (never a torn snapshot), a stuck odd seq, every corrupt header field, bad entries dropped, layout skew (v1 reader and
  v2 writer), unknown layouts, the section round trip and a squatted low-integrity section (Vista+; no XP label).
  A foreign-owner squat needs an administrator and is not tested.
- `tests/apps`: `m3_snapshot_and_icon_follow_mount` (section entry and drive icon while mounted, both gone after
  unmount) and `m3_network_location_entries_at_start` (the profile's folder with the marker, `target.lnk` and the
  placeholder; a stale marked folder removed; an unmarked folder kept). All registry and NetHood writes go to test
  locations (see 8.8); test builds never start `shelldrive-ui.exe` unless `SHELLDRIVE_TEST_UI_LAUNCH=1`. `target.lnk` contents and the
  icon on real Explorer are not checked (lab).
- The CLI is unchanged. Its replies gained only additive fields (`queued`, `deadline_ms` on `prompt.request`,
  `warnings` on `list`, `features` on hello), which the CLI ignores.

- M3 agent methods (WP-A part 3): `tests/apps/test_agent_m3.c` (`m3_profile_test_results_and_errors`, `m3_config_changed_and_agent_stopping`, `m3_refresh_cache_attach_and_status_stats`, `m3_cache_clear_refuses_queued_writes`; the agent runs against the fake backend, `SHELLDRIVE_TEST_UI_LAUNCH` stays 0), `tests/unit/sd_mount/test_mount.c` (`mount_m3_*`), and `tests/unit/sd_ipc` (`ipc_deferred_reply_roundtrip`, `m3_owner_label_fails_closed`).

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

- **UI grammar:** resolved: `ui_wire.c` accepts `--action open <X:>` (the profile editor package) and opens the drive
  in Explorer.
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

### M3 profile keys, CLI and autostart (3.4.1, 6.1, 6.2)

Contract changes made in this package. Spec corrections are in 03 §3.4.1 and the changelog at its end.

Profile keys (`src/sd_config/profile_m3.c`, fields in `sd_profile`, parsed and validated; round trip writes a key only
when it differs from its default or is already present; legacy `cache.metadata_ttl`, `directory_ttl`,
`read_cache_disk` are read once and removed on save, `read_cache_memory` is ignored with a log line):

- Applied, with the consumer named:
  - `security.trust` and `mount.shell_active_files`: `block_shell_active` = `shell_active_files` or the D41 default from trust.
  - `mount.hide_dotfiles`, `mount.show_special`, `mount.map_readonly`, `mount.case`, `mount.remote_case`, `mount.umask`,
    `mount.fsync_on_flush`, `mount.fs_name` (Dokany): `sd_vfs_options` through `sd_mount_params.tuning`.
  - `cache.attr_ttl`, `cache.dir_ttl`, `cache.neg_ttl`, `cache.open_revalidate`, `cache.max_readahead`: `sd_vfs_options`.
  - `mount.identity_probe = exec`: `SD_SFTP_OPT_IDENTITY_EXEC` in the sftp options (sd_mount).
  - `mount.autostart = logon` and `mount.autostart_sessions`: the agent starts the mount at its start (`work_autostart`,
    no client, prompts off, no open). `boot` is logged and left to the service (M5).
  - `mount.open_after_mount` and the `open` request of `mount --open`: the agent posts `work_open` at the first MOUNTED of
    a user-initiated mount (never on a reconnect or a logon mount); `ShellExecuteW(..., "explore", "X:\")`. Test builds never
    open a window: they append the drive root to the file named by `SHELLDRIVE_TEST_OPEN_FILE`.
- Parsed only (no consumer, or the consumer refuses the value today):
  - `mount.exec_hint`, `mount.atomic_put`, `mount.strict_acl`: no reader in sd_vfs or sd_webdav.
  - `mount.remote_charset`: `sd_vfs` refuses a non-zero code page (`SD_VFS_E_UNSUPPORTED`), so UTF-8 is used.
  - `mount.mark_of_the_web`: `sd_vfs` refuses it until a later milestone (`SD_VFS_E_UNSUPPORTED`). 02 §1.1 and TST-21 apply.
  - `mount.offline_hint_over_mb`: no reader (`sd_webdav` does not read the field yet).
  - `security.crypto_backend`: `sd_ssh_algo_cfg.crypto_backend` exists but nothing reads it; the mount does not set it.
- M5, parsed and validated only: `profile.scope` (`user | users | service`), `profile.service_access`,
  `profile.service_access_write` (a subset of `service_access`, by name or SID string, ASCII case-insensitive; names are
  not resolved here), `mount.allow_system` (the vfs option stays FALSE in this build, as before).
- Validation: `scope = service` needs `service_access`; `autostart = boot` needs `scope = service`. Bounds: TTLs 1 ms to 1 h,
  `open_revalidate` 1 ms to 1 h or `never`, `max_readahead` 64 KiB to 1 GiB, `umask` 001 to 777 (octal), `offline_hint_over_mb`
  up to 1048576. Zero is refused where the vfs would read it as its default.
- Behaviour change: `hide_dotfiles`, `map_readonly` and `fsync_on_flush` default to yes, so the mounts now hide dot files
  and map read-only bits by default (the agent passed FALSE before).

Agent and IPC:

- `refresh`, `cache.clear`, `profile.test`, `status {stats}` and `mount {open}` are the existing methods; this package adds
  the `open` boolean to `mount` (ignored by `profile.test`). Nothing new was added to `features`.
- `not_mounted` (exit 3) and `write_behind_pending` (exit 8) are in `sd_ipc_exit_code_for_code` since M3 and now have CLI texts.

CLI (`apps/shelldrive`, new file `cli_cmds3.c`):

- `refresh <X:|X:\path>`: `refresh` IPC; drive letters only (folder targets need Dokany folder mounts).
- `cache clear [<profile>|X:|m-N] | --all [--force]`: `cache.clear`. Without an agent, `--all` reports 0 and a named
  target is `mount_not_found`.
- `profile test <profile>`: `profile.test` on a worker thread; the main thread answers `prompt.request` events of the
  connection (the same `handle_prompt` as mount). Result lines are localized; `--json` prints the reply.
- `status --stats` and the `stats <X:>` alias: `list`, then `status {mount_id, stats: true}` per matching mount.
- Exit codes: `not_mounted` (3) and `write_behind_pending` (8) have localized texts. Spec 6.2 lists both.
- New strings (19 msgctxt ids, all six locales, `cli.*`): see `l10n/cli/en.po` (the `M3` block). sdl10n: Spanish,
  French, Italian and Portuguese plurals have three forms, German and English two (the checker's rule).

Tests:

- `tests/unit/sd_config/test_config_m3.c`: defaults, every M3 key's values and bounds (49 cases), umask octal, the derived
  shell-active default, legacy names, round trip.
- `tests/apps/test_cli_m3.c` (`cli_parse_m3_commands`): refresh, cache clear, profile test, status --stats, the stats alias,
  mount --open, and the option limits per command.
- `tests/apps/test_agent_m3.c` (`m3_autostart_and_open_after_mount`): the logon autostart and the session check (read from
  the agent log through `log.tail`), no autostart for `autostart = no`, and one open of the drive root after the first
  MOUNTED of a user mount. No Explorer window is started.

Open items:

- The lab check of `open_after_mount` on a real Explorer and of `ShellExecuteW` on XP (TST, not run here).
- `profile test` prompts: exercised only through the agent test harness, not with the real console prompt.
