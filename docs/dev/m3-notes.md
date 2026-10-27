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
- sd_ipc: exit code `secret_not_found` (3) added to the table. The contract lists `busy` as an IPC code with exit 10, but
  `busy` is already the sd_err name `SD_E_BUSY` with exit 8 (unchanged, so existing replies do not move). Lead to decide.
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
- Test hooks (SD_HOST_TEST_HOOKS builds only): `SHELLDRIVE_TEST_NO_UI` (no `shelldrive-ui.exe` launch),
  `SHELLDRIVE_TEST_EXPLORER_KEY` and `SHELLDRIVE_TEST_NETHOOD` (test locations for icons and Network locations).

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
  locations (see 8.8); `SHELLDRIVE_TEST_NO_UI` keeps `shelldrive-ui.exe` from starting. `target.lnk` contents and the
  icon on real Explorer are not checked (lab).
- The CLI is unchanged. Its replies gained only additive fields (`queued`, `deadline_ms` on `prompt.request`,
  `warnings` on `list`, `features` on hello), which the CLI ignores.
