# M5 notes

## Scope of this branch (`wip/r7-svc`, part 1)

The service core of `shelldrive-host.exe service` (03 §1.3, §2.2, §2.6, §3.2, §4.5; D6, D17, D35), the global
mount path through `sd_mount` and Dokany, the service pipe methods, the `shelldrive service` CLI verbs and the tests.
Not in this part: the global WebDAV spike (D11), the elevated admin UI and the tray attention flow (03 §2.6 rule 3,
UI side), `hostkey add --machine --from-server`, the SCM install/uninstall/start/stop/repair-data verbs, and the
items listed under "Left" below.

## Files

| Path | What |
|---|---|
| `apps/shelldrive-host/service.c`, `service.h` | service core: `svc_run` (one core for the SCM and the console), SCM dispatch and control handler, `service-debug` console mode, pipe handlers, machine profile loading, mount records and their control-thread jobs, prompt routing, secrets |
| `apps/shelldrive-host/svc_access.c`, `svc_access.h` | pure rules: the decision table (`svc_decide`), list resolution (`svc_acl_build`), profile refusals (`svc_validate_profile`), volume SDDL (`svc_volume_sddl`), identity path rule |
| `apps/shelldrive-host/main.c` | `service` and `service-debug` modes |
| `apps/shelldrive/cli_service.c` | `shelldrive service list | mount | unmount | status` |
| `l10n/svc/*.po` | service strings (`svc` domain, six locales) |
| `tests/unit/sd_svc/` | `sd-test-svc.exe`: pure rules and the in-process core with the fake backend (`unit.svc`) |

## Contract changes

Changes to shared interfaces made in this branch. Additive unless stated.

**sd_ipc (03 §2.2, §2.4)**

- `sd_ipc_server_cfg` gets a new last member `topic_allowed` (`int (*)(void *ctx, sd_ipc_client *, const char *)`).
  Called for every valid topic of a `subscribe` request before anything is subscribed; `0` refuses the whole request
  with `access_denied`. The service uses it for `prompt`, `log` and `hostkeys` (elevated admins only, TM-R25).
- New `sd_ipc_client_member_of(client, PSID, int *member)`: whether the client's token has the SID enabled (or is
  the client's own user SID). Pipe thread, from a handler only (the client is impersonated for the check). Fails
  closed.
- New test hook `sd_ipc_test_set_service_owner(sid)`: creates the service pipe with that owner instead of `S-1-5-18`
  (an unelevated test process cannot give a pipe the SYSTEM owner). The DACL is unchanged. Never set by shipping code.
- Service pipe limits in this build: one 64 KiB request cap for every client (03 §2.2 says 1 MiB for elevated admins);
  `max_per_sid` 4, `max_requests_per_sec` 10 and `idle_timeout` 60 s as in 03 §2.2.
- Service `hello` features: `list`, `status`, `mount`, `unmount`, `selftest`, `secret.set`, `secret.delete`,
  `prompt.list`, `prompt.answer`, `config.reload`, `prompt.routing`.

**sd_mount (03 §1.11)**

- `sd_mount_params` gets `global_mount`, `volume_sd`, `volume_sd_len` (last members). A global mount has no
  `DOKAN_OPTION_CURRENT_SESSION` and must carry the volume security descriptor; without it `sd_mount_create` returns
  `SD_E_INVALID_PARAM`.
- The `sd_vfs_options.global_mount` flag is set from the params.

**sd_dokan (02 §6.4)**

- `sd_dokan_mount_start` accepts `global_mount` (it was refused with `SD_E_UNSUPPORTED` before M5). It requires
  `volume_sd`.

**tests/unit/sd_mount (test helper, not shipped)**

- `fake_backend_pre_trust(host)`: marks a host trusted as if its key had been stored, so service tests can mount
  without a TOFU prompt.

**CLI (03 §6.1, §6.2)**

- New command word `service` (`CLI_CMD_SERVICE`). Verbs: `list`, `mount <profile>`, `unmount <profile|X:>`,
  `status <profile|X:>`. `install`, `uninstall`, `start`, `stop` and `repair-data` are parsed and exit 1 with a
  localized "not part of this build yet".
- Exit codes: 9 for `mount` and `unmount` from a console that is not elevated (no self-elevation, 6.1); 8 when the
  service pipe is unreachable (`service_not_installed` spelling); the IPC error code's exit code otherwise.
- `shelldrive help service` and the general help list gain the `service` line.

**Service error codes (IPC, 6.2 spellings)**

Used by the service and mapped by the CLI through the existing table: `access_denied`, `not_mounted`,
`profile_not_found`, `already_mounted`, `target_in_use`, `prompt_unavailable`, `host_key_unknown`,
`secret_not_found`, `usage` (refused profile, with the offending key in `detail`). No new error code was added.

**Events (03 §2.4)**

- `mount.state` on topic `mount` carries only `mount_id`, `target` and `state` for every subscriber (the full data is
  in `status`, admins only). `prompt.request`, `prompt.closed` on topic `prompt`; `attention {count}` on topic
  `attention` whenever the number of open routed prompts changes (0 included), and once to each new subscriber with
  the current count. `prompt.list` entries carry the `prompt.request` fields (`kind` is the name, not a number).

## Decisions taken in this part

- A global mount is Dokany only (`backend = auto` and `dokan` are the same; `webdav` is refused with `usage`,
  `mount.backend`). The WebDAV spike (D11) decides the others later.
- No trust on first use for the service (03 §2.6 rule 2): a TOFU host-key prompt is refused with `host_key_unknown`
  even when an admin UI is subscribed. Admins pin keys first.
- Password and passphrase prompts go to an elevated admin that subscribed to `prompt` with the `prompts.ui`
  capability. With none, the mount fails with `prompt_unavailable`. A routed prompt that is not answered within
  120 s is rejected by the control thread.
- Service mounts never save a secret they were given (`can_save` is false).
- A failed mount keeps its record and drive letter until someone unmounts it (03 §1.11). `list` and `status` show it.
- `service_access` is resolved to SID strings when the machine profile is loaded (names through
  `LookupAccountNameW`, resolved at run time). An unresolved name drops the profile (fail closed).
- Access, decided per caller token (`svc_decide`): the letter is always visible; state is visible to members of
  `service_access` and to elevated admins; details (host, user, remote path, last error) and every admin method need
  an elevated admin. `use` needs membership; `write` needs membership and (`service_access_write` or elevated admin).
  An admin outside `service_access` manages the drive but does not use it (D35).
- The volume security descriptor is built from the resolved lists: SYSTEM and Administrators full control, each
  access SID `FRFX`, each write SID `FA`, inherited to containers and objects.
- Machine secrets are DPAPI files under `service\secrets\` (service scope, `CryptProtectData` in the process user scope;
  under the service that is LocalSystem, no `CRYPTPROTECT_LOCAL_MACHINE`). Only `password` secrets are accepted in this
  part; the tests exercise the round trip in the test user's scope (LocalSystem decryption is a lab item).
- Test hooks: `SD_SVC_TEST_HOOKS` (compiled into `sd-test-svc` and `sd-test-host-fake` only) enables `svc_opts.test_all_admin`,
  which treats a client whose hello kind is `testadmin` as an elevated admin. Every other client, including the
  restricted-token client, gets the real check.
- Import and ISA floors: `LookupAccountNameW` is resolved at run time (not on the static floor list); the CRT
  `wcsstr` is not used (it has SSE code, forbidden in the x86-ia32 flavour).

## Tests and verification

| Check | Result |
|---|---|
| `x64-modern` Debug, full build | clean, zero warnings |
| `x64-modern` ctest, default labels (`-LE "matrix|bench|interop|repro"`), 76 tests | all pass |
| `unit.svc` (`sd-test-svc.exe`), 16 tests | all pass: attention count on change and on subscribe (`svc_attention_counts_the_open_prompts`), decision table, list resolution, profile refusals, volume SDDL parses, identity path rule, core start and selftest, profile loading (D17), non-admin restricted token refused for every admin method and for the topic gate, admin mount/status/unmount, prompt refused without UI (`prompt_unavailable`), TOFU refused (`host_key_unknown`), password prompt answered over the pipe, DPAPI secret round trip, list visibility for restricted tokens, stop with nothing left behind |
| `x64-xp` Debug, `shelldrive-host` and `shelldrive` | clean; XP SP2 x64 import audit passes |
| `x86-ia32` Debug, `shelldrive-host` and `shelldrive` | clean; IA32 ISA audit passes |

The tests run in-process: no SCM registration, no child process, no real drive. The restricted-token tests need the
interactive-user ACE on the pipe (they accept a refused connect as the refusal).

## Part 2: service registration and Event Log

**Files**

| Path | What |
|---|---|
| `apps/shelldrive-host/svc_scm.c`, `svc_scm.h` | `shelldrive service install | uninstall | start | stop`: the rules (elevation, order of the SCM calls, rollback) over a function-pointer seam (`svc_scm_ops`); `svc_scm_real_ops` is the only code that calls advapi32 and HKLM |
| `apps/shelldrive-host/svc_events.mc` | Event Log message table, English only (10.3). `mc.exe` writes `svc_events.h` and `svc_events.rc` into `generated/svc_events/<config>`; the `.rc` is linked into `shelldrive-host.exe`, which is the event message file |
| `apps/shelldrive-host/service.c` | Event Log events from the core (start, stop, start failure, mounted, unmounted, mount failed) through `svc_opts.event`; the SCM path sets it to `svc_eventlog_write` (`ReportEventW`) |
| `apps/shelldrive/cli_service.c` | the four verbs; `repair-data` is still "not part of this build" |
| `tests/unit/sd_svc/test_scm.c` | 12 tests against a fake SCM; no test calls `svc_scm_real_ops` |

**Contract changes**

- `svc_opts` gets `event` and `event_ctx` (`svc_event_fn`). NULL means no Event Log writes: console mode and the unit
  tests. Additive.
- CLI: `install`, `uninstall`, `start` and `stop` now run (no longer "not part of this build"). Exit codes: 9 when
  not elevated (`ERROR_ACCESS_DENIED`, the same as `mount`), 1 for the other SCM errors (`already_installed`,
  `not_installed`, `already_running`, `not_running`, `scm_failed` with the Win32 code), 0 on success.
- New CLI strings (cli domain, six locales): `cli.service.installed`, `uninstalled`, `started`, `stopped`,
  `already_installed`, `not_installed`, `already_running`, `not_running`, `scm_failed`, `description`.
  `cli.help.service` lists the new verbs.

**Decisions taken in this part**

- Registration (`CreateServiceW`): LocalSystem (null start name), `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_AUTO_START`,
  dependency `Tcpip` only (1.3). Failure actions: restart after 5 s, 30 s, then 5 min; the count resets after one day.
  `SERVICE_SID_TYPE_UNRESTRICTED` only on Vista and later (checked with `GetVersionExW`); XP skips it.
- Installation order: create, description, failure actions, SID type, Event Log source. A failure after create deletes
  the service again. A failed `register` does not unregister the source (it was not ours to remove). An existing
  service is not touched.
- Uninstall stops the service (a service that is not running is fine), deletes it, then removes the Event Log source
  key. A missing source is not an error. Secrets are not removed here; that stays with the installer (4.7).
- Event source `ShellDrive` under `...\Services\EventLog\Application\ShellDrive`: `EventMessageFile` is the path of
  `shelldrive-host.exe` (REG_EXPAND_SZ), `TypesSupported = 7` (DWORD).
- Start waits up to 30 s for `SERVICE_RUNNING`; stop waits up to 60 s for `SERVICE_STOPPED`.
- Event IDs (10.3): 1000 started (`%1` version), 1001 stopped, 1100 mounted (`%1` profile, `%2` target),
  1101 unmounted (same inserts), 2100 mount failed (`%1` profile, `%2` IPC code, `%3` detail), 2110 start failed
  (`%1` reason). Deviation from 10.3: 1100 has no host name (`%3` in the design) so that no server name reaches the
  Event Log by default (settings.log_privacy). 3100 (configuration invalid) is not emitted yet.
- The description is localized at install time in the language of the installing console (cli domain); it is written
  once with `ChangeServiceConfig2W`. The display name is the English product name, not an indirect string.
- The `svc` domain has no new strings: the service writes no user-facing text in this part.

**Tests and verification**

| Check | Result |
|---|---|
| `unit.svc` (`sd-test-svc.exe`), 27 tests: the 15 of part 1 and 12 new fake-SCM tests in `test_scm.c` (install order and spec, SID type per OS, refusal without elevation, rollbacks, existing service, uninstall order, missing service and source, start/stop elevation and results, host spec) | all pass in `x64-modern`, `x64-xp`, `x86-ia32` (Debug) |
| `svc_core_stops_and_leaves_nothing_behind` also checks the Event Log sink order: 1000 first, mounted, unmounted, mount failed, 1001 last | pass |
| `x64-modern` Debug, ctest `-LE "matrix|bench|interop|repro"`, 76 tests | 75 pass; `unit.crypto_pk` hits its 300 s ctest timeout on this machine (it does not link any service code; unchanged by this part) |
| `x64-xp` Debug, ctest, 76 tests | all pass; XP SP2 x64 import audit passes (`DeleteService` and `QueryServiceStatus` added to the floor list, both documented from Windows 2000) |
| `x86-ia32` Debug, ctest, 97 tests | all pass; IA32 ISA audit passes |

Build notes: `mc.exe` runs on the `.mc` file in ANSI mode (no `-u`; the file is ASCII and has no comments, because mc
copies comment lines into the generated header). The message file is `MSG00409.bin` (named after the English LCID).

## Part 3: service status and repair-data

**Files**

| Path | What |
|---|---|
| `apps/shelldrive-host/svc_scm.c`, `svc_scm.h` | `svc_scm_status` (the rules, over the seam) and `svc_path_check_of`; the seam gets `query_service` and `query_source` (read-only); `svc_scm_real_ops` fills them |
| `apps/shelldrive-host/svc_repair.c`, `svc_repair.h` | `svc_repair_data`: the machine data folder repair over a base folder, with the owner rule and the extra-ACE seam |
| `apps/shelldrive/cli_service.c` | `service status` (no argument) and `service repair-data`; `service status <profile|X:>` is still the drive status |
| `tests/unit/sd_svc/test_scm.c` (6 new), `test_repair.c` (8 new) | the status rules against the fake SCM; the repair on a temp folder under `%TEMP%` |
| `l10n/cli/*.po` | 26 new `cli.service.*` entries per locale (status, state and start type words, repair messages); `cli.service.unimplemented` removed; `cli.help.service` lists `repair-data` |

**Contract changes**

- `svc_scm_ops` gets `query_service` and `query_source` (last members, additive). The fake fills them in the tests.
- CLI: `service status` with no argument reports the service; exit 0 whenever the facts could be read, also when the
  service is not installed. A failed SCM query is exit 1. `service repair-data` is exit 9 without elevation (before
  anything else), 0 on success, 1 when the base is a link or a Win32 call fails.
- JSON (`--json`), English keys: `installed`, `state` (`running`, `stopped`, `starting`, `stopping`, `paused`,
  `unknown`, `not_installed`), `start_type` (`automatic`, `manual`, `disabled`, `unknown`), `program` (`path`, `check`:
  `ok`, `unquoted`, `other`, `unknown`), `event_source` (`state`: `registered`, `missing`, `other`, `unknown`;
  `message_file`), `pipe` (`null` unless running; else `reachable`, `healthy`, `global_drives`, `prompts`).
  `repair-data --json`: `moved`, `moved_to`, `folders`.

**Decisions taken in this part**

- The program check is exact: the registered ImagePath must equal this install's `"<dir>\shelldrive-host.exe" service`
  (case-insensitive). An unquoted path is its own result, because an unquoted service path is refused. The Event Log
  source is `ok` only when its `EventMessageFile` is this install's `shelldrive-host.exe`.
- Status of a running service asks the pipe: `selftest` for the layout (`healthy`), `list` for the global drives
  (visible ones plus the reserved letters), and the content-free `attention` count for the open administrator prompts.
  Subscribing to `attention` needs no elevation, so the count is shown to every user, not only admins. No new service
  method was added.
- `repair-data` works on the machine tree in this order: the vendor folder `LibreStatic` (its own DACL only), then
  `ShellDrive` with the whole tree scanned (a link, a foreign-owned folder, an unreadable entry or more than 20000
  entries makes the tree untrusted: fail closed), then the subfolders and stores at their 3.2 DACLs. An untrusted
  folder is renamed to `<name>.untrusted-<n>` (a link is renamed itself, never followed) and a fresh one is created;
  nothing from the renamed folder is imported. A link in the base folder itself refuses the repair (nothing changed).
- Every check and every security change goes through one handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`:
  `GetFileInformationByHandle` and `GetSecurityInfo` for the owner, `SetSecurityInfo` for the DACL. Folders created by
  the repair get the default owner of the creating token (Administrators under UAC, SYSTEM under the service); the
  DACL text is not given an explicit owner, which keeps the XP and non-elevated paths simple.
- The owner rule (shipping): SYSTEM or BUILTIN\Administrators (`IsWellKnownSid`). The tests replace it with a seam
  that trusts every owner or none, and the owner rule itself is tested with the well-known SIDs.
- The seam `extra_ace` (`svc_repair_ops`) is NULL in the shipping build. The tests set `(A;OICI;FA;;;OW)` so the
  non-elevated test process, which owns the folders it creates, can build and remove the tree.
- The repair does not stop the service. A running service that holds `service.log` open makes the rename fail
  (sharing violation); the error is reported and nothing is changed. Stopping the service first is the documented way.

**Tests and verification**

| Check | Result |
|---|---|
| `unit.svc` (`sd-test-svc.exe`), 42 tests: the 28 of parts 1 and 2 (`main.c` lists 28 at the previous commit), 6 status tests in `test_scm.c` (missing service and source, our install as ok, unquoted and foreign paths, host program missing gives UNKNOWN, query failures passed through, the exact path check; none records a call) and 8 repair tests in `test_repair.c` (empty base builds the tree, sound tree kept, junction at `logs` moved aside and the sentinel untouched, junction at the vendor folder, untrusted owner moved aside and nothing imported, link as the base refused, missing base, owner rule with well-known SIDs) | pass in `x64-modern`, `x64-xp`, `x86-ia32` (Debug) |
| `x64-modern` Debug, ctest `-LE "matrix|bench|interop|repro"`, 76 tests | 76 pass (`unit.crypto_pk` passed this time) |
| `x64-xp` Debug, ctest, 76 tests | 76 pass; XP SP2 x64 import audit passes after `IsWellKnownSid`, `QueryServiceConfigW` and `lstrcmpW` were added to `xp-sp2-x64.txt` and `xp-sp3-x86.txt` (documented from Windows 2000 or earlier) |
| `x86-ia32` Debug, ctest, 97 tests | 96 pass, 1 skipped (`dokany.mount`, always skipped under WOW64); IA32 ISA audit passes |
| `sdl10n` (build) | the six `cli` catalogs are complete for the new entries (every CLDR form for es, fr, pt-BR, it; two forms for en, de) |

The tests never query or change a real service and never touch the real `%ProgramData%`; the repair tests use a folder
under `%TEMP%` that they create and remove, and they need no elevation.

Manual check (read-only, not elevated, no service installed on this machine): `shelldrive service status` prints
"The ShellDrive service is not installed." and "The Event Log source is not registered." and exits 0;
`shelldrive --json service status` gives `installed: false`; `shelldrive service repair-data` exits 9 without changing
anything.

## Part 4: machine folder check at start and Event 3102

**Files**

| Path | What |
|---|---|
| `apps/shelldrive-host/svc_folder.c`, `svc_folder.h` | the machine folder trust check shared by the service start and `svc_repair`: open with `FILE_FLAG_OPEN_REPARSE_POINT`, reparse point, kind, owner (`GetSecurityInfo` on the handle); the shipping owner rule (SYSTEM or BUILTIN\Administrators, `svc_folder_owner_shipping`); reason text for the event |
| `apps/shelldrive-host/service.c`, `service.h` | `svc_ensure_layout` checks each existing machine folder through `svc_folder` (the vendor folder too, default location only); the first refusal is logged and written as Event 3102; `svc_opts.owner_trusted` (NULL = shipping rule) |
| `apps/shelldrive-host/svc_repair.c` | uses `svc_folder` instead of its own open/owner code (same rules, same results) |
| `apps/shelldrive-host/svc_events.mc` | message 3102 (warning): `%1` folder, `%2` reason |
| `tests/unit/sd_svc/test_service.c` | fixture trusts every owner (the temp folders belong to this process); one new core run refuses the root on owner and checks the 3102 insert strings and that nothing was created |
| `tests/unit/sd_svc/test_repair.c` | one new test: reparse point, file where a folder belongs, owner decision, store file (no owner rule), missing path |
| `tests/unit/sd_svc/main.c`, `CMakeLists.txt` (`sd_svc`, `shelldrive`, `shelldrive-host`) | the new tests; `svc_folder.c` is compiled into the three targets |

**Decisions taken in this part**

- At start the service stays idle (no repair) when a machine folder is a reparse point or its owner is not SYSTEM or
  Administrators. The check order per folder: open (never follows a link), reparse point, folder kind, owner. An
  existing folder that cannot be opened or checked is refused too (reason `acl`). A missing folder is created with its
  3.2 DACL as before.
- Checked at start: `%ProgramData%\LibreStatic` (default location only), `ShellDrive`, `logs`, `profiles`, `service`,
  `service\secrets`, `service\keys`. Store files (`known_hosts`, `settings.ini`) are not checked at start, as before.
- Event 3102 is written once per start, for the first refused folder: `%1` the folder path, `%2` the reason. Its
  severity is Warning. The message is English only (10.3, and AGENTS.md: event log payloads are English).
- The reason vocabulary is `owner`, `reparse_point`, `acl` plus `not_directory` for a file where a folder belongs;
  10.3 lists all four.
- Tests never write to the Event Log: the sink is a seam (`svc_opts.event`). Tests never touch `%ProgramData%`.
- The owner seam (`svc_opts.owner_trusted`) is for tests only in practice: the SCM path leaves it NULL.

**Tests and verification**

| Check | Result |
|---|---|
| `unit.svc` (`sd-test-svc.exe`): new `svc_refuses_a_machine_folder_with_a_foreign_owner_at_start` and `folder_check_reports_reparse_kind_and_owner`; `svc_core_stops_and_leaves_nothing_behind` also checks that no 3102 was written for the trusted fixture | pass (x64-modern Release and Debug) |

The reparse-point start refusal (a junction at a machine folder) has the same code path as the owner refusal and the
shared check tests, but no end-to-end test of its own (the junction helper lives in `test_repair.c`).

## Part 5: hostkey add and the machine gate (partial)

Found on this branch: there was no `hostkey add --from-server` in any scope (per-user or machine). `hostkey
accept-announced` existed for the per-user store only (agent IPC). The service pipe has no `hostkey.*` method, and
`service.c` only logs announcements (`svc_on_hostkeys`). The CLI has no SSH connect of its own: `sd_ssh_conn_create` is
used by `sd_sftp` alone. So the connect-and-store part below is not built; this part adds the command surface and
the elevation rule.

**Files**

| Path | What |
|---|---|
| `apps/shelldrive/cli_args.c`, `cli.h` | `hostkey add --from-server host[:port] [--type T] [--expect SHA256:...]`, the `--machine` option (hostkey add and accept-announced only), `--from-server` and `--expect` (hostkey add only); the parse checks |
| `apps/shelldrive/cli_cmds2.c` | `hk_add`, the machine gate on `accept-announced --machine`; the not-built answer |
| `apps/shelldrive/cli_cmds.c` | help: the `hostkey add` line, the three options |
| `apps/shelldrive/cli_common.c`, `cli_int.h` | `cli_is_elevated()` (moved from `cli_service.c`, which now calls it) with the test seam below |
| `l10n/cli/*.po` | 5 entries per locale: `cli.help.opt_from_server`, `cli.help.opt_expect`, `cli.help.opt_machine`, `cli.hk.need_admin`, `cli.hk.not_built` |
| `tests/apps/test_cli_args.c`, `test_smoke.c`, `main.c` | `cli_parse_hostkey_add_machine` (parser), `smoke_hostkey_add_machine` (exit codes and text through `sd-test-cli.exe`) |

**Behaviour**

- `hostkey add` without `--from-server`, with a bad host, a bad `--expect` (must be `SHA256:` plus base64 characters)
  or with a positional argument: usage, exit 2.
- `hostkey add --machine` and `hostkey accept-announced <id> --machine` from a non-elevated console: exit 9, the
  localized "needs an elevated console" line (JSON: `access_denied`). Nothing is read or written.
- Elevated, or without `--machine`: exit 1 with "not part of this build yet" (JSON: `not_implemented`). Nothing is written.
- `--machine`, `--from-server` and `--expect` on any other command: unknown option (exit 2). `--machine` before the
  command word is accepted, as the other global options.

**Test seam**

`SHELLDRIVE_TEST_ELEVATED=0` makes `cli_is_elevated()` report a non-elevated token (the same style as the other
`SHELLDRIVE_TEST_*` variables). Only the value `0` is read, so a test can deny elevation but cannot grant it.
The elevated path is not exercised by any test.

**Not done (open)**

- The connect: the verified connection with the stored key types only (01 §4.3, TM-R04), `sd_ssh_conn_fetch_hostkeys`
  for the other types (exists since M2, no caller yet), the fingerprint confirmation and `--expect`, and the write.
- Where the machine store is written from: through the service pipe (new `hostkey.*` methods, the service serves
  `hostkey.announced.list` and `.accept` as 5.6 describes) or by the elevated CLI directly (`sd_known_hosts` on the
  `%ProgramData%` store, with the 3.2 owner rule). 03 §2.6 rule 2 says the elevated CLI "connects through the
  service", so the service-pipe route is the one to build.
- `hostkey list --announced --machine`; the service's announcement store (`service.c` only logs, Event 2300 is not written).
- Per-user `hostkey add --from-server` (the same connect path without `--machine`).

## Part 6: per-user hostkey add (`wip/r13-hkuser`)

Part 5 left `hostkey add --from-server` without `--machine` as "not part of this build". This part builds the
per-user path: the agent connects, the CLI asks. The machine store (`--machine`) is unchanged: still exit 1 when
elevated, exit 9 when not.

**Files**

| Path | What |
|---|---|
| `src/sd_mount/include/sd_mount/sd_mount.h` | `sd_mount_hk_fetch` (verified, lookup name, keys), `sd_mount_hostkey` moved above the backend table, the new backend member `hostkeys_fetch` (last, NULL in old fakes), `sd_mount_hostkeys_fetch()` |
| `src/sd_mount/mount.c` | `sd_mount_hostkeys_fetch()`: the core shared by the agent and, later, the service. Validates the host, sets the lookup name, calls the backend, rejects more than 8 keys |
| `src/sd_mount/mount_real.c` | `real_hostkeys_fetch`: returns `SD_E_UNSUPPORTED` (see "Not done") |
| `apps/shelldrive-host/agent.c` | `hostkey.add` (`handle_hostkey_add`, dispatched in `ipc_handler`) |
| `apps/shelldrive/cli_cmds2.c` | `hk_add_user` (the question and the answer; the agent is started on demand through `connect_agent`), `hk_accept_offer`, `print_applied`; `hk_add` routes `--machine` as before |
| `apps/shelldrive/cli_args.c`, `cli_cmds.c` | `--stdin` is accepted by `hostkey add` (answers the question from standard input, as for mount); help line |
| `tests/apps/host_fake_backend.c` | `hostkeys_fetch` scripted by the host name (below); `kh_apply_hostkeys` writes the real user store under the test root |
| `tests/apps/test_smoke.c`, `main.c` | `smoke_hostkey_add_offers` (new, at the end of the file); `smoke_hostkey_add_machine` checks the user-add exit codes too (the agent is started on demand and stopped at the end) |
| `l10n/cli/*.po` | 4 entries per locale: `cli.hk.add_none`, `cli.hk.add_offer` (plural), `cli.hk.add_first_question`, `cli.hk.add_choices` |

**IPC method `hostkey.add {host, port, lookup, type?, expect?}`** (user agent pipe, no capability, like
`hostkey.announced.*`; not on the service pipe yet). `lookup` is the known_hosts name the CLI computed (`host`, or
`[host]:port`). The agent:

1. connects through the backend (`sd_mount_hostkeys_fetch`): offering only the stored key types of the host (TM-R04),
   the other host keys inside that connection (or only `type`). The agent recomputes every fingerprint from the blob
   and drops keys of other types than `type`;
2. with `expect`: stores only the key whose SHA-256 fingerprint is `expect` (user store, add only), no question. No
   match: `host_key_mismatch` (exit 6) when the host is verified by a stored key, `host_key_rejected` (exit 5) on first
   contact. Reply `{host, lookup_name, verified, added: 1, removed: 0, keys[]}`;
3. without `expect`: keeps the keys as an announcement (`a-<n>`, the same list as `hostkey.announced.list`) and replies
   `{host, lookup_name, verified, keys[{type, fingerprint}], id}`. No keys: no `id`.

The CLI then asks and, on yes, calls the existing `hostkey.announced.accept {id, add_only: true}`. So the store write,
the removal rule and the `# updated-by` comment are the ones of 5.6. A refused offer is not deleted: it stays in
`hostkey list --announced` like an announcement left at "Not now" (there is no reject method).

**Behaviour (CLI, `hostkey add --from-server host[:port] [--type T] [--expect SHA256:...]`)**

- `--expect` given: stored with no question, the "Updated the host keys" line, exit 0.
- Verified host (a stored key matched): "<host> also has N other host key(s). Add it?" with each key listed, then
  `[y]es, [N]o:`. Yes stores them; anything else exits 5 (`host_key_rejected`).
- First contact (no stored key, 5.2): the "authenticity can't be established" text with the presented key and its
  fingerprint, `Add this key? [y]es, [N]o:`. Yes stores it (the trust decision); no exits 5.
- `--json` only offers (no question): the reply holds the `id` for `hostkey accept-announced <id> --add-only`.
- The server offers nothing new (or nothing of `--type`): "has no other host keys to add", exit 0.
- `--stdin` reads the answer from standard input (as mount does). Without it and without a console the question gets
  no answer and the offer is refused (exit 5).
- No agent running: the CLI starts it, as mount does; if that fails, `agent_unavailable` (exit 8).
- `--machine`: unchanged (exit 9 without elevation, exit 1 with it).

**Test seam**

`sd-test-host-fake` scripts `hostkeys_fetch` by host name: `*.known.test` verified (ECDSA and ssh-rsa besides the
stored key), `*.changed.test` a mismatch, any other name a first contact with one ssh-ed25519 key. The keys are
synthetic blobs (the fingerprints are real SHA-256 of those blobs). The fake is wrapped in `host_fake_backend.c`,
so `tests/unit/sd_mount` is unchanged. Its own `kh_apply_hostkeys` only counts, so the wrapper writes the user store
through `sd_known_hosts` under the test configuration root; the tests read the keys back with `hostkey list`.

Result of the last run (`ci-local -Presets x64-modern -ReleaseOnly -TestRegex unit.apps|unit.ssh|unit.ipc`): all five
groups pass. `smoke_hostkey_add_offers` is new; `smoke_hostkey_add_machine` now also checks the user-add exit codes.

**Finding that blocks the real connect**

`sd_ssh` reaches `SSH_ST_CONNECTED` only after user authentication (`ssh_on_authenticated`, conn.c). `fetch_hostkeys`
requires that state (hostkey_update.c, `fetch_run`), and `hostkeys-prove-00` is sent only after authentication too. So
a connect that offers only the stored key types can still not collect the other keys without credentials, and
`hostkey add --from-server host[:port]` has none. The spec's flow (01 §4.3, 03 §6.1) assumes a connection that is
verified but not yet authenticated. That needs a decision: an auth method for this command (the user's agent keys, a
profile, or a password prompt), or an sd_ssh "post-KEX" connect mode that stops before `ssh-userauth`.

**Not done (open)**

- The real connect (`real_hostkeys_fetch` answers `SD_E_UNSUPPORTED`, which the CLI reports as "not part of this build
  yet"). Blocked by the authentication question above. Also still to do with it: run the blocking connect on a worker
  (the handler runs on the IPC thread), route its host-key prompt (TOFU) through the prompt broker instead of the
  two-step offer, and use `sd_ssh_conn_fetch_hostkeys` for the re-key path.
- The first-contact flow in the real backend: 5.2 wants the TOFU prompt from the connect itself. The offer model here
  gives the same question, but the other keys of a first contact are only learned after a second, verified connect
  (not built).
- Service side: `hostkey.add` on the service pipe and the machine store (`--machine`), as before.
- Refused offers stay in the announcement list until the agent restarts.
- Spec text: 03 §2 lists the method; 03 §6.1 is unchanged (the offer model is an implementation detail of this part).
  01 (~lines 759 and 2589) and TM-R04 are unchanged.

## Left (not in this part)

- Global WebDAV (D11 spike, `system` / `link` / `attach` modes, 03 §1.3).
- The display name as an indirect string (`@<path>,-<id>`, Vista+); the service's own re-set of the description at
  first start (1.3); the Event Log 3100 and the other 2xxx/3xxx ids of 10.3 that depend on features not in
  this part. Event 3102 is written (part 4).
- `hostkey add --machine --from-server` and `hostkey accept-announced --machine` (5.6 machine store): the command
  surface and the elevation rule are in part 5; the connect, the store write and the service side are not (the
  per-user connect of part 6 is blocked on authentication, see there).
- Chains (`proxy.jump`), proxies, and the `system` proxy for service profiles (2.6 rule 1 lists them as allowed; refused
  in this part with `usage`).
- Identity files: the path rule and the handle checks (owner, reparse point, DACL) are done in part 6 for the identity
  file of a service profile. Still open: certificate files (no service profile loads one yet), file-level checks of
  machine profiles, `known_hosts` and `settings.ini` (only the folder rule covers them), passphrase secrets and
  `identity_store` keys for service profiles.
- Re-applying the 3.2 DACLs of existing machine folders at service start (3.2): done in part 6 for trusted folders.
  Untrusted folders are still only refused at start; `service repair-data` (part 3) moves them aside.
- Power events and session changes are logged only; the admin session list for the attention flow (2.6) is not kept.
- Admin UI, not done: a list window of pending service prompts (the admin mode shows one prompt dialog per open prompt
  instead); host-key announcements of the service machine store in the admin UI (`hostkey.announced` on the service is
  not served yet); `--elevated-view` (03 §1.7.2) is a CLI flag of the WebDAV elevated mapping and has no UI mode here.
- Admin UI, done (`shelldrive-ui.exe` part, `ui_svc.c`, `ui_admin_model.c`): the attention watch of a logged-on
  administrator (linked token on Vista+, membership on XP) and the tray state and menu item that relaunch the UI with
  `--elevated-admin` (`runas` on Vista+, plain `open` on XP). The admin mode connects to the service pipe only, has no
  tray icon and no mutex (it never forwards to the running UI), lists the open prompts, shows their dialogs and sends
  `prompt.answer` over the service pipe. It leaves when the service goes away or after 60 s with no prompt.
- Secret types other than `password`; `secret.set` for passphrases needs the key fingerprint target.
- Lab items: a real Dokany global mount (visible to a second session, before logon), LocalSystem decryption of the
  service secrets, and the SYSTEM-owned service pipe as a non-test client.

## Part 6: key file trust (TM-R27) and the start re-apply of the 3.2 DACLs

Closes the two "Left" items on identity files and on the start re-apply (both above).

**Files**

| Path | What |
|---|---|
| `apps/shelldrive-host/svc_folder.c`, `svc_folder.h` | `svc_file_read_trusted` (checked read of a key file), `svc_folder_apply_dacl` (3.2 DACL compare and set), the DACL check (`dacl_untrusted_write`), reasons `acl` and `not_file` |
| `apps/shelldrive-host/service.c` | identity file read in `job_start` (the bytes go to `sd_mount` as a hop `key_blob`, label = the path); `svc_check_existing` re-applies the DACL of a trusted folder; `svc_event_key_refused` (Event 3102 with the file as `%1`); the 3.2 SDDL constants are file-scope |
| `apps/shelldrive-host/service.h` | `svc_opts.dacl_extra_ace` (test seam, honoured only in `SD_SVC_TEST_HOOKS` builds) |
| `tests/unit/sd_svc/test_identity.c` (new), `main.c`, `CMakeLists.txt` | the seven identity and DACL cases below |
| `tests/unit/sd_svc/test_service.c` | the fixture writes `service\keys\key1.ppk` (the identity profiles name it) and sets `dacl_extra_ace` |

**Behaviour (2.6 rule 1, TM-R27, T-51)**

- The identity file path must be under `<machine root>\service\` (unchanged rule, `svc_path_under`).
- Every folder between the service folder and the file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked on its
  handle: not a reparse point, a folder, owner SYSTEM or Administrators (the owner rule), and a DACL that grants no write
  to an untrusted principal.
- The file is opened without following a link (`FILE_FLAG_OPEN_REPARSE_POINT`), checked on that handle: not a reparse
  point, a plain file of 1 B to 256 KiB, owner trusted, DACL with no write, modify, delete, WRITE_DAC or WRITE_OWNER for a
  principal other than SYSTEM, Administrators, the owner, CREATOR OWNER and OWNER RIGHTS. A NULL DACL and an ACE type the
  check does not understand (object or callback ACEs) are refused. Deny ACEs are not counted.
- The bytes are read from that same handle, which is opened with `FILE_SHARE_READ` only, so no writer can open the file
  while it is read. The mount then receives the bytes (`sd_mount_hop.key_blob`, the `SD_ID_BLOB` path of sd_ssh), not the
  path: there is no second open. The bytes are wiped after `sd_mount_create`.
- A refused file: Event 3102 (`%1` = the file, `%2` = `owner`, `reparse_point`, `not_directory`, `acl` or `not_file`)
  and the mount fails with `usage` ("identity file refused ... (TM-R27)"). A file that cannot be opened or read fails the
  mount with `usage` and no event. The service itself stays up. The 3102 text says "Machine folder ... stays idle",
  which is not what happens for a key file; the message text is not changed here (open).
- Start, for a trusted folder (owner and no reparse point, 3.2): the DACL is compared with the 3.2 SDDL (protected, the
  same ACEs in order) and set back when it differs. The folder is opened with `WRITE_DAC` when the service can; without
  it, the check still runs and a wrong DACL is refused with `acl`. An untrusted folder is still not fixed here
  (`repair-data` moves it aside, part 3).

**Test seam**

`svc_opts.dacl_extra_ace` appends an ACE to every machine DACL the start sets or checks (tests only). The test process is
the owner of its folders, so the tests pass `(A;OICI;FA;;;OW)`, as `svc_repair` does. The shipping build never reads it.

**Tests (`unit.svc`, new cases)**

- `identity_file_through_a_junction_is_refused`: a junction for the `keys` folder into a sentinel folder: `reparse_point`.
- `identity_file_symlink_or_link_tag_is_refused`: a file symbolic link when the process may create one; otherwise a file
  with a user-defined reparse tag (same refusal).
- `identity_file_with_a_foreign_owner_is_refused`: `owner`.
- `identity_file_with_a_user_writable_acl_is_refused`: a key file, then a keys folder, that Everyone may write: `acl`.
- `identity_file_good_is_read_from_the_checked_handle`: accepted, bytes equal.
- `identity_path_that_is_a_folder_is_not_a_file`: `not_directory`.
- `machine_folder_dacl_is_reapplied_once_then_left_alone`: first set changes the DACL, the second call writes nothing.
- The existing service cases (`svc_admin_mounts_reports_and_unmounts` and the others that use `key1.ppk`) now go through
  the handle read and the blob hop; they pass the fixture key file.
- Every test uses a fresh folder under `%TEMP%` named with the PID and a QueryPerformanceCounter value, removed at the
  end of the test. Nothing touches `%ProgramData%`, the registry, the Event Log or the SCM.

**Not done (open)**

- Certificate files (`auth.certificate` for service profiles): no service profile loads one; the same helper applies when
  one is wired.
- File-level checks of machine profiles, `known_hosts` and `settings.ini` (03 §2.6 names them): only the folder rule
  covers them today.
- The Event 3102 text is written for machine folders ("stays idle"); a key file refusal reuses it.
- The mount-level refusal is not tested end to end through the core (the helper and the blob hop are tested on their
  own and through the existing core cases that read the fixture key).
- The DACL re-apply is tested on a folder with the helper directly, not through a full core start on a folder with a
  wrong DACL.

## Part 7: per-request access in `sd_vfs`

**Spec.** 02 §6.7 (requestor check, write right), §7.7 (SSPI caller, `service_access_write`), §8 (`sd_vfs_caller`,
`access_sids` / `write_sids`), TM-R24 and D35 (no default audience). The spec puts the caller in `sd_vfs_caller` and the
lists in the options; the vfs now enforces them.

**Files**

| Path | What |
|---|---|
| `src/sd_vfs/vfs_access.c` | new: mount-time copy of the lists and the well-known SIDs; `vfs_access_check` (per request) |
| `src/sd_vfs/vfs_ops.c` | `sd_vfs_create` checks before any work (write request = write-class access or a create/truncate disposition; `MAXIMUM_ALLOWED` is a read); `sd_vfs_stat_path` takes the caller |
| `src/sd_vfs/vfs_core.c` | `global_mount` accepted; lists copied at mount |
| `src/sd_mount/mount.c`, `sd_mount.h` | `sd_mount_params.access_sids` / `write_sids` (copied at create; a global mount needs `n_access >= 1`) |
| `src/sd_dokan/dokan_mount.c` | global mounts: requestor token user and enabled, non-deny-only groups go to the vfs; a request without a token is refused |
| `src/sd_webdav/wd_methods.c`, `wd_server.c` | `sd_vfs_stat_path` gets the caller; groups NULL |
| `apps/shelldrive-host/service.c` | the resolved `service_access` / `service_access_write` strings become SIDs for the mount |

**Decisions**

- Per-user mounts: the caller's SID must equal the mount owner (a NULL caller stays allowed for host-internal use).
- Global mounts: no caller or no SID is refused. LocalSystem is allowed in full only with `allow_system`. Any access
  needs the caller (SID or an enabled group) in `service_access`. A write also needs `caller->can_write`, a SID or group
  in `service_access_write`, or an enabled BUILTIN\Administrators group. A UAC-filtered admin token does not count.
- Empty `service_access` on a global mount: refused at mount with `SD_VFS_E_ACCESS_DENIED` (D35). Empty
  `service_access_write`: members are read-only.
- A write by a member without the write right fails with `SD_VFS_E_ACCESS_DENIED` (403 / `STATUS_ACCESS_DENIED`),
  not `SD_VFS_E_READ_ONLY`, as 6.7 says.
- Read-class checks: lookups (`stat_path`) are reads, so a non-member gets nothing.

**Limitations and open items**

- Dokany reads the requestor token on every create (no 60 s per-(LUID, SID) cache from 6.7 yet).
- WebDAV has no token groups on the per-user SSPI path, so group entries in `service_access` only match by user SID there.
  Global WebDAV is still the attach fallback (D11), so this does not reach a global mount yet.
- `SD_VFS_EV_AUDIT` (Event 1200, TM-R24) is not raised yet.
- The Dokany requestor check is not unit-tested (the callbacks are static); the vfs rules are.

**Tests.** `tests/unit/sd_vfs/test_vfs_access.c` (8 tests): global mount needs `service_access`; per-user owner only and
NULL caller; read needs the access list (and `stat_path`); a member without the write right is read-only, with
create/truncate/delete/rename denied and nothing changed; the write list grants write; group matching and admins
writing; a group in the write list; SYSTEM with and without `allow_system`; the frontend `can_write` flag restricts.
`test_mount.c` gives its global-mount case a `service_access` SID.

**Build.** `ci-local.ps1 -Presets 'x64-modern' -ReleaseOnly -NoFixture -AllowSkip -TestRegex 'vfs|webdav|dokany'`:
pass, 4 of 4 tests (`unit.vfs`, `unit.webdav`, `webdav.redirector`, `dokany.mount`).

## Service pipe: non-admin cap, reserved administrator instances, Event 3101 (TM-R25)

Closes the "Left" item on the non-admin request cap and the reserved administrator slots of the service pipe (03 §2.2,
TM-R25). The 4-per-SID and 10-per-second limits were already in place and are unchanged.

**Spec values (03 §2.2, 05 TM-R25, 03 §10.3):** request cap 1 MiB for elevated admins and 64 KiB for every other client,
also before hello; 32 instances of which 2 are reserved: once 30 other instances are connected, a client that is not an
elevated admin is closed at hello with `too_many_connections`; 4 instances per SID; 10 requests per second for
non-admins; Event 3101 at most once per SID per 10 minutes (`%1` SID, `%2` reason).

**Changes**

- `src/sd_ipc/include/sd_ipc/sd_ipc.h`, `src/sd_ipc/ipc_server.c`: `sd_ipc_server_cfg` gets four members at the end,
  all zero or NULL for the agent (its behaviour is unchanged): `max_message_nonadmin` (request cap of non-admins,
  checked per read; before hello the non-admin cap applies), `reserved_admin_instances` (checked at hello, after the
  client kind is known), `is_admin` (the service's `caller_is_admin`, so the test admin override applies) and
  `on_refused` (called on the pipe thread for reasons `token`, `per_sid`, `reserved` and `rate`). New accessor
  `sd_ipc_client_sid`.
- `apps/shelldrive-host/service.c`: admin cap `SD_IPC_MAX_MESSAGE` (1 MiB), non-admin cap 64 KiB, 2 reserved
  instances, and `svc_on_refused`, which writes Event 3101 through the existing `svc_event` seam.
- `apps/shelldrive-host/svc_access.c`, `svc_access.h`: `svc_refuse_log_due`, the 10-minute per-SID throttle for 3101
  (32 slots; a full table reuses the entry logged longest ago). Takes the clock as a parameter, so tests use fake times.
- `apps/shelldrive-host/svc_events.mc`: Event 3101 `SVC_MSG_CLIENT_REFUSED`.

**Tests** (`tests/unit/sd_svc`, `sd-test-svc.exe`, 67 of 67 pass):

- `refuse_log_is_once_per_sid_per_window`: fake clock; first event due, same SID inside the window not due, due again
  after 10 minutes, another SID due at once, eviction of the oldest entry.
- `svc_pipe_caps_and_reserved_admin_instances`: a restricted-token client's 100 KiB request is refused and the same
  request from `testadmin` is accepted; with 30 raw pipe instances held (connected, no hello), a restricted client is
  refused at hello, two such refusals write at most one 3101, and a new `testadmin` connection still succeeds.

**Build.** `ci-local.ps1 -Presets 'x64-modern' -ReleaseOnly -NoFixture -AllowSkip -Jobs 4 -TestRegex 'unit\.svc|unit\.ipc|unit\.apps'`:
pass, 3 of 3 (`unit.svc`, `unit.ipc`, `unit.apps`).

**Open items**

- A client that connects and never sends hello holds an instance until the 60 s idle timeout, and the reservation is
  decided at hello (as 03 §2.2 describes). Thirty-two hello-less connections can therefore still block administrators
  for up to a minute. A connect-time token check would close that gap; it is not done.
- The non-admin cap check in `svc_pipe_caps_and_reserved_admin_instances` only runs when the restricted-token connect
  succeeds, which depends on the pipe ACE in the test session (the same convention as the existing tests). The
  check was not separately confirmed to run in this session.
- Event 3101 is not written for a refusal before the token gives a SID (`token` refusals with no SID).
- Event 3101 is English only, like the other 3xxx events in `svc_events.mc`; it is not in the `svc` l10n catalogs.
- Not exercised on a real elevated admin token or on XP; TST-23 in 05 §7 covers that in the lab.

## Part 8: the per-user hostkey connect (`wip/r14-hkconn`)

Part 6 left `real_hostkeys_fetch` answering `SD_E_UNSUPPORTED`: `sd_ssh` reaches `SSH_ST_CONNECTED` only after user
authentication, and the fetch needs that state. This part makes `hostkey add --from-server` (per user, without
`--machine`) connect for real. The machine store is unchanged.

**Decision (01 §4.3, 03 §6.1).** The connect is a normal connection with the matching profile's authentication and
prompts, offering only the stored host-key types; `sd_ssh_conn_fetch_hostkeys()` runs inside that verified
connection. A host with no stored key is a first contact (TOFU, 5.2): the presented key is taken with
`SD_HK_ACCEPT_ONCE`, nothing is stored, and the CLI's question is the trust decision.

**Shape.** The `hostkeys_fetch` backend member (a blocking call with no prompt context) is replaced by a *hostkey
mount*: `sd_mount_params.hostkey_fetch` (with `hostkey_type`) makes `sd_mount` connect through sd_ssh without an sftp
session and without a vfs. The prompts, the broker and the deferred IPC reply are the ones of `profile.test`, so the
work runs on the agent's control thread and the sd_ssh I/O thread; the IPC thread only queues the request. The
connection's own callbacks stay in `mount.c`, which is what answers the broker's prompts by id.

**Files**

| Path | What |
|---|---|
| `src/sd_mount/include/sd_mount/sd_mount.h` | `sd_mount_params.hostkey_fetch`, `.hostkey_type`; backend members `hk_conn_create`, `hk_conn_connect`, `hk_conn_fetch`, `hk_conn_destroy` (replace `hostkeys_fetch`); `sd_mount_get_hostkeys()` (replaces `sd_mount_hostkeys_fetch()`) |
| `src/sd_mount/mount.c` | `build_ssh_config()` (the hop configuration, shared with the sftp start); `hk_start`, `hk_on_connected`, `hk_on_fetched`, `hk_finish`; `EV_HK_DONE`; first-contact TOFU prompt in `ssh_on_prompt` (ACCEPT_ONCE, the presented key kept); `update_host_keys = no` on the hops (announcements are not stored by this path) |
| `src/sd_mount/mount_real.c` | the four members as thin wrappers over sd_ssh |
| `src/sd_ssh/include/sd_ssh/sd_prompt.h`, `kex.c`, `prompt.c`, `conn_internal.h` | `sd_hostkey_prompt_info.blob`/`blob_len`: the presented key, owned by the prompt (needed to store a first-contact key after the CLI's yes) |
| `apps/shelldrive-host/agent.c` | `handle_hostkey_add` (profile matched by host and port as `mount` finds one, else the `--host` defaults; `handle_mount_body(..., test = 2)` makes the connect-only record), `reply_hostkey_add` (the deferred reply, from `on_state`), `hk_complete` (expect rule, announcement list, the reply members), `hk_error_text` |
| `tests/apps/host_fake_backend.c` | the fake sd_ssh connection (`hk_fake_*`): a stored host (`*.known.test`), a mismatch (`*.changed.test`), first contact (anything else); the TOFU prompt goes through the mount's own `ssh_on_prompt` |
| `tests/unit/sd_ssh/test_interop.c` | `interop_hostkeys_fetch_none_offered`, `interop_hostkeys_fetch_first_contact_refused` (WSL fixture, label `interop`, `wsl_sshd_fixture`) |
| `docs/design/01-ssh-sftp-crypto.md` §4.3, §9; `docs/design/05-threat-model.md` TM-R04 | status notes |

**Behaviour**

- Stored key of the host: the connection is MATCH (or a mismatch, which fails like a mount). The keys returned are
  the server's other host keys: announced keys are proven with `hostkeys-prove-00`; each requested type that was not
  announced is obtained by a re-key restricted to that type. The default list is ed25519, ECDSA P-256/384/521 and
  ssh-rsa (the legacy type only where the legacy policy allows it); `--type T` asks for T alone.
- The server offers none of the stored types: `host_key_type_unavailable` (exit 6) as for a mount.
- First contact: no fetch (01 §4.3: a fetch needs a key trusted before the connection). The reply has the one presented
  key with `verified: false`, and nothing is stored until the CLI's yes (`hostkey.announced.accept`). `--expect`
  stores the key with that fingerprint without a question, as before.
- The fingerprints are recomputed from the blobs in the agent, as before; only `--type` keys are kept.

**Test seam and results**

- The smoke tests (`sd-test-apps.exe --filter hostkey`, 5 of 5) run the agent path on the fake connection:
  `smoke_hostkey_add_offers` and `smoke_hostkey_add_machine` pass unchanged.
- `ci-local.ps1 -Presets 'x64-modern' -ReleaseOnly -AllowSkip -Jobs 4 -TestRegex 'unit\.ssh|unit\.apps|unit\.mount|interop\.ssh'`:
  build passes; unit.ssh, unit.ssh_transport, unit.ssh_auth, unit.mount, unit.apps pass; interop.ssh is skipped.
- **Interop not run.** The WSL sshd fixture on port 2222 is running but belongs to another worktree; this worktree has
  no `tests/fixtures/wsl-sshd/state/env`, so `sd-test-ssh-interop.exe` exits 77 ("fixture not started"). The two new
  tests are compiled and linked but have never run against a server. To run them: start the fixture for this
  worktree (`tests/fixtures/wsl-sshd/start.ps1` once port 2222 is free, or `SD_SSH_WSL_FIXTURE_DIR`), then
  `sd-test-ssh-interop.exe --filter hostkeys_fetch`.
- No unit test in `tests/unit/sd_mount` covers the hostkey mount: the fake backend there has no hk members, so the
  hostkey path is covered by the apps smoke tests only.

**Not done (open)**

- Interop run of `interop_hostkeys_fetch_*` (see above) and an interop case with several server host keys (the
  `matrix` fixture in `run-matrix.ps1` has them; `rotate ab`). Until then the re-key path for a type the server does
  offer is unverified against a real server (01 §15 item 9).
- Announcements race: OpenSSH may send `hostkeys-00` after `USERAUTH_SUCCESS`; the fetch starts when the connect is
  done, so an announced key may not be proven by `hostkeys-prove-00` and is re-keyed instead. Correct, but it costs
  one re-key per type. Measure on the interop run.
- A first contact is not fetched, so `hostkey add` on a new host gives only the one key the server presents (5.2); the
  other types need a second `hostkey add` after the first key is stored.
- The service pipe (`hostkey.add` on the service, the machine store with `--machine`) is still not built.
- Refused offers stay in the announcement list until the agent restarts (unchanged from Part 6).

## Part 7 follow-up: Dokany requestor cache and Event 1200

Closes two of the open items above (the Dokany 60 s cache and `SD_VFS_EV_AUDIT`). The WebDAV item stays open.

**Dokany cache (02 6.7).** `src/sd_dokan/dokan_cache.c` (private) keeps the enabled groups of a requestor token for
60 s, bounded to 32 entries, guarded by one critical section, with lookups that return copies. `dokan_mount.c` reads
`TOKEN_STATISTICS` (one query) and the user SID on every create, and the groups only on a miss. Decisions:

- The key is (`TokenId`, `ModifiedId`, user SID). `TokenId` identifies one token object: a UAC-filtered, restricted,
  privilege-stripped or duplicated token has its own, even when it shares the logon LUID and the SID with its parent.
  `ModifiedId` changes when the token's groups or privileges are adjusted, so an entry from before the change is not
  reused. The LUID is not part of the key.
- The earlier key (LUID, elevation type, SID) was not enough. A privilege-stripped token with deny-only groups kept
  the LUID, SID and elevation type of its parent, so within 60 s it could hit the parent's entry and inherit an
  enabled Administrators group it does not have, which grants write. The residual is closed by the TokenId key.
- Restricted tokens are cached too, under their own TokenId. There is no restriction query on the path any more.
- A failed token query returns "denied" and stores nothing. The 60 s window is measured from the store; a hit does
  not extend it.
- Hit rate depends on `DokanOpenRequestorToken` returning the same token object for repeated opens from one process.
  If it duplicates the token on each call, each open gets a new TokenId and misses. Not verified on a live mount.

**Open.** Verify the hit rate on a live Dokany mount (the TokenId stability above). Without a stable token object
the cache saves nothing, but it still never grants more than a fresh read.

**Event 1200 (03 10.3, TM-R24).** The vfs raises `SD_VFS_EV_AUDIT` in `vfs_access.c` (`vfs_audit`) after a successful
mutating operation on a global mount: `create` (new file), `write_open` (one per open for write), `delete` (from
cleanup, with the requestor of the handle), `rename`, `setattr` (winattrs and times) and `set_security`. Requestor
SIDs come from the create that opened the handle. Denied requests raise nothing: Event 1200 records changes. Per-user
mounts never raise it. Coalescing is per (requestor SID, operation, path) in a 60 s window (`VFS_AUDIT_WINDOW_MS`)
with a 32-slot table; suppressed repeats are dropped, not counted. The clock is `v->audit_now` (`sd_tick_ms` by
default; the tests replace it).

The host seam: `sd_mount_callbacks.on_audit` (control thread, the SID valid during the call) carries the event from
`mount.c`. `service.c` resolves the account name on the control thread and raises `SVC_MSG_AUDIT` (1200, Information,
`svc_events.mc`) with the Event Log sink, which tests replace. The agent leaves `on_audit` NULL: it never mounts a
global drive, and the spec writes Event 1200 from the service only.

**Remaining gaps.**
- Handle-based operations (`setattr`, `rename`, `set_security`, delete at cleanup) use the handle's node key as the
  path. The key is case-folded in the insensitive view, so the path can differ in case from the one the client sent.
- WebDAV reaches the vfs with a caller, so it should raise the same events; this round did not test it.
- The `delete_path` recursion audits each child delete under its own path, so one recursive delete raises one event
  per child, subject to coalescing.

**Tests.** `tests/unit/sd_vfs/test_vfs_access.c`: `vfs_audit_raised_for_global_changes` (reads and denied opens silent;
create, write_open, setattr, rename and delete raised once each), `vfs_audit_coalesces_per_window` (fake clock: inside
the window coalesced, other SID / path / operation raised, raised again at exactly 60 s),
`vfs_audit_never_raised_on_per_user_mount`. `tests/unit/sd_dokan/test_dokan.c`: `dokan_cache_hit_expiry_and_keys`
(hit inside 60 s; expiry at 60 s; another user misses), `dokan_cache_different_token_object_misses` (same LUID and SID,
different TokenId: miss), `dokan_cache_changed_modified_id_misses` (adjusted ModifiedId: miss),
`dokan_cache_wraps_and_refreshes`, `dokan_cache_failures_are_not_stored`, `dokan_cache_is_bounded_and_evicts_oldest`.
`tests/unit/sd_svc/test_service.c` (`svc_admin_mounts_reports_and_unmounts`): a fake vfs audit reaches the Event
Log seam as SVC_MSG_AUDIT. The Dokany requestor path itself (`requestor_identity`) is not unit-tested: it needs a
live requestor token.
