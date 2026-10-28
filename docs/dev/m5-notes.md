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

## Left (not in this part)

- Global WebDAV (D11 spike, `system` / `link` / `attach` modes, 03 §1.3).
- The display name as an indirect string (`@<path>,-<id>`, Vista+); the service's own re-set of the description at
  first start (1.3); the Event Log 3100 and 3101 and the other 2xxx/3xxx ids of 10.3 that depend on features not in
  this part. Event 3102 is written (part 4).
- `hostkey add --machine --from-server` and `hostkey accept-announced --machine` (5.6 machine store): the command
  surface and the elevation rule are in part 5; the connect, the store write and the service side are not.
- Chains (`proxy.jump`), proxies, and the `system` proxy for service profiles (2.6 rule 1 lists them as allowed; refused
  in this part with `usage`).
- Identity files: only the path rule (under `<machine root>\service\`). The ACL and handle-based checks of TM-R27 are not
  done. Passphrase secrets and `identity_store` keys for service profiles are not wired.
- Re-applying the 3.2 DACLs of existing machine folders at service start (3.2). The start check (part 4) only refuses;
  `service repair-data` (part 3) is still the one that fixes folders.
- Non-admin 64 KiB cap separate from the admin cap, and the two reserved administrator slots of the service pipe
  (2.2, TM-R25). One 64 KiB cap applies to every client; the 4-per-SID and 10-per-second limits are in place.
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

## Part 6: per-request access in `sd_vfs`

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
