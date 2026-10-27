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
  `attention` when a prompt is routed to an admin.

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
| `unit.svc` (`sd-test-svc.exe`), 15 tests | all pass: decision table, list resolution, profile refusals, volume SDDL parses, identity path rule, core start and selftest, profile loading (D17), non-admin restricted token refused for every admin method and for the topic gate, admin mount/status/unmount, prompt refused without UI (`prompt_unavailable`), TOFU refused (`host_key_unknown`), password prompt answered over the pipe, DPAPI secret round trip, list visibility for restricted tokens, stop with nothing left behind |
| `x64-xp` Debug, `shelldrive-host` and `shelldrive` | clean; XP SP2 x64 import audit passes |
| `x86-ia32` Debug, `shelldrive-host` and `shelldrive` | clean; IA32 ISA audit passes |

The tests run in-process: no SCM registration, no child process, no real drive. The restricted-token tests need the
interactive-user ACE on the pipe (they accept a refused connect as the refusal).

## Left (not in this part)

- Global WebDAV (D11 spike, `system` / `link` / `attach` modes, 03 §1.3).
- SCM install, uninstall, start, stop, status and `repair-data` (`shelldrive service ...`); the recovery actions and
  the localized display name and description (`ChangeServiceConfig2W`, 03 §1.3); the Event Log (10.3).
- `hostkey add --machine --from-server` and `hostkey accept-announced --machine` (5.6 machine store).
- Chains (`proxy.jump`), proxies, and the `system` proxy for service profiles (2.6 rule 1 lists them as allowed; refused
  in this part with `usage`).
- Identity files: only the path rule (under `<machine root>\service\`). The ACL and handle-based checks of TM-R27 are not
  done. Passphrase secrets and `identity_store` keys for service profiles are not wired.
- ACL repair and the owner check of the machine folders (3.2, TM-R34, Event 3102). Today a reparse point on a machine
  folder makes the service idle; a foreign owner does not.
- Non-admin 64 KiB cap separate from the admin cap, and the two reserved administrator slots of the service pipe
  (2.2, TM-R25). One 64 KiB cap applies to every client; the 4-per-SID and 10-per-second limits are in place.
- Per-request access check in `sd_vfs` (`access_sids` / `write_sids` are passed in the options but not enforced); the
  Dokany volume descriptor is the only enforcement on the drive.
- Power events and session changes are logged only; the admin session list for the attention flow (2.6) is not kept.
- Admin UI: the tray attention flow, `shelldrive-ui.exe --elevated-admin`, the prompt dialog (UI side, later).
- Secret types other than `password`; `secret.set` for passphrases needs the key fingerprint target.
- Lab items: a real Dokany global mount (visible to a second session, before logon), LocalSystem decryption of the
  service secrets, and the SYSTEM-owned service pipe as a non-test client.
