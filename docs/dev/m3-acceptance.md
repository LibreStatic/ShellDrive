# M3 acceptance run

Acceptance of the M3 milestone (00 §6, row "M3 — UI, Explorer, full localization") on this Windows 11 machine,
from the `wip/m2-backend` tree at `635832b` plus the uncommitted acceptance doc. Date: 2026-10-27.

The run covers the local CI gate (build, warnings, import audit and CTest with the interop tests) and the
automated UI, shell-extension, state, agent and localization evidence. The M3 demoable outcome is a
GUI flow in Spanish and German at 150 % DPI on Windows 11, and the Explorer behaviours of 03 §8. Neither was
run here, because the agent cannot be isolated from the user's configuration (see "End-to-end through the agent").
They are listed under "Not covered" and "Known gaps".

## Environment

| Item | Value |
|---|---|
| Machine | AMD Ryzen 7 2700X, Windows 11 IoT Enterprise LTSC 2024 (10.0.26100), x64, non-elevated user |
| Build | `x64-modern` Debug (`cmake --build --preset x64-modern-debug`, already up to date, no new warnings); `x64-analysis` built warning-free at `635832b` (lead run) |
| Interop fixtures | WSL `tests/fixtures/wsl-sshd`, OpenSSH, port 2222 (up for the run; `wsl --shutdown` not used) |
| Dokany | installed; `dokany.mount` ran and passed |
| Scratch output | `build/m3/ctest-debug-interop.txt`, `build/m3/ctest-debug-interop.err` |

## Results

### 1. Local CI gate

| Check | Tree | Result |
|---|---|---|
| `x64-modern` Debug build | `635832b` | up to date, warning-free, import audit of `shelldrive`, `shelldrive-host` and `shelldrive-shellext` clean |
| `x64-analysis` build | `635832b` (lead run) | built warning-free |
| `x64-modern` CTest, incremental (lead run) | `6561fc3` | pass, 57 tests including interop |
| `x64-xp`, `x86-ia32`, `x86-sse2`, `x64-analysis` with `-Clean` (lead run) | `6561fc3` | pass; x86 `dokany.*` skipped under WOW64, as expected |
| `x64-modern` CTest without interop (lead run) | `635832b` | 55/55 pass |
| **`x64-modern` CTest with interop, this run** | `635832b` | **58/58 pass** (401 s) |

Command (reviewer):

```powershell
ctest --preset x64-modern-debug -LE "matrix|bench" --output-on-failure
```

Of the 65 registered tests, the label filter excludes 7 (the six `interop.ssh_matrix_*` tests and
`bench.vfs_pool`), so 58 ran. The matrix rows run through `tests/interop/run-matrix.ps1`
(see the M2 record for the reviewer command); they were not repeated for M3.

The interop tests passed: `interop.ssh` (12.1 s), `interop.sftp` (4.2 s) and `interop.sftp_ssh` (78.0 s, all
`m2_` striping and pool tests). The M2 `m2_striping_member_lost_mid_transfer` flake did not recur in this run.

Per-label times from the run: unit 288 s (21 tests), interop 94 s (3), l10n 0.7 s (16), ui 1.1 s (5),
importcheck 0.1 s (9), webdav 7.4 s, dokany 6.6 s, apps 1.4 s, isacheck 0.02 s.

### 2. What the automated evidence proves (M3 scope)

All names below are CTest tests of the `x64-modern` Debug tree and passed in the run above. The counts are
the number of `SD_TEST` cases in each source file.

**UI model and smoke (`unit.ui`, 74 cases in `tests/ui`; `ui.*` smoke tests)**

| Test | Cases | What it proves |
|---|---|---|
| `unit.ui` | 74 | Wire codec and verbs (11), DPI rounding and font height (2), dialog template layout and parsing (10), prompt model: parse of host key, password, passphrase, keyboard-interactive, password change, legacy and proxy prompts, server text sanitized and capped, answers escaped and secrets wiped (17), profile form round trip and validation, `.sdmount` parsing, JSON escaping (8), Logs cursor, filters and levels (6), host key rows and store enumeration (5), settings defaults, round trip and save in a temp root (5), notification rate limit per subject and kind (5), dark-mode decision on Windows 10 build 22000+ with the app theme value (3), first-run wizard opens once for an empty store only (2) |
| `ui.smoke` | 1 | `shelldrive-ui --test-window`: main window created hidden, class and controls checked, exits 0 |
| `ui.prompts` | 1 | every prompt dialog created hidden and destroyed |
| `ui.editor` | 1 | profile editor created hidden and destroyed |
| `ui.windows` | 1 | host key manager, Logs, Settings and About created hidden and destroyed |
| `ui.wizard` | 1 | first-run wizard smoke path (`--test-wizard`) |

None of the UI tests starts an agent, reads the user's settings or `known_hosts`, or leaves a process behind.
They prove that the dialogs and windows construct and tear down; they do not prove layout, focus, or the
rendering at 150 % DPI on screen.

**Shell extension (`unit.shellext`, 17 cases in `tests/shellext`; importcheck of the DLL)**

| Test | What it proves |
|---|---|
| snapshot read (`snapshot_valid_entries`, `snapshot_drops_bad_entries_only`, `snapshot_bad_header_is_no_data`, `snapshot_odd_seq_is_no_data`, `snapshot_missing_section_is_no_data`, `snapshot_low_label_is_refused`, `snapshot_random_corruption_is_bounded`) | the DLL reads only the state section; bad entries are dropped one by one, a bad header, odd sequence, missing section or low integrity label gives no data, and random corruption is bounded |
| menu (`menu_items_for_mounted_drive`, `menu_failed_drive_offers_reconnect`, `menu_global_drive_offers_open_only`, `menu_no_items_for_other_selections`, `menu_corrupt_snapshot_has_no_items`) | the menu shows only what the snapshot says: mounted drive items, reconnect for a failed drive, open only for a global drive, nothing for other selections or a corrupt snapshot |
| `invoke_builds_the_ui_command_line` | the verb is passed to `shelldrive-ui` in the grammar the UI accepts |
| `register_redirected_hkcu_leaves_real_registry` | registration is exercised only against a redirected HKCU key; the real registry is not written |
| `unload_and_locks_follow_references`, `exports_and_factory_arguments`, `dll_loads_with_the_four_exports` | DLL exports, factory arguments, reference counting and unload |
| `importcheck.shelldrive-shellext` and `importcheck.shelldrive-shellext-test` | the shipping and the test DLL import no post-XP API |

**State snapshot (`unit.state`, 10 cases in `tests/unit/sd_state`)**

Round trip; truncation is safe (cut and surrogate-safe); torn reads never mix two writes (seqlock, reader under a
live writer thread); odd sequence and corrupt header are no data; bad entries are dropped; a v1 reader accepts a v2
writer; unknown layouts are no data; section create and read round trip; a squatted low-integrity section is
refused (Vista and later). The foreign-owner squat needs an administrator and is not tested.

**IPC (`unit.ipc`, `test_ipc_m3.c`, 5 cases)**

Topic validation; subscribe drops invalid topics and reports `features` in hello; broadcast counts with the
capability filter and exclusion; the state and UI object names and their create and open with owner checks;
the owner label fails closed when it cannot be read (TM-R26).

**Agent methods and CLI (`unit.apps`, `tests/apps`; `apps.no_leftover_processes`)**

`test_agent_m3.c` (13 cases) runs the real agent over the real pipe against the scripted fake backend
(`SHELLDRIVE_TEST_UI_LAUNCH` stays 0, no Explorer window):

| Case | What it proves |
|---|---|
| `m3_snapshot_and_icon_follow_mount` | the section entry and the drive icon exist while mounted and are gone after unmount |
| `m3_network_location_entries_at_start` | Network location folders with the marker, `target.lnk` and the placeholder; a stale marked folder is removed, an unmarked folder is kept (test locations only) |
| `m3_ui_only_prompts_and_answers`, `m3_prompt_deadline_timeout`, `m3_queue_evicts_and_drains_to_ui`, `m3_initiator_gone_keeps_prompts_for_ui`, `m3_initiator_gone_without_ui_cancels` | prompt routing: UI-only prompts, deadline, queue eviction and drain, the initiator-disconnect rules |
| `m3_new_methods_and_list_warnings`, `m3_profile_test_results_and_errors`, `m3_config_changed_and_agent_stopping`, `m3_refresh_cache_attach_and_status_stats`, `m3_cache_clear_refuses_queued_writes` | `profile.test`, `refresh`, `cache.clear` (refused while write-behind data is queued), `mount.attach_info`, `status {stats}`, `config.changed`, `agent.stopping` |
| `m3_autostart_and_open_after_mount` | logon autostart and the session check; one open of the drive root after the first MOUNTED of a user mount; no open for an autostart or reconnect |
| `cli_parse_m3_commands` (`test_cli_m3.c`) | `refresh`, `cache clear`, `profile test`, `status --stats` and its `stats` alias, `mount --open`, and the option limits |

`apps.no_leftover_processes` checks after `unit.apps` that no agent or UI process remains.

**Mount and configuration (`unit.mount`, `unit.config`)**

`unit.mount` (16 cases, 4 new `mount_m3_*`): test-only probe mount for `profile.test`, refresh, stats, cache clear
and stop, and the WebDAV attach port (from the fake; the real `sd_webdav` port is not exercised).
`unit.config` (`test_config_m3.c`, 6 cases): M3 key defaults, values and bounds (49 cases), octal umask, the derived
shell-active default, legacy key names, round trip.

**Localization and register (`unit.l10n`, `l10n.*`, 16 tests)**

| Test | What it proves |
|---|---|
| `l10n.real_catalogs_complete` | the shipped `l10n/cli` catalogs are complete for every locale (sdl10n `--check`) |
| `l10n.empty_catalogs_check`, `l10n.missing_string_fails`, `l10n.missing_string_allowed`, `l10n.missing_plural_form_fails`, `l10n.placeholder_mismatch_fails`, `l10n.plural_header_fails` | the completeness, plural and placeholder rules fail the build and are relaxed only by `--allow-incomplete` |
| `l10n.register_wrong_fails`, `l10n.register_correct_passes` | the register lint (03 §9.2) rejects a wrong register and passes the right one |
| `l10n.mnemonic_dropped_fails`, `l10n.mnemonic_duplicates_warn`, `l10n.mnemonic_distinct_passes` | mnemonic (accelerator) rules |
| `l10n.maxlen_exceeded_fails`, `l10n.maxlen_within_passes` | maximum length rule |
| `l10n.qps_table_generated`, `l10n.qps_keeps_mnemonics` | the `qps-ploc` pseudo-locale is generated in Debug, keeps placeholders and mnemonics, and is absent without `--qps` (Release) |

At build time `sdl10n` runs for every catalog domain (`cli`, `common`, `shell`, `ui`) with all six locales
(`en`, `es`, `fr`, `pt-BR`, `it`, `de`) and fails the build on any missing string or rule, so a green build means
the four `ui`, `shell`, `common` and `cli` domains are complete. `l10n.real_catalogs_complete` checks the `cli`
domain on its own.

**Other suites in the same run**

`unit.webdav`, `webdav.redirector`, `unit.vfs`, `unit.sftp`, `unit.ipc`, `unit.crypto*`, `unit.ssh*`, `unit.dokany`,
`dokany.mount`, `isacheck.selftest` and the `importcheck.*` suites all passed; they are the M0–M2 base and were not
changed for M3.

### 3. End-to-end through the agent

Not run. The isolated-instance hooks (`SHELLDRIVE_TEST_INSTANCE`, `SHELLDRIVE_TEST_CONFIG_DIR`,
`SHELLDRIVE_TEST_HOST_EXE`) are compiled only into `sd-test-cli` (`SD_CLI_TEST_HOOKS`) and
`sd-test-host-fake` (`SD_HOST_TEST_HOOKS`). The shipping `shelldrive.exe` and `shelldrive-host.exe` resolve the
configuration root through the known-folder API and use the default pipe names, so starting them would read and
write the user's real profiles, agent pipe, state section and logs. The step was therefore skipped, as the
brief requires.

This is a lab/manual item: create a profile for the wsl-sshd fixture, then `mount` with `--backend webdav` and
with Dokany, `status --stats`, `refresh`, `cache clear`, `profile test`, `unmount`, and check the state section
through `shelldrive status`. It needs a disposable Windows user account, or a lab machine, before it is run.

### 4. Not covered (M3 demoable outcome)

| Demo step (00 §6, M3) | Status |
|---|---|
| Full GUI flow in Spanish (voseo) and German at 150 % DPI on Windows 11 | not run: no interactive GUI verification in this run |
| Create a profile in the editor | not run; the editor is covered only as a hidden create and destroy (`ui.editor`) |
| Mount from the This PC context menu | not run; the menu logic is covered by `unit.shellext` against a fake snapshot |
| The profile appears under "Network locations" | not run on Explorer; the folder, marker and `target.lnk` are covered in test locations |
| Offline tray state | not run; the notification rate limit is covered by `unit.ui` |
| Unmount from the drive context menu | not run; covered by the snapshot and menu tests only |
| 32-bit app file dialog shows the menu | not run; the x86 DLL is built and tested, but not registered on WOW64 (see gaps) |

## Reviewer commands

Build and gate:

```powershell
cmake --build --preset x64-modern-debug
ctest --preset x64-modern-debug -LE "matrix|bench" --output-on-failure
```

The interop tests need the wsl-sshd fixture up:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\start.ps1
```

Single UI smoke tests (hidden windows, exit 0):

```powershell
build\x64-modern\bin\Debug\shelldrive-ui.exe --test-window
build\x64-modern\bin\Debug\shelldrive-ui.exe --test-prompts
build\x64-modern\bin\Debug\shelldrive-ui.exe --test-editor
build\x64-modern\bin\Debug\shelldrive-ui.exe --test-windows
build\x64-modern\bin\Debug\shelldrive-ui.exe --test-wizard
```

Localization, by name:

```powershell
ctest --test-dir build\x64-modern -C Debug -R "^l10n\." --output-on-failure
```

## Known gaps

**Not verified in this run**

- **No interactive GUI verification.** Only the hidden smoke tests ran. Layout at 150 % DPI, focus order, the tray,
  dark mode on screen and the wizard flow are not checked by eye.
- **End-to-end through the real agent** was not run (see section 3); it needs an isolated user or lab machine.
- **XP and Windows 7 lab not run.** The `x86-ia32` and `x86-sse2` builds passed their `-Clean` gate at `6561fc3` (lead run), but the
  shell-extension and state-section behaviour on XP and 7 (03 §8.2.1, §8.3) was not exercised on those systems.
- **Translations need native review.** The six catalogs pass the completeness, register and placeholder rules, but
  the wording has not been reviewed by a native speaker.
- **Plural forms.** The checker requires every category CLDR defines for each locale: `one`/`other` for `de` and
  `en`, `one`/`many`/`other` for `es`, `fr`, `it` and `pt-BR`. That is the meaning of "the full CLDR plural
  categories" in AGENTS.md: no locale's category set is shortened, and categories a locale does not have are not
  invented.
- **Explorer behaviours of 03 §8 (`[verify]` items).** Not checked on real Explorer:
  - §8.2.1: the state section open with `READ_CONTROL` on XP and 7; the owner read on a reader.
  - §8.3: drive labels and icons on XP and 11; the per-user drive icon key on Windows 11.
  - §8.6: the Windows 11 modern menu (`IExplorerCommand`) is not implemented, and the sparse-package route depends on
    the certificate (M6). Whether a `Drive` item type is valid, and whether sparse packages can register it, is open.
  - §8.7: `desktop.ini` honoured with the read-only folder attribute on XP, 7, 10 and 11; folder shortcuts honour
    `[.ShellClassInfo]` (otherwise the target's icon is shown); the Network location entry opens its target.
  - §8.8 (M3 decisions): the `[verify]` marks in the Explorer data producer.
  - Approved shell-extension list written under HKCU: whether Explorer honours it under
    `EnforceShellExtensionSecurity` on Windows 10 and 11 (`m3-notes.md`, shell extension open items).
- **Shell-extension open items (`docs/dev/m3-notes.md`):**
  - Not implemented from 03 §8.2: Copy remote path, the Directory, `*` and This PC registrations, "Mount with
    ShellDrive" under This PC, and menu icons.
  - `IExplorerCommand` (§8.6) is not implemented.
  - The x86 DLL is not registered on WOW64 (only the native HKCU view is written).
  - The import floors for `DisableThreadLibraryCalls`, `ReleaseStgMedium`, `DragQueryFileW` and `InsertMenuItemW`
    were added to the XP lists as documentation only, pending the XP lab capture.
  - Explorer was not restarted and nothing was registered in the real registry.
  - Error UI: a failed launch returns `E_FAIL` and shows nothing.
- **Label check (TM-R26).** `sd_ipc` now fails closed when the owner label cannot be read on Vista and later
  (lead decision). The M3 notes record this as a decision; no lab check of the label on the target systems was run.
- **Profile keys parsed but not applied** (`m3-notes.md`, "M3 profile keys"): `mount.exec_hint`, `mount.atomic_put`,
  `mount.strict_acl`, `mount.remote_charset` (UTF-8 is used), `mount.mark_of_the_web` (refused until a later
  milestone), `mount.offline_hint_over_mb`, `security.crypto_backend`. The `open_after_mount` check on a real
  Explorer and `ShellExecuteW` on XP are not run.
- **Behaviour change in M3:** `mount.hide_dotfiles`, `mount.map_readonly` and `mount.fsync_on_flush` now default to
  yes, so mounts hide dot files and map read-only bits by default.
- **Items listed as "left for later" in `docs/dev/m3-notes.md`:**
  - `diag.collect` and the `log` topic with `log.tail {follow}` (M4).
  - `update.check` and `update.apply` (M4); `secret.set` and `secret.delete` (M5).
  - Service side of `refresh`, `cache.clear`, `profile.test`, `mount.attach_info`, `status stats`, the service
    prompts (`prompt.answer` and `prompt.list` for the service) and `hostkey.announced.list` (M5).
  - Session lock state is not probed before a UI launch.
  - `config.reload` returns an empty `restart_required` list.
  - The real `sd_webdav_mount_port` path (WebClient) is only the lab check.
  - The `profile test` prompts are exercised by the agent harness only, not with the real console prompt.
- **Accessibility pass.** The M3 row's accessibility pass (03 §11) is not evidenced in this run.

**Not failed.** No test failed in the run. No product code was changed for this acceptance.

## Not in this document

Fixture credentials, host names, user names, the profile and key paths, and any machine-specific path are not
recorded here. The interop tests read the fixture keys in-process; nothing was printed.
