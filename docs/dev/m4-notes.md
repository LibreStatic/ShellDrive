# M4 notes

## Updater engine (sd_update)
Scope of this branch (`wip/m4-updater`): the updater engine of 04 §9, the agent methods `update.check` and
`update.apply`, the offline signing tool `sd-updsign`, and the tests. The Settings update group in the UI is a
later change; it uses the IPC described below. Design decisions taken here are recorded in 04 §9.7.

## Files

| Path | What |
|---|---|
| `src/sd_update/include/sd_update/sd_update.h` | public API: result codes, versions, keys, keyset and manifest types, state, transport, engine |
| `src/sd_update/update_verify.c` | pure part: strict manifest and keyset syntax, the signature chain, base64, dates, version compare |
| `src/sd_update/update_state.c` | `last_serial.<channel>`, `last_verified.<channel>`, `keyset`, `roots`, `manifest.<channel>` (atomic writes) |
| `src/sd_update/update_winhttp.c` | WinHTTP transport, every entry point resolved at run time; redirect allow list; size limits |
| `src/sd_update/update_engine.c` | check, stage, apply (setup run, file swap with rollback), flavour detection, staging cleanup |
| `apps/shelldrive-host/update_ipc.c` | `update.check`, `update.apply`, events, policy and settings reads |
| `tools/sd-updsign/sd-updsign.c` | offline signing tool (release pipeline only, never shipped) |
| `tests/unit/sd_update/` | unit tests: pure verification, state, engine over a loopback server (`sd-test-update.exe`) |

## Signing tool (`sd-updsign`)

The tool is built with the rest of the tree (`build/<preset>/bin/Debug/sd-updsign.exe`). It is not in any
installer and the product never calls it. Commands:

```
sd-updsign keygen   --seed <file> [--pub <file>]         new ed25519 key: prints "pubkey <base64>" and "key-id <16 hex>"
sd-updsign pubkey   --seed <file>                        public key and key id of an existing seed file
sd-updsign sign-keyset   --in <body> --root <seed> [--root <seed>] --out keyset.txt
sd-updsign sign-manifest --in <body> --key <seed> --out manifest.txt
sd-updsign hash     --file <path> [--alg 256|512]        "sha256:<hex>" for a `file` line
```

- `<body>` is the unsigned text: it ends with LF and has no `sig` line. The tool appends one `sig ed25519 <key-id>
  <base64>` line per signer (keyset: one per root; manifest: one). The signed bytes are the domain string of
  `sd_update.h` followed by the body.
- Seed files hold 32 bytes as 64 hex digits. The production seeds are created and kept on the offline signing
  machine in an encrypted volume (04 §9.3); the root keys never touch a networked machine or CI. The tool writes the
  seed in clear text, so use it only on that machine or in a test directory.
- Release order (04 §12.3): sign the keyset with both current roots only when the roots change, otherwise with one
  root; sign the manifest with the channel key whose id the keyset lists for that channel; re-sign the current
  manifest of each channel every two weeks with a new serial (TM-R36).
- Manifest lines for an artifact: `file <id> <name> <size> sha256:<hex>` (size in bytes, the digest from `hash`).
  `base` lines are the download prefixes (HTTPS first, then the HTTP mirror), each ending with `/`.
- Example (test-style, one root for brevity):

```
sd-updsign keygen --seed C:\secure\root-a.seed --pub C:\secure\root-a.pub
sd-updsign keygen --seed C:\secure\stable.seed
sd-updsign hash --file dist\ShellDrive-1.1.0-setup.exe
sd-updsign sign-manifest --in manifest.body --key C:\secure\stable.seed --out manifest.txt
```

## Client configuration (agent)

- Settings (`settings.ini`, 03 §3.4): `[update] enabled`, `channel` (`stable` or `beta`), `manifest_url`
  (https or http). Machine values in `%ProgramData%\LibreStatic\ShellDrive\settings.ini`, user values in
  `%APPDATA%\LibreStatic\ShellDrive\settings.ini`, portable values in `<exe dir>\data\settings.ini`.
- Policy (`HKLM` wins over `HKCU`, `Software\Policies\LibreStatic\ShellDrive`): `DisableUpdateCheck` (DWORD),
  `UpdateChannel`, `UpdateUrl` (REG_SZ).
- State: `%LOCALAPPDATA%\LibreStatic\ShellDrive\state\` (per user), `%ProgramData%\LibreStatic\ShellDrive\state\`
  (per machine, read only for the agent), staging `%LOCALAPPDATA%\LibreStatic\ShellDrive\updates\<version>\`.

## Contract changes (IPC, 03 §2.8)

Proto stays 1. Additive changes only.

Methods:

| Method | Params | Reply | Notes |
|---|---|---|---|
| `update.check` | none | `{enabled, reason?, available, channel, stale, version?, notes?, size?, file_id?, serial?}` | deferred (network). Disabled by policy or settings: `enabled: false`, `reason` `policy` or `settings`, no network |
| `update.apply` | `{consent: true}` | `{applied, state: "applied" or "up_to_date", version?}` | deferred. `consent` is required. Refused for portable installs and when disabled |

Errors (IPC codes, exit code in brackets): `consent_required` (1), `update_disabled` (1), `busy` (1),
`update_verify_failed` (17, existing), `update_unavailable` (1, no base reachable or redirect refused),
`update_no_target` (1), `update_apply_failed` (1), `selftest_failed` (17, existing).

Features in `hello`: `update`, `update.check`, `update.apply` (the Settings group is greyed out while they are absent).

Events (topic: every client that completed hello, like `config.changed`):

| Event | Data | When |
|---|---|---|
| `update.available` | `{version, channel, notes, size, file_id}` | a verified manifest offers a newer version |
| `update.progress` | `{stage: "downloading" or "applying" or "done" or "failed", version}` | during `update.apply` |
| `update.stale` | `{days}` | a check failed and the last verified manifest is older than 14 days |

The M3 test that expected `update.check` to be absent was updated (tests/apps/test_agent_m3.c).

## Tests

`ctest --preset x64-modern-debug -R update -LE "matrix|bench|interop"` runs `sd-test-update.exe` (34 tests). Fixtures are
made at test time by `sd-updsign` in a temporary directory (test keys only, removed afterwards). The engine tests run a
winsock server bound to `127.0.0.1` on an ephemeral port; no test connects anywhere else. The "new binaries" are copies of
`sd-test-update-fakeapp.exe`, whose `--selftest` (and `/update`) exit code is read from a `selftest.code` file next to it.

Covered: valid chain; manifest byte flip; wrong key (unknown key id); beta key on stable and stable key on beta; expired
keyset key; revoked key; expired manifest; freshness limits (30/14 days); serial rollback and same-serial-other-bytes;
channel mismatch; product mismatch; unknown format major; oversized manifest; sig line not last; keyset tampering;
keyset rollback; keyset signed by an unknown root; rotation with one root (refused) and both roots (accepted); per-channel
serials and the legacy migration; check, stage, apply and rollback in a temporary install directory; `--selftest` failure
restoring the old files byte for byte; HTTPS to HTTP fallback; redirect to a foreign host refused without connecting;
Content-Length above the manifest size; digest mismatch with nothing kept; setup exit code; staging cleanup.

## Open decisions

- **Release roots:** no root public key is compiled into this build. The release build must add the two root keys and
  the keyset current at build time (`installer/keys/`, 04 §9.3); until then every verification fails closed
  (`update_verify_failed`). The `k_trust` table in `update_ipc.c` is the single place to change.
- **Bootstrap URLs:** only the GitHub URL is the default. The HTTP mirror (`http://dl.<our-domain>/...`) needs the domain
  (D30, an operational choice); until then, testers set `manifest_url`. The `manifest_alt` slot exists for it.
- **Beta:** there is no default beta manifest URL; a beta user sets `manifest_url` and `channel = beta`.
- **Install mode:** the agent always uses setup mode. MSI installs (`msi-<flavour>`) and the detection of an MSI
  install are not implemented; the engine supports the mode.
- **Portable updates:** check only. Unpacking a portable archive is not implemented (no zip reader in the product).
- **Per-machine updates:** the elevated stages of 04 §6.4 and §9.6 (admin-only copy, re-verification in stage 2) are the
  setup program's job and are not in the agent.
- **Progress granularity:** the events report stages, not byte counts.
- **Trust state:** `state\keyset` and `state\roots` are trusted as local files (see 04 §9.7).

Developer notes for milestone M4 (installer). Decisions are in `docs/design/04-build-install-update.md` §6.10.

## Setup engine

Components, all under `apps/shelldrive-setup/` unless noted:

- `setup_core.h`: public interface of the engine (`sd_setup_core`, static library, built in every preset).
- `setup_args.c`: command line, host detection, flavour choice, Dokany decision, version order, payload table
  lookup, CAB member-name rules.
- `setup_cab.c`: payload extraction through `cabinet.dll` FDI (loaded from System32, memory source).
- `setup_reg.c`, `setup_host.c`, `setup_shortcut.c`, `setup_log.c`, `setup_msg.c`, `setup_util.c`: registration,
  running agents, Start menu shortcut, setup log, message formatting, helpers.
- `setup_install.c`: per-user install, repair, upgrade, portable and uninstall.
- `setup_main.c`, `setup_ui.c/.h`: the stub (`shelldrive-setup-stub.exe`, x86-ia32 preset only). The window is a
  minimal progress view behind `setup_ui.h`; the frontend replaces it.
- `packaging/registration.txt`: registry rows, single source (also for the MSI later).
- `tools/sd-payload/`: attaches the payload CAB and the `PAYLOAD_TABLE` hash to the stub copy.
- `l10n/installer/*.po`: installer strings, six locales.
- `tests/setup/`: `sd-test-engine.exe` (24 tests, CTest `unit.engine`). CAB fixtures are made at run time with
  `makecab` (traversal fixture has a `..\evil.txt` member).

Build and test (worktree root, Visual Studio generator through the presets):

    cmake --preset x86-ia32
    cmake --build build/x86-ia32 --config Debug --target shelldrive-setup
    ctest --test-dir build/x86-ia32 -C Debug -R "engine|importcheck.stub" --output-on-failure

Output: `build/x86-ia32/bin/Debug/shelldrive-setup.exe` (stub plus payload), `shelldrive-setup-stub.exe` (without
payload, the uninstaller's source), `sd-test-engine.exe`.

Tests never touch the real account: HKCU is redirected with `RegOverridePredefKey` to a test key
`ShellDriveTest-<hex>` under HKCU, and removed afterwards. Start menu shortcuts, hooks and running-agent signals
are switched off through `skip_*` options. Do not run the stub on a development machine to test installs: it
writes to the real account.

### Gotchas found in M4

- **FDI and multi-member CABs.** FDI opens the cabinet more than once while it decodes. Every `pfnopen` needs
  its own read position. With one shared position the second reader hit the end of the payload and FDI reported
  `FDIERROR_CORRUPT_CABINET` after the first member. Single-member archives always worked, which hid it.
- **Installer detection.** An executable whose name contains `setup`, `install` or `update` is elevated by
  Windows unless its manifest says `asInvoker`. The stub has that manifest; the test executable is named
  `sd-test-engine` for this reason.
- **Registry test key.** A key created implicitly with a volatile option is volatile, and a non-volatile child of
  a volatile key fails with error 1021. The test key is created one level deep and non-volatile.
- **Toolhelp and cabinet.dll are not on the XP floor list.** They are resolved with `sd_setup_proc` (run time),
  never imported.
- **Generated sources.** The catalog helper generates into `build/<preset>/generated/l10n/$<CONFIG>`; that works
  with the Visual Studio generator as is.
- **Lint-free C.** `/W4 /WX` plus `_CRT_SECURE_NO_WARNINGS` only in build-time tools. Use `StringCchPrintfW`, not
  `_snwprintf`; avoid `wcsstr` in the stub (not on the IA32 ISA allowlist, so the ISA audit fails).

### Open items (M4)

1. `PAYLOAD_SIG`: the payload table is not signed yet and the stub does not verify a signature (TM-R38). Needs
   the release keyset (04 §6.1, 04 §9.3).
2. Per-machine install: MSI build (WiX 3.14.1), the two elevation stages, and the `%ProgramData%\LibreStatic`
   checks (TM-R34). `/permachine` returns the machine-unsupported message; administrators get per-user by default.
3. Dokany chaining: the `DOKANY_<ARCH>` payload resource and the per-machine call. The decision function exists.
4. `/extract=` admin copy (needs the MSI).
5. ARM64 stub (`arm64` preset is not built here) and the ARM32 EXE.
6. Agent shutdown event: `shelldrive-host.exe agent` does not create
   `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<session>` yet (03 §1.2). Until it does, the upgrade
   wait finds nothing to signal.
7. Hooks in M5: `webdav-tune`, `user-cleanup`, `modern-menu`, `programdata-secure` log "not yet implemented".
8. `/removedata` (remove settings on uninstall) is not implemented.
9. KnownDLLs and XP floor: `tests/os-imports/knowndlls.txt` comes from a Windows 11 capture; the XP SP3 and XP x64
   captures (04 §11.4 lab) must confirm it. The ten Win32 1.0 names added to `xp-sp3-x86.txt` need the same
   confirmation.
10. Frontend (done in `wip/r6-uisetup`): the wizard pages in `setup_ui.c` (welcome, MIT license, mode, destination, Dokany,
    progress, finish, removal confirmation) are driven by the page flow in `setup_flow.c`. Plain Win32 controls, no comctl32.
    The all-users choice is shown disabled (`SD_FLOW_MACHINE_AVAILABLE = 0`), so the Dokany page is reached only through
    `shelldrive-setup-stub.exe /test-pages /permachine` until the MSI lands. No language page: the language follows
    `/lang` and the UI language order (03 §9.3). Hidden `/test-pages` builds the pages, logs them and installs nothing.

## ADMX and reproducibility

Branch `wip/m4-admx`. Design references: 03 §3.5 (policy values), 04 §8.4 and §8.6 (ADMX/ADML, localization),
04 §12.2 (reproducible builds).

### Policy table and template

- `res/policy/policies.txt` is the single source of the 21 policy values (03 §3.5), with `@key
  Software\Policies\LibreStatic\ShellDrive`.
- `tools/sd-admxgen` (build-time C, no third-party code) generates into `generated/policy/`:
  `ShellDrive.admx`, `en-US`, `es-ES`, `fr-FR`, `pt-BR`, `it-IT`, `de-DE` `ShellDrive.adml`, `sd_policy_ids.h`
  and `sd_policy_table.h`. The output has no timestamps or absolute paths.
- Texts come from `l10n/policy/<lang>.po` (domain `policy`, six locales, English in msgid of `en.po`). `sdl10n --check
  --domain l10n/policy` (ctest `l10n.policy_catalogs_complete`) checks completeness, register and plurals. Keys are
  lower case (`policy.<name>.title`, `.explain`, `.label`, `.opt.<value>`), because sdl10n accepts `[a-z0-9_.-]`.
- Deviation: the ADML is produced by `sd-admxgen` and not by `sdl10n` (04 §8.6, C41 say `sdl10n`). `sdl10n` still
  owns the completeness rules for the domain. Owners of the ADML format should confirm this.
- The table has no decimal policy. The generator, the ADMX and the checks support `decimal` (min and max); unit tests
  cover it, and the first decimal policy needs only a table line and six translations.
- `supportedOn`: `SD_SUPPORTED_XP` (Windows XP SP3 or later) for 20 policies, `SD_SUPPORTED_WIN11` for
  `DisableModernContextMenu`.
- Enum types: `UpdateHostKeys`, `LegacyAlgorithms`, `LogPrivacy` are REG_DWORD; `UILanguage` (en, es, fr, pt-BR, it, de)
  and `UpdateChannel` (stable, beta) are REG_SZ, as the readers expect.

### Readers

- `src/sd_policy` (`sd_policy_get_dword`, `sd_policy_get_sz`) reads HKLM then HKCU with the generated names and
  types. A value of the wrong registry type reads as absent. Nothing writes the registry.
- `src/sd_l10n` (UILanguage) and `apps/shelldrive-host/explorer_data.c` (DisableNetworkLocations) use it. The
  `UILanguage` fallback changed slightly: an HKLM value of the right type is used even when it names an unknown language,
  so HKCU is no longer consulted in that case (the old code fell back to HKCU only when HKLM was absent or unparsable).
- `tests/policy/check-raw-reads.ps1` (ctest `policy.no_raw_reads`) fails when a source outside `src/sd_policy` contains
  the key path or a `L"<value name>"` literal.

### Checks

- `tests/policy/check-admx.ps1` (ctest `policy.admx_structure`): XML well-formedness, the target namespace, the policies
  against the table (name order, class, key, valueName, supportedOn, enum items and their value types, text maxLength,
  decimal range), every category, definition, presentation and `$(string.*)` reference, unique ids and names, the six
  culture folders and the strings and presentations of each ADML. It does not validate against the PolicyDefinitions
  schema, which is not available offline.
- `unit.admxgen` (`tools/sd-admxgen/test_admxgen.c`): XML and C escaping, table validation (every rejected form), PO
  parsing (continuation lines, escapes, fuzzy entries, plurals), enum and decimal and boolean emission, the headers,
  and a full run over the real table and catalogs (21 policies).
- `unit.policy` (`tests/unit/sd_policy`): the table is complete and its kinds match the readers; type mismatches
  read as absent.

### Reproducible builds

- Flags: `/Brepro` (compile and link), `/PDBALTPATH:<pdb name>`, `/Zi`, `/OPT:REF /OPT:ICF` (Release) were already in
  `cmake/SdOptions.cmake`, and nothing was added. No shipping source uses `__DATE__`, `__TIME__`, `__TIMESTAMP__` or
  `__FILE__`.
- `tools/check-repro.ps1 -Preset <preset> [-Config Release] [-KeepBuilds]` builds the preset twice (`build\repro-a`,
  `build\repro-b`) from one source tree mapped with `subst` to a free drive letter, and compares the PEs (`bin\*.exe`,
  `bin\*.dll`), the static libraries (`lib\*.lib`) and `generated\policy\**` byte for byte. PDBs are not compared.
- ctest `repro.x64-modern` and `repro.x86-ia32` (label `repro`). They are excluded from the default run in
  `tools/ci-local.ps1` (`-LE 'matrix|bench|repro'`) and from the commands in this file.

#### Results

RESULTS_PLACEHOLDER

### Build and test commands

```
cmake --preset x64-modern
cmake --build --preset x64-modern-debug
ctest --preset x64-modern-debug -LE "matrix|bench|interop|repro"
powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x64-modern
powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x86-ia32
```

## MSI

Per-machine MSI packages (04 §8; decisions and open items in 04 §8.7). Opt-in: `-DSD_BUILD_MSI=ON`, then
`cmake --build build/<preset> --target msi` (WiX 3.14 at `WIX` or `C:\Program Files (x86)\WiX Toolset v3.14`). Output:
`build/<preset>/msi/<Config>/ShellDrive-<MAJOR.MINOR.PATCH>-<flavour>.msi` with every language transform embedded.

| Path | What |
|---|---|
| `packaging/msi/ShellDrive.wxs` | the package for every flavour (defines from `build-msi.cmake`), the `ShellDriveUI` dialog set (WixUI_Common dialogs, feature tree, options page), features, hooks |
| `packaging/msi/build-msi.cmake` | one flavour: sd-msigen, candle, light (ICE), torch per language, sd-msiembed |
| `packaging/msi/CMakeLists.txt` | the `msi` target, per-flavour table (family, platform, UpgradeCode, launch condition) |
| `tools/sd-msigen/` | GUIDs, `Registry.wxi` from `packaging/registration.txt`, `.wxl` from the `msi.*` entries of `l10n/installer` |
| `tools/sd-msiembed/` | embeds a language transform under its LCIDs through `msi.dll` and updates the Template summary |
| `packaging/msi/wixui/` | WixUI string overrides, one complete `WixUI_<culture>.wxl` per culture (es-es voseo, de-de `du`, it-it informal), and `dialog-set.txt` (the 212 WixUI ids the package shows) |
| `tests/msi/` | `sd-test-msi`: `tables` (package contents, transforms with the language check) and `admin` (`msiexec /a`); `check-wixui.cmake` (`msi.<flavour>.wixui`: every id of `dialog-set.txt` in every override, Spanish register lint) |

Checks: `ctest -L msi` (after the `msi` target). Light runs ICE validation on the base package; the suppressions and
their reasons are in 04 §8.7. Strings for the installer are in `l10n/installer` (the `msi.*` entries; the lowercase dotted
msgctxt is the id, the WiX id is its PascalCase form, for example `msi.feature.core.title` is `FeatureCoreTitle`).

WixUI strings: the stock `WixUI_<culture>.wxl` of the WiX SDK is not edited. `build-msi.cmake` passes an override
`packaging/msi/wixui/WixUI_<culture>.wxl` to light before the stock file when it exists (light takes the first definition
of an overridable string). fr-fr and pt-BR have no override:
the stock French ("vous") and Brazilian Portuguese ("você") text already follows the register. The ids of the dialog set
were taken from the built package: every WixUI `loc.*` reference of the Control, Dialog, RadioButton and UIText tables.
To rebuild the list, replace each WixUI string with a marker in a copy of `WixUI_en-us.wxl`, light the English package
with it and read the `@@` markers back from the tables (`WindowsInstaller.Installer`); overrides are then regenerated.

Dialog set (`ShellDriveUI`, 04 §6.7 and §8.7): the flow of `WixUI_FeatureTree` on the stock `WixUI_Common` dialogs, with
`OptionsDlg` after the customize page. Maintenance (Change, Repair, Remove) comes from the maintenance dialogs of the same set.
`ARPNOMODIFY` is `0`, set explicitly (Property table checked with `WindowsInstaller.Installer`), so "Change" is offered and
runs the feature tree and the options page. The install folder is no longer configurable in the dialogs (no
`ConfigurableDirectory`). The license page shows the repository `LICENSE`, converted to RTF by `build-msi.cmake` (candle gets
`-dSD_LICENSE_RTF`). The `DOKANY` and `ENABLELINKEDCONNECTIONS` checkboxes are bound to `SD_UI_DOKANY` and `SD_UI_ELC`
(`CheckBoxValue="1"`), not to the public properties, which have no default (empty = not given).
Remembered choices (04 §8.7): `C_Installer` (always installed, Core) writes `HKLM\SOFTWARE\LibreStatic\ShellDrive\Installer`
with `DOKANY`, `ENABLELINKEDCONNECTIONS` and `ELC_OWNED`. Each run reads them with `RegistrySearch` (`SD_REG_*`, `RegLocator`
rows). The init rows (`SetSD_UI_DOKANY`, `SetSD_UI_ELC`, `SetSD_UI_INIT`, after `AppSearch`) take the command line first, then
the stored value, then the default, once per run; the state rows (`SD_DOKANY_STATE`, `SD_ELC_STATE`, `SD_ELC_WRITE`) come before
`CostInitialize`. `C_Ini_Backend` follows `SD_DOKANY_STATE` (`[backend] dokany = no` when 0), so `settings.ini` and the registry
agree. The `SD_PRODUCT_DATA`, `SD_DOKANY_INI` (IniFileSearch) and `SD_ELC_EXISTS`-only preselection of the earlier draft are gone.
ELC ownership: `C_LinkedConn` is installed only when `SD_ELC_WRITE = 1` (wanted, and the value does not exist or `ELC_OWNED`
is 1). `ELC_OWNED` records what the package wrote, so uninstall (which removes an installed keypath value) removes it only when
this package created it. A value that exists and is not ours is never written, changed or removed.
Checks: `msi.<flavour>.tables` covers the Property defaults, `ARPNOMODIFY`, the `RegLocator`/`AppSearch` rows, the `C_LinkedConn`
and `C_Ini_Backend` conditions, the `C_Installer` values and the sequence order.
The strings of the options page are `msi.options.*` in all six catalogs of `l10n/installer` (`WiX` ids `OptionsTitle`,
`OptionsDokanyCheckbox`, ...); the WixUI ids of the set are in the overrides, and `dialog-set.txt` lists them.

Open items: DEFAULTPROFILES (no MSI MoveFile authoring in WiX 3.14), `programdata-secure` runs after InstallFiles, hook
rollbacks not authored, SERVICE/SERVICESTART with the service (M5), shell extension registration rows, timestamps in the summary
information (12.2). Lab checks of the installed behaviour (11.4): the Installer key on install, Change, repair and uninstall; the
ownership rules with a pre-existing `EnableLinkedConnections` value; the options page. The Dokany driver is not installed or
removed by the MSI (setup does that).

## Installer audit and status (wip/r15-installer)

Audit of the M4 installer backlog (`docs/dev/handoff-backend.md`, "M4 — backend parts") against the tree. Status: **Done** =
implemented and checked (here or in CI); **Partial** = some of it exists, the rest is open; **Missing** = not in the tree;
**Blocked** = needs the lab, a certificate, or a design decision. Paths are relative to the repository root.

| # | Backlog item | Status | Where / evidence |
|---|---|---|---|
| 1 | Setup engine: CAB payload through `cabinet.dll` FDI, flavour choice by CPU and OS, per-user, portable, repair, uninstall | Partial (per user and portable done; machine mode missing) | `apps/shelldrive-setup/setup_*.c`; `tests/setup` (`sd-test-engine`, 37 tests pass) |
| 2 | Stub flavours: `x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, ARM64 and ARM32 stubs | Partial | Stub built by `x86-ia32` (importcheck and isacheck pass). ARM stubs are built by their presets; they cannot run here (04 §11.4). |
| 3 | Per-machine install through the MSI | Missing | `apps/shelldrive-setup/setup_main.c` refuses `SD_SETUP_MODE_MACHINE` (`MACHINE_UNSUPPORTED`); `/extract=` is refused too. |
| 4 | Two-stage elevation (04 §6.4): `runas` relaunch, stage 1, stage 2 (`/elevated-child`), pipe | Missing | No `runas`, hidden switch or pipe in `setup_main.c` or `setup_args.c`. Building blocks are in row 7. |
| 5 | DLL search rules (TM-R33), KnownDLL-only imports | Done | `restrict_dll_search` in `setup_main.c`; ctest `importcheck.stub.knowndlls`, `importcheck.shelldrive-setup-stub`, `isacheck.shelldrive-setup-stub` pass on `x86-ia32`. |
| 6 | Owner and link checks of `%ProgramData%\LibreStatic\ShellDrive` (TM-R34) | Partial (was Missing in the setup engine) | The check is the service's `apps/shelldrive-host/svc_repair.c` and `svc_folder.c` (tests `unit.svc`), now also compiled into `sd_setup_core` (`apps/shelldrive-setup/CMakeLists.txt`). Wrapper: `apps/shelldrive-setup/setup_trust.c` (`sd_setup_secure_programdata`, logs `setup.programdata_untrusted`). Test: `setup_programdata_trust`. The machine install path that would call it is still missing. |
| 7 | Stage folder with its protected DACL in one `CreateDirectoryW` call (04 §6.4 stage 1, step c) | Partial | `sd_setup_create_stage_dir` in `setup_trust.c`; test `setup_stage_dir_fresh_names`. Not wired: there is no stage 1. |
| 8 | Dokany decision table (04 §7.3) | Done for the decision; chaining Partial | `sd_setup_dokany_decide` in `setup_core.h`; the wizard option is `setup_flow.c`. |
| 9 | Dokany chaining after the `dokan2.dll` VC++ check (C31, D32) | Partial | `apps/shelldrive-setup/setup_dokany.c`: PE import reader for `vcruntime140*` and `msvcp140*`, chain choice (MSI, BUNDLE, UNAVAILABLE), command lines, run gate with an injected runner. This build injects none, so nothing starts. Tests: `setup_dokany_*` (5 tests). Missing: `installer/dokany/dokany.lock` (pins, signer), a production runner, the post-install `dokan2.dll` load check (`shelldrive-host --selftest`), and the [lab-verify] items of 04 §7.1 and §7.3 (dependency per architecture, bundle switches, signer name). |
| 10 | `REMOVESECRETS` | Done in the MSI; lab check pending | `packaging/msi/ShellDrive.wxs`: property (`REMOVESECRETS` = 1), removal conditions. The keep-secrets check of the install smoke (04 §11.2) is not run. |
| 11 | `DEFAULTPROFILES` (C9) | Missing | `ShellDrive.wxs`: accepted and ignored (WiX 3.14 has no MoveFile element; 04 §8.4 open item). |
| 12 | WiX MSIs for `x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern` | Done (build and `msiexec /a` checks); install lab pending | `packaging/msi/CMakeLists.txt` (flavour table), `build-msi.cmake`, `tests/msi` (`msi.<flavour>.tables`, `.admin`, `.wixui`). |
| 13 | ARM64 MSI | Blocked (missing) | `packaging/msi/CMakeLists.txt` refuses `SD_BUILD_MSI` on ARM presets: the MSI tools run on the x86/x64 host. Needs a cross-tree `msi` target (04 §8, M6). |
| 14 | ARM32 MSI (D31) | Blocked (missing) | No ARM32 row in the flavour table; same reason as row 13. |
| 15 | Language transforms for every LCID (C43) | Done | `tools/sd-msiembed`, `l10n/installer/*.po` (six locales), `msi.<flavour>.tables`. |
| 16 | WixUI overrides and the dialog set | Done | `packaging/msi/wixui/` (es-es voseo, de-de `du`, it-it informal), `tests/msi/check-wixui.cmake` (`msi.<flavour>.wixui`). |
| 17 | ADMX and ADML generated from the policy table (03 §3.5) | Done | `res/policy/policies.txt`, `tools/sd-admxgen`, `l10n/policy`. Run here (`x86-ia32` debug): `unit.admxgen`, `unit.policy`, `policy.admx_structure`, `policy.no_raw_reads`, `l10n.policy_catalogs_complete` pass. |
| 18 | Sparse MSIX build switch (D27) | Missing | No `packaging/msix`, no `SD_SPARSE_MSIX` option in CMake. Shipping also needs the certificate (D27). |
| 19 | Reproducible-build check (04 §12.2) | Done (not run in this change) | `tools/check-repro.ps1`; ctest `repro.*`, excluded from the default run. |
| 20 | Release pipeline (04 §12.3, §11.2) | Partial | `.github/workflows/ci.yml` pins its actions by SHA (done). New `.github/workflows/release.yml` skeleton: input and gate checks, build matrix, `check-repro`, binary upload. The `package` and `finalize` jobs stop with an error. Missing: `installer/` (keys, `release-gates.txt`, `dokany.lock`), `tools/sd-release`, `resign.yml`, `CODEOWNERS`, the `workflow-lint` job, the signed-tag gate and the tag trigger. |
| 21 | Two offline signing sessions (D42) | Missing (manual steps only) | `release.yml`: `signing-session-1` and `signing-session-2` are approval gates with the checklist, no secrets, no signing in CI. `sd-release verify` and `sign` do not exist. |
| 22 | `PAYLOAD_SIG` and signed payload tables (TM-R38) | Missing | Open item 1 of the M4 setup notes. |
| 23 | Installer hook `programdata-secure` (TM-R34) | Done in the hook; order Partial | `apps/shelldrive-host/installer_hooks.c` now runs `svc_repair_data` (host builds `svc_repair.c` too). Open: `CA_ProgramDataSecure` is scheduled `After="InstallFiles"` in `packaging/msi/ShellDrive.wxs`, but TM-R34 needs the check before any ProgramData write. The other hooks still log "not yet implemented (M5)". |
| 24 | Updater engine (04 §9) | Done (engine); MSI install detection missing | Section "Updater engine" above. |

### Changes made by this audit pass

- `apps/shelldrive-setup/setup_trust.c|h`: TM-R34 wrapper, common AppData lookup, stage folder creation.
- `apps/shelldrive-setup/setup_dokany.c|h`: VC++ dependency check of `dokan2.dll` (read-only PE parse, fails closed),
  chain choice, command lines, run gate. No process is started by the engine in this build.
- `apps/shelldrive-setup/CMakeLists.txt`: `sd_setup_core` compiles `svc_folder.c` and `svc_repair.c` from
  `apps/shelldrive-host` (one source, not a copy) and links `sd_base`.
- `apps/shelldrive-host/installer_hooks.c` and `CMakeLists.txt`: `programdata-secure --apply` runs the repair.
- `tests/setup/test_trust.c`, `tests/setup/test_dokany.c`, `tests/setup/main.c`, `tests/setup/CMakeLists.txt`: 7 new tests.
- `.github/workflows/release.yml`: skeleton, fails closed (see row 20).

Verification (`x86-ia32` debug, `sd-test-engine`, stub import and ISA audits, `unit.admxgen`, `unit.policy`,
`policy.*`): see the final gate run in the commit message.

### Open items after this audit

1. Per-machine install: the MSI call, the two elevation stages (runas, pipe, stage 2), and the wiring of rows 6, 7 and 9.
2. Move `CA_ProgramDataSecure` before `InstallFiles` (or check ProgramData first in the setup engine).
3. Dokany: `installer/dokany/dokany.lock`, the production runner (MSI and bundle), the post-install check, the lab items.
4. `DEFAULTPROFILES` (MSI MoveFile authoring or a custom action), `/extract=`, `/removedata`.
5. ARM64 and ARM32 MSI: a cross-tree `msi` target that takes ARM binaries from another build directory.
6. Release: `installer/` keys and records, `tools/sd-release`, signed tag gate, `resign.yml`, `CODEOWNERS`, `workflow-lint`.
7. Sparse MSIX (D27) build switch.
8. Lab checks: install smoke, `REMOVESECRETS`, Dokany and XP import captures (04 §11.4).

## Installer audit update (wip/r16-setupelev)

Second pass on the round 15 audit above: rows 3, 4, 6, 7, 11 and 23 (and their open items 1, 2 and 4 of that section).
Paths are relative to the repository root. Status words as in the audit table.

| # | Backlog item | Status | Where / evidence |
|---|---|---|---|
| 3 | Per-machine install through the MSI | Partial | `apps/shelldrive-setup/setup_main.c` (`run_machine`): `/permachine` starts the two stages and reads their result. Open: the MSI is not yet a member of the payload CAB (the release pipeline adds it), so stage 2 stops with `installer.error.msi_missing` today; the wizard's all-users choice stays disabled (`SD_FLOW_MACHINE_AVAILABLE = 0`); `/extract=` and the per-machine uninstall are not in this pass. |
| 4 | Two-stage elevation (04 §6.4) | Done in the engine; lab pending | `apps/shelldrive-setup/setup_elevate.c|h`. Parent (asInvoker): pipe server with the user SID DACL, `runas` (or in-process when already elevated). Stage 1: `secure_programdata`, `create_stage` (one call, protected DACL), `copy_image` (source opened with `FILE_SHARE_READ`), start the copy with `/elevated-child`. Stage 2: re-derives the folder from its own image, checks the stage name and root, the owner, the payload table hash, extracts, runs msiexec. Every process start, elevation check and msiexec call goes through `sd_setup_elev_ops`. Tests: `tests/setup/test_elevate.c` (15 tests, `setup_elev_*`). |
| 6 | Owner and link checks of `%ProgramData%\LibreStatic\ShellDrive` (TM-R34) | Done for the machine path | Stage 1 runs `sd_setup_secure_programdata` before any stage folder exists; stage 2 checks its folder for a reparse point and a trusted owner (`svc_repair_real_ops`). |
| 7 | Stage folder with its protected DACL (04 §6.4 stage 1, step c) | Done | `sd_setup_create_stage_dir` is called by stage 1. A successful stage removes its folder; a failed one keeps the MSI log (admin-only). |
| 11 | `DEFAULTPROFILES` (C9) | Done (authored); install lab pending | `packaging/msi/ShellDrive.wxs`: a `CustomTable` named `MoveFile` (copy, `*.ini`, source property `DEFAULTPROFILES`, destination `SD_CAD_PROFILES`) and component `C_DefaultProfiles`. WiX 3.14 has no `MoveFile` element; the custom table must sit directly in `Product` (in a fragment light drops it). Checked by `msi.x86-ia32.tables`. |
| 23 | `programdata-secure` before any ProgramData write (TM-R34, TM-R35) | Done | `CA_ProgramDataSecure` now runs from the `BIN_ShellDriveHost` Binary entry (BinaryKey), because the installed copy does not exist before `InstallFiles`. It is scheduled `Before="MoveFiles"` (and so before `InstallFiles`), and `MoveFiles` follows it. Runs again on repair (TM-R35). Checked by `msi.x86-ia32.tables`. |

Design decisions taken in this pass:

- Pipe protocol: one UTF-16 line per message: `P <percent>`, `M <msg id> <code>`, `R <exit code>` (last). The server end is
  nonblocking, so a stage that never connected cannot hang the parent. The parent reads the pipe after the stage has exited;
  live progress in the window is not done yet.
- Stage 2 takes no path from the command line. The forwarded switches are the sanitised set of `sd_setup_elev_forward`
  (quiet, passive, norestart, force, update, dokany, lang, flavour and the validated `PROPERTY=value` tokens, quoted). `/log=` and
  `/installdir=` are not forwarded; the MSI log is `msi.log` in the stage folder.
- `PROPERTY=value` tokens are now kept (`sd_setup_args.props`), each quoted, and reach msiexec unchanged. A token with a double
  quote is refused.
- Stage 2 checks the payload table hash of its own image before extraction, as the user path does. Hashes of the members after
  extraction are not checked: the payload has no member manifest yet (TM-R38, `PAYLOAD_SIG`).
- Four new installer messages (`installer.error.elevation`, `.stage_untrusted`, `.msi_missing`, `.msi_failed`) in all six
  catalogs of `l10n/installer`.
- `CA_ProgramDataSecure` moved from `After="InstallFiles"` to `Before="MoveFiles"`. `MoveFiles` is the default MSI step (before
  `InstallFiles`), so the hook also precedes `InstallFiles`.

Verification (`x86-ia32` Release, `ctest -C Release`): `unit.engine` (`sd-test-engine`, 52 tests, 15 new), `importcheck.shelldrive-setup-stub`, `isacheck.shelldrive-setup-stub`, `importcheck.stub.knowndlls` and the setup stub test-page checks pass; with `-DSD_BUILD_MSI=ON`, `msi.x86-ia32.tables`, `.admin` and `.wixui` pass (`msiexec /a` admin image only).

Open items after this pass:

1. Put `ShellDrive.msi` into the payload of each flavour (`cmake/SdPayload.cmake`, `tools/sd-payload`; the MSI needs WiX, so the payload step must follow the `msi` target). Until then `/permachine` reports `installer.error.msi_missing`.
2. Live progress in the parent window; copy the stage log to the user's `/log=` path.
3. Per-member SHA-256 manifest for the post-extraction check, together with `PAYLOAD_SIG` (TM-R38).
4. Wizard: the all-users choice and its options page (`SD_FLOW_MACHINE_AVAILABLE`), so interactive per-machine installs show the pages.
5. Per-machine uninstall through the same two stages, and `/extract=`.
6. Lab checks (04 §11.4): UAC prompt and the XP Run As dialog, the pipe under a split token, the stage folder DACL, msiexec install, Change, Repair and Remove, and the ProgramData hook order.
7. CI note: the required gate's `-TestRegex 'setup|msi|l10n|importcheck|isacheck'` does not match the CTest name `unit.engine`, so the 52 engine tests run only with `ctest -R engine` (or `-R unit`). Add `engine` to the regex in the release gate.
