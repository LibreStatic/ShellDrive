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
10. Frontend: setup pages (mode, options, Dokany, language) replace `setup_ui.c`, using the same engine interface.

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
