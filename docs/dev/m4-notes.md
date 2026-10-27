# M4 notes

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
