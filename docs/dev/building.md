# Building ShellDrive

Design reference: `docs/design/04-build-install-update.md` §2–§4 and §11. This page lists the
commands that are known to work.

## Requirements

- Visual Studio 2022 17.14 (Build Tools are enough) with the components in `.vsconfig`. For M0 you need:
  - `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` (v143, MSVC 14.44) and the Windows SDK 10.0.26100,
  - `Microsoft.VisualStudio.Component.VC.v141.x86.x64` and `Microsoft.VisualStudio.Component.WinXP`
    (v141_xp, MSVC 14.16, Windows SDK 7.1A) for the `x64-xp` preset,
  - `Microsoft.VisualStudio.Component.VC.ASAN` only for the optional ASan build.
- CMake 3.25 or newer. The one bundled with VS works and needs no PATH change:
  `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
  (`ctest.exe` is in the same folder). A Developer PowerShell for VS 2022 puts both on PATH.

The presets use the "Visual Studio 17 2022" generator, so no vcvars environment is needed. Ninja is
not supported for the XP preset (it ignores the toolset).

## Presets

| Configure preset | Toolset | Notes |
|---|---|---|
| `x64-modern` | v143, SDK 10.0.26100 | Windows 10+, `/sdl /guard:cf`, `/CETCOMPAT`, `/std:c11` |
| `x64-xp` | v141_xp, SDK 7.1A | XP x64 SP2+, `/SUBSYSTEM:...,5.02`, no CFG |
| `x64-analysis` | v143 | `/analyze` (warnings are errors); add `-DSD_ENABLE_ASAN=ON` for AddressSanitizer |

Build presets: `x64-modern`, `x64-modern-debug`, `x64-xp`, `x64-xp-debug`, `x64-analysis` (Debug).
Test presets have the same names. Build trees go to `build/<configure preset>/`; executables to
`build/<preset>/bin/<Debug|Release>/`.

## Commands

From the repository root, in PowerShell (`$cmake`/`$ctest` can be plain `cmake`/`ctest` when they
are on PATH):

```powershell
$bin   = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$cmake = "$bin\cmake.exe"; $ctest = "$bin\ctest.exe"

# Windows 10+ flavour
& $cmake --preset x64-modern
& $cmake --build --preset x64-modern          # Release
& $cmake --build --preset x64-modern-debug    # Debug
& $ctest --preset x64-modern
& $ctest --preset x64-modern-debug

# XP flavour
& $cmake --preset x64-xp
& $cmake --build --preset x64-xp
& $cmake --build --preset x64-xp-debug
& $ctest --preset x64-xp
& $ctest --preset x64-xp-debug

# Static analysis
& $cmake --preset x64-analysis
& $cmake --build --preset x64-analysis
& $ctest --preset x64-analysis
```

Run one unit-test executable directly with `--list` or `--filter <substring>`, e.g.
`build\x64-xp\bin\Release\sd-test-base.exe --filter utf`.

## What the build enforces

- **Import audit.** Every shipping executable (`sd_add_app`) runs `tools/sd-importcheck` as a post-build
  step against the flavour's floor list in `tests/os-imports/` (`xp-sp2-x64.txt` for `x64-xp`,
  `win10-1507-x64.txt` for `x64-modern`). A post-XP static import, a missing `/DYNAMICBASE` or
  `/NXCOMPAT`, a wrong subsystem version (5.02 on `x64-xp`), CFG on the XP flavour or missing CFG/CET on
  `x64-modern` fails the build. The same check runs again as CTest `importcheck.*`, plus a negative test
  that must reject a fixture importing `GetTickCount64`. Use any Vista+ API through
  `sd_platform_resolve()` instead (`src/sd_platform/include/sd_platform/sd_platform.h`).
- **Localization completeness.** `tools/sdl10n` compiles `l10n/<domain>/<lang>.po` into C tables and fails
  the build if any locale (es, fr, pt-BR, it, de) misses a string, has a fuzzy or stale entry, lacks a
  CLDR plural form, uses different placeholders than English or has a non-canonical `Plural-Forms`
  header (03 §9.2, D26).

  Developer escape hatch, never for CI or releases: configure with
  `-DSD_L10N_ALLOW_INCOMPLETE=ON` (e.g. `& $cmake --preset x64-modern -DSD_L10N_ALLOW_INCOMPLETE=ON`).
  Missing, empty, fuzzy and stale translations then become warnings and fall back to English at run
  time; structural errors (placeholders, plural forms, header, UTF-8) still fail. Turn it off again
  with `-DSD_L10N_ALLOW_INCOMPLETE=OFF`.

  Check the catalogs without building: `build\x64-modern\bin\Release\sdl10n.exe --check --domain l10n\cli`.
- **Warnings are errors** (`/W4 /WX`) on both toolsets; the v141 C compiler is the common dialect (no VLAs,
  `_Generic`, C11 atomics/threads, `_Thread_local`; see `include/sd/base.h`).

## CI

`.github/workflows/ci.yml` builds and tests `x64-modern` and `x64-xp` (Release and Debug) and the
`x64-analysis` preset on `windows-2022`. The XP job installs the v141_xp components first with
`.github/actions/setup-xp-toolset`. Actions are pinned by commit SHA (TM-R39).

## Known noise

- `x64-xp`: the SDK 7.1A `mt.exe` prints `manifest authoring warning 81010002: Unrecognized Element
  "longPathAware"`. The element is ignored by older loaders; the warning is harmless (manifest lab check
  on XP is 04 §3.3's `[lab-verify]`).
