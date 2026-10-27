# 04 — Build, packaging, installation, updates, CI and test infrastructure

Status: draft, updated with the accepted decisions (`decisions.md`, 2026-10-24), the conflict resolutions
of `00-integration-review.md` and the threat-model recommendations of `05-threat-model.md` that target this
document (TM-R23, R28, R29, R33–R39, TM-Q06/Q09 as decided by D36/D38; §16). Scope: everything between "source code" and "a running, updatable ShellDrive on
the user's machine", plus the test infrastructure that proves it works on every supported OS, architecture and
build flavour.

Companion documents: `01-ssh-sftp-crypto.md` (SSH/crypto core), `02-filesystem.md` (WebDAV + Dokany adapter),
`03-apps-platform.md` (host agent/service, CLI, UI, shell extension, configuration schema, localization),
`05-threat-model.md` (threats `T-xx`, recommendations `TM-Rxx` and tests `TST-xx` cited here). Where this document imposes a rule on them, it is listed in §14 "Contracts with other teams". Where
`decisions.md` and this document differ, `decisions.md` wins; §16 lists the decisions and conflict ids applied
here.

Facts that were verified on the web are cited inline. Everything marked **[lab-verify]** must be confirmed in the
test lab (§11.4) before release 1.0.

---

## 1. Decisions at a glance

| Topic | Decision |
|---|---|
| Binaries (D3) | Four per flavour: `shelldrive.exe` (CLI), `shelldrive-host.exe` (`agent` and `service` modes), `shelldrive-ui.exe`, `shelldrive-shellext.dll`; plus setup stub and `uninstall.exe` |
| Build flavours (D4, D28, D5) | Six: `x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, `arm32` (best effort), `arm64` (§1.1) |
| Compiler, x86 and `x64-xp` | MSVC **v141_xp** (VS2017 14.16 toolset, Windows 7.1A SDK), driven from VS2022 17.14 |
| Compiler, `x64-modern` / ARM64 | MSVC **v143** (VS2022) + Windows SDK **10.0.26100** |
| Compiler, ARM32 | MSVC **v143** (VS2022) + Windows SDK **10.0.22621** (last SDK with ARM32 libs) |
| Extra (non-shipping) build | v143 x64 for ASan, libFuzzer, `/analyze`, C11 conformance |
| Build system | **CMake ≥ 3.24** with the **"Visual Studio 17 2022"** generator, one `CMakePresets.json` preset per flavour |
| CRT | **Static `/MT`**, curated CRT subset; no-CRT rejected for v1 (§3) |
| Language level | Code must compile as MSVC v141 C (C99 subset + MS extensions); C11 features behind macros |
| Hardening | `/GS`, `/DYNAMICBASE /NXCOMPAT`, `/SAFESEH` (x86), `/HIGHENTROPYVA` (64-bit); `/guard:cf` on v143 flavours only; `/CETCOMPAT` on `x64-modern` |
| Third-party code (D1) | **None shipped**, crypto included; the only third-party binary shipped is Dokany, unmodified |
| Installer technology | Our own native setup EXE (C, same codebase) + WiX-built MSI for per-machine |
| Setup stub | Built from the `x86-ia32` preset (runs on any x86/x64 CPU); picks the flavour by CPU (SSE2) and OS version (§6.2) |
| Per-machine install | **Always via our MSI** (the EXE is a chainer: Dokany, then our MSI); **service installed and enabled by default** (D6) |
| Per-user install | EXE copies files itself, HKCU registration, no admin, **never a service**, no Dokany install |
| Payload container | **CAB** (built with `makecab`, extracted with `cabinet.dll` FDI — native on XP+) |
| MSI authoring | **WiX 3.14.1** now (on GitHub runners, XP-proven, no WiX custom actions used); migrate later |
| MSI packages | One per flavour, including **ARM32** (D31); flavours of one architecture share an UpgradeCode |
| Dokany | Pinned version **2.3.1.1000**; offline setup EXEs embed upstream `Dokan_<arch>.msi` or the upstream `DokanSetup.exe` bundle, depending on the VC++ dependency check (D32, §7.3); universal EXE downloads on demand; SHA-256 and upstream signer pinned and checked at embed and at install (TM-R23); never modified. Installing it is an **explicit, pre-checked option** on the per-machine options page (7 SP1+), mirrored by the MSI property `DOKANY` (D36, §6.3) |
| Localization | PO is the only source; `tools/sdl10n` generates C tables, STRINGTABLEs, `.wxl` and ADML with full CLDR plural categories (D26) |
| Updates | Signed text manifest (ed25519, `sd_crypto`); offline **root** keys certify per-channel release keys in a signed `keyset` (rotation, revocation), per-channel anti-rollback, `expires` ≤ 30/14 days (TM-R36, TM-R37, §9.2–§9.3); HTTPS first, **plain-HTTP mirror on static object storage** (D30) for XP/Vista/unpatched 7; consent required; settings in `settings.ini [update]` |
| Installer elevation | Setup stub and `uninstall.exe` import only KnownDLLs and restrict the DLL search path; the elevated instance never runs its work from `Downloads` but from a copy in a fresh admin-only directory; `%ProgramData%\LibreStatic\ShellDrive` ownership checked and reset; no SYSTEM custom action runs during repair except idempotent ones (TM-R33–R35, §6.4, §8.3) |
| Release gates | No public download links until Authenticode exists (TM-R38); no public beta before crypto review pass 1, 1.0 only after pass 2 (D38); stable signing only after an independent rebuild by the maintainer outside GitHub Actions (TM-R39, §12.3) |
| Authenticode | Pipeline designed, disabled until a certificate exists (SignPath Foundation, else Certum OSS, before a public 1.0 — D29); PE dual-signed SHA-1 + SHA-256; MSI single SHA-256 |
| Windows 11 modern menu (D27) | Signed sparse MSIX package in 1.0 **only if** the certificate exists in time; otherwise classic menu only |
| CI | GitHub Actions, **`windows-2022`** runners (pinned), install the WinXP component per job; six-flavour build matrix |
| XP/Vista/7/ARM32 testing | Self-hosted Hyper-V (or QEMU/KVM) lab with snapshots and a serial-port smoke harness; a QEMU VM without SSE2 for `x86-ia32` |
| Integration fixture | OpenSSH `sshd` inside WSL on the Windows runner (test-only, D21), legacy servers in the lab |
| Versioning | SemVer `MAJOR.MINOR.PATCH`; Windows file version `MAJOR.MINOR.PATCH.BUILD` |

### 1.1 Build flavours

Normative table (from `decisions.md`). A *flavour* is one compiled set of the four binaries.

| Flavour | Toolset / SDK | Arch flags | Min OS | Selected when | Notes |
|---|---|---|---|---|---|
| `x86-ia32` | v141_xp, 7.1A | `/arch:IA32` | XP SP3 | x86 OS and CPU without SSE2 | Pentium Pro/II/III, Athlon XP class; portable scalar crypto only; also builds the setup stub and `uninstall.exe` |
| `x86-sse2` | v141_xp, 7.1A | `/arch:SSE2` | XP SP3 | x86 OS with SSE2 (default x86) | SSE2/SHA-NI/AES-NI fast paths, runtime-detected; its shell DLL is the x86 copy installed on x64/ARM64 |
| `x64-xp` | v141_xp, 7.1A | — | XP x64 SP2 / Vista+ | x64 OS below Windows 10 | No CFG, no CET |
| `x64-modern` | v143, 10.0.26100 | `/guard:cf`, `/CETCOMPAT`, `/sdl` | Windows 10 | x64 OS, Windows 10 or later | Doubles x64 test runs |
| `arm32` | v143, 10.0.22621 | `/guard:cf` | Windows 10 on ARM / Windows 11 ≤ 23H2 (ARM32 app support; RT 8.1 and 10 IoT Core not runnable, §5.1) | ARM32 setup EXE / MSI only | Best effort (D5): CLI + host in agent mode + WebDAV only; dropped if the toolchain breaks. **Build only** in CI and ci-local, cross-compiled with the build-time tools from a nested x64 build (§2.5), no test run; no UI, no shell extension (§5.1) |
| `arm64` | v143, 10.0.26100 | `/guard:cf` (no `/CETCOMPAT`: x64 only) | Windows 10 on ARM (1709) | ARM64 OS | Native host; ARM64 + x86 (+ x64 on Windows 11) shell DLLs. **Build only** on x64 hosts (M6): cross-compiled, build-time tools from a nested x64 build (§2.5), no test run (§11.4) |

The `arm64` flavour (M6) is built with `cmake --preset arm64` (`arm64-debug` for Debug). `/volatile:ms` is set on every flavour
(§3.2), so volatile flags and sequence counters are acquire/release on ARM64 as they are on x86 and x64.

Flavours of the same architecture share all source code; the flavour only changes the configure preset. Every
binary carries its flavour name in its version resource (`SD_FLAVOUR`, e.g. `"x64-modern"`; the same resource has
`CompanyName` = `LibreStatic` and `ProductName` = `ShellDrive`, D45), which the updater
and `shelldrive selftest --json` report.

---

## 2. Toolchain

### 2.1 Why two MSVC toolsets

- VS2019 and later toolsets cannot target XP; the only Microsoft-supported route is the VS2017 **v141_xp**
  toolset, still offered as the individual component *"C++ Windows XP Support for VS 2017 (v141) tools
  [Deprecated]"* in the VS2022 installer
  ([Microsoft Learn: Configuring programs for Windows XP](https://learn.microsoft.com/en-us/cpp/build/configuring-programs-for-windows-xp)).
  It is on the VS2019 out-of-support component list, so it receives no fixes
  ([out-of-support components](https://learn.microsoft.com/hi-in/previous-versions/visualstudio/visual-studio-2019/install/out-of-support-components)).
- v141_xp targets **x86 and x64 only**. It has no ARM or ARM64 back end.
- VS2026 (toolset v145) raised the minimum target OS to Windows 10 and **dropped the ARM32 toolchain**
  ([Microsoft Learn: features deprecated or removed](https://learn.microsoft.com/en-us/cpp/porting/features-deprecated-in-visual-studio?view=msvc-170)).
  Therefore **VS2022 (v143) is the last toolset that builds ARM32**, and we pin to VS2022 17.14.
- Windows SDK **10.0.26100 ships empty `um\arm` / `ucrt\arm` lib folders**; ARM32 builds must pin
  **10.0.22621** ([SDL issue #11484](https://github.com/libsdl-org/SDL/issues/11484),
  [notepad4 issue #839](https://github.com/zufuliu/notepad4/issues/839)). We found no official Microsoft
  statement; treat 22621 as "last known good" and keep it in the pinned `.vsconfig`.
- ARM64 and `x64-modern` use v143 with SDK 10.0.26100 (the current SDK; nothing in our code needs newer).
  `x64-modern` exists because v141 cannot emit `/CETCOMPAT` and its CFG output is not trusted on XP (§3.2);
  Windows 10+ x64 users get CFG and CET shadow-stack compatibility without giving up XP x64 support (D28).

**One codebase, two toolsets: yes.** The toolset is a property of the CMake configure step
(`-T v141_xp` vs `-T v143`), not of the source. The only consequences for source code are:

1. The common language is what v141's C compiler accepts (§2.3).
2. Headers come from SDK 7.1A on x86 and `x64-xp` and from the Windows 10/11 SDK on `x64-modern`, ARM32 and
   ARM64. Code must not rely on
   declarations that exist only in newer SDKs; post-XP APIs are declared in our own
   `include/sd/winapi_compat.h` and resolved at run time (§2.4).

### 2.2 Alternatives evaluated

| Option | Verdict |
|---|---|
| **clang-cl** (LLVM 20 is on the runners) | Can target XP only by linking against the v141_xp CRT/SDK 7.1A libs anyway; adds a second compiler to qualify. Kept as an **optional lint/sanitizer compiler** (warnings, `-fsanitize=fuzzer` alternative), never for shipped binaries. |
| **MinGW-w64** | A native toolchain (not Cygwin), technically able to target XP and ARM64 (llvm-mingw). But its runtime (mingw-w64 CRT, winpthreads, libgcc/compiler-rt) is a port of Unix-ecosystem runtime code linked into every binary, which is at odds with the "no ported Unix code" spirit even if the letter permits it. It also brings GNU headers that differ from the SDK. **Rejected for shipped binaries.** |
| **VS2026 v145** | Cannot target XP/7/8 or ARM32. Usable only for the non-shipping analysis build in future. |

### 2.3 Language rules imposed by v141

v141 `cl.exe` in C mode is effectively C99 with gaps and has no `/std:c11` (that arrived in VS2019 16.8).
Rules (enforced by building every module with both v141_xp and v143 `/std:c11 /W4 /WX` in CI):

- Allowed: `//` comments, mixed declarations, designated initializers, compound literals, `<stdint.h>`,
  `<stdbool.h>`, `inline` (via `SD_INLINE`), `__declspec`, `__try/__except`.
- Forbidden: VLAs, `_Generic`, `<stdatomic.h>`, `<threads.h>`, `_Thread_local`, `_Alignas` directly.
  Use `SD_STATIC_ASSERT(expr, msg)`, `SD_ALIGN(n)`, `SD_NORETURN`, `SD_UNUSED` from `include/sd/base.h`.
  Atomics: `Interlocked*` only.
- `UNICODE`/`_UNICODE` always defined; only `W` APIs.
- `_WIN32_WINNT`/`NTDDI_VERSION`: `0x0501` (both x86 flavours), `0x0502` (`x64-xp`), `0x0602` (ARM32),
  `0x0A00` (`x64-modern`, ARM64).
  Code must not branch on these macros for behavior; it branches on run-time capability detection.

### 2.4 XP-compatibility guard rails (mandatory for every module)

- **No static imports of post-XP functions.** Anything newer (CNG `bcrypt.dll`, `IsWow64Process2`,
  `RmStartSession`, `GetTickCount64`, SRW locks, condition variables, `InitOnceExecuteOnce`,
  `CreateSymbolicLinkW`, `WinHttpSetOption` flags beyond WinHTTP 5.1…) is resolved with
  `sd_platform_resolve()` (a `GetProcAddress` wrapper with a cached table).
- **Import audit tool** `tools/sd-importcheck` (C, part of the build) parses each PE import table and fails
  the build if any imported `dll!function` is not in the flavour's floor list:
  `tests/os-imports/xp-sp3-x86.txt` (both x86 flavours), `xp-sp2-x64.txt` (`x64-xp`), `win10-1507-x64.txt`
  (`x64-modern`), `win10-arm32.txt` (ARM32, from the SysArm32 folder of Windows 10 on ARM), `win10-arm64.txt`
  (ARM64, Windows 10 1709+; bootstrap list until the lab capture, M6) — export lists captured from clean lab VMs,
  names only, no Microsoft binaries in the repo.
  Same tool checks the PE `MajorSubsystemVersion`, the absence of a TLS directory in DLLs, and the
  `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` / `GUARD_CF` bits expected for the flavour.
- **Setup stub and `uninstall.exe` import only KnownDLLs (TM-R33, T-62).** `sd-importcheck --stub` fails if
  any static import of the stub or `uninstall.exe` (every architecture) is not in
  `tests/os-imports/knowndlls.txt` — the intersection of the `KnownDLLs` registry lists captured from the XP SP3,
  XP x64, 7, 10 and 11 lab VMs (kernel32, user32, gdi32, advapi32, shell32, ole32 and similar) — or if the image
  has a delay-load directory. Every other module (`cabinet.dll`, `msi.dll`, `wintrust.dll`, `crypt32.dll`,
  `comctl32.dll`, `winhttp.dll`…) is loaded at run time by full System32 path after the search path is
  restricted (§6.4). This list is part of TST-30.
- **ISA audit (`x86-ia32`)** `tools/sd-isacheck` disassembles the code sections of every `x86-ia32` PE (and of
  the setup stub) with `dumpbin /disasm` and fails on any SSE/SSE2 instruction outside an allowlist of static
  CRT routines that dispatch on `__isa_available` at run time. The lab VM without SSE2 (§11.4) is the
  authoritative runtime check.
- **No implicit TLS (`__declspec(thread)`) in any DLL.** On XP, static TLS does not work in DLLs loaded with
  `LoadLibrary` — the shell extension is always loaded that way. Use `TlsAlloc`. (Checked by sd-importcheck.)
- **No cross-module CRT objects:** with `/MT` each DLL has its own CRT heap. All modules allocate through
  `sd_alloc`/`sd_free` in `sd_platform` (`HeapAlloc(GetProcessHeap())`), and memory is never freed across a
  public API boundary (every API that returns memory has its own free function; 00 §4).

### 2.5 Build system: CMake + Visual Studio generator

Decision: **CMake** (build-time tool, like WiX; nothing of it ships).

- The Ninja generator ignores the toolset selection, so XP builds must use the
  **"Visual Studio 17 2022" generator with `-T v141_xp`**
  ([Cahute issue](https://gitlab.com/cahute/cahute/-/work_items/68)). Ninja is allowed for local v143
  developer loops only.
- Plain `.vcxproj` files were rejected: six flavours × several configurations × ~20 targets is a lot of
  hand-maintained XML; CMake also gives us CTest and presets.
- NMake/batch was rejected: we would re-implement dependency tracking and the XP toolset environment setup
  (SDK 7.1A paths, `_USING_V110_SDK71_`) by hand.

`CMakePresets.json` (configure presets):

| Preset | Generator / toolset | Arch | SDK | Ships |
|---|---|---|---|---|
| `x86-ia32` | VS 17 2022, `-T v141_xp` | `-A Win32`, `SD_X86_ARCH=IA32` | 7.1A | yes (+ setup stub, `uninstall.exe`) |
| `x86-sse2` | VS 17 2022, `-T v141_xp` | `-A Win32`, `SD_X86_ARCH=SSE2` | 7.1A | yes |
| `x64-xp` | VS 17 2022, `-T v141_xp` | `-A x64` | 7.1A | yes |
| `x64-modern` | VS 17 2022, `-T v143` | `-A x64` | `CMAKE_SYSTEM_VERSION=10.0.26100.0` | yes |
| `arm32` | VS 17 2022, `-T v143` | `-A ARM` | `CMAKE_SYSTEM_VERSION=10.0.22621.0` | yes, best effort (+ native ARM32 stub) |
| `arm64` | VS 17 2022, `-T v143` | `-A ARM64` | `CMAKE_SYSTEM_VERSION=10.0.26100.0` | yes (+ native ARM64 stub) |
| `x64-analysis` | VS 17 2022 or Ninja, `-T v143` | x64 | 10.0.26100 (ASan, fuzz, `/analyze`, `/std:c11`) | no |

The `arm32` preset builds only the targets D5 allows (`shelldrive.exe`, `shelldrive-host.exe`, the setup stub
and `uninstall.exe`); `shelldrive-ui.exe` and `shelldrive-shellext.dll` are not built there.

**ARM64 build tools (M6).** An ARM64 tree cannot run its own build-time tools on an x64 host, and Windows 11 on x64
does not run ARM64 binaries. `cmake/SdHostTools.cmake` therefore builds `sdl10n`, `sd-importcheck`, `sd-admxgen` and
`sd-payload` in a nested **x64** configure of the same source tree (`SD_HOST_TOOLS_ONLY=ON`, an ExternalProject target
`sd_host_tools`); the ARM64 targets see them as imported executables. `sd-isacheck` (x86 audit) and `sd-updsign` are
not part of the ARM64 tree (`sd-isacheck` is skipped, `sd-updsign` is built as an ARM64 target and not run at build
time). The native flavours build their tools exactly as before.

Configurations: `Debug`, `Release` (shipping = `Release` with PDBs). A repository-root **`.vsconfig`**
pins the required VS components so developer machines and self-hosted runners are identical:
`Microsoft.VisualStudio.Component.VC.Tools.x86.x64`, `Microsoft.VisualStudio.Component.VC.v141.x86.x64`,
`Microsoft.VisualStudio.Component.WinXP`, `Microsoft.VisualStudio.Component.VC.Tools.ARM`,
`Microsoft.VisualStudio.Component.VC.Tools.ARM64`, `Microsoft.VisualStudio.Component.Windows11SDK.22621`,
`Microsoft.VisualStudio.Component.Windows11SDK.26100`, `Microsoft.VisualStudio.Component.VC.ASAN`.

---

## 3. CRT strategy and compiler/linker flags

### 3.1 `/MT` static vs no-CRT

| | Static `/MT` (v141_xp / v143 CRT) | No-CRT (`/NODEFAULTLIB`, own entry point) |
|---|---|---|
| Size | ≈ +60–120 KB per EXE/DLL for our usage pattern **[lab-verify]** | Smallest (tens of KB) |
| Work | None | Must provide: `memcpy/memset/memmove/memcmp` (the compiler emits calls even with intrinsics), `_chkstk`/`__chkstk`, `/GS` runtime (`__security_init_cookie`, `__security_check_cookie`, `__GSHandlerCheck`), SEH handlers (`_except_handler4`, `__C_specific_handler`), x86 64-bit arithmetic helpers (`_allmul`, `_alldiv`, `_aullrem`, `_allshl`… — the crypto code is full of 64-bit math), ARM32 division helpers (`__rt_sdiv`, `__rt_udiv64`…), `_fltused`, load-config/SafeSEH table, CFG stubs |
| Security | `/GS`, SafeSEH, CFG plumbing all work out of the box | Each of the above re-implemented = new attack surface and subtle bugs |
| Risk | CRT startup code in DLLs (fine for C with no static constructors) | High, per-arch assembly-level work for four architectures and six flavours |

**Decision: `/MT` everywhere.** We keep CRT *usage* minimal so that a later no-CRT build remains possible
(for the shell extension, if Explorer load time or size ever matters):

- Allowed CRT: `mem*`, bounded `wcs*`/`str*` (`*_s` variants), `qsort`, `_wcsicmp`, `swprintf_s` for
  diagnostics. Not allowed in shipping code: `stdio` file I/O, `locale`, `time()`/`localtime`, `malloc` outside
  `sd_platform`, `atexit`, `errno`-based logic, `rand`.
- Memory: `sd_alloc/sd_free` (wraps `HeapAlloc`) so every module shares one allocation policy.

### 3.2 Flags

Compiler (all): `/W4 /WX /utf-8 /Zi /O2 /Gy /Gw /GS /GF /MT /we4013 /we4047 /we4024` (implicit
declarations and pointer mismatches are errors) and `/Brepro` (§12). v143 flavours add `/sdl` and
`/guard:cf`. This section is normative for all modules' flags (C36); 01 §12.1 refers to it.

Memory model (M6, all flavours): `/volatile:ms` makes every `volatile` access an acquire load or release store. It is
the default on x86 and x64, so those builds do not change; on ARM64 the default is `/volatile:iso`, which does not
order volatile accesses. The atomics review that goes with it is in `docs/dev/m6-notes.md`.

ARM64 (`arm64`, M6): `/guard:cf` and `/sdl`; no `/CETCOMPAT` (x64 only, `SD_CET` in `cmake/SdOptions.cmake`); the
import audit requires CFG, not CET; no ISA audit (x86 only). The linker floor is Windows 10 1709.

x86 CPU floor (D4): **two x86 flavours**.

- `x86-sse2` uses **`/arch:SSE2`** (the v141 default; Pentium 4 / Athlon 64 class, 2001+). Crypto SIMD and
  SHA-NI/AES-NI paths are compiled only here and selected at run time by CPUID.
- `x86-ia32` uses **`/arch:IA32`** (x87 floating point, no SSE/SSE2 code generation) for Pentium Pro/II/III and
  Athlon XP class CPUs. Crypto uses the portable scalar paths only (01 §2.3). The SIMD source files are excluded
  from this preset by CMake, not by `#ifdef`, so nothing SSE2 can be linked in by accident.
- The setup stub and `uninstall.exe` are built **only** from the `x86-ia32` preset, so the stub can never
  execute an SSE2 instruction before its CPU check (this resolves C35: the stub links the IA32 builds of the
  minimal `sd_stubcore` subset — `sd_platform` minimal, SHA-256/512, Ed25519 verify, FDI glue —
  instead of a separate re-compilation of SSE2 libraries).
- Defence in depth for `x86-sse2` binaries started on a non-SSE2 CPU (copied by hand, or installed from the SSE2
  MSI by an administrator): each `x86-sse2` EXE links a tiny entry thunk `sd_cpucheck.c`, compiled `/arch:IA32`
  in its own translation unit and set as `/ENTRY`, which calls
  `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)` (XP+) and, if FALSE, shows a fixed message
  naming the `x86-ia32` download and exits before the CRT starts. The shell DLL checks the same in `DllMain`
  (`DLL_PROCESS_ATTACH` returns FALSE). **[lab-verify]** on the non-SSE2 VM that the v141 static CRT start-up
  itself does not execute SSE2 before the thunk returns.

Linker (all): `/DEBUG:FULL /PDBALTPATH:%_PDB% /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /RELEASE /Brepro
/MANIFEST:EMBED /MANIFESTUAC:NO` (UAC level comes from our manifest file).

| Target | Extra linker flags | Subsystem version |
|---|---|---|
| `x86-ia32`, `x86-sse2` (v141_xp) | `/SAFESEH /LARGEADDRESSAWARE` | `/SUBSYSTEM:WINDOWS,5.01` (or `CONSOLE,5.01` for `shelldrive.exe`) |
| `x64-xp` (v141_xp) | `/HIGHENTROPYVA` | `,5.02` (XP x64 / Server 2003 kernel) |
| `x64-modern` (v143) | `/guard:cf /CETCOMPAT /HIGHENTROPYVA` | `,6.02` (linker default; actual floor Windows 10, enforced by setup, the MSI launch condition and `--selftest`) |
| `arm32` (v143) | `/guard:cf` | `,6.02` |
| `arm64` (v143) | `/guard:cf` | `,6.02` (linker default; actual floor Windows 10) |

- Setup stub and `uninstall.exe` (TM-R33): v143 builds (native ARM32/ARM64 stubs) link with
  `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32` for the dependencies the loader resolves; honored
  by Windows 10 1607+ loaders). The `x86-ia32` stub uses it too if the v141 14.16 linker accepts the switch
  **[verify]**; otherwise the run-time measures of §6.4 are the only protection, which is why the stub's
  elevated work never runs from the download directory.
- DEP/ASLR flags are ignored by XP's loader and honored on Vista+ — harmless.
- `/guard:cf` on v141_xp: CFG metadata is ignored by pre-8.1 loaders in principle, but the XP x86 loader is
  picky about the load-config directory layout used by SafeSEH. **Not enabled on the v141_xp flavours**;
  Windows 10+ x64 users get CFG through `x64-modern` instead. **[lab-verify]** a CFG-enabled v141_xp build on XP
  SP3/XP x64 later; enabling it there would be a post-1.0 change.
- `/CETCOMPAT` is not available in v141, so only `x64-modern` is CET shadow-stack compatible. Rules for CET
  compatibility (all code, since sources are shared): no hand-written return-address manipulation, no
  `longjmp` across our own frames outside the CRT, no stack switching. **[lab-verify]** with hardware-enforced
  stack protection in strict mode on a Windows 11 VM with a CET-capable CPU (§11.4).

### 3.3 Application manifests

One template `res/manifest/app.manifest.in`, instantiated per binary:

- `trustInfo` in the **`urn:schemas-microsoft-com:asm.v2`** namespace (XP SP2's loader rejects the v3
  form) with `requestedExecutionLevel level="asInvoker"` for every binary, **including setup** (setup elevates
  explicitly; an explicit level also disables Vista's "setup.exe" installer-detection heuristic).
- `supportedOS` GUIDs Vista → 10/11 (so `GetVersionEx` is not lied to and RM/heap behavior is current).
- Common Controls v6 dependency (UI, setup), `dpiAware true` + `dpiAwareness PerMonitorV2` (UI, setup),
  `longPathAware true`.
- **[lab-verify]** every manifest on XP SP3 x86 and XP x64 SP2 (smoke test step 1 is "does it start").

---

## 4. Repository layout

```
/CMakeLists.txt  CMakePresets.json  .vsconfig  VERSION  LICENSE  THIRD-PARTY-NOTICES.md
/cmake/                  SdOptions.cmake (flags §3), SdVersion.cmake, SdSign.cmake, SdPayload.cmake
/include/sd/             cross-cutting headers only: base.h, winapi_compat.h, version.h(.in)
/src/<module>/           one static library per module
    include/<module>/    public headers of the module (e.g. src/sd_ssh/include/sd_ssh/session.h)
    *.c, *.h             private sources
    AGENTS.md            component notes
  sd_base/  sd_platform/  sd_crypto/  sd_ssh/  sd_sftp/  sd_vfs/  sd_webdav/  sd_dokan/  sd_l10n/
  sd_config/  sd_ipc/  sd_import/  sd_secret/  sd_update/  sd_mount/  sd_stubcore/
                         (dependency graph: 00 §5; sd_base has no windows.h, sd_platform is the Win32 layer, C39)
/apps/
  shelldrive/            CLI                      -> shelldrive.exe (console subsystem)
  shelldrive-host/       agent + service (D3)     -> shelldrive-host.exe (`agent` | `service`)
  shelldrive-ui/         tray + window            -> shelldrive-ui.exe
  shelldrive-shellext/   Explorer DLL             -> shelldrive-shellext.dll
  shelldrive-setup/      installer stub           -> ShellDrive-<ver>-setup*.exe, uninstall.exe
/l10n/<domain>/<lang>.po PO sources, the only source of user-visible text (03 §9; domains incl. `installer`, `shell`)
/res/                    manifests, icons, version.rc.in (no hand-written string tables)
/installer/
  wix/                   Product.wxs, Files.wxs (generated), Registry.wxs (generated); *.wxl generated by sdl10n
  registry/              declarative registration tables (context-menu handler, Approved, `.sdmount` ProgID,
                         App Paths, Run keys, Event Log source) — single source for MSI and per-user setup (§6.6)
  dokany/dokany.lock     pinned Dokany version, file names, sizes, SHA-256, source URLs, VC++ dependency result,
                         expected upstream Authenticode signer name (TM-R23)
  keys/                  update trust anchors (§9.3): root-a.pub, root-b.pub, the current signed keyset.txt
                         compiled into every binary and stub (public keys only; private keys never in the repo)
  msix/                  sparse package manifest template (D27, §10.1)
  payload/               CAB directive files (.ddf) per flavour
/tools/                  build-time tools, written in C against our own modules:
  sd-importcheck/        PE import/TLS/subsystem/CFG/CET audit (§2.4)
  sd-isacheck/           no-SSE2 audit of x86-ia32 code (§2.4)
  sd-ctcheck/            constant-time disassembly check (01 §2.7.5, TM-R02, TST-03)
  sd-release/            manifest build/sign/verify, SHA256SUMS (links sd_crypto)
  sd-regtable/           generates Registry.wxs + C tables from installer/registry/
  sdl10n/                PO validation + generation of C tables, STRINGTABLEs, .wxl, ADML, LCID lists (§8.6)
  sd-msilang/            embeds language transforms into MSIs via msi.dll (§8.6)
/tests/
  harness/               our minimal C unit-test runner (no third-party framework)
  unit/<module>/         unit tests, one exe per module (sd-test-<module>.exe)
  vectors/               known-answer test data (RFC vectors, Wycheproof JSON — data only)
  fuzz/<target>/         libFuzzer targets + seed corpus
  integration/           CTest-driven tests + fixtures/ (sshd_config variants, WSL setup scripts)
  smoke/                 smoke.cmd (runs on XP..11, cmd.exe only) + expected outputs
  lab/                   Hyper-V/QEMU orchestration (PowerShell on the host), VM inventory
  os-imports/            export-name lists for the import audit, one per flavour floor, plus knowndlls.txt (§2.4)
/third_party/            test-only material, see policy below (nothing in it is compiled into shipped binaries)
/docs/  design/  ...
/.github/workflows/      ci.yml, release.yml, fuzz.yml, ct.yml, lab.yml, resign.yml
/.github/CODEOWNERS      maintainer review required for .github/, installer/, cmake/SdSign.cmake, tools/sd-release/ (TM-R39)
```

**Third-party policy**

- **Shipped code: zero third-party source, crypto included (D1).** No fiat-crypto, no Monocypher, no BearSSL,
  no vendored fragments; field arithmetic, bignum, ML-KEM and SHA-3 are our own code. Papers, RFCs and specs
  may be read; no code is copied. The only third-party binary we ship is Dokany, unmodified.
- Dokany declarations: no upstream header is copied. `src/sd_dokan/dokan_abi.h` holds our own minimal
  declarations of the `DOKAN_*` ABI, frozen at 2.3.1, with a notice (C38). `dokan2.dll` is loaded dynamically
  from System32.
- Test-only third-party (allowed, D21): test vectors such as Wycheproof JSON and RFC vectors (data, in
  `tests/vectors/`), OpenSSH/dropbear servers as fixtures (never linked, never shipped), litmus WebDAV suite
  run inside WSL, Linux used only as test infrastructure.
- Build-time tools (allowed): CMake, WiX, `makecab`, `makeappx`, `signtool`, `dumpbin` — nothing of them is in
  the output.
- Every third-party directory (test-only) carries a `README.md` (origin, version, license, for humans) and a
  `PROVENANCE.md` (exact source URL, SHA-256, import date, for audit) (C40). A CI check fails if any file under
  `third_party/` or `tests/vectors/` is referenced by a shipping target.
- `THIRD-PARTY-NOTICES.md` lists Dokany only.

---

## 5. Release artifacts

Per release `X.Y.Z` (examples for 1.0.0):

| Artifact | Contents | Audience |
|---|---|---|
| `ShellDrive-1.0.0-setup.exe` | **Universal** `x86-ia32` stub + `x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, `arm64` payloads; Dokany downloaded on demand | Default download |
| `ShellDrive-1.0.0-setup-x86.exe` | `x86-ia32` stub + both x86 payloads + Dokany x86 (MSI or bundle, §7.3) | Offline install |
| `ShellDrive-1.0.0-setup-x64.exe` | `x86-ia32` stub + `x64-xp` and `x64-modern` payloads (+ `x86-sse2` shell DLL) + Dokany x64 | Offline install |
| `ShellDrive-1.0.0-setup-arm64.exe` | ARM64 payload (+ `x86-sse2` and `x64-modern` shell DLLs) + Dokany ARM64 (stub is native ARM64) | Offline install |
| `ShellDrive-1.0.0-setup-arm32.exe` | ARM32 payload (CLI + host only), no Dokany (none upstream), native ARM32 stub | Best effort |
| `ShellDrive-1.0.0-<flavour>.msi` for all six flavours (`x86-ia32`, `x86-sse2`, `x64-xp`, `x64-modern`, `arm32`, `arm64`) | Per-machine MSI, no Dokany inside | GPO/Intune |
| `ShellDrive-1.0.0-portable-<flavour>.zip` (six) | Binaries + `shelldrive.portable` marker | Portable |
| `ShellDrive-1.0.0-sparse-<x64|arm64>.msix` | Signed sparse package for the Windows 11 modern context menu; embedded in the payloads, also published for admins. **Only when a certificate exists** (D27, §10.1) | Windows 11 |
| `ShellDrive-1.0.0-symbols.zip` | PDBs of all flavours | Crash analysis |
| `manifest.txt` | Signed release manifest (§9) | Updater |
| `keyset.txt` | Root-signed list of release keys per channel, with validity and revocations (§9.3, TM-R37) | Updater, setup stub |
| `SHA256SUMS`, `SHA256SUMS.sig` | Hashes + ed25519 signature | Humans, scripts |
| `dokany-2.3.1.1000-source.zip` | Mirror of upstream source of the pinned tag (LGPL compliance, §7.3) | Compliance |

The universal stub cannot serve ARM32-only Windows (no x86 emulation there), hence the separate ARM32 EXE and
MSI. Administrators who pick an MSI by hand use `x86-sse2` and `x64-modern` unless their fleet has pre-SSE2 CPUs
or pre-Windows 10 x64 machines; the MSI launch conditions (§8.2) refuse the wrong one.

### 5.1 ARM32 (best effort, D5/D31)

- Contents: `shelldrive.exe` and `shelldrive-host.exe` (agent mode only), WebDAV backend only. No UI, no shell
  extension, no service, no Dokany (no upstream ARM32 build). The CI build stays; ARM32 is dropped from a
  release the moment the toolchain breaks (§15 R2).
- Implementation status (`wip/r7-arm32`, M6 notes "ARM32 flavour"): the `arm32` preset builds Release and Debug
  with no warnings; the UI, the shell extension and their tests are not built; the setup stub is native ARM32 and
  installs the `PAYLOAD_ARM32` CAB (CLI, host, uninstall.exe). CI and `tools/ci-local.ps1` build it without tests.
  Not implemented yet: the Windows 11 24H2 and RT/IoT refusals below, the ARM32 MSI (D31), and the ARM32
  constant-time gate and test run (open items in the M6 notes).
- Targets, with their limits:
  - **Windows 10 on ARM64 and Windows 11 up to 23H2 (ARM64 hardware)** run ARM32 desktop apps and include
    Windows Installer 5.0 and WebClient. This is the only realistic target and the one the lab tests.
    Windows 11 24H2+ removed ARM32 app support; setup and the MSI refuse to install there (MSI launch
    condition on the `SD_OSBUILD` AppSearch property, §8.2; setup checks the build number) **[lab-verify]** the
    exact build cut-off.
  - **Windows RT 8.1** ships Windows Installer 5.0 (`msiexec.exe` is present) **[lab-verify]**, but code
    integrity allows only Microsoft-signed desktop code, so our binaries do not start even after a
    successful install. The MSI and EXE detect RT (`ProductType`/SKU check, **[lab-verify]** the detection
    value) and refuse with an explanation. RT is listed as "not runnable" in the release notes.
  - **Windows 10 IoT Core** has no Windows Installer, no desktop shell and no WebClient: not targeted. IoT
    Enterprise is not offered as ARM32.
- MSI: `Platform="arm"` (Template `Arm;1033`) **[lab-verify]** WiX 3.14 emits it correctly and Windows Installer
  on ARM64 Windows accepts an ARM32 package; `InstallerVersion=500`; installs into the folder Windows Installer
  resolves for 32-bit ARM packages on ARM64 (`Program Files (Arm)` expected, **[lab-verify]**). Features: `Core`
  and `Autostart` only.

---

## 6. Self-installing EXE (`shelldrive-setup`)

### 6.1 Structure

- `shelldrive-setup.exe` is a small Win32 GUI program (C, `/MT`, linked with `sd_stubcore` and
  `sd_l10n[installer]`) built from the `x86-ia32` preset (`/arch:IA32`, subsystem 5.01; C35, D4) and natively
  from the `arm32` and `arm64` presets.
- Payload is appended as **`RT_RCDATA` resources** (one per flavour: `PAYLOAD_X86_IA32`, `PAYLOAD_X86_SSE2`,
  `PAYLOAD_X64_XP`, `PAYLOAD_X64_MODERN`, `PAYLOAD_ARM64`, `PAYLOAD_ARM32`; optional `DOKANY_<ARCH>` and
  `SPARSE_<ARCH>`), inserted after linking by `UpdateResourceW` in a build tool — so the stub is built and
  tested once and payloads are attached later. Files identical across two flavours (icons, licences, the
  `x86-sse2` shell DLL cross-included in x64/ARM64 payloads) are stored once per CAB.
- Each payload is a **CAB** (LZX:21) built with `makecab.exe` from a `.ddf` and extracted at run time with
  the **FDI API in `cabinet.dll`** (`FDICreate`/`FDICopy`), present on every Windows since 95. Benefits:
  native on XP, good ratio, no decompressor of our own. The CAB contains the per-user file set **and** the
  per-arch MSI for per-machine installs.
- A signed **payload table** resource lists every embedded blob with its SHA-256; the stub verifies hashes
  before extracting (catches truncated downloads before any file is written). The table carries an ed25519
  signature (`PAYLOAD_SIG` resource) by a release key that the keyset compiled into the stub authorizes for the
  build's channel (§9.3); the stub **refuses to run** on a missing or invalid signature (TM-R38, T-71). Once
  we sign, Authenticode covers the whole EXE as well, and the elevated instance additionally checks
  `WinVerifyTrust` with the expected publisher name before executing its staged copy (§6.4).

### 6.2 Native architecture detection (universal stub)

Order, first that succeeds wins (all functions resolved dynamically):

1. `IsWow64Process2(GetCurrentProcess(), &proc, &native)` — Windows 10 **1709+**
   ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)).
   Returns the native machine directly (`IMAGE_FILE_MACHINE_ARM64`, `AMD64`, `I386`).
2. `IsWow64Process` (XP SP2+): if FALSE, the OS is 32-bit x86 → x86. If TRUE, call
3. `GetNativeSystemInfo` → `PROCESSOR_ARCHITECTURE_AMD64` → x64; `PROCESSOR_ARCHITECTURE_ARM64` → ARM64
   (pre-1709 ARM64 builds report this through `GetNativeSystemInfo` — **[lab-verify]** on a Windows 10 1703
   ARM64 image if obtainable; otherwise 1709 is effectively the floor for Windows on ARM, which shipped with
   1709 anyway).

Flavour selection (after the native architecture is known):

| Native arch | Test | Flavour |
|---|---|---|
| x86 | `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)` (XP+) is TRUE | `x86-sse2` |
| x86 | it is FALSE | `x86-ia32` |
| x64 | OS version ≥ 10.0, read with `RtlGetVersion` (resolved from `ntdll.dll`, not lied to by the manifest/compat layer) | `x64-modern` |
| x64 | OS version < 10.0 | `x64-xp` |
| ARM64 | — | `arm64` (even on Windows 11 where x64 emulation exists — native is faster and Dokany/shell extension must match Explorer's architecture) |
| ARM32 | universal stub cannot run there | `arm32` via the separate ARM32 EXE/MSI (§5.1) |

A `/flavour=<x86-ia32|x86-sse2|x64-xp|x64-modern|arm64>` switch overrides (support/diagnostics only). It
refuses `x86-sse2` on a CPU without SSE2, `x64-modern` below Windows 10, and combinations where the shell
extension would not load. `x86-ia32` is accepted on any x86 OS (useful for testing). The decision and the
detection path are written to the setup log.

When the OS is upgraded in place (for example 8.1 → 10 on x64), the next update (§9) switches the install from
`x64-xp` to `x64-modern`; the reverse never happens automatically.

The shell extension must match Explorer's bitness: on x64 Windows we install **both** the x64 shell DLL of the
selected flavour and the `x86-sse2` shell DLL (the x86 copy serves 32-bit apps' file dialogs; every x64 CPU has
SSE2); on ARM64 we install ARM64 + `x86-sse2` (and `x64-modern` on Windows 11, for x64-emulated apps' dialogs)
**[lab-verify]** necessity. The payloads therefore cross-include those DLLs.

### 6.3 Install modes

| | Per-user (default for non-admins) | Per-machine (default for admins) | Portable |
|---|---|---|---|
| Location | `%LOCALAPPDATA%\Programs\LibreStatic\ShellDrive` (XP: `CSIDL_LOCAL_APPDATA` = `…\Local Settings\Application Data\Programs\LibreStatic\ShellDrive`) | `%ProgramFiles%\LibreStatic\ShellDrive` (native-arch Program Files) | Any folder (USB stick) |
| Engine | Setup copies files itself | **Our MSI** via `msiexec`/`MsiInstallProduct` with our external UI | Setup extracts (or user unzips) |
| Admin | No | Yes | No |
| Registration | HKCU: Uninstall key, Run keys, COM (HKCU\Software\Classes), context-menu handlers, `.sdmount`, App Paths | HKLM via MSI | **None** |
| Service | **Never** (D6) | **Yes, installed and enabled by default** (D6; `ServiceInstall` table; `SERVICE=0` turns it off) | No |
| Dokany install | No (can use an already-installed Dokany) | Yes: explicit option, pre-checked, 7 SP1+ only (D36); unchecked = WebDAV only | No (uses it if already installed) |
| Shell extension | Yes (HKCU COM) **[lab-verify]** XP honors HKCU classes for shell extensions | Yes | No |
| Sparse MSIX (Win11, D27) | Registered for the user by setup, if shipped | Registered per user by the agent at first start, if shipped (§10.1) | No |
| Network Shortcuts (D14) | Created at run time by the host/UI; removed by uninstall (§6.7) | Same, per user | Not created |
| Updates | Agent, no elevation | Agent + elevation prompt; disabled by default when installed by MSI deployment (§8.5) | Manual, or "download and replace" with consent |

Mode selection UI (first page): "Install for me" / "Install for all users (requires administrator)" /
"Portable (extract to a folder)". The per-machine options page shows "Install the ShellDrive service (global
drives, before sign-in)" **checked by default** (D6), "Start ShellDrive when users sign in" (checked) and
"Allow elevated programs to see mapped drives (`EnableLinkedConnections`)" (unchecked, explained; D24, §8.4).

**Dokany option (D36, TM-Q06, T-42).** On Windows 7 SP1 / Server 2008 R2 SP1 and later the per-machine
options page also shows "Install the Dokany file system driver (recommended)", **checked by default**, with a
short explanation: Dokany is a signed third-party kernel-mode driver from the Dokany project, it is installed
for the whole computer and stays available to every local user, it is not removed automatically with
ShellDrive (§6.7), and unchecking it leaves ShellDrive on the WebDAV backend only (no Dokany global drives;
the service falls back to D11 global WebDAV or per-user attach). Variants of the same row:

- Dokany already present at an acceptable version (§7.3 table): the checkbox is replaced by "Dokany
  <version> is already installed and will be used"; an upgrade offer follows the decision table.
- Driver install not possible (below 7 SP1, ARM32, SHA-2 support missing, memory integrity incompatibility,
  version on the `dokany-deny` list without an upgrade path; §7.2, §7.3): the row is shown disabled and unchecked
  with the localized reason.
- The checkbox maps to `/dokany=auto` (checked) or `/dokany=skip` (unchecked) and to the MSI property
  `DOKANY=1|0` (§8.4), so GUI, command line and MSI deployments express the same choice. Silent installs use
  `/dokany=auto` (= checked) unless the admin passes `/dokany=skip` or `DOKANY=0`.

Per-user setup never installs Dokany and shows no such option. Per-user and per-machine installs of the same version are mutually exclusive on one account: setup detects the
other mode (HKCU/HKLM Uninstall keys) and offers to remove it.

### 6.4 Elevation

- Setup always starts `asInvoker`. For per-machine it relaunches itself with
  `ShellExecuteExW(lpVerb=L"runas", "/elevated-stage1 <pipe-name> …")` (two elevated stages, below).
- Vista+: UAC prompt. **XP: no UAC**; `runas` shows the "Run As" credential dialog when the user is limited;
  if the user is an administrator (the common XP case) `IsUserAnAdmin()` is already TRUE and no `runas`
  relaunch happens, but the process still goes through stage 1 (it re-executes itself from the protected
  copy before creating any window), as does any instance that finds itself with an administrator token
  (UAC disabled, admin running a per-user install).
- The unelevated parent keeps the UI; the elevated child reports progress over a named pipe whose DACL
  allows only the launching user's SID. No arguments from the pipe are trusted for paths — the child
  re-derives everything from its own image and re-verifies payload hashes.

**DLL search hardening (TM-R33, T-62).** The loader resolves static imports, and DLLs that system DLLs load on
our behalf (`cryptbase.dll`, `version.dll`, `uxtheme.dll`, `dwmapi.dll`…), from the application directory
first unless they are KnownDLLs; the application directory of a downloaded setup is usually `Downloads`. Rules
for the setup stub, every elevated stage and `uninstall.exe`:

1. Static imports are KnownDLLs only, no delay-load (§2.4, enforced by `sd-importcheck --stub`); v143 stubs set
   `/DEPENDENTLOADFLAG:0x800` (§3.2).
2. The first statement of the entry point calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
   (resolved with `GetProcAddress` from kernel32; present on Windows 8+ and on Vista/7 with KB2533623). If it is
   missing (XP, Vista and 7 without that update) the stub calls `SetDllDirectoryW(L"")` (XP SP1+; removes the
   current directory from the search order) and relies on rule 3 and on stage 1 creating no window.
3. Every non-KnownDLL module is loaded by full path built from `GetSystemDirectoryW` with
   `LOAD_LIBRARY_SEARCH_SYSTEM32` where supported, else `LOAD_WITH_ALTERED_SEARCH_PATH` (so the module's own
   dependencies are searched in System32 first). `comctl32.dll` v6 comes from WinSxS through the manifest's
   activation context.
4. On XP/Vista/7 without KB2533623, the app directory still comes first for DLLs loaded implicitly by system
   code (for example `uxtheme.dll` when the first window is created). This is why the **unelevated** parent
   is the only instance that ever creates UI from the download directory: a planted DLL there runs with the
   user's own rights, which the planter already had (residual noted in §15 R16).

**Two-stage elevation: never run elevated work from a user-writable directory (TM-R33, TM-R34, T-62, T-63).**

1. **Stage 1** (`/elevated-stage1`, started by `runas` from wherever the user ran setup) creates no window and
   loads no module beyond its KnownDLL imports. It (a) applies the DLL rules above; (b) secures
   `%ProgramData%\LibreStatic\ShellDrive` (XP: `CSIDL_COMMON_APPDATA`) as described below; (c) creates a **new**
   directory `%ProgramData%\LibreStatic\ShellDrive\setup\<random 128-bit hex>` with `CreateDirectoryW` and an explicit
   security descriptor in the same call (owner Administrators, protected DACL: SYSTEM and Administrators full
   control, nothing else; the call fails if the name exists, and stage 1 then picks a new name); (d) copies its
   own image into it, reading the source opened with `FILE_SHARE_READ` only (no write or delete sharing, so it
   cannot be swapped during the copy); (e) starts the copy with `CreateProcessW` (inherits the elevated token,
   no second prompt) and `/elevated-child <pipe-name>`, waits for it and returns its exit code. Stage 1 never
   extracts payloads, never parses the pipe and never reads anything from the download directory except its own
   image.
2. **Stage 2** (`/elevated-child`, running from the admin-only directory) verifies its payload table signature
   (§6.1; and, once signed, `WinVerifyTrust` of its own image with the expected publisher), extracts into the
   same directory, re-verifies hashes *after* extraction with files opened `FILE_SHARE_READ` only, and only then
   does the install work (MSI, Dokany). Its application directory is admin-only, so DLL planting there needs
   admin rights.
3. A same-user attacker that is already running could still race the image between the UAC prompt and the copy
   (UAC is not a security boundary, T-60). Authenticode verification in stage 2 closes this once a certificate
   exists; until then the payload-table signature limits it to swapping in another genuine, signed-table build.
4. The update path (§9.6) and `setup /uninstall` for per-machine installs use the same two stages.

**Securing `%ProgramData%\LibreStatic\ShellDrive` before use (TM-R34, T-63).** Standard users can create subfolders of
`%ProgramData%`; whoever creates `LibreStatic` (or `LibreStatic\ShellDrive`) first owns it. The checks below apply to
the vendor folder `%ProgramData%\LibreStatic` first (D45; trusted means the same, its DACL is the 03 §3.2 `LibreStatic\`
entry, and an untrusted one is renamed aside to `%ProgramData%\LibreStatic.untrusted-<n>`), then to `ShellDrive` inside it. Before stage 1 (or the MSI hook
`programdata-secure`, §8.3, for direct `msiexec` installs) touches the folder:

- Each path component is opened with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`; a reparse
  point anywhere in `%ProgramData%\LibreStatic\ShellDrive\…` makes the tree untrusted. Owner and DACL are read **on the
  opened handle** (`GetSecurityInfo`).
- Trusted means: owner is Administrators or SYSTEM, the DACL grants write, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`
  or `FILE_DELETE_CHILD` to nobody else, and the same holds for every existing first-level child (`setup\`,
  `updates\`, `profiles\`, `service\`, `state\`, `logs\`, `settings.ini`).
- Untrusted: the folder is renamed aside to `%ProgramData%\LibreStatic\ShellDrive.untrusted-<n>` (never followed, never
  read, never imported; `setup.programdata_untrusted` is logged with the previous owner SID), and a fresh
  folder is created with `CreateDirectoryW` and the 03 §3.2 security descriptor in the same call. If the
  rename fails (for example an attacker holds a handle without delete sharing) or the create races with a
  re-creation, setup aborts with a localized error instead of continuing.
- Trusted: the 03 §3.2 DACL is re-applied (protected, no inheritance from `%ProgramData%`).
- Only then are `settings.ini`, `profiles\` (`DEFAULTPROFILES`), `state\`, `updates\` and `logs\` written.

### 6.5 Command line (setup EXE)

```
ShellDrive-<ver>-setup.exe [/quiet | /passive] [/peruser | /permachine | /portable=<dir>]
                           [/dokany=auto|install|skip] [/norestart] [/log=<file>]
                           (auto = the pre-checked D36 option; skip = WebDAV only; install = also upgrade, §7.3)
                           [/lang=<en|es|fr|pt-BR|it|de>]   (pt accepted as an alias of pt-BR, C42)
                           [/flavour=<x86-ia32|x86-sse2|x64-xp|x64-modern|arm64>] [/extract=<dir>]
                           [/uninstall] [/update]
                           [PROPERTY=value ...]          (passed to the MSI in per-machine mode)
```

Without `/lang`, setup resolves the language with 03 §9.3 (policy `UILanguage`, then the user UI language,
then English) and always passes the matching `TRANSFORMS` to the MSI explicitly (§8.6).

Exit codes follow MSI conventions: `0` success, `3010` success-reboot-required, `1602` user cancel,
`1603` fatal, `1638` another version installed (when `/update` not given and downgrade attempted).
`/extract` writes the MSIs of the payload's flavours, the Dokany redistributable and (if shipped) the sparse
MSIX for admins who deploy with GPO/Intune.

### 6.6 Registration data: one source of truth

Registration is limited to (C10): the context-menu handler (`Drive`, `Directory`, `*` and the This PC CLSID
`{20D04FE0-3AEA-1069-A2D8-08002B30309D}`, 03 §8.2), the `Shell Extensions\Approved` entry, the `.sdmount`
ProgID, App Paths, the Run keys (§8.3, C11) and the Event Log source (English message file, C44). No shell
namespace extension is registered. "Add network location" entries (D14) are Network Shortcuts folders that the
host creates per user at run time (03), not registry data; packaging only cleans them up (§6.7). These are
described once in `installer/registry/*.tbl` (simple line format: root, key, name, type, value with
`[INSTALLDIR]`/`[CLSID_x]` placeholders). `tools/sd-regtable` generates:

- `installer/wix/Registry.wxs` (HKLM, MSI `Registry` table, no `SelfReg`, no `DllRegisterServer`), and
- a C table compiled into setup for per-user mode (HKCU equivalents).

`DllRegisterServer` in the shell extension is implemented only for developer convenience and is never called
by installers.

### 6.7 Uninstall entry (Add/Remove Programs)

- Per-machine: provided by MSI (`Package Manufacturer="LibreStatic"`, which ARP shows as publisher, D45; `ARPPRODUCTICON`, `ARPURLINFOABOUT`, `ARPNOMODIFY=0` so "Change" offers
  feature selection).
- Per-user: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\ShellDrive` with `DisplayName`,
  `DisplayVersion`, `Publisher` = `LibreStatic` (D45), `DisplayIcon`, `InstallLocation`, `UninstallString` = `"<root>\uninstall.exe"
  /uninstall`, `QuietUninstallString`, `EstimatedSize`, `NoModify=1`, `NoRepair=1`. **[lab-verify]** that XP
  ARP lists HKCU entries.
- `uninstall.exe` is the stub without payload and follows the DLL rules of §6.4 (TM-R33).
  - **Per-user installs** (never elevated): it creates a new directory `%TEMP%\ShellDrive-uninstall-<random>`
    with `CreateDirectoryW` and an explicit DACL (user and SYSTEM only; fails if it exists), copies itself
    there, relaunches from there, removes the installation, and leaves the copy for the next `%TEMP%` cleanup
    (documented). It never elevates from `%TEMP%`; if it finds itself with an administrator token it does not
    proceed from `%TEMP%` but asks the user to run it unelevated.
  - **Per-machine installs:** uninstall goes through the MSI (ARP, `msiexec /x`) or `setup /uninstall`, which
    uses the two elevated stages of §6.4. `uninstall.exe`, if invoked on a per-machine install, runs only from
    `%ProgramFiles%\LibreStatic\ShellDrive` (admin-only) and hands over to `MsiConfigureProductExW`; it never copies itself
    to `%TEMP%`, and Windows Installer removes the file itself.
- User data (profiles, `known_hosts`, logs under `%APPDATA%\LibreStatic\ShellDrive`) is kept by default; "Also remove my
  settings" checkbox; Credential Manager entries removed only with that checkbox (enumerated by our target
  name prefix, owned by the credentials design).
- **Caches are always removed (TM-R28, T-54):** every uninstall deletes the uninstalling user's disk cache
  (`%LOCALAPPDATA%\LibreStatic\ShellDrive\cache\`, by `uninstall.exe` per user and by the impersonated `user-cleanup` hook
  per machine) and, per machine, the service's cache under `%ProgramData%\LibreStatic\ShellDrive\`. Other users' caches
  cannot be reached safely (the SYSTEM context never walks user-writable profile paths, TM-R35); the host
  deletes a cache whose profile no longer exists at its next start, and the limit is documented next to the
  Network Shortcuts one.
- **Uninstall summary (TM-R28):** the last page of the uninstall UI (and the uninstall log, for silent and
  `msiexec` uninstalls) lists what was kept: user settings, profiles and `known_hosts` when not removed,
  saved credentials of the current user when not removed, other users' data, caches and Network Shortcuts,
  machine profiles and settings (`REMOVEDATA=0`), service secrets and keys if `REMOVESECRETS=0`, and Dokany.
- Dokany is **never removed automatically** (shared component). If ShellDrive installed it
  (`HKLM\Software\LibreStatic\ShellDrive\DokanyInstalledBySetup=1`) the uninstaller offers removal, default unchecked.
- **Network Shortcuts (D14, design in 03 §8.7).** Each entry the agent creates is a read-only folder with
  `desktop.ini` and `target.lnk` under `CSIDL_NETHOOD` (`%APPDATA%\Microsoft\Windows\Network Shortcuts` on
  Vista+, `%USERPROFILE%\NetHood` on XP); its `desktop.ini` carries the marker `[ShellDrive] profile=<id>`,
  which is how our entries are recognized (no separate list file). Cleanup uses the hook `user-cleanup`
  (03 §6.1), which also removes the user's Run/tray keys and Explorer label/icon keys:
  - per-user uninstall: `uninstall.exe` runs `shelldrive-host.exe --installer-hook user-cleanup --apply`;
  - per-machine uninstall (setup, ARP or `msiexec /x`): an MSI deferred custom action of our own binary
    (§8.3 rules), **impersonated** (`msidbCustomActionTypeNoImpersonate` not set), runs
    `shelldrive-host.exe --installer-hook user-cleanup --apply` as the uninstalling user before `RemoveFiles`,
    which cleans that user's entries. Other users' entries cannot be reached reliably from an uninstall (their
    profiles may not be loaded); they become dead links that Explorer shows as unavailable. The host also
    removes entries for deleted profiles at every start. This limit is documented in the admin guide;
  - uninstalls run as SYSTEM (GPO, Intune) therefore clean no user entries.
- **Sparse MSIX package (D27, if shipped).** Per-user uninstall removes the user's registration; per-machine
  uninstall calls the hook `modern-menu --revert` (elevated), which uses `PackageManager.RemovePackageAsync` with
  `RemovalOptions.RemoveForAllUsers` (Windows 10 1809+, elevated) so no other user keeps a package pointing at
  the deleted install directory (§10.1).
- **Service secrets and keys are removed by default (TM-R28, T-54):** a per-machine uninstall deletes
  `%ProgramData%\LibreStatic\ShellDrive\service\secrets\` and `service\keys\` (SYSTEM-DPAPI-protected passwords and private
  keys of global mounts) unless the admin unchecks "Remove the service's saved passwords and keys" (checked by
  default) or passes `REMOVESECRETS=0`. Implementation: MSI `RemoveFile`/`RemoveFolder` entries in a component
  conditioned on `REMOVESECRETS=1 AND REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` (no custom action; upgrades keep
  them).
- **Machine profiles and settings** (`%ProgramData%\LibreStatic\ShellDrive\`, 03 §3.2) are removed only when the admin
  checks "Also remove settings" (MSI property `REMOVEDATA=1`, which implies `REMOVESECRETS=1`).

### 6.8 Portable mode

- Portable is detected by the presence of **`shelldrive.portable`** next to the executables (empty file or INI
  with options). All apps call `sd_platform_is_portable()` once at start.
- In portable mode: configuration/data live in `<exe dir>\data\` (including `settings.ini` and `state\`); no
  registry writes (no Run key, no COM, no ARP); no service; no shell extension; no sparse package; no Network
  Shortcuts; WebDAV backend works where WebClient exists; Dokany backend works only if Dokany is already
  installed. Credentials: Credential Manager is still used (it is per-user and machine-bound — a
  portable copy on another PC simply prompts again); this is a deliberate exception, see credentials design.
- `setup.exe /portable=<dir>` extracts the flavour chosen by §6.2; the per-flavour zip is equivalent.
- **Volumes without persistent ACLs (TM-R29, T-55, T-59):** if `<exe dir>\data\` is on a volume whose
  `GetVolumeInformationW` flags lack `FILE_PERSISTENT_ACLS` (FAT, exFAT, most USB sticks), the host refuses the
  disk cache (02 §4.2) and shows a one-time warning that host keys and profiles on this medium can be changed
  by anyone who has it (03 §1.9). `setup /portable=<dir>` shows the same warning before extracting to such a
  volume; extraction still proceeds.

### 6.9 Upgrade in place with running processes

Per-user mode (setup does the file work):

1. **Ask politely (C3):** every running agent owns a manual-reset event
   `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>` with DACL `user, SY, BA: EVENT_MODIFY_STATE |
   SYNCHRONIZE` (03 §2.1) and waits on it. Setup finds running `shelldrive-host.exe` processes with Toolhelp32
   (`CreateToolhelp32Snapshot`, XP+), opens each token (`OpenProcessToken`) to derive SID and session id, and
   signals the matching events — per-user setup only for its own SID, elevated setup for every SID. The agent
   unmounts cleanly, tells its UI clients to exit over IPC, and exits within 15 s. `Global\` names work on XP,
   so there is no `Local\` fallback. Pipes are never enumerated. Mounted drives are listed to the user first;
   setup refuses `/quiet` upgrade while writes are in flight unless `/force`.
2. **Vista+: Restart Manager** (`RmStartSession`, `RmRegisterResources` with our file list, `RmGetList`).
   Remaining holders other than Explorer are shown; with consent `RmShutdown(RmForceShutdown=0)`.
   Explorer is **never** restarted automatically.
3. **Rename-aside** any file still locked (typically `shelldrive-shellext.dll` loaded in Explorer): NTFS allows
   renaming a loaded image. Rename to `*.sd-old-<n>`, write the new file, and delete the old ones at the next
   agent start (no admin needed). XP and FAT volumes: same technique works on FAT for renames **[lab-verify]**.
4. **Versioned shell extension directory:** the DLL is installed as `shellext\<version>\shelldrive-shellext.dll`
   and the COM `InprocServer32` path is rewritten (C4: no reboot needed). Explorer keeps the old DLL until it
   restarts, new instances load the new one. The shell extension has no IPC; it reads the
   `Local\com.librestatic.shelldrive.state.<SID>` section and launches `shelldrive-ui.exe --action`. Therefore the section
   layout is versioned and architecture-independent (fixed-width fields, no pointers), and `--action` verbs
   are additive only (C5, §14). If the sparse package is shipped, a new package version pointing at the new
   versioned path is registered in the same step (§10.1).
5. Backup: replaced files are moved to `<root>\.rollback\<oldver>\` and deleted after the new agent reports
   healthy (§8.4).

Per-machine mode (MSI does the file work):

- Setup performs steps 1–2 above (stopping the `ShellDriveSvc` service — `shelldrive-host.exe service` —
  happens through MSI `ServiceControl`).
- Major upgrade (`RemoveExistingProducts` scheduled **after `InstallInitialize`** — old product removed first,
  so locked old files are scheduled for reboot deletion while new versioned shell-extension paths install
  without conflict).
- Vista+: MSI's own Restart Manager integration is left on (`MSIRESTARTMANAGERCONTROL` default) but Explorer is
  excluded by our pre-step; `REBOOT=ReallySuppress` in quiet mode, exit code 3010 propagated.
- **XP: no Restart Manager.** MSI shows its FilesInUse dialog (interactive) or uses
  `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` replacement (quiet) and returns 3010.

### 6.10 Implementation decisions (M4, setup engine)

Status of this build (`apps/shelldrive-setup`, tests in `tests/setup`, notes in `docs/dev/m4-notes.md`). Each
decision implements §6.1–§6.9 or narrows it, and says which.

- **Layout (6.1).** `sd_setup_core` is a static library (engine, all presets; the tests link it). The stub
  `shelldrive-setup-stub.exe` (GUI subsystem, no comctl32 import) is built in the `x86-ia32` preset only. Its
  payload CAB is `makecab` output of the same tree: `shelldrive.exe`, `shelldrive-host.exe`,
  `shelldrive-ui.exe`, `shelldrive-shellext.dll`, and the payload-less stub as `uninstall.exe`.
  `tools/sd-payload` attaches the CAB as `RT_RCDATA` `PAYLOAD_<FLAVOUR>`, plus `PAYLOAD_TABLE` (one line per
  flavour: name, SHA-256, size), to a copy of the stub: `bin/<config>/shelldrive-setup.exe`.
- **Signature not yet (6.1, TM-R38).** `PAYLOAD_SIG` is neither written nor checked: the repository has no release
  keyset. Until it lands, the table is an integrity check only. The stub refuses to run without a table. Open item.
- **Import rules (2.4, TM-R33).** The stub imports only `kernel32`, `user32`, `gdi32`, `advapi32`, `ole32` and
  `shell32` (`tests/os-imports/knowndlls.txt`). `cabinet.dll`, the Toolhelp and Win8+ entry points and `ntdll`
  are resolved at run time by full System32 path (`sd_setup_proc`). `sd-importcheck --knowndlls` runs as the CTest
  `importcheck.stub.knowndlls`. The XP floor list gained ten Win32 1.0 names that the clean-VM capture lacks; the
  XP lab capture (04 §11.4) must confirm them. The list is shared by every x86 binary.
- **Flavour (6.2).** Native architecture from `IsWow64Process2`, falling back to `IsWow64Process` and
  `GetNativeSystemInfo`; SSE2 from `IsProcessorFeaturePresent`; OS version from `RtlGetVersion`. A `/flavour=`
  override is refused when the host cannot run it (for example `x86-*` on x64 or ARM64). The inputs and the
  choice go to the setup log. ARM32 is refused with its own message.
- **Modes (6.3).** Per-user install, repair and upgrade are implemented. Repair is a same-version reinstall; there
  is no separate switch. An older version over a newer one is refused with exit 1638 unless `/update` is given.
  Portable (`/portable=<dir>`) extracts into an empty folder, adds `data\` and `shelldrive.portable`, deletes
  `uninstall.exe`, writes no registry value and warns on a volume without persistent ACLs. **Per-machine is not in
  this build:** `/permachine` fails with the machine-unsupported message. It needs the MSI (WiX, outside this
  milestone) and the two elevation stages. Until then administrators also get the per-user install by default,
  which differs from the 6.3 default. Open item.
- **Dokany (7, D32, D36).** `sd_setup_dokany_decide` implements the decision table: per-user never installs it;
  per-machine installs unless `skip`; below 7 SP1 it is unavailable. No `DOKANY_<ARCH>` payload resource exists
  yet, so the chaining waits for the per-machine path. The option page is the frontend's.
- **Registration (6.6).** `packaging/registration.txt` is the single source. `cmake/SdPayload.cmake` generates
  `sd_setup_regtable.c` at configure time, and the same file feeds the MSI tables later. Rows: the Uninstall entry
  (HKCU), `Software\LibreStatic\ShellDrive` (`InstallDir`, `Version`, `Flavour`), App Paths, and the Run value
  only for sign-in start (`/autostart=1`). Shell-extension COM and context-menu rows are not in the table yet;
  they come with the shell extension's registration. Writes and removals touch only ShellDrive-owned keys, and a
  shared key is never deleted.
- **Start menu (6.6).** `Programs\ShellDrive.lnk` through `IShellLinkW`, target `shelldrive-ui.exe`. Uninstall
  removes it.
- **Uninstall (6.7).** `uninstall.exe` in the install folder copies itself to `%TEMP%\ShellDrive-uninstall-<hex>`.
  The folder is created with a DACL for SYSTEM and the user only, in the same call. The copy is started with
  `/waitpid=<parent>` and the parent returns. The copy waits for the parent to exit, then removes the registration,
  the shortcut, the caches (`%LOCALAPPDATA%\LibreStatic\ShellDrive\cache`, no walk through reparse points) and the
  install folder. Settings, profiles and `known_hosts` are kept. `/removedata` (the "also remove settings"
  checkbox) is not implemented yet.
- **Hooks (8.3).** `shelldrive-host.exe --installer-hook <name> --apply|--revert` exists. `signal-shutdown` is
  implemented for the current account and session. `webdav-tune`, `user-cleanup`, `modern-menu` and
  `programdata-secure` log "not yet implemented (M5)" and succeed. The uninstall runs `user-cleanup`.
- **Upgrade with running processes (6.9).** The engine finds the account's `shelldrive-host.exe` processes
  (Toolhelp, resolved at run time), signals `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<session>`,
  waits up to 15 s, and refuses with exit 1603 if an agent still runs (unless `/force`). Files in use are renamed to
  `*.sd-old-<n>` first (NTFS allows renaming a loaded image). The agent does not create its shutdown event yet
  (03 §1.2, the M3 owner), so the signal currently reaches no agent and the wait ends at once. Open item.
- **Not in this build.** Two-stage elevation and the `%ProgramData%\LibreStatic` checks (TM-R34); the `/extract=`
  admin copy; the ARM64 stub; the `PAYLOAD_SIG` signature (above); the MSI; the frontend pages.
- **Log (13).** English, UTF-8: `%TEMP%\ShellDrive-setup-<timestamp>.log`, or `/log=`. It records every file move,
  registry step, hook exit code and the final result.
- **Messages (8.6).** The installer domain (`l10n/installer`, 36 messages) is in all six locales, with CLDR plural
  forms for `installer.summary.files`. The stub's window and message boxes use it.
- **Engine details worth keeping.** FDI may open the cabinet a second time while it decodes a folder. Every open
  needs its own read position. A shared one made the second reader hit the end of the payload, and FDI reported a
  corrupt cabinet (any payload with more than one member failed; a single member worked). Test-only registry keys
  are created one level deep under HKCU and non-volatile: a nested key created implicitly can come out volatile,
  and a child of a volatile key cannot be persistent (error 1021). Test executables must not have "setup" in their
  name: Windows applies installer detection and asks for elevation unless the manifest says `asInvoker`.

---

## 7. Dokany redistribution

### 7.1 Verified facts (as of 2026-10-24)

- Latest release: **v2.3.1.1000, published 2025-09-28** (GitHub API). Assets: `Dokan_x86.msi` (5,128,192 B,
  sha256 `c833fd51…ef618`), `Dokan_x64.msi` (9,269,248 B, sha256 `69ff8cb3…5465`), `Dokan_ARM64.msi`
  (5,128,192 B, sha256 `f812a5bf…91d2e`), `DokanSetup.exe` (bundle, 19 MB), `DokanSetupDbg.exe`, `dokan.zip`
  ([releases](https://github.com/dokan-dev/dokany/releases/tag/v2.3.1.1000)). Full hashes go in
  `installer/dokany/dokany.lock`; the GitHub asset `digest` field is the source and is cross-checked by CI.
- **There is no Dokany ARM32 installer** (README lists ARM among build platforms, but no ARM installer is
  published) — matches the requirement "Dokany backend x86/x64/ARM64". Our own ARM32 MSI (§5.1) therefore
  never carries or chains Dokany.
- Whether `dokan2.dll` 2.3.1 imports the VC++ runtime (`vcruntime140*.dll`) on any architecture is **not
  documented → [lab-verify] in the first week of M4** (C31) with `dumpbin /dependents` on the DLL extracted
  from every per-arch MSI. Upstream `DokanSetup.exe` is a bundle that also installs the VC++ redistributable.
- Supported OS: Windows 7 SP1, 8, 8.1, 10, 11; Server 2008 R2 SP1 – 2022
  ([README](https://github.com/dokan-dev/dokany)). Below that, the WebDAV backend is the only one.
- License: driver `dokan2.sys`, `dokan2.dll`, `dokannp2.dll`, `dokanfuse2.dll` and **the installer** are
  **LGPL**; `dokanctl.exe` and samples MIT ([README](https://github.com/dokan-dev/dokany)). Redistributing
  unmodified binaries is permitted under LGPL with license text and source availability (§7.3).
- Installer behavior changes we must respect (from
  [CHANGELOG](https://github.com/dokan-dev/dokany/blob/master/CHANGELOG.md)): since 2.2.0 the installer is
  WiX 5 based and an ARM64 MSI exists; since **2.3.0 the installer fails if the driver service already exists
  and was installed by something else**; 2.1.0 introduced primitive-driver INF and `dokanctl`-based service
  install; uninstall requires a reboot.
- Signing: upstream states "signed release and debug drivers are provided at each release for all platforms";
  the 2.1.0 release notes mention Microsoft's changed signing rules for primitive drivers and an EV
  certificate renewal ([releases](https://github.com/dokan-dev/dokany/releases)). The exact signature type
  (attestation vs. WHQL) is **not documented upstream → [lab-verify]** with `signtool verify /kp /v` and
  `Get-AuthenticodeSignature` on the extracted `dokan2.sys` of the pinned version.

### 7.2 Signing-policy implications per OS

- **Windows 7 SP1 / 2008 R2:** Microsoft-signed (attestation/HLK) drivers from the Partner Center are SHA-2
  only. Windows 7 needs the SHA-2 code-signing updates **KB4474419 and KB4490628**
  ([Microsoft: 2019 SHA-2 code signing support requirement](https://support.microsoft.com/en-us/topic/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus-64d1c82d-31ee-c273-3930-69a4cde8e64f)).
  Without them, SHA-2-signed drivers fail signature verification (vendors such as
  [Broadcom/VMware](https://knowledge.broadcom.com/external/article/315311/windows-without-sha2-code-signing-suppor.html)
  report this). Setup therefore **checks for KB4474419/KB4490628 on Windows 7** (via
  `Win32_QuickFixEngineering`-free method: presence of SHA-2 support is probed with `WinVerifyTrust` on the
  extracted `dokan2.sys` catalog, falling back to checking the `ci.dll` file version **[lab-verify] exact
  threshold**). If missing: Dokany install is skipped with a localized explanation and a link; ShellDrive
  continues with WebDAV only. We never touch signing policy. This detection and the decision table in §7.3 are
  normative; 02 §6.3 refers to them, and the runtime probe `DokanDriverVersion() != 0` stays the final
  authority (C32).
- **Windows 10/11:** attestation-signed drivers load on client SKUs; Server SKUs require WHQL-certified
  drivers when Secure Boot is on — a Server 2016+ machine may refuse an attestation-only driver
  **[lab-verify]** on Server 2022 with Secure Boot.
- **HVCI / Memory integrity:** a driver must be HVCI-compatible (NX pools, no RWX) to load when memory
  integrity is on ([Microsoft: implement HVCI-compatible code](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/driversecurity/implement-hvci-compatible-code.md)).
  No upstream statement found → **[lab-verify]** on Windows 11 with memory integrity on (lab VM template has
  it enabled by default). If it fails, setup detects memory integrity
  (`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled`)
  and skips Dokany with an explanation — never advises disabling it.
- **Smart App Control:** SAC blocks unsigned/unknown executables in enforcement mode and has no per-app
  exception ([Microsoft SAC FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions)).
  Dokany's MSI is signed upstream; **our own unsigned setup will be blocked on SAC machines** — see §10.

### 7.3 Redistribution design

- `installer/dokany/dokany.lock` pins: version `2.3.1.1000`, minimum supported API version (from the filesystem
  team, e.g. `2.1.0`), per-arch file name, size, SHA-256, upstream URL, mirror URL, Dokany MSI UpgradeCode(s)
  (extracted once with Orca/`msiinfo` and recorded **[lab-verify]**), and the result of the VC++ dependency
  check (`vcruntime = none | required`) per arch, with the date and tool output it is based on.
- **Redistributable form (D32, C31)**, chosen per arch from the lock file:

  | `dokan2.dll` imports | Offline setup EXEs embed | MSI deployments (GPO/Intune) |
  |---|---|---|
  | no VC++ runtime | upstream `Dokan_<arch>.msi` | deploy upstream `Dokan_<arch>.msi` before ShellDrive |
  | `vcruntime140*.dll` | upstream **`DokanSetup.exe` bundle, unmodified** (≈ 19 MB, all arches inside; the x64 offline EXE grows accordingly) | deploy the upstream MSI **and** the VC++ 2015–2022 redistributable as a documented prerequisite; we do not ship the VC++ redistributable ourselves |

  After a Dokany install, setup verifies that `dokan2.dll` loads and the driver answers
  (`DokanDriverVersion() != 0`). The check runs in the installed **native-architecture**
  `shelldrive-host.exe --selftest` (the `x86-ia32` stub cannot load the x64/ARM64 DLL under WOW64), which loads
  `dokan2.dll` only by full System32 path: `LoadLibraryExW(<System32>\dokan2.dll, NULL,
  LOAD_LIBRARY_SEARCH_SYSTEM32)` where the flag is supported, else the same full path with
  `LOAD_WITH_ALTERED_SEARCH_PATH` (Windows 7 SP1 without KB2533623), so its own imports, including a VC++
  runtime, also resolve from System32 and never from our or the current directory (02 §6.2). If it does not
  load because the VC++ runtime is missing, setup reports it and continues with WebDAV only.
- **Embed** in per-arch setup EXEs (MSI form: x64 adds ≈ 9 MB, x86/ARM64 ≈ 5 MB). **Download on demand** in the
  universal EXE (keeps it small): upstream GitHub URL first (needs TLS 1.2), then our HTTP mirror carrying
  the byte-identical file. Integrity is the pinned SHA-256 in both cases; transport security is irrelevant.
- **Integrity is checked when used, not only when fetched (TM-R23, T-65):** the `package` job verifies size and
  SHA-256 of every Dokany file against `dokany.lock` **at embed time**, whether it came from the CI cache or a
  fresh download (a poisoned cache entry fails the build); setup verifies size and SHA-256 again **at install
  time**, on the copy in its admin-only stage-2 directory opened `FILE_SHARE_READ` only, immediately before
  `msiexec`/the bundle runs, and checks the file's Authenticode signature with `WinVerifyTrust` plus the signer
  subject name recorded in `dokany.lock` (`signer = …`, extracted once from the pinned release **[lab-verify]**).
  Any mismatch refuses the Dokany install and continues with WebDAV only. On Windows 7 without SHA-2 support
  the install is skipped earlier (§7.2), so the signer check never has to be weakened.
- **Deny list (TM-R23, T-42):** the signed update manifest may carry `dokany-deny <min>-<max> <reason-id>`
  lines (§9.2). Setup applies the list compiled into it plus the one from the last verified manifest it can
  read; the host (02 §6.3) warns and disables the Dokany backend for listed versions. The bundled version is
  never on the list at release time (release check).
- Never modified, never re-signed, never repacked; we ship the upstream file as-is. A self-built Dokany fork
  was rejected (D12): it would need our own EV certificate and attestation signing, load only on Windows 10+,
  and conflict with an existing official Dokany install.
- Install command (MSI form): `msiexec /i Dokan_<arch>.msi /qn /norestart /l*v
  "%ProgramData%\LibreStatic\ShellDrive\logs\dokany-install.log"`. Bundle form: `DokanSetup.exe /install /quiet /norestart
  /log "%ProgramData%\LibreStatic\ShellDrive\logs\dokany-install.log"` **[lab-verify]** the bundle's switches (WiX Burn
  conventions). `3010` is propagated (reboot required); Dokany can be used without reboot in most cases
  **[lab-verify]**.
- Detection of an existing installation (in this order): `MsiEnumRelatedProducts` with the Dokany UpgradeCode(s)
  → product version; else file version of `%SystemRoot%\System32\dokan2.dll` and presence of the `dokan2`
  driver service **[lab-verify] service name**. Decision table:

| Found | Action |
|---|---|
| Nothing | Install bundled/downloaded MSI if mode/OS allow and the D36 option is checked (`/dokany=auto` or `install`, `DOKANY=1`); unchecked → WebDAV only |
| Any version on the `dokany-deny` list | Offer upgrade with bundled MSI (default on; silent: upgrade unless `/dokany=skip`); otherwise Dokany backend disabled |
| 2.x ≥ min API and ≥ bundled | Use it, do nothing |
| 2.x ≥ min API but < bundled | Use it; offer upgrade (default off; silent mode: no upgrade unless `/dokany=install`) |
| 2.x < min API (MSI-installed) | Offer upgrade with bundled MSI (default on); otherwise Dokany backend disabled |
| Driver present but no Dokany MSI product (third-party install) | Do not install (upstream 2.3 installer would fail anyway); use if API ≥ min |
| Dokany 1.x (`dokan1`) | Coexists; ignored; we install 2.x side by side |

- LGPL compliance: install `licenses\dokany\license.lgpl.txt` + notice text in our install dir (we copy the
  upstream license text, not modify the MSI), show it in the "third-party components" page, and publish
  `dokany-<ver>-source.zip` (the upstream tag archive) next to every release that embeds Dokany.

---

## 8. MSI (per-machine, corporate)

### 8.1 Authoring tool

- **WiX 3.14.1** (`3.14.1.8722` preinstalled on `windows-2022`/`windows-2025` runners per the
  [runner image README](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md)).
  MS-RL license, no EULA gating, decades of XP-installable MSIs.
- WiX v4 set **Windows 7** as its minimum OS (for its custom actions/Burn)
  ([FireGiant meeting #302](https://www.firegiant.com/blog/2025/12/17/wix-online-meeting-302-highlights/));
  v3/v4/v5 are out of community support ([FireGiant](https://www.firegiant.com/wixtoolset/)); v6+ adds the
  Open Source Maintenance Fee/EULA acceptance ([OSMF](https://docs.firegiant.com/wix/osmf/)). An MSI database
  itself has no OS minimum beyond `InstallerVersion`, so **we use no WiX custom actions and no Burn**; then the
  WiX version only affects the build machine and a later migration to v6+ is a source conversion.
- Fallback if WiX 3.14 ever becomes unusable: a small in-repo tool using `msi.dll` (`MsiOpenDatabase`,
  `MsiDatabaseImport` of IDT tables) — native, but more work. Not planned.

### 8.2 Package parameters

| | `x86-ia32`, `x86-sse2` | `x64-xp` | `x64-modern` | `arm32` | `arm64` |
|---|---|---|---|---|---|
| `Platform` / Template | `Intel;1033` | `x64;1033` | `x64;1033` | `Arm;1033` **[lab-verify]** (§5.1) | `Arm64;1033` |
| `InstallerVersion` | **301** (XP SP3 ships Windows Installer 3.1) | **301** (XP x64 SP2 has 3.1) | **500** | **500** (Windows Installer 5.0 is the only version on ARM Windows) | **500** (set explicitly — WiX 3.14 had a bug not raising it for ARM64, [FireGiant #184](https://www.firegiant.com/blog/2020/3/4/wix-online-meeting-184-highlights/)) |
| UpgradeCode | x86 GUID, **shared** by both x86 flavours | x64 GUID, **shared** by both x64 flavours | (same as `x64-xp`) | ARM32 GUID | ARM64 GUID |
| Launch condition | `x86-sse2`: CPU has SSE2 (see below) | none (also runs on 10+, for admins who standardize on one MSI) | OS ≥ 10.0 | ARM32-capable OS, not RT (§5.1) | — |
| Scope | `ALLUSERS=1` (per-machine only; per-user is the EXE's job) | | | | |

UpgradeCodes are fixed forever. Sharing one UpgradeCode between the flavours of an architecture makes a
flavour switch (8.1 → 10 upgrade, or an admin replacing `x86-ia32` with `x86-sse2`) an ordinary major upgrade;
`MajorUpgrade AllowSameVersionUpgrades="yes"` is required so that a switch at the **same** version removes the
other flavour instead of installing side by side (ICE61 warning accepted).

Launch conditions use no custom actions:

- OS version: `AppSearch`/`RegistrySearch` sets `SD_OSMAJOR` from
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMajorVersionNumber` (a DWORD present only on Windows
  10+, read as `#10`) and `SD_OSBUILD` from `CurrentBuildNumber`. `VersionNT` is not used for the 10.0 test
  because Windows Installer reports 603 on Windows 10 for unmanifested callers **[lab-verify]**.
- SSE2 (`x86-sse2` MSI): Windows Installer has no CPU-feature property. The condition reads
  `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` `FeatureSet` **[lab-verify]** that the SSE2 bit is
  reported on XP SP3 and Windows 10 x86; if not reliable, the MSI has no SSE2 launch condition and relies on the
  `/arch:IA32` entry thunk (§3.2), which refuses to start with a message naming the `x86-ia32` MSI.

Rules to stay MSI 3.1-compatible: no `MsiServiceConfig`/`MsiServiceConfigFailureActions` tables (MSI 5.0), no
`MsiLockPermissionsEx` (5.0; use `LockPermissions` or none), no hyperlink controls (5.0), no
`MSIFASTINSTALL`, no `ARPSYSTEMCOMPONENT` tricks. The `x64-modern`, ARM32 and ARM64 MSIs could use 5.0
features but share the source, so we simply avoid them everywhere. ICE validation (`light -sval` disabled)
runs in CI for all six MSIs.

MSI ProductVersion is `MAJOR.MINOR.PATCH` (MSI ignores the 4th field when comparing versions; we never ship
two releases differing only in BUILD). Every release is a **major upgrade** (new ProductCode, same UpgradeCode,
`MajorUpgrade Schedule="afterInstallInitialize"`, `AllowDowngrades="no"`, `AllowSameVersionUpgrades="yes"`).

### 8.3 Contents

Features: `Core` (required: `shelldrive.exe`, `shelldrive-host.exe`, `shelldrive-ui.exe`; `sd_*` are static so
no DLLs), `ShellExt` (default on), `Service` (**default on**, D6), `StartMenu`, `Autostart` (HKLM Run, default
on). The ARM32 MSI has `Core` (CLI + host only) and `Autostart` only (§5.1).

- Service (D6): feature level 1, so it is installed and enabled by default. The public property `SERVICE`
  (default `1`) lets corporate deployments turn it off: `SERVICE=0` sets the feature level to 0 through a
  `Condition` element (equivalent to `ADDLOCAL` without `Service`). `ServiceInstall` (name `ShellDriveSvc`,
  binary `"[INSTALLDIR]shelldrive-host.exe" service`, `LocalSystem`, `Start=auto` unless `SERVICESTART` says
  otherwise, `ErrorControl=normal`) + `ServiceControl` (stop on install/uninstall, start on install, remove on
  uninstall). With no machine profiles the service idles (03). The MSI `Description` is static in the install
  language; the service sets its localized display name/description itself with `ChangeServiceConfig2`
  (indirect string on Vista+), and sets its failure actions at first start with
  `ChangeServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS)` (XP-compatible) — no MSI 5.0 table needed (C44).
  The Event Log source uses an English-only message file (C44).
- Shell extension: COM + context-menu registration from `Registry.wxs` (generated, §6.6); 64-bit and 32-bit
  registry views both written on x64/ARM64 (`Win64="yes"` components and 32-bit components).
- Autostart (C11): HKLM Run value starts `"[INSTALLDIR]shelldrive-host.exe" agent --logon --if-needed`, which
  exits at once if the user has no autostart profiles and no tray; the agent mutex prevents a double start
  with HKCU Run entries.
- Our own deferred EXE custom actions are allowed only if they run our own binaries
  (`shelldrive-host.exe --installer-hook <name> --apply|--revert`, the hidden command of 03 §6.1, C7;
  GUI-subsystem, so no console window), are idempotent, and have a rollback counterpart. The hook names are
  03's: `webdav-tune`, `user-cleanup`, `modern-menu`, `signal-shutdown`, plus `programdata-secure` (TM-R34, 03 §6.1). Uses:
  - `programdata-secure` (deferred, `NoImpersonate`, before `CreateFolders`, `WriteIniValues` and `MoveFiles`,
    install/upgrade/repair): the `%ProgramData%\LibreStatic\ShellDrive` check and reset of §6.4 for installs that do not go
    through our setup EXE (GPO, Intune, `msiexec /i`). It reads no file content, only owners and DACLs.
  - `webdav-tune` (C28): sets only `FileSizeLimitInBytes=0xFFFFFFFF` and
    `FileAttributesLimitInBytes=100000000` under the WebClient parameters, records the original values and
    restores them on uninstall. `BasicAuthLevel` is never touched (A2). Exposed as `WEBDAV_TUNING=1|0`.
    Per-user setup skips it (no HKLM access) and shows how to apply it (`shelldrive --installer-hook
    webdav-tune --apply`, elevated, as in 02 §7.1; `diag --fix webclient` only enables/starts WebClient).
  - `user-cleanup` (impersonated, uninstall only, §6.7).
  - `modern-menu --revert` (uninstall only, elevated, if the sparse package is shipped, §10.1).
  - `signal-shutdown` (deferred, `NoImpersonate`, before `StopServices`, upgrade and uninstall): signals the
    shutdown events of all running agents (§6.9 step 1) when the MSI runs without our setup EXE (ARP, GPO,
    Intune); files still held afterwards fall to the MSI's own Restart Manager/FilesInUse handling.
- **SYSTEM custom actions and repair (TM-R35, T-64).** A standard user can run `msiexec /fa` (or `/fu`, `/fm`)
  on the cached package, and deferred `NoImpersonate` actions then run as SYSTEM. Rules:
  - Conditions (normative; `REINSTALL` is set by every repair):

    | Hook | Context | Condition |
    |---|---|---|
    | `programdata-secure --apply` | deferred, SYSTEM | `NOT REMOVE~="ALL"` — runs during repair too: it is itself the protection and reads no content |
    | `webdav-tune --apply` / `--revert` | deferred, SYSTEM | apply: `WEBDAV_TUNING=1 AND NOT REMOVE~="ALL"` (idempotent, so repair is allowed; the recorded originals in `%ProgramData%\LibreStatic\ShellDrive\service\state\webdav-tune.ini` (03 §6.1) are never overwritten by a repeat run); revert: `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` |
    | `signal-shutdown` | deferred, SYSTEM | `NOT REINSTALL AND (REMOVE~="ALL" OR WIX_UPGRADE_DETECTED)` |
    | `modern-menu --revert` | deferred, SYSTEM | `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE AND NOT REINSTALL` |
    | `user-cleanup --apply` | deferred, **impersonated** | `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` |

    Each rollback counterpart carries the same condition. No other action of ours runs as SYSTEM.
  - While its token is SYSTEM, the hook host loads no user configuration (no HKCU, no `%APPDATA%`, no
    `settings.ini` of a user, no policy beyond HKLM), resolves no environment-relative path (paths come from its
    own module path, which must be under an admin-owned `[INSTALLDIR]`, and from known-folder APIs for common
    folders; `CustomActionData` is treated as untrusted and carries only the hook name and fixed flags), opens no
    window, starts no child process, and applies the DLL rules of §6.4 (`SetDefaultDllDirectories` /
    full System32 paths). Files it touches are opened with `FILE_FLAG_OPEN_REPARSE_POINT` and owner checks.
  - CI check (TST-29 support): `tools/sd-msilang --dump-sequences` prints the `InstallExecuteSequence` and
    `CustomAction` rows of all six MSIs; the `package` job fails if any `NoImpersonate` action lacks the
    condition above or a new one appears without an entry in this table.
- `EnableLinkedConnections` (D24): see `ENABLELINKEDCONNECTIONS` in §8.4. Plain `Registry` table component,
  no custom action.
- Machine settings: `UPDATECHECK`, `UPDATEURL` and `UPDATECHANNEL` are written to
  `[CommonAppDataFolder]LibreStatic\ShellDrive\settings.ini` `[update]` with the native `IniFile` table (MSI 3.1, C8),
  sequenced after `programdata-secure`.
  `HKLM\Software\LibreStatic\ShellDrive\Version` is written by the MSI only, for Intune detection.
- Localization: §8.6.

### 8.4 Public properties for silent configuration

| Property | Default | Meaning |
|---|---|---|
| `INSTALLDIR` | `[ProgramFiles64Folder]LibreStatic\ShellDrive` | Install location |
| `ADDLOCAL` / `REMOVE` | all | Standard feature selection |
| `DEFAULTPROFILES` | empty | Path to a **folder** of `.ini` profiles (03 §3.4 format, typically `scope = users`) that the MSI copies into `[CommonAppDataFolder]LibreStatic\ShellDrive\profiles\` with the native `MoveFile` table (copy mode, `*.ini` wildcard, no custom action) (C9) |
| `UPDATECHECK` | `0` when installed with `/qn`, else `1` | Writes `settings.ini [update] enabled` in `%ProgramData%\LibreStatic\ShellDrive\` (C8) |
| `UPDATEURL` | empty | Writes `settings.ini [update] manifest_url` (internal mirror) |
| `UPDATECHANNEL` | `stable` | Writes `settings.ini [update] channel` |
| `SERVICE` | `1` | `0` = do not install the service (D6) |
| `SERVICESTART` | `auto` | `auto`/`demand`/`disabled` |
| `AUTOSTART` | `1` | Agent autostart for all users (HKLM Run, §8.3) |
| `WEBDAV_TUNING` | `1` | See §8.3 |
| `ENABLELINKEDCONNECTIONS` | `0` | D24. `1` writes `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections = 1` (DWORD) on Vista+ (`VersionNT >= 600`) so elevated processes see per-user mapped drives; takes effect after a reboot (setup returns 3010). An `AppSearch` detects a pre-existing value; if the admin had already set it, the MSI neither writes nor removes it, otherwise uninstall removes the value it wrote. Per-user setup never sets it |
| `DOKANY` | `1` | D36: mirrors the setup option. The MSI never installs Dokany itself (§8.5); setup passes `DOKANY=0` for `/dokany=skip` or an unchecked box, and `DOKANY=0` writes the machine default `settings.ini [backend] dokany = no` (key owned by 03 §3.4) so ShellDrive stays on WebDAV even if Dokany is present or installed later. `1` writes nothing |
| `REMOVESECRETS` | `1` | Uninstall only (TM-R28): `1` removes `%ProgramData%\LibreStatic\ShellDrive\service\secrets\` and `service\keys\`; `0` keeps them. Not applied during upgrades |
| `REMOVEDATA` | `0` | Uninstall only: `1` removes `%ProgramData%\LibreStatic\ShellDrive\` (machine profiles, settings, state, and — implied — service secrets and keys) |

Policies live in one key, `HKLM|HKCU\Software\Policies\LibreStatic\ShellDrive` (HKLM wins; the list and semantics are
owned by 03 §3.5), override these at run time and are documented in an ADMX/ADML pair shipped in the release
(`policy\ShellDrive.admx` + ADML for the six languages, generated by `sdl10n`, §8.6). The ADMX target namespace
is `com.librestatic.shelldrive.policies` (prefix `shelldrive`), under a `LibreStatic` > `ShellDrive` category (D45). The ADMX has one policy
per 03 §3.5 value, machine and user class unless noted. M4 implementation: the table is `res/policy/policies.txt`,
`tools/sd-admxgen` generates the ADMX and ADML (texts from `l10n/policy`, checked by `sdl10n --check`), and
`tests/policy/check-admx.ps1` fails the build's tests when the ADMX and the table differ. The rows below are the
mapping the table implements:

| Policy value | ADMX element |
|---|---|
| `LegacyAlgorithms` | enum: 0 allow, 1 warn, 2 refuse |
| `AllowUserProfiles`, `AllowAdHocMounts`, `DisableCredentialSaving` | boolean |
| `AllowedBackends` | text (`webdav,dokany`) |
| `StrictHostKeyChecking`, `DisableKnownHostsSources` | boolean |
| `UpdateHostKeys` | enum: 0 never, 1 ask, 2 accept proven keys (machine class: lets the service update the machine store) |
| `ForceWriteThrough` | boolean |
| `ProxyServer` | text (proxy spec, 03 §3.8) |
| `AllowSystemProxy` | boolean |
| `UILanguage` | enum of the six canonical codes |
| `DisableUpdateCheck` | boolean |
| `UpdateChannel` | enum: `stable`, `beta` |
| `UpdateUrl` | text |
| `HideTrayIcon`, `DisableNetworkLocations`, `DisableModernContextMenu` | boolean |

### 8.5 Dokany with MSI deployments

MSI cannot nest MSI installs. Options documented for administrators:

- **GPO Software Installation:** deploy `Dokan_<arch>.msi` (upstream, signed) as its own package ordered before
  ShellDrive (and, if the lock file says `vcruntime = required`, the VC++ 2015–2022 redistributable before
  Dokany, §7.3); properties are passed with an `.mst` (GPO cannot pass properties) — we document creating one
  with Orca and ship `ShellDrive-defaults.mst` examples (including `SERVICE=0`, `DOKANY=0` and
  `ENABLELINKEDCONNECTIONS`). The admin guide states, as the setup page does (D36), that deploying Dokany installs
  a signed third-party kernel driver available to every local user; fleets that do not want it deploy
  ShellDrive alone with `DOKANY=0`.
- **Intune Win32 app:** two apps (Dokany, ShellDrive) with a *dependency* relationship; detection rule by
  `HKLM\Software\LibreStatic\ShellDrive\Version` ≥ X (ProductCode changes every release, so not by ProductCode).
- **Setup EXE as chainer:** `ShellDrive-<ver>-setup-x64.exe /quiet /permachine /dokany=install
  DEFAULTPROFILES=\\srv\share\shelldrive-profiles` installs both (in the bundle form, the VC++ runtime too) —
  valid for Intune Win32 apps, SCCM, PDQ.
- ShellDrive works without Dokany (WebDAV backend); the MSI has no launch condition on it. Global drives of the
  service use Dokany as the primary path; without Dokany the service attempts global WebDAV drives (D11,
  02 §7.7: `system`/`link` mapping where the M5 lab spike passed, otherwise per-user `attach` at logon, so
  "available after sign-in" only).

### 8.6 Installer localization (C41, C42, C43, D26)

- **PO is the only source** of installer text (domain `installer`, 03 §9). `tools/sdl10n` generates from it:
  the C string tables of the setup stub and `uninstall.exe`, the STRINGTABLE resources (service display
  name/description, ProgID), the WiX `.wxl` files and the ADML files. No `.wxl` or ADML is edited by hand;
  AGENTS.md register rules apply (Rioplatense voseo, Brazilian Portuguese, French "vous", informal German and
  Italian imperative).
- **Plurals (D26):** the catalog supports the full CLDR plural categories (zero/one/two/few/many/other) for
  every locale; `sdl10n` holds the CLDR plural rules of our six languages, transcribed by hand from the CLDR
  specification (data, with the CLDR version noted; no CLDR files or code are vendored) and checks that every
  plural message has exactly the categories its locale needs (es/fr/it/pt-BR use `many`). Plural selection
  happens at run time in our C code. `.wxl` and ADML have no plural mechanism, so `sdl10n` **rejects** plural
  messages in the subsets it exports to `.wxl` and ADML; such text is reworded or shown by the setup EXE.
- Language codes are `en es fr pt-BR it de`; `pt` is accepted as an alias of `pt-BR` (C42). The build-only
  `qps` pseudo-locale is generated for layout tests and never embedded in shipped MSIs.
- **Transforms:** the base MSI is en-US; `tools/sd-msilang` (C, using `msi.dll`:
  `MsiDatabaseGenerateTransform`, `_Storages` substorage insertion, summary `Template` languages) embeds one
  transform per language and **registers it under every LCID of that language**, because Windows Installer
  applies an embedded language transform only on an exact LCID match (C43):
  - `es` (voseo text) under 11274 (es-AR), 3082 (es-ES), 1034 (es-ES traditional), 2058 (es-MX), 21514 (es-US)
    and every other `es-*` LCID;
  - `pt-BR` under 1046 (pt-BR) and 2070 (pt-PT);
  - `fr`, `it`, `de` under every LCID of their primary language (e.g. fr 1036/3084/2060/4108, de
    1031/3079/2055, it 1040/2064).
  `sdl10n` emits the LCID lists from one table, so the mapping is not maintained in two places.
- The setup EXE always passes `TRANSFORMS=:<lcid>` explicitly from its own language resolution (§6.5), so
  automatic selection matters only for direct `msiexec` installs, where it is undocumented behaviour
  **[lab-verify]** on XP SP3 and Windows 11.

---

## 9. Updater

### 9.1 Ownership and flow

- The per-user **agent** (`shelldrive-host.exe agent`, module `sd_update`) checks for updates (at most once per
  24 h + random 0–6 h jitter, and on demand from the UI/CLI `shelldrive update check|apply [--manifest
  <path>]`, IPC `update.check`/`update.apply`, event `update.available`, C7). The service never downloads
  anything.
- Flow: fetch manifest (and `keyset.txt` when the manifest names a newer keyset, §9.3) → verify keyset and
  manifest signature, channel and expiry → compare version → **ask the user** (tray notification + dialog with
  release notes link, "Install now / Later / Skip this version") → download artifact for the current install
  mode and **target flavour** → verify SHA-256 from the manifest → stage → apply → health check → cleanup or
  rollback.
- Target flavour: re-evaluated at every check with §6.2 (CPU SSE2 and OS version), not copied from the running
  binary, so an OS upgrade moves `x64-xp` to `x64-modern`. The running flavour is read from `SD_FLAVOUR`.
- Settings (C8, owned by 03 §3.4/§3.5): `settings.ini [update] enabled, channel, manifest_url` — machine
  defaults in `%ProgramData%\LibreStatic\ShellDrive\settings.ini` (written by the MSI), user overrides in
  `%APPDATA%\LibreStatic\ShellDrive\settings.ini`, portable in `<exe dir>\data\settings.ini`. Policy values
  (`HKLM\Software\Policies\LibreStatic\ShellDrive`: `DisableUpdateCheck`, `UpdateChannel`, `UpdateUrl`) win over both.
  No update setting is stored elsewhere in the registry.
- Disabled when: portable (check only, user downloads manually), `[update] enabled = no`, or policy
  `DisableUpdateCheck`. When an organization manages updates the UI shows "Updates are managed by your
  organization".

### 9.2 Manifest format (`manifest.txt`)

UTF-8, LF line endings, one record per line, ASCII keys, space-separated fields, no escapes needed (fields
contain no spaces by construction), max 64 KB. Simple to parse in C, trivially canonical (the signed bytes are
the file bytes).

```
shelldrive-manifest 1
product com.librestatic.shelldrive
channel stable
keyset 1
serial 2026102401
version 1.0.0
released 2026-10-24T12:00:00Z
expires 2026-11-23T00:00:00Z
min-os x86-ia32 5.1
min-os x86-sse2 5.1
min-os x64-xp 5.2
min-os x64-modern 10.0
min-os arm32 6.3
min-os arm64 10.0
notes https://github.com/LibreStatic/ShellDrive/releases/tag/v1.0.0
file setup-universal ShellDrive-1.0.0-setup.exe 7123456 sha256:<64 hex>
file setup-x86 ShellDrive-1.0.0-setup-x86.exe 9876543 sha256:<64 hex>
file setup-x64 ShellDrive-1.0.0-setup-x64.exe ...
file setup-arm64 ShellDrive-1.0.0-setup-arm64.exe ...
file setup-arm32 ShellDrive-1.0.0-setup-arm32.exe ...
file msi-x86-ia32 ShellDrive-1.0.0-x86-ia32.msi ...
file msi-x86-sse2 ShellDrive-1.0.0-x86-sse2.msi ...
file msi-x64-xp ShellDrive-1.0.0-x64-xp.msi ...
file msi-x64-modern ShellDrive-1.0.0-x64-modern.msi ...
file msi-arm32 ShellDrive-1.0.0-arm32.msi ...
file msi-arm64 ShellDrive-1.0.0-arm64.msi ...
file portable-x86-ia32 ShellDrive-1.0.0-portable-x86-ia32.zip ...
file portable-x64-modern ShellDrive-1.0.0-portable-x64-modern.zip ...
dokany 2.3.1.1000 x64 Dokan_x64.msi 9269248 sha256:69ff8cb37bfec3a75921c85ffd1c6370b50a9ec4ecef2cf3a009d488dcbf5465
dokany-deny <min-version>-<max-version> <reason-id>        (zero or more lines, TM-R23)
base https://github.com/LibreStatic/ShellDrive/releases/download/v1.0.0/
base http://dl.<our-domain>/releases/1.0.0/
sig ed25519 <key-id-16hex> <signature-base64>
```

- Signature: ed25519 over `"com.librestatic.shelldrive release manifest v1\n" || <all bytes up to and including the LF before
  the sig line>`. Verification code is in `sd_crypto` (shared with SSH ed25519); `tools/sd-release` signs.
- Unknown keys are ignored (forward compatible); unknown `shelldrive-manifest` major version → "update the
  application manually".
- **Product binding (D45):** a manifest whose `product` is not `com.librestatic.shelldrive` is rejected. Channel
  names are short (`stable`, `beta`) and scoped by that product id; their full ids are
  `com.librestatic.shelldrive.stable` / `.beta`.
- **Channel binding (TM-R37, T-67):** a manifest is accepted only if its `channel` equals the configured channel
  and its `sig` key is authorized for that channel by the current keyset (§9.3). A beta-signed manifest is
  therefore never accepted on stable, and a stable key cannot sign beta.
- **Anti-rollback per channel (TM-R37):** `serial` must be > the last accepted serial **of the same channel**,
  stored as `last_serial.<channel>` (`last_serial.stable`, `last_serial.beta`) in the `state\` directory (C8):
  per user `<LocalAppData>\LibreStatic\ShellDrive\state\` (written by the agent), per machine `%ProgramData%\LibreStatic\ShellDrive\state\`
  (written by the elevated setup after a per-machine update; users can read but not write it), portable
  `<exe dir>\data\state\`. The agent uses, per channel, the maximum of the values it can read. A huge beta
  serial therefore cannot block stable updates. The pre-integration single `last_serial` file is migrated to
  `last_serial.<configured channel>` once. Switching from beta to stable installs nothing until a stable
  version greater than the installed one exists (no downgrade, §8.2).
- **Freshness (TM-R36, T-66):** `expires` is at most **30 days** after `released`/re-signing for `stable` and at
  most **14 days** for `beta` (`sd-release` refuses longer values); `expires` in the past → "cannot verify
  updates" (no install). The release process re-signs the current manifest of each channel every two weeks with
  a new serial (§12.3), so a hostile mirror or network can hide a security fix for at most about a month. The
  agent records `last_verified.<channel>` (time of the last successful verification) in `state\`; after
  14 days without a fresh manifest the UI shows the staleness notice (03 §7.7, string `warn.update_stale`,
  "ShellDrive could not check for updates for {days} days."; text and placement owned by 03). A stale mirror can therefore delay, but never downgrade or forge.
- `dokany-deny <min>-<max> <reason-id>` (TM-R23): Dokany versions the host must not use (§7.3, 02 §6.3); the
  host keeps the list from the last verified manifest of its channel in `state\`.
- Channels: `stable`, `beta`. Each channel has its own manifest URL and its own release key (§9.3).

### 9.3 Keys

TUF-style split of roles (TM-R37, T-67): offline root keys decide which keys may sign; online release keys sign
manifests and payload tables only and cannot change who is trusted.

| Role | Keys | Held where | Signs |
|---|---|---|---|
| **root** | `root-a` (the former `release-backup`) and `root-b`, ed25519 | offline only, on two separate encrypted media in two locations, never on a networked machine and never in CI | `keyset.txt` |
| **release-stable** | one active ed25519 key (plus at most one overlapping successor during rotation) | the maintainer's offline signing machine, encrypted key file with passphrase | stable `manifest.txt`, stable payload tables (§6.1), `SHA256SUMS.sig` |
| **release-beta** | one active ed25519 key | GitHub environment secret `beta-signing` (protected, required reviewer = maintainer) | beta manifests, beta payload tables |

- Key ID = first 8 bytes of SHA-256(public key). Key labels (key file names, keyset comments, CI secret
  descriptions) are reverse-DNS (D45): `com.librestatic.shelldrive.root-a`, `.root-b`, `.release-stable`,
  `.release-beta`. The two **root public keys** and the keyset current at build
  time (`installer/keys/`) are compiled into every binary and stub.
- **Keyset format** (`keyset.txt`, same line syntax and size limit as the manifest):

  ```
  shelldrive-keyset 1
  product com.librestatic.shelldrive
  version 3
  issued 2026-10-24T00:00:00Z
  key <key-id> stable <pubkey-base64> 2026-10-24 2028-10-24
  key <key-id> beta <pubkey-base64> 2026-10-24 2027-10-24
  revoke <key-id> <reason-id>
  sig ed25519 <root-key-id> <signature-base64>
  ```

  Signed with the domain string `"com.librestatic.shelldrive keyset v1\n"`. A keyset is valid if signed by **either** root key;
  a keyset that changes the root keys (`root <key-id> <pubkey>` lines) needs signatures by **both** current
  roots. Keyset `version` is monotonic: clients store the highest accepted one in `state\keyset` (with the
  file) and refuse lower versions, so revocations cannot be rolled back; the compiled-in keyset is the floor.
- **Using it:** the manifest names the keyset version it needs (`keyset <n>`); if that is higher than the stored
  one the agent fetches `keyset.txt` from the same base URLs, verifies it against the roots, stores it, then
  verifies the manifest. The `sig` key must be listed for the manifest's channel, inside its validity dates,
  and not revoked.
- **Rotation:** the maintainer signs, offline with a root key, a keyset version `n+1` that adds the new release
  key; releases signed with the new key name `keyset n+1`; a later keyset removes the old key.
- **Compromise of a release key** (for example the CI-held beta key): a root-signed keyset revokes it and
  authorizes a replacement; every client that sees any newer manifest fetches the keyset and rejects the old
  key from then on. The compromised key cannot prevent this because it cannot sign keysets. **Compromise of
  one root key:** a keyset signed by both roots replaces it. Loss of both roots needs a manual reinstall with
  new binaries (documented).
- Re-signing for freshness (TM-R36) uses the release keys only; root keys are touched only for keyset changes.

### 9.4 Transport

Facts: GitHub removed TLS 1.0/1.1 for github.com and api.github.com in February 2018
([GitHub blog](https://github.blog/2018-02-23-weak-cryptographic-standards-removed)). XP's Schannel/WinHTTP 5.1
offers only up to TLS 1.0. Windows 7 Schannel supports TLS 1.2 but **WinHTTP uses TLS 1.0 unless
KB3140245** is installed (and the option is set) ([KB3140245](https://support.microsoft.com/en-us/help/3140245)).
Vista has no TLS 1.2 at all.

Options considered:

| Option | Verdict |
|---|---|
| Our own TLS 1.2 client | We already will have X25519, ECDSA, RSA, AES-GCM, ChaCha20-Poly1305, SHA-2. Missing: TLS record/handshake state machine, X.509/ASN.1 parsing, chain validation, and **a trust store** (XP's root store is frozen and does not contain today's roots — we would have to pin roots ourselves). Weeks of security-critical code for a channel that needs only integrity. **Rejected.** |
| Plain HTTP mirror + our signature | Integrity and authenticity come from the ed25519 manifest + SHA-256 per file; privacy of "this machine runs ShellDrive vX" is not a requirement. **Chosen.** |
| Manual updates on XP | Remains available (download on another machine, run setup); the updater also reports "update available, download manually" if both transports fail. |

Algorithm (WinHTTP everywhere, `WinHttpOpen` with `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`, honoring IE/`netsh
winhttp` proxy; on XP also `WinHttpGetIEProxyConfigForCurrentUser` + auto-proxy):

1. Windows 7+: request `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2` via `WinHttpSetOption`; try the HTTPS base
   URLs. Windows 8+: default protocols already include TLS 1.2.
2. On `ERROR_WINHTTP_SECURE_FAILURE`, `ERROR_WINHTTP_INVALID_OPTION` or on XP/Vista directly: try the
   `http://` base URLs.
3. All downloads are written to the staging file, size-checked against the manifest, hashed, and only then
   used. HTTP redirects allowed only to URLs in the manifest's `base` list or GitHub's release-asset storage
   hosts.
4. Bootstrap manifest URLs compiled in (overridable by policy/`UPDATEURL`):
   `https://github.com/LibreStatic/ShellDrive/releases/latest/download/manifest.txt` and
   `http://dl.<our-domain>/stable/manifest.txt`.

The HTTP mirror (D30) is **static object storage** that serves plain HTTP without a forced redirect to HTTPS
(a bucket or static site with "always HTTPS" disabled). No server-side code runs there; integrity comes only
from the ed25519 manifest and the per-file SHA-256, so any provider is acceptable and can be replaced by
changing DNS. The release workflow uploads the same files there. The specific provider is an operational
choice made before the first public release, not a design question.

Proxies: the updater uses WinHTTP with the system proxy settings above; the per-profile SSH proxies of D20
do not apply to update traffic.

### 9.5 Private repository (interim)

- GitHub private release assets need an authenticated API call (`GET /repos/{o}/{r}/releases/assets/{id}`
  with `Accept: application/octet-stream` and a token) ([community discussion](https://github.com/orgs/community/discussions/47453)).
  **We will not embed tokens in binaries.**
- Interim: shipping builds have the updater compiled in but the default bootstrap URLs point to the future public
  locations; while the repo is private, testers set `settings.ini [update] manifest_url` to a
  `file://\\share\…` or a private HTTP mirror, or run `shelldrive update check --manifest <path>`. The release
  workflow can also publish to the HTTP mirror while the repo is private (signature makes this safe).

### 9.6 Staging, apply, rollback

- Staging dir: per-user `%LOCALAPPDATA%\LibreStatic\ShellDrive\updates\<version>\`; per-machine downloads by the user's
  agent go there too, then the elevated setup **copies them into an admin-only directory and re-verifies
  signature and hash** before execution (no TOCTOU, no execution from user-writable paths while elevated).
  Concretely the per-machine update runs the two elevated stages of §6.4 (TM-R33, T-70): stage 1 is started from
  the user's staging folder but creates no window and loads no non-KnownDLL module; it copies the setup EXE into
  a fresh `%ProgramData%\LibreStatic\ShellDrive\setup\<random>` directory and stage 2 re-verifies the manifest signature, the
  file hash from the manifest and the payload table before doing anything else.
- Apply: launch `setup.exe /update /passive` (per-machine: via `runas` → UAC; XP limited user: "ask an
  administrator to install this update" and stop).
- Per-user mode rollback: setup keeps `<root>\.rollback\<oldver>\`; after install it starts
  `shelldrive-host.exe --selftest` (C2: loads every module, resolves imports, checks the flavour's CPU/OS floor,
  opens config, exits 0). Failure or
  no "healthy" marker within 60 s of first start → restore from `.rollback`, record the bad version as
  skipped, report.
- Per-machine rollback: MSI transactions handle install failures. For post-install health failure, the
  previous MSI is kept in `%ProgramData%\LibreStatic\ShellDrive\updates\last-good\`; setup uninstalls the new product and
  reinstalls the previous one (an explicit uninstall+install, since `AllowDowngrades="no"`).
- Cleanup: keep only the current and last-good versions; delete old `.sd-old-*` files at agent start.

### 9.7 Decisions taken in M4 (`sd_update`)

The engine is `src/sd_update` (pure verification, state, WinHTTP transport, engine); the agent methods are in
`apps/shelldrive-host/update_ipc.c`; the release-side signing tool is `tools/sd-updsign`. Developer notes:
`docs/dev/m4-notes.md`. Where §9.1–§9.6 left a choice, the following applies.

- **Signature primitive:** ed25519 (`sd_ed25519_verify`, sd_crypto M0) for keyset and manifest. Message = domain string
  || the exact bytes before the first `sig` line. The keyset may carry several `sig` lines (one per root); a sig whose key
  id is not a current root is ignored, a sig by a current root that does not verify is a hard error.
- **Keyset rules:** each `key` line carries the key id, which must equal the first 8 bytes of SHA-256 of the public key
  (checked at parse); `revoke` applies to the keys listed in the same keyset; a keyset with `root` lines (rotation) needs
  valid signatures by **both** current roots, and the `root` lines become the roots in effect. A keyset with a version lower
  than the stored one is `keyset_rollback`; an equal one is accepted.
- **Stored keyset:** `state\keyset` (the accepted keyset.txt bytes) and `state\roots` (40-byte records: key id, public key)
  are written only after verification and are parsed without a second signature check, because a rotation keyset is
  signed by the roots it replaces. Local state is trusted as far as local files are trusted (a user can already replace
  the agent); the per-machine copy is written by elevated setup only.
- **First run:** with no stored keyset the trust anchor is the compiled-in roots at keyset version 0; a manifest that
  names keyset n ≥ 1 makes the agent fetch `keyset.txt` next to the manifest URL and verify it.
- **Anti-rollback:** `serial` must be ≥ `last_serial.<channel>`. A serial equal to the last accepted one is accepted only
  with the same bytes as `state\manifest.<channel>` (a re-signed manifest needs a new serial). Writes happen only after the
  whole chain passed: serial, manifest bytes, then `last_verified`.
- **Freshness:** `expires - released` ≤ 30 days (stable), ≤ 14 days (beta); `expires` in the past is `manifest_expired`.
  `update.stale` is reported when the last successful verification is older than 14 days and the current check fails.
- **Manifest syntax:** printable ASCII and LF only, one record per line, single spaces, final LF, the sig line last and
  unique. Unknown keys are ignored. The `shelldrive-manifest` major must be 1, otherwise `format_version_unknown`
  ("update the application manually"). A `dokany` line is stored as file `dokany-<arch>`; `dokany-deny` lines stay in the
  stored manifest for the Dokany check (TM-R23).
- **Transport (§9.4):** WinHTTP is loaded from System32 and every entry point is resolved at run time, so nothing post-XP
  is imported statically. `WINHTTP_OPTION_SECURE_PROTOCOLS` requests TLS 1.2 where the option exists. Redirects are followed
  by hand: a `Location` must name a host from the manifest's `base` lines or a GitHub release-asset host, and https to http
  is refused. The manifest URL has an optional fallback (`manifest_alt`): the HTTP mirror is tried when the HTTPS URL fails
  with a network error. A response over the manifest size (or over its declared Content-Length) is refused before the body
  is used.
- **Artifact selection:** `msi-<flavour>` for MSI installs, `portable-<flavour>` for portable, and for per-user EXE
  installs `setup-universal` first, then `setup-<arch>` (`x86`, `x64`, `arm32`, `arm64`). `min-os` lines are checked
  against the running OS. The flavour is detected at every check (§6.2): `x86-sse2` or `x86-ia32` from the CPU; on AMD64
  `x64-xp` for NT 5.x and `x64-modern` otherwise; `arm32` and `arm64` from the native architecture.
- **Staging and download:** `<staging>\<version>\<name>`. The bases are tried in manifest order; size and digest are checked
  after the download and before the file is moved into place; a complete earlier download is reused. A file that fails the
  check is deleted and never used.
- **Apply:** setup mode runs the staged `setup.exe /update /passive` and waits (10 minutes) for exit code 0. The file-swap
  mode (portable layouts and the engine tests) keeps the previous files in `install\.rollback\<old>\`, copies each new file
  to `<name>.sd-new` and moves it over the old name with MoveFileEx, runs `--selftest` (60 s limit), and restores everything
  on failure. A file in use cannot be replaced by this mode, so the agent uses the setup mode, which is the one that ships.
- **Policy and settings:** `DisableUpdateCheck` (HKLM, then HKCU) disables checks with reason `policy`; `UpdateChannel` and
  `UpdateUrl` override the settings. `[update] enabled = no` gives reason `settings`. A portable install (a
  `data\settings.ini` next to the executable) may check, but `update.apply` refuses it (`update_disabled`) and the UI offers
  the manual download. Defaults: enabled, channel `stable`, the GitHub bootstrap manifest.
- **Trust in this build:** no release root is compiled in yet (the release build adds `installer/keys/`, §9.3). Without
  roots every verification fails closed with `update_verify_failed`.

---

## 10. Authenticode signing of our binaries

No certificate yet. The pipeline exists, is exercised with a **test certificate** in CI (self-signed,
discarded, only to validate tooling — not trusted on any machine, and never shipped), and is switched to the
real certificate by adding secrets.

- What gets signed: every PE we build (exe/dll, all six flavours), the setup EXEs (after payload resources are
  attached — signing is the last mutation; the sparse MSIX is signed before it is embedded), MSIs, the sparse
  MSIX (§10.1), and `uninstall.exe`. Never Dokany files.
- **PE dual signing:** first `signtool sign /fd sha1 /t <legacy timestamp URL>` then
  `signtool sign /as /fd sha256 /tr <RFC3161 URL> /td sha256`. XP SP3 validates SHA-256 *certificates* but not
  SHA-256 *file digests*, so the SHA-1-digest signature is what XP checks; `/as` requires signtool ≥ 6.3
  ([Slicer docs](https://www.slicer.org/wiki/Documentation/4.8/Developers/Windows_Code_Signing),
  [Indigo Rose](https://indigorose.com/webhelp/vp/Program_Reference/Build_Settings/Code_Signing.htm)).
  **[lab-verify]** on XP SP3 and on Windows 7 without updates.
- **MSI: single SHA-256 signature** — MSI does not support appended signatures
  ([InstallAware](https://www.installaware.com/forums/viewtopic.php?p=42733)); XP will show an unverified
  publisher for the MSI, the EXEs inside are still dual-signed.
- Timestamping is mandatory (signatures must outlive the certificate). Whether any public TSA still issues
  SHA-1 legacy (`/t`) timestamps must be checked when we buy the certificate **[open]**; if none does, XP
  sees a valid signature only while the certificate is unexpired.
- Certificate source (decided, D29): **SignPath Foundation** free OSS signing (requires a public repo, signs
  in their HSM via CI integration); if that is not granted, **Certum Open Source Code Signing** (individual,
  low cost, cloud HSM). The certificate must be in place **before a public 1.0**. A commercial OV certificate is
  not planned. **Azure Artifact Signing** is limited to
  organizations in US/CA/EU/UK and individuals in US/CA
  ([Microsoft Learn: code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options))
  and its short-lived certs chain to recent Microsoft roots that XP lacks — unsuitable as the only option.
  Since 2023 private keys must live in HSMs, so `SdSign.cmake` supports both `signtool /f` (test) and
  `signtool /dlib` / KSP providers (cloud HSM).
- **SmartScreen:** unsigned or new-certificate downloads show "Windows protected your PC" until reputation
  accrues; OV, EV and Artifact Signing all build reputation the same way now
  ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)).
  **Smart App Control** in enforcement mode blocks our unsigned binaries outright with no user override
  ([SAC FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions)) —
  this is the strongest reason to obtain a certificate before a public 1.0.
- Windows 11 modern context menu: see §10.1.

**Interim rules while binaries are unsigned (TM-R38, T-71, D38).** Users who learn to click through "Windows
protected your PC" cannot tell a trojaned look-alike from our build. Until the Authenticode certificate exists:

- **No public download links.** No GitHub release is published as public, no mirror path is linked from the
  README or a web page, and no manifest on a public URL points at unsigned builds. Builds go to **named
  testers** only (private repository releases or a private mirror path, §9.5).
- Each tester build is accompanied by `SHA256SUMS` and its ed25519 `SHA256SUMS.sig`; the fingerprints (key IDs
  and full public keys) of the root and release keys are published in the repository `README.md`, so they come
  over an authenticated channel separate from the download. Tester instructions: compare the setup EXE's
  SHA-256 (`certutil -hashfile <file> SHA256` on Vista+) with `SHA256SUMS` obtained from the repository, never
  run a ShellDrive EXE from any other source, and expect the SmartScreen warning only for files whose hash
  matched. Machines with Smart App Control in enforcement mode cannot run tester builds; we do not advise
  turning it off.
- The setup stub verifies its own payload table against the compiled-in keyset and refuses on mismatch (§6.1);
  existing installs update only through the signed manifest (§9).
- Before crypto review pass 1 (end of M2, D38) tester builds show "pre-release, cryptography not yet externally
  reviewed" on the first setup page, and tester instructions recommend test servers and test keys.
- The gates for wider distribution are in §12.3 ("Release gates").

### 10.1 Sparse MSIX package for the Windows 11 modern context menu (D27)

Decision: in 1.0 **if** the code-signing certificate exists in time; otherwise 1.0 ships the classic menu
only (entries under "Show more options") and the sparse package lands in a 1.x release. The release workflow
treats it as a build switch `SD_SPARSE_MSIX=ON|OFF`, ON only when real signing secrets are configured; nothing
else in the installer changes when it is OFF.

- **What it is:** a package with identity but no payload of its own (`AppxManifest.xml` with
  `uap10:AllowExternalContent`, `ExternalLocation` = the install directory). It declares
  `desktop4:FileExplorerContextMenus` / `desktop5:ItemType` entries (`Directory`, `Directory\Background`, `*`,
  and `Drive` if Windows honors it, 03 §8.6) and a
  `com:SurrogateServer` class pointing to the `IExplorerCommand` implementation in
  `shellext\<version>\shelldrive-shellext.dll` (implementation owned by 03). Template:
  `installer/msix/AppxManifest.xml.in`; built with `makeappx pack` (SDK tool, build-time) and signed with the
  same certificate as the binaries — the manifest `Publisher` must equal the certificate subject, so the package
  cannot exist without the certificate.
- **Flavours:** only `x64-modern` and `arm64` carry it (Windows 11 exists only on x64 and ARM64, and setup always
  picks `x64-modern` there). The shell DLL in the package must match Explorer's architecture.
- **Registration** (Windows 11 build 22000+ only; on Windows 10 nothing is registered and the classic handler
  is used):
  - per-user install: setup calls `PackageManager.AddPackageByUriAsync` with `ExternalLocationUri` (Windows 10
    2004+ API) for the current user;
  - per-machine install: the MSI does not register it (no supported MSI table for packages, and we avoid
    custom actions that would run as SYSTEM). The agent registers the package for each user at its first start
    after an install or update (the code of the hook `modern-menu --apply`, 03 §6.1, idempotent: compares the
    registered package version with its own);
  - the classic `IContextMenu` registration stays in place on every OS; on Windows 11 with the package
    registered, the shell DLL suppresses duplicate classic items **[lab-verify]** the exact behaviour with 03.
- **Update:** each release has a new package version whose external location points to the new versioned
  shell-extension directory; the agent re-registers after an update (§6.9 step 4).
- **Removal:** per-user uninstall removes the user's registration; per-machine uninstall runs
  `modern-menu --revert` elevated with `RemovalOptions.RemoveForAllUsers` (§6.7).
- WinRT calls (`PackageManager`) are made from C through `RoActivateInstance` and the raw ABI vtables, resolved
  dynamically from `combase.dll` (Windows 8+), so binaries keep running on older OS versions.

---

## 11. CI on GitHub Actions

### 11.1 Runners

- **`windows-2022`** (VS2022 17.14, SDKs 17763/19041/22621/26100, VC.Tools.ARM and ARM64 present, WiX
  3.14.1, LLVM 20, WSLv1 enabled, Docker for Windows containers)
  ([runner README](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md)).
  It does **not** include the WinXP/v141 components → each XP build job installs them:
  `vs_installer.exe modify --installPath "<VS path>" --add Microsoft.VisualStudio.Component.WinXP
  --add Microsoft.VisualStudio.Component.VC.v141.x86.x64 --quiet --norestart --nocache` (pattern confirmed working
  on this image in [runner-images #6067](https://github.com/actions/runner-images/issues/6067)). Expect several
  minutes per job; the step is a composite action `.github/actions/setup-xp-toolset` with a verification that
  `Microsoft.Windows.XPSupport.*` packages exist.
- `windows-latest`/`windows-2025` moved to VS2026 in mid-2026 and the `windows-11-arm` image migrated to VS2026
  in September 2026, dropping ARM32 tools
  ([report](https://ecorpit.com/github-actions-windows-11-arm-vs2026-migration-september-2026/)). **We pin
  `windows-2022` for all builds** and never use `-latest` labels.
- `windows-11-arm` (Arm64 hosted runner): used **only to run ARM64 tests** of binaries built on
  `windows-2022`. Standard ARM64 runners became GA for public repos in Aug 2025
  ([GitHub changelog](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/));
  the current docs list `windows-11-arm` for private repos as well, billed per minute
  ([GitHub docs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)). If unavailable
  for our plan, the ARM64 test job moves to the lab.
- **Exit plan** when `windows-2022` is retired: a self-hosted runner VM built from `.vsconfig` (VS2022 Build
  Tools 17.14 + components), registered with the labels `sd-build`. The workflow uses
  `runs-on: ${{ vars.SD_BUILD_RUNNER || 'windows-2022' }}` so switching is one variable.

### 11.2 Workflows

`ci.yml` (push, PR):

| Job | Runner | Steps |
|---|---|---|
| `build` matrix `{x86-ia32, x86-sse2, x64-xp, x64-modern, arm32, arm64}` | windows-2022 | setup-xp-toolset (v141_xp flavours only) → `cmake --preset` → build Release+Debug → `sd-importcheck` (flavour floor list, CFG/CET bits) → `sd-isacheck` (`x86-ia32` only) → `sd-ctcheck` (all flavours; on `x86-ia32`, `x86-sse2` and `arm32` it also fails on any compiler runtime helper call such as `_allmul`/`_aullmul` from constant-time code, 01 §2.7.5, TM-R02; M0 gate, TST-03) → upload `bin-<flavour>` artifact. `arm32` is `continue-on-error` only if the maintainer marks ARM32 as dropped (D5) |
| `analysis` | windows-2022 | `x64-analysis` preset: `/std:c11` build of everything, `/analyze`, ASan unit tests |
| `l10n` | windows-2022 | `sdl10n --check`: completeness in all six locales, placeholder sets, CLDR plural categories per locale, no plural messages in `.wxl`/ADML subsets, register lint (D26, C41) |
| `unit-x86` matrix `{x86-ia32, x86-sse2}` | windows-2022 | download artifact → run `sd-test-*.exe` under WOW64 (CTest, JUnit XML). The IA32 run covers the scalar crypto paths; the SSE2 run additionally forces each SIMD path off and on (`SD_CPU_MASK`) |
| `unit-x64` matrix `{x64-xp, x64-modern}` | windows-2022 | same; `x64-modern` also runs with process mitigation policy for CET shadow stacks requested **[verify]** whether the runner CPU/OS enforces it (the lab covers it otherwise) |
| `crypto-diff` | windows-2022 | D1/D2: `sd-test-crypto --diff-cng` on `x64-modern` and `x86-sse2`: randomized differential tests of our SHA-2/HMAC, AES-CTR/GCM, ECDH/ECDSA P-256/384/521, RSA, X25519/Ed25519 (where CNG has them) against CNG, plus all Wycheproof and RFC vectors. CNG is a reference only, never linked into shipping code paths for hashes |
| `unit-arm64` | windows-11-arm | same as `unit-x64` for `arm64` (+ `crypto-diff` on ARM64). **Not yet in CI:** the `build` matrix entry for `arm64` is build-only (Release and Debug cross-compiled on windows-2022, no `ctest` step, because the test binaries cannot run there); this job is the one that runs them, once the windows-11-arm runner is in use (M6, §1.1). |
| `integration` | windows-2022 | §11.3 (runs `x64-modern`; a reduced auth/transfer set also runs `x64-xp` and `x86-sse2`) |
| `package` | windows-2022 | needs build: Dokany files verified against `dokany.lock` (size, SHA-256, signer; at embed time, also when served from the cache, TM-R23) → payload CABs (six flavours) → six MSIs (WiX 3.14, ICE validation) → `sd-msilang` transforms → `sd-msilang --dump-sequences` custom-action condition check (TM-R35, §8.3) → sparse MSIX (only with `SD_SPARSE_MSIX=ON`) → setup EXEs with a test-key payload-table signature → test-sign → `sd-release manifest --unsigned` → artifacts |
| `release-checks` | windows-2022 | TST-30 on every Release build: no `none` cipher or test-only flags, no fuzz hooks, no test certificates or test keys (only `installer/keys/` public keys), no `__DATE__`/`__TIME__` strings; `sd-importcheck --stub` (KnownDLLs-only imports, no delay-load, TM-R33) |
| `workflow-lint` | windows-2022 | TM-R39/TST-32: every `uses:` is a first-party (`actions/*`) or in-repo (`./.github/actions/*`) action pinned by a 40-hex commit SHA; no `pull_request_target`; every workflow declares top-level `permissions: contents: read` and widens only per job; `release.yml` and `resign.yml` contain no `actions/cache` and no restore of other workflows' artifacts; `CODEOWNERS` covers `.github/` and `installer/` |
| `install-smoke` | windows-2022 | silent per-user install/upgrade/uninstall, per-machine MSI install/upgrade/uninstall (service on by default, then `SERVICE=0`); universal EXE (expects `x64-modern` on Server 2022), `/flavour=x64-xp`, `/flavour=x86-sse2`; same-version flavour switch `x64-xp` → `x64-modern` MSI; language transform selection for es-AR (11274) and pt-PT (2070); `DOKANY=0` / `/dokany=skip` writes the WebDAV-only default; per-machine uninstall removes `service\secrets\`/`service\keys\` by default and keeps them with `REMOVESECRETS=0`, and the uninstall log lists what was kept (TM-R28); `%ProgramData%\LibreStatic\ShellDrive` pre-created by a non-admin test account is renamed aside before any file is written (TM-R34, reduced TST-29); Dokany install optional step **[verify drivers can be installed on hosted runners]** |

`ARM32` binaries cannot run on any hosted runner (Windows 11 24H2+ ARM64 images no longer run ARM32), so ARM32
tests run only in the lab.

`fuzz.yml` (nightly + manual): v143 x64 `/fsanitize=fuzzer,address` targets — SSH packet/binary-packet
parser, KEX message decoders (including ML-KEM/`mlkem768x25519-sha256` messages), public/private key file
parsers (OpenSSH, PEM/PKCS#8, PPK v2/v3), `known_hosts`, SFTP reply decoder, WebDAV/HTTP request parser + XML
body parser, release manifest parser, CAB payload table, PO parser of `sdl10n`. Each target runs 10 min
nightly; corpus cached (`actions/cache` keyed by target + week) and minimized weekly; crashes uploaded as
artifacts and fail the job. PRs run each target for 60 s on the seed corpus. An optional Linux fuzz job
(test infrastructure only, D21) may run the `sd_base`/`sd_crypto` targets that need no `windows.h`.

`ct.yml` (nightly, D1): dudect-style constant-time timing tests of the field arithmetic (curve25519, P-256,
P-384, P-521), bignum modular exponentiation, ML-KEM decapsulation, AES (table-free paths) and MAC
comparisons, on `x86-ia32`, `x86-sse2`, `x64-modern` and `arm64` builds. Hosted runners are noisy, so a
failure triggers a rerun on the lab's dedicated machine before it is reported; results are trended, and a
confirmed leak blocks the next release.

`release.yml` (tag `v*`): §12.3. `lab.yml`: dispatched to the self-hosted lab runner (§11.4). `resign.yml`
(scheduled every 14 days, TM-R36): re-signs the current beta manifest with a new serial and `expires` using the
`beta-signing` environment, and opens a maintainer issue for the stable re-signing (offline key, §12.3) when the
stable manifest has 16 days or less left.

Caching: no package downloads exist for our own code; caches are used for fuzz corpora, the WSL fixture rootfs
tarball, Dokany MSIs (key = hash of `dokany.lock`; their hash is verified when used, TM-R23), and CMake build
trees for PRs only. **`release.yml` reads no cache at all** (TM-R39): it downloads Dokany files fresh and checks
them against `dokany.lock`.

**Workflow hardening (TM-R39, T-72).** Only first-party Actions pinned by commit SHA (updates by reviewed PR
only); minimal `GITHUB_TOKEN` permissions (`contents: read` by default; only the job that creates the draft
release gets `contents: write`, only `resign.yml` gets `issues: write`); release tags are signed (`git tag -s`)
and protected (only the maintainer may create `v*`), and `release.yml` verifies the tag signature against the
maintainer key in the repository before building; `CODEOWNERS` requires maintainer review for `.github/`,
`installer/`, `cmake/SdSign.cmake` and `tools/sd-release/`; signing secrets live in protected environments with
a required reviewer. Integration fixtures (WSL rootfs, `sshd`, litmus) and the lab run in jobs with a read-only
token whose outputs are test reports only — release artifacts come exclusively from the build and package jobs
and are never re-uploaded by a test job. The self-hosted lab runner (§11.4) accepts only `lab.yml` on `main`
and tags (no PR or fork workflows).

### 11.3 Integration tests

- Fixture: **OpenSSH `sshd` inside WSL** on the Windows runner (WSLv1 is enabled on `windows-2022`; WSLv2 on
  2025 images). A pinned Ubuntu rootfs tarball is imported with `wsl --import`, `openssh-server` installed
  (cached), and several `sshd` instances started on different ports with configurations from
  `tests/integration/fixtures/`: modern-only, legacy-enabled (ssh-rsa, group14-sha1, aes-cbc, hmac-sha1),
  password, keyboard-interactive with a PAM OTP stub, certificate authority, `ProxyJump` chain (three sshd
  instances), chroot SFTP. Fixtures are test-only; nothing from them ships.
- Fallback fixture: Windows' own OpenSSH Server capability (`Add-WindowsCapability -Online -Name
  OpenSSH.Server~~~~0.0.1.0`) for basic connect/auth tests when WSL is unavailable.
- Tests are CTest cases calling `shelldrive.exe` and test executables linked against `sd_ssh`/`sd_sftp`:
  connect, auth matrix, host-key TOFU/mismatch, SFTP operations, reconnect after `kill -STOP`/`kill` of the
  server, large file transfer with hash compare.
- WebDAV server: tested via HTTP against `sd_webdav` (our own client tests + litmus run inside WSL against
  `127.0.0.1`). The **Windows WebDAV redirector** cannot be enabled on Server runners without a reboot (it is
  an optional feature) → redirector tests run in the lab.
- Dokany: if driver install on hosted runners works, a job installs the pinned Dokan MSI and runs the Dokany
  adapter tests; otherwise lab only.

### 11.4 Test lab for XP/Vista/7/8.1/non-SSE2/ARM32 (self-hosted)

GitHub-hosted runners cannot run these OSes. A lab host (developer workstation with Hyper-V, or a Linux box with
QEMU/KVM; the non-SSE2 VM needs QEMU) runs a self-hosted GitHub runner labeled `sd-lab` and these VMs, each with a clean snapshot
`base` (and `base-sha2` where relevant). OS media/licenses are supplied by the maintainer; no images are stored
in the repository.

| VM | Flavours exercised | Purpose |
|---|---|---|
| XP SP3 x86 (no post-SP3 updates) | `x86-sse2`, `x86-ia32` | Minimum OS: WebDAV backend, per-user + MSI, updater over HTTP |
| **XP SP3 x86 on QEMU `-cpu pentium3`** (no SSE2; Hyper-V cannot mask SSE2) | `x86-ia32`, setup stub, `uninstall.exe` | D4/C35: universal stub picks `x86-ia32`; `x86-sse2` binaries refuse cleanly via the entry thunk; full smoke incl. crypto KATs; also the authoritative check behind `sd-isacheck` |
| XP x64 SP2 | `x64-xp`, `x86-sse2` shell DLL | x64 v141_xp binaries, subsystem 5.02 |
| Vista SP2 x86 | `x86-sse2` | UAC elevation, RM, no TLS 1.2 |
| 7 SP1 x64 without updates / with KB4474419+KB4490628+KB3140245 | `x64-xp` | Dokany SHA-2 gating, WinHTTP TLS 1.2 path, Dokany VC++ dependency on a clean OS (C31) |
| 7 SP1 x86 updated | `x86-sse2` | Dokany x86 |
| 8.1 x64 | `x64-xp` → in-place upgrade to 10 → `x64-modern` | Middle ground; flavour switch by the updater |
| 10 22H2 x86 | `x86-sse2` | Last x86 Windows |
| 10 LTSC 2021 x64, 11 25H2 x64 (memory integrity ON, SAC evaluation, hardware-enforced stack protection where the host CPU supports CET) | `x64-modern`; `x64-xp` forced | Modern, HVCI-Dokany check, CET strict mode, Windows 11 sparse MSIX (when signed), Network Shortcuts |
| Server 2022 x64 (Secure Boot) | `x64-modern` | Global mounts via service (on by default, D6), attestation-vs-WHQL check, D11 spike |
| 11 ARM64 (on ARM64 hardware host or QEMU TCG) | `arm64`, `x86-sse2` and `x64-modern` shell DLLs | ARM64 native + x86/x64 shell-ext in dialogs, sparse MSIX on ARM64 |
| 10 ARM64 22H2 or 11 23H2 ARM64 | `arm32` (EXE and MSI) | **ARM32** binaries (24H2+ no longer runs ARM32 apps — [report](https://elevenforum.com/t/microsoft-removed-support-for-arm32-uwp-apps-in-windows-11.16335)); ARM32 MSI install folder and `Arm` template acceptance (§5.1) |
| Windows RT 8.1 device (if one is available) | `arm32` MSI | Only to confirm `msiexec` presence and our RT refusal; our code cannot run there |

Windows RT 8.1 runs only Microsoft-signed desktop code, so it is "not runnable" rather than tested. ARM32
"best effort" in practice means Windows 10 on ARM64 and Windows 11 up to 23H2 (§5.1).

**Security lab runs (05 §7).** The lab also runs the threat-model tests that need real OS versions:

| Test | Milestone / priority | VMs | What |
|---|---|---|---|
| TST-29 installer elevation | M4, P1 | XP SP3, 7 SP1, 10, 11 | Procmon "NAME NOT FOUND" capture in the stub's directory for setup, both elevated stages, `uninstall.exe` and the update path; planted-DLL canaries (`version.dll`, `cryptbase.dll`, `uxtheme.dll`, `dwmapi.dll`, `cabinet.dll`, `msi.dll`…) in `Downloads`, `%TEMP%` and the update staging folder must never load in an elevated process (TM-R33); `%ProgramData%\LibreStatic\ShellDrive` pre-created by a standard user (owner, DACL, junctions, pre-seeded `settings.ini`/`profiles\`) before install and before service start (TM-R34); `msiexec /fa` and `/fu` as a standard user under Procmon: no SYSTEM process touches a user-writable path (TM-R35); Dokany MSI with wrong hash or signer refused (TM-R23) |
| TST-27 uninstall residue | M4, P2 | 7, 10, 11 | per-user and per-machine (setup, ARP, `msiexec /x`, SYSTEM/Intune), with and without "remove data"/`REMOVESECRETS=0`; list every remaining secret, cache and registry value and compare with §6.7 and the uninstall summary (TM-R28) |
| TST-31 updater | M4, P1 | XP SP3 (HTTP), 7, 11 | against a lab mirror: tampered manifest/file, replayed old manifest, expired manifest, beta-signed manifest on stable, beta serial poisoning, keyset rollback, revoked key, key rotation across two keysets, redirect to a foreign host, oversized responses, interrupted downloads, stale-information warning after 14 days (TM-R36, TM-R37) |
| TST-32 provenance | M4, P2 | dedicated clean build VM (not a runner) | the maintainer's independent rebuild of the release tag (§12.3) and hash comparison with CI |
| TST-19/TST-26 | M0/M5 | as listed in 05 §7 | Dokany isolation and global WebDAV criteria (owned by 02, run here) |

**D11 spike (early M5, go/no-go per OS):** on XP SP3, Server 2022 and Windows 11, check whether a WebDAV
mapping made by the LocalSystem-hosted service can be made visible to all users. The result is recorded per OS
in the lab inventory; a "no-go" OS falls back to per-user attach at logon (02/03). Packaging is not affected
either way.

**Smoke harness (works from XP to 11, no PowerShell in the guest):**

1. Host (`tests/lab/Invoke-SdLab.ps1`): restore snapshot (`Restore-VMSnapshot` / `virsh snapshot-revert`),
   build an ISO with the artifacts + `smoke.cmd` (IMAPI2 COM on Windows hosts, `xorriso` on Linux hosts — the
   host is a test fixture), attach it, boot.
2. Guest: an autologon account has a `Startup` entry that runs `D:\smoke.cmd` if present.
3. `smoke.cmd` (cmd.exe only) runs `setup.exe /quiet /peruser /log=…`, then `shelldrive selftest --json`
   (C2/C7; our CLI does the heavy checks: flavour and its CPU/OS floor, imports, crypto KATs, CNG presence,
   WebClient state, Dokany detection), mounts a profile against the lab's sshd VM via WebDAV (and Dokany where
   available), writes/reads/hashes a file, upgrades to the "next" build, uninstalls, repeats with
   `/permachine` (checking that the service is installed and running by default) and, on the VMs listed with
   two flavours, with the second flavour forced.
4. Results are written to **COM1**, which the host maps to a named pipe (Hyper-V `Set-VMComPort`) or a file
   (QEMU `-serial file:`), so no network shares or guest integration services are needed (XP has none on
   modern Hyper-V). The host parses the JSON lines, attaches logs, and reverts the snapshot.

The lab job is mandatory for releases (§12.3) and runs weekly on `main`. With six flavours the full lab pass is
roughly twice the earlier matrix; the weekly run may rotate the forced second flavours, the release run never
does.

---

## 12. Versioning, reproducible builds, release process

### 12.1 Versioning

- `VERSION` file holds `MAJOR.MINOR.PATCH` (SemVer). Pre-releases: `1.1.0-beta.2` (tag `v1.1.0-beta.2`, beta
  channel).
- Windows `FILEVERSION`/`PRODUCTVERSION`: `MAJOR.MINOR.PATCH.BUILD`, `BUILD` = GitHub run number for CI builds,
  `0` for local builds. Release builds use the tag; `version.h` also carries the git commit (12 hex) and a
  `SD_BUILD_DIRTY` flag.
- MSI `ProductVersion` = `MAJOR.MINOR.PATCH` (§8.2). Manifest `serial` = `YYYYMMDDnn`.
- IPC/protocol/config-format versions are independent integers owned by their teams.

### 12.2 Reproducible builds

Goal: two clean builds of the same tag on the pinned toolchain produce byte-identical unsigned PEs, CABs, MSIs
(all six flavours) and, when built, the unsigned sparse MSIX.

- Compiler/linker `/Brepro` (undocumented but supported since VS2015; replaces timestamps with content hashes).
  **[verify]** in the v141 14.16 toolset — fallback is a post-link tool that zeroes `TimeDateStamp`/debug
  directory timestamps deterministically.
- `/PDBALTPATH:%_PDB%` so no absolute build paths are embedded in PEs; builds run from a fixed path
  (`subst S: <workspace>`) so `__FILE__` and PDB source paths are stable. No `__DATE__`/`__TIME__` (a CI grep rejects them).
- Resource compiler, `makecab` (fixed `.Set` directives, sorted inputs, `SOURCE_DATE_EPOCH`-derived file
  times), WiX (fixed `PackageCode` derived from a hash of version+arch instead of random) **[verify]** WiX determinism; if `light` embeds timestamps, the summary-info times are set from
  `SOURCE_DATE_EPOCH` in a post-step with `MsiSummaryInfoSetProperty`.
- Toolchain fingerprint (`cl.exe`/`link.exe` versions, SDK versions, WiX version, CMake version) is recorded in
  `build-info.txt` inside the symbols zip.
- `release.yml` builds twice on two runners and compares SHA-256 of all unsigned outputs; signing happens only
  after the comparison passes. Authenticode signatures are excluded from comparison (`signtool remove /s` for
  verification by third parties).
- The double CI build proves **determinism, not provenance** (T-72): both runs use the same workflow, Actions,
  runner image and provider, so a compromise there yields identical malicious outputs. Provenance comes from
  the **maintainer's independent rebuild** (TM-R39, TST-32): before any stable signing, the maintainer builds
  the signed tag from a clean checkout on a separate machine that is not a GitHub runner (the lab's dedicated
  build VM restored from a clean snapshot, or another clean machine), with the toolchain installed from the
  privately archived VS layout pinned by `.vsconfig` (§15 R1), running the same CMake presets and packaging
  steps as CI by hand (no GitHub Action involved; the only downloads are the pinned Dokany files, checked
  against `dokany.lock`), and compares the SHA-256 of every unsigned output and the toolchain
  fingerprint in `build-info.txt` with the CI draft. Any difference stops the release.

Local check (M4): `tools/check-repro.ps1 -Preset <preset>` builds the preset twice in `build\repro-a\<preset>` and
`build\repro-b\<preset>`, both from the same source through a `subst` drive (so `__FILE__` and source paths match), with
`--config Release`, and compares byte for byte: `bin\Release\*.exe`, `*.dll`, `lib\Release\*.lib` and
`generated\policy\**` (ADMX, ADML, policy headers). It exits 1 and names each differing file. PDBs are not compared
(they hold build-directory object paths; each PE carries only the PDB name through `/PDBALTPATH`). The check is the
opt-in CTest `repro.<preset>` (label `repro`, excluded from the default run with the matrix, bench and interop labels).
Shipping code must not use `__DATE__`, `__TIME__`, `__TIMESTAMP__` or `__FILE__` (none is used today).

### 12.3 Release process

**Release gates (D38, TM-R38, D29).** Each gate is a checklist item in the release PR and is checked by
`release.yml` against a `release-gates.txt` record in the repository (maintainer-edited, CODEOWNERS-protected):

| Distribution | Requires |
|---|---|
| Named testers (private) | Lab pass; interim rules of §10 while unsigned; before crypto pass 1, the "not yet externally reviewed" notice |
| **Public beta** (public links, public beta manifest) | External crypto review **pass 1** (end of M2: all SSH and crypto code, D38) completed and its findings closed; **and** Authenticode signing in place (TM-R38: no public download links for unsigned builds) |
| **1.0 and later stable** | Crypto review **pass 2** closed (D38, TST-33); certificate (D29); all P3 tests of 05 §7; independent maintainer rebuild (TM-R39) |

**Steps**

1. Bump `VERSION`, update `CHANGELOG.md`, PR, merge to `main`.
2. Push a **signed** tag `vX.Y.Z` (protected; only the maintainer).
3. `release.yml` (pinned Actions, no caches, minimal permissions, §11.2): verify the tag signature → double build
   + compare → unit/integration → package with **unsigned payload tables** → lab smoke (all VMs) → draft
   artifacts plus `payload-tables.txt` (the payload table of every setup EXE).
4. Maintainer, independent rebuild (stable only, TST-32): rebuild the tag outside GitHub as in §12.2 and compare
   all unsigned outputs with the draft; stop on any difference.
5. Maintainer, offline signing session 1 of 2 (stable, D42): verify `payload-tables.txt` against the rebuilt payloads with
   `sd-release verify`, sign them with the `release-stable` key, upload the signatures.
6. `release.yml` job `finalize` (manually approved environment): insert the `PAYLOAD_SIG` resources →
   Authenticode signing (when configured, protected environment) → `SHA256SUMS`, unsigned `manifest.txt`
   (`expires` ≤ 30 days, `keyset` = current) → **draft** GitHub release with all artifacts + Dokany source mirror.
7. Maintainer, offline signing session 2 of 2 (D42): verify `manifest.txt`/`SHA256SUMS` against the draft assets with
   `sd-release verify` (which also checks that each setup EXE, after `signtool remove /s` and removal of
   `PAYLOAD_SIG`, equals the rebuilt one from step 4), sign with the `release-stable` key, upload
   `manifest.txt` (signed) and `SHA256SUMS.sig`.
8. Publish the release; the workflow `publish-mirror` copies the identical files to the HTTP mirror.
   Updating the channel manifest pointer (`stable/manifest.txt`) is the last step. If the keyset changed, the
   root-signed `keyset.txt` is published to every base before the manifest that names it.
9. **Re-signing (TM-R36):** every 14 days the current manifest of each channel is re-signed with a new serial and
   a new `expires`, content otherwise unchanged: beta by `resign.yml`, stable by the maintainer offline
   (`sd-release resign`, prompted by the `resign.yml` issue), then uploaded to both bases.
10. Beta channel: steps 3–8 automated with the CI-held `release-beta` key behind the `beta-signing` environment
    (no independent rebuild required, but public betas still need the gates above).
11. Key ceremony (rare): keyset changes are signed offline with a root key (both roots for root changes) and
    committed to `installer/keys/keyset.txt` for future builds.

Hotfix: branch `release/X.Y` from the tag, cherry-pick, tag `vX.Y.(Z+1)`.

---

## 13. Logging and diagnostics for install/update

- Setup log: `%TEMP%\ShellDrive-setup-<timestamp>.log` (or `/log`), English, includes OS version, native arch
  detection path taken, mode, every file operation, MSI/Dokany exit codes; MSI verbose log beside it.
  The log records the flavour decision (SSE2 test result, `RtlGetVersion` result, `/flavour` override), the
  Dokany redistributable form used, and the MSI `TRANSFORMS` passed.
- Updater log entries go to the agent log (format owned by 03, `sd_log` component `upd`) with stable English
  event IDs (`update.check`, `update.verify_failed`, `update.applied`, `update.rolled_back`,
  `update.flavour_switch`, `update.keyset_updated`, `update.key_revoked`, `update.channel_mismatch`,
  `update.expired`, `update.stale`).
- Setup security events (English, setup log and, per machine, the Application Event Log): `setup.programdata_untrusted`
  (folder renamed aside, previous owner SID), `setup.payload_sig_invalid`, `setup.dokany_verify_failed`
  (hash or signer), `setup.dokany_denied`, and the uninstall summary of kept items (§6.7).
- `shelldrive diag --bundle` (03; replaces the earlier `diag collect` name, C7) includes the latest setup/update
  logs.

---

## 14. Contracts with other teams

**All teams**
- Code compiles under v141 C (§2.3) and builds in all six flavour presets; post-XP APIs only through
  `sd_platform_resolve` (§2.4); the import audit is a build failure, not a warning.
- No `__declspec(thread)` in anything linked into a DLL; no cross-module CRT frees; allocation through
  `sd_alloc` (§2.4).
- No third-party source in any shipping target (D1, §4).
- Code is CET-compatible (§3.2), because the same sources build `x64-modern`.
- Every user-facing string, including installer and updater dialogs, exists in all six locales, in PO only,
  with full CLDR plural categories (D26, §8.6).

**Crypto/SSH core (01)**
- `sd_crypto` exports `sd_ed25519_verify` and `sd_sha256_*`/`sd_sha512_*` with no dependency on CNG (the setup
  stub and updater run on XP). `sd_ed25519_sign` is needed only by `tools/sd-release`.
- Portable scalar implementations of everything (they are the only code in `x86-ia32`); SIMD/SHA-NI/AES-NI
  paths in separate source files that the `x86-ia32` preset excludes, selected at run time elsewhere (D4).
- A CNG differential-test mode in `sd-test-crypto` (`--diff-cng`) and dudect-style timing tests (§11.2, D1/D2).
- Fuzz entry points (`LLVMFuzzerTestOneInput`) for parsers listed in §11.2 live in `tests/fuzz/`.
- 01 §12.1 refers to §3.2 for all compiler/linker flags (C36).
- `sd_ed25519_verify` with domain-separated messages is also used for `keyset.txt` and the payload table
  (§6.1, §9.3); the code it pulls into `sd_stubcore` stays free of non-KnownDLL imports (TM-R33).
- External review in two passes (D38): pass 1 at the end of M2 (all SSH and crypto code) gates public betas,
  pass 2 before 1.0 (§12.3).

**Filesystem team (02)**
- Declare the minimum Dokany API version in `installer/dokany/dokany.lock`; load `dokan2.dll` dynamically and
  degrade to WebDAV when missing/too old; own ABI declarations in `src/sd_dokan/dokan_abi.h` (C38).
- `webdav-tune` sets only the two values in §8.3 (C28); never `BasicAuthLevel`.
- 02 §6.1/§6.3 refer to §7.2/§7.3 for SHA-2 detection, the upgrade decision table and the redistributable form
  (C31, C32, D32).
- Honor `dokany-deny` from the last verified manifest (warn, disable the Dokany backend; TM-R23) and the
  machine default `[backend] dokany = no` written by `DOKANY=0` (D36).
- Refuse the disk cache on volumes without `FILE_PERSISTENT_ACLS` (TM-R29, §6.8).

**Apps team (03)**
- Each agent creates and waits on `Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>` (manual-reset, DACL in
  §6.9) and exits cleanly within 15 s after telling its UI clients to exit (C3; specified in
  03 §1.2 and §12.3, which never enumerate or connect to agent pipes).
- Service: `shelldrive-host.exe service`, name `ShellDriveSvc`; listen to SCM stop; set its own failure
  actions and localized description (C44); installed and enabled by default per machine (D6).
- `shelldrive-host.exe --selftest` (exit 0 = healthy) and `shelldrive selftest --json` (C2); hidden
  `shelldrive-host.exe --installer-hook <webdav-tune|user-cleanup|modern-menu|signal-shutdown> --apply|--revert`
  (names and semantics owned by 03 §6.1); `update check|apply`,
  `diag --bundle`, `diag --fix webclient` (C7).
- Update settings in `settings.ini [update] enabled, channel, manifest_url`; in `state\`:
  `last_serial.<channel>`, `last_verified.<channel>`, `keyset` and the cached `dokany-deny` list (TM-R36,
  TM-R37); policies in `HKLM\Software\Policies\LibreStatic\ShellDrive` (C8, §9.1). UI notice `warn.update_stale` (03 §9.6)
  after 14 days (TM-R36).
- New installer hook `programdata-secure` (TM-R34, §8.3) in 03 §6.1's list; the hook host's SYSTEM-mode rules
  of §8.3 (no user configuration, no environment-relative paths, no window, no child process; TM-R35); 03 §3.2
  states that setup creates or resets `%ProgramData%\LibreStatic\ShellDrive` with its DACL before use (§6.4).
- Settings key `[backend] dokany = yes|no` in the machine `settings.ini` (D36, §8.4).
- Portable mode: one-time warning on volumes without persistent ACLs (TM-R29, 03 §1.9).
- Per-machine uninstall removes `service\secrets\` and `service\keys\` unless `REMOVESECRETS=0`; caches are
  always removed; the host deletes caches of deleted profiles at start (TM-R28, §6.7).
- Portable detection via `sd_platform_is_portable()` and `shelldrive.portable`.
- Shell extension: DLL may be loaded from `shellext\<version>\`; the `Local\com.librestatic.shelldrive.state.<SID>` layout is
  versioned and architecture-independent and `--action` verbs are additive only (C5); registration is declared
  in `installer/registry/*.tbl` (no self-registration at install time); `IExplorerCommand` implementation for
  the sparse package (D27, §10.1); `DllMain` refuses to load an `x86-sse2` DLL on a non-SSE2 CPU (§3.2).
- Network Shortcuts (D14): created per user at run time under `CSIDL_NETHOOD` with the `desktop.ini` marker
  `[ShellDrive] profile=<id>` (03 §8.7); reconciled at agent start and removed by `user-cleanup` (§6.7).
- `DEFAULTPROFILES` is a folder of `.ini` profiles copied to `%ProgramData%\LibreStatic\ShellDrive\profiles\` (C9).
- `tools/sdl10n` emits C tables, STRINGTABLEs, `.wxl`, ADML and the LCID lists used by `sd-msilang` (C41, C43).

---

## 15. Risks and open questions

| # | Risk / question | Mitigation / next step |
|---|---|---|
| R1 | v141_xp is deprecated; could disappear from the VS installer or the `windows-2022` image could be retired | Pin VS2022 17.14 via `.vsconfig`; offline layout (`vs_buildtools --layout`) archived privately; self-hosted runner switch (§11.1) |
| R2 | ARM32: SDK 22621 is the last with libs, VS2026 dropped ARM32, Windows 11 24H2+ can't run ARM32, RT runs no third-party code | ARM32 stays "best effort" (D5) with an EXE and an MSI (D31) for Windows 10 on ARM64 / Windows 11 ≤ 23H2; dropped from a release as soon as the toolchain breaks |
| R3 | Dokany driver signature type and HVCI compatibility unknown | Lab checks §7.2; skip Dokany cleanly when it would not load |
| R4 | Unsigned binaries blocked by Smart App Control; SmartScreen warnings train users to click through, so look-alike installers are indistinguishable (T-71); the sparse MSIX (D27) cannot exist without a certificate | Certificate from SignPath Foundation, else Certum OSS, obtained before public 1.0 (D29); until then no public links, named testers, signed `SHA256SUMS`, payload-table signature check (TM-R38, §10); without it 1.0 ships the classic menu only |
| R5 | XP root store and SHA-1 timestamping availability for dual-signing | Verify with the chosen CA; XP users may see "unknown publisher" — acceptable |
| R6 | WiX 3.14 out of support; ARM64 support in 3.14 had bugs; ARM32 (`Arm` template) support in 3.14 unverified | No WiX custom actions, explicit InstallerVersion, ICE validation; migrate to v6+ (accept EULA/OSMF terms) if 3.14 breaks; MSI-from-`msi.dll` fallback (the same code as `sd-msilang`) |
| R7 | HTTP mirror long-term cost | Static object storage with plain HTTP (D30); signature makes any provider safe |
| R8 | Driver installs (Dokany) and WSL may not work on hosted runners | Lab coverage is the fallback; CI marks those jobs optional |
| R9 | `/Brepro` and WiX determinism on v141 | Verify early; post-processing fallback (§12.2) |
| R10 | Six flavours roughly double build, test and lab time (D4, D28) | Flavours share all source; CI runs all six on every PR for build + unit, the full integration set only on `x64-modern`; lab rotates second flavours weekly, never for releases |
| R11 | Own crypto, including field arithmetic, bignum and ML-KEM, with no vendored verified code (D1) | Wycheproof + RFC vectors, CNG differential tests, fuzzing, nightly constant-time tests (§11.2), and an external crypto review in two passes as release gates: pass 1 at the end of M2 before any public beta, pass 2 before 1.0 (D38, §12.3) |
| R12 | `x86-ia32` correctness cannot be proven on hosted runners (all have SSE2, and SDE flags SSE2 inside Windows' own DLLs) | `sd-isacheck` static audit in CI; the QEMU non-SSE2 VM is mandatory in the release lab run |
| R13 | `dokan2.dll` may need the VC++ runtime (C31) | Lab check in the first week of M4; bundle form in offline EXEs and a documented prerequisite for MSI deployments (§7.3) |
| R14 | Network Shortcuts of other users survive a per-machine uninstall (D14) | Dead links only; host cleanup at start; documented (§6.7) |
| R15 | Update key management: stable releases need two offline signing sessions plus a re-signing every 14 days; a single compromised root key can still authorize a release key (keysets need one root signature, TM-R37) | Fixed calendar and `resign.yml` reminders; stable `expires` 30 days leaves 16 days of slack; roots on separate offline media in two locations, touched only for keyset ceremonies; a both-roots keyset replaces a compromised root (§9.3) |
| R16 | XP, Vista and 7 without KB2533623 have no `SetDefaultDllDirectories`; system code may still load a planted `uxtheme.dll`/`dwmapi.dll` from the download directory into the **unelevated** setup UI | No elevated instance ever creates UI or loads non-KnownDLL modules from there (two-stage elevation, §6.4); residual is same-user code execution only; TST-29 canaries on XP and 7 |
| R17 | A running same-user attacker can swap the setup image between the UAC prompt and stage 1's copy while binaries are unsigned | Payload-table signature limits it to another genuine build; closed by `WinVerifyTrust` in stage 2 once Authenticode exists (§6.4, D29) |
| R18 | GitHub Actions/runner-image compromise yields identical outputs in both CI builds (T-72) | Independent maintainer rebuild outside GitHub before stable signing, pinned first-party Actions, no caches in releases, CODEOWNERS, signed tags (TM-R39, §11.2, §12.2) |
| Q2 | Exact SHA-2 support detection method on Windows 7 for gating Dokany | Lab: compare `ci.dll` versions with and without KB4474419 |
| Q3 | Do x86 (and x64 on ARM64) shell-extension copies need registering for file dialogs of emulated/32-bit apps? | Lab test on x64 and ARM64; default yes on x64 |
| Q6 | XP ARP lists HKCU uninstall entries; HKCU COM shell extensions on XP | Lab verify; if not, per-user mode on XP registers only the Start-menu uninstall shortcut and no shell extension |

Former Q1 (second x64 flavour), Q4 (ARM32 MSI) and Q5 (sparse MSIX) are closed by D28, D31 and D27.

---

## 16. Changelog: integrated decisions

Applied from `decisions.md`: **D1** (zero third-party code, test strategy, `ct.yml`), **D2** (CNG only as
differential reference), **D3** (four binaries, `apps/` layout), **D4** (`x86-ia32` + `x86-sse2`, IA32 setup
stub selecting by SSE2, entry thunk), **D5** (ARM32 best effort, CLI + host + WebDAV), **D6** (service on by
default per machine, `SERVICE=0`, never per user), **D11** (lab spike only), **D12** (no Dokany fork), **D14**
(Network Shortcuts cleanup), **D20** (updater proxy scope), **D21** (Linux as test infrastructure), **D24**
(`ENABLELINKEDCONNECTIONS`), **D26** (full CLDR plurals in `sdl10n`, `.wxl`/ADML generation), **D27**
(conditional sparse MSIX, §10.1), **D28** (`x64-modern`, OS-based selection, shared UpgradeCode), **D29**
(certificate source), **D30** (static object-storage mirror), **D31** (ARM32 MSI and its limits), **D32**
(Dokany redistributable form); "Resulting build flavours" table (§1.1).

Applied conflict resolutions from `00-integration-review.md`: **C1**, **C2**, **C3** (shutdown event name,
DACL, Toolhelp32 discovery, no `Local\` fallback), **C4**, **C5**, **C6** (overridden by D6: default on),
**C7**, **C8** (update settings in `settings.ini`/`state\`, single policy key), **C9**, **C10**, **C11**,
**C27** (service global drives need Dokany), **C28**, **C31** (VC++ dependency check, via D32), **C32**,
**C34** (superseded by D4), **C35** (stub built from `x86-ia32`), **C36**, **C37** (superseded by D1: no
exception, amendment A6 dropped), **C38**, **C39**, **C40**, **C41**, **C42**, **C43** (transforms under every
LCID of a language, explicit `TRANSFORMS`), **C44**. Amendments A2, A4, A7 and A8 (as rewritten by D4) are
reflected. C12–C26, C29, C30, C33, C45 and C46 do not concern this document.

Final reconciliation 2026-10-24: installer hooks renamed to 03 §6.1's set (`webdav-tune`, `user-cleanup`,
`modern-menu`, `signal-shutdown`; `netshortcuts-remove`, `sparse-register`, `sparse-remove` dropped), always run
as `shelldrive-host.exe --installer-hook … --apply|--revert` (§6.7, §8.3, §10.1, §14); Network Shortcuts use 03's
`[ShellDrive] profile=` marker and no list file; the ADMX table in §8.4 lists every 03 §3.5 policy (incl.
`ProxyServer`, `AllowSystemProxy`, `UpdateHostKeys`, `ForceWriteThrough`, `DisableNetworkLocations`,
`DisableModernContextMenu`); §8.5 no longer says service global drives need Dokany (C27 is superseded by D11);
`webdav-tune` hint for per-user installs matches 02; sparse-package item types follow 03 §8.6. §3.2 already had
the two x86 flavours per D4 (only `x86-sse2` binaries carry the refusing entry thunk).

Threat-model integration 2026-10-24 (`05-threat-model.md` §8, as decided by D33–D39): **TM-R23** (Dokany
SHA-256 checked at embed and at install time, `WinVerifyTrust` + pinned signer name in `dokany.lock`,
`dokany-deny` manifest lines and decision-table row; §7.3, §9.2, §11.2), **TM-R28** (`REMOVESECRETS=1` default
removes `service\secrets\`/`service\keys\`, caches always removed, uninstall summary; §6.7, §8.4), **TM-R29**
(portable warning and cache refusal on volumes without persistent ACLs; §6.8), **TM-R33** (KnownDLLs-only static
imports enforced by `sd-importcheck --stub`, no delay-load, `SetDefaultDllDirectories` with `SetDllDirectoryW(L"")`
fallback on XP/Vista/7, full System32 paths, `/DEPENDENTLOADFLAG:0x800`, two-stage elevation that runs the
elevated work only from a copy in a fresh admin-only directory, `uninstall.exe` never elevated from `%TEMP%`,
`dokan2.dll` checked from the native host by full System32 path; §2.4, §3.2, §6.4, §6.7, §7.3, §9.6), **TM-R34**
(`%ProgramData%\LibreStatic\ShellDrive` owner/DACL/reparse check on the handle, rename-aside and fresh creation with an
explicit SD, also as the new MSI hook `programdata-secure`; §6.4, §8.3), **TM-R35** (normative custom-action
condition table, no SYSTEM action during repair except idempotent ones, SYSTEM-mode rules for the hook host,
CI dump of `InstallExecuteSequence`; §8.3), **TM-R36** (`expires` ≤ 30/14 days, re-signing every 14 days via
`resign.yml` and offline stable re-signing, "N days old" warning; §9.2, §11.2, §12.3), **TM-R37** (offline
root keys certifying per-channel release keys in a versioned, root-signed `keyset.txt` with rotation and
revocation, channel binding, `last_serial.<channel>`; §9.2, §9.3), **TM-R38** (no public links while unsigned,
named testers, signed `SHA256SUMS`, key fingerprints in the README, stub refuses an invalid payload-table
signature; §6.1, §10), **TM-R39** (first-party Actions pinned by SHA, minimal permissions, no caches in
releases, signed protected tags, CODEOWNERS, fixtures in read-only jobs, independent maintainer rebuild outside
GitHub before stable signing; §11.2, §12.2, §12.3). **D36** (TM-Q06): Dokany is an explicit, pre-checked
option on the per-machine page (7 SP1+) that explains the third-party kernel driver, with `/dokany=skip` and
the MSI property `DOKANY=0` meaning WebDAV only (§6.3, §6.5, §7.3, §8.4, §8.5). **D38** (TM-Q09): two-pass
crypto review as release gates, no public beta before pass 1 (§10, §12.3, §15 R11). Tests wired in: TST-27,
TST-29, TST-30, TST-31, TST-32 (§11.2 `package`, `release-checks`, `workflow-lint`, `install-smoke`; §11.4
security lab runs). New risks R15–R18. Items for other documents: 03 §6.1 (hook `programdata-secure`, SYSTEM
rules), 03 §3.2/§3.4 (`%ProgramData%` reset by setup, `[backend] dokany`, `state\` files), 03 UI string for stale
update information, 02 §6.3 (`dokany-deny`, `DOKANY=0`), 02 §4.2/03 §1.9 (TM-R29).

Final reconciliation (threat model) 2026-10-24: `sd-ctcheck` constant-time disassembly gate in the `build` job
and `tools/` (01 §2.7.5, TM-R02, TST-03; §4, §11.2); signing sessions labelled D42 (§12.3); staleness text is 03's
`warn.update_stale` (§9.2, §14); `webdav-tune` originals live in 03's `service\state\webdav-tune.ini`, not HKLM
(§8.3); `programdata-secure` is now in 03 §6.1. The items listed above for 02 and 03 are present there.

LibreStatic naming (D45) 2026-10-24: install dirs `%ProgramFiles%\LibreStatic\ShellDrive` and
`%LOCALAPPDATA%\Programs\LibreStatic\ShellDrive` (§6.3, §8.4); `%ProgramData%\LibreStatic` vendor folder checked
before `ShellDrive` (§6.4); `Publisher`/`Manufacturer`/`CompanyName` = `LibreStatic` (§1.1, §6.7, §8); registry
`Software\LibreStatic\ShellDrive` and `Software\Policies\LibreStatic\ShellDrive`, ADMX namespace
`com.librestatic.shelldrive.policies` (§8.4); manifest and keyset carry `product com.librestatic.shelldrive`, signing
domain strings and key labels use `com.librestatic.shelldrive` (§9.2, §9.3); URLs `github.com/LibreStatic/ShellDrive`
(§9.2, §9.4); shutdown event and snapshot names `Global\|Local\com.librestatic.shelldrive.*` (§6.9, §14).
