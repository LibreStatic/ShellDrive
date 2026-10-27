# M6 notes: ARM64 flavour

Scope of this branch (`wip/r6-arm64`): the `arm64` build flavour (04 §1.1, §2, §3, M6 in 00 §6). ARM32 (D5, D31) is not
in scope: SDK 10.0.22621 is not installed. Nothing here runs ARM64 code: this x64 machine cannot run ARM64 binaries, so
the ARM64 result is **build only**. The ARM64 tests are built but not run.

## Status

| Item | State |
|---|---|
| `cmake --preset arm64` / `arm64-debug` (v143, SDK 10.0.26100, `-A ARM64`) | builds, Release and Debug, no warnings (`/W4 /WX`), PE32+ `aa64` images |
| Build-time tools for the ARM64 tree | built by a nested x64 configure (`cmake/SdHostTools.cmake`) |
| Import audit | runs on every ARM64 image against `tests/os-imports/win10-arm64.txt` (bootstrap list) |
| ARM64 tests | built, **not run** (the `arm64` test preset selects no tests; CI and ci-local do not run ctest for it) |
| Setup stub and `shelldrive-setup.exe` for arm64 | built (native ARM64 stub, payload CAB of the ARM64 binaries) |
| Agent shutdown event | already created by the agent (see below); test `agent_shutdown_event_stops_agent` added |
| ci-local / CI | `arm64` is build-only in `tools/ci-local.ps1` (not in the default list) and in `ci.yml` |

Verified on this machine after the changes: `x64-modern` (Release and Debug, CTest suite with the 2 interop tests skipped as
before, since there is no WSL fixture), `x64-xp` Debug build, `x86-ia32` Release build, `x64-analysis` build. Each build
log was checked for `warning C` and `error` lines.

## Build layout for ARM64

- `cmake/SdOptions.cmake`: the `arm64` flavour (ARM64 platform required, v143, floor `win10-arm64.txt`,
  `SD_MODERN_SECURITY` = `/sdl` and `/guard:cf`, `SD_CET` = 0, so no `/CETCOMPAT` and no `--require-cet`).
- `cmake/SdHostTools.cmake`: `sdl10n`, `sd-importcheck`, `sd-admxgen` and `sd-payload` run during the build, so they must
  run on the host. An ARM64 configure builds them in a nested **x64** configure of the same tree (`SD_HOST_TOOLS_ONLY=ON`,
  ExternalProject `sd_host_tools`, output `build/arm64/host-tools/bin/<Config>/`) and declares them as imported
  executables. Native flavours are unchanged. `sd-isacheck` (x86 audit) is not part of the ARM64 tree. `sd-updsign` is
  built as an ARM64 target and is not run during the build.
- `CMakeLists.txt`: the `SD_HOST_TOOLS_ONLY` branch returns after the four tools.
- `apps/shelldrive-setup/CMakeLists.txt`: the stub is built for `arm64` too (native ARM64 stub), with the knownDLLs test
  using the flavour floor list.
- `cmake/SdPayload.cmake`: the function is unchanged apart from the host-tool dependency. The arm64 payload CAB is made from
  the arm64 tree: `shelldrive.exe`, `shelldrive-host.exe`, `shelldrive-ui.exe`, `shelldrive-shellext.dll` and `uninstall.exe`
  (the stub). **Missing for a shipping ARM64 payload** (04 §5, §6.1): the x86-sse2 and x64-modern shell DLLs that the ARM64
  payload also carries (built by the other presets; the release pipeline cross-includes them), and the ARM64 Dokany
  installer (`dokany.lock`, 04 §7).
- Presets: `arm64` and `arm64-debug` build presets. The `arm64` test preset selects no tests (`noTestsAction: ignore`), so `ctest --preset arm64` exits 0 and runs nothing (CI and ci-local skip ctest for arm64 explicitly).
- `tests/os-imports/win10-arm64.txt`: the floor list, in the bootstrap style of `win10-1507-x64.txt` (whole system DLLs).
  Replace it with the per-function capture from a Windows 10 ARM64 lab VM (04 §2.4, §11.4).
- Manifests: `processorArchitecture="arm64"` comes from `SD_MANIFEST_ARCH`, which `SdOptions.cmake` already set.
- Dokany: `sd_dokan` loads `dokan2.dll` at run time, so the import audit needs nothing for it (kept as is).

## Source changes for ARM64

| File | Change | Why |
|---|---|---|
| `src/sd_platform/platform.c` (`detect_cpu`) | the `__cpuid` locals moved into the x86/x64 branch | ARM64 build warned (C4101) about unused locals; no change on x86/x64 |
| `src/sd_crypto/sd_ct64.h` | `sd_mul64_wide` on `_M_ARM64`: `a * b` and `__umulh(a, b)`; new `sd_addcarry64` / `sd_subborrow64` (intrinsics on x64, branch-free arithmetic elsewhere) | ARM64 has no `_umul128`, `_addcarry_u64` or `_subborrow_u64` (C4013 errors); 01 §2.7 names `__umulh` for ARM64 |
| `src/sd_crypto/bn.c` | `mac`, `adc`, `sbb` use `sd_mul64_wide` and the carry helpers | same reason; the x64 code is the same intrinsics as before |
| `apps/shelldrive-setup/setup_install.c` | `logf` renamed `setup_logf` | `logf` clashes with the CRT intrinsic and MSVC refused the definition (C2169, C2220, C4391). This broke the **x64-modern** Release build on this branch too; it is not ARM64-specific |
| `cmake/SdOptions.cmake` | `/volatile:ms` on all C compiles | see the atomics review below |

## Atomics and memory-order review (ARM64)

ARM64 is weakly ordered. MSVC's default on ARM64 is `/volatile:iso`, under which a `volatile` access carries no ordering,
so the tree's volatile flags and sequence counters would not be ordered. The review covered every `Interlocked*`,
`MemoryBarrier`, volatile publication and seqlock in `src/`, `apps/` and `tools/`.

1. **`/volatile:ms` on every flavour** (`cmake/SdOptions.cmake`). Each volatile load becomes an acquire and each volatile store
   a release on ARM64. It is already the default on x86 and x64, so those builds do not change. It makes these publications
   correct on ARM64:
   - `src/sd_platform/alloc.c` (`sd_mem_set_fail_hook` and its reader): the writer stores `g_fail_ctx` and then `g_fail_hook`;
     the reader loads the hook first. This needs the release/acquire pair, otherwise a reader can see the hook with a stale
     context.
   - The `volatile LONG` stop, close and state flags that are read without an Interlocked call (for example
     `apps/shelldrive-host/agent.c` `g.stop`, the `sd_webdav` `stop` and `evict` flags, the `sd_sftp` `state` and `closing`
     flags).
2. **Interlocked forms: no change.** The `InterlockedXxx` intrinsics are full sequentially consistent fences on ARM64, so every
   `InterlockedCompareExchange`, `Exchange`, `Increment` and `Decrement` used as a publish or a test is ordered. Checked sites:
   `sd_platform/platform.c` `sd_platform_resolve` (the pointer is stored before the state is set; the reader tests the state
   first), `sd_dokan/dokan_load.c` (the API table is filled before `g_ready`), `sd_platform/thread.c` `sd_once_run`,
   `sd_platform/time.c` tick state (compare-exchange loop), `sd_l10n/l10n.c` (the cache entry is published with
   `InterlockedCompareExchangePointer` and read through a volatile array), and `sd_platform/include/sd_platform/sd_thread.h`
   `sd_atomic_*64` (`_InterlockedCompareExchange64` and `_InterlockedExchangeAdd64` are full fences). The Acquire and Release
   variants were not needed, so every flavour keeps one form.
3. **Seqlocks: no change.** `sd_state/state_codec.c` and `apps/shelldrive-shellext/shellext_snapshot.c` use a writer of
   `InterlockedIncrement`, `MemoryBarrier()`, data, `MemoryBarrier()`, `InterlockedIncrement`, and a reader of a volatile
   sequence read, `MemoryBarrier()`, copy, `MemoryBarrier()`, volatile re-read. `MemoryBarrier()` is `__dmb(_ARM_BARRIER_SY)`
   on ARM64, a full system barrier, so the data accesses stay between the sequence accesses on both sides.
4. **`sd_base`**: no atomics. `secure_zero.c` and the `sd_ct` helpers use volatile accesses, which the compiler keeps.
5. **Constant-time code**: the value barriers in `sd_ct64.h` (volatile round trip) are unchanged. The ARM64 128-bit product
   and the carry helpers are the only new code there. The disassembly gate that TM-R02 requires does not exist for ARM64 yet
   (open item).

## Shutdown event (item 4)

`agent.c` already creates the manual-reset event through `sd_ipc_object_create(SD_IPC_OBJ_AGENT_STOP)`, named
`Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<session>` (03 §1.2, `sd_ipc_object_name`). The setup engine
(`apps/shelldrive-setup/setup_host.c`, prefix `Global\com.librestatic.shelldrive.agent.shutdown.`) and the `signal-shutdown`
hook (`apps/shelldrive-host/installer_hooks.c`) open the same name with `EVENT_MODIFY_STATE`. The DACL
(`src/sd_ipc/ipc_common.c` `object_sddl`) grants `SYNCHRONIZE | EVENT_MODIFY_STATE` to the owner, SYSTEM and Administrators, as
03 §1.2 specifies. The task asked for owner-only; the wider grant of the spec is kept because the elevated setup must signal a
per-user agent.

When the event is signalled, the agent leaves its loop (`reason: "event"`), sends `agent.stopping`, stops the mounts and
returns. The new test `agent_shutdown_event_stops_agent` (`tests/apps/test_agent_m3.c`) opens the event by name, signals it,
waits for `agent.stopping` with reason `event`, and waits until the session mutex is gone (the process has exited). It passes
on x64-modern (`sd-test-apps.exe --filter agent_shutdown_event_stops_agent`).

## CI and ci-local

- `.github/workflows/ci.yml`: `arm64` joins the `build` matrix. The v141_xp setup step is skipped for it. Release and Debug
  are built, and the two `ctest` steps are skipped. Pinned actions are unchanged.
- `tools/ci-local.ps1`: `arm64` is optional (not in the default list). It builds both configurations and records the
  build-only result in the summary instead of running `ctest`.
- No ARM64 test run exists anywhere yet. The `unit-arm64` job (04 §11.2, windows-11-arm) is the place for it.

## Open items

- ARM64 test run (windows-11-arm or the lab), dudect, and the ARM64 constant-time disassembly gate (TM-R02, TST-03).
- Per-function floor list for ARM64 (`win10-arm64.txt` is a bootstrap list).
- The ARM64 payload's cross-included shell DLLs and the ARM64 Dokany installer (release pipeline, 04 §5, §7).
- ARMv8 crypto fast paths (AES, PMULL, SHA-1/256): `SD_CPU_ARMV8_CRYPTO` is detected, but no fast path exists yet
  (`src/sd_ssh/kex.c` selects GCM on AES-NI only, so ARM64 takes the portable path).
- `sd_cpucheck` (the SSE2 entry thunk) is x86-sse2 only, as designed.
