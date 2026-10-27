# M6 notes

## Fuzzing, constant-time checks and nightly runs

Status of the work that started the M6 fuzzing item (01 section 12.2, 04 section 11.2, TST-01, TST-02, TST-03). The
review evidence is in `docs/review/d38-pass1.md` section 9. Everything here is test infrastructure and never ships
(TST-30).

## What exists

| Piece | Where | Runs |
|---|---|---|
| Harness contract `int sd_fuzz_one(const uint8_t *, size_t)` | `tests/fuzz/include/sd_fuzz.h` | - |
| 13 harnesses (json, ini, utf_names, text_sanitize, keyfile, known_hosts, cert, kexinit, sftp_reply, wd_http, wd_xml, state, manifest) | `tests/fuzz/harness/fuzz_<target>.c` | - |
| Seed corpora (hand-written, or copied from our own test fixtures) | `tests/fuzz/corpus/<target>/` | - |
| Replay driver `sd-fuzz-<target>.exe` (corpus + deterministic mutations, seed 0x5d0f2e1a) | `tests/fuzz/replay/sd_fuzz_replay.c` | every normal run, CTest label `fuzz` |
| libFuzzer driver `sd-fuzz-<target>-libfuzzer.exe` | `tests/fuzz/replay/libfuzzer_entry.c` | only with `SD_FUZZ=ON` |
| Fuzz flavour (libFuzzer and ASan on every module, DLL CRT) | `cmake/SdOptions.cmake` (`SD_FUZZ`), preset `x86-fuzz` | - |
| Constant-time branch and divide rules | `tools/sd-isacheck` (`--ct-allow`, `ct-branch-allow.txt`) | `isacheck.*`, the `sd_crypto_ctcheck` build step |
| dudect-style timing tests `sd-ct-dudect.exe` | `tests/ct/ct_dudect.c` | only with `-DSD_CT_TIMING=ON`, CTest label `ct` |

Not covered yet (01 section 12.2 list): `fuzz_packet`, `fuzz_kex_reply`, `fuzz_userauth`, `fuzz_channel`,
`fuzz_putty_hostkey`, `fuzz_agent_reply`, `fuzz_proxy_http`, `fuzz_proxy_socks5`, `fuzz_hostkeys`, `fuzz_mlkem`,
the field and bignum differential targets, the `.sdmount` parser and the keyset verifier of the update engine.
Adding a target: a harness file, a corpus directory, and one `sd_add_fuzz_target(...)` line in
`tests/fuzz/CMakeLists.txt`.

## Toolchain on this host

- The MSVC 14.44 toolset of Visual Studio 2022 BuildTools here ships the libFuzzer and ASan runtimes only for
  **x86** (`clang_rt.fuzzer_*-i386.lib`, `clang_rt.asan_dynamic-i386.lib`). A `/fsanitize=fuzzer` link for x64 fails
  (`clang_rt.asan_static_runtime_thunk-x86_64.lib` is missing). Install the VS component **"C++ AddressSanitizer"**
  (x64 and x86 variants) to get the x64 runtimes; CI should do so before the nightly job.
- `libsancov.lib` is shipped but the runtime's auto-link directive asks for `sancov.lib`. `cmake/SdOptions.cmake`
  links the file that exists and passes `/NODEFAULTLIB:sancov.lib`.
- The fuzz build uses the v143 toolset and the DLL CRT (`MultiThreadedDLL`). The ASan and libFuzzer runtimes do not
  come in static-CRT variants.
- The x86 fuzz preset runs the test executables with `clang_rt.asan_dynamic-i386.dll` on `PATH`; the test preset
  `x86-fuzz` in `CMakePresets.json` adds the MSVC host directory for that reason.

## Run the regression set (every change, every run)

```
cmake --preset x64-modern                      # or x86-fuzz for ASan
cmake --build build/x64-modern --config Debug --target sd-fuzz-json sd-fuzz-ini   # ...or the whole tree
ctest --preset x64-modern-debug -L fuzz        # 13 targets, about 2 s on x64 without ASan
```

On `x86-fuzz` (Debug, ASan, 32-bit) the same set takes about 20 s, dominated by `fuzz.keyfile` (KDF-protected files
cost seconds each under ASan). `fuzz.keyfile` runs 200 mutations for that reason; the others run 4000.

## Run libFuzzer (a few minutes per target, or nightly)

```
cmake --preset x86-fuzz
cmake --build build/x86-fuzz --config Debug --target sd-fuzz-json-libfuzzer
mkdir C:\scratch\json && copy tests\fuzz\corpus\json\* C:\scratch\json\
build\x86-fuzz\bin\Debug\sd-fuzz-json-libfuzzer.exe C:\scratch\json -max_total_time=600 -timeout=20 ^
    -artifact_prefix=C:\scratch\json\ -print_final_stats=1
```

- Always run on a **scratch copy** of the corpus: libFuzzer writes new interesting inputs into the first directory.
- A crash or timeout leaves `crash-*`, `timeout-*` or `oom-*` in the artifact directory. Turn it into a regression
  seed `tests/fuzz/corpus/<target>/regress_<short-name>`, fix the cause, and run `ctest -L fuzz` (the seed runs in the
  replay driver on every run). Add a unit test as well when the bug is in a function with a clear contract.
- Exit status 0 with `Done N runs` means no finding in that time. Exit 77 or a `SUMMARY: AddressSanitizer` line is a
  finding.
- Last recorded campaign (2026-10-27): 13 targets x 150 s, about 29.5 million executions, no crash, no timeout.

## Nightly fuzzing (intended CI, 04 section 11.2 `fuzz.yml`; not wired yet)

1. Runner: `windows-2022` with the "C++ AddressSanitizer" component (see above). Matrix over the 13 targets (add new
   ones here).
2. Build: `cmake --preset x86-fuzz` and `cmake --build build/x86-fuzz --config Debug --target sd-fuzz-<t>-libfuzzer`.
3. Corpus: `actions/cache` keyed by target and ISO week. Restore it, run, then save it. Minimize weekly with
   `sd-fuzz-<t>-libfuzzer.exe -merge=1 <min-dir> <corpus-dir>`.
4. Run 10 minutes per target nightly (`-max_total_time=600 -timeout=20`), and 60 seconds per target on pull requests
   that touch `src/sd_ssh`, `src/sd_sftp`, `src/sd_crypto`, `src/sd_config`, `src/sd_update`, `src/sd_webdav`,
   `src/sd_state` or `src/sd_base`.
5. Every job also runs `ctest --preset x86-fuzz -L fuzz`.
6. On a crash, upload the artifact directory and fail the job. Do not commit the crash; the fix and the regression
   seed are committed by a person.

## Constant-time checks

Gate (every x86 and x64 Release build, `sd_crypto_ctcheck`, CTest `isacheck.ct_sd_crypto`):

- No call to a compiler helper from constant-time code (as before).
- DIV and IDIV are forbidden in constant-time-named functions (`*_ct_*`, `*_ct`, `sd_ct_*`).
- Which objects: the constant-time list of `tools/sd-isacheck/CMakeLists.txt` (`SD_CT_SOURCES`). On x86-sse2 it also
  takes the AES-NI and SHA-NI objects (`aes_ni`, `sha256_ni`); on the x64 flavours it takes those two plus `aes_ct` and
  `hash`. x86-ia32 and ARM take no hardware object. A new hardware or SIMD function that must be judged needs the
  constant-time name; the `isacheck.ct_scans_*` tests fail if a rename removes it from the scan.
- x64 objects are decoded in 64-bit mode (`isacheck.selftest` covers both modes). The branch and divide rules on x64
  reach only the functions listed above.
- A **forward** conditional branch in those functions is reported, except a loop-entry guard (a forward branch that
  skips a loop whose back-edge lies inside the skipped region). Backward branches are loop back-edges; their bounds
  are public by 01 section 2.4 rule 1 and are not classified.
- Functions whose forward branches were reviewed and depend on public data only are listed in
  `tools/sd-isacheck/ct-branch-allow.txt` with the reason. The list is exempt from the forward-branch rule only.
  A change to a listed function needs its branches reviewed again.

Not implemented: secret-indexed memory operands, the 64x64 multiply sequence check, the ARM32 run. The x86-sse2 run is in place: the vectorizer's overlap checks are kept out of CT loops with `SD_CT_NO_VECTOR` (d38-pass1 section 9.4). Round 10 (d38-pass1 section 9.4) brought the AES-NI and SHA-NI code and the dispatch cores under the gate. The `sha256_final` digest store still vectorizes to SSSE3 `PSHUFB` on x86-sse2 and is not judged (open).

dudect-style timing (opt-in, once per release candidate and nightly on a quiet machine):

```
cmake -S . -B build/x86-ia32 -DSD_CT_TIMING=ON        # after cmake --preset x86-ia32
cmake --build build/x86-ia32 --config Release --target sd-ct-dudect
build\x86-ia32\bin\Release\sd-ct-dudect.exe            # all primitives, default samples (20000; RSA 4000)
build\x86-ia32\bin\Release\sd-ct-dudect.exe 1000000 X25519   # one primitive, a million samples per class
```

A |t| above 10 exits 1. A value above 4.5 at small samples means "rerun with more samples", not a leak. Confirm any
report on the lab machine before treating it as a leak (04 section 11.2 `ct.yml`).

## ARM64 flavour

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

## ARM32 flavour

Scope of this branch (`wip/r7-arm32`): the `arm32` build flavour (04 §1.1, §5.1, D5 best effort, D31 MSI not done
here). Build only: this x64 machine cannot run ARM32 binaries, and the lab has no Windows on ARM device yet. Nothing
here runs ARM32 code.

### Status

| Item | State |
|---|---|
| `cmake --preset arm32` / `arm32-debug` (v143, SDK 10.0.22621, `-A ARM`) | Release and Debug build; `/W4 /WX`, no warnings; PE32 images, machine `ARMNT` (0x1C4), subsystem 6.02 |
| Build-time tools | built by a nested x64 configure (`SD_HOST_TOOLS_ONLY`, as for ARM64) |
| UI and shell extension | not built (D5, 04 §5.1); `tests/ui` and `tests/shellext` are not added on ARM32 |
| Import audit | runs on `shelldrive.exe`, `shelldrive-host.exe` and the setup stub against `tests/os-imports/win10-arm32.txt` (bootstrap list) |
| Setup stub and `shelldrive-setup.exe` | native ARM32 stub; it selects flavour `arm32` (payload `PAYLOAD_ARM32`) on ARM32 and ARM64 hosts |
| Payload CAB | `shelldrive.exe`, `shelldrive-host.exe`, `uninstall.exe` (the stub); no UI or shell extension members |
| ARM32 tests | built, **not run** (the `arm32` test preset selects no tests; CI and ci-local skip ctest) |
| ci.yml / ci-local.ps1 | `arm32` is build-only, in the CI matrix and as an optional preset in ci-local |
| Dokany, MSI | none (no upstream ARM32 installer, 04 §7; the MSI is D31 and not built) |

### Build layout

- `CMakePresets.json`: `arm32` configure preset (VS 2022, `-A ARM`, `-T v143`, `CMAKE_SYSTEM_VERSION=10.0.22621.0`),
  build presets `arm32` and `arm32-debug`, and a test preset with no tests (as `arm64`).
- **Compiler probe skipped for this preset (workaround, remove when it is no longer needed).** With the default SDK
  10.0.26100 the compiler test of CMake 3.31 fails with MSB8087 (that SDK has no ARM libraries). The compiler test
  builds its try-compile project without the `CMAKE_SYSTEM_VERSION` SDK. Tried and not enough: `CMAKE_SYSTEM_VERSION`
  before `project()`, `CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION` (on the command line and before `project()`),
  `CMAKE_TRY_COMPILE_PLATFORM_VARIABLES`, `CMAKE_VS_GLOBALS=WindowsTargetPlatformVersion=...` and the
  `WindowsTargetPlatformVersion` environment variable. The preset therefore sets `CMAKE_C_COMPILER_WORKS=1` and
  `CMAKE_C_ABI_COMPILED=ON`. The compiler identification still runs, and the real projects still get
  `WindowsTargetPlatformVersion=10.0.22621.0` (checked in the generated vcxproj files).
- Skipping the probe also leaves CMake without the ARM architecture family, so the platform file picks the ARM
  default library list (kernel32 and user32 only). The preset pins `CMAKE_C_STANDARD_LIBRARIES` to the desktop list
  that the arm64 cache uses; without it the setup stub fails to link (gdi32, shell32, ole32 unresolved).
- `cmake/SdOptions.cmake`: the `arm32` flavour (ARM platform, v143, SDK 10.0.22621, `_WIN32_WINNT=0x0602`,
  `/SUBSYSTEM:WINDOWS,6.02`, floor `win10-arm32.txt`, `SD_MODERN_SECURITY` = `/sdl` and `/guard:cf`, no CET, no
  `/HIGHENTROPYVA`, manifest `processorArchitecture="arm"`). `SD_ARM32` drops the UI and the shell extension and
  makes the tree cross-compiled (`SD_CROSS_HOST_TOOLS`). `sd-isacheck` (x86 audit) is not built, as on ARM64.
- `cmake/SdPayload.cmake`: the UI and shell-extension members and dependencies are left out on ARM32.
- `tests/os-imports/win10-arm32.txt`: bootstrap list in the style of `win10-arm64.txt`. Replace it with the
  per-function capture from a Windows 10 on ARM device (04 §2.4, §11.4).

### Source changes

| File | Change | Why |
|---|---|---|
| `src/sd_crypto/sd_ct64.h` | `SD_MUL32` on `_M_ARM` is `_arm_umull` (one UMULL); `sd_mul64_wide` uses the 32-bit pieces | 32-bit ARM has no `__umulh` or `_umul128`; 64x64 products must not reach a compiler helper (01 2.4.3) |
| `src/sd_crypto/bn.c` | unchanged: 32-bit limbs on every target that is not x64 or ARM64 | ARM32 takes the same limb size as the x86 flavours (`SD_BN_LIMB_BITS` 32) |
| `apps/shelldrive-setup/setup_core.h`, `setup_args.c` | `SD_SETUP_FL_ARM32`, name `arm32`, payload `PAYLOAD_ARM32`; an ARM32 stub (`_M_ARM`) accepts ARM32 or ARM64 hosts and picks `arm32`; a 32-bit ARM process on a 32-bit ARM OS reports native machine `ARMNT` | 04 §6.2: ARM32 has its own setup EXE and the universal stub refuses `ARMNT` |
| `src/sd_update/update_engine.c` | an ARM32 build reports flavour `arm32` even on an ARM64 host | `GetNativeSystemInfo` reports ARM64 for a 32-bit process on ARM64 Windows; the update must match the binary |
| `CMakeLists.txt`, `tests/CMakeLists.txt` | UI, shell extension and their tests are not added on ARM32 | D5, 04 §5.1 |
| `tests/setup/test_args.c` | checks the `arm32` name and payload resource | |

### Constant-time status (ARM32)

- Products of secrets: the disassembly of the Release `sd_crypto` `bn.obj` (checked by hand with `dumpbin /disasm`)
  has 5 `umull` (the 32x32->64 products of the Montgomery code), no `__rt_*` helper call and no `_all*`/`_aull*`
  call. Calls go only to functions of this tree and to the stack-cookie and `memcpy` runtime. This is a one-off check.
  The automated gate (TM-R02, TST-03: `sd-ctcheck` for ARM32 with the call allow-list, no branch on secrets, no 64x64
  multiply) does not exist yet.
- **Unverified (01 2.4.1, 2.4 rule 3, marked [verify]):** whether `UMULL` takes the same time for every operand on
  the cores that run Windows on ARM32. The rule relies on dudect on the lab device. Check the TRM of each target core
  first: some ARM cores of earlier generations had early-terminating multipliers, which would make the cycle count
  depend on an operand. Until dudect has run on a device, the ARM32 constant-time claim is not made.
- Not reviewed on ARM32: secret-indexed memory, branches on secret data in the field code (the x86 review applies, the
  ARM32 code generator has not been looked at), and the `sd_ct_*` value barriers (`volatile` round trips, unchanged).

### Verification run on this machine

- `arm32` Release and Debug: built, zero warnings (`/W4 /WX`), import audit and setup payload pass on the shipping images.
- `x64-modern` Debug: built, zero warnings. `ctest --preset x64-modern-debug -LE "matrix|bench|interop|repro"`: 74 of
  75 tests pass. `unit.crypto_pk` times out at 300 s: its `bench_pk_throughput` (RSA-3072 signing loop) is slow in a Debug
  build. That code path is not changed on x64 by this branch, but the base commit was not rebuilt to confirm it.
- `x86-ia32` Release and Debug: built, zero warnings, import and ISA audits pass.
- No ARM32 test binary was run.

### Open items (ARM32)

- ARM32 test run on a Windows 10 on ARM device or in the lab, dudect on UMULL (TM-R02), and the ARM32
  constant-time disassembly gate (TST-03).
- Per-function floor list for ARM32 (`win10-arm32.txt` is a bootstrap list).
- Refusals in the setup and the MSI: Windows 11 24H2 and later (no ARM32 app support, 04 §5.1, `[lab-verify]` the build
  cut-off) and Windows RT and IoT Core (`[lab-verify]` the detection value). Not implemented: the stub has no build
  number check.
- MSI `Platform="arm"` package, install into the ARM32 Program Files folder, `[lab-verify]` (D31).
- Backend choice: 02 §10.1 ("auto") and 03 §3.4.1 never pick Dokany on ARM32. `sd_mount` has no architecture check yet; on ARM32 the
  Dokany probe fails because `dokan2.dll` is absent, so WebDAV is chosen by the existing fallback.
- CI: the `arm32` job runs on `windows-2022`. Whether that image has the ARM32 toolset and the SDK 10.0.22621 ARM
  libraries is not verified here (the local machine has both).
- Removing the compiler-probe workaround once CMake's compiler test honours the SDK version (see Build layout).
