# M1 implementation notes

Choices made during M1 where the design documents leave detail open, and small deviations with their
reason. The design documents stay authoritative. Each workstream appends its own section.

## x86 flavours, sd-isacheck and the lab harness

Foundation work for D4/D28 (two x86 flavours), 04 §1.1, §2.4, §3.2, §11.2 and §11.4, and the TM-R02
helper-call gate of 01 §2.4 rule 3 / §2.7.5.

### Presets and flags

- Configure presets `x86-ia32` and `x86-sse2` (hidden base `x86-base`: VS 17 2022, `-A Win32`,
  `-T v141_xp`); build and test presets `x86-ia32`, `x86-ia32-debug`, `x86-sse2`, `x86-sse2-debug`. Build
  trees `build/x86-ia32/`, `build/x86-sse2/`. The cache variable `SD_X86_ARCH` (`IA32` / `SSE2`) is set by
  the preset and checked against `SD_FLAVOUR`.
- `cmake/SdOptions.cmake`: `_WIN32_WINNT=0x0501`, `NTDDI_VERSION=0x05010300`, `/SUBSYSTEM:<kind>,5.01`,
  floor list `tests/os-imports/xp-sp3-x86.txt`, `/arch:IA32` or `/arch:SSE2`, `/SAFESEH /LARGEADDRESSAWARE`;
  `/HIGHENTROPYVA` is now 64-bit only (it is meaningless for PE32). The compile definition
  `SD_X86_ARCH_IA32=1` / `SD_X86_ARCH_SSE2=1` exists for the rare code that must know the floor; SIMD
  translation units are still excluded by CMake lists (`SD_X86_IA32` variable), not by `#ifdef` (01 §2.3).
- A target can override the flavour's `/arch` with the target property `SD_X86_ARCH_OVERRIDE` (one `/arch`
  per command line, so cl never prints D9025). Used by the entry thunk (always IA32) and the sd-isacheck
  fixtures.
- **Bug fix, all flavours:** `/PDBALTPATH:%_PDB%` reached the linker as `%%%%_PDB%%%%` (the VS generator
  doubles `%`), so every PE recorded the PDB name as `%%%name.pdb%%%` and no debugger or dbghelp found the
  PDB by name. The option is now `/PDBALTPATH:$<TARGET_PDB_FILE_NAME:...>` (same value, the bare file name).
- `sd-importcheck --require-safeseh` (on for both x86 flavours): the load-config directory must carry a
  SafeSEH handler table (or the image is `NO_SEH`). Negative CTest `importcheck.detects_missing_safeseh`
  links a fixture with `/SAFESEH:NO` (target property `SD_SAFESEH_NO`).
- `tests/os-imports/xp-sp3-x86.txt` is a **bootstrap** list like the x64 ones: the `xp-sp2-x64.txt` set minus
  the x64-only unwind exports, plus the 32-bit `Interlocked*` family that SDK 7.1A binds to kernel32 exports
  on x86. Replace it with the export capture of the XP SP3 x86 lab VM (04 §2.4).

### x86-sse2 entry thunk (04 §3.2)

- `src/sd_platform/entry/sd_cpucheck.c`, compiled into the object libraries `sd_cpucheck_console` /
  `sd_cpucheck_gui` (always `/arch:IA32`) and linked into every `sd_add_app` executable of `x86-sse2` with
  `/ENTRY:sd_cpucheck_entry`. It calls `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)` and
  either tail-calls `wmainCRTStartup` / `wWinMainCRTStartup` or prints the refusal (stderr for console apps,
  `MessageBoxW` for windowed ones) and exits with `STATUS_ILLEGAL_INSTRUCTION` (0xC000001D) before the CRT
  starts. Apps therefore use `wmain` / `wWinMain`.
- The refusal text is user-facing and exists in all six languages, but it is a table inside the thunk, not a
  PO string: the thunk runs before the CRT and the `sd_l10n` runtime is compiled `/arch:SSE2` in this
  flavour. Selected by `GetUserDefaultUILanguage()`. Keep it in sync with the registers in AGENTS.md.
- The shell DLL's `DllMain` check (04 §3.2) is not implemented: there is no shell DLL yet.
- The fixture `cpucheck-fixture` links the thunk with `SD_CPUCHECK_TEST_HOOK` (non-shipping):
  `SD_CPUCHECK_SIMULATE_NO_SSE2=1` forces the refusal path, so CTest `cpucheck.refuses_without_sse2` runs it on
  any CPU. The real check on a CPU without SSE2 is the QEMU lab VM.
- `[lab-verify]` (unchanged from 04 §3.2): the v141 static CRT start-up executes no SSE2 before the thunk
  returns; the thunk itself is verified IA32-clean by sd-isacheck (`--entry`).

### sd-isacheck (ISA audit)

Deviation from 04 §2.4 (which says `dumpbin /disasm`): the tool has its own small x86 decoder
(`tools/sd-isacheck/x86_decode.c`), so it needs no VS command prompt and its output is stable across toolset
updates. Method:

1. Function boundaries come from the image's PDB through dbghelp (`SymEnumSymbols`): private function symbols
   with their sizes, plus public symbols for assembler routines (range = up to the next symbol). This is why
   the `/PDBALTPATH` fix above was needed. A missing or mismatched PDB is an error, not a pass.
2. Each range is decoded linearly: legacy prefixes, one-byte / `0F` / `0F 38` / `0F 3A` maps, ModRM/SIB/
   displacement/immediates, VEX (`C4`/`C5`) and EVEX (`62`), which 32-bit mode tells apart from LES/LDS/
   BOUND by ModRM.mod = 11. Every instruction is classified: base (P6 incl. CMOV, CMPXCHG8B), MMX, SSE, SSE2,
   SSE3+ (SSE3/SSSE3/SSE4/POPCNT/LZCNT/RDRAND/...), AVX (VEX), AVX-512 (EVEX), 3DNow!, FXSAVE/XSAVE/XGETBV/
   CLFLUSH.
3. Jump tables in `.text`: a dword with a base relocation at an instruction boundary is data. In a sized
   (compiler-generated) function the sweep stops there, because MSVC places switch tables after the body;
   in an unsized (assembler) range the dword is skipped.
4. Floors: `ia32` (x86-ia32) rejects everything but base; `sse2` (x86-sse2) rejects SSE3+, AVX, AVX-512 and
   3DNow!. Hits inside functions listed in `tools/sd-isacheck/crt-allow.txt` are allowed: static CRT routines
   that test `__isa_available`, `__sse2_available` or `__use_sse2_mathfcns` before their SIMD path (each was
   checked in `dumpbin /disasm`; re-check on any toolset update). Our own code never goes on that list.
5. sse2 floor only: a function that reads `__isa_available` (a relocated absolute reference; address from
   `SymFromName`) counts as dispatching and its hits are allowed. It was needed because the v141 auto-vectorizer
   compiled our plain-C byte-swap loops in `hash.c` (`sha256_blocks`, `sha256_final`) into a PSHUFB (SSSE3)
   loop behind `cmp __isa_available, 2; jl <scalar>` in the x86-sse2 build. Both loops now carry `SD_CT_NO_VECTOR`
   (M6 round 12), so no hit in our code needs this rule; it stays for the CRT. Never applied on the ia32 floor.
6. `--entry <symbol>`: the PE entry point must be that symbol and its function must be IA32-clean even on the
   sse2 floor.

Wiring: post-build on every `sd_add_app` executable of both x86 flavours (`sd_add_isa_check` in
`cmake/SdModule.cmake`) and CTest `isacheck.<exe>`; `isacheck.selftest` (44 encodings, every flavour),
`isacheck.detects_sse2` (fixture compiled `/arch:SSE2` must fail on the ia32 floor, naming the function),
`isacheck.sse2_floor_accepts_sse2`, `isacheck.entry_thunk_is_ia32`. Report with `--list`.

First finding: `detect_cpu()` in `sd_platform` executed a (CPUID-guarded) `XGETBV` in the x86-ia32 build.
01 §2.3 says the IA32 build does no run-time detection at all, so `sd_cpu_features()` now returns 0 there
(`SD_X86_ARCH_IA32`), and `unit.platform` checks it.

### Constant-time helper-call gate (TM-R02, part of TST-03)

`sd-isacheck --ct-lib <lib> --ct-member <obj>...` reads the COFF objects of the listed members of a static
library (the `.lib` archive is parsed directly) and fails on any relocation, from a code section, to an
undefined external that is a compiler runtime helper: `_allmul _aullmul _alldiv _aulldiv _allrem _aullrem
_alldvrm _aulldvrm _allshl _allshr _aullshr` and the float-conversion helpers (`_ftol*`, `_dtol3`, `_dtoui3`,
`_dtoul3`, `_ltod3`, `_ultod3`). With `/Gy` each function is its own COMDAT section, so the report names the
calling function. Working on objects rather than the linked image keeps the attribution exact and cannot be
confused by inlining across translation units (there is no `/GL`). `--list` prints every external each
function references (the input for the callee allow-list of 01 §2.7.5).

- Constant-time sources (`SD_CT_SOURCES` in `tools/sd-isacheck/CMakeLists.txt`, owned with the crypto agent):
  `aes_ct`, `ct`, `curve25519`, `gcm`, `chacha_poly`, `hash`. A listed object that disappears fails the gate.
- Judges Release objects only (`--config`; Debug reports a skip): at `/Od` MSVC calls `_allshl` /
  `_aullshr` even for shifts by constants, so every 64-bit shift in sd_crypto shows up there. Shipping code is
  Release (01 §2.7.5 checks "the release objects").
- Runs on both x86 flavours: custom target `sd_crypto_ctcheck` (in ALL, re-runs when `sd_crypto.lib`
  changes) and CTest `isacheck.ct_sd_crypto`; negative CTest `isacheck.detects_ct_helper_call` (a fixture
  with `uint64_t * uint64_t` and a run-time 64-bit shift must report `_allmul` and `_allshl`).
- Result: sd_crypto Release is clean on x86-ia32 and x86-sse2 (no helper references; the 64-bit products
  already go through `sd_ct64.h`).
- Not done yet (still TST-03 / `sd-ctcheck` of 01 §2.7.5): the conditional-branch, `div` and secret-indexed
  memory-operand checks, the callee allow-list and the 64x64-multiply-sequence check. The decoder in
  `tools/sd-isacheck` is meant to be reused for them.

### 32-bit fixes in modules

- `sd_platform` (`sd_thread.h`): new `sd_atomic_load64` / `sd_atomic_add64` / `sd_atomic_inc64`. SDK 7.1A has
  no `InterlockedExchangeAdd64` / `InterlockedIncrement64` for x86 and the kernel32
  `InterlockedCompareExchange64` export is Vista+, so they loop on the `_InterlockedCompareExchange64`
  intrinsic (CMPXCHG8B). Plain reads of a `LONG64` can tear on x86; use `sd_atomic_load64`.
- `sd_sftp` (`sftp_session.c`): the rx/tx byte counters use the helpers above (were
  `InterlockedExchangeAdd64` and plain 64-bit reads).
- `sd_vfs` (`vfs_core.c`, `vfs_ops.c`): cache hit/miss and byte counters use the helpers above (were
  `InterlockedIncrement64` / `InterlockedExchangeAdd64` / `InterlockedCompareExchange64`).
- `sd_platform` (`platform.c`): no CPU detection on x86-ia32 (see sd-isacheck above).
- `tests/unit/sd_dokan` (`test_dokan.c`): the ABI layout test checks the x86 offsets on 32-bit builds
  (`SD_DOKAN_OPTIONS` 0x4028 bytes, `UNCName` at 0x14, `SD_DOKAN_FILE_INFO` 0x28 bytes, `IsDirectory` at 0x1C;
  they follow from the same declarations, `[lab-verify]` against dokan2.dll x86 like the x64 ones), and the
  probe test accepts `SD_DOKAN_WOW64`.
- `tests/unit/sd_sftp` (`main_interop.c`): finds `wsl.exe` through `%SystemRoot%\Sysnative` under WOW64.
- No printf-format or size-type problems showed up: the tree was already warning-free at `/W4 /WX` on Win32.

### Results (2026-10-25, this Windows 11 x64 machine)

Warning-free builds of `x86-ia32`, `x86-ia32-debug`, `x86-sse2`, `x86-sse2-debug` (post-build import, ISA
and constant-time checks pass). CTest: 40 tests per preset; all pass except `dokany.mount` (skipped,
WOW64). `interop.ssh` / `interop_rekey_bulk` fails on `x86-ia32-debug` only: it sees 8-9 key exchanges where
it requires more than 10 (x64: 16). It passes on every Release preset and on `x86-sse2-debug`. It is timing
dependent (slow unoptimized 32-bit KEX), so it is left to the sd_ssh owner.

### Running x86 tests on an x64 host

The x86 test binaries run under WOW64. `dokany.mount` always skips there (`sd_dokan_probe` returns
`SD_DOKAN_WOW64` by design, and Dokany x86 is not installed in WOW64); `tools/ci-local.ps1` reports that
skip instead of failing on it. `interop.*` run against the WSL fixture as on x64.

### CI

`.github/workflows/ci.yml`: the build matrix is `x64-modern, x64-xp, x86-ia32, x86-sse2` (Release + Debug
build and test each); every v141_xp job runs `.github/actions/setup-xp-toolset`, which now also verifies the
Win32 platform toolset folder. Actions stay pinned by SHA. `tools/ci-local.ps1` defaults to all five presets.

### Lab harness (`tests/lab/`, 04 §11.4)

Contents:

| File | What |
|---|---|
| `lab.example.psd1` | lab config template: lab folder, optional switch, Hyper-V VMs (XP SP3 x86, 7 SP1 x86, 7 SP1 x64), QEMU VM |
| `SdLab.psm1` | shared functions: config, payload staging, ISO building (oscdimg, else IMAPI2 COM), serial pipe reader, transcript judge |
| `New-LabVM.ps1` | creates generation-1 VMs: differencing disk over your VHDX (or empty disk + setup ISO), COM1 on `\\.\pipe\sd-lab-<vm>`, standard checkpoints, legacy NIC only if a switch is configured; `-Checkpoint` takes the `base` checkpoint |
| `Restore-LabVM.ps1` | reverts to `base`, attaches the payload ISO, starts the VM |
| `New-PayloadIso.ps1` | ISO 9660 + Joliet payload: `\sdlab\` guest scripts (rewritten with CRLF), `\<flavour>\` shipping EXEs, `\<flavour>\tests\` unit tests (`-IncludeTests`) |
| `Read-LabSerial.ps1` | host COM1 reader on the named pipe, logs the transcript, exit code = verdict |
| `Invoke-SdLab.ps1` | one run per VM: payload, revert, boot, read COM1, judge, power off; logs in `<LabRoot>\logs` |
| `qemu/Start-QemuPentium3.ps1` | `qemu-system-i386 -cpu pentium3 -accel tcg -snapshot`, payload as CD, `-serial pipe:sd-lab-<vm>`; the help text has the disk-preparation recipe and how to install QEMU |
| `guest/smoke.cmd`, `guest/sysinfo.vbs` | in-guest smoke (cmd + cscript only, XP-compatible): OS/CPU facts, `--version`/`--help`/`--selftest` of each flavour, every unit test; `SDLAB ...` lines to COM1 and `%SystemDrive%\sdlab\smoke.log`; powers off at the end |
| `guest/install-runner.cmd`, `guest/sdlab-runner.cmd` | one-time guest setup: scheduled task `SdLabSmoke` (at start-up, SYSTEM) that runs `\sdlab\smoke.cmd` from whichever drive holds the payload |

Verdict: every `SDLAB RESULT` must be exit code 0, except that on a VM with `ExpectSse2 = $false` every
x86-sse2 executable must exit with 0xC000001D (the entry thunk's refusal) and x86-sse2 unit tests are not
judged (they have no thunk).

What you must provide (nothing is downloaded by the scripts):

1. Licensed Windows media, as installed and shut-down VHDX disks (`BaseVhdx`, preferred) or setup ISOs
   (`InstallIso`): Windows XP Professional SP3 x86, Windows 7 SP1 x86, Windows 7 SP1 x64. For the no-SSE2 VM:
   a qcow2 disk with XP Professional SP3 x86 installed **under QEMU** with `-cpu pentium3` (recipe in
   `Get-Help tests\lab\qemu\Start-QemuPentium3.ps1 -Full`; needs your XP ISO).
2. A lab config: copy `tests/lab/lab.example.psd1` outside the repository and set `LabRoot` (about 5 GB per
   VM) and the image paths.
3. An elevated PowerShell (or membership in "Hyper-V Administrators") for the Hyper-V scripts. Hyper-V is
   enabled on the development machine.
4. QEMU for the Pentium III VM, installed by you, e.g. `winget install --id SoftwareFreedomConservancy.QEMU`
   (or MSYS2 `mingw-w64-ucrt-x86_64-qemu`); set `Qemu.QemuDir`. It is not installed on the development
   machine yet.
5. Optional: Windows ADK "Deployment Tools" for `oscdimg.exe`; without it the built-in IMAPI2 is used.
6. One-time guest setup per VM: boot with a payload ISO, run `\sdlab\install-runner.cmd` as an administrator,
   shut down, then `New-LabVM.ps1 -Checkpoint` (Hyper-V) — for QEMU just shut down; it always boots with
   `-snapshot`.

Deviations from 04 §11.4 and what is verified:

- The guest starts the smoke run from a SYSTEM scheduled task at boot instead of an autologon account's
  Startup entry: no autologon to configure and no desktop needed for console tools. UI smoke steps (later
  milestones) will need the autologon variant.
- QEMU's COM1 goes to a named pipe (`-serial pipe:`) rather than a file, so one reader serves both
  hypervisors. The checkpoint is named `base` as in 04 §11.4 (`base-sha2` is not created yet).
- The M1 smoke covers start-up (`--version`, `--help`, `shelldrive-host --selftest`) and the unit tests; the
  setup/MSI/mount/upgrade steps of 04 §11.4 arrive with those components.
- Verified on the development machine: all scripts parse; the payload ISO builds through IMAPI2 and mounts with
  the expected layout; `smoke.cmd` runs end to end with COM1 redirected to a file; the serial reader and judge
  pass and fail correctly against a fake pipe server. **Not run:** the Hyper-V cmdlets (no OS images here) and
  QEMU (not installed). `[lab-verify]` the first real run on each VM, including XP's `schtasks /ru SYSTEM`
  syntax and QEMU's Windows pipe chardev.

## sd_ssh / sd_sftp resilience (reconnect, meta + bulk channels)

Implements 01 §8, §10.4-§10.6, §11 step 6, C16/C17 and D19 for one connection per session (the pool, D18,
is M2: `connections` is still clamped to 1 and `SD_SFTP_O_STRIPED` is ignored). Headers: `sd_ssh/sd_ssh.h`,
`sd_ssh/sd_prompt.h`, `sd_sftp/sd_sftp.h` (its top comment is the reconnect contract) and
`sd_sftp/sd_sftp_transport.h`. Every addition is an appended field or a new function; M0 callers compile
and behave as before.

### What sd_vfs gets (API additions)

| Addition | Meaning |
|---|---|
| `sd_sftp_session_reconnect_now()` | Now implemented: skips the backoff in `RECONNECT_WAIT`; from `FAILED` / `AUTH_REQUIRED` it restarts the loop (attempts count from 0). `SD_E_UNSUPPORTED` only for a transport without `SD_SFTP_TP_REOPEN`. |
| `sd_sftp_session_reconnect_stop()` (new) | Cancels the loop (a running attempt is aborted): `FAILED` with reason `SD_E_CANCELLED`; waiting requests complete with `SD_E_DISCONNECTED`. |
| `sd_sftp_event.attempt`, `.generation` (new fields) | `RECONNECT_WAIT` carries `retry_in_ms` and the 1-based `attempt` that follows; every event carries the session generation (the new one on `READY` / `READY_INFO`). |
| `sd_sftp_stats.generation`, `.channels`, `.reconnect_attempts` (new fields) | `rx_total` / `tx_total` count the current generation; `srtt_ms` / `rttvar_ms` come from sd_ssh keepalive and probe samples when there are any (transport `rtt` op), else from meta-channel round trips. |
| `sd_sftp_file_reopen()` | Now documented and tested: same object, `u.open.attrs` = fresh FSTAT (files), `generation` and `attrs_at_open` updated; directories restart the listing; a failure leaves the handle stale. |
| `sd_sftp_open(..., same_channel_as, ...)` | Now honoured: the new handle lives on the channel of `same_channel_as` (copy-data). |
| `server_info.channels` | 1 or 2, per generation. |
| `sd_ssh_conn_set_keepalive()`, `sd_ssh_conn_clear_secrets()` (new) | Run-time keepalive tuning; dropping the cached reconnect secrets. |
| `sd_ssh_auth_info.is_reconnect`, `.hostkey_just_accepted`, `sd_hostkey_prompt_info.is_reconnect` (new fields) | |
| `sd_sftp_transport.caps`, `open_stream`, `write_stream`, `consumed_stream`, `rtt` (new) | `SD_SFTP_TP_REOPEN` (open again after close) and `SD_SFTP_TP_STREAMS` (stream 1 = bulk). `sd_sftp_session_create()` sets both. |

State machine as implemented: `IDLE -> CONNECTING -> READY (generation 1)`. On a loss: `DISCONNECTED(reason)`,
then every request that was in flight or queued completes with `SD_E_DISCONNECTED`, then every handle is
stale, then `RECONNECT_WAIT(retry_in_ms, attempt) -> CONNECTING` (with `AUTH_REQUIRED(SD_E_AUTH_REQUIRED)` while
a reconnect prompt is out) `-> READY` + `READY_INFO` with generation + 1. A failed attempt goes back to
`RECONNECT_WAIT`. Backoff: `min(max_delay, initial_delay * 2^n)` with +/-20 % jitter (xorshift, not crypto);
`max_attempts` 0 = unlimited. The loop stops in `FAILED` for host-key mismatch / revoked / rejected / type
unavailable, legacy refused, KEX failure, unsupported, invalid key, `max_attempts` and `reconnect_stop`, and in
`AUTH_REQUIRED` for auth failed, prompt cancelled and passphrase problems. `WAIT_READY` requests wait in
`IDLE`, `CONNECTING`, `DISCONNECTED`, `RECONNECT_WAIT`, and in `AUTH_REQUIRED` while an attempt runs (02 §5.2
`offline_wait`). Unsent `WAIT_READY` path operations that were queued at the moment of a loss keep waiting
instead of failing.

### Decisions and deviations

- **The first connect does not loop**: its failure is `FAILED` (M0 behaviour; the host decides).
  `reconnect_now()` retries it with the full loop. Only a session that was READY once reconnects by itself.
- **`maybe_executed`** stays as in M0: 1 for every request that was sent, reads included. It only means
  something for mutating requests; the header lists them.
- **Bulk channel**: opened once the meta channel is up; READY waits until it has its VERSION or has failed.
  An `on_open` error (MaxSessions 1 gives `SD_E_BUSY`), a refused subsystem, or close / EOF before VERSION
  degrade that generation to one channel; every reconnect tries two again. Losing either channel after
  READY is a connection loss (no degrade in the middle of a generation). Request ids are unique across both
  channels; a reply on the wrong channel is `SD_E_PROTOCOL`.
- **Reconnect secret cache** (01 §7.4): sd_ssh caches the password and the **key-file passphrases**, not
  decrypted keys (the M0 key object has no serializer; the cost is one KDF per reconnect). Protection is
  `CryptProtectMemory(SAME_PROCESS)` (resolved at run time, Vista+) or `RtlEncryptMemory`
  (`SystemFunction040/041` through `sd_platform_resolve_by_name`, XP); with neither, nothing is cached. The
  cache is neither read nor written on a connection with `hostkey_just_accepted` (TM-R05; applied to
  passphrases too, conservatively). A cached secret that the server rejects is dropped and the normal prompt
  follows (it does not count as a round). Proxy passwords: there are no proxies before M2.
- **Host key on reconnect**: the key verified by the last successful connect is pinned in the
  `sd_ssh_conn`. Every reconnect runs the full known_hosts check: `MATCH` proceeds (a different key that
  matches a store is logged), `MISMATCH` / `REVOKED` / `NEW_TYPE` fail without a prompt, and `NEW` proceeds
  silently only when the key equals the pinned one (it was accepted once for this session, and the
  connection is still `hostkey_just_accepted`); otherwise the prompt carries `is_reconnect = 1`.
- No `sd_sftp_session_set_keepalive`: keepalive values come from `sd_ssh_config` at create time, and
  `sd_ssh_conn_set_keepalive()` is there for code that owns the connection.
- `sd_ssh_conn_connect()` may be called again on the same object after a failure or a disconnect;
  `is_reconnect` is set once a connect of that object has reached CONNECTED.

### Tests

- `unit.sftp` (`tests/unit/sd_sftp/test_reconnect.c`): a scripted in-memory server over the fake transport,
  which now has two streams, reconnects, a refusable bulk stream and failing opens. Covers a drop while
  idle, during 16 pipelined reads, during 32 pipelined writes (never replayed), during OPEN and READDIR (the
  listing restarts after reopen); `maybe_executed` for rename / posix-rename / remove / mkdir / setstat;
  WAIT_READY across an outage and its timeout; meta / bulk classes (a stat completes while bulk reads are
  stuck; CLASS_META and same_channel_as opens); degrade to one channel and back to two on reconnect; one
  channel by option or by transport; backoff and jitter bounds; permanent failure and `reconnect_now`;
  `AUTH_REQUIRED`; `max_attempts`; `reconnect_stop`; reconnect disabled; `READY_INFO` re-read (the extensions
  change); reopen of a vanished file; close during the backoff.
- `unit.ssh`: secret cache round trip (the blob never holds the plain secret; TM-R05 gate) and repeated
  connects on one object.
- `interop.ssh` (4 new): reconnect with the pinned key (ACCEPT_ONCE); secret cache across reconnects including
  the TM-R05 rule and `clear_secrets`; host key mismatch on reconnect (then the pinned key after the store was
  emptied); run-time keepalive tuning.
- `interop.sftp_ssh` (new, `sd-test-sftp-ssh-interop.exe`, sd_sftp over sd_ssh against the fixture): two
  channels; **sshd killed during a 256 MiB pipelined read and during a 256 MiB pipelined write** (8 x 4 MiB in
  flight) and restarted: the session comes back in generation 2, the handle is reopened, the transfer finishes
  from the last contiguous offset, and SHA-256 is compared with `sha256sum` in WSL; a TCP drop with the
  listener alive; a frozen link (sessions SIGSTOPped) detected by the liveness probe after a 2 s request
  timeout (about 7 s in total: no RTT sample yet, so the probe window is 5 s). It shares
  `RESOURCE_LOCK wsl_sshd_fixture` with `interop.ssh`.
- Fault injection: `tests/fixtures/wsl-sshd/ctl.sh` (and `ctl.ps1`) with `kill | start | restart | drop |
  freeze | reap | thaw | status`. It touches only the fixture listener (pid file) and the processes below it.
- The fixture also listens on the WSL VM address in NAT mode (`direct_host` in `state/env`) and both
  `interop.ssh` and `interop.sftp_ssh` connect there: killing sshd during a 256 MiB transfer through the
  Windows localhost relay (`wslrelay`) wedged the relay forwarder for port 2222 once (connections are
  accepted, nothing is forwarded, until WSL restarts). `SD_SSHD_VIA_RELAY=1` forces `127.0.0.1`.

## sd_vfs / sd_dokan: caches, read-ahead, write modes, reconnect, identity

Implements 02 §3.4, §4.1-§4.4, §5.1-§5.3 and D9/D10 in `src/sd_vfs/` (new files `vfs_cache.c` memory
tier, `vfs_disk.c` disk tier, `vfs_data.c` data path; `vfs_core.c`, `vfs_ops.c`, `vfs_req.c` adapted).
`sd_dokan` needed no change. Header additions are appended fields and new functions only.

### API additions (`sd_vfs/sd_vfs.h`)

| Addition | Meaning |
|---|---|
| `sd_vfs_cache_set_budget(bytes)`, `sd_vfs_cache_get_stats()` | Process-wide memory tier (`settings.ini [cache] memory`); 0 = min(256 MB, RAM/16), floor 16 MB. sd_mount calls it at start (see Integration). |
| `sd_vfs_options.known_identity` | Definitive identity the host cached per server identity (02 §3.4 step 2); NULL = learn. |
| `sd_vfs_get_identity()` | Current identity (`definitive` once the first created object confirmed it). |
| `sd_vfs_event.detail` | English reason for `NOTICE` (for example why `disk_cache_refused`). |
| Options accepted now | `write_mode = behind`, `disk_cache_mb` + `disk_cache_dir`, `max_readahead`, `wb_window`, `wb_window_mount`, `offline_wait_ms`, `reconnect_grace_ms` (0xFFFFFFFF = no grace). Still `SD_VFS_E_UNSUPPORTED`: `global_mount`, `mark_of_the_web`, `remote_codepage`. |
| Events | `WRITE_FAILED` (path = mount-relative display path, bytes lost, the sticky status; once per error and node; never in write-through mode), `STATE` (`change_kind = SD_SFTP_ST_READY` when the vfs synced to a new generation), `IDENTITY` (also when a new generation's server_info changes the provisional uid). |
| `sd_vfs_stats.write_failed`, `.reconnects` | Now filled. |

### Data cache and read-ahead

- Memory tier: 256 KiB blocks, 16 shards (one `sd_mutex` each), LRU, key (mount id, file id, validator
  generation, block index). A validator change bumps the node's generation and reclaims the old blocks.
  A shard lock is the innermost lock (taken after `v->lock`, never before it); completions never take it.
- Validator (02 §4.2): the node keeps the server `(size, mtime)` its blocks were fetched under. Server
  attributes that differ drop the blocks. After our own writes the mtime is "pending": the next server
  attributes are adopted without dropping when the size matches our view. Hot blocks (validator mtime
  within 2 s of the estimated server clock; the skew is learned from objects we create) expire after
  `attr_ttl` and are never written to disk. Local writes update cached blocks on submission in both modes;
  a failed write drops the affected blocks.
- Read-ahead per handle (02 §4.3): sequential when `off == ra_next`; the window starts at 256 KiB (2 MiB
  with `FILE_SEQUENTIAL_ONLY`), doubles per sequential read up to `max_readahead` (8 MiB), resets on a
  random access; `FILE_RANDOM_ACCESS` disables it. It tops up when less than half a window is left ahead.
  Sizing from `sd_sftp_session_stats()` (R16) is not done; doubling only.
- Single-flight (02 §4.1): a block being fetched is listed on its node; concurrent misses wait for it and
  exactly one thread turns the result into a cache block (short reads not at EOF are completed there).
  Read-ahead blocks have no waiter: their batch only signals (review §4.1 rule 1) and the block is
  processed when a reader reaches it. Unconsumed read-ahead blocks are released at the last close (at most
  one window per handle).
- Disk tier (02 §4.2, TM-R29). Checks before enabling: the directory is opened with
  `FILE_FLAG_OPEN_REPARSE_POINT` and refused if it is a reparse point; its owner must be the mount owner
  (SYSTEM or Administrators for service mounts); every allow ACE that grants more than
  `SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES` must be for the owner, SYSTEM (Administrators for
  service mounts) or an inherit-only CREATOR OWNER; the volume must report `FILE_PERSISTENT_ACLS`. The
  volume root is derived from the path (`C:\` or `\\server\share\`) because `GetVolumePathNameW` is not in
  the XP floor list; a volume mounted in a folder of another volume is therefore judged by the outer one.
  Files: `<hex SHA-256(host key fingerprint, NUL, remote path)>.dat` (sparse) and `.hdr` (magic,
  validator, last use, block bitmap), `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, no explicit security
  descriptor (inherits the protected DACL), the data file opened without `FILE_SHARE_DELETE`. Trim at mount
  and every 60 s, LRU by last use, using logical file sizes (`GetCompressedFileSizeW` is not in the XP
  floor list either; logical sizes trim conservatively). An I/O error disables the tier for the session.
  sd_vfs creates nothing outside the directory it is given.

### Write modes (D9, 02 §4.4)

- Write-through (default): as in M0, plus the cache updates. The wait for an overlapping in-flight extent
  is now a condition wait (per-node waiter list, one event per waiter, XP-compatible) instead of the
  `Sleep(1)` poll. A chunk lost with `session_ready = 1` is resubmitted once on the same handle. A write
  that ends with `DISCONNECTED` or `TIMEOUT` records "the size may include this extent" for the identity
  check after reconnect.
- Write-behind (opt-in): data is copied into the node queue (window 16 MiB per node, 64 MiB per mount;
  the writer blocks on a full window until acks arrive). Sequential writes are sent at once, others
  coalesce for up to 500 ms or 1 MiB; no two overlapping extents are in flight. Reads overlay the queued
  data and see the local size. The first failed ack is sticky until the last handle closes; cleanup drains
  synchronously and raises `WRITE_FAILED` for a sticky error. On a disconnect, unacknowledged and unsent
  extents wait up to `reconnect_grace` (60 s) and are retransmitted after the identity check; expiry, a
  failed check or the end of the quiesce budget give sticky `DISCONNECTED` / `STALE` plus `WRITE_FAILED`.
  A handle opened with `FILE_WRITE_THROUGH` writes through (after draining the node's queue).
- Background timer per mount (`CreateTimerQueueTimer`, 100 ms; only with write-behind or the disk tier):
  coalescing deadlines, ack reaping, grace expiry, retransmission, disk trim. Stopped first at unmount.

### Reconnect (02 §5)

Integrated directly against the sd_sftp contract of the previous section (no adapter was needed):
`sd_sftp_session_generation()`, `sd_sftp_file_get_info().stale`, `sd_sftp_file_reopen()`.
- sd_vfs does not need the session events (sd_mount keeps the callback): it notices a new generation on
  the next data operation or timer tick and re-reads `server_info` (limits, identity).
- Lazy re-open on the first use of a node after the reconnect, single-flight per node, with the identity
  check (size adjusted for acknowledged writes; widened by extents that may have executed, and then the
  mtime is not compared). Mismatch: the blocks are dropped and read handles see the new content; with
  unacknowledged write-behind data the node is conflicted (`SD_VFS_E_STALE`, `STATUS_FILE_INVALID`,
  `WRITE_FAILED`). File gone: `SD_VFS_E_STALE`.
- While disconnected: cached blocks are served as they were at the disconnect; a miss waits up to
  `offline_wait` (3 s), then returns `SD_VFS_E_DISCONNECTED` (`STATUS_CONNECTION_DISCONNECTED`); writes,
  truncation and opens with write access fail at once with the same status.

### Identity (D10, 02 §3.4)

Provisional uid/gid from `server_info.identity` (the home owner; unknown when the home is owned by uid 0),
made definitive by the attributes of the first file or directory the mount creates (the gid only when the
parent has no setgid bit). `SD_SFTP_ID_EXEC` counts as definitive. Re-read on every generation until
definitive.

### Other changes

- Node eviction pops an idle-node LRU (nodes without references) instead of sweeping the whole table.
- `SD_E_STALE_HANDLE` is handled by re-opening; it maps to `SD_VFS_E_STALE` only when that fails.
- Metadata TTL defaults were already those of 02 §4.1 (30 s / 30 s / 10 s, 300 s for probe names,
  revalidate on open-for-data after 1 s, statvfs 30 s); unchanged. Deviation kept from M0:
  `open_revalidate_ms = 0` means the default (1 s), not "always" (use 1).

### Tests

`unit.vfs` gained 17 tests (`tests/unit/sd_vfs/test_vfs_m1.c`). The fake sd_sftp gained a pipelined
per-request latency, held writes, disconnect/reconnect with generations and stale handles,
`sd_sftp_file_reopen`, remote overwrite/mtime hooks and a separately owned home directory.
- 4 KiB sequential reads with 10 ms simulated latency: about 290-400 MiB/s with read-ahead (target
  >= 50 MiB/s), about 15 MiB/s with `FILE_RANDOM_ACCESS` (block cache alone; M0 made one round trip per
  4 KiB read).
- Single-flight (8 concurrent misses, one wire read); coherency by validator (size, mtime, hot blocks);
  local writes into cached blocks; write-behind (queue, read overlay, coalescing, window backpressure,
  sticky error with one `WRITE_FAILED`, grace retransmit after reconnect, grace expiry, conflict after
  reconnect); write-through failing the call on a disconnect; offline cache service and lazy reopen;
  change detected at reopen; identity (shared home, root-owned home, host-provided); disk tier (persists
  across mounts, validator change, refusal for a DACL granting Everyone, a missing directory and a
  junction, trim to the limit).
- `dokany.mount` still passes with the real Dokany 2.3.1. Both presets, Release and Debug, warning-free;
  `x64-analysis` is clean for the sd_vfs and sd_dokan sources and their tests.

### Open items

- (Done in Integration: sd_mount sets the budget and passes the disk cache, grace, offline wait and
  the cached identity.)
- Offline waits poll the session state every 50 ms instead of submitting with `SD_SFTP_REQ_WAIT_READY`
  (works with the fake and the real session; switch when convenient).
- Retransmission after the last handle closed keeps the stale handle and re-opens it. If the node had no
  write handle at the disconnect, the fresh open does no identity check. After a rename with queued data
  the reopen (old path) fails and the data is reported lost.
- Not implemented: `SD_VFS_EV_CHANGE` on refreshed listings (02 §4.1 change detection) with its
  `DokanNotify*` forwarding; `DokanResetTimeout` on progress (drains stop at the request deadline and leave
  the rest to the timer); read-ahead sizing from session statistics; the striping policy (M2 pool).

## sd_webdav (WebDAV backend, 02 §7)

Local HTTP/1.1 + WebDAV server over `sd_vfs`, mapped through the built-in Windows WebDAV redirector
(WebClient). Module `src/sd_webdav/` (public header `sd_webdav/sd_webdav.h`), tests in
`tests/unit/sd_webdav/`, wiring in `sd_mount`, `shelldrive-host` and `shelldrive`.

### What is implemented

- **Listener** (`wd_server.c`): `127.0.0.1:0` plus the same port on `[::1]` (rebinds both when `::1` cannot
  take it), `SO_EXCLUSIVEADDRUSE` before `bind` with no shared-bind fallback, non-inheritable sockets,
  `TCP_NODELAY`. One accept thread, one thread per connection, at most 64 connections. One process-wide
  server for `sd_mount` (`sd_webdav_mount_start/stop`, refcounted); tests use the lower-level
  `sd_webdav_server_*` / `sd_webdav_export_*` API.
- **Gate before authentication**, in this order: head limits (request line 8 KiB -> 414, head 32 KiB / 64
  fields -> 431, obs-fold / bare LF / CL+TE / differing CLs -> 400, non-chunked TE -> 501), `Host` exactly
  `localhost:PORT` / `127.0.0.1:PORT` / `[::1]:PORT` once (else 400 + close), `Origin` or any `Sec-Fetch-*`
  (403 + close, no challenge, before the token check), request-target decoding (TM-R12 rules, 400),
  `OPTIONS` (unauthenticated, `DAV: 1, 2`, `MS-Author-Via: DAV`, `Allow` without write methods on read-only
  exports), token prefix `s-<26 base32>` compared in constant time (unknown -> 404, no challenge), then
  Negotiate/NTLM. Nothing else (body, `If`, `Destination`, `Range`, XML) is parsed before that; an announced
  body is drained unparsed up to 64 KiB (never with `100 Continue`), otherwise the connection closes after
  the 401.
- **Pre-authentication limits (TM-R20)**: head within 10 s of accept or of the previous response,
  authentication within 30 s, <= 8 unauthenticated connections, <= 4 per client process (owner PID of the
  loopback peer from `GetExtendedTcpTable`, IPv4 and IPv6 tables), the WebClient service process (PID from
  `QueryServiceStatusEx`, cached 5 s) exempt and never evicted, the oldest other unauthenticated connection
  evicted when the global limit is hit. Authenticated keep-alive idle 120 s. All configurable in
  `sd_webdav_server_cfg` for tests. Closes are lingering (300 ms drain) so a final 4xx is not lost to a reset.
- **SSPI** (`wd_auth.c`): `secur32!InitSecurityInterfaceW` resolved at run time (by System32 path), one
  inbound `Negotiate` credential, one context per TCP connection (`ASC_REQ_CONNECTION`), raw `NTLM` tokens
  accepted through Negotiate. On `SEC_E_OK`: `QuerySecurityContextToken` -> `TokenUser`, `EqualSid` with the
  owner SID (default: the process user), else 403 + close. The connection then stays authenticated; a
  new `Authorization` on it re-runs the exchange. `BasicAuthLevel` and every other WebClient setting are
  never touched.
- **Methods** (`wd_methods.c`): `PROPFIND` depth 0/1 (missing/infinity -> 403 `propfind-finite-depth`;
  allprop / empty body, `prop`, `propname`; live props, `Win32FileAttributes` and `Win32*Time`,
  `supportedlock` on the target, `lockdiscovery` when locked, RFC 4331 quota on the mount root, 404 propstat
  for unknown props; `PROPFIND /` lists no members), `PROPPATCH` (`Win32LastAccessTime` /
  `Win32LastModifiedTime` -> `sd_vfs_set_times`, `Win32FileAttributes` -> `sd_vfs_set_winattrs`,
  `Win32CreationTime` and dead properties reported 200 and discarded), `GET` / `HEAD` (single `Range` ->
  206, unsatisfiable -> 416, multi-range -> 200, `If-Range`, `If-None-Match`, `If-Modified-Since`, headers
  sent before the body is read), `PUT` (streamed into `sd_vfs_write` as it arrives, chunked and
  `Expect: 100-continue` after auth, `If-None-Match: *` -> create-only, 201/204), `DELETE` (recursive),
  `MKCOL` (body -> 415, parent missing -> 409, exists -> 405), `MOVE` (same authority and token, else 502;
  `Overwrite`; a directory destination is deleted first), `COPY` (depth 0/infinity, streamed through the
  vfs because `sd_vfs_copy_path` is not implemented yet), `LOCK` (exclusive and shared write locks,
  `Timeout` capped at 3600 s, refresh through `If`, LOCK on an unmapped URL creates an empty file -> 201),
  `UNLOCK` (204 / 409). Write methods honour locks (423 without a matching token in `If`). Other methods:
  405 (`POST`, `PATCH`, ...) or 501. Error mapping follows 02 §7.5 (503 carries `Retry-After`).
- **Own parsers** (`wd_http.c`, `wd_xml.c`, `wd_util.c`): HTTP head parser and chunked decoder (chunk-size
  line <= 32 bytes), XML parser (namespace-aware, no DTD at all, only the five predefined entities and
  numeric references, depth <= 32, <= 8192 elements, <= 1 MiB, strict UTF-8), base64, base32 tokens (130
  bits from `RtlGenRandom`), RFC 1123 / RFC 3339 dates, `Range`, `Timeout`, `If` lock tokens, `Destination`.
  The request path (it carries the token) is never logged; debug logs carry the method and status only.
- **WebClient** (`wd_client.c`): `sd_webdav_query_client()` is a read-only SCM query (used by backend
  selection, TM-R21); `sd_webdav_ensure_client()` tries `StartService`, then (7+) writes an event of the
  trigger provider `{22B6D684-FA63-4578-87C9-EFFCBE6643C7}` (`EventRegister`/`EventWrite`, resolved at run
  time), then polls up to 10 s. It is called only after a mount resolved to WebDAV.
- **Mapping**: `WNetAddConnection2W` without `CONNECT_UPDATE_PROFILE`, Vista+ remote name
  `\\localhost@PORT\DavWWWRoot\s-<token>`, XP `http://localhost:PORT/s-<token>` with provider
  `Web Client Network`. `_LabelFromReg` is written to both MountPoints2 key forms (see below) and removed at
  unmount. `sd_webdav_cleanup_mappings(keep_port, only_port)` cancels this logon session's
  `\\localhost@<port>\[DavWWWRoot\]s-<26>` and XP-form connections and their MountPoints2 entries: the agent
  calls it at start before anything binds (TM-R17 d), `sd_webdav_mount_start` again before the first bind,
  and watchers can pass `only_port`. `sd_webdav_emergency_unmap()` (no allocation) is for the crash filter.
  The installer limits are read at server start and logged when still at their defaults.
- **Backend selection** (`sd_mount`, 02 §10.1): `sd_mount_params.backend` (`auto` = 0, `dokany`, `webdav`).
  `auto` takes Dokany when `sd_dokan_probe()` is OK, else WebDAV when WebClient is present and not disabled;
  forced backends never fall back. Failure codes: `backend_unavailable` (no Dokany and no/unstartable
  WebClient), `webclient_disabled`. WebDAV mounts get `request_timeout_ms = 50000` (Dokany 25000).
  `sd_mount_backend` grew five entries (`webdav_*`); `NULL` entries mean "no WebDAV" (the M0 bring-up backend
  and older fakes keep working). `sd_mount_backend_kind_used()` feeds the agent's `backend` field in `list`
  and mount JSON. IPC `mount` accepts `"backend": "auto" | "dokany" | "webdav"`.
- **CLI**: `shelldrive mount ... --backend auto|dokany|webdav`; new strings `cli.help.opt_backend`,
  `cli.error.webclient_disabled` (remedy `sc config WebClient start= demand`) and
  `cli.error.webdav_unavailable` (remedy `sc start WebClient`, WebDAV Redirector feature on Server), in all
  six locales. `backend_unavailable` with a WebClient detail prints the WebDAV message.

### Verified on this machine (Windows 11 IoT Enterprise LTSC 2024, 10.0.26100, non-elevated)

- WebClient is installed, start type Manual (demand) with the ETW trigger, stopped by default. The trigger
  event written by a standard (filtered) token starts it within a second; `StartService` is denied
  (`IU` has no `RP` in the service DACL). No administrator and no setting change were needed.
- All of these remote names map and serve files: `\\localhost@PORT\DavWWWRoot\s-<token>` (used),
  `\\localhost@PORT\s-<token>`, `\\127.0.0.1@PORT\DavWWWRoot\s-<token>` and `http://localhost:PORT/s-<token>`.
  `net use` and Explorer report the connection as `\\localhost@PORT\s-<token>` (DavWWWRoot dropped), so
  Explorer reads the label from `MountPoints2\##localhost@PORT#s-<token>`; both key forms are written and
  cleaned, and the stale-mapping matcher accepts both.
- Requests the redirector sent during the integration test: OPTIONS, PROPFIND (depth 0 and 1; 2-leg
  Negotiate per connection), HEAD, GET, PUT (0-byte create then content), LOCK/UNLOCK around every write,
  PROPPATCH (Win32 times/attributes), MOVE, DELETE, MKCOL. No `Origin`/`Sec-Fetch-*` headers.
- `FileSizeLimitInBytes` (here the default 50,000,000) limits **downloads only**: a 64 MiB upload through
  the drive succeeds and reaches the vfs intact, while opening a 64 MiB file that is not in the redirector
  cache fails with `ERROR_FILE_TOO_LARGE` (223). The integration test asserts exactly that and does the
  download round trip with 49,999,999 bytes; with the installer's `WEBDAV_TUNING` it does the full 64 MiB.
- End to end with the real stack: `shelldrive mount --host <user>@<wsl>:2222 -i <key> --backend webdav` ->
  `P:` mapped, `dir`/write/read/rename through the drive land on the SFTP server, `list` reports
  `"backend":"webdav"`, `unmount` removes the mapping and labels.

### Deviations and decisions

- The UNC form is the design's; the label goes to both MountPoints2 forms (observed normalization above).
- Locks are keyed by vfs path (case-insensitive) and re-keyed by MOVE, not by vfs node (sd_vfs exposes no
  node identity); they take no vfs share registration yet (coexistence with a Dokany mount of the same path
  in one process is therefore not enforced).
- `If` headers are used only to find submitted lock tokens; a non-matching `If` condition is not a 412.
- The XML parser keeps the character data of an element up to its first child (WebDAV bodies have no
  meaningful mixed content); `owner` is echoed as `<D:href>` text.
- `sd_webdav_ensure_client()` runs on the host control thread and can block it for up to 10 s.
- `tests/unit/sd_webdav` is added from `src/sd_webdav/CMakeLists.txt` (`add_subdirectory` with an explicit
  binary dir) so the shared `tests/CMakeLists.txt` list stays untouched; move it into that list with the
  next foundation change. The only shared-file change is the root `add_subdirectory(src/sd_webdav)` line.
- XP floor: secur32 (`InitSecurityInterfaceW`), iphlpapi (`GetExtendedTcpTable`), `QueryServiceConfigW`,
  `WNetOpenEnumW`/`WNetEnumResourceW`/`WNetCloseEnum` and the ETW functions are resolved through
  `sd_platform_resolve_by_name`, because the bootstrap XP floor list does not list them (all but ETW exist
  on XP x64 SP2). Adding them to `tests/os-imports/xp-sp2-x64.txt` would let them be imported; review item.

### Tests

- `unit.webdav` (`sd-test-webdav.exe`, 17 tests): HTTP head parser and every limit, chunked decoding byte
  by byte, request-target decoding (35 rejected targets: `%2F`, `%5C`, `%00`, controls, dot segments in any
  case, overlong/surrogate/out-of-range UTF-8, malformed escapes, `//`, query, fragment), href encoding,
  tokens, `Host` / DNS rebinding, `Destination`, XML parser and its rejects (DTD, entities, depth 33, 1 MiB,
  undeclared prefix, ...), base64 / dates / Range / Timeout / If; then the real server over raw loopback
  sockets with client-side SSPI: OPTIONS, 404-before-401, 401 with both schemes, body before auth (drained
  vs. closed), Origin and Sec-Fetch 403 without challenge, bad Host, 431, full Negotiate login and every
  method against the fake-backed vfs, owner-SID mismatch -> 403 (server owned by LocalSystem), read-only
  export, slowloris header and auth deadlines, per-process quota, IPv6 loopback.
- `webdav.redirector` (label `webdav`, `sd-test-webdav-redirector.exe`, exit 77 when WebClient is missing,
  disabled or not startable): starts WebClient, maps a free letter through the real redirector, listing,
  free space, create/overwrite/read, rename with a non-ASCII name, delete, directories, the 64 MiB upload and
  the download round trip with FNV checksums against the fake backend, `_LabelFromReg` in both key forms,
  stale-mapping cleanup by port; then probes the four UNC forms and prints the methods seen.
- `unit.mount`: `mount_backend_selection` (auto -> Dokany without touching WebClient, auto -> WebDAV without
  Dokany, forced webdav, forced dokany without fallback, disabled / missing / not-startable WebClient,
  request timeouts per backend).
- Green on x64-modern and x64-xp (Release and Debug), x86-sse2 (WebDAV targets) and the WebDAV targets under
  x64-analysis; import audit green on both x64 flavours.

### Gaps (not done in M1 by this module)

- Token-only fallback (TM-R19), partly done in r10 (branch wip/r10-tokconsent): the question
  `webdav_token_only` through the prompt broker (CLI y/N, UI dialog), per-enable consent, the no-SSPI trigger
  (`SD_WD_E_AUTH_UNAVAILABLE`, exit 4), plumbing `token_only` / `token_only_confirmed` into sd_mount and the WebDAV
  cfg, and tests (sd_mount, agent broker). Still open: the WinHTTP autologon-LOW self-test that detects a
  redirector authentication failure (02 §7.4), and the "redirector prompted for credentials" detection. No profile
  key exists for token-only, so the answer is asked per enable. The CLI answer is covered end to end by the apps smoke tests
  (`smoke_webdav_token_only_cli_yes`, `_cli_refused`, `_prompt_none`; r12), which drive the console y/N over `--stdin`.
- Watchers (TM-R17 c, e): the API exists (`sd_webdav_cleanup_mappings(0, port)`) but there is no
  long-running CLI/tray to watch the agent. (The crash filter and the cleanup at stop are wired; see
  Integration.)
- No notification when the user disconnects the drive from Explorer (the mount stays "mounted").
- `offline_hint_over_mb`
  (D22), `atomic_put`, shell-active `GET` is enforced by the vfs (403 via ACCESS_DENIED) without a dedicated
  test, Office FrontPage probes are plain 404s (untested with Office).
- Global (service) WebDAV mounts (7.7), multi-user TST-09/TST-10 lab runs, XP (http form, port, LOCK) and
  Windows 7/8/10 behaviour are unverified here.

### M1 remainder: replacing MOVE locks and the negative cache (r13, `wip/r13-davmove`)

Spec: `docs/design/02-filesystem.md` §7.5 "Locks across a replacing MOVE" and §7.6 "Negative cache".

- **Replacing MOVE drops the destination lock: fixed.** `m_move_copy` called `wd_lock_drop_tree(dv)` after a
  replacing MOVE, which removed the lock the Office save holds on the document, so the final `UNLOCK` got 409.
  Decision: the lock on the destination URL survives the replacing MOVE (same token, same timeout), because the
  client holds it and the URL now names the moved resource. Locks below a replaced collection go with its
  children; a lock on the source URL moves with the resource unless the destination already has one (the
  destination lock wins, so one URL never needs two tokens). `wd_lock_replace` implements this; `COPY` with
  `Overwrite: T` keeps the destination lock and uses `wd_lock_drop_below`. The lock manager keys locks by vfs
  path, not vfs node: the comments and the 02 text said node.
- **Tests** (`unit.webdav`, `tests/unit/sd_webdav/test_server.c`): `webdav_server_office_save_sequence` (LOCK,
  temp PUT, MOVE 423 without a token and with a wrong token, MOVE 204 with `If:`, PROPFIND shows the lock, GET
  content, UNLOCK 204 and 409, plain PUT 204, two cycles); `webdav_server_replacing_move_drops_replaced_children_locks`
  (a MOVE of a collection onto a locked child: 423 without the token, 204 with it, the replaced child's lock gone);
  `webdav_server_link_down_miss_is_503_not_404` (the negative-cache mitigation below).
- **Negative cache (`FileNotFoundCacheLifeTimeInSec`, 60 s).** WebClient answers "not found" for a name from its
  own cache after a failed lookup, without a request. A rename or create made on the server after that is not
  visible on `P:` for up to 60 s (acceptance, `m1-acceptance.md`). The server cannot clear that cache.
  - Mitigated: a miss while the link is down is `503` + `Retry-After: 10` (vfs `DISCONNECTED`), never `404`.
    The redirector retries rather than caching a miss.
  - Not mitigated, open: the vfs answers from its own negative cache while the link is down and reports
    `NOT_FOUND`, so a `404` still reaches the redirector in that window. Closing it needs the session state in
    `sd_webdav_export_cfg` (`sd_sftp_session_state`, which `sd_vfs` does not expose per connection). Owner:
    `sd_mount` wiring; not implemented here.
  - User-facing: a name the user sees missing right after a change made elsewhere can stay missing for about
    60 s. Waiting is the only fix on the drive; `shelldrive refresh` drops the vfs TTLs, not WebClient's cache.
  - CLI and agent: they work through the agent (sd_vfs and IPC), never through the drive letter, so they do not
    fill the redirector cache. `sd_mount` maps the letter only after the vfs is mounted and the export is listening.
- **Build/test:** `ci-local -Presets x64-modern -ReleaseOnly -NoFixture -TestRegex webdav`: `unit.webdav` and
  `webdav.redirector` pass, no compiler warnings in sd_webdav (Release, x64-modern). Debug, the x86 presets and the
  WebDAV lab runs were not run in this change.
- **Open:** real Office and LibreOffice saves against the lab mount (the 204 instead of 409 after the final
  UNLOCK; `[lab-verify]`), and the 60 s wait measured on Windows 7/10 with the link down.

## Integration (sd_mount, host, CLI wiring of the M1 modules)

Done when the four workstreams above were merged. Acceptance results: `docs/dev/m1-acceptance.md`.

### sd_mount

- Reconnect is on: `sd_sftp_options.reconnect` comes from `sd_mount_params` (enabled, 1 s initial, 60 s
  cap, unlimited attempts unless set), `channels` from `connection.channels` (default 2, D19), and
  `auth.cache_secrets_for_reconnect` is on (03 §3.4 default; TM-R05 is enforced by sd_ssh).
- State mapping after the first READY: `DISCONNECTED` / `RECONNECT_WAIT` / `CONNECTING` keep the mount
  `offline` (drive kept), `AUTH_REQUIRED` gives `auth_required`, the next `READY` puts it back to `mounted`
  without mounting the vfs or the backend again (that was the bug: a second READY ran the whole backend
  start again). `FAILED` after READY stays `offline` until the user unmounts (03 §1.11). Regression:
  `unit.mount` `mount_reconnect_keeps_drive`.
- `sd_mount_get_conn()` (session sub-state, attempt, backoff, generation, reconnects, offline time,
  write_failed count and last path) and `cb.on_conn` when it changes.
- `sd_mount_start` calls `sd_vfs_cache_set_budget([cache] memory)`. Passed to the vfs: `offline_wait_ms`,
  `reconnect_grace_ms`, `disk_cache_mb` + `disk_cache_dir`, `known_identity`.
- vfs events are posted to the control thread: `WRITE_FAILED` -> `cb.on_write_failed` (path, bytes,
  status code), `NOTICE` -> `cb.on_notice`, `IDENTITY` -> `cb.store_identity` once definitive. The host key
  fingerprint comes from `on_negotiated`. Regression: `mount_write_failed_and_identity`.
- Backend table gained `vfs_cache_set_budget`, `vfs_get_identity`, `webdav_emergency_unmap` (NULL = skipped).

### Host (agent)

- Per-source cache folder `%LOCALAPPDATA%\LibreStatic\ShellDrive\cache\<FNV-1a 64 of user@host:port>`
  created with the protected DACL (`sd_config_cache_dir`); the disk tier uses it when `cache.disk` > 0,
  and `identity.ini` there caches the definitive uid/gid with the verified host key (a different key never
  matches; `sd_config_identity_load/store`). FNV is a folder name, not a security boundary: the DACL is.
- `mount.state` events and `list` entries carry `"connection": {session, generation, reconnects,
  offline_ms, attempt, retry_in_ms, reason}`, `write_failed` and `last_write_failed`. A sub-state change
  re-sends `mount.state` with the same state.
- `warning {code, mount_id, data}` on the `mount` and `warning` topics: `write_failed` (path, bytes,
  status) and vfs notices such as `disk_cache_refused`.
- TM-R17: `sd_webdav_cleanup_mappings` at start (before anything binds) and again at stop after the
  mounts were torn down; `SetUnhandledExceptionFilter` calls `sd_webdav_emergency_unmap()` and chains to the
  previous filter (no crash dump yet, 03 §10.4). Watchers (TM-R17 c, e) still need a long-running client.
- `settings.ini` (M1 subset, `sd_settings_load`): `[log] level` and `[cache] memory`.

### sd_config and CLI

- Profile keys `mount.backend`, `mount.offline_wait`, `mount.reconnect_grace`, `cache.disk`,
  `connection.channels` (written only when set or already present). The IPC `backend` parameter
  overrides `mount.backend`.
- `shelldrive list`: an `offline` mount whose session is still trying shows "reconnecting"; mounts with
  lost write-behind data print one plural-aware line (`cli.state.reconnecting`, `cli.list.write_failed`,
  six locales). There is no separate `status` command yet; `list --json` carries the details.

### Other fixes

- `sd_sftp` (`sftp_session.c`): `x64-analysis` C6011 (possible NULL `r->f2` in the copy-data channel check;
  the analyzer did not correlate the two `OP_COPY` tests). One block now; no behaviour change.
- `interop.ssh` `interop_rekey_bulk`: the bound is now in bytes. Each key epoch can carry up to
  `rekey_bytes` plus one channel window (2 MiB) that the server sends before it sees our KEXINIT, so the
  test transfers 32 MB and requires at least `32 MB / (256 KiB + 2 MiB + 64 KiB)` volume rekeys (13) and
  more than 10 in total; slow builds land more of the window per epoch (8-9 rekeys for 12 MB on
  x86-ia32-debug), which the old count did not allow for.
- `sd_webdav` (`wd_methods.c`): a case-only MOVE (`Case.txt` -> `case.TXT`, what Explorer and
  `Rename-Item` send) answered 403 because the same-resource check compared case-insensitively; it is now a
  rename (201). A MOVE onto the identical URL stays 403. Regression in `unit.webdav` (found in acceptance).
- `sd_vfs` (`vfs_core.c`): `SD_VFS_EV_IDENTITY` was raised only when the first create changed the uid, so
  when the home owner's uid was merely confirmed the host never learned that the identity became
  definitive and never cached it. Now raised in both cases. Regression in `unit.vfs`.
- `cpucheck.refuses_without_sse2`: the fixture exits with `STATUS_ILLEGAL_INSTRUCTION` by design, which CTest
  reports as `***Exception: Illegal` and fails before `PASS_REGULAR_EXPRESSION` is evaluated. It now runs
  through `tools/sd-isacheck/expect_refusal.cmake`, which checks the text and the 0xC000001D status.
- `tools/ci-local.ps1`: under Windows PowerShell 5.1 a native stderr line became a terminating error, so a
  failing CTest run was reported as "Errors while running CTest" without its output; build and test now run
  with `Continue` and are judged by the exit code.
- Not changed (done in r14, see the r14 section below): the vfs offline wait still polled the session state every 50 ms. `SD_SFTP_REQ_WAIT_READY`
  would need a WAIT_READY queue in the unit tests' fake sd_sftp and a cancel path for quiesce; left for
  the vfs owner.
- XP floor: the import audit is green on every preset with sd_webdav's dynamic resolution of secur32,
  iphlpapi, the WNet enumeration and ETW; unchanged.

### M1 remainder: offline waits and negative entries while offline (r14, `wip/r14-offwait`)

Spec: `docs/design/02-filesystem.md` §5.2 (offline behaviour, `offline_wait`) and §7.6 (negative cache).

- **Offline wait is event-driven (`sd_vfs`, `vfs_data.c`).** `vfs_wait_online` no longer sleeps 50 ms in a loop.
  It submits one path operation (`realpath "."`) with `SD_SFTP_REQ_WAIT_READY` and `timeout_ms = offline_wait`;
  sd_sftp holds it until READY (then it runs at once) or its deadline, and the completion callback wakes the
  waiter. The request's token is kept per waiter. Each waiter has a heap object with two references (the
  waiter and the callback), so a waiter that gives up cancels its request and returns without waiting for the
  callback. Waits are bounded: `offline_wait` plus `VFS_WAIT_GRACE_MS`.
- **Cancel path.** `vfs_cancel_waits()` cancels every offline waiter; `sd_vfs_quiesce` and `sd_vfs_unmount` call
  it after setting `quiescing`, so a waiting read or write returns `SD_VFS_E_DISCONNECTED` at once instead of at
  its deadline. A waiter that starts after the quiesce flag is set is cancelled as soon as its token is
  published (both sides take `wait_lock`). Not wired: a close of one handle does not cancel another request's
  wait (a handle is closed by the client that is waiting on it, so there is nothing to cancel in practice);
  the WebDAV and Dokany request layers end a wait through the quiesce path only.
- **Behaviour change.** A waiter now also returns at once when sd_sftp fails the session (`FAILED`, `CLOSED`,
  reconnect stopped), because the request is refused without a callback or completes with the error. Before, it
  slept to the deadline in those states. 02 §5.2 already says the outage ends in `DISCONNECTED`.
- **Negative entries while offline (`vfs_core.c`, `lookup_child`).** Option chosen: the vfs reports
  `SD_VFS_E_DISCONNECTED` (not `NOT_FOUND`) for a cached negative entry while the session is not READY, whatever
  its age, and for a name absent from a cached listing while offline (which is not recorded as a negative
  entry any more). WebDAV already maps `DISCONNECTED` to `503` + `Retry-After`, so `sd_mount` wiring and
  `sd_webdav_export_cfg` do not change. The alternative (passing `sd_sftp_session_state` into the export config)
  would have needed a per-connection state accessor and a second source of truth for the same answer.
- **Not changed, open:** an unknown name (not cached) still fails at once while offline, as before. 02 §5.2 says
  lookups wait `offline_wait` with `WAIT_READY`; that is not implemented for lookups (a cache-miss probe would then
  stall for 3 s on every Explorer probe during an outage). Decide with the 02 owner. The 60 s WebClient cache of
  a miss that the server answered 404 while the link was up is unchanged (02 §7.6 (b)).
- **Tests.** `unit.vfs`: `vfs_offline_wait_completes_on_reconnect` (the wait ends right after `fake_reconnect`,
  not at its 5 s deadline), `vfs_offline_wait_cancel_returns_promptly` (quiesce ends a 10 s wait), and
  `vfs_offline_negative_lookup_is_disconnected` (online NOT_FOUND, offline DISCONNECTED, online NOT_FOUND again).
  `unit.webdav`: `webdav_server_cached_miss_is_503_while_link_down` (a 404 the vfs cached is 503 while down, 404
  again after READY). The fake sd_sftp (`tests/unit/sd_vfs/fake_sftp.c`) now holds WAIT_READY requests while not
  READY, completes them with `SD_E_TIMEOUT` at the deadline or `SD_E_CANCELLED`, and wakes on cancel. The tests
  use bounded waits (5 s to 10 s) and check the outcome, not a latency: a 50 ms poll and an event wake both pass
  "completes within 2 s", so the test does not show the poll is gone; that is shown by reading the code.
- **Build/test:** `tools/ci-local.ps1 -Presets x64-modern -ReleaseOnly -NoFixture -AllowSkip -TestRegex
  'vfs|webdav|sftp|mount'` (log in `build/agent-offwait.log`, not committed). Debug, x86 presets and the lab
  runs were not run here.
