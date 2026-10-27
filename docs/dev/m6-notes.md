# M6 notes: fuzzing, constant-time checks and nightly runs

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

Gate (every x86-ia32 Release build, `sd_crypto_ctcheck`, CTest `isacheck.ct_sd_crypto`):

- No call to a compiler helper from constant-time code (as before).
- DIV and IDIV are forbidden in constant-time-named functions (`*_ct_*`, `*_ct`, `sd_ct_*`).
- A **forward** conditional branch in those functions is reported, except a loop-entry guard (a forward branch that
  skips a loop whose back-edge lies inside the skipped region). Backward branches are loop back-edges; their bounds
  are public by 01 section 2.4 rule 1 and are not classified.
- Functions whose forward branches were reviewed and depend on public data only are listed in
  `tools/sd-isacheck/ct-branch-allow.txt` with the reason. The list is exempt from the forward-branch rule only.
  A change to a listed function needs its branches reviewed again.

Not implemented: secret-indexed memory operands, the 64x64 multiply sequence check, the x86-sse2 and ARM32 runs.

dudect-style timing (opt-in, once per release candidate and nightly on a quiet machine):

```
cmake -S . -B build/x86-ia32 -DSD_CT_TIMING=ON        # after cmake --preset x86-ia32
cmake --build build/x86-ia32 --config Release --target sd-ct-dudect
build\x86-ia32\bin\Release\sd-ct-dudect.exe            # all primitives, default samples (20000; RSA 4000)
build\x86-ia32\bin\Release\sd-ct-dudect.exe 1000000 X25519   # one primitive, a million samples per class
```

A |t| above 10 exits 1. A value above 4.5 at small samples means "rerun with more samples", not a leak. Confirm any
report on the lab machine before treating it as a leak (04 section 11.2 `ct.yml`).
