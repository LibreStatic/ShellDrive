# M0 foundation notes

Choices made while laying the M0 foundation where the design documents leave detail open, plus the
rules for the module agents that build on it. The design documents stay authoritative; these notes
record implementation detail and small deviations, each with its reason.

## Ownership: shared files vs. module files

Module agents edit only inside their own directories:

| Owner | Directories |
|---|---|
| crypto | `src/sd_crypto/`, `tests/unit/sd_crypto/`, `tests/vectors/` |
| ssh | `src/sd_ssh/`, `tests/unit/sd_ssh/` |
| sftp | `src/sd_sftp/`, `tests/unit/sd_sftp/` |
| vfs + dokan | `src/sd_vfs/`, `src/sd_dokan/`, `tests/unit/sd_vfs/`, `tests/unit/sd_dokan/` |
| apps / ipc / l10n | `src/sd_ipc/`, `src/sd_l10n/`, `src/sd_config/`, `src/sd_mount/`, `apps/`, `l10n/`, the matching `tests/unit/*/`, and `src/sd_base/json*.c` (the `sd_json.h` implementation; picked up by a glob in `src/sd_base/CMakeLists.txt`) |

Shared (foundation) files, changed only by a reviewed foundation change: the top-level
`CMakeLists.txt`, `CMakePresets.json`, `cmake/*`, `include/sd/*`, `res/*`, `src/sd_base/` (except
`json*.c`), `src/sd_platform/`, `tests/harness/`, `tests/CMakeLists.txt`, `tests/l10n/`,
`tests/importcheck/`, `tests/os-imports/`, `tools/`, `.github/`, `.vsconfig`, `.gitignore`.

Public headers are the contracts between agents. Change them additively; a breaking change to another
module's header needs that owner's agreement. Every listed public header is compiled standalone,
twice, on both toolsets (`<module>_hdrcheck` targets), so a header that stops being self-contained
breaks the build.

A module starts as an INTERFACE (header-only) target. Adding `SOURCES` to its `sd_add_module()` call
turns it into a static library; nothing else needs to change. Unit tests: `sd_add_unit_test(<short>
SOURCES ... DEPS ...)` in `tests/unit/<module>/CMakeLists.txt` (see `tests/unit/sd_base/` for the
pattern; the harness is `tests/harness/sd_test.h`).

## Layout and build

- Layout follows 04 §4. Public headers live in `src/<module>/include/<module>/` and are included as
  `"<module>/<header>.h"`. Header file names follow the 01/02/03 sketches (`sd_err.h`, `sd_buf.h`,
  `sd_utf.h`, `sd_crypto.h`, `sd_vfs.h`, `sd_ipc.h`, `sd_l10n.h`, ...).
- The import audit tool is `tools/sd-importcheck` (04's name; the M0 task called it "import-audit").
  It runs post-build on every `sd_add_app` target and again under CTest.
- The SDK 7.1A `ws2_32.lib` (x64-xp) imports the WinSock 1.1 set by ordinal (`closesocket` #3,
  `connect` #4, `recv` #16, `send` #19, `setsockopt` #21, `WSAGetLastError` #111, `WSAStartup` #115).
  `sd-importcheck` maps the frozen ws2_32/wsock32 ordinals (taken from the 7.1A import libraries,
  cross-checked against the DLL export tables; the two DLLs differ at 10-12) to names, so the floor
  list judges them by name; unknown ordinals stay `dll!#n` and need an explicit floor entry. CTest
  `importcheck.maps_winsock_ordinals` / `importcheck.lists_winsock_names` cover it.
- `tests/os-imports/*.txt` are **bootstrap** floor lists: `xp-sp2-x64.txt` is hand-curated from the
  documented minimum versions (conservative, per function); `win10-1507-x64.txt` allows whole system
  DLLs (still catches a dynamic CRT or foreign DLLs). Both must be replaced by the lab captures of
  04 §2.4 / §11.4. Adding a function to the XP list is a review item.
- Debug builds use `/MTd` (the static debug CRT); Release uses `/MT`. Debug adds a few kernel32 imports
  (all XP-safe, listed in the floor).
- `x64-analysis` builds Debug with `/analyze` and treats analyzer warnings as errors. ASan needs the
  `VC.ASAN` component (`-DSD_ENABLE_ASAN=ON`; it also drops CFG/CET for that build).
- Version: `VERSION` + git commit captured at configure time into `generated/sd/version.h` (re-run
  configure to refresh). FILEVERSION build number is `SD_BUILD_NUMBER` (CI run number, 0 locally).
- `/SUBSYSTEM:<kind>,5.02` is added for `x64-xp` apps only; `x64-modern` keeps the linker default.

## sd_base / sd_platform split (C39)

The M0 task listed allocation, logging, time and threads under sd_base; the dependency graph (00 §5)
and 01 §1 put them in sd_platform because they need `windows.h`. The graph wins:

- `sd_base` (no `windows.h`): `sd_err.h` (master `SD_ERR_LIST` X-macro, `sd_err_name`,
  `sd_err_from_name`), `sd_buf.h` (bounded reader/writer), `sd_utf.h` (UTF-8/16, stage-1 name mapping,
  `sd_text_sanitize_*`), `sd_checked.h`, `sd_mem.h` (allocator **declarations** + `sd_secure_zero`),
  `sd_json.h` (declarations only, see ownership).
- `sd_platform`: allocator implementation (process heap, failure-injection hook, `sd_secure_free` with
  `SecureZeroMemory`), `sd_platform_resolve`, OS version (`RtlGetVersion`), CPU features (+ `SD_CPU_MASK`
  env override), threads/mutex/event/once, `sd_tick_ms`, logging, `sd_secbuf`.
- `sd_base` therefore links `sd_platform` (INTERFACE); MSVC resolves symbols across static libraries in
  any order. A fuzz or host-only build of `sd_base` must supply its own `sd_alloc`/`sd_free`.

Details chosen here:

- `sd_err` names: the second column of `SD_ERR_LIST` is the IPC/JSON spelling (01 §10.2 special cases
  included); `SD_ERR_COUNT` terminates the enum; out-of-range values print `"unknown"`.
- `sd_rd_mpint` returns the magnitude without the sign byte and rejects negative and non-canonical
  encodings (including a non-empty zero). `sd_wr_mpint` takes an unsigned big-endian magnitude.
- Name mapping: invalid UTF-8 is escaped one byte at a time and decoding resynchronizes at the next
  byte; bytes -> UTF-16 -> bytes is exact for every byte string (unit-tested exhaustively for single
  bytes). Arbitrary UTF-16 that contains U+F780..U+F7FF maps back to raw bytes by design.
- `sd_text_sanitize_host` = server rules plus removal of TAB/CR/LF. The punycode display form (01 §6.1)
  is not done yet (IDN is M2).
- Logging format language (restricted printf): `%s %ls %c %d %u %x %lld %llu %llx %zu %p %%`;
  anything else prints `%?`. Strings are escaped and capped at 512 bytes, records at 4 KiB. M0 logs
  synchronously under one lock; 03 §10.1's logger thread replaces that without API change. The typed
  privacy fields (`host`/`user`/`rpath`, TM-R31) and `sd_dump_mark_sensitive()` (TM-R30) are not in
  the foundation yet; they belong in `sd_platform` (foundation change) before M0 ends.
- `sd_once` spins with `Sleep(1)` while another thread runs the initializer (no InitOnce on XP).
- `sd_tick_ms` uses `GetTickCount64` when present, else a lock-free 64-bit extension of `GetTickCount`
  (`_InterlockedCompareExchange64` intrinsic, so x86 XP also works later).
- Post-XP APIs: add an entry to `SD_API_LIST` (`sd_platform.h`) and a `sd_pfn_*` typedef to
  `include/sd/winapi_compat.h`. Non-kernel32/ntdll DLLs are loaded by full System32 path with
  `LOAD_WITH_ALTERED_SEARCH_PATH`. Apps call `sd_platform_harden_dll_search()` first in `main`.

## Header notes (deviations from the sketches)

- `sd_crypto.h`: M0 subset only (00 §6). `sd_hash_alg` values 0/1 are reserved for MD5/SHA-1 so later
  additions do not renumber; CPU bits come from `sd_platform` (`SD_CPU_*`), not from `sd_crypto`.
  Raw `sd_aes_gcm_*`, `sd_aes_ctr`, `sd_chacha20`, `sd_poly1305` are exposed for KAT/Wycheproof/CNG
  differential tests. Constant-time helpers are in `sd_crypto/sd_ct.h`.
- `sd_ssh`: split into `sd_ssh.h` (connection, channels), `sd_known_hosts.h` (stores, `sd_hk_status`,
  `sd_hk_result`, fingerprint helper), `sd_prompt.h` (prompt model, `sd_hostkey_prompt_info`,
  `sd_hostkey_decision`, which 01 references but does not define) and `sd_keyfile.h` (key files; no
  transport dependency, for the CLI/UI). The identity `kind` enum got a name (`sd_ssh_identity_kind`).
- `sd_sftp.h`: the path variant of statvfs is `sd_sftp_statvfs_path()` because 01 uses
  `sd_sftp_statvfs` for both a type and a function, which C does not allow. The sync wrappers needed by
  the CLI are declared explicitly; `sd_sftp_status_to_err()` is exported for the error-table tests.
- `sd_vfs.h`: `sd_vfs_attr`, `sd_vfs_symlinks`, `sd_vfs_case`, `SD_VFS_EOF`, the `SD_VFS_FILE_*`
  disposition/option constants and `sd_vfs_status_from_err()` are defined here (02 uses but does not
  define them). `sd_vfs_to_ntstatus()` is declared in `sd_dokan.h` (02 places it in sd_dokan).
- `sd_dokan`: `src/sd_dokan/dokan_abi.h` is private, written from the documented Dokany 2.x ABI with an
  `SD_` prefix (no upstream header copied). **Every layout and constant is `[lab-verify]` against a
  live dokan2.dll 2.3.1 before M0 sign-off.** The public header exposes probe, mount start/stop and
  stale-mount cleanup only.
- `sd_ipc.h`: pipe and kernel-object names per D45 as macros; error struct carries `sd_err` plus the
  code string; handlers return `sd_err`; `sd_ipc_broadcast` takes encoded JSON. `sd_json` itself is
  declared in sd_base.
- `sd_l10n.h`: `sd_l10n_init()` takes the binary's generated catalog (`&sd_l10n_catalog_<name>`)
  because each binary links its own merged set of domains. The table layout shared with the generator
  is `sd_l10n/sd_l10n_catalog.h` (strings indexed by CLDR category, not by PO index).

## Localization (sdl10n)

- PO sources live in `l10n/<domain>/<lang>.po` (04 §4 layout; 03 §9.1 writes `locale/<lang>/<domain>.po`
  — same content, the repository layout of 04 was used). Languages: `en es fr pt-BR it de`.
- `en.po` is the source of truth: `msgctxt` = stable id (`[a-z0-9_.-]`), `msgid`/`msgid_plural` =
  English one/other forms, `msgstr` left empty. Plural argument: `#, plural-arg=<name>` (default
  `count`).
- One catalog per binary: `sd_add_l10n_catalog(<name> DOMAINS ...)` in `l10n/CMakeLists.txt` generates
  `sd_l10n_<name>.c` and `<sd_l10n_<name>_ids.h>` (ids `SD_MSG_<MSGCTXT>`, dots to underscores) and the
  library `sd_l10n_catalog_<name>`. M0 has the `cli` catalog with four strings, complete in all six
  languages, linked by `shelldrive.exe`.
- Not yet implemented from 03 §9.2: dialog mnemonic scopes, hard length limits, the register lint,
  `.wxl`/ADML/STRINGTABLE outputs and the `qps` pseudo-locale (they land with the UI/installer work).
- `tests/l10n/` proves the failure modes (missing string, missing plural form, placeholder mismatch,
  wrong `Plural-Forms`) and that `--allow-incomplete` only relaxes missing strings.

## CI

- Actions pinned by SHA (verified with `git ls-remote` on 2026-10-24): `actions/checkout` v7.0.1
  `3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/upload-artifact` v7.0.2
  `cf430e030ddbb5b0abf93d22962f4752f3646cd9`.
- The XP job installs the toolset with the composite action `.github/actions/setup-xp-toolset`
  (04 §11.1); not yet run on GitHub, so its first run is the verification.
