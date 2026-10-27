# Flavour selection and compiler/linker flags. 04 §2.3, §3.1 and §3.2 are normative.
#
# SD_FLAVOUR is set by CMakePresets.json. Supported: x86-ia32, x86-sse2 (M1), x64-modern, x64-xp,
# x64-analysis, arm64 (04 §1.1), arm32 (best effort, D5; SDK 10.0.22621, D31).

set(SD_FLAVOUR "" CACHE STRING "Build flavour (x86-ia32, x86-sse2, x64-modern, x64-xp, x64-analysis, arm64, arm32)")
set_property(CACHE SD_FLAVOUR PROPERTY STRINGS x86-ia32 x86-sse2 x64-modern x64-xp x64-analysis arm64 arm32)
# Internal: the nested x64 configure that builds the build-time tools for an ARM64 or ARM32 tree (cmake/SdHostTools.cmake).
option(SD_HOST_TOOLS_ONLY "Internal: configure only the build-time tools for an ARM64 or ARM32 tree" OFF)
set(SD_X86_ARCH "" CACHE STRING "x86 flavours: code generation floor (IA32 or SSE2, decisions.md D4)")
option(SD_ENABLE_ASAN "x64-analysis: build with AddressSanitizer" OFF)
option(SD_ENABLE_ANALYZE "Run the MSVC code analyzer (/analyze)" OFF)
option(SD_FUZZ "Fuzz build (tests/fuzz): libFuzzer + AddressSanitizer on every module, v143 toolset, DLL CRT. Never shipped."
       OFF)
option(SD_L10N_ALLOW_INCOMPLETE
       "Developer escape hatch: build even when a locale lacks strings (falls back to en). Never in CI." OFF)
option(SD_L10N_QPS
       "Debug builds only: include the qps-ploc pseudo-locale (accented, +40 % length) for layout tests (03 §9.1)." ON)

if(SD_FLAVOUR STREQUAL "")
  message(FATAL_ERROR "SD_FLAVOUR is not set. Configure with a preset, e.g. cmake --preset x64-modern")
endif()

set(SD_X86 0)
if(SD_FLAVOUR STREQUAL "arm32")
  # 32-bit ARM (04 §1.1, §5.1): 4-byte pointers and 32-bit limbs (sd_ct64.h, bn.c). The pointer size is not
  # checked here: the arm32 presets skip CMake's compiler ABI probe (see CMakePresets.json), so it is unset.
  if(NOT CMAKE_VS_PLATFORM_NAME STREQUAL "ARM")
    message(FATAL_ERROR "arm32 is a 32-bit ARM flavour (-A ARM), got '${CMAKE_VS_PLATFORM_NAME}'.")
  endif()
elseif(SD_FLAVOUR STREQUAL "x86-ia32" OR SD_FLAVOUR STREQUAL "x86-sse2")
  set(SD_X86 1)
  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "${SD_FLAVOUR} is a 32-bit flavour (-A Win32), got a ${CMAKE_SIZEOF_VOID_P}-byte pointer build.")
  endif()
  if(SD_FLAVOUR STREQUAL "x86-ia32")
    set(_want_arch IA32)
  else()
    set(_want_arch SSE2)
  endif()
  if(SD_X86_ARCH STREQUAL "")
    set(SD_X86_ARCH ${_want_arch} CACHE STRING "" FORCE)
  elseif(NOT SD_X86_ARCH STREQUAL _want_arch)
    message(FATAL_ERROR "${SD_FLAVOUR} needs SD_X86_ARCH=${_want_arch}, got '${SD_X86_ARCH}'.")
  endif()
elseif(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "${SD_FLAVOUR} is a 64-bit flavour (got a ${CMAKE_SIZEOF_VOID_P}-byte pointer build).")
endif()

set(SD_TOOLSET "${CMAKE_VS_PLATFORM_TOOLSET}")
if(SD_TOOLSET STREQUAL "")
  set(SD_TOOLSET "${CMAKE_GENERATOR_TOOLSET}")
endif()

if(SD_FUZZ)
  # Fuzz builds run on the build host, so the XP floor (v141_xp, SDK 7.1A, _WIN32_WINNT 0x0501) does not apply.
  # The libFuzzer and ASan runtimes come with the v143 toolset (docs/dev/m6-notes.md lists the VS components).
  if(NOT SD_TOOLSET STREQUAL "v143")
    message(FATAL_ERROR "SD_FUZZ=ON needs the v143 toolset (-T v143), got '${SD_TOOLSET}'.")
  endif()
  if(SD_FLAVOUR STREQUAL "x64-xp")
    message(FATAL_ERROR "SD_FUZZ=ON is not compatible with the x64-xp flavour.")
  endif()
  set(SD_XP 0)
  set(SD_WINNT 0x0A00)
  set(SD_NTDDI 0x0A000000)
  set(SD_SUBSYSTEM_VERSION "")
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/win10-1507-x64.txt")
elseif(SD_X86)
  if(NOT SD_TOOLSET STREQUAL "v141_xp")
    message(FATAL_ERROR "${SD_FLAVOUR} needs the v141_xp toolset (-T v141_xp), got '${SD_TOOLSET}'.")
  endif()
  set(SD_XP 1)
  set(SD_WINNT 0x0501)        # XP SP3 x86 (04 §2.3)
  set(SD_NTDDI 0x05010300)
  set(SD_SUBSYSTEM_VERSION 5.01)
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp3-x86.txt")
  set(CMAKE_VS_GLOBALS "XPDeprecationWarning=false")
elseif(SD_FLAVOUR STREQUAL "x64-xp")
  if(NOT SD_TOOLSET STREQUAL "v141_xp")
    message(FATAL_ERROR "x64-xp needs the v141_xp toolset (-T v141_xp), got '${SD_TOOLSET}'.")
  endif()
  set(SD_XP 1)
  set(SD_WINNT 0x0502)        # XP x64 / Server 2003 SP1+
  set(SD_NTDDI 0x05020000)
  set(SD_SUBSYSTEM_VERSION 5.02)
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp2-x64.txt")
  # Silence MSB8051 ("targeting Windows XP is deprecated"): the XP flavours are deliberate (D28).
  set(CMAKE_VS_GLOBALS "XPDeprecationWarning=false")
elseif(SD_FLAVOUR STREQUAL "x64-modern" OR SD_FLAVOUR STREQUAL "x64-analysis")
  if(MSVC_VERSION LESS 1930)
    message(FATAL_ERROR "${SD_FLAVOUR} needs the v143 toolset, got MSVC ${MSVC_VERSION}.")
  endif()
  set(SD_XP 0)
  set(SD_WINNT 0x0A00)
  set(SD_NTDDI 0x0A000000)
  set(SD_SUBSYSTEM_VERSION "")  # linker default (6.00 for x64); floor enforced by setup (04 §3.2)
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/win10-1507-x64.txt")
elseif(SD_FLAVOUR STREQUAL "arm64")
  # Native ARM64 (04 §1.1, §2.5): v143 with SDK 10.0.26100, cross-compiled on an x64 host. Build only: no
  # ARM64 test runs on x64 machines (04 §11.4), and the build-time tools run from the x64 nested build.
  if(NOT CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
    message(FATAL_ERROR "arm64 needs the ARM64 platform (-A ARM64), got '${CMAKE_VS_PLATFORM_NAME}'.")
  endif()
  if(MSVC_VERSION LESS 1930)
    message(FATAL_ERROR "arm64 needs the v143 toolset, got MSVC ${MSVC_VERSION}.")
  endif()
  set(SD_XP 0)
  set(SD_WINNT 0x0A00)
  set(SD_NTDDI 0x0A000000)
  set(SD_SUBSYSTEM_VERSION "")  # linker default (6.00); the floor is Windows 10 1709 (04 §1.1, §3.2)
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/win10-arm64.txt")
elseif(SD_FLAVOUR STREQUAL "arm32")
  # Native ARM32 (04 §1.1, §5.1, D5, D31): v143 with SDK 10.0.22621, the last SDK with ARM32 libraries (VS2026 has
  # no ARM32 toolset). Cross-compiled on an x64 host; build only, no ARM32 test run on x64 machines (04 §11.4).
  # Best effort: CLI, agent and WebDAV only, so the UI and the shell extension are not built (SD_ARM32 below).
  if(NOT CMAKE_VS_PLATFORM_NAME STREQUAL "ARM")
    message(FATAL_ERROR "arm32 needs the ARM platform (-A ARM), got '${CMAKE_VS_PLATFORM_NAME}'.")
  endif()
  if(NOT SD_TOOLSET STREQUAL "v143")
    message(FATAL_ERROR "arm32 needs the v143 toolset, got '${SD_TOOLSET}'.")
  endif()
  if(NOT CMAKE_SYSTEM_VERSION STREQUAL "10.0.22621.0")
    message(FATAL_ERROR "arm32 needs CMAKE_SYSTEM_VERSION=10.0.22621.0 (SDK 10.0.26100 ships no ARM libraries), "
                        "got '${CMAKE_SYSTEM_VERSION}'.")
  endif()
  set(SD_XP 0)
  set(SD_WINNT 0x0602)        # 04 §2.3: the ARM32 header floor; behaviour is detected at run time
  set(SD_NTDDI 0x06020000)
  set(SD_SUBSYSTEM_VERSION 6.02)  # 04 §3.2 table
  set(SD_OS_FLOOR_LIST "${CMAKE_SOURCE_DIR}/tests/os-imports/win10-arm32.txt")
else()
  message(FATAL_ERROR "Unknown SD_FLAVOUR '${SD_FLAVOUR}'.")
endif()

# ARM64 and ARM32 targets cannot run on an x64 build host: the build-time tools (sdl10n, sd-admxgen, sd-importcheck,
# sd-payload) are then built by a nested x64 configure (cmake/SdHostTools.cmake).
# SD_ARM64 / SD_ARM32: the native ARM flavours. SD_ARM32 also leaves out the UI and the shell extension (04 §5.1).
set(SD_ARM64 0)
set(SD_ARM32 0)
set(SD_CROSS_HOST_TOOLS 0)
if(SD_FLAVOUR STREQUAL "arm64")
  set(SD_ARM64 1)
  set(SD_CROSS_HOST_TOOLS 1)
elseif(SD_FLAVOUR STREQUAL "arm32")
  set(SD_ARM32 1)
  set(SD_CROSS_HOST_TOOLS 1)
endif()

# Application manifest processorArchitecture (res/manifest/app.manifest.in): the flavour's architecture.
if(SD_X86)
  set(SD_MANIFEST_ARCH x86)
elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
  set(SD_MANIFEST_ARCH arm64)
elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "ARM")
  set(SD_MANIFEST_ARCH arm)
else()
  set(SD_MANIFEST_ARCH amd64)
endif()

set(SD_MODERN_SECURITY 0)
if(SD_FLAVOUR STREQUAL "x64-modern" OR (SD_FLAVOUR STREQUAL "x64-analysis" AND NOT SD_ENABLE_ASAN))
  set(SD_MODERN_SECURITY 1)    # /sdl, /guard:cf, /CETCOMPAT
endif()
if(SD_FLAVOUR STREQUAL "arm64" OR SD_FLAVOUR STREQUAL "arm32")
  set(SD_MODERN_SECURITY 1)    # /sdl, /guard:cf (04 §1.1); CET shadow stacks are x64 only, see SD_CET
endif()
# /CETCOMPAT (x64 only: the ARM64 and ARM32 linkers have no such option, 04 §1.1 and §3.2).
set(SD_CET 0)
if(SD_MODERN_SECURITY AND NOT SD_ARM64 AND NOT SD_ARM32)
  set(SD_CET 1)
endif()

# Static CRT everywhere (04 §3.1). Fuzz builds use the DLL CRT: the ASan and libFuzzer runtimes ship only in
# their clang_rt.*_dynamic and MD variants, and the static CRT would not match them.
if(SD_FUZZ)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
else()
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Drop CMake's default MSVC flags so ours are the only ones (/W3, /Ob, /RTC1 and friends).
foreach(cfg C_FLAGS C_FLAGS_DEBUG C_FLAGS_RELEASE C_FLAGS_RELWITHDEBINFO C_FLAGS_MINSIZEREL)
  set(CMAKE_${cfg} "")
endforeach()
foreach(kind EXE SHARED MODULE)
  foreach(cfg "" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)
    set(CMAKE_${kind}_LINKER_FLAGS${cfg} "")
  endforeach()
endforeach()
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

add_compile_definitions(
  UNICODE _UNICODE
  WIN32_LEAN_AND_MEAN NOMINMAX
  _WIN32_WINNT=${SD_WINNT} WINVER=${SD_WINNT} NTDDI_VERSION=${SD_NTDDI}
  SD_FLAVOUR_XP=${SD_XP}
  $<$<CONFIG:Debug>:SD_DEBUG=1>
  $<$<NOT:$<CONFIG:Debug>>:NDEBUG>)

# C compiler (04 §3.2). /we4013 /we4047 /we4024: implicit declarations and pointer mismatches.
add_compile_options(
  "$<$<COMPILE_LANGUAGE:C>:/W4;/WX;/utf-8;/Zi;/Gy;/Gw;/GS;/GF;/we4013;/we4047;/we4024;/Brepro>"
  "$<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Release>>:/O2>"
  "$<$<AND:$<COMPILE_LANGUAGE:C>,$<CONFIG:Debug>>:/Od>")
# Volatile semantics (04 §1.1, M6): /volatile:ms makes every volatile access an acquire load or release store.
# It is the default on x86 and x64 (no code change there); on ARM64 the default is /volatile:iso, which would
# leave the volatile flags and sequence counters of sd_state, sd_ipc and the shell extension unordered.
add_compile_options("$<$<COMPILE_LANGUAGE:C>:/volatile:ms>")
if(NOT SD_XP)
  # v143 compiles C as C11 (04 §2.3: both toolsets must accept the code; v141 has no /std flag).
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:/std:c11>")
endif()
if(SD_MODERN_SECURITY)
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:/sdl;/guard:cf>")
endif()
if(SD_X86)
  # x86 CPU floor (04 §3.2, D4): /arch:IA32 = x87 only, no SSE/SSE2 code generation; /arch:SSE2 is the
  # v141 default, spelled out. SD_X86_IA32 lets CMake lists (not #ifdef) drop SIMD translation units.
  # A target can override the flavour's value with the SD_X86_ARCH_OVERRIDE property (the x86-sse2 entry
  # thunk is always IA32; sd-isacheck fixtures); one /arch per command line avoids cl warning D9025.
  add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:/arch:$<IF:$<BOOL:$<TARGET_PROPERTY:SD_X86_ARCH_OVERRIDE>>,$<TARGET_PROPERTY:SD_X86_ARCH_OVERRIDE>,${SD_X86_ARCH}>>")
  if(SD_X86_ARCH STREQUAL "IA32")
    set(SD_X86_IA32 1)
  else()
    set(SD_X86_IA32 0)
  endif()
  add_compile_definitions(SD_X86_ARCH_${SD_X86_ARCH}=1)
else()
  set(SD_X86_IA32 0)
endif()
if(SD_ENABLE_ANALYZE)
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:/analyze;/analyze:external->")
endif()
if(SD_ENABLE_ASAN)
  if(SD_XP)
    message(FATAL_ERROR "AddressSanitizer is available on the v143 flavours only.")
  endif()
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:/fsanitize=address>")
endif()
if(SD_FUZZ)
  # libFuzzer needs coverage instrumentation in every module it drives, and ASan finds the memory bugs (01 12.2).
  add_compile_options("$<$<COMPILE_LANGUAGE:C>:/fsanitize=fuzzer;/fsanitize=address>")
  # Some MSVC toolsets ship the coverage runtime as libsancov.lib while the runtime's auto-link directive names
  # sancov.lib. Link the file that exists and stop the directive from pulling in a missing one.
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_sd_fuzz_arch x86)
  else()
    set(_sd_fuzz_arch x64)
  endif()
  get_filename_component(_sd_fuzz_cl_dir "${CMAKE_C_COMPILER}" DIRECTORY)
  get_filename_component(_sd_fuzz_msvc_lib "${_sd_fuzz_cl_dir}/../../../lib/${_sd_fuzz_arch}" ABSOLUTE)
  find_file(SD_FUZZ_SANCOV_LIB NAMES libsancov.lib NO_DEFAULT_PATH PATHS "${_sd_fuzz_msvc_lib}")
  if(SD_FUZZ_SANCOV_LIB)
    add_link_options("/NODEFAULTLIB:sancov.lib" "${SD_FUZZ_SANCOV_LIB}")
  endif()
endif()

# Librarian (lib.exe) for static libraries: /Brepro keeps the archive member timestamps fixed (04 §12.2).
set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /Brepro")

# Linker (04 §3.2).
# /PDBALTPATH:%_PDB% (04 §3.2, §12.2) cannot be spelled literally: the VS generator doubles '%' in link
# options, so the debug directory recorded "%%%name.pdb%%%" and debuggers / dbghelp (sd-isacheck) could
# not find the PDB. The per-target PDB file name is the same value without the escaping problem.
add_link_options(
  /DEBUG:FULL "/PDBALTPATH:$<TARGET_PDB_FILE_NAME:$<TARGET_PROPERTY:NAME>>" /DYNAMICBASE /NXCOMPAT /Brepro
  /MANIFEST:EMBED /MANIFESTUAC:NO /INCREMENTAL:NO
  "$<$<CONFIG:Release>:/OPT:REF;/OPT:ICF;/RELEASE>")
if(SD_X86)
  # SD_SAFESEH_NO (target property) exists only for the sd-importcheck negative fixture.
  add_link_options("$<IF:$<BOOL:$<TARGET_PROPERTY:SD_SAFESEH_NO>>,/SAFESEH:NO,/SAFESEH>" /LARGEADDRESSAWARE)
elseif(NOT SD_ARM32)
  add_link_options(/HIGHENTROPYVA)   # 64-bit images only: ARM32 is a 32-bit image (04 §3.2)
endif()
if(SD_MODERN_SECURITY)
  add_link_options(/guard:cf)
endif()
if(SD_CET)
  add_link_options(/CETCOMPAT)
endif()

message(STATUS "ShellDrive flavour: ${SD_FLAVOUR} (toolset ${SD_TOOLSET}, MSVC ${MSVC_VERSION}, "
               "_WIN32_WINNT=${SD_WINNT}, modern security=${SD_MODERN_SECURITY})")
