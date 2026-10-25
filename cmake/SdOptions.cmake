# Flavour selection and compiler/linker flags. 04 §2.3, §3.1 and §3.2 are normative.
#
# SD_FLAVOUR is set by CMakePresets.json. Supported: x86-ia32, x86-sse2 (M1), x64-modern, x64-xp,
# x64-analysis.

set(SD_FLAVOUR "" CACHE STRING "Build flavour (x86-ia32, x86-sse2, x64-modern, x64-xp, x64-analysis)")
set_property(CACHE SD_FLAVOUR PROPERTY STRINGS x86-ia32 x86-sse2 x64-modern x64-xp x64-analysis)
set(SD_X86_ARCH "" CACHE STRING "x86 flavours: code generation floor (IA32 or SSE2, decisions.md D4)")
option(SD_ENABLE_ASAN "x64-analysis: build with AddressSanitizer" OFF)
option(SD_ENABLE_ANALYZE "Run the MSVC code analyzer (/analyze)" OFF)
option(SD_L10N_ALLOW_INCOMPLETE
       "Developer escape hatch: build even when a locale lacks strings (falls back to en). Never in CI." OFF)

if(SD_FLAVOUR STREQUAL "")
  message(FATAL_ERROR "SD_FLAVOUR is not set. Configure with a preset, e.g. cmake --preset x64-modern")
endif()

set(SD_X86 0)
if(SD_FLAVOUR STREQUAL "x86-ia32" OR SD_FLAVOUR STREQUAL "x86-sse2")
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

if(SD_X86)
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
else()
  message(FATAL_ERROR "Unknown SD_FLAVOUR '${SD_FLAVOUR}'.")
endif()

set(SD_MODERN_SECURITY 0)
if(SD_FLAVOUR STREQUAL "x64-modern" OR (SD_FLAVOUR STREQUAL "x64-analysis" AND NOT SD_ENABLE_ASAN))
  set(SD_MODERN_SECURITY 1)    # /sdl, /guard:cf, /CETCOMPAT
endif()

# Static CRT everywhere (04 §3.1).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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
else()
  add_link_options(/HIGHENTROPYVA)
endif()
if(SD_MODERN_SECURITY)
  add_link_options(/guard:cf /CETCOMPAT)
endif()

message(STATUS "ShellDrive flavour: ${SD_FLAVOUR} (toolset ${SD_TOOLSET}, MSVC ${MSVC_VERSION}, "
               "_WIN32_WINNT=${SD_WINNT}, modern security=${SD_MODERN_SECURITY})")
