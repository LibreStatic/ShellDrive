# Flavour selection and compiler/linker flags. 04 §2.3, §3.1 and §3.2 are normative.
#
# SD_FLAVOUR is set by CMakePresets.json. Supported in M0: x64-modern, x64-xp, x64-analysis.

set(SD_FLAVOUR "" CACHE STRING "Build flavour (x64-modern, x64-xp, x64-analysis)")
set_property(CACHE SD_FLAVOUR PROPERTY STRINGS x64-modern x64-xp x64-analysis)
option(SD_ENABLE_ASAN "x64-analysis: build with AddressSanitizer" OFF)
option(SD_ENABLE_ANALYZE "Run the MSVC code analyzer (/analyze)" OFF)
option(SD_L10N_ALLOW_INCOMPLETE
       "Developer escape hatch: build even when a locale lacks strings (falls back to en). Never in CI." OFF)

if(SD_FLAVOUR STREQUAL "")
  message(FATAL_ERROR "SD_FLAVOUR is not set. Configure with a preset, e.g. cmake --preset x64-modern")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "M0 flavours are x64 only (got a ${CMAKE_SIZEOF_VOID_P}-byte pointer build).")
endif()

set(SD_TOOLSET "${CMAKE_VS_PLATFORM_TOOLSET}")
if(SD_TOOLSET STREQUAL "")
  set(SD_TOOLSET "${CMAKE_GENERATOR_TOOLSET}")
endif()

if(SD_FLAVOUR STREQUAL "x64-xp")
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
add_link_options(
  /DEBUG:FULL /PDBALTPATH:%_PDB% /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /Brepro
  /MANIFEST:EMBED /MANIFESTUAC:NO /INCREMENTAL:NO
  "$<$<CONFIG:Release>:/OPT:REF;/OPT:ICF;/RELEASE>")
if(SD_MODERN_SECURITY)
  add_link_options(/guard:cf /CETCOMPAT)
endif()

message(STATUS "ShellDrive flavour: ${SD_FLAVOUR} (toolset ${SD_TOOLSET}, MSVC ${MSVC_VERSION}, "
               "_WIN32_WINNT=${SD_WINNT}, modern security=${SD_MODERN_SECURITY})")
