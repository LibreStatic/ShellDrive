# Helpers used by every module, test and app CMakeLists.txt.
#
#   sd_add_module(<name> [SOURCES ...] [DEPS ...] [SYSTEM_LIBS ...]
#                 [HEADERS ...] [PRIVATE_HEADERS ...])
#       Static library src/<name>. Without SOURCES it is an INTERFACE (header-only) target, so a module
#       can publish headers before it has code. HEADERS (public, under include/) and PRIVATE_HEADERS
#       (relative to the module directory) are compiled standalone, twice each, by a header check.
#
#   sd_add_unit_test(<short> SOURCES ... DEPS ...)
#       Test executable sd-test-<short>.exe built on tests/harness, registered with CTest.
#
#   sd_add_app(<target> OUTPUT_NAME <exe name> DESCRIPTION <text> SOURCES ... DEPS ... [WINDOWS])
#       Shipping executable with version resource, manifest and the post-build import audit (04 §2.4).
#       x86 flavours add the ISA audit (sd-isacheck); x86-sse2 executables also get the SSE2 entry thunk
#       (src/sd_platform/entry/sd_cpucheck.c, /ENTRY:sd_cpucheck_entry, 04 §3.2). Apps use wmain /
#       wWinMain (the thunk tail-calls wmainCRTStartup or wWinMainCRTStartup).

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

function(sd_add_header_check name)
  cmake_parse_arguments(H "" "" "HEADERS;PRIVATE_HEADERS" ${ARGN})
  set(_srcs "")
  set(_i 0)
  foreach(_h IN LISTS H_HEADERS H_PRIVATE_HEADERS)
    math(EXPR _i "${_i} + 1")
    get_filename_component(_base "${_h}" NAME_WE)
    set(_out "${CMAKE_CURRENT_BINARY_DIR}/hdrcheck/${name}_${_i}_${_base}.c")
    if(_h IN_LIST H_HEADERS)
      string(REGEX REPLACE "^include/" "" _inc "${_h}")
    else()
      set(_inc "${_h}")
    endif()
    # Included twice: proves self-containment and the include guard.
    file(CONFIGURE OUTPUT "${_out}" CONTENT
"/* Generated header check for ${_h}. */
#include \"${_inc}\"
#include \"${_inc}\"
int sd_hdrcheck_${name}_${_i};
" @ONLY)
    list(APPEND _srcs "${_out}")
  endforeach()
  if(_srcs)
    add_library(${name}_hdrcheck OBJECT ${_srcs})
    target_link_libraries(${name}_hdrcheck PRIVATE ${name})
    if(H_PRIVATE_HEADERS)
      target_include_directories(${name}_hdrcheck PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    endif()
    set_target_properties(${name}_hdrcheck PROPERTIES FOLDER "checks")
  endif()
endfunction()

function(sd_add_module name)
  cmake_parse_arguments(M "" "" "SOURCES;DEPS;SYSTEM_LIBS;HEADERS;PRIVATE_HEADERS" ${ARGN})
  if(M_SOURCES)
    add_library(${name} STATIC ${M_SOURCES} ${M_HEADERS} ${M_PRIVATE_HEADERS})
    target_include_directories(${name} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
                                       PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(${name} PUBLIC sd_headers ${M_DEPS} ${M_SYSTEM_LIBS})
  else()
    add_library(${name} INTERFACE)
    target_include_directories(${name} INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_link_libraries(${name} INTERFACE sd_headers ${M_DEPS} ${M_SYSTEM_LIBS})
  endif()
  if(M_HEADERS OR M_PRIVATE_HEADERS)
    sd_add_header_check(${name} HEADERS ${M_HEADERS} PRIVATE_HEADERS ${M_PRIVATE_HEADERS})
  endif()
endfunction()

function(sd_add_unit_test short)
  cmake_parse_arguments(T "" "" "SOURCES;DEPS" ${ARGN})
  set(_t sd-test-${short})
  add_executable(${_t} ${T_SOURCES})
  target_link_libraries(${_t} PRIVATE sd_test_harness ${T_DEPS})
  set_target_properties(${_t} PROPERTIES FOLDER "tests")
  add_test(NAME unit.${short} COMMAND ${_t})
  set_tests_properties(unit.${short} PROPERTIES LABELS unit TIMEOUT 300)
endfunction()

# Object library with the x86-sse2 entry thunk, always compiled /arch:IA32 (SD_X86_ARCH_OVERRIDE).
# out_var receives the target name; gui selects the wWinMain variant.
function(sd_cpucheck_target out_var gui)
  if(gui)
    set(_n sd_cpucheck_gui)
  else()
    set(_n sd_cpucheck_console)
  endif()
  if(NOT TARGET ${_n})
    add_library(${_n} OBJECT "${CMAKE_SOURCE_DIR}/src/sd_platform/entry/sd_cpucheck.c")
    set_target_properties(${_n} PROPERTIES SD_X86_ARCH_OVERRIDE IA32 FOLDER "apps")
    if(gui)
      target_compile_definitions(${_n} PRIVATE SD_CPUCHECK_GUI=1)
    endif()
  endif()
  set(${out_var} ${_n} PARENT_SCOPE)
endfunction()

# Post-build ISA audit of a 32-bit executable (04 §2.4) + CTest isacheck.<name>.
function(sd_add_isa_check target name)
  if(NOT SD_X86 OR SD_ENABLE_ASAN)
    return()
  endif()
  if(SD_X86_IA32)
    set(_args --floor ia32)
  else()
    set(_args --floor sse2)
  endif()
  list(APPEND _args --allow "${CMAKE_SOURCE_DIR}/tools/sd-isacheck/crt-allow.txt" ${ARGN})
  add_dependencies(${target} sd-isacheck)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND "$<TARGET_FILE:sd-isacheck>" ${_args} "$<TARGET_FILE:${target}>"
    COMMENT "ISA audit of ${name} (${SD_FLAVOUR})" VERBATIM)
  add_test(NAME isacheck.${name} COMMAND sd-isacheck ${_args} "$<TARGET_FILE:${target}>")
  set_tests_properties(isacheck.${name} PROPERTIES LABELS isacheck)
endfunction()

function(sd_add_app target)
  cmake_parse_arguments(A "WINDOWS" "OUTPUT_NAME;DESCRIPTION" "SOURCES;DEPS" ${ARGN})
  if(NOT A_OUTPUT_NAME)
    set(A_OUTPUT_NAME ${target})
  endif()

  set(SD_RC_DESCRIPTION "${A_DESCRIPTION}")
  set(SD_RC_INTERNAL_NAME "${A_OUTPUT_NAME}")
  set(SD_RC_ORIGINAL_FILENAME "${A_OUTPUT_NAME}.exe")
  set(_rc "${CMAKE_CURRENT_BINARY_DIR}/${A_OUTPUT_NAME}.version.rc")
  set(_manifest "${CMAKE_CURRENT_BINARY_DIR}/${A_OUTPUT_NAME}.manifest")
  set(SD_MANIFEST_NAME "${A_OUTPUT_NAME}")
  configure_file("${CMAKE_SOURCE_DIR}/res/version.rc.in" "${_rc}" @ONLY)
  configure_file("${CMAKE_SOURCE_DIR}/res/manifest/app.manifest.in" "${_manifest}" @ONLY)

  if(A_WINDOWS)
    add_executable(${target} WIN32 ${A_SOURCES} "${_rc}" "${_manifest}")
    set(_subsystem WINDOWS)
  else()
    add_executable(${target} ${A_SOURCES} "${_rc}" "${_manifest}")
    set(_subsystem CONSOLE)
  endif()
  set_target_properties(${target} PROPERTIES OUTPUT_NAME "${A_OUTPUT_NAME}" FOLDER "apps")
  set(_isa_extra "")
  if(SD_FLAVOUR STREQUAL "x86-sse2")
    sd_cpucheck_target(_cpucheck "${A_WINDOWS}")
    target_sources(${target} PRIVATE $<TARGET_OBJECTS:${_cpucheck}>)
    target_link_options(${target} PRIVATE /ENTRY:sd_cpucheck_entry)
    set(_isa_extra --entry sd_cpucheck_entry)
  endif()
  target_link_libraries(${target} PRIVATE sd_headers ${A_DEPS})
  target_include_directories(${target} PRIVATE "${SD_GENERATED_DIR}")
  if(SD_SUBSYSTEM_VERSION)
    target_link_options(${target} PRIVATE "/SUBSYSTEM:${_subsystem},${SD_SUBSYSTEM_VERSION}")
  endif()

  # Import audit (04 §2.4): fails the build, and runs again under CTest.
  if(NOT SD_ENABLE_ASAN)
    set(_args --floor "${SD_OS_FLOOR_LIST}")
    if(SD_SUBSYSTEM_VERSION)
      list(APPEND _args --subsystem "${SD_SUBSYSTEM_VERSION}")
    endif()
    if(SD_MODERN_SECURITY)
      list(APPEND _args --require-cfg --require-cet)
    else()
      list(APPEND _args --forbid-cfg)
    endif()
    if(SD_X86)
      list(APPEND _args --require-safeseh)
    endif()
    add_dependencies(${target} sd-importcheck)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND "$<TARGET_FILE:sd-importcheck>" ${_args} "$<TARGET_FILE:${target}>"
      COMMENT "Import audit of ${A_OUTPUT_NAME}.exe (${SD_FLAVOUR})" VERBATIM)
    add_test(NAME importcheck.${A_OUTPUT_NAME}
             COMMAND sd-importcheck ${_args} "$<TARGET_FILE:${target}>")
    set_tests_properties(importcheck.${A_OUTPUT_NAME} PROPERTIES LABELS importcheck)
  endif()
  sd_add_isa_check(${target} ${A_OUTPUT_NAME} ${_isa_extra})
endfunction()
