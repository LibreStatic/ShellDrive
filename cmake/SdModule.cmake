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
#       WINDOWS: GUI subsystem, WIN32 target, comctl32 v6 dependency and DPI awareness in the manifest.
#
#   sd_add_dll(<target> OUTPUT_NAME <name> DESCRIPTION <text> SOURCES ... DEPS ... [DEF <file>])
#       Shipping DLL with version resource, import audit and ISA audit; no embedded manifest.
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
  # The asInvoker manifest keeps Windows installer detection from elevating 32-bit test binaries whose names
  # contain "setup", "update", "install" or "patch" (ctest then reports them as Not Run).
  set(_manifest "${CMAKE_CURRENT_BINARY_DIR}/${_t}.manifest")
  sd_manifest_configure("${_manifest}" "${_t}" FALSE)
  add_executable(${_t} ${T_SOURCES} "${_manifest}")
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
  if(NOT SD_X86 OR SD_ENABLE_ASAN OR SD_FUZZ)
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

# Instantiates res/manifest/app.manifest.in for one binary. gui (TRUE/FALSE) adds the comctl32 v6
# dependency and the DPI awareness settings (03 §7.1, §7.3); console binaries get neither.
# processorArchitecture follows the flavour (SD_MANIFEST_ARCH, cmake/SdOptions.cmake).
function(sd_manifest_configure out_file name gui)
  set(SD_MANIFEST_NAME "${name}")
  if(gui)
    set(SD_MANIFEST_DEPENDENCY [[  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>]])
    set(SD_MANIFEST_DPI [[      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/PM</dpiAware>]])
    if(NOT SD_XP)
      # dpiAwareness (Windows 10 1703 PerMonitorV2, fallback PerMonitor) is in the 2016 namespace, which the
      # SDK 7.1A of the XP flavours does not know (manifest warning 81010002). XP flavours keep dpiAware only.
      string(APPEND SD_MANIFEST_DPI "\n      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerMonitor</dpiAwareness>")
    endif()
  else()
    set(SD_MANIFEST_DEPENDENCY "")
    set(SD_MANIFEST_DPI "")
  endif()
  # longPathAware is in the 2016 namespace too: the XP flavours (SDK 7.1A) do not know it, and XP has no
  # long path support to ask for (manifest warning 81010002).
  if(NOT SD_XP)
    set(SD_MANIFEST_LONGPATH [[      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>]])
  else()
    set(SD_MANIFEST_LONGPATH "")
  endif()
  configure_file("${CMAKE_SOURCE_DIR}/res/manifest/app.manifest.in" "${out_file}" @ONLY)
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
  sd_manifest_configure("${_manifest}" "${A_OUTPUT_NAME}" "${A_WINDOWS}")
  configure_file("${CMAKE_SOURCE_DIR}/res/version.rc.in" "${_rc}" @ONLY)

  if(A_WINDOWS)
    add_executable(${target} WIN32 ${A_SOURCES} "${_rc}" "${_manifest}")
    set(_subsystem WINDOWS)
    # GUI applications: common controls v6 (XP+ through the manifest dependency, 03 §7.1).
    target_link_libraries(${target} PRIVATE comctl32)
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

  sd_add_import_audit(${target} ${A_OUTPUT_NAME})
  sd_add_isa_check(${target} ${A_OUTPUT_NAME} ${_isa_extra})
endfunction()

# Shipping DLL (03 §1.6, shell extension and later helpers): version resource, import audit and ISA
# audit exactly like an executable. DLLs take the manifest of the host process, so none is embedded.
#
#   sd_add_dll(<target> OUTPUT_NAME <name> DESCRIPTION <text> SOURCES ... DEPS ... [DEF <file.def>])
function(sd_add_dll target)
  cmake_parse_arguments(D "" "OUTPUT_NAME;DESCRIPTION;DEF" "SOURCES;DEPS" ${ARGN})
  if(NOT D_OUTPUT_NAME)
    set(D_OUTPUT_NAME ${target})
  endif()

  set(SD_RC_DESCRIPTION "${D_DESCRIPTION}")
  set(SD_RC_INTERNAL_NAME "${D_OUTPUT_NAME}")
  set(SD_RC_ORIGINAL_FILENAME "${D_OUTPUT_NAME}.dll")
  set(_rc "${CMAKE_CURRENT_BINARY_DIR}/${D_OUTPUT_NAME}.version.rc")
  configure_file("${CMAKE_SOURCE_DIR}/res/version.rc.in" "${_rc}" @ONLY)

  add_library(${target} SHARED ${D_SOURCES} "${_rc}")
  set_target_properties(${target} PROPERTIES OUTPUT_NAME "${D_OUTPUT_NAME}" FOLDER "libs")
  set(_isa_extra "")
  target_link_libraries(${target} PRIVATE sd_headers ${D_DEPS})
  target_include_directories(${target} PRIVATE "${SD_GENERATED_DIR}")
  if(SD_SUBSYSTEM_VERSION)
    target_link_options(${target} PRIVATE "/SUBSYSTEM:WINDOWS,${SD_SUBSYSTEM_VERSION}")
  endif()
  if(D_DEF)
    target_link_options(${target} PRIVATE "/DEF:${D_DEF}")
  endif()
  sd_add_import_audit(${target} ${D_OUTPUT_NAME})
  sd_add_isa_check(${target} ${D_OUTPUT_NAME} ${_isa_extra})
endfunction()

# Import audit (04 §2.4) of a shipping image: fails the build, and runs again under CTest
# (importcheck.<file name>). The floor list is the flavour's (cmake/SdOptions.cmake).
function(sd_add_import_audit target name)
  if(SD_ENABLE_ASAN)
    return()
  endif()
  set(_args --floor "${SD_OS_FLOOR_LIST}")
  if(SD_SUBSYSTEM_VERSION)
    list(APPEND _args --subsystem "${SD_SUBSYSTEM_VERSION}")
  endif()
  if(SD_MODERN_SECURITY)
    list(APPEND _args --require-cfg)
    if(SD_CET)
      list(APPEND _args --require-cet)
    endif()
  else()
    list(APPEND _args --forbid-cfg)
  endif()
  if(SD_X86)
    list(APPEND _args --require-safeseh)
  endif()
  sd_add_tool_dependency(${target} sd-importcheck)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND "$<TARGET_FILE:sd-importcheck>" ${_args} "$<TARGET_FILE:${target}>"
    COMMENT "Import audit of ${name} (${SD_FLAVOUR})" VERBATIM)
  add_test(NAME importcheck.${name}
           COMMAND sd-importcheck ${_args} "$<TARGET_FILE:${target}>")
  set_tests_properties(importcheck.${name} PROPERTIES LABELS importcheck)
endfunction()
