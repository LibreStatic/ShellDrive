# 32-bit shell extension of the x64 packages (docs/design/04 §6.2, §8.3; 03 §8.5).
#
# Explorer's 32-bit file dialogs load the 32-bit shell extension, so an x64 package carries the x86-sse2 copy of
# shelldrive-shellext.dll beside the x64 one. The copy is built in a nested x86 configure of this same source tree
# (SD_SHELLEXT_ONLY=ON, Win32, v141_xp, SD_FLAVOUR=x86-sse2), through the ExternalProject target sd_shellext_x86,
# the same way the ARM trees build their host tools in a nested x64 configure (cmake/SdHostTools.cmake). The DLL then
# has the x86-sse2 rules: the import audit against xp-sp3-x86.txt and the SSE2 ISA audit (04 §2.4).
#
#   sd_add_x86_shellext(<target_var>)
#       Creates the ExternalProject target (name in <target_var>) and the imported shared library
#       sd_shellext_x86_dll, whose location follows the configuration of the outer build. The caller adds the
#       dependency of its own targets (add_dependencies) and the DLL to its DEPENDS lists.

function(sd_add_x86_shellext out_var)
  set(_bin "${CMAKE_BINARY_DIR}/shellext-x86")
  include(ExternalProject)
  ExternalProject_Add(sd_shellext_x86
    SOURCE_DIR "${CMAKE_SOURCE_DIR}"
    BINARY_DIR "${_bin}"
    PREFIX "${CMAKE_BINARY_DIR}/shellext-x86-prefix"
    CMAKE_GENERATOR "${CMAKE_GENERATOR}"
    CMAKE_GENERATOR_PLATFORM Win32
    CMAKE_GENERATOR_TOOLSET v141_xp
    CMAKE_ARGS -DSD_SHELLEXT_ONLY=ON -DSD_FLAVOUR=x86-sse2 -DSD_X86_ARCH=SSE2
    BUILD_COMMAND "${CMAKE_COMMAND}" --build <BINARY_DIR> --config $<CONFIG> --target shelldrive-shellext
    INSTALL_COMMAND ""
    BUILD_ALWAYS ON)
  set_target_properties(sd_shellext_x86 PROPERTIES FOLDER "packaging")

  add_library(sd_shellext_x86_dll SHARED IMPORTED GLOBAL)
  set_target_properties(sd_shellext_x86_dll PROPERTIES
    IMPORTED_LOCATION_DEBUG "${_bin}/bin/Debug/shelldrive-shellext.dll"
    IMPORTED_LOCATION_RELEASE "${_bin}/bin/Release/shelldrive-shellext.dll")
  set(${out_var} sd_shellext_x86 PARENT_SCOPE)
endfunction()
