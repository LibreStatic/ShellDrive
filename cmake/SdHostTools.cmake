# Build-time tools for cross-compiled trees (ARM64 and ARM32, 04 §1.1, §2.5).
#
# The tools that run during the build (sdl10n, sd-importcheck, sd-admxgen, sd-payload) must run on the build
# host. An ARM64 or ARM32 tree cannot run them: its executables are ARM and Windows 11 on x64 does not run ARM
# binaries. So an ARM64 or ARM32 configure builds them in a nested x64 configure of this same source tree
# (SD_HOST_TOOLS_ONLY=ON, see the root CMakeLists.txt) through the ExternalProject target sd_host_tools, and the
# tool names become imported executables that point at the x64 binaries. The native flavours do not use this.
#
#   sd_host_tools_setup()                     called once by the root CMakeLists.txt (ARM64 and ARM32 trees only).
#   sd_add_tool_dependency(<target> <tool>)   <target> runs <tool> in a build step: build it first.
#   sd_tool_depends(<tool> <out_var>)         DEPENDS list for a custom command that runs <tool>.
#
# With SD_BUILD_MSI the nested build also has the MSI tools (SD_HOST_TOOLS_MSI): sd-msigen and sd-msiembed, which
# packaging/msi runs, and sd-test-msi, which the msi.* CTests run on the package (tests/msi). So an ARM tree builds its
# MSI and checks it on this host, the way an x86 or x64 tree does (04 §8, D31).

set(SD_HOST_TOOLS_NAMES sdl10n sd-importcheck sd-admxgen sd-payload)
set(SD_HOST_TOOLS_MSI_NAMES sd-msigen sd-msiembed sd-test-msi)

function(sd_host_tools_setup)
  set(_bin "${CMAKE_BINARY_DIR}/host-tools")
  set(_names ${SD_HOST_TOOLS_NAMES})
  set(_msi OFF)
  if(SD_BUILD_MSI)
    set(_msi ON)
    list(APPEND _names ${SD_HOST_TOOLS_MSI_NAMES})
  endif()
  include(ExternalProject)
  ExternalProject_Add(sd_host_tools
    SOURCE_DIR "${CMAKE_SOURCE_DIR}"
    BINARY_DIR "${_bin}"
    PREFIX "${CMAKE_BINARY_DIR}/host-tools-prefix"
    CMAKE_GENERATOR "${CMAKE_GENERATOR}"
    CMAKE_GENERATOR_PLATFORM x64
    CMAKE_ARGS -DSD_HOST_TOOLS_ONLY=ON -DSD_FLAVOUR=x64-modern -DSD_HOST_TOOLS_MSI=${_msi}
    INSTALL_COMMAND ""
    BUILD_ALWAYS ON)
  set_target_properties(sd_host_tools PROPERTIES FOLDER "tools")
  foreach(_t IN LISTS _names)
    add_executable(${_t} IMPORTED GLOBAL)
    set_target_properties(${_t} PROPERTIES
      IMPORTED_LOCATION_DEBUG "${_bin}/bin/Debug/${_t}.exe"
      IMPORTED_LOCATION_RELEASE "${_bin}/bin/Release/${_t}.exe")
  endforeach()
endfunction()

function(sd_add_tool_dependency target tool)
  if(SD_CROSS_HOST_TOOLS)
    add_dependencies(${target} sd_host_tools)
  else()
    add_dependencies(${target} ${tool})
  endif()
endfunction()

function(sd_tool_depends tool out_var)
  if(SD_CROSS_HOST_TOOLS)
    set(${out_var} "" PARENT_SCOPE)   # the owning target depends on sd_host_tools instead
  else()
    set(${out_var} ${tool} PARENT_SCOPE)
  endif()
endfunction()
