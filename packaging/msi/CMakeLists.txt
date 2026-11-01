# Per-machine MSI packages (docs/design/04 §8). Added by the root CMakeLists.txt only with -DSD_BUILD_MSI=ON.
#
#   cmake --build build/<preset> --target msi
#
# builds the MSI of this preset's flavour from the binaries of the preset (packaging/msi/build-msi.cmake):
# sd-msigen, candle, light (ICE validation on the base package), torch and sd-msiembed. The MSI tools run on the
# build host: an ARM64 or ARM32 tree takes sd-msigen and sd-msiembed from its nested x64 build (cmake/SdHostTools.cmake,
# SD_HOST_TOOLS_MSI), the way it takes sdl10n; WiX is an x86 .NET program that the host runs either way.

if(SD_CROSS_HOST_TOOLS)
  set(_msi_tool_deps "")   # the msi target depends on sd_host_tools instead
else()
  add_subdirectory(${CMAKE_SOURCE_DIR}/tools/sd-msigen ${CMAKE_BINARY_DIR}/tools/sd-msigen)
  add_subdirectory(${CMAKE_SOURCE_DIR}/tools/sd-msiembed ${CMAKE_BINARY_DIR}/tools/sd-msiembed)
  set(_msi_tool_deps sd-msigen sd-msiembed)
endif()

# WiX Toolset 3.14 (04 §8.1): the WIX environment variable of the WiX installer, else its default folder.
if(DEFINED ENV{WIX} AND NOT "$ENV{WIX}" STREQUAL "")
  set(_sd_wix_default "$ENV{WIX}")
else()
  set(_sd_wix_default "C:/Program Files (x86)/WiX Toolset v3.14")
endif()
set(SD_WIX_DIR "${_sd_wix_default}" CACHE PATH "WiX Toolset 3.14 root (bin/candle.exe, bin/light.exe, bin/torch.exe)")
file(TO_CMAKE_PATH "${SD_WIX_DIR}" SD_WIX_DIR)
if(NOT EXISTS "${SD_WIX_DIR}/bin/candle.exe")
  message(FATAL_ERROR "SD_BUILD_MSI: WiX 3.14 not found at ${SD_WIX_DIR} (set WIX or SD_WIX_DIR)")
endif()

# Per-flavour package parameters (04 §8.2). UpgradeCodes are fixed forever; the x86 pair and the x64 pair share one.
#   family  arch  Program Files folder           win64  installer  launch   UpgradeCode
# ARM32 (D31, 04 §5.1) has the CLI and the host only: no UI, no shell extension, no Start menu, no Dokany (_ui 0).
set(_ui 1)
if(SD_FLAVOUR STREQUAL "x86-ia32" OR SD_FLAVOUR STREQUAL "x86-sse2")
  set(_family x86)
  set(_arch x86)
  set(_pf ProgramFilesFolder)
  set(_win64 no)
  set(_installer 301)
  set(_launch none)
  set(_upgrade "{8901324D-C7E1-44ED-BA3C-B1EB08B70174}")
elseif(SD_FLAVOUR STREQUAL "x64-xp")
  set(_family x64)
  set(_arch x64)
  set(_pf ProgramFiles64Folder)
  set(_win64 yes)
  set(_installer 301)
  set(_launch none)
  set(_upgrade "{37D2227E-A917-46A7-8F8E-0F9A8146CA5F}")
elseif(SD_FLAVOUR STREQUAL "x64-modern")
  set(_family x64)
  set(_arch x64)
  set(_pf ProgramFiles64Folder)
  set(_win64 yes)
  set(_installer 500)
  set(_launch win10)
  set(_upgrade "{37D2227E-A917-46A7-8F8E-0F9A8146CA5F}")
elseif(SD_FLAVOUR STREQUAL "arm64")
  set(_family arm64)
  set(_arch arm64)
  set(_pf ProgramFiles64Folder)
  set(_win64 yes)
  set(_installer 500)
  set(_launch none)
  set(_upgrade "{1438051B-3E86-459D-8199-E8D786F5A32B}")
elseif(SD_FLAVOUR STREQUAL "arm32")
  set(_family arm32)
  set(_arch arm)
  set(_pf ProgramFilesFolder)
  set(_win64 no)
  set(_installer 500)
  set(_launch arm32)
  set(_upgrade "{23F62FB5-0CD9-4087-B04C-D2A1B4A0A8F2}")
  set(_ui 0)
else()
  message(FATAL_ERROR "SD_BUILD_MSI: no MSI for the flavour ${SD_FLAVOUR} (04 §8.2)")
endif()

# The 32-bit shell extension (04 §6.2, §8.3; 03 §8.5). An x64 or ARM64 package also carries the x86-sse2 copy of the
# DLL in Program Files (x86) and registers it in the 32-bit registry view (32-bit apps' file dialogs load it; on ARM64
# the x86 apps run under WOW64 with the same view). The copy comes from a nested x86 configure
# (cmake/SdShellExtX86.cmake). The x86 packages have no 32-bit view to add: their DLL is the 32-bit one already. The
# ARM32 package has no shell extension.
set(SD_MSI_SHELLEXT32 0)
set(SD_MSI_BIN32 "$<TARGET_FILE_DIR:shelldrive>")   # any existing folder when there is no 32-bit copy
set(_msi_x86_deps "")
set(SD_MSI_TEST_X86_DLL "")
if(_arch STREQUAL "x64" OR _arch STREQUAL "arm64")
  include(SdShellExtX86)
  sd_add_x86_shellext(_sd_x86_shellext_target)
  set(SD_MSI_SHELLEXT32 1)
  set(SD_MSI_BIN32 "$<TARGET_FILE_DIR:sd_shellext_x86_dll>")
  set(_msi_x86_deps "$<TARGET_FILE:sd_shellext_x86_dll>")
  set(SD_MSI_TEST_X86_DLL "$<TARGET_FILE:sd_shellext_x86_dll>")
endif()

# The service (M5, D6) is not there yet: its ServiceInstall stays behind this define (ShellDrive.wxs).
set(SD_MSI_WITH_SERVICE 0 CACHE STRING "1 once the service binary exists (M5): ServiceInstall/ServiceControl on")

set(_msi_ui_deps "")
if(_ui)
  set(_msi_ui_deps shelldrive-ui shelldrive-shellext)
endif()

set(_msi_version "${SD_VERSION_MAJOR}.${SD_VERSION_MINOR}.${SD_VERSION_PATCH}")
set(_msi_dir "${CMAKE_BINARY_DIR}/msi/$<CONFIG>")
set(_msi_out "${_msi_dir}/ShellDrive-${_msi_version}-${SD_FLAVOUR}.msi")
set(_msi_gen "${CMAKE_BINARY_DIR}/generated/msi/$<CONFIG>")

file(GLOB _msi_po "${CMAKE_SOURCE_DIR}/l10n/installer/*.po")
file(GLOB _msi_wixui "${CMAKE_CURRENT_SOURCE_DIR}/wixui/*")
add_custom_command(
  OUTPUT "${_msi_out}"
  COMMAND "${CMAKE_COMMAND}"
          "-DSD_MSI_FLAVOUR=${SD_FLAVOUR}"
          "-DSD_MSI_FAMILY=${_family}"
          "-DSD_MSI_VERSION=${_msi_version}"
          "-DSD_MSI_ARCH=${_arch}"
          "-DSD_MSI_INSTALLER_VERSION=${_installer}"
          "-DSD_MSI_PF=${_pf}"
          "-DSD_MSI_WIN64=${_win64}"
          "-DSD_MSI_LAUNCH=${_launch}"
          "-DSD_MSI_WITH_SERVICE=${SD_MSI_WITH_SERVICE}"
          "-DSD_MSI_UPGRADE_CODE=${_upgrade}"
          "-DSD_MSI_BIN=$<TARGET_FILE_DIR:shelldrive>"
          "-DSD_MSI_SHELLEXT32=${SD_MSI_SHELLEXT32}"
          "-DSD_MSI_BIN32=${SD_MSI_BIN32}"
          "-DSD_MSI_UI=${_ui}"
          "-DSD_MSI_DOKANY=${_ui}"
          "-DSD_MSI_ICON=${CMAKE_SOURCE_DIR}/res/icons/shelldrive.ico"
          "-DSD_MSI_SRC=${CMAKE_CURRENT_SOURCE_DIR}"
          "-DSD_MSI_GEN=${_msi_gen}"
          "-DSD_MSI_OUT=${_msi_dir}"
          "-DSD_MSI_REG=${CMAKE_SOURCE_DIR}/packaging/registration.txt"
          "-DSD_MSI_PO=${CMAKE_SOURCE_DIR}/l10n/installer"
          "-DSD_MSI_WIX=${SD_WIX_DIR}"
          "-DSD_MSI_LICENSE=${CMAKE_SOURCE_DIR}/LICENSE"
          "-DSD_MSIGEN=$<TARGET_FILE:sd-msigen>"
          "-DSD_MSIEMBED=$<TARGET_FILE:sd-msiembed>"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/build-msi.cmake"
  DEPENDS ${_msi_tool_deps} shelldrive shelldrive-host ${_msi_ui_deps} ${_msi_x86_deps}
          "${CMAKE_CURRENT_SOURCE_DIR}/build-msi.cmake" "${CMAKE_CURRENT_SOURCE_DIR}/ShellDrive.wxs"
          "${CMAKE_SOURCE_DIR}/packaging/registration.txt" "${CMAKE_SOURCE_DIR}/LICENSE" ${_msi_po} ${_msi_wixui}
  COMMENT "msi: ShellDrive ${SD_FLAVOUR} ${_msi_version}"
  VERBATIM)

add_custom_target(msi DEPENDS "${_msi_out}")
set_target_properties(msi PROPERTIES FOLDER "packaging")
if(SD_CROSS_HOST_TOOLS)
  add_dependencies(msi sd_host_tools)
endif()
if(SD_MSI_SHELLEXT32)
  add_dependencies(msi sd_shellext_x86)
endif()

# Parameters of the CTest checks in tests/msi (the root scope sees them: packaging/msi is added first). The platform is
# the Template prefix of the summary information (04 §8.2).
if(_arch STREQUAL "x86")
  set(_platform Intel)
elseif(_arch STREQUAL "x64")
  set(_platform x64)
elseif(_arch STREQUAL "arm64")
  set(_platform Arm64)
else()
  set(_platform Arm)
endif()
if(NOT _launch STREQUAL "none")
  set(_launch_count 2)
else()
  set(_launch_count 1)
endif()
set(SD_MSI_PACKAGE "${_msi_out}" PARENT_SCOPE)
set(SD_MSI_TEST_VERSION "${_msi_version}" PARENT_SCOPE)
set(SD_MSI_TEST_UPGRADE "${_upgrade}" PARENT_SCOPE)
set(SD_MSI_TEST_PLATFORM "${_platform}" PARENT_SCOPE)
set(SD_MSI_TEST_INSTALLER "${_installer}" PARENT_SCOPE)
set(SD_MSI_TEST_LAUNCH_COUNT "${_launch_count}" PARENT_SCOPE)
set(SD_MSI_TEST_SHELLEXT32 "${SD_MSI_SHELLEXT32}" PARENT_SCOPE)
set(SD_MSI_TEST_X86_DLL "${SD_MSI_TEST_X86_DLL}" PARENT_SCOPE)
set(SD_MSI_TEST_UI "${_ui}" PARENT_SCOPE)
