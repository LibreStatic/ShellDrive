# Per-machine MSI packages (docs/design/04 §8). Added by the root CMakeLists.txt only with -DSD_BUILD_MSI=ON.
#
#   cmake --build build/<preset> --target msi
#
# builds the MSI of this preset's flavour from the binaries of the preset (packaging/msi/build-msi.cmake):
# sd-msigen, candle, light (ICE validation on the base package), torch and sd-msiembed. The MSI tools run on the
# build host, so an ARM64 tree cannot build it (the ARM64 MSI is M6, 04 §1.1).

if(SD_ARM64)
  message(FATAL_ERROR "SD_BUILD_MSI needs an x86 or x64 preset: the MSI tools run on the build host (04 §8).")
endif()

add_subdirectory(${CMAKE_SOURCE_DIR}/tools/sd-msigen ${CMAKE_BINARY_DIR}/tools/sd-msigen)
add_subdirectory(${CMAKE_SOURCE_DIR}/tools/sd-msiembed ${CMAKE_BINARY_DIR}/tools/sd-msiembed)

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
# The arm32 row is authored for the day an arm32 preset exists (D31); there is none, so it is not built.
#   family  arch  Program Files folder           win64  installer  launch   UpgradeCode
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
else()
  message(FATAL_ERROR "SD_BUILD_MSI: no MSI for the flavour ${SD_FLAVOUR} (04 §8.2)")
endif()

# The service (M5, D6) is not there yet: its ServiceInstall stays behind this define (ShellDrive.wxs).
set(SD_MSI_WITH_SERVICE 0 CACHE STRING "1 once the service binary exists (M5): ServiceInstall/ServiceControl on")

set(_msi_version "${SD_VERSION_MAJOR}.${SD_VERSION_MINOR}.${SD_VERSION_PATCH}")
set(_msi_dir "${CMAKE_BINARY_DIR}/msi/$<CONFIG>")
set(_msi_out "${_msi_dir}/ShellDrive-${_msi_version}-${SD_FLAVOUR}.msi")
set(_msi_gen "${CMAKE_BINARY_DIR}/generated/msi/$<CONFIG>")

file(GLOB _msi_po "${CMAKE_SOURCE_DIR}/l10n/installer/*.po")
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
          "-DSD_MSI_ICON=${CMAKE_SOURCE_DIR}/res/icons/shelldrive.ico"
          "-DSD_MSI_SRC=${CMAKE_CURRENT_SOURCE_DIR}"
          "-DSD_MSI_GEN=${_msi_gen}"
          "-DSD_MSI_OUT=${_msi_dir}"
          "-DSD_MSI_REG=${CMAKE_SOURCE_DIR}/packaging/registration.txt"
          "-DSD_MSI_PO=${CMAKE_SOURCE_DIR}/l10n/installer"
          "-DSD_MSI_WIX=${SD_WIX_DIR}"
          "-DSD_MSIGEN=$<TARGET_FILE:sd-msigen>"
          "-DSD_MSIEMBED=$<TARGET_FILE:sd-msiembed>"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/build-msi.cmake"
  DEPENDS sd-msigen sd-msiembed shelldrive shelldrive-host shelldrive-ui shelldrive-shellext
          "${CMAKE_CURRENT_SOURCE_DIR}/build-msi.cmake" "${CMAKE_CURRENT_SOURCE_DIR}/ShellDrive.wxs"
          "${CMAKE_SOURCE_DIR}/packaging/registration.txt" ${_msi_po}
  COMMENT "msi: ShellDrive ${SD_FLAVOUR} ${_msi_version}"
  VERBATIM)

add_custom_target(msi DEPENDS "${_msi_out}")
set_target_properties(msi PROPERTIES FOLDER "packaging")

# Parameters of the CTest checks in tests/msi (the root scope sees them: packaging/msi is added first).
if(_arch STREQUAL "x86")
  set(_platform Intel)
else()
  set(_platform x64)
endif()
if(_launch STREQUAL "win10")
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
