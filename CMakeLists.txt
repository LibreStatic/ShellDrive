# ShellDrive top-level build (design: docs/design/04-build-install-update.md).
#
# Shared file: module agents do not edit it. Every module, app, tool and test directory below
# owns its own CMakeLists.txt.

cmake_minimum_required(VERSION 3.21)

# MSVC_RUNTIME_LIBRARY property (static /MT CRT).
cmake_policy(SET CMP0091 NEW)

project(ShellDrive LANGUAGES C RC)

if(NOT MSVC)
  message(FATAL_ERROR "ShellDrive builds with MSVC only (04 §2).")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(SdOptions)   # flavour, compiler and linker flags (04 §3.2)
include(SdVersion)   # VERSION file, git commit, generated sd/version.h
include(SdModule)    # sd_add_module, sd_add_unit_test, sd_add_app helpers
include(SdL10n)      # sdl10n catalog generation (03 §9)
include(SdHostTools) # build-time tools of cross-compiled (ARM64, ARM32) trees (04 §2.5)

# Group Policy headers and ADMX/ADML outputs (03 §3.5); generated under generated/policy/.
set(SD_POLICY_DIR "${SD_GENERATED_DIR}/policy")

enable_testing()

if(SD_HOST_TOOLS_ONLY)
  # Nested x64 configure of an ARM64 or ARM32 tree: only the tools that run during the build (cmake/SdHostTools.cmake).
  add_subdirectory(tools/sdl10n)
  add_subdirectory(tools/sd-importcheck)
  add_subdirectory(tools/sd-admxgen)
  add_subdirectory(tools/sd-payload)
  return()
endif()

# Build-time tools first: sdl10n, sd-importcheck and sd-admxgen run during the build. An ARM64 or ARM32 tree takes
# them from the nested x64 build instead of building ARM copies that cannot run here.
if(SD_CROSS_HOST_TOOLS)
  sd_host_tools_setup()
else()
  add_subdirectory(tools/sdl10n)
  add_subdirectory(tools/sd-importcheck)
  add_subdirectory(tools/sd-admxgen)
  add_subdirectory(tools/sd-payload)
endif()
# sd-isacheck audits x86 code only (04 §2.4): not part of the ARM64 or ARM32 trees.
if(NOT SD_ARM64 AND NOT SD_ARM32)
  add_subdirectory(tools/sd-isacheck)
endif()
add_subdirectory(tools/sd-updsign)

# Test harness (needed by module unit tests).
add_subdirectory(tests/harness)

# Group Policy template generation (needs sd-admxgen, built above).
add_subdirectory(res/policy)

# Modules, in dependency order (00 §5).
add_subdirectory(src/sd_base)
add_subdirectory(src/sd_platform)
add_subdirectory(src/sd_crypto)
add_subdirectory(src/sd_ssh)
add_subdirectory(src/sd_sftp)
add_subdirectory(src/sd_vfs)
add_subdirectory(src/sd_dokan)
add_subdirectory(src/sd_webdav)
add_subdirectory(src/sd_policy)
add_subdirectory(src/sd_l10n)
add_subdirectory(src/sd_config)
add_subdirectory(src/sd_secret)
add_subdirectory(src/sd_ipc)
add_subdirectory(src/sd_state)
add_subdirectory(src/sd_mount)
add_subdirectory(src/sd_update)

# Localized catalogs (PO sources under l10n/).
add_subdirectory(l10n)

# Applications. ARM32 ships no UI and no shell extension (D5, 04 §5.1: Windows RT runs no third-party desktop code and
# IoT images have no Explorer), so those two are not built there.
add_subdirectory(apps/shelldrive)
add_subdirectory(apps/shelldrive-host)
if(NOT SD_ARM32)
  add_subdirectory(apps/shelldrive-ui)
  add_subdirectory(apps/shelldrive-shellext)
endif()

# Setup engine, stub and payload (04 §6; tools/sd-payload attaches the payload CAB, added above).
add_subdirectory(apps/shelldrive-setup)

# Per-machine MSI packages (04 §8): opt-in, target msi, needs WiX 3.14 (packaging/msi/CMakeLists.txt).
option(SD_BUILD_MSI "Build the per-machine MSI of this flavour (target msi, WiX 3.14; 04 §8)" OFF)
if(SD_BUILD_MSI)
  add_subdirectory(packaging/msi)
endif()

# Unit tests and other test suites.
add_subdirectory(tests)
