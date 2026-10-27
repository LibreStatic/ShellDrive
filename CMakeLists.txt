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

enable_testing()

# Build-time tools first: sdl10n, sd-importcheck and sd-isacheck run during the build.
add_subdirectory(tools/sdl10n)
add_subdirectory(tools/sd-importcheck)
add_subdirectory(tools/sd-isacheck)
add_subdirectory(tools/sd-updsign)

# Test harness (needed by module unit tests).
add_subdirectory(tests/harness)

# Modules, in dependency order (00 §5).
add_subdirectory(src/sd_base)
add_subdirectory(src/sd_platform)
add_subdirectory(src/sd_crypto)
add_subdirectory(src/sd_ssh)
add_subdirectory(src/sd_sftp)
add_subdirectory(src/sd_vfs)
add_subdirectory(src/sd_dokan)
add_subdirectory(src/sd_webdav)
add_subdirectory(src/sd_l10n)
add_subdirectory(src/sd_config)
add_subdirectory(src/sd_secret)
add_subdirectory(src/sd_ipc)
add_subdirectory(src/sd_state)
add_subdirectory(src/sd_mount)
add_subdirectory(src/sd_update)

# Localized catalogs (PO sources under l10n/).
add_subdirectory(l10n)

# Applications.
add_subdirectory(apps/shelldrive)
add_subdirectory(apps/shelldrive-host)
add_subdirectory(apps/shelldrive-ui)
add_subdirectory(apps/shelldrive-shellext)

# Unit tests and other test suites.
add_subdirectory(tests)
