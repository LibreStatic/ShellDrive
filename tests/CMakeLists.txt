# Test suites. Each tests/unit/<module>/ directory is owned by that module's agent.

foreach(_m sd_base sd_platform sd_crypto sd_crypto_pq sd_ssh sd_sftp sd_vfs sd_dokan sd_ipc sd_state sd_l10n sd_config sd_secret sd_mount sd_policy)
  add_subdirectory(unit/${_m})
endforeach()
add_subdirectory(unit/sd_crypto_pk)
add_subdirectory(unit/sd_update)

# Opt-in constant-time timing tests (-DSD_CT_TIMING=ON, never in the default run).
option(SD_CT_TIMING "Build the dudect-style timing tests (tests/ct), label ct, not part of the default run" OFF)
if(SD_CT_TIMING)
  add_subdirectory(ct)
endif()

add_subdirectory(fuzz)
add_subdirectory(apps)
add_subdirectory(l10n)
add_subdirectory(policy)
add_subdirectory(logpriv)
add_subdirectory(repro)
add_subdirectory(importcheck)
# The UI and the shell extension are not built for ARM32 (04 §5.1), so their tests are not either.
if(NOT SD_ARM32)
  add_subdirectory(ui)
  add_subdirectory(shellext)
endif()
add_subdirectory(setup)
add_subdirectory(release)
add_subdirectory(unit/sd_svc)

# MSI checks (04 §8): only with -DSD_BUILD_MSI=ON, which also builds the package they read (label msi).
if(SD_BUILD_MSI)
  add_subdirectory(msi)
endif()
