# Test suites. Each tests/unit/<module>/ directory is owned by that module's agent.

foreach(_m sd_base sd_platform sd_crypto sd_crypto_pq sd_ssh sd_sftp sd_vfs sd_dokan sd_ipc sd_state sd_l10n sd_config sd_secret sd_mount)
  add_subdirectory(unit/${_m})
endforeach()
add_subdirectory(unit/sd_crypto_pk)

add_subdirectory(apps)
add_subdirectory(l10n)
add_subdirectory(importcheck)
add_subdirectory(ui)
add_subdirectory(shellext)
