# shelldrive-shellext.dll: classic Explorer context menu handler for ShellDrive drives (03 §1.6, §8.2, §8.5).
#
# Shipping DLL, one per architecture. Built with sd_add_dll (version resource, import audit, ISA audit).
# SD_SHELLEXT_SOURCES is also used by tests/shellext to build the test-hook variant of the same code.

set(SD_SHELLEXT_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_com.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_cache.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_register.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_snapshot.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_int.h
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_model.h
  ${CMAKE_CURRENT_SOURCE_DIR}/shellext_snapshot.h)
set(SD_SHELLEXT_SOURCES ${SD_SHELLEXT_SOURCES} PARENT_SCOPE)

sd_add_dll(shelldrive-shellext
  OUTPUT_NAME shelldrive-shellext
  DESCRIPTION "ShellDrive Explorer context menu"
  DEF ${CMAKE_CURRENT_SOURCE_DIR}/shelldrive-shellext.def
  SOURCES ${SD_SHELLEXT_SOURCES}
  DEPS sd_ipc sd_l10n sd_l10n_catalog_shell sd_platform sd_base
       advapi32 ole32 shell32 user32)
