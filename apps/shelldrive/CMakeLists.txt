# shelldrive.exe (CLI). Owned by the apps agent. The command sources are also compiled into a test
# build (tests/apps) with SD_CLI_TEST_HOOKS for the smoke test; the shipping binary has no hooks.

set(SD_CLI_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/cli.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_int.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_args.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_common.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_cmds.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_cmds2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_cmds3.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_out.c)
set(SD_CLI_SOURCES ${SD_CLI_SOURCES} PARENT_SCOPE)

# sd_ssh: the host key commands run sd_known_hosts in the CLI process (03 §5: the CLI and UI link
# the same sd_known_hosts translation units; it has no transport dependency).
sd_add_app(shelldrive
  OUTPUT_NAME shelldrive
  DESCRIPTION "ShellDrive command-line interface"
  SOURCES main.c ${SD_CLI_SOURCES}
  DEPS sd_ipc sd_config sd_l10n sd_l10n_catalog_cli sd_platform sd_base sd_ssh)
