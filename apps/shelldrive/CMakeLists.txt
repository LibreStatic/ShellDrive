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
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_service.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli_out.c
  # service install/uninstall/start/stop/status (M5): the SCM seam lives with the service it registers (03 §1.3).
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_scm.c
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_scm.h
  # service repair-data (M5, 3.2, TM-R34): the machine data folder repair; the tests call it on a temp folder.
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_repair.c
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_repair.h
  # the machine folder checks (3.2, TM-R34), shared by the service start and the repair.
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_folder.c
  ${CMAKE_SOURCE_DIR}/apps/shelldrive-host/svc_folder.h)
set(SD_CLI_SOURCES ${SD_CLI_SOURCES} PARENT_SCOPE)

# sd_ssh: the host key commands run sd_known_hosts in the CLI process (03 §5: the CLI and UI link
# the same sd_known_hosts translation units; it has no transport dependency).
sd_add_app(shelldrive
  OUTPUT_NAME shelldrive
  DESCRIPTION "ShellDrive command-line interface"
  SOURCES main.c ${SD_CLI_SOURCES}
  DEPS sd_ipc sd_config sd_l10n sd_l10n_catalog_cli sd_platform sd_base sd_ssh advapi32)
target_include_directories(shelldrive PRIVATE "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")
