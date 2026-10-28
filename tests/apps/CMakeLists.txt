# Host and CLI tests (owned by the apps agent). Added from tests/CMakeLists.txt.
#
#   sd-test-host-fake.exe  the agent sources with the scripted fake backend and SD_HOST_TEST_HOOKS
#   sd-test-cli.exe        the CLI sources with SD_CLI_TEST_HOOKS (instance suffix, config root,
#                          agent path from SHELLDRIVE_TEST_* variables)
#   sd-test-apps.exe       CLI parsing unit tests + the end-to-end smoke test driving the two above
# None of these is a shipping binary (no import audit, never installed).

set(_host_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")
set(_cli_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive")

add_executable(sd-test-host-fake
  "${_host_dir}/main.c" "${_host_dir}/agent.c" "${_host_dir}/log_ring.c" "${_host_dir}/state_producer.c"
  "${_host_dir}/explorer_data.c" "${_host_dir}/config_watch.c" "${_host_dir}/update_ipc.c" "${_host_dir}/host.h" host_fake_backend.c "${_host_dir}/installer_hooks.c"
  "${_host_dir}/service.c" "${_host_dir}/svc_access.c" "${_host_dir}/svc_folder.c"
  "${_host_dir}/svc_scm.c" "${_host_dir}/svc_repair.c" "${_host_dir}/svc_status.c")
target_compile_definitions(sd-test-host-fake PRIVATE SD_HOST_TEST_HOOKS=1)
target_include_directories(sd-test-host-fake PRIVATE "${_host_dir}" "${SD_GENERATED_DIR}/svc_events/$<CONFIG>")
add_dependencies(sd-test-host-fake sd_svc_events)
target_link_libraries(sd-test-host-fake PRIVATE sd_headers sd_mount_fake_backend sd_mount sd_ipc sd_state sd_secret sd_config sd_update sd_policy
                      sd_l10n sd_l10n_catalog_svc sd_ssh sd_platform sd_base ole32 shell32 user32 advapi32)
set_target_properties(sd-test-host-fake PROPERTIES FOLDER "tests")

add_executable(sd-test-cli "${_cli_dir}/main.c" ${SD_CLI_SOURCES})
target_compile_definitions(sd-test-cli PRIVATE SD_CLI_TEST_HOOKS=1)
target_include_directories(sd-test-cli PRIVATE "${_cli_dir}" "${_host_dir}")
target_link_libraries(sd-test-cli PRIVATE sd_headers sd_ipc sd_config sd_l10n sd_l10n_catalog_cli sd_platform
                      sd_base sd_ssh advapi32)
set_target_properties(sd-test-cli PROPERTIES FOLDER "tests")

sd_add_unit_test(apps
  SOURCES main.c test_cli_args.c test_cli_m3.c test_smoke.c test_agent_m3.c "${_cli_dir}/cli_args.c"
  DEPS sd_ipc sd_state sd_config sd_platform sd_base ole32 shell32 advapi32 user32)
target_include_directories(sd-test-apps PRIVATE "${_cli_dir}")
add_dependencies(sd-test-apps sd-test-cli sd-test-host-fake)
# unit.apps writes and removes the HKCU key tree Software\LibreStatic\ShellDriveTest (test_agent_m3.c), which the
# transport tests also use for their keys (unit.ssh_transport, same parent): one lock for both.
set_tests_properties(unit.apps PROPERTIES TIMEOUT 600 RESOURCE_LOCK hkcu_shelldrivetest)

# The apps tests must leave no ShellDrive process behind (test agents never start the real UI, and every test
# agent runs on its own instance). Runs after unit.apps; a leak fails this test with the process list.
# RUN_SERIAL: the check scans every ShellDrive process of the build tree, so no other test may run beside it
# (the ui smoke tests start shelldrive-ui.exe from the same tree).
add_test(NAME apps.no_leftover_processes
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check_no_leftovers.ps1" -BuildDir "${CMAKE_BINARY_DIR}")
set_tests_properties(apps.no_leftover_processes PROPERTIES LABELS apps DEPENDS unit.apps TIMEOUT 60 RUN_SERIAL TRUE)
