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
  "${_host_dir}/main.c" "${_host_dir}/agent.c" "${_host_dir}/log_ring.c" "${_host_dir}/host.h" host_fake_backend.c)
target_compile_definitions(sd-test-host-fake PRIVATE SD_HOST_TEST_HOOKS=1)
target_include_directories(sd-test-host-fake PRIVATE "${_host_dir}")
target_link_libraries(sd-test-host-fake PRIVATE sd_headers sd_mount_fake_backend sd_mount sd_ipc sd_secret sd_config
                      sd_platform sd_base)
set_target_properties(sd-test-host-fake PROPERTIES FOLDER "tests")

add_executable(sd-test-cli "${_cli_dir}/main.c" ${SD_CLI_SOURCES})
target_compile_definitions(sd-test-cli PRIVATE SD_CLI_TEST_HOOKS=1)
target_include_directories(sd-test-cli PRIVATE "${_cli_dir}")
target_link_libraries(sd-test-cli PRIVATE sd_headers sd_ipc sd_config sd_l10n sd_l10n_catalog_cli sd_platform
                      sd_base sd_ssh)
set_target_properties(sd-test-cli PROPERTIES FOLDER "tests")

sd_add_unit_test(apps
  SOURCES main.c test_cli_args.c test_smoke.c test_agent_m3.c "${_cli_dir}/cli_args.c"
  DEPS sd_ipc sd_config sd_platform sd_base)
target_include_directories(sd-test-apps PRIVATE "${_cli_dir}")
add_dependencies(sd-test-apps sd-test-cli sd-test-host-fake)
set_tests_properties(unit.apps PROPERTIES TIMEOUT 600)
