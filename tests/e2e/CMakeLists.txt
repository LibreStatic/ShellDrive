# End-to-end tests of the CLI and the service pipe (docs/dev/m5-notes.md, part 13).
#
#   sd-test-e2e.exe  hosts the service core (the svc_run of sd-test-svc: service.c and its seams, SD_SVC_TEST_HOOKS,
#                    the fake mount backend, a temp machine root) on a per-run pipe name, and starts the real CLI,
#                    sd-test-cli.exe (SD_CLI_TEST_HOOKS), as a child process for every command. The CLI reaches the
#                    service only through the named pipe; the test reads the service's stores in-process.
#   e2e.shipping_has_no_test_hooks  the shipping shelldrive.exe and shelldrive-host.exe contain no SHELLDRIVE_TEST_* name.
# Test binaries only; never installed. The CLI seams are SHELLDRIVE_TEST_INSTANCE, _CONFIG_DIR, _EXPECTED_OWNER,
# _ELEVATED and _SCM, all read only when SD_CLI_TEST_HOOKS is defined.

set(_host_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")
set(_fake_dir "${CMAKE_SOURCE_DIR}/tests/unit/sd_mount")

# The service core and its seams, compiled as in tests/unit/sd_svc (the same sources, the same test hooks).
sd_add_unit_test(e2e
  SOURCES main.c e2e_host.c test_cli_service.c
          "${_host_dir}/service.c" "${_host_dir}/svc_access.c" "${_host_dir}/svc_scm.c"
          "${_host_dir}/svc_gw.c" "${_host_dir}/svc_gw_attach.c" "${_host_dir}/svc_repair.c"
          "${_host_dir}/svc_folder.c" "${_host_dir}/svc_status.c"
          "${_host_dir}/backend_unavailable.c"
  DEPS sd_mount_fake_backend sd_mount sd_ipc sd_secret sd_config sd_policy sd_l10n sd_l10n_catalog_svc sd_ssh sd_platform
       sd_base ole32 shell32 user32 advapi32 mpr)
target_include_directories(sd-test-e2e PRIVATE "${_host_dir}" "${_fake_dir}" "${SD_GENERATED_DIR}/svc_events/$<CONFIG>")
add_dependencies(sd-test-e2e sd_svc_events sd-test-cli)
target_compile_definitions(sd-test-e2e PRIVATE SD_SVC_TEST_HOOKS=1)
set_tests_properties(unit.e2e PROPERTIES TIMEOUT 900)

# The shipping binaries are built next to the test binaries (the output directory is shared, bin/).
add_dependencies(sd-test-e2e shelldrive shelldrive-host)
add_test(NAME e2e.shipping_has_no_test_hooks
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check_no_test_hooks.ps1"
          -BinDir "$<TARGET_FILE_DIR:shelldrive>")
set_tests_properties(e2e.shipping_has_no_test_hooks PROPERTIES LABELS e2e TIMEOUT 120)
