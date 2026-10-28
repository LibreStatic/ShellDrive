# Unit tests for the M5 service core (03 §1.3, §2.2, §2.6, §4.5): svc_access (pure rules) and service.c run in-process
# with the scripted fake mount backend (tests/unit/sd_mount). No SCM, no elevation, no real drive, no child process.
# The restricted-token case uses CreateRestrictedToken; a process that cannot connect to the pipe with that token
# still passes the refusal check (the connect itself is the refusal).

set(_host_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")
set(_fake_dir "${CMAKE_SOURCE_DIR}/tests/unit/sd_mount")

# test_scm.c drives the SCM registration rules (svc_scm.c) through a fake seam: it never reaches the real Service Control
# Manager, the registry or the Event Log. svc_scm.c is compiled here, but svc_scm_real_ops is never called by the tests.
# test_repair.c runs the machine data folder repair (svc_repair.c) on a temp folder only: no %ProgramData%, no elevation.
sd_add_unit_test(svc
  SOURCES main.c test_access.c test_service.c test_scm.c test_gw.c test_repair.c test_identity.c test_svcrepair.c
          test_evtmsg.c
          "${_host_dir}/service.c" "${_host_dir}/svc_access.c" "${_host_dir}/svc_scm.c"
          "${_host_dir}/svc_gw.c" "${_host_dir}/svc_gw_attach.c" "${_host_dir}/svc_repair.c"
          "${_host_dir}/svc_folder.c" "${_host_dir}/svc_status.c"
          "${_host_dir}/backend_unavailable.c"
  DEPS sd_mount_fake_backend sd_mount sd_ipc sd_secret sd_config sd_policy sd_l10n sd_l10n_catalog_svc sd_ssh sd_platform
       sd_base ole32 shell32 user32 advapi32 mpr)
target_include_directories(sd-test-svc PRIVATE "${_host_dir}" "${_fake_dir}" "${SD_GENERATED_DIR}/svc_events/$<CONFIG>")
add_dependencies(sd-test-svc sd_svc_events)
target_compile_definitions(sd-test-svc PRIVATE SD_SVC_TEST_HOOKS=1)
# test_evtmsg.c reads the generated Event Log source and resolves every id in the built shelldrive-host.exe (03 §10.3).
add_dependencies(sd-test-svc shelldrive-host)
target_compile_definitions(sd-test-svc PRIVATE
  "SD_SVC_EVENTS_MC=\"${SD_GENERATED_DIR}/svc_events/$<CONFIG>/svc_events.mc\""
  "SD_SVC_HOST_EXE=\"$<TARGET_FILE:shelldrive-host>\"")
set_tests_properties(unit.svc PROPERTIES TIMEOUT 600)
