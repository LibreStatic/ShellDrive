# shelldrive-setup (docs/design/04 §6): the setup engine, the setup stub and its payload.
#
#   sd_setup_core      engine library (all presets; tests/setup links it)
#   shelldrive-setup-stub  the stub without payload (x86-ia32 preset: an x86 program that runs on every x86 and
#                      x64 CPU, 04 §6.1; arm64 and arm32 presets: the native ARM64 and ARM32 stubs, §1.1, §5.1). It is
#                      also uninstall.exe inside the payload.
#   shelldrive-setup   the stub with the payload of this preset attached (tools/sd-payload). The arm64 CAB holds the
#                      ARM64 binaries only; the x86-sse2 and x64-modern shell DLLs that the ARM64 payload also
#                      carries (04 §6.1) are added by the release pipeline, not by this preset. The arm32 CAB holds
#                      the ARM32 CLI and host only (04 §5.1).

include(SdPayload)

sd_add_l10n_catalog(installer DOMAINS installer)

sd_setup_generate_regtable(SD_SETUP_REGTABLE_C)

# The TM-R34 folder check is the service's (svc_repair.c, svc_folder.c): the same source files, not a copy.
set(_sd_setup_host_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")

add_library(sd_setup_core STATIC
  setup_args.c
  setup_sha256.c
  setup_cab.c
  setup_util.c
  setup_reg.c
  setup_host.c
  setup_log.c
  setup_shortcut.c
  setup_msg.c
  setup_flow.c
  setup_install.c
  setup_trust.c
  setup_dokany.c
  "${_sd_setup_host_dir}/svc_folder.c"
  "${_sd_setup_host_dir}/svc_repair.c"
  ${SD_SETUP_REGTABLE_C})
target_include_directories(sd_setup_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(sd_setup_core PRIVATE "${_sd_setup_host_dir}")
target_link_libraries(sd_setup_core PUBLIC sd_headers sd_l10n sd_l10n_catalog_installer sd_base)
set_target_properties(sd_setup_core PROPERTIES FOLDER "apps")

if(SD_FLAVOUR STREQUAL "x86-ia32" OR SD_FLAVOUR STREQUAL "arm64" OR SD_FLAVOUR STREQUAL "arm32")
  set(SD_RC_DESCRIPTION "ShellDrive setup")
  set(SD_RC_INTERNAL_NAME "shelldrive-setup")
  set(SD_RC_ORIGINAL_FILENAME "shelldrive-setup.exe")
  set(_rc "${CMAKE_CURRENT_BINARY_DIR}/shelldrive-setup.version.rc")
  configure_file("${CMAKE_SOURCE_DIR}/res/version.rc.in" "${_rc}" @ONLY)
  set(_manifest "${CMAKE_CURRENT_BINARY_DIR}/shelldrive-setup.manifest")
  sd_manifest_configure("${_manifest}" "shelldrive-setup" TRUE)

  # GUI subsystem, but no comctl32 import: common controls come from the manifest only (04 §2.4).
  add_executable(shelldrive-setup-stub WIN32 setup_main.c setup_ui.c "${_rc}" "${_manifest}")
  set_target_properties(shelldrive-setup-stub PROPERTIES OUTPUT_NAME "shelldrive-setup-stub" FOLDER "apps")
  target_link_libraries(shelldrive-setup-stub PRIVATE sd_setup_core sd_l10n sd_l10n_catalog_installer sd_headers)
  if(SD_SUBSYSTEM_VERSION)
    target_link_options(shelldrive-setup-stub PRIVATE "/SUBSYSTEM:WINDOWS,${SD_SUBSYSTEM_VERSION}")
  endif()
  sd_add_import_audit(shelldrive-setup-stub shelldrive-setup-stub)
  sd_add_isa_check(shelldrive-setup-stub shelldrive-setup-stub)

  # Only KnownDLLs may be imported by the stub and uninstall.exe (TM-R33, TST-30).
  add_test(NAME importcheck.stub.knowndlls
           COMMAND sd-importcheck --floor "${SD_OS_FLOOR_LIST}"
                   --knowndlls "${CMAKE_SOURCE_DIR}/tests/os-imports/knowndlls.txt" --no-delayload
                   "$<TARGET_FILE:shelldrive-setup-stub>")
  set_tests_properties(importcheck.stub.knowndlls PROPERTIES LABELS importcheck)

  # Hidden /test-pages: the wizard pages are built and logged, nothing is installed (04 §6.10, tests/setup).
  set(_tp_dir "${CMAKE_BINARY_DIR}/test-pages")
  file(MAKE_DIRECTORY "${_tp_dir}")
  add_test(NAME setup.stub.test_pages
           COMMAND $<TARGET_FILE:shelldrive-setup-stub> /test-pages "/log=${_tp_dir}/pages.log"
                   "/installdir=${_tp_dir}/install")
  add_test(NAME setup.stub.test_pages_log
           COMMAND "${CMAKE_COMMAND}" "-DLOG=${_tp_dir}/pages.log" "-DNOT_CREATED=${_tp_dir}/install"
                   -P "${CMAKE_SOURCE_DIR}/tests/setup/check_test_pages.cmake")
  set_tests_properties(setup.stub.test_pages setup.stub.test_pages_log PROPERTIES LABELS setup TIMEOUT 120)
  set_tests_properties(setup.stub.test_pages_log PROPERTIES DEPENDS setup.stub.test_pages)

  sd_setup_add_payload(shelldrive-setup-stub SD_SETUP_EXE "${SD_FLAVOUR}")
endif()
