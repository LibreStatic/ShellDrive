# shelldrive-setup (docs/design/04 §6): the setup engine, the setup stub and its payload.
#
#   sd_setup_core      engine library (all presets; tests/setup links it)
#   shelldrive-setup-stub  the stub without payload (x86-ia32 preset: an x86 program that runs on every x86 and
#                      x64 CPU, 04 §6.1; arm64 preset: the native ARM64 stub, §1.1). It is also uninstall.exe
#                      inside the payload.
#   shelldrive-setup   the stub with the payload of this preset attached (tools/sd-payload). The arm64 CAB holds the
#                      ARM64 binaries only; the x86-sse2 and x64-modern shell DLLs that the ARM64 payload also
#                      carries (04 §6.1) are added by the release pipeline, not by this preset.

include(SdPayload)

sd_add_l10n_catalog(installer DOMAINS installer)

sd_setup_generate_regtable(SD_SETUP_REGTABLE_C)

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
  setup_install.c
  ${SD_SETUP_REGTABLE_C})
target_include_directories(sd_setup_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(sd_setup_core PUBLIC sd_headers sd_l10n sd_l10n_catalog_installer)
set_target_properties(sd_setup_core PROPERTIES FOLDER "apps")

if(SD_FLAVOUR STREQUAL "x86-ia32" OR SD_FLAVOUR STREQUAL "arm64")
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

  sd_setup_add_payload(shelldrive-setup-stub SD_SETUP_EXE "${SD_FLAVOUR}")
endif()
