# Setup engine tests (docs/design/04 §6). sd-test-setup.exe covers the pure logic (flavour table, command line,
# versions, Dokany, CAB names, payload table, SHA-256) and, through real CABs, the extraction and the
# per-user and portable flows in a temp folder with HKCU redirected (RegOverridePredefKey).
#
# The CAB fixtures (including the ..\ traversal member) are built at run time by test_common.c with makecab,
# a Windows tool used at test time only and never part of the shipped output.

sd_add_unit_test(engine
  SOURCES main.c test_common.c test_args.c test_cab.c test_install.c test_flow.c test_trust.c test_dokany.c
    test_payload_sig.c
  DEPS sd_setup_core sd_crypto)
# test_trust.c uses the service's svc_repair.h seam (the same owner rule as tests/unit/sd_svc/test_repair.c).
target_include_directories(sd-test-engine PRIVATE "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")
