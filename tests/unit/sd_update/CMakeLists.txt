# sd_update unit tests (owned by the updater agent). Fixtures are made at test time by sd-updsign (test keys in a
# temporary directory). The fake binaries are built from fakeapp.c. Only loopback 127.0.0.1 is used.
sd_manifest_configure("${CMAKE_CURRENT_BINARY_DIR}/sd-test-update-fakeapp.manifest" "sd-test-update-fakeapp" FALSE)
add_executable(sd-test-update-fakeapp fakeapp.c "${CMAKE_CURRENT_BINARY_DIR}/sd-test-update-fakeapp.manifest")
set_target_properties(sd-test-update-fakeapp PROPERTIES FOLDER "tests")

sd_add_unit_test(update
  SOURCES main.c fixture.c test_verify.c test_state.c test_engine.c
  DEPS sd_update sd_crypto sd_platform sd_base ws2_32 advapi32)
# Fixture executables sit next to this test in bin/<Config> and are resolved at run time
# (sd_test_exe_dir_path): a compile-time absolute path would bake the build directory into the
# binary and break the reproducible-build check (04 §12.2).
target_compile_definitions(sd-test-update PRIVATE
  "SD_TEST_UPDSIGN=\"sd-updsign.exe\""
  "SD_TEST_FAKEAPP=\"sd-test-update-fakeapp.exe\"")
add_dependencies(sd-test-update sd-updsign sd-test-update-fakeapp)
