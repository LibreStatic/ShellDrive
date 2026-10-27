# sd_update unit tests (owned by the updater agent). Fixtures are made at test time by sd-updsign (test keys in a
# temporary directory). The fake binaries are built from fakeapp.c. Only loopback 127.0.0.1 is used.
add_executable(sd-test-update-fakeapp fakeapp.c)
set_target_properties(sd-test-update-fakeapp PROPERTIES FOLDER "tests")

sd_add_unit_test(update
  SOURCES main.c fixture.c test_verify.c test_state.c test_engine.c
  DEPS sd_update sd_crypto sd_platform sd_base ws2_32 advapi32)
target_compile_definitions(sd-test-update PRIVATE
  "SD_TEST_UPDSIGN=\"$<TARGET_FILE:sd-updsign>\""
  "SD_TEST_FAKEAPP=\"$<TARGET_FILE:sd-test-update-fakeapp>\"")
add_dependencies(sd-test-update sd-updsign sd-test-update-fakeapp)
