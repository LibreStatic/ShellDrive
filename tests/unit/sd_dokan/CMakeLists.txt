# Unit and integration tests for sd_dokan. Owned by the sd_dokan agent.
#
# sd_dokan_fake: the adapter sources on top of sd_vfs_fake (tests/unit/sd_vfs), so the Dokany mount
# test runs without SSH.

add_library(sd_dokan_fake STATIC ${SD_DOKAN_SOURCES})
target_include_directories(sd_dokan_fake PUBLIC "${SD_DOKAN_DIR}/include" "${SD_DOKAN_DIR}")
target_link_libraries(sd_dokan_fake PUBLIC sd_vfs_fake)
set_target_properties(sd_dokan_fake PROPERTIES FOLDER "tests")

sd_add_unit_test(dokan
  SOURCES main.c test_dokan.c
  DEPS sd_dokan_fake)

# Integration: mounts a drive letter through the installed Dokany (current-session mount, no
# elevation). Exit code 77 = skipped (no Dokany 2.1+, or the mount is refused).
add_executable(sd-test-dokany test_dokany_mount.c)
target_link_libraries(sd-test-dokany PRIVATE sd_test_harness sd_dokan_fake)
set_target_properties(sd-test-dokany PROPERTIES FOLDER "tests")
add_test(NAME dokany.mount COMMAND sd-test-dokany)
# Picks the first free drive letter, as webdav.redirector does: drive_letter keeps the two apart.
set_tests_properties(dokany.mount PROPERTIES LABELS dokany SKIP_RETURN_CODE 77 TIMEOUT 900
  RESOURCE_LOCK drive_letter)
