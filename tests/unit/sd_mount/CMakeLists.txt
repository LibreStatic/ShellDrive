# Unit tests for sd_mount against a scripted fake of sd_ssh/sd_sftp/sd_vfs/sd_dokan (no network).
# The fake (fake_backend.c) is also used by the host smoke test in tests/apps.

add_library(sd_mount_fake_backend STATIC fake_backend.c fake_backend.h)
target_link_libraries(sd_mount_fake_backend PUBLIC sd_mount sd_base sd_platform)
target_include_directories(sd_mount_fake_backend PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(sd_mount_fake_backend PROPERTIES FOLDER "tests")

sd_add_unit_test(mount
  SOURCES main.c test_mount.c test_mount_m2.c
  DEPS sd_mount_fake_backend sd_mount)
