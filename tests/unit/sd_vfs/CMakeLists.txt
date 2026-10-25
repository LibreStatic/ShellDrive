# Unit tests for sd_vfs. Owned by the sd_vfs agent.
#
# sd_vfs_fake: the sd_vfs sources compiled against the in-memory fake sd_sftp (fake_sftp.c), without
# linking the real sd_sftp library. Also used by tests/unit/sd_dokan.

add_library(sd_vfs_fake STATIC ${SD_VFS_SOURCES} fake_sftp.c fake_sftp.h)
target_include_directories(sd_vfs_fake PUBLIC
  "${SD_VFS_DIR}/include"
  "${SD_VFS_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_SOURCE_DIR}/src/sd_sftp/include"
  "${CMAKE_SOURCE_DIR}/src/sd_ssh/include")
target_link_libraries(sd_vfs_fake PUBLIC sd_headers sd_crypto sd_base sd_platform)
set_target_properties(sd_vfs_fake PROPERTIES FOLDER "tests")

sd_add_unit_test(vfs
  SOURCES main.c test_vfs_name.c test_vfs_ops.c test_vfs_m1.c
  DEPS sd_vfs_fake)
