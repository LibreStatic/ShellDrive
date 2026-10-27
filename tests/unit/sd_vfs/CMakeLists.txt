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
  SOURCES main.c test_vfs_name.c test_vfs_ops.c test_vfs_m1.c test_vfs_stripe.c
  DEPS sd_vfs_fake)

# Striping bench (02 §5.6): 1 GiB written and read through sd_vfs against the wsl-sshd fixture with
# connections = 1 versus connections = 3 striped. Plain ctest skips it (exit 77); run with
# SD_IT_BENCH=1 and the fixture up (tests/fixtures/wsl-sshd/start.ps1).
add_executable(sd-test-vfs-bench bench_pool.c)
target_link_libraries(sd-test-vfs-bench PRIVATE sd_test_harness sd_vfs sd_sftp sd_ssh sd_crypto
  sd_base sd_platform ws2_32)
target_include_directories(sd-test-vfs-bench PRIVATE
  "${SD_VFS_DIR}/include" "${CMAKE_SOURCE_DIR}/src/sd_sftp/include" "${CMAKE_SOURCE_DIR}/src/sd_ssh/include")
target_compile_definitions(sd-test-vfs-bench PRIVATE
  SD_SSH_WSL_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/wsl-sshd")
set_target_properties(sd-test-vfs-bench PROPERTIES FOLDER "tests")
add_test(NAME bench.vfs_pool COMMAND sd-test-vfs-bench)
# Throughput measurement (RUN_SERIAL) against the shared sshd fixture (wsl_sshd_fixture).
set_tests_properties(bench.vfs_pool PROPERTIES LABELS bench TIMEOUT 1800 SKIP_RETURN_CODE 77
  RESOURCE_LOCK wsl_sshd_fixture RUN_SERIAL TRUE)
