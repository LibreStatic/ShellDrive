# Unit tests for sd_ssh. Owned by the sd_ssh agent.
#
#   unit.ssh       sd-test-ssh.exe: parsing and state-machine tests; tests that need sd_crypto print
#                  "[skip]" while sd_crypto still uses link-time fallbacks.
#   interop.ssh    sd-test-ssh-interop.exe against the WSL sshd fixture (tests/fixtures/wsl-sshd);
#                  exits 77 (CTest "skipped") when the fixture is not running or sd_crypto is incomplete.

sd_add_unit_test(ssh
  SOURCES main.c test_util.c test_negotiate.c test_packet.c test_known_hosts.c test_keyfile.c test_conn.c
  DEPS sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
target_compile_definitions(sd-test-ssh PRIVATE
  SD_SSH_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

add_executable(sd-test-ssh-interop test_interop.c test_util.c)
target_link_libraries(sd-test-ssh-interop PRIVATE sd_test_harness sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh-interop PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
target_compile_definitions(sd-test-ssh-interop PRIVATE
  SD_SSH_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  SD_SSH_WSL_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/wsl-sshd")
set_target_properties(sd-test-ssh-interop PROPERTIES FOLDER "tests")
add_test(NAME interop.ssh COMMAND sd-test-ssh-interop)
# interop.sftp_ssh kills and restarts the same fixture: never run both at once
set_tests_properties(interop.ssh PROPERTIES LABELS interop TIMEOUT 300 SKIP_RETURN_CODE 77
  RESOURCE_LOCK wsl_sshd_fixture)

# M2 matrix interop (run-matrix.ps1): one entry per sub-test so the runner can scope rows by label.
# srv_all = every row; plain `ctest` without SD_IT_* exits 77 (skipped).
add_executable(sd-test-ssh-interop-m2 test_interop_m2.c test_util.c)
target_link_libraries(sd-test-ssh-interop-m2 PRIVATE sd_test_harness sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh-interop-m2 PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
target_compile_definitions(sd-test-ssh-interop-m2 PRIVATE
  SD_SSH_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set_target_properties(sd-test-ssh-interop-m2 PROPERTIES FOLDER "tests")
add_test(NAME interop.ssh_matrix_connect COMMAND sd-test-ssh-interop-m2 --filter matrix_connect_exec)
add_test(NAME interop.ssh_matrix_kex COMMAND sd-test-ssh-interop-m2 --filter matrix_kex_walk)
add_test(NAME interop.ssh_matrix_pq COMMAND sd-test-ssh-interop-m2 --filter matrix_pq_required)
add_test(NAME interop.ssh_matrix_update COMMAND sd-test-ssh-interop-m2 --filter matrix_hostkeys_update)
set_tests_properties(interop.ssh_matrix_connect PROPERTIES LABELS "interop;srv_all" TIMEOUT 300
  SKIP_RETURN_CODE 77)
set_tests_properties(interop.ssh_matrix_kex PROPERTIES
  LABELS "interop;srv_modern;srv_ossh10;srv_ossh10pq;srv_legacy;srv_legacy3des;srv_cert" TIMEOUT 600
  SKIP_RETURN_CODE 77)
set_tests_properties(interop.ssh_matrix_pq PROPERTIES LABELS "interop;srv_ossh10pq" TIMEOUT 300
  SKIP_RETURN_CODE 77)
set_tests_properties(interop.ssh_matrix_update PROPERTIES LABELS "interop;srv_rotate" TIMEOUT 300
  SKIP_RETURN_CODE 77 RESOURCE_LOCK wsl_rotate_fixture)

# M2 per-area test lists (each area owns tests_<area>.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/tests_auth.cmake OPTIONAL)
