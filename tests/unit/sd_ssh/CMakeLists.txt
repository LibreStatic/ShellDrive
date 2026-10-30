# Unit tests for sd_ssh. Owned by the sd_ssh agent.
#
#   unit.ssh       sd-test-ssh.exe: parsing and state-machine tests; tests that need sd_crypto print
#                  "[skip]" while sd_crypto still uses link-time fallbacks.
#   interop.ssh    sd-test-ssh-interop.exe against the WSL sshd fixture (tests/fixtures/wsl-sshd);
#                  exits 77 (CTest "skipped") when the fixture is not running or sd_crypto is incomplete.

sd_add_unit_test(ssh
  SOURCES main.c test_util.c test_negotiate.c test_packet.c test_known_hosts.c test_keyfile.c test_conn.c test_proxy.c
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
# interop.sftp_ssh kills and restarts the same fixture: never run both at once. The matrix "modern" row is the same
# sshd on port 2222, so the matrix rows that use it take wsl_sshd_fixture too; "rotate" rewrites its own host keys
# (wsl_rotate_fixture), and srv_all includes that row.
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
add_test(NAME interop.ssh_matrix_auth_keys COMMAND sd-test-ssh-interop-m2 --filter matrix_auth_key_formats)
add_test(NAME interop.ssh_matrix_auth_certs COMMAND sd-test-ssh-interop-m2 --filter matrix_auth_certs)
set_tests_properties(interop.ssh_matrix_connect PROPERTIES LABELS "interop;matrix;srv_all" TIMEOUT 300
  SKIP_RETURN_CODE 77 RESOURCE_LOCK "wsl_sshd_fixture;wsl_rotate_fixture")
set_tests_properties(interop.ssh_matrix_kex PROPERTIES
  LABELS "interop;matrix;srv_modern;srv_ossh10;srv_ossh10pq;srv_legacy;srv_legacy3des;srv_cert" TIMEOUT 600
  SKIP_RETURN_CODE 77 RESOURCE_LOCK wsl_sshd_fixture)
set_tests_properties(interop.ssh_matrix_pq PROPERTIES LABELS "interop;matrix;srv_ossh10pq" TIMEOUT 300
  SKIP_RETURN_CODE 77)
set_tests_properties(interop.ssh_matrix_update PROPERTIES LABELS "interop;matrix;srv_rotate" TIMEOUT 300
  SKIP_RETURN_CODE 77 RESOURCE_LOCK wsl_rotate_fixture)
set_tests_properties(interop.ssh_matrix_auth_keys PROPERTIES
  LABELS "interop;matrix;srv_ossh10" TIMEOUT 600 SKIP_RETURN_CODE 77)
set_tests_properties(interop.ssh_matrix_auth_certs PROPERTIES LABELS "interop;matrix;srv_cert" TIMEOUT 600
  SKIP_RETURN_CODE 77)

# M2 transport area (01 §4, §7): algorithm lists, KEX methods against an in-process mock server,
# host key signatures, certificates, CBC/SHA-1 packet protection, known_hosts M2 (hashed, live sources,
# UpdateHostKeys review helpers). test_kex_main.c owns main() and runs the tr_* cases of both sources.
#   unit.ssh_transport     sd-test-ssh_transport.exe (no network)
sd_add_unit_test(ssh_transport
  SOURCES test_kex_main.c test_kex.c test_known_hosts_m2.c test_util.c
  DEPS sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh_transport PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
target_compile_definitions(sd-test-ssh_transport PRIVATE
  SD_SSH_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
# known_hosts M2 writes HKCU Software\LibreStatic\ShellDriveTest\SshHostKeys-<pid> (test_known_hosts_m2.c): the
# parent key is the one unit.apps sweeps (hkcu_shelldrivetest).
set_tests_properties(unit.ssh_transport PROPERTIES RESOURCE_LOCK hkcu_shelldrivetest)

# M2 per-area test lists (each area owns tests_<area>.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/tests_auth.cmake OPTIONAL)

# zlib@openssh.com (01 section 4.7): own RFC 1950/1951 codec, streams with reference fixtures, corrupt and bomb
# input, round trips, and the delayed-compression packet test lives in unit.ssh (test_packet.c).
#   unit.zlib              sd-test-zlib.exe (no network)
sd_add_unit_test(zlib
  SOURCES test_zlib.c
  DEPS sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-zlib PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")

# interop.zlib: the same sd-test-ssh-interop binary, one test. The fixture's sshd uses OpenSSH's default
# "Compression delayed", so zlib@openssh.com is negotiated; exit 77 when the fixture is not running.
add_test(NAME interop.zlib COMMAND sd-test-ssh-interop --filter interop_zlib_delayed)
set_tests_properties(interop.zlib PROPERTIES LABELS interop TIMEOUT 300 SKIP_RETURN_CODE 77
  RESOURCE_LOCK wsl_sshd_fixture)

# M7 adaptive channel windows (01 section 4.8): a simulated link with a virtual clock (test_window.c). No network.
#   unit.ssh_window        sd-test-ssh_window.exe
sd_add_unit_test(ssh_window
  SOURCES test_window.c
  DEPS sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh_window PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
