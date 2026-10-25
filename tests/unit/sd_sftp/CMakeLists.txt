# Unit tests for sd_sftp. Owned by the sd_sftp agent.
#
# unit.sftp      codec fixtures + a scripted fake server (no SSH, no network); runs everywhere.
# interop.sftp   against OpenSSH sftp-server inside WSL over stdio pipes (D21: test fixture only);
#                exits with 77 (skipped) when wsl.exe or /usr/lib/openssh/sftp-server is missing.
# interop.sftp_ssh  sd_sftp over sd_ssh against the WSL sshd fixture (tests/fixtures/wsl-sshd): M1
#                reconnect with sshd killed during 256 MiB transfers, TCP drop, frozen link. Exits 77
#                when the fixture is not running. Shares the fixture with interop.ssh (RESOURCE_LOCK).

set(_sftp_test_common sftp_test_tp.c sftp_test_tp.h test_util.c test_util.h)

sd_add_unit_test(sftp
  SOURCES main.c test_proto.c test_session.c test_reconnect.c ${_sftp_test_common}
  DEPS sd_sftp sd_base sd_platform)
target_include_directories(sd-test-sftp PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_sftp")

add_executable(sd-test-sftp-interop main_interop.c test_interop.c ${_sftp_test_common})
target_link_libraries(sd-test-sftp-interop PRIVATE sd_test_harness sd_sftp sd_base sd_platform)
target_include_directories(sd-test-sftp-interop PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_sftp")
set_target_properties(sd-test-sftp-interop PROPERTIES FOLDER "tests")
add_test(NAME interop.sftp COMMAND sd-test-sftp-interop)
set_tests_properties(interop.sftp PROPERTIES LABELS interop TIMEOUT 600 SKIP_RETURN_CODE 77)

add_executable(sd-test-sftp-ssh-interop test_ssh_interop.c ${_sftp_test_common})
target_link_libraries(sd-test-sftp-ssh-interop PRIVATE sd_test_harness sd_sftp sd_ssh sd_crypto sd_base sd_platform ws2_32)
target_include_directories(sd-test-sftp-ssh-interop PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_sftp")
target_compile_definitions(sd-test-sftp-ssh-interop PRIVATE
  SD_SSH_WSL_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/wsl-sshd")
set_target_properties(sd-test-sftp-ssh-interop PROPERTIES FOLDER "tests")
add_test(NAME interop.sftp_ssh COMMAND sd-test-sftp-ssh-interop)
set_tests_properties(interop.sftp_ssh PROPERTIES LABELS interop TIMEOUT 900 SKIP_RETURN_CODE 77
  RESOURCE_LOCK wsl_sshd_fixture)
