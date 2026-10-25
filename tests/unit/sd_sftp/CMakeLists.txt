# Unit tests for sd_sftp. Owned by the sd_sftp agent.
#
# unit.sftp      codec fixtures + a scripted fake server (no SSH, no network); runs everywhere.
# interop.sftp   against OpenSSH sftp-server inside WSL over stdio pipes (D21: test fixture only);
#                exits with 77 (skipped) when wsl.exe or /usr/lib/openssh/sftp-server is missing.

set(_sftp_test_common sftp_test_tp.c sftp_test_tp.h test_util.c test_util.h)

sd_add_unit_test(sftp
  SOURCES main.c test_proto.c test_session.c ${_sftp_test_common}
  DEPS sd_sftp sd_base sd_platform)
target_include_directories(sd-test-sftp PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_sftp")

add_executable(sd-test-sftp-interop main_interop.c test_interop.c ${_sftp_test_common})
target_link_libraries(sd-test-sftp-interop PRIVATE sd_test_harness sd_sftp sd_base sd_platform)
target_include_directories(sd-test-sftp-interop PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_sftp")
set_target_properties(sd-test-sftp-interop PROPERTIES FOLDER "tests")
add_test(NAME interop.sftp COMMAND sd-test-sftp-interop)
set_tests_properties(interop.sftp PROPERTIES LABELS interop TIMEOUT 600 SKIP_RETURN_CODE 77)
