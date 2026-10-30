# Tests of the sd_ssh `auth` area (M2): key formats, certificates, DPAPI keys, agents, userauth.
#   unit.ssh_auth          sd-test-ssh_auth.exe (no network; fake agents and a scripted server)
#   interop.ssh_auth       sd-test-ssh-auth-interop.exe against its own WSL sshd instance
#                          (fixtures/auth-sshd.sh); exits 77 (skipped) without WSL/sshd.

sd_add_unit_test(ssh_auth
  SOURCES test_auth_main.c test_util.c test_keyfile_formats.c test_agent.c test_auth_flow.c
  DEPS sd_ssh sd_crypto sd_base sd_platform)
target_include_directories(sd-test-ssh_auth PRIVATE "${CMAKE_SOURCE_DIR}/src/sd_ssh")
target_compile_definitions(sd-test-ssh_auth PRIVATE
  SD_SSH_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
