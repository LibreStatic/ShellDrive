# Unit and integration tests for sd_webdav. Owned by the WebDAV agent.
#
# sd_webdav_fake: the server sources on top of sd_vfs_fake (tests/unit/sd_vfs), so the tests run without
# SSH. Added from src/sd_webdav/CMakeLists.txt (see there).

add_library(sd_webdav_fake STATIC ${SD_WEBDAV_SOURCES})
target_include_directories(sd_webdav_fake PUBLIC "${SD_WEBDAV_DIR}/include" "${SD_WEBDAV_DIR}")
target_link_libraries(sd_webdav_fake PUBLIC sd_vfs_fake ${SD_WEBDAV_SYSTEM_LIBS})
set_target_properties(sd_webdav_fake PROPERTIES FOLDER "tests")

# Protocol helpers, the loopback server through raw sockets (client-side SSPI) and its limits.
sd_add_unit_test(webdav
  SOURCES main.c test_proto.c test_server.c wd_client_util.c wd_client_util.h
  DEPS sd_webdav_fake secur32)

# Integration: maps the fake-backed export through the real Windows WebDAV redirector (WebClient) on
# a free drive letter and drives it with Win32 file APIs. Exit code 77 = skipped (WebClient missing,
# disabled or not startable without an administrator).
add_executable(sd-test-webdav-redirector test_redirector.c)
target_link_libraries(sd-test-webdav-redirector PRIVATE sd_test_harness sd_webdav_fake)
set_target_properties(sd-test-webdav-redirector PROPERTIES FOLDER "tests")
add_test(NAME webdav.redirector COMMAND sd-test-webdav-redirector)
set_tests_properties(webdav.redirector PROPERTIES LABELS webdav SKIP_RETURN_CODE 77 TIMEOUT 900)
