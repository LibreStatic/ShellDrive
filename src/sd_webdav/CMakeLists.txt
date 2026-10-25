# sd_webdav (02 §7): local WebDAV server for the Windows WebDAV redirector. Owned by the WebDAV agent.
#
# SSPI (secur32), iphlpapi, ETW and WNetOpenEnum are resolved at run time (XP floor); only ws2_32,
# mpr (WNetAddConnection2W / WNetCancelConnection2W) and advapi32 are imported.
#
# SD_WEBDAV_SOURCES is exported so tests can build the server on top of the fake-backed sd_vfs
# (tests/unit/sd_vfs) without SSH.

set(SD_WEBDAV_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_auth.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_client.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_http.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_lock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_methods.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_server.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_util.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wd_xml.c
  CACHE INTERNAL "sd_webdav sources")
set(SD_WEBDAV_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "sd_webdav directory")
set(SD_WEBDAV_SYSTEM_LIBS ws2_32 mpr advapi32 CACHE INTERNAL "sd_webdav system libraries")

sd_add_module(sd_webdav
  SOURCES
    ${SD_WEBDAV_SOURCES}
  DEPS
    sd_vfs
    sd_base
    sd_platform
  SYSTEM_LIBS
    ${SD_WEBDAV_SYSTEM_LIBS}
  HEADERS
    include/sd_webdav/sd_webdav.h
  PRIVATE_HEADERS
    wd_proto.h
    wd_server.h)

# Unit and integration tests (tests/unit/sd_webdav, owned by this module). Added from here so the
# shared tests/CMakeLists.txt list stays untouched; move it there with the next foundation change.
add_subdirectory(${CMAKE_SOURCE_DIR}/tests/unit/sd_webdav ${CMAKE_BINARY_DIR}/tests/unit/sd_webdav)
