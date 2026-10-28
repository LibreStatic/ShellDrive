# sd_dokan (02 §6). Owned by the VFS agent. dokan2.dll is never linked: GetProcAddress only.
#
# SD_DOKAN_SOURCES is exported so tests can build the adapter on top of the fake-backed sd_vfs.

set(SD_DOKAN_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/dokan_load.c
  ${CMAKE_CURRENT_SOURCE_DIR}/dokan_mount.c
  ${CMAKE_CURRENT_SOURCE_DIR}/dokan_cache.c
  CACHE INTERNAL "sd_dokan sources")
set(SD_DOKAN_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "sd_dokan directory")

sd_add_module(sd_dokan
  SOURCES
    ${SD_DOKAN_SOURCES}
  DEPS
    sd_vfs
    sd_base
    sd_platform
  HEADERS
    include/sd_dokan/sd_dokan.h
  PRIVATE_HEADERS
    dokan_abi.h
    dokan_internal.h
    dokan_cache.h)
