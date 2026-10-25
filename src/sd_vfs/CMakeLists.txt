# sd_vfs (02 §1-§5, §8). Owned by the VFS agent (together with sd_dokan).
#
# SD_VFS_SOURCES is exported so tests can compile the module against a fake sd_sftp
# (tests/unit/sd_vfs) without linking the real sd_sftp library.

set(SD_VFS_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/vfs_core.c
  ${CMAKE_CURRENT_SOURCE_DIR}/vfs_name.c
  ${CMAKE_CURRENT_SOURCE_DIR}/vfs_ops.c
  ${CMAKE_CURRENT_SOURCE_DIR}/vfs_req.c
  ${CMAKE_CURRENT_SOURCE_DIR}/vfs_sd.c
  CACHE INTERNAL "sd_vfs sources")
set(SD_VFS_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "sd_vfs directory")

sd_add_module(sd_vfs
  SOURCES
    ${SD_VFS_SOURCES}
  DEPS
    sd_sftp
    sd_base
    sd_platform
  HEADERS
    include/sd_vfs/sd_vfs.h
  PRIVATE_HEADERS
    vfs_internal.h)
