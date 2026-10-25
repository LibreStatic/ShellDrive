# sd_mount (03 §1.11: profile -> session -> vfs -> backend; host only). Owned by the apps agent.
#
# sd_mount itself compiles against the public headers of sd_ssh/sd_sftp/sd_vfs/sd_dokan and reaches
# them only through sd_mount_backend, so it links and is unit-tested with fakes while those modules
# are built in parallel. sd_mount_real binds the real functions; it is always compiled (header drift
# shows up at once) but linked only into binaries that need the real stack.

sd_add_module(sd_mount
  SOURCES
    mount.c
  DEPS
    sd_base
    sd_platform
  HEADERS
    include/sd_mount/sd_mount.h)
# Header-only use of the other modules: include paths without linking their (maybe absent) code.
foreach(_m sd_ssh sd_sftp sd_vfs sd_dokan sd_crypto)
  target_include_directories(sd_mount PUBLIC $<TARGET_PROPERTY:${_m},INTERFACE_INCLUDE_DIRECTORIES>)
endforeach()

add_library(sd_mount_real STATIC mount_real.c)
target_link_libraries(sd_mount_real PUBLIC sd_mount sd_dokan sd_vfs sd_sftp sd_ssh)

# AUTO: the real backend is linked into shelldrive-host when every module it needs is a library.
set(SD_MOUNT_REAL_BACKEND "AUTO" CACHE STRING "Link the real SSH/SFTP/VFS/Dokany stack into the host (AUTO|ON|OFF)")
set_property(CACHE SD_MOUNT_REAL_BACKEND PROPERTY STRINGS AUTO ON OFF)
set(_sd_real_ok ON)
foreach(_m sd_ssh sd_sftp sd_vfs sd_dokan sd_crypto)
  get_target_property(_t ${_m} TYPE)
  if(NOT _t STREQUAL "STATIC_LIBRARY")
    set(_sd_real_ok OFF)
  endif()
endforeach()
if(SD_MOUNT_REAL_BACKEND STREQUAL "ON")
  set(_sd_real_ok ON)
elseif(SD_MOUNT_REAL_BACKEND STREQUAL "OFF")
  set(_sd_real_ok OFF)
endif()
set(SD_HOST_REAL_BACKEND ${_sd_real_ok} CACHE INTERNAL "shelldrive-host links sd_mount_real")
message(STATUS "shelldrive-host mount backend: real=${SD_HOST_REAL_BACKEND} (SD_MOUNT_REAL_BACKEND=${SD_MOUNT_REAL_BACKEND})")
