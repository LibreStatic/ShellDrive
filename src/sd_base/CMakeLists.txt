# sd_base: no windows.h (00 §5, C39). Fuzzable; the allocator (sd_mem.h) is provided by sd_platform.

# Optional sources added by other M0 agents without editing this file: the sd_ipc agent owns json*.c
# (sd_json.h), the sd_config agent owns ini*.c. Re-run CMake configure after adding one.
file(GLOB SD_BASE_OPTIONAL_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/json*.c" "${CMAKE_CURRENT_SOURCE_DIR}/ini*.c")

sd_add_module(sd_base
  SOURCES
    buf.c
    err.c
    secure_zero.c
    utf.c
    ${SD_BASE_OPTIONAL_SOURCES}
  HEADERS
    include/sd_base/sd_buf.h
    include/sd_base/sd_checked.h
    include/sd_base/sd_err.h
    include/sd_base/sd_json.h
    include/sd_base/sd_mem.h
    include/sd_base/sd_utf.h)

# sd_alloc and friends live in sd_platform; MSVC resolves symbols across static libraries in any
# order, the INTERFACE link only makes sure every consumer of sd_base also links sd_platform.
target_link_libraries(sd_base INTERFACE sd_platform)
