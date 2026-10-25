# sd_platform: the Win32 layer (00 §5, C39): allocator, run-time API resolution, OS/CPU detection,
# threads, time, logging, secret buffers.

sd_add_module(sd_platform
  SOURCES
    alloc.c
    log.c
    platform.c
    secbuf.c
    thread.c
    time.c
  DEPS
    sd_base
  HEADERS
    include/sd_platform/sd_log.h
    include/sd_platform/sd_platform.h
    include/sd_platform/sd_secbuf.h
    include/sd_platform/sd_thread.h
    include/sd_platform/sd_time.h)
