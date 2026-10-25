# sd_ipc (03 §2). Owned by the apps/IPC agent (which also owns src/sd_base/json*.c, see sd_json.h).

sd_add_module(sd_ipc
  SOURCES
    ipc_common.c
    ipc_client.c
    ipc_server.c
  DEPS
    sd_base
    sd_platform
  SYSTEM_LIBS
    advapi32
  HEADERS
    include/sd_ipc/sd_ipc.h
  PRIVATE_HEADERS
    ipc_internal.h)
