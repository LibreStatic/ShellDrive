# sd_state (03 §8.2.1, TM-R26): the mount state snapshot section, shared by the agent (writer) and the
# shell extension (reader). Depends only on sd_base, sd_platform and sd_ipc, so the DLL can link it.

sd_add_module(sd_state
  SOURCES
    state_codec.c
    state_section.c
  DEPS
    sd_ipc
    sd_platform
    sd_base
  SYSTEM_LIBS
    advapi32
  HEADERS
    include/sd_state/sd_state.h)
