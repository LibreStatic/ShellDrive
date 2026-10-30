# sd_update: updater engine (04 §9). Pure verification, state, WinHTTP transport (resolved at run time, no
# static winhttp import) and the engine. Owned by the updater agent.

sd_add_module(sd_update
  SOURCES
    update_verify.c
    update_state.c
    update_winhttp.c
    update_engine.c
  DEPS
    sd_base
    sd_platform
    sd_crypto
  HEADERS
    include/sd_update/sd_update.h
  PRIVATE_HEADERS
    update_internal.h)
