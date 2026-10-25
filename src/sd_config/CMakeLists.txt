# sd_config (03 §3: profiles, settings, policies). Placeholder so the apps agent can add it without
# touching the top-level CMakeLists.txt. Add SOURCES and HEADERS here.

sd_add_module(sd_config
  DEPS
    sd_base
    sd_platform)
