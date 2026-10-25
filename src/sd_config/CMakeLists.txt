# sd_config (03 §3: profiles, settings, policies). Owned by the apps agent. The INI format (sd_ini,
# 03 §3.3) lives here rather than in sd_base because it decodes ANSI files through Win32.

sd_add_module(sd_config
  SOURCES
    ini.c
    profile.c
    profile_m2.c
    import.c
  DEPS
    sd_base
    sd_platform
    sd_crypto
  SYSTEM_LIBS
    advapi32
    shell32
  HEADERS
    include/sd_config/sd_config.h
    include/sd_config/sd_ini.h
    include/sd_config/sd_import.h
  PRIVATE_HEADERS
    config_internal.h)
