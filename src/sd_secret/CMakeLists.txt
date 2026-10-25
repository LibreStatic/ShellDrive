# sd_secret (03 §4: Credential Manager, DPAPI secret files, DPAPI-kept keys). Owned by the apps agent.

sd_add_module(sd_secret
  SOURCES
    secret.c
  DEPS
    sd_config
    sd_crypto
    sd_base
    sd_platform
  SYSTEM_LIBS
    advapi32
    crypt32
    shell32
  HEADERS
    include/sd_secret/sd_secret.h)
