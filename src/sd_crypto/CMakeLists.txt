# sd_crypto (01 §2). Owned by the crypto agent: add sources here (SOURCES makes it a static library).
# SIMD/AES-NI/SHA-NI translation units go in a separate list excluded from x86-ia32 by CMake (01 §2.3).

sd_add_module(sd_crypto
  DEPS
    sd_base
    sd_platform
  HEADERS
    include/sd_crypto/sd_crypto.h
    include/sd_crypto/sd_ct.h)
