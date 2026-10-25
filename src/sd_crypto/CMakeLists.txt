# sd_crypto (01 §2). Owned by the crypto agent: add sources here (SOURCES makes it a static library).
# SIMD/AES-NI/SHA-NI translation units go in a separate list excluded from x86-ia32 by CMake (01 §2.3).
# blowfish_pi.inc and sha2_consts.inc are generated data tables (gen_blowfish_pi.py,
# gen_sha2_consts.py, run by hand; the outputs are committed).

# Per-area source lists (M2): each area agent owns sources_<area>.cmake and appends with
#   list(APPEND SD_CRYPTO_SOURCES file.c)  and, for public headers,  list(APPEND SD_CRYPTO_SOURCES_HEADERS include/...h)
set(SD_CRYPTO_SOURCES
    aes_cng.c
    aes_ct.c
    bcrypt_pbkdf.c
    chacha_poly.c
    ct.c
    curve25519.c
    gcm.c
    hash.c
    init.c
    pktcipher.c
    blowfish_pi.inc
    sha2_consts.inc)
set(SD_CRYPTO_SOURCES_HEADERS)
include(${CMAKE_CURRENT_LIST_DIR}/sources_pk.cmake OPTIONAL)
include(${CMAKE_CURRENT_LIST_DIR}/sources_pq.cmake OPTIONAL)

sd_add_module(sd_crypto
  SOURCES
    ${SD_CRYPTO_SOURCES}
  DEPS
    sd_base
    sd_platform
  HEADERS
    ${SD_CRYPTO_SOURCES_HEADERS}
    include/sd_crypto/sd_crypto.h
    include/sd_crypto/sd_ct.h
  PRIVATE_HEADERS
    crypto_internal.h
    sd_ct64.h)
