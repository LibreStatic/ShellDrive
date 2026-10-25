# sd_crypto (01 §2). Owned by the crypto agent: add sources here (SOURCES makes it a static library).
# SIMD/AES-NI/SHA-NI translation units go in a separate list excluded from x86-ia32 by CMake (01 §2.3).
# blowfish_pi.inc and sha2_consts.inc are generated data tables (gen_blowfish_pi.py,
# gen_sha2_consts.py, run by hand; the outputs are committed).

sd_add_module(sd_crypto
  SOURCES
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
    sha2_consts.inc
  DEPS
    sd_base
    sd_platform
  HEADERS
    include/sd_crypto/sd_crypto.h
    include/sd_crypto/sd_ct.h
  PRIVATE_HEADERS
    crypto_internal.h
    sd_ct64.h)
