/* sd_crypto private interfaces shared between its translation units and its unit tests
 * (tests/unit/sd_crypto). Not a public contract. */
#ifndef SD_CRYPTO_INTERNAL_H
#define SD_CRYPTO_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"

/* ---- init state ---- */

/* Runs sd_crypto_init(0) if nobody did yet; returns the effective flags. */
uint32_t sd_crypto_ensure_init(void);
/* Nonzero when the CNG AES backend may be used (probed, and not SD_CRYPTO_INIT_OWN_ONLY). */
int sd_crypto_use_cng_aes(void);
int sd_crypto_use_cng_gcm(void);
/* Test hook: nonzero forces the own AES backend for objects created afterwards (process-wide). */
void sd_crypto_test_force_own(int on);

/* x86/x64 hardware fast paths (M6, SHA-NI and AES-NI). SD_CRYPTO_X86_HW is 1 only where the hardware files
   (aes_ni.c, sha256_ni.c) are built: the x86-sse2 and x64 flavours, never x86-ia32 and never ARM. CMake
   (src/sd_crypto/sources_hw.cmake) must agree with this test. */
#if !defined(SD_CRYPTO_X86_HW)
#  if (defined(_M_X64) || (defined(_M_IX86) && defined(SD_X86_ARCH_SSE2))) && !defined(SD_X86_ARCH_IA32)
#    define SD_CRYPTO_X86_HW 1
#  else
#    define SD_CRYPTO_X86_HW 0
#  endif
#endif
/* Hardware usable on this CPU and build (ignores the portable hook). */
int sd_crypto_hw_aes_capable(void);
int sd_crypto_hw_sha256_capable(void);
/* Hardware in use: capable and not forced to the portable code (SD_CRYPTO_PORTABLE=1 or the test hook). */
int sd_crypto_use_hw_aes(void);
int sd_crypto_use_hw_sha256(void);
/* Test hook: nonzero forces the portable SHA-256 and AES code for everything created or hashed afterwards. */
void sd_crypto_test_force_portable(int on);

/* ---- AES, constant-time bitsliced (aes_ct.c) ---- */

/* Round keys in bitsliced form: 8 words per round key, each word holds one bit of all 16 key bytes,
   replicated for the 4 parallel blocks. */
typedef struct sd_aes_own {
  uint64_t rk[15][8];
  uint32_t rounds;            /* 10, 12, 14 */
  uint32_t hw;                /* nonzero: encryption runs on AES-NI over ni_rk (chosen at key setup) */
  uint8_t ni_rk[15][16];      /* the same byte round keys FIPS 197 expands, for AES-NI */
} sd_aes_own;

#if SD_CRYPTO_X86_HW
/* AES-NI rounds over byte round keys (16 * (rounds + 1) bytes, FIPS 197 order). Encryption only: CTR and GCM
   need no decryption, and CBC decryption stays on the bitsliced core (aes_ni.c). */
void sd_aes_ni_encrypt_blocks(const uint8_t *rk, uint32_t rounds, const uint8_t *in, uint8_t *out,
                              size_t nblocks);
/* SHA-256 compression over nblocks 64-byte blocks with the SHA extensions; k is the FIPS 180-4 constant
   table (sha256_ni.c). */
void sd_sha256_ni_blocks(uint32_t st[8], const uint8_t *p, size_t nblocks, const uint32_t k[64]);
#endif

sd_err sd_aes_own_init(sd_aes_own *k, const uint8_t *key, size_t key_len);
/* Encrypts/decrypts n (1..4) independent 16-byte blocks; time depends only on the call, not n. */
void   sd_aes_own_encrypt(const sd_aes_own *k, const uint8_t *in, uint8_t *out, size_t nblocks);
void   sd_aes_own_decrypt(const sd_aes_own *k, const uint8_t *in, uint8_t *out, size_t nblocks);
void   sd_aes_own_wipe(sd_aes_own *k);
/* S-box via the bitsliced circuit, for the unit test (inverse = 1 for the inverse S-box). */
uint8_t sd_aes_sbox_ct(uint8_t x, int inverse);

/* CTR over the own core; ctr is advanced by the number of blocks used (partial block counts). */
void sd_aes_own_ctr(const sd_aes_own *k, uint8_t ctr[16], const uint8_t *in, size_t len, uint8_t *out);

/* ---- GHASH, constant time (gcm.c) ---- */

typedef struct sd_ghash {
  uint64_t h[2];              /* hash key, big-endian halves */
  uint64_t y[2];              /* accumulator */
} sd_ghash;
void sd_ghash_init(sd_ghash *g, const uint8_t h[16]);
void sd_ghash_update(sd_ghash *g, const uint8_t *p, size_t n);   /* zero-pads the last block */
void sd_ghash_lengths(sd_ghash *g, uint64_t aad_len, uint64_t ct_len);
void sd_ghash_out(const sd_ghash *g, uint8_t out[16]);

/* GCM building blocks on an own key: CTR with the 32-bit increment of SP 800-38D (in may equal out;
   ctr is advanced), and the tag over aad || ciphertext (derives H and E(J0) from the key). */
void sd_gcm_own_ctr32(const sd_aes_own *k, uint8_t ctr[16], const uint8_t *in, size_t len, uint8_t *out);
void sd_gcm_own_tag(const sd_aes_own *k, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, uint8_t tag[16]);

/* Explicit backends of the public raw AES functions (the public ones dispatch). */
sd_err sd_aes_ctr_own(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                      const uint8_t *in, size_t len, uint8_t *out);
sd_err sd_aes_gcm_encrypt_own(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16]);
sd_err sd_aes_gcm_decrypt_own(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              const uint8_t tag[16], uint8_t *out);

/* ---- CNG AES backend (aes_cng.c). SD_E_UNSUPPORTED when CNG is absent. ---- */

typedef struct sd_cng_key sd_cng_key;
sd_err sd_cng_probe(uint32_t *os_caps);            /* sets SD_OS_CNG / SD_OS_CNG_GCM */
sd_err sd_cng_key_new(const uint8_t *key, size_t key_len, int gcm, sd_cng_key **out);
void   sd_cng_key_free(sd_cng_key *k);
/* ECB encryption of whole blocks (CTR keystream). */
sd_err sd_cng_ecb_encrypt(sd_cng_key *k, const uint8_t *in, uint8_t *out, size_t len);
sd_err sd_cng_gcm(sd_cng_key *k, int encrypt, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                  const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]);
sd_err sd_aes_ctr_cng(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                      const uint8_t *in, size_t len, uint8_t *out);
sd_err sd_aes_gcm_encrypt_cng(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16]);
sd_err sd_aes_gcm_decrypt_cng(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              const uint8_t tag[16], uint8_t *out);

/* ---- byte order helpers (every Windows target is little-endian) ---- */

#include <stdlib.h>
#include <string.h>

static SD_FORCEINLINE uint32_t sd_load_le32(const uint8_t *p)
{
  uint32_t v;
  memcpy(&v, p, 4);
  return v;
}
static SD_FORCEINLINE void sd_store_le32(uint8_t *p, uint32_t v)
{
  memcpy(p, &v, 4);
}
static SD_FORCEINLINE uint32_t sd_load_be32(const uint8_t *p)
{
  return _byteswap_ulong(sd_load_le32(p));
}
static SD_FORCEINLINE void sd_store_be32(uint8_t *p, uint32_t v)
{
  sd_store_le32(p, _byteswap_ulong(v));
}
static SD_FORCEINLINE uint64_t sd_load_be64(const uint8_t *p)
{
  uint64_t v;
  memcpy(&v, p, 8);
  return _byteswap_uint64(v);
}
static SD_FORCEINLINE void sd_store_be64(uint8_t *p, uint64_t v)
{
  v = _byteswap_uint64(v);
  memcpy(p, &v, 8);
}

#endif /* SD_CRYPTO_INTERNAL_H */
