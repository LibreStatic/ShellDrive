/* sd_crypto M2 additions, symmetric and post-quantum (01 §2.2, §2.6, §2.8.4; decisions.md D15, D33):
 * SHA3-256/512 and SHAKE128/256 (FIPS 202), ML-KEM-768 (FIPS 203) with the mlkem768x25519-sha256
 * combiner, BLAKE2b (RFC 7693), Argon2d/i/id (RFC 9106, PuTTY PPK v3), raw AES-CBC and 3DES-CBC.
 * The packet cipher names aes128-cbc, aes192-cbc, aes256-cbc and 3des-cbc are served by
 * sd_pktcipher_find()/sd_pktcipher_crypt() (sd_crypto.h, flags SD_PC_CBC | SD_PC_LEGACY); the CBC
 * chaining value is kept in the object across calls. Packet MACs (hmac-sha1, hmac-sha1-etm@openssh.com,
 * hmac-sha2-*) are computed by sd_ssh with sd_hmac_*; SHA-1 comes from sd_crypto_pk.h.
 * sd_cipher_oneshot() also accepts "3des-cbc" and the PEM name "DES-EDE3-CBC" (24-byte key, 8-byte IV).
 *
 * Rules of sd_crypto.h apply: reentrant, secrets wipe themselves, no allocation except Argon2's memory
 * (VirtualAlloc, released and wiped before return). Included by sd_crypto.h; do not include directly. */
#ifndef SD_CRYPTO_PQ_H
#define SD_CRYPTO_PQ_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* ---- SHA-3 / SHAKE (FIPS 202). Fixed-size context, no allocation. ---- */

typedef struct sd_keccak_ctx { uint64_t a[25]; uint32_t rate, pos; uint8_t pad, squeezing, outlen, rsvd; } sd_keccak_ctx;

void sd_sha3_256(uint8_t out[32], const void *p, size_t n);
void sd_sha3_512(uint8_t out[64], const void *p, size_t n);
/* Incremental SHA3-256/512: bits = 256 | 512. final writes bits/8 bytes and zeroizes c. */
void sd_sha3_init(sd_keccak_ctx *c, int bits);
void sd_sha3_update(sd_keccak_ctx *c, const void *p, size_t n);
void sd_sha3_final(sd_keccak_ctx *c, uint8_t *out);
/* SHAKE128/256 XOF: bits = 128 | 256. Absorb any number of times, then squeeze any number of times
   (no absorb after the first squeeze). Call sd_keccak_wipe when done. */
void sd_shake_init(sd_keccak_ctx *c, int bits);
void sd_shake_absorb(sd_keccak_ctx *c, const void *p, size_t n);
void sd_shake_squeeze(sd_keccak_ctx *c, uint8_t *out, size_t n);
void sd_shake(int bits, uint8_t *out, size_t outlen, const void *p, size_t n);    /* one-shot */
void sd_keccak_wipe(sd_keccak_ctx *c);

/* ---- ML-KEM-768 (FIPS 203) ---- */

#define SD_MLKEM768_PK_LEN 1184     /* encapsulation key ek */
#define SD_MLKEM768_SK_LEN 2400     /* decapsulation key dk = dk_pke || ek || H(ek) || z */
#define SD_MLKEM768_CT_LEN 1088
#define SD_MLKEM768_SS_LEN 32

/* Seeds come from sd_random(). SD_E_CRYPTO only if the RNG fails. */
sd_err sd_mlkem768_keypair(uint8_t pk[1184], uint8_t sk[2400]);
/* Encaps checks the ek modulus (FIPS 203 7.2): SD_E_CRYPTO when a coefficient is >= q. */
sd_err sd_mlkem768_encaps(uint8_t ct[1088], uint8_t ss[32], const uint8_t pk[1184]);
/* Decaps checks the dk hash (FIPS 203 7.3): SD_E_CRYPTO when H(ek) inside dk does not match. A bad
   ciphertext is never reported: implicit rejection returns SD_OK with ss = J(z || ct). Constant time. */
sd_err sd_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400]);
/* Deterministic variants (ML-KEM.KeyGen_internal / Encaps_internal) for KATs and the mock server. */
sd_err sd_mlkem768_keypair_derand(uint8_t pk[1184], uint8_t sk[2400], const uint8_t d[32], const uint8_t z[32]);
sd_err sd_mlkem768_encaps_derand(uint8_t ct[1088], uint8_t ss[32], const uint8_t pk[1184], const uint8_t m[32]);
sd_err sd_mlkem768_check_pk(const uint8_t pk[1184]);                     /* modulus check only */

/* ---- mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex, OpenSSH 9.9+) ----
   Client init (Q_C) = ML-KEM ek (1184) || X25519 pub (32); server reply (Q_S) = ML-KEM ct (1088) ||
   X25519 pub (32); shared secret K = SHA-256(mlkem_ss || x25519_ss), 32 bytes, which sd_ssh encodes
   as an SSH *string* in the exchange hash and key derivation. An all-zero X25519 result is rejected. */
#define SD_MLKEM768X25519_INIT_LEN  1216
#define SD_MLKEM768X25519_REPLY_LEN 1120

typedef struct sd_mlkem768x25519_client {
  uint8_t mlkem_sk[2400];
  uint8_t x25519_sk[32];
} sd_mlkem768x25519_client;

/* Generates fresh ephemeral keys into st and writes Q_C. */
sd_err sd_mlkem768x25519_client_init(sd_mlkem768x25519_client *st, uint8_t q_c[1216]);
/* Consumes Q_S and writes K. Always wipes st. SD_E_CRYPTO on an all-zero X25519 secret. */
sd_err sd_mlkem768x25519_client_finish(sd_mlkem768x25519_client *st, const uint8_t q_s[1120], uint8_t k[32]);
void   sd_mlkem768x25519_client_wipe(sd_mlkem768x25519_client *st);
/* Server side (test-only mock server, differential tests): consumes Q_C, writes Q_S and K.
   SD_E_CRYPTO when the ek modulus check fails or the X25519 secret is all-zero. */
sd_err sd_mlkem768x25519_server(const uint8_t q_c[1216], uint8_t q_s[1120], uint8_t k[32]);

/* ---- BLAKE2b (RFC 7693) ---- */

typedef struct sd_blake2b_ctx {
  uint64_t h[8], t[2];
  uint8_t buf[128];
  uint32_t buflen, outlen;
} sd_blake2b_ctx;

/* outlen 1..64, keylen 0..64 (key may be NULL when keylen is 0). SD_E_INVALID_PARAM otherwise. */
sd_err sd_blake2b_init(sd_blake2b_ctx *c, size_t outlen, const void *key, size_t keylen);
void   sd_blake2b_update(sd_blake2b_ctx *c, const void *p, size_t n);
void   sd_blake2b_final(sd_blake2b_ctx *c, uint8_t *out);       /* writes outlen bytes; zeroizes c */
sd_err sd_blake2b(uint8_t *out, size_t outlen, const void *key, size_t keylen, const void *p, size_t n);

/* ---- Argon2 (RFC 9106, version 0x13). May take seconds: never call on an I/O thread. ---- */

typedef enum sd_argon2_type { SD_ARGON2D = 0, SD_ARGON2I = 1, SD_ARGON2ID = 2 } sd_argon2_type;

#define SD_ARGON2_MAX_MEM_KIB (1024u * 1024u)    /* 1 GiB (01 §7.4) */
#define SD_ARGON2_MAX_PASSES  1000u
#define SD_ARGON2_MAX_LANES   255u

/* mem_kib >= 8 * lanes, passes >= 1, 1 <= lanes, outlen >= 4. Over the caps: SD_E_UNSUPPORTED.
   SD_E_NO_MEMORY when the allocation fails (likely on x86 with large mem_kib). cancel is optional:
   when it becomes nonzero the computation stops at the next segment with SD_E_CANCELLED.
   Lanes are computed sequentially on the calling thread. */
sd_err sd_argon2(sd_argon2_type t, uint32_t mem_kib, uint32_t passes, uint32_t lanes,
                 const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                 uint8_t *out, size_t outlen, volatile long *cancel);
/* Full form with the optional secret K and associated data X (RFC 9106 test vectors). */
sd_err sd_argon2_ex(sd_argon2_type t, uint32_t mem_kib, uint32_t passes, uint32_t lanes,
                    const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                    const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen,
                    uint8_t *out, size_t outlen, volatile long *cancel);

/* ---- raw block-cipher modes (key files, KAT and CNG differential tests) ---- */

/* AES-CBC without padding: len % 16 == 0; key_len 16, 24 or 32; in may equal out. Own constant-time
   core. */
sd_err sd_aes_cbc(int encrypt, const uint8_t *key, size_t key_len, const uint8_t iv[16],
                  const uint8_t *in, size_t len, uint8_t *out);
/* 3DES-EDE-CBC (SP 800-67, keying option 1 or 2 as K1||K2||K3), len % 8 == 0; in may equal out.
   Constant-time DES (S-boxes as boolean multiplexer networks, no secret-indexed tables). */
sd_err sd_3des_cbc(int encrypt, const uint8_t key[24], const uint8_t iv[8],
                   const uint8_t *in, size_t len, uint8_t *out);
/* Single-block 3DES-EDE (ECB), for vectors. */
sd_err sd_3des_ecb(int encrypt, const uint8_t key[24], const uint8_t *in, size_t len, uint8_t *out);

#endif /* SD_CRYPTO_PQ_H */
