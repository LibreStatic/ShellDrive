/* sd_crypto public API, M0 subset (01 §2.6, 00 §6 M0): RNG, SHA-256/384/512, HMAC, X25519, Ed25519,
 * chacha20-poly1305@openssh.com, AES-CTR, AES-GCM (own code; CNG only as a backend for AES and as a
 * differential-test reference, decisions.md D1/D2), bcrypt_pbkdf for OpenSSH key files.
 * Later milestones extend this header additively (MD5/SHA-1 fingerprints, ECDH/ECDSA, RSA, DH,
 * SHA-3, ML-KEM; see 01 §2.6).
 *
 * Rules (01 §2.4): secrets never drive branches, loop bounds or table indices; every function that
 * holds secrets wipes them before returning; contexts are fixed size (no allocation) unless an
 * object type is returned.
 *
 * Threading and ownership: all functions are reentrant. sd_crypto_init() is idempotent and
 * thread-safe. Contexts and cipher objects belong to one owner at a time (each SSH connection owns
 * its own); share them only with external locking. Objects returned through **out are freed with
 * their own *_free function, which zeroizes. */
#ifndef SD_CRYPTO_H
#define SD_CRYPTO_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* ---- init and capabilities ---- */

/* CPU bits are sd_platform's SD_CPU_* (sd_platform/sd_platform.h). */
enum { SD_OS_CNG = 1u << 0, SD_OS_CNG_GCM = 1u << 1, SD_OS_CNG_RAW_SECRET = 1u << 2 };
typedef struct sd_crypto_caps { uint32_t cpu, os; } sd_crypto_caps;

enum { SD_CRYPTO_INIT_OWN_ONLY = 1u << 0 };    /* never use CNG, even for AES */
sd_err sd_crypto_init(uint32_t flags);
const sd_crypto_caps *sd_crypto_caps_get(void);

/* OS RNG (BCryptGenRandom, else RtlGenRandom on XP). Fails only if the OS RNG fails. */
sd_err sd_random(void *buf, size_t len);

/* ---- hashes and HMAC: fixed-size contexts, no allocation ---- */

/* Values 0 and 1 are reserved for MD5 and SHA-1 (fingerprints, legacy; later milestones). */
typedef enum sd_hash_alg { SD_HASH_SHA256 = 2, SD_HASH_SHA384 = 3, SD_HASH_SHA512 = 4 } sd_hash_alg;
#define SD_HASH_MAX_LEN   64
#define SD_HASH_MAX_BLOCK 128
typedef struct sd_hash_ctx { sd_hash_alg alg; uint64_t opaque[28]; } sd_hash_ctx;
void   sd_hash_init(sd_hash_ctx *c, sd_hash_alg alg);
void   sd_hash_update(sd_hash_ctx *c, const void *p, size_t n);
void   sd_hash_final(sd_hash_ctx *c, uint8_t *out);           /* writes sd_hash_len bytes; zeroizes c */
size_t sd_hash_len(sd_hash_alg alg);
size_t sd_hash_block_len(sd_hash_alg alg);
void   sd_hash(sd_hash_alg alg, const void *p, size_t n, uint8_t *out);   /* one-shot */

typedef struct sd_hmac_ctx { sd_hash_ctx inner, outer, inner0, outer0; } sd_hmac_ctx;
void   sd_hmac_init(sd_hmac_ctx *c, sd_hash_alg alg, const void *key, size_t klen);
void   sd_hmac_update(sd_hmac_ctx *c, const void *p, size_t n);
void   sd_hmac_final(sd_hmac_ctx *c, uint8_t *out);           /* leaves the keyed state for reset */
void   sd_hmac_reset(sd_hmac_ctx *c);                          /* same key, next message (per packet) */
void   sd_hmac_wipe(sd_hmac_ctx *c);                           /* zeroizes the key state */

/* ---- SSH packet protection (one object per direction, created by sd_ssh after NEWKEYS) ---- */

enum {
  SD_PC_AEAD          = 1u << 0,   /* tag produced/checked by seal/open */
  SD_PC_LEN_ENCRYPTED = 1u << 1,   /* chacha20-poly1305@openssh.com: length field encrypted */
  SD_PC_LEGACY        = 1u << 2,
  SD_PC_CBC           = 1u << 3
};
typedef struct sd_pktcipher sd_pktcipher;
typedef struct sd_pktcipher_info {
  const char *ssh_name;            /* "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", ... */
  uint8_t key_len, iv_len, block_len, tag_len;
  uint32_t flags;                  /* SD_PC_* */
} sd_pktcipher_info;
/* M0 names: chacha20-poly1305@openssh.com, aes128-gcm@openssh.com, aes256-gcm@openssh.com,
   aes128-ctr, aes192-ctr, aes256-ctr. NULL for anything else. */
const sd_pktcipher_info *sd_pktcipher_find(const char *ssh_name);
sd_err sd_pktcipher_new(const sd_pktcipher_info *i, int encrypt, const uint8_t *key, const uint8_t *iv,
                        sd_pktcipher **out);
/* Non-AEAD (CTR): in-place encryption/decryption of whole blocks; MAC is done by sd_ssh with HMAC. */
sd_err sd_pktcipher_crypt(sd_pktcipher *c, uint8_t *buf, size_t len);
/* AEAD: seal/open a full packet (4-byte length + payload) in place; seq = SSH sequence number.
   open verifies the tag before any plaintext is released (constant-time compare). */
sd_err sd_pktcipher_seal(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, uint8_t *tag);
sd_err sd_pktcipher_open(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, const uint8_t *tag);
/* chacha only: decrypts the 4-byte length without authenticating it (as OpenSSH specifies). */
sd_err sd_pktcipher_peek_len(sd_pktcipher *c, uint32_t seq, const uint8_t enc_len[4], uint32_t *len);
void   sd_pktcipher_free(sd_pktcipher *c);                     /* zeroizes */

/* Generic block cipher for key files. M0: "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes256-cbc". */
sd_err sd_cipher_oneshot(const char *ssh_or_pem_name, int encrypt, const uint8_t *key, const uint8_t *iv,
                         uint8_t *buf, size_t len);

/* ---- raw AEAD / stream primitives (KAT, Wycheproof and CNG differential tests) ---- */

/* AES-GCM with a 12-byte nonce and 16-byte tag. key_len 16 or 32. */
sd_err sd_aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          uint8_t *out, uint8_t tag[16]);
sd_err sd_aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          const uint8_t tag[16], uint8_t *out);            /* SD_E_CRYPTO on bad tag */
/* AES-CTR with a 16-byte big-endian counter block (SSH style). key_len 16, 24 or 32. */
sd_err sd_aes_ctr(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                  const uint8_t *in, size_t len, uint8_t *out);
/* ChaCha20 (original 64-bit nonce / 64-bit counter layout used by OpenSSH) and Poly1305. */
void   sd_chacha20(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter,
                   const uint8_t *in, size_t len, uint8_t *out);
void   sd_poly1305(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[32]);

/* ---- asymmetric primitives on raw encodings (SSH wire encoding is sd_ssh's job) ---- */

sd_err sd_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]); /* rejects all-zero out */
sd_err sd_x25519_base(uint8_t pub[32], const uint8_t scalar[32]);
sd_err sd_ed25519_pub_from_seed(uint8_t pub[32], const uint8_t seed[32]);
sd_err sd_ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t pub[32],
                       const void *m, size_t n);
sd_err sd_ed25519_verify(const uint8_t sig[64], const uint8_t pub[32], const void *m, size_t n);
                                                     /* SD_OK or SD_E_CRYPTO; rejects non-canonical S */

/* ---- KDFs: may take long, never call them on an I/O thread ---- */

sd_err sd_bcrypt_pbkdf(const void *pass, size_t plen, const uint8_t *salt, size_t slen, uint32_t rounds,
                       uint8_t *out, size_t outlen);      /* OpenSSH key files */
sd_err sd_pbkdf2_hmac(sd_hash_alg h, const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                      uint32_t iters, uint8_t *out, size_t outlen);

#endif /* SD_CRYPTO_H */
