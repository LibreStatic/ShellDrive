/* sd_crypto M2 additions, public-key side (01 §2.2, §2.6, §2.8.2, §2.8.3): SHA-1 (as SD_HASH_SHA1 of the
 * generic hash/HMAC API), big numbers (sd_bn), RSA PKCS#1 v1.5 (ssh-rsa, rsa-sha2-256/512), finite-field
 * Diffie-Hellman (RFC 2409/3526 groups, group-exchange validation), ECDH and ECDSA on NIST P-256/384/521.
 * All own code (decisions.md D1); CNG is only a differential-test reference for these primitives.
 *
 * Constant-time contract (01 §2.4): functions named *_ct_* and every private-key operation (RSA sign,
 * DH public/compute, ECDH, ECDSA sign, EC key generation) have no branch, loop bound or memory index that
 * depends on secret values; their time depends only on public sizes (limb counts, the declared exponent
 * bit length). Functions named *_vt_* and the verification paths (RSA verify, ECDSA verify, DH group
 * validation, point decoding) are variable time and must only see public values.
 *
 * Encodings: integers are unsigned big-endian magnitudes (leading zero bytes allowed on input); SSH
 * mpint/string framing is sd_ssh's job. Outputs that may be secret (DH shared secret, ECDH x coordinate,
 * signatures) are written at a fixed width.
 *
 * Errors: SD_E_INVALID_PARAM (bad arguments, buffer too small), SD_E_NO_MEMORY, SD_E_CRYPTO (invalid
 * signature, invalid peer value, failed self-check), SD_E_KEY_FORMAT (inconsistent key components),
 * SD_E_KEY_UNSUPPORTED (size outside the hard limits or the caller's policy), SD_E_UNSUPPORTED (algorithm
 * or hash not supported, group outside policy), SD_E_FAILURE (RNG failure).
 *
 * Threading: reentrant; key and DH objects belong to one owner at a time (read-only use of a key from
 * several threads is safe: sign/verify/ecdh do not modify the key). Objects are freed with their *_free
 * function, which zeroizes. Included by sd_crypto.h; do not include directly. */
#ifndef SD_CRYPTO_PK_H
#define SD_CRYPTO_PK_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"   /* sd_hash_alg; its trailing include of this header is a no-op here */

/* ---- SHA-1 (FIPS 180-4): legacy KEX hashes (group1/14-sha1, gex-sha1), ssh-rsa, hmac-sha1(-etm),
   hashed known_hosts (HMAC-SHA1 of the host name keyed with the salt). Use the generic API:
   sd_hash(SD_HASH_SHA1, ...), sd_hash_init/update/final, sd_hmac_init(&c, SD_HASH_SHA1, ...),
   sd_pbkdf2_hmac(SD_HASH_SHA1, ...). Output 20 bytes, block 64 bytes. SD_HASH_SHA1 is value 1 of\n   sd_hash_alg (reserved in sd_crypto.h) but not an enumerator: switch on (int)alg to avoid C4063. ---- */
#define SD_HASH_SHA1     ((sd_hash_alg)1)
#define SD_SHA1_LEN      20

/* ---- big numbers ----
 * Fixed capacity (SD_BN_MAX_BITS); the used limb count `n` is public. Limbs are little-endian
 * (v[0] least significant): 64-bit limbs on 64-bit targets, 32-bit limbs on 32-bit targets (products
 * through sd_ct64.h, TM-R02). Functions return SD_E_INVALID_PARAM when a result does not fit. Moduli of
 * the Montgomery functions must be odd and > 1. sd_bn is large (about 2 KiB): allocate it or keep few
 * on the stack. */
#if defined(_M_X64) || defined(_M_ARM64)
typedef uint64_t sd_bn_limb;
#define SD_BN_LIMB_BITS 64
#else
typedef uint32_t sd_bn_limb;
#define SD_BN_LIMB_BITS 32
#endif
#define SD_BN_MAX_BITS  16384
#define SD_BN_MAX_LIMBS (SD_BN_MAX_BITS / SD_BN_LIMB_BITS)
typedef struct sd_bn { uint32_t n; sd_bn_limb v[SD_BN_MAX_LIMBS]; } sd_bn;

/* Big-endian bytes <-> sd_bn. from_bytes sets n = ceil(len / limb bytes) (leading zero bytes still
   count: the length is public). to_bytes writes exactly len bytes, left-padded with zeros; it fails if
   the value does not fit (that decision branches on the value's length only after the fixed-time
   copy, so use it for secrets only with len >= the modulus length). */
sd_err   sd_bn_from_bytes(sd_bn *r, const uint8_t *be, size_t len);
sd_err   sd_bn_to_bytes(const sd_bn *a, uint8_t *be, size_t len);
void     sd_bn_from_u32(sd_bn *r, uint32_t x);                     /* n = 1 */
void     sd_bn_wipe(sd_bn *a);                                      /* zeroizes, n = 0 */
/* Public-value helpers (variable time). */
uint32_t sd_bn_vt_bits(const sd_bn *a);                             /* 0 for zero */
int      sd_bn_vt_cmp(const sd_bn *a, const sd_bn *b);              /* -1, 0, 1 (any limb counts) */
int      sd_bn_vt_is_zero(const sd_bn *a);
sd_err   sd_bn_vt_modexp(sd_bn *r, const sd_bn *base, const sd_bn *exp, const sd_bn *mod);
/* Constant-time arithmetic (time depends on the limb counts and exp_bits only). */
sd_err   sd_bn_ct_mul(sd_bn *r, const sd_bn *a, const sd_bn *b);    /* r->n = a->n + b->n */
sd_err   sd_bn_ct_mod(sd_bn *r, const sd_bn *a, const sd_bn *mod);  /* any mod with nonzero top limb */
/* r = base^exp mod mod (mod odd). Only the low exp_bits bits of exp are used (0 = all limbs of exp);
   base may be >= mod (it is reduced first). Montgomery multiplication, fixed 4-bit window, constant-time
   table scan. */
sd_err   sd_bn_ct_modexp(sd_bn *r, const sd_bn *base, const sd_bn *exp, uint32_t exp_bits, const sd_bn *mod);
/* r = a^-1 mod mod (mod odd, a < mod): constant-time binary extended GCD with 2*bits(mod) fixed
   iterations. SD_E_CRYPTO if gcd(a, mod) != 1 (that result is not secret). */
sd_err   sd_bn_ct_modinv(sd_bn *r, const sd_bn *a, const sd_bn *mod);

/* ---- RSA (RFC 8017 PKCS#1 v1.5 signatures; RFC 4253 ssh-rsa, RFC 8332 rsa-sha2-256/512) ----
 * Hard limits: modulus SD_RSA_MIN_BITS..SD_RSA_MAX_BITS, e odd, 3 <= e < 2^64. The import parameters
 * carry the caller's policy (stricter minimum, e.g. 2048 for new keys). Private operations: CRT when p
 * and q are present (else plain d), base blinding with a fresh random r, constant-time Montgomery
 * exponentiation, and verify-after-sign (a fault returns SD_E_CRYPTO, no signature is released). */
#define SD_RSA_MIN_BITS 1024
#define SD_RSA_MAX_BITS 16384
typedef struct sd_rsa_key sd_rsa_key;
typedef struct sd_rsa_import_params {
  const uint8_t *n;    size_t n_len;    /* required */
  const uint8_t *e;    size_t e_len;    /* required */
  const uint8_t *d;    size_t d_len;    /* NULL = public key only */
  const uint8_t *p;    size_t p_len;    /* optional (both p and q, or neither): enables CRT */
  const uint8_t *q;    size_t q_len;
  const uint8_t *iqmp; size_t iqmp_len; /* optional q^-1 mod p; checked when given, computed otherwise */
  uint32_t min_bits;                    /* policy: 0 = SD_RSA_MIN_BITS; values below it are raised to it */
  uint32_t max_bits;                    /* policy: 0 = SD_RSA_MAX_BITS; values above it are lowered */
} sd_rsa_import_params;
/* Validates: n odd and within limits, e as above; with private parts: d < n, p*q == n, p and q odd,
   iqmp consistent (SD_E_KEY_FORMAT otherwise). dp, dq and q^-1 mod p are derived in constant time. */
sd_err   sd_rsa_import(const sd_rsa_import_params *p, sd_rsa_key **out);
uint32_t sd_rsa_bits(const sd_rsa_key *k);              /* modulus bits */
size_t   sd_rsa_len(const sd_rsa_key *k);               /* modulus bytes = signature length */
int      sd_rsa_has_private(const sd_rsa_key *k);
/* Big-endian n and e (minimal, no leading zeros); *len in = capacity, out = written. */
sd_err   sd_rsa_export_pub(const sd_rsa_key *k, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len);
/* EMSA-PKCS1-v1_5 with h in {SD_HASH_SHA1, SHA256, SHA384, SHA512}; dlen must be sd_hash_len(h).
   sign: *siglen in = capacity (>= sd_rsa_len), out = sd_rsa_len (fixed width, left-padded).
   verify: siglen must equal sd_rsa_len (SSH callers left-pad a shorter ssh-rsa blob, as OpenSSH does);
   the signature must be < n; the encoded message is rebuilt and compared in full (no padding parser).
   SD_OK or SD_E_CRYPTO. */
sd_err   sd_rsa_pkcs1_sign(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                           uint8_t *sig, size_t *siglen);
sd_err   sd_rsa_pkcs1_verify(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                             const uint8_t *sig, size_t siglen);
void     sd_rsa_free(sd_rsa_key *k);                    /* NULL is a no-op; zeroizes */

/* ---- finite-field Diffie-Hellman (RFC 4253 §8, RFC 4419, RFC 8268) ----
 * Hard limits: p odd, SD_DH_MIN_BITS..SD_DH_MAX_BITS, 1 < g < p-1. sd_dh_new does not test primality:
 * groups received in group exchange go through sd_dh_gex_validate first. priv_bits = 0 picks the
 * default private exponent length (256 bits for p <= 3072 bits, 512 bits above: 2x the security
 * strength, 01 §2.2); otherwise 160..bits(p)-1. Public values and the shared secret are written at the
 * fixed width sd_dh_len() (left-padded); sd_ssh strips leading zeros for the mpint encoding. */
#define SD_DH_MIN_BITS 1024
#define SD_DH_MAX_BITS 8192
typedef struct sd_dh sd_dh;
sd_err   sd_dh_new(const uint8_t *p, size_t plen, const uint8_t *g, size_t glen, uint32_t priv_bits, sd_dh **out);
/* Well-known MODP groups, generator 2: SD_DH_GROUP1 = RFC 2409 Oakley group 2 (1024 bits, SSH
   "diffie-hellman-group1-sha1"; id 2 is accepted as an alias), 14 (2048), 16 (4096), 18 (8192) of
   RFC 3526. Returns the big-endian prime and its length, or NULL for an unknown id. */
enum { SD_DH_GROUP1 = 1, SD_DH_GROUP14 = 14, SD_DH_GROUP16 = 16, SD_DH_GROUP18 = 18 };
const uint8_t *sd_dh_group_modp(int id, size_t *plen);
sd_err   sd_dh_new_group(int id, uint32_t priv_bits, sd_dh **out);
size_t   sd_dh_len(const sd_dh *d);                     /* bytes of p */
uint32_t sd_dh_bits(const sd_dh *d);                    /* bits of p */
/* Draws a fresh private exponent from the OS RNG (replacing any earlier one) and writes e = g^x mod p
   (elen >= sd_dh_len; exactly sd_dh_len bytes are written). */
sd_err   sd_dh_public(sd_dh *d, uint8_t *e, size_t elen);
/* k = f^x mod p after checking 1 < f < p-1 (SD_E_CRYPTO otherwise); klen >= sd_dh_len, exactly
   sd_dh_len bytes are written. SD_E_INVALID_PARAM if sd_dh_public was not called. */
sd_err   sd_dh_compute(sd_dh *d, const uint8_t *f, size_t flen, uint8_t *k, size_t klen);
void     sd_dh_free(sd_dh *d);                          /* NULL is a no-op; zeroizes */

/* Group-exchange group validation (server-chosen p, g; RFC 4419, RFC 8270 minimum 2048). Checks the
   size policy, p odd, 1 < g < p-1, trial division of p and (p-1)/2 by small primes, then (unless
   SD_DH_GEX_NO_PRIME_TEST) proves p = 2q+1 a safe prime with mr_rounds Miller-Rabin rounds on q (random
   bases) plus a Pocklington check of p with base 2. RFC 3526 groups are recognized and skip the
   primality work. Bounded cost: about (mr_rounds + 1) modular exponentiations of bits(p) bits.
   pol NULL = defaults. Returns SD_OK, SD_E_UNSUPPORTED (size outside the policy) or SD_E_CRYPTO. */
#define SD_DH_GEX_DEFAULT_MIN_BITS  2048
#define SD_DH_GEX_DEFAULT_MAX_BITS  8192
#define SD_DH_GEX_DEFAULT_MR_ROUNDS 8
enum { SD_DH_GEX_NO_PRIME_TEST = 1u << 0 };
typedef struct sd_dh_gex_policy {
  uint32_t min_bits;          /* 0 = SD_DH_GEX_DEFAULT_MIN_BITS (never below SD_DH_MIN_BITS) */
  uint32_t max_bits;          /* 0 = SD_DH_GEX_DEFAULT_MAX_BITS (never above SD_DH_MAX_BITS) */
  uint32_t mr_rounds;         /* 0 = SD_DH_GEX_DEFAULT_MR_ROUNDS; capped at 64 */
  uint32_t flags;             /* SD_DH_GEX_* */
} sd_dh_gex_policy;
sd_err   sd_dh_gex_validate(const uint8_t *p, size_t plen, const uint8_t *g, size_t glen,
                            const sd_dh_gex_policy *pol);

/* ---- ECDH / ECDSA on NIST P-256, P-384, P-521 (FIPS 186-4 / SEC 1; RFC 5656 for SSH) ----
 * Own Montgomery field engine, projective points with the complete Renes-Costello-Batina formulas
 * (a = -3), fixed-window constant-time scalar multiplication with a masked table scan. Points are
 * uncompressed only (0x04 || X || Y, each sd_ec_field_len bytes); decoding checks coordinates < p and
 * the curve equation (prime order, so that is full validation) and rejects compressed points and the
 * point at infinity. Scalars and r, s are big-endian; private scalars must be in [1, n-1]. */
typedef enum sd_curve { SD_CURVE_P256 = 1, SD_CURVE_P384 = 2, SD_CURVE_P521 = 3 } sd_curve;
#define SD_EC_MAX_FIELD_LEN 66
#define SD_EC_MAX_POINT_LEN (1 + 2 * SD_EC_MAX_FIELD_LEN)
size_t   sd_ec_field_len(sd_curve c);                   /* 32, 48, 66; 0 for an unknown curve */
size_t   sd_ec_point_len(sd_curve c);                   /* 1 + 2 * field_len */
sd_hash_alg sd_ec_hash(sd_curve c);                     /* RFC 5656 §6.2.1: SHA-256/384/512 */
typedef struct sd_ec_key sd_ec_key;
/* New random private key (OS RNG, rejection sampling in [1, n-1]) with its public point. */
sd_err   sd_ec_generate(sd_curve c, sd_ec_key **out);
/* pub: encoded point or NULL; priv: scalar or NULL (at least one of them). With both, pub must equal
   priv*G (SD_E_KEY_FORMAT otherwise); with priv only, pub is computed. Invalid point: SD_E_CRYPTO;
   priv out of range: SD_E_KEY_FORMAT. */
sd_err   sd_ec_import(sd_curve c, const uint8_t *pub, size_t publen, const uint8_t *priv, size_t privlen,
                      sd_ec_key **out);
sd_curve sd_ec_key_curve(const sd_ec_key *k);
int      sd_ec_has_private(const sd_ec_key *k);
sd_err   sd_ec_export_pub(const sd_ec_key *k, uint8_t *out, size_t *len);     /* *len in cap, out written */
/* Shared secret = x coordinate of priv * peer (fixed field_len bytes; *slen in cap, out written).
   The peer point is fully validated before any secret-dependent work (SD_E_CRYPTO if invalid). */
sd_err   sd_ecdh(const sd_ec_key *mine, const uint8_t *peer_pub, size_t len, uint8_t *secret_x, size_t *slen);
/* ECDSA over a precomputed digest of hash h (h selects the RFC 6979 HMAC; for SSH use sd_ec_hash()).
   The digest is truncated to bits(n) as FIPS 186-4 specifies. r and s are written at field_len bytes
   each. sd_ecdsa_sign uses the RFC 6979 nonce hedged with 32 fresh random bytes (RFC 6979 §3.6 extra
   data); sd_ecdsa_sign_ex takes the extra data explicitly (NULL/0 = plain deterministic RFC 6979, for
   known-answer tests). */
sd_err   sd_ecdsa_sign(const sd_ec_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                       uint8_t *r, uint8_t *s);
sd_err   sd_ecdsa_sign_ex(const sd_ec_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                          const uint8_t *extra, size_t extralen, uint8_t *r, uint8_t *s);
/* r, s: big-endian magnitudes of any length (leading zeros allowed); must be in [1, n-1].
   SD_OK or SD_E_CRYPTO. Variable time (public inputs). */
sd_err   sd_ecdsa_verify(const sd_ec_key *k, const uint8_t *digest, size_t dlen,
                         const uint8_t *r, size_t rlen, const uint8_t *s, size_t slen);
void     sd_ec_free(sd_ec_key *k);                      /* NULL is a no-op; zeroizes */

#endif /* SD_CRYPTO_PK_H */
