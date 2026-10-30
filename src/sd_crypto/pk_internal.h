/* Private interfaces of the public-key code of sd_crypto (bn.c, rsa.c, dh.c, dh_gex.c, ec_p.c, sha1.c) and
 * of its unit tests (tests/unit/sd_crypto_pk). Not a public contract.
 *
 * Multiprecision layer (sd_mp_*): little-endian limb arrays with an explicit, public limb count n. Every
 * sd_mp_* function is constant time: no branch, loop bound or index depends on limb values (01 §2.4);
 * 64-bit arithmetic on 32-bit targets goes through sd_ct64.h (TM-R02). Montgomery functions take an odd
 * modulus m with m < R = 2^(W*n) and operands < m unless noted. */
#ifndef SD_PK_INTERNAL_H
#define SD_PK_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"

typedef sd_bn_limb sd_limb;
#define SD_LIMB_BITS  SD_BN_LIMB_BITS
#define SD_LIMB_BYTES (SD_BN_LIMB_BITS / 8)
#define SD_MP_MAX     SD_BN_MAX_LIMBS

/* ---- SHA-1 state behind sd_hash_ctx (sha1.c; hash.c dispatches SD_HASH_SHA1 here) ---- */
void sd_sha1_state_init(uint64_t *opaque);
void sd_sha1_state_update(uint64_t *opaque, const uint8_t *p, size_t n);
void sd_sha1_state_final(uint64_t *opaque, uint8_t out[20]);

/* ---- constant-time limb helpers ---- */
sd_limb sd_mp_mask(sd_limb bit);                                    /* bit (0/1) -> mask */
sd_limb sd_mp_is_zero(const sd_limb *a, size_t n);                  /* mask */
sd_limb sd_mp_eq(const sd_limb *a, const sd_limb *b, size_t n);     /* mask */
sd_limb sd_mp_add(sd_limb *r, const sd_limb *a, const sd_limb *b, size_t n);           /* carry 0/1 */
sd_limb sd_mp_sub(sd_limb *r, const sd_limb *a, const sd_limb *b, size_t n);           /* borrow 0/1 */
sd_limb sd_mp_lt(const sd_limb *a, const sd_limb *b, size_t n);     /* borrow of a - b (0/1), no store */
/* r = a + (b & mask) / r = a - (b & mask); returns carry / borrow. */
sd_limb sd_mp_add_mask(sd_limb *r, const sd_limb *a, const sd_limb *b, sd_limb mask, size_t n);
sd_limb sd_mp_sub_mask(sd_limb *r, const sd_limb *a, const sd_limb *b, sd_limb mask, size_t n);
void    sd_mp_cmov(sd_limb *r, const sd_limb *a, sd_limb mask, size_t n);              /* r = mask ? a : r */
void    sd_mp_cswap(sd_limb *a, sd_limb *b, sd_limb mask, size_t n);
void    sd_mp_shr1(sd_limb *a, sd_limb top, size_t n);              /* a = (top:a) >> 1, top 0/1 */
/* Modular add/sub for a, b < m. r may alias a or b. */
void    sd_mp_modadd(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, size_t n);
void    sd_mp_modsub(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, size_t n);

/* r[0..na+nb) = a * b (schoolbook). r must not alias a or b. */
void    sd_mp_mul(sd_limb *r, const sd_limb *a, size_t na, const sd_limb *b, size_t nb);
/* r[0..nm) = a mod m, bit-serial shift and conditional subtraction over all na*W bits; m[nm-1] != 0.
   r must not alias a. */
void    sd_mp_mod(sd_limb *r, const sd_limb *a, size_t na, const sd_limb *m, size_t nm);

/* ---- Montgomery engine ---- */
sd_limb sd_mp_m0inv(sd_limb m0);                                    /* -m0^-1 mod 2^W, m0 odd */
void    sd_mp_mont_r2(sd_limb *r2, const sd_limb *m, size_t n);     /* R^2 mod m (needs m[n-1] != 0) */
/* r = a * b * R^-1 mod m (CIOS, final subtraction by mask). r may alias a or b. */
void    sd_mp_montmul(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, sd_limb m0i, size_t n);
/* r = base^exp mod m. base < m (normal form), exp has ceil(ebits/W) limbs (bits >= ebits ignored),
   ebits > 0 is public. work: SD_MP_MODEXP_WORK(n) limbs. Fixed 4-bit window, masked table scan. */
#define SD_MP_MODEXP_WORK(n) (18 * (size_t)(n))
void    sd_mp_modexp_ct(sd_limb *r, const sd_limb *base, const sd_limb *exp, uint32_t ebits,
                        const sd_limb *m, sd_limb m0i, const sd_limb *r2, size_t n, sd_limb *work);
/* Same with a public exponent (square-and-multiply over its significant bits; time depends on exp
   only, never on base). work: SD_MP_MODEXP_VT_WORK(n) limbs. */
#define SD_MP_MODEXP_VT_WORK(n) (3 * (size_t)(n))
void    sd_mp_modexp_vt(sd_limb *r, const sd_limb *base, const sd_limb *exp, size_t ne,
                        const sd_limb *m, sd_limb m0i, const sd_limb *r2, size_t n, sd_limb *work);
/* r = a^-1 mod m (m odd, any a with n limbs): binary extended GCD, 2*W*n fixed iterations.
   Returns an all-ones mask when gcd(a, m) == 1, else 0 (r is then meaningless). work: 5n limbs. */
#define SD_MP_MODINV_WORK(n) (5 * (size_t)(n))
sd_limb sd_mp_modinv_ct(sd_limb *r, const sd_limb *a, const sd_limb *m, size_t n, sd_limb *work);

/* Big-endian bytes <-> limbs (fixed width: n limbs / len bytes; extra input bytes must be zero is the
   caller's business: from_be ignores bytes beyond n limbs, to_be writes the low len bytes). */
void    sd_mp_from_be(sd_limb *r, size_t n, const uint8_t *be, size_t len);
void    sd_mp_to_be(uint8_t *be, size_t len, const sd_limb *a, size_t n);
/* Public helpers (variable time). */
size_t  sd_mp_vt_trim(const sd_limb *a, size_t n);                  /* significant limbs (0 for zero) */
uint32_t sd_mp_vt_bits(const sd_limb *a, size_t n);
int     sd_mp_vt_cmp(const sd_limb *a, size_t na, const sd_limb *b, size_t nb);

/* Overwrites a few KiB of stack below the caller (callees' frames of a secret operation). */
void    sd_pk_scrub_stack(void);

/* ---- EC internals exposed for tests (ec_p.c) ---- */
/* r = k*P for an affine point (big-endian 0x04||X||Y input, already validated by the caller) and a
   big-endian scalar of any value < 2^(8*field_len); output encoded the same way, or SD_E_CRYPTO if the
   result is the point at infinity. Used by the arithmetic cross-check against the Python reference. */
sd_err  sd_ec_test_mul(sd_curve c, const uint8_t *k, size_t klen, const uint8_t *pt, uint8_t *out);
/* r = P + Q (complete formulas) and r = 2P (doubling formula), same encodings. */
sd_err  sd_ec_test_add(sd_curve c, const uint8_t *p, const uint8_t *q, uint8_t *out);
sd_err  sd_ec_test_dbl(sd_curve c, const uint8_t *p, uint8_t *out);
/* Field products mod p on plain big-endian operands (field-length bytes): the NIST reduction (fe_mul_nist),
   the product in the curve's selected representation (fe_mul), a bit-serial reference (sd_mp_mod of the
   product), and the Montgomery path (inputs below p). */
sd_err  sd_ec_test_fe_nist(sd_curve c, const uint8_t *a, const uint8_t *b, uint8_t *out);
sd_err  sd_ec_test_fe_sel(sd_curve c, const uint8_t *a, const uint8_t *b, uint8_t *out);
sd_err  sd_ec_test_fe_ref(sd_curve c, const uint8_t *a, const uint8_t *b, uint8_t *out);
sd_err  sd_ec_test_fe_mont(sd_curve c, const uint8_t *a, const uint8_t *b, uint8_t *out);

#endif /* SD_PK_INTERNAL_H */
