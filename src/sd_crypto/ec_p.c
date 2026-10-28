/* ECDH and ECDSA over NIST P-256, P-384 and P-521 (FIPS 186-4, SEC 1 v2, RFC 5656 for SSH; 01 §2.8.2).
 *
 * Field arithmetic: normal-form limbs; products are reduced by the curve-specific NIST reductions of this file
 * (FIPS 186-4 D.2 for P-256 and P-384, a Mersenne-type fold for P-521; section "field multiplication").
 * Scalar arithmetic (group order n): the generic Montgomery engine of bn.c with a fixed limb count per curve.
 * Constants: pk_consts.inc, generated from RFC 5903 by gen_pk_consts.py.
 * Points: homogeneous projective coordinates with the complete addition (Algorithm 4) and doubling
 * (Algorithm 6) formulas for a = -3 of Renes, Costello and Batina, "Complete addition formulas for prime
 * order elliptic curves" (EUROCRYPT 2016): no exceptional cases, so no branches on point values.
 * Scalar multiplication: fixed 4-bit windows over the full order length, table of 16 multiples scanned
 * with masks for every digit (01 §2.4 rule 4). Inversions: constant-time binary GCD of bn.c.
 * Nonces: RFC 6979 §3.2 HMAC-DRBG, optionally hedged with extra data (§3.6).
 * Verification and point decoding see public values only; they reuse the constant-time code. */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"

#include "pk_consts.inc"

#if SD_LIMB_BITS == 64
#define EC_MAXL 9
#else
#define EC_MAXL 17
#endif

typedef struct ec_curve {
  sd_curve id;
  size_t nl, flen;
  uint32_t bits;             /* bits of p and of n */
  sd_hash_alg hash;
  /* p, p_r2 and p_m0i serve the Montgomery reference path (tests only); b, gx, gy are normal form. */
  const sd_limb *p, *p_r2, *p_one, *n, *n_r2, *n_one, *b, *gx, *gy;
  sd_limb p_m0i, n_m0i;
} ec_curve;

static const ec_curve k_curves[3] = {
  { SD_CURVE_P256, K_P256_LIMBS, 32, 256, SD_HASH_SHA256, k_p256_p, k_p256_p_r2, k_p256_p_one, k_p256_n,
    k_p256_n_r2, k_p256_n_one, k_p256_b, k_p256_gx, k_p256_gy, K_P256_P_M0I, K_P256_N_M0I },
  { SD_CURVE_P384, K_P384_LIMBS, 48, 384, SD_HASH_SHA384, k_p384_p, k_p384_p_r2, k_p384_p_one, k_p384_n,
    k_p384_n_r2, k_p384_n_one, k_p384_b, k_p384_gx, k_p384_gy, K_P384_P_M0I, K_P384_N_M0I },
  { SD_CURVE_P521, K_P521_LIMBS, 66, 521, SD_HASH_SHA512, k_p521_p, k_p521_p_r2, k_p521_p_one, k_p521_n,
    k_p521_n_r2, k_p521_n_one, k_p521_b, k_p521_gx, k_p521_gy, K_P521_P_M0I, K_P521_N_M0I },
};

static const ec_curve *curve_get(sd_curve c)
{
  if (c == SD_CURVE_P256) return &k_curves[0];
  if (c == SD_CURVE_P384) return &k_curves[1];
  if (c == SD_CURVE_P521) return &k_curves[2];
  return NULL;
}

typedef struct ec_pt { sd_limb x[EC_MAXL], y[EC_MAXL], z[EC_MAXL]; } ec_pt;

struct sd_ec_key {
  const ec_curve *c;
  int has_priv;
  sd_limb d[EC_MAXL];
  ec_pt q;
  uint8_t pub[SD_EC_MAX_POINT_LEN];
};

/* ---- field multiplication (01 §2.8.2; FIPS 186-4 D.2 for P-256 and P-384, Mersenne-type for P-521) ----
 * Field elements are normal-form limbs in [0, p). A product is a schoolbook sd_mp_mul over the limbs; the
 * reduction then works on 32-bit words whatever the limb size, so both builds run the same code. The
 * reductions are Solinas-type: 2^256 = 2^224 - 2^192 - 2^96 + 1 (P-256, one pass as in D.2.3),
 * 2^384 = 2^128 + 2^96 - 2^32 + 1 (P-384, two folds), 2^521 = 1 (P-521, one fold). Sums are signed 64-bit
 * additions of 32-bit words with constant shifts: no multiplication, no secret-dependent branch, index or
 * division. Every result is brought into [0, p) by conditional subtractions with masks.
 * Operands must be below 2^(bits) of the curve field (true for every operand: all are reduced), and the
 * P-521 fold assumes operands below 2^521. */
#define EC_W32_MAX  17             /* 32-bit words of a P-521 field element */
#define EC_PROD_W32 36             /* 32-bit words of a product (2 * 9 limbs * 2) */

/* p, 2p, 4p, 5p, 8p (P-256, 9 words) and p (P-384 with a zero top word; P-521, 17 words), least significant
   word first. Generated from the field primes (gen_pk_consts.py documents the primes). */
static const uint32_t k_w32_p256_1p[9] = {
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u, 0x00000000u, 0x00000000u,
  0x00000001u, 0xffffffffu, 0x00000000u,
};
static const uint32_t k_w32_p256_2p[9] = {
  0xfffffffeu, 0xffffffffu, 0xffffffffu, 0x00000001u, 0x00000000u, 0x00000000u,
  0x00000002u, 0xfffffffeu, 0x00000001u,
};
static const uint32_t k_w32_p256_4p[9] = {
  0xfffffffcu, 0xffffffffu, 0xffffffffu, 0x00000003u, 0x00000000u, 0x00000000u,
  0x00000004u, 0xfffffffcu, 0x00000003u,
};
static const uint32_t k_w32_p256_5p[9] = {
  0xfffffffbu, 0xffffffffu, 0xffffffffu, 0x00000004u, 0x00000000u, 0x00000000u,
  0x00000005u, 0xfffffffbu, 0x00000004u,
};
static const uint32_t k_w32_p256_8p[9] = {
  0xfffffff8u, 0xffffffffu, 0xffffffffu, 0x00000007u, 0x00000000u, 0x00000000u,
  0x00000008u, 0xfffffff8u, 0x00000007u,
};
static const uint32_t k_w32_p384_p[13] = {
  0xffffffffu, 0x00000000u, 0x00000000u, 0xffffffffu, 0xfffffffeu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0x00000000u,
};
static const uint32_t k_w32_p521_p[17] = {
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
  0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0x000001ffu,
};

static void w32_from_limbs(uint32_t *w, const sd_limb *a, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
#if SD_LIMB_BITS == 64
    w[2 * i] = (uint32_t)a[i];
    w[2 * i + 1] = (uint32_t)(a[i] >> 32);
#else
    w[i] = (uint32_t)a[i];
#endif
  }
}

static void w32_to_limbs(sd_limb *a, const uint32_t *w, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
#if SD_LIMB_BITS == 64
    a[i] = (uint64_t)w[2 * i] | ((uint64_t)w[2 * i + 1] << 32);
#else
    a[i] = w[i];
#endif
  }
}

/* Carry propagation of signed column sums into n words. Returns the signed carry out of the top word. */
static int64_t w32_norm(uint32_t *out, const int64_t *acc, size_t n)
{
  int64_t c = 0;
  size_t i;
  SD_CT_NO_VECTOR
  for (i = 0; i < n; i++) {
    int64_t v = acc[i] + c;
    out[i] = (uint32_t)v;
    c = v >> 32;
  }
  return c;
}

/* x = x - m if x >= m, for x < 2m (n words). Constant time. */
static void w32_csub(uint32_t *x, const uint32_t *m, size_t n)
{
  uint32_t t[EC_W32_MAX], keep, borrow = 0;
  size_t i;
  SD_CT_NO_VECTOR
  for (i = 0; i < n; i++) {
    int64_t d = (int64_t)x[i] - (int64_t)m[i] - (int64_t)borrow;
    t[i] = (uint32_t)d;
    borrow = (uint32_t)(((uint64_t)d >> 63) & 1u);
  }
  keep = (uint32_t)0 - (borrow ^ 1u);       /* all ones when x >= m */
  SD_CT_NO_VECTOR
  for (i = 0; i < n; i++)
    x[i] = (t[i] & keep) | (x[i] & ~keep);
}

/* P-256, FIPS 186-4 D.2.3: c0..c15 are the product words. Vector j lists, least significant word first,
   which c_k fills word k (index 16 is a zero word). The result is s0 + 2 s1 + 2 s2 + s3 + s4 - s5 - s6 - s7
   - s8 (mod p). The sum lies in (-4 2^256, 7 2^256); 5p makes it non-negative and below 13p. */
static void red_p256(uint32_t *r, const uint32_t *t)
{
  static const uint8_t s0[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  static const uint8_t s1[8] = {16, 16, 16, 11, 12, 13, 14, 15};
  static const uint8_t s2[8] = {16, 16, 16, 12, 13, 14, 15, 16};
  static const uint8_t s3[8] = {8, 9, 10, 16, 16, 16, 14, 15};
  static const uint8_t s4[8] = {9, 10, 11, 13, 14, 15, 13, 8};
  static const uint8_t s5[8] = {11, 12, 13, 16, 16, 16, 8, 10};
  static const uint8_t s6[8] = {12, 13, 14, 15, 16, 16, 9, 11};
  static const uint8_t s7[8] = {13, 14, 15, 8, 9, 10, 16, 12};
  static const uint8_t s8[8] = {14, 15, 16, 9, 10, 11, 16, 13};
  uint32_t tz[17], x[9];
  int64_t acc[9];
  size_t k;
  memcpy(tz, t, 16 * sizeof(uint32_t));
  tz[16] = 0;
  SD_CT_NO_VECTOR
  for (k = 0; k < 9; k++)
    acc[k] = (int64_t)k_w32_p256_5p[k];
  SD_CT_NO_VECTOR
  for (k = 0; k < 8; k++) {
    acc[k] += (int64_t)tz[s0[k]];
    acc[k] += (int64_t)tz[s1[k]] << 1;
    acc[k] += (int64_t)tz[s2[k]] << 1;
    acc[k] += (int64_t)tz[s3[k]];
    acc[k] += (int64_t)tz[s4[k]];
    acc[k] -= (int64_t)tz[s5[k]];
    acc[k] -= (int64_t)tz[s6[k]];
    acc[k] -= (int64_t)tz[s7[k]];
    acc[k] -= (int64_t)tz[s8[k]];
  }
  (void)w32_norm(x, acc, 9);            /* 0 <= value < 13p < 2^260: nine words, no carry out */
  w32_csub(x, k_w32_p256_8p, 9);
  w32_csub(x, k_w32_p256_4p, 9);
  w32_csub(x, k_w32_p256_2p, 9);
  w32_csub(x, k_w32_p256_1p, 9);
  memcpy(r, x, 8 * sizeof(uint32_t));
}

/* P-384: 2^384 = 2^128 + 2^96 - 2^32 + 1 (mod p). Fold the high 12 words twice (the first fold leaves a value
   below 2^513, the second below 2^385), then once more for the single carry word, and subtract p once.
   Each fold is a signed sum of four shifted copies of the high words. */
static void red_p384(uint32_t *r, const uint32_t *t)
{
  uint32_t tz[24], w[17], z[13], y[13];
  int64_t acc[17], acc2[13], acc3[12], hh, t3;
  size_t i, k;
  memcpy(tz, t, 24 * sizeof(uint32_t));
  SD_CT_NO_VECTOR
  for (k = 0; k < 17; k++)
    acc[k] = (k < 12) ? (int64_t)tz[k] : 0;
  SD_CT_NO_VECTOR
  for (i = 0; i < 12; i++) {
    hh = (int64_t)tz[12 + i];
    acc[i + 4] += hh;
    acc[i + 3] += hh;
    acc[i + 1] -= hh;
    acc[i] += hh;
  }
  (void)w32_norm(w, acc, 17);
  SD_CT_NO_VECTOR
  for (k = 0; k < 13; k++)
    acc2[k] = (k < 12) ? (int64_t)w[k] : 0;
  SD_CT_NO_VECTOR
  for (i = 0; i < 5; i++) {
    hh = (int64_t)w[12 + i];
    acc2[i + 4] += hh;
    acc2[i + 3] += hh;
    acc2[i + 1] -= hh;
    acc2[i] += hh;
  }
  (void)w32_norm(z, acc2, 13);          /* z[12] is 0 or 1 */
  t3 = (int64_t)z[12];
  SD_CT_NO_VECTOR
  for (k = 0; k < 12; k++)
    acc3[k] = (int64_t)z[k];
  acc3[0] += t3;
  acc3[1] -= t3;
  acc3[3] += t3;
  acc3[4] += t3;
  y[12] = (uint32_t)w32_norm(y, acc3, 12);  /* value < 2^384 + 2^129 < 2p */
  w32_csub(y, k_w32_p384_p, 13);
  memcpy(r, y, 12 * sizeof(uint32_t));
}

/* P-521: 2^521 = 1 (mod p). With V < 2^1042: V = lo + hi 2^521 gives lo + hi < 2^522; folding bit 521 once
   more gives T < 2^521 + 2 < 2p, and one conditional subtraction of p finishes. */
static void red_p521(uint32_t *r, const uint32_t *t)
{
  uint32_t lo[17], hi[17], s[17], top;
  uint64_t v, cc = 0;
  size_t k;
  SD_CT_NO_VECTOR
  for (k = 0; k < 16; k++)
    lo[k] = t[k];
  lo[16] = t[16] & 0x1ffu;
  SD_CT_NO_VECTOR
  for (k = 0; k < 17; k++)
    hi[k] = (t[16 + k] >> 9) | (t[17 + k] << 23);
  SD_CT_NO_VECTOR
  for (k = 0; k < 17; k++) {
    v = (uint64_t)lo[k] + hi[k] + cc;
    s[k] = (uint32_t)v;
    cc = v >> 32;
  }
  top = s[16] >> 9;                     /* bit 521 of the sum */
  s[16] &= 0x1ffu;
  cc = top;
  SD_CT_NO_VECTOR
  for (k = 0; k < 17; k++) {
    v = (uint64_t)s[k] + cc;
    s[k] = (uint32_t)v;
    cc = v >> 32;
  }
  w32_csub(s, k_w32_p521_p, 17);
  memcpy(r, s, 17 * sizeof(uint32_t));
  r[17] = 0;                            /* the 18th word of a 64-bit-limb element */
}

/* r = a * b mod p, normal form. r may alias a or b. */
static void fe_mul(const ec_curve *c, sd_limb *r, const sd_limb *a, const sd_limb *b)
{
  sd_limb prod[2 * EC_MAXL];
  uint32_t t[EC_PROD_W32], w[EC_PROD_W32];
  sd_mp_mul(prod, a, c->nl, b, c->nl);
  w32_from_limbs(t, prod, 2 * c->nl);
  switch (c->id) {
  case SD_CURVE_P256: red_p256(w, t); break;
  case SD_CURVE_P384: red_p384(w, t); break;
  default: red_p521(w, t); break;
  }
  w32_to_limbs(r, w, c->nl);
}

#define MUL(r, a, b) fe_mul(c, (r), (a), (b))
#define ADD(r, a, b) sd_mp_modadd((r), (a), (b), c->p, c->nl)
#define SUB(r, a, b) sd_mp_modsub((r), (a), (b), c->p, c->nl)

/* ---- points ---- */

static void fe_one(const ec_curve *c, sd_limb *r)
{
  memset(r, 0, c->nl * sizeof(sd_limb));
  r[0] = 1;
}

static void pt_set_inf(const ec_curve *c, ec_pt *r)
{
  memset(r, 0, sizeof(*r));
  fe_one(c, r->y);
}

static void pt_set_g(const ec_curve *c, ec_pt *r)
{
  memset(r, 0, sizeof(*r));
  memcpy(r->x, c->gx, c->nl * sizeof(sd_limb));
  memcpy(r->y, c->gy, c->nl * sizeof(sd_limb));
  fe_one(c, r->z);
}

/* RCB Algorithm 4 (complete addition, a = -3). r may alias p or q. */
static void pt_add(const ec_curve *c, ec_pt *r, const ec_pt *p, const ec_pt *q)
{
  sd_limb t0[EC_MAXL], t1[EC_MAXL], t2[EC_MAXL], t3[EC_MAXL], t4[EC_MAXL];
  sd_limb x3[EC_MAXL], y3[EC_MAXL], z3[EC_MAXL];
  const sd_limb *b = c->b;
  MUL(t0, p->x, q->x);
  MUL(t1, p->y, q->y);
  MUL(t2, p->z, q->z);
  ADD(t3, p->x, p->y);
  ADD(t4, q->x, q->y);
  MUL(t3, t3, t4);
  ADD(t4, t0, t1);
  SUB(t3, t3, t4);
  ADD(t4, p->y, p->z);
  ADD(x3, q->y, q->z);
  MUL(t4, t4, x3);
  ADD(x3, t1, t2);
  SUB(t4, t4, x3);
  ADD(x3, p->x, p->z);
  ADD(y3, q->x, q->z);
  MUL(x3, x3, y3);
  ADD(y3, t0, t2);
  SUB(y3, x3, y3);
  MUL(z3, b, t2);
  SUB(x3, y3, z3);
  ADD(z3, x3, x3);
  ADD(x3, x3, z3);
  SUB(z3, t1, x3);
  ADD(x3, t1, x3);
  MUL(y3, b, y3);
  ADD(t1, t2, t2);
  ADD(t2, t1, t2);
  SUB(y3, y3, t2);
  SUB(y3, y3, t0);
  ADD(t1, y3, y3);
  ADD(y3, t1, y3);
  ADD(t1, t0, t0);
  ADD(t0, t1, t0);
  SUB(t0, t0, t2);
  MUL(t1, t4, y3);
  MUL(t2, t0, y3);
  MUL(y3, x3, z3);
  ADD(y3, y3, t2);
  MUL(x3, x3, t3);
  SUB(x3, x3, t1);
  MUL(z3, t4, z3);
  MUL(t1, t3, t0);
  ADD(z3, z3, t1);
  memcpy(r->x, x3, c->nl * sizeof(sd_limb));
  memcpy(r->y, y3, c->nl * sizeof(sd_limb));
  memcpy(r->z, z3, c->nl * sizeof(sd_limb));
}

/* RCB Algorithm 6 (doubling, a = -3). r may alias p. */
static void pt_dbl(const ec_curve *c, ec_pt *r, const ec_pt *p)
{
  sd_limb t0[EC_MAXL], t1[EC_MAXL], t2[EC_MAXL], t3[EC_MAXL];
  sd_limb x3[EC_MAXL], y3[EC_MAXL], z3[EC_MAXL];
  const sd_limb *b = c->b;
  MUL(t0, p->x, p->x);
  MUL(t1, p->y, p->y);
  MUL(t2, p->z, p->z);
  MUL(t3, p->x, p->y);
  ADD(t3, t3, t3);
  MUL(z3, p->x, p->z);
  ADD(z3, z3, z3);
  MUL(y3, b, t2);
  SUB(y3, y3, z3);
  ADD(x3, y3, y3);
  ADD(y3, x3, y3);
  SUB(x3, t1, y3);
  ADD(y3, t1, y3);
  MUL(y3, x3, y3);
  MUL(x3, x3, t3);
  ADD(t3, t2, t2);
  ADD(t2, t2, t3);
  MUL(z3, b, z3);
  SUB(z3, z3, t2);
  SUB(z3, z3, t0);
  ADD(t3, z3, z3);
  ADD(z3, z3, t3);
  ADD(t3, t0, t0);
  ADD(t0, t3, t0);
  SUB(t0, t0, t2);
  MUL(t0, t0, z3);
  ADD(y3, y3, t0);
  MUL(t0, p->y, p->z);
  ADD(t0, t0, t0);
  MUL(z3, t0, z3);
  SUB(x3, x3, z3);
  MUL(z3, t0, t1);
  ADD(z3, z3, z3);
  ADD(z3, z3, z3);
  memcpy(r->x, x3, c->nl * sizeof(sd_limb));
  memcpy(r->y, y3, c->nl * sizeof(sd_limb));
  memcpy(r->z, z3, c->nl * sizeof(sd_limb));
}

/* r = k*p, k has nl limbs (any value below 2^(4*ceil(bits/4))). Constant time. */
static void pt_mul(const ec_curve *c, ec_pt *r, const sd_limb *k, const ec_pt *p)
{
  ec_pt tab[16], acc, sel;
  uint32_t nwin = (c->bits + 3) / 4, w, j;
  size_t i, nl = c->nl;
  pt_set_inf(c, &tab[0]);
  tab[1] = *p;
  for (j = 2; j < 16; j++)
    pt_add(c, &tab[j], &tab[j - 1], p);
  pt_set_inf(c, &acc);
  for (w = nwin; w-- > 0;) {
    uint32_t bit = 4 * w;
    uint32_t digit = (uint32_t)((k[bit / SD_LIMB_BITS] >> (bit % SD_LIMB_BITS)) & 15u);
    for (j = 0; j < 4; j++)
      pt_dbl(c, &acc, &acc);
    memset(&sel, 0, sizeof(sel));
    for (j = 0; j < 16; j++) {
      sd_limb m = sd_mp_mask(sd_ct_eq_u32(j, digit) & 1u);
      for (i = 0; i < nl; i++) {
        sel.x[i] |= tab[j].x[i] & m;
        sel.y[i] |= tab[j].y[i] & m;
        sel.z[i] |= tab[j].z[i] & m;
      }
    }
    pt_add(c, &acc, &acc, &sel);
  }
  *r = acc;
  sd_secure_zero(tab, sizeof(tab));
  sd_secure_zero(&sel, sizeof(sel));
  sd_secure_zero(&acc, sizeof(acc));
}

/* Affine coordinates (normal form). Returns an all-ones mask unless p is infinity. */
static sd_limb pt_affine(const ec_curve *c, sd_limb *x, sd_limb *y, const ec_pt *p)
{
  sd_limb zi[EC_MAXL], work[SD_MP_MODINV_WORK(EC_MAXL)], ok;
  size_t nl = c->nl;
  ok = ~sd_mp_is_zero(p->z, nl);
  (void)sd_mp_modinv_ct(zi, p->z, c->p, nl, work);
  MUL(x, p->x, zi);          /* X * Z^-1 */
  if (y)
    MUL(y, p->y, zi);
  sd_secure_zero(zi, sizeof(zi));
  sd_secure_zero(work, sizeof(work));
  return ok;
}

static void encode_point(const ec_curve *c, uint8_t *out, const sd_limb *x, const sd_limb *y)
{
  out[0] = 0x04;
  sd_mp_to_be(out + 1, c->flen, x, c->nl);
  sd_mp_to_be(out + 1 + c->flen, c->flen, y, c->nl);
}

/* Decodes and validates an uncompressed point (public input, variable time). */
static sd_err decode_point(const ec_curve *c, ec_pt *r, const uint8_t *in, size_t len)
{
  sd_limb x[EC_MAXL], y[EC_MAXL], lhs[EC_MAXL], rhs[EC_MAXL], t[EC_MAXL];
  size_t nl = c->nl;
  if (in == NULL || len != 1 + 2 * c->flen || in[0] != 0x04)
    return SD_E_CRYPTO;
  sd_mp_from_be(x, nl, in + 1, c->flen);
  sd_mp_from_be(y, nl, in + 1 + c->flen, c->flen);
  if (sd_mp_vt_cmp(x, nl, c->p, nl) >= 0 || sd_mp_vt_cmp(y, nl, c->p, nl) >= 0)
    return SD_E_CRYPTO;
  memset(r, 0, sizeof(*r));
  memcpy(r->x, x, nl * sizeof(sd_limb));
  memcpy(r->y, y, nl * sizeof(sd_limb));
  fe_one(c, r->z);
  /* y^2 == x^3 - 3x + b */
  MUL(lhs, r->y, r->y);
  MUL(t, r->x, r->x);
  MUL(rhs, t, r->x);
  SUB(rhs, rhs, r->x);
  SUB(rhs, rhs, r->x);
  SUB(rhs, rhs, r->x);
  ADD(rhs, rhs, c->b);
  if (sd_mp_vt_cmp(lhs, nl, rhs, nl) != 0)
    return SD_E_CRYPTO;
  return SD_OK;
}

/* ---- scalars ---- */

/* Leftmost `bits` bits of the big-endian string (SEC 1 / RFC 6979 bits2int) into nl limbs. */
static void bits2int(const ec_curve *c, sd_limb *r, const uint8_t *s, size_t len)
{
  size_t take = SD_MIN(len, ((size_t)c->bits + 7) / 8), sh;
  sd_mp_from_be(r, c->nl, s, take);
  for (sh = 8 * take; sh > c->bits; sh--)
    sd_mp_shr1(r, 0, c->nl);
}

/* r = a mod n for a < 2n. */
static void reduce_once(const ec_curve *c, sd_limb *a)
{
  sd_limb t[EC_MAXL];
  sd_limb borrow = sd_mp_sub(t, a, c->n, c->nl);
  sd_mp_cmov(a, t, sd_mp_mask(borrow ^ 1u), c->nl);
}

/* Mask: 1 <= a < n. */
static sd_limb scalar_in_range(const ec_curve *c, const sd_limb *a)
{
  return ~sd_mp_is_zero(a, c->nl) & sd_mp_mask(sd_mp_lt(a, c->n, c->nl));
}

/* r = a * b mod n for normal-form a, b < n. */
static void scalar_mul(const ec_curve *c, sd_limb *r, const sd_limb *a, const sd_limb *b)
{
  sd_limb t[EC_MAXL];
  sd_mp_montmul(t, a, c->n_r2, c->n, c->n_m0i, c->nl);
  sd_mp_montmul(r, t, b, c->n, c->n_m0i, c->nl);
}

/* ---- RFC 6979 HMAC-DRBG ---- */

typedef struct drbg {
  sd_hash_alg h;
  size_t hl;
  uint8_t k[SD_HASH_MAX_LEN], v[SD_HASH_MAX_LEN];
} drbg;

static void drbg_hmac(drbg *g, uint8_t *out, const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                      const uint8_t *cc, size_t cl, const uint8_t *d, size_t dl, const uint8_t *e, size_t el)
{
  sd_hmac_ctx h;
  sd_hmac_init(&h, g->h, g->k, g->hl);
  sd_hmac_update(&h, a, al);
  if (bl) sd_hmac_update(&h, b, bl);
  if (cl) sd_hmac_update(&h, cc, cl);
  if (dl) sd_hmac_update(&h, d, dl);
  if (el) sd_hmac_update(&h, e, el);
  sd_hmac_final(&h, out);
  sd_hmac_wipe(&h);
}

static void drbg_init(const ec_curve *c, drbg *g, sd_hash_alg h, const sd_limb *x, const uint8_t *digest,
                      size_t dlen, const uint8_t *extra, size_t extralen)
{
  uint8_t xo[SD_EC_MAX_FIELD_LEN], ho[SD_EC_MAX_FIELD_LEN];
  static const uint8_t z0 = 0x00, z1 = 0x01;
  sd_limb hv[EC_MAXL];
  size_t rl = c->flen;
  g->h = h;
  g->hl = sd_hash_len(h);
  memset(g->v, 0x01, g->hl);
  memset(g->k, 0x00, g->hl);
  sd_mp_to_be(xo, rl, x, c->nl);
  bits2int(c, hv, digest, dlen);
  reduce_once(c, hv);
  sd_mp_to_be(ho, rl, hv, c->nl);
  drbg_hmac(g, g->k, g->v, g->hl, &z0, 1, xo, rl, ho, rl, extra, extralen);
  drbg_hmac(g, g->v, g->v, g->hl, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  drbg_hmac(g, g->k, g->v, g->hl, &z1, 1, xo, rl, ho, rl, extra, extralen);
  drbg_hmac(g, g->v, g->v, g->hl, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
  sd_secure_zero(xo, sizeof(xo));
  sd_secure_zero(hv, sizeof(hv));
}

/* Next candidate nonce in [1, n-1] (RFC 6979 §3.2 step h); `again` runs the K/V update first. */
static void drbg_nonce(const ec_curve *c, drbg *g, sd_limb *k, int again)
{
  static const uint8_t z0 = 0x00;
  uint8_t t[SD_EC_MAX_FIELD_LEN + SD_HASH_MAX_LEN];
  size_t rl = c->flen, tl;
  for (;;) {
    if (again) {
      drbg_hmac(g, g->k, g->v, g->hl, &z0, 1, NULL, 0, NULL, 0, NULL, 0);
      drbg_hmac(g, g->v, g->v, g->hl, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    }
    again = 1;
    for (tl = 0; tl < rl; tl += g->hl) {
      drbg_hmac(g, g->v, g->v, g->hl, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
      memcpy(t + tl, g->v, g->hl);
    }
    bits2int(c, k, t, rl);
    if (scalar_in_range(c, k))      /* rejection is negligible and reveals only a discarded value */
      break;
  }
  sd_secure_zero(t, sizeof(t));
}

/* ---- public API ---- */

size_t sd_ec_field_len(sd_curve c)
{
  const ec_curve *cv = curve_get(c);
  return cv ? cv->flen : 0;
}

size_t sd_ec_point_len(sd_curve c)
{
  const ec_curve *cv = curve_get(c);
  return cv ? 1 + 2 * cv->flen : 0;
}

sd_hash_alg sd_ec_hash(sd_curve c)
{
  const ec_curve *cv = curve_get(c);
  return cv ? cv->hash : SD_HASH_SHA256;
}

sd_curve sd_ec_key_curve(const sd_ec_key *k)
{
  return k->c->id;
}

int sd_ec_has_private(const sd_ec_key *k)
{
  return k ? k->has_priv : 0;
}

void sd_ec_free(sd_ec_key *k)
{
  if (k)
    sd_secure_free(k, sizeof(*k));
}

/* Public point from k->d. */
static void derive_pub(sd_ec_key *k)
{
  const ec_curve *c = k->c;
  ec_pt g, q;
  sd_limb x[EC_MAXL], y[EC_MAXL];
  pt_set_g(c, &g);
  pt_mul(c, &q, k->d, &g);
  (void)pt_affine(c, x, y, &q);        /* d in [1, n-1]: never infinity */
  encode_point(c, k->pub, x, y);
  (void)decode_point(c, &k->q, k->pub, 1 + 2 * c->flen);
  sd_secure_zero(&q, sizeof(q));
}

sd_err sd_ec_generate(sd_curve cid, sd_ec_key **out)
{
  const ec_curve *c = curve_get(cid);
  sd_ec_key *k;
  uint8_t buf[SD_EC_MAX_FIELD_LEN];
  int tries;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (c == NULL)
    return SD_E_UNSUPPORTED;
  k = (sd_ec_key *)sd_calloc(1, sizeof(*k));
  if (k == NULL)
    return SD_E_NO_MEMORY;
  k->c = c;
  for (tries = 0;; tries++) {
    if (tries == 64 || sd_random(buf, c->flen) != SD_OK) {
      sd_secure_zero(buf, sizeof(buf));
      sd_ec_free(k);
      return SD_E_FAILURE;
    }
    if (c->bits % 8)
      buf[0] &= (uint8_t)((1u << (c->bits % 8)) - 1u);
    sd_mp_from_be(k->d, c->nl, buf, c->flen);
    if (scalar_in_range(c, k->d))
      break;
  }
  sd_secure_zero(buf, sizeof(buf));
  k->has_priv = 1;
  derive_pub(k);
  sd_pk_scrub_stack();
  *out = k;
  return SD_OK;
}

sd_err sd_ec_import(sd_curve cid, const uint8_t *pub, size_t publen, const uint8_t *priv, size_t privlen,
                    sd_ec_key **out)
{
  const ec_curve *c = curve_get(cid);
  sd_ec_key *k;
  sd_err err;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (c == NULL)
    return SD_E_UNSUPPORTED;
  if (pub == NULL && priv == NULL)
    return SD_E_INVALID_PARAM;
  k = (sd_ec_key *)sd_calloc(1, sizeof(*k));
  if (k == NULL)
    return SD_E_NO_MEMORY;
  k->c = c;
  if (pub) {
    err = decode_point(c, &k->q, pub, publen);
    if (err != SD_OK) {
      sd_ec_free(k);
      return err;
    }
    memcpy(k->pub, pub, publen);
  }
  if (priv) {
    uint8_t extra = 0;
    size_t i, skip = privlen > c->flen ? privlen - c->flen : 0;
    uint8_t given[SD_EC_MAX_POINT_LEN];
    for (i = 0; i < skip; i++)
      extra |= priv[i];
    sd_mp_from_be(k->d, c->nl, priv + skip, privlen - skip);
    if (extra || !scalar_in_range(c, k->d)) {
      sd_ec_free(k);
      return SD_E_KEY_FORMAT;
    }
    k->has_priv = 1;
    memcpy(given, k->pub, sizeof(given));
    derive_pub(k);
    sd_pk_scrub_stack();
    if (pub && memcmp(given, k->pub, 1 + 2 * c->flen) != 0) {
      sd_ec_free(k);
      return SD_E_KEY_FORMAT;
    }
  }
  *out = k;
  return SD_OK;
}

sd_err sd_ec_export_pub(const sd_ec_key *k, uint8_t *out, size_t *len)
{
  size_t pl;
  if (k == NULL || out == NULL || len == NULL)
    return SD_E_INVALID_PARAM;
  pl = 1 + 2 * k->c->flen;
  if (*len < pl)
    return SD_E_INVALID_PARAM;
  memcpy(out, k->pub, pl);
  *len = pl;
  return SD_OK;
}

sd_err sd_ecdh(const sd_ec_key *mine, const uint8_t *peer_pub, size_t len, uint8_t *secret_x, size_t *slen)
{
  const ec_curve *c;
  ec_pt q, r;
  sd_limb x[EC_MAXL], ok;
  sd_err err;
  if (mine == NULL || secret_x == NULL || slen == NULL || !mine->has_priv)
    return SD_E_INVALID_PARAM;
  c = mine->c;
  if (*slen < c->flen)
    return SD_E_INVALID_PARAM;
  err = decode_point(c, &q, peer_pub, len);   /* validated before any secret-dependent work */
  if (err != SD_OK)
    return err;
  pt_mul(c, &r, mine->d, &q);
  ok = pt_affine(c, x, NULL, &r);
  sd_mp_to_be(secret_x, c->flen, x, c->nl);
  sd_secure_zero(&r, sizeof(r));
  sd_secure_zero(x, sizeof(x));
  sd_pk_scrub_stack();
  if (!ok) {
    sd_secure_zero(secret_x, c->flen);
    return SD_E_CRYPTO;
  }
  *slen = c->flen;
  return SD_OK;
}

sd_err sd_ecdsa_sign_ex(const sd_ec_key *key, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                        const uint8_t *extra, size_t extralen, uint8_t *r_out, uint8_t *s_out)
{
  const ec_curve *c;
  drbg g;
  ec_pt G, R;
  sd_limb e[EC_MAXL], k[EC_MAXL], r[EC_MAXL], s[EC_MAXL], t[EC_MAXL], kinv[EC_MAXL];
  sd_limb work[SD_MP_MODINV_WORK(EC_MAXL)];
  int again = 0, tries;
  sd_err err = SD_E_CRYPTO;
  if (key == NULL || digest == NULL || r_out == NULL || s_out == NULL || !key->has_priv ||
      (extralen && extra == NULL))
    return SD_E_INVALID_PARAM;
  if (sd_hash_len(h) == 0 || dlen == 0)
    return SD_E_INVALID_PARAM;
  c = key->c;
  bits2int(c, e, digest, dlen);
  reduce_once(c, e);
  drbg_init(c, &g, h, key->d, digest, dlen, extra, extralen);
  pt_set_g(c, &G);
  for (tries = 0; tries < 16; tries++) {
    sd_limb ok;
    drbg_nonce(c, &g, k, again);
    again = 1;
    pt_mul(c, &R, k, &G);
    (void)pt_affine(c, r, NULL, &R);
    reduce_once(c, r);                          /* x(R) < p < 2n */
    (void)sd_mp_modinv_ct(kinv, k, c->n, c->nl, work);
    scalar_mul(c, t, r, key->d);
    sd_mp_modadd(t, t, e, c->n, c->nl);         /* e + r*d */
    scalar_mul(c, s, kinv, t);
    ok = ~sd_mp_is_zero(r, c->nl) & ~sd_mp_is_zero(s, c->nl);
    if (ok) {
      sd_mp_to_be(r_out, c->flen, r, c->nl);
      sd_mp_to_be(s_out, c->flen, s, c->nl);
      err = SD_OK;
      break;
    }
  }
  sd_secure_zero(&g, sizeof(g));
  sd_secure_zero(&R, sizeof(R));
  sd_secure_zero(k, sizeof(k));
  sd_secure_zero(kinv, sizeof(kinv));
  sd_secure_zero(t, sizeof(t));
  sd_secure_zero(s, sizeof(s));
  sd_pk_scrub_stack();
  return err;
}

sd_err sd_ecdsa_sign(const sd_ec_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                     uint8_t *r, uint8_t *s)
{
  uint8_t extra[32];
  sd_err err;
  if (sd_random(extra, sizeof(extra)) != SD_OK)
    return SD_E_FAILURE;
  err = sd_ecdsa_sign_ex(k, h, digest, dlen, extra, sizeof(extra), r, s);
  sd_secure_zero(extra, sizeof(extra));
  return err;
}

static int parse_scalar_vt(const ec_curve *c, sd_limb *out, const uint8_t *b, size_t len)
{
  while (len > 0 && b[0] == 0) {
    b++;
    len--;
  }
  if (len == 0 || len > c->flen)
    return 0;
  sd_mp_from_be(out, c->nl, b, len);
  return sd_mp_vt_cmp(out, c->nl, c->n, c->nl) < 0;
}

sd_err sd_ecdsa_verify(const sd_ec_key *key, const uint8_t *digest, size_t dlen,
                       const uint8_t *rb, size_t rlen, const uint8_t *sb, size_t slen)
{
  const ec_curve *c;
  sd_limb r[EC_MAXL], s[EC_MAXL], e[EC_MAXL], w[EC_MAXL], u1[EC_MAXL], u2[EC_MAXL], x[EC_MAXL];
  sd_limb work[SD_MP_MODINV_WORK(EC_MAXL)];
  ec_pt G, P1, P2;
  if (key == NULL || (dlen && digest == NULL) || (rlen && rb == NULL) || (slen && sb == NULL))
    return SD_E_INVALID_PARAM;
  c = key->c;
  if (!parse_scalar_vt(c, r, rb, rlen) || !parse_scalar_vt(c, s, sb, slen))
    return SD_E_CRYPTO;
  bits2int(c, e, digest, dlen);
  reduce_once(c, e);
  (void)sd_mp_modinv_ct(w, s, c->n, c->nl, work);  /* n prime, s != 0 */
  scalar_mul(c, u1, e, w);
  scalar_mul(c, u2, r, w);
  pt_set_g(c, &G);
  pt_mul(c, &P1, u1, &G);
  pt_mul(c, &P2, u2, &key->q);
  pt_add(c, &P1, &P1, &P2);
  if (!pt_affine(c, x, NULL, &P1))
    return SD_E_CRYPTO;
  reduce_once(c, x);
  return sd_mp_vt_cmp(x, c->nl, r, c->nl) == 0 ? SD_OK : SD_E_CRYPTO;
}

/* ---- test hooks ----
 * Compiled only into the test translation unit tests/unit/sd_crypto_pk/ec_test_hooks.c, which includes
 * this file with SD_EC_TEST_HOOKS defined. The product object never carries these entry points. */
#ifdef SD_EC_TEST_HOOKS

sd_err sd_ec_test_mul(sd_curve cid, const uint8_t *kb, size_t klen, const uint8_t *pt, uint8_t *out)
{
  const ec_curve *c = curve_get(cid);
  ec_pt p, r;
  sd_limb k[EC_MAXL], x[EC_MAXL], y[EC_MAXL];
  sd_err err;
  if (c == NULL || klen > c->flen)
    return SD_E_INVALID_PARAM;
  err = decode_point(c, &p, pt, 1 + 2 * c->flen);
  if (err != SD_OK)
    return err;
  memset(k, 0, sizeof(k));
  sd_mp_from_be(k, c->nl, kb, klen);
  pt_mul(c, &r, k, &p);
  if (!pt_affine(c, x, y, &r))
    return SD_E_CRYPTO;
  encode_point(c, out, x, y);
  return SD_OK;
}

sd_err sd_ec_test_add(sd_curve cid, const uint8_t *pa, const uint8_t *qa, uint8_t *out)
{
  const ec_curve *c = curve_get(cid);
  ec_pt p, q;
  sd_limb x[EC_MAXL], y[EC_MAXL];
  if (c == NULL || decode_point(c, &p, pa, 1 + 2 * c->flen) != SD_OK ||
      decode_point(c, &q, qa, 1 + 2 * c->flen) != SD_OK)
    return SD_E_INVALID_PARAM;
  pt_add(c, &p, &p, &q);
  if (!pt_affine(c, x, y, &p))
    return SD_E_CRYPTO;
  encode_point(c, out, x, y);
  return SD_OK;
}

sd_err sd_ec_test_dbl(sd_curve cid, const uint8_t *pa, uint8_t *out)
{
  const ec_curve *c = curve_get(cid);
  ec_pt p;
  sd_limb x[EC_MAXL], y[EC_MAXL];
  if (c == NULL || decode_point(c, &p, pa, 1 + 2 * c->flen) != SD_OK)
    return SD_E_INVALID_PARAM;
  pt_dbl(c, &p, &p);
  if (!pt_affine(c, x, y, &p))
    return SD_E_CRYPTO;
  encode_point(c, out, x, y);
  return SD_OK;
}

/* Field multiplication: a, b are big-endian field_len bytes (inputs must be below the field bound of the
   curve, see the field multiplication section); out receives the product mod p. Three implementations:
   the NIST reduction (fe_mul), a bit-serial reference (sd_mp_mod of the schoolbook product), and the
   previous Montgomery path (two montmul calls against R^2 mod p; inputs below p). */
static sd_err fe_test_io(sd_curve cid, const uint8_t *a, const uint8_t *b, uint8_t *out, int mode)
{
  const ec_curve *c = curve_get(cid);
  sd_limb x[EC_MAXL], y[EC_MAXL], r[EC_MAXL], prod[2 * EC_MAXL], t[EC_MAXL];
  if (c == NULL || a == NULL || b == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  sd_mp_from_be(x, c->nl, a, c->flen);
  sd_mp_from_be(y, c->nl, b, c->flen);
  if (mode == 0) {
    fe_mul(c, r, x, y);
  } else if (mode == 1) {
    sd_mp_mul(prod, x, c->nl, y, c->nl);
    sd_mp_mod(r, prod, 2 * c->nl, c->p, c->nl);
  } else {
    sd_mp_montmul(t, x, y, c->p, c->p_m0i, c->nl);
    sd_mp_montmul(r, t, c->p_r2, c->p, c->p_m0i, c->nl);
  }
  sd_mp_to_be(out, c->flen, r, c->nl);
  return SD_OK;
}

sd_err sd_ec_test_fe_mul(sd_curve cid, const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  return fe_test_io(cid, a, b, out, 0);
}

sd_err sd_ec_test_fe_ref(sd_curve cid, const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  return fe_test_io(cid, a, b, out, 1);
}

sd_err sd_ec_test_fe_mont(sd_curve cid, const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  return fe_test_io(cid, a, b, out, 2);
}

#endif /* SD_EC_TEST_HOOKS */
