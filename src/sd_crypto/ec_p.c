/* ECDH and ECDSA over NIST P-256, P-384 and P-521 (FIPS 186-4, SEC 1 v2, RFC 5656 for SSH; 01 §2.8.2).
 *
 * Field and scalar arithmetic: the generic Montgomery engine of bn.c with a fixed limb count per curve
 * (constants in pk_consts.inc, generated from RFC 5903 by gen_pk_consts.py).
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
  const sd_limb *p, *p_r2, *p_one, *n, *n_r2, *n_one, *b_m, *gx_m, *gy_m;
  sd_limb p_m0i, n_m0i;
} ec_curve;

static const ec_curve k_curves[3] = {
  { SD_CURVE_P256, K_P256_LIMBS, 32, 256, SD_HASH_SHA256, k_p256_p, k_p256_p_r2, k_p256_p_one, k_p256_n,
    k_p256_n_r2, k_p256_n_one, k_p256_b_m, k_p256_gx_m, k_p256_gy_m, K_P256_P_M0I, K_P256_N_M0I },
  { SD_CURVE_P384, K_P384_LIMBS, 48, 384, SD_HASH_SHA384, k_p384_p, k_p384_p_r2, k_p384_p_one, k_p384_n,
    k_p384_n_r2, k_p384_n_one, k_p384_b_m, k_p384_gx_m, k_p384_gy_m, K_P384_P_M0I, K_P384_N_M0I },
  { SD_CURVE_P521, K_P521_LIMBS, 66, 521, SD_HASH_SHA512, k_p521_p, k_p521_p_r2, k_p521_p_one, k_p521_n,
    k_p521_n_r2, k_p521_n_one, k_p521_b_m, k_p521_gx_m, k_p521_gy_m, K_P521_P_M0I, K_P521_N_M0I },
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

#define MUL(r, a, b) sd_mp_montmul((r), (a), (b), c->p, c->p_m0i, c->nl)
#define ADD(r, a, b) sd_mp_modadd((r), (a), (b), c->p, c->nl)
#define SUB(r, a, b) sd_mp_modsub((r), (a), (b), c->p, c->nl)

/* ---- points ---- */

static void pt_set_inf(const ec_curve *c, ec_pt *r)
{
  memset(r, 0, sizeof(*r));
  memcpy(r->y, c->p_one, c->nl * sizeof(sd_limb));
}

static void pt_set_g(const ec_curve *c, ec_pt *r)
{
  memset(r, 0, sizeof(*r));
  memcpy(r->x, c->gx_m, c->nl * sizeof(sd_limb));
  memcpy(r->y, c->gy_m, c->nl * sizeof(sd_limb));
  memcpy(r->z, c->p_one, c->nl * sizeof(sd_limb));
}

/* RCB Algorithm 4 (complete addition, a = -3). r may alias p or q. */
static void pt_add(const ec_curve *c, ec_pt *r, const ec_pt *p, const ec_pt *q)
{
  sd_limb t0[EC_MAXL], t1[EC_MAXL], t2[EC_MAXL], t3[EC_MAXL], t4[EC_MAXL];
  sd_limb x3[EC_MAXL], y3[EC_MAXL], z3[EC_MAXL];
  const sd_limb *b = c->b_m;
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
  const sd_limb *b = c->b_m;
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

/* Affine coordinates in normal (non-Montgomery) form. Returns an all-ones mask unless p is infinity. */
static sd_limb pt_affine(const ec_curve *c, sd_limb *x, sd_limb *y, const ec_pt *p)
{
  sd_limb z[EC_MAXL], zi[EC_MAXL], one[EC_MAXL], work[SD_MP_MODINV_WORK(EC_MAXL)], ok;
  size_t nl = c->nl;
  memset(one, 0, sizeof(one));
  one[0] = 1;
  MUL(z, p->z, one);
  ok = ~sd_mp_is_zero(z, nl);
  (void)sd_mp_modinv_ct(zi, z, c->p, nl, work);
  MUL(x, p->x, zi);          /* (X R) * Z^-1 * R^-1 = X / Z */
  if (y)
    MUL(y, p->y, zi);
  sd_secure_zero(z, sizeof(z));
  sd_secure_zero(zi, sizeof(zi));
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
  MUL(r->x, x, c->p_r2);
  MUL(r->y, y, c->p_r2);
  memcpy(r->z, c->p_one, nl * sizeof(sd_limb));
  /* y^2 == x^3 - 3x + b */
  MUL(lhs, r->y, r->y);
  MUL(t, r->x, r->x);
  MUL(rhs, t, r->x);
  SUB(rhs, rhs, r->x);
  SUB(rhs, rhs, r->x);
  SUB(rhs, rhs, r->x);
  ADD(rhs, rhs, c->b_m);
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

#endif /* SD_EC_TEST_HOOKS */
