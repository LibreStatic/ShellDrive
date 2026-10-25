/* GF(2^255-19), X25519 (RFC 7748) and Ed25519 (RFC 8032), own arithmetic (01 §2.8.1).
 *
 * References read: RFC 7748 (Montgomery ladder, clamping), RFC 8032 (encoding, decoding, signing,
 * verification), Hisil-Wong-Carter-Dawson 2008 "Twisted Edwards curves revisited" (extended
 * coordinates, a = -1 unified addition and doubling), Bernstein 2006 "Curve25519" (radix 2^25.5).
 *
 * Field elements: 10 unsigned limbs, radix 2^25.5 (26/25 bits alternating). Every product is a
 * 32x32->64 multiplication through SD_MUL32 (sd_ct64.h, rule 2.4.3); 64-bit values are only added and
 * shifted by constants. Limb bounds: outputs of every fe_* function have limbs < 2^26 + 2^15
 * (carried); inputs may be any output. Products then stay below 2^61 per accumulator.
 *
 * Constant time: X25519 and Ed25519 signing (scalar multiplication, table lookups by mask, scalar
 * reduction mod L bit by bit) have no secret-dependent branches or indices. Ed25519 verification
 * reuses the same code (it only handles public data, so this is conservative, not required). */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"
#include "sd_platform/sd_thread.h"

typedef struct fe { uint32_t v[10]; } fe;

#define M26 0x3ffffffu
#define M25 0x1ffffffu

/* ---- field ---- */

static void fe_0(fe *h) { memset(h, 0, sizeof(*h)); }
static void fe_1(fe *h) { memset(h, 0, sizeof(*h)); h->v[0] = 1; }

/* Carry chain on 32-bit limbs that are each below 2^31. */
static void fe_carry32(fe *h, uint32_t *t)
{
  uint32_t c;
  c = t[0] >> 26; t[0] &= M26; t[1] += c;
  c = t[1] >> 25; t[1] &= M25; t[2] += c;
  c = t[2] >> 26; t[2] &= M26; t[3] += c;
  c = t[3] >> 25; t[3] &= M25; t[4] += c;
  c = t[4] >> 26; t[4] &= M26; t[5] += c;
  c = t[5] >> 25; t[5] &= M25; t[6] += c;
  c = t[6] >> 26; t[6] &= M26; t[7] += c;
  c = t[7] >> 25; t[7] &= M25; t[8] += c;
  c = t[8] >> 26; t[8] &= M26; t[9] += c;
  c = t[9] >> 25; t[9] &= M25; t[0] += 19u * c;
  c = t[0] >> 26; t[0] &= M26; t[1] += c;
  memcpy(h->v, t, sizeof(h->v));
}

/* Carry chain on 64-bit accumulators below 2^62. */
static void fe_carry64(fe *h, uint64_t *t)
{
  uint64_t c;
  c = t[0] >> 26; t[0] &= M26; t[1] += c;
  c = t[1] >> 25; t[1] &= M25; t[2] += c;
  c = t[2] >> 26; t[2] &= M26; t[3] += c;
  c = t[3] >> 25; t[3] &= M25; t[4] += c;
  c = t[4] >> 26; t[4] &= M26; t[5] += c;
  c = t[5] >> 25; t[5] &= M25; t[6] += c;
  c = t[6] >> 26; t[6] &= M26; t[7] += c;
  c = t[7] >> 25; t[7] &= M25; t[8] += c;
  c = t[8] >> 26; t[8] &= M26; t[9] += c;
  c = t[9] >> 25; t[9] &= M25;
  t[0] += (c << 4) + (c << 1) + c;          /* 19 * c without a 64-bit multiply */
  c = t[0] >> 26; t[0] &= M26; t[1] += c;
  c = t[1] >> 25; t[1] &= M25; t[2] += c;
  {
    int i;
    for (i = 0; i < 10; i++)
      h->v[i] = (uint32_t)t[i];
  }
}

static void fe_add(fe *h, const fe *f, const fe *g)
{
  uint32_t t[10];
  int i;
  for (i = 0; i < 10; i++)
    t[i] = f->v[i] + g->v[i];
  fe_carry32(h, t);
}

/* 4p, limb by limb, so f + 4p - g never goes negative for carried g. */
static const uint32_t k_4p[10] = {
  0xfffffb4u, 0x7fffffcu, 0xffffffcu, 0x7fffffcu, 0xffffffcu,
  0x7fffffcu, 0xffffffcu, 0x7fffffcu, 0xffffffcu, 0x7fffffcu
};

static void fe_sub(fe *h, const fe *f, const fe *g)
{
  uint32_t t[10];
  int i;
  for (i = 0; i < 10; i++)
    t[i] = f->v[i] + k_4p[i] - g->v[i];
  fe_carry32(h, t);
}

static void fe_neg(fe *h, const fe *f)
{
  fe z;
  fe_0(&z);
  fe_sub(h, &z, f);
}

/* h = f * g. Term f_i g_j lands in limb (i + j) mod 10, times 2 when i and j are both odd (radix
   2^25.5) and times 19 when i + j >= 10 (2^255 = 19 mod p). Fully unrolled (generated layout). */
static void fe_mul(fe *h, const fe *f, const fe *g)
{
  uint32_t f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4], f5 = f->v[5], f6 = f->v[6],
           f7 = f->v[7], f8 = f->v[8], f9 = f->v[9];
  uint32_t g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4], g5 = g->v[5], g6 = g->v[6],
           g7 = g->v[7], g8 = g->v[8], g9 = g->v[9];
  uint32_t f2_1 = 2u * f1, f2_3 = 2u * f3, f2_5 = 2u * f5, f2_7 = 2u * f7, f2_9 = 2u * f9;
  uint32_t g19_1 = 19u * g1, g19_2 = 19u * g2, g19_3 = 19u * g3, g19_4 = 19u * g4, g19_5 = 19u * g5, g19_6 =
           19u * g6, g19_7 = 19u * g7, g19_8 = 19u * g8, g19_9 = 19u * g9;
  uint64_t t[10];
  t[0] = SD_MUL32(f0, g0)
         + SD_MUL32(f2_1, g19_9)
         + SD_MUL32(f2, g19_8)
         + SD_MUL32(f2_3, g19_7)
         + SD_MUL32(f4, g19_6)
         + SD_MUL32(f2_5, g19_5)
         + SD_MUL32(f6, g19_4)
         + SD_MUL32(f2_7, g19_3)
         + SD_MUL32(f8, g19_2)
         + SD_MUL32(f2_9, g19_1);
  t[1] = SD_MUL32(f0, g1)
         + SD_MUL32(f1, g0)
         + SD_MUL32(f2, g19_9)
         + SD_MUL32(f3, g19_8)
         + SD_MUL32(f4, g19_7)
         + SD_MUL32(f5, g19_6)
         + SD_MUL32(f6, g19_5)
         + SD_MUL32(f7, g19_4)
         + SD_MUL32(f8, g19_3)
         + SD_MUL32(f9, g19_2);
  t[2] = SD_MUL32(f0, g2)
         + SD_MUL32(f2_1, g1)
         + SD_MUL32(f2, g0)
         + SD_MUL32(f2_3, g19_9)
         + SD_MUL32(f4, g19_8)
         + SD_MUL32(f2_5, g19_7)
         + SD_MUL32(f6, g19_6)
         + SD_MUL32(f2_7, g19_5)
         + SD_MUL32(f8, g19_4)
         + SD_MUL32(f2_9, g19_3);
  t[3] = SD_MUL32(f0, g3)
         + SD_MUL32(f1, g2)
         + SD_MUL32(f2, g1)
         + SD_MUL32(f3, g0)
         + SD_MUL32(f4, g19_9)
         + SD_MUL32(f5, g19_8)
         + SD_MUL32(f6, g19_7)
         + SD_MUL32(f7, g19_6)
         + SD_MUL32(f8, g19_5)
         + SD_MUL32(f9, g19_4);
  t[4] = SD_MUL32(f0, g4)
         + SD_MUL32(f2_1, g3)
         + SD_MUL32(f2, g2)
         + SD_MUL32(f2_3, g1)
         + SD_MUL32(f4, g0)
         + SD_MUL32(f2_5, g19_9)
         + SD_MUL32(f6, g19_8)
         + SD_MUL32(f2_7, g19_7)
         + SD_MUL32(f8, g19_6)
         + SD_MUL32(f2_9, g19_5);
  t[5] = SD_MUL32(f0, g5)
         + SD_MUL32(f1, g4)
         + SD_MUL32(f2, g3)
         + SD_MUL32(f3, g2)
         + SD_MUL32(f4, g1)
         + SD_MUL32(f5, g0)
         + SD_MUL32(f6, g19_9)
         + SD_MUL32(f7, g19_8)
         + SD_MUL32(f8, g19_7)
         + SD_MUL32(f9, g19_6);
  t[6] = SD_MUL32(f0, g6)
         + SD_MUL32(f2_1, g5)
         + SD_MUL32(f2, g4)
         + SD_MUL32(f2_3, g3)
         + SD_MUL32(f4, g2)
         + SD_MUL32(f2_5, g1)
         + SD_MUL32(f6, g0)
         + SD_MUL32(f2_7, g19_9)
         + SD_MUL32(f8, g19_8)
         + SD_MUL32(f2_9, g19_7);
  t[7] = SD_MUL32(f0, g7)
         + SD_MUL32(f1, g6)
         + SD_MUL32(f2, g5)
         + SD_MUL32(f3, g4)
         + SD_MUL32(f4, g3)
         + SD_MUL32(f5, g2)
         + SD_MUL32(f6, g1)
         + SD_MUL32(f7, g0)
         + SD_MUL32(f8, g19_9)
         + SD_MUL32(f9, g19_8);
  t[8] = SD_MUL32(f0, g8)
         + SD_MUL32(f2_1, g7)
         + SD_MUL32(f2, g6)
         + SD_MUL32(f2_3, g5)
         + SD_MUL32(f4, g4)
         + SD_MUL32(f2_5, g3)
         + SD_MUL32(f6, g2)
         + SD_MUL32(f2_7, g1)
         + SD_MUL32(f8, g0)
         + SD_MUL32(f2_9, g19_9);
  t[9] = SD_MUL32(f0, g9)
         + SD_MUL32(f1, g8)
         + SD_MUL32(f2, g7)
         + SD_MUL32(f3, g6)
         + SD_MUL32(f4, g5)
         + SD_MUL32(f5, g4)
         + SD_MUL32(f6, g3)
         + SD_MUL32(f7, g2)
         + SD_MUL32(f8, g1)
         + SD_MUL32(f9, g0);
  fe_carry64(h, t);
}

static void fe_sq(fe *h, const fe *f)
{
  fe_mul(h, f, f);
}

static void fe_sqn(fe *h, const fe *f, int n)
{
  fe_sq(h, f);
  while (--n > 0)
    fe_sq(h, h);
}

static void fe_mul_small(fe *h, const fe *f, uint32_t k)    /* k < 2^17 */
{
  uint64_t t[10];
  int i;
  for (i = 0; i < 10; i++)
    t[i] = SD_MUL32(f->v[i], k);
  fe_carry64(h, t);
}

/* z^(2^250 - 1), shared by inversion and the square-root exponent. Also returns z^11. */
static void fe_pow2_250_1(fe *out, fe *z11, const fe *z)
{
  fe z2, z9, t, z_5_0, z_10_0, z_20_0, z_50_0, z_100_0;
  fe_sq(&z2, z);                       /* z^2 */
  fe_sqn(&t, &z2, 2);                  /* z^8 */
  fe_mul(&z9, &t, z);                  /* z^9 */
  fe_mul(z11, &z9, &z2);               /* z^11 */
  fe_sq(&t, z11);                      /* z^22 */
  fe_mul(&z_5_0, &t, &z9);             /* z^(2^5-1) */
  fe_sqn(&t, &z_5_0, 5);
  fe_mul(&z_10_0, &t, &z_5_0);         /* z^(2^10-1) */
  fe_sqn(&t, &z_10_0, 10);
  fe_mul(&z_20_0, &t, &z_10_0);        /* z^(2^20-1) */
  fe_sqn(&t, &z_20_0, 20);
  fe_mul(&t, &t, &z_20_0);             /* z^(2^40-1) */
  fe_sqn(&t, &t, 10);
  fe_mul(&z_50_0, &t, &z_10_0);        /* z^(2^50-1) */
  fe_sqn(&t, &z_50_0, 50);
  fe_mul(&z_100_0, &t, &z_50_0);       /* z^(2^100-1) */
  fe_sqn(&t, &z_100_0, 100);
  fe_mul(&t, &t, &z_100_0);            /* z^(2^200-1) */
  fe_sqn(&t, &t, 50);
  fe_mul(out, &t, &z_50_0);            /* z^(2^250-1) */
}

static void fe_invert(fe *out, const fe *z)        /* z^(p-2) = z^(2^255-21) */
{
  fe t, z11;
  fe_pow2_250_1(&t, &z11, z);
  fe_sqn(&t, &t, 5);
  fe_mul(out, &t, &z11);
}

static void fe_pow22523(fe *out, const fe *z)      /* z^((p-5)/8) = z^(2^252-3) */
{
  fe t, z11;
  fe_pow2_250_1(&t, &z11, z);
  fe_sqn(&t, &t, 2);
  fe_mul(out, &t, z);
}

static void fe_frombytes(fe *h, const uint8_t s[32])        /* ignores bit 255 */
{
  uint32_t w[8];
  int i;
  for (i = 0; i < 8; i++)
    w[i] = sd_load_le32(s + 4 * i);
  h->v[0] = w[0] & M26;
  h->v[1] = ((w[0] >> 26) | (w[1] << 6)) & M25;
  h->v[2] = ((w[1] >> 19) | (w[2] << 13)) & M26;
  h->v[3] = ((w[2] >> 13) | (w[3] << 19)) & M25;
  h->v[4] = (w[3] >> 6) & M26;
  h->v[5] = w[4] & M25;
  h->v[6] = ((w[4] >> 25) | (w[5] << 7)) & M26;
  h->v[7] = ((w[5] >> 19) | (w[6] << 13)) & M25;
  h->v[8] = ((w[6] >> 12) | (w[7] << 20)) & M26;
  h->v[9] = (w[7] >> 6) & M25;
}

static void fe_tobytes(uint8_t s[32], const fe *f)
{
  uint32_t t[10], w[8], q;
  fe h;
  int i;
  memcpy(t, f->v, sizeof(t));
  fe_carry32(&h, t);                   /* value v < 2^255 + 2^27 < 2p, limbs nonnegative */
  memcpy(t, h.v, sizeof(t));
  /* q = floor((v + 19) / 2^255) in {0, 1} by exact carry propagation; then v - q p. */
  q = (t[0] + 19u) >> 26;
  q = (t[1] + q) >> 25; q = (t[2] + q) >> 26; q = (t[3] + q) >> 25; q = (t[4] + q) >> 26;
  q = (t[5] + q) >> 25; q = (t[6] + q) >> 26; q = (t[7] + q) >> 25; q = (t[8] + q) >> 26;
  q = (t[9] + q) >> 25;
  t[0] += 19u * q;
  for (i = 0; i < 9; i++) {
    uint32_t bits = (i & 1) ? 25u : 26u;
    t[i + 1] += t[i] >> bits;
    t[i] &= (1u << bits) - 1u;
  }
  t[9] &= M25;                         /* drops q * 2^255 */
  w[0] = t[0] | (t[1] << 26);
  w[1] = (t[1] >> 6) | (t[2] << 19);
  w[2] = (t[2] >> 13) | (t[3] << 13);
  w[3] = (t[3] >> 19) | (t[4] << 6);
  w[4] = t[5] | (t[6] << 25);
  w[5] = (t[6] >> 7) | (t[7] << 19);
  w[6] = (t[7] >> 13) | (t[8] << 12);
  w[7] = (t[8] >> 20) | (t[9] << 6);
  for (i = 0; i < 8; i++)
    sd_store_le32(s + 4 * i, w[i]);
  sd_secure_zero(t, sizeof(t));
  sd_secure_zero(&h, sizeof(h));
}

static uint32_t fe_isnonzero_mask(const fe *f)
{
  uint8_t s[32];
  uint32_t acc = 0;
  int i;
  fe_tobytes(s, f);
  for (i = 0; i < 32; i++)
    acc |= s[i];
  return ~sd_ct_is_zero_u32(acc);
}

static int fe_isneg(const fe *f)
{
  uint8_t s[32];
  fe_tobytes(s, f);
  return s[0] & 1;
}

static void fe_cmov(fe *f, const fe *g, uint32_t mask)
{
  int i;
  for (i = 0; i < 10; i++)
    f->v[i] = sd_ct_select_u32(mask, g->v[i], f->v[i]);
}

/* ---- constants, computed once from their definitions ---- */

typedef struct ge { fe X, Y, Z, T; } ge;

static sd_once g_const_once = SD_ONCE_INIT;
static fe g_d, g_d2, g_sqrtm1;
static ge g_base;
static int ge_frombytes(ge *p, const uint8_t s[32]);

static void consts_init(void *arg)
{
  fe a, b;
  static const uint8_t base_enc[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
  };
  int i;
  SD_UNUSED(arg);
  /* d = -121665 / 121666 */
  fe_0(&a); a.v[0] = 121665;
  fe_neg(&a, &a);
  fe_0(&b); b.v[0] = 121666;
  fe_invert(&b, &b);
  fe_mul(&g_d, &a, &b);
  fe_add(&g_d2, &g_d, &g_d);
  /* sqrt(-1) = 2^((p-1)/4); 2 is a non-residue since p = 5 mod 8. (p-1)/4 = 2^253 - 5. */
  fe_0(&a); a.v[0] = 2;
  fe_pow22523(&b, &a);                 /* 2^(2^252-3) */
  fe_sq(&b, &b);                       /* 2^(2^253-6) */
  fe_mul(&g_sqrtm1, &b, &a);           /* 2^(2^253-5) */
  /* Base point B: y = 4/5, x even (RFC 8032 §5.1). */
  i = ge_frombytes(&g_base, base_enc);
  SD_UNUSED(i);
}

static void consts(void)
{
  sd_once_run(&g_const_once, consts_init, NULL);
}

/* ---- X25519 (RFC 7748 §5) ---- */

static void x25519_ladder(uint8_t out[32], const uint8_t k[32], const uint8_t u[32])
{
  fe x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t;
  uint32_t swap = 0;
  int pos;
  fe_frombytes(&x1, u);
  fe_1(&x2); fe_0(&z2);
  x3 = x1; fe_1(&z3);
  for (pos = 254; pos >= 0; pos--) {
    uint32_t bit = (k[pos >> 3] >> (pos & 7)) & 1u;
    swap ^= bit;
    sd_ct_cswap_u32(swap, x2.v, x3.v, 10);
    sd_ct_cswap_u32(swap, z2.v, z3.v, 10);
    swap = bit;
    fe_add(&a, &x2, &z2);
    fe_sq(&aa, &a);
    fe_sub(&b, &x2, &z2);
    fe_sq(&bb, &b);
    fe_sub(&e, &aa, &bb);
    fe_add(&c, &x3, &z3);
    fe_sub(&d, &x3, &z3);
    fe_mul(&da, &d, &a);
    fe_mul(&cb, &c, &b);
    fe_add(&t, &da, &cb);
    fe_sq(&x3, &t);
    fe_sub(&t, &da, &cb);
    fe_sq(&t, &t);
    fe_mul(&z3, &x1, &t);
    fe_mul(&x2, &aa, &bb);
    fe_mul_small(&t, &e, 121665);
    fe_add(&t, &aa, &t);
    fe_mul(&z2, &e, &t);
  }
  sd_ct_cswap_u32(swap, x2.v, x3.v, 10);
  sd_ct_cswap_u32(swap, z2.v, z3.v, 10);
  fe_invert(&z2, &z2);
  fe_mul(&x2, &x2, &z2);
  fe_tobytes(out, &x2);
  sd_secure_zero(&x2, sizeof(x2)); sd_secure_zero(&z2, sizeof(z2));
  sd_secure_zero(&x3, sizeof(x3)); sd_secure_zero(&z3, sizeof(z3));
  sd_secure_zero(&a, sizeof(a)); sd_secure_zero(&aa, sizeof(aa));
  sd_secure_zero(&b, sizeof(b)); sd_secure_zero(&bb, sizeof(bb));
  sd_secure_zero(&e, sizeof(e)); sd_secure_zero(&c, sizeof(c));
  sd_secure_zero(&d, sizeof(d)); sd_secure_zero(&da, sizeof(da));
  sd_secure_zero(&cb, sizeof(cb)); sd_secure_zero(&t, sizeof(t));
}

sd_err sd_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
  uint8_t k[32];
  uint32_t acc = 0;
  int i;
  if (out == NULL || scalar == NULL || point == NULL)
    return SD_E_INVALID_PARAM;
  memcpy(k, scalar, 32);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  x25519_ladder(out, k, point);
  sd_secure_zero(k, sizeof(k));
  for (i = 0; i < 32; i++)
    acc |= out[i];
  /* All-zero output (small-order peer point) is rejected (RFC 7748 §6.1, RFC 8731). */
  return (sd_ct_is_zero_u32(acc) & 1u) ? SD_E_CRYPTO : SD_OK;
}

sd_err sd_x25519_base(uint8_t pub[32], const uint8_t scalar[32])
{
  static const uint8_t nine[32] = { 9 };
  return sd_x25519(pub, scalar, nine);
}

/* ---- Edwards group (a = -1, extended coordinates) ---- */

static void ge_identity(ge *p)
{
  fe_0(&p->X); fe_1(&p->Y); fe_1(&p->Z); fe_0(&p->T);
}

static void ge_add(ge *r, const ge *p, const ge *q)
{
  fe a, b, c, d, e, f, g, h, t;
  fe_sub(&a, &p->Y, &p->X);
  fe_sub(&t, &q->Y, &q->X);
  fe_mul(&a, &a, &t);
  fe_add(&b, &p->Y, &p->X);
  fe_add(&t, &q->Y, &q->X);
  fe_mul(&b, &b, &t);
  fe_mul(&c, &p->T, &q->T);
  fe_mul(&c, &c, &g_d2);
  fe_mul(&d, &p->Z, &q->Z);
  fe_add(&d, &d, &d);
  fe_sub(&e, &b, &a);
  fe_sub(&f, &d, &c);
  fe_add(&g, &d, &c);
  fe_add(&h, &b, &a);
  fe_mul(&r->X, &e, &f);
  fe_mul(&r->Y, &g, &h);
  fe_mul(&r->T, &e, &h);
  fe_mul(&r->Z, &f, &g);
}

static void ge_dbl(ge *r, const ge *p)
{
  fe a, b, c, e, g, f, h, t;
  fe_sq(&a, &p->X);
  fe_sq(&b, &p->Y);
  fe_sq(&c, &p->Z);
  fe_add(&c, &c, &c);
  fe_add(&t, &p->X, &p->Y);
  fe_sq(&t, &t);
  fe_sub(&e, &t, &a);
  fe_sub(&e, &e, &b);                  /* E = (X+Y)^2 - A - B */
  fe_sub(&g, &b, &a);                  /* G = D + B with D = -A */
  fe_sub(&f, &g, &c);                  /* F = G - C */
  fe_add(&h, &a, &b);
  fe_neg(&h, &h);                      /* H = D - B = -A - B */
  fe_mul(&r->X, &e, &f);
  fe_mul(&r->Y, &g, &h);
  fe_mul(&r->T, &e, &h);
  fe_mul(&r->Z, &f, &g);
}

static void ge_cmov(ge *p, const ge *q, uint32_t mask)
{
  fe_cmov(&p->X, &q->X, mask);
  fe_cmov(&p->Y, &q->Y, mask);
  fe_cmov(&p->Z, &q->Z, mask);
  fe_cmov(&p->T, &q->T, mask);
}

/* r = [s]P with a fixed 4-bit window; every table lookup scans all 16 entries by mask. */
static void ge_scalarmult(ge *r, const ge *p, const uint8_t s[32])
{
  ge table[16], sel, acc;
  int i, j;
  ge_identity(&table[0]);
  table[1] = *p;
  for (i = 2; i < 16; i++)
    ge_add(&table[i], &table[i - 1], p);
  ge_identity(&acc);
  for (i = 63; i >= 0; i--) {
    uint32_t nib = (uint32_t)(s[i >> 1] >> ((i & 1) * 4)) & 15u;
    ge_dbl(&acc, &acc);
    ge_dbl(&acc, &acc);
    ge_dbl(&acc, &acc);
    ge_dbl(&acc, &acc);
    ge_identity(&sel);
    for (j = 0; j < 16; j++)
      ge_cmov(&sel, &table[j], sd_ct_eq_u32((uint32_t)j, nib));
    ge_add(&acc, &acc, &sel);
  }
  *r = acc;
  sd_secure_zero(table, sizeof(table));
  sd_secure_zero(&sel, sizeof(sel));
  sd_secure_zero(&acc, sizeof(acc));
}

static void ge_tobytes(uint8_t s[32], const ge *p)
{
  fe zi, x, y;
  fe_invert(&zi, &p->Z);
  fe_mul(&x, &p->X, &zi);
  fe_mul(&y, &p->Y, &zi);
  fe_tobytes(s, &y);
  s[31] = (uint8_t)(s[31] ^ (fe_isneg(&x) << 7));
}

/* RFC 8032 §5.1.3 with strict checks: y < p, a square root exists, x = 0 needs sign bit 0.
   Public data only. Returns 0 on success. */
static int ge_frombytes(ge *p, const uint8_t s[32])
{
  uint8_t chk[32];
  fe u, v, v3, x, vxx, t;
  int sign = s[31] >> 7;
  fe_frombytes(&p->Y, s);
  fe_tobytes(chk, &p->Y);
  if (memcmp(chk, s, 31) != 0 || chk[31] != (s[31] & 0x7f))
    return -1;                                         /* y >= p */
  fe_1(&p->Z);
  fe_sq(&u, &p->Y);
  fe_mul(&v, &u, &g_d);
  fe_sub(&u, &u, &p->Z);                               /* u = y^2 - 1 */
  fe_add(&v, &v, &p->Z);                               /* v = d y^2 + 1 */
  fe_sq(&v3, &v);
  fe_mul(&v3, &v3, &v);                                /* v^3 */
  fe_sq(&x, &v3);
  fe_mul(&x, &x, &v);
  fe_mul(&x, &x, &u);                                  /* u v^7 */
  fe_pow22523(&x, &x);
  fe_mul(&x, &x, &v3);
  fe_mul(&x, &x, &u);                                  /* u v^3 (u v^7)^((p-5)/8) */
  fe_sq(&vxx, &x);
  fe_mul(&vxx, &vxx, &v);
  fe_sub(&t, &vxx, &u);
  if (fe_isnonzero_mask(&t)) {
    fe_add(&t, &vxx, &u);
    if (fe_isnonzero_mask(&t))
      return -1;                                       /* no square root */
    fe_mul(&x, &x, &g_sqrtm1);
  }
  if (!fe_isnonzero_mask(&x) && sign)
    return -1;
  if (fe_isneg(&x) != sign)
    fe_neg(&x, &x);
  p->X = x;
  fe_mul(&p->T, &p->X, &p->Y);
  return 0;
}

/* ---- scalars mod L = 2^252 + 27742317777372353535851937790883648493 ---- */

static const uint32_t k_L[8] = {
  0x5cf5d3edu, 0x5812631au, 0xa2f79cd6u, 0x14def9deu, 0, 0, 0, 0x10000000u
};

/* out = in mod L for an n-byte little-endian input, bit-serial (512 fixed steps for n = 64). */
static void sc_reduce(uint8_t out[32], const uint8_t *in, size_t n)
{
  uint32_t r[8], t[8];
  size_t bitpos;
  int i;
  memset(r, 0, sizeof(r));
  for (bitpos = n * 8; bitpos-- > 0;) {
    uint32_t bit = (in[bitpos >> 3] >> (bitpos & 7)) & 1u, borrow = 0, keep;
    for (i = 7; i > 0; i--)
      r[i] = (r[i] << 1) | (r[i - 1] >> 31);
    r[0] = (r[0] << 1) | bit;
    for (i = 0; i < 8; i++) {
      uint64_t d = (uint64_t)r[i] - k_L[i] - borrow;
      t[i] = (uint32_t)d;
      borrow = (uint32_t)(d >> 32) & 1u;
    }
    keep = 0u - borrow;                                /* r < L: keep r */
    for (i = 0; i < 8; i++)
      r[i] = sd_ct_select_u32(keep, r[i], t[i]);
  }
  for (i = 0; i < 8; i++)
    sd_store_le32(out + 4 * i, r[i]);
  sd_secure_zero(r, sizeof(r));
  sd_secure_zero(t, sizeof(t));
}

/* s = (a * b + c) mod L; a, b, c are 32-byte little-endian. */
static void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
  uint32_t x[8], y[8], prod[16];
  uint8_t wide[64];
  uint64_t carry;
  int i, j;
  for (i = 0; i < 8; i++) {
    x[i] = sd_load_le32(a + 4 * i);
    y[i] = sd_load_le32(b + 4 * i);
  }
  memset(prod, 0, sizeof(prod));
  for (i = 0; i < 8; i++) {
    carry = 0;
    for (j = 0; j < 8; j++) {
      uint64_t t = (uint64_t)prod[i + j] + SD_MUL32(x[i], y[j]) + carry;
      prod[i + j] = (uint32_t)t;
      carry = t >> 32;
    }
    prod[i + 8] = (uint32_t)carry;
  }
  carry = 0;
  for (i = 0; i < 16; i++) {
    uint64_t t = (uint64_t)prod[i] + (i < 8 ? sd_load_le32(c + 4 * i) : 0) + carry;
    prod[i] = (uint32_t)t;
    carry = t >> 32;
  }
  for (i = 0; i < 16; i++)
    sd_store_le32(wide + 4 * i, prod[i]);
  sc_reduce(s, wide, 64);
  sd_secure_zero(x, sizeof(x));
  sd_secure_zero(y, sizeof(y));
  sd_secure_zero(prod, sizeof(prod));
  sd_secure_zero(wide, sizeof(wide));
}

static int sc_is_canonical(const uint8_t s[32])      /* public: S < L */
{
  int i;
  for (i = 7; i >= 0; i--) {
    uint32_t w = sd_load_le32(s + 4 * i);
    if (w < k_L[i]) return 1;
    if (w > k_L[i]) return 0;
  }
  return 0;
}

/* ---- Ed25519 (RFC 8032 §5.1.5-5.1.7) ---- */

static void ed25519_expand(uint8_t az[64], const uint8_t seed[32])
{
  sd_hash(SD_HASH_SHA512, seed, 32, az);
  az[0] &= 248;
  az[31] &= 127;
  az[31] |= 64;
}

sd_err sd_ed25519_pub_from_seed(uint8_t pub[32], const uint8_t seed[32])
{
  uint8_t az[64];
  ge a;
  if (pub == NULL || seed == NULL)
    return SD_E_INVALID_PARAM;
  consts();
  ed25519_expand(az, seed);
  ge_scalarmult(&a, &g_base, az);
  ge_tobytes(pub, &a);
  sd_secure_zero(az, sizeof(az));
  sd_secure_zero(&a, sizeof(a));
  return SD_OK;
}

sd_err sd_ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t pub[32],
                       const void *m, size_t n)
{
  uint8_t az[64], a_enc[32], nonce[64], r[32], hram[64], k[32];
  sd_hash_ctx h;
  ge p;
  sd_err err = SD_OK;
  if (sig == NULL || seed == NULL || (n && m == NULL))
    return SD_E_INVALID_PARAM;
  consts();
  ed25519_expand(az, seed);
  ge_scalarmult(&p, &g_base, az);
  ge_tobytes(a_enc, &p);
  /* A public key that does not belong to the seed would turn signatures into a key-recovery oracle,
     so the caller's copy is checked, not trusted. */
  if (pub != NULL && !sd_ct_memeq(pub, a_enc, 32)) {
    err = SD_E_INVALID_PARAM;
    goto out;
  }
  sd_hash_init(&h, SD_HASH_SHA512);
  sd_hash_update(&h, az + 32, 32);
  sd_hash_update(&h, m, n);
  sd_hash_final(&h, nonce);
  sc_reduce(r, nonce, 64);
  ge_scalarmult(&p, &g_base, r);
  ge_tobytes(sig, &p);
  sd_hash_init(&h, SD_HASH_SHA512);
  sd_hash_update(&h, sig, 32);
  sd_hash_update(&h, a_enc, 32);
  sd_hash_update(&h, m, n);
  sd_hash_final(&h, hram);
  sc_reduce(k, hram, 64);
  sc_muladd(sig + 32, k, az, r);
out:
  sd_secure_zero(az, sizeof(az));
  sd_secure_zero(nonce, sizeof(nonce));
  sd_secure_zero(r, sizeof(r));
  sd_secure_zero(&p, sizeof(p));
  sd_secure_zero(&h, sizeof(h));
  return err;
}

sd_err sd_ed25519_verify(const uint8_t sig[64], const uint8_t pub[32], const void *m, size_t n)
{
  uint8_t hram[64], k[32], chk[32];
  sd_hash_ctx h;
  ge a, sb, ka;
  if (sig == NULL || pub == NULL || (n && m == NULL))
    return SD_E_INVALID_PARAM;
  consts();
  if (!sc_is_canonical(sig + 32))
    return SD_E_CRYPTO;                                /* malleability: S >= L */
  if (ge_frombytes(&a, pub) != 0)
    return SD_E_CRYPTO;
  sd_hash_init(&h, SD_HASH_SHA512);
  sd_hash_update(&h, sig, 32);
  sd_hash_update(&h, pub, 32);
  sd_hash_update(&h, m, n);
  sd_hash_final(&h, hram);
  sc_reduce(k, hram, 64);
  /* R' = [S]B - [k]A, compared by encoding with R (cofactorless, as OpenSSH). A non-canonical R can
     never match because ge_tobytes is canonical. */
  fe_neg(&a.X, &a.X);
  fe_neg(&a.T, &a.T);
  ge_scalarmult(&sb, &g_base, sig + 32);
  ge_scalarmult(&ka, &a, k);
  ge_add(&sb, &sb, &ka);
  ge_tobytes(chk, &sb);
  return memcmp(chk, sig, 32) == 0 ? SD_OK : SD_E_CRYPTO;
}
