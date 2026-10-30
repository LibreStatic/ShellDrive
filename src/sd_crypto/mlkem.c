/* ML-KEM-768 (FIPS 203), written from the standard (01 §2.8.4, decisions.md D15).
 *
 * Parameters: n = 256, q = 3329, k = 3, eta1 = eta2 = 2, du = 10, dv = 4.
 * Polynomials hold int16 coefficients. Multiplication in the NTT domain uses Montgomery reduction
 * (R = 2^16) and Barrett reduction, both in 32-bit arithmetic; no division and no secret-dependent
 * branch or index anywhere on secret data. Compression divides by q through a 32x32->64 multiply by
 * ceil(2^35 / q) (exact for every input below 2^24; checked exhaustively when the constant was chosen).
 * The tables below are 17^BitRev7(i) * R mod q (NTT) and 17^(2 BitRev7(i) + 1) * R mod q (base-case
 * products), centered; they were computed with a few lines of Python from the definitions in FIPS 203
 * section 4.3.
 * Matrix sampling (SampleNTT, rejection on public rho) is variable time, as the standard allows.
 * Decapsulation re-encrypts, compares the ciphertexts in constant time and selects between K' and
 * the implicit-rejection key J(z || c) with a mask. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"

#define MLKEM_N   256
#define MLKEM_Q   3329
#define MLKEM_K   3
#define POLYBYTES 384                    /* ByteEncode12 */
#define PKE_PK    (MLKEM_K * POLYBYTES + 32)
#define PKE_SK    (MLKEM_K * POLYBYTES)
#define C1_BYTES  (MLKEM_K * 320)        /* du = 10 */
#define C2_BYTES  128                    /* dv = 4 */
#define QINV      (-3327)                /* q^-1 mod 2^16 */

SD_STATIC_ASSERT(PKE_PK == SD_MLKEM768_PK_LEN, "ek size");
SD_STATIC_ASSERT(PKE_SK + PKE_PK + 64 == SD_MLKEM768_SK_LEN, "dk size");
SD_STATIC_ASSERT(C1_BYTES + C2_BYTES == SD_MLKEM768_CT_LEN, "ct size");

typedef struct poly { int16_t c[MLKEM_N]; } poly;
typedef struct polyvec { poly v[MLKEM_K]; } polyvec;

static const int16_t k_zetas[128] = {
  -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
  573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
  1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
  -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
  -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653,
  -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75,
  817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
  -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
};

static const int16_t k_gammas[128] = {
  -1103, 1103, 430, -430, 555, -555, 843, -843, -1251, 1251, 871, -871, 1550, -1550, 105, -105,
  422, -422, 587, -587, 177, -177, -235, 235, -291, 291, -460, 460, 1574, -1574, 1653, -1653,
  -246, 246, 778, -778, 1159, -1159, -147, 147, -777, 777, 1483, -1483, -602, 602, 1119, -1119,
  -1590, 1590, 644, -644, -872, 872, 349, -349, 418, -418, 329, -329, -156, 156, -75, 75,
  817, -817, 1097, -1097, 603, -603, 610, -610, 1322, -1322, -1285, 1285, -1465, 1465, 384, -384,
  -1215, 1215, -136, 136, 1218, -1218, -1335, 1335, -874, 874, 220, -220, -1187, 1187, -1659, 1659,
  -1185, 1185, -1530, 1530, -1278, 1278, 794, -794, -1510, 1510, -854, 854, -870, 870, 478, -478,
  -108, 108, -308, 308, 996, -996, 991, -991, 958, -958, -1460, 1460, 1522, -1522, 1628, -1628,
};

/* ---- modular arithmetic ---- */

/* a * R^-1 mod q, in (-q, q), for |a| < q * 2^15. */
static SD_FORCEINLINE int16_t mont_reduce(int32_t a)
{
  int16_t t = (int16_t)((int16_t)a * QINV);
  return (int16_t)((a - (int32_t)t * MLKEM_Q) >> 16);
}

static SD_FORCEINLINE int16_t fqmul(int16_t a, int16_t b)
{
  return mont_reduce((int32_t)a * b);
}

/* Centered representative of a mod q, |result| <= q/2. */
static SD_FORCEINLINE int16_t barrett_reduce(int16_t a)
{
  const int32_t v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;   /* 20159, compile-time constant */
  int16_t t = (int16_t)((v * a + (1 << 25)) >> 26);
  return (int16_t)(a - t * MLKEM_Q);
}

/* Representative in [0, q). */
static SD_FORCEINLINE int16_t freeze(int16_t a)
{
  a = barrett_reduce(a);
  return (int16_t)(a + ((a >> 15) & MLKEM_Q));
}

/* ---- NTT (FIPS 203 Algorithms 9-12) ---- */

static void poly_ntt(poly *p)
{
  int16_t *f = p->c;
  unsigned len, start, j, i = 1;
  for (len = 128; len >= 2; len >>= 1) {
    for (start = 0; start < MLKEM_N; start += 2 * len) {
      int16_t zeta = k_zetas[i++];
      for (j = start; j < start + len; j++) {
        int16_t t = fqmul(zeta, f[j + len]);
        f[j + len] = (int16_t)(f[j] - t);
        f[j] = (int16_t)(f[j] + t);
      }
    }
  }
  for (j = 0; j < MLKEM_N; j++)
    f[j] = barrett_reduce(f[j]);
}

/* Inverse NTT. Expects inputs carrying a factor R^-1 (base-case products); the final scaling by
   128^-1 * R^2 (= 1441) removes it. */
static void poly_invntt(poly *p)
{
  int16_t *f = p->c;
  unsigned len, start, j, i = 127;
  for (len = 2; len <= 128; len <<= 1) {
    for (start = 0; start < MLKEM_N; start += 2 * len) {
      int16_t zeta = k_zetas[i--];
      for (j = start; j < start + len; j++) {
        int16_t t = f[j];
        f[j] = barrett_reduce((int16_t)(t + f[j + len]));
        f[j + len] = fqmul(zeta, (int16_t)(f[j + len] - t));
      }
    }
  }
  for (j = 0; j < MLKEM_N; j++)
    f[j] = fqmul(f[j], 1441);
}

/* r += a o b (MultiplyNTTs), result carries a factor R^-1. */
static void poly_basemul_acc(poly *r, const poly *a, const poly *b)
{
  unsigned i;
  for (i = 0; i < 128; i++) {
    int16_t a0 = a->c[2 * i], a1 = a->c[2 * i + 1], b0 = b->c[2 * i], b1 = b->c[2 * i + 1];
    int16_t c0 = (int16_t)(fqmul(fqmul(a1, b1), k_gammas[i]) + fqmul(a0, b0));
    int16_t c1 = (int16_t)(fqmul(a0, b1) + fqmul(a1, b0));
    r->c[2 * i] = barrett_reduce((int16_t)(r->c[2 * i] + c0));
    r->c[2 * i + 1] = barrett_reduce((int16_t)(r->c[2 * i + 1] + c1));
  }
}

static void poly_add(poly *r, const poly *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
    r->c[i] = barrett_reduce((int16_t)(r->c[i] + a->c[i]));
}

static void poly_sub_from(poly *r, const poly *a)       /* r = a - r */
{
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
    r->c[i] = barrett_reduce((int16_t)(a->c[i] - r->c[i]));
}

/* x -> x * R mod q (undoes the R^-1 of a base-case product). */
static void poly_tomont(poly *r)
{
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
    r->c[i] = fqmul(r->c[i], 1353);   /* R^2 mod q */
}

/* ---- sampling (Algorithms 7 and 8) ---- */

/* SampleNTT(rho || x || y): rejection sampling from SHAKE128 on public data. */
static void poly_sample_ntt(poly *p, const uint8_t rho[32], uint8_t x, uint8_t y)
{
  sd_keccak_ctx xof;
  uint8_t seed[34], buf[168];
  unsigned n = 0, i;
  memcpy(seed, rho, 32);
  seed[32] = x;
  seed[33] = y;
  sd_shake_init(&xof, 128);
  sd_shake_absorb(&xof, seed, sizeof(seed));
  while (n < MLKEM_N) {
    sd_shake_squeeze(&xof, buf, sizeof(buf));
    for (i = 0; i + 3 <= sizeof(buf) && n < MLKEM_N; i += 3) {
      uint16_t d1 = (uint16_t)(buf[i] | ((buf[i + 1] & 0x0f) << 8));
      uint16_t d2 = (uint16_t)((buf[i + 1] >> 4) | (buf[i + 2] << 4));
      if (d1 < MLKEM_Q)
        p->c[n++] = (int16_t)d1;
      if (d2 < MLKEM_Q && n < MLKEM_N)
        p->c[n++] = (int16_t)d2;
    }
  }
  sd_keccak_wipe(&xof);
}

/* SamplePolyCBD_2(PRF_2(s, nonce)), constant time. */
static void poly_sample_cbd2(poly *p, const uint8_t s[32], uint8_t nonce)
{
  uint8_t in[33], buf[128];
  unsigned i, j;
  memcpy(in, s, 32);
  in[32] = nonce;
  sd_shake(256, buf, sizeof(buf), in, sizeof(in));
  for (i = 0; i < 32; i++) {
    uint32_t t = sd_load_le32(buf + 4 * i);
    uint32_t d = (t & 0x55555555u) + ((t >> 1) & 0x55555555u);
    for (j = 0; j < 8; j++) {
      int16_t a = (int16_t)((d >> (4 * j)) & 3), b = (int16_t)((d >> (4 * j + 2)) & 3);
      p->c[8 * i + j] = (int16_t)(a - b);
    }
  }
  sd_secure_zero(buf, sizeof(buf));
  sd_secure_zero(in, sizeof(in));
}

/* ---- encodings (Algorithms 5 and 6, compression of section 4.2.1) ---- */

static void poly_tobytes(uint8_t r[POLYBYTES], const poly *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++) {
    uint16_t t0 = (uint16_t)freeze(a->c[2 * i]), t1 = (uint16_t)freeze(a->c[2 * i + 1]);
    r[3 * i] = (uint8_t)t0;
    r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
    r[3 * i + 2] = (uint8_t)(t1 >> 4);
  }
}

/* ByteDecode12 followed by reduction mod q (values up to 4095, one conditional subtraction). */
static void poly_frombytes(poly *r, const uint8_t a[POLYBYTES])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++) {
    int16_t t0 = (int16_t)(a[3 * i] | ((a[3 * i + 1] & 0x0f) << 8));
    int16_t t1 = (int16_t)((a[3 * i + 1] >> 4) | (a[3 * i + 2] << 4));
    t0 = (int16_t)(t0 - MLKEM_Q);
    t1 = (int16_t)(t1 - MLKEM_Q);
    r->c[2 * i] = (int16_t)(t0 + ((t0 >> 15) & MLKEM_Q));
    r->c[2 * i + 1] = (int16_t)(t1 + ((t1 >> 15) & MLKEM_Q));
  }
}

/* Compress_d(x) for x in [0, q): round(2^d x / q) mod 2^d. */
static SD_FORCEINLINE uint32_t compress(int16_t x, unsigned d)
{
  uint32_t a = ((uint32_t)(uint16_t)x << d) + (MLKEM_Q - 1) / 2;
  return (uint32_t)(SD_MUL32(a, 10321340u) >> 35) & ((1u << d) - 1u);
}

static SD_FORCEINLINE int16_t decompress(uint32_t y, unsigned d)
{
  return (int16_t)((y * MLKEM_Q + (1u << (d - 1))) >> d);
}

static void poly_compress10(uint8_t r[320], const poly *a)
{
  unsigned i, j;
  for (i = 0; i < MLKEM_N / 4; i++) {
    uint32_t t[4];
    for (j = 0; j < 4; j++)
      t[j] = compress(freeze(a->c[4 * i + j]), 10);
    r[5 * i + 0] = (uint8_t)t[0];
    r[5 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
    r[5 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
    r[5 * i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
    r[5 * i + 4] = (uint8_t)(t[3] >> 2);
  }
}

static void poly_decompress10(poly *r, const uint8_t a[320])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 4; i++) {
    const uint8_t *b = a + 5 * i;
    r->c[4 * i + 0] = decompress((b[0] | ((uint32_t)b[1] << 8)) & 0x3ff, 10);
    r->c[4 * i + 1] = decompress(((b[1] >> 2) | ((uint32_t)b[2] << 6)) & 0x3ff, 10);
    r->c[4 * i + 2] = decompress(((b[2] >> 4) | ((uint32_t)b[3] << 4)) & 0x3ff, 10);
    r->c[4 * i + 3] = decompress(((b[3] >> 6) | ((uint32_t)b[4] << 2)) & 0x3ff, 10);
  }
}

static void poly_compress4(uint8_t r[128], const poly *a)
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++)
    r[i] = (uint8_t)(compress(freeze(a->c[2 * i]), 4) | (compress(freeze(a->c[2 * i + 1]), 4) << 4));
}

static void poly_decompress4(poly *r, const uint8_t a[128])
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 2; i++) {
    r->c[2 * i] = decompress(a[i] & 15u, 4);
    r->c[2 * i + 1] = decompress((uint32_t)a[i] >> 4, 4);
  }
}

static void poly_frommsg(poly *r, const uint8_t m[32])
{
  unsigned i, j;
  for (i = 0; i < 32; i++)
    for (j = 0; j < 8; j++) {
      uint32_t bit = ((uint32_t)m[i] >> j) & 1u;
      r->c[8 * i + j] = (int16_t)((0u - bit) & ((MLKEM_Q + 1) / 2));   /* Decompress_1 */
    }
}

static void poly_tomsg(uint8_t m[32], const poly *a)
{
  unsigned i, j;
  for (i = 0; i < 32; i++) {
    uint32_t b = 0;
    for (j = 0; j < 8; j++)
      b |= compress(freeze(a->c[8 * i + j]), 1) << j;
    m[i] = (uint8_t)b;
  }
}

/* ---- K-PKE (Algorithms 13-15) ---- */

typedef struct pke_work {
  polyvec s, e, t, y, u;
  poly v, w, tmp;
  uint8_t g_in[33], rs[64];
} pke_work;

static void pke_keygen(pke_work *w, uint8_t ek[PKE_PK], uint8_t dk[PKE_SK], const uint8_t d[32])
{
  const uint8_t *rho = w->rs, *sigma = w->rs + 32;
  unsigned i, j;
  memcpy(w->g_in, d, 32);
  w->g_in[32] = MLKEM_K;
  sd_sha3_512(w->rs, w->g_in, 33);
  for (i = 0; i < MLKEM_K; i++)
    poly_sample_cbd2(&w->s.v[i], sigma, (uint8_t)i);
  for (i = 0; i < MLKEM_K; i++)
    poly_sample_cbd2(&w->e.v[i], sigma, (uint8_t)(MLKEM_K + i));
  for (i = 0; i < MLKEM_K; i++) {
    poly_ntt(&w->s.v[i]);
    poly_ntt(&w->e.v[i]);
  }
  for (i = 0; i < MLKEM_K; i++) {
    memset(&w->t.v[i], 0, sizeof(poly));
    for (j = 0; j < MLKEM_K; j++) {
      poly_sample_ntt(&w->tmp, rho, (uint8_t)j, (uint8_t)i);         /* A[i][j] */
      poly_basemul_acc(&w->t.v[i], &w->tmp, &w->s.v[j]);
    }
    poly_tomont(&w->t.v[i]);
    poly_add(&w->t.v[i], &w->e.v[i]);
  }
  for (i = 0; i < MLKEM_K; i++) {
    poly_tobytes(ek + i * POLYBYTES, &w->t.v[i]);
    poly_tobytes(dk + i * POLYBYTES, &w->s.v[i]);
  }
  memcpy(ek + MLKEM_K * POLYBYTES, rho, 32);
}

static void pke_encrypt(pke_work *w, uint8_t c[SD_MLKEM768_CT_LEN], const uint8_t ek[PKE_PK],
                        const uint8_t m[32], const uint8_t r[32])
{
  const uint8_t *rho = ek + MLKEM_K * POLYBYTES;
  unsigned i, j;
  for (i = 0; i < MLKEM_K; i++)
    poly_frombytes(&w->t.v[i], ek + i * POLYBYTES);
  for (i = 0; i < MLKEM_K; i++)
    poly_sample_cbd2(&w->y.v[i], r, (uint8_t)i);
  for (i = 0; i < MLKEM_K; i++)
    poly_sample_cbd2(&w->e.v[i], r, (uint8_t)(MLKEM_K + i));      /* e1 */
  poly_sample_cbd2(&w->w, r, (uint8_t)(2 * MLKEM_K));              /* e2 */
  for (i = 0; i < MLKEM_K; i++)
    poly_ntt(&w->y.v[i]);
  for (i = 0; i < MLKEM_K; i++) {
    memset(&w->u.v[i], 0, sizeof(poly));
    for (j = 0; j < MLKEM_K; j++) {
      poly_sample_ntt(&w->tmp, rho, (uint8_t)i, (uint8_t)j);         /* A[j][i] = A^T[i][j] */
      poly_basemul_acc(&w->u.v[i], &w->tmp, &w->y.v[j]);
    }
    poly_invntt(&w->u.v[i]);
    poly_add(&w->u.v[i], &w->e.v[i]);
  }
  memset(&w->v, 0, sizeof(poly));
  for (j = 0; j < MLKEM_K; j++)
    poly_basemul_acc(&w->v, &w->t.v[j], &w->y.v[j]);
  poly_invntt(&w->v);
  poly_add(&w->v, &w->w);
  poly_frommsg(&w->tmp, m);
  poly_add(&w->v, &w->tmp);
  for (i = 0; i < MLKEM_K; i++)
    poly_compress10(c + 320 * i, &w->u.v[i]);
  poly_compress4(c + C1_BYTES, &w->v);
}

static void pke_decrypt(pke_work *w, uint8_t m[32], const uint8_t dk[PKE_SK], const uint8_t *c)
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++) {
    poly_decompress10(&w->u.v[i], c + 320 * i);
    poly_ntt(&w->u.v[i]);
    poly_frombytes(&w->s.v[i], dk + i * POLYBYTES);
  }
  poly_decompress4(&w->v, c + C1_BYTES);
  memset(&w->w, 0, sizeof(poly));
  for (i = 0; i < MLKEM_K; i++)
    poly_basemul_acc(&w->w, &w->s.v[i], &w->u.v[i]);
  poly_invntt(&w->w);
  poly_sub_from(&w->w, &w->v);                                     /* w = v - NTT^-1(s^T o NTT(u)) */
  poly_tomsg(m, &w->w);
}

/* ---- ML-KEM (Algorithms 16-18 and the input checks of section 7) ---- */

sd_err sd_mlkem768_check_pk(const uint8_t pk[1184])
{
  unsigned i;
  if (pk == NULL)
    return SD_E_INVALID_PARAM;
  for (i = 0; i < MLKEM_K * POLYBYTES; i += 3) {
    uint32_t t0 = pk[i] | ((uint32_t)(pk[i + 1] & 0x0f) << 8);
    uint32_t t1 = ((uint32_t)pk[i + 1] >> 4) | ((uint32_t)pk[i + 2] << 4);
    if (t0 >= MLKEM_Q || t1 >= MLKEM_Q)
      return SD_E_CRYPTO;
  }
  return SD_OK;
}

sd_err sd_mlkem768_keypair_derand(uint8_t pk[1184], uint8_t sk[2400], const uint8_t d[32], const uint8_t z[32])
{
  pke_work w;
  if (pk == NULL || sk == NULL || d == NULL || z == NULL)
    return SD_E_INVALID_PARAM;
  pke_keygen(&w, pk, sk, d);
  memcpy(sk + PKE_SK, pk, PKE_PK);
  sd_sha3_256(sk + PKE_SK + PKE_PK, pk, PKE_PK);
  memcpy(sk + PKE_SK + PKE_PK + 32, z, 32);
  sd_secure_zero(&w, sizeof(w));
  return SD_OK;
}

sd_err sd_mlkem768_keypair(uint8_t pk[1184], uint8_t sk[2400])
{
  uint8_t seed[64];
  sd_err err;
  if (pk == NULL || sk == NULL)
    return SD_E_INVALID_PARAM;
  if (sd_random(seed, sizeof(seed)) != SD_OK)
    return SD_E_CRYPTO;
  err = sd_mlkem768_keypair_derand(pk, sk, seed, seed + 32);
  sd_secure_zero(seed, sizeof(seed));
  return err;
}

sd_err sd_mlkem768_encaps_derand(uint8_t ct[1088], uint8_t ss[32], const uint8_t pk[1184], const uint8_t m[32])
{
  pke_work w;
  uint8_t g_in[64], kr[64];
  sd_err err;
  if (ct == NULL || ss == NULL || m == NULL)
    return SD_E_INVALID_PARAM;
  err = sd_mlkem768_check_pk(pk);
  if (err != SD_OK)
    return err;
  memcpy(g_in, m, 32);
  sd_sha3_256(g_in + 32, pk, PKE_PK);
  sd_sha3_512(kr, g_in, sizeof(g_in));
  pke_encrypt(&w, ct, pk, m, kr + 32);
  memcpy(ss, kr, 32);
  sd_secure_zero(&w, sizeof(w));
  sd_secure_zero(g_in, sizeof(g_in));
  sd_secure_zero(kr, sizeof(kr));
  return SD_OK;
}

sd_err sd_mlkem768_encaps(uint8_t ct[1088], uint8_t ss[32], const uint8_t pk[1184])
{
  uint8_t m[32];
  sd_err err;
  if (sd_random(m, sizeof(m)) != SD_OK)
    return SD_E_CRYPTO;
  err = sd_mlkem768_encaps_derand(ct, ss, pk, m);
  sd_secure_zero(m, sizeof(m));
  return err;
}

typedef struct decaps_work {
  pke_work w;
  uint8_t g_in[64], kr[64], kbar[32], h[32];
  uint8_t ct2[SD_MLKEM768_CT_LEN];
  sd_keccak_ctx j;
} decaps_work;

sd_err sd_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400])
{
  decaps_work dw, *d = &dw;
  const uint8_t *ek, *h, *z;
  int eq;
  if (ss == NULL || ct == NULL || sk == NULL)
    return SD_E_INVALID_PARAM;
  ek = sk + PKE_SK;
  h = ek + PKE_PK;
  z = h + 32;
  /* Hash check (FIPS 203 7.3): H(ek) must equal the copy stored in dk. Public property of the key. */
  sd_sha3_256(d->h, ek, PKE_PK);
  if (!sd_ct_memeq(d->h, h, 32)) {
    memset(ss, 0, 32);
    sd_secure_zero(&dw, sizeof(dw));
    return SD_E_CRYPTO;
  }
  pke_decrypt(&d->w, d->g_in, sk, ct);                             /* m' */
  memcpy(d->g_in + 32, h, 32);
  sd_sha3_512(d->kr, d->g_in, 64);                                 /* (K', r') = G(m' || h) */
  sd_shake_init(&d->j, 256);                                       /* Kbar = J(z || c) */
  sd_shake_absorb(&d->j, z, 32);
  sd_shake_absorb(&d->j, ct, SD_MLKEM768_CT_LEN);
  sd_shake_squeeze(&d->j, d->kbar, 32);
  pke_encrypt(&d->w, d->ct2, ek, d->g_in, d->kr + 32);             /* c' */
  eq = sd_ct_memeq(ct, d->ct2, SD_MLKEM768_CT_LEN);
  memcpy(ss, d->kr, 32);
  sd_ct_cmov(ss, d->kbar, 32, (uint8_t)(1 - eq));
  sd_secure_zero(&dw, sizeof(dw));
  return SD_OK;
}
