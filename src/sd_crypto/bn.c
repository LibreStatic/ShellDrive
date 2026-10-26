/* Multiprecision arithmetic for RSA, DH and the NIST curves (01 §2.8.2, §2.8.3) and the public sd_bn API.
 *
 * Written from the literature: Montgomery multiplication in the CIOS form (Koc, Acar, Kaliski, "Analyzing
 * and comparing Montgomery multiplication algorithms", IEEE Micro 1996), fixed-window exponentiation
 * (Handbook of Applied Cryptography §14.6), Newton iteration for -m^-1 mod 2^W (Dusse-Kaliski), and the
 * binary extended GCD (Stein; HAC §14.4.3) arranged with a fixed iteration count and masked updates.
 *
 * Constant time (01 §2.4): every sd_mp_* function except the *_vt_* ones has control flow and memory
 * access that depend only on limb counts and public bit lengths. Limb products are _umul128 on x64 and
 * __emulu on x86 (sd_ct64.h); no compiler runtime helper is referenced (TM-R02 gate). */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"

#if SD_LIMB_BITS == 64
#include <intrin.h>
static SD_FORCEINLINE sd_limb barrier(sd_limb x) { return sd_ct_barrier64(x); }
/* (hi:lo) = a*b + c + d; cannot overflow two limbs. */
static SD_FORCEINLINE sd_limb mac(sd_limb a, sd_limb b, sd_limb c, sd_limb d, sd_limb *hi)
{
  unsigned __int64 h, l = _umul128(a, b, &h);
  unsigned char cf = _addcarry_u64(0, l, c, &l);
  (void)_addcarry_u64(cf, h, 0, &h);
  cf = _addcarry_u64(0, l, d, &l);
  (void)_addcarry_u64(cf, h, 0, &h);
  *hi = h;
  return l;
}
static SD_FORCEINLINE sd_limb adc(sd_limb a, sd_limb b, sd_limb cin, sd_limb *cout)
{
  unsigned __int64 r;
  *cout = _addcarry_u64((unsigned char)cin, a, b, &r);
  return r;
}
static SD_FORCEINLINE sd_limb sbb(sd_limb a, sd_limb b, sd_limb bin, sd_limb *bout)
{
  unsigned __int64 r;
  *bout = _subborrow_u64((unsigned char)bin, a, b, &r);
  return r;
}
#else
static SD_FORCEINLINE sd_limb barrier(sd_limb x) { return sd_ct_barrier32(x); }
static SD_FORCEINLINE sd_limb mac(sd_limb a, sd_limb b, sd_limb c, sd_limb d, sd_limb *hi)
{
  uint64_t t = SD_MUL32(a, b) + c + d;
  *hi = (sd_limb)(t >> 32);
  return (sd_limb)t;
}
static SD_FORCEINLINE sd_limb adc(sd_limb a, sd_limb b, sd_limb cin, sd_limb *cout)
{
  uint64_t t = (uint64_t)a + b + cin;
  *cout = (sd_limb)(t >> 32);
  return (sd_limb)t;
}
static SD_FORCEINLINE sd_limb sbb(sd_limb a, sd_limb b, sd_limb bin, sd_limb *bout)
{
  uint64_t t = (uint64_t)a - b - bin;
  *bout = (sd_limb)(t >> 32) & 1u;
  return (sd_limb)t;
}
#endif

/* ---- constant-time helpers ---- */

sd_limb sd_mp_mask(sd_limb bit)
{
  return barrier((sd_limb)0 - (bit & 1u));
}

static SD_FORCEINLINE sd_limb limb_is_zero(sd_limb x)
{
  return sd_mp_mask((~x & (x - 1u)) >> (SD_LIMB_BITS - 1));
}

sd_limb sd_mp_is_zero(const sd_limb *a, size_t n)
{
  sd_limb acc = 0;
  size_t i;
  for (i = 0; i < n; i++)
    acc |= a[i];
  return limb_is_zero(acc);
}

sd_limb sd_mp_eq(const sd_limb *a, const sd_limb *b, size_t n)
{
  sd_limb acc = 0;
  size_t i;
  for (i = 0; i < n; i++)
    acc |= a[i] ^ b[i];
  return limb_is_zero(acc);
}

sd_limb sd_mp_add(sd_limb *r, const sd_limb *a, const sd_limb *b, size_t n)
{
  sd_limb c = 0;
  size_t i;
  for (i = 0; i < n; i++)
    r[i] = adc(a[i], b[i], c, &c);
  return c;
}

sd_limb sd_mp_sub(sd_limb *r, const sd_limb *a, const sd_limb *b, size_t n)
{
  sd_limb c = 0;
  size_t i;
  for (i = 0; i < n; i++)
    r[i] = sbb(a[i], b[i], c, &c);
  return c;
}

sd_limb sd_mp_lt(const sd_limb *a, const sd_limb *b, size_t n)
{
  sd_limb c = 0;
  size_t i;
  for (i = 0; i < n; i++)
    (void)sbb(a[i], b[i], c, &c);
  return c;
}

sd_limb sd_mp_add_mask(sd_limb *r, const sd_limb *a, const sd_limb *b, sd_limb mask, size_t n)
{
  sd_limb c = 0;
  size_t i;
  mask = barrier(mask);
  for (i = 0; i < n; i++)
    r[i] = adc(a[i], b[i] & mask, c, &c);
  return c;
}

sd_limb sd_mp_sub_mask(sd_limb *r, const sd_limb *a, const sd_limb *b, sd_limb mask, size_t n)
{
  sd_limb c = 0;
  size_t i;
  mask = barrier(mask);
  for (i = 0; i < n; i++)
    r[i] = sbb(a[i], b[i] & mask, c, &c);
  return c;
}

void sd_mp_cmov(sd_limb *r, const sd_limb *a, sd_limb mask, size_t n)
{
  size_t i;
  mask = barrier(mask);
  for (i = 0; i < n; i++)
    r[i] ^= mask & (r[i] ^ a[i]);
}

void sd_mp_cswap(sd_limb *a, sd_limb *b, sd_limb mask, size_t n)
{
  size_t i;
  mask = barrier(mask);
  for (i = 0; i < n; i++) {
    sd_limb t = mask & (a[i] ^ b[i]);
    a[i] ^= t;
    b[i] ^= t;
  }
}

void sd_mp_shr1(sd_limb *a, sd_limb top, size_t n)
{
  size_t i;
  for (i = 0; i + 1 < n; i++)
    a[i] = (a[i] >> 1) | (a[i + 1] << (SD_LIMB_BITS - 1));
  a[n - 1] = (a[n - 1] >> 1) | ((top & 1u) << (SD_LIMB_BITS - 1));
}

void sd_mp_modadd(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, size_t n)
{
  sd_limb c = sd_mp_add(r, a, b, n);
  sd_limb lt = sd_mp_lt(r, m, n);
  /* subtract m when the sum overflowed or is >= m */
  (void)sd_mp_sub_mask(r, r, m, sd_mp_mask(c | (lt ^ 1u)), n);
}

void sd_mp_modsub(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, size_t n)
{
  sd_limb bo = sd_mp_sub(r, a, b, n);
  (void)sd_mp_add_mask(r, r, m, sd_mp_mask(bo), n);
}

void sd_mp_mul(sd_limb *r, const sd_limb *a, size_t na, const sd_limb *b, size_t nb)
{
  size_t i, j;
  for (i = 0; i < na + nb; i++)
    r[i] = 0;
  for (i = 0; i < nb; i++) {
    sd_limb c = 0, bi = b[i];
    for (j = 0; j < na; j++)
      r[i + j] = mac(a[j], bi, r[i + j], c, &c);
    r[i + na] = c;
  }
}

/* Shifts a left by one bit, inserting `in` at the bottom; returns the bit shifted out. */
static sd_limb shl1(sd_limb *a, sd_limb in, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
    sd_limb out = a[i] >> (SD_LIMB_BITS - 1);
    a[i] = (a[i] << 1) | in;
    in = out;
  }
  return in;
}

void sd_mp_mod(sd_limb *r, const sd_limb *a, size_t na, const sd_limb *m, size_t nm)
{
  sd_limb t[SD_MP_MAX];
  size_t i;
  for (i = 0; i < nm; i++)
    r[i] = 0;
  for (i = na * SD_LIMB_BITS; i-- > 0;) {
    sd_limb bit = (a[i / SD_LIMB_BITS] >> (i % SD_LIMB_BITS)) & 1u;
    sd_limb carry = shl1(r, bit, nm);
    sd_limb borrow = sd_mp_sub(t, r, m, nm);
    sd_mp_cmov(r, t, sd_mp_mask(carry | (borrow ^ 1u)), nm);
  }
  sd_secure_zero(t, nm * sizeof(sd_limb));
}

/* ---- Montgomery ---- */

sd_limb sd_mp_m0inv(sd_limb m0)
{
  sd_limb x = m0;           /* correct to 3 bits for odd m0 */
  int i;
  for (i = 0; i < 6; i++)   /* 3, 6, 12, 24, 48, 96 bits */
    x = x * (2u - m0 * x);
  return (sd_limb)0 - x;
}

void sd_mp_mont_r2(sd_limb *r2, const sd_limb *m, size_t n)
{
  sd_limb t[SD_MP_MAX];
  size_t i;
  for (i = 0; i < n; i++)
    r2[i] = 0;
  r2[0] = 1;                /* m > 1 */
  for (i = 0; i < 2 * n * SD_LIMB_BITS; i++) {
    sd_limb carry = shl1(r2, 0, n);
    sd_limb borrow = sd_mp_sub(t, r2, m, n);
    sd_mp_cmov(r2, t, sd_mp_mask(carry | (borrow ^ 1u)), n);
  }
  sd_secure_zero(t, n * sizeof(sd_limb));
}

void sd_mp_montmul(sd_limb *r, const sd_limb *a, const sd_limb *b, const sd_limb *m, sd_limb m0i, size_t n)
{
  sd_limb t[SD_MP_MAX + 2];
  size_t i, j;
  sd_limb c, c2, u, top, borrow;
  memset(t, 0, (n + 1) * sizeof(sd_limb));   /* the analyzer tracks memset, not the loop */
  for (i = 0; i < n; i++) {
    sd_limb bi = b[i];
    c = 0;
    for (j = 0; j < n; j++)
      t[j] = mac(a[j], bi, t[j], c, &c);
    t[n] = adc(t[n], c, 0, &c2);
    u = t[0] * m0i;
    (void)mac(u, m[0], t[0], 0, &c);
    for (j = 1; j < n; j++)
      t[j - 1] = mac(u, m[j], t[j], c, &c);
    t[n - 1] = adc(t[n], c, 0, &c);
    t[n] = c2 + c;
  }
  top = t[n];
  borrow = sd_mp_sub(r, t, m, n);
  /* keep t when it was already < m (no top bit and the subtraction borrowed) */
  sd_mp_cmov(r, t, sd_mp_mask((top ^ 1u) & borrow), n);
}

void sd_mp_modexp_ct(sd_limb *r, const sd_limb *base, const sd_limb *exp, uint32_t ebits,
                     const sd_limb *m, sd_limb m0i, const sd_limb *r2, size_t n, sd_limb *work)
{
  sd_limb *tab = work, *acc = work + 16 * n, *sel = work + 17 * n;
  uint32_t nwin = (ebits + 3) / 4, w, k;
  size_t i;
  /* tab[k] = base^k * R mod m */
  for (i = 0; i < n; i++)
    sel[i] = 0;
  sel[0] = 1;
  sd_mp_montmul(tab, r2, sel, m, m0i, n);                /* R mod m */
  sd_mp_montmul(tab + n, base, r2, m, m0i, n);
  for (k = 2; k < 16; k++)
    sd_mp_montmul(tab + k * n, tab + (k - 1) * n, tab + n, m, m0i, n);
  memcpy(acc, tab, n * sizeof(sd_limb));
  for (w = nwin; w-- > 0;) {
    uint32_t bit = 4 * w, digit;
    sd_limb word = exp[bit / SD_LIMB_BITS] >> (bit % SD_LIMB_BITS);
    digit = (uint32_t)(word & 15u);
    if (bit + 4 > ebits)    /* public: the top window may be partial */
      digit &= (1u << (ebits - bit)) - 1u;
    for (k = 0; k < 4; k++)
      sd_mp_montmul(acc, acc, acc, m, m0i, n);
    for (i = 0; i < n; i++)
      sel[i] = 0;
    for (k = 0; k < 16; k++) {
      sd_limb mk = sd_mp_mask(sd_ct_eq_u32(k, digit) & 1u);
      for (i = 0; i < n; i++)
        sel[i] |= tab[k * n + i] & mk;
    }
    sd_mp_montmul(acc, acc, sel, m, m0i, n);
  }
  for (i = 0; i < n; i++)
    sel[i] = 0;
  sel[0] = 1;
  sd_mp_montmul(r, acc, sel, m, m0i, n);
  sd_secure_zero(work, SD_MP_MODEXP_WORK(n) * sizeof(sd_limb));
}

void sd_mp_modexp_vt(sd_limb *r, const sd_limb *base, const sd_limb *exp, size_t ne,
                     const sd_limb *m, sd_limb m0i, const sd_limb *r2, size_t n, sd_limb *work)
{
  sd_limb *b = work, *acc = work + n, *one = work + 2 * n;
  uint32_t bits = sd_mp_vt_bits(exp, ne), i;
  size_t j;
  for (j = 0; j < n; j++)
    one[j] = 0;
  one[0] = 1;
  sd_mp_montmul(b, base, r2, m, m0i, n);
  sd_mp_montmul(acc, r2, one, m, m0i, n);                /* R mod m */
  for (i = bits; i-- > 0;) {
    sd_mp_montmul(acc, acc, acc, m, m0i, n);
    if ((exp[i / SD_LIMB_BITS] >> (i % SD_LIMB_BITS)) & 1u)   /* public exponent */
      sd_mp_montmul(acc, acc, b, m, m0i, n);
  }
  sd_mp_montmul(r, acc, one, m, m0i, n);
  sd_secure_zero(work, SD_MP_MODEXP_VT_WORK(n) * sizeof(sd_limb));
}

sd_limb sd_mp_modinv_ct(sd_limb *r, const sd_limb *a, const sd_limb *m, size_t n, sd_limb *work)
{
  sd_limb *u = work, *v = work + n, *x1 = work + 2 * n, *x2 = work + 3 * n, *t = work + 4 * n;
  size_t i, it;
  sd_limb ok, one;
  memcpy(u, a, n * sizeof(sd_limb));
  memcpy(v, m, n * sizeof(sd_limb));
  for (i = 0; i < n; i++)
    x1[i] = x2[i] = 0;
  x1[0] = 1;
  /* Invariants: u = x1*a, v = x2*a (mod m); bits(u) + bits(v) drops every step while u != 0. */
  for (it = 0; it < 2 * n * SD_LIMB_BITS; it++) {
    sd_limb odd = u[0] & 1u;
    sd_limb borrow = sd_mp_sub(t, u, v, n);
    sd_limb sw = sd_mp_mask(odd & borrow), om = sd_mp_mask(odd), b;
    sd_mp_cswap(u, v, sw, n);
    sd_mp_cswap(x1, x2, sw, n);
    (void)sd_mp_sub_mask(u, u, v, om, n);
    b = sd_mp_sub_mask(x1, x1, x2, om, n);
    (void)sd_mp_add_mask(x1, x1, m, sd_mp_mask(b), n);
    sd_mp_shr1(u, 0, n);
    b = sd_mp_add_mask(x1, x1, m, sd_mp_mask(x1[0] & 1u), n);
    sd_mp_shr1(x1, b, n);
  }
  /* v = gcd(a, m) */
  one = v[0] ^ 1u;
  for (i = 1; i < n; i++)
    one |= v[i];
  ok = limb_is_zero(one);
  memcpy(r, x2, n * sizeof(sd_limb));
  sd_secure_zero(work, SD_MP_MODINV_WORK(n) * sizeof(sd_limb));
  return ok;
}

/* ---- encodings ---- */

void sd_mp_from_be(sd_limb *r, size_t n, const uint8_t *be, size_t len)
{
  size_t i;
  for (i = 0; i < n; i++)
    r[i] = 0;
  for (i = 0; i < len && i < n * SD_LIMB_BYTES; i++)
    r[i / SD_LIMB_BYTES] |= (sd_limb)be[len - 1 - i] << (8 * (i % SD_LIMB_BYTES));
}

void sd_mp_to_be(uint8_t *be, size_t len, const sd_limb *a, size_t n)
{
  size_t i;
  for (i = 0; i < len; i++) {
    sd_limb v = (i / SD_LIMB_BYTES < n) ? a[i / SD_LIMB_BYTES] : 0;
    be[len - 1 - i] = (uint8_t)(v >> (8 * (i % SD_LIMB_BYTES)));
  }
}

size_t sd_mp_vt_trim(const sd_limb *a, size_t n)
{
  while (n > 0 && a[n - 1] == 0)
    n--;
  return n;
}

uint32_t sd_mp_vt_bits(const sd_limb *a, size_t n)
{
  sd_limb top;
  uint32_t b;
  n = sd_mp_vt_trim(a, n);
  if (n == 0)
    return 0;
  top = a[n - 1];
  b = (uint32_t)((n - 1) * SD_LIMB_BITS);
  while (top) {
    b++;
    top >>= 1;
  }
  return b;
}

int sd_mp_vt_cmp(const sd_limb *a, size_t na, const sd_limb *b, size_t nb)
{
  size_t i;
  na = sd_mp_vt_trim(a, na);
  nb = sd_mp_vt_trim(b, nb);
  if (na != nb)
    return na < nb ? -1 : 1;
  for (i = na; i-- > 0;)
    if (a[i] != b[i])
      return a[i] < b[i] ? -1 : 1;
  return 0;
}

SD_NOINLINE void sd_pk_scrub_stack(void)
{
  uint8_t buf[6144];
  sd_secure_zero(buf, sizeof(buf));
}

/* ---- public sd_bn API ---- */

sd_err sd_bn_from_bytes(sd_bn *r, const uint8_t *be, size_t len)
{
  size_t n;
  if (r == NULL || (len && be == NULL) || len > SD_BN_MAX_BITS / 8)
    return SD_E_INVALID_PARAM;
  n = (len + SD_LIMB_BYTES - 1) / SD_LIMB_BYTES;
  if (n == 0)
    n = 1;
  sd_mp_from_be(r->v, n, be, len);
  r->n = (uint32_t)n;
  return SD_OK;
}

sd_err sd_bn_to_bytes(const sd_bn *a, uint8_t *be, size_t len)
{
  size_t i;
  uint8_t extra = 0;
  if (a == NULL || (len && be == NULL))
    return SD_E_INVALID_PARAM;
  sd_mp_to_be(be, len, a->v, a->n);
  for (i = len; i < (size_t)a->n * SD_LIMB_BYTES; i++)
    extra |= (uint8_t)(a->v[i / SD_LIMB_BYTES] >> (8 * (i % SD_LIMB_BYTES)));
  if (extra) {
    memset(be, 0, len);
    return SD_E_INVALID_PARAM;
  }
  return SD_OK;
}

void sd_bn_from_u32(sd_bn *r, uint32_t x)
{
  r->n = 1;
  r->v[0] = x;
}

void sd_bn_wipe(sd_bn *a)
{
  if (a)
    sd_secure_zero(a, sizeof(*a));
}

uint32_t sd_bn_vt_bits(const sd_bn *a)
{
  return sd_mp_vt_bits(a->v, a->n);
}

int sd_bn_vt_cmp(const sd_bn *a, const sd_bn *b)
{
  return sd_mp_vt_cmp(a->v, a->n, b->v, b->n);
}

int sd_bn_vt_is_zero(const sd_bn *a)
{
  return sd_mp_vt_trim(a->v, a->n) == 0;
}

static int bn_ok(const sd_bn *a)
{
  return a != NULL && a->n >= 1 && a->n <= SD_MP_MAX;
}

sd_err sd_bn_ct_mul(sd_bn *r, const sd_bn *a, const sd_bn *b)
{
  sd_limb *t;
  size_t n;
  if (!bn_ok(a) || !bn_ok(b) || r == NULL || (size_t)a->n + b->n > SD_MP_MAX)
    return SD_E_INVALID_PARAM;
  n = (size_t)a->n + b->n;
  t = (sd_limb *)sd_alloc(n * sizeof(sd_limb));
  if (t == NULL)
    return SD_E_NO_MEMORY;
  sd_mp_mul(t, a->v, a->n, b->v, b->n);
  memcpy(r->v, t, n * sizeof(sd_limb));
  r->n = (uint32_t)n;
  sd_secure_free(t, n * sizeof(sd_limb));
  return SD_OK;
}

/* Modulus checks shared by the public wrappers: the modulus length is public, so trimming is fine. */
static size_t mod_limbs(const sd_bn *m)
{
  return bn_ok(m) ? sd_mp_vt_trim(m->v, m->n) : 0;
}

sd_err sd_bn_ct_mod(sd_bn *r, const sd_bn *a, const sd_bn *mod)
{
  size_t nm = mod_limbs(mod);
  sd_limb *t;
  if (nm == 0 || !bn_ok(a) || r == NULL)
    return SD_E_INVALID_PARAM;
  t = (sd_limb *)sd_alloc(nm * sizeof(sd_limb));
  if (t == NULL)
    return SD_E_NO_MEMORY;
  sd_mp_mod(t, a->v, a->n, mod->v, nm);
  memcpy(r->v, t, nm * sizeof(sd_limb));
  r->n = (uint32_t)nm;
  sd_secure_free(t, nm * sizeof(sd_limb));
  return SD_OK;
}

/* Allocates base (n), r2 (n) and work (w) for the exponentiation wrappers. */
static sd_err modexp_prep(const sd_bn *base, const sd_bn *mod, size_t w, size_t *pn, sd_limb **mem)
{
  size_t n = mod_limbs(mod);
  sd_limb *p;
  if (n == 0 || !bn_ok(base) || (mod->v[0] & 1u) == 0 || (n == 1 && mod->v[0] == 1))
    return SD_E_INVALID_PARAM;
  p = (sd_limb *)sd_calloc(2 * n + w, sizeof(sd_limb));
  if (p == NULL)
    return SD_E_NO_MEMORY;
  sd_mp_mod(p, base->v, base->n, mod->v, n);
  sd_mp_mont_r2(p + n, mod->v, n);
  *pn = n;
  *mem = p;
  return SD_OK;
}

sd_err sd_bn_ct_modexp(sd_bn *r, const sd_bn *base, const sd_bn *exp, uint32_t exp_bits, const sd_bn *mod)
{
  size_t n;
  sd_limb *p;
  sd_err e;
  if (!bn_ok(exp) || r == NULL || exp_bits > exp->n * SD_LIMB_BITS)
    return SD_E_INVALID_PARAM;
  if (exp_bits == 0)
    exp_bits = exp->n * SD_LIMB_BITS;
  e = modexp_prep(base, mod, SD_MP_MODEXP_WORK(mod_limbs(mod)), &n, &p);
  if (e != SD_OK)
    return e;
  sd_mp_modexp_ct(r->v, p, exp->v, exp_bits, mod->v, sd_mp_m0inv(mod->v[0]), p + n, n, p + 2 * n);
  r->n = (uint32_t)n;
  sd_secure_free(p, (2 * n + SD_MP_MODEXP_WORK(n)) * sizeof(sd_limb));
  sd_pk_scrub_stack();
  return SD_OK;
}

sd_err sd_bn_vt_modexp(sd_bn *r, const sd_bn *base, const sd_bn *exp, const sd_bn *mod)
{
  size_t n;
  sd_limb *p;
  sd_err e;
  if (!bn_ok(exp) || r == NULL)
    return SD_E_INVALID_PARAM;
  e = modexp_prep(base, mod, SD_MP_MODEXP_VT_WORK(mod_limbs(mod)), &n, &p);
  if (e != SD_OK)
    return e;
  sd_mp_modexp_vt(r->v, p, exp->v, exp->n, mod->v, sd_mp_m0inv(mod->v[0]), p + n, n, p + 2 * n);
  r->n = (uint32_t)n;
  sd_secure_free(p, (2 * n + SD_MP_MODEXP_VT_WORK(n)) * sizeof(sd_limb));
  return SD_OK;
}

sd_err sd_bn_ct_modinv(sd_bn *r, const sd_bn *a, const sd_bn *mod)
{
  size_t n = mod_limbs(mod);
  sd_limb *p, ok;
  if (n == 0 || !bn_ok(a) || r == NULL || (mod->v[0] & 1u) == 0)
    return SD_E_INVALID_PARAM;
  p = (sd_limb *)sd_calloc(n + SD_MP_MODINV_WORK(n), sizeof(sd_limb));
  if (p == NULL)
    return SD_E_NO_MEMORY;
  sd_mp_mod(p, a->v, a->n, mod->v, n);
  ok = sd_mp_modinv_ct(r->v, p, mod->v, n, p + n);
  r->n = (uint32_t)n;
  sd_secure_free(p, (n + SD_MP_MODINV_WORK(n)) * sizeof(sd_limb));
  sd_pk_scrub_stack();
  if (!ok) {
    sd_secure_zero(r->v, n * sizeof(sd_limb));
    return SD_E_CRYPTO;
  }
  return SD_OK;
}
