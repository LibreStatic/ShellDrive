/* Validation of server-chosen Diffie-Hellman group-exchange groups (RFC 4419, RFC 8270). Public data
 * only, so this file is variable time and is not in the constant-time object list.
 *
 * p must be a safe prime p = 2q + 1. q is tested with Miller-Rabin (HAC §4.24) on random bases; given
 * q prime, p is then proven prime by Pocklington's criterion (HAC §4.40): q > sqrt(p) divides p - 1,
 * 2^(p-1) = 1 mod p and gcd(2^2 - 1, p) = gcd(3, p) = 1 (trial division covers 3). */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"

static const uint8_t *strip(const uint8_t *p, size_t *len)
{
  while (*len > 0 && p[0] == 0) {
    p++;
    (*len)--;
  }
  return p;
}

/* a mod s for s < 2^16, 16 bits at a time so only 32-bit division is used. */
static uint32_t mod_small(const sd_limb *a, size_t n, uint32_t s)
{
  uint32_t rem = 0;
  size_t i;
  int sh;
  for (i = n; i-- > 0;)
    for (sh = SD_LIMB_BITS - 16; sh >= 0; sh -= 16)
      rem = ((rem << 16) | (uint32_t)((a[i] >> sh) & 0xffffu)) % s;
  return rem;
}

static int known_group(const uint8_t *p, size_t plen)
{
  static const int ids[] = { 1, 14, 16, 18 };
  size_t i, l;
  for (i = 0; i < SD_COUNTOF(ids); i++) {
    const uint8_t *k = sd_dh_group_modp(ids[i], &l);
    if (l == plen && memcmp(k, p, l) == 0)
      return 1;
  }
  return 0;
}

/* Miller-Rabin on odd m (n limbs, m[n-1] != 0) with `rounds` random bases. 1 = probably prime. */
static int miller_rabin(const sd_limb *m, size_t n, uint32_t rounds, int *rng_failed)
{
  size_t wl = 8 * n + SD_MP_MODEXP_VT_WORK(n);
  sd_limb *w = (sd_limb *)sd_calloc(wl, sizeof(sd_limb));
  sd_limb *r2, *t, *a, *x, *one_m, *mone_m, *tmp, *vw, m0i;
  uint32_t s = 0, i, round;
  int result = 1;
  if (w == NULL)
    return -1;
  r2 = w; t = r2 + n; a = t + n; x = a + n; one_m = x + n; mone_m = one_m + n; tmp = mone_m + n;
  vw = tmp + 2 * n;
  m0i = sd_mp_m0inv(m[0]);
  sd_mp_mont_r2(r2, m, n);
  /* t = (m - 1) / 2^s */
  memcpy(t, m, n * sizeof(sd_limb));
  t[0] &= ~(sd_limb)1;
  while ((t[0] & 1u) == 0) {
    sd_mp_shr1(t, 0, n);
    s++;
  }
  memset(tmp, 0, n * sizeof(sd_limb));
  tmp[0] = 1;
  sd_mp_montmul(one_m, r2, tmp, m, m0i, n);             /* R mod m */
  (void)sd_mp_sub(mone_m, m, one_m, n);                  /* -R mod m */
  for (round = 0; round < rounds && result == 1; round++) {
    if (sd_random(tmp, 2 * n * sizeof(sd_limb)) != SD_OK) {
      *rng_failed = 1;
      result = -1;
      break;
    }
    sd_mp_mod(a, tmp, 2 * n, m, n);
    if (sd_mp_vt_bits(a, n) < 2) {                       /* a in {0, 1}: use 2 */
      memset(a, 0, n * sizeof(sd_limb));
      a[0] = 2;
    }
    sd_mp_modexp_vt(x, a, t, n, m, m0i, r2, n, vw);
    sd_mp_montmul(x, x, r2, m, m0i, n);                  /* to Montgomery form */
    if (sd_mp_vt_cmp(x, n, one_m, n) == 0 || sd_mp_vt_cmp(x, n, mone_m, n) == 0)
      continue;
    for (i = 1; i < s; i++) {
      sd_mp_montmul(x, x, x, m, m0i, n);
      if (sd_mp_vt_cmp(x, n, mone_m, n) == 0)
        break;
    }
    if (i >= s)
      result = 0;
  }
  sd_secure_free(w, wl * sizeof(sd_limb));
  return result;
}

sd_err sd_dh_gex_validate(const uint8_t *p, size_t plen, const uint8_t *g, size_t glen,
                          const sd_dh_gex_policy *pol)
{
  sd_dh_gex_policy dp;
  uint32_t bits, minb, maxb, rounds, sp;
  size_t nl, ql, i;
  sd_limb *pool, *pv, *gv, *pm1, *q, *two, *x, *r2, *vw;
  sd_err err = SD_OK;
  int rngf = 0, mr;
  memset(&dp, 0, sizeof(dp));
  if (pol)
    dp = *pol;
  minb = dp.min_bits ? SD_MAX(dp.min_bits, (uint32_t)SD_DH_MIN_BITS) : SD_DH_GEX_DEFAULT_MIN_BITS;
  maxb = dp.max_bits ? SD_MIN(dp.max_bits, (uint32_t)SD_DH_MAX_BITS) : SD_DH_GEX_DEFAULT_MAX_BITS;
  rounds = dp.mr_rounds ? SD_MIN(dp.mr_rounds, 64u) : SD_DH_GEX_DEFAULT_MR_ROUNDS;
  if (p == NULL || g == NULL)
    return SD_E_INVALID_PARAM;
  p = strip(p, &plen);
  g = strip(g, &glen);
  if (plen == 0 || plen > SD_DH_MAX_BITS / 8)
    return SD_E_UNSUPPORTED;
  bits = (uint32_t)(plen - 1) * 8;
  for (i = p[0]; i; i >>= 1)
    bits++;
  if (bits < minb || bits > maxb)
    return SD_E_UNSUPPORTED;
  /* a safe prime > 7 is 3 mod 4 */
  if ((p[plen - 1] & 3u) != 3u || glen > plen)
    return SD_E_CRYPTO;
  nl = (plen + SD_LIMB_BYTES - 1) / SD_LIMB_BYTES;
  pool = (sd_limb *)sd_calloc(8 * nl + SD_MP_MODEXP_VT_WORK(nl), sizeof(sd_limb));
  if (pool == NULL)
    return SD_E_NO_MEMORY;
  pv = pool; gv = pv + nl; pm1 = gv + nl; q = pm1 + nl; two = q + nl; x = two + nl; r2 = x + nl;
  vw = r2 + nl;
  sd_mp_from_be(pv, nl, p, plen);
  sd_mp_from_be(gv, nl, g, glen);
  memcpy(pm1, pv, nl * sizeof(sd_limb));
  pm1[0] &= ~(sd_limb)1;
  if (sd_mp_vt_bits(gv, nl) < 2 || sd_mp_vt_cmp(gv, nl, pm1, nl) >= 0) {
    err = SD_E_CRYPTO;
    goto done;
  }
  if (known_group(p, plen) || (dp.flags & SD_DH_GEX_NO_PRIME_TEST))
    goto done;
  /* Trial division of p and q = (p-1)/2 by the odd primes below 2^13: p mod s must not be 0 or 1. */
  for (sp = 3; sp < 8192; sp += 2) {
    uint32_t d, r;
    for (d = 3; d * d <= sp; d += 2)
      if (sp % d == 0)
        break;
    if (d * d <= sp)
      continue;
    r = mod_small(pv, nl, sp);
    if (r == 0 || r == 1) {
      err = SD_E_CRYPTO;
      goto done;
    }
  }
  memcpy(q, pv, nl * sizeof(sd_limb));
  sd_mp_shr1(q, 0, nl);
  ql = sd_mp_vt_trim(q, nl);
  mr = miller_rabin(q, ql, rounds, &rngf);
  if (mr != 1) {
    err = mr == 0 ? SD_E_CRYPTO : (rngf ? SD_E_FAILURE : SD_E_NO_MEMORY);
    goto done;
  }
  /* Pocklington: 2^(p-1) == 1 mod p */
  memset(two, 0, nl * sizeof(sd_limb));
  two[0] = 2;
  sd_mp_mont_r2(r2, pv, nl);
  sd_mp_modexp_vt(x, two, pm1, nl, pv, sd_mp_m0inv(pv[0]), r2, nl, vw);
  two[0] = 1;
  if (sd_mp_vt_cmp(x, nl, two, nl) != 0)
    err = SD_E_CRYPTO;
done:
  sd_secure_free(pool, (8 * nl + SD_MP_MODEXP_VT_WORK(nl)) * sizeof(sd_limb));
  return err;
}
