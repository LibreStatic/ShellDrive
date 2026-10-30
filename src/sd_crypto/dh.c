/* Finite-field Diffie-Hellman for SSH (RFC 4253 §8, RFC 4419, RFC 8268) over the RFC 2409 / RFC 3526
 * MODP groups or a validated group-exchange group. The private exponent comes from the OS RNG at the moment
 * sd_dh_public is called (01 §2.2 RNG notes); both exponentiations are the constant-time Montgomery
 * fixed-window code of bn.c over the public exponent length priv_bits. */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"

#include "pk_consts.inc"

struct sd_dh {
  uint32_t bits, xbits;
  size_t len, nl, xl;
  int have_x;
  sd_limb m0i;
  sd_limb *pool;             /* p, r2, g, x, work */
  size_t pool_limbs;
  sd_limb *p, *r2, *g, *x, *work;
};

const uint8_t *sd_dh_group_modp(int id, size_t *plen)
{
  const uint8_t *p;
  size_t l;
  switch (id) {
  case 1:
  case 2: p = k_modp_1024; l = sizeof(k_modp_1024); break;
  case 14: p = k_modp_2048; l = sizeof(k_modp_2048); break;
  case 16: p = k_modp_4096; l = sizeof(k_modp_4096); break;
  case 18: p = k_modp_8192; l = sizeof(k_modp_8192); break;
  default: p = NULL; l = 0; break;
  }
  if (plen)
    *plen = l;
  return p;
}

void sd_dh_free(sd_dh *d)
{
  if (d == NULL)
    return;
  if (d->pool)
    sd_secure_free(d->pool, d->pool_limbs * sizeof(sd_limb));
  sd_secure_free(d, sizeof(*d));
}

sd_err sd_dh_new(const uint8_t *p, size_t plen, const uint8_t *g, size_t glen, uint32_t priv_bits, sd_dh **out)
{
  sd_dh *d;
  size_t nl, xl, i;
  uint32_t bits;
  sd_limb *pm1;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (p == NULL || g == NULL)
    return SD_E_INVALID_PARAM;
  while (plen > 0 && p[0] == 0) {
    p++;
    plen--;
  }
  while (glen > 0 && g[0] == 0) {
    g++;
    glen--;
  }
  if (plen == 0 || plen > SD_DH_MAX_BITS / 8 || glen > plen)
    return SD_E_UNSUPPORTED;
  bits = (uint32_t)(plen - 1) * 8;
  for (i = p[0]; i; i >>= 1)
    bits++;
  if (bits < SD_DH_MIN_BITS || bits > SD_DH_MAX_BITS)
    return SD_E_UNSUPPORTED;
  if ((p[plen - 1] & 1u) == 0)
    return SD_E_CRYPTO;
  if (priv_bits == 0)
    priv_bits = bits <= 3072 ? 256 : 512;
  if (priv_bits < 160 || priv_bits >= bits)
    return SD_E_INVALID_PARAM;
  nl = (plen + SD_LIMB_BYTES - 1) / SD_LIMB_BYTES;
  xl = (priv_bits + SD_LIMB_BITS - 1) / SD_LIMB_BITS;
  d = (sd_dh *)sd_calloc(1, sizeof(*d));
  if (d == NULL)
    return SD_E_NO_MEMORY;
  d->pool_limbs = 4 * nl + xl + SD_MP_MODEXP_WORK(nl);
  d->pool = (sd_limb *)sd_calloc(d->pool_limbs, sizeof(sd_limb));
  if (d->pool == NULL) {
    sd_dh_free(d);
    return SD_E_NO_MEMORY;
  }
  d->p = d->pool;
  d->r2 = d->p + nl;
  d->g = d->r2 + nl;
  pm1 = d->g + nl;          /* scratch, nl limbs */
  d->x = pm1 + nl;
  d->work = d->x + xl;
  d->bits = bits;
  d->xbits = priv_bits;
  d->len = plen;
  d->nl = nl;
  d->xl = xl;
  sd_mp_from_be(d->p, nl, p, plen);
  sd_mp_from_be(d->g, nl, g, glen);
  /* 1 < g < p - 1 */
  memcpy(pm1, d->p, nl * sizeof(sd_limb));
  pm1[0] &= ~(sd_limb)1;
  if (sd_mp_vt_bits(d->g, nl) < 2 || sd_mp_vt_cmp(d->g, nl, pm1, nl) >= 0) {
    sd_dh_free(d);
    return SD_E_CRYPTO;
  }
  d->m0i = sd_mp_m0inv(d->p[0]);
  sd_mp_mont_r2(d->r2, d->p, nl);
  *out = d;
  return SD_OK;
}

sd_err sd_dh_new_group(int id, uint32_t priv_bits, sd_dh **out)
{
  static const uint8_t two = 2;
  size_t plen;
  const uint8_t *p = sd_dh_group_modp(id, &plen);
  if (out)
    *out = NULL;
  if (p == NULL)
    return SD_E_UNSUPPORTED;
  return sd_dh_new(p, plen, &two, 1, priv_bits, out);
}

size_t sd_dh_len(const sd_dh *d)
{
  return d ? d->len : 0;
}

uint32_t sd_dh_bits(const sd_dh *d)
{
  return d ? d->bits : 0;
}

sd_err sd_dh_public(sd_dh *d, uint8_t *e, size_t elen)
{
  sd_limb *r;
  uint32_t top;
  if (d == NULL || e == NULL || elen < d->len)
    return SD_E_INVALID_PARAM;
  if (sd_random(d->x, d->xl * sizeof(sd_limb)) != SD_OK) {
    sd_secure_zero(d->x, d->xl * sizeof(sd_limb));
    d->have_x = 0;
    return SD_E_FAILURE;
  }
  /* exactly xbits bits: clear above, set the top bit */
  top = (d->xbits - 1) % SD_LIMB_BITS;
  d->x[d->xl - 1] &= ((sd_limb)2 << top) - 1u;
  d->x[d->xl - 1] |= (sd_limb)1 << top;
  d->have_x = 1;
  r = (sd_limb *)sd_alloc(d->nl * sizeof(sd_limb));
  if (r == NULL)
    return SD_E_NO_MEMORY;
  sd_mp_modexp_ct(r, d->g, d->x, d->xbits, d->p, d->m0i, d->r2, d->nl, d->work);
  sd_mp_to_be(e, d->len, r, d->nl);
  sd_secure_free(r, d->nl * sizeof(sd_limb));
  sd_pk_scrub_stack();
  return SD_OK;
}

sd_err sd_dh_compute(sd_dh *d, const uint8_t *f, size_t flen, uint8_t *k, size_t klen)
{
  sd_limb *fv, *res, *pm1;
  sd_err err = SD_OK;
  size_t nl;
  if (d == NULL || f == NULL || k == NULL || klen < d->len || !d->have_x)
    return SD_E_INVALID_PARAM;
  nl = d->nl;
  while (flen > 0 && f[0] == 0) {
    f++;
    flen--;
  }
  if (flen > d->len)
    return SD_E_CRYPTO;
  fv = (sd_limb *)sd_calloc(3 * nl, sizeof(sd_limb));
  if (fv == NULL)
    return SD_E_NO_MEMORY;
  res = fv + nl;
  pm1 = res + nl;
  sd_mp_from_be(fv, nl, f, flen);
  memcpy(pm1, d->p, nl * sizeof(sd_limb));
  pm1[0] &= ~(sd_limb)1;
  /* 1 < f < p - 1 (public value, RFC 4253 §8) */
  if (sd_mp_vt_bits(fv, nl) < 2 || sd_mp_vt_cmp(fv, nl, pm1, nl) >= 0) {
    err = SD_E_CRYPTO;
  } else {
    sd_mp_modexp_ct(res, fv, d->x, d->xbits, d->p, d->m0i, d->r2, nl, d->work);
    sd_mp_to_be(k, d->len, res, nl);
  }
  sd_secure_free(fv, 3 * nl * sizeof(sd_limb));
  sd_pk_scrub_stack();
  return err;
}
