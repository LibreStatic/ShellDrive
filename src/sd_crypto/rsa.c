/* RSA PKCS#1 v1.5 signatures (RFC 8017 §8.2, §9.2; RFC 4253 ssh-rsa, RFC 8332 rsa-sha2-256/512).
 *
 * Private operation (01 §2.2, §2.8.3): base blinding with a fresh random r (x' = x * r^e), CRT with
 * Garner's recombination (HAC §14.75) when p and q are known, constant-time Montgomery exponentiation
 * (bn.c), unblinding with r^-1 (constant-time binary inversion) and verify-after-sign, which withholds the
 * result on a mismatch (fault-attack countermeasure). dp, dq and q^-1 mod p are derived at import with
 * the constant-time reduction and inversion; there is no division on secrets.
 * Verification rebuilds the full encoded message and compares it (no padding parser to get wrong). */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"

#define E_LIMBS (64 / SD_LIMB_BITS)

struct sd_rsa_key {
  uint32_t bits, nl, pl, ql, ebits;
  size_t len;
  int has_priv, crt;
  sd_limb n_m0i, p_m0i, q_m0i;
  sd_limb e[E_LIMBS];
  sd_limb *pool;
  size_t pool_limbs;
  sd_limb *n, *n_r2, *d, *p, *q, *p_r2, *q_r2, *dp, *dq, *qinv_m;
};

/* DigestInfo prefixes, RFC 8017 §9.2 note 1. */
static const uint8_t k_di_sha1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
                                     0x00, 0x04, 0x14 };
static const uint8_t k_di_sha256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                       0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
static const uint8_t k_di_sha384[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                       0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
static const uint8_t k_di_sha512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                       0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

static const uint8_t *digest_info(sd_hash_alg h, size_t *len)
{
  switch ((int)h) {
  case 1: *len = sizeof(k_di_sha1); return k_di_sha1;
  case SD_HASH_SHA256: *len = sizeof(k_di_sha256); return k_di_sha256;
  case SD_HASH_SHA384: *len = sizeof(k_di_sha384); return k_di_sha384;
  case SD_HASH_SHA512: *len = sizeof(k_di_sha512); return k_di_sha512;
  default: *len = 0; return NULL;
  }
}

/* EMSA-PKCS1-v1_5 (RFC 8017 §9.2): 0x00 0x01 FF..FF 0x00 DigestInfo H, exactly k bytes. */
static sd_err emsa_encode(sd_hash_alg h, const uint8_t *digest, size_t dlen, uint8_t *em, size_t k)
{
  size_t dil, t;
  const uint8_t *di = digest_info(h, &dil);
  if (di == NULL)
    return SD_E_UNSUPPORTED;
  if (digest == NULL || dlen != sd_hash_len(h))
    return SD_E_INVALID_PARAM;
  t = dil + dlen;
  if (k < t + 11)
    return SD_E_INVALID_PARAM;
  em[0] = 0x00;
  em[1] = 0x01;
  memset(em + 2, 0xff, k - t - 3);
  em[k - t - 1] = 0x00;
  memcpy(em + k - t, di, dil);
  memcpy(em + k - dlen, digest, dlen);
  return SD_OK;
}

static const uint8_t *skip_zeros(const uint8_t *p, size_t *len)
{
  while (*len > 0 && p[0] == 0) {
    p++;
    (*len)--;
  }
  return p;
}

static size_t limbs_for_bytes(size_t len)
{
  return (len + SD_LIMB_BYTES - 1) / SD_LIMB_BYTES;
}

/* Work area of rsa_private, in limbs. */
static size_t private_work(const sd_rsa_key *k)
{
  return 16 * (size_t)k->nl + 8 + SD_MP_MODEXP_WORK(k->nl);
}

/* out = in^d mod n with blinding and verify-after-sign; in < n. SD_E_CRYPTO on a fault. */
static sd_err rsa_private(const sd_rsa_key *k, const sd_limb *in, sd_limb *out)
{
  size_t nl = k->nl, pl = k->pl, ql = k->ql, wl = private_work(k), i;
  sd_limb *w, *r, *rinv, *re, *x, *t, *y, *z, *ex, ok = 0;
  sd_err err = SD_OK;
  int tries;
  w = (sd_limb *)sd_calloc(wl, sizeof(sd_limb));
  if (w == NULL)
    return SD_E_NO_MEMORY;
  r = w; rinv = r + nl; re = rinv + nl; x = re + nl; t = x + nl; y = t + nl + 2; z = y + nl;
  ex = z + nl + 2;           /* 8 nl + 4 used above; ex has 8 nl + 4 + modexp work */
  for (tries = 0; tries < 4 && !ok; tries++) {
    if (sd_random(r, nl * sizeof(sd_limb)) != SD_OK) {
      err = SD_E_FAILURE;
      goto done;
    }
    r[nl - 1] &= k->n[nl - 1] >> 1;                          /* r < n */
    ok = sd_mp_modinv_ct(rinv, r, k->n, nl, ex) & ~sd_mp_is_zero(r, nl);
  }
  if (!ok) {
    err = SD_E_CRYPTO;
    goto done;
  }
  sd_mp_modexp_vt(re, r, k->e, E_LIMBS, k->n, k->n_m0i, k->n_r2, nl, ex);
  sd_mp_montmul(t, in, k->n_r2, k->n, k->n_m0i, nl);
  sd_mp_montmul(x, t, re, k->n, k->n_m0i, nl);              /* x = in * r^e mod n */
  if (k->crt) {
    sd_limb *xp = ex, *xq = xp + pl, *s1 = xq + ql, *s2 = s1 + pl, *h = s2 + ql, *s2p = h + pl,
            *mw = s2p + pl + 4;
    sd_mp_mod(xp, x, nl, k->p, pl);
    sd_mp_mod(xq, x, nl, k->q, ql);
    sd_mp_modexp_ct(s1, xp, k->dp, (uint32_t)(pl * SD_LIMB_BITS), k->p, k->p_m0i, k->p_r2, pl, mw);
    sd_mp_modexp_ct(s2, xq, k->dq, (uint32_t)(ql * SD_LIMB_BITS), k->q, k->q_m0i, k->q_r2, ql, mw);
    sd_mp_mod(s2p, s2, ql, k->p, pl);
    sd_mp_modsub(h, s1, s2p, k->p, pl);
    sd_mp_montmul(h, h, k->qinv_m, k->p, k->p_m0i, pl);   /* h = (s1 - s2) * q^-1 mod p */
    sd_mp_mul(t, h, pl, k->q, ql);                        /* pl + ql <= nl + 1 limbs */
    for (i = 0; i < pl + ql; i++)
      z[i] = i < ql ? s2[i] : 0;
    (void)sd_mp_add(t, t, z, pl + ql);                    /* t = s2 + h*q < n */
    memcpy(y, t, nl * sizeof(sd_limb));
  } else {
    sd_mp_modexp_ct(y, x, k->d, (uint32_t)(nl * SD_LIMB_BITS), k->n, k->n_m0i, k->n_r2, nl, ex);
  }
  sd_mp_montmul(t, y, k->n_r2, k->n, k->n_m0i, nl);
  sd_mp_montmul(y, t, rinv, k->n, k->n_m0i, nl);            /* unblind */
  sd_mp_modexp_vt(z, y, k->e, E_LIMBS, k->n, k->n_m0i, k->n_r2, nl, ex);
  if (!sd_mp_eq(z, in, nl)) {
    err = SD_E_CRYPTO;      /* fault or inconsistent key: release nothing */
    goto done;
  }
  memcpy(out, y, nl * sizeof(sd_limb));
done:
  sd_secure_free(w, wl * sizeof(sd_limb));
  sd_pk_scrub_stack();
  return err;
}

void sd_rsa_free(sd_rsa_key *k)
{
  if (k == NULL)
    return;
  if (k->pool)
    sd_secure_free(k->pool, k->pool_limbs * sizeof(sd_limb));
  sd_secure_free(k, sizeof(*k));
}

sd_err sd_rsa_import(const sd_rsa_import_params *ip, sd_rsa_key **out)
{
  const uint8_t *n, *e, *d = NULL, *p = NULL, *q = NULL;
  size_t nlen, elen, dlen = 0, plen = 0, qlen = 0, nl, pl = 0, ql = 0, total, i;
  uint32_t bits, minb, maxb;
  sd_rsa_key *k;
  sd_limb *tmp = NULL;
  sd_err err = SD_OK;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (ip == NULL || ip->n == NULL || ip->e == NULL)
    return SD_E_INVALID_PARAM;
  nlen = ip->n_len;
  elen = ip->e_len;
  n = skip_zeros(ip->n, &nlen);
  e = skip_zeros(ip->e, &elen);
  minb = SD_MAX(ip->min_bits, (uint32_t)SD_RSA_MIN_BITS);
  maxb = ip->max_bits ? SD_MIN(ip->max_bits, (uint32_t)SD_RSA_MAX_BITS) : (uint32_t)SD_RSA_MAX_BITS;
  if (nlen == 0 || nlen > SD_RSA_MAX_BITS / 8)
    return SD_E_KEY_UNSUPPORTED;
  bits = (uint32_t)(nlen - 1) * 8;
  for (i = n[0]; i; i >>= 1)
    bits++;
  if (bits < minb || bits > maxb)
    return SD_E_KEY_UNSUPPORTED;
  if ((n[nlen - 1] & 1u) == 0)
    return SD_E_KEY_FORMAT;
  if (elen == 0 || elen > 8)
    return elen ? SD_E_KEY_UNSUPPORTED : SD_E_KEY_FORMAT;
  if ((e[elen - 1] & 1u) == 0 || (elen == 1 && e[0] < 3))
    return SD_E_KEY_FORMAT;
  if (ip->d) {
    dlen = ip->d_len;
    d = skip_zeros(ip->d, &dlen);
    if (dlen == 0 || dlen > nlen)
      return SD_E_KEY_FORMAT;
    if ((ip->p == NULL) != (ip->q == NULL))
      return SD_E_KEY_FORMAT;
    if (ip->p) {
      plen = ip->p_len;
      qlen = ip->q_len;
      p = skip_zeros(ip->p, &plen);
      q = skip_zeros(ip->q, &qlen);
      if (plen == 0 || qlen == 0 || plen > nlen || qlen > nlen || (p[plen - 1] & 1u) == 0 ||
          (q[qlen - 1] & 1u) == 0)
        return SD_E_KEY_FORMAT;
    }
  }
  k = (sd_rsa_key *)sd_calloc(1, sizeof(*k));
  if (k == NULL)
    return SD_E_NO_MEMORY;
  nl = limbs_for_bytes(nlen);
  if (p) {
    pl = limbs_for_bytes(plen);
    ql = limbs_for_bytes(qlen);
  }
  k->bits = bits;
  k->len = nlen;
  k->nl = (uint32_t)nl;
  k->pl = (uint32_t)pl;
  k->ql = (uint32_t)ql;
  k->has_priv = d != NULL;
  k->crt = p != NULL;
  total = 3 * nl + 4 * pl + 3 * ql;
  k->pool_limbs = total;
  k->pool = (sd_limb *)sd_calloc(total, sizeof(sd_limb));
  if (k->pool == NULL) {
    sd_rsa_free(k);
    return SD_E_NO_MEMORY;
  }
  k->n = k->pool;
  k->n_r2 = k->n + nl;
  k->d = k->n_r2 + nl;
  k->p = k->d + nl;
  k->p_r2 = k->p + pl;
  k->dp = k->p_r2 + pl;
  k->qinv_m = k->dp + pl;
  k->q = k->qinv_m + pl;
  k->q_r2 = k->q + ql;
  k->dq = k->q_r2 + ql;
  sd_mp_from_be(k->n, nl, n, nlen);
  sd_mp_from_be(k->e, E_LIMBS, e, elen);
  k->ebits = sd_mp_vt_bits(k->e, E_LIMBS);
  k->n_m0i = sd_mp_m0inv(k->n[0]);
  sd_mp_mont_r2(k->n_r2, k->n, nl);
  if (d) {
    sd_mp_from_be(k->d, nl, d, dlen);
    /* d < n and d != 0 (the comparison outcome is not secret) */
    if (!sd_mp_lt(k->d, k->n, nl) || sd_mp_is_zero(k->d, nl)) {
      err = SD_E_KEY_FORMAT;
      goto fail;
    }
  }
  if (p) {
    size_t wl = (pl + ql) + 2 * pl + SD_MP_MODINV_WORK(pl);
    sd_limb *prod, *pm1, *qmodp, *iw, okinv;
    tmp = (sd_limb *)sd_calloc(wl + nl, sizeof(sd_limb));
    if (tmp == NULL) {
      err = SD_E_NO_MEMORY;
      goto fail;
    }
    prod = tmp;
    pm1 = prod + pl + ql;
    qmodp = pm1 + pl;
    iw = qmodp + pl;
    sd_mp_from_be(k->p, pl, p, plen);
    sd_mp_from_be(k->q, ql, q, qlen);
    sd_mp_mul(prod, k->p, pl, k->q, ql);
    if (sd_mp_vt_cmp(prod, pl + ql, k->n, nl) != 0 || sd_mp_vt_bits(k->p, pl) < 2 ||
        sd_mp_vt_bits(k->q, ql) < 2) {
      err = SD_E_KEY_FORMAT;
      goto fail;
    }
    k->p_m0i = sd_mp_m0inv(k->p[0]);
    k->q_m0i = sd_mp_m0inv(k->q[0]);
    sd_mp_mont_r2(k->p_r2, k->p, pl);
    sd_mp_mont_r2(k->q_r2, k->q, ql);
    /* dp = d mod (p-1), dq = d mod (q-1); p and q are odd, so p-1 only clears bit 0 */
    memcpy(pm1, k->p, pl * sizeof(sd_limb));
    pm1[0] &= ~(sd_limb)1;
    sd_mp_mod(k->dp, k->d, nl, pm1, pl);
    memcpy(pm1, k->q, ql * sizeof(sd_limb));
    pm1[0] &= ~(sd_limb)1;
    sd_mp_mod(k->dq, k->d, nl, pm1, ql);
    /* q^-1 mod p */
    sd_mp_mod(qmodp, k->q, ql, k->p, pl);
    okinv = sd_mp_modinv_ct(pm1, qmodp, k->p, pl, iw);
    if (!okinv) {
      err = SD_E_KEY_FORMAT;
      goto fail;
    }
    if (ip->iqmp) {
      size_t il = ip->iqmp_len;
      const uint8_t *iq = skip_zeros(ip->iqmp, &il);
      if (il > pl * SD_LIMB_BYTES) {
        err = SD_E_KEY_FORMAT;
        goto fail;
      }
      sd_mp_from_be(qmodp, pl, iq, il);
      if (!sd_mp_eq(qmodp, pm1, pl)) {
        err = SD_E_KEY_FORMAT;
        goto fail;
      }
    }
    sd_mp_montmul(k->qinv_m, pm1, k->p_r2, k->p, k->p_m0i, pl);
  }
  if (d) {
    /* Consistency self-check: one private operation on a fixed value must verify. */
    sd_limb *v = (sd_limb *)sd_calloc(2 * nl, sizeof(sd_limb));
    if (v == NULL) {
      err = SD_E_NO_MEMORY;
      goto fail;
    }
    v[0] = 2;
    err = rsa_private(k, v, v + nl);
    sd_secure_free(v, 2 * nl * sizeof(sd_limb));
    if (err == SD_E_CRYPTO)
      err = SD_E_KEY_FORMAT;
    if (err != SD_OK)
      goto fail;
  }
  if (tmp)
    sd_secure_free(tmp, ((pl + ql) + 2 * pl + SD_MP_MODINV_WORK(pl) + nl) * sizeof(sd_limb));
  sd_pk_scrub_stack();
  *out = k;
  return SD_OK;
fail:
  if (tmp)
    sd_secure_free(tmp, ((pl + ql) + 2 * pl + SD_MP_MODINV_WORK(pl) + nl) * sizeof(sd_limb));
  sd_rsa_free(k);
  sd_pk_scrub_stack();
  return err;
}

uint32_t sd_rsa_bits(const sd_rsa_key *k)
{
  return k ? k->bits : 0;
}

size_t sd_rsa_len(const sd_rsa_key *k)
{
  return k ? k->len : 0;
}

int sd_rsa_has_private(const sd_rsa_key *k)
{
  return k ? k->has_priv : 0;
}

sd_err sd_rsa_export_pub(const sd_rsa_key *k, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len)
{
  size_t el;
  uint8_t eb[8];
  if (k == NULL || n == NULL || n_len == NULL || e == NULL || e_len == NULL)
    return SD_E_INVALID_PARAM;
  el = (k->ebits + 7) / 8;
  if (*n_len < k->len || *e_len < el)
    return SD_E_INVALID_PARAM;
  sd_mp_to_be(n, k->len, k->n, k->nl);
  sd_mp_to_be(eb, 8, k->e, E_LIMBS);
  memcpy(e, eb + 8 - el, el);
  *n_len = k->len;
  *e_len = el;
  return SD_OK;
}

sd_err sd_rsa_pkcs1_sign(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                         uint8_t *sig, size_t *siglen)
{
  uint8_t *em;
  sd_limb *v;
  sd_err err;
  size_t nl;
  if (k == NULL || sig == NULL || siglen == NULL)
    return SD_E_INVALID_PARAM;
  if (!k->has_priv)
    return SD_E_INVALID_PARAM;
  if (*siglen < k->len)
    return SD_E_INVALID_PARAM;
  nl = k->nl;
  em = (uint8_t *)sd_alloc(k->len);
  v = (sd_limb *)sd_calloc(2 * nl, sizeof(sd_limb));
  if (em == NULL || v == NULL) {
    sd_free(em);
    sd_free(v);
    return SD_E_NO_MEMORY;
  }
  err = emsa_encode(h, digest, dlen, em, k->len);
  if (err == SD_OK) {
    sd_mp_from_be(v, nl, em, k->len);
    err = rsa_private(k, v, v + nl);
  }
  if (err == SD_OK) {
    sd_mp_to_be(sig, k->len, v + nl, nl);
    *siglen = k->len;
  }
  sd_secure_free(em, k->len);
  sd_secure_free(v, 2 * nl * sizeof(sd_limb));
  return err;
}

sd_err sd_rsa_pkcs1_verify(const sd_rsa_key *k, sd_hash_alg h, const uint8_t *digest, size_t dlen,
                           const uint8_t *sig, size_t siglen)
{
  uint8_t *em, *got;
  sd_limb *v;
  sd_err err;
  size_t nl;
  if (k == NULL || (siglen && sig == NULL))
    return SD_E_INVALID_PARAM;
  if (siglen != k->len)
    return SD_E_CRYPTO;
  nl = k->nl;
  em = (uint8_t *)sd_alloc(2 * k->len);
  v = (sd_limb *)sd_calloc(2 * nl + SD_MP_MODEXP_VT_WORK(nl), sizeof(sd_limb));
  if (em == NULL || v == NULL) {
    sd_free(em);
    sd_free(v);
    return SD_E_NO_MEMORY;
  }
  got = em + k->len;
  err = emsa_encode(h, digest, dlen, em, k->len);
  if (err == SD_OK) {
    sd_mp_from_be(v, nl, sig, siglen);
    if (sd_mp_vt_cmp(v, nl, k->n, nl) >= 0) {
      err = SD_E_CRYPTO;
    } else {
      sd_mp_modexp_vt(v + nl, v, k->e, E_LIMBS, k->n, k->n_m0i, k->n_r2, nl, v + 2 * nl);
      sd_mp_to_be(got, k->len, v + nl, nl);
      err = sd_ct_memeq(got, em, k->len) ? SD_OK : SD_E_CRYPTO;
    }
  }
  sd_free(em);
  sd_free(v);
  return err;
}
