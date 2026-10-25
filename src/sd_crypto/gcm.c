/* AES-GCM (NIST SP 800-38D) and AES-CTR dispatch, own GHASH in constant time.
 *
 * GHASH multiplies in GF(2^128) with carry-less products emulated by integer multiplications on
 * operands whose bits are spaced four apart ("multiplication with holes", described in public
 * constant-time write-ups): 32x32 carry-less products from sixteen 32x32->64 MULs (SD_MUL32), two
 * Karatsuba levels for 128x128, and a shift-and-xor reduction in the bit-reflected representation
 * of SP 800-38D. No tables, no data-dependent branches.
 *
 * Dispatch (01 §2.2): own HW > CNG > own bitsliced. M0 has no AES-NI path yet, so CNG is used when
 * probed and allowed, else the own bitsliced core. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"

/* ---- GHASH ---- */

static uint64_t bmul32(uint32_t x, uint32_t y)
{
  uint32_t x0 = x & 0x11111111u, x1 = x & 0x22222222u, x2 = x & 0x44444444u, x3 = x & 0x88888888u;
  uint32_t y0 = y & 0x11111111u, y1 = y & 0x22222222u, y2 = y & 0x44444444u, y3 = y & 0x88888888u;
  uint64_t z0 = SD_MUL32(x0, y0) ^ SD_MUL32(x1, y3) ^ SD_MUL32(x2, y2) ^ SD_MUL32(x3, y1);
  uint64_t z1 = SD_MUL32(x0, y1) ^ SD_MUL32(x1, y0) ^ SD_MUL32(x2, y3) ^ SD_MUL32(x3, y2);
  uint64_t z2 = SD_MUL32(x0, y2) ^ SD_MUL32(x1, y1) ^ SD_MUL32(x2, y0) ^ SD_MUL32(x3, y3);
  uint64_t z3 = SD_MUL32(x0, y3) ^ SD_MUL32(x1, y2) ^ SD_MUL32(x2, y1) ^ SD_MUL32(x3, y0);
  return (z0 & 0x1111111111111111ull) | (z1 & 0x2222222222222222ull) |
         (z2 & 0x4444444444444444ull) | (z3 & 0x8888888888888888ull);
}

static void clmul64(uint64_t x, uint64_t y, uint64_t *hi, uint64_t *lo)
{
  uint32_t x0 = (uint32_t)x, x1 = (uint32_t)(x >> 32), y0 = (uint32_t)y, y1 = (uint32_t)(y >> 32);
  uint64_t z0 = bmul32(x0, y0), z2 = bmul32(x1, y1);
  uint64_t z1 = bmul32(x0 ^ x1, y0 ^ y1) ^ z0 ^ z2;
  *lo = z0 ^ (z1 << 32);
  *hi = z2 ^ (z1 >> 32);
}

/* y = y * h in GF(2^128); both as (high, low) big-endian halves of the reflected block value. */
static void gf128_mul(uint64_t y[2], const uint64_t h[2])
{
  uint64_t p0h, p0l, p1h, p1l, p2h, p2l, r0, r1, r2, r3, z0, z1, z2, z3, hi, lo, o;
  clmul64(y[1], h[1], &p0h, &p0l);
  clmul64(y[0], h[0], &p2h, &p2l);
  clmul64(y[0] ^ y[1], h[0] ^ h[1], &p1h, &p1l);
  p1h ^= p0h ^ p2h;
  p1l ^= p0l ^ p2l;
  r0 = p0l; r1 = p0h ^ p1l; r2 = p2l ^ p1h; r3 = p2h;
  /* The reflected product has 255 bits; shift left once so bit (255 - k) holds x^k. */
  z3 = (r3 << 1) | (r2 >> 63);
  z2 = (r2 << 1) | (r1 >> 63);
  z1 = (r1 << 1) | (r0 >> 63);
  z0 = r0 << 1;
  /* (z3:z2) holds x^0..x^127, (z1:z0) = H holds x^128..x^255; x^128 = 1 + x + x^2 + x^7. Multiplying
     by x is a right shift in this representation; bits shifted out (degree >= 128 again) are folded
     a second time through o. */
  hi = z1 ^ (z1 >> 1) ^ (z1 >> 2) ^ (z1 >> 7);
  lo = z0 ^ ((z0 >> 1) | (z1 << 63)) ^ ((z0 >> 2) | (z1 << 62)) ^ ((z0 >> 7) | (z1 << 57));
  o = (z0 << 63) ^ (z0 << 62) ^ (z0 << 57);
  hi ^= o ^ (o >> 1) ^ (o >> 2) ^ (o >> 7);
  lo ^= (o << 63) ^ (o << 62) ^ (o << 57);
  y[0] = z3 ^ hi;
  y[1] = z2 ^ lo;
}

void sd_ghash_init(sd_ghash *g, const uint8_t h[16])
{
  g->h[0] = sd_load_be64(h);
  g->h[1] = sd_load_be64(h + 8);
  g->y[0] = g->y[1] = 0;
}

void sd_ghash_update(sd_ghash *g, const uint8_t *p, size_t n)
{
  while (n) {
    uint8_t blk[16];
    size_t take = SD_MIN(n, (size_t)16);
    const uint8_t *src = p;
    if (take < 16) {
      memset(blk, 0, sizeof(blk));
      memcpy(blk, p, take);
      src = blk;
    }
    g->y[0] ^= sd_load_be64(src);
    g->y[1] ^= sd_load_be64(src + 8);
    gf128_mul(g->y, g->h);
    p += take;
    n -= take;
  }
}

void sd_ghash_lengths(sd_ghash *g, uint64_t aad_len, uint64_t ct_len)
{
  g->y[0] ^= aad_len << 3;
  g->y[1] ^= ct_len << 3;
  gf128_mul(g->y, g->h);
}

void sd_ghash_out(const sd_ghash *g, uint8_t out[16])
{
  sd_store_be64(out, g->y[0]);
  sd_store_be64(out + 8, g->y[1]);
}

/* ---- GCM over the own AES core ---- */

void sd_gcm_own_ctr32(const sd_aes_own *k, uint8_t ctr[16], const uint8_t *in, size_t len, uint8_t *out)
{
  uint8_t blocks[64], ks[64];
  while (len) {
    size_t n = SD_MIN(len, (size_t)64), nb = (n + 15) / 16, i;
    for (i = 0; i < nb; i++) {
      memcpy(blocks + 16 * i, ctr, 16);
      sd_store_be32(ctr + 12, sd_load_be32(ctr + 12) + 1);
    }
    sd_aes_own_encrypt(k, blocks, ks, nb);
    for (i = 0; i < n; i++)
      out[i] = (uint8_t)(in[i] ^ ks[i]);
    in += n;
    out += n;
    len -= n;
  }
  sd_secure_zero(ks, sizeof(ks));
}

static int gcm_len_ok(size_t aad_len, size_t len)
{
  /* SP 800-38D: P <= 2^39 - 256 bits, A < 2^64 bits. */
  return (uint64_t)len <= ((uint64_t)1 << 36) - 32 && (uint64_t)aad_len < ((uint64_t)1 << 61);
}

void sd_gcm_own_tag(const sd_aes_own *k, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, uint8_t tag[16])
{
  uint8_t in[32], out[32];
  sd_ghash g;
  int i;
  memset(in, 0, sizeof(in));
  memcpy(in + 16, nonce, 12);
  in[31] = 1;
  sd_aes_own_encrypt(k, in, out, 2);             /* H = E(0), E(J0) */
  sd_ghash_init(&g, out);
  sd_ghash_update(&g, aad, aad_len);
  sd_ghash_update(&g, ct, len);
  sd_ghash_lengths(&g, aad_len, len);
  sd_ghash_out(&g, tag);
  for (i = 0; i < 16; i++)
    tag[i] ^= out[16 + i];
  sd_secure_zero(out, sizeof(out));
  sd_secure_zero(&g, sizeof(g));
}

sd_err sd_aes_gcm_encrypt_own(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16])
{
  sd_aes_own k;
  uint8_t ctr[16];
  sd_err err;
  if (!gcm_len_ok(aad_len, len))
    return SD_E_INVALID_PARAM;
  err = sd_aes_own_init(&k, key, key_len);
  if (err != SD_OK)
    return err;
  memcpy(ctr, nonce, 12);
  sd_store_be32(ctr + 12, 2);
  sd_gcm_own_ctr32(&k, ctr, in, len, out);
  sd_gcm_own_tag(&k, nonce, aad, aad_len, out, len, tag);
  sd_aes_own_wipe(&k);
  return SD_OK;
}

sd_err sd_aes_gcm_decrypt_own(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              const uint8_t tag[16], uint8_t *out)
{
  sd_aes_own k;
  uint8_t ctr[16], calc[16];
  sd_err err;
  if (!gcm_len_ok(aad_len, len))
    return SD_E_INVALID_PARAM;
  err = sd_aes_own_init(&k, key, key_len);
  if (err != SD_OK)
    return err;
  sd_gcm_own_tag(&k, nonce, aad, aad_len, in, len, calc);
  if (!sd_ct_memeq(calc, tag, 16)) {
    sd_aes_own_wipe(&k);
    return SD_E_CRYPTO;                          /* nothing released before verification */
  }
  memcpy(ctr, nonce, 12);
  sd_store_be32(ctr + 12, 2);
  sd_gcm_own_ctr32(&k, ctr, in, len, out);
  sd_aes_own_wipe(&k);
  return SD_OK;
}

sd_err sd_aes_ctr_own(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                      const uint8_t *in, size_t len, uint8_t *out)
{
  sd_aes_own k;
  uint8_t c[16];
  sd_err err = sd_aes_own_init(&k, key, key_len);
  if (err != SD_OK)
    return err;
  memcpy(c, ctr, 16);
  sd_aes_own_ctr(&k, c, in, len, out);
  sd_aes_own_wipe(&k);
  return SD_OK;
}

/* ---- public dispatch ---- */

sd_err sd_aes_ctr(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                  const uint8_t *in, size_t len, uint8_t *out)
{
  if (key == NULL || ctr == NULL || (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  if (sd_crypto_use_cng_aes()) {
    sd_err err = sd_aes_ctr_cng(key, key_len, ctr, in, len, out);
    if (err != SD_E_UNSUPPORTED)
      return err;
  }
  return sd_aes_ctr_own(key, key_len, ctr, in, len, out);
}

sd_err sd_aes_gcm_encrypt(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          uint8_t *out, uint8_t tag[16])
{
  if (key == NULL || nonce == NULL || tag == NULL || (aad_len && aad == NULL) ||
      (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  if (sd_crypto_use_cng_gcm()) {
    sd_err err = sd_aes_gcm_encrypt_cng(key, key_len, nonce, aad, aad_len, in, len, out, tag);
    if (err != SD_E_UNSUPPORTED)
      return err;
  }
  return sd_aes_gcm_encrypt_own(key, key_len, nonce, aad, aad_len, in, len, out, tag);
}

sd_err sd_aes_gcm_decrypt(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                          const uint8_t tag[16], uint8_t *out)
{
  if (key == NULL || nonce == NULL || tag == NULL || (aad_len && aad == NULL) ||
      (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  if (sd_crypto_use_cng_gcm()) {
    sd_err err = sd_aes_gcm_decrypt_cng(key, key_len, nonce, aad, aad_len, in, len, tag, out);
    if (err != SD_E_UNSUPPORTED)
      return err;
  }
  return sd_aes_gcm_decrypt_own(key, key_len, nonce, aad, aad_len, in, len, tag, out);
}
