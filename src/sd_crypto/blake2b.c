/* BLAKE2b (RFC 7693), written from the RFC; used by Argon2 (RFC 9106) for PuTTY PPK v3 keys.
 * No secret-dependent branches or indices (the message schedule permutes by public round index);
 * rotations are by constants. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static const uint64_t k_iv[8] = {
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static const uint8_t k_sigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};

static SD_FORCEINLINE uint64_t load_le64(const uint8_t *p)
{
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}

#define G(a, b, c, d, x, y)        \
  do {                             \
    v[a] = v[a] + v[b] + (x);      \
    v[d] = ROR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];            \
    v[b] = ROR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + (y);      \
    v[d] = ROR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];            \
    v[b] = ROR64(v[b] ^ v[c], 63); \
  } while (0)

/* Compression function F (RFC 7693 3.2). */
static void blake2b_compress(sd_blake2b_ctx *c, const uint8_t block[128], int last)
{
  uint64_t v[16], m[16];
  int i;
  for (i = 0; i < 16; i++)
    m[i] = load_le64(block + 8 * i);
  for (i = 0; i < 8; i++) {
    v[i] = c->h[i];
    v[i + 8] = k_iv[i];
  }
  v[12] ^= c->t[0];
  v[13] ^= c->t[1];
  if (last)
    v[14] = ~v[14];
  for (i = 0; i < 12; i++) {
    const uint8_t *s = k_sigma[i];
    G(0, 4, 8, 12, m[s[0]], m[s[1]]);
    G(1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(2, 6, 10, 14, m[s[4]], m[s[5]]);
    G(3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(0, 5, 10, 15, m[s[8]], m[s[9]]);
    G(1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(2, 7, 8, 13, m[s[12]], m[s[13]]);
    G(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (i = 0; i < 8; i++)
    c->h[i] ^= v[i] ^ v[i + 8];
  sd_secure_zero(v, sizeof(v));
  sd_secure_zero(m, sizeof(m));
}

static void add_counter(sd_blake2b_ctx *c, uint32_t n)
{
  c->t[0] += n;
  if (c->t[0] < n)
    c->t[1]++;
}

sd_err sd_blake2b_init(sd_blake2b_ctx *c, size_t outlen, const void *key, size_t keylen)
{
  if (c == NULL || outlen == 0 || outlen > 64 || keylen > 64 || (keylen && key == NULL))
    return SD_E_INVALID_PARAM;
  memset(c, 0, sizeof(*c));
  memcpy(c->h, k_iv, sizeof(c->h));
  c->h[0] ^= 0x01010000u ^ ((uint64_t)keylen << 8) ^ (uint64_t)outlen;
  c->outlen = (uint32_t)outlen;
  if (keylen) {
    memcpy(c->buf, key, keylen);
    c->buflen = 128;              /* the padded key block, compressed once more data arrives */
  }
  return SD_OK;
}

void sd_blake2b_update(sd_blake2b_ctx *c, const void *p, size_t n)
{
  const uint8_t *in = (const uint8_t *)p;
  while (n) {
    size_t take;
    if (c->buflen == 128) {       /* more input follows: this block is not the last one */
      add_counter(c, 128);
      blake2b_compress(c, c->buf, 0);
      c->buflen = 0;
    }
    take = SD_MIN(n, (size_t)(128 - c->buflen));
    memcpy(c->buf + c->buflen, in, take);
    c->buflen += (uint32_t)take;
    in += take;
    n -= take;
  }
}

void sd_blake2b_final(sd_blake2b_ctx *c, uint8_t *out)
{
  uint8_t full[64];
  add_counter(c, c->buflen);
  memset(c->buf + c->buflen, 0, 128 - c->buflen);
  blake2b_compress(c, c->buf, 1);
  memcpy(full, c->h, 64);         /* little-endian words */
  memcpy(out, full, c->outlen);
  sd_secure_zero(full, sizeof(full));
  sd_secure_zero(c, sizeof(*c));
}

sd_err sd_blake2b(uint8_t *out, size_t outlen, const void *key, size_t keylen, const void *p, size_t n)
{
  sd_blake2b_ctx c;
  sd_err err;
  if (out == NULL || (n && p == NULL))
    return SD_E_INVALID_PARAM;
  err = sd_blake2b_init(&c, outlen, key, keylen);
  if (err != SD_OK)
    return err;
  sd_blake2b_update(&c, p, n);
  sd_blake2b_final(&c, out);
  return SD_OK;
}
