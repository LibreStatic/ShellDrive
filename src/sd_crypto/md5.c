/* MD5 (RFC 1321), written from the RFC. Legacy only: MD5:xx:xx fingerprints shown next to the SHA-256 one for
 * comparison with old servers (01 §2.1, 5.2), and EVP_BytesToKey of encrypted PEM key files (01 §3). Not for
 * anything that needs collision resistance. Hashing has no secret-dependent branches or indices (the round
 * function and the shifts depend on the round number only); the message words on the stack are wiped. */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"

typedef struct md5_state {
  uint32_t h[4];
  uint64_t total;             /* bytes */
  uint32_t n;                 /* bytes in buf */
  uint8_t buf[64];
} md5_state;

SD_STATIC_ASSERT(sizeof(md5_state) <= sizeof(((sd_hash_ctx *)0)->opaque), "md5 ctx size");

static const uint32_t k_md5_k[64] = {
  0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
  0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
  0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
  0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
  0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
  0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
  0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
  0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static const uint8_t k_md5_r[16] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };

static void md5_blocks(uint32_t h[4], const uint8_t *p, size_t nblocks)
{
  uint32_t w[16];
  uint32_t a, b, c, d;
  unsigned i;
  while (nblocks--) {
    for (i = 0; i < 16; i++)
      w[i] = sd_load_le32(p + 4 * i);
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    for (i = 0; i < 64; i++) {
      uint32_t f, t;
      unsigned g, s;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      s = k_md5_r[(i >> 4) * 4 + (i & 3)];
      t = a + f + k_md5_k[i] + w[g];
      a = d; d = c; c = b;
      b = b + ((t << s) | (t >> (32 - s)));
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    p += 64;
  }
  sd_secure_zero(w, sizeof(w));
}

void sd_md5_state_init(uint64_t *opaque)
{
  md5_state *s = (md5_state *)opaque;
  s->h[0] = 0x67452301u;
  s->h[1] = 0xefcdab89u;
  s->h[2] = 0x98badcfeu;
  s->h[3] = 0x10325476u;
  s->total = 0;
  s->n = 0;
}

void sd_md5_state_update(uint64_t *opaque, const uint8_t *p, size_t n)
{
  md5_state *s = (md5_state *)opaque;
  s->total += n;
  if (s->n) {
    size_t take = SD_MIN(n, 64 - (size_t)s->n);
    memcpy(s->buf + s->n, p, take);
    s->n += (uint32_t)take;
    p += take;
    n -= take;
    if (s->n < 64)
      return;
    md5_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  if (n >= 64) {
    md5_blocks(s->h, p, n / 64);
    p += n & ~(size_t)63;
    n &= 63;
  }
  if (n) {
    memcpy(s->buf, p, n);
    s->n = (uint32_t)n;
  }
}

void sd_md5_state_final(uint64_t *opaque, uint8_t out[16])
{
  md5_state *s = (md5_state *)opaque;
  uint64_t bits = s->total << 3;
  unsigned i;
  s->buf[s->n++] = 0x80;
  if (s->n > 56) {
    memset(s->buf + s->n, 0, 64 - s->n);
    md5_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  memset(s->buf + s->n, 0, 56 - s->n);
  for (i = 0; i < 8; i++)                   /* the length is little-endian in MD5 */
    s->buf[56 + i] = (uint8_t)(bits >> (8 * i));
  md5_blocks(s->h, s->buf, 1);
  for (i = 0; i < 4; i++)
    sd_store_le32(out + 4 * i, s->h[i]);
}
