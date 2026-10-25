/* SHA-1 (FIPS 180-4 §6.1), written from the standard. Legacy only: ssh-rsa, hmac-sha1, the *-sha1 key
 * exchanges and hashed known_hosts (01 §2.1). Plugged into the generic sd_hash_* API as SD_HASH_SHA1
 * (hash.c dispatches here). No secret-dependent branches or indices; the message schedule is wiped. */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"

typedef struct sha1_state {
  uint32_t h[5];
  uint64_t total;             /* bytes */
  uint32_t n;                 /* bytes in buf */
  uint8_t buf[64];
} sha1_state;

SD_STATIC_ASSERT(sizeof(sha1_state) <= sizeof(((sd_hash_ctx *)0)->opaque), "sha1 ctx size");

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_blocks(uint32_t st[5], const uint8_t *p, size_t nblocks)
{
  uint32_t w[80];
  uint32_t a, b, c, d, e, t;
  int i;
  while (nblocks--) {
    for (i = 0; i < 16; i++)
      w[i] = sd_load_be32(p + 4 * i);
    for (i = 16; i < 80; i++)
      w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4];
    for (i = 0; i < 20; i++) {
      t = ROL32(a, 5) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w[i];
      e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    for (; i < 40; i++) {
      t = ROL32(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1u + w[i];
      e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    for (; i < 60; i++) {
      t = ROL32(a, 5) + ((b & c) | (d & (b | c))) + e + 0x8f1bbcdcu + w[i];
      e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    for (; i < 80; i++) {
      t = ROL32(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6u + w[i];
      e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e;
    p += 64;
  }
  sd_secure_zero(w, sizeof(w));
}

void sd_sha1_state_init(uint64_t *opaque)
{
  sha1_state *s = (sha1_state *)opaque;
  memset(s, 0, sizeof(*s));
  s->h[0] = 0x67452301u;
  s->h[1] = 0xefcdab89u;
  s->h[2] = 0x98badcfeu;
  s->h[3] = 0x10325476u;
  s->h[4] = 0xc3d2e1f0u;
}

void sd_sha1_state_update(uint64_t *opaque, const uint8_t *p, size_t n)
{
  sha1_state *s = (sha1_state *)opaque;
  s->total += n;
  if (s->n) {
    size_t take = SD_MIN(n, 64 - (size_t)s->n);
    memcpy(s->buf + s->n, p, take);
    s->n += (uint32_t)take;
    p += take;
    n -= take;
    if (s->n < 64)
      return;
    sha1_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  if (n >= 64) {
    sha1_blocks(s->h, p, n / 64);
    p += n & ~(size_t)63;
    n &= 63;
  }
  if (n) {
    memcpy(s->buf, p, n);
    s->n = (uint32_t)n;
  }
}

void sd_sha1_state_final(uint64_t *opaque, uint8_t out[20])
{
  sha1_state *s = (sha1_state *)opaque;
  uint64_t bits = s->total << 3;
  int i;
  s->buf[s->n++] = 0x80;
  if (s->n > 56) {
    memset(s->buf + s->n, 0, 64 - s->n);
    sha1_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  memset(s->buf + s->n, 0, 56 - s->n);
  sd_store_be64(s->buf + 56, bits);
  sha1_blocks(s->h, s->buf, 1);
  for (i = 0; i < 5; i++)
    sd_store_be32(out + 4 * i, s->h[i]);
}
