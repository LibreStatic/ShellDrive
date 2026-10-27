/* SHA-256, SHA-384, SHA-512 (FIPS 180-4), HMAC (RFC 2104 / FIPS 198-1) and PBKDF2 (RFC 8018 §5.2).
 * Written from the standards; always own code (decisions.md D2). Hashing has no secret-dependent
 * branches or indices; message schedules on the stack are wiped once per update call. */
#include <string.h>

#include "crypto_internal.h"
#include "pk_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_ct64.h"

#include "sha2_consts.inc"

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

typedef struct sha256_state {
  uint32_t h[8];
  uint64_t total;             /* bytes */
  uint32_t n;                 /* bytes in buf */
  uint8_t buf[64];
} sha256_state;

typedef struct sha512_state {
  uint64_t h[8];
  uint64_t total;             /* bytes (2^64 bytes is far beyond any input we hash) */
  uint32_t n;
  uint8_t buf[128];
} sha512_state;

SD_STATIC_ASSERT(sizeof(sha256_state) <= sizeof(((sd_hash_ctx *)0)->opaque), "sha256 ctx size");
SD_STATIC_ASSERT(sizeof(sha512_state) <= sizeof(((sd_hash_ctx *)0)->opaque), "sha512 ctx size");

/* ---- SHA-256 ---- */

#define S256_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define S256_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
/* One round; the caller rotates the variable names instead of moving values. */
#define R256(a, b, c, d, e, f, g, h, i)                     \
  t1 = h + S256_1(e) + CH(e, f, g) + k_sha256_k[i] + w[i];  \
  d += t1;                                                  \
  h = t1 + S256_0(a) + MAJ(a, b, c)

/* The portable block function is the reference; the SHA extensions (sha256_ni.c) take over when the CPU has
   them and the portable hook is off. The choice depends on the CPU only, never on the message. It is the
   constant-time core of the SHA-256 block path (sd-isacheck, _ct name); SD_NOINLINE keeps it a separate
   function for the gate. */
SD_NOINLINE static void sha256_blocks_portable_ct(uint32_t st[8], const uint8_t *p, size_t nblocks)
{
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h, t1;
  int i;
  while (nblocks--) {
    /* Scalar loads only: at /arch:SSE2 the vectorizer would turn this into SSSE3 PSHUFB (not on the x86-sse2
       floor) with overlap and length-split branches around it. */
    SD_CT_NO_VECTOR
    for (i = 0; i < 16; i++)
      w[i] = sd_load_be32(p + 4 * i);
    for (i = 16; i < 64; i++) {
      uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 64; i += 8) {
      R256(a, b, c, d, e, f, g, h, i + 0);
      R256(h, a, b, c, d, e, f, g, i + 1);
      R256(g, h, a, b, c, d, e, f, i + 2);
      R256(f, g, h, a, b, c, d, e, i + 3);
      R256(e, f, g, h, a, b, c, d, i + 4);
      R256(d, e, f, g, h, a, b, c, i + 5);
      R256(c, d, e, f, g, h, a, b, i + 6);
      R256(b, c, d, e, f, g, h, a, i + 7);
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    p += 64;
  }
  sd_secure_zero(w, sizeof(w));
}

static void sha256_blocks(uint32_t st[8], const uint8_t *p, size_t nblocks)
{
#if SD_CRYPTO_X86_HW
  if (nblocks != 0 && sd_crypto_use_hw_sha256()) {
    sd_sha256_ni_blocks_ct(st, p, nblocks, k_sha256_k);
    return;
  }
#endif
  sha256_blocks_portable_ct(st, p, nblocks);
}

static void sha256_update(sha256_state *s, const uint8_t *p, size_t n)
{
  s->total += n;
  if (s->n) {
    size_t take = SD_MIN(n, 64 - (size_t)s->n);
    memcpy(s->buf + s->n, p, take);
    s->n += (uint32_t)take;
    p += take;
    n -= take;
    if (s->n < 64)
      return;
    sha256_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  if (n >= 64) {
    sha256_blocks(s->h, p, n / 64);
    p += n & ~(size_t)63;
    n &= 63;
  }
  if (n) {
    memcpy(s->buf, p, n);
    s->n = (uint32_t)n;
  }
}

static void sha256_final(sha256_state *s, uint8_t *out, size_t outlen)
{
  uint64_t bits = s->total << 3;
  size_t i;
  s->buf[s->n++] = 0x80;
  if (s->n > 56) {
    memset(s->buf + s->n, 0, 64 - s->n);
    sha256_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  memset(s->buf + s->n, 0, 56 - s->n);
  sd_store_be64(s->buf + 56, bits);
  sha256_blocks(s->h, s->buf, 1);
  for (i = 0; i < outlen / 4; i++)
    sd_store_be32(out + 4 * i, s->h[i]);
}

/* ---- SHA-512 / SHA-384 ---- */

#define S512_0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define S512_1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define R512(a, b, c, d, e, f, g, h, i)                     \
  t1 = h + S512_1(e) + CH(e, f, g) + k_sha512_k[i] + w[i];  \
  d += t1;                                                  \
  h = t1 + S512_0(a) + MAJ(a, b, c)

static void sha512_blocks(uint64_t st[8], const uint8_t *p, size_t nblocks)
{
  uint64_t w[80];
  uint64_t a, b, c, d, e, f, g, h, t1;
  int i;
  while (nblocks--) {
    for (i = 0; i < 16; i++)
      w[i] = sd_load_be64(p + 8 * i);
    for (i = 16; i < 80; i++) {
      uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3]; e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 80; i += 8) {
      R512(a, b, c, d, e, f, g, h, i + 0);
      R512(h, a, b, c, d, e, f, g, i + 1);
      R512(g, h, a, b, c, d, e, f, i + 2);
      R512(f, g, h, a, b, c, d, e, i + 3);
      R512(e, f, g, h, a, b, c, d, i + 4);
      R512(d, e, f, g, h, a, b, c, i + 5);
      R512(c, d, e, f, g, h, a, b, i + 6);
      R512(b, c, d, e, f, g, h, a, i + 7);
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    p += 128;
  }
  sd_secure_zero(w, sizeof(w));
}

static void sha512_update(sha512_state *s, const uint8_t *p, size_t n)
{
  s->total += n;
  if (s->n) {
    size_t take = SD_MIN(n, 128 - (size_t)s->n);
    memcpy(s->buf + s->n, p, take);
    s->n += (uint32_t)take;
    p += take;
    n -= take;
    if (s->n < 128)
      return;
    sha512_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  if (n >= 128) {
    sha512_blocks(s->h, p, n / 128);
    p += n & ~(size_t)127;
    n &= 127;
  }
  if (n) {
    memcpy(s->buf, p, n);
    s->n = (uint32_t)n;
  }
}

static void sha512_final(sha512_state *s, uint8_t *out, size_t outlen)
{
  uint64_t total = s->total;
  size_t i;
  s->buf[s->n++] = 0x80;
  if (s->n > 112) {
    memset(s->buf + s->n, 0, 128 - s->n);
    sha512_blocks(s->h, s->buf, 1);
    s->n = 0;
  }
  memset(s->buf + s->n, 0, 112 - s->n);
  sd_store_be64(s->buf + 112, total >> 61);
  sd_store_be64(s->buf + 120, total << 3);
  sha512_blocks(s->h, s->buf, 1);
  for (i = 0; i < outlen / 8; i++)
    sd_store_be64(out + 8 * i, s->h[i]);
}

/* ---- generic hash API ---- */

size_t sd_hash_len(sd_hash_alg alg)
{
  switch ((int)alg) {
  case SD_HASH_SHA1: return 20;
  case SD_HASH_SHA256: return 32;
  case SD_HASH_SHA384: return 48;
  case SD_HASH_SHA512: return 64;
  default: return 0;
  }
}

size_t sd_hash_block_len(sd_hash_alg alg)
{
  switch ((int)alg) {
  case SD_HASH_SHA1:
  case SD_HASH_SHA256: return 64;
  case SD_HASH_SHA384:
  case SD_HASH_SHA512: return 128;
  default: return 0;
  }
}

void sd_hash_init(sd_hash_ctx *c, sd_hash_alg alg)
{
  memset(c, 0, sizeof(*c));
  c->alg = alg;
  if (alg == SD_HASH_SHA1) {
    sd_sha1_state_init(c->opaque);
  } else if (alg == SD_HASH_SHA256) {
    sha256_state *s = (sha256_state *)c->opaque;
    memcpy(s->h, k_sha256_iv, sizeof(s->h));
  } else if (alg == SD_HASH_SHA384 || alg == SD_HASH_SHA512) {
    sha512_state *s = (sha512_state *)c->opaque;
    memcpy(s->h, alg == SD_HASH_SHA384 ? k_sha384_iv : k_sha512_iv, sizeof(s->h));
  }
}

void sd_hash_update(sd_hash_ctx *c, const void *p, size_t n)
{
  if (n == 0)
    return;
  if (c->alg == SD_HASH_SHA1)
    sd_sha1_state_update(c->opaque, (const uint8_t *)p, n);
  else if (c->alg == SD_HASH_SHA256)
    sha256_update((sha256_state *)c->opaque, (const uint8_t *)p, n);
  else if (c->alg == SD_HASH_SHA384 || c->alg == SD_HASH_SHA512)
    sha512_update((sha512_state *)c->opaque, (const uint8_t *)p, n);
}

void sd_hash_final(sd_hash_ctx *c, uint8_t *out)
{
  if (c->alg == SD_HASH_SHA1)
    sd_sha1_state_final(c->opaque, out);
  else if (c->alg == SD_HASH_SHA256)
    sha256_final((sha256_state *)c->opaque, out, 32);
  else if (c->alg == SD_HASH_SHA384 || c->alg == SD_HASH_SHA512)
    sha512_final((sha512_state *)c->opaque, out, sd_hash_len(c->alg));
  sd_secure_zero(c, sizeof(*c));
}

void sd_hash(sd_hash_alg alg, const void *p, size_t n, uint8_t *out)
{
  sd_hash_ctx c;
  sd_hash_init(&c, alg);
  sd_hash_update(&c, p, n);
  sd_hash_final(&c, out);
}

/* ---- HMAC ---- */

void sd_hmac_init(sd_hmac_ctx *c, sd_hash_alg alg, const void *key, size_t klen)
{
  uint8_t k0[SD_HASH_MAX_BLOCK], pad[SD_HASH_MAX_BLOCK];
  size_t bl = sd_hash_block_len(alg), i;
  memset(k0, 0, sizeof(k0));
  if (klen > bl) {
    sd_hash(alg, key, klen, k0);
  } else {
    const uint8_t *kb = (const uint8_t *)key;
    for (i = 0; i < klen; i++)
      k0[i] = kb[i];
  }
  for (i = 0; i < bl; i++)
    pad[i] = (uint8_t)(k0[i] ^ 0x36);
  sd_hash_init(&c->inner0, alg);
  sd_hash_update(&c->inner0, pad, bl);
  for (i = 0; i < bl; i++)
    pad[i] = (uint8_t)(k0[i] ^ 0x5c);
  sd_hash_init(&c->outer0, alg);
  sd_hash_update(&c->outer0, pad, bl);
  c->inner = c->inner0;
  c->outer = c->outer0;
  sd_secure_zero(k0, sizeof(k0));
  sd_secure_zero(pad, sizeof(pad));
}

void sd_hmac_update(sd_hmac_ctx *c, const void *p, size_t n)
{
  sd_hash_update(&c->inner, p, n);
}

void sd_hmac_final(sd_hmac_ctx *c, uint8_t *out)
{
  uint8_t ih[SD_HASH_MAX_LEN];
  size_t hl = sd_hash_len(c->inner.alg);
  sd_hash_final(&c->inner, ih);
  sd_hash_update(&c->outer, ih, hl);
  sd_hash_final(&c->outer, out);
  sd_secure_zero(ih, sizeof(ih));
  sd_hmac_reset(c);
}

void sd_hmac_reset(sd_hmac_ctx *c)
{
  c->inner = c->inner0;
  c->outer = c->outer0;
}

void sd_hmac_wipe(sd_hmac_ctx *c)
{
  sd_secure_zero(c, sizeof(*c));
}

/* ---- PBKDF2 (RFC 8018 §5.2) ---- */

sd_err sd_pbkdf2_hmac(sd_hash_alg h, const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                      uint32_t iters, uint8_t *out, size_t outlen)
{
  sd_hmac_ctx base, c;
  uint8_t u[SD_HASH_MAX_LEN], t[SD_HASH_MAX_LEN], be[4];
  size_t hl = sd_hash_len(h), done = 0, i;
  uint32_t block = 1, j;
  if (hl == 0 || iters == 0 || (outlen && out == NULL) || (slen && salt == NULL) || (plen && pass == NULL))
    return SD_E_INVALID_PARAM;
  if ((uint64_t)outlen > (uint64_t)0xffffffffu * hl)
    return SD_E_INVALID_PARAM;
  sd_hmac_init(&base, h, pass, plen);
  while (done < outlen) {
    size_t take = SD_MIN(hl, outlen - done);
    c = base;
    sd_hmac_update(&c, salt, slen);
    sd_store_be32(be, block);
    sd_hmac_update(&c, be, 4);
    sd_hmac_final(&c, u);
    memcpy(t, u, hl);
    for (j = 1; j < iters; j++) {
      sd_hmac_update(&c, u, hl);
      sd_hmac_final(&c, u);
      for (i = 0; i < hl; i++)
        t[i] ^= u[i];
    }
    memcpy(out + done, t, take);
    done += take;
    block++;
  }
  sd_hmac_wipe(&base);
  sd_hmac_wipe(&c);
  sd_secure_zero(u, sizeof(u));
  sd_secure_zero(t, sizeof(t));
  return SD_OK;
}
