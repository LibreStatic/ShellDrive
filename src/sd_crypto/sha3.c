/* SHA3-256, SHA3-512, SHAKE128, SHAKE256 (FIPS 202), written from the standard.
 *
 * Keccak-f[1600] on 25 64-bit lanes, lane (x, y) at a[x + 5y], bytes little-endian (FIPS 202 B.1).
 * All rotations are by compile-time constants (on 32-bit targets the compiler inlines them as
 * 32-bit shift pairs, no runtime helper; constant-time gate in tools/sd-isacheck). Byte access to the
 * state goes through an unsigned char view, so no 64-bit shift by a run-time count appears. The
 * permutation has no data-dependent branches or indices. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static SD_FORCEINLINE uint64_t sd_load_le64(const uint8_t *p)
{
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}

static const uint64_t k_rc[24] = {
  0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
  0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
  0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
  0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
  0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
  0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull,
};

/* Keccak-p[1600, 24] (FIPS 202 3.3, 3.4): theta, rho, pi, chi, iota. */
static void keccak_f1600(uint64_t a[25])
{
  uint64_t b[25], c0, c1, c2, c3, c4, d0, d1, d2, d3, d4;
  int r, y;
  for (r = 0; r < 24; r++) {
    /* theta */
    c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    d0 = c4 ^ ROL64(c1, 1);
    d1 = c0 ^ ROL64(c2, 1);
    d2 = c1 ^ ROL64(c3, 1);
    d3 = c2 ^ ROL64(c4, 1);
    d4 = c3 ^ ROL64(c0, 1);
    for (y = 0; y < 25; y += 5) {
      a[y + 0] ^= d0;
      a[y + 1] ^= d1;
      a[y + 2] ^= d2;
      a[y + 3] ^= d3;
      a[y + 4] ^= d4;
    }
    /* rho and pi: B[y, 2x + 3y] = ROT(A[x, y], r[x, y]) */
    b[0] = a[0];
    b[10] = ROL64(a[1], 1);
    b[20] = ROL64(a[2], 62);
    b[5] = ROL64(a[3], 28);
    b[15] = ROL64(a[4], 27);
    b[16] = ROL64(a[5], 36);
    b[1] = ROL64(a[6], 44);
    b[11] = ROL64(a[7], 6);
    b[21] = ROL64(a[8], 55);
    b[6] = ROL64(a[9], 20);
    b[7] = ROL64(a[10], 3);
    b[17] = ROL64(a[11], 10);
    b[2] = ROL64(a[12], 43);
    b[12] = ROL64(a[13], 25);
    b[22] = ROL64(a[14], 39);
    b[23] = ROL64(a[15], 41);
    b[8] = ROL64(a[16], 45);
    b[18] = ROL64(a[17], 15);
    b[3] = ROL64(a[18], 21);
    b[13] = ROL64(a[19], 8);
    b[14] = ROL64(a[20], 18);
    b[24] = ROL64(a[21], 2);
    b[9] = ROL64(a[22], 61);
    b[19] = ROL64(a[23], 56);
    b[4] = ROL64(a[24], 14);
    /* chi */
    for (y = 0; y < 25; y += 5) {
      a[y + 0] = b[y + 0] ^ (~b[y + 1] & b[y + 2]);
      a[y + 1] = b[y + 1] ^ (~b[y + 2] & b[y + 3]);
      a[y + 2] = b[y + 2] ^ (~b[y + 3] & b[y + 4]);
      a[y + 3] = b[y + 3] ^ (~b[y + 4] & b[y + 0]);
      a[y + 4] = b[y + 4] ^ (~b[y + 0] & b[y + 1]);
    }
    /* iota */
    a[0] ^= k_rc[r];
  }
  sd_secure_zero(b, sizeof(b));
}

static void keccak_init(sd_keccak_ctx *c, uint32_t rate, uint8_t pad, uint8_t outlen)
{
  memset(c, 0, sizeof(*c));
  c->rate = rate;
  c->pad = pad;
  c->outlen = outlen;
}

static void keccak_absorb(sd_keccak_ctx *c, const uint8_t *p, size_t n)
{
  uint8_t *s = (uint8_t *)c->a;
  size_t i;
  while (n) {
    size_t take = SD_MIN(n, (size_t)(c->rate - c->pos));
    if (c->pos == 0 && take == c->rate) {
      for (i = 0; i < take / 8; i++)
        c->a[i] ^= sd_load_le64(p + 8 * i);
    } else {
      for (i = 0; i < take; i++)
        s[c->pos + i] ^= p[i];
    }
    c->pos += (uint32_t)take;
    p += take;
    n -= take;
    if (c->pos == c->rate) {
      keccak_f1600(c->a);
      c->pos = 0;
    }
  }
}

/* Pads (domain bits + pad10*1) and switches to squeezing; pos becomes the read offset. */
static void keccak_finish_absorb(sd_keccak_ctx *c)
{
  uint8_t *s = (uint8_t *)c->a;
  s[c->pos] ^= c->pad;
  s[c->rate - 1] ^= 0x80;
  keccak_f1600(c->a);
  c->pos = 0;
  c->squeezing = 1;
}

static void keccak_squeeze(sd_keccak_ctx *c, uint8_t *out, size_t n)
{
  const uint8_t *s = (const uint8_t *)c->a;
  while (n) {
    size_t take;
    if (c->pos == c->rate) {
      keccak_f1600(c->a);
      c->pos = 0;
    }
    take = SD_MIN(n, (size_t)(c->rate - c->pos));
    memcpy(out, s + c->pos, take);
    c->pos += (uint32_t)take;
    out += take;
    n -= take;
  }
}

void sd_keccak_wipe(sd_keccak_ctx *c)
{
  if (c)
    sd_secure_zero(c, sizeof(*c));
}

void sd_sha3_init(sd_keccak_ctx *c, int bits)
{
  if (bits == 512)
    keccak_init(c, 72, 0x06, 64);
  else
    keccak_init(c, 136, 0x06, 32);
}

void sd_sha3_update(sd_keccak_ctx *c, const void *p, size_t n)
{
  if (n)
    keccak_absorb(c, (const uint8_t *)p, n);
}

void sd_sha3_final(sd_keccak_ctx *c, uint8_t *out)
{
  keccak_finish_absorb(c);
  keccak_squeeze(c, out, c->outlen);
  sd_keccak_wipe(c);
}

void sd_sha3_256(uint8_t out[32], const void *p, size_t n)
{
  sd_keccak_ctx c;
  sd_sha3_init(&c, 256);
  sd_sha3_update(&c, p, n);
  sd_sha3_final(&c, out);
}

void sd_sha3_512(uint8_t out[64], const void *p, size_t n)
{
  sd_keccak_ctx c;
  sd_sha3_init(&c, 512);
  sd_sha3_update(&c, p, n);
  sd_sha3_final(&c, out);
}

void sd_shake_init(sd_keccak_ctx *c, int bits)
{
  if (bits == 256)
    keccak_init(c, 136, 0x1f, 0);
  else
    keccak_init(c, 168, 0x1f, 0);
}

void sd_shake_absorb(sd_keccak_ctx *c, const void *p, size_t n)
{
  if (n && !c->squeezing)
    keccak_absorb(c, (const uint8_t *)p, n);
}

void sd_shake_squeeze(sd_keccak_ctx *c, uint8_t *out, size_t n)
{
  if (!c->squeezing)
    keccak_finish_absorb(c);
  keccak_squeeze(c, out, n);
}

void sd_shake(int bits, uint8_t *out, size_t outlen, const void *p, size_t n)
{
  sd_keccak_ctx c;
  sd_shake_init(&c, bits);
  sd_shake_absorb(&c, p, n);
  sd_shake_squeeze(&c, out, outlen);
  sd_keccak_wipe(&c);
}
