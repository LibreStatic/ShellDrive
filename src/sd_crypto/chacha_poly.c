/* ChaCha20 (Bernstein 2008, original 64-bit nonce / 64-bit counter layout used by OpenSSH; RFC 8439
 * §2.1-2.4 for the quarter round and block function) and Poly1305 (RFC 8439 §2.5, Bernstein 2005).
 * Written from the specifications. Poly1305 uses five 26-bit limbs with 32x32->64 products
 * (SD_MUL32), on every target. No secret-dependent branches or indices. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_ct64.h"

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)                    \
  a += b; d ^= a; d = ROL32(d, 16);       \
  c += d; b ^= c; b = ROL32(b, 12);       \
  a += b; d ^= a; d = ROL32(d, 8);        \
  c += d; b ^= c; b = ROL32(b, 7)

static void chacha_block(const uint32_t in[16], uint32_t out[16])
{
  uint32_t x0 = in[0], x1 = in[1], x2 = in[2], x3 = in[3], x4 = in[4], x5 = in[5], x6 = in[6],
           x7 = in[7], x8 = in[8], x9 = in[9], x10 = in[10], x11 = in[11], x12 = in[12],
           x13 = in[13], x14 = in[14], x15 = in[15];
  int i;
  for (i = 0; i < 10; i++) {
    QR(x0, x4, x8, x12); QR(x1, x5, x9, x13); QR(x2, x6, x10, x14); QR(x3, x7, x11, x15);
    QR(x0, x5, x10, x15); QR(x1, x6, x11, x12); QR(x2, x7, x8, x13); QR(x3, x4, x9, x14);
  }
  out[0] = x0 + in[0];    out[1] = x1 + in[1];    out[2] = x2 + in[2];    out[3] = x3 + in[3];
  out[4] = x4 + in[4];    out[5] = x5 + in[5];    out[6] = x6 + in[6];    out[7] = x7 + in[7];
  out[8] = x8 + in[8];    out[9] = x9 + in[9];    out[10] = x10 + in[10]; out[11] = x11 + in[11];
  out[12] = x12 + in[12]; out[13] = x13 + in[13]; out[14] = x14 + in[14]; out[15] = x15 + in[15];
}

void sd_chacha20(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter,
                 const uint8_t *in, size_t len, uint8_t *out)
{
  uint32_t st[16], ks[16];
  int k;
  st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
  for (k = 0; k < 8; k++)
    st[4 + k] = sd_load_le32(key + 4 * k);
  st[12] = (uint32_t)counter;
  st[13] = (uint32_t)(counter >> 32);
  st[14] = sd_load_le32(nonce);
  st[15] = sd_load_le32(nonce + 4);
  while (len >= 64) {
    chacha_block(st, ks);
    for (k = 0; k < 16; k++)
      sd_store_le32(out + 4 * k, sd_load_le32(in + 4 * k) ^ ks[k]);
    in += 64;
    out += 64;
    len -= 64;
    if (++st[12] == 0)
      st[13]++;
  }
  if (len) {
    uint8_t tail[64];
    size_t i;
    chacha_block(st, ks);
    for (k = 0; k < 16; k++)
      sd_store_le32(tail + 4 * k, ks[k]);
    for (i = 0; i < len; i++)
      out[i] = (uint8_t)(in[i] ^ tail[i]);
    sd_secure_zero(tail, sizeof(tail));
  }
  sd_secure_zero(st, sizeof(st));
  sd_secure_zero(ks, sizeof(ks));
}

/* ---- Poly1305 ---- */

#define M26 0x3ffffffu

typedef struct poly1305 {
  uint32_t r[5], s4[4], h[5], pad[4];
} poly1305;

static void poly_init(poly1305 *p, const uint8_t key[32])
{
  uint32_t t0 = sd_load_le32(key), t1 = sd_load_le32(key + 4), t2 = sd_load_le32(key + 8),
           t3 = sd_load_le32(key + 12);
  int i;
  /* r is clamped (RFC 8439 §2.5.1) while splitting into 26-bit limbs. */
  p->r[0] = t0 & 0x3ffffffu;
  p->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
  p->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
  p->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
  p->r[4] = (t3 >> 8) & 0x00fffffu;
  for (i = 0; i < 4; i++)
    p->s4[i] = p->r[i + 1] * 5u;
  memset(p->h, 0, sizeof(p->h));
  for (i = 0; i < 4; i++)
    p->pad[i] = sd_load_le32(key + 16 + 4 * i);
}

static void poly_blocks(poly1305 *p, const uint8_t *m, size_t nblocks, uint32_t hibit)
{
  uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
  uint32_t s1 = p->s4[0], s2 = p->s4[1], s3 = p->s4[2], s4 = p->s4[3];
  uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
  while (nblocks--) {
    uint32_t t0 = sd_load_le32(m), t1 = sd_load_le32(m + 4), t2 = sd_load_le32(m + 8),
             t3 = sd_load_le32(m + 12);
    uint64_t d0, d1, d2, d3, d4, c;
    h0 += t0 & M26;
    h1 += ((t0 >> 26) | (t1 << 6)) & M26;
    h2 += ((t1 >> 20) | (t2 << 12)) & M26;
    h3 += ((t2 >> 14) | (t3 << 18)) & M26;
    h4 += (t3 >> 8) | hibit;
    d0 = SD_MUL32(h0, r0) + SD_MUL32(h1, s4) + SD_MUL32(h2, s3) + SD_MUL32(h3, s2) + SD_MUL32(h4, s1);
    d1 = SD_MUL32(h0, r1) + SD_MUL32(h1, r0) + SD_MUL32(h2, s4) + SD_MUL32(h3, s3) + SD_MUL32(h4, s2);
    d2 = SD_MUL32(h0, r2) + SD_MUL32(h1, r1) + SD_MUL32(h2, r0) + SD_MUL32(h3, s4) + SD_MUL32(h4, s3);
    d3 = SD_MUL32(h0, r3) + SD_MUL32(h1, r2) + SD_MUL32(h2, r1) + SD_MUL32(h3, r0) + SD_MUL32(h4, s4);
    d4 = SD_MUL32(h0, r4) + SD_MUL32(h1, r3) + SD_MUL32(h2, r2) + SD_MUL32(h3, r1) + SD_MUL32(h4, r0);
    c = d0 >> 26; h0 = (uint32_t)d0 & M26; d1 += c;
    c = d1 >> 26; h1 = (uint32_t)d1 & M26; d2 += c;
    c = d2 >> 26; h2 = (uint32_t)d2 & M26; d3 += c;
    c = d3 >> 26; h3 = (uint32_t)d3 & M26; d4 += c;
    c = d4 >> 26; h4 = (uint32_t)d4 & M26;
    c = (uint64_t)h0 + (c << 2) + c;
    h0 = (uint32_t)c & M26;
    h1 += (uint32_t)(c >> 26);
    m += 16;
  }
  p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

static void poly_finish(poly1305 *p, uint8_t tag[16])
{
  uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
  uint32_t g0, g1, g2, g3, g4, c, mask, w0, w1, w2, w3;
  uint64_t f;
  c = h1 >> 26; h1 &= M26; h2 += c;
  c = h2 >> 26; h2 &= M26; h3 += c;
  c = h3 >> 26; h3 &= M26; h4 += c;
  c = h4 >> 26; h4 &= M26; h0 += c * 5u;
  c = h0 >> 26; h0 &= M26; h1 += c;
  /* g = h + 5 - 2^130; use it when it does not go negative (h >= p). */
  g0 = h0 + 5u; c = g0 >> 26; g0 &= M26;
  g1 = h1 + c;  c = g1 >> 26; g1 &= M26;
  g2 = h2 + c;  c = g2 >> 26; g2 &= M26;
  g3 = h3 + c;  c = g3 >> 26; g3 &= M26;
  g4 = h4 + c - (1u << 26);
  mask = (g4 >> 31) - 1u;              /* all ones when g4 >= 0 */
  h0 = (h0 & ~mask) | (g0 & mask);
  h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask);
  h3 = (h3 & ~mask) | (g3 & mask);
  h4 = (h4 & ~mask) | (g4 & mask);
  w0 = h0 | (h1 << 26);
  w1 = (h1 >> 6) | (h2 << 20);
  w2 = (h2 >> 12) | (h3 << 14);
  w3 = (h3 >> 18) | (h4 << 8);
  f = (uint64_t)w0 + p->pad[0];             sd_store_le32(tag, (uint32_t)f);
  f = (uint64_t)w1 + p->pad[1] + (f >> 32); sd_store_le32(tag + 4, (uint32_t)f);
  f = (uint64_t)w2 + p->pad[2] + (f >> 32); sd_store_le32(tag + 8, (uint32_t)f);
  f = (uint64_t)w3 + p->pad[3] + (f >> 32); sd_store_le32(tag + 12, (uint32_t)f);
}

void sd_poly1305(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[32])
{
  poly1305 p;
  poly_init(&p, key);
  if (len >= 16) {
    poly_blocks(&p, msg, len / 16, 1u << 24);
    msg += len & ~(size_t)15;
    len &= 15;
  }
  if (len) {
    uint8_t last[16];
    memset(last, 0, sizeof(last));
    memcpy(last, msg, len);
    last[len] = 1;
    poly_blocks(&p, last, 1, 0);
    sd_secure_zero(last, sizeof(last));
  }
  poly_finish(&p, tag);
  sd_secure_zero(&p, sizeof(p));
}
