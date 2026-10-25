/* DES and 3DES-EDE (FIPS 46-3, SP 800-67 Rev. 2), constant time, for 3des-cbc and DES-EDE3-CBC
 * key files (legacy, decisions.md D33; 01 §2.2).
 *
 * The eight S-boxes are evaluated together as a boolean multiplexer network on 32-bit words, one
 * nibble per box (the pre-P layout of the standard): the six S-box input bits of all boxes are
 * spread into six selector words (bit b_j of box s fills nibble s), and a 64-leaf multiplexer tree
 * whose leaves are public constants (des3_tables.inc, generated from the standard's tables by
 * des3_gen_tables.py) selects S_s(input) in every nibble at once. There is no table lookup indexed
 * by secret data, no secret-dependent branch and no shift by a secret amount. The permutations
 * (IP, FP, P, PC-1, PC-2, E) use public positions only.
 * Single blocks are processed one at a time (CBC encryption is sequential anyway). */
#include <string.h>

#include "crypto_internal.h"
#include "des3_internal.h"
#include "sd_base/sd_mem.h"

#include "des3_tables.inc"

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Bit 0 of every nibble, replicated over the nibble. */
static SD_FORCEINLINE uint32_t spread(uint32_t t)
{
  t &= 0x11111111u;
  t |= t << 1;
  t |= t << 2;
  return t;
}

/* The multiplexer network: x[0] .. x[5] are the selector words of b1 .. b6. */
static SD_FORCEINLINE uint32_t sbox_net(const uint32_t x[6])
{
  uint32_t m[32];
  unsigned i;
  for (i = 0; i < 32; i++)
    m[i] = k_des_mux[i][0] ^ (k_des_mux[i][1] & x[5]);
#define MUX_LEVEL(n, sel)                                \
  for (i = 0; i < (n); i++)                              \
    m[i] = m[2 * i] ^ ((m[2 * i] ^ m[2 * i + 1]) & (sel))
  MUX_LEVEL(16, x[4]);
  MUX_LEVEL(8, x[3]);
  MUX_LEVEL(4, x[2]);
  MUX_LEVEL(2, x[1]);
#undef MUX_LEVEL
  return m[0] ^ ((m[0] ^ m[1]) & x[0]);
}

/* f(R, K) = P(S(E(R) xor K)) with K given as six selector masks. */
static SD_FORCEINLINE uint32_t des_f(uint32_t r, const uint32_t k[6])
{
  uint32_t x[6];
  x[0] = spread(ROR32(r, 4)) ^ k[0];   /* b1: last bit of the previous nibble */
  x[1] = spread(r >> 3) ^ k[1];        /* b2 .. b5: the nibble itself */
  x[2] = spread(r >> 2) ^ k[2];
  x[3] = spread(r >> 1) ^ k[3];
  x[4] = spread(r) ^ k[4];
  x[5] = spread(ROL32(r, 1)) ^ k[5];   /* b6: first bit of the next nibble */
  return des_perm_p(sbox_net(x));
}

uint32_t sd_des_sbox_ct(unsigned box, unsigned v)
{
  uint32_t x[6];
  unsigned j;
  for (j = 0; j < 6; j++)
    x[j] = (0u - ((v >> (5 - j)) & 1u)) & (0xfu << (28 - 4 * (box & 7)));
  return (sbox_net(x) >> (28 - 4 * (box & 7))) & 0xfu;
}

/* 16 rounds and the final swap; decrypt runs the subkeys backwards. */
static void des_rounds(uint32_t *l, uint32_t *r, const uint32_t ks[16][6], int decrypt)
{
  uint32_t a = *l, b = *r;
  int i;
  for (i = 0; i < 16; i++) {
    uint32_t t = b;
    b = a ^ des_f(b, ks[decrypt ? 15 - i : i]);
    a = t;
  }
  *l = b;
  *r = a;
}

/* 64-bit permutation with public positions (1-based, MSB first), on two 32-bit halves. */
static void perm64(const uint8_t tab[64], const uint32_t in[2], uint32_t out[2])
{
  unsigned i;
  out[0] = out[1] = 0;
  for (i = 0; i < 64; i++) {
    unsigned src = (unsigned)tab[i] - 1u;
    uint32_t bit = (in[src >> 5] >> (31u - (src & 31u))) & 1u;
    out[i >> 5] |= bit << (31u - (i & 31u));
  }
}

static void des_key_schedule(uint32_t ks[16][6], const uint8_t key[8])
{
  uint32_t c = 0, d = 0;
  unsigned i, j, s;
  for (i = 0; i < 56; i++) {
    unsigned p = (unsigned)k_des_pc1[i] - 1u;
    uint32_t bit = ((uint32_t)key[p >> 3] >> (7u - (p & 7u))) & 1u;
    if (i < 28)
      c |= bit << (27u - i);
    else
      d |= bit << (55u - i);
  }
  for (i = 0; i < 16; i++) {
    unsigned sh = k_des_shifts[i];
    c = ((c << sh) | (c >> (28u - sh))) & 0x0fffffffu;
    d = ((d << sh) | (d >> (28u - sh))) & 0x0fffffffu;
    for (j = 0; j < 6; j++)
      ks[i][j] = 0;
    for (s = 0; s < 8; s++)
      for (j = 0; j < 6; j++) {
        unsigned p = (unsigned)k_des_pc2[6 * s + j];      /* 1..56 */
        uint32_t bit = p <= 28 ? (c >> (28u - p)) & 1u : (d >> (56u - p)) & 1u;
        ks[i][j] |= (0u - bit) & (0xfu << (28u - 4u * s));
      }
  }
  sd_secure_zero(&c, sizeof(c));
  sd_secure_zero(&d, sizeof(d));
}

void sd_des3_key_init(sd_des3_key *k, const uint8_t key[24])
{
  des_key_schedule(k->ks[0], key);
  des_key_schedule(k->ks[1], key + 8);
  des_key_schedule(k->ks[2], key + 16);
}

void sd_des3_key_wipe(sd_des3_key *k)
{
  sd_secure_zero(k, sizeof(*k));
}

/* EDE: E_K1, D_K2, E_K3; decryption: D_K3, E_K2, D_K1. IP/FP between stages cancel. */
void sd_des3_block(const sd_des3_key *k, int encrypt, const uint8_t in[8], uint8_t out[8])
{
  uint32_t b[2], p[2];
  b[0] = sd_load_be32(in);
  b[1] = sd_load_be32(in + 4);
  perm64(k_des_ip, b, p);
  if (encrypt) {
    des_rounds(&p[0], &p[1], k->ks[0], 0);
    des_rounds(&p[0], &p[1], k->ks[1], 1);
    des_rounds(&p[0], &p[1], k->ks[2], 0);
  } else {
    des_rounds(&p[0], &p[1], k->ks[2], 1);
    des_rounds(&p[0], &p[1], k->ks[1], 0);
    des_rounds(&p[0], &p[1], k->ks[0], 1);
  }
  perm64(k_des_fp, p, b);
  sd_store_be32(out, b[0]);
  sd_store_be32(out + 4, b[1]);
  sd_secure_zero(b, sizeof(b));
  sd_secure_zero(p, sizeof(p));
}

void sd_des3_cbc(const sd_des3_key *k, int encrypt, uint8_t iv[8], const uint8_t *in, size_t len, uint8_t *out)
{
  uint8_t blk[8], ct[8];
  size_t i, j;
  for (i = 0; i + 8 <= len; i += 8) {
    if (encrypt) {
      for (j = 0; j < 8; j++)
        blk[j] = (uint8_t)(in[i + j] ^ iv[j]);
      sd_des3_block(k, 1, blk, out + i);
      memcpy(iv, out + i, 8);
    } else {
      memcpy(ct, in + i, 8);
      sd_des3_block(k, 0, ct, blk);
      for (j = 0; j < 8; j++)
        out[i + j] = (uint8_t)(blk[j] ^ iv[j]);
      memcpy(iv, ct, 8);
    }
  }
  sd_secure_zero(blk, sizeof(blk));
}

sd_err sd_3des_cbc(int encrypt, const uint8_t key[24], const uint8_t iv[8],
                   const uint8_t *in, size_t len, uint8_t *out)
{
  sd_des3_key k;
  uint8_t chain[8];
  if (key == NULL || iv == NULL || len % 8 || (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  sd_des3_key_init(&k, key);
  memcpy(chain, iv, 8);
  sd_des3_cbc(&k, encrypt, chain, in, len, out);
  sd_des3_key_wipe(&k);
  sd_secure_zero(chain, sizeof(chain));
  return SD_OK;
}

sd_err sd_3des_ecb(int encrypt, const uint8_t key[24], const uint8_t *in, size_t len, uint8_t *out)
{
  sd_des3_key k;
  size_t i;
  if (key == NULL || len % 8 || (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  sd_des3_key_init(&k, key);
  for (i = 0; i < len; i += 8)
    sd_des3_block(&k, encrypt, in + i, out + i);
  sd_des3_key_wipe(&k);
  return SD_OK;
}
