/* Constant-time AES (FIPS 197) without table lookups: our own bitsliced implementation.
 *
 * References read: FIPS 197; Kasper and Schwabe 2009 "Faster and timing-attack resistant AES-GCM"
 * (the bitslicing technique); Boyar and Peralta 2010/2012 "A depth-16 circuit for the AES S-box"
 * and "A new combinational logic minimization technique with applications to cryptology" (the
 * 113-gate S-box circuit, used as published). The layout, the linear layers, the inverse S-box
 * (inverse affine map around the forward circuit) and the key schedule are our own.
 *
 * Layout: four blocks at once in eight 64-bit words. Word q[b] holds bit b of every state byte:
 * bit position (col * 16 + row * 4 + block). ShiftRows is then a rotation by 16 * row restricted to
 * one nibble per 16-bit group, and the MixColumns row rotation is a nibble rotation inside each
 * 16-bit group. Only shifts by constants, AND, OR, XOR and NOT are used; there are no branches,
 * no indices and no multiplications that depend on keys or data. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* 8x8 bit transpose of x, where bit (8r + c) is row r, column c (involution). */
static SD_FORCEINLINE uint64_t transpose8(uint64_t x)
{
  uint64_t t;
  t = (x ^ (x >> 7)) & 0x00aa00aa00aa00aaull;  x ^= t ^ (t << 7);
  t = (x ^ (x >> 14)) & 0x0000cccc0000ccccull; x ^= t ^ (t << 14);
  t = (x ^ (x >> 28)) & 0x00000000f0f0f0f0ull; x ^= t ^ (t << 28);
  return x;
}

static uint64_t load_le64(const uint8_t *p)
{
  return (uint64_t)sd_load_le32(p) | ((uint64_t)sd_load_le32(p + 4) << 32);
}

static void store_le64(uint8_t *p, uint64_t v)
{
  sd_store_le32(p, (uint32_t)v);
  sd_store_le32(p + 4, (uint32_t)(v >> 32));
}

/* Byte n of x, moved to byte m (shift counts are compile-time constants: no runtime helpers). */
#define BYTE_TO(x, n, m) ((((x) >> (8 * (n))) & 0xffu) << (8 * (m)))
#define GATHER8(t, n)                                                                       \
  (BYTE_TO(t[0], n, 0) | BYTE_TO(t[1], n, 1) | BYTE_TO(t[2], n, 2) | BYTE_TO(t[3], n, 3) |  \
   BYTE_TO(t[4], n, 4) | BYTE_TO(t[5], n, 5) | BYTE_TO(t[6], n, 6) | BYTE_TO(t[7], n, 7))

/* Byte transpose of eight words: out[n] byte m = in[m] byte n. */
static void transpose_bytes(uint64_t out[8], const uint64_t t[8])
{
  out[0] = GATHER8(t, 0); out[1] = GATHER8(t, 1); out[2] = GATHER8(t, 2); out[3] = GATHER8(t, 3);
  out[4] = GATHER8(t, 4); out[5] = GATHER8(t, 5); out[6] = GATHER8(t, 6); out[7] = GATHER8(t, 7);
}

/* b[64] is byte-interleaved: b[j * 4 + k] = byte j of block k. */
static void pack(uint64_t q[8], const uint8_t b[64])
{
  uint64_t t[8];
  int g;
  for (g = 0; g < 8; g++)
    t[g] = transpose8(load_le64(b + 8 * g));
  transpose_bytes(q, t);
  sd_secure_zero(t, sizeof(t));
}

static void unpack(uint8_t b[64], const uint64_t q[8])
{
  uint64_t t[8];
  int g;
  transpose_bytes(t, q);
  for (g = 0; g < 8; g++)
    store_le64(b + 8 * g, transpose8(t[g]));
  sd_secure_zero(t, sizeof(t));
}

/* Boyar-Peralta forward S-box. U0 is the most significant bit (q[7]), S0 likewise. */
static void sbox(uint64_t q[8])
{
  uint64_t U0 = q[7], U1 = q[6], U2 = q[5], U3 = q[4], U4 = q[3], U5 = q[2], U6 = q[1], U7 = q[0];
  uint64_t T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19,
           T20, T21, T22, T23, T24, T25, T26, T27;
  uint64_t M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M16, M17, M18, M19,
           M20, M21, M22, M23, M24, M25, M26, M27, M28, M29, M30, M31, M32, M33, M34, M35, M36,
           M37, M38, M39, M40, M41, M42, M43, M44, M45, M46, M47, M48, M49, M50, M51, M52, M53,
           M54, M55, M56, M57, M58, M59, M60, M61, M62, M63;
  uint64_t L0, L1, L2, L3, L4, L5, L6, L7, L8, L9, L10, L11, L12, L13, L14, L15, L16, L17, L18,
           L19, L20, L21, L22, L23, L24, L25, L26, L27, L28, L29;

  /* top linear transform */
  T1 = U0 ^ U3;   T2 = U0 ^ U5;   T3 = U0 ^ U6;   T4 = U3 ^ U5;   T5 = U4 ^ U6;
  T6 = T1 ^ T5;   T7 = U1 ^ U2;   T8 = U7 ^ T6;   T9 = U7 ^ T7;   T10 = T6 ^ T7;
  T11 = U1 ^ U5;  T12 = U2 ^ U5;  T13 = T3 ^ T4;  T14 = T6 ^ T11; T15 = T5 ^ T11;
  T16 = T5 ^ T12; T17 = T9 ^ T16; T18 = U3 ^ U7;  T19 = T7 ^ T18; T20 = T1 ^ T19;
  T21 = U6 ^ U7;  T22 = T7 ^ T21; T23 = T2 ^ T22; T24 = T2 ^ T10; T25 = T20 ^ T17;
  T26 = T3 ^ T16; T27 = T1 ^ T12;

  /* shared non-linear middle part (GF(2^8) inversion) */
  M1 = T13 & T6;   M2 = T23 & T8;   M3 = T14 ^ M1;   M4 = T19 & U7;   M5 = M4 ^ M1;
  M6 = T3 & T16;   M7 = T22 & T9;   M8 = T26 ^ M6;   M9 = T20 & T17;  M10 = M9 ^ M6;
  M11 = T1 & T15;  M12 = T4 & T27;  M13 = M12 ^ M11; M14 = T2 & T10;  M15 = M14 ^ M11;
  M16 = M3 ^ M2;   M17 = M5 ^ T24;  M18 = M8 ^ M7;   M19 = M10 ^ M15; M20 = M16 ^ M13;
  M21 = M17 ^ M15; M22 = M18 ^ M13; M23 = M19 ^ T25; M24 = M22 ^ M23; M25 = M22 & M20;
  M26 = M21 ^ M25; M27 = M20 ^ M21; M28 = M23 ^ M25; M29 = M28 & M27; M30 = M26 & M24;
  M31 = M20 & M23; M32 = M27 & M31; M33 = M27 ^ M25; M34 = M21 & M22; M35 = M24 & M34;
  M36 = M24 ^ M25; M37 = M21 ^ M29; M38 = M32 ^ M33; M39 = M23 ^ M30; M40 = M35 ^ M36;
  M41 = M38 ^ M40; M42 = M37 ^ M39; M43 = M37 ^ M38; M44 = M39 ^ M40; M45 = M42 ^ M41;
  M46 = M44 & T6;  M47 = M40 & T8;  M48 = M39 & U7;  M49 = M43 & T16; M50 = M38 & T9;
  M51 = M37 & T17; M52 = M42 & T15; M53 = M45 & T27; M54 = M41 & T10; M55 = M44 & T13;
  M56 = M40 & T23; M57 = M39 & T19; M58 = M43 & T3;  M59 = M38 & T22; M60 = M37 & T20;
  M61 = M42 & T1;  M62 = M45 & T4;  M63 = M41 & T2;

  /* bottom linear transform */
  L0 = M61 ^ M62;  L1 = M50 ^ M56;  L2 = M46 ^ M48;  L3 = M47 ^ M55;  L4 = M54 ^ M58;
  L5 = M49 ^ M61;  L6 = M62 ^ L5;   L7 = M46 ^ L3;   L8 = M51 ^ M59;  L9 = M52 ^ M53;
  L10 = M53 ^ L4;  L11 = M60 ^ L2;  L12 = M48 ^ M51; L13 = M50 ^ L0;  L14 = M52 ^ M61;
  L15 = M55 ^ L1;  L16 = M56 ^ L0;  L17 = M57 ^ L1;  L18 = M58 ^ L8;  L19 = M63 ^ L4;
  L20 = L0 ^ L1;   L21 = L1 ^ L7;   L22 = L3 ^ L12;  L23 = L18 ^ L2;  L24 = L15 ^ L9;
  L25 = L6 ^ L10;  L26 = L7 ^ L9;   L27 = L8 ^ L10;  L28 = L11 ^ L14; L29 = L11 ^ L17;

  q[7] = L6 ^ L24;
  q[6] = ~(L16 ^ L26);
  q[5] = ~(L19 ^ L28);
  q[4] = L6 ^ L21;
  q[3] = L20 ^ L22;
  q[2] = L25 ^ L29;
  q[1] = ~(L13 ^ L27);
  q[0] = ~(L6 ^ L23);
}

/* Inverse affine map of InvSubBytes: b'_i = b_(i+2) ^ b_(i+5) ^ b_(i+7) ^ (0x05)_i. */
static void inv_affine(uint64_t q[8])
{
  uint64_t r[8];
  int i;
  for (i = 0; i < 8; i++)
    r[i] = q[(i + 2) & 7] ^ q[(i + 5) & 7] ^ q[(i + 7) & 7];
  r[0] = ~r[0];
  r[2] = ~r[2];
  memcpy(q, r, sizeof(r));
}

/* InvS(x) = L(S(L(x))) with L the inverse affine map, since L(S(y)) = y^-1. */
static void inv_sbox(uint64_t q[8])
{
  inv_affine(q);
  sbox(q);
  inv_affine(q);
}

static void shift_rows(uint64_t q[8])
{
  int i;
  for (i = 0; i < 8; i++) {
    uint64_t x = q[i];
    q[i] = (x & 0x000f000f000f000full) | (ROR64(x, 16) & 0x00f000f000f000f0ull) |
           (ROR64(x, 32) & 0x0f000f000f000f00ull) | (ROR64(x, 48) & 0xf000f000f000f000ull);
  }
}

static void inv_shift_rows(uint64_t q[8])
{
  int i;
  for (i = 0; i < 8; i++) {
    uint64_t x = q[i];
    q[i] = (x & 0x000f000f000f000full) | (ROR64(x, 48) & 0x00f000f000f000f0ull) |
           (ROR64(x, 32) & 0x0f000f000f000f00ull) | (ROR64(x, 16) & 0xf000f000f000f000ull);
  }
}

/* Row r takes row r + n of the same column. */
static SD_FORCEINLINE uint64_t rot_rows1(uint64_t x)
{
  return ((x >> 4) & 0x0fff0fff0fff0fffull) | ((x << 12) & 0xf000f000f000f000ull);
}
static SD_FORCEINLINE uint64_t rot_rows2(uint64_t x)
{
  return ((x >> 8) & 0x00ff00ff00ff00ffull) | ((x << 8) & 0xff00ff00ff00ff00ull);
}

/* Multiplication by x in GF(2^8) on bit planes (x^8 = x^4 + x^3 + x + 1). */
static void xtime(uint64_t r[8], const uint64_t t[8])
{
  uint64_t hi = t[7];
  r[7] = t[6]; r[6] = t[5]; r[5] = t[4];
  r[4] = t[3] ^ hi; r[3] = t[2] ^ hi;
  r[2] = t[1]; r[1] = t[0] ^ hi; r[0] = hi;
}

static void mix_columns(uint64_t q[8])
{
  uint64_t r1[8], t[8], x2[8];
  int i;
  for (i = 0; i < 8; i++) {
    r1[i] = rot_rows1(q[i]);
    t[i] = q[i] ^ r1[i];
  }
  xtime(x2, t);
  /* out_r = 2 (a_r ^ a_r+1) ^ a_r+1 ^ a_r+2 ^ a_r+3 */
  for (i = 0; i < 8; i++)
    q[i] = x2[i] ^ r1[i] ^ rot_rows2(q[i] ^ r1[i]);
}

static void inv_mix_columns(uint64_t q[8])
{
  uint64_t v[8], w[8], w2[8];
  int i;
  /* InvMixColumns = MixColumns o (05 + 04 x^2): u_r = a_r ^ 4 (a_r ^ a_r+2) */
  for (i = 0; i < 8; i++)
    v[i] = q[i] ^ rot_rows2(q[i]);
  xtime(w, v);
  xtime(w2, w);
  for (i = 0; i < 8; i++)
    q[i] ^= w2[i];
  mix_columns(q);
}

static void add_round_key(uint64_t q[8], const uint64_t rk[8])
{
  int i;
  for (i = 0; i < 8; i++)
    q[i] ^= rk[i];
}

uint8_t sd_aes_sbox_ct(uint8_t x, int inverse)
{
  uint64_t q[8];
  int i;
  for (i = 0; i < 8; i++)
    q[i] = (uint64_t)(((uint32_t)x >> i) & 1u);
  if (inverse)
    inv_sbox(q);
  else
    sbox(q);
  x = 0;
  for (i = 0; i < 8; i++)
    x = (uint8_t)(x | (((uint32_t)q[i] & 1u) << i));
  return x;
}

/* SubWord on 4 bytes (key schedule) through the same circuit: byte i in bit i of each plane. */
static void sub_word(uint8_t w[4])
{
  uint64_t q[8];
  int i, b;
  for (b = 0; b < 8; b++) {
    uint32_t v = 0;
    for (i = 0; i < 4; i++)
      v |= (((uint32_t)w[i] >> b) & 1u) << i;
    q[b] = v;
  }
  sbox(q);
  for (i = 0; i < 4; i++) {
    uint8_t x = 0;
    for (b = 0; b < 8; b++)
      x = (uint8_t)(x | ((((uint32_t)q[b] >> i) & 1u) << b));
    w[i] = x;
  }
  sd_secure_zero(q, sizeof(q));
}

sd_err sd_aes_own_init(sd_aes_own *k, const uint8_t *key, size_t key_len)
{
  uint8_t w[60 * 4], b[64];
  uint8_t rcon = 1;
  size_t nk, total, i;
  uint32_t r;
  if (key_len != 16 && key_len != 24 && key_len != 32)
    return SD_E_INVALID_PARAM;
  nk = key_len / 4;
  k->rounds = (uint32_t)(nk + 6);
  total = 4 * (k->rounds + 1);
  /* The key schedule below stays the constant-time bitsliced S-box circuit on every path; AES-NI only takes
     the resulting byte round keys for the encryption rounds. */
  memset(k->ni_rk, 0, sizeof(k->ni_rk));
  k->hw = (uint32_t)(sd_crypto_use_hw_aes() ? 1 : 0);
  memcpy(w, key, key_len);
  for (i = nk; i < total; i++) {
    uint8_t t[4];
    memcpy(t, w + 4 * (i - 1), 4);
    if (i % nk == 0) {
      uint8_t x = t[0];
      t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = x;
      sub_word(t);
      t[0] ^= rcon;
      rcon = (uint8_t)((rcon << 1) ^ ((rcon >> 7) * 0x1b));    /* public round constant */
    } else if (nk > 6 && i % nk == 4) {
      sub_word(t);
    }
    w[4 * i + 0] = (uint8_t)(w[4 * (i - nk) + 0] ^ t[0]);
    w[4 * i + 1] = (uint8_t)(w[4 * (i - nk) + 1] ^ t[1]);
    w[4 * i + 2] = (uint8_t)(w[4 * (i - nk) + 2] ^ t[2]);
    w[4 * i + 3] = (uint8_t)(w[4 * (i - nk) + 3] ^ t[3]);
    sd_secure_zero(t, sizeof(t));
  }
  for (r = 0; r <= k->rounds; r++) {
    int j, blk;
    for (j = 0; j < 16; j++)
      for (blk = 0; blk < 4; blk++)
        b[j * 4 + blk] = w[16 * r + j];
    pack(k->rk[r], b);
  }
#if SD_CRYPTO_X86_HW
  if (k->hw)
    memcpy(k->ni_rk, w, 16 * (size_t)(k->rounds + 1));
#endif
  sd_secure_zero(w, sizeof(w));
  sd_secure_zero(b, sizeof(b));
  return SD_OK;
}

void sd_aes_own_wipe(sd_aes_own *k)
{
  sd_secure_zero(k, sizeof(*k));
}

static void gather(uint8_t b[64], const uint8_t *in, size_t nblocks)
{
  size_t j, blk;
  memset(b, 0, 64);
  for (blk = 0; blk < nblocks; blk++)
    for (j = 0; j < 16; j++)
      b[j * 4 + blk] = in[16 * blk + j];
}

static void scatter(uint8_t *out, const uint8_t b[64], size_t nblocks)
{
  size_t j, blk;
  for (blk = 0; blk < nblocks; blk++)
    for (j = 0; j < 16; j++)
      out[16 * blk + j] = b[j * 4 + blk];
}

void sd_aes_own_encrypt(const sd_aes_own *k, const uint8_t *in, uint8_t *out, size_t nblocks)
{
  uint64_t q[8];
  uint8_t b[64];
  uint32_t r;
#if SD_CRYPTO_X86_HW
  /* k->hw is a CPU capability chosen at key setup, not a secret; AES-NI itself has no data-dependent timing. */
  if (k->hw) {
    sd_aes_ni_encrypt_blocks(k->ni_rk[0], k->rounds, in, out, nblocks);
    return;
  }
#endif
  gather(b, in, nblocks);
  pack(q, b);
  add_round_key(q, k->rk[0]);
  for (r = 1; r < k->rounds; r++) {
    sbox(q);
    shift_rows(q);
    mix_columns(q);
    add_round_key(q, k->rk[r]);
  }
  sbox(q);
  shift_rows(q);
  add_round_key(q, k->rk[k->rounds]);
  unpack(b, q);
  scatter(out, b, nblocks);
  sd_secure_zero(q, sizeof(q));
  sd_secure_zero(b, sizeof(b));
}

void sd_aes_own_decrypt(const sd_aes_own *k, const uint8_t *in, uint8_t *out, size_t nblocks)
{
  uint64_t q[8];
  uint8_t b[64];
  uint32_t r;
  gather(b, in, nblocks);
  pack(q, b);
  add_round_key(q, k->rk[k->rounds]);
  for (r = k->rounds - 1; r > 0; r--) {
    inv_shift_rows(q);
    inv_sbox(q);
    add_round_key(q, k->rk[r]);
    inv_mix_columns(q);
  }
  inv_shift_rows(q);
  inv_sbox(q);
  add_round_key(q, k->rk[0]);
  unpack(b, q);
  scatter(out, b, nblocks);
  sd_secure_zero(q, sizeof(q));
  sd_secure_zero(b, sizeof(b));
}

static void ctr_inc128(uint8_t c[16])
{
  int i;
  uint32_t carry = 1;
  for (i = 15; i >= 0; i--) {
    carry += c[i];
    c[i] = (uint8_t)carry;
    carry >>= 8;
  }
}

void sd_aes_own_ctr(const sd_aes_own *k, uint8_t ctr[16], const uint8_t *in, size_t len, uint8_t *out)
{
  uint8_t blocks[64], ks[64];
  while (len) {
    size_t n = SD_MIN(len, (size_t)64), nb = (n + 15) / 16, i;
    for (i = 0; i < nb; i++) {
      memcpy(blocks + 16 * i, ctr, 16);
      ctr_inc128(ctr);
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
