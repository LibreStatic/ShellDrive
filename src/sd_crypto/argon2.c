/* Argon2d / Argon2i / Argon2id, version 0x13 (RFC 9106), written from the RFC, for PuTTY PPK v3
 * key files (01 §2.2, §7.4). Memory comes from VirtualAlloc and is wiped before it is released.
 * Lanes are processed sequentially on the calling thread (results are identical to a parallel
 * run: within a slice no lane reads another lane's current segment).
 * Argon2d and the second half of Argon2id index memory by data, by design of the algorithm; the
 * passphrase still never drives a branch. The 32x32 products of the BlaMka function use SD_MUL32
 * (no runtime helper on 32-bit x86). */
#include <windows.h>

#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_ct64.h"

#define ARGON2_VERSION 0x13u
#define BLOCK_WORDS    128
#define SYNC_POINTS    4

typedef struct argon2_block { uint64_t v[BLOCK_WORDS]; } argon2_block;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void store_le32(uint8_t *p, uint32_t v)
{
  memcpy(p, &v, 4);
}

/* H' (RFC 9106 3.3): variable-length hash built on BLAKE2b. */
static void blake2b_long(uint8_t *out, uint32_t outlen, const uint8_t *in, size_t inlen)
{
  sd_blake2b_ctx c;
  uint8_t len_le[4], v[64];
  store_le32(len_le, outlen);
  if (outlen <= 64) {
    sd_blake2b_init(&c, outlen, NULL, 0);
    sd_blake2b_update(&c, len_le, 4);
    sd_blake2b_update(&c, in, inlen);
    sd_blake2b_final(&c, out);
    return;
  }
  sd_blake2b_init(&c, 64, NULL, 0);
  sd_blake2b_update(&c, len_le, 4);
  sd_blake2b_update(&c, in, inlen);
  sd_blake2b_final(&c, v);
  memcpy(out, v, 32);
  out += 32;
  outlen -= 32;
  while (outlen > 64) {
    sd_blake2b(v, 64, NULL, 0, v, 64);
    memcpy(out, v, 32);
    out += 32;
    outlen -= 32;
  }
  sd_blake2b(v, outlen, NULL, 0, v, 64);
  memcpy(out, v, outlen);
  sd_secure_zero(v, sizeof(v));
}

/* ---- compression function G (RFC 9106 3.5, 3.6) ---- */

static SD_FORCEINLINE uint64_t blamka(uint64_t x, uint64_t y)
{
  return x + y + (SD_MUL32((uint32_t)x, (uint32_t)y) << 1);
}

#define GB(a, b, c, d)            \
  do {                            \
    a = blamka(a, b);             \
    d = ROR64(d ^ a, 32);         \
    c = blamka(c, d);             \
    b = ROR64(b ^ c, 24);         \
    a = blamka(a, b);             \
    d = ROR64(d ^ a, 16);         \
    c = blamka(c, d);             \
    b = ROR64(b ^ c, 63);         \
  } while (0)

/* Permutation P on sixteen 64-bit words given by index (eight 16-byte registers). */
#define PERM(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) \
  do {                                                                              \
    GB(v0, v4, v8, v12);                                                            \
    GB(v1, v5, v9, v13);                                                            \
    GB(v2, v6, v10, v14);                                                           \
    GB(v3, v7, v11, v15);                                                           \
    GB(v0, v5, v10, v15);                                                           \
    GB(v1, v6, v11, v12);                                                           \
    GB(v2, v7, v8, v13);                                                            \
    GB(v3, v4, v9, v14);                                                            \
  } while (0)

/* out = G(x, y) (xor_into: out ^= G(x, y), version 0x13 passes after the first). */
static void fill_block(const argon2_block *x, const argon2_block *y, argon2_block *out, int xor_into)
{
  argon2_block r, z;
  unsigned i;
  for (i = 0; i < BLOCK_WORDS; i++)
    r.v[i] = z.v[i] = x->v[i] ^ y->v[i];
  for (i = 0; i < 8; i++) {
    uint64_t *w = z.v + 16 * i;
    PERM(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14],
         w[15]);
  }
  for (i = 0; i < 8; i++) {
    uint64_t *w = z.v + 2 * i;
    PERM(w[0], w[1], w[16], w[17], w[32], w[33], w[48], w[49], w[64], w[65], w[80], w[81], w[96], w[97],
         w[112], w[113]);
  }
  if (xor_into) {
    for (i = 0; i < BLOCK_WORDS; i++)
      out->v[i] ^= z.v[i] ^ r.v[i];
  } else {
    for (i = 0; i < BLOCK_WORDS; i++)
      out->v[i] = z.v[i] ^ r.v[i];
  }
  sd_secure_zero(&r, sizeof(r));
  sd_secure_zero(&z, sizeof(z));
}

/* ---- memory filling (RFC 9106 3.2, 3.4) ---- */

typedef struct argon2_inst {
  argon2_block *mem;
  uint32_t lanes, lane_len, seg_len, passes, blocks;
  sd_argon2_type type;
} argon2_inst;

typedef struct addr_state {
  argon2_block input, addr, zero;
} addr_state;

static void next_addresses(addr_state *a)
{
  argon2_block tmp;
  a->input.v[6]++;
  fill_block(&a->zero, &a->input, &tmp, 0);
  fill_block(&a->zero, &tmp, &a->addr, 0);
  sd_secure_zero(&tmp, sizeof(tmp));
}

static void fill_segment(const argon2_inst *in, uint32_t pass, uint32_t lane, uint32_t slice, addr_state *as)
{
  int indep = in->type == SD_ARGON2I || (in->type == SD_ARGON2ID && pass == 0 && slice < SYNC_POINTS / 2);
  uint32_t start = (pass == 0 && slice == 0) ? 2u : 0u, i;
  uint32_t cur = lane * in->lane_len + slice * in->seg_len + start;
  if (indep) {
    memset(as, 0, sizeof(*as));
    as->input.v[0] = pass;
    as->input.v[1] = lane;
    as->input.v[2] = slice;
    as->input.v[3] = in->blocks;
    as->input.v[4] = in->passes;
    as->input.v[5] = (uint64_t)in->type;
  }
  for (i = start; i < in->seg_len; i++, cur++) {
    uint64_t rnd;
    uint32_t j1, j2, ref_lane, area, x, y, rel, start_pos, ref_index, prev;
    prev = (slice == 0 && i == 0) ? cur + in->lane_len - 1 : cur - 1;   /* previous block, wrapping in the lane */
    if (indep) {
      if (i == start || i % BLOCK_WORDS == 0)
        next_addresses(as);
      rnd = as->addr.v[i % BLOCK_WORDS];
    } else {
      rnd = in->mem[prev].v[0];
    }
    j1 = (uint32_t)rnd;
    j2 = (uint32_t)(rnd >> 32);
    ref_lane = (pass == 0 && slice == 0) ? lane : j2 % in->lanes;
    /* reference area (RFC 9106 3.4.1.2) */
    if (pass == 0) {
      if (ref_lane == lane)
        area = slice * in->seg_len + i - 1;
      else
        area = slice * in->seg_len - (i == 0 ? 1u : 0u);
    } else {
      if (ref_lane == lane)
        area = in->lane_len - in->seg_len + i - 1;
      else
        area = in->lane_len - in->seg_len - (i == 0 ? 1u : 0u);
    }
    x = (uint32_t)(SD_MUL32(j1, j1) >> 32);
    y = (uint32_t)(SD_MUL32(area, x) >> 32);
    rel = area - 1 - y;
    start_pos = (pass != 0 && slice != SYNC_POINTS - 1) ? (slice + 1) * in->seg_len : 0;
    ref_index = (start_pos + rel) % in->lane_len;
    fill_block(&in->mem[prev], &in->mem[ref_lane * in->lane_len + ref_index], &in->mem[cur], pass != 0);
  }
}

sd_err sd_argon2_ex(sd_argon2_type t, uint32_t mem_kib, uint32_t passes, uint32_t lanes,
                    const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                    const uint8_t *secret, size_t secretlen, const uint8_t *ad, size_t adlen,
                    uint8_t *out, size_t outlen, volatile long *cancel)
{
  argon2_inst in;
  addr_state as;
  sd_blake2b_ctx h;
  uint8_t h0[72], le[4], blockbytes[1024];
  size_t bytes;
  uint32_t r, s, l, i;
  sd_err err = SD_OK;
  if ((t != SD_ARGON2D && t != SD_ARGON2I && t != SD_ARGON2ID) || out == NULL || outlen < 4 ||
      outlen > 0xffffffffu || passes == 0 || lanes == 0 || (plen && pass == NULL) ||
      (slen && salt == NULL) || (secretlen && secret == NULL) || (adlen && ad == NULL) ||
      plen > 0xffffffffu || slen > 0xffffffffu || secretlen > 0xffffffffu || adlen > 0xffffffffu)
    return SD_E_INVALID_PARAM;
  if (lanes > SD_ARGON2_MAX_LANES || passes > SD_ARGON2_MAX_PASSES || mem_kib > SD_ARGON2_MAX_MEM_KIB)
    return SD_E_UNSUPPORTED;
  if (mem_kib < 8 * lanes)
    return SD_E_INVALID_PARAM;

  /* H0 (RFC 9106 3.2 step 1) */
  sd_blake2b_init(&h, 64, NULL, 0);
#define LE32(v) (store_le32(le, (uint32_t)(v)), sd_blake2b_update(&h, le, 4))
  LE32(lanes);
  LE32(outlen);
  LE32(mem_kib);
  LE32(passes);
  LE32(ARGON2_VERSION);
  LE32(t);
  LE32(plen);
  sd_blake2b_update(&h, pass, plen);
  LE32(slen);
  sd_blake2b_update(&h, salt, slen);
  LE32(secretlen);
  sd_blake2b_update(&h, secret, secretlen);
  LE32(adlen);
  sd_blake2b_update(&h, ad, adlen);
#undef LE32
  sd_blake2b_final(&h, h0);

  in.type = t;
  in.lanes = lanes;
  in.passes = passes;
  in.seg_len = mem_kib / (SYNC_POINTS * lanes);
  in.lane_len = in.seg_len * SYNC_POINTS;
  in.blocks = in.lane_len * lanes;
  bytes = (size_t)in.blocks * sizeof(argon2_block);
  in.mem = (argon2_block *)VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (in.mem == NULL) {
    sd_secure_zero(h0, sizeof(h0));
    return SD_E_NO_MEMORY;
  }

  /* first two blocks of every lane (step 3, 4) */
  for (l = 0; l < lanes; l++) {
    for (i = 0; i < 2; i++) {
      store_le32(h0 + 64, i);
      store_le32(h0 + 68, l);
      blake2b_long(blockbytes, 1024, h0, 72);
      memcpy(&in.mem[l * in.lane_len + i], blockbytes, 1024);
    }
  }
  for (r = 0; r < passes && err == SD_OK; r++)
    for (s = 0; s < SYNC_POINTS && err == SD_OK; s++) {
      for (l = 0; l < lanes; l++)
        fill_segment(&in, r, l, s, &as);
      if (cancel && *cancel)
        err = SD_E_CANCELLED;
    }
  if (err == SD_OK) {
    /* final block C = xor of the last column, tag = H'^T(C) */
    argon2_block *c = &in.mem[in.lane_len - 1];
    for (l = 1; l < lanes; l++)
      for (i = 0; i < BLOCK_WORDS; i++)
        c->v[i] ^= in.mem[l * in.lane_len + in.lane_len - 1].v[i];
    memcpy(blockbytes, c, 1024);
    blake2b_long(out, (uint32_t)outlen, blockbytes, 1024);
  }
  sd_secure_zero(in.mem, bytes);
  VirtualFree(in.mem, 0, MEM_RELEASE);
  sd_secure_zero(&as, sizeof(as));
  sd_secure_zero(blockbytes, sizeof(blockbytes));
  sd_secure_zero(h0, sizeof(h0));
  return err;
}

sd_err sd_argon2(sd_argon2_type t, uint32_t mem_kib, uint32_t passes, uint32_t lanes,
                 const void *pass, size_t plen, const uint8_t *salt, size_t slen,
                 uint8_t *out, size_t outlen, volatile long *cancel)
{
  return sd_argon2_ex(t, mem_kib, passes, lanes, pass, plen, salt, slen, NULL, 0, NULL, 0, out, outlen,
                      cancel);
}
