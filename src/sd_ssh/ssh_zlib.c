/* zlib@openssh.com codec (01 section 4.7): RFC 1951 DEFLATE and RFC 1950 framing, written for this project.
 *
 * Decoder: a resumable state machine over the bits of the input. Every decision that needs more bits than
 * are present leaves the bit position where it was and reports ZR_NEED; the unread bytes are then carried
 * to the next call together with the block state. Blocks of all three types are accepted. Code sets follow
 * zlib's rules: no over-subscribed or incomplete codes (except a single one-bit code for distances and
 * lengths), no distance codes 30 and 31, no length codes 286 and 287, and every distance must reach back
 * into the history.
 *
 * Encoder: greedy LZ77 with hash chains over the 32 KiB history, fixed Huffman codes. Kept simple on purpose:
 * the format is what interoperates, the ratio is secondary. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "ssh_zlib.h"

#define ZWIN         SSH_ZLIB_WINDOW
#define ZWMASK       (ZWIN - 1u)
#define ZCARRY_MAX   512u        /* unread bytes kept between calls: at most one dynamic block header (about 290) */
#define ZHASH_BITS   13u
#define ZHASH_SIZE   (1u << ZHASH_BITS)
#define ZMAX_CHAIN   32u
#define ZMIN_MATCH   3u
#define ZMAX_MATCH   258u
#define ZHIST_CAP    (ZWIN + SSH_ZLIB_PACKET_MAX)
#define ZCODE_EOB    256u

enum { ZR_OK = 0, ZR_NEED = 1, ZR_BAD = 2, ZR_LIMIT = 3 };
enum { ZS_HDR = 0, ZS_BLOCK, ZS_STORED, ZS_CODES, ZS_TRAILER, ZS_DONE };
enum { ZK_CODES = 0, ZK_LENS, ZK_DISTS };

static const uint16_t k_len_base[29] = {
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t k_len_extra[29] = {
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t k_dist_base[30] = {
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
  4097, 6145, 8193, 12289, 16385, 24577
};
static const uint8_t k_dist_extra[30] = {
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
static const uint8_t k_clen_order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

/* ---- Huffman codes (canonical, RFC 1951 3.2.2) ---- */

typedef struct zhuff {
  uint16_t count[16];            /* codes per length; count[0] is always 0 */
  uint16_t sym[288];             /* symbols ordered by code */
} zhuff;

/* Returns 0 for a usable table, -1 for an invalid one. An empty distance table is valid (no distance is
   ever coded); any other empty table is invalid. */
static int huff_build(zhuff *h, const uint8_t *lens, unsigned n, int kind)
{
  unsigned len, s, max = 0, left = 1, off[16];
  memset(h->count, 0, sizeof(h->count));
  for (s = 0; s < n; s++) {
    h->count[lens[s]]++;
    if (lens[s] > max) max = lens[s];
  }
  if (h->count[0] == n) return kind == ZK_DISTS ? 0 : -1;
  h->count[0] = 0;
  for (len = 1; len <= 15; len++) {
    left <<= 1;
    if (h->count[len] > left) return -1;             /* over-subscribed */
    left -= h->count[len];
  }
  /* zlib's rule: incomplete only for a single one-bit code, and never for the code-length code */
  if (left > 0 && (kind == ZK_CODES || max != 1)) return -1;
  off[1] = 0;
  for (len = 1; len < 15; len++) off[len + 1] = off[len] + h->count[len];
  for (s = 0; s < n; s++) {
    if (lens[s] != 0) h->sym[off[lens[s]]++] = (uint16_t)s;
  }
  return 0;
}

/* Reads one code bit by bit (canonical decode). ZR_NEED leaves *pos unchanged. */
static int huff_decode(const zhuff *h, const uint8_t *w, size_t nbits, size_t *pos, unsigned *sym)
{
  int code = 0, first = 0, index = 0;
  unsigned len;
  size_t p = *pos;
  for (len = 1; len <= 15; len++) {
    int count;
    if (p >= nbits) return ZR_NEED;
    code |= (w[p >> 3] >> (p & 7u)) & 1;
    p++;
    count = h->count[len];
    if (code < first + count) {
      *sym = h->sym[index + (code - first)];
      *pos = p;
      return ZR_OK;
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return ZR_BAD;
}

/* Reads n (<= 16) bits, least significant first. ZR_NEED leaves *pos unchanged. */
static int get_bits(const uint8_t *w, size_t nbits, size_t *pos, unsigned n, unsigned *v)
{
  unsigned r = 0, i;
  size_t p = *pos;
  if (p > nbits || nbits - p < n) return ZR_NEED;
  for (i = 0; i < n; i++, p++) r |= (unsigned)((w[p >> 3] >> (p & 7u)) & 1u) << i;
  *v = r;
  *pos = p;
  return ZR_OK;
}

/* ---- decoder ---- */

struct ssh_zinf {
  uint8_t win[ZWIN];             /* history: the last wcount bytes of output, circular */
  uint32_t wpos, wcount;
  int stage;
  int last;                      /* BFINAL of the current block */
  int oneshot;                   /* the stream may end: final block and RFC 1950 trailer accepted (tests, fuzz) */
  uint32_t adler_a, adler_b;     /* running Adler-32 of the output (oneshot only) */
  int failed;
  uint32_t stored_left;
  uint8_t carry[ZCARRY_MAX];     /* unread bytes from the previous call */
  size_t ncarry;
  unsigned carry_bit;            /* first unread bit of carry[0] */
  zhuff lit, dist;               /* tables of the current block */
  zhuff fix_lit, fix_dist;
};

static void zput(ssh_zinf *z, uint8_t *out, size_t *o, uint8_t b)
{
  out[*o] = b;
  (*o)++;
  if (z->oneshot) {
    z->adler_a = (z->adler_a + b) % 65521u;
    z->adler_b = (z->adler_b + z->adler_a) % 65521u;
  }
  z->win[z->wpos] = b;
  z->wpos = (z->wpos + 1u) & ZWMASK;
  if (z->wcount < ZWIN) z->wcount++;
}

/* Reads the code length tables of a dynamic block (RFC 1951 3.2.7). Writes *pos only on success. */
static int read_dynamic(ssh_zinf *z, const uint8_t *w, size_t nbits, size_t *pos)
{
  uint8_t lens[320], cl[19];
  zhuff clh;
  memset(lens, 0, sizeof(lens));
  unsigned hlit, hdist, hclen, i, idx, nl, sym, rep, v;
  uint8_t val;
  size_t p = *pos;

  if (get_bits(w, nbits, &p, 5, &hlit) != ZR_OK || get_bits(w, nbits, &p, 5, &hdist) != ZR_OK ||
      get_bits(w, nbits, &p, 4, &hclen) != ZR_OK)
    return ZR_NEED;
  hlit += 257;
  hdist += 1;
  hclen += 4;
  if (hlit > 286 || hdist > 30) return ZR_BAD;
  memset(cl, 0, sizeof(cl));
  for (i = 0; i < hclen; i++) {
    if (get_bits(w, nbits, &p, 3, &v) != ZR_OK) return ZR_NEED;
    cl[k_clen_order[i]] = (uint8_t)v;
  }
  if (huff_build(&clh, cl, 19, ZK_CODES) != 0) return ZR_BAD;

  nl = hlit + hdist;
  idx = 0;
  while (idx < nl) {
    int r = huff_decode(&clh, w, nbits, &p, &sym);
    if (r == ZR_NEED) return ZR_NEED;
    if (r != ZR_OK) return ZR_BAD;
    if (sym < 16) {
      lens[idx++] = (uint8_t)sym;
      continue;
    }
    if (sym == 16) {
      if (idx == 0) return ZR_BAD;
      if (get_bits(w, nbits, &p, 2, &v) != ZR_OK) return ZR_NEED;
      rep = 3u + v;
      val = lens[idx - 1];
    } else if (sym == 17) {
      if (get_bits(w, nbits, &p, 3, &v) != ZR_OK) return ZR_NEED;
      rep = 3u + v;
      val = 0;
    } else {
      if (get_bits(w, nbits, &p, 7, &v) != ZR_OK) return ZR_NEED;
      rep = 11u + v;
      val = 0;
    }
    if (rep > nl - idx) return ZR_BAD;
    for (i = 0; i < rep; i++) lens[idx++] = val;
  }
  if (lens[ZCODE_EOB] == 0) return ZR_BAD;
  if (huff_build(&z->lit, lens, hlit, ZK_LENS) != 0) return ZR_BAD;
  if (huff_build(&z->dist, lens + hlit, hdist, ZK_DISTS) != 0) return ZR_BAD;
  *pos = p;
  return ZR_OK;
}

static int block_end(ssh_zinf *z)
{
  if (!z->last) {
    z->stage = ZS_BLOCK;
    return ZR_OK;
  }
  /* the stream ends with this block: only a one-shot stream has a trailer; a packet stream never ends */
  if (!z->oneshot) return ZR_BAD;
  z->stage = ZS_TRAILER;
  return ZR_OK;
}

/* Runs the state machine until the input runs out (ZR_NEED), the stream ends (ZR_OK at ZS_DONE) or it fails.
   *pos is the bit position in w and only moves past complete units. */
static int zinf_run(ssh_zinf *z, const uint8_t *w, size_t nbits, size_t *pos, uint8_t *out, size_t cap, size_t *o)
{
  for (;;) {
    switch (z->stage) {
    case ZS_HDR: {
      unsigned cmf, flg;
      size_t p = *pos;
      if (get_bits(w, nbits, &p, 8, &cmf) != ZR_OK || get_bits(w, nbits, &p, 8, &flg) != ZR_OK) return ZR_NEED;
      if ((cmf & 0x0fu) != 8u || (cmf >> 4) > 7u || (flg & 0x20u) != 0 || ((cmf << 8) | flg) % 31u != 0)
        return ZR_BAD;
      *pos = p;
      z->stage = ZS_BLOCK;
      break;
    }
    case ZS_BLOCK: {
      size_t p = *pos;
      unsigned bfinal, btype, len, nlen;
      int r;
      if (get_bits(w, nbits, &p, 1, &bfinal) != ZR_OK || get_bits(w, nbits, &p, 2, &btype) != ZR_OK) return ZR_NEED;
      z->last = (int)bfinal;
      if (btype == 0) {
        p = (p + 7u) & ~(size_t)7u;                    /* stored: skip to the byte boundary */
        if (get_bits(w, nbits, &p, 16, &len) != ZR_OK || get_bits(w, nbits, &p, 16, &nlen) != ZR_OK)
          return ZR_NEED;
        if ((len ^ 0xffffu) != nlen) return ZR_BAD;
        z->stored_left = len;
        z->stage = ZS_STORED;
      } else if (btype == 1) {
        z->lit = z->fix_lit;
        z->dist = z->fix_dist;
        z->stage = ZS_CODES;
      } else if (btype == 2) {
        r = read_dynamic(z, w, nbits, &p);
        if (r != ZR_OK) return r;
        z->stage = ZS_CODES;
      } else {
        return ZR_BAD;
      }
      *pos = p;
      break;
    }
    case ZS_STORED: {
      size_t p = *pos;
      while (z->stored_left > 0) {
        if (p > nbits || nbits - p < 8) {
          *pos = p;
          return ZR_NEED;
        }
        if (*o >= cap) return ZR_LIMIT;
        zput(z, out, o, w[p >> 3]);
        p += 8;
        z->stored_left--;
      }
      *pos = p;
      if (block_end(z) != ZR_OK) return ZR_BAD;
      break;
    }
    case ZS_CODES: {
      size_t p = *pos;
      unsigned sym = 0, li, dsym = 0, extra = 0, length, dist, i;
      int r = huff_decode(&z->lit, w, nbits, &p, &sym);
      if (r != ZR_OK) return r;
      if (sym < 256u) {
        if (*o >= cap) return ZR_LIMIT;
        zput(z, out, o, (uint8_t)sym);
        *pos = p;
        break;
      }
      if (sym == ZCODE_EOB) {
        *pos = p;
        if (block_end(z) != ZR_OK) return ZR_BAD;
        break;
      }
      if (sym > 285u) return ZR_BAD;
      li = sym - 257u;
      if (get_bits(w, nbits, &p, k_len_extra[li], &extra) != ZR_OK) return ZR_NEED;
      length = k_len_base[li] + extra;
      r = huff_decode(&z->dist, w, nbits, &p, &dsym);
      if (r != ZR_OK) return r;
      if (dsym > 29u) return ZR_BAD;
      if (get_bits(w, nbits, &p, k_dist_extra[dsym], &extra) != ZR_OK) return ZR_NEED;
      dist = k_dist_base[dsym] + extra;
      if (dist > z->wcount) return ZR_BAD;               /* reaches before the start of the history */
      if (cap - *o < length) return ZR_LIMIT;
      for (i = 0; i < length; i++) zput(z, out, o, z->win[(z->wpos - dist) & ZWMASK]);
      *pos = p;
      break;
    }
    case ZS_TRAILER: {
      size_t p = (*pos + 7u) & ~(size_t)7u;
      unsigned b0, b1, b2, b3;
      uint32_t want;
      if (get_bits(w, nbits, &p, 8, &b0) != ZR_OK || get_bits(w, nbits, &p, 8, &b1) != ZR_OK ||
          get_bits(w, nbits, &p, 8, &b2) != ZR_OK || get_bits(w, nbits, &p, 8, &b3) != ZR_OK)
        return ZR_NEED;
      want = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3;
      if (want != ((z->adler_b << 16) | z->adler_a)) return ZR_BAD;
      if (p != nbits) return ZR_BAD;                     /* bytes after the stream */
      *pos = p;
      z->stage = ZS_DONE;
      return ZR_OK;
    }
    case ZS_DONE:
      return *pos == nbits ? ZR_OK : ZR_BAD;           /* nothing may follow the end of the stream */
    default:
      return ZR_BAD;
    }
  }
}

ssh_zinf *ssh_zinf_new_ex(int oneshot)
{
  ssh_zinf *z = (ssh_zinf *)sd_alloc(sizeof(*z));
  uint8_t lens[288];
  unsigned i;
  if (!z) return NULL;
  memset(z, 0, sizeof(*z));
  z->stage = ZS_HDR;
  z->oneshot = oneshot ? 1 : 0;
  z->adler_a = 1;
  for (i = 0; i < 288; i++) lens[i] = (uint8_t)(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
  if (huff_build(&z->fix_lit, lens, 288, ZK_LENS) != 0) {
    sd_free(z);
    return NULL;
  }
  for (i = 0; i < 32; i++) lens[i] = 5;
  if (huff_build(&z->fix_dist, lens, 32, ZK_DISTS) != 0) {
    sd_free(z);
    return NULL;
  }
  return z;
}

ssh_zinf *ssh_zinf_new(void)
{
  return ssh_zinf_new_ex(0);
}

void ssh_zinf_free(ssh_zinf *z)
{
  sd_free(z);
}

sd_err ssh_zinf_packet(ssh_zinf *z, const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *outn)
{
  const uint8_t *w = in;
  uint8_t *buf = NULL;
  size_t total, pos, o = 0, first;
  int r;

  if (!z || !outn || !out || (!in && n)) return SD_E_INVALID_PARAM;
  *outn = 0;
  if (z->failed) return SD_E_PROTOCOL;
  if (z->ncarry) {
    total = z->ncarry + n;
    buf = (uint8_t *)sd_alloc(total);
    if (!buf) return SD_E_NO_MEMORY;
    memcpy(buf, z->carry, z->ncarry);
    if (n) memcpy(buf + z->ncarry, in, n);
    w = buf;
  } else {
    total = n;
  }
  pos = z->ncarry ? z->carry_bit : 0;

  r = zinf_run(z, w, total * 8u, &pos, out, cap, &o);
  if (r == ZR_NEED) {
    /* keep the bytes from the first unread bit on, for the next packet */
    first = pos >> 3;
    if (total - first > ZCARRY_MAX) {
      r = ZR_BAD;
    } else {
      z->ncarry = total - first;
      if (z->ncarry) memcpy(z->carry, w + first, z->ncarry);
      z->carry_bit = (unsigned)(pos & 7u);
    }
  }
  sd_free(buf);
  if (r == ZR_NEED || r == ZR_OK) {
    /* NEED: possibly no output yet, the rest of the symbol comes later. OK: a one-shot stream ended */
    if (r == ZR_OK) z->ncarry = 0;
    *outn = o;
    return SD_OK;
  }
  /* a bad stream or the output limit: the decoder is unusable from here on */
  z->failed = 1;
  return SD_E_PROTOCOL;
}

sd_err ssh_zlib_oneshot(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *outn)
{
  ssh_zinf *z;
  size_t pos = 0, o = 0;
  int r;
  if (!in || !out || !outn) return SD_E_INVALID_PARAM;
  *outn = 0;
  z = ssh_zinf_new_ex(1);
  if (!z) return SD_E_NO_MEMORY;
  r = zinf_run(z, in, n * 8u, &pos, out, cap, &o);
  ssh_zinf_free(z);
  if (r != ZR_OK) return SD_E_PROTOCOL;
  *outn = o;
  return SD_OK;
}

/* ---- encoder ---- */

struct ssh_zdef {
  uint8_t hist[ZHIST_CAP];       /* history followed by the packet being compressed */
  size_t hlen;
  int32_t head[ZHASH_SIZE];      /* most recent position per 3-byte hash, -1 when none */
  int32_t prev[ZWIN];            /* previous position with the same hash, indexed by position & ZWMASK */
  uint32_t bitbuf;
  unsigned bitcnt;               /* pending bits, always < 8 between calls */
  int started;
  uint32_t adler_a, adler_b;
  int err;
};

static void zb_put(ssh_zdef *z, sd_wr *out, uint32_t v, unsigned n)
{
  z->bitbuf |= v << z->bitcnt;
  z->bitcnt += n;
  while (z->bitcnt >= 8) {
    sd_wr_u8(out, (uint8_t)z->bitbuf);
    z->bitbuf >>= 8;
    z->bitcnt -= 8;
  }
}

static uint32_t rev_bits(uint32_t v, unsigned n)
{
  uint32_t r = 0;
  while (n--) {
    r = (r << 1) | (v & 1u);
    v >>= 1;
  }
  return r;
}

/* Fixed literal/length code (RFC 1951 3.2.6), written most significant bit first. */
static void put_fixed_lit(ssh_zdef *z, sd_wr *out, unsigned sym)
{
  uint32_t code;
  unsigned len;
  if (sym < 144u) {
    code = 0x30u + sym;
    len = 8;
  } else if (sym < 256u) {
    code = 0x190u + (sym - 144u);
    len = 9;
  } else if (sym < 280u) {
    code = sym - 256u;
    len = 7;
  } else {
    code = 0xc0u + (sym - 280u);
    len = 8;
  }
  zb_put(z, out, rev_bits(code, len), len);
}

static void put_match(ssh_zdef *z, sd_wr *out, unsigned length, unsigned dist)
{
  unsigned li = 28, di = 29;
  while (k_len_base[li] > length) li--;
  put_fixed_lit(z, out, 257u + li);
  zb_put(z, out, length - k_len_base[li], k_len_extra[li]);
  while (k_dist_base[di] > dist) di--;
  zb_put(z, out, rev_bits(di, 5), 5);                  /* fixed distance codes are 5 bits */
  zb_put(z, out, dist - k_dist_base[di], k_dist_extra[di]);
}

static uint32_t zhash(const uint8_t *p)
{
  return (((uint32_t)p[0] << 10) ^ ((uint32_t)p[1] << 5) ^ (uint32_t)p[2]) & (ZHASH_SIZE - 1u);
}

/* Adds position p to the hash chains (needs 3 bytes of history from p). */
static void insert_pos(ssh_zdef *z, size_t p)
{
  uint32_t h;
  if (p + ZMIN_MATCH > z->hlen) return;
  h = zhash(z->hist + p);
  z->prev[p & ZWMASK] = z->head[h];
  z->head[h] = (int32_t)p;
}

/* Greedy LZ77 over hist[p .. end). Matches may reach back into earlier packets. */
static void lz_packet(ssh_zdef *z, sd_wr *out, size_t p, size_t end)
{
  while (p < end) {
    size_t best_len = 0, best_dist = 0, maxlen = 0, i;
    unsigned chain = 0;
    int32_t c = -1;
    if (p + ZMIN_MATCH <= end) {
      c = z->head[zhash(z->hist + p)];
      maxlen = end - p;
      if (maxlen > ZMAX_MATCH) maxlen = ZMAX_MATCH;
      while (c >= 0 && chain < ZMAX_CHAIN && p - (size_t)c <= ZWIN) {
        size_t l = 0;
        while (l < maxlen && z->hist[(size_t)c + l] == z->hist[p + l]) l++;
        if (l > best_len) {
          best_len = l;
          best_dist = p - (size_t)c;
          if (l == maxlen) break;
        }
        c = z->prev[(size_t)c & ZWMASK];
        chain++;
      }
      insert_pos(z, p);
    }
    if (best_len >= ZMIN_MATCH) {
      put_match(z, out, (unsigned)best_len, (unsigned)best_dist);
      for (i = 1; i < best_len; i++) insert_pos(z, p + i);
      p += best_len;
    } else {
      put_fixed_lit(z, out, z->hist[p]);
      p++;
    }
  }
}

ssh_zdef *ssh_zdef_new(void)
{
  ssh_zdef *z = (ssh_zdef *)sd_alloc(sizeof(*z));
  unsigned i;
  if (!z) return NULL;
  memset(z, 0, sizeof(*z));
  for (i = 0; i < ZHASH_SIZE; i++) z->head[i] = -1;
  z->adler_a = 1;
  return z;
}

void ssh_zdef_free(ssh_zdef *z)
{
  sd_free(z);
}

sd_err ssh_zdef_compress(ssh_zdef *z, const uint8_t *in, size_t n, sd_wr *out)
{
  size_t start, i;
  if (!z || !out || !in || n == 0 || n > SSH_ZLIB_PACKET_MAX) return SD_E_INVALID_PARAM;
  if (z->err) return SD_E_INTERNAL;
  if (!z->started) {
    sd_wr_u8(out, 0x78);                               /* CMF: deflate, 32 KiB window */
    sd_wr_u8(out, 0x9c);                               /* FLG: default level; (0x78 << 8 | 0x9c) % 31 == 0 */
    z->started = 1;
  }
  if (z->hlen + n > ZHIST_CAP) {
    size_t keep = z->hlen < ZWIN ? z->hlen : ZWIN;
    memmove(z->hist, z->hist + z->hlen - keep, keep);
    z->hlen = keep;
    for (i = 0; i < ZHASH_SIZE; i++) z->head[i] = -1;
  }
  memcpy(z->hist + z->hlen, in, n);
  start = z->hlen;
  z->hlen += n;
  for (i = 0; i < n; i++) {
    z->adler_a = (z->adler_a + in[i]) % 65521u;
    z->adler_b = (z->adler_b + z->adler_a) % 65521u;
  }

  zb_put(z, out, 0, 1);                                /* BFINAL = 0 */
  zb_put(z, out, 1, 2);                                /* BTYPE = 01, fixed Huffman */
  lz_packet(z, out, start, z->hlen);
  put_fixed_lit(z, out, ZCODE_EOB);
  /* partial flush: an empty static block (10 bits), so the packet's symbols end inside its bytes */
  zb_put(z, out, 0, 1);
  zb_put(z, out, 1, 2);
  put_fixed_lit(z, out, ZCODE_EOB);
  if (!sd_wr_ok(out)) {
    z->err = 1;
    return SD_E_NO_MEMORY;
  }
  return SD_OK;
}

sd_err ssh_zdef_finish(ssh_zdef *z, sd_wr *out)
{
  uint32_t adler;
  if (!z || !out) return SD_E_INVALID_PARAM;
  if (z->err) return SD_E_INTERNAL;
  if (!z->started) {
    sd_wr_u8(out, 0x78);
    sd_wr_u8(out, 0x9c);
    z->started = 1;
  }
  zb_put(z, out, 1, 1);                                /* BFINAL = 1 */
  zb_put(z, out, 1, 2);
  put_fixed_lit(z, out, ZCODE_EOB);
  if (z->bitcnt) zb_put(z, out, 0, 8u - z->bitcnt);   /* pad to a byte boundary */
  adler = (z->adler_b << 16) | z->adler_a;
  sd_wr_u8(out, (uint8_t)(adler >> 24));
  sd_wr_u8(out, (uint8_t)(adler >> 16));
  sd_wr_u8(out, (uint8_t)(adler >> 8));
  sd_wr_u8(out, (uint8_t)adler);
  if (!sd_wr_ok(out)) {
    z->err = 1;
    return SD_E_NO_MEMORY;
  }
  return SD_OK;
}
