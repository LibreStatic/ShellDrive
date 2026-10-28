/* zlib@openssh.com codec (src/sd_ssh/ssh_zlib.c): RFC 1950/1951 streams, hand-built blocks, corrupt and truncated
 * input, split feeding, round trips with our encoder, the per-packet output limit, and partial-flush packets
 * produced by the reference zlib (Python 3.14, zlib 1.3.1 family; the fixtures are literal hex below).
 * Test-only file: no third-party code is linked or included. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "ssh_zlib.h"

/* ---- helpers ---- */

static size_t hex_bytes(const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;
  while (hex[0] && hex[1]) {
    int v = 0, i;
    for (i = 0; i < 2; i++) {
      char c = hex[i];
      int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
      if (d < 0) return 0;
      v = v * 16 + d;
    }
    if (n >= cap) return 0;
    out[n++] = (uint8_t)v;
    hex += 2;
  }
  return n;
}

static uint32_t adler_of(const uint8_t *p, size_t n)
{
  uint32_t a = 1, b = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    a = (a + p[i]) % 65521u;
    b = (b + a) % 65521u;
  }
  return (b << 16) | a;
}

/* LSB-first bit writer for hand-built blocks. */
typedef struct bitw {
  uint8_t b[512];
  size_t bits;
} bitw;

static void bw_put(bitw *w, uint32_t v, unsigned n)
{
  unsigned i;
  for (i = 0; i < n; i++, w->bits++)
    if ((v >> i) & 1u) w->b[w->bits >> 3] |= (uint8_t)(1u << (w->bits & 7u));
}

/* Huffman codes are written most significant bit first. */
static void bw_code(bitw *w, uint32_t code, unsigned n)
{
  unsigned i;
  for (i = n; i-- > 0;) bw_put(w, (code >> i) & 1u, 1);
}

static void bw_fixed_lit(bitw *w, unsigned sym)
{
  if (sym < 144) bw_code(w, 0x30u + sym, 8);
  else if (sym < 256) bw_code(w, 0x190u + (sym - 144u), 9);
  else if (sym < 280) bw_code(w, sym - 256u, 7);
  else bw_code(w, 0xc0u + (sym - 280u), 8);
}

static uint32_t rng_next(uint32_t *s)
{
  uint32_t x = *s;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *s = x;
  return x;
}

/* Compressible but varied payload: short words, repeats of earlier bytes, and some noise. */
static void make_payload(uint8_t *p, size_t n, uint32_t *seed)
{
  size_t i;
  for (i = 0; i < n; i++) {
    uint32_t r = rng_next(seed) % 16u;
    if (r < 8u) p[i] = (uint8_t)('a' + (rng_next(seed) % 6u));
    else if (r < 13u && i > 20u) p[i] = p[i - 1u - (rng_next(seed) % 20u)];
    else p[i] = (uint8_t)rng_next(seed);
  }
}

static const char k_dynamic_hex[] =
  "78da554e5b0ec02008bb0a5763eaa299738bb098ecf47b5013fda2b4a554249267655af3d5a1680dbcd39dd342f29226fd6b4bc51f8d4e765b50089fc5452e2564bb87a97388c3b01b04c0891c338c112335b532dc3fccad6c7b00627f5141";

/* ---- reference streams ---- */

SD_TEST(zlib_reference_streams_oneshot)
{
  uint8_t in[256], out[512];
  size_t n, outn = 0;
  /* zlib.compress(b"hello world") */
  n = hex_bytes("789ccb48cdc9c95728cf2fca4901001a0b045d", in, sizeof(in));
  SD_REQUIRE(n == 19);
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) == SD_OK);
  SD_CHECK(outn == 11 && memcmp(out, "hello world", 11) == 0);

  /* fixed Huffman block: zlib.compressobj(9, DEFLATED, 15, 8, Z_FIXED) on b"abcabcabcabc hello hello" */
  n = hex_bytes("78014b4c4a4e8421858cd49c9c7c08090070120901", in, sizeof(in));
  SD_REQUIRE(n == 21);
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) == SD_OK);
  SD_CHECK(outn == 24 && memcmp(out, "abcabcabcabc hello hello", 24) == 0);

  /* stored block: zlib.compressobj(0) on b"stored block text" */
  n = hex_bytes("7801011100eeff73746f72656420626c6f636b2074657874" "3c3406a2", in, sizeof(in));
  SD_REQUIRE(n == 28);
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) == SD_OK);
  SD_CHECK(outn == 17 && memcmp(out, "stored block text", 17) == 0);
}

SD_TEST(zlib_reference_dynamic_block)
{
  uint8_t in[256], out[512];
  size_t n, outn = 0;
  n = hex_bytes(k_dynamic_hex, in, sizeof(in));
  SD_REQUIRE(n == 95);
  /* 217 bytes, dynamic Huffman (BTYPE 2); the Adler-32 trailer checks the text */
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) == SD_OK);
  SD_CHECK(outn == 217);
  /* the same stream with a small output limit must fail, not truncate */
  SD_CHECK(ssh_zlib_oneshot(in, n, out, 216, &outn) != SD_OK);
}

SD_TEST(zlib_hand_built_fixed_block)
{
  bitw w;
  uint8_t in[64], out[16];
  size_t n, outn = 0;
  uint32_t ad;
  memset(&w, 0, sizeof(w));
  /* BFINAL 1, BTYPE 01, literal 'a', match length 3 at distance 1, end of block */
  bw_put(&w, 1, 1);
  bw_put(&w, 1, 2);
  bw_fixed_lit(&w, 'a');
  bw_fixed_lit(&w, 257);
  bw_code(&w, 0, 5);
  bw_fixed_lit(&w, 256);
  n = 0;
  in[n++] = 0x78;
  in[n++] = 0x9c;
  memcpy(in + n, w.b, (w.bits + 7) / 8);
  n += (w.bits + 7) / 8;
  ad = adler_of((const uint8_t *)"aaaa", 4);
  in[n++] = (uint8_t)(ad >> 24);
  in[n++] = (uint8_t)(ad >> 16);
  in[n++] = (uint8_t)(ad >> 8);
  in[n++] = (uint8_t)ad;
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) == SD_OK);
  SD_CHECK(outn == 4 && memcmp(out, "aaaa", 4) == 0);

  /* the same block with distance 2 reaches before the first byte: invalid */
  memset(&w, 0, sizeof(w));
  bw_put(&w, 1, 1);
  bw_put(&w, 1, 2);
  bw_fixed_lit(&w, 'a');
  bw_fixed_lit(&w, 257);
  bw_code(&w, 1, 5);
  bw_fixed_lit(&w, 256);
  n = 2;
  memcpy(in + 2, w.b, (w.bits + 7) / 8);
  n += (w.bits + 7) / 8;
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) != SD_OK);

  /* reserved BTYPE 11 */
  in[0] = 0x78; in[1] = 0x9c; in[2] = 0x07; in[3] = 0;
  SD_CHECK(ssh_zlib_oneshot(in, 4, out, sizeof(out), &outn) != SD_OK);
}

SD_TEST(zlib_rejects_malformed_streams)
{
  uint8_t in[256], out[512];
  size_t n, outn = 0, i, cut;
  n = hex_bytes(k_dynamic_hex, in, sizeof(in));
  SD_REQUIRE(n == 95);
  /* every proper prefix is truncated */
  for (cut = 0; cut < n; cut++) SD_CHECK(ssh_zlib_oneshot(in, cut, out, sizeof(out), &outn) != SD_OK);
  /* a flipped bit in the trailer or the header changes the Adler-32 or the header check */
  for (i = n - 4; i < n; i++) {
    uint8_t t[256];
    memcpy(t, in, n);
    t[i] ^= 0x10;
    SD_CHECK(ssh_zlib_oneshot(t, n, out, sizeof(out), &outn) != SD_OK);
  }
  for (i = 0; i < 2; i++) {
    uint8_t t[256];
    memcpy(t, in, n);
    t[i] ^= 0x01;
    SD_CHECK(ssh_zlib_oneshot(t, n, out, sizeof(out), &outn) != SD_OK);
  }
  /* bytes after the trailer */
  {
    uint8_t t[256];
    memcpy(t, in, n);
    t[n] = 0;
    SD_CHECK(ssh_zlib_oneshot(t, n + 1, out, sizeof(out), &outn) != SD_OK);
  }
  /* wrong method (CM 9) and a header check that does not divide by 31 */
  in[0] = 0x79;
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) != SD_OK);
  in[0] = 0x78;
  in[1] = 0x9d;
  SD_CHECK(ssh_zlib_oneshot(in, n, out, sizeof(out), &outn) != SD_OK);
  /* stored block with LEN != ~NLEN */
  {
    uint8_t t[64];
    size_t m = hex_bytes("7801010500000068656c6c6f00000000", t, sizeof(t));
    SD_CHECK(m == 16);
    SD_CHECK(ssh_zlib_oneshot(t, m, out, sizeof(out), &outn) != SD_OK);
  }
}

/* ---- decoder packet API, incremental ---- */

SD_TEST(zlib_reference_partial_flush_packets)
{
  /* zlib.compressobj(6): three packets, each ended with Z_PARTIAL_FLUSH, the way OpenSSH sends them. Only the
     first carries the zlib header; the pending bits of an empty block carry over between packets. */
  static const char k_p1[] = "789c2a484cce4e2d51c8cf4bb55228c94855282ccd4cce56482aca2fcf5348cbaf0008";
  static const char k_p2[] = "a002887449793e566985c4f4c4cc3c8000";
  static const char k_p3[] = "aa0008";
  static const char *k_pkts[3] = { k_p1, k_p2, k_p3 };
  static const char *k_want[3] = {
    "packet one: the quick brown fox",
    "packet two: the quick brown fox again",
    "x"
  };
  ssh_zinf *z = ssh_zinf_new();
  int k;
  SD_REQUIRE(z != NULL);
  for (k = 0; k < 3; k++) {
    uint8_t in[256], out[512];
    size_t n = hex_bytes(k_pkts[k], in, sizeof(in)), outn = 0;
    SD_REQUIRE(n > 0);
    SD_REQUIRE(ssh_zinf_packet(z, in, n, out, sizeof(out), &outn) == SD_OK);
    SD_CHECK(outn == strlen(k_want[k]));
    SD_CHECK(memcmp(out, k_want[k], outn) == 0);
  }
  ssh_zinf_free(z);
}

SD_TEST(zlib_reference_dynamic_split_feed)
{
  /* the dynamic block fed one byte at a time: the header and every symbol resume across calls */
  uint8_t in[256], want[512], out[512];
  size_t n = hex_bytes(k_dynamic_hex, in, sizeof(in)), wantn = 0, got = 0, i;
  ssh_zinf *z;
  SD_REQUIRE(ssh_zlib_oneshot(in, n, want, sizeof(want), &wantn) == SD_OK);
  z = ssh_zinf_new_ex(1);
  SD_REQUIRE(z != NULL);
  for (i = 0; i < n; i++) {
    size_t outn = 0;
    SD_REQUIRE(ssh_zinf_packet(z, in + i, 1, out + got, sizeof(out) - got, &outn) == SD_OK);
    got += outn;
  }
  SD_CHECK(got == wantn);
  SD_CHECK(memcmp(out, want, wantn) == 0);
  ssh_zinf_free(z);
}

/* ---- encoder ---- */

SD_TEST(zlib_encoder_roundtrip_packets)
{
  enum { NPKT = 40 };
  ssh_zdef *zd = ssh_zdef_new();
  ssh_zinf *zi = ssh_zinf_new();
  uint8_t *plain = (uint8_t *)sd_alloc(NPKT * 35000u);
  uint8_t *out = (uint8_t *)sd_alloc(SSH_ZLIB_PACKET_MAX);
  sd_wr wire, whole;
  uint32_t seed = 0x1234567u;
  size_t total = 0, wire_total = 0;
  int k;
  SD_REQUIRE(zd != NULL && zi != NULL && plain != NULL && out != NULL);
  sd_wr_init(&wire, 1u << 22);
  sd_wr_init(&whole, 1u << 22);
  for (k = 0; k < NPKT; k++) {
    size_t n = 1u + (size_t)(rng_next(&seed) % 35000u), outn = 0;
    uint8_t *p = plain + total;
    make_payload(p, n, &seed);
    sd_wr_reset(&wire);
    SD_REQUIRE(ssh_zdef_compress(zd, p, n, &wire) == SD_OK);
    SD_REQUIRE(sd_wr_ok(&wire));
    SD_REQUIRE(ssh_zinf_packet(zi, wire.p, wire.len, out, SSH_ZLIB_PACKET_MAX, &outn) == SD_OK);
    SD_CHECK(outn == n);
    SD_CHECK(memcmp(out, p, n) == 0);
    sd_wr_bytes(&whole, wire.p, wire.len);
    wire_total += wire.len;
    total += n;
  }
  /* the whole stream plus the finish is a valid RFC 1950 stream */
  SD_REQUIRE(ssh_zdef_finish(zd, &whole) == SD_OK);
  SD_REQUIRE(sd_wr_ok(&whole));
  {
    size_t outn = 0;
    uint8_t *big = (uint8_t *)sd_alloc(total);
    SD_REQUIRE(big != NULL);
    SD_CHECK(ssh_zlib_oneshot(whole.p, whole.len, big, total, &outn) == SD_OK);
    SD_CHECK(outn == total && memcmp(big, plain, total) == 0);
    sd_free(big);
  }
  SD_CHECK(wire_total < total);                /* compressible input: the wire is smaller */
  sd_wr_free(&wire);
  sd_wr_free(&whole);
  ssh_zdef_free(zd);
  ssh_zinf_free(zi);
  sd_free(out);
  sd_free(plain);
}

SD_TEST(zlib_split_feed_matches_packets)
{
  /* the packets of an encoder stream, fed in pieces of 1 to 9 bytes that ignore the packet boundaries */
  enum { NPKT = 12 };
  ssh_zdef *zd = ssh_zdef_new();
  ssh_zinf *zi = ssh_zinf_new();
  sd_wr wire;
  uint8_t *plain = (uint8_t *)sd_alloc(NPKT * 4000u);
  uint8_t *out = (uint8_t *)sd_alloc(NPKT * 4000u + 16u);
  uint32_t seed = 0xabcdefu;
  size_t total = 0, off = 0, got = 0, piece = 1;
  int k;
  SD_REQUIRE(zd && zi && plain && out);
  sd_wr_init(&wire, 1u << 20);
  for (k = 0; k < NPKT; k++) {
    size_t n = 1u + (size_t)(rng_next(&seed) % 4000u);
    make_payload(plain + total, n, &seed);
    SD_REQUIRE(ssh_zdef_compress(zd, plain + total, n, &wire) == SD_OK);
    total += n;
  }
  while (off < wire.len) {
    size_t take = piece < wire.len - off ? piece : wire.len - off, outn = 0;
    SD_REQUIRE(ssh_zinf_packet(zi, wire.p + off, take, out + got, total - got, &outn) == SD_OK);
    got += outn;
    off += take;
    piece = piece % 9u + 1u;
  }
  SD_CHECK(got == total);
  SD_CHECK(memcmp(out, plain, total) == 0);
  sd_wr_free(&wire);
  ssh_zdef_free(zd);
  ssh_zinf_free(zi);
  sd_free(out);
  sd_free(plain);
}

SD_TEST(zlib_output_limit_is_per_packet)
{
  /* 256 KiB of zeros compresses to a few hundred bytes; the decoder refuses to produce more than the limit */
  ssh_zdef *zd = ssh_zdef_new();
  ssh_zinf *zi;
  uint8_t *zero = (uint8_t *)sd_alloc(SSH_ZLIB_PACKET_MAX);
  uint8_t *out = (uint8_t *)sd_alloc(SSH_ZLIB_PACKET_MAX);
  sd_wr w;
  size_t outn = 0;
  SD_REQUIRE(zd && zero && out);
  memset(zero, 0, SSH_ZLIB_PACKET_MAX);
  sd_wr_init(&w, 1u << 22);
  SD_REQUIRE(ssh_zdef_compress(zd, zero, SSH_ZLIB_PACKET_MAX, &w) == SD_OK);
  SD_CHECK(w.len < 8192);                     /* a bomb: far more output than input */
  zi = ssh_zinf_new();
  SD_REQUIRE(zi != NULL);
  SD_CHECK(ssh_zinf_packet(zi, w.p, w.len, out, 64u * 1024u, &outn) == SD_E_PROTOCOL);
  /* once refused, the stream stays refused */
  SD_CHECK(ssh_zinf_packet(zi, w.p, 0, out, SSH_ZLIB_PACKET_MAX, &outn) == SD_E_PROTOCOL);
  ssh_zinf_free(zi);
  /* at the limit it is accepted */
  zi = ssh_zinf_new();
  SD_REQUIRE(zi != NULL);
  SD_CHECK(ssh_zinf_packet(zi, w.p, w.len, out, SSH_ZLIB_PACKET_MAX, &outn) == SD_OK);
  SD_CHECK(outn == SSH_ZLIB_PACKET_MAX);
  ssh_zinf_free(zi);
  sd_wr_free(&w);
  ssh_zdef_free(zd);
  sd_free(out);
  sd_free(zero);
}

SD_TEST(zlib_encoder_rejects_bad_sizes)
{
  ssh_zdef *zd = ssh_zdef_new();
  sd_wr w;
  uint8_t b = 1;
  SD_REQUIRE(zd != NULL);
  sd_wr_init(&w, 1u << 20);
  SD_CHECK(ssh_zdef_compress(zd, &b, 0, &w) == SD_E_INVALID_PARAM);
  SD_CHECK(ssh_zdef_compress(zd, &b, SSH_ZLIB_PACKET_MAX + 1u, &w) == SD_E_INVALID_PARAM);
  sd_wr_free(&w);
  ssh_zdef_free(zd);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(zlib_reference_streams_oneshot),
  SD_TEST_ENTRY(zlib_reference_dynamic_block),
  SD_TEST_ENTRY(zlib_hand_built_fixed_block),
  SD_TEST_ENTRY(zlib_rejects_malformed_streams),
  SD_TEST_ENTRY(zlib_reference_partial_flush_packets),
  SD_TEST_ENTRY(zlib_reference_dynamic_split_feed),
  SD_TEST_ENTRY(zlib_encoder_roundtrip_packets),
  SD_TEST_ENTRY(zlib_split_feed_matches_packets),
  SD_TEST_ENTRY(zlib_output_limit_is_per_packet),
  SD_TEST_ENTRY(zlib_encoder_rejects_bad_sizes),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
