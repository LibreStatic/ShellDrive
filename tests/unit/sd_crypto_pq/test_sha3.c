/* SHA-3 / SHAKE (FIPS 202): NIST CAVP SHA3VS/SHAKEVS vectors, the Monte Carlo test, random cases from
 * an independent implementation (hashlib) and incremental-update consistency. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

static void hash_by_bits(int bits, const uint8_t *m, size_t n, uint8_t *out, size_t outlen)
{
  if (bits == 256)
    sd_sha3_256(out, m, n);
  else if (bits == 512)
    sd_sha3_512(out, m, n);
  else
    sd_shake(bits == -128 ? 128 : 256, out, outlen, m, n);
}

static int run_file(sd_test_ctx *sd_t_, const char *rel, int bits)
{
  tu_lines l;
  char *f[3];
  int n = 0;
  if (tu_lines_open(&l, rel) != 0) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "missing vector file %s", rel);
    return 0;
  }
  while (tu_lines_next(&l, f, 3) == 2) {
    uint8_t *msg, *exp, *got;
    size_t ml = tu_hex(f[0], &msg), el = tu_hex(f[1], &exp);
    got = (uint8_t *)tu_alloc(el);
    hash_by_bits(bits, msg, ml, got, el);
    if (memcmp(got, exp, el) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s case %d (msg %u bytes, out %u)", rel, n, (unsigned)ml,
                   (unsigned)el);
      n = -1000000;
    }
    free(msg);
    free(exp);
    free(got);
    n++;
  }
  tu_lines_close(&l);
  return n;
}

SD_TEST(sha3_fips202_cavp_short)
{
  SD_CHECK(run_file(sd_t_, "pq/sha3_256_short.txt", 256) == 137);
  SD_CHECK(run_file(sd_t_, "pq/sha3_512_short.txt", 512) == 73);
}

SD_TEST(shake_fips202_cavp)
{
  SD_CHECK(run_file(sd_t_, "pq/shake128.txt", -128) > 500);
  SD_CHECK(run_file(sd_t_, "pq/shake256.txt", -256) > 500);
}

SD_TEST(sha3_cavp_monte)
{
  static const int bits[2] = { 256, 512 };
  static const char *files[2] = { "pq/sha3_256_monte.txt", "pq/sha3_512_monte.txt" };
  int b;
  for (b = 0; b < 2; b++) {
    tu_lines l;
    char *f[2];
    uint8_t md[64], exp[64];
    size_t hl = (size_t)bits[b] / 8;
    int checkpoints = 0, i;
    SD_REQUIRE(tu_lines_open(&l, files[b]) == 0);
    SD_REQUIRE(tu_lines_next(&l, f, 2) == 2 && strcmp(f[0], "seed") == 0);
    SD_REQUIRE(tu_hexbuf(f[1], md, sizeof(md)) == hl);
    while (tu_lines_next(&l, f, 2) == 2) {
      for (i = 0; i < 1000; i++)
        hash_by_bits(bits[b], md, hl, md, hl);
      SD_REQUIRE(tu_hexbuf(f[1], exp, sizeof(exp)) == hl);
      if (memcmp(md, exp, hl) != 0) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "SHA3-%d Monte checkpoint %s", bits[b], f[0]);
        break;
      }
      checkpoints++;
    }
    tu_lines_close(&l);
    SD_CHECK(checkpoints == 100);
  }
}

SD_TEST(sha3_hashlib_reference)
{
  tu_lines l;
  char *f[3];
  int n = 0;
  SD_REQUIRE(tu_lines_open(&l, "pq/sha3_random.txt") == 0);
  while (tu_lines_next(&l, f, 3) == 3) {
    uint8_t *msg, *exp, *got;
    size_t ml = tu_hex(f[1], &msg), el = tu_hex(f[2], &exp);
    int bits = f[0][0] == 's' ? -atoi(f[0] + 1) : atoi(f[0]);
    got = (uint8_t *)tu_alloc(el);
    hash_by_bits(bits, msg, ml, got, el);
    if (memcmp(got, exp, el) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "alg %s msg %u bytes out %u", f[0], (unsigned)ml, (unsigned)el);
    free(msg);
    free(exp);
    free(got);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n > 150);
}

SD_TEST(sha3_incremental_matches_oneshot)
{
  uint8_t msg[700], a[200], b[200];
  uint64_t rs = 3;
  int i;
  tu_rand_fill(&rs, msg, sizeof(msg));
  for (i = 0; i < 200; i++) {
    size_t n = tu_rand_u32(&rs) % sizeof(msg), pos = 0, outlen = 1 + tu_rand_u32(&rs) % sizeof(a), got = 0;
    sd_keccak_ctx c;
    int bits = (i & 1) ? 512 : 256;
    sd_sha3_init(&c, bits);
    while (pos < n) {
      size_t r = tu_rand_u32(&rs) % 200, take = SD_MIN(n - pos, r);
      sd_sha3_update(&c, msg + pos, take);
      pos += take;
    }
    sd_sha3_final(&c, a);
    hash_by_bits(bits, msg, n, b, 0);
    SD_CHECK(memcmp(a, b, (size_t)bits / 8) == 0);

    sd_shake_init(&c, (i & 2) ? 256 : 128);
    for (pos = 0; pos < n;) {
      size_t r = tu_rand_u32(&rs) % 300, take = SD_MIN(n - pos, r);
      sd_shake_absorb(&c, msg + pos, take);
      pos += take;
    }
    while (got < outlen) {
      size_t r = 1 + tu_rand_u32(&rs) % 170, take = SD_MIN(outlen - got, r);
      sd_shake_squeeze(&c, a + got, take);
      got += take;
    }
    sd_keccak_wipe(&c);
    sd_shake((i & 2) ? 256 : 128, b, outlen, msg, n);
    SD_CHECK(memcmp(a, b, outlen) == 0);
  }
}
