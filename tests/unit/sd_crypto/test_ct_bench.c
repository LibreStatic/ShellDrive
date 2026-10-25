/* Constant-time helper tests and a throughput report (printed, never failing on speed). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_internal.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_ct.h"
#include "sd_test.h"
#include "tutil.h"

SD_TEST(ct_helpers)
{
  static const uint32_t vals[] = { 0, 1, 2, 0x7fffffffu, 0x80000000u, 0x80000001u, 0xfffffffeu, 0xffffffffu };
  uint32_t a[3] = { 1, 2, 3 }, b[3] = { 4, 5, 6 };
  uint64_t c[2] = { 1, 2 }, d[2] = { 3, 4 };
  uint8_t x[4] = { 1, 2, 3, 4 }, y[4] = { 9, 9, 9, 9 };
  size_t i, j;
  for (i = 0; i < SD_COUNTOF(vals); i++)
    for (j = 0; j < SD_COUNTOF(vals); j++) {
      SD_CHECK(sd_ct_eq_u32(vals[i], vals[j]) == (vals[i] == vals[j] ? 0xffffffffu : 0));
      SD_CHECK(sd_ct_lt_u32(vals[i], vals[j]) == (vals[i] < vals[j] ? 0xffffffffu : 0));
    }
  SD_CHECK(sd_ct_is_zero_u32(0) == 0xffffffffu && sd_ct_is_zero_u32(5) == 0);
  SD_CHECK(sd_ct_select_u32(0xffffffffu, 7, 9) == 7 && sd_ct_select_u32(0, 7, 9) == 9);
  SD_CHECK(sd_ct_select_u64(~(uint64_t)0, 7, 9) == 7 && sd_ct_select_u64(0, 7, 9) == 9);
  sd_ct_cswap_u32(0, a, b, 3);
  SD_CHECK(a[0] == 1 && b[2] == 6);
  sd_ct_cswap_u32(1, a, b, 3);
  SD_CHECK(a[0] == 4 && a[2] == 6 && b[0] == 1 && b[2] == 3);
  sd_ct_cswap_u64(1, c, d, 2);
  SD_CHECK(c[0] == 3 && d[1] == 2);
  sd_ct_cmov(x, y, 4, 0);
  SD_CHECK(x[0] == 1);
  sd_ct_cmov(x, y, 4, 0xff);
  SD_CHECK(x[0] == 9 && x[3] == 9);
  SD_CHECK(sd_ct_memeq("abc", "abc", 3) == 1);
  SD_CHECK(sd_ct_memeq("abc", "abd", 3) == 0);
  SD_CHECK(sd_ct_memeq("abc", "xbc", 0) == 1);
}

static double mbps(size_t bytes, double secs)
{
  return secs > 0 ? (double)bytes / (1024.0 * 1024.0) / secs : 0;
}

SD_TEST(bench_throughput)
{
  enum { BUF = 1 << 20, PKT = 32768 };
  uint8_t *buf = (uint8_t *)tu_alloc(BUF + 64), key[64], iv[16], tag[16], out[64];
  const sd_pktcipher_info *info;
  sd_pktcipher *pc;
  double t0, t1;
  int i, rounds;
  uint64_t rs = 1;
  SD_REQUIRE(buf != NULL);
  tu_rand_fill(&rs, buf, BUF);
  tu_rand_fill(&rs, key, sizeof(key));
  tu_rand_fill(&rs, iv, sizeof(iv));

  rounds = 32;
  t0 = tu_seconds();
  for (i = 0; i < rounds; i++)
    sd_hash(SD_HASH_SHA256, buf, BUF, out);
  t1 = tu_seconds();
  printf("    sha256              %8.1f MB/s\n", mbps((size_t)rounds * BUF, t1 - t0));
  t0 = tu_seconds();
  for (i = 0; i < rounds; i++)
    sd_hash(SD_HASH_SHA512, buf, BUF, out);
  t1 = tu_seconds();
  printf("    sha512              %8.1f MB/s\n", mbps((size_t)rounds * BUF, t1 - t0));

  info = sd_pktcipher_find("chacha20-poly1305@openssh.com");
  SD_REQUIRE(sd_pktcipher_new(info, 1, key, NULL, &pc) == SD_OK);
  t0 = tu_seconds();
  for (i = 0; i < rounds * (BUF / PKT); i++)
    sd_pktcipher_seal(pc, (uint32_t)i, buf + (size_t)(i % (BUF / PKT)) * PKT, PKT, tag);
  t1 = tu_seconds();
  printf("    chacha20-poly1305   %8.1f MB/s (32 KiB packets)\n", mbps((size_t)rounds * BUF, t1 - t0));
  sd_pktcipher_free(pc);

  rounds = 4;
  {
    sd_aes_own k;
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    SD_REQUIRE(sd_aes_own_init(&k, key, 32) == SD_OK);
    t0 = tu_seconds();
    for (i = 0; i < rounds; i++)
      sd_aes_own_ctr(&k, ctr, buf, BUF, buf);
    t1 = tu_seconds();
    printf("    aes256-ctr (own ct) %8.1f MB/s\n", mbps((size_t)rounds * BUF, t1 - t0));
    sd_aes_own_wipe(&k);
  }
  t0 = tu_seconds();
  for (i = 0; i < rounds; i++)
    sd_aes_gcm_encrypt_own(key, 32, iv, NULL, 0, buf, BUF, buf, tag);
  t1 = tu_seconds();
  printf("    aes256-gcm (own ct) %8.1f MB/s\n", mbps((size_t)rounds * BUF, t1 - t0));
  if (sd_crypto_caps_get()->os & SD_OS_CNG_GCM) {
    info = sd_pktcipher_find("aes256-gcm@openssh.com");
    SD_REQUIRE(sd_pktcipher_new(info, 1, key, iv, &pc) == SD_OK);
    rounds = 32;
    t0 = tu_seconds();
    for (i = 0; i < rounds * (BUF / PKT); i++)
      sd_pktcipher_seal(pc, 0, buf + (size_t)(i % (BUF / PKT)) * PKT, PKT, tag);
    t1 = tu_seconds();
    printf("    aes256-gcm (CNG)    %8.1f MB/s (32 KiB packets)\n", mbps((size_t)rounds * BUF, t1 - t0));
    sd_pktcipher_free(pc);
  }

  {
    uint8_t pub[32], sig[64];
    int n = 200;
    t0 = tu_seconds();
    for (i = 0; i < n; i++)
      sd_x25519_base(pub, key);
    t1 = tu_seconds();
    printf("    x25519              %8.0f ops/s\n", n / (t1 - t0));
    sd_ed25519_pub_from_seed(pub, key);
    t0 = tu_seconds();
    for (i = 0; i < n; i++)
      sd_ed25519_sign(sig, key, pub, buf, 64);
    t1 = tu_seconds();
    printf("    ed25519 sign        %8.0f ops/s\n", n / (t1 - t0));
    t0 = tu_seconds();
    for (i = 0; i < n; i++)
      SD_CHECK(sd_ed25519_verify(sig, pub, buf, 64) == SD_OK);
    t1 = tu_seconds();
    printf("    ed25519 verify      %8.0f ops/s\n", n / (t1 - t0));
  }
  free(buf);
}
