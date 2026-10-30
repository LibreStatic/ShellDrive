/* Throughput report for the M2 symmetric/PQ primitives (printed, never failing on speed). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

static double mbps(size_t bytes, double secs)
{
  return secs > 0 ? (double)bytes / (1024.0 * 1024.0) / secs : 0;
}

SD_TEST(bench_pq)
{
  enum { BUF = 1 << 20 };
  uint8_t *buf = (uint8_t *)tu_alloc(BUF), key[32], iv[16], out[64];
  uint8_t *pk = (uint8_t *)tu_alloc(SD_MLKEM768_PK_LEN), *sk = (uint8_t *)tu_alloc(SD_MLKEM768_SK_LEN);
  uint8_t ct[SD_MLKEM768_CT_LEN], ss[32];
  const sd_pktcipher_info *info;
  sd_pktcipher *pc;
  double t0, t1;
  int i, n;
  uint64_t rs = 9;
  tu_rand_fill(&rs, buf, BUF);
  tu_rand_fill(&rs, key, sizeof(key));
  tu_rand_fill(&rs, iv, sizeof(iv));

  t0 = tu_seconds();
  for (i = 0; i < 8; i++)
    sd_sha3_256(out, buf, BUF);
  t1 = tu_seconds();
  printf("    sha3-256            %8.1f MB/s\n", mbps((size_t)8 * BUF, t1 - t0));

  n = 300;
  t0 = tu_seconds();
  for (i = 0; i < n; i++)
    sd_mlkem768_keypair(pk, sk);
  t1 = tu_seconds();
  printf("    ml-kem-768 keygen   %8.0f ops/s\n", n / (t1 - t0));
  t0 = tu_seconds();
  for (i = 0; i < n; i++)
    sd_mlkem768_encaps(ct, ss, pk);
  t1 = tu_seconds();
  printf("    ml-kem-768 encaps   %8.0f ops/s\n", n / (t1 - t0));
  t0 = tu_seconds();
  for (i = 0; i < n; i++)
    sd_mlkem768_decaps(ss, ct, sk);
  t1 = tu_seconds();
  printf("    ml-kem-768 decaps   %8.0f ops/s\n", n / (t1 - t0));

  info = sd_pktcipher_find("3des-cbc");
  SD_REQUIRE(info != NULL && sd_pktcipher_new(info, 1, key, iv, &pc) == SD_OK);
  t0 = tu_seconds();
  sd_pktcipher_crypt(pc, buf, BUF);
  t1 = tu_seconds();
  printf("    3des-cbc (own ct)   %8.1f MB/s encrypt\n", mbps(BUF, t1 - t0));
  sd_pktcipher_free(pc);
  info = sd_pktcipher_find("aes256-cbc");
  SD_REQUIRE(info != NULL && sd_pktcipher_new(info, 0, key, iv, &pc) == SD_OK);
  t0 = tu_seconds();
  for (i = 0; i < 4; i++)
    sd_pktcipher_crypt(pc, buf, BUF);
  t1 = tu_seconds();
  printf("    aes256-cbc (own ct) %8.1f MB/s decrypt\n", mbps((size_t)4 * BUF, t1 - t0));
  sd_pktcipher_free(pc);

  t0 = tu_seconds();
  SD_CHECK(sd_argon2(SD_ARGON2ID, 8192, 1, 1, "pass", 4, key, 16, out, 32, NULL) == SD_OK);
  t1 = tu_seconds();
  printf("    argon2id 8 MiB t=1  %8.1f ms\n", (t1 - t0) * 1000.0);
  free(buf);
  free(pk);
  free(sk);
}
