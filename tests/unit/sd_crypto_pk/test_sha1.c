/* SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1: FIPS 180 examples, RFC 2202, RFC 6070, Wycheproof hmac_sha1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

static void hex_check(sd_test_ctx *sd_t_, const uint8_t *got, size_t n, const char *hex)
{
  uint8_t want[64];
  size_t wl = tu_hexbuf(hex, want, sizeof(want));
  SD_REQUIRE(wl == n);
  SD_CHECK_MEM(got, want, n);
}

SD_TEST(sha1_fips180)
{
  uint8_t out[20];
  uint8_t *big = (uint8_t *)tu_alloc(1000000);
  sd_hash_ctx c;
  size_t i;
  SD_CHECK_EQ_U64(sd_hash_len(SD_HASH_SHA1), 20);
  SD_CHECK_EQ_U64(sd_hash_block_len(SD_HASH_SHA1), 64);
  sd_hash(SD_HASH_SHA1, "", 0, out);
  hex_check(sd_t_, out, 20, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  sd_hash(SD_HASH_SHA1, "abc", 3, out);
  hex_check(sd_t_, out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
  sd_hash(SD_HASH_SHA1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, out);
  hex_check(sd_t_, out, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  memset(big, 'a', 1000000);
  sd_hash(SD_HASH_SHA1, big, 1000000, out);
  hex_check(sd_t_, out, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
  /* the same in uneven pieces */
  sd_hash_init(&c, SD_HASH_SHA1);
  for (i = 0; i < 1000000;) {
    size_t take = SD_MIN((size_t)(1 + (i * 7) % 131), 1000000 - i);
    sd_hash_update(&c, big + i, take);
    i += take;
  }
  sd_hash_final(&c, out);
  hex_check(sd_t_, out, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
  free(big);
}

SD_TEST(hmac_sha1_rfc2202)
{
  uint8_t key[80], out[20];
  sd_hmac_ctx h;
  memset(key, 0x0b, 20);
  sd_hmac_init(&h, SD_HASH_SHA1, key, 20);
  sd_hmac_update(&h, "Hi There", 8);
  sd_hmac_final(&h, out);
  hex_check(sd_t_, out, 20, "b617318655057264e28bc0b6fb378c8ef146be00");
  sd_hmac_init(&h, SD_HASH_SHA1, "Jefe", 4);
  sd_hmac_update(&h, "what do ya want for nothing?", 28);
  sd_hmac_final(&h, out);
  hex_check(sd_t_, out, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
  /* reset reuses the key (per-packet MAC use) */
  sd_hmac_update(&h, "what do ya want for nothing?", 28);
  sd_hmac_final(&h, out);
  hex_check(sd_t_, out, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
  memset(key, 0xaa, 80);
  sd_hmac_init(&h, SD_HASH_SHA1, key, 80);
  sd_hmac_update(&h, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
  sd_hmac_final(&h, out);
  hex_check(sd_t_, out, 20, "aa4ae5e15272d00e95705637ce8a3b55ed402112");
  sd_hmac_wipe(&h);
}

SD_TEST(pbkdf2_sha1_rfc6070)
{
  uint8_t out[25];
  SD_REQUIRE(sd_pbkdf2_hmac(SD_HASH_SHA1, "password", 8, (const uint8_t *)"salt", 4, 1, out, 20) == SD_OK);
  hex_check(sd_t_, out, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
  SD_REQUIRE(sd_pbkdf2_hmac(SD_HASH_SHA1, "password", 8, (const uint8_t *)"salt", 4, 2, out, 20) == SD_OK);
  hex_check(sd_t_, out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
  SD_REQUIRE(sd_pbkdf2_hmac(SD_HASH_SHA1, "password", 8, (const uint8_t *)"salt", 4, 4096, out, 20) == SD_OK);
  hex_check(sd_t_, out, 20, "4b007901b765489abead49d926f721d065a429c1");
  SD_REQUIRE(sd_pbkdf2_hmac(SD_HASH_SHA1, "passwordPASSWORDpassword", 24,
                            (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, out, 25) == SD_OK);
  hex_check(sd_t_, out, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
}

SD_TEST(wycheproof_hmac_sha1)
{
  tu_lines l;
  char *f[6];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "wycheproof/hmac_sha1_test.txt") == 0);
  while ((n = tu_lines_next(&l, f, 6)) == 5) {
    uint8_t *key, *msg, *tag, out[20];
    size_t kl = tu_hex(f[1], &key), ml = tu_hex(f[2], &msg), tl = tu_hex(f[3], &tag);
    sd_hmac_ctx h;
    int match;
    sd_hmac_init(&h, SD_HASH_SHA1, key, kl);
    sd_hmac_update(&h, msg, ml);
    sd_hmac_final(&h, out);
    match = tl <= 20 && memcmp(out, tag, tl) == 0;
    if (f[4][0] == 'v' && !match)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "hmac_sha1 tcId %s: valid tag rejected", f[0]);
    if (f[4][0] == 'i' && match)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "hmac_sha1 tcId %s: invalid tag accepted", f[0]);
    free(key);
    free(msg);
    free(tag);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK(count >= 170);
}
