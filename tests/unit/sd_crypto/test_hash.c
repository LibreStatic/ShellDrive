/* SHA-2, HMAC and PBKDF2 known-answer tests (FIPS 180-4 examples, RFC 4231, RFC 7914 §11) and the
 * Wycheproof HMAC suites. */
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

static void check_hash(sd_test_ctx *sd_t_, sd_hash_alg alg, const void *msg, size_t n, const char *hex)
{
  uint8_t want[64], got[64];
  size_t wl = tu_hexbuf(hex, want, sizeof(want));
  SD_REQUIRE(wl == sd_hash_len(alg));
  sd_hash(alg, msg, n, got);
  SD_CHECK_MEM(got, want, wl);
}

static const char k_448[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char k_896[] =
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

SD_TEST(sha256_kat)
{
  char *m = (char *)tu_alloc(1000000);
  SD_REQUIRE(m != NULL);
  check_hash(sd_t_, SD_HASH_SHA256, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check_hash(sd_t_, SD_HASH_SHA256, "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check_hash(sd_t_, SD_HASH_SHA256, k_448, strlen(k_448),
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  memset(m, 'a', 1000000);
  check_hash(sd_t_, SD_HASH_SHA256, m, 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  free(m);
}

SD_TEST(sha512_sha384_kat)
{
  char *m = (char *)tu_alloc(1000000);
  SD_REQUIRE(m != NULL);
  check_hash(sd_t_, SD_HASH_SHA512, "abc", 3,
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
             "454d4423643ce80e2a9ac94fa54ca49f");
  check_hash(sd_t_, SD_HASH_SHA512, "", 0,
             "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
             "63b931bd47417a81a538327af927da3e");
  check_hash(sd_t_, SD_HASH_SHA512, k_896, strlen(k_896),
             "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433a"
             "c7d329eeb6dd26545e96e55b874be909");
  check_hash(sd_t_, SD_HASH_SHA384, "abc", 3,
             "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
  check_hash(sd_t_, SD_HASH_SHA384, "", 0,
             "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
  check_hash(sd_t_, SD_HASH_SHA384, k_896, strlen(k_896),
             "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
  memset(m, 'a', 1000000);
  check_hash(sd_t_, SD_HASH_SHA512, m, 1000000,
             "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31b"
             "eb009c5c2c49aa2e4eadb217ad8cc09b");
  free(m);
}

SD_TEST(hash_incremental_matches_oneshot)
{
  static const sd_hash_alg algs[] = { SD_HASH_SHA256, SD_HASH_SHA384, SD_HASH_SHA512 };
  uint8_t msg[1000], a[64], b[64];
  uint64_t rs = 0x1234567;
  size_t ai, n;
  tu_rand_fill(&rs, msg, sizeof(msg));
  for (ai = 0; ai < SD_COUNTOF(algs); ai++)
    for (n = 0; n <= sizeof(msg); n += 37) {
      sd_hash_ctx c;
      size_t off = 0;
      sd_hash(algs[ai], msg, n, a);
      sd_hash_init(&c, algs[ai]);
      while (off < n) {
        size_t r = tu_rand_u32(&rs) % 150;            /* SD_MIN evaluates its arguments twice */
        size_t step = SD_MIN(n - off, r);
        sd_hash_update(&c, msg + off, step);
        off += step;
      }
      sd_hash_final(&c, b);
      SD_CHECK_MEM(a, b, sd_hash_len(algs[ai]));
    }
  SD_CHECK_EQ_U64(sd_hash_len(SD_HASH_SHA384), 48);
  SD_CHECK_EQ_U64(sd_hash_block_len(SD_HASH_SHA384), 128);
  SD_CHECK_EQ_U64(sd_hash_block_len(SD_HASH_SHA256), 64);
}

static void check_hmac(sd_test_ctx *sd_t_, sd_hash_alg alg, const uint8_t *key, size_t kl, const void *msg,
                       size_t ml, const char *hex)
{
  uint8_t want[64], got[64];
  sd_hmac_ctx c;
  size_t wl = tu_hexbuf(hex, want, sizeof(want));
  SD_REQUIRE(wl == sd_hash_len(alg));
  sd_hmac_init(&c, alg, key, kl);
  sd_hmac_update(&c, msg, ml);
  sd_hmac_final(&c, got);
  SD_CHECK_MEM(got, want, wl);
  /* final leaves the keyed state: the same message again gives the same tag */
  sd_hmac_update(&c, msg, ml);
  sd_hmac_final(&c, got);
  SD_CHECK_MEM(got, want, wl);
  sd_hmac_wipe(&c);
}

SD_TEST(hmac_rfc4231)
{
  uint8_t k1[20], k3[20], d3[50], k6[131];
  static const char m6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
  memset(k1, 0x0b, sizeof(k1));
  memset(k3, 0xaa, sizeof(k3));
  memset(d3, 0xdd, sizeof(d3));
  memset(k6, 0xaa, sizeof(k6));
  check_hmac(sd_t_, SD_HASH_SHA256, k1, 20, "Hi There", 8,
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  check_hmac(sd_t_, SD_HASH_SHA384, k1, 20, "Hi There", 8,
             "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
  check_hmac(sd_t_, SD_HASH_SHA512, k1, 20, "Hi There", 8,
             "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
             "be9d914eeb61f1702e696c203a126854");
  check_hmac(sd_t_, SD_HASH_SHA256, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28,
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  check_hmac(sd_t_, SD_HASH_SHA384, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28,
             "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
  check_hmac(sd_t_, SD_HASH_SHA512, (const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28,
             "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd"
             "caeab1a34d4a6b4b636e070a38bce737");
  check_hmac(sd_t_, SD_HASH_SHA256, k3, 20, d3, 50,
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
  check_hmac(sd_t_, SD_HASH_SHA512, k3, 20, d3, 50,
             "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807"
             "b946a337bee8942674278859e13292fb");
  check_hmac(sd_t_, SD_HASH_SHA256, k6, 131, m6, strlen(m6),
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  check_hmac(sd_t_, SD_HASH_SHA384, k6, 131, m6, strlen(m6),
             "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952");
  check_hmac(sd_t_, SD_HASH_SHA512, k6, 131, m6, strlen(m6),
             "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e52"
             "95e64f73f63f0aec8b915a985d786598");
}

SD_TEST(pbkdf2_rfc7914)
{
  uint8_t want[64], got[64];
  SD_REQUIRE(tu_hexbuf("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645"
                       "991664b39d77ef317c71b845b1e30bd509112041d3a19783", want, 64) == 64);
  SD_CHECK(sd_pbkdf2_hmac(SD_HASH_SHA256, "passwd", 6, (const uint8_t *)"salt", 4, 1, got, 64) == SD_OK);
  SD_CHECK_MEM(got, want, 64);
  SD_REQUIRE(tu_hexbuf("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a122583354"
                       "9adb841b51c9b3176a272bdebba1d078478f62b397f33c8d", want, 64) == 64);
  SD_CHECK(sd_pbkdf2_hmac(SD_HASH_SHA256, "Password", 8, (const uint8_t *)"NaCl", 4, 80000, got, 64) == SD_OK);
  SD_CHECK_MEM(got, want, 64);
  SD_CHECK(sd_pbkdf2_hmac(SD_HASH_SHA256, "x", 1, (const uint8_t *)"s", 1, 0, got, 16) == SD_E_INVALID_PARAM);
}

static void wycheproof_hmac(sd_test_ctx *sd_t_, const char *file, sd_hash_alg alg)
{
  tu_lines l;
  char *f[8];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, file) == 0);
  while ((n = tu_lines_next(&l, f, 8)) != 0) {
    uint8_t *key, *msg, *tag, got[64];
    size_t kl, ml, tl;
    int match;
    sd_hmac_ctx c;
    SD_REQUIRE(n == 5);
    kl = tu_hex(f[1], &key);
    ml = tu_hex(f[2], &msg);
    tl = tu_hex(f[3], &tag);
    sd_hmac_init(&c, alg, key, kl);
    sd_hmac_update(&c, msg, ml);
    sd_hmac_final(&c, got);
    match = tl <= sd_hash_len(alg) && memcmp(got, tag, tl) == 0;
    if (f[4][0] == 'v' && !match)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: valid tag rejected", file, f[0]);
    if (f[4][0] == 'i' && match)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: invalid tag accepted", file, f[0]);
    free(key); free(msg); free(tag);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK(count == 174);
}

SD_TEST(wycheproof_hmac_sha256)
{
  wycheproof_hmac(sd_t_, "wycheproof/hmac_sha256_test.txt", SD_HASH_SHA256);
}

SD_TEST(wycheproof_hmac_sha512)
{
  wycheproof_hmac(sd_t_, "wycheproof/hmac_sha512_test.txt", SD_HASH_SHA512);
}
