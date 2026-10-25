/* ML-KEM-768 (FIPS 203): NIST ACVP keyGen / encapDecap vectors (incl. modified ciphertexts and key
 * checks), Wycheproof ML-KEM-768 (strcmp, modulus overflow, implicit rejection, malformed keys),
 * random round trips, the implicit-rejection key, and the mlkem768x25519-sha256 combiner. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

/* Opens a vector file or fails the test. */
#define OPEN_OR_FAIL(l, rel)                                                      \
  do {                                                                            \
    if (tu_lines_open(&(l), (rel)) != 0) {                                        \
      sd_test_fail(sd_t_, __FILE__, __LINE__, "missing vector file %s", (rel));   \
      return;                                                                     \
    }                                                                             \
  } while (0)

typedef struct kem_buf {
  uint8_t pk[SD_MLKEM768_PK_LEN], sk[SD_MLKEM768_SK_LEN], ct[SD_MLKEM768_CT_LEN], ss[32];
} kem_buf;

SD_TEST(mlkem768_acvp_keygen)
{
  tu_lines l;
  char *f[4];
  int n = 0;
  kem_buf *b = (kem_buf *)tu_alloc(sizeof(kem_buf));
  OPEN_OR_FAIL(l, "pq/mlkem768_acvp_keygen.txt");
  while (tu_lines_next(&l, f, 4) == 4) {
    uint8_t d[32], z[32], *ek, *dk;
    size_t ekl = tu_hex(f[2], &ek), dkl = tu_hex(f[3], &dk);
    SD_REQUIRE(tu_hexbuf(f[0], d, 32) == 32 && tu_hexbuf(f[1], z, 32) == 32);
    SD_REQUIRE(ekl == SD_MLKEM768_PK_LEN && dkl == SD_MLKEM768_SK_LEN);
    SD_CHECK(sd_mlkem768_keypair_derand(b->pk, b->sk, d, z) == SD_OK);
    if (memcmp(b->pk, ek, ekl) != 0 || memcmp(b->sk, dk, dkl) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "ACVP keyGen case %d", n);
    free(ek);
    free(dk);
    n++;
  }
  tu_lines_close(&l);
  free(b);
  SD_CHECK(n == 25);
}

SD_TEST(mlkem768_acvp_encap_decap)
{
  tu_lines l;
  char *f[4];
  int n = 0;
  kem_buf *b = (kem_buf *)tu_alloc(sizeof(kem_buf));
  OPEN_OR_FAIL(l, "pq/mlkem768_acvp_encap.txt");
  while (tu_lines_next(&l, f, 4) == 4) {
    uint8_t ek[SD_MLKEM768_PK_LEN], m[32], c[SD_MLKEM768_CT_LEN], k[32];
    SD_REQUIRE(tu_hexbuf(f[0], ek, sizeof(ek)) == sizeof(ek) && tu_hexbuf(f[1], m, 32) == 32);
    SD_REQUIRE(tu_hexbuf(f[2], c, sizeof(c)) == sizeof(c) && tu_hexbuf(f[3], k, 32) == 32);
    SD_CHECK(sd_mlkem768_encaps_derand(b->ct, b->ss, ek, m) == SD_OK);
    if (memcmp(b->ct, c, sizeof(c)) != 0 || memcmp(b->ss, k, 32) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "ACVP encapsulation case %d", n);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 25);
  n = 0;
  OPEN_OR_FAIL(l, "pq/mlkem768_acvp_decap.txt");
  while (tu_lines_next(&l, f, 3) == 3) {
    uint8_t c[SD_MLKEM768_CT_LEN], k[32];
    SD_REQUIRE(tu_hexbuf(f[0], b->sk, sizeof(b->sk)) == sizeof(b->sk));
    SD_REQUIRE(tu_hexbuf(f[1], c, sizeof(c)) == sizeof(c) && tu_hexbuf(f[2], k, 32) == 32);
    SD_CHECK(sd_mlkem768_decaps(b->ss, c, b->sk) == SD_OK);
    if (memcmp(b->ss, k, 32) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "ACVP decapsulation case %d", n);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 10);
  n = 0;
  OPEN_OR_FAIL(l, "pq/mlkem768_acvp_keycheck.txt");
  while (tu_lines_next(&l, f, 3) == 3) {
    int passed = atoi(f[1]);
    if (strcmp(f[0], "ek") == 0) {
      SD_REQUIRE(tu_hexbuf(f[2], b->pk, sizeof(b->pk)) == sizeof(b->pk));
      SD_CHECK((sd_mlkem768_check_pk(b->pk) == SD_OK) == (passed != 0));
    } else {
      uint8_t c[SD_MLKEM768_CT_LEN] = { 0 };
      SD_REQUIRE(tu_hexbuf(f[2], b->sk, sizeof(b->sk)) == sizeof(b->sk));
      SD_CHECK((sd_mlkem768_decaps(b->ss, c, b->sk) == SD_OK) == (passed != 0));
    }
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 20);
  free(b);
}

SD_TEST(wycheproof_mlkem768)
{
  tu_lines l;
  char *f[6];
  int n = 0, valid = 0, skipped_len = 0;
  kem_buf *b = (kem_buf *)tu_alloc(sizeof(kem_buf));
  /* Decapsulation from a seed: KeyGen(d, z), check ek, Decaps(c). Wrong-length seeds or ciphertexts
     cannot be expressed with the fixed-size API; they count as rejected by the caller (sd_ssh checks
     lengths before calling), which is what Wycheproof expects ("invalid"). */
  OPEN_OR_FAIL(l, "pq/wycheproof_mlkem768.txt");
  while (tu_lines_next(&l, f, 6) == 6) {
    uint8_t *seed, *ek, *c, *k;
    size_t sl = tu_hex(f[2], &seed), ekl = tu_hex(f[3], &ek), cl = tu_hex(f[4], &c);
    size_t kl = tu_hex(f[5], &k);
    int expect_valid = strcmp(f[1], "valid") == 0;
    if (sl != 64 || cl != SD_MLKEM768_CT_LEN) {
      SD_CHECK(!expect_valid);
      skipped_len++;
    } else {
      SD_CHECK(sd_mlkem768_keypair_derand(b->pk, b->sk, seed, seed + 32) == SD_OK);
      SD_CHECK(ekl == SD_MLKEM768_PK_LEN && memcmp(b->pk, ek, ekl) == 0);
      SD_CHECK(sd_mlkem768_decaps(b->ss, c, b->sk) == SD_OK);
      if (!expect_valid || kl != 32 || memcmp(b->ss, k, 32) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "wycheproof mlkem_768_test tcId %s", f[0]);
      valid++;
    }
    free(seed);
    free(ek);
    free(c);
    free(k);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 201 && valid > 150);
  printf("    mlkem_768_test: %d cases, %d by length only\n", n, skipped_len);

  n = 0;
  OPEN_OR_FAIL(l, "pq/wycheproof_mlkem768_encaps.txt");
  while (tu_lines_next(&l, f, 6) == 6) {
    uint8_t *m, *ek, *c, *k;
    size_t ml = tu_hex(f[2], &m), ekl = tu_hex(f[3], &ek), cl = tu_hex(f[4], &c), kl = tu_hex(f[5], &k);
    int expect_valid = strcmp(f[1], "valid") == 0;
    if (ekl != SD_MLKEM768_PK_LEN || ml != 32) {
      SD_CHECK(!expect_valid);
    } else {
      sd_err e = sd_mlkem768_encaps_derand(b->ct, b->ss, ek, m);
      if (expect_valid) {
        SD_CHECK(e == SD_OK && cl == SD_MLKEM768_CT_LEN && kl == 32);
        if (e != SD_OK || memcmp(b->ct, c, cl) != 0 || memcmp(b->ss, k, 32) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "wycheproof encaps tcId %s", f[0]);
      } else if (e != SD_E_CRYPTO) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "wycheproof encaps tcId %s accepted an invalid ek", f[0]);
      }
    }
    free(m);
    free(ek);
    free(c);
    free(k);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 265);

  n = 0;
  OPEN_OR_FAIL(l, "pq/wycheproof_mlkem768_keygen.txt");
  while (tu_lines_next(&l, f, 4) == 4) {
    uint8_t seed[64], *ek, *dk;
    size_t ekl = tu_hex(f[2], &ek), dkl = tu_hex(f[3], &dk);
    SD_REQUIRE(tu_hexbuf(f[1], seed, 64) == 64);
    SD_CHECK(sd_mlkem768_keypair_derand(b->pk, b->sk, seed, seed + 32) == SD_OK);
    if (ekl != SD_MLKEM768_PK_LEN || dkl != SD_MLKEM768_SK_LEN || memcmp(b->pk, ek, ekl) != 0 ||
        memcmp(b->sk, dk, dkl) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "wycheproof keygen tcId %s", f[0]);
    free(ek);
    free(dk);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 100);

  n = 0;
  OPEN_OR_FAIL(l, "pq/wycheproof_mlkem768_decaps.txt");
  while (tu_lines_next(&l, f, 5) == 5) {
    uint8_t *dk, *c, *k;
    size_t dkl = tu_hex(f[2], &dk), cl = tu_hex(f[3], &c), kl = tu_hex(f[4], &k);
    int expect_valid = strcmp(f[1], "valid") == 0;
    if (dkl != SD_MLKEM768_SK_LEN || cl != SD_MLKEM768_CT_LEN) {
      SD_CHECK(!expect_valid);
    } else {
      sd_err e = sd_mlkem768_decaps(b->ss, c, dk);
      if (expect_valid ? (e != SD_OK || kl != 32 || memcmp(b->ss, k, 32) != 0) : e != SD_E_CRYPTO)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "wycheproof semi-expanded decaps tcId %s", f[0]);
    }
    free(dk);
    free(c);
    free(k);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 9);
  free(b);
}

SD_TEST(mlkem768_roundtrip_and_implicit_rejection)
{
  kem_buf *b = (kem_buf *)tu_alloc(sizeof(kem_buf));
  uint8_t ss2[32], jin[32 + SD_MLKEM768_CT_LEN], kbar[32];
  uint64_t rs = 77;
  int i;
  for (i = 0; i < 40; i++) {
    SD_REQUIRE(sd_mlkem768_keypair(b->pk, b->sk) == SD_OK);
    SD_REQUIRE(sd_mlkem768_encaps(b->ct, b->ss, b->pk) == SD_OK);
    SD_REQUIRE(sd_mlkem768_decaps(ss2, b->ct, b->sk) == SD_OK);
    SD_CHECK(memcmp(b->ss, ss2, 32) == 0);
    /* flip one ciphertext bit: decaps still succeeds and returns J(z || c') */
    b->ct[tu_rand_u32(&rs) % SD_MLKEM768_CT_LEN] ^= (uint8_t)(1u << (tu_rand_u32(&rs) % 8));
    SD_REQUIRE(sd_mlkem768_decaps(ss2, b->ct, b->sk) == SD_OK);
    memcpy(jin, b->sk + SD_MLKEM768_SK_LEN - 32, 32);
    memcpy(jin + 32, b->ct, SD_MLKEM768_CT_LEN);
    sd_shake(256, kbar, 32, jin, sizeof(jin));
    SD_CHECK(memcmp(ss2, kbar, 32) == 0);
    SD_CHECK(memcmp(ss2, b->ss, 32) != 0);
  }
  /* dk hash check */
  b->sk[SD_MLKEM768_SK_LEN - 40] ^= 1;
  SD_CHECK(sd_mlkem768_decaps(ss2, b->ct, b->sk) == SD_E_CRYPTO);
  /* ek modulus check: coefficient 0 = 0xfff */
  b->pk[0] = 0xff;
  b->pk[1] |= 0x0f;
  SD_CHECK(sd_mlkem768_check_pk(b->pk) == SD_E_CRYPTO);
  SD_CHECK(sd_mlkem768_encaps(b->ct, b->ss, b->pk) == SD_E_CRYPTO);
  free(b);
}

SD_TEST(mlkem768x25519_combiner)
{
  sd_mlkem768x25519_client *st = (sd_mlkem768x25519_client *)tu_alloc(sizeof(*st));
  sd_mlkem768x25519_client *st2 = (sd_mlkem768x25519_client *)tu_alloc(sizeof(*st2));
  uint8_t q_c[SD_MLKEM768X25519_INIT_LEN], q_s[SD_MLKEM768X25519_REPLY_LEN], kc[32], ks[32];
  uint8_t pq[32], cl[32], both[64], expect[32];
  int i;
  for (i = 0; i < 10; i++) {
    SD_REQUIRE(sd_mlkem768x25519_client_init(st, q_c) == SD_OK);
    memcpy(st2, st, sizeof(*st));
    SD_REQUIRE(sd_mlkem768x25519_server(q_c, q_s, ks) == SD_OK);
    SD_REQUIRE(sd_mlkem768x25519_client_finish(st, q_s, kc) == SD_OK);
    SD_CHECK(memcmp(kc, ks, 32) == 0);
    /* K = SHA-256(K_PQ || K_CL), recomputed from the primitives */
    SD_REQUIRE(sd_mlkem768_decaps(pq, q_s, st2->mlkem_sk) == SD_OK);
    SD_REQUIRE(sd_x25519(cl, st2->x25519_sk, q_s + SD_MLKEM768_CT_LEN) == SD_OK);
    memcpy(both, pq, 32);
    memcpy(both + 32, cl, 32);
    sd_hash(SD_HASH_SHA256, both, 64, expect);
    SD_CHECK(memcmp(kc, expect, 32) == 0);
    {
      static const uint8_t zero[32] = { 0 };
      SD_CHECK(memcmp(st->x25519_sk, zero, 32) == 0);           /* finish wiped the state */
    }
  }
  /* an all-zero (low-order) X25519 server key is rejected */
  SD_REQUIRE(sd_mlkem768x25519_client_init(st, q_c) == SD_OK);
  SD_REQUIRE(sd_mlkem768x25519_server(q_c, q_s, ks) == SD_OK);
  memset(q_s + SD_MLKEM768_CT_LEN, 0, 32);
  SD_CHECK(sd_mlkem768x25519_client_finish(st, q_s, kc) == SD_E_CRYPTO);
  /* a server given an ek with an out-of-range coefficient refuses */
  SD_REQUIRE(sd_mlkem768x25519_client_init(st, q_c) == SD_OK);
  q_c[0] = 0xff;
  q_c[1] |= 0x0f;
  SD_CHECK(sd_mlkem768x25519_server(q_c, q_s, ks) == SD_E_CRYPTO);
  sd_mlkem768x25519_client_wipe(st);
  free(st);
  free(st2);
}
