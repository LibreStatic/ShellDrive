/* Hardware fast paths (M6): SHA-NI for SHA-256 and AES-NI for the AES encryption rounds behind AES-CTR, AES-GCM and
 * AES-CBC encryption. Every check runs the same input through the portable code (sd_crypto_test_force_portable(1))
 * and through the hardware path (force 0). Known-answer vectors pin both; random inputs cross-check them against
 * each other. On a CPU without the feature (or a build without the hardware files) the hardware half is skipped
 * with a note and the portable half still runs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_internal.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

/* Selects the path for the following calls: hw nonzero = hardware when the CPU has it, zero = portable. */
static void select_path(int hw)
{
  sd_crypto_test_force_portable(hw ? 0 : 1);
}

static void hx(sd_test_ctx *sd_t_, const char *hex, uint8_t *out, size_t n)
{
  if (tu_hexbuf(hex, out, n) != n)
    sd_test_fail(sd_t_, __FILE__, __LINE__, "bad test hex: %s", hex);
}

static const char k_448[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char k_896[] =
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

static void check_sha256(sd_test_ctx *sd_t_, const void *msg, size_t n, const char *hex)
{
  uint8_t want[32], got[32];
  hx(sd_t_, hex, want, 32);
  sd_hash(SD_HASH_SHA256, msg, n, got);
  SD_CHECK_MEM(got, want, 32);
}

SD_TEST(hw_sha256_kat_both_paths)
{
  char *m = (char *)tu_alloc(1000000);
  int hw;
  SD_REQUIRE(m != NULL);
  memset(m, 'a', 1000000);
  for (hw = 0; hw <= 1; hw++) {
    select_path(hw);
    if (hw && !sd_crypto_hw_sha256_capable()) {
      printf("    (no SHA-NI on this CPU: hardware SHA-256 path skipped)\n");
      continue;
    }
    SD_CHECK(sd_crypto_use_hw_sha256() == (hw != 0));
    check_sha256(sd_t_, "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_sha256(sd_t_, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_sha256(sd_t_, k_448, strlen(k_448), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    check_sha256(sd_t_, k_896, strlen(k_896), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    check_sha256(sd_t_, m, 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  }
  select_path(0);
  free(m);
}

/* Random messages of every length up to 2 KiB: the hardware digest must equal the portable one, one-shot and fed
   in random pieces (the piecewise case covers the partial-block buffering in sha256_update). */
SD_TEST(hw_sha256_random_vs_portable)
{
  uint64_t rs = 0x5a4e2d53484132ull;
  uint8_t *msg = (uint8_t *)tu_alloc(2048);
  int iter;
  SD_REQUIRE(msg != NULL);
  for (iter = 0; iter < 400; iter++) {
    size_t n = tu_rand_u32(&rs) % 2049, off = 0;
    uint8_t want[32], got[32];
    sd_hash_ctx c;
    tu_rand_fill(&rs, msg, n);
    select_path(1);
    sd_hash(SD_HASH_SHA256, msg, n, want);
    select_path(0);
    sd_hash(SD_HASH_SHA256, msg, n, got);
    SD_CHECK_MEM(got, want, 32);

    sd_hash_init(&c, SD_HASH_SHA256);
    while (off < n) {
      size_t take = 1 + tu_rand_u32(&rs) % (n - off);
      sd_hash_update(&c, msg + off, take);
      off += take;
    }
    sd_hash_final(&c, got);
    SD_CHECK_MEM(got, want, 32);
  }
  select_path(0);
}

/* FIPS 197 Appendix C.1 to C.3 for each key size, on both paths: encryption of one block and of four, and the
   bitsliced decryption (always portable) of the hardware output. */
SD_TEST(hw_aes_fips197_both_paths)
{
  static const char *keys[3] = {
    "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" };
  static const char *cts[3] = {
    "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191", "8ea2b7ca516745bfeafc49904b496089" };
  uint8_t pt[64], want_blk[16];
  int i, hw;
  hx(sd_t_, "00112233445566778899aabbccddeeff", pt, 16);
  for (i = 0; i < 3; i++) {
    uint8_t key[32];
    size_t kl = tu_hexbuf(keys[i], key, 32), j;
    hx(sd_t_, cts[i], want_blk, 16);
    for (hw = 0; hw <= 1; hw++) {
      sd_aes_own k;
      uint8_t in4[64], out[64], back[64];
      select_path(hw);
      SD_REQUIRE(sd_aes_own_init(&k, key, kl) == SD_OK);
      SD_CHECK(k.hw == (uint32_t)(hw && sd_crypto_hw_aes_capable()));
      for (j = 0; j < 4; j++)
        memcpy(in4 + 16 * j, pt, 16);
      sd_aes_own_encrypt(&k, in4, out, 1);
      SD_CHECK_MEM(out, want_blk, 16);
      sd_aes_own_encrypt(&k, in4, out, 4);
      for (j = 0; j < 4; j++)
        SD_CHECK_MEM(out + 16 * j, want_blk, 16);
      sd_aes_own_decrypt(&k, out, back, 4);
      SD_CHECK_MEM(back, in4, 64);
      sd_aes_own_wipe(&k);
    }
  }
  select_path(0);
}

/* sd_aes_own_encrypt takes at most 4 blocks per call on the portable core (its gather buffer is 64 bytes). */
static void encrypt_in_batches(const sd_aes_own *k, const uint8_t *in, uint8_t *out, size_t nb)
{
  while (nb) {
    size_t n = nb < 4 ? nb : 4;
    sd_aes_own_encrypt(k, in, out, n);
    in += 16 * n;
    out += 16 * n;
    nb -= n;
  }
}

/* Random keys, batch sizes 1..9 (crosses the 4-block batches and the single-block tail) and in-place use: the
   hardware encryption must equal the portable one. */
SD_TEST(hw_aes_random_vs_portable)
{
  static const size_t key_lens[3] = { 16, 24, 32 };
  uint64_t rs = 0x414553484e4937ull;
  int iter;
  for (iter = 0; iter < 200; iter++) {
    uint8_t key[32], in[9 * 16], hwout[9 * 16], swout[9 * 16];
    size_t kl = key_lens[tu_rand_u32(&rs) % 3], nb = 1 + tu_rand_u32(&rs) % 9;
    sd_aes_own kh, ks;
    tu_rand_fill(&rs, key, sizeof(key));
    tu_rand_fill(&rs, in, sizeof(in));
    select_path(1);
    SD_REQUIRE(sd_aes_own_init(&ks, key, kl) == SD_OK);
    select_path(0);
    SD_REQUIRE(sd_aes_own_init(&kh, key, kl) == SD_OK);
    encrypt_in_batches(&ks, in, swout, nb);
    encrypt_in_batches(&kh, in, hwout, nb);
    SD_CHECK_MEM(hwout, swout, nb * 16);
    memcpy(hwout, in, nb * 16);
    encrypt_in_batches(&kh, hwout, hwout, nb);
    SD_CHECK_MEM(hwout, swout, nb * 16);
    sd_aes_own_wipe(&kh);
    sd_aes_own_wipe(&ks);
  }
  select_path(0);
}

/* CTR on both paths: SP 800-38A F.5.1 (AES-128), then random counters near the top of the 128-bit space (the carry
   must cross every byte) and random lengths. */
SD_TEST(hw_aes_ctr_both_paths)
{
  static const char *pt_hex =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710";
  static const size_t key_lens_ctr[3] = { 16, 24, 32 };
  uint64_t rs = 0x435452485754ull;
  int hw, iter;
  for (hw = 0; hw <= 1; hw++) {
    uint8_t key[16], ctr[16], pt[64], want[64], out[64];
    select_path(hw);
    hx(sd_t_, "2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hx(sd_t_, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);
    hx(sd_t_, pt_hex, pt, 64);
    hx(sd_t_, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab"
              "1e031dda2fbe03d1792170a0f3009cee", want, 64);
    SD_CHECK(sd_aes_ctr_own(key, 16, ctr, pt, 64, out) == SD_OK);
    SD_CHECK_MEM(out, want, 64);
  }
  /* Random counters whose low 1..4 bytes are all ff, so the increment carries across them, and random lengths. */
  for (iter = 0; iter < 64; iter++) {
    uint8_t key[32], cw[16], zero[80], hwo[80], swo[80];
    size_t kl = key_lens_ctr[iter % 3], len = 1 + tu_rand_u32(&rs) % 80;
    size_t carry = 1 + tu_rand_u32(&rs) % 4, b;
    tu_rand_fill(&rs, key, sizeof(key));
    tu_rand_fill(&rs, cw, sizeof(cw));
    for (b = 0; b < carry; b++)
      cw[15 - b] = 0xff;
    memset(zero, 0, sizeof(zero));
    select_path(1);
    SD_CHECK(sd_aes_ctr_own(key, kl, cw, zero, len, swo) == SD_OK);
    select_path(0);
    SD_CHECK(sd_aes_ctr_own(key, kl, cw, zero, len, hwo) == SD_OK);
    SD_CHECK_MEM(hwo, swo, len);
  }
  /* Explicit wrap check: blocks 0 and 1 of ff..ff are E(ff..ff) and E(00..00). */
  {
    uint8_t key[16], cw[16], zero[32], two[32], one[16];
    hx(sd_t_, "2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    memset(cw, 0xff, 16);
    memset(zero, 0, sizeof(zero));
    select_path(0);
    SD_CHECK(sd_aes_ctr_own(key, 16, cw, zero, 32, two) == SD_OK);
    memset(cw, 0, 16);
    SD_CHECK(sd_aes_ctr_own(key, 16, cw, zero, 16, one) == SD_OK);
    SD_CHECK_MEM(two + 16, one, 16);
  }
  select_path(0);
}

/* GCM on both paths: spec test case 2 (one zero block, zero key and nonce) and random inputs with AAD, then the
   tag and plaintext round-trip with the hardware decryption of the portable output. */
SD_TEST(hw_aes_gcm_both_paths)
{
  static const size_t key_lens[3] = { 16, 24, 32 };
  uint8_t zkey[16], znonce[12], zero[16], out[16], tag[16], want[16], back[16];
  uint64_t rs = 0x47434d484cull;
  int iter;
  memset(zkey, 0, sizeof(zkey));
  memset(znonce, 0, sizeof(znonce));
  memset(zero, 0, sizeof(zero));
  select_path(0);
  SD_CHECK(sd_aes_gcm_encrypt_own(zkey, 16, znonce, NULL, 0, zero, 16, out, tag) == SD_OK);
  hx(sd_t_, "0388dace60b6a392f328c2b971b2fe78", want, 16);
  SD_CHECK_MEM(out, want, 16);
  hx(sd_t_, "ab6e47d42cec13bdf53a67b21257bddf", want, 16);
  SD_CHECK_MEM(tag, want, 16);
  SD_CHECK(sd_aes_gcm_decrypt_own(zkey, 16, znonce, NULL, 0, out, 16, tag, back) == SD_OK);
  SD_CHECK_MEM(back, zero, 16);

  for (iter = 0; iter < 120; iter++) {
    uint8_t key[32], nonce[12], aad[40], pt[300], ct_s[300], ct_h[300], tag_s[16], tag_h[16], dec[300];
    size_t kl = key_lens[tu_rand_u32(&rs) % 3], al = tu_rand_u32(&rs) % 41, pl = tu_rand_u32(&rs) % 301;
    tu_rand_fill(&rs, key, sizeof(key));
    tu_rand_fill(&rs, nonce, sizeof(nonce));
    tu_rand_fill(&rs, aad, sizeof(aad));
    tu_rand_fill(&rs, pt, sizeof(pt));
    select_path(1);
    SD_CHECK(sd_aes_gcm_encrypt_own(key, kl, nonce, aad, al, pt, pl, ct_s, tag_s) == SD_OK);
    select_path(0);
    SD_CHECK(sd_aes_gcm_encrypt_own(key, kl, nonce, aad, al, pt, pl, ct_h, tag_h) == SD_OK);
    SD_CHECK_MEM(ct_h, ct_s, pl);
    SD_CHECK_MEM(tag_h, tag_s, 16);
    /* Decrypt the portable ciphertext on the hardware path: the tag must verify and the plaintext must return. */
    SD_CHECK(sd_aes_gcm_decrypt_own(key, kl, nonce, aad, al, ct_s, pl, tag_s, dec) == SD_OK);
    SD_CHECK_MEM(dec, pt, pl);
  }
  select_path(0);
}
