/* AES-CBC and 3DES-CBC: NIST CAVP KAT/MMT vectors, the CBC packet-cipher objects (chaining across
 * calls, in-place), the key-file one-shot names, the boolean DES S-box network, and differential
 * tests against CNG (AES-CBC, 3DES-CBC, and ML-KEM where bcrypt.dll provides it). */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des3_internal.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_platform.h"
#include "sd_test.h"
#include "tutil.h"

static void run_cbc_file(sd_test_ctx *sd_t_, const char *rel, int des, int expect)
{
  tu_lines l;
  char *f[5];
  int n = 0;
  if (tu_lines_open(&l, rel) != 0) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "missing vector file %s", rel);
    return;
  }
  while (tu_lines_next(&l, f, 5) == 5) {
    uint8_t *key, *iv, *pt, *ct, *out;
    size_t kl = tu_hex(f[1], &key), ivl = tu_hex(f[2], &iv), pl = tu_hex(f[3], &pt), cl = tu_hex(f[4], &ct);
    int enc = atoi(f[0]);
    sd_err e;
    SD_REQUIRE(pl == cl);
    out = (uint8_t *)tu_alloc(pl);
    if (des && ivl == 0)
      e = sd_3des_ecb(enc, key, enc ? pt : ct, pl, out);
    else if (des)
      e = sd_3des_cbc(enc, key, iv, enc ? pt : ct, pl, out);
    else
      e = sd_aes_cbc(enc, key, kl, iv, enc ? pt : ct, pl, out);
    SD_CHECK(e == SD_OK);
    if (memcmp(out, enc ? ct : pt, pl) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s case %d (%s)", rel, n, enc ? "encrypt" : "decrypt");
    free(key);
    free(iv);
    free(pt);
    free(ct);
    free(out);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK_EQ_INT(n, expect);
}

SD_TEST(aes_cbc_cavp)
{
  run_cbc_file(sd_t_, "pq/aes_cbc_cavp.txt", 0, 218);
}

SD_TEST(tdes_cavp)
{
  run_cbc_file(sd_t_, "pq/tdes_cavp.txt", 1, 530);
}

SD_TEST(des_sbox_network)
{
  /* Every row of every S-box is a permutation of 0..15 (FIPS 46-3); exercised through the network. */
  unsigned box, row, col;
  for (box = 0; box < 8; box++)
    for (row = 0; row < 4; row++) {
      unsigned seen = 0;
      for (col = 0; col < 16; col++) {
        unsigned v = ((row & 2) << 4) | (col << 1) | (row & 1);
        seen |= 1u << sd_des_sbox_ct(box, v);
      }
      SD_CHECK(seen == 0xffffu);
    }
  /* S1(0) = 14, S8(63) = 11 */
  SD_CHECK(sd_des_sbox_ct(0, 0) == 14);
  SD_CHECK(sd_des_sbox_ct(7, 63) == 11);
}

SD_TEST(pktcipher_cbc_streams)
{
  static const char *names[4] = { "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc" };
  uint8_t key[32], iv[16], msg[1024], a[1024], b[1024];
  uint64_t rs = 99;
  int ni;
  for (ni = 0; ni < 4; ni++) {
    const sd_pktcipher_info *info = sd_pktcipher_find(names[ni]);
    sd_pktcipher *enc, *dec;
    size_t pos = 0, bl;
    SD_REQUIRE(info != NULL);
    SD_CHECK((info->flags & (SD_PC_CBC | SD_PC_LEGACY)) == (SD_PC_CBC | SD_PC_LEGACY));
    SD_CHECK(info->tag_len == 0 && !(info->flags & SD_PC_AEAD));
    bl = info->block_len;
    SD_CHECK(bl == (ni == 3 ? 8u : 16u) && info->iv_len == bl);
    tu_rand_fill(&rs, key, sizeof(key));
    tu_rand_fill(&rs, iv, sizeof(iv));
    tu_rand_fill(&rs, msg, sizeof(msg));
    if (ni == 3)
      SD_CHECK(sd_3des_cbc(1, key, iv, msg, sizeof(msg), a) == SD_OK);
    else
      SD_CHECK(sd_aes_cbc(1, key, info->key_len, iv, msg, sizeof(msg), a) == SD_OK);
    SD_REQUIRE(sd_pktcipher_new(info, 1, key, iv, &enc) == SD_OK);
    SD_REQUIRE(sd_pktcipher_new(info, 0, key, iv, &dec) == SD_OK);
    memcpy(b, msg, sizeof(msg));
    while (pos < sizeof(msg)) {                   /* uneven packets, whole blocks */
      size_t r = bl * (1 + tu_rand_u32(&rs) % 9), n = SD_MIN(sizeof(msg) - pos, r);
      SD_CHECK(sd_pktcipher_crypt(enc, b + pos, n) == SD_OK);
      pos += n;
    }
    SD_CHECK(memcmp(a, b, sizeof(msg)) == 0);
    for (pos = 0; pos < sizeof(msg);) {
      size_t r = bl * (1 + tu_rand_u32(&rs) % 13), n = SD_MIN(sizeof(msg) - pos, r);
      SD_CHECK(sd_pktcipher_crypt(dec, b + pos, n) == SD_OK);
      pos += n;
    }
    SD_CHECK(memcmp(msg, b, sizeof(msg)) == 0);
    SD_CHECK(sd_pktcipher_crypt(enc, b, bl + 1) == SD_E_INVALID_PARAM);
    SD_CHECK(sd_pktcipher_seal(enc, 0, b, 32, a) == SD_E_INVALID_PARAM);
    sd_pktcipher_free(enc);
    sd_pktcipher_free(dec);
  }
}

SD_TEST(cipher_oneshot_3des_names)
{
  uint8_t key[24], iv[8], msg[64], a[64], b[64];
  uint64_t rs = 5;
  tu_rand_fill(&rs, key, sizeof(key));
  tu_rand_fill(&rs, iv, sizeof(iv));
  tu_rand_fill(&rs, msg, sizeof(msg));
  SD_CHECK(sd_3des_cbc(1, key, iv, msg, sizeof(msg), a) == SD_OK);
  memcpy(b, msg, sizeof(msg));
  SD_CHECK(sd_cipher_oneshot("DES-EDE3-CBC", 1, key, iv, b, sizeof(b)) == SD_OK);
  SD_CHECK(memcmp(a, b, sizeof(a)) == 0);
  SD_CHECK(sd_cipher_oneshot("3des-cbc", 0, key, iv, b, sizeof(b)) == SD_OK);
  SD_CHECK(memcmp(msg, b, sizeof(b)) == 0);
  SD_CHECK(sd_cipher_oneshot("3des-cbc", 0, key, iv, b, 12) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_cipher_oneshot("aes256-cbc", 1, key, iv, b, 12) == SD_E_INVALID_PARAM);
}

/* ---- CNG differential ---- */

typedef LONG (WINAPI *pfn_open)(void **alg, LPCWSTR id, LPCWSTR impl, ULONG flags);
typedef LONG (WINAPI *pfn_close)(void *alg, ULONG flags);
typedef LONG (WINAPI *pfn_setprop)(void *obj, LPCWSTR prop, PUCHAR in, ULONG cb, ULONG flags);
typedef LONG (WINAPI *pfn_genkey)(void *alg, void **key, PUCHAR obj, ULONG cbobj, PUCHAR secret, ULONG cb,
                                   ULONG flags);
typedef LONG (WINAPI *pfn_crypt)(void *key, PUCHAR in, ULONG cbin, void *pad, PUCHAR iv, ULONG cbiv, PUCHAR out,
                                  ULONG cbout, ULONG *res, ULONG flags);
typedef LONG (WINAPI *pfn_destroy)(void *key);
typedef LONG (WINAPI *pfn_import_pair)(void *alg, void *imp, LPCWSTR type, void **key, PUCHAR in, ULONG cb,
                                        ULONG flags);
typedef LONG (WINAPI *pfn_export)(void *key, void *exp, LPCWSTR type, PUCHAR out, ULONG cb, ULONG *res,
                                   ULONG flags);
typedef LONG (WINAPI *pfn_encaps)(void *key, PUCHAR ss, ULONG cbss, ULONG *rss, PUCHAR ct, ULONG cbct, ULONG *rct,
                                   ULONG flags);
typedef LONG (WINAPI *pfn_decaps)(void *key, PUCHAR ct, ULONG cbct, PUCHAR ss, ULONG cbss, ULONG *rss, ULONG flags);

typedef struct cng_api {
  pfn_open open;
  pfn_close close;
  pfn_setprop setprop;
  pfn_genkey genkey;
  pfn_crypt encrypt, decrypt;
  pfn_destroy destroy;
  pfn_import_pair import_pair;
  pfn_export export_key;
  pfn_encaps encaps;
  pfn_decaps decaps;
} cng_api;

static int cng_load(cng_api *a)
{
#define R(f, n)                                              \
  do {                                                       \
    void *p_ = sd_platform_resolve_by_name(L"bcrypt.dll", n); \
    memcpy(&a->f, &p_, sizeof(p_));                          \
  } while (0)
  memset(a, 0, sizeof(*a));
  R(open, "BCryptOpenAlgorithmProvider");
  R(close, "BCryptCloseAlgorithmProvider");
  R(setprop, "BCryptSetProperty");
  R(genkey, "BCryptGenerateSymmetricKey");
  R(encrypt, "BCryptEncrypt");
  R(decrypt, "BCryptDecrypt");
  R(destroy, "BCryptDestroyKey");
  R(import_pair, "BCryptImportKeyPair");
  R(export_key, "BCryptExportKey");
  R(encaps, "BCryptEncapsulate");
  R(decaps, "BCryptDecapsulate");
#undef R
  if (a->open == NULL || a->close == NULL || a->setprop == NULL || a->genkey == NULL || a->encrypt == NULL ||
      a->decrypt == NULL || a->destroy == NULL) {
    printf("    (CNG not available: differential test skipped)\n");
    return 0;
  }
  return 1;
}

static int cng_cbc(const cng_api *a, void *alg, int enc, const uint8_t *key, size_t kl, const uint8_t *iv,
                   size_t ivl, const uint8_t *in, size_t len, uint8_t *out)
{
  void *k = NULL;
  uint8_t ivc[16];
  ULONG res = 0;
  LONG st;
  if (a->genkey(alg, &k, NULL, 0, (PUCHAR)key, (ULONG)kl, 0) != 0)
    return 0;
  memcpy(ivc, iv, ivl);
  st = (enc ? a->encrypt : a->decrypt)(k, (PUCHAR)in, (ULONG)len, NULL, ivc, (ULONG)ivl, out, (ULONG)len, &res, 0);
  a->destroy(k);
  return st == 0 && res == len;
}

SD_TEST(cng_diff_aes_cbc_3des_cbc)
{
  static const wchar_t mode[] = L"ChainingModeCBC";
  cng_api api;
  void *aes = NULL, *tdes = NULL;
  uint8_t key[32], iv[16], in[800], a[800], b[800];
  uint64_t rs = 2026;
  int i;
  if (!cng_load(&api))
    return;
  SD_REQUIRE(api.open(&aes, L"AES", NULL, 0) == 0);
  SD_REQUIRE(api.open(&tdes, L"3DES", NULL, 0) == 0);
  SD_REQUIRE(api.setprop(aes, L"ChainingMode", (PUCHAR)mode, sizeof(mode), 0) == 0);
  SD_REQUIRE(api.setprop(tdes, L"ChainingMode", (PUCHAR)mode, sizeof(mode), 0) == 0);
  for (i = 0; i < 1500; i++) {
    static const size_t kls[3] = { 16, 24, 32 };
    int des = i % 4 == 3, enc = (i / 4) & 1;
    size_t kl = des ? 24 : kls[i % 3], bl = des ? 8 : 16;
    size_t len = bl * (tu_rand_u32(&rs) % (sizeof(in) / bl + 1));
    tu_rand_fill(&rs, key, kl);
    tu_rand_fill(&rs, iv, bl);
    tu_rand_fill(&rs, in, len);
    if (des)
      SD_REQUIRE(sd_3des_cbc(enc, key, iv, in, len, a) == SD_OK);
    else
      SD_REQUIRE(sd_aes_cbc(enc, key, kl, iv, in, len, a) == SD_OK);
    if (len == 0)
      continue;
    SD_REQUIRE(cng_cbc(&api, des ? tdes : aes, enc, key, kl, iv, bl, in, len, b));
    if (memcmp(a, b, len) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s-cbc %s differs from CNG (klen %u, len %u)", des ? "3des" : "aes",
                   enc ? "encrypt" : "decrypt", (unsigned)kl, (unsigned)len);
      break;
    }
  }
  api.close(aes, 0);
  api.close(tdes, 0);
}

/* BCRYPT_MLKEM_KEY_BLOB (bcrypt.h of SDK 10.0.26100) followed by L"768" and the key bytes. */
typedef struct mlkem_blob {
  ULONG magic, cb_param, cb_key;
  wchar_t param[4];
  uint8_t key[SD_MLKEM768_SK_LEN];
} mlkem_blob;

SD_TEST(cng_diff_mlkem768)
{
  cng_api api;
  void *alg = NULL;
  mlkem_blob blob;
  uint8_t seed[64], pk[SD_MLKEM768_PK_LEN], sk[SD_MLKEM768_SK_LEN], ct[SD_MLKEM768_CT_LEN], s1[32], s2[32];
  int i, ok = 0;
  if (!cng_load(&api))
    return;
  if (api.import_pair == NULL || api.encaps == NULL || api.decaps == NULL || api.export_key == NULL ||
      api.open(&alg, L"ML-KEM", NULL, 0) != 0) {
    printf("    (CNG ML-KEM not available on this Windows build: skipped)\n");
    return;
  }
  for (i = 0; i < 50; i++) {
    void *priv = NULL, *pub = NULL;
    ULONG res = 0, r2 = 0;
    SD_REQUIRE(sd_random(seed, sizeof(seed)) == SD_OK);
    SD_REQUIRE(sd_mlkem768_keypair_derand(pk, sk, seed, seed + 32) == SD_OK);
    /* CNG key from the same seed (d || z): exported ek must equal ours */
    memset(&blob, 0, sizeof(blob));
    blob.magic = 0x534B4C4D;                                    /* BCRYPT_MLKEM_PRIVATE_SEED_MAGIC */
    blob.cb_param = sizeof(blob.param);
    blob.cb_key = 64;
    memcpy(blob.param, L"768", sizeof(L"768"));
    memcpy(blob.key, seed, 64);
    SD_REQUIRE(api.import_pair(alg, NULL, L"MLKEMPRIVATESEEDBLOB", &priv, (PUCHAR)&blob,
                               (ULONG)(offsetof(mlkem_blob, key) + 64), 0) == 0);
    SD_REQUIRE(api.export_key(priv, NULL, L"MLKEMPUBLICBLOB", (PUCHAR)&blob, sizeof(blob), &res, 0) == 0);
    SD_CHECK(res == offsetof(mlkem_blob, key) + SD_MLKEM768_PK_LEN && blob.cb_key == SD_MLKEM768_PK_LEN);
    SD_CHECK(memcmp(blob.key, pk, SD_MLKEM768_PK_LEN) == 0);
    /* CNG encapsulates to our ek, we decapsulate */
    blob.magic = 0x504B4C4D;                                    /* BCRYPT_MLKEM_PUBLIC_MAGIC */
    SD_REQUIRE(api.import_pair(alg, NULL, L"MLKEMPUBLICBLOB", &pub, (PUCHAR)&blob,
                               (ULONG)(offsetof(mlkem_blob, key) + SD_MLKEM768_PK_LEN), 0) == 0);
    SD_REQUIRE(api.encaps(pub, s1, 32, &res, ct, sizeof(ct), &r2, 0) == 0 && res == 32 && r2 == sizeof(ct));
    SD_REQUIRE(sd_mlkem768_decaps(s2, ct, sk) == SD_OK);
    SD_CHECK(memcmp(s1, s2, 32) == 0);
    /* we encapsulate, CNG decapsulates; then a tampered ciphertext on both sides */
    SD_REQUIRE(sd_mlkem768_encaps(ct, s1, pk) == SD_OK);
    SD_REQUIRE(api.decaps(priv, ct, sizeof(ct), s2, 32, &res, 0) == 0 && res == 32);
    SD_CHECK(memcmp(s1, s2, 32) == 0);
    ct[i * 21 % sizeof(ct)] ^= 0x10;
    SD_REQUIRE(api.decaps(priv, ct, sizeof(ct), s2, 32, &res, 0) == 0);
    SD_REQUIRE(sd_mlkem768_decaps(s1, ct, sk) == SD_OK);
    SD_CHECK(memcmp(s1, s2, 32) == 0);
    api.destroy(pub);
    api.destroy(priv);
    ok++;
  }
  api.close(alg, 0);
  printf("    CNG ML-KEM-768 differential: %d keys\n", ok);
}
