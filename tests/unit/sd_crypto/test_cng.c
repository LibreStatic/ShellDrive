/* Differential tests against CNG (01 §2.7.3): random inputs, own code vs bcrypt.dll for SHA-2, HMAC,
 * AES-CTR and AES-GCM. Skipped (with a note) when CNG is not available. CI runs more iterations
 * nightly; this keeps the per-PR run short. */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_internal.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_platform.h"
#include "sd_test.h"
#include "tutil.h"

typedef LONG (WINAPI *pfn_create_hash)(sd_bcrypt_handle alg, sd_bcrypt_handle *h, PUCHAR obj, ULONG cbobj,
                                        PUCHAR secret, ULONG cbsecret, ULONG flags);
typedef LONG (WINAPI *pfn_hash_data)(sd_bcrypt_handle h, PUCHAR in, ULONG cb, ULONG flags);
typedef LONG (WINAPI *pfn_finish_hash)(sd_bcrypt_handle h, PUCHAR out, ULONG cb, ULONG flags);
typedef LONG (WINAPI *pfn_destroy_hash)(sd_bcrypt_handle h);

typedef struct cng_hash_api {
  sd_pfn_BCryptOpenAlgorithmProvider open_alg;
  pfn_create_hash create;
  pfn_hash_data data;
  pfn_finish_hash finish;
  pfn_destroy_hash destroy;
} cng_hash_api;

static int load_hash_api(cng_hash_api *a)
{
  a->open_alg = (sd_pfn_BCryptOpenAlgorithmProvider)sd_platform_resolve(SD_API_BCryptOpenAlgorithmProvider);
  a->create = (pfn_create_hash)sd_platform_resolve_by_name(L"bcrypt.dll", "BCryptCreateHash");
  a->data = (pfn_hash_data)sd_platform_resolve_by_name(L"bcrypt.dll", "BCryptHashData");
  a->finish = (pfn_finish_hash)sd_platform_resolve_by_name(L"bcrypt.dll", "BCryptFinishHash");
  a->destroy = (pfn_destroy_hash)sd_platform_resolve_by_name(L"bcrypt.dll", "BCryptDestroyHash");
  return a->open_alg && a->create && a->data && a->finish && a->destroy;
}

static int cng_hash(const cng_hash_api *a, sd_bcrypt_handle alg, const uint8_t *key, size_t kl,
                    const uint8_t *msg, size_t ml, uint8_t *out, size_t outlen)
{
  sd_bcrypt_handle h = NULL;
  int ok;
  if (a->create(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)kl, 0) != 0)
    return 0;
  ok = a->data(h, (PUCHAR)msg, (ULONG)ml, 0) == 0 && a->finish(h, out, (ULONG)outlen, 0) == 0;
  a->destroy(h);
  return ok;
}

static int cng_available(void)
{
  if ((sd_crypto_caps_get()->os & SD_OS_CNG) == 0) {
    printf("    (CNG not available: differential test skipped)\n");
    return 0;
  }
  return 1;
}

SD_TEST(cng_diff_sha2_hmac)
{
  static const sd_hash_alg algs[3] = { SD_HASH_SHA256, SD_HASH_SHA384, SD_HASH_SHA512 };
  static const wchar_t *names[3] = { L"SHA256", L"SHA384", L"SHA512" };
  cng_hash_api api;
  uint8_t msg[2048], key[200], a[64], b[64];
  uint64_t rs = 0xc0ffee;
  int ai, i;
  if (!cng_available())
    return;
  SD_REQUIRE(load_hash_api(&api));
  for (ai = 0; ai < 3; ai++) {
    sd_bcrypt_handle hash_alg = NULL, hmac_alg = NULL;
    size_t hl = sd_hash_len(algs[ai]);
    SD_REQUIRE(api.open_alg(&hash_alg, names[ai], NULL, 0) == 0);
    SD_REQUIRE(api.open_alg(&hmac_alg, names[ai], NULL, 0x00000008 /* BCRYPT_ALG_HANDLE_HMAC_FLAG */) == 0);
    for (i = 0; i < 1500; i++) {
      size_t ml = tu_rand_u32(&rs) % sizeof(msg), kl = 1 + tu_rand_u32(&rs) % sizeof(key);
      sd_hmac_ctx hc;
      tu_rand_fill(&rs, msg, ml);
      tu_rand_fill(&rs, key, kl);
      sd_hash(algs[ai], msg, ml, a);
      SD_REQUIRE(cng_hash(&api, hash_alg, NULL, 0, msg, ml, b, hl));
      if (memcmp(a, b, hl) != 0) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "hash %d differs from CNG at len %u", ai, (unsigned)ml);
        break;
      }
      sd_hmac_init(&hc, algs[ai], key, kl);
      sd_hmac_update(&hc, msg, ml);
      sd_hmac_final(&hc, a);
      sd_hmac_wipe(&hc);
      SD_REQUIRE(cng_hash(&api, hmac_alg, key, kl, msg, ml, b, hl));
      if (memcmp(a, b, hl) != 0) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "hmac %d differs from CNG (klen %u, len %u)", ai,
                     (unsigned)kl, (unsigned)ml);
        break;
      }
    }
  }
}

SD_TEST(cng_diff_aes_ctr)
{
  uint8_t key[32], ctr[16], in[700], a[700], b[700];
  uint64_t rs = 11;
  int i;
  if (!cng_available())
    return;
  for (i = 0; i < 1500; i++) {
    static const size_t kls[3] = { 16, 24, 32 };
    size_t kl = kls[i % 3], len = tu_rand_u32(&rs) % sizeof(in);
    tu_rand_fill(&rs, key, kl);
    tu_rand_fill(&rs, ctr, 16);
    if (i % 7 == 0)
      memset(ctr + 4, 0xff, 12);                 /* long carry chains */
    tu_rand_fill(&rs, in, len);
    SD_REQUIRE(sd_aes_ctr_own(key, kl, ctr, in, len, a) == SD_OK);
    SD_REQUIRE(sd_aes_ctr_cng(key, kl, ctr, in, len, b) == SD_OK);
    if (memcmp(a, b, len) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "aes-ctr differs from CNG (klen %u, len %u)", (unsigned)kl,
                   (unsigned)len);
      break;
    }
  }
}

SD_TEST(cng_diff_aes_gcm)
{
  uint8_t key[32], nonce[12], aad[100], in[600], a[600], b[600], ta[16], tb[16];
  uint64_t rs = 12;
  int i;
  if (!cng_available())
    return;
  if ((sd_crypto_caps_get()->os & SD_OS_CNG_GCM) == 0) {
    printf("    (CNG GCM not available: skipped)\n");
    return;
  }
  for (i = 0; i < 1500; i++) {
    size_t kl = (i & 1) ? 32 : 16, len = tu_rand_u32(&rs) % sizeof(in), al = tu_rand_u32(&rs) % sizeof(aad);
    sd_err e1, e2;
    tu_rand_fill(&rs, key, kl);
    tu_rand_fill(&rs, nonce, 12);
    tu_rand_fill(&rs, aad, al);
    tu_rand_fill(&rs, in, len);
    SD_REQUIRE(sd_aes_gcm_encrypt_own(key, kl, nonce, aad, al, in, len, a, ta) == SD_OK);
    SD_REQUIRE(sd_aes_gcm_encrypt_cng(key, kl, nonce, aad, al, in, len, b, tb) == SD_OK);
    if (memcmp(a, b, len) != 0 || memcmp(ta, tb, 16) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "aes-gcm differs from CNG (klen %u, len %u, aad %u)",
                   (unsigned)kl, (unsigned)len, (unsigned)al);
      break;
    }
    /* decrypt each other's output; and a tampered tag must fail on both */
    SD_CHECK(sd_aes_gcm_decrypt_cng(key, kl, nonce, aad, al, a, len, ta, b) == SD_OK);
    SD_CHECK(memcmp(b, in, len) == 0);
    ta[i % 16] ^= 0x20;
    e1 = sd_aes_gcm_decrypt_own(key, kl, nonce, aad, al, a, len, ta, b);
    e2 = sd_aes_gcm_decrypt_cng(key, kl, nonce, aad, al, a, len, ta, b);
    SD_CHECK(e1 == SD_E_CRYPTO && e2 == SD_E_CRYPTO);
  }
}

SD_TEST(crypto_init_and_random)
{
  const sd_crypto_caps *caps;
  uint8_t a[64], b[64];
  SD_CHECK(sd_crypto_init(0) == SD_OK);
  caps = sd_crypto_caps_get();
  SD_REQUIRE(caps != NULL);
  printf("    caps: cpu=0x%x os=0x%x\n", caps->cpu, caps->os);
  SD_CHECK(sd_random(a, sizeof(a)) == SD_OK);
  SD_CHECK(sd_random(b, sizeof(b)) == SD_OK);
  SD_CHECK(memcmp(a, b, sizeof(a)) != 0);
  SD_CHECK(sd_random(a, 0) == SD_OK);
}
