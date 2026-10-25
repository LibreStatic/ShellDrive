/* CNG (bcrypt.dll) backend for AES-ECB (CTR keystream) and AES-GCM (01 §2.2). Every bcrypt entry
 * point is resolved through sd_platform_resolve, so the XP build has no bcrypt import; probing does
 * not trust the OS version: it opens the provider and sets the chaining mode. Algorithm handles are
 * opened once and kept for the process lifetime (CNG allows concurrent use of algorithm handles);
 * keys belong to one owner. */
#include <windows.h>
#include <bcrypt.h>
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((LONG)0xC000A002L)
#endif

static sd_bcrypt_handle g_alg_ecb, g_alg_gcm;
static ULONG g_obj_ecb, g_obj_gcm;

struct sd_cng_key {
  sd_bcrypt_handle key;
  uint8_t *obj;
  ULONG objlen;
};

#define PFN(name) ((sd_pfn_##name)sd_platform_resolve(SD_API_##name))

static int open_mode(sd_bcrypt_handle *alg, ULONG *objlen, const wchar_t *mode)
{
  sd_pfn_BCryptOpenAlgorithmProvider open_alg = PFN(BCryptOpenAlgorithmProvider);
  sd_pfn_BCryptSetProperty setp = PFN(BCryptSetProperty);
  sd_pfn_BCryptGetProperty getp = PFN(BCryptGetProperty);
  sd_pfn_BCryptCloseAlgorithmProvider close_alg = PFN(BCryptCloseAlgorithmProvider);
  sd_bcrypt_handle h = NULL;
  ULONG got = 0, len = 0;
  if (!open_alg || !setp || !getp || !close_alg || !PFN(BCryptGenerateSymmetricKey) ||
      !PFN(BCryptDestroyKey) || !PFN(BCryptEncrypt) || !PFN(BCryptDecrypt))
    return 0;
  if (open_alg(&h, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
    return 0;
  if (setp(h, BCRYPT_CHAINING_MODE, (PUCHAR)mode, (ULONG)((wcslen(mode) + 1) * sizeof(wchar_t)), 0) != 0 ||
      getp(h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&len, sizeof(len), &got, 0) != 0 || got != sizeof(len)) {
    close_alg(h, 0);
    return 0;
  }
  *alg = h;
  *objlen = len;
  return 1;
}

sd_err sd_cng_probe(uint32_t *os_caps)
{
  if (open_mode(&g_alg_ecb, &g_obj_ecb, BCRYPT_CHAIN_MODE_ECB))
    *os_caps |= SD_OS_CNG;
  if (open_mode(&g_alg_gcm, &g_obj_gcm, BCRYPT_CHAIN_MODE_GCM))
    *os_caps |= SD_OS_CNG_GCM;
  return SD_OK;
}

sd_err sd_cng_key_new(const uint8_t *key, size_t key_len, int gcm, sd_cng_key **out)
{
  sd_bcrypt_handle alg = gcm ? g_alg_gcm : g_alg_ecb;
  ULONG objlen = gcm ? g_obj_gcm : g_obj_ecb;
  sd_pfn_BCryptGenerateSymmetricKey gen = PFN(BCryptGenerateSymmetricKey);
  sd_cng_key *k;
  *out = NULL;
  sd_crypto_ensure_init();
  if (alg == NULL || gen == NULL)
    return SD_E_UNSUPPORTED;
  if (key_len != 16 && key_len != 24 && key_len != 32)
    return SD_E_INVALID_PARAM;
  k = (sd_cng_key *)sd_calloc(1, sizeof(*k));
  if (k == NULL)
    return SD_E_NO_MEMORY;
  k->objlen = objlen;
  k->obj = (uint8_t *)sd_calloc(1, objlen ? objlen : 1);
  if (k->obj == NULL) {
    sd_free(k);
    return SD_E_NO_MEMORY;
  }
  if (gen(alg, &k->key, k->obj, objlen, (PUCHAR)key, (ULONG)key_len, 0) != 0) {
    sd_secure_free(k->obj, objlen ? objlen : 1);
    sd_free(k);
    return SD_E_UNSUPPORTED;
  }
  *out = k;
  return SD_OK;
}

void sd_cng_key_free(sd_cng_key *k)
{
  sd_pfn_BCryptDestroyKey destroy = PFN(BCryptDestroyKey);
  if (k == NULL)
    return;
  if (k->key && destroy)
    destroy(k->key);
  sd_secure_free(k->obj, k->objlen ? k->objlen : 1);
  sd_secure_free(k, sizeof(*k));
}

sd_err sd_cng_ecb_encrypt(sd_cng_key *k, const uint8_t *in, uint8_t *out, size_t len)
{
  sd_pfn_BCryptEncrypt enc = PFN(BCryptEncrypt);
  ULONG got = 0;
  if (len % 16 || len > 0x7fffffffu)
    return SD_E_INVALID_PARAM;
  if (enc(k->key, (PUCHAR)in, (ULONG)len, NULL, NULL, 0, out, (ULONG)len, &got, 0) != 0 || got != len)
    return SD_E_CRYPTO;
  return SD_OK;
}

sd_err sd_cng_gcm(sd_cng_key *k, int encrypt, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                  const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16])
{
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  ULONG got = 0;
  LONG st;
  if (len > 0x7fffffffu || aad_len > 0x7fffffffu)
    return SD_E_UNSUPPORTED;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = (PUCHAR)nonce;
  info.cbNonce = 12;
  info.pbAuthData = aad_len ? (PUCHAR)aad : NULL;
  info.cbAuthData = (ULONG)aad_len;
  info.pbTag = tag;
  info.cbTag = 16;
  if (encrypt)
    st = PFN(BCryptEncrypt)(k->key, (PUCHAR)in, (ULONG)len, &info, NULL, 0, out, (ULONG)len, &got, 0);
  else
    st = PFN(BCryptDecrypt)(k->key, (PUCHAR)in, (ULONG)len, &info, NULL, 0, out, (ULONG)len, &got, 0);
  if (st == STATUS_AUTH_TAG_MISMATCH) {
    if (len)
      sd_secure_zero(out, len);
    return SD_E_CRYPTO;
  }
  if (st != 0 || got != len) {
    if (len)
      sd_secure_zero(out, len);
    return SD_E_CRYPTO;
  }
  return SD_OK;
}

sd_err sd_aes_ctr_cng(const uint8_t *key, size_t key_len, const uint8_t ctr[16],
                      const uint8_t *in, size_t len, uint8_t *out)
{
  uint8_t blocks[4096], c[16];
  sd_cng_key *k;
  sd_err err = sd_cng_key_new(key, key_len, 0, &k);
  if (err != SD_OK)
    return err;
  memcpy(c, ctr, 16);
  while (len && err == SD_OK) {
    size_t n = SD_MIN(len, sizeof(blocks)), nb = (n + 15) / 16, i;
    for (i = 0; i < nb; i++) {
      int j;
      uint32_t carry = 1;
      memcpy(blocks + 16 * i, c, 16);
      for (j = 15; j >= 0; j--) {
        carry += c[j];
        c[j] = (uint8_t)carry;
        carry >>= 8;
      }
    }
    err = sd_cng_ecb_encrypt(k, blocks, blocks, nb * 16);
    for (i = 0; err == SD_OK && i < n; i++)
      out[i] = (uint8_t)(in[i] ^ blocks[i]);
    in += n;
    out += n;
    len -= n;
  }
  sd_secure_zero(blocks, sizeof(blocks));
  sd_cng_key_free(k);
  return err;
}

sd_err sd_aes_gcm_encrypt_cng(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              uint8_t *out, uint8_t tag[16])
{
  sd_cng_key *k;
  sd_err err = sd_cng_key_new(key, key_len, 1, &k);
  if (err != SD_OK)
    return err;
  err = sd_cng_gcm(k, 1, nonce, aad, aad_len, in, len, out, tag);
  sd_cng_key_free(k);
  return err;
}

sd_err sd_aes_gcm_decrypt_cng(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                              const uint8_t tag[16], uint8_t *out)
{
  uint8_t t[16];
  sd_cng_key *k;
  sd_err err = sd_cng_key_new(key, key_len, 1, &k);
  if (err != SD_OK)
    return err;
  memcpy(t, tag, 16);
  err = sd_cng_gcm(k, 0, nonce, aad, aad_len, in, len, out, t);
  sd_cng_key_free(k);
  return err;
}
