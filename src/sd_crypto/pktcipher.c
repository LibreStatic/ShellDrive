/* SSH packet protection objects (01 §2.6) and the one-shot key-file cipher.
 *
 * chacha20-poly1305@openssh.com follows OpenSSH PROTOCOL.chacha20poly1305: the 64-byte key is
 * K_2 (bytes 0..31, payload and Poly1305 key) then K_1 (bytes 32..63, length field); the nonce is
 * the 64-bit big-endian sequence number; the Poly1305 key is the first 32 bytes of K_2 block 0; the
 * payload uses K_2 from block counter 1; the tag covers encrypted length || encrypted payload.
 * aesN-gcm@openssh.com follows RFC 5647 framing: AAD = 4-byte packet length, 12-byte nonce = 4-byte
 * fixed field + 64-bit invocation counter, incremented after every packet. aesN-ctr keeps one
 * 128-bit big-endian counter across calls. aesN-cbc and 3des-cbc (RFC 4253 6.3, legacy, decisions.md D33)
 * keep the CBC chaining value across calls; 3DES is the constant-time core of des3.c. */
#include <string.h>

#include "crypto_internal.h"
#include "des3_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"

enum { PC_CHACHA = 1, PC_GCM = 2, PC_CTR = 3, PC_CBC = 4, PC_3DES = 5 };

static const sd_pktcipher_info k_infos[] = {
  { "chacha20-poly1305@openssh.com", 64, 0, 8, 16, SD_PC_AEAD | SD_PC_LEN_ENCRYPTED },
  { "aes128-gcm@openssh.com", 16, 12, 16, 16, SD_PC_AEAD },
  { "aes256-gcm@openssh.com", 32, 12, 16, 16, SD_PC_AEAD },
  { "aes128-ctr", 16, 16, 16, 0, 0 },
  { "aes192-ctr", 24, 16, 16, 0, 0 },
  { "aes256-ctr", 32, 16, 16, 0, 0 },
  { "aes128-cbc", 16, 16, 16, 0, SD_PC_CBC | SD_PC_LEGACY },
  { "aes192-cbc", 24, 16, 16, 0, SD_PC_CBC | SD_PC_LEGACY },
  { "aes256-cbc", 32, 16, 16, 0, SD_PC_CBC | SD_PC_LEGACY },
  { "3des-cbc", 24, 8, 8, 0, SD_PC_CBC | SD_PC_LEGACY },
};

struct sd_pktcipher {
  const sd_pktcipher_info *info;
  int kind;
  int encrypt;
  uint8_t k_main[32], k_hdr[32];   /* chacha: K_2, K_1 */
  uint8_t iv[16];                  /* gcm: nonce (12 bytes); ctr: counter block; cbc: chaining value */
  sd_cng_key *cng;                 /* CNG key when that backend is used, else NULL */
  sd_aes_own aes;
  sd_des3_key des3;
  int failed;                      /* a GCM open failed: the record stream is dead, later GCM opens refuse */
};

const sd_pktcipher_info *sd_pktcipher_find(const char *ssh_name)
{
  size_t i;
  if (ssh_name == NULL)
    return NULL;
  for (i = 0; i < SD_COUNTOF(k_infos); i++)
    if (strcmp(k_infos[i].ssh_name, ssh_name) == 0)
      return &k_infos[i];
  return NULL;
}

static int kind_of(const sd_pktcipher_info *i)
{
  size_t n = (size_t)(i - k_infos);
  if (i < k_infos || n >= SD_COUNTOF(k_infos))
    return 0;
  return n == 0 ? PC_CHACHA : n <= 2 ? PC_GCM : n <= 5 ? PC_CTR : n <= 8 ? PC_CBC : PC_3DES;
}

sd_err sd_pktcipher_new(const sd_pktcipher_info *i, int encrypt, const uint8_t *key, const uint8_t *iv,
                        sd_pktcipher **out)
{
  sd_pktcipher *c;
  sd_err err = SD_OK;
  int kind;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  kind = i ? kind_of(i) : 0;
  if (kind == 0 || key == NULL || (i->iv_len && iv == NULL))
    return SD_E_INVALID_PARAM;
  c = (sd_pktcipher *)sd_calloc(1, sizeof(*c));
  if (c == NULL)
    return SD_E_NO_MEMORY;
  c->info = i;
  c->kind = kind;
  c->encrypt = encrypt != 0;
  if (kind == PC_CHACHA) {
    memcpy(c->k_main, key, 32);
    memcpy(c->k_hdr, key + 32, 32);
  } else if (kind == PC_3DES) {
    memcpy(c->iv, iv, 8);
    sd_des3_key_init(&c->des3, key);
  } else if (kind == PC_CBC) {
    memcpy(c->iv, iv, 16);
    err = sd_aes_own_init(&c->aes, key, i->key_len);
  } else {
    memcpy(c->iv, iv, i->iv_len);
    if ((kind == PC_GCM && sd_crypto_use_cng_gcm()) || (kind == PC_CTR && sd_crypto_use_cng_aes()))
      if (sd_cng_key_new(key, i->key_len, kind == PC_GCM, &c->cng) != SD_OK)
        c->cng = NULL;
    if (c->cng == NULL)
      err = sd_aes_own_init(&c->aes, key, i->key_len);
  }
  if (err != SD_OK) {
    sd_pktcipher_free(c);
    return err;
  }
  *out = c;
  return SD_OK;
}

void sd_pktcipher_free(sd_pktcipher *c)
{
  if (c == NULL)
    return;
  sd_cng_key_free(c->cng);
  sd_secure_free(c, sizeof(*c));
}

static void ctr_inc128(uint8_t c[16])
{
  int i;
  uint32_t carry = 1;
  for (i = 15; i >= 0; i--) {
    carry += c[i];
    c[i] = (uint8_t)carry;
    carry >>= 8;
  }
}

/* AES-CBC on the own constant-time core; iv is the chaining value and is updated; in may equal out.
   Decryption runs four blocks per core call. */
static void aes_cbc_own(const sd_aes_own *k, int encrypt, uint8_t iv[16], const uint8_t *in, size_t len,
                        uint8_t *out)
{
  size_t i, j;
  if (encrypt) {
    uint8_t blk[16];
    for (i = 0; i < len; i += 16) {
      for (j = 0; j < 16; j++)
        blk[j] = (uint8_t)(in[i + j] ^ iv[j]);
      sd_aes_own_encrypt(k, blk, out + i, 1);
      memcpy(iv, out + i, 16);
    }
    sd_secure_zero(blk, sizeof(blk));
  } else {
    uint8_t ct[64], pt[64];
    for (i = 0; i < len; i += 64) {
      size_t n_bytes = SD_MIN((size_t)64, len - i);
      memcpy(ct, in + i, n_bytes);
      sd_aes_own_decrypt(k, ct, pt, n_bytes / 16);
      for (j = 0; j < n_bytes; j++)
        out[i + j] = (uint8_t)(pt[j] ^ (j < 16 ? iv[j] : ct[j - 16]));
      memcpy(iv, ct + n_bytes - 16, 16);
    }
    sd_secure_zero(pt, sizeof(pt));
    sd_secure_zero(ct, sizeof(ct));
  }
}

sd_err sd_aes_cbc(int encrypt, const uint8_t *key, size_t key_len, const uint8_t iv[16],
                  const uint8_t *in, size_t len, uint8_t *out)
{
  sd_aes_own k;
  uint8_t chain[16];
  sd_err err;
  if (key == NULL || iv == NULL || len % 16 || (len && (in == NULL || out == NULL)))
    return SD_E_INVALID_PARAM;
  err = sd_aes_own_init(&k, key, key_len);
  if (err != SD_OK)
    return err;
  memcpy(chain, iv, 16);
  aes_cbc_own(&k, encrypt, chain, in, len, out);
  sd_secure_zero(chain, sizeof(chain));
  sd_aes_own_wipe(&k);
  return SD_OK;
}

sd_err sd_pktcipher_crypt(sd_pktcipher *c, uint8_t *buf, size_t len)
{
  if (c == NULL || (len && buf == NULL))
    return SD_E_INVALID_PARAM;
  if (c->kind == PC_CBC || c->kind == PC_3DES) {
    if (len % c->info->block_len)
      return SD_E_INVALID_PARAM;
    if (c->kind == PC_3DES)
      sd_des3_cbc(&c->des3, c->encrypt, c->iv, buf, len, buf);
    else
      aes_cbc_own(&c->aes, c->encrypt, c->iv, buf, len, buf);
    return SD_OK;
  }
  if (c->kind != PC_CTR || len % 16)
    return SD_E_INVALID_PARAM;
  if (c->cng) {
    uint8_t ks[4096];
    sd_err err = SD_OK;
    while (len && err == SD_OK) {
      size_t n = SD_MIN(len, sizeof(ks)), i;
      for (i = 0; i < n; i += 16) {
        memcpy(ks + i, c->iv, 16);
        ctr_inc128(c->iv);
      }
      err = sd_cng_ecb_encrypt(c->cng, ks, ks, n);
      for (i = 0; err == SD_OK && i < n; i++)
        buf[i] ^= ks[i];
      buf += n;
      len -= n;
    }
    sd_secure_zero(ks, sizeof(ks));
    return err;
  }
  sd_aes_own_ctr(&c->aes, c->iv, buf, len, buf);
  return SD_OK;
}

static void seq_nonce(uint8_t nonce[8], uint32_t seq)
{
  memset(nonce, 0, 4);
  sd_store_be32(nonce + 4, seq);
}

static void chacha_polykey(const sd_pktcipher *c, const uint8_t nonce[8], uint8_t pk[32])
{
  memset(pk, 0, 32);
  sd_chacha20(c->k_main, nonce, 0, pk, 32, pk);
}

static void gcm_next_iv(sd_pktcipher *c)
{
  int i;
  for (i = 11; i >= 4; i--)
    if (++c->iv[i] != 0)
      break;
}

sd_err sd_pktcipher_seal(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, uint8_t *tag)
{
  sd_err err = SD_OK;
  if (c == NULL || pkt == NULL || tag == NULL || len < 4 || !(c->info->flags & SD_PC_AEAD))
    return SD_E_INVALID_PARAM;
  if (c->kind == PC_CHACHA) {
    uint8_t nonce[8], pk[32];
    seq_nonce(nonce, seq);
    chacha_polykey(c, nonce, pk);
    sd_chacha20(c->k_hdr, nonce, 0, pkt, 4, pkt);
    sd_chacha20(c->k_main, nonce, 1, pkt + 4, len - 4, pkt + 4);
    sd_poly1305(tag, pkt, len, pk);
    sd_secure_zero(pk, sizeof(pk));
    return SD_OK;
  }
  if (c->cng) {
    err = sd_cng_gcm(c->cng, 1, c->iv, pkt, 4, pkt + 4, len - 4, pkt + 4, tag);
  } else {
    uint8_t ctr[16];
    memcpy(ctr, c->iv, 12);
    sd_store_be32(ctr + 12, 2);
    sd_gcm_own_ctr32(&c->aes, ctr, pkt + 4, len - 4, pkt + 4);
    sd_gcm_own_tag(&c->aes, c->iv, pkt, 4, pkt + 4, len - 4, tag);
  }
  gcm_next_iv(c);
  return err;
}

/* Own GCM open: tag check over AAD || ciphertext before any decryption. */
static sd_err gcm_open_own(sd_pktcipher *c, uint8_t *pkt, size_t len, const uint8_t *tag)
{
  uint8_t calc[16], ctr[16];
  sd_gcm_own_tag(&c->aes, c->iv, pkt, 4, pkt + 4, len - 4, calc);
  if (!sd_ct_memeq(calc, tag, 16))
    return SD_E_CRYPTO;
  memcpy(ctr, c->iv, 12);
  sd_store_be32(ctr + 12, 2);
  sd_gcm_own_ctr32(&c->aes, ctr, pkt + 4, len - 4, pkt + 4);
  return SD_OK;
}

sd_err sd_pktcipher_open(sd_pktcipher *c, uint32_t seq, uint8_t *pkt, size_t len, const uint8_t *tag)
{
  sd_err err;
  if (c == NULL || pkt == NULL || tag == NULL || len < 4 || !(c->info->flags & SD_PC_AEAD))
    return SD_E_INVALID_PARAM;
  if (c->kind == PC_CHACHA) {
    uint8_t nonce[8], pk[32], calc[16];
    int ok;
    seq_nonce(nonce, seq);
    chacha_polykey(c, nonce, pk);
    sd_poly1305(calc, pkt, len, pk);
    sd_secure_zero(pk, sizeof(pk));
    ok = sd_ct_memeq(calc, tag, 16);
    if (!ok)
      return SD_E_CRYPTO;
    sd_chacha20(c->k_hdr, nonce, 0, pkt, 4, pkt);
    sd_chacha20(c->k_main, nonce, 1, pkt + 4, len - 4, pkt + 4);
    return SD_OK;
  }
  /* RFC 5647 / OpenSSH: a failed record ends the connection (SD_E_CRYPTO is fatal to the caller).
     The sticky flag makes that hold at this layer too: no later record is decrypted with a counter
     that the failed record left out of step. Both backends wipe or never write the plaintext on
     a tag mismatch (sd_cng_gcm zeroes the buffer; gcm_open_own checks the tag before decrypting). */
  if (c->failed)
    return SD_E_CRYPTO;
  if (c->cng) {
    uint8_t t[16];
    memcpy(t, tag, 16);
    err = sd_cng_gcm(c->cng, 0, c->iv, pkt, 4, pkt + 4, len - 4, pkt + 4, t);
  } else {
    err = gcm_open_own(c, pkt, len, tag);
  }
  if (err != SD_OK) {
    c->failed = 1;
    return err;
  }
  gcm_next_iv(c);
  return SD_OK;
}

sd_err sd_pktcipher_peek_len(sd_pktcipher *c, uint32_t seq, const uint8_t enc_len[4], uint32_t *len)
{
  uint8_t nonce[8], plain[4];
  if (c == NULL || enc_len == NULL || len == NULL || c->kind != PC_CHACHA)
    return SD_E_INVALID_PARAM;
  seq_nonce(nonce, seq);
  sd_chacha20(c->k_hdr, nonce, 0, enc_len, 4, plain);
  *len = sd_load_be32(plain);
  return SD_OK;
}

/* ---- one-shot cipher for key files ---- */

typedef struct oneshot_name { const char *name; uint8_t key_len; uint8_t cbc; } oneshot_name;

static const oneshot_name k_oneshot[] = {
  { "aes128-ctr", 16, 0 }, { "aes192-ctr", 24, 0 }, { "aes256-ctr", 32, 0 },
  { "aes128-cbc", 16, 1 }, { "aes192-cbc", 24, 1 }, { "aes256-cbc", 32, 1 },
  { "AES-128-CBC", 16, 1 }, { "AES-192-CBC", 24, 1 }, { "AES-256-CBC", 32, 1 },   /* PEM DEK-Info */
  { "3des-cbc", 24, 2 }, { "DES-EDE3-CBC", 24, 2 },                              /* cbc = 2: 3DES */
};

sd_err sd_cipher_oneshot(const char *ssh_or_pem_name, int encrypt, const uint8_t *key, const uint8_t *iv,
                         uint8_t *buf, size_t len)
{
  const oneshot_name *n = NULL;
  size_t i;
  if (ssh_or_pem_name == NULL || key == NULL || iv == NULL || (len && buf == NULL))
    return SD_E_INVALID_PARAM;
  for (i = 0; i < SD_COUNTOF(k_oneshot); i++)
    if (strcmp(k_oneshot[i].name, ssh_or_pem_name) == 0)
      n = &k_oneshot[i];
  if (n == NULL)
    return SD_E_UNSUPPORTED;
  if (n->cbc == 0)
    return sd_aes_ctr(key, n->key_len, iv, buf, len, buf);
  if (n->cbc == 2)
    return sd_3des_cbc(encrypt, key, iv, buf, len, buf);
  return sd_aes_cbc(encrypt, key, n->key_len, iv, buf, len, buf);
}