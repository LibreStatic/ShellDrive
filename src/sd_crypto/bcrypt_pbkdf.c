/* bcrypt_pbkdf as used by OpenSSH key files (OpenSSH PROTOCOL.key; Provos-Mazieres 1999 "A
 * Future-Adaptable Password Scheme" for EksBlowfish; Schneier 1993 for Blowfish), written from the
 * algorithm descriptions:
 *
 *   bcrypt_hash(P, S): state = EksBlowfishSetup with salt S and key P (64-byte SHA-512 digests),
 *     then 64 rounds of expand0(S), expand0(P); encrypt "OxychromaticBlowfishSwatDynamite"
 *     (eight big-endian words) 64 times in ECB; output the words little-endian (32 bytes).
 *   bcrypt_pbkdf: for each output block i: T = bcrypt_hash(SHA512(P), SHA512(S || be32(i))),
 *     then rounds - 1 more iterations of U = bcrypt_hash(SHA512(P), SHA512(U)), T ^= U; the key
 *     bytes are spread over the blocks with stride ceil(keylen / 32).
 *
 * Blowfish indexes its S-boxes with key-dependent data, an accepted exception to rule 2.4.4 for this
 * offline, local KDF over key-file passphrases (01 §2.5 lists bcrypt-pbkdf as own code from the
 * spec). State lives in a heap block that is wiped on exit, not on the stack. */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"

#include "blowfish_pi.inc"

typedef struct blf {
  uint32_t p[18];
  uint32_t s[4][256];
} blf;

#define BLF_F(c, x) \
  ((((c)->s[0][(x) >> 24] + (c)->s[1][((x) >> 16) & 0xff]) ^ (c)->s[2][((x) >> 8) & 0xff]) + \
   (c)->s[3][(x) & 0xff])

static void blf_encipher(const blf *c, uint32_t *xl, uint32_t *xr)
{
  uint32_t l = *xl, r = *xr;
  int i;
  for (i = 0; i < 16; i += 2) {
    l ^= c->p[i];
    r ^= BLF_F(c, l);
    r ^= c->p[i + 1];
    l ^= BLF_F(c, r);
  }
  *xl = r ^ c->p[17];
  *xr = l ^ c->p[16];
}

/* Next 32-bit big-endian word of data, cycling (Blowfish key schedule convention). */
static uint32_t stream_word(const uint8_t *data, size_t len, size_t *pos)
{
  uint32_t w = 0;
  int i;
  for (i = 0; i < 4; i++) {
    w = (w << 8) | data[*pos];
    *pos = (*pos + 1) % len;
  }
  return w;
}

static void blf_init(blf *c)
{
  memcpy(c->p, k_blf_pi, sizeof(c->p));
  memcpy(c->s, k_blf_pi + 18, sizeof(c->s));
}

/* EksBlowfish expandstate (with data) and expand0state (data == NULL). */
static void blf_expand(blf *c, const uint8_t *data, size_t dlen, const uint8_t *key, size_t klen)
{
  size_t kp = 0, dp = 0;
  uint32_t l = 0, r = 0;
  int i, k;
  for (i = 0; i < 18; i++)
    c->p[i] ^= stream_word(key, klen, &kp);
  for (i = 0; i < 18; i += 2) {
    if (data) {
      l ^= stream_word(data, dlen, &dp);
      r ^= stream_word(data, dlen, &dp);
    }
    blf_encipher(c, &l, &r);
    c->p[i] = l;
    c->p[i + 1] = r;
  }
  for (i = 0; i < 4; i++)
    for (k = 0; k < 256; k += 2) {
      if (data) {
        l ^= stream_word(data, dlen, &dp);
        r ^= stream_word(data, dlen, &dp);
      }
      blf_encipher(c, &l, &r);
      c->s[i][k] = l;
      c->s[i][k + 1] = r;
    }
}

static void bcrypt_hash(blf *c, const uint8_t pass[64], const uint8_t salt[64], uint8_t out[32])
{
  static const char magic[] = "OxychromaticBlowfishSwatDynamite";
  uint32_t cdata[8];
  size_t pos = 0;
  int i, j;
  blf_init(c);
  blf_expand(c, salt, 64, pass, 64);
  for (i = 0; i < 64; i++) {
    blf_expand(c, NULL, 0, salt, 64);
    blf_expand(c, NULL, 0, pass, 64);
  }
  for (i = 0; i < 8; i++)
    cdata[i] = stream_word((const uint8_t *)magic, 32, &pos);
  for (i = 0; i < 64; i++)
    for (j = 0; j < 8; j += 2)
      blf_encipher(c, &cdata[j], &cdata[j + 1]);
  for (i = 0; i < 8; i++)
    sd_store_le32(out + 4 * i, cdata[i]);
  sd_secure_zero(cdata, sizeof(cdata));
}

sd_err sd_bcrypt_pbkdf(const void *pass, size_t plen, const uint8_t *salt, size_t slen, uint32_t rounds,
                       uint8_t *out, size_t outlen)
{
  typedef struct work {
    blf c;
    uint8_t sha2pass[64], sha2salt[64], tmp[32], acc[32], cnt[4];
  } work;
  work *w;
  size_t stride, amt, keylen = outlen, i;
  uint32_t count, r;
  sd_hash_ctx h;
  if (rounds < 1 || plen == 0 || slen == 0 || pass == NULL || salt == NULL || out == NULL ||
      outlen == 0 || outlen > 32 * 32 || slen > ((size_t)1 << 20))
    return SD_E_INVALID_PARAM;
  w = (work *)sd_calloc(1, sizeof(*w));
  if (w == NULL)
    return SD_E_NO_MEMORY;
  stride = (outlen + 32 - 1) / 32;
  amt = (outlen + stride - 1) / stride;
  sd_hash(SD_HASH_SHA512, pass, plen, w->sha2pass);
  for (count = 1; keylen > 0; count++) {
    sd_store_be32(w->cnt, count);
    sd_hash_init(&h, SD_HASH_SHA512);
    sd_hash_update(&h, salt, slen);
    sd_hash_update(&h, w->cnt, 4);
    sd_hash_final(&h, w->sha2salt);
    bcrypt_hash(&w->c, w->sha2pass, w->sha2salt, w->tmp);
    memcpy(w->acc, w->tmp, 32);
    for (r = 1; r < rounds; r++) {
      sd_hash(SD_HASH_SHA512, w->tmp, 32, w->sha2salt);
      bcrypt_hash(&w->c, w->sha2pass, w->sha2salt, w->tmp);
      for (i = 0; i < 32; i++)
        w->acc[i] ^= w->tmp[i];
    }
    amt = SD_MIN(amt, keylen);
    for (i = 0; i < amt; i++) {
      size_t dest = i * stride + (count - 1);
      if (dest >= outlen)
        break;
      out[dest] = w->acc[i];
    }
    keylen -= i;
  }
  sd_secure_free(w, sizeof(*w));
  return SD_OK;
}
