/* BLAKE2b (RFC 7693 Appendix A, BLAKE2 reference KAT), Argon2d/i/id (RFC 9106 section 5) and the
 * PuTTY PPK v3 key derivation (Argon2 -> AES-256-CBC key || IV || HMAC-SHA-256 key) on fixtures
 * written by tests/vectors/pq/ppk_fixture.py. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

SD_TEST(blake2b_rfc7693_and_kat)
{
  static const char abc512[] =
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
    "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
  uint8_t out[64], exp[64];
  tu_lines l;
  char *f[3];
  int n = 0;
  SD_REQUIRE(sd_blake2b(out, 64, NULL, 0, "abc", 3) == SD_OK);
  SD_REQUIRE(tu_hexbuf(abc512, exp, 64) == 64);
  SD_CHECK(memcmp(out, exp, 64) == 0);
  SD_CHECK(sd_blake2b(out, 0, NULL, 0, "abc", 3) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_blake2b(out, 65, NULL, 0, "abc", 3) == SD_E_INVALID_PARAM);
  SD_REQUIRE(tu_lines_open(&l, "pq/blake2b_kat.txt") == 0);
  while (tu_lines_next(&l, f, 3) == 3) {
    uint8_t *in, *key, *h;
    size_t il = tu_hex(f[0], &in), kl = tu_hex(f[1], &key), hl = tu_hex(f[2], &h);
    sd_blake2b_ctx c;
    size_t pos = 0;
    SD_CHECK(sd_blake2b(out, hl, key, kl, in, il) == SD_OK);
    if (memcmp(out, h, hl) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "blake2b KAT case %d", n);
    /* the same in odd-sized pieces */
    SD_CHECK(sd_blake2b_init(&c, hl, key, kl) == SD_OK);
    while (pos < il) {
      size_t take = SD_MIN(il - pos, (size_t)(1 + (pos * 7 + 3) % 61));
      sd_blake2b_update(&c, in + pos, take);
      pos += take;
    }
    sd_blake2b_final(&c, out);
    SD_CHECK(memcmp(out, h, hl) == 0);
    free(in);
    free(key);
    free(h);
    n++;
  }
  tu_lines_close(&l);
  SD_CHECK(n == 256);
}

SD_TEST(argon2_rfc9106)
{
  static const char *tags[3] = {
    "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",   /* 5.1 Argon2d */
    "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",   /* 5.2 Argon2i */
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",   /* 5.3 Argon2id */
  };
  static const sd_argon2_type types[3] = { SD_ARGON2D, SD_ARGON2I, SD_ARGON2ID };
  uint8_t pw[32], salt[16], secret[8], ad[12], out[32], exp[32];
  volatile long cancel = 1;
  int i;
  memset(pw, 1, sizeof(pw));
  memset(salt, 2, sizeof(salt));
  memset(secret, 3, sizeof(secret));
  memset(ad, 4, sizeof(ad));
  for (i = 0; i < 3; i++) {
    SD_REQUIRE(tu_hexbuf(tags[i], exp, 32) == 32);
    SD_CHECK(sd_argon2_ex(types[i], 32, 3, 4, pw, 32, salt, 16, secret, 8, ad, 12, out, 32, NULL) == SD_OK);
    if (memcmp(out, exp, 32) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "RFC 9106 vector %d", i);
  }
  SD_CHECK(sd_argon2(SD_ARGON2ID, 7, 1, 1, pw, 32, salt, 16, out, 32, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_argon2(SD_ARGON2ID, 64, 0, 1, pw, 32, salt, 16, out, 32, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_argon2(SD_ARGON2ID, 64, 1, 1, pw, 32, salt, 16, out, 3, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_argon2(SD_ARGON2ID, SD_ARGON2_MAX_MEM_KIB + 1, 1, 1, pw, 32, salt, 16, out, 32, NULL) ==
           SD_E_UNSUPPORTED);
  SD_CHECK(sd_argon2(SD_ARGON2ID, 64, SD_ARGON2_MAX_PASSES + 1, 1, pw, 32, salt, 16, out, 32, NULL) ==
           SD_E_UNSUPPORTED);
  SD_CHECK(sd_argon2(SD_ARGON2ID, 64, 2, 1, pw, 32, salt, 16, out, 32, &cancel) == SD_E_CANCELLED);
}

/* ---- PPK v3 ---- */

typedef struct ppk {
  char alg[64], enc[32], comment[128], kdf[16];
  uint32_t mem, passes, par;
  uint8_t salt[64], pub[512], priv[512], mac[32];
  size_t salt_len, pub_len, priv_len;
} ppk;

static const char *field(char *line, const char *name)
{
  size_t n = strlen(name);
  return strncmp(line, name, n) == 0 && line[n] == ':' && line[n + 1] == ' ' ? line + n + 2 : NULL;
}

static size_t b64_lines(char **pos, int count, uint8_t *out, size_t cap)
{
  char buf[4096];
  int i;
  buf[0] = 0;
  for (i = 0; i < count; i++) {
    char *e = strchr(*pos, '\n');
    if (e == NULL)
      return SIZE_MAX;
    *e = 0;
    if (e > *pos && e[-1] == '\r')
      e[-1] = 0;
    if (strlen(buf) + strlen(*pos) >= sizeof(buf))
      return SIZE_MAX;
    strcat_s(buf, sizeof(buf), *pos);
    *pos = e + 1;
  }
  return tu_base64(buf, out, cap);
}

static int ppk_parse(char *text, ppk *k)
{
  char *pos = text;
  memset(k, 0, sizeof(*k));
  while (*pos) {
    char *e = strchr(pos, '\n'), *line = pos;
    const char *v;
    if (e == NULL)
      break;
    *e = 0;
    if (e > pos && e[-1] == '\r')
      e[-1] = 0;
    pos = e + 1;
    if ((v = field(line, "PuTTY-User-Key-File-3")) != NULL) strcpy_s(k->alg, sizeof(k->alg), v);
    else if ((v = field(line, "Encryption")) != NULL) strcpy_s(k->enc, sizeof(k->enc), v);
    else if ((v = field(line, "Comment")) != NULL) strcpy_s(k->comment, sizeof(k->comment), v);
    else if ((v = field(line, "Key-Derivation")) != NULL) strcpy_s(k->kdf, sizeof(k->kdf), v);
    else if ((v = field(line, "Argon2-Memory")) != NULL) k->mem = (uint32_t)atoi(v);
    else if ((v = field(line, "Argon2-Passes")) != NULL) k->passes = (uint32_t)atoi(v);
    else if ((v = field(line, "Argon2-Parallelism")) != NULL) k->par = (uint32_t)atoi(v);
    else if ((v = field(line, "Argon2-Salt")) != NULL) k->salt_len = tu_hexbuf(v, k->salt, sizeof(k->salt));
    else if ((v = field(line, "Public-Lines")) != NULL) k->pub_len = b64_lines(&pos, atoi(v), k->pub, sizeof(k->pub));
    else if ((v = field(line, "Private-Lines")) != NULL)
      k->priv_len = b64_lines(&pos, atoi(v), k->priv, sizeof(k->priv));
    else if ((v = field(line, "Private-MAC")) != NULL) {
      if (tu_hexbuf(v, k->mac, sizeof(k->mac)) != 32)
        return 0;
    }
  }
  return k->alg[0] && k->kdf[0] && k->salt_len != SIZE_MAX && k->pub_len != SIZE_MAX && k->priv_len != SIZE_MAX &&
         k->priv_len % 16 == 0;
}

static void mac_string(sd_hmac_ctx *h, const void *p, size_t n)
{
  uint8_t len[4];
  len[0] = (uint8_t)(n >> 24);
  len[1] = (uint8_t)(n >> 16);
  len[2] = (uint8_t)(n >> 8);
  len[3] = (uint8_t)n;
  sd_hmac_update(h, len, 4);
  sd_hmac_update(h, p, n);
}

SD_TEST(ppk_v3_key_derivation)
{
  static const char *files[3] = { "pq/ed25519_ppk3_argon2id.ppk", "pq/ed25519_ppk3_argon2i.ppk",
                                  "pq/ed25519_ppk3_argon2d.ppk" };
  static const char pass[] = "correct horse battery staple";
  int i;
  for (i = 0; i < 3; i++) {
    char *text = tu_read_vector_file(files[i], NULL);
    ppk k;
    uint8_t km[80], plain[512], mac[32], seed[32], pub[32];
    sd_argon2_type t;
    sd_hmac_ctx h;
    size_t mlen, j;
    SD_REQUIRE(text != NULL);
    SD_REQUIRE(ppk_parse(text, &k));
    SD_CHECK(strcmp(k.alg, "ssh-ed25519") == 0 && strcmp(k.enc, "aes256-cbc") == 0);
    t = strcmp(k.kdf, "Argon2id") == 0 ? SD_ARGON2ID : strcmp(k.kdf, "Argon2i") == 0 ? SD_ARGON2I : SD_ARGON2D;
    SD_CHECK(sd_argon2(t, k.mem, k.passes, k.par, pass, sizeof(pass) - 1, k.salt, k.salt_len, km, 80, NULL) ==
             SD_OK);
    SD_CHECK(sd_aes_cbc(0, km, 32, km + 32, k.priv, k.priv_len, plain) == SD_OK);
    sd_hmac_init(&h, SD_HASH_SHA256, km + 48, 32);
    mac_string(&h, k.alg, strlen(k.alg));
    mac_string(&h, k.enc, strlen(k.enc));
    mac_string(&h, k.comment, strlen(k.comment));
    mac_string(&h, k.pub, k.pub_len);
    mac_string(&h, plain, k.priv_len);
    sd_hmac_final(&h, mac);
    sd_hmac_wipe(&h);
    if (memcmp(mac, k.mac, 32) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: Private-MAC mismatch", files[i]);
      free(text);
      continue;
    }
    /* private blob: mpint of the Ed25519 private key read as a little-endian integer */
    mlen = ((size_t)plain[0] << 24) | ((size_t)plain[1] << 16) | ((size_t)plain[2] << 8) | plain[3];
    SD_REQUIRE(mlen <= 33 && 4 + mlen <= k.priv_len);
    memset(seed, 0, sizeof(seed));
    for (j = 0; j < mlen && j < 32; j++)
      seed[j] = plain[4 + mlen - 1 - j];
    SD_CHECK(sd_ed25519_pub_from_seed(pub, seed) == SD_OK);
    SD_CHECK(k.pub_len == 51 && memcmp(pub, k.pub + 19, 32) == 0);
    /* a wrong passphrase gives a different MAC */
    SD_CHECK(sd_argon2(t, k.mem, k.passes, k.par, "x", 1, k.salt, k.salt_len, km, 80, NULL) == SD_OK);
    sd_hmac_init(&h, SD_HASH_SHA256, km + 48, 32);
    mac_string(&h, plain, k.priv_len);
    sd_hmac_final(&h, mac);
    sd_hmac_wipe(&h);
    SD_CHECK(memcmp(mac, k.mac, 32) != 0);
    free(text);
  }
}
