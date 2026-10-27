/* AES (FIPS 197, SP 800-38A, GCM spec, Wycheproof), ChaCha20/Poly1305 (RFC 8439, Wycheproof), the
 * SSH packet ciphers and bcrypt_pbkdf (published vectors and an ssh-keygen key file). */
#include <stdlib.h>
#include <string.h>

#include "crypto_internal.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_ct.h"
#include "sd_test.h"
#include "tutil.h"

static void hx(sd_test_ctx *sd_t_, const char *hex, uint8_t *out, size_t n)
{
  if (tu_hexbuf(hex, out, n) != n)
    sd_test_fail(sd_t_, __FILE__, __LINE__, "bad test hex: %s", hex);
}

/* Reference S-box computed independently: inverse in GF(2^8) by exhaustive search, then the affine
   map of FIPS 197 §5.1.1. */
static uint8_t gmul(uint8_t a, uint8_t b)
{
  uint8_t p = 0;
  while (b) {
    if (b & 1) p ^= a;
    a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
    b >>= 1;
  }
  return p;
}

static uint8_t ref_sbox(uint8_t x)
{
  uint8_t inv = 0, s, r;
  int i;
  for (i = 1; i < 256 && x; i++)
    if (gmul(x, (uint8_t)i) == 1) { inv = (uint8_t)i; break; }
  s = inv;
  r = inv;
  for (i = 0; i < 4; i++) {
    r = (uint8_t)((r << 1) | (r >> 7));
    s ^= r;
  }
  return (uint8_t)(s ^ 0x63);
}

SD_TEST(aes_sbox_circuit)
{
  int x;
  uint8_t fwd[256];
  for (x = 0; x < 256; x++) {
    fwd[x] = ref_sbox((uint8_t)x);
    if (sd_aes_sbox_ct((uint8_t)x, 0) != fwd[x])
      sd_test_fail(sd_t_, __FILE__, __LINE__, "sbox(%02x) = %02x, want %02x", x, sd_aes_sbox_ct((uint8_t)x, 0), fwd[x]);
  }
  for (x = 0; x < 256; x++)
    if (sd_aes_sbox_ct(fwd[x], 1) != x)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "inv_sbox(%02x) != %02x", fwd[x], x);
}

SD_TEST(aes_fips197)
{
  static const char *keys[3] = {
    "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" };
  static const char *cts[3] = {
    "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191", "8ea2b7ca516745bfeafc49904b496089" };
  int i;
  for (i = 0; i < 3; i++) {
    uint8_t key[32], pt[64], ct[16], out[64], back[64];
    sd_aes_own k;
    size_t kl = tu_hexbuf(keys[i], key, 32), j;
    hx(sd_t_, "00112233445566778899aabbccddeeff", pt, 16);
    hx(sd_t_, cts[i], ct, 16);
    SD_REQUIRE(sd_aes_own_init(&k, key, kl) == SD_OK);
    /* every lane of the 4-block core gives the same answer */
    for (j = 1; j < 4; j++)
      memcpy(pt + 16 * j, pt, 16);
    sd_aes_own_encrypt(&k, pt, out, 4);
    for (j = 0; j < 4; j++)
      SD_CHECK_MEM(out + 16 * j, ct, 16);
    sd_aes_own_decrypt(&k, out, back, 4);
    SD_CHECK_MEM(back, pt, 64);
    sd_aes_own_encrypt(&k, pt, out, 1);
    SD_CHECK_MEM(out, ct, 16);
    sd_aes_own_wipe(&k);
  }
}

static const char k_38a_pt[] =
  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
  "f69f2445df4f9b17ad2b417be66c3710";

SD_TEST(aes_ctr_sp800_38a)
{
  uint8_t key[32], ctr[16], pt[64], want[64], out[64];
  hx(sd_t_, k_38a_pt, pt, 64);
  hx(sd_t_, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);
  hx(sd_t_, "2b7e151628aed2a6abf7158809cf4f3c", key, 16);
  hx(sd_t_, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee", want, 64);
  SD_CHECK(sd_aes_ctr_own(key, 16, ctr, pt, 64, out) == SD_OK);
  SD_CHECK_MEM(out, want, 64);
  SD_CHECK(sd_aes_ctr(key, 16, ctr, pt, 64, out) == SD_OK);
  SD_CHECK_MEM(out, want, 64);
  hx(sd_t_, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
  hx(sd_t_, "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988d"
            "dfc9c58db67aada613c2dd08457941a6", want, 64);
  SD_CHECK(sd_aes_ctr_own(key, 32, ctr, pt, 64, out) == SD_OK);
  SD_CHECK_MEM(out, want, 64);
  SD_CHECK(sd_aes_ctr(key, 32, ctr, pt, 64, out) == SD_OK);
  SD_CHECK_MEM(out, want, 64);
  /* oneshot naming */
  memcpy(out, pt, 64);
  SD_CHECK(sd_cipher_oneshot("aes256-ctr", 1, key, ctr, out, 64) == SD_OK);
  SD_CHECK_MEM(out, want, 64);
  SD_CHECK(sd_cipher_oneshot("des-cbc", 1, key, ctr, out, 64) == SD_E_UNSUPPORTED);
}

SD_TEST(aes_cbc_sp800_38a)
{
  uint8_t key[32], iv[16], pt[64], want[64], buf[64];
  hx(sd_t_, k_38a_pt, pt, 64);
  hx(sd_t_, "000102030405060708090a0b0c0d0e0f", iv, 16);
  hx(sd_t_, "2b7e151628aed2a6abf7158809cf4f3c", key, 16);
  hx(sd_t_, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7", want, 64);
  memcpy(buf, pt, 64);
  SD_CHECK(sd_cipher_oneshot("aes128-cbc", 1, key, iv, buf, 64) == SD_OK);
  SD_CHECK_MEM(buf, want, 64);
  SD_CHECK(sd_cipher_oneshot("AES-128-CBC", 0, key, iv, buf, 64) == SD_OK);
  SD_CHECK_MEM(buf, pt, 64);
  hx(sd_t_, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
  hx(sd_t_, "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b", want, 64);
  memcpy(buf, pt, 64);
  SD_CHECK(sd_cipher_oneshot("aes256-cbc", 1, key, iv, buf, 64) == SD_OK);
  SD_CHECK_MEM(buf, want, 64);
  SD_CHECK(sd_cipher_oneshot("aes256-cbc", 0, key, iv, buf, 64) == SD_OK);
  SD_CHECK_MEM(buf, pt, 64);
  SD_CHECK(sd_cipher_oneshot("aes256-cbc", 0, key, iv, buf, 15) == SD_E_INVALID_PARAM);
}

typedef struct gcm_kat { const char *key, *iv, *pt, *aad, *ct, *tag; } gcm_kat;

static const gcm_kat k_gcm[] = {
  { "00000000000000000000000000000000", "000000000000000000000000", "-", "-", "-",
    "58e2fccefa7e3061367f1d57a4e7455a" },
  { "00000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "-",
    "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf" },
  { "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255", "-",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4" },
  { "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
    "1ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47" },
  { "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "-", "-",
    "-", "530f8afbc74536b9a963b4f1c4cb738b" },
  { "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
    "00000000000000000000000000000000", "-", "cea7403d4d606b6e074ec5d3baf39d18",
    "d0d1c8a799996bf0265b98b5d48ab919" },
};

SD_TEST(aes_gcm_spec_vectors)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_gcm); i++) {
    uint8_t *key, *iv, *pt, *aad, *ct, tag[16], out[64], t[16];
    size_t kl = tu_hex(k_gcm[i].key, &key), pl, al, cl;
    (void)tu_hex(k_gcm[i].iv, &iv);   /* the IV length is known to the test table */
    pl = tu_hex(k_gcm[i].pt, &pt);
    al = tu_hex(k_gcm[i].aad, &aad);
    cl = tu_hex(k_gcm[i].ct, &ct);
    hx(sd_t_, k_gcm[i].tag, tag, 16);
    SD_CHECK(pl == cl);
    SD_CHECK(sd_aes_gcm_encrypt_own(key, kl, iv, aad, al, pt, pl, out, t) == SD_OK);
    SD_CHECK_MEM(out, ct, cl);
    SD_CHECK_MEM(t, tag, 16);
    SD_CHECK(sd_aes_gcm_decrypt_own(key, kl, iv, aad, al, ct, cl, tag, out) == SD_OK);
    SD_CHECK_MEM(out, pt, pl);
    SD_CHECK(sd_aes_gcm_encrypt(key, kl, iv, aad, al, pt, pl, out, t) == SD_OK);
    SD_CHECK_MEM(out, ct, cl);
    SD_CHECK_MEM(t, tag, 16);
    tag[3] ^= 4;
    SD_CHECK(sd_aes_gcm_decrypt_own(key, kl, iv, aad, al, ct, cl, tag, out) == SD_E_CRYPTO);
    SD_CHECK(sd_aes_gcm_decrypt(key, kl, iv, aad, al, ct, cl, tag, out) == SD_E_CRYPTO);
    free(key); free(iv); free(pt); free(aad); free(ct);
  }
}

typedef sd_err (*gcm_dec_fn)(const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t,
                             const uint8_t *, size_t, const uint8_t *, uint8_t *);

/* Wycheproof skips (01 §2.7.2): aes_gcm_test groups with IVs other than 96 bits or tags other than
   128 bits are dropped by convert.py (119 tests) because sd_aes_gcm_* and the SSH framing only take
   12-byte nonces and 16-byte tags. */
static int run_wycheproof_gcm(sd_test_ctx *sd_t_, gcm_dec_fn dec, int use_encrypt_own)
{
  tu_lines l;
  char *f[10];
  int n, count = 0;
  if (tu_lines_open(&l, "wycheproof/aes_gcm_test.txt") != 0) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "missing aes_gcm vectors");
    return 0;
  }
  while ((n = tu_lines_next(&l, f, 10)) != 0) {
    uint8_t *key, *iv, *aad, *msg, *ct, *out, tag[16], t[16];
    size_t kl = tu_hex(f[1], &key), al, ml, cl;
    sd_err err;
    (void)tu_hex(f[2], &iv);        /* the IV length is unused on this path */
    al = tu_hex(f[3], &aad);
    ml = tu_hex(f[4], &msg);
    cl = tu_hex(f[5], &ct);
    if (tu_hexbuf(f[6], tag, 16) != 16) continue;   /* wycheproof GCM tags are 16 bytes */
    out = (uint8_t *)tu_alloc(cl + 1);
    if (kl == 24 && dec != sd_aes_gcm_decrypt_own) {
      /* the public API documents 16/32-byte GCM keys; 24 is exercised on the own path only */
      free(key); free(iv); free(aad); free(msg); free(ct); free(out);
      continue;
    }
    err = dec(key, kl, iv, aad, al, ct, cl, tag, out);
    if (f[7][0] == 'v') {
      if (err != SD_OK || memcmp(out, msg, ml) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "aes-gcm tcId %s: valid case failed", f[0]);
      if (use_encrypt_own) {
        if (sd_aes_gcm_encrypt_own(key, kl, iv, aad, al, msg, ml, out, t) != SD_OK ||
            memcmp(out, ct, cl) != 0 || memcmp(t, tag, 16) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "aes-gcm tcId %s: encryption differs", f[0]);
      }
    } else if (f[7][0] == 'i' && err == SD_OK) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "aes-gcm tcId %s: invalid case accepted", f[0]);
    }
    free(key); free(iv); free(aad); free(msg); free(ct); free(out);
    count++;
  }
  tu_lines_close(&l);
  return count;
}

SD_TEST(wycheproof_aes_gcm_own)
{
  SD_CHECK(run_wycheproof_gcm(sd_t_, sd_aes_gcm_decrypt_own, 1) == 197);
}

SD_TEST(wycheproof_aes_gcm_dispatch)
{
  SD_CHECK(run_wycheproof_gcm(sd_t_, sd_aes_gcm_decrypt, 0) > 100);
}

SD_TEST(chacha20_rfc8439_block)
{
  /* RFC 8439 §2.3.2: key 00..1f, IETF nonce 000000090000004a00000000, counter 1. In the 64-bit
     layout: counter = 1 | (0x09000000 << 32), nonce = 0000004a00000000. */
  uint8_t key[32], nonce[8], zero[64], out[64], want[64];
  int i;
  for (i = 0; i < 32; i++)
    key[i] = (uint8_t)i;
  hx(sd_t_, "0000004a00000000", nonce, 8);
  memset(zero, 0, sizeof(zero));
  sd_chacha20(key, nonce, 1 | ((uint64_t)0x09000000 << 32), zero, 64, out);
  hx(sd_t_, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e", want, 64);
  SD_CHECK_MEM(out, want, 64);
}

SD_TEST(poly1305_rfc8439)
{
  uint8_t key[32], tag[16], want[16];
  static const char msg[] = "Cryptographic Forum Research Group";
  hx(sd_t_, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, 32);
  hx(sd_t_, "a8061dc1305136c6c22b8baf0c0127a9", want, 16);
  sd_poly1305(tag, (const uint8_t *)msg, strlen(msg), key);
  SD_CHECK_MEM(tag, want, 16);
}

/* RFC 8439 §2.8 AEAD built from the raw primitives (IETF nonce mapped onto the 64-bit layout). */
static void ietf_chacha(const uint8_t key[32], const uint8_t n12[12], uint32_t ctr, const uint8_t *in,
                        size_t len, uint8_t *out)
{
  uint64_t c = (uint64_t)ctr | ((uint64_t)sd_load_le32(n12) << 32);
  sd_chacha20(key, n12 + 4, c, in, len, out);
}

static void aead_tag(const uint8_t key[32], const uint8_t n12[12], const uint8_t *aad, size_t al,
                     const uint8_t *ct, size_t cl, uint8_t tag[16])
{
  uint8_t pk[32], *buf;
  size_t pa = (al + 15) & ~(size_t)15, pc = (cl + 15) & ~(size_t)15, i;
  buf = (uint8_t *)tu_alloc(pa + pc + 16);
  memset(pk, 0, 32);
  ietf_chacha(key, n12, 0, pk, 32, pk);
  if (al) memcpy(buf, aad, al);
  if (cl) memcpy(buf + pa, ct, cl);
  for (i = 0; i < 8; i++) {
    buf[pa + pc + i] = (uint8_t)((uint64_t)al >> (8 * i));
    buf[pa + pc + 8 + i] = (uint8_t)((uint64_t)cl >> (8 * i));
  }
  sd_poly1305(tag, buf, pa + pc + 16, pk);
  free(buf);
}

/* Wycheproof skips: the 9 chacha20_poly1305_test cases with non-96-bit nonces are dropped by
   convert.py (the RFC 8439 AEAD only defines 96-bit nonces). */
SD_TEST(wycheproof_chacha20_poly1305)
{
  tu_lines l;
  char *f[10];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "wycheproof/chacha20_poly1305_test.txt") == 0);
  while ((n = tu_lines_next(&l, f, 10)) != 0) {
    uint8_t *key, *iv, *aad, *msg, *ct, *tag, *out, t[16];
    size_t kl = tu_hex(f[1], &key), il, al, ml, cl;
    int ok;
    il = tu_hex(f[2], &iv);
    al = tu_hex(f[3], &aad);
    ml = tu_hex(f[4], &msg);
    cl = tu_hex(f[5], &ct);
    (void)tu_hex(f[6], &tag);       /* Poly1305 tags are 16 bytes; checked against t below */
    out = (uint8_t *)tu_alloc(cl + 1);
    SD_REQUIRE(kl == 32 && il == 12);
    aead_tag(key, iv, aad, al, ct, cl, t);
    ok = sd_ct_memeq(t, tag, 16);
    if (ok)
      ietf_chacha(key, iv, 1, ct, cl, out);
    if (f[7][0] == 'v' && (!ok || memcmp(out, msg, ml) != 0))
      sd_test_fail(sd_t_, __FILE__, __LINE__, "chacha20-poly1305 tcId %s: valid case failed", f[0]);
    if (f[7][0] == 'i' && ok)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "chacha20-poly1305 tcId %s: invalid case accepted", f[0]);
    free(key); free(iv); free(aad); free(msg); free(ct); free(out);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK(count == 316);
}

/* chacha20-poly1305@openssh.com rebuilt from PROTOCOL.chacha20poly1305 with the raw primitives. */
SD_TEST(pktcipher_chacha_openssh_construction)
{
  const sd_pktcipher_info *info = sd_pktcipher_find("chacha20-poly1305@openssh.com");
  uint8_t key[64], pkt[100], ref[100], tag[16], rtag[16], nonce[8], pk[32];
  sd_pktcipher *enc, *dec;
  uint32_t seq = 0x01020304, len;
  uint64_t rs = 5;
  SD_REQUIRE(info != NULL);
  SD_CHECK(info->key_len == 64 && info->tag_len == 16 && info->block_len == 8);
  SD_CHECK(info->flags == (SD_PC_AEAD | SD_PC_LEN_ENCRYPTED));
  tu_rand_fill(&rs, key, 64);
  tu_rand_fill(&rs, pkt, sizeof(pkt));
  pkt[0] = 0; pkt[1] = 0; pkt[2] = 0; pkt[3] = 96;
  memcpy(ref, pkt, sizeof(pkt));
  /* reference: K_2 = key[0..31] (main), K_1 = key[32..63] (length) */
  memset(nonce, 0, 4);
  sd_store_be32(nonce + 4, seq);
  memset(pk, 0, 32);
  sd_chacha20(key, nonce, 0, pk, 32, pk);
  sd_chacha20(key + 32, nonce, 0, ref, 4, ref);
  sd_chacha20(key, nonce, 1, ref + 4, 96, ref + 4);
  sd_poly1305(rtag, ref, 100, pk);

  SD_REQUIRE(sd_pktcipher_new(info, 1, key, NULL, &enc) == SD_OK);
  SD_REQUIRE(sd_pktcipher_new(info, 0, key, NULL, &dec) == SD_OK);
  SD_CHECK(sd_pktcipher_seal(enc, seq, pkt, 100, tag) == SD_OK);
  SD_CHECK_MEM(pkt, ref, 100);
  SD_CHECK_MEM(tag, rtag, 16);
  SD_CHECK(sd_pktcipher_peek_len(dec, seq, pkt, &len) == SD_OK);
  SD_CHECK_EQ_U64(len, 96);
  pkt[50] ^= 1;
  SD_CHECK(sd_pktcipher_open(dec, seq, pkt, 100, tag) == SD_E_CRYPTO);
  SD_CHECK_MEM(pkt + 4, ref + 4, 46);              /* nothing decrypted on failure */
  pkt[50] ^= 1;
  SD_CHECK(sd_pktcipher_open(dec, seq + 1, pkt, 100, tag) == SD_E_CRYPTO);
  SD_CHECK(sd_pktcipher_open(dec, seq, pkt, 100, tag) == SD_OK);
  SD_CHECK(pkt[3] == 96);
  SD_CHECK(sd_pktcipher_crypt(dec, pkt, 16) == SD_E_INVALID_PARAM);
  sd_pktcipher_free(enc);
  sd_pktcipher_free(dec);
}

static void gcm_pkt_roundtrip(sd_test_ctx *sd_t_, const char *name, size_t kl)
{
  const sd_pktcipher_info *info = sd_pktcipher_find(name);
  uint8_t key[32], iv[12], pkt[4 + 64], orig[4 + 64], tag[16], ct[64], t[16], nonce[12];
  sd_pktcipher *enc, *dec;
  uint64_t rs = 77;
  int round;
  SD_REQUIRE(info != NULL && info->key_len == kl && info->iv_len == 12 && info->flags == SD_PC_AEAD);
  tu_rand_fill(&rs, key, sizeof(key));
  tu_rand_fill(&rs, iv, sizeof(iv));
  iv[11] = 0xfe;                                   /* exercises the carry of the invocation counter */
  SD_REQUIRE(sd_pktcipher_new(info, 1, key, iv, &enc) == SD_OK);
  SD_REQUIRE(sd_pktcipher_new(info, 0, key, iv, &dec) == SD_OK);
  memcpy(nonce, iv, 12);
  for (round = 0; round < 4; round++) {
    tu_rand_fill(&rs, orig, sizeof(orig));
    memcpy(pkt, orig, sizeof(pkt));
    SD_CHECK(sd_pktcipher_seal(enc, (uint32_t)round, pkt, sizeof(pkt), tag) == SD_OK);
    SD_CHECK_MEM(pkt, orig, 4);                    /* length stays clear (AAD) */
    SD_CHECK(sd_aes_gcm_encrypt_own(key, kl, nonce, orig, 4, orig + 4, 64, ct, t) == SD_OK);
    SD_CHECK_MEM(pkt + 4, ct, 64);
    SD_CHECK_MEM(tag, t, 16);
    if (round == 1) {
      uint8_t keep[sizeof(pkt)];
      memcpy(keep, pkt, sizeof(pkt));
      tag[0] ^= 1;
      SD_CHECK(sd_pktcipher_open(dec, 0, pkt, sizeof(pkt), tag) == SD_E_CRYPTO);
      /* no plaintext released on a tag mismatch: CNG zeroes the buffer, the own path never decrypted it */
      SD_CHECK(memcmp(pkt + 4, orig + 4, 64) != 0);
      tag[0] ^= 1;
      memcpy(pkt, keep, sizeof(pkt));
      /* sticky failure: the same object refuses the next record, even with a valid tag */
      SD_CHECK(sd_pktcipher_open(dec, 0, pkt, sizeof(pkt), tag) == SD_E_CRYPTO);
      memcpy(pkt, keep, sizeof(pkt));
      sd_pktcipher_free(dec);                      /* the failed open ends this stream: restart */
      SD_REQUIRE(sd_pktcipher_new(info, 0, key, nonce, &dec) == SD_OK);
    }
    SD_CHECK(sd_pktcipher_open(dec, 0, pkt, sizeof(pkt), tag) == SD_OK);
    SD_CHECK_MEM(pkt, orig, sizeof(orig));
    /* next invocation counter (big-endian increment of the last 8 bytes) */
    {
      int i;
      for (i = 11; i >= 4; i--)
        if (++nonce[i] != 0)
          break;
    }
  }
  sd_pktcipher_free(enc);
  sd_pktcipher_free(dec);
}

SD_TEST(pktcipher_aes_gcm)
{
  gcm_pkt_roundtrip(sd_t_, "aes128-gcm@openssh.com", 16);
  gcm_pkt_roundtrip(sd_t_, "aes256-gcm@openssh.com", 32);
}

SD_TEST(pktcipher_aes_ctr_streams)
{
  static const char *names[3] = { "aes128-ctr", "aes192-ctr", "aes256-ctr" };
  int i;
  SD_CHECK(sd_pktcipher_find("blowfish-cbc") == NULL);   /* aes*-cbc and 3des-cbc exist since M2 */
  SD_CHECK(sd_pktcipher_find(NULL) == NULL);
  for (i = 0; i < 3; i++) {
    const sd_pktcipher_info *info = sd_pktcipher_find(names[i]);
    uint8_t key[32], iv[16], data[5000], ref[5000];
    sd_pktcipher *c;
    uint64_t rs = 3 + (uint64_t)i;
    size_t off = 0;
    SD_REQUIRE(info != NULL && info->tag_len == 0 && info->block_len == 16);
    tu_rand_fill(&rs, key, 32);
    tu_rand_fill(&rs, iv, 16);
    memset(iv + 8, 0xff, 8);                       /* carry across the low 64 bits */
    tu_rand_fill(&rs, data, sizeof(data) - 8);
    SD_REQUIRE(sd_aes_ctr_own(key, info->key_len, iv, data, 4992, ref) == SD_OK);
    SD_REQUIRE(sd_pktcipher_new(info, 1, key, iv, &c) == SD_OK);
    while (off < 4992) {                           /* split into whole-block pieces */
      size_t r = 16 * (1 + tu_rand_u32(&rs) % 40);
      size_t step = SD_MIN(r, 4992 - off);
      SD_CHECK(sd_pktcipher_crypt(c, data + off, step) == SD_OK);
      off += step;
    }
    SD_CHECK_MEM(data, ref, 4992);
    SD_CHECK(sd_pktcipher_crypt(c, data, 15) == SD_E_INVALID_PARAM);
    sd_pktcipher_free(c);
  }
}

/* The same packet tests with the CNG backend switched off (own bitsliced AES + GHASH in sd_pktcipher). */
SD_TEST_DECL(pktcipher_aes_gcm);
SD_TEST_DECL(pktcipher_aes_ctr_streams);
SD_TEST(pktcipher_own_backend)
{
  sd_crypto_test_force_own(1);
  sd_test_pktcipher_aes_gcm(sd_t_);
  sd_test_pktcipher_aes_ctr_streams(sd_t_);
  sd_crypto_test_force_own(0);
}

typedef struct bcrypt_kat { uint32_t rounds; const char *pass; size_t plen; const char *salt; size_t slen;
                            const char *out; } bcrypt_kat;

SD_TEST(bcrypt_pbkdf_vectors)
{
  /* UTF-8 of the Russian test strings */
  static const char rpass[] = "\xd1\x81\xd0\xb5\xd0\xba\xd1\x80\xd0\xb5\xd1\x82\xd0\xbd\xd0\xbe\xd0\xb5 "
                              "\xd1\x81\xd0\xbb\xd0\xbe\xd0\xb2\xd0\xbe";
  static const char rsalt[] = "\xd0\xbf\xd0\xbe\xd1\x81\xd0\xbe\xd0\xbb\xd0\xb8\xd1\x82\xd1\x8c "
                              "\xd0\xbd\xd0\xb5\xd0\xbc\xd0\xbd\xd0\xbe\xd0\xb6\xd0\xba\xd0\xbe";
  const bcrypt_kat kats[3] = {
    { 12, "password", 8, "salt", 4, "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a" },
    { 3, "passwordy\0PASSWORD\0", 19, "salty\0SALT\0", 11,
      "7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad" },
    { 8, rpass, sizeof(rpass) - 1, rsalt, sizeof(rsalt) - 1,
      "8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733ea765f315a3e1e4afc35bf8687d18925"
      "4c1e05a6fe80c0617f9183d67260d6a115c6c94e3603e2303fbb43a76a64523ffda686b1d4518543" },
  };
  size_t i;
  for (i = 0; i < 3; i++) {
    uint8_t want[128], got[128];
    size_t n = tu_hexbuf(kats[i].out, want, sizeof(want));
    SD_REQUIRE(n != SIZE_MAX);
    SD_CHECK(sd_bcrypt_pbkdf(kats[i].pass, kats[i].plen, (const uint8_t *)kats[i].salt, kats[i].slen,
                             kats[i].rounds, got, n) == SD_OK);
    SD_CHECK_MEM(got, want, n);
  }
  SD_CHECK(sd_bcrypt_pbkdf("p", 1, (const uint8_t *)"s", 1, 0, (uint8_t *)&i, 1) == SD_E_INVALID_PARAM);
}

static uint32_t rd32(const uint8_t **p, const uint8_t *end, int *ok)
{
  uint32_t v;
  if (end - *p < 4) { *ok = 0; return 0; }
  v = sd_load_be32(*p);
  *p += 4;
  return v;
}

static const uint8_t *rdstr(const uint8_t **p, const uint8_t *end, uint32_t *len, int *ok)
{
  const uint8_t *s;
  *len = rd32(p, end, ok);
  if (!*ok || (size_t)(end - *p) < *len) { *ok = 0; return NULL; }
  s = *p;
  *p += *len;
  return s;
}

/* openssh-key-v1 (PROTOCOL.key) decrypted with bcrypt_pbkdf + aes256-ctr; the private section must
   pass the check-int test and hold a seed whose Ed25519 public key matches. */
SD_TEST(openssh_keyfile_bcrypt_aes256ctr)
{
  static const char pass[] = "correct horse battery staple";
  char *pem = tu_read_vector_file("openssh/ed25519_aes256ctr_r16.key", NULL), *b, *e;
  uint8_t blob[1024], kiv[48], derived_pub[32];
  const uint8_t *p, *end, *cipher, *kdf, *opts, *pub, *priv, *salt, *q, *qend, *ppub, *ppriv;
  uint32_t cl, kl, ol, publ, privl, sl, rounds, nkeys, l1, l2;
  size_t blen;
  int ok = 1;
  SD_REQUIRE(pem != NULL);
  b = strstr(pem, "-----BEGIN OPENSSH PRIVATE KEY-----");
  e = strstr(pem, "-----END OPENSSH PRIVATE KEY-----");
  SD_REQUIRE(b && e);
  *e = 0;
  blen = tu_base64(b + 35, blob, sizeof(blob));
  SD_REQUIRE(blen != SIZE_MAX && blen > 15 && memcmp(blob, "openssh-key-v1", 15) == 0);
  p = blob + 15;
  end = blob + blen;
  cipher = rdstr(&p, end, &cl, &ok);
  kdf = rdstr(&p, end, &kl, &ok);
  opts = rdstr(&p, end, &ol, &ok);
  nkeys = rd32(&p, end, &ok);
  pub = rdstr(&p, end, &publ, &ok);
  priv = rdstr(&p, end, &privl, &ok);
  SD_REQUIRE(ok && nkeys == 1);
  SD_REQUIRE(cl == 10 && memcmp(cipher, "aes256-ctr", 10) == 0 && kl == 6 && memcmp(kdf, "bcrypt", 6) == 0);
  q = opts;
  qend = opts + ol;
  salt = rdstr(&q, qend, &sl, &ok);
  rounds = rd32(&q, qend, &ok);
  SD_REQUIRE(ok && rounds == 16 && privl % 16 == 0);
  SD_REQUIRE(sd_bcrypt_pbkdf(pass, strlen(pass), salt, sl, rounds, kiv, 48) == SD_OK);
  SD_REQUIRE(sd_cipher_oneshot("aes256-ctr", 0, kiv, kiv + 32, (uint8_t *)priv, privl) == SD_OK);
  q = priv;
  qend = priv + privl;
  l1 = rd32(&q, qend, &ok);
  l2 = rd32(&q, qend, &ok);
  SD_CHECK(ok && l1 == l2);                         /* wrong key/KDF would fail here */
  rdstr(&q, qend, &cl, &ok);                        /* key type */
  ppub = rdstr(&q, qend, &kl, &ok);
  ppriv = rdstr(&q, qend, &ol, &ok);
  SD_REQUIRE(ok && kl == 32 && ol == 64);
  SD_CHECK(memcmp(ppub, pub + publ - 32, 32) == 0);
  SD_CHECK(memcmp(ppriv + 32, ppub, 32) == 0);
  SD_CHECK(sd_ed25519_pub_from_seed(derived_pub, ppriv) == SD_OK);
  SD_CHECK_MEM(derived_pub, ppub, 32);
  free(pem);
}
