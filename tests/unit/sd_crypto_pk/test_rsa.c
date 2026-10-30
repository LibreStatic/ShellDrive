/* RSA PKCS#1 v1.5: Wycheproof rsa_signature_* (verify) and rsa_pkcs1_*_sig_gen (sign, non-CRT keys),
 * keys from the independent Python reference (CRT keys up to 16384 bits, odd shapes), import validation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

typedef struct hexbuf { uint8_t *p; size_t n; } hexbuf;

static hexbuf hb(const char *hex)
{
  hexbuf b;
  b.p = NULL;                 /* defined seed: the analyzer cannot see through tu_hex */
  b.n = tu_hex(hex, &b.p);
  return b;
}

static void verify_suite(sd_test_ctx *sd_t_, const char *file, int *total)
{
  tu_lines l;
  char *f[8];
  int n, skip = 0;
  sd_rsa_key *k = NULL;
  sd_hash_alg h = SD_HASH_SHA256;
  if (tu_lines_open(&l, file) != 0) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "missing %s", file);
    return;
  }
  while ((n = tu_lines_next(&l, f, 8)) > 0) {
    if (f[0][0] == 'K') {
      sd_rsa_import_params ip;
      hexbuf nn = hb(f[3]), ee = hb(f[4]);
      sd_rsa_free(k);
      k = NULL;
      memset(&ip, 0, sizeof(ip));
      ip.n = nn.p; ip.n_len = nn.n; ip.e = ee.p; ip.e_len = ee.n;
      skip = !pkt_hash(f[2], &h) || sd_rsa_import(&ip, &k) != SD_OK;
      if (skip && pkt_hash(f[2], &h))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: key import failed", file);
      free(nn.p);
      free(ee.p);
    } else if (!skip) {
      hexbuf msg = hb(f[3]), sig = hb(f[4]);
      uint8_t dg[64];
      sd_err e;
      sd_hash(h, msg.p, msg.n, dg);
      e = sd_rsa_pkcs1_verify(k, h, dg, sd_hash_len(h), sig.p, sig.n);
      if (f[2][0] == 'v' && e != SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: valid signature rejected (%d)", file, f[1], (int)e);
      if (f[2][0] == 'i' && e == SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: invalid signature accepted", file, f[1]);
      free(msg.p);
      free(sig.p);
      (*total)++;
    }
  }
  sd_rsa_free(k);
  tu_lines_close(&l);
}

SD_TEST(wycheproof_rsa_pkcs1_verify)
{
  static const char *files[] = {
    "wycheproof/rsa_signature_2048_sha256_test.txt", "wycheproof/rsa_signature_2048_sha384_test.txt",
    "wycheproof/rsa_signature_2048_sha512_test.txt", "wycheproof/rsa_signature_3072_sha256_test.txt",
    "wycheproof/rsa_signature_3072_sha512_test.txt", "wycheproof/rsa_signature_4096_sha256_test.txt",
    "wycheproof/rsa_signature_4096_sha512_test.txt", "wycheproof/rsa_signature_8192_sha256_test.txt",
    "wycheproof/rsa_signature_8192_sha512_test.txt",
  };
  size_t i;
  int total = 0;
  for (i = 0; i < SD_COUNTOF(files); i++)
    verify_suite(sd_t_, files[i], &total);
  printf("    %d verifications\n", total);
  SD_CHECK(total > 2000);
}

/* Wycheproof sig_gen: n, e, d only (no CRT parameters). Sign must reproduce the published signature. */
SD_TEST(wycheproof_rsa_pkcs1_sign)
{
  static const char *files[] = {
    "wycheproof/rsa_pkcs1_1024_sig_gen_test.txt", "wycheproof/rsa_pkcs1_1536_sig_gen_test.txt",
    "wycheproof/rsa_pkcs1_2048_sig_gen_test.txt", "wycheproof/rsa_pkcs1_3072_sig_gen_test.txt",
    "wycheproof/rsa_pkcs1_4096_sig_gen_test.txt",
  };
  size_t i;
  int total = 0, skipped = 0;
  for (i = 0; i < SD_COUNTOF(files); i++) {
    tu_lines l;
    char *f[8];
    int n, skip = 0;
    sd_rsa_key *k = NULL;
    sd_hash_alg h = SD_HASH_SHA256;
    SD_REQUIRE(tu_lines_open(&l, files[i]) == 0);
    while ((n = tu_lines_next(&l, f, 8)) > 0) {
      if (f[0][0] == 'K') {
        sd_rsa_import_params ip;
        hexbuf nn = hb(f[3]), ee = hb(f[4]), dd = hb(f[5]);
        sd_rsa_free(k);
        k = NULL;
        memset(&ip, 0, sizeof(ip));
        ip.n = nn.p; ip.n_len = nn.n; ip.e = ee.p; ip.e_len = ee.n; ip.d = dd.p; ip.d_len = dd.n;
        skip = !pkt_hash(f[2], &h);       /* SHA-224 keys: sd_crypto has no SHA-224 */
        if (!skip && sd_rsa_import(&ip, &k) != SD_OK) {
          sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: private key import failed", files[i]);
          skip = 1;
        }
        free(nn.p);
        free(ee.p);
        free(dd.p);
      } else if (skip) {
        skipped++;
      } else {
        uint8_t *msg_p = NULL, *want_p = NULL;   /* direct tu_hex calls: hb's struct return loses the SAL state */
        size_t msg_n = tu_hex(f[3], &msg_p), want_n = tu_hex(f[4], &want_p);
        uint8_t dg[64], sig[1024];
        size_t sl = sizeof(sig);
        sd_hash(h, msg_p, msg_n, dg);
        if (sd_rsa_pkcs1_sign(k, h, dg, sd_hash_len(h), sig, &sl) != SD_OK || sl != want_n ||
            memcmp(sig, want_p, sl) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: signature differs", files[i], f[1]);
        SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg, sd_hash_len(h), sig, sl) == SD_OK);
        free(msg_p);
        free(want_p);
        total++;
      }
    }
    sd_rsa_free(k);
    tu_lines_close(&l);
  }
  printf("    %d signatures (%d SHA-224 cases skipped: no SHA-224 in sd_crypto)\n", total, skipped);
  SD_CHECK(total > 100);
}

typedef struct refkey {
  unsigned bits;
  hexbuf n, e, d, p, q, iqmp;
} refkey;

static void refkey_free(refkey *r)
{
  free(r->n.p); free(r->e.p); free(r->d.p); free(r->p.p); free(r->q.p); free(r->iqmp.p);
  memset(r, 0, sizeof(*r));
}

static void params_full(sd_rsa_import_params *ip, const refkey *r)
{
  memset(ip, 0, sizeof(*ip));
  ip->n = r->n.p; ip->n_len = r->n.n; ip->e = r->e.p; ip->e_len = r->e.n; ip->d = r->d.p; ip->d_len = r->d.n;
  ip->p = r->p.p; ip->p_len = r->p.n; ip->q = r->q.p; ip->q_len = r->q.n;
  ip->iqmp = r->iqmp.p; ip->iqmp_len = r->iqmp.n;
}

/* Python reference keys (CRT) and their deterministic signatures; key variants and import errors. */
SD_TEST(rsa_reference_keys)
{
  tu_lines l;
  char *f[9];
  int n, keys = 0, sigs = 0, skip_key = 0;
  refkey rk;
  sd_rsa_key *k = NULL, *kswap = NULL, *knocrt = NULL;
  memset(&rk, 0, sizeof(rk));
  SD_REQUIRE(tu_lines_open(&l, "refimpl/rsa_keys.txt") == 0);
  while ((n = tu_lines_next(&l, f, 9)) > 0) {
    if (f[0][0] == 'K') {
      sd_rsa_import_params ip;
      SD_REQUIRE(n == 8);
      sd_rsa_free(k); sd_rsa_free(kswap); sd_rsa_free(knocrt);
      k = kswap = knocrt = NULL;
      refkey_free(&rk);
      rk.bits = (unsigned)atoi(f[1]);
#ifdef _DEBUG
      if (rk.bits > 8192) {     /* unoptimized 16384-bit CRT signing takes minutes; Release covers it */
        printf("    (Debug build: %u-bit reference key skipped)\n", rk.bits);
        skip_key = 1;
        continue;
      }
#endif
      skip_key = 0;
      rk.n = hb(f[2]); rk.e = hb(f[3]); rk.d = hb(f[4]); rk.p = hb(f[5]); rk.q = hb(f[6]); rk.iqmp = hb(f[7]);
      params_full(&ip, &rk);
      SD_REQUIRE(sd_rsa_import(&ip, &k) == SD_OK);
      SD_CHECK_EQ_U64(sd_rsa_bits(k), rk.bits);
      SD_CHECK_EQ_U64(sd_rsa_len(k), (rk.bits + 7) / 8);
      SD_CHECK(sd_rsa_has_private(k));
      if (rk.bits <= 4096) {
        /* p and q swapped, iqmp omitted (q > p shapes and the computed inverse) */
        params_full(&ip, &rk);
        ip.p = rk.q.p; ip.p_len = rk.q.n; ip.q = rk.p.p; ip.q_len = rk.p.n; ip.iqmp = NULL;
        SD_CHECK(sd_rsa_import(&ip, &kswap) == SD_OK);
        /* the given iqmp no longer matches the swapped order */
        {
          sd_rsa_key *bad = NULL;
          ip.iqmp = rk.iqmp.p; ip.iqmp_len = rk.iqmp.n;
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_FORMAT);
          SD_CHECK(bad == NULL);
        }
        /* d only */
        params_full(&ip, &rk);
        ip.p = ip.q = ip.iqmp = NULL;
        SD_CHECK(sd_rsa_import(&ip, &knocrt) == SD_OK);
        /* broken components */
        {
          sd_rsa_key *bad = NULL;
          uint8_t save;
          params_full(&ip, &rk);
          ip.q = rk.p.p; ip.q_len = rk.p.n;                       /* p*p != n */
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_FORMAT);
          params_full(&ip, &rk);
          save = rk.d.p[rk.d.n - 1];
          rk.d.p[rk.d.n - 1] ^= 2;                                /* d no longer inverts e */
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_FORMAT);
          ip.p = ip.q = ip.iqmp = NULL;
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_FORMAT);
          rk.d.p[rk.d.n - 1] = save;
          params_full(&ip, &rk);
          ip.min_bits = rk.bits + 1;                              /* caller policy */
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_UNSUPPORTED);
          params_full(&ip, &rk);
          ip.max_bits = rk.bits - 1;
          SD_CHECK(sd_rsa_import(&ip, &bad) == SD_E_KEY_UNSUPPORTED);
          SD_CHECK(bad == NULL);
        }
      }
      keys++;
    } else if (!skip_key) {
      sd_hash_alg h;
      uint8_t *dg_p = NULL, *want_p = NULL;   /* direct tu_hex calls: hb loses the SAL state */
      size_t dg_n = tu_hex(f[2], &dg_p), want_n = tu_hex(f[3], &want_p);
      uint8_t *sig = (uint8_t *)tu_alloc(2048);
      size_t sl = 2048;
      SD_REQUIRE(n == 4 && pkt_hash(f[1], &h));
      SD_CHECK(sd_rsa_pkcs1_sign(k, h, dg_p, dg_n, sig, &sl) == SD_OK);
      SD_CHECK(sl == want_n && memcmp(sig, want_p, sl) == 0);
      SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg_p, dg_n, want_p, want_n) == SD_OK);
      if (kswap) {
        sl = 2048;
        SD_CHECK(sd_rsa_pkcs1_sign(kswap, h, dg_p, dg_n, sig, &sl) == SD_OK && memcmp(sig, want_p, sl) == 0);
      }
      if (knocrt) {
        sl = 2048;
        SD_CHECK(sd_rsa_pkcs1_sign(knocrt, h, dg_p, dg_n, sig, &sl) == SD_OK && memcmp(sig, want_p, sl) == 0);
      }
      /* tampering */
      want_p[want_n - 1] ^= 1;
      SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg_p, dg_n, want_p, want_n) == SD_E_CRYPTO);
      SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg_p, dg_n, want_p, want_n - 1) == SD_E_CRYPTO);
      dg_p[0] ^= 1;
      want_p[want_n - 1] ^= 1;
      SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg_p, dg_n, want_p, want_n) == SD_E_CRYPTO);
      /* wrong hash algorithm for the digest length */
      SD_CHECK(sd_rsa_pkcs1_verify(k, h == SD_HASH_SHA1 ? SD_HASH_SHA256 : SD_HASH_SHA1, dg_p, dg_n, want_p,
                                   want_n) == SD_E_INVALID_PARAM);
      free(sig);
      free(dg_p);
      free(want_p);
      sigs++;
    }
  }
  sd_rsa_free(k); sd_rsa_free(kswap); sd_rsa_free(knocrt);
  refkey_free(&rk);
  tu_lines_close(&l);
  printf("    %d keys, %d signatures\n", keys, sigs);
  SD_CHECK(keys >= 6 && sigs >= 24);
}

SD_TEST(rsa_public_key_rules)
{
  sd_rsa_import_params ip;
  sd_rsa_key *k = NULL;
  uint8_t n[256], e[9], ob[256], oe[8];
  size_t onl = sizeof(ob), oel = sizeof(oe);
  memset(n, 0xc5, sizeof(n));
  n[255] |= 1;
  memset(&ip, 0, sizeof(ip));
  e[0] = 0x01; e[1] = 0x00; e[2] = 0x01;
  ip.n = n; ip.n_len = 256; ip.e = e; ip.e_len = 3;
  SD_REQUIRE(sd_rsa_import(&ip, &k) == SD_OK);
  SD_CHECK(!sd_rsa_has_private(k));
  SD_CHECK(sd_rsa_export_pub(k, ob, &onl, oe, &oel) == SD_OK && onl == 256 && oel == 3);
  SD_CHECK(memcmp(ob, n, 256) == 0 && memcmp(oe, e, 3) == 0);
  {
    uint8_t dg[32] = { 0 }, sig[256];
    size_t sl = sizeof(sig);
    SD_CHECK(sd_rsa_pkcs1_sign(k, SD_HASH_SHA256, dg, 32, sig, &sl) == SD_E_INVALID_PARAM);
    memset(sig, 0xff, sizeof(sig));                                        /* s >= n */
    SD_CHECK(sd_rsa_pkcs1_verify(k, SD_HASH_SHA256, dg, 32, sig, 256) == SD_E_CRYPTO);
    SD_CHECK(sd_rsa_pkcs1_verify(k, SD_HASH_SHA256, dg, 32, n, 256) == SD_E_CRYPTO);   /* s == n */
  }
  sd_rsa_free(k);
  k = NULL;
  e[2] = 0x02;                                                             /* even e */
  SD_CHECK(sd_rsa_import(&ip, &k) == SD_E_KEY_FORMAT);
  e[0] = 1; ip.e_len = 1;                                                  /* e = 1 */
  SD_CHECK(sd_rsa_import(&ip, &k) == SD_E_KEY_FORMAT);
  memset(e, 0x01, 9); ip.e_len = 9;                                        /* e >= 2^64 */
  SD_CHECK(sd_rsa_import(&ip, &k) == SD_E_KEY_UNSUPPORTED);
  e[0] = 3; ip.e_len = 1;
  ip.n_len = 127;                                                          /* 1016 bits */
  SD_CHECK(sd_rsa_import(&ip, &k) == SD_E_KEY_UNSUPPORTED);
  ip.n_len = 256;
  n[255] &= 0xfe;                                                          /* even n */
  SD_CHECK(sd_rsa_import(&ip, &k) == SD_E_KEY_FORMAT);
  SD_CHECK(k == NULL);
  sd_rsa_free(NULL);
}
