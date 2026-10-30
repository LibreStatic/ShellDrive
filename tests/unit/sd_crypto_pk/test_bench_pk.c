/* Throughput of the public-key operations (printed, not asserted): RSA-3072 sign/verify, P-256/384/521
 * ECDSA sign/verify and ECDH, DH group14/16 (public value + shared secret). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

static sd_rsa_key *load_ref_key(unsigned want_bits)
{
  tu_lines l;
  char *f[9];
  int n;
  sd_rsa_key *k = NULL;
  if (tu_lines_open(&l, "refimpl/rsa_keys.txt") != 0)
    return NULL;
  while (k == NULL && (n = tu_lines_next(&l, f, 9)) > 0) {
    if (f[0][0] == 'K' && (unsigned)atoi(f[1]) == want_bits) {
      uint8_t *b[6];
      size_t len[6];
      int i;
      sd_rsa_import_params ip;
      for (i = 0; i < 6; i++)
        len[i] = tu_hex(f[2 + i], &b[i]);
      memset(&ip, 0, sizeof(ip));
      ip.n = b[0]; ip.n_len = len[0]; ip.e = b[1]; ip.e_len = len[1]; ip.d = b[2]; ip.d_len = len[2];
      ip.p = b[3]; ip.p_len = len[3]; ip.q = b[4]; ip.q_len = len[4]; ip.iqmp = b[5]; ip.iqmp_len = len[5];
      if (sd_rsa_import(&ip, &k) != SD_OK)
        k = NULL;
      for (i = 0; i < 6; i++)
        free(b[i]);
    }
  }
  tu_lines_close(&l);
  return k;
}

SD_TEST(bench_pk_throughput)
{
  double t0, t1;
  int i, n;
  uint8_t dg[64], sig[1024], r[66], s[66];
  memset(dg, 0x5a, sizeof(dg));
  {
    sd_rsa_key *k = load_ref_key(3072);
    size_t sl = sizeof(sig);
    SD_REQUIRE(k != NULL);
    n = 20;
    t0 = tu_seconds();
    for (i = 0; i < n; i++) {
      sl = sizeof(sig);
      SD_CHECK(sd_rsa_pkcs1_sign(k, SD_HASH_SHA256, dg, 32, sig, &sl) == SD_OK);
    }
    t1 = tu_seconds();
    printf("    rsa-3072 sign (CRT, blinded) %8.1f ops/s\n", n / (t1 - t0));
    n = 200;
    t0 = tu_seconds();
    for (i = 0; i < n; i++)
      SD_CHECK(sd_rsa_pkcs1_verify(k, SD_HASH_SHA256, dg, 32, sig, sl) == SD_OK);
    t1 = tu_seconds();
    printf("    rsa-3072 verify (e=65537)    %8.1f ops/s\n", n / (t1 - t0));
    sd_rsa_free(k);
  }
  {
    static const sd_curve cs[] = { SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521 };
    static const char *names[] = { "p-256", "p-384", "p-521" };
    size_t ci;
    for (ci = 0; ci < 3; ci++) {
      sd_ec_key *k = NULL, *o = NULL;
      sd_hash_alg h = sd_ec_hash(cs[ci]);
      size_t fl = sd_ec_field_len(cs[ci]), pl = sd_ec_point_len(cs[ci]), l;
      uint8_t pub[133], sec[66];
      SD_REQUIRE(sd_ec_generate(cs[ci], &k) == SD_OK && sd_ec_generate(cs[ci], &o) == SD_OK);
      n = ci == 0 ? 200 : 50;
      t0 = tu_seconds();
      for (i = 0; i < n; i++)
        SD_CHECK(sd_ecdsa_sign(k, h, dg, sd_hash_len(h), r, s) == SD_OK);
      t1 = tu_seconds();
      printf("    %s ecdsa sign             %8.1f ops/s\n", names[ci], n / (t1 - t0));
      t0 = tu_seconds();
      for (i = 0; i < n; i++)
        SD_CHECK(sd_ecdsa_verify(k, dg, sd_hash_len(h), r, fl, s, fl) == SD_OK);
      t1 = tu_seconds();
      printf("    %s ecdsa verify           %8.1f ops/s\n", names[ci], n / (t1 - t0));
      l = sizeof(pub);
      SD_REQUIRE(sd_ec_export_pub(o, pub, &l) == SD_OK);
      t0 = tu_seconds();
      for (i = 0; i < n; i++) {
        l = sizeof(sec);
        SD_CHECK(sd_ecdh(k, pub, pl, sec, &l) == SD_OK);
      }
      t1 = tu_seconds();
      printf("    %s ecdh (shared secret)   %8.1f ops/s\n", names[ci], n / (t1 - t0));
      sd_ec_free(k);
      sd_ec_free(o);
    }
  }
  {
    static const int ids[] = { 14, 16 };
    size_t gi;
    for (gi = 0; gi < 2; gi++) {
      sd_dh *a = NULL, *b = NULL;
      uint8_t *ea = (uint8_t *)tu_alloc(512), *eb = (uint8_t *)tu_alloc(512), *kk = (uint8_t *)tu_alloc(512);
      size_t l;
      SD_REQUIRE(sd_dh_new_group(ids[gi], 0, &a) == SD_OK && sd_dh_new_group(ids[gi], 0, &b) == SD_OK);
      l = sd_dh_len(a);
      SD_REQUIRE(sd_dh_public(b, eb, l) == SD_OK);
      n = gi == 0 ? 20 : 5;
      t0 = tu_seconds();
      for (i = 0; i < n; i++) {
        SD_CHECK(sd_dh_public(a, ea, l) == SD_OK);
        SD_CHECK(sd_dh_compute(a, eb, l, kk, l) == SD_OK);
      }
      t1 = tu_seconds();
      printf("    dh group%d (public + secret) %7.1f ops/s\n", ids[gi], n / (t1 - t0));
      sd_dh_free(a);
      sd_dh_free(b);
      free(ea); free(eb); free(kk);
    }
  }
}
