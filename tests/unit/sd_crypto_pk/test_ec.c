/* P-256/384/521: RFC 5903 Â§8 ECDH, RFC 6979 A.2.5-A.2.7 ECDSA, Wycheproof ECDSA (P1363) and ECDH (ecpoint),
 * the independent Python reference (scalar multiplication, complete addition, doubling, RFC 6979 signatures)
 * and import / encoding rules. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pk_internal.h"
#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

static size_t hx(const char *hex, uint8_t *out, size_t cap)
{
  size_t n = tu_hexbuf(hex, out, cap);
  if (n == SIZE_MAX)
    abort();
  return n;
}

SD_TEST(ec_rfc5903_ecdh)
{
  tu_lines l;
  char *f[10];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "rfc/rfc5903_ecdh.txt") == 0);
  while ((n = tu_lines_next(&l, f, 10)) == 9) {
    sd_curve c = pkt_curve(f[0]);
    size_t fl = sd_ec_field_len(c), il, rl, pl;
    uint8_t i[66], r[66], gi[133], gr[133], pub[133], sec[66], want[66];
    sd_ec_key *ki = NULL, *kr = NULL;
    il = hx(f[1], i, sizeof(i));
    gi[0] = gr[0] = 0x04;
    hx(f[2], gi + 1, fl); hx(f[3], gi + 1 + fl, fl);
    rl = hx(f[4], r, sizeof(r));
    hx(f[5], gr + 1, fl); hx(f[6], gr + 1 + fl, fl);
    hx(f[7], want, sizeof(want));
    SD_REQUIRE(sd_ec_import(c, NULL, 0, i, il, &ki) == SD_OK);
    SD_REQUIRE(sd_ec_import(c, gr, 1 + 2 * fl, r, rl, &kr) == SD_OK);
    pl = sizeof(pub);
    SD_CHECK(sd_ec_export_pub(ki, pub, &pl) == SD_OK && pl == 1 + 2 * fl && memcmp(pub, gi, pl) == 0);
    pl = sizeof(sec);
    SD_CHECK(sd_ecdh(ki, gr, 1 + 2 * fl, sec, &pl) == SD_OK && pl == fl && memcmp(sec, want, fl) == 0);
    pl = sizeof(sec);
    SD_CHECK(sd_ecdh(kr, gi, 1 + 2 * fl, sec, &pl) == SD_OK && memcmp(sec, want, fl) == 0);
    sd_ec_free(ki);
    sd_ec_free(kr);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK_EQ_INT(count, 3);
}

SD_TEST(ec_rfc6979_ecdsa)
{
  tu_lines l;
  char *f[10];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "rfc/rfc6979_ecdsa.txt") == 0);
  while ((n = tu_lines_next(&l, f, 10)) == 9) {
    sd_curve c = pkt_curve(f[0]);
    size_t fl = sd_ec_field_len(c), xl, ml;
    uint8_t x[66], pub[133], msg[16], dg[64], r[66], s[66], wr[66], ws[66];
    sd_hash_alg h;
    sd_ec_key *k = NULL;
    xl = hx(f[1], x, sizeof(x));
    pub[0] = 0x04;
    hx(f[2], pub + 1, fl); hx(f[3], pub + 1 + fl, fl);
    SD_REQUIRE(pkt_hash(f[4], &h));
    ml = hx(f[5], msg, sizeof(msg));
    hx(f[7], wr, sizeof(wr)); hx(f[8], ws, sizeof(ws));
    SD_REQUIRE(sd_ec_import(c, pub, 1 + 2 * fl, x, xl, &k) == SD_OK);   /* checks pub == x*G */
    sd_hash(h, msg, ml, dg);
    SD_CHECK(sd_ecdsa_sign_ex(k, h, dg, sd_hash_len(h), NULL, 0, r, s) == SD_OK);
    if (memcmp(r, wr, fl) != 0 || memcmp(s, ws, fl) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "RFC 6979 P-%s %s \"%s\": signature differs", f[0], f[4], f[5]);
    SD_CHECK(sd_ecdsa_verify(k, dg, sd_hash_len(h), r, fl, s, fl) == SD_OK);
    /* hedged signatures differ but verify */
    SD_CHECK(sd_ecdsa_sign(k, h, dg, sd_hash_len(h), r, s) == SD_OK);
    SD_CHECK(memcmp(r, wr, fl) != 0);
    SD_CHECK(sd_ecdsa_verify(k, dg, sd_hash_len(h), r, fl, s, fl) == SD_OK);
    sd_ec_free(k);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK_EQ_INT(count, 24);    /* 3 curves x 4 hashes x 2 messages */
}

SD_TEST(ec_independent_reference)
{
  tu_lines l;
  char *f[8];
  int n, cnt[4] = { 0, 0, 0, 0 };
  SD_REQUIRE(tu_lines_open(&l, "refimpl/ec_random.txt") == 0);
  while ((n = tu_lines_next(&l, f, 8)) > 0) {
    sd_curve c = pkt_curve(f[1]);
    size_t fl = sd_ec_field_len(c), pl = 1 + 2 * fl;
    uint8_t a[133], b[133], want[133], out[133];
    switch (f[0][0]) {
    case 'M': {
      size_t kl = hx(f[2], a, sizeof(a));
      sd_err e;
      hx(f[3], b, sizeof(b));
      e = sd_ec_test_mul(c, a, kl, b, out);
      if (strcmp(f[4], "-") == 0) {
        SD_CHECK(e == SD_E_CRYPTO);
      } else {
        hx(f[4], want, sizeof(want));
        if (e != SD_OK || memcmp(out, want, pl) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "P-%s scalar mult mismatch (k %.24s...)", f[1], f[2]);
      }
      cnt[0]++;
      break;
    }
    case 'A': {
      sd_err e;
      hx(f[2], a, sizeof(a));
      hx(f[3], b, sizeof(b));
      e = sd_ec_test_add(c, a, b, out);
      if (strcmp(f[4], "-") == 0) {
        SD_CHECK(e == SD_E_CRYPTO);
      } else {
        hx(f[4], want, sizeof(want));
        SD_CHECK(e == SD_OK && memcmp(out, want, pl) == 0);
      }
      cnt[1]++;
      break;
    }
    case 'D':
      hx(f[2], a, sizeof(a));
      hx(f[3], want, sizeof(want));
      SD_CHECK(sd_ec_test_dbl(c, a, out) == SD_OK && memcmp(out, want, pl) == 0);
      cnt[2]++;
      break;
    case 'S': {
      sd_hash_alg h;
      sd_ec_key *k = NULL;
      size_t dl, gl;
      uint8_t d[66], dg[64], r[66], s[66];
      SD_REQUIRE(n == 7 && pkt_hash(f[2], &h));
      dl = hx(f[3], d, sizeof(d));
      gl = hx(f[4], dg, sizeof(dg));
      hx(f[5], a, sizeof(a));
      hx(f[6], b, sizeof(b));
      SD_REQUIRE(sd_ec_import(c, NULL, 0, d, dl, &k) == SD_OK);
      SD_CHECK(sd_ecdsa_sign_ex(k, h, dg, gl, NULL, 0, r, s) == SD_OK);
      SD_CHECK(memcmp(r, a, fl) == 0 && memcmp(s, b, fl) == 0);
      SD_CHECK(sd_ecdsa_verify(k, dg, gl, a, fl, b, fl) == SD_OK);
      sd_ec_free(k);
      cnt[3]++;
      break;
    }
    default:
      SD_CHECK(0);
    }
  }
  tu_lines_close(&l);
  printf("    %d scalar mults, %d additions, %d doublings, %d signatures\n", cnt[0], cnt[1], cnt[2], cnt[3]);
  SD_CHECK(cnt[0] > 200 && cnt[1] >= 72 && cnt[2] >= 24 && cnt[3] >= 60);
}

static void ecdsa_suite(sd_test_ctx *sd_t_, const char *file, int *total)
{
  tu_lines l;
  char *f[6];
  int n;
  sd_ec_key *k = NULL;
  sd_hash_alg h = SD_HASH_SHA256;
  size_t fl = 0;
  if (tu_lines_open(&l, file) != 0) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "missing %s", file);
    return;
  }
  while ((n = tu_lines_next(&l, f, 6)) > 0) {
    if (f[0][0] == 'K') {
      uint8_t pub[133];
      size_t pl = hx(f[3], pub, sizeof(pub));
      sd_curve c = pkt_curve(f[1]);
      sd_ec_free(k);
      k = NULL;
      SD_REQUIRE(pkt_hash(f[2], &h));
      fl = sd_ec_field_len(c);
      SD_REQUIRE(sd_ec_import(c, pub, pl, NULL, 0, &k) == SD_OK);
    } else {
      uint8_t *msg, *sig, dg[64];
      size_t ml = tu_hex(f[3], &msg), sl = tu_hex(f[4], &sig);
      sd_err e = SD_E_CRYPTO;
      sd_hash(h, msg, ml, dg);
      /* SSH carries r and s as separate mpints; a P1363 blob of the wrong size never decodes to them */
      if (sl == 2 * fl)
        e = sd_ecdsa_verify(k, dg, sd_hash_len(h), sig, fl, sig + fl, fl);
      if (f[2][0] == 'v' && e != SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: valid signature rejected", file, f[1]);
      if (f[2][0] == 'i' && e == SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: invalid signature accepted", file, f[1]);
      free(msg);
      free(sig);
      (*total)++;
    }
  }
  sd_ec_free(k);
  tu_lines_close(&l);
}

SD_TEST(wycheproof_ecdsa)
{
  static const char *files[] = {
    "wycheproof/ecdsa_secp256r1_sha256_p1363_test.txt", "wycheproof/ecdsa_secp256r1_sha512_p1363_test.txt",
    "wycheproof/ecdsa_secp384r1_sha384_p1363_test.txt", "wycheproof/ecdsa_secp384r1_sha512_p1363_test.txt",
    "wycheproof/ecdsa_secp521r1_sha512_p1363_test.txt",
  };
  size_t i;
  int total = 0;
  for (i = 0; i < SD_COUNTOF(files); i++)
    ecdsa_suite(sd_t_, files[i], &total);
  printf("    %d verifications\n", total);
  SD_CHECK(total > 1000);
}

SD_TEST(wycheproof_ecdh)
{
  static const char *files[] = { "wycheproof/ecdh_secp256r1_ecpoint_test.txt",
                                 "wycheproof/ecdh_secp384r1_ecpoint_test.txt",
                                 "wycheproof/ecdh_secp521r1_ecpoint_test.txt" };
  static const sd_curve curves[] = { SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521 };
  size_t i;
  int total = 0, compressed = 0;
  for (i = 0; i < SD_COUNTOF(files); i++) {
    tu_lines l;
    char *f[8];
    int n;
    SD_REQUIRE(tu_lines_open(&l, files[i]) == 0);
    while ((n = tu_lines_next(&l, f, 8)) == 7) {
      uint8_t *pub, *priv, *shared, sec[66];
      size_t pl = tu_hex(f[3], &pub), dl = tu_hex(f[4], &priv), shl = tu_hex(f[5], &shared), sl = sizeof(sec);
      sd_ec_key *k = NULL;
      sd_err e = sd_ec_import(curves[i], NULL, 0, priv, dl, &k);
      int ok;
      SD_REQUIRE(e == SD_OK);
      e = sd_ecdh(k, pub, pl, sec, &sl);
      ok = e == SD_OK && sl == shl && memcmp(sec, shared, shl) == 0;
      if (strstr(f[6], "CompressedPoint")) {
        /* compressed points are not supported (SSH uses uncompressed only): must be rejected */
        SD_CHECK(e == SD_E_CRYPTO);
        compressed++;
      } else if (f[2][0] == 'v' && !ok) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: valid case failed (%d)", files[i], f[1], (int)e);
      } else if (f[2][0] == 'i' && e == SD_OK) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s tcId %s: invalid public key accepted", files[i], f[1]);
      }
      sd_ec_free(k);
      free(pub);
      free(priv);
      free(shared);
      total++;
    }
    tu_lines_close(&l);
  }
  printf("    %d cases (%d with compressed points, rejected by design)\n", total, compressed);
  SD_CHECK(total > 1000);
}

SD_TEST(ec_sign_verify_and_rules)
{
  static const sd_curve curves[] = { SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521 };
  size_t ci;
  for (ci = 0; ci < SD_COUNTOF(curves); ci++) {
    sd_curve c = curves[ci];
    size_t fl = sd_ec_field_len(c), pl = sd_ec_point_len(c), l, i;
    sd_hash_alg h = sd_ec_hash(c);
    sd_ec_key *k = NULL, *pubk = NULL, *other = NULL, *bad = NULL;
    uint8_t pub[133], pub2[133], dg[64], r[66], s[66], z[66], sec1[66], sec2[66];
    SD_REQUIRE(sd_ec_generate(c, &k) == SD_OK);
    SD_REQUIRE(sd_ec_generate(c, &other) == SD_OK);
    SD_CHECK(sd_ec_key_curve(k) == c && sd_ec_has_private(k));
    l = sizeof(pub);
    SD_REQUIRE(sd_ec_export_pub(k, pub, &l) == SD_OK && l == pl);
    SD_REQUIRE(sd_ec_import(c, pub, pl, NULL, 0, &pubk) == SD_OK);
    SD_CHECK(!sd_ec_has_private(pubk));
    for (i = 0; i < 8; i++) {
      memset(dg, (int)i * 37, sizeof(dg));
      SD_CHECK(sd_ecdsa_sign(k, h, dg, sd_hash_len(h), r, s) == SD_OK);
      SD_CHECK(sd_ecdsa_verify(pubk, dg, sd_hash_len(h), r, fl, s, fl) == SD_OK);
      SD_CHECK(sd_ecdsa_verify(other, dg, sd_hash_len(h), r, fl, s, fl) == SD_E_CRYPTO);
      dg[3] ^= 1;
      SD_CHECK(sd_ecdsa_verify(pubk, dg, sd_hash_len(h), r, fl, s, fl) == SD_E_CRYPTO);
    }
    /* r, s range: 0 and n are rejected; leading zeros are accepted */
    memset(z, 0, sizeof(z));
    SD_CHECK(sd_ecdsa_verify(pubk, dg, sd_hash_len(h), z, fl, s, fl) == SD_E_CRYPTO);
    SD_CHECK(sd_ecdsa_verify(pubk, dg, sd_hash_len(h), r, fl, z, 0) == SD_E_CRYPTO);
    dg[3] ^= 1;
    {
      uint8_t r2[67];
      r2[0] = 0;
      memcpy(r2 + 1, r, fl);
      SD_CHECK(sd_ecdsa_verify(pubk, dg, sd_hash_len(h), r2, fl + 1, s, fl) == SD_OK);
    }
    /* ECDH both ways */
    l = sizeof(pub2);
    SD_REQUIRE(sd_ec_export_pub(other, pub2, &l) == SD_OK);
    l = sizeof(sec1);
    SD_CHECK(sd_ecdh(k, pub2, pl, sec1, &l) == SD_OK && l == fl);
    l = sizeof(sec2);
    SD_CHECK(sd_ecdh(other, pub, pl, sec2, &l) == SD_OK && memcmp(sec1, sec2, fl) == 0);
    l = sizeof(sec2);
    SD_CHECK(sd_ecdh(pubk, pub2, pl, sec2, &l) == SD_E_INVALID_PARAM);     /* no private key */
    /* point encoding rules */
    pub2[pl - 1] ^= 1;                                                     /* off the curve */
    l = sizeof(sec2);
    SD_CHECK(sd_ecdh(k, pub2, pl, sec2, &l) == SD_E_CRYPTO);
    SD_CHECK(sd_ec_import(c, pub2, pl, NULL, 0, &bad) == SD_E_CRYPTO && bad == NULL);
    pub2[pl - 1] ^= 1;
    pub2[0] = 0x02;                                                        /* compressed tag */
    SD_CHECK(sd_ec_import(c, pub2, 1 + fl, NULL, 0, &bad) == SD_E_CRYPTO);
    SD_CHECK(sd_ec_import(c, pub2, pl, NULL, 0, &bad) == SD_E_CRYPTO);
    z[0] = 0;
    SD_CHECK(sd_ec_import(c, z, 1, NULL, 0, &bad) == SD_E_CRYPTO);         /* infinity */
    memset(pub2 + 1, 0xff, fl);                                            /* x >= p */
    pub2[0] = 0x04;
    SD_CHECK(sd_ec_import(c, pub2, pl, NULL, 0, &bad) == SD_E_CRYPTO);
    /* private scalar rules */
    memset(z, 0, sizeof(z));
    SD_CHECK(sd_ec_import(c, NULL, 0, z, fl, &bad) == SD_E_KEY_FORMAT);    /* 0 */
    memset(z, 0xff, sizeof(z));
    SD_CHECK(sd_ec_import(c, NULL, 0, z, fl, &bad) == SD_E_KEY_FORMAT);    /* >= n */
    z[0] = 1;
    memset(z + 1, 0, fl);
    z[fl] = 1;
    SD_CHECK(sd_ec_import(c, NULL, 0, z, fl + 1, &bad) == SD_E_KEY_FORMAT);  /* too long */
    z[0] = 0;
    SD_CHECK(sd_ec_import(c, NULL, 0, z, fl + 1, &bad) == SD_OK);         /* 1 with a leading zero byte */
    sd_ec_free(bad);
    bad = NULL;
    SD_CHECK(sd_ec_import(c, pub, pl, z, fl + 1, &bad) == SD_E_KEY_FORMAT);  /* pub != 1*G */
    sd_ec_free(k);
    sd_ec_free(pubk);
    sd_ec_free(other);
  }
  SD_CHECK(sd_ec_field_len((sd_curve)9) == 0);
  sd_ec_free(NULL);
}

/* ---- NIST field reductions (ec_p.c fe_mul: FIPS 186-4 D.2 for P-256/P-384, Mersenne-type for P-521) ----
 * Each product is checked against the bit-serial reference (sd_mp_mod of the schoolbook product) on edge
 * operands (0, 1, 2, p-1, p, p+1, all ones, one all-ones word, boundary words 0 / 1 / 2^31 / 2^32-2 / 2^32-1,
 * random words), and against the previous Montgomery path where both operands are below p. P-521 operands
 * stay below 2^521, the bound its fold is written for; P-256 and P-384 operands range over the whole field
 * length, including values above p. */
static void fe_words_to_be(uint8_t *out, size_t fl, const uint32_t *w)
{
  size_t i;
  for (i = 0; i < fl; i++)
    out[fl - 1 - i] = (uint8_t)(w[i / 4] >> (8 * (i % 4)));
}

/* kind: 0 zero, 1 all ones, 2 one all-ones word, 3 boundary words, 4 random words; masked to `bits` bits. */
static void fe_operand(uint8_t *out, size_t fl, unsigned bits, uint64_t *seed, int kind)
{
  static const uint32_t special[6] = {0, 1, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu};
  uint32_t w[17];
  uint8_t rb[4];
  unsigned b, i;
  memset(w, 0, sizeof(w));
  if (kind == 1)
    memset(w, 0xff, sizeof(w));
  if (kind == 2) {
    tu_rand_fill(seed, rb, sizeof(rb));
    w[rb[0] % 17] = 0xffffffffu;
  }
  if (kind == 3 || kind == 4) {
    for (i = 0; i < 17; i++) {
      tu_rand_fill(seed, rb, sizeof(rb));
      if (kind == 3 && (rb[1] & 1))
        w[i] = special[rb[0] % 6];
      else
        w[i] = ((uint32_t)rb[0] << 24) | ((uint32_t)rb[1] << 16) | ((uint32_t)rb[2] << 8) | rb[3];
    }
  }
  for (b = bits; b < 17 * 32; b++)
    w[b / 32] &= ~(1u << (b % 32));
  fe_words_to_be(out, fl, w);
}

/* out = in + d for d = +1 or -1 (big-endian, len bytes; the caller keeps the result in range). */
static void fe_add_small(uint8_t *out, const uint8_t *in, size_t len, int d)
{
  int carry = d;
  size_t i;
  for (i = len; i-- > 0;) {
    int v = in[i] + carry;
    out[i] = (uint8_t)(v & 0xff);
    carry = (v < 0) ? -1 : (v > 255);
  }
}

SD_TEST(ec_field_reduction_differential)
{
  static const sd_curve curves[3] = {SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521};
  static const unsigned bits[3] = {256, 384, 521};
  static const char *p_hex[2] = {
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
  };
  static const int kinds[5] = {0, 1, 2, 3, 4};
  static const int counts[5] = {1, 1, 8, 16, 16};
  uint64_t seed = 0x6a09e667f3bcc908ull;
  uint8_t ops[64][66], pb[66], ref[66], got[66], mont[66];
  uint8_t pfull[66], pm1[66], pp1[66];
  size_t ci, i, j, n, fl, total = 0;
  int k, q;
  for (ci = 0; ci < 3; ci++) {
    sd_curve c = curves[ci];
    unsigned nb = bits[ci];
    fl = sd_ec_field_len(c);
    SD_REQUIRE(fl != 0);
    memset(pfull, 0, sizeof(pfull));
    if (ci < 2) {
      SD_REQUIRE(hx(p_hex[ci], pfull + (66 - fl), fl) == fl);
    } else {
      memset(pfull + 1, 0xff, 65);
      pfull[0] = 0x01;                 /* 2^521 - 1 in 66 bytes */
    }
    memcpy(pb, pfull + (66 - fl), fl);
    fe_add_small(pm1, pb, fl, -1);
    fe_add_small(pp1, pb, fl, +1);
    n = 0;
    memset(ops[n], 0, 66);
    n++;                                /* 0 */
    memset(ops[n], 0, 66);
    ops[n][fl - 1] = 1;
    n++;                                /* 1 */
    memset(ops[n], 0, 66);
    ops[n][fl - 1] = 2;
    n++;                                /* 2 */
    memcpy(ops[n++], pm1, fl);          /* p - 1 */
    memcpy(ops[n++], pb, fl);           /* p */
    if (ci < 2)
      memcpy(ops[n++], pp1, fl);        /* p + 1 (below 2^bits only for P-256 and P-384) */
    for (k = 0; k < 5; k++)
      for (q = 0; q < counts[k]; q++)
        fe_operand(ops[n++], fl, nb, &seed, kinds[k]);
    SD_CHECK(n > 40);
    for (i = 0; i < n; i++) {
      for (j = 0; j < n; j++) {
        SD_CHECK(sd_ec_test_fe_ref(c, ops[i], ops[j], ref) == SD_OK);
        SD_CHECK(memcmp(ref, pb, fl) < 0);                       /* the reference is reduced */
        SD_CHECK(sd_ec_test_fe_mul(c, ops[i], ops[j], got) == SD_OK && memcmp(got, ref, fl) == 0);
        if (memcmp(ops[i], pb, fl) < 0 && memcmp(ops[j], pb, fl) < 0) {
          SD_CHECK(sd_ec_test_fe_mont(c, ops[i], ops[j], mont) == SD_OK && memcmp(mont, ref, fl) == 0);
        }
        total++;
      }
    }
  }
  SD_CHECK(total > 6000);
}
