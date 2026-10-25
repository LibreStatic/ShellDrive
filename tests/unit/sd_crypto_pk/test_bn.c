/* sd_bn against the independent Python reference (tests/vectors/refimpl/pk_ref.py -> bn_random.txt) and
 * the API edge cases (01 Â§2.7.4). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pk_internal.h"
#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

static sd_bn *bn_new(void)
{
  return (sd_bn *)tu_alloc(sizeof(sd_bn));
}

static void bn_hex(sd_bn *r, const char *hex)
{
  uint8_t *b;
  size_t n = tu_hex(hex, &b);
  if (sd_bn_from_bytes(r, b, n) != SD_OK)
    abort();
  free(b);
}

/* Compares r (written at the expected width) with hex. */
static int bn_eq_hex(const sd_bn *r, const char *hex)
{
  uint8_t *want, *got;
  size_t n = tu_hex(hex, &want);
  int ok;
  got = (uint8_t *)tu_alloc(n + 1);
  ok = sd_bn_to_bytes(r, got, n) == SD_OK && memcmp(got, want, n) == 0;
  free(want);
  free(got);
  return ok;
}

SD_TEST(bn_independent_reference)
{
  tu_lines l;
  char *f[6];
  int n, cnt[4] = { 0, 0, 0, 0 };
  sd_bn *a = bn_new(), *b = bn_new(), *m = bn_new(), *r = bn_new();
  SD_REQUIRE(tu_lines_open(&l, "refimpl/bn_random.txt") == 0);
  while ((n = tu_lines_next(&l, f, 6)) > 0) {
    switch (f[0][0]) {
    case 'x':
      SD_REQUIRE(n == 5);
      bn_hex(m, f[1]);
      bn_hex(a, f[2]);
      bn_hex(b, f[3]);
      SD_REQUIRE(sd_bn_ct_modexp(r, a, b, 0, m) == SD_OK);
      if (!bn_eq_hex(r, f[4]))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "ct_modexp mismatch, mod %.40s", f[1]);
      SD_REQUIRE(sd_bn_vt_modexp(r, a, b, m) == SD_OK);
      if (!bn_eq_hex(r, f[4]))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "vt_modexp mismatch, mod %.40s", f[1]);
      cnt[0]++;
      break;
    case 'i': {
      sd_err e;
      SD_REQUIRE(n == 4);
      bn_hex(m, f[1]);
      bn_hex(a, f[2]);
      e = sd_bn_ct_modinv(r, a, m);
      if (strcmp(f[3], "-") == 0) {
        if (e != SD_E_CRYPTO)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "modinv of a non-invertible value succeeded");
      } else if (e != SD_OK || !bn_eq_hex(r, f[3])) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "modinv mismatch, mod %.40s", f[1]);
      }
      cnt[1]++;
      break;
    }
    case 'r':
      SD_REQUIRE(n == 4);
      bn_hex(m, f[1]);
      bn_hex(a, f[2]);
      SD_REQUIRE(sd_bn_ct_mod(r, a, m) == SD_OK);
      if (!bn_eq_hex(r, f[3]))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "ct_mod mismatch, mod %.40s", f[1]);
      cnt[2]++;
      break;
    case 'm':
      SD_REQUIRE(n == 4);
      bn_hex(a, f[1]);
      bn_hex(b, f[2]);
      SD_REQUIRE(sd_bn_ct_mul(r, a, b) == SD_OK);
      if (!bn_eq_hex(r, f[3]))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "ct_mul mismatch, a %.40s", f[1]);
      cnt[3]++;
      break;
    default:
      SD_CHECK(0);
    }
  }
  tu_lines_close(&l);
  printf("    %d modexp, %d modinv, %d mod, %d mul cases\n", cnt[0], cnt[1], cnt[2], cnt[3]);
  SD_CHECK(cnt[0] > 50 && cnt[1] > 50 && cnt[2] > 50 && cnt[3] > 50);
  free(a);
  free(b);
  free(m);
  free(r);
}

SD_TEST(bn_api_edges)
{
  sd_bn *a = bn_new(), *m = bn_new(), *r = bn_new();
  uint8_t out[8];
  static const uint8_t v[3] = { 0x01, 0x02, 0x03 };
  SD_CHECK(sd_bn_from_bytes(a, v, 3) == SD_OK);
  SD_CHECK_EQ_U64(sd_bn_vt_bits(a), 17);
  SD_CHECK(sd_bn_to_bytes(a, out, 2) == SD_E_INVALID_PARAM);    /* does not fit */
  SD_CHECK(sd_bn_to_bytes(a, out, 4) == SD_OK && out[0] == 0 && out[3] == 3);
  sd_bn_from_u32(m, 10);                                          /* even modulus */
  SD_CHECK(sd_bn_ct_modexp(r, a, a, 0, m) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_bn_ct_modinv(r, a, m) == SD_E_INVALID_PARAM);
  sd_bn_from_u32(m, 1);
  SD_CHECK(sd_bn_vt_modexp(r, a, a, m) == SD_E_INVALID_PARAM);
  sd_bn_from_u32(m, 0);
  SD_CHECK(sd_bn_ct_mod(r, a, m) == SD_E_INVALID_PARAM);
  /* 0x010203^5 mod 1000003 = 66301 (computed by hand with Python) */
  sd_bn_from_u32(m, 1000003);
  sd_bn_from_u32(r, 5);
  SD_CHECK(sd_bn_ct_modexp(r, a, r, 3, m) == SD_OK);
  SD_CHECK(sd_bn_to_bytes(r, out, 4) == SD_OK);
  {
    uint64_t want = 1;
    int i;
    for (i = 0; i < 5; i++)
      want = want * 0x010203u % 1000003u;
    SD_CHECK_EQ_U64(((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) | ((uint32_t)out[2] << 8) | out[3], want);
  }
  SD_CHECK(sd_bn_vt_is_zero(m) == 0);
  sd_bn_wipe(a);
  SD_CHECK(a->n == 0);
  free(a);
  free(m);
  free(r);
}

/* Montgomery engine directly: montmul(a, b) * R == a * b mod m for random operands, every limb count. */
SD_TEST(bn_montmul_matches_mul_mod)
{
  uint64_t seed = 0x5eed1234u;
  sd_limb m[40], a[40], b[40], r2[40], t[40], prod[80], want[40], one[40];
  size_t n, it;
  for (n = 1; n <= 40; n++) {
    for (it = 0; it < 6; it++) {
      sd_limb m0i;
      tu_rand_fill(&seed, (uint8_t *)m, n * sizeof(sd_limb));
      m[0] |= 1;
      if (it == 1) memset(m, 0xff, n * sizeof(sd_limb));
      if (m[n - 1] == 0) m[n - 1] = 1;
      tu_rand_fill(&seed, (uint8_t *)prod, 2 * n * sizeof(sd_limb));
      sd_mp_mod(a, prod, n, m, n);
      sd_mp_mod(b, prod + n, n, m, n);
      if (it == 2) { memcpy(a, m, n * sizeof(sd_limb)); a[0] -= 1; memcpy(b, a, n * sizeof(sd_limb)); }
      m0i = sd_mp_m0inv(m[0]);
      SD_CHECK((sd_limb)(m[0] * (sd_limb)(0 - m0i)) == 1);
      sd_mp_mont_r2(r2, m, n);
      memset(one, 0, sizeof(one));
      one[0] = 1;
      /* montmul(montmul(a, b), R^2) = a*b*R^-1*R^2*R^-1 = a*b */
      sd_mp_montmul(t, a, b, m, m0i, n);
      sd_mp_montmul(t, t, r2, m, m0i, n);
      sd_mp_mul(prod, a, n, b, n);
      sd_mp_mod(want, prod, 2 * n, m, n);
      if (!sd_mp_eq(t, want, n))
        sd_test_fail(sd_t_, __FILE__, __LINE__, "montmul mismatch at %u limbs", (unsigned)n);
      /* modinv round trip when invertible */
      {
        sd_limb inv[40], w[5 * 40], chk[40];
        if (sd_mp_modinv_ct(inv, a, m, n, w)) {
          sd_mp_mul(prod, a, n, inv, n);
          sd_mp_mod(chk, prod, 2 * n, m, n);
          if (!(sd_mp_eq(chk, one, n) || (n == 1 && m[0] == 1)))
            sd_test_fail(sd_t_, __FILE__, __LINE__, "modinv round trip failed at %u limbs", (unsigned)n);
        }
      }
    }
  }
}
