/* Finite-field DH: RFC 2409/3526 group constants, key agreement, invalid peer values (01 Â§2.7.1), group-
 * exchange validation against cases from the Python reference (refimpl/dh_gex.txt) and the size policy. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "sd_test.h"
#include "tutil.h"

SD_TEST(dh_group_constants)
{
  static const int ids[] = { 1, 2, 14, 16, 18 };
  static const size_t lens[] = { 128, 128, 256, 512, 1024 };
  size_t i, j, l;
  for (i = 0; i < SD_COUNTOF(ids); i++) {
    const uint8_t *p = sd_dh_group_modp(ids[i], &l);
    int ones = 1;
    SD_REQUIRE(p != NULL);
    SD_CHECK_EQ_U64(l, lens[i]);
    /* 2^n - 2^(n-64) - 1 + 2^64 * (...): top and bottom 64 bits are all ones; the next ones are pi */
    for (j = 0; j < 8; j++)
      ones &= p[j] == 0xff && p[l - 1 - j] == 0xff;
    SD_CHECK(ones);
    SD_CHECK(p[8] == 0xc9 && p[9] == 0x0f && p[10] == 0xda && p[11] == 0xa2);
    /* recognized by the GEX validation (known-group shortcut) */
    {
      sd_dh_gex_policy pol;
      memset(&pol, 0, sizeof(pol));
      pol.min_bits = 1024;
      SD_CHECK(sd_dh_gex_validate(p, l, (const uint8_t *)"\x02", 1, &pol) == SD_OK);
    }
  }
  SD_CHECK(sd_dh_group_modp(15, &l) == NULL && l == 0);
  {
    sd_dh *d = NULL;
    SD_CHECK(sd_dh_new_group(5, 0, &d) == SD_E_UNSUPPORTED && d == NULL);
  }
}

static void agree(sd_test_ctx *sd_t_, int id, uint32_t priv_bits)
{
  sd_dh *a = NULL, *b = NULL;
  uint8_t *ea, *eb, *ka, *kb;
  size_t l;
  SD_REQUIRE(sd_dh_new_group(id, priv_bits, &a) == SD_OK);
  SD_REQUIRE(sd_dh_new_group(id, priv_bits, &b) == SD_OK);
  l = sd_dh_len(a);
  ea = (uint8_t *)tu_alloc(l); eb = (uint8_t *)tu_alloc(l); ka = (uint8_t *)tu_alloc(l); kb = (uint8_t *)tu_alloc(l);
  SD_CHECK(sd_dh_compute(a, ea, l, ka, l) == SD_E_INVALID_PARAM);       /* no private exponent yet */
  SD_REQUIRE(sd_dh_public(a, ea, l) == SD_OK);
  SD_REQUIRE(sd_dh_public(b, eb, l) == SD_OK);
  SD_CHECK(memcmp(ea, eb, l) != 0);
  SD_REQUIRE(sd_dh_compute(a, eb, l, ka, l) == SD_OK);
  SD_REQUIRE(sd_dh_compute(b, ea, l, kb, l) == SD_OK);
  SD_CHECK(memcmp(ka, kb, l) == 0);
  /* the same secret when the peer value comes without leading zero bytes */
  {
    size_t z = 0;
    while (z < l && eb[z] == 0)
      z++;
    SD_CHECK(sd_dh_compute(a, eb + z, l - z, kb, l) == SD_OK && memcmp(ka, kb, l) == 0);
  }
  /* invalid peer values: 0, 1, p-1, p, p+1, longer than p */
  {
    size_t pl;
    const uint8_t *p = sd_dh_group_modp(id, &pl);
    uint8_t *v = (uint8_t *)tu_alloc(pl + 1);
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_E_CRYPTO);
    v[pl - 1] = 1;
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_E_CRYPTO);
    memcpy(v, p, pl);
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_E_CRYPTO);              /* p */
    v[pl - 1] -= 1;
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_E_CRYPTO);              /* p - 1 */
    v[pl - 1] -= 1;
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_OK);                    /* p - 2 is fine */
    memset(v, 0xff, pl);                                                  /* 2^(8*pl) - 1 > p */
    SD_CHECK(sd_dh_compute(a, v, pl, ka, l) == SD_E_CRYPTO);
    memset(v, 0, pl + 1);
    v[0] = 1;
    SD_CHECK(sd_dh_compute(a, v, pl + 1, ka, l) == SD_E_CRYPTO);          /* 2^(8*pl) */
    SD_CHECK(sd_dh_compute(a, v, 0, ka, l) == SD_E_CRYPTO);               /* empty = 0 */
    SD_CHECK(sd_dh_compute(a, eb, l, ka, l - 1) == SD_E_INVALID_PARAM);
    free(v);
  }
  free(ea); free(eb); free(ka); free(kb);
  sd_dh_free(a);
  sd_dh_free(b);
}

SD_TEST(dh_key_agreement)
{
  agree(sd_t_, 1, 0);
  agree(sd_t_, 14, 0);
  agree(sd_t_, 14, 2047);
  agree(sd_t_, 16, 0);
  agree(sd_t_, 18, 0);
}

SD_TEST(dh_new_rules)
{
  sd_dh *d = NULL;
  size_t pl;
  const uint8_t *p = sd_dh_group_modp(14, &pl);
  uint8_t *v = (uint8_t *)tu_alloc(pl);
  static const uint8_t one = 1, two = 2;
  SD_CHECK(sd_dh_bits(NULL) == 0 && sd_dh_len(NULL) == 0);
  SD_CHECK(sd_dh_new(p, pl, &one, 1, 0, &d) == SD_E_CRYPTO);              /* g = 1 */
  memcpy(v, p, pl);
  v[pl - 1] -= 1;
  SD_CHECK(sd_dh_new(p, pl, v, pl, 0, &d) == SD_E_CRYPTO);                /* g = p - 1 */
  SD_CHECK(sd_dh_new(v, pl, &two, 1, 0, &d) == SD_E_CRYPTO);              /* even p */
  SD_CHECK(sd_dh_new(p + 64, pl - 64, &two, 1, 0, &d) == SD_OK);         /* 1536 bits: allowed size */
  sd_dh_free(d);
  d = NULL;
  SD_CHECK(sd_dh_new(p + 160, pl - 160, &two, 1, 0, &d) == SD_E_UNSUPPORTED); /* 768 bits */
  SD_CHECK(sd_dh_new(p, pl, &two, 1, 159, &d) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_dh_new(p, pl, &two, 1, 2048, &d) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_dh_new(p, pl, &two, 1, 0, &d) == SD_OK);
  SD_CHECK(sd_dh_bits(d) == 2048 && sd_dh_len(d) == 256);
  sd_dh_free(d);
  free(v);
}

SD_TEST(dh_gex_validation)
{
  tu_lines l;
  char *f[5];
  int n, cases = 0;
  sd_dh_gex_policy pol;
  size_t pl;
  const uint8_t *p;
  memset(&pol, 0, sizeof(pol));
  pol.min_bits = 1024;
  SD_REQUIRE(tu_lines_open(&l, "refimpl/dh_gex.txt") == 0);
  while ((n = tu_lines_next(&l, f, 5)) == 4) {
    uint8_t *pp, *g;
    size_t ppl = tu_hex(f[2], &pp), gl = tu_hex(f[3], &g);
    sd_err want = strcmp(f[1], "ok") == 0 ? SD_OK : SD_E_CRYPTO, got;
    double t0 = tu_seconds();
    got = sd_dh_gex_validate(pp, ppl, g, gl, &pol);
    if (got != want)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "gex case %d (%u bits): got %d, want %d", cases, (unsigned)ppl * 8,
                   (int)got, (int)want);
    if (want == SD_OK && strcmp(f[3], "02") == 0)
      printf("    %u-bit safe prime validated in %.0f ms\n", (unsigned)ppl * 8, (tu_seconds() - t0) * 1000);
    free(pp);
    free(g);
    cases++;
  }
  tu_lines_close(&l);
  SD_CHECK(cases >= 13);
  /* size policy */
  p = sd_dh_group_modp(1, &pl);
  SD_CHECK(sd_dh_gex_validate(p, pl, (const uint8_t *)"\x02", 1, NULL) == SD_E_UNSUPPORTED);  /* < 2048 */
  p = sd_dh_group_modp(18, &pl);
  pol.max_bits = 4096;
  SD_CHECK(sd_dh_gex_validate(p, pl, (const uint8_t *)"\x02", 1, &pol) == SD_E_UNSUPPORTED);
  pol.max_bits = 0;
  SD_CHECK(sd_dh_gex_validate(p, pl, (const uint8_t *)"\x02", 1, &pol) == SD_OK);
  SD_CHECK(sd_dh_gex_validate(p, pl, (const uint8_t *)"\x01", 1, &pol) == SD_E_CRYPTO);
}
