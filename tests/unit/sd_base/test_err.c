#include <string.h>

#include "sd_base/sd_checked.h"
#include "sd_base/sd_err.h"
#include "sd_test.h"

/* Covers every value of the master table (review §4: one test over every enum value). */
SD_TEST(err_names_unique_and_stable)
{
  int i, j;
  for (i = 0; i < SD_ERR_COUNT; i++) {
    const char *n = sd_err_name((sd_err)i);
    const char *c;
    SD_REQUIRE(n != NULL && n[0] != 0);
    SD_CHECK(strcmp(n, "unknown") != 0);
    for (c = n; *c; c++)
      SD_CHECK((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_');
    for (j = i + 1; j < SD_ERR_COUNT; j++)
      SD_CHECK(strcmp(n, sd_err_name((sd_err)j)) != 0);
    SD_CHECK(sd_err_from_name(n) == (sd_err)i);
  }
  SD_CHECK_STR(sd_err_name((sd_err)SD_ERR_COUNT), "unknown");
  SD_CHECK(sd_err_from_name("no_such_error") == SD_ERR_COUNT);
}

SD_TEST(err_ipc_spellings)
{
  /* 01 §10.2 / 03 §6.2 spellings that differ from the enum name. */
  SD_CHECK_STR(sd_err_name(SD_OK), "ok");
  SD_CHECK_STR(sd_err_name(SD_E_NOT_FOUND), "not_found");
  SD_CHECK_STR(sd_err_name(SD_E_HOSTKEY_MISMATCH), "host_key_mismatch");
  SD_CHECK_STR(sd_err_name(SD_E_HOSTKEY_TYPE_UNAVAILABLE), "host_key_type_unavailable");
  SD_CHECK_STR(sd_err_name(SD_E_DNS), "dns_failed");
  SD_CHECK_STR(sd_err_name(SD_E_AUTH_REQUIRED), "prompt_required");
  SD_CHECK_STR(sd_err_name(SD_E_PROXY), "proxy_connect_failed");
  SD_CHECK_STR(sd_err_name(SD_E_PROXY_AUTH), "proxy_auth_failed");
  SD_CHECK_STR(sd_err_name(SD_E_LEGACY_REJECTED), "legacy_refused");
}

SD_TEST(checked_arithmetic)
{
  size_t s;
  uint64_t u;
  SD_CHECK(sd_add_ovf(1, 2, &s) == 0 && s == 3);
  SD_CHECK(sd_add_ovf(SIZE_MAX, 1, &s) == 1 && s == SIZE_MAX);
  SD_CHECK(sd_mul_ovf(SIZE_MAX / 2, 2, &s) == 0);
  SD_CHECK(sd_mul_ovf(SIZE_MAX / 2 + 1, 2, &s) == 1);
  SD_CHECK(sd_mul_ovf(0, SIZE_MAX, &s) == 0 && s == 0);
  SD_CHECK(sd_add_ovf_u64(UINT64_MAX, 0, &u) == 0 && u == UINT64_MAX);
  SD_CHECK(sd_mul_ovf_u64(1ull << 32, 1ull << 32, &u) == 1);
  SD_CHECK(sd_mul_sat_u64(1ull << 40, 1ull << 40) == UINT64_MAX);
  SD_CHECK(sd_mul_sat_u64(4096, 1000) == 4096000);
}
