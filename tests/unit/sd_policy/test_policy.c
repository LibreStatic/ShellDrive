/* sd_policy: the generated table is complete and matches the types the readers rely on. The tests never
 * write the registry; a type mismatch is refused before any value is read. */
#include <windows.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_policy/sd_policy.h"

static const wchar_t k_key[] = L"Software\\Policies\\LibreStatic\\ShellDrive";

SD_TEST(policy_table_is_complete)
{
  sd_policy_id id;
  int i, j;
  const int want_count = 23;
  SD_CHECK((int)SD_POLICY_ID_COUNT == want_count);
  SD_CHECK(wcscmp(sd_policy_key(), k_key) == 0);
  for (i = 0; i < (int)SD_POLICY_ID_COUNT; i++) {
    const sd_policy_def *d;
    id = (sd_policy_id)i;
    d = sd_policy_def_of(id);
    SD_REQUIRE(d != NULL);
    SD_REQUIRE(d->name != NULL && d->name[0] != 0);
    for (j = 0; j < i; j++) {
      const sd_policy_def *o = sd_policy_def_of((sd_policy_id)j);
      SD_CHECK(wcscmp(o->name, d->name) != 0);
    }
    if (d->reg == SD_POLICY_REG_DWORD)
      SD_CHECK(d->min <= d->max);
    if (d->kind == SD_POLICY_KIND_TEXT) {
      SD_CHECK(d->reg == SD_POLICY_REG_SZ && d->maxlen > 0);
    }
  }
  SD_CHECK(sd_policy_def_of((sd_policy_id)SD_POLICY_ID_COUNT) == NULL);
  SD_CHECK(sd_policy_def_of((sd_policy_id)-1) == NULL);
}

SD_TEST(policy_kinds_match_readers)
{
  const sd_policy_def *d = sd_policy_def_of(SD_POLICY_UILANGUAGE);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_ENUM && d->reg == SD_POLICY_REG_SZ);
  SD_CHECK(wcscmp(d->name, L"UILanguage") == 0);

  d = sd_policy_def_of(SD_POLICY_DISABLENETWORKLOCATIONS);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_BOOLEAN && d->reg == SD_POLICY_REG_DWORD);
  SD_CHECK(d->min == 0 && d->max == 1);

  d = sd_policy_def_of(SD_POLICY_LEGACYALGORITHMS);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_ENUM && d->reg == SD_POLICY_REG_DWORD && d->max == 2);

  d = sd_policy_def_of(SD_POLICY_PROXYSERVER);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_TEXT && d->reg == SD_POLICY_REG_SZ && d->maxlen == 1024);
}

SD_TEST(policy_type_mismatch_reads_absent)
{
  DWORD v = 7;
  wchar_t buf[16];
  /* A text policy is never read as a DWORD, a DWORD policy never as text, and out-of-range ids read
   * as absent; all three return before the registry is touched. */
  SD_CHECK(sd_policy_get_dword(SD_POLICY_UILANGUAGE, &v) == 0);
  SD_CHECK(sd_policy_get_sz(SD_POLICY_DISABLENETWORKLOCATIONS, buf, SD_COUNTOF(buf)) == 0);
  SD_CHECK(sd_policy_get_dword((sd_policy_id)SD_POLICY_ID_COUNT, &v) == 0);
  SD_CHECK(sd_policy_get_sz(SD_POLICY_UILANGUAGE, NULL, 0) == 0);
  SD_CHECK(v == 7);
}

SD_TEST(policy_machine_reads_refuse_type_and_id_mismatch)
{
  DWORD v = 7;
  wchar_t buf[16];
  /* The machine-only readers (the service, 2.6 rule 1) apply the same type and id checks, before any registry access */
  SD_CHECK(sd_policy_machine_get_dword(SD_POLICY_UILANGUAGE, &v) == 0);
  SD_CHECK(sd_policy_machine_get_sz(SD_POLICY_DISABLENETWORKLOCATIONS, buf, SD_COUNTOF(buf)) == 0);
  SD_CHECK(sd_policy_machine_get_dword((sd_policy_id)SD_POLICY_ID_COUNT, &v) == 0);
  SD_CHECK(sd_policy_machine_get_dword((sd_policy_id)-1, &v) == 0);
  SD_CHECK(sd_policy_machine_get_sz(SD_POLICY_UILANGUAGE, NULL, 0) == 0);
  SD_CHECK(sd_policy_machine_get_dword(SD_POLICY_ALLOWSYSTEMPROXY, NULL) == 0);
  SD_CHECK(v == 7);
}

SD_TEST(policy_system_proxy_policies_are_boolean_machine_ready)
{
  const sd_policy_def *d = sd_policy_def_of(SD_POLICY_ALLOWSYSTEMPROXY);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_BOOLEAN && d->reg == SD_POLICY_REG_DWORD && d->min == 0 && d->max == 1);
  d = sd_policy_def_of(SD_POLICY_ALLOWSYSTEMPROXYSSPI);
  SD_REQUIRE(d != NULL);
  SD_CHECK(d->kind == SD_POLICY_KIND_BOOLEAN && d->reg == SD_POLICY_REG_DWORD && d->min == 0 && d->max == 1);
}
