/* sd_update state: per-channel anti-rollback serials, the legacy single-file migration, the machine copy
 * (maximum of the readable values), last_verified, blobs and the stored manifest. Temp directories only. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "fixture.h"
#include "sd_base/sd_mem.h"

static int make_dirs(fx *f, wchar_t *user, size_t ucap, wchar_t *machine, size_t mcap)
{
  if (!fx_path(f, L"state-user", user, ucap) || !CreateDirectoryW(user, NULL))
    return 0;
  if (!fx_path(f, L"state-machine", machine, mcap) || !CreateDirectoryW(machine, NULL))
    return 0;
  return 1;
}

SD_TEST(state_serial_is_per_channel)
{
  fx f;
  wchar_t user[MAX_PATH], machine[MAX_PATH];
  sd_upd_state_dirs d;
  uint64_t v = 99;
  SD_REQUIRE(fx_init(&f, "stserial"));
  SD_REQUIRE(make_dirs(&f, user, MAX_PATH, machine, MAX_PATH));
  d.user = user;
  d.machine = NULL;

  SD_CHECK(sd_upd_state_read_serial(&d, "stable", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 0);
  SD_CHECK(sd_upd_state_write_serial(&d, "beta", 1000) == SD_UPD_OK);   /* a huge beta serial ... */
  SD_CHECK(sd_upd_state_write_serial(&d, "stable", 5) == SD_UPD_OK);     /* ... does not block stable */
  SD_CHECK(sd_upd_state_read_serial(&d, "stable", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 5);
  SD_CHECK(sd_upd_state_read_serial(&d, "beta", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 1000);
  SD_CHECK(sd_upd_state_write_serial(&d, "stable", 4) == SD_UPD_E_ROLLBACK);
  SD_CHECK(sd_upd_state_write_serial(&d, "stable", 5) == SD_UPD_OK);     /* equal is not a rollback */
  SD_CHECK(sd_upd_state_read_serial(&d, "stable", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 5);
  SD_CHECK(sd_upd_state_read_serial(&d, "nightly", &v) == SD_UPD_E_INVALID);
  fx_done(&f);
}

SD_TEST(state_machine_copy_counts_as_maximum)
{
  fx f;
  wchar_t user[MAX_PATH], machine[MAX_PATH], path[MAX_PATH];
  sd_upd_state_dirs d;
  uint64_t v = 0;
  SD_REQUIRE(fx_init(&f, "stmach"));
  SD_REQUIRE(make_dirs(&f, user, MAX_PATH, machine, MAX_PATH));
  d.user = user;
  d.machine = machine;
  SD_REQUIRE(fx_path(&f, L"state-machine\\last_serial.stable", path, MAX_PATH));
  SD_REQUIRE(fx_write(path, "9\n", 2));
  SD_CHECK(sd_upd_state_write_serial(&d, "stable", 3) == SD_UPD_E_ROLLBACK);   /* machine copy is higher */
  SD_CHECK(sd_upd_state_read_serial(&d, "stable", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 9);
  fx_done(&f);
}

SD_TEST(state_legacy_serial_is_migrated_once)
{
  fx f;
  wchar_t user[MAX_PATH], machine[MAX_PATH], legacy[MAX_PATH], target[MAX_PATH];
  sd_upd_state_dirs d;
  uint64_t v = 0;
  uint8_t *buf = NULL;
  size_t n = 0;
  SD_REQUIRE(fx_init(&f, "stlegacy"));
  SD_REQUIRE(make_dirs(&f, user, MAX_PATH, machine, MAX_PATH));
  d.user = user;
  d.machine = NULL;
  SD_REQUIRE(fx_path(&f, L"state-user\\last_serial", legacy, MAX_PATH));
  SD_REQUIRE(fx_write(legacy, "7\n", 2));
  SD_CHECK(sd_upd_state_read_serial(&d, "stable", &v) == SD_UPD_OK);
  SD_CHECK_EQ_INT(v, 7);
  SD_REQUIRE(fx_path(&f, L"state-user\\last_serial.stable", target, MAX_PATH));
  SD_CHECK(fx_read(target, &buf, &n));                      /* migrated to the configured channel */
  SD_CHECK(n >= 1 && buf[0] == '7');
  if (buf) sd_free(buf);
  SD_CHECK(GetFileAttributesW(legacy) == INVALID_FILE_ATTRIBUTES);   /* the legacy file is gone */
  fx_done(&f);
}

SD_TEST(state_verified_blobs_and_manifest)
{
  fx f;
  wchar_t user[MAX_PATH], machine[MAX_PATH];
  sd_upd_state_dirs d;
  int64_t t = 0;
  uint8_t *buf = NULL;
  size_t n = 0;
  static const uint8_t blob[5] = { 1, 2, 3, 4, 5 };
  SD_REQUIRE(fx_init(&f, "stblob"));
  SD_REQUIRE(make_dirs(&f, user, MAX_PATH, machine, MAX_PATH));
  d.user = user;
  d.machine = machine;

  SD_CHECK(sd_upd_state_write_verified(&d, "stable", 1800000000) == SD_UPD_OK);
  SD_CHECK(sd_upd_state_read_verified(&d, "stable", &t) == SD_UPD_OK);
  SD_CHECK(t == 1800000000);

  SD_CHECK(sd_upd_state_write_blob(&d, L"keyset", blob, sizeof(blob)) == SD_UPD_OK);
  SD_CHECK(sd_upd_state_read_blob(&d, L"keyset", &buf, &n) == SD_UPD_OK);
  SD_CHECK(n == sizeof(blob) && memcmp(buf, blob, n) == 0);
  sd_free(buf);
  buf = NULL;

  SD_CHECK(sd_upd_state_write_manifest(&d, "beta", blob, 3) == SD_UPD_OK);
  SD_CHECK(sd_upd_state_read_manifest(&d, "beta", &buf, &n) == SD_UPD_OK);
  SD_CHECK(n == 3);
  sd_free(buf);
  buf = NULL;

  SD_CHECK(sd_upd_state_read_blob(&d, L"absent", &buf, &n) != SD_UPD_OK);
  SD_CHECK(buf == NULL && n == 0);
  fx_done(&f);
}
