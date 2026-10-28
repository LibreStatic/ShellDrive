/* %ProgramData% trust (TM-R34) and the stage folder of the elevated stages, on temp folders only. The owner rule is a
   seam (trust every owner, or none), as in tests/unit/sd_svc/test_repair.c; nothing here touches the real
   %ProgramData%, needs elevation or creates a service. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "setup_int.h"
#include "setup_trust.h"
#include "svc_repair.h"
#include "test_common.h"

static int owner_any(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 1;
}

static int owner_none(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 0;
}

/* The test folders are owned by this (non-elevated) process: the owner gets full control as an extra ACE, the same way
   BUILTIN\Administrators does in the shipping build, so the tree can be built and removed. */
static void ops_make(svc_repair_ops *o, int trust)
{
  o->ctx = NULL;
  o->owner_trusted = trust ? owner_any : owner_none;
  o->extra_ace = L"(A;OICI;FA;;;OW)";
}

static int dir_exists(const wchar_t *path)
{
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

SD_TEST(setup_programdata_trust)
{
  wchar_t base[MAX_PATH];
  wchar_t vendor[MAX_PATH];
  wchar_t product[MAX_PATH];
  wchar_t missing[MAX_PATH];
  svc_repair_ops ops;
  sd_setup_trust_result tr;
  DWORD err;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(vendor, MAX_PATH, base, L"LibreStatic") == 0);
  SD_REQUIRE(sd_setup_path_join(product, MAX_PATH, vendor, L"ShellDrive") == 0);

  /* A missing base is an error and changes nothing. */
  SD_REQUIRE(sd_setup_path_join(missing, MAX_PATH, base, L"no-such-base") == 0);
  ops_make(&ops, 1);
  err = sd_setup_secure_programdata_with(&ops, missing, &tr);
  SD_CHECK(err != 0);
  SD_CHECK_EQ_INT(tr.moved, 0);

  /* Trusted owners: the vendor and product folders are created, nothing is moved, and a second run is clean. */
  err = sd_setup_secure_programdata_with(&ops, base, &tr);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK_EQ_INT(tr.moved, 0);
  SD_CHECK(dir_exists(vendor));
  SD_CHECK(dir_exists(product));
  err = sd_setup_secure_programdata_with(&ops, base, &tr);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK_EQ_INT(tr.moved, 0);

  /* An untrusted owner: the vendor folder is moved aside (never followed) and a fresh one is created in its place. */
  ops_make(&ops, 0);
  err = sd_setup_secure_programdata_with(&ops, base, &tr);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK_EQ_INT(tr.moved, 1);
  SD_CHECK(wcsstr(tr.path, L"LibreStatic.untrusted-") != NULL);
  SD_CHECK(dir_exists(vendor));

  test_remove_tree(base);
}

SD_TEST(setup_stage_dir_fresh_names)
{
  wchar_t base[MAX_PATH];
  wchar_t setup_dir[MAX_PATH];
  wchar_t first[MAX_PATH];
  wchar_t second[MAX_PATH];
  wchar_t *leaf;
  DWORD err;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(setup_dir, MAX_PATH, base, L"setup") == 0);

  /* The folder is created with its name in one call, and the setup folder is created when it is missing. */
  err = sd_setup_create_stage_dir(setup_dir, L"(A;OICI;FA;;;OW)", first, MAX_PATH);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK(dir_exists(setup_dir));
  SD_CHECK(dir_exists(first));
  leaf = wcsrchr(first, L'\\');
  SD_REQUIRE(leaf != NULL);
  SD_CHECK_EQ_INT((int)wcslen(leaf + 1), 32);

  /* Every call makes a new folder; an old one is never reused. */
  err = sd_setup_create_stage_dir(setup_dir, L"(A;OICI;FA;;;OW)", second, MAX_PATH);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK(wcscmp(first, second) != 0);
  SD_CHECK(dir_exists(second));

  test_remove_tree(base);
}
