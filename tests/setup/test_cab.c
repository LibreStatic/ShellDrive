/* CAB extraction through FDI (cabinet.dll): a good payload, traversal rejection (member names with ../, made
   by makecab at build time), member and total size limits, and a damaged payload that must fail cleanly. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>

#include "setup_int.h"
#include "sd_test.h"
#include "test_common.h"

/* Opens <base>\<leaf>; returns 1 when the file exists. */
static int exists_in(const wchar_t *base, const wchar_t *leaf)
{
  wchar_t p[MAX_PATH];
  if (sd_setup_path_join(p, MAX_PATH, base, leaf) != 0)
    return 0;
  return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

static int load_fixture(const wchar_t *leaf, unsigned char **buf, size_t *size)
{
  wchar_t path[MAX_PATH];
  test_fixture_path(leaf, path, MAX_PATH);
  return test_read_file(path, buf, size);
}

SD_TEST(setup_cab_extract_good)
{
  unsigned char *buf = NULL;
  size_t size = 0;
  wchar_t base[MAX_PATH];
  wchar_t dest[MAX_PATH];
  sd_setup_payload p;
  sd_setup_result r;
  unsigned files = 0;
  wchar_t readme[MAX_PATH];
  HANDLE h;
  char got[64];
  DWORD n = 0;

  SD_REQUIRE(load_fixture(L"payload-ok.cab", &buf, &size) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"out") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));

  p.data = buf;
  p.size = size;
  memset(&r, 0, sizeof(r));
  {
    int rc = sd_setup_cab_extract(&p, dest, NULL, &r, &files);
    if (rc != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "extract failed: msg %lu, code %ld", (unsigned long)r.msg, r.code);
  }
  SD_CHECK_EQ_INT(files, 6);
  SD_CHECK(exists_in(dest, L"shelldrive.exe"));
  SD_CHECK(exists_in(dest, L"shelldrive-host.exe"));
  SD_CHECK(exists_in(dest, L"shelldrive-ui.exe"));
  SD_CHECK(exists_in(dest, L"shelldrive-shellext.dll"));
  SD_CHECK(exists_in(dest, L"uninstall.exe"));

  /* A member in a sub-folder keeps its folder. */
  SD_REQUIRE(sd_setup_path_join(readme, MAX_PATH, dest, L"sub\\readme.txt") == 0);
  h = CreateFileW(readme, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(h, got, sizeof(got) - 1, &n, NULL));
  got[n] = '\0';
  CloseHandle(h);
  SD_CHECK(strncmp(got, "readme", 6) == 0);

  HeapFree(GetProcessHeap(), 0, buf);
  test_remove_tree(base);
}

SD_TEST(setup_cab_traversal_refused)
{
  unsigned char *buf = NULL;
  size_t size = 0;
  wchar_t base[MAX_PATH];
  wchar_t dest[MAX_PATH];
  sd_setup_payload p;
  sd_setup_result r;
  unsigned files = 0;
  int rc;

  SD_REQUIRE(load_fixture(L"payload-traversal.cab", &buf, &size) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"out") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));

  p.data = buf;
  p.size = size;
  memset(&r, 0, sizeof(r));
  rc = sd_setup_cab_extract(&p, dest, NULL, &r, &files);
  SD_CHECK_EQ_INT(rc, SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_UNSAFE);
  /* The member would land next to the destination (\evil.txt in base): it must not exist. */
  SD_CHECK(!exists_in(base, L"evil.txt"));
  SD_CHECK(!exists_in(dest, L"..\\evil.txt"));

  HeapFree(GetProcessHeap(), 0, buf);
  test_remove_tree(base);
}

SD_TEST(setup_cab_size_limits)
{
  unsigned char *buf = NULL;
  size_t size = 0;
  wchar_t base[MAX_PATH];
  wchar_t dest[MAX_PATH];
  sd_setup_payload p;
  sd_setup_result r;
  sd_setup_cab_limits lim;
  unsigned files = 0;

  SD_REQUIRE(load_fixture(L"payload-ok.cab", &buf, &size) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  p.data = buf;
  p.size = size;

  /* Per member: every member is larger than 4 bytes. */
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"small") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));
  sd_setup_cab_limits_default(&lim);
  lim.max_member = 4;
  memset(&r, 0, sizeof(r));
  SD_CHECK_EQ_INT(sd_setup_cab_extract(&p, dest, &lim, &r, &files), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_TOO_BIG);

  /* Member count. */
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"count") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));
  sd_setup_cab_limits_default(&lim);
  lim.max_members = 2;
  memset(&r, 0, sizeof(r));
  SD_CHECK_EQ_INT(sd_setup_cab_extract(&p, dest, &lim, &r, &files), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_TOO_BIG);

  /* Total size. */
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"total") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));
  sd_setup_cab_limits_default(&lim);
  lim.max_total = 8;
  memset(&r, 0, sizeof(r));
  SD_CHECK_EQ_INT(sd_setup_cab_extract(&p, dest, &lim, &r, &files), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_TOO_BIG);

  HeapFree(GetProcessHeap(), 0, buf);
  test_remove_tree(base);
}

SD_TEST(setup_cab_damaged_payload)
{
  static const unsigned char junk[] = "MSCF-not-really-a-cabinet-at-all, just junk bytes 0123456789";
  wchar_t base[MAX_PATH];
  wchar_t dest[MAX_PATH];
  sd_setup_payload p;
  sd_setup_result r;
  unsigned files = 0;
  int rc;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(dest, MAX_PATH, base, L"out") == 0);
  SD_REQUIRE(CreateDirectoryW(dest, NULL));
  p.data = junk;
  p.size = sizeof(junk) - 1;
  memset(&r, 0, sizeof(r));
  rc = sd_setup_cab_extract(&p, dest, NULL, &r, &files);
  SD_CHECK_EQ_INT(rc, SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT);
  SD_CHECK_EQ_INT(files, 0);
  test_remove_tree(base);
}
