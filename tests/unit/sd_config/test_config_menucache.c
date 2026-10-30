/* sd_config menu.cache (03 §8.2.2): name sanitizing, the text format and its caps, and the writer through the profile
 * store (add, rename, delete, the import path, the atomic replace and the absence of secrets in the file). */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"

#define ID_A "0123456789abcdef0123456789abcdef"
#define ID_B "11111111111111111111111111111111"
#define ID_C "22222222222222222222222222222222"

static void mc_temp_root(wchar_t *out, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  FILETIME ft;
  ULARGE_INTEGER now;
  GetSystemTimeAsFileTime(&ft);
  now.LowPart = ft.dwLowDateTime;
  now.HighPart = ft.dwHighDateTime;
  _snwprintf_s(out, cch, _TRUNCATE, L"%ssd-test-menucache-%lu-%lu", n ? tmp : L"", (unsigned long)GetCurrentProcessId(),
               (unsigned long)(now.QuadPart & 0xFFFFFFFFu));
}

static void mc_remove_tree(const wchar_t *root)
{
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*", root);
  f = FindFirstFileExW(pattern, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  if (f != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        continue;
      _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\%s", root, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        mc_remove_tree(path);
      else
        DeleteFileW(path);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
  }
  RemoveDirectoryW(root);
}

/* Reads the whole file into buf (NUL-terminated). Returns the length, or -1 when it cannot be read. */
static long mc_read(const wchar_t *path, char *buf, size_t cap)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD got = 0;
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  if (!ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL)) {
    CloseHandle(h);
    return -1;
  }
  CloseHandle(h);
  buf[got] = '\0';
  return (long)got;
}

/* Number of files in dir whose name ends in .tmp. */
static int mc_count_tmp(const wchar_t *dir)
{
  wchar_t pattern[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  int n = 0;
  _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*.tmp", dir);
  f = FindFirstFileExW(pattern, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  if (f != INVALID_HANDLE_VALUE) {
    do {
      n++;
    } while (FindNextFileW(f, &fd));
    FindClose(f);
  }
  return n;
}

static void mc_set_entry(sd_menu_entry *e, const char *id, const char *name)
{
  memset(e, 0, sizeof(*e));
  strcpy_s(e->id, sizeof(e->id), id);
  strcpy_s(e->name, sizeof(e->name), name);
}

SD_TEST(menu_entry_sanitizing)
{
  static sd_profile p;
  sd_menu_entry e;

  /* control characters, a bidi override and a zero-width space are removed; spaces are kept and trimmed at the ends */
  sd_profile_defaults(&p);
  strcpy_s(p.id, sizeof(p.id), ID_A);
  strcpy_s(p.name, sizeof(p.name), "  Web\tServer\x01 \xE2\x80\xAE" "Caf\xC3\xA9 \xE2\x80\x8B  ");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_OK);
  SD_CHECK_STR(e.id, ID_A);
  SD_CHECK_STR(e.name, "WebServer Caf\xC3\xA9");

  /* invalid UTF-8 bytes are dropped; a supplementary-plane character (two UTF-16 units) is kept */
  strcpy_s(p.name, sizeof(p.name), "A\xFF" "B\xC3" "\xF0\x9F\x98\x80");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_OK);
  SD_CHECK_STR(e.name, "AB\xF0\x9F\x98\x80");

  /* nothing left after sanitizing: not listed */
  strcpy_s(p.name, sizeof(p.name), "\x01\t \xE2\x80\x8B");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_E_INVALID_PARAM);

  /* ids: 32 lowercase hex digits only */
  strcpy_s(p.name, sizeof(p.name), "Named");
  strcpy_s(p.id, sizeof(p.id), "0123456789ABCDEF0123456789abcdef");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_E_INVALID_PARAM);
  strcpy_s(p.id, sizeof(p.id), "0123456789abcdef0123456789abcde");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_E_INVALID_PARAM);
  strcpy_s(p.id, sizeof(p.id), "");
  SD_CHECK(sd_menu_entry_from_profile(&p, &e) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_menu_entry_from_profile(NULL, &e) == SD_E_INVALID_PARAM);
}

SD_TEST(menu_format_layout)
{
  static char out[1024];
  sd_menu_entry e[4];
  size_t n;

  mc_set_entry(&e[0], ID_B, "Zeta");
  mc_set_entry(&e[1], ID_C, "alpha");
  mc_set_entry(&e[2], ID_A, "Beta");
  mc_set_entry(&e[3], ID_B, "Repeated id, dropped");   /* the first ID_B wins */
  memset(out, 0, sizeof(out));
  n = sd_menu_format(e, 4, out, sizeof(out));
  /* header, then the lines sorted by name, ASCII case-insensitive */
  SD_CHECK_EQ_INT(n, strlen("SDMENU 1\n" ID_C "\talpha\n" ID_A "\tBeta\n" ID_B "\tZeta\n"));
  SD_CHECK_STR(out, "SDMENU 1\n" ID_C "\talpha\n" ID_A "\tBeta\n" ID_B "\tZeta\n");

  /* an empty list is the header alone */
  memset(out, 0, sizeof(out));
  n = sd_menu_format(NULL, 0, out, sizeof(out));
  SD_CHECK_STR(out, "SDMENU 1\n");

  /* a malformed hand-built entry (uppercase id, control character in the name) is left out */
  mc_set_entry(&e[0], "0123456789ABCDEF0123456789ABCDEF", "Bad id");
  mc_set_entry(&e[1], ID_C, "Bad\tname");
  mc_set_entry(&e[2], ID_A, "Good");
  memset(out, 0, sizeof(out));
  n = sd_menu_format(e, 3, out, sizeof(out));
  SD_CHECK_STR(out, "SDMENU 1\n" ID_A "\tGood\n");

  /* a cap too small for the header is an error; a cap that fits the header and one line keeps that line only */
  SD_CHECK_EQ_INT(sd_menu_format(e, 3, out, 8), 0);
  SD_CHECK_EQ_INT(sd_menu_format(NULL, 1, out, sizeof(out)), 0);
  mc_set_entry(&e[0], ID_B, "Zeta");
  mc_set_entry(&e[1], ID_C, "alpha");
  n = sd_menu_format(e, 2, out, strlen("SDMENU 1\n" ID_C "\talpha\n") + 3);
  SD_CHECK_EQ_INT(n, strlen("SDMENU 1\n" ID_C "\talpha\n"));
}

SD_TEST(menu_format_caps)
{
  static sd_menu_entry e[SD_MENU_MAX_PROFILES + 40];
  static char out[SD_MENU_MAX_BYTES + 16];
  size_t i, n, lines = 0;

  /* more profiles than the cap: the first 256 valid ones (input order), sorted */
  for (i = 0; i < SD_COUNTOF(e); i++) {
    sprintf_s(e[i].id, sizeof(e[i].id), "%032lx", (unsigned long)(i + 1));
    sprintf_s(e[i].name, sizeof(e[i].name), "Profile %03u", (unsigned)i);
  }
  n = sd_menu_format(e, SD_COUNTOF(e), out, sizeof(out));
  for (i = 0; i < n; i++)
    if (out[i] == '\n')
      lines++;
  SD_CHECK_EQ_INT(lines, 1 + SD_MENU_MAX_PROFILES);
  SD_CHECK(n <= SD_MENU_MAX_BYTES);

  /* long names (384 bytes each): the byte cap leaves out the lines that would pass 64 KiB */
  for (i = 0; i < SD_MENU_MAX_PROFILES; i++) {
    char name[SD_MENU_NAME_BYTES + 1];
    size_t k;
    for (k = 0; k < 380; k++)
      name[k] = 'y';
    sprintf_s(name + 380, 5, "%04u", (unsigned)i);
    strcpy_s(e[i].name, sizeof(e[i].name), name);
    sprintf_s(e[i].id, sizeof(e[i].id), "%032lx", (unsigned long)(i + 1000));
  }
  n = sd_menu_format(e, SD_MENU_MAX_PROFILES, out, sizeof(out));
  SD_CHECK(n <= SD_MENU_MAX_BYTES);
  SD_CHECK_EQ_INT(n, 9 + 156 * (SD_MENU_ID_CHARS + 1 + SD_MENU_NAME_BYTES + 1));
}

SD_TEST(menu_writer_through_profile_store)
{
  static sd_profile p, q;
  wchar_t root[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
  static char text[SD_MENU_MAX_BYTES + 16];
  long got;

  mc_temp_root(root, SD_COUNTOF(root));
  mc_remove_tree(root);
  sd_config_set_root_override(root);
  SD_REQUIRE(sd_config_ensure_dirs() == SD_OK);
  SD_REQUIRE(sd_menucache_path(path, SD_COUNTOF(path)) == SD_OK);
  SD_CHECK(wcsstr(path, L"\\state\\menu.cache") != NULL);
  SD_REQUIRE(_snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%s\\state", root) > 0);

  /* no profile: the refresh writes the header alone */
  SD_REQUIRE(sd_menucache_refresh() == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  SD_CHECK_STR(text, "SDMENU 1\n");

  /* add: the entry appears with the id the save assigned */
  sd_profile_defaults(&p);
  strcpy_s(p.name, sizeof(p.name), "Web Server");
  strcpy_s(p.host, sizeof(p.host), "secret-host.example.org");
  strcpy_s(p.user, sizeof(p.user), "deploy");
  SD_REQUIRE(sd_profile_save(&p) == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  {
    char want[128];
    sprintf_s(want, sizeof(want), "SDMENU 1\n%s\tWeb Server\n", p.id);
    SD_CHECK_STR(text, want);
  }
  /* the host and the user are not in the file: only ids and names */
  SD_CHECK(strstr(text, "secret-host") == NULL);
  SD_CHECK(strstr(text, "deploy") == NULL);

  /* a second profile: sorted by name, so Backups comes first */
  sd_profile_defaults(&q);
  strcpy_s(q.name, sizeof(q.name), "Backups");
  strcpy_s(q.host, sizeof(q.host), "backup.example.org");
  strcpy_s(q.user, sizeof(q.user), "ops");
  SD_REQUIRE(sd_profile_save(&q) == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  {
    char want[256];
    sprintf_s(want, sizeof(want), "SDMENU 1\n%s\tBackups\n%s\tWeb Server\n", q.id, p.id);
    SD_CHECK_STR(text, want);
  }

  /* rename: the same id, a new name in the file */
  strcpy_s(p.name, sizeof(p.name), "Web Main");
  SD_REQUIRE(sd_profile_save(&p) == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  SD_CHECK(strstr(text, "Web Server") == NULL);
  SD_CHECK(strstr(text, "Web Main") != NULL);

  /* delete: the entry leaves the file */
  SD_REQUIRE(sd_profile_delete(q.id) == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  {
    char want[128];
    sprintf_s(want, sizeof(want), "SDMENU 1\n%s\tWeb Main\n", p.id);
    SD_CHECK_STR(text, want);
  }

  /* the import path saves without rewriting the file; one refresh afterwards brings it up to date */
  sd_profile_defaults(&q);
  strcpy_s(q.name, sizeof(q.name), "Imported");
  strcpy_s(q.host, sizeof(q.host), "imp.example.org");
  strcpy_s(q.user, sizeof(q.user), "ops");
  SD_REQUIRE(sd_profile_save_ex(&q, 0) == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  SD_CHECK(strstr(text, "Imported") == NULL);
  SD_REQUIRE(sd_menucache_refresh() == SD_OK);
  got = mc_read(path, text, sizeof(text));
  SD_REQUIRE(got > 0);
  SD_CHECK(strstr(text, "Imported") != NULL);

  /* the atomic replace leaves no temporary file behind */
  SD_CHECK_EQ_INT(mc_count_tmp(dir), 0);

  sd_config_set_root_override(NULL);
  mc_remove_tree(root);
}
