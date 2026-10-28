/* sd_config machine templates (03 §3.2, 3.4 scope = users): sd_profile_enum_templates lists only the scope = users
 * profiles of the machine store, skips other files and a missing folder, and sd_config_machine_root places the machine
 * store under the test override (<override>\machine). Every file operation runs under a temporary root. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "sd_platform/sd_time.h"

typedef struct tpl_ctx {
  int n;
  char name[4][128];
} tpl_ctx;

static int tpl_cb(void *vctx, const sd_profile *p, const wchar_t *path)
{
  tpl_ctx *c = (tpl_ctx *)vctx;
  SD_UNUSED(path);
  if (c->n < 4)
    _snprintf_s(c->name[c->n], sizeof(c->name[0]), _TRUNCATE, "%s", p->name);
  c->n++;
  return 1;
}

static void tpl_remove_dir(const wchar_t *root)
{
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  wcscpy_s(pattern, MAX_PATH, root);
  wcscat_s(pattern, MAX_PATH, L"\\*");
  f = FindFirstFileW(pattern, &fd);
  if (f == INVALID_HANDLE_VALUE)
    return;
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    wcscpy_s(path, MAX_PATH, root);
    wcscat_s(path, MAX_PATH, L"\\");
    wcscat_s(path, MAX_PATH, fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      tpl_remove_dir(path);
    else
      DeleteFileW(path);
  } while (FindNextFileW(f, &fd));
  FindClose(f);
  RemoveDirectoryW(root);
}

static int tpl_write(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD n = 0;
  int ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = WriteFile(h, text, (DWORD)strlen(text), &n, NULL) && n == strlen(text);
  CloseHandle(h);
  return ok;
}

static const char k_users_profile[] =
  "[profile]\r\n"
  "format = 1\r\n"
  "id = 3a1f0c2b9d8e4f7a8b6c5d4e3f2a1b0c\r\n"
  "name = Team share\r\n"
  "host = files.example.org\r\n"
  "port = 22\r\n"
  "user = deploy\r\n"
  "remote_path = /srv/team\r\n"
  "scope = users\r\n"
  "[auth]\r\n"
  "methods = publickey\r\n"
  "[mount]\r\n"
  "target = auto\r\n";

static const char k_user_profile[] =
  "[profile]\r\n"
  "format = 1\r\n"
  "id = 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b\r\n"
  "name = My own\r\n"
  "host = example.org\r\n"
  "port = 22\r\n"
  "user = alice\r\n"
  "scope = user\r\n";

SD_TEST(profile_templates_machine_scope_users)
{
  wchar_t tmp[MAX_PATH], root[MAX_PATH], machine[MAX_PATH], profiles[MAX_PATH], file[MAX_PATH], expect[MAX_PATH];
  wchar_t num[64];
  DWORD n;
  tpl_ctx c;
  n = GetTempPathW(MAX_PATH, tmp);
  SD_REQUIRE(n != 0 && n < MAX_PATH - 64);
  swprintf_s(num, SD_COUNTOF(num), L"sd-test-config-tpl-%lu-%llu", (unsigned long)GetCurrentProcessId(),
             (unsigned long long)sd_tick_ms());
  wcscpy_s(root, MAX_PATH, tmp);
  wcscat_s(root, MAX_PATH, num);
  tpl_remove_dir(root);
  SD_REQUIRE(CreateDirectoryW(root, NULL));
  sd_config_set_root_override(root);

  /* the machine store of the test override is <override>\machine (not %ProgramData%) */
  SD_CHECK(sd_config_machine_root(machine, SD_COUNTOF(machine)) == SD_OK);
  wcscpy_s(expect, MAX_PATH, root);
  wcscat_s(expect, MAX_PATH, L"\\machine");
  SD_CHECK(wcscmp(machine, expect) == 0);

  wcscpy_s(profiles, MAX_PATH, machine);
  wcscat_s(profiles, MAX_PATH, L"\\profiles");
  SD_REQUIRE(CreateDirectoryW(machine, NULL));
  SD_REQUIRE(CreateDirectoryW(profiles, NULL));

  wcscpy_s(file, MAX_PATH, profiles);
  wcscat_s(file, MAX_PATH, L"\\team.ini");
  SD_REQUIRE(tpl_write(file, k_users_profile));
  wcscpy_s(file, MAX_PATH, profiles);
  wcscat_s(file, MAX_PATH, L"\\own.ini");
  SD_REQUIRE(tpl_write(file, k_user_profile));
  wcscpy_s(file, MAX_PATH, profiles);
  wcscat_s(file, MAX_PATH, L"\\notes.txt");
  SD_REQUIRE(tpl_write(file, k_users_profile));

  memset(&c, 0, sizeof(c));
  SD_CHECK(sd_profile_enum_templates(tpl_cb, &c) == SD_OK);
  SD_CHECK_EQ_INT(c.n, 1);
  SD_CHECK_STR(c.name[0], "Team share");

  /* no machine folder: nothing to list, and no error */
  tpl_remove_dir(machine);
  memset(&c, 0, sizeof(c));
  SD_CHECK(sd_profile_enum_templates(tpl_cb, &c) == SD_OK);
  SD_CHECK_EQ_INT(c.n, 0);

  sd_config_set_root_override(NULL);
  tpl_remove_dir(root);
}

/* The mount path finds a template by id or name (sd_profile_find_mountable); sd_profile_find, which saves and duplicate
   checks use, still reads the user's store only. */
SD_TEST(profile_find_mountable_reaches_templates)
{
  wchar_t tmp[MAX_PATH], root[MAX_PATH], machine[MAX_PATH], profiles[MAX_PATH], file[MAX_PATH];
  wchar_t num[64];
  DWORD n;
  sd_profile p;
  n = GetTempPathW(MAX_PATH, tmp);
  SD_REQUIRE(n != 0 && n < MAX_PATH - 64);
  swprintf_s(num, SD_COUNTOF(num), L"sd-test-config-mnt-%lu-%llu", (unsigned long)GetCurrentProcessId(),
             (unsigned long long)sd_tick_ms());
  wcscpy_s(root, MAX_PATH, tmp);
  wcscat_s(root, MAX_PATH, num);
  tpl_remove_dir(root);
  SD_REQUIRE(CreateDirectoryW(root, NULL));
  sd_config_set_root_override(root);
  SD_REQUIRE(sd_config_machine_root(machine, SD_COUNTOF(machine)) == SD_OK);
  wcscpy_s(profiles, MAX_PATH, machine);
  wcscat_s(profiles, MAX_PATH, L"\\profiles");
  SD_REQUIRE(CreateDirectoryW(machine, NULL));
  SD_REQUIRE(CreateDirectoryW(profiles, NULL));
  wcscpy_s(file, MAX_PATH, profiles);
  wcscat_s(file, MAX_PATH, L"\\team.ini");
  SD_REQUIRE(tpl_write(file, k_users_profile));

  memset(&p, 0, sizeof(p));
  SD_CHECK(sd_profile_find_mountable("3a1f0c2b9d8e4f7a8b6c5d4e3f2a1b0c", &p, NULL, 0) == SD_OK);
  SD_CHECK_STR(p.name, "Team share");
  SD_CHECK(p.scope == SD_PROFILE_SCOPE_USERS);
  memset(&p, 0, sizeof(p));
  SD_CHECK(sd_profile_find_mountable("team share", &p, NULL, 0) == SD_OK);   /* by name, case-insensitively */
  SD_CHECK_STR(p.id, "3a1f0c2b9d8e4f7a8b6c5d4e3f2a1b0c");
  SD_CHECK(sd_profile_find("3a1f0c2b9d8e4f7a8b6c5d4e3f2a1b0c", &p, NULL, 0) != SD_OK);
  SD_CHECK(sd_profile_find_mountable("Nobody here", &p, NULL, 0) == SD_E_NOT_FOUND);
  SD_CHECK(sd_profile_find_mountable(NULL, &p, NULL, 0) == SD_E_INVALID_PARAM);

  sd_config_set_root_override(NULL);
  tpl_remove_dir(root);
}
