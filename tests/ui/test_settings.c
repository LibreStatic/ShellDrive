/* Settings model (apps/shelldrive-ui/ui_settings_model.c) and the save path it relies on (sd_settings_save). The
   settings folder is a temporary root (sd_config_set_root_override); the real %APPDATA% is never written. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "ui_settings_model.h"

SD_TEST(settings_model_defaults_and_mapping)
{
  sd_settings s;
  ui_settings_model m;
  sd_settings_defaults(&s);
  ui_settings_from_sd(&s, &m);
  SD_CHECK_STR(m.language, "");
  SD_CHECK_EQ_INT(m.notify, 1);
  SD_CHECK_EQ_INT(m.default_backend, SD_PROFILE_BACKEND_AUTO);
  SD_CHECK_EQ_INT((int)m.cache_mb, 0);

  /* "system" in the file is the same as an empty language */
  strcpy_s(s.ui_language, sizeof(s.ui_language), "system");
  ui_settings_from_sd(&s, &m);
  SD_CHECK_STR(m.language, "");

  s.cache_memory = (UINT64)3 << 20;
  s.cache_memory += 512 * 1024;                             /* 3.5 MiB shows as 3 */
  ui_settings_from_sd(&s, &m);
  SD_CHECK_EQ_INT((int)m.cache_mb, 3);
}

SD_TEST(settings_model_round_trip_keeps_other_fields)
{
  sd_settings s, back;
  ui_settings_model m, m2;
  sd_settings_defaults(&s);
  s.log_level = 3;                                          /* not shown by the window: must survive */
  s.putty_source = 0;
  strcpy_s(s.ui_language, sizeof(s.ui_language), "pt-BR");
  s.notify = 0;
  s.default_backend = SD_PROFILE_BACKEND_WEBDAV;
  s.cache_memory = (UINT64)512 << 20;

  ui_settings_from_sd(&s, &m);
  SD_CHECK_STR(m.language, "pt-BR");
  SD_CHECK_EQ_INT(m.notify, 0);
  SD_CHECK_EQ_INT(m.default_backend, SD_PROFILE_BACKEND_WEBDAV);
  SD_CHECK_EQ_INT((int)m.cache_mb, 512);

  m.cache_mb = 1024;
  m.notify = 1;
  ui_settings_to_sd(&m, &s);
  SD_CHECK(s.cache_memory == (UINT64)1024 << 20);
  SD_CHECK_EQ_INT(s.log_level, 3);
  SD_CHECK_EQ_INT(s.putty_source, 0);

  back = s;
  ui_settings_from_sd(&back, &m2);
  SD_CHECK_STR(m2.language, "pt-BR");
  SD_CHECK_EQ_INT(m2.notify, 1);
  SD_CHECK_EQ_INT((int)m2.cache_mb, 1024);
  SD_CHECK_EQ_INT(m2.default_backend, SD_PROFILE_BACKEND_WEBDAV);
}

static void temp_root(wchar_t *out, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  out[0] = L'\0';
  if (n == 0 || n > MAX_PATH - 40)
    return;
  wcscpy_s(out, cch, tmp);
  wcscat_s(out, cch, L"sd-test-ui-settings-");
  {
    wchar_t num[16];
    _snwprintf_s(num, SD_COUNTOF(num), _TRUNCATE, L"%lu", (unsigned long)GetCurrentProcessId());
    wcscat_s(out, cch, num);
  }
}

static void remove_tree(const wchar_t *root)
{
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  wcscpy_s(pattern, SD_COUNTOF(pattern), root);
  wcscat_s(pattern, SD_COUNTOF(pattern), L"\\*");
  f = FindFirstFileW(pattern, &fd);
  if (f != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        continue;
      wcscpy_s(path, SD_COUNTOF(path), root);
      wcscat_s(path, SD_COUNTOF(path), L"\\");
      wcscat_s(path, SD_COUNTOF(path), fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        remove_tree(path);
      else
        DeleteFileW(path);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
  }
  RemoveDirectoryW(root);
}

SD_TEST(settings_save_load_round_trip_in_a_temp_root)
{
  wchar_t root[MAX_PATH], file[MAX_PATH];
  sd_settings s, back;
  ui_settings_model m, m2;
  HANDLE h;
  DWORD got = 0;
  char text[4096];
  size_t len = 0;
  temp_root(root, SD_COUNTOF(root));
  SD_REQUIRE(root[0] != L'\0');
  remove_tree(root);
  sd_config_set_root_override(root);
  SD_REQUIRE(sd_config_ensure_dirs() == SD_OK);

  /* a key this UI does not know must survive a save */
  wcscpy_s(file, SD_COUNTOF(file), root);
  wcscat_s(file, SD_COUNTOF(file), L"\\settings.ini");
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  {
    static const char k[] = "; kept comment\r\n[update]\r\nenabled = no\r\n";
    WriteFile(h, k, sizeof(k) - 1, &got, NULL);
  }
  CloseHandle(h);

  sd_settings_defaults(&s);
  ui_settings_from_sd(&s, &m);
  m.notify = 0;
  m.default_backend = SD_PROFILE_BACKEND_DOKANY;
  m.cache_mb = 256;
  strcpy_s(m.language, sizeof(m.language), "de");
  ui_settings_to_sd(&m, &s);
  SD_CHECK(sd_settings_save(&s) == SD_OK);

  h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(h, text, sizeof(text) - 1, &got, NULL));
  CloseHandle(h);
  len = got;
  text[len] = '\0';
  SD_CHECK(strstr(text, "[update]") != NULL);
  SD_CHECK(strstr(text, "enabled = no") != NULL);
  SD_CHECK(strstr(text, "kept comment") != NULL);

  SD_CHECK(sd_settings_load(&back) == SD_OK);
  ui_settings_from_sd(&back, &m2);
  SD_CHECK_STR(m2.language, "de");
  SD_CHECK_EQ_INT(m2.notify, 0);
  SD_CHECK_EQ_INT(m2.default_backend, SD_PROFILE_BACKEND_DOKANY);
  SD_CHECK_EQ_INT((int)m2.cache_mb, 256);

  /* the system default removes the [ui] language key */
  m2.language[0] = '\0';
  sd_settings_defaults(&back);
  ui_settings_from_sd(&back, &m);
  ui_settings_to_sd(&m, &back);
  SD_CHECK(sd_settings_save(&back) == SD_OK);
  SD_CHECK(sd_settings_load(&back) == SD_OK);
  SD_CHECK_STR(back.ui_language, "");

  sd_config_set_root_override(NULL);
  remove_tree(root);
}

SD_TEST(settings_cache_budget_parsing)
{
  unsigned mb = 99;
  SD_CHECK(ui_settings_parse_cache(L"0", &mb) == SD_OK && mb == 0);
  SD_CHECK(ui_settings_parse_cache(L"16", &mb) == SD_OK && mb == 16);
  SD_CHECK(ui_settings_parse_cache(L" 65536 ", &mb) == SD_OK && mb == 65536);
  SD_CHECK(ui_settings_parse_cache(L"15", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(L"65537", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(L"12a", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(L"", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(L"-4", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(L"99999999999999999999", &mb) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_parse_cache(NULL, &mb) == SD_E_INVALID_PARAM);
}

SD_TEST(settings_language_index_and_run_command)
{
  wchar_t cmd[256];
  SD_CHECK_EQ_INT(ui_settings_lang_index(""), 0);
  SD_CHECK_EQ_INT(ui_settings_lang_index("en"), 1);
  SD_CHECK_EQ_INT(ui_settings_lang_index("pt-BR"), 4);
  SD_CHECK_EQ_INT(ui_settings_lang_index("DE"), 6);
  SD_CHECK_EQ_INT(ui_settings_lang_index("xx"), 0);
  SD_CHECK_EQ_INT(ui_settings_lang_index(NULL), 0);

  SD_CHECK(ui_settings_run_command(L"C:\\Program Files\\ShellDrive\\shelldrive-ui.exe", cmd, SD_COUNTOF(cmd)) ==
           SD_OK);
  SD_CHECK(wcscmp(cmd, L"\"C:\\Program Files\\ShellDrive\\shelldrive-ui.exe\" --tray") == 0);
  SD_CHECK(ui_settings_run_command(L"C:\\x\"y.exe", cmd, SD_COUNTOF(cmd)) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_settings_run_command(L"C:\\x.exe", cmd, 4) == SD_E_NAME_TOO_LONG);
}
