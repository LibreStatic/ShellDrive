/* sd_config M4 settings (03 §3.4 global settings, §7.7, §10.1): [defaults] write_mode, [log] privacy,
 * [agent] start_at_logon, [ui] notify_<kind> under the notify master; the effective write mode of a profile
 * (an absent mount.write_mode takes the default, ForceWriteThrough refuses an explicit behind); the LogPrivacy
 * policy override; the agent's Run value condition and the per-installation log key. Every file operation runs
 * under a temporary root (sd_config_set_root_override), never the real %APPDATA%. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"

static sd_ini *parse_text(const char *text)
{
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  if (sd_ini_parse(text, strlen(text), &ini, &flags) != SD_OK)
    return NULL;
  return ini;
}

static void temp_root_m4(wchar_t *out, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  out[0] = 0;
  if (n == 0 || n > MAX_PATH - 40)
    return;
  wcscpy_s(out, cch, tmp);
  {
    wchar_t num[64];
    swprintf_s(num, SD_COUNTOF(num), L"sd-test-config-m4-%lu-%llu", (unsigned long)GetCurrentProcessId(),
               (unsigned long long)sd_tick_ms());
    wcscat_s(out, cch, num);
  }
}

static void remove_tree_m4(const wchar_t *root)
{
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  wcscpy_s(pattern, MAX_PATH, root);
  wcscat_s(pattern, MAX_PATH, L"\\*");
  f = FindFirstFileW(pattern, &fd);
  if (f != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        continue;
      wcscpy_s(path, MAX_PATH, root);
      wcscat_s(path, MAX_PATH, L"\\");
      wcscat_s(path, MAX_PATH, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        remove_tree_m4(path);
      else
        DeleteFileW(path);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
  }
  RemoveDirectoryW(root);
}

SD_TEST(settings_m4_defaults)
{
  sd_settings s;
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(s.default_write_mode, SD_PROFILE_WRITE_THROUGH);     /* D9 */
  SD_CHECK_EQ_INT(s.log_privacy, SD_SETTINGS_PRIVACY_STANDARD);
  SD_CHECK_EQ_INT(s.agent_start_at_logon, 0);
  SD_CHECK_EQ_INT(s.notify, 1);
  /* 03 §7.7 defaults: mounted and the pool limit are off, the rest on */
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_CONNECTION_LOST], 1);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_MOUNTED], 0);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_POOL_LIMITED], 0);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_TERRAPIN], 1);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_DISK_CACHE], 1);
}

SD_TEST(settings_ui_tier_keys)
{
  sd_settings s;
  sd_ini *ini;
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(s.ui_style, SD_SETTINGS_STYLE_AUTO);              /* 06 5.3 */
  SD_CHECK_EQ_INT(s.ui_dark_helpers, 1);                            /* 06 3.6 */
  ini = parse_text("[ui]\r\nstyle = classic\r\ndark_helpers = off\r\n");
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_OK);
  SD_CHECK_EQ_INT(s.ui_style, SD_SETTINGS_STYLE_CLASSIC);
  SD_CHECK_EQ_INT(s.ui_dark_helpers, 0);
  sd_ini_free(ini);
  ini = parse_text("[ui]\r\nstyle = auto\r\ndark_helpers = on\r\n");
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_OK);
  SD_CHECK_EQ_INT(s.ui_style, SD_SETTINGS_STYLE_AUTO);
  SD_CHECK_EQ_INT(s.ui_dark_helpers, 1);
  sd_ini_free(ini);
  /* invalid values are reported and keep the defaults */
  sd_settings_defaults(&s);
  ini = parse_text("[ui]\r\nstyle = fancy\r\ndark_helpers = sometimes\r\n");
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(s.ui_style, SD_SETTINGS_STYLE_AUTO);
  SD_CHECK_EQ_INT(s.ui_dark_helpers, 1);
  sd_ini_free(ini);
}

SD_TEST(settings_m4_parse_values)
{
  sd_settings s;
  sd_ini *ini;
  sd_settings_defaults(&s);
  ini = parse_text("[defaults]\r\nwrite_mode = behind\r\n[log]\r\nprivacy = strict\r\n"
                   "[agent]\r\nstart_at_logon = yes\r\n[ui]\r\nnotify_mounted = yes\r\nnotify_terrapin = no\r\n");
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_OK);
  SD_CHECK_EQ_INT(s.default_write_mode, SD_PROFILE_WRITE_BEHIND);
  SD_CHECK_EQ_INT(s.log_privacy, SD_SETTINGS_PRIVACY_STRICT);
  SD_CHECK_EQ_INT(s.agent_start_at_logon, 1);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_MOUNTED], 1);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_TERRAPIN], 0);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_CONNECTION_LOST], 1);       /* untouched keys keep their default */
  sd_ini_free(ini);

  /* invalid values are reported, keep the default and do not disturb the valid keys */
  sd_settings_defaults(&s);
  ini = parse_text("[defaults]\r\nwrite_mode = later\r\n[log]\r\nprivacy = loud\r\n[agent]\r\nstart_at_logon = maybe\r\n"
                   "[ui]\r\nnotify_mounted = sometimes\r\nnotify_reconnected = no\r\n");
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(s.default_write_mode, SD_PROFILE_WRITE_THROUGH);
  SD_CHECK_EQ_INT(s.log_privacy, SD_SETTINGS_PRIVACY_STANDARD);
  SD_CHECK_EQ_INT(s.agent_start_at_logon, 0);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_MOUNTED], 0);
  SD_CHECK_EQ_INT(s.notify_kind[SD_NOTIFY_RECONNECTED], 0);
  sd_ini_free(ini);
}

SD_TEST(settings_m4_notify_kinds_and_codes)
{
  sd_settings s;
  sd_settings_defaults(&s);
  SD_CHECK(strcmp(sd_notify_kind_key(SD_NOTIFY_CONNECTION_LOST), "notify_connection_lost") == 0);
  SD_CHECK(strcmp(sd_notify_kind_key(SD_NOTIFY_HOSTKEYS_SOURCE), "notify_hostkeys_source") == 0);
  SD_CHECK(strcmp(sd_notify_kind_key(SD_NOTIFY_COUNT), "") == 0);

  SD_CHECK_EQ_INT(sd_notify_kind_from_code("legacy_algorithms"), SD_NOTIFY_LEGACY_ALGORITHMS);
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("terrapin_exposed"), SD_NOTIFY_TERRAPIN);
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("pool_limited"), SD_NOTIFY_POOL_LIMITED);
  /* the agent raises proxy_cleartext (03 §3.8); proxy_password is the older code: both are the proxy password kind */
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("proxy_cleartext"), SD_NOTIFY_PROXY_PASSWORD);
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("proxy_password"), SD_NOTIFY_PROXY_PASSWORD);
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("write_failed"), -1);       /* always shown: no switch */
  SD_CHECK_EQ_INT(sd_notify_kind_from_code(NULL), -1);

  /* the master switch gates every kind; a kind's own switch gates that kind only */
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, SD_NOTIFY_LEGACY_ALGORITHMS), 1);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, SD_NOTIFY_POOL_LIMITED), 0);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, -1), 1);
  s.notify_kind[SD_NOTIFY_LEGACY_ALGORITHMS] = 0;
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, SD_NOTIFY_LEGACY_ALGORITHMS), 0);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, SD_NOTIFY_TERRAPIN), 1);
  s.notify = 0;
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, SD_NOTIFY_TERRAPIN), 0);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, -1), 0);
}

SD_TEST(settings_m4_write_mode_resolution)
{
  static sd_profile p;
  sd_settings s;
  int mode = -1;
  sd_profile_defaults(&p);
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(p.write_mode_set, 0);

  /* an unset key takes the default; no default means through (D9) */
  SD_CHECK(sd_profile_effective_write_mode(&p, &s, 0, &mode) == SD_OK);
  SD_CHECK_EQ_INT(mode, SD_PROFILE_WRITE_THROUGH);
  s.default_write_mode = SD_PROFILE_WRITE_BEHIND;
  SD_CHECK(sd_profile_effective_write_mode(&p, &s, 0, &mode) == SD_OK);
  SD_CHECK_EQ_INT(mode, SD_PROFILE_WRITE_BEHIND);

  /* an explicit key wins over the default */
  p.write_mode = SD_PROFILE_WRITE_THROUGH;
  p.write_mode_set = 1;
  SD_CHECK(sd_profile_effective_write_mode(&p, &s, 0, &mode) == SD_OK);
  SD_CHECK_EQ_INT(mode, SD_PROFILE_WRITE_THROUGH);

  /* ForceWriteThrough: an explicit behind is refused, a default is clamped to through */
  p.write_mode = SD_PROFILE_WRITE_BEHIND;
  SD_CHECK(sd_profile_effective_write_mode(&p, &s, 1, &mode) == SD_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(mode, SD_PROFILE_WRITE_THROUGH);
  p.write_mode_set = 0;
  SD_CHECK(sd_profile_effective_write_mode(&p, &s, 1, &mode) == SD_OK);
  SD_CHECK_EQ_INT(mode, SD_PROFILE_WRITE_THROUGH);
  SD_CHECK(sd_profile_effective_write_mode(NULL, &s, 0, &mode) == SD_E_INVALID_PARAM);
}

SD_TEST(profile_m4_write_mode_key_round_trip)
{
  static sd_profile p, q;
  sd_ini *ini = NULL;
  const char *bad = NULL;
  sd_profile_defaults(&p);
  p.host[0] = 'h';
  p.host[1] = 0;
  /* an absent key stays absent when the profile is written back */
  SD_CHECK(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK(sd_ini_get(ini, "mount", "write_mode") == NULL);
  SD_CHECK(sd_profile_from_ini(ini, &q, &bad) == SD_OK);
  SD_CHECK_EQ_INT(q.write_mode_set, 0);
  sd_ini_free(ini);
  ini = NULL;

  /* an explicit value is written and read back as explicit */
  p.write_mode = SD_PROFILE_WRITE_BEHIND;
  p.write_mode_set = 1;
  SD_CHECK(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK(strcmp(sd_ini_get(ini, "mount", "write_mode"), "behind") == 0);
  SD_CHECK(sd_profile_from_ini(ini, &q, &bad) == SD_OK);
  SD_CHECK_EQ_INT(q.write_mode_set, 1);
  SD_CHECK_EQ_INT(q.write_mode, SD_PROFILE_WRITE_BEHIND);
  sd_ini_free(ini);
}

SD_TEST(settings_m4_privacy_policy_override)
{
  sd_settings s;
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(sd_settings_effective_privacy(&s, -1), SD_SETTINGS_PRIVACY_STANDARD);
  s.log_privacy = SD_SETTINGS_PRIVACY_STRICT;
  SD_CHECK_EQ_INT(sd_settings_effective_privacy(&s, -1), SD_SETTINGS_PRIVACY_STRICT);
  /* a set LogPrivacy policy overrides the file in both directions (03 §3.1) */
  SD_CHECK_EQ_INT(sd_settings_effective_privacy(&s, 0), SD_SETTINGS_PRIVACY_STANDARD);
  s.log_privacy = SD_SETTINGS_PRIVACY_STANDARD;
  SD_CHECK_EQ_INT(sd_settings_effective_privacy(&s, 1), SD_SETTINGS_PRIVACY_STRICT);
}

SD_TEST(settings_m4_save_round_trip_and_run_condition)
{
  wchar_t root[MAX_PATH], ini_path[MAX_PATH];
  sd_settings s, back;
  sd_settings_defaults(&s);
  temp_root_m4(root, SD_COUNTOF(root));
  SD_REQUIRE(root[0] != 0);
  remove_tree_m4(root);
  SD_REQUIRE(CreateDirectoryW(root, NULL));
  sd_config_set_root_override(root);

  /* a settings.ini with keys of other sections survives the save */
  wcscpy_s(ini_path, SD_COUNTOF(ini_path), root);
  wcscat_s(ini_path, SD_COUNTOF(ini_path), L"\\settings.ini");
  {
    static const char text[] = "; keep me\r\n[cache]\r\nmemory = 32M\r\n[mystery]\r\nkey = 1\r\n";
    HANDLE h = CreateFileW(ini_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD n = 0;
    SD_REQUIRE(h != INVALID_HANDLE_VALUE);
    SD_CHECK(WriteFile(h, text, (DWORD)(sizeof(text) - 1), &n, NULL));
    CloseHandle(h);
  }

  s.default_write_mode = SD_PROFILE_WRITE_BEHIND;
  s.cache_memory = (UINT64)32 << 20;
  s.log_privacy = SD_SETTINGS_PRIVACY_STRICT;
  s.agent_start_at_logon = 1;
  s.notify_kind[SD_NOTIFY_MOUNTED] = 1;
  s.notify_kind[SD_NOTIFY_POOL_LIMITED] = 0;
  s.notify_kind[SD_NOTIFY_HOSTKEYS_SOURCE] = 0;
  SD_CHECK(sd_settings_save(&s) == SD_OK);

  sd_settings_defaults(&back);
  SD_CHECK(sd_settings_load(&back) == SD_OK);
  SD_CHECK_EQ_INT(back.default_write_mode, SD_PROFILE_WRITE_BEHIND);
  SD_CHECK_EQ_INT(back.log_privacy, SD_SETTINGS_PRIVACY_STRICT);
  SD_CHECK_EQ_INT(back.agent_start_at_logon, 1);
  SD_CHECK_EQ_INT(back.notify_kind[SD_NOTIFY_MOUNTED], 1);
  SD_CHECK_EQ_INT(back.notify_kind[SD_NOTIFY_POOL_LIMITED], 0);
  SD_CHECK_EQ_INT(back.notify_kind[SD_NOTIFY_HOSTKEYS_SOURCE], 0);
  SD_CHECK(memcmp(back.notify_kind, s.notify_kind, sizeof(s.notify_kind)) == 0);
  SD_CHECK_EQ_INT(back.cache_memory, (UINT64)32 << 20);
  {
    HANDLE h = CreateFileW(ini_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    char buf[2048];
    DWORD n = 0;
    SD_REQUIRE(h != INVALID_HANDLE_VALUE);
    SD_CHECK(ReadFile(h, buf, sizeof(buf) - 1, &n, NULL));
    CloseHandle(h);
    buf[n] = 0;
    SD_CHECK(strstr(buf, "; keep me") != NULL);
    SD_CHECK(strstr(buf, "[mystery]") != NULL);
    SD_CHECK(strstr(buf, "write_mode = behind") != NULL);
    SD_CHECK(strstr(buf, "privacy = strict") != NULL);
    SD_CHECK(strstr(buf, "start_at_logon = yes") != NULL);
    SD_CHECK(strstr(buf, "notify_pool_limited = no") != NULL);
  }

  /* an invalid value is refused by the writer */
  s.default_write_mode = 7;
  SD_CHECK(sd_settings_save(&s) == SD_E_INVALID_PARAM);
  s.default_write_mode = SD_PROFILE_WRITE_BEHIND;

  /* the agent's Run value is wanted for start_at_logon, and for a profile with autostart = logon */
  SD_CHECK_EQ_INT(sd_settings_agent_run_wanted(&s), 1);
  s.agent_start_at_logon = 0;
  SD_CHECK_EQ_INT(sd_settings_agent_run_wanted(&s), 0);      /* no profiles in this root */
  {
    static sd_profile p;
    sd_profile_defaults(&p);
    strcpy_s(p.name, sizeof(p.name), "logon-test");
    strcpy_s(p.host, sizeof(p.host), "h.test");
    p.autostart = SD_PROFILE_AUTOSTART_LOGON;
    SD_CHECK(sd_profile_save(&p) == SD_OK);
    SD_CHECK_EQ_INT(sd_settings_agent_run_wanted(&s), 1);
    SD_CHECK(sd_profile_delete(p.id) == SD_OK);
  }

  /* the per-installation log key: created once, read back the same */
  {
    uint8_t k1[32], k2[32];
    SD_CHECK(sd_config_log_key(k1) == SD_OK);
    SD_CHECK(sd_config_log_key(k2) == SD_OK);
    SD_CHECK(memcmp(k1, k2, 32) == 0);
  }

  sd_config_set_root_override(NULL);
  remove_tree_m4(root);
}
