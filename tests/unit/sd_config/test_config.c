/* sd_config: sd_ini grammar and round trip (03 §3.3), profile model (3.4.1), host specs, files. */
#include <windows.h>
#include <string.h>

#include <aclapi.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "sd_base/sd_mem.h"

static sd_ini *parse_s(const char *s, uint32_t *flags)
{
  sd_ini *ini = NULL;
  if (sd_ini_parse(s, strlen(s), &ini, flags) != SD_OK)
    return NULL;
  return ini;
}

static char *ser(const sd_ini *ini)
{
  sd_wr w;
  char *out;
  sd_wr_init(&w, 1 << 20);
  if (sd_ini_serialize(ini, &w) != SD_OK) { sd_wr_free(&w); return NULL; }
  out = (char *)sd_alloc(w.len + 1);
  if (out) { memcpy(out, w.p, w.len); out[w.len] = 0; }
  sd_wr_free(&w);
  return out;
}

SD_TEST(ini_parses_grammar)
{
  static const char text[] =
    "\xef\xbb\xbf; leading comment\r\n"
    "[profile]\r\n"
    "format = 1\r\n"
    "name = Web server   ; display name\r\n"
    "host=example.org\r\n"
    "path = C:\\Users\\me\\x;y\r\n"
    "quoted = \"  keep  \\\"spaces\\\" \\\\ \\n end \"  # trailing\r\n"
    "empty =\r\n"
    "\r\n"
    "# another comment\r\n"
    "[mount]\r\n"
    "read_only = yes\r\n"
    "Bad Key = 1\r\n"
    "[unknown.section-x]\r\n"
    "future_key = v\r\n";
  uint32_t flags = 0;
  sd_ini *ini = parse_s(text, &flags);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(flags & SD_INI_F_INVALID_LINES);
  SD_CHECK(!(flags & SD_INI_F_ANSI_DECODED));
  SD_CHECK_STR(sd_ini_get(ini, "profile", "format"), "1");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "name"), "Web server");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "host"), "example.org");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "path"), "C:\\Users\\me\\x;y");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "quoted"), "  keep  \"spaces\" \\ \n end ");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "empty"), "");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "read_only"), "yes");
  SD_CHECK_STR(sd_ini_get(ini, "unknown.section-x", "future_key"), "v");
  SD_CHECK(sd_ini_get(ini, "mount", "Bad Key") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "host") == NULL);
  sd_ini_free(ini);
}

SD_TEST(ini_round_trip_preserves_everything)
{
  static const char text[] =
    "; header comment\r\n"
    "[profile]\r\n"
    "name = Web   ; keep me\r\n"
    "x.custom = 42\r\n"
    "\r\n"
    "[other]\r\n"
    "k = v\r\n"
    "this line is not ini\r\n";
  sd_ini *ini = parse_s(text, NULL);
  char *out;
  SD_REQUIRE(ini != NULL);
  out = ser(ini);
  SD_REQUIRE(out != NULL);
  SD_CHECK_STR(out, text);                    /* untouched documents serialize byte-identically */
  sd_free(out);
  SD_CHECK(sd_ini_set(ini, "profile", "name", "New name") == SD_OK);
  SD_CHECK(sd_ini_set(ini, "profile", "host", "h.example") == SD_OK);    /* appended to the section */
  SD_CHECK(sd_ini_set(ini, "mount", "target", "Z:") == SD_OK);           /* new section at the end */
  SD_CHECK(sd_ini_set(ini, "other", "spaced", " a ; b ") == SD_OK);       /* needs quotes */
  out = ser(ini);
  SD_REQUIRE(out != NULL);
  SD_CHECK(strstr(out, "name = New name   ; keep me\r\n") != NULL);      /* inline comment kept */
  SD_CHECK(strstr(out, "x.custom = 42\r\nhost = h.example\r\n\r\n[other]") != NULL);
  SD_CHECK(strstr(out, "this line is not ini\r\n") != NULL);
  SD_CHECK(strstr(out, "\r\n[mount]\r\ntarget = Z:\r\n") != NULL);
  SD_CHECK(strstr(out, "spaced = \" a ; b \"") != NULL);
  sd_ini_free(ini);
  ini = parse_s(out, NULL);
  SD_REQUIRE(ini != NULL);
  SD_CHECK_STR(sd_ini_get(ini, "other", "spaced"), " a ; b ");
  SD_CHECK_STR(sd_ini_get(ini, "profile", "x.custom"), "42");
  SD_CHECK(sd_ini_remove(ini, "profile", "x.custom") == SD_OK);
  SD_CHECK(sd_ini_remove(ini, "profile", "x.custom") == SD_E_NOT_FOUND);
  SD_CHECK(sd_ini_get(ini, "profile", "x.custom") == NULL);
  SD_CHECK(sd_ini_set(ini, "Bad", "k", "v") == SD_E_INVALID_PARAM);
  SD_CHECK(sd_ini_set(ini, "ok", "K", "v") == SD_E_INVALID_PARAM);
  SD_CHECK(sd_ini_set(ini, "ok", "k", "\xff") == SD_E_INVALID_PARAM);
  sd_ini_free(ini);
  sd_free(out);
}

SD_TEST(ini_duplicates_ansi_and_limits)
{
  uint32_t flags = 0;
  sd_ini *ini = parse_s("[a]\nk = first\nk = second\n", &flags);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(flags & SD_INI_F_DUPLICATE_KEYS);
  SD_CHECK_STR(sd_ini_get(ini, "a", "k"), "first");
  sd_ini_free(ini);
  /* Windows-1252 "é" (0xE9) is not UTF-8: decoded with the ANSI code page */
  ini = parse_s("[a]\nname = Caf\xe9\n", &flags);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(flags & SD_INI_F_ANSI_DECODED);
  SD_CHECK(sd_ini_get(ini, "a", "name") != NULL);
  sd_ini_free(ini);
  {
    sd_ini *x = NULL;
    SD_CHECK(sd_ini_parse("[a]\nk = a\0b\n", 12, &x, NULL) == SD_E_INVALID_PARAM);   /* embedded NUL */
    SD_CHECK(x == NULL);
  }
}

SD_TEST(ini_value_helpers)
{
  int b = -1;
  uint32_t u = 0;
  uint64_t z = 0;
  SD_CHECK(sd_ini_parse_bool("Yes", &b) && b == 1);
  SD_CHECK(sd_ini_parse_bool("0", &b) && b == 0);
  SD_CHECK(!sd_ini_parse_bool("maybe", &b));
  SD_CHECK(sd_ini_parse_u32("65535", &u) && u == 65535);
  SD_CHECK(!sd_ini_parse_u32("4294967296", &u));
  SD_CHECK(!sd_ini_parse_u32("12a", &u));
  SD_CHECK(sd_ini_parse_duration_ms("30s", &u) && u == 30000);
  SD_CHECK(sd_ini_parse_duration_ms("250ms", &u) && u == 250);
  SD_CHECK(sd_ini_parse_duration_ms("2m", &u) && u == 120000);
  SD_CHECK(sd_ini_parse_duration_ms("1h", &u) && u == 3600000);
  SD_CHECK(sd_ini_parse_duration_ms("15", &u) && u == 15000);
  SD_CHECK(!sd_ini_parse_duration_ms("5d", &u));
  SD_CHECK(sd_ini_parse_size("8M", &z) && z == 8u * 1024 * 1024);
  SD_CHECK(sd_ini_parse_size("2G", &z) && z == 2ull * 1024 * 1024 * 1024);
  SD_CHECK(sd_ini_parse_size("0", &z) && z == 0);
  SD_CHECK(!sd_ini_parse_size("1T", &z));
}

SD_TEST(profile_from_and_to_ini)
{
  static const char text[] =
    "[profile]\nformat = 1\nid = 7f3c2a90d1e44b6c9a0e5b21c4d7f8aa\nname = Web server\nhost = example.org\n"
    "port = 2222\nuser = deploy\nremote_path = /var/www\nkeep.me = yes\n"
    "[auth]\nmethods = publickey, password\nidentity = ~\\.ssh\\id_ed25519\n"
    "[mount]\ntarget = W:\nread_only = yes\nsymlinks = hide\nwrite_mode = through\n";
  sd_ini *ini = parse_s(text, NULL);
  sd_profile p;
  const char *bad = "x";
  char *out;
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK(bad == NULL);
  SD_CHECK_STR(p.id, "7f3c2a90d1e44b6c9a0e5b21c4d7f8aa");
  SD_CHECK_STR(p.name, "Web server");
  SD_CHECK_STR(p.host, "example.org");
  SD_CHECK_EQ_INT(p.port, 2222);
  SD_CHECK_STR(p.user, "deploy");
  SD_CHECK_STR(p.remote_path, "/var/www");
  SD_CHECK_STR(p.identity, "~\\.ssh\\id_ed25519");
  SD_CHECK_EQ_INT(p.auth_methods, SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD);
  SD_CHECK_STR(p.target, "W:");
  SD_CHECK_EQ_INT(p.read_only, 1);
  SD_CHECK_EQ_INT(p.symlinks, SD_PROFILE_SYMLINKS_HIDE);
  SD_CHECK_EQ_INT(p.write_mode, SD_PROFILE_WRITE_THROUGH);
  p.port = 22;
  p.read_only = 0;
  SD_REQUIRE(sd_profile_to_ini(&p, &ini) == SD_OK);
  out = ser(ini);
  SD_REQUIRE(out != NULL);
  SD_CHECK(strstr(out, "port = 22\r\n") != NULL);
  SD_CHECK(strstr(out, "read_only = no\r\n") != NULL);
  SD_CHECK(strstr(out, "keep.me = yes\r\n") != NULL);           /* unknown key preserved */
  SD_CHECK(strstr(out, "methods = publickey, password\r\n") != NULL);
  sd_free(out);
  sd_ini_free(ini);
}

SD_TEST(profile_defaults_and_validation)
{
  sd_profile p;
  const char *bad = NULL;
  struct { const char *text; const char *key; } cases[] = {
    { "[profile]\nport = 22\n", "profile.host" },
    { "[profile]\nhost = a b\n", "profile.host" },
    { "[profile]\nhost = h\nport = 0\n", "profile.port" },
    { "[profile]\nhost = h\nport = 70000\n", "profile.port" },
    { "[profile]\nhost = h\nid = XYZ\n", "profile.id" },
    { "[profile]\nhost = h\nformat = 2\n", "profile.format" },
    { "[profile]\nhost = h\n[mount]\nsymlinks = reparse\n", "mount.symlinks" },
    { "[profile]\nhost = h\n[mount]\nwrite_mode = later\n", "mount.write_mode" },
    { "[profile]\nhost = h\n[mount]\ntarget = C:\\Mounts\\x\n", "mount.target" },
    { "[profile]\nhost = h\n[mount]\nread_only = perhaps\n", "mount.read_only" },
    { "[profile]\nhost = h\n[auth]\nmethods = magic\n", "auth.methods" },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(cases); i++) {
    sd_ini *ini = parse_s(cases[i].text, NULL);
    SD_REQUIRE(ini != NULL);
    bad = NULL;
    if (sd_profile_from_ini(ini, &p, &bad) != SD_E_INVALID_PARAM || bad == NULL || strcmp(bad, cases[i].key) != 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "case %u: expected %s, got %s", (unsigned)i, cases[i].key,
                   bad ? bad : "(ok)");
    sd_ini_free(ini);
  }
  {
    sd_ini *ini = parse_s("[profile]\nhost = only.example\n", NULL);
    SD_REQUIRE(ini != NULL);
    SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
    SD_CHECK_STR(p.name, "only.example");          /* name defaults to the host */
    SD_CHECK_EQ_INT(p.port, 22);
    SD_CHECK_STR(p.target, "auto");
    SD_CHECK_EQ_INT(p.symlinks, SD_PROFILE_SYMLINKS_FOLLOW_INSIDE);   /* D40 */
    SD_CHECK_EQ_INT(p.write_mode, SD_PROFILE_WRITE_THROUGH);           /* D9 */
    SD_CHECK_EQ_INT(p.read_only, 0);
    sd_ini_free(ini);
  }
}

SD_TEST(host_spec_and_letters)
{
  char user[64], host[128];
  uint16_t port;
  SD_CHECK(sd_parse_host_spec(L"alice@example.org:2222", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(user, "alice");
  SD_CHECK_STR(host, "example.org");
  SD_CHECK_EQ_INT(port, 2222);
  SD_CHECK(sd_parse_host_spec(L"example.org", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(user, "");
  SD_CHECK_EQ_INT(port, 22);
  SD_CHECK(sd_parse_host_spec(L"bob@[::1]:2200", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(host, "::1");
  SD_CHECK_EQ_INT(port, 2200);
  SD_CHECK(sd_parse_host_spec(L"fe80::1", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(host, "fe80::1");
  SD_CHECK_EQ_INT(port, 22);
  SD_CHECK(sd_parse_host_spec(L"a@b@host", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(user, "a@b");
  SD_CHECK(sd_parse_host_spec(L"j\x00fcrgen@h\x00f6st", user, sizeof(user), host, sizeof(host), &port) == SD_OK);
  SD_CHECK_STR(user, "j\xc3\xbcrgen");
  SD_CHECK(sd_parse_host_spec(L"host:0", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"host:65536", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"host:", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"@host", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"user@", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"bad host", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_host_spec(L"[::1", user, sizeof(user), host, sizeof(host), &port) != SD_OK);
  SD_CHECK(sd_parse_drive_letter(L"z:") == L'Z');
  SD_CHECK(sd_parse_drive_letter(L"Q:\\") == L'Q');
  SD_CHECK(sd_parse_drive_letter(L"QQ:") == 0);
  SD_CHECK(sd_parse_drive_letter(L"Q") == 0);
  SD_CHECK(sd_parse_drive_letter(L"1:") == 0);
}

/* ---- files under a temporary root ---- */

static void temp_root(wchar_t *out, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  unsigned pid = (unsigned)GetCurrentProcessId(), t = 0;
  wchar_t num[16];
  out[0] = 0;
  if (n == 0 || n > MAX_PATH - 40) return;
  wcscpy_s(out, cch, tmp);
  wcscat_s(out, cch, L"sd-test-config-");
  do { num[t++] = (wchar_t)(L'0' + pid % 10); pid /= 10; } while (pid);
  {
    wchar_t r[16];
    unsigned k = 0;
    while (t) r[k++] = num[--t];
    r[k] = 0;
    wcscat_s(out, cch, r);
  }
}

static int count_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  SD_UNUSED(p);
  SD_UNUSED(path);
  (*(int *)ctx)++;
  return 1;
}

static void remove_tree(const wchar_t *root)
{
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  wcscpy_s(pattern, MAX_PATH, root);
  wcscat_s(pattern, MAX_PATH, L"\\*");
  f = FindFirstFileExW(pattern, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  if (f != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
      wcscpy_s(path, MAX_PATH, root);
      wcscat_s(path, MAX_PATH, L"\\");
      wcscat_s(path, MAX_PATH, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(path);
      else DeleteFileW(path);
    } while (FindNextFileW(f, &fd));
    FindClose(f);
  }
  RemoveDirectoryW(root);
}

SD_TEST(profile_files_save_find_enum_delete)
{
  wchar_t root[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
  static sd_profile p, q;              /* profiles are big: keep the test off the stack */
  int n = 0;
  temp_root(root, SD_COUNTOF(root));
  SD_REQUIRE(root[0] != 0);
  remove_tree(root);
  sd_config_set_root_override(root);
  SD_REQUIRE(sd_config_ensure_dirs() == SD_OK);
  SD_REQUIRE(sd_config_profiles_dir(dir, SD_COUNTOF(dir)) == SD_OK);
  SD_CHECK(GetFileAttributesW(dir) & FILE_ATTRIBUTE_DIRECTORY);
  sd_profile_defaults(&p);
  strcpy_s(p.name, sizeof(p.name), "Web Server");
  strcpy_s(p.host, sizeof(p.host), "example.org");
  strcpy_s(p.user, sizeof(p.user), "deploy");
  SD_REQUIRE(sd_profile_save(&p) == SD_OK);
  SD_CHECK_EQ_U64(strlen(p.id), 32);
  SD_REQUIRE(sd_profile_find("web server", &q, path, SD_COUNTOF(path)) == SD_OK);   /* case-insensitive */
  SD_CHECK_STR(q.id, p.id);
  SD_CHECK(wcsstr(path, L"\\profiles\\web-server.ini") != NULL);
  SD_REQUIRE(sd_profile_find(p.id, &q, NULL, 0) == SD_OK);
  /* a second profile with the same name slug gets another file name */
  {
    static sd_profile r;               /* keep the test under the analysis stack budget */
    sd_profile_defaults(&r);
    strcpy_s(r.name, sizeof(r.name), "web-server");
    strcpy_s(r.host, sizeof(r.host), "other.example");
    SD_REQUIRE(sd_profile_save(&r) == SD_OK);
  }
  SD_CHECK(sd_profile_enum(count_cb, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 2);
  /* update keeps the file and its unknown keys */
  {
    HANDLE h;
    DWORD put;
    static const char extra[] = "\r\n[future]\r\nkey = kept\r\n";
    h = CreateFileW(path, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SD_REQUIRE(h != INVALID_HANDLE_VALUE);
    WriteFile(h, extra, sizeof(extra) - 1, &put, NULL);
    CloseHandle(h);
    q.port = 2022;
    SD_REQUIRE(sd_profile_save(&q) == SD_OK);
    SD_REQUIRE(sd_profile_find(p.id, &q, NULL, 0) == SD_OK);
    SD_CHECK_EQ_INT(q.port, 2022);
    {
      static char buf[4096];
      DWORD got = 0;
      h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
      SD_REQUIRE(h != INVALID_HANDLE_VALUE);
      if (!ReadFile(h, buf, sizeof(buf) - 1, &got, NULL))
        got = 0;
      CloseHandle(h);
      buf[got] = 0;
      SD_CHECK(strstr(buf, "[future]\r\nkey = kept") != NULL);
    }
  }
  SD_CHECK(sd_profile_delete("Web Server") == SD_OK);
  SD_CHECK(sd_profile_find("Web Server", &q, NULL, 0) == SD_E_NOT_FOUND);
  {
    HANDLE lock = NULL, lock2 = NULL;
    SD_REQUIRE(sd_config_lock(&lock, 1000) == SD_OK);
    SD_CHECK(sd_config_lock(&lock2, 100) == SD_E_TIMEOUT);
    sd_config_unlock(lock);
  }
  sd_config_set_root_override(NULL);
  remove_tree(root);
}

SD_TEST(config_paths_and_expansion)
{
  wchar_t root[MAX_PATH], out[MAX_PATH], prof[MAX_PATH];
  sd_config_set_root_override(NULL);
  SD_REQUIRE(sd_config_root(root, SD_COUNTOF(root)) == SD_OK);
  SD_CHECK(wcsstr(root, L"\\LibreStatic\\ShellDrive") != NULL);           /* D45 */
  SD_REQUIRE(sd_config_expand_path("~\\.ssh\\id_ed25519", out, SD_COUNTOF(out)) == SD_OK);
  SD_CHECK(GetEnvironmentVariableW(L"USERPROFILE", prof, MAX_PATH) > 0);
  SD_CHECK(wcsncmp(out, prof, wcslen(prof)) == 0);
  SD_CHECK(wcsstr(out, L"\\.ssh\\id_ed25519") != NULL);
  SD_REQUIRE(sd_config_expand_path("%SystemRoot%\\x", out, SD_COUNTOF(out)) == SD_OK);
  SD_CHECK(out[0] != L'%');
}

SD_TEST(profile_m1_keys)
{
  static const char text[] =
    "[profile]\r\nhost = h.test\r\n"
    "[mount]\r\nbackend = webdav\r\noffline_wait = 5s\r\nreconnect_grace = 2m\r\n"
    "[cache]\r\ndisk = 512M\r\n"
    "[connection]\r\nchannels = 1\r\n";
  sd_ini *ini = parse_s(text, NULL), *out = NULL;
  static sd_profile p, q;              /* keep the test under the analysis stack budget */
  const char *bad = NULL;
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK_EQ_INT(p.backend, SD_PROFILE_BACKEND_WEBDAV);
  SD_CHECK_EQ_INT(p.offline_wait_ms, 5000);
  SD_CHECK_EQ_INT(p.reconnect_grace_ms, 120000);
  SD_CHECK_EQ_INT(p.disk_cache_mb, 512);
  SD_CHECK_EQ_INT(p.channels, 1);
  SD_REQUIRE(sd_profile_to_ini(&p, &out) == SD_OK);
  SD_REQUIRE(sd_profile_from_ini(out, &q, &bad) == SD_OK);
  SD_CHECK_EQ_INT(q.backend, SD_PROFILE_BACKEND_WEBDAV);
  SD_CHECK_EQ_INT(q.offline_wait_ms, 5000);
  SD_CHECK_EQ_INT(q.reconnect_grace_ms, 120000);
  SD_CHECK_EQ_INT(q.disk_cache_mb, 512);
  SD_CHECK_EQ_INT(q.channels, 1);
  sd_ini_free(out);
  sd_ini_free(ini);
  /* defaults are not written into a new file; bad values name the key */
  sd_profile_defaults(&p);
  SD_CHECK_EQ_INT(p.backend, SD_PROFILE_BACKEND_AUTO);
  SD_CHECK_EQ_INT(p.channels, 2);
  {
    sd_ini *d = NULL;
    memcpy(p.host, "h.test", 7);
    memcpy(p.name, "h.test", 7);
    SD_REQUIRE(sd_profile_to_ini(&p, &d) == SD_OK);
    SD_CHECK(sd_ini_get(d, "mount", "backend") == NULL);
    SD_CHECK(sd_ini_get(d, "cache", "disk") == NULL);
    SD_CHECK(sd_ini_get(d, "connection", "channels") == NULL);
    sd_ini_free(d);
  }
  ini = parse_s("[profile]\r\nhost = h.test\r\n[mount]\r\nbackend = smb\r\n", NULL);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_profile_from_ini(ini, &p, &bad) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(bad, "mount.backend");
  sd_ini_free(ini);
  ini = parse_s("[profile]\r\nhost = h.test\r\n[connection]\r\nchannels = 3\r\n", NULL);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_profile_from_ini(ini, &p, &bad) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(bad, "connection.channels");
  sd_ini_free(ini);
}

SD_TEST(settings_log_level_and_cache_memory)
{
  sd_settings s;
  sd_ini *ini = parse_s("[log]\r\nlevel = debug\r\n[cache]\r\nmemory = 64M\r\n", NULL);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_OK);
  SD_CHECK_EQ_INT(s.log_level, 3);
  SD_CHECK(s.cache_memory == (UINT64)64 << 20);
  sd_ini_free(ini);
  ini = parse_s("[log]\r\nlevel = loud\r\n", NULL);
  SD_REQUIRE(ini != NULL);
  SD_CHECK(sd_settings_from_ini(ini, &s) == SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(s.log_level, 2);              /* invalid value keeps the default */
  sd_ini_free(ini);
}

SD_TEST(cache_dir_and_identity_cache)
{
  wchar_t root[MAX_PATH], dir[MAX_PATH], dir2[MAX_PATH];
  uint32_t uid = 0, gid = 0;
  PSECURITY_DESCRIPTOR sd = NULL;
  PACL dacl = NULL;
  SECURITY_DESCRIPTOR_CONTROL ctl = 0;
  DWORD rev = 0;
  temp_root(root, SD_COUNTOF(root));
  SD_REQUIRE(root[0] != 0);
  remove_tree(root);
  sd_config_set_root_override(root);
  SD_REQUIRE(sd_config_cache_dir("alice@h.test:22", dir, SD_COUNTOF(dir)) == SD_OK);
  SD_CHECK(wcsstr(dir, L"\\cache\\") != NULL);
  SD_CHECK_EQ_INT((int)wcslen(wcsrchr(dir, L'\\') + 1), 16);
  SD_CHECK((GetFileAttributesW(dir) & FILE_ATTRIBUTE_DIRECTORY) != 0 && GetFileAttributesW(dir) != INVALID_FILE_ATTRIBUTES);
  /* the per-source folder carries the protected DACL (TM-R07, the disk tier refuses anything else) */
  SD_CHECK(GetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) ==
           ERROR_SUCCESS);
  SD_CHECK(sd && GetSecurityDescriptorControl(sd, &ctl, &rev) && (ctl & SE_DACL_PROTECTED));
  if (sd) LocalFree(sd);
  SD_REQUIRE(sd_config_cache_dir("bob@h.test:22", dir2, SD_COUNTOF(dir2)) == SD_OK);
  SD_CHECK(wcscmp(dir, dir2) != 0);
  SD_CHECK(sd_config_identity_load(dir, "SHA256:abc", &uid, &gid) == SD_E_NOT_FOUND);
  SD_REQUIRE(sd_config_identity_store(dir, "SHA256:abc", 1000, 1001) == SD_OK);
  SD_CHECK(sd_config_identity_load(dir, "SHA256:abc", &uid, &gid) == SD_OK);
  SD_CHECK_EQ_INT(uid, 1000);
  SD_CHECK_EQ_INT(gid, 1001);
  SD_CHECK(sd_config_identity_load(dir, "SHA256:other", &uid, &gid) == SD_E_NOT_FOUND);   /* new host key */
  SD_CHECK(sd_config_identity_load(dir2, "SHA256:abc", &uid, &gid) == SD_E_NOT_FOUND);
  sd_config_set_root_override(NULL);
  remove_tree(root);
}
