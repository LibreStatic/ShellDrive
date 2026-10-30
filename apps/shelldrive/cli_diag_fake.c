/* Test fake of the diag seam (cli_diag.c, diag_env). Compiled only with SD_CLI_TEST_HOOKS (tests/apps); the
 * shipping shelldrive.exe contains nothing from this file. The state of the fake machine is a text file of the
 * test (SHELLDRIVE_TEST_DIAG_FAKE), one key=value per line; every change rewrites that file, so the test can
 * read what "diag --fix" did. Keys: webclient (running, stopped, disabled, missing, unknown), webclient_start
 * (number or none), size, attr, auth (numbers or none), linked (number or none), dokany, split, w32, domain
 * (0 or 1) and drives (decimal drive mask). A missing key reads as not set.
 * Round 19: dokany_version (x.y.z, absent = not installed), dokany_deny ("x.y.z-a.b.c reason-id", absent = none),
 * menu (0 or 1), netloc (comma or blank separated ids of our Network location entries; absent or none = the
 * NetHood folder is unknown), netloc_wanted (ids that want one), setup_dir (folder of the setup logs; absent = none). */
#include <windows.h>
#include <stdio.h>
#include "cli_diag_rules.h"
#include <string.h>

#include "cli_diag.h"

/* Keeps the translation unit non-empty in the shipping build (C4206 under /W4). */
typedef int cli_diag_fake_unit;

#ifdef SD_CLI_TEST_HOOKS

#define FAKE_MAX 4096u

static int fake_read(char *buf, size_t cap)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  DWORD got = 0;
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", path, MAX_PATH) - 1u >= MAX_PATH - 1u)
    return 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    buf[0] = 0;
    return 1;
  }
  if (!ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL))
    got = 0;
  CloseHandle(h);
  buf[got] = 0;
  return 1;
}

/* Value of key (the text after "key="), or NULL. */
static const char *fake_find(const char *text, const char *key, char *tmp, size_t cap)
{
  size_t k = strlen(key), i = 0;
  while (text[i]) {
    size_t e = i;
    while (text[e] && text[e] != '\n') e++;
    if (e - i > k + 1 && strncmp(text + i, key, k) == 0 && text[i + k] == '=') {
      size_t n = e - (i + k + 1);
      if (n && text[e - 1] == '\r') n--;
      if (n >= cap) n = cap - 1;
      memcpy(tmp, text + i + k + 1, n);
      tmp[n] = 0;
      return tmp;
    }
    i = text[e] ? e + 1 : e;
  }
  return NULL;
}

static DWORD fake_num(const char *v)
{
  DWORD n = 0;
  if (v == NULL || strcmp(v, "none") == 0 || v[0] == 0)
    return DIAG_NOT_SET;
  while (*v >= '0' && *v <= '9') {
    n = n * 10u + (DWORD)(*v - '0');
    v++;
  }
  return n;
}

static int fake_get(const char *key, char *tmp, size_t cap, const char **out)
{
  char text[FAKE_MAX];
  if (!fake_read(text, sizeof(text)))
    return 0;
  *out = fake_find(text, key, tmp, cap);
  return 1;
}

static DWORD fake_num_of(const char *key)
{
  char tmp[64];
  const char *v = NULL;
  if (!fake_get(key, tmp, sizeof(tmp), &v) || v == NULL)
    return DIAG_NOT_SET;
  return fake_num(v);
}

static int fake_flag(const char *key)
{
  return fake_num_of(key) == 1;
}

/* Rewrites the file with key set to value (appended when absent). */
static DWORD fake_set(const char *key, const char *value)
{
  char text[FAKE_MAX], out[FAKE_MAX + 64];
  wchar_t path[MAX_PATH];
  char line[80];
  size_t k = strlen(key), i = 0, o = 0;
  int replaced = 0;
  HANDLE h;
  DWORD wrote = 0;
  if (!fake_read(text, sizeof(text)))
    return ERROR_INVALID_PARAMETER;
  sprintf_s(line, sizeof(line), "%s=%s\r\n", key, value);
  while (text[i]) {
    size_t e = i;
    while (text[e] && text[e] != '\n') e++;
    if (e - i > k && strncmp(text + i, key, k) == 0 && text[i + k] == '=') {
      memcpy(out + o, line, strlen(line));
      o += strlen(line);
      replaced = 1;
    } else {
      size_t len = (text[e] ? e + 1 : e) - i;
      if (o + len >= sizeof(out)) return ERROR_INVALID_PARAMETER;
      memcpy(out + o, text + i, len);
      o += len;
    }
    i = text[e] ? e + 1 : e;
  }
  if (!replaced) {
    if (o + strlen(line) >= sizeof(out)) return ERROR_INVALID_PARAMETER;
    memcpy(out + o, line, strlen(line));
    o += strlen(line);
  }
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", path, MAX_PATH) - 1u >= MAX_PATH - 1u)
    return ERROR_INVALID_PARAMETER;
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError();
  if (!WriteFile(h, out, (DWORD)o, &wrote, NULL) || wrote != (DWORD)o) {
    DWORD e = GetLastError();
    CloseHandle(h);
    return e ? e : ERROR_WRITE_FAULT;
  }
  CloseHandle(h);
  return 0;
}

static diag_wc_state f_webclient_state(void *ctx, DWORD *start_type)
{
  char tmp[32];
  const char *v = NULL;
  (void)ctx;
  *start_type = fake_num_of("webclient_start");
  if (!fake_get("webclient", tmp, sizeof(tmp), &v) || v == NULL)
    return DIAG_WC_MISSING;
  if (strcmp(v, "running") == 0) return DIAG_WC_RUNNING;
  if (strcmp(v, "stopped") == 0) return DIAG_WC_STOPPED;
  if (strcmp(v, "disabled") == 0) return DIAG_WC_DISABLED;
  if (strcmp(v, "missing") == 0) return DIAG_WC_MISSING;
  return DIAG_WC_UNKNOWN;
}

/* A WebDAV limit of the fake: the number of the key, -1 when absent (64-bit, as the seam). */
static __int64 fake_limit_of(const char *key)
{
  char tmp[64];
  const char *v = NULL;
  __int64 n = 0;
  if (!fake_get(key, tmp, sizeof(tmp), &v) || v == NULL || v[0] == 0 || strcmp(v, "none") == 0)
    return -1;
  while (*v >= '0' && *v <= '9') {
    n = n * 10 + (*v - '0');
    v++;
  }
  return n;
}

static __int64 f_webdav_value(void *ctx, int which)
{
  (void)ctx;
  if (which == DIAG_WEBDAV_FILE_SIZE) return fake_limit_of("size");
  if (which == DIAG_WEBDAV_FILE_ATTRIBUTES) return fake_limit_of("attr");
  return fake_limit_of("auth");
}

static DWORD f_linked(void *ctx)
{
  (void)ctx;
  return fake_num_of("linked");
}

static int f_dokany(void *ctx) { (void)ctx; return fake_flag("dokany"); }
static int f_split(void *ctx) { (void)ctx; return fake_flag("split"); }

/* The fake grants elevation only through its own key (absent = not elevated), and the existing test seam
   SHELLDRIVE_TEST_ELEVATED=0 still denies it first, as in the real cli_is_elevated. */
static int f_elevated(void *ctx)
{
  wchar_t v[4];
  (void)ctx;
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", v, SD_COUNTOF(v)) == 1 && v[0] == L'0')
    return 0;
  return fake_flag("elevated");
}
static int f_w32(void *ctx) { (void)ctx; return fake_flag("w32"); }
static int f_domain(void *ctx) { (void)ctx; return fake_flag("domain"); }

static DWORD f_drives(void *ctx)
{
  DWORD m = fake_num_of("drives");
  (void)ctx;
  return m == DIAG_NOT_SET ? 0 : m;
}

static DWORD f_set_start(void *ctx, DWORD start_type)
{
  char v[16];
  (void)ctx;
  sprintf_s(v, sizeof(v), "%lu", (unsigned long)start_type);
  return fake_set("webclient_start", v);
}

/* the service comes up when it is started (the fake does not wait) */
static DWORD f_start(void *ctx)
{
  (void)ctx;
  return fake_set("webclient", "running");
}

static DWORD f_linked_set(void *ctx, DWORD value)
{
  char v[16];
  (void)ctx;
  sprintf_s(v, sizeof(v), "%lu", (unsigned long)value);
  return fake_set("linked", v);
}

static DWORD f_dokany_version(void *ctx)
{
  char tmp[32];
  const char *v = NULL;
  (void)ctx;
  if (!fake_get("dokany_version", tmp, sizeof(tmp), &v) || v == NULL || v[0] == 0 || strcmp(v, "none") == 0)
    return 0;
  return diag_version_parse(v, strlen(v));
}

static int f_menu(void *ctx) { (void)ctx; return fake_flag("menu"); }

/* A token list of the fake: -1 when the key is absent or none, else the value copied into out. */
static int fake_list(const char *key, char *out, size_t cap)
{
  char tmp[1024];
  const char *v = NULL;
  out[0] = 0;
  if (!fake_get(key, tmp, sizeof(tmp), &v) || v == NULL || strcmp(v, "none") == 0)
    return -1;
  strncpy_s(out, cap, v, _TRUNCATE);
  return 0;
}

static int f_netloc_entries(void *ctx, char *out, size_t cap)
{
  (void)ctx;
  return fake_list("netloc", out, cap);
}

static int f_netloc_wanted(void *ctx, char *out, size_t cap)
{
  (void)ctx;
  if (fake_list("netloc_wanted", out, cap) != 0)
    out[0] = 0;
  return 0;
}

static int f_setup_dir(void *ctx, wchar_t *out, size_t cch)
{
  char tmp[MAX_PATH];
  const char *v = NULL;
  (void)ctx;
  if (!fake_get("setup_dir", tmp, sizeof(tmp), &v) || v == NULL || v[0] == 0 || strcmp(v, "none") == 0)
    return 0;
  _snwprintf_s(out, cch, _TRUNCATE, L"%S", v);
  return 1;
}

static int f_deny(void *ctx, diag_deny_list *out)
{
  char tmp[160], line[200];
  const char *v = NULL;
  (void)ctx;
  if (fake_get("dokany_deny", tmp, sizeof(tmp), &v) && v != NULL && v[0] != 0 && strcmp(v, "none") != 0) {
    sprintf_s(line, sizeof(line), "dokany-deny %s\n", v);
    diag_deny_parse(out, line, strlen(line));
  }
  return 0;
}

static const diag_env k_fake_env = {
  NULL,
  f_webclient_state, f_webdav_value, f_linked, f_dokany, f_split, f_elevated, f_w32, f_domain, f_drives,
  f_set_start, f_start, f_linked_set,
  f_dokany_version, f_menu, f_netloc_entries, f_netloc_wanted, f_setup_dir, f_deny
};

const diag_env *diag_env_fake(void)
{
  return &k_fake_env;
}

#endif /* SD_CLI_TEST_HOOKS */
