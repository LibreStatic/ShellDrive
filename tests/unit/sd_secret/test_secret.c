/* sd_secret: target names, Credential Manager round trips (under a test-only target prefix, removed
 * afterwards), DPAPI secret files, the XP Home fallback path (forced DPAPI), enumeration and key files. */
#include <windows.h>
#include <wincred.h>
#include <string.h>

#include "sd_test.h"
#include "sd_secret/sd_secret.h"
#include "sd_base/sd_mem.h"

static wchar_t g_dir[MAX_PATH];
static char g_prefix[64];

static void setup(int force_dpapi)
{
  sd_secret_config c;
  wchar_t num[16];
  DWORD pid = GetCurrentProcessId();
  int i = 0;
  char p[16];
  GetTempPathW(MAX_PATH, g_dir);
  wcscat_s(g_dir, MAX_PATH, L"sd-secret-test-");
  do { num[i++] = (wchar_t)(L'0' + pid % 10); pid /= 10; } while (pid && i < 15);
  num[i] = 0;
  _wcsrev(num);
  wcscat_s(g_dir, MAX_PATH, num);
  CreateDirectoryW(g_dir, NULL);
  for (i = 0; num[i]; i++) p[i] = (char)num[i];
  p[i] = 0;
  strcpy_s(g_prefix, sizeof(g_prefix), "com.librestatic.shelldrive.test-");
  strcat_s(g_prefix, sizeof(g_prefix), p);
  strcat_s(g_prefix, sizeof(g_prefix), ":");
  memset(&c, 0, sizeof(c));
  c.user_dir = g_dir;
  c.service_dir = g_dir;
  c.prefix = g_prefix;
  c.force_dpapi = force_dpapi;
  sd_secret_configure(&c);
}

static void teardown(void)
{
  uint32_t n = 0;
  sd_secret_config c;
  /* both modes, so that nothing of this run survives in Credential Manager */
  memset(&c, 0, sizeof(c));
  c.user_dir = g_dir;
  c.prefix = g_prefix;
  sd_secret_configure(&c);
  sd_secret_delete_all(SD_SECRET_USER, &n);
  c.force_dpapi = 1;
  sd_secret_configure(&c);
  sd_secret_delete_all(SD_SECRET_USER, &n);
  sd_secret_configure(NULL);
}

static int get_eq(sd_secret_kind k, const char *target, const char *want)
{
  sd_secbuf *b = NULL;
  int ok;
  if (sd_secret_get(SD_SECRET_USER, k, target, &b) != SD_OK)
    return 0;
  ok = b->len == strlen(want) && memcmp(b->p, want, b->len) == 0 && b->p[b->len] == 0;
  sd_secbuf_free(b);
  return ok;
}

SD_TEST(secret_target_names)
{
  char out[SD_SECRET_MAX_TARGET], raw[256];
  sd_secret_configure(NULL);
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSWORD, "Alice@Example.ORG:22", out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "com.librestatic.shelldrive:password:%41lice@example.org:22");
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSWORD, "50%off@h:2222", out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "com.librestatic.shelldrive:password:50%25off@h:2222");
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSPHRASE, "SHA256:AbC+/x", out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "com.librestatic.shelldrive:passphrase:SHA256:AbC+/x");
  SD_CHECK(sd_secret_target_name(SD_SECRET_PROXY, "SOCKS5:Bob@Socks.Corp:1080", out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "com.librestatic.shelldrive:proxy:socks5:%42ob@socks.corp:1080");
  SD_CHECK(sd_secret_target_name(SD_SECRET_PROXY, "ftp:bob@h:1", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSWORD, "nouser", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSWORD, "a\nb@h:22", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_target_name(SD_SECRET_PASSPHRASE, "MD5:xx", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_target_password("deploy", "::1", 2222, raw, sizeof(raw)) == SD_OK);
  SD_CHECK_STR(raw, "deploy@[::1]:2222");
  SD_CHECK(sd_secret_target_password("deploy", "web", 0, raw, sizeof(raw)) == SD_OK);
  SD_CHECK_STR(raw, "deploy@web:22");
  SD_CHECK(sd_secret_target_proxy("http", "u", "proxy", 3128, raw, sizeof(raw)) == SD_OK);
  SD_CHECK_STR(raw, "http:u@proxy:3128");
  SD_CHECK(sd_secret_target_proxy("socks4", "u", "proxy", 1, raw, sizeof(raw)) == SD_E_INVALID_PARAM);
}

typedef struct enum_ctx { int pw, pp, px; sd_secret_store pw_store; } enum_ctx;

static int enum_cb(void *ctx, sd_secret_kind k, const char *raw, sd_secret_store st)
{
  enum_ctx *e = (enum_ctx *)ctx;
  if (k == SD_SECRET_PASSWORD && strcmp(raw, "alice@host.test:22") == 0) { e->pw++; e->pw_store = st; }
  if (k == SD_SECRET_PASSPHRASE && strcmp(raw, "SHA256:fingerprint") == 0) e->pp++;
  if (k == SD_SECRET_PROXY && strcmp(raw, "http:u@proxy.test:3128") == 0) e->px++;
  return 1;
}

static void round_trip(sd_test_ctx *sd_t_, int force_dpapi)
{
  static const char pw[] = "p\xc3\xa4ss w\xc3\xb6rd";     /* UTF-8, non-ASCII */
  char longv[600];
  enum_ctx ec;
  sd_secbuf *b = NULL;
  setup(force_dpapi);
  SD_CHECK(sd_secret_get(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22", &b) == SD_E_NOT_FOUND);
  SD_CHECK(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22", L"Saved by ShellDrive for Test",
                         pw, strlen(pw)) == SD_OK);
  SD_CHECK(get_eq(SD_SECRET_PASSWORD, "alice@HOST.test:22", pw));      /* host is case-insensitive */
  SD_CHECK(sd_secret_get(SD_SECRET_USER, SD_SECRET_PASSWORD, "Alice@host.test:22", &b) == SD_E_NOT_FOUND);
  SD_CHECK(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22", NULL, "second", 6) == SD_OK);
  SD_CHECK(get_eq(SD_SECRET_PASSWORD, "alice@host.test:22", "second"));
  SD_CHECK(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSPHRASE, "SHA256:fingerprint", NULL, "pp", 2) == SD_OK);
  SD_CHECK(sd_secret_put(SD_SECRET_USER, SD_SECRET_PROXY, "http:u@proxy.test:3128", NULL, "px", 2) == SD_OK);
  SD_CHECK(get_eq(SD_SECRET_PASSPHRASE, "SHA256:fingerprint", "pp"));
  SD_CHECK(get_eq(SD_SECRET_PROXY, "http:u@proxy.test:3128", "px"));
  memset(&ec, 0, sizeof(ec));
  SD_CHECK(sd_secret_enum(SD_SECRET_USER, enum_cb, &ec) == SD_OK);
  SD_CHECK(ec.pw == 1 && ec.pp == 1 && ec.px == 1);
  SD_CHECK(ec.pw_store == (force_dpapi ? SD_SECRET_STORE_DPAPI : sd_secret_store_for(SD_SECRET_USER, 6)));
  /* longer than the 512-byte Credential Manager cap: always the DPAPI file */
  memset(longv, 'x', sizeof(longv) - 1);
  longv[sizeof(longv) - 1] = 0;
  SD_CHECK(sd_secret_store_for(SD_SECRET_USER, strlen(longv)) == SD_SECRET_STORE_DPAPI);
  SD_CHECK(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSWORD, "bob@host.test:22", NULL, longv, strlen(longv)) == SD_OK);
  SD_CHECK(get_eq(SD_SECRET_PASSWORD, "bob@host.test:22", longv));
  /* delete */
  SD_CHECK(sd_secret_delete(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22") == SD_OK);
  SD_CHECK(sd_secret_delete(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22") == SD_E_NOT_FOUND);
  SD_CHECK(sd_secret_get(SD_SECRET_USER, SD_SECRET_PASSWORD, "alice@host.test:22", &b) == SD_E_NOT_FOUND);
  teardown();
  memset(&ec, 0, sizeof(ec));
  setup(force_dpapi);
  sd_secret_enum(SD_SECRET_USER, enum_cb, &ec);
  SD_CHECK(ec.pw == 0 && ec.pp == 0 && ec.px == 0);
  teardown();
}

SD_TEST(secret_credman_round_trip)
{
  setup(0);
  if (sd_secret_store_for(SD_SECRET_USER, 4) != SD_SECRET_STORE_CREDMAN) {
    teardown();
    return;   /* generic credentials cannot persist here (XP Home class): the DPAPI test covers it */
  }
  teardown();
  round_trip(sd_t_, 0);
}

SD_TEST(secret_dpapi_round_trip)
{
  /* the XP Home / Vista Home path: every secret goes to DPAPI files */
  round_trip(sd_t_, 1);
}

SD_TEST(secret_dpapi_file_layout)
{
  wchar_t pat[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f, h;
  uint8_t buf[2048];
  DWORD got = 0;
  sd_secbuf *b = NULL;
  setup(1);
  SD_REQUIRE(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSWORD, "carol@layout.test:22", NULL, "s3cret", 6) == SD_OK);
  wcscpy_s(pat, MAX_PATH, g_dir);
  wcscat_s(pat, MAX_PATH, L"\\secrets\\*.sdsec");
  f = FindFirstFileW(pat, &fd);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  FindClose(f);
  SD_CHECK(wcslen(fd.cFileName) == 64 + 6);
  wcscpy_s(path, MAX_PATH, g_dir);
  wcscat_s(path, MAX_PATH, L"\\secrets\\");
  wcscat_s(path, MAX_PATH, fd.cFileName);
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  if (!ReadFile(h, buf, sizeof(buf), &got, NULL)) got = 0;
  CloseHandle(h);
  SD_CHECK(got > 20 && memcmp(buf, "SDSEC1\0\0", 8) == 0 && buf[8] == 1 && buf[9] == 0);
  /* the plain secret (UTF-16LE) never appears in the file */
  {
    static const uint8_t w[] = { 's', 0, '3', 0, 'c', 0, 'r', 0 };
    DWORD i;
    int found = 0;
    for (i = 0; i + sizeof(w) <= got; i++)
      if (memcmp(buf + i, w, sizeof(w)) == 0) found = 1;
    SD_CHECK(!found);
  }
  /* a file copied under another target's name is not accepted (entropy and description differ) */
  SD_REQUIRE(sd_secret_put(SD_SECRET_USER, SD_SECRET_PASSWORD, "dave@layout.test:22", NULL, "other", 5) == SD_OK);
  {
    wchar_t p2[MAX_PATH];
    char full[SD_SECRET_MAX_TARGET];
    WIN32_FIND_DATAW fd2;
    HANDLE f2 = FindFirstFileW(pat, &fd2);
    int copied = 0;
    SD_REQUIRE(f2 != INVALID_HANDLE_VALUE);
    do {
      if (wcscmp(fd2.cFileName, fd.cFileName) != 0) {
        wcscpy_s(p2, MAX_PATH, g_dir);
        wcscat_s(p2, MAX_PATH, L"\\secrets\\");
        wcscat_s(p2, MAX_PATH, fd2.cFileName);
        copied = CopyFileW(path, p2, FALSE);
      }
    } while (FindNextFileW(f2, &fd2));
    FindClose(f2);
    SD_CHECK(copied);
    SD_CHECK(sd_secret_target_name(SD_SECRET_PASSWORD, "dave@layout.test:22", full, sizeof(full)) == SD_OK);
    SD_CHECK(sd_secret_get(SD_SECRET_USER, SD_SECRET_PASSWORD, "dave@layout.test:22", &b) == SD_E_NOT_FOUND);
  }
  teardown();
}

static int key_cb(void *ctx, const char *id)
{
  int *n = (int *)ctx;
  SD_UNUSED(id);
  (*n)++;
  return 1;
}

SD_TEST(secret_key_files)
{
  uint8_t img[64], *back = NULL;
  size_t len = 0;
  char id[33];
  int n = 0;
  setup(1);
  memset(img, 0xA5, sizeof(img));
  memcpy(img, "SDKEY1\0\0", 8);
  SD_REQUIRE(sd_secret_key_new_id(id) == SD_OK);
  SD_CHECK(strlen(id) == 32);
  SD_CHECK(sd_secret_key_write(SD_SECRET_USER, id, img, sizeof(img)) == SD_OK);
  SD_CHECK(sd_secret_key_write(SD_SECRET_USER, "../evil", img, sizeof(img)) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_key_write(SD_SECRET_USER, id, (const uint8_t *)"not a key image!", 16) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_secret_key_read(SD_SECRET_USER, id, &back, &len) == SD_OK);
  SD_CHECK(len == sizeof(img) && back && memcmp(back, img, len) == 0);
  sd_free(back);
  SD_CHECK(sd_secret_key_enum(SD_SECRET_USER, key_cb, &n) == SD_OK && n == 1);
  SD_CHECK(sd_secret_key_delete(SD_SECRET_USER, id) == SD_OK);
  SD_CHECK(sd_secret_key_delete(SD_SECRET_USER, id) == SD_E_NOT_FOUND);
  SD_CHECK(sd_secret_key_read(SD_SECRET_USER, id, &back, &len) == SD_E_NOT_FOUND);
  teardown();
}
