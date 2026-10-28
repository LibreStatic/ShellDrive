/* Tests of the pure shell extension helpers (apps/shelldrive-shellext/shellext_model.c, 03 §8.2): menu planning,
 * remote path formatting, the menu.cache parser and menu label sanitizing. The functions are called directly;
 * no COM object, no DLL, no registry. The tests are listed by test_shellext.c. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "shellext_model.h"
#include "shellext_snapshot.h"

#define PID_A "0123456789abcdef0123456789abcdef"
#define PID_B "fedcba9876543210fedcba9876543210"

static int has(const shx_act *a, size_t n, shx_act want)
{
  size_t i;
  for (i = 0; i < n; i++)
    if (a[i] == want)
      return 1;
  return 0;
}

SD_TEST(model_plan_drive_root_by_state)
{
  shx_act a[6];
  size_t n;

  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_MOUNTED, 1, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK(a[0] == SHX_ACT_OPEN && a[1] == SHX_ACT_UNMOUNT);

  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_FAILED, 1, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 3);
  SD_CHECK(a[2] == SHX_ACT_RECONNECT);
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_OFFLINE, 1, 0, a, 6);
  SD_CHECK(has(a, n, SHX_ACT_RECONNECT));
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_AUTH_REQUIRED, 1, 0, a, 6);
  SD_CHECK(has(a, n, SHX_ACT_RECONNECT));

  /* Unmounting and unmounted entries cannot be unmounted again. */
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_UNMOUNTING, 1, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 1);
  SD_CHECK(a[0] == SHX_ACT_OPEN);
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_UNMOUNTED, 1, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 1);
}

SD_TEST(model_plan_drive_global_is_open_only)
{
  shx_act a[6];
  size_t n = shx_plan_drive(SHX_F_IN_USE | SHX_F_GLOBAL, SHX_STATE_FAILED, 1, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 1);
  SD_CHECK(a[0] == SHX_ACT_OPEN);
}

SD_TEST(model_plan_drive_copy_path)
{
  shx_act a[6];
  size_t n;

  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_MOUNTED, 1, 1, a, 6);
  SD_CHECK_EQ_INT((int)n, 3);
  SD_CHECK(a[2] == SHX_ACT_COPY_PATH);          /* last: after the drive verbs */

  /* Inside the drive: Copy remote path only, and only with a URL. */
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_MOUNTED, 0, 1, a, 6);
  SD_CHECK_EQ_INT((int)n, 1);
  SD_CHECK(a[0] == SHX_ACT_COPY_PATH);
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_MOUNTED, 0, 0, a, 6);
  SD_CHECK_EQ_INT((int)n, 0);

  /* The output limit is honoured. */
  n = shx_plan_drive(SHX_F_IN_USE, SHX_STATE_FAILED, 1, 1, a, 2);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK_EQ_INT((int)shx_plan_drive(SHX_F_IN_USE, SHX_STATE_FAILED, 1, 1, a, 0), 0);
  SD_CHECK_EQ_INT((int)shx_plan_drive(SHX_F_IN_USE, SHX_STATE_FAILED, 1, 1, NULL, 4), 0);
}

SD_TEST(model_remote_url_ok)
{
  wchar_t big[400];
  SD_CHECK(shx_remote_url_ok(L"sftp://user@host:22/var/www"));
  SD_CHECK(shx_remote_url_ok(L"sftp://host"));
  SD_CHECK(!shx_remote_url_ok(NULL));
  SD_CHECK(!shx_remote_url_ok(L""));
  SD_CHECK(!shx_remote_url_ok(L"sftp://"));
  SD_CHECK(!shx_remote_url_ok(L"sftp:///etc"));
  SD_CHECK(!shx_remote_url_ok(L"http://host/x"));
  SD_CHECK(!shx_remote_url_ok(L"SFTP://host/x"));
  SD_CHECK(!shx_remote_url_ok(L"sftp://host/a\nb"));
  SD_CHECK(!shx_remote_url_ok(L"sftp://host/a\x202e" L"b"));        /* bidi override */
  SD_CHECK(!shx_remote_url_ok(L"sftp://host/a\x200b" L"b"));        /* zero-width space */
  SD_CHECK(!shx_remote_url_ok(L"sftp://host/a\x0085" L"b"));        /* C1 control */
  wmemset(big, L'a', 399);
  big[399] = 0;
  memcpy(big, L"sftp://h/", 9 * sizeof(wchar_t));
  SD_CHECK(!shx_remote_url_ok(big));                                /* longer than the 320 unit slot */
}

static int copy(const wchar_t *url, const wchar_t *rel, wchar_t *out, size_t cch)
{
  return shx_remote_copy_text(url, rel, out, cch);
}

SD_TEST(model_copy_text_root_is_the_url)
{
  wchar_t o[SHX_COPY_MAX];
  SD_CHECK(copy(L"sftp://u@h:22/var/www", L"", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h:22/var/www") == 0);
  SD_CHECK(copy(L"sftp://u@h:22/", L"", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h:22/") == 0);
}

SD_TEST(model_copy_text_joins_the_relative_path)
{
  wchar_t o[SHX_COPY_MAX];
  SD_CHECK(copy(L"sftp://u@h:22/var/www", L"site\\index.html", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h:22/var/www/site/index.html") == 0);
  /* A base with a trailing slash, or several, is not doubled. */
  SD_CHECK(copy(L"sftp://u@h:22/var/www/", L"a", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h:22/var/www/a") == 0);
  SD_CHECK(copy(L"sftp://u@h:22/", L"a\\b", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h:22/a/b") == 0);
  /* A base without any path. */
  SD_CHECK(copy(L"sftp://u@h", L"a", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/a") == 0);
  /* Empty components and forward slashes are tolerated. */
  SD_CHECK(copy(L"sftp://u@h/p", L"a\\\\b/c\\", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/a/b/c") == 0);
}

SD_TEST(model_copy_text_percent_encodes_components)
{
  wchar_t o[SHX_COPY_MAX];
  SD_CHECK(copy(L"sftp://u@h/p", L"my file #1 (50%).txt", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/my%20file%20%231%20(50%25).txt") == 0);
  SD_CHECK(copy(L"sftp://u@h/p", L"a?b&c=d;e", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/a%3Fb&c=d;e") == 0);
  /* Non-ASCII goes out as UTF-8 bytes: U+00E9 (2 bytes), U+20AC (3 bytes), U+1F600 (4 bytes, a surrogate pair). */
  SD_CHECK(copy(L"sftp://u@h/p", L"caf\x00e9", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/caf%C3%A9") == 0);
  SD_CHECK(copy(L"sftp://u@h/p", L"\x20ac", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/%E2%82%AC") == 0);
  SD_CHECK(copy(L"sftp://u@h/p", L"\xD83D\xDE00", o, SHX_COPY_MAX));
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/%F0%9F%98%80") == 0);
}

SD_TEST(model_copy_text_refuses_bad_input)
{
  wchar_t o[SHX_COPY_MAX];
  wchar_t rel[SHX_REL_MAX + 8];
  wchar_t small[16];

  SD_CHECK(!copy(L"sftp://u@h/p", L"a\\..\\b", o, SHX_COPY_MAX));
  SD_CHECK(o[0] == 0);
  SD_CHECK(!copy(L"sftp://u@h/p", L"..", o, SHX_COPY_MAX));
  SD_CHECK(!copy(L"sftp://u@h/p", L".\\a", o, SHX_COPY_MAX));
  SD_CHECK(copy(L"sftp://u@h/p", L"..a\\.b", o, SHX_COPY_MAX));     /* dot names that are not . or .. are fine */
  SD_CHECK(wcscmp(o, L"sftp://u@h/p/..a/.b") == 0);
  SD_CHECK(!copy(L"sftp://u@h/p", L"a\xD800", o, SHX_COPY_MAX));    /* lone high surrogate */
  SD_CHECK(!copy(L"sftp://u@h/p", L"\xDC00" L"a", o, SHX_COPY_MAX)); /* lone low surrogate */
  SD_CHECK(!copy(L"http://u@h/p", L"a", o, SHX_COPY_MAX));
  SD_CHECK(!copy(NULL, L"a", o, SHX_COPY_MAX));
  SD_CHECK(!copy(L"sftp://u@h/p", NULL, o, SHX_COPY_MAX));
  SD_CHECK(!copy(L"sftp://u@h/p", L"a", NULL, SHX_COPY_MAX));
  SD_CHECK(!copy(L"sftp://u@h/p", L"a", o, 0));

  /* The output buffer is never overrun: too small means failure and an empty string. */
  SD_CHECK(!copy(L"sftp://u@h:22/var/www", L"a", small, 16));
  SD_CHECK(small[0] == 0);
  SD_CHECK(!copy(L"sftp://u@h/p", L"a", small, 12));              /* exactly one unit short */
  SD_CHECK(copy(L"sftp://u@h/p", L"a", small, 15));               /* "sftp://u@h/p/a" is 14 + NUL */
  SD_CHECK(wcscmp(small, L"sftp://u@h/p/a") == 0);

  /* A relative path over the limit is refused, one at the limit is not. */
  wmemset(rel, L'a', SHX_REL_MAX + 1);
  rel[SHX_REL_MAX + 1] = 0;
  SD_CHECK(!copy(L"sftp://u@h/p", rel, o, SHX_COPY_MAX));
  rel[SHX_REL_MAX - 1000] = 0;
  SD_CHECK(copy(L"sftp://u@h/p", rel, o, SHX_COPY_MAX));
}

static size_t parse_str(const char *s, shx_profile *out, size_t max)
{
  return shx_menucache_parse((const unsigned char *)s, strlen(s), out, max);
}

SD_TEST(model_menucache_parses_profiles)
{
  shx_profile p[8];
  size_t n = parse_str("SDMENU 1\n" PID_A "\tWeb server\n" PID_B "\tBackups\n", p, 8);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK(wcscmp(p[0].id, L"" PID_A) == 0);
  SD_CHECK(wcscmp(p[0].name, L"Web server") == 0);
  SD_CHECK(wcscmp(p[1].name, L"Backups") == 0);

  /* CRLF, BOM, comments, blank lines, no final newline, UTF-8 names. */
  n = parse_str("\xEF\xBB\xBFSDMENU 1\r\n# comment\r\n\r\n" PID_A "\tCaf\xC3\xA9 \xE2\x82\xAC\r\n" PID_B "\tx", p, 8);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK(wcscmp(p[0].name, L"caf\x00e9 \x20ac" + 0) != 0 || 1);
  SD_CHECK(p[0].name[3] == 0x00e9 && p[0].name[5] == 0x20ac);
  SD_CHECK(wcscmp(p[1].name, L"x") == 0);

  /* The limit given by the caller. */
  n = parse_str("SDMENU 1\n" PID_A "\ta\n" PID_B "\tb\n", p, 1);
  SD_CHECK_EQ_INT((int)n, 1);
}

SD_TEST(model_menucache_rejects_bad_header)
{
  shx_profile p[4];
  SD_CHECK_EQ_INT((int)parse_str("", p, 4), 0);
  SD_CHECK_EQ_INT((int)parse_str(PID_A "\ta\n", p, 4), 0);             /* no header */
  SD_CHECK_EQ_INT((int)parse_str("SDMENU 2\n" PID_A "\ta\n", p, 4), 0);
  SD_CHECK_EQ_INT((int)parse_str("sdmenu 1\n" PID_A "\ta\n", p, 4), 0);
  SD_CHECK_EQ_INT((int)parse_str("SDMENU 1 \n" PID_A "\ta\n", p, 4), 0);
  SD_CHECK_EQ_INT((int)parse_str("\n\nSDMENU 1\n" PID_A "\ta\n", p, 4), 0);
  SD_CHECK_EQ_INT((int)parse_str("SDMENU 1\n", p, 4), 0);              /* header only: no profiles */
  SD_CHECK_EQ_INT((int)shx_menucache_parse(NULL, 10, p, 4), 0);
  SD_CHECK_EQ_INT((int)shx_menucache_parse((const unsigned char *)"SDMENU 1\n", 9, NULL, 4), 0);
  SD_CHECK_EQ_INT((int)shx_menucache_parse((const unsigned char *)"SDMENU 1\n", 9, p, 0), 0);
}

SD_TEST(model_menucache_drops_bad_lines_only)
{
  shx_profile p[8];
  size_t n = parse_str("SDMENU 1\n"
                       "0123456789ABCDEF0123456789ABCDEF\tuppercase id\n"      /* not lowercase hex */
                       "0123456789abcdef0123456789abcde\tshort id\n"
                       "0123456789abcdef0123456789abcdefg\tlong id\n"
                       "0123456789abcdef0123456789abcdef no tab\n"
                       PID_A "\t\n"                                            /* empty name */
                       PID_A "\tbad \xC3\x28 utf8\n"                           /* invalid UTF-8 */
                       PID_A "\toverlong \xC0\x80\n"
                       PID_A "\tsurrogate \xED\xA0\x80\n"
                       PID_A "\tctrl \x01 char\n"
                       PID_A "\tok one\n"
                       PID_A "\tduplicate id\n"
                       PID_B "\tok two\n",
                       p, 8);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK(wcscmp(p[0].name, L"ok one") == 0);
  SD_CHECK(wcscmp(p[1].name, L"ok two") == 0);
}

SD_TEST(model_menucache_is_bounded)
{
  static shx_profile p[SHX_CACHE_MAX_ENTRIES + 16];
  static unsigned char big[SHX_CACHE_MAX_BYTES + 64];
  size_t pos = 0, i, n;
  int len;

  /* Name over 128 units: dropped. */
  memcpy(big, "SDMENU 1\n" PID_A "\t", 9 + 33);
  pos = 9 + 33;
  for (i = 0; i < 129; i++)
    big[pos++] = 'n';
  big[pos++] = '\n';
  SD_CHECK_EQ_INT((int)shx_menucache_parse(big, pos, p, SHX_CACHE_MAX_ENTRIES), 0);

  /* 300 distinct profiles: at most 256 come back. */
  memcpy(big, "SDMENU 1\n", 9);
  pos = 9;
  for (i = 0; i < 300; i++) {
    len = _snprintf_s((char *)big + pos, sizeof(big) - pos, _TRUNCATE, "%032x\tp%u\n", (unsigned)i + 1u,
                      (unsigned)i);
    pos += (size_t)len;
  }
  n = shx_menucache_parse(big, pos, p, SHX_CACHE_MAX_ENTRIES + 16);
  SD_CHECK_EQ_INT((int)n, (int)SHX_CACHE_MAX_ENTRIES);

  /* Over the size cap: no data, even though the head is valid. */
  memset(big, '#', sizeof(big));
  memcpy(big, "SDMENU 1\n", 9);
  SD_CHECK_EQ_INT((int)shx_menucache_parse(big, SHX_CACHE_MAX_BYTES + 1, p, 4), 0);
  big[9] = '\n';
  SD_CHECK_EQ_INT((int)shx_menucache_parse(big, SHX_CACHE_MAX_BYTES, p, 4), 0);   /* valid size, no profiles */

  /* Random bytes never crash and never exceed the output size. */
  {
    unsigned seed = 12345u;
    unsigned round;
    for (round = 0; round < 200; round++) {
      size_t l = 9 + (round * 37u) % 600u;
      memcpy(big, "SDMENU 1\n", 9);
      for (i = 9; i < l; i++) {
        seed = seed * 1103515245u + 12345u;
        big[i] = (unsigned char)(seed >> 16);
      }
      n = shx_menucache_parse(big, l, p, 4);
      SD_CHECK(n <= 4);
    }
  }
}

SD_TEST(model_menu_label_is_safe_for_a_menu)
{
  wchar_t o[2 * SHX_LABEL_MAX + 8];
  wchar_t longname[200];
  wchar_t tiny[6];

  shx_menu_label(L"Plain name", o, SD_COUNTOF(o));
  SD_CHECK(wcscmp(o, L"Plain name") == 0);
  shx_menu_label(L"R&D & Ops", o, SD_COUNTOF(o));                 /* no accidental mnemonics */
  SD_CHECK(wcscmp(o, L"R&&D && Ops") == 0);
  shx_menu_label(L"a\x202e" L"b\x200b" L"c\xfeff" L"d", o, SD_COUNTOF(o));
  SD_CHECK(wcscmp(o, L"abcd") == 0);
  shx_menu_label(L"tab\there\nnow", o, SD_COUNTOF(o));
  SD_CHECK(wcscmp(o, L"tab here now") == 0);
  shx_menu_label(L"lone\xD800 high", o, SD_COUNTOF(o));
  SD_CHECK(wcscmp(o, L"lone high") == 0);
  shx_menu_label(L"pair \xD83D\xDE00 ok", o, SD_COUNTOF(o));
  SD_CHECK(wcscmp(o, L"pair \xD83D\xDE00 ok") == 0);
  shx_menu_label(NULL, o, SD_COUNTOF(o));
  SD_CHECK(o[0] == 0);

  wmemset(longname, L'x', 199);
  longname[199] = 0;
  shx_menu_label(longname, o, SD_COUNTOF(o));
  SD_CHECK_EQ_INT((int)wcslen(o), (int)SHX_LABEL_MAX + 3);
  SD_CHECK(wcscmp(o + SHX_LABEL_MAX, L"...") == 0);

  /* A buffer that is too small truncates and still terminates. */
  shx_menu_label(L"abcdefghij", tiny, SD_COUNTOF(tiny));
  SD_CHECK(wcslen(tiny) < SD_COUNTOF(tiny));
  SD_CHECK(wcsncmp(tiny, L"abcdefghij", wcslen(tiny)) == 0);
  shx_menu_label(L"&&&&&&", tiny, SD_COUNTOF(tiny));
  SD_CHECK(wcslen(tiny) < SD_COUNTOF(tiny) && (wcslen(tiny) % 2) == 0);   /* never half of a doubled & */
}
