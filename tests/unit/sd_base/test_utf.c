#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_test.h"

SD_TEST(utf8_to_utf16_basic)
{
  /* "aé€😀": 1, 2, 3 and 4-byte sequences */
  static const char in[] = "a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80";
  static const wchar_t want[] = { L'a', 0x00E9, 0x20AC, 0xD83D, 0xDE00 };
  wchar_t out[8];
  size_t n;
  SD_REQUIRE(sd_utf8_to_utf16(in, sizeof(in) - 1, out, SD_COUNTOF(out), &n, SD_UTF_STRICT) == SD_OK);
  SD_CHECK_EQ_U64(n, 5);
  SD_CHECK_MEM(out, want, sizeof(want));

  /* measuring and a too-small buffer */
  SD_CHECK(sd_utf8_to_utf16(in, sizeof(in) - 1, NULL, 0, &n, SD_UTF_STRICT) == SD_OK && n == 5);
  SD_CHECK(sd_utf8_to_utf16(in, sizeof(in) - 1, out, 4, &n, SD_UTF_STRICT) == SD_E_INVALID_PARAM && n == 5);
}

SD_TEST(utf8_rejects_invalid)
{
  static const char *const bad[] = {
    "\xC0\xAF",              /* overlong '/' */
    "\xE0\x80\xAF",          /* overlong */
    "\xED\xA0\x80",          /* surrogate D800 */
    "\xF4\x90\x80\x80",      /* > U+10FFFF */
    "\x80",                  /* lone continuation */
    "\xE2\x82",              /* truncated */
    "\xFF"
  };
  size_t i, n;
  wchar_t out[8];
  for (i = 0; i < SD_COUNTOF(bad); i++) {
    SD_CHECK(!sd_utf8_valid(bad[i], strlen(bad[i])));
    SD_CHECK(sd_utf8_to_utf16(bad[i], strlen(bad[i]), out, 8, &n, SD_UTF_STRICT) == SD_E_INVALID_PARAM);
  }
  /* replacement mode: one U+FFFD per invalid byte */
  SD_REQUIRE(sd_utf8_to_utf16("a\xFF" "b", 3, out, 8, &n, SD_UTF_REPLACE) == SD_OK);
  SD_CHECK(n == 3 && out[1] == 0xFFFD && out[2] == L'b');
}

SD_TEST(utf16_to_utf8_and_surrogates)
{
  static const wchar_t in[] = { L'a', 0x00E9, 0xD83D, 0xDE00 };
  static const wchar_t lone[] = { L'x', 0xDC00 };
  char out[16];
  size_t n;
  SD_REQUIRE(sd_utf16_to_utf8(in, SD_COUNTOF(in), out, sizeof(out), &n, SD_UTF_STRICT) == SD_OK);
  SD_CHECK(n == 7 && memcmp(out, "a\xC3\xA9\xF0\x9F\x98\x80", 7) == 0);
  SD_CHECK(sd_utf16_to_utf8(lone, 2, out, sizeof(out), &n, SD_UTF_STRICT) == SD_E_INVALID_PARAM);
  SD_REQUIRE(sd_utf16_to_utf8(lone, 2, out, sizeof(out), &n, SD_UTF_REPLACE) == SD_OK);
  SD_CHECK(n == 4 && memcmp(out, "x\xEF\xBF\xBD", 4) == 0);
}

SD_TEST(utf_alloc_variants)
{
  wchar_t *w = NULL;
  char *s = NULL;
  SD_REQUIRE(sd_utf8_to_wide_alloc("Gr\xC3\xBC\xC3\x9F" "e", (size_t)-1, SD_UTF_STRICT, &w) == SD_OK);
  SD_CHECK(wcscmp(w, L"Gr\x00FC\x00DF" L"e") == 0);
  SD_REQUIRE(sd_wide_to_utf8_alloc(w, (size_t)-1, SD_UTF_STRICT, &s) == SD_OK);
  SD_CHECK_STR(s, "Gr\xC3\xBC\xC3\x9F" "e");
  sd_free(w);
  sd_free(s);

  sd_test_alloc_fail_after(0);
  SD_CHECK(sd_utf8_to_wide_alloc("x", 1, SD_UTF_STRICT, &w) == SD_E_NO_MEMORY && w == NULL);
  sd_test_alloc_fail_off();
}

/* Every byte string must survive bytes -> UTF-16 -> bytes exactly (01 §10.7). */
static int name_roundtrip(const char *bytes, uint32_t len)
{
  wchar_t w[64];
  char back[128];
  uint32_t wn, bn;
  if (sd_name_to_wide(bytes, len, w, SD_COUNTOF(w), &wn) != SD_OK)
    return 0;
  if (sd_name_from_wide(w, wn, back, sizeof(back), &bn) != SD_OK)
    return 0;
  return bn == len && memcmp(back, bytes, len) == 0;
}

SD_TEST(name_mapping_is_lossless)
{
  static const char *const cases[] = {
    "plain.txt",
    "caf\xC3\xA9",                       /* valid UTF-8 */
    "latin1-\xE9t\xE9",                  /* invalid: Latin-1 bytes */
    "\xC0\xAF",                          /* overlong */
    "\xED\xA0\x80",                      /* encoded surrogate */
    "\xEF\x9E\x80",                      /* valid UTF-8 for U+F780: must be escaped */
    "\xE2\x82",                          /* truncated */
    "\xF0\x9F\x98\x80 emoji"
  };
  size_t i;
  uint32_t b;
  for (i = 0; i < SD_COUNTOF(cases); i++)
    SD_CHECK(name_roundtrip(cases[i], (uint32_t)strlen(cases[i])));
  /* exhaustive over all single bytes except NUL and '/' */
  for (b = 1; b < 256; b++) {
    char c = (char)b;
    if (b == '/')
      continue;
    SD_CHECK(name_roundtrip(&c, 1));
  }
}

SD_TEST(name_escape_values)
{
  wchar_t w[8];
  uint32_t n;
  SD_REQUIRE(sd_name_to_wide("\xE9", 1, w, 8, &n) == SD_OK);
  SD_CHECK(n == 1 && w[0] == 0xF7E9);
  SD_REQUIRE(sd_name_to_wide("\xEF\x9E\x80", 3, w, 8, &n) == SD_OK);   /* U+F780 escaped byte-wise */
  SD_CHECK(n == 3 && w[0] == 0xF7EF && w[1] == 0xF79E && w[2] == 0xF780);
}

SD_TEST(name_from_wide_rejects)
{
  static const wchar_t slash[] = { L'a', L'/', L'b' };
  static const wchar_t nul[] = { L'a', 0, L'b' };
  static const wchar_t lone[] = { 0xD800 };
  char out[16];
  uint32_t n;
  SD_CHECK(sd_name_from_wide(slash, 3, out, sizeof(out), &n) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_from_wide(nul, 3, out, sizeof(out), &n) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_from_wide(lone, 1, out, sizeof(out), &n) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_from_wide(L"abcdef", 6, out, 3, &n) == SD_E_NAME_TOO_LONG && n == 6);
}

SD_TEST(name_component_check)
{
  SD_CHECK(sd_name_component_check("a", 1) == SD_OK);
  SD_CHECK(sd_name_component_check("...", 3) == SD_OK);
  SD_CHECK(sd_name_component_check("", 0) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_component_check(".", 1) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_component_check("..", 2) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_component_check("a/b", 3) == SD_E_INVALID_NAME);
  SD_CHECK(sd_name_component_check("a\0b", 3) == SD_E_INVALID_NAME);
}

SD_TEST(text_sanitize_server)
{
  /* bidi override U+202E, zero-width space U+200B, BEL, C1 U+0085, invalid byte, kept CR/LF/TAB */
  static const char in[] = "ok\xE2\x80\xAE" "x\xE2\x80\x8B" "y\x07" "z\xC2\x85\xFF\r\n\t.";
  char out[64];
  size_t n;
  SD_REQUIRE(sd_text_sanitize_server(in, sizeof(in) - 1, out, sizeof(out), &n) == SD_OK);
  SD_CHECK(n == 12 && memcmp(out, "okxyz\xEF\xBF\xBD\r\n\t.", 12) == 0);
  SD_REQUIRE(sd_text_sanitize_host("h\r\nost", 6, out, sizeof(out), &n) == SD_OK);
  SD_CHECK(n == 4 && memcmp(out, "host", 4) == 0);
}
