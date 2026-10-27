/* sd_vfs name mapping (02 §1.2, TM-R11/R12), collisions (§1.3) and the error table (§8). */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "vfs_internal.h"

static int wide_eq(const WCHAR *a, const WCHAR *b) { return a && b && wcscmp(a, b) == 0; }

SD_TEST(vfs_err_table_covers_every_value)
{
  static const struct { sd_err e; sd_vfs_status s; } k[] = {
    { SD_OK, SD_VFS_OK }, { SD_E_EOF, SD_VFS_E_END_OF_FILE }, { SD_E_NOT_FOUND, SD_VFS_E_NOT_FOUND },
    { SD_E_ACCESS_DENIED, SD_VFS_E_ACCESS_DENIED }, { SD_E_EXISTS, SD_VFS_E_EXISTS },
    { SD_E_NOT_EMPTY, SD_VFS_E_NOT_EMPTY }, { SD_E_NOT_A_DIRECTORY, SD_VFS_E_NOT_DIR },
    { SD_E_IS_A_DIRECTORY, SD_VFS_E_IS_DIR }, { SD_E_NO_SPACE, SD_VFS_E_NO_SPACE }, { SD_E_QUOTA, SD_VFS_E_QUOTA },
    { SD_E_READ_ONLY, SD_VFS_E_READ_ONLY }, { SD_E_INVALID_NAME, SD_VFS_E_INVALID_NAME },
    { SD_E_NAME_TOO_LONG, SD_VFS_E_NAME_TOO_LONG }, { SD_E_LINK_LOOP, SD_VFS_E_NOT_FOUND },
    { SD_E_LOCK_CONFLICT, SD_VFS_E_ACCESS_DENIED }, { SD_E_INVALID_PARAM, SD_VFS_E_IO },
    { SD_E_UNSUPPORTED, SD_VFS_E_UNSUPPORTED }, { SD_E_FAILURE, SD_VFS_E_IO },
    { SD_E_DISCONNECTED, SD_VFS_E_DISCONNECTED }, { SD_E_STALE_HANDLE, SD_VFS_E_STALE },
    { SD_E_TIMEOUT, SD_VFS_E_TIMEOUT }, { SD_E_CANCELLED, SD_VFS_E_CANCELLED }, { SD_E_PROTOCOL, SD_VFS_E_IO },
    { SD_E_BUSY, SD_VFS_E_IO }, { SD_E_WOULD_DEADLOCK, SD_VFS_E_IO }, { SD_E_SHUTDOWN, SD_VFS_E_DISCONNECTED },
    { SD_E_DNS, SD_VFS_E_IO }, { SD_E_CONN_REFUSED, SD_VFS_E_IO }, { SD_E_NET_UNREACHABLE, SD_VFS_E_IO },
    { SD_E_KEX_FAILED, SD_VFS_E_IO }, { SD_E_HOSTKEY_REJECTED, SD_VFS_E_IO }, { SD_E_HOSTKEY_MISMATCH, SD_VFS_E_IO },
    { SD_E_HOSTKEY_REVOKED, SD_VFS_E_IO }, { SD_E_HOSTKEY_TYPE_UNAVAILABLE, SD_VFS_E_IO },
    { SD_E_AUTH_FAILED, SD_VFS_E_IO }, { SD_E_AUTH_REQUIRED, SD_VFS_E_DISCONNECTED },
    { SD_E_LEGACY_REJECTED, SD_VFS_E_IO }, { SD_E_PROXY, SD_VFS_E_IO }, { SD_E_PROXY_AUTH, SD_VFS_E_IO },
    { SD_E_POOL_ABANDONED, SD_VFS_E_IO },
    { SD_E_NO_MEMORY, SD_VFS_E_NO_MEMORY }, { SD_E_CRYPTO, SD_VFS_E_IO }, { SD_E_KEY_FORMAT, SD_VFS_E_IO },
    { SD_E_KEY_UNSUPPORTED, SD_VFS_E_IO }, { SD_E_BAD_PASSPHRASE, SD_VFS_E_IO },
    { SD_E_KEY_PASSPHRASE_REQUIRED, SD_VFS_E_IO }, { SD_E_INTERNAL, SD_VFS_E_IO },
    { SD_WD_E_AUTH_UNAVAILABLE, SD_VFS_E_IO },
  };
  size_t i;
  /* One row per SD_ERR_LIST value: a new sd_err must be added here (00 §4). */
  SD_CHECK_EQ_INT(SD_COUNTOF(k), SD_ERR_COUNT);
  for (i = 0; i < SD_COUNTOF(k); i++) {
    SD_CHECK_EQ_INT(k[i].e, (int)i);
    if (sd_vfs_status_from_err(k[i].e) != k[i].s)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "sd_err %s maps to %d, expected %d", sd_err_name(k[i].e),
                   (int)sd_vfs_status_from_err(k[i].e), (int)k[i].s);
  }
}

static void check_fwd(sd_test_ctx *sd_t_, const char *raw, uint32_t len, const WCHAR *want)
{
  WCHAR *w = NULL;
  SD_REQUIRE(vfs_name_to_display(raw, len, &w, NULL) == SD_VFS_OK);
  if (!wide_eq(w, want))
    sd_test_fail(sd_t_, __FILE__, __LINE__, "display of \"%s\" differs", raw);
  sd_free(w);
}

static void check_inv(sd_test_ctx *sd_t_, const WCHAR *w, const char *want, uint32_t want_len)
{
  char *raw = NULL;
  uint32_t n = 0;
  sd_vfs_status st = vfs_name_from_display(w, (uint32_t)wcslen(w), &raw, &n);
  if (!want) {
    SD_CHECK_EQ_INT(st, SD_VFS_E_INVALID_NAME);
    sd_free(raw);
    return;
  }
  SD_REQUIRE(st == SD_VFS_OK);
  SD_CHECK_EQ_INT(n, want_len);
  SD_CHECK_MEM(raw, want, want_len);
  sd_free(raw);
}

SD_TEST(vfs_stage2_forward)
{
  check_fwd(sd_t_, "a:b", 3, L"a\xF03A" L"b");
  check_fwd(sd_t_, "q?*<>|\"\\", 8, L"q\xF03F\xF02A\xF03C\xF03E\xF07C\xF022\xF05C");
  check_fwd(sd_t_, "\x01x\x1f", 3, L"\xF001x\xF01F");
  check_fwd(sd_t_, "a.", 2, L"a\xF02E");
  check_fwd(sd_t_, "a..", 3, L"a.\xF02E");      /* only the last character */
  check_fwd(sd_t_, "a b ", 4, L"a b\xF020");
  check_fwd(sd_t_, "plain.txt", 9, L"plain.txt");
  check_fwd(sd_t_, "\xff", 1, L"\xF7FF");        /* stage 1 escape */
}

SD_TEST(vfs_stage2_inverse_decodes_only_produced_codes)
{
  check_inv(sd_t_, L"a\xF03A" L"b", "a:b", 3);
  check_inv(sd_t_, L"\xF001x", "\x01x", 2);
  check_inv(sd_t_, L"a\xF02E", "a.", 2);
  check_inv(sd_t_, L"a\xF020", "a ", 2);
  /* U+F02E / U+F020 not in last position, U+F000 (would be NUL) and U+F02F (would be '/') pass
     through as their own UTF-8 bytes (TM-R11, TST-05). */
  check_inv(sd_t_, L"a\xF02E" L"b", "a\xEF\x80\xAE" "b", 5);
  check_inv(sd_t_, L"\xF000", "\xEF\x80\x80", 3);
  check_inv(sd_t_, L"x\xF02F", "x\xEF\x80\xAF", 4);
  check_inv(sd_t_, L"\xF040", "\xEF\x81\x80", 3);
  /* Never "." or ".." on the wire. */
  check_inv(sd_t_, L"\xF02E", NULL, 0);
  check_inv(sd_t_, L".\xF02E", NULL, 0);
  check_inv(sd_t_, L"..", NULL, 0);
}

SD_TEST(vfs_name_roundtrip_bytes)
{
  uint32_t seed = 12345, i, j;
  for (i = 0; i < 5000; i++) {
    char raw[24], *back = NULL;
    uint32_t len = 1 + (seed % 20), n = 0;
    WCHAR *w = NULL;
    for (j = 0; j < len; j++) {
      seed = seed * 1103515245u + 12345u;
      raw[j] = (char)((seed >> 16) & 0xFF);
      if (raw[j] == 0 || raw[j] == '/') raw[j] = 'x';
    }
    if ((len == 1 && raw[0] == '.') || (len == 2 && raw[0] == '.' && raw[1] == '.'))
      continue;
    SD_REQUIRE(vfs_name_to_display(raw, len, &w, NULL) == SD_VFS_OK);
    SD_REQUIRE(vfs_name_from_display(w, (uint32_t)wcslen(w), &back, &n) == SD_VFS_OK);
    SD_CHECK_EQ_INT(n, len);
    SD_CHECK_MEM(back, raw, len);
    sd_free(w);
    sd_free(back);
  }
}

SD_TEST(vfs_input_checks)
{
  SD_CHECK_EQ_INT(vfs_name_check_input(L"a:b", 3), SD_VFS_E_INVALID_NAME);   /* stream syntax */
  SD_CHECK_EQ_INT(vfs_name_check_input(L"a*", 2), SD_VFS_E_INVALID_NAME);
  SD_CHECK_EQ_INT(vfs_name_check_input(L"ok.txt", 6), SD_VFS_OK);
  {
    WCHAR big[300];
    int i;
    for (i = 0; i < 299; i++) big[i] = L'a';
    big[299] = 0;
    SD_CHECK_EQ_INT(vfs_name_check_input(big, 256), SD_VFS_E_NAME_TOO_LONG);
    SD_CHECK_EQ_INT(vfs_name_check_input(big, 255), SD_VFS_OK);
  }
}

SD_TEST(vfs_shell_active_set)
{
  SD_CHECK(vfs_is_shell_active(L"x.LNK"));
  SD_CHECK(vfs_is_shell_active(L"x~c2.lnk"));
  SD_CHECK(vfs_is_shell_active(L"Desktop.INI"));
  SD_CHECK(vfs_is_shell_active(L"a.library-ms"));
  SD_CHECK(vfs_is_shell_active(L"a.searchConnector-ms"));
  SD_CHECK(vfs_is_shell_active(L"a.url"));
  SD_CHECK(vfs_is_shell_active(L"a.scf"));
  SD_CHECK(!vfs_is_shell_active(L"a.txt"));
  SD_CHECK(!vfs_is_shell_active(L"lnk"));
}

static void ent(vfs_dirent *e, const char *raw, BOOL fold)
{
  memset(e, 0, sizeof(*e));
  e->raw = vfs_strndup(raw, strlen(raw));
  e->raw_len = (uint32_t)strlen(raw);
  vfs_name_to_display(e->raw, e->raw_len, &e->wname, &e->wlen);
  e->key = fold ? vfs_fold(e->wname, e->wlen) : vfs_wcsdup(e->wname);
}

static const vfs_dirent *by_raw(const vfs_dirent *e, uint32_t n, const char *raw)
{
  uint32_t i;
  for (i = 0; i < n; i++)
    if (e[i].raw_len == strlen(raw) && memcmp(e[i].raw, raw, e[i].raw_len) == 0) return &e[i];
  return NULL;
}

static void free_ents(vfs_dirent *e, uint32_t n)
{
  uint32_t i;
  for (i = 0; i < n; i++) {
    sd_free(e[i].raw);
    sd_free(e[i].wname);
    sd_free(e[i].key);
  }
}

SD_TEST(vfs_case_collisions_mangle_by_byte_order)
{
  vfs_dirent e[5];
  ent(&e[0], "readme", TRUE);
  ent(&e[1], "README", TRUE);
  ent(&e[2], "Readme.txt", TRUE);
  ent(&e[3], "README.TXT", TRUE);
  ent(&e[4], "readme~c2", TRUE);    /* the first candidate already exists: N moves on */
  SD_CHECK_EQ_INT(vfs_mangle_collisions(e, 5, TRUE), 2);
  SD_CHECK(wide_eq(by_raw(e, 5, "README")->wname, L"README"));        /* byte order: 'R' < 'r' */
  SD_CHECK(wide_eq(by_raw(e, 5, "readme")->wname, L"readme~c3"));
  SD_CHECK(wide_eq(by_raw(e, 5, "README.TXT")->wname, L"README.TXT"));
  SD_CHECK(wide_eq(by_raw(e, 5, "Readme.txt")->wname, L"Readme~c2.txt"));
  SD_CHECK(wide_eq(by_raw(e, 5, "readme~c2")->wname, L"readme~c2"));
  free_ents(e, 5);
}

SD_TEST(vfs_identical_display_names_collide_in_sensitive_view)
{
  /* Remote "a:" and remote "a" + U+F03A have the same Windows name (TM-R12). */
  vfs_dirent e[3];
  ent(&e[0], "a\xEF\x80\xBA", FALSE);
  ent(&e[1], "a:", FALSE);
  ent(&e[2], "A:", FALSE);           /* differs by case only: no collision in the sensitive view */
  SD_CHECK_EQ_INT(vfs_mangle_collisions(e, 3, FALSE), 1);
  SD_CHECK(wide_eq(by_raw(e, 3, "a:")->wname, L"a\xF03A"));
  SD_CHECK(wide_eq(by_raw(e, 3, "a\xEF\x80\xBA")->wname, L"a\xF03A~c2"));
  SD_CHECK(wide_eq(by_raw(e, 3, "A:")->wname, L"A\xF03A"));
  free_ents(e, 3);
}
