/* Host key manager: row formatting (apps/shelldrive-ui/ui_hostkeys_model.c) and the known_hosts enumeration the
   window uses (sd_known_hosts_list_all, sd_known_hosts_remove_key). The stores are files in a temporary folder;
   no user or machine store is touched. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ssh/sd_known_hosts.h"
#include "ui_hostkeys_model.h"

#define KEY_B64 "AAAAB3NzaC1yc2EAAAADAQABAAABAQ=="

SD_TEST(hk_row_plain_and_bracketed_hosts)
{
  ui_hk_row r;
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "example.org", 0, "ssh-ed25519", "SHA256:abc", 3) == SD_OK);
  SD_CHECK_STR(r.host, "example.org");
  SD_CHECK_EQ_INT((int)r.port, 22);
  SD_CHECK_EQ_INT(r.removable, 1);
  SD_CHECK_STR(r.lookup, "example.org");
  SD_CHECK_EQ_INT((int)r.line, 3);

  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "[h.example]:2222", 0, "ecdsa-sha2-nistp256", "SHA256:x", 4) ==
           SD_OK);
  SD_CHECK_STR(r.host, "h.example");
  SD_CHECK_EQ_INT((int)r.port, 2222);
  SD_CHECK_EQ_INT(r.removable, 1);
  SD_CHECK_STR(r.lookup, "[h.example]:2222");

  /* malformed brackets and port 0 are shown as written and cannot be removed */
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "[h.example]:0", 0, "rsa-sha2-256", "SHA256:x", 5) == SD_OK);
  SD_CHECK_EQ_INT(r.removable, 0);
  SD_CHECK_EQ_INT((int)r.port, 22);
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "[h.example", 0, "rsa-sha2-256", "SHA256:x", 5) == SD_OK);
  SD_CHECK_EQ_INT(r.removable, 0);
}

SD_TEST(hk_row_lists_wildcards_and_hashed_entries)
{
  ui_hk_row r;
  wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX];
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "a.example,b.example", 0, "ssh-ed25519", "SHA256:x", 1) == SD_OK);
  SD_CHECK_EQ_INT(r.removable, 0);
  SD_CHECK_STR(r.host, "a.example,b.example");

  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "*.example.org", 0, "ssh-ed25519", "SHA256:x", 2) == SD_OK);
  SD_CHECK_EQ_INT(r.removable, 0);

  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_MACHINE, "|1|c2FsdA==|aGFzaA==", 1, "ssh-ed25519", "SHA256:x", 9) ==
           SD_OK);
  SD_CHECK_EQ_INT(r.hashed, 1);
  SD_CHECK_EQ_INT(r.removable, 0);
  ui_hk_row_cells(&r, L"(hashed)", L"Machine", L"User", cells);
  SD_CHECK(wcscmp(cells[0], L"(hashed)") == 0);
  SD_CHECK(cells[1][0] == L'\0');                              /* no port for a hashed entry */
  SD_CHECK(wcscmp(cells[2], L"ssh-ed25519") == 0);
  SD_CHECK(wcscmp(cells[3], L"SHA256:x") == 0);
  SD_CHECK(wcscmp(cells[4], L"Machine") == 0);                  /* machine store source */
}

SD_TEST(hk_row_cells_and_source_labels)
{
  ui_hk_row r;
  wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX];
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "[h.example]:2222", 0, "ecdsa-sha2-nistp256", "SHA256:abc", 4) ==
           SD_OK);
  ui_hk_row_cells(&r, L"(hashed)", L"Machine", L"User", cells);
  SD_CHECK(wcscmp(cells[0], L"h.example") == 0);
  SD_CHECK(wcscmp(cells[1], L"2222") == 0);
  SD_CHECK(wcscmp(cells[2], L"ecdsa-sha2-nistp256") == 0);
  SD_CHECK(wcscmp(cells[3], L"SHA256:abc") == 0);
  SD_CHECK(wcscmp(cells[4], L"User") == 0);

  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_MACHINE, "example.org", 0, "ssh-ed25519", "SHA256:q", 1) == SD_OK);
  ui_hk_row_cells(&r, L"(hashed)", L"Machine", L"User", cells);
  SD_CHECK(wcscmp(cells[4], L"Machine") == 0);

  /* bad input is refused */
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "", 0, "ssh-ed25519", "SHA256:x", 1) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_hk_row_init(&r, (ui_hk_store)7, "a", 0, "ssh-ed25519", "SHA256:x", 1) == SD_E_INVALID_PARAM);
}

SD_TEST(hk_announcement_cells)
{
  wchar_t cells[4][UI_HK_CELL_MAX];
  ui_hk_announce_cells("example.org", 1, "ssh-ed25519", "SHA256:n", L"Add", L"Remove", cells);
  SD_CHECK(wcscmp(cells[0], L"example.org") == 0);
  SD_CHECK(wcscmp(cells[1], L"Add") == 0);
  SD_CHECK(wcscmp(cells[2], L"ssh-ed25519") == 0);
  SD_CHECK(wcscmp(cells[3], L"SHA256:n") == 0);
  ui_hk_announce_cells("example.org", 0, "rsa-sha2-256", "SHA256:o", L"Add", L"Remove", cells);
  SD_CHECK(wcscmp(cells[1], L"Remove") == 0);
}

/* ---- known_hosts files in a temporary folder ---- */

static void temp_file(wchar_t *out, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  out[0] = L'\0';
  if (n == 0 || n > MAX_PATH - 40)
    return;
  wcscpy_s(out, cch, tmp);
  wcscat_s(out, cch, L"sd-test-ui-hostkeys-");
  {
    wchar_t num[16];
    _snwprintf_s(num, SD_COUNTOF(num), _TRUNCATE, L"%lu", (unsigned long)GetCurrentProcessId());
    wcscat_s(out, cch, num);
  }
  wcscat_s(out, cch, L".txt");
}

static int write_text(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD w = 0;
  size_t n = strlen(text);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!WriteFile(h, text, (DWORD)n, &w, NULL) || w != n) {
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  return 1;
}

typedef struct list_ctx {
  int plain, hashed;
  char pattern[8][256];
  uint8_t blob[256];                 /* blob of the first plain entry */
  size_t blen;
} list_ctx;

static int list_cb(void *vctx, const sd_kh_all_entry *e)
{
  list_ctx *c = (list_ctx *)vctx;
  if (e->hashed)
    c->hashed++;
  else
    c->plain++;
  if (c->plain + c->hashed <= 8)
    strcpy_s(c->pattern[c->plain + c->hashed - 1], sizeof(c->pattern[0]), e->pattern);
  if (!e->hashed && c->plain == 1 && e->len <= sizeof(c->blob)) {
    memcpy(c->blob, e->blob, e->len);
    c->blen = e->len;
  }
  return 0;
}

SD_TEST(hk_store_enumeration_and_remove)
{
  wchar_t path[MAX_PATH];
  sd_kh_store stores[1];
  sd_known_hosts *kh = NULL;
  list_ctx c;
  sd_err e;
  memset(&c, 0, sizeof(c));

  temp_file(path, SD_COUNTOF(path));
  SD_REQUIRE(path[0] != L'\0');
  SD_REQUIRE(write_text(path,
                        "# comment line\r\n"
                        "example.org ssh-rsa " KEY_B64 " # added=2026-10-27\r\n"
                        "[h.example]:2222 ssh-rsa " KEY_B64 "\r\n"
                        "|1|c2FsdA==|aGFzaA== ssh-rsa " KEY_B64 "\r\n"
                        "@revoked bad.example ssh-rsa " KEY_B64 "\r\n"
                        "broken line\r\n"));

  memset(stores, 0, sizeof(stores));
  stores[0].kind = SD_KH_STORE_USER;
  stores[0].path = path;
  stores[0].writable = 1;
  SD_REQUIRE(sd_known_hosts_open(stores, 1, &kh) == SD_OK);

  memset(&c, 0, sizeof(c));
  SD_CHECK(sd_known_hosts_list_all(kh, SD_KH_STORE_USER, list_cb, &c) == SD_OK);
  SD_CHECK_EQ_INT(c.plain, 2);                               /* @revoked lines are not listed */
  SD_CHECK_EQ_INT(c.hashed, 1);
  SD_CHECK(strcmp(c.pattern[0], "example.org") == 0);
  SD_CHECK(strcmp(c.pattern[1], "[h.example]:2222") == 0);
  SD_CHECK(c.pattern[2][0] == '|');

  /* a store that is not a file store cannot be enumerated */
  SD_CHECK(sd_known_hosts_list_all(kh, SD_KH_SRC_OPENSSH, list_cb, &c) == SD_E_INVALID_PARAM);

  /* the removal the window does: one key of one host, addressed by its blob */
  SD_REQUIRE(c.blen > 0);
  e = sd_known_hosts_remove_key(kh, SD_KH_STORE_USER, "example.org", c.blob, c.blen);
  SD_CHECK(e == SD_OK);
  memset(&c, 0, sizeof(c));
  SD_CHECK(sd_known_hosts_list_all(kh, SD_KH_STORE_USER, list_cb, &c) == SD_OK);
  SD_CHECK_EQ_INT(c.plain, 1);
  SD_CHECK(strcmp(c.pattern[0], "[h.example]:2222") == 0);

  sd_known_hosts_close(kh);
  DeleteFileW(path);
}
