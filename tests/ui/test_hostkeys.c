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

/* ---- "Add key from server..." model ---- */

SD_TEST(hk_target_parse_forms)
{
  ui_hk_target t;
  SD_CHECK(ui_hk_target_parse("Example.ORG", &t));
  SD_CHECK_STR(t.host, "example.org");
  SD_CHECK_EQ_INT((int)t.port, 22);
  SD_CHECK_STR(t.lookup, "example.org");

  SD_CHECK(ui_hk_target_parse("  example.org:2222 \t", &t));
  SD_CHECK_STR(t.host, "example.org");
  SD_CHECK_EQ_INT((int)t.port, 2222);
  SD_CHECK_STR(t.lookup, "[example.org]:2222");

  SD_CHECK(ui_hk_target_parse("example.org:22", &t));                 /* the default port keeps the plain name */
  SD_CHECK_STR(t.lookup, "example.org");

  SD_CHECK(ui_hk_target_parse("[::1]:2200", &t));
  SD_CHECK_STR(t.host, "::1");
  SD_CHECK_EQ_INT((int)t.port, 2200);
  SD_CHECK_STR(t.lookup, "[::1]:2200");
  SD_CHECK(ui_hk_target_parse("[fe80::1]", &t));
  SD_CHECK_STR(t.lookup, "fe80::1");
  SD_CHECK(ui_hk_target_parse("2001:db8::7", &t));                    /* bare IPv6: no port */
  SD_CHECK_EQ_INT((int)t.port, 22);
  SD_CHECK_STR(t.host, "2001:db8::7");
  SD_CHECK(ui_hk_target_parse("192.168.0.5", &t));
  SD_CHECK(ui_hk_target_parse("xn--bcher-kva.example", &t));
  SD_CHECK(ui_hk_target_parse("my_host-1.lan", &t));
}

SD_TEST(hk_target_parse_refusals)
{
  ui_hk_target t;
  char longname[400];
  SD_CHECK(!ui_hk_target_parse(NULL, &t));
  SD_CHECK(!ui_hk_target_parse("", &t));
  SD_CHECK(!ui_hk_target_parse("   ", &t));
  SD_CHECK(!ui_hk_target_parse("user@example.org", &t));
  SD_CHECK(!ui_hk_target_parse("example.org:0", &t));
  SD_CHECK(!ui_hk_target_parse("example.org:65536", &t));
  SD_CHECK(!ui_hk_target_parse("example.org:", &t));
  SD_CHECK(!ui_hk_target_parse("example.org:22x", &t));
  SD_CHECK(!ui_hk_target_parse("exa mple.org", &t));
  SD_CHECK(!ui_hk_target_parse("ex?mple.org", &t));                   /* a non-ASCII character reaches here as a question mark */
  SD_CHECK(!ui_hk_target_parse("\"quote\".org", &t));
  SD_CHECK(!ui_hk_target_parse("a\\b", &t));
  SD_CHECK(!ui_hk_target_parse("[::1", &t));
  SD_CHECK(!ui_hk_target_parse("[]:22", &t));
  SD_CHECK(!ui_hk_target_parse("[::1]x", &t));
  SD_CHECK(!ui_hk_target_parse("-leading.example", &t));
  SD_CHECK(!ui_hk_target_parse(".leading.example", &t));
  memset(longname, 'a', sizeof(longname) - 1);
  longname[sizeof(longname) - 1] = '\0';
  SD_CHECK(!ui_hk_target_parse(longname, &t));
  SD_CHECK(t.host[0] == '\0');                                        /* a refusal leaves nothing behind */
}

SD_TEST(hk_add_params_json)
{
  ui_hk_target t;
  char buf[256], tiny[16];
  sd_json *j = NULL;
  int64_t port = 0;
  SD_REQUIRE(ui_hk_target_parse("Example.org:2222", &t));
  SD_CHECK(ui_hk_add_params(&t, NULL, buf, sizeof(buf)) == SD_OK);
  SD_CHECK_STR(buf, "{\"host\":\"example.org\",\"port\":2222,\"lookup\":\"[example.org]:2222\"}");
  SD_REQUIRE(sd_json_parse(buf, strlen(buf), 8, &j) == SD_OK);          /* the agent can read it */
  SD_CHECK_STR(sd_json_get_str(j, "lookup"), "[example.org]:2222");
  SD_CHECK(sd_json_get_int64(j, "port", &port) && port == 2222);
  sd_json_free(j);

  SD_CHECK(ui_hk_add_params(&t, "ssh-ed25519", buf, sizeof(buf)) == SD_OK);
  SD_CHECK(strstr(buf, "\"type\":\"ssh-ed25519\"") != NULL);
  SD_CHECK(ui_hk_add_params(&t, "", buf, sizeof(buf)) == SD_OK);
  SD_CHECK(strstr(buf, "\"type\"") == NULL);

  SD_CHECK(ui_hk_add_params(&t, "SSH\"", buf, sizeof(buf)) == SD_E_INVALID_PARAM);
  SD_CHECK(buf[0] == '\0');
  SD_CHECK(ui_hk_add_params(&t, NULL, tiny, sizeof(tiny)) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_hk_add_params(NULL, NULL, buf, sizeof(buf)) == SD_E_INVALID_PARAM);
  memset(&t, 0, sizeof(t));
  SD_CHECK(ui_hk_add_params(&t, NULL, buf, sizeof(buf)) == SD_E_INVALID_PARAM);

  SD_CHECK(ui_hk_type_ok("ecdsa-sha2-nistp256"));
  SD_CHECK(ui_hk_type_ok("ssh-ed25519"));
  SD_CHECK(!ui_hk_type_ok(""));
  SD_CHECK(!ui_hk_type_ok("SSH-RSA"));
  SD_CHECK(!ui_hk_type_ok("a b"));
}

static sd_json *parse_text(const char *s)
{
  sd_json *j = NULL;
  if (sd_json_parse(s, strlen(s), 16, &j) != SD_OK)
    return NULL;
  return j;
}

SD_TEST(hk_offer_parse_first_contact_and_verified)
{
  ui_hk_offer o;
  wchar_t lines[512];
  sd_json *j = parse_text("{\"host\":\"example.org\",\"lookup_name\":\"example.org\",\"verified\":false,"
                          "\"keys\":[{\"type\":\"ssh-ed25519\",\"fingerprint\":\"SHA256:aaa\"}],\"id\":\"a-3\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK_STR(o.host, "example.org");
  SD_CHECK_EQ_INT(o.verified, 0);
  SD_CHECK_STR(o.id, "a-3");
  SD_CHECK_EQ_INT((int)o.nkeys, 1);
  SD_CHECK_STR(o.keys[0].type, "ssh-ed25519");
  SD_CHECK_STR(o.keys[0].fp, "SHA256:aaa");
  sd_json_free(j);

  j = parse_text("{\"host\":\"h\",\"verified\":true,\"id\":\"a-4\",\"keys\":["
                 "{\"type\":\"ecdsa-sha2-nistp256\",\"fingerprint\":\"SHA256:bbb\"},"
                 "{\"type\":\"ssh-rsa\",\"fingerprint\":\"SHA256:ccc\"}]}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK_EQ_INT(o.verified, 1);
  SD_CHECK_EQ_INT((int)o.nkeys, 2);
  ui_hk_offer_lines(&o, lines, SD_COUNTOF(lines));
  SD_CHECK(wcscmp(lines, L"ecdsa-sha2-nistp256  SHA256:bbb\r\nssh-rsa  SHA256:ccc") == 0);
  ui_hk_offer_lines(&o, lines, 12);                                    /* a small buffer holds no partial line */
  SD_CHECK(lines[0] == L'\0');
  sd_json_free(j);
}

SD_TEST(hk_offer_parse_degenerate_replies)
{
  ui_hk_offer o;
  sd_json *j;
  /* the server offered nothing new: no id, no offer */
  j = parse_text("{\"host\":\"h\",\"verified\":true,\"keys\":[]}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK_EQ_INT((int)o.nkeys, 0);
  SD_CHECK(o.id[0] == '\0');
  sd_json_free(j);
  /* an id with a character the accept request must not carry is dropped with the offer */
  j = parse_text("{\"host\":\"h\",\"id\":\"a-1\\\"}\",\"keys\":[{\"type\":\"t\",\"fingerprint\":\"f\"}]}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK(o.id[0] == '\0');
  SD_CHECK_EQ_INT((int)o.nkeys, 0);
  sd_json_free(j);
  /* keys without a type or a fingerprint are skipped; control characters are shown as question marks */
  j = parse_text("{\"host\":\"h\\u0001x\",\"id\":\"a-2\",\"keys\":[{\"type\":\"t\"},{\"fingerprint\":\"f\"},"
                 "{\"type\":\"ssh-ed25519\",\"fingerprint\":\"SHA256:z\\u0007\"}]}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK_EQ_INT((int)o.nkeys, 1);
  SD_CHECK_STR(o.host, "h?x");
  SD_CHECK_STR(o.keys[0].fp, "SHA256:z?");
  sd_json_free(j);
  /* more keys than the agent ever sends are cut */
  j = parse_text("{\"host\":\"h\",\"id\":\"a-5\",\"keys\":[{\"type\":\"a\",\"fingerprint\":\"1\"},"
                 "{\"type\":\"a\",\"fingerprint\":\"2\"},{\"type\":\"a\",\"fingerprint\":\"3\"},"
                 "{\"type\":\"a\",\"fingerprint\":\"4\"},{\"type\":\"a\",\"fingerprint\":\"5\"},"
                 "{\"type\":\"a\",\"fingerprint\":\"6\"},{\"type\":\"a\",\"fingerprint\":\"7\"},"
                 "{\"type\":\"a\",\"fingerprint\":\"8\"},{\"type\":\"a\",\"fingerprint\":\"9\"}]}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_OK);
  SD_CHECK_EQ_INT((int)o.nkeys, UI_HK_OFFER_KEYS);
  sd_json_free(j);
  /* not an object */
  j = parse_text("[1]");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_hk_offer_parse(j, &o) == SD_E_INVALID_PARAM);
  sd_json_free(j);
  SD_CHECK(ui_hk_offer_parse(NULL, &o) == SD_E_INVALID_PARAM);
}

SD_TEST(hk_add_fail_classes)
{
  SD_CHECK(ui_hk_add_fail_of(SD_E_DISCONNECTED) == UI_HK_ADD_FAIL_AGENT_DOWN);
  SD_CHECK(ui_hk_add_fail_of(SD_E_UNSUPPORTED) == UI_HK_ADD_FAIL_UNSUPPORTED);
  SD_CHECK(ui_hk_add_fail_of(SD_E_HOSTKEY_MISMATCH) == UI_HK_ADD_FAIL_MISMATCH);
  SD_CHECK(ui_hk_add_fail_of(SD_E_HOSTKEY_REJECTED) == UI_HK_ADD_FAIL_REJECTED);
  SD_CHECK(ui_hk_add_fail_of(SD_E_BUSY) == UI_HK_ADD_FAIL_BUSY);
  SD_CHECK(ui_hk_add_fail_of(SD_E_TIMEOUT) == UI_HK_ADD_FAIL_OTHER);
  SD_CHECK(ui_hk_add_fail_of(SD_E_HOSTKEY_TYPE_UNAVAILABLE) == UI_HK_ADD_FAIL_OTHER);
  SD_CHECK(ui_hk_id_ok("a-12"));
  SD_CHECK(!ui_hk_id_ok(""));
  SD_CHECK(!ui_hk_id_ok("a b"));
  SD_CHECK(!ui_hk_id_ok(NULL));
}

SD_TEST(hk_reject_params_json)
{
  char out[64];
  SD_CHECK(ui_hk_reject_params("a-1.b_2", out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "{\"id\":\"a-1.b_2\"}");
  SD_CHECK(ui_hk_reject_params("", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_hk_reject_params("a\"b", out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_hk_reject_params(NULL, out, sizeof(out)) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_hk_reject_params("abc", out, 5) == SD_E_INVALID_PARAM);       /* too small: nothing half written */
  SD_CHECK_STR(out, "");
}

SD_TEST(hk_row_details_follow_the_row)
{
  static const wchar_t *const origins[UI_HK_ORIGINS] = { L"", L"ShellDrive", L"From PuTTY", L"From OpenSSH", L"By server" };
  ui_hk_row r;
  wchar_t v[UI_HK_DETAILS][UI_HK_CELL_MAX];
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "[h.example]:2222", 0, "ssh-ed25519", "SHA256:abc", 7) == SD_OK);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(wcscmp(v[UI_HK_DET_HOST], L"h.example") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_PORT], L"2222") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_TYPE], L"ssh-ed25519") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_FP], L"SHA256:abc") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_STORE], L"User") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_LINE], L"7") == 0);
  /* a row without extras shows no MD5, source, date or comment (the window leaves those lines out) */
  SD_CHECK(v[UI_HK_DET_MD5][0] == 0);
  SD_CHECK(v[UI_HK_DET_ORIGIN][0] == 0);
  SD_CHECK(v[UI_HK_DET_ADDED][0] == 0);
  SD_CHECK(v[UI_HK_DET_COMMENT][0] == 0);

  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_MACHINE, "|1|c2FsdA==|aGFzaA==", 1, "ssh-rsa", "SHA256:x", 12) == SD_OK);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(wcscmp(v[UI_HK_DET_HOST], L"(hashed)") == 0);
  SD_CHECK(v[UI_HK_DET_PORT][0] == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_STORE], L"Machine") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_LINE], L"12") == 0);
}

SD_TEST(hk_row_details_show_comment_added_origin_and_md5)
{
  static const wchar_t *const origins[UI_HK_ORIGINS] = { L"", L"ShellDrive", L"From PuTTY", L"From OpenSSH", L"By server" };
  ui_hk_row r;
  wchar_t v[UI_HK_DETAILS][UI_HK_CELL_MAX];
  char longtext[400];
  SD_CHECK(ui_hk_row_init(&r, UI_HK_STORE_USER, "example.org", 0, "ssh-ed25519", "SHA256:abc", 2) == SD_OK);
  ui_hk_row_set_extras(&r, "MD5:aa:bb", "imported-from=putty added=2026-10-24", "2026-10-24", UI_HK_ORIGIN_PUTTY);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(wcscmp(v[UI_HK_DET_MD5], L"MD5:aa:bb") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_ORIGIN], L"From PuTTY") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_ADDED], L"2026-10-24") == 0);
  SD_CHECK(wcscmp(v[UI_HK_DET_COMMENT], L"imported-from=putty added=2026-10-24") == 0);

  /* the origin "other" and an origin out of range say nothing; every named origin has its own text */
  ui_hk_row_set_extras(&r, NULL, NULL, NULL, UI_HK_ORIGIN_OTHER);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(v[UI_HK_DET_ORIGIN][0] == 0 && v[UI_HK_DET_MD5][0] == 0);
  ui_hk_row_set_extras(&r, NULL, NULL, NULL, 99);
  SD_CHECK_EQ_INT(r.origin, UI_HK_ORIGIN_OTHER);
  ui_hk_row_set_extras(&r, NULL, NULL, NULL, UI_HK_ORIGIN_SERVER);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(wcscmp(v[UI_HK_DET_ORIGIN], L"By server") == 0);
  ui_hk_row_set_extras(&r, NULL, NULL, NULL, UI_HK_ORIGIN_OPENSSH);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(wcscmp(v[UI_HK_DET_ORIGIN], L"From OpenSSH") == 0);

  /* text from a file is cut to the fields and shown as printable ASCII */
  memset(longtext, 'x', sizeof(longtext) - 1);
  longtext[sizeof(longtext) - 1] = 0;
  longtext[3] = '\t';
  ui_hk_row_set_extras(&r, NULL, longtext, NULL, UI_HK_ORIGIN_SHELLDRIVE);
  SD_CHECK(strlen(r.comment) == UI_HK_COMMENT_MAX - 1);
  ui_hk_row_details(&r, L"(hashed)", L"Machine", L"User", origins, v);
  SD_CHECK(v[UI_HK_DET_COMMENT][3] == L'?');
  SD_CHECK_EQ_INT((int)wcslen(v[UI_HK_DET_COMMENT]), UI_HK_COMMENT_MAX - 1);
}

static int extras_cb(void *vctx, const sd_kh_all_entry *e)
{
  ui_hk_row *r = (ui_hk_row *)vctx;
  char md5[64];
  if (sd_hostkey_fingerprint_md5(e->blob, e->len, md5) != SD_OK)
    md5[0] = 0;
  if (ui_hk_row_init(r, UI_HK_STORE_USER, e->pattern, e->hashed, e->type, "SHA256:x", e->line) != SD_OK)
    return 1;
  ui_hk_row_set_extras(r, md5, e->comment, e->added, (int)e->origin);
  return 1;
}

/* What the window does with a line of the store: the comment, the added date and the origin of
   sd_known_hosts_list_all, and the MD5 fingerprint of the key, end up in the row. */
SD_TEST(hk_store_extras_reach_the_row)
{
  wchar_t path[MAX_PATH];
  sd_kh_store stores[1];
  sd_known_hosts *kh = NULL;
  ui_hk_row r;
  memset(&r, 0, sizeof(r));
  temp_file(path, SD_COUNTOF(path));
  SD_REQUIRE(path[0] != L'\0');
  SD_REQUIRE(write_text(path, "example.org ssh-rsa " KEY_B64 " # imported-from=openssh added=2026-10-24\r\n"));
  memset(stores, 0, sizeof(stores));
  stores[0].kind = SD_KH_STORE_USER;
  stores[0].path = path;
  stores[0].writable = 1;
  SD_REQUIRE(sd_known_hosts_open(stores, 1, &kh) == SD_OK);
  SD_CHECK(sd_known_hosts_list_all(kh, SD_KH_STORE_USER, extras_cb, &r) == SD_OK);
  SD_CHECK_EQ_INT(r.origin, UI_HK_ORIGIN_OPENSSH);
  SD_CHECK_STR(r.added, "2026-10-24");
  SD_CHECK(strstr(r.comment, "imported-from=openssh") != NULL);
  SD_CHECK(strncmp(r.md5, "MD5:", 4) == 0);
  sd_known_hosts_close(kh);
  DeleteFileW(path);
}
