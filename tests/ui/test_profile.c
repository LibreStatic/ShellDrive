/* Profile editor model and .sdmount grammar (apps/shelldrive-ui/ui_profile_model.c, ui_sdmount.c). Pure: no window,
   file or agent calls. The validation uses sd_config's sd_profile_validate, so sd_config is linked into the test. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "ui_profile_model.h"
#include "ui_sdmount.h"

#define TEST_ID "0123456789abcdef0123456789abcdef"

static sd_err parse_text(const char *s, char id[33])
{
  return ui_sdmount_parse((const unsigned char *)s, strlen(s), id);
}

SD_TEST(sdmount_accepts_one_profile_line)
{
  char id[33];
  static const char plain[] = "profile = " TEST_ID "\n";
  static const char crlf[] = "profile=" TEST_ID "\r\n";
  static const char comments[] = "# my drive\n\n; note\n   profile\t=\t" TEST_ID "   \n";
  static const char bom[] = "\xEF\xBB\xBFprofile = " TEST_ID;
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)plain, strlen(plain), id), SD_OK);
  SD_CHECK(strcmp(id, TEST_ID) == 0);
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)crlf, strlen(crlf), id), SD_OK);
  SD_CHECK(strcmp(id, TEST_ID) == 0);
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)comments, strlen(comments), id), SD_OK);
  SD_CHECK(strcmp(id, TEST_ID) == 0);
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)bom, strlen(bom), id), SD_OK);
  SD_CHECK(strcmp(id, TEST_ID) == 0);
}

SD_TEST(sdmount_rejects_anything_else)
{
  char id[33];
  static const char other_key[] = "profile = " TEST_ID "\nhost = example.org\n";
  static const char two_profiles[] = "profile = " TEST_ID "\nprofile = " TEST_ID "\n";
  static const char upper_hex[] = "profile = 0123456789ABCDEF0123456789ABCDEF\n";
  static const char short_id[] = "profile = 0123\n";
  static const char no_value[] = "profile =\n";
  static const char prefix_key[] = "profile_x = " TEST_ID "\n";
  static const char empty_file[] = "# only a comment\n";
  static const char trailing_text[] = "profile = " TEST_ID " extra\n";
  static const char bad_utf8[] = "profile = \xFF\xFE\n";
  static const char nul_byte[] = "profile = " TEST_ID "\0\n";
  SD_CHECK_EQ_INT(parse_text(other_key, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(two_profiles, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(upper_hex, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(short_id, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(no_value, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(prefix_key, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(empty_file, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(parse_text(trailing_text, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)bad_utf8, strlen(bad_utf8), id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_sdmount_parse((const unsigned char *)nul_byte, sizeof(nul_byte) - 2, id), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_sdmount_parse(NULL, 0, id), SD_E_INVALID_PARAM);
}

SD_TEST(sdmount_size_limit)
{
  char id[33];
  unsigned char *big = (unsigned char *)sd_calloc(1, UI_SDMOUNT_MAX_BYTES + 2u);
  size_t i;
  SD_CHECK(big != NULL);
  if (big == NULL)
    return;
  memset(big, '#', UI_SDMOUNT_MAX_BYTES + 1u);
  SD_CHECK_EQ_INT(ui_sdmount_parse(big, UI_SDMOUNT_MAX_BYTES + 1u, id), SD_E_INVALID_PARAM);
  /* exactly 4096 bytes: a comment line and the profile line at the end */
  memset(big, '#', UI_SDMOUNT_MAX_BYTES);
  i = UI_SDMOUNT_MAX_BYTES - 1u - 32u - 10u;
  memcpy(big + i, "profile = ", 10);
  memcpy(big + i + 10, TEST_ID, 32);
  big[i - 1] = '\n';
  big[UI_SDMOUNT_MAX_BYTES - 1u] = '\n';
  SD_CHECK_EQ_INT(ui_sdmount_parse(big, UI_SDMOUNT_MAX_BYTES, id), SD_OK);
  sd_free(big);
}

/* Every field goes profile -> text -> profile -> text and the text is the same both times. */
SD_TEST(profile_form_round_trip)
{
  /* two profiles are about 26 KB: static, not on the stack (/analyze C6262) */
  static sd_profile p, q;
  int f;
  sd_profile_defaults(&p);
  strcpy_s(p.name, sizeof(p.name), "Work NAS");
  strcpy_s(p.host, sizeof(p.host), "nas.example.org");
  p.port = 2222;
  strcpy_s(p.user, sizeof(p.user), "facu");
  strcpy_s(p.remote_path, sizeof(p.remote_path), "/srv/share");
  strcpy_s(p.identity, sizeof(p.identity), "C:\\Users\\facu\\.ssh\\id_ed25519");
  p.auth_methods = SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD;
  p.identities_only = SD_PROFILE_UNSET;
  p.agent = SD_PROFILE_AGENT_OPENSSH;
  p.save_password = 1;
  p.proxy[0].kind = SD_PROFILE_PROXY_SOCKS5;
  strcpy_s(p.proxy[0].host, sizeof(p.proxy[0].host), "proxy.example.org");
  p.proxy[0].port = 1080;
  p.connections = 3;
  p.keepalive_ms = 15000;
  strcpy_s(p.target, sizeof(p.target), "E:");
  p.backend = SD_PROFILE_BACKEND_WEBDAV;
  p.read_only = 1;
  p.write_mode = SD_PROFILE_WRITE_BEHIND;
  p.symlinks = SD_PROFILE_SYMLINKS_HIDE;
  strcpy_s(p.label, sizeof(p.label), "Projects");
  p.network_location = 1;
  p.legacy_algorithms = SD_PROFILE_LEGACY_REFUSE;
  p.update_host_keys = SD_PROFILE_HKU_NO;
  p.refuse_terrapin_exposed = 1;

  sd_profile_defaults(&q);
  for (f = 0; f < UI_PF_COUNT; f++) {
    char a[UI_PF_TEXT_MAX], b[UI_PF_TEXT_MAX];
    SD_CHECK_EQ_INT(ui_pform_get(&p, (ui_pfield)f, a, sizeof(a)), SD_OK);
    SD_CHECK_EQ_INT(ui_pform_set(&q, (ui_pfield)f, a), SD_OK);
    SD_CHECK_EQ_INT(ui_pform_get(&q, (ui_pfield)f, b, sizeof(b)), SD_OK);
    SD_CHECK(strcmp(a, b) == 0);
  }
  SD_CHECK(strcmp(q.name, "Work NAS") == 0);
  SD_CHECK(strcmp(q.target, "E:") == 0);
  SD_CHECK_EQ_INT(q.port, 2222);
  SD_CHECK_EQ_INT(q.identities_only, SD_PROFILE_UNSET);
  SD_CHECK_EQ_INT(q.auth_methods, SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD);
  SD_CHECK_EQ_INT(q.refuse_terrapin_exposed, 1);
}

SD_TEST(profile_form_set_rejects_bad_text)
{
  sd_profile p;
  char long_name[200];
  sd_profile_defaults(&p);
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_PORT, "70000"), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_PORT, "abc"), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_PORT, ""), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_READ_ONLY, "2"), SD_E_INVALID_PARAM);
  memset(long_name, 'n', sizeof(long_name) - 1);
  long_name[sizeof(long_name) - 1] = 0;
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_NAME, long_name), SD_E_INVALID_PARAM);
  SD_CHECK(p.name[0] == 0);
  /* a value with spaces around it is trimmed */
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_HOST, "  nas.example.org \t"), SD_OK);
  SD_CHECK(strcmp(p.host, "nas.example.org") == 0);
  /* identities_only takes -1, 0 and 1 */
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_IDENTITIES_ONLY, "1"), SD_OK);
  SD_CHECK_EQ_INT(p.identities_only, 1);
  SD_CHECK_EQ_INT(ui_pform_set(&p, UI_PF_IDENTITIES_ONLY, "-1"), SD_OK);
  SD_CHECK_EQ_INT(p.identities_only, SD_PROFILE_UNSET);
}

SD_TEST(profile_form_validation_fields)
{
  sd_profile p;
  ui_pferr errs[16];
  size_t n;
  sd_profile_defaults(&p);

  /* name and host are required */
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK(n >= 2);
  SD_CHECK(errs[0].field == UI_PF_NAME && errs[0].code == UI_PERR_NAME);
  SD_CHECK(errs[1].field == UI_PF_HOST && errs[1].code == UI_PERR_HOST);

  strcpy_s(p.name, sizeof(p.name), "Office");
  strcpy_s(p.host, sizeof(p.host), "office.example.org");
  p.port = 22;
  /* the rules of sd_config apply to what the UI checks did not catch: a fine profile has no errors */
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 0);

  p.auth_methods = 0;
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 1);
  SD_CHECK(errs[0].field == UI_PF_METHOD_PUBLICKEY && errs[0].code == UI_PERR_METHODS);
  p.auth_methods = SD_PROFILE_AUTH_PASSWORD;

  p.connections = 5;
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 1);
  SD_CHECK(errs[0].field == UI_PF_CONNECTIONS && errs[0].code == UI_PERR_CONNECTIONS);
  p.connections = 2;

  p.proxy[0].kind = SD_PROFILE_PROXY_HTTP;
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 2);
  SD_CHECK(errs[0].field == UI_PF_PROXY_HOST && errs[0].code == UI_PERR_PROXY_HOST);
  SD_CHECK(errs[1].field == UI_PF_PROXY_PORT && errs[1].code == UI_PERR_PROXY_PORT);
  p.proxy[0].kind = SD_PROFILE_PROXY_NONE;

  /* a value sd_config rejects, with no field check of its own, is mapped to its field */
  p.backend = 7;
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 1);
  SD_CHECK(errs[0].field == UI_PF_BACKEND && errs[0].code == UI_PERR_OTHER);
  p.backend = SD_PROFILE_BACKEND_AUTO;

  p.port = 0;
  n = ui_pform_validate(&p, errs, 16);
  SD_CHECK_EQ_INT(n, 1);
  SD_CHECK(errs[0].field == UI_PF_PORT && errs[0].code == UI_PERR_PORT);
}

SD_TEST(free_drive_letters)
{
  wchar_t out[UI_DRIVE_CANDIDATES][3];
  size_t n;
  n = ui_drive_free_list(0, out);
  SD_CHECK_EQ_INT((int)n, UI_DRIVE_CANDIDATES);
  SD_CHECK(wcscmp(out[0], L"D:") == 0);
  SD_CHECK(wcscmp(out[n - 1], L"Z:") == 0);

  /* C: and D: in use: the first free letter is E: */
  n = ui_drive_free_list((1u << 2) | (1u << 3), out);
  SD_CHECK_EQ_INT((int)n, UI_DRIVE_CANDIDATES - 1);
  SD_CHECK(wcscmp(out[0], L"E:") == 0);

  /* every letter used */
  n = ui_drive_free_list(0x03FFFFFFu, out);
  SD_CHECK_EQ_INT((int)n, 0);

  /* A: and B: are never offered, even when they are free */
  n = ui_drive_free_list(0, out);
  SD_CHECK(wcscmp(out[0], L"A:") != 0 && wcscmp(out[0], L"B:") != 0);
}

SD_TEST(json_escape_and_mount_params)
{
  char esc[64];
  char params[1024];
  sd_profile p;
  SD_CHECK_EQ_INT(ui_json_escape("a\"b\\c\n", esc, sizeof(esc)), SD_OK);
  SD_CHECK(strcmp(esc, "a\\\"b\\\\c\\u000a") == 0);
  SD_CHECK_EQ_INT(ui_json_escape("abcdef", esc, 4), SD_E_INVALID_PARAM);

  sd_profile_defaults(&p);
  strcpy_s(p.id, sizeof(p.id), TEST_ID);
  SD_CHECK_EQ_INT(ui_mount_params_json(&p, 0, "auto", 1, NULL, params, sizeof(params)), SD_OK);
  SD_CHECK(strcmp(params, "{\"profile\":\"" TEST_ID "\",\"target\":\"auto\",\"read_only\":true}") == 0);

  sd_profile_defaults(&p);
  strcpy_s(p.host, sizeof(p.host), "nas.example.org");
  p.port = 2200;
  strcpy_s(p.user, sizeof(p.user), "a\"b");
  SD_CHECK_EQ_INT(ui_mount_params_json(&p, 1, "E:", 0, "webdav", params, sizeof(params)), SD_OK);
  SD_CHECK(strstr(params, "\"adhoc\":{\"host\":\"nas.example.org\",\"port\":2200,\"user\":\"a\\\"b\"}") != NULL);
  SD_CHECK(strstr(params, "\"target\":\"E:\"") != NULL);
  SD_CHECK(strstr(params, "\"backend\":\"webdav\"") != NULL);
  SD_CHECK(strstr(params, "read_only") == NULL);
  SD_CHECK_EQ_INT(ui_mount_params_json(&p, 1, "E:", 0, NULL, params, 20), SD_E_INVALID_PARAM);
  SD_CHECK(params[0] == 0);
}
