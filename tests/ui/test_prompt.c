/* Prompt model (apps/shelldrive-ui/ui_prompt_model.c): prompt.request objects of every kind are parsed into
   the dialog model, server text is sanitized, and the prompt.answer JSON is built with the secrets wiped
   afterwards. The JSON shapes are the ones the agent sends (apps/shelldrive-host/agent.c on_prompt) and reads
   (handle_prompt_answer). No window, no pipe, no agent. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "ui_prompt_model.h"

/* Parses a JSON text and returns the root (caller frees with sd_json_free), or NULL. */
static sd_json *parse_text(const char *text)
{
  sd_json *root = NULL;
  if (sd_json_parse(text, strlen(text), 32, &root) != SD_OK)
    return NULL;
  return root;
}

/* Parses the prompt.request data object in text into out. */
static sd_err parse_request(const char *text, ui_prompt *out)
{
  sd_json *root = parse_text(text);
  sd_err e;
  if (root == NULL)
    return SD_E_INVALID_PARAM;
  e = ui_prompt_parse(root, out);
  sd_json_free(root);
  return e;
}

SD_TEST(prompt_kind_names)
{
  SD_CHECK(ui_prompt_kind_from_name("hostkey_unknown") == UI_PK_HOSTKEY);
  SD_CHECK(ui_prompt_kind_from_name("hostkey_changed") == UI_PK_HOSTKEY_CHANGED);
  SD_CHECK(ui_prompt_kind_from_name("password") == UI_PK_PASSWORD);
  SD_CHECK(ui_prompt_kind_from_name("passphrase") == UI_PK_PASSPHRASE);
  SD_CHECK(ui_prompt_kind_from_name("kbdint") == UI_PK_KBDINT);
  SD_CHECK(ui_prompt_kind_from_name("password_change") == UI_PK_PASSWORD_CHANGE);
  SD_CHECK(ui_prompt_kind_from_name("legacy_ack") == UI_PK_LEGACY_ACK);
  SD_CHECK(ui_prompt_kind_from_name("proxy_password") == UI_PK_PROXY_PASSWORD);
  SD_CHECK(ui_prompt_kind_from_name("webdav_token_only") == UI_PK_WEBDAV_TOKEN_ONLY);
  SD_CHECK(ui_prompt_kind_from_name("made_up") == UI_PK_NONE);
  SD_CHECK(ui_prompt_kind_from_name(NULL) == UI_PK_NONE);
}

SD_TEST(prompt_parse_hostkey_new_identity)
{
  static const char text[] =
    "{\"prompt_id\":\"p-3-7\",\"kind\":\"hostkey_unknown\",\"mount_id\":\"m-3\",\"profile_id\":\"web\","
    "\"profile_name\":\"Web server\",\"host\":\"example.org\",\"port\":2222,\"user\":\"deploy\",\"hop\":2,\"hops\":2,"
    "\"via_host\":\"bastion.example.org\",\"is_reconnect\":false,\"key_type\":\"ED25519\",\"key_bits\":256,"
    "\"fingerprint\":\"SHA256:4bWb1x\",\"lookup_name\":\"example.org\",\"can_save\":false,\"queued\":true,"
    "\"deadline_ms\":119000}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_REQUIRE(parse_request(text, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_HOSTKEY);
  SD_CHECK_STR(p.prompt_id, "p-3-7");
  SD_CHECK_STR(p.mount_id, "m-3");
  SD_CHECK(wcscmp(p.profile, L"Web server") == 0);
  SD_CHECK(wcscmp(p.host, L"example.org") == 0);
  SD_CHECK_EQ_INT(p.port, 2222);
  SD_CHECK(wcscmp(p.user, L"deploy") == 0);
  SD_CHECK_EQ_INT(p.hop, 2);
  SD_CHECK_EQ_INT(p.hops, 2);
  SD_CHECK(wcscmp(p.via, L"bastion.example.org") == 0);
  SD_CHECK(wcscmp(p.key_type, L"ED25519") == 0);
  SD_CHECK_EQ_INT(p.key_bits, 256);
  SD_CHECK(wcscmp(p.fingerprint, L"SHA256:4bWb1x") == 0);
  SD_CHECK_EQ_INT(p.can_save, 0);
  SD_CHECK_EQ_INT(p.has_deadline, 1);
  SD_CHECK_EQ_INT(p.deadline_ms, 119000);
  SD_CHECK_EQ_INT(p.item_count, 0);
}

SD_TEST(prompt_parse_hostkey_changed_variant)
{
  static const char text[] =
    "{\"prompt_id\":\"p-1-1\",\"kind\":\"hostkey_changed\",\"mount_id\":\"m-1\",\"host\":\"example.org\","
    "\"port\":22,\"stored_fingerprint\":\"SHA256:old\",\"fingerprint\":\"SHA256:new\"}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_REQUIRE(parse_request(text, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_HOSTKEY_CHANGED);
  SD_CHECK(wcscmp(p.stored_fingerprint, L"SHA256:old") == 0);
  SD_CHECK(wcscmp(p.fingerprint, L"SHA256:new") == 0);
  SD_CHECK_EQ_INT(p.has_deadline, 0);
}

SD_TEST(prompt_parse_password_and_passphrase)
{
  static const char pw[] =
    "{\"prompt_id\":\"p-2-1\",\"kind\":\"password\",\"mount_id\":\"m-2\",\"host\":\"h.example\",\"port\":22,"
    "\"user\":\"ana\",\"hop\":1,\"hops\":1,\"is_reconnect\":true,\"hostkey_just_accepted\":true,"
    "\"round\":0,\"can_save\":true,\"deadline_ms\":600000}";
  static const char pp[] =
    "{\"prompt_id\":\"p-2-2\",\"kind\":\"passphrase\",\"mount_id\":\"m-2\",\"host\":\"h.example\",\"port\":22,"
    "\"user\":\"ana\",\"hop\":1,\"hops\":1,\"key_path\":\"C:\\\\keys\\\\id\",\"key_fingerprint\":\"SHA256:abc\","
    "\"can_save\":true}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */

  SD_REQUIRE(parse_request(pw, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_PASSWORD);
  SD_CHECK_EQ_INT(p.is_reconnect, 1);
  SD_CHECK_EQ_INT(p.hostkey_just_accepted, 1);
  SD_CHECK_EQ_INT(p.can_save, 1);
  SD_CHECK_EQ_INT(p.deadline_ms, 600000);

  SD_REQUIRE(parse_request(pp, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_PASSPHRASE);
  SD_CHECK(wcscmp(p.key_fingerprint, L"SHA256:abc") == 0);
  SD_CHECK_EQ_INT(p.can_save, 1);
  SD_CHECK_EQ_INT(p.has_deadline, 0);
}

SD_TEST(prompt_parse_kbdint_items_and_echo)
{
  static const char text[] =
    "{\"prompt_id\":\"p-4-1\",\"kind\":\"kbdint\",\"mount_id\":\"m-4\",\"host\":\"h\",\"port\":22,\"user\":\"u\","
    "\"kbdint\":{\"name\":\"Second factor\",\"instruction\":\"Enter the code\","
    "\"prompts\":[{\"text\":\"Code: \",\"echo\":false},{\"text\":\"Device: \",\"echo\":true}]},\"can_save\":false}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_REQUIRE(parse_request(text, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_KBDINT);
  SD_CHECK(wcscmp(p.name, L"Second factor") == 0);
  SD_CHECK(wcscmp(p.instruction, L"Enter the code") == 0);
  SD_REQUIRE(p.item_count == 2);
  SD_CHECK(wcscmp(p.items[0].text, L"Code: ") == 0);
  SD_CHECK_EQ_INT(p.items[0].echo, 0);
  SD_CHECK(wcscmp(p.items[1].text, L"Device: ") == 0);
  SD_CHECK_EQ_INT(p.items[1].echo, 1);
}

SD_TEST(prompt_parse_password_change_three_fields)
{
  static const char text[] =
    "{\"prompt_id\":\"p-5-1\",\"kind\":\"password_change\",\"mount_id\":\"m-5\",\"host\":\"h\",\"port\":22,"
    "\"user\":\"u\",\"kbdint\":{\"name\":\"\",\"instruction\":\"\",\"prompts\":["
    "{\"text\":\"Current\",\"echo\":false},{\"text\":\"New\",\"echo\":false},{\"text\":\"Retype\",\"echo\":false}]},"
    "\"can_save\":false}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_REQUIRE(parse_request(text, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_PASSWORD_CHANGE);
  SD_CHECK_EQ_INT(p.item_count, 3);
  SD_CHECK_EQ_INT(p.can_save, 0);
}

SD_TEST(prompt_parse_legacy_and_proxy)
{
  static const char legacy[] =
    "{\"prompt_id\":\"p-6-1\",\"kind\":\"legacy_ack\",\"mount_id\":\"m-6\",\"host\":\"old.example\",\"port\":22,"
    "\"algorithms\":[\"hmac-sha1\",\"3des-cbc\"]}";
  static const char proxy[] =
    "{\"prompt_id\":\"p-6-2\",\"kind\":\"proxy_password\",\"mount_id\":\"m-6\",\"host\":\"h\",\"port\":22,"
    "\"user\":\"ana\",\"round\":0,\"proxy_host\":\"proxy.example.net\",\"proxy_port\":3128,\"can_save\":true}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */

  SD_REQUIRE(parse_request(legacy, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_LEGACY_ACK);
  SD_CHECK(wcscmp(p.algorithms, L"hmac-sha1, 3des-cbc") == 0);

  SD_REQUIRE(parse_request(proxy, &p) == SD_OK);
  SD_CHECK(p.kind == UI_PK_PROXY_PASSWORD);
  SD_CHECK(wcscmp(p.proxy_host, L"proxy.example.net") == 0);
  SD_CHECK_EQ_INT(p.proxy_port, 3128);
  SD_CHECK_EQ_INT(p.can_save, 1);
}

SD_TEST(prompt_parse_rejects_bad_requests)
{
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_CHECK(parse_request("{\"prompt_id\":\"p-1-1\",\"mount_id\":\"m-1\",\"kind\":\"made_up\"}", &p) == SD_E_INVALID_PARAM);
  SD_CHECK(parse_request("{\"mount_id\":\"m-1\",\"kind\":\"password\"}", &p) == SD_E_INVALID_PARAM);
  SD_CHECK(parse_request("{\"prompt_id\":\"p-1-1\",\"kind\":\"password\"}", &p) == SD_E_INVALID_PARAM);
  SD_CHECK(parse_request("[1,2,3]", &p) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_prompt_parse(NULL, &p) == SD_E_INVALID_PARAM);
}

SD_TEST(prompt_server_text_is_sanitized)
{
  /* U+202E (RLO), U+200B (zero width space), U+FEFF (BOM), a C0 control and a DEL are dropped */
  static const char raw[] = "ab\xE2\x80\xAE" "cd\xE2\x80\x8B" "e\x01" "f\xEF\xBB\xBF" "g\x7F" "h";
  wchar_t out[64];
  ui_text_safe(raw, out, SD_COUNTOF(out));
  SD_CHECK(wcscmp(out, L"abcdefgh") == 0);
}

SD_TEST(prompt_server_text_is_capped)
{
  char *big = (char *)sd_alloc(4096);
  wchar_t *out = (wchar_t *)sd_alloc(4096 * sizeof(wchar_t));
  SD_REQUIRE(big != NULL && out != NULL);
  memset(big, 'a', 4000);
  big[4000] = 0;
  ui_text_safe(big, out, 4096);
  /* input is cut at 2 KiB before conversion */
  SD_CHECK(wcslen(out) <= 2048);
  SD_CHECK(wcslen(out) > 0);
  ui_text_safe(big, out, 16);                 /* the output buffer limit is honoured too */
  SD_CHECK(wcslen(out) == 15);
  sd_free(big);
  sd_free(out);
}

SD_TEST(prompt_parse_sanitizes_names_and_text)
{
  static const char text[] =
    "{\"prompt_id\":\"p-9-9\",\"kind\":\"kbdint\",\"mount_id\":\"m-9\","
    "\"profile_name\":\"Bad\xE2\x80\xAE\x66\x61\x6B\x65\",\"host\":\"h\",\"port\":22,"
    "\"kbdint\":{\"name\":\"N\",\"instruction\":\"\",\"prompts\":[{\"text\":\"Pass\\u202eword\",\"echo\":false}]}}";
  static ui_prompt p;                  /* large: static keeps it off the stack (tests run one at a time) */
  SD_REQUIRE(parse_request(text, &p) == SD_OK);
  SD_CHECK(wcscmp(p.profile, L"Badfake") == 0);
  SD_REQUIRE(p.item_count == 1);
  SD_CHECK(wcscmp(p.items[0].text, L"Password") == 0);
}

SD_TEST(prompt_fixtures_have_their_fields)
{
  ui_prompt *p = (ui_prompt *)sd_calloc(1, sizeof(*p));
  SD_REQUIRE(p != NULL);
  ui_prompt_fixture(UI_PK_HOSTKEY, p);
  SD_CHECK(p->kind == UI_PK_HOSTKEY);
  SD_CHECK(p->fingerprint[0] != 0);
  ui_prompt_fixture(UI_PK_PASSWORD_CHANGE, p);
  SD_CHECK_EQ_INT(p->item_count, 3);
  ui_prompt_fixture(UI_PK_LEGACY_ACK, p);
  SD_CHECK(p->algorithms[0] != 0);
  sd_free(p);
}

/* ---- answers ---- */

static void answer_fields(const char *json, sd_json **root)
{
  *root = parse_text(json);
}

SD_TEST(answer_accept_has_no_responses)
{
  char *json = NULL;
  size_t len = 0;
  sd_json *root = NULL;
  sd_err e = ui_prompt_build_answer("p-3-7", "accept", NULL, 0, 0, &json, &len);
  SD_REQUIRE(e == SD_OK && json != NULL);
  answer_fields(json, &root);
  SD_REQUIRE(root != NULL);
  SD_CHECK_STR(sd_json_get_str(root, "prompt_id"), "p-3-7");
  SD_CHECK_STR(sd_json_get_str(root, "action"), "accept");
  SD_CHECK(sd_json_get(root, "responses") == NULL);
  SD_CHECK(sd_json_get(root, "save") == NULL);
  sd_json_free(root);
  ui_secret_free(json, len + 1);
}

SD_TEST(answer_responses_are_escaped_and_utf8)
{
  wchar_t *resp[2];
  wchar_t a[32], b[32];
  char *json = NULL;
  size_t len = 0;
  sd_json *root = NULL;
  const sd_json *arr;
  size_t n;
  sd_err e;

  wcscpy_s(a, SD_COUNTOF(a), L"s3\"cret\\x");
  wcscpy_s(b, SD_COUNTOF(b), L"\x00D1" L"and\x00FA");   /* Ñandú */
  resp[0] = a;
  resp[1] = b;
  e = ui_prompt_build_answer("p-4-1", "answer", resp, 2, 1, &json, &len);
  SD_REQUIRE(e == SD_OK && json != NULL);
  answer_fields(json, &root);
  SD_REQUIRE(root != NULL);
  SD_CHECK_STR(sd_json_get_str(root, "action"), "answer");
  arr = sd_json_get(root, "responses");
  n = sd_json_count(arr);
  SD_REQUIRE(n == 2);
  {
    size_t l0 = 0, l1 = 0;
    const char *r0 = sd_json_str(sd_json_at(arr, 0), &l0);
    const char *r1 = sd_json_str(sd_json_at(arr, 1), &l1);
    SD_REQUIRE(r0 != NULL && r1 != NULL);
    SD_CHECK(l0 == 9 && memcmp(r0, "s3\"cret\\x", 9) == 0);
    SD_CHECK(l1 == strlen("\xC3\x91" "and\xC3\xBA") && memcmp(r1, "\xC3\x91" "and\xC3\xBA", l1) == 0);
  }
  {
    int save = 0;
    SD_CHECK(sd_json_get_bool(root, "save", &save) && save == 1);
  }
  sd_json_free(root);
  ui_secret_free(json, len + 1);
}

SD_TEST(answer_wipes_the_secrets_it_was_given)
{
  wchar_t pw[64];
  wchar_t *resp[1];
  char *json = NULL;
  size_t len = 0, i;
  sd_err e;

  wcscpy_s(pw, SD_COUNTOF(pw), L"hunter2-secret");
  resp[0] = pw;
  e = ui_prompt_build_answer("p-1-1", "answer", resp, 1, 0, &json, &len);
  SD_CHECK(e == SD_OK);
  /* the caller's buffer no longer holds the secret: every unit up to the terminator is zero */
  for (i = 0; i < SD_COUNTOF(pw); i++)
    if (pw[i] == 0)
      break;
  SD_CHECK_EQ_INT(i, 0);
  SD_CHECK(wcsstr(pw, L"hunter") == NULL);
  ui_secret_free(json, len + 1);
}

SD_TEST(answer_wipes_inputs_even_on_error)
{
  wchar_t pw[32];
  wchar_t *resp[1];
  char *json = NULL;
  size_t len = 0;
  sd_err e;

  wcscpy_s(pw, SD_COUNTOF(pw), L"still-secret");
  resp[0] = pw;
  e = ui_prompt_build_answer(NULL, "answer", resp, 1, 0, &json, &len);   /* no prompt id: refused */
  SD_CHECK(e == SD_E_INVALID_PARAM);
  SD_CHECK(json == NULL);
  SD_CHECK(pw[0] == 0);
}

SD_TEST(answer_rejects_bad_arguments)
{
  char *json = NULL;
  size_t len = 0;
  SD_CHECK(ui_prompt_build_answer("p-1-1", "answer", NULL, 1, 0, &json, &len) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_prompt_build_answer(NULL, "accept", NULL, 0, 0, &json, &len) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_prompt_build_answer("p-1-1", "accept", NULL, 0, 0, NULL, &len) == SD_E_INVALID_PARAM);
  SD_CHECK(json == NULL);
}
