/* The administrator side of the service prompts (apps/shelldrive-ui/ui_admin_model.c, ui_wire.c): the attention
   count of the service event, when the tray shows it, where an answer goes, the relaunch verb, the --elevated-admin
   verb, and the prompt.list entries that the admin mode turns into dialogs. Pure: no window, pipe or token call. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "ui_admin_model.h"
#include "ui_prompt_model.h"
#include "ui_wire.h"

static sd_json *parse_text(const char *text)
{
  sd_json *root = NULL;
  if (sd_json_parse(text, strlen(text), 32, &root) != SD_OK)
    return NULL;
  return root;
}

SD_TEST(admin_attention_count_parses_from_the_event)
{
  sd_json *root;
  int n = -1;

  root = parse_text("{\"count\":0}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 0);
  sd_json_free(root);

  root = parse_text("{\"count\":3}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 3);
  sd_json_free(root);

  root = parse_text("{\"count\":-1}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(n, 0);
  sd_json_free(root);

  root = parse_text("{\"count\":1025}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_E_INVALID_PARAM);
  sd_json_free(root);

  root = parse_text("{\"count\":\"2\"}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_E_INVALID_PARAM);
  sd_json_free(root);

  root = parse_text("{}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_E_INVALID_PARAM);
  sd_json_free(root);

  root = parse_text("[1]");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_E_INVALID_PARAM);
  sd_json_free(root);

  SD_CHECK(ui_admin_parse_attention(NULL, &n) == SD_E_INVALID_PARAM);
}

SD_TEST(admin_pending_count_drives_the_attention_state)
{
  sd_json *root;
  int n = 0;

  /* prompt routed: the service sends count 2; the admin tray shows the attention state */
  root = parse_text("{\"count\":2}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_OK);
  sd_json_free(root);
  SD_CHECK_EQ_INT(ui_admin_attention_shown(n, 1), 1);

  /* a non-administrator never sees it, whatever the count */
  SD_CHECK_EQ_INT(ui_admin_attention_shown(n, 0), 0);

  /* prompts answered or expired: the service sends count 0 and the state clears */
  root = parse_text("{\"count\":0}");
  SD_REQUIRE(root != NULL);
  SD_CHECK(ui_admin_parse_attention(root, &n) == SD_OK);
  sd_json_free(root);
  SD_CHECK_EQ_INT(ui_admin_attention_shown(n, 1), 0);

  SD_CHECK_EQ_INT(ui_admin_attention_shown(-1, 1), 0);
}

SD_TEST(admin_answers_go_to_the_service_only_from_the_admin_mode)
{
  SD_CHECK(ui_admin_answer_route(1) == UI_ROUTE_SERVICE);
  SD_CHECK(ui_admin_answer_route(0) == UI_ROUTE_AGENT);

  /* service prompts need an elevated process of an administrator (the service checks the same, TM-R25) */
  SD_CHECK_EQ_INT(ui_admin_may_answer_service(1, 1), 1);
  SD_CHECK_EQ_INT(ui_admin_may_answer_service(0, 1), 0);
  SD_CHECK_EQ_INT(ui_admin_may_answer_service(1, 0), 0);
  SD_CHECK_EQ_INT(ui_admin_may_answer_service(0, 0), 0);
}

SD_TEST(admin_relaunch_verb_is_runas_on_vista_and_open_on_xp)
{
  SD_CHECK(wcscmp(ui_admin_launch_verb(1), L"runas") == 0);
  SD_CHECK(wcscmp(ui_admin_launch_verb(0), L"open") == 0);
}

SD_TEST(admin_elevated_verb_is_exact)
{
  ui_request req;
  static const wchar_t *const ok[] = { L"--elevated-admin" };
  static const wchar_t *const extra[] = { L"--elevated-admin", L"x" };
  static const wchar_t *const view[] = { L"--elevated-view" };

  SD_CHECK(ui_request_from_args(1, ok, &req) == SD_OK);
  SD_CHECK(req.verb == UI_VERB_ELEVATED_ADMIN);
  SD_CHECK(ui_request_from_args(2, extra, &req) == SD_E_INVALID_PARAM);
  /* --elevated-view is a CLI flag of the WebDAV mapping (03 §1.7.2), not a UI verb */
  SD_CHECK(ui_request_from_args(1, view, &req) == SD_E_INVALID_PARAM);
}

SD_TEST(admin_prompt_list_entry_becomes_a_prompt)
{
  /* one entry of prompt.list from the service: the same fields as prompt.request */
  sd_json *root = parse_text("{\"prompt_id\":\"p-7\",\"mount_id\":\"g-1\",\"profile_id\":"
                             "\"0123456789abcdef0123456789abcdef\",\"kind\":\"password\","
                             "\"host\":\"files.example.org\",\"port\":22,\"user\":\"ana\","
                             "\"is_reconnect\":false,\"can_save\":false,\"queued\":false,\"deadline_ms\":90000}");
  ui_prompt *p;
  SD_REQUIRE(root != NULL);
  p = (ui_prompt *)sd_calloc(1, sizeof(*p));
  SD_REQUIRE(p != NULL);
  SD_CHECK(ui_prompt_parse(root, p) == SD_OK);
  SD_CHECK(p->kind == UI_PK_PASSWORD);
  SD_CHECK(strcmp(p->prompt_id, "p-7") == 0);
  SD_CHECK(wcscmp(p->host, L"files.example.org") == 0);
  SD_CHECK(wcscmp(p->user, L"ana") == 0);
  SD_CHECK(p->has_deadline && p->deadline_ms == 90000);
  SD_CHECK(p->can_save == 0);
  sd_free(p);
  sd_json_free(root);
}
