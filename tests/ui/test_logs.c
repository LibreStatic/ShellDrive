/* Logs viewer model (apps/shelldrive-ui/ui_logs_model.c): log.tail cursor handling (03 §2.4.1), the record cap,
   the level and search filters and the visible text. Pure: no agent, no window. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "ui_logs_model.h"

/* Parses a JSON text into *out (sd_json_free); NULL on a parse error. */
static sd_json *parse(const char *text)
{
  sd_json *root = NULL;
  if (sd_json_parse(text, strlen(text), 16, &root) != SD_OK)
    return NULL;
  return root;
}

#define REPLY_1 "{\"records\":[" \
  "{\"seq\":1,\"time\":\"2026-10-27T10:00:00.000Z\",\"level\":\"info\",\"component\":\"agent\",\"text\":\"started\"}," \
  "{\"seq\":2,\"time\":\"2026-10-27T10:00:01.000Z\",\"level\":\"warn\",\"component\":\"ssh\",\"mount_id\":\"m-1\"," \
  "\"text\":\"Slow server answer\"}],\"cursor\":\"1a.2b.2\",\"reset\":false,\"dropped\":0}"

SD_TEST(logs_cursor_appends_records_in_order)
{
  ui_log_model m;
  sd_json *r = parse(REPLY_1);
  size_t n = 0;
  SD_REQUIRE(r != NULL);
  ui_logs_model_init(&m);
  SD_REQUIRE(ui_logs_model_apply(&m, r, &n) == SD_OK);
  SD_CHECK_EQ_INT((int)n, 2);
  SD_CHECK_EQ_INT((int)m.count, 2);
  SD_CHECK_STR(m.cursor, "1a.2b.2");
  SD_CHECK_EQ_INT(m.reset, 0);
  SD_CHECK(m.rec[0].seq == 1 && m.rec[1].seq == 2);
  SD_CHECK_EQ_INT(m.rec[0].level, 2);
  SD_CHECK_EQ_INT(m.rec[1].level, 1);
  SD_CHECK(wcsstr(m.rec[1].line, L"WARN ssh [m-1] Slow server answer") != NULL);
  SD_CHECK(wcsstr(m.rec[0].line, L"INFO agent started") != NULL);
  sd_json_free(r);

  r = parse("{\"records\":[{\"seq\":3,\"time\":\"t\",\"level\":\"debug\",\"component\":\"x\",\"text\":\"more\"}],"
            "\"cursor\":\"1a.2b.3\",\"reset\":false,\"dropped\":0}");
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_OK);
  SD_CHECK_EQ_INT((int)n, 1);
  SD_CHECK_EQ_INT((int)m.count, 3);
  SD_CHECK_STR(m.cursor, "1a.2b.3");
  sd_json_free(r);
  ui_logs_model_free(&m);
}

SD_TEST(logs_reset_clears_or_keeps_by_dropped_count)
{
  ui_log_model m;
  sd_json *r;
  size_t n = 0;
  ui_logs_model_init(&m);
  r = parse(REPLY_1);
  SD_REQUIRE(r != NULL && ui_logs_model_apply(&m, r, &n) == SD_OK);
  sd_json_free(r);

  /* a foreign or older cursor: the agent restarted, the old records are not ours any more */
  r = parse("{\"records\":[{\"seq\":1,\"time\":\"t\",\"level\":\"error\",\"component\":\"agent\",\"text\":\"new\"}],"
            "\"cursor\":\"ffff.1.1\",\"reset\":true,\"dropped\":0}");
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_OK);
  SD_CHECK_EQ_INT((int)m.count, 1);
  SD_CHECK_EQ_INT(m.reset, 1);
  SD_CHECK_EQ_INT(m.rec[0].level, 0);
  sd_json_free(r);

  /* the cursor fell out of the ring: the records we kept stay, the gap is reported */
  r = parse("{\"records\":[{\"seq\":9,\"time\":\"t\",\"level\":\"info\",\"component\":\"agent\",\"text\":\"later\"}],"
            "\"cursor\":\"ffff.1.9\",\"reset\":true,\"dropped\":5}");
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_OK);
  SD_CHECK_EQ_INT((int)m.count, 2);
  SD_CHECK_EQ_U64(m.dropped, 5);
  SD_CHECK_EQ_INT(m.reset, 1);
  sd_json_free(r);
  ui_logs_model_free(&m);
}

SD_TEST(logs_malformed_reply_changes_nothing)
{
  ui_log_model m;
  sd_json *r;
  size_t n = 7;
  ui_logs_model_init(&m);
  r = parse(REPLY_1);
  SD_REQUIRE(r != NULL && ui_logs_model_apply(&m, r, &n) == SD_OK);
  sd_json_free(r);

  r = parse("{\"cursor\":\"1.2.3\"}");                         /* no records */
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_E_INVALID_PARAM);
  sd_json_free(r);

  r = parse("{\"records\":[{\"seq\":5,\"text\":\"ok\"},{\"time\":\"no seq\",\"text\":\"bad\"}],\"cursor\":\"1.2.5\"}");
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_E_INVALID_PARAM);   /* one bad record: the batch is refused */
  SD_CHECK_EQ_INT((int)m.count, 2);
  SD_CHECK_STR(m.cursor, "1a.2b.2");
  sd_json_free(r);

  r = parse("{\"records\":[],\"cursor\":\"0123456789012345678901234567890123456789012345678901234567890123456789\"}");
  SD_REQUIRE(r != NULL);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_E_INVALID_PARAM);  /* cursor longer than the buffer */
  sd_json_free(r);
  SD_CHECK(ui_logs_model_apply(&m, NULL, &n) == SD_E_INVALID_PARAM);
  ui_logs_model_free(&m);
}

SD_TEST(logs_keeps_the_newest_records_only)
{
  ui_log_model m;
  sd_json *r;
  size_t n = 0, i, cap = 2 * UI_LOG_MAX_RECORDS;
  char *buf = (char *)sd_alloc(cap * 160 + 256);
  size_t pos = 0;
  SD_REQUIRE(buf != NULL);
  pos += (size_t)sprintf_s(buf + pos, cap * 160 + 256 - pos, "{\"records\":[");
  for (i = 0; i < UI_LOG_MAX_RECORDS + 1; i++) {
    pos += (size_t)sprintf_s(buf + pos, cap * 160 + 256 - pos,
                             "%s{\"seq\":%u,\"time\":\"t\",\"level\":\"info\",\"component\":\"c\",\"text\":\"n%u\"}",
                             i ? "," : "", (unsigned)(i + 1), (unsigned)(i + 1));
  }
  pos += (size_t)sprintf_s(buf + pos, cap * 160 + 256 - pos, "],\"cursor\":\"1.2.2001\",\"reset\":false,\"dropped\":0}");
  r = parse(buf);
  sd_free(buf);
  SD_REQUIRE(r != NULL);
  ui_logs_model_init(&m);
  SD_CHECK(ui_logs_model_apply(&m, r, &n) == SD_OK);
  SD_CHECK_EQ_INT((int)m.count, (int)UI_LOG_MAX_RECORDS);
  SD_CHECK(m.rec[0].seq == 2);                               /* the oldest record went first */
  SD_CHECK(m.rec[m.count - 1].seq == UI_LOG_MAX_RECORDS + 1);
  sd_json_free(r);
  ui_logs_model_free(&m);
}

SD_TEST(logs_filters_by_level_and_search)
{
  ui_log_model m;
  sd_json *r = parse(REPLY_1);
  size_t n = 0, lines = 0;
  wchar_t *text = NULL;
  SD_REQUIRE(r != NULL);
  ui_logs_model_init(&m);
  SD_REQUIRE(ui_logs_model_apply(&m, r, &n) == SD_OK);
  sd_json_free(r);

  SD_CHECK(ui_logs_match(&m.rec[0], 2, L"") == 1);          /* info record, info and above */
  SD_CHECK(ui_logs_match(&m.rec[0], 0, NULL) == 0);         /* errors only */
  SD_CHECK(ui_logs_match(&m.rec[1], 1, NULL) == 1);         /* warnings and errors */
  SD_CHECK(ui_logs_match(&m.rec[0], 1, NULL) == 0);
  SD_CHECK(ui_logs_match(&m.rec[1], 4, L"SLOW") == 1);      /* search is case-insensitive */
  SD_CHECK(ui_logs_match(&m.rec[1], 4, L"m-1") == 1);       /* the mount id is part of the line */
  SD_CHECK(ui_logs_match(&m.rec[0], 4, L"ssh") == 0);
  SD_CHECK(ui_logs_match(&m.rec[0], 4, L"started") == 1);

  SD_CHECK(ui_logs_build_text(&m, 4, L"", &text, &lines) == SD_OK);
  SD_CHECK_EQ_INT((int)lines, 2);
  SD_CHECK(text != NULL && wcsstr(text, L"started") != NULL && wcsstr(text, L"Slow server") != NULL);
  SD_CHECK(wcsstr(text, L"\r\n") != NULL);
  sd_free(text);
  text = NULL;

  SD_CHECK(ui_logs_build_text(&m, 1, L"nothing like this", &text, &lines) == SD_OK);
  SD_CHECK_EQ_INT((int)lines, 0);
  SD_CHECK(text != NULL && text[0] == L'\0');
  sd_free(text);
  ui_logs_model_free(&m);
}

SD_TEST(logs_level_names)
{
  SD_CHECK_EQ_INT(ui_log_level_parse("error"), 0);
  SD_CHECK_EQ_INT(ui_log_level_parse("warn"), 1);
  SD_CHECK_EQ_INT(ui_log_level_parse("info"), 2);
  SD_CHECK_EQ_INT(ui_log_level_parse("debug"), 3);
  SD_CHECK_EQ_INT(ui_log_level_parse("trace"), 4);
  SD_CHECK_EQ_INT(ui_log_level_parse("loud"), -1);
  SD_CHECK_EQ_INT(ui_log_level_parse(NULL), -1);
}
