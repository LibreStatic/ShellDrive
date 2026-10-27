/* sd_ipc M3 additions (docs/design/03-apps-platform.md §2.4, §2.5, §8.2): subscribe topic validation,
 * features[] in hello, broadcast recipient counting with capability filter and exclusion, and the
 * state section helpers. Each test uses its own instance suffix, as test_ipc.c does. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

static unsigned g_m3_seq;

static void m3_suffix(void)
{
  wchar_t s[64];
  DWORD pid = GetCurrentProcessId();
  unsigned n = ++g_m3_seq, i = 0;
  wchar_t tmp[24];
  size_t t = 0;
  s[i++] = L'm';
  s[i++] = L'3';
  s[i++] = L'-';
  do { tmp[t++] = (wchar_t)(L'0' + pid % 10); pid /= 10; } while (pid);
  while (t) s[i++] = tmp[--t];
  s[i++] = L'-';
  do { tmp[t++] = (wchar_t)(L'0' + n % 10); n /= 10; } while (n);
  while (t) s[i++] = tmp[--t];
  s[i] = 0;
  sd_ipc_set_instance_suffix(s);
}

typedef struct m3_ctx {
  volatile LONG subs;
} m3_ctx;

static void m3_on_sub(void *ctx, sd_ipc_client *client, const char *topic)
{
  m3_ctx *m = (m3_ctx *)ctx;
  SD_UNUSED(client);
  if (strcmp(topic, "prompt") == 0)
    InterlockedIncrement(&m->subs);
}

static sd_err m3_handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                         sd_json_writer *res, sd_ipc_error *err)
{
  SD_UNUSED(ctx);
  SD_UNUSED(params);
  if (strcmp(method, "who") == 0) {
    sd_jw_key(res, "id");
    sd_jw_int(res, (int64_t)sd_ipc_client_id(client));
    sd_jw_key(res, "kind");
    sd_jw_cstr(res, sd_ipc_client_kind(client));
    return SD_OK;
  }
  sd_ipc_error_set(err, SD_E_UNSUPPORTED, "usage", "unknown");
  return SD_E_UNSUPPORTED;
}

static const char *const k_m3_features[] = { "status", "selftest", NULL };

static sd_err m3_start(m3_ctx *ctx, sd_ipc_server **out)
{
  sd_ipc_server_cfg cfg;
  memset(ctx, 0, sizeof(*ctx));
  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = m3_handler;
  cfg.ctx = ctx;
  cfg.on_subscribe = m3_on_sub;
  cfg.features = k_m3_features;
  return sd_ipc_server_start_ex(SD_IPC_AGENT, &cfg, out);
}

static sd_err m3_connect(uint32_t caps, const char *kind, sd_ipc_conn **c)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = kind;
  h.lang = "de";
  h.caps = caps;
  return sd_ipc_connect(SD_IPC_AGENT, &h, 0, 2000, c);
}

static uint64_t m3_who(sd_ipc_conn *c, char kind[16])
{
  sd_json *res = NULL;
  sd_ipc_error err;
  int64_t v = 0;
  uint64_t id = 0;
  const char *k;
  if (sd_ipc_call_raw(c, "who", NULL, 0, 5000, &res, &err) != SD_OK)
    return 0;
  if (sd_json_get_int64(res, "id", &v))
    id = (uint64_t)v;
  k = sd_json_get_str(res, "kind");
  if (kind) {
    kind[0] = 0;
    if (k) {
      size_t kl = strlen(k);
      if (kl > 15) kl = 15;
      memcpy(kind, k, kl);
      kind[kl] = 0;
    }
  }
  sd_json_free(res);
  return id;
}

SD_TEST(m3_topic_validation)
{
  SD_CHECK(sd_ipc_topic_valid("mount"));
  SD_CHECK(sd_ipc_topic_valid("hostkeys.announced"));
  SD_CHECK(sd_ipc_topic_valid("a-b_c.d9"));
  SD_CHECK(sd_ipc_topic_valid("01234567890123456789012"));           /* 23 bytes: the maximum */
  SD_CHECK(!sd_ipc_topic_valid("012345678901234567890123"));         /* 24 bytes */
  SD_CHECK(!sd_ipc_topic_valid(""));
  SD_CHECK(!sd_ipc_topic_valid(NULL));
  SD_CHECK(!sd_ipc_topic_valid("Mount"));
  SD_CHECK(!sd_ipc_topic_valid("a b"));
  SD_CHECK(!sd_ipc_topic_valid("a/b"));
}

SD_TEST(m3_subscribe_drops_invalid_topics_and_features_in_hello)
{
  m3_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  m3_suffix();
  SD_REQUIRE(m3_start(&ctx, &s) == SD_OK);
  SD_REQUIRE(m3_connect(SD_IPC_CAP_PROMPTS_UI, "ui", &c) == SD_OK);
  SD_CHECK(sd_ipc_conn_has_feature(c, "status"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "selftest"));
  SD_CHECK(!sd_ipc_conn_has_feature(c, "update.check"));
  SD_CHECK(!sd_ipc_conn_has_feature(c, NULL));
  /* invalid names are dropped from the accepted set; valid unknown names are kept (03 §2.0) */
  SD_REQUIRE(sd_ipc_call_raw(c, "subscribe", "{\"topics\":[\"mount\",\"Bad Topic\",\"prompt\",\"\",\"future.topic\"]}",
                             59, 5000, &res, &err) == SD_OK);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(res, "topics")), 3);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(ctx.subs == 1);            /* on_subscribe fires once per accepted new topic */
  {
    char kind[16];
    SD_CHECK(m3_who(c, kind) != 0);
    SD_CHECK_STR(kind, "ui");
  }
  sd_ipc_close(c);
  sd_ipc_server_stop(s);
}

SD_TEST(m3_broadcast_counts_recipients)
{
  m3_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *ui = NULL, *cli = NULL, *idle = NULL;
  sd_json *res = NULL, *ev = NULL;
  sd_ipc_error err;
  uint32_t n = 99;
  uint64_t ui_id;
  sd_wr w;
  m3_suffix();
  SD_REQUIRE(m3_start(&ctx, &s) == SD_OK);
  SD_REQUIRE(m3_connect(SD_IPC_CAP_PROMPTS_UI, "ui", &ui) == SD_OK);
  SD_REQUIRE(m3_connect(SD_IPC_CAP_PROMPTS_CONSOLE, "cli", &cli) == SD_OK);
  SD_REQUIRE(m3_connect(SD_IPC_CAP_PROMPTS_UI, "ui", &idle) == SD_OK);
  SD_REQUIRE(sd_ipc_call_raw(ui, "subscribe", "{\"topics\":[\"prompt\"]}", 21, 5000, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(sd_ipc_call_raw(cli, "subscribe", "{\"topics\":[\"prompt\"]}", 21, 5000, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  ui_id = m3_who(ui, NULL);
  SD_REQUIRE(ui_id != 0);
  SD_CHECK_EQ_U64(sd_ipc_topic_subscribers(s, "prompt", 0), 2);
  SD_CHECK_EQ_U64(sd_ipc_topic_subscribers(s, "prompt", SD_IPC_CAP_PROMPTS_UI), 1);
  SD_CHECK_EQ_U64(sd_ipc_topic_subscribers(s, "mount", 0), 0);
  SD_CHECK_EQ_U64(sd_ipc_topic_subscribers(s, "Bad Topic", 0), 0);
  SD_CHECK(ctx.subs == 2);

  sd_wr_init(&w, 4096);
  SD_REQUIRE(sd_ipc_build_event("prompt.request", "{\"prompt_id\":\"p-1-1\"}", 21, &w) == SD_OK);
  /* the UI-only filter: the console client is subscribed but lacks the cap, so it is not counted */
  SD_REQUIRE(sd_ipc_broadcast_count(s, "prompt", (const char *)w.p, w.len, SD_IPC_CAP_PROMPTS_UI, 0, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 1);
  SD_REQUIRE(sd_ipc_next_event(ui, 3000, &ev) == SD_OK);
  SD_CHECK_STR(sd_json_get_str(ev, "event"), "prompt.request");
  sd_json_free(ev);
  ev = NULL;
  SD_CHECK(sd_ipc_next_event(cli, 300, &ev) == SD_E_TIMEOUT);
  /* excluding the subscribed UI leaves nobody: nothing is queued */
  SD_REQUIRE(sd_ipc_broadcast_count(s, "prompt", (const char *)w.p, w.len, SD_IPC_CAP_PROMPTS_UI, ui_id, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 0);
  SD_CHECK(sd_ipc_next_event(ui, 300, &ev) == SD_E_TIMEOUT);
  /* no cap filter: both subscribers, exactly one copy each */
  SD_REQUIRE(sd_ipc_broadcast_count(s, "prompt", (const char *)w.p, w.len, 0, 0, &n) == SD_OK);
  SD_CHECK_EQ_INT(n, 2);
  sd_wr_free(&w);
  SD_REQUIRE(sd_ipc_next_event(ui, 3000, &ev) == SD_OK);
  sd_json_free(ev);
  ev = NULL;
  SD_REQUIRE(sd_ipc_next_event(cli, 3000, &ev) == SD_OK);
  sd_json_free(ev);
  ev = NULL;
  SD_CHECK(sd_ipc_next_event(ui, 200, &ev) == SD_E_TIMEOUT);
  SD_CHECK(sd_ipc_next_event(cli, 200, &ev) == SD_E_TIMEOUT);
  SD_CHECK(sd_ipc_broadcast_count(s, "Bad Topic", "{}", 2, 0, 0, &n) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_ipc_broadcast_count(s, "idle", "{}", 2, 0, 0, &n) == SD_OK && n == 0);
  sd_ipc_close(ui);
  sd_ipc_close(cli);
  sd_ipc_close(idle);
  sd_ipc_server_stop(s);
}

SD_TEST(m3_state_section_create_open)
{
  HANDLE h = NULL, h2 = NULL, o = NULL, x = NULL;
  int existed = 0;
  wchar_t name[512];
  void *p;
  m3_suffix();
  SD_CHECK(sd_ipc_state_open(&o) == SD_E_NOT_FOUND);
  SD_REQUIRE(sd_ipc_state_create(&h, &existed) == SD_OK);
  SD_CHECK(!existed);
  p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, 64);
  SD_REQUIRE(p != NULL);
  memcpy(p, "SDST", 4);
  UnmapViewOfFile(p);
  SD_REQUIRE(sd_ipc_state_create(&h2, &existed) == SD_OK);       /* our own second instance */
  SD_CHECK(existed);
  SD_REQUIRE(sd_ipc_state_open(&o) == SD_OK);
  p = MapViewOfFile(o, FILE_MAP_READ, 0, 0, 64);
  SD_REQUIRE(p != NULL);
  SD_CHECK(memcmp(p, "SDST", 4) == 0);
  UnmapViewOfFile(p);
  /* the snapshot is a file mapping, not an event or mutex */
  SD_CHECK(sd_ipc_object_create(SD_IPC_OBJ_STATE, &x, &existed) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_ipc_object_open(SD_IPC_OBJ_STATE, &x) == SD_E_INVALID_PARAM);
  /* names (D45, 03 §2.1): Local\ per session, SID suffix */
  SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_UI_MUTEX, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcsncmp(name, L"Local\\com.librestatic.shelldrive.ui.S-1-5-", 42) == 0);
  SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_STATE, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcsncmp(name, L"Local\\com.librestatic.shelldrive.state.S-1-5-", 45) == 0);
  {
    HANDLE m = NULL;
    SD_REQUIRE(sd_ipc_object_create(SD_IPC_OBJ_UI_MUTEX, &m, &existed) == SD_OK);
    SD_CHECK(!existed);
    CloseHandle(m);
  }
  CloseHandle(o);
  CloseHandle(h2);
  CloseHandle(h);
}

/* TM-R26 (lead decision): the owner and label decision fails closed on Vista+ when the label cannot be read,
   and XP (no labels) decides on the owner alone. Every branch of the decision is driven here. */
SD_TEST(m3_owner_label_fails_closed)
{
  /* XP: owner only; there is no label to read */
  SD_CHECK(sd_ipc_test_owner_decision(1, 0, 0, 0, 0) == SD_OK);
  SD_CHECK(sd_ipc_test_owner_decision(0, 0, 0, 0, 0) == SD_E_ACCESS_DENIED);
  /* Vista+: an unreadable label refuses, even when the owner matches (no owner-only fallback) */
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 0, 0, 0) == SD_E_ACCESS_DENIED);
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 0, 1, 0x2000) == SD_E_ACCESS_DENIED);
  SD_CHECK(sd_ipc_test_owner_decision(0, 1, 0, 0, 0) == SD_E_ACCESS_DENIED);
  /* Vista+ with a readable label: no label ACE is the default (medium); medium and high pass, low refuses */
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 1, 0, 0) == SD_OK);
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 1, 1, 0x2000) == SD_OK);
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 1, 1, 0x3000) == SD_OK);
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 1, 1, 0x1000) == SD_E_ACCESS_DENIED);
  SD_CHECK(sd_ipc_test_owner_decision(1, 1, 1, 1, 0x0000) == SD_E_ACCESS_DENIED);
  /* a readable low label on a foreign owner is refused as well */
  SD_CHECK(sd_ipc_test_owner_decision(0, 1, 1, 1, 0x3000) == SD_E_ACCESS_DENIED);
}
