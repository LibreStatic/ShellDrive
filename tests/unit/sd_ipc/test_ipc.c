/* sd_ipc: error table, names, in-process server/client round trips, limits and the anti-spoofing
 * checks of 03 §2.2 (TM-R25/R26 basics). Every test uses its own instance suffix so it never
 * touches a running agent. */
#include <windows.h>
#include <sddl.h>
#include <string.h>

#include "sd_test.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

static unsigned g_seq;

static void unique_suffix(void)
{
  wchar_t s[64];
  DWORD pid = GetCurrentProcessId();
  unsigned n = ++g_seq, i = 0, k;
  wchar_t tmp[24];
  size_t t = 0;
  s[i++] = L't';
  s[i++] = L'e';
  s[i++] = L's';
  s[i++] = L't';
  do { tmp[t++] = (wchar_t)(L'0' + pid % 10); pid /= 10; } while (pid);
  while (t) s[i++] = tmp[--t];
  s[i++] = L'-';
  do { tmp[t++] = (wchar_t)(L'0' + n % 10); n /= 10; } while (n);
  while (t) s[i++] = tmp[--t];
  s[i] = 0;
  k = 0;
  SD_UNUSED(k);
  sd_ipc_set_instance_suffix(s);
}

/* ---- error table ---- */

SD_TEST(ipc_exit_codes_cover_every_err)
{
  int e;
  for (e = 0; e < SD_ERR_COUNT; e++) {
    int x = sd_ipc_exit_code_for_err((sd_err)e);
    if (x < 0 || x > 17)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s maps to %d", sd_err_name((sd_err)e), x);
    if (e != SD_OK && x == 0)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "%s maps to success", sd_err_name((sd_err)e));
    /* the code spelling maps to the same exit code */
    SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code(sd_err_name((sd_err)e)), x);
  }
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_OK), 0);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_AUTH_FAILED), 4);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_AUTH_REQUIRED), 4);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_HOSTKEY_REJECTED), 5);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_HOSTKEY_MISMATCH), 6);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_HOSTKEY_TYPE_UNAVAILABLE), 6);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_DNS), 7);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_TIMEOUT), 12);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_CANCELLED), 13);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_LEGACY_REJECTED), 15);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err(SD_E_PROXY), 16);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_err((sd_err)9999), 1);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("usage"), 2);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("profile_not_found"), 3);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("prompt_required"), 4);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("host_key_unknown"), 5);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("agent_unavailable"), 8);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("too_many_connections"), 8);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("rate_limited"), 8);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("elevation_required"), 9);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("target_in_use"), 10);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("backend_unavailable"), 11);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("proto_unsupported"), 14);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("policy_denied"), 15);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("selftest_failed"), 17);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("prompt_unavailable"), 4);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("token_only_refused"), 4);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("secret_not_found"), 3);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("no_such_code"), 1);
  {
    sd_ipc_error err;
    sd_ipc_error_set(&err, SD_E_EXISTS, "target_in_use", "letter taken");
    SD_CHECK_STR(err.code, "target_in_use");
    SD_CHECK_EQ_INT(err.exit_code, 10);
    sd_ipc_error_set(&err, SD_E_HOSTKEY_MISMATCH, NULL, NULL);
    SD_CHECK_STR(err.code, "host_key_mismatch");
    SD_CHECK_EQ_INT(err.exit_code, 6);
  }
}

SD_TEST(ipc_names_follow_d45)
{
  wchar_t name[512], sid[192];
  DWORD session = 0;
  sd_ipc_set_instance_suffix(NULL);
  SD_REQUIRE(sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session) == SD_OK);
  SD_CHECK(wcsncmp(sid, L"S-1-5-", 6) == 0);
  SD_REQUIRE(sd_ipc_pipe_name(SD_IPC_AGENT, L"S-1-5-21-1-2-3-1001", 2, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcscmp(name, L"\\\\.\\pipe\\com.librestatic.shelldrive.agent.S-1-5-21-1-2-3-1001.2") == 0);
  SD_REQUIRE(sd_ipc_pipe_name(SD_IPC_SERVICE, NULL, 0, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcscmp(name, L"\\\\.\\pipe\\com.librestatic.shelldrive.service") == 0);
  SD_CHECK(sd_ipc_pipe_name(SD_IPC_AGENT, L"S-1", 1, name, 10) != SD_OK);   /* too small */
  SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_AGENT_READY, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcsncmp(name, L"Local\\com.librestatic.shelldrive.agent.ready.S-1-5-", 51) == 0);
  SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_AGENT_STOP, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcsncmp(name, L"Global\\com.librestatic.shelldrive.agent.shutdown.S-1-5-", 55) == 0);
  sd_ipc_set_instance_suffix(L"x1");
  SD_REQUIRE(sd_ipc_pipe_name(SD_IPC_SERVICE, NULL, 0, name, SD_COUNTOF(name)) == SD_OK);
  SD_CHECK(wcscmp(name, L"\\\\.\\pipe\\com.librestatic.shelldrive.service.x1") == 0);
  sd_ipc_set_instance_suffix(NULL);
}

SD_TEST(ipc_named_objects_owner_checked)
{
  HANDLE a = NULL, b = NULL, o = NULL;
  int existed = 0;
  unique_suffix();
  SD_REQUIRE(sd_ipc_object_create(SD_IPC_OBJ_AGENT_MUTEX, &a, &existed) == SD_OK);
  SD_CHECK(!existed);
  SD_REQUIRE(sd_ipc_object_create(SD_IPC_OBJ_AGENT_MUTEX, &b, &existed) == SD_OK);
  SD_CHECK(existed);                       /* second instance of ours */
  SD_REQUIRE(sd_ipc_object_create(SD_IPC_OBJ_AGENT_READY, &o, &existed) == SD_OK);
  CloseHandle(o);
  o = NULL;
  CloseHandle(a);
  CloseHandle(b);
  SD_CHECK(sd_ipc_object_open(SD_IPC_OBJ_AGENT_READY, &o) == SD_E_NOT_FOUND);
  /* A same-named event created by "someone else" with a foreign owner is squatting. Without
     privileges we cannot set a foreign owner, so model it with an event whose owner is
     BUILTIN\Administrators when the token allows that (elevated runs); otherwise skip. */
  {
    wchar_t name[512];
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    HANDLE sq;
    SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_AGENT_READY, name, SD_COUNTOF(name)) == SD_OK);
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAD:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, NULL)) {
      sa.nLength = sizeof(sa);
      sa.lpSecurityDescriptor = sd;
      sa.bInheritHandle = FALSE;
      sq = CreateEventW(&sa, TRUE, FALSE, name);
      LocalFree(sd);
      if (sq != NULL) {
        SD_CHECK(sd_ipc_object_open(SD_IPC_OBJ_AGENT_READY, &o) == SD_E_ACCESS_DENIED);
        SD_CHECK(sd_ipc_object_create(SD_IPC_OBJ_AGENT_READY, &o, &existed) == SD_E_ACCESS_DENIED);
        CloseHandle(sq);
      }
    }
  }
}

/* ---- server/client ---- */

typedef struct srv_ctx {
  volatile LONG calls;
  volatile LONG disconnects;
  uint64_t last_client;
  sd_ipc_server *srv;                   /* M3 deferred replies: the worker answers through it */
} srv_ctx;

/* M3: a deferred request is answered by a worker thread after the handler returned. */
typedef struct defer_arg {
  sd_ipc_server *srv;
  uint64_t cid;
  int64_t rid;
  int fail;
} defer_arg;

static DWORD WINAPI defer_worker(void *p)
{
  defer_arg *a = (defer_arg *)p;
  Sleep(150);
  if (a->fail)
    (void)sd_ipc_reply_deferred(a->srv, a->cid, a->rid, SD_E_EXISTS, "target_in_use", "deferred failure", NULL, 0);
  else
    (void)sd_ipc_reply_deferred(a->srv, a->cid, a->rid, SD_OK, NULL, NULL, "{\"done\":true,\"n\":7}", 19);
  sd_free(a);
  return 0;
}

static sd_err handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                      sd_json_writer *res, sd_ipc_error *err)
{
  srv_ctx *s = (srv_ctx *)ctx;
  InterlockedIncrement(&s->calls);
  s->last_client = sd_ipc_client_id(client);
  if (strcmp(method, "defer") == 0 || strcmp(method, "defer_err") == 0) {
    defer_arg *a = (defer_arg *)sd_calloc(1, sizeof(*a));
    HANDLE t;
    if (a == NULL) return SD_E_NO_MEMORY;
    if (!sd_ipc_defer(client, &a->rid)) {
      sd_free(a);
      return SD_E_INTERNAL;
    }
    a->srv = s->srv;
    a->cid = sd_ipc_client_id(client);
    a->fail = strcmp(method, "defer_err") == 0;
    t = CreateThread(NULL, 0, defer_worker, a, 0, NULL);
    if (t == NULL) {
      sd_free(a);
      return SD_E_NO_MEMORY;
    }
    CloseHandle(t);
    return SD_OK;                         /* not sent: the worker replies */
  }
  if (strcmp(method, "echo") == 0) {
    sd_jw_key(res, "params");
    sd_jw_value(res, params);
    sd_jw_key(res, "caps");
    sd_jw_int(res, sd_ipc_client_caps(client));
    sd_jw_key(res, "lang");
    sd_jw_cstr(res, sd_ipc_client_lang(client));
    return SD_OK;
  }
  if (strcmp(method, "fail") == 0) {
    sd_ipc_error_set(err, SD_E_EXISTS, "target_in_use", "test failure");
    return SD_E_EXISTS;
  }
  if (strcmp(method, "big") == 0) {
    int64_t n = 0;
    char *buf;
    sd_json_get_int64(params, "n", &n);
    buf = (char *)sd_alloc((size_t)n + 1);
    if (buf == NULL) return SD_E_NO_MEMORY;
    memset(buf, 'x', (size_t)n);
    sd_jw_key(res, "data");
    sd_jw_str(res, buf, (size_t)n);
    sd_free(buf);
    return SD_OK;
  }
  sd_ipc_error_set(err, SD_E_UNSUPPORTED, "usage", "unknown");
  return SD_E_UNSUPPORTED;
}

static void on_disc(void *ctx, uint64_t id)
{
  srv_ctx *s = (srv_ctx *)ctx;
  SD_UNUSED(id);
  InterlockedIncrement(&s->disconnects);
}

static sd_err start_server(srv_ctx *ctx, uint32_t max_instances, uint32_t per_sid, uint32_t rate, sd_ipc_server **out)
{
  sd_ipc_server_cfg cfg;
  memset(ctx, 0, sizeof(*ctx));
  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = handler;
  cfg.ctx = ctx;
  cfg.on_disconnect = on_disc;
  cfg.max_instances = max_instances;
  cfg.max_per_sid = per_sid;
  cfg.max_requests_per_sec = rate;
  return sd_ipc_server_start_ex(SD_IPC_AGENT, &cfg, out);
}

static sd_err connect_client(uint32_t caps, DWORD timeout, sd_ipc_conn **c)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = "cli";
  h.lang = "es";
  h.caps = caps;
  return sd_ipc_connect(SD_IPC_AGENT, &h, 0, timeout, c);
}

SD_TEST(ipc_roundtrip_call_error_event)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL, *ev = NULL;
  sd_ipc_error err;
  int64_t caps = 0;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  SD_REQUIRE(connect_client(SD_IPC_CAP_PROMPTS_CONSOLE, 2000, &c) == SD_OK);
  SD_REQUIRE(sd_ipc_call_raw(c, "echo", "{\"x\":[1,\"\xc3\xa9\"]}", 14, 5000, &res, &err) == SD_OK);
  SD_CHECK(sd_json_get_int64(res, "caps", &caps) && caps == SD_IPC_CAP_PROMPTS_CONSOLE);
  SD_CHECK_STR(sd_json_get_str(res, "lang"), "es");
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(sd_json_get(res, "params"), "x")), 2);
  sd_json_free(res);
  res = NULL;
  /* errors carry the code and the CLI exit code */
  SD_CHECK(sd_ipc_call_raw(c, "fail", NULL, 0, 5000, &res, &err) == SD_E_EXISTS);
  SD_CHECK_STR(err.code, "target_in_use");
  SD_CHECK_EQ_INT(err.exit_code, 10);
  SD_CHECK(res == NULL);
  SD_CHECK(sd_ipc_call_raw(c, "nope", NULL, 0, 5000, &res, &err) != SD_OK);
  /* events need a subscription */
  sd_ipc_broadcast(s, "mount", "{\"type\":\"evt\",\"event\":\"x\",\"data\":{}}", 36);
  SD_CHECK(sd_ipc_next_event(c, 300, &ev) == SD_E_TIMEOUT);
  SD_REQUIRE(sd_ipc_call_raw(c, "subscribe", "{\"topics\":[\"mount\"]}", 20, 5000, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  {
    sd_wr w;
    sd_wr_init(&w, 4096);
    SD_REQUIRE(sd_ipc_build_event("mount.state", "{\"mount_id\":\"m-1\"}", 18, &w) == SD_OK);
    sd_ipc_broadcast(s, "mount", (const char *)w.p, w.len);
    sd_ipc_broadcast(s, "other", (const char *)w.p, w.len);
    sd_wr_free(&w);
  }
  SD_REQUIRE(sd_ipc_next_event(c, 3000, &ev) == SD_OK);
  SD_CHECK_STR(sd_json_get_str(ev, "event"), "mount.state");
  SD_CHECK_STR(sd_json_get_str(sd_json_get(ev, "data"), "mount_id"), "m-1");
  sd_json_free(ev);
  ev = NULL;
  SD_CHECK(sd_ipc_next_event(c, 200, &ev) == SD_E_TIMEOUT);      /* "other" not subscribed */
  /* direct send to one client */
  SD_CHECK_EQ_INT(sd_ipc_server_client_count(s), 1);
  SD_CHECK(sd_ipc_send_to(s, ctx.last_client, "{\"type\":\"evt\",\"event\":\"p\",\"data\":{}}", 36) == SD_OK);
  SD_REQUIRE(sd_ipc_next_event(c, 3000, &ev) == SD_OK);
  SD_CHECK_STR(sd_json_get_str(ev, "event"), "p");
  sd_json_free(ev);
  SD_CHECK(sd_ipc_send_to(s, 987654, "{}", 2) == SD_E_NOT_FOUND);
  SD_CHECK(WaitForSingleObject(sd_ipc_event_handle(c), 0) == WAIT_TIMEOUT);
  sd_ipc_close(c);
  {
    uint64_t end = sd_tick_ms() + 3000;
    while (ctx.disconnects == 0 && sd_tick_ms() < end) Sleep(10);
  }
  SD_CHECK_EQ_INT(ctx.disconnects, 1);
  sd_ipc_server_stop(s);
}

/* M3: deferred replies. The handler defers; a worker thread answers later through sd_ipc_reply_deferred. */
SD_TEST(ipc_deferred_reply_roundtrip)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  int64_t n = 0;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  ctx.srv = s;
  SD_REQUIRE(connect_client(0, 2000, &c) == SD_OK);
  SD_REQUIRE(sd_ipc_call_raw(c, "defer", NULL, 0, 5000, &res, &err) == SD_OK);
  SD_CHECK(sd_json_get_int64(res, "n", &n) && n == 7);
  SD_CHECK(sd_json_get(res, "done") != NULL);
  sd_json_free(res);
  res = NULL;
  /* an error reply carries the code and the exit code like any handler error */
  SD_CHECK(sd_ipc_call_raw(c, "defer_err", NULL, 0, 5000, &res, &err) == SD_E_EXISTS);
  SD_CHECK_STR(err.code, "target_in_use");
  SD_CHECK_EQ_INT(err.exit_code, 10);
  SD_CHECK(res == NULL);
  /* the connection keeps serving requests after a deferred one */
  SD_REQUIRE(sd_ipc_call_raw(c, "echo", NULL, 0, 5000, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  /* a reply to a client that is gone is not_found; sd_ipc_defer outside a handler is refused */
  SD_CHECK(sd_ipc_reply_deferred(s, 987654, 1, SD_OK, NULL, NULL, "{}", 2) == SD_E_NOT_FOUND);
  {
    int64_t rid = 0;
    SD_CHECK(sd_ipc_defer(NULL, &rid) == 0);
  }
  /* sd_ipc_broadcast_all reaches every client that completed hello, subscribed or not */
  {
    sd_wr w;
    sd_json *ev = NULL;
    sd_wr_init(&w, 1024);
    SD_REQUIRE(sd_ipc_build_event("agent.stopping", "{\"reason\":\"test\"}", 17, &w) == SD_OK);
    SD_CHECK(sd_ipc_broadcast_all(s, (const char *)w.p, w.len) == SD_OK);
    sd_wr_free(&w);
    SD_REQUIRE(sd_ipc_next_event(c, 3000, &ev) == SD_OK);
    SD_CHECK_STR(sd_json_get_str(ev, "event"), "agent.stopping");
    SD_CHECK_STR(sd_json_get_str(sd_json_get(ev, "data"), "reason"), "test");
    sd_json_free(ev);
  }
  sd_ipc_close(c);
  sd_ipc_server_stop(s);
}

SD_TEST(ipc_large_messages_and_cap)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  size_t n;
  char *big;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  SD_REQUIRE(connect_client(0, 2000, &c) == SD_OK);
  /* a 300 KiB response crosses the 64 KiB read chunk (ERROR_MORE_DATA continuation) */
  SD_REQUIRE(sd_ipc_call_raw(c, "big", "{\"n\":300000}", 12, 10000, &res, &err) == SD_OK);
  SD_CHECK(sd_json_str(sd_json_get(res, "data"), &n) && n == 300000);
  sd_json_free(res);
  res = NULL;
  /* a 200 KiB request is fine, a request over 1 MiB is refused by the client... */
  big = (char *)sd_alloc(SD_IPC_MAX_MESSAGE + 64);
  SD_REQUIRE(big != NULL);
  memcpy(big, "{\"s\":\"", 6);
  memset(big + 6, 'a', 200000);
  memcpy(big + 6 + 200000, "\"}", 2);
  SD_CHECK(sd_ipc_call_raw(c, "echo", big, 200008, 10000, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  memset(big + 6, 'a', SD_IPC_MAX_MESSAGE);
  memcpy(big + 6 + SD_IPC_MAX_MESSAGE, "\"}", 2);
  SD_CHECK(sd_ipc_call_raw(c, "echo", big, SD_IPC_MAX_MESSAGE + 8, 10000, &res, &err) != SD_OK);
  sd_free(big);
  sd_ipc_close(c);
  sd_ipc_server_stop(s);
}

/* Raw pipe client used to send what the real client never would. */
static HANDLE raw_connect(void)
{
  wchar_t sid[192], name[512];
  DWORD session = 0, mode = PIPE_READMODE_MESSAGE;
  HANDLE h;
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session) != SD_OK ||
      sd_ipc_pipe_name(SD_IPC_AGENT, sid, session, name, SD_COUNTOF(name)) != SD_OK)
    return INVALID_HANDLE_VALUE;
  h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                  SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
  if (h != INVALID_HANDLE_VALUE)
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
  return h;
}

static int raw_closed_by_server(HANDLE h)
{
  char buf[256];
  DWORD got = 0;
  /* the server either closes at once or answers once and then closes */
  if (!ReadFile(h, buf, sizeof(buf), &got, NULL))
    return 1;
  return !ReadFile(h, buf, sizeof(buf), &got, NULL);
}

SD_TEST(ipc_server_closes_bad_clients)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  HANDLE h;
  DWORD put = 0;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  /* malformed JSON */
  h = raw_connect();
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(h, "{not json", 9, &put, NULL));
  SD_CHECK(raw_closed_by_server(h));
  CloseHandle(h);
  /* request before hello */
  h = raw_connect();
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(h, "{\"type\":\"req\",\"id\":1,\"method\":\"echo\"}", 37, &put, NULL));
  SD_CHECK(raw_closed_by_server(h));
  CloseHandle(h);
  /* protocol version without overlap: error reply, then close */
  h = raw_connect();
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  {
    static const char hello[] = "{\"type\":\"hello\",\"id\":0,\"proto\":7,\"min_proto\":7}";
    char buf[512];
    DWORD got = 0;
    SD_CHECK(WriteFile(h, hello, sizeof(hello) - 1, &put, NULL));
    SD_CHECK(ReadFile(h, buf, sizeof(buf) - 1, &got, NULL));
    buf[got] = 0;
    SD_CHECK(strstr(buf, "proto_unsupported") != NULL);
    SD_CHECK(!ReadFile(h, buf, sizeof(buf), &got, NULL));
  }
  CloseHandle(h);
  SD_CHECK_EQ_INT(ctx.calls, 0);
  sd_ipc_server_stop(s);
}

static int test_process_is_elevated(void)
{
  HANDLE tok = NULL;
  DWORD elevated = 0, len = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  if (!GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20 /* TokenElevation */, &elevated, sizeof(elevated), &len))
    elevated = 0;
  CloseHandle(tok);
  return elevated != 0;
}

SD_TEST(ipc_instance_quota_and_rate_limit)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c1 = NULL, *c2 = NULL, *c3 = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  int i, limited = 0;
  unique_suffix();
  /* at most 2 instances: the third client cannot even reach hello */
  SD_REQUIRE(start_server(&ctx, 2, 0, 0, &s) == SD_OK);
  SD_REQUIRE(connect_client(0, 2000, &c1) == SD_OK);
  SD_REQUIRE(connect_client(0, 2000, &c2) == SD_OK);
  SD_CHECK(connect_client(0, 600, &c3) != SD_OK);
  sd_ipc_close(c2);
  c2 = NULL;
  Sleep(200);
  SD_CHECK(connect_client(0, 3000, &c3) == SD_OK);     /* the freed instance listens again */
  sd_ipc_close(c3);
  sd_ipc_close(c1);
  sd_ipc_server_stop(s);

  /* per-SID quota (service rule TM-R25, here 1) and request rate (3/s) */
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 1, 3, &s) == SD_OK);
  SD_REQUIRE(connect_client(0, 2000, &c1) == SD_OK);
  SD_CHECK(connect_client(0, 2000, &c2) != SD_OK);
  /* 30 calls against 3/s: the limit trips in every 1 s window even on a slow runner */
  for (i = 0; i < 30; i++) {
    if (sd_ipc_call_raw(c1, "echo", NULL, 0, 5000, &res, &err) != SD_OK && strcmp(err.code, "rate_limited") == 0)
      limited++;
    sd_json_free(res);
    res = NULL;
  }
  /* elevated admins are exempt from the rate limit by design (TM-R25); CI runners are elevated */
  if (test_process_is_elevated())
    SD_CHECK_EQ_INT(limited, 0);
  else
    SD_CHECK(limited >= 2);
  SD_CHECK_EQ_INT(sd_ipc_exit_code_for_code("rate_limited"), 8);
  sd_ipc_close(c1);
  sd_ipc_server_stop(s);
}

SD_TEST(ipc_first_instance_detects_squatting)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL, *s2 = NULL;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  /* a second server (or a squatter that came first) cannot take the name */
  SD_CHECK(start_server(&ctx, 0, 0, 0, &s2) == SD_E_ACCESS_DENIED);
  sd_ipc_server_stop(s);
}

SD_TEST(ipc_client_rejects_foreign_owner)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_ipc_conn *c = NULL;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  /* The client requires owner == our SID. Expecting another owner models a pipe instance created
     by a different user: the connection must be refused before anything is sent. */
  sd_ipc_test_set_expected_owner(L"S-1-5-18");
  SD_CHECK(connect_client(0, 2000, &c) == SD_E_ACCESS_DENIED);
  SD_CHECK(c == NULL);
  sd_ipc_test_set_expected_owner(NULL);
  SD_CHECK_EQ_INT(ctx.calls, 0);
  /* Rejected clients drop their instance at once; the server must keep serving (instance turnover
     regression: the next client must always reach hello). */
  {
    int k;
    for (k = 0; k < 50; k++) {
      sd_ipc_test_set_expected_owner(L"S-1-5-18");
      SD_CHECK(connect_client(0, 2000, &c) == SD_E_ACCESS_DENIED);
      sd_ipc_test_set_expected_owner(NULL);
      SD_REQUIRE(connect_client(0, 2000, &c) == SD_OK);
      sd_ipc_close(c);
      c = NULL;
    }
  }
  SD_CHECK_EQ_INT(ctx.calls, 0);
  sd_ipc_server_stop(s);
}

SD_TEST(ipc_client_rejects_squatted_pipe)
{
  /* A squatter creates the agent pipe first with an owner other than the user. A standard user
     can only do this for a group it owns (BUILTIN\Administrators in an elevated token); when the
     test runs unelevated the pipe cannot be created that way and the case is skipped. */
  wchar_t sid[192], name[512];
  DWORD session = 0;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE squat;
  sd_ipc_conn *c = NULL;
  OVERLAPPED ov;
  unique_suffix();
  SD_REQUIRE(sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session) == SD_OK);
  SD_REQUIRE(sd_ipc_pipe_name(SD_IPC_AGENT, sid, session, name, SD_COUNTOF(name)) == SD_OK);
  SD_REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAD:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, NULL));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  squat = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 4, 4096, 4096, 0, &sa);
  LocalFree(sd);
  if (squat == INVALID_HANDLE_VALUE)
    return;   /* not elevated: covered by ipc_client_rejects_foreign_owner */
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  ConnectNamedPipe(squat, &ov);
  SD_CHECK(connect_client(0, 2000, &c) == SD_E_ACCESS_DENIED);
  {
    srv_ctx ctx;
    sd_ipc_server *s = NULL;
    SD_CHECK(start_server(&ctx, 0, 0, 0, &s) == SD_E_ACCESS_DENIED);   /* the agent refuses to start */
  }
  CancelIo(squat);
  if (ov.hEvent) CloseHandle(ov.hEvent);
  CloseHandle(squat);
}

SD_TEST(ipc_connect_without_server)
{
  sd_ipc_conn *c = NULL;
  uint64_t t0;
  unique_suffix();
  t0 = sd_tick_ms();
  SD_CHECK(connect_client(0, 2000, &c) == SD_E_NOT_FOUND);
  SD_CHECK(sd_tick_ms() - t0 < 1500);
}

/* Instance lifecycle under load: clients that connect, call and close back to back (several threads,
   plus clients that close before hello) must never hit an instance the server tears down while they
   attach. sd_ipc_connect retries that case as defense; the regression is that it never has to. */
typedef struct stress_arg {
  int iterations;
  volatile LONG failures;
} stress_arg;

static unsigned __stdcall stress_thread(void *p)
{
  stress_arg *a = (stress_arg *)p;
  int i;
  for (i = 0; i < a->iterations; i++) {
    sd_ipc_conn *c = NULL;
    sd_json *res = NULL;
    sd_ipc_error err;
    if (connect_client(0, 5000, &c) != SD_OK) {
      InterlockedIncrement(&a->failures);
      continue;
    }
    if ((i & 1) == 0) {
      if (sd_ipc_call_raw(c, "echo", NULL, 0, 5000, &res, &err) != SD_OK)
        InterlockedIncrement(&a->failures);
      sd_json_free(res);
    }
    sd_ipc_close(c);
  }
  return 0;
}

SD_TEST(ipc_instance_turnover_under_load)
{
  srv_ctx ctx;
  sd_ipc_server *s = NULL;
  sd_thread th[4];
  stress_arg arg;
  uint32_t retries0;
  int i;
  unique_suffix();
  SD_REQUIRE(start_server(&ctx, 0, 0, 0, &s) == SD_OK);
  retries0 = sd_ipc_test_connect_retries();
  arg.iterations = 150;
  arg.failures = 0;
  for (i = 0; i < 4; i++)
    SD_REQUIRE(sd_thread_create(&th[i], stress_thread, &arg, 0, L"ipc-stress") == SD_OK);
  for (i = 0; i < 4; i++)
    sd_thread_join(&th[i], SD_WAIT_INFINITE, NULL);
  SD_CHECK_EQ_INT((int)arg.failures, 0);
  SD_CHECK_EQ_INT((int)(sd_ipc_test_connect_retries() - retries0), 0);
  sd_ipc_server_stop(s);
}
