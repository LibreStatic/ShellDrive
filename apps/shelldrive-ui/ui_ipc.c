/* shelldrive-ui: the agent client thread (03 §2, §1.4).
 *
 * One thread owns the sd_ipc_conn: it connects (starting the agent only at the first attempt of this
 * process, so a user who stopped the agent is not fought), says hello, subscribes to mount, warning and
 * prompt, asks for the mount list, and then waits on three handles: the stop event, the request queue
 * (UI thread -> agent calls) and the connection's event handle (agent -> UI events). Results travel back
 * to the UI thread as posted messages that own their sd_json payload.
 *
 * The UI declares prompts.ui in hello and subscribes to "prompt": the agent routes prompt.request here, and
 * the answers (prompt.answer) leave through this thread (ui_ipc_answer). A prompt-host process (--prompt-host)
 * never starts an agent: its connect passes start_if_missing = 0 and it leaves when the agent is gone. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd/version.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_platform/sd_log.h"
#include "ui_admin_model.h"
#include "ui_int.h"
#include "ui_win.h"

#define UI_IPC_QUEUE       8u
#define UI_IPC_CALL_MS     10000u
#define UI_IPC_RETRY_MS    10000u
#define UI_IPC_CONNECT_MS  10000u
#define UI_IPC_UPDATE_MS   120000u   /* update.check: the manifest download may take a while */
#define UI_IPC_APPLY_MS    630000u   /* update.apply: the agent's staged setup waits up to 600 s (04 §9) */
#define UI_IPC_HKADD_MS    60000u    /* hostkey.add: the agent connects to the server and reads its host keys */

typedef struct ui_ipc_req {
  ui_ipc_kind kind;
  char method[32];              /* the longest is hostkey.announced.accept (24 characters) */
  char *params;                 /* heap copy, NULL when the call has no parameters */
  wchar_t drive[3];
} ui_ipc_req;

static struct {
  HANDLE thread;
  HANDLE stop;
  HANDLE wake;
  HANDLE start;                 /* "Agent not running - Start" (ui_ipc_start_agent): connect now and start the agent */
  CRITICAL_SECTION cs;
  int cs_ready;
  ui_ipc_req queue[UI_IPC_QUEUE];
  size_t count;
} g_ipc;

/* Agent features of the hello reply that the windows use (ui_win.h). */
static int features_of(sd_ipc_conn *c)
{
  int f = 0;
  if (sd_ipc_conn_has_feature(c, "log.tail"))
    f |= UI_FEAT_LOG_TAIL;
  if (sd_ipc_conn_has_feature(c, "config.reload"))
    f |= UI_FEAT_RELOAD;
  if (sd_ipc_conn_has_feature(c, "update.check"))
    f |= UI_FEAT_UPDATE;
  if (sd_ipc_conn_has_feature(c, "update.apply"))
    f |= UI_FEAT_UPDATE_APPLY;
  return f;
}

static void post_state(int up)
{
  PostMessageW(g_app.ctrl, UI_WM_IPC_STATE, (WPARAM)(up ? 1 : 0), 0);
}

static void post_json(UINT msg, sd_json *j)
{
  if (j == NULL)
    return;
  if (!PostMessageW(g_app.ctrl, msg, 0, (LPARAM)j))
    sd_json_free(j);
}

static void post_reply(ui_ipc_kind kind, sd_err err, const wchar_t *drive, sd_json *result)
{
  ui_ipc_reply *r = sd_alloc(sizeof(*r));
  if (r == NULL) {
    sd_json_free(result);
    return;
  }
  memset(r, 0, sizeof(*r));
  r->kind = kind;
  r->err = err;
  if (drive)
    wcscpy_s(r->drive, SD_COUNTOF(r->drive), drive);
  r->result = result;
  if (!PostMessageW(g_app.ctrl, UI_WM_IPC_REPLY, 0, (LPARAM)r)) {
    sd_json_free(result);
    sd_free(r);
  }
}

static int pop_request(ui_ipc_req *out)
{
  int got = 0;
  EnterCriticalSection(&g_ipc.cs);
  if (g_ipc.count > 0) {
    *out = g_ipc.queue[0];
    memmove(&g_ipc.queue[0], &g_ipc.queue[1], (g_ipc.count - 1) * sizeof(ui_ipc_req));
    g_ipc.count--;
    memset(&g_ipc.queue[g_ipc.count], 0, sizeof(ui_ipc_req));
    got = 1;
  }
  LeaveCriticalSection(&g_ipc.cs);
  return got;
}

/* Frees the parameters of a request. An answer carries a secret: its copy is wiped before it is freed. */
static void free_params(ui_ipc_req *r)
{
  if (r->params != NULL && r->kind == UI_IPC_ANSWER)
    SecureZeroMemory(r->params, strlen(r->params));
  sd_free(r->params);
  r->params = NULL;
}

static void fail_queued(void)
{
  ui_ipc_req r;
  while (pop_request(&r)) {
    post_reply(r.kind, SD_E_DISCONNECTED, r.drive, NULL);
    free_params(&r);
  }
}

static sd_err subscribe_topics(sd_ipc_conn *c)
{
  /* The agent sends every warning on both "mount" and "warning" (agent.c); subscribing to both would show
     each balloon twice, so warnings arrive on "mount" only. TODO: subscribe to "warning" when the agent
     drops the mount copy (proto 2, docs/design/m3-contracts-draft.md). */
  static const char k_params[] = "{\"topics\":[\"mount\",\"prompt\"]}";
  sd_json *res = NULL;
  sd_ipc_error err;
  sd_err e = sd_ipc_call_raw(c, "subscribe", k_params, sizeof(k_params) - 1, UI_IPC_CALL_MS, &res, &err);
  sd_json_free(res);
  return e;
}

/* Time allowed for one call: the updater calls are deferred and may take much longer than the others. */
static unsigned ui_ipc_call_ms(ui_ipc_kind kind)
{
  if (kind == UI_IPC_UPDATE_CHECK)
    return UI_IPC_UPDATE_MS;
  if (kind == UI_IPC_HK_ADD)
    return UI_IPC_HKADD_MS;
  if (kind == UI_IPC_UPDATE_APPLY)
    return UI_IPC_APPLY_MS;
  return UI_IPC_CALL_MS;
}

static int pump_requests(sd_ipc_conn *c)
{
  ui_ipc_req r;
  while (pop_request(&r)) {
    sd_json *res = NULL;
    sd_ipc_error err;
    sd_err e;

    memset(&err, 0, sizeof(err));
    e = sd_ipc_call_raw(c, r.method, r.params, r.params ? strlen(r.params) : 0, ui_ipc_call_ms(r.kind), &res, &err);
    if (r.kind == UI_IPC_LIST) {
      if (e == SD_OK)
        post_json(UI_WM_IPC_LIST, res);
      else
        sd_json_free(res);
    } else {
      post_reply(r.kind, e, r.drive, res);
    }
    free_params(&r);
    if (e == SD_E_DISCONNECTED)
      return 0;
  }
  return 1;
}

/* Returns 0 when the connection is lost, 1 when no event is pending any more. */
static int pump_events(sd_ipc_conn *c)
{
  for (;;) {
    sd_json *ev = NULL;
    sd_err e = sd_ipc_next_event(c, 0, &ev);
    if (e == SD_OK && ev != NULL) {
      post_json(UI_WM_IPC_EVENT, ev);
      continue;
    }
    if (e == SD_E_TIMEOUT || e == SD_OK)
      return 1;
    return 0;
  }
}

/* Serves one connection until it is lost (returns 0) or the stop event is set (returns 1). */
static int serve(sd_ipc_conn *c)
{
  HANDLE h[3];
  h[0] = g_ipc.stop;
  h[1] = g_ipc.wake;
  h[2] = sd_ipc_event_handle(c);
  for (;;) {
    DWORD w = WaitForMultipleObjects(3, h, FALSE, INFINITE);
    if (w == WAIT_OBJECT_0)
      return 1;
    if (w == WAIT_OBJECT_0 + 1) {
      if (!pump_requests(c))
        return 0;
    } else if (w == WAIT_OBJECT_0 + 2) {
      if (!pump_events(c))
        return 0;
    } else {
      return 0;
    }
  }
}

static DWORD WINAPI ipc_thread(void *arg)
{
  int first = 1;
  int failures = 0;
  int want_start = 0;
  (void)arg;
  for (;;) {
    sd_ipc_conn *c = NULL;
    sd_ipc_hello hello;
    sd_err e;
    int stop = 0;

    memset(&hello, 0, sizeof(hello));
    hello.client_kind = "ui";
    hello.client_version = SD_VERSION_STRING;
    hello.lang = sd_l10n_lang_code(sd_l10n_lang());
    hello.caps = SD_IPC_CAP_PROMPTS_UI;

    /* PROMPT-HOST RULE (03 §1.4): a --prompt-host process never starts the agent. The agent starts us, not
       the other way round. */
    if (want_start && !g_app.prompt_host) {
      /* the user asked for it in the status bar: the same start and connect as the CLI (03 §7.5) */
      e = sd_ipc_connect_agent_or_start(&hello, &c);
      post_reply(UI_IPC_AGENT_START, e, NULL, NULL);
    } else {
      e = sd_ipc_connect(SD_IPC_AGENT, &hello, first && !g_app.prompt_host, UI_IPC_CONNECT_MS, &c);
    }
    want_start = 0;
    first = 0;
    if (e == SD_OK) {
      sd_json *res = NULL;
      sd_ipc_error err;
      failures = 0;
      memset(&err, 0, sizeof(err));
      ResetEvent(g_ipc.start);          /* a click that came while we were connecting is answered by the connection */
      InterlockedExchange((volatile LONG *)&g_app.agent_features, features_of(c));
      post_state(1);
      if (subscribe_topics(c) == SD_OK &&
          sd_ipc_call_raw(c, "list", NULL, 0, UI_IPC_CALL_MS, &res, &err) == SD_OK) {
        post_json(UI_WM_IPC_LIST, res);
      } else {
        sd_json_free(res);
      }
      /* the open prompts of the agent: dialogs for prompts it no longer holds are closed (ui_prompt.c) */
      if (sd_ipc_conn_has_feature(c, "prompt.list")) {
        res = NULL;
        memset(&err, 0, sizeof(err));
        if (sd_ipc_call_raw(c, "prompt.list", NULL, 0, UI_IPC_CALL_MS, &res, &err) == SD_OK)
          post_json(UI_WM_IPC_PROMPTS, res);
        else
          sd_json_free(res);
      }
      /* the agent's event history: a UI that starts late shows what happened before (03 2.4, 7.7) */
      if (sd_ipc_conn_has_feature(c, "events.recent")) {
        res = NULL;
        memset(&err, 0, sizeof(err));
        if (sd_ipc_call_raw(c, "events.recent", NULL, 0, UI_IPC_CALL_MS, &res, &err) == SD_OK)
          post_json(UI_WM_IPC_HISTORY, res);
        else
          sd_json_free(res);
      }
      stop = serve(c) == 1;
      sd_ipc_close(c);
      InterlockedExchange((volatile LONG *)&g_app.agent_features, 0);
      post_state(0);
      fail_queued();
    } else {
      SD_LOGD("ui", "agent not reachable (%s)", sd_err_name(e));
      fail_queued();
      /* a prompt-host process whose agent does not answer twice has no work left: it leaves */
      if (g_app.prompt_host && ++failures >= 2) {
        post_state(0);
        break;
      }
    }
    if (stop)
      break;
    {
      HANDLE w[2];
      DWORD r;
      w[0] = g_ipc.stop;
      w[1] = g_ipc.start;
      r = WaitForMultipleObjects(2, w, FALSE, UI_IPC_RETRY_MS);
      if (r == WAIT_OBJECT_0)
        break;
      if (r == WAIT_OBJECT_0 + 1)
        want_start = 1;                 /* a request that arrived while connected was dropped at the connect below */
    }
  }
  fail_queued();
  return 0;
}

static sd_err enqueue(ui_ipc_kind kind, const char *method, const char *params, const wchar_t *drive)
{
  ui_ipc_req r;
  sd_err e = SD_OK;

  if (g_ipc.thread == NULL)
    return SD_E_SHUTDOWN;
  memset(&r, 0, sizeof(r));
  r.kind = kind;
  if (strlen(method) >= sizeof(r.method))
    return SD_E_INVALID_PARAM;
  strcpy_s(r.method, sizeof(r.method), method);
  if (params != NULL) {
    size_t n = strlen(params);
    r.params = sd_alloc(n + 1);
    if (r.params == NULL)
      return SD_E_NO_MEMORY;
    memcpy(r.params, params, n + 1);
  }
  if (drive != NULL)
    wcscpy_s(r.drive, SD_COUNTOF(r.drive), drive);

  EnterCriticalSection(&g_ipc.cs);
  if (g_ipc.count >= UI_IPC_QUEUE) {
    e = SD_E_BUSY;
  } else {
    g_ipc.queue[g_ipc.count++] = r;
  }
  LeaveCriticalSection(&g_ipc.cs);
  if (e != SD_OK) {
    free_params(&r);
    return e;
  }
  SetEvent(g_ipc.wake);
  return SD_OK;
}

sd_err ui_ipc_start(void)
{
  memset(&g_ipc, 0, sizeof(g_ipc));
  InitializeCriticalSection(&g_ipc.cs);
  g_ipc.cs_ready = 1;
  g_ipc.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_ipc.wake = CreateEventW(NULL, FALSE, FALSE, NULL);
  g_ipc.start = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (g_ipc.stop == NULL || g_ipc.wake == NULL || g_ipc.start == NULL)
    return SD_E_NO_MEMORY;
  g_ipc.thread = CreateThread(NULL, 0, ipc_thread, NULL, 0, NULL);
  if (g_ipc.thread == NULL)
    return SD_E_FAILURE;
  return SD_OK;
}

void ui_ipc_stop(void)
{
  if (g_ipc.thread != NULL) {
    SetEvent(g_ipc.stop);
    WaitForSingleObject(g_ipc.thread, 15000);
    CloseHandle(g_ipc.thread);
    g_ipc.thread = NULL;
  }
  if (g_ipc.stop)
    CloseHandle(g_ipc.stop);
  if (g_ipc.wake)
    CloseHandle(g_ipc.wake);
  if (g_ipc.start)
    CloseHandle(g_ipc.start);
  if (g_ipc.cs_ready)
    DeleteCriticalSection(&g_ipc.cs);
  memset(&g_ipc, 0, sizeof(g_ipc));
}

sd_err ui_ipc_list(void)
{
  return enqueue(UI_IPC_LIST, "list", NULL, NULL);
}

sd_err ui_ipc_unmount(const wchar_t *drive)
{
  char params[32];
  char d[4];
  ui_text_ascii(drive, d, sizeof(d));
  if (d[0] == 0 || d[1] != ':' || d[2] != 0)
    return SD_E_INVALID_PARAM;
  sprintf_s(params, sizeof(params), "{\"target\":\"%s\"}", d);
  return enqueue(UI_IPC_UNMOUNT, "unmount", params, drive);
}

sd_err ui_ipc_mount(const char *profile_id)
{
  char params[64];
  if (profile_id == NULL || strlen(profile_id) != 32)
    return SD_E_INVALID_PARAM;
  sprintf_s(params, sizeof(params), "{\"profile\":\"%s\"}", profile_id);
  return enqueue(UI_IPC_MOUNT, "mount", params, NULL);
}

/* mount with a complete params object (ui_mount_params_json): the profile or the ad-hoc connection, with the
   overrides of the mount dialog. The queue keeps its own copy. */
sd_err ui_ipc_mount_params(const char *json)
{
  if (json == NULL || json[0] != '{')
    return SD_E_INVALID_PARAM;
  return enqueue(UI_IPC_MOUNT, "mount", json, NULL);
}

/* config.reload: the agent re-reads the profile store (03 §2.4). A failed call is only logged. */
sd_err ui_ipc_config_reload(void)
{
  return enqueue(UI_IPC_RELOAD, "config.reload", NULL, NULL);
}

/* prompt.answer: json is the complete request object, NUL-terminated, with len bytes. The queue keeps its own
   copy, which is wiped after the call (free_params). The caller wipes its copy. In the elevated admin mode the
   answer goes to the service pipe instead (ui_admin_answer_route, ui_svc.c). */
sd_err ui_ipc_answer(const char *json, size_t len)
{
  if (json == NULL || strlen(json) != len)
    return SD_E_INVALID_PARAM;
  if (ui_admin_answer_route(g_app.elevated_admin) == UI_ROUTE_SERVICE)
    return ui_svc_answer(json, len);
  return enqueue(UI_IPC_ANSWER, "prompt.answer", json, NULL);
}

/* Generic call of the secondary windows (ui_win.c): the reply is UI_WM_IPC_REPLY with this kind, and the
   result is owned by the UI until the reply is handled. */
sd_err ui_ipc_call(ui_ipc_kind kind, const char *method, const char *params)
{
  if (method == NULL)
    return SD_E_INVALID_PARAM;
  return enqueue(kind, method, params, NULL);
}

/* The status bar's "Agent not running - Start" (03 §7.5): the thread connects at once and starts the agent when it is
   not running. The result comes back as UI_IPC_AGENT_START (error only; success is the agent state going up). A prompt
   host never starts an agent (1.4). Returns SD_E_SHUTDOWN when the thread is not running. */
sd_err ui_ipc_start_agent(void)
{
  if (g_ipc.thread == NULL || g_ipc.start == NULL)
    return SD_E_SHUTDOWN;
  if (g_app.prompt_host)
    return SD_E_ACCESS_DENIED;
  SetEvent(g_ipc.start);
  return SD_OK;
}
