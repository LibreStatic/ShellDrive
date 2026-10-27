/* shelldrive-ui: the agent client thread (03 §2, §1.4).
 *
 * One thread owns the sd_ipc_conn: it connects (starting the agent only at the first attempt of this
 * process, so a user who stopped the agent is not fought), says hello, subscribes to mount, warning and
 * prompt, asks for the mount list, and then waits on three handles: the stop event, the request queue
 * (UI thread -> agent calls) and the connection's event handle (agent -> UI events). Results travel back
 * to the UI thread as posted messages that own their sd_json payload.
 *
 * The prompt topic is subscribed without declaring prompts.ui, so the agent never routes a prompt here;
 * the prompt host is the next package. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd/version.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_platform/sd_log.h"
#include "ui_int.h"

#define UI_IPC_QUEUE       8u
#define UI_IPC_CALL_MS     10000u
#define UI_IPC_RETRY_MS    10000u
#define UI_IPC_CONNECT_MS  10000u

typedef struct ui_ipc_req {
  ui_ipc_kind kind;
  char method[24];
  char *params;                 /* heap copy, NULL when the call has no parameters */
  wchar_t drive[3];
} ui_ipc_req;

static struct {
  HANDLE thread;
  HANDLE stop;
  HANDLE wake;
  CRITICAL_SECTION cs;
  int cs_ready;
  ui_ipc_req queue[UI_IPC_QUEUE];
  size_t count;
} g_ipc;

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

static void fail_queued(void)
{
  ui_ipc_req r;
  while (pop_request(&r)) {
    post_reply(r.kind, SD_E_DISCONNECTED, r.drive, NULL);
    sd_free(r.params);
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

static int pump_requests(sd_ipc_conn *c)
{
  ui_ipc_req r;
  while (pop_request(&r)) {
    sd_json *res = NULL;
    sd_ipc_error err;
    sd_err e;

    memset(&err, 0, sizeof(err));
    e = sd_ipc_call_raw(c, r.method, r.params, r.params ? strlen(r.params) : 0, UI_IPC_CALL_MS, &res, &err);
    if (r.kind == UI_IPC_LIST) {
      if (e == SD_OK)
        post_json(UI_WM_IPC_LIST, res);
      else
        sd_json_free(res);
    } else {
      post_reply(r.kind, e, r.drive, res);
    }
    sd_free(r.params);
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
    hello.caps = 0;                     /* prompts.ui is not declared yet (see the file comment) */

    /* A prompt host (--prompt-host) was started by the agent: it never starts one itself (03 §2.5), and it
       exits when the agent is gone (post_state(0) makes the UI thread quit). */
    e = sd_ipc_connect(SD_IPC_AGENT, &hello, first && !g_app.prompt_host, UI_IPC_CONNECT_MS, &c);
    first = 0;
    if (e == SD_OK) {
      sd_json *res = NULL;
      sd_ipc_error err;
      memset(&err, 0, sizeof(err));
      post_state(1);
      if (subscribe_topics(c) == SD_OK &&
          sd_ipc_call_raw(c, "list", NULL, 0, UI_IPC_CALL_MS, &res, &err) == SD_OK) {
        post_json(UI_WM_IPC_LIST, res);
      } else {
        sd_json_free(res);
      }
      stop = serve(c) == 1;
      sd_ipc_close(c);
      post_state(0);
      fail_queued();
    } else {
      SD_LOGD("ui", "agent not reachable (%s)", sd_err_name(e));
      fail_queued();
      if (g_app.prompt_host) {
        SD_LOGI("ui", "prompt host: no agent, exiting");
        post_state(0);
      }
    }
    if (stop || g_app.prompt_host)
      break;
    if (WaitForSingleObject(g_ipc.stop, UI_IPC_RETRY_MS) == WAIT_OBJECT_0)
      break;
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
    sd_free(r.params);
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
  if (g_ipc.stop == NULL || g_ipc.wake == NULL)
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
