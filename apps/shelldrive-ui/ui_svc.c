/* shelldrive-ui: the service pipe client (03 §2.6 rule 3, §1.4, TM-R25).
 *
 * One thread per process, two uses:
 *  - the attention watch (the normal UI of a logged-on administrator): subscribes to the content-free "attention"
 *    topic and posts the count of prompts waiting for an administrator (UI_WM_SVC_ATTENTION). The service sends the
 *    current count when the subscription starts and again on every change. Other users never start this thread.
 *  - the admin mode (--elevated-admin): subscribes to "prompt" and "attention" with the prompts.ui capability, lists
 *    the open prompts (prompt.list, posted as UI_WM_IPC_PROMPTS), forwards prompt.request and prompt.closed as
 *    UI_WM_IPC_EVENT (the prompt dialogs of ui_prompt.c show them) and sends the answers (prompt.answer). It posts
 *    UI_WM_IPC_STATE like the agent thread does, so the prompt host rules (leave when the peer goes) apply.
 *
 * The thread never starts the service: sd_ipc_connect with SD_IPC_SERVICE does not spawn anything. Every
 * connection is verified by sd_ipc (owner SID of the pipe). The answers carry secrets: their copies are wiped.
 * Nothing here logs the content of an event or an answer. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <stdio.h>

#include "sd/version.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "ui_admin_model.h"
#include "ui_int.h"
#include "ui_win.h"

#define UI_SVC_QUEUE       8u
#define UI_SVC_CALL_MS     10000u
#define UI_SVC_CONNECT_MS  5000u
#define UI_SVC_WATCH_MS    60000u    /* attention watch: the service is retried this often */
#define UI_SVC_ADMIN_MS    10000u    /* admin mode: retried this often, then it leaves (two failures) */

typedef struct ui_svc_req {
  char method[24];
  char *params;                 /* heap copy of the prompt.answer object, wiped after the call */
} ui_svc_req;

static struct {
  HANDLE thread;
  HANDLE stop;
  HANDLE wake;
  CRITICAL_SECTION cs;
  int cs_ready;
  int admin;
  ui_svc_req queue[UI_SVC_QUEUE];
  size_t count;
} g_svc;

static HANDLE g_child;          /* the last elevated relaunch: a second one is not started while it runs */
static HANDLE g_child_page;     /* the same for the Service page (--elevated-service) */

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

static void free_req(ui_svc_req *r)
{
  if (r->params != NULL) {
    SecureZeroMemory(r->params, strlen(r->params));
    sd_free(r->params);
  }
  r->params = NULL;
}

static int pop_request(ui_svc_req *out)
{
  int got = 0;
  EnterCriticalSection(&g_svc.cs);
  if (g_svc.count > 0) {
    *out = g_svc.queue[0];
    memmove(&g_svc.queue[0], &g_svc.queue[1], (g_svc.count - 1) * sizeof(ui_svc_req));
    g_svc.count--;
    memset(&g_svc.queue[g_svc.count], 0, sizeof(ui_svc_req));
    got = 1;
  }
  LeaveCriticalSection(&g_svc.cs);
  return got;
}

static void fail_queued(void)
{
  ui_svc_req r;
  while (pop_request(&r))
    free_req(&r);
}

static sd_err connect_service(sd_ipc_conn **c)
{
  sd_ipc_hello hello;
  memset(&hello, 0, sizeof(hello));
  hello.client_kind = "ui";
  hello.client_version = SD_VERSION_STRING;
  hello.lang = sd_l10n_lang_code(sd_l10n_lang());
  hello.caps = g_svc.admin ? SD_IPC_CAP_PROMPTS_UI : 0;
  return sd_ipc_connect(SD_IPC_SERVICE, &hello, 0, UI_SVC_CONNECT_MS, c);
}

static sd_err subscribe(sd_ipc_conn *c)
{
  static const char k_admin[] = "{\"topics\":[\"prompt\",\"attention\"]}";
  static const char k_watch[] = "{\"topics\":[\"attention\"]}";
  const char *params = g_svc.admin ? k_admin : k_watch;
  sd_json *res = NULL;
  sd_ipc_error err;
  sd_err e;
  memset(&err, 0, sizeof(err));
  e = sd_ipc_call_raw(c, "subscribe", params, strlen(params), UI_SVC_CALL_MS, &res, &err);
  sd_json_free(res);
  return e;
}

/* The open prompts at the start of the admin mode (the dialogs of prompts that came before this connection). */
static void list_prompts(sd_ipc_conn *c)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  memset(&err, 0, sizeof(err));
  if (sd_ipc_call_raw(c, "prompt.list", NULL, 0, UI_SVC_CALL_MS, &res, &err) == SD_OK)
    post_json(UI_WM_IPC_PROMPTS, res);
  else
    sd_json_free(res);
}

static void handle_event(sd_json *ev)
{
  const char *name = sd_json_get_str(ev, "event");
  const sd_json *data = sd_json_get(ev, "data");
  if (name != NULL && strcmp(name, "attention") == 0) {
    int count = 0;
    if (ui_admin_parse_attention(data, &count) == SD_OK)
      PostMessageW(g_app.ctrl, UI_WM_SVC_ATTENTION, (WPARAM)count, 0);
    sd_json_free(ev);
    return;
  }
  if (g_svc.admin && name != NULL && (strcmp(name, "prompt.request") == 0 || strcmp(name, "prompt.closed") == 0)) {
    post_json(UI_WM_IPC_EVENT, ev);
    return;
  }
  sd_json_free(ev);
}

/* Returns 0 when the connection is lost, 1 when no event is pending any more. */
static int pump_events(sd_ipc_conn *c)
{
  for (;;) {
    sd_json *ev = NULL;
    sd_err e = sd_ipc_next_event(c, 0, &ev);
    if (e == SD_OK && ev != NULL) {
      handle_event(ev);
      continue;
    }
    if (e == SD_E_TIMEOUT || e == SD_OK)
      return 1;
    return 0;
  }
}

/* Sends the queued answers. Returns 0 when the connection is lost. */
static int pump_answers(sd_ipc_conn *c)
{
  ui_svc_req r;
  while (pop_request(&r)) {
    sd_json *res = NULL;
    sd_ipc_error err;
    sd_err e;
    memset(&err, 0, sizeof(err));
    e = sd_ipc_call_raw(c, r.method, r.params, strlen(r.params), UI_SVC_CALL_MS, &res, &err);
    sd_json_free(res);
    /* the outcome only: the dialog closed when the answer was queued, and a refused one says why in the log */
    if (e != SD_OK)
      SD_LOGW("ui", "service did not accept the prompt answer (%s)", sd_err_name(e));
    free_req(&r);
    if (e == SD_E_DISCONNECTED) {
      fail_queued();
      return 0;
    }
  }
  return 1;
}

/* Serves one connection until it is lost (returns 0) or the stop event is set (returns 1). */
static int serve(sd_ipc_conn *c)
{
  HANDLE h[3];
  h[0] = g_svc.stop;
  h[1] = g_svc.wake;
  h[2] = sd_ipc_event_handle(c);
  for (;;) {
    DWORD w = WaitForMultipleObjects(3, h, FALSE, INFINITE);
    if (w == WAIT_OBJECT_0)
      return 1;
    if (w == WAIT_OBJECT_0 + 1) {
      if (!pump_answers(c))
        return 0;
    } else if (w == WAIT_OBJECT_0 + 2) {
      if (!pump_events(c))
        return 0;
    } else {
      return 0;
    }
  }
}

static DWORD WINAPI svc_thread(void *arg)
{
  int failures = 0;
  (void)arg;
  for (;;) {
    sd_ipc_conn *c = NULL;
    sd_err e;
    int stop = 0;

    e = connect_service(&c);
    if (e == SD_OK) {
      failures = 0;
      if (subscribe(c) == SD_OK) {
        if (g_svc.admin) {
          post_state(1);
          list_prompts(c);
        }
        stop = serve(c) == 1;
        sd_ipc_close(c);
        if (g_svc.admin) {
          /* the service went away (or stopped): the prompts it held are gone with it, so this process leaves */
          fail_queued();
          post_state(0);
          break;
        }
      } else {
        /* admin mode without the rights (access_denied on prompt): nothing to do here, leave */
        sd_ipc_close(c);
        SD_LOGW("ui", "the service refused the subscription (%s)", sd_err_name(e));
        if (g_svc.admin) {
          fail_queued();
          post_state(0);
          break;
        }
      }
    } else {
      SD_LOGD("ui", "service pipe not reachable (%s)", sd_err_name(e));
      if (g_svc.admin) {
        fail_queued();
        if (++failures >= 2) {
          post_state(0);
          break;
        }
      }
    }
    if (stop)
      break;
    if (WaitForSingleObject(g_svc.stop, g_svc.admin ? UI_SVC_ADMIN_MS : UI_SVC_WATCH_MS) == WAIT_OBJECT_0)
      break;
  }
  fail_queued();
  return 0;
}

sd_err ui_svc_start(int admin)
{
  memset(&g_svc, 0, sizeof(g_svc));
  g_svc.admin = admin ? 1 : 0;
  InitializeCriticalSection(&g_svc.cs);
  g_svc.cs_ready = 1;
  g_svc.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_svc.wake = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (g_svc.stop == NULL || g_svc.wake == NULL)
    return SD_E_NO_MEMORY;
  g_svc.thread = CreateThread(NULL, 0, svc_thread, NULL, 0, NULL);
  if (g_svc.thread == NULL)
    return SD_E_FAILURE;
  return SD_OK;
}

void ui_svc_stop(void)
{
  if (g_svc.thread != NULL) {
    SetEvent(g_svc.stop);
    WaitForSingleObject(g_svc.thread, 15000);
    CloseHandle(g_svc.thread);
    g_svc.thread = NULL;
  }
  if (g_svc.stop)
    CloseHandle(g_svc.stop);
  if (g_svc.wake)
    CloseHandle(g_svc.wake);
  if (g_svc.cs_ready)
    DeleteCriticalSection(&g_svc.cs);
  memset(&g_svc, 0, sizeof(g_svc));
  if (g_child != NULL) {
    CloseHandle(g_child);
    g_child = NULL;
  }
  if (g_child_page != NULL) {
    CloseHandle(g_child_page);
    g_child_page = NULL;
  }
}

sd_err ui_svc_answer(const char *json, size_t len)
{
  ui_svc_req r;
  sd_err e = SD_OK;
  size_t n;

  if (json == NULL || strlen(json) != len)
    return SD_E_INVALID_PARAM;
  if (!g_svc.admin || g_svc.thread == NULL)
    return SD_E_SHUTDOWN;
  memset(&r, 0, sizeof(r));
  strcpy_s(r.method, sizeof(r.method), "prompt.answer");
  n = strlen(json);
  r.params = sd_alloc(n + 1);
  if (r.params == NULL)
    return SD_E_NO_MEMORY;
  memcpy(r.params, json, n + 1);

  EnterCriticalSection(&g_svc.cs);
  if (g_svc.count >= UI_SVC_QUEUE)
    e = SD_E_BUSY;
  else
    g_svc.queue[g_svc.count++] = r;
  LeaveCriticalSection(&g_svc.cs);
  if (e != SD_OK) {
    free_req(&r);
    return e;
  }
  SetEvent(g_svc.wake);
  return SD_OK;
}

int ui_svc_user_is_admin(void)
{
  HANDLE tok = NULL, check = NULL;
  TOKEN_LINKED_TOKEN linked;
  DWORD need = 0;
  PSID admins = NULL;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  BOOL member = FALSE;
  int ok = 0;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &tok))
    return 0;
  check = tok;
  /* a split token (UAC): the filtered token denies the Administrators group; the linked token is the elevated one */
  memset(&linked, 0, sizeof(linked));
  if (sd_os_at_least(6, 0, 0) && GetTokenInformation(tok, TokenLinkedToken, &linked, sizeof(linked), &need) &&
      linked.LinkedToken != NULL)
    check = linked.LinkedToken;
  if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &admins)) {
    if (CheckTokenMembership(check, admins, &member))
      ok = member ? 1 : 0;
    FreeSid(admins);
  }
  if (check != tok && check != NULL)
    CloseHandle(check);
  CloseHandle(tok);
  return ok;
}

int ui_svc_process_elevated(void)
{
  HANDLE tok = NULL;
  TOKEN_ELEVATION te;
  DWORD need = 0;
  int ok = 0;
  if (!sd_os_at_least(6, 0, 0))
    return ui_svc_user_is_admin();      /* no split token on XP: an administrator always runs with the full token */
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  memset(&te, 0, sizeof(te));
  if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &need))
    ok = te.TokenIsElevated ? 1 : 0;
  CloseHandle(tok);
  return ok;
}

/* ShellExecute of this executable with args (verb runas on Vista and later); *child keeps the process so that a
   second launch is not started while the first one runs. */
static int launch_elevated(HWND owner, HANDLE *child, const wchar_t *args)
{
  SHELLEXECUTEINFOW sei;
  wchar_t path[MAX_PATH];

  if (*child != NULL) {
    if (WaitForSingleObject(*child, 0) == WAIT_TIMEOUT)
      return 1;                       /* already running: do not open a second window */
    CloseHandle(*child);
    *child = NULL;
  }
  if (GetModuleFileNameW(NULL, path, SD_COUNTOF(path)) == 0)
    return 0;
  memset(&sei, 0, sizeof(sei));
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
  sei.hwnd = owner;
  sei.lpVerb = ui_admin_launch_verb(sd_os_at_least(6, 0, 0));
  sei.lpFile = path;
  sei.lpParameters = args;
  sei.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&sei)) {
    /* the user declining the UAC prompt is not an error to report */
    if (GetLastError() != ERROR_CANCELLED)
      MessageBoxW(owner, sd_l10n_get(SD_MSG_UI_ADMIN_LAUNCH_FAILED), L"ShellDrive", MB_OK | MB_ICONERROR);
    return 0;
  }
  *child = sei.hProcess;
  return 1;
}

int ui_svc_launch_admin(HWND owner)
{
  return launch_elevated(owner, &g_child, L"--elevated-admin");
}

int ui_svc_launch_service_page(HWND owner)
{
  return launch_elevated(owner, &g_child_page, L"--elevated-service");
}
