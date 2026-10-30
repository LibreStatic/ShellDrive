/* sd_ipc client (03 §2.2 client side, §2.3).
 *
 * Connection: CreateFileW with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, message read mode,
 * then the anti-spoofing checks BEFORE anything is sent: pipe owner == our user SID (agent) or
 * LocalSystem (service); on Vista+ the server process must run in our session (agent).
 * A reader thread receives every message: responses complete the pending call, events go to a
 * bounded queue whose manual-reset event is sd_ipc_event_handle(). */
#include <windows.h>
#include <sddl.h>
#include <string.h>

#include "ipc_internal.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

#define CONN_MAX_EVENTS 256
#define CONN_READ_CHUNK (64u * 1024u)

#define SD_IPC_MAX_FEATURES 32
#define SD_IPC_FEATURE_MAX  32

typedef struct conn_evt { struct conn_evt *next; sd_json *msg; } conn_evt;

struct sd_ipc_conn {
  HANDLE pipe;
  HANDLE close_ev;           /* asks the reader to stop */
  HANDLE res_ev;             /* auto-reset: response or disconnect */
  HANDLE evt_ev;             /* manual-reset: event queue non-empty or disconnected */
  sd_thread reader;
  int reader_started;
  sd_mutex lock;
  int64_t awaited_id;        /* -1 = none */
  sd_json *res;
  int broken;
  conn_evt *eq_head, *eq_tail;
  uint32_t eq_count;
  int64_t next_id;
  DWORD server_pid;
  char features[SD_IPC_MAX_FEATURES][SD_IPC_FEATURE_MAX];   /* hello reply "features" (M3) */
  uint32_t nfeatures;
};

/* ---- reader ---- */

static void route_message(sd_ipc_conn *c, sd_json *msg)
{
  const char *type = sd_json_get_str(msg, "type");
  int64_t id = -1;
  if (type && strcmp(type, "res") == 0 && sd_json_get_int64(msg, "id", &id)) {
    sd_mutex_lock(&c->lock);
    if (id == c->awaited_id && c->res == NULL) {
      c->res = msg;
      msg = NULL;
      SetEvent(c->res_ev);
    }
    sd_mutex_unlock(&c->lock);
  } else if (type && strcmp(type, "evt") == 0) {
    conn_evt *e = (conn_evt *)sd_calloc(1, sizeof(*e));
    if (e) {
      e->msg = msg;
      msg = NULL;
      sd_mutex_lock(&c->lock);
      if (c->eq_count >= CONN_MAX_EVENTS) {       /* drop the oldest */
        conn_evt *old = c->eq_head;
        c->eq_head = old->next;
        if (c->eq_head == NULL) c->eq_tail = NULL;
        c->eq_count--;
        sd_json_free(old->msg);
        sd_free(old);
      }
      if (c->eq_tail) c->eq_tail->next = e; else c->eq_head = e;
      c->eq_tail = e;
      c->eq_count++;
      SetEvent(c->evt_ev);
      sd_mutex_unlock(&c->lock);
    }
  }
  sd_json_free(msg);   /* stale responses and unknown kinds */
}

static unsigned __stdcall reader_thread(void *arg)
{
  sd_ipc_conn *c = (sd_ipc_conn *)arg;
  HANDLE rd_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  uint8_t *buf = (uint8_t *)sd_alloc(CONN_READ_CHUNK);
  size_t cap = CONN_READ_CHUNK, len = 0;
  if (rd_ev == NULL || buf == NULL)
    goto out;
  for (;;) {
    OVERLAPPED ov;
    DWORD n = 0, gle;
    BOOL ok;
    HANDLE hs[2];
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = rd_ev;
    ResetEvent(rd_ev);
    ok = ReadFile(c->pipe, buf + len, (DWORD)(cap - len), NULL, &ov);
    gle = ok ? 0 : GetLastError();
    if (!ok && gle != ERROR_IO_PENDING && gle != ERROR_MORE_DATA)
      break;
    hs[0] = rd_ev;
    hs[1] = c->close_ev;
    if (WaitForMultipleObjects(2, hs, FALSE, INFINITE) != WAIT_OBJECT_0) {
      CancelIo(c->pipe);
      GetOverlappedResult(c->pipe, &ov, &n, TRUE);
      break;
    }
    ok = GetOverlappedResult(c->pipe, &ov, &n, FALSE);
    gle = ok ? 0 : GetLastError();
    len += n;
    if (!ok && gle == ERROR_MORE_DATA) {
      DWORD left = 0;
      size_t want;
      uint8_t *nb;
      if (!PeekNamedPipe(c->pipe, NULL, 0, NULL, NULL, &left) || left == 0)
        left = CONN_READ_CHUNK;
      want = len + left;
      if (want > SD_IPC_MAX_MESSAGE)
        break;                                   /* oversized message from the server */
      if (want > cap) {
        nb = (uint8_t *)sd_realloc(buf, want);
        if (nb == NULL)
          break;
        buf = nb;
        cap = want;
      }
      continue;
    }
    if (!ok)
      break;
    {
      sd_json *msg = NULL;
      if (sd_json_parse((const char *)buf, len, 32, &msg) == SD_OK && sd_json_type_of(msg) == SD_JSON_OBJECT)
        route_message(c, msg);
      else
        sd_json_free(msg);
    }
    len = 0;
    if (cap > CONN_READ_CHUNK) {
      uint8_t *nb = (uint8_t *)sd_realloc(buf, CONN_READ_CHUNK);
      if (nb) { buf = nb; cap = CONN_READ_CHUNK; }
    }
  }
out:
  sd_mutex_lock(&c->lock);
  c->broken = 1;
  SetEvent(c->res_ev);
  SetEvent(c->evt_ev);
  sd_mutex_unlock(&c->lock);
  if (rd_ev) CloseHandle(rd_ev);
  sd_free(buf);
  return 0;
}

/* ---- writing and calls ---- */

static sd_err conn_write(sd_ipc_conn *c, const void *p, size_t n, DWORD timeout_ms)
{
  OVERLAPPED ov;
  HANDLE ev;
  DWORD done = 0;
  BOOL ok;
  sd_err e = SD_OK;
  if (n > SD_IPC_MAX_MESSAGE)
    return SD_E_INVALID_PARAM;
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (ev == NULL)
    return SD_E_NO_MEMORY;
  memset(&ov, 0, sizeof(ov));
  ov.hEvent = ev;
  ok = WriteFile(c->pipe, p, (DWORD)n, NULL, &ov);
  if (!ok && GetLastError() != ERROR_IO_PENDING) {
    e = SD_E_DISCONNECTED;
  } else if (WaitForSingleObject(ev, timeout_ms) != WAIT_OBJECT_0) {
    CancelIo(c->pipe);
    GetOverlappedResult(c->pipe, &ov, &done, TRUE);
    e = SD_E_TIMEOUT;
  } else if (!GetOverlappedResult(c->pipe, &ov, &done, FALSE) || done != n) {
    e = SD_E_DISCONNECTED;
  }
  CloseHandle(ev);
  return e;
}

/* Sends a complete message with the given id and waits for the matching response. */
static sd_err conn_roundtrip(sd_ipc_conn *c, int64_t id, const void *msg, size_t len, DWORD timeout_ms,
                             sd_json **res)
{
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  sd_err e;
  *res = NULL;
  sd_mutex_lock(&c->lock);
  if (c->broken) {
    sd_mutex_unlock(&c->lock);
    return SD_E_DISCONNECTED;
  }
  c->awaited_id = id;
  sd_json_free(c->res);
  c->res = NULL;
  ResetEvent(c->res_ev);
  sd_mutex_unlock(&c->lock);
  e = conn_write(c, msg, len, timeout_ms);
  while (e == SD_OK) {
    uint64_t now = sd_tick_ms();
    DWORD wait = timeout_ms == INFINITE ? INFINITE : (DWORD)(now >= deadline ? 0 : deadline - now);
    DWORD w = WaitForSingleObject(c->res_ev, wait);
    sd_mutex_lock(&c->lock);
    if (c->res) {
      *res = c->res;
      c->res = NULL;
      c->awaited_id = -1;
      sd_mutex_unlock(&c->lock);
      return SD_OK;
    }
    if (c->broken) e = SD_E_DISCONNECTED;
    else if (w != WAIT_OBJECT_0) e = SD_E_TIMEOUT;
    sd_mutex_unlock(&c->lock);
  }
  sd_mutex_lock(&c->lock);
  c->awaited_id = -1;
  sd_mutex_unlock(&c->lock);
  return e;
}

static void copy_str(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (src)
    for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
  dst[i] = 0;
}

/* Interprets a response: result (re-rooted copy) or error. */
static sd_err take_result(sd_json *res, sd_json **result, sd_ipc_error *err)
{
  const sd_json *er = sd_json_get(res, "error");
  if (er) {
    const char *code = sd_json_get_str(er, "code");
    const char *detail = sd_json_get_str(er, "detail");
    const char *errname = sd_json_get_str(er, "err");
    int64_t xc = 0;
    sd_err e = errname ? sd_err_from_name(errname) : SD_ERR_COUNT;
    if ((e == SD_ERR_COUNT || e == SD_OK) && code)
      e = sd_err_from_name(code);
    if (e == SD_ERR_COUNT || e == SD_OK)
      e = SD_E_FAILURE;
    if (err) {
      memset(err, 0, sizeof(*err));
      err->err = e;
      copy_str(err->code, sizeof(err->code), code ? code : "internal");
      copy_str(err->detail, sizeof(err->detail), detail);
      err->exit_code = sd_json_get_int64(er, "exit_code", &xc) ? (int)xc : sd_ipc_exit_code_for_code(err->code);
    }
    return e;
  }
  if (result) {
    sd_wr w;
    sd_json_writer jw;
    sd_err e;
    const sd_json *r = sd_json_get(res, "result");
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    sd_jw_init(&jw, &w);
    if (r) sd_jw_value(&jw, r);
    else { sd_jw_obj_begin(&jw); sd_jw_obj_end(&jw); }
    e = sd_jw_finish(&jw);
    if (e == SD_OK)
      e = sd_json_parse((const char *)w.p, w.len, 32, result);
    sd_wr_free(&w);
    if (e != SD_OK) {
      if (err) sd_ipc_error_set(err, SD_E_INTERNAL, NULL, "cannot copy result");
      return SD_E_INTERNAL;
    }
  }
  if (err) {
    memset(err, 0, sizeof(*err));
    err->err = SD_OK;
  }
  return SD_OK;
}

sd_err sd_ipc_call_raw(sd_ipc_conn *c, const char *method, const char *params_json, size_t len,
                       DWORD timeout_ms, sd_json **result, sd_ipc_error *err)
{
  sd_wr w;
  sd_json_writer jw;
  sd_json *res = NULL;
  int64_t id;
  sd_err e;
  if (result) *result = NULL;
  if (c == NULL || method == NULL) {
    if (err) sd_ipc_error_set(err, SD_E_INVALID_PARAM, "usage", "invalid call");
    return SD_E_INVALID_PARAM;
  }
  id = ++c->next_id;
  sd_wr_init_secret(&w, SD_IPC_MAX_MESSAGE);   /* params may hold prompt answers */
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "req");
  sd_jw_key(&jw, "id"); sd_jw_int(&jw, id);
  sd_jw_key(&jw, "method"); sd_jw_cstr(&jw, method);
  sd_jw_key(&jw, "params");
  if (params_json && len) sd_jw_raw(&jw, params_json, len);
  else { sd_jw_obj_begin(&jw); sd_jw_obj_end(&jw); }
  sd_jw_obj_end(&jw);
  e = sd_jw_finish(&jw);
  if (e == SD_OK)
    e = conn_roundtrip(c, id, w.p, w.len, timeout_ms, &res);
  sd_wr_free(&w);
  if (e != SD_OK) {
    if (err) sd_ipc_error_set(err, e, e == SD_E_DISCONNECTED ? "agent_unavailable" : NULL, "call failed");
    return e;
  }
  e = take_result(res, result, err);
  sd_json_free(res);
  return e;
}

sd_err sd_ipc_call(sd_ipc_conn *c, const char *method, const sd_json *params,
                   DWORD timeout_ms, sd_json **result, sd_ipc_error *err)
{
  sd_wr w;
  sd_json_writer jw;
  sd_err e;
  if (params == NULL)
    return sd_ipc_call_raw(c, method, NULL, 0, timeout_ms, result, err);
  sd_wr_init_secret(&w, SD_IPC_MAX_MESSAGE);
  sd_jw_init(&jw, &w);
  sd_jw_value(&jw, params);
  e = sd_jw_finish(&jw);
  if (e == SD_OK)
    e = sd_ipc_call_raw(c, method, (const char *)w.p, w.len, timeout_ms, result, err);
  else if (err)
    sd_ipc_error_set(err, e, "usage", "invalid params");
  sd_wr_free(&w);
  return e;
}

sd_err sd_ipc_next_event(sd_ipc_conn *c, DWORD timeout_ms, sd_json **event)
{
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  *event = NULL;
  for (;;) {
    conn_evt *e = NULL;
    int broken;
    uint64_t now;
    sd_mutex_lock(&c->lock);
    if (c->eq_head) {
      e = c->eq_head;
      c->eq_head = e->next;
      if (c->eq_head == NULL) c->eq_tail = NULL;
      c->eq_count--;
    }
    if (c->eq_head == NULL && !c->broken)
      ResetEvent(c->evt_ev);
    broken = c->broken;
    sd_mutex_unlock(&c->lock);
    if (e) {
      *event = e->msg;
      sd_free(e);
      return SD_OK;
    }
    if (broken)
      return SD_E_DISCONNECTED;
    now = sd_tick_ms();
    if (timeout_ms != INFINITE && now >= deadline)
      return SD_E_TIMEOUT;
    WaitForSingleObject(c->evt_ev, timeout_ms == INFINITE ? INFINITE : (DWORD)(deadline - now));
  }
}

HANDLE sd_ipc_event_handle(sd_ipc_conn *c)
{
  return c ? c->evt_ev : NULL;
}

int sd_ipc_conn_has_feature(const sd_ipc_conn *c, const char *name)
{
  uint32_t i;
  if (c == NULL || name == NULL)
    return 0;
  for (i = 0; i < c->nfeatures; i++)
    if (strcmp(c->features[i], name) == 0)
      return 1;
  return 0;
}

void sd_ipc_close(sd_ipc_conn *c)
{
  conn_evt *e;
  if (c == NULL)
    return;
  if (c->reader_started) {
    SetEvent(c->close_ev);
    sd_thread_join(&c->reader, SD_WAIT_INFINITE, NULL);
  }
  if (c->pipe && c->pipe != INVALID_HANDLE_VALUE)
    CloseHandle(c->pipe);
  while ((e = c->eq_head) != NULL) {
    c->eq_head = e->next;
    sd_json_free(e->msg);
    sd_free(e);
  }
  sd_json_free(c->res);
  if (c->close_ev) CloseHandle(c->close_ev);
  if (c->res_ev) CloseHandle(c->res_ev);
  if (c->evt_ev) CloseHandle(c->evt_ev);
  sd_mutex_destroy(&c->lock);
  sd_free(c);
}

/* ---- connect ---- */

typedef BOOL (WINAPI *pfn_GetNamedPipeServerProcessId)(HANDLE, PULONG);

static sd_err verify_server(sd_ipc_conn *c, sd_ipc_endpoint ep)
{
  PSID expected = NULL;
  int free_expected = 0;
  sd_err e;
  const wchar_t *ov = ipc_expected_owner_override();
  if (ov) {
    if (!ConvertStringSidToSidW(ov, &expected))
      return SD_E_ACCESS_DENIED;
  } else if (ep == SD_IPC_SERVICE) {
    if (!ConvertStringSidToSidW(L"S-1-5-18", &expected))
      return SD_E_INTERNAL;
  } else {
    e = ipc_process_user_sid(&expected);
    if (e != SD_OK)
      return e;
    free_expected = 1;
  }
  e = ipc_verify_object_owner(c->pipe, expected, 0);
  if (free_expected) sd_free(expected); else LocalFree(expected);
  if (e != SD_OK) {
    SD_LOGE("ipc", "pipe server owner check failed (possible squatting)");
    return SD_E_ACCESS_DENIED;
  }
  {
    pfn_GetNamedPipeServerProcessId fn =
        (pfn_GetNamedPipeServerProcessId)sd_platform_resolve_by_name(L"kernel32.dll", "GetNamedPipeServerProcessId");
    ULONG pid = 0;
    if (fn && fn(c->pipe, &pid)) {
      c->server_pid = pid;
      if (ep == SD_IPC_AGENT) {
        DWORD theirs = 0, mine = 0;
        if (!ProcessIdToSessionId(pid, &theirs) || !ProcessIdToSessionId(GetCurrentProcessId(), &mine) ||
            theirs != mine) {
          SD_LOGE("ipc", "agent pipe server runs in another session");
          return SD_E_ACCESS_DENIED;
        }
      }
    }
  }
  return SD_OK;
}

static sd_err spawn_agent(void)
{
  wchar_t path[MAX_PATH], cmd[MAX_PATH + 32], dir[MAX_PATH];
  const wchar_t *ov = ipc_agent_path_override();
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  size_t i, slash = 0;
  path[0] = 0;
  if (ov) {
    ipc_wcat(path, SD_COUNTOF(path), ov);
  } else {
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
      return SD_E_INTERNAL;
    for (i = 0; path[i]; i++)
      if (path[i] == L'\\') slash = i + 1;
    path[slash] = 0;
    if (!ipc_wcat(path, SD_COUNTOF(path), L"shelldrive-host.exe"))
      return SD_E_INTERNAL;
  }
  dir[0] = 0;
  ipc_wcat(dir, SD_COUNTOF(dir), path);
  for (i = 0, slash = 0; dir[i]; i++)
    if (dir[i] == L'\\') slash = i;
  if (slash) dir[slash] = 0;
  cmd[0] = 0;
  if (!(ipc_wcat(cmd, SD_COUNTOF(cmd), L"\"") && ipc_wcat(cmd, SD_COUNTOF(cmd), path) &&
        ipc_wcat(cmd, SD_COUNTOF(cmd), L"\" agent")))
    return SD_E_INTERNAL;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(path, cmd, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, NULL,
                      slash ? dir : NULL, &si, &pi)) {
    SD_LOGW("ipc", "cannot start the agent: %u", (unsigned)GetLastError());
    return SD_E_NOT_FOUND;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return SD_OK;
}

static sd_err open_pipe(const wchar_t *name, sd_ipc_endpoint ep, int start_if_missing, DWORD timeout_ms,
                        HANDLE *out)
{
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  int spawned = 0, missing = 0;
  HANDLE ready = NULL;
  *out = INVALID_HANDLE_VALUE;
  for (;;) {
    HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    DWORD gle;
    uint64_t now;
    if (h != INVALID_HANDLE_VALUE) {
      if (ready) CloseHandle(ready);
      *out = h;
      return SD_OK;
    }
    gle = GetLastError();
    now = sd_tick_ms();
    if (now >= deadline)
      break;
    if (gle == ERROR_PIPE_BUSY) {
      WaitNamedPipeW(name, (DWORD)SD_MIN(deadline - now, 1000));
      continue;
    }
    if (gle != ERROR_FILE_NOT_FOUND)
      break;
    if (!start_if_missing || ep != SD_IPC_AGENT) {
      if (++missing < 3) {     /* ride out an instance turnover on the server */
        Sleep(20);
        continue;
      }
      if (ready) CloseHandle(ready);
      return SD_E_NOT_FOUND;
    }
    if (!spawned) {
      if (spawn_agent() != SD_OK) {
        if (ready) CloseHandle(ready);
        return SD_E_NOT_FOUND;
      }
      spawned = 1;
    }
    /* Wait on the ready event (owner-checked) when it exists, else poll the pipe. */
    if (ready == NULL)
      (void)sd_ipc_object_open(SD_IPC_OBJ_AGENT_READY, &ready);
    if (ready)
      WaitForSingleObject(ready, (DWORD)SD_MIN(deadline - now, 200));
    else
      Sleep(50);
  }
  if (ready) CloseHandle(ready);
  return spawned ? SD_E_TIMEOUT : SD_E_NOT_FOUND;
}

static sd_err connect_once(sd_ipc_endpoint ep, const sd_ipc_hello *hello, int start_if_missing,
                           DWORD timeout_ms, sd_ipc_conn **out)
{
  wchar_t sid[192], name[IPC_NAME_CCH];
  DWORD session = 0, mode = PIPE_READMODE_MESSAGE;
  sd_ipc_conn *c;
  sd_err e;
  if (out == NULL || hello == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (timeout_ms == 0)
    timeout_ms = 10000;
  e = sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session);
  if (e == SD_OK)
    e = sd_ipc_pipe_name(ep, sid, session, name, SD_COUNTOF(name));
  if (e != SD_OK)
    return e;
  c = (sd_ipc_conn *)sd_calloc(1, sizeof(*c));
  if (c == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&c->lock);
  c->awaited_id = -1;
  c->close_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  c->res_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  c->evt_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!c->close_ev || !c->res_ev || !c->evt_ev) {
    sd_ipc_close(c);
    return SD_E_NO_MEMORY;
  }
  e = open_pipe(name, ep, start_if_missing, timeout_ms, &c->pipe);
  if (e != SD_OK) {
    c->pipe = NULL;
    sd_ipc_close(c);
    return e;
  }
  if (!SetNamedPipeHandleState(c->pipe, &mode, NULL, NULL)) {
    sd_ipc_close(c);
    return SD_E_PROTOCOL;
  }
  /* Anti-spoofing checks before any byte is sent (03 §2.2). */
  e = verify_server(c, ep);
  if (e != SD_OK) {
    sd_ipc_close(c);
    return e;
  }
  e = sd_thread_create(&c->reader, reader_thread, c, 0, L"sd-ipc-client");
  if (e != SD_OK) {
    sd_ipc_close(c);
    return e;
  }
  c->reader_started = 1;
  {
    sd_wr w;
    sd_json_writer jw;
    sd_json *res = NULL;
    sd_ipc_error err;
    sd_wr_init(&w, 4096);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "hello");
    sd_jw_key(&jw, "id"); sd_jw_int(&jw, 0);
    sd_jw_key(&jw, "proto"); sd_jw_int(&jw, SD_IPC_PROTO);
    sd_jw_key(&jw, "min_proto"); sd_jw_int(&jw, SD_IPC_MIN_PROTO);
    sd_jw_key(&jw, "client"); sd_jw_cstr(&jw, hello->client_kind ? hello->client_kind : "cli");
    sd_jw_key(&jw, "client_version"); sd_jw_cstr(&jw, hello->client_version ? hello->client_version : SD_VERSION_STRING);
    sd_jw_key(&jw, "lang"); sd_jw_cstr(&jw, hello->lang ? hello->lang : "en");
    sd_jw_key(&jw, "pid"); sd_jw_int(&jw, (int64_t)GetCurrentProcessId());
    sd_jw_key(&jw, "caps");
    sd_jw_arr_begin(&jw);
    if (hello->caps & SD_IPC_CAP_PROMPTS_CONSOLE) sd_jw_cstr(&jw, "prompts.console");
    if (hello->caps & SD_IPC_CAP_PROMPTS_UI) sd_jw_cstr(&jw, "prompts.ui");
    sd_jw_arr_end(&jw);
    sd_jw_obj_end(&jw);
    e = sd_jw_finish(&jw);
    if (e == SD_OK)
      e = conn_roundtrip(c, 0, w.p, w.len, timeout_ms, &res);
    sd_wr_free(&w);
    if (e == SD_OK) {
      sd_json *result = NULL;
      e = take_result(res, &result, &err);
      if (e == SD_OK) {
        int64_t pid = 0;
        if (sd_json_get_int64(result, "server_pid", &pid) && c->server_pid == 0)
          c->server_pid = (DWORD)pid;
        {
          const sd_json *fs = sd_json_get(result, "features");
          size_t k, nf = sd_json_count(fs);
          for (k = 0; k < nf && c->nfeatures < SD_IPC_MAX_FEATURES; k++) {
            size_t fn = 0;
            const char *f = sd_json_str(sd_json_at(fs, k), &fn);
            if (f && fn > 0 && fn < SD_IPC_FEATURE_MAX) {
              memcpy(c->features[c->nfeatures], f, fn);
              c->features[c->nfeatures][fn] = 0;
              c->nfeatures++;
            }
          }
        }
      } else if (strcmp(err.code, "proto_unsupported") == 0) {
        e = SD_E_PROTOCOL;
      }
      sd_json_free(result);
    }
    sd_json_free(res);
    if (e != SD_OK) {
      sd_ipc_close(c);
      return e;
    }
  }
  *out = c;
  return SD_OK;
}

static volatile LONG g_connect_retries;

uint32_t sd_ipc_test_connect_retries(void) { return (uint32_t)g_connect_retries; }

sd_err sd_ipc_connect(sd_ipc_endpoint ep, const sd_ipc_hello *hello, int start_if_missing,
                      DWORD timeout_ms, sd_ipc_conn **out)
{
  uint64_t deadline;
  int attempt;
  if (timeout_ms == 0)
    timeout_ms = 10000;
  deadline = sd_tick_ms() + timeout_ms;
  for (attempt = 0;; attempt++) {
    uint64_t now = sd_tick_ms();
    DWORD left = now >= deadline ? 1 : (DWORD)(deadline - now);
    sd_err e = connect_once(ep, hello, start_if_missing, left, out);
    /* Defense only: an instance that breaks before hello completes (a server that closes instances,
       e.g. quotas, or an older agent with the ERROR_PIPE_CONNECTED listen bug) shows up as a broken
       pipe: retry a few times. The current server never drops an attaching client
       (ipc_instance_turnover_under_load checks that no retry happens). */
    if (e != SD_E_DISCONNECTED || attempt >= 4 || sd_tick_ms() >= deadline)
      return e;
    InterlockedIncrement(&g_connect_retries);
    SD_LOGD("ipc", "connect: instance broke before hello, retrying");
    Sleep(10);
  }
}

sd_err sd_ipc_connect_agent_or_start(const sd_ipc_hello *hello, sd_ipc_conn **out)
{
  return sd_ipc_connect(SD_IPC_AGENT, hello, 1, SD_IPC_AGENT_START_TIMEOUT_MS, out);
}
