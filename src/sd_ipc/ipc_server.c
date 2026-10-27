/* sd_ipc server (03 §2.2, §2.3; TM-R25 basics).
 *
 * One pipe thread per server. Reads and writes are overlapped with completion routines
 * (ReadFileEx/WriteFileEx), the thread waits alertably on {stop, connect, wake}. One pending
 * instance is always listening while fewer than max_instances exist. Clients are checked at hello
 * (impersonation at identification level: token user, integrity >= medium, not an AppContainer);
 * every error path closes the instance. Messages over max_message, malformed JSON, requests before
 * hello and output queues over 8 MiB close the connection. */
#include <windows.h>
#include <string.h>

#include "ipc_internal.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

#define IPC_READ_CHUNK     (64u * 1024u)
#define IPC_MAX_OUT_BYTES  (8u * 1024u * 1024u)
#define IPC_MAX_TOPICS     16
#define IPC_TOPIC_LEN      24
#define IPC_PIPE_BUF       (64u * 1024u)

#ifndef PIPE_REJECT_REMOTE_CLIENTS
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008
#endif

typedef struct ipc_msg {
  struct ipc_msg *next;
  uint64_t client_id;                 /* 0 = broadcast */
  uint32_t caps;                      /* broadcast: every bit must be in the client's caps */
  uint64_t exclude;                   /* broadcast: client id that never receives it (0 = none) */
  char topic[IPC_TOPIC_LEN];
  size_t len;
  char data[1];
} ipc_msg;

struct sd_ipc_client {
  OVERLAPPED read_ov;
  OVERLAPPED write_ov;
  sd_ipc_server *srv;
  struct sd_ipc_client *next;
  HANDLE pipe;
  uint64_t id;
  int hello_done, closing, close_after_write;
  int cur_req_active, deferred;      /* M3: inside a handler call; the handler deferred its reply */
  int64_t cur_req_id;
  int pending;                        /* outstanding ReadFileEx/WriteFileEx */
  uint8_t *rbuf;
  size_t rcap, rlen;
  ipc_msg *out_head, *out_tail;
  size_t out_bytes;
  int writing;
  char topics[IPC_MAX_TOPICS][IPC_TOPIC_LEN];
  uint32_t ntopics;
  uint32_t caps;
  char lang[8];
  char kind[16];                      /* hello "client" */
  PSID sid;
  int elevated, admin;
  DWORD pid;
  uint64_t last_activity;
  uint64_t rate_window;
  uint32_t rate_count;
};

struct sd_ipc_server {
  sd_ipc_endpoint ep;
  sd_ipc_server_cfg cfg;
  wchar_t name[IPC_NAME_CCH];
  PSECURITY_DESCRIPTOR sd;
  PSID own_sid;
  HANDLE stop_ev, wake_ev, connect_ev;
  HANDLE pending_pipe;
  int pending_connected;              /* ConnectNamedPipe said ERROR_PIPE_CONNECTED (connect_ov unused) */
  OVERLAPPED connect_ov;
  sd_thread thread;
  sd_mutex lock;                      /* queue, client list, counters */
  ipc_msg *q_head, *q_tail;
  sd_ipc_client *clients;
  uint32_t ninstances;                /* connected clients + pending listener */
  uint32_t nhello;
  uint64_t next_id;
  int stopping;
};

static void client_close(sd_ipc_client *c);
static void client_start_read(sd_ipc_client *c);
static void client_pump_write(sd_ipc_client *c);

/* ---- instances ---- */

static HANDLE create_instance(sd_ipc_server *s, int first)
{
  SECURITY_ATTRIBUTES sa;
  DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
  DWORD pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT;
  if (sd_os_at_least(6, 0, 0))
    pipe_mode |= PIPE_REJECT_REMOTE_CLIENTS;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = s->sd;
  sa.bInheritHandle = FALSE;
  return CreateNamedPipeW(s->name, open_mode, pipe_mode, s->cfg.max_instances, IPC_PIPE_BUF, IPC_PIPE_BUF,
                          0, &sa);
}

/* Starts the overlapped listen on a new instance h (already counted in ninstances). A client can
   attach between CreateNamedPipeW and ConnectNamedPipe; the call then fails with ERROR_PIPE_CONNECTED
   without touching connect_ov (Internal stays STATUS_PENDING), so on_connected must not ask
   GetOverlappedResult about it: pending_connected records that case. Returns the error, 0 = ok. */
static DWORD start_listen(sd_ipc_server *s, HANDLE h)
{
  memset(&s->connect_ov, 0, sizeof(s->connect_ov));
  s->connect_ov.hEvent = s->connect_ev;
  ResetEvent(s->connect_ev);
  s->pending_pipe = h;
  s->pending_connected = 0;
  if (!ConnectNamedPipe(h, &s->connect_ov)) {
    DWORD gle = GetLastError();
    if (gle == ERROR_PIPE_CONNECTED) {
      s->pending_connected = 1;
      SetEvent(s->connect_ev);
    } else if (gle != ERROR_IO_PENDING) {
      s->pending_pipe = NULL;
      return gle;
    }
  }
  return 0;
}

/* Creates the listening instance if the instance budget allows. */
static void listen_next(sd_ipc_server *s)
{
  HANDLE h;
  DWORD gle;
  if (s->pending_pipe != NULL || s->stopping || s->ninstances >= s->cfg.max_instances)
    return;
  h = create_instance(s, 0);
  if (h == INVALID_HANDLE_VALUE) {
    SD_LOGW("ipc", "CreateNamedPipeW failed: %u", (unsigned)GetLastError());
    return;
  }
  s->ninstances++;
  gle = start_listen(s, h);
  if (gle != 0) {
    /* ERROR_NO_DATA: a client attached and left before the listen; nothing to serve. */
    if (gle != ERROR_NO_DATA)
      SD_LOGW("ipc", "ConnectNamedPipe failed: %u", (unsigned)gle);
    CloseHandle(h);
    s->ninstances--;
  }
}

static void on_connected(sd_ipc_server *s)
{
  DWORD n;
  HANDLE h = s->pending_pipe;
  sd_ipc_client *c;
  ResetEvent(s->connect_ev);
  if (h == NULL)
    return;
  if (!s->pending_connected && !GetOverlappedResult(h, &s->connect_ov, &n, FALSE)) {
    if (GetLastError() == ERROR_IO_INCOMPLETE)
      return;                /* still listening (spurious wake): keep the instance */
    s->pending_pipe = NULL;
    listen_next(s);          /* keep the name alive: a new instance before the old one closes */
    CloseHandle(h);
    s->ninstances--;
    listen_next(s);
    return;
  }
  s->pending_pipe = NULL;
  s->pending_connected = 0;
  c = (sd_ipc_client *)sd_calloc(1, sizeof(*c));
  if (c)
    c->rbuf = (uint8_t *)sd_alloc(IPC_READ_CHUNK);
  if (c == NULL || c->rbuf == NULL) {
    if (c) sd_free(c);
    listen_next(s);
    CloseHandle(h);
    s->ninstances--;
    listen_next(s);
    return;
  }
  c->srv = s;
  c->pipe = h;
  c->rcap = IPC_READ_CHUNK;
  c->last_activity = sd_tick_ms();
  memcpy(c->lang, "en", 3);
  sd_mutex_lock(&s->lock);
  c->id = ++s->next_id;
  c->next = s->clients;
  s->clients = c;
  sd_mutex_unlock(&s->lock);
  SD_LOGD("ipc", "client %llu connected", (unsigned long long)c->id);
  /* Listen again BEFORE the read: if this client is already gone, closing its instance must not
     leave the pipe name without any instance (clients would see ERROR_FILE_NOT_FOUND). */
  listen_next(s);
  client_start_read(c);
}

/* ---- client teardown ---- */

static void client_free(sd_ipc_client *c)
{
  sd_ipc_server *s = c->srv;
  sd_ipc_client **pp;
  ipc_msg *m;
  int was_hello = c->hello_done;
  uint64_t id = c->id;
  sd_mutex_lock(&s->lock);
  for (pp = &s->clients; *pp; pp = &(*pp)->next) {
    if (*pp == c) {
      *pp = c->next;
      break;
    }
  }
  if (was_hello)
    s->nhello--;
  sd_mutex_unlock(&s->lock);
  SD_LOGD("ipc", "client %llu freed (hello %d)", (unsigned long long)id, was_hello);
  listen_next(s);            /* see on_connected: never let the last instance disappear */
  /* No DisconnectNamedPipe: it would make the instance connectable again for a moment before the
     CloseHandle (a new client could attach and be dropped), and it discards unread replies. */
  CloseHandle(c->pipe);
  while ((m = c->out_head) != NULL) {
    c->out_head = m->next;
    sd_free(m);
  }
  sd_secure_free(c->rbuf, c->rcap);
  sd_free(c->sid);
  sd_free(c);
  s->ninstances--;
  if (was_hello && s->cfg.on_disconnect && !s->stopping)
    s->cfg.on_disconnect(s->cfg.ctx, id);
  listen_next(s);
}

static void client_close(sd_ipc_client *c)
{
  if (!c->closing) {
    c->closing = 1;
    CancelIo(c->pipe);
  }
  if (c->pending == 0)
    client_free(c);
}

/* ---- writing ---- */

static void CALLBACK write_done(DWORD err, DWORD n, LPOVERLAPPED ov)
{
  sd_ipc_client *c = CONTAINING_RECORD(ov, sd_ipc_client, write_ov);
  ipc_msg *m = c->out_head;
  SD_UNUSED(n);
  c->pending--;
  c->writing = 0;
  if (m) {
    c->out_head = m->next;
    if (c->out_head == NULL) c->out_tail = NULL;
    c->out_bytes -= m->len;
    sd_free(m);
  }
  if (c->closing || err != 0) {
    client_close(c);
    return;
  }
  if (c->out_head == NULL && c->close_after_write) {
    client_close(c);
    return;
  }
  client_pump_write(c);
}

static void client_pump_write(sd_ipc_client *c)
{
  ipc_msg *m = c->out_head;
  if (c->writing || c->closing || m == NULL)
    return;
  memset(&c->write_ov, 0, sizeof(c->write_ov));
  if (!WriteFileEx(c->pipe, m->data, (DWORD)m->len, &c->write_ov, write_done)) {
    client_close(c);
    return;
  }
  c->writing = 1;
  c->pending++;
}

static void client_queue(sd_ipc_client *c, const char *data, size_t len)
{
  ipc_msg *m;
  if (c->closing)
    return;
  if (c->out_bytes + len > IPC_MAX_OUT_BYTES) {
    SD_LOGW("ipc", "client %llu output queue overflow; closing", (unsigned long long)c->id);
    client_close(c);
    return;
  }
  m = (ipc_msg *)sd_alloc(sizeof(ipc_msg) + len);
  if (m == NULL) {
    client_close(c);
    return;
  }
  memset(m, 0, sizeof(*m));
  memcpy(m->data, data, len);
  m->len = len;
  if (c->out_tail) c->out_tail->next = m; else c->out_head = m;
  c->out_tail = m;
  c->out_bytes += len;
  client_pump_write(c);
}

static void reply_error(sd_ipc_client *c, int64_t id, const sd_ipc_error *err)
{
  sd_wr w;
  sd_json_writer jw;
  sd_wr_init(&w, 64 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "res");
  sd_jw_key(&jw, "id"); sd_jw_int(&jw, id);
  sd_jw_key(&jw, "error");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, err->code[0] ? err->code : sd_err_name(err->err));
  sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, err->detail);
  sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, err->exit_code);
  sd_jw_key(&jw, "err"); sd_jw_cstr(&jw, sd_err_name(err->err));   /* additive: the sd_err spelling */
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    client_queue(c, (const char *)w.p, w.len);
  else
    client_close(c);
  sd_wr_free(&w);
}

static void reply_error_code(sd_ipc_client *c, int64_t id, sd_err e, const char *code, const char *detail)
{
  sd_ipc_error err;
  memset(&err, 0, sizeof(err));
  sd_ipc_error_set(&err, e, code, detail);
  reply_error(c, id, &err);
}

/* ---- hello ---- */

static int token_checks(sd_ipc_client *c, HANDLE tok, const char **code)
{
  sd_ipc_server *s = c->srv;
  DWORD rid = 0, len = 0, appc = 0, elevated = 0;
  *code = "access_denied";
  if (ipc_token_user_sid(tok, &c->sid) != SD_OK)
    return 0;
  if (s->ep == SD_IPC_AGENT && !EqualSid(c->sid, s->own_sid))
    return 0;
  if (ipc_token_integrity(tok, &rid) && rid < 0x2000)
    return 0;                                         /* below medium (T-45) */
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)29 /* TokenIsAppContainer */, &appc, sizeof(appc), &len) &&
      appc)
    return 0;
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20 /* TokenElevation */, &elevated, sizeof(elevated), &len))
    c->elevated = elevated ? 1 : 0;
  {
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &admins)) {
      if (CheckTokenMembership(tok, admins, &member) && member)
        c->admin = (c->elevated || !sd_os_at_least(6, 0, 0)) ? 1 : 0;
      FreeSid(admins);
    }
  }
  return 1;
}

static int check_client_token(sd_ipc_client *c, const char **code)
{
  HANDLE tok = NULL;
  int ok;
  *code = "access_denied";
  if (!ImpersonateNamedPipeClient(c->pipe))
    return 0;
  if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tok))
    tok = NULL;
  if (!RevertToSelf()) {
    /* Continuing under the client's identity is never acceptable. */
    ExitProcess(1);
  }
  if (tok == NULL)
    return 0;
  ok = token_checks(c, tok, code);
  CloseHandle(tok);
  return ok;
}

typedef BOOL (WINAPI *pfn_GetNamedPipeClientProcessId)(HANDLE, PULONG);

static void handle_hello(sd_ipc_client *c, const sd_json *msg)
{
  sd_ipc_server *s = c->srv;
  int64_t proto = 0, min_proto = 0, chosen;
  const sd_json *caps;
  const char *lang, *code;
  size_t i;
  if (!sd_json_get_int64(msg, "proto", &proto))
    proto = 1;
  if (!sd_json_get_int64(msg, "min_proto", &min_proto))
    min_proto = proto;
  chosen = proto < SD_IPC_PROTO ? proto : SD_IPC_PROTO;
  if (chosen < min_proto || chosen < SD_IPC_MIN_PROTO) {
    c->close_after_write = 1;
    reply_error_code(c, 0, SD_E_PROTOCOL, "proto_unsupported", "no common protocol version");
    return;
  }
  if (!check_client_token(c, &code)) {
    SD_LOGW("ipc", "client %llu refused at hello", (unsigned long long)c->id);
    c->close_after_write = 1;
    reply_error_code(c, 0, SD_E_ACCESS_DENIED, code, "client token refused");
    return;
  }
  if (s->cfg.max_per_sid) {
    uint32_t same = 0;
    sd_ipc_client *o;
    sd_mutex_lock(&s->lock);
    for (o = s->clients; o; o = o->next)
      if (o != c && o->hello_done && o->sid && EqualSid(o->sid, c->sid))
        same++;
    sd_mutex_unlock(&s->lock);
    if (same >= s->cfg.max_per_sid) {
      c->close_after_write = 1;
      reply_error_code(c, 0, SD_E_BUSY, "too_many_connections", "per-user instance quota reached");
      return;
    }
  }
  {
    pfn_GetNamedPipeClientProcessId fn =
        (pfn_GetNamedPipeClientProcessId)sd_platform_resolve_by_name(L"kernel32.dll", "GetNamedPipeClientProcessId");
    ULONG pid = 0;
    if (fn && fn(c->pipe, &pid))
      c->pid = pid;
  }
  caps = sd_json_get(msg, "caps");
  for (i = 0; i < sd_json_count(caps); i++) {
    const char *cap = sd_json_str(sd_json_at(caps, i), NULL);
    if (cap && strcmp(cap, "prompts.console") == 0) c->caps |= SD_IPC_CAP_PROMPTS_CONSOLE;
    if (cap && strcmp(cap, "prompts.ui") == 0) c->caps |= SD_IPC_CAP_PROMPTS_UI;
  }
  lang = sd_json_get_str(msg, "lang");
  if (lang && strlen(lang) < sizeof(c->lang)) {
    memcpy(c->lang, lang, strlen(lang) + 1);
  }
  {
    const char *kind = sd_json_get_str(msg, "client");
    if (kind && strlen(kind) < sizeof(c->kind))
      memcpy(c->kind, kind, strlen(kind) + 1);
  }
  {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, 4096);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "res");
    sd_jw_key(&jw, "id"); sd_jw_int(&jw, 0);
    sd_jw_key(&jw, "result");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "proto"); sd_jw_int(&jw, chosen);
    sd_jw_key(&jw, "server_pid"); sd_jw_int(&jw, (int64_t)GetCurrentProcessId());
    sd_jw_key(&jw, "server_version"); sd_jw_cstr(&jw, SD_VERSION_STRING);
    if (s->cfg.features) {
      const char *const *f;
      sd_jw_key(&jw, "features");
      sd_jw_arr_begin(&jw);
      for (f = s->cfg.features; *f; f++)
        sd_jw_cstr(&jw, *f);
      sd_jw_arr_end(&jw);
    }
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK) {
      sd_mutex_lock(&s->lock);
      c->hello_done = 1;
      s->nhello++;
      sd_mutex_unlock(&s->lock);
      client_queue(c, (const char *)w.p, w.len);
    } else {
      client_close(c);
    }
    sd_wr_free(&w);
  }
}

/* ---- requests ---- */

static void handle_subscribe(sd_ipc_client *c, int64_t id, const sd_json *params)
{
  const sd_json *topics = sd_json_get(params, "topics");
  size_t i;
  sd_wr w;
  sd_json_writer jw;
  if (sd_json_type_of(topics) != SD_JSON_ARRAY) {
    reply_error_code(c, id, SD_E_INVALID_PARAM, "usage", "subscribe needs topics[]");
    return;
  }
  for (i = 0; i < sd_json_count(topics); i++) {
    size_t n;
    const char *t = sd_json_str(sd_json_at(topics, i), &n);
    uint32_t k, dup = 0;
    int added = 0;
    /* M3: syntactic validation; an invalid name is dropped from the accepted set, not an error */
    if (t == NULL || n == 0 || n >= IPC_TOPIC_LEN || !sd_ipc_topic_valid(t))
      continue;
    /* the topic list is read by the broadcast counts of other threads: change it under s->lock */
    sd_mutex_lock(&c->srv->lock);
    for (k = 0; k < c->ntopics; k++)
      if (strcmp(c->topics[k], t) == 0) dup = 1;
    if (!dup && c->ntopics < IPC_MAX_TOPICS) {
      memcpy(c->topics[c->ntopics], t, n + 1);
      c->ntopics++;
      added = 1;
    }
    sd_mutex_unlock(&c->srv->lock);
    /* the hook runs without s->lock: it may take the agent's lock, which other threads hold while they
       call into the server */
    if (added && c->srv->cfg.on_subscribe)
      c->srv->cfg.on_subscribe(c->srv->cfg.ctx, c, c->topics[c->ntopics - 1]);
  }
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "res");
  sd_jw_key(&jw, "id"); sd_jw_int(&jw, id);
  sd_jw_key(&jw, "result");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "topics");
  sd_jw_arr_begin(&jw);
  for (i = 0; i < c->ntopics; i++)
    sd_jw_cstr(&jw, c->topics[i]);
  sd_jw_arr_end(&jw);
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    client_queue(c, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

static void handle_request(sd_ipc_client *c, const sd_json *msg)
{
  sd_ipc_server *s = c->srv;
  int64_t id = 0;
  const char *method = sd_json_get_str(msg, "method");
  const sd_json *params = sd_json_get(msg, "params");
  if (!sd_json_get_int64(msg, "id", &id) || method == NULL ||
      (params != NULL && sd_json_type_of(params) != SD_JSON_OBJECT)) {
    reply_error_code(c, id, SD_E_PROTOCOL, "usage", "malformed request");
    return;
  }
  if (s->cfg.max_requests_per_sec && !c->admin) {
    uint64_t now = sd_tick_ms();
    if (now - c->rate_window >= 1000) {
      c->rate_window = now;
      c->rate_count = 0;
    }
    if (++c->rate_count > s->cfg.max_requests_per_sec) {
      reply_error_code(c, id, SD_E_BUSY, "rate_limited", "too many requests");
      return;
    }
  }
  if (strcmp(method, "subscribe") == 0) {
    handle_subscribe(c, id, params);
    return;
  }
  if (strcmp(method, "hello") == 0) {
    reply_error_code(c, id, SD_E_PROTOCOL, "usage", "hello already done");
    return;
  }
  {
    sd_wr w;
    sd_json_writer jw;
    sd_ipc_error err;
    sd_err r;
    memset(&err, 0, sizeof(err));
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "res");
    sd_jw_key(&jw, "id"); sd_jw_int(&jw, id);
    sd_jw_key(&jw, "result");
    sd_jw_obj_begin(&jw);
    c->cur_req_active = 1;
    c->cur_req_id = id;
    c->deferred = 0;
    r = s->cfg.handler ? s->cfg.handler(s->cfg.ctx, c, method, params, &jw, &err) : SD_E_UNSUPPORTED;
    c->cur_req_active = 0;
    if (c->deferred) {                /* the reply comes later through sd_ipc_reply_deferred */
      c->deferred = 0;
      sd_wr_free(&w);
      return;
    }
    if (r == SD_OK && err.err != SD_OK)
      r = err.err;
    if (r == SD_OK) {
      sd_jw_obj_end(&jw);
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK) {
        client_queue(c, (const char *)w.p, w.len);
        sd_wr_free(&w);
        return;
      }
      r = SD_E_INTERNAL;
      sd_ipc_error_set(&err, r, NULL, "handler produced invalid JSON");
    }
    sd_wr_free(&w);
    if (err.code[0] == 0)
      sd_ipc_error_set(&err, r, r == SD_E_UNSUPPORTED ? "usage" : NULL,
                       r == SD_E_UNSUPPORTED ? "unknown method" : err.detail);
    reply_error(c, id, &err);
  }
}

static void process_message(sd_ipc_client *c, const uint8_t *data, size_t len)
{
  sd_json *msg = NULL;
  const char *type;
  if (sd_json_parse((const char *)data, len, 32, &msg) != SD_OK || sd_json_type_of(msg) != SD_JSON_OBJECT) {
    SD_LOGW("ipc", "client %llu sent malformed JSON; closing", (unsigned long long)c->id);
    sd_json_free(msg);
    client_close(c);
    return;
  }
  c->last_activity = sd_tick_ms();
  type = sd_json_get_str(msg, "type");
  if (!c->hello_done) {
    if (type && strcmp(type, "hello") == 0)
      handle_hello(c, msg);
    else
      client_close(c);
  } else if (type && strcmp(type, "req") == 0) {
    handle_request(c, msg);
  } else {
    client_close(c);
  }
  sd_json_free(msg);
}

/* ---- reading ---- */

static void CALLBACK read_done(DWORD err, DWORD n, LPOVERLAPPED ov)
{
  sd_ipc_client *c = CONTAINING_RECORD(ov, sd_ipc_client, read_ov);
  sd_ipc_server *s = c->srv;
  DWORD left = 0;
  c->pending--;
  /* A message larger than the buffer completes with STATUS_BUFFER_OVERFLOW (a warning): the
     routine may see it as ERROR_MORE_DATA or as success, so the status in the OVERLAPPED decides. */
  if (err == 0 && (DWORD)ov->Internal == 0x80000005UL)
    err = ERROR_MORE_DATA;
  if (c->closing || (err != 0 && err != ERROR_MORE_DATA)) {
    SD_LOGD("ipc", "client %llu read ended (%u)", (unsigned long long)c->id, (unsigned)err);
    client_close(c);
    return;
  }
  c->rlen += n;
  /* Message larger than the buffer: the completion reports ERROR_MORE_DATA (STATUS_BUFFER_OVERFLOW);
     the rest of the message is sized with PeekNamedPipe. */
  if (err == ERROR_MORE_DATA) {
    size_t want;
    if (!PeekNamedPipe(c->pipe, NULL, 0, NULL, NULL, &left) || left == 0)
      left = IPC_READ_CHUNK;
    want = c->rlen + left;
    if (want > s->cfg.max_message) {
      SD_LOGW("ipc", "client %llu message over the size cap; closing", (unsigned long long)c->id);
      client_close(c);
      return;
    }
    if (want > c->rcap) {
      uint8_t *nb = (uint8_t *)sd_realloc(c->rbuf, want);
      if (nb == NULL) {
        client_close(c);
        return;
      }
      c->rbuf = nb;
      c->rcap = want;
    }
    client_start_read(c);
    return;
  }
  if (c->rlen > s->cfg.max_message) {
    client_close(c);
    return;
  }
  {
    size_t len = c->rlen;
    c->rlen = 0;
    c->pending++;                 /* guard: process_message may close (not free) the client */
    process_message(c, c->rbuf, len);
    sd_secure_zero(c->rbuf, len); /* requests may carry prompt answers */
    c->pending--;
  }
  if (c->closing) {
    client_close(c);
    return;
  }
  client_start_read(c);
}

static void client_start_read(sd_ipc_client *c)
{
  if (c->closing)
    return;
  if (c->rlen == 0 && c->rcap > IPC_READ_CHUNK) {
    uint8_t *nb = (uint8_t *)sd_realloc(c->rbuf, IPC_READ_CHUNK);   /* shrink after a large message */
    if (nb) { c->rbuf = nb; c->rcap = IPC_READ_CHUNK; }
  }
  memset(&c->read_ov, 0, sizeof(c->read_ov));
  if (!ReadFileEx(c->pipe, c->rbuf + c->rlen, (DWORD)(c->rcap - c->rlen), &c->read_ov, read_done)) {
    SD_LOGD("ipc", "client %llu ReadFileEx failed (%u)", (unsigned long long)c->id, (unsigned)GetLastError());
    client_close(c);
    return;
  }
  c->pending++;
}

/* ---- queue from other threads ---- */

static int client_subscribed(const sd_ipc_client *c, const char *topic)
{
  uint32_t i;
  for (i = 0; i < c->ntopics; i++)
    if (strcmp(c->topics[i], topic) == 0)
      return 1;
  return 0;
}

/* Recipient rule of a broadcast, shared by the count (enqueue time) and the drain (pipe thread). */
static int client_is_recipient(const sd_ipc_client *c, const char *topic, uint32_t caps, uint64_t exclude)
{
  if (!c->hello_done || c->closing || c->id == exclude)
    return 0;
  if ((c->caps & caps) != caps)
    return 0;
  return client_subscribed(c, topic);
}

#define IPC_TOPIC_ALL "*"

static void drain_queue(sd_ipc_server *s)
{
  ipc_msg *m;
  for (;;) {
    sd_ipc_client *c, *next;
    sd_mutex_lock(&s->lock);
    m = s->q_head;
    if (m) {
      s->q_head = m->next;
      if (s->q_head == NULL) s->q_tail = NULL;
    }
    sd_mutex_unlock(&s->lock);
    if (m == NULL)
      return;
    for (c = s->clients; c; c = next) {
      next = c->next;   /* client_queue may free c */
      if (!c->hello_done || c->closing)
        continue;
      if (m->client_id ? c->id == m->client_id
                       : (strcmp(m->topic, IPC_TOPIC_ALL) == 0 || client_is_recipient(c, m->topic, m->caps, m->exclude)))
        client_queue(c, m->data, m->len);
    }
    sd_free(m);
  }
}

static sd_err enqueue(sd_ipc_server *s, uint64_t client_id, const char *topic, const char *json, size_t len,
                      uint32_t caps, uint64_t exclude)
{
  ipc_msg *m;
  if (s == NULL || json == NULL || len == 0 || len > s->cfg.max_message)
    return SD_E_INVALID_PARAM;
  m = (ipc_msg *)sd_alloc(sizeof(ipc_msg) + len);
  if (m == NULL)
    return SD_E_NO_MEMORY;
  memset(m, 0, sizeof(*m));
  m->client_id = client_id;
  m->caps = caps;
  m->exclude = exclude;
  if (topic) {
    size_t n = strlen(topic);
    if (n >= IPC_TOPIC_LEN) { sd_free(m); return SD_E_INVALID_PARAM; }
    memcpy(m->topic, topic, n + 1);
  }
  memcpy(m->data, json, len);
  m->len = len;
  sd_mutex_lock(&s->lock);
  if (client_id) {
    sd_ipc_client *c;
    int found = 0;
    for (c = s->clients; c; c = c->next)
      if (c->id == client_id && c->hello_done && !c->closing) found = 1;
    if (!found) {
      sd_mutex_unlock(&s->lock);
      sd_free(m);
      return SD_E_NOT_FOUND;
    }
  }
  if (s->q_tail) s->q_tail->next = m; else s->q_head = m;
  s->q_tail = m;
  sd_mutex_unlock(&s->lock);
  SetEvent(s->wake_ev);
  return SD_OK;
}

int sd_ipc_topic_valid(const char *topic)
{
  size_t i, n;
  if (topic == NULL)
    return 0;
  n = strlen(topic);
  if (n == 0 || n > SD_IPC_TOPIC_MAX)
    return 0;
  for (i = 0; i < n; i++) {
    char ch = topic[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'))
      return 0;
  }
  return 1;
}

sd_err sd_ipc_broadcast_count(sd_ipc_server *s, const char *topic, const char *event_json, size_t len,
                              uint32_t required_caps, uint64_t exclude_client, uint32_t *count)
{
  sd_ipc_client *c;
  uint32_t n = 0;
  sd_err e;
  if (count)
    *count = 0;
  if (s == NULL || !sd_ipc_topic_valid(topic))
    return SD_E_INVALID_PARAM;
  sd_mutex_lock(&s->lock);
  for (c = s->clients; c; c = c->next)
    if (client_is_recipient(c, topic, required_caps, exclude_client))
      n++;
  sd_mutex_unlock(&s->lock);
  if (n == 0)
    return SD_OK;               /* nobody to deliver to: nothing is queued */
  e = enqueue(s, 0, topic, event_json, len, required_caps, exclude_client);
  if (e == SD_OK && count)
    *count = n;
  return e;
}

void sd_ipc_broadcast(sd_ipc_server *s, const char *topic, const char *event_json, size_t len)
{
  (void)sd_ipc_broadcast_count(s, topic, event_json, len, 0, 0, NULL);
}

/* M3: an event for every client that completed hello (events without a topic, config.changed and
   agent.stopping). IPC_TOPIC_ALL is not a valid topic name, so no subscription can match it. */
sd_err sd_ipc_broadcast_all(sd_ipc_server *s, const char *event_json, size_t len)
{
  return enqueue(s, 0, IPC_TOPIC_ALL, event_json, len, 0, 0);
}

uint32_t sd_ipc_topic_subscribers(sd_ipc_server *s, const char *topic, uint32_t required_caps)
{
  sd_ipc_client *c;
  uint32_t n = 0;
  if (s == NULL || !sd_ipc_topic_valid(topic))
    return 0;
  sd_mutex_lock(&s->lock);
  for (c = s->clients; c; c = c->next)
    if (client_is_recipient(c, topic, required_caps, 0))
      n++;
  sd_mutex_unlock(&s->lock);
  return n;
}

sd_err sd_ipc_send_to(sd_ipc_server *s, uint64_t client_id, const char *event_json, size_t len)
{
  if (client_id == 0)
    return SD_E_INVALID_PARAM;
  return enqueue(s, client_id, NULL, event_json, len, 0, 0);
}

/* M3: deferred replies (profile.test). Called inside the handler, on the pipe thread. */
int sd_ipc_defer(sd_ipc_client *client, int64_t *req_id)
{
  if (client == NULL || !client->cur_req_active)
    return 0;
  client->deferred = 1;
  if (req_id)
    *req_id = client->cur_req_id;
  return 1;
}

/* Any thread. Builds the complete "res" message of the request (result object, or the error of e/code/detail
   with the table's exit code) and queues it for the client. SD_E_NOT_FOUND once the client is gone. */
sd_err sd_ipc_reply_deferred(sd_ipc_server *s, uint64_t client_id, int64_t req_id, sd_err e, const char *code,
                             const char *detail, const char *result_json, size_t result_len)
{
  sd_wr w;
  sd_err r;
  char idbuf[24];
  if (s == NULL || client_id == 0)
    return SD_E_INVALID_PARAM;
  {
    /* decimal id without the CRT: at most 20 digits and a sign */
    uint64_t v = req_id < 0 ? (uint64_t)0 - (uint64_t)req_id : (uint64_t)req_id;
    char tmp[24];
    size_t n = 0, o = 0;
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    if (req_id < 0) idbuf[o++] = '-';
    while (n) idbuf[o++] = tmp[--n];
    idbuf[o] = 0;
  }
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  if (e == SD_OK && result_json != NULL) {
    sd_wr_bytes(&w, "{\"type\":\"res\",\"id\":", strlen("{\"type\":\"res\",\"id\":"));
    sd_wr_bytes(&w, idbuf, strlen(idbuf));
    sd_wr_bytes(&w, ",\"result\":", strlen(",\"result\":"));
    sd_wr_bytes(&w, result_json, result_len);
    sd_wr_bytes(&w, "}", 1);
  } else {
    sd_ipc_error err;
    sd_json_writer jw;
    memset(&err, 0, sizeof(err));
    sd_ipc_error_set(&err, e == SD_OK ? SD_E_INTERNAL : e, code, detail);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, "res");
    sd_jw_key(&jw, "id"); sd_jw_int(&jw, req_id);
    sd_jw_key(&jw, "error");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, err.code[0] ? err.code : sd_err_name(err.err));
    sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, err.detail);
    sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, err.exit_code);
    sd_jw_key(&jw, "err"); sd_jw_cstr(&jw, sd_err_name(err.err));
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) != SD_OK) {
      sd_wr_free(&w);
      return SD_E_INTERNAL;
    }
  }
  r = sd_ipc_send_to(s, client_id, (const char *)w.p, w.len);
  sd_wr_free(&w);
  return r;
}

/* ---- thread ---- */

static void idle_sweep(sd_ipc_server *s)
{
  uint64_t now = sd_tick_ms();
  sd_ipc_client *c, *next;
  for (c = s->clients; c; c = next) {
    next = c->next;
    if (!c->closing && c->ntopics == 0 && now - c->last_activity > s->cfg.idle_timeout_ms)
      client_close(c);
  }
}

static unsigned __stdcall server_thread(void *arg)
{
  sd_ipc_server *s = (sd_ipc_server *)arg;
  HANDLE hs[3];
  uint64_t deadline;
  hs[0] = s->stop_ev;
  hs[1] = s->connect_ev;
  hs[2] = s->wake_ev;
  for (;;) {
    DWORD w = WaitForMultipleObjectsEx(3, hs, FALSE, 1000, TRUE);
    if (w == WAIT_OBJECT_0)
      break;
    if (w == WAIT_OBJECT_0 + 1)
      on_connected(s);
    else if (w == WAIT_OBJECT_0 + 2)
      drain_queue(s);
    else if (w == WAIT_TIMEOUT)
      idle_sweep(s);
    if (s->pending_pipe == NULL)
      listen_next(s);
  }
  s->stopping = 1;
  if (s->pending_pipe) {
    CancelIo(s->pending_pipe);
    CloseHandle(s->pending_pipe);
    s->pending_pipe = NULL;
    s->ninstances--;
  }
  {
    sd_ipc_client *c, *next;
    for (c = s->clients; c; c = next) {
      next = c->next;
      client_close(c);
    }
  }
  deadline = sd_tick_ms() + 5000;
  while (s->clients && sd_tick_ms() < deadline)
    SleepEx(20, TRUE);
  return 0;
}

static sd_err build_sd(sd_ipc_server *s)
{
  wchar_t sddl[512];
  wchar_t *sid = NULL;
  sd_err e;
  sddl[0] = 0;
  if (s->ep == SD_IPC_SERVICE) {
    ipc_wcat(sddl, SD_COUNTOF(sddl), L"O:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
  } else {
    e = ipc_sid_to_string(s->own_sid, &sid);
    if (e != SD_OK)
      return e;
    if (!(ipc_wcat(sddl, SD_COUNTOF(sddl), L"O:") && ipc_wcat(sddl, SD_COUNTOF(sddl), sid) &&
          ipc_wcat(sddl, SD_COUNTOF(sddl), L"D:P(D;;GA;;;NU)(A;;GRGW;;;") &&
          ipc_wcat(sddl, SD_COUNTOF(sddl), sid) && ipc_wcat(sddl, SD_COUNTOF(sddl), L")"))) {
      sd_free(sid);
      return SD_E_INVALID_PARAM;
    }
    sd_free(sid);
  }
  return ipc_sd_from_sddl(sddl, &s->sd);
}

static void server_free(sd_ipc_server *s)
{
  ipc_msg *m;
  if (s->stop_ev) CloseHandle(s->stop_ev);
  if (s->wake_ev) CloseHandle(s->wake_ev);
  if (s->connect_ev) CloseHandle(s->connect_ev);
  while ((m = s->q_head) != NULL) {
    s->q_head = m->next;
    sd_free(m);
  }
  if (s->sd) LocalFree(s->sd);
  sd_free(s->own_sid);
  sd_mutex_destroy(&s->lock);
  sd_free(s);
}

sd_err sd_ipc_server_start_ex(sd_ipc_endpoint ep, const sd_ipc_server_cfg *cfg, sd_ipc_server **out)
{
  sd_ipc_server *s;
  wchar_t sidstr[192];
  DWORD session = 0;
  HANDLE first;
  sd_err e;
  if (out == NULL || cfg == NULL || cfg->struct_size < sizeof(sd_ipc_server_cfg))
    return SD_E_INVALID_PARAM;
  *out = NULL;
  s = (sd_ipc_server *)sd_calloc(1, sizeof(*s));
  if (s == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&s->lock);
  s->ep = ep;
  s->cfg = *cfg;
  if (s->cfg.max_instances == 0 || s->cfg.max_instances > PIPE_UNLIMITED_INSTANCES - 1) s->cfg.max_instances = 32;
  if (s->cfg.max_message == 0 || s->cfg.max_message > SD_IPC_MAX_MESSAGE) s->cfg.max_message = SD_IPC_MAX_MESSAGE;
  if (s->cfg.idle_timeout_ms == 0) s->cfg.idle_timeout_ms = 10u * 60u * 1000u;
  e = ipc_process_user_sid(&s->own_sid);
  if (e == SD_OK) e = sd_ipc_current_identity(sidstr, SD_COUNTOF(sidstr), &session);
  if (e == SD_OK) e = sd_ipc_pipe_name(ep, sidstr, session, s->name, SD_COUNTOF(s->name));
  if (e == SD_OK) e = build_sd(s);
  if (e != SD_OK) {
    server_free(s);
    return e;
  }
  s->stop_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  s->wake_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  s->connect_ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!s->stop_ev || !s->wake_ev || !s->connect_ev) {
    server_free(s);
    return SD_E_NO_MEMORY;
  }
  /* First instance: FILE_FLAG_FIRST_PIPE_INSTANCE is the authoritative uniqueness/squat check. */
  first = create_instance(s, 1);
  if (first == INVALID_HANDLE_VALUE) {
    DWORD gle = GetLastError();
    SD_LOGE("ipc", "cannot create the first pipe instance: %u (squatted or already running)", (unsigned)gle);
    server_free(s);
    return gle == ERROR_ACCESS_DENIED || gle == ERROR_PIPE_BUSY ? SD_E_ACCESS_DENIED : SD_E_INTERNAL;
  }
  s->ninstances = 1;
  if (start_listen(s, first) != 0) {
    CloseHandle(first);
    server_free(s);
    return SD_E_INTERNAL;
  }
  e = sd_thread_create(&s->thread, server_thread, s, 0, L"sd-ipc-server");
  if (e != SD_OK) {
    CancelIo(first);
    CloseHandle(first);
    server_free(s);
    return e;
  }
  *out = s;
  return SD_OK;
}

sd_err sd_ipc_server_start(sd_ipc_endpoint ep, sd_ipc_handler h, void *ctx, sd_ipc_server **out)
{
  sd_ipc_server_cfg cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = h;
  cfg.ctx = ctx;
  if (ep == SD_IPC_SERVICE) {
    cfg.max_per_sid = 4;
    cfg.max_requests_per_sec = 10;
    cfg.idle_timeout_ms = 60000;
  }
  return sd_ipc_server_start_ex(ep, &cfg, out);
}

void sd_ipc_server_stop(sd_ipc_server *s)
{
  if (s == NULL)
    return;
  SetEvent(s->stop_ev);
  sd_thread_join(&s->thread, SD_WAIT_INFINITE, NULL);
  server_free(s);
}

int sd_ipc_client_is_elevated(sd_ipc_client *client) { return client ? client->elevated : 0; }
int sd_ipc_client_is_admin(sd_ipc_client *client) { return client ? client->admin : 0; }
DWORD sd_ipc_client_pid(sd_ipc_client *client) { return client ? client->pid : 0; }
uint64_t sd_ipc_client_id(sd_ipc_client *client) { return client ? client->id : 0; }
const char *sd_ipc_client_kind(sd_ipc_client *client) { return client ? client->kind : ""; }
uint32_t sd_ipc_client_caps(sd_ipc_client *client) { return client ? client->caps : 0; }
const char *sd_ipc_client_lang(sd_ipc_client *client) { return client ? client->lang : "en"; }

uint32_t sd_ipc_server_client_count(sd_ipc_server *s)
{
  uint32_t n;
  if (s == NULL)
    return 0;
  sd_mutex_lock(&s->lock);
  n = s->nhello;
  sd_mutex_unlock(&s->lock);
  return n;
}
