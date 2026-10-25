/* shelldrive-host agent mode (03 §1.2, §1.11, §2.4, §2.5).
 *
 * Threads: the main thread is the control thread (sd_mount lifecycle, mount callbacks, the work
 * queue); the IPC server thread runs the request handler, which never blocks on network work: it
 * validates, records the mount and posts the start to the control thread. Host state (the mount
 * list) is guarded by g.lock; sd_mount objects are destroyed only under that lock so that
 * prompt.answer on the IPC thread never races a destroy.
 *
 * Named objects (TM-R26): the session mutex gives single instance per user + session; the pipe's
 * FILE_FLAG_FIRST_PIPE_INSTANCE stays authoritative. Squatted mutex/events are logged and skipped.
 *
 * M1: reconnect state (mount.state events and `list` carry a "connection" object), write_failed and
 * vfs notices as `warning` events (03 §2.4, C45), per-source cache folder (disk tier + identity
 * cache, 03 §3.2), WebDAV mapping cleanup at start and stop (TM-R17 d) and in the crash filter
 * (TM-R17 b).
 *
 * M0 gaps (documented in docs/dev/m0-notes.md by the lead): no hidden window (WM_ENDSESSION, WTS
 * and power notifications), no prompt queue while locked, no UI launch for prompts, no autostart. */
#include <windows.h>
#include <string.h>

#include "host.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

typedef struct work { struct work *next; void (*fn)(void *); void *arg; } work;

typedef struct host_mount {
  struct host_mount *next;
  uint32_t num;
  char id[16];                  /* "m-<num>" */
  sd_mount *m;
  char profile_name[128];
  char profile_id[33];
  char host[256];
  char user[128];
  uint16_t port;
  wchar_t letter;
  int read_only;
  int backend_req;              /* sd_mount_backend_kind requested (02 §10.1) */
  sd_mount_state state;
  uint64_t initiator;           /* IPC client that asked for the mount */
  int prompt_none;              /* prompt_mode = none */
  char fail_code[64];           /* overrides the code of the final error */
  sd_mount_params params;       /* strings below stay valid until sd_mount_create copied them */
  wchar_t whost[256], identity[MAX_PATH], label[128], kh[MAX_PATH];
  wchar_t cache_dir[MAX_PATH];  /* per-source cache folder ("" when it could not be created) */
  char remote[1024];
  int started, stop_requested;
} host_mount;

static struct {
  sd_mutex lock;
  host_mount *mounts;
  uint32_t next_num;
  sd_ipc_server *srv;
  /* control queue */
  sd_mutex qlock;
  work *qhead, *qtail;
  HANDLE qev;
  volatile LONG stop;
  uint64_t last_busy;
  sd_settings settings;         /* settings.ini, read at start */
} g;

/* ---- control queue ---- */

static void post(void *ctx, void (*fn)(void *), void *arg)
{
  work *w = (work *)sd_calloc(1, sizeof(*w));
  SD_UNUSED(ctx);
  if (w == NULL) {
    SD_LOGE("agent", "control queue allocation failed");
    return;
  }
  w->fn = fn;
  w->arg = arg;
  sd_mutex_lock(&g.qlock);
  if (g.qtail) g.qtail->next = w; else g.qhead = w;
  g.qtail = w;
  sd_mutex_unlock(&g.qlock);
  SetEvent(g.qev);
}

static void drain(void)
{
  for (;;) {
    work *w;
    sd_mutex_lock(&g.qlock);
    w = g.qhead;
    if (w) { g.qhead = w->next; if (!g.qhead) g.qtail = NULL; }
    sd_mutex_unlock(&g.qlock);
    if (w == NULL)
      return;
    w->fn(w->arg);
    sd_free(w);
  }
}

/* ---- small helpers ---- */

static void scopy(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (cap == 0) return;
  if (src) for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
  dst[i] = 0;
}

static int wide_from_utf8(const char *s, wchar_t *out, size_t cch)
{
  size_t got = 0;
  out[0] = 0;
  if (s == NULL) return 1;
  if (sd_utf8_to_utf16(s, strlen(s), out, cch - 1, &got, SD_UTF_STRICT) != SD_OK) return 0;
  out[got] = 0;
  return 1;
}

static void jw_wstr(sd_json_writer *jw, const wchar_t *w)
{
  char buf[1024];
  size_t got = 0;
  if (w == NULL || sd_utf16_to_utf8(w, wcslen(w), buf, sizeof(buf) - 1, &got, SD_UTF_REPLACE) != SD_OK)
    got = 0;
  buf[got] = 0;
  sd_jw_cstr(jw, buf);
}

static void jw_letter(sd_json_writer *jw, wchar_t l)
{
  char t[3];
  t[0] = (char)l; t[1] = ':'; t[2] = 0;
  sd_jw_cstr(jw, t);
}

static host_mount *find_by_mount(sd_mount *m)
{
  host_mount *h;
  for (h = g.mounts; h; h = h->next)
    if (h->m == m) return h;
  return NULL;
}

static void broadcast_data(const char *topic, const char *event, sd_wr *data)
{
  sd_wr w;
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  if (sd_ipc_build_event(event, (const char *)data->p, data->len, &w) == SD_OK)
    sd_ipc_broadcast(g.srv, topic, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* ---- events ---- */

static const char *final_code(host_mount *h, const sd_mount_failure *f)
{
  if (h->fail_code[0]) return h->fail_code;
  if (f->code) return f->code;
  return sd_err_name(f->err);
}

/* M1 connection sub-state: "connection" object plus the write_failed counters (03 §2.4). */
static void write_conn_json(sd_json_writer *jw, host_mount *h)
{
  sd_mount_conn c;
  if (h->m == NULL)
    return;
  sd_mount_get_conn(h->m, &c);
  sd_jw_key(jw, "connection");
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "session"); sd_jw_cstr(jw, sd_mount_session_state_name(c.session));
  sd_jw_key(jw, "generation"); sd_jw_int(jw, c.generation);
  sd_jw_key(jw, "reconnects"); sd_jw_int(jw, c.reconnects);
  if (c.offline_since_ms) {
    sd_jw_key(jw, "offline_ms"); sd_jw_int(jw, (int64_t)(sd_tick_ms() - c.offline_since_ms));
  }
  if (c.session == SD_SFTP_ST_RECONNECT_WAIT) {
    sd_jw_key(jw, "attempt"); sd_jw_int(jw, c.attempt);
    sd_jw_key(jw, "retry_in_ms"); sd_jw_int(jw, c.retry_in_ms);
  }
  if (c.reason != SD_OK) {
    sd_jw_key(jw, "reason"); sd_jw_cstr(jw, sd_err_name(c.reason));
  }
  sd_jw_obj_end(jw);
  sd_jw_key(jw, "write_failed"); sd_jw_int(jw, c.write_failed);
  if (c.write_failed) {
    sd_jw_key(jw, "last_write_failed"); jw_wstr(jw, c.last_write_failed);
  }
}

static void write_mount_json(sd_json_writer *jw, host_mount *h)
{
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "mount_id"); sd_jw_cstr(jw, h->id);
  sd_jw_key(jw, "profile"); sd_jw_cstr(jw, h->profile_name);
  if (h->profile_id[0]) { sd_jw_key(jw, "profile_id"); sd_jw_cstr(jw, h->profile_id); }
  sd_jw_key(jw, "target"); jw_letter(jw, h->letter);
  sd_jw_key(jw, "backend");
  sd_jw_cstr(jw, sd_mount_backend_kind_name(h->m ? sd_mount_backend_kind_used(h->m) : (sd_mount_backend_kind)h->backend_req));
  sd_jw_key(jw, "state"); sd_jw_cstr(jw, sd_mount_state_name(h->state));
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, h->host);
  sd_jw_key(jw, "port"); sd_jw_int(jw, h->port);
  sd_jw_key(jw, "user"); sd_jw_cstr(jw, h->user);
  sd_jw_key(jw, "read_only"); sd_jw_bool(jw, h->read_only);
  write_conn_json(jw, h);
  sd_jw_obj_end(jw);
}

static void send_state_event(host_mount *h, sd_mount_state st, sd_err why)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 64 * 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
  sd_jw_key(&jw, "state"); sd_jw_cstr(&jw, sd_mount_state_name(st));
  sd_jw_key(&jw, "target"); jw_letter(&jw, h->letter);
  if (st == SD_MOUNT_FAILED || st == SD_MOUNT_OFFLINE || (st == SD_MOUNT_UNMOUNTED && why != SD_OK)) {
    sd_mount_failure f;
    const char *code;
    sd_mount_get_failure(h->m, &f);
    if (f.err == SD_OK) f.err = why;
    code = final_code(h, &f);
    sd_jw_key(&jw, "error");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, code);
    sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, f.detail);
    sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, sd_ipc_exit_code_for_code(code));
    if (f.err == SD_E_HOSTKEY_MISMATCH) {
      sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, h->host);
      sd_jw_key(&jw, "stored_type"); sd_jw_cstr(&jw, f.stored_type);
      sd_jw_key(&jw, "stored_fp"); sd_jw_cstr(&jw, f.stored_fp);
      sd_jw_key(&jw, "offered_type"); sd_jw_cstr(&jw, f.offered_type);
      sd_jw_key(&jw, "offered_fp"); sd_jw_cstr(&jw, f.offered_fp);
      sd_jw_key(&jw, "store_path"); jw_wstr(&jw, f.store_path);
      sd_jw_key(&jw, "store_line"); sd_jw_int(&jw, f.store_line);
    }
    sd_jw_obj_end(&jw);
  }
  write_conn_json(&jw, h);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_data("mount", "mount.state", &d);
  sd_wr_free(&d);
}

/* `warning {code, mount_id, data}` (03 §2.4); write_failed is always delivered (C45). */
static void send_warning(host_mount *h, const char *code, const wchar_t *path, UINT64 bytes, const char *status,
                         const char *detail)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 64 * 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, code);
  sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
  sd_jw_key(&jw, "data");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "target"); jw_letter(&jw, h->letter);
  if (path) { sd_jw_key(&jw, "path"); jw_wstr(&jw, path); }
  if (path) { sd_jw_key(&jw, "bytes"); sd_jw_int(&jw, (int64_t)bytes); }
  if (status) { sd_jw_key(&jw, "status"); sd_jw_cstr(&jw, status); }
  if (detail) { sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, detail); }
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK) {
    broadcast_data("mount", "warning", &d);
    broadcast_data("warning", "warning", &d);
  }
  sd_wr_free(&d);
}

/* ---- sd_mount callbacks (control thread) ---- */

static void destroy_record_locked(host_mount *h)
{
  host_mount **pp;
  for (pp = &g.mounts; *pp; pp = &(*pp)->next)
    if (*pp == h) { *pp = h->next; break; }
  if (h->m) sd_mount_destroy(h->m);
  sd_free(h);
}

/* Destroys a finished mount from a fresh work item, never from inside an sd_mount callback. */
static void work_reap(void *arg)
{
  host_mount *h = (host_mount *)arg, *o;
  sd_mutex_lock(&g.lock);
  for (o = g.mounts; o; o = o->next)
    if (o == h) break;
  if (o && (o->m == NULL || sd_mount_is_final(o->m)))
    destroy_record_locked(h);
  sd_mutex_unlock(&g.lock);
}

static void on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) {
    h->state = st;
    send_state_event(h, st, why);
    if (sd_mount_is_final(m))
      post(NULL, work_reap, h);
  }
  g.last_busy = sd_tick_ms();
  sd_mutex_unlock(&g.lock);
}

static void on_conn(void *ctx, sd_mount *m)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h)
    send_state_event(h, h->state, SD_OK);   /* same state, new "connection" details */
  sd_mutex_unlock(&g.lock);
}

static void on_write_failed(void *ctx, sd_mount *m, const wchar_t *path, UINT64 bytes, const char *status)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) {
    SD_LOGW("agent", "%s: write_failed (%s, %llu bytes)", h->id, status, (unsigned long long)bytes);
    send_warning(h, "write_failed", path ? path : L"", bytes, status, NULL);
  }
  sd_mutex_unlock(&g.lock);
}

static void on_notice(void *ctx, sd_mount *m, const char *code, const char *detail)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h && code && code[0])
    send_warning(h, code, NULL, 0, NULL, detail);
  sd_mutex_unlock(&g.lock);
}

static int lookup_identity(void *ctx, sd_mount *m, const char *fp, sd_vfs_identity *out)
{
  host_mount *h;
  wchar_t dir[MAX_PATH];
  uint32_t uid = 0, gid = 0;
  SD_UNUSED(ctx);
  dir[0] = 0;
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) memcpy(dir, h->cache_dir, sizeof(dir));
  sd_mutex_unlock(&g.lock);
  if (dir[0] == 0 || sd_config_identity_load(dir, fp, &uid, &gid) != SD_OK)
    return 0;
  memset(out, 0, sizeof(*out));
  out->uid_known = out->definitive = TRUE;
  out->uid = uid;
  out->gid = gid;
  SD_LOGI("agent", "using the cached remote identity %u:%u", (unsigned)uid, (unsigned)gid);
  return 1;
}

static void store_identity(void *ctx, sd_mount *m, const char *fp, const sd_vfs_identity *id)
{
  host_mount *h;
  wchar_t dir[MAX_PATH];
  uint32_t uid = 0, gid = 0;
  SD_UNUSED(ctx);
  dir[0] = 0;
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) memcpy(dir, h->cache_dir, sizeof(dir));
  sd_mutex_unlock(&g.lock);
  if (dir[0] == 0)
    return;
  if (sd_config_identity_load(dir, fp, &uid, &gid) == SD_OK && uid == id->uid && gid == id->gid)
    return;
  if (sd_config_identity_store(dir, fp, id->uid, id->gid) != SD_OK)
    SD_LOGW("agent", "cannot store the remote identity");
}

static void prompt_id_str(host_mount *h, uint32_t pid, char out[32])
{
  char tmp[12];
  size_t n = 0, o = 0;
  uint32_t v;
  out[o++] = 'p'; out[o++] = '-';
  for (v = h->num; ; ) { tmp[n++] = (char)('0' + v % 10u); v /= 10u; if (!v) break; }
  while (n) out[o++] = tmp[--n];
  out[o++] = '-';
  for (v = pid; ; ) { tmp[n++] = (char)('0' + v % 10u); v /= 10u; if (!v) break; }
  while (n) out[o++] = tmp[--n];
  out[o] = 0;
}

static int parse_prompt_id(const char *s, uint32_t *mnum, uint32_t *pid)
{
  uint32_t a = 0, b = 0;
  if (s == NULL || s[0] != 'p' || s[1] != '-') return 0;
  s += 2;
  if (*s < '0' || *s > '9') return 0;
  while (*s >= '0' && *s <= '9') { a = a * 10u + (uint32_t)(*s - '0'); s++; if (a > 100000000u) return 0; }
  if (*s++ != '-') return 0;
  if (*s < '0' || *s > '9') return 0;
  while (*s >= '0' && *s <= '9') { b = b * 10u + (uint32_t)(*s - '0'); s++; if (b > 100000000u) return 0; }
  if (*s) return 0;
  *mnum = a;
  *pid = b;
  return 1;
}

static void on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  host_mount *h;
  char pid[32];
  sd_wr d, w;
  sd_json_writer jw;
  uint32_t i;
  int delivered = 0;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h == NULL) {
    sd_mutex_unlock(&g.lock);
    return;
  }
  if (h->prompt_none) {
    scopy(h->fail_code, sizeof(h->fail_code), p->kind == SD_MP_HOSTKEY ? "host_key_unknown" : "prompt_required");
    sd_mutex_unlock(&g.lock);
    sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
    return;
  }
  prompt_id_str(h, p->id, pid);
  sd_wr_init(&d, 64 * 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, pid);
  sd_jw_key(&jw, "kind"); sd_jw_cstr(&jw, sd_mount_prompt_kind_name(p->kind));
  sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
  sd_jw_key(&jw, "profile_name"); sd_jw_cstr(&jw, h->profile_name);
  sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, p->host[0] ? p->host : h->host);
  sd_jw_key(&jw, "port"); sd_jw_int(&jw, p->port ? p->port : h->port);
  sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, p->user[0] ? p->user : h->user);
  sd_jw_key(&jw, "hop"); sd_jw_int(&jw, (int64_t)p->hop_index + 1);
  sd_jw_key(&jw, "hops"); sd_jw_int(&jw, 1);
  if (p->kind == SD_MP_HOSTKEY) {
    sd_jw_key(&jw, "key_type"); sd_jw_cstr(&jw, p->key_type);
    sd_jw_key(&jw, "key_bits"); sd_jw_int(&jw, p->key_bits);
    sd_jw_key(&jw, "fingerprint"); sd_jw_cstr(&jw, p->fp_sha256);
    sd_jw_key(&jw, "lookup_name"); sd_jw_cstr(&jw, p->lookup_name);
  } else {
    sd_jw_key(&jw, "round"); sd_jw_int(&jw, p->round);
    sd_jw_key(&jw, "hostkey_just_accepted"); sd_jw_bool(&jw, p->hostkey_just_accepted);
    if (p->kind == SD_MP_PASSPHRASE) {
      sd_jw_key(&jw, "key_path"); sd_jw_cstr(&jw, p->key_path);
      sd_jw_key(&jw, "key_fingerprint"); sd_jw_cstr(&jw, p->key_fp);
    }
    if (p->kind == SD_MP_KBDINT) {
      sd_jw_key(&jw, "kbdint");
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "name"); sd_jw_cstr(&jw, p->name);
      sd_jw_key(&jw, "instruction"); sd_jw_cstr(&jw, p->instruction);
      sd_jw_key(&jw, "prompts");
      sd_jw_arr_begin(&jw);
      for (i = 0; i < p->item_count; i++) {
        sd_jw_obj_begin(&jw);
        sd_jw_key(&jw, "text"); sd_jw_cstr(&jw, p->items[i].text);
        sd_jw_key(&jw, "echo"); sd_jw_bool(&jw, p->items[i].echo);
        sd_jw_obj_end(&jw);
      }
      sd_jw_arr_end(&jw);
      sd_jw_obj_end(&jw);
    }
  }
  sd_jw_key(&jw, "can_save"); sd_jw_bool(&jw, 0);
  sd_jw_key(&jw, "deadline_ms"); sd_jw_int(&jw, 120000);
  sd_jw_obj_end(&jw);
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  if (sd_jw_finish(&jw) == SD_OK && sd_ipc_build_event("prompt.request", (const char *)d.p, d.len, &w) == SD_OK) {
    /* Routing (2.5): the initiating console client first, then UI subscribers of "prompt". */
    if (h->initiator && sd_ipc_send_to(g.srv, h->initiator, (const char *)w.p, w.len) == SD_OK)
      delivered = 1;
    sd_ipc_broadcast(g.srv, "prompt", (const char *)w.p, w.len);
  }
  sd_wr_free(&w);
  sd_wr_free(&d);
  if (!delivered) {
    /* No console client to answer and no UI launch/queue in M0: fail with prompt_required. */
    scopy(h->fail_code, sizeof(h->fail_code), p->kind == SD_MP_HOSTKEY ? "host_key_unknown" : "prompt_required");
    sd_mutex_unlock(&g.lock);
    sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
    return;
  }
  sd_mutex_unlock(&g.lock);
}

static void on_prompt_closed(void *ctx, sd_mount *m, uint32_t prompt_id)
{
  host_mount *h;
  char pid[32];
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) {
    sd_wr d;
    sd_json_writer jw;
    prompt_id_str(h, prompt_id, pid);
    sd_wr_init(&d, 4096);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, pid);
    sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
    sd_jw_key(&jw, "reason"); sd_jw_cstr(&jw, "answered");
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK) {
      sd_wr w;
      sd_wr_init(&w, 8192);
      if (sd_ipc_build_event("prompt.closed", (const char *)d.p, d.len, &w) == SD_OK) {
        if (h->initiator)
          (void)sd_ipc_send_to(g.srv, h->initiator, (const char *)w.p, w.len);
        sd_ipc_broadcast(g.srv, "prompt", (const char *)w.p, w.len);
      }
      sd_wr_free(&w);
    }
    sd_wr_free(&d);
  }
  sd_mutex_unlock(&g.lock);
}

/* ---- control-thread work items ---- */

static void work_start(void *arg)
{
  host_mount *h = (host_mount *)arg;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  sd_err e;
  memset(&cb, 0, sizeof(cb));
  cb.post = post;
  cb.on_state = on_state;
  cb.on_prompt = on_prompt;
  cb.on_prompt_closed = on_prompt_closed;
  cb.on_conn = on_conn;
  cb.on_write_failed = on_write_failed;
  cb.on_notice = on_notice;
  cb.lookup_identity = lookup_identity;
  cb.store_identity = store_identity;
  sd_mutex_lock(&g.lock);
  if (h->stop_requested) {
    /* unmounted before it started */
    host_mount **pp;
    for (pp = &g.mounts; *pp; pp = &(*pp)->next)
      if (*pp == h) { *pp = h->next; break; }
    sd_mutex_unlock(&g.lock);
    sd_free(h);
    return;
  }
  e = sd_mount_create(host_backend(), &h->params, &cb, &m);
  h->m = m;
  h->started = 1;
  sd_mutex_unlock(&g.lock);
  if (e != SD_OK) {
    sd_mutex_lock(&g.lock);
    h->state = SD_MOUNT_FAILED;
    {
      sd_wr d;
      sd_json_writer jw;
      sd_wr_init(&d, 4096);
      sd_jw_init(&jw, &d);
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
      sd_jw_key(&jw, "state"); sd_jw_cstr(&jw, "failed");
      sd_jw_key(&jw, "target"); jw_letter(&jw, h->letter);
      sd_jw_key(&jw, "error"); sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, sd_err_name(e));
      sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, "mount create failed");
      sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, sd_ipc_exit_code_for_err(e));
      sd_jw_obj_end(&jw);
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK) broadcast_data("mount", "mount.state", &d);
      sd_wr_free(&d);
    }
    destroy_record_locked(h);
    sd_mutex_unlock(&g.lock);
    return;
  }
  /* sd_mount_start reports failures through on_state (which may destroy the record). */
  (void)sd_mount_start(m);
}

static void work_stop(void *arg)
{
  uint32_t num = (uint32_t)(uintptr_t)arg;
  host_mount *h;
  sd_mount *m = NULL;
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (h->num == num) break;
  if (h && h->m && !sd_mount_is_final(h->m))
    m = h->m;
  sd_mutex_unlock(&g.lock);
  /* sd_mount_stop calls on_state synchronously (which takes g.lock): never call it locked. */
  if (m)
    sd_mount_stop(m);
}

static void work_shutdown(void *arg)
{
  SD_UNUSED(arg);
  InterlockedExchange(&g.stop, 1);
}

static void work_cancel_client(void *arg)
{
  uint64_t cid = *(uint64_t *)arg;
  host_mount *h;
  sd_free(arg);
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next) {
    if (h->initiator == cid) {
      h->initiator = 0;
      if (h->m && sd_mount_cancel_prompts(h->m) > 0)
        scopy(h->fail_code, sizeof(h->fail_code), "prompt_required");
    }
  }
  sd_mutex_unlock(&g.lock);
}

/* ---- IPC handler (IPC thread) ---- */

static int letter_in_use_locked(wchar_t l)
{
  host_mount *h;
  DWORD drives = GetLogicalDrives();
  if (drives & (1u << (l - L'A')))
    return 1;
  for (h = g.mounts; h; h = h->next)
    if (h->letter == l) return 1;
  return 0;
}

static sd_err fail(sd_ipc_error *err, sd_err e, const char *code, const char *detail)
{
  sd_ipc_error_set(err, e, code, detail);
  return err->err;
}

static sd_err handle_mount(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  sd_profile prof;
  const sd_json *adhoc = sd_json_get(params, "adhoc");
  const char *pname = sd_json_get_str(params, "profile");
  const char *target = sd_json_get_str(params, "target");
  const char *pmode = sd_json_get_str(params, "prompt_mode");
  const char *pbackend = sd_json_get_str(params, "backend");
  sd_mount_backend_kind backend = SD_MOUNT_BACKEND_AUTO;
  const char *bad = NULL;
  host_mount *h, *o;
  wchar_t wt[8], letter = 0;
  wchar_t root[MAX_PATH];
  int ro = 0;
  sd_err e;

  sd_profile_defaults(&prof);
  if (adhoc) {
    const char *v;
    int64_t port = 22;
    if ((v = sd_json_get_str(adhoc, "host")) == NULL || strlen(v) >= sizeof(prof.host))
      return fail(err, SD_E_INVALID_PARAM, "usage", "adhoc.host required");
    scopy(prof.host, sizeof(prof.host), v);
    scopy(prof.name, sizeof(prof.name), v);
    if (sd_json_get(adhoc, "port") && (!sd_json_get_int64(adhoc, "port", &port) || port < 1 || port > 65535))
      return fail(err, SD_E_INVALID_PARAM, "usage", "adhoc.port invalid");
    prof.port = (uint16_t)port;
    if ((v = sd_json_get_str(adhoc, "user")) != NULL) scopy(prof.user, sizeof(prof.user), v);
    if ((v = sd_json_get_str(adhoc, "identity")) != NULL) scopy(prof.identity, sizeof(prof.identity), v);
    if ((v = sd_json_get_str(adhoc, "remote_path")) != NULL) scopy(prof.remote_path, sizeof(prof.remote_path), v);
    if (sd_profile_validate(&prof, &bad) != SD_OK)
      return fail(err, SD_E_INVALID_PARAM, "usage", bad);
  } else if (pname) {
    e = sd_profile_find(pname, &prof, NULL, 0);
    if (e == SD_E_NOT_FOUND)
      return fail(err, e, "profile_not_found", "no such profile");
    if (e != SD_OK)
      return fail(err, e, NULL, "cannot read profiles");
  } else {
    return fail(err, SD_E_INVALID_PARAM, "usage", "profile or adhoc required");
  }
  if (sd_json_get_bool(params, "read_only", &ro) && ro)
    prof.read_only = 1;
  if (pbackend && !sd_mount_backend_kind_parse(pbackend, &backend))
    return fail(err, SD_E_INVALID_PARAM, "usage", "backend must be auto, dokany or webdav");
  if (pbackend == NULL)
    backend = (sd_mount_backend_kind)prof.backend;    /* mount.backend (same values) */
  if (target == NULL || strcmp(target, "auto") == 0)
    target = prof.target;
  if (strcmp(target, "auto") != 0) {
    if (!wide_from_utf8(target, wt, SD_COUNTOF(wt)) || (letter = sd_parse_drive_letter(wt)) == 0)
      return fail(err, SD_E_INVALID_PARAM, "invalid_target", "target must be a drive letter");
    if (letter < L'D')
      return fail(err, SD_E_INVALID_PARAM, "invalid_target", "drive letters A: to C: are not used");
  }
  if (prof.user[0] == 0) {
    wchar_t wu[128];
    DWORD n = SD_COUNTOF(wu);
    size_t got = 0;
    if (GetUserNameW(wu, &n) && n > 0 &&
        sd_utf16_to_utf8(wu, n - 1, prof.user, sizeof(prof.user) - 1, &got, SD_UTF_STRICT) == SD_OK)
      prof.user[got] = 0;
    else
      return fail(err, SD_E_INVALID_PARAM, "usage", "user required");
  }

  h = (host_mount *)sd_calloc(1, sizeof(*h));
  if (h == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  scopy(h->profile_name, sizeof(h->profile_name), prof.name);
  scopy(h->profile_id, sizeof(h->profile_id), prof.id);
  scopy(h->host, sizeof(h->host), prof.host);
  scopy(h->user, sizeof(h->user), prof.user);
  scopy(h->remote, sizeof(h->remote), prof.remote_path);
  h->port = prof.port;
  h->read_only = prof.read_only;
  h->backend_req = (int)backend;
  h->initiator = sd_ipc_client_id(client);
  h->prompt_none = (pmode && strcmp(pmode, "none") == 0) ||
                   !(sd_ipc_client_caps(client) & (SD_IPC_CAP_PROMPTS_CONSOLE | SD_IPC_CAP_PROMPTS_UI));
  h->state = SD_MOUNT_CONNECTING;
  if (!wide_from_utf8(prof.host, h->whost, SD_COUNTOF(h->whost)) ||
      !wide_from_utf8(prof.label[0] ? prof.label : prof.name, h->label, SD_COUNTOF(h->label))) {
    sd_free(h);
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid host or label");
  }
  if (prof.identity[0] && sd_config_expand_path(prof.identity, h->identity, SD_COUNTOF(h->identity)) != SD_OK) {
    sd_free(h);
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid identity path");
  }
  if (sd_config_root(root, SD_COUNTOF(root)) == SD_OK && wcslen(root) + 13 < SD_COUNTOF(h->kh)) {
    memcpy(h->kh, root, (wcslen(root) + 1) * sizeof(wchar_t));
    wcscat_s(h->kh, SD_COUNTOF(h->kh), L"\\known_hosts");
  }
  {
    /* per-source cache folder (disk tier, identity cache): key "user@host:port" */
    char key[512], pnum[8];
    size_t kn = strlen(prof.user) + strlen(prof.host) + 8;
    uint32_t v = prof.port, pi = 0;
    char tmp[8];
    size_t tn = 0;
    do { tmp[tn++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (tn) pnum[pi++] = tmp[--tn];
    pnum[pi] = 0;
    if (kn < sizeof(key)) {
      key[0] = 0;
      strcat_s(key, sizeof(key), prof.user);
      strcat_s(key, sizeof(key), "@");
      strcat_s(key, sizeof(key), prof.host);
      strcat_s(key, sizeof(key), ":");
      strcat_s(key, sizeof(key), pnum);
      if (sd_config_cache_dir(key, h->cache_dir, SD_COUNTOF(h->cache_dir)) != SD_OK) {
        SD_LOGW("agent", "cache folder unavailable; no disk tier or identity cache");
        h->cache_dir[0] = 0;
      }
    }
  }

  sd_mutex_lock(&g.lock);
  for (o = g.mounts; o; o = o->next) {
    if (prof.id[0] && strcmp(o->profile_id, prof.id) == 0) {
      sd_mutex_unlock(&g.lock);
      sd_free(h);
      return fail(err, SD_E_EXISTS, "already_mounted", "profile already mounted");
    }
  }
  if (letter) {
    if (letter_in_use_locked(letter)) {
      char detail[32];
      sd_mutex_unlock(&g.lock);
      sd_free(h);
      scopy(detail, sizeof(detail), "drive letter in use: X:");
      detail[21] = (char)letter;     /* the CLI reads the letter from the end of the detail */
      return fail(err, SD_E_EXISTS, "target_in_use", detail);
    }
  } else {
    wchar_t l;
    for (l = L'Z'; l >= L'D'; l--)
      if (!letter_in_use_locked(l)) { letter = l; break; }
    if (letter == 0) {
      sd_mutex_unlock(&g.lock);
      sd_free(h);
      return fail(err, SD_E_EXISTS, "target_in_use", "no free drive letter");
    }
  }
  h->letter = letter;
  h->num = ++g.next_num;
  {
    char tmp[12];
    size_t n = 0, i = 0;
    uint32_t v = h->num;
    h->id[i++] = 'm'; h->id[i++] = '-';
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (n) h->id[i++] = tmp[--n];
    h->id[i] = 0;
  }
  memset(&h->params, 0, sizeof(h->params));
  h->params.struct_size = sizeof(h->params);
  h->params.host = h->whost;
  h->params.port = h->port;
  h->params.user = h->user;
  h->params.identity_path = h->identity[0] ? h->identity : NULL;
  h->params.auth_methods = ((prof.auth_methods & SD_PROFILE_AUTH_PUBLICKEY) ? SD_AUTH_PUBLICKEY : 0) |
                           ((prof.auth_methods & SD_PROFILE_AUTH_KBDINT) ? SD_AUTH_KBDINT : 0) |
                           ((prof.auth_methods & SD_PROFILE_AUTH_PASSWORD) ? SD_AUTH_PASSWORD : 0);
  h->params.remote_path = h->remote[0] ? h->remote : NULL;
  h->params.letter = letter;
  h->params.read_only = prof.read_only;
  h->params.symlinks = prof.symlinks;
  h->params.write_mode = prof.write_mode;
  h->params.volume_label = h->label;
  h->params.known_hosts_path = h->kh[0] ? h->kh : NULL;
  h->params.backend = h->backend_req;
  h->params.disk_cache_mb = prof.disk_cache_mb;
  h->params.disk_cache_dir = h->cache_dir[0] ? h->cache_dir : NULL;
  h->params.offline_wait_ms = prof.offline_wait_ms;
  h->params.reconnect_grace_ms = prof.reconnect_grace_ms;
  h->params.channels = prof.channels;
  h->params.cache_memory_bytes = g.settings.cache_memory;
  h->next = g.mounts;
  g.mounts = h;
  g.last_busy = sd_tick_ms();
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
  sd_jw_key(res, "target"); jw_letter(res, letter);
  sd_jw_key(res, "profile"); sd_jw_cstr(res, h->profile_name);
  sd_jw_key(res, "state"); sd_jw_cstr(res, "connecting");
  sd_mutex_unlock(&g.lock);
  SD_LOGI("agent", "mount %s requested by client %llu", h->id, (unsigned long long)h->initiator);
  post(NULL, work_start, h);
  return SD_OK;
}

static int mount_matches(host_mount *h, const char *target, const char *mount_id, const char *profile)
{
  if (mount_id && strcmp(h->id, mount_id) == 0) return 1;
  if (profile && (strcmp(h->profile_name, profile) == 0 || strcmp(h->profile_id, profile) == 0)) return 1;
  if (target) {
    wchar_t wt[8];
    if (wide_from_utf8(target, wt, SD_COUNTOF(wt)) && sd_parse_drive_letter(wt) == h->letter) return 1;
  }
  return 0;
}

static sd_err handle_unmount(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *target = sd_json_get_str(params, "target");
  const char *mount_id = sd_json_get_str(params, "mount_id");
  const char *profile = sd_json_get_str(params, "profile");
  int all = 0, n = 0;
  host_mount *h;
  sd_json_get_bool(params, "all", &all);
  if (!all && !target && !mount_id && !profile)
    return fail(err, SD_E_INVALID_PARAM, "usage", "target, mount_id, profile or all required");
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  for (h = g.mounts; h; h = h->next) {
    if (all || mount_matches(h, target, mount_id, profile)) {
      if (!h->stop_requested) {
        h->stop_requested = 1;
        post(NULL, work_stop, (void *)(uintptr_t)h->num);
      }
      sd_jw_obj_begin(res);
      sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
      sd_jw_key(res, "target"); jw_letter(res, h->letter);
      sd_jw_obj_end(res);
      n++;
    }
  }
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  if (n == 0 && !all)
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  return SD_OK;
}

static sd_err handle_list(sd_json_writer *res)
{
  host_mount *h;
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  for (h = g.mounts; h; h = h->next)
    write_mount_json(res, h);
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

static sd_err handle_prompt_answer(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *pid = sd_json_get_str(params, "prompt_id");
  const char *action = sd_json_get_str(params, "action");
  const sd_json *resp = sd_json_get(params, "responses");
  const char *r[SD_MOUNT_PROMPT_MAX_ITEMS];
  uint32_t mnum = 0, id = 0, n = 0, i;
  sd_mount_answer_kind kind;
  host_mount *h;
  sd_err e = SD_E_NOT_FOUND;
  if (!parse_prompt_id(pid, &mnum, &id) || action == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "prompt_id and action required");
  if (strcmp(action, "accept") == 0) kind = SD_MA_HOSTKEY_TRUST;
  else if (strcmp(action, "once") == 0) kind = SD_MA_HOSTKEY_ONCE;
  else if (strcmp(action, "answer") == 0) kind = SD_MA_RESPONSES;
  else if (strcmp(action, "reject") == 0 || strcmp(action, "cancel") == 0) kind = SD_MA_REJECT;
  else return fail(err, SD_E_INVALID_PARAM, "usage", "unknown action");
  if (kind == SD_MA_RESPONSES) {
    n = (uint32_t)sd_json_count(resp);
    if (n == 0 || n > SD_MOUNT_PROMPT_MAX_ITEMS)
      return fail(err, SD_E_INVALID_PARAM, "usage", "responses required");
    for (i = 0; i < n; i++) {
      r[i] = sd_json_str(sd_json_at(resp, i), NULL);
      if (r[i] == NULL)
        return fail(err, SD_E_INVALID_PARAM, "usage", "responses must be strings");
    }
  }
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next) {
    if (h->num == mnum && h->m) {
      if (kind == SD_MA_REJECT && strcmp(action, "cancel") == 0)
        scopy(h->fail_code, sizeof(h->fail_code), "cancelled");
      e = sd_mount_answer(h->m, id, kind, n, r);
      break;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (e == SD_E_NOT_FOUND)
    return fail(err, e, "not_found", "prompt not open");
  sd_jw_key(res, "accepted"); sd_jw_bool(res, e == SD_OK);
  return SD_OK;
}

static sd_err ipc_handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                          sd_json_writer *res, sd_ipc_error *err)
{
  SD_UNUSED(ctx);
  if (strcmp(method, "mount") == 0) return handle_mount(client, params, res, err);
  if (strcmp(method, "unmount") == 0) return handle_unmount(params, res, err);
  if (strcmp(method, "list") == 0) return handle_list(res);
  if (strcmp(method, "prompt.answer") == 0) return handle_prompt_answer(params, res, err);
  if (strcmp(method, "agent.shutdown") == 0) {
    post(NULL, work_shutdown, NULL);
    sd_jw_key(res, "stopping"); sd_jw_bool(res, 1);
    return SD_OK;
  }
  return fail(err, SD_E_UNSUPPORTED, "usage", "unknown method");
}

static void ipc_on_disconnect(void *ctx, uint64_t client_id)
{
  uint64_t *p = (uint64_t *)sd_alloc(sizeof(uint64_t));
  SD_UNUSED(ctx);
  if (p == NULL) return;
  *p = client_id;
  post(NULL, work_cancel_client, p);
}

/* ---- crash filter (TM-R17 b) ---- */

static LPTOP_LEVEL_EXCEPTION_FILTER g_prev_filter;

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep)
{
  /* No allocation, no locks: drop this process's WebDAV mappings so that the drive letter does not
     keep pointing at a port another local user could bind. Crash dumps (03 §10.4) come later. */
  if (host_backend()->webdav_emergency_unmap)
    host_backend()->webdav_emergency_unmap();
  return g_prev_filter ? g_prev_filter(ep) : EXCEPTION_CONTINUE_SEARCH;
}

static void cleanup_webdav_mappings(const char *when)
{
  if (host_backend()->webdav_cleanup_mappings) {
    uint32_t removed = 0;
    host_backend()->webdav_cleanup_mappings(0, 0, &removed);
    if (removed)
      SD_LOGW("agent", "removed %u stale WebDAV mapping(s) at %s", (unsigned)removed, when);
  }
}

/* ---- main loop ---- */

static int mounts_empty(void)
{
  int empty;
  sd_mutex_lock(&g.lock);
  empty = g.mounts == NULL;
  sd_mutex_unlock(&g.lock);
  return empty;
}

int host_agent_run(const host_agent_opts *opts)
{
  HANDLE mutex = NULL, stop_ev = NULL, ready = NULL;
  int existed = 0;
  sd_ipc_server_cfg cfg;
  sd_err e;
  uint64_t deadline;

  memset(&g, 0, sizeof(g));
  (void)sd_settings_load(&g.settings);
  sd_log_set_level((sd_log_level)g.settings.log_level);
  sd_mutex_init(&g.lock);
  sd_mutex_init(&g.qlock);
  g.qev = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (g.qev == NULL)
    return 1;

  e = sd_ipc_object_create(SD_IPC_OBJ_AGENT_MUTEX, &mutex, &existed);
  if (e == SD_OK && existed) {
    SD_LOGI("agent", "another agent runs in this session; exiting");
    CloseHandle(mutex);
    return 0;
  }
  if (e != SD_OK)
    SD_LOGE("agent", "session mutex unavailable (%s): named_object_squatted", sd_err_name(e));
  if (sd_ipc_object_create(SD_IPC_OBJ_AGENT_STOP, &stop_ev, &existed) != SD_OK) {
    SD_LOGE("agent", "shutdown event unavailable: named_object_squatted");
    stop_ev = NULL;
  } else {
    ResetEvent(stop_ev);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = ipc_handler;
  cfg.on_disconnect = ipc_on_disconnect;
  e = sd_ipc_server_start_ex(SD_IPC_AGENT, &cfg, &g.srv);
  if (e != SD_OK) {
    SD_LOGE("agent", "cannot serve the agent pipe (%s)", sd_err_name(e));
    if (stop_ev) CloseHandle(stop_ev);
    if (mutex) CloseHandle(mutex);
    return e == SD_E_ACCESS_DENIED ? 9 : 1;
  }
  if (sd_ipc_object_create(SD_IPC_OBJ_AGENT_READY, &ready, &existed) == SD_OK)
    SetEvent(ready);
  else
    SD_LOGE("agent", "ready event unavailable: named_object_squatted");
  SD_LOGI("agent", "agent %s ready (backend %s)", SD_VERSION_STRING, host_backend()->name);
  /* TM-R17 d: WebDAV mappings left by a crashed agent of this logon session point at a free port that
     another user could bind; remove them before anything else */
  cleanup_webdav_mappings("start");
  g_prev_filter = SetUnhandledExceptionFilter(crash_filter);
  g.last_busy = sd_tick_ms();

  while (!g.stop) {
    HANDLE hs[2];
    DWORD n = 0, w;
    hs[n++] = g.qev;
    if (stop_ev) hs[n++] = stop_ev;
    w = WaitForMultipleObjects(n, hs, FALSE, 1000);
    if (stop_ev && w == WAIT_OBJECT_0 + 1) {
      SD_LOGI("agent", "shutdown event signaled");
      break;
    }
    drain();
    if (!opts->logon && opts->idle_exit_ms) {
      uint64_t now = sd_tick_ms();
      if (!mounts_empty() || sd_ipc_server_client_count(g.srv) > 0)
        g.last_busy = now;
      else if (now - g.last_busy > opts->idle_exit_ms) {
        SD_LOGI("agent", "idle; exiting");
        break;
      }
    }
  }

  /* Shutdown sequence (1.2): stop every mount, wait (bounded) for teardown, then the pipe. */
  if (ready) ResetEvent(ready);
  {
    host_mount *h;
    sd_mutex_lock(&g.lock);
    for (h = g.mounts; h; h = h->next) {
      if (!h->stop_requested) {
        h->stop_requested = 1;
        post(NULL, work_stop, (void *)(uintptr_t)h->num);
      }
    }
    sd_mutex_unlock(&g.lock);
  }
  deadline = sd_tick_ms() + 15000;
  while (!mounts_empty() && sd_tick_ms() < deadline) {
    WaitForSingleObject(g.qev, 100);
    drain();
  }
  sd_ipc_server_stop(g.srv);
  g.srv = NULL;
  drain();
  /* mounts that did not finish their teardown in time must not leave a mapping behind (TM-R17) */
  cleanup_webdav_mappings("stop");
  SetUnhandledExceptionFilter(g_prev_filter);
  if (ready) CloseHandle(ready);
  if (stop_ev) CloseHandle(stop_ev);
  if (mutex) CloseHandle(mutex);
  SD_LOGI("agent", "agent stopped");
  return 0;
}
