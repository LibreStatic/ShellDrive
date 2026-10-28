/* sd_mount glue (03 §1.11). See sd_mount.h for the contract. */
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "sd_mount/sd_mount.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

#define MAX_PROMPTS 8
#define MAX_SAVES 8
#define TARGET_CAP 320
#define SECRET_CAP 1024
#define NO_HOP 0xFFFFFFFFu

typedef struct pending_prompt {
  uint32_t id; sd_prompt *p; sd_mount_prompt_kind kind;
  /* M2 */
  uint32_t hop;
  int skind;                     /* SD_MOUNT_SECRET_* this prompt can be answered from, or -1 */
  int savable;
  char target[TARGET_CAP];
} pending_prompt;

enum { EV_READY, EV_FAILED, EV_DISCONNECTED, EV_CLOSED, EV_PROMPT, EV_PROMPT_CLOSED, EV_DOKAN_UNMOUNTED,
       EV_CONN, EV_AUTH_REQUIRED, EV_WRITE_FAILED, EV_NOTICE, EV_IDENTITY,
       EV_WARNING, EV_ANNOUNCED,
       EV_TOKEN_ASK,            /* TM-R19: raise SD_MP_WEBDAV_TOKEN_ONLY (it->prompt) */
       EV_TOKEN_ONLY,           /* TM-R19: the answer (err SD_OK = accept, otherwise refused) */
       EV_HK_DONE,              /* M5 hostkey mount: the connect and the fetch ended (err = the failure) */
       EV_AUDIT };              /* M5: it->detail = requestor SID text, it->code = operation, it->path */

/* M2: owned copy of one hop (sd_mount_hop) */
typedef struct owned_hop {
  wchar_t *host; uint16_t port; char *user;
  char host8[256];               /* UTF-8 host (secret targets, prompt labels) */
  wchar_t *ident[SD_MOUNT_MAX_IDENTITIES]; uint32_t nident;
  uint8_t *blob; size_t blob_len; char *label;
  wchar_t *cert;
  uint32_t agents; int ident_only;
  char agent_key[SD_MOUNT_MAX_AGENT_KEYS][72]; uint32_t nagent_keys;
  uint32_t methods; char *alias; int hku; int no_save;
  int pkind; wchar_t *phost; uint16_t pport; char *puser; uint32_t pauth; int psspi, psys, pfallback;
  char phost8[256];
} owned_hop;

typedef struct mount_item {
  sd_mount *m;
  int kind;
  sd_err err;
  uint32_t prompt_id;
  sd_mount_prompt *prompt;
  /* EV_WRITE_FAILED / EV_NOTICE */
  UINT64 bytes;
  const char *status;            /* static string */
  wchar_t path[260];
  char code[48], detail[256];
  BYTE sid[SECURITY_MAX_SID_SIZE];      /* M5 audit: a copy of the requestor SID (EV_AUDIT) */
  /* M2 */
  int pool_member;               /* EV_PROMPT of a pool member: store or cancel, never shown */
  uint32_t hop;                  /* EV_WARNING */
  sd_mount_announcement *ann;    /* EV_ANNOUNCED */
} mount_item;

struct sd_mount {
  const sd_mount_backend *be;
  sd_mount_callbacks cb;
  volatile LONG refs;
  /* owned copies of the parameters */
  wchar_t *host, *identity, *label, *kh_path;
  char *user, *remote;
  uint16_t port;
  uint32_t methods;
  wchar_t letter;
  int read_only, symlinks, write_mode;
  sd_mount_tuning tune;           /* M3 vfs and session tuning (copied) */
  PSID owner_sid;
  /* M5: global mount (service, D35): no per-session drive, volume SD copied from the params */
  int global_mount;
  uint8_t *volume_sd;
  uint32_t volume_sd_len;
  PSID *acc_sids; uint32_t n_acc;       /* M5: service_access and service_access_write, copied (02 6.7) */
  PSID *wrt_sids; uint32_t n_wrt;
  /* M1 parameters */
  UINT64 cache_mem;
  uint32_t disk_mb, offline_wait, grace, channels;
  wchar_t *disk_dir;
  int reconnect_disabled, no_secret_cache;
  uint32_t rc_initial, rc_max, rc_attempts;
  /* configuration handed to sd_ssh / sd_sftp (must stay valid while the session lives) */
  sd_ssh_identity ident;
  sd_ssh_hop hop;
  sd_ssh_config ssh;
  sd_ssh_callbacks sshcb;
  sd_sftp_options sopt;
  sd_kh_store store;
  /* objects */
  sd_known_hosts *kh;
  sd_sftp_session *sess;
  sd_vfs *vfs;
  sd_dokan_mount *dm;
  sd_webdav_mount *wm;
  int backend_req;                /* sd_mount_backend_kind requested */
  sd_mount_backend_kind used;     /* resolved at on_ready */
  /* state (control thread) */
  sd_mount_state state;
  int started, stopping, user_stop, session_closing, finished, destroyed;
  /* shared with I/O threads */
  sd_mutex lock;
  pending_prompt prompts[MAX_PROMPTS];
  uint32_t nprompts, next_prompt_id;
  sd_mount_failure fail;
  sd_mount_conn conn;             /* M1 connection sub-state */
  char hostkey_fp[64];            /* verified host key of the current connection */
  /* TM-R19: token-only WebDAV. consent_pending: the mount waits for the user's answer to
     SD_MP_WEBDAV_TOKEN_ONLY (consent_id); token_only/_confirmed are copied from the params and set on accept */
  int token_only, token_only_confirmed;
  int consent_pending;
  uint32_t consent_id;
  sd_vfs_identity known_id;       /* passed to the vfs (lookup_identity) */
  /* M2 */
  owned_hop hops[SD_MOUNT_MAX_HOPS];
  uint32_t nhops;
  sd_ssh_hop sshhops[SD_MOUNT_MAX_HOPS];
  sd_ssh_identity ids[SD_MOUNT_MAX_HOPS][SD_MOUNT_MAX_IDENTITIES + 1 + SD_MOUNT_MAX_AGENT_KEYS];
  sd_kh_store *stores;
  uint32_t nstores;
  int legacy_policy, refuse_terrapin;
  uint32_t connections, keepalive, ctimeout;
  wchar_t *profile_name;
  uint32_t ja_from;               /* first hop whose key was accepted by a prompt in this connection (TM-R05) */
  uint32_t autofilled[3];         /* per secret kind, bit per hop: a stored secret was used in this connection */
  struct { int kind; char target[TARGET_CAP]; char *value; size_t len; } saves[MAX_SAVES];
  uint32_t nsaves;
  uint32_t warned_legacy, warned_proxy;   /* bit per hop */
  int warned_pool;
  /* M3 */
  int test_only;                  /* profile.test: connect, authenticate, realpath; no vfs */
  int force_stop;                 /* sd_mount_stop_ex(force): no write-behind drain budget */
  int readers;                    /* stats / refresh / cache calls in progress (under lock) */
  uint16_t wport;                 /* WebDAV export port while the export exists (under lock) */
  int legacy_seen;                /* an outdated algorithm was negotiated on some hop */
  int probe_ok;                   /* probe holds the profile.test result */
  sd_mount_probe probe;
  /* M5 hostkey mount (params.hostkey_fetch): no sftp session; the connection is hk_conn */
  int hk_fetch;
  char hk_type[64];               /* "" = the default key types */
  sd_ssh_conn *hk_conn;
  int hk_presented;               /* first contact: the presented key was taken (I/O thread, under lock) */
  sd_mount_hostkey hk_key;        /* the presented key (first contact) */
  sd_mount_hk_fetch hk_res;       /* the result (under lock) */
};

static const char *const k_sess_names[] = {
  "idle", "connecting", "ready", "disconnected", "reconnect_wait", "auth_required", "failed", "closed"
};

const char *sd_mount_session_state_name(sd_sftp_state st)
{
  return (unsigned)st < SD_COUNTOF(k_sess_names) ? k_sess_names[st] : "failed";
}

static const char *const k_state_names[] = {
  "connecting", "authenticating", "mounted", "offline", "auth_required", "failed", "unmounting", "unmounted"
};

const char *sd_mount_state_name(sd_mount_state st)
{
  return (unsigned)st < SD_COUNTOF(k_state_names) ? k_state_names[st] : "failed";
}

const char *sd_mount_backend_kind_name(sd_mount_backend_kind k)
{
  switch (k) {
  case SD_MOUNT_BACKEND_DOKANY: return "dokany";
  case SD_MOUNT_BACKEND_WEBDAV: return "webdav";
  default:                      return "auto";
  }
}

int sd_mount_backend_kind_parse(const char *s, sd_mount_backend_kind *out)
{
  if (s == NULL) return 0;
  if (strcmp(s, "auto") == 0) *out = SD_MOUNT_BACKEND_AUTO;
  else if (strcmp(s, "dokany") == 0) *out = SD_MOUNT_BACKEND_DOKANY;
  else if (strcmp(s, "webdav") == 0) *out = SD_MOUNT_BACKEND_WEBDAV;
  else return 0;
  return 1;
}

const char *sd_mount_prompt_kind_name(sd_mount_prompt_kind k)
{
  switch (k) {
  case SD_MP_HOSTKEY:    return "hostkey_unknown";
  case SD_MP_PASSWORD:   return "password";
  case SD_MP_PASSPHRASE: return "passphrase";
  case SD_MP_KBDINT:     return "kbdint";
  case SD_MP_PASSWORD_CHANGE: return "password_change";
  case SD_MP_LEGACY_ACK: return "legacy_ack";
  case SD_MP_WEBDAV_TOKEN_ONLY: return "webdav_token_only";
  case SD_MP_PROXY_PASSWORD: return "proxy_password";
  }
  return "password";
}

/* ---- helpers ---- */

static wchar_t *wdup(const wchar_t *s)
{
  size_t n;
  wchar_t *d;
  if (s == NULL || s[0] == 0)
    return NULL;
  n = wcslen(s);
  d = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
  if (d) memcpy(d, s, (n + 1) * sizeof(wchar_t));
  return d;
}

static char *sdup(const char *s)
{
  size_t n;
  char *d;
  if (s == NULL || s[0] == 0)
    return NULL;
  n = strlen(s);
  d = (char *)sd_alloc(n + 1);
  if (d) memcpy(d, s, n + 1);
  return d;
}

static void scopy(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (cap == 0)
    return;
  if (src)
    for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
  dst[i] = 0;
}

static void addref(sd_mount *m) { InterlockedIncrement(&m->refs); }

static void wipe_saves(sd_mount *m)
{
  uint32_t i;
  for (i = 0; i < m->nsaves; i++) {
    if (m->saves[i].value) sd_secure_free(m->saves[i].value, m->saves[i].len + 1);
    m->saves[i].value = NULL;
  }
  m->nsaves = 0;
}

static void free_hop(owned_hop *h)
{
  uint32_t i;
  sd_free(h->host);
  sd_free(h->user);
  for (i = 0; i < SD_MOUNT_MAX_IDENTITIES; i++) sd_free(h->ident[i]);
  if (h->blob) sd_secure_free(h->blob, h->blob_len);
  sd_free(h->label);
  sd_free(h->cert);
  sd_free(h->alias);
  sd_free(h->phost);
  sd_free(h->puser);
  memset(h, 0, sizeof(*h));
}

/* M5: deep copies of a SID list for a global mount (02 6.7). *nout is set before the copies so that a
   partial copy is released by free_sid_list. */
static void free_sid_list(PSID **list, uint32_t *n)
{
  uint32_t i;
  if (*list) {
    for (i = 0; i < *n; i++)
      sd_free((*list)[i]);
    sd_free(*list);
  }
  *list = NULL;
  *n = 0;
}

static sd_err copy_sid_list(void *const *in, uint32_t n, PSID **list, uint32_t *nout)
{
  uint32_t i;
  *list = NULL;
  *nout = 0;
  if (n == 0)
    return SD_OK;
  if (in == NULL)
    return SD_E_INVALID_PARAM;
  *list = (PSID *)sd_calloc(n, sizeof(PSID));
  if (*list == NULL)
    return SD_E_NO_MEMORY;
  *nout = n;
  for (i = 0; i < n; i++) {
    DWORD len;
    if (in[i] == NULL || !IsValidSid(in[i]))
      return SD_E_INVALID_PARAM;
    len = GetLengthSid(in[i]);
    (*list)[i] = sd_alloc(len);
    if ((*list)[i] == NULL)
      return SD_E_NO_MEMORY;
    if (!CopySid(len, (*list)[i], in[i]))
      return SD_E_INVALID_PARAM;
  }
  return SD_OK;
}

static void free_mount(sd_mount *m)
{
  uint32_t i;
  wipe_saves(m);
  for (i = 0; i < SD_MOUNT_MAX_HOPS; i++) free_hop(&m->hops[i]);
  for (i = 0; i < m->nstores; i++) sd_free((void *)m->stores[i].path);
  sd_free(m->stores);
  sd_free(m->profile_name);
  sd_free(m->host);
  sd_free(m->identity);
  sd_free(m->label);
  sd_free(m->kh_path);
  sd_free(m->user);
  sd_free(m->remote);
  sd_free(m->owner_sid);
  sd_free(m->volume_sd);
  free_sid_list(&m->acc_sids, &m->n_acc);
  free_sid_list(&m->wrt_sids, &m->n_wrt);
  sd_free(m->disk_dir);
  sd_mutex_destroy(&m->lock);
  sd_free(m);
}

static void release(sd_mount *m)
{
  if (InterlockedDecrement(&m->refs) == 0)
    free_mount(m);
}

static void run_item(void *arg);

/* Any thread: queue an item for the control thread. */
static void post_item(sd_mount *m, int kind, sd_err err, uint32_t prompt_id, sd_mount_prompt *prompt)
{
  mount_item *it = (mount_item *)sd_calloc(1, sizeof(*it));
  if (it == NULL) {
    SD_LOGE("mount", "out of memory posting to the control thread");
    sd_free(prompt);
    return;
  }
  it->m = m;
  it->kind = kind;
  it->err = err;
  it->prompt_id = prompt_id;
  it->prompt = prompt;
  addref(m);
  m->cb.post(m->cb.ctx, run_item, it);
}

static void set_state(sd_mount *m, sd_mount_state st, sd_err why)
{
  if (m->state == st)
    return;
  m->state = st;
  SD_LOGI("mount", "%c: state %s (%s)", (int)m->letter, sd_mount_state_name(st), sd_err_name(why));
  if (m->cb.on_state)
    m->cb.on_state(m->cb.ctx, m, st, why);
}

static void record_failure(sd_mount *m, sd_err e, const char *code, const char *detail)
{
  sd_mutex_lock(&m->lock);
  if (m->fail.err == SD_OK) {
    m->fail.err = e;
    m->fail.code = code;
    scopy(m->fail.detail, sizeof(m->fail.detail), detail ? detail : sd_err_name(e));
  }
  sd_mutex_unlock(&m->lock);
}

static void run_item(void *arg);
static void post_item(sd_mount *m, int kind, sd_err err, uint32_t prompt_id, sd_mount_prompt *prompt);
static void build_ssh_config(sd_mount *m);
static sd_err hk_start(sd_mount *m);
static void hk_finish(sd_mount *m);

/* Dokany thread: post only (sd_dokan.h). */
static void dokan_on_unmounted(void *ctx, sd_dokan_mount *dm)
{
  SD_UNUSED(dm);
  post_item((sd_mount *)ctx, EV_DOKAN_UNMOUNTED, SD_OK, 0, NULL);
}

static const char *vfs_status_code(sd_vfs_status st)
{
  switch (st) {
  case SD_VFS_E_DISCONNECTED:   return "disconnected";
  case SD_VFS_E_STALE:          return "stale";
  case SD_VFS_E_TIMEOUT:        return "timeout";
  case SD_VFS_E_NO_SPACE:       return "no_space";
  case SD_VFS_E_QUOTA:          return "quota";
  case SD_VFS_E_ACCESS_DENIED:  return "access_denied";
  case SD_VFS_E_NOT_FOUND:
  case SD_VFS_E_PATH_NOT_FOUND: return "not_found";
  case SD_VFS_E_CANCELLED:      return "cancelled";
  default:                      return "io_error";
  }
}

/* vfs threads, no vfs lock held: post only (the control thread reports). */
/* M5 audit (vfs threads): the SID is copied into the item, since the vfs pointer is valid only during the callback.
   The copy is built from the SID layout (Revision, SubAuthorityCount, IdentifierAuthority, sub-authorities), so this
   file needs no advapi32; the host converts it to text. */
static void vfs_audit_post(sd_mount *m, const sd_vfs_event *ev)
{
  mount_item *it;
  DWORD len;
  size_t n;
  if (ev->caller_sid == NULL || ev->path == NULL)
    return;
  len = 8u + 4u * (DWORD)((const BYTE *)ev->caller_sid)[1];
  if (len > SECURITY_MAX_SID_SIZE)
    return;
  it = (mount_item *)sd_calloc(1, sizeof(*it));
  if (it == NULL) {
    SD_LOGE("mount", "out of memory posting an audit event");
    return;
  }
  it->m = m;
  it->kind = EV_AUDIT;
  memcpy(it->sid, ev->caller_sid, len);
  scopy(it->code, sizeof(it->code), ev->op ? ev->op : "");
  n = wcslen(ev->path);
  if (n >= SD_COUNTOF(it->path)) n = SD_COUNTOF(it->path) - 1;
  memcpy(it->path, ev->path, n * sizeof(wchar_t));
  it->path[n] = 0;
  addref(m);
  m->cb.post(m->cb.ctx, run_item, it);
}

static void vfs_on_event(void *ctx, const sd_vfs_event *ev)
{
  sd_mount *m = (sd_mount *)ctx;
  mount_item *it;
  if (ev->kind == SD_VFS_EV_AUDIT) {
    vfs_audit_post(m, ev);
    return;
  }
  if (ev->kind == SD_VFS_EV_DELETE_FAILED)
    SD_LOGW("mount", "%c: delete failed (%s)", (int)m->letter, vfs_status_code(ev->status));
  if (ev->kind != SD_VFS_EV_WRITE_FAILED && ev->kind != SD_VFS_EV_NOTICE && ev->kind != SD_VFS_EV_IDENTITY)
    return;
  it = (mount_item *)sd_calloc(1, sizeof(*it));
  if (ev->kind == SD_VFS_EV_WRITE_FAILED) {
    size_t n = ev->path ? wcslen(ev->path) : 0;
    if (n >= SD_COUNTOF(m->conn.last_write_failed)) n = SD_COUNTOF(m->conn.last_write_failed) - 1;
    sd_mutex_lock(&m->lock);
    m->conn.write_failed++;
    if (n) memcpy(m->conn.last_write_failed, ev->path, n * sizeof(wchar_t));
    m->conn.last_write_failed[n] = 0;
    sd_mutex_unlock(&m->lock);
    if (it) {
      if (n) memcpy(it->path, ev->path, n * sizeof(wchar_t));
      it->path[n] = 0;
    }
    SD_LOGW("mount", "%c: write_failed, %llu bytes lost (%s)", (int)m->letter, (unsigned long long)ev->bytes,
            vfs_status_code(ev->status));
  } else if (ev->kind == SD_VFS_EV_NOTICE) {
    SD_LOGW("mount", "%c: vfs notice %s: %s", (int)m->letter, ev->code ? ev->code : "", ev->detail ? ev->detail : "");
  }
  if (it == NULL)
    return;
  it->m = m;
  it->kind = ev->kind == SD_VFS_EV_WRITE_FAILED ? EV_WRITE_FAILED : ev->kind == SD_VFS_EV_NOTICE ? EV_NOTICE : EV_IDENTITY;
  it->bytes = ev->bytes;
  it->status = vfs_status_code(ev->status);
  scopy(it->code, sizeof(it->code), ev->code);
  scopy(it->detail, sizeof(it->detail), ev->detail);
  addref(m);
  m->cb.post(m->cb.ctx, run_item, it);
}

/* ---- teardown (control thread) ---- */

/* M3 readers: the stats, refresh and cache calls use the session and vfs outside m->lock (the backend
   may take locks of its own), so the control thread waits for them before it destroys either object.
   A reader takes its count and the pointers in one locked step; no lock is held while waiting. */
static void readers_drain(sd_mount *m)
{
  for (;;) {
    int r;
    sd_mutex_lock(&m->lock);
    r = m->readers;
    sd_mutex_unlock(&m->lock);
    if (r == 0)
      return;
    Sleep(1);
  }
}

static void finish(sd_mount *m)
{
  sd_err why;
  sd_sftp_session *s;
  if (m->finished)
    return;
  sd_mutex_lock(&m->lock);
  wipe_saves(m);
  s = m->sess;                    /* taken under the lock: stats readers see NULL from here on */
  m->sess = NULL;
  sd_mutex_unlock(&m->lock);
  readers_drain(m);
  if (s)
    m->be->session_destroy(s);
  if (m->kh) {
    m->be->kh_close(m->kh);
    m->kh = NULL;
  }
  m->finished = 1;
  sd_mutex_lock(&m->lock);
  why = m->fail.err;
  sd_mutex_unlock(&m->lock);
  /* Always notify the final state, even if it equals the current one (callers reap on it). */
  m->state = (sd_mount_state)-1;
  set_state(m, (why != SD_OK && !m->user_stop) ? SD_MOUNT_FAILED : SD_MOUNT_UNMOUNTED, why);
}

static void teardown(sd_mount *m)
{
  if (!m->stopping) {
    int failing;
    m->stopping = 1;
    sd_mutex_lock(&m->lock);
    failing = m->fail.err != SD_OK && !m->user_stop;
    sd_mutex_unlock(&m->lock);
    if (!failing)
      set_state(m, SD_MOUNT_UNMOUNTING, SD_OK);   /* a failing mount reports FAILED once, at the end */
  }
  sd_mount_cancel_prompts(m);
  if (m->wm) {
    sd_err e = m->be->webdav_mount_stop(m->wm);
    if (e != SD_OK)
      SD_LOGW("mount", "webdav_mount_stop: %s", sd_err_name(e));
    m->wm = NULL;
    sd_mutex_lock(&m->lock);
    m->wport = 0;
    sd_mutex_unlock(&m->lock);
  }
  if (m->dm) {
    sd_err e = m->be->dokan_mount_stop(m->dm);
    if (e != SD_OK)
      SD_LOGW("mount", "dokan_mount_stop: %s", sd_err_name(e));
    m->dm = NULL;
  }
  if (m->vfs) {
    sd_vfs *v;
    /* M3: the vfs leaves the mount under the lock, so a stats reader never sees a freed vfs. A forced
       stop gives the write-behind drain no time: what is queued is reported as write_failed (02 §4.4). */
    sd_mutex_lock(&m->lock);
    v = m->vfs;
    m->vfs = NULL;
    sd_mutex_unlock(&m->lock);
    readers_drain(m);
    m->be->vfs_quiesce(v, m->force_stop ? 0 : 10000);
    m->be->vfs_unmount(v);
  }
  if (m->sess && !m->session_closing) {
    m->session_closing = 1;
    if (m->be->session_close(m->sess) != SD_OK) {
      SD_LOGW("mount", "session close refused; destroying");
      finish(m);
    }
    return;   /* finish() runs on EV_CLOSED */
  }
  if (m->sess == NULL)
    finish(m);
}

/* ---- control-thread event handling ---- */

/* Backend selection (02 §10.1). Only read-only queries here: WebClient is started after WebDAV was
   chosen (TM-R21). Returns DOKANY / WEBDAV, or -1 with the failure recorded. */
static int choose_backend(sd_mount *m)
{
  sd_dokan_probe_info pi;
  sd_dokan_avail av = SD_DOKAN_NOT_INSTALLED;
  sd_webdav_client_info ci;
  sd_webdav_client_state cs;
  if (m->backend_req != SD_MOUNT_BACKEND_WEBDAV) {
    memset(&pi, 0, sizeof(pi));
    av = m->be->dokan_probe(NULL, &pi);
    if (av == SD_DOKAN_OK)
      return SD_MOUNT_BACKEND_DOKANY;
    SD_LOGW("mount", "Dokany unavailable (%d, load error %u)", (int)av, (unsigned)pi.load_error);
    if (m->backend_req == SD_MOUNT_BACKEND_DOKANY) {
      record_failure(m, SD_E_UNSUPPORTED, "backend_unavailable", "Dokany 2.1+ is not installed or not usable");
      return -1;
    }
  }
  if (m->be->webdav_query_client == NULL || m->be->webdav_mount_start == NULL) {
    record_failure(m, SD_E_UNSUPPORTED, "backend_unavailable", "Dokany 2.1+ is not installed or not usable");
    return -1;
  }
  memset(&ci, 0, sizeof(ci));
  cs = m->be->webdav_query_client(&ci);
  if (cs == SD_WD_CLIENT_MISSING) {
    record_failure(m, SD_E_UNSUPPORTED, "backend_unavailable",
                   m->backend_req == SD_MOUNT_BACKEND_WEBDAV ? "WebClient service not installed"
                                                             : "no Dokany and no WebClient service");
    return -1;
  }
  if (cs == SD_WD_CLIENT_DISABLED) {
    record_failure(m, SD_E_UNSUPPORTED, "webclient_disabled", "WebClient service disabled");
    return -1;
  }
  return SD_MOUNT_BACKEND_WEBDAV;
}

/* Authentication succeeded: keep the secrets the user asked to save (4.2). */
static void commit_saves(sd_mount *m)
{
  uint32_t i, n;
  struct { int kind; char target[TARGET_CAP]; char *value; size_t len; } local[MAX_SAVES];
  sd_mutex_lock(&m->lock);
  n = m->nsaves;
  memcpy(local, m->saves, sizeof(local[0]) * n);
  m->nsaves = 0;
  sd_mutex_unlock(&m->lock);
  for (i = 0; i < n; i++) {
    if (m->cb.secret_put && local[i].value)
      m->cb.secret_put(m->cb.ctx, m, local[i].kind, local[i].target, local[i].value);
    if (local[i].value) sd_secure_free(local[i].value, local[i].len + 1);
  }
}

/* 3.8: HTTP Basic and SOCKS5 username/password send the proxy password in clear text to the proxy. */
static void warn_proxy_cleartext(sd_mount *m)
{
  uint32_t i;
  for (i = 0; i < m->nhops; i++) {
    owned_hop *h = &m->hops[i];
    char detail[300];
    int clear = (h->pkind == SD_PROXY_HTTP && (h->pauth & SD_PROXY_AUTH_BASIC) && h->puser && h->puser[0]) ||
                (h->pkind == SD_PROXY_SOCKS5 && h->puser && h->puser[0]);
    if (!clear || (m->warned_proxy & (1u << i)))
      continue;
    m->warned_proxy |= 1u << i;
    scopy(detail, sizeof(detail), h->phost8);
    {
      char num[8];
      uint32_t v = h->pport, k = 0;
      char tmp[8];
      size_t tn = 0, dl = strlen(detail);
      do { tmp[tn++] = (char)('0' + v % 10u); v /= 10u; } while (v);
      while (tn) num[k++] = tmp[--tn];
      num[k] = 0;
      if (dl + k + 2 < sizeof(detail)) {
        detail[dl] = ':';
        memcpy(detail + dl + 1, num, k + 1);
      }
    }
    if (m->cb.on_warning)
      m->cb.on_warning(m->cb.ctx, m, "proxy_cleartext", i, detail);
  }
}

/* M3 profile.test: realpath of the remote path and the negotiated summary, read from the READY session.
   Control thread; a failure is recorded like any mount failure (the caller then tears the mount down). */
static void do_probe(sd_mount *m)
{
  sd_mount_probe p;
  sd_err e;
  memset(&p, 0, sizeof(p));
  if (m->be->session_probe == NULL) {
    record_failure(m, SD_E_UNSUPPORTED, NULL, "profile test is not available in this build");
    return;
  }
  e = m->be->session_probe(m->sess, m->remote, 15000, &p);
  if (e != SD_OK) {
    record_failure(m, e, NULL, "profile test: realpath failed");
    return;
  }
  sd_mutex_lock(&m->lock);
  p.legacy = m->legacy_seen;
  m->probe = p;
  m->probe_ok = 1;
  sd_mutex_unlock(&m->lock);
}

/* TM-R19 (02 §7.4, 03 §7.5): the answer to the token-only question. Accept is SD_MA_HOSTKEY_TRUST or
   SD_MA_HOSTKEY_ONCE (the host's "accept" and "once"); anything else refuses. Returns 0 when prompt_id is not
   the open question. Any thread. */
static int take_consent(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind)
{
  int found = 0;
  sd_mutex_lock(&m->lock);
  if (m->consent_pending && m->consent_id == prompt_id) {
    m->consent_pending = 0;
    m->consent_id = 0;
    found = 1;
  }
  sd_mutex_unlock(&m->lock);
  if (found)
    post_item(m, EV_TOKEN_ONLY, (kind == SD_MA_HOSTKEY_TRUST || kind == SD_MA_HOSTKEY_ONCE) ? SD_OK : SD_E_ACCESS_DENIED,
              0, NULL);
  return found;
}

/* TM-R19: starts the WebDAV export of the mount's vfs with the mount's token-only settings. Control thread.
   On failure m->wm is NULL and the caller records the failure. */
static sd_err webdav_start(sd_mount *m)
{
  sd_webdav_mount_cfg wc;
  sd_err e;
  memset(&wc, 0, sizeof(wc));
  wc.struct_size = sizeof(wc);
  wc.letter = m->letter;
  wc.read_only = m->read_only ? TRUE : FALSE;
  wc.label = m->label ? m->label : m->host;
  wc.owner_sid = m->owner_sid;
  wc.global = m->global_mount ? TRUE : FALSE;     /* TM-R19: token-only is always refused for global mounts */
  wc.token_only = m->token_only ? TRUE : FALSE;
  wc.token_only_confirmed = m->token_only_confirmed ? TRUE : FALSE;
  e = m->be->webdav_mount_start(m->vfs, &wc, &m->wm);
  if (e != SD_OK) {
    m->wm = NULL;
    return e;
  }
  if (m->be->webdav_port) {
    sd_mutex_lock(&m->lock);
    m->wport = m->be->webdav_port(m->wm);
    sd_mutex_unlock(&m->lock);
  }
  return SD_OK;
}

/* TM-R19 (03 §7.5): asks the user whether token-only WebDAV may be used for this enable. The mount keeps its vfs
   and waits; the answer comes back through sd_mount_answer (take_consent). Control thread. */
static void ask_token_only(sd_mount *m)
{
  sd_mount_prompt *mp;
  uint32_t id;
  sd_mutex_lock(&m->lock);
  id = ++m->next_prompt_id;
  m->consent_pending = 1;
  m->consent_id = id;
  sd_mutex_unlock(&m->lock);
  mp = (sd_mount_prompt *)sd_calloc(1, sizeof(*mp));
  if (mp == NULL || m->cb.on_prompt == NULL) {
    sd_free(mp);
    (void)take_consent(m, id, SD_MA_REJECT);        /* nobody can ask: refused */
    return;
  }
  mp->id = id;
  mp->kind = SD_MP_WEBDAV_TOKEN_ONLY;
  post_item(m, EV_TOKEN_ASK, SD_OK, id, mp);
}

static void on_ready(sd_mount *m)
{
  sd_vfs_options vo;
  sd_vfs_status vs;
  int use;
  sd_err e;
  if (m->stopping)
    return;
  if (m->consent_pending)
    return;                         /* TM-R19: parked until the user answers the token-only question */
  commit_saves(m);
  warn_proxy_cleartext(m);
  if (m->vfs) {
    /* reconnected (generation > 1): the vfs and the backend stay; the vfs re-syncs by itself */
    set_state(m, SD_MOUNT_MOUNTED, SD_OK);
    if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
    return;
  }
  if (m->test_only) {
    do_probe(m);
    teardown(m);                    /* no vfs, no backend: the session closes and the mount ends */
    return;
  }
  use = choose_backend(m);
  if (use < 0) {
    teardown(m);
    return;
  }
  m->used = (sd_mount_backend_kind)use;
  if (use == SD_MOUNT_BACKEND_WEBDAV) {
    sd_webdav_client_info ci;
    memset(&ci, 0, sizeof(ci));
    e = m->be->webdav_ensure_client ? m->be->webdav_ensure_client(10000, &ci) : SD_E_UNSUPPORTED;
    if (e != SD_OK) {
      SD_LOGW("mount", "WebClient not running (%s, state %d, error %u)", sd_err_name(e), (int)ci.state,
              (unsigned)ci.error);
      record_failure(m, SD_E_UNSUPPORTED, ci.state == SD_WD_CLIENT_DISABLED ? "webclient_disabled" : "backend_unavailable",
                     ci.needs_admin ? "WebClient service cannot be started without an administrator"
                                    : "WebClient service did not start");
      teardown(m);
      return;
    }
  }
  memset(&vo, 0, sizeof(vo));
  vo.struct_size = sizeof(vo);
  vo.remote_root = m->remote;
  vo.read_only = m->read_only ? TRUE : FALSE;
  vo.symlinks = m->symlinks;
  vo.write_mode = (sd_vfs_write_mode)m->write_mode;
  vo.block_shell_active = m->tune.shell_active_show ? FALSE : TRUE;   /* D41: untrusted blocks, mount.shell_active_files */
  /* below the Dokany 30 s timeout / the redirector's 60 s SendReceiveTimeoutInSec (02 §5.7) */
  vo.request_timeout_ms = use == SD_MOUNT_BACKEND_WEBDAV ? 50000 : 25000;
  vo.volume_label = m->label ? m->label : m->host;
  vo.owner_sid = m->owner_sid;
  vo.global_mount = m->global_mount ? TRUE : FALSE;
  vo.access_sids = m->acc_sids;  vo.n_access = m->n_acc;     /* M5: checked per request in sd_vfs */
  vo.write_sids = m->wrt_sids;   vo.n_write = m->n_wrt;
  vo.offline_wait_ms = m->offline_wait;
  vo.reconnect_grace_ms = m->grace;
  vo.attr_ttl_ms = m->tune.attr_ttl_ms;
  vo.dir_ttl_ms = m->tune.dir_ttl_ms;
  vo.neg_ttl_ms = m->tune.neg_ttl_ms;
  vo.open_revalidate_ms = m->tune.open_revalidate_ms;
  vo.max_readahead = m->tune.max_readahead;
  vo.umask = m->tune.umask;
  vo.hide_dotfiles = m->tune.hide_dotfiles ? TRUE : FALSE;
  vo.map_readonly = m->tune.map_readonly ? TRUE : FALSE;
  vo.show_special = m->tune.show_special ? TRUE : FALSE;
  vo.case_sensitive_view = m->tune.case_sensitive ? TRUE : FALSE;
  vo.remote_case = m->tune.remote_case;
  vo.fsync_on_flush = m->tune.fsync_on_flush ? TRUE : FALSE;
  vo.volume_fs_name = m->tune.fs_name[0] ? m->tune.fs_name : NULL;
  vo.disk_cache_mb = m->disk_dir ? m->disk_mb : 0;
  vo.disk_cache_dir = m->disk_dir;
  {
    char fp[64];
    sd_mutex_lock(&m->lock);
    scopy(fp, sizeof(fp), m->hostkey_fp);
    sd_mutex_unlock(&m->lock);
    memset(&m->known_id, 0, sizeof(m->known_id));
    if (fp[0] && m->cb.lookup_identity && m->cb.lookup_identity(m->cb.ctx, m, fp, &m->known_id) &&
        m->known_id.uid_known && m->known_id.definitive) {
      m->known_id.groups = NULL;
      m->known_id.ngroups = 0;
      vo.known_identity = &m->known_id;
    }
  }
  vs = m->be->vfs_mount(m->sess, &vo, vfs_on_event, m, &m->vfs);
  if (vs != SD_VFS_OK) {
    m->vfs = NULL;
    record_failure(m, vs == SD_VFS_E_UNSUPPORTED ? SD_E_UNSUPPORTED : SD_E_FAILURE, NULL, "vfs mount failed");
    teardown(m);
    return;
  }
  if (use == SD_MOUNT_BACKEND_WEBDAV) {
    if (m->token_only && !m->token_only_confirmed && !m->global_mount) {
      ask_token_only(m);            /* the host asked for token-only: the user confirms this enable first */
      return;
    }
    e = webdav_start(m);
    if (e == SD_WD_E_AUTH_UNAVAILABLE && !m->global_mount && !m->token_only) {
      /* TM-R19 (02 §7.4): SSPI is unavailable, so the redirector cannot authenticate; ask before token-only */
      ask_token_only(m);
      return;
    }
    if (e != SD_OK) {
      record_failure(m, e, e == SD_E_EXISTS ? "target_in_use" : NULL, "webdav mount failed");
      teardown(m);
      return;
    }
  } else {
    sd_dokan_mount_cfg dc;
    wchar_t mp[4];
    mp[0] = m->letter;
    mp[1] = L':';
    mp[2] = L'\\';
    mp[3] = 0;
    memset(&dc, 0, sizeof(dc));
    dc.struct_size = sizeof(dc);
    dc.mount_point = mp;
    /* M5: a service mount is global (no DOKAN_OPTION_CURRENT_SESSION, D35 and 03 §1.3) */
    dc.current_session = m->global_mount ? FALSE : TRUE;
    dc.global_mount = m->global_mount ? TRUE : FALSE;
    dc.volume_sd = m->volume_sd;
    dc.volume_sd_len = m->volume_sd_len;
    dc.read_only = m->read_only ? TRUE : FALSE;
    e = m->be->dokan_mount_start(m->vfs, &dc, dokan_on_unmounted, m, &m->dm);
    if (e != SD_OK) {
      m->dm = NULL;
      record_failure(m, e, e == SD_E_EXISTS ? "target_in_use" : NULL, "dokan mount failed");
      teardown(m);
      return;
    }
  }
  set_state(m, SD_MOUNT_MOUNTED, SD_OK);
}

static int try_autofill(sd_mount *m, const sd_mount_prompt *mp);
static int take_prompt_by_id(sd_mount *m, uint32_t id, sd_prompt **p, sd_mount_prompt_kind *kind, pending_prompt *copy);
static sd_err apply_on(const sd_mount_backend *be, sd_known_hosts *kh, sd_kh_store_kind target,
                       const sd_mount_announcement *a, int add_only);

static void run_item(void *arg)
{
  mount_item *it = (mount_item *)arg;
  sd_mount *m = it->m;
  if (!m->destroyed) {
    switch (it->kind) {
    case EV_READY:
      on_ready(m);
      break;
    case EV_FAILED:
      if (m->vfs && !m->stopping) {
        /* lost after READY and the loop gave up (or a permanent error): keep the letter offline,
           cached reads go on, only the user unmounts (03 §1.11) */
        set_state(m, SD_MOUNT_OFFLINE, it->err);
        if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
      } else {
        record_failure(m, it->err, NULL, "session failed");
        teardown(m);                               /* FAILED is reported by finish() */
      }
      break;
    case EV_DISCONNECTED:
      if (m->vfs && !m->stopping)
        set_state(m, SD_MOUNT_OFFLINE, it->err);
      if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
      break;
    case EV_AUTH_REQUIRED:
      if (m->vfs && !m->stopping)
        set_state(m, SD_MOUNT_AUTH_REQUIRED, it->err);
      if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
      break;
    case EV_CONN:
      if (m->vfs && !m->stopping && m->state == SD_MOUNT_AUTH_REQUIRED)
        set_state(m, SD_MOUNT_OFFLINE, it->err);   /* the prompt was answered: the attempt goes on */
      if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
      break;
    case EV_WRITE_FAILED:
      if (m->cb.on_write_failed)
        m->cb.on_write_failed(m->cb.ctx, m, it->path, it->bytes, it->status);
      if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
      break;
    case EV_NOTICE:
      if (m->cb.on_notice)
        m->cb.on_notice(m->cb.ctx, m, it->code, it->detail);
      break;
    case EV_AUDIT:
      if (m->cb.on_audit)
        m->cb.on_audit(m->cb.ctx, m, (PSID)it->sid, it->code, it->path);
      break;
    case EV_IDENTITY:
      if (m->vfs && m->be->vfs_get_identity && m->cb.store_identity) {
        sd_vfs_identity id;
        char fp[64];
        memset(&id, 0, sizeof(id));
        m->be->vfs_get_identity(m->vfs, &id);
        sd_mutex_lock(&m->lock);
        scopy(fp, sizeof(fp), m->hostkey_fp);
        sd_mutex_unlock(&m->lock);
        if (fp[0] && id.uid_known && id.definitive)
          m->cb.store_identity(m->cb.ctx, m, fp, &id);
      }
      break;
    case EV_CLOSED:
      if (m->sess) {
        m->session_closing = 1;
        if (!m->stopping) {
          record_failure(m, SD_E_DISCONNECTED, NULL, "session closed");
          teardown(m);
        }
        finish(m);
      }
      break;
    case EV_PROMPT:
      if (try_autofill(m, it->prompt))
        break;
      if (it->pool_member) {
        /* secondary pool connections never prompt (2.5, D18) */
        uint32_t pid = it->prompt->id;
        sd_prompt *p = NULL;
        sd_mount_prompt_kind pk = SD_MP_PASSWORD;
        if (take_prompt_by_id(m, pid, &p, &pk, NULL)) {
          if (pk == SD_MP_HOSTKEY) m->be->prompt_answer_hostkey(p, SD_HK_REJECT);
          else m->be->prompt_cancel(p);
        }
        if (!m->warned_pool) {
          m->warned_pool = 1;
          SD_LOGI("mount", "%c: pool member needs interactive auth; pool limited", (int)m->letter);
          if (m->cb.on_warning) m->cb.on_warning(m->cb.ctx, m, "pool_limited", 0, "interactive_auth");
        }
        break;
      }
      if (m->state == SD_MOUNT_CONNECTING && it->prompt->kind != SD_MP_HOSTKEY)
        set_state(m, SD_MOUNT_AUTHENTICATING, SD_OK);
      if (m->cb.on_prompt)
        m->cb.on_prompt(m->cb.ctx, m, it->prompt);
      break;
    case EV_WARNING:
      if (m->cb.on_warning)
        m->cb.on_warning(m->cb.ctx, m, it->code, it->hop, it->detail);
      break;
    case EV_ANNOUNCED:
      if (it->ann) {
        sd_mount_announcement *a = it->ann;
        if (a->mode == SD_HKU_YES && m->kh && m->be->kh_apply_hostkeys) {
          sd_err ae = apply_on(m->be, m->kh, SD_KH_STORE_USER, a, 1);   /* removals always need the review (5.6) */
          SD_LOGI("mount", "%c: UpdateHostKeys: %u new key(s) for %s saved (%s)", (int)m->letter,
                  (unsigned)a->add_count, a->lookup_name, sd_err_name(ae));
          if (m->cb.on_hostkeys_announced) m->cb.on_hostkeys_announced(m->cb.ctx, m, a, 1, ae);
          if (a->remove_count && m->cb.on_hostkeys_announced) {
            a->add_count = 0;                          /* what is left to review: the removals */
            m->cb.on_hostkeys_announced(m->cb.ctx, m, a, 0, SD_OK);
          }
        } else if (a->mode != SD_HKU_NO) {
          if (m->cb.on_hostkeys_announced) m->cb.on_hostkeys_announced(m->cb.ctx, m, a, 0, SD_OK);
        } else {
          SD_LOGI("mount", "%c: UpdateHostKeys announcement for %s ignored (update_host_keys = no)",
                  (int)m->letter, a->lookup_name);
        }
      }
      break;
    case EV_TOKEN_ASK:
      /* TM-R19: a closed or stopping mount refuses at once, so that the question is never left open */
      if (m->stopping || m->cb.on_prompt == NULL)
        (void)take_consent(m, it->prompt_id, SD_MA_REJECT);
      else
        m->cb.on_prompt(m->cb.ctx, m, it->prompt);
      break;
    case EV_TOKEN_ONLY:
      if (m->stopping || m->vfs == NULL)
        break;
      if (it->err == SD_OK) {
        sd_err we;
        /* accepted for this enable only (03 §7.5): never stored, never switched on again by itself */
        m->token_only = 1;
        m->token_only_confirmed = 1;
        we = webdav_start(m);
        if (we == SD_OK) {
          set_state(m, SD_MOUNT_MOUNTED, SD_OK);
          if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
        } else {
          record_failure(m, we, we == SD_E_EXISTS ? "target_in_use" : NULL, "webdav mount failed");
          teardown(m);
        }
      } else {
        record_failure(m, SD_E_ACCESS_DENIED, "token_only_refused", "token-only WebDAV was not confirmed");
        teardown(m);
      }
      break;
    case EV_HK_DONE:
      if (it->err != SD_OK && !m->finished)
        record_failure(m, it->err, NULL, "hostkey fetch failed");
      hk_finish(m);
      break;
    case EV_PROMPT_CLOSED:
      if (m->cb.on_prompt_closed)
        m->cb.on_prompt_closed(m->cb.ctx, m, it->prompt_id);
      break;
    case EV_DOKAN_UNMOUNTED:
      if (!m->stopping) {
        m->user_stop = 1;                    /* removed from outside (dokanctl, Explorer) */
        teardown(m);
      }
      break;
    }
  }
  sd_free(it->prompt);
  sd_free(it->ann);
  sd_free(it);
  release(m);
}

/* ---- callbacks from I/O threads ---- */

/* Password-shaped keyboard-interactive round (4.2): one prompt, no echo, text naming a password in
   one of the PAM languages we know. OTP prompts never match. */
static int password_shaped(const sd_auth_prompt_info *a)
{
  static const char *const words[] = { "password", "passwort", "contrase\xc3\xb1" "a", "mot de passe", "senha",
                                       "kennwort", "parola d'ordine" };
  char low[512];
  size_t i, n;
  if (a->item_count != 1 || a->items[0].echo || a->items[0].text == NULL)
    return 0;
  n = strlen(a->items[0].text);
  if (n >= sizeof(low)) n = sizeof(low) - 1;
  for (i = 0; i < n; i++) {
    char c = a->items[0].text[i];
    low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
  }
  low[n] = 0;
  for (i = 0; i < SD_COUNTOF(words); i++)
    if (strstr(low, words[i])) return 1;
  return 0;
}

static void u16dec(char *out, size_t cap, uint32_t v)
{
  char tmp[12];
  size_t n = 0, o = 0;
  do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
  while (n && o + 1 < cap) out[o++] = tmp[--n];
  out[o] = 0;
}

/* raw sd_secret targets (sd_secret.h): "user@host:port", "<scheme>:user@host:port" */
static void make_userhost_target(char *out, size_t cap, const char *scheme, const char *user, const char *host,
                                 uint16_t port)
{
  char num[12];
  int v6 = strchr(host, ':') != NULL;
  out[0] = 0;
  u16dec(num, sizeof(num), port ? port : 22);
  if (user == NULL || user[0] == 0 || host[0] == 0)
    return;
  if (scheme) { strcat_s(out, cap, scheme); strcat_s(out, cap, ":"); }
  if (strlen(out) + strlen(user) + strlen(host) + strlen(num) + 5 >= cap) { out[0] = 0; return; }
  strcat_s(out, cap, user);
  strcat_s(out, cap, "@");
  if (v6) strcat_s(out, cap, "[");
  strcat_s(out, cap, host);
  if (v6) strcat_s(out, cap, "]");
  strcat_s(out, cap, ":");
  strcat_s(out, cap, num);
}

static void ssh_on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *auth, const sd_hostkey_prompt_info *hk)
{
  sd_mount *m = (sd_mount *)ctx;
  sd_mount_prompt *mp;
  mount_item *it;
  uint32_t i, id, hop;
  sd_mount_prompt_kind kind;
  int skind = -1, savable = 0, pool = 0;
  char target[TARGET_CAP];
  owned_hop *oh;
  target[0] = 0;
  if (hk && m->hk_fetch) {
    /* M5: first contact (or an accept-once case): the presented key is taken and nothing is stored; the agent
       asks the user (5.2). The connection goes on, and the fetch then reports verified = 0. */
    sd_mutex_lock(&m->lock);
    m->hk_presented = 0;
    memset(&m->hk_key, 0, sizeof(m->hk_key));
    if (hk->blob && hk->blob_len && hk->blob_len <= sizeof(m->hk_key.blob)) {
      scopy(m->hk_key.type, sizeof(m->hk_key.type), hk->key_type);
      scopy(m->hk_key.fp_sha256, sizeof(m->hk_key.fp_sha256), hk->fp_sha256);
      m->hk_key.len = hk->blob_len;
      memcpy(m->hk_key.blob, hk->blob, hk->blob_len);
      m->hk_presented = 1;
    }
    sd_mutex_unlock(&m->lock);
    m->be->prompt_answer_hostkey(p, SD_HK_ACCEPT_ONCE);
    return;
  }
  if (hk) {
    kind = SD_MP_HOSTKEY;
  } else if (auth && auth->kind == SD_PROMPT_PASSWORD) {
    kind = SD_MP_PASSWORD;
  } else if (auth && auth->kind == SD_PROMPT_KEY_PASSPHRASE) {
    kind = SD_MP_PASSPHRASE;
  } else if (auth && auth->kind == SD_PROMPT_KBDINT) {
    kind = SD_MP_KBDINT;
  } else if (auth && auth->kind == SD_PROMPT_NEW_PASSWORD) {
    kind = SD_MP_PASSWORD_CHANGE;
  } else if (auth && auth->kind == SD_PROMPT_LEGACY_ACK) {
    kind = SD_MP_LEGACY_ACK;
  } else if (auth && auth->kind == SD_PROMPT_PROXY_PASSWORD) {
    kind = SD_MP_PROXY_PASSWORD;
  } else {
    m->be->prompt_cancel(p);
    return;
  }
  hop = hk ? hk->hop_index : auth->hop_index;
  if (hop >= m->nhops) hop = m->nhops ? m->nhops - 1 : 0;
  oh = &m->hops[hop];
  pool = auth && auth->is_pool_member;
  if (pool && kind != SD_MP_PASSWORD && kind != SD_MP_PASSPHRASE && kind != SD_MP_KBDINT && kind != SD_MP_PROXY_PASSWORD) {
    m->be->prompt_cancel(p);                /* pool members never show UI (01 §10.9) */
    return;
  }
  /* which saved secret could answer it (4.2) */
  if (kind == SD_MP_PASSWORD || (kind == SD_MP_KBDINT && password_shaped(auth))) {
    skind = SD_MOUNT_SECRET_PASSWORD;
    make_userhost_target(target, sizeof(target), NULL, auth->user && auth->user[0] ? auth->user : oh->user,
                         oh->host8, oh->port);
  } else if (kind == SD_MP_PASSPHRASE && auth->key_fingerprint && strncmp(auth->key_fingerprint, "SHA256:", 7) == 0) {
    skind = SD_MOUNT_SECRET_PASSPHRASE;
    scopy(target, sizeof(target), auth->key_fingerprint);
  } else if (kind == SD_MP_PROXY_PASSWORD) {
    const char *scheme = oh->pkind == SD_PROXY_SOCKS5 ? "socks5" : "http";
    char ph[256];
    scopy(ph, sizeof(ph), auth->proxy_host && auth->proxy_host[0] ? auth->proxy_host : oh->phost8);
    skind = SD_MOUNT_SECRET_PROXY;
    make_userhost_target(target, sizeof(target), scheme, auth->user && auth->user[0] ? auth->user : oh->puser,
                         ph, auth->proxy_port ? auth->proxy_port : oh->pport);
  }
  if (target[0] == 0)
    skind = -1;
  savable = skind >= 0 && !oh->no_save;
  mp = (sd_mount_prompt *)sd_calloc(1, sizeof(*mp));
  it = (mount_item *)sd_calloc(1, sizeof(*it));
  sd_mutex_lock(&m->lock);
  if (mp == NULL || it == NULL || m->nprompts >= MAX_PROMPTS || m->stopping) {
    sd_mutex_unlock(&m->lock);
    sd_free(mp);
    sd_free(it);
    m->be->prompt_cancel(p);
    return;
  }
  id = ++m->next_prompt_id;
  memset(&m->prompts[m->nprompts], 0, sizeof(m->prompts[0]));
  m->prompts[m->nprompts].id = id;
  m->prompts[m->nprompts].p = p;
  m->prompts[m->nprompts].kind = kind;
  m->prompts[m->nprompts].hop = hop;
  m->prompts[m->nprompts].skind = skind;
  m->prompts[m->nprompts].savable = savable;
  scopy(m->prompts[m->nprompts].target, TARGET_CAP, target);
  m->nprompts++;
  sd_mutex_unlock(&m->lock);
  mp->id = id;
  mp->kind = kind;
  mp->hop_count = m->nhops ? m->nhops : 1;
  mp->can_save = savable;
  if (hk) {
    mp->hop_index = hk->hop_index;
    scopy(mp->host, sizeof(mp->host), hk->host);
    mp->port = hk->port;
    scopy(mp->key_type, sizeof(mp->key_type), hk->key_type);
    mp->key_bits = hk->key_bits;
    scopy(mp->fp_sha256, sizeof(mp->fp_sha256), hk->fp_sha256);
    scopy(mp->lookup_name, sizeof(mp->lookup_name), hk->lookup_name);
    scopy(mp->via_host, sizeof(mp->via_host), hk->via_host);
    mp->is_reconnect = hk->is_reconnect;
  } else {
    mp->hop_index = auth->hop_index;
    scopy(mp->host, sizeof(mp->host), auth->host);
    mp->port = oh->port ? oh->port : m->port;
    scopy(mp->user, sizeof(mp->user), auth->user);
    mp->round = auth->round;
    mp->hostkey_just_accepted = auth->hostkey_just_accepted;
    mp->is_reconnect = auth->is_reconnect;
    scopy(mp->key_path, sizeof(mp->key_path), auth->key_path);
    scopy(mp->key_fp, sizeof(mp->key_fp), auth->key_fingerprint);
    scopy(mp->name, sizeof(mp->name), auth->name);
    scopy(mp->instruction, sizeof(mp->instruction), auth->instruction);
    mp->item_count = SD_MIN(auth->item_count, SD_MOUNT_PROMPT_MAX_ITEMS);
    for (i = 0; i < mp->item_count; i++) {
      scopy(mp->items[i].text, sizeof(mp->items[i].text), auth->items[i].text);
      mp->items[i].echo = auth->items[i].echo;
    }
    if ((kind == SD_MP_PASSWORD || kind == SD_MP_PROXY_PASSWORD) && mp->item_count == 0) {
      mp->item_count = 1;
      mp->items[0].echo = 0;
    }
    if (kind == SD_MP_PROXY_PASSWORD) {
      scopy(mp->proxy_host, sizeof(mp->proxy_host), auth->proxy_host && auth->proxy_host[0] ? auth->proxy_host : oh->phost8);
      mp->proxy_port = auth->proxy_port ? auth->proxy_port : oh->pport;
      if (mp->user[0] == 0) scopy(mp->user, sizeof(mp->user), oh->puser);
    }
    if (kind == SD_MP_LEGACY_ACK)
      scopy(mp->legacy_names, sizeof(mp->legacy_names), auth->legacy_names);
    if (hop >= 1 && hop - 1 < m->nhops)
      scopy(mp->via_host, sizeof(mp->via_host), m->hops[hop - 1].host8);
  }
  if (mp->port == 0)
    mp->port = m->port;
  it->m = m;
  it->kind = EV_PROMPT;
  it->prompt_id = id;
  it->prompt = mp;
  it->pool_member = pool;
  addref(m);
  m->cb.post(m->cb.ctx, run_item, it);
}

/* Control thread. Answers a prompt from the host's secret store when the rules allow it (see the
   header): returns 1 when the prompt was answered (or vanished meanwhile). */
static int try_autofill(sd_mount *m, const sd_mount_prompt *mp)
{
  pending_prompt pp;
  sd_prompt *p = NULL;
  sd_mount_prompt_kind pk;
  char *buf;
  const char *resp[1];
  int found = 0;
  uint32_t i, bit;
  sd_err e;
  if (m->cb.secret_get == NULL)
    return 0;
  memset(&pp, 0, sizeof(pp));
  sd_mutex_lock(&m->lock);
  for (i = 0; i < m->nprompts; i++)
    if (m->prompts[i].id == mp->id) { pp = m->prompts[i]; found = 1; break; }
  sd_mutex_unlock(&m->lock);
  if (!found || pp.skind < 0 || pp.target[0] == 0)
    return 0;
  bit = pp.hop < 32 ? 1u << pp.hop : 0;
  if (pp.skind != SD_MOUNT_SECRET_PASSPHRASE) {
    uint32_t ja;
    if (mp->hostkey_just_accepted)
      return 0;                                  /* TM-R05 */
    sd_mutex_lock(&m->lock);
    ja = m->ja_from;
    sd_mutex_unlock(&m->lock);
    /* a password goes to hop `hop`; a proxy password of leg `hop` travels through hop - 1 */
    if (ja != NO_HOP) {
      if (pp.skind == SD_MOUNT_SECRET_PASSWORD && pp.hop >= ja) return 0;
      if (pp.skind == SD_MOUNT_SECRET_PROXY && pp.hop >= 1 && pp.hop - 1 >= ja) return 0;
    }
  }
  if ((m->autofilled[pp.skind] & bit) && mp->round > 0)
    return 0;                                    /* the stored secret was rejected: ask the user */
  buf = (char *)sd_alloc(SECRET_CAP);
  if (buf == NULL)
    return 0;
  buf[0] = 0;
  if (!m->cb.secret_get(m->cb.ctx, m, pp.skind, pp.target, buf, SECRET_CAP) || buf[0] == 0) {
    sd_secure_free(buf, SECRET_CAP);
    return 0;
  }
  buf[SECRET_CAP - 1] = 0;
  if (!take_prompt_by_id(m, mp->id, &p, &pk, NULL)) {
    sd_secure_free(buf, SECRET_CAP);
    return 1;                                    /* withdrawn meanwhile */
  }
  resp[0] = buf;
  e = m->be->prompt_answer_ex ? m->be->prompt_answer_ex(p, 1, resp, SD_ANSWER_FROM_STORE)
                              : m->be->prompt_answer(p, 1, resp);
  sd_secure_free(buf, SECRET_CAP);
  m->autofilled[pp.skind] |= bit;
  SD_LOGI("mount", "%c: %s prompt of hop %u answered from the saved secrets (%s)", (int)m->letter,
          sd_mount_prompt_kind_name(pk), (unsigned)pp.hop, sd_err_name(e));
  return 1;
}

static int take_prompt_by_id(sd_mount *m, uint32_t id, sd_prompt **p, sd_mount_prompt_kind *kind, pending_prompt *copy)
{
  uint32_t i;
  int found = 0;
  sd_mutex_lock(&m->lock);
  for (i = 0; i < m->nprompts; i++) {
    if (m->prompts[i].id == id) {
      *p = m->prompts[i].p;
      if (kind) *kind = m->prompts[i].kind;
      if (copy) *copy = m->prompts[i];
      m->prompts[i] = m->prompts[m->nprompts - 1];
      m->nprompts--;
      found = 1;
      break;
    }
  }
  sd_mutex_unlock(&m->lock);
  return found;
}

static int take_prompt_by_ptr(sd_mount *m, sd_prompt *p, uint32_t *id)
{
  uint32_t i;
  int found = 0;
  sd_mutex_lock(&m->lock);
  for (i = 0; i < m->nprompts; i++) {
    if (m->prompts[i].p == p) {
      *id = m->prompts[i].id;
      m->prompts[i] = m->prompts[m->nprompts - 1];
      m->nprompts--;
      found = 1;
      break;
    }
  }
  sd_mutex_unlock(&m->lock);
  return found;
}

static void ssh_on_prompt_withdrawn(void *ctx, sd_prompt *p)
{
  sd_mount *m = (sd_mount *)ctx;
  uint32_t id;
  if (take_prompt_by_ptr(m, p, &id))
    post_item(m, EV_PROMPT_CLOSED, SD_OK, id, NULL);
}

static void ssh_on_banner(void *ctx, uint32_t hop, const char *utf8)
{
  SD_UNUSED(ctx);
  SD_LOGD("mount", "banner from hop %u: %s", hop, utf8);
}

/* 7.6: outdated algorithms by name (the legacy_mask of 01 only says that there are some). */
static int legacy_name(const char *a)
{
  static const char *const exact[] = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
    "ssh-rsa", "ssh-dss", "ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc",
    "aes256-cbc", "rijndael-cbc@lysator.liu.se", "des-cbc",
    "hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-ripemd160", "hmac-ripemd160@openssh.com",
    "hmac-ripemd160-etm@openssh.com"
  };
  size_t i;
  if (a == NULL || a[0] == 0)
    return 0;
  for (i = 0; i < SD_COUNTOF(exact); i++)
    if (strcmp(a, exact[i]) == 0) return 1;
  return 0;
}

static int cmp_cstr(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }

static void post_warning(sd_mount *m, const char *code, uint32_t hop, const char *detail)
{
  mount_item *it = (mount_item *)sd_calloc(1, sizeof(*it));
  if (it == NULL)
    return;
  it->m = m;
  it->kind = EV_WARNING;
  it->hop = hop;
  scopy(it->code, sizeof(it->code), code);
  scopy(it->detail, sizeof(it->detail), detail);
  addref(m);
  m->cb.post(m->cb.ctx, run_item, it);
}

static void ssh_on_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  sd_mount *m = (sd_mount *)ctx;
  const char *names[8], *legacy[8];
  uint32_t i, k = 0, hop = n->hop_index;
  char detail[256];
  int warn;
  SD_LOGI("mount", "hop %u negotiated kex=%s hostkey=%s cipher=%s mac=%s", (unsigned)hop, n->kex, n->hostkey,
          n->cipher_c2s, n->mac_c2s ? n->mac_c2s : "");
  sd_mutex_lock(&m->lock);
  if (m->nhops == 0 || hop + 1 >= m->nhops)
    scopy(m->hostkey_fp, sizeof(m->hostkey_fp), n->hostkey_fp_sha256);   /* the target's key */
  sd_mutex_unlock(&m->lock);
  names[0] = n->kex; names[1] = n->hostkey; names[2] = n->cipher_c2s; names[3] = n->cipher_s2c;
  names[4] = n->mac_c2s; names[5] = n->mac_s2c; names[6] = NULL; names[7] = NULL;
  for (i = 0; i < 6; i++)
    if (legacy_name(names[i])) legacy[k++] = names[i];
  if (k == 0 && n->legacy_mask == 0)
    return;
  sd_mutex_lock(&m->lock);
  m->legacy_seen = 1;             /* profile.test reports it whatever the legacy policy */
  sd_mutex_unlock(&m->lock);
  qsort((void *)legacy, k, sizeof(legacy[0]), cmp_cstr);
  detail[0] = 0;
  for (i = 0; i < k; i++) {
    if (i > 0 && strcmp(legacy[i], legacy[i - 1]) == 0) continue;
    if (detail[0]) strcat_s(detail, sizeof(detail), ",");
    if (strlen(detail) + strlen(legacy[i]) + 1 < sizeof(detail)) strcat_s(detail, sizeof(detail), legacy[i]);
  }
  if (detail[0] == 0)
    strcpy_s(detail, sizeof(detail), "legacy");  /* mask without a name we know */
  sd_mutex_lock(&m->lock);
  warn = m->legacy_policy != SD_LEGACY_ALLOW && hop < 32 && !(m->warned_legacy & (1u << hop));
  if (warn) m->warned_legacy |= 1u << hop;
  sd_mutex_unlock(&m->lock);
  if (m->legacy_policy == SD_LEGACY_ALLOW)
    SD_LOGI("mount", "hop %u uses outdated algorithms (allowed): %s", (unsigned)hop, detail);
  else if (warn)
    post_warning(m, "legacy_algorithms", hop, detail);
}

static void copy_hk(sd_mount_hostkey *d, const sd_hk_key *k)
{
  scopy(d->type, sizeof(d->type), k->type);
  scopy(d->fp_sha256, sizeof(d->fp_sha256), k->fp_sha256);
  d->len = (k->blob && k->len <= sizeof(d->blob)) ? k->len : 0;
  if (d->len) memcpy(d->blob, k->blob, d->len);
}

/* ---- M5 hostkey mount (params.hostkey_fetch, 03 §6.1, 01 §4.3, TM-R04) ----
   The connection is the profile's own (every hop, the profile's authentication, the same prompts through the
   broker), without sftp. Its host key is verified as usual: a stored key must match (MISMATCH and type
   restrictions fail as they do for a mount). The other host keys come from sd_ssh_conn_fetch_hostkeys inside
   that verified connection. First contact (no stored key, 5.2) accepts the presented key ONCE, nothing stored:
   the result is that one key with verified = 0, and the caller's confirmation is the trust decision. */

static const char *const k_hk_default_types[] = {
  "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"
};

static void hk_on_fetched(void *ctx, sd_err err, const sd_hk_key *keys, uint32_t count)
{
  sd_mount *m = (sd_mount *)ctx;
  sd_err out = SD_OK;
  uint32_t i;
  sd_mutex_lock(&m->lock);
  memset(&m->hk_res.keys, 0, sizeof(m->hk_res.keys));
  m->hk_res.count = 0;
  m->hk_res.verified = 0;
  if (err == SD_OK || err == SD_E_HOSTKEY_TYPE_UNAVAILABLE) {
    /* verified: the other keys (none is not an error here; the caller says so) */
    m->hk_res.verified = 1;
    if (err == SD_OK)
      for (i = 0; i < count && i < SD_MOUNT_ANNOUNCE_MAX; i++) {
        copy_hk(&m->hk_res.keys[m->hk_res.count], &keys[i]);
        if (m->hk_res.keys[m->hk_res.count].len) m->hk_res.count++;
      }
  } else if (err == SD_E_HOSTKEY_REJECTED && m->hk_presented) {
    /* first contact: the one presented key, not stored */
    m->hk_res.count = 1;
    m->hk_res.keys[0] = m->hk_key;
    err = SD_OK;
  } else {
    out = err;
  }
  sd_mutex_unlock(&m->lock);
  post_item(m, EV_HK_DONE, out, 0, NULL);
}

static void hk_on_connected(void *ctx, sd_err err, uint32_t failed_hop)
{
  sd_mount *m = (sd_mount *)ctx;
  const char *types[SD_COUNTOF(k_hk_default_types)];
  uint32_t n = 0, i;
  sd_err e;
  SD_UNUSED(failed_hop);
  if (err != SD_OK) {
    post_item(m, EV_HK_DONE, err, 0, NULL);
    return;
  }
  if (m->hk_type[0]) {
    types[n++] = m->hk_type;
  } else {
    for (i = 0; i < SD_COUNTOF(k_hk_default_types); i++) types[n++] = k_hk_default_types[i];
  }
  e = m->be->hk_conn_fetch(m->hk_conn, m->nhops ? m->nhops - 1 : 0, types, n, hk_on_fetched, m);
  if (e != SD_OK)
    post_item(m, EV_HK_DONE, e, 0, NULL);
}

static sd_err hk_start(sd_mount *m)
{
  sd_err e = SD_OK;
  if (!m->be->hk_conn_create || !m->be->hk_conn_connect || !m->be->hk_conn_fetch || !m->be->hk_conn_destroy)
    e = SD_E_UNSUPPORTED;
  if (e == SD_OK) {
    build_ssh_config(m);
    e = m->be->hk_conn_create(&m->ssh, &m->sshcb, &m->hk_conn);
  }
  if (e == SD_OK)
    e = m->be->hk_conn_connect(m->hk_conn, hk_on_connected, m);
  /* a synchronous failure is reported like any other end of the mount (its callback did not run) */
  if (e != SD_OK)
    post_item(m, EV_HK_DONE, e, 0, NULL);
  if (m->cb.on_state)
    m->cb.on_state(m->cb.ctx, m, SD_MOUNT_CONNECTING, SD_OK);
  return SD_OK;
}

/* control thread: the connection is closed and destroyed (sd_ssh_conn_destroy waits for its I/O thread), the
   mount ends (on_state reports UNMOUNTED, or FAILED with the recorded failure). */
static void hk_finish(sd_mount *m)
{
  sd_mount_cancel_prompts(m);
  m->stopping = 1;
  if (m->hk_conn) {
    m->be->hk_conn_destroy(m->hk_conn);
    m->hk_conn = NULL;
  }
  finish(m);
}

static void ssh_on_hostkey_event(void *ctx, const sd_hostkey_event *e)
{
  sd_mount *m = (sd_mount *)ctx;
  if (e->kind == SD_HKEV_ANNOUNCED) {
    sd_mount_announcement *a = (sd_mount_announcement *)sd_calloc(1, sizeof(*a));
    mount_item *it = (mount_item *)sd_calloc(1, sizeof(*it));
    uint32_t i, hop = e->hop_index < m->nhops ? e->hop_index : (m->nhops ? m->nhops - 1 : 0);
    if (a == NULL || it == NULL) {
      sd_free(a);
      sd_free(it);
      return;
    }
    a->hop_index = e->hop_index;
    scopy(a->host, sizeof(a->host), m->hops[hop].host8);
    scopy(a->lookup_name, sizeof(a->lookup_name), e->lookup_name);
    a->mode = m->hops[hop].hku;
    for (i = 0; i < e->add_count && a->add_count < SD_MOUNT_ANNOUNCE_MAX; i++)
      copy_hk(&a->add[a->add_count++], &e->add[i]);
    for (i = 0; i < e->remove_count && a->remove_count < SD_MOUNT_ANNOUNCE_MAX; i++)
      copy_hk(&a->remove[a->remove_count++], &e->remove[i]);
    it->m = m;
    it->kind = EV_ANNOUNCED;
    it->ann = a;
    addref(m);
    m->cb.post(m->cb.ctx, run_item, it);
    return;
  }
  if (e->kind != SD_HKEV_MISMATCH)
    return;
  sd_mutex_lock(&m->lock);
  if (e->old_key) {
    scopy(m->fail.stored_type, sizeof(m->fail.stored_type), e->old_key->type);
    scopy(m->fail.stored_fp, sizeof(m->fail.stored_fp), e->old_key->fp_sha256);
  }
  if (e->new_key) {
    scopy(m->fail.offered_type, sizeof(m->fail.offered_type), e->new_key->type);
    scopy(m->fail.offered_fp, sizeof(m->fail.offered_fp), e->new_key->fp_sha256);
  }
  m->fail.store_path[0] = 0;
  if (e->path) {
    size_t n = wcslen(e->path);
    if (n < SD_COUNTOF(m->fail.store_path))
      memcpy(m->fail.store_path, e->path, (n + 1) * sizeof(wchar_t));
  }
  m->fail.store_line = e->line;
  sd_mutex_unlock(&m->lock);
}

static void sftp_on_event(void *ctx, const sd_sftp_event *ev)
{
  sd_mount *m = (sd_mount *)ctx;
  if (ev->type != SD_SFTP_EV_STATE && ev->type != SD_SFTP_EV_POOL)
    return;
  if (ev->type == SD_SFTP_EV_POOL) {
    sd_mutex_lock(&m->lock);
    m->conn.pool = ev->connections;
    sd_mutex_unlock(&m->lock);
    post_item(m, EV_CONN, SD_OK, 0, NULL);
    return;
  }
  sd_mutex_lock(&m->lock);
  m->conn.session = ev->state;
  if (ev->state == SD_SFTP_ST_CONNECTING) {
    /* a new connection: TM-R05 and the "stored secret rejected" memory are per connection */
    m->ja_from = NO_HOP;
    memset(m->autofilled, 0, sizeof(m->autofilled));
  }
  if (ev->state == SD_SFTP_ST_FAILED || ev->state == SD_SFTP_ST_AUTH_REQUIRED)
    m->conn.failed_hop = ev->failed_hop;
  switch (ev->state) {
  case SD_SFTP_ST_READY:
    if (m->conn.generation && ev->generation != m->conn.generation)
      m->conn.reconnects++;
    if (ev->generation)
      m->conn.generation = ev->generation;
    m->conn.attempt = m->conn.retry_in_ms = 0;
    m->conn.offline_since_ms = 0;
    m->conn.reason = SD_OK;
    break;
  case SD_SFTP_ST_DISCONNECTED:
    if (!m->conn.offline_since_ms) m->conn.offline_since_ms = sd_tick_ms();
    m->conn.reason = ev->reason;
    break;
  case SD_SFTP_ST_RECONNECT_WAIT:
    m->conn.attempt = ev->attempt;
    m->conn.retry_in_ms = ev->retry_in_ms;
    if (ev->reason) m->conn.reason = ev->reason;
    break;
  case SD_SFTP_ST_AUTH_REQUIRED:
  case SD_SFTP_ST_FAILED:
    if (ev->reason) m->conn.reason = ev->reason;
    break;
  default: break;
  }
  sd_mutex_unlock(&m->lock);
  switch (ev->state) {
  case SD_SFTP_ST_READY:          post_item(m, EV_READY, SD_OK, 0, NULL); break;
  case SD_SFTP_ST_FAILED:         post_item(m, EV_FAILED, ev->reason ? ev->reason : SD_E_FAILURE, 0, NULL); break;
  case SD_SFTP_ST_DISCONNECTED:   post_item(m, EV_DISCONNECTED, ev->reason, 0, NULL); break;
  case SD_SFTP_ST_AUTH_REQUIRED:  post_item(m, EV_AUTH_REQUIRED, ev->reason, 0, NULL); break;
  case SD_SFTP_ST_RECONNECT_WAIT:
  case SD_SFTP_ST_CONNECTING:     post_item(m, EV_CONN, ev->reason, 0, NULL); break;
  case SD_SFTP_ST_CLOSED:         post_item(m, EV_CLOSED, ev->reason, 0, NULL); break;
  default: break;
  }
}

/* ---- public API ---- */

static PSID process_sid(void)
{
  HANDLE tok;
  uint8_t buf[256];
  DWORD len = 0, sl;
  PSID copy = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return NULL;
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len)) {
    PSID s = ((TOKEN_USER *)buf)->User.Sid;
    sl = GetLengthSid(s);
    copy = sd_alloc(sl);
    if (copy && !CopySid(sl, copy, s)) {
      sd_free(copy);
      copy = NULL;
    }
  }
  CloseHandle(tok);
  return copy;
}

static int utf8_of(const wchar_t *w, char *out, size_t cap)
{
  size_t got = 0;
  out[0] = 0;
  if (w == NULL) return 1;
  if (sd_utf16_to_utf8(w, wcslen(w), out, cap - 1, &got, SD_UTF_REPLACE) != SD_OK) return 0;
  out[got] = 0;
  return 1;
}

/* Deep copy of one hop; 0 on allocation failure or an invalid hop. */
static int copy_hop(owned_hop *d, const sd_mount_hop *h)
{
  uint32_t i;
  if (h->host == NULL || h->host[0] == 0 || h->user == NULL || h->user[0] == 0 ||
      h->identity_count > SD_MOUNT_MAX_IDENTITIES)
    return 0;
  d->host = wdup(h->host);
  d->user = sdup(h->user);
  d->port = h->port ? h->port : 22;
  if (d->host == NULL || d->user == NULL || !utf8_of(h->host, d->host8, sizeof(d->host8)))
    return 0;
  for (i = 0; i < h->identity_count; i++) {
    if (h->identities[i] == NULL || h->identities[i][0] == 0) continue;
    if ((d->ident[d->nident] = wdup(h->identities[i])) == NULL) return 0;
    d->nident++;
  }
  if (h->key_blob && h->key_blob_len) {
    d->blob = (uint8_t *)sd_alloc(h->key_blob_len);
    if (d->blob == NULL) return 0;
    memcpy(d->blob, h->key_blob, h->key_blob_len);
    d->blob_len = h->key_blob_len;
    d->label = sdup(h->key_label);
  }
  d->cert = wdup(h->certificate);
  d->agents = h->agents;
  d->ident_only = h->identities_only;
  if (h->agent_keys) {
    const char *q = h->agent_keys;
    while (*q && d->nagent_keys < SD_MOUNT_MAX_AGENT_KEYS) {
      size_t n = 0;
      while (*q == ' ' || *q == ',' || *q == '\t') q++;
      while (q[n] && q[n] != ',' && q[n] != ' ' && q[n] != '\t') n++;
      if (n && n < sizeof(d->agent_key[0]) && strncmp(q, "SHA256:", 7) == 0) {
        memcpy(d->agent_key[d->nagent_keys], q, n);
        d->agent_key[d->nagent_keys][n] = 0;
        d->nagent_keys++;
      }
      q += n;
    }
  }
  d->methods = h->auth_methods ? h->auth_methods : (SD_AUTH_PUBLICKEY | SD_AUTH_KBDINT | SD_AUTH_PASSWORD);
  d->alias = sdup(h->host_key_alias);
  d->hku = h->update_host_keys;
  d->no_save = h->no_save;
  d->pkind = h->proxy.kind;
  if (d->pkind != SD_PROXY_NONE) {
    d->phost = wdup(h->proxy.host);
    d->puser = sdup(h->proxy.user);
    d->pport = h->proxy.port;
    d->pauth = h->proxy.auth;
    d->psspi = h->proxy.allow_discovered_sspi;
    d->psys = h->proxy.allow_system;
    d->pfallback = h->proxy.fallback_direct;
    if (!utf8_of(h->proxy.host, d->phost8, sizeof(d->phost8)))
      return 0;
    if (d->pkind != SD_PROXY_SYSTEM && d->phost == NULL)
      return 0;
  }
  return 1;
}

sd_err sd_mount_create(const sd_mount_backend *be, const sd_mount_params *p, const sd_mount_callbacks *cb,
                       sd_mount **out)
{
  sd_mount *m;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (be == NULL || p == NULL || cb == NULL || cb->post == NULL || p->struct_size < sizeof(sd_mount_params) ||
      p->host == NULL || p->host[0] == 0 || p->user == NULL || p->user[0] == 0 ||
      p->letter < L'A' || p->letter > L'Z' || p->backend < SD_MOUNT_BACKEND_AUTO || p->backend > SD_MOUNT_BACKEND_WEBDAV)
    return SD_E_INVALID_PARAM;
  /* M5: a global mount needs its volume security descriptor (service_access, D35) */
  if (p->global_mount && (p->volume_sd == NULL || p->volume_sd_len == 0))
    return SD_E_INVALID_PARAM;
  /* M5: and its service_access list (no default audience, D35); service_access_write may be empty */
  if (p->global_mount && (p->access_sids == NULL || p->n_access == 0))
    return SD_E_INVALID_PARAM;
  /* TM-R19: token-only WebDAV is never used by a global (service) mount */
  if (p->global_mount && p->token_only)
    return SD_E_INVALID_PARAM;
  /* M5: a hostkey mount is never global, and its key type fits the buffer */
  if (p->hostkey_fetch && (p->global_mount || (p->hostkey_type && strlen(p->hostkey_type) >= 64)))
    return SD_E_INVALID_PARAM;
  m = (sd_mount *)sd_calloc(1, sizeof(*m));
  if (m == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&m->lock);
  m->refs = 1;
  m->be = be;
  m->cb = *cb;
  m->host = wdup(p->host);
  m->user = sdup(p->user);
  m->identity = wdup(p->identity_path);
  m->remote = sdup(p->remote_path);
  m->label = wdup(p->volume_label);
  m->kh_path = wdup(p->known_hosts_path);
  m->owner_sid = process_sid();
  m->port = p->port ? p->port : 22;
  m->methods = p->auth_methods ? p->auth_methods : (SD_AUTH_PUBLICKEY | SD_AUTH_KBDINT | SD_AUTH_PASSWORD);
  m->letter = p->letter;
  m->global_mount = p->global_mount ? 1 : 0;
  m->token_only = p->token_only ? 1 : 0;
  m->token_only_confirmed = p->token_only_confirmed ? 1 : 0;
  if (p->volume_sd && p->volume_sd_len) {
    m->volume_sd = (uint8_t *)sd_alloc(p->volume_sd_len);
    if (m->volume_sd == NULL) {
      sd_mount_destroy(m);          /* allowed before sd_mount_start */
      return SD_E_NO_MEMORY;
    }
    memcpy(m->volume_sd, p->volume_sd, p->volume_sd_len);
    m->volume_sd_len = p->volume_sd_len;
  }
  if (p->global_mount) {                /* M5: the per-request lists (02 6.7, 7.7); the vfs copies them again at mount */
    sd_err ce = copy_sid_list(p->access_sids, p->n_access, &m->acc_sids, &m->n_acc);
    if (ce == SD_OK)
      ce = copy_sid_list(p->write_sids, p->n_write, &m->wrt_sids, &m->n_wrt);
    if (ce != SD_OK) {
      sd_mount_destroy(m);
      return ce;
    }
  }
  m->read_only = p->read_only;
  m->tune = p->tuning;
  m->symlinks = p->symlinks;
  m->write_mode = p->write_mode;
  m->backend_req = p->backend;
  m->used = (sd_mount_backend_kind)p->backend;
  m->cache_mem = p->cache_memory_bytes;
  m->disk_mb = p->disk_cache_mb;
  m->disk_dir = wdup(p->disk_cache_dir);
  m->offline_wait = p->offline_wait_ms;
  m->grace = p->reconnect_grace_ms;
  m->channels = p->channels == 1 ? 1 : 2;
  m->reconnect_disabled = p->reconnect_disabled;
  m->rc_initial = p->reconnect_initial_ms ? p->reconnect_initial_ms : 1000;
  m->rc_max = p->reconnect_max_ms ? p->reconnect_max_ms : 60000;
  m->rc_attempts = p->reconnect_max_attempts;
  m->no_secret_cache = p->no_secret_cache;
  m->conn.session = SD_SFTP_ST_IDLE;
  m->state = SD_MOUNT_CONNECTING;
  if (m->host == NULL || m->user == NULL || m->owner_sid == NULL ||
      (p->identity_path && p->identity_path[0] && m->identity == NULL) ||
      (p->remote_path && p->remote_path[0] && m->remote == NULL) ||
      (p->disk_cache_dir && p->disk_cache_dir[0] && m->disk_dir == NULL)) {
    release(m);
    return SD_E_NO_MEMORY;
  }
  /* M2 */
  m->ja_from = NO_HOP;
  m->legacy_policy = p->legacy_policy;
  m->refuse_terrapin = p->refuse_terrapin_exposed;
  m->connections = p->connections >= 1 && p->connections <= 4 ? p->connections : 1;
  m->conn.pool_wanted = m->connections;
  m->test_only = p->test_only ? 1 : 0;
  m->hk_fetch = p->hostkey_fetch ? 1 : 0;
  if (m->hk_fetch) {
    m->test_only = 1;               /* connect and authenticate only; no vfs */
    scopy(m->hk_type, sizeof(m->hk_type), p->hostkey_type ? p->hostkey_type : "");
  }
  m->keepalive = p->keepalive_ms;
  m->ctimeout = p->connect_timeout_ms;
  m->profile_name = wdup(p->profile_name);
  if (p->hops && p->hop_count) {
    uint32_t i;
    if (p->hop_count > SD_MOUNT_MAX_HOPS) {
      release(m);
      return SD_E_INVALID_PARAM;
    }
    for (i = 0; i < p->hop_count; i++) {
      if (!copy_hop(&m->hops[i], &p->hops[i])) {
        release(m);
        return SD_E_INVALID_PARAM;
      }
    }
    m->nhops = p->hop_count;
  } else {
    /* M0/M1: one hop from the flat fields */
    sd_mount_hop h;
    const wchar_t *ids[1];
    memset(&h, 0, sizeof(h));
    h.host = p->host;
    h.port = m->port;
    h.user = p->user;
    ids[0] = m->identity;
    h.identities = ids;
    h.identity_count = m->identity ? 1 : 0;
    h.identities_only = m->identity ? 1 : 0;      /* D37 */
    h.auth_methods = m->methods;
    h.update_host_keys = SD_HKU_ASK;
    if (!copy_hop(&m->hops[0], &h)) {
      release(m);
      return SD_E_NO_MEMORY;
    }
    m->nhops = 1;
  }
  if (p->kh_stores && p->kh_store_count) {
    uint32_t i;
    m->stores = (sd_kh_store *)sd_calloc(p->kh_store_count, sizeof(sd_kh_store));
    if (m->stores == NULL) {
      release(m);
      return SD_E_NO_MEMORY;
    }
    for (i = 0; i < p->kh_store_count; i++) {
      m->stores[i] = p->kh_stores[i];
      m->stores[i].path = wdup(p->kh_stores[i].path);
    }
    m->nstores = p->kh_store_count;
  }
  *out = m;
  return SD_OK;
}

/* The sd_ssh configuration of every hop (01 §5.1), shared by the sftp session and the hostkey connection. */
static void build_ssh_config(sd_mount *m)
{
  uint32_t i, k;
  memset(m->sshhops, 0, sizeof(m->sshhops));
  memset(m->ids, 0, sizeof(m->ids));
  for (i = 0; i < m->nhops; i++) {
    owned_hop *oh = &m->hops[i];
    sd_ssh_hop *sh = &m->sshhops[i];
    sd_ssh_identity *id = m->ids[i];
    uint32_t n = 0;
    for (k = 0; k < oh->nident; k++) {
      id[n].kind = SD_ID_FILE;
      id[n].path = oh->ident[k];
      if (k == 0) id[n].cert_path = oh->cert;
      n++;
    }
    if (oh->blob) {
      id[n].kind = SD_ID_BLOB;
      id[n].blob = oh->blob;
      id[n].blob_len = oh->blob_len;
      id[n].label = oh->label;
      if (oh->nident == 0) id[n].cert_path = oh->cert;
      n++;
    }
    for (k = 0; k < oh->nagent_keys; k++) {
      id[n].kind = SD_ID_AGENT_KEY;
      id[n].agent_fingerprint = oh->agent_key[k];
      n++;
    }
    sh->host = oh->host;
    sh->port = oh->port;
    sh->host_key_alias = oh->alias;
    sh->auth.user = oh->user;
    sh->auth.identities = n ? id : NULL;
    sh->auth.identity_count = n;
    sh->auth.methods = oh->methods | ((oh->nident || oh->blob) ? SD_AUTH_PUBLICKEY : 0);
    sh->auth.agents = oh->agents;
    sh->auth.identities_only = oh->ident_only;
    sh->auth.cache_secrets_for_reconnect = m->no_secret_cache ? 0 : 1;   /* 03 §3.4 default yes */
    sh->proxy.kind = (sd_proxy_kind)oh->pkind;
    sh->proxy.host = oh->phost;
    sh->proxy.port = oh->pport;
    sh->proxy.auth = oh->pauth;
    sh->proxy.allow_discovered_sspi = oh->psspi;
    sh->proxy.allow_system = oh->psys;
    sh->proxy.user = oh->puser;
    sh->proxy.remote_dns = 1;                /* socks5h semantics (3.8) */
    sh->proxy.fallback_direct = oh->pfallback;
    sh->update_host_keys = (sd_hku_mode)oh->hku;
  }
  memset(&m->ssh, 0, sizeof(m->ssh));
  m->ssh.struct_size = sizeof(m->ssh);
  m->ssh.hops = m->sshhops;
  m->ssh.hop_count = m->nhops;
  m->ssh.algos.legacy_policy = (sd_legacy_policy)m->legacy_policy;
  m->ssh.algos.refuse_terrapin_exposed = m->refuse_terrapin;
  m->ssh.connect_timeout_ms = m->ctimeout;
  m->ssh.keepalive_interval_ms = m->keepalive;
  m->ssh.known_hosts = m->kh;
  memset(&m->sshcb, 0, sizeof(m->sshcb));
  m->sshcb.ctx = m;
  m->sshcb.on_prompt = ssh_on_prompt;
  m->sshcb.on_prompt_withdrawn = ssh_on_prompt_withdrawn;
  m->sshcb.on_banner = ssh_on_banner;
  m->sshcb.on_negotiated = ssh_on_negotiated;
  m->sshcb.on_hostkey_event = ssh_on_hostkey_event;
}

static sd_err hk_start(sd_mount *m);
static void hk_finish(sd_mount *m);

sd_err sd_mount_start(sd_mount *m)
{
  sd_err e;
  if (m == NULL || m->started)
    return SD_E_INVALID_PARAM;
  m->started = 1;
  if (m->be->vfs_cache_set_budget)
    m->be->vfs_cache_set_budget(m->cache_mem);   /* process-wide; 0 = min(256 MB, RAM/16) */
  e = m->be->ssh_global_init();
  if (e == SD_OK) {
    if (m->nstores) {
      e = m->be->kh_open(m->stores, m->nstores, &m->kh);
    } else {
      memset(&m->store, 0, sizeof(m->store));
      m->store.kind = SD_KH_STORE_USER;
      m->store.path = m->kh_path;
      m->store.writable = 1;
      e = m->be->kh_open(&m->store, 1, &m->kh);
    }
  }
  if (e == SD_OK && m->hk_fetch)
    return hk_start(m);            /* M5: a hostkey mount has no sftp session */
  if (e == SD_OK) {
    build_ssh_config(m);
    memset(&m->sopt, 0, sizeof(m->sopt));
    m->sopt.struct_size = sizeof(m->sopt);
    m->sopt.channels = m->channels;            /* meta + bulk (D19) unless the profile says 1 */
    m->sopt.connections = m->connections;      /* D18: sd_sftp opens members only after non-interactive auth */
    m->sopt.flags = SD_SFTP_OPT_REFINE_ERRORS | (m->tune.identity_probe_exec ? SD_SFTP_OPT_IDENTITY_EXEC : 0);
    m->sopt.reconnect.enabled = m->reconnect_disabled ? 0 : 1;
    m->sopt.reconnect.initial_delay_ms = m->rc_initial;
    m->sopt.reconnect.max_delay_ms = m->rc_max;
    m->sopt.reconnect.max_attempts = m->rc_attempts;
    m->sopt.default_timeout_ms = 30000;
    e = m->be->session_create(&m->ssh, &m->sshcb, &m->sopt, sftp_on_event, m, &m->sess);
    if (e != SD_OK)
      m->sess = NULL;
  }
  if (e == SD_OK) {
    e = m->be->session_start(m->sess);
  }
  if (e != SD_OK) {
    record_failure(m, e, e == SD_E_UNSUPPORTED ? "backend_unavailable" : NULL, "session start failed");
    m->stopping = 1;
    if (m->sess) {
      m->be->session_destroy(m->sess);
      m->sess = NULL;
    }
    finish(m);
    return e;
  }
  if (m->cb.on_state)
    m->cb.on_state(m->cb.ctx, m, SD_MOUNT_CONNECTING, SD_OK);
  return SD_OK;
}

sd_err sd_mount_stop(sd_mount *m)
{
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  if (m->finished)
    return SD_OK;
  m->user_stop = 1;
  teardown(m);
  return SD_OK;
}

void sd_mount_destroy(sd_mount *m)
{
  if (m == NULL)
    return;
  if (!m->finished && m->started)
    SD_LOGE("mount", "destroy before teardown finished");
  m->destroyed = 1;
  if (m->sess) {
    m->be->session_destroy(m->sess);
    m->sess = NULL;
  }
  if (m->kh) {
    m->be->kh_close(m->kh);
    m->kh = NULL;
  }
  release(m);
}

sd_mount_state sd_mount_get_state(const sd_mount *m) { return m->state; }
wchar_t sd_mount_letter(const sd_mount *m) { return m->letter; }
int sd_mount_is_final(const sd_mount *m) { return m->finished; }
sd_mount_backend_kind sd_mount_backend_kind_used(const sd_mount *m) { return m->used; }

void sd_mount_get_conn(const sd_mount *m, sd_mount_conn *out)
{
  sd_mutex_lock((sd_mutex *)&m->lock);
  *out = m->conn;
  sd_mutex_unlock((sd_mutex *)&m->lock);
}

void sd_mount_get_failure(const sd_mount *m, sd_mount_failure *out)
{
  sd_mutex_lock((sd_mutex *)&m->lock);
  *out = m->fail;
  sd_mutex_unlock((sd_mutex *)&m->lock);
}

sd_err sd_mount_answer(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind, uint32_t n,
                       const char *const *utf8_responses)
{
  return sd_mount_answer_ex(m, prompt_id, kind, n, utf8_responses, 0);
}

sd_err sd_mount_answer_ex(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind, uint32_t n,
                          const char *const *utf8_responses, uint32_t flags)
{
  sd_prompt *p = NULL;
  sd_mount_prompt_kind pk = SD_MP_PASSWORD;
  pending_prompt pp;
  sd_err e;
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  if (take_consent(m, prompt_id, kind))
    return SD_OK;                   /* TM-R19: the token-only question has no sd_prompt behind it */
  if (!take_prompt_by_id(m, prompt_id, &p, &pk, &pp))
    return SD_E_NOT_FOUND;
  if (pk == SD_MP_HOSTKEY && (kind == SD_MA_HOSTKEY_TRUST || kind == SD_MA_HOSTKEY_ONCE)) {
    /* TM-R05: this connection is now hostkey_just_accepted from this hop on */
    sd_mutex_lock(&m->lock);
    if (m->ja_from == NO_HOP || pp.hop < m->ja_from) m->ja_from = pp.hop;
    sd_mutex_unlock(&m->lock);
  }
  if ((flags & SD_MOUNT_ANSWER_SAVE) && kind == SD_MA_RESPONSES && pp.savable && n >= 1 && utf8_responses &&
      utf8_responses[0] && utf8_responses[0][0]) {
    size_t len = strlen(utf8_responses[0]);
    char *v = (char *)sd_alloc(len + 1);
    sd_mutex_lock(&m->lock);
    if (v && m->nsaves < MAX_SAVES) {
      memcpy(v, utf8_responses[0], len + 1);
      m->saves[m->nsaves].kind = pp.skind;
      scopy(m->saves[m->nsaves].target, TARGET_CAP, pp.target);
      m->saves[m->nsaves].value = v;
      m->saves[m->nsaves].len = len;
      m->nsaves++;
      v = NULL;
    }
    sd_mutex_unlock(&m->lock);
    if (v) sd_secure_free(v, len + 1);
  }
  if (pk == SD_MP_LEGACY_ACK) {
    int accept = kind == SD_MA_HOSTKEY_TRUST || kind == SD_MA_HOSTKEY_ONCE;
    e = m->be->prompt_answer_ack ? m->be->prompt_answer_ack(p, accept) : m->be->prompt_cancel(p);
  } else if (kind == SD_MA_REJECT) {
    e = pk == SD_MP_HOSTKEY ? m->be->prompt_answer_hostkey(p, SD_HK_REJECT) : m->be->prompt_cancel(p);
  } else if (pk == SD_MP_HOSTKEY) {
    e = kind == SD_MA_HOSTKEY_TRUST ? m->be->prompt_answer_hostkey(p, SD_HK_ACCEPT_AND_STORE)
      : kind == SD_MA_HOSTKEY_ONCE  ? m->be->prompt_answer_hostkey(p, SD_HK_ACCEPT_ONCE)
                                    : m->be->prompt_answer_hostkey(p, SD_HK_REJECT);
  } else if (kind == SD_MA_RESPONSES) {
    e = m->be->prompt_answer(p, n, utf8_responses);
  } else {
    e = m->be->prompt_cancel(p);
  }
  post_item(m, EV_PROMPT_CLOSED, SD_OK, prompt_id, NULL);
  return e;
}

/* ---- UpdateHostKeys (5.6) ---- */

static sd_err apply_on(const sd_mount_backend *be, sd_known_hosts *kh, sd_kh_store_kind target,
                       const sd_mount_announcement *a, int add_only)
{
  sd_hk_key add[SD_MOUNT_ANNOUNCE_MAX], rem[SD_MOUNT_ANNOUNCE_MAX];
  uint32_t i, na = 0, nr = 0;
  if (be->kh_apply_hostkeys == NULL)
    return SD_E_UNSUPPORTED;
  for (i = 0; i < a->add_count && i < SD_MOUNT_ANNOUNCE_MAX; i++) {
    if (a->add[i].len == 0) continue;
    add[na].blob = a->add[i].blob; add[na].len = a->add[i].len;
    add[na].type = a->add[i].type; add[na].fp_sha256 = a->add[i].fp_sha256;
    na++;
  }
  for (i = 0; !add_only && i < a->remove_count && i < SD_MOUNT_ANNOUNCE_MAX; i++) {
    if (a->remove[i].len == 0) continue;
    rem[nr].blob = a->remove[i].blob; rem[nr].len = a->remove[i].len;
    rem[nr].type = a->remove[i].type; rem[nr].fp_sha256 = a->remove[i].fp_sha256;
    nr++;
  }
  return be->kh_apply_hostkeys(kh, target, a->lookup_name, na ? add : NULL, na, nr ? rem : NULL, nr);
}

sd_err sd_mount_apply_hostkeys_to(const sd_mount_backend *be, const sd_kh_store *stores, uint32_t store_count,
                                  sd_kh_store_kind target, const sd_mount_announcement *a, int add_only)
{
  sd_known_hosts *kh = NULL;
  sd_err e;
  if (be == NULL || stores == NULL || store_count == 0 || a == NULL || a->lookup_name[0] == 0)
    return SD_E_INVALID_PARAM;
  if (be->kh_apply_hostkeys == NULL)
    return SD_E_UNSUPPORTED;
  if ((e = be->kh_open(stores, store_count, &kh)) != SD_OK)
    return e;
  e = apply_on(be, kh, target, a, add_only);
  be->kh_close(kh);
  return e;
}

sd_err sd_mount_apply_hostkeys(const sd_mount_backend *be, const sd_kh_store *stores, uint32_t store_count,
                               const sd_mount_announcement *a, int add_only)
{
  return sd_mount_apply_hostkeys_to(be, stores, store_count, SD_KH_STORE_USER, a, add_only);
}

sd_err sd_mount_get_hostkeys(const sd_mount *cm, sd_mount_hk_fetch *out)
{
  sd_mount *m = (sd_mount *)(uintptr_t)cm;
  if (cm == NULL || out == NULL || !cm->hk_fetch)
    return SD_E_INVALID_PARAM;
  sd_mutex_lock(&m->lock);
  *out = m->hk_res;
  sd_mutex_unlock(&m->lock);
  return SD_OK;
}

uint32_t sd_mount_cancel_prompts(sd_mount *m)
{
  uint32_t count = 0;
  for (;;) {
    sd_prompt *p = NULL;
    sd_mount_prompt_kind pk = SD_MP_PASSWORD;
    uint32_t id = 0;
    sd_mutex_lock(&m->lock);
    if (m->nprompts) {
      m->nprompts--;
      p = m->prompts[m->nprompts].p;
      pk = m->prompts[m->nprompts].kind;
      id = m->prompts[m->nprompts].id;
    }
    sd_mutex_unlock(&m->lock);
    if (p == NULL)
      return count;
    count++;
    if (pk == SD_MP_HOSTKEY)
      m->be->prompt_answer_hostkey(p, SD_HK_REJECT);
    else
      m->be->prompt_cancel(p);
    post_item(m, EV_PROMPT_CLOSED, SD_OK, id, NULL);
  }
}


/* ---- M3: stop force, refresh, cache.clear, stats, attach info, profile.test result ----
 * Stats, refresh and cache calls may run on any thread that holds the host's lock for the mount (the
 * host destroys mounts under that lock). They count themselves in m->readers under m->lock, so the
 * control thread never frees the session or the vfs under them (readers_drain). */

static void reader_leave(sd_mount *m)
{
  sd_mutex_lock(&m->lock);
  m->readers--;
  sd_mutex_unlock(&m->lock);
}

sd_err sd_mount_stop_ex(sd_mount *m, int force)
{
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  m->force_stop = force ? 1 : 0;
  return sd_mount_stop(m);
}

sd_err sd_mount_refresh(sd_mount *m, const wchar_t *subtree)
{
  sd_vfs *v;
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  if (m->be->vfs_refresh == NULL)
    return SD_E_UNSUPPORTED;
  sd_mutex_lock(&m->lock);
  v = m->vfs;
  if (v == NULL) {
    sd_mutex_unlock(&m->lock);
    return SD_E_NOT_FOUND;
  }
  m->readers++;
  sd_mutex_unlock(&m->lock);
  m->be->vfs_refresh(v, subtree);
  reader_leave(m);
  return SD_OK;
}

sd_err sd_mount_cache_clear(sd_mount *m, int disk_too, int force)
{
  sd_vfs *v;
  sd_err e = SD_OK;
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  if (m->be->vfs_cache_clear == NULL)
    return SD_E_UNSUPPORTED;
  sd_mutex_lock(&m->lock);
  v = m->vfs;
  if (v == NULL) {
    sd_mutex_unlock(&m->lock);
    return SD_E_NOT_FOUND;
  }
  m->readers++;
  sd_mutex_unlock(&m->lock);
  /* write-behind data is still queued: the clear would not be the only copy, but it is not safe to
     pretend the cache is clean either, so the host gets busy and decides (force) */
  if (!force && m->be->vfs_write_behind_bytes && m->be->vfs_write_behind_bytes(v) > 0)
    e = SD_E_BUSY;
  else
    m->be->vfs_cache_clear(v, disk_too ? 1 : 0);
  reader_leave(m);
  return e;
}

void sd_mount_get_stats(const sd_mount *cm, sd_mount_stats *out)
{
  sd_mount *m = (sd_mount *)cm;
  sd_sftp_session *s;
  sd_vfs *v;
  if (out == NULL)
    return;
  memset(out, 0, sizeof(*out));
  if (m == NULL)
    return;
  sd_mutex_lock(&m->lock);
  s = m->sess;
  v = m->vfs;
  m->readers++;
  sd_mutex_unlock(&m->lock);
  if (s && m->be->session_stats) {
    m->be->session_stats(s, out);
    out->has_session = 1;
  }
  if (v) {
    if (m->be->vfs_stats)
      m->be->vfs_stats(v, out);
    if (m->be->vfs_write_behind_bytes)
      out->wb_bytes = m->be->vfs_write_behind_bytes(v);
    out->has_vfs = 1;
  }
  reader_leave(m);
}

void sd_mount_get_attach(const sd_mount *cm, sd_mount_attach *out)
{
  sd_mount *m = (sd_mount *)cm;
  if (out == NULL)
    return;
  memset(out, 0, sizeof(*out));
  if (m == NULL)
    return;
  sd_mutex_lock(&m->lock);
  out->backend = m->vfs ? m->used : (sd_mount_backend_kind)m->backend_req;
  out->letter = m->letter;
  out->mounted = m->state == SD_MOUNT_MOUNTED;
  out->webdav_port = m->wport;
  sd_mutex_unlock(&m->lock);
}

int sd_mount_get_probe(const sd_mount *cm, sd_mount_probe *out)
{
  sd_mount *m = (sd_mount *)cm;
  int ok;
  if (out == NULL || m == NULL)
    return 0;
  sd_mutex_lock(&m->lock);
  ok = m->probe_ok;
  if (ok)
    *out = m->probe;
  sd_mutex_unlock(&m->lock);
  return ok;
}
