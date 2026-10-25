/* sd_mount glue (03 §1.11). See sd_mount.h for the contract. */
#include <windows.h>
#include <string.h>

#include "sd_mount/sd_mount.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

#define MAX_PROMPTS 8

typedef struct pending_prompt { uint32_t id; sd_prompt *p; sd_mount_prompt_kind kind; } pending_prompt;

enum { EV_READY, EV_FAILED, EV_DISCONNECTED, EV_CLOSED, EV_PROMPT, EV_PROMPT_CLOSED, EV_DOKAN_UNMOUNTED,
       EV_CONN, EV_AUTH_REQUIRED, EV_WRITE_FAILED, EV_NOTICE, EV_IDENTITY };

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
  PSID owner_sid;
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
  sd_vfs_identity known_id;       /* passed to the vfs (lookup_identity) */
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

static void free_mount(sd_mount *m)
{
  sd_free(m->host);
  sd_free(m->identity);
  sd_free(m->label);
  sd_free(m->kh_path);
  sd_free(m->user);
  sd_free(m->remote);
  sd_free(m->owner_sid);
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
static void vfs_on_event(void *ctx, const sd_vfs_event *ev)
{
  sd_mount *m = (sd_mount *)ctx;
  mount_item *it;
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

static void finish(sd_mount *m)
{
  sd_err why;
  if (m->finished)
    return;
  if (m->sess) {
    m->be->session_destroy(m->sess);
    m->sess = NULL;
  }
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
  }
  if (m->dm) {
    sd_err e = m->be->dokan_mount_stop(m->dm);
    if (e != SD_OK)
      SD_LOGW("mount", "dokan_mount_stop: %s", sd_err_name(e));
    m->dm = NULL;
  }
  if (m->vfs) {
    m->be->vfs_quiesce(m->vfs, 10000);
    m->be->vfs_unmount(m->vfs);
    m->vfs = NULL;
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

static void on_ready(sd_mount *m)
{
  sd_vfs_options vo;
  sd_vfs_status vs;
  int use;
  sd_err e;
  if (m->stopping)
    return;
  if (m->vfs) {
    /* reconnected (generation > 1): the vfs and the backend stay; the vfs re-syncs by itself */
    set_state(m, SD_MOUNT_MOUNTED, SD_OK);
    if (m->cb.on_conn) m->cb.on_conn(m->cb.ctx, m);
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
  vo.block_shell_active = TRUE;            /* security.trust = untrusted (D41 default) */
  /* below the Dokany 30 s timeout / the redirector's 60 s SendReceiveTimeoutInSec (02 §5.7) */
  vo.request_timeout_ms = use == SD_MOUNT_BACKEND_WEBDAV ? 50000 : 25000;
  vo.volume_label = m->label ? m->label : m->host;
  vo.owner_sid = m->owner_sid;
  vo.offline_wait_ms = m->offline_wait;
  vo.reconnect_grace_ms = m->grace;
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
    sd_webdav_mount_cfg wc;
    memset(&wc, 0, sizeof(wc));
    wc.struct_size = sizeof(wc);
    wc.letter = m->letter;
    wc.read_only = m->read_only ? TRUE : FALSE;
    wc.label = vo.volume_label;
    wc.owner_sid = m->owner_sid;
    e = m->be->webdav_mount_start(m->vfs, &wc, &m->wm);
    if (e != SD_OK) {
      m->wm = NULL;
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
    dc.current_session = TRUE;
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
      if (m->state == SD_MOUNT_CONNECTING && it->prompt->kind != SD_MP_HOSTKEY)
        set_state(m, SD_MOUNT_AUTHENTICATING, SD_OK);
      if (m->cb.on_prompt)
        m->cb.on_prompt(m->cb.ctx, m, it->prompt);
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
  sd_free(it);
  release(m);
}

/* ---- callbacks from I/O threads ---- */

static void ssh_on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *auth, const sd_hostkey_prompt_info *hk)
{
  sd_mount *m = (sd_mount *)ctx;
  sd_mount_prompt *mp;
  uint32_t i, id;
  sd_mount_prompt_kind kind;
  if (hk) {
    kind = SD_MP_HOSTKEY;
  } else if (auth && auth->kind == SD_PROMPT_PASSWORD) {
    kind = SD_MP_PASSWORD;
  } else if (auth && auth->kind == SD_PROMPT_KEY_PASSPHRASE) {
    kind = SD_MP_PASSPHRASE;
  } else if (auth && auth->kind == SD_PROMPT_KBDINT) {
    kind = SD_MP_KBDINT;
  } else {
    /* password change, legacy ack, proxy password: not in M0 */
    m->be->prompt_cancel(p);
    return;
  }
  if (auth && auth->is_pool_member) {
    m->be->prompt_cancel(p);                /* pool members never prompt (01 §10.9) */
    return;
  }
  mp = (sd_mount_prompt *)sd_calloc(1, sizeof(*mp));
  sd_mutex_lock(&m->lock);
  if (mp == NULL || m->nprompts >= MAX_PROMPTS || m->stopping) {
    sd_mutex_unlock(&m->lock);
    sd_free(mp);
    m->be->prompt_cancel(p);
    return;
  }
  id = ++m->next_prompt_id;
  m->prompts[m->nprompts].id = id;
  m->prompts[m->nprompts].p = p;
  m->prompts[m->nprompts].kind = kind;
  m->nprompts++;
  sd_mutex_unlock(&m->lock);
  mp->id = id;
  mp->kind = kind;
  if (hk) {
    mp->hop_index = hk->hop_index;
    scopy(mp->host, sizeof(mp->host), hk->host);
    mp->port = hk->port;
    scopy(mp->key_type, sizeof(mp->key_type), hk->key_type);
    mp->key_bits = hk->key_bits;
    scopy(mp->fp_sha256, sizeof(mp->fp_sha256), hk->fp_sha256);
    scopy(mp->lookup_name, sizeof(mp->lookup_name), hk->lookup_name);
  } else {
    mp->hop_index = auth->hop_index;
    scopy(mp->host, sizeof(mp->host), auth->host);
    mp->port = m->port;
    scopy(mp->user, sizeof(mp->user), auth->user);
    mp->round = auth->round;
    mp->hostkey_just_accepted = auth->hostkey_just_accepted;
    scopy(mp->key_path, sizeof(mp->key_path), auth->key_path);
    scopy(mp->key_fp, sizeof(mp->key_fp), auth->key_fingerprint);
    scopy(mp->name, sizeof(mp->name), auth->name);
    scopy(mp->instruction, sizeof(mp->instruction), auth->instruction);
    mp->item_count = SD_MIN(auth->item_count, SD_MOUNT_PROMPT_MAX_ITEMS);
    for (i = 0; i < mp->item_count; i++) {
      scopy(mp->items[i].text, sizeof(mp->items[i].text), auth->items[i].text);
      mp->items[i].echo = auth->items[i].echo;
    }
    if (kind == SD_MP_PASSWORD && mp->item_count == 0) {
      mp->item_count = 1;
      mp->items[0].echo = 0;
    }
  }
  if (mp->port == 0)
    mp->port = m->port;
  post_item(m, EV_PROMPT, SD_OK, id, mp);
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

static void ssh_on_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  sd_mount *m = (sd_mount *)ctx;
  SD_LOGI("mount", "negotiated kex=%s hostkey=%s cipher=%s", n->kex, n->hostkey, n->cipher_c2s);
  sd_mutex_lock(&m->lock);
  scopy(m->hostkey_fp, sizeof(m->hostkey_fp), n->hostkey_fp_sha256);
  sd_mutex_unlock(&m->lock);
}

static void ssh_on_hostkey_event(void *ctx, const sd_hostkey_event *e)
{
  sd_mount *m = (sd_mount *)ctx;
  if (e->kind != SD_HKEV_MISMATCH)
    return;    /* UpdateHostKeys announcements: M2 */
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
  if (ev->type != SD_SFTP_EV_STATE)
    return;
  sd_mutex_lock(&m->lock);
  m->conn.session = ev->state;
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
  m->read_only = p->read_only;
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
  *out = m;
  return SD_OK;
}

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
    memset(&m->store, 0, sizeof(m->store));
    m->store.kind = SD_KH_STORE_USER;
    m->store.path = m->kh_path;
    m->store.writable = 1;
    e = m->be->kh_open(&m->store, 1, &m->kh);
  }
  if (e == SD_OK) {
    memset(&m->ident, 0, sizeof(m->ident));
    m->ident.kind = SD_ID_FILE;
    m->ident.path = m->identity;
    memset(&m->hop, 0, sizeof(m->hop));
    m->hop.host = m->host;
    m->hop.port = m->port;
    m->hop.auth.user = m->user;
    m->hop.auth.identities = m->identity ? &m->ident : NULL;
    m->hop.auth.identity_count = m->identity ? 1 : 0;
    m->hop.auth.methods = m->methods | (m->identity ? SD_AUTH_PUBLICKEY : 0);
    m->hop.auth.agents = 0;                    /* agents: M2 */
    m->hop.auth.identities_only = m->identity ? 1 : 0;   /* D37 */
    m->hop.auth.cache_secrets_for_reconnect = m->no_secret_cache ? 0 : 1;   /* 03 §3.4 default yes */
    m->hop.proxy.kind = SD_PROXY_NONE;
    m->hop.update_host_keys = SD_HKU_NO;       /* announcements: M2 */
    memset(&m->ssh, 0, sizeof(m->ssh));
    m->ssh.struct_size = sizeof(m->ssh);
    m->ssh.hops = &m->hop;
    m->ssh.hop_count = 1;
    m->ssh.algos.legacy_policy = SD_LEGACY_WARN;
    m->ssh.known_hosts = m->kh;
    memset(&m->sshcb, 0, sizeof(m->sshcb));
    m->sshcb.ctx = m;
    m->sshcb.on_prompt = ssh_on_prompt;
    m->sshcb.on_prompt_withdrawn = ssh_on_prompt_withdrawn;
    m->sshcb.on_banner = ssh_on_banner;
    m->sshcb.on_negotiated = ssh_on_negotiated;
    m->sshcb.on_hostkey_event = ssh_on_hostkey_event;
    memset(&m->sopt, 0, sizeof(m->sopt));
    m->sopt.struct_size = sizeof(m->sopt);
    m->sopt.channels = m->channels;            /* meta + bulk (D19) unless the profile says 1 */
    m->sopt.connections = 1;
    m->sopt.flags = SD_SFTP_OPT_REFINE_ERRORS;
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
  sd_prompt *p = NULL;
  sd_mount_prompt_kind pk = SD_MP_PASSWORD;
  uint32_t i;
  sd_err e;
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  sd_mutex_lock(&m->lock);
  for (i = 0; i < m->nprompts; i++) {
    if (m->prompts[i].id == prompt_id) {
      p = m->prompts[i].p;
      pk = m->prompts[i].kind;
      m->prompts[i] = m->prompts[m->nprompts - 1];
      m->nprompts--;
      break;
    }
  }
  sd_mutex_unlock(&m->lock);
  if (p == NULL)
    return SD_E_NOT_FOUND;
  if (kind == SD_MA_REJECT) {
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

