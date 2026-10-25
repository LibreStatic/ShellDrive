/* Scripted fake backend for sd_mount (see fake_backend.h). Test code: plain Win32, no network. */
#include <windows.h>
#include <string.h>

#include "fake_backend.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"

struct sd_prompt {
  struct sd_prompt *next;
  struct sd_sftp_session *s;
  int done;                       /* answered, cancelled or withdrawn */
  int cancelled;
  sd_hostkey_decision decision;
  char resp[256];
};

struct sd_sftp_session {
  sd_sftp_event_cb ev;
  void *ev_ctx;
  sd_ssh_callbacks cb;
  char host[256];
  uint16_t port;
  char user[128];
  char identity[MAX_PATH * 3];
  sd_thread thread;
  HANDLE wake;                    /* answer or close */
  volatile LONG close_req;
  sd_mutex lock;
  struct sd_prompt *prompts;      /* kept until destroy */
};

struct sd_vfs { int unused; };
struct sd_dokan_mount { wchar_t letter; };
struct sd_webdav_mount { wchar_t letter; };
struct sd_known_hosts { int unused; };

static sd_mutex g_lock;
static sd_once g_once = SD_ONCE_INIT;
static char g_trusted[16][256];
static uint32_t g_ntrusted;
static wchar_t g_letters[26];
static volatile LONG g_live;
static int g_last_ro;
static char g_last_root[256];
static sd_webdav_client_state g_webclient = SD_WD_CLIENT_MISSING;
static int g_webclient_startable = 1;
static volatile LONG g_ensure_calls, g_webdav_mounts;
static uint32_t g_last_timeout;
/* M1 */
static volatile LONG g_drop_req = -1;     /* -1 none, 0 reconnect, 1 fail */
static volatile LONG g_dokan_starts, g_vfs_mounts, g_budget_calls;
static int g_last_rc_enabled, g_last_secret_cache;
static uint32_t g_last_channels, g_last_offline_wait, g_last_grace, g_last_disk_mb;
static wchar_t g_last_disk_dir[MAX_PATH];
static int g_last_known;
static uint32_t g_last_known_uid;
static sd_vfs_event_cb g_vfs_cb;
static void *g_vfs_ctx;
static sd_vfs_identity g_vfs_ident;

static void init_once(void *arg) { SD_UNUSED(arg); sd_mutex_init(&g_lock); }
static void ensure(void) { sd_once_run(&g_once, init_once, NULL); }

void fake_backend_reset(void)
{
  ensure();
  sd_mutex_lock(&g_lock);
  g_ntrusted = 0;
  memset(g_letters, 0, sizeof(g_letters));
  g_webclient = SD_WD_CLIENT_MISSING;
  g_webclient_startable = 1;
  g_ensure_calls = g_webdav_mounts = 0;
  g_drop_req = -1;
  g_dokan_starts = g_vfs_mounts = g_budget_calls = 0;
  g_vfs_cb = NULL;
  memset(&g_vfs_ident, 0, sizeof(g_vfs_ident));
  sd_mutex_unlock(&g_lock);
}

void fake_backend_drop(int fail) { InterlockedExchange(&g_drop_req, fail ? 1 : 0); }
uint32_t fake_backend_dokan_starts(void) { return (uint32_t)g_dokan_starts; }
uint32_t fake_backend_vfs_mounts(void) { return (uint32_t)g_vfs_mounts; }
uint32_t fake_backend_budget_calls(void) { return (uint32_t)g_budget_calls; }
int fake_backend_last_reconnect_enabled(void) { return g_last_rc_enabled; }
uint32_t fake_backend_last_channels(void) { return g_last_channels; }
int fake_backend_last_secret_cache(void) { return g_last_secret_cache; }
uint32_t fake_backend_last_offline_wait(void) { return g_last_offline_wait; }
uint32_t fake_backend_last_grace(void) { return g_last_grace; }
uint32_t fake_backend_last_disk_mb(void) { return g_last_disk_mb; }
const wchar_t *fake_backend_last_disk_dir(void) { return g_last_disk_dir; }
int fake_backend_last_known_uid(uint32_t *uid) { *uid = g_last_known_uid; return g_last_known; }

typedef struct fake_vev { int kind; wchar_t path[260]; UINT64 bytes; } fake_vev;

static unsigned __stdcall vfs_event_thread(void *arg)
{
  fake_vev *e = (fake_vev *)arg;
  sd_vfs_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.kind = (sd_vfs_event_kind)e->kind;
  ev.path = e->path;
  ev.bytes = e->bytes;
  ev.status = SD_VFS_E_DISCONNECTED;
  ev.code = "write_failed";
  if (g_vfs_cb)
    g_vfs_cb(g_vfs_ctx, &ev);
  sd_free(e);
  return 0;
}

static void raise_vfs_event(int kind, const wchar_t *path, UINT64 bytes)
{
  sd_thread t;
  fake_vev *e = (fake_vev *)sd_calloc(1, sizeof(*e));
  if (e == NULL)
    return;
  e->kind = kind;
  if (path && wcslen(path) < SD_COUNTOF(e->path))
    memcpy(e->path, path, (wcslen(path) + 1) * sizeof(wchar_t));
  e->bytes = bytes;
  if (sd_thread_create(&t, vfs_event_thread, e, 0, L"fake-vfs") == SD_OK)
    sd_thread_join(&t, SD_WAIT_INFINITE, NULL);
}

void fake_backend_vfs_write_failed(const wchar_t *path, UINT64 bytes)
{
  raise_vfs_event(SD_VFS_EV_WRITE_FAILED, path, bytes);
}

void fake_backend_vfs_identity(uint32_t uid, uint32_t gid)
{
  g_vfs_ident.uid_known = g_vfs_ident.definitive = TRUE;
  g_vfs_ident.uid = uid;
  g_vfs_ident.gid = gid;
  raise_vfs_event(SD_VFS_EV_IDENTITY, NULL, 0);
}

void fake_backend_set_webclient(sd_webdav_client_state st, int startable)
{
  ensure();
  sd_mutex_lock(&g_lock);
  g_webclient = st;
  g_webclient_startable = startable;
  sd_mutex_unlock(&g_lock);
}

uint32_t fake_backend_webclient_starts(void) { return (uint32_t)g_ensure_calls; }
uint32_t fake_backend_webdav_mounts(void) { return (uint32_t)g_webdav_mounts; }
uint32_t fake_backend_last_request_timeout(void) { return g_last_timeout; }

int fake_backend_is_trusted(const char *host)
{
  uint32_t i;
  int r = 0;
  ensure();
  sd_mutex_lock(&g_lock);
  for (i = 0; i < g_ntrusted; i++)
    if (strcmp(g_trusted[i], host) == 0) r = 1;
  sd_mutex_unlock(&g_lock);
  return r;
}

static void trust(const char *host)
{
  ensure();
  sd_mutex_lock(&g_lock);
  if (g_ntrusted < 16 && strlen(host) < 256) {
    memcpy(g_trusted[g_ntrusted], host, strlen(host) + 1);
    g_ntrusted++;
  }
  sd_mutex_unlock(&g_lock);
}

int fake_backend_letter_mounted(wchar_t letter)
{
  int r;
  ensure();
  sd_mutex_lock(&g_lock);
  r = letter >= L'A' && letter <= L'Z' && g_letters[letter - L'A'] != 0;
  sd_mutex_unlock(&g_lock);
  return r;
}

uint32_t fake_backend_live_sessions(void) { return (uint32_t)g_live; }
int fake_backend_last_read_only(void) { return g_last_ro; }
const char *fake_backend_last_remote_root(void) { return g_last_root; }

static int starts_with(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

static void emit_state_gen(struct sd_sftp_session *s, sd_sftp_state st, sd_err reason, uint32_t gen)
{
  sd_sftp_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = SD_SFTP_EV_STATE;
  ev.state = st;
  ev.reason = reason;
  ev.generation = gen;
  if (st == SD_SFTP_ST_RECONNECT_WAIT) {
    ev.attempt = 1;
    ev.retry_in_ms = 1000;
  }
  s->ev(s->ev_ctx, &ev);
}

static void emit_state(struct sd_sftp_session *s, sd_sftp_state st, sd_err reason)
{
  emit_state_gen(s, st, reason, st == SD_SFTP_ST_READY ? 1 : 0);
}

/* Raises a prompt and waits for its answer; returns 0 if the session is closing. */
static struct sd_prompt *ask(struct sd_sftp_session *s, const sd_auth_prompt_info *auth,
                             const sd_hostkey_prompt_info *hk)
{
  struct sd_prompt *p = (struct sd_prompt *)sd_calloc(1, sizeof(*p));
  if (p == NULL)
    return NULL;
  p->s = s;
  sd_mutex_lock(&s->lock);
  p->next = s->prompts;
  s->prompts = p;
  sd_mutex_unlock(&s->lock);
  s->cb.on_prompt(s->cb.ctx, p, auth, hk);
  for (;;) {
    int done;
    sd_mutex_lock(&s->lock);
    done = p->done;
    sd_mutex_unlock(&s->lock);
    if (done)
      return p;
    if (s->close_req) {
      sd_mutex_lock(&s->lock);
      p->done = 1;
      p->cancelled = 1;
      sd_mutex_unlock(&s->lock);
      if (s->cb.on_prompt_withdrawn)
        s->cb.on_prompt_withdrawn(s->cb.ctx, p);
      return NULL;
    }
    WaitForSingleObject(s->wake, 100);
  }
}

static int password_flow(struct sd_sftp_session *s, sd_prompt_kind kind, const char *expect, sd_err *fail)
{
  uint32_t round;
  sd_prompt_item item;
  for (round = 0; round < 2; round++) {
    sd_auth_prompt_info ai;
    struct sd_prompt *p;
    memset(&ai, 0, sizeof(ai));
    ai.kind = kind;
    ai.host = s->host;
    ai.user = s->user;
    ai.name = "";
    ai.instruction = "";
    item.text = kind == SD_PROMPT_KEY_PASSPHRASE ? "Passphrase: " : "Password: ";
    item.echo = 0;
    ai.items = &item;
    ai.item_count = 1;
    ai.round = round;
    ai.key_path = kind == SD_PROMPT_KEY_PASSPHRASE ? s->identity : NULL;
    ai.key_fingerprint = kind == SD_PROMPT_KEY_PASSPHRASE ? FAKE_FP : NULL;
    p = ask(s, &ai, NULL);
    if (p == NULL) {
      *fail = SD_E_SHUTDOWN;
      return 0;
    }
    if (p->cancelled) {
      *fail = SD_E_CANCELLED;
      return 0;
    }
    if (strcmp(p->resp, expect) == 0)
      return 1;
  }
  *fail = kind == SD_PROMPT_KEY_PASSPHRASE ? SD_E_BAD_PASSPHRASE : SD_E_AUTH_FAILED;
  return 0;
}

static unsigned __stdcall session_thread(void *arg)
{
  struct sd_sftp_session *s = (struct sd_sftp_session *)arg;
  sd_err fail = SD_OK;
  emit_state(s, SD_SFTP_ST_CONNECTING, SD_OK);
  if (starts_with(s->host, "unreachable")) {
    fail = SD_E_CONN_REFUSED;
  } else if (starts_with(s->host, "mismatch")) {
    sd_hostkey_event he;
    sd_hk_key oldk, newk;
    memset(&he, 0, sizeof(he));
    oldk.blob = NULL; oldk.len = 0; oldk.type = "ssh-ed25519"; oldk.fp_sha256 = "SHA256:storedstoredstoredstoredstoredstored00";
    newk.blob = NULL; newk.len = 0; newk.type = "ssh-ed25519"; newk.fp_sha256 = FAKE_FP;
    he.kind = SD_HKEV_MISMATCH;
    he.lookup_name = s->host;
    he.store = SD_KH_STORE_USER;
    he.path = L"C:\\fake\\known_hosts";
    he.line = 3;
    he.old_key = &oldk;
    he.new_key = &newk;
    if (s->cb.on_hostkey_event)
      s->cb.on_hostkey_event(s->cb.ctx, &he);
    fail = SD_E_HOSTKEY_MISMATCH;
  } else {
    int just_accepted = 0;
    if (!fake_backend_is_trusted(s->host)) {
      sd_hostkey_prompt_info hk;
      struct sd_prompt *p;
      memset(&hk, 0, sizeof(hk));
      hk.host = s->host;
      hk.port = s->port;
      hk.lookup_name = s->host;
      hk.key_type = "ssh-ed25519";
      hk.key_bits = 256;
      hk.fp_sha256 = FAKE_FP;
      hk.fp_md5 = "";
      hk.status = SD_HK_NEW;
      p = ask(s, NULL, &hk);
      if (p == NULL) fail = SD_E_SHUTDOWN;
      else if (p->cancelled || p->decision == SD_HK_REJECT) fail = SD_E_HOSTKEY_REJECTED;
      else {
        if (p->decision == SD_HK_ACCEPT_AND_STORE) trust(s->host);
        just_accepted = 1;
      }
    }
    SD_UNUSED(just_accepted);
    if (fail == SD_OK) {
      if (s->identity[0] && strstr(s->identity, "encrypted"))
        password_flow(s, SD_PROMPT_KEY_PASSPHRASE, FAKE_PASSPHRASE, &fail);
      else if (s->identity[0] == 0)
        password_flow(s, SD_PROMPT_PASSWORD, FAKE_PASSWORD, &fail);
    }
  }
  if (fail == SD_OK && !s->close_req) {
    sd_ssh_negotiated n;
    memset(&n, 0, sizeof(n));
    n.kex = n.hostkey = n.cipher_c2s = "fake";
    n.hostkey_fp_sha256 = FAKE_FP;
    if (s->cb.on_negotiated)
      s->cb.on_negotiated(s->cb.ctx, &n);
    emit_state(s, SD_SFTP_ST_READY, SD_OK);
  } else if (fail != SD_OK && fail != SD_E_SHUTDOWN) {
    emit_state(s, SD_SFTP_ST_FAILED, fail);
  }
  {
    uint32_t gen = 1;
    while (!s->close_req) {
      LONG d = starts_with(s->host, "flaky") && fail == SD_OK ? InterlockedExchange(&g_drop_req, -1) : -1;
      if (d >= 0) {
        emit_state_gen(s, SD_SFTP_ST_DISCONNECTED, SD_E_DISCONNECTED, gen);
        if (d == 1) {
          emit_state_gen(s, SD_SFTP_ST_FAILED, SD_E_HOSTKEY_MISMATCH, gen);
          fail = SD_E_HOSTKEY_MISMATCH;
        } else {
          emit_state_gen(s, SD_SFTP_ST_RECONNECT_WAIT, SD_E_CONN_REFUSED, gen);
          emit_state_gen(s, SD_SFTP_ST_CONNECTING, SD_OK, gen);
          emit_state_gen(s, SD_SFTP_ST_READY, SD_OK, ++gen);
        }
      }
      WaitForSingleObject(s->wake, 20);
    }
  }
  emit_state(s, SD_SFTP_ST_CLOSED, SD_E_SHUTDOWN);
  return 0;
}

/* ---- backend functions ---- */

static sd_err f_global_init(void) { return SD_OK; }

static sd_err f_kh_open(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out)
{
  SD_UNUSED(stores);
  SD_UNUSED(count);
  *out = (sd_known_hosts *)sd_calloc(1, sizeof(sd_known_hosts));
  return *out ? SD_OK : SD_E_NO_MEMORY;
}

static void f_kh_close(sd_known_hosts *kh) { sd_free(kh); }

static void to_utf8(const wchar_t *w, char *out, size_t cap)
{
  int n;
  out[0] = 0;
  if (w == NULL) return;
  n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
  if (n <= 0) out[0] = 0;
}

static sd_err f_session_create(const sd_ssh_config *ssh, const sd_ssh_callbacks *cb, const sd_sftp_options *opt,
                               sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out)
{
  struct sd_sftp_session *s;
  if (ssh == NULL || ssh->hop_count != 1 || ssh->struct_size != sizeof(sd_ssh_config))
    return SD_E_INVALID_PARAM;
  if (opt) {
    g_last_rc_enabled = opt->reconnect.enabled;
    g_last_channels = opt->channels;
  }
  g_last_secret_cache = ssh->hops[0].auth.cache_secrets_for_reconnect;
  s = (struct sd_sftp_session *)sd_calloc(1, sizeof(*s));
  if (s == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&s->lock);
  s->ev = ev;
  s->ev_ctx = ev_ctx;
  s->cb = *cb;
  to_utf8(ssh->hops[0].host, s->host, sizeof(s->host));
  s->port = ssh->hops[0].port;
  if (ssh->hops[0].auth.user) {
    size_t n = strlen(ssh->hops[0].auth.user);
    if (n < sizeof(s->user)) memcpy(s->user, ssh->hops[0].auth.user, n + 1);
  }
  if (ssh->hops[0].auth.identity_count)
    to_utf8(ssh->hops[0].auth.identities[0].path, s->identity, sizeof(s->identity));
  s->wake = CreateEventW(NULL, FALSE, FALSE, NULL);
  *out = s;
  InterlockedIncrement(&g_live);
  return SD_OK;
}

static sd_err f_session_start(sd_sftp_session *s)
{
  return sd_thread_create(&s->thread, session_thread, s, 0, L"fake-ssh-io");
}

static sd_err f_session_close(sd_sftp_session *s)
{
  InterlockedExchange(&s->close_req, 1);
  SetEvent(s->wake);
  return SD_OK;
}

static void f_session_destroy(sd_sftp_session *s)
{
  struct sd_prompt *p;
  if (s == NULL)
    return;
  InterlockedExchange(&s->close_req, 1);
  SetEvent(s->wake);
  if (s->thread.h)
    sd_thread_join(&s->thread, SD_WAIT_INFINITE, NULL);
  while ((p = s->prompts) != NULL) {
    s->prompts = p->next;
    sd_secure_zero(p->resp, sizeof(p->resp));
    sd_free(p);
  }
  CloseHandle(s->wake);
  sd_mutex_destroy(&s->lock);
  sd_free(s);
  InterlockedDecrement(&g_live);
}

static sd_err finish_prompt(sd_prompt *p, int cancelled, sd_hostkey_decision d, const char *resp)
{
  struct sd_sftp_session *s = p->s;
  sd_mutex_lock(&s->lock);
  if (p->done) {
    sd_mutex_unlock(&s->lock);
    return SD_E_CANCELLED;
  }
  p->done = 1;
  p->cancelled = cancelled;
  p->decision = d;
  if (resp) {
    size_t n = strlen(resp);
    if (n >= sizeof(p->resp)) n = sizeof(p->resp) - 1;
    memcpy(p->resp, resp, n);
    p->resp[n] = 0;
  }
  sd_mutex_unlock(&s->lock);
  SetEvent(s->wake);
  return SD_OK;
}

static sd_err f_prompt_answer(sd_prompt *p, uint32_t n, const char *const *r)
{
  return finish_prompt(p, 0, SD_HK_REJECT, n ? r[0] : "");
}

static sd_err f_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d)
{
  return finish_prompt(p, 0, d, NULL);
}

static sd_err f_prompt_cancel(sd_prompt *p)
{
  return finish_prompt(p, 1, SD_HK_REJECT, NULL);
}

static sd_vfs_status f_vfs_mount(sd_sftp_session *s, const sd_vfs_options *o, sd_vfs_event_cb cb, void *ctx,
                                 sd_vfs **out)
{
  SD_UNUSED(s);
  if (o == NULL || o->struct_size != sizeof(sd_vfs_options))
    return SD_VFS_E_UNSUPPORTED;
  g_vfs_cb = cb;
  g_vfs_ctx = ctx;
  InterlockedIncrement(&g_vfs_mounts);
  g_last_offline_wait = o->offline_wait_ms;
  g_last_grace = o->reconnect_grace_ms;
  g_last_disk_mb = o->disk_cache_mb;
  g_last_disk_dir[0] = 0;
  if (o->disk_cache_dir && wcslen(o->disk_cache_dir) < MAX_PATH)
    memcpy(g_last_disk_dir, o->disk_cache_dir, (wcslen(o->disk_cache_dir) + 1) * sizeof(wchar_t));
  g_last_known = o->known_identity != NULL;
  g_last_known_uid = o->known_identity ? o->known_identity->uid : 0;
  g_last_ro = o->read_only ? 1 : 0;
  g_last_timeout = o->request_timeout_ms;
  g_last_root[0] = 0;
  if (o->remote_root && strlen(o->remote_root) < sizeof(g_last_root))
    memcpy(g_last_root, o->remote_root, strlen(o->remote_root) + 1);
  *out = (sd_vfs *)sd_calloc(1, sizeof(sd_vfs));
  return *out ? SD_VFS_OK : SD_VFS_E_NO_MEMORY;
}

static void f_vfs_quiesce(sd_vfs *v, DWORD budget) { SD_UNUSED(v); SD_UNUSED(budget); }
static void f_vfs_unmount(sd_vfs *v) { sd_free(v); }

static int g_probe_fail_next;   /* set by a "nodokany" session */

static sd_dokan_avail f_dokan_probe(const sd_dokan_deny *deny, sd_dokan_probe_info *info)
{
  SD_UNUSED(deny);
  if (info) {
    memset(info, 0, sizeof(*info));
    info->lib_version = 231;
    info->driver_version = 231;
  }
  if (g_probe_fail_next) {
    g_probe_fail_next = 0;
    if (info) info->avail = SD_DOKAN_NOT_INSTALLED;
    return SD_DOKAN_NOT_INSTALLED;
  }
  return SD_DOKAN_OK;
}

static sd_err f_dokan_start(sd_vfs *vfs, const sd_dokan_mount_cfg *cfg, sd_dokan_unmounted_cb cb, void *ctx,
                            sd_dokan_mount **out)
{
  wchar_t l;
  SD_UNUSED(vfs);
  SD_UNUSED(cb);
  SD_UNUSED(ctx);
  if (cfg == NULL || cfg->mount_point == NULL)
    return SD_E_INVALID_PARAM;
  l = cfg->mount_point[0];
  if (l < L'A' || l > L'Z')
    return SD_E_INVALID_PARAM;
  ensure();
  sd_mutex_lock(&g_lock);
  if (g_letters[l - L'A']) {
    sd_mutex_unlock(&g_lock);
    return SD_E_EXISTS;
  }
  g_letters[l - L'A'] = l;
  sd_mutex_unlock(&g_lock);
  InterlockedIncrement(&g_dokan_starts);
  *out = (sd_dokan_mount *)sd_calloc(1, sizeof(sd_dokan_mount));
  if (*out == NULL)
    return SD_E_NO_MEMORY;
  (*out)->letter = l;
  return SD_OK;
}

static sd_err f_dokan_stop(sd_dokan_mount *m)
{
  ensure();
  sd_mutex_lock(&g_lock);
  g_letters[m->letter - L'A'] = 0;
  sd_mutex_unlock(&g_lock);
  sd_free(m);
  return SD_OK;
}

static sd_webdav_client_state f_wd_query(sd_webdav_client_info *out)
{
  sd_webdav_client_state st;
  ensure();
  sd_mutex_lock(&g_lock);
  st = g_webclient;
  sd_mutex_unlock(&g_lock);
  if (out) {
    memset(out, 0, sizeof(*out));
    out->state = st;
  }
  return st;
}

static sd_err f_wd_ensure(uint32_t timeout_ms, sd_webdav_client_info *out)
{
  sd_webdav_client_state st = f_wd_query(out);
  SD_UNUSED(timeout_ms);
  InterlockedIncrement(&g_ensure_calls);
  if (st == SD_WD_CLIENT_RUNNING)
    return SD_OK;
  if (st == SD_WD_CLIENT_MISSING || st == SD_WD_CLIENT_DISABLED)
    return SD_E_UNSUPPORTED;
  if (!g_webclient_startable) {
    if (out) out->needs_admin = TRUE;
    return SD_E_ACCESS_DENIED;
  }
  sd_mutex_lock(&g_lock);
  g_webclient = SD_WD_CLIENT_RUNNING;
  sd_mutex_unlock(&g_lock);
  if (out) { out->state = SD_WD_CLIENT_RUNNING; out->started_by_us = TRUE; }
  return SD_OK;
}

static sd_err f_wd_start(sd_vfs *vfs, const sd_webdav_mount_cfg *cfg, sd_webdav_mount **out)
{
  wchar_t l;
  SD_UNUSED(vfs);
  if (cfg == NULL || cfg->letter < L'A' || cfg->letter > L'Z')
    return SD_E_INVALID_PARAM;
  l = cfg->letter;
  ensure();
  sd_mutex_lock(&g_lock);
  if (g_letters[l - L'A']) {
    sd_mutex_unlock(&g_lock);
    return SD_E_EXISTS;
  }
  g_letters[l - L'A'] = l;
  sd_mutex_unlock(&g_lock);
  *out = (sd_webdav_mount *)sd_calloc(1, sizeof(sd_webdav_mount));
  if (*out == NULL)
    return SD_E_NO_MEMORY;
  (*out)->letter = l;
  InterlockedIncrement(&g_webdav_mounts);
  return SD_OK;
}

static sd_err f_wd_stop(sd_webdav_mount *m)
{
  ensure();
  sd_mutex_lock(&g_lock);
  g_letters[m->letter - L'A'] = 0;
  sd_mutex_unlock(&g_lock);
  sd_free(m);
  return SD_OK;
}

static sd_err f_wd_cleanup(uint16_t keep, uint16_t only, uint32_t *removed)
{
  SD_UNUSED(keep);
  SD_UNUSED(only);
  if (removed) *removed = 0;
  return SD_OK;
}

static void f_cache_budget(UINT64 bytes) { SD_UNUSED(bytes); InterlockedIncrement(&g_budget_calls); }

static void f_vfs_get_identity(sd_vfs *v, sd_vfs_identity *out)
{
  SD_UNUSED(v);
  *out = g_vfs_ident;
}

static void f_wd_emergency(void) {}

/* "nodokany*" hosts make the next probe fail: wrap session_create to detect them. */
static sd_err f_session_create_wrap(const sd_ssh_config *ssh, const sd_ssh_callbacks *cb, const sd_sftp_options *opt,
                                    sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out)
{
  sd_err e = f_session_create(ssh, cb, opt, ev, ev_ctx, out);
  if (e == SD_OK && starts_with((*out)->host, "nodokany"))
    g_probe_fail_next = 1;
  return e;
}

static const sd_mount_backend k_fake = {
  "fake",
  f_global_init,
  f_kh_open,
  f_kh_close,
  f_session_create_wrap,
  f_session_start,
  f_session_close,
  f_session_destroy,
  f_prompt_answer,
  f_prompt_answer_hostkey,
  f_prompt_cancel,
  f_vfs_mount,
  f_vfs_quiesce,
  f_vfs_unmount,
  f_dokan_probe,
  f_dokan_start,
  f_dokan_stop,
  f_wd_query,
  f_wd_ensure,
  f_wd_start,
  f_wd_stop,
  f_wd_cleanup,
  f_cache_budget,
  f_vfs_get_identity,
  f_wd_emergency,
};

const sd_mount_backend *fake_backend(void)
{
  ensure();
  return &k_fake;
}
