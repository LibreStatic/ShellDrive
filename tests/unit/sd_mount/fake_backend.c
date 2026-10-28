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
  /* M2 */
  char resp2[3][256];             /* every response (password change: current, new, confirm) */
  uint32_t nresp;
  uint32_t flags;                 /* answer flags (SD_ANSWER_FROM_STORE) */
  int ack;                        /* legacy ack: 1 accept */
};

#define FAKE_MAX_HOPS 9
typedef struct fake_hop {
  char host[256]; uint16_t port; char user[128];
  char identity[MAX_PATH * 3];
  uint32_t nidentities, nagent_keys;
  int proxy_kind; char proxy_host[256]; char proxy_user[128]; uint16_t proxy_port;
  int identities_only;
  int hku;
  uint32_t proxy_auth;                  /* SD_PROXY_AUTH_* of the leg (M5) */
  int blob;                             /* an identity given as key bytes (SD_ID_BLOB, M5 service hops) */
  uint32_t auth_methods;                /* SD_AUTH_* of the hop (0 = all three in sd_mount) */
} fake_hop;

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
  /* M2 */
  fake_hop hops[FAKE_MAX_HOPS];
  uint32_t nhops;
  int legacy_policy;
  uint32_t connections;
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
/* TM-R19: no SSPI (SD_WD_E_AUTH_UNAVAILABLE for a non-token-only mount) when set here or by the environment
   variable SHELLDRIVE_TEST_WD_NOAUTH=1 (the agent tests set it); the last cfg seen is recorded. */
static int g_wd_noauth;
static int g_wd_last_token_only, g_wd_last_confirmed;
static volatile LONG g_wd_calls;
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
static volatile LONG g_quiesce_budget = -1;
static volatile LONG g_refresh_calls, g_cache_clears, g_clear_disk, g_wb_dirty;
static sd_vfs_identity g_vfs_ident;
/* M2 */
static fake_hop g_last_hops[FAKE_MAX_HOPS];
static uint32_t g_last_nhops, g_last_connections, g_store_answers, g_applied_add, g_applied_remove, g_apply_calls;
static uint32_t g_apply_machine_calls;
static int g_last_legacy;
static char g_applied_name[300];
static char g_last_new_password[256];

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
  g_wd_noauth = 0;
  g_wd_last_token_only = g_wd_last_confirmed = 0;
  g_wd_calls = 0;
  g_drop_req = -1;
  g_dokan_starts = g_vfs_mounts = g_budget_calls = 0;
  g_vfs_cb = NULL;
  memset(&g_vfs_ident, 0, sizeof(g_vfs_ident));
  g_last_nhops = g_last_connections = g_store_answers = g_applied_add = g_applied_remove = g_apply_calls = 0;
  g_apply_machine_calls = 0;
  g_applied_name[0] = g_last_new_password[0] = 0;
  g_refresh_calls = g_cache_clears = g_clear_disk = g_wb_dirty = 0;
  g_quiesce_budget = -1;
  sd_mutex_unlock(&g_lock);
}

uint32_t fake_backend_last_hop_count(void) { return g_last_nhops; }
const char *fake_backend_last_hop_host(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].host : ""; }
const char *fake_backend_last_hop_user(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].user : ""; }
int fake_backend_last_hop_proxy(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].proxy_kind : -1; }
uint32_t fake_backend_last_hop_identities(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].nidentities : 0; }
uint32_t fake_backend_last_hop_agent_keys(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].nagent_keys : 0; }
int fake_backend_last_hop_identities_only(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].identities_only : -1; }
/* M5: what the service passed per hop (proxy legs, key blobs, host key mode, auth methods) */
const char *fake_backend_last_hop_proxy_host(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].proxy_host : ""; }
const char *fake_backend_last_hop_proxy_user(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].proxy_user : ""; }
uint16_t fake_backend_last_hop_proxy_port(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].proxy_port : 0; }
uint32_t fake_backend_last_hop_proxy_auth(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].proxy_auth : 0; }
int fake_backend_last_hop_blob(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].blob : -1; }
int fake_backend_last_hop_hku(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].hku : -1; }
uint32_t fake_backend_last_hop_auth_methods(uint32_t i) { return i < g_last_nhops ? g_last_hops[i].auth_methods : 0; }
uint32_t fake_backend_last_connections(void) { return g_last_connections; }
int fake_backend_last_legacy_policy(void) { return g_last_legacy; }
uint32_t fake_backend_store_answers(void) { return g_store_answers; }
uint32_t fake_backend_applied(uint32_t *removed, const char **name)
{
  if (removed) *removed = g_applied_remove;
  if (name) *name = g_applied_name;
  return g_applied_add;
}
uint32_t fake_backend_apply_calls(void) { return g_apply_calls; }
uint32_t fake_backend_apply_machine_calls(void) { return g_apply_machine_calls; }
const char *fake_backend_last_new_password(void) { return g_last_new_password; }

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

typedef struct fake_vev { int kind; wchar_t path[260]; UINT64 bytes; PSID sid; char op[16]; } fake_vev;

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
  ev.caller_sid = e->sid;               /* AUDIT only */
  ev.op = e->op;
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

/* M5 audit: a successful change by sid (valid for the call) on the last mounted vfs. */
void fake_backend_vfs_audit(const wchar_t *path, const char *op, PSID sid)
{
  sd_thread t;
  fake_vev *e = (fake_vev *)sd_calloc(1, sizeof(*e));
  if (e == NULL)
    return;
  e->kind = SD_VFS_EV_AUDIT;
  if (path && wcslen(path) < SD_COUNTOF(e->path))
    memcpy(e->path, path, (wcslen(path) + 1) * sizeof(wchar_t));
  e->sid = sid;
  strcpy_s(e->op, sizeof(e->op), op);
  if (sd_thread_create(&t, vfs_event_thread, e, 0, L"fake-vfs") == SD_OK)
    sd_thread_join(&t, SD_WAIT_INFINITE, NULL);
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
void fake_backend_set_webdav_noauth(int on) { g_wd_noauth = on ? 1 : 0; }
uint32_t fake_backend_webdav_calls(void) { return (uint32_t)g_wd_calls; }
int fake_backend_last_webdav_token_only(void) { return g_wd_last_token_only; }
int fake_backend_last_webdav_confirmed(void) { return g_wd_last_confirmed; }
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

void fake_backend_pre_trust(const char *host)
{
  trust(host);
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

static int password_flow_hop(struct sd_sftp_session *s, uint32_t hop, sd_prompt_kind kind, const char *expect,
                             int just_accepted, sd_err *fail)
{
  uint32_t round;
  sd_prompt_item item;
  const fake_hop *h = &s->hops[hop < s->nhops ? hop : 0];
  for (round = 0; round < 2; round++) {
    sd_auth_prompt_info ai;
    struct sd_prompt *p;
    memset(&ai, 0, sizeof(ai));
    ai.kind = kind;
    ai.hop_index = hop;
    ai.host = h->host;
    ai.user = kind == SD_PROMPT_PROXY_PASSWORD ? h->proxy_user : h->user;
    ai.hostkey_just_accepted = just_accepted && kind != SD_PROMPT_KEY_PASSPHRASE;
    if (kind == SD_PROMPT_PROXY_PASSWORD) {
      ai.proxy_host = h->proxy_host;
      ai.proxy_port = h->proxy_port;
    }
    ai.name = "";
    ai.instruction = "";
    item.text = kind == SD_PROMPT_KEY_PASSPHRASE ? "Passphrase: " : "Password: ";
    item.echo = 0;
    ai.items = &item;
    ai.item_count = 1;
    ai.round = round;
    ai.key_path = kind == SD_PROMPT_KEY_PASSPHRASE ? h->identity : NULL;
    ai.key_fingerprint = kind == SD_PROMPT_KEY_PASSPHRASE ? FAKE_FP : NULL;
    p = ask(s, &ai, NULL);
    if (p == NULL) {
      *fail = SD_E_SHUTDOWN;
      return 0;
    }
    if (p->cancelled) {
      *fail = kind == SD_PROMPT_PROXY_PASSWORD ? SD_E_PROXY_AUTH : SD_E_CANCELLED;
      return 0;
    }
    if (strcmp(p->resp, expect) == 0)
      return 1;
  }
  *fail = kind == SD_PROMPT_KEY_PASSPHRASE ? SD_E_BAD_PASSPHRASE
        : kind == SD_PROMPT_PROXY_PASSWORD ? SD_E_PROXY_AUTH : SD_E_AUTH_FAILED;
  return 0;
}

/* keyboard-interactive: a password-shaped round, then an OTP round (FAKE_OTP). */
static int kbdint_flow(struct sd_sftp_session *s, uint32_t hop, int just_accepted, sd_err *fail)
{
  sd_prompt_item item;
  const fake_hop *h = &s->hops[hop];
  uint32_t round, tries = 0;
  for (round = 0; round < 2 && tries < 4; tries++) {
    sd_auth_prompt_info ai;
    struct sd_prompt *p;
    memset(&ai, 0, sizeof(ai));
    ai.kind = SD_PROMPT_KBDINT;
    ai.hop_index = hop;
    ai.host = h->host;
    ai.user = h->user;
    ai.name = "";
    ai.instruction = round == 0 ? "" : "Two-factor authentication";
    item.text = round == 0 ? "Password: " : "Verification code: ";
    item.echo = 0;
    ai.items = &item;
    ai.item_count = 1;
    ai.round = tries;
    ai.hostkey_just_accepted = just_accepted;
    p = ask(s, &ai, NULL);
    if (p == NULL) { *fail = SD_E_SHUTDOWN; return 0; }
    if (p->cancelled) { *fail = SD_E_CANCELLED; return 0; }
    if (strcmp(p->resp, round == 0 ? FAKE_PASSWORD : FAKE_OTP) == 0)
      round++;
  }
  if (round == 2)
    return 1;
  *fail = SD_E_AUTH_FAILED;
  return 0;
}

/* SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: current, new, confirm (01 §6.7). */
static int change_flow(struct sd_sftp_session *s, uint32_t hop, sd_err *fail)
{
  sd_prompt_item items[3];
  sd_auth_prompt_info ai;
  struct sd_prompt *p;
  memset(&ai, 0, sizeof(ai));
  ai.kind = SD_PROMPT_NEW_PASSWORD;
  ai.hop_index = hop;
  ai.host = s->hops[hop].host;
  ai.user = s->hops[hop].user;
  ai.name = "";
  ai.instruction = "Your password has expired.";
  items[0].text = "Current password: "; items[0].echo = 0;
  items[1].text = "New password: "; items[1].echo = 0;
  items[2].text = "Retype new password: "; items[2].echo = 0;
  ai.items = items;
  ai.item_count = 3;
  p = ask(s, &ai, NULL);
  if (p == NULL) { *fail = SD_E_SHUTDOWN; return 0; }
  if (p->cancelled || p->nresp != 3) { *fail = SD_E_CANCELLED; return 0; }
  if (strcmp(p->resp2[0], FAKE_PASSWORD) != 0 || p->resp2[1][0] == 0 || strcmp(p->resp2[1], p->resp2[2]) != 0) {
    *fail = SD_E_AUTH_FAILED;
    return 0;
  }
  sd_mutex_lock(&g_lock);
  strcpy_s(g_last_new_password, sizeof(g_last_new_password), p->resp2[1]);
  sd_mutex_unlock(&g_lock);
  return 1;
}

static int legacy_ack_flow(struct sd_sftp_session *s, uint32_t hop, sd_err *fail)
{
  sd_auth_prompt_info ai;
  struct sd_prompt *p;
  memset(&ai, 0, sizeof(ai));
  ai.kind = SD_PROMPT_LEGACY_ACK;
  ai.hop_index = hop;
  ai.host = s->hops[hop].host;
  ai.user = s->hops[hop].user;
  ai.name = "";
  ai.instruction = "";
  ai.legacy_mask = 1;
  ai.legacy_names = "3des-cbc,hmac-sha1";
  p = ask(s, &ai, NULL);
  if (p == NULL) { *fail = SD_E_SHUTDOWN; return 0; }
  if (p->cancelled || !p->ack) { *fail = SD_E_LEGACY_REJECTED; return 0; }
  return 1;
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
    /* every hop: proxy password (leg with a proxy user), TOFU, legacy ack, then authentication */
    int just_accepted = 0;
    uint32_t hop;
    for (hop = 0; hop < s->nhops && fail == SD_OK; hop++) {
      const fake_hop *h = &s->hops[hop];
      int target = hop + 1 == s->nhops;
      if (h->proxy_kind != SD_PROXY_NONE && h->proxy_user[0])
        password_flow_hop(s, hop, SD_PROMPT_PROXY_PASSWORD, FAKE_PROXY_PASSWORD, just_accepted, &fail);
      if (fail == SD_OK && !fake_backend_is_trusted(h->host)) {
        sd_hostkey_prompt_info hk;
        struct sd_prompt *p;
        memset(&hk, 0, sizeof(hk));
        hk.hop_index = hop;
        hk.host = h->host;
        hk.port = h->port;
        hk.via_host = hop ? s->hops[hop - 1].host : NULL;
        hk.lookup_name = h->host;
        hk.key_type = "ssh-ed25519";
        hk.key_bits = 256;
        hk.fp_sha256 = FAKE_FP;
        hk.fp_md5 = "";
        hk.status = SD_HK_NEW;
        p = ask(s, NULL, &hk);
        if (p == NULL) fail = SD_E_SHUTDOWN;
        else if (p->cancelled || p->decision == SD_HK_REJECT) fail = SD_E_HOSTKEY_REJECTED;
        else {
          if (p->decision == SD_HK_ACCEPT_AND_STORE) trust(h->host);
          just_accepted = 1;
        }
      }
      if (fail == SD_OK && target && starts_with(h->host, "legacy") && s->legacy_policy == SD_LEGACY_ASK)
        legacy_ack_flow(s, hop, &fail);
      if (fail == SD_OK && target && starts_with(h->host, "legacy") && s->legacy_policy == SD_LEGACY_REFUSE)
        fail = SD_E_LEGACY_REJECTED;
      if (fail != SD_OK) break;
      if (target && starts_with(h->host, "kbd"))
        kbdint_flow(s, hop, just_accepted, &fail);
      else if (h->identity[0] && strstr(h->identity, "encrypted"))
        password_flow_hop(s, hop, SD_PROMPT_KEY_PASSPHRASE, FAKE_PASSPHRASE, just_accepted, &fail);
      else if (h->identity[0] == 0 && h->nidentities == 0)
        password_flow_hop(s, hop, SD_PROMPT_PASSWORD, FAKE_PASSWORD, just_accepted, &fail);
      if (fail == SD_OK && target && starts_with(h->host, "chpw"))
        change_flow(s, hop, &fail);
      if (fail == SD_OK) {
        sd_ssh_negotiated n;
        memset(&n, 0, sizeof(n));
        n.hop_index = hop;
        n.kex = "curve25519-sha256";
        n.hostkey = "ssh-ed25519";
        n.cipher_c2s = n.cipher_s2c = target && starts_with(h->host, "legacy") ? "3des-cbc" : "aes256-gcm@openssh.com";
        n.mac_c2s = n.mac_s2c = target && starts_with(h->host, "legacy") ? "hmac-sha1" : "";
        n.legacy_mask = target && starts_with(h->host, "legacy") ? 3u : 0u;
        n.hostkey_fp_sha256 = FAKE_FP;
        if (s->cb.on_negotiated)
          s->cb.on_negotiated(s->cb.ctx, &n);
      }
    }
  }
  if (fail == SD_OK && !s->close_req) {
    emit_state(s, SD_SFTP_ST_READY, SD_OK);
    if (s->nhops && starts_with(s->hops[s->nhops - 1].host, "rotate") && s->cb.on_hostkey_event) {
      /* UpdateHostKeys: one proven new key, one key no longer offered (5.6) */
      static const uint8_t add_blob[] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 1, 0xA1 };
      static const uint8_t rem_blob[] = { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 1, 0xB2 };
      sd_hostkey_event he;
      sd_hk_key add, rem;
      memset(&he, 0, sizeof(he));
      add.blob = add_blob; add.len = sizeof(add_blob); add.type = "ssh-ed25519";
      add.fp_sha256 = "SHA256:newnewnewnewnewnewnewnewnewnewnewnewnew0";
      rem.blob = rem_blob; rem.len = sizeof(rem_blob); rem.type = "ssh-rsa";
      rem.fp_sha256 = "SHA256:oldoldoldoldoldoldoldoldoldoldoldoldold00";
      he.kind = SD_HKEV_ANNOUNCED;
      he.hop_index = s->nhops - 1;
      he.lookup_name = s->hops[s->nhops - 1].host;
      he.store = SD_KH_STORE_USER;
      he.add = &add; he.add_count = 1;
      he.remove = &rem; he.remove_count = 1;
      s->cb.on_hostkey_event(s->cb.ctx, &he);
    }
    if (s->connections > 1 && s->nhops > 0) {
      /* the pool (D18): one member, which asks for the password: answered from the store or cancelled */
      uint32_t hi = s->nhops - 1;
      sd_auth_prompt_info ai;
      sd_prompt_item item;
      struct sd_prompt *p;
      sd_sftp_event ev;
      memset(&ai, 0, sizeof(ai));
      ai.kind = SD_PROMPT_PASSWORD;
      ai.hop_index = hi;
      ai.host = s->hops[hi].host;
      ai.user = s->hops[hi].user;
      ai.name = ai.instruction = "";
      item.text = "Password: ";
      item.echo = 0;
      ai.items = &item;
      ai.item_count = 1;
      ai.is_pool_member = 1;
      p = ask(s, &ai, NULL);
      memset(&ev, 0, sizeof(ev));
      ev.type = SD_SFTP_EV_POOL;
      ev.member = 1;
      ev.connections = (p && !p->cancelled && strcmp(p->resp, FAKE_PASSWORD) == 0) ? 2 : 1;
      s->ev(s->ev_ctx, &ev);
    }
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
  if (ssh == NULL || ssh->hop_count < 1 || ssh->hop_count > FAKE_MAX_HOPS || ssh->struct_size != sizeof(sd_ssh_config))
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
  {
    uint32_t i, k;
    const sd_ssh_hop *t = &ssh->hops[ssh->hop_count - 1];
    s->nhops = ssh->hop_count;
    s->legacy_policy = ssh->algos.legacy_policy;
    s->connections = opt ? opt->connections : 1;
    for (i = 0; i < ssh->hop_count; i++) {
      const sd_ssh_hop *sh = &ssh->hops[i];
      fake_hop *h = &s->hops[i];
      to_utf8(sh->host, h->host, sizeof(h->host));
      h->port = sh->port;
      if (sh->auth.user && strlen(sh->auth.user) < sizeof(h->user))
        memcpy(h->user, sh->auth.user, strlen(sh->auth.user) + 1);
      for (k = 0; k < sh->auth.identity_count; k++) {
        if (sh->auth.identities[k].kind == SD_ID_AGENT_KEY) h->nagent_keys++;
        else h->nidentities++;
        if (sh->auth.identities[k].kind == SD_ID_FILE && h->identity[0] == 0)
          to_utf8(sh->auth.identities[k].path, h->identity, sizeof(h->identity));
        if (sh->auth.identities[k].kind == SD_ID_BLOB)
          h->blob = 1;
      }
      h->identities_only = sh->auth.identities_only;
      h->auth_methods = sh->auth.methods;
      h->proxy_kind = sh->proxy.kind;
      h->proxy_port = sh->proxy.port;
      h->proxy_auth = sh->proxy.auth;
      if (sh->proxy.host)
        to_utf8(sh->proxy.host, h->proxy_host, sizeof(h->proxy_host));
      if (sh->proxy.user && strlen(sh->proxy.user) < sizeof(h->proxy_user))
        memcpy(h->proxy_user, sh->proxy.user, strlen(sh->proxy.user) + 1);
      h->hku = sh->update_host_keys;
    }
    to_utf8(t->host, s->host, sizeof(s->host));
    s->port = t->port;
    memcpy(s->user, s->hops[ssh->hop_count - 1].user, sizeof(s->user));
    memcpy(s->identity, s->hops[ssh->hop_count - 1].identity, sizeof(s->identity));
    sd_mutex_lock(&g_lock);
    memcpy(g_last_hops, s->hops, sizeof(g_last_hops));
    g_last_nhops = s->nhops;
    g_last_connections = s->connections;
    g_last_legacy = s->legacy_policy;
    sd_mutex_unlock(&g_lock);
  }
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

static sd_err finish_prompt_ex(sd_prompt *p, int cancelled, sd_hostkey_decision d, uint32_t n,
                               const char *const *r, uint32_t flags, int ack)
{
  struct sd_sftp_session *s = p->s;
  uint32_t i;
  sd_mutex_lock(&s->lock);
  if (p->done) {
    sd_mutex_unlock(&s->lock);
    return SD_E_CANCELLED;
  }
  p->done = 1;
  p->cancelled = cancelled;
  p->decision = d;
  p->flags = flags;
  p->ack = ack;
  for (i = 0; r && i < n && i < 3; i++) {
    size_t k = strlen(r[i]);
    if (k >= sizeof(p->resp2[0])) k = sizeof(p->resp2[0]) - 1;
    memcpy(p->resp2[i], r[i], k);
    p->resp2[i][k] = 0;
  }
  p->nresp = r ? (n < 3 ? n : 3) : 0;
  if (r && n) memcpy(p->resp, p->resp2[0], sizeof(p->resp));
  sd_mutex_unlock(&s->lock);
  if (flags & SD_ANSWER_FROM_STORE) InterlockedIncrement((volatile LONG *)&g_store_answers);
  SetEvent(s->wake);
  return SD_OK;
}

static sd_err finish_prompt(sd_prompt *p, int cancelled, sd_hostkey_decision d, const char *resp)
{
  const char *r[1];
  r[0] = resp;
  return finish_prompt_ex(p, cancelled, d, resp ? 1 : 0, resp ? r : NULL, 0, 0);
}

static sd_err f_prompt_answer(sd_prompt *p, uint32_t n, const char *const *r)
{
  return finish_prompt_ex(p, 0, SD_HK_REJECT, n, r, 0, 0);
}

static sd_err f_prompt_answer_ex(sd_prompt *p, uint32_t n, const char *const *r, uint32_t flags)
{
  return finish_prompt_ex(p, 0, SD_HK_REJECT, n, r, flags, 0);
}

static sd_err f_prompt_answer_ack(sd_prompt *p, int accept)
{
  return finish_prompt_ex(p, 0, SD_HK_REJECT, 0, NULL, 0, accept);
}

static sd_err f_kh_apply(sd_known_hosts *kh, sd_kh_store_kind target, const char *name, const sd_hk_key *add,
                         uint32_t add_count, const sd_hk_key *remove, uint32_t remove_count)
{
  SD_UNUSED(kh);
  SD_UNUSED(add);
  SD_UNUSED(remove);
  /* the user store (5.6) and, for the service (M5 hostkey add), the machine store; anything else is refused */
  if (target != SD_KH_STORE_USER && target != SD_KH_STORE_MACHINE)
    return SD_E_ACCESS_DENIED;
  sd_mutex_lock(&g_lock);
  g_applied_add += add_count;
  g_applied_remove += remove_count;
  g_apply_calls++;
  if (target == SD_KH_STORE_MACHINE)
    g_apply_machine_calls++;
  strncpy_s(g_applied_name, sizeof(g_applied_name), name ? name : "", _TRUNCATE);
  sd_mutex_unlock(&g_lock);
  if (add_count) trust(name);
  return SD_OK;
}

static sd_err f_key_unprotect(const uint8_t *bytes, size_t len, const char *id, sd_secbuf **out)
{
  SD_UNUSED(id);
  if (len < 8 || memcmp(bytes, "SDKEY1", 6) != 0)
    return SD_E_KEY_FORMAT;
  return sd_secbuf_from(bytes + 8, len - 8, out);
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

static void f_vfs_quiesce(sd_vfs *v, DWORD budget) { SD_UNUSED(v); InterlockedExchange(&g_quiesce_budget, (LONG)budget); }
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
  {
    wchar_t nv[8];
    int noauth = g_wd_noauth || (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_WD_NOAUTH", nv, 8) > 0 && nv[0] == L'1');
    InterlockedIncrement(&g_wd_calls);
    g_wd_last_token_only = cfg->token_only ? 1 : 0;
    g_wd_last_confirmed = cfg->token_only_confirmed ? 1 : 0;
    if (noauth && !cfg->token_only)
      return SD_WD_E_AUTH_UNAVAILABLE;
  }
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

/* M3 fakes: profile.test probe, stats, refresh, cache clear, write-behind bytes, WebDAV port */

static sd_err f_session_probe(sd_sftp_session *s, const char *remote, uint32_t timeout_ms, sd_mount_probe *out)
{
  SD_UNUSED(timeout_ms);
  if (starts_with(s->host, "probefail"))
    return SD_E_NOT_FOUND;
  strcpy_s(out->kex, sizeof(out->kex), "curve25519-sha256");
  strcpy_s(out->hostkey, sizeof(out->hostkey), "ssh-ed25519");
  strcpy_s(out->cipher_c2s, sizeof(out->cipher_c2s), "chacha20-poly1305@openssh.com");
  strcpy_s(out->cipher_s2c, sizeof(out->cipher_s2c), "chacha20-poly1305@openssh.com");
  strcpy_s(out->mac_c2s, sizeof(out->mac_c2s), "");
  strcpy_s(out->mac_s2c, sizeof(out->mac_s2c), "");
  strcpy_s(out->hostkey_fp, sizeof(out->hostkey_fp), FAKE_FP);
  strcpy_s(out->server_version, sizeof(out->server_version), "FakeSSH_1.0");
  strcpy_s(out->remote_real, sizeof(out->remote_real), (remote && remote[0]) ? remote : "/home/fake");
  return SD_OK;
}

static void f_session_stats(const sd_sftp_session *s, sd_mount_stats *out)
{
  SD_UNUSED(s);
  out->srtt_ms = 12;
  out->rttvar_ms = 3;
  out->rx_bps = 2048;
  out->tx_bps = 512;
  out->rx_total = 4096;
  out->tx_total = 1024;
  out->inflight = 2;
  out->queued = 1;
  out->channels = 1;
  out->generation = 1;
  out->members = 1;
  out->member[0].ready = 1;
  out->member[0].srtt_ms = 12;
  out->member[0].inflight = 2;
  out->member[0].queued = 1;
  out->member[0].rx_total = 4096;
  out->member[0].tx_total = 1024;
}

static void f_vfs_stats(sd_vfs *v, sd_mount_stats *out)
{
  SD_UNUSED(v);
  out->cache_hits = 7;
  out->cache_misses = 5;
  out->bytes_rd = 4096;
  out->bytes_wr = 0;
  out->write_failed = 0;
  out->reconnects = 0;
}

static void f_vfs_refresh(sd_vfs *v, const wchar_t *subtree)
{
  SD_UNUSED(v);
  SD_UNUSED(subtree);
  InterlockedIncrement(&g_refresh_calls);
}

static void f_vfs_cache_clear(sd_vfs *v, int disk_too)
{
  SD_UNUSED(v);
  InterlockedIncrement(&g_cache_clears);
  InterlockedExchange(&g_clear_disk, disk_too ? 1 : 0);
}

static UINT64 f_wb_bytes(sd_vfs *v)
{
  SD_UNUSED(v);
  return (UINT64)g_wb_dirty;
}

static uint16_t f_webdav_port(const sd_webdav_mount *m)
{
  SD_UNUSED(m);
  return 49321;
}

void fake_backend_set_wb_dirty(UINT64 bytes) { InterlockedExchange(&g_wb_dirty, (LONG)bytes); }
uint32_t fake_backend_refresh_calls(void) { return (uint32_t)g_refresh_calls; }
uint32_t fake_backend_cache_clears(int *disk_too) { if (disk_too) *disk_too = (int)g_clear_disk; return (uint32_t)g_cache_clears; }
int fake_backend_last_quiesce_budget(void) { return (int)g_quiesce_budget; }

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
  f_prompt_answer_ex,
  f_prompt_answer_ack,
  f_kh_apply,
  f_key_unprotect,
  f_session_probe,
  f_session_stats,
  f_vfs_stats,
  f_vfs_refresh,
  f_vfs_cache_clear,
  f_wb_bytes,
  f_webdav_port,
};

const sd_mount_backend *fake_backend(void)
{
  ensure();
  return &k_fake;
}

/* ---- M5 hostkey add (tests/unit/sd_svc): the fake table plus a scripted hostkey connection ----
   Scripted by the host name, as tests/apps/host_fake_backend.c does for the smoke tests:
   *.known.test    a stored key verifies the connection; the server has an ECDSA and an ssh-rsa key besides it
   *.changed.test  the stored key does not match (SD_E_HOSTKEY_MISMATCH)
   anything else   first contact: the server presents one ssh-ed25519 key (TOFU, 5.2, taken by the mount)
   A jump hop whose host is not trusted (fake_backend_pre_trust) raises a host-key prompt for that hop first; the
   connection waits for its answer and fails with SD_E_HOSTKEY_REJECTED when it is rejected or cancelled. */

typedef struct fake_hk {
  char host[256];
  sd_ssh_callbacks cb;
  int first;
  int changed;
  uint32_t hop_count;
  int jump_hop;                                        /* first untrusted jump hop, -1 = none */
  char jump_host[256];
  sd_ssh_done_cb done;                                 /* pending while the jump prompt is open */
  void *done_ctx;
  uint8_t ed[4 + 11 + 4 + 32];
  size_t ed_len;
  char ed_fp[64];
} fake_hk;

static char k_fake_hk_marker;                          /* the prompt object the hostkey connection raises */
static char k_fake_hk_jump_marker;                     /* the prompt of an untrusted jump hop */
static fake_hk *k_fake_hk_pending;                     /* the connection waiting for that answer (tests are serial) */
static uint32_t k_fake_hk_jump_prompts;
static sd_mount_backend k_fake_hk_table;
static int k_fake_hk_ready;

uint32_t fake_backend_hk_jump_prompts(void) { return k_fake_hk_jump_prompts; }

static void fk_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static size_t fk_str(uint8_t *p, size_t at, const void *s, size_t n)
{
  fk_u32(p + at, (uint32_t)n);
  memcpy(p + at + 4, s, n);
  return at + 4 + n;
}

static int fk_ends_with(const char *s, const char *suffix)
{
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && _stricmp(s + n - m, suffix) == 0;
}

static void fk_connect_target(fake_hk *c, sd_ssh_done_cb done, void *ctx);

/* The answer to the jump prompt resumes (or fails) the pending connection. */
static void fk_jump_answered(int accepted)
{
  fake_hk *c = k_fake_hk_pending;
  sd_ssh_done_cb done;
  void *ctx;
  if (c == NULL)
    return;
  k_fake_hk_pending = NULL;
  done = c->done;
  ctx = c->done_ctx;
  c->done = NULL;
  if (!accepted)
    done(ctx, SD_E_HOSTKEY_REJECTED, (uint32_t)c->jump_hop);
  else
    fk_connect_target(c, done, ctx);
}

static sd_err fk_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d)
{
  if ((void *)p == (void *)&k_fake_hk_marker)
    return SD_OK;
  if ((void *)p == (void *)&k_fake_hk_jump_marker) {
    fk_jump_answered(d != SD_HK_REJECT);
    return SD_OK;
  }
  return f_prompt_answer_hostkey(p, d);
}

static sd_err fk_prompt_cancel(sd_prompt *p)
{
  if ((void *)p == (void *)&k_fake_hk_marker)
    return SD_OK;
  if ((void *)p == (void *)&k_fake_hk_jump_marker) {
    fk_jump_answered(0);
    return SD_OK;
  }
  return f_prompt_cancel(p);
}

static sd_err fk_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out)
{
  fake_hk *c = (fake_hk *)sd_calloc(1, sizeof(*c));
  const sd_ssh_hop *last;
  uint8_t pk[32];
  uint32_t i;
  if (c == NULL)
    return SD_E_NO_MEMORY;
  last = &cfg->hops[cfg->hop_count - 1];
  WideCharToMultiByte(CP_UTF8, 0, last->host, -1, c->host, sizeof(c->host), NULL, NULL);
  c->cb = *cb;
  c->hop_count = cfg->hop_count;
  c->jump_hop = -1;
  for (i = 0; i + 1 < cfg->hop_count && c->jump_hop < 0; i++) {
    WideCharToMultiByte(CP_UTF8, 0, cfg->hops[i].host, -1, c->jump_host, sizeof(c->jump_host), NULL, NULL);
    if (!fake_backend_is_trusted(c->jump_host))
      c->jump_hop = (int)i;
  }
  c->changed = fk_ends_with(c->host, ".changed.test");
  c->first = !c->changed && !fk_ends_with(c->host, ".known.test");
  memset(pk, 0x33, sizeof(pk));
  c->ed_len = fk_str(c->ed, 0, "ssh-ed25519", 11);
  c->ed_len = fk_str(c->ed, c->ed_len, pk, sizeof(pk));
  /* a label only: the service recomputes every fingerprint from the blob (sd_ssh is not linked into this fake) */
  strcpy_s(c->ed_fp, sizeof(c->ed_fp), "SHA256:ed25519-fake");
  *out = (sd_ssh_conn *)c;
  return SD_OK;
}

static void fk_connect_target(fake_hk *c, sd_ssh_done_cb done, void *ctx)
{
  if (c->changed) {
    done(ctx, SD_E_HOSTKEY_MISMATCH, c->hop_count - 1);
    return;
  }
  if (c->first) {
    sd_hostkey_prompt_info hk;
    memset(&hk, 0, sizeof(hk));
    hk.hop_index = c->hop_count - 1;
    hk.host = c->host;
    hk.port = 22;
    hk.lookup_name = c->host;
    hk.key_type = "ssh-ed25519";
    hk.key_bits = 256;
    hk.fp_sha256 = c->ed_fp;
    hk.fp_md5 = "";
    hk.status = SD_HK_NEW;
    hk.blob = c->ed;
    hk.blob_len = c->ed_len;
    c->cb.on_prompt(c->cb.ctx, (sd_prompt *)&k_fake_hk_marker, NULL, &hk);
  }
  done(ctx, SD_OK, 0);
}

static sd_err fk_connect(sd_ssh_conn *cc, sd_ssh_done_cb done, void *ctx)
{
  fake_hk *c = (fake_hk *)cc;
  if (c->jump_hop >= 0) {
    sd_hostkey_prompt_info hk;
    memset(&hk, 0, sizeof(hk));
    hk.hop_index = (uint32_t)c->jump_hop;
    hk.host = c->jump_host;
    hk.port = 22;
    hk.lookup_name = c->jump_host;
    hk.key_type = "ssh-ed25519";
    hk.key_bits = 256;
    hk.fp_sha256 = c->ed_fp;
    hk.fp_md5 = "";
    hk.status = SD_HK_NEW;
    hk.blob = c->ed;
    hk.blob_len = c->ed_len;
    c->done = done;
    c->done_ctx = ctx;
    k_fake_hk_pending = c;
    k_fake_hk_jump_prompts++;
    c->cb.on_prompt(c->cb.ctx, (sd_prompt *)&k_fake_hk_jump_marker, NULL, &hk);
    return SD_OK;
  }
  fk_connect_target(c, done, ctx);
  return SD_OK;
}

static sd_err fk_fetch(sd_ssh_conn *cc, uint32_t hop, const char *const *types, uint32_t ntypes,
                       sd_ssh_hostkeys_cb done, void *ctx)
{
  static uint8_t blob_ec[600], blob_rsa[600];
  static sd_hk_key keys[2];
  static const char *const fp_ec = "SHA256:ecdsa-fake", *const fp_rsa = "SHA256:rsa-fake";
  static const uint8_t e65537[3] = { 0x01, 0x00, 0x01 };
  uint8_t pt[65], mod[256];
  fake_hk *c = (fake_hk *)cc;
  size_t n;
  uint32_t i, k = 0, want_ec = 1, want_rsa = 1;
  SD_UNUSED(hop);
  if (c->first) {
    done(ctx, SD_E_HOSTKEY_REJECTED, NULL, 0);
    return SD_OK;
  }
  if (ntypes) {
    want_ec = want_rsa = 0;
    for (i = 0; i < ntypes; i++) {
      if (strcmp(types[i], "ecdsa-sha2-nistp256") == 0) want_ec = 1;
      if (strcmp(types[i], "ssh-rsa") == 0) want_rsa = 1;
    }
  }
  memset(pt, 0x11, sizeof(pt));
  pt[0] = 0x04;
  n = fk_str(blob_ec, 0, "ecdsa-sha2-nistp256", 19);
  n = fk_str(blob_ec, n, "nistp256", 8);
  n = fk_str(blob_ec, n, pt, sizeof(pt));
  if (want_ec) {
    keys[k].blob = blob_ec; keys[k].len = n; keys[k].type = "ecdsa-sha2-nistp256"; keys[k].fp_sha256 = fp_ec; k++;
  }
  memset(mod, 0x5a, sizeof(mod));
  n = fk_str(blob_rsa, 0, "ssh-rsa", 7);
  n = fk_str(blob_rsa, n, e65537, sizeof(e65537));
  n = fk_str(blob_rsa, n, mod, sizeof(mod));
  if (want_rsa) {
    keys[k].blob = blob_rsa; keys[k].len = n; keys[k].type = "ssh-rsa"; keys[k].fp_sha256 = fp_rsa; k++;
  }
  done(ctx, SD_OK, keys, k);
  return SD_OK;
}

static void fk_destroy(sd_ssh_conn *cc)
{
  if (k_fake_hk_pending == (fake_hk *)cc)
    k_fake_hk_pending = NULL;
  sd_free(cc);
}

const sd_mount_backend *fake_backend_hostkeys(void)
{
  ensure();
  if (!k_fake_hk_ready) {
    k_fake_hk_table = k_fake;
    k_fake_hk_table.prompt_answer_hostkey = fk_prompt_answer_hostkey;
    k_fake_hk_table.prompt_cancel = fk_prompt_cancel;
    k_fake_hk_table.hk_conn_create = fk_create;
    k_fake_hk_table.hk_conn_connect = fk_connect;
    k_fake_hk_table.hk_conn_fetch = fk_fetch;
    k_fake_hk_table.hk_conn_destroy = fk_destroy;
    k_fake_hk_ready = 1;
  }
  return &k_fake_hk_table;
}
