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
 * M2: the profile's connection chain (sd_chain_resolve: ProxyJump hops, a proxy per leg, identities,
 * DPAPI-kept keys, agents, D37), the known_hosts store list with the live sources of settings.ini
 * (5.1), legacy policy and the legacy_algorithms warning (filtered by security.legacy_accepted),
 * the pool size, saved secrets (sd_secret: prompts answered from Credential Manager / DPAPI by
 * sd_mount, "save" answers kept after a successful login with the comment the client localized),
 * the new prompt kinds (password_change, legacy_ack, proxy_password) and UpdateHostKeys
 * announcements: "hostkeys.announced" events, hostkey.announced.list / .accept (5.6).
 *
 * M3: the prompt broker (03 §2.5, §3.2, §3.3; docs/dev/m3-notes.md): every prompt has a record until its
 * prompt.closed; routing to the initiator and the prompt UI subscribers with delivery accounting, a queue of 16
 * drained on subscribe, deadlines checked by the control thread once a second, and the initiator-disconnect rule.
 * Also the read-only methods status, selftest, log.tail (log_ring.c), config.reload, prompt.list and the warnings of list.
 *
 * M0 gaps (documented in docs/dev/m0-notes.md by the lead): no hidden window (WM_ENDSESSION, WTS
 * and power notifications), no prompt queue while locked, no UI launch for prompts, no autostart. */
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>

#include "host.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_policy/sd_policy.h"
#include "sd_secret/sd_secret.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

#include "log_ring.h"
#include "state_producer.h"
#include "explorer_data.h"
#include "config_watch.h"
#include "update_ipc.h"
#include "sd_state/sd_state.h"

typedef struct work { struct work *next; void (*fn)(void *); void *arg; } work;

/* M2: what sd_mount_create needs for the chain; freed once sd_mount_create copied it. */
typedef struct host_chain {
  uint32_t count;
  sd_mount_hop hop[SD_MOUNT_MAX_HOPS];
  wchar_t host[SD_MOUNT_MAX_HOPS][256];
  char user[SD_MOUNT_MAX_HOPS][128];
  wchar_t ident[SD_MOUNT_MAX_HOPS][SD_MOUNT_MAX_IDENTITIES][MAX_PATH];
  const wchar_t *ident_ptr[SD_MOUNT_MAX_HOPS][SD_MOUNT_MAX_IDENTITIES];
  wchar_t cert[SD_MOUNT_MAX_HOPS][MAX_PATH];
  char agent_keys[SD_MOUNT_MAX_HOPS][512];
  char alias[SD_MOUNT_MAX_HOPS][256];
  sd_secbuf *key[SD_MOUNT_MAX_HOPS];
  char key_label[SD_MOUNT_MAX_HOPS][64];
  wchar_t proxy_host[SD_MOUNT_MAX_HOPS][256];
  char proxy_user[SD_MOUNT_MAX_HOPS][128];
  sd_kh_store stores[4];
  uint32_t nstores;
  wchar_t machine_kh[MAX_PATH];
} host_chain;

/* A pending UpdateHostKeys announcement (5.6, update_host_keys = ask). */
typedef struct host_announce {
  struct host_announce *next;
  char id[16];                  /* "a-<n>" */
  char mount_id[16];
  sd_mount_announcement a;
} host_announce;

/* M3 status proxy_legs: one proxy of the chain (no credentials). */
typedef struct host_leg {
  uint32_t hop;                 /* 1-based hop the leg reaches */
  int kind;                     /* sd_proxy_kind */
  char host[256];
  uint16_t port;
} host_leg;

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
  /* M2 */
  host_chain *chain;            /* owned until sd_mount_create */
  char legacy_accepted[80];     /* security.legacy_accepted of the profile */
  int scope;                    /* SD_PROFILE_SCOPE_* of the profile: `list` scope */
  wchar_t save_comment[256];    /* Credential Manager comment, localized by the client */
  uint32_t hop_count;
  /* M3 */
  uint32_t initiator_caps;      /* SD_IPC_CAP_* of the initiator when it asked for the mount */
  int network_location;         /* profile mount.network_location (03 §8.7) */
  int open_after, opened;       /* mount.open_after_mount (or the mount open request): opened at the first MOUNTED */
  /* M3 (profile.test, status, unmount force) */
  int test_only;                /* profile.test: not in `list`, the snapshot, Explorer or mount.state */
  int stop_force;               /* unmount {force}: the write-behind drain gets no budget */
  uint64_t defer_cid;           /* profile.test: the client waiting for the reply (0 = none) */
  int64_t defer_rid;            /* its request id */
  uint32_t nlegs;               /* proxy legs of the chain, for status proxy_legs */
  host_leg legs[SD_MOUNT_MAX_HOPS];
  /* M5 hostkey add (test = 2): the request fields the reply needs (hk = 1) */
  int hk;
  char hk_lookup[300];
  char hk_type[64];
  char hk_expect[96];
} host_mount;

/* ---- M3 constants (03 §2.5, §3.3, 1.7.4) ---- */
#define PROMPT_QUEUE_MAX      16u
#define PROMPT_DEADLINE_MS    120000u     /* user-initiated prompts */
#define PROMPT_RECONNECT_MS   600000u     /* prompts raised by a reconnect */
#define UI_LAUNCH_INTERVAL_MS 30000u      /* at most one prompt-UI launch per 30 s */
#define WARN_RING             32u         /* recent warnings kept for `list` */
#define EVENT_RING            200u        /* recent events kept for `events.recent` (03 §2.4, 7.7) */

/* Feature names of the hello reply (03 §7, 2.8): only what this build implements. */
static const char *const k_agent_features[] = {
  "status", "config.reload", "log.tail", "selftest", "prompt.list", "prompt.queued",
  "refresh", "cache.clear", "profile.test", "mount.attach_info", "status.stats", "status.proxy_legs",
  "config.changed", "agent.stopping", "update", "update.check", "update.apply", "diag.collect", "events.recent", NULL
};

#ifdef SD_HOST_TEST_HOOKS
/* tests: prompt deadlines and queue size can be shortened through the environment */
static uint32_t env_u32(const wchar_t *name, uint32_t def)
{
  wchar_t v[16];
  uint32_t n = 0;
  const wchar_t *p;
  if (GetEnvironmentVariableW(name, v, SD_COUNTOF(v)) - 1u >= SD_COUNTOF(v) - 1u)
    return def;
  for (p = v; *p >= L'0' && *p <= L'9'; p++)
    n = n * 10u + (uint32_t)(*p - L'0');
  return n ? n : def;
}
#endif

typedef struct host_warn { char code[40]; char mount_id[16]; } host_warn;

/* One event of the agent's history (03 §2.4 events.recent): the mount.state, warning and hostkeys.announced events
   the clients get, as short records. Oldest records are dropped first; seq is never reused in this process. */
typedef struct host_event {
  uint64_t seq;
  int64_t time;                 /* unix seconds */
  char event[24];
  char mount_id[16];
  char state[24];              /* mount.state: the new state */
  char code[40];               /* error or warning code; "" when none */
} host_event;

/* M3 prompt record (03 §3.2): from the sd_mount prompt until its prompt.closed. */
typedef struct host_prompt {
  struct host_prompt *next;
  sd_mount *m;
  uint32_t prompt_id;           /* sd_mount's id */
  char pid[32];                 /* "p-<mount num>-<prompt id>" */
  char mount_id[16];
  char profile_id[33];
  char kind[24];
  uint64_t initiator;           /* client that asked for the mount when raised (0 = none) */
  int queued;                   /* 1: not delivered to any client yet */
  int expire;                   /* deadline passed or evicted: rejected by the next flush */
  int answering;                /* a reject is in flight */
  uint64_t deadline;            /* sd_tick_ms() */
  uint64_t seq;                 /* queue order */
  const char *reason;           /* answered | cancelled | timeout | superseded; NULL = cancelled */
  const char *answered_by;      /* "cli" | "ui" once a client answered */
  char *body;                   /* the prompt.request data object without its closing brace */
  size_t body_len;
} host_prompt;

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
  /* M2 */
  host_announce *announces;
  uint32_t next_announce;
  wchar_t user_kh[MAX_PATH];
  /* M3 */
  host_prompt *prompts;         /* open and queued prompts */
  uint64_t prompt_seq;
  uint32_t prompt_queue_max;    /* PROMPT_QUEUE_MAX (test hook: SHELLDRIVE_TEST_PROMPT_QUEUE_MAX) */
  uint64_t prompt_ms, reconnect_prompt_ms;
  int no_route;                 /* test hook: prompts are never routed (queue tests) */
  uint64_t last_ui_launch;      /* tick of the last prompt-UI launch attempt; 0 = never */
  int ui_launch;                /* 0 in test builds unless SHELLDRIVE_TEST_UI_LAUNCH=1: tests never start a UI */
  host_warn warns[WARN_RING];
  uint32_t warn_next, warn_count;
  /* event history: its own lock, a leaf (taken while g.lock may be held, never the other way round) */
  sd_mutex evlock;
  host_event events[EVENT_RING];
  uint32_t event_next, event_count;
  uint64_t event_seq;
  uint64_t boot_tick;           /* log.tail cursor boot id */
  /* M3 agent.stopping reason: "request", "event" or "idle" */
  const char *stop_reason;
} g;

/* forward declarations: the prompt broker and the warning ring are defined further down */
static void prompt_drop_mount(sd_mount *m);
static void remember_warning(const char *code, const char *mount_id);

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

/* Appends one event to the history (03 §2.4 events.recent). Callers may hold g.lock: evlock is a leaf. */
static void record_event(const char *event, const char *mount_id, const char *state, const char *code)
{
  host_event *e;
  sd_mutex_lock(&g.evlock);
  e = &g.events[g.event_next];
  e->seq = ++g.event_seq;
  e->time = sd_unix_time_now();
  scopy(e->event, sizeof(e->event), event);
  scopy(e->mount_id, sizeof(e->mount_id), mount_id);
  scopy(e->state, sizeof(e->state), state);
  scopy(e->code, sizeof(e->code), code);
  g.event_next = (g.event_next + 1u) % EVENT_RING;
  if (g.event_count < EVENT_RING)
    g.event_count++;
  sd_mutex_unlock(&g.evlock);
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

static void free_chain(host_chain *c)
{
  uint32_t i;
  if (c == NULL)
    return;
  for (i = 0; i < SD_MOUNT_MAX_HOPS; i++)
    sd_secbuf_free(c->key[i]);
  sd_secure_zero(c, sizeof(*c));
  sd_free(c);
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
  if (c.pool || c.pool_wanted > 1) {
    /* pool size and the requested one (03 §2.4 status detail; the 2FA rule shows as pool < wanted) */
    sd_jw_key(jw, "pool"); sd_jw_int(jw, c.pool);
    if (c.pool_wanted > 1) {
      sd_jw_key(jw, "pool_wanted"); sd_jw_int(jw, c.pool_wanted);
    }
  }
  sd_jw_obj_end(jw);
  sd_jw_key(jw, "write_failed"); sd_jw_int(jw, c.write_failed);
  if (c.write_failed) {
    sd_jw_key(jw, "last_write_failed"); jw_wstr(jw, c.last_write_failed);
  }
}

/* `list` scope (03 §2.3): user (the user's own profile), machine_template (scope = users, read-only templates
   from sd_config) or global (scope = service, the Global drives group). */
static const char *scope_name(int scope)
{
  switch (scope) {
  case SD_PROFILE_SCOPE_USERS: return "machine_template";
  case SD_PROFILE_SCOPE_SERVICE: return "global";
  default: return "user";
  }
}

/* Names of the store kinds of a host key (03 §2.4 error.store_kind, 5.4): machine, user, openssh, putty. */
static const char *store_kind_name(sd_kh_store_kind k)
{
  switch (k) {
  case SD_KH_STORE_MACHINE: return "machine";
  case SD_KH_STORE_USER: return "user";
  case SD_KH_SRC_OPENSSH: return "openssh";
  case SD_KH_SRC_PUTTY: return "putty";
  }
  return "unknown";
}

/* A comma list as a JSON array of its non-empty items (stored and offered key types). */
static void write_csv_array(sd_json_writer *jw, const char *key, const char *csv)
{
  char buf[256];
  char *t, *ctx = NULL;
  sd_jw_key(jw, key);
  sd_jw_arr_begin(jw);
  scopy(buf, sizeof(buf), csv ? csv : "");
  for (t = strtok_s(buf, ",", &ctx); t; t = strtok_s(NULL, ",", &ctx))
    if (t[0]) sd_jw_cstr(jw, t);
  sd_jw_arr_end(jw);
}

/* The Security state of the current connection (03 §7.6, 2.4), not the warnings ring: legacy (the flag),
   legacy_algorithms ([{category, name}]) and terrapin_exposed. g.lock held. */
static void write_security_json(sd_json_writer *jw, host_mount *h)
{
  sd_mount_security sec;
  uint32_t i;
  memset(&sec, 0, sizeof(sec));
  if (h->m)
    sd_mount_get_security(h->m, &sec);
  sd_jw_key(jw, "legacy"); sd_jw_bool(jw, sec.legacy);
  sd_jw_key(jw, "legacy_algorithms");
  sd_jw_arr_begin(jw);
  for (i = 0; i < sec.legacy_count; i++) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "category"); sd_jw_cstr(jw, sec.legacy_algs[i].category);
    sd_jw_key(jw, "name"); sd_jw_cstr(jw, sec.legacy_algs[i].name);
    sd_jw_obj_end(jw);
  }
  sd_jw_arr_end(jw);
  sd_jw_key(jw, "terrapin_exposed"); sd_jw_bool(jw, sec.terrapin_exposed);
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
  sd_jw_key(jw, "scope"); sd_jw_cstr(jw, scope_name(h->scope));
  write_security_json(jw, h);
  write_conn_json(jw, h);
  sd_jw_obj_end(jw);
}

static void send_state_event(host_mount *h, sd_mount_state st, sd_err why)
{
  sd_wr d;
  sd_json_writer jw;
  const char *ecode = NULL;         /* the error code of a failed state, for the event history */
  if (h->test_only)                 /* profile.test is not a mount for the clients (M3) */
    return;
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
    ecode = code;
    sd_jw_key(&jw, "error");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, code);
    sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, f.detail);
    sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, sd_ipc_exit_code_for_code(code));
    if (f.err == SD_E_HOSTKEY_MISMATCH || f.err == SD_E_HOSTKEY_TYPE_UNAVAILABLE) {
      sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, h->host);
      if (f.lookup_name[0]) { sd_jw_key(&jw, "lookup_name"); sd_jw_cstr(&jw, f.lookup_name); }
    }
    if (f.err == SD_E_HOSTKEY_MISMATCH) {
      sd_jw_key(&jw, "stored_type"); sd_jw_cstr(&jw, f.stored_type);
      sd_jw_key(&jw, "stored_fp"); sd_jw_cstr(&jw, f.stored_fp);
      sd_jw_key(&jw, "offered_type"); sd_jw_cstr(&jw, f.offered_type);
      sd_jw_key(&jw, "offered_fp"); sd_jw_cstr(&jw, f.offered_fp);
      sd_jw_key(&jw, "store_path"); jw_wstr(&jw, f.store_path);
      sd_jw_key(&jw, "store_line"); sd_jw_int(&jw, f.store_line);
      if (f.has_store_kind) { sd_jw_key(&jw, "store_kind"); sd_jw_cstr(&jw, store_kind_name(f.store_kind)); }
    } else if (f.err == SD_E_HOSTKEY_TYPE_UNAVAILABLE) {
      /* the stored types (comma list, also in stored_type for clients that show one string) and the server's
         offered algorithms; the offered key and its fingerprint when the server presented one (03 §5.2) */
      sd_jw_key(&jw, "stored_type"); sd_jw_cstr(&jw, f.stored_types);
      write_csv_array(&jw, "stored_types", f.stored_types);
      write_csv_array(&jw, "offered_types", f.offered_types);
      sd_jw_key(&jw, "offered_type"); sd_jw_cstr(&jw, f.offered_type);
      sd_jw_key(&jw, "offered_fp"); sd_jw_cstr(&jw, f.offered_fp);
    }
    sd_jw_obj_end(&jw);
  }
  write_conn_json(&jw, h);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_data("mount", "mount.state", &d);
  record_event("mount.state", h->id, sd_mount_state_name(st), ecode);
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
  remember_warning(code, h->id);
  record_event("warning", h->id, NULL, code);
  if (sd_jw_finish(&jw) == SD_OK) {
    broadcast_data("mount", "warning", &d);
    broadcast_data("warning", "warning", &d);
  }
  sd_wr_free(&d);
}

/* ---- M3 state snapshot and Explorer data (03 §8.2.1, §8.3, §8.7) ---- */

/* The producer copies the URL during the call; this table keeps the strings alive for that call. g.lock held. */
static char g_snap_url[SD_STATE_MAX_ENTRIES][1024];

static uint32_t snap_backend(const host_mount *h)
{
  const char *n = h->m ? sd_mount_backend_kind_name(sd_mount_backend_kind_used(h->m)) : NULL;
  if (n && strcmp(n, "webdav") == 0)
    return SD_STATE_B_WEBDAV;
  if (n && strcmp(n, "dokany") == 0)
    return SD_STATE_B_DOKANY;
  return SD_STATE_B_UNKNOWN;
}

/* The drive is mapped: mounted, offline (the letter stays) or waiting for credentials. */
static int mount_present(const host_mount *h)
{
  return h->state == SD_MOUNT_MOUNTED || h->state == SD_MOUNT_OFFLINE || h->state == SD_MOUNT_AUTH_REQUIRED;
}

/* sftp://user@host:port/path (IPv6 literals in brackets). The path only: never credentials (03 §8.2.1). */
static void mount_url(const host_mount *h, char *out, size_t cap)
{
  if (strchr(h->host, ':') != NULL)
    _snprintf_s(out, cap, _TRUNCATE, "sftp://%s@[%s]:%u%s", h->user, h->host, (unsigned)h->port, h->remote);
  else
    _snprintf_s(out, cap, _TRUNCATE, "sftp://%s@%s:%u%s", h->user, h->host, (unsigned)h->port, h->remote);
}

/* Publishes every mount into the snapshot section. g.lock held. */
static void state_publish_locked(uint32_t flags)
{
  host_state_src src[SD_STATE_MAX_ENTRIES];
  uint32_t n = 0;
  const host_mount *h;
  for (h = g.mounts; h && n < SD_STATE_MAX_ENTRIES; h = h->next) {
    host_state_src *s;
    if (h->test_only)
      continue;
    s = &src[n];
    memset(s, 0, sizeof(*s));
    s->mount_num = h->num;
    s->mount_id = h->id;
    s->profile_id = h->profile_id;
    s->profile_name = h->profile_name;
    mount_url(h, g_snap_url[n], sizeof(g_snap_url[n]));
    s->remote_url = g_snap_url[n];
    s->label = h->label;
    s->letter = h->letter;
    s->state = SD_STATE_S_CONNECTING + (uint32_t)h->state;   /* sd_mount_state has the order of SD_STATE_S_* */
    s->backend = snap_backend(h);
    s->read_only = h->read_only;
    s->network_location = h->network_location;
    n++;
  }
  host_state_publish(src, n, flags);
}

static void work_explorer(void *arg)
{
  host_explorer_mount *x = (host_explorer_mount *)arg;
  explorer_apply(x);
  sd_free(x);
}

/* Copies the Explorer data of a mount and runs the change on the control thread, without g.lock. */
static void explorer_post_locked(const host_mount *h)
{
  host_explorer_mount *x = (host_explorer_mount *)sd_calloc(1, sizeof(*x));
  if (x == NULL)
    return;
  x->letter = h->letter;
  x->present = mount_present(h);
  x->network_location = h->network_location;
  scopy(x->profile_id, sizeof(x->profile_id), h->profile_id);
  scopy(x->profile_name, sizeof(x->profile_name), h->profile_name);
  post(NULL, work_explorer, x);
}

/* A mount was added, changed or removed (h is no longer linked when it is removed). g.lock held. */
static void mount_changed_locked(const host_mount *h)
{
  if (h->test_only)
    return;
  state_publish_locked(0);
  explorer_post_locked(h);
}

/* ---- sd_mount callbacks (control thread) ---- */

/* The recent warnings of a mount that is gone leave the ring, the others keep their order (g.lock held). The
   ring is rewritten from slot 0 so that warn_next = warn_count again. */
static void forget_warnings_locked(const char *mount_id)
{
  host_warn kept[WARN_RING];
  uint32_t i, start, n = 0;
  start = (g.warn_next + WARN_RING - g.warn_count) % WARN_RING;
  for (i = 0; i < g.warn_count; i++) {
    const host_warn *w = &g.warns[(start + i) % WARN_RING];
    if (strcmp(w->mount_id, mount_id) != 0)
      kept[n++] = *w;
  }
  memcpy(g.warns, kept, n * sizeof(kept[0]));
  g.warn_count = n;
  g.warn_next = n % WARN_RING;
}

static void destroy_record_locked(host_mount *h)
{
  host_mount **pp;
  for (pp = &g.mounts; *pp; pp = &(*pp)->next)
    if (*pp == h) { *pp = h->next; break; }
  forget_warnings_locked(h->id);
  mount_changed_locked(h);
  if (h->m) {
    prompt_drop_mount(h->m);
    sd_mount_destroy(h->m);
  }
  free_chain(h->chain);
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

/* profile.test (M3): the deferred reply of the test mount, sent once when the mount is final. g.lock held. */
static void reply_profile_test(host_mount *h, sd_mount *m, sd_err why)
{
  sd_mount_probe p;
  sd_mount_failure f;
  sd_err e;
  if (h->defer_cid == 0 || g.srv == NULL)
    return;
  if (why == SD_OK && sd_mount_get_probe(m, &p)) {
    sd_wr d;
    sd_json_writer jw;
    sd_wr_init(&d, 8 * 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "profile"); sd_jw_cstr(&jw, h->profile_name);
    sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, h->host);
    sd_jw_key(&jw, "port"); sd_jw_int(&jw, h->port);
    sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, h->user);
    sd_jw_key(&jw, "remote_path"); sd_jw_cstr(&jw, p.remote_real);
    sd_jw_key(&jw, "hostkey_fingerprint"); sd_jw_cstr(&jw, p.hostkey_fp);
    sd_jw_key(&jw, "server_version"); sd_jw_cstr(&jw, p.server_version);
    sd_jw_key(&jw, "algorithms");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "kex"); sd_jw_cstr(&jw, p.kex);
    sd_jw_key(&jw, "hostkey"); sd_jw_cstr(&jw, p.hostkey);
    sd_jw_key(&jw, "cipher_c2s"); sd_jw_cstr(&jw, p.cipher_c2s);
    sd_jw_key(&jw, "cipher_s2c"); sd_jw_cstr(&jw, p.cipher_s2c);
    sd_jw_key(&jw, "mac_c2s"); sd_jw_cstr(&jw, p.mac_c2s);
    sd_jw_key(&jw, "mac_s2c"); sd_jw_cstr(&jw, p.mac_s2c);
    sd_jw_obj_end(&jw);
    sd_jw_key(&jw, "legacy"); sd_jw_bool(&jw, p.legacy);
    sd_jw_key(&jw, "hops"); sd_jw_int(&jw, h->hop_count ? h->hop_count : 1);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      e = sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, SD_OK, NULL, NULL, (const char *)d.p, d.len);
    else
      e = sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, SD_E_INTERNAL, NULL, "reply too large", NULL, 0);
    sd_wr_free(&d);
  } else {
    const char *code;
    memset(&f, 0, sizeof(f));
    sd_mount_get_failure(m, &f);
    if (why == SD_OK) {
      /* ended without a result (torn down before READY): the request is answered, not left hanging */
      code = "cancelled";
      f.err = SD_E_CANCELLED;
      if (f.detail[0] == 0)
        scopy(f.detail, sizeof(f.detail), "the test ended before the connection was ready");
    } else {
      if (f.err == SD_OK) f.err = why;
      code = final_code(h, &f);
      if (f.detail[0] == 0)
        scopy(f.detail, sizeof(f.detail), sd_err_name(f.err));
    }
    e = sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, f.err, code, f.detail, NULL, 0);
  }
  if (e != SD_OK && e != SD_E_NOT_FOUND)
    SD_LOGW("agent", "%s: profile.test reply not sent (%s)", h->id, sd_err_name(e));
  h->defer_cid = 0;
}

/* ---- M3 profile tuning, open after mount, autostart (03 §3.4.1) ---- */

/* The vfs and session options of the profile. */
static void tuning_of(const sd_profile *p, sd_mount_tuning *t)
{
  memset(t, 0, sizeof(*t));
  t->attr_ttl_ms = p->attr_ttl_ms;
  t->dir_ttl_ms = p->dir_ttl_ms;
  t->neg_ttl_ms = p->neg_ttl_ms;
  t->open_revalidate_ms = p->open_revalidate_ms;
  t->max_readahead = p->max_readahead;
  t->umask = p->umask;
  t->hide_dotfiles = p->hide_dotfiles;
  t->map_readonly = p->map_readonly;
  t->show_special = p->show_special;
  t->case_sensitive = p->case_sensitive;
  t->remote_case = p->remote_case;
  t->fsync_on_flush = p->fsync_on_flush;
  t->shell_active_show = !sd_profile_block_shell_active(p);
  t->identity_probe_exec = p->identity_probe_exec;
  (void)wide_from_utf8(p->fs_name, t->fs_name, SD_COUNTOF(t->fs_name));
}

/* mount.open_after_mount: Explorer opens the drive root. Test builds never open a window: the root is appended
   to the file named by SHELLDRIVE_TEST_OPEN_FILE (nothing is written when the variable is not set). */
static void shell_explore(const wchar_t *root)
{
#ifdef SD_HOST_TEST_HOOKS
  {
    wchar_t file[MAX_PATH];
    if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_OPEN_FILE", file, MAX_PATH) > 0 && wcslen(file) < MAX_PATH - 1) {
      HANDLE f = CreateFileW(file, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (f != INVALID_HANDLE_VALUE) {
        char line[4];
        DWORD put = 0;
        line[0] = (char)root[0];
        line[1] = ':';
        line[2] = '\\';
        line[3] = '\n';
        SetFilePointer(f, 0, NULL, FILE_END);
        (void)WriteFile(f, line, sizeof(line), &put, NULL);
        CloseHandle(f);
      }
    }
    return;
  }
#else
  if ((INT_PTR)ShellExecuteW(NULL, L"explore", root, NULL, NULL, SW_SHOWNORMAL) <= 32)
    SD_LOGW("agent", "explorer did not open the drive (error %u)", (unsigned)GetLastError());
#endif
}

/* Posted by on_state at the first MOUNTED of a user-initiated mount (never on a reconnect). */
static void work_open(void *arg)
{
  uint32_t num = (uint32_t)(uintptr_t)arg;
  host_mount *h;
  wchar_t root[4];
  root[0] = 0;
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next) {
    if (h->num == num && h->state == SD_MOUNT_MOUNTED && !h->test_only) {
      root[0] = h->letter;
      root[1] = L':';
      root[2] = L'\\';
      root[3] = 0;
      break;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (root[0])
    shell_explore(root);
}

static void reply_hostkey_add(host_mount *h, sd_mount *m, sd_err why);

static void on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) {
    h->state = st;
    if (st == SD_MOUNT_MOUNTED && h->open_after && !h->opened) {
      h->opened = 1;
      post(NULL, work_open, (void *)(uintptr_t)h->num);
    }
    send_state_event(h, st, why);
    mount_changed_locked(h);
    if (h->test_only && sd_mount_is_final(m)) {
      if (h->hk)
        reply_hostkey_add(h, m, why);
      else
        reply_profile_test(h, m, why);
    }
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

/* M2 warnings (03 §2.4, §7.6): legacy_algorithms carries "algorithms": [...]. */
static void on_warning(void *ctx, sd_mount *m, const char *code, uint32_t hop, const char *detail)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h && code) {
    sd_wr d;
    sd_json_writer jw;
    int suppress = 0;
    if (strcmp(code, "legacy_algorithms") == 0 && detail && h->legacy_accepted[0]) {
      const char *names[16];
      char buf[256], hash[80];
      uint32_t n = 0;
      char *t, *ctxs = NULL;
      scopy(buf, sizeof(buf), detail);
      for (t = strtok_s(buf, ",", &ctxs); t && n < 16; t = strtok_s(NULL, ",", &ctxs)) names[n++] = t;
      sd_legacy_set_hash(names, n, hash);
      suppress = strcmp(hash, h->legacy_accepted) == 0;   /* "Don't warn again for this server" (7.6) */
    }
    if (suppress) {
      SD_LOGI("agent", "%s: legacy algorithms %s accepted by the profile", h->id, detail);
    } else {
      SD_LOGW("agent", "%s: warning %s (hop %u): %s", h->id, code, (unsigned)hop, detail ? detail : "");
      remember_warning(code, h->id);
      record_event("warning", h->id, NULL, code);
      sd_wr_init(&d, 16 * 1024);
      sd_jw_init(&jw, &d);
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, code);
      sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
      sd_jw_key(&jw, "data");
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "target"); jw_letter(&jw, h->letter);
      sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, h->host);
      sd_jw_key(&jw, "hop"); sd_jw_int(&jw, (int64_t)hop + 1);
      sd_jw_key(&jw, "hops"); sd_jw_int(&jw, h->hop_count ? h->hop_count : 1);
      if (detail) { sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, detail); }
      if (strcmp(code, "legacy_algorithms") == 0 && detail) {
        char buf[256];
        char *t, *ctxs = NULL;
        scopy(buf, sizeof(buf), detail);
        sd_jw_key(&jw, "algorithms");
        sd_jw_arr_begin(&jw);
        for (t = strtok_s(buf, ",", &ctxs); t; t = strtok_s(NULL, ",", &ctxs)) sd_jw_cstr(&jw, t);
        sd_jw_arr_end(&jw);
      }
      sd_jw_obj_end(&jw);
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK) {
        broadcast_data("mount", "warning", &d);
        broadcast_data("warning", "warning", &d);
      }
      sd_wr_free(&d);
    }
  }
  sd_mutex_unlock(&g.lock);
}

/* Saved secrets (03 §4): user scope; sd_mount decides when they may be used (TM-R05). */
static int secret_get(void *ctx, sd_mount *m, int kind, const char *target, char *out, size_t cap)
{
  sd_secbuf *b = NULL;
  int ok = 0;
  SD_UNUSED(ctx);
  SD_UNUSED(m);
  if (sd_secret_get(SD_SECRET_USER, (sd_secret_kind)kind, target, &b) == SD_OK) {
    if (b->len + 1 <= cap) {
      memcpy(out, b->p, b->len);
      out[b->len] = 0;
      ok = 1;
    }
    sd_secbuf_free(b);
  }
  return ok;
}

static void secret_put(void *ctx, sd_mount *m, int kind, const char *target, const char *value)
{
  host_mount *h;
  wchar_t comment[256];
  sd_err e;
  SD_UNUSED(ctx);
  comment[0] = 0;
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) memcpy(comment, h->save_comment, sizeof(comment));
  sd_mutex_unlock(&g.lock);
  e = sd_secret_put(SD_SECRET_USER, (sd_secret_kind)kind, target, comment[0] ? comment : NULL, value, strlen(value));
  if (e != SD_OK)
    SD_LOGW("agent", "cannot save the secret (%s)", sd_err_name(e));
}

static void write_keys_json(sd_json_writer *jw, const char *key, const sd_mount_hostkey *k, uint32_t n)
{
  uint32_t i;
  sd_jw_key(jw, key);
  sd_jw_arr_begin(jw);
  for (i = 0; i < n; i++) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "type"); sd_jw_cstr(jw, k[i].type);
    sd_jw_key(jw, "fingerprint"); sd_jw_cstr(jw, k[i].fp_sha256);
    sd_jw_obj_end(jw);
  }
  sd_jw_arr_end(jw);
}

static void write_announce_json(sd_json_writer *jw, const host_announce *x)
{
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "id"); sd_jw_cstr(jw, x->id);
  sd_jw_key(jw, "mount_id"); sd_jw_cstr(jw, x->mount_id);
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, x->a.host);
  sd_jw_key(jw, "lookup_name"); sd_jw_cstr(jw, x->a.lookup_name);
  sd_jw_key(jw, "hop"); sd_jw_int(jw, (int64_t)x->a.hop_index + 1);
  write_keys_json(jw, "add", x->a.add, x->a.add_count);
  write_keys_json(jw, "remove", x->a.remove, x->a.remove_count);
  sd_jw_obj_end(jw);
}

/* UpdateHostKeys (5.6): ask -> kept for review and announced; yes -> already applied, announced too. */
static void on_hostkeys_announced(void *ctx, sd_mount *m, const sd_mount_announcement *a, int applied, sd_err err)
{
  host_mount *h;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  h = find_by_mount(m);
  if (h) {
    sd_wr d;
    sd_json_writer jw;
    sd_wr_init(&d, 64 * 1024);
    sd_jw_init(&jw, &d);
    if (applied) {
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, h->id);
      sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, a->host);
      sd_jw_key(&jw, "applied"); sd_jw_bool(&jw, 1);
      sd_jw_key(&jw, "result"); sd_jw_cstr(&jw, sd_err_name(err));
      write_keys_json(&jw, "add", a->add, a->add_count);
      sd_jw_obj_end(&jw);
    } else {
      host_announce *x = (host_announce *)sd_calloc(1, sizeof(*x)), *o;
      char tmp[12];
      size_t n = 0, i = 0;
      uint32_t v;
      if (x == NULL) {
        sd_mutex_unlock(&g.lock);
        sd_wr_free(&d);
        return;
      }
      /* once per host and announced key set: a newer announcement for the same name replaces the old */
      for (o = g.announces; o; o = o->next)
        if (strcmp(o->a.lookup_name, a->lookup_name) == 0) break;
      if (o) {
        memcpy(x->id, o->id, sizeof(x->id));
        o->a = *a;
        scopy(o->mount_id, sizeof(o->mount_id), h->id);
        sd_free(x);
        x = o;
      } else {
        v = ++g.next_announce;
        x->id[i++] = 'a'; x->id[i++] = '-';
        do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
        while (n) x->id[i++] = tmp[--n];
        x->id[i] = 0;
        x->a = *a;
        scopy(x->mount_id, sizeof(x->mount_id), h->id);
        x->next = g.announces;
        g.announces = x;
      }
      write_announce_json(&jw, x);
      SD_LOGI("agent", "%s: %Hs offered new host keys (%s)", h->id, a->lookup_name, x->id);
    }
    record_event("hostkeys.announced", h->id, NULL, NULL);
    if (sd_jw_finish(&jw) == SD_OK) {
      broadcast_data("mount", "hostkeys.announced", &d);
      broadcast_data("hostkeys", "hostkeys.announced", &d);
    }
    sd_wr_free(&d);
  }
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

/* ---- M3 prompt broker (03 §2.5, §3.2, §3.3) ----
 * Each prompt raised by sd_mount has a record in g.prompts until its prompt.closed. Routing: the
 * initiator (when prompt-capable), then UI subscribers of "prompt" (cap prompts.ui); when nothing
 * takes it the prompt is queued (PROMPT_QUEUE_MAX at most; the oldest queued prompt is evicted with
 * reason superseded) and drained to the first UI that subscribes. Deadlines are checked by
 * prompt_sweep once a second on the control thread. g.lock guards the list; sd_mount_answer is
 * never called with g.lock held (it may run callbacks that take it), so rejects go through
 * prompt_flush on the control queue. */

static void wr_raw(sd_wr *w, const char *s)
{
  sd_wr_bytes(w, s, strlen(s));
}

static void wr_u64(sd_wr *w, uint64_t v)
{
  char tmp[24];
  size_t n = 0;
  do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
  while (n) {
    char c = tmp[--n];
    sd_wr_bytes(w, &c, 1);
  }
}

/* prompt.request: the stored data object (without its closing brace) plus queued and the remaining
   deadline in ms at send time (03 §2.5, 1.7.4). `out` must be initialized by the caller. */
static sd_err prompt_request_event(const host_prompt *r, int queued, uint64_t now, sd_wr *out)
{
  sd_wr d;
  sd_err e;
  uint64_t remain = r->deadline > now ? r->deadline - now : 0;
  sd_wr_init(&d, r->body_len + 128);
  sd_wr_bytes(&d, r->body, r->body_len);
  wr_raw(&d, queued ? ",\"queued\":true,\"deadline_ms\":" : ",\"queued\":false,\"deadline_ms\":");
  wr_u64(&d, remain);
  wr_raw(&d, "}");
  e = sd_ipc_build_event("prompt.request", (const char *)d.p, d.len, out);
  sd_wr_free(&d);
  return e;
}

static void prompt_free(host_prompt *r)
{
  if (r->body) {
    sd_secure_zero(r->body, r->body_len);
    sd_free(r->body);
  }
  sd_free(r);
}

static void prompt_unlink(host_prompt *r)
{
  host_prompt **pp;
  for (pp = &g.prompts; *pp; pp = &(*pp)->next)
    if (*pp == r) {
      *pp = r->next;
      return;
    }
}

/* g.lock held. Called before a mount is destroyed: its prompts are gone with it. */
static void prompt_drop_mount(sd_mount *m)
{
  host_prompt *r, *next;
  for (r = g.prompts; r; r = next) {
    next = r->next;
    if (r->m == m) {
      prompt_unlink(r);
      prompt_free(r);
    }
  }
}

/* prompt.closed to the initiator (once) and to UI subscribers of "prompt" that are not the initiator. */
static void prompt_emit_closed(const host_prompt *r, const char *reason)
{
  sd_wr d, w;
  sd_json_writer jw;
  sd_wr_init(&d, 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, r->pid);
  sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, r->mount_id);
  sd_jw_key(&jw, "reason"); sd_jw_cstr(&jw, reason);
  if (r->answered_by) {
    sd_jw_key(&jw, "answered_by");
    sd_jw_cstr(&jw, r->answered_by);
  }
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK) {
    sd_wr_init(&w, 4096);
    if (sd_ipc_build_event("prompt.closed", (const char *)d.p, d.len, &w) == SD_OK) {
      uint64_t skip = 0;
      if (r->initiator && sd_ipc_send_to(g.srv, r->initiator, (const char *)w.p, w.len) == SD_OK)
        skip = r->initiator;
      (void)sd_ipc_broadcast_count(g.srv, "prompt", (const char *)w.p, w.len, SD_IPC_CAP_PROMPTS_UI, skip, NULL);
    }
    sd_wr_free(&w);
  }
  sd_wr_free(&d);
}

/* Starts the UI for prompts nobody took (03 §2.5 step 3). Rate-limited, skipped while a UI holds its
   mutex, and a missing executable just leaves the prompts queued. Session lock state is not probed
   in M3: a UI started while locked waits for its first subscription. g.lock held. */
static void maybe_launch_ui(void)
{
  uint64_t now = sd_tick_ms();
  wchar_t dir[MAX_PATH], exe[MAX_PATH], cmd[MAX_PATH + 32];
  HANDLE ui = NULL;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD n;
  size_t i;
  if (!g.ui_launch)
    return;
  if (g.last_ui_launch && now - g.last_ui_launch < UI_LAUNCH_INTERVAL_MS)
    return;
  g.last_ui_launch = now;
  if (sd_ipc_object_open(SD_IPC_OBJ_UI_MUTEX, &ui) == SD_OK) {
    CloseHandle(ui);                  /* a UI runs and is not subscribed yet: it will drain the queue */
    return;
  }
  n = GetModuleFileNameW(NULL, dir, MAX_PATH);
  if (n == 0 || n >= MAX_PATH)
    return;
  for (i = wcslen(dir); i > 0 && dir[i - 1] != L'\\'; i--)
    ;
  if (i == 0 || i + 20 >= MAX_PATH)
    return;
  dir[i - 1] = 0;
  wcscpy_s(exe, MAX_PATH, dir);
  wcscat_s(exe, MAX_PATH, L"\\shelldrive-ui.exe");
  if (GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES)
    return;                           /* not installed (yet): the prompts stay queued */
  wcscpy_s(cmd, SD_COUNTOF(cmd), L"\"");
  wcscat_s(cmd, SD_COUNTOF(cmd), exe);
  wcscat_s(cmd, SD_COUNTOF(cmd), L"\" --prompt-host");
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
    SD_LOGI("agent", "started the prompt UI");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    SD_LOGW("agent", "cannot start the prompt UI (%u)", (unsigned)GetLastError());
  }
}

/* Marks queued prompts that nobody can answer any more and rejects them on the control thread. */
static void prompt_flush(void)
{
  for (;;) {
    host_prompt *r;
    sd_mount *m = NULL;
    uint32_t id = 0;
    sd_err e;
    sd_mutex_lock(&g.lock);
    for (r = g.prompts; r; r = r->next)
      if (r->expire && !r->answering)
        break;
    if (r == NULL) {
      sd_mutex_unlock(&g.lock);
      return;
    }
    r->answering = 1;
    m = r->m;
    id = r->prompt_id;
    sd_mutex_unlock(&g.lock);
    e = sd_mount_answer(m, id, SD_MA_REJECT, 0, NULL);
    if (e == SD_E_NOT_FOUND) {
      /* the mount no longer holds it and no close event will come: drop the record */
      host_prompt *o;
      sd_mutex_lock(&g.lock);
      for (o = g.prompts; o; o = o->next)
        if (o->m == m && o->prompt_id == id) {
          prompt_unlink(o);
          prompt_free(o);
          break;
        }
      sd_mutex_unlock(&g.lock);
    }
  }
}

static void work_flush(void *arg)
{
  SD_UNUSED(arg);
  prompt_flush();
}

/* Once a second on the control thread: prompts past their deadline are rejected (reason timeout). */
static void prompt_sweep(void)
{
  uint64_t now = sd_tick_ms();
  host_prompt *r;
  int any = 0;
  sd_mutex_lock(&g.lock);
  for (r = g.prompts; r; r = r->next) {
    if (!r->expire && now >= r->deadline) {
      host_mount *h = find_by_mount(r->m);
      r->expire = 1;
      r->reason = "timeout";
      if (h) scopy(h->fail_code, sizeof(h->fail_code), "prompt_unavailable");
      any = 1;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (any)
    prompt_flush();
}

static void on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  host_mount *h;
  char pid[32];
  sd_wr d, w;
  sd_json_writer jw;
  uint32_t i;
  uint64_t now = sd_tick_ms();
  uint64_t to_initiator = 0;
  uint32_t delivered = 0, queued_n = 0;
  host_prompt *r = NULL;
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
  sd_jw_key(&jw, "profile_id"); sd_jw_cstr(&jw, h->profile_id);
  sd_jw_key(&jw, "profile_name"); sd_jw_cstr(&jw, h->profile_name);
  sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, p->host[0] ? p->host : h->host);
  sd_jw_key(&jw, "port"); sd_jw_int(&jw, p->port ? p->port : h->port);
  sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, p->user[0] ? p->user : h->user);
  sd_jw_key(&jw, "hop"); sd_jw_int(&jw, (int64_t)p->hop_index + 1);
  sd_jw_key(&jw, "hops"); sd_jw_int(&jw, p->hop_count ? p->hop_count : 1);
  if (p->via_host[0]) { sd_jw_key(&jw, "via_host"); sd_jw_cstr(&jw, p->via_host); }
  sd_jw_key(&jw, "is_reconnect"); sd_jw_bool(&jw, p->is_reconnect);
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
    if (p->kind == SD_MP_PROXY_PASSWORD) {
      sd_jw_key(&jw, "proxy_host"); sd_jw_cstr(&jw, p->proxy_host);
      sd_jw_key(&jw, "proxy_port"); sd_jw_int(&jw, p->proxy_port);
    }
    if (p->kind == SD_MP_LEGACY_ACK) {
      char buf[512];
      char *t, *ctxs = NULL;
      scopy(buf, sizeof(buf), p->legacy_names);
      sd_jw_key(&jw, "algorithms");
      sd_jw_arr_begin(&jw);
      for (t = strtok_s(buf, ",", &ctxs); t; t = strtok_s(NULL, ",", &ctxs)) sd_jw_cstr(&jw, t);
      sd_jw_arr_end(&jw);
    }
    if (p->kind == SD_MP_KBDINT || p->kind == SD_MP_PASSWORD_CHANGE) {
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
  sd_jw_key(&jw, "can_save"); sd_jw_bool(&jw, p->can_save);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) != SD_OK || d.len < 2) {
    sd_wr_free(&d);
    sd_mutex_unlock(&g.lock);
    scopy(h->fail_code, sizeof(h->fail_code), "prompt_required");
    sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
    return;
  }
  r = (host_prompt *)sd_calloc(1, sizeof(*r));
  if (r != NULL)
    r->body = (char *)sd_alloc(d.len);
  if (r == NULL || r->body == NULL) {
    if (r) sd_free(r);
    sd_wr_free(&d);
    sd_mutex_unlock(&g.lock);
    sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
    return;
  }
  /* stored without the closing brace: prompt_request_event appends queued and deadline_ms */
  memcpy(r->body, d.p, d.len - 1);
  r->body_len = d.len - 1;
  sd_wr_free(&d);
  r->m = m;
  r->prompt_id = p->id;
  scopy(r->pid, sizeof(r->pid), pid);
  scopy(r->mount_id, sizeof(r->mount_id), h->id);
  scopy(r->profile_id, sizeof(r->profile_id), h->profile_id);
  scopy(r->kind, sizeof(r->kind), sd_mount_prompt_kind_name(p->kind));
  r->initiator = h->initiator;
  r->deadline = now + (p->is_reconnect ? g.reconnect_prompt_ms : g.prompt_ms);
  r->seq = ++g.prompt_seq;
  r->next = g.prompts;
  g.prompts = r;

  /* step 1 and 2: the initiator (prompt-capable), then UI subscribers, the initiator excluded */
  if (!g.no_route) {
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    if (prompt_request_event(r, 0, now, &w) == SD_OK) {
      if (h->initiator && (h->initiator_caps & (SD_IPC_CAP_PROMPTS_CONSOLE | SD_IPC_CAP_PROMPTS_UI)) &&
          sd_ipc_send_to(g.srv, h->initiator, (const char *)w.p, w.len) == SD_OK) {
        delivered++;
        to_initiator = h->initiator;
      }
      {
        uint32_t n = 0;
        if (sd_ipc_broadcast_count(g.srv, "prompt", (const char *)w.p, w.len, SD_IPC_CAP_PROMPTS_UI, to_initiator,
                                   &n) == SD_OK)
          delivered += n;
      }
    }
    sd_wr_free(&w);
  }
  if (delivered) {
    sd_mutex_unlock(&g.lock);
    return;
  }

  /* step 3 and 4: nothing took it. Start a UI if that is possible, then queue (16 at most). */
  r->queued = 1;
  maybe_launch_ui();
  {
    host_prompt *o;
    for (o = g.prompts; o; o = o->next)
      if (o->queued && !o->expire) queued_n++;
  }
  while (queued_n > g.prompt_queue_max) {
    host_prompt *old = NULL, *o;
    for (o = g.prompts; o; o = o->next)
      if (o->queued && !o->expire && o != r && (old == NULL || o->seq < old->seq)) old = o;
    if (old == NULL)
      break;
    {
      host_mount *oh = find_by_mount(old->m);
      if (oh) scopy(oh->fail_code, sizeof(oh->fail_code), "prompt_unavailable");
    }
    old->expire = 1;
    old->reason = "superseded";
    queued_n--;
    post(NULL, work_flush, NULL);
  }
  SD_LOGI("agent", "%s: prompt %s queued (no UI or console client)", h->id, pid);
  sd_mutex_unlock(&g.lock);
}

static void on_prompt_closed(void *ctx, sd_mount *m, uint32_t prompt_id)
{
  host_prompt *r = NULL, **pp;
  SD_UNUSED(ctx);
  sd_mutex_lock(&g.lock);
  for (pp = &g.prompts; *pp; pp = &(*pp)->next)
    if ((*pp)->m == m && (*pp)->prompt_id == prompt_id) {
      r = *pp;
      *pp = r->next;
      break;
    }
  if (r) {
    /* a prompt the agent did not answer or expire was closed by the mount itself: cancelled */
    prompt_emit_closed(r, r->reason ? r->reason : "cancelled");
    prompt_free(r);
  }
  sd_mutex_unlock(&g.lock);
}

/* A UI (or console) subscribed to "prompt": the queued prompts go to it first (oldest first), with
   queued:true and the remaining deadline. Runs on the pipe thread. */
static void ipc_on_subscribe(void *ctx, sd_ipc_client *client, const char *topic)
{
  uint64_t cid;
  SD_UNUSED(ctx);
  if (strcmp(topic, "prompt") != 0 || !(sd_ipc_client_caps(client) & SD_IPC_CAP_PROMPTS_UI))
    return;
  cid = sd_ipc_client_id(client);
  sd_mutex_lock(&g.lock);
  for (;;) {
    host_prompt *r = NULL, *o;
    sd_wr w;
    uint64_t now = sd_tick_ms();
    for (o = g.prompts; o; o = o->next)
      if (o->queued && !o->expire && (r == NULL || o->seq < r->seq)) r = o;
    if (r == NULL)
      break;
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    if (prompt_request_event(r, 1, now, &w) != SD_OK || sd_ipc_send_to(g.srv, cid, (const char *)w.p, w.len) != SD_OK) {
      sd_wr_free(&w);
      break;
    }
    sd_wr_free(&w);
    r->queued = 0;
    SD_LOGI("agent", "%s: queued prompt %s delivered to a UI", r->mount_id, r->pid);
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
  cb.secret_get = secret_get;
  cb.secret_put = secret_put;
  cb.on_warning = on_warning;
  cb.on_hostkeys_announced = on_hostkeys_announced;
  sd_mutex_lock(&g.lock);
  if (h->stop_requested) {
    /* unmounted before it started */
    host_mount **pp;
    for (pp = &g.mounts; *pp; pp = &(*pp)->next)
      if (*pp == h) { *pp = h->next; break; }
    state_publish_locked(0);            /* never started: its CONNECTING entry goes */
    sd_mutex_unlock(&g.lock);
    free_chain(h->chain);
    sd_free(h);
    return;
  }
  /* M3 status proxy_legs: the proxies of the chain, kept before sd_mount_create consumes the hops (no secrets) */
  h->nlegs = 0;
  if (h->params.hops) {
    uint32_t i;
    for (i = 0; i < h->params.hop_count && h->nlegs < SD_MOUNT_MAX_HOPS; i++) {
      const sd_mount_proxy *px = &h->params.hops[i].proxy;
      host_leg *lg = &h->legs[h->nlegs];
      if (px->kind == SD_PROXY_NONE)
        continue;
      lg->hop = i + 1;
      lg->kind = px->kind;
      lg->port = px->port;
      lg->host[0] = 0;
      if (px->host) {
        size_t got = 0;
        if (sd_utf16_to_utf8(px->host, wcslen(px->host), lg->host, sizeof(lg->host) - 1, &got, SD_UTF_REPLACE) == SD_OK)
          lg->host[got] = 0;
      }
      h->nlegs++;
    }
  }
  e = sd_mount_create(host_backend(), &h->params, &cb, &m);
  h->m = m;
  h->started = 1;
  free_chain(h->chain);         /* sd_mount copied it (key blobs included) */
  h->chain = NULL;
  h->params.hops = NULL;
  h->params.hop_count = 0;
  h->params.kh_stores = NULL;
  h->params.kh_store_count = 0;
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
      if (!h->test_only) record_event("mount.state", h->id, "failed", sd_err_name(e));
      if (!h->test_only && sd_jw_finish(&jw) == SD_OK) broadcast_data("mount", "mount.state", &d);
      sd_wr_free(&d);
    }
    if (h->test_only && h->defer_cid && g.srv)
      (void)sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, e, NULL, "mount create failed", NULL, 0);
    h->defer_cid = 0;
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
  int force = 0;
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (h->num == num) break;
  if (h && h->m && !sd_mount_is_final(h->m)) {
    m = h->m;
    force = h->stop_force;
  }
  sd_mutex_unlock(&g.lock);
  /* sd_mount_stop calls on_state synchronously (which takes g.lock): never call it locked. */
  if (m)
    (void)sd_mount_stop_ex(m, force);
}

static void work_shutdown(void *arg)
{
  SD_UNUSED(arg);
  g.stop_reason = "request";
  InterlockedExchange(&g.stop, 1);
}

static void work_cancel_client(void *arg)
{
  uint64_t cid = *(uint64_t *)arg;
  host_mount *h;
  int ui;
  sd_free(arg);
  /* section 10, decision 5: cancel only when no prompt-capable client is subscribed; otherwise the
     mount keeps routing its prompts to that client */
  ui = sd_ipc_topic_subscribers(g.srv, "prompt", SD_IPC_CAP_PROMPTS_UI) > 0;
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next) {
    if (h->initiator == cid) {
      h->initiator = 0;
      if (!ui && h->m && sd_mount_cancel_prompts(h->m) > 0)
        scopy(h->fail_code, sizeof(h->fail_code), "cancelled");
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
    if (h->letter == l && !h->test_only) return 1;      /* a test holds no drive */
  return 0;
}

static sd_err fail(sd_ipc_error *err, sd_err e, const char *code, const char *detail)
{
  sd_ipc_error_set(err, e, code, detail);
  return err->err;
}

/* M2: sd_chain -> sd_mount_hop[] with every string the hops need (03 §3.4.1, §3.8). */
static uint32_t agents_of(int agent)
{
  switch (agent) {
  case SD_PROFILE_AGENT_PAGEANT: return SD_AGENT_PAGEANT;
  case SD_PROFILE_AGENT_OPENSSH: return SD_AGENT_OPENSSH;
  case SD_PROFILE_AGENT_NONE:    return 0;
  default:                       return SD_AGENT_PAGEANT | SD_AGENT_OPENSSH;
  }
}

static uint32_t methods_of(uint32_t pm)
{
  return ((pm & SD_PROFILE_AUTH_PUBLICKEY) ? SD_AUTH_PUBLICKEY : 0) | ((pm & SD_PROFILE_AUTH_KBDINT) ? SD_AUTH_KBDINT : 0) |
         ((pm & SD_PROFILE_AUTH_PASSWORD) ? SD_AUTH_PASSWORD : 0);
}

/* proxy_auth (3.8): auto = Basic or Kerberos-only Negotiate; negotiate also NTLM; basic; none. */
static uint32_t proxy_auth_of(const sd_proxy_spec *x, int pa)
{
  if (x->kind == SD_PROFILE_PROXY_SOCKS5)
    return x->user[0] ? SD_PROXY_AUTH_USERPASS : 0;
  switch (pa) {
  case SD_PROFILE_PROXY_AUTH_BASIC:     return SD_PROXY_AUTH_BASIC;
  case SD_PROFILE_PROXY_AUTH_NEGOTIATE: return SD_PROXY_AUTH_SSPI | (x->user[0] ? SD_PROXY_AUTH_BASIC : 0);
  case SD_PROFILE_PROXY_AUTH_NONE:      return 0;
  default:                              return SD_PROXY_AUTH_SSPI_KERBEROS | (x->user[0] ? SD_PROXY_AUTH_BASIC : 0);
  }
}

static sd_err build_chain(host_mount *h, const sd_profile *prof, const sd_chain *ch, const char **why)
{
  host_chain *c = (host_chain *)sd_calloc(1, sizeof(*c));
  uint32_t i, k;
  if (c == NULL)
    return SD_E_NO_MEMORY;
  h->chain = c;
  c->count = ch->count;
  for (i = 0; i < ch->count && i < SD_MOUNT_MAX_HOPS; i++) {
    const sd_chain_hop *s = &ch->hop[i];
    sd_mount_hop *d = &c->hop[i];
    if (!wide_from_utf8(s->host, c->host[i], SD_COUNTOF(c->host[i]))) { *why = "invalid host"; return SD_E_INVALID_PARAM; }
    d->host = c->host[i];
    d->port = s->port ? s->port : 22;
    if (s->user[0]) scopy(c->user[i], sizeof(c->user[i]), s->user);
    else scopy(c->user[i], sizeof(c->user[i]), prof->user);   /* the Windows user name (filled above) */
    d->user = c->user[i];
    for (k = 0; k < s->identity_count && k < SD_MOUNT_MAX_IDENTITIES; k++) {
      if (sd_config_expand_path(s->identity[k], c->ident[i][k], MAX_PATH) != SD_OK) { *why = "invalid identity path"; return SD_E_INVALID_PARAM; }
      c->ident_ptr[i][k] = c->ident[i][k];
    }
    d->identities = c->ident_ptr[i];
    d->identity_count = k;
    if (s->certificate[0]) {
      if (sd_config_expand_path(s->certificate, c->cert[i], MAX_PATH) != SD_OK) { *why = "invalid certificate path"; return SD_E_INVALID_PARAM; }
      d->certificate = c->cert[i];
    }
    if (s->identity_store[0]) {
      /* a DPAPI-kept key (4.4): read the file, decrypt with the user's logon (sd_keyfile) */
      uint8_t *img = NULL;
      size_t len = 0;
      sd_err e = sd_secret_key_read(SD_SECRET_USER, s->identity_store, &img, &len);
      if (e == SD_OK)
        e = host_backend()->key_dpapi_unprotect ? host_backend()->key_dpapi_unprotect(img, len, s->identity_store, &c->key[i])
                                                : SD_E_UNSUPPORTED;
      sd_free(img);
      if (e != SD_OK) {
        *why = "the protected key cannot be opened";
        return e == SD_E_NOT_FOUND ? SD_E_KEY_FORMAT : e;
      }
      d->key_blob = c->key[i]->p;
      d->key_blob_len = c->key[i]->len;
      scopy(c->key_label[i], sizeof(c->key_label[i]), s->identity_store);
      d->key_label = c->key_label[i];
    }
    d->agents = agents_of(s->agent);
    d->identities_only = s->identities_only;
    scopy(c->agent_keys[i], sizeof(c->agent_keys[i]), s->agent_keys);
    d->agent_keys = c->agent_keys[i];
    d->auth_methods = methods_of(s->auth_methods);
    scopy(c->alias[i], sizeof(c->alias[i]), s->host_key_alias);
    d->host_key_alias = c->alias[i][0] ? c->alias[i] : NULL;
    d->update_host_keys = s->update_host_keys;            /* same values as sd_hku_mode */
    d->no_save = !s->save_password;
    if (ch->proxy[i].kind != SD_PROFILE_PROXY_NONE) {
      const sd_proxy_spec *x = &ch->proxy[i];
      d->proxy.kind = x->kind;                            /* same values as sd_proxy_kind */
      if (x->host[0] && !wide_from_utf8(x->host, c->proxy_host[i], SD_COUNTOF(c->proxy_host[i]))) {
        *why = "invalid proxy";
        return SD_E_INVALID_PARAM;
      }
      d->proxy.host = c->proxy_host[i][0] ? c->proxy_host[i] : NULL;
      d->proxy.port = x->port;
      scopy(c->proxy_user[i], sizeof(c->proxy_user[i]), x->user);
      d->proxy.user = c->proxy_user[i][0] ? c->proxy_user[i] : NULL;
      d->proxy.auth = proxy_auth_of(x, ch->proxy_auth[i]);
      d->proxy.fallback_direct = (ch->proxy_fallback_direct & (1u << i)) ? 1 : 0;
    }
  }
  /* known_hosts (5.1): machine (read-only here), user, then the live sources the settings allow */
  c->stores[c->nstores].kind = SD_KH_STORE_MACHINE;
  c->stores[c->nstores].writable = 0;
  c->nstores++;
  c->stores[c->nstores].kind = SD_KH_STORE_USER;
  c->stores[c->nstores].path = h->kh[0] ? h->kh : NULL;
  c->stores[c->nstores].writable = 1;
  c->nstores++;
  if (g.settings.openssh_source) {
    c->stores[c->nstores].kind = SD_KH_SRC_OPENSSH;
    c->nstores++;
  }
  if (g.settings.putty_source) {
    c->stores[c->nstores].kind = SD_KH_SRC_PUTTY;
    c->nstores++;
  }
  return SD_OK;
}

/* test = 1 for profile.test (M3): the mount is a connect-only test (no drive letter, no list entry, no snapshot);
   the reply is deferred to the end of the test. */
static sd_err handle_mount_body(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err,
                                sd_profile *prof, int test)
{
  const sd_json *adhoc = sd_json_get(params, "adhoc");
  const char *pname = sd_json_get_str(params, "profile");
  if (pname == NULL)
    pname = sd_json_get_str(params, "profile_id");
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
  /* test = 2: hostkey add (M5). The caller resolved the profile; the request is a connect-only test */
  int hk = test == 2;
  if (hk)
    test = 1;

  if (!hk) {
  sd_profile_defaults(prof);
  if (adhoc) {
    const char *v;
    int64_t port = 22;
    if ((v = sd_json_get_str(adhoc, "host")) == NULL || strlen(v) >= sizeof(prof->host))
      return fail(err, SD_E_INVALID_PARAM, "usage", "adhoc.host required");
    scopy(prof->host, sizeof(prof->host), v);
    scopy(prof->name, sizeof(prof->name), v);
    if (sd_json_get(adhoc, "port") && (!sd_json_get_int64(adhoc, "port", &port) || port < 1 || port > 65535))
      return fail(err, SD_E_INVALID_PARAM, "usage", "adhoc.port invalid");
    prof->port = (uint16_t)port;
    if ((v = sd_json_get_str(adhoc, "user")) != NULL) scopy(prof->user, sizeof(prof->user), v);
    if ((v = sd_json_get_str(adhoc, "identity")) != NULL) scopy(prof->identity, sizeof(prof->identity), v);
    if ((v = sd_json_get_str(adhoc, "remote_path")) != NULL) scopy(prof->remote_path, sizeof(prof->remote_path), v);
    /* M2: --jump and --proxy */
    if ((v = sd_json_get_str(adhoc, "jump")) != NULL) {
      sd_jump_list jl;
      if (strlen(v) >= sizeof(prof->jump) || sd_jump_parse(v, &jl) != SD_OK)
        return fail(err, SD_E_INVALID_PARAM, "usage", "invalid jump host list");
      scopy(prof->jump, sizeof(prof->jump), v);
    }
    if ((v = sd_json_get_str(adhoc, "proxy")) != NULL && sd_proxy_spec_parse(v, &prof->proxy[0]) != SD_OK)
      return fail(err, SD_E_INVALID_PARAM, "usage", "invalid proxy");
    if (sd_profile_validate(prof, &bad) != SD_OK)
      return fail(err, SD_E_INVALID_PARAM, "usage", bad);
  } else if (pname) {
    e = sd_profile_find(pname, prof, NULL, 0);
    if (e == SD_E_NOT_FOUND)
      return fail(err, e, "profile_not_found", "no such profile");
    if (e != SD_OK)
      return fail(err, e, NULL, "cannot read profiles");
  } else {
    return fail(err, SD_E_INVALID_PARAM, "usage", "profile or adhoc required");
  }
  }
  {
    /* M4 (03 §3.4, §3.5): the effective write mode. An unset mount.write_mode takes [defaults] write_mode;
       ForceWriteThrough refuses an explicit behind */
    DWORD fv = 0;
    int wm = prof->write_mode;
    int force = sd_policy_get_dword(SD_POLICY_FORCEWRITETHROUGH, &fv) && fv != 0;
    if (sd_profile_effective_write_mode(prof, &g.settings, force, &wm) != SD_OK)
      return fail(err, SD_E_ACCESS_DENIED, "policy_denied", "write mode behind is not allowed by policy");
    prof->write_mode = wm;
  }
  if (sd_json_get_bool(params, "read_only", &ro) && ro)
    prof->read_only = 1;
  if (sd_json_get(params, "connections")) {
    int64_t nc = 0;
    if (!sd_json_get_int64(params, "connections", &nc) || nc < 1 || nc > 4)
      return fail(err, SD_E_INVALID_PARAM, "usage", "connections must be 1 to 4");
    prof->connections = (uint32_t)nc;
  }
  if (pbackend && !sd_mount_backend_kind_parse(pbackend, &backend))
    return fail(err, SD_E_INVALID_PARAM, "usage", "backend must be auto, dokany or webdav");
  if (pbackend == NULL)
    backend = (sd_mount_backend_kind)prof->backend;    /* mount.backend (same values) */
  if (target == NULL || strcmp(target, "auto") == 0)
    target = prof->target;
  if (strcmp(target, "auto") != 0) {
    if (!wide_from_utf8(target, wt, SD_COUNTOF(wt)) || (letter = sd_parse_drive_letter(wt)) == 0)
      return fail(err, SD_E_INVALID_PARAM, "invalid_target", "target must be a drive letter");
    if (letter < L'D')
      return fail(err, SD_E_INVALID_PARAM, "invalid_target", "drive letters A: to C: are not used");
  }
  if (prof->user[0] == 0) {
    wchar_t wu[128];
    DWORD n = SD_COUNTOF(wu);
    size_t got = 0;
    if (GetUserNameW(wu, &n) && n > 0 &&
        sd_utf16_to_utf8(wu, n - 1, prof->user, sizeof(prof->user) - 1, &got, SD_UTF_STRICT) == SD_OK)
      prof->user[got] = 0;
    else
      return fail(err, SD_E_INVALID_PARAM, "usage", "user required");
  }

  h = (host_mount *)sd_calloc(1, sizeof(*h));
  if (h == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  scopy(h->profile_name, sizeof(h->profile_name), prof->name);
  scopy(h->profile_id, sizeof(h->profile_id), prof->id);
  h->scope = prof->scope;
  scopy(h->host, sizeof(h->host), prof->host);
  scopy(h->user, sizeof(h->user), prof->user);
  scopy(h->remote, sizeof(h->remote), prof->remote_path);
  h->port = prof->port;
  h->read_only = prof->read_only;
  h->backend_req = (int)backend;
  /* a logon mount (client NULL) has no initiator: no prompts and no open after mount */
  h->initiator = client ? sd_ipc_client_id(client) : 0;
  h->initiator_caps = client ? sd_ipc_client_caps(client) : 0;
  h->prompt_none = (pmode && strcmp(pmode, "none") == 0) ||
                   !(h->initiator_caps & (SD_IPC_CAP_PROMPTS_CONSOLE | SD_IPC_CAP_PROMPTS_UI));
  h->state = SD_MOUNT_CONNECTING;
  if (!wide_from_utf8(prof->host, h->whost, SD_COUNTOF(h->whost)) ||
      !wide_from_utf8(prof->label[0] ? prof->label : prof->name, h->label, SD_COUNTOF(h->label))) {
    sd_free(h);
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid host or label");
  }
  if (prof->identity[0] && sd_config_expand_path(prof->identity, h->identity, SD_COUNTOF(h->identity)) != SD_OK) {
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
    size_t kn = strlen(prof->user) + strlen(prof->host) + 8;
    uint32_t v = prof->port, pi = 0;
    char tmp[8];
    size_t tn = 0;
    do { tmp[tn++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (tn) pnum[pi++] = tmp[--tn];
    pnum[pi] = 0;
    if (kn < sizeof(key)) {
      key[0] = 0;
      strcat_s(key, sizeof(key), prof->user);
      strcat_s(key, sizeof(key), "@");
      strcat_s(key, sizeof(key), prof->host);
      strcat_s(key, sizeof(key), ":");
      strcat_s(key, sizeof(key), pnum);
      if (sd_config_cache_dir(key, h->cache_dir, SD_COUNTOF(h->cache_dir)) != SD_OK) {
        SD_LOGW("agent", "cache folder unavailable; no disk tier or identity cache");
        h->cache_dir[0] = 0;
      }
    }
  }

  {
    sd_chain *ch = NULL;
    const char *why = NULL;
    e = sd_chain_resolve(prof, NULL, NULL, &ch, &why);
    if (e == SD_OK) {
      e = build_chain(h, prof, ch, &why);
      sd_free(ch);
    }
    if (e != SD_OK) {
      free_chain(h->chain);
      sd_free(h);
      return fail(err, e, e == SD_E_INVALID_PARAM ? "usage" : NULL, why ? why : "cannot resolve the jump hosts");
    }
  }
  sd_mutex_lock(&g.lock);
  for (o = g.mounts; o; o = o->next) {
    if (!test && prof->id[0] && strcmp(o->profile_id, prof->id) == 0) {
      sd_mutex_unlock(&g.lock);
      free_chain(h->chain);
      sd_free(h);
      return fail(err, SD_E_EXISTS, "already_mounted", "profile already mounted");
    }
  }
  if (hk) {
    letter = 0;                        /* a hostkey mount has no drive (params.hostkey_fetch, 03 §6.1) */
  } else if (test) {
    letter = L'Z';                     /* profile.test has no drive: the letter only satisfies the mount record */
  } else if (letter) {
    if (letter_in_use_locked(letter)) {
      char detail[32];
      sd_mutex_unlock(&g.lock);
      free_chain(h->chain);
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
      free_chain(h->chain);
      sd_free(h);
      return fail(err, SD_E_EXISTS, "target_in_use", "no free drive letter");
    }
  }
  h->letter = letter;
  h->test_only = test;
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
  h->params.auth_methods = ((prof->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) ? SD_AUTH_PUBLICKEY : 0) |
                           ((prof->auth_methods & SD_PROFILE_AUTH_KBDINT) ? SD_AUTH_KBDINT : 0) |
                           ((prof->auth_methods & SD_PROFILE_AUTH_PASSWORD) ? SD_AUTH_PASSWORD : 0);
  h->params.remote_path = h->remote[0] ? h->remote : NULL;
  h->params.letter = letter;
  h->params.test_only = test;
  if (hk) {
    const char *v;
    h->hk = 1;
    scopy(h->hk_lookup, sizeof(h->hk_lookup), (v = sd_json_get_str(params, "lookup")) != NULL ? v : "");
    scopy(h->hk_type, sizeof(h->hk_type), (v = sd_json_get_str(params, "type")) != NULL ? v : "");
    scopy(h->hk_expect, sizeof(h->hk_expect), (v = sd_json_get_str(params, "expect")) != NULL ? v : "");
    h->params.hostkey_fetch = 1;
    h->params.hostkey_type = h->hk_type[0] ? h->hk_type : NULL;
  }
  h->params.read_only = prof->read_only;
  h->params.symlinks = prof->symlinks;
  h->params.write_mode = prof->write_mode;
  h->params.volume_label = h->label;
  h->params.known_hosts_path = h->kh[0] ? h->kh : NULL;
  h->params.backend = h->backend_req;
  h->params.disk_cache_mb = prof->disk_cache_mb;
  h->params.disk_cache_dir = h->cache_dir[0] ? h->cache_dir : NULL;
  h->params.offline_wait_ms = prof->offline_wait_ms;
  h->params.reconnect_grace_ms = prof->reconnect_grace_ms;
  h->params.channels = prof->channels;
  h->params.cache_memory_bytes = g.settings.cache_memory;
  /* M2 */
  h->params.hops = h->chain->hop;
  h->params.hop_count = h->chain->count;
  h->params.legacy_policy = prof->legacy_algorithms;          /* same values as sd_legacy_policy */
  h->params.refuse_terrapin_exposed = prof->refuse_terrapin_exposed;
  h->params.compression = prof->compression;
  h->params.connections = prof->connections;
  h->params.keepalive_ms = prof->keepalive_ms;
  h->params.connect_timeout_ms = prof->connect_timeout_ms;
  h->params.no_secret_cache = !prof->cache_secrets;
  h->params.profile_name = h->label;
  h->params.kh_stores = h->chain->stores;
  h->params.kh_store_count = h->chain->nstores;
  h->hop_count = h->chain->count;
  scopy(h->legacy_accepted, sizeof(h->legacy_accepted), prof->legacy_accepted);
  h->network_location = prof->network_location;
  tuning_of(prof, &h->params.tuning);
  {
    /* mount.open_after_mount, or the open request of `shelldrive mount --open`; never for profile.test */
    int open_req = 0;
    (void)sd_json_get_bool(params, "open", &open_req);
    h->open_after = !test && (prof->open_after_mount || open_req);
  }
  /* profile.test: the request is answered when the test ends (on_state). sd_ipc_defer is valid inside the
     handler only; it is taken before the record is linked, so a refusal leaves nothing behind. */
  if (test) {
    if (!sd_ipc_defer(client, &h->defer_rid)) {
      sd_mutex_unlock(&g.lock);
      free_chain(h->chain);
      sd_free(h);
      return fail(err, SD_E_INTERNAL, NULL, "profile.test outside a request");
    }
    h->defer_cid = sd_ipc_client_id(client);
  }
  h->next = g.mounts;
  g.mounts = h;
  g.last_busy = sd_tick_ms();
  if (!test) {
    state_publish_locked(0);
    sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
    sd_jw_key(res, "target"); jw_letter(res, letter);
    sd_jw_key(res, "profile"); sd_jw_cstr(res, h->profile_name);
    sd_jw_key(res, "state"); sd_jw_cstr(res, "connecting");
  }
  sd_mutex_unlock(&g.lock);
  SD_LOGI("agent", "mount %s requested by client %llu", h->id, (unsigned long long)h->initiator);
  post(NULL, work_start, h);
  return SD_OK;
}

static sd_err handle_mount(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  sd_profile *prof = (sd_profile *)sd_alloc(sizeof(sd_profile));   /* ~13 KB: off the IPC thread stack */
  sd_err e;
  if (prof == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  e = handle_mount_body(client, params, res, err, prof, 0);
  sd_free(prof);
  return e;
}

/* profile.test {profile | profile_id | adhoc} (M3, 03 §2.4): connect, authenticate and realpath, no drive. The
   prompts go through the normal broker. The reply is deferred (sd_ipc_defer) to the end of the test. */
/* ---- M3 autostart (03 §3.4.1): profiles with autostart = logon are mounted when the agent starts ---- */

#define AUTOSTART_MAX 16u
typedef struct autostart_list {
  char id[AUTOSTART_MAX][33];
  uint32_t n;
} autostart_list;

static int autostart_sessions_ok(int want)
{
  int remote = GetSystemMetrics(SM_REMOTESESSION) != 0;
  if (want == SD_PROFILE_SESSIONS_CONSOLE) return !remote;
  if (want == SD_PROFILE_SESSIONS_REMOTE) return remote;
  return 1;
}

static int autostart_cb(void *vctx, const sd_profile *p, const wchar_t *path)
{
  autostart_list *l = (autostart_list *)vctx;
  SD_UNUSED(path);
  if (p->autostart == SD_PROFILE_AUTOSTART_NO)
    return 1;
  if (p->autostart == SD_PROFILE_AUTOSTART_BOOT) {
    SD_LOGI("agent", "profile %s: autostart = boot is applied by the service only", p->id);
    return 1;
  }
  if (p->scope != SD_PROFILE_SCOPE_USER) {
    SD_LOGI("agent", "profile %s: autostart for a machine profile is not applied by the agent", p->id);
    return 1;
  }
  if (!autostart_sessions_ok(p->autostart_sessions)) {
    SD_LOGI("agent", "profile %s: autostart skipped (autostart_sessions does not match this session)", p->id);
    return 1;
  }
  if (l->n < AUTOSTART_MAX && p->id[0]) {
    scopy(l->id[l->n], sizeof(l->id[0]), p->id);
    l->n++;
  }
  return 1;
}

/* A logon mount is not a user request: no client, no prompt (prompt_none), no open after mount. */
static void start_autostart(const char *id)
{
  sd_profile *prof = (sd_profile *)sd_alloc(sizeof(sd_profile));
  sd_json *params = NULL;
  sd_wr w;
  sd_json_writer jw;
  sd_ipc_error err;
  char text[96];
  sd_err e;
  if (prof == NULL)
    return;
  strcpy_s(text, sizeof(text), "{\"profile_id\":\"");
  strcat_s(text, sizeof(text), id);
  strcat_s(text, sizeof(text), "\"}");
  if (sd_json_parse(text, strlen(text), 8, &params) == SD_OK) {
    sd_wr_init(&w, 4096);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    memset(&err, 0, sizeof(err));
    e = handle_mount_body(NULL, params, &jw, &err, prof, 0);
    if (e != SD_OK)
      SD_LOGW("agent", "autostart of profile %s failed: %s", id, err.code[0] ? err.code : sd_err_name(e));
    else
      SD_LOGI("agent", "autostart of profile %s requested", id);
    sd_wr_free(&w);
    sd_json_free(params);
  }
  sd_free(prof);
}

static void work_autostart(void *arg)
{
  autostart_list *l;
  uint32_t i;
  SD_UNUSED(arg);
  l = (autostart_list *)sd_alloc(sizeof(*l));
  if (l == NULL)
    return;
  memset(l, 0, sizeof(*l));
  (void)sd_profile_enum(autostart_cb, l);
  for (i = 0; i < l->n; i++)
    start_autostart(l->id[i]);
  sd_free(l);
}

static sd_err handle_profile_test(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  sd_profile *prof = (sd_profile *)sd_alloc(sizeof(sd_profile));
  sd_err e;
  if (prof == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  e = handle_mount_body(client, params, res, err, prof, 1);
  sd_free(prof);
  return e;
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
  int all = 0, force = 0, n = 0;
  host_mount *h;
  sd_json_get_bool(params, "all", &all);
  sd_json_get_bool(params, "force", &force);   /* M3: no write-behind drain budget (02 §4.4); see work_stop */
  if (!all && !target && !mount_id && !profile)
    return fail(err, SD_E_INVALID_PARAM, "usage", "target, mount_id, profile or all required");
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  for (h = g.mounts; h; h = h->next) {
    if (h->test_only)
      continue;                 /* a profile test is not a mount: profile.test ends by itself */
    if (all || mount_matches(h, target, mount_id, profile)) {
      if (!h->stop_requested) {
        h->stop_requested = 1;
        h->stop_force = force ? 1 : 0;
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

static void remember_warning(const char *code, const char *mount_id)   /* g.lock held */
{
  host_warn *w = &g.warns[g.warn_next];
  scopy(w->code, sizeof(w->code), code);
  scopy(w->mount_id, sizeof(w->mount_id), mount_id ? mount_id : "");
  g.warn_next = (g.warn_next + 1u) % WARN_RING;
  if (g.warn_count < WARN_RING)
    g.warn_count++;
}

static sd_err handle_list(sd_json_writer *res)
{
  host_mount *h;
  uint32_t i, start;
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  for (h = g.mounts; h; h = h->next)
    if (!h->test_only)
      write_mount_json(res, h);
  sd_jw_arr_end(res);
  /* M3: the recent warnings of this agent, oldest first (codes of the warning events) */
  sd_jw_key(res, "warnings");
  sd_jw_arr_begin(res);
  start = (g.warn_next + WARN_RING - g.warn_count) % WARN_RING;
  for (i = 0; i < g.warn_count; i++) {
    const host_warn *w = &g.warns[(start + i) % WARN_RING];
    sd_jw_obj_begin(res);
    sd_jw_key(res, "code"); sd_jw_cstr(res, w->code);
    if (w->mount_id[0]) { sd_jw_key(res, "mount_id"); sd_jw_cstr(res, w->mount_id); }
    sd_jw_obj_end(res);
  }
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* M3 status stats (03 §2.4): the session and vfs counters of one mount and its pool members. g.lock held. */
static void write_stats_json(sd_json_writer *jw, host_mount *h)
{
  sd_mount_stats st;
  sd_mount_conn c;
  uint32_t i;
  memset(&st, 0, sizeof(st));
  memset(&c, 0, sizeof(c));
  if (h->m) {
    sd_mount_get_stats(h->m, &st);
    sd_mount_get_conn(h->m, &c);
  }
  sd_jw_key(jw, "stats");
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "session"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "present"); sd_jw_bool(jw, st.has_session);
  sd_jw_key(jw, "generation"); sd_jw_int(jw, st.generation);
  sd_jw_key(jw, "channels"); sd_jw_int(jw, st.channels);
  sd_jw_key(jw, "srtt_ms"); sd_jw_int(jw, st.srtt_ms);
  sd_jw_key(jw, "rttvar_ms"); sd_jw_int(jw, st.rttvar_ms);
  sd_jw_key(jw, "rx_bps"); sd_jw_int(jw, (int64_t)st.rx_bps);
  sd_jw_key(jw, "tx_bps"); sd_jw_int(jw, (int64_t)st.tx_bps);
  sd_jw_key(jw, "rx_bytes"); sd_jw_int(jw, (int64_t)st.rx_total);
  sd_jw_key(jw, "tx_bytes"); sd_jw_int(jw, (int64_t)st.tx_total);
  sd_jw_key(jw, "inflight"); sd_jw_int(jw, st.inflight);
  sd_jw_key(jw, "queued"); sd_jw_int(jw, st.queued);
  sd_jw_key(jw, "reconnect_attempts"); sd_jw_int(jw, st.reconnect_attempts);
  sd_jw_obj_end(jw);
  sd_jw_key(jw, "pool"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "ready"); sd_jw_int(jw, c.pool);
  sd_jw_key(jw, "wanted"); sd_jw_int(jw, c.pool_wanted);
  sd_jw_key(jw, "members"); sd_jw_arr_begin(jw);
  for (i = 0; i < st.members; i++) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "ready"); sd_jw_bool(jw, st.member[i].ready);
    sd_jw_key(jw, "srtt_ms"); sd_jw_int(jw, st.member[i].srtt_ms);
    sd_jw_key(jw, "inflight"); sd_jw_int(jw, st.member[i].inflight);
    sd_jw_key(jw, "queued"); sd_jw_int(jw, st.member[i].queued);
    sd_jw_key(jw, "rx_bytes"); sd_jw_int(jw, (int64_t)st.member[i].rx_total);
    sd_jw_key(jw, "tx_bytes"); sd_jw_int(jw, (int64_t)st.member[i].tx_total);
    sd_jw_obj_end(jw);
  }
  sd_jw_arr_end(jw);
  sd_jw_obj_end(jw);
  sd_jw_key(jw, "cache"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "vfs"); sd_jw_bool(jw, st.has_vfs);
  sd_jw_key(jw, "hits"); sd_jw_int(jw, (int64_t)st.cache_hits);
  sd_jw_key(jw, "misses"); sd_jw_int(jw, (int64_t)st.cache_misses);
  sd_jw_key(jw, "bytes_read"); sd_jw_int(jw, (int64_t)st.bytes_rd);
  sd_jw_key(jw, "bytes_written"); sd_jw_int(jw, (int64_t)st.bytes_wr);
  sd_jw_key(jw, "write_failed"); sd_jw_int(jw, (int64_t)st.write_failed);
  sd_jw_key(jw, "write_behind_bytes"); sd_jw_int(jw, (int64_t)st.wb_bytes);
  sd_jw_key(jw, "reconnects"); sd_jw_int(jw, (int64_t)st.reconnects);
  sd_jw_obj_end(jw);
  sd_jw_obj_end(jw);
}

/* status proxy_legs (M3): the proxies of the chain, without credentials. g.lock held. */
static void write_legs_json(sd_json_writer *jw, const host_mount *h)
{
  uint32_t i;
  sd_jw_key(jw, "proxy_legs");
  sd_jw_arr_begin(jw);
  for (i = 0; i < h->nlegs; i++) {
    const host_leg *lg = &h->legs[i];
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "hop"); sd_jw_int(jw, lg->hop);
    sd_jw_key(jw, "kind");
    sd_jw_cstr(jw, lg->kind == SD_PROXY_HTTP ? "http" : lg->kind == SD_PROXY_SOCKS5 ? "socks5"
                   : lg->kind == SD_PROXY_SYSTEM ? "system" : "none");
    sd_jw_key(jw, "host"); sd_jw_cstr(jw, lg->host);
    sd_jw_key(jw, "port"); sd_jw_int(jw, lg->port);
    sd_jw_obj_end(jw);
  }
  sd_jw_arr_end(jw);
}

/* status {mount_id | target, stats?}: the list object, the last failure, the connection details, and with
   stats the session, pool and cache counters; proxy_legs always (03 §2.4, M3). */
static sd_err handle_status(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *mid = sd_json_get_str(params, "mount_id");
  const char *target = sd_json_get_str(params, "target");
  int stats = 0;
  host_mount *h;
  if (mid == NULL && target == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "mount_id or target required");
  sd_json_get_bool(params, "stats", &stats);
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (!h->test_only && mount_matches(h, target, mid, NULL)) break;
  if (h == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  }
  sd_jw_key(res, "mount");
  write_mount_json(res, h);
  if (stats)
    write_stats_json(res, h);
  write_legs_json(res, h);
  if (h->m && (h->state == SD_MOUNT_FAILED || h->state == SD_MOUNT_OFFLINE)) {
    sd_mount_failure f;
    sd_mount_get_failure(h->m, &f);
    sd_jw_key(res, "last_error");
    sd_jw_obj_begin(res);
    sd_jw_key(res, "code"); sd_jw_cstr(res, final_code(h, &f));
    sd_jw_key(res, "detail"); sd_jw_cstr(res, f.detail);
    sd_jw_obj_end(res);
  }
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* refresh {mount_id | target, path} (M3): drops the cached attributes and listings under path ("" or "/" = the
   whole mount). Not mounted: not_mounted (exit 3). */
static sd_err handle_refresh(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *mid = sd_json_get_str(params, "mount_id");
  const char *target = sd_json_get_str(params, "target");
  const char *path = sd_json_get_str(params, "path");
  wchar_t wp[1024];
  host_mount *h;
  sd_err e;
  size_t i;
  int all;
  if (mid == NULL && target == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "mount_id or target required");
  if (path == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "path required");
  if (!wide_from_utf8(path, wp, SD_COUNTOF(wp)))
    return fail(err, SD_E_INVALID_PARAM, "usage", "path is too long or not UTF-8");
  for (i = 0; wp[i]; i++)
    if (wp[i] == L'/') wp[i] = L'\\';
  all = wp[0] == 0 || (wp[0] == L'\\' && wp[1] == 0);
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (!h->test_only && mount_matches(h, target, mid, NULL)) break;
  if (h == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  }
  e = h->m ? sd_mount_refresh(h->m, all ? NULL : wp) : SD_E_NOT_FOUND;
  if (e == SD_OK) {
    sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
    sd_jw_key(res, "path"); sd_jw_cstr(res, all ? "\\" : path);
    sd_jw_key(res, "refreshed"); sd_jw_bool(res, 1);
  }
  sd_mutex_unlock(&g.lock);
  if (e == SD_E_NOT_FOUND)
    return fail(err, e, "not_mounted", "the mount has no file system to refresh");
  if (e == SD_E_UNSUPPORTED)
    return fail(err, e, "unsupported", "refresh is not available in this build");
  return e == SD_OK ? SD_OK : fail(err, e, NULL, "refresh failed");
}

/* cache.clear {profile_id | mount_id | target | all} (M3): drops the memory blocks and the disk-tier files of the
   matching mounts. Write-behind data still queued on one of them refuses the whole request with busy
   (write_behind_pending, exit 8) unless force is set; the queued data is never dropped. */
static sd_err handle_cache_clear(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *profile = sd_json_get_str(params, "profile_id");
  const char *mid = sd_json_get_str(params, "mount_id");
  const char *target = sd_json_get_str(params, "target");
  int all = 0, force = 0, matched = 0, cleared = 0, busy = 0;
  host_mount *h;
  sd_json_get_bool(params, "all", &all);
  sd_json_get_bool(params, "force", &force);
  if (!all && !profile && !mid && !target)
    return fail(err, SD_E_INVALID_PARAM, "usage", "profile_id, mount_id, target or all required");
  sd_mutex_lock(&g.lock);
  if (!force) {
    for (h = g.mounts; h && !busy; h = h->next) {
      sd_mount_stats st;
      if (h->test_only || h->m == NULL || !(all || mount_matches(h, target, mid, profile)))
        continue;
      sd_mount_get_stats(h->m, &st);
      if (st.has_vfs && st.wb_bytes > 0)
        busy = 1;
    }
    if (busy) {
      sd_mutex_unlock(&g.lock);
      return fail(err, SD_E_BUSY, "write_behind_pending", "write-behind data is queued; use force to clear anyway");
    }
  }
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  for (h = g.mounts; h; h = h->next) {
    sd_err e;
    if (h->test_only || h->m == NULL || !(all || mount_matches(h, target, mid, profile)))
      continue;
    matched++;
    e = sd_mount_cache_clear(h->m, 1, force);
    if (e == SD_OK) {
      cleared++;
      sd_jw_obj_begin(res);
      sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
      sd_jw_obj_end(res);
    } else if (e == SD_E_BUSY) {
      busy = 1;                 /* queued meanwhile: this mount keeps its cache, the rest is reported */
    }
  }
  sd_jw_arr_end(res);
  sd_jw_key(res, "cleared"); sd_jw_int(res, cleared);
  sd_jw_key(res, "disk_tier"); sd_jw_bool(res, 1);
  sd_mutex_unlock(&g.lock);
  if (matched == 0 && !all)
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  if (busy)
    return fail(err, SD_E_BUSY, "write_behind_pending", "write-behind data was queued during the clear");
  return SD_OK;
}

/* mount.attach_info {mount_id | target} (M3): the backend, the state and, for WebDAV, the loopback port and the
   share root. The export token of the path (the capability in \\localhost@PORT\DavWWWRoot\s-<token>) is never
   returned. */
static sd_err handle_attach_info(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *mid = sd_json_get_str(params, "mount_id");
  const char *target = sd_json_get_str(params, "target");
  host_mount *h;
  sd_mount_attach a;
  if (mid == NULL && target == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "mount_id or target required");
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (!h->test_only && mount_matches(h, target, mid, NULL)) break;
  if (h == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  }
  memset(&a, 0, sizeof(a));
  if (h->m)
    sd_mount_get_attach(h->m, &a);
  else
    a.backend = (sd_mount_backend_kind)h->backend_req;
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, h->id);
  sd_jw_key(res, "target"); jw_letter(res, h->letter);
  sd_jw_key(res, "backend"); sd_jw_cstr(res, sd_mount_backend_kind_name(a.backend));
  sd_jw_key(res, "state"); sd_jw_cstr(res, sd_mount_state_name(h->state));
  sd_jw_key(res, "mounted"); sd_jw_bool(res, a.mounted);
  if (a.webdav_port) {
    char port[8], unc[64], url[64];
    size_t n = 0, o = 0;
    uint32_t v = a.webdav_port;
    char tmp[8];
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (n) port[o++] = tmp[--n];
    port[o] = 0;
    unc[0] = 0;
    url[0] = 0;
    strcat_s(unc, sizeof(unc), "\\\\localhost@");
    strcat_s(unc, sizeof(unc), port);
    strcat_s(unc, sizeof(unc), "\\DavWWWRoot");
    strcat_s(url, sizeof(url), "http://localhost:");
    strcat_s(url, sizeof(url), port);
    strcat_s(url, sizeof(url), "/");
    sd_jw_key(res, "webdav");
    sd_jw_obj_begin(res);
    sd_jw_key(res, "host"); sd_jw_cstr(res, "localhost");
    sd_jw_key(res, "port"); sd_jw_int(res, a.webdav_port);
    sd_jw_key(res, "unc_root"); sd_jw_cstr(res, unc);
    sd_jw_key(res, "xp_url"); sd_jw_cstr(res, url);
    sd_jw_obj_end(res);
  }
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* selftest {}: the in-process checks of `shelldrive-host --selftest` plus the live pipe (03 §6.1). */
static sd_err handle_selftest(sd_json_writer *res)
{
  wchar_t root[MAX_PATH];
  sd_settings tmp;
  int healthy = 1;
  sd_jw_key(res, "checks");
  sd_jw_arr_begin(res);
#define SELFTEST_ROW(name_, ok_, code_, detail_)                                  \
  do {                                                                            \
    sd_jw_obj_begin(res);                                                         \
    sd_jw_key(res, "name"); sd_jw_cstr(res, name_);                               \
    sd_jw_key(res, "result"); sd_jw_cstr(res, (ok_) ? "pass" : "fail");           \
    if (!(ok_)) { sd_jw_key(res, "code"); sd_jw_cstr(res, code_); healthy = 0; } \
    sd_jw_key(res, "detail"); sd_jw_cstr(res, detail_);                           \
    sd_jw_obj_end(res);                                                           \
  } while (0)
  {
    int ok = sd_config_root(root, SD_COUNTOF(root)) == SD_OK;
    SELFTEST_ROW("config_root", ok, "config_root_unavailable", ok ? "" : "no per-user root");
  }
  {
    sd_err e = sd_settings_load(&tmp);
    SELFTEST_ROW("settings", e == SD_OK, sd_err_name(e), e == SD_OK ? "" : "settings.ini cannot be read");
  }
  {
    int ok = host_backend() != NULL && host_backend()->name != NULL;
    SELFTEST_ROW("backend", ok, "backend_unavailable", ok ? host_backend()->name : "no backend");
  }
  {
    int ok;
    sd_mutex_lock(&g.lock);
    ok = g.srv != NULL;
    sd_mutex_unlock(&g.lock);
    SELFTEST_ROW("pipe", ok, "internal", ok ? "" : "the agent pipe is not served");
  }
#undef SELFTEST_ROW
  sd_jw_arr_end(res);
  sd_jw_key(res, "healthy");
  sd_jw_bool(res, healthy);
  return SD_OK;
}

/* ---- log.tail (03 §2.1 row 17, decision 12) ---- */

typedef struct tail_ctx {
  sd_json_writer *jw;
  const char *component;
  uint32_t level_max;           /* sd_log_level: records with a higher level are skipped */
  uint32_t lines;               /* records to return */
  uint32_t skip;                /* matching records to skip first (tail mode) */
  uint32_t matches;             /* matching records seen (counting pass, emit pass) */
  uint32_t emitted;
  uint64_t last_seq;
} tail_ctx;

static const char *const k_level_names[] = { "error", "warn", "info", "debug", "trace" };

static int tail_match(const tail_ctx *t, const log_ring_rec *r)
{
  if (r->level < 0 || (uint32_t)r->level > t->level_max)
    return 0;
  return t->component == NULL || strcmp(r->component, t->component) == 0;
}

static int tail_count_cb(void *vctx, const log_ring_rec *r)
{
  tail_ctx *t = (tail_ctx *)vctx;
  if (tail_match(t, r))
    t->matches++;
  return 1;
}

static int tail_emit_cb(void *vctx, const log_ring_rec *r)
{
  tail_ctx *t = (tail_ctx *)vctx;
  if (!tail_match(t, r))
    return 1;
  if (t->matches++ < t->skip)
    return 1;
  sd_jw_obj_begin(t->jw);
  sd_jw_key(t->jw, "seq"); sd_jw_int(t->jw, (int64_t)r->seq);
  sd_jw_key(t->jw, "time"); sd_jw_cstr(t->jw, r->time);
  sd_jw_key(t->jw, "level"); sd_jw_cstr(t->jw, k_level_names[r->level]);
  sd_jw_key(t->jw, "component"); sd_jw_cstr(t->jw, r->component);
  if (r->mount_id[0]) { sd_jw_key(t->jw, "mount_id"); sd_jw_cstr(t->jw, r->mount_id); }
  sd_jw_key(t->jw, "text"); sd_jw_cstr(t->jw, r->text);
  sd_jw_obj_end(t->jw);
  t->emitted++;
  t->last_seq = r->seq;
  return t->emitted < t->lines;
}

static int noop_cb(void *ctx, const log_ring_rec *r)
{
  SD_UNUSED(ctx);
  SD_UNUSED(r);
  return 0;
}

static size_t put_hex(char *o, uint64_t v)
{
  char tmp[17];
  size_t n = 0, k = 0;
  do { tmp[n++] = "0123456789abcdef"[v & 15u]; v >>= 4; } while (v);
  while (n) o[k++] = tmp[--n];
  o[k] = 0;
  return k;
}

static void put_cursor(char *o, size_t cap, uint64_t seq)
{
  size_t k = put_hex(o, (uint64_t)GetCurrentProcessId());
  char tmp[24];
  size_t n = 0;
  if (k + 1 < cap) o[k++] = '.';
  k += put_hex(o + k, g.boot_tick);
  if (k + 1 < cap) o[k++] = '.';
  do { tmp[n++] = (char)('0' + seq % 10u); seq /= 10u; } while (seq);
  while (n && k + 1 < cap) o[k++] = tmp[--n];
  o[k] = 0;
}

/* "<pid hex>.<boot hex>.<seq dec>": false on any other shape. */
static int parse_cursor(const char *s, uint64_t *pid, uint64_t *boot, uint64_t *seq)
{
  uint64_t *field[3];
  int part;
  field[0] = pid;
  field[1] = boot;
  field[2] = seq;
  for (part = 0; part < 3; part++) {
    uint64_t v = 0;
    int digits = 0, hex = part < 2;
    while (*s && *s != '.') {
      int d;
      char c = *s;
      if (c >= '0' && c <= '9') d = c - '0';
      else if (hex && c >= 'a' && c <= 'f') d = c - 'a' + 10;
      else if (hex && c >= 'A' && c <= 'F') d = c - 'A' + 10;
      else return 0;
      if (digits >= (hex ? 16 : 19)) return 0;
      v = hex ? (v << 4) | (uint64_t)d : v * 10u + (uint64_t)d;
      digits++;
      s++;
    }
    if (digits == 0)
      return 0;
    *field[part] = v;
    if (part < 2) {
      if (*s != '.')
        return 0;
      s++;
    }
  }
  return *s == 0;
}

static sd_err handle_log_tail(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  int64_t lines = 200;
  int follow = 0;
  const char *level = sd_json_get_str(params, "level");
  const char *cursor = sd_json_get_str(params, "cursor");
  tail_ctx t;
  uint64_t oldest = 0, newest = 0, from = 0, dropped = 0, cpid = 0, cboot = 0, cseq = 0, next = 0;
  int valid = 0, reset = 0;
  char cur[80];
  memset(&t, 0, sizeof(t));
  t.level_max = (uint32_t)SD_LOG_TRACE;
  if (sd_json_get(params, "lines") && (!sd_json_get_int64(params, "lines", &lines) || lines < 1 || lines > 2000))
    return fail(err, SD_E_INVALID_PARAM, "usage", "lines must be 1 to 2000");
  sd_json_get_bool(params, "follow", &follow);
  if (follow)
    return fail(err, SD_E_UNSUPPORTED, "unsupported", "follow is not available in this build");
  if (level) {
    uint32_t i;
    for (i = 0; i < SD_COUNTOF(k_level_names); i++)
      if (strcmp(level, k_level_names[i]) == 0) break;
    if (i == SD_COUNTOF(k_level_names))
      return fail(err, SD_E_INVALID_PARAM, "usage", "level must be error, warn, info, debug or trace");
    t.level_max = i;
  }
  t.component = sd_json_get_str(params, "component");
  t.lines = (uint32_t)lines;
  if (cursor) {
    if (parse_cursor(cursor, &cpid, &cboot, &cseq) && cpid == (uint64_t)GetCurrentProcessId() && cboot == g.boot_tick)
      valid = 1;
    else
      reset = 1;                  /* foreign, malformed or from an earlier agent: start at the oldest */
  }
  log_ring_scan(~(uint64_t)0, &oldest, &newest, noop_cb, NULL);   /* range only */
  if (valid) {
    from = cseq + 1;
    if (newest && from < oldest) {
      dropped = oldest - from;
      from = oldest;
      reset = 1;
    }
  } else if (cursor) {
    from = 0;
  } else {
    /* tail: the last `lines` matching records */
    log_ring_scan(0, NULL, NULL, tail_count_cb, &t);
    t.skip = t.matches > t.lines ? t.matches - t.lines : 0;
    t.matches = 0;
  }
  sd_jw_key(res, "records");
  sd_jw_arr_begin(res);
  t.jw = res;
  log_ring_scan(from, NULL, NULL, tail_emit_cb, &t);
  sd_jw_arr_end(res);
  if (t.emitted && t.emitted >= t.lines) {
    next = t.last_seq;                /* more may follow: continue right after the last one */
  } else {
    next = newest;                    /* everything up to the newest record was looked at */
    if (valid && cseq > next)
      next = cseq;
  }
  put_cursor(cur, sizeof(cur), next);
  sd_jw_key(res, "cursor"); sd_jw_cstr(res, cur);
  sd_jw_key(res, "reset"); sd_jw_bool(res, reset);
  sd_jw_key(res, "dropped"); sd_jw_int(res, (int64_t)dropped);
  return SD_OK;
}

/* ---- config.reload {scope?} (decision 3: the service only relies on this in M3) ---- */

/* M4 (03 §10.1, TM-R31): [log] privacy and the LogPrivacy policy. Strict mode hashes host, user and remote path
   with HMAC-SHA-256 under the per-installation key state\log.key. */
static uint8_t g_log_key[32];

static void log_privacy_hash(void *ctx, const char *utf8, size_t len, uint8_t out[32])
{
  sd_hmac_ctx c;
  (void)ctx;
  sd_hmac_init(&c, SD_HASH_SHA256, g_log_key, sizeof(g_log_key));
  sd_hmac_update(&c, utf8, len);
  sd_hmac_final(&c, out);
  sd_hmac_wipe(&c);
}

static void log_privacy_apply(const sd_settings *s)
{
  DWORD v = 0;
  int pol = sd_policy_get_dword(SD_POLICY_LOGPRIVACY, &v) ? (v ? 1 : 0) : -1;
  int mode = sd_settings_effective_privacy(s, pol);
  if (mode != SD_SETTINGS_PRIVACY_STRICT) {
    sd_log_set_privacy(SD_LOG_PRIVACY_STANDARD, NULL, NULL);
  } else if (sd_config_log_key(g_log_key) == SD_OK) {
    sd_log_set_privacy(SD_LOG_PRIVACY_STRICT, log_privacy_hash, NULL);
  } else {
    sd_log_set_privacy(SD_LOG_PRIVACY_STRICT, NULL, NULL);   /* no key: names print as [redacted] */
    SD_LOGW("agent", "log.key cannot be read or created: strict log privacy keeps names out of the log");
  }
}

static int count_profile(void *ctx, const sd_profile *p, const wchar_t *path)
{
  SD_UNUSED(p);
  SD_UNUSED(path);
  (*(uint32_t *)ctx)++;
  return 1;
}

static sd_err handle_config_reload(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *scope = sd_json_get_str(params, "scope");
  sd_settings ns;
  uint32_t profiles = 0;
  int changed;
  sd_err e;
  if (scope && strcmp(scope, "machine") == 0)
    return fail(err, SD_E_UNSUPPORTED, "unsupported", "machine scope is served by the service");
  if (scope && strcmp(scope, "user") != 0)
    return fail(err, SD_E_INVALID_PARAM, "usage", "scope must be user or machine");
  e = sd_settings_load(&ns);
  if (e != SD_OK)
    return fail(err, e, NULL, "settings.ini cannot be read");
  sd_mutex_lock(&g.lock);
  changed = memcmp(&g.settings, &ns, sizeof(ns)) != 0;
  g.settings = ns;
  sd_mutex_unlock(&g.lock);
  if (changed) {
    sd_log_set_level((sd_log_level)ns.log_level);
    log_privacy_apply(&ns);
  }
  (void)sd_profile_enum(count_profile, &profiles);
  sd_jw_key(res, "profiles");
  sd_jw_obj_begin(res);
  sd_jw_key(res, "loaded"); sd_jw_int(res, profiles);
  sd_jw_key(res, "errors"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  sd_jw_obj_end(res);
  sd_jw_key(res, "settings"); sd_jw_cstr(res, changed ? "reloaded" : "unchanged");
  sd_jw_key(res, "restart_required"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  return SD_OK;
}

/* prompt.answer {prompt_id, action, responses?, save?, save_comment?}: the first accepted answer wins.
   The record gets its prompt.closed reason before sd_mount sees the answer (03 §3.3). */
static sd_err handle_prompt_answer(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *pid = sd_json_get_str(params, "prompt_id");
  const char *action = sd_json_get_str(params, "action");
  const sd_json *resp = sd_json_get(params, "responses");
  const char *rs[SD_MOUNT_PROMPT_MAX_ITEMS];
  uint32_t mnum = 0, id = 0, n = 0, i;
  sd_mount_answer_kind kind;
  host_mount *h;
  sd_err e = SD_E_NOT_FOUND;
  int save = 0;
  const char *comment = sd_json_get_str(params, "save_comment");
  sd_json_get_bool(params, "save", &save);
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
      rs[i] = sd_json_str(sd_json_at(resp, i), NULL);
      if (rs[i] == NULL)
        return fail(err, SD_E_INVALID_PARAM, "usage", "responses must be strings");
    }
  }
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h && e == SD_E_NOT_FOUND; h = h->next) {
    host_prompt *r;
    if (h->num != mnum || h->m == NULL)
      continue;
    for (r = g.prompts; r; r = r->next)
      if (r->m == h->m && r->prompt_id == id && !r->expire) break;
    if (r == NULL)
      break;
    if (kind == SD_MA_REJECT && strcmp(action, "cancel") == 0) {
      scopy(h->fail_code, sizeof(h->fail_code), "cancelled");
      r->reason = "cancelled";
    } else {
      r->reason = "answered";
    }
    r->answered_by = strcmp(sd_ipc_client_kind(client), "ui") == 0 ? "ui" : "cli";
    if (save && comment && !wide_from_utf8(comment, h->save_comment, SD_COUNTOF(h->save_comment)))
      h->save_comment[0] = 0;
    e = sd_mount_answer_ex(h->m, id, kind, n, rs, save ? SD_MOUNT_ANSWER_SAVE : 0);
  }
  sd_mutex_unlock(&g.lock);
  if (e == SD_E_NOT_FOUND)
    return fail(err, e, "not_found", "prompt not open");
  sd_jw_key(res, "accepted"); sd_jw_bool(res, e == SD_OK);
  return SD_OK;
}

/* prompt.list {}: the open and queued prompts (03 §2.1 row 11). */
static sd_err handle_prompt_list(sd_json_writer *res)
{
  host_prompt *r;
  uint64_t now = sd_tick_ms();
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "prompts");
  sd_jw_arr_begin(res);
  for (r = g.prompts; r; r = r->next) {
    if (r->expire)
      continue;
    sd_jw_obj_begin(res);
    sd_jw_key(res, "prompt_id"); sd_jw_cstr(res, r->pid);
    sd_jw_key(res, "mount_id"); sd_jw_cstr(res, r->mount_id);
    sd_jw_key(res, "profile_id"); sd_jw_cstr(res, r->profile_id);
    sd_jw_key(res, "kind"); sd_jw_cstr(res, r->kind);
    sd_jw_key(res, "queued"); sd_jw_bool(res, r->queued);
    sd_jw_key(res, "deadline_ms"); sd_jw_int(res, (int64_t)(r->deadline > now ? r->deadline - now : 0));
    sd_jw_obj_end(res);
  }
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

static sd_err handle_announced_list(sd_json_writer *res)
{
  host_announce *x;
  sd_mutex_lock(&g.lock);
  sd_jw_key(res, "announcements");
  sd_jw_arr_begin(res);
  for (x = g.announces; x; x = x->next)
    write_announce_json(res, x);
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* hostkey.announced.accept {id, add_only}: applies the reviewed announcement to the user store. */
static sd_err handle_announced_accept(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *id = sd_json_get_str(params, "id");
  int add_only = 0;
  host_announce **pp, *x = NULL;
  sd_kh_store st;
  sd_err e;
  sd_json_get_bool(params, "add_only", &add_only);
  if (id == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "id required");
  sd_mutex_lock(&g.lock);
  for (pp = &g.announces; *pp; pp = &(*pp)->next)
    if (strcmp((*pp)->id, id) == 0) { x = *pp; *pp = x->next; break; }
  sd_mutex_unlock(&g.lock);
  if (x == NULL)
    return fail(err, SD_E_NOT_FOUND, "announcement_not_found", "no such announcement");
  memset(&st, 0, sizeof(st));
  st.kind = SD_KH_STORE_USER;                    /* never the machine store from a user's connection */
  st.path = g.user_kh[0] ? g.user_kh : NULL;
  st.writable = 1;
  e = sd_mount_apply_hostkeys(host_backend(), &st, 1, &x->a, add_only);
  if (e != SD_OK) {
    sd_mutex_lock(&g.lock);                      /* keep it for another try */
    x->next = g.announces;
    g.announces = x;
    sd_mutex_unlock(&g.lock);
    return fail(err, e, NULL, "cannot update known_hosts");
  }
  SD_LOGI("agent", "host keys of %Hs updated (%u added, %u removed)", x->a.lookup_name, (unsigned)x->a.add_count,
          add_only ? 0u : (unsigned)x->a.remove_count);
  sd_jw_key(res, "host"); sd_jw_cstr(res, x->a.host);
  sd_jw_key(res, "added"); sd_jw_int(res, x->a.add_count);
  sd_jw_key(res, "removed"); sd_jw_int(res, add_only ? 0 : x->a.remove_count);
  sd_free(x);
  return SD_OK;
}

/* hostkey.announced.reject {id} (03 §2.4, 5.6): drops a kept announcement without changing any store. The CLI sends it
   when the user answers no to a hostkey add offer, so a refused offer leaves the list at once. */
static sd_err handle_announced_reject(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *id = sd_json_get_str(params, "id");
  host_announce **pp, *x = NULL;
  if (id == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "id required");
  sd_mutex_lock(&g.lock);
  for (pp = &g.announces; *pp; pp = &(*pp)->next)
    if (strcmp((*pp)->id, id) == 0) { x = *pp; *pp = x->next; break; }
  sd_mutex_unlock(&g.lock);
  if (x == NULL)
    return fail(err, SD_E_NOT_FOUND, "announcement_not_found", "no such announcement");
  SD_LOGI("agent", "host keys of %Hs not added (%s rejected)", x->a.lookup_name, x->id);
  sd_jw_key(res, "host"); sd_jw_cstr(res, x->a.host);
  sd_jw_key(res, "rejected"); sd_jw_bool(res, 1);
  sd_free(x);
  return SD_OK;
}

/* ---- hostkey add (03 §6.1, 5.2, TM-R04) ----
   hostkey.add {host, port, lookup, type?, expect?}: the profile whose host and port match is used (its
   authentication, jump hosts and proxies), else the host-only defaults of `mount --host`. The connection is a
   hostkey mount (hostkey_fetch, sd_mount): it authenticates, offers only the stored key types of the host and
   collects the other host keys inside that verified connection. The request is deferred: the reply is sent when the
   mount ends (reply_hostkey_add), so the IPC thread never waits for the network.
   expect: only the key with that SHA-256 fingerprint is stored, with no prompt (scripts); no match fails. Without
   expect the keys are kept as an announcement for review: the CLI asks, then calls hostkey.announced.accept
   {id, add_only: true}. A first contact (no stored key) offers the one key the server presented (5.2); accepting
   it is the trust decision. Reply: {host, lookup_name, verified, keys[{type, fingerprint}], id? (pending),
   added?, removed? (expect)}. */
static int hk_type_ok(const char *t)
{
  size_t i, n = strlen(t);
  if (n == 0 || n >= 64) return 0;
  for (i = 0; i < n; i++)
    if (!((t[i] >= 'a' && t[i] <= 'z') || (t[i] >= '0' && t[i] <= '9') || t[i] == '-' || t[i] == '@' || t[i] == '.'))
      return 0;
  return 1;
}

/* The IPC code and the English detail of a failed mount for hostkey add (the CLI maps the code to its text). */
static void hk_error_text(sd_err e, const char *mount_code, const char **code, char *detail, size_t cap)
{
  *code = "connect_failed";
  scopy(detail, cap, "cannot get the host keys of the server");
  if (e == SD_E_UNSUPPORTED) {
    *code = "not_implemented";
    scopy(detail, cap, "hostkey add is not available on this backend");
  } else if (e == SD_E_HOSTKEY_MISMATCH) {
    *code = "host_key_mismatch";
    scopy(detail, cap, "the server's host key does not match the stored one");
  } else if (e == SD_E_HOSTKEY_TYPE_UNAVAILABLE) {
    *code = "host_key_type_unavailable";
    scopy(detail, cap, "the server offers none of the key types stored for it");
  } else if (e == SD_E_HOSTKEY_REJECTED) {
    *code = "host_key_rejected";
    scopy(detail, cap, "the host key was not accepted");
  } else if (e == SD_E_INVALID_PARAM) {
    *code = "usage";
    scopy(detail, cap, "invalid host");
  } else if (e == SD_E_NO_MEMORY) {
    *code = NULL;
    scopy(detail, cap, "out of memory");
  } else if (mount_code != NULL) {
    *code = mount_code;
  }
}

/* The keys of a finished hostkey mount: the requested type only, fingerprints recomputed from the blobs. Writes the
   reply members into jw (the caller opened and closes the object). On failure sets *code and detail (IPC) and
   returns the error. */
static sd_err hk_complete(sd_json_writer *jw, host_mount *h, sd_mount_hk_fetch *f, const char **code, char *detail,
                          size_t cap)
{
  uint32_t i, n = 0;
  int found = -1;
  const char *type = h->hk_type[0] ? h->hk_type : NULL;
  const char *expect = h->hk_expect[0] ? h->hk_expect : NULL;
  int verified = f->verified != 0;
  for (i = 0; i < f->count; i++) {
    if (type != NULL && strcmp(f->keys[i].type, type) != 0)
      continue;
    if (sd_hostkey_fingerprint_sha256(f->keys[i].blob, f->keys[i].len, f->keys[i].fp_sha256) != SD_OK)
      continue;
    if (n != i)
      f->keys[n] = f->keys[i];
    n++;
  }
  f->count = n;
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, h->host);
  sd_jw_key(jw, "lookup_name"); sd_jw_cstr(jw, h->hk_lookup);
  sd_jw_key(jw, "verified"); sd_jw_bool(jw, verified);
  if (expect != NULL) {
    /* stored with no question: the user store only, as hostkey.announced.accept */
    sd_kh_store st;
    host_announce *x;
    sd_err e;
    for (i = 0; i < n; i++)
      if (strcmp(f->keys[i].fp_sha256, expect) == 0) { found = (int)i; break; }
    if (found < 0) {
      *code = verified ? "host_key_mismatch" : "host_key_rejected";
      scopy(detail, cap, "no key of the server has that fingerprint");
      return verified ? SD_E_HOSTKEY_MISMATCH : SD_E_HOSTKEY_REJECTED;
    }
    x = (host_announce *)sd_calloc(1, sizeof(*x));
    if (x == NULL) {
      *code = NULL;
      scopy(detail, cap, "out of memory");
      return SD_E_NO_MEMORY;
    }
    x->a.add[0] = f->keys[found];
    x->a.add_count = 1;
    scopy(x->a.host, sizeof(x->a.host), h->host);
    scopy(x->a.lookup_name, sizeof(x->a.lookup_name), h->hk_lookup);
    memset(&st, 0, sizeof(st));
    st.kind = SD_KH_STORE_USER;                  /* the user store only, as hostkey.announced.accept */
    st.path = g.user_kh[0] ? g.user_kh : NULL;
    st.writable = 1;
    e = sd_mount_apply_hostkeys(host_backend(), &st, 1, &x->a, 1);
    sd_free(x);
    if (e != SD_OK) {
      *code = NULL;
      scopy(detail, cap, "cannot update known_hosts");
      return e;
    }
    SD_LOGI("agent", "hostkey add: stored one key of %Hs (%s)", h->hk_lookup, verified ? "verified" : "first contact");
    sd_jw_key(jw, "added"); sd_jw_int(jw, 1);
    sd_jw_key(jw, "removed"); sd_jw_int(jw, 0);
    write_keys_json(jw, "keys", f->keys, n);
    return SD_OK;
  }
  write_keys_json(jw, "keys", f->keys, n);
  if (n > 0) {
    host_announce *x = (host_announce *)sd_calloc(1, sizeof(*x));
    unsigned long v;
    if (x == NULL) {
      *code = NULL;
      scopy(detail, cap, "out of memory");
      return SD_E_NO_MEMORY;
    }
    memcpy(x->a.add, f->keys, n * sizeof(f->keys[0]));
    x->a.add_count = n;
    scopy(x->a.host, sizeof(x->a.host), h->host);
    scopy(x->a.lookup_name, sizeof(x->a.lookup_name), h->hk_lookup);
    sd_mutex_lock(&g.lock);
    v = ++g.next_announce;
    _snprintf_s(x->id, sizeof(x->id), _TRUNCATE, "a-%lu", v);
    x->next = g.announces;
    g.announces = x;
    sd_mutex_unlock(&g.lock);
    sd_jw_key(jw, "id"); sd_jw_cstr(jw, x->id);
    SD_LOGI("agent", "hostkey add: %Hs offers %u key(s), kept for review (%s)", h->hk_lookup, (unsigned)n, x->id);
  }
  return SD_OK;
}

/* control thread: the hostkey mount ended; the deferred hostkey.add request is answered. */
static void reply_hostkey_add(host_mount *h, sd_mount *m, sd_err why)
{
  sd_mount_hk_fetch *f = NULL;
  sd_mount_failure fl;
  sd_wr d;
  sd_json_writer jw;
  const char *code = NULL;
  char detail[256];
  sd_err e = why;
  int ok = 0;
  if (h->defer_cid == 0 || g.srv == NULL)
    return;
  detail[0] = 0;
  if (why == SD_OK) {
    f = (sd_mount_hk_fetch *)sd_calloc(1, sizeof(*f));
    e = f == NULL ? SD_E_NO_MEMORY : sd_mount_get_hostkeys(m, f);
  }
  if (e == SD_OK) {
    sd_wr_init(&d, 16 * 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    e = hk_complete(&jw, h, f, &code, detail, sizeof(detail));
    if (e == SD_OK) {
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK) {
        ok = 1;
      } else {
        e = SD_E_INTERNAL;
        code = NULL;
        scopy(detail, sizeof(detail), "reply too large");
      }
    }
    if (ok) {
      sd_err se = sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, SD_OK, NULL, NULL, (const char *)d.p, d.len);
      if (se != SD_OK && se != SD_E_NOT_FOUND)
        SD_LOGW("agent", "%s: hostkey.add reply not sent (%s)", h->id, sd_err_name(se));
    }
    sd_wr_free(&d);
  }
  if (!ok) {
    if (why != SD_OK) {
      /* the mount itself failed: its error decides the code */
      memset(&fl, 0, sizeof(fl));
      sd_mount_get_failure(m, &fl);
      if (fl.err != SD_OK)
        e = fl.err;
      hk_error_text(e, fl.code, &code, detail, sizeof(detail));
      if (fl.detail[0] != 0 && code != NULL && strcmp(code, "connect_failed") == 0)
        scopy(detail, sizeof(detail), fl.detail);
    }
    (void)sd_ipc_reply_deferred(g.srv, h->defer_cid, h->defer_rid, e, code, detail, NULL, 0);
  }
  sd_free(f);
  h->defer_cid = 0;
}

/* The profile of a hostkey add: the first profile with the host and port (as mount finds it), else the host-only
   defaults of `mount --host`. The profile store is only read. */
typedef struct hk_match { const char *host; uint16_t port; sd_profile *out; int found; } hk_match;

static int hk_match_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  hk_match *k = (hk_match *)ctx;
  uint16_t pp = p->port ? p->port : 22;
  SD_UNUSED(path);
  if (p->host[0] != 0 && _stricmp(p->host, k->host) == 0 && pp == k->port) {
    *k->out = *p;
    k->found = 1;
    return 0;
  }
  return 1;
}

static sd_err handle_hostkey_add(sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *host = sd_json_get_str(params, "host");
  const char *lookup = sd_json_get_str(params, "lookup");
  const char *type = sd_json_get_str(params, "type");
  const char *expect = sd_json_get_str(params, "expect");
  const char *bad = NULL;
  int64_t port = 22;
  sd_profile *prof;
  hk_match k;
  sd_err e;

  sd_json_get_int64(params, "port", &port);
  if (host == NULL || host[0] == 0 || lookup == NULL || lookup[0] == 0 || port < 1 || port > 65535)
    return fail(err, SD_E_INVALID_PARAM, "usage", "host, port and lookup required");
  if (strlen(host) >= 256 || strlen(lookup) >= 300)
    return fail(err, SD_E_INVALID_PARAM, "usage", "host or lookup too long");
  if (type != NULL && !hk_type_ok(type))
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid key type");
  if (expect != NULL && strlen(expect) >= 96)
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid fingerprint");
  prof = (sd_profile *)sd_calloc(1, sizeof(sd_profile));
  if (prof == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  memset(&k, 0, sizeof(k));
  k.host = host;
  k.port = (uint16_t)port;
  k.out = prof;
  (void)sd_profile_enum(hk_match_cb, &k);
  if (!k.found) {
    sd_profile_defaults(prof);
    scopy(prof->host, sizeof(prof->host), host);
    scopy(prof->name, sizeof(prof->name), host);
    prof->port = (uint16_t)port;
    if (sd_profile_validate(prof, &bad) != SD_OK) {
      sd_free(prof);
      return fail(err, SD_E_INVALID_PARAM, "usage", bad ? bad : "invalid host");
    }
  }
  e = handle_mount_body(client, params, res, err, prof, 2);
  sd_free(prof);
  return e;
}

/* diag.collect (03 §10.5, 6.1): the agent's own data for "diag --bundle". Counts and warning codes only: no host
   name, user name or remote path is returned, so the bundle has nothing to anonymize from here. Open to every
   client of the pipe (the same as status counters). */
static sd_err handle_diag_collect(sd_json_writer *res)
{
  host_mount *h;
  uint32_t i, start, n = 0;
  sd_jw_key(res, "version"); sd_jw_cstr(res, SD_VERSION_STRING);
  sd_jw_key(res, "pid"); sd_jw_int(res, (int64_t)GetCurrentProcessId());
  sd_mutex_lock(&g.lock);
  for (h = g.mounts; h; h = h->next)
    if (!h->test_only)
      n++;
  sd_jw_key(res, "mounts"); sd_jw_int(res, (int64_t)n);
  sd_jw_key(res, "warnings");
  sd_jw_arr_begin(res);
  start = (g.warn_next + WARN_RING - g.warn_count) % WARN_RING;
  for (i = 0; i < g.warn_count; i++) {
    const host_warn *w = &g.warns[(start + i) % WARN_RING];
    sd_jw_cstr(res, w->code);
  }
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* events.recent {limit?} (03 §2.4): the newest records of the event history, oldest first, at most EVENT_RING (200;
   limit 1 to 200, default 200). Reply {events: [{seq, time, event, mount_id?, state?, code?}], last_seq}. seq counts
   from 1 in this agent process; a client that started later sees the same history as the others. Open to every
   client of the pipe, like list. */
static sd_err handle_events_recent(const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  int64_t limit = EVENT_RING;
  uint32_t n, first, k;
  if (sd_json_get(params, "limit") && (!sd_json_get_int64(params, "limit", &limit) || limit < 1 || limit > EVENT_RING))
    return fail(err, SD_E_INVALID_PARAM, "usage", "limit must be 1 to 200");
  sd_mutex_lock(&g.evlock);
  n = g.event_count < (uint32_t)limit ? g.event_count : (uint32_t)limit;
  first = (g.event_next + EVENT_RING - n) % EVENT_RING;
  sd_jw_key(res, "events");
  sd_jw_arr_begin(res);
  for (k = 0; k < n; k++) {
    const host_event *e = &g.events[(first + k) % EVENT_RING];
    sd_jw_obj_begin(res);
    sd_jw_key(res, "seq"); sd_jw_int(res, (int64_t)e->seq);
    sd_jw_key(res, "time"); sd_jw_int(res, e->time);
    sd_jw_key(res, "event"); sd_jw_cstr(res, e->event);
    if (e->mount_id[0]) { sd_jw_key(res, "mount_id"); sd_jw_cstr(res, e->mount_id); }
    if (e->state[0]) { sd_jw_key(res, "state"); sd_jw_cstr(res, e->state); }
    if (e->code[0]) { sd_jw_key(res, "code"); sd_jw_cstr(res, e->code); }
    sd_jw_obj_end(res);
  }
  sd_jw_arr_end(res);
  sd_jw_key(res, "last_seq"); sd_jw_int(res, (int64_t)g.event_seq);
  sd_mutex_unlock(&g.evlock);
  return SD_OK;
}

static sd_err ipc_handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                          sd_json_writer *res, sd_ipc_error *err)
{
  SD_UNUSED(ctx);
  if (strcmp(method, "hostkey.announced.list") == 0) return handle_announced_list(res);
  if (strcmp(method, "hostkey.announced.accept") == 0) return handle_announced_accept(params, res, err);
  if (strcmp(method, "hostkey.announced.reject") == 0) return handle_announced_reject(params, res, err);
  if (strcmp(method, "hostkey.add") == 0) return handle_hostkey_add(client, params, res, err);
  if (strcmp(method, "mount") == 0) return handle_mount(client, params, res, err);
  if (strcmp(method, "unmount") == 0) return handle_unmount(params, res, err);
  if (strcmp(method, "list") == 0) return handle_list(res);
  if (strcmp(method, "status") == 0) return handle_status(params, res, err);
  if (strcmp(method, "selftest") == 0) return handle_selftest(res);
  if (strcmp(method, "events.recent") == 0) return handle_events_recent(params, res, err);
  if (strcmp(method, "diag.collect") == 0) return handle_diag_collect(res);
  if (strcmp(method, "profile.test") == 0) return handle_profile_test(client, params, res, err);
  if (strcmp(method, "refresh") == 0) return handle_refresh(params, res, err);
  if (strcmp(method, "cache.clear") == 0) return handle_cache_clear(params, res, err);
  if (strcmp(method, "mount.attach_info") == 0) return handle_attach_info(params, res, err);
  if (strcmp(method, "log.tail") == 0) return handle_log_tail(params, res, err);
  if (strcmp(method, "config.reload") == 0) return handle_config_reload(params, res, err);
  if (strcmp(method, "prompt.answer") == 0) return handle_prompt_answer(client, params, res, err);
  if (strcmp(method, "prompt.list") == 0) return handle_prompt_list(res);
  if (strcmp(method, "update.check") == 0) return upd_method_check(g.srv, client, params, res, err);
  if (strcmp(method, "update.apply") == 0) return upd_method_apply(g.srv, client, params, res, err);
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

/* ---- M3 config.changed and agent.stopping (03 §2.4) ---- */

/* Event to every client that completed hello (events of the agent are not topic-bound here). */
static void broadcast_all_json(const char *event, sd_wr *data)
{
  sd_wr w;
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  if (g.srv && sd_ipc_build_event(event, (const char *)data->p, data->len, &w) == SD_OK)
    (void)sd_ipc_broadcast_all(g.srv, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* config.changed {what: "settings" | "profiles", ids?}: runs on the watch thread. The ids of the profiles are the
   ids of the changed files that still exist (a removed profile is not named; clients list again). */
static void on_config_changed(void *ctx, const char *what, const wchar_t *const *paths, uint32_t npaths)
{
  sd_wr d;
  sd_json_writer jw;
  uint32_t i;
  SD_UNUSED(ctx);
  sd_wr_init(&d, 16 * 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "what"); sd_jw_cstr(&jw, what);
  if (strcmp(what, "profiles") == 0) {
    sd_jw_key(&jw, "ids");
    sd_jw_arr_begin(&jw);
    for (i = 0; i < npaths; i++) {
      sd_profile *p = (sd_profile *)sd_alloc(sizeof(sd_profile));
      const char *bad = NULL;
      if (p != NULL && sd_profile_load_file(paths[i], p, &bad) == SD_OK && p->id[0])
        sd_jw_cstr(&jw, p->id);
      sd_free(p);
    }
    sd_jw_arr_end(&jw);
  }
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_all_json("config.changed", &d);
  sd_wr_free(&d);
  SD_LOGI("agent", "configuration changed: %s", what);
}

/* agent.stopping {reason}: sent once when the shutdown sequence starts (request, event or idle). */
static void broadcast_stopping(void)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 256);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "reason"); sd_jw_cstr(&jw, g.stop_reason ? g.stop_reason : "request");
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_all_json("agent.stopping", &d);
  sd_wr_free(&d);
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
  uint64_t next_sweep = 0;

  memset(&g, 0, sizeof(g));
  (void)log_ring_start();
  g.prompt_queue_max = PROMPT_QUEUE_MAX;
  g.prompt_ms = PROMPT_DEADLINE_MS;
  g.reconnect_prompt_ms = PROMPT_RECONNECT_MS;
  g.ui_launch = 1;
#ifdef SD_HOST_TEST_HOOKS
  g.prompt_ms = env_u32(L"SHELLDRIVE_TEST_PROMPT_MS", (uint32_t)g.prompt_ms);
  g.reconnect_prompt_ms = env_u32(L"SHELLDRIVE_TEST_RECONNECT_PROMPT_MS", (uint32_t)g.reconnect_prompt_ms);
  g.prompt_queue_max = env_u32(L"SHELLDRIVE_TEST_PROMPT_QUEUE_MAX", g.prompt_queue_max);
  g.no_route = env_u32(L"SHELLDRIVE_TEST_PROMPT_NO_ROUTE", 0) != 0;
  /* a test agent never starts the prompt UI: the UI would reach the default instance and start the real
     agent. Only a test that asks for the launch sets SHELLDRIVE_TEST_UI_LAUNCH=1. */
  g.ui_launch = env_u32(L"SHELLDRIVE_TEST_UI_LAUNCH", 0) != 0;
#endif
  g.boot_tick = sd_tick_ms();
  (void)sd_settings_load(&g.settings);
  sd_log_set_level((sd_log_level)g.settings.log_level);
  log_privacy_apply(&g.settings);
  {
    sd_secret_config sc;
    wchar_t root[MAX_PATH];
    memset(&sc, 0, sizeof(sc));
    sc.persist_enterprise = g.settings.persist_enterprise;
#ifdef SD_HOST_TEST_HOOKS
    {
      /* tests: secrets live as DPAPI files under the test root, never in the real Credential Manager */
      static wchar_t tdir[MAX_PATH];
      if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", tdir, MAX_PATH) - 1u < MAX_PATH - 1u) {
        sc.user_dir = tdir;
        sc.prefix = "com.librestatic.shelldrive.test:";
        sc.force_dpapi = 1;
      }
    }
#endif
    sd_secret_configure(&sc);
    if (sd_config_root(root, SD_COUNTOF(root)) == SD_OK && wcslen(root) + 13 < SD_COUNTOF(g.user_kh)) {
      memcpy(g.user_kh, root, (wcslen(root) + 1) * sizeof(wchar_t));
      wcscat_s(g.user_kh, SD_COUNTOF(g.user_kh), L"\\known_hosts");
    }
  }
  sd_mutex_init(&g.lock);
  sd_mutex_init(&g.qlock);
  sd_mutex_init(&g.evlock);
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

  /* M3: the snapshot section (03 §8.2.1) exists before any client can connect; then the Explorer data
     left by a crashed agent is reconciled (03 §8.3, §8.7). */
  explorer_init();
  if (host_state_open() != SD_OK)
    SD_LOGW("agent", "state snapshot unavailable (named object squatted or no memory)");
  explorer_reconcile_start();
  /* menu.cache (03 §8.2.2) is rewritten on every profile change; one rewrite here also covers profiles made before it
     existed or edited by hand. A failure only leaves the old file (or the empty submenu) in place. */
  if (sd_menucache_refresh() != SD_OK)
    SD_LOGW("agent", "menu.cache not refreshed at start");

  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = ipc_handler;
  cfg.on_disconnect = ipc_on_disconnect;
  cfg.on_subscribe = ipc_on_subscribe;
  cfg.features = k_agent_features;
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
  if (config_watch_start(on_config_changed, NULL) != SD_OK)
    SD_LOGI("agent", "configuration watch not started (no config root)");
  g.last_busy = sd_tick_ms();
  post(NULL, work_autostart, NULL);     /* M3 mount.autostart = logon (03 §3.4.1) */

  while (!g.stop) {
    HANDLE hs[2];
    DWORD n = 0, w;
    hs[n++] = g.qev;
    if (stop_ev) hs[n++] = stop_ev;
    w = WaitForMultipleObjects(n, hs, FALSE, 1000);
    if (stop_ev && w == WAIT_OBJECT_0 + 1) {
      SD_LOGI("agent", "shutdown event signaled");
      g.stop_reason = "event";
      break;
    }
    drain();
    if (sd_tick_ms() >= next_sweep) {
      next_sweep = sd_tick_ms() + 1000;
      prompt_sweep();
    }
    if (!opts->logon && opts->idle_exit_ms) {
      uint64_t now = sd_tick_ms();
      if (!mounts_empty() || sd_ipc_server_client_count(g.srv) > 0)
        g.last_busy = now;
      else if (now - g.last_busy > opts->idle_exit_ms) {
        SD_LOGI("agent", "idle; exiting");
        g.stop_reason = "idle";
        break;
      }
    }
  }

  /* Shutdown sequence (1.2): the config watch stops, agent.stopping goes out, every mount is stopped, the wait
     (bounded) for teardown, then the pipe. */
  config_watch_stop();
  broadcast_stopping();
  Sleep(100);                           /* the pipe thread writes the queued events; there is no flush call */
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
  explorer_shutdown();                  /* icons of this agent go; the snapshot is emptied below */
  host_state_close();
  /* mounts that did not finish their teardown in time must not leave a mapping behind (TM-R17) */
  cleanup_webdav_mappings("stop");
  SetUnhandledExceptionFilter(g_prev_filter);
  while (g.prompts) {
    host_prompt *r = g.prompts;
    g.prompts = r->next;
    prompt_free(r);
  }
  while (g.announces) {
    host_announce *x = g.announces;
    g.announces = x->next;
    sd_free(x);
  }
  if (ready) CloseHandle(ready);
  if (stop_ev) CloseHandle(stop_ev);
  if (mutex) CloseHandle(mutex);
  SD_LOGI("agent", "agent stopped");
  log_ring_stop();
  return 0;
}
