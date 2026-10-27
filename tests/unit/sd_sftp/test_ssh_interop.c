/* sd-test-sftp-ssh-interop: sd_sftp over sd_ssh against the WSL sshd fixture (tests/fixtures/wsl-sshd;
 * D21: test infrastructure only). Exit code 77 (CTest "skipped") when the fixture is not running.
 *
 * M1 resilience (00 §6 M1 acceptance, 01 §10.6): sshd is killed during a 256 MiB pipelined read and
 * during a 256 MiB pipelined write and restarted; the session reconnects by itself, the stale
 * handles are reopened and the transfer finishes from the last acknowledged offset, verified with
 * SHA-256 on both sides. Also: meta + bulk channels, a TCP drop with the listener alive, and a
 * frozen (silent) link detected by the liveness probe after a request timeout (C16). Faults are
 * injected with tests/fixtures/wsl-sshd/ctl.sh.
 *
 * M2 pool striping (01 §10.9): a striped handle over a three-connection pool writes and reads a
 * >= 32 MiB pattern with every byte verified and payload on every member connection, and a single
 * member connection is dropped mid-transfer: its reads are re-issued on the primary, its writes
 * complete with SD_E_DISCONNECTED / maybe_executed / session_ready, the session stays READY and
 * usable. ctl.sh cannot drop a single connection (kill/drop take the listener or every session),
 * so the per-member fault is built from the fixture state (see ctl_drop_one_member). */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_test.h"
#include "sftp_test_tp.h"
#include "test_util.h"

#define BIG       (256ull * 1024ull * 1024ull)
#define SLOTS     8
#define BLK       (4u * 1024u * 1024u)
#define RDIR      "/tmp/sd-m1-interop"
#define M2_TOTAL  (32ull * 1024ull * 1024ull)   /* striped transfer size: 128+ stripe units */
#define M2_BURST  24                             /* requests submitted while the fixture is frozen */
#define M2_BUNIT  (1024u * 1024u)                /* their size */
#define M2_FOLLOW (8ull * 1024ull * 1024ull)    /* follow-up transfer after a member loss */

static char g_dir[MAX_PATH], g_dir_wsl[MAX_PATH];
static char g_user[64], g_key[MAX_PATH], g_hostkey[256];
static char g_key_enc[MAX_PATH], g_pass[128];
static uint16_t g_port = 2222;
/* The fixture's direct address in WSL NAT mode ("direct_host" in state/env) bypasses the localhost relay,
   which can wedge when sshd is killed during heavy traffic; SD_SSHD_VIA_RELAY=1 forces 127.0.0.1. */
static char g_host[64] = "127.0.0.1";
static wchar_t g_whost[64] = L"127.0.0.1";
static wchar_t g_wsl[MAX_PATH], g_kh_path[MAX_PATH];

/* ---- fixture ---- */

static void trim(char *s)
{
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ')) s[--n] = 0;
}

static int load_env(void)
{
  char path[MAX_PATH], line[512];
  FILE *f;
  size_t i;
  DWORD n = GetEnvironmentVariableA("SD_SSH_WSL_FIXTURE_DIR", g_dir, sizeof(g_dir));
  if (n == 0 || n >= sizeof(g_dir)) _snprintf_s(g_dir, sizeof(g_dir), _TRUNCATE, "%s", SD_SSH_WSL_FIXTURE_DIR);
  for (i = 0; g_dir[i]; i++) if (g_dir[i] == '\\') g_dir[i] = '/';
  if (g_dir[0] && g_dir[1] == ':')    /* default WSL automount */
    _snprintf_s(g_dir_wsl, sizeof(g_dir_wsl), _TRUNCATE, "/mnt/%c%s", (char)(g_dir[0] | 0x20), g_dir + 2);
  else
    _snprintf_s(g_dir_wsl, sizeof(g_dir_wsl), _TRUNCATE, "%s", g_dir);
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/state/env", g_dir);
  if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
  while (fgets(line, sizeof(line), f)) {
    char *eq = strchr(line, '=');
    trim(line);
    if (!eq) continue;
    *eq = 0;
    if (strcmp(line, "user") == 0) _snprintf_s(g_user, sizeof(g_user), _TRUNCATE, "%s", eq + 1);
    else if (strcmp(line, "port") == 0) g_port = (uint16_t)atoi(eq + 1);
    else if (strcmp(line, "direct_host") == 0 && !GetEnvironmentVariableA("SD_SSHD_VIA_RELAY", NULL, 0) &&
             strlen(eq + 1) < sizeof(g_host)) {
      _snprintf_s(g_host, sizeof(g_host), _TRUNCATE, "%s", eq + 1);
      MultiByteToWideChar(CP_UTF8, 0, g_host, -1, g_whost, (int)SD_COUNTOF(g_whost));
    }
    else if (strcmp(line, "key") == 0) _snprintf_s(g_key, sizeof(g_key), _TRUNCATE, "%s/state/%s", g_dir, eq + 1);
    else if (strcmp(line, "key_enc") == 0) _snprintf_s(g_key_enc, sizeof(g_key_enc), _TRUNCATE, "%s/state/%s", g_dir, eq + 1);
    else if (strcmp(line, "pass") == 0) _snprintf_s(g_pass, sizeof(g_pass), _TRUNCATE, "%s", eq + 1);
    else if (strcmp(line, "hostkey") == 0) _snprintf_s(g_hostkey, sizeof(g_hostkey), _TRUNCATE, "%s", eq + 1);
  }
  fclose(f);
  return g_user[0] && g_key[0] && g_hostkey[0];
}

/* Dotted-quad parser (inet_pton is Vista+, inet_addr is deprecated); host byte order. */
static uint32_t ipv4_or_loopback(const char *h)
{
  uint32_t v = 0, part = 0;
  int dots = 0, digits = 0;
  for (; *h; h++) {
    if (*h >= '0' && *h <= '9') { part = part * 10u + (uint32_t)(*h - '0'); if (++digits > 3 || part > 255) return 0x7F000001u; }
    else if (*h == '.' && digits && dots < 3) { v = (v << 8) | part; part = 0; digits = 0; dots++; }
    else return 0x7F000001u;
  }
  if (dots != 3 || !digits) return 0x7F000001u;
  return (v << 8) | part;
}

static int port_open(void)
{
  SOCKET s;
  struct sockaddr_in a;
  int ok;
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(g_port);
  a.sin_addr.s_addr = htonl(ipv4_or_loopback(g_host));
  ok = connect(s, (struct sockaddr *)&a, sizeof(a)) == 0;
  closesocket(s);
  return ok;
}

static int find_wsl(void)
{
  UINT n = GetSystemDirectoryW(g_wsl, MAX_PATH);
  if (n == 0 || n + 20 >= MAX_PATH) return 0;
  wcscat_s(g_wsl, MAX_PATH, L"\\wsl.exe");
  if (GetFileAttributesW(g_wsl) != INVALID_FILE_ATTRIBUTES) return 1;
  n = GetSystemWindowsDirectoryW(g_wsl, MAX_PATH);      /* x86 under WOW64: System32 is SysWOW64 */
  if (n == 0 || n + 20 >= MAX_PATH) return 0;
  wcscat_s(g_wsl, MAX_PATH, L"\\Sysnative\\wsl.exe");
  return GetFileAttributesW(g_wsl) != INVALID_FILE_ATTRIBUTES;
}

/* Runs `sh -c script` in WSL (script must not contain double quotes). */
static int wsl_sh(const char *script, uint32_t timeout_ms)
{
  wchar_t cmd[4096], ws[3000];
  if (MultiByteToWideChar(CP_UTF8, 0, script, -1, ws, (int)SD_COUNTOF(ws)) <= 0) return -1;
  _snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%s\" -e sh -c \"%s\"", g_wsl, ws);
  return run_cmd(cmd, timeout_ms);
}

static int ctl(const char *what)
{
  char s[1024];
  _snprintf_s(s, sizeof(s), _TRUNCATE, "sh '%s/ctl.sh' %s >/dev/null 2>&1", g_dir_wsl, what);
  return wsl_sh(s, 60000);
}

/* Local ports of this process's ESTABLISHED IPv4 connections to the fixture (the primary and the
 * pool members; an abandoned admission attempt is closed on this side and is not listed). */
static int fixture_conn_ports(uint16_t *ports, int cap, int *count)
{
  DWORD size = 0, pid = GetCurrentProcessId(), i;
  PMIB_TCPTABLE_OWNER_PID t;
  int n = 0;
  *count = 0;
  if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) !=
      ERROR_INSUFFICIENT_BUFFER)
    return 0;
  t = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
  if (!t) return 0;
  if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR) {
    free(t);
    return 0;
  }
  for (i = 0; i < t->dwNumEntries; i++) {
    const MIB_TCPROW_OWNER_PID *r = &t->table[i];
    if (r->dwOwningPid != pid || r->dwState != MIB_TCP_STATE_ESTAB) continue;
    if (ntohs((u_short)r->dwRemotePort) != g_port) continue;
    if (n < cap) ports[n] = ntohs((u_short)r->dwLocalPort);
    n++;
  }
  free(t);
  *count = n;
  return 1;
}

/* Fault for the pool member tests: ctl.sh only knows whole-fixture verbs (kill: the listener and
 * every session, drop: every session), so a single member connection is dropped from the fixture
 * state instead. The member is identified by its TCP peer port: the pool holds exactly three
 * ESTABLISHED connections (the primary plus two members). Local ports are not allocated in connect
 * order, so they cannot tell the primary apart; the fixture's sshd accepts connections in order and
 * the members connect only after READY, so on the server the primary's per-connection monitor has
 * the lowest pid and the victim is the highest-pid monitor among the three. The fixture side finds
 * each connection's sshd session by its peer port (the connection is direct, no relay, so the
 * client's local port is the server's peer port), climbs to its monitor (a direct child of the
 * listener) and kills that subtree; the listener and the other connections stay up. SIGKILL also works on the frozen (SIGSTOPped) processes the member-drop
 * tests leave behind. The chosen port is logged to <fixture>/state/drop_win.log. */
static int ctl_drop_one_member(void)
{
  uint16_t ports[8], victim = 0;
  int cnt = 0, i;
  char s[1800], logp[MAX_PATH];
  FILE *f;
  if (!fixture_conn_ports(ports, 8, &cnt) || cnt != 3) return 2;
  for (i = 0; i < cnt; i++)
    if (ports[i] > victim) victim = ports[i];
  _snprintf_s(logp, sizeof(logp), _TRUNCATE, "%s/state/drop_win.log", g_dir);
  if (fopen_s(&f, logp, "a") == 0 && f) {
    fprintf(f, "drop: established=%d ports=%u,%u,%u victim=%u\n", cnt, (unsigned)ports[0],
            (unsigned)ports[1], (unsigned)ports[2], (unsigned)victim);
    fclose(f);
  }
  _snprintf_s(s, sizeof(s), _TRUNCATE,
    "run=${XDG_STATE_HOME:-$HOME/.local/state}/shelldrive-wsl-sshd; "
    "root=$(cat $run/sshd.pid 2>/dev/null) || exit 1; "
    "best=0; bestp=0; "
    "for p in %u %u %u; do "
    "pid=$(ss -Htnp state established '( sport = :%u )' | awk -v p=:$p '{ if (substr($4, length($4) - length(p) + 1) == p) { print; exit } }' | sed 's/.*pid=\\([0-9]*\\).*/\\1/'); "
    "case $pid in ''|*[!0-9]*) echo no sshd for port $p >> '%s/state/drop.log'; exit 1;; esac; "
    "m=$(ps -eo pid=,ppid= | awk -v q=$pid -v r=$root '{p[$1]=$2} END {x=q; while ((x in p) && p[x]!=r && x>1) x=p[x]; if (p[x]==r) print x}'); "
    "case $m in ''|*[!0-9]*) echo no monitor for port $p >> '%s/state/drop.log'; exit 1;; esac; "
    "echo port $p session $pid monitor $m >> '%s/state/drop.log'; "
    "if [ $m -gt $best ]; then best=$m; bestp=$p; fi; "
    "done; "
    "n=$best; "
    "echo drop victim port $bestp monitor $n >> '%s/state/drop.log'; "
    "ps -eo pid=,ppid= | awk -v r=$n "
    "'{p[$1]=$2} END {for (q in p) { x=q; while ((x in p) && x!=r && x>1) x=p[x]; "
    "if (x==r && q!=r) print q }}' | xargs -r kill -9 2>/dev/null; "
    "kill -9 $n 2>/dev/null; exit 0",
    (unsigned)ports[0], (unsigned)ports[1], (unsigned)ports[2], (unsigned)g_port,
    g_dir_wsl, g_dir_wsl, g_dir_wsl, g_dir_wsl);
  return wsl_sh(s, 60000);
}

/* SHA-256 (hex) of a remote file, computed in WSL and passed back through the fixture state dir. */
static int remote_sha(const char *rpath, char out[65])
{
  char s[1024], path[MAX_PATH];
  FILE *f;
  size_t n;
  _snprintf_s(s, sizeof(s), _TRUNCATE, "sha256sum '%s' | cut -c1-64 > '%s/state/m1.sha'", rpath, g_dir_wsl);
  if (wsl_sh(s, 120000) != 0) return 0;
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/state/m1.sha", g_dir);
  if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
  n = fread(out, 1, 64, f);
  fclose(f);
  out[n < 64 ? n : 64] = 0;
  return n == 64;
}

static void hex(const uint8_t *d, size_t n, char *out)
{
  static const char k[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) { out[2 * i] = k[d[i] >> 4]; out[2 * i + 1] = k[d[i] & 15]; }
  out[2 * n] = 0;
}

/* ---- session ---- */

typedef struct ev {
  sd_mutex lock;
  sd_event changed;
  sd_sftp_session *session;       /* set before the session starts; for stats snapshots */
  uint32_t ready_gen, channels;
  uint32_t n_pool, pool_conns;
  sd_sftp_state last;
  int n_disc, n_wait, n_failed;
  sd_err disc_reason;
  sd_sftp_stats pool_st;          /* snapshot taken when a POOL drop event arrives */
} ev;

static void ev_cb(void *ctx, const sd_sftp_event *e)
{
  ev *x = (ev *)ctx;
  sd_mutex_lock(&x->lock);
  if (e->type == SD_SFTP_EV_STATE) {
    x->last = e->state;
    if (e->state == SD_SFTP_ST_DISCONNECTED) { x->n_disc++; x->disc_reason = e->reason; }
    if (e->state == SD_SFTP_ST_RECONNECT_WAIT) x->n_wait++;
    if (e->state == SD_SFTP_ST_FAILED) x->n_failed++;
    printf("  [event] state %d reason %s retry %u attempt %u\n", (int)e->state, sd_err_name(e->reason),
           e->retry_in_ms, e->attempt);
  } else if (e->type == SD_SFTP_EV_POOL) {
    x->n_pool++;
    x->pool_conns = e->connections;
    printf("  [event] POOL member %u -> %u connection(s), reason %s\n", e->member,
           e->connections, sd_err_name(e->reason));
    if (e->reason != SD_OK && x->session && sd_sftp_session_stats(x->session, &x->pool_st) == SD_OK) {
      uint32_t i;
      for (i = 0; i < x->pool_st.conn_count; i++)
        printf("  [event]   conn[%u] rx %llu tx %llu\n", i,
               (unsigned long long)x->pool_st.conn[i].rx_total,
               (unsigned long long)x->pool_st.conn[i].tx_total);
    }
  } else if (e->type == SD_SFTP_EV_READY_INFO) {
    x->ready_gen = e->info->generation;
    x->channels = e->info->channels;
    printf("  [event] READY_INFO generation %u channels %u\n", e->info->generation, e->info->channels);
  }
  sd_mutex_unlock(&x->lock);
  sd_event_set(&x->changed);
}

static int wait_gen(sd_sftp_session *s, ev *x, uint32_t gen, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    uint32_t g;
    sd_mutex_lock(&x->lock);
    g = x->ready_gen;
    sd_mutex_unlock(&x->lock);
    if (g >= gen && sd_sftp_session_state(s) == SD_SFTP_ST_READY) return 1;
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&x->changed, 50);
  }
}

static int wait_not_ready(sd_sftp_session *s, ev *x, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_sftp_session_state(s) == SD_SFTP_ST_READY) {
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&x->changed, 50);
  }
  return 1;
}

static char g_answer_passphrase;    /* on_prompt answers key passphrases with g_pass */

static void on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  SD_UNUSED(ctx); SD_UNUSED(h);
  if (g_answer_passphrase && a && a->kind == SD_PROMPT_KEY_PASSPHRASE) {
    const char *resp[1] = { g_pass };
    sd_prompt_answer(p, 1, resp);
    return;
  }
  SD_UNUSED(a);
  sd_prompt_cancel(p);                 /* known host, plain key: no prompt is expected */
}

typedef struct fx {
  sd_known_hosts *kh;
  sd_sftp_session *s;
  ev e;
} fx;

static int fx_start_opt(fx *x, uint32_t keepalive_ms, uint32_t connections, const char *key_utf8)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_identity id;
  sd_ssh_callbacks cb;
  sd_sftp_options opt;
  sd_kh_store st;
  wchar_t wkey[MAX_PATH];
  char line[400];
  HANDLE h;
  DWORD w;
  memset(x, 0, sizeof(*x));
  sd_mutex_init(&x->e.lock);
  (void)sd_event_init(&x->e.changed, 0, 0);
  /* known_hosts with the fixture's key: every connect is a MATCH */
  _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s]:%u %s\n", g_host, (unsigned)g_port, g_hostkey);
  h = CreateFileW(g_kh_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  WriteFile(h, line, (DWORD)strlen(line), &w, NULL);
  CloseHandle(h);
  st.kind = SD_KH_STORE_USER;
  st.path = g_kh_path;
  st.writable = 1;
  if (sd_known_hosts_open(&st, 1, &x->kh) != SD_OK) return 0;
  memset(&cfg, 0, sizeof(cfg));
  memset(&hop, 0, sizeof(hop));
  memset(&id, 0, sizeof(id));
  memset(&cb, 0, sizeof(cb));
  MultiByteToWideChar(CP_UTF8, 0, key_utf8 ? key_utf8 : g_key, -1, wkey, MAX_PATH);
  id.kind = SD_ID_FILE;
  id.path = wkey;
  hop.host = g_whost;
  hop.port = g_port;
  hop.auth.user = g_user;
  hop.auth.identities = &id;
  hop.auth.identity_count = 1;
  hop.auth.methods = SD_AUTH_PUBLICKEY;
  hop.auth.identities_only = 1;
  cfg.struct_size = sizeof(cfg);
  cfg.hops = &hop;
  cfg.hop_count = 1;
  cfg.known_hosts = x->kh;
  cfg.connect_timeout_ms = 10000;
  cfg.keepalive_interval_ms = keepalive_ms;
  cb.on_prompt = on_prompt;
  sd_sftp_options_init(&opt);
  opt.connections = connections;
  opt.reconnect.initial_delay_ms = 300;
  opt.reconnect.max_delay_ms = 2000;
  opt.default_timeout_ms = 30000;
  if (sd_sftp_session_create(&cfg, &cb, &opt, ev_cb, &x->e, &x->s) != SD_OK) return 0;
  x->e.session = x->s;
  if (sd_sftp_session_start(x->s) != SD_OK) return 0;
  if (wait_gen(x->s, &x->e, 1, 30000)) return 1;
  /* the first connect does not loop by itself; one fixture hiccup is retried through reconnect_now */
  printf("  first connect ended in state %d; retrying with reconnect_now\n", (int)sd_sftp_session_state(x->s));
  if (sd_sftp_session_reconnect_now(x->s) != SD_OK) return 0;
  return wait_gen(x->s, &x->e, 1, 60000);
}

static int fx_start(fx *x, uint32_t keepalive_ms)
{
  return fx_start_opt(x, keepalive_ms, 1, NULL);
}

static void fx_stop(fx *x)
{
  if (x->s) {
    (void)sd_sftp_session_close(x->s);
    {
      uint64_t end = sd_tick_ms() + 10000;
      while (sd_sftp_session_state(x->s) != SD_SFTP_ST_CLOSED && sd_tick_ms() < end) Sleep(10);
    }
    sd_sftp_session_destroy(x->s);
  }
  if (x->kh) sd_known_hosts_close(x->kh);
  sd_event_destroy(&x->e.changed);
  sd_mutex_destroy(&x->e.lock);
}

/* ---- pipelined transfers ---- */

typedef struct slot { waiter w; uint8_t *buf; uint64_t off; uint32_t len; int busy; } slot;

static void pattern(uint8_t *p, uint64_t off, uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++) {
    uint64_t o = off + i;
    p[i] = (uint8_t)((((o >> 3) * 2654435761u) >> 11) ^ ((o & 7u) * 37u));
  }
}

typedef struct xfer {
  sd_sftp_file *f;
  int write;
  uint64_t total;
  sd_hash_ctx *h;                 /* reads: hash of the data in order */
  uint8_t *ref;                   /* reads: pattern reference; every buffer is compared (t.corrupt) */
  int corrupt;                    /* a read buffer did not match the pattern */
  uint64_t kill_at;               /* inject the fault once `done` passes this offset (0: never) */
  const char *fault;              /* ctl.sh command */
  int faulted;
  sd_err err;                     /* first error */
} xfer;

static int submit(xfer *t, slot *s, uint64_t off)
{
  sd_sftp_reqopt o = { 0, 60000, NULL };
  sd_err e;
  s->off = off;
  s->len = (uint32_t)(t->total - off < BLK ? t->total - off : BLK);
  waiter_reset(&s->w, W_RW);
  if (t->write) {
    pattern(s->buf, off, s->len);
    e = sd_sftp_write(t->f, off, s->buf, s->len, &o, waiter_cb, &s->w);
  } else {
    e = sd_sftp_read(t->f, off, s->buf, s->len, &o, waiter_cb, &s->w);
  }
  if (e != SD_OK) { if (t->err == SD_OK) t->err = e; s->busy = 0; return 0; }
  s->busy = 1;
  return 1;
}

/* Transfers [from, total) with SLOTS requests of BLK in flight; returns the contiguous offset that
   was read (and hashed) or acknowledged. */
static uint64_t pipe_xfer(xfer *t, slot *sl, uint64_t from)
{
  uint64_t next = from, done = from;
  int head = 0, i, stop = 0;
  t->err = SD_OK;
  for (i = 0; i < SLOTS && next < t->total; i++) { if (!submit(t, &sl[i], next)) { stop = 1; break; } next += sl[i].len; }
  while (done < t->total) {
    slot *s = &sl[head];
    if (!s->busy) break;
    if (!waiter_wait(&s->w, 120000)) { t->err = SD_E_TIMEOUT; break; }
    s->busy = 0;
    if (s->w.err != SD_OK || s->w.bytes != s->len) {
      if (t->err == SD_OK) t->err = s->w.err != SD_OK ? s->w.err : SD_E_EOF;
      break;
    }
    if (!t->write && t->h) sd_hash_update(t->h, s->buf, s->len);
    if (!t->write && t->ref) {
      pattern(t->ref, s->off, s->len);
      if (memcmp(t->ref, s->buf, s->len) != 0) {
        t->corrupt = 1;
        printf("  pattern mismatch in [%llu, %llu)\n", (unsigned long long)s->off,
               (unsigned long long)(s->off + s->len));
        if (t->err == SD_OK) t->err = SD_E_INTERNAL;
        break;
      }
    }
    done += s->len;
    if (t->kill_at && !t->faulted && done >= t->kill_at) {
      t->faulted = 1;
      printf("  injecting '%s' at %llu MiB\n", t->fault, (unsigned long long)(done >> 20));
      (void)ctl(t->fault);
    }
    if (!stop && t->err == SD_OK && next < t->total) {
      if (submit(t, s, next)) next += s->len;
      else stop = 1;
    }
    head = (head + 1) % SLOTS;
  }
  for (i = 0; i < SLOTS; i++)       /* every buffer must be free before it is reused */
    if (sl[i].busy) { (void)waiter_wait(&sl[i].w, 120000); sl[i].busy = 0; }
  return done;
}

static slot *slots_new(void *session)
{
  slot *sl = (slot *)sd_calloc(SLOTS, sizeof(slot));
  int i;
  if (!sl) return NULL;
  for (i = 0; i < SLOTS; i++) {
    waiter_init(&sl[i].w, session);
    sl[i].buf = (uint8_t *)sd_alloc(BLK);
    if (!sl[i].buf) return NULL;
  }
  return sl;
}

static void slots_free(slot *sl)
{
  int i;
  if (!sl) return;
  for (i = 0; i < SLOTS; i++) { waiter_free(&sl[i].w); sd_free(sl[i].buf); }
  sd_free(sl);
}

static sd_err open_sync(sd_sftp_session *s, const char *path, uint32_t fl, sd_sftp_file **out)
{
  sd_sftp_attrs a;
  return sd_sftp_open_sync(s, path, fl, NULL, out, &a, 30000);
}

static sd_err reopen_sync(sd_sftp_file *f, sd_sftp_attrs *attrs)
{
  waiter w;
  sd_sftp_reqopt o = { 0, 30000, NULL };
  sd_err e;
  waiter_init(&w, NULL);
  waiter_reset(&w, W_OPEN);
  e = sd_sftp_file_reopen(f, &o, waiter_cb, &w);
  if (e == SD_OK) { e = waiter_wait(&w, 35000) ? w.err : SD_E_TIMEOUT; if (attrs) *attrs = w.attrs; }
  waiter_free(&w);
  return e;
}

/* ---- tests ---- */

SD_TEST(m1_session_two_channels)
{
  fx x;
  sd_sftp_server_info info;
  sd_sftp_stats st;
  sd_sftp_attrs a;
  SD_REQUIRE(fx_start(&x, 0));
  SD_CHECK(sd_sftp_session_info(x.s, &info, NULL, 0) == SD_OK);
  SD_CHECK_EQ_INT(info.channels, 2);
  SD_CHECK_EQ_INT(info.generation, 1);
  SD_CHECK(info.ext & SD_SFTP_EXT_POSIX_RENAME);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(x.s, "/", &a, 10000), SD_OK);
  SD_CHECK(sd_sftp_session_stats(x.s, &st) == SD_OK && st.channels == 2 && st.generation == 1);
  printf("  srtt %u ms\n", st.conn[0].srtt_ms);
  fx_stop(&x);
}

static void kill_restart(sd_test_ctx *sd_t_, fx *x, uint32_t gen)
{
  SD_CHECK(wait_not_ready(x->s, &x->e, 30000));
  Sleep(800);                                       /* a few refused reconnect attempts */
  SD_CHECK_EQ_INT(ctl("start"), 0);
  SD_CHECK(wait_gen(x->s, &x->e, gen, 60000));
}

SD_TEST(m1_kill_sshd_during_pipelined_read)
{
  fx x;
  sd_sftp_file *f = NULL;
  slot *sl;
  xfer t;
  sd_hash_ctx h;
  uint8_t dg[32];
  char want[65], got[65];
  uint64_t done;
  uint64_t t0;
  sd_sftp_attrs a;
  SD_REQUIRE(wsl_sh("mkdir -p " RDIR " && head -c 268435456 /dev/urandom > " RDIR "/read.bin", 120000) == 0);
  SD_REQUIRE(remote_sha(RDIR "/read.bin", want));
  SD_REQUIRE(fx_start(&x, 0));
  sl = slots_new(x.s);
  SD_REQUIRE(sl != NULL);
  SD_REQUIRE(open_sync(x.s, RDIR "/read.bin", SD_SFTP_O_READ, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.total = BIG;
  t.h = &h;
  t.kill_at = BIG / 4;
  t.fault = "kill";
  sd_hash_init(&h, SD_HASH_SHA256);
  t0 = sd_tick_ms();
  done = pipe_xfer(&t, sl, 0);
  printf("  first pass: %llu MiB, then %s\n", (unsigned long long)(done >> 20), sd_err_name(t.err));
  SD_CHECK(t.faulted);
  SD_CHECK(done < BIG);
  SD_CHECK(t.err == SD_E_DISCONNECTED || t.err == SD_E_STALE_HANDLE);
  kill_restart(sd_t_, &x, 2);
  /* the handle is stale; reopen it in generation 2 and finish from the last contiguous offset */
  {
    sd_sftp_file_info fi;
    SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && fi.stale);
  }
  SD_REQUIRE(reopen_sync(f, &a) == SD_OK);
  SD_CHECK_EQ_U64(a.size, BIG);
  t.kill_at = 0;
  done = pipe_xfer(&t, sl, done);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK_EQ_U64(done, BIG);
  sd_hash_final(&h, dg);
  hex(dg, 32, got);
  SD_CHECK_STR(got, want);
  printf("  256 MiB read across a sshd restart in %llu ms\n", (unsigned long long)(sd_tick_ms() - t0));
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 10000), SD_OK);
  slots_free(sl);
  fx_stop(&x);
  (void)wsl_sh("rm -f " RDIR "/read.bin", 30000);
}

SD_TEST(m1_kill_sshd_during_pipelined_write)
{
  fx x;
  sd_sftp_file *f = NULL;
  slot *sl;
  xfer t;
  sd_hash_ctx h;
  uint8_t dg[32];
  char want[65], got[65];
  uint64_t done, off;
  uint8_t *tmp;
  SD_REQUIRE(wsl_sh("mkdir -p " RDIR " && rm -f " RDIR "/write.bin", 30000) == 0);
  SD_REQUIRE(fx_start(&x, 0));
  sl = slots_new(x.s);
  tmp = (uint8_t *)sd_alloc(BLK);
  SD_REQUIRE(sl != NULL && tmp != NULL);
  SD_REQUIRE(open_sync(x.s, RDIR "/write.bin", SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.write = 1;
  t.total = BIG;
  t.kill_at = BIG / 4;
  t.fault = "kill";
  done = pipe_xfer(&t, sl, 0);
  printf("  first pass: %llu MiB acknowledged, then %s\n", (unsigned long long)(done >> 20), sd_err_name(t.err));
  SD_CHECK(t.faulted);
  SD_CHECK(done < BIG);
  SD_CHECK(t.err == SD_E_DISCONNECTED || t.err == SD_E_STALE_HANDLE);
  kill_restart(sd_t_, &x, 2);
  /* reopen (O_WRITE, without CREAT/TRUNC) and re-send everything after the acknowledged prefix */
  SD_REQUIRE(reopen_sync(f, NULL) == SD_OK);
  t.kill_at = 0;
  done = pipe_xfer(&t, sl, done);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK_EQ_U64(done, BIG);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  sd_hash_init(&h, SD_HASH_SHA256);
  for (off = 0; off < BIG; off += BLK) { pattern(tmp, off, BLK); sd_hash_update(&h, tmp, BLK); }
  sd_hash_final(&h, dg);
  hex(dg, 32, want);
  SD_REQUIRE(remote_sha(RDIR "/write.bin", got));
  SD_CHECK_STR(got, want);
  sd_free(tmp);
  slots_free(sl);
  fx_stop(&x);
  (void)wsl_sh("rm -f " RDIR "/write.bin", 30000);
}

SD_TEST(m1_tcp_drop_reconnects)
{
  fx x;
  sd_sftp_file *f = NULL;
  sd_sftp_attrs a;
  uint8_t buf[4096];
  uint32_t got = 0;
  SD_REQUIRE(wsl_sh("mkdir -p " RDIR " && head -c 1048576 /dev/urandom > " RDIR "/small.bin", 30000) == 0);
  SD_REQUIRE(fx_start(&x, 0));
  SD_REQUIRE(open_sync(x.s, RDIR "/small.bin", SD_SFTP_O_READ, &f) == SD_OK);
  SD_CHECK_EQ_INT(ctl("drop"), 0);                  /* the listener stays: reconnect at once */
  SD_CHECK(wait_gen(x.s, &x.e, 2, 30000));
  SD_CHECK_EQ_INT(x.e.disc_reason, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(sd_sftp_read_sync(f, 0, buf, sizeof(buf), &got, 10000), SD_E_STALE_HANDLE);
  SD_REQUIRE(reopen_sync(f, &a) == SD_OK);
  SD_CHECK_EQ_U64(a.size, 1048576);
  SD_CHECK_EQ_INT(sd_sftp_read_sync(f, 1000, buf, sizeof(buf), &got, 10000), SD_OK);
  SD_CHECK_EQ_INT(got, sizeof(buf));
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 10000), SD_OK);
  fx_stop(&x);
}

SD_TEST(m1_frozen_link_liveness_probe)
{
  fx x;
  sd_sftp_attrs a;
  uint64_t t0, dt;
  SD_REQUIRE(fx_start(&x, 60000));                  /* keepalives far away: only the probe can tell */
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(x.s, "/", &a, 10000), SD_OK);
  SD_CHECK_EQ_INT(ctl("freeze"), 0);
  t0 = sd_tick_ms();
  /* the request times out; the liveness probe then declares the link dead (01 §4.6, C16) */
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(x.s, "/", &a, 2000), SD_E_TIMEOUT);
  SD_CHECK(wait_not_ready(x.s, &x.e, 10000));
  dt = sd_tick_ms() - t0;
  printf("  link declared dead after %llu ms (%s)\n", (unsigned long long)dt, sd_err_name(x.e.disc_reason));
  SD_CHECK(dt < 9000);
  SD_CHECK_EQ_INT(x.e.disc_reason, SD_E_TIMEOUT);
  SD_CHECK(wait_gen(x.s, &x.e, 2, 30000));          /* new connection, served by the live listener */
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(x.s, "/", &a, 10000), SD_OK);
  fx_stop(&x);
  (void)ctl("reap");
}

/* ---- M2 connection pool (01 §10.9) ---- */

/* Waits until the session reports `want` connections (stats include admitted members). */
static int wait_pool(fx *x, uint32_t want, uint32_t ms)
{
  sd_sftp_stats st;
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    if (sd_sftp_session_stats(x->s, &st) == SD_OK && st.conn_count >= want) return 1;
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&x->e.changed, 100);
  }
}

SD_TEST(m2_pool_admits_members)
{
  fx x;
  sd_sftp_stats st;
  if (!fx_start_opt(&x, 15000, 3, NULL)) { SD_CHECK(!"fixture connect failed"); return; }
  /* admission happens after READY: INIT/VERSION/realpath per member, one at a time */
  if (!wait_pool(&x, 3, 30000)) {
    sd_sftp_session_stats(x.s, &st);
    printf("  pool reached %u/3 connections\n", st.conn_count);
    SD_CHECK(!"pool members were not admitted");
  } else {
    sd_sftp_session_stats(x.s, &st);
    SD_CHECK_EQ_INT(st.conn_count, 3);
    SD_CHECK(st.conn[1].ready && st.conn[2].ready);
    SD_CHECK(x.e.n_pool >= 2);
    sd_mutex_lock(&x.e.lock);
    SD_CHECK_EQ_INT(x.e.pool_conns, 3);
    sd_mutex_unlock(&x.e.lock);
  }
  fx_stop(&x);
}

/* The 2FA rule: authentication that showed a prompt (here: a key passphrase answered by the
   "user") keeps the pool at 1 for the session, 01 §10.9. */
SD_TEST(m2_pool_interactive_stays_at_one)
{
  fx x;
  sd_sftp_stats st;
  if (!g_key_enc[0] || !g_pass[0]) { printf("  [skip] no encrypted fixture key\n"); return; }
  g_answer_passphrase = 1;
  if (!fx_start_opt(&x, 15000, 3, g_key_enc)) {
    g_answer_passphrase = 0;
    SD_CHECK(!"fixture connect failed");
    return;
  }
  g_answer_passphrase = 0;
  Sleep(3000);                          /* admission would have started right after READY */
  sd_sftp_session_stats(x.s, &st);
  SD_CHECK_EQ_INT(st.conn_count, 1);
  sd_mutex_lock(&x.e.lock);
  SD_CHECK_EQ_INT(x.e.n_pool, 0);
  sd_mutex_unlock(&x.e.lock);
  fx_stop(&x);
}

/* ---- M2 pool striping (01 §10.9) ---- */

/* Waits until the pool reports at most `want` connections (a member was dropped; admissions only
   grow it). */
static int wait_pool_lost(fx *x, uint32_t want, uint32_t ms)
{
  sd_sftp_stats st;
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    if (sd_sftp_session_stats(x->s, &st) == SD_OK && st.conn_count <= want) return 1;
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&x->e.changed, 100);
  }
}

/* Hash of the deterministic pattern over [0, total), the reference for the remote SHA-256. */
static void pattern_sha(uint8_t *ref, uint64_t total, char out[65])
{
  sd_hash_ctx h;
  uint8_t dg[32];
  uint64_t off;
  sd_hash_init(&h, SD_HASH_SHA256);
  for (off = 0; off < total; off += BLK) { pattern(ref, off, BLK); sd_hash_update(&h, ref, BLK); }
  sd_hash_final(&h, dg);
  hex(dg, 32, out);
}

/* A >= 32 MiB deterministic pattern goes through a striped handle on a three-connection pool and
   every byte comes back; every member connection carried payload in both directions. */
SD_TEST(m2_striping_end_to_end)
{
  fx x;
  sd_sftp_file *f = NULL;
  slot *sl;
  xfer t;
  sd_sftp_stats st;
  uint8_t *ref;
  char want[65], got[65];
  uint64_t done, t0;
  uint32_t i;
  SD_REQUIRE(wsl_sh("mkdir -p " RDIR " && rm -f " RDIR "/stripe.bin", 30000) == 0);
  if (!fx_start_opt(&x, 0, 3, NULL)) { SD_CHECK(!"fixture connect failed"); return; }
  SD_REQUIRE(wait_pool(&x, 3, 30000));
  sl = slots_new(x.s);
  ref = (uint8_t *)sd_alloc(BLK);
  SD_REQUIRE(sl != NULL && ref != NULL);
  /* striped write: stripe units alternate primary / member 1 / member 2 (route k % 3) */
  SD_REQUIRE(open_sync(x.s, RDIR "/stripe.bin",
                       SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC | SD_SFTP_O_STRIPED, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.write = 1;
  t.total = M2_TOTAL;
  t0 = sd_tick_ms();
  done = pipe_xfer(&t, sl, 0);
  printf("  striped write: %s, %llu MiB in %llu ms\n", sd_err_name(t.err),
         (unsigned long long)(done >> 20), (unsigned long long)(sd_tick_ms() - t0));
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK_EQ_U64(done, M2_TOTAL);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  /* the server really holds the pattern */
  pattern_sha(ref, M2_TOTAL, want);
  SD_REQUIRE(remote_sha(RDIR "/stripe.bin", got));
  SD_CHECK_STR(got, want);
  /* striped read-back: pipe_xfer compares every read buffer against the pattern */
  SD_REQUIRE(open_sync(x.s, RDIR "/stripe.bin", SD_SFTP_O_READ | SD_SFTP_O_STRIPED, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.total = M2_TOTAL;
  t.ref = ref;
  done = pipe_xfer(&t, sl, 0);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK(!t.corrupt);
  SD_CHECK_EQ_U64(done, M2_TOTAL);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  /* the pool did the work: every member connection carried payload in both directions */
  SD_CHECK(sd_sftp_session_stats(x.s, &st) == SD_OK);
  SD_CHECK_EQ_INT(st.conn_count, 3);
  for (i = 1; i < st.conn_count; i++) {
    printf("  conn[%u] rx %llu tx %llu bytes\n", i, (unsigned long long)st.conn[i].rx_total,
           (unsigned long long)st.conn[i].tx_total);
    SD_CHECK(st.conn[i].rx_total > 0 && st.conn[i].tx_total > 0);
  }
  printf("  %llu MiB striped write + read over 3 connections in %llu ms\n",
         (unsigned long long)((2 * M2_TOTAL) >> 20), (unsigned long long)(sd_tick_ms() - t0));
  sd_free(ref);
  slots_free(sl);
  fx_stop(&x);
  (void)wsl_sh("rm -f " RDIR "/stripe.bin", 30000);
}

/* Exactly one member connection is dropped mid-transfer, deterministically: the fixture's sftp
   processes are frozen (ctl.sh freeze), then a burst of striped requests is submitted - emission
   is submit-driven, so every channel ends up with pieces that can never be answered - then the
   newest connection of the listener (the last member admitted, see ctl_drop_one_member) is
   killed and the rest thawed. The member's in-flight reads are re-issued on the primary and the
   data still verifies byte for byte; its in-flight writes complete with SD_E_DISCONNECTED /
   maybe_executed / session_ready; the session never leaves READY and a follow-up striped open +
   transfer succeeds. A fresh session per phase: the other member must survive the drop. */
SD_TEST(m2_striping_member_lost_mid_transfer)
{
  fx x;
  sd_sftp_file *f = NULL;
  slot *sl;
  xfer t;
  sd_sftp_stats st;
  sd_sftp_reqopt o = { 0, 60000, NULL };
  static waiter bw[M2_BURST];
  uint8_t *bb[M2_BURST];
  uint8_t *ref;
  uint64_t off, done, s1_tx;
  int i, n_fail = 0, fail_maybe = 0, fail_ready = 0;
  waiter w0;

  /* -- reads across the loss of one member connection -- */
  SD_REQUIRE(wsl_sh("mkdir -p " RDIR " && rm -f " RDIR "/ml_src.bin", 30000) == 0);
  if (!fx_start_opt(&x, 0, 3, NULL)) { SD_CHECK(!"fixture connect failed"); return; }
  SD_REQUIRE(wait_pool(&x, 3, 30000));
  sl = slots_new(x.s);
  ref = (uint8_t *)sd_alloc(BLK);
  SD_REQUIRE(sl != NULL && ref != NULL);
  /* the source file, written through a plain (non-striped) handle */
  SD_REQUIRE(open_sync(x.s, RDIR "/ml_src.bin",
                       SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.write = 1;
  t.total = M2_TOTAL;
  done = pipe_xfer(&t, sl, 0);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK_EQ_U64(done, M2_TOTAL);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  /* striped read; the warm-up completes, so both member sub-handles are open */
  SD_REQUIRE(open_sync(x.s, RDIR "/ml_src.bin", SD_SFTP_O_READ | SD_SFTP_O_STRIPED, &f) == SD_OK);
  waiter_init(&w0, x.s);
  waiter_reset(&w0, W_RW);
  bb[0] = (uint8_t *)sd_alloc(M2_BUNIT);
  SD_REQUIRE(bb[0] != NULL);
  SD_CHECK_EQ_INT(sd_sftp_read(f, 0, bb[0], M2_BUNIT, &o, waiter_cb, &w0), SD_OK);
  SD_CHECK(waiter_wait(&w0, 60000) && w0.err == SD_OK && w0.bytes == M2_BUNIT);
  pattern(ref, 0, M2_BUNIT);
  SD_CHECK(!memcmp(ref, bb[0], M2_BUNIT));
  waiter_free(&w0);
  sd_free(bb[0]);
  /* freeze the fixture: replies stop from now on. The burst is submitted while frozen: its
     pieces go out (emission is submit-driven) and can never be answered, so the kill below is
     certain to land on wires the member really carried. */
  SD_CHECK_EQ_INT(ctl("freeze"), 0);
  for (i = 0; i < M2_BURST; i++) {
    bb[i] = (uint8_t *)sd_alloc(M2_BUNIT);
    SD_REQUIRE(bb[i] != NULL);
    off = (uint64_t)(i + 1) * M2_BUNIT;
    waiter_init(&bw[i], x.s);
    waiter_reset(&bw[i], W_RW);
    SD_CHECK_EQ_INT(sd_sftp_read(f, off, bb[i], M2_BUNIT, &o, waiter_cb, &bw[i]), SD_OK);
  }
  {
    sd_sftp_stats fst;
    uint32_t seen = 0;
    uint64_t ft0 = sd_tick_ms();
    while (sd_tick_ms() - ft0 < 2500) {
      if (sd_sftp_session_stats(x.s, &fst) == SD_OK) {
        seen = fst.conn[0].inflight_reqs;
        if (seen >= 12) break;
      }
      Sleep(20);
    }
    printf("  fixture frozen, burst of %d MiB read in flight (%u pieces); dropping one member\n",
           M2_BURST, seen);
    SD_CHECK_EQ_INT(ctl_drop_one_member(), 0);
    SD_CHECK_EQ_INT(ctl("thaw"), 0);
  }
  /* every burst read completes: the pieces the member carried were re-issued on the primary */
  for (i = 0; i < M2_BURST; i++) {
    off = (uint64_t)(i + 1) * M2_BUNIT;
    if (!waiter_wait(&bw[i], 60000)) { SD_CHECK(!"burst read did not complete"); continue; }
    SD_CHECK_EQ_INT(bw[i].err, SD_OK);
    SD_CHECK_EQ_INT((int)bw[i].bytes, (int)M2_BUNIT);
    pattern(ref, off, M2_BUNIT);
    SD_CHECK(!memcmp(ref, bb[i], M2_BUNIT));
    waiter_free(&bw[i]);
    sd_free(bb[i]);
  }
  printf("  all %d burst reads completed and verified after the member loss\n", M2_BURST);
  /* the pool shrank by exactly one member; the session never dropped */
  SD_CHECK(wait_pool_lost(&x, 2, 15000));
  SD_CHECK(sd_sftp_session_stats(x.s, &st) == SD_OK);
  SD_CHECK_EQ_INT(st.conn_count, 2);
  SD_CHECK_EQ_INT((int)sd_sftp_session_state(x.s), (int)SD_SFTP_ST_READY);
  sd_mutex_lock(&x.e.lock);
  SD_CHECK(x.e.n_disc == 0 && x.e.n_failed == 0);
  SD_CHECK(x.e.n_pool >= 3);            /* two admissions and at least the drop */
  SD_CHECK_EQ_INT(x.e.pool_conns, 2);   /* the drop event, not an admission, came last */
  sd_mutex_unlock(&x.e.lock);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  sd_free(ref);
  slots_free(sl);
  fx_stop(&x);

  /* -- writes across the loss: the member's in-flight writes surface DISCONNECTED -- */
  if (!fx_start_opt(&x, 0, 3, NULL)) { SD_CHECK(!"fixture reconnect failed"); return; }
  SD_REQUIRE(wait_pool(&x, 3, 30000));
  sl = slots_new(x.s);
  ref = (uint8_t *)sd_alloc(BLK);
  SD_REQUIRE(sl != NULL && ref != NULL);
  SD_REQUIRE(open_sync(x.s, RDIR "/ml_dst.bin",
                       SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC | SD_SFTP_O_STRIPED, &f) == SD_OK);
  /* warm-up write so both member sub-handles are open before the freeze */
  waiter_init(&w0, x.s);
  waiter_reset(&w0, W_RW);
  pattern(ref, 0, M2_BUNIT);
  SD_CHECK_EQ_INT(sd_sftp_write(f, 0, ref, M2_BUNIT, &o, waiter_cb, &w0), SD_OK);
  SD_CHECK(waiter_wait(&w0, 60000) && w0.err == SD_OK && w0.bytes == M2_BUNIT);
  waiter_free(&w0);
  SD_CHECK_EQ_INT(ctl("freeze"), 0);
  for (i = 0; i < M2_BURST; i++) {
    bb[i] = (uint8_t *)sd_alloc(M2_BUNIT);
    SD_REQUIRE(bb[i] != NULL);
    off = (uint64_t)(i + 1) * M2_BUNIT;
    pattern(bb[i], off, M2_BUNIT);
    waiter_init(&bw[i], x.s);
    waiter_reset(&bw[i], W_RW);
    SD_CHECK_EQ_INT(sd_sftp_write(f, off, bb[i], M2_BUNIT, &o, waiter_cb, &bw[i]), SD_OK);
  }
  {
    sd_sftp_stats fst;
    uint32_t seen = 0;
    uint64_t ft0 = sd_tick_ms();
    while (sd_tick_ms() - ft0 < 2500) {
      if (sd_sftp_session_stats(x.s, &fst) == SD_OK) {
        seen = fst.conn[0].inflight_reqs;
        if (seen >= 12) break;
      }
      Sleep(20);
    }
    printf("  fixture frozen, burst of %d MiB written in flight (%u pieces); dropping one member\n",
           M2_BURST, seen);
    SD_CHECK_EQ_INT(ctl_drop_one_member(), 0);
    SD_CHECK_EQ_INT(ctl("thaw"), 0);
  }
  /* the writes the member carried fail; writes on the live channels were acknowledged */
  for (i = 0; i < M2_BURST; i++) {
    if (!waiter_wait(&bw[i], 60000)) { SD_CHECK(!"burst write did not complete"); continue; }
    if (bw[i].err == SD_E_DISCONNECTED && bw[i].session_ready) {
      if (!n_fail) { fail_maybe = bw[i].maybe_executed; fail_ready = bw[i].session_ready; }
      n_fail++;
    } else {
      SD_CHECK_EQ_INT(bw[i].err, SD_OK);
    }
    waiter_free(&bw[i]);
    sd_free(bb[i]);
  }
  printf("  member drop failed %d of %d burst write(s)\n", n_fail, M2_BURST);
  SD_CHECK(n_fail >= 1);
  SD_CHECK_EQ_INT(fail_maybe, 1);   /* the request was sent: the server-side effect is unknown */
  SD_CHECK_EQ_INT(fail_ready, 1);   /* the failure came from a member, not from the session */
  SD_CHECK_EQ_INT((int)sd_sftp_session_state(x.s), (int)SD_SFTP_ST_READY);
  sd_mutex_lock(&x.e.lock);
  SD_CHECK(x.e.n_disc == 0 && x.e.n_failed == 0);
  sd_mutex_unlock(&x.e.lock);
  SD_CHECK(wait_pool_lost(&x, 2, 15000));
  SD_CHECK(sd_sftp_session_stats(x.s, &st) == SD_OK);
  SD_CHECK_EQ_INT(st.conn_count, 2);    /* exactly one member was lost, the other one survived */
  s1_tx = st.conn[1].tx_total;
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;

  /* -- the session is still usable: a follow-up striped open + transfer succeeds -- */
  SD_REQUIRE(open_sync(x.s, RDIR "/ml_dst.bin",
                       SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC | SD_SFTP_O_STRIPED, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.write = 1;
  t.total = M2_FOLLOW;
  done = pipe_xfer(&t, sl, 0);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK_EQ_U64(done, M2_FOLLOW);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  SD_REQUIRE(open_sync(x.s, RDIR "/ml_dst.bin", SD_SFTP_O_READ | SD_SFTP_O_STRIPED, &f) == SD_OK);
  memset(&t, 0, sizeof(t));
  t.f = f;
  t.total = M2_FOLLOW;
  t.ref = ref;
  done = pipe_xfer(&t, sl, 0);
  SD_CHECK_EQ_INT(t.err, SD_OK);
  SD_CHECK(!t.corrupt);
  SD_CHECK_EQ_U64(done, M2_FOLLOW);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 30000), SD_OK);
  f = NULL;
  /* the surviving member carried the follow-up traffic */
  SD_CHECK(sd_sftp_session_stats(x.s, &st) == SD_OK);
  SD_CHECK_EQ_INT(st.conn_count, 2);
  printf("  surviving member conn[1] tx %llu -> %llu bytes\n", (unsigned long long)s1_tx,
         (unsigned long long)st.conn[1].tx_total);
  SD_CHECK(st.conn[1].tx_total > s1_tx);
  SD_CHECK_EQ_INT((int)sd_sftp_session_state(x.s), (int)SD_SFTP_ST_READY);
  sd_free(ref);
  slots_free(sl);
  fx_stop(&x);
  (void)wsl_sh("rm -f " RDIR "/ml_src.bin " RDIR "/ml_dst.bin", 30000);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(m1_session_two_channels),
  SD_TEST_ENTRY(m1_kill_sshd_during_pipelined_read),
  SD_TEST_ENTRY(m1_kill_sshd_during_pipelined_write),
  SD_TEST_ENTRY(m1_tcp_drop_reconnects),
  SD_TEST_ENTRY(m1_frozen_link_liveness_probe),
  SD_TEST_ENTRY(m2_pool_admits_members),
  SD_TEST_ENTRY(m2_pool_interactive_stays_at_one),
  SD_TEST_ENTRY(m2_striping_end_to_end),
  SD_TEST_ENTRY(m2_striping_member_lost_mid_transfer),
};

int main(int argc, char **argv)
{
  int rc;
  sd_log_set_level(SD_LOG_WARN);
  if (sd_ssh_global_init() != SD_OK) return 1;
  if (!load_env()) {
    printf("interop.sftp_ssh skipped: fixture not started (%s/state/env missing); run tests/fixtures/wsl-sshd/start.ps1\n", g_dir);
    return 77;
  }
  if (!port_open()) {
    printf("interop.sftp_ssh skipped: nothing listens on %s:%u\n", g_host, (unsigned)g_port);
    return 77;
  }
  if (!find_wsl()) { printf("interop.sftp_ssh skipped: wsl.exe not found\n"); return 77; }
  {
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n + 40 >= MAX_PATH) return 1;
    _snwprintf_s(g_kh_path, MAX_PATH, _TRUNCATE, L"%ssd_m1_known_hosts_%lu", tmp, GetCurrentProcessId());
  }
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  if (!port_open()) (void)ctl("start");           /* leave the fixture running for other tests */
  DeleteFileW(g_kh_path);
  (void)wsl_sh("rm -rf " RDIR, 30000);
  return rc;
}
