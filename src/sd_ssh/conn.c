/* Connection object, I/O thread, sockets and transport dispatch (01 §3, §4.1, §4.6).
 *
 * One I/O thread per connection waits on {cmd_ev, socket event(s)} with the next timer as timeout.
 * Blocking work (DNS, known_hosts, key files) runs on worker items that post their result back.
 * Errors found deep inside the protocol code only record the failure (ssh_fail); the connection
 * is torn down at the next safe point of the loop, so no callback frees state a caller still uses. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <string.h>

#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "conn_internal.h"

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0x00000400
#endif

#define SSH_IDENT_C "SSH-2.0-ShellDrive_" SD_SSH_STR(SD_VERSION_MAJOR) "." SD_SSH_STR(SD_VERSION_MINOR)
#define SD_SSH_STR_(x) #x
#define SD_SSH_STR(x) SD_SSH_STR_(x)

#define SSH_IN_MAX (SSH_MAX_PACKET_LEN * 2u + 128u * 1024u)
#define SSH_KEXINIT_WAIT_MS 3000u
#define SSH_ATTEMPT_STAGGER_MS 250u

const char ssh_ident_c[] = SSH_IDENT_C;

uint64_t ssh_now(void) { return sd_tick_ms(); }

void ssh_log(sd_ssh_conn *c, sd_log_level level, _Printf_format_string_ const char *fmt, ...)
{
  char buf[1024];
  va_list ap;
  if (!sd_log_enabled(level) && !(c && c->cb.on_log)) return;
  va_start(ap, fmt);
  sd_log_format(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  sd_log(level, "ssh", NULL, "%s", buf);
  if (c && c->cb.on_log) c->cb.on_log(c->cb.ctx, (int)level, buf);
}

void ssh_sanitize(const uint8_t *p, size_t n, char *out, size_t cap)
{
  size_t ol = 0;
  if (cap == 0) return;
  n = SD_MIN(n, (cap - 1) / 3);
  if (sd_text_sanitize_server((const char *)p, n, out, cap - 1, &ol) != SD_OK) ol = 0;
  out[ol] = '\0';
}

/* ---- global init ---- */

static sd_once g_wsa_once = SD_ONCE_INIT;
static sd_err g_wsa_err = SD_E_INTERNAL;

static void wsa_init(void *arg)
{
  WSADATA wd;
  SD_UNUSED(arg);
  sd_platform_init();
  g_wsa_err = WSAStartup(MAKEWORD(2, 2), &wd) == 0 ? SD_OK : SD_E_INTERNAL;
}

sd_err sd_ssh_global_init(void)
{
  sd_once_run(&g_wsa_once, wsa_init, NULL);
  return g_wsa_err;
}

/* ---- command queue and workers ---- */

sd_err ssh_post_cmd(sd_ssh_conn *c, ssh_cmd *cmd)
{
  sd_ssh_conn *r = c->root ? c->root : c;    /* M2: every hop posts to the chain's queue */
  cmd->next = NULL;
  cmd->conn = c;
  sd_mutex_lock(&r->qlock);
  if (r->queue_closed) { sd_mutex_unlock(&r->qlock); return SD_E_SHUTDOWN; }
  if (r->qtail) r->qtail->next = cmd; else r->qhead = cmd;
  r->qtail = cmd;
  sd_mutex_unlock(&r->qlock);
  SetEvent(r->cmd_ev);
  return SD_OK;
}

static DWORD WINAPI work_thunk(LPVOID arg)
{
  ssh_work *w = (ssh_work *)arg;
  sd_ssh_conn *c = w->c;
  sd_ssh_conn *r = c->root ? c->root : c;
  w->work(w);
  if (ssh_post_cmd(c, &w->cmd) != SD_OK) w->cmd.drop(&w->cmd);
  if (InterlockedDecrement(&r->workers) == 0) SetEvent(r->workers_idle);
  return 0;
}

sd_err ssh_queue_work(sd_ssh_conn *c, ssh_work *w)
{
  sd_ssh_conn *r = c->root ? c->root : c;
  w->c = c;
  w->gen = c->gen;
  if (InterlockedIncrement(&r->workers) == 1) ResetEvent(r->workers_idle);
  if (!QueueUserWorkItem(work_thunk, w, WT_EXECUTELONGFUNCTION)) {
    if (InterlockedDecrement(&r->workers) == 0) SetEvent(r->workers_idle);
    return SD_E_INTERNAL;
  }
  return SD_OK;
}

typedef struct post_cmd { ssh_cmd cmd; void (*fn)(void *); void *arg; } post_cmd;
static void post_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  post_cmd *pc = (post_cmd *)cmd;
  void (*fn)(void *) = pc->fn;
  void *arg = pc->arg;
  SD_UNUSED(c);
  sd_free(pc);
  fn(arg);
}
static void post_drop(ssh_cmd *cmd) { sd_free(cmd); }

sd_err sd_ssh_conn_post(sd_ssh_conn *c, void (*fn)(void *), void *arg)
{
  post_cmd *pc;
  sd_err e;
  if (!c || !fn) return SD_E_INVALID_PARAM;
  pc = (post_cmd *)sd_calloc(1, sizeof(*pc));
  if (!pc) return SD_E_NO_MEMORY;
  pc->cmd.run = post_run;
  pc->cmd.drop = post_drop;
  pc->fn = fn;
  pc->arg = arg;
  e = ssh_post_cmd(c, &pc->cmd);
  if (e != SD_OK) sd_free(pc);
  return e;
}

int sd_ssh_conn_is_io_thread(const sd_ssh_conn *c)
{
  const sd_ssh_conn *r;
  if (!c) return 0;
  r = c->root ? c->root : c;
  return r->thread.id == GetCurrentThreadId();
}

/* ---- output ---- */

size_t ssh_out_pending(const sd_ssh_conn *c) { return (c->out.len - c->out_off) + c->pend_bytes; }

/* The byte stream below SSH exists: the TCP socket (hop 0) or the open tunnel (hop i >= 1). */
static int lower_up(const sd_ssh_conn *c)
{
  return c->s != INVALID_SOCKET || (c->tun && c->tun->open && c->tun->ch);
}

static void flush_out(sd_ssh_conn *c)
{
  if (c->tun) {      /* hop i >= 1: the direct-tcpip channel on hop i-1 (01 §3.3) */
    while (c->tun && c->tun->open && c->tun->ch && c->out_off < c->out.len && !c->failing) {
      size_t acc = 0;
      sd_err e = sd_ssh_channel_write(c->tun->ch, c->out.p + c->out_off, c->out.len - c->out_off, &acc);
      if (e != SD_OK) { ssh_fail(c, SD_E_DISCONNECTED, 0, "tunnel write failed"); return; }
      if (acc == 0) break;      /* the tunnel's on_writable flushes again */
      c->out_off += acc;
    }
  }
  while (c->s != INVALID_SOCKET && c->out_off < c->out.len) {
    size_t n = SD_MIN(c->out.len - c->out_off, (size_t)256 * 1024);
    int r = send(c->s, (const char *)c->out.p + c->out_off, (int)n, 0);
    if (r == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) break;
      ssh_fail(c, SD_E_DISCONNECTED, 0, "send failed");
      return;
    }
    c->out_off += (size_t)r;
  }
  if (c->out_off == c->out.len) {
    c->out_off = 0;
    if (c->out.cap > 4u * 1024u * 1024u) { sd_wr_free(&c->out); sd_wr_init(&c->out, 64u * 1024u * 1024u); }
    else sd_wr_reset(&c->out);
  } else if (c->out_off > 1024u * 1024u) {
    memmove(c->out.p, c->out.p + c->out_off, c->out.len - c->out_off);
    c->out.len -= c->out_off;
    c->out_off = 0;
  }
}

static int msg_is_transport(uint8_t m) { return m >= 1 && m <= 49; }

sd_err ssh_send(sd_ssh_conn *c, const uint8_t *payload, size_t n)
{
  sd_err e;
  if (c->failing || c->st == SSH_ST_CLOSED) return SD_E_DISCONNECTED;
  if (n == 0) return SD_E_INVALID_PARAM;
  /* During a KEX only transport messages go out; everything else waits for our NEWKEYS (01 §4.4). */
  if (c->kex.active && c->kex.we_sent_kexinit && !c->kex.newkeys_sent && !msg_is_transport(payload[0])) {
    ssh_pending *pn = (ssh_pending *)sd_alloc(sizeof(ssh_pending) + n);
    if (!pn) return SD_E_NO_MEMORY;
    pn->next = NULL;
    pn->n = n;
    memcpy(pn->p, payload, n);
    if (c->pend_tail) c->pend_tail->next = pn; else c->pend_head = pn;
    c->pend_tail = pn;
    c->pend_bytes += n;
    return SD_OK;
  }
  e = ssh_pkt_seal(&c->tx, payload, n, &c->out);
  if (e != SD_OK) { ssh_fail(c, e, SSH_DISCONNECT_PROTOCOL_ERROR, "packet seal failed"); return e; }
  flush_out(c);
  /* rekey by volume or before the sequence number would wrap (01 §4.4) */
  if (c->st == SSH_ST_CONNECTED && !c->kex.active &&
      (c->tx.bytes >= c->rekey_bytes || (!c->strict && c->tx.packets >= 0x80000000u)))
    ssh_kex_start_rekey(c);
  return SD_OK;
}

sd_err ssh_send_wr(sd_ssh_conn *c, sd_wr *w)
{
  sd_err e;
  if (!sd_wr_ok(w)) { sd_wr_free(w); return SD_E_NO_MEMORY; }
  e = ssh_send(c, w->p, w->len);
  sd_wr_free(w);
  return e;
}

void ssh_flush_pending(sd_ssh_conn *c)
{
  while (c->pend_head && !c->failing) {
    ssh_pending *pn = c->pend_head;
    c->pend_head = pn->next;
    if (!c->pend_head) c->pend_tail = NULL;
    c->pend_bytes -= pn->n;
    ssh_send(c, pn->p, pn->n);
    sd_secure_free(pn, sizeof(ssh_pending) + pn->n);
  }
  if (c->probe_pending && !c->failing) {
    uint32_t w = c->have_rtt ? SD_MIN(5000u, SD_MAX(1000u, 3u * c->srtt)) : 5000u;
    c->probe_pending = 0;
    c->probe_deadline = ssh_now() + w;
  }
}

static void free_pending(sd_ssh_conn *c)
{
  while (c->pend_head) {
    ssh_pending *pn = c->pend_head;
    c->pend_head = pn->next;
    sd_secure_free(pn, sizeof(ssh_pending) + pn->n);
  }
  c->pend_tail = NULL;
  c->pend_bytes = 0;
}

/* ---- failure and teardown ---- */

void ssh_fail(sd_ssh_conn *c, sd_err e, uint32_t reason, const char *why)
{
  if (c->failing || c->st == SSH_ST_CLOSED) return;
  c->failing = 1;
  c->fail_err = e;
  ssh_log(c, SD_LOG_INFO, "connection failed: %s (%s)", sd_err_name(e), why ? why : "");
  /* Best-effort DISCONNECT once the transport is up (keys or not). */
  if (reason && lower_up(c) && c->st >= SSH_ST_KEX) {
    uint8_t buf[128];
    sd_wr w;
    sd_wr_init_fixed(&w, buf, sizeof(buf));
    sd_wr_u8(&w, SSH_MSG_DISCONNECT);
    sd_wr_u32(&w, reason);
    sd_wr_cstring(&w, why ? why : "");
    sd_wr_cstring(&w, "");
    if (sd_wr_ok(&w) && ssh_pkt_seal(&c->tx, w.p, w.len, &c->out) == SD_OK) flush_out(c);
  }
}

static void close_socket(sd_ssh_conn *c)
{
  uint32_t i;
  if (c->s != INVALID_SOCKET) { closesocket(c->s); c->s = INVALID_SOCKET; }
  if (c->ev) { WSACloseEvent(c->ev); c->ev = NULL; }   /* the next TCP connect brings its own */
  for (i = 0; i < 2; i++) {
    if (c->att[i].s != INVALID_SOCKET) { closesocket(c->att[i].s); c->att[i].s = INVALID_SOCKET; }
  }
  ssh_tunnel_release(c);
}

/* Proxy reopen (01 §5.2): drops the lower transport and the bytes read from it. */
void ssh_close_lower(sd_ssh_conn *c)
{
  close_socket(c);
  c->in_len = 0;
  c->in_reset = 1;
  sd_wr_reset(&c->out);
  c->out_off = 0;
}

static void wipe_transport(sd_ssh_conn *c)
{
  ssh_dir_clear(&c->tx);
  ssh_dir_clear(&c->rx);
  ssh_kex_reset(c);
  ssh_auth_clear(c);
  ssh_proxy_done_cleanup(c);
  free_pending(c);
  sd_secure_zero(c->session_id, sizeof(c->session_id));
  if (c->in) sd_secure_zero(c->in, c->in_cap);
  c->in_len = 0;
  sd_wr_reset(&c->out);
  c->out_off = 0;
}

/* Safe point: delivers the failure to everyone who is waiting. */
static void finalize(sd_ssh_conn *c)
{
  sd_err e = c->fail_err;
  sd_ssh_done_cb cd = c->connect_done, dd = c->disc_done;
  void *cctx = c->connect_ctx, *dctx = c->disc_ctx;
  close_socket(c);
  c->st = SSH_ST_CLOSED;
  c->connect_done = NULL;
  c->disc_done = NULL;
  if (c->cur_prompt) ssh_prompt_withdraw(c, c->cur_prompt);
  ssh_channels_fail_all(c, e);
  ssh_hku_reset(c);           /* completes a pending fetch_hostkeys with the error */
  wipe_transport(c);
  c->failing = 0;
  if (cd) cd(cctx, e, 0);
  if (dd) dd(dctx, SD_OK, 0);
}

/* ---- create / destroy ---- */

static char *dup_str(const char *s)
{
  size_t n;
  char *d;
  if (!s) return NULL;
  n = strlen(s);
  d = (char *)sd_alloc(n + 1);
  if (d) memcpy(d, s, n + 1);
  return d;
}

static char *dup_bytes_str(const char *s, size_t n)
{
  char *d = (char *)sd_alloc(n + 1);
  if (d) { memcpy(d, s, n); d[n] = 0; }
  return d;
}

static wchar_t *dup_wstr(const wchar_t *s)
{
  size_t n;
  wchar_t *d;
  if (!s) return NULL;
  n = wcslen(s);
  d = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
  if (d) memcpy(d, s, (n + 1) * sizeof(wchar_t));
  return d;
}

static void free_config(sd_ssh_conn *c)
{
  sd_free(c->host_w);
  sd_free(c->host_utf8);
  sd_free(c->host_ascii);
  if (c->user) sd_secure_free(c->user, strlen(c->user) + 1);
  ssh_auth_cfg_free(c);
  sd_free(c->disabled);
  ssh_pxcfg_free(&c->pxcfg);
  ssh_secret_clear(&c->px_secret);
}

/* Per-hop configuration (deep copies). c is zero-filled by the caller (jump_chain.c). */
sd_err ssh_hop_init(sd_ssh_conn *c, const sd_ssh_config *cfg, const sd_ssh_hop *h, uint32_t hop_index)
{
  char *host8 = NULL;
  sd_err e;

  if (!h->host || !h->host[0] || !h->auth.user || !h->auth.user[0]) return SD_E_INVALID_PARAM;
  e = ssh_auth_cfg_check(&h->auth);                                 /* identities, agents (auth_cfg.c) */
  if (e != SD_OK) return e;

  c->s = INVALID_SOCKET;
  c->att[0].s = c->att[1].s = INVALID_SOCKET;
  c->hop_index = hop_index;
  sd_mutex_init(&c->qlock);
  sd_wr_init(&c->out, 64u * 1024u * 1024u);
  ssh_dir_init(&c->tx);
  ssh_dir_init(&c->rx);

  c->host_w = dup_wstr(h->host);
  c->port = h->port ? h->port : 22;
  c->user = dup_str(h->auth.user);
  c->disabled = dup_str(cfg->algos.disabled);
  if (!c->host_w || !c->user || (cfg->algos.disabled && !c->disabled)) { e = SD_E_NO_MEMORY; goto fail; }
  e = sd_wide_to_utf8_alloc(h->host, (size_t)-1, SD_UTF_STRICT, &host8);
  if (e != SD_OK) goto fail;
  {
    size_t n = strlen(host8), ol = 0;
    c->host_utf8 = (char *)sd_alloc(n * 3 + 1);
    if (!c->host_utf8) { e = SD_E_NO_MEMORY; goto fail; }
    if (sd_text_sanitize_host(host8, n, c->host_utf8, n * 3, &ol) != SD_OK) ol = 0;
    c->host_utf8[ol] = '\0';
    /* as sent to a proxy or in direct-tcpip: IPv6 literals without brackets */
    if (n >= 2 && host8[0] == '[' && host8[n - 1] == ']') c->host_ascii = dup_bytes_str(host8 + 1, n - 2);
    else c->host_ascii = dup_str(host8);
    if (!c->host_ascii) { e = SD_E_NO_MEMORY; goto fail; }
  }
  if (h->host_key_alias && h->host_key_alias[0]) {
    size_t n = strlen(h->host_key_alias);
    if (n >= sizeof(c->lookup_name)) { e = SD_E_INVALID_PARAM; goto fail; }
    memcpy(c->lookup_name, h->host_key_alias, n + 1);
  } else {
    e = ssh_kh_lookup_name(host8, c->port, c->lookup_name, sizeof(c->lookup_name));
    if (e != SD_OK) { e = SD_E_UNSUPPORTED; goto fail; }   /* non-ASCII names need IDN (M2) */
  }
  e = ssh_auth_cfg_copy(c, &h->auth);
  if (e != SD_OK) goto fail;
  e = ssh_pxcfg_copy(&c->pxcfg, &h->proxy, hop_index);
  if (e != SD_OK) goto fail;
  c->methods = h->auth.methods ? h->auth.methods : (SD_AUTH_PUBLICKEY | SD_AUTH_KBDINT | SD_AUTH_PASSWORD);
  c->pool_member = (cfg->flags & SD_SSH_CFG_POOL_MEMBER) != 0;
  c->compress = (cfg->flags & SD_SSH_CFG_COMPRESS) != 0;
  c->legacy_policy = cfg->algos.legacy_policy;
  c->refuse_terrapin = cfg->algos.refuse_terrapin_exposed;
  c->hku_mode = h->update_host_keys;
  c->kh = cfg->known_hosts;
  c->connect_timeout_ms = cfg->connect_timeout_ms ? cfg->connect_timeout_ms : 15000u;
  c->ka_interval_ms = cfg->keepalive_interval_ms ? cfg->keepalive_interval_ms : 15000u;
  c->ka_max_missed = cfg->keepalive_max_missed ? cfg->keepalive_max_missed : 3u;
  c->rekey_bytes = cfg->rekey_bytes ? cfg->rekey_bytes : ((uint64_t)1 << 30);
  c->rekey_seconds = cfg->rekey_seconds ? cfg->rekey_seconds : 3600u;
  c->af = cfg->address_family;
  c->cache_secrets = h->auth.cache_secrets_for_reconnect != 0;
  ssh_seccache_init(&c->cache, c->id_count);
  if (c->id_count && !c->cache.pass) { e = SD_E_NO_MEMORY; goto fail; }
  sd_free(host8);
  return SD_OK;

fail:
  sd_free(host8);
  ssh_hop_release(c);
  return e;
}

/* Frees what ssh_hop_init allocated (the struct itself stays with the caller). */
void ssh_hop_release(sd_ssh_conn *c)
{
  ssh_hku_free(c);
  ssh_seccache_free(&c->cache);
  free_config(c);
  sd_wr_free(&c->out);
  if (c->in) sd_secure_free(c->in, c->in_cap);
  c->in = NULL;
  sd_mutex_destroy(&c->qlock);
}

sd_err sd_ssh_conn_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out)
{
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (!cfg || cfg->struct_size < sizeof(sd_ssh_config) || !cfg->hops || cfg->hop_count == 0) return SD_E_INVALID_PARAM;
  if (cfg->hop_count > 8) return SD_E_INVALID_PARAM;
  if (cfg->address_family != 0 && cfg->address_family != AF_INET && cfg->address_family != AF_INET6)
    return SD_E_INVALID_PARAM;
  e = sd_ssh_global_init();
  if (e != SD_OK) return e;
  return ssh_chain_create(cfg, cb, out);     /* jump_chain.c: one sd_ssh_conn per hop + the I/O thread */
}

void sd_ssh_conn_destroy(sd_ssh_conn *c)
{
  if (!c) return;
  ssh_chain_destroy(c);
}

/* ---- DNS and TCP connect ---- */

typedef struct dns_work {
  ssh_work w;
  wchar_t *host; uint16_t port; int af;
  sd_err err;
  uint32_t n;
  struct sockaddr_storage addrs[SSH_MAX_ADDRS];
  int lens[SSH_MAX_ADDRS];
} dns_work;

static void dns_do(ssh_work *w)
{
  dns_work *d = (dns_work *)w;
  ADDRINFOW hints, *res = NULL, *ai;
  wchar_t port[8];
  int r, i = 0;
  uint16_t p = d->port;
  struct sockaddr_storage v4[SSH_MAX_ADDRS], v6[SSH_MAX_ADDRS];
  int l4[SSH_MAX_ADDRS], l6[SSH_MAX_ADDRS];
  uint32_t n4 = 0, n6 = 0, k4 = 0, k6 = 0;
  int first6 = -1;
  wchar_t *host = d->host;
  size_t hl = wcslen(host);
  wchar_t tmp[300];
  /* bracketed IPv6 literal */
  if (hl >= 2 && host[0] == L'[' && host[hl - 1] == L']' && hl - 2 < SD_COUNTOF(tmp)) {
    memcpy(tmp, host + 1, (hl - 2) * sizeof(wchar_t));
    tmp[hl - 2] = L'\0';
    host = tmp;
  }
  do { port[i++] = (wchar_t)(L'0' + p % 10); p = (uint16_t)(p / 10); } while (p && i < 6);
  port[i] = L'\0';
  { int a = 0, b = i - 1; while (a < b) { wchar_t t = port[a]; port[a] = port[b]; port[b] = t; a++; b--; } }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = d->af ? d->af : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (sd_os_at_least(6, 0, 0)) hints.ai_flags = AI_ADDRCONFIG;
  r = GetAddrInfoW(host, port, &hints, &res);
  if (r != 0 && hints.ai_flags) {
    hints.ai_flags = 0;
    r = GetAddrInfoW(host, port, &hints, &res);
  }
  if (r != 0 || !res) { d->err = SD_E_DNS; return; }
  for (ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) continue;
    if (ai->ai_family == AF_INET6 && n6 < SSH_MAX_ADDRS) {
      if (first6 < 0) first6 = (n4 == 0);
      memcpy(&v6[n6], ai->ai_addr, ai->ai_addrlen); l6[n6++] = (int)ai->ai_addrlen;
    } else if (ai->ai_family == AF_INET && n4 < SSH_MAX_ADDRS) {
      if (first6 < 0) first6 = 0;
      memcpy(&v4[n4], ai->ai_addr, ai->ai_addrlen); l4[n4++] = (int)ai->ai_addrlen;
    }
  }
  FreeAddrInfoW(res);
  /* interleave by family, starting with the family the resolver listed first (RFC 8305 style) */
  while ((k4 < n4 || k6 < n6) && d->n < SSH_MAX_ADDRS) {
    int take6 = (d->n % 2 == 0) ? first6 == 1 : first6 != 1;
    if (take6 && k6 < n6) { d->addrs[d->n] = v6[k6]; d->lens[d->n++] = l6[k6++]; }
    else if (!take6 && k4 < n4) { d->addrs[d->n] = v4[k4]; d->lens[d->n++] = l4[k4++]; }
    else if (k6 < n6) { d->addrs[d->n] = v6[k6]; d->lens[d->n++] = l6[k6++]; }
    else { d->addrs[d->n] = v4[k4]; d->lens[d->n++] = l4[k4++]; }
  }
  d->err = d->n ? SD_OK : SD_E_DNS;
}

static void start_next_attempt(sd_ssh_conn *c);

static void dns_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  dns_work *d = (dns_work *)cmd;
  if (d->w.gen == c->gen && c->st == SSH_ST_RESOLVING && !c->failing) {
    if (d->err != SD_OK) {
      ssh_fail(c, SD_E_DNS, 0, "name resolution failed");
    } else {
      memcpy(c->addrs, d->addrs, sizeof(d->addrs));
      memcpy(c->addr_len, d->lens, sizeof(d->lens));
      c->naddr = d->n;
      c->next_addr = 0;
      c->st = SSH_ST_CONNECTING;
      start_next_attempt(c);
    }
  }
  sd_free(d->host);
  sd_free(d);
}

static void dns_drop(ssh_cmd *cmd)
{
  dns_work *d = (dns_work *)cmd;
  sd_free(d->host);
  sd_free(d);
}

typedef struct types_work { ssh_work w; sd_known_hosts *kh; char name[320]; sd_kh_types t; sd_err err; } types_work;

static void types_do(ssh_work *w)
{
  types_work *t = (types_work *)w;
  t->err = sd_known_hosts_stored_types(t->kh, t->name, &t->t);
}

static void types_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  types_work *t = (types_work *)cmd;
  if (t->w.gen == c->gen && !c->stored_types_done) {
    if (t->err != SD_OK) {
      ssh_log(c, SD_LOG_WARN, "stored host key types unavailable: %s", sd_err_name(t->err));
      memset(&c->stored_types, 0, sizeof(c->stored_types));
    } else {
      c->stored_types = t->t;
    }
    c->stored_types_done = 1;
    if (c->st == SSH_ST_KEX) ssh_kex_try_send_initial(c);
  }
  sd_free(t);
}

static void free_cmd(ssh_cmd *cmd) { sd_free(cmd); }

static sd_err map_wsa(int err)
{
  switch (err) {
  case WSAECONNREFUSED: return SD_E_CONN_REFUSED;
  case WSAENETUNREACH: case WSAEHOSTUNREACH: case WSAENETDOWN: return SD_E_NET_UNREACHABLE;
  case WSAETIMEDOUT: return SD_E_TIMEOUT;
  default: return SD_E_DISCONNECTED;
  }
}

static SOCKET make_socket(int af)
{
  SOCKET s = WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
  if (s == INVALID_SOCKET && WSAGetLastError() == WSAEINVAL) {
    s = WSASocketW(af, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s != INVALID_SOCKET) SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
  }
  return s;
}

static int attempts_pending(const sd_ssh_conn *c)
{
  return (c->att[0].s != INVALID_SOCKET) + (c->att[1].s != INVALID_SOCKET);
}

static void start_next_attempt(sd_ssh_conn *c)
{
  while (c->next_addr < c->naddr) {
    uint32_t slot = c->att[0].s == INVALID_SOCKET ? 0 : (c->att[1].s == INVALID_SOCKET ? 1 : 2);
    uint32_t i = c->next_addr++;
    SOCKET s;
    if (slot == 2) { c->next_addr--; return; }
    s = make_socket(c->addrs[i].ss_family);
    if (s == INVALID_SOCKET) { c->last_connect_error = WSAGetLastError(); continue; }
    if (!c->att[slot].ev) c->att[slot].ev = WSACreateEvent();
    if (c->att[slot].ev == WSA_INVALID_EVENT || c->att[slot].ev == NULL) { closesocket(s); ssh_fail(c, SD_E_INTERNAL, 0, "WSACreateEvent"); return; }
    WSAResetEvent(c->att[slot].ev);
    if (WSAEventSelect(s, c->att[slot].ev, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE) != 0) {
      closesocket(s);
      continue;
    }
    if (connect(s, (const struct sockaddr *)&c->addrs[i], c->addr_len[i]) != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
      c->last_connect_error = WSAGetLastError();
      closesocket(s);
      continue;
    }
    c->att[slot].s = s;
    c->att[slot].started = ssh_now();
    return;
  }
  if (!attempts_pending(c))
    ssh_fail(c, map_wsa(c->last_connect_error), 0, "connect failed");
}

static void set_socket_options(sd_ssh_conn *c)
{
  int one = 1;
  struct tcp_keepalive ka;
  DWORD got = 0;
  setsockopt(c->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
  setsockopt(c->s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&one, sizeof(one));
  ka.onoff = 1;
  ka.keepalivetime = 60000;
  ka.keepaliveinterval = 10000;
  WSAIoctl(c->s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &got, NULL, NULL);
  if (!sd_os_at_least(6, 0, 0)) {   /* XP: no receive-window autotuning */
    int sz = 512 * 1024;
    setsockopt(c->s, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof(sz));
    setsockopt(c->s, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof(sz));
  }
}

static void send_ident(sd_ssh_conn *c)
{
  c->st = SSH_ST_VERSION;
  sd_wr_bytes(&c->out, ssh_ident_c, sizeof(ssh_ident_c) - 1);
  sd_wr_bytes(&c->out, "\r\n", 2);
  flush_out(c);
  ssh_log(c, SD_LOG_DEBUG, "hop %u: transport up, sent %s", c->hop_index, ssh_ident_c);
}

/* The byte stream below SSH is up (TCP or tunnel): a proxy handshake first, or the identification. */
void ssh_transport_up(sd_ssh_conn *c)
{
  if (ssh_proxy_active(c)) { c->st = SSH_ST_PROXY; ssh_proxy_start(c); return; }
  send_ident(c);
}

void ssh_proxy_tunnel_ready(sd_ssh_conn *c) { send_ident(c); }

void ssh_flush(sd_ssh_conn *c) { if (!c->failing) flush_out(c); }

static void on_tcp_connected(sd_ssh_conn *c, uint32_t slot)
{
  uint32_t other = slot ^ 1u;
  if (c->att[other].s != INVALID_SOCKET) { closesocket(c->att[other].s); c->att[other].s = INVALID_SOCKET; }
  if (c->ev) WSACloseEvent(c->ev);
  c->s = c->att[slot].s;
  c->ev = c->att[slot].ev;
  c->att[slot].s = INVALID_SOCKET;
  c->att[slot].ev = NULL;
  set_socket_options(c);
  ssh_transport_up(c);
}

/* Hop 0: resolve the proxy (if any) or the host, then TCP (01 §3.2). */
void ssh_start_dns(sd_ssh_conn *c)
{
  dns_work *d = (dns_work *)sd_calloc(1, sizeof(*d));
  c->st = SSH_ST_RESOLVING;
  if (d) d->host = dup_wstr(ssh_lower_host_w(c));
  if (!d || !d->host) { if (d) sd_free(d); ssh_fail(c, SD_E_NO_MEMORY, 0, "dns"); return; }
  d->port = ssh_lower_port(c);
  d->af = c->af;
  d->w.cmd.run = dns_done;
  d->w.cmd.drop = dns_drop;
  d->w.work = dns_do;
  if (ssh_queue_work(c, &d->w) != SD_OK) { dns_drop(&d->w.cmd); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

/* Proxy reopen on hop 0 (01 §5.2): a new TCP connection to the already resolved proxy addresses. */
void ssh_reconnect_lower(sd_ssh_conn *c)
{
  ssh_close_lower(c);
  if (c->outer) { ssh_tunnel_open(c); return; }
  c->st = SSH_ST_CONNECTING;
  c->next_addr = 0;
  start_next_attempt(c);
}

/* ---- connect / disconnect (per hop; the public calls run the chain, jump_chain.c) ---- */

typedef struct life_cmd { ssh_cmd cmd; sd_ssh_done_cb done; void *ctx; } life_cmd;

void ssh_hop_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx)
{
  sd_ssh_conn *r = c->root ? c->root : c;
  if (r->stopping) { if (done) done(ctx, SD_E_SHUTDOWN, 0); return; }
  if (c->st != SSH_ST_IDLE && c->st != SSH_ST_CLOSED) { if (done) done(ctx, SD_E_BUSY, 0); return; }
  c->gen++;
  c->is_reconnect = c->ever_connected;
  c->hk_once = 0;
  c->st = SSH_ST_RESOLVING;
  c->fail_err = SD_OK;
  c->failing = 0;
  c->connect_done = done;
  c->connect_ctx = ctx;
  c->connect_deadline = ssh_now() + c->connect_timeout_ms;
  c->hostkey_len = 0;
  c->session_id_len = 0;
  c->strict = 0;
  c->legacy_mask = 0;
  c->hostkey_just_accepted = 0;
  c->interactive_used = 0;
  c->methods_used = 0;
  c->prebanner_bytes = 0;
  c->prebanner_lines = 0;
  c->rx_packets_before_kexinit = 0;
  c->server_sig_algs[0] = '\0';
  c->ka_count = c->ka_head = 0;
  c->probe_deadline = 0;
  c->probe_pending = 0;
  c->in_len = 0;
  ssh_dir_init(&c->tx);
  ssh_dir_init(&c->rx);
  ssh_kex_reset(c);
  c->kex.active = 1;
  c->kex.initial = 1;
  memset(&c->auth, 0, sizeof(c->auth));

  /* TM-R04: stored key types, in parallel with DNS and TCP */
  if (c->kh) {
    types_work *t = (types_work *)sd_calloc(1, sizeof(*t));
    if (!t) { ssh_fail(c, SD_E_NO_MEMORY, 0, "types"); return; }
    t->kh = c->kh;
    memcpy(t->name, c->lookup_name, sizeof(t->name));
    t->w.cmd.run = types_done;
    t->w.cmd.drop = free_cmd;
    t->w.work = types_do;
    c->stored_types_done = 0;
    if (ssh_queue_work(c, &t->w) != SD_OK) { sd_free(t); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); return; }
  } else {
    memset(&c->stored_types, 0, sizeof(c->stored_types));
    c->stored_types_done = 1;
  }

  /* proxy (system resolution first), then DNS + TCP (hop 0) or the tunnel on the previous hop */
  ssh_proxy_reset(c);
  ssh_proxy_begin(c);
}

static void connect_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  life_cmd *lc = (life_cmd *)cmd;
  sd_ssh_done_cb done = lc->done;
  void *ctx = lc->ctx;
  sd_free(lc);
  if (c->stopping) { if (done) done(ctx, SD_E_SHUTDOWN, 0); return; }
  ssh_chain_connect(c, done, ctx);
}

sd_err sd_ssh_conn_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx)
{
  life_cmd *lc;
  sd_err e;
  if (!c) return SD_E_INVALID_PARAM;
  if (!ssh_crypto_ready()) {
    sd_log(SD_LOG_ERROR, "ssh", NULL, "sd_crypto_init failed");
    return SD_E_UNSUPPORTED;
  }
  lc = (life_cmd *)sd_calloc(1, sizeof(*lc));
  if (!lc) return SD_E_NO_MEMORY;
  lc->cmd.run = connect_run;
  lc->cmd.drop = free_cmd;
  lc->done = done;
  lc->ctx = ctx;
  e = ssh_post_cmd(c, &lc->cmd);
  if (e != SD_OK) sd_free(lc);
  return e;
}

void ssh_hop_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx)
{
  if (c->st == SSH_ST_IDLE || c->st == SSH_ST_CLOSED) { if (done) done(ctx, SD_OK, 0); return; }
  if (c->disc_done) { if (done) done(ctx, SD_E_BUSY, 0); return; }
  c->disc_done = done;
  c->disc_ctx = ctx;
  if (c->failing || c->st == SSH_ST_CLOSING) return;
  if (c->connect_done) {
    /* still connecting: abort */
    ssh_fail(c, SD_E_CANCELLED, SSH_DISCONNECT_BY_APPLICATION, "cancelled");
    return;
  }
  {
    uint8_t buf[64];
    sd_wr w;
    sd_wr_init_fixed(&w, buf, sizeof(buf));
    sd_wr_u8(&w, SSH_MSG_DISCONNECT);
    sd_wr_u32(&w, SSH_DISCONNECT_BY_APPLICATION);
    sd_wr_cstring(&w, "disconnected by user");
    sd_wr_cstring(&w, "");
    ssh_send(c, w.p, w.len);
  }
  c->st = SSH_ST_CLOSING;
  c->close_deadline = ssh_now() + 1000;
}

static void disconnect_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  life_cmd *lc = (life_cmd *)cmd;
  sd_ssh_done_cb done = lc->done;
  void *ctx = lc->ctx;
  sd_free(lc);
  ssh_chain_disconnect(c, done, ctx);
}

sd_err sd_ssh_conn_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx)
{
  life_cmd *lc;
  sd_err e;
  if (!c) return SD_E_INVALID_PARAM;
  lc = (life_cmd *)sd_calloc(1, sizeof(*lc));
  if (!lc) return SD_E_NO_MEMORY;
  lc->cmd.run = disconnect_run;
  lc->cmd.drop = free_cmd;
  lc->done = done;
  lc->ctx = ctx;
  e = ssh_post_cmd(c, &lc->cmd);
  if (e != SD_OK) sd_free(lc);
  return e;
}

/* 01 §10.9: noninteractive covers every hop of the chain (no prompt was shown to a user anywhere). */
sd_err sd_ssh_conn_auth_info(const sd_ssh_conn *c, sd_ssh_auth_info *out)
{
  uint32_t i, n;
  if (!c || !out) return SD_E_INVALID_PARAM;
  out->noninteractive = !c->interactive_used;
  out->methods_used = c->methods_used;
  out->is_reconnect = c->is_reconnect;
  out->hostkey_just_accepted = c->hostkey_just_accepted;
  n = c->hops ? c->nhops : 0;
  for (i = 0; i + 1 < n; i++) {
    const sd_ssh_conn *h = c->hops[i];
    if (h->interactive_used) out->noninteractive = 0;
    if (h->hostkey_just_accepted) out->hostkey_just_accepted = 1;
  }
  return SD_OK;
}

/* sd_ssh_conn_fetch_hostkeys: hostkey_update.c (M2 transport) */

/* ---- keepalive, probe, RTT (01 §4.6) ---- */

void ssh_send_keepalive(sd_ssh_conn *c)
{
  uint8_t buf[64];
  sd_wr w;
  sd_wr_init_fixed(&w, buf, sizeof(buf));
  sd_wr_u8(&w, SSH_MSG_GLOBAL_REQUEST);
  sd_wr_cstring(&w, "keepalive@openssh.com");
  sd_wr_bool(&w, 1);
  if (ssh_send(c, w.p, w.len) != SD_OK) return;
  if (c->ka_count < SSH_KA_RING) {
    c->ka_ring[(c->ka_head + c->ka_count) % SSH_KA_RING] = ssh_now();
    c->ka_count++;
  } else {
    c->ka_count++;   /* beyond the ring: counted, no RTT sample */
  }
}

static void rtt_sample(sd_ssh_conn *c, uint32_t r)
{
  if (!c->have_rtt) { c->srtt = r; c->rttvar = r / 2; c->have_rtt = 1; return; }
  {
    uint32_t d = c->srtt > r ? c->srtt - r : r - c->srtt;
    c->rttvar = (3u * c->rttvar + d) / 4u;
    c->srtt = (7u * c->srtt + r) / 8u;
  }
}

static void on_global_reply(sd_ssh_conn *c)
{
  if (c->ka_count == 0) return;
  if (c->ka_count <= SSH_KA_RING) {
    uint64_t sent = c->ka_ring[c->ka_head];
    uint64_t now = ssh_now();
    rtt_sample(c, (uint32_t)SD_MIN(now - sent, (uint64_t)600000));
    c->ka_head = (c->ka_head + 1) % SSH_KA_RING;
  }
  c->ka_count--;
}

void sd_ssh_conn_probe(sd_ssh_conn *c)
{
  if (!c || c->st != SSH_ST_CONNECTED || c->failing) return;
  if (c->probe_deadline || c->probe_pending) return;
  ssh_send_keepalive(c);
  if (c->kex.active) { c->probe_pending = 1; return; }   /* window starts when actually sent */
  c->probe_deadline = ssh_now() + (c->have_rtt ? SD_MIN(5000u, SD_MAX(1000u, 3u * c->srtt)) : 5000u);
}

typedef struct ka_cmd { ssh_cmd cmd; uint32_t interval_ms, max_missed; } ka_cmd;

static void ka_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  ka_cmd *k = (ka_cmd *)cmd;
  uint32_t i, n = c->hops ? c->nhops : 1;
  for (i = 0; i < n; i++) {     /* every hop of the chain */
    sd_ssh_conn *h = c->hops ? c->hops[i] : c;
    if (k->interval_ms) h->ka_interval_ms = k->interval_ms;
    if (k->max_missed) h->ka_max_missed = k->max_missed;
    if (h->st == SSH_ST_CONNECTED) h->next_ka_tick = SD_MIN(h->next_ka_tick, ssh_now() + h->ka_interval_ms);
  }
  sd_free(k);
}

sd_err sd_ssh_conn_set_keepalive(sd_ssh_conn *c, uint32_t interval_ms, uint32_t max_missed)
{
  ka_cmd *k;
  sd_err e;
  if (!c || (interval_ms && interval_ms < 1000u) || max_missed > 100u) return SD_E_INVALID_PARAM;
  k = (ka_cmd *)sd_calloc(1, sizeof(*k));
  if (!k) return SD_E_NO_MEMORY;
  k->cmd.run = ka_run;
  k->cmd.drop = free_cmd;
  k->interval_ms = interval_ms;
  k->max_missed = max_missed;
  e = ssh_post_cmd(c, &k->cmd);
  if (e != SD_OK) sd_free(k);
  return e;
}

static void clear_secrets_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  uint32_t i, n = c->hops ? c->nhops : 1;
  sd_free(cmd);
  for (i = 0; i < n; i++) {
    sd_ssh_conn *h = c->hops ? c->hops[i] : c;
    ssh_seccache_clear(&h->cache);
    ssh_secret_clear(&h->px_secret);
  }
}

sd_err sd_ssh_conn_clear_secrets(sd_ssh_conn *c)
{
  ssh_cmd *cmd;
  sd_err e;
  if (!c) return SD_E_INVALID_PARAM;
  cmd = (ssh_cmd *)sd_calloc(1, sizeof(*cmd));
  if (!cmd) return SD_E_NO_MEMORY;
  cmd->run = clear_secrets_run;
  cmd->drop = free_cmd;
  e = ssh_post_cmd(c, cmd);
  if (e != SD_OK) sd_free(cmd);
  return e;
}

void sd_ssh_conn_rtt(const sd_ssh_conn *c, uint32_t *srtt_ms, uint32_t *rttvar_ms)
{
  if (srtt_ms) *srtt_ms = c && c->have_rtt ? c->srtt : 0;
  if (rttvar_ms) *rttvar_ms = c && c->have_rtt ? c->rttvar : 0;
}

/* ---- packet dispatch ---- */

static void send_unimplemented(sd_ssh_conn *c, uint32_t seq)
{
  uint8_t buf[8];
  buf[0] = SSH_MSG_UNIMPLEMENTED;
  sd_store_be32(buf + 1, seq);
  ssh_send(c, buf, 5);
}

static sd_err map_disconnect_reason(uint32_t r)
{
  switch (r) {
  case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: return SD_E_HOSTKEY_REJECTED;
  case SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: return SD_E_AUTH_FAILED;
  case SSH_DISCONNECT_KEY_EXCHANGE_FAILED: return SD_E_KEX_FAILED;
  case SSH_DISCONNECT_PROTOCOL_ERROR: return SD_E_PROTOCOL;
  default: return SD_E_DISCONNECTED;
  }
}

static void parse_ext_info(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  sd_rd r;
  uint32_t cnt, i;
  sd_rd_init(&r, p + 1, n - 1);
  cnt = sd_rd_u32(&r);
  if (cnt > 64) cnt = 64;
  for (i = 0; i < cnt && sd_rd_ok(&r); i++) {
    sd_span name = sd_rd_string(&r, 256), val = sd_rd_string(&r, 16384);
    if (!sd_rd_ok(&r)) break;
    if (ssh_span_eq(name, "server-sig-algs")) {
      if (!ssh_span_copy(val, c->server_sig_algs, sizeof(c->server_sig_algs))) c->server_sig_algs[0] = '\0';
      ssh_log(c, SD_LOG_DEBUG, "ext-info server-sig-algs=%s", c->server_sig_algs);
    }
  }
  if (!sd_rd_ok(&r)) ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad EXT_INFO");
}

static void handle_global_request(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  sd_rd r;
  sd_span name;
  int want;
  char nm[64];
  sd_rd_init(&r, p + 1, n - 1);
  name = sd_rd_string(&r, 256);
  want = sd_rd_bool(&r);
  if (!sd_rd_ok(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad GLOBAL_REQUEST"); return; }
  if (ssh_hku_on_global_request(c, name, want, p, n)) return;   /* hostkeys-00@openssh.com (01 §7.5) */
  ssh_sanitize(name.p, name.n, nm, sizeof(nm));
  ssh_log(c, SD_LOG_DEBUG, "server global request %s ignored", nm);
  if (want) { uint8_t b = SSH_MSG_REQUEST_FAILURE; ssh_send(c, &b, 1); }
}

static void refuse_channel_open(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  sd_rd r;
  uint32_t sender;
  sd_wr w;
  sd_rd_init(&r, p + 1, n - 1);
  (void)sd_rd_string(&r, 256);
  sender = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad CHANNEL_OPEN"); return; }
  sd_wr_init(&w, 256);
  sd_wr_u8(&w, SSH_MSG_CHANNEL_OPEN_FAILURE);
  sd_wr_u32(&w, sender);
  sd_wr_u32(&w, 1);   /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
  sd_wr_cstring(&w, "not allowed");
  sd_wr_cstring(&w, "");
  ssh_send_wr(c, &w);
}

static void handle_packet(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  uint8_t m = p[0];
  uint32_t seq = c->rx.seq - 1u;
  int in_initial_kex = c->session_id_len == 0 || (c->kex.initial && !c->kex.newkeys_recv);

  c->last_rx_tick = ssh_now();
  c->probe_deadline = 0;

  /* message gating (01 §4.1, §4.2) */
  if (in_initial_kex) {
    if (c->strict && c->kex.got_server_kexinit && m != SSH_MSG_DISCONNECT && !(m >= 20 && m <= 49)) {
      ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "strict KEX: unexpected message");
      return;
    }
    if (!(m >= 1 && m <= 4) && !(m >= 20 && m <= 49)) {
      ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected message before NEWKEYS");
      return;
    }
    if (!c->kex.got_server_kexinit && m != SSH_MSG_KEXINIT) c->rx_packets_before_kexinit++;
  }
  if (m >= 50 && m <= 79 && c->st != SSH_ST_AUTH) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "userauth message outside USERAUTH");
    return;
  }
  if (m >= 80 && m <= 127 && c->st != SSH_ST_CONNECTED && c->st != SSH_ST_CLOSING) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "connection message before USERAUTH_SUCCESS");
    return;
  }

  switch (m) {
  case SSH_MSG_DISCONNECT: {
    sd_rd r;
    uint32_t reason;
    sd_span desc;
    char txt[256];
    sd_rd_init(&r, p + 1, n - 1);
    reason = sd_rd_u32(&r);
    desc = sd_rd_string(&r, 4096);
    ssh_sanitize(desc.p, desc.n, txt, sizeof(txt));
    ssh_log(c, SD_LOG_INFO, "server disconnected: reason %u: %s", reason, txt);
    if (c->st == SSH_ST_CLOSING) { c->fail_err = SD_E_SHUTDOWN; c->failing = 1; return; }
    ssh_fail(c, map_disconnect_reason(reason), 0, "server disconnect");
    return;
  }
  case SSH_MSG_IGNORE:
    return;
  case SSH_MSG_UNIMPLEMENTED:
    if (ssh_hku_on_reply(c, p, n)) return;   /* hostkeys-prove-00 refused */
    on_global_reply(c);   /* counts as liveness for keepalives (01 §4.1) */
    return;
  case SSH_MSG_DEBUG: {
    sd_rd r;
    int disp;
    sd_span msg;
    char txt[512];
    sd_rd_init(&r, p + 1, n - 1);
    disp = sd_rd_bool(&r);
    msg = sd_rd_string(&r, 4096);
    if (sd_rd_ok(&r)) {
      ssh_sanitize(msg.p, msg.n, txt, sizeof(txt));
      ssh_log(c, disp ? SD_LOG_INFO : SD_LOG_DEBUG, "server debug: %s", txt);
    }
    return;
  }
  case SSH_MSG_SERVICE_ACCEPT:
    if (c->st != SSH_ST_SERVICE) break;
    ssh_auth_start(c);
    return;
  case SSH_MSG_EXT_INFO:
    if (c->st == SSH_ST_KEX || c->st == SSH_ST_LEGACY_ACK || c->st == SSH_ST_SERVICE || c->st == SSH_ST_AUTH) {
      parse_ext_info(c, p, n);
      return;
    }
    break;
  case SSH_MSG_KEXINIT: case SSH_MSG_NEWKEYS: case SSH_MSG_KEX_ECDH_INIT: case SSH_MSG_KEX_ECDH_REPLY:
    ssh_kex_on_msg(c, p, n);
    return;
  case SSH_MSG_GLOBAL_REQUEST:
    handle_global_request(c, p, n);
    return;
  case SSH_MSG_REQUEST_SUCCESS: case SSH_MSG_REQUEST_FAILURE:
    if (ssh_hku_on_reply(c, p, n)) return;   /* hostkeys-prove-00 reply (01 §7.5) */
    on_global_reply(c);
    return;
  case SSH_MSG_CHANNEL_OPEN:
    refuse_channel_open(c, p, n);
    return;
  default:
    if (m >= 50 && m <= 79) { ssh_auth_on_msg(c, p, n); return; }
    if (m >= 91 && m <= 100) { ssh_channel_on_msg(c, p, n); return; }
    if (m >= 30 && m <= 49) { ssh_kex_on_msg(c, p, n); return; }
    break;
  }
  send_unimplemented(c, seq);
}

static void process_input(sd_ssh_conn *c)
{
  size_t off = 0;
  c->in_reset = 0;
  while (!c->failing && c->st != SSH_ST_CLOSED && off < c->in_len) {
    if (c->st == SSH_ST_PROXY) {           /* proxy handshake (01 §5.2); bytes after it are SSH */
      size_t used = ssh_proxy_input(c, c->in + off, c->in_len - off);
      if (c->in_reset) { c->in_reset = 0; return; }   /* reopened: the buffer was dropped */
      off += used;
      if (c->st == SSH_ST_PROXY && !used) break;
      continue;
    }
    if (c->st < SSH_ST_PROXY) { off = c->in_len; break; }   /* nothing is expected yet */
    if (c->st == SSH_ST_VERSION) {
      size_t ll;
      int ident;
      char line[256];
      sd_err e = ssh_version_line(c->in + off, c->in_len - off, &ll, &ident, line, sizeof(line));
      if (e != SD_OK) { ssh_fail(c, SD_E_PROTOCOL, 0, "bad identification line"); break; }
      if (!ll) break;
      off += ll;
      if (!ident) {
        c->prebanner_lines++;
        c->prebanner_bytes += ll;
        if (c->prebanner_lines > 1024 || c->prebanner_bytes > 64u * 1024u) {
          ssh_fail(c, SD_E_PROTOCOL, 0, "too much text before identification");
          break;
        }
        continue;
      }
      memcpy(c->ident_s, line, strlen(line) + 1);
      {
        const char *sw = strchr(line + 4, '-');
        sw = sw ? sw + 1 : "";
        ssh_sanitize((const uint8_t *)sw, strlen(sw), c->server_version, sizeof(c->server_version));
      }
      ssh_log(c, SD_LOG_INFO, "server version %s", c->server_version);
      c->st = SSH_ST_KEX;
      c->kexinit_wait_deadline = ssh_now() + SSH_KEXINIT_WAIT_MS;
      ssh_kex_on_ident(c);
      continue;
    }
    {
      size_t used = 0;
      sd_span pl;
      sd_err e = ssh_pkt_open(&c->rx, c->in + off, c->in_len - off, &used, &pl);
      if (e != SD_OK) {
        ssh_fail(c, e == SD_E_CRYPTO ? SD_E_CRYPTO : SD_E_PROTOCOL,
                 e == SD_E_CRYPTO ? SSH_DISCONNECT_MAC_ERROR : SSH_DISCONNECT_PROTOCOL_ERROR,
                 e == SD_E_CRYPTO ? "packet authentication failed" : "bad packet framing");
        break;
      }
      if (!pl.p) break;
      off += used;
      if (pl.n == 0) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "empty payload"); break; }
      handle_packet(c, pl.p, pl.n);
      sd_secure_zero((uint8_t *)pl.p, pl.n);
      if (c->st == SSH_ST_CONNECTED && !c->kex.active && !c->failing &&
          (c->rx.bytes >= c->rekey_bytes || (!c->strict && c->rx.packets >= 0x80000000u)))
        ssh_kex_start_rekey(c);
    }
  }
  if (off) {
    memmove(c->in, c->in + off, c->in_len - off);
    c->in_len -= off;
  }
}

static void do_recv(sd_ssh_conn *c)
{
  for (;;) {
    int r;
    if (c->failing || c->s == INVALID_SOCKET) return;
    if (c->in_cap - c->in_len < 16u * 1024u) {
      size_t ncap = c->in_cap ? c->in_cap * 2 : 128u * 1024u;
      uint8_t *nb;
      if (ncap > SSH_IN_MAX) ncap = SSH_IN_MAX;
      if (ncap <= c->in_cap) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "input overflow"); return; }
      nb = (uint8_t *)sd_alloc(ncap);
      if (!nb) { ssh_fail(c, SD_E_NO_MEMORY, 0, "input buffer"); return; }
      if (c->in) { memcpy(nb, c->in, c->in_len); sd_secure_free(c->in, c->in_cap); }
      c->in = nb;
      c->in_cap = ncap;
    }
    r = recv(c->s, (char *)c->in + c->in_len, (int)SD_MIN(c->in_cap - c->in_len, (size_t)64 * 1024), 0);
    if (r == 0) {
      if (c->st == SSH_ST_CLOSING) { c->fail_err = SD_E_SHUTDOWN; c->failing = 1; return; }
      ssh_fail(c, SD_E_DISCONNECTED, 0, "connection closed by server");
      return;
    }
    if (r == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) return;
      if (c->st == SSH_ST_CLOSING) { c->fail_err = SD_E_SHUTDOWN; c->failing = 1; return; }
      ssh_fail(c, SD_E_DISCONNECTED, 0, "recv failed");
      return;
    }
    c->in_len += (size_t)r;
    process_input(c);
  }
}

/* Bytes from the tunnel of hop i >= 1 (jump_chain.c). */
void ssh_ingest(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  if (c->failing || c->st == SSH_ST_CLOSED) return;
  if (!n) { if (c->in_len) process_input(c); return; }   /* re-run on buffered bytes */
  if (c->in_cap - c->in_len < n) {
    size_t ncap = c->in_cap ? c->in_cap : 128u * 1024u;
    uint8_t *nb;
    while (ncap - c->in_len < n) ncap *= 2;
    if (ncap > SSH_IN_MAX) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "input overflow"); return; }
    nb = (uint8_t *)sd_alloc(ncap);
    if (!nb) { ssh_fail(c, SD_E_NO_MEMORY, 0, "input buffer"); return; }
    if (c->in) { memcpy(nb, c->in, c->in_len); sd_secure_free(c->in, c->in_cap); }
    c->in = nb;
    c->in_cap = ncap;
  }
  memcpy(c->in + c->in_len, p, n);
  c->in_len += n;
  process_input(c);
}

/* ---- prompts answered ---- */

void ssh_on_prompt_answered(sd_ssh_conn *c, sd_prompt *p)
{
  ssh_prompt_answer *a = ssh_prompt_take_answer(p);
  ssh_prompt_purpose pp = ssh_prompt_purpose_of(p);
  if (c->failing || c->st == SSH_ST_CLOSED) return;
  if (!a->cancelled && !(a->flags & SD_ANSWER_FROM_STORE)) c->interactive_used = 1;
  if (pp == SSH_PP_HOSTKEY) ssh_kex_on_hostkey_answer(c, a);
  else if (pp == SSH_PP_PROXY) ssh_proxy_on_answer(c, a);
  else if (pp == SSH_PP_LEGACY) ssh_kex_on_legacy_answer(c, a);
  else ssh_auth_on_answer(c, pp, a);
}

/* ---- after KEX and auth ---- */

void ssh_after_initial_kex(sd_ssh_conn *c)
{
  uint8_t buf[64];
  sd_wr w;
  if (c->legacy_policy == SD_LEGACY_ASK && (c->legacy_mask & ~(uint32_t)SD_LEGACY_MAC_NON_ETM)) {
    sd_prompt *p = ssh_prompt_new(c, SSH_PP_LEGACY, SD_PROMPT_LEGACY_ACK);
    sd_auth_prompt_info *ai;
    if (!p) { ssh_fail(c, SD_E_NO_MEMORY, SSH_DISCONNECT_BY_APPLICATION, "prompt"); return; }
    ai = ssh_prompt_auth_info(p);
    ai->legacy_mask = c->legacy_mask;
    {
      char names[512];
      ssh_kex_legacy_names(c, names, sizeof(names));   /* e.g. "3des-cbc,hmac-sha1,no_strict_kex" */
      ai->legacy_names = ssh_prompt_str(p, names);
    }
    c->st = SSH_ST_LEGACY_ACK;
    ssh_prompt_raise(c, p);
    return;
  }
  c->st = SSH_ST_SERVICE;
  sd_wr_init_fixed(&w, buf, sizeof(buf));
  sd_wr_u8(&w, SSH_MSG_SERVICE_REQUEST);
  sd_wr_cstring(&w, "ssh-userauth");
  ssh_send(c, w.p, w.len);
}

void ssh_on_authenticated(sd_ssh_conn *c)
{
  sd_ssh_done_cb cd = c->connect_done;
  void *ctx = c->connect_ctx;
  c->st = SSH_ST_CONNECTED;
  c->connect_done = NULL;
  /* 01 §8: the verified key of this connect is pinned for later reconnects of this object */
  if (c->hostkey_len && c->hostkey_len <= sizeof(c->pinned_hostkey)) {
    memcpy(c->pinned_hostkey, c->hostkey, c->hostkey_len);
    c->pinned_len = c->hostkey_len;
    c->pinned_unstored = c->hk_once;
  }
  c->ever_connected = 1;
  c->last_rx_tick = ssh_now();
  c->next_ka_tick = c->last_rx_tick + c->ka_interval_ms;
  ssh_auth_clear(c);
  ssh_log(c, SD_LOG_INFO, "authenticated as %s", c->user);
  if (cd) cd(ctx, SD_OK, 0);
}

/* ---- timers ---- */

static void upd(uint64_t *next, uint64_t t) { if (t && (*next == 0 || t < *next)) *next = t; }

static uint64_t run_timers(sd_ssh_conn *c)
{
  uint64_t now = ssh_now(), next = 0;
  if (c->failing) return 0;
  /* connect timeout: until the server's KEX reply arrived */
  /* (not while a proxy password prompt is out: the deadline restarts when it is answered) */
  if (c->st > SSH_ST_IDLE && (c->st < SSH_ST_KEX || (c->st == SSH_ST_KEX && !c->kex.reply_done && c->kex.initial)) &&
      !(c->st == SSH_ST_PROXY && c->cur_prompt)) {
    if (now >= c->connect_deadline) { ssh_fail(c, SD_E_TIMEOUT, SSH_DISCONNECT_BY_APPLICATION, "connect timeout"); return 0; }
    upd(&next, c->connect_deadline);
  }
  if (c->st == SSH_ST_CONNECTING && attempts_pending(c) == 1 && c->next_addr < c->naddr) {
    uint64_t started = c->att[0].s != INVALID_SOCKET ? c->att[0].started : c->att[1].started;
    if (now >= started + SSH_ATTEMPT_STAGGER_MS) start_next_attempt(c);
    else upd(&next, started + SSH_ATTEMPT_STAGGER_MS);
  }
  if (c->st == SSH_ST_KEX && c->kex.initial && !c->kex.we_sent_kexinit) {
    if (now >= c->kexinit_wait_deadline) ssh_kex_try_send_initial(c);
    else upd(&next, c->kexinit_wait_deadline);
  }
  if (c->st == SSH_ST_CONNECTED) {
    if (c->probe_deadline) {
      if (now >= c->probe_deadline) { ssh_fail(c, SD_E_TIMEOUT, SSH_DISCONNECT_BY_APPLICATION, "liveness probe timeout"); return 0; }
      upd(&next, c->probe_deadline);
    }
    if (now >= c->last_rx_tick + c->ka_interval_ms && now >= c->next_ka_tick) {
      if (c->ka_count >= c->ka_max_missed) { ssh_fail(c, SD_E_TIMEOUT, SSH_DISCONNECT_BY_APPLICATION, "keepalive timeout"); return 0; }
      ssh_send_keepalive(c);
      c->next_ka_tick = now + c->ka_interval_ms;
    }
    upd(&next, SD_MAX(c->last_rx_tick + c->ka_interval_ms, c->next_ka_tick));
    if (!c->kex.active) {
      uint64_t due = c->last_kex_tick + (uint64_t)c->rekey_seconds * 1000u;
      if (now >= due) ssh_kex_start_rekey(c);
      else upd(&next, due);
    }
    ssh_channels_timers(c, now, &next);
  }
  if (c->st == SSH_ST_CLOSING) {
    if (now >= c->close_deadline || ssh_out_pending(c) == 0) { c->fail_err = SD_E_SHUTDOWN; c->failing = 1; return 0; }
    upd(&next, c->close_deadline);
  }
  return next;
}

/* ---- the loop ---- */

/* Every hop that failed is torn down, outermost first: an outer hop's teardown fails the tunnel of
   the next hop, which is then finalized in the same pass. */
static void finalize_all(sd_ssh_conn *r)
{
  uint32_t i, n = r->hops ? r->nhops : 1;
  for (i = 0; i < n; i++) {
    sd_ssh_conn *h = r->hops ? r->hops[i] : r;
    if (h->failing) finalize(h);
  }
}

static int any_failing(const sd_ssh_conn *r)
{
  uint32_t i, n = r->hops ? r->nhops : 1;
  for (i = 0; i < n; i++) if ((r->hops ? r->hops[i] : r)->failing) return 1;
  return 0;
}

static void run_queue(sd_ssh_conn *c)
{
  for (;;) {
    ssh_cmd *q;
    sd_mutex_lock(&c->qlock);
    q = c->qhead;
    if (q) { c->qhead = q->next; if (!c->qhead) c->qtail = NULL; }
    sd_mutex_unlock(&c->qlock);
    if (!q) return;
    q->run(q->conn ? q->conn : c, q);
    if (any_failing(c)) finalize_all(c);
  }
}

static void socket_events(sd_ssh_conn *c)
{
  uint32_t i;
  for (i = 0; i < 2 && c->st == SSH_ST_CONNECTING; i++) {
    WSANETWORKEVENTS ne;
    if (c->att[i].s == INVALID_SOCKET) continue;
    if (WSAEnumNetworkEvents(c->att[i].s, c->att[i].ev, &ne) != 0) continue;
    if (ne.lNetworkEvents & FD_CONNECT) {
      if (ne.iErrorCode[FD_CONNECT_BIT] == 0) {
        on_tcp_connected(c, i);
        break;
      }
      c->last_connect_error = ne.iErrorCode[FD_CONNECT_BIT];
      closesocket(c->att[i].s);
      c->att[i].s = INVALID_SOCKET;
      start_next_attempt(c);
    }
  }
  if (c->s != INVALID_SOCKET) {
    WSANETWORKEVENTS ne;
    WSAEnumNetworkEvents(c->s, c->ev, &ne);
    do_recv(c);
    if (!c->failing) flush_out(c);
  }
}

unsigned __stdcall ssh_io_main(void *arg)
{
  sd_ssh_conn *c = (sd_ssh_conn *)arg;      /* the root (target hop) */
  uint32_t nh_hops = c->hops ? c->nhops : 1, i;
  sd_ssh_conn *h0 = c->hops ? c->hops[0] : c;   /* the only hop with a socket */
  for (;;) {
    HANDLE hs[3];
    DWORD nh = 0, timeout, w;
    uint64_t next = 0, now;
    int stop;

    run_queue(c);
    for (i = 0; i < nh_hops; i++) {         /* outermost first: inner hops write into outer channels */
      sd_ssh_conn *h = c->hops ? c->hops[i] : c;
      if (lower_up(h) && !h->failing) {
        flush_out(h);
        if (h->st == SSH_ST_CONNECTED && !h->failing && ssh_out_pending(h) < SSH_OUT_BUDGET / 2) ssh_channels_writable(h);
      }
    }
    for (i = 0; i < nh_hops; i++) {
      sd_ssh_conn *h = c->hops ? c->hops[i] : c;
      uint64_t t = run_timers(h);
      if (t && (next == 0 || t < next)) next = t;
    }
    if (any_failing(c)) { finalize_all(c); continue; }

    sd_mutex_lock(&c->qlock);
    stop = c->stopping;
    sd_mutex_unlock(&c->qlock);
    if (stop) break;

    hs[nh++] = c->cmd_ev;
    if (h0->st == SSH_ST_CONNECTING) {
      if (h0->att[0].s != INVALID_SOCKET) hs[nh++] = h0->att[0].ev;
      if (h0->att[1].s != INVALID_SOCKET) hs[nh++] = h0->att[1].ev;
    } else if (h0->s != INVALID_SOCKET) {
      hs[nh++] = h0->ev;
    }
    now = ssh_now();
    timeout = next == 0 ? INFINITE : (next <= now ? 0 : (DWORD)SD_MIN(next - now, (uint64_t)0x7FFFFFFF));
    w = WaitForMultipleObjects(nh, hs, FALSE, timeout);
    if (w != WAIT_OBJECT_0 && w != WAIT_TIMEOUT) socket_events(h0);
    if (any_failing(c)) finalize_all(c);
  }

  /* shutdown: fail every hop (innermost first), then run every queued command so callbacks are delivered */
  for (i = nh_hops; i-- > 0;) {
    sd_ssh_conn *h = c->hops ? c->hops[i] : c;
    if (h->st != SSH_ST_IDLE && h->st != SSH_ST_CLOSED) {
      if (!h->failing) ssh_fail(h, SD_E_SHUTDOWN, SSH_DISCONNECT_BY_APPLICATION, "shutdown");
      finalize(h);
    }
  }
  if (any_failing(c)) finalize_all(c);
  for (;;) {
    ssh_cmd *q;
    sd_mutex_lock(&c->qlock);
    q = c->qhead;
    if (q) { c->qhead = q->next; if (!c->qhead) c->qtail = NULL; }
    else c->queue_closed = 1;
    sd_mutex_unlock(&c->qlock);
    if (!q) break;
    q->run(q->conn ? q->conn : c, q);
    if (any_failing(c)) finalize_all(c);
  }
  for (i = 0; i < nh_hops; i++) {
    sd_ssh_conn *h = c->hops ? c->hops[i] : c;
    if (h->ev) WSACloseEvent(h->ev);
    if (h->att[0].ev) WSACloseEvent(h->att[0].ev);
    if (h->att[1].ev) WSACloseEvent(h->att[1].ev);
    h->ev = h->att[0].ev = h->att[1].ev = NULL;
  }
  return 0;
}
