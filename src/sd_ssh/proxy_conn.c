/* Proxy glue for one hop (01 §5.2, D20, TM-R10): configuration copy, the system proxy step, the
 * handshake over the hop's lower transport (TCP socket for hop 0, direct-tcpip tunnel for hop i >= 1),
 * proxy password prompts (SD_PROMPT_PROXY_PASSWORD) and the reconnect cache, SSPI tokens on workers,
 * local DNS for SOCKS5 remote_dns = 0, and reopening the connection to the proxy between rounds.
 * Everything runs on the chain's I/O thread except the worker bodies. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "conn_internal.h"

#define PX_MAX_REOPENS 4u

/* ---- configuration ---- */

static char *dupn(const char *s, size_t n)
{
  char *d = (char *)sd_alloc(n + 1);
  if (d) { memcpy(d, s, n); d[n] = 0; }
  return d;
}

sd_err ssh_pxcfg_copy(ssh_pxcfg *d, const sd_proxy_cfg *s, uint32_t hop_index)
{
  memset(d, 0, sizeof(*d));
  d->kind = s->kind;
  if (s->kind == SD_PROXY_NONE) return SD_OK;
  if (s->kind != SD_PROXY_HTTP && s->kind != SD_PROXY_SOCKS5 && s->kind != SD_PROXY_SYSTEM) return SD_E_INVALID_PARAM;
  if (s->kind == SD_PROXY_SYSTEM && hop_index != 0) return SD_E_INVALID_PARAM;   /* the system proxy reaches hop 0 */
  if (s->kind == SD_PROXY_SYSTEM && !s->allow_system)
    return SD_E_PROXY;                     /* policy AllowSystemProxy = 0 refuses the opt-in (03 §3.8, TM-R10) */
  if (s->user && strlen(s->user) > 255) return SD_E_INVALID_PARAM;
  d->auth = s->auth;
  d->allow_discovered_sspi = s->allow_discovered_sspi;
  d->allow_system = s->allow_system;
  d->remote_dns = s->remote_dns;
  d->fallback_direct = s->fallback_direct;
  if (s->user && s->user[0]) { d->user = dupn(s->user, strlen(s->user)); if (!d->user) return SD_E_NO_MEMORY; }
  if (s->kind != SD_PROXY_SYSTEM) {
    char *h8 = NULL;
    size_t n, i;
    if (!s->host || !s->host[0]) { ssh_pxcfg_free(d); return SD_E_INVALID_PARAM; }
    n = wcslen(s->host);
    if (n >= 255) { ssh_pxcfg_free(d); return SD_E_INVALID_PARAM; }
    if (sd_wide_to_utf8_alloc(s->host, (size_t)-1, SD_UTF_STRICT, &h8) != SD_OK) { ssh_pxcfg_free(d); return SD_E_INVALID_PARAM; }
    for (i = 0; h8[i]; i++)       /* proxy names go on the wire as typed: ASCII only (IDN: punycode first) */
      if ((uint8_t)h8[i] <= 0x20 || (uint8_t)h8[i] >= 0x7F) { sd_free(h8); ssh_pxcfg_free(d); return SD_E_UNSUPPORTED; }
    d->host8 = h8;
    d->host_w = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
    if (!d->host_w) { ssh_pxcfg_free(d); return SD_E_NO_MEMORY; }
    memcpy(d->host_w, s->host, (n + 1) * sizeof(wchar_t));
    d->port = s->port ? s->port : (s->kind == SD_PROXY_SOCKS5 ? 1080 : 8080);
  }
  return SD_OK;
}

void ssh_pxcfg_free(ssh_pxcfg *d)
{
  sd_free(d->host_w);
  sd_free(d->host8);
  if (d->user) sd_secure_free(d->user, strlen(d->user) + 1);
  memset(d, 0, sizeof(*d));
}

static void set_lower(sd_ssh_conn *c, sd_proxy_kind kind, const wchar_t *host, uint16_t port)
{
  ssh_pxrun *x = &c->pxr;
  size_t n = wcslen(host), i, o = 0;
  x->kind = kind;
  x->port = port;
  if (n >= SD_COUNTOF(x->host_w)) n = SD_COUNTOF(x->host_w) - 1;
  memcpy(x->host_w, host, n * sizeof(wchar_t));
  x->host_w[n] = 0;
  /* ASCII form without IPv6 brackets (direct-tcpip, SSPI target, logs) */
  for (i = 0; i < n && o + 1 < sizeof(x->host8); i++) {
    wchar_t ch = host[i];
    if ((i == 0 && ch == L'[') || (i == n - 1 && ch == L']' && host[0] == L'[')) continue;
    x->host8[o++] = (ch > 0x20 && ch < 0x7F) ? (char)ch : '?';
  }
  x->host8[o] = 0;
}

const wchar_t *ssh_lower_host_w(const sd_ssh_conn *c) { return c->pxr.kind != SD_PROXY_NONE ? c->pxr.host_w : c->host_w; }
const char *ssh_lower_host8(const sd_ssh_conn *c) { return c->pxr.kind != SD_PROXY_NONE ? c->pxr.host8 : c->host_ascii; }
uint16_t ssh_lower_port(const sd_ssh_conn *c) { return c->pxr.kind != SD_PROXY_NONE ? c->pxr.port : c->port; }

int ssh_proxy_active(const sd_ssh_conn *c) { return c->pxr.kind == SD_PROXY_HTTP || c->pxr.kind == SD_PROXY_SOCKS5; }

void ssh_proxy_done_cleanup(sd_ssh_conn *c)
{
  ssh_pxrun *x = &c->pxr;
  ssh_px_free(&x->px);
  if (x->sspi) { ssh_sspi_free((ssh_sspi *)x->sspi); x->sspi = NULL; }
  sd_secbuf_free(x->pw_pending);
  x->pw_pending = NULL;
  x->px_active = 0;
}

void ssh_proxy_reset(sd_ssh_conn *c)
{
  ssh_proxy_done_cleanup(c);
  memset(&c->pxr, 0, sizeof(c->pxr));
  if (c->pxcfg.kind == SD_PROXY_HTTP || c->pxcfg.kind == SD_PROXY_SOCKS5) {
    set_lower(c, c->pxcfg.kind, c->pxcfg.host_w, c->pxcfg.port);
    c->pxr.sspi_allowed = 1;               /* TM-R10: a proxy configured in the profile may use SSPI */
  }
}

/* ---- system proxy step (worker) ---- */

typedef struct sys_work { ssh_work w; wchar_t host[300]; uint16_t port; int service; ssh_sysproxy res; sd_err err; } sys_work;

static void sys_do(ssh_work *w)
{
  sys_work *s = (sys_work *)w;
  s->err = ssh_sysproxy_resolve(s->host, s->port, s->service, &s->res);
}

static int is_local_system(void)
{
  HANDLE tok = NULL;
  uint8_t buf[256];
  DWORD len = 0;
  int sys = 0;
  SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
  PSID ls = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len) &&
      AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &ls)) {
    sys = EqualSid(((TOKEN_USER *)buf)->User.Sid, ls) != 0;
    FreeSid(ls);
  }
  CloseHandle(tok);
  return sys;
}

static void proceed_lower(sd_ssh_conn *c)
{
  if (c->outer) ssh_tunnel_open(c);
  else ssh_start_dns(c);
}

static void sys_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  sys_work *s = (sys_work *)cmd;
  if (s->w.gen == c->gen && c->st == SSH_ST_SYSPROXY && !c->failing) {
    if (s->err != SD_OK) {
      if (!c->pxcfg.fallback_direct) {
        ssh_log(c, SD_LOG_WARN, "hop %u: system proxy discovery failed (fallback_direct is off)", c->hop_index);
        ssh_fail(c, SD_E_PROXY, 0, "system proxy discovery failed");
        sd_free(s);
        return;
      }
      ssh_log(c, SD_LOG_INFO, "hop %u: system proxy discovery failed, connecting directly (fallback_direct)", c->hop_index);
    } else if (s->res.kind == SD_PROXY_NONE) {
      ssh_log(c, SD_LOG_INFO, "hop %u: system proxy: direct connection", c->hop_index);
    } else {
      ssh_sys_decision d;
      /* ssh_pxcfg_copy already refused a policy-off opt-in; the decision is re-checked per
         resolution so TM-R10 lives in one place (01 §5.2, 03 §3.8) */
      if (ssh_sysproxy_decide(1, c->pxcfg.allow_system, c->pxcfg.allow_discovered_sspi, &s->res, &d) != SD_OK) {
        ssh_log(c, SD_LOG_WARN, "hop %u: proxy = system refused by policy AllowSystemProxy", c->hop_index);
        ssh_fail(c, SD_E_PROXY, 0, "system proxy refused by policy");
        sd_free(s);
        return;
      }
      if (d.kind == SD_PROXY_NONE) {
        ssh_log(c, SD_LOG_INFO, "hop %u: system proxy: direct connection", c->hop_index);
      } else {
        set_lower(c, d.kind, d.host, d.port);
        c->pxr.sspi_allowed = d.sspi_allowed;
        ssh_log(c, SD_LOG_INFO, "hop %u: system proxy %s %Hs:%u (origin %s)", c->hop_index,
                d.kind == SD_PROXY_SOCKS5 ? "socks5" : "http", c->pxr.host8, (unsigned)c->pxr.port,
                d.discovered ? "discovered" : "configured");
      }
    }
    proceed_lower(c);
  }
  sd_free(s);
}

static void free_cmd(ssh_cmd *cmd) { sd_free(cmd); }

void ssh_proxy_begin(sd_ssh_conn *c)
{
  if (c->pxcfg.kind == SD_PROXY_SYSTEM) {
    sys_work *s = (sys_work *)sd_calloc(1, sizeof(*s));
    size_t n = wcslen(c->host_w);
    if (!s) { ssh_fail(c, SD_E_NO_MEMORY, 0, "system proxy"); return; }
    if (n >= SD_COUNTOF(s->host)) { sd_free(s); ssh_fail(c, SD_E_INVALID_PARAM, 0, "system proxy"); return; }
    c->st = SSH_ST_SYSPROXY;
    memcpy(s->host, c->host_w, (n + 1) * sizeof(wchar_t));
    s->port = c->port;
    s->service = is_local_system();
    s->w.cmd.run = sys_done;
    s->w.cmd.drop = free_cmd;
    s->w.work = sys_do;
    if (ssh_queue_work(c, &s->w) != SD_OK) { sd_free(s); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
    return;
  }
  if (ssh_proxy_active(c))
    ssh_log(c, SD_LOG_INFO, "hop %u: via %s proxy %Hs:%u", c->hop_index, c->pxr.kind == SD_PROXY_SOCKS5 ? "socks5" : "http",
            c->pxr.host8, (unsigned)c->pxr.port);
  proceed_lower(c);
}

/* ---- handshake ---- */

static void handle(sd_ssh_conn *c, ssh_px_status st);

static void resume(sd_ssh_conn *c)
{
  ssh_px_status st = ssh_px_resume(&c->pxr.px, &c->out);
  ssh_flush(c);
  handle(c, st);
}

/* SOCKS5 remote_dns = 0: the target name is resolved here first (worker). */
typedef struct tdns_work { ssh_work w; wchar_t host[300]; int af; int atyp; uint8_t addr[16]; sd_err err; } tdns_work;

static void tdns_do(ssh_work *w)
{
  tdns_work *t = (tdns_work *)w;
  ADDRINFOW hints, *res = NULL, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = t->af ? t->af : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  t->err = SD_E_DNS;
  if (GetAddrInfoW(t->host, NULL, &hints, &res) != 0 || !res) return;
  for (ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
      memcpy(t->addr, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
      t->atyp = 1;
      t->err = SD_OK;
      break;
    }
    if (ai->ai_family == AF_INET6 && ai->ai_addrlen >= sizeof(struct sockaddr_in6) && t->atyp == 0) {
      memcpy(t->addr, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
      t->atyp = 4;
      t->err = SD_OK;     /* keep looking for IPv4 (more proxies support it) */
    }
  }
  FreeAddrInfoW(res);
}

static void start_handshake(sd_ssh_conn *c)
{
  ssh_px_start(&c->pxr.px, &c->out);
  ssh_flush(c);
}

static void tdns_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  tdns_work *t = (tdns_work *)cmd;
  if (t->w.gen == c->gen && c->st == SSH_ST_PROXY && !c->failing && c->pxr.px_active) {
    if (t->err != SD_OK) ssh_fail(c, SD_E_DNS, 0, "local name resolution for the SOCKS5 target failed");
    else { ssh_px_set_target_addr(&c->pxr.px, t->atyp, t->addr); start_handshake(c); }
  }
  sd_free(t);
}

void ssh_proxy_start(sd_ssh_conn *c)
{
  ssh_pxrun *x = &c->pxr;
  sd_err e;
  if (x->px_active) { resume(c); return; }      /* reopened connection: continue with the next round */
  e = ssh_px_init(&x->px, x->kind, c->host_ascii, c->port, x->host8, x->port, c->pxcfg.auth,
                  x->sspi_allowed, c->pxcfg.user, c->pxcfg.remote_dns);   /* TM-R10 verdict */
  if (e != SD_OK) { ssh_fail(c, e, 0, "proxy target"); return; }
  x->px_active = 1;
  if (ssh_px_wants_local_dns(&x->px)) {
    tdns_work *t = (tdns_work *)sd_calloc(1, sizeof(*t));
    size_t n = wcslen(c->host_w);
    if (!t || n >= SD_COUNTOF(t->host)) { sd_free(t); ssh_fail(c, SD_E_NO_MEMORY, 0, "dns"); return; }
    memcpy(t->host, c->host_w, (n + 1) * sizeof(wchar_t));
    t->af = c->af;
    t->w.cmd.run = tdns_done;
    t->w.cmd.drop = free_cmd;
    t->w.work = tdns_do;
    if (ssh_queue_work(c, &t->w) != SD_OK) { sd_free(t); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
    return;
  }
  start_handshake(c);
}

size_t ssh_proxy_input(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  size_t used = 0;
  ssh_px_status st;
  if (!c->pxr.px_active || c->cur_prompt) return 0;     /* waiting for a password: keep the bytes */
  st = ssh_px_input(&c->pxr.px, p, n, &used, &c->out);
  ssh_flush(c);
  handle(c, st);
  return used;
}

/* ---- passwords ---- */

static void raise_password_prompt(sd_ssh_conn *c)
{
  ssh_pxrun *x = &c->pxr;
  sd_prompt *p = ssh_prompt_new(c, SSH_PP_PROXY, SD_PROMPT_PROXY_PASSWORD);
  sd_auth_prompt_info *ai;
  sd_prompt_item *it;
  if (!p) { ssh_fail(c, SD_E_NO_MEMORY, 0, "prompt"); return; }
  ai = ssh_prompt_auth_info(p);
  ai->hop_index = c->hop_index;
  ai->host = c->host_utf8;
  ai->user = ssh_prompt_str(p, c->pxcfg.user ? c->pxcfg.user : "");
  ai->proxy_host = ssh_prompt_str(p, x->host8);
  ai->proxy_port = x->port;
  ai->round = x->px.rounds ? x->px.rounds - 1 : 0;
  ai->may_autofill = !x->px.password_failed;
  ai->hostkey_just_accepted = 0;           /* no host key is involved yet */
  it = ssh_prompt_items(p, 1);
  if (it) { it[0].text = "Proxy password: "; it[0].echo = 0; }
  ssh_prompt_raise(c, p);
}

static void need_password(sd_ssh_conn *c)
{
  ssh_pxrun *x = &c->pxr;
  if (x->px.password_failed && x->pw_from_cache) {
    ssh_log(c, SD_LOG_INFO, "hop %u: the cached proxy password was rejected", c->hop_index);
    ssh_secret_clear(&c->px_secret);
  }
  x->pw_from_cache = 0;
  if (c->cache_secrets && !x->pw_cache_tried && c->px_secret.blob) {
    sd_secbuf *pw = NULL;
    x->pw_cache_tried = 1;
    if (ssh_secret_load(&c->px_secret, &pw) == SD_OK) {
      ssh_log(c, SD_LOG_INFO, "hop %u: proxy password from the reconnect cache", c->hop_index);
      x->pw_from_cache = 1;
      ssh_px_set_password(&x->px, pw);
      resume(c);
      return;
    }
  }
  x->pw_cache_tried = 1;
  raise_password_prompt(c);
}

void ssh_proxy_on_answer(sd_ssh_conn *c, ssh_prompt_answer *a)
{
  ssh_pxrun *x = &c->pxr;
  sd_secbuf *pw = NULL;
  if (c->st != SSH_ST_PROXY || !x->px_active) return;
  c->connect_deadline = ssh_now() + c->connect_timeout_ms;   /* the user's time does not count */
  if (a->cancelled || a->n < 1 || !a->resp[0]) { ssh_fail(c, SD_E_CANCELLED, 0, "proxy password prompt cancelled"); return; }
  if (sd_secbuf_from(a->resp[0]->p, a->resp[0]->len, &pw) != SD_OK) { ssh_fail(c, SD_E_NO_MEMORY, 0, "password"); return; }
  sd_secbuf_free(x->pw_pending);
  x->pw_pending = NULL;
  if (c->cache_secrets) (void)sd_secbuf_from(a->resp[0]->p, a->resp[0]->len, &x->pw_pending);
  ssh_px_set_password(&x->px, pw);
  resume(c);
  /* bytes that arrived while the prompt was out */
  if (!c->failing && c->st == SSH_ST_PROXY && c->in_len) ssh_ingest(c, NULL, 0);   /* n = 0: re-runs the parser */
}

/* ---- SSPI (worker) ---- */

typedef struct sspi_work {
  ssh_work w;
  ssh_sspi *s;
  wchar_t package[16];
  int kerberos_only;
  wchar_t target[300];
  uint8_t *in; size_t in_len;
  uint8_t *out; size_t out_len;
  sd_err err;
} sspi_work;

static void sspi_do(ssh_work *w)
{
  sspi_work *k = (sspi_work *)w;
  if (!k->s) k->err = ssh_sspi_create(k->package, k->kerberos_only, k->target, &k->s);
  else k->err = SD_OK;
  if (k->err == SD_OK) k->err = ssh_sspi_step(k->s, k->in, k->in_len, &k->out, &k->out_len);
}

static void sspi_free_work(sspi_work *k)
{
  if (k->in) sd_secure_free(k->in, k->in_len);
  if (k->out) sd_secure_free(k->out, k->out_len);
  sd_free(k);
}

static void sspi_drop(ssh_cmd *cmd)
{
  sspi_work *k = (sspi_work *)cmd;
  ssh_sspi_free(k->s);
  sspi_free_work(k);
}

static void sspi_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  sspi_work *k = (sspi_work *)cmd;
  if (k->w.gen != c->gen || c->st != SSH_ST_PROXY || c->failing || !c->pxr.px_active || c->pxr.sspi) {
    sspi_drop(cmd);
    return;
  }
  c->pxr.sspi = k->s;
  k->s = NULL;
  if (k->err != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "hop %u: SSPI %ls for proxy %Hs failed%s", c->hop_index, k->package, c->pxr.host8,
            k->kerberos_only ? " (Kerberos only, proxy_auth = auto)" : "");
    ssh_fail(c, k->err == SD_E_NO_MEMORY ? k->err : SD_E_PROXY_AUTH, 0, "SSPI");
  } else if (ssh_px_set_token(&c->pxr.px, k->out, k->out_len) != SD_OK) {
    ssh_fail(c, SD_E_PROXY_AUTH, 0, "SSPI token");
  } else {
    resume(c);
  }
  sspi_free_work(k);
}

static void need_sspi(sd_ssh_conn *c)
{
  ssh_pxrun *x = &c->pxr;
  sspi_work *k = (sspi_work *)sd_calloc(1, sizeof(*k));
  if (!k) { ssh_fail(c, SD_E_NO_MEMORY, 0, "sspi"); return; }
  k->s = (ssh_sspi *)x->sspi;          /* continue the context of the previous round */
  x->sspi = NULL;
  wcscpy_s(k->package, SD_COUNTOF(k->package), x->px.scheme == PX_SCHEME_NTLM ? L"NTLM" : L"Negotiate");
  k->kerberos_only = x->px.kerberos_only;
  /* TM-R10: the SPN is the proxy host as configured, never a name from the proxy's reply */
  _snwprintf_s(k->target, SD_COUNTOF(k->target), _TRUNCATE, L"HTTP/%hs", x->host8);
  if (x->px.challenge_len) {
    k->in = (uint8_t *)sd_alloc(x->px.challenge_len);
    if (!k->in) { ssh_sspi_free(k->s); sd_free(k); ssh_fail(c, SD_E_NO_MEMORY, 0, "sspi"); return; }
    memcpy(k->in, x->px.challenge, x->px.challenge_len);
    k->in_len = x->px.challenge_len;
  }
  k->w.cmd.run = sspi_done;
  k->w.cmd.drop = sspi_drop;
  k->w.work = sspi_do;
  if (ssh_queue_work(c, &k->w) != SD_OK) { sspi_drop(&k->w.cmd); ssh_fail(c, SD_E_INTERNAL, 0, "worker"); }
}

/* ---- status dispatch ---- */

static void handle(sd_ssh_conn *c, ssh_px_status st)
{
  ssh_pxrun *x = &c->pxr;
  if (c->failing) return;
  switch (st) {
  case PX_MORE:
    return;
  case PX_DONE:
    ssh_log(c, SD_LOG_INFO, "hop %u: %s", c->hop_index, x->px.why[0] ? x->px.why : "proxy tunnel established");
    if (x->pw_pending && c->cache_secrets) {
      if (ssh_secret_store(&c->px_secret, x->pw_pending->p, x->pw_pending->len) == SD_OK)
        ssh_log(c, SD_LOG_DEBUG, "hop %u: proxy password kept for reconnects", c->hop_index);
    }
    ssh_proxy_done_cleanup(c);
    ssh_proxy_tunnel_ready(c);
    return;
  case PX_NEED_PASSWORD:
    need_password(c);
    return;
  case PX_NEED_SSPI:
    need_sspi(c);
    return;
  case PX_REOPEN:
    if (++x->reopens > PX_MAX_REOPENS) { ssh_fail(c, SD_E_PROXY, 0, "proxy keeps closing the connection"); return; }
    ssh_log(c, SD_LOG_DEBUG, "hop %u: proxy closes between rounds, reconnecting to it", c->hop_index);
    ssh_reconnect_lower(c);
    return;
  case PX_FAIL:
  default:
    if (x->px.password_failed && x->pw_from_cache && x->kind == SD_PROXY_SOCKS5 && x->reopens < PX_MAX_REOPENS) {
      /* RFC 1929 rejected the cached password: the proxy closes; ask the user on a new connection */
      ssh_log(c, SD_LOG_INFO, "hop %u: the cached proxy password was rejected", c->hop_index);
      ssh_secret_clear(&c->px_secret);
      x->pw_from_cache = 0;
      x->reopens++;
      ssh_px_free(&x->px);
      x->px_active = 0;              /* ssh_proxy_start() initializes a fresh handshake */
      ssh_reconnect_lower(c);
      return;
    }
    if (x->px.password_failed && x->pw_from_cache) ssh_secret_clear(&c->px_secret);
    ssh_log(c, SD_LOG_WARN, "hop %u: proxy %Hs:%u: %s", c->hop_index, x->host8, (unsigned)x->port,
            x->px.why[0] ? x->px.why : sd_err_name(x->px.err));
    ssh_fail(c, x->px.err != SD_OK ? x->px.err : SD_E_PROXY, 0, "proxy handshake failed");
    return;
  }
}
