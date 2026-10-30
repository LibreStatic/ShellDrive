/* sd_webdav: loopback listener, connection threads, pre-authentication gate (02 §7.3, §7.4).
 *
 * Order of checks for every request (nothing else is parsed before authentication):
 *   head limits (431/400) -> Host (400, close) -> Origin / Sec-Fetch-* (403, close, no challenge)
 *   -> request-target decoding (400) -> OPTIONS (unauthenticated) -> token prefix (404, no challenge)
 *   -> SSPI Negotiate/NTLM (401) -> owner SID (403, close) -> method dispatch.
 * Pre-authentication limits (TM-R20): head within 10 s of accept or of the previous response,
 * authentication within 30 s, <= 8 unauthenticated connections (<= 4 per client process, WebClient
 * exempt, oldest non-WebClient evicted), <= 64 connections, idle authenticated 120 s. An announced body
 * on an unauthenticated request is drained unparsed up to 64 KiB, else the connection closes. */
#include "wd_server.h"

#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"

/* ---- Winsock ---- */

static sd_once g_wsa_once = SD_ONCE_INIT;
static int g_wsa_ok;

static void wsa_init(void *arg)
{
  WSADATA wd;
  SD_UNUSED(arg);
  g_wsa_ok = WSAStartup(MAKEWORD(2, 2), &wd) == 0;
}

/* ---- peer process (GetExtendedTcpTable, iphlpapi, XP SP2+; resolved at run time) ---- */

typedef DWORD (WINAPI *pfn_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, int, ULONG);
typedef struct wd_tcprow4 { DWORD state, laddr, lport, raddr, rport, pid; } wd_tcprow4;
typedef struct wd_tcprow6 {
  UCHAR laddr[16]; DWORD lscope, lport; UCHAR raddr[16]; DWORD rscope, rport, state, pid;
} wd_tcprow6;
#define WD_TCP_TABLE_OWNER_PID_CONNECTIONS 4

/* Request ring for unit tests (no log sink there); off by default, product never records targets. */
static volatile LONG wd_dbg_on;
static volatile LONG wd_dbg_idx;
static char wd_dbg_ring[WD_SERVER_DBG_N][96];

void wd_server_dbg_enable(int on)
{
  wd_dbg_on = on;
  wd_dbg_idx = 0;
}

int wd_server_dbg_last(char out[][96], int max)
{
  LONG total = wd_dbg_idx;
  int n = (int)(total < WD_SERVER_DBG_N ? total : WD_SERVER_DBG_N), i;
  if (n > max) n = max;
  for (i = 0; i < n; i++) {
    LONG k = (total - i) % WD_SERVER_DBG_N;   /* request k wrote slot k (idx increments first) */
    memcpy(out[i], wd_dbg_ring[k], 96);
  }
  return n;
}

static DWORD peer_pid(int family, uint16_t peer_port_net, uint16_t our_port_net)
{
  static pfn_GetExtendedTcpTable fn;
  static volatile LONG resolved;
  DWORD size = 0, pid = 0, i, n;
  uint8_t *buf;
  if (!InterlockedCompareExchange(&resolved, 0, 0)) {
    fn = (pfn_GetExtendedTcpTable)sd_platform_resolve_by_name(L"iphlpapi.dll", "GetExtendedTcpTable");
    InterlockedExchange(&resolved, 1);
  }
  if (fn == NULL)
    return 0;
  if (fn(NULL, &size, FALSE, (ULONG)family, WD_TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != ERROR_INSUFFICIENT_BUFFER ||
      size == 0 || size > (16u << 20))
    return 0;
  size += 4096;
  buf = (uint8_t *)sd_alloc(size);
  if (buf == NULL)
    return 0;
  if (fn(buf, &size, FALSE, (ULONG)family, WD_TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
    n = *(DWORD *)buf;
    if (family == AF_INET) {
      wd_tcprow4 *r = (wd_tcprow4 *)(buf + sizeof(DWORD));
      if ((size - sizeof(DWORD)) / sizeof(*r) >= n)
        for (i = 0; i < n; i++)
          if ((uint16_t)r[i].lport == peer_port_net && (uint16_t)r[i].rport == our_port_net) { pid = r[i].pid; break; }
    } else {
      wd_tcprow6 *r = (wd_tcprow6 *)(buf + sizeof(DWORD));
      if ((size - sizeof(DWORD)) / sizeof(*r) >= n)
        for (i = 0; i < n; i++)
          if ((uint16_t)r[i].lport == peer_port_net && (uint16_t)r[i].rport == our_port_net) { pid = r[i].pid; break; }
    }
  }
  sd_free(buf);
  return pid;
}

static DWORD webclient_pid(sd_webdav_server *s)
{
  uint64_t now = sd_tick_ms();
  DWORD pid;
  sd_mutex_lock(&s->mu);
  if (s->webclient_pid_at && now - s->webclient_pid_at < 5000) {
    pid = s->webclient_pid;
    sd_mutex_unlock(&s->mu);
    return pid;
  }
  sd_mutex_unlock(&s->mu);
  {
    sd_webdav_client_info ci;
    sd_webdav_query_client(&ci);
    pid = ci.state == SD_WD_CLIENT_RUNNING ? ci.pid : 0;
  }
  sd_mutex_lock(&s->mu);
  s->webclient_pid = pid;
  s->webclient_pid_at = now ? now : 1;
  sd_mutex_unlock(&s->mu);
  return pid;
}

/* ---- I/O ---- */

int wd_send_all(wd_conn *c, const void *p, size_t n)
{
  const char *b = (const char *)p;
  while (n > 0) {
    int k = send(c->s, b, (int)SD_MIN(n, (size_t)(1u << 20)), 0);
    if (k <= 0)
      return -1;
    b += k;
    n -= (size_t)k;
  }
  return 0;
}

/* Receives into the connection buffer before the deadline. >0 bytes, 0 = closed/timeout/error. */
static int recv_some(wd_conn *c, uint64_t deadline)
{
  for (;;) {
    fd_set rs;
    struct timeval tv;
    uint64_t now = sd_tick_ms();
    int k;
    if (InterlockedCompareExchange(&c->evict, 0, 0) || InterlockedCompareExchange(&c->srv->stop, 0, 0))
      return 0;
    if (now >= deadline)
      return 0;
    if (c->ipos == c->ilen) {
      c->ipos = c->ilen = 0;
    } else if (c->ilen == WD_IBUF && c->ipos > 0) {
      memmove(c->ib, c->ib + c->ipos, c->ilen - c->ipos);
      c->ilen -= c->ipos;
      c->ipos = 0;
    }
    if (c->ilen >= WD_IBUF)
      return 0;
    FD_ZERO(&rs);
    FD_SET(c->s, &rs);
    {
      uint64_t wait = SD_MIN(deadline - now, (uint64_t)1000u);
      tv.tv_sec = (long)(wait / 1000u);
      tv.tv_usec = (long)((wait % 1000u) * 1000u);
    }
    k = select(0, &rs, NULL, NULL, &tv);
    if (k < 0)
      return 0;
    if (k == 0)
      continue;
    k = recv(c->s, c->ib + c->ilen, (int)(WD_IBUF - c->ilen), 0);
    if (k <= 0)
      return 0;
    c->ilen += (size_t)k;
    return k;
  }
}

static void fmt_date(char out[32])
{
  wd_rfc1123(sd_filetime_now(), out);
}

static void build_head(wd_rq *q, wd_sb *h, int status, const char *extra, const char *ctype, uint64_t len)
{
  char date[32];
  fmt_date(date);
  q->status = status;
  wd_sb_fmt(h, "HTTP/1.1 %d %s\r\nServer: ShellDrive\r\nDate: %s\r\n", status, wd_status_text(status), date);
  if (q->c->auth_reply[0]) {
    wd_sb_str(h, "WWW-Authenticate: ");
    wd_sb_str(h, q->c->auth_reply);
    wd_sb_str(h, "\r\n");
    q->c->auth_reply[0] = 0;
  }
  if (ctype)
    wd_sb_fmt(h, "Content-Type: %s\r\n", ctype);
  if (extra)
    wd_sb_str(h, extra);
  if (status != 304 && !(status >= 100 && status < 200))
    wd_sb_fmt(h, "Content-Length: %llu\r\n", (unsigned long long)len);
  if (q->close_after)
    wd_sb_str(h, "Connection: close\r\n");
  wd_sb_str(h, "\r\n");
}

int wd_respond_head(wd_rq *q, int status, const char *extra, const char *ctype, uint64_t content_length)
{
  wd_sb h;
  int rc;
  wd_sb_init(&h, 64u * 1024u);
  build_head(q, &h, status, extra, ctype, content_length);
  rc = h.oom ? -1 : wd_send_all(q->c, h.p, h.n);
  wd_sb_free(&h);
  q->sent = 1;
  if (rc != 0)
    q->close_after = 1;
  return rc;
}

void wd_respond(wd_rq *q, int status, const char *extra, const char *ctype, const void *body, size_t n)
{
  wd_sb h;
  int rc;
  wd_sb_init(&h, 64u * 1024u + (n < 65536u ? n : 0));
  build_head(q, &h, status, extra, ctype, n);
  if (n && n < 65536u) {
    wd_sb_add(&h, body, n);
    n = 0;
  }
  rc = h.oom ? -1 : wd_send_all(q->c, h.p, h.n);
  if (rc == 0 && n)
    rc = wd_send_all(q->c, body, n);
  wd_sb_free(&h);
  q->sent = 1;
  if (rc != 0)
    q->close_after = 1;
}

/* ---- body ---- */

int wd_has_body(const wd_rq *q)
{
  return q->r.chunked || (q->r.has_length && q->r.length > 0);
}

static int body_next_impl(wd_rq *q, const char **p, size_t *n, int allow_continue)
{
  wd_conn *c = q->c;
  *p = NULL;
  *n = 0;
  if (q->body_error)
    return -1;
  for (;;) {
    size_t avail;
    if (q->body_done)
      return 0;
    if (!q->r.chunked && q->body_left == 0) {
      q->body_done = 1;
      return 0;
    }
    if (c->ipos == c->ilen) {
      if (allow_continue && q->r.expect_continue && !q->continue_sent) {
        static const char k100[] = "HTTP/1.1 100 Continue\r\n\r\n";
        q->continue_sent = 1;
        if (wd_send_all(c, k100, sizeof(k100) - 1) != 0) {
          q->body_error = 1;
          return -1;
        }
      }
      if (recv_some(c, sd_tick_ms() + 60000u) <= 0) {
        q->body_error = 1;
        q->close_after = 1;
        return -1;
      }
    }
    avail = c->ilen - c->ipos;
    if (!q->r.chunked) {
      size_t take = (uint64_t)avail > q->body_left ? (size_t)q->body_left : avail;
      *p = c->ib + c->ipos;
      *n = take;
      c->ipos += take;
      q->body_left -= take;
      return 0;
    } else {
      size_t used = 0, dn = 0;
      const char *d = NULL;
      if (wd_chunked_feed(&q->ch, c->ib + c->ipos, avail, &used, &d, &dn) != 0) {
        q->body_error = 1;
        q->close_after = 1;
        return -1;
      }
      c->ipos += used;
      if (q->ch.done)
        q->body_done = 1;
      if (dn) {
        *p = d;
        *n = dn;
        return 0;
      }
    }
  }
}

int wd_body_next(wd_rq *q, const char **p, size_t *n)
{
  return body_next_impl(q, p, n, 1);
}

int wd_body_read_all(wd_rq *q, wd_sb *b, size_t max)
{
  for (;;) {
    const char *p;
    size_t n;
    if (wd_body_next(q, &p, &n) != 0)
      return 400;
    if (n == 0)
      return 0;
    if (b->n + n > max) {
      q->close_after = 1;
      return 413;
    }
    wd_sb_add(b, p, n);
    if (b->oom)
      return 500;
  }
}

/* Drains what is left of the body (unparsed). Returns 0 when fully drained within limit. */
static int drain(wd_rq *q, uint64_t limit, int allow_continue)
{
  uint64_t total = 0;
  if (!wd_has_body(q))
    return 0;
  if (!q->r.chunked && q->body_left > limit)
    return -1;
  for (;;) {
    const char *p;
    size_t n;
    if (body_next_impl(q, &p, &n, allow_continue) != 0)
      return -1;
    if (n == 0)
      return 0;
    total += n;
    if (total > limit)
      return -1;
  }
}

/* ---- exports ---- */

static sd_webdav_export *export_acquire(sd_webdav_server *s, const char *seg)
{
  sd_webdav_export *e, *found = NULL;
  sd_mutex_lock(&s->mu);
  for (e = s->exports; e; e = e->next) {
    int eq = wd_ct_equal(e->token, seg + 2, WD_TOKEN_CHARS);
    if (eq && !e->removing && !found)
      found = e;
  }
  if (found)
    InterlockedIncrement(&found->busy);
  sd_mutex_unlock(&s->mu);
  return found;
}

static void export_release(sd_webdav_export *e)
{
  if (e) InterlockedDecrement(&e->busy);
}

/* ---- request gate ---- */

static void respond_simple(wd_rq *q, int status, int close)
{
  if (close) q->close_after = 1;
  wd_respond(q, status, NULL, NULL, NULL, 0);
}

static void challenge(wd_rq *q, const char *token_hdr)
{
  wd_sb extra;
  wd_sb_init(&extra, 128u * 1024u);
  if (token_hdr && token_hdr[0]) {
    wd_sb_str(&extra, "WWW-Authenticate: ");
    wd_sb_str(&extra, token_hdr);
    wd_sb_str(&extra, "\r\n");
  } else {
    wd_sb_str(&extra, "WWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n");
  }
  /* an announced body is drained unparsed up to 64 KiB, never with 100 Continue (02 §7.3) */
  if (wd_has_body(q) && (q->r.expect_continue || drain(q, WD_UNAUTH_DRAIN_MAX, 0) != 0))
    q->close_after = 1;
  if (extra.oom)
    q->close_after = 1;
  wd_respond(q, 401, extra.oom ? NULL : extra.p, NULL, NULL, 0);
  wd_sb_free(&extra);
}

/* A token-only export answered on this connection: it leaves the unauthenticated quota and gets the
   authenticated idle deadline, without becoming authenticated (see wd_conn.tok). */
static void mark_token_conn(wd_conn *c)
{
  sd_webdav_server *s = c->srv;
  sd_mutex_lock(&s->mu);
  c->tok = 1;
  if (c->unauth_counted) {
    c->unauth_counted = 0;
    s->nunauth--;
  }
  sd_mutex_unlock(&s->mu);
}

static void set_authed(wd_conn *c, PSID user)
{
  sd_webdav_server *s = c->srv;
  sd_free(c->user);
  c->user = user;
  if (!c->authed) {
    c->authed = 1;
    sd_mutex_lock(&s->mu);
    if (c->unauth_counted) {
      c->unauth_counted = 0;
      s->nunauth--;
    }
    sd_mutex_unlock(&s->mu);
  }
}

/* Returns 1 when the request may proceed. */
static int authenticate(wd_rq *q)
{
  wd_conn *c = q->c;
  uint32_t cnt = 0;
  const wd_hdr *ah = wd_req_header(&q->r, "Authorization", &cnt);
  enum { OUT_CAP = 1024 * 64 / 3 + 64 };
  char *out;
  PSID user = NULL;
  int rc, ok = 0;
  if (cnt > 1) {
    respond_simple(q, 400, 1);
    return 0;
  }
  if (ah == NULL) {
    if (c->authed)
      return 1;
    challenge(q, NULL);
    return 0;
  }
  if (c->authed && !wd_ieq(ah->val, SD_MIN(ah->vlen, 9u), "Negotiate") && !wd_ieq(ah->val, SD_MIN(ah->vlen, 4u), "NTLM"))
    return 1;                              /* another scheme on an authenticated connection: ignored */
  out = (char *)sd_alloc(OUT_CAP);
  if (out == NULL) {
    respond_simple(q, 500, 1);
    return 0;
  }
  rc = wd_auth_step(&c->auth, ah->val, ah->vlen, out, OUT_CAP, &user);
  if (rc == WD_AUTH_CONTINUE) {
    challenge(q, out);
  } else if (rc != WD_AUTH_OK) {
    c->authed = 0;
    q->close_after = 1;
    challenge(q, NULL);
  } else if (!EqualSid(user, c->srv->owner)) {
    SD_LOGW(WD_LOG, "rejected a caller whose SID is not the mount owner");
    sd_free(user);
    respond_simple(q, 403, 1);
  } else {
    if (out[0] && strlen(out) < sizeof(c->auth_reply))
      memcpy(c->auth_reply, out, strlen(out) + 1);
    set_authed(c, user);
    ok = 1;
  }
  sd_free(out);
  return ok;
}

static void handle(wd_rq *q)
{
  wd_conn *c = q->c;
  uint32_t cnt = 0;
  const wd_hdr *hh = wd_req_header(&q->r, "Host", &cnt);
  int rc;
  if (q->r.close)
    q->close_after = 1;
  if (hh == NULL || cnt != 1 || !wd_host_ok(hh->val, hh->vlen, c->srv->port) || hh->vlen >= sizeof(q->host)) {
    respond_simple(q, 400, 1);
    return;
  }
  memcpy(q->host, hh->val, hh->vlen);
  q->host[hh->vlen] = 0;
  q->host_n = hh->vlen;
  /* browser-origin requests: 403, before the token check and without a challenge (T-33) */
  if (wd_req_header(&q->r, "Origin", NULL) || wd_req_has_prefix_header(&q->r, "Sec-Fetch-")) {
    respond_simple(q, 403, 1);
    return;
  }
  if (strcmp(q->r.method, "OPTIONS") == 0 && q->r.tlen == 1 && q->r.target[0] == '*') {
    if (drain(q, WD_UNAUTH_DRAIN_MAX, 0) != 0) q->close_after = 1;
    wd_options(q);
    return;
  }
  rc = wd_path_decode(q->r.target, q->r.tlen, &q->path);
  if (rc != 0) {
    respond_simple(q, rc, 1);
    return;
  }
  if (q->path.nseg > 0) {
    if (!wd_is_token_seg(q->path.seg[0]) || (q->ex = export_acquire(c->srv, q->path.seg[0])) == NULL) {
      if (strcmp(q->r.method, "OPTIONS") == 0) {
        if (drain(q, WD_UNAUTH_DRAIN_MAX, 0) != 0) q->close_after = 1;
        wd_options(q);
        return;
      }
      /* unknown prefix: 404 before authentication, no challenge (02 §7.4) */
      if (wd_has_body(q) && (q->r.expect_continue || drain(q, WD_UNAUTH_DRAIN_MAX, 0) != 0))
        q->close_after = 1;
      respond_simple(q, 404, 0);
      return;
    }
  }
  if (strcmp(q->r.method, "OPTIONS") == 0) {
    if (drain(q, WD_UNAUTH_DRAIN_MAX, 0) != 0) q->close_after = 1;
    wd_options(q);
    return;
  }
  if (q->ex && q->ex->token_only) {
    /* TM-R19 token-only export: the per-mount token (already matched above) is the sole authenticator. No
       SSPI challenge, no owner SID check; the caller is the mount owner. The connection is marked, but
       authed stays 0 so that a later request to any other export still goes through SSPI. */
    mark_token_conn(c);
    q->caller.sid = c->srv->owner;
  } else {
    if (!authenticate(q))
      return;
    q->caller.sid = c->user;
  }
  q->caller.can_write = q->ex ? !q->ex->read_only : FALSE;
  q->caller.groups = NULL;              /* M5: no token groups on the per-user SSPI path (matched by SID) */
  q->caller.n_groups = 0;
  q->vpath = wd_path_to_vfs(&q->path, 1);
  if (q->vpath == NULL) {
    respond_simple(q, 400, 0);
    return;
  }
  wd_dispatch(q);
}

/* ---- connection thread ---- */

static void conn_unlink(wd_conn *c)
{
  sd_webdav_server *s = c->srv;
  sd_mutex_lock(&s->mu);
  if (c->prev) c->prev->next = c->next;
  else s->conns = c->next;
  if (c->next) c->next->prev = c->prev;
  s->nconn--;
  if (c->unauth_counted) {
    c->unauth_counted = 0;
    s->nunauth--;
  }
  sd_mutex_unlock(&s->mu);
}

static unsigned __stdcall conn_main(void *arg)
{
  wd_conn *c = (wd_conn *)arg;
  sd_webdav_server *s = c->srv;
  for (;;) {
    wd_rq q;
    int st = 400, pr = WD_PARSE_MORE;
    uint64_t deadline;
    memset(&q, 0, sizeof(q));
    q.c = c;
    deadline = (c->authed || c->tok) ? c->last_at + s->idle_ms
                         : SD_MIN(c->last_at + s->header_ms, c->accepted_at + s->auth_ms);
    for (;;) {
      if (c->ilen > c->ipos) {
        pr = wd_http_parse_head(c->ib + c->ipos, c->ilen - c->ipos, &q.r, &st);
        if (pr != WD_PARSE_MORE)
          break;
        if (c->ipos > 0) {                 /* make room for the rest of the head */
          memmove(c->ib, c->ib + c->ipos, c->ilen - c->ipos);
          c->ilen -= c->ipos;
          c->ipos = 0;
        }
      }
      if (recv_some(c, deadline) <= 0) {
        pr = WD_PARSE_MORE;
        break;
      }
    }
    if (pr == WD_PARSE_MORE)
      break;                               /* closed, timed out or evicted */
    if (pr == WD_PARSE_ERROR) {
      q.close_after = 1;
      wd_respond(&q, st, NULL, NULL, NULL, 0);
      break;
    }
    c->ipos += q.r.head_len;
    q.body_left = q.r.has_length ? q.r.length : 0;
    wd_chunked_init(&q.ch);
    handle(&q);
    if (!q.sent) {
      q.close_after = 1;
      wd_respond(&q, 500, NULL, NULL, NULL, 0);
    }
    /* the path is never logged: it carries the per-mount token (02 §7.3) */
    SD_LOGD(WD_LOG, "request %s -> %d%s", q.r.method, q.status, c->authed ? "" : " (unauthenticated)");
    if (wd_dbg_on) {
      char *r = wd_dbg_ring[InterlockedIncrement(&wd_dbg_idx) % WD_SERVER_DBG_N];
      _snprintf_s(r, 96, _TRUNCATE, "-> %d authed=%d tok=%d %s [%.20s]", q.status, c->authed, c->tok,
                  q.r.method, q.r.target);
    }
    /* whatever the handler left of the body is drained (or the connection closes) */
    if (!q.close_after && wd_has_body(&q) && !q.body_done) {
      if (q.r.expect_continue && !q.continue_sent)
        q.close_after = 1;               /* the client may or may not send it: framing is lost */
      else if (drain(&q, (c->authed || (q.ex && q.ex->token_only)) ? (1u << 20) : WD_UNAUTH_DRAIN_MAX, 0) != 0)
        q.close_after = 1;
    }
    export_release(q.ex);
    wd_path_free(&q.path);
    sd_free(q.vpath);
    c->last_at = sd_tick_ms();
    if (q.close_after)
      break;
  }
  /* lingering close: discard what the peer still sends for a moment, so that unread input does not turn
     the close into a reset that destroys the final response on the client side */
  shutdown(c->s, SD_SEND);
  if (!InterlockedCompareExchange(&s->stop, 0, 0)) {
    uint64_t end = sd_tick_ms() + 300u;
    size_t total = 0;
    while (total < (1u << 20)) {
      c->ipos = c->ilen = 0;
      if (recv_some(c, end) <= 0)
        break;
      total += c->ilen;
    }
  }
  closesocket(c->s);
  conn_unlink(c);
  wd_auth_reset(&c->auth);
  sd_free(c->user);
  sd_free(c->ib);
  sd_free(c);
  if (InterlockedDecrement(&s->live) == 0)
    sd_event_set(&s->idle_ev);
  return 0;
}

/* ---- accept ---- */

static void admit(sd_webdav_server *s, SOCKET cs, int family, uint16_t peer_port_net)
{
  wd_conn *c, *it, *oldest = NULL;
  DWORD pid, wc;
  uint32_t same = 0;
  BOOL one = TRUE;
  int ms = 60000;
  sd_thread t;
  SetHandleInformation((HANDLE)cs, HANDLE_FLAG_INHERIT, 0);
  setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
  setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
  pid = peer_pid(family, peer_port_net, htons(s->port));
  wc = webclient_pid(s);
  c = (wd_conn *)sd_calloc(1, sizeof(*c));
  if (c) c->ib = (char *)sd_alloc(WD_IBUF);
  if (c == NULL || c->ib == NULL) {
    if (c) sd_free(c);
    closesocket(cs);
    return;
  }
  c->srv = s;
  c->s = cs;
  c->peer_pid = pid;
  c->exempt = pid != 0 && pid == wc;
  c->accepted_at = c->last_at = sd_tick_ms();
  sd_mutex_lock(&s->mu);
  if (s->nconn >= s->max_conn) {
    sd_mutex_unlock(&s->mu);
    SD_LOGW(WD_LOG, "connection limit reached");
    goto reject;
  }
  for (it = s->conns; it; it = it->next) {
    if (it->unauth_counted && !it->exempt) {
      if (pid && it->peer_pid == pid) same++;
      if (!InterlockedCompareExchange(&it->evict, 0, 0) && (oldest == NULL || it->accepted_at < oldest->accepted_at))
        oldest = it;
    }
  }
  if (!c->exempt && same >= s->max_unauth_pp) {
    sd_mutex_unlock(&s->mu);
    SD_LOGW(WD_LOG, "per-process unauthenticated limit reached (pid %u)", (unsigned)pid);
    goto reject;
  }
  if (s->nunauth >= s->max_unauth) {
    if (oldest == NULL) {
      if (!c->exempt) {
        sd_mutex_unlock(&s->mu);
        goto reject;
      }
    } else {
      InterlockedExchange(&oldest->evict, 1);
      shutdown(oldest->s, SD_BOTH);
    }
  }
  c->unauth_counted = 1;
  s->nunauth++;
  s->nconn++;
  c->next = s->conns;
  if (s->conns) s->conns->prev = c;
  s->conns = c;
  InterlockedIncrement(&s->live);
  sd_event_reset(&s->idle_ev);
  sd_mutex_unlock(&s->mu);
  if (sd_thread_create(&t, conn_main, c, 0, L"sd-webdav-conn") != SD_OK) {
    conn_unlink(c);
    closesocket(cs);
    sd_free(c->ib);
    sd_free(c);
    if (InterlockedDecrement(&s->live) == 0)
      sd_event_set(&s->idle_ev);
    return;
  }
  CloseHandle(t.h);                        /* detached; stop waits on s->live */
  return;
reject:
  closesocket(cs);
  sd_free(c->ib);
  sd_free(c);
}

static unsigned __stdcall accept_main(void *arg)
{
  sd_webdav_server *s = (sd_webdav_server *)arg;
  while (!InterlockedCompareExchange(&s->stop, 0, 0)) {
    fd_set rs;
    struct timeval tv = { 0, 250000 };
    int i, k;
    FD_ZERO(&rs);
    for (i = 0; i < s->nls; i++)
      FD_SET(s->ls[i], &rs);
    k = select(0, &rs, NULL, NULL, &tv);
    if (k <= 0)
      continue;
    for (i = 0; i < s->nls; i++) {
      if (FD_ISSET(s->ls[i], &rs)) {
        struct sockaddr_storage ss;
        int sl = sizeof(ss);
        SOCKET cs = accept(s->ls[i], (struct sockaddr *)&ss, &sl);
        uint16_t pport;
        if (cs == INVALID_SOCKET)
          continue;
        pport = ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                         : ((struct sockaddr_in *)&ss)->sin_port;
        admit(s, cs, ss.ss_family == AF_INET6 ? AF_INET6 : AF_INET, pport);
      }
    }
  }
  return 0;
}

/* ---- listener ---- */

static SOCKET listen_on(int family, uint16_t port, int *werr)
{
  SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
  BOOL one = TRUE;
  *werr = 0;
  if (s == INVALID_SOCKET) {
    *werr = WSAGetLastError();
    return INVALID_SOCKET;
  }
  SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
  /* TM-R17 a: before bind, never a fallback to a shared bind */
  if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof(one)) != 0) {
    *werr = -1;
    closesocket(s);
    return INVALID_SOCKET;
  }
  if (family == AF_INET) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) goto fail;
  } else {
    struct sockaddr_in6 a;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    a.sin6_addr.s6_addr[15] = 1;           /* ::1 */
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) goto fail;
  }
  if (listen(s, 32) != 0) goto fail;
  return s;
fail:
  *werr = WSAGetLastError();
  closesocket(s);
  return INVALID_SOCKET;
}

static PSID process_sid(void)
{
  HANDLE tok;
  uint8_t buf[512];
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

static void server_free(sd_webdav_server *s)
{
  sd_free(s->owner);
  sd_event_destroy(&s->idle_ev);
  sd_mutex_destroy(&s->mu);
  sd_free(s);
}

sd_err sd_webdav_server_start(const sd_webdav_server_cfg *cfg, sd_webdav_server **out)
{
  sd_webdav_server *s;
  int attempt, werr = 0;
  if (out == NULL || cfg == NULL || cfg->struct_size < sizeof(*cfg))
    return SD_E_INVALID_PARAM;
  *out = NULL;
  sd_once_run(&g_wsa_once, wsa_init, NULL);
  if (!g_wsa_ok)
    return SD_E_UNSUPPORTED;
  if (!wd_auth_available() && !cfg->token_only)
    return SD_WD_E_AUTH_UNAVAILABLE;       /* no SSPI Negotiate (02 §7.4); token-only exports do not need it */
  s = (sd_webdav_server *)sd_calloc(1, sizeof(*s));
  if (s == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&s->mu);
  if (sd_event_init(&s->idle_ev, 1, 1) != SD_OK) {
    sd_mutex_destroy(&s->mu);
    sd_free(s);
    return SD_E_NO_MEMORY;
  }
  if (cfg->owner_sid) {
    DWORD l = GetLengthSid(cfg->owner_sid);
    s->owner = sd_alloc(l);
    if (s->owner && !CopySid(l, s->owner, cfg->owner_sid)) { sd_free(s->owner); s->owner = NULL; }
  } else {
    s->owner = process_sid();
  }
  if (s->owner == NULL) {
    server_free(s);
    return SD_E_NO_MEMORY;
  }
  s->header_ms = cfg->header_timeout_ms ? cfg->header_timeout_ms : 10000u;
  s->auth_ms = cfg->auth_timeout_ms ? cfg->auth_timeout_ms : 30000u;
  s->idle_ms = cfg->idle_timeout_ms ? cfg->idle_timeout_ms : 120000u;
  s->max_unauth = cfg->max_unauth ? cfg->max_unauth : 8u;
  s->max_unauth_pp = cfg->max_unauth_per_process ? cfg->max_unauth_per_process : 4u;
  s->max_conn = cfg->max_connections ? cfg->max_connections : 64u;
  for (attempt = 0; attempt < 16; attempt++) {
    struct sockaddr_in a;
    int al = sizeof(a);
    SOCKET l4 = listen_on(AF_INET, cfg->port, &werr), l6;
    if (l4 == INVALID_SOCKET) {
      if (werr == -1) {
        SD_LOGE(WD_LOG, "SO_EXCLUSIVEADDRUSE refused; not listening");
        server_free(s);
        return SD_E_ACCESS_DENIED;         /* SD_WD_E_EXCLUSIVE_BIND */
      }
      if (cfg->port) break;
      continue;
    }
    if (getsockname(l4, (struct sockaddr *)&a, &al) != 0) {
      closesocket(l4);
      continue;
    }
    s->port = ntohs(a.sin_port);
    s->ls[0] = l4;
    s->nls = 1;
    if (cfg->no_ipv6)
      break;
    l6 = listen_on(AF_INET6, s->port, &werr);
    if (l6 != INVALID_SOCKET) {
      s->ls[1] = l6;
      s->nls = 2;
      break;
    }
    if (werr == WSAEAFNOSUPPORT || werr == WSAEPROTONOSUPPORT || werr == WSAEADDRNOTAVAIL || werr == WSAEPFNOSUPPORT)
      break;                               /* no IPv6 loopback: IPv4 only */
    /* ::1 cannot take the same port: rebind both on a new one (02 §7.3) */
    closesocket(l4);
    s->nls = 0;
    if (cfg->port) break;
  }
  if (s->nls == 0) {
    SD_LOGE(WD_LOG, "listen failed (%d)", werr);
    server_free(s);
    return SD_E_FAILURE;
  }
  if (sd_thread_create(&s->accept_thr, accept_main, s, 0, L"sd-webdav-accept") != SD_OK) {
    int i;
    for (i = 0; i < s->nls; i++) closesocket(s->ls[i]);
    server_free(s);
    return SD_E_FAILURE;
  }
  SD_LOGI(WD_LOG, "listening on 127.0.0.1:%u%s", (unsigned)s->port, s->nls == 2 ? " and [::1]" : "");
  *out = s;
  return SD_OK;
}

uint16_t sd_webdav_server_port(const sd_webdav_server *s)
{
  return s ? s->port : 0;
}

void sd_webdav_server_stop(sd_webdav_server *s)
{
  wd_conn *c;
  int i;
  if (s == NULL)
    return;
  InterlockedExchange(&s->stop, 1);
  sd_thread_join(&s->accept_thr, SD_WAIT_INFINITE, NULL);
  for (i = 0; i < s->nls; i++)
    closesocket(s->ls[i]);
  s->nls = 0;
  sd_mutex_lock(&s->mu);
  for (c = s->conns; c; c = c->next) {
    InterlockedExchange(&c->evict, 1);
    shutdown(c->s, SD_BOTH);
  }
  sd_mutex_unlock(&s->mu);
  if (sd_event_wait(&s->idle_ev, 60000) != SD_OK)
    SD_LOGE(WD_LOG, "connection threads did not exit; leaking the server");
  else {
    while (s->exports) {
      sd_webdav_export *e = s->exports;
      s->exports = e->next;
      wd_locks_free(e);
      sd_mutex_destroy(&e->lock_mu);
      sd_free(e->label);
      sd_free(e);
    }
    server_free(s);
  }
}

sd_err sd_webdav_export_add(sd_webdav_server *s, sd_vfs *vfs, const sd_webdav_export_cfg *cfg,
                            sd_webdav_export **out)
{
  sd_webdav_export *e;
  if (out == NULL || s == NULL || vfs == NULL || cfg == NULL || cfg->struct_size < sizeof(*cfg))
    return SD_E_INVALID_PARAM;
  *out = NULL;
  e = (sd_webdav_export *)sd_calloc(1, sizeof(*e));
  if (e == NULL)
    return SD_E_NO_MEMORY;
  if (wd_make_token(e->token) != 0) {
    sd_free(e);
    return SD_E_CRYPTO;
  }
  _snprintf_s(e->prefix, sizeof(e->prefix), _TRUNCATE, "/s-%s", e->token);
  e->srv = s;
  e->vfs = vfs;
  e->read_only = cfg->read_only;
  e->token_only = cfg->token_only;
  if (cfg->label && cfg->label[0]) {
    size_t n = wcslen(cfg->label);
    e->label = (WCHAR *)sd_alloc((n + 1) * sizeof(WCHAR));
    if (e->label == NULL) {
      sd_free(e);
      return SD_E_NO_MEMORY;
    }
    memcpy(e->label, cfg->label, (n + 1) * sizeof(WCHAR));
  }
  sd_mutex_init(&e->lock_mu);
  sd_mutex_lock(&s->mu);
  e->next = s->exports;
  s->exports = e;
  sd_mutex_unlock(&s->mu);
  *out = e;
  return SD_OK;
}

void sd_webdav_export_remove(sd_webdav_export *e)
{
  sd_webdav_server *s;
  sd_webdav_export **pp;
  if (e == NULL)
    return;
  s = e->srv;
  sd_mutex_lock(&s->mu);
  e->removing = 1;
  for (pp = &s->exports; *pp; pp = &(*pp)->next) {
    if (*pp == e) {
      *pp = e->next;
      break;
    }
  }
  sd_mutex_unlock(&s->mu);
  while (InterlockedCompareExchange(&e->busy, 0, 0) != 0)
    Sleep(10);
  wd_locks_free(e);
  sd_mutex_destroy(&e->lock_mu);
  sd_free(e->label);
  sd_free(e);
}

const char *sd_webdav_export_prefix(const sd_webdav_export *e)
{
  return e ? e->prefix : "";
}

sd_err sd_webdav_export_remote_name(const sd_webdav_export *e, BOOL xp_form, wchar_t *out, size_t cap)
{
  int k;
  if (e == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  if (xp_form)
    k = _snwprintf_s(out, cap, _TRUNCATE, L"http://localhost:%u/s-%S", (unsigned)e->srv->port, e->token);
  else
    k = _snwprintf_s(out, cap, _TRUNCATE, L"\\\\localhost@%u\\DavWWWRoot\\s-%S", (unsigned)e->srv->port, e->token);
  return k < 0 ? SD_E_INVALID_PARAM : SD_OK;
}
