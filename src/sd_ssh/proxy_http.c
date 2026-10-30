/* HTTP CONNECT client (01 §5.2, D20) and the shared ssh_px entry points.
 *
 * Request: CONNECT <host>:<port> HTTP/1.1, Host, User-Agent and, when authenticating,
 * Proxy-Authorization (Basic, or Negotiate/NTLM tokens produced by SSPI in the glue). The response
 * head is read byte by byte up to the blank line (16 KiB, 100 lines), so bytes that follow it in
 * the same segment stay for the SSH layer. Any 2xx opens the tunnel; a 2xx with a body is a protocol
 * error. 407 is answered per the allowed schemes and TM-R10 (at most 3 rounds); its body is skipped,
 * or the connection is reopened when the proxy closes it (Connection: close, HTTP/1.0, chunked). */
#include <string.h>

#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "ssh_internal.h"
#include "proxy_internal.h"

#define PX_VSTR_(x) #x
#define PX_VSTR(x) PX_VSTR_(x)
#define PX_USER_AGENT "ShellDrive/" PX_VSTR(SD_VERSION_MAJOR) "." PX_VSTR(SD_VERSION_MINOR) "." PX_VSTR(SD_VERSION_PATCH)

enum { H_HEAD = 1, H_BODY, H_ACTION, H_DONE, H_FAIL };
enum { ACT_NONE = 0, ACT_PASSWORD, ACT_SSPI, ACT_SEND };

/* ---- common ---- */

static void set_why(ssh_px *px, const char *s)
{
  size_t n = strlen(s);
  if (n >= sizeof(px->why)) n = sizeof(px->why) - 1;
  memcpy(px->why, s, n);
  px->why[n] = 0;
}

static ssh_px_status px_fail(ssh_px *px, sd_err e, const char *why)
{
  px->err = e;
  px->step = H_FAIL;
  if (why) set_why(px, why);
  return PX_FAIL;
}

int ssh_px_parse_ipv4(const char *s, uint8_t out[4])
{
  uint32_t part = 0;
  int dots = 0, digits = 0;
  for (; *s; s++) {
    if (*s >= '0' && *s <= '9') {
      part = part * 10u + (uint32_t)(*s - '0');
      if (++digits > 3 || part > 255) return 0;
    } else if (*s == '.' && digits && dots < 3) {
      out[dots++] = (uint8_t)part;
      part = 0;
      digits = 0;
    } else {
      return 0;
    }
  }
  if (dots != 3 || !digits) return 0;
  out[3] = (uint8_t)part;
  return 1;
}

static int hexval(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int ssh_px_parse_ipv6(const char *s, uint8_t out[16])
{
  uint16_t head[8], tail[8];
  uint32_t nh = 0, nt = 0, i;
  int dbl = 0;
  const char *p = s;
  if (!*p) return 0;
  if (p[0] == ':') { if (p[1] != ':') return 0; dbl = 1; p += 2; }
  while (*p && *p != '%') {
    uint32_t v = 0;
    int nd = 0;
    while (hexval(*p) >= 0) { v = (v << 4) | (uint32_t)hexval(*p); p++; if (++nd > 4) return 0; }
    if (!nd) return 0;
    if (dbl) { if (nt >= 8) return 0; tail[nt++] = (uint16_t)v; }
    else { if (nh >= 8) return 0; head[nh++] = (uint16_t)v; }
    if (*p == ':') {
      if (p[1] == ':') { if (dbl) return 0; dbl = 1; p += 2; if (!*p || *p == '%') break; continue; }
      p++;
      if (!*p) return 0;
    } else if (*p && *p != '%') {
      return 0;
    }
  }
  if (dbl ? nh + nt > 7 : nh != 8) return 0;
  memset(out, 0, 16);
  for (i = 0; i < nh; i++) { out[2 * i] = (uint8_t)(head[i] >> 8); out[2 * i + 1] = (uint8_t)head[i]; }
  for (i = 0; i < nt; i++) {
    uint32_t k = 8 - nt + i;
    out[2 * k] = (uint8_t)(tail[i] >> 8);
    out[2 * k + 1] = (uint8_t)tail[i];
  }
  return 1;
}

sd_err ssh_px_init(ssh_px *px, sd_proxy_kind kind, const char *host, uint16_t port, const char *proxy_host,
                   uint16_t proxy_port, uint32_t auth, int sspi_allowed, const char *user, int remote_dns)
{
  size_t n, i;
  memset(px, 0, sizeof(*px));
  if ((kind != SD_PROXY_HTTP && kind != SD_PROXY_SOCKS5) || !host || !port) return SD_E_INVALID_PARAM;
  n = strlen(host);
  if (n >= 2 && host[0] == '[' && host[n - 1] == ']') { host++; n -= 2; }
  if (n == 0 || n >= sizeof(px->target)) return SD_E_INVALID_PARAM;
  for (i = 0; i < n; i++)
    if ((uint8_t)host[i] <= 0x20 || (uint8_t)host[i] >= 0x7F || host[i] == '/' || host[i] == '@')
      return SD_E_INVALID_PARAM;
  memcpy(px->target, host, n);
  px->target[n] = 0;
  px->target_port = port;
  px->kind = kind;
  px->auth = auth;
  px->sspi_allowed = sspi_allowed;
  px->proxy_port = proxy_port;
  px->user_agent = PX_USER_AGENT;
  if (proxy_host) {
    n = strlen(proxy_host);
    if (n >= sizeof(px->proxy_host)) return SD_E_INVALID_PARAM;
    memcpy(px->proxy_host, proxy_host, n + 1);
  }
  if (user && user[0]) {
    n = strlen(user);
    if (n > 255) return SD_E_INVALID_PARAM;
    memcpy(px->user, user, n + 1);
  }
  /* SOCKS5 address type: literals always as addresses; names per remote_dns */
  if (ssh_px_parse_ipv4(px->target, px->target_addr)) px->target_atyp = 1;
  else if (strchr(px->target, ':')) {
    if (!ssh_px_parse_ipv6(px->target, px->target_addr)) return SD_E_INVALID_PARAM;
    px->target_atyp = 4;
  } else {
    px->target_atyp = remote_dns ? 3 : -3;   /* -3: resolve locally first */
  }
  return SD_OK;
}

int ssh_px_wants_local_dns(const ssh_px *px) { return px->kind == SD_PROXY_SOCKS5 && px->target_atyp == -3; }

void ssh_px_set_target_addr(ssh_px *px, int atyp, const uint8_t *addr)
{
  px->target_atyp = atyp;
  memcpy(px->target_addr, addr, atyp == 1 ? 4u : 16u);
}

void ssh_px_free(ssh_px *px)
{
  sd_secbuf_free(px->password);
  px->password = NULL;
  if (px->token) sd_secure_free(px->token, px->token_len);
  if (px->challenge) sd_secure_free(px->challenge, px->challenge_len);
  px->token = px->challenge = NULL;
  px->token_len = px->challenge_len = 0;
  sd_secure_zero(px->hdr, sizeof(px->hdr));
  sd_secure_zero(px->sbuf, sizeof(px->sbuf));
}

void ssh_px_set_password(ssh_px *px, sd_secbuf *pw)
{
  sd_secbuf_free(px->password);
  px->password = pw;
}

sd_err ssh_px_set_token(ssh_px *px, const uint8_t *tok, size_t n)
{
  if (px->token) sd_secure_free(px->token, px->token_len);
  px->token = NULL;
  px->token_len = 0;
  if (!n) return SD_OK;
  if (n > SSH_PX_TOKEN_MAX) return SD_E_INVALID_PARAM;
  px->token = (uint8_t *)sd_alloc(n);
  if (!px->token) return SD_E_NO_MEMORY;
  memcpy(px->token, tok, n);
  px->token_len = n;
  return SD_OK;
}

/* ---- HTTP request ---- */

static void wr_str(sd_wr *w, const char *s) { sd_wr_bytes(w, s, strlen(s)); }

static void wr_port(sd_wr *w, uint16_t port)
{
  char b[8];
  int i = 7;
  b[i] = 0;
  do { b[--i] = (char)('0' + port % 10); port = (uint16_t)(port / 10); } while (port && i > 0);
  wr_str(w, b + i);
}

static void wr_authority(sd_wr *w, const ssh_px *px)
{
  int v6 = strchr(px->target, ':') != NULL;
  if (v6) sd_wr_u8(w, '[');
  wr_str(w, px->target);
  if (v6) sd_wr_u8(w, ']');
  sd_wr_u8(w, ':');
  wr_port(w, px->target_port);
}

static void wr_b64(sd_wr *w, const uint8_t *p, size_t n)
{
  size_t need = ssh_b64_encoded_len(n, 1) + 1;
  uint8_t *dst = sd_wr_reserve(w, need);
  size_t got;
  if (!dst) return;
  got = ssh_b64_encode(p, n, (char *)dst, need, 1);
  w->len -= need - got;   /* drop the NUL and the unused tail */
}

static void http_request(ssh_px *px, sd_wr *out)
{
  wr_str(out, "CONNECT ");
  wr_authority(out, px);
  wr_str(out, " HTTP/1.1\r\nHost: ");
  wr_authority(out, px);
  wr_str(out, "\r\nUser-Agent: ");
  wr_str(out, px->user_agent);
  wr_str(out, "\r\n");
  if (px->scheme == PX_SCHEME_BASIC && px->password) {
    sd_wr cred;
    sd_wr_init_secret(&cred, 1024);
    wr_str(&cred, px->user);
    sd_wr_u8(&cred, ':');
    sd_wr_bytes(&cred, px->password->p, px->password->len);
    wr_str(out, "Proxy-Authorization: Basic ");
    if (sd_wr_ok(&cred)) wr_b64(out, cred.p, cred.len);
    sd_wr_free(&cred);
    wr_str(out, "\r\n");
  } else if ((px->scheme == PX_SCHEME_NEGOTIATE || px->scheme == PX_SCHEME_NTLM) && px->token_len) {
    wr_str(out, px->scheme == PX_SCHEME_NEGOTIATE ? "Proxy-Authorization: Negotiate " : "Proxy-Authorization: NTLM ");
    wr_b64(out, px->token, px->token_len);
    wr_str(out, "\r\n");
  }
  wr_str(out, "\r\n");
  px->step = H_HEAD;
  px->hlen = 0;
}

/* ---- HTTP response ---- */

static int ieq_prefix(const char *p, size_t n, const char *lit)
{
  size_t i, l = strlen(lit);
  if (n < l) return 0;
  for (i = 0; i < l; i++) {
    char a = p[i], b = lit[i];
    if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
    if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
    if (a != b) return 0;
  }
  return 1;
}

static const char *skip_ws(const char *p, const char *e) { while (p < e && (*p == ' ' || *p == '\t')) p++; return p; }

typedef struct http_head {
  uint32_t status, minor;
  int have_len, chunked, close, keepalive;
  uint64_t clen;
  int offer_basic, offer_negotiate, offer_ntlm;
  const char *neg_tok; size_t neg_len;      /* "Negotiate <tok>" */
  const char *ntlm_tok; size_t ntlm_len;
} http_head;

static int token_is(const char *v, const char *e, const char *name, const char **rest)
{
  size_t l = strlen(name);
  if ((size_t)(e - v) < l || !ieq_prefix(v, (size_t)(e - v), name)) return 0;
  if (v + l < e && v[l] != ' ' && v[l] != '\t' && v[l] != ',') return 0;
  *rest = skip_ws(v + l, e);
  return 1;
}

static void parse_auth_header(http_head *h, const char *v, const char *e)
{
  const char *rest;
  v = skip_ws(v, e);
  if (token_is(v, e, "Basic", &rest)) h->offer_basic = 1;
  else if (token_is(v, e, "Negotiate", &rest)) {
    const char *t = rest;
    h->offer_negotiate = 1;
    while (rest < e && *rest != ' ' && *rest != ',' && *rest != '\t') rest++;
    if (rest > t) { h->neg_tok = t; h->neg_len = (size_t)(rest - t); }
  } else if (token_is(v, e, "NTLM", &rest)) {
    const char *t = rest;
    h->offer_ntlm = 1;
    while (rest < e && *rest != ' ' && *rest != ',' && *rest != '\t') rest++;
    if (rest > t) { h->ntlm_tok = t; h->ntlm_len = (size_t)(rest - t); }
  }
}

static int has_token(const char *v, const char *e, const char *tok)
{
  while (v < e) {
    const char *s = skip_ws(v, e), *t = s;
    while (t < e && *t != ',') t++;
    {
      const char *te = t;
      while (te > s && (te[-1] == ' ' || te[-1] == '\t')) te--;
      if ((size_t)(te - s) == strlen(tok) && ieq_prefix(s, (size_t)(te - s), tok)) return 1;
    }
    v = t + 1;
  }
  return 0;
}

static int parse_head(ssh_px *px, http_head *h)
{
  const char *p = (const char *)px->hdr, *e = p + px->hlen, *le;
  uint32_t lines = 0;
  memset(h, 0, sizeof(*h));
  /* status line */
  le = p;
  while (le < e && *le != '\n') le++;
  if ((size_t)(le - p) < 12 || !ieq_prefix(p, (size_t)(le - p), "HTTP/1.")) return 0;
  if (p[7] < '0' || p[7] > '9' || p[8] != ' ') return 0;
  h->minor = (uint32_t)(p[7] - '0');
  if (p[9] < '1' || p[9] > '5' || p[10] < '0' || p[10] > '9' || p[11] < '0' || p[11] > '9') return 0;
  h->status = (uint32_t)(p[9] - '0') * 100u + (uint32_t)(p[10] - '0') * 10u + (uint32_t)(p[11] - '0');
  p = le + 1;
  while (p < e) {
    const char *colon, *v, *ve;
    le = p;
    while (le < e && *le != '\n') le++;
    ve = le;
    if (ve > p && ve[-1] == '\r') ve--;
    if (ve == p) break;                                 /* blank line */
    if (++lines > SSH_PX_HDR_LINES) return 0;
    if (*p == ' ' || *p == '\t') { p = le + 1; continue; }   /* folded continuation: ignored */
    colon = p;
    while (colon < ve && *colon != ':') colon++;
    if (colon == ve) return 0;
    v = skip_ws(colon + 1, ve);
    if (ieq_prefix(p, (size_t)(colon - p), "Content-Length") && colon - p == 14) {
      uint64_t n = 0;
      const char *q = v;
      if (q == ve) return 0;
      for (; q < ve && *q >= '0' && *q <= '9'; q++) { if (n > (UINT64_MAX - 9) / 10) return 0; n = n * 10 + (uint64_t)(*q - '0'); }
      if (skip_ws(q, ve) != ve) return 0;
      if (h->have_len && h->clen != n) return 0;
      h->have_len = 1;
      h->clen = n;
    } else if (ieq_prefix(p, (size_t)(colon - p), "Transfer-Encoding") && colon - p == 17) {
      if (has_token(v, ve, "chunked")) h->chunked = 1;
    } else if ((ieq_prefix(p, (size_t)(colon - p), "Connection") && colon - p == 10) ||
               (ieq_prefix(p, (size_t)(colon - p), "Proxy-Connection") && colon - p == 16)) {
      if (has_token(v, ve, "close")) h->close = 1;
      if (has_token(v, ve, "keep-alive")) h->keepalive = 1;
    } else if (ieq_prefix(p, (size_t)(colon - p), "Proxy-Authenticate") && colon - p == 18) {
      parse_auth_header(h, v, ve);
    }
    p = le + 1;
  }
  return 1;
}

static void log_status(ssh_px *px, const char *what)
{
  /* "<what> <status> <reason>" with the reason sanitized */
  const char *p = (const char *)px->hdr + 12, *e = (const char *)px->hdr + px->hlen;
  char reason[64];
  size_t n = 0;
  char buf[160];
  size_t bl;
  while (p < e && *p == ' ') p++;
  while (p < e && *p != '\r' && *p != '\n' && n < 40) {
    char ch = *p++;
    reason[n++] = (ch >= 0x20 && ch < 0x7F) ? ch : '?';
  }
  reason[n] = 0;
  bl = strlen(what);
  if (bl > 80) bl = 80;
  memcpy(buf, what, bl);
  buf[bl++] = ' ';
  buf[bl++] = (char)('0' + px->status / 100);
  buf[bl++] = (char)('0' + px->status / 10 % 10);
  buf[bl++] = (char)('0' + px->status % 10);
  buf[bl++] = ' ';
  memcpy(buf + bl, reason, n + 1);
  set_why(px, buf);
}

static int b64_to_challenge(ssh_px *px, const char *t, size_t n)
{
  size_t cap = n, got = 0;
  uint8_t *d;
  if (px->challenge) sd_secure_free(px->challenge, px->challenge_len);
  px->challenge = NULL;
  px->challenge_len = 0;
  if (n == 0) return 1;
  if (n > SSH_PX_TOKEN_MAX * 2) return 0;
  d = (uint8_t *)sd_alloc(cap);
  if (!d) return 0;
  if (ssh_b64_decode(t, n, d, cap, &got, 0) != SD_OK) { sd_free(d); return 0; }
  px->challenge = d;
  px->challenge_len = got;
  return 1;
}

/* Chooses how to answer a 407; sets px->pending. */
static ssh_px_status answer_407(ssh_px *px, const http_head *h)
{
  int sspi_any = (px->auth & (SD_PROXY_AUTH_SSPI | SD_PROXY_AUTH_SSPI_KERBEROS)) != 0;
  if (px->rounds >= SSH_PX_ROUNDS) return px_fail(px, SD_E_PROXY_AUTH, "proxy authentication: rounds exhausted");
  px->rounds++;
  /* continue an SSPI exchange */
  if ((px->scheme == PX_SCHEME_NEGOTIATE && h->offer_negotiate && h->neg_tok) ||
      (px->scheme == PX_SCHEME_NTLM && h->offer_ntlm && h->ntlm_tok)) {
    const char *t = px->scheme == PX_SCHEME_NEGOTIATE ? h->neg_tok : h->ntlm_tok;
    size_t tl = px->scheme == PX_SCHEME_NEGOTIATE ? h->neg_len : h->ntlm_len;
    if (!b64_to_challenge(px, t, tl)) return px_fail(px, SD_E_PROXY, "proxy sent a malformed SSPI token");
    px->pending = ACT_SSPI;
    return PX_NEED_SSPI;
  }
  if (px->scheme == PX_SCHEME_NEGOTIATE || px->scheme == PX_SCHEME_NTLM)
    return px_fail(px, SD_E_PROXY_AUTH, "proxy rejected the SSPI credentials");
  if (px->scheme == PX_SCHEME_BASIC) px->password_failed = 1;
  /* first choice (TM-R10: SSPI only towards configured proxies, or with the policy) */
  if (h->offer_negotiate && sspi_any && px->sspi_allowed && px->scheme == PX_SCHEME_NONE) {
    px->scheme = PX_SCHEME_NEGOTIATE;
    px->kerberos_only = !(px->auth & SD_PROXY_AUTH_SSPI);
    b64_to_challenge(px, NULL, 0);
    px->pending = ACT_SSPI;
    return PX_NEED_SSPI;
  }
  if (h->offer_ntlm && (px->auth & SD_PROXY_AUTH_SSPI) && px->sspi_allowed && px->scheme == PX_SCHEME_NONE) {
    px->scheme = PX_SCHEME_NTLM;
    px->kerberos_only = 0;
    b64_to_challenge(px, NULL, 0);
    px->pending = ACT_SSPI;
    return PX_NEED_SSPI;
  }
  if (h->offer_basic && (px->auth & SD_PROXY_AUTH_BASIC) && px->user[0]) {
    px->scheme = PX_SCHEME_BASIC;
    px->pending = ACT_PASSWORD;
    return PX_NEED_PASSWORD;
  }
  if ((h->offer_negotiate || h->offer_ntlm) && sspi_any && !px->sspi_allowed)
    return px_fail(px, SD_E_PROXY_AUTH,
                   "proxy asks for Negotiate/NTLM, refused towards a discovered proxy (policy AllowSystemProxySspi)");
  if (h->offer_basic && (px->auth & SD_PROXY_AUTH_BASIC) && !px->user[0])
    return px_fail(px, SD_E_PROXY_AUTH, "proxy asks for Basic authentication but no proxy user is configured");
  return px_fail(px, SD_E_PROXY_AUTH, "proxy asks for an authentication scheme that is not allowed");
}

static ssh_px_status after_body(ssh_px *px)
{
  px->step = H_ACTION;
  if (px->pending == ACT_PASSWORD) return PX_NEED_PASSWORD;
  if (px->pending == ACT_SSPI) return PX_NEED_SSPI;
  return px_fail(px, SD_E_INTERNAL, "proxy state");
}

static ssh_px_status http_input(ssh_px *px, const uint8_t *p, size_t n, size_t *used, sd_wr *out)
{
  size_t i = 0;
  SD_UNUSED(out);
  *used = 0;
  if (px->step == H_BODY) {
    size_t take = (size_t)SD_MIN((uint64_t)n, px->body_left);
    px->body_left -= take;
    *used = take;
    if (px->body_left) return PX_MORE;
    return after_body(px);
  }
  if (px->step != H_HEAD) return n ? px_fail(px, SD_E_PROXY, "unexpected data from the proxy") : PX_MORE;
  while (i < n) {
    if (px->hlen >= SSH_PX_HDR_MAX) return px_fail(px, SD_E_PROXY, "proxy response head too long");
    px->hdr[px->hlen++] = p[i++];
    if (px->hlen >= 2 && px->hdr[px->hlen - 1] == '\n' &&
        (px->hdr[px->hlen - 2] == '\n' || (px->hlen >= 4 && px->hdr[px->hlen - 2] == '\r' && px->hdr[px->hlen - 3] == '\n')))
      break;
  }
  *used = i;
  if (!(px->hlen >= 2 && px->hdr[px->hlen - 1] == '\n' &&
        (px->hdr[px->hlen - 2] == '\n' || (px->hlen >= 4 && px->hdr[px->hlen - 2] == '\r' && px->hdr[px->hlen - 3] == '\n'))))
    return PX_MORE;
  {
    http_head h;
    ssh_px_status st;
    if (!parse_head(px, &h)) return px_fail(px, SD_E_PROXY, "malformed proxy response");
    px->status = h.status;
    if (h.status >= 200 && h.status <= 299) {
      if (h.chunked || (h.have_len && h.clen > 0)) return px_fail(px, SD_E_PROXY, "proxy sent a body with its 2xx reply");
      log_status(px, "proxy tunnel established:");
      px->step = H_DONE;
      ssh_px_free(px);
      return PX_DONE;
    }
    if (h.status != 407) { log_status(px, "proxy refused CONNECT:"); return px_fail(px, SD_E_PROXY, NULL); }
    st = answer_407(px, &h);
    if (st == PX_FAIL) { if (!px->why[0]) log_status(px, "proxy authentication failed:"); return st; }
    /* the body is delimited by the connection close unless it has a length on a persistent one */
    px->must_reopen = h.close || h.chunked || (h.minor == 0 && !h.keepalive) || !h.have_len;
    if (!px->must_reopen && h.clen) {
      px->body_left = h.clen;
      px->step = H_BODY;
      {
        size_t take = (size_t)SD_MIN((uint64_t)(n - i), px->body_left);
        px->body_left -= take;
        *used += take;
      }
      if (px->body_left) return PX_MORE;
    }
    return after_body(px);
  }
}

static ssh_px_status http_resume(ssh_px *px, sd_wr *out)
{
  if (px->step == H_FAIL) return PX_FAIL;
  if (px->step != H_ACTION) return PX_MORE;
  if (px->pending == ACT_PASSWORD && !px->password) return px_fail(px, SD_E_PROXY_AUTH, "no proxy password");
  if (px->pending == ACT_SSPI && !px->token_len) return px_fail(px, SD_E_PROXY_AUTH, "no SSPI token");
  if (px->must_reopen) { px->must_reopen = 0; return PX_REOPEN; }
  px->pending = ACT_NONE;
  http_request(px, out);
  return PX_MORE;
}

/* ---- dispatch ---- */

void ssh_px_start(ssh_px *px, sd_wr *out)
{
  px->err = SD_OK;
  px->why[0] = 0;
  if (px->kind == SD_PROXY_SOCKS5) { ssh_px_socks5_start(px, out); return; }
  px->scheme = PX_SCHEME_NONE;
  http_request(px, out);
}

ssh_px_status ssh_px_input(ssh_px *px, const uint8_t *p, size_t n, size_t *used, sd_wr *out)
{
  if (px->kind == SD_PROXY_SOCKS5) return ssh_px_socks5_input(px, p, n, used, out);
  return http_input(px, p, n, used, out);
}

ssh_px_status ssh_px_resume(ssh_px *px, sd_wr *out)
{
  if (px->kind == SD_PROXY_SOCKS5) return ssh_px_socks5_resume(px, out);
  return http_resume(px, out);
}
