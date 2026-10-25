/* Test-only HTTP client with client-side SSPI (see wd_client_util.h). */
#define SECURITY_WIN32
#include "wd_client_util.h"

#include <ws2tcpip.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "wd_proto.h"

int tc_connect(tc_conn *c, uint16_t port, int ipv6)
{
  WSADATA wd;
  if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
    return -1;
  c->len = 0;
  c->s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (c->s == INVALID_SOCKET)
    return -1;
  if (ipv6) {
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    a.sin6_addr.s6_addr[15] = 1;
    if (connect(c->s, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(c->s); c->s = INVALID_SOCKET; return -1; }
  } else {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(c->s, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(c->s); c->s = INVALID_SOCKET; return -1; }
  }
  return 0;
}

void tc_close(tc_conn *c)
{
  if (c->s != INVALID_SOCKET)
    closesocket(c->s);
  c->s = INVALID_SOCKET;
}

int tc_send(tc_conn *c, const void *p, size_t n)
{
  const char *b = (const char *)p;
  while (n) {
    int k = send(c->s, b, (int)SD_MIN(n, (size_t)65536), 0);
    if (k <= 0) return -1;
    b += k;
    n -= (size_t)k;
  }
  return 0;
}

static int fill(tc_conn *c, uint64_t deadline)
{
  fd_set rs;
  struct timeval tv;
  int k;
  uint64_t now = sd_tick_ms();
  if (now >= deadline || c->len >= sizeof(c->buf))
    return -1;
  FD_ZERO(&rs);
  FD_SET(c->s, &rs);
  tv.tv_sec = (long)((deadline - now) / 1000u);
  tv.tv_usec = (long)(((deadline - now) % 1000u) * 1000u);
  k = select(0, &rs, NULL, NULL, &tv);
  if (k <= 0)
    return -1;
  k = recv(c->s, c->buf + c->len, (int)(sizeof(c->buf) - c->len), 0);
  if (k <= 0)
    return 0;
  c->len += (size_t)k;
  return k;
}

int tc_wait_closed(tc_conn *c, uint32_t timeout_ms)
{
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  for (;;) {
    int k;
    c->len = 0;
    k = fill(c, deadline);
    if (k == 0) return 1;
    if (k < 0) return 0;
  }
}

int tc_header(const tc_resp *r, const char *name, char *out, size_t cap)
{
  size_t nl = strlen(name);
  const char *p = r->head;
  while ((p = strstr(p, "\r\n")) != NULL) {
    p += 2;
    if (_strnicmp(p, name, nl) == 0 && p[nl] == ':') {
      const char *v = p + nl + 1, *e;
      size_t n;
      while (*v == ' ') v++;
      e = strstr(v, "\r\n");
      n = e ? (size_t)(e - v) : strlen(v);
      if (n >= cap) n = cap - 1;
      memcpy(out, v, n);
      out[n] = 0;
      return 1;
    }
  }
  return 0;
}

int tc_read(tc_conn *c, tc_resp *r, int no_body, uint32_t timeout_ms)
{
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  char *end;
  size_t hl, cl = 0;
  char v[64];
  memset(r, 0, sizeof(*r));
  for (;;) {
    int k;
    if (c->len >= 4) {
      c->buf[SD_MIN(c->len, sizeof(c->buf) - 1)] = 0;
      end = NULL;
      {
        size_t i;
        for (i = 0; i + 3 < c->len; i++)
          if (memcmp(c->buf + i, "\r\n\r\n", 4) == 0) { end = c->buf + i; break; }
      }
      if (end) break;
    }
    k = fill(c, deadline);
    if (k <= 0) {
      r->closed = 1;
      return -1;
    }
  }
  hl = (size_t)(end - c->buf) + 4;
  memcpy(r->head, c->buf, SD_MIN(hl, sizeof(r->head) - 1));
  r->head[SD_MIN(hl, sizeof(r->head) - 1)] = 0;
  if (sscanf_s(r->head, "HTTP/1.1 %d", &r->status) != 1)
    return -1;
  if (r->status == 100) {                    /* skip interim responses */
    memmove(c->buf, c->buf + hl, c->len - hl);
    c->len -= hl;
    return tc_read(c, r, no_body, timeout_ms);
  }
  if (tc_header(r, "Content-Length", v, sizeof(v)))
    cl = (size_t)_strtoui64(v, NULL, 10);
  if (no_body || r->status == 204 || r->status == 304)
    cl = 0;
  r->body = (char *)sd_alloc(cl + 1);
  if (r->body == NULL)
    return -1;
  while (c->len - hl < cl && c->len < sizeof(c->buf)) {
    if (fill(c, deadline) <= 0) { r->closed = 1; break; }
  }
  {
    size_t have = SD_MIN(c->len - hl, cl), got = have;
    memcpy(r->body, c->buf + hl, have);
    memmove(c->buf, c->buf + hl + have, c->len - hl - have);
    c->len -= hl + have;
    /* bodies larger than the buffer */
    while (got < cl) {
      int k;
      c->len = 0;
      k = fill(c, deadline);
      if (k <= 0) { r->closed = 1; break; }
      if ((size_t)k > cl - got) k = (int)(cl - got);
      memcpy(r->body + got, c->buf, (size_t)k);
      memmove(c->buf, c->buf + k, c->len - (size_t)k);
      c->len -= (size_t)k;
      got += (size_t)k;
    }
    r->body_n = got;
    r->body[got] = 0;
  }
  if (tc_header(r, "Connection", v, sizeof(v)) && _stricmp(v, "close") == 0)
    r->closed = 1;
  return 0;
}

void tc_resp_free(tc_resp *r)
{
  sd_free(r->body);
  r->body = NULL;
}

int tc_request(tc_conn *c, uint16_t port, const char *method, const char *path, const char *extra,
               const void *body, size_t body_n, tc_resp *r)
{
  enum { HEAD_CAP = 70000 };
  char *head = (char *)sd_alloc(HEAD_CAP);
  int n, rc;
  if (head == NULL)
    return -1;
  n = _snprintf_s(head, HEAD_CAP, _TRUNCATE, "%s %s HTTP/1.1\r\nHost: localhost:%u\r\n%sContent-Length: %u\r\n\r\n",
                      method, path, (unsigned)port, extra ? extra : "", (unsigned)body_n);
  memset(r, 0, sizeof(*r));
  rc = (n < 0 || tc_send(c, head, (size_t)n) != 0 || (body_n && tc_send(c, body, body_n) != 0)) ? -1 : 0;
  sd_free(head);
  if (rc != 0)
    return -1;
  return tc_read(c, r, strcmp(method, "HEAD") == 0, 20000);
}

int tc_authenticate(tc_conn *c, uint16_t port, const char *path)
{
  CredHandle cred;
  CtxtHandle ctx = { 0, 0 };
  TimeStamp exp;
  int have_ctx = 0, status = -1, round;
  typedef struct auth_bufs { char in_b64[16384]; uint8_t inbuf[12288], outbuf[16384]; char extra[24000], b64[22000]; } auth_bufs;
  auth_bufs *ab = (auth_bufs *)sd_alloc(sizeof(auth_bufs));
  char *in_b64;
  if (ab == NULL)
    return -1;
  in_b64 = ab->in_b64;
  if (AcquireCredentialsHandleW(NULL, L"Negotiate", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cred, &exp) != SEC_E_OK) {
    sd_free(ab);
    return -1;
  }
  in_b64[0] = 0;
  for (round = 0; round < 6; round++) {
    uint8_t *inbuf = ab->inbuf, *outbuf = ab->outbuf;
    size_t in_n = 0;
    SecBuffer ib, ob;
    SecBufferDesc ibd, obd;
    ULONG attrs = 0;
    SECURITY_STATUS ss;
    char *extra = ab->extra, *b64 = ab->b64;
    tc_resp r;
    if (in_b64[0] && wd_b64_decode(in_b64, strlen(in_b64), inbuf, sizeof(ab->inbuf), &in_n) != 0)
      break;
    ib.BufferType = SECBUFFER_TOKEN; ib.cbBuffer = (ULONG)in_n; ib.pvBuffer = inbuf;
    ibd.ulVersion = SECBUFFER_VERSION; ibd.cBuffers = 1; ibd.pBuffers = &ib;
    ob.BufferType = SECBUFFER_TOKEN; ob.cbBuffer = sizeof(ab->outbuf); ob.pvBuffer = outbuf;
    obd.ulVersion = SECBUFFER_VERSION; obd.cBuffers = 1; obd.pBuffers = &ob;
    ss = InitializeSecurityContextW(&cred, have_ctx ? &ctx : NULL, (SEC_WCHAR *)L"HTTP/localhost", ISC_REQ_CONNECTION,
                                    0, SECURITY_NATIVE_DREP, in_n ? &ibd : NULL, 0, &ctx, &obd, &attrs, &exp);
    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED)
      break;
    have_ctx = 1;
    if (ob.cbBuffer == 0)
      break;
    wd_b64_encode(outbuf, ob.cbBuffer, b64, sizeof(ab->b64));
    _snprintf_s(extra, sizeof(ab->extra), _TRUNCATE, "Authorization: Negotiate %s\r\nDepth: 0\r\n", b64);
    if (tc_request(c, port, "PROPFIND", path, extra, NULL, 0, &r) != 0)
      break;
    status = r.status;
    tc_resp_free(&r);
    if (status != 401) {
      break;
    }
    if (!tc_header(&r, "WWW-Authenticate", extra, sizeof(ab->extra)) || _strnicmp(extra, "Negotiate ", 10) != 0)
      break;
    strcpy_s(in_b64, sizeof(ab->in_b64), extra + 10);
  }
  if (have_ctx) DeleteSecurityContext(&ctx);
  FreeCredentialsHandle(&cred);
  sd_free(ab);
  return status;
}
