/* sd_webdav: buffer, HTTP/1.1 request head parser and chunked decoder (02 §7.3, §7.5; TM-R20). */
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "wd_proto.h"

/* ---- wd_sb ---- */

void wd_sb_init(wd_sb *b, size_t max)
{
  memset(b, 0, sizeof(*b));
  b->max = max ? max : (64u << 20);
}

void wd_sb_free(wd_sb *b)
{
  sd_free(b->p);
  memset(b, 0, sizeof(*b));
}

void wd_sb_add(wd_sb *b, const void *p, size_t n)
{
  if (b->oom || n == 0)
    return;
  if (b->n + n + 1 > b->cap) {
    size_t nc = b->cap ? b->cap : 256;
    char *np;
    while (nc < b->n + n + 1) {
      if (nc > b->max) break;
      nc *= 2;
    }
    if (b->n + n + 1 > b->max + 1) {
      b->oom = 1;
      return;
    }
    if (nc > b->max + 1) nc = b->max + 1;
    np = (char *)sd_realloc(b->p, nc);
    if (np == NULL) {
      b->oom = 1;
      return;
    }
    b->p = np;
    b->cap = nc;
  }
  memcpy(b->p + b->n, p, n);
  b->n += n;
  b->p[b->n] = 0;
}

void wd_sb_str(wd_sb *b, const char *s)
{
  wd_sb_add(b, s, strlen(s));
}

void wd_sb_fmt(wd_sb *b, const char *fmt, ...)
{
  char tmp[1024];
  int k;
  va_list ap;
  va_start(ap, fmt);
  k = _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);
  va_end(ap);
  if (k < 0) {
    b->oom = 1;
    return;
  }
  wd_sb_add(b, tmp, (size_t)k);
}

void wd_sb_xml(wd_sb *b, const char *s, size_t n)
{
  size_t i, run = 0;
  for (i = 0; i < n; i++) {
    const char *rep = NULL;
    switch (s[i]) {
    case '<': rep = "&lt;"; break;
    case '>': rep = "&gt;"; break;
    case '&': rep = "&amp;"; break;
    case '"': rep = "&quot;"; break;
    case '\'': rep = "&apos;"; break;
    default: break;
    }
    if (rep) {
      wd_sb_add(b, s + run, i - run);
      wd_sb_str(b, rep);
      run = i + 1;
    }
  }
  wd_sb_add(b, s + run, n - run);
}

/* ---- helpers ---- */

static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

int wd_ieq(const char *a, size_t an, const char *b)
{
  size_t i;
  for (i = 0; i < an; i++) {
    if (b[i] == 0 || lower((unsigned char)a[i]) != lower((unsigned char)b[i]))
      return 0;
  }
  return b[an] == 0;
}

static int is_tchar(int c)
{
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
    return 1;
  return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

const wd_hdr *wd_req_header(const wd_req *r, const char *name, uint32_t *count)
{
  const wd_hdr *first = NULL;
  uint32_t i, c = 0;
  for (i = 0; i < r->nh; i++) {
    if (wd_ieq(r->h[i].name, r->h[i].nlen, name)) {
      if (!first) first = &r->h[i];
      c++;
    }
  }
  if (count) *count = c;
  return first;
}

int wd_req_has_prefix_header(const wd_req *r, const char *prefix)
{
  size_t pl = strlen(prefix);
  uint32_t i, k;
  for (i = 0; i < r->nh; i++) {
    if (r->h[i].nlen < pl)
      continue;
    for (k = 0; k < pl; k++)
      if (lower((unsigned char)r->h[i].name[k]) != lower((unsigned char)prefix[k]))
        break;
    if (k == pl)
      return 1;
  }
  return 0;
}

/* Does a comma-separated header value contain the token (case-insensitive)? */
static int list_has(const char *v, uint32_t n, const char *tok)
{
  uint32_t i = 0;
  while (i < n) {
    uint32_t s, e;
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ','))
      i++;
    s = i;
    while (i < n && v[i] != ',')
      i++;
    e = i;
    while (e > s && (v[e - 1] == ' ' || v[e - 1] == '\t'))
      e--;
    if (e > s && wd_ieq(v + s, e - s, tok))
      return 1;
  }
  return 0;
}

static int parse_u64_dec(const char *v, uint32_t n, uint64_t *out)
{
  uint64_t x = 0;
  uint32_t i;
  if (n == 0 || n > 19)
    return -1;
  for (i = 0; i < n; i++) {
    if (v[i] < '0' || v[i] > '9')
      return -1;
    x = x * 10u + (uint64_t)(v[i] - '0');
  }
  *out = x;
  return 0;
}

/* ---- head parser ---- */

int wd_http_parse_head(const char *buf, size_t len, wd_req *r, int *status)
{
  size_t pos = 0, line_end, i, sp1, sp2;
  const char *line;
  uint32_t te_count = 0, cl_count = 0;
  *status = 400;
  memset(r, 0, sizeof(*r));
  /* RFC 9112 §2.2: ignore at least one empty line before the request line. */
  while (pos + 1 < len && buf[pos] == '\r' && buf[pos + 1] == '\n' && pos < 8)
    pos += 2;
  /* request line */
  for (i = pos; i < len && buf[i] != '\n'; i++) {
    if (i - pos >= WD_MAX_REQUEST_LINE) {
      *status = 414;
      return WD_PARSE_ERROR;
    }
  }
  if (i >= len) {
    if (len - pos >= WD_MAX_REQUEST_LINE) { *status = 414; return WD_PARSE_ERROR; }
    return WD_PARSE_MORE;
  }
  if (i == pos || buf[i - 1] != '\r')
    return WD_PARSE_ERROR;                 /* bare LF */
  line = buf + pos;
  line_end = i - 1 - pos;
  for (sp1 = 0; sp1 < line_end && line[sp1] != ' '; sp1++)
    if (!is_tchar((unsigned char)line[sp1])) return WD_PARSE_ERROR;
  if (sp1 == 0 || sp1 >= line_end || sp1 >= sizeof(r->method))
    return sp1 >= sizeof(r->method) ? (*status = 501, WD_PARSE_ERROR) : WD_PARSE_ERROR;
  memcpy(r->method, line, sp1);
  r->method[sp1] = 0;
  for (sp2 = sp1 + 1; sp2 < line_end && line[sp2] != ' '; sp2++) {
    unsigned char c = (unsigned char)line[sp2];
    if (c <= 0x20 || c >= 0x7F) return WD_PARSE_ERROR;
  }
  if (sp2 == sp1 + 1 || sp2 >= line_end)
    return WD_PARSE_ERROR;
  r->target = line + sp1 + 1;
  r->tlen = (uint32_t)(sp2 - sp1 - 1);
  if (line_end - sp2 - 1 != 8 || memcmp(line + sp2 + 1, "HTTP/1.", 7) != 0) {
    if (line_end - sp2 - 1 == 8 && memcmp(line + sp2 + 1, "HTTP/", 5) == 0) {
      *status = 505;
    }
    return WD_PARSE_ERROR;
  }
  if (line[sp2 + 8] != '0' && line[sp2 + 8] != '1') {
    *status = 505;
    return WD_PARSE_ERROR;
  }
  r->minor = line[sp2 + 8] - '0';
  pos = i + 1;
  /* header fields */
  for (;;) {
    size_t s = pos, colon, vs, ve;
    for (i = pos; i < len && buf[i] != '\n'; i++) {
      if (i >= WD_MAX_HEAD) { *status = 431; return WD_PARSE_ERROR; }
    }
    if (i >= len) {
      if (len >= WD_MAX_HEAD) { *status = 431; return WD_PARSE_ERROR; }
      return WD_PARSE_MORE;
    }
    if (i >= WD_MAX_HEAD) { *status = 431; return WD_PARSE_ERROR; }
    if (i == s || buf[i - 1] != '\r')
      return WD_PARSE_ERROR;
    if (i - 1 == s) {                       /* empty line: end of head */
      r->head_len = i + 1;
      break;
    }
    if (buf[s] == ' ' || buf[s] == '\t')
      return WD_PARSE_ERROR;               /* obsolete line folding */
    if (r->nh >= WD_MAX_HEADERS) { *status = 431; return WD_PARSE_ERROR; }
    for (colon = s; colon < i - 1 && buf[colon] != ':'; colon++)
      if (!is_tchar((unsigned char)buf[colon])) return WD_PARSE_ERROR;
    if (colon == s || colon >= i - 1)
      return WD_PARSE_ERROR;
    vs = colon + 1;
    ve = i - 1;
    while (vs < ve && (buf[vs] == ' ' || buf[vs] == '\t')) vs++;
    while (ve > vs && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t')) ve--;
    for (pos = vs; pos < ve; pos++) {
      unsigned char c = (unsigned char)buf[pos];
      if ((c < 0x20 && c != '\t') || c == 0x7F) return WD_PARSE_ERROR;
    }
    r->h[r->nh].name = buf + s;
    r->h[r->nh].nlen = (uint32_t)(colon - s);
    r->h[r->nh].val = buf + vs;
    r->h[r->nh].vlen = (uint32_t)(ve - vs);
    r->nh++;
    pos = i + 1;
  }
  /* framing (RFC 9112 §6) */
  for (i = 0; i < r->nh; i++) {
    const wd_hdr *h = &r->h[i];
    if (wd_ieq(h->name, h->nlen, "Content-Length")) {
      uint64_t v;
      if (parse_u64_dec(h->val, h->vlen, &v) != 0) return WD_PARSE_ERROR;
      if (cl_count++ && v != r->length) return WD_PARSE_ERROR;
      r->has_length = 1;
      r->length = v;
    } else if (wd_ieq(h->name, h->nlen, "Transfer-Encoding")) {
      te_count++;
      if (!wd_ieq(h->val, h->vlen, "chunked")) { *status = 501; return WD_PARSE_ERROR; }
      r->chunked = 1;
    } else if (wd_ieq(h->name, h->nlen, "Connection")) {
      if (list_has(h->val, h->vlen, "close")) r->close = 1;
      if (r->minor == 0 && list_has(h->val, h->vlen, "keep-alive")) r->close = -1;
    } else if (wd_ieq(h->name, h->nlen, "Expect")) {
      if (!wd_ieq(h->val, h->vlen, "100-continue")) { *status = 417; return WD_PARSE_ERROR; }
      r->expect_continue = 1;
    }
  }
  if (te_count > 1 || (r->chunked && r->has_length))
    return WD_PARSE_ERROR;                 /* request smuggling shapes */
  if (r->minor == 0)
    r->close = r->close == -1 ? 0 : 1;
  else if (r->close < 0)
    r->close = 0;
  return WD_PARSE_DONE;
}

const char *wd_status_text(int status)
{
  switch (status) {
  case 100: return "Continue";
  case 200: return "OK";
  case 201: return "Created";
  case 204: return "No Content";
  case 206: return "Partial Content";
  case 207: return "Multi-Status";
  case 304: return "Not Modified";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 409: return "Conflict";
  case 411: return "Length Required";
  case 412: return "Precondition Failed";
  case 413: return "Content Too Large";
  case 414: return "URI Too Long";
  case 415: return "Unsupported Media Type";
  case 416: return "Range Not Satisfiable";
  case 417: return "Expectation Failed";
  case 423: return "Locked";
  case 424: return "Failed Dependency";
  case 431: return "Request Header Fields Too Large";
  case 500: return "Internal Server Error";
  case 501: return "Not Implemented";
  case 502: return "Bad Gateway";
  case 503: return "Service Unavailable";
  case 504: return "Gateway Timeout";
  case 505: return "HTTP Version Not Supported";
  case 507: return "Insufficient Storage";
  default:  return "Unknown";
  }
}

/* ---- chunked decoding ---- */

enum { CH_SIZE, CH_EXT, CH_SIZE_LF, CH_DATA, CH_DATA_CR, CH_DATA_LF, CH_TRAILER, CH_TRAILER_LF, CH_DONE };

void wd_chunked_init(wd_chunked *c)
{
  memset(c, 0, sizeof(*c));
  c->state = CH_SIZE;
}

static int hexval(int ch)
{
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

int wd_chunked_feed(wd_chunked *c, const char *in, size_t n, size_t *used, const char **data, size_t *data_n)
{
  size_t i = 0;
  *data = NULL;
  *data_n = 0;
  while (i < n && c->state != CH_DONE) {
    char ch = in[i];
    switch (c->state) {
    case CH_SIZE: {
      int hv = hexval((unsigned char)ch);
      if (++c->linelen > WD_MAX_CHUNK_LINE) return -1;
      if (hv >= 0) {
        if (c->left > (UINT64_MAX >> 4) || c->linelen > 16) return -1;
        c->left = (c->left << 4) | (uint64_t)hv;
      } else if (c->linelen == 1) {
        return -1;                         /* no digits */
      } else if (ch == ';' || ch == ' ' || ch == '\t') {
        c->state = CH_EXT;
      } else if (ch == '\r') {
        c->state = CH_SIZE_LF;
      } else {
        return -1;
      }
      i++;
      break;
    }
    case CH_EXT:
      if (++c->linelen > WD_MAX_CHUNK_LINE) return -1;
      if (ch == '\r') c->state = CH_SIZE_LF;
      else if ((unsigned char)ch < 0x20 && ch != '\t') return -1;
      i++;
      break;
    case CH_SIZE_LF:
      if (ch != '\n') return -1;
      i++;
      c->linelen = 0;
      c->state = c->left ? CH_DATA : CH_TRAILER;
      break;
    case CH_DATA: {
      size_t take = n - i;
      if ((uint64_t)take > c->left) take = (size_t)c->left;
      *data = in + i;
      *data_n = take;
      c->left -= take;
      i += take;
      if (c->left == 0) c->state = CH_DATA_CR;
      *used = i;
      return 0;                            /* one data slice per call */
    }
    case CH_DATA_CR:
      if (ch != '\r') return -1;
      c->state = CH_DATA_LF;
      i++;
      break;
    case CH_DATA_LF:
      if (ch != '\n') return -1;
      c->state = CH_SIZE;
      c->linelen = 0;
      i++;
      break;
    case CH_TRAILER:                       /* trailer fields are skipped, bounded */
      if (++c->trailer_bytes > 8192) return -1;
      if (ch == '\r') {
        c->state = CH_TRAILER_LF;
      } else {
        c->linelen++;
      }
      i++;
      break;
    case CH_TRAILER_LF:
      if (ch != '\n') return -1;
      i++;
      if (c->linelen == 0) {
        c->state = CH_DONE;
        c->done = 1;
      } else {
        c->linelen = 0;
        c->state = CH_TRAILER;
      }
      break;
    default:
      return -1;
    }
  }
  *used = i;
  return 0;
}
