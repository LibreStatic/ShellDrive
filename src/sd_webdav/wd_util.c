/* sd_webdav: request-target decoding (TM-R12), Host/Destination checks, encodings and header values. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_platform.h"
#include "wd_proto.h"

static int hexval(int ch)
{
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

/* ---- request target ---- */

void wd_path_free(wd_path *p)
{
  sd_free(p->buf);
  memset(p, 0, sizeof(*p));
}

int wd_path_decode(const char *t, size_t n, wd_path *out)
{
  size_t i, o = 0, seg_start;
  char *buf;
  memset(out, 0, sizeof(*out));
  if (n == 0 || t[0] != '/')
    return 400;                            /* origin-form only (absolute-form only in Destination) */
  for (i = 0; i < n; i++) {
    if (t[i] == '?' || t[i] == '#')
      return 400;
  }
  buf = (char *)sd_alloc(n + 1);
  if (buf == NULL)
    return 500;
  out->buf = buf;
  i = 1;
  if (n == 1)
    return 0;                              /* "/" */
  for (;;) {
    size_t s = i, k;
    /* raw segment [s, e) */
    while (i < n && t[i] != '/')
      i++;
    if (i == s) {
      /* empty segment ("//"); a single trailing slash is handled after the segment */
      wd_path_free(out);
      return 400;
    }
    if (out->nseg >= WD_MAX_SEGMENTS) {
      wd_path_free(out);
      return 400;
    }
    seg_start = o;
    for (k = s; k < i; k++) {
      unsigned char c = (unsigned char)t[k];
      if (c == '%') {
        int h, l;
        if (k + 2 >= i) { wd_path_free(out); return 400; }
        h = hexval((unsigned char)t[k + 1]);
        l = hexval((unsigned char)t[k + 2]);
        if (h < 0 || l < 0) { wd_path_free(out); return 400; }
        c = (unsigned char)(h * 16 + l);
        k += 2;
      }
      if (c == '/' || c == '\\' || c == 0 || c < 0x20 || c == 0x7F) {
        wd_path_free(out);
        return 400;                        /* %2F, %5C, %00, controls */
      }
      buf[o++] = (char)c;
    }
    buf[o] = 0;
    if (!sd_utf8_valid(buf + seg_start, o - seg_start) ||
        strcmp(buf + seg_start, ".") == 0 || strcmp(buf + seg_start, "..") == 0) {
      wd_path_free(out);
      return 400;
    }
    out->seg[out->nseg++] = buf + seg_start;
    o++;
    if (i >= n)
      break;
    i++;                                   /* skip '/' */
    if (i == n) {
      out->trailing_slash = 1;
      break;
    }
  }
  return 0;
}

WCHAR *wd_path_to_vfs(const wd_path *p, uint32_t first)
{
  size_t total = 2, i;
  WCHAR *w, *o;
  for (i = first; i < p->nseg; i++) {
    size_t wl = 0;
    if (sd_utf8_to_utf16(p->seg[i], strlen(p->seg[i]), NULL, 0, &wl, SD_UTF_STRICT) != SD_OK && wl == 0)
      return NULL;
    total += wl + 1;
  }
  w = (WCHAR *)sd_alloc(total * sizeof(WCHAR));
  if (w == NULL)
    return NULL;
  o = w;
  if (first >= p->nseg) {
    *o++ = L'\\';
  }
  for (i = first; i < p->nseg; i++) {
    size_t wl = 0, len = strlen(p->seg[i]);
    *o++ = L'\\';
    if (sd_utf8_to_utf16(p->seg[i], len, o, total - (size_t)(o - w), &wl, SD_UTF_STRICT) != SD_OK) {
      sd_free(w);
      return NULL;
    }
    o += wl;
  }
  *o = 0;
  return w;
}

void wd_href_seg(wd_sb *b, const char *seg, size_t n)
{
  static const char hx[] = "0123456789ABCDEF";
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)seg[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
        c == '_' || c == '~') {
      wd_sb_add(b, &seg[i], 1);
    } else {
      char e[3];
      e[0] = '%';
      e[1] = hx[c >> 4];
      e[2] = hx[c & 15];
      wd_sb_add(b, e, 3);
    }
  }
}

int wd_is_token_seg(const char *s)
{
  size_t i;
  if (s[0] != 's' || s[1] != '-')
    return 0;
  for (i = 0; i < WD_TOKEN_CHARS; i++) {
    char c = s[2 + i];
    if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
      return 0;
  }
  return s[2 + WD_TOKEN_CHARS] == 0;
}

int wd_ct_equal(const char *a, const char *b, size_t n)
{
  volatile unsigned char d = 0;
  size_t i;
  for (i = 0; i < n; i++)
    d |= (unsigned char)(a[i] ^ b[i]);
  return d == 0;
}

/* ---- Host / Destination ---- */

int wd_host_ok(const char *v, size_t n, uint16_t port)
{
  static const char *const hosts[] = { "localhost", "127.0.0.1", "[::1]" };
  char want[32];
  size_t i, k;
  for (i = 0; i < SD_COUNTOF(hosts); i++) {
    int wl = _snprintf_s(want, sizeof(want), _TRUNCATE, "%s:%u", hosts[i], (unsigned)port);
    if (wl > 0 && (size_t)wl == n) {
      for (k = 0; k < n; k++) {
        char a = v[k], b = want[k];
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (a != b) break;
      }
      if (k == n)
        return 1;
    }
  }
  return 0;
}

int wd_destination_parse(const char *v, size_t n, const char *host, size_t host_n, wd_path *out)
{
  size_t i, auth_start, auth_end;
  memset(out, 0, sizeof(*out));
  if (n < 8 || !(wd_ieq(v, 7, "http://")))
    return 400;
  auth_start = 7;
  for (i = auth_start; i < n && v[i] != '/'; i++) {
    if (v[i] == '@' || v[i] == '?' || v[i] == '#')
      return 400;                          /* userinfo / query / fragment */
  }
  auth_end = i;
  if (auth_end == auth_start || i >= n)
    return 400;
  if (auth_end - auth_start != host_n)
    return 502;
  for (i = 0; i < host_n; i++) {
    char a = v[auth_start + i], b = host[i];
    if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
    if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
    if (a != b)
      return 502;
  }
  return wd_path_decode(v + auth_end, n - auth_end, out);
}

/* ---- base64 ---- */

static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t wd_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
  size_t i, o = 0;
  if (cap < ((n + 2) / 3) * 4 + 1)
    return 0;
  for (i = 0; i + 2 < n; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = k_b64[v >> 18];
    out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = k_b64[(v >> 6) & 63];
    out[o++] = k_b64[v & 63];
  }
  if (i < n) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
    out[o++] = k_b64[v >> 18];
    out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = i + 1 < n ? k_b64[(v >> 6) & 63] : '=';
    out[o++] = '=';
  }
  out[o] = 0;
  return o;
}

int wd_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_n)
{
  uint32_t acc = 0;
  int bits = 0, pad = 0;
  size_t i, o = 0;
  for (i = 0; i < n; i++) {
    const char *p;
    char c = in[i];
    if (c == '=') {
      pad++;
      continue;
    }
    if (pad)
      return -1;                           /* data after padding */
    p = c ? strchr(k_b64, c) : NULL;
    if (p == NULL)
      return -1;
    acc = (acc << 6) | (uint32_t)(p - k_b64);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= cap)
        return -1;
      out[o++] = (uint8_t)(acc >> bits);
      acc &= (1u << bits) - 1u;
    }
  }
  if (pad > 2 || ((n % 4) != 0 && pad))
    return -1;
  *out_n = o;
  return 0;
}

/* ---- randomness, tokens ---- */

int wd_random(void *p, size_t n)
{
  sd_pfn_RtlGenRandom gen = (sd_pfn_RtlGenRandom)sd_platform_resolve(SD_API_RtlGenRandom);
  if (gen == NULL || n > 0xFFFFFFFFu || !gen(p, (ULONG)n))
    return -1;
  return 0;
}

int wd_make_token(char out[WD_TOKEN_CHARS + 1])
{
  static const char a32[] = "abcdefghijklmnopqrstuvwxyz234567";
  uint8_t r[17];
  uint32_t i, bit = 0;
  if (wd_random(r, sizeof(r)) != 0)
    return -1;
  for (i = 0; i < WD_TOKEN_CHARS; i++) {   /* 26 x 5 = 130 bits */
    uint32_t v = 0, k;
    for (k = 0; k < 5; k++, bit++)
      v = (v << 1) | ((r[bit >> 3] >> (7 - (bit & 7))) & 1u);
    out[i] = a32[v];
  }
  out[WD_TOKEN_CHARS] = 0;
  SecureZeroMemory(r, sizeof(r));
  return 0;
}

void wd_uuid(char out[37])
{
  uint8_t r[16];
  if (wd_random(r, sizeof(r)) != 0) {
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    memset(r, 0, sizeof(r));
    memcpy(r, &c, sizeof(c));
  }
  r[6] = (uint8_t)((r[6] & 0x0F) | 0x40);
  r[8] = (uint8_t)((r[8] & 0x3F) | 0x80);
  _snprintf_s(out, 37, _TRUNCATE, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
}

/* ---- dates ---- */

static const char *const k_wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *const k_mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static void to_systime(uint64_t ft, SYSTEMTIME *st)
{
  FILETIME f;
  f.dwLowDateTime = (DWORD)ft;
  f.dwHighDateTime = (DWORD)(ft >> 32);
  if (!FileTimeToSystemTime(&f, st))
    memset(st, 0, sizeof(*st));
  if (st->wYear < 1601) {
    memset(st, 0, sizeof(*st));
    st->wYear = 1970; st->wMonth = 1; st->wDay = 1; st->wDayOfWeek = 4;
  }
}

void wd_rfc1123(uint64_t ft, char out[32])
{
  SYSTEMTIME st;
  to_systime(ft, &st);
  _snprintf_s(out, 32, _TRUNCATE, "%s, %02u %s %04u %02u:%02u:%02u GMT", k_wday[st.wDayOfWeek % 7],
              st.wDay, k_mon[(st.wMonth + 11) % 12], st.wYear, st.wHour, st.wMinute, st.wSecond);
}

void wd_rfc3339(uint64_t ft, char out[32])
{
  SYSTEMTIME st;
  to_systime(ft, &st);
  _snprintf_s(out, 32, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour,
              st.wMinute, st.wSecond);
}

static int num(const char *s, size_t n, size_t *i, uint32_t digits, uint32_t *v)
{
  uint32_t k, x = 0;
  for (k = 0; k < digits; k++) {
    if (*i >= n || s[*i] < '0' || s[*i] > '9')
      return -1;
    x = x * 10u + (uint32_t)(s[(*i)++] - '0');
  }
  *v = x;
  return 0;
}

int wd_parse_rfc1123(const char *s, size_t n, uint64_t *filetime)
{
  SYSTEMTIME st;
  FILETIME f;
  size_t i = 0;
  uint32_t d, y, h, mi, se, m;
  memset(&st, 0, sizeof(st));
  while (i < n && s[i] != ',') i++;        /* weekday is not checked */
  if (i >= n) return -1;
  i++;
  while (i < n && s[i] == ' ') i++;
  if (num(s, n, &i, 2, &d) != 0) {
    i--;                                   /* allow a one-digit day */
    if (num(s, n, &i, 1, &d) != 0) return -1;
  }
  if (i + 5 > n || s[i] != ' ') return -1;
  i++;
  for (m = 0; m < 12; m++)
    if (memcmp(s + i, k_mon[m], 3) == 0) break;
  if (m == 12) return -1;
  i += 3;
  if (i >= n || s[i++] != ' ') return -1;
  if (num(s, n, &i, 4, &y) != 0) return -1;
  if (i >= n || s[i++] != ' ') return -1;
  if (num(s, n, &i, 2, &h) != 0 || i >= n || s[i++] != ':') return -1;
  if (num(s, n, &i, 2, &mi) != 0 || i >= n || s[i++] != ':') return -1;
  if (num(s, n, &i, 2, &se) != 0) return -1;
  while (i < n && s[i] == ' ') i++;
  if (!(n - i == 3 && memcmp(s + i, "GMT", 3) == 0) && !(n - i == 3 && memcmp(s + i, "UTC", 3) == 0))
    return -1;
  if (d < 1 || d > 31 || h > 23 || mi > 59 || se > 60 || y < 1601 || y > 30827)
    return -1;
  st.wYear = (WORD)y; st.wMonth = (WORD)(m + 1); st.wDay = (WORD)d;
  st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)(se == 60 ? 59 : se);
  if (!SystemTimeToFileTime(&st, &f))
    return -1;
  *filetime = ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime;
  return 0;
}

/* ---- Range, Timeout, If ---- */

static int parse_u64(const char *s, size_t a, size_t b, uint64_t *v)
{
  uint64_t x = 0;
  size_t i;
  if (a >= b || b - a > 19)
    return -1;
  for (i = a; i < b; i++) {
    if (s[i] < '0' || s[i] > '9')
      return -1;
    x = x * 10u + (uint64_t)(s[i] - '0');
  }
  *v = x;
  return 0;
}

int wd_range_parse(const char *v, size_t n, uint64_t size, uint64_t *first, uint64_t *last)
{
  size_t i, dash = 0, s = 6, e = n;
  uint64_t a, b;
  if (n < 7 || !wd_ieq(v, 6, "bytes="))
    return 0;
  for (i = s; i < n; i++) {
    if (v[i] == ',') return 0;             /* multi-range: send the whole entity */
    if (v[i] == '-' && !dash) dash = i;
  }
  while (s < e && v[s] == ' ') s++;
  while (e > s && v[e - 1] == ' ') e--;
  if (!dash || dash < s || dash >= e + 1)
    return 0;
  if (dash == s) {                         /* suffix: -n */
    if (parse_u64(v, dash + 1, e, &b) != 0) return 0;
    if (b == 0 || size == 0) return 416;
    *first = b >= size ? 0 : size - b;
    *last = size - 1;
    return 1;
  }
  if (parse_u64(v, s, dash, &a) != 0) return 0;
  if (dash + 1 == e) {
    b = size ? size - 1 : 0;
  } else {
    if (parse_u64(v, dash + 1, e, &b) != 0 || b < a) return 0;
    if (size && b >= size) b = size - 1;
  }
  if (a >= size)
    return 416;
  *first = a;
  *last = b;
  return 1;
}

uint32_t wd_timeout_parse(const char *v, size_t n)
{
  size_t i = 0;
  while (i < n) {
    size_t s, e;
    while (i < n && (v[i] == ' ' || v[i] == ',')) i++;
    s = i;
    while (i < n && v[i] != ',') i++;
    e = i;
    while (e > s && v[e - 1] == ' ') e--;
    if (e - s >= 8 && wd_ieq(v + s, 7, "Second-")) {
      uint64_t x;
      if (parse_u64(v, s + 7, e, &x) == 0 && x > 0)
        return x > 3600 ? 3600u : (uint32_t)x;
    } else if (wd_ieq(v + s, e - s, "Infinite")) {
      return 3600u;
    }
  }
  return 3600u;
}

uint32_t wd_if_tokens(const char *v, size_t n, char tokens[][80], uint32_t max)
{
  size_t i;
  int depth = 0;
  uint32_t c = 0;
  for (i = 0; i < n; i++) {
    if (v[i] == '(') depth++;
    else if (v[i] == ')') depth = depth ? depth - 1 : 0;
    else if (v[i] == '<') {
      size_t s = i + 1, e = s;
      while (e < n && v[e] != '>') e++;
      if (e >= n) break;
      if (depth > 0 && e - s < 80 && c < max && e - s > 16 && memcmp(v + s, "opaquelocktoken:", 16) == 0) {
        memcpy(tokens[c], v + s, e - s);
        tokens[c][e - s] = 0;
        c++;
      }
      i = e;
    }
  }
  return c;
}
