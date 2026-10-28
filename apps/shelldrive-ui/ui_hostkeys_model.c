/* shelldrive-ui: rows of the host key manager (03 §5.1, §5.6). See ui_hostkeys_model.h.
 *
 * Pure: no window or process calls. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "ui_hostkeys_model.h"

#define UI_HK_DEFAULT_PORT 22u

static void put_ascii(wchar_t *dst, size_t cap, const char *src)
{
  size_t i;
  if (cap == 0)
    return;
  for (i = 0; i + 1 < cap && src != NULL && src[i] != '\0'; i++)
    dst[i] = (src[i] >= 0x20 && src[i] < 0x7f) ? (wchar_t)(unsigned char)src[i] : L'?';
  dst[i] = L'\0';
}

static void put_wide(wchar_t *dst, size_t cap, const wchar_t *src)
{
  if (cap == 0)
    return;
  if (src == NULL)
    src = L"";
  wcsncpy_s(dst, cap, src, _TRUNCATE);
}

static int is_digit(char c)
{
  return c >= '0' && c <= '9';
}

/* "[host]:port" with a port 1..65535. */
static int parse_bracketed(const char *p, char *host, size_t host_cap, unsigned *port)
{
  const char *close = strchr(p, ']');
  size_t hl, i;
  unsigned long v = 0;
  if (p[0] != '[' || close == NULL)
    return 0;
  hl = (size_t)(close - (p + 1));
  if (hl == 0 || hl + 1 > host_cap || close[1] != ':' || !is_digit(close[2]))
    return 0;
  for (i = 2; close[i] != '\0'; i++) {
    if (!is_digit(close[i]) || v > 65535)
      return 0;
    v = v * 10u + (unsigned long)(close[i] - '0');
  }
  if (v == 0 || v > 65535)
    return 0;
  memcpy(host, p + 1, hl);
  host[hl] = '\0';
  *port = (unsigned)v;
  return 1;
}

sd_err ui_hk_row_init(ui_hk_row *row, ui_hk_store store, const char *pattern, int hashed, const char *type,
                      const char *fp, uint32_t line)
{
  size_t pl;
  if (row == NULL || pattern == NULL || type == NULL || fp == NULL)
    return SD_E_INVALID_PARAM;
  if (store != UI_HK_STORE_MACHINE && store != UI_HK_STORE_USER)
    return SD_E_INVALID_PARAM;
  pl = strlen(pattern);
  if (pl == 0 || pl >= UI_HK_HOST_MAX || strlen(type) >= UI_HK_TYPE_MAX || strlen(fp) >= UI_HK_FP_MAX)
    return SD_E_INVALID_PARAM;

  memset(row, 0, sizeof(*row));
  row->store = store;
  row->line = line;
  row->hashed = hashed ? 1 : 0;
  strcpy_s(row->type, sizeof(row->type), type);
  strcpy_s(row->fp, sizeof(row->fp), fp);
  strcpy_s(row->pattern, sizeof(row->pattern), pattern);
  row->port = UI_HK_DEFAULT_PORT;

  if (row->hashed || pattern[0] == '|') {
    row->hashed = 1;
    return SD_OK;
  }
  if (strchr(pattern, ',') != NULL || strchr(pattern, '*') != NULL || strchr(pattern, '?') != NULL ||
      strchr(pattern, '!') != NULL) {
    /* a list or a wildcard: shown as written, removed only through the file editor */
    strcpy_s(row->host, sizeof(row->host), pattern);
    return SD_OK;
  }
  if (pattern[0] == '[') {
    if (!parse_bracketed(pattern, row->host, sizeof(row->host), &row->port))
      return SD_OK;                       /* malformed: shown as written, not removable */
    strcpy_s(row->lookup, sizeof(row->lookup), pattern);
    row->removable = 1;
    return SD_OK;
  }
  strcpy_s(row->host, sizeof(row->host), pattern);
  strcpy_s(row->lookup, sizeof(row->lookup), pattern);
  row->removable = 1;
  return SD_OK;
}

void ui_hk_row_cells(const ui_hk_row *row, const wchar_t *hashed_text, const wchar_t *machine_text,
                     const wchar_t *user_text, wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX])
{
  memset(cells, 0, sizeof(wchar_t) * UI_HK_CELLS * UI_HK_CELL_MAX);
  if (row->hashed) {
    put_wide(cells[0], UI_HK_CELL_MAX, hashed_text);
    cells[1][0] = L'\0';
  } else {
    put_ascii(cells[0], UI_HK_CELL_MAX, row->host);
    swprintf_s(cells[1], UI_HK_CELL_MAX, L"%u", row->port);
  }
  put_ascii(cells[2], UI_HK_CELL_MAX, row->type);
  put_ascii(cells[3], UI_HK_CELL_MAX, row->fp);
  put_wide(cells[4], UI_HK_CELL_MAX, row->store == UI_HK_STORE_MACHINE ? machine_text : user_text);
}

void ui_hk_announce_cells(const char *host, int action, const char *type, const char *fp,
                          const wchar_t *add_text, const wchar_t *remove_text,
                          wchar_t cells[4][UI_HK_CELL_MAX])
{
  memset(cells, 0, sizeof(wchar_t) * 4 * UI_HK_CELL_MAX);
  put_ascii(cells[0], UI_HK_CELL_MAX, host);
  put_wide(cells[1], UI_HK_CELL_MAX, action ? add_text : remove_text);
  put_ascii(cells[2], UI_HK_CELL_MAX, type);
  put_ascii(cells[3], UI_HK_CELL_MAX, fp);
}

/* ---- "Add key from server..." ---- */

static int host_char_ok(char c, int v6)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '-' || c == '.' || c == '_' ||
         (v6 && c == ':');
}

/* Parses a port: 1..65535, digits only. */
static int parse_port(const char *s, unsigned *port)
{
  unsigned long v = 0;
  size_t i;
  if (s[0] == '\0' || strlen(s) > 5)
    return 0;
  for (i = 0; s[i] != '\0'; i++) {
    if (!is_digit(s[i]))
      return 0;
    v = v * 10 + (unsigned long)(s[i] - '0');
  }
  if (v < 1 || v > 65535)
    return 0;
  *port = (unsigned)v;
  return 1;
}

int ui_hk_target_parse(const char *spec, ui_hk_target *t)
{
  char buf[UI_HK_HOST_MAX + 16];
  char *p, *end, *colon;
  size_t n, i, ncolon = 0;
  int v6 = 0;
  unsigned port = UI_HK_DEFAULT_PORT;
  if (t != NULL)
    memset(t, 0, sizeof(*t));
  if (spec == NULL || t == NULL)
    return 0;
  while (*spec == ' ' || *spec == '\t')
    spec++;
  n = strlen(spec);
  while (n > 0 && (spec[n - 1] == ' ' || spec[n - 1] == '\t'))
    n--;
  if (n == 0 || n >= sizeof(buf))
    return 0;
  memcpy(buf, spec, n);
  buf[n] = '\0';
  p = buf;
  end = buf + n;
  if (p[0] == '[') {
    char *close = strchr(p, ']');
    if (close == NULL || close == p + 1)
      return 0;
    *close = '\0';
    if (close[1] == ':') {
      if (!parse_port(close + 2, &port))
        return 0;
    } else if (close + 1 != end) {
      return 0;
    }
    p++;
    v6 = 1;
  } else {
    for (i = 0; p[i] != '\0'; i++)
      if (p[i] == ':')
        ncolon++;
    if (ncolon == 1) {
      colon = strchr(p, ':');
      *colon = '\0';
      if (!parse_port(colon + 1, &port))
        return 0;
    } else if (ncolon > 1) {
      v6 = 1;                          /* a bare IPv6 address: no port */
    }
  }
  n = strlen(p);
  if (n == 0 || n >= UI_HK_HOST_MAX)
    return 0;
  for (i = 0; i < n; i++) {
    if (!host_char_ok(p[i], v6))
      return 0;
    t->host[i] = (p[i] >= 'A' && p[i] <= 'Z') ? (char)(p[i] - 'A' + 'a') : p[i];
  }
  t->host[n] = '\0';
  if (t->host[0] == '.' || t->host[0] == '-')
    return 0;
  t->port = port;
  if (port == UI_HK_DEFAULT_PORT)
    strcpy_s(t->lookup, sizeof(t->lookup), t->host);
  else
    sprintf_s(t->lookup, sizeof(t->lookup), "[%s]:%u", t->host, port);
  return 1;
}

int ui_hk_type_ok(const char *type)
{
  size_t i, n;
  if (type == NULL)
    return 0;
  n = strlen(type);
  if (n == 0 || n >= 64)
    return 0;
  for (i = 0; i < n; i++) {
    char c = type[i];
    if (!((c >= 'a' && c <= 'z') || is_digit(c) || c == '-' || c == '@' || c == '.'))
      return 0;
  }
  return 1;
}

sd_err ui_hk_add_params(const ui_hk_target *t, const char *type, char *out, size_t cap)
{
  int n;
  if (out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  out[0] = '\0';
  if (t == NULL || t->host[0] == '\0' || t->lookup[0] == '\0' || t->port < 1 || t->port > 65535)
    return SD_E_INVALID_PARAM;
  /* host and lookup hold letters, digits and "-._:[]" only (ui_hk_target_parse), so no JSON escaping is needed */
  if (type != NULL && type[0] != '\0') {
    if (!ui_hk_type_ok(type))
      return SD_E_INVALID_PARAM;
    n = _snprintf_s(out, cap, _TRUNCATE, "{\"host\":\"%s\",\"port\":%u,\"lookup\":\"%s\",\"type\":\"%s\"}", t->host,
                    t->port, t->lookup, type);
  } else {
    n = _snprintf_s(out, cap, _TRUNCATE, "{\"host\":\"%s\",\"port\":%u,\"lookup\":\"%s\"}", t->host, t->port,
                    t->lookup);
  }
  if (n < 0) {
    out[0] = '\0';
    return SD_E_INVALID_PARAM;
  }
  return SD_OK;
}

int ui_hk_id_ok(const char *id)
{
  size_t i, n;
  if (id == NULL)
    return 0;
  n = strlen(id);
  if (n == 0 || n >= UI_HK_ID_MAX)
    return 0;
  for (i = 0; i < n; i++) {
    char c = id[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '-' || c == '_' || c == '.'))
      return 0;
  }
  return 1;
}

/* Copies s as printable ASCII, a bad character becomes '?'; cut at cap - 1. */
static void copy_printable(char *dst, size_t cap, const char *s)
{
  size_t i;
  for (i = 0; i + 1 < cap && s != NULL && s[i] != '\0'; i++)
    dst[i] = (s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : '?';
  dst[i] = '\0';
}

sd_err ui_hk_offer_parse(const sd_json *reply, ui_hk_offer *o)
{
  const sd_json *keys;
  const char *id, *host;
  size_t i, n;
  int verified = 0;
  if (o != NULL)
    memset(o, 0, sizeof(*o));
  if (o == NULL || reply == NULL || sd_json_type_of(reply) != SD_JSON_OBJECT)
    return SD_E_INVALID_PARAM;
  host = sd_json_get_str(reply, "host");
  copy_printable(o->host, sizeof(o->host), host ? host : "");
  sd_json_get_bool(reply, "verified", &verified);
  o->verified = verified != 0;
  id = sd_json_get_str(reply, "id");
  if (!ui_hk_id_ok(id))
    return SD_OK;                        /* nothing was kept: no offer */
  keys = sd_json_get(reply, "keys");
  n = sd_json_count(keys);
  for (i = 0; i < n && o->nkeys < UI_HK_OFFER_KEYS; i++) {
    const sd_json *k = sd_json_at(keys, i);
    const char *type = sd_json_get_str(k, "type");
    const char *fp = sd_json_get_str(k, "fingerprint");
    if (type == NULL || fp == NULL || type[0] == '\0' || fp[0] == '\0')
      continue;
    copy_printable(o->keys[o->nkeys].type, sizeof(o->keys[0].type), type);
    copy_printable(o->keys[o->nkeys].fp, sizeof(o->keys[0].fp), fp);
    o->nkeys++;
  }
  if (o->nkeys > 0)
    strcpy_s(o->id, sizeof(o->id), id);
  return SD_OK;
}

void ui_hk_offer_lines(const ui_hk_offer *o, wchar_t *out, size_t cap)
{
  size_t i, len = 0;
  if (out == NULL || cap == 0)
    return;
  out[0] = L'\0';
  if (o == NULL)
    return;
  for (i = 0; i < o->nkeys; i++) {
    wchar_t line[UI_HK_TYPE_MAX + UI_HK_FP_MAX + 8];
    size_t ll;
    put_ascii(line, SD_COUNTOF(line), o->keys[i].type);
    wcscat_s(line, SD_COUNTOF(line), L"  ");
    ll = wcslen(line);
    put_ascii(line + ll, SD_COUNTOF(line) - ll, o->keys[i].fp);
    ll = wcslen(line);
    if (len + ll + 3 > cap)
      break;
    if (i > 0) {
      out[len++] = L'\r';
      out[len++] = L'\n';
    }
    memcpy(out + len, line, ll * sizeof(wchar_t));
    len += ll;
    out[len] = L'\0';
  }
}

ui_hk_add_fail ui_hk_add_fail_of(sd_err e)
{
  switch (e) {
  case SD_E_DISCONNECTED:
  case SD_E_SHUTDOWN:
    return UI_HK_ADD_FAIL_AGENT_DOWN;
  case SD_E_UNSUPPORTED:
    return UI_HK_ADD_FAIL_UNSUPPORTED;
  case SD_E_HOSTKEY_MISMATCH:
    return UI_HK_ADD_FAIL_MISMATCH;
  case SD_E_HOSTKEY_REJECTED:
    return UI_HK_ADD_FAIL_REJECTED;
  case SD_E_BUSY:
    return UI_HK_ADD_FAIL_BUSY;
  default:
    return UI_HK_ADD_FAIL_OTHER;
  }
}
