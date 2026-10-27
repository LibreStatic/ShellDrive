/* sd_ini implementation (03 §3.3). */
#include <windows.h>
#include <string.h>

#include "sd_config/sd_ini.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_base/sd_checked.h"

typedef enum { L_RAW, L_SECTION, L_KV } line_kind;

typedef struct ini_line {
  line_kind kind;
  char *raw;          /* L_RAW: verbatim text (blank, comment, invalid) */
  char *section;      /* L_SECTION */
  char *key;          /* L_KV */
  char *value;        /* L_KV: decoded value */
  char *trail;        /* L_KV: inline comment including its leading whitespace, or NULL */
} ini_line;

struct sd_ini {
  ini_line *lines;
  size_t n, cap;
};

static char *dup_n(const char *s, size_t n)
{
  char *d = (char *)sd_alloc(n + 1);
  if (d) {
    memcpy(d, s, n);
    d[n] = 0;
  }
  return d;
}

static char *dup_s(const char *s) { return dup_n(s, strlen(s)); }

static void line_clear(ini_line *l)
{
  sd_free(l->raw);
  sd_free(l->section);
  sd_free(l->key);
  sd_free(l->value);
  sd_free(l->trail);
  memset(l, 0, sizeof(*l));
}

static int grow(sd_ini *ini, size_t need)
{
  ini_line *nl;
  size_t cap, bytes;
  if (need <= ini->cap)
    return 1;
  cap = ini->cap ? ini->cap * 2 : 32;
  while (cap < need) cap *= 2;
  if (sd_mul_ovf(cap, sizeof(ini_line), &bytes))
    return 0;
  nl = (ini_line *)sd_realloc(ini->lines, bytes);
  if (nl == NULL)
    return 0;
  ini->lines = nl;
  ini->cap = cap;
  return 1;
}

static int insert_line(sd_ini *ini, size_t at, const ini_line *l)
{
  if (!grow(ini, ini->n + 1))
    return 0;
  memmove(&ini->lines[at + 1], &ini->lines[at], (ini->n - at) * sizeof(ini_line));
  ini->lines[at] = *l;
  ini->n++;
  return 1;
}

int sd_ini_valid_key(const char *k)
{
  if (k == NULL || *k == 0)
    return 0;
  for (; *k; k++)
    if (!((*k >= 'a' && *k <= 'z') || (*k >= '0' && *k <= '9') || *k == '_' || *k == '.'))
      return 0;
  return 1;
}

int sd_ini_valid_section(const char *s)
{
  if (s == NULL || *s == 0)
    return 0;
  for (; *s; s++)
    if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '_' || *s == '.' || *s == '-'))
      return 0;
  return 1;
}

static int is_ws(char c) { return c == ' ' || c == '\t'; }

/* Parses the text after '='. Sets *value (decoded) and *trail (inline comment or NULL). */
static int parse_value(const char *s, size_t n, char **value, char **trail)
{
  size_t i = 0, end;
  *value = NULL;
  *trail = NULL;
  while (i < n && is_ws(s[i])) i++;
  if (i < n && s[i] == '"') {
    char *v = (char *)sd_alloc(n + 1);
    size_t o = 0, j = i + 1;
    if (v == NULL)
      return 0;
    for (; j < n; j++) {
      char c = s[j];
      if (c == '"')
        break;
      if (c == '\\' && j + 1 < n) {
        char e = s[++j];
        if (e == 'n') v[o++] = '\n';
        else if (e == '"' || e == '\\') v[o++] = e;
        else { v[o++] = '\\'; v[o++] = e; }
        continue;
      }
      v[o++] = c;
    }
    if (j >= n) {                    /* unterminated quote: invalid */
      sd_free(v);
      return 0;
    }
    v[o] = 0;
    j++;
    if (j < n) {
      size_t k = j;
      while (k < n && is_ws(s[k])) k++;
      if (k < n && s[k] != ';' && s[k] != '#') {   /* garbage after the closing quote */
        sd_free(v);
        return 0;
      }
      if (k < n) {
        *trail = dup_n(s + j, n - j);
        if (*trail == NULL) { sd_free(v); return 0; }
      }
    }
    *value = v;
    return 1;
  }
  end = n;
  {
    size_t k;
    for (k = i; k < n; k++) {
      if ((s[k] == ';' || s[k] == '#') && k > i && is_ws(s[k - 1])) {
        size_t t = k;
        while (t > i && is_ws(s[t - 1])) t--;
        *trail = dup_n(s + t, n - t);
        if (*trail == NULL) return 0;
        end = t;
        break;
      }
    }
  }
  while (end > i && is_ws(s[end - 1])) end--;
  *value = dup_n(s + i, end - i);
  if (*value == NULL) {
    sd_free(*trail);
    *trail = NULL;
    return 0;
  }
  return 1;
}

static int parse_line(const char *s, size_t n, ini_line *out, int *invalid)
{
  size_t i = 0, e;
  memset(out, 0, sizeof(*out));
  *invalid = 0;
  while (i < n && is_ws(s[i])) i++;
  if (i == n || s[i] == ';' || s[i] == '#') {
    out->kind = L_RAW;
    out->raw = dup_n(s, n);
    return out->raw != NULL;
  }
  if (s[i] == '[') {
    e = i + 1;
    while (e < n && s[e] != ']') e++;
    if (e < n) {
      char *name = dup_n(s + i + 1, e - i - 1);
      size_t k = e + 1;
      if (name == NULL) return 0;
      while (k < n && is_ws(s[k])) k++;
      if (sd_ini_valid_section(name) && (k == n || s[k] == ';' || s[k] == '#')) {
        out->kind = L_SECTION;
        out->section = name;
        out->raw = dup_n(s, n);
        return out->raw != NULL;
      }
      sd_free(name);
    }
  } else {
    for (e = i; e < n && s[e] != '='; e++)
      ;
    if (e < n) {
      size_t ke = e;
      char *key;
      while (ke > i && is_ws(s[ke - 1])) ke--;
      key = dup_n(s + i, ke - i);
      if (key == NULL) return 0;
      if (sd_ini_valid_key(key) && parse_value(s + e + 1, n - e - 1, &out->value, &out->trail)) {
        out->kind = L_KV;
        out->key = key;
        out->raw = dup_n(s, n);
        if (out->raw == NULL) { line_clear(out); return 0; }
        return 1;
      }
      sd_free(key);
    }
  }
  out->kind = L_RAW;
  out->raw = dup_n(s, n);
  *invalid = 1;
  return out->raw != NULL;
}

sd_err sd_ini_new(sd_ini **out)
{
  *out = (sd_ini *)sd_calloc(1, sizeof(sd_ini));
  return *out ? SD_OK : SD_E_NO_MEMORY;
}

void sd_ini_free(sd_ini *ini)
{
  size_t i;
  if (ini == NULL)
    return;
  for (i = 0; i < ini->n; i++)
    line_clear(&ini->lines[i]);
  sd_free(ini->lines);
  sd_free(ini);
}

/* ANSI -> UTF-8 for files saved by legacy editors. */
static char *ansi_to_utf8(const char *data, size_t len, size_t *out_len)
{
  int wn, un;
  wchar_t *w;
  char *u;
  if (len > SD_INI_MAX_BYTES)
    return NULL;
  wn = MultiByteToWideChar(CP_ACP, 0, data, (int)len, NULL, 0);
  if (wn <= 0)
    return NULL;
  w = (wchar_t *)sd_alloc((size_t)wn * sizeof(wchar_t));
  if (w == NULL)
    return NULL;
  MultiByteToWideChar(CP_ACP, 0, data, (int)len, w, wn);
  un = WideCharToMultiByte(CP_UTF8, 0, w, wn, NULL, 0, NULL, NULL);
  u = un > 0 ? (char *)sd_alloc((size_t)un + 1) : NULL;
  if (u) {
    WideCharToMultiByte(CP_UTF8, 0, w, wn, u, un, NULL, NULL);
    u[un] = 0;
    *out_len = (size_t)un;
  }
  sd_free(w);
  return u;
}

sd_err sd_ini_parse(const char *data, size_t len, sd_ini **out, uint32_t *flags)
{
  sd_ini *ini;
  char *conv = NULL;
  size_t pos = 0, i, j;
  uint32_t f = 0;
  *out = NULL;
  if (flags) *flags = 0;
  if (data == NULL && len)
    return SD_E_INVALID_PARAM;
  if (len > SD_INI_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  if (len >= 3 && (uint8_t)data[0] == 0xEF && (uint8_t)data[1] == 0xBB && (uint8_t)data[2] == 0xBF) {
    data += 3;
    len -= 3;
  }
  if (!sd_utf8_valid(data, len)) {
    size_t cl = 0;
    conv = ansi_to_utf8(data, len, &cl);
    if (conv == NULL)
      return SD_E_INVALID_PARAM;
    data = conv;
    len = cl;
    f |= SD_INI_F_ANSI_DECODED;
  }
  if (sd_ini_new(&ini) != SD_OK) {
    sd_free(conv);
    return SD_E_NO_MEMORY;
  }
  while (pos < len) {
    size_t e = pos, n;
    ini_line l;
    int invalid;
    while (e < len && data[e] != '\n') e++;
    n = e - pos;
    if (n && data[pos + n - 1] == '\r') n--;
    if (memchr(data + pos, 0, n) != NULL || !parse_line(data + pos, n, &l, &invalid) ||
        !insert_line(ini, ini->n, &l)) {
      /* Decide the error before freeing conv: data may point into conv (ANSI-decoded input). */
      int has_nul = memchr(data + pos, 0, n) != NULL;
      if (!has_nul) line_clear(&l);
      sd_ini_free(ini);
      sd_free(conv);
      return has_nul ? SD_E_INVALID_PARAM : SD_E_NO_MEMORY;
    }
    if (invalid) f |= SD_INI_F_INVALID_LINES;
    pos = e < len ? e + 1 : e;
  }
  sd_free(conv);
  /* duplicate detection (first wins) */
  {
    const char *sec_i = "";
    for (i = 0; i < ini->n; i++) {
      if (ini->lines[i].kind == L_SECTION) { sec_i = ini->lines[i].section; continue; }
      if (ini->lines[i].kind != L_KV) continue;
      {
        const char *sec_j = sec_i;
        for (j = i + 1; j < ini->n; j++) {
          if (ini->lines[j].kind == L_SECTION) { sec_j = ini->lines[j].section; continue; }
          if (ini->lines[j].kind == L_KV && strcmp(sec_i, sec_j) == 0 &&
              strcmp(ini->lines[i].key, ini->lines[j].key) == 0)
            f |= SD_INI_F_DUPLICATE_KEYS;
        }
      }
    }
  }
  if (flags) *flags = f;
  *out = ini;
  return SD_OK;
}

static ini_line *find(const sd_ini *ini, const char *section, const char *key, size_t *idx)
{
  const char *cur = "";
  size_t i;
  for (i = 0; i < ini->n; i++) {
    ini_line *l = &ini->lines[i];
    if (l->kind == L_SECTION) {
      cur = l->section;
    } else if (l->kind == L_KV && strcmp(cur, section) == 0 && strcmp(l->key, key) == 0) {
      if (idx) *idx = i;
      return l;
    }
  }
  return NULL;
}

const char *sd_ini_get(const sd_ini *ini, const char *section, const char *key)
{
  ini_line *l;
  if (ini == NULL || section == NULL || key == NULL)
    return NULL;
  l = find(ini, section, key, NULL);
  return l ? l->value : NULL;
}

static int needs_quotes(const char *v)
{
  size_t n = strlen(v), i;
  if (n == 0)
    return 0;
  if (is_ws(v[0]) || is_ws(v[n - 1]) || v[0] == '"')
    return 1;
  for (i = 0; i < n; i++) {
    if (v[i] == '\n' || v[i] == '\r')
      return 1;
    if ((v[i] == ';' || v[i] == '#') && i > 0 && is_ws(v[i - 1]))
      return 1;
  }
  return 0;
}

static char *encode_kv(const char *key, const char *value, const char *trail)
{
  size_t n = strlen(key) + 4 + strlen(value) * 2 + 2 + (trail ? strlen(trail) : 0) + 1, o = 0, i;
  char *s = (char *)sd_alloc(n);
  int q = needs_quotes(value);
  if (s == NULL)
    return NULL;
  memcpy(s, key, strlen(key));
  o = strlen(key);
  memcpy(s + o, value[0] || q ? " = " : " =", value[0] || q ? 3 : 2);
  o += value[0] || q ? 3 : 2;
  if (q) s[o++] = '"';
  for (i = 0; value[i]; i++) {
    char c = value[i];
    if (q && (c == '"' || c == '\\')) { s[o++] = '\\'; s[o++] = c; }
    else if (q && c == '\n') { s[o++] = '\\'; s[o++] = 'n'; }
    else if (c == '\r') continue;
    else s[o++] = c;
  }
  if (q) s[o++] = '"';
  if (trail) {
    memcpy(s + o, trail, strlen(trail));
    o += strlen(trail);
  }
  s[o] = 0;
  return s;
}

sd_err sd_ini_set(sd_ini *ini, const char *section, const char *key, const char *value)
{
  ini_line *l;
  ini_line nl;
  size_t idx, i, insert_at;
  int found_section = 0;
  if (ini == NULL || !sd_ini_valid_section(section) || !sd_ini_valid_key(key) || value == NULL ||
      !sd_utf8_valid(value, strlen(value)))
    return SD_E_INVALID_PARAM;
  l = find(ini, section, key, &idx);
  if (l) {
    char *v = dup_s(value), *raw = encode_kv(key, value, l->trail);
    if (v == NULL || raw == NULL) {
      sd_free(v); sd_free(raw);
      return SD_E_NO_MEMORY;
    }
    sd_free(l->value);
    sd_free(l->raw);
    l->value = v;
    l->raw = raw;
    return SD_OK;
  }
  /* find the end of the section (last non-blank line before the next section) */
  insert_at = ini->n;
  for (i = 0; i < ini->n; i++) {
    if (ini->lines[i].kind == L_SECTION && strcmp(ini->lines[i].section, section) == 0) {
      size_t k = i + 1, last = i;
      found_section = 1;
      for (; k < ini->n && ini->lines[k].kind != L_SECTION; k++) {
        const char *r = ini->lines[k].raw;
        size_t t = 0;
        while (r && is_ws(r[t])) t++;
        if (ini->lines[k].kind != L_RAW || (r && r[t] != 0))
          last = k;
      }
      insert_at = last + 1;
      break;
    }
  }
  if (!found_section) {
    memset(&nl, 0, sizeof(nl));
    if (ini->n > 0) {
      const char *r = ini->lines[ini->n - 1].raw;
      if (ini->lines[ini->n - 1].kind != L_RAW || (r && r[0])) {
        nl.kind = L_RAW;
        nl.raw = dup_s("");
        if (nl.raw == NULL || !insert_line(ini, ini->n, &nl)) { line_clear(&nl); return SD_E_NO_MEMORY; }
      }
    }
    memset(&nl, 0, sizeof(nl));
    nl.kind = L_SECTION;
    nl.section = dup_s(section);
    nl.raw = (char *)sd_alloc(strlen(section) + 3);
    if (nl.section == NULL || nl.raw == NULL) { line_clear(&nl); return SD_E_NO_MEMORY; }
    nl.raw[0] = '[';
    memcpy(nl.raw + 1, section, strlen(section));
    nl.raw[strlen(section) + 1] = ']';
    nl.raw[strlen(section) + 2] = 0;
    if (!insert_line(ini, ini->n, &nl)) { line_clear(&nl); return SD_E_NO_MEMORY; }
    insert_at = ini->n;
  }
  memset(&nl, 0, sizeof(nl));
  nl.kind = L_KV;
  nl.key = dup_s(key);
  nl.value = dup_s(value);
  nl.raw = encode_kv(key, value, NULL);
  if (nl.key == NULL || nl.value == NULL || nl.raw == NULL || !insert_line(ini, insert_at, &nl)) {
    line_clear(&nl);
    return SD_E_NO_MEMORY;
  }
  return SD_OK;
}

sd_err sd_ini_remove(sd_ini *ini, const char *section, const char *key)
{
  size_t idx;
  if (ini == NULL || section == NULL || key == NULL)
    return SD_E_INVALID_PARAM;
  if (find(ini, section, key, &idx) == NULL)
    return SD_E_NOT_FOUND;
  line_clear(&ini->lines[idx]);
  memmove(&ini->lines[idx], &ini->lines[idx + 1], (ini->n - idx - 1) * sizeof(ini_line));
  ini->n--;
  return SD_OK;
}

sd_err sd_ini_serialize(const sd_ini *ini, sd_wr *out)
{
  size_t i;
  if (ini == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  for (i = 0; i < ini->n; i++) {
    const char *r = ini->lines[i].raw ? ini->lines[i].raw : "";
    sd_wr_bytes(out, r, strlen(r));
    sd_wr_bytes(out, "\r\n", 2);
  }
  return sd_wr_ok(out) ? SD_OK : SD_E_NO_MEMORY;
}

/* ---- value helpers ---- */

static int ieq(const char *a, const char *b)
{
  for (; *a && *b; a++, b++) {
    char x = *a, y = *b;
    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
    if (x != y) return 0;
  }
  return *a == *b;
}

int sd_ini_parse_bool(const char *v, int *out)
{
  if (v == NULL) return 0;
  if (ieq(v, "yes") || ieq(v, "true") || ieq(v, "1") || ieq(v, "on")) { *out = 1; return 1; }
  if (ieq(v, "no") || ieq(v, "false") || ieq(v, "0") || ieq(v, "off")) { *out = 0; return 1; }
  return 0;
}

static int parse_u64_prefix(const char *v, uint64_t *out, const char **rest)
{
  uint64_t x = 0;
  const char *p = v;
  if (p == NULL || *p < '0' || *p > '9')
    return 0;
  while (*p >= '0' && *p <= '9') {
    uint64_t d = (uint64_t)(*p - '0');
    if (x > (UINT64_MAX - d) / 10u) return 0;
    x = x * 10u + d;
    p++;
  }
  *out = x;
  *rest = p;
  return 1;
}

int sd_ini_parse_u32(const char *v, uint32_t *out)
{
  uint64_t x;
  const char *rest;
  if (!parse_u64_prefix(v, &x, &rest) || *rest || x > UINT32_MAX)
    return 0;
  *out = (uint32_t)x;
  return 1;
}

int sd_ini_parse_duration_ms(const char *v, uint32_t *out)
{
  uint64_t x, mul;
  const char *rest;
  if (!parse_u64_prefix(v, &x, &rest))
    return 0;
  while (is_ws(*rest)) rest++;
  if (*rest == 0 || ieq(rest, "s")) mul = 1000;
  else if (ieq(rest, "ms")) mul = 1;
  else if (ieq(rest, "m")) mul = 60000;
  else if (ieq(rest, "h")) mul = 3600000;
  else return 0;
  if (x > UINT32_MAX / mul)
    return 0;
  *out = (uint32_t)(x * mul);
  return 1;
}

int sd_ini_parse_size(const char *v, uint64_t *out)
{
  uint64_t x, mul;
  const char *rest;
  if (!parse_u64_prefix(v, &x, &rest))
    return 0;
  while (is_ws(*rest)) rest++;
  if (*rest == 0) mul = 1;
  else if (ieq(rest, "k")) mul = 1024u;
  else if (ieq(rest, "m")) mul = 1024u * 1024u;
  else if (ieq(rest, "g")) mul = 1024u * 1024u * 1024u;
  else return 0;
  if (x > UINT64_MAX / mul)
    return 0;
  *out = x * mul;
  return 1;
}
