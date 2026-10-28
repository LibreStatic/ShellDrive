/* Anonymizer for diag --bundle (see cli_anon.h). Pure text processing over UTF-8 lines: no file or registry
 * access, so the unit tests drive it directly. */
#include <windows.h>
#include <string.h>

#include "cli_anon.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"

/* Appends a NUL-terminated text as raw bytes (sd_wr_cstring writes a length-prefixed SSH string). */
static void wr_text(sd_wr *w, const char *s)
{
  sd_wr_bytes(w, s, strlen(s));
}

#define ANON_MAX_VALUES   1024u
#define ANON_MIN_VALUE    2u
#define ANON_MAX_SPANS    64u
#define ANON_REDACTED     "<redacted>"
#define ANON_TOKEN_CAP    16u

typedef struct anon_value {
  char *text;
  size_t len;
  char kind;
  char tok[ANON_TOKEN_CAP];
} anon_value;

struct anon_ctx {
  int enabled;
  uint8_t key[32];
  anon_value *vals;
  size_t n, cap;
};

/* A piece of a line that is replaced: [start, end) becomes tok. */
typedef struct anon_span {
  size_t start, end;
  char tok[ANON_TOKEN_CAP];
} anon_span;

static char lower_ascii(char c)
{
  return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static int key_is(const char *s, size_t n, const char *name)
{
  size_t i, m = strlen(name);
  if (n != m)
    return 0;
  for (i = 0; i < n; i++)
    if (lower_ascii(s[i]) != name[i])
      return 0;
  return 1;
}

static int key_char(char ch)
{
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_';
}

static int contains_ci(const char *s, size_t n, const char *word)
{
  size_t m = strlen(word), i, k;
  if (m > n)
    return 0;
  for (i = 0; i + m <= n; i++) {
    for (k = 0; k < m && lower_ascii(s[i + k]) == word[k]; k++)
      ;
    if (k == m)
      return 1;
  }
  return 0;
}

int anon_is_secret_key(const char *key, size_t n)
{
  return contains_ci(key, n, "pass") || contains_ci(key, n, "secret") || contains_ci(key, n, "token") ||
         contains_ci(key, n, "credential") || contains_ci(key, n, "private");
}

static char kind_of_key(const char *s, size_t n)
{
  if (key_is(s, n, "host") || key_is(s, n, "jump") || key_is(s, n, "proxy")) return 'h';
  if (key_is(s, n, "user")) return 'u';
  if (key_is(s, n, "rpath") || key_is(s, n, "remote_path") || key_is(s, n, "path") || key_is(s, n, "identity"))
    return 'p';
  return 0;
}

/* ---- context ---- */

anon_ctx *anon_new(int enabled)
{
  anon_ctx *c = (anon_ctx *)sd_alloc(sizeof(*c));
  if (c == NULL)
    return NULL;
  memset(c, 0, sizeof(*c));
  c->enabled = enabled ? 1 : 0;
  if (sd_random(c->key, sizeof(c->key)) != SD_OK) {
    sd_free(c);
    return NULL;
  }
  return c;
}

void anon_free(anon_ctx *c)
{
  size_t i;
  if (c == NULL)
    return;
  for (i = 0; i < c->n; i++) {
    SecureZeroMemory(c->vals[i].text, c->vals[i].len);
    sd_free(c->vals[i].text);
  }
  sd_free(c->vals);
  SecureZeroMemory(c->key, sizeof(c->key));
  sd_free(c);
}

int anon_enabled(const anon_ctx *c)
{
  return c != NULL && c->enabled;
}

void anon_token(anon_ctx *c, char kind, const char *utf8, char *out, size_t cap)
{
  static const char hex[] = "0123456789abcdef";
  uint8_t mac[32];
  sd_hmac_ctx h;
  size_t i;
  if (out == NULL || cap < 9)
    return;
  out[0] = kind;
  out[1] = ':';
  out[2] = 0;
  if (c == NULL || utf8 == NULL) {
    memcpy(out, "x:000000", 9);
    return;
  }
  sd_hmac_init(&h, SD_HASH_SHA256, c->key, sizeof(c->key));
  sd_hmac_update(&h, &kind, 1);
  sd_hmac_update(&h, utf8, strlen(utf8));
  sd_hmac_final(&h, mac);
  sd_hmac_wipe(&h);
  for (i = 0; i < 3; i++) {
    out[2 + 2 * i] = hex[mac[i] >> 4];
    out[3 + 2 * i] = hex[mac[i] & 0xF];
  }
  out[8] = 0;
}

void anon_add_value(anon_ctx *c, char kind, const char *utf8)
{
  size_t len, i;
  anon_value *v;
  if (c == NULL || !c->enabled || utf8 == NULL)
    return;
  len = strlen(utf8);
  if (len < ANON_MIN_VALUE || c->n >= ANON_MAX_VALUES)
    return;
  for (i = 0; i < c->n; i++)
    if (c->vals[i].len == len && _strnicmp(c->vals[i].text, utf8, len) == 0)
      return;
  if (c->n == c->cap) {
    size_t nc = c->cap ? c->cap * 2 : 32;
    anon_value *nv;
    if (nc > ANON_MAX_VALUES) nc = ANON_MAX_VALUES;
    nv = (anon_value *)sd_realloc(c->vals, nc * sizeof(anon_value));
    if (nv == NULL)
      return;
    c->vals = nv;
    c->cap = nc;
  }
  v = &c->vals[c->n];
  v->text = (char *)sd_alloc(len + 1);
  if (v->text == NULL)
    return;
  memcpy(v->text, utf8, len + 1);
  v->len = len;
  v->kind = kind;
  anon_token(c, kind, utf8, v->tok, sizeof(v->tok));
  c->n++;
}

/* ---- spans ---- */

static int add_span(anon_span *sp, size_t *nsp, size_t start, size_t end, const char *tok)
{
  if (*nsp >= ANON_MAX_SPANS)
    return 0;
  sp[*nsp].start = start;
  sp[*nsp].end = end;
  strcpy_s(sp[*nsp].tok, sizeof(sp[*nsp].tok), tok);
  (*nsp)++;
  return 1;
}

/* A log field "key=" starts at i when i is the start of the line or follows a space. Returns the key length. */
static size_t log_field_key(const char *s, size_t n, size_t i)
{
  size_t j = i;
  if (i > 0 && s[i - 1] != ' ' && s[i - 1] != '\t')
    return 0;
  while (j < n && key_char(s[j]))
    j++;
  if (j == i || j >= n || s[j] != '=')
    return 0;
  return j - i;
}

/* The value of a log field ends before the next " key=" or at the end of the line. */
static size_t log_value_end(const char *s, size_t n, size_t v)
{
  size_t j;
  for (j = v; j < n; j++)
    if (s[j] == ' ' && j + 1 < n && log_field_key(s, n, j + 1) != 0)
      return j;
  return n;
}

/* Builds the spans of a log line. Each field value is hidden (its key decides the kind, a secret key is
   redacted) and registered, so the same text elsewhere in the line is hidden too. */
static sd_err log_spans(anon_ctx *c, const char *s, size_t n, anon_span *sp, size_t *nsp)
{
  size_t i = 0;
  *nsp = 0;
  while (i < n) {
    size_t klen = log_field_key(s, n, i);
    if (klen) {
      size_t vstart = i + klen + 1, vend = log_value_end(s, n, vstart);
      char kind = kind_of_key(s + i, klen);
      if (anon_is_secret_key(s + i, klen)) {
        if (vend > vstart && !add_span(sp, nsp, vstart, vend, ANON_REDACTED))
          return SD_E_FAILURE;
      } else if (kind && c->enabled && vend > vstart) {
        char *val = (char *)sd_alloc(vend - vstart + 1);
        char tok[ANON_TOKEN_CAP];
        if (val == NULL)
          return SD_E_NO_MEMORY;
        memcpy(val, s + vstart, vend - vstart);
        val[vend - vstart] = 0;
        anon_token(c, kind, val, tok, sizeof(tok));
        anon_add_value(c, kind, val);
        if (!add_span(sp, nsp, vstart, vend, tok)) {
          sd_free(val);
          return SD_E_FAILURE;
        }
        sd_free(val);
      }
      i = vend > i ? vend : i + 1;
      continue;
    }
    i++;
  }
  return SD_OK;
}

/* Builds the spans of a configuration line "key = value": secret values are redacted, the values of host,
   user, remote_path and identity are tokens when anonymization is on. */
static sd_err config_spans(anon_ctx *c, const char *s, size_t n, anon_span *sp, size_t *nsp)
{
  size_t i = 0, eq, ke, vs, ve;
  *nsp = 0;
  while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
  if (i >= n || s[i] == ';' || s[i] == '#' || s[i] == '[')
    return SD_OK;
  for (eq = i; eq < n && s[eq] != '='; eq++)
    ;
  if (eq >= n)
    return SD_OK;
  ke = eq;
  while (ke > i && (s[ke - 1] == ' ' || s[ke - 1] == '\t')) ke--;
  vs = eq + 1;
  while (vs < n && (s[vs] == ' ' || s[vs] == '\t')) vs++;
  ve = n;
  while (ve > vs && (s[ve - 1] == ' ' || s[ve - 1] == '\t' || s[ve - 1] == '\r')) ve--;
  if (ve <= vs)
    return SD_OK;
  if (anon_is_secret_key(s + i, ke - i)) {
    if (!add_span(sp, nsp, vs, ve, ANON_REDACTED))
      return SD_E_FAILURE;
  } else {
    char kind = kind_of_key(s + i, ke - i);
    if (kind && c->enabled) {
      char *val = (char *)sd_alloc(ve - vs + 1);
      char tok[ANON_TOKEN_CAP];
      if (val == NULL)
        return SD_E_NO_MEMORY;
      memcpy(val, s + vs, ve - vs);
      val[ve - vs] = 0;
      anon_token(c, kind, val, tok, sizeof(tok));
      anon_add_value(c, kind, val);
      if (!add_span(sp, nsp, vs, ve, tok)) {
        sd_free(val);
        return SD_E_FAILURE;
      }
      sd_free(val);
    }
  }
  return SD_OK;
}

/* Copies the line with each span replaced by its token and every registered value replaced by its token
   (the longest match at each position; ASCII case is ignored). */
static sd_err emit_line(anon_ctx *c, const char *s, size_t n, const anon_span *sp, size_t nsp, sd_wr *out)
{
  size_t i = 0, k = 0;
  while (i < n) {
    if (k < nsp && i == sp[k].start) {
      wr_text(out, sp[k].tok);
      i = sp[k].end;
      k++;
      continue;
    }
    if (c->enabled) {
      size_t best = 0, bi = 0, j;
      for (j = 0; j < c->n; j++) {
        const anon_value *v = &c->vals[j];
        if (v->len > best && v->len <= n - i && _strnicmp(s + i, v->text, v->len) == 0) {
          best = v->len;
          bi = j;
        }
      }
      if (best) {
        wr_text(out, c->vals[bi].tok);
        i += best;
        continue;
      }
    }
    sd_wr_u8(out, (uint8_t)s[i]);
    i++;
  }
  return sd_wr_ok(out) ? SD_OK : SD_E_NO_MEMORY;
}

sd_err anon_log_line(anon_ctx *c, const char *in, size_t n, sd_wr *out)
{
  anon_span sp[ANON_MAX_SPANS];
  size_t nsp = 0;
  sd_err e;
  if (c == NULL || out == NULL || (n && in == NULL))
    return SD_E_INVALID_PARAM;
  e = log_spans(c, in, n, sp, &nsp);
  if (e != SD_OK)
    return e;
  return emit_line(c, in, n, sp, nsp, out);
}

sd_err anon_config_line(anon_ctx *c, const char *in, size_t n, sd_wr *out)
{
  anon_span sp[ANON_MAX_SPANS];
  size_t nsp = 0;
  sd_err e;
  if (c == NULL || out == NULL || (n && in == NULL))
    return SD_E_INVALID_PARAM;
  e = config_spans(c, in, n, sp, &nsp);
  if (e != SD_OK)
    return e;
  return emit_line(c, in, n, sp, nsp, out);
}
