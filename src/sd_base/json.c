/* sd_json: strict, bounded RFC 8259 reader and a validating writer (03 §2.3).
 *
 * Reader: one arena per document; every node, string and member table lives in it. Strings are
 * NUL-terminated copies (escapes decoded) and must be valid UTF-8; unpaired surrogate escapes,
 * control characters, duplicate keys, leading zeros, trailing data and nesting beyond max_depth
 * are errors. Numbers keep their source text; integral values without fraction or exponent that
 * fit in int64 are also available as integers.
 *
 * Writer: tracks nesting in sd_json_writer.state[] (one entry per open container, entry 0 for the
 * top level). Any misuse (value where a key is expected, unbalanced end, invalid UTF-8, nesting
 * beyond 31) sets the sticky err flag; sd_jw_finish reports it. */
#include <string.h>

#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_base/sd_checked.h"

/* ---- arena ---- */

typedef struct json_block { struct json_block *next; size_t used, cap; } json_block;

typedef struct json_arena { json_block *head; } json_arena;

#define JSON_BLOCK_MIN 4096u

static void *arena_alloc(json_arena *a, size_t n)
{
  json_block *b = a->head;
  size_t need;
  n = (n + 7u) & ~(size_t)7u;
  if (n == 0)
    n = 8;
  if (b == NULL || b->cap - b->used < n) {
    size_t cap = n > JSON_BLOCK_MIN ? n : JSON_BLOCK_MIN;
    if (sd_add_ovf(cap, sizeof(json_block), &need))
      return NULL;
    b = (json_block *)sd_alloc(need);
    if (b == NULL)
      return NULL;
    b->next = a->head;
    b->used = 0;
    b->cap = cap;
    a->head = b;
  }
  {
    uint8_t *p = (uint8_t *)(b + 1) + b->used;
    b->used += n;
    return p;
  }
}

static void arena_free(json_arena *a)
{
  json_block *b = a->head;
  while (b) {
    json_block *n = b->next;
    /* Documents carry prompt answers (passwords) over IPC: wipe before release. */
    sd_secure_free(b, sizeof(json_block) + b->cap);
    b = n;
  }
  a->head = NULL;
}

/* ---- nodes ---- */

struct sd_json {
  sd_json_type type;
  int          bval;
  int          is_int;
  int64_t      ival;
  const char  *str;       /* string value, or number source text */
  size_t       len;
  size_t       count;     /* array / object members */
  sd_json    **items;
  const char **keys;      /* object keys (NUL-terminated) */
  size_t      *key_lens;
};

typedef struct json_doc {
  json_arena arena;
  sd_json    root;
} json_doc;

typedef struct json_parser {
  const char *p, *end;
  uint32_t max_depth;
  json_arena *arena;
  sd_err err;
} json_parser;

/* Temporary list used while a container is parsed (members are linked, then flattened). */
typedef struct json_member {
  struct json_member *next;
  sd_json *value;
  const char *key;
  size_t key_len;
} json_member;

static void skip_ws(json_parser *ps)
{
  while (ps->p < ps->end) {
    char c = *ps->p;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
      ps->p++;
    else
      break;
  }
}

static int fail(json_parser *ps, sd_err e)
{
  if (ps->err == SD_OK)
    ps->err = e;
  return 0;
}

static int hex4(const char *p, uint32_t *out)
{
  uint32_t v = 0;
  int i;
  for (i = 0; i < 4; i++) {
    char c = p[i];
    v <<= 4;
    if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
    else return 0;
  }
  *out = v;
  return 1;
}

static size_t put_utf8(char *o, uint32_t cp)
{
  if (cp < 0x80) { o[0] = (char)cp; return 1; }
  if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
  if (cp < 0x10000) {
    o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    o[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
  }
  o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
  o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
  return 4;
}

/* Parses a string starting at '"'. The decoded form is never longer than the source. */
static int parse_string(json_parser *ps, const char **out, size_t *out_len)
{
  const char *s = ps->p + 1, *q;
  size_t raw = 0, n = 0;
  char *buf;
  /* find the closing quote, skipping escapes */
  for (q = s; q < ps->end; q++) {
    if (*q == '"')
      break;
    if (*q == '\\') {
      q++;
      if (q >= ps->end)
        return fail(ps, SD_E_PROTOCOL);
    } else if ((unsigned char)*q < 0x20) {
      return fail(ps, SD_E_PROTOCOL);
    }
  }
  if (q >= ps->end)
    return fail(ps, SD_E_PROTOCOL);
  raw = (size_t)(q - s);
  buf = (char *)arena_alloc(ps->arena, raw + 1);
  if (buf == NULL)
    return fail(ps, SD_E_NO_MEMORY);
  while (s < q) {
    char c = *s++;
    if (c != '\\') {
      buf[n++] = c;
      continue;
    }
    c = *s++;
    switch (c) {
    case '"':  buf[n++] = '"'; break;
    case '\\': buf[n++] = '\\'; break;
    case '/':  buf[n++] = '/'; break;
    case 'b':  buf[n++] = '\b'; break;
    case 'f':  buf[n++] = '\f'; break;
    case 'n':  buf[n++] = '\n'; break;
    case 'r':  buf[n++] = '\r'; break;
    case 't':  buf[n++] = '\t'; break;
    case 'u': {
      uint32_t cp, lo;
      if (q - s < 4 || !hex4(s, &cp))
        return fail(ps, SD_E_PROTOCOL);
      s += 4;
      if (cp >= 0xD800 && cp <= 0xDBFF) {
        if (q - s < 6 || s[0] != '\\' || s[1] != 'u' || !hex4(s + 2, &lo) || lo < 0xDC00 || lo > 0xDFFF)
          return fail(ps, SD_E_PROTOCOL);
        s += 6;
        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
      } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
        return fail(ps, SD_E_PROTOCOL);
      }
      /* "\uXXXX" is 6 source bytes and decodes to at most 3 (or 12 -> 4 for a pair). */
      n += put_utf8(buf + n, cp);
      break;
    }
    default:
      return fail(ps, SD_E_PROTOCOL);
    }
  }
  buf[n] = '\0';
  if (!sd_utf8_valid(buf, n))
    return fail(ps, SD_E_PROTOCOL);
  ps->p = q + 1;
  *out = buf;
  *out_len = n;
  return 1;
}

static int parse_number(json_parser *ps, sd_json *v)
{
  const char *s = ps->p, *p = ps->p;
  int neg = 0, integral = 1, overflow = 0;
  uint64_t mag = 0;
  char *copy;
  if (p < ps->end && *p == '-') { neg = 1; p++; }
  if (p >= ps->end)
    return fail(ps, SD_E_PROTOCOL);
  if (*p == '0') {
    p++;
  } else if (*p >= '1' && *p <= '9') {
    while (p < ps->end && *p >= '0' && *p <= '9') {
      uint64_t d = (uint64_t)(*p - '0');
      if (mag > (UINT64_MAX - d) / 10u) overflow = 1;
      else mag = mag * 10u + d;
      p++;
    }
  } else {
    return fail(ps, SD_E_PROTOCOL);
  }
  if (p < ps->end && *p == '.') {
    integral = 0;
    p++;
    if (p >= ps->end || *p < '0' || *p > '9')
      return fail(ps, SD_E_PROTOCOL);
    while (p < ps->end && *p >= '0' && *p <= '9') p++;
  }
  if (p < ps->end && (*p == 'e' || *p == 'E')) {
    integral = 0;
    p++;
    if (p < ps->end && (*p == '+' || *p == '-')) p++;
    if (p >= ps->end || *p < '0' || *p > '9')
      return fail(ps, SD_E_PROTOCOL);
    while (p < ps->end && *p >= '0' && *p <= '9') p++;
  }
  v->type = SD_JSON_NUMBER;
  v->len = (size_t)(p - s);
  copy = (char *)arena_alloc(ps->arena, v->len + 1);
  if (copy == NULL)
    return fail(ps, SD_E_NO_MEMORY);
  memcpy(copy, s, v->len);
  copy[v->len] = '\0';
  v->str = copy;
  if (integral && !overflow) {
    if (neg && mag <= (uint64_t)INT64_MAX + 1u) {
      v->is_int = 1;
      v->ival = mag == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)mag;
    } else if (!neg && mag <= (uint64_t)INT64_MAX) {
      v->is_int = 1;
      v->ival = (int64_t)mag;
    }
  }
  ps->p = p;
  return 1;
}

static int literal(json_parser *ps, const char *word)
{
  size_t n = strlen(word);
  if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n) != 0)
    return fail(ps, SD_E_PROTOCOL);
  ps->p += n;
  return 1;
}

static int parse_value(json_parser *ps, sd_json *v, uint32_t depth);

static int parse_container(json_parser *ps, sd_json *v, uint32_t depth, int is_object)
{
  json_member *first = NULL, *last = NULL, *m;
  size_t count = 0, i;
  char close = is_object ? '}' : ']';
  if (depth >= ps->max_depth)
    return fail(ps, SD_E_PROTOCOL);
  ps->p++;  /* '{' or '[' */
  skip_ws(ps);
  if (ps->p < ps->end && *ps->p == close) {
    ps->p++;
  } else {
    for (;;) {
      m = (json_member *)arena_alloc(ps->arena, sizeof(*m));
      if (m == NULL)
        return fail(ps, SD_E_NO_MEMORY);
      memset(m, 0, sizeof(*m));
      skip_ws(ps);
      if (is_object) {
        if (ps->p >= ps->end || *ps->p != '"')
          return fail(ps, SD_E_PROTOCOL);
        if (!parse_string(ps, &m->key, &m->key_len))
          return 0;
        if (strlen(m->key) != m->key_len)          /* keys are C strings: no embedded NUL */
          return fail(ps, SD_E_PROTOCOL);
        {
          json_member *o;
          for (o = first; o; o = o->next)
            if (o->key_len == m->key_len && memcmp(o->key, m->key, m->key_len) == 0)
              return fail(ps, SD_E_PROTOCOL);    /* duplicate key */
        }
        skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':')
          return fail(ps, SD_E_PROTOCOL);
        ps->p++;
        skip_ws(ps);
      }
      m->value = (sd_json *)arena_alloc(ps->arena, sizeof(sd_json));
      if (m->value == NULL)
        return fail(ps, SD_E_NO_MEMORY);
      memset(m->value, 0, sizeof(sd_json));
      if (!parse_value(ps, m->value, depth + 1))
        return 0;
      if (last) last->next = m; else first = m;
      last = m;
      count++;
      skip_ws(ps);
      if (ps->p >= ps->end)
        return fail(ps, SD_E_PROTOCOL);
      if (*ps->p == ',') { ps->p++; continue; }
      if (*ps->p == close) { ps->p++; break; }
      return fail(ps, SD_E_PROTOCOL);
    }
  }
  v->type = is_object ? SD_JSON_OBJECT : SD_JSON_ARRAY;
  v->count = count;
  if (count) {
    size_t bytes;
    if (sd_mul_ovf(count, sizeof(sd_json *), &bytes))
      return fail(ps, SD_E_NO_MEMORY);
    v->items = (sd_json **)arena_alloc(ps->arena, bytes);
    if (v->items == NULL)
      return fail(ps, SD_E_NO_MEMORY);
    if (is_object) {
      v->keys = (const char **)arena_alloc(ps->arena, count * sizeof(char *));
      v->key_lens = (size_t *)arena_alloc(ps->arena, count * sizeof(size_t));
      if (v->keys == NULL || v->key_lens == NULL)
        return fail(ps, SD_E_NO_MEMORY);
    }
    for (m = first, i = 0; m; m = m->next, i++) {
      v->items[i] = m->value;
      if (is_object) {
        v->keys[i] = m->key;
        v->key_lens[i] = m->key_len;
      }
    }
  }
  return 1;
}

static int parse_value(json_parser *ps, sd_json *v, uint32_t depth)
{
  skip_ws(ps);
  if (ps->p >= ps->end)
    return fail(ps, SD_E_PROTOCOL);
  switch (*ps->p) {
  case '{': return parse_container(ps, v, depth, 1);
  case '[': return parse_container(ps, v, depth, 0);
  case '"':
    v->type = SD_JSON_STRING;
    return parse_string(ps, &v->str, &v->len);
  case 't': v->type = SD_JSON_BOOL; v->bval = 1; return literal(ps, "true");
  case 'f': v->type = SD_JSON_BOOL; v->bval = 0; return literal(ps, "false");
  case 'n': v->type = SD_JSON_NULL; return literal(ps, "null");
  default:
    return parse_number(ps, v);
  }
}

sd_err sd_json_parse(const char *utf8, size_t len, uint32_t max_depth, sd_json **out)
{
  json_doc *doc;
  json_parser ps;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if (utf8 == NULL && len != 0)
    return SD_E_INVALID_PARAM;
  doc = (json_doc *)sd_calloc(1, sizeof(*doc));
  if (doc == NULL)
    return SD_E_NO_MEMORY;
  ps.p = utf8;
  ps.end = utf8 + len;
  ps.max_depth = max_depth ? max_depth : 32;
  ps.arena = &doc->arena;
  ps.err = SD_OK;
  if (parse_value(&ps, &doc->root, 0)) {
    skip_ws(&ps);
    if (ps.p != ps.end)
      fail(&ps, SD_E_PROTOCOL);
  } else if (ps.err == SD_OK) {
    ps.err = SD_E_PROTOCOL;
  }
  if (ps.err != SD_OK) {
    arena_free(&doc->arena);
    sd_free(doc);
    return ps.err;
  }
  *out = &doc->root;
  return SD_OK;
}

void sd_json_free(sd_json *root)
{
  json_doc *doc;
  if (root == NULL)
    return;
  doc = (json_doc *)((uint8_t *)root - offsetof(json_doc, root));
  arena_free(&doc->arena);
  sd_free(doc);
}

sd_json_type sd_json_type_of(const sd_json *v)
{
  return v ? v->type : SD_JSON_NULL;
}

const sd_json *sd_json_get(const sd_json *obj, const char *key)
{
  size_t i, n;
  if (obj == NULL || obj->type != SD_JSON_OBJECT || key == NULL)
    return NULL;
  n = strlen(key);
  for (i = 0; i < obj->count; i++)
    if (obj->key_lens[i] == n && memcmp(obj->keys[i], key, n) == 0)
      return obj->items[i];
  return NULL;
}

size_t sd_json_count(const sd_json *v)
{
  if (v == NULL || (v->type != SD_JSON_ARRAY && v->type != SD_JSON_OBJECT))
    return 0;
  return v->count;
}

const sd_json *sd_json_at(const sd_json *v, size_t i)
{
  if (v == NULL || (v->type != SD_JSON_ARRAY && v->type != SD_JSON_OBJECT) || i >= v->count)
    return NULL;
  return v->items[i];
}

const char *sd_json_key_at(const sd_json *obj, size_t i)
{
  if (obj == NULL || obj->type != SD_JSON_OBJECT || i >= obj->count)
    return NULL;
  return obj->keys[i];
}

const char *sd_json_str(const sd_json *v, size_t *len)
{
  if (v == NULL || v->type != SD_JSON_STRING) {
    if (len) *len = 0;
    return NULL;
  }
  if (len) *len = v->len;
  return v->str;
}

int sd_json_int64(const sd_json *v, int64_t *out)
{
  if (v == NULL || v->type != SD_JSON_NUMBER || !v->is_int)
    return 0;
  if (out) *out = v->ival;
  return 1;
}

int sd_json_bool(const sd_json *v, int *out)
{
  if (v == NULL || v->type != SD_JSON_BOOL)
    return 0;
  if (out) *out = v->bval;
  return 1;
}

const char *sd_json_get_str(const sd_json *obj, const char *key)
{
  const sd_json *v = sd_json_get(obj, key);
  size_t n;
  const char *s = sd_json_str(v, &n);
  if (s == NULL || strlen(s) != n)
    return NULL;            /* absent, not a string, or embedded NUL */
  return s;
}

int sd_json_get_int64(const sd_json *obj, const char *key, int64_t *out)
{
  return sd_json_int64(sd_json_get(obj, key), out);
}

int sd_json_get_bool(const sd_json *obj, const char *key, int *out)
{
  return sd_json_bool(sd_json_get(obj, key), out);
}

/* ---- writer ----
 * state[d] for d >= 1 (an open container): bit 0 = object, bit 1 = has members, bit 2 = key written
 * and value pending. state[0] (top level): bit 1 = a value was written. */

#define JW_OBJ   1u
#define JW_ANY   2u
#define JW_KEY   4u
#define JW_MAX_DEPTH 31u

static void jw_put(sd_json_writer *jw, const char *s, size_t n)
{
  if (!jw->err)
    sd_wr_bytes(jw->out, s, n);
}

/* Called before every value: checks position and writes a separating comma. */
static int jw_before_value(sd_json_writer *jw)
{
  uint32_t *st;
  if (jw->err)
    return 0;
  st = &jw->state[jw->depth];
  if (jw->depth == 0) {
    if (*st & JW_ANY) { jw->err = 1; return 0; }
    *st |= JW_ANY;
    return 1;
  }
  if (*st & JW_OBJ) {
    if (!(*st & JW_KEY)) { jw->err = 1; return 0; }
    *st &= ~JW_KEY;
    *st |= JW_ANY;
    return 1;
  }
  if (*st & JW_ANY)
    jw_put(jw, ",", 1);
  *st |= JW_ANY;
  return 1;
}

void sd_jw_init(sd_json_writer *jw, sd_wr *out)
{
  memset(jw, 0, sizeof(*jw));
  jw->out = out;
  if (out == NULL)
    jw->err = 1;
}

static void jw_open(sd_json_writer *jw, int obj)
{
  if (!jw_before_value(jw))
    return;
  if (jw->depth >= JW_MAX_DEPTH) { jw->err = 1; return; }
  jw->depth++;
  jw->state[jw->depth] = obj ? JW_OBJ : 0;
  jw_put(jw, obj ? "{" : "[", 1);
}

static void jw_close(sd_json_writer *jw, int obj)
{
  uint32_t st;
  if (jw->err)
    return;
  if (jw->depth == 0) { jw->err = 1; return; }
  st = jw->state[jw->depth];
  if (((st & JW_OBJ) != 0) != (obj != 0) || (st & JW_KEY)) { jw->err = 1; return; }
  jw->depth--;
  jw_put(jw, obj ? "}" : "]", 1);
}

void sd_jw_obj_begin(sd_json_writer *jw) { jw_open(jw, 1); }
void sd_jw_obj_end(sd_json_writer *jw)   { jw_close(jw, 1); }
void sd_jw_arr_begin(sd_json_writer *jw) { jw_open(jw, 0); }
void sd_jw_arr_end(sd_json_writer *jw)   { jw_close(jw, 0); }

static void jw_string(sd_json_writer *jw, const char *s, size_t n)
{
  static const char hex[] = "0123456789abcdef";
  size_t i, run = 0;
  if (s == NULL && n != 0) { jw->err = 1; return; }
  if (!sd_utf8_valid(s, n)) { jw->err = 1; return; }
  jw_put(jw, "\"", 1);
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    const char *esc = NULL;
    char u[6];
    if (c == '"') esc = "\\\"";
    else if (c == '\\') esc = "\\\\";
    else if (c == '\n') esc = "\\n";
    else if (c == '\r') esc = "\\r";
    else if (c == '\t') esc = "\\t";
    else if (c < 0x20 || c == 0x7F) {
      u[0] = '\\'; u[1] = 'u'; u[2] = '0'; u[3] = '0'; u[4] = hex[c >> 4]; u[5] = hex[c & 15];
    } else {
      run++;
      continue;
    }
    if (run) jw_put(jw, s + i - run, run);
    run = 0;
    if (esc) jw_put(jw, esc, strlen(esc));
    else jw_put(jw, u, 6);
  }
  if (run) jw_put(jw, s + n - run, run);
  jw_put(jw, "\"", 1);
}

void sd_jw_key(sd_json_writer *jw, const char *key)
{
  uint32_t *st;
  if (jw->err)
    return;
  st = &jw->state[jw->depth];
  if (jw->depth == 0 || !(*st & JW_OBJ) || (*st & JW_KEY) || key == NULL) { jw->err = 1; return; }
  if (*st & JW_ANY)
    jw_put(jw, ",", 1);
  jw_string(jw, key, strlen(key));
  jw_put(jw, ":", 1);
  *st |= JW_KEY;
}

void sd_jw_str(sd_json_writer *jw, const char *utf8, size_t len)
{
  if (jw_before_value(jw))
    jw_string(jw, utf8, len);
}

void sd_jw_cstr(sd_json_writer *jw, const char *utf8)
{
  if (utf8 == NULL)
    sd_jw_null(jw);
  else
    sd_jw_str(jw, utf8, strlen(utf8));
}

void sd_jw_int(sd_json_writer *jw, int64_t v)
{
  char buf[24];
  size_t n = 0, i;
  uint64_t m = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
  char tmp[24];
  if (!jw_before_value(jw))
    return;
  do { tmp[n++] = (char)('0' + (m % 10u)); m /= 10u; } while (m);
  i = 0;
  if (v < 0) buf[i++] = '-';
  while (n) buf[i++] = tmp[--n];
  jw_put(jw, buf, i);
}

void sd_jw_bool(sd_json_writer *jw, int v)
{
  if (jw_before_value(jw))
    jw_put(jw, v ? "true" : "false", v ? 4 : 5);
}

void sd_jw_null(sd_json_writer *jw)
{
  if (jw_before_value(jw))
    jw_put(jw, "null", 4);
}

static void jw_copy(sd_json_writer *jw, const sd_json *v)
{
  size_t i;
  if (v == NULL) { sd_jw_null(jw); return; }
  switch (v->type) {
  case SD_JSON_NULL:   sd_jw_null(jw); break;
  case SD_JSON_BOOL:   sd_jw_bool(jw, v->bval); break;
  case SD_JSON_STRING: sd_jw_str(jw, v->str, v->len); break;
  case SD_JSON_NUMBER:
    if (jw_before_value(jw))
      jw_put(jw, v->str, v->len);
    break;
  case SD_JSON_ARRAY:
    sd_jw_arr_begin(jw);
    for (i = 0; i < v->count; i++)
      jw_copy(jw, v->items[i]);
    sd_jw_arr_end(jw);
    break;
  case SD_JSON_OBJECT:
    sd_jw_obj_begin(jw);
    for (i = 0; i < v->count; i++) {
      sd_jw_key(jw, v->keys[i]);
      jw_copy(jw, v->items[i]);
    }
    sd_jw_obj_end(jw);
    break;
  }
}

void sd_jw_value(sd_json_writer *jw, const sd_json *v)
{
  jw_copy(jw, v);
}

void sd_jw_raw(sd_json_writer *jw, const char *json, size_t len)
{
  sd_json *v = NULL;
  if (jw->err)
    return;
  if (sd_json_parse(json, len, JW_MAX_DEPTH - jw->depth, &v) != SD_OK) {
    jw->err = 1;
    return;
  }
  jw_copy(jw, v);
  sd_json_free(v);
}

sd_err sd_jw_finish(sd_json_writer *jw)
{
  if (jw->err || jw->depth != 0 || !(jw->state[0] & JW_ANY))
    return SD_E_INVALID_PARAM;
  if (!sd_wr_ok(jw->out))
    return SD_E_NO_MEMORY;
  return SD_OK;
}
