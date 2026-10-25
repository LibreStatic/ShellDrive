/* sdl10n: validates PO catalogs and compiles them into C message tables (03 §9.1, §9.2, §9.4; D26).
 *
 *   sdl10n --name <catalog> --out-c <file.c> --out-h <file.h> --domain <dir> [--domain <dir>...]
 *          [--allow-incomplete]
 *   sdl10n --check --domain <dir> [...] [--allow-incomplete]
 *
 * Each domain directory holds en.po (the source of truth) and es/fr/pt-BR/it/de.po. Checks (errors
 * fail with exit code 1):
 *   - every en entry has a unique msgctxt (the symbolic id) and a non-empty msgid;
 *   - every other locale has every entry, with the same msgid/msgid_plural as en, not fuzzy, with
 *     non-empty msgstr, and exactly one msgstr[n] per CLDR category of that language;
 *   - no entries that en does not have;
 *   - placeholder sets ({name}; "{{" and "}}" are escapes) equal to the English ones (the plural
 *     argument may be omitted in a form);
 *   - the Plural-Forms header equals the canonical expression of 03 §9.4;
 *   - all text is valid UTF-8.
 * --allow-incomplete downgrades only missing, empty, fuzzy and stale translations to warnings; those
 * slots are left NULL in the tables and fall back to English at run time.
 *
 * Plural argument: "#, plural-arg=<name>" on the en entry (default "count").
 * Build-time tool, never shipped: plain C with stdio. */
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FORMS 6
#define MAX_DOMAINS 16
#define NLANGS 6

enum { CAT_ZERO, CAT_ONE, CAT_TWO, CAT_FEW, CAT_MANY, CAT_OTHER };

typedef struct lang_def {
  const char *code;            /* file name stem */
  const char *ident;           /* C identifier part */
  int ncats;
  int cats[MAX_FORMS];         /* PO msgstr index -> CLDR category */
  const char *plural_forms;    /* canonical header value */
} lang_def;

static const lang_def g_langs[NLANGS] = {
  { "en",    "en",    2, { CAT_ONE, CAT_OTHER }, "nplurals=2; plural=(n != 1);" },
  { "es",    "es",    3, { CAT_ONE, CAT_MANY, CAT_OTHER },
    "nplurals=3; plural=(n == 1 ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);" },
  { "fr",    "fr",    3, { CAT_ONE, CAT_MANY, CAT_OTHER },
    "nplurals=3; plural=((n == 0 || n == 1) ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);" },
  { "pt-BR", "pt_br", 3, { CAT_ONE, CAT_MANY, CAT_OTHER },
    "nplurals=3; plural=((n == 0 || n == 1) ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);" },
  { "it",    "it",    3, { CAT_ONE, CAT_MANY, CAT_OTHER },
    "nplurals=3; plural=(n == 1 ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2);" },
  { "de",    "de",    2, { CAT_ONE, CAT_OTHER }, "nplurals=2; plural=(n != 1);" },
};

/* ---- small utilities ---- */

static int g_errors, g_warnings;

static void diag(int is_error, const char *file, int line, const char *fmt, ...)
{
  va_list ap;
  if (is_error) g_errors++; else g_warnings++;
  if (file)
    fprintf(stderr, "%s:%d: %s: ", file, line, is_error ? "error" : "warning");
  else
    fprintf(stderr, "sdl10n: %s: ", is_error ? "error" : "warning");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static void *xmalloc(size_t n)
{
  void *p = malloc(n ? n : 1);
  if (!p) { fprintf(stderr, "sdl10n: out of memory\n"); exit(2); }
  return p;
}

static char *xstrdup(const char *s)
{
  size_t n = strlen(s) + 1;
  char *d = (char *)xmalloc(n);
  memcpy(d, s, n);
  return d;
}

typedef struct strbuf { char *p; size_t len, cap; } strbuf;

static void sb_putc(strbuf *b, char c)
{
  if (b->len + 2 > b->cap) {
    size_t ncap = b->cap ? b->cap * 2 : 64;
    char *np = (char *)realloc(b->p, ncap);
    if (!np) { fprintf(stderr, "sdl10n: out of memory\n"); exit(2); }
    b->p = np;
    b->cap = ncap;
  }
  b->p[b->len++] = c;
  b->p[b->len] = 0;
}

static char *sb_take(strbuf *b)
{
  char *r = b->p ? b->p : xstrdup("");
  b->p = NULL;
  b->len = b->cap = 0;
  return r;
}

static int utf8_valid(const char *s)
{
  const unsigned char *u = (const unsigned char *)s;
  while (*u) {
    unsigned c = *u, cp, min;
    int len, i;
    if (c < 0x80) { u++; continue; }
    if (c < 0xC2) return 0;
    if (c < 0xE0) { len = 2; cp = c & 0x1F; min = 0x80; }
    else if (c < 0xF0) { len = 3; cp = c & 0x0F; min = 0x800; }
    else if (c < 0xF5) { len = 4; cp = c & 0x07; min = 0x10000; }
    else return 0;
    for (i = 1; i < len; i++) {
      if ((u[i] & 0xC0) != 0x80) return 0;
      cp = (cp << 6) | (u[i] & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    u += len;
  }
  return 1;
}

/* ---- PO model ---- */

typedef struct po_entry {
  int line;
  char *ctx, *id, *id_plural;
  char *str[MAX_FORMS];
  int nstr;                    /* number of msgstr[n] (plural) or 1 (plain msgstr) */
  int plural_strs;             /* msgstr[n] syntax used */
  int fuzzy;
  char *plural_arg;
} po_entry;

typedef struct po_file {
  const char *path;
  int present;
  po_entry *e;
  int count, cap;
  char *plural_forms;          /* header value, NULL if absent */
  int header_line;
} po_file;

static void entry_free(po_entry *e)
{
  int i;
  free(e->ctx); free(e->id); free(e->id_plural); free(e->plural_arg);
  for (i = 0; i < MAX_FORMS; i++) free(e->str[i]);
  memset(e, 0, sizeof(*e));
}

static char *read_file(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  char *buf;
  long n;
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = (char *)xmalloc((size_t)n + 1);
  if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
  fclose(f);
  buf[n] = 0;
  *len = (size_t)n;
  return buf;
}

/* Parses one "..." literal starting at *p, appending its unescaped bytes to b. */
static int parse_quoted(const char **pp, strbuf *b)
{
  const char *p = *pp;
  while (*p == ' ' || *p == '\t') p++;
  if (*p != '"') return 0;
  p++;
  while (*p && *p != '"') {
    char c = *p++;
    if (c == '\\') {
      c = *p++;
      switch (c) {
      case 'n': sb_putc(b, '\n'); break;
      case 't': sb_putc(b, '\t'); break;
      case 'r': sb_putc(b, '\r'); break;
      case '"': sb_putc(b, '"'); break;
      case '\\': sb_putc(b, '\\'); break;
      default: return 0;
      }
    } else {
      sb_putc(b, c);
    }
  }
  if (*p != '"') return 0;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\r') p++;
  if (*p != 0) return 0;
  *pp = p;
  return 1;
}

static char *header_field(const char *hdr, const char *name)
{
  size_t nl = strlen(name);
  const char *p = hdr;
  while (p && *p) {
    const char *eol = strchr(p, '\n');
    size_t ll = eol ? (size_t)(eol - p) : strlen(p);
    if (ll > nl && strncmp(p, name, nl) == 0 && p[nl] == ':') {
      const char *v = p + nl + 1;
      char *out;
      size_t vl;
      while (*v == ' ') v++;
      vl = (size_t)(p + ll - v);
      while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\r')) vl--;
      out = (char *)xmalloc(vl + 1);
      memcpy(out, v, vl);
      out[vl] = 0;
      return out;
    }
    p = eol ? eol + 1 : NULL;
  }
  return NULL;
}

static void po_push(po_file *f, po_entry *cur)
{
  if (!cur->id && !cur->ctx && cur->nstr == 0) {
    entry_free(cur);
    return;
  }
  if (!cur->id) {
    diag(1, f->path, cur->line, "entry without msgid");
    entry_free(cur);
    return;
  }
  if (!cur->ctx && cur->id[0] == 0) {              /* header */
    if (cur->str[0]) {
      f->plural_forms = header_field(cur->str[0], "Plural-Forms");
      f->header_line = cur->line;
    }
    entry_free(cur);
    return;
  }
  if (f->count == f->cap) {
    f->cap = f->cap ? f->cap * 2 : 32;
    po_entry *ne = (po_entry *)realloc(f->e, (size_t)f->cap * sizeof(po_entry));
    if (!ne) { fprintf(stderr, "sdl10n: out of memory\n"); exit(2); }
    f->e = ne;
  }
  f->e[f->count++] = *cur;
  memset(cur, 0, sizeof(*cur));
}

enum { K_NONE, K_CTX, K_ID, K_IDP, K_STR };

static void po_parse(po_file *f)
{
  size_t len;
  char *buf = read_file(f->path, &len), *line, *next;
  po_entry cur;
  strbuf sb = { 0 };
  int lineno = 0, kind = K_NONE, str_index = 0, have_str = 0;

  memset(&cur, 0, sizeof(cur));
  if (!buf) { f->present = 0; return; }
  f->present = 1;
  line = buf;
  if ((unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
    line += 3;

#define FLUSH_FIELD()                                                          \
  do {                                                                         \
    if (kind != K_NONE) {                                                      \
      char *v = sb_take(&sb);                                                  \
      if (kind == K_CTX) { free(cur.ctx); cur.ctx = v; }                       \
      else if (kind == K_ID) { free(cur.id); cur.id = v; }                     \
      else if (kind == K_IDP) { free(cur.id_plural); cur.id_plural = v; }      \
      else { free(cur.str[str_index]); cur.str[str_index] = v; }               \
      kind = K_NONE;                                                           \
    }                                                                          \
  } while (0)

  for (; line; line = next) {
    char *p;
    size_t ll;
    lineno++;
    next = strchr(line, '\n');
    if (next) *next++ = 0;
    ll = strlen(line);
    if (ll && line[ll - 1] == '\r') line[--ll] = 0;
    p = line;
    while (*p == ' ' || *p == '\t') p++;

    if (*p == 0) {                                     /* blank line ends an entry */
      FLUSH_FIELD();
      po_push(f, &cur);
      have_str = 0;
      continue;
    }
    if (*p == '#') {
      if (p[1] == '~') continue;                       /* obsolete */
      if (have_str) { FLUSH_FIELD(); po_push(f, &cur); have_str = 0; }
      if (!cur.line) cur.line = lineno;
      if (p[1] == ',') {
        char *tok = p + 2;
        while (*tok) {
          char *end;
          size_t tl;
          while (*tok == ' ' || *tok == ',') tok++;
          end = tok;
          while (*end && *end != ',' && *end != ' ') end++;
          tl = (size_t)(end - tok);
          if (tl == 5 && strncmp(tok, "fuzzy", 5) == 0) cur.fuzzy = 1;
          else if (tl > 11 && strncmp(tok, "plural-arg=", 11) == 0) {
            free(cur.plural_arg);
            cur.plural_arg = (char *)xmalloc(tl - 10);
            memcpy(cur.plural_arg, tok + 11, tl - 11);
            cur.plural_arg[tl - 11] = 0;
          }
          tok = end;
        }
      }
      continue;
    }
    if (*p == '"') {                                   /* continuation */
      if (kind == K_NONE || !parse_quoted((const char **)&p, &sb))
        diag(1, f->path, lineno, "unexpected or malformed string continuation");
      continue;
    }

    FLUSH_FIELD();
    {
      const char *q = p;
      int k = K_NONE, idx = 0;
      if (strncmp(q, "msgctxt", 7) == 0 && (q[7] == ' ' || q[7] == '\t')) { k = K_CTX; q += 7; }
      else if (strncmp(q, "msgid_plural", 12) == 0) { k = K_IDP; q += 12; }
      else if (strncmp(q, "msgid", 5) == 0 && (q[5] == ' ' || q[5] == '\t')) { k = K_ID; q += 5; }
      else if (strncmp(q, "msgstr[", 7) == 0) {
        k = K_STR; q += 7;
        idx = atoi(q);
        while (*q >= '0' && *q <= '9') q++;
        if (*q != ']' || idx < 0 || idx >= MAX_FORMS) { diag(1, f->path, lineno, "bad msgstr index"); continue; }
        q++;
        cur.plural_strs = 1;
      }
      else if (strncmp(q, "msgstr", 6) == 0 && (q[6] == ' ' || q[6] == '\t')) { k = K_STR; q += 6; }
      else { diag(1, f->path, lineno, "unknown keyword"); continue; }

      if ((k == K_CTX || k == K_ID) && have_str) {
        po_push(f, &cur);                              /* new entry without a blank line */
        have_str = 0;
      }
      if (!cur.line) cur.line = lineno;
      if (k == K_STR) {
        have_str = 1;
        if (idx + 1 > cur.nstr) cur.nstr = idx + 1;
      }
      kind = k;
      str_index = idx;
      if (!parse_quoted(&q, &sb))
        diag(1, f->path, lineno, "malformed string literal");
    }
  }
  FLUSH_FIELD();
  po_push(f, &cur);
#undef FLUSH_FIELD
  free(buf);
}

/* ---- placeholders ---- */

typedef struct ph_set { char *names[32]; int n; } ph_set;

static void ph_free(ph_set *s)
{
  int i;
  for (i = 0; i < s->n; i++) free(s->names[i]);
  s->n = 0;
}

static int ph_has(const ph_set *s, const char *name)
{
  int i;
  for (i = 0; i < s->n; i++) if (strcmp(s->names[i], name) == 0) return 1;
  return 0;
}

/* Returns 0 on malformed braces. */
static int ph_extract(const char *s, ph_set *out)
{
  out->n = 0;
  while (*s) {
    if (s[0] == '{' && s[1] == '{') { s += 2; continue; }
    if (s[0] == '}' && s[1] == '}') { s += 2; continue; }
    if (*s == '}') return 0;
    if (*s == '{') {
      const char *e = s + 1;
      char *name;
      while ((*e >= 'a' && *e <= 'z') || (*e >= '0' && *e <= '9') || *e == '_') e++;
      if (*e != '}' || e == s + 1) return 0;
      name = (char *)xmalloc((size_t)(e - s));
      memcpy(name, s + 1, (size_t)(e - s - 1));
      name[e - s - 1] = 0;
      if (!ph_has(out, name) && out->n < 32) out->names[out->n++] = name; else free(name);
      s = e + 1;
      continue;
    }
    s++;
  }
  return 1;
}

/* 1 if `got` equals `want`, except that `optional` may be missing from got. */
static int ph_equal(const ph_set *want, const ph_set *got, const char *optional)
{
  int i;
  for (i = 0; i < got->n; i++) if (!ph_has(want, got->names[i])) return 0;
  for (i = 0; i < want->n; i++)
    if (!ph_has(got, want->names[i]) && !(optional && strcmp(want->names[i], optional) == 0)) return 0;
  return 1;
}

/* ---- catalog model ---- */

typedef struct msg {
  char *key;
  char *plural_arg;                 /* NULL = not plural */
  const char *forms[NLANGS][MAX_FORMS];   /* by CLDR category */
} msg;

static msg *g_msgs;
static int g_nmsgs, g_capmsgs;
static unsigned g_complete_mask = (1u << NLANGS) - 1;

static int find_entry(const po_file *f, const char *ctx)
{
  int i;
  for (i = 0; i < f->count; i++) if (f->e[i].ctx && strcmp(f->e[i].ctx, ctx) == 0) return i;
  return -1;
}

static int valid_key(const char *k)
{
  if (!*k) return 0;
  for (; *k; k++)
    if (!((*k >= 'a' && *k <= 'z') || (*k >= '0' && *k <= '9') || *k == '_' || *k == '.' || *k == '-'))
      return 0;
  return 1;
}

static void check_strings_utf8(const po_file *f)
{
  int i, j;
  for (i = 0; i < f->count; i++) {
    const po_entry *e = &f->e[i];
    if ((e->ctx && !utf8_valid(e->ctx)) || !utf8_valid(e->id) || (e->id_plural && !utf8_valid(e->id_plural)))
      diag(1, f->path, e->line, "invalid UTF-8");
    for (j = 0; j < MAX_FORMS; j++)
      if (e->str[j] && !utf8_valid(e->str[j])) diag(1, f->path, e->line, "invalid UTF-8 in msgstr");
  }
}

static void process_domain(const char *dir, int allow_incomplete)
{
  po_file files[NLANGS];
  int li, i, j;
  memset(files, 0, sizeof(files));

  for (li = 0; li < NLANGS; li++) {
    size_t n = strlen(dir) + strlen(g_langs[li].code) + 8;
    char *path = (char *)xmalloc(n);
    snprintf(path, n, "%s/%s.po", dir, g_langs[li].code);
    files[li].path = path;
    po_parse(&files[li]);
    if (!files[li].present) {
      if (li == 0 || !allow_incomplete) diag(1, path, 0, "catalog file missing");
      else diag(0, path, 0, "catalog file missing (allowed by --allow-incomplete)");
      if (li != 0) g_complete_mask &= ~(1u << li);
      continue;
    }
    check_strings_utf8(&files[li]);
    if (!files[li].plural_forms)
      diag(1, path, 1, "missing Plural-Forms header");
    else if (strcmp(files[li].plural_forms, g_langs[li].plural_forms) != 0)
      diag(1, path, files[li].header_line, "Plural-Forms must be \"%s\" (03 §9.4), got \"%s\"",
           g_langs[li].plural_forms, files[li].plural_forms);
  }
  if (!files[0].present)
    return;

  /* English source entries. */
  for (i = 0; i < files[0].count; i++) {
    po_entry *e = &files[0].e[i];
    msg *m;
    ph_set want, got;
    const char *optional;
    if (!e->ctx || !valid_key(e->ctx)) {
      diag(1, files[0].path, e->line, "en entries need a msgctxt id made of [a-z0-9_.-]");
      continue;
    }
    if (e->id[0] == 0) { diag(1, files[0].path, e->line, "empty msgid"); continue; }
    for (j = 0; j < g_nmsgs; j++)
      if (strcmp(g_msgs[j].key, e->ctx) == 0) diag(1, files[0].path, e->line, "duplicate id '%s'", e->ctx);
    if (e->fuzzy) diag(1, files[0].path, e->line, "fuzzy entry in the en source");
    if (g_nmsgs == g_capmsgs) {
      g_capmsgs = g_capmsgs ? g_capmsgs * 2 : 32;
      msg *nm = (msg *)realloc(g_msgs, (size_t)g_capmsgs * sizeof(msg));
      if (!nm) { fprintf(stderr, "sdl10n: out of memory\n"); exit(2); }
      g_msgs = nm;
    }
    m = &g_msgs[g_nmsgs++];
    memset(m, 0, sizeof(*m));
    m->key = xstrdup(e->ctx);
    if (e->id_plural) {
      m->plural_arg = xstrdup(e->plural_arg ? e->plural_arg : "count");
      m->forms[0][CAT_ONE] = e->id;
      m->forms[0][CAT_OTHER] = e->id_plural;
    } else {
      m->forms[0][CAT_OTHER] = e->id;
    }
    if (!ph_extract(e->id, &want) || (e->id_plural && !ph_extract(e->id_plural, &got))) {
      diag(1, files[0].path, e->line, "malformed placeholder in msgid");
      continue;
    }
    if (e->id_plural) {
      ph_set u;
      ph_extract(e->id_plural, &u);
      if (!ph_equal(&u, &want, m->plural_arg))
        diag(1, files[0].path, e->line, "msgid and msgid_plural use different placeholders");
      ph_free(&want);
      want = u;
      ph_free(&got);
      if (!ph_has(&want, m->plural_arg))
        diag(1, files[0].path, e->line, "msgid_plural lacks the plural argument {%s}", m->plural_arg);
    }
    optional = m->plural_arg;

    /* Translations. */
    for (li = 1; li < NLANGS; li++) {
      po_file *f = &files[li];
      int k, missing = 0;
      po_entry *t;
      if (!f->present) continue;
      k = find_entry(f, e->ctx);
      if (k < 0) {
        diag(!allow_incomplete, f->path, 0, "missing translation for '%s'", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      t = &f->e[k];
      if (strcmp(t->id, e->id) != 0 || (e->id_plural == NULL) != (t->id_plural == NULL) ||
          (e->id_plural && strcmp(t->id_plural, e->id_plural) != 0)) {
        diag(!allow_incomplete, f->path, t->line, "stale translation for '%s': msgid differs from en", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      if (t->fuzzy) {
        diag(!allow_incomplete, f->path, t->line, "fuzzy translation for '%s'", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      if (e->id_plural) {
        if (!t->plural_strs || t->nstr != g_langs[li].ncats) {
          diag(1, f->path, t->line, "'%s' needs exactly %d plural forms (msgstr[0..%d]) for %s",
               e->ctx, g_langs[li].ncats, g_langs[li].ncats - 1, g_langs[li].code);
          continue;
        }
      } else if (t->plural_strs) {
        diag(1, f->path, t->line, "'%s' is not a plural entry", e->ctx);
        continue;
      }
      for (j = 0; j < t->nstr; j++)
        if (!t->str[j] || !t->str[j][0]) missing = 1;
      if (missing) {
        diag(!allow_incomplete, f->path, t->line, "empty translation for '%s'", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      for (j = 0; j < t->nstr; j++) {
        ph_set ps;
        if (!ph_extract(t->str[j], &ps) || !ph_equal(&want, &ps, e->id_plural ? optional : NULL))
          diag(1, f->path, t->line, "placeholders of '%s' (form %d) differ from en", e->ctx, j);
        ph_free(&ps);
        m->forms[li][e->id_plural ? g_langs[li].cats[j] : CAT_OTHER] = t->str[j];
      }
    }
    ph_free(&want);
  }

  /* Entries that en does not have. */
  for (li = 1; li < NLANGS; li++) {
    for (i = 0; i < files[li].count; i++) {
      po_entry *t = &files[li].e[i];
      if (!t->ctx || find_entry(&files[0], t->ctx) < 0)
        diag(1, files[li].path, t->line, "entry '%s' does not exist in en.po", t->ctx ? t->ctx : "(no msgctxt)");
    }
  }
  /* PO data stays allocated: g_msgs points into it until the process exits. */
}

/* ---- output ---- */

static void emit_cstr(FILE *o, const char *s)
{
  if (!s) { fputs("NULL", o); return; }
  fputc('"', o);
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') fprintf(o, "\\%c", c);
    else if (c < 0x20 || c >= 0x7F) fprintf(o, "\\%03o", c);
    else fputc(c, o);
  }
  fputc('"', o);
}

static void make_ident(const char *key, char *out, size_t cap, int upper)
{
  size_t i;
  for (i = 0; key[i] && i + 1 < cap; i++) {
    char c = key[i];
    if (c == '.' || c == '-') c = '_';
    else if (upper && c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    out[i] = c;
  }
  out[i] = 0;
}

static int write_outputs(const char *name, const char *out_c, const char *out_h)
{
  FILE *h, *c;
  char NAME[64], ident[128], base[512];
  const char *slash;
  int i, li, k;

  make_ident(name, NAME, sizeof(NAME), 1);
  h = fopen(out_h, "wb");
  if (!h) { diag(1, NULL, 0, "cannot write %s", out_h); return 0; }
  fprintf(h, "/* Generated by tools/sdl10n from l10n/ PO files. Do not edit. */\n");
  fprintf(h, "#ifndef SD_L10N_%s_IDS_H\n#define SD_L10N_%s_IDS_H\n\n", NAME, NAME);
  fprintf(h, "#include \"sd_l10n/sd_l10n_catalog.h\"\n\n");
  for (i = 0; i < g_nmsgs; i++) {
    make_ident(g_msgs[i].key, ident, sizeof(ident), 1);
    fprintf(h, "#define SD_MSG_%s ((sd_msg_id)%d)\n", ident, i);
  }
  fprintf(h, "\n#define SD_MSG_COUNT_%s %d\n\n", NAME, g_nmsgs);
  fprintf(h, "extern const sd_l10n_catalog sd_l10n_catalog_%s;\n\n#endif\n", name);
  fclose(h);

  c = fopen(out_c, "wb");
  if (!c) { diag(1, NULL, 0, "cannot write %s", out_c); return 0; }
  slash = strrchr(out_h, '/');
  if (!slash) slash = strrchr(out_h, '\\');
  snprintf(base, sizeof(base), "%s", slash ? slash + 1 : out_h);
  fprintf(c, "/* Generated by tools/sdl10n from l10n/ PO files. Do not edit. */\n");
  fprintf(c, "#include <stddef.h>\n\n#include \"%s\"\n\n", base);
  fprintf(c, "static const char *const k_keys[] = {\n");
  if (g_nmsgs == 0) fprintf(c, "  NULL,\n");
  for (i = 0; i < g_nmsgs; i++) { fputs("  ", c); emit_cstr(c, g_msgs[i].key); fputs(",\n", c); }
  fprintf(c, "};\n\nstatic const char *const k_plural_arg[] = {\n");
  if (g_nmsgs == 0) fprintf(c, "  NULL,\n");
  for (i = 0; i < g_nmsgs; i++) { fputs("  ", c); emit_cstr(c, g_msgs[i].plural_arg); fputs(",\n", c); }
  fprintf(c, "};\n");
  for (li = 0; li < NLANGS; li++) {
    fprintf(c, "\nstatic const char *const k_%s[] = {\n", g_langs[li].ident);
    if (g_nmsgs == 0) fprintf(c, "  NULL,\n");
    for (i = 0; i < g_nmsgs; i++) {
      fprintf(c, "  /* %s */\n", g_msgs[i].key);
      for (k = 0; k < MAX_FORMS; k++) {
        fputs("  ", c);
        emit_cstr(c, g_msgs[i].forms[li][k]);
        fputs(",\n", c);
      }
    }
    fprintf(c, "};\n");
  }
  fprintf(c, "\nconst sd_l10n_catalog sd_l10n_catalog_%s = {\n", name);
  fprintf(c, "  SD_L10N_CATALOG_ABI,\n  %d,\n  \"%s\",\n  k_keys,\n  k_plural_arg,\n  {", g_nmsgs, name);
  for (li = 0; li < NLANGS; li++) fprintf(c, " k_%s%s", g_langs[li].ident, li + 1 < NLANGS ? "," : " ");
  fprintf(c, "},\n  0x%02xu\n};\n", g_complete_mask);
  fclose(c);
  return 1;
}

static void usage(void)
{
  fprintf(stderr,
          "usage: sdl10n --name <catalog> --out-c <file.c> --out-h <file.h> --domain <dir>... [--allow-incomplete]\n"
          "       sdl10n --check --domain <dir>... [--allow-incomplete]\n");
}

int main(int argc, char **argv)
{
  const char *name = NULL, *out_c = NULL, *out_h = NULL;
  const char *domains[MAX_DOMAINS];
  int ndomains = 0, check = 0, allow = 0, i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
    else if (strcmp(argv[i], "--out-c") == 0 && i + 1 < argc) out_c = argv[++i];
    else if (strcmp(argv[i], "--out-h") == 0 && i + 1 < argc) out_h = argv[++i];
    else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc && ndomains < MAX_DOMAINS) domains[ndomains++] = argv[++i];
    else if (strcmp(argv[i], "--check") == 0) check = 1;
    else if (strcmp(argv[i], "--allow-incomplete") == 0) allow = 1;
    else { usage(); return 2; }
  }
  if (ndomains == 0 || (!check && (!name || !out_c || !out_h))) { usage(); return 2; }
  if (name) {
    const char *p;
    for (p = name; *p; p++)
      if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) { usage(); return 2; }
  }

  for (i = 0; i < ndomains; i++)
    process_domain(domains[i], allow);

  if (g_errors) {
    fprintf(stderr, "sdl10n: %d error(s), %d warning(s); catalog not generated. "
                    "Translate the missing strings (configure with -DSD_L10N_ALLOW_INCOMPLETE=ON "
                    "only for local development).\n", g_errors, g_warnings);
    return 1;
  }
  if (!check && !write_outputs(name, out_c, out_h))
    return 1;
  if (g_warnings)
    fprintf(stderr, "sdl10n: %d warning(s); incomplete locales fall back to English.\n", g_warnings);
  return 0;
}
