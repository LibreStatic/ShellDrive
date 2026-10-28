/* sdl10n: validates PO catalogs and compiles them into C message tables (03 §9.1, §9.2, §9.4; D26).
 *
 *   sdl10n --name <catalog> --out-c <file.c> --out-h <file.h> --domain <dir> [--domain <dir>...]
 *          [--allow-incomplete] [--qps]
 *   sdl10n --out-mc <file.mc> --domain <dir>
 *   sdl10n --check --domain <dir> [...] [--allow-incomplete]
 *
 * Each domain directory is l10n/<domain>/ and holds en.po (the source of truth) and es/fr/pt-BR/it/de.po.
 * A domain may hold header-only files (an empty catalog). Checks (errors fail with exit code 1):
 *   - every en entry has a unique msgctxt (the symbolic id) and a non-empty msgid;
 *   - every other locale has every entry, with the same msgid/msgid_plural as en, not fuzzy, with
 *     non-empty msgstr, and exactly one msgstr[n] per CLDR category of that language;
 *   - no entries that en does not have;
 *   - placeholder sets ({name}; "{{" and "}}" are escapes) equal to the English ones (the plural
 *     argument may be omitted in a form);
 *   - the Plural-Forms header equals the canonical expression of 03 §9.4;
 *   - all text is valid UTF-8;
 *   - register (lint, per language, see k_register): a translation uses a word of the wrong
 *     register; a per-entry opt-out is the translator comment "#. sdl10n:register-ok";
 *   - mnemonics: a translation drops the "&X" mnemonic that the English source has (error);
 *     within one mnemonic group, a letter used twice in one string or by two entries is a warning;
 *   - length: "#. sdl10n:maxlen=N" on the en entry limits every translation of it to N-1 UTF-16 units
 *     (N is the buffer size including the terminating NUL, as in 03 §7).
 * Mnemonic group: the msgctxt prefix up to its last '.' ("menu.file.open" and "menu.file.save" are
 * in group "menu.file"; "cli" entries without a dot share the group "").
 * --allow-incomplete downgrades only missing, empty, fuzzy and stale translations to warnings; those
 * slots are left NULL in the tables and fall back to English at run time.
 * --qps adds the build-only pseudo-locale qps-ploc, generated from en (03 §9.1); --no-qps (the
 * default, also written by CMake for Release) leaves it out.
 *
 * Event Log messages (03 §10.3): "#. sdl10n:event=<id>,<Severity>,<SYMBOL>" on the en entry makes it a message
 * of the Event Log table. Such an entry is plain (no plural), must exist in every locale without fuzzy or empty
 * strings (--allow-incomplete does not relax this), and every translation must use the %N placeholders of en
 * in the same order. --out-mc writes that table as a UTF-16LE .mc source for mc.exe -u.
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
#define NPO_LANGS 6            /* languages read from l10n/<domain>/<lang>.po */
#define LANG_QPS 6             /* the generated pseudo-locale, a table slot only */
#define NLANGS 7

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
  { "qps-ploc", "qps_ploc", 2, { CAT_ONE, CAT_OTHER }, "nplurals=2; plural=(n != 1);" },
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
  int register_ok;             /* translator comment sdl10n:register-ok */
  int maxlen;                  /* translator comment sdl10n:maxlen=N, 0 = none */
  char *plural_arg;
  int event_id;                /* sdl10n:event=<id>,<Severity>,<SYMBOL>; 0 = not an Event Log message */
  char event_sev[16];
  char event_sym[64];
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

/* Translator comment "#. ...": sdl10n:register-ok and sdl10n:maxlen=N (03 §9.2). */
static void po_comment(po_file *f, po_entry *cur, const char *text, int lineno)
{
  const char *m = strstr(text, "sdl10n:register-ok");
  if (m) cur->register_ok = 1;
  m = strstr(text, "sdl10n:maxlen=");
  if (m) {
    int v = atoi(m + 14);
    if (v <= 0) diag(1, f->path, lineno, "sdl10n:maxlen needs a positive number");
    else cur->maxlen = v;
  }
  m = strstr(text, "sdl10n:event=");
  if (m) {
    int id = 0;
    char sev[16], sym[64];
    if (sscanf(m + 13, "%d,%15[A-Za-z],%63[A-Z0-9_]", &id, sev, sym) != 3 || id < 1 || id > 0xFFFF)
      diag(1, f->path, lineno, "sdl10n:event needs <id 1-65535>,<Severity>,<SYMBOL>");
    else {
      cur->event_id = id;
      snprintf(cur->event_sev, sizeof(cur->event_sev), "%s", sev);
      snprintf(cur->event_sym, sizeof(cur->event_sym), "%s", sym);
    }
  }
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
      if (p[1] == '.') po_comment(f, &cur, p + 2, lineno);
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

/* ---- register lint (03 §9.2, AGENTS.md) ---- */

/* Conservative word lists. Words are ASCII-case-insensitive unless exact_case; sentence_start words
   count only as the first word of a sentence. Non-ASCII bytes belong to words. "tu" and "tus"
   (possessive, Rioplatense voseo) and "su" are not flagged. The lint warns about likely mistakes;
   reviewers decide the rest. */
typedef struct reg_rule {
  const char *word;
  int sentence_start;
  int exact_case;
} reg_rule;

static const reg_rule k_reg_es[] = {          /* voseo: no tu/usted forms */
  { "usted", 0, 0 }, { "ustedes", 0, 0 }, { "t\xc3\xba", 0, 0 },
  { "elija", 0, 0 }, { "seleccione", 0, 0 }, { "haga", 0, 0 }, { "ingrese", 0, 0 },
  { "intente", 0, 0 }, { "verifique", 0, 0 }, { "introduzca", 0, 0 },
  { "elige", 1, 0 }, { "haz", 1, 0 }, { "pulsa", 1, 0 }, { "introduce", 1, 0 },
  { "selecciona", 1, 0 }, { "ingresa", 1, 0 },
};
static const reg_rule k_reg_fr[] = {          /* vous */
  { "tu", 0, 0 }, { "ton", 0, 0 }, { "ta", 0, 0 }, { "tes", 0, 0 },
  { "s\xc3\xa9lectionne", 1, 0 }, { "saisis", 1, 0 }, { "clique", 1, 0 }, { "choisis", 1, 0 },
  { "ouvre", 1, 0 }, { "tape", 1, 0 }, { "v\xc3\xa9rifie", 1, 0 },
};
static const reg_rule k_reg_de[] = {          /* Sie / Ihr: capitalized forms only */
  { "Sie", 0, 1 }, { "Ihr", 0, 1 }, { "Ihre", 0, 1 }, { "Ihrem", 0, 1 }, { "Ihren", 0, 1 },
  { "Ihrer", 0, 1 }, { "Ihres", 0, 1 }, { "Ihnen", 0, 1 },
};
static const reg_rule k_reg_it[] = {          /* informal imperative: Lei and formal imperatives */
  { "Lei", 0, 1 }, { "prema", 0, 0 }, { "selezioni", 0, 0 }, { "inserisca", 0, 0 },
  { "verifichi", 0, 0 }, { "scelga", 0, 0 }, { "digiti", 0, 0 }, { "immetta", 0, 0 },
};

typedef struct reg_set { const reg_rule *rules; size_t n; } reg_set;

/* Indexed like g_langs; en and pt-BR have no rules. */
static const reg_set k_register[NPO_LANGS] = {
  { NULL, 0 },
  { k_reg_es, sizeof(k_reg_es) / sizeof(k_reg_es[0]) },
  { k_reg_fr, sizeof(k_reg_fr) / sizeof(k_reg_fr[0]) },
  { NULL, 0 },
  { k_reg_it, sizeof(k_reg_it) / sizeof(k_reg_it[0]) },
  { k_reg_de, sizeof(k_reg_de) / sizeof(k_reg_de[0]) },
};

static int is_word_byte(unsigned char c)
{
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c >= 0x80;
}

static int lower_ascii(int c)
{
  return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static int word_equal(const char *a, const char *b, size_t n, int exact_case)
{
  size_t i;
  for (i = 0; i < n; i++) {
    int x = (unsigned char)a[i], y = (unsigned char)b[i];
    if (!exact_case) { x = lower_ascii(x); y = lower_ascii(y); }
    if (x != y) return 0;
  }
  return 1;
}

/* First rule that matches a word of s, or NULL. Text inside {placeholders} is skipped. */
static const reg_rule *register_hit(const char *s, const reg_rule *rules, size_t nrules)
{
  const char *p = s;
  int sent = 1;
  while (*p) {
    unsigned char c = (unsigned char)*p;
    if (c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '(' || c == '[') { p++; continue; }
    if (c == '.' || c == '!' || c == '?' || c == ':' || c == ';' || c == '\n') { sent = 1; p++; continue; }
    if (c == '{') {
      while (*p && *p != '}') p++;
      if (*p) p++;
      sent = 0;
      continue;
    }
    if (is_word_byte(c)) {
      const char *b = p;
      size_t i, n;
      while (is_word_byte((unsigned char)*p)) p++;
      n = (size_t)(p - b);
      for (i = 0; i < nrules; i++) {
        const reg_rule *r = &rules[i];
        if (strlen(r->word) == n && (!r->sentence_start || sent) && word_equal(b, r->word, n, r->exact_case))
          return r;
      }
      sent = 0;
      continue;
    }
    sent = 0;
    p++;
  }
  return NULL;
}

/* ---- mnemonics (03 §9.2) ---- */

/* Bit of a mnemonic letter or digit: a-z = 0..25, 0-9 = 26..35; -1 for anything else. */
static int mn_bit(int c)
{
  c = lower_ascii(c);
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '0' && c <= '9') return 26 + c - '0';
  return -1;
}

static char mn_char(int bit)
{
  return (char)(bit < 26 ? 'a' + bit : '0' + bit - 26);
}

/* Mnemonics of s as a bit set over mn_bit. "&&" is a literal ampersand. *dup receives the first bit
   that s uses twice, or -1. */
static unsigned long long mnemonic_mask(const char *s, int *dup)
{
  unsigned long long mask = 0;
  const char *p;
  *dup = -1;
  for (p = s; *p; p++) {
    int b;
    if (*p != '&') continue;
    if (p[1] == '&') { p++; continue; }
    b = mn_bit((unsigned char)p[1]);
    if (b < 0) continue;
    if ((mask & (1ULL << b)) && *dup < 0) *dup = b;
    mask |= 1ULL << b;
    p++;
  }
  return mask;
}

static int has_mnemonic(const char *s)
{
  int dup;
  return mnemonic_mask(s, &dup) != 0;
}

/* Mnemonic group of a msgctxt: the prefix up to its last '.' (length 0 when there is no dot). */
static size_t group_len(const char *ctx)
{
  const char *dot = strrchr(ctx, '.');
  return dot ? (size_t)(dot - ctx) : 0;
}

static int same_group(const char *a, const char *b)
{
  size_t n = group_len(a);
  return n == group_len(b) && strncmp(a, b, n) == 0;
}

/* The texts of an entry: id and id_plural for the en source, the msgstr[] forms otherwise. */
static int entry_forms(const po_entry *e, int is_source, const char **out)
{
  int n = 0, k;
  if (is_source) {
    out[n++] = e->id;
    if (e->id_plural) out[n++] = e->id_plural;
    return n;
  }
  for (k = 0; k < e->nstr && k < MAX_FORMS; k++)
    if (e->str[k]) out[n++] = e->str[k];
  return n;
}

/* Warns when one string uses a mnemonic twice, or two entries of one group share a mnemonic. */
static void check_mnemonics(const po_file *f, int is_source)
{
  unsigned long long *masks;
  int i, j, k, bit;
  if (f->count == 0) return;
  masks = (unsigned long long *)xmalloc((size_t)f->count * sizeof(*masks));
  for (i = 0; i < f->count; i++) {
    const po_entry *e = &f->e[i];
    const char *forms[MAX_FORMS];
    int n = entry_forms(e, is_source, forms);
    masks[i] = 0;
    if (!e->ctx) continue;
    for (k = 0; k < n; k++) {
      int dup;
      masks[i] |= mnemonic_mask(forms[k], &dup);
      if (dup >= 0)
        diag(0, f->path, e->line, "'%s' uses the &%c mnemonic twice in one string", e->ctx, mn_char(dup));
    }
  }
  for (i = 0; i < f->count; i++) {
    for (j = 0; j < i; j++) {
      const po_entry *a = &f->e[i], *b = &f->e[j];
      unsigned long long common;
      if (!a->ctx || !b->ctx || !same_group(a->ctx, b->ctx)) continue;
      common = masks[i] & masks[j];
      for (bit = 0; bit < 36; bit++)
        if (common & (1ULL << bit)) {
          diag(0, f->path, a->line, "'%s' and '%s' share the &%c mnemonic in group '%.*s'",
               a->ctx, b->ctx, mn_char(bit), (int)group_len(a->ctx), a->ctx);
          break;
        }
    }
  }
  free(masks);
}

/* ---- length limits (sdl10n:maxlen, 03 §7) ---- */

/* UTF-16 code units of a UTF-8 string (NOTIFYICONDATAW sizes count these). */
static size_t utf16_units(const char *s)
{
  const unsigned char *u = (const unsigned char *)s;
  size_t n = 0;
  for (; *u; u++) {
    if ((*u & 0xC0) != 0x80) n++;
    if (*u >= 0xF0) n++;
  }
  return n;
}

static void check_maxlen(const char *path, int line, const char *ctx, const char *text, int form, int maxlen)
{
  size_t units;
  if (maxlen <= 0 || text == NULL) return;
  units = utf16_units(text);
  if (units > (size_t)(maxlen - 1))
    diag(1, path, line, "'%s' form %d is %lu UTF-16 units; sdl10n:maxlen=%d allows %d (the limit counts the NUL)",
         ctx, form, (unsigned long)units, maxlen, maxlen - 1);
}

/* ---- Event Log placeholders (03 §10.3): %N tokens in order of appearance ---- */

/* Stores the numbers of the %N tokens of s in out (at most max) and returns their count. A bare '%' or a
   token that is not %<digits> makes it return -1; "%%" is a literal percent sign. */
static int pct_seq(const char *s, int *out, int max)
{
  int n = 0;
  const char *p;
  for (p = s; *p; p++) {
    long v = 0;
    if (*p != '%') continue;
    if (p[1] == '%') { p++; continue; }
    if (p[1] < '0' || p[1] > '9') return -1;
    for (p++; *p >= '0' && *p <= '9'; p++) {
      v = v * 10 + (*p - '0');
      if (v > 100000) return -1;
    }
    p--;
    if (n == max) return -1;
    out[n++] = (int)v;
  }
  return n;
}

/* ---- qps-ploc pseudo-locale (03 §9.1) ---- */

/* Accented look-alikes of a-z and A-Z (code points, so this file stays ASCII). */
static const unsigned short k_qps_lower[26] = {
  0xE5, 0x180, 0xE7, 0xF0, 0xE9, 0x192, 0x11D, 0x125, 0xED, 0x135, 0x137, 0x13C, 0x1E3F,
  0xF1, 0xF6, 0xFE, 'q', 0x155, 0x161, 0x163, 0xFC, 0x1E7D, 0x175, 0x1E8B, 0xFD, 0x17E
};
static const unsigned short k_qps_upper[26] = {
  0xC5, 0x181, 0xC7, 0xD0, 0xC9, 0x191, 0x11C, 0x124, 0xCD, 0x134, 0x136, 0x13B, 0x1E3E,
  0xD1, 0xD6, 0xDE, 'Q', 0x154, 0x160, 0x162, 0xDC, 0x1E7C, 0x174, 0x1E8A, 0xDD, 0x17D
};

static void sb_utf8(strbuf *b, unsigned cp)
{
  if (cp < 0x80) {
    sb_putc(b, (char)cp);
  } else if (cp < 0x800) {
    sb_putc(b, (char)(0xC0 | (cp >> 6)));
    sb_putc(b, (char)(0x80 | (cp & 0x3F)));
  } else {
    sb_putc(b, (char)(0xE0 | (cp >> 12)));
    sb_putc(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
    sb_putc(b, (char)(0x80 | (cp & 0x3F)));
  }
}

/* The pseudo-translation of one English template: "[" + accented text + ~ padding (40 %) + "]".
   Placeholders, {{ and }} escapes and the letter after an & mnemonic are copied unchanged. */
static char *qps_text(const char *src)
{
  strbuf b = { 0 };
  const char *p = src;
  size_t n = 0, pad, i;
  sb_putc(&b, '[');
  while (*p) {
    unsigned char c = (unsigned char)*p;
    if ((c == '{' && p[1] == '{') || (c == '}' && p[1] == '}')) {
      sb_putc(&b, (char)c);
      sb_putc(&b, (char)c);
      p += 2;
      n++;
      continue;
    }
    if (c == '{') {
      while (*p && *p != '}') sb_putc(&b, *p++);
      if (*p) sb_putc(&b, *p++);
      continue;
    }
    if (c == '&' && p[1] == '&') {
      sb_putc(&b, '&');
      sb_putc(&b, '&');
      p += 2;
      n++;
      continue;
    }
    if (c == '&' && p[1]) {
      sb_putc(&b, '&');
      sb_putc(&b, p[1]);
      p += 2;
      continue;
    }
    if (c >= 'a' && c <= 'z') sb_utf8(&b, k_qps_lower[c - 'a']);
    else if (c >= 'A' && c <= 'Z') sb_utf8(&b, k_qps_upper[c - 'A']);
    else sb_putc(&b, (char)c);
    if ((c & 0xC0) != 0x80) n++;
    p++;
  }
  pad = (2 * n + 4) / 5;
  for (i = 0; i < pad; i++) sb_putc(&b, '~');
  sb_putc(&b, ']');
  return sb_take(&b);
}

/* ---- catalog model ---- */

typedef struct msg {
  char *key;
  char *plural_arg;                 /* NULL = not plural */
  const char *forms[NLANGS][MAX_FORMS];   /* by CLDR category */
  int event_id;                     /* Event Log message id, 0 = none */
  char event_sev[16];
  char event_sym[64];
} msg;

static msg *g_msgs;
static int g_nmsgs, g_capmsgs;
static unsigned g_complete_mask = (1u << NPO_LANGS) - 1;
static int g_qps;                 /* --qps: emit the qps-ploc table */

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

static void qps_forms(msg *m)
{
  int cat;
  for (cat = 0; cat < MAX_FORMS; cat++)
    if (m->forms[0][cat]) m->forms[LANG_QPS][cat] = qps_text(m->forms[0][cat]);
}

static void process_domain(const char *dir, int allow_incomplete)
{
  po_file files[NPO_LANGS];
  int li, i, j;
  memset(files, 0, sizeof(files));

  for (li = 0; li < NPO_LANGS; li++) {
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
  for (li = 0; li < NPO_LANGS; li++)
    if (files[li].present) check_mnemonics(&files[li], li == 0);

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
    check_maxlen(files[0].path, e->line, e->ctx, e->id, 0, e->maxlen);
    if (e->id_plural) check_maxlen(files[0].path, e->line, e->ctx, e->id_plural, 1, e->maxlen);
    for (j = 0; j < g_nmsgs; j++)
      if (strcmp(g_msgs[j].key, e->ctx) == 0) diag(1, files[0].path, e->line, "duplicate id '%s'", e->ctx);
    if (e->fuzzy) diag(1, files[0].path, e->line, "fuzzy entry in the en source");
    if (e->event_id) {
      int j2, seq[MAX_FORMS * 8];
      if (e->id_plural) diag(1, files[0].path, e->line, "'%s' is an Event Log message and cannot be plural", e->ctx);
      if (!e->event_sym[0]) diag(1, files[0].path, e->line, "'%s': sdl10n:event needs a symbol name", e->ctx);
      for (j2 = 0; j2 < g_nmsgs; j2++)
        if (g_msgs[j2].event_id && (g_msgs[j2].event_id == e->event_id || strcmp(g_msgs[j2].event_sym, e->event_sym) == 0))
          diag(1, files[0].path, e->line, "Event Log id %d (%s) is used twice", e->event_id, e->event_sym);
      if (pct_seq(e->id, seq, sizeof(seq) / sizeof(seq[0])) < 0)
        diag(1, files[0].path, e->line, "'%s': Event Log placeholders must be %%<digits>", e->ctx);
    }
    if (g_nmsgs == g_capmsgs) {
      g_capmsgs = g_capmsgs ? g_capmsgs * 2 : 32;
      msg *nm = (msg *)realloc(g_msgs, (size_t)g_capmsgs * sizeof(msg));
      if (!nm) { fprintf(stderr, "sdl10n: out of memory\n"); exit(2); }
      g_msgs = nm;
    }
    m = &g_msgs[g_nmsgs++];
    memset(m, 0, sizeof(*m));
    m->key = xstrdup(e->ctx);
    m->event_id = e->event_id;
    snprintf(m->event_sev, sizeof(m->event_sev), "%s", e->event_sev);
    snprintf(m->event_sym, sizeof(m->event_sym), "%s", e->event_sym);
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
    for (li = 1; li < NPO_LANGS; li++) {
      po_file *f = &files[li];
      int k, missing = 0;
      po_entry *t;
      /* Event Log messages are complete in every locale, whatever --allow-incomplete says (03 §10.3). */
      int strict = e->event_id != 0;
      if (!f->present) {
        if (strict) diag(1, f->path, 0, "missing translation for '%s' (Event Log message)", e->ctx);
        continue;
      }
      k = find_entry(f, e->ctx);
      if (k < 0) {
        diag(!allow_incomplete || strict, f->path, 0, "missing translation for '%s'", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      t = &f->e[k];
      if (strcmp(t->id, e->id) != 0 || (e->id_plural == NULL) != (t->id_plural == NULL) ||
          (e->id_plural && strcmp(t->id_plural, e->id_plural) != 0)) {
        diag(!allow_incomplete || strict, f->path, t->line, "stale translation for '%s': msgid differs from en", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      if (t->fuzzy) {
        diag(!allow_incomplete || strict, f->path, t->line, "fuzzy translation for '%s'", e->ctx);
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
        diag(!allow_incomplete || strict, f->path, t->line, "empty translation for '%s'", e->ctx);
        g_complete_mask &= ~(1u << li);
        continue;
      }
      /* Register, mnemonic and length rules (03 §9.2). */
      if (k_register[li].n && !t->register_ok) {
        for (j = 0; j < t->nstr; j++) {
          const reg_rule *r = register_hit(t->str[j], k_register[li].rules, k_register[li].n);
          if (r) {
            diag(1, f->path, t->line, "'%s' form %d uses \"%s\", not the %s register; fix it or add #. sdl10n:register-ok",
                 e->ctx, j, r->word, g_langs[li].code);
            break;
          }
        }
      }
      if (has_mnemonic(e->id) || (e->id_plural && has_mnemonic(e->id_plural))) {
        for (j = 0; j < t->nstr; j++)
          if (!has_mnemonic(t->str[j])) {
            diag(1, f->path, t->line, "'%s' form %d drops the &-mnemonic of the English source", e->ctx, j);
            break;
          }
      }
      for (j = 0; j < t->nstr; j++)
        check_maxlen(f->path, t->line, e->ctx, t->str[j], j, e->maxlen);

      for (j = 0; j < t->nstr; j++) {
        ph_set ps;
        if (!ph_extract(t->str[j], &ps) || !ph_equal(&want, &ps, e->id_plural ? optional : NULL))
          diag(1, f->path, t->line, "placeholders of '%s' (form %d) differ from en", e->ctx, j);
        ph_free(&ps);
        m->forms[li][e->id_plural ? g_langs[li].cats[j] : CAT_OTHER] = t->str[j];
      }
      if (strict && t->nstr == 1) {
        int want_seq[MAX_FORMS * 8], got_seq[MAX_FORMS * 8];
        int nw = pct_seq(e->id, want_seq, MAX_FORMS * 8), ng = pct_seq(t->str[0], got_seq, MAX_FORMS * 8);
        if (nw < 0 || ng != nw || memcmp(want_seq, got_seq, sizeof(int) * (size_t)nw) != 0)
          diag(1, f->path, t->line, "'%s' must use the %%N placeholders of en in the same order (Event Log)", e->ctx);
      }
    }
    if (g_qps) qps_forms(m);
    ph_free(&want);
  }

  /* Entries that en does not have. */
  for (li = 1; li < NPO_LANGS; li++) {
    for (i = 0; i < files[li].count; i++) {
      po_entry *t = &files[li].e[i];
      if (!t->ctx || find_entry(&files[0], t->ctx) < 0)
        diag(1, files[li].path, t->line, "entry '%s' does not exist in en.po", t->ctx ? t->ctx : "(no msgctxt)");
    }
  }
  /* PO data stays allocated: g_msgs points into it until the process exits. */
}

/* ---- output ---- */

/* Writes s as a C string literal. Bytes >= 0x7F and controls become 3-digit octal escapes; a digit that
   follows such an escape starts a new adjacent literal, because MSVC warns (C4125) about it. */
static void emit_cstr(FILE *o, const char *s)
{
  int after_escape = 0;
  if (!s) { fputs("NULL", o); return; }
  fputc('"', o);
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (after_escape && c >= '0' && c <= '9') fputs("\" \"", o);
    after_escape = 0;
    if (c == '"' || c == '\\') fprintf(o, "\\%c", c);
    else if (c < 0x20 || c >= 0x7F) { fprintf(o, "\\%03o", c); after_escape = 1; }
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
    if (li == LANG_QPS && !g_qps) continue;
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
  for (li = 0; li < NLANGS; li++) {
    if (li == LANG_QPS && !g_qps) fputs(" NULL", c);
    else fprintf(c, " k_%s", g_langs[li].ident);
    fputs(li + 1 < NLANGS ? "," : " ", c);
  }
  fprintf(c, "},\n  0x%02xu\n};\n", g_complete_mask);
  fclose(c);
  return 1;
}

/* Writes s as UTF-16LE code units (surrogate pairs for code points above U+FFFF). The input is valid UTF-8. */
static void put_unit(FILE *o, unsigned unit)
{
  fputc((int)(unit & 0xFF), o);
  fputc((int)((unit >> 8) & 0xFF), o);
}

static void w16_utf8(FILE *o, const char *s)
{
  const unsigned char *u = (const unsigned char *)s;
  while (*u) {
    unsigned cp = *u, len = 1, i;
    if (cp >= 0xF0) { len = 4; cp &= 0x07; }
    else if (cp >= 0xE0) { len = 3; cp &= 0x0F; }
    else if (cp >= 0xC0) { len = 2; cp &= 0x1F; }
    for (i = 1; i < len; i++) cp = (cp << 6) | (u[i] & 0x3F);
    u += len;
    if (cp >= 0x10000) {
      cp -= 0x10000;
      put_unit(o, 0xD800 + (cp >> 10));
      cp = 0xDC00 + (cp & 0x3FF);
    }
    put_unit(o, cp);
  }
}

static void w16_line(FILE *o, const char *s)
{
  w16_utf8(o, s);
  w16_utf8(o, "\r\n");
}

/* Writes the Event Log message table of the catalog (03 §10.3) as a UTF-16LE .mc file for "mc -u". The
   language names and LCIDs are the ones of the Windows message table of shelldrive-host: es is Rioplatense
   text under es-AR (11274), the LCID the MSI also uses for its Spanish transform. */
static const struct { const char *name; unsigned lcid; const char *file; int li; } k_mc_langs[] = {
  { "English",           0x409,  "MSG00409", 0 },
  { "Spanish",           0x2C0A, "MSG02C0A", 1 },
  { "French",            0x40C,  "MSG0040C", 2 },
  { "PortugueseBrazil",  0x416,  "MSG00416", 3 },
  { "Italian",           0x410,  "MSG00410", 4 },
  { "German",            0x407,  "MSG00407", 5 },
};

static int write_mc(const char *out_mc)
{
  FILE *o;
  int i, k;
  char line[256];
  o = fopen(out_mc, "wb");
  if (!o) { diag(1, NULL, 0, "cannot write %s", out_mc); return 0; }
  put_unit(o, 0xFEFF);
  w16_line(o, "MessageIdTypedef=DWORD");
  w16_line(o, "");
  w16_line(o, "SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS");
  w16_line(o, "               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL");
  w16_line(o, "               Warning=0x2:STATUS_SEVERITY_WARNING");
  w16_line(o, "               Error=0x3:STATUS_SEVERITY_ERROR");
  w16_line(o, "              )");
  w16_line(o, "");
  strcpy(line, "LanguageNames=(");
  for (k = 0; k < (int)(sizeof(k_mc_langs) / sizeof(k_mc_langs[0])); k++) {
    char part[128];
    snprintf(part, sizeof(part), "%s%s=0x%X:%s", k ? " " : "", k_mc_langs[k].name, k_mc_langs[k].lcid, k_mc_langs[k].file);
    strcat(line, part);
  }
  strcat(line, ")");
  w16_line(o, line);
  w16_line(o, "");
  for (i = 0; i < g_nmsgs; i++) {
    const msg *m = &g_msgs[i];
    if (!m->event_id) continue;
    snprintf(line, sizeof(line), "MessageId=%d Severity=%s SymbolicName=%s", m->event_id, m->event_sev, m->event_sym);
    w16_line(o, line);
    for (k = 0; k < (int)(sizeof(k_mc_langs) / sizeof(k_mc_langs[0])); k++) {
      const char *text = m->forms[k_mc_langs[k].li][CAT_OTHER];
      if (!text) text = m->forms[0][CAT_OTHER];   /* not reached: strict checks fail first */
      snprintf(line, sizeof(line), "Language=%s", k_mc_langs[k].name);
      w16_line(o, line);
      w16_line(o, text);
      w16_line(o, ".");
    }
    w16_line(o, "");
  }
  fclose(o);
  return 1;
}

static void usage(void)
{
  fprintf(stderr,
          "usage: sdl10n --name <catalog> --out-c <file.c> --out-h <file.h> --domain <dir>... [--allow-incomplete] [--qps | --no-qps]\n"
          "       sdl10n --out-mc <file.mc> --domain <dir>...\n"
          "       sdl10n --check --domain <dir>... [--allow-incomplete]\n");
}

int main(int argc, char **argv)
{
  const char *name = NULL, *out_c = NULL, *out_h = NULL, *out_mc = NULL;
  const char *domains[MAX_DOMAINS];
  int ndomains = 0, check = 0, allow = 0, qps = 0, i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) name = argv[++i];
    else if (strcmp(argv[i], "--out-c") == 0 && i + 1 < argc) out_c = argv[++i];
    else if (strcmp(argv[i], "--out-h") == 0 && i + 1 < argc) out_h = argv[++i];
    else if (strcmp(argv[i], "--out-mc") == 0 && i + 1 < argc) out_mc = argv[++i];
    else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc && ndomains < MAX_DOMAINS) domains[ndomains++] = argv[++i];
    else if (strcmp(argv[i], "--check") == 0) check = 1;
    else if (strcmp(argv[i], "--allow-incomplete") == 0) allow = 1;
    else if (strcmp(argv[i], "--qps") == 0) qps = 1;
    else if (strcmp(argv[i], "--no-qps") == 0) qps = 0;
    else { usage(); return 2; }
  }
  if (ndomains == 0 || (!check && !out_mc && !out_c && !out_h)) { usage(); return 2; }
  if (!check && (out_c || out_h) && (!name || !out_c || !out_h)) { usage(); return 2; }
  g_qps = qps;
  if (qps) g_complete_mask |= 1u << LANG_QPS;
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
  if (!check && out_c && !write_outputs(name, out_c, out_h))
    return 1;
  if (!check && out_mc && !write_mc(out_mc))
    return 1;
  if (g_warnings)
    fprintf(stderr, "sdl10n: %d warning(s); incomplete locales fall back to English.\n", g_warnings);
  return 0;
}
