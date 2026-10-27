/* sd-admxgen: Group Policy template generator (03 §3.5, 04 §8.6, 04 §12.2).
 *
 *   sd-admxgen --table <policies.txt> --po-dir <l10n/policy> --out-dir <dir> --header-dir <dir> [--check]
 *
 * Input: res/policy/policies.txt, the single table of policy values (format in that file), and the
 * policy catalogs l10n/policy/<lang>.po (sdl10n domain "policy"; en.po carries the English text in
 * msgid, the other five carry translations in msgstr).
 *
 * Output (skipped with --check, which validates the inputs only):
 *   <out-dir>\ShellDrive.admx                   the template (policy definitions, no text)
 *   <out-dir>\<culture>\ShellDrive.adml         one resource file per culture: en-US, es-ES, fr-FR,
 *                                               pt-BR, it-IT, de-DE (Windows folder names)
 *   <header-dir>\sd_policy_ids.h                enum sd_policy_id, one value per table line
 *   <header-dir>\sd_policy_table.h              name, kind, registry type and range of every policy,
 *                                               and SD_POLICY_REGKEY; included by src/sd_policy only
 *
 * Output is deterministic: table order, no timestamps, no absolute paths, so the reproducible-build check
 * (tools/check-repro.ps1) covers it. Each string key "policy.<...>" becomes the ADML id with dots replaced
 * by underscores (policy.LegacyAlgorithms.title -> policy_LegacyAlgorithms_title).
 *
 * The inputs are validated: table syntax and values, duplicate names, every key present with a non-empty
 * text in every locale. Errors are reported as file:line: error and the exit code is 1.
 *
 * Build-time tool, never shipped: plain C with stdio, kept C89-friendly for the v141_xp toolset. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SDG_MAX_POLICIES 64
#define SDG_MAX_ENUM 16
#define SDG_NAME_MAX 64
#define SDG_KEY_MAX 192
#define SDG_NLOCALES 6
#define SDG_NCAT 6

typedef enum sdg_kind { SDG_BOOLEAN, SDG_ENUM, SDG_TEXT, SDG_DECIMAL } sdg_kind;
typedef enum sdg_class { SDG_CLS_BOTH, SDG_CLS_MACHINE, SDG_CLS_USER } sdg_class;

typedef struct sdg_policy {
  char name[SDG_NAME_MAX];
  sdg_class cls;
  sdg_kind kind;
  int nvalues;                                   /* enum: number of values */
  char values[SDG_MAX_ENUM][SDG_NAME_MAX];       /* enum: values in table order */
  int numeric;                                   /* enum: every value is decimal (REG_DWORD) */
  unsigned long min, max;                        /* boolean 0..1, decimal range, numeric enum range */
  unsigned long maxlen;                          /* text: maximum length in characters */
  int win11;                                     /* supportedOn: 0 = xp, 1 = win11 */
  int category;                                  /* index into sdg_cat_ids */
  int line;
} sdg_policy;

typedef struct sdg_table {
  char key[256];                                 /* registry key below HKLM|HKCU */
  int npolicies;
  sdg_policy policies[SDG_MAX_POLICIES];
} sdg_table;

typedef struct sdg_po_entry {
  char *ctx;                                     /* msgctxt: the key */
  char *text;                                    /* English msgid (en) or the translation msgstr */
  int fuzzy;
} sdg_po_entry;

typedef struct sdg_catalog {
  sdg_po_entry *e;
  size_t n, cap;
} sdg_catalog;

typedef struct sdg_sb {
  char *p;
  size_t len, cap;
} sdg_sb;

typedef struct sdg_locale {
  const char *code;                              /* PO file stem */
  const char *culture;                           /* ADML folder */
} sdg_locale;

static const sdg_locale sdg_locales[SDG_NLOCALES] = {
  { "en", "en-US" }, { "es", "es-ES" }, { "fr", "fr-FR" },
  { "pt-BR", "pt-BR" }, { "it", "it-IT" }, { "de", "de-DE" },
};

/* Category ids in the table (lower case) and their ADMX category names. Order is the ADMX order. */
static const char *const sdg_cat_ids[SDG_NCAT] = {
  "security", "network", "mounts", "updates", "interface", "logging"
};
static const char *const sdg_cat_admx[SDG_NCAT] = {
  "ShellDrive_Security", "ShellDrive_Network", "ShellDrive_Mounts",
  "ShellDrive_Updates", "ShellDrive_Interface", "ShellDrive_Logging"
};

#define SDG_NS "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
#define SDG_BOM "\xEF\xBB\xBF"

/* Diagnostics go to sdg_diag (tests set it to NULL); every error is counted. */
static FILE *sdg_diag = NULL;
static int sdg_nerrors = 0;

static void sdg_error(const char *file, int line, const char *fmt, ...)
{
  va_list ap;
  sdg_nerrors++;
  if (sdg_diag == NULL)
    return;
  fprintf(sdg_diag, "%s:%d: error: ", file ? file : "sd-admxgen", line);
  va_start(ap, fmt);
  vfprintf(sdg_diag, fmt, ap);
  va_end(ap);
  fputc('\n', sdg_diag);
}

/* ---- string builder ---- */

static __declspec(noreturn) void sdg_die_oom(void)
{
  fprintf(stderr, "sd-admxgen: out of memory\n");
  exit(3);
}

static void sdg_sb_add(sdg_sb *b, const char *s, size_t n)
{
  if (b->len + n + 1 > b->cap || b->p == NULL) {
    size_t cap = b->cap ? b->cap : 256;
    char *p;
    while (b->len + n + 1 > cap)
      cap *= 2;
    p = (char *)realloc(b->p, cap);
    if (p == NULL)
      sdg_die_oom();
    b->p = p;
    b->cap = cap;
  }
  if (n && b->p != NULL)
    memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = 0;
}

static void sdg_sb_puts(sdg_sb *b, const char *s)
{
  sdg_sb_add(b, s, strlen(s));
}

static void sdg_sb_printf(sdg_sb *b, const char *fmt, ...)
{
  va_list ap;
  int n;
  char *tmp;
  va_start(ap, fmt);
  n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0)
    sdg_die_oom();
  tmp = (char *)malloc((size_t)n + 1);
  if (tmp == NULL)
    sdg_die_oom();
  va_start(ap, fmt);
  vsnprintf(tmp, (size_t)n + 1, fmt, ap);
  va_end(ap);
  sdg_sb_add(b, tmp, (size_t)n);
  free(tmp);
}

static void sdg_sb_free(sdg_sb *b)
{
  free(b->p);
  b->p = NULL;
  b->len = b->cap = 0;
}

/* ---- escaping ---- */

/* XML text and attribute escaping. Returns 0 when a control character other than TAB and LF is present:
   nothing of that kind is allowed in ADMX or ADML. */
int sdg_xml_escape(sdg_sb *b, const char *s)
{
  const unsigned char *p = (const unsigned char *)s;
  int ok = 1;
  for (; *p; p++) {
    switch (*p) {
    case '&':  sdg_sb_puts(b, "&amp;"); break;
    case '<':  sdg_sb_puts(b, "&lt;"); break;
    case '>':  sdg_sb_puts(b, "&gt;"); break;
    case '"':  sdg_sb_puts(b, "&quot;"); break;
    case '\'': sdg_sb_puts(b, "&apos;"); break;
    default:
      if (*p < 0x20 && *p != '\t' && *p != '\n')
        ok = 0;
      else
        sdg_sb_add(b, (const char *)p, 1);
    }
  }
  return ok;
}

/* C string literal body (for the generated headers): backslash and double quote escaped. */
void sdg_c_escape(sdg_sb *b, const char *s)
{
  const char *p;
  for (p = s; *p; p++) {
    if (*p == '\\' || *p == '"')
      sdg_sb_add(b, "\\", 1);
    sdg_sb_add(b, p, 1);
  }
}

/* ---- small helpers ---- */

static char *sdg_trim(char *s)
{
  char *e;
  while (*s == ' ' || *s == '\t')
    s++;
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
    *--e = 0;
  return s;
}

static int sdg_is_ident(const char *s, size_t max)
{
  size_t n = strlen(s), i;
  if (n == 0 || n > max || !((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')))
    return 0;
  for (i = 1; i < n; i++)
    if (!((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')))
      return 0;
  return 1;
}

/* Enum value token: letters, digits, '.', '_' and '-' (pt-BR, stable, 0). */
static int sdg_is_token(const char *s)
{
  size_t n = strlen(s), i;
  if (n == 0 || n >= SDG_NAME_MAX)
    return 0;
  for (i = 0; i < n; i++)
    if (!((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') ||
          s[i] == '.' || s[i] == '_' || s[i] == '-'))
      return 0;
  return 1;
}

static int sdg_is_decimal(const char *s)
{
  size_t i, n = strlen(s);
  if (n == 0 || n > 9)
    return 0;
  for (i = 0; i < n; i++)
    if (s[i] < '0' || s[i] > '9')
      return 0;
  return 1;
}

/* PO keys are lower case (sdl10n accepts [a-z0-9_.-] only); ADML ids derive from them. */
static void sdg_lower_inplace(char *s)
{
  for (; *s; s++)
    if (*s >= 'A' && *s <= 'Z')
      *s = (char)(*s - 'A' + 'a');
}

/* Key-to-id mapping: dots become underscores, letters lower case. */
static void sdg_key_to_id(sdg_sb *b, const char *key)
{
  const char *p;
  for (p = key; *p; p++) {
    char c = *p;
    if (c == '.')
      c = '_';
    else if (c >= 'A' && c <= 'Z')
      c = (char)(c - 'A' + 'a');
    sdg_sb_add(b, &c, 1);
  }
}

/* ---- table (res/policy/policies.txt) ---- */

static int sdg_split_fields(char *s, char *f[], int max, const char *file, int line)
{
  int n = 1;
  char *q;
  f[0] = s;
  for (q = s; *q && n < max; q++) {
    if (*q == '|') {
      *q = 0;
      f[n++] = q + 1;
    }
  }
  if (strchr(f[n - 1], '|') != NULL) {
    sdg_error(file, line, "too many fields (expected 6 separated by '|')");
    return -1;
  }
  return n;
}

static int sdg_parse_uint(const char *s, unsigned long *out)
{
  size_t i, n = strlen(s);
  if (!sdg_is_decimal(s) || n == 0)
    return 0;
  *out = 0;
  for (i = 0; i < n; i++)
    *out = *out * 10 + (unsigned long)(s[i] - '0');
  return 1;
}

static void sdg_table_policy(sdg_table *t, char *fields[], const char *file, int line)
{
  sdg_policy *p;
  char *params;
  int i, nf;
  char *tok, *next;
  unsigned long v = 0;
  char buf[256];

  if (t->npolicies >= SDG_MAX_POLICIES) {
    sdg_error(file, line, "more than %d policies", SDG_MAX_POLICIES);
    return;
  }
  for (i = 0; i < 6; i++)
    fields[i] = sdg_trim(fields[i]);
  p = &t->policies[t->npolicies];
  memset(p, 0, sizeof(*p));
  p->line = line;

  if (!sdg_is_ident(fields[0], SDG_NAME_MAX - 1)) {
    sdg_error(file, line, "policy name '%s' must be ASCII letters and digits, starting with a letter", fields[0]);
    return;
  }
  for (i = 0; i < t->npolicies; i++)
    if (strcmp(t->policies[i].name, fields[0]) == 0) {
      sdg_error(file, line, "duplicate policy '%s'", fields[0]);
      return;
    }
  strcpy(p->name, fields[0]);

  if (strcmp(fields[1], "both") == 0) p->cls = SDG_CLS_BOTH;
  else if (strcmp(fields[1], "machine") == 0) p->cls = SDG_CLS_MACHINE;
  else if (strcmp(fields[1], "user") == 0) p->cls = SDG_CLS_USER;
  else { sdg_error(file, line, "class '%s' must be both, machine or user", fields[1]); return; }

  if (strcmp(fields[2], "boolean") == 0) p->kind = SDG_BOOLEAN;
  else if (strcmp(fields[2], "enum") == 0) p->kind = SDG_ENUM;
  else if (strcmp(fields[2], "text") == 0) p->kind = SDG_TEXT;
  else if (strcmp(fields[2], "decimal") == 0) p->kind = SDG_DECIMAL;
  else { sdg_error(file, line, "type '%s' must be boolean, enum, text or decimal", fields[2]); return; }

  params = fields[3];
  switch (p->kind) {
  case SDG_BOOLEAN:
    if (strcmp(params, "-") != 0) { sdg_error(file, line, "boolean takes '-' as params"); return; }
    p->min = 0;
    p->max = 1;
    break;
  case SDG_TEXT:
    if (!sdg_parse_uint(params, &v) || v < 1 || v > 65535) {
      sdg_error(file, line, "text needs a maximum length from 1 to 65535, got '%s'", params);
      return;
    }
    p->maxlen = v;
    break;
  case SDG_DECIMAL:
    {
      char *comma = strchr(params, ',');
      char lo_s[16];
      char hi_s[16];
      unsigned long lo = 0, hi = 0;
      if (comma == NULL || (size_t)(comma - params) >= sizeof(lo_s) || strlen(comma + 1) >= sizeof(hi_s)) {
        sdg_error(file, line, "decimal needs min,max with 0 <= min <= max, got '%s'", params);
        return;
      }
      memcpy(lo_s, params, (size_t)(comma - params));
      lo_s[comma - params] = 0;
      strcpy(hi_s, comma + 1);
      if (!sdg_parse_uint(lo_s, &lo) || !sdg_parse_uint(hi_s, &hi) || lo > hi) {
        sdg_error(file, line, "decimal needs min,max with 0 <= min <= max, got '%s'", params);
        return;
      }
      p->min = lo;
      p->max = hi;
    }
    break;
  case SDG_ENUM:
    if (strlen(params) >= sizeof(buf)) { sdg_error(file, line, "enum values too long"); return; }
    strcpy(buf, params);
    p->numeric = 1;
    nf = 0;
    for (tok = buf; tok != NULL; tok = next) {
      next = strchr(tok, ',');
      if (next) *next++ = 0;
      tok = sdg_trim(tok);
      if (nf >= SDG_MAX_ENUM) { sdg_error(file, line, "more than %d enum values", SDG_MAX_ENUM); return; }
      if (!sdg_is_token(tok)) { sdg_error(file, line, "enum value '%s' is not a token", tok); return; }
      for (i = 0; i < nf; i++)
        if (strcmp(p->values[i], tok) == 0) { sdg_error(file, line, "duplicate enum value '%s'", tok); return; }
      strcpy(p->values[nf], tok);
      if (!sdg_is_decimal(tok))
        p->numeric = 0;
      nf++;
    }
    if (nf == 0) { sdg_error(file, line, "enum needs at least one value"); return; }
    p->nvalues = nf;
    if (p->numeric) {
      unsigned long lo = 0, hi = 0;
      sdg_parse_uint(p->values[0], &lo);
      hi = lo;
      for (i = 1; i < nf; i++) {
        unsigned long x = 0;
        sdg_parse_uint(p->values[i], &x);
        if (x < lo) lo = x;
        if (x > hi) hi = x;
      }
      p->min = lo;
      p->max = hi;
    } else {
      for (i = 0; i < nf; i++)
        if (sdg_is_decimal(p->values[i])) {
          sdg_error(file, line, "enum mixes decimal and text values ('%s')", p->values[i]);
          return;
        }
    }
    break;
  }

  if (strcmp(fields[4], "xp") == 0) p->win11 = 0;
  else if (strcmp(fields[4], "win11") == 0) p->win11 = 1;
  else { sdg_error(file, line, "supported '%s' must be xp or win11", fields[4]); return; }

  for (i = 0; i < SDG_NCAT; i++)
    if (strcmp(fields[5], sdg_cat_ids[i]) == 0)
      break;
  if (i == SDG_NCAT) { sdg_error(file, line, "unknown category '%s'", fields[5]); return; }
  p->category = i;
  t->npolicies++;
}

static void sdg_table_line(sdg_table *t, char *s, const char *file, int line)
{
  char *fields[6];
  int nf;
  s = sdg_trim(s);
  if (s[0] == 0 || s[0] == '#')
    return;
  if (strncmp(s, "@key ", 5) == 0) {
    char *k = sdg_trim(s + 5);
    size_t i;
    if (t->key[0]) { sdg_error(file, line, "@key given twice"); return; }
    if (k[0] == 0 || strlen(k) >= sizeof(t->key)) { sdg_error(file, line, "@key is empty or too long"); return; }
    for (i = 0; k[i]; i++)
      if (!((k[i] >= 'A' && k[i] <= 'Z') || (k[i] >= 'a' && k[i] <= 'z') || (k[i] >= '0' && k[i] <= '9') ||
            k[i] == '\\' || k[i] == '_'))
        { sdg_error(file, line, "@key may only contain letters, digits, '\\' and '_'"); return; }
    strcpy(t->key, k);
    return;
  }
  nf = sdg_split_fields(s, fields, 6, file, line);
  if (nf != 6) {
    if (nf > 0 && nf < 6)
      sdg_error(file, line, "expected 6 fields separated by '|', got %d", nf);
    return;
  }
  sdg_table_policy(t, fields, file, line);
}

/* Parses the table text. Returns the number of errors it added. */
int sdg_parse_table_text(sdg_table *t, const char *text, const char *file)
{
  const char *p = text;
  int line = 0, before = sdg_nerrors;
  char buf[1024];
  memset(t, 0, sizeof(*t));
  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    line++;
    if (n >= sizeof(buf)) {
      sdg_error(file, line, "line too long");
    } else {
      memcpy(buf, p, n);
      buf[n] = 0;
      sdg_table_line(t, buf, file, line);
    }
    p = nl ? nl + 1 : p + n;
  }
  if (t->key[0] == 0)
    sdg_error(file, 0, "missing @key line");
  if (t->npolicies == 0 && sdg_nerrors == before)
    sdg_error(file, 0, "no policies");
  return sdg_nerrors - before;
}

/* ---- PO catalogs (l10n/policy/<lang>.po) ---- */

static int sdg_catalog_add(sdg_catalog *c, char *ctx, char *text, int fuzzy)
{
  sdg_po_entry *e;
  if (c->n == c->cap) {
    size_t cap = c->cap ? c->cap * 2 : 64;
    sdg_po_entry *n = (sdg_po_entry *)realloc(c->e, cap * sizeof(sdg_po_entry));
    if (n == NULL)
      sdg_die_oom();
    c->e = n;
    c->cap = cap;
  }
  e = &c->e[c->n++];
  e->ctx = ctx;
  e->text = text;
  e->fuzzy = fuzzy;
  return 1;
}

/* Appends the unescaped body of one quoted PO string ("..."). Returns 0 on a malformed string. */
static int sdg_po_quoted(sdg_sb *b, const char *s, const char *file, int line)
{
  const char *end;
  size_t i;
  if (s[0] != '"')
    return 0;
  end = strrchr(s, '"');
  if (end == NULL || end == s)
    return 0;
  for (i = 1; s + i < end; i++) {
    char c = s[i];
    if (c == '\\' && s + i + 1 < end) {
      char d = s[++i];
      switch (d) {
      case 'n': c = '\n'; break;
      case 't': c = '\t'; break;
      case 'r': c = '\r'; break;
      case '"': c = '"'; break;
      case '\\': c = '\\'; break;
      default:
        sdg_error(file, line, "unsupported escape \\%c", d);
        c = d;
      }
    }
    sdg_sb_add(b, &c, 1);
  }
  return 1;
}

static void sdg_po_flush(sdg_catalog *c, sdg_sb *ctx, sdg_sb *id, sdg_sb *str, int have_ctx, int fuzzy,
                         int is_en)
{
  if (have_ctx) {
    char *key = _strdup(ctx->p ? ctx->p : "");
    char *text = _strdup(is_en ? (id->p ? id->p : "") : (str->p ? str->p : ""));
    if (!key || !text)
      sdg_die_oom();
    sdg_catalog_add(c, key, text, fuzzy);
  }
  ctx->len = id->len = str->len = 0;
  if (ctx->p) ctx->p[0] = 0;
  if (id->p) id->p[0] = 0;
  if (str->p) str->p[0] = 0;
}

/* Parses one PO file. is_en: the text is the msgid (en.po keeps msgstr empty). Returns errors added. */
int sdg_parse_po_text(sdg_catalog *c, const char *text, int is_en, const char *file)
{
  const char *p = text;
  int line = 0, before = sdg_nerrors;
  sdg_sb ctx = { 0, 0, 0 }, id = { 0, 0, 0 }, str = { 0, 0, 0 };
  int field = 0;               /* 1 ctx, 2 id, 3 str, 0 other */
  int have_ctx = 0, fuzzy = 0;
  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    char *ln;
    line++;
    ln = (char *)malloc(n + 1);
    if (ln == NULL)
      sdg_die_oom();
    memcpy(ln, p, n);
    ln[n] = 0;
    p = nl ? nl + 1 : p + n;
    while (n && ln[n - 1] == '\r')
      ln[--n] = 0;
    if (ln[0] == 0) {
      sdg_po_flush(c, &ctx, &id, &str, have_ctx, fuzzy, is_en);
      have_ctx = fuzzy = 0;
      field = 0;
    } else if (strncmp(ln, "#,", 2) == 0) {
      if (strstr(ln, "fuzzy") != NULL)
        fuzzy = 1;
    } else if (ln[0] == '#') {
      /* translator and reference comments */
    } else if (strncmp(ln, "msgctxt ", 8) == 0) {
      if (have_ctx) sdg_error(file, line, "entry without a blank line before msgctxt");
      ctx.len = 0;
      if (!sdg_po_quoted(&ctx, ln + 8, file, line)) sdg_error(file, line, "malformed msgctxt");
      have_ctx = 1;
      field = 1;
    } else if (strncmp(ln, "msgid ", 6) == 0) {
      id.len = 0;
      if (!sdg_po_quoted(&id, ln + 6, file, line)) sdg_error(file, line, "malformed msgid");
      field = 2;
    } else if (strncmp(ln, "msgstr ", 7) == 0) {
      str.len = 0;
      if (!sdg_po_quoted(&str, ln + 7, file, line)) sdg_error(file, line, "malformed msgstr");
      field = 3;
    } else if (strncmp(ln, "msgid_plural ", 13) == 0 || strncmp(ln, "msgstr[", 7) == 0) {
      field = 0;   /* plurals are not used by the policy domain; sdl10n rejects them in ADML */
      sdg_error(file, line, "plural messages are not allowed in the policy domain");
    } else if (ln[0] == '"') {
      sdg_sb *dst = field == 1 ? &ctx : field == 2 ? &id : field == 3 ? &str : NULL;
      if (dst == NULL || !sdg_po_quoted(dst, ln, file, line))
        sdg_error(file, line, "unexpected continuation line");
    } else {
      sdg_error(file, line, "unexpected line");
    }
    free(ln);
  }
  sdg_po_flush(c, &ctx, &id, &str, have_ctx, fuzzy, is_en);
  sdg_sb_free(&ctx);
  sdg_sb_free(&id);
  sdg_sb_free(&str);
  return sdg_nerrors - before;
}

/* Text of a key, or NULL when the catalog has no usable entry (missing or fuzzy, or an empty translation). */
static const char *sdg_po_get(const sdg_catalog *c, const char *key)
{
  size_t i;
  for (i = 0; i < c->n; i++)
    if (strcmp(c->e[i].ctx, key) == 0)
      return (c->e[i].fuzzy || c->e[i].text[0] == 0) ? NULL : c->e[i].text;
  return NULL;
}

/* Text for a key in one locale; reports a diagnostic and returns "" when it is missing. */
static const char *sdg_text(const sdg_catalog *c, const char *lang, const char *key, const char *file)
{
  const char *s = sdg_po_get(c, key);
  if (s == NULL) {
    sdg_error(file, 0, "missing translation for '%s' in %s.po", key, lang);
    return "";
  }
  return s;
}

/* ---- ADMX ---- */

static void sdg_emit_value(sdg_sb *b, const char *v)
{
  if (sdg_is_decimal(v)) {
    sdg_sb_printf(b, "<decimal value=\"%lu\"/>", (unsigned long)atol(v));
  } else {
    sdg_sb_puts(b, "<string>");
    sdg_xml_escape(b, v);
    sdg_sb_puts(b, "</string>");
  }
}

static void sdg_emit_policy(sdg_sb *b, const sdg_policy *p, const sdg_table *t)
{
  int hasel = p->kind != SDG_BOOLEAN;
  int i;
  const char *cls = p->cls == SDG_CLS_BOTH ? "Both" : p->cls == SDG_CLS_MACHINE ? "Machine" : "User";

  sdg_sb_printf(b, "    <policy name=\"%s\" class=\"%s\" displayName=\"$(string.", p->name, cls);
  sdg_sb_puts(b, "policy_"); sdg_key_to_id(b, p->name); sdg_sb_puts(b, "_title)\"");
  sdg_sb_puts(b, " explainText=\"$(string.policy_"); sdg_key_to_id(b, p->name); sdg_sb_puts(b, "_explain)\"");
  sdg_sb_puts(b, " key=\"");
  sdg_xml_escape(b, t->key);
  sdg_sb_puts(b, "\"");
  sdg_sb_puts(b, " valueName=\""); sdg_sb_puts(b, p->name); sdg_sb_puts(b, "\"");
  if (hasel) {
    sdg_sb_puts(b, " presentation=\"$(presentation.P_"); sdg_sb_puts(b, p->name); sdg_sb_puts(b, ")\"");
  }
  sdg_sb_puts(b, ">\n");
  sdg_sb_puts(b, "      <parentCategory ref=\""); sdg_sb_puts(b, sdg_cat_admx[p->category]); sdg_sb_puts(b, "\"/>\n");
  sdg_sb_puts(b, "      <supportedOn ref=\"");
  sdg_sb_puts(b, p->win11 ? "SD_SUPPORTED_WIN11" : "SD_SUPPORTED_XP");
  sdg_sb_puts(b, "\"/>\n");

  if (hasel) {
    sdg_sb_puts(b, "      <elements>\n");
    switch (p->kind) {
    case SDG_ENUM:
      sdg_sb_printf(b, "        <enum id=\"ID_%s\" valueName=\"%s\" required=\"true\">\n", p->name, p->name);
      for (i = 0; i < p->nvalues; i++) {
        sdg_sb_puts(b, "          <item displayName=\"$(string.policy_"); sdg_key_to_id(b, p->name);
        sdg_sb_puts(b, "_opt_");
        sdg_key_to_id(b, p->values[i]);   /* values are tokens: '.' becomes '_' like the key */
        sdg_sb_puts(b, ")\">\n            <value>");
        sdg_emit_value(b, p->values[i]);
        sdg_sb_puts(b, "</value>\n          </item>\n");
      }
      sdg_sb_puts(b, "        </enum>\n");
      break;
    case SDG_TEXT:
      sdg_sb_printf(b, "        <text id=\"ID_%s\" valueName=\"%s\" required=\"false\" maxLength=\"%lu\"/>\n",
                    p->name, p->name, p->maxlen);
      break;
    case SDG_DECIMAL:
      sdg_sb_printf(b, "        <decimal id=\"ID_%s\" valueName=\"%s\" required=\"true\" minValue=\"%lu\" maxValue=\"%lu\"/>\n",
                    p->name, p->name, p->min, p->max);
      break;
    case SDG_BOOLEAN:
      break;
    }
    sdg_sb_puts(b, "      </elements>\n");
  } else {
    sdg_sb_puts(b, "      <enabledValue><decimal value=\"1\"/></enabledValue>\n");
    sdg_sb_puts(b, "      <disabledValue><decimal value=\"0\"/></disabledValue>\n");
  }
  sdg_sb_puts(b, "    </policy>\n");
}

/* The ADMX file. Pure: no text, only ids and references the ADML must define. */
void sdg_emit_admx(sdg_sb *b, const sdg_table *t)
{
  int i;
  sdg_sb_puts(b, SDG_BOM "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
  sdg_sb_puts(b, "<policyDefinitions revision=\"1.0\" schemaVersion=\"1.0\" xmlns=\"" SDG_NS "\">\n");
  sdg_sb_puts(b, "  <policyNamespaces>\n");
  sdg_sb_puts(b, "    <target prefix=\"shelldrive\" namespace=\"com.librestatic.shelldrive.policies\"/>\n");
  sdg_sb_puts(b, "  </policyNamespaces>\n");
  sdg_sb_puts(b, "  <resources minRequiredRevision=\"1.0\"/>\n");
  sdg_sb_puts(b, "  <supportedOn>\n    <definitions>\n");
  sdg_sb_puts(b, "      <definition name=\"SD_SUPPORTED_XP\" displayName=\"$(string.policy_supported_xp)\"/>\n");
  sdg_sb_puts(b, "      <definition name=\"SD_SUPPORTED_WIN11\" displayName=\"$(string.policy_supported_win11)\"/>\n");
  sdg_sb_puts(b, "    </definitions>\n  </supportedOn>\n");
  sdg_sb_puts(b, "  <categories>\n");
  sdg_sb_puts(b, "    <category name=\"LibreStatic\" displayName=\"$(string.policy_cat_librestatic)\"/>\n");
  sdg_sb_puts(b, "    <category name=\"ShellDrive\" displayName=\"$(string.policy_cat_shelldrive)\">\n");
  sdg_sb_puts(b, "      <parentCategory ref=\"LibreStatic\"/>\n    </category>\n");
  for (i = 0; i < SDG_NCAT; i++) {
    sdg_sb_puts(b, "    <category name=\""); sdg_sb_puts(b, sdg_cat_admx[i]);
    sdg_sb_puts(b, "\" displayName=\"$(string.policy_cat_"); sdg_sb_puts(b, sdg_cat_ids[i]);
    sdg_sb_puts(b, ")\">\n      <parentCategory ref=\"ShellDrive\"/>\n    </category>\n");
  }
  sdg_sb_puts(b, "  </categories>\n");
  sdg_sb_puts(b, "  <policies>\n");
  for (i = 0; i < t->npolicies; i++)
    sdg_emit_policy(b, &t->policies[i], t);
  sdg_sb_puts(b, "  </policies>\n");
  sdg_sb_puts(b, "  <presentations>\n");
  for (i = 0; i < t->npolicies; i++)
    if (t->policies[i].kind != SDG_BOOLEAN) {
      sdg_sb_puts(b, "    <presentation id=\"P_"); sdg_sb_puts(b, t->policies[i].name); sdg_sb_puts(b, "\"/>\n");
    }
  sdg_sb_puts(b, "  </presentations>\n");
  sdg_sb_puts(b, "</policyDefinitions>\n");
}

/* ---- ADML ---- */

/* Adds one stringTable entry: the id is the key with dots replaced, the text is the locale's text. */
static void sdg_adml_string(sdg_sb *b, const sdg_catalog *c, const char *lang, const char *key,
                            const char *file)
{
  const char *text = sdg_text(c, lang, key, file);
  sdg_sb_puts(b, "      <string id=\"");
  sdg_key_to_id(b, key);
  sdg_sb_puts(b, "\">");
  if (!sdg_xml_escape(b, text))
    sdg_error(file, 0, "control character in '%s'", key);
  sdg_sb_puts(b, "</string>\n");
}

/* Every key the ADML of this table needs, in emission order. Used for both the stringTable and checks. */
static void sdg_adml_keys(sdg_sb *b, const sdg_catalog *c, const char *lang, const sdg_table *t,
                          const char *file)
{
  static const char *const brand[] = { "policy.cat.librestatic", "policy.cat.shelldrive" };
  static const char *const sup[] = { "policy.supported.xp", "policy.supported.win11" };
  char key[SDG_KEY_MAX];
  int i, j;
  for (i = 0; i < 2; i++) sdg_adml_string(b, c, lang, brand[i], file);
  for (i = 0; i < SDG_NCAT; i++) {
    sprintf(key, "policy.cat.%s", sdg_cat_ids[i]);
    sdg_lower_inplace(key);
    sdg_adml_string(b, c, lang, key, file);
  }
  for (i = 0; i < 2; i++) sdg_adml_string(b, c, lang, sup[i], file);
  for (i = 0; i < t->npolicies; i++) {
    const sdg_policy *p = &t->policies[i];
    sprintf(key, "policy.%s.title", p->name);
    sdg_lower_inplace(key);
    sdg_adml_string(b, c, lang, key, file);
    sprintf(key, "policy.%s.explain", p->name);
    sdg_lower_inplace(key);
    sdg_adml_string(b, c, lang, key, file);
    if (p->kind == SDG_ENUM)
      for (j = 0; j < p->nvalues; j++) {
        sprintf(key, "policy.%s.opt.%s", p->name, p->values[j]);
        sdg_lower_inplace(key);
        sdg_adml_string(b, c, lang, key, file);
      }
  }
}

/* One ADML file for a locale. Returns errors added (missing translations). */
int sdg_emit_adml(sdg_sb *b, const sdg_table *t, const sdg_catalog *c, const char *lang, const char *file)
{
  int i, before = sdg_nerrors;
  char key[SDG_KEY_MAX];
  sdg_sb_puts(b, SDG_BOM "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
  sdg_sb_puts(b, "<policyDefinitionResources revision=\"1.0\" schemaVersion=\"1.0\" xmlns=\"" SDG_NS "\">\n");
  sdg_sb_puts(b, "  <displayName>");
  sdg_xml_escape(b, sdg_text(c, lang, "policy.file.display", file));
  sdg_sb_puts(b, "</displayName>\n  <description>");
  sdg_xml_escape(b, sdg_text(c, lang, "policy.file.description", file));
  sdg_sb_puts(b, "</description>\n  <resources>\n    <stringTable>\n");
  sdg_adml_keys(b, c, lang, t, file);
  sdg_sb_puts(b, "    </stringTable>\n    <presentationTable>\n");
  for (i = 0; i < t->npolicies; i++) {
    const sdg_policy *p = &t->policies[i];
    const char *label;
    if (p->kind == SDG_BOOLEAN)
      continue;
    sprintf(key, "policy.%s.label", p->name);
    sdg_lower_inplace(key);
    label = sdg_text(c, lang, key, file);
    sdg_sb_puts(b, "      <presentation id=\"P_"); sdg_sb_puts(b, p->name); sdg_sb_puts(b, "\">");
    if (p->kind == SDG_ENUM) {
      sdg_sb_puts(b, "<dropdownList refId=\"ID_"); sdg_sb_puts(b, p->name);
      sdg_sb_puts(b, "\" noSort=\"true\">");
      sdg_xml_escape(b, label);
      sdg_sb_puts(b, "</dropdownList>");
    } else if (p->kind == SDG_DECIMAL) {
      sdg_sb_puts(b, "<decimalTextBox refId=\"ID_"); sdg_sb_puts(b, p->name); sdg_sb_puts(b, "\">");
      sdg_xml_escape(b, label);
      sdg_sb_puts(b, "</decimalTextBox>");
    } else {
      sdg_sb_puts(b, "<textBox refId=\"ID_"); sdg_sb_puts(b, p->name); sdg_sb_puts(b, "\"><label>");
      sdg_xml_escape(b, label);
      sdg_sb_puts(b, "</label></textBox>");
    }
    sdg_sb_puts(b, "</presentation>\n");
  }
  sdg_sb_puts(b, "    </presentationTable>\n  </resources>\n</policyDefinitionResources>\n");
  return sdg_nerrors - before;
}

/* ---- generated headers ---- */

void sdg_emit_ids_header(sdg_sb *b, const sdg_table *t)
{
  int i;
  sdg_sb_puts(b, "/* Generated by tools/sd-admxgen from res/policy/policies.txt. Do not edit. */\n");
  sdg_sb_puts(b, "#ifndef SD_POLICY_IDS_H\n#define SD_POLICY_IDS_H\n\n");
  sdg_sb_puts(b, "typedef enum sd_policy_id {\n");
  for (i = 0; i < t->npolicies; i++) {
    const char *p;
    sdg_sb_puts(b, "  SD_POLICY_");
    for (p = t->policies[i].name; *p; p++) {
      char c = *p;
      if (c >= 'a' && c <= 'z')
        c = (char)(c - 'a' + 'A');
      sdg_sb_add(b, &c, 1);
    }
    sdg_sb_printf(b, " = %d,\n", i);
  }
  sdg_sb_puts(b, "  SD_POLICY_ID_COUNT\n} sd_policy_id;\n\n#endif\n");
}

void sdg_emit_table_header(sdg_sb *b, const sdg_table *t)
{
  int i;
  sdg_sb_puts(b, "/* Generated by tools/sd-admxgen from res/policy/policies.txt. Do not edit.\n");
  sdg_sb_puts(b, " * Included by src/sd_policy/sd_policy.c only (needs sd_policy.h for the types). */\n");
  sdg_sb_puts(b, "#define SD_POLICY_REGKEY L\"");
  sdg_c_escape(b, t->key);
  sdg_sb_puts(b, "\"\n\n");
  sdg_sb_puts(b, "static const sd_policy_def sd_policy_defs[SD_POLICY_ID_COUNT] = {\n");
  for (i = 0; i < t->npolicies; i++) {
    const sdg_policy *p = &t->policies[i];
    const char *kind = p->kind == SDG_BOOLEAN ? "BOOLEAN" : p->kind == SDG_ENUM ? "ENUM" :
                       p->kind == SDG_TEXT ? "TEXT" : "DECIMAL";
    int dword = p->kind == SDG_BOOLEAN || p->kind == SDG_DECIMAL || (p->kind == SDG_ENUM && p->numeric);
    sdg_sb_puts(b, "  { L\""); sdg_sb_puts(b, p->name);
    sdg_sb_printf(b, "\", SD_POLICY_KIND_%s, SD_POLICY_REG_%s, %luUL, %luUL, %luUL },\n", kind,
                  dword ? "DWORD" : "SZ", dword ? p->min : 0UL, dword ? p->max : 0UL,
                  p->kind == SDG_TEXT ? p->maxlen : 0UL);
  }
  sdg_sb_puts(b, "};\n");
}

/* ---- files ---- */

static char *sdg_read_file(const char *path)
{
  FILE *f = fopen(path, "rb");
  char *buf;
  long size;
  size_t got;
  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  size = ftell(f);
  if (size < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
  buf = (char *)malloc((size_t)size + 1);
  if (buf == NULL) sdg_die_oom();
  got = fread(buf, 1, (size_t)size, f);
  fclose(f);
  buf[got] = 0;
  return buf;
}

static int sdg_write_file(const char *path, const sdg_sb *b)
{
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    fprintf(stderr, "sd-admxgen: cannot write %s\n", path);
    return 0;
  }
  if (b->len && fwrite(b->p, 1, b->len, f) != b->len) {
    fclose(f);
    fprintf(stderr, "sd-admxgen: short write to %s\n", path);
    return 0;
  }
  return fclose(f) == 0;
}

/* ---- main ---- */

#ifndef SD_ADMXGEN_NO_MAIN

static void sdg_usage(void)
{
  fprintf(stderr, "usage: sd-admxgen --table <policies.txt> --po-dir <dir> --out-dir <dir> "
                  "--header-dir <dir> [--check]\n");
}

int main(int argc, char **argv)
{
  const char *table_path = NULL, *po_dir = NULL, *out_dir = NULL, *hdr_dir = NULL;
  int check = 0, i, ok;
  char *text;
  static sdg_table t;
  static sdg_catalog cats[SDG_NLOCALES];
  sdg_sb admx = { 0, 0, 0 }, ids = { 0, 0, 0 }, tbl = { 0, 0, 0 }, adml = { 0, 0, 0 };

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--table") == 0 && i + 1 < argc) table_path = argv[++i];
    else if (strcmp(argv[i], "--po-dir") == 0 && i + 1 < argc) po_dir = argv[++i];
    else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) out_dir = argv[++i];
    else if (strcmp(argv[i], "--header-dir") == 0 && i + 1 < argc) hdr_dir = argv[++i];
    else if (strcmp(argv[i], "--check") == 0) check = 1;
    else { sdg_usage(); return 2; }
  }
  if (table_path == NULL || po_dir == NULL || (!check && (out_dir == NULL || hdr_dir == NULL))) {
    sdg_usage();
    return 2;
  }
  sdg_diag = stderr;

  text = sdg_read_file(table_path);
  if (text == NULL) {
    fprintf(stderr, "sd-admxgen: cannot read %s\n", table_path);
    return 1;
  }
  sdg_parse_table_text(&t, text, table_path);
  free(text);

  for (i = 0; i < SDG_NLOCALES; i++) {
    char file[512];
    sprintf(file, "%s/%s.po", po_dir, sdg_locales[i].code);
    text = sdg_read_file(file);
    if (text == NULL) {
      fprintf(stderr, "sd-admxgen: cannot read %s\n", file);
      sdg_nerrors++;
      continue;
    }
    sdg_parse_po_text(&cats[i], text, i == 0, file);
    free(text);
  }

  /* Validation: every locale's ADML must build without missing keys (output discarded here). */
  if (sdg_nerrors == 0) {
    sdg_emit_admx(&admx, &t);
    for (i = 0; i < SDG_NLOCALES; i++) {
      char file[512];
      sprintf(file, "%s/%s.po", po_dir, sdg_locales[i].code);
      sdg_emit_adml(&adml, &t, &cats[i], sdg_locales[i].code, file);
      adml.len = 0;
      if (adml.p)
        adml.p[0] = 0;
    }
  }
  sdg_emit_ids_header(&ids, &t);
  sdg_emit_table_header(&tbl, &t);

  if (sdg_nerrors == 0 && !check) {
    char file[512];
    sprintf(file, "%s/ShellDrive.admx", out_dir);
    ok = sdg_write_file(file, &admx);
    for (i = 0; ok && i < SDG_NLOCALES; i++) {
      adml.len = 0;
      if (adml.p)
        adml.p[0] = 0;
      sdg_emit_adml(&adml, &t, &cats[i], sdg_locales[i].code, "");
      sprintf(file, "%s/%s/ShellDrive.adml", out_dir, sdg_locales[i].culture);
      ok = sdg_write_file(file, &adml);
    }
    sprintf(file, "%s/sd_policy_ids.h", hdr_dir);
    ok = ok && sdg_write_file(file, &ids);
    sprintf(file, "%s/sd_policy_table.h", hdr_dir);
    ok = ok && sdg_write_file(file, &tbl);
    if (!ok)
      sdg_nerrors++;
  }
  if (sdg_nerrors)
    fprintf(stderr, "sd-admxgen: %d error(s)\n", sdg_nerrors);

  sdg_sb_free(&admx);
  sdg_sb_free(&ids);
  sdg_sb_free(&tbl);
  sdg_sb_free(&adml);
  return sdg_nerrors ? 1 : 0;
}

#endif /* SD_ADMXGEN_NO_MAIN */
