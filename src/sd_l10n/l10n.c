/* sd_l10n runtime (03 §9.3-§9.5): language resolution, CLDR plural categories, cached UTF-16
 * strings and the named-placeholder formatter.
 *
 * M0 notes: the settings.ini [ui] language step of 9.3 is not consulted yet (the caller may pass it
 * as override_code); SD_ARG_SIZE renders the byte count with digit grouping and SD_ARG_DURATION_MS
 * the millisecond count (unit names are catalog entries of each binary, so the caller formats
 * human-friendly units itself); SD_ARG_FILETIME uses GetDateFormatW/GetTimeFormatW of the user locale. */
#include <windows.h>
#include <string.h>

#include "sd_l10n/sd_l10n.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_policy/sd_policy.h"

static const sd_l10n_catalog *g_cat;
static sd_lang g_lang = SD_LANG_EN;
/* g_cache[id * SD_PLURAL_CAT_COUNT + cat]: lazily converted UTF-16 of the resolved string. */
static wchar_t *volatile *g_cache;

static const char *const k_codes[SD_LANG_COUNT] = { "en", "es", "fr", "pt-BR", "it", "de", "qps-ploc" };

const char *sd_l10n_lang_code(sd_lang lang)
{
  return (unsigned)lang < (unsigned)SD_LANG_COUNT ? k_codes[lang] : "en";
}

static int wide_ieq_ascii(const wchar_t *w, size_t n, const char *a)
{
  size_t i;
  for (i = 0; i < n; i++) {
    wchar_t c = w[i];
    char d = a[i];
    if (d == '\0') return 0;
    if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    if (d >= 'A' && d <= 'Z') d = (char)(d - 'A' + 'a');
    if (c != (wchar_t)d) return 0;
  }
  return a[n] == '\0';
}

int sd_l10n_parse_lang(const wchar_t *code, sd_lang *out)
{
  size_t n, prim;
  sd_lang l;
  if (code == NULL)
    return 0;
  n = wcslen(code);
  if (n == 0 || n > 16)
    return 0;
  if (wide_ieq_ascii(code, n, "pt") || wide_ieq_ascii(code, n, "pt-br") ||
      wide_ieq_ascii(code, n, "pt_br")) {
    *out = SD_LANG_PT_BR;
    return 1;
  }
  for (l = SD_LANG_EN; l < SD_LANG_PSEUDO; l = (sd_lang)(l + 1)) {
    if (wide_ieq_ascii(code, n, k_codes[l])) {
      *out = l;
      return 1;
    }
  }
  /* Region-qualified codes ("es-AR", "de_CH", "fr-CA"): match by primary language. */
  for (prim = 0; prim < n && code[prim] != L'-' && code[prim] != L'_'; prim++)
    ;
  if (prim < n) {
    if (wide_ieq_ascii(code, prim, "pt")) { *out = SD_LANG_PT_BR; return 1; }
    for (l = SD_LANG_EN; l < SD_LANG_PSEUDO; l = (sd_lang)(l + 1)) {
      if (l != SD_LANG_PT_BR && wide_ieq_ascii(code, prim, k_codes[l])) {
        *out = l;
        return 1;
      }
    }
  }
  return 0;
}

static int lang_from_langid(LANGID id, sd_lang *out)
{
  switch (PRIMARYLANGID(id)) {
  case LANG_ENGLISH:    *out = SD_LANG_EN; return 1;
  case LANG_SPANISH:    *out = SD_LANG_ES; return 1;
  case LANG_FRENCH:     *out = SD_LANG_FR; return 1;
  case LANG_PORTUGUESE: *out = SD_LANG_PT_BR; return 1;
  case LANG_ITALIAN:    *out = SD_LANG_IT; return 1;
  case LANG_GERMAN:     *out = SD_LANG_DE; return 1;
  default: return 0;
  }
}

static int lang_from_policy(sd_lang *out)
{
  wchar_t buf[32];
  if (!sd_policy_get_sz(SD_POLICY_UILANGUAGE, buf, SD_COUNTOF(buf)))
    return 0;
  return sd_l10n_parse_lang(buf, out);
}

sd_lang sd_l10n_init(const sd_l10n_catalog *catalog, const wchar_t *override_code)
{
  sd_lang l = SD_LANG_EN;
  if (catalog != NULL && catalog->abi == SD_L10N_CATALOG_ABI) {
    size_t n = (size_t)catalog->count * SD_PLURAL_CAT_COUNT, i;
    /* Re-initialization (tests, a language switch before other threads start) drops the cache. */
    if (g_cache != NULL) {
      size_t old = g_cat ? (size_t)g_cat->count * SD_PLURAL_CAT_COUNT : 0;
      for (i = 0; i < old; i++)
        sd_free(g_cache[i]);
      sd_free((void *)g_cache);
      g_cache = NULL;
    }
    g_cat = catalog;
    if (n)
      g_cache = (wchar_t *volatile *)sd_calloc(n, sizeof(wchar_t *));
  }
  if (override_code && override_code[0] && catalog != NULL && catalog->abi == SD_L10N_CATALOG_ABI &&
      catalog->strings[SD_LANG_PSEUDO] != NULL && wide_ieq_ascii(override_code, wcslen(override_code), "qps-ploc")) {
    l = SD_LANG_PSEUDO;            /* Debug builds only: the catalog carries the table */
  } else if (override_code && override_code[0] && sd_l10n_parse_lang(override_code, &l)) {
    /* explicit choice */
  } else if (lang_from_policy(&l)) {
    /* policy UILanguage (HKLM wins, sd_policy) */
  } else if (!lang_from_langid(GetUserDefaultUILanguage(), &l)) {
    l = SD_LANG_EN;
  }
  g_lang = l;
  return l;
}

sd_lang sd_l10n_lang(void)
{
  return g_lang;
}

sd_plural_cat sd_l10n_plural_category(sd_lang lang, long long n)
{
  long long a = n < 0 ? -n : n;
  switch (lang) {
  case SD_LANG_ES:
  case SD_LANG_IT:
    if (a == 1) return SD_PLURAL_ONE;
    if (a != 0 && a % 1000000 == 0) return SD_PLURAL_MANY;
    return SD_PLURAL_OTHER;
  case SD_LANG_FR:
  case SD_LANG_PT_BR:
    if (a == 0 || a == 1) return SD_PLURAL_ONE;
    if (a % 1000000 == 0) return SD_PLURAL_MANY;
    return SD_PLURAL_OTHER;
  case SD_LANG_EN:
  case SD_LANG_DE:
  default:
    return a == 1 ? SD_PLURAL_ONE : SD_PLURAL_OTHER;
  }
}

/* UTF-8 template for (id, category) in the current language, with en and key fallbacks. */
static const char *lookup(sd_msg_id id, sd_plural_cat cat)
{
  const char *s;
  size_t idx;
  if (g_cat == NULL || id >= g_cat->count)
    return NULL;
  idx = (size_t)id * SD_PLURAL_CAT_COUNT + (size_t)cat;
  s = g_cat->strings[g_lang] ? g_cat->strings[g_lang][idx] : NULL;
  if (s == NULL && g_cat->strings[SD_LANG_EN])
    s = g_cat->strings[SD_LANG_EN][idx];
  if (s == NULL && cat != SD_PLURAL_OTHER)
    return lookup(id, SD_PLURAL_OTHER);
  if (s == NULL)
    s = g_cat->keys[id];
  return s;
}

static wchar_t *to_wide(const char *s)
{
  wchar_t *w = NULL;
  if (s == NULL || sd_utf8_to_wide_alloc(s, (size_t)-1, SD_UTF_REPLACE, &w) != SD_OK)
    return NULL;
  return w;
}

const wchar_t *sd_l10n_get(sd_msg_id id)
{
  size_t idx;
  wchar_t *w;
  if (g_cat == NULL || g_cache == NULL || id >= g_cat->count)
    return L"";
  idx = (size_t)id * SD_PLURAL_CAT_COUNT + SD_PLURAL_OTHER;
  w = g_cache[idx];
  if (w)
    return w;
  w = to_wide(lookup(id, SD_PLURAL_OTHER));
  if (w == NULL)
    return L"";
  if (InterlockedCompareExchangePointer((PVOID volatile *)&g_cache[idx], w, NULL) != NULL) {
    sd_free(w);   /* another thread won */
    w = g_cache[idx];
  }
  return w;
}

/* ---- formatting ---- */

typedef struct fmt_out { wchar_t *buf; size_t cch, len; int overflow; } fmt_out;

static void out_w(fmt_out *o, const wchar_t *s, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
    if (o->buf && o->len + 1 < o->cch)
      o->buf[o->len] = s[i];
    else
      o->overflow = 1;
    o->len++;
  }
}

static void out_utf8(fmt_out *o, const char *s, size_t n)
{
  wchar_t tmp[128];
  size_t got = 0;
  while (n) {
    /* convert in chunks; a chunk boundary inside a sequence is avoided by backing off */
    size_t take = n > 120 ? 120 : n;
    while (take < n && take > 0 && ((unsigned char)s[take] & 0xC0) == 0x80)
      take--;
    if (take == 0) take = n > 120 ? 120 : n;
    if (sd_utf8_to_utf16(s, take, tmp, SD_COUNTOF(tmp), &got, SD_UTF_REPLACE) == SD_OK)
      out_w(o, tmp, got);
    s += take;
    n -= take;
  }
}

static void format_int(fmt_out *o, long long v)
{
  wchar_t raw[32], dec[8], thou[8], grp[16], res[64];
  size_t n = 0, i;
  unsigned long long m = v < 0 ? (unsigned long long)0 - (unsigned long long)v : (unsigned long long)v;
  wchar_t tmp[32];
  NUMBERFMTW nf;
  int r;
  do { tmp[n++] = (wchar_t)(L'0' + (m % 10u)); m /= 10u; } while (m);
  i = 0;
  if (v < 0) raw[i++] = L'-';
  while (n) raw[i++] = tmp[--n];
  raw[i] = 0;
  memset(&nf, 0, sizeof(nf));
  if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL, dec, SD_COUNTOF(dec)) &&
      GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STHOUSAND, thou, SD_COUNTOF(thou)) &&
      GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SGROUPING, grp, SD_COUNTOF(grp))) {
    nf.NumDigits = 0;
    nf.LeadingZero = 1;
    /* LOCALE_SGROUPING -> NUMBERFMT: "3;0" -> 3 (repeat), "3;2;0" -> 32, "3" -> 30 (no repeat) */
    {
      UINT g = 0, digits = 0, last = 0;
      for (i = 0; grp[i]; i++)
        if (grp[i] >= L'0' && grp[i] <= L'9') {
          last = (UINT)(grp[i] - L'0');
          g = g * 10 + last;
          digits++;
        }
      if (digits > 1 && last == 0) g /= 10;
      else g *= 10;
      nf.Grouping = g;
    }
    nf.lpDecimalSep = dec;
    nf.lpThousandSep = thou;
    nf.NegativeOrder = 1;
    r = GetNumberFormatW(LOCALE_USER_DEFAULT, 0, raw, &nf, res, SD_COUNTOF(res));
    if (r > 1) {
      out_w(o, res, (size_t)(r - 1));
      return;
    }
  }
  out_w(o, raw, wcslen(raw));
}

static void format_filetime(fmt_out *o, FILETIME ft)
{
  FILETIME local;
  SYSTEMTIME st;
  wchar_t d[64], t[64];
  int nd, nt;
  if (!FileTimeToLocalFileTime(&ft, &local) || !FileTimeToSystemTime(&local, &st))
    return;
  nd = GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, d, SD_COUNTOF(d));
  nt = GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_NOSECONDS, &st, NULL, t, SD_COUNTOF(t));
  if (nd > 1) out_w(o, d, (size_t)(nd - 1));
  if (nd > 1 && nt > 1) out_w(o, L" ", 1);
  if (nt > 1) out_w(o, t, (size_t)(nt - 1));
}

static const sd_arg *find_arg(const sd_arg *args, size_t nargs, const char *name, size_t n)
{
  size_t i;
  for (i = 0; i < nargs; i++)
    if (args[i].name && strlen(args[i].name) == n && memcmp(args[i].name, name, n) == 0)
      return &args[i];
  return NULL;
}

static void render(fmt_out *o, const char *tpl, const sd_arg *args, size_t nargs)
{
  const char *p = tpl, *lit = tpl;
  while (*p) {
    if ((p[0] == '{' && p[1] == '{') || (p[0] == '}' && p[1] == '}')) {
      out_utf8(o, lit, (size_t)(p - lit));
      out_utf8(o, p, 1);
      p += 2;
      lit = p;
      continue;
    }
    if (p[0] == '{') {
      const char *e = p + 1;
      while (*e && *e != '}' && *e != '{')
        e++;
      if (*e == '}') {
        const sd_arg *a = find_arg(args, nargs, p + 1, (size_t)(e - p - 1));
        out_utf8(o, lit, (size_t)(p - lit));
        if (a == NULL) {
          out_utf8(o, p, (size_t)(e - p + 1));     /* missing argument: rendered literally */
        } else {
          switch (a->type) {
          case SD_ARG_STR:
            if (a->v.s) out_w(o, a->v.s, wcslen(a->v.s));
            break;
          case SD_ARG_INT:
          case SD_ARG_SIZE:
          case SD_ARG_DURATION_MS:
            format_int(o, a->v.i);
            break;
          case SD_ARG_FILETIME:
            format_filetime(o, a->v.t);
            break;
          }
        }
        p = e + 1;
        lit = p;
        continue;
      }
    }
    p++;
  }
  out_utf8(o, lit, (size_t)(p - lit));
}

static const char *select_template(sd_msg_id id, const sd_arg *args, size_t nargs)
{
  sd_plural_cat cat = SD_PLURAL_OTHER;
  if (g_cat && id < g_cat->count && g_cat->plural_arg[id]) {
    const char *pa = g_cat->plural_arg[id];
    const sd_arg *a = find_arg(args, nargs, pa, strlen(pa));
    if (a && a->type != SD_ARG_STR && a->type != SD_ARG_FILETIME)
      cat = sd_l10n_plural_category(g_lang, a->v.i);
  }
  return lookup(id, cat);
}

int sd_l10n_format(wchar_t *buf, size_t cch, sd_msg_id id, const sd_arg *args, size_t nargs)
{
  fmt_out o;
  const char *tpl = select_template(id, args, nargs);
  o.buf = buf; o.cch = cch; o.len = 0; o.overflow = 0;
  if (buf == NULL || cch == 0)
    return -1;
  if (tpl)
    render(&o, tpl, args, nargs);
  buf[o.len < cch ? o.len : cch - 1] = 0;
  return o.overflow ? -1 : (int)o.len;
}

wchar_t *sd_l10n_format_alloc(sd_msg_id id, const sd_arg *args, size_t nargs)
{
  fmt_out o;
  const char *tpl = select_template(id, args, nargs);
  wchar_t *w;
  o.buf = NULL; o.cch = 0; o.len = 0; o.overflow = 0;
  if (tpl)
    render(&o, tpl, args, nargs);   /* measure */
  w = (wchar_t *)sd_calloc(o.len + 1, sizeof(wchar_t));
  if (w == NULL)
    return NULL;
  o.buf = w; o.cch = o.len + 1; o.len = 0; o.overflow = 0;
  if (tpl)
    render(&o, tpl, args, nargs);
  w[o.len < o.cch ? o.len : o.cch - 1] = 0;
  return w;
}
