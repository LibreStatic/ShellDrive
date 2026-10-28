/* Pure helpers of the shell extension. See shellext_model.h. */
#include <string.h>

#include "shellext_model.h"
#include "shellext_snapshot.h"

/* ---- characters ---- */

/* Bidi controls and zero-width characters (03 §2.5): removed from anything shown, rejected in a URL. */
static int mdl_invisible(unsigned c)
{
  return (c >= 0x200Bu && c <= 0x200Fu) || (c >= 0x202Au && c <= 0x202Eu) || (c >= 0x2060u && c <= 0x2064u) ||
         (c >= 0x2066u && c <= 0x2069u) || c == 0x061Cu || c == 0xFEFFu || c == 0x00ADu;
}

static int mdl_control(unsigned c)
{
  return c < 0x20u || (c >= 0x7Fu && c <= 0x9Fu);
}

/* ---- menu planning ---- */

size_t shx_plan_drive(uint32_t flags, uint32_t state, int is_root, int has_url, shx_act *out, size_t max)
{
  size_t n = 0;
  if (out == NULL || max == 0)
    return 0;
  if (is_root) {
    if (n < max)
      out[n++] = SHX_ACT_OPEN;
    if ((flags & SHX_F_GLOBAL) == 0) {
      if (state != SHX_STATE_UNMOUNTING && state != SHX_STATE_UNMOUNTED && n < max)
        out[n++] = SHX_ACT_UNMOUNT;
      if ((state == SHX_STATE_OFFLINE || state == SHX_STATE_AUTH_REQUIRED || state == SHX_STATE_FAILED) && n < max)
        out[n++] = SHX_ACT_RECONNECT;
    }
  }
  if (has_url && n < max)
    out[n++] = SHX_ACT_COPY_PATH;
  return n;
}

/* ---- remote path ---- */

int shx_remote_url_ok(const wchar_t *url)
{
  size_t i, n;
  if (url == NULL)
    return 0;
  n = wcsnlen(url, SHX_URL_UNITS + 1);
  if (n <= 7 || n > SHX_URL_UNITS)
    return 0;
  if (wcsncmp(url, L"sftp://", 7) != 0)
    return 0;
  for (i = 7; i < n; i++) {
    unsigned c = (unsigned)(unsigned short)url[i];
    if (mdl_control(c) || mdl_invisible(c))
      return 0;
  }
  return url[7] != L'/';                /* an authority is required */
}

typedef struct mdl_out {
  wchar_t *p;
  size_t cch;
  size_t n;
  int ok;
} mdl_out;

static void mdl_put(mdl_out *o, wchar_t c)
{
  if (!o->ok)
    return;
  if (o->n + 1 >= o->cch) {
    o->ok = 0;
    return;
  }
  o->p[o->n++] = c;
}

static void mdl_put_pct(mdl_out *o, unsigned b)
{
  static const wchar_t hex[] = L"0123456789ABCDEF";
  mdl_put(o, L'%');
  mdl_put(o, hex[(b >> 4) & 15u]);
  mdl_put(o, hex[b & 15u]);
}

/* RFC 3986 unreserved and the sub-delims, ':' and '@' that a path segment may carry as they are. */
static int mdl_pchar(unsigned c)
{
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
    return 1;
  switch (c) {
  case '-': case '.': case '_': case '~': case '!': case '$': case '&': case '\'': case '(': case ')':
  case '*': case '+': case ',': case ';': case '=': case ':': case '@':
    return 1;
  default:
    return 0;
  }
}

/* One code point at s[*i]; advances *i. Returns 0xFFFFFFFF for a lone surrogate. */
static uint32_t mdl_next_cp(const wchar_t *s, size_t *i)
{
  uint32_t c = (uint32_t)(unsigned short)s[*i];
  (*i)++;
  if (c >= 0xD800u && c <= 0xDBFFu) {
    uint32_t d = (uint32_t)(unsigned short)s[*i];
    if (d >= 0xDC00u && d <= 0xDFFFu) {
      (*i)++;
      return 0x10000u + ((c - 0xD800u) << 10) + (d - 0xDC00u);
    }
    return 0xFFFFFFFFu;
  }
  if (c >= 0xDC00u && c <= 0xDFFFu)
    return 0xFFFFFFFFu;
  return c;
}

static void mdl_put_cp(mdl_out *o, uint32_t cp)
{
  if (cp < 0x80u) {
    if (mdl_pchar(cp))
      mdl_put(o, (wchar_t)cp);
    else
      mdl_put_pct(o, cp);
  } else if (cp < 0x800u) {
    mdl_put_pct(o, 0xC0u | (cp >> 6));
    mdl_put_pct(o, 0x80u | (cp & 0x3Fu));
  } else if (cp < 0x10000u) {
    mdl_put_pct(o, 0xE0u | (cp >> 12));
    mdl_put_pct(o, 0x80u | ((cp >> 6) & 0x3Fu));
    mdl_put_pct(o, 0x80u | (cp & 0x3Fu));
  } else {
    mdl_put_pct(o, 0xF0u | (cp >> 18));
    mdl_put_pct(o, 0x80u | ((cp >> 12) & 0x3Fu));
    mdl_put_pct(o, 0x80u | ((cp >> 6) & 0x3Fu));
    mdl_put_pct(o, 0x80u | (cp & 0x3Fu));
  }
}

int shx_remote_copy_text(const wchar_t *url, const wchar_t *rel, wchar_t *out, size_t cch)
{
  mdl_out o;
  size_t base, i, rn;

  if (out == NULL || cch == 0)
    return 0;
  out[0] = 0;
  if (rel == NULL || !shx_remote_url_ok(url))
    return 0;
  rn = wcsnlen(rel, SHX_REL_MAX + 1);
  if (rn > SHX_REL_MAX)
    return 0;

  o.p = out;
  o.cch = cch;
  o.n = 0;
  o.ok = 1;

  if (rn == 0) {
    /* The drive root itself: the URL as the agent wrote it. */
    for (i = 0; url[i] != 0; i++)
      mdl_put(&o, url[i]);
  } else {
    base = wcslen(url);
    while (base > 7 && url[base - 1] == L'/')
      base--;
    for (i = 0; i < base; i++)
      mdl_put(&o, url[i]);
    i = 0;
    while (i < rn) {
      size_t start = i, end, k;
      while (i < rn && rel[i] != L'\\' && rel[i] != L'/')
        i++;
      end = i;
      if (i < rn)
        i++;                            /* the separator */
      if (end == start)
        continue;                       /* empty component */
      if ((end - start == 1 && rel[start] == L'.') ||
          (end - start == 2 && rel[start] == L'.' && rel[start + 1] == L'.')) {
        out[0] = 0;
        return 0;
      }
      mdl_put(&o, L'/');
      k = start;
      while (k < end) {
        uint32_t cp = mdl_next_cp(rel, &k);
        if (cp == 0xFFFFFFFFu) {
          out[0] = 0;
          return 0;
        }
        mdl_put_cp(&o, cp);
      }
    }
  }
  if (!o.ok) {
    out[0] = 0;
    return 0;
  }
  out[o.n] = 0;
  return 1;
}

/* ---- menu.cache ---- */

/* Strict UTF-8 -> UTF-16 of [s, s+n). Returns the number of units written (<= cap) or -1 on invalid input,
   overlong forms, surrogates, code points above U+10FFFF, control characters, or output above cap. */
static int mdl_utf8_to_utf16(const unsigned char *s, size_t n, wchar_t *out, size_t cap)
{
  size_t i = 0, o = 0;
  while (i < n) {
    uint32_t cp;
    unsigned char b = s[i];
    size_t extra, k;
    if (b < 0x80u) {
      cp = b;
      extra = 0;
    } else if (b >= 0xC2u && b <= 0xDFu) {
      cp = b & 0x1Fu;
      extra = 1;
    } else if (b >= 0xE0u && b <= 0xEFu) {
      cp = b & 0x0Fu;
      extra = 2;
    } else if (b >= 0xF0u && b <= 0xF4u) {
      cp = b & 0x07u;
      extra = 3;
    } else {
      return -1;
    }
    for (k = 1; k <= extra; k++) {
      if (i + k >= n || (s[i + k] & 0xC0u) != 0x80u)
        return -1;
      cp = (cp << 6) | (s[i + k] & 0x3Fu);
    }
    if ((extra == 2 && cp < 0x800u) || (extra == 3 && cp < 0x10000u) || cp > 0x10FFFFu ||
        (cp >= 0xD800u && cp <= 0xDFFFu) || mdl_control(cp))
      return -1;
    i += extra + 1;
    if (cp >= 0x10000u) {
      if (o + 2 > cap)
        return -1;
      cp -= 0x10000u;
      out[o++] = (wchar_t)(0xD800u + (cp >> 10));
      out[o++] = (wchar_t)(0xDC00u + (cp & 0x3FFu));
    } else {
      if (o + 1 > cap)
        return -1;
      out[o++] = (wchar_t)cp;
    }
  }
  return (int)o;
}

static int mdl_hex_lower(unsigned char c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

size_t shx_menucache_parse(const unsigned char *buf, size_t len, shx_profile *out, size_t max)
{
  size_t pos = 0, count = 0, lines = 0;
  int header = 0;

  if (buf == NULL || out == NULL || max == 0 || len == 0 || len > SHX_CACHE_MAX_BYTES)
    return 0;
  if (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
    pos = 3;
  while (pos < len) {
    size_t start = pos, end, k;
    while (pos < len && buf[pos] != '\n')
      pos++;
    end = pos;
    if (pos < len)
      pos++;
    if (end > start && buf[end - 1] == '\r')
      end--;
    if (++lines > 4u * SHX_CACHE_MAX_ENTRIES)
      break;                            /* bounded work whatever the content */

    if (!header) {
      static const unsigned char tag[] = "SDMENU 1";
      if (end - start != sizeof(tag) - 1 || memcmp(buf + start, tag, sizeof(tag) - 1) != 0)
        return 0;
      header = 1;
      continue;
    }
    if (end == start || buf[start] == '#')
      continue;
    if (count >= max || count >= SHX_CACHE_MAX_ENTRIES)
      break;
    if (end - start < SHX_ID_UNITS + 2 || buf[start + SHX_ID_UNITS] != '\t')
      continue;
    {
      shx_profile p;
      int units, dup = 0;
      for (k = 0; k < SHX_ID_UNITS; k++) {
        if (!mdl_hex_lower(buf[start + k]))
          break;
        p.id[k] = (wchar_t)buf[start + k];
      }
      if (k != SHX_ID_UNITS)
        continue;
      p.id[SHX_ID_UNITS] = 0;
      units = mdl_utf8_to_utf16(buf + start + SHX_ID_UNITS + 1, end - start - SHX_ID_UNITS - 1, p.name,
                                SHX_NAME_UNITS);
      if (units <= 0)
        continue;
      p.name[units] = 0;
      for (k = 0; k < count; k++) {
        if (wcscmp(out[k].id, p.id) == 0) {
          dup = 1;
          break;
        }
      }
      if (dup)
        continue;
      out[count++] = p;
    }
  }
  return header ? count : 0;
}

/* ---- menu label ---- */

void shx_menu_label(const wchar_t *name, wchar_t *out, size_t cch)
{
  size_t i = 0, o = 0, shown = 0;
  int cut = 0;

  if (out == NULL || cch == 0)
    return;
  out[0] = 0;
  if (name == NULL)
    return;
  while (name[i] != 0) {
    unsigned c = (unsigned)(unsigned short)name[i];
    size_t units = 1;
    if (c >= 0xD800u && c <= 0xDBFFu) {
      unsigned d = (unsigned)(unsigned short)name[i + 1];
      if (d < 0xDC00u || d > 0xDFFFu) {
        i++;                            /* lone high surrogate: dropped */
        continue;
      }
      units = 2;
    } else if (c >= 0xDC00u && c <= 0xDFFFu) {
      i++;                              /* lone low surrogate: dropped */
      continue;
    }
    if (units == 1 && mdl_invisible(c)) {
      i++;
      continue;
    }
    if (shown >= SHX_LABEL_MAX) {
      cut = 1;
      break;
    }
    if (units == 1 && mdl_control(c))
      c = ' ';
    if (c == '&') {
      if (o + 2 >= cch)
        break;
      out[o++] = L'&';
      out[o++] = L'&';
    } else {
      if (o + units >= cch)
        break;
      if (units == 2) {
        out[o++] = name[i];
        out[o++] = name[i + 1];
      } else {
        out[o++] = (wchar_t)c;
      }
    }
    shown++;
    i += units;
  }
  if (cut && o + 3 < cch) {
    out[o++] = L'.';
    out[o++] = L'.';
    out[o++] = L'.';
  }
  out[o] = 0;
}
