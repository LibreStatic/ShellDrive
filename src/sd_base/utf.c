#include "sd_base/sd_utf.h"
#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"

#include <string.h>

#define SD_REPLACEMENT_CHAR 0xFFFDu

/* Decodes one well-formed UTF-8 sequence at s[0..n). Returns its length (1..4) and sets *cp, or 0 if
   the bytes at s do not start a valid, shortest-form, non-surrogate sequence <= U+10FFFF. */
static size_t utf8_decode(const uint8_t *s, size_t n, uint32_t *cp)
{
  uint32_t c = s[0], min;
  size_t len, i;
  if (c < 0x80) { *cp = c; return 1; }
  if (c < 0xC2) return 0;                       /* continuation byte or overlong 2-byte lead */
  if (c < 0xE0)      { len = 2; c &= 0x1F; min = 0x80; }
  else if (c < 0xF0) { len = 3; c &= 0x0F; min = 0x800; }
  else if (c < 0xF5) { len = 4; c &= 0x07; min = 0x10000; }
  else return 0;
  if (n < len) return 0;
  for (i = 1; i < len; i++) {
    if ((s[i] & 0xC0) != 0x80) return 0;
    c = (c << 6) | (s[i] & 0x3Fu);
  }
  if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) return 0;
  *cp = c;
  return len;
}

static size_t utf8_encode(uint32_t c, uint8_t out[4])
{
  if (c < 0x80) { out[0] = (uint8_t)c; return 1; }
  if (c < 0x800) {
    out[0] = (uint8_t)(0xC0 | (c >> 6));
    out[1] = (uint8_t)(0x80 | (c & 0x3F));
    return 2;
  }
  if (c < 0x10000) {
    out[0] = (uint8_t)(0xE0 | (c >> 12));
    out[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
    out[2] = (uint8_t)(0x80 | (c & 0x3F));
    return 3;
  }
  out[0] = (uint8_t)(0xF0 | (c >> 18));
  out[1] = (uint8_t)(0x80 | ((c >> 12) & 0x3F));
  out[2] = (uint8_t)(0x80 | ((c >> 6) & 0x3F));
  out[3] = (uint8_t)(0x80 | (c & 0x3F));
  return 4;
}

/* Reads one code point from UTF-16. Returns units consumed (1 or 2), or 0 for an unpaired surrogate. */
static size_t utf16_decode(const wchar_t *s, size_t n, uint32_t *cp)
{
  uint32_t c = (uint16_t)s[0];
  if (c < 0xD800 || c > 0xDFFF) { *cp = c; return 1; }
  if (c <= 0xDBFF && n >= 2) {
    uint32_t d = (uint16_t)s[1];
    if (d >= 0xDC00 && d <= 0xDFFF) {
      *cp = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
      return 2;
    }
  }
  return 0;
}

/* Appends a code point as UTF-16 to out if it fits; always advances *pos. */
static void put16(wchar_t *out, size_t cap, size_t *pos, uint32_t c)
{
  if (c >= 0x10000) {
    c -= 0x10000;
    if (out && *pos + 2 <= cap) {
      out[*pos] = (wchar_t)(0xD800 + (c >> 10));
      out[*pos + 1] = (wchar_t)(0xDC00 + (c & 0x3FF));
    }
    *pos += 2;
  } else {
    if (out && *pos < cap)
      out[*pos] = (wchar_t)c;
    *pos += 1;
  }
}

static void put8(char *out, size_t cap, size_t *pos, uint32_t c)
{
  uint8_t tmp[4];
  size_t k = utf8_encode(c, tmp), i;
  for (i = 0; i < k; i++) {
    if (out && *pos < cap)
      out[*pos] = (char)tmp[i];
    (*pos)++;
  }
}

int sd_utf8_valid(const char *in, size_t len)
{
  const uint8_t *s = (const uint8_t *)in;
  size_t i = 0, k;
  uint32_t cp;
  while (i < len) {
    k = utf8_decode(s + i, len - i, &cp);
    if (k == 0)
      return 0;
    i += k;
  }
  return 1;
}

sd_err sd_utf8_to_utf16(const char *in, size_t len, wchar_t *out, size_t cap, size_t *out_len,
                        uint32_t flags)
{
  const uint8_t *s = (const uint8_t *)in;
  size_t i = 0, pos = 0, k;
  uint32_t cp;
  while (i < len) {
    k = utf8_decode(s + i, len - i, &cp);
    if (k == 0) {
      if (!(flags & SD_UTF_REPLACE)) {
        if (out_len) *out_len = 0;
        return SD_E_INVALID_PARAM;
      }
      cp = SD_REPLACEMENT_CHAR;
      k = 1;
    }
    put16(out, cap, &pos, cp);
    i += k;
  }
  if (out_len) *out_len = pos;
  return (out && pos > cap) ? SD_E_INVALID_PARAM : SD_OK;
}

sd_err sd_utf16_to_utf8(const wchar_t *in, size_t len, char *out, size_t cap, size_t *out_len,
                        uint32_t flags)
{
  size_t i = 0, pos = 0, k;
  uint32_t cp;
  while (i < len) {
    k = utf16_decode(in + i, len - i, &cp);
    if (k == 0) {
      if (!(flags & SD_UTF_REPLACE)) {
        if (out_len) *out_len = 0;
        return SD_E_INVALID_PARAM;
      }
      cp = SD_REPLACEMENT_CHAR;
      k = 1;
    }
    put8(out, cap, &pos, cp);
    i += k;
  }
  if (out_len) *out_len = pos;
  return (out && pos > cap) ? SD_E_INVALID_PARAM : SD_OK;
}

sd_err sd_utf8_to_wide_alloc(const char *in, size_t len, uint32_t flags, wchar_t **out)
{
  size_t need, bytes;
  sd_err e;
  wchar_t *w;
  *out = NULL;
  if (len == (size_t)-1)
    len = strlen(in);
  e = sd_utf8_to_utf16(in, len, NULL, 0, &need, flags);
  if (e != SD_OK)
    return e;
  if (sd_add_ovf(need, 1, &bytes) || sd_mul_ovf(bytes, sizeof(wchar_t), &bytes))
    return SD_E_NO_MEMORY;
  w = (wchar_t *)sd_alloc(bytes);
  if (w == NULL)
    return SD_E_NO_MEMORY;
  sd_utf8_to_utf16(in, len, w, need, &need, flags);
  w[need] = 0;
  *out = w;
  return SD_OK;
}

sd_err sd_wide_to_utf8_alloc(const wchar_t *in, size_t len, uint32_t flags, char **out)
{
  size_t need, bytes;
  sd_err e;
  char *s;
  *out = NULL;
  if (len == (size_t)-1)
    len = wcslen(in);
  e = sd_utf16_to_utf8(in, len, NULL, 0, &need, flags);
  if (e != SD_OK)
    return e;
  if (sd_add_ovf(need, 1, &bytes))
    return SD_E_NO_MEMORY;
  s = (char *)sd_alloc(bytes);
  if (s == NULL)
    return SD_E_NO_MEMORY;
  sd_utf16_to_utf8(in, len, s, need, &need, flags);
  s[need] = 0;
  *out = s;
  return SD_OK;
}

/* ---- stage 1 name mapping (01 §10.7) ---- */

#define SD_NAME_ESC_BASE 0xF700u
#define SD_NAME_ESC_LO   0xF780u
#define SD_NAME_ESC_HI   0xF7FFu

sd_err sd_name_to_wide(const char *bytes, uint32_t len, wchar_t *out, uint32_t cap, uint32_t *out_len)
{
  const uint8_t *s = (const uint8_t *)bytes;
  size_t i = 0, pos = 0, k, j;
  uint32_t cp;
  while (i < len) {
    k = utf8_decode(s + i, len - i, &cp);
    if (k != 0 && !(cp >= SD_NAME_ESC_LO && cp <= SD_NAME_ESC_HI)) {
      put16(out, cap, &pos, cp);
      i += k;
      continue;
    }
    if (k == 0)
      k = 1;                                    /* escape just this byte, resync at the next */
    for (j = 0; j < k; j++)                     /* bytes here are always >= 0x80 */
      put16(out, cap, &pos, SD_NAME_ESC_BASE + s[i + j]);
    i += k;
  }
  if (pos > UINT32_MAX)
    return SD_E_NAME_TOO_LONG;
  if (out_len) *out_len = (uint32_t)pos;
  return (out && pos > cap) ? SD_E_NAME_TOO_LONG : SD_OK;
}

sd_err sd_name_from_wide(const wchar_t *w, uint32_t len, char *out, uint32_t cap, uint32_t *out_len)
{
  size_t i = 0, pos = 0, k;
  uint32_t cp;
  if (out_len) *out_len = 0;
  while (i < len) {
    k = utf16_decode(w + i, len - i, &cp);
    if (k == 0 || cp == 0 || cp == '/')
      return SD_E_INVALID_NAME;
    if (cp >= SD_NAME_ESC_LO && cp <= SD_NAME_ESC_HI) {
      if (out && pos < cap)
        out[pos] = (char)(uint8_t)(cp - SD_NAME_ESC_BASE);
      pos++;
    } else {
      put8(out, cap, &pos, cp);
    }
    i += k;
  }
  if (pos > UINT32_MAX)
    return SD_E_NAME_TOO_LONG;
  if (out_len) *out_len = (uint32_t)pos;
  return (out && pos > cap) ? SD_E_NAME_TOO_LONG : SD_OK;
}

sd_err sd_name_component_check(const char *bytes, uint32_t len)
{
  uint32_t i;
  if (len == 0)
    return SD_E_INVALID_NAME;
  if ((len == 1 && bytes[0] == '.') || (len == 2 && bytes[0] == '.' && bytes[1] == '.'))
    return SD_E_INVALID_NAME;
  for (i = 0; i < len; i++) {
    if (bytes[i] == 0 || bytes[i] == '/')
      return SD_E_INVALID_NAME;
  }
  return SD_OK;
}

/* ---- server text sanitization (TM-R09) ---- */

static int is_removed_cp(uint32_t c, int host)
{
  if (c < 0x20)
    return host || !(c == '\t' || c == '\n' || c == '\r');
  if (c == 0x7F || (c >= 0x80 && c <= 0x9F))
    return 1;
  if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) ||
      c == 0x200E || c == 0x200F || c == 0x061C)
    return 1;                                   /* bidi controls */
  if ((c >= 0x200B && c <= 0x200D) || c == 0x2060 || c == 0xFEFF || c == 0x180E)
    return 1;                                   /* zero-width / invisible */
  return 0;
}

static sd_err sanitize(const char *in, size_t len, char *out, size_t cap, size_t *out_len, int host)
{
  const uint8_t *s = (const uint8_t *)in;
  size_t i = 0, pos = 0, k;
  uint32_t cp;
  while (i < len) {
    k = utf8_decode(s + i, len - i, &cp);
    if (k == 0) {
      cp = SD_REPLACEMENT_CHAR;
      k = 1;
    }
    if (!is_removed_cp(cp, host))
      put8(out, cap, &pos, cp);
    i += k;
  }
  if (out_len) *out_len = pos;
  return (out && pos > cap) ? SD_E_INVALID_PARAM : SD_OK;
}

sd_err sd_text_sanitize_server(const char *in, size_t len, char *out, size_t cap, size_t *out_len)
{
  return sanitize(in, len, out, cap, out_len, 0);
}

sd_err sd_text_sanitize_host(const char *in, size_t len, char *out, size_t cap, size_t *out_len)
{
  return sanitize(in, len, out, cap, out_len, 1);
}
