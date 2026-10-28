/* menu.cache text (docs/design/03-apps-platform.md §8.2.2): sanitizing of profile names and formatting of the file.
 * Pure code: no Win32 calls, no allocation, no global state. The writer (menucache.c) and the shell extension's
 * parser (apps/shelldrive-shellext/shellext_model.c, shx_menucache_parse) follow the same rules, and the shell
 * extension's test build links this file to check the round trip. */
#include <string.h>

#include "sd_config/sd_config.h"

#define MF_HEADER      "SDMENU 1\n"
#define MF_HEADER_LEN  9u
#define MF_ID_LEN      32u

/* Bidi controls, zero-width characters, the byte-order mark and the soft hyphen (03 §2.5). The same set that
   shx_menu_label removes for display, so a name reads the same in the menu and in the file. */
static int mf_invisible(unsigned c)
{
  return (c >= 0x200Bu && c <= 0x200Fu) || (c >= 0x202Au && c <= 0x202Eu) || (c >= 0x2060u && c <= 0x2064u) ||
         (c >= 0x2066u && c <= 0x2069u) || c == 0x061Cu || c == 0xFEFFu || c == 0x00ADu;
}

static int mf_control(unsigned c)
{
  return c < 0x20u || (c >= 0x7Fu && c <= 0x9Fu);
}

/* Decodes the UTF-8 sequence at s (n bytes left). Returns its length (1..4) and sets *cp, or 0 when the bytes are
   not a valid sequence (overlong forms, surrogates and values above U+10FFFF included). */
static size_t mf_decode(const unsigned char *s, size_t n, unsigned *cp)
{
  unsigned char b = s[0];
  size_t extra, k;
  unsigned v;

  if (b < 0x80u) {
    *cp = b;
    return 1;
  }
  if (b >= 0xC2u && b <= 0xDFu) {
    extra = 1;
    v = b & 0x1Fu;
  } else if (b >= 0xE0u && b <= 0xEFu) {
    extra = 2;
    v = b & 0x0Fu;
  } else if (b >= 0xF0u && b <= 0xF4u) {
    extra = 3;
    v = b & 0x07u;
  } else {
    return 0;
  }
  if (n < extra + 1)
    return 0;
  for (k = 1; k <= extra; k++) {
    if ((s[k] & 0xC0u) != 0x80u)
      return 0;
    v = (v << 6) | (s[k] & 0x3Fu);
  }
  if ((extra == 2 && v < 0x800u) || (extra == 3 && v < 0x10000u) || v > 0x10FFFFu || (v >= 0xD800u && v <= 0xDFFFu))
    return 0;
  *cp = v;
  return extra + 1;
}

/* Copies the sanitized form of in into out (cap bytes, NUL-terminated). Invalid UTF-8 bytes, control, bidi and
   zero-width characters are dropped; the result is cut before the first character that would exceed
   SD_MENU_NAME_UNITS UTF-16 units; leading and trailing spaces are trimmed. Returns the byte length (0 = empty). */
static size_t mf_clean_name(const char *in, char *out, size_t cap)
{
  const unsigned char *s = (const unsigned char *)in;
  size_t n = strlen(in), i = 0, o = 0, units = 0, start = 0;

  if (cap == 0)
    return 0;
  while (i < n) {
    unsigned cp = 0;
    size_t len = mf_decode(s + i, n - i, &cp), u;

    if (len == 0) {
      i++;
      continue;
    }
    if (mf_control(cp) || mf_invisible(cp)) {
      i += len;
      continue;
    }
    u = cp >= 0x10000u ? 2u : 1u;
    if (units + u > SD_MENU_NAME_UNITS || o + len + 1 > cap)
      break;
    memcpy(out + o, s + i, len);
    o += len;
    units += u;
    i += len;
  }
  while (start < o && out[start] == ' ')
    start++;
  while (o > start && out[o - 1] == ' ')
    o--;
  if (start > 0)
    memmove(out, out + start, o - start);
  out[o - start] = '\0';
  return o - start;
}

/* 1 when id is 32 lowercase hex digits. */
static int mf_valid_id(const char *id)
{
  size_t i;
  for (i = 0; i < MF_ID_LEN; i++) {
    char c = id[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 0;
  }
  return id[MF_ID_LEN] == '\0';
}

sd_err sd_menu_entry_from_profile(const sd_profile *p, sd_menu_entry *e)
{
  if (p == NULL || e == NULL || !mf_valid_id(p->id))
    return SD_E_INVALID_PARAM;
  if (mf_clean_name(p->name, e->name, sizeof(e->name)) == 0)
    return SD_E_INVALID_PARAM;
  memcpy(e->id, p->id, MF_ID_LEN + 1);
  return SD_OK;
}

/* Sort key order: ASCII case-insensitive, then bytes. UTF-8 byte order is code point order, so this is stable for
   every name the sanitizer lets through. */
static int mf_name_less(const char *a, const char *b)
{
  for (;;) {
    unsigned char x = (unsigned char)*a, y = (unsigned char)*b;
    if (x >= 'A' && x <= 'Z')
      x = (unsigned char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z')
      y = (unsigned char)(y - 'A' + 'a');
    if (x != y)
      return x < y;
    if (x == 0)
      return 0;
    a++;
    b++;
  }
}

/* An entry the formatter can write: valid id and a non-empty name without control characters. Entries from
   sd_menu_entry_from_profile always are; the check keeps a hand-built entry from breaking the one-tab-per-line form. */
static int mf_entry_ok(const sd_menu_entry *e)
{
  const unsigned char *s = (const unsigned char *)e->name;
  if (!mf_valid_id(e->id) || s[0] == '\0')
    return 0;
  for (; *s != '\0'; s++) {
    if (*s < 0x20u || *s == 0x7Fu)
      return 0;
  }
  return 1;
}

size_t sd_menu_format(const sd_menu_entry *e, size_t n, char *out, size_t cap)
{
  const sd_menu_entry *sel[SD_MENU_MAX_PROFILES];
  size_t m = 0, i, j, o = 0;

  if (out == NULL || cap < MF_HEADER_LEN || (e == NULL && n != 0))
    return 0;

  /* Valid entries in input order (the first of two equal ids wins), at most SD_MENU_MAX_PROFILES. */
  for (i = 0; i < n && m < SD_MENU_MAX_PROFILES; i++) {
    if (!mf_entry_ok(&e[i]))
      continue;
    for (j = 0; j < m; j++) {
      if (strcmp(sel[j]->id, e[i].id) == 0)
        break;
    }
    if (j == m)
      sel[m++] = &e[i];
  }

  /* Insertion sort by name: at most 256 pointers, and the list is small. */
  for (i = 1; i < m; i++) {
    const sd_menu_entry *key = sel[i];
    j = i;
    while (j > 0 && mf_name_less(key->name, sel[j - 1]->name)) {
      sel[j] = sel[j - 1];
      j--;
    }
    sel[j] = key;
  }

  memcpy(out, MF_HEADER, MF_HEADER_LEN);
  o = MF_HEADER_LEN;
  for (i = 0; i < m; i++) {
    size_t nl = strlen(sel[i]->name);
    size_t need = MF_ID_LEN + 1 + nl + 1;
    if (o + need > cap || o + need > SD_MENU_MAX_BYTES)
      break;
    memcpy(out + o, sel[i]->id, MF_ID_LEN);
    o += MF_ID_LEN;
    out[o++] = '\t';
    memcpy(out + o, sel[i]->name, nl);
    o += nl;
    out[o++] = '\n';
  }
  return o;
}
