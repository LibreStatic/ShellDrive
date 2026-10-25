/* Name mapping stage 2, case folding and the ~cN collision rule (02 §1.2, §1.3, §1.6, §4.5).
 * Thread safety: pure functions, any thread. */
#include <windows.h>
#include <stdio.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "vfs_internal.h"

#define PUA_BASE 0xF000u

WCHAR *vfs_wcsndup(const WCHAR *w, size_t n)
{
  WCHAR *r = (WCHAR *)sd_alloc((n + 1) * sizeof(WCHAR));
  if (r) {
    if (n) memcpy(r, w, n * sizeof(WCHAR));
    r[n] = 0;
  }
  return r;
}

WCHAR *vfs_wcsdup(const WCHAR *w) { return vfs_wcsndup(w, wcslen(w)); }

char *vfs_strndup(const char *s, size_t n)
{
  char *r = (char *)sd_alloc(n + 1);
  if (r) {
    if (n) memcpy(r, s, n);
    r[n] = 0;
  }
  return r;
}

uint32_t vfs_hash_w(const WCHAR *w)
{
  uint32_t h = 2166136261u;
  for (; *w; w++) {
    h ^= (uint32_t)*w;
    h *= 16777619u;
  }
  return h;
}

/* Characters illegal in Win32 names that stage 2 maps to U+F000 + ch anywhere in a component. */
static int is_win_illegal(uint32_t c)
{
  return (c >= 1 && c <= 0x1F) || c == '"' || c == '*' || c == ':' || c == '<' || c == '>' || c == '?' ||
         c == '\\' || c == '|';
}

sd_vfs_status vfs_name_to_display(const char *raw, uint32_t raw_len, WCHAR **out, uint32_t *out_len)
{
  uint32_t n = 0, i;
  WCHAR *w;
  *out = NULL;
  if (sd_name_to_wide(raw, raw_len, NULL, 0, &n) != SD_OK)
    return SD_VFS_E_INVALID_NAME;
  w = (WCHAR *)sd_alloc(((size_t)n + 1) * sizeof(WCHAR));
  if (!w)
    return SD_VFS_E_NO_MEMORY;
  if (sd_name_to_wide(raw, raw_len, w, n, &n) != SD_OK) {
    sd_free(w);
    return SD_VFS_E_INVALID_NAME;
  }
  for (i = 0; i < n; i++) {
    if (is_win_illegal(w[i]))
      w[i] = (WCHAR)(PUA_BASE + w[i]);
  }
  /* Only the last character: Win32 strips trailing dots and spaces ("a.." -> "a." + U+F02E). */
  if (n > 0 && (w[n - 1] == L' ' || w[n - 1] == L'.'))
    w[n - 1] = (WCHAR)(PUA_BASE + w[n - 1]);
  w[n] = 0;
  *out = w;
  if (out_len) *out_len = n;
  return SD_VFS_OK;
}

/* Inverse of stage 2: decodes ONLY the code points the forward map produces (TM-R11). */
static uint32_t stage2_inverse(uint32_t c, int last)
{
  if (c >= 0xF001u && c <= 0xF01Fu)
    return c - PUA_BASE;
  switch (c) {
    case 0xF022: case 0xF02A: case 0xF03A: case 0xF03C: case 0xF03E: case 0xF03F: case 0xF05C: case 0xF07C:
      return c - PUA_BASE;
    case 0xF020: case 0xF02E:
      return last ? c - PUA_BASE : c;
    default:
      return c;
  }
}

sd_vfs_status vfs_name_from_display(const WCHAR *w, uint32_t len, char **out, uint32_t *out_len)
{
  WCHAR *tmp;
  uint32_t i, n = 0;
  char *r;
  sd_err e;
  *out = NULL;
  if (len == 0)
    return SD_VFS_E_INVALID_NAME;
  tmp = vfs_wcsndup(w, len);
  if (!tmp)
    return SD_VFS_E_NO_MEMORY;
  for (i = 0; i < len; i++)
    tmp[i] = (WCHAR)stage2_inverse(tmp[i], i + 1 == len);
  e = sd_name_from_wide(tmp, len, NULL, 0, &n);
  if (e != SD_OK) {
    sd_free(tmp);
    return e == SD_E_NAME_TOO_LONG ? SD_VFS_E_NAME_TOO_LONG : SD_VFS_E_INVALID_NAME;
  }
  r = (char *)sd_alloc((size_t)n + 1);
  if (!r) {
    sd_free(tmp);
    return SD_VFS_E_NO_MEMORY;
  }
  e = sd_name_from_wide(tmp, len, r, n, &n);
  sd_free(tmp);
  if (e != SD_OK || sd_name_component_check(r, n) != SD_OK) {
    sd_free(r);
    return SD_VFS_E_INVALID_NAME;     /* wire invariant on the final bytes (02 §1.2) */
  }
  r[n] = 0;
  *out = r;
  if (out_len) *out_len = n;
  return SD_VFS_OK;
}

sd_vfs_status vfs_name_check_input(const WCHAR *w, uint32_t len)
{
  uint32_t i;
  if (len == 0)
    return SD_VFS_E_INVALID_NAME;
  if (len > VFS_MAX_WIN_COMPONENT)
    return SD_VFS_E_NAME_TOO_LONG;
  for (i = 0; i < len; i++) {
    WCHAR c = w[i];
    /* ':' is stream syntax (rejected, 02 §1.1); the rest cannot appear in a Win32 name. */
    if (c < 0x20 || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' ||
        c == L'|' || c == L'/' || c == L'\\')
      return SD_VFS_E_INVALID_NAME;
  }
  return SD_VFS_OK;
}

WCHAR *vfs_fold(const WCHAR *w, uint32_t len)
{
  WCHAR *r = vfs_wcsndup(w, len);
  if (r && len > 0) {
    if (LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, w, (int)len, r, (int)len) != (int)len) {
      uint32_t i;                         /* fallback: ASCII only */
      for (i = 0; i < len; i++)
        r[i] = (w[i] >= L'a' && w[i] <= L'z') ? (WCHAR)(w[i] - 32) : w[i];
    }
    r[len] = 0;
  }
  return r;
}

int vfs_has_pua(const WCHAR *w, uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++) {
    if (w[i] >= 0xF000 && w[i] <= 0xF07F)
      return 1;
  }
  return 0;
}

static int ends_with_ci(const WCHAR *s, const WCHAR *suffix)
{
  size_t ls = wcslen(s), lx = wcslen(suffix);
  return ls >= lx && _wcsicmp(s + ls - lx, suffix) == 0;
}

int vfs_is_shell_active(const WCHAR *name)
{
  static const WCHAR *const k_ext[] = { L".library-ms", L".searchConnector-ms", L".url", L".lnk", L".scf" };
  size_t i;
  if (_wcsicmp(name, L"desktop.ini") == 0)
    return 1;
  for (i = 0; i < SD_COUNTOF(k_ext); i++) {
    if (ends_with_ci(name, k_ext[i]))
      return 1;
  }
  return 0;
}

int vfs_is_probe_name(const WCHAR *name)
{
  static const WCHAR *const k_names[] = { L"desktop.ini", L"Thumbs.db", L"folder.jpg", L"folder.gif",
                                          L"AutoRun.inf", L"$RECYCLE.BIN", L"System Volume Information" };
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_names); i++) {
    if (_wcsicmp(name, k_names[i]) == 0)
      return 1;
  }
  return 0;
}

/* ---- ~cN collision rule (02 §1.3) ---- */

static int raw_cmp(const vfs_dirent *a, const vfs_dirent *b)
{
  uint32_t m = SD_MIN(a->raw_len, b->raw_len);
  int c = memcmp(a->raw, b->raw, m);
  if (c != 0) return c;
  return a->raw_len < b->raw_len ? -1 : a->raw_len > b->raw_len ? 1 : 0;
}

/* Stable merge sort by raw bytes. */
static void sort_raw(vfs_dirent *e, vfs_dirent *tmp, uint32_t n)
{
  uint32_t mid, i, j, k;
  if (n < 2)
    return;
  mid = n / 2;
  sort_raw(e, tmp, mid);
  sort_raw(e + mid, tmp, n - mid);
  i = 0; j = mid; k = 0;
  while (i < mid && j < n)
    tmp[k++] = raw_cmp(&e[j], &e[i]) < 0 ? e[j++] : e[i++];
  while (i < mid) tmp[k++] = e[i++];
  while (j < n) tmp[k++] = e[j++];
  memcpy(e, tmp, (size_t)n * sizeof(*e));
}

typedef struct key_set { const WCHAR **slot; uint32_t cap; } key_set;

static int ks_init(key_set *s, uint32_t n)
{
  uint32_t cap = 16;
  while (cap < n * 2 + 16) cap <<= 1;
  s->slot = (const WCHAR **)sd_calloc(cap, sizeof(*s->slot));
  s->cap = cap;
  return s->slot != NULL;
}

/* Returns 1 if inserted, 0 if already present. The set never fills (sized 2n + 16 for n + mangles). */
static int ks_add(key_set *s, const WCHAR *k)
{
  uint32_t i = vfs_hash_w(k) & (s->cap - 1);
  while (s->slot[i]) {
    if (wcscmp(s->slot[i], k) == 0)
      return 0;
    i = (i + 1) & (s->cap - 1);
  }
  s->slot[i] = k;
  return 1;
}

static int ks_has(const key_set *s, const WCHAR *k)
{
  uint32_t i = vfs_hash_w(k) & (s->cap - 1);
  while (s->slot[i]) {
    if (wcscmp(s->slot[i], k) == 0)
      return 1;
    i = (i + 1) & (s->cap - 1);
  }
  return 0;
}

uint32_t vfs_mangle_collisions(vfs_dirent *e, uint32_t n, BOOL fold)
{
  vfs_dirent *tmp;
  key_set all, used;
  uint32_t i, renamed = 0, nold = 0;
  WCHAR **old;                            /* replaced names/keys: freed at the end (the sets point at them) */
  if (n < 2)
    return 0;
  tmp = (vfs_dirent *)sd_alloc((size_t)n * sizeof(*tmp));
  if (!tmp)
    return (uint32_t)-1;
  sort_raw(e, tmp, n);
  sd_free(tmp);
  /* The mangled keys must also avoid every original key; 2n slots cover originals + renamed. */
  all.slot = used.slot = NULL;
  old = (WCHAR **)sd_calloc((size_t)n * 2, sizeof(*old));
  if (!old || !ks_init(&all, n * 2) || !ks_init(&used, n * 2)) {
    sd_free((void *)all.slot);
    sd_free(old);
    return (uint32_t)-1;
  }
  for (i = 0; i < n; i++)
    ks_add(&all, e[i].key);
  for (i = 0; i < n; i++) {
    WCHAR buf[VFS_MAX_RAW_NAME + 32];
    const WCHAR *dot;
    size_t stem_len, wl;
    uint32_t c;
    WCHAR *nw, *nk;
    if (ks_add(&used, e[i].key))
      continue;
    wl = e[i].wlen;
    if (wl > VFS_MAX_RAW_NAME)
      continue;                            /* cannot happen: raw names are capped at 4096 bytes */
    dot = wcsrchr(e[i].wname, L'.');
    stem_len = (dot && dot != e[i].wname) ? (size_t)(dot - e[i].wname) : wl;
    for (c = 2;; c++) {
      int k = _snwprintf_s(buf, SD_COUNTOF(buf), _TRUNCATE, L"%.*s~c%u%s", (int)stem_len, e[i].wname, c,
                           e[i].wname + stem_len);
      if (k < 0)
        break;
      nk = fold ? vfs_fold(buf, (uint32_t)k) : vfs_wcsndup(buf, (size_t)k);
      if (!nk)
        break;
      if (!ks_has(&all, nk) && !ks_has(&used, nk)) {
        nw = vfs_wcsndup(buf, (size_t)k);
        if (!nw) {
          sd_free(nk);
          break;
        }
        old[nold++] = e[i].wname;
        old[nold++] = e[i].key;
        e[i].wname = nw;
        e[i].wlen = (uint32_t)k;
        e[i].key = nk;
        ks_add(&used, nk);
        renamed++;
        break;
      }
      sd_free(nk);
    }
  }
  sd_free((void *)all.slot);
  sd_free((void *)used.slot);
  for (i = 0; i < nold; i++)
    sd_free(old[i]);
  sd_free(old);
  return renamed;
}
