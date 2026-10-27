/* shelldrive-ui: WM_COPYDATA payload codec and the verb grammar (ui_wire.h). Pure, see the header. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "ui_wire.h"

static void put_u32(unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)(v & 0xFFu);
  p[1] = (unsigned char)((v >> 8) & 0xFFu);
  p[2] = (unsigned char)((v >> 16) & 0xFFu);
  p[3] = (unsigned char)((v >> 24) & 0xFFu);
}

static uint32_t get_u32(const unsigned char *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* True when the units hold no NUL and no unpaired surrogate (valid UTF-16). */
static int units_wellformed(const wchar_t *s, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned c = (unsigned)(unsigned short)s[i];
    if (c == 0)
      return 0;
    if (c >= 0xD800u && c <= 0xDBFFu) {
      unsigned d;
      if (i + 1 >= n)
        return 0;
      d = (unsigned)(unsigned short)s[i + 1];
      if (d < 0xDC00u || d > 0xDFFFu)
        return 0;
      i++;
    } else if (c >= 0xDC00u && c <= 0xDFFFu) {
      return 0;
    }
  }
  return 1;
}

static int is_ascii_letter(wchar_t c)
{
  return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
}

int ui_profile_id_valid(const wchar_t *s)
{
  size_t i;
  if (s == NULL || wcslen(s) != 32)
    return 0;
  for (i = 0; i < 32; i++) {
    wchar_t c = s[i];
    if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f')))
      return 0;
  }
  return 1;
}

int ui_drive_normalize(const wchar_t *s, wchar_t out[3])
{
  if (s == NULL || wcslen(s) != 2 || !is_ascii_letter(s[0]) || s[1] != L':')
    return 0;
  out[0] = (wchar_t)((s[0] >= L'a' && s[0] <= L'z') ? s[0] - (L'a' - L'A') : s[0]);
  out[1] = L':';
  out[2] = 0;
  return 1;
}

int ui_path_valid(const wchar_t *s)
{
  size_t i, n;
  if (s == NULL)
    return 0;
  n = wcslen(s);
  if (n < 3 || n >= UI_WIRE_MAX_UNITS || !is_ascii_letter(s[0]) || s[1] != L':' || s[2] != L'\\')
    return 0;
  for (i = 0; i < n; i++) {
    wchar_t c = s[i];
    if ((unsigned)c < 0x20u || wcschr(L"<>\"|?*", c) != NULL)
      return 0;
    if (c == L'.' && i + 1 < n && s[i + 1] == L'.')
      return 0;
  }
  return units_wellformed(s, n);
}

sd_err ui_wire_encode(int argc, const wchar_t *const *argv, unsigned char **out, size_t *out_bytes)
{
  size_t total = UI_WIRE_HEADER, off;
  int i;
  unsigned char *p;

  if (out == NULL || out_bytes == NULL || argc < 0 || (unsigned)argc > UI_WIRE_MAX_ARGS || (argc > 0 && argv == NULL))
    return SD_E_INVALID_PARAM;
  for (i = 0; i < argc; i++) {
    size_t n;
    if (argv[i] == NULL)
      return SD_E_INVALID_PARAM;
    n = wcslen(argv[i]);
    if (n >= UI_WIRE_MAX_UNITS || !units_wellformed(argv[i], n))
      return SD_E_INVALID_PARAM;
    total += 4 + 2 * n;
  }
  if (total > UI_WIRE_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  p = sd_alloc(total);
  if (p == NULL)
    return SD_E_NO_MEMORY;
  put_u32(p, UI_WIRE_MAGIC);
  put_u32(p + 4, UI_WIRE_VERSION);
  put_u32(p + 8, (uint32_t)argc);
  put_u32(p + 12, 0);
  off = UI_WIRE_HEADER;
  for (i = 0; i < argc; i++) {
    size_t j, n = wcslen(argv[i]);
    put_u32(p + off, (uint32_t)n);
    off += 4;
    for (j = 0; j < n; j++) {
      unsigned c = (unsigned)(unsigned short)argv[i][j];
      p[off + 2 * j] = (unsigned char)(c & 0xFFu);
      p[off + 2 * j + 1] = (unsigned char)(c >> 8);
    }
    off += 2 * n;
  }
  *out = p;
  *out_bytes = total;
  return SD_OK;
}

sd_err ui_request_from_args(int argc, const wchar_t *const *argv, ui_request *req)
{
  ui_request r;
  int i;

  if (req == NULL || argc < 0 || (argc > 0 && argv == NULL) || argc > (int)UI_WIRE_MAX_ARGS)
    return SD_E_INVALID_PARAM;
  memset(&r, 0, sizeof(r));
  for (i = 0; i < argc; i++) {
    if (argv[i] == NULL || wcslen(argv[i]) >= UI_WIRE_MAX_UNITS || !units_wellformed(argv[i], wcslen(argv[i])))
      return SD_E_INVALID_PARAM;
  }
  if (argc == 0) {
    r.verb = UI_VERB_NONE;
  } else if (argc == 1 && wcscmp(argv[0], L"--tray") == 0) {
    r.verb = UI_VERB_TRAY;
  } else if (argc == 1 && wcscmp(argv[0], L"--prompt-host") == 0) {
    r.verb = UI_VERB_PROMPT_HOST;
  } else if (argc == 1 && wcscmp(argv[0], L"--elevated-admin") == 0) {
    r.verb = UI_VERB_ELEVATED_ADMIN;
  } else if (argc >= 2 && wcscmp(argv[0], L"--action") == 0 && wcscmp(argv[1], L"show") == 0) {
    if (argc != 2)
      return SD_E_INVALID_PARAM;
    r.verb = UI_VERB_SHOW;
  } else if (argc == 3 && wcscmp(argv[0], L"--action") == 0) {
    const wchar_t *v = argv[1], *t = argv[2];
    if (wcscmp(v, L"mount") == 0 || wcscmp(v, L"reconnect") == 0) {
      if (ui_profile_id_valid(t)) {
        r.kind = UI_TARGET_PROFILE;
        if (wcscpy_s(r.target, UI_WIRE_MAX_UNITS + 1, t) != 0)
          return SD_E_INVALID_PARAM;
      } else if (wcscmp(v, L"reconnect") == 0 && ui_drive_normalize(t, r.target)) {
        r.kind = UI_TARGET_DRIVE;
      } else {
        return SD_E_INVALID_PARAM;
      }
      r.verb = wcscmp(v, L"mount") == 0 ? UI_VERB_MOUNT : UI_VERB_RECONNECT;
    } else if (wcscmp(v, L"unmount") == 0 || wcscmp(v, L"open") == 0) {
      if (!ui_drive_normalize(t, r.target))
        return SD_E_INVALID_PARAM;
      r.kind = UI_TARGET_DRIVE;
      r.verb = wcscmp(v, L"open") == 0 ? UI_VERB_OPEN : UI_VERB_UNMOUNT;
    } else if (wcscmp(v, L"mount-file") == 0) {
      if (!ui_path_valid(t) || wcscpy_s(r.target, UI_WIRE_MAX_UNITS + 1, t) != 0)
        return SD_E_INVALID_PARAM;
      r.kind = UI_TARGET_PATH;
      r.verb = UI_VERB_MOUNT_FILE;
    } else {
      return SD_E_INVALID_PARAM;
    }
  } else {
    return SD_E_INVALID_PARAM;
  }
  *req = r;
  return SD_OK;
}

sd_err ui_request_from_payload(const void *data, size_t bytes, ui_request *req)
{
  const unsigned char *p = (const unsigned char *)data;
  size_t pos = UI_WIRE_HEADER;
  uint32_t argc, i;
  wchar_t units[UI_WIRE_MAX_ARGS][UI_WIRE_MAX_UNITS + 1];
  const wchar_t *argv[UI_WIRE_MAX_ARGS];

  if (req == NULL || data == NULL || bytes < UI_WIRE_HEADER || bytes > UI_WIRE_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  if (get_u32(p) != UI_WIRE_MAGIC || get_u32(p + 4) != UI_WIRE_VERSION || get_u32(p + 12) != 0)
    return SD_E_INVALID_PARAM;
  argc = get_u32(p + 8);
  if (argc > UI_WIRE_MAX_ARGS)
    return SD_E_INVALID_PARAM;
  for (i = 0; i < argc; i++) {
    uint32_t n, k;
    if (bytes - pos < 4)
      return SD_E_INVALID_PARAM;
    n = get_u32(p + pos);
    pos += 4;
    if (n >= UI_WIRE_MAX_UNITS || (size_t)n * 2 > bytes - pos)
      return SD_E_INVALID_PARAM;
    for (k = 0; k < n; k++)
      units[i][k] = (wchar_t)(p[pos + 2 * k] | (p[pos + 2 * k + 1] << 8));
    units[i][n] = 0;
    if (!units_wellformed(units[i], n))
      return SD_E_INVALID_PARAM;
    argv[i] = units[i];
    pos += (size_t)n * 2;
  }
  if (pos != bytes)
    return SD_E_INVALID_PARAM;
  return ui_request_from_args((int)argc, argv, req);
}
