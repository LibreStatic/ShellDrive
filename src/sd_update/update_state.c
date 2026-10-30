/* sd_update state (04 §9.2, §9.3; C8): the anti-rollback and freshness records of each channel.
 *
 *   last_serial.<channel>      decimal serial of the last accepted manifest (max over the readable copies)
 *   last_verified.<channel>    unix seconds of the last successful verification
 *   keyset, roots              the accepted keyset.txt bytes and the accepted root keys
 *   manifest.<channel>         the last accepted manifest bytes (same-serial check, dokany-deny list)
 *
 * Writes go to <name>.tmp and are moved over the file with MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH), so a
 * reader sees the old or the new content, never a mix. The per-machine directory is read only here (the
 * elevated setup writes it). Files are read with a size cap. */
#include <windows.h>
#include <string.h>

#include "sd_update/sd_update.h"
#include "sd_base/sd_mem.h"
#include "update_internal.h"

#define STATE_FILE_MAX 4096u
#define BLOB_MAX       (SD_UPD_KEYSET_MAX + 4096u)

int upd_wcpy(wchar_t *dst, size_t cap, const wchar_t *src)
{
  size_t n = wcslen(src);
  if (n + 1 > cap)
    return 0;
  memcpy(dst, src, (n + 1) * sizeof(wchar_t));
  return 1;
}

int upd_wcat(wchar_t *dst, size_t cap, const wchar_t *src)
{
  size_t n = wcslen(dst), m = wcslen(src);
  if (n + m + 1 > cap)
    return 0;
  memcpy(dst + n, src, (m + 1) * sizeof(wchar_t));
  return 1;
}

/* dir\name into out. */
static int path_join(wchar_t *out, size_t cap, const wchar_t *dir, const wchar_t *name)
{
  if (!upd_wcpy(out, cap, dir))
    return 0;
  if (!upd_wcat(out, cap, L"\\"))
    return 0;
  return upd_wcat(out, cap, name);
}

/* "<prefix>.<channel>" */
static int channel_name(wchar_t *out, size_t cap, const wchar_t *prefix, const char *channel)
{
  wchar_t ch[16];
  size_t i, n = strlen(channel);
  if (n == 0 || n >= SD_COUNTOF(ch))
    return 0;
  for (i = 0; i < n; i++)
    ch[i] = (wchar_t)(unsigned char)channel[i];
  ch[n] = L'\0';
  if (!upd_wcpy(out, cap, prefix))
    return 0;
  if (!upd_wcat(out, cap, L"."))
    return 0;
  return upd_wcat(out, cap, ch);
}

static int channel_ok(const char *channel)
{
  return channel && (strcmp(channel, "stable") == 0 || strcmp(channel, "beta") == 0);
}

static void ensure_dir(const wchar_t *dir)
{
  if (dir)
    CreateDirectoryW(dir, NULL);          /* exists or fails with a reason the write reports */
}

/* Reads a whole file (at most max bytes). Missing file: SD_UPD_E_STATE with *len = 0. */
static sd_upd_res read_file(const wchar_t *path, size_t max, uint8_t **buf, size_t *len)
{
  HANDLE h;
  LARGE_INTEGER sz;
  DWORD got = 0;
  uint8_t *p;
  *buf = NULL;
  *len = 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_UPD_E_STATE;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || (unsigned long long)sz.QuadPart > max) {
    CloseHandle(h);
    return SD_UPD_E_TOO_LARGE;
  }
  p = (uint8_t *)sd_alloc((size_t)sz.QuadPart + 1);
  if (p == NULL) {
    CloseHandle(h);
    return SD_UPD_E_NO_MEMORY;
  }
  if (sz.QuadPart > 0 && (!ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    CloseHandle(h);
    sd_free(p);
    return SD_UPD_E_IO;
  }
  CloseHandle(h);
  p[got] = 0;
  *buf = p;
  *len = got;
  return SD_UPD_OK;
}

/* Writes <path>.tmp, flushes, then replaces <path> atomically. */
static sd_upd_res write_file_atomic(const wchar_t *path, const uint8_t *buf, size_t len)
{
  wchar_t tmp[MAX_PATH * 2];
  HANDLE h;
  DWORD put = 0;
  if (!upd_wcpy(tmp, SD_COUNTOF(tmp), path) || !upd_wcat(tmp, SD_COUNTOF(tmp), L".tmp"))
    return SD_UPD_E_INVALID;
  h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_UPD_E_STATE;
  if ((len && (!WriteFile(h, buf, (DWORD)len, &put, NULL) || put != (DWORD)len)) || !FlushFileBuffers(h)) {
    CloseHandle(h);
    DeleteFileW(tmp);
    return SD_UPD_E_STATE;
  }
  CloseHandle(h);
  if (!MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(tmp);
    return SD_UPD_E_STATE;
  }
  return SD_UPD_OK;
}

static int parse_decimal(const uint8_t *s, size_t n, uint64_t *out)
{
  uint64_t v = 0;
  size_t i = 0;
  while (i < n && (s[i] == ' ' || s[i] == '\r' || s[i] == '\n'))
    i++;
  if (i == n)
    return 0;
  for (; i < n && s[i] >= '0' && s[i] <= '9'; i++) {
    if (v > (UINT64_MAX - 9) / 10)
      return 0;
    v = v * 10u + (uint64_t)(s[i] - '0');
  }
  while (i < n && (s[i] == ' ' || s[i] == '\r' || s[i] == '\n'))
    i++;
  if (i != n)
    return 0;
  *out = v;
  return 1;
}

static void format_decimal(uint64_t v, char *out)
{
  char tmp[24];
  size_t n = 0, i;
  do {
    tmp[n++] = (char)('0' + (v % 10u));
    v /= 10u;
  } while (v);
  for (i = 0; i < n; i++)
    out[i] = tmp[n - 1 - i];
  out[n++] = '\n';
  out[n] = '\0';
}

/* Reads one decimal record from dir\name. Missing file: returns 0 with *found = 0. */
static sd_upd_res read_decimal(const wchar_t *dir, const wchar_t *name, uint64_t *v, int *found)
{
  wchar_t path[MAX_PATH * 2];
  uint8_t *buf = NULL;
  size_t len = 0;
  sd_upd_res r;
  *found = 0;
  if (dir == NULL || !path_join(path, SD_COUNTOF(path), dir, name))
    return SD_UPD_OK;
  r = read_file(path, STATE_FILE_MAX, &buf, &len);
  if (r == SD_UPD_E_STATE)
    return SD_UPD_OK;                   /* absent: not an error */
  if (r != SD_UPD_OK)
    return r;
  if (!parse_decimal(buf, len, v)) {
    sd_free(buf);
    return SD_UPD_E_STATE;              /* corrupt record: never silently reset a counter */
  }
  sd_free(buf);
  *found = 1;
  return SD_UPD_OK;
}

/* Pre-integration single file "last_serial": migrated once to last_serial.<channel>. */
static void migrate_legacy_serial(const sd_upd_state_dirs *d, const char *channel)
{
  wchar_t legacy[MAX_PATH * 2], target_name[64];
  uint64_t v;
  int found = 0;
  if (d->user == NULL || !channel_ok(channel))
    return;
  if (!channel_name(target_name, SD_COUNTOF(target_name), L"last_serial", channel))
    return;
  if (read_decimal(d->user, L"last_serial", &v, &found) != SD_UPD_OK || !found)
    return;
  {
    wchar_t tp[MAX_PATH * 2];
    uint64_t cur = 0;
    int have = 0;
    if (read_decimal(d->user, target_name, &cur, &have) != SD_UPD_OK)
      return;
    if (!have && path_join(tp, SD_COUNTOF(tp), d->user, target_name)) {
      char txt[32];
      format_decimal(v, txt);
      if (write_file_atomic(tp, (const uint8_t *)txt, strlen(txt)) != SD_UPD_OK)
        return;
    }
  }
  if (path_join(legacy, SD_COUNTOF(legacy), d->user, L"last_serial"))
    DeleteFileW(legacy);                /* migrated: the legacy file is ours to remove */
}

sd_upd_res sd_upd_state_read_serial(const sd_upd_state_dirs *d, const char *channel, uint64_t *serial)
{
  wchar_t name[64];
  uint64_t best = 0, v;
  int found;
  sd_upd_res r;
  if (d == NULL || serial == NULL || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"last_serial", channel))
    return SD_UPD_E_INVALID;
  migrate_legacy_serial(d, channel);
  if ((r = read_decimal(d->user, name, &v, &found)) != SD_UPD_OK) return r;
  if (found && v > best) best = v;
  if ((r = read_decimal(d->machine, name, &v, &found)) != SD_UPD_OK) return r;
  if (found && v > best) best = v;
  *serial = best;                       /* per channel maximum of what can be read (04 §9.2) */
  return SD_UPD_OK;
}

sd_upd_res sd_upd_state_write_serial(const sd_upd_state_dirs *d, const char *channel, uint64_t serial)
{
  wchar_t name[64], path[MAX_PATH * 2];
  char txt[32];
  uint64_t cur = 0;
  sd_upd_res r;
  if (d == NULL || d->user == NULL || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"last_serial", channel))
    return SD_UPD_E_INVALID;
  if ((r = sd_upd_state_read_serial(d, channel, &cur)) != SD_UPD_OK)
    return r;
  if (serial < cur)
    return SD_UPD_E_ROLLBACK;
  ensure_dir(d->user);
  if (!path_join(path, SD_COUNTOF(path), d->user, name))
    return SD_UPD_E_INVALID;
  format_decimal(serial, txt);
  return write_file_atomic(path, (const uint8_t *)txt, strlen(txt));
}

sd_upd_res sd_upd_state_read_verified(const sd_upd_state_dirs *d, const char *channel, int64_t *unix_s)
{
  wchar_t name[64];
  uint64_t best = 0, v;
  int found;
  sd_upd_res r;
  if (d == NULL || unix_s == NULL || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"last_verified", channel))
    return SD_UPD_E_INVALID;
  if ((r = read_decimal(d->user, name, &v, &found)) != SD_UPD_OK) return r;
  if (found && v > best) best = v;
  if ((r = read_decimal(d->machine, name, &v, &found)) != SD_UPD_OK) return r;
  if (found && v > best) best = v;
  *unix_s = (int64_t)best;
  return SD_UPD_OK;
}

sd_upd_res sd_upd_state_write_verified(const sd_upd_state_dirs *d, const char *channel, int64_t unix_s)
{
  wchar_t name[64], path[MAX_PATH * 2];
  char txt[32];
  if (d == NULL || d->user == NULL || unix_s < 0 || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"last_verified", channel))
    return SD_UPD_E_INVALID;
  ensure_dir(d->user);
  if (!path_join(path, SD_COUNTOF(path), d->user, name))
    return SD_UPD_E_INVALID;
  format_decimal((uint64_t)unix_s, txt);
  return write_file_atomic(path, (const uint8_t *)txt, strlen(txt));
}

/* Reads a named blob: the per-user copy, else the per-machine copy. */
static sd_upd_res read_blob_from(const wchar_t *dir, const wchar_t *name, size_t max, uint8_t **buf, size_t *len)
{
  wchar_t path[MAX_PATH * 2];
  if (dir == NULL || !path_join(path, SD_COUNTOF(path), dir, name)) {
    *buf = NULL;
    *len = 0;
    return SD_UPD_E_STATE;
  }
  return read_file(path, max, buf, len);
}

sd_upd_res sd_upd_state_read_blob(const sd_upd_state_dirs *d, const wchar_t *name, uint8_t **buf, size_t *len)
{
  sd_upd_res r;
  if (d == NULL || name == NULL || buf == NULL || len == NULL)
    return SD_UPD_E_INVALID;
  r = read_blob_from(d->user, name, BLOB_MAX, buf, len);
  if (r == SD_UPD_OK)
    return r;
  if (r != SD_UPD_E_STATE)
    return r;
  return read_blob_from(d->machine, name, BLOB_MAX, buf, len);
}

sd_upd_res sd_upd_state_write_blob(const sd_upd_state_dirs *d, const wchar_t *name, const uint8_t *buf, size_t len)
{
  wchar_t path[MAX_PATH * 2];
  if (d == NULL || d->user == NULL || name == NULL || len > BLOB_MAX)
    return SD_UPD_E_INVALID;
  ensure_dir(d->user);
  if (!path_join(path, SD_COUNTOF(path), d->user, name))
    return SD_UPD_E_INVALID;
  return write_file_atomic(path, buf, len);
}

sd_upd_res sd_upd_state_read_manifest(const sd_upd_state_dirs *d, const char *channel, uint8_t **buf, size_t *len)
{
  wchar_t name[64];
  if (d == NULL || buf == NULL || len == NULL || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"manifest", channel))
    return SD_UPD_E_INVALID;
  return sd_upd_state_read_blob(d, name, buf, len);
}

sd_upd_res sd_upd_state_write_manifest(const sd_upd_state_dirs *d, const char *channel, const uint8_t *buf, size_t len)
{
  wchar_t name[64];
  if (d == NULL || !channel_ok(channel) || !channel_name(name, SD_COUNTOF(name), L"manifest", channel))
    return SD_UPD_E_INVALID;
  return sd_upd_state_write_blob(d, name, buf, len);
}
