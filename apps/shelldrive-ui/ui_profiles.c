/* shelldrive-ui: the profile list of the main window and the file side of .sdmount files (03 §3.4, §8.1).
 *
 * The profiles are read from the per-user store with sd_profile_enum (sd_config is linked directly, 2.4
 * decision). The list is a snapshot: the UI reloads it after every save or delete. Sorted by name,
 * case-insensitively, so the list order does not depend on the file names. */
#include <windows.h>
#include <string.h>
#include <stdlib.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "ui_int.h"
#include "ui_sdmount.h"

#define UI_PROFILES_MAX 512u

static struct {
  sd_profile *items;
  size_t count, cap;
} g_profiles;

static int by_name(const void *a, const void *b)
{
  const sd_profile *pa = (const sd_profile *)a, *pb = (const sd_profile *)b;
  int c = _stricmp(pa->name, pb->name);
  if (c != 0)
    return c;
  return strcmp(pa->id, pb->id);
}

static int collect(void *ctx, const sd_profile *p, const wchar_t *path)
{
  SD_UNUSED(ctx);
  SD_UNUSED(path);
  if (g_profiles.count >= UI_PROFILES_MAX)
    return 0;
  if (g_profiles.count == g_profiles.cap) {
    size_t ncap = g_profiles.cap ? g_profiles.cap * 2 : 16;
    sd_profile *n = (sd_profile *)sd_realloc(g_profiles.items, ncap * sizeof(sd_profile));
    if (n == NULL)
      return 0;
    g_profiles.items = n;
    g_profiles.cap = ncap;
  }
  g_profiles.items[g_profiles.count++] = *p;
  return 1;
}

void ui_profiles_clear(void)
{
  sd_free(g_profiles.items);
  g_profiles.items = NULL;
  g_profiles.count = 0;
  g_profiles.cap = 0;
}

sd_err ui_profiles_load(void)
{
  sd_err e;
  ui_profiles_clear();
  e = sd_profile_enum(collect, NULL);
  if (e == SD_E_NOT_FOUND)                   /* no profiles folder yet: an empty list */
    e = SD_OK;
  if (g_profiles.count > 1)
    qsort(g_profiles.items, g_profiles.count, sizeof(sd_profile), by_name);
  return e;
}

size_t ui_profiles_count(void)
{
  return g_profiles.count;
}

const sd_profile *ui_profiles_at(size_t i)
{
  return i < g_profiles.count ? &g_profiles.items[i] : NULL;
}

const sd_profile *ui_profiles_find_id(const char *id)
{
  size_t i;
  if (id == NULL)
    return NULL;
  for (i = 0; i < g_profiles.count; i++)
    if (strcmp(g_profiles.items[i].id, id) == 0)
      return &g_profiles.items[i];
  return NULL;
}

/* Reads a .sdmount file of at most UI_SDMOUNT_MAX_BYTES + 1 bytes (the extra byte detects a larger file). */
sd_err ui_sdmount_read(const wchar_t *path, unsigned char *buf, size_t cap, size_t *len)
{
  HANDLE h;
  DWORD got = 0;
  LARGE_INTEGER size;
  *len = 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > (LONGLONG)UI_SDMOUNT_MAX_BYTES ||
      cap < UI_SDMOUNT_MAX_BYTES + 1u || !ReadFile(h, buf, UI_SDMOUNT_MAX_BYTES + 1u, &got, NULL)) {
    CloseHandle(h);
    return SD_E_INVALID_PARAM;
  }
  CloseHandle(h);
  if (got == 0 || got > UI_SDMOUNT_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  *len = got;
  return SD_OK;
}

/* Mark of the Web (03 §8.1): the file has a Zone.Identifier stream with ZoneId >= 3. An absent stream is no mark;
   an unreadable one counts as marked. */
int ui_file_has_mark(const wchar_t *path)
{
  wchar_t stream[MAX_PATH + 32];
  HANDLE h;
  char text[1024];
  DWORD got = 0;
  const char *z;
  int zone = 0;

  if (wcslen(path) + 20 >= SD_COUNTOF(stream))
    return 1;
  wcscpy_s(stream, SD_COUNTOF(stream), path);
  wcscat_s(stream, SD_COUNTOF(stream), L":Zone.Identifier");
  h = CreateFileW(stream, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND ? 0 : 1;
  if (!ReadFile(h, text, sizeof(text) - 1, &got, NULL))
    got = 0;
  CloseHandle(h);
  text[got] = 0;
  z = strstr(text, "ZoneId=");
  if (z == NULL)
    return 0;
  zone = atoi(z + 7);
  return zone >= 3;
}
