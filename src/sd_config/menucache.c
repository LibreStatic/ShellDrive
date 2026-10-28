/* menu.cache writer (docs/design/03-apps-platform.md §8.2.2). The file is
 *   %LOCALAPPDATA%\LibreStatic\ShellDrive\state\menu.cache
 * the same path apps/shelldrive-shellext/shellext_cache.c reads (read-only, owner checked). It is rewritten from the
 * profile store by sd_profile_save_ex and sd_profile_delete (under config.lock, so the CLI, the UI and the agent all
 * go through here), and once by sd_menucache_refresh after an import.
 *
 * The write goes to menu.cache.<pid>.tmp in the same folder, is flushed, and is moved over menu.cache with
 * MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH): a reader sees the old or the new file, never a mix. MoveFileExW is
 * in Windows XP, so no separate XP path exists (the other atomic writers in the tree do the same). The reader opens
 * the file with FILE_SHARE_DELETE, so the replacement does not wait for it. Nothing but profile ids and names is
 * written. */
#include <windows.h>
#include <string.h>

#include <stdio.h>

#include "sd_config/sd_config.h"
#include "config_internal.h"
#include "sd_base/sd_mem.h"

#define MC_FILE_NAME  L"menu.cache"
#define MC_MOVE_TRIES 5

typedef struct mc_collect {
  sd_menu_entry *items;
  size_t n;
} mc_collect;

static int mc_collect_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  mc_collect *c = (mc_collect *)ctx;
  (void)path;
  if (c->n >= SD_MENU_MAX_PROFILES)
    return 0;
  if (sd_menu_entry_from_profile(p, &c->items[c->n]) == SD_OK)
    c->n++;
  return 1;
}

sd_err sd_menucache_path(wchar_t *out, size_t cch)
{
  wchar_t dir[MAX_PATH];
  sd_err e = sd_config_state_dir(dir, SD_COUNTOF(dir));
  if (e != SD_OK)
    return e;
  if (_snwprintf_s(out, cch, _TRUNCATE, L"%s\\%s", dir, MC_FILE_NAME) < 0)
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

/* Writes data to path through a temporary file in the same folder, then replaces path. */
static sd_err mc_write_atomic(const wchar_t *path, const void *data, size_t len)
{
  wchar_t tmp[MAX_PATH + 32];
  HANDLE h;
  DWORD put = 0;
  BOOL ok;
  int tries;

  if (_snwprintf_s(tmp, SD_COUNTOF(tmp), _TRUNCATE, L"%s.%lu.tmp", path, (unsigned long)GetCurrentProcessId()) < 0)
    return SD_E_NAME_TOO_LONG;
  h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_ACCESS_DENIED;
  ok = WriteFile(h, data, (DWORD)len, &put, NULL) && put == (DWORD)len && FlushFileBuffers(h);
  CloseHandle(h);
  if (!ok) {
    DeleteFileW(tmp);
    return SD_E_FAILURE;
  }
  for (tries = 0; tries < MC_MOVE_TRIES; tries++) {
    if (MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      return SD_OK;
    /* A scanner or an Explorer thread may hold the old file for a moment. */
    Sleep(20);
  }
  DeleteFileW(tmp);
  return SD_E_FAILURE;
}

sd_err sd_menucache_rewrite(void)
{
  mc_collect c;
  char *buf;
  size_t len = 0;
  wchar_t path[MAX_PATH + 32];
  sd_err e;

  c.items = (sd_menu_entry *)sd_alloc(sizeof(sd_menu_entry) * SD_MENU_MAX_PROFILES);
  buf = (char *)sd_alloc(SD_MENU_MAX_BYTES);
  if (c.items == NULL || buf == NULL) {
    sd_free(c.items);
    sd_free(buf);
    return SD_E_NO_MEMORY;
  }
  c.n = 0;
  e = sd_profile_enum(mc_collect_cb, &c);
  if (e == SD_OK) {
    len = sd_menu_format(c.items, c.n, buf, SD_MENU_MAX_BYTES);
    e = len == 0 ? SD_E_FAILURE : sd_menucache_path(path, SD_COUNTOF(path));
  }
  if (e == SD_OK)
    e = mc_write_atomic(path, buf, len);
  sd_free(c.items);
  sd_free(buf);
  return e;
}

sd_err sd_menucache_refresh(void)
{
  HANDLE lock = NULL;
  sd_err e = sd_config_lock(&lock, 5000);
  if (e != SD_OK)
    return e;
  e = sd_menucache_rewrite();
  sd_config_unlock(lock);
  return e;
}
