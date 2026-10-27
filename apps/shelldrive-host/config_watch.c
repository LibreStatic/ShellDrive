/* Watch of the user's configuration (see config_watch.h). One thread with two overlapped directory watches
 * (the config root for settings.ini and the creation of the profiles folder, the profiles folder for *.ini)
 * and one stop event. Debounce: a batch is delivered once 500 ms have passed since its last change. The
 * buffers are on the heap: the thread's stack stays small (a batch of paths and two read buffers). */
#include <windows.h>
#include <string.h>

#include "config_watch.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"

#define CW_LOG          "agent"
#define CW_DEBOUNCE_MS  500u
#define CW_RETRY_MS     2000u       /* reopen of the profiles folder while it does not exist */
#define CW_BUF          16384
#define CW_MAX_PATHS    64u
#define CW_FILTER       (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE)

typedef struct cw_dir {
  HANDLE dir;                       /* INVALID_HANDLE_VALUE when not open */
  HANDLE ev;
  OVERLAPPED ov;
  BYTE buf[CW_BUF];
  int armed;
} cw_dir;

/* Changes of one debounce window. */
typedef struct cw_batch {
  int settings, profiles, overflow, profiles_dir_added;
  wchar_t paths[CW_MAX_PATHS][MAX_PATH];
  uint32_t npaths;
} cw_batch;

/* The watch state of one run of the thread (heap allocated). */
typedef struct cw_state {
  cw_dir root, prof;
  cw_batch batch;
  uint64_t last_event, last_try;
  int pending;
} cw_state;

static struct {
  HANDLE thread, stop;
  config_watch_cb cb;
  void *ctx;
  wchar_t root[MAX_PATH], profiles[MAX_PATH];
} g_cw;

static void cw_close(cw_dir *d)
{
  if (d->dir != INVALID_HANDLE_VALUE) {
    if (d->armed)
      CancelIo(d->dir);
    CloseHandle(d->dir);
  }
  if (d->ev)
    CloseHandle(d->ev);
  d->dir = INVALID_HANDLE_VALUE;
  d->ev = NULL;
  d->armed = 0;
}

static int cw_open(cw_dir *d, const wchar_t *path)
{
  d->dir = CreateFileW(path, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
  if (d->dir == INVALID_HANDLE_VALUE)
    return 0;
  d->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (d->ev == NULL) {
    cw_close(d);
    return 0;
  }
  d->armed = 0;
  return 1;
}

static void cw_arm(cw_dir *d)
{
  DWORD got = 0;
  memset(&d->ov, 0, sizeof(d->ov));
  d->ov.hEvent = d->ev;
  ResetEvent(d->ev);
  if (ReadDirectoryChangesW(d->dir, d->buf, sizeof(d->buf), FALSE, CW_FILTER, &got, &d->ov, NULL) ||
      GetLastError() == ERROR_IO_PENDING) {
    d->armed = 1;
  } else {
    d->armed = 0;
    SD_LOGW(CW_LOG, "config watch: ReadDirectoryChangesW failed (%u)", (unsigned)GetLastError());
  }
}

static void batch_add_path(cw_batch *b, const wchar_t *dir, const wchar_t *name, size_t nchars)
{
  size_t i;
  if (b->npaths >= CW_MAX_PATHS || wcslen(dir) + nchars + 2 >= MAX_PATH)
    return;
  wcscpy_s(b->paths[b->npaths], MAX_PATH, dir);
  wcscat_s(b->paths[b->npaths], MAX_PATH, L"\\");
  wcsncat_s(b->paths[b->npaths], MAX_PATH, name, nchars);
  for (i = 0; i < b->npaths; i++)
    if (wcscmp(b->paths[i], b->paths[b->npaths]) == 0)
      return;                       /* the same file twice in one window */
  b->npaths++;
}

/* Parses the FILE_NOTIFY_INFORMATION records of a completed read (bytes 0 = the buffer overflowed). */
static void cw_parse(cw_dir *d, DWORD bytes, const wchar_t *dir, int is_root, cw_batch *b)
{
  DWORD off = 0;
  if (bytes == 0) {
    b->overflow = 1;                /* everything may have changed */
    return;
  }
  for (;;) {
    FILE_NOTIFY_INFORMATION *fi = (FILE_NOTIFY_INFORMATION *)(d->buf + off);
    size_t nc = fi->FileNameLength / sizeof(wchar_t);
    const wchar_t *nm = fi->FileName;
    if (is_root) {
      if (nc == 12 && _wcsnicmp(nm, L"settings.ini", 12) == 0)
        b->settings = 1;
      else if (nc == 8 && _wcsnicmp(nm, L"profiles", 8) == 0)
        b->profiles_dir_added = 1;
    } else if (nc > 4 && _wcsnicmp(nm + nc - 4, L".ini", 4) == 0) {
      b->profiles = 1;
      if (fi->Action != FILE_ACTION_REMOVED && fi->Action != FILE_ACTION_RENAMED_OLD_NAME)
        batch_add_path(b, dir, nm, nc);
    }
    if (fi->NextEntryOffset == 0 || off + fi->NextEntryOffset >= sizeof(d->buf))
      break;
    off += fi->NextEntryOffset;
  }
}

static void batch_flush(cw_batch *b)
{
  if (b->settings || b->overflow) {
    const wchar_t *none[1];
    g_cw.cb(g_cw.ctx, "settings", none, 0);
  }
  if (b->profiles || b->overflow) {
    const wchar_t *ps[CW_MAX_PATHS];
    uint32_t i;
    for (i = 0; i < b->npaths; i++)
      ps[i] = b->paths[i];
    g_cw.cb(g_cw.ctx, "profiles", ps, b->npaths);
  }
  memset(b, 0, sizeof(*b));
}

/* One read completed on `d` (root or profiles): parse it, re-arm, and note when the batch became dirty. */
static void cw_on_read(cw_state *st, cw_dir *d, const wchar_t *dir, int is_root)
{
  DWORD got = 0;
  int ok = GetOverlappedResult(d->dir, &d->ov, &got, FALSE) || GetLastError() == ERROR_MORE_DATA;
  int before = st->batch.profiles_dir_added;
  d->armed = 0;
  if (ok)
    cw_parse(d, got, dir, is_root, &st->batch);
  if (is_root && ok && st->batch.profiles_dir_added != before && !st->prof.armed &&
      cw_open(&st->prof, g_cw.profiles))
    cw_arm(&st->prof);              /* the profiles folder was created: watch it from now on */
  if (ok)
    st->pending = 1;                /* the flush emits only what the window really contained */
  st->last_event = sd_tick_ms();
  cw_arm(d);
}

static DWORD WINAPI cw_thread(void *arg)
{
  cw_state *st;
  SD_UNUSED(arg);
  st = (cw_state *)sd_calloc(1, sizeof(*st));
  if (st == NULL)
    return 0;
  st->root.dir = INVALID_HANDLE_VALUE;
  st->prof.dir = INVALID_HANDLE_VALUE;
  if (!cw_open(&st->root, g_cw.root)) {
    SD_LOGW(CW_LOG, "config watch: the config root cannot be opened; no config.changed events");
    sd_free(st);
    return 0;
  }
  cw_arm(&st->root);
  if (cw_open(&st->prof, g_cw.profiles))
    cw_arm(&st->prof);
  st->last_try = sd_tick_ms();
  for (;;) {
    HANDLE hs[3];
    DWORD n = 0, w;
    DWORD wait = st->pending ? CW_DEBOUNCE_MS : 500;
    hs[n++] = g_cw.stop;
    if (st->root.armed) hs[n++] = st->root.ev;
    if (st->prof.armed) hs[n++] = st->prof.ev;
    w = WaitForMultipleObjects(n, hs, FALSE, wait);
    if (w == WAIT_OBJECT_0 || w == WAIT_FAILED)
      break;
    if (w > WAIT_OBJECT_0 && w < WAIT_OBJECT_0 + n) {
      HANDLE which = hs[w - WAIT_OBJECT_0];
      if (which == st->root.ev)
        cw_on_read(st, &st->root, g_cw.root, 1);
      else if (which == st->prof.ev)
        cw_on_read(st, &st->prof, g_cw.profiles, 0);
    }
    if (st->pending && sd_tick_ms() - st->last_event >= CW_DEBOUNCE_MS) {
      st->pending = 0;
      batch_flush(&st->batch);
    }
    if (!st->prof.armed && sd_tick_ms() - st->last_try >= CW_RETRY_MS) {
      st->last_try = sd_tick_ms();
      if (cw_open(&st->prof, g_cw.profiles))
        cw_arm(&st->prof);
    }
  }
  cw_close(&st->root);
  cw_close(&st->prof);
  sd_free(st);
  return 0;
}

sd_err config_watch_start(config_watch_cb cb, void *ctx)
{
  wchar_t dir[MAX_PATH];
  DWORD attr;
  if (cb == NULL)
    return SD_E_INVALID_PARAM;
  if (g_cw.thread)
    return SD_OK;
  if (sd_config_root(dir, SD_COUNTOF(dir)) != SD_OK)
    return SD_E_NOT_FOUND;
  attr = GetFileAttributesW(dir);
  if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
    return SD_E_NOT_FOUND;
  wcscpy_s(g_cw.root, SD_COUNTOF(g_cw.root), dir);
  if (sd_config_profiles_dir(dir, SD_COUNTOF(dir)) != SD_OK)
    return SD_E_NOT_FOUND;
  wcscpy_s(g_cw.profiles, SD_COUNTOF(g_cw.profiles), dir);
  g_cw.cb = cb;
  g_cw.ctx = ctx;
  g_cw.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (g_cw.stop == NULL)
    return SD_E_NO_MEMORY;
  g_cw.thread = CreateThread(NULL, 0, cw_thread, NULL, 0, NULL);
  if (g_cw.thread == NULL) {
    CloseHandle(g_cw.stop);
    g_cw.stop = NULL;
    return SD_E_NO_MEMORY;
  }
  return SD_OK;
}

void config_watch_stop(void)
{
  if (g_cw.thread == NULL)
    return;
  SetEvent(g_cw.stop);
  if (WaitForSingleObject(g_cw.thread, 5000) == WAIT_OBJECT_0)
    CloseHandle(g_cw.thread);
  else
    SD_LOGW(CW_LOG, "config watch thread did not stop in time");
  g_cw.thread = NULL;
  CloseHandle(g_cw.stop);
  g_cw.stop = NULL;
  g_cw.cb = NULL;
}
