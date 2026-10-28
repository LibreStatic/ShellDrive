/* shelldrive-ui: the notification area icon (03 §7.2, §7.7).
 *
 * The icon is identified by uID, not guidItem (7.2). On Windows Vista and later the icon uses NOTIFYICON_VERSION_4
 * (NIN_SELECT for a left click, WM_CONTEXTMENU for the menu, NIN_BALLOONUSERCLICK for a balloon click) and the V3
 * structure, so a balloon can carry NIIF_USER with our own icon (hBalloonIcon). XP keeps the version 0 callbacks, the
 * V2 structure and the classic balloon icons. ui_tray_callback reads LOWORD(lParam), which serves both.
 *
 * Balloons (7.7): at most one per (mount, event type) every 60 s (ui_notify_model.c). A balloon that is not allowed yet
 * waits in a small queue; the one-second timer UI_TIMER_NOTIFY (ui_app_on_timer calls ui_tray_flush) shows at most one
 * queued balloon per tick. A queued balloon for the same subject and kind is replaced by the newer text, never doubled.
 *
 * Re-added when Explorer restarts (TaskbarCreated, handled by the main window). */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "ui_int.h"
#include "ui_notify_model.h"
#include "ui_win.h"

#ifndef NIIF_RESPECT_QUIET_TIME
#define NIIF_RESPECT_QUIET_TIME 0x00000080
#endif
#ifndef NIIF_USER
#define NIIF_USER 0x00000004
#endif
#ifndef NIM_SETVERSION
#define NIM_SETVERSION 0x00000004
#endif
#ifndef NOTIFYICON_VERSION_4
#define NOTIFYICON_VERSION_4 4
#endif
#ifndef NIN_SELECT
#define NIN_SELECT (WM_USER + 0)
#endif
#ifndef NIN_KEYSELECT
#define NIN_KEYSELECT (WM_USER + 1)
#endif
#ifndef NIN_BALLOONUSERCLICK
#define NIN_BALLOONUSERCLICK (WM_USER + 5)
#endif

/* The NOTIFYICONDATAW layout of Windows 2000 and later, with the Vista fields (guidItem, hBalloonIcon). The XP SDK
   (7.1A, the v141_xp toolset) does not declare the Vista fields, so the layout is spelled out here. Shell_NotifyIconW
   reads cbSize bytes of it; the offsets are the ones the SDK uses on every flavour. */
typedef struct ui_nid {
  DWORD cbSize;
  HWND hWnd;
  UINT uID;
  UINT uFlags;
  UINT uCallbackMessage;
  HICON hIcon;
  WCHAR szTip[128];
  DWORD dwState;
  DWORD dwStateMask;
  WCHAR szInfo[256];
  union {
    UINT uTimeout;
    UINT uVersion;
  } u;
  WCHAR szInfoTitle[64];
  DWORD dwInfoFlags;
  GUID guidItem;
  HICON hBalloonIcon;
} ui_nid;

#define UI_TRAY_ID          1u
#define UI_NID_SIZE_V2      (FIELD_OFFSET(ui_nid, dwInfoFlags) + sizeof(DWORD))
#define UI_NID_SIZE_V3      (FIELD_OFFSET(ui_nid, hBalloonIcon) + sizeof(HICON))
#define UI_TRAY_QUEUE_MAX   16
#define UI_BALLOON_TEXT_MAX 255           /* szInfo has 256 units with the terminator */

typedef struct tray_pending {
  int used;
  sd_msg_id msg;
  wchar_t subject[UI_NOTIFY_SUBJECT_MAX + 1];
  wchar_t text[UI_BALLOON_TEXT_MAX + 1];
} tray_pending;

static int g_tray_added;
static int g_sizes_known;
static size_t g_nid_size = UI_NID_SIZE_V2;
static int g_nid_v4;                    /* Vista and later: NOTIFYICON_VERSION_4 and V3 balloons */
static int g_timer_on;
static sd_msg_id g_last_balloon = SD_MSG_UI_WARN_GENERIC;
static ui_notify_limiter g_limiter;
static tray_pending g_queue[UI_TRAY_QUEUE_MAX];

static void copy_text(wchar_t *dst, size_t cch, const wchar_t *src)
{
  wcsncpy_s(dst, cch, src ? src : L"", _TRUNCATE);
}

static void ensure_sizes(void)
{
  if (g_sizes_known)
    return;
  g_sizes_known = 1;
  g_nid_v4 = sd_os_at_least(6, 0, 0) ? 1 : 0;
  g_nid_size = g_nid_v4 ? UI_NID_SIZE_V3 : UI_NID_SIZE_V2;
  ui_notify_limiter_init(&g_limiter);
}

static void fill_nid(ui_nid *nid)
{
  wchar_t *count_text = NULL;
  size_t n = g_app.model.count;

  memset(nid, 0, sizeof(*nid));
  nid->cbSize = (DWORD)g_nid_size;
  nid->hWnd = g_app.ctrl;
  nid->uID = UI_TRAY_ID;
  nid->uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  nid->uCallbackMessage = UI_WM_TRAY;
  nid->hIcon = ui_icon_get(n > 0 && g_app.agent_up ? UI_ICON_CONNECTED : UI_ICON_IDLE,
                           GetSystemMetrics(SM_CXSMICON));
  if (g_app.attention > 0) {
    /* a global drive waits for an administrator: the warning icon and its text take precedence (03 §2.6 rule 3) */
    nid->hIcon = ui_icon_get(UI_ICON_WARNING, GetSystemMetrics(SM_CXSMICON));
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), sd_l10n_get(SD_MSG_UI_TRAY_ADMIN_TIP));
  } else if (n == 0) {
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), sd_l10n_get(SD_MSG_UI_TRAY_TIP_NONE));
  } else {
    count_text = ui_format_count(SD_MSG_UI_TRAY_TIP_COUNT, (long long)n);
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), count_text);
    sd_free(count_text);
  }
}

sd_err ui_tray_add(void)
{
  ui_nid nid;
  if (g_app.ctrl == NULL)
    return SD_E_INVALID_PARAM;
  ensure_sizes();
  fill_nid(&nid);
  if (!Shell_NotifyIconW(NIM_ADD, (NOTIFYICONDATAW *)&nid))
    return SD_E_FAILURE;             /* Explorer not ready yet; TaskbarCreated adds it later */
  g_tray_added = 1;
  if (g_nid_v4) {
    nid.u.uVersion = NOTIFYICON_VERSION_4;
    if (!Shell_NotifyIconW(NIM_SETVERSION, (NOTIFYICONDATAW *)&nid))
      SD_LOGW("ui", "the notification area did not accept version 4 callbacks; the legacy ones are used");
  }
  return SD_OK;
}

void ui_tray_readd(void)
{
  g_tray_added = 0;
  ui_tray_add();
}

void ui_tray_update(void)
{
  ui_nid nid;
  if (!g_tray_added)
    return;
  fill_nid(&nid);
  Shell_NotifyIconW(NIM_MODIFY, (NOTIFYICONDATAW *)&nid);
}

void ui_tray_remove(void)
{
  ui_nid nid;
  if (!g_tray_added)
    return;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = (DWORD)g_nid_size;
  nid.hWnd = g_app.ctrl;
  nid.uID = UI_TRAY_ID;
  Shell_NotifyIconW(NIM_DELETE, (NOTIFYICONDATAW *)&nid);
  g_tray_added = 0;
}

/* ---- balloons (7.7) ---- */

static int is_info_balloon(sd_msg_id msg)
{
  return msg == SD_MSG_UI_PROMPT_TIMEOUT || msg == SD_MSG_UI_NOTIFY_HOSTKEYS;
}

/* Shows one balloon now; the limiter has already allowed it. */
static void show_balloon(sd_msg_id msg, const wchar_t *text)
{
  ui_nid nid;
  int info = is_info_balloon(msg);

  if (!g_tray_added)
    return;
  fill_nid(&nid);
  nid.uFlags |= NIF_INFO;
  copy_text(nid.szInfo, SD_COUNTOF(nid.szInfo), text);
  copy_text(nid.szInfoTitle, SD_COUNTOF(nid.szInfoTitle),
            msg == SD_MSG_UI_NOTIFY_HOSTKEYS ? sd_l10n_get(SD_MSG_UI_NOTIFY_TITLE)
                                             : sd_l10n_get(SD_MSG_UI_WARN_TITLE));
  if (g_nid_v4) {
    nid.dwInfoFlags = NIIF_USER | NIIF_RESPECT_QUIET_TIME;
    nid.hBalloonIcon = ui_icon_get(info ? UI_ICON_CONNECTED : UI_ICON_WARNING, GetSystemMetrics(SM_CXICON));
  } else {
    nid.dwInfoFlags = (info ? NIIF_INFO : NIIF_WARNING) | NIIF_RESPECT_QUIET_TIME;
  }
  Shell_NotifyIconW(NIM_MODIFY, (NOTIFYICONDATAW *)&nid);
  g_last_balloon = msg;
}

static void start_timer(void)
{
  if (!g_timer_on && g_app.ctrl != NULL) {
    SetTimer(g_app.ctrl, UI_TIMER_NOTIFY, 1000, NULL);
    g_timer_on = 1;
  }
}

static void stop_timer(void)
{
  if (g_timer_on && g_app.ctrl != NULL)
    KillTimer(g_app.ctrl, UI_TIMER_NOTIFY);
  g_timer_on = 0;
}

/* One balloon: shown when the limiter allows it, otherwise queued. */
static void post_balloon(sd_msg_id msg, const wchar_t *subject, const wchar_t *text)
{
  unsigned long long now = sd_tick_ms(), wait = 0;
  size_t i;

  ensure_sizes();
  if (!g_tray_added)
    return;
  if (ui_notify_limiter_take(&g_limiter, subject, (int)msg, now, &wait)) {
    show_balloon(msg, text);
    return;
  }
  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (p->used && p->msg == msg && wcscmp(p->subject, subject ? subject : L"") == 0) {
      copy_text(p->text, SD_COUNTOF(p->text), text);      /* the newest text replaces the queued one */
      return;
    }
  }
  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (!p->used) {
      p->used = 1;
      p->msg = msg;
      copy_text(p->subject, SD_COUNTOF(p->subject), subject);
      copy_text(p->text, SD_COUNTOF(p->text), text);
      start_timer();
      return;
    }
  }
  SD_LOGW("ui", "balloon queue full: a notification was dropped");
}

/* Called by the timer once a second while balloons wait: shows the first queued balloon that is allowed now. */
void ui_tray_flush(void)
{
  unsigned long long now = sd_tick_ms();
  size_t i;
  int pending = 0, shown = 0;

  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (!p->used)
      continue;
    if (!shown && ui_notify_limiter_take(&g_limiter, p->subject, (int)p->msg, now, NULL)) {
      show_balloon(p->msg, p->text);
      p->used = 0;
      shown = 1;
      continue;
    }
    pending++;
  }
  if (pending == 0)
    stop_timer();
}

void ui_tray_notify_msg(sd_msg_id msg, const char *name, const wchar_t *arg)
{
  wchar_t *text = ui_format1(msg, name, arg ? arg : L"");
  if (text == NULL)
    return;
  post_balloon(msg, arg ? arg : L"", text);
  sd_free(text);
}

void ui_tray_balloon(const char *code, const wchar_t *drive)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  /* write_failed is always shown (03 §7.7); the others follow the notifications setting */
  if (!g_app.notify_on && !(code && strcmp(code, "write_failed") == 0))
    return;
  if (code && strcmp(code, "legacy_algorithms") == 0)
    msg = SD_MSG_UI_WARN_LEGACY;
  else if (code && strcmp(code, "terrapin_exposed") == 0)
    msg = SD_MSG_UI_WARN_TERRAPIN;
  else if (code && strcmp(code, "write_failed") == 0)
    msg = SD_MSG_UI_WARN_WRITE_FAILED;
  ui_tray_notify_msg(msg, "drive", drive);
}

static void notify_hostkeys(const wchar_t *host)
{
  wchar_t *text = ui_format1(SD_MSG_UI_NOTIFY_HOSTKEYS, "host", host);
  if (text == NULL)
    return;
  post_balloon(SD_MSG_UI_NOTIFY_HOSTKEYS, host, text);
  sd_free(text);
}

/* hostkeys.announced (5.6): "example.org offered new host keys. Review", on the notifications switch. The host comes
   from the event; without one, the server of the mount named by mount_id is used. */
void ui_tray_on_hostkeys_announced(const sd_json *data)
{
  const char *host = sd_json_get_str(data, "host");
  const char *mount_id = sd_json_get_str(data, "mount_id");
  wchar_t w[UI_NOTIFY_SUBJECT_MAX + 1];
  ui_mount *m;

  if (!g_app.notify_on)
    return;
  if (host != NULL && host[0] != '\0') {
    ui_text_utf8(host, w, SD_COUNTOF(w));
    notify_hostkeys(w);
    return;
  }
  m = mount_id != NULL ? ui_model_find_id(&g_app.model, mount_id) : NULL;
  if (m != NULL)
    notify_hostkeys(m->server);
}

/* ---- menu and callbacks ---- */

/* Two-argument unmount item text: "Unmount {drive} ({profile})". */
static wchar_t *unmount_item_text(const wchar_t *drive, const wchar_t *profile)
{
  sd_arg a[2];
  a[0].name = "drive";
  a[0].type = SD_ARG_STR;
  a[0].v.s = drive;
  a[1].name = "profile";
  a[1].type = SD_ARG_STR;
  a[1].v.s = profile;
  return sd_l10n_format_alloc(SD_MSG_UI_TRAY_UNMOUNT, a, 2);
}

static void show_menu(void)
{
  HMENU menu;
  POINT pt;
  UINT cmd;
  size_t i, n = g_app.model.count;
  wchar_t drives[UI_MAX_MOUNTS][3];

  menu = CreatePopupMenu();
  if (menu == NULL)
    return;
  if (g_app.attention > 0) {
    wchar_t *t = ui_format_count(SD_MSG_UI_TRAY_ADMIN_PROMPTS, (long long)g_app.attention);
    AppendMenuW(menu, MF_STRING, UI_CMD_ADMIN, t != NULL ? t : sd_l10n_get(SD_MSG_UI_TRAY_ADMIN_TIP));
    sd_free(t);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
  }
  for (i = 0; i < n; i++) {
    wchar_t *t = unmount_item_text(g_app.model.items[i].drive, g_app.model.items[i].profile);
    wcscpy_s(drives[i], SD_COUNTOF(drives[i]), g_app.model.items[i].drive);
    if (t != NULL) {
      AppendMenuW(menu, MF_STRING, UI_CMD_UNMOUNT_BASE + (UINT)i, t);
      sd_free(t);
    }
  }
  if (n == 0)
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, sd_l10n_get(SD_MSG_UI_TRAY_NO_DRIVES));
  else
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
  AppendMenuW(menu, MF_STRING, UI_CMD_OPEN, sd_l10n_get(SD_MSG_UI_TRAY_OPEN));
  AppendMenuW(menu, MF_STRING, UI_CMD_HOSTKEYS, sd_l10n_get(SD_MSG_UI_MENU_HOSTKEYS));
  AppendMenuW(menu, MF_STRING, UI_CMD_LOGS, sd_l10n_get(SD_MSG_UI_MENU_LOGS));
  AppendMenuW(menu, MF_STRING, UI_CMD_SERVICE, sd_l10n_get(SD_MSG_UI_MENU_SERVICE));
  AppendMenuW(menu, MF_STRING, UI_CMD_SETTINGS, sd_l10n_get(SD_MSG_UI_MENU_SETTINGS));
  AppendMenuW(menu, MF_STRING, UI_CMD_ABOUT, sd_l10n_get(SD_MSG_UI_MENU_ABOUT));
  AppendMenuW(menu, MF_STRING, UI_CMD_EXIT, sd_l10n_get(SD_MSG_UI_TRAY_EXIT));
  SetMenuDefaultItem(menu, UI_CMD_OPEN, FALSE);

  GetCursorPos(&pt);
  /* Classic tray menu rules: foreground first, WM_NULL after, so the menu dismisses properly. */
  SetForegroundWindow(g_app.ctrl);
  cmd = (UINT)TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_BOTTOMALIGN, pt.x, pt.y, 0,
                             g_app.ctrl, NULL);
  PostMessageW(g_app.ctrl, WM_NULL, 0, 0);
  DestroyMenu(menu);

  if (cmd == UI_CMD_OPEN) {
    ui_main_show();
  } else if (cmd == UI_CMD_HOSTKEYS || cmd == UI_CMD_LOGS || cmd == UI_CMD_SETTINGS || cmd == UI_CMD_SERVICE ||
             cmd == UI_CMD_ABOUT) {
    ui_windows_command(cmd);
  } else if (cmd == UI_CMD_ADMIN) {
    (void)ui_svc_launch_admin(g_app.main);
  } else if (cmd == UI_CMD_EXIT) {
    ui_app_quit();
  } else if (cmd >= UI_CMD_UNMOUNT_BASE && cmd < UI_CMD_UNMOUNT_BASE + n) {
    /* The drive letter was captured when the menu was built; the list may have changed meanwhile. */
    ui_ipc_unmount(drives[cmd - UI_CMD_UNMOUNT_BASE]);
  }
}

/* A click on a balloon opens the window the balloon is about (7.7). */
static void balloon_clicked(void)
{
  if (g_last_balloon == SD_MSG_UI_NOTIFY_HOSTKEYS)
    ui_windows_command(UI_CMD_HOSTKEYS);
  else
    ui_main_show();
}

void ui_tray_callback(LPARAM mouse_message)
{
  /* NOTIFYICON_VERSION_4 packs the icon id into HIWORD and the mouse message into LOWORD; version 0 sends the message
     itself. Mouse messages are below 0x10000, so LOWORD serves both. */
  UINT m = LOWORD(mouse_message);
  if (m == WM_LBUTTONUP || m == NIN_SELECT || m == NIN_KEYSELECT)
    ui_main_show();
  else if (m == WM_RBUTTONUP || m == WM_CONTEXTMENU)
    show_menu();
  else if (m == NIN_BALLOONUSERCLICK)
    balloon_clicked();
}
