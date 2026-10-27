/* shelldrive-ui: the notification area icon (03 §7.2, §7.7).
 *
 * Shell_NotifyIconW with the XP-compatible NOTIFYICONDATAW V2 layout on every system: NIF_INFO balloons
 * and the legacy callback (the mouse message in lParam) do not need the V3 fields. The icon is identified
 * by uID, not guidItem (7.2). Re-added when Explorer restarts (TaskbarCreated, handled by the main window).
 *
 * TODO (7.7): one balloon per (mount, event type) per 60 s is not enforced yet, and NIIF_USER with a custom
 * balloon icon is not used. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_int.h"

#ifndef NIIF_RESPECT_QUIET_TIME
#define NIIF_RESPECT_QUIET_TIME 0x00000080
#endif

#define UI_TRAY_ID   1u
#define UI_NID_SIZE  (FIELD_OFFSET(NOTIFYICONDATAW, dwInfoFlags) + sizeof(DWORD))

static int g_tray_added;

static void copy_text(wchar_t *dst, size_t cch, const wchar_t *src)
{
  wcsncpy_s(dst, cch, src ? src : L"", _TRUNCATE);
}

static void fill_nid(NOTIFYICONDATAW *nid)
{
  wchar_t *count_text = NULL;
  size_t n = g_app.model.count;

  memset(nid, 0, sizeof(*nid));
  nid->cbSize = UI_NID_SIZE;
  nid->hWnd = g_app.ctrl;
  nid->uID = UI_TRAY_ID;
  nid->uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  nid->uCallbackMessage = UI_WM_TRAY;
  nid->hIcon = ui_icon_get(n > 0 && g_app.agent_up ? UI_ICON_CONNECTED : UI_ICON_IDLE,
                           GetSystemMetrics(SM_CXSMICON));
  if (n == 0) {
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), sd_l10n_get(SD_MSG_UI_TRAY_TIP_NONE));
  } else {
    count_text = ui_format_count(SD_MSG_UI_TRAY_TIP_COUNT, (long long)n);
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), count_text);
    sd_free(count_text);
  }
}

sd_err ui_tray_add(void)
{
  NOTIFYICONDATAW nid;
  if (g_app.ctrl == NULL)
    return SD_E_INVALID_PARAM;
  fill_nid(&nid);
  if (!Shell_NotifyIconW(NIM_ADD, &nid))
    return SD_E_FAILURE;             /* Explorer not ready yet; TaskbarCreated adds it later */
  g_tray_added = 1;
  return SD_OK;
}

void ui_tray_readd(void)
{
  g_tray_added = 0;
  ui_tray_add();
}

void ui_tray_update(void)
{
  NOTIFYICONDATAW nid;
  if (!g_tray_added)
    return;
  fill_nid(&nid);
  Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void ui_tray_remove(void)
{
  NOTIFYICONDATAW nid;
  if (!g_tray_added)
    return;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = UI_NID_SIZE;
  nid.hWnd = g_app.ctrl;
  nid.uID = UI_TRAY_ID;
  Shell_NotifyIconW(NIM_DELETE, &nid);
  g_tray_added = 0;
}

void ui_tray_notify_msg(sd_msg_id msg, const char *name, const wchar_t *arg)
{
  NOTIFYICONDATAW nid;
  wchar_t *text;

  if (!g_tray_added)
    return;
  text = ui_format1(msg, name, arg ? arg : L"");
  if (text == NULL)
    return;
  fill_nid(&nid);
  nid.uFlags |= NIF_INFO;
  copy_text(nid.szInfo, SD_COUNTOF(nid.szInfo), text);
  copy_text(nid.szInfoTitle, SD_COUNTOF(nid.szInfoTitle), sd_l10n_get(SD_MSG_UI_WARN_TITLE));
  nid.dwInfoFlags = (msg == SD_MSG_UI_PROMPT_TIMEOUT ? NIIF_INFO : NIIF_WARNING) | NIIF_RESPECT_QUIET_TIME;
  Shell_NotifyIconW(NIM_MODIFY, &nid);
  sd_free(text);
}

void ui_tray_balloon(const char *code, const wchar_t *drive)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  if (code && strcmp(code, "legacy_algorithms") == 0)
    msg = SD_MSG_UI_WARN_LEGACY;
  else if (code && strcmp(code, "terrapin_exposed") == 0)
    msg = SD_MSG_UI_WARN_TERRAPIN;
  else if (code && strcmp(code, "write_failed") == 0)
    msg = SD_MSG_UI_WARN_WRITE_FAILED;
  ui_tray_notify_msg(msg, "drive", drive);
}

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
  } else if (cmd == UI_CMD_EXIT) {
    ui_app_quit();
  } else if (cmd >= UI_CMD_UNMOUNT_BASE && cmd < UI_CMD_UNMOUNT_BASE + n) {
    /* The drive letter was captured when the menu was built; the list may have changed meanwhile. */
    ui_ipc_unmount(drives[cmd - UI_CMD_UNMOUNT_BASE]);
  }
}

void ui_tray_callback(LPARAM mouse_message)
{
  UINT m = (UINT)mouse_message;
  if (m == WM_LBUTTONUP)
    ui_main_show();
  else if (m == WM_RBUTTONUP || m == WM_CONTEXTMENU)
    show_menu();
}
