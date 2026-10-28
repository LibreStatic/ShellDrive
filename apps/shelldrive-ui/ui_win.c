/* shelldrive-ui: shared helpers and the glue of the secondary windows (03 §3.2, §5, §7.5, §10). See ui_win.h.
 *
 * Fonts follow the message font scaled to the window DPI (7.3), as the main window does. Windows are created
 * on demand and destroyed when closed; the process keeps none of them alive. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_res.h"
#include "ui_update.h"
#include "ui_win.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

HFONT ui_win_font(unsigned dpi)
{
  NONCLIENTMETRICSW ncm;
  LOGFONTW lf;
  unsigned sys = ui_dpi_system();
  long long h;

  memset(&ncm, 0, sizeof(ncm));
  ncm.cbSize = sizeof(ncm);
  if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
    lf = ncm.lfMessageFont;
  } else {
    memset(&lf, 0, sizeof(lf));
    GetObjectW(GetStockObject(DEFAULT_GUI_FONT), sizeof(lf), &lf);
  }
  /* the message font height is in pixels of the system DPI; move it to the window DPI */
  h = lf.lfHeight < 0 ? -(long long)lf.lfHeight : (long long)lf.lfHeight;
  if (h == 0)
    h = 12;
  if (sys == 0)
    sys = UI_DPI_BASE;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  h = (h * (long long)dpi + (long long)sys / 2) / (long long)sys;
  lf.lfHeight = (LONG)-h;
  return CreateFontIndirectW(&lf);
}

int ui_win_text_width(HFONT font, const wchar_t *text)
{
  HDC dc = GetDC(NULL);
  RECT rc;
  HGDIOBJ old = NULL;
  int w = 0;
  if (dc == NULL || text == NULL)
    return 0;
  memset(&rc, 0, sizeof(rc));
  if (font)
    old = SelectObject(dc, font);
  DrawTextW(dc, text, -1, &rc, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
  w = rc.right - rc.left;
  if (old)
    SelectObject(dc, old);
  ReleaseDC(NULL, dc);
  return w;
}

void ui_win_class_name(const wchar_t *suffix, wchar_t out[320])
{
  wcscpy_s(out, 320, g_app.class_ctrl);
  wcscat_s(out, 320, L".");
  wcscat_s(out, 320, suffix);
}

int ui_win_register(HINSTANCE inst, const wchar_t *name, WNDPROC proc)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = proc;
  wc.hInstance = inst;
  wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(UI_IDI_APP));
  wc.hIconSm = wc.hIcon;
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = name;
  if (RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    return 0;
  return 1;
}

void ui_win_message(HWND owner, const wchar_t *text, UINT flags)
{
  MessageBoxW(owner, text, L"ShellDrive", flags | MB_SETFOREGROUND);
}

void ui_win_error(HWND owner, sd_msg_id msg, sd_err err)
{
  wchar_t code[64];
  wchar_t *t;
  ui_text_utf8(sd_err_name(err), code, SD_COUNTOF(code));
  t = ui_format1(msg, "code", code);
  if (t != NULL) {
    ui_win_message(owner, t, MB_OK | MB_ICONERROR);
    sd_free(t);
  }
}

int ui_win_copy_text(HWND owner, const wchar_t *text, size_t len)
{
  HGLOBAL h;
  wchar_t *p;
  int ok = 0;
  if (text == NULL)
    return 0;
  if (!OpenClipboard(owner))
    return 0;
  EmptyClipboard();
  h = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
  if (h != NULL) {
    p = (wchar_t *)GlobalLock(h);
    if (p != NULL) {
      memcpy(p, text, len * sizeof(wchar_t));
      p[len] = L'\0';
      GlobalUnlock(h);
      if (SetClipboardData(CF_UNICODETEXT, h) != NULL)
        ok = 1;
      else
        GlobalFree(h);
    } else {
      GlobalFree(h);
    }
  }
  CloseClipboard();
  return ok;
}

static BOOL CALLBACK set_font_cb(HWND child, LPARAM font)
{
  SendMessageW(child, WM_SETFONT, (WPARAM)font, MAKELPARAM(TRUE, 0));
  return TRUE;
}

void ui_win_apply_font(HWND wnd, HFONT font)
{
  EnumChildWindows(wnd, set_font_cb, (LPARAM)font);
}

/* ---- commands and glue ---- */

void ui_windows_command(UINT cmd)
{
  switch (cmd) {
  case UI_CMD_HOSTKEYS:
    ui_hostkeys_open();
    break;
  case UI_CMD_LOGS:
    ui_logs_open();
    break;
  case UI_CMD_SETTINGS:
    ui_settings_open();
    break;
  case UI_CMD_SERVICE:
    ui_service_open();
    break;
  case UI_CMD_ABOUT:
    ui_about_open();
    break;
  default:
    break;
  }
}

void ui_windows_on_reply(int kind, sd_err err, const sd_json *result)
{
  switch (kind) {
  case UI_IPC_ANNOUNCED:
  case UI_IPC_ACCEPT:
  case UI_IPC_HK_ADD:
    ui_hostkeys_on_reply(kind, err, result);
    break;
  case UI_IPC_LOG:
    ui_logs_on_reply(err, result);
    break;
  case UI_IPC_RELOAD:
    ui_settings_on_reply(kind, err, result);
    break;
  case UI_IPC_UPDATE_CHECK:
  case UI_IPC_UPDATE_APPLY:
    ui_update_on_reply(kind, err, result);
    break;
  default:
    break;
  }
}

void ui_windows_on_event(const char *name, const sd_json *data)
{
  if (name != NULL && strcmp(name, "hostkeys.announced") == 0)
    ui_hostkeys_on_event();
  else if (name != NULL && strncmp(name, "update.", 7) == 0)
    ui_update_on_event(name, data);
}

void ui_windows_on_agent_state(int up)
{
  ui_hostkeys_on_agent_state(up);
  ui_logs_on_agent_state(up);
  ui_update_on_agent_state(up);
}

void ui_windows_close_all(void)
{
  ui_hostkeys_close();
  ui_logs_close();
  ui_settings_close();
  ui_service_close();
  ui_about_close();
}

/* Each window is created hidden, checked and destroyed: no agent is contacted, no timer runs visibly. */
int ui_windows_smoke_test(void)
{
  int ok = 1;
  HWND w;

  w = ui_hostkeys_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  if (w)
    DestroyWindow(w);
  ok = ok && ui_hostkeys_dialogs_smoke();

  w = ui_logs_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  if (w)
    DestroyWindow(w);

  w = ui_settings_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  /* the update group of Settings: channel list, status, Check now, Install update, Release notes */
  ok = ok && ui_settings_update_controls_ok();
  if (w)
    DestroyWindow(w);

  w = ui_service_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  /* no status yet and no administrator: Repair data stays off, Refresh is on */
  ok = ok && ui_service_controls_ok();
  if (w)
    DestroyWindow(w);

  w = ui_about_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  if (w)
    DestroyWindow(w);
  return ok ? 1 : 0;
}
