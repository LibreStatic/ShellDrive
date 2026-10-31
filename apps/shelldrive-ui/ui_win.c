/* shelldrive-ui: shared helpers and the glue of the secondary windows (03 §3.2, §5, §7.5, §10). See ui_win.h.
 *
 * Fonts follow the message font scaled to the window DPI (7.3), as the main window does. Windows are created
 * on demand and destroyed when closed; the process keeps none of them alive. */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_res.h"
#include "ui_taskdlg_model.h"
#include "ui_theme.h"
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

/* ---- task dialogs (06 §6.2) ----
   TaskDialogIndirect lives in comctl32 v6 (Vista and later) and is resolved from the already loaded module, never
   imported: the XP import floor stays empty. The struct is a private copy of TASKDIALOGCONFIG with the documented
   layout (packed like commctrl.h), because the XP flavours compile against headers that do not declare it. */
#include <pshpack1.h>
typedef struct sd_task_button {
  int id;
  PCWSTR text;
} sd_task_button;

typedef struct sd_task_config {
  UINT cbSize;
  HWND hwndParent;
  HINSTANCE hInstance;
  DWORD dwFlags;
  DWORD dwCommonButtons;
  PCWSTR pszWindowTitle;
  PCWSTR pszMainIcon;                  /* union with HICON: MAKEINTRESOURCE(-1..-4) here */
  PCWSTR pszMainInstruction;
  PCWSTR pszContent;
  UINT cButtons;
  const sd_task_button *pButtons;
  int nDefaultButton;
  UINT cRadioButtons;
  const sd_task_button *pRadioButtons;
  int nDefaultRadioButton;
  PCWSTR pszVerificationText;
  PCWSTR pszExpandedInformation;
  PCWSTR pszExpandedControlText;
  PCWSTR pszCollapsedControlText;
  PCWSTR pszFooterIcon;                /* union with HICON */
  PCWSTR pszFooter;
  void *pfCallback;
  LONG_PTR lpCallbackData;
  UINT cxWidth;
} sd_task_config;
#include <poppack.h>

#define SD_TDF_ALLOW_DIALOG_CANCELLATION 0x0008u
#define SD_TDF_POSITION_RELATIVE_TO_WINDOW 0x1000u

typedef HRESULT (WINAPI *ui_pfn_TaskDialogIndirect)(const sd_task_config *cfg, int *button, int *radio, BOOL *verify);

static ui_pfn_TaskDialogIndirect task_dialog_fn(void)
{
  static ui_pfn_TaskDialogIndirect fn;
  static int resolved;
  HMODULE cc;
  if (!resolved) {
    resolved = 1;
    cc = GetModuleHandleW(L"comctl32.dll");
    if (cc != NULL)
      fn = (ui_pfn_TaskDialogIndirect)GetProcAddress(cc, "TaskDialogIndirect");
  }
  return fn;
}

int ui_win_task(HWND owner, const wchar_t *main_text, const wchar_t *content, const wchar_t *details,
                UINT mb_flags)
{
  const ui_theme *t = ui_theme_current();
  ui_pfn_TaskDialogIndirect fn;
  ui_task_map map;
  wchar_t plain[2048 + 1536];
  const wchar_t *text;

  if (main_text == NULL)
    main_text = L"";
  if (t != NULL && t->task_dialogs && (fn = task_dialog_fn()) != NULL && main_text[0] != L'\0' &&
      ui_task_map_flags(mb_flags, &map)) {
    sd_task_config cfg;
    int button = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cbSize = sizeof(cfg);
    cfg.hwndParent = owner;
    cfg.dwFlags = SD_TDF_POSITION_RELATIVE_TO_WINDOW | (map.allow_cancel ? SD_TDF_ALLOW_DIALOG_CANCELLATION : 0u);
    cfg.dwCommonButtons = map.buttons;
    cfg.pszWindowTitle = L"ShellDrive";
    cfg.pszMainIcon = map.icon != UI_TASK_ICON_NONE ? MAKEINTRESOURCEW(map.icon) : NULL;
    cfg.pszMainInstruction = main_text;
    cfg.pszContent = (content != NULL && content[0] != L'\0') ? content : NULL;
    if (details != NULL && details[0] != L'\0') {
      /* expandable, collapsed by default; the control texts are the system's own (Windows localizes them) */
      cfg.pszExpandedInformation = details;
    }
    cfg.nDefaultButton = map.default_id;
    if (SUCCEEDED(fn(&cfg, &button, NULL, NULL)) && button != 0)
      return button;
  }
  text = main_text;
  if (ui_task_plain_text(main_text, content, details, plain, SD_COUNTOF(plain)) > 0)
    text = plain;
  return MessageBoxW(owner, text, L"ShellDrive", mb_flags | MB_SETFOREGROUND);
}

void ui_win_message(HWND owner, const wchar_t *text, UINT flags)
{
  (void)ui_win_task(owner, text, NULL, NULL, flags);
}

void ui_win_error(HWND owner, sd_msg_id msg, sd_err err)
{
  wchar_t code[64];
  wchar_t *t, *details;
  ui_text_utf8(sd_err_name(err), code, SD_COUNTOF(code));
  t = ui_format1(msg, "code", code);
  if (t != NULL) {
    /* the code goes in the expandable details, unless the catalog message already names it inline */
    details = wcsstr(t, code) != NULL ? NULL : ui_format1(SD_MSG_UI_WIN_ERROR_DETAILS, "code", code);
    (void)ui_win_task(owner, t, NULL, details, MB_OK | MB_ICONERROR);
    sd_free(details);
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

/* Control ids of the property sheet buttons (comctl32; the SDK headers do not name them). */
#define SHEET_ID_BACK   0x3023
#define SHEET_ID_NEXT   0x3024
#define SHEET_ID_FINISH 0x3025

int CALLBACK ui_win_sheet_callback(HWND sheet, UINT msg, LPARAM lp)
{
  (void)lp;
  if (msg == PSCB_INITIALIZED) {
    /* a missing button (Back and Next on a plain sheet, OK on a wizard) is skipped by SetDlgItemTextW */
    SetDlgItemTextW(sheet, IDOK, sd_l10n_get(SD_MSG_UI_SHEET_OK));
    SetDlgItemTextW(sheet, IDCANCEL, sd_l10n_get(SD_MSG_UI_SHEET_CANCEL));
    SetDlgItemTextW(sheet, SHEET_ID_BACK, sd_l10n_get(SD_MSG_UI_SHEET_BACK));
    SetDlgItemTextW(sheet, SHEET_ID_NEXT, sd_l10n_get(SD_MSG_UI_SHEET_NEXT));
    SetDlgItemTextW(sheet, SHEET_ID_FINISH, sd_l10n_get(SD_MSG_UI_SHEET_FINISH));
  }
  return 0;
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
  case UI_CMD_EVENTS:
    ui_events_open();
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
  case UI_IPC_HK_REJECT:
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
  ui_events_close();
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
  ok = ok && ui_hkissue_smoke();       /* the changed-key dialog for every source of the old key */
  ok = ok && ui_secdlg_smoke();        /* the legacy and Terrapin details dialog */

  w = ui_logs_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  if (w)
    DestroyWindow(w);

  w = ui_events_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  ok = ok && ui_events_controls_ok();
  if (w)
    DestroyWindow(w);

  w = ui_settings_create_hidden();
  ok = ok && w != NULL && IsWindow(w) && !IsWindowVisible(w);
  /* the update group of Settings: channel list, status, Check now, Install update, Release notes */
  ok = ok && ui_settings_update_controls_ok();
  ok = ok && ui_settings_security_smoke();
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
