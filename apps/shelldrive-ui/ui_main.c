/* shelldrive-ui: the main window (03 §7.5, reduced to the mount list for this package).
 *
 * ListView (report view, 5 columns), buttons Mount..., Unmount and Refresh, and a status bar. Mount... is
 * disabled: the mount dialog is the next package (TODO). Closing the window hides it; the tray icon keeps
 * the application running. Sizes are scaled from 96-DPI values with ui_dpi_scale; on WM_DPICHANGED the
 * suggested rectangle is applied, the font is rebuilt and the layout runs again (7.3). */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_int.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#define UI_CLIENT_W  640
#define UI_CLIENT_H  400
#define UI_COLUMNS   5

static const wchar_t k_title[] = L"ShellDrive";

static int dpx(int v)
{
  return ui_dpi_scale(v, g_app.dpi);
}

static HFONT make_font(unsigned dpi)
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
  /* The message font height is in pixels of the system DPI; move it to the window DPI. */
  h = lf.lfHeight < 0 ? -(long long)lf.lfHeight : (long long)lf.lfHeight;
  if (h == 0)
    h = 12;
  if (sys == 0)
    sys = UI_DPI_BASE;
  h = (h * (long long)dpi + (long long)sys / 2) / (long long)sys;
  lf.lfHeight = (LONG)-h;
  return CreateFontIndirectW(&lf);
}

static void set_children_font(void)
{
  HWND kids[5];
  size_t i;
  kids[0] = g_app.btn_mount;
  kids[1] = g_app.btn_unmount;
  kids[2] = g_app.btn_refresh;
  kids[3] = g_app.list;
  kids[4] = g_app.status;
  for (i = 0; i < SD_COUNTOF(kids); i++)
    if (kids[i])
      SendMessageW(kids[i], WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
}

static void set_columns(void)
{
  static const int widths[UI_COLUMNS] = { 180, 70, 150, 90, 150 };
  int i;
  if (!g_app.list)
    return;
  for (i = 0; i < UI_COLUMNS; i++)
    SendMessageW(g_app.list, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(widths[i]));
}

static void layout(HWND hwnd)
{
  RECT rc, sb;
  int m, bh, bw, y, w, h, sbh, lh;

  if (!g_app.list || !g_app.status)
    return;
  m = dpx(8);
  bh = dpx(26);
  bw = dpx(112);
  GetClientRect(hwnd, &rc);
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  SendMessageW(g_app.status, WM_SIZE, 0, 0);   /* the status bar positions itself at the bottom */
  GetWindowRect(g_app.status, &sb);
  sbh = sb.bottom - sb.top;
  MoveWindow(g_app.btn_mount, m, m, bw, bh, TRUE);
  MoveWindow(g_app.btn_unmount, m + bw + m, m, bw, bh, TRUE);
  MoveWindow(g_app.btn_refresh, m + 2 * (bw + m), m, bw, bh, TRUE);
  y = m + bh + m;
  lh = h - y - sbh - m;
  if (lh < 0)
    lh = 0;
  MoveWindow(g_app.list, m, y, w - 2 * m > 0 ? w - 2 * m : 0, lh, TRUE);
}

static int selected_index(void)
{
  if (!g_app.list)
    return -1;
  return (int)SendMessageW(g_app.list, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
}

static void update_buttons(void)
{
  int sel = selected_index();
  if (g_app.btn_unmount)
    EnableWindow(g_app.btn_unmount, g_app.agent_up && sel >= 0 && (size_t)sel < g_app.model.count);
  if (g_app.btn_refresh)
    EnableWindow(g_app.btn_refresh, g_app.agent_up);
  /* TODO (mount dialog package): enable Mount... once the profile picker and prompts exist. */
  if (g_app.btn_mount)
    EnableWindow(g_app.btn_mount, FALSE);
}

static void set_status_text(void)
{
  wchar_t *t;
  const wchar_t *text;
  if (!g_app.status)
    return;
  if (!g_app.agent_up) {
    text = sd_l10n_get(SD_MSG_UI_STATUS_AGENT_DOWN);
    SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)text);
    return;
  }
  t = ui_format_count(SD_MSG_UI_STATUS_COUNT, (long long)g_app.model.count);
  if (t != NULL) {
    SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)t);
    sd_free(t);
  }
}

void ui_main_refresh(void)
{
  size_t i;
  if (!g_app.list)
    return;
  SendMessageW(g_app.list, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_app.list, LVM_DELETEALLITEMS, 0, 0);
  for (i = 0; i < g_app.model.count; i++) {
    const ui_mount *m = &g_app.model.items[i];
    LVITEMW it;
    const wchar_t *cells[UI_COLUMNS];
    int j;

    cells[0] = m->profile;
    cells[1] = m->drive;
    cells[2] = ui_model_state_text(m);
    cells[3] = m->backend;
    cells[4] = m->server;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = (int)i;
    it.pszText = (LPWSTR)cells[0];
    SendMessageW(g_app.list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    for (j = 1; j < UI_COLUMNS; j++) {
      LVITEMW sub;
      memset(&sub, 0, sizeof(sub));
      sub.iItem = (int)i;
      sub.iSubItem = j;
      sub.pszText = (LPWSTR)cells[j];
      SendMessageW(g_app.list, LVM_SETITEMTEXTW, (WPARAM)i, (LPARAM)&sub);
    }
  }
  SendMessageW(g_app.list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_app.list, NULL, TRUE);
  set_status_text();
  update_buttons();
  ui_tray_update();
}

static void on_command(WORD id)
{
  int sel;
  switch (id) {
  case UI_CMD_UNMOUNT:
    sel = selected_index();
    if (sel >= 0 && (size_t)sel < g_app.model.count)
      ui_ipc_unmount(g_app.model.items[sel].drive);
    break;
  case UI_CMD_REFRESH:
    ui_ipc_list();
    break;
  default:
    break;
  }
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_app.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_app.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_app.font = make_font(dpi);
  set_children_font();
  if (old)
    DeleteObject(old);
  set_columns();
  layout(hwnd);
}

static int on_create(HWND hwnd)
{
  LVCOLUMNW col;
  int i;

  g_app.dpi = ui_dpi_window(hwnd);
  g_app.font = make_font(g_app.dpi);

  g_app.btn_mount = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_MAIN_MOUNT),
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                    (HMENU)(UINT_PTR)UI_CMD_MOUNT, g_app.inst, NULL);
  g_app.btn_unmount = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_MAIN_UNMOUNT),
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                      (HMENU)(UINT_PTR)UI_CMD_UNMOUNT, g_app.inst, NULL);
  g_app.btn_refresh = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_MAIN_REFRESH),
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                      (HMENU)(UINT_PTR)UI_CMD_REFRESH, g_app.inst, NULL);
  g_app.list = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                   LVS_SHOWSELALWAYS,
                               0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)UI_CTL_LIST, g_app.inst, NULL);
  g_app.status = CreateWindowExW(0, L"msctls_statusbar32", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                 (HMENU)(UINT_PTR)UI_CTL_STATUS, g_app.inst, NULL);
  if (!g_app.btn_mount || !g_app.btn_unmount || !g_app.btn_refresh || !g_app.list || !g_app.status)
    return -1;

  SendMessageW(g_app.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
  for (i = 0; i < UI_COLUMNS; i++) {
    const wchar_t *text;
    switch (i) {
    case 0: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_NAME); break;
    case 1: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_DRIVE); break;
    case 2: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_STATE); break;
    case 3: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_BACKEND); break;
    default: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SERVER); break;
    }
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
    col.pszText = (LPWSTR)text;
    col.iSubItem = i;
    col.cx = 100;
    SendMessageW(g_app.list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
  set_columns();
  set_children_font();
  layout(hwnd);
  set_status_text();
  update_buttons();
  return 0;
}

static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  if (g_app.wm_taskbar != 0 && msg == g_app.wm_taskbar) {
    ui_tray_readd();
    return 0;
  }
  switch (msg) {
  case WM_CREATE:
    return on_create(hwnd) == 0 ? 0 : -1;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp));
    return 0;
  case WM_NOTIFY:
    if (((const NMHDR *)lp)->idFrom == UI_CTL_LIST && ((const NMHDR *)lp)->code == LVN_ITEMCHANGED)
      update_buttons();
    return 0;
  case WM_CLOSE:
    ShowWindow(hwnd, SW_HIDE);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    if (g_app.font)
      DeleteObject(g_app.font);
    g_app.font = NULL;
    if (g_app.main == hwnd)
      g_app.main = NULL;
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

int ui_main_register_class(HINSTANCE inst, const wchar_t *class_name)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = main_proc;
  wc.hInstance = inst;
  wc.hIcon = ui_icon_get(UI_ICON_IDLE, GetSystemMetrics(SM_CXICON));
  wc.hIconSm = ui_icon_get(UI_ICON_IDLE, GetSystemMetrics(SM_CXSMICON));
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = class_name;
  if (RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    return 0;
  return 1;
}

HWND ui_main_create(HINSTANCE inst, const wchar_t *class_name, int visible)
{
  HWND hwnd;
  g_app.inst = inst;
  hwnd = CreateWindowExW(0, class_name, k_title, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
                         CW_USEDEFAULT, UI_CLIENT_W, UI_CLIENT_H, NULL, NULL, inst, NULL);
  if (hwnd == NULL)
    return NULL;
  g_app.main = hwnd;
  /* The creation size is in pixels of 96 DPI; WM_CREATE has set the window DPI by now. */
  SetWindowPos(hwnd, NULL, 0, 0, dpx(UI_CLIENT_W), dpx(UI_CLIENT_H), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(hwnd, SW_SHOW);
  return hwnd;
}

void ui_main_show(void)
{
  if (!g_app.main)
    return;
  ShowWindow(g_app.main, IsIconic(g_app.main) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(g_app.main);
}

int ui_main_test_controls(void)
{
  return g_app.btn_mount && g_app.btn_unmount && g_app.btn_refresh && g_app.list && g_app.status &&
         IsWindow(g_app.list) && IsWindow(g_app.status);
}
