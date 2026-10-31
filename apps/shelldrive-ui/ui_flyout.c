/* shelldrive-ui: the Windows 11 tray flyout (06 §6.3, D47). See ui_flyout.h.
 *
 * A WS_POPUP | WS_BORDER tool window above the tray icon: a header, the connected-drives line the tray tooltip uses,
 * one check box per profile (checked = mounted; a click mounts or unmounts through the calls of the main window and
 * the tray menu), and the buttons "Open ShellDrive" (accent) and "Settings". It closes when it loses activation or on
 * Escape. The strings are the tray's and the menu's; the colors come from the palette (ui_theme_color).
 *
 * Shell_NotifyIconGetRect (Windows 7) is resolved at run time, so the XP import floor stays empty. */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_platform.h"
#include "ui_dpi.h"
#include "ui_flyout.h"
#include "ui_int.h"
#include "ui_mainview_model.h"
#include "ui_theme.h"
#include "ui_win.h"


/* The layout in 96-DPI units. */
#define FLY_WIDTH       320
#define FLY_PAD         16
#define FLY_TOP         14
#define FLY_HEADER_H    24
#define FLY_SUB_H       18
#define FLY_GAP         10
#define FLY_ROW_H       26
#define FLY_STATUS_H    16
#define FLY_STATUS_INDENT 22          /* the status line sits under the text of the check box */
#define FLY_BUTTON_H    32
#define FLY_BUTTON_GAP  8
#define FLY_BOTTOM      14
#define FLY_SCREEN_GAP  12
#define FLY_MAX_ROWS    12
#define FLY_REOPEN_MS   400           /* a click on the icon that deactivated the flyout must not reopen it */

#define FLY_ID_HEADER   7003
#define FLY_ID_SUB      7004
#define FLY_ID_EMPTY    7005
#define FLY_ID_OPEN     7001
#define FLY_ID_SETTINGS 7002
#define FLY_ID_ROW      7100          /* + row */
#define FLY_ID_STATUS   7200          /* + row */

#define UI_FLYOUT_TRAY_ID 1u          /* the uID of the icon (ui_tray.c UI_TRAY_ID) */

/* NOTIFYICONIDENTIFIER of Windows 7, spelled out for the XP SDK. */
typedef struct fly_nii {
  DWORD cbSize;
  HWND hWnd;
  UINT uID;
  GUID guidItem;
} fly_nii;
typedef HRESULT (WINAPI *fly_pfn_GetRect)(const fly_nii *id, RECT *rect);

typedef struct fly_row {
  HWND check;
  HWND status;
  char profile_id[33];
  wchar_t drive[3];                   /* the drive of the mount, "" when not mounted */
  int mounted;
} fly_row;

typedef struct fly_state {
  HWND hwnd;
  HWND header, sub, empty, open, settings;
  HFONT font, bold;
  unsigned dpi;
  int rows;
  fly_row row[FLY_MAX_ROWS];
} fly_state;

static fly_state g_fl;
static int g_closing;
static DWORD g_closed_tick;
static int g_class_ok;

#define S(v) ui_dpi_scale((v), g_fl.dpi)

int ui_flyout_wanted(void)
{
  const ui_theme *t = ui_theme_current();
  return t != NULL && t->tier == UI_TIER_FLUENT && (t->level == UI_LEVEL_B || t->level == UI_LEVEL_C);
}

/* ---- the rows ---- */

/* The mount of a profile: the first item of the model that came from it (NULL when not mounted). */
static const ui_mount *mount_of(const char *profile_id)
{
  size_t i;
  if (profile_id == NULL || profile_id[0] == 0)
    return NULL;
  for (i = 0; i < g_app.model.count; i++)
    if (strcmp(g_app.model.items[i].profile_id, profile_id) == 0)
      return &g_app.model.items[i];
  return NULL;
}

/* The text of one row: the name, or ui.flyout.row_label ("<name> (<drive>)") with the drive of the mount or the one the profile asks for. */
static void row_text(const sd_profile *p, const ui_mount *m, wchar_t *out, size_t cch)
{
  wchar_t name[160], drive[4];

  ui_text_utf8(p->name, name, SD_COUNTOF(name));
  drive[0] = 0;
  if (m != NULL && m->drive[0] != 0) {
    wcscpy_s(drive, SD_COUNTOF(drive), m->drive);
  } else if (p->target[0] != 0 && p->target[1] == ':' && p->target[2] == 0) {
    drive[0] = (wchar_t)(unsigned char)p->target[0];
    drive[1] = L':';
    drive[2] = 0;
  }
  if (drive[0] != 0) {
    sd_arg a[2];
    a[0].name = "name";
    a[0].type = SD_ARG_STR;
    a[0].v.s = name;
    a[1].name = "drive";
    a[1].type = SD_ARG_STR;
    a[1].v.s = drive;
    (void)sd_l10n_format(out, cch, SD_MSG_UI_FLYOUT_ROW_LABEL, a, 2);
  } else {
    wcsncpy_s(out, cch, name, _TRUNCATE);
  }
}

static void set_text_if_changed(HWND w, const wchar_t *text)
{
  wchar_t cur[300];
  cur[0] = 0;
  GetWindowTextW(w, cur, SD_COUNTOF(cur));
  if (wcscmp(cur, text) != 0)
    SetWindowTextW(w, text);
}

/* The connected-drives line of the tray tooltip. */
static void update_sub(void)
{
  size_t n = ui_model_mounted_count(&g_app.model);
  if (n == 0) {
    set_text_if_changed(g_fl.sub, sd_l10n_get(SD_MSG_UI_TRAY_TIP_NONE));
  } else {
    wchar_t *t = ui_format_count(SD_MSG_UI_TRAY_TIP_COUNT, (long long)n);
    if (t != NULL) {
      set_text_if_changed(g_fl.sub, t);
      sd_free(t);
    }
  }
}

/* Check state, text and status line of the existing rows from the profiles and the model. */
static void update_rows(void)
{
  int i;

  for (i = 0; i < g_fl.rows; i++) {
    const sd_profile *p = ui_profiles_at((size_t)i);
    const ui_mount *m;
    fly_row *r = &g_fl.row[i];
    wchar_t text[300];
    const wchar_t *status = L"";

    if (p == NULL)
      continue;
    m = mount_of(p->id);
    r->mounted = m != NULL && ui_mv_is_mounted(m->state, m->session, m->attempt);
    r->drive[0] = 0;
    if (m != NULL && m->drive[0] != 0)
      wcscpy_s(r->drive, SD_COUNTOF(r->drive), m->drive);
    row_text(p, m, text, SD_COUNTOF(text));
    set_text_if_changed(r->check, text);
    SendMessageW(r->check, BM_SETCHECK, r->mounted ? BST_CHECKED : BST_UNCHECKED, 0);
    if (m != NULL && strcmp(m->state, "mounted") != 0)
      status = ui_model_state_text(m);
    set_text_if_changed(r->status, status);
    ShowWindow(r->status, status[0] != 0 ? SW_SHOWNA : SW_HIDE);
  }
  update_sub();
}

/* ---- layout and creation ---- */

static HWND make_child(const wchar_t *cls, const wchar_t *text, DWORD style, int id, HFONT font)
{
  HWND w = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g_fl.hwnd,
                           (HMENU)(INT_PTR)id, g_app.inst, NULL);
  if (w != NULL) {
    SendMessageW(w, WM_SETFONT, (WPARAM)font, 0);
    ui_theme_apply_control(w);
  }
  return w;
}

/* Positions the children and returns the client height. */
static int layout(void)
{
  int w = S(FLY_WIDTH), pad = S(FLY_PAD), inner = w - 2 * pad, y = S(FLY_TOP), i, bw;

  MoveWindow(g_fl.header, pad, y, inner, S(FLY_HEADER_H), TRUE);
  y += S(FLY_HEADER_H);
  MoveWindow(g_fl.sub, pad, y, inner, S(FLY_SUB_H), TRUE);
  y += S(FLY_SUB_H) + S(FLY_GAP);
  if (g_fl.rows == 0) {
    MoveWindow(g_fl.empty, pad, y, inner, S(FLY_SUB_H), TRUE);
    y += S(FLY_SUB_H);
  }
  for (i = 0; i < g_fl.rows; i++) {
    fly_row *r = &g_fl.row[i];
    int has_status = (GetWindowLongW(r->status, GWL_STYLE) & WS_VISIBLE) != 0;
    MoveWindow(r->check, pad, y, inner, S(FLY_ROW_H), TRUE);
    y += S(FLY_ROW_H);
    if (has_status) {
      MoveWindow(r->status, pad + S(FLY_STATUS_INDENT), y, inner - S(FLY_STATUS_INDENT), S(FLY_STATUS_H), TRUE);
      y += S(FLY_STATUS_H);
    }
  }
  y += S(FLY_GAP);
  bw = (inner - S(FLY_BUTTON_GAP)) / 2;
  MoveWindow(g_fl.open, pad, y, bw, S(FLY_BUTTON_H), TRUE);
  MoveWindow(g_fl.settings, pad + bw + S(FLY_BUTTON_GAP), y, inner - bw - S(FLY_BUTTON_GAP), S(FLY_BUTTON_H), TRUE);
  y += S(FLY_BUTTON_H) + S(FLY_BOTTOM);
  return y;
}

/* Sets the window size for a client of the given height, keeping the bottom edge where it is. */
static void fit_window(int client_h)
{
  RECT rc, wr;
  int w, h;

  rc.left = 0;
  rc.top = 0;
  rc.right = S(FLY_WIDTH);
  rc.bottom = client_h;
  AdjustWindowRectEx(&rc, (DWORD)GetWindowLongW(g_fl.hwnd, GWL_STYLE), FALSE,
                     (DWORD)GetWindowLongW(g_fl.hwnd, GWL_EXSTYLE));
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  GetWindowRect(g_fl.hwnd, &wr);
  SetWindowPos(g_fl.hwnd, NULL, wr.left, wr.bottom - h, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
}

static HFONT make_bold(HFONT base)
{
  LOGFONTW lf;
  if (base == NULL || GetObjectW(base, sizeof(lf), &lf) == 0)
    return NULL;
  lf.lfWeight = FW_BOLD;
  lf.lfHeight = lf.lfHeight - lf.lfHeight / 5;      /* a fifth larger (lfHeight is negative) */
  return CreateFontIndirectW(&lf);
}

static void free_fonts(void)
{
  if (g_fl.font != NULL)
    DeleteObject(g_fl.font);
  if (g_fl.bold != NULL)
    DeleteObject(g_fl.bold);
  g_fl.font = NULL;
  g_fl.bold = NULL;
}

/* Creates the children for the current profiles; the window exists and g_fl.dpi is set. */
static int build_children(void)
{
  size_t n = ui_profiles_count();
  int i;

  g_fl.font = ui_win_font(g_fl.dpi);
  g_fl.bold = make_bold(g_fl.font);
  g_fl.header = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_NOTIFY_TITLE), SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                           FLY_ID_HEADER, g_fl.bold != NULL ? g_fl.bold : g_fl.font);
  g_fl.sub = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, FLY_ID_SUB, g_fl.font);
  g_fl.rows = n > FLY_MAX_ROWS ? FLY_MAX_ROWS : (int)n;
  g_fl.empty = NULL;
  if (g_fl.rows == 0)
    g_fl.empty = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_TRAY_NO_DRIVES), SS_LEFT | SS_NOPREFIX, FLY_ID_EMPTY,
                            g_fl.font);
  for (i = 0; i < g_fl.rows; i++) {
    const sd_profile *p = ui_profiles_at((size_t)i);
    fly_row *r = &g_fl.row[i];
    memset(r, 0, sizeof(*r));
    if (p != NULL)
      strcpy_s(r->profile_id, sizeof(r->profile_id), p->id);
    r->check = make_child(L"BUTTON", L"", WS_TABSTOP | BS_CHECKBOX | BS_LEFT | BS_VCENTER, FLY_ID_ROW + i, g_fl.font);
    r->status = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, FLY_ID_STATUS + i, g_fl.font);
    if (r->check == NULL || r->status == NULL)
      return 0;
  }
  g_fl.open = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_TRAY_OPEN), WS_TABSTOP | BS_OWNERDRAW, FLY_ID_OPEN,
                         g_fl.font);
  g_fl.settings = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_MENU_SETTINGS), WS_TABSTOP | BS_PUSHBUTTON,
                             FLY_ID_SETTINGS, g_fl.font);
  if (g_fl.header == NULL || g_fl.sub == NULL || g_fl.open == NULL || g_fl.settings == NULL ||
      (g_fl.rows == 0 && g_fl.empty == NULL))
    return 0;
  update_rows();
  return 1;
}

/* ---- the window ---- */

static void close_flyout(int by_deactivation)
{
  HWND w = g_fl.hwnd;
  if (w == NULL || g_closing)
    return;
  g_closing = 1;
  if (by_deactivation)
    g_closed_tick = GetTickCount();
  DestroyWindow(w);
  g_closing = 0;
}

void ui_flyout_close(void)
{
  close_flyout(0);
}

static COLORREF blend(COLORREF a, COLORREF b, int pct_b)
{
  return RGB((GetRValue(a) * (100 - pct_b) + GetRValue(b) * pct_b) / 100,
             (GetGValue(a) * (100 - pct_b) + GetGValue(b) * pct_b) / 100,
             (GetBValue(a) * (100 - pct_b) + GetBValue(b) * pct_b) / 100);
}

/* The accent push button "Open ShellDrive": owner drawn, since the theme has no accent button on every tier. */
static void draw_accent_button(const DRAWITEMSTRUCT *di)
{
  COLORREF fill = ui_theme_color(UI_TOK_ACCENT);
  RECT rc = di->rcItem;
  POINT pt;
  HBRUSH br;
  HPEN pen, old_pen;
  HGDIOBJ old_br, old_font;
  wchar_t text[96];
  int r = S(4);

  GetCursorPos(&pt);
  ScreenToClient(di->hwndItem, &pt);
  if (di->itemState & ODS_SELECTED)
    fill = blend(fill, RGB(0, 0, 0), 25);
  else if (PtInRect(&rc, pt))
    fill = blend(fill, RGB(0, 0, 0), 10);

  FillRect(di->hDC, &rc, ui_theme_brush(UI_TOK_LAYER));
  br = CreateSolidBrush(fill);
  pen = CreatePen(PS_SOLID, 1, fill);
  old_br = SelectObject(di->hDC, br);
  old_pen = (HPEN)SelectObject(di->hDC, pen);
  RoundRect(di->hDC, rc.left, rc.top, rc.right, rc.bottom, 2 * r, 2 * r);
  SelectObject(di->hDC, old_pen);
  SelectObject(di->hDC, old_br);
  DeleteObject(pen);
  DeleteObject(br);

  GetWindowTextW(di->hwndItem, text, SD_COUNTOF(text));
  old_font = SelectObject(di->hDC, (HFONT)SendMessageW(di->hwndItem, WM_GETFONT, 0, 0));
  SetBkMode(di->hDC, TRANSPARENT);
  SetTextColor(di->hDC, ui_theme_color(UI_TOK_ACCENT_TEXT));
  DrawTextW(di->hDC, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
  SelectObject(di->hDC, old_font);
  if (di->itemState & ODS_FOCUS) {
    RECT f = di->rcItem;
    InflateRect(&f, -S(3), -S(3));
    SetTextColor(di->hDC, ui_theme_color(UI_TOK_ACCENT_TEXT));
    DrawFocusRect(di->hDC, &f);
  }
}

/* A click on a row: mounts the profile, or unmounts its drive (the calls of the main window and the tray menu). */
static void row_clicked(int i)
{
  fly_row *r;
  sd_err e;

  if (i < 0 || i >= g_fl.rows)
    return;
  r = &g_fl.row[i];
  if (r->mounted && r->drive[0] != 0)
    e = ui_ipc_unmount(r->drive);
  else
    e = ui_ipc_mount(r->profile_id);
  if (e == SD_OK) {
    r->mounted = !r->mounted;
    SendMessageW(r->check, BM_SETCHECK, r->mounted ? BST_CHECKED : BST_UNCHECKED, 0);
  } else if (!r->mounted) {
    close_flyout(0);
    ui_win_message(NULL, sd_l10n_get(SD_MSG_UI_ERROR_MOUNT), MB_OK | MB_ICONERROR);
  }
}

static LRESULT CALLBACK fly_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_ERASEBKGND: {
    RECT rc;
    GetClientRect(hwnd, &rc);
    FillRect((HDC)wp, &rc, ui_theme_brush(UI_TOK_LAYER));
    return 1;
  }
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN: {
    HDC dc = (HDC)wp;
    int id = GetDlgCtrlID((HWND)lp);
    int secondary = id == FLY_ID_SUB || (id >= FLY_ID_STATUS && id < FLY_ID_STATUS + FLY_MAX_ROWS);
    SetTextColor(dc, ui_theme_color(secondary ? UI_TOK_TEXT_SECONDARY : UI_TOK_TEXT));
    SetBkColor(dc, ui_theme_color(UI_TOK_LAYER));
    return (LRESULT)ui_theme_brush(UI_TOK_LAYER);
  }
  case WM_NOTIFY: {
    const NMCUSTOMDRAW *cd = (const NMCUSTOMDRAW *)lp;
    if (cd->hdr.code == NM_CUSTOMDRAW && cd->hdr.idFrom >= FLY_ID_ROW && cd->hdr.idFrom < FLY_ID_ROW + FLY_MAX_ROWS) {
      /* the check box text in the palette's color; the theme draws the glyph */
      if (cd->dwDrawStage == CDDS_PREPAINT)
        SetTextColor(cd->hdc, ui_theme_color(UI_TOK_TEXT));
      return CDRF_DODEFAULT;
    }
    break;
  }
  case WM_DRAWITEM:
    if (wp == FLY_ID_OPEN) {
      draw_accent_button((const DRAWITEMSTRUCT *)lp);
      return TRUE;
    }
    break;
  case WM_COMMAND: {
    int id = LOWORD(wp);
    if (id == IDCANCEL) {
      close_flyout(0);
      return 0;
    }
    if (id == IDOK) {
      /* Enter on the focused row or button acts as a click on it */
      HWND f = GetFocus();
      if (f != NULL && GetParent(f) == hwnd)
        SendMessageW(f, BM_CLICK, 0, 0);
      return 0;
    }
    if (HIWORD(wp) != BN_CLICKED)
      break;
    if (id == FLY_ID_OPEN) {
      close_flyout(0);
      ui_main_show();
      return 0;
    }
    if (id == FLY_ID_SETTINGS) {
      close_flyout(0);
      ui_windows_command(UI_CMD_SETTINGS);
      return 0;
    }
    if (id >= FLY_ID_ROW && id < FLY_ID_ROW + FLY_MAX_ROWS) {
      row_clicked(id - FLY_ID_ROW);
      return 0;
    }
    break;
  }
  case WM_LBUTTONDBLCLK:
    close_flyout(0);
    ui_main_show();
    return 0;
  case WM_ACTIVATE:
    if (LOWORD(wp) == WA_INACTIVE && IsWindowVisible(hwnd))
      close_flyout(1);
    return 0;
  case WM_NCDESTROY:
    free_fonts();
    memset(&g_fl, 0, sizeof(g_fl));
    return DefWindowProcW(hwnd, msg, wp, lp);
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static int register_class(wchar_t name[320])
{
  WNDCLASSEXW wc;

  ui_win_class_name(L"flyout", name);
  if (g_class_ok)
    return 1;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_DBLCLKS;
  wc.lpfnWndProc = fly_proc;
  wc.hInstance = g_app.inst;
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.lpszClassName = name;
  if (RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    return 0;
  g_class_ok = 1;
  return 1;
}

/* Creates the window at (x, y) with the children; not shown. */
static HWND create_flyout(int x, int y)
{
  wchar_t cls[320];
  HWND w;

  if (!register_class(cls))
    return NULL;
  memset(&g_fl, 0, sizeof(g_fl));
  w = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, cls, sd_l10n_get(SD_MSG_UI_NOTIFY_TITLE),
                      WS_POPUP | WS_BORDER | WS_CLIPCHILDREN, x, y, 100, 100, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  g_fl.hwnd = w;
  g_fl.dpi = ui_dpi_window(w);
  if (g_fl.dpi == 0)
    g_fl.dpi = UI_DPI_BASE;
  ui_theme_apply_window(w, UI_THEME_WND_FLYOUT);
  if (!build_children()) {
    DestroyWindow(w);
    return NULL;
  }
  return w;
}

/* Where the icon is: Shell_NotifyIconGetRect when the shell has it, else the cursor. */
static void icon_anchor(POINT *center, int *have_rect)
{
  fly_pfn_GetRect get_rect;
  fly_nii id;
  RECT rc;

  *have_rect = 0;
  GetCursorPos(center);
  get_rect = (fly_pfn_GetRect)sd_platform_resolve_by_name(L"shell32.dll", "Shell_NotifyIconGetRect");
  if (get_rect == NULL || g_app.ctrl == NULL)
    return;
  memset(&id, 0, sizeof(id));
  id.cbSize = sizeof(id);
  id.hWnd = g_app.ctrl;
  id.uID = UI_FLYOUT_TRAY_ID;
  if (SUCCEEDED(get_rect(&id, &rc)) && rc.right > rc.left) {
    center->x = (rc.left + rc.right) / 2;
    center->y = (rc.top + rc.bottom) / 2;
    *have_rect = 1;
  }
}

void ui_flyout_open(void)
{
  POINT cur, anchor;
  MONITORINFO mi;
  HMONITOR mon;
  int have_rect, client_h, x, y, w, gap;
  RECT wr;

  if (g_fl.hwnd != NULL) {
    close_flyout(0);                      /* a second click on the icon closes it */
    return;
  }
  if (g_closed_tick != 0 && GetTickCount() - g_closed_tick < FLY_REOPEN_MS)
    return;                               /* this click is what deactivated and closed it */
  icon_anchor(&anchor, &have_rect);
  GetCursorPos(&cur);
  mon = MonitorFromPoint(cur, MONITOR_DEFAULTTONEAREST);
  memset(&mi, 0, sizeof(mi));
  mi.cbSize = sizeof(mi);
  if (mon == NULL || !GetMonitorInfoW(mon, &mi)) {
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &mi.rcWork, 0);
  }
  if (create_flyout(mi.rcWork.right - 10, mi.rcWork.bottom - 10) == NULL)
    return;
  client_h = layout();
  gap = S(FLY_SCREEN_GAP);
  /* bottom right of the work area; centered on the icon when the shell tells where it is */
  fit_window(client_h);
  GetWindowRect(g_fl.hwnd, &wr);
  w = wr.right - wr.left;
  x = have_rect ? anchor.x - w / 2 : mi.rcWork.right - w - gap;
  if (x + w > mi.rcWork.right - gap)
    x = mi.rcWork.right - w - gap;
  if (x < mi.rcWork.left + gap)
    x = mi.rcWork.left + gap;
  y = mi.rcWork.bottom - (wr.bottom - wr.top) - gap;
  if (y < mi.rcWork.top)
    y = mi.rcWork.top;
  SetWindowPos(g_fl.hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
  ShowWindow(g_fl.hwnd, SW_SHOW);
  SetForegroundWindow(g_fl.hwnd);
  SetFocus(g_fl.rows > 0 ? g_fl.row[0].check : g_fl.open);
}

void ui_flyout_refresh(void)
{
  if (g_fl.hwnd == NULL || g_closing)
    return;
  if (g_fl.rows != (ui_profiles_count() > FLY_MAX_ROWS ? FLY_MAX_ROWS : (int)ui_profiles_count())) {
    close_flyout(0);                      /* the profile list changed: the next open rebuilds the rows */
    return;
  }
  update_rows();
  fit_window(layout());
  InvalidateRect(g_fl.hwnd, NULL, TRUE);
}

int ui_flyout_filter(MSG *msg)
{
  if (g_fl.hwnd == NULL || !IsWindow(g_fl.hwnd))
    return 0;
  return IsDialogMessageW(g_fl.hwnd, msg) ? 1 : 0;
}

/* ---- smoke test (--test-flyout) ---- */

int ui_flyout_smoke_test(void)
{
  HWND w;
  int ok;

  if (g_fl.hwnd != NULL)
    return 0;
  w = create_flyout(0, 0);
  if (w == NULL)
    return 0;
  fit_window(layout());
  ok = IsWindow(w) && !IsWindowVisible(w) && GetDlgItem(w, FLY_ID_HEADER) != NULL &&
       GetDlgItem(w, FLY_ID_SUB) != NULL && GetDlgItem(w, FLY_ID_OPEN) != NULL &&
       GetDlgItem(w, FLY_ID_SETTINGS) != NULL;
  DestroyWindow(w);
  return ok ? 1 : 0;
}
