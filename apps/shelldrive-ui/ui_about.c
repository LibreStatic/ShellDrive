/* shelldrive-ui: the About window (03 §1.4, decision D45 identity strings).
 *
 * Shows the product name, the version (SD_VERSION_STRING, the same text as the version resource), the license
 * and the project address. The project button opens the address in the default browser; the address itself is
 * not translated. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_res.h"
#include "ui_theme.h"
#include "ui_win.h"

#define AB_ID_ICON     4501
#define AB_ID_NAME     4502
#define AB_ID_VERSION  4503
#define AB_ID_LICENSE  4504
#define AB_ID_COPY     4505
#define AB_ID_URL      4506
#define AB_ID_PROJECT  4507
#define AB_ID_CLOSE    4508
#define AB_CLIENT_W    440
#define AB_CLIENT_H    300

#define AB_URL L"https://github.com/LibreStatic/ShellDrive"

static struct {
  HWND wnd, icon, name, version, license, copyright, url, project, close;
  HFONT font, bold;
  unsigned dpi;
} g_ab;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_ab.dpi);
}

static void layout(HWND hwnd)
{
  RECT rc;
  int m, W, H, y, bw1, bw2, lh, iconsz;
  if (!g_ab.close)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(16);
  lh = dpx(22);
  iconsz = dpx(48);
  MoveWindow(g_ab.icon, m, m, iconsz, iconsz, TRUE);
  MoveWindow(g_ab.name, m + iconsz + m, m, W - (m + iconsz + m) - m > 0 ? W - (m + iconsz + m) - m : 0, lh, TRUE);
  MoveWindow(g_ab.version, m + iconsz + m, m + lh, W - (m + iconsz + m) - m > 0 ? W - (m + iconsz + m) - m : 0, lh,
             TRUE);
  y = m + iconsz + m;
  MoveWindow(g_ab.license, m, y, W - 2 * m > 0 ? W - 2 * m : 0, lh, TRUE);
  y += lh + dpx(4);
  MoveWindow(g_ab.copyright, m, y, W - 2 * m > 0 ? W - 2 * m : 0, lh, TRUE);
  y += lh + dpx(4);
  MoveWindow(g_ab.url, m, y, W - 2 * m > 0 ? W - 2 * m : 0, lh, TRUE);
  bw1 = ui_win_text_width(g_ab.font, sd_l10n_get(SD_MSG_UI_ABOUT_BTN_PROJECT)) + dpx(32);
  bw2 = ui_win_text_width(g_ab.font, sd_l10n_get(SD_MSG_UI_ABOUT_BTN_CLOSE)) + dpx(32);
  if (bw1 < dpx(96)) bw1 = dpx(96);
  if (bw2 < dpx(96)) bw2 = dpx(96);
  MoveWindow(g_ab.close, W - m - bw2, H - m - dpx(26), bw2, dpx(26), TRUE);
  MoveWindow(g_ab.project, W - m - bw2 - dpx(8) - bw1, H - m - dpx(26), bw1, dpx(26), TRUE);
}

static void create_children(HWND hwnd)
{
  wchar_t version[64];
  wchar_t *t;
  sd_arg a;
  HINSTANCE inst = g_app.inst;

  g_ab.icon = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_ICON, 0, 0, 10, 10, hwnd,
                              (HMENU)(UINT_PTR)AB_ID_ICON, inst, NULL);
  SendMessageW(g_ab.icon, STM_SETICON, (WPARAM)LoadIconW(inst, MAKEINTRESOURCEW(UI_IDI_APP)), 0);
  g_ab.name = CreateWindowExW(0, L"STATIC", L"ShellDrive", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0,
                              10, 10, hwnd, (HMENU)(UINT_PTR)AB_ID_NAME, inst, NULL);
  ui_text_utf8(SD_VERSION_STRING, version, SD_COUNTOF(version));
  a.name = "version";
  a.type = SD_ARG_STR;
  a.v.s = version;
  t = sd_l10n_format_alloc(SD_MSG_UI_ABOUT_VERSION, &a, 1);
  g_ab.version = CreateWindowExW(0, L"STATIC", t ? t : version, WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0,
                                 0, 10, 10, hwnd, (HMENU)(UINT_PTR)AB_ID_VERSION, inst, NULL);
  sd_free(t);
  g_ab.license = CreateWindowExW(0, L"STATIC", sd_l10n_get(SD_MSG_UI_ABOUT_LICENSE),
                                 WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                                 (HMENU)(UINT_PTR)AB_ID_LICENSE, inst, NULL);
  g_ab.copyright = CreateWindowExW(0, L"STATIC", sd_l10n_get(SD_MSG_UI_ABOUT_COPYRIGHT),
                                   WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                                   (HMENU)(UINT_PTR)AB_ID_COPY, inst, NULL);
  g_ab.url = CreateWindowExW(0, L"STATIC", AB_URL, WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10,
                             hwnd, (HMENU)(UINT_PTR)AB_ID_URL, inst, NULL);
  g_ab.project = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_ABOUT_BTN_PROJECT),
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                 (HMENU)(UINT_PTR)AB_ID_PROJECT, inst, NULL);
  g_ab.close = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_ABOUT_BTN_CLOSE),
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 10, 10, hwnd,
                               (HMENU)(UINT_PTR)AB_ID_CLOSE, inst, NULL);
  ui_win_apply_font(hwnd, g_ab.font);
  SendMessageW(g_ab.name, WM_SETFONT, (WPARAM)g_ab.bold, MAKELPARAM(TRUE, 0));
}

static void on_command(WORD id, WORD code)
{
  if (code != BN_CLICKED)
    return;
  if (id == AB_ID_PROJECT) {
    HINSTANCE r = ShellExecuteW(g_ab.wnd, L"open", AB_URL, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)r <= 32)
      ui_win_message(g_ab.wnd, sd_l10n_get(SD_MSG_UI_ABOUT_OPEN_FAILED), MB_OK | MB_ICONWARNING);
  } else if (id == AB_ID_CLOSE) {
    DestroyWindow(g_ab.wnd);
  }
}

static void make_fonts(unsigned dpi)
{
  g_ab.font = ui_win_font(dpi);
  g_ab.bold = ui_theme_font(UI_FONT_HEADER, dpi);   /* the product name: the header role of the tier */
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_ab.font, oldb = g_ab.bold;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_ab.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_ab.font = NULL;
  g_ab.bold = NULL;
  make_fonts(dpi);
  ui_win_apply_font(hwnd, g_ab.font);
  SendMessageW(g_ab.name, WM_SETFONT, (WPARAM)g_ab.bold, MAKELPARAM(TRUE, 0));
  if (old)
    DeleteObject(old);
  if (oldb)
    DeleteObject(oldb);
  layout(hwnd);
}

static LRESULT CALLBACK ab_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_ab.wnd = hwnd;
    g_ab.dpi = ui_dpi_window(hwnd);
    make_fonts(g_ab.dpi);
    create_children(hwnd);
    ui_theme_apply_dialog(hwnd);
    layout(hwnd);
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp), HIWORD(wp));
    return 0;
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    if (g_ab.font)
      DeleteObject(g_ab.font);
    if (g_ab.bold)
      DeleteObject(g_ab.bold);
    memset(&g_ab, 0, sizeof(g_ab));
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static HWND create_window(int visible)
{
  wchar_t cls[320];
  HWND w;
  ui_win_class_name(L"about", cls);
  if (!ui_win_register(g_app.inst, cls, ab_proc))
    return NULL;
  if (g_ab.wnd != NULL && IsWindow(g_ab.wnd))
    return g_ab.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_ABOUT_TITLE), WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, AB_CLIENT_W, AB_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(AB_CLIENT_W, ui_dpi_window(w)),
               ui_dpi_scale(AB_CLIENT_H, ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(w, SW_SHOW);
  return w;
}

void ui_about_open(void)
{
  if (g_ab.wnd != NULL && IsWindow(g_ab.wnd)) {
    ShowWindow(g_ab.wnd, IsIconic(g_ab.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_ab.wnd);
    return;
  }
  (void)create_window(1);
}

void ui_about_close(void)
{
  if (g_ab.wnd != NULL && IsWindow(g_ab.wnd))
    DestroyWindow(g_ab.wnd);
}

HWND ui_about_create_hidden(void)
{
  return create_window(0);
}
