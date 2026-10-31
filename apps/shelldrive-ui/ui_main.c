/* shelldrive-ui: the main window, the connection manager (03 §7.5).
 *
 * A toolbar with text labels (New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs) above a report ListView with
 * the columns Name, Server, Drive, Backend, Status and Security. Status and Security show an icon and text. The rows
 * are in ListView groups ("My connections", "Provided by your organization", "Global drives"; LVM_ENABLEGROUPVIEW needs
 * comctl32 v6, XP and later; without it the list is flat). Duplicate, Quick mount, Import, Refresh and the security
 * details are in the Connection menu.
 *
 * One row per saved profile (sorted by name inside its group), joined with the agent's mounts by profile id: a profile
 * that is mounted shows its drive and state, one that is not shows "Not mounted". Mounts that match no saved profile
 * (ad-hoc mounts) follow as rows of their own. Enter or double-click mounts a profile, or opens its drive when
 * mounted; the Delete key deletes after confirmation. Closing the window hides it; the tray icon keeps the application
 * running. Sizes are scaled from 96-DPI values with ui_dpi_scale; on WM_DPICHANGED the suggested rectangle is applied,
 * the font and the image list are rebuilt and the layout runs again (7.3). */
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "ui_theme.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_mainview_model.h"
#include "ui_profile_model.h"
#include "ui_win.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif
#ifndef WM_DWMCOMPOSITIONCHANGED
#define WM_DWMCOMPOSITIONCHANGED 0x031E
#endif

/* ListView groups are comctl32 v6 (XP and later). The group structure is spelled out in its XP layout: the Vista
   fields are not needed and the XP SDK of the v141_xp toolset does not declare them. */
#ifndef LVM_INSERTGROUP
#define LVM_INSERTGROUP     (LVM_FIRST + 145)
#endif
#ifndef LVM_REMOVEALLGROUPS
#define LVM_REMOVEALLGROUPS (LVM_FIRST + 160)
#endif
#ifndef LVM_ENABLEGROUPVIEW
#define LVM_ENABLEGROUPVIEW (LVM_FIRST + 157)
#endif
#ifndef LVIF_GROUPID
#define LVIF_GROUPID        0x0100
#endif
#ifndef LVCDI_GROUP
#define LVCDI_GROUP         1
#endif
#ifndef LVM_GETGROUPINFO
#define LVM_GETGROUPINFO    (LVM_FIRST + 149)
#endif
#define UI_LVGF_HEADER      0x00000001u
#define UI_LVGF_GROUPID     0x00000010u
#ifndef LVS_EX_DOUBLEBUFFER
#define LVS_EX_DOUBLEBUFFER 0x00010000
#endif
#ifndef LVS_EX_SUBITEMIMAGES
#define LVS_EX_SUBITEMIMAGES 0x00000002
#endif

typedef struct ui_lvgroup {
  UINT cbSize, mask;
  LPWSTR pszHeader;
  int cchHeader;
  LPWSTR pszFooter;
  int cchFooter;
  int iGroupId;
  UINT stateMask, state, uAlign;
} ui_lvgroup;

#define UI_CLIENT_W  760
#define UI_CLIENT_H  420
#define UI_COLUMNS   6
#define UI_ROWS_MAX  (512 + UI_MAX_MOUNTS)
#define UI_TB_BUTTONS 8

/* Columns: 0 Name, 1 Server, 2 Drive, 3 Backend, 4 Status, 5 Security (7.5). */
#define UI_COL_STATUS   4
#define UI_COL_SECURITY 5

typedef struct ui_row {
  int profile;                  /* index in the profile list, -1 for an ad-hoc mount */
  int mount;                    /* index in the mount model, -1 when not mounted */
  int group;                    /* ui_mv_group */
} ui_row;

static const wchar_t k_title[] = L"ShellDrive";
static ui_row g_rows[UI_ROWS_MAX];
static size_t g_nrows;
static HIMAGELIST g_images;
static int g_groups_on;
static int g_agent_starting;      /* "Start" was clicked and the IPC thread has not answered yet */

static int dpx(int v)
{
  return ui_dpi_scale(v, g_app.dpi);
}

/* ---- Fluent window: command bar, Mica band, card (06 §3.3, §3.5, §6.1) ----
 *
 * Only on the Fluent tier (chosen when the window is created; a tier change between Fluent and the others at
 * run time takes effect at the next start, colors and dark/light follow live). The command bar is owner-drawn
 * push buttons whose ids are the UI_CMD_* ids, so WM_COMMAND is unchanged. On level 'c' the top band is Mica:
 * the frame is extended into the client area by the band height and the buttons are drawn with buffered
 * paint so their alpha is right (GDI writes alpha 0). Every post-XP function is resolved at run time. */

#ifndef ODS_NOFOCUSRECT
#define ODS_NOFOCUSRECT 0x0200
#endif
#define UI_BPBF_TOPDOWNDIB 2
#define UI_BPPF_ERASE      1
#define UI_DTT_TEXTCOLOR   0x00000001u
#define UI_DTT_COMPOSITED  0x00002000u
#define UI_DTT_GLOWSIZE    0x00000800u
#define UI_TMT_TEXTGLOWSIZE 2425
#define UI_AERO_GLOW_DEFAULT 10
#define UI_DWMWA_EXTENDED_FRAME_BOUNDS 9
#define UI_CB_COUNT        (UI_TB_BUTTONS + 1)

typedef struct ui_margins { int left, right, top, bottom; } ui_margins;
typedef struct ui_bp_params { DWORD cbSize, dwFlags; const RECT *exclude; const void *blend; } ui_bp_params;
typedef struct ui_dttopts {
  DWORD dwSize, dwFlags;
  COLORREF crText, crBorder, crShadow;
  int shadow_type;
  POINT shadow_offset;
  int border_size, font_prop, color_prop, state_id;
  BOOL apply_overlay;
  int glow_size;
  void *callback;
  LPARAM lparam;
} ui_dttopts;

typedef HRESULT (WINAPI *ui_pfn_extend)(HWND hwnd, const ui_margins *m);
typedef HRESULT (WINAPI *ui_pfn_getattr)(HWND hwnd, DWORD attr, void *value, DWORD size);
typedef HRESULT (WINAPI *ui_pfn_bpinit)(void);
typedef HANDLE (WINAPI *ui_pfn_bpbegin)(HDC target, const RECT *rc, int format, ui_bp_params *params, HDC *out);
typedef HRESULT (WINAPI *ui_pfn_bpend)(HANDLE buf, BOOL update);
typedef HRESULT (WINAPI *ui_pfn_bpalpha)(HANDLE buf, const RECT *rc, BYTE alpha);
typedef HANDLE (WINAPI *ui_pfn_opentheme)(HWND hwnd, LPCWSTR classes);
typedef HRESULT (WINAPI *ui_pfn_closetheme)(HANDLE theme);
typedef HRESULT (WINAPI *ui_pfn_themetext)(HANDLE theme, HDC dc, int part, int state, LPCWSTR text, int cch,
                                           DWORD flags, LPRECT rc, const ui_dttopts *opts);
typedef HRESULT (WINAPI *ui_pfn_settheme)(HWND hwnd, LPCWSTR subapp, LPCWSTR sublist);
typedef HRESULT (WINAPI *ui_pfn_themebg)(HANDLE theme, HDC dc, int part, int state, const RECT *rc, const RECT *clip);
typedef HRESULT (WINAPI *ui_pfn_themeint)(HANDLE theme, int part, int state, int prop, int *value);

static ui_pfn_extend g_fx_extend;
static ui_pfn_getattr g_fx_getattr;
static ui_pfn_bpinit g_fx_bpinit, g_fx_bpuninit;
static ui_pfn_bpbegin g_fx_bpbegin;
static ui_pfn_bpend g_fx_bpend;
static ui_pfn_bpalpha g_fx_bpalpha;
static ui_pfn_opentheme g_fx_open;
static ui_pfn_closetheme g_fx_close;
static ui_pfn_themetext g_fx_text;
static ui_pfn_settheme g_fx_settheme;
static ui_pfn_themebg g_fx_bg;
static ui_pfn_themeint g_fx_int;
static int g_fx_resolved;
static int g_bp_inited;           /* BufferedPaintInit succeeded on this thread */

static int g_fluent;              /* the window was created with the Fluent controls */
static int g_aero;                /* the window was created on the Aero tier (glass band while composition is on) */
static HWND g_cb[UI_TB_BUTTONS];  /* the command bar buttons, in k_cb order */
static HWND g_overflow;           /* the "..." button */
static HWND g_hot;                /* the command bar button under the mouse */
static WNDPROC g_cb_proc;         /* the original button window procedure (the buttons are subclassed) */
static HMENU g_menu;              /* the menu bar, or on Fluent the overflow popup with the same items */
static int g_band_h;              /* height of the top band (command bar), px */
static int g_frame_cy;            /* the top margin last given to DwmExtendFrameIntoClientArea */
static RECT g_card, g_strip;      /* the layer card around the list and the status strip, client px */

static const struct { int cmd; sd_msg_id text; int gap; } k_cb[UI_TB_BUTTONS] = {
  { UI_CMD_NEW, SD_MSG_UI_MAIN_NEW, 0 },       { UI_CMD_EDIT, SD_MSG_UI_MAIN_EDIT, 0 },
  { UI_CMD_DELETE, SD_MSG_UI_MAIN_DELETE, 0 }, { UI_CMD_MOUNT, SD_MSG_UI_MAIN_MOUNT, 1 },
  { UI_CMD_UNMOUNT, SD_MSG_UI_MAIN_UNMOUNT, 0 }, { UI_CMD_OPEN_DRIVE, SD_MSG_UI_MAIN_OPEN, 0 },
  { UI_CMD_HOSTKEYS, SD_MSG_UI_MENU_HOSTKEYS, 1 }, { UI_CMD_LOGS, SD_MSG_UI_MENU_LOGS, 0 }
};

static void fx_resolve(void)
{
  if (g_fx_resolved)
    return;
  g_fx_resolved = 1;
  g_fx_extend = (ui_pfn_extend)sd_platform_resolve_by_name(L"dwmapi.dll", "DwmExtendFrameIntoClientArea");
  g_fx_getattr = (ui_pfn_getattr)sd_platform_resolve_by_name(L"dwmapi.dll", "DwmGetWindowAttribute");
  g_fx_bpinit = (ui_pfn_bpinit)sd_platform_resolve_by_name(L"uxtheme.dll", "BufferedPaintInit");
  g_fx_bpuninit = (ui_pfn_bpinit)sd_platform_resolve_by_name(L"uxtheme.dll", "BufferedPaintUnInit");
  g_fx_bpbegin = (ui_pfn_bpbegin)sd_platform_resolve_by_name(L"uxtheme.dll", "BeginBufferedPaint");
  g_fx_bpend = (ui_pfn_bpend)sd_platform_resolve_by_name(L"uxtheme.dll", "EndBufferedPaint");
  g_fx_bpalpha = (ui_pfn_bpalpha)sd_platform_resolve_by_name(L"uxtheme.dll", "BufferedPaintSetAlpha");
  g_fx_open = (ui_pfn_opentheme)sd_platform_resolve_by_name(L"uxtheme.dll", "OpenThemeData");
  g_fx_close = (ui_pfn_closetheme)sd_platform_resolve_by_name(L"uxtheme.dll", "CloseThemeData");
  g_fx_text = (ui_pfn_themetext)sd_platform_resolve_by_name(L"uxtheme.dll", "DrawThemeTextEx");
  g_fx_settheme = (ui_pfn_settheme)sd_platform_resolve_by_name(L"uxtheme.dll", "SetWindowTheme");
  g_fx_bg = (ui_pfn_themebg)sd_platform_resolve_by_name(L"uxtheme.dll", "DrawThemeBackground");
  g_fx_int = (ui_pfn_themeint)sd_platform_resolve_by_name(L"uxtheme.dll", "GetThemeInt");
}

/* 1 when the band can be Mica: level 'c' and every function of the extended-frame and buffered-paint path
   resolved (BufferedPaintInit succeeded). Otherwise the band is a plain UI_TOK_SURFACE strip (06 §3.3 S1). */
static int mica_active(void)
{
  const ui_theme *t = ui_theme_current();
  return g_fluent && t != NULL && t->backdrop && g_fx_extend != NULL && g_bp_inited && g_fx_bpbegin != NULL &&
         g_fx_bpend != NULL && g_fx_bpalpha != NULL && g_fx_open != NULL && g_fx_close != NULL && g_fx_text != NULL;
}

/* 1 while the Aero glass band is shown: the window was created on Aero, the theme still reports glass (composition
   on) and every function of the extended-frame and buffered-paint path resolved. Turns 0 when composition is
   switched off (WM_DWMCOMPOSITIONCHANGED), and the toolbar then paints normally. */
static int aero_glass(void)
{
  const ui_theme *t = ui_theme_current();
  return g_aero && !g_fluent && t != NULL && t->tier == UI_TIER_AERO && t->glass && g_app.toolbar != NULL &&
         g_fx_extend != NULL && g_bp_inited && g_fx_bpbegin != NULL && g_fx_bpend != NULL && g_fx_open != NULL &&
         g_fx_close != NULL && g_fx_text != NULL && g_fx_bg != NULL;
}

/* a moved toward b by pct percent, per channel */
static COLORREF blend(COLORREF a, COLORREF b, int pct)
{
  int r = GetRValue(a) + (GetRValue(b) - GetRValue(a)) * pct / 100;
  int g = GetGValue(a) + (GetGValue(b) - GetGValue(a)) * pct / 100;
  int bl = GetBValue(a) + (GetBValue(b) - GetBValue(a)) * pct / 100;
  return RGB(r, g, bl);
}

/* BufferedPaintSetAlpha(buf, NULL, 255) for a button whose rounded corners (clip, NULL when square) stay
   transparent: the rows of the corners are set span by span, the rest in one call. */
static void set_alpha_clipped(HANDLE buf, const RECT *rc, HRGN clip)
{
  RECT r;
  int rad = dpx(4), y, i, x0, x1;
  if (clip == NULL || rad < 1 || rc->bottom - rc->top < 2 * rad) {
    g_fx_bpalpha(buf, rc, 255);
    return;
  }
  r = *rc;
  r.top += rad;
  r.bottom -= rad;
  g_fx_bpalpha(buf, &r, 255);
  for (i = 0; i < rad; i++) {
    for (y = 0; y < 2; y++) {
      int row = y == 0 ? rc->top + i : rc->bottom - 1 - i;
      for (x0 = rc->left; x0 < rc->right && !PtInRegion(clip, x0, row); x0++)
        ;
      for (x1 = rc->right - 1; x1 > x0 && !PtInRegion(clip, x1, row); x1--)
        ;
      if (x0 <= x1) {
        r.left = x0;
        r.right = x1 + 1;
        r.top = row;
        r.bottom = row + 1;
        g_fx_bpalpha(buf, &r, 255);
      }
    }
  }
}

/* The extended frame covers the command bar band on Mica and the toolbar band on Aero glass, nothing otherwise. */
static void update_frame(HWND hwnd)
{
  ui_margins m;
  memset(&m, 0, sizeof(m));
  if (g_fx_extend == NULL)
    return;
  if (mica_active() || aero_glass())
    m.top = g_band_h;
  if (m.top == g_frame_cy)
    return;
  g_frame_cy = m.top;
  g_fx_extend(hwnd, &m);
}

/* One command bar button (WM_DRAWITEM): idle, hover, pressed, disabled, focus; the accent fill for New. */
static void draw_cmd_button(const DRAWITEMSTRUCT *d)
{
  const ui_theme *t = ui_theme_current();
  RECT rc = d->rcItem;
  wchar_t text[96];
  int accent = (int)d->CtlID == UI_CMD_NEW;
  int disabled = (d->itemState & ODS_DISABLED) != 0;
  int pressed = (d->itemState & ODS_SELECTED) != 0 && !disabled;
  int hot = d->hwndItem == g_hot && !disabled;
  int focus = (d->itemState & ODS_FOCUS) != 0 && (d->itemState & ODS_NOFOCUSRECT) == 0;
  int rounded = t != NULL && t->level != UI_LEVEL_A;
  int opaque = accent || hot || pressed || focus;
  int use_bp = mica_active();
  COLORREF fill, fg, surface = ui_theme_color(UI_TOK_SURFACE);
  HANDLE theme = NULL, buf = NULL;
  HDC dc = d->hDC, mdc = NULL, target;
  HFONT old;
  HBRUSH br;
  HRGN clip = NULL;

  /* the overflow button's window text is its accessible name ("More options"); it shows three dots */
  if (d->CtlID == UI_CTL_OVERFLOW)
    wcscpy_s(text, SD_COUNTOF(text), L"\x00B7\x00B7\x00B7");
  else
    GetWindowTextW(d->hwndItem, text, SD_COUNTOF(text));
  if (accent) {
    fg = ui_theme_color(UI_TOK_ACCENT_TEXT);
    fill = ui_theme_color(UI_TOK_ACCENT);
    /* the palette accent as is; hover lightens it a little, pressed darkens it (whichever the text color) */
    if (pressed)
      fill = blend(fill, RGB(0, 0, 0), 14);
    else if (hot)
      fill = blend(fill, RGB(255, 255, 255), 12);
  } else {
    fg = disabled ? blend(ui_theme_color(UI_TOK_TEXT_SECONDARY), surface, 45) : ui_theme_color(UI_TOK_TEXT);
    fill = pressed ? blend(surface, ui_theme_color(UI_TOK_TEXT), 16)
                   : (hot || focus) ? blend(surface, ui_theme_color(UI_TOK_TEXT), 9) : surface;
  }
  if (use_bp && !opaque) {
    theme = g_fx_open(d->hwndItem, L"CompositedWindow::Window");
    if (theme == NULL)
      theme = g_fx_open(d->hwndItem, L"WINDOW");
    if (theme == NULL)
      opaque = 1;                     /* no way to get the text alpha right: draw it as an opaque button */
  }
  if (use_bp) {
    ui_bp_params bpp;
    memset(&bpp, 0, sizeof(bpp));
    bpp.cbSize = sizeof(bpp);
    bpp.dwFlags = UI_BPPF_ERASE;
    buf = g_fx_bpbegin(dc, &rc, UI_BPBF_TOPDOWNDIB, &bpp, &mdc);
  }
  target = buf != NULL ? mdc : dc;
  old = (HFONT)SelectObject(target, g_app.font);
  if (rounded) {                        /* also clip here: the window region alone left square corners painted */
    clip = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, dpx(8), dpx(8));
    SelectClipRgn(target, clip);
  }
  if (opaque || buf == NULL) {
    br = CreateSolidBrush(fill);
    FillRect(target, &rc, br);          /* corners: clip above and the window region of layout_fluent */
    DeleteObject(br);
  }
  if (buf != NULL && !opaque && theme != NULL) {
    ui_dttopts o;
    memset(&o, 0, sizeof(o));
    o.dwSize = sizeof(o);
    o.dwFlags = UI_DTT_COMPOSITED | UI_DTT_TEXTCOLOR;
    o.crText = fg;
    g_fx_text(theme, target, 0, 0, text, -1, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX, &rc, &o);
  } else {
    SetBkMode(target, TRANSPARENT);
    SetTextColor(target, fg);
    DrawTextW(target, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
  }
  if (focus) {
    HPEN pen = CreatePen(PS_INSIDEFRAME, dpx(2) > 1 ? dpx(2) : 2, ui_theme_color(UI_TOK_FOCUS));
    HGDIOBJ op = SelectObject(target, pen);
    HGDIOBJ ob = SelectObject(target, GetStockObject(NULL_BRUSH));
    if (rounded)
      RoundRect(target, rc.left, rc.top, rc.right, rc.bottom, dpx(8), dpx(8));
    else
      Rectangle(target, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(target, ob);
    SelectObject(target, op);
    DeleteObject(pen);
  }
  SelectObject(target, old);
  if (clip != NULL)
    SelectClipRgn(target, NULL);
  if (buf != NULL) {
    if (opaque)
      set_alpha_clipped(buf, &rc, clip);   /* a filled button is opaque inside its corners, an idle one keeps the text alpha only */
    g_fx_bpend(buf, TRUE);
  }
  if (clip != NULL)
    DeleteObject(clip);
  if (theme != NULL)
    g_fx_close(theme);
}

/* NM_CUSTOMDRAW of the toolbar on the glass band (06 §3.2): a transparent toolbar over black (glass) whose buttons
   are painted into a buffered-paint DIB: the hot/pressed background of the toolbar theme and the text through
   DrawThemeTextEx with the composited glow of the Windows 7 caption. GDI text alone would write alpha 0. */
static LRESULT aero_toolbar_draw(NMTBCUSTOMDRAW *cd)
{
  HANDLE buf, bt, ct;
  HDC mdc = NULL;
  RECT rc = cd->nmcd.rc, tr;
  ui_bp_params bpp;
  ui_dttopts o;
  wchar_t text[96];
  int state = cd->nmcd.uItemState, glow = UI_AERO_GLOW_DEFAULT, id = (int)cd->nmcd.dwItemSpec;
  int disabled = (state & CDIS_DISABLED) != 0;
  HFONT old;

  if (cd->nmcd.dwDrawStage == CDDS_PREPAINT)
    return CDRF_NOTIFYITEMDRAW;
  if (cd->nmcd.dwDrawStage != CDDS_ITEMPREPAINT)
    return CDRF_DODEFAULT;
  text[0] = 0;
  if (id != 0)
    SendMessageW(g_app.toolbar, TB_GETBUTTONTEXTW, (WPARAM)id, (LPARAM)text);
  if (text[0] == 0)
    return CDRF_SKIPDEFAULT;            /* separators: the black band shows through */
  ct = g_fx_open(g_app.toolbar, L"CompositedWindow::Window");
  if (ct == NULL)
    return CDRF_DODEFAULT;
  memset(&bpp, 0, sizeof(bpp));
  bpp.cbSize = sizeof(bpp);
  bpp.dwFlags = UI_BPPF_ERASE;
  buf = g_fx_bpbegin(cd->nmcd.hdc, &rc, UI_BPBF_TOPDOWNDIB, &bpp, &mdc);
  if (buf == NULL) {
    g_fx_close(ct);
    return CDRF_DODEFAULT;
  }
  if ((state & (CDIS_HOT | CDIS_SELECTED)) != 0 && !disabled) {
    bt = g_fx_open(g_app.toolbar, L"Toolbar");
    if (bt != NULL) {
      g_fx_bg(bt, mdc, 1 /* TP_BUTTON */, (state & CDIS_SELECTED) != 0 ? 3 /* TS_PRESSED */ : 2 /* TS_HOT */, &rc,
              NULL);
      g_fx_close(bt);
    }
  }
  if (g_fx_int != NULL)
    g_fx_int(ct, 1 /* WP_CAPTION */, 1 /* CS_ACTIVE */, UI_TMT_TEXTGLOWSIZE, &glow);
  if (glow <= 0)
    glow = UI_AERO_GLOW_DEFAULT;
  memset(&o, 0, sizeof(o));
  o.dwSize = sizeof(o);
  o.dwFlags = UI_DTT_COMPOSITED | UI_DTT_GLOWSIZE;
  if (disabled) {
    o.dwFlags |= UI_DTT_TEXTCOLOR;
    o.crText = GetSysColor(COLOR_GRAYTEXT);
  } else {
    o.dwFlags |= UI_DTT_TEXTCOLOR;
    o.crText = RGB(0, 0, 0);
  }
  o.glow_size = glow;
  old = (HFONT)SelectObject(mdc, g_app.font);
  tr = rc;
  g_fx_text(ct, mdc, 1, 1, text, -1, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX, &tr, &o);
  SelectObject(mdc, old);
  g_fx_bpend(buf, TRUE);
  g_fx_close(ct);
  return CDRF_SKIPDEFAULT;
}

/* The glass band: black in the client area (alpha 0 shows the glass). */
static void aero_fill_band(HDC dc, HWND hwnd)
{
  RECT rc;
  GetClientRect(hwnd, &rc);
  if (g_band_h < rc.bottom)
    rc.bottom = g_band_h;
  FillRect(dc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
}

/* Focus order of the command bar: the buttons, the overflow button, then the list. */
static HWND cb_at(int i)
{
  return i < UI_TB_BUTTONS ? g_cb[i] : g_overflow;
}

static void cb_focus_from(int from, int dir, int wrap)
{
  int i = from;
  for (;;) {
    HWND h;
    i += dir;
    if (i < 0 || i >= UI_CB_COUNT) {
      if (!wrap) {
        SetFocus(g_app.list);
        return;
      }
      i = i < 0 ? UI_CB_COUNT - 1 : 0;
    }
    h = cb_at(i);
    if (i == from)
      return;
    if (h != NULL && IsWindowEnabled(h) && IsWindowVisible(h)) {
      SetFocus(h);
      return;
    }
  }
}

/* Tab and Shift+Tab from the list enter the command bar (the main window has no dialog manager). */
static void cb_focus_edge(int last)
{
  cb_focus_from(last ? UI_CB_COUNT : -1, last ? -1 : 1, 0);
}

static void show_overflow(void)
{
  RECT r;
  if (g_menu == NULL || g_overflow == NULL || g_app.main == NULL)
    return;
  GetWindowRect(g_overflow, &r);
  SetForegroundWindow(g_app.main);
  TrackPopupMenu(g_menu, TPM_RIGHTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, r.right, r.bottom, 0, g_app.main, NULL);
  PostMessageW(g_app.main, WM_NULL, 0, 0);
}

static LRESULT CALLBACK cb_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
  TRACKMOUSEEVENT tme;
  int i, at = -1;
  switch (msg) {
  case WM_ERASEBKGND:
    return 1;                           /* WM_DRAWITEM paints the whole button */
  case WM_MOUSEMOVE:
    if (g_hot != h) {
      HWND prev = g_hot;
      g_hot = h;
      memset(&tme, 0, sizeof(tme));
      tme.cbSize = sizeof(tme);
      tme.dwFlags = TME_LEAVE;
      tme.hwndTrack = h;
      TrackMouseEvent(&tme);
      if (prev != NULL)
        InvalidateRect(prev, NULL, FALSE);
      InvalidateRect(h, NULL, FALSE);
    }
    break;
  case WM_MOUSELEAVE:
    if (g_hot == h) {
      g_hot = NULL;
      InvalidateRect(h, NULL, FALSE);
    }
    break;
  case WM_KEYDOWN:
    for (i = 0; i < UI_CB_COUNT; i++)
      if (cb_at(i) == h)
        at = i;
    if (wp == VK_RETURN) {
      SendMessageW(h, BM_CLICK, 0, 0);
      return 0;
    }
    if (wp == VK_ESCAPE) {
      SetFocus(g_app.list);
      return 0;
    }
    if (wp == VK_RIGHT || wp == VK_LEFT) {
      cb_focus_from(at, wp == VK_RIGHT ? 1 : -1, 1);
      return 0;
    }
    if (wp == VK_TAB) {
      cb_focus_from(at, GetKeyState(VK_SHIFT) < 0 ? -1 : 1, 0);
      return 0;
    }
    break;
  case WM_GETDLGCODE:
    return CallWindowProcW(g_cb_proc, h, msg, wp, lp) | DLGC_WANTTAB | DLGC_WANTARROWS;
  default:
    break;
  }
  return CallWindowProcW(g_cb_proc, h, msg, wp, lp);
}

static HWND make_cb_button(HWND parent, const wchar_t *text, int id)
{
  HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 10, 10,
                           parent, (HMENU)(UINT_PTR)id, g_app.inst, NULL);
  WNDPROC old;
  if (b == NULL)
    return NULL;
  old = (WNDPROC)SetWindowLongPtrW(b, GWLP_WNDPROC, (LONG_PTR)cb_proc);
  if (g_cb_proc == NULL)
    g_cb_proc = old;
  return b;
}

static int make_command_bar(HWND parent)
{
  size_t i;
  for (i = 0; i < UI_TB_BUTTONS; i++) {
    g_cb[i] = make_cb_button(parent, sd_l10n_get(k_cb[i].text), k_cb[i].cmd);
    if (g_cb[i] == NULL)
      return 0;
  }
  g_overflow = make_cb_button(parent, sd_l10n_get(SD_MSG_UI_MAIN_MORE_OPTIONS), UI_CTL_OVERFLOW);
  return g_overflow != NULL;
}

/* The list on the card: layer colors for the rows, the DarkMode_ItemsView theme of the helpers on dark (06 §3.5,
   §3.6). The header is dark even without the helpers through fluent_header_draw. */
static void apply_list_theme(void)
{
  const ui_theme *t = ui_theme_current();
  HWND hdr;
  if (!g_fluent || g_app.list == NULL || t == NULL)
    return;
  SendMessageW(g_app.list, LVM_SETBKCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_LAYER));
  SendMessageW(g_app.list, LVM_SETTEXTBKCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_LAYER));
  SendMessageW(g_app.list, LVM_SETTEXTCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_TEXT));
  ui_theme_apply_control(g_app.list);
  hdr = (HWND)SendMessageW(g_app.list, LVM_GETHEADER, 0, 0);
  if (g_fx_settheme != NULL) {
    /* the list keeps DarkMode_Explorer from ui_theme_apply_control (DarkMode_ItemsView drew column lines through
       the empty area). The header is painted by fluent_header_draw, so it takes the classic (empty) theme: any
       themed header continues its column dividers as lines through the list area on Windows 11. */
    if (hdr != NULL)
      g_fx_settheme(hdr, L"", L"");
  }
  InvalidateRect(g_app.list, NULL, TRUE);
  if (hdr != NULL)
    InvalidateRect(hdr, NULL, TRUE);
}

/* NM_CUSTOMDRAW of the list header: layer background, secondary text, a stroke line under the items. */
static LRESULT fluent_header_draw(NMCUSTOMDRAW *cd)
{
  HDITEMW hi;
  wchar_t text[96];
  RECT rc, line;
  HFONT old;
  if (cd->dwDrawStage == CDDS_PREPAINT) {
    FillRect(cd->hdc, &cd->rc, ui_theme_brush(UI_TOK_LAYER));
    return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
  }
  if (cd->dwDrawStage == CDDS_POSTPAINT) {
    /* the filler to the right of the last item is painted by the theme after the items: cover it */
    int n = (int)SendMessageW(cd->hdr.hwndFrom, HDM_GETITEMCOUNT, 0, 0);
    GetClientRect(cd->hdr.hwndFrom, &rc);
    if (n > 0 && SendMessageW(cd->hdr.hwndFrom, HDM_GETITEMRECT, (WPARAM)(n - 1), (LPARAM)&line))
      rc.left = line.right;
    if (rc.left < rc.right) {
      FillRect(cd->hdc, &rc, ui_theme_brush(UI_TOK_LAYER));
      line = rc;
      line.top = line.bottom - 1;
      FillRect(cd->hdc, &line, ui_theme_brush(UI_TOK_STROKE));
    }
    return CDRF_DODEFAULT;
  }
  if (cd->dwDrawStage != CDDS_ITEMPREPAINT)
    return CDRF_DODEFAULT;
  rc = cd->rc;
  text[0] = 0;
  memset(&hi, 0, sizeof(hi));
  hi.mask = HDI_TEXT;
  hi.pszText = text;
  hi.cchTextMax = SD_COUNTOF(text);
  SendMessageW(cd->hdr.hwndFrom, HDM_GETITEMW, (WPARAM)cd->dwItemSpec, (LPARAM)&hi);
  FillRect(cd->hdc, &rc, ui_theme_brush(UI_TOK_LAYER));
  line = rc;
  line.top = line.bottom - 1;
  FillRect(cd->hdc, &line, ui_theme_brush(UI_TOK_STROKE));
  old = (HFONT)SelectObject(cd->hdc, g_app.font);
  SetBkMode(cd->hdc, TRANSPARENT);
  SetTextColor(cd->hdc, ui_theme_color(UI_TOK_TEXT_SECONDARY));
  rc.left += dpx(8);
  rc.right -= dpx(4);
  DrawTextW(cd->hdc, text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
  SelectObject(cd->hdc, old);
  return CDRF_SKIPDEFAULT;
}

/* NM_CUSTOMDRAW of the list on Fluent: the group headers (Vista+) are drawn here in UI_TOK_TEXT with a semibold
   font, because the dark ListView theme leaves them dark blue on the dark layer. Rows keep the default drawing
   (selection and focus stay the control's own). */
static LRESULT fluent_list_draw(NMLVCUSTOMDRAW *cd)
{
  ui_lvgroup grp;
  wchar_t text[128];
  LOGFONTW lf;
  HFONT font, old;
  RECT rc = cd->nmcd.rc, tr;
  SIZE sz;
  int id;

  /* a group header is one CDDS_PREPAINT with dwItemType LVCDI_GROUP (the list itself and the rows have other types) */
  if (cd->nmcd.dwDrawStage != CDDS_PREPAINT || cd->dwItemType != LVCDI_GROUP)
    return CDRF_DODEFAULT;
  id = (int)cd->nmcd.dwItemSpec;
  text[0] = 0;
  memset(&grp, 0, sizeof(grp));
  grp.cbSize = sizeof(grp);
  grp.mask = UI_LVGF_HEADER;
  grp.pszHeader = text;
  grp.cchHeader = SD_COUNTOF(text);
  if (SendMessageW(g_app.list, LVM_GETGROUPINFO, (WPARAM)id, (LPARAM)&grp) < 0 || text[0] == 0)
    return CDRF_DODEFAULT;
  memset(&lf, 0, sizeof(lf));
  GetObjectW(g_app.font, sizeof(lf), &lf);
  lf.lfWeight = FW_SEMIBOLD;
  font = CreateFontIndirectW(&lf);
  old = (HFONT)SelectObject(cd->nmcd.hdc, font != NULL ? font : g_app.font);
  SetBkMode(cd->nmcd.hdc, TRANSPARENT);
  SetTextColor(cd->nmcd.hdc, ui_theme_color(UI_TOK_TEXT));
  tr = rc;
  tr.left += dpx(6);
  DrawTextW(cd->nmcd.hdc, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
  if (GetTextExtentPoint32W(cd->nmcd.hdc, text, (int)wcslen(text), &sz)) {
    RECT line = rc;
    line.left = tr.left + sz.cx + dpx(8);
    line.right -= dpx(4);
    line.top = (rc.top + rc.bottom) / 2;
    line.bottom = line.top + 1;
    if (line.left < line.right)
      FillRect(cd->nmcd.hdc, &line, ui_theme_brush(UI_TOK_STROKE));
  }
  SelectObject(cd->nmcd.hdc, old);
  if (font != NULL)
    DeleteObject(font);
  return CDRF_SKIPDEFAULT;
}

/* The ListView is subclassed to see the custom draw of its header: the control sends the header's WM_NOTIFY to
   itself and does not forward NM_CUSTOMDRAW to its parent. */
static WNDPROC g_list_proc;

static LRESULT CALLBACK list_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
  if (msg == WM_NOTIFY && lp != 0) {
    NMHDR *nm = (NMHDR *)lp;
    if (nm->code == NM_CUSTOMDRAW && nm->hwndFrom == (HWND)SendMessageW(h, LVM_GETHEADER, 0, 0) &&
        ui_theme_brush(UI_TOK_LAYER) != NULL)
      return fluent_header_draw((NMCUSTOMDRAW *)nm);
  }
  return CallWindowProcW(g_list_proc, h, msg, wp, lp);
}

/* Places the command bar, the card with the list and the status strip; sets the Mica frame (06 §6.1). */
static void layout_fluent(HWND hwnd)
{
  RECT rc;
  HDC dc;
  HFONT old;
  TEXTMETRICW tm;
  const ui_theme *t = ui_theme_current();
  int m, w, h, bh, x, y, i, ox, ow, sh, cw;
  int right[UI_TB_BUTTONS];

  m = dpx(8);
  GetClientRect(hwnd, &rc);
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  dc = GetDC(hwnd);
  old = (HFONT)SelectObject(dc, g_app.font);
  GetTextMetricsW(dc, &tm);
  bh = tm.tmHeight + dpx(14);
  if (bh < dpx(32))
    bh = dpx(32);
  g_band_h = bh + dpx(12);
  sh = tm.tmHeight + dpx(14);
  y = dpx(6);
  x = m;
  ow = bh + dpx(8);
  ox = w - m - ow;
  for (i = 0; i < UI_TB_BUTTONS; i++) {
    wchar_t text[96];
    SIZE sz;
    int n = GetWindowTextW(g_cb[i], text, SD_COUNTOF(text));
    sz.cx = 0;
    sz.cy = 0;
    GetTextExtentPoint32W(dc, text, n, &sz);
    cw = (int)sz.cx + dpx(24);
    if (k_cb[i].gap)
      x += dpx(10);
    MoveWindow(g_cb[i], x, y, cw, bh, TRUE);
    if (t != NULL && t->level != UI_LEVEL_A)
      SetWindowRgn(g_cb[i], CreateRoundRectRgn(0, 0, cw + 1, bh + 1, dpx(8), dpx(8)), TRUE);
    x += cw;
    right[i] = x;
    x += dpx(2);
  }
  SelectObject(dc, old);
  ReleaseDC(hwnd, dc);
  MoveWindow(g_overflow, ox, y, ow, bh, TRUE);
  if (t != NULL && t->level != UI_LEVEL_A)
    SetWindowRgn(g_overflow, CreateRoundRectRgn(0, 0, ow + 1, bh + 1, dpx(8), dpx(8)), TRUE);
  for (i = 0; i < UI_TB_BUTTONS; i++)       /* a narrow window hides what does not fit; the overflow menu stays */
    ShowWindow(g_cb[i], right[i] <= ox - dpx(4) ? SW_SHOWNA : SW_HIDE);

  g_card.left = m;
  g_card.top = g_band_h;
  g_card.right = w - m > m ? w - m : m;
  g_card.bottom = h - m - sh - dpx(6);
  if (g_card.bottom < g_card.top + 2)
    g_card.bottom = g_card.top + 2;
  g_strip.left = g_card.left;
  g_strip.right = g_card.right;
  g_strip.top = g_card.bottom + dpx(6);
  g_strip.bottom = g_strip.top + sh;
  MoveWindow(g_app.list, g_card.left + 1, g_card.top + 1, g_card.right - g_card.left - 2,
             g_card.bottom - g_card.top - 2, TRUE);
  MoveWindow(g_app.status, g_strip.left + dpx(10), g_strip.top + 1, g_strip.right - g_strip.left - dpx(20),
             g_strip.bottom - g_strip.top - 2, TRUE);
  update_frame(hwnd);
  RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

/* WM_ERASEBKGND: the band is black on Mica (alpha 0 lets the backdrop show), else the surface color. */
static void fluent_erase(HWND hwnd, HDC dc)
{
  RECT rc, band;
  GetClientRect(hwnd, &rc);
  band = rc;
  band.bottom = g_band_h < rc.bottom ? g_band_h : rc.bottom;
  FillRect(dc, &band, mica_active() ? (HBRUSH)GetStockObject(BLACK_BRUSH) : ui_theme_brush(UI_TOK_SURFACE));
  rc.top = band.bottom;
  FillRect(dc, &rc, ui_theme_brush(UI_TOK_SURFACE));
}

/* WM_PAINT: the card border and the status strip (the list and the status text are child windows). */
static void fluent_paint(HWND hwnd)
{
  PAINTSTRUCT ps;
  HDC dc = BeginPaint(hwnd, &ps);
  FillRect(dc, &g_strip, ui_theme_brush(UI_TOK_LAYER));
  FrameRect(dc, &g_strip, ui_theme_brush(UI_TOK_STROKE));
  FrameRect(dc, &g_card, ui_theme_brush(UI_TOK_STROKE));
  EndPaint(hwnd, &ps);
}

static int CALLBACK face_cb(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
  (void)lf;
  (void)tm;
  (void)type;
  *(int *)lp = 1;
  return 0;
}

/* 1 when "Segoe UI Variable Text" is installed (Windows 11); the body font uses it on Fluent (06 §3.3). */
static int has_variable_face(void)
{
  static int known = -1;
  LOGFONTW lf;
  HDC dc;
  int found = 0;
  if (known >= 0)
    return known;
  memset(&lf, 0, sizeof(lf));
  lf.lfCharSet = DEFAULT_CHARSET;
  wcscpy_s(lf.lfFaceName, SD_COUNTOF(lf.lfFaceName), L"Segoe UI Variable Text");
  dc = GetDC(NULL);
  if (dc != NULL) {
    EnumFontFamiliesExW(dc, &lf, (FONTENUMPROCW)face_cb, (LPARAM)&found, 0);
    ReleaseDC(NULL, dc);
  }
  known = found;
  return known;
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
  if (g_fluent && has_variable_face())
    wcscpy_s(lf.lfFaceName, SD_COUNTOF(lf.lfFaceName), L"Segoe UI Variable Text");
  return CreateFontIndirectW(&lf);
}

static void set_children_font(void)
{
  size_t i;
  if (g_app.toolbar)
    SendMessageW(g_app.toolbar, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  for (i = 0; i < UI_TB_BUTTONS; i++)
    if (g_cb[i])
      SendMessageW(g_cb[i], WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_overflow)
    SendMessageW(g_overflow, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.list)
    SendMessageW(g_app.list, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.status)
    SendMessageW(g_app.status, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
}

static void set_columns(void)
{
  static const int widths[UI_COLUMNS] = { 160, 140, 60, 70, 140, 130 };
  int i;
  if (!g_app.list)
    return;
  for (i = 0; i < UI_COLUMNS; i++)
    SendMessageW(g_app.list, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(widths[i]));
}

/* The small icons of the Status and Security cells: connected, idle, warning (ui_mv_icon order minus none). */
static void build_images(void)
{
  int sz = dpx(16);
  if (g_images) {
    ImageList_Destroy(g_images);
    g_images = NULL;
  }
  g_images = ImageList_Create(sz, sz, ILC_COLOR32, 3, 0);
  if (g_images == NULL)
    return;
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_CONNECTED, sz));
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_IDLE, sz));
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_WARNING, sz));
  if (g_app.list)
    SendMessageW(g_app.list, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)g_images);
}

static int image_of(ui_mv_icon icon)
{
  switch (icon) {
  case UI_MV_ICON_OK:   return 0;
  case UI_MV_ICON_IDLE: return 1;
  case UI_MV_ICON_WARN: return 2;
  default:              return -1;
  }
}

/* The toolbar wraps its buttons when the window is narrow; its height is the bottom of the last button. */
static int toolbar_height(int width)
{
  RECT r;
  int n;
  if (!g_app.toolbar)
    return 0;
  MoveWindow(g_app.toolbar, 0, 0, width, dpx(30), FALSE);
  n = (int)SendMessageW(g_app.toolbar, TB_BUTTONCOUNT, 0, 0);
  if (n <= 0 || !SendMessageW(g_app.toolbar, TB_GETITEMRECT, (WPARAM)(n - 1), (LPARAM)&r))
    return dpx(30);
  return r.bottom + dpx(2);
}

static void layout(HWND hwnd)
{
  RECT rc, sb;
  int m, w, h, sbh, lh, y, th;
  if (g_fluent && g_app.list && g_app.status && g_overflow) {
    layout_fluent(hwnd);
    return;
  }
  if (!g_app.list || !g_app.status || !g_app.toolbar)
    return;
  m = dpx(8);
  GetClientRect(hwnd, &rc);
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  SendMessageW(g_app.status, WM_SIZE, 0, 0);   /* the status bar positions itself at the bottom */
  GetWindowRect(g_app.status, &sb);
  sbh = sb.bottom - sb.top;
  th = toolbar_height(w - 2 * m > 0 ? w - 2 * m : 0);
  MoveWindow(g_app.toolbar, m, m / 2, w - 2 * m > 0 ? w - 2 * m : 0, th, TRUE);
  y = m / 2 + th + m / 2;
  g_band_h = g_aero ? y : 0;               /* the toolbar band: glass on Aero (06 §3.2) */
  update_frame(hwnd);
  lh = h - y - sbh - m;
  if (lh < 0)
    lh = 0;
  MoveWindow(g_app.list, m, y, w - 2 * m > 0 ? w - 2 * m : 0, lh, TRUE);
}

/* ---- rows ---- */

/* Rows of a group follow each other; the profile list is sorted by name already, so the order inside a group is too. */
static void build_rows(void)
{
  size_t i, j;
  int g;
  ui_row all[UI_ROWS_MAX];
  size_t n = 0;

  for (i = 0; i < ui_profiles_count() && n < UI_ROWS_MAX; i++) {
    const sd_profile *p = ui_profiles_at(i);
    ui_row *r = &all[n++];
    r->profile = (int)i;
    r->mount = -1;
    r->group = (int)ui_mv_group_of_scope(p->scope);
    for (j = 0; j < g_app.model.count; j++) {
      if (p->id[0] && strcmp(g_app.model.items[j].profile_id, p->id) == 0) {
        r->mount = (int)j;
        if (g_app.model.items[j].scope >= 0)       /* the agent knows the scope of a mount it runs (round 17) */
          r->group = (int)ui_mv_group_of_scope(g_app.model.items[j].scope);
        break;
      }
    }
  }
  for (j = 0; j < g_app.model.count && n < UI_ROWS_MAX; j++) {
    const ui_mount *m = &g_app.model.items[j];
    if (m->profile_id[0] && ui_profiles_find_id(m->profile_id) != NULL)
      continue;
    all[n].profile = -1;
    all[n].mount = (int)j;
    /* a mount without a profile in the user's store: an ad-hoc mount, or a drive of the organization or all users, whose
       profile this list does not read; the scope comes from the agent */
    all[n].group = (int)ui_mv_group_of_scope(m->scope);
    n++;
  }
  g_nrows = 0;
  for (g = 0; g < (int)UI_MV_GROUPS; g++)
    for (i = 0; i < n; i++)
      if (all[i].group == g)
        g_rows[g_nrows++] = all[i];
}

static const ui_row *selected_row(void)
{
  int sel;
  if (!g_app.list)
    return NULL;
  sel = (int)SendMessageW(g_app.list, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
  if (sel < 0 || (size_t)sel >= g_nrows)
    return NULL;
  return &g_rows[sel];
}

const sd_profile *ui_main_selected_profile(void)
{
  const ui_row *r = selected_row();
  return r && r->profile >= 0 ? ui_profiles_at((size_t)r->profile) : NULL;
}

ui_mount *ui_main_selected_mount(void)
{
  const ui_row *r = selected_row();
  return r && r->mount >= 0 ? &g_app.model.items[r->mount] : NULL;
}

/* "host" or "host:port" (the SSH default port is left out). */
static void profile_server(const sd_profile *p, wchar_t *out, size_t cch)
{
  wchar_t host[256];
  ui_text_utf8(p->host, host, SD_COUNTOF(host));
  wcsncpy_s(out, cch, host, _TRUNCATE);
  if (p->port != 22 && p->port != 0) {
    wchar_t num[12];
    size_t len = wcslen(out);
    wsprintfW(num, L":%u", (unsigned)p->port);
    if (len + wcslen(num) + 1 <= cch)
      wcscat_s(out, cch, num);
  }
}

/* The text of the Status cell: "Reconnecting (3)" while the connection retries, otherwise the state. */
static void status_text(const ui_mount *m, wchar_t *out, size_t cch)
{
  if (m == NULL) {
    wcsncpy_s(out, cch, sd_l10n_get(SD_MSG_UI_MAIN_NOT_MOUNTED), _TRUNCATE);
    return;
  }
  if (ui_mv_status_of(m->state, m->session, m->attempt) == UI_MV_ST_RECONNECTING) {
    sd_arg a[1];
    wchar_t *t;
    a[0].name = "attempt";
    a[0].type = SD_ARG_INT;
    a[0].v.i = (long long)m->attempt;
    t = sd_l10n_format_alloc(SD_MSG_UI_MAIN_STATUS_RECONNECTING, a, 1);
    if (t != NULL) {
      wcsncpy_s(out, cch, t, _TRUNCATE);
      sd_free(t);
      return;
    }
  }
  wcsncpy_s(out, cch, ui_model_state_text(m), _TRUNCATE);
}

/* The text of the Security cell (7.5, 7.6). */
static const wchar_t *security_text(unsigned sec)
{
  if ((sec & UI_MV_SEC_LEGACY) && (sec & UI_MV_SEC_TERRAPIN))
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_BOTH);
  if (sec & UI_MV_SEC_TERRAPIN)
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_TERRAPIN);
  if (sec & UI_MV_SEC_LEGACY)
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_LEGACY);
  return L"";
}

static void enable_tb(int id, int on)
{
  size_t i;
  if (g_app.toolbar)
    SendMessageW(g_app.toolbar, TB_ENABLEBUTTON, (WPARAM)id, MAKELPARAM(on ? TRUE : FALSE, 0));
  for (i = 0; i < UI_TB_BUTTONS; i++)
    if (g_cb[i] != NULL && (int)GetDlgCtrlID(g_cb[i]) == id && IsWindowEnabled(g_cb[i]) != (on ? TRUE : FALSE))
      EnableWindow(g_cb[i], on ? TRUE : FALSE);
}

static void enable_menu(UINT id, int on)
{
  if (g_menu)
    EnableMenuItem(g_menu, id, MF_BYCOMMAND | (on ? MF_ENABLED : MF_GRAYED));
}

static void update_buttons(void)
{
  const ui_row *r = selected_row();
  int mounted = r != NULL && r->mount >= 0;
  int has_profile = r != NULL && r->profile >= 0;
  int secure = mounted && g_app.model.items[r->mount].sec != 0;
  /* a machine template is read-only: no Edit, Duplicate or Delete (Mount stays) */
  const sd_profile *cur = has_profile ? ui_profiles_at((size_t)r->profile) : NULL;
  int editable = cur != NULL && !ui_mv_scope_read_only(cur->scope);

  enable_tb(UI_CMD_NEW, TRUE);
  enable_tb(UI_CMD_EDIT, editable);
  enable_tb(UI_CMD_DELETE, editable);
  enable_tb(UI_CMD_MOUNT, has_profile && !mounted && g_app.agent_up);
  enable_tb(UI_CMD_UNMOUNT, mounted && g_app.agent_up);
  enable_tb(UI_CMD_OPEN_DRIVE, mounted);
  enable_tb(UI_CMD_HOSTKEYS, TRUE);
  enable_tb(UI_CMD_LOGS, TRUE);
  enable_menu(UI_CMD_DUPLICATE, editable);
  enable_menu(UI_CMD_QUICK_MOUNT, TRUE);
  enable_menu(UI_CMD_IMPORT, TRUE);
  enable_menu(UI_CMD_REFRESH, g_app.agent_up);
  enable_menu(UI_CMD_SECURITY, secure);
}

/* The status bar (Classic, Aero) or the STATIC strip of the Fluent window shows the text. */
static void put_status(const wchar_t *text)
{
  if (g_fluent)
    SetWindowTextW(g_app.status, text);
  else
    SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)text);
}

static void set_status_text(void)
{
  wchar_t *t;
  const wchar_t *text;
  if (!g_app.status)
    return;
  if (g_app.agent_up)
    g_agent_starting = 0;
  if (!g_app.agent_up) {
    /* "ShellDrive is not running. Click here to start it." while a click starts it: "Starting ShellDrive..." */
    text = sd_l10n_get(g_agent_starting ? SD_MSG_UI_STATUS_AGENT_STARTING : SD_MSG_UI_STATUS_AGENT_DOWN);
    put_status(text);
    return;
  }
  /* The status bar counts the drives that are mounted (reconnecting included), like the tray (03 §7.2). */
  t = ui_format_count(SD_MSG_UI_STATUS_COUNT, (long long)ui_model_mounted_count(&g_app.model));
  if (t != NULL) {
    put_status(t);
    sd_free(t);
  }
}

/* One group header for each group that has rows. Without group view support the list stays flat. */
static void insert_groups(void)
{
  static const sd_msg_id titles[UI_MV_GROUPS] = { SD_MSG_UI_MAIN_GROUP_MINE, SD_MSG_UI_MAIN_GROUP_ORG,
                                                  SD_MSG_UI_MAIN_GROUP_GLOBAL };
  int used[UI_MV_GROUPS] = { 0, 0, 0 };
  size_t i;
  int g;
  for (i = 0; i < g_nrows; i++)
    used[g_rows[i].group] = 1;
  SendMessageW(g_app.list, LVM_REMOVEALLGROUPS, 0, 0);
  for (g = 0; g < (int)UI_MV_GROUPS; g++) {
    ui_lvgroup grp;
    if (!used[g])
      continue;
    memset(&grp, 0, sizeof(grp));
    grp.cbSize = sizeof(grp);
    grp.mask = UI_LVGF_HEADER | UI_LVGF_GROUPID;
    grp.pszHeader = (LPWSTR)sd_l10n_get(titles[g]);
    grp.cchHeader = (int)wcslen(grp.pszHeader);
    grp.iGroupId = g;
    SendMessageW(g_app.list, LVM_INSERTGROUP, (WPARAM)-1, (LPARAM)&grp);
  }
}

/* One list row: the cells, its group and the icons of the Status and Security cells (-1: none). */
static void insert_row(int index, const wchar_t *const cells[UI_COLUMNS], int group, int status_image, int sec_image)
{
  LVITEMW it;
  int j;
  memset(&it, 0, sizeof(it));
  it.mask = LVIF_TEXT | (g_groups_on ? LVIF_GROUPID : 0);
  it.iItem = index;
  it.pszText = (LPWSTR)cells[0];
  it.iGroupId = group;
  SendMessageW(g_app.list, LVM_INSERTITEMW, 0, (LPARAM)&it);
  for (j = 1; j < UI_COLUMNS; j++) {
    LVITEMW sub;
    memset(&sub, 0, sizeof(sub));
    sub.mask = LVIF_TEXT;
    sub.iItem = index;
    sub.iSubItem = j;
    sub.pszText = (LPWSTR)cells[j];
    if (j == UI_COL_STATUS && status_image >= 0) {
      sub.iImage = status_image;
      sub.mask |= LVIF_IMAGE;
    } else if (j == UI_COL_SECURITY && sec_image >= 0) {
      sub.iImage = sec_image;
      sub.mask |= LVIF_IMAGE;
    }
    SendMessageW(g_app.list, LVM_SETITEMW, 0, (LPARAM)&sub);
  }
}

void ui_main_refresh(void)
{
  size_t i;
  if (!g_app.list)
    return;
  build_rows();
  SendMessageW(g_app.list, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_app.list, LVM_DELETEALLITEMS, 0, 0);
  if (g_groups_on)
    insert_groups();
  for (i = 0; i < g_nrows; i++) {
    const ui_row *row = &g_rows[i];
    const ui_mount *m = row->mount >= 0 ? &g_app.model.items[row->mount] : NULL;
    const sd_profile *p = row->profile >= 0 ? ui_profiles_at((size_t)row->profile) : NULL;
    wchar_t name[160], server[300], status[96];
    const wchar_t *cells[UI_COLUMNS];

    if (p) {
      ui_text_utf8(p->name, name, SD_COUNTOF(name));
      profile_server(p, server, SD_COUNTOF(server));
    } else if (m) {
      wcsncpy_s(name, SD_COUNTOF(name), m->profile, _TRUNCATE);
      wcsncpy_s(server, SD_COUNTOF(server), m->server, _TRUNCATE);
    } else {
      name[0] = 0;
      server[0] = 0;
    }
    status_text(m, status, SD_COUNTOF(status));
    cells[0] = name;
    cells[1] = server;
    cells[2] = m ? m->drive : L"";
    cells[3] = m ? m->backend : L"";
    cells[UI_COL_STATUS] = status;
    cells[UI_COL_SECURITY] = m ? security_text(m->sec) : L"";
    insert_row((int)i, cells, row->group,
               m ? image_of(ui_mv_status_icon(ui_mv_status_of(m->state, m->session, m->attempt))) : -1,
               m ? image_of(ui_mv_sec_icon(m->sec)) : -1);
  }
  SendMessageW(g_app.list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_app.list, NULL, TRUE);
  set_status_text();
  update_buttons();
  ui_tray_update();
}

void ui_main_reload_profiles(void)
{
  sd_err e = ui_profiles_load();
  if (e != SD_OK)
    SD_LOGW("ui", "the profile list could not be read (%s)", sd_err_name(e));
  ui_main_refresh();
}

/* ---- actions ---- */

static void message(sd_msg_id id, UINT flags)
{
  (void)ui_win_task(g_app.main, sd_l10n_get(id), NULL, NULL, flags);
}

/* Saves a profile (sd_profile_save), then has the agent read the store again (03 §2.4). */
static int save_profile(sd_profile *p)
{
  sd_err e = sd_profile_save(p);
  if (e != SD_OK) {
    message(SD_MSG_UI_ERROR_SAVE, MB_OK | MB_ICONERROR);
    return 0;
  }
  ui_main_reload_profiles();
  ui_ipc_config_reload();
  return 1;
}

static void select_profile_id(const char *id)
{
  size_t i;
  for (i = 0; i < g_nrows; i++) {
    const sd_profile *p = g_rows[i].profile >= 0 ? ui_profiles_at((size_t)g_rows[i].profile) : NULL;
    if (p && strcmp(p->id, id) == 0) {
      ListView_SetItemState(g_app.list, (int)i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      ListView_EnsureVisible(g_app.list, (int)i, FALSE);
      break;
    }
  }
}

static void do_new(void)
{
  sd_profile p;
  sd_profile_defaults(&p);
  if (!ui_editor_run(g_app.main, UI_EDIT_NEW, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

static void do_edit(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  sd_profile p;
  if (cur == NULL || ui_mv_scope_read_only(cur->scope))
    return;
  p = *cur;
  if (!ui_editor_run(g_app.main, UI_EDIT_EDIT, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

/* A copy opens in the editor as a new profile, so its name can be changed before it is saved. */
static void do_duplicate(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  sd_profile p;
  if (cur == NULL || ui_mv_scope_read_only(cur->scope))
    return;
  p = *cur;
  p.id[0] = 0;
  if (strlen(p.name) + 4 < sizeof(p.name))
    strcat_s(p.name, sizeof(p.name), " (2)");
  if (!ui_editor_run(g_app.main, UI_EDIT_NEW, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

static void do_delete(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  wchar_t name[160];
  char id[33];
  sd_err e;
  if (cur == NULL || ui_mv_scope_read_only(cur->scope))
    return;
  strcpy_s(id, sizeof(id), cur->id);
  ui_text_utf8(cur->name, name, SD_COUNTOF(name));
  if (!ui_confirm(g_app.main, SD_MSG_UI_DELETE_TITLE, SD_MSG_UI_DELETE_TEXT, name, SD_MSG_UI_DELETE_YES,
                  SD_MSG_UI_DELETE_NO, 0))
    return;
  e = sd_profile_delete(id);
  if (e != SD_OK) {
    message(SD_MSG_UI_ERROR_DELETE, MB_OK | MB_ICONERROR);
    return;
  }
  ui_main_reload_profiles();
  ui_ipc_config_reload();
}

static void do_mount_selected(void)
{
  const sd_profile *p = ui_main_selected_profile();
  if (p && ui_ipc_mount(p->id) != SD_OK)
    message(SD_MSG_UI_ERROR_MOUNT, MB_OK | MB_ICONERROR);
}

/* The ad-hoc mount dialog: the connection goes to the agent as an "adhoc" object (03 §2.4). */
static void do_quick_mount(void)
{
  sd_profile p;
  char target[16], params[2048];
  const char *backend = "auto";
  sd_err e;
  sd_profile_defaults(&p);
  if (!ui_editor_run(g_app.main, UI_EDIT_ADHOC, &p))
    return;
  if (ui_pform_get(&p, UI_PF_TARGET, target, sizeof(target)) != SD_OK)
    strcpy_s(target, sizeof(target), "auto");
  if (p.backend == SD_PROFILE_BACKEND_DOKANY)
    backend = "dokany";
  else if (p.backend == SD_PROFILE_BACKEND_WEBDAV)
    backend = "webdav";
  e = ui_mount_params_json(&p, 1, target, p.read_only, backend, params, sizeof(params));
  if (e != SD_OK || ui_ipc_mount_params(params) != SD_OK)
    message(SD_MSG_UI_ERROR_MOUNT, MB_OK | MB_ICONERROR);
}

static void do_unmount_selected(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m && m->drive[0])
    ui_ipc_unmount(m->drive);
}

/* Shows a drive in Explorer (the "explore" verb of ShellExecuteW, 03 §8.1). */
void ui_open_drive(const wchar_t *drive)
{
  wchar_t root[4];
  if (drive == NULL || drive[0] == 0 || drive[1] != L':')
    return;
  root[0] = drive[0];
  root[1] = L':';
  root[2] = L'\\';
  root[3] = 0;
  ShellExecuteW(g_app.main, L"explore", root, NULL, NULL, SW_SHOWNORMAL);
}

static void do_open_selected(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m)
    ui_open_drive(m->drive);
}

/* Enter or double-click: open the drive of a mounted profile, mount a profile that is not mounted. */
static void activate_selected(void)
{
  const ui_row *r = selected_row();
  if (r == NULL)
    return;
  if (r->mount >= 0)
    do_open_selected();
  else
    do_mount_selected();
}

static void do_security_details(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m && m->sec != 0)
    ui_secdlg_open(g_app.main, m->drive);
}

static void on_command(WORD id)
{
  switch (id) {
  case UI_CMD_NEW:         do_new(); break;
  case UI_CMD_EDIT:        do_edit(); break;
  case UI_CMD_DUPLICATE:   do_duplicate(); break;
  case UI_CMD_DELETE:      do_delete(); break;
  case UI_CMD_QUICK_MOUNT: do_quick_mount(); break;
  case UI_CMD_IMPORT:      ui_import_run(g_app.main); break;
  case UI_CMD_MOUNT:       do_mount_selected(); break;
  case UI_CMD_UNMOUNT:     do_unmount_selected(); break;
  case UI_CMD_OPEN_DRIVE:  do_open_selected(); break;
  case UI_CMD_REFRESH:     ui_ipc_list(); break;
  case UI_CMD_SECURITY:    do_security_details(); break;
  case UI_CTL_OVERFLOW:    show_overflow(); break;
  case UI_CMD_HOSTKEYS:
  case UI_CMD_LOGS:
  case UI_CMD_SETTINGS:
  case UI_CMD_SERVICE:
  case UI_CMD_EVENTS:
  case UI_CMD_ABOUT:
    ui_windows_command(id);
    break;
  default:
    break;
  }
}

static void rebuild_font(void)
{
  HFONT old = g_app.font;
  g_app.font = make_font(g_app.dpi);
  set_children_font();
  if (old)
    DeleteObject(old);
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_app.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  rebuild_font();
  build_images();
  set_columns();
  layout(hwnd);
}

/* The system theme, the colors, the accent, DWM composition or the dark setting changed (06 §4): the theme has been
   re-selected by ui_theme_refresh. A change of tier between Fluent and the others takes effect at the next start
   (the controls of the window are chosen at creation); the palette, dark/light and the Mica band follow live. */
static void on_theme_changed(HWND hwnd)
{
  ui_theme_refresh();
  if (g_aero) {
    /* composition on or off: the glass band follows live (margins 0 and normal toolbar painting without it) */
    update_frame(hwnd);
    layout(hwnd);
    RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
    return;
  }
  if (!g_fluent)
    return;
  ui_theme_apply_window(hwnd, UI_THEME_WND_MAIN);
  apply_list_theme();
  rebuild_font();
  layout(hwnd);
  RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
}

/* The menu bar (popup == 0) or, on Fluent, a popup menu with the same three submenus for the "..." button. */
static HMENU build_menu(int popup)
{
  HMENU bar = popup ? CreatePopupMenu() : CreateMenu();
  HMENU conn = CreatePopupMenu();
  HMENU tools = CreatePopupMenu();
  HMENU help = CreatePopupMenu();
  if (bar == NULL || conn == NULL || tools == NULL || help == NULL) {
    if (bar) DestroyMenu(bar);
    if (conn) DestroyMenu(conn);
    if (tools) DestroyMenu(tools);
    if (help) DestroyMenu(help);
    return NULL;
  }
  AppendMenuW(conn, MF_STRING, UI_CMD_DUPLICATE, sd_l10n_get(SD_MSG_UI_MAIN_DUPLICATE));
  AppendMenuW(conn, MF_STRING, UI_CMD_QUICK_MOUNT, sd_l10n_get(SD_MSG_UI_MAIN_QUICK_MOUNT));
  AppendMenuW(conn, MF_STRING, UI_CMD_IMPORT, sd_l10n_get(SD_MSG_UI_MAIN_IMPORT));
  AppendMenuW(conn, MF_SEPARATOR, 0, NULL);
  AppendMenuW(conn, MF_STRING, UI_CMD_SECURITY, sd_l10n_get(SD_MSG_UI_MENU_SECURITY));
  AppendMenuW(conn, MF_SEPARATOR, 0, NULL);
  AppendMenuW(conn, MF_STRING, UI_CMD_REFRESH, sd_l10n_get(SD_MSG_UI_MAIN_REFRESH));
  AppendMenuW(tools, MF_STRING, UI_CMD_HOSTKEYS, sd_l10n_get(SD_MSG_UI_MENU_HOSTKEYS));
  AppendMenuW(tools, MF_STRING, UI_CMD_LOGS, sd_l10n_get(SD_MSG_UI_MENU_LOGS));
  AppendMenuW(tools, MF_STRING, UI_CMD_EVENTS, sd_l10n_get(SD_MSG_UI_MENU_EVENTS));
  AppendMenuW(tools, MF_STRING, UI_CMD_SERVICE, sd_l10n_get(SD_MSG_UI_MENU_SERVICE));
  AppendMenuW(tools, MF_SEPARATOR, 0, NULL);
  AppendMenuW(tools, MF_STRING, UI_CMD_SETTINGS, sd_l10n_get(SD_MSG_UI_MENU_SETTINGS));
  AppendMenuW(help, MF_STRING, UI_CMD_ABOUT, sd_l10n_get(SD_MSG_UI_MENU_ABOUT));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)conn, sd_l10n_get(SD_MSG_UI_MENU_CONNECTION));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)tools, sd_l10n_get(SD_MSG_UI_MENU_TOOLS));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, sd_l10n_get(SD_MSG_UI_MENU_HELP));
  return bar;
}

/* The toolbar of 7.5: text buttons, no icons. Separators group the connection, the drive and the tools. */
static HWND make_toolbar(HWND parent)
{
  static const struct { int cmd; sd_msg_id text; } k_buttons[] = {
    { UI_CMD_NEW, SD_MSG_UI_MAIN_NEW },       { UI_CMD_EDIT, SD_MSG_UI_MAIN_EDIT },
    { UI_CMD_DELETE, SD_MSG_UI_MAIN_DELETE }, { 0, 0 },
    { UI_CMD_MOUNT, SD_MSG_UI_MAIN_MOUNT },   { UI_CMD_UNMOUNT, SD_MSG_UI_MAIN_UNMOUNT },
    { UI_CMD_OPEN_DRIVE, SD_MSG_UI_MAIN_OPEN }, { 0, 0 },
    { UI_CMD_HOSTKEYS, SD_MSG_UI_MENU_HOSTKEYS }, { UI_CMD_LOGS, SD_MSG_UI_MENU_LOGS }
  };
  HWND tb;
  TBBUTTON b[SD_COUNTOF(k_buttons)];
  size_t i;

  tb = CreateWindowExW(0, TOOLBARCLASSNAMEW, L"",
                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBSTYLE_FLAT | TBSTYLE_LIST | TBSTYLE_WRAPABLE | (g_aero ? TBSTYLE_TRANSPARENT : 0) |
                           CCS_NODIVIDER | CCS_NOPARENTALIGN | CCS_NORESIZE,
                       0, 0, 10, 10, parent, (HMENU)(UINT_PTR)UI_CTL_TOOLBAR, g_app.inst, NULL);
  if (tb == NULL)
    return NULL;
  SendMessageW(tb, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
  memset(b, 0, sizeof(b));
  for (i = 0; i < SD_COUNTOF(k_buttons); i++) {
    if (k_buttons[i].cmd == 0) {
      b[i].fsStyle = BTNS_SEP;
      continue;
    }
    b[i].iBitmap = I_IMAGENONE;
    b[i].idCommand = k_buttons[i].cmd;
    b[i].fsState = TBSTATE_ENABLED;
    b[i].fsStyle = BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT;
    b[i].iString = (INT_PTR)sd_l10n_get(k_buttons[i].text);
  }
  SendMessageW(tb, TB_ADDBUTTONSW, (WPARAM)SD_COUNTOF(k_buttons), (LPARAM)b);
  return tb;
}

static int on_create(HWND hwnd)
{
  LVCOLUMNW col;
  int i;

  const ui_theme *theme = ui_theme_current();

  /* Fluent: command bar, layer card and status strip instead of the menu bar, toolbar and status bar (06 §6.1) */
  g_fluent = theme != NULL && theme->tier == UI_TIER_FLUENT;
  g_aero = theme != NULL && theme->tier == UI_TIER_AERO;
  if (g_fluent || g_aero) {
    fx_resolve();
    if (!g_bp_inited && g_fx_bpinit != NULL && g_fx_bpinit() >= 0)
      g_bp_inited = 1;
  }
  g_app.dpi = ui_dpi_window(hwnd);
  g_app.font = make_font(g_app.dpi);
  g_menu = build_menu(g_fluent);
  if (!g_fluent)
    SetMenu(hwnd, g_menu);

  if (g_fluent) {
    if (!make_command_bar(hwnd))
      return -1;
    g_app.toolbar = NULL;
  } else {
    g_app.toolbar = make_toolbar(hwnd);
  }
  g_app.list = CreateWindowExW(g_fluent ? 0 : WS_EX_CLIENTEDGE, L"SysListView32", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                   LVS_SHOWSELALWAYS,
                               0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)UI_CTL_LIST, g_app.inst, NULL);
  if (g_fluent)
    g_app.status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_LEFT | SS_CENTERIMAGE,
                                   0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)UI_CTL_STATUS, g_app.inst, NULL);
  else
    g_app.status = CreateWindowExW(0, L"msctls_statusbar32", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                   (HMENU)(UINT_PTR)UI_CTL_STATUS, g_app.inst, NULL);
  if ((!g_fluent && !g_app.toolbar) || !g_app.list || !g_app.status)
    return -1;
  if (g_fluent) {
    g_list_proc = (WNDPROC)SetWindowLongPtrW(g_app.list, GWLP_WNDPROC, (LONG_PTR)list_proc);
    apply_list_theme();
  } else if (g_aero) {
    ui_theme_apply_control(g_app.list);     /* the Explorer theme of the white list under the glass band */
  }

  SendMessageW(g_app.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
               LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_SUBITEMIMAGES | LVS_EX_DOUBLEBUFFER);
  /* groups need comctl32 v6; the message fails (negative) on an older control and the list stays flat (XP without the
     manifest cannot happen, the manifest is part of the executable; this keeps a failure from hiding the rows) */
  g_groups_on = (int)SendMessageW(g_app.list, LVM_ENABLEGROUPVIEW, TRUE, 0) >= 0;
  build_images();
  for (i = 0; i < UI_COLUMNS; i++) {
    const wchar_t *text;
    switch (i) {
    case 0: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_NAME); break;
    case 1: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SERVER); break;
    case 2: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_DRIVE); break;
    case 3: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_BACKEND); break;
    case 4: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_STATE); break;
    default: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SECURITY); break;
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
  if (ui_profiles_load() != SD_OK)
    SD_LOGW("ui", "the profile list could not be read");
  layout(hwnd);
  set_status_text();
  ui_main_refresh();
  return 0;
}

void ui_main_start_agent(void)
{
  if (g_app.agent_up || g_agent_starting)
    return;
  if (ui_ipc_start_agent() != SD_OK)
    return;
  g_agent_starting = 1;
  set_status_text();
}

void ui_main_agent_start_done(sd_err err)
{
  g_agent_starting = 0;
  if (err != SD_OK && !g_app.agent_up) {
    wchar_t *t;
    wchar_t code[64];
    ui_text_utf8(sd_err_name(err), code, SD_COUNTOF(code));
    t = ui_format1(SD_MSG_UI_STATUS_AGENT_START_FAILED, "code", code);
    if (t != NULL) {
      (void)ui_win_task(g_app.main, t, NULL, NULL, MB_OK | MB_ICONERROR);
      sd_free(t);
    }
  }
  set_status_text();
}

static LRESULT on_notify(NMHDR *nm)
{
  if (nm->idFrom == UI_CTL_STATUS) {
    /* the status bar is the Start button while the agent is not running (7.5) */
    if ((nm->code == NM_CLICK || nm->code == NM_DBLCLK) && !g_app.agent_up)
      ui_main_start_agent();
    return 0;
  }
  if (nm->idFrom == UI_CTL_TOOLBAR && nm->code == NM_CUSTOMDRAW)
    return aero_glass() ? aero_toolbar_draw((NMTBCUSTOMDRAW *)nm) : CDRF_DODEFAULT;
  if (nm->idFrom != UI_CTL_LIST)
    return 0;
  if (nm->code == NM_CUSTOMDRAW && g_fluent)
    return fluent_list_draw((NMLVCUSTOMDRAW *)nm);
  if (nm->code == LVN_ITEMCHANGED) {
    update_buttons();
  } else if (nm->code == NM_DBLCLK) {
    activate_selected();
  } else if (nm->code == LVN_KEYDOWN) {
    const NMLVKEYDOWN *kd = (const NMLVKEYDOWN *)nm;
    if (kd->wVKey == VK_DELETE)
      do_delete();
    else if (kd->wVKey == VK_RETURN)
      activate_selected();
    else if (kd->wVKey == VK_TAB && g_fluent)
      cb_focus_edge(GetKeyState(VK_SHIFT) < 0);
  }
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
    if (g_fluent && LOWORD(wp) == UI_CTL_STATUS) {
      /* the status strip is the Start button while the agent is not running (7.5) */
      if (HIWORD(wp) == STN_CLICKED && !g_app.agent_up)
        ui_main_start_agent();
      return 0;
    }
    on_command(LOWORD(wp));
    return 0;
  case WM_NOTIFY:
    return on_notify((NMHDR *)lp);
  case WM_DRAWITEM:
    if (g_fluent && wp != 0 && ((const DRAWITEMSTRUCT *)lp)->CtlType == ODT_BUTTON) {
      draw_cmd_button((const DRAWITEMSTRUCT *)lp);
      return TRUE;
    }
    break;
  case WM_CTLCOLORSTATIC:
    if (g_fluent && (HWND)lp == g_app.status) {
      SetTextColor((HDC)wp, ui_theme_color(UI_TOK_TEXT_SECONDARY));
      SetBkColor((HDC)wp, ui_theme_color(UI_TOK_LAYER));
      return (LRESULT)ui_theme_brush(UI_TOK_LAYER);
    }
    break;
  case WM_ERASEBKGND:
    if (g_fluent) {
      fluent_erase(hwnd, (HDC)wp);
      return 1;
    }
    if (aero_glass()) {
      RECT rc;
      GetClientRect(hwnd, &rc);
      FillRect((HDC)wp, &rc, (HBRUSH)(COLOR_BTNFACE + 1));
      aero_fill_band((HDC)wp, hwnd);
      return 1;
    }
    break;
  case WM_PAINT:
    if (g_fluent) {
      fluent_paint(hwnd);
      return 0;
    }
    if (aero_glass()) {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(hwnd, &ps);
      aero_fill_band(dc, hwnd);
      EndPaint(hwnd, &ps);
      return 0;
    }
    break;
  case WM_SYSCOMMAND:
    /* Alt pressed alone (and F10) opens the overflow menu where the menu bar was (06 §6.1) */
    if (g_fluent && (wp & 0xFFF0) == SC_KEYMENU && lp == 0) {
      show_overflow();
      return 0;
    }
    break;
  case WM_CLOSE:
    ShowWindow(hwnd, SW_HIDE);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_SETTINGCHANGE:
    /* the app theme changed (06 §4): the dark decision follows it; the broadcast reaches every window */
    if (lp != 0 && wcscmp((const wchar_t *)lp, L"ImmersiveColorSet") == 0)
      on_theme_changed(hwnd);
    break;
  case WM_THEMECHANGED:
  case WM_SYSCOLORCHANGE:
  case WM_DWMCOMPOSITIONCHANGED:
    /* the system theme, the system colors or DWM composition changed: re-select the tier (06 §4) */
    on_theme_changed(hwnd);
    break;
  case WM_DESTROY:
    if (g_bp_inited && g_fx_bpuninit != NULL)
      g_fx_bpuninit();
    g_bp_inited = 0;
    g_fluent = 0;
    g_aero = 0;
    g_band_h = 0;
    memset(g_cb, 0, sizeof(g_cb));
    g_overflow = NULL;
    g_hot = NULL;
    if (g_menu != NULL && GetMenu(hwnd) == NULL)
      DestroyMenu(g_menu);              /* the Fluent popup; a menu bar goes with its window */
    g_menu = NULL;
    g_frame_cy = 0;
    if (g_app.font)
      DeleteObject(g_app.font);
    g_app.font = NULL;
    if (g_images) {
      ImageList_Destroy(g_images);
      g_images = NULL;
    }
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
  if (g_fluent) {
    ui_theme_apply_window(hwnd, UI_THEME_WND_MAIN);   /* Mica on level 'c' (06 §3.3) */
    layout(hwnd);                                     /* sets the extended frame for the band */
  }
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

/* --test-window: the toolbar has its eight buttons, the list its six columns and the image list, and the menu
   has the Connection items. Groups are reported only when the control supports them (always with the v6 manifest). */
int ui_main_test_controls(void)
{
  static const int k_cmds[UI_TB_BUTTONS] = { UI_CMD_NEW, UI_CMD_EDIT, UI_CMD_DELETE, UI_CMD_MOUNT, UI_CMD_UNMOUNT,
                                             UI_CMD_OPEN_DRIVE, UI_CMD_HOSTKEYS, UI_CMD_LOGS };
  HWND header;
  HMENU bar;
  int i;
  if (!g_app.list || !g_app.status || !IsWindow(g_app.list) || !IsWindow(g_app.status))
    return 0;
  if (g_fluent) {
    /* the command bar: eight owner-drawn command buttons with the UI_CMD_* ids and the overflow button; no toolbar,
       no menu bar, a STATIC strip instead of the status bar (06 §6.1) */
    if (g_app.toolbar != NULL || GetMenu(g_app.main) != NULL || g_overflow == NULL || !IsWindow(g_overflow) ||
        GetDlgCtrlID(g_overflow) != UI_CTL_OVERFLOW)
      return 0;
    for (i = 0; i < UI_TB_BUTTONS; i++) {
      if (g_cb[i] == NULL || !IsWindow(g_cb[i]) || GetDlgCtrlID(g_cb[i]) != k_cmds[i] ||
          (GetWindowLongW(g_cb[i], GWL_STYLE) & BS_TYPEMASK) != BS_OWNERDRAW)
        return 0;
    }
  } else {
    if (!g_app.toolbar || !IsWindow(g_app.toolbar))
      return 0;
    for (i = 0; i < UI_TB_BUTTONS; i++)
      if (SendMessageW(g_app.toolbar, TB_COMMANDTOINDEX, (WPARAM)k_cmds[i], 0) < 0)
        return 0;
    /* eight buttons and two separators */
    if ((int)SendMessageW(g_app.toolbar, TB_BUTTONCOUNT, 0, 0) != UI_TB_BUTTONS + 2)
      return 0;
  }
  header = (HWND)SendMessageW(g_app.list, LVM_GETHEADER, 0, 0);
  if (header == NULL || (int)SendMessageW(header, HDM_GETITEMCOUNT, 0, 0) != UI_COLUMNS)
    return 0;
  if (g_images == NULL || (HIMAGELIST)SendMessageW(g_app.list, LVM_GETIMAGELIST, LVSIL_SMALL, 0) != g_images)
    return 0;
  bar = g_menu;                         /* the menu bar, or the overflow popup on Fluent */
  if (bar == NULL || GetMenuState(bar, UI_CMD_SECURITY, MF_BYCOMMAND) == (UINT)-1 ||
      GetMenuState(bar, UI_CMD_DUPLICATE, MF_BYCOMMAND) == (UINT)-1)
    return 0;
  return 1;
}

/* ---- --test-shot (06 §8.2) ---- */

typedef struct ui_shot_row {
  const wchar_t *cells[UI_COLUMNS];
  int group, status_image, sec_image;
} ui_shot_row;

/* Fixture strings are test data and are not localized. */
static const ui_shot_row k_shot_rows[4] = {
  { { L"Work files", L"files.example.org", L"W:", L"Dokany", L"Connected", L"OK" }, UI_MV_GROUP_MINE, 0, 0 },
  { { L"Home server", L"nas.example.net", L"H:", L"WebDAV", L"Not mounted", L"Legacy encryption" },
    UI_MV_GROUP_MINE, -1, 2 },
  { { L"Projects", L"sftp.corp.example", L"P:", L"Dokany", L"Reconnecting (3)", L"OK" }, UI_MV_GROUP_ORG, 1, 0 },
  { { L"Shared archive", L"archive.corp.example", L"S:", L"Dokany", L"Connected", L"OK" }, UI_MV_GROUP_GLOBAL, 0, 0 }
};

static void pump_for(DWORD ms)
{
  uint64_t t0 = sd_tick_ms();
  MSG msg;
  while (sd_tick_ms() - t0 < ms) {
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
    Sleep(10);
  }
}

/* The window rectangle from the screen DC into a 24-bit .bmp (the screen DC shows the Mica backdrop). */
static int capture_to_bmp(HWND hwnd, const wchar_t *path)
{
  RECT r;
  BITMAPINFO bi;
  BITMAPFILEHEADER fh;
  void *bits = NULL;
  HDC screen, mem;
  HBITMAP bmp, oldbmp;
  HANDLE file;
  DWORD done, size;
  int w, h, ok = 0;

  fx_resolve();
  if (g_fx_getattr == NULL || FAILED(g_fx_getattr(hwnd, UI_DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r))))
    GetWindowRect(hwnd, &r);
  w = r.right - r.left;
  h = r.bottom - r.top;
  if (w <= 0 || h <= 0)
    return 0;
  memset(&bi, 0, sizeof(bi));
  bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
  bi.bmiHeader.biWidth = w;
  bi.bmiHeader.biHeight = h;               /* bottom-up */
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 24;
  bi.bmiHeader.biCompression = BI_RGB;
  screen = GetDC(NULL);
  mem = CreateCompatibleDC(screen);
  bmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
  if (screen == NULL || mem == NULL || bmp == NULL || bits == NULL) {
    if (bmp)
      DeleteObject(bmp);
    if (mem)
      DeleteDC(mem);
    if (screen)
      ReleaseDC(NULL, screen);
    return 0;
  }
  oldbmp = (HBITMAP)SelectObject(mem, bmp);
  size = (DWORD)(((w * 3 + 3) & ~3) * h);
  if (BitBlt(mem, 0, 0, w, h, screen, r.left, r.top, SRCCOPY | 0x40000000 /* CAPTUREBLT */)) {
    memset(&fh, 0, sizeof(fh));
    fh.bfType = 0x4D42;
    fh.bfOffBits = (DWORD)(sizeof(fh) + sizeof(bi.bmiHeader));
    fh.bfSize = fh.bfOffBits + size;
    bi.bmiHeader.biSizeImage = size;
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
      ok = WriteFile(file, &fh, sizeof(fh), &done, NULL) && done == sizeof(fh) &&
           WriteFile(file, &bi.bmiHeader, sizeof(bi.bmiHeader), &done, NULL) && done == sizeof(bi.bmiHeader) &&
           WriteFile(file, bits, size, &done, NULL) && done == size;
      CloseHandle(file);
    }
  }
  SelectObject(mem, oldbmp);
  DeleteObject(bmp);
  DeleteDC(mem);
  ReleaseDC(NULL, screen);
  return ok;
}

int ui_main_test_shot(HWND hwnd, const wchar_t *path)
{
  size_t i;
  if (hwnd == NULL || path == NULL || !g_app.list)
    return 0;
  /* the fixture rows replace the list without an agent; g_rows keeps the groups for insert_groups */
  g_nrows = SD_COUNTOF(k_shot_rows);
  for (i = 0; i < g_nrows; i++) {
    g_rows[i].profile = -1;
    g_rows[i].mount = -1;
    g_rows[i].group = k_shot_rows[i].group;
  }
  SendMessageW(g_app.list, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_app.list, LVM_DELETEALLITEMS, 0, 0);
  if (g_groups_on)
    insert_groups();
  for (i = 0; i < g_nrows; i++)
    insert_row((int)i, k_shot_rows[i].cells, k_shot_rows[i].group, k_shot_rows[i].status_image,
               k_shot_rows[i].sec_image);
  SendMessageW(g_app.list, WM_SETREDRAW, TRUE, 0);
  ListView_SetItemState(g_app.list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
  set_status_text();
  SetWindowPos(hwnd, HWND_TOPMOST, 60, 60, dpx(880), dpx(560), SWP_SHOWWINDOW);
  SetForegroundWindow(hwnd);
  pump_for(1500);
  return capture_to_bmp(hwnd, path);
}
