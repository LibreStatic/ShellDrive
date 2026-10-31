/* shelldrive-ui: the OS-tiered theme (06 §4, §5). See ui_theme.h.
 *
 * Gathers the inputs (OS version, DWM, High Contrast, AppsUseLightTheme, visual styles, remote session),
 * selects the tier with ui_theme_select and owns the palette: colors and cached brushes per token. Every
 * post-XP function is resolved at run time, by name from System32 or, for the undocumented dark helpers of
 * 06 §3.6, by ordinal; there is no static import of dwmapi.dll or uxtheme.dll in any flavour, so the XP
 * import floor (tests/os-imports) stays empty. */
#include <windows.h>
#include <commctrl.h>

#include <string.h>

#include "sd/base.h"
#include "sd_platform/sd_platform.h"
#include "ui_dpi.h"
#include "ui_theme.h"
#include "ui_win.h"

/* Window properties of the dialog helpers: the original window procedure of a themed window, the marker of a
   window ui_theme_apply_dialog handled (a refresh re-applies it), and the controls that were switched to a dark
   class or a dark list palette (so a switch back to a light theme can undo it). */
#define UI_PROP_OLDPROC  L"sd.theme.oldproc"
#define UI_PROP_DIALOG   L"sd.theme.dialog"
#define UI_PROP_CTLDARK  L"sd.theme.ctldark"
#define UI_PROP_LISTDARK L"sd.theme.listdark"
#define UI_PROP_LISTPROC L"sd.theme.listproc"

#ifndef TMT_FONT
#define TMT_FONT 210
#endif

/* DWM attributes and values the XP SDK 7.1A headers lack (06 §12); DwmSetWindowAttribute itself is resolved
   at run time, and an attribute the OS does not know fails harmlessly. */
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif
#ifndef DWMWCP_ROUNDSMALL
#define DWMWCP_ROUNDSMALL 3
#endif
#ifndef DWMSBT_MAINWINDOW
#define DWMSBT_MAINWINDOW 2
#endif
#ifndef DWMSBT_TRANSIENTWINDOW
#define DWMSBT_TRANSIENTWINDOW 3
#endif

/* The undocumented dark-mode helpers of 06 §3.6, resolved by ordinal only. */
#define UI_UX_ORD_REFRESH_IMMERSIVE_COLOR_POLICY_STATE 104
#define UI_UX_ORD_ALLOW_DARK_MODE_FOR_WINDOW           133
#define UI_UX_ORD_ALLOW_DARK_MODE_FOR_APP              135  /* SetPreferredAppMode(int) from build 18362 */
#define UI_UX_ORD_FLUSH_MENU_THEMES                    136

typedef HRESULT (WINAPI *ui_pfn_DwmSetWindowAttribute)(HWND hwnd, DWORD attribute, LPCVOID value, DWORD size);
typedef HRESULT (WINAPI *ui_pfn_DwmIsCompositionEnabled)(BOOL *enabled);
typedef HRESULT (WINAPI *ui_pfn_DwmGetColorizationColor)(DWORD *color, BOOL *opaque);
typedef HRESULT (WINAPI *ui_pfn_SetWindowTheme)(HWND hwnd, const wchar_t *subapp, const wchar_t *sublist);
typedef BOOL (WINAPI *ui_pfn_IsAppThemed)(void);
typedef BOOL (WINAPI *ui_pfn_IsThemeActive)(void);
typedef void (WINAPI *ui_pfn_RefreshImmersiveColorPolicyState)(void);
typedef void (WINAPI *ui_pfn_AllowDarkModeForWindow)(HWND hwnd, BOOL allow);
typedef void (WINAPI *ui_pfn_PreferredAppMode)(int mode);   /* AllowDarkModeForApp(BOOL) before 18362 */
typedef void (WINAPI *ui_pfn_FlushMenuThemes)(void);

/* Classic and Aero map every token to a system color (06 §5.1); warning and error stay plain text there. */
static const int k_sys_tokens[UI_TOK_COUNT] = {
  COLOR_BTNFACE,      /* UI_TOK_SURFACE */
  COLOR_WINDOW,       /* UI_TOK_LAYER */
  COLOR_WINDOWTEXT,   /* UI_TOK_TEXT */
  COLOR_GRAYTEXT,     /* UI_TOK_TEXT_SECONDARY */
  COLOR_HIGHLIGHT,    /* UI_TOK_ACCENT */
  COLOR_HIGHLIGHTTEXT,/* UI_TOK_ACCENT_TEXT */
  COLOR_BTNSHADOW,    /* UI_TOK_STROKE */
  COLOR_HIGHLIGHT,    /* UI_TOK_SELECTION */
  COLOR_WINDOWTEXT,   /* UI_TOK_FOCUS */
  COLOR_WINDOWTEXT,   /* UI_TOK_WARNING */
  COLOR_WINDOWTEXT    /* UI_TOK_ERROR */
};

static ui_pfn_DwmSetWindowAttribute g_dwm_set;
static ui_pfn_DwmIsCompositionEnabled g_dwm_composition;
static ui_pfn_DwmGetColorizationColor g_dwm_colorization;
static ui_pfn_SetWindowTheme g_ux_set_window_theme;
static ui_pfn_IsAppThemed g_ux_is_app_themed;
static ui_pfn_IsThemeActive g_ux_is_theme_active;
static ui_pfn_RefreshImmersiveColorPolicyState g_refresh_policy;
static ui_pfn_AllowDarkModeForWindow g_allow_window;
static ui_pfn_PreferredAppMode g_preferred_app_mode;
static ui_pfn_FlushMenuThemes g_flush_menus;
static HHOOK g_hook;
static ui_theme g_theme;
static int g_ready;
static int g_style_setting;
static int g_dark_helpers_setting = 1;
static int g_forced_tier = -1;
static int g_helpers_on;          /* the last refresh switched the helper policy on */
static COLORREF g_accent;
static COLORREF g_sys[UI_TOK_COUNT];
static COLORREF g_colors[UI_TOK_COUNT];
static HBRUSH g_brushes[UI_TOK_COUNT];

static int read_apps_use_light(void)
{
  HKEY key;
  DWORD value = 0, type = 0, cb = sizeof(value);
  LONG r;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0,
                    KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
    return -1;
  r = RegQueryValueExW(key, L"AppsUseLightTheme", NULL, &type, (LPBYTE)&value, &cb);
  RegCloseKey(key);
  if (r != ERROR_SUCCESS || type != REG_DWORD || cb != sizeof(value))
    return -1;
  return value ? 1 : 0;
}

static void resolve_apis(void)
{
  const sd_os_version *v = sd_os_version_get();
  HMODULE ux;

  g_dwm_set = (ui_pfn_DwmSetWindowAttribute)sd_platform_resolve_by_name(L"dwmapi.dll",
                                                                        "DwmSetWindowAttribute");
  g_dwm_composition = (ui_pfn_DwmIsCompositionEnabled)sd_platform_resolve_by_name(L"dwmapi.dll",
                                                                                  "DwmIsCompositionEnabled");
  g_dwm_colorization = (ui_pfn_DwmGetColorizationColor)sd_platform_resolve_by_name(L"dwmapi.dll",
                                                                                   "DwmGetColorizationColor");
  g_ux_set_window_theme = (ui_pfn_SetWindowTheme)sd_platform_resolve_by_name(L"uxtheme.dll", "SetWindowTheme");
  g_ux_is_app_themed = (ui_pfn_IsAppThemed)sd_platform_resolve_by_name(L"uxtheme.dll", "IsAppThemed");
  g_ux_is_theme_active = (ui_pfn_IsThemeActive)sd_platform_resolve_by_name(L"uxtheme.dll", "IsThemeActive");

  /* The ordinals name other functions (or nothing) before 1809, so they are looked up from build 17763 only
     (06 §3.6). */
  if (v == NULL || v->build < UI_THEME_BUILD_HELPERS_MIN)
    return;
  ux = sd_platform_load_system_dll(L"uxtheme.dll");
  if (ux == NULL)
    return;
  g_refresh_policy = (ui_pfn_RefreshImmersiveColorPolicyState)GetProcAddress(
      ux, MAKEINTRESOURCEA(UI_UX_ORD_REFRESH_IMMERSIVE_COLOR_POLICY_STATE));
  g_allow_window = (ui_pfn_AllowDarkModeForWindow)GetProcAddress(
      ux, MAKEINTRESOURCEA(UI_UX_ORD_ALLOW_DARK_MODE_FOR_WINDOW));
  g_preferred_app_mode = (ui_pfn_PreferredAppMode)GetProcAddress(
      ux, MAKEINTRESOURCEA(UI_UX_ORD_ALLOW_DARK_MODE_FOR_APP));
  g_flush_menus = (ui_pfn_FlushMenuThemes)GetProcAddress(ux,
                                                         MAKEINTRESOURCEA(UI_UX_ORD_FLUSH_MENU_THEMES));
}

static void gather_inputs(ui_theme_inputs *in)
{
  const sd_os_version *v = sd_os_version_get();
  BOOL composed = FALSE;
  HIGHCONTRASTW hc;
  DWORD argb = 0;
  BOOL opaque = FALSE;

  memset(in, 0, sizeof(*in));
  in->os_major = v != NULL ? v->major : 0;
  in->os_minor = v != NULL ? v->minor : 0;
  in->os_build = v != NULL ? v->build : 0;
  in->dwm_present = g_dwm_set != NULL;
  if (g_dwm_composition != NULL && SUCCEEDED(g_dwm_composition(&composed)))
    in->composition = composed ? 1 : 0;
  memset(&hc, 0, sizeof(hc));
  hc.cbSize = sizeof(hc);
  if (SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0))
    in->high_contrast = (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
  in->apps_use_light = read_apps_use_light();
  in->themed = g_ux_is_app_themed != NULL && g_ux_is_theme_active != NULL && g_ux_is_app_themed() &&
               g_ux_is_theme_active();
  in->remote_session = GetSystemMetrics(SM_REMOTESESSION) != 0;
  in->style_setting = g_style_setting;
  in->dark_helpers_setting = g_dark_helpers_setting;
  in->forced_tier = g_forced_tier;
  in->helper_ordinals = g_allow_window != NULL && g_preferred_app_mode != NULL;

  g_accent = RGB(0x00, 0x78, 0xD4);            /* the fallback of 06 §5.1 when DWM has no color */
  if (g_dwm_colorization != NULL && SUCCEEDED(g_dwm_colorization(&argb, &opaque)))
    g_accent = RGB((int)((argb >> 16) & 0xFF), (int)((argb >> 8) & 0xFF), (int)(argb & 0xFF));
}

static void read_sys_colors(void)
{
  int i;
  for (i = 0; i < UI_TOK_COUNT; i++)
    g_sys[i] = GetSysColor(k_sys_tokens[i]);
}

/* The brushes follow the colors; a brush whose color did not change is kept (06 §8.3 S3). */
static void rebuild_brushes(void)
{
  int i;
  for (i = 0; i < UI_TOK_COUNT; i++) {
    LOGBRUSH lb;
    if (g_brushes[i] != NULL &&
        (GetObjectW(g_brushes[i], sizeof(lb), &lb) == 0 || lb.lbColor != g_colors[i])) {
      DeleteObject(g_brushes[i]);
      g_brushes[i] = NULL;
    }
    if (g_brushes[i] == NULL)
      g_brushes[i] = CreateSolidBrush(g_colors[i]);
  }
}

static void set_window_theme(HWND hwnd, const wchar_t *subapp)
{
  if (g_ux_set_window_theme != NULL)
    g_ux_set_window_theme(hwnd, subapp, NULL);
}

static int class_is(HWND hwnd, const wchar_t *name)
{
  wchar_t cls[32];
  if (GetClassNameW(hwnd, cls, SD_COUNTOF(cls)) == 0)
    return 0;
  return wcscmp(cls, name) == 0;
}

/* The title bar attribute (when the tier wants it, the documented value or 19) and the per-window dark-mode
   flag of the helpers. A light theme clears both, so a refresh can undo a dark one. */
static void apply_dark(HWND hwnd, const ui_theme *t)
{
  int attr;
  BOOL on;

  if (hwnd == NULL || g_dwm_set == NULL)
    return;
  attr = t->titlebar_attr != 0 ? t->titlebar_attr : DWMWA_USE_IMMERSIVE_DARK_MODE;
  on = t->dark ? TRUE : FALSE;
  g_dwm_set(hwnd, (DWORD)attr, &on, sizeof(on));
  if (g_allow_window != NULL && (t->dark_helpers || g_helpers_on))
    g_allow_window(hwnd, on);
}

static void apply_helpers_policy(void)
{
  int want = g_theme.dark_helpers;

  if (g_preferred_app_mode != NULL) {
    if (want)
      g_preferred_app_mode(1);               /* AllowDarkModeForApp(TRUE) / SetPreferredAppMode(AllowDark) */
    else if (g_helpers_on)
      g_preferred_app_mode(0);               /* back to the default when the helpers turn off */
    g_helpers_on = want;
  }
  if (want) {
    if (g_refresh_policy != NULL)
      g_refresh_policy();
    if (g_flush_menus != NULL)
      g_flush_menus();
  }
}

static int is_captioned(HWND hwnd)
{
  return (GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION) == WS_CAPTION;
}

static BOOL CALLBACK enum_cb(HWND hwnd, LPARAM lp)
{
  (void)lp;
  if (is_captioned(hwnd))
    apply_dark(hwnd, &g_theme);
  /* a window ui_theme_apply_dialog handled gets its controls re-themed, then every window repaints */
  if (GetPropW(hwnd, UI_PROP_DIALOG) != NULL)
    ui_theme_apply_dialog(hwnd);
  RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
  return TRUE;
}

/* A window that is activated for the first time gets the attribute before it is seen in its own mode. */
static LRESULT CALLBACK cbt_proc(int code, WPARAM wp, LPARAM lp)
{
  if (code == HCBT_ACTIVATE && wp != 0 && is_captioned((HWND)wp))
    apply_dark((HWND)wp, &g_theme);
  return CallNextHookEx(g_hook, code, wp, lp);
}

void ui_theme_set_options(int style_setting, int dark_helpers_setting, int forced_tier)
{
  g_style_setting = style_setting;
  g_dark_helpers_setting = dark_helpers_setting ? 1 : 0;
  g_forced_tier = forced_tier;
}

void ui_theme_init(void)
{
  const sd_os_version *v = sd_os_version_get();

  resolve_apis();
  if (g_dwm_set != NULL && v != NULL && v->build >= UI_THEME_BUILD_HELPERS_MIN && g_hook == NULL)
    g_hook = SetWindowsHookExW(WH_CBT, cbt_proc, NULL, GetCurrentThreadId());
  ui_theme_refresh();
}

void ui_theme_shutdown(void)
{
  int i;
  if (g_hook != NULL)
    UnhookWindowsHookEx(g_hook);
  g_hook = NULL;
  for (i = 0; i < UI_TOK_COUNT; i++) {
    if (g_brushes[i] != NULL)
      DeleteObject(g_brushes[i]);
    g_brushes[i] = NULL;
  }
  g_ready = 0;
}

void ui_theme_refresh(void)
{
  ui_theme_inputs in;

  gather_inputs(&in);
  ui_theme_select(&in, &g_theme);
  g_ready = 1;
  read_sys_colors();
  ui_theme_palette(&g_theme, g_accent, g_sys, g_colors);
  rebuild_brushes();
  apply_helpers_policy();
  EnumThreadWindows(GetCurrentThreadId(), enum_cb, 0);
}

const ui_theme *ui_theme_current(void)
{
  return g_ready ? &g_theme : NULL;
}

COLORREF ui_theme_color(int token)
{
  if (token < 0 || token >= UI_TOK_COUNT)
    return 0;
  return g_colors[token];
}

HBRUSH ui_theme_brush(int token)
{
  if (token < 0 || token >= UI_TOK_COUNT)
    return NULL;
  return g_brushes[token];
}

void ui_theme_apply_window(HWND hwnd, int kind)
{
  const ui_theme *t = ui_theme_current();
  int backdrop = 0, corner = 0;

  if (hwnd == NULL || t == NULL)
    return;
  apply_dark(hwnd, t);
  if (g_dwm_set == NULL)
    return;
  if (kind == UI_THEME_WND_MAIN && t->backdrop)
    backdrop = DWMSBT_MAINWINDOW;            /* Mica on the main window (06 §3.3, 2c) */
  else if (kind == UI_THEME_WND_FLYOUT && t->backdrop)
    backdrop = DWMSBT_TRANSIENTWINDOW;       /* Acrylic on the tray flyout (06 §6.3) */
  if (kind == UI_THEME_WND_FLYOUT && t->corners)
    corner = DWMWCP_ROUNDSMALL;
  if (backdrop != 0)
    g_dwm_set(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop, sizeof(backdrop));
  if (corner != 0)
    g_dwm_set(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
}

void ui_theme_apply_control(HWND ctl)
{
  const ui_theme *t = ui_theme_current();

  if (ctl == NULL || t == NULL)
    return;
  if (t->dark && t->dark_helpers) {
    /* DarkMode_Explorer covers the ListView, the TreeView, buttons and the scroll bars; combo and edit use
       the CFD classes (06 §3.6). */
    set_window_theme(ctl, class_is(ctl, L"Edit") || class_is(ctl, L"ComboBox") ||
                          class_is(ctl, L"ComboBoxEx32") ? L"DarkMode_CFD" : L"DarkMode_Explorer");
    if (g_allow_window != NULL)
      g_allow_window(ctl, TRUE);
    SetPropW(ctl, UI_PROP_CTLDARK, (HANDLE)1);
    return;
  }
  if (GetPropW(ctl, UI_PROP_CTLDARK) != NULL) {
    /* the theme switched from dark to light while the control lives: back to the default class */
    set_window_theme(ctl, NULL);
    if (g_allow_window != NULL)
      g_allow_window(ctl, FALSE);
    RemovePropW(ctl, UI_PROP_CTLDARK);
  }
  if ((t->tier == UI_TIER_FLUENT || t->tier == UI_TIER_AERO) && class_is(ctl, L"SysListView32")) {
    /* the Explorer theme of the list on light Fluent and Aero (06 §6.1) */
    set_window_theme(ctl, L"Explorer");
  }
  /* Classic: nothing (06 §3.1) */
}

int ui_theme_header_customdraw(NMCUSTOMDRAW *cd, LRESULT *result)
{
  HDITEMW hi;
  wchar_t text[96];
  RECT rc, line;
  HFONT font, old;
  HWND hdr;
  unsigned dpi;

  if (cd == NULL || result == NULL || ui_theme_brush(UI_TOK_LAYER) == NULL)
    return 0;
  hdr = cd->hdr.hwndFrom;
  if (cd->dwDrawStage == CDDS_PREPAINT) {
    FillRect(cd->hdc, &cd->rc, ui_theme_brush(UI_TOK_LAYER));
    *result = CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
    return 1;
  }
  if (cd->dwDrawStage == CDDS_POSTPAINT) {
    /* the filler to the right of the last item is painted by the theme after the items: cover it */
    int n = (int)SendMessageW(hdr, HDM_GETITEMCOUNT, 0, 0);
    GetClientRect(hdr, &rc);
    if (n > 0 && SendMessageW(hdr, HDM_GETITEMRECT, (WPARAM)(n - 1), (LPARAM)&line))
      rc.left = line.right;
    if (rc.left < rc.right) {
      FillRect(cd->hdc, &rc, ui_theme_brush(UI_TOK_LAYER));
      line = rc;
      line.top = line.bottom - 1;
      FillRect(cd->hdc, &line, ui_theme_brush(UI_TOK_STROKE));
    }
    *result = CDRF_DODEFAULT;
    return 1;
  }
  if (cd->dwDrawStage != CDDS_ITEMPREPAINT) {
    *result = CDRF_DODEFAULT;
    return 1;
  }
  rc = cd->rc;
  text[0] = 0;
  memset(&hi, 0, sizeof(hi));
  hi.mask = HDI_TEXT;
  hi.pszText = text;
  hi.cchTextMax = SD_COUNTOF(text);
  SendMessageW(hdr, HDM_GETITEMW, (WPARAM)cd->dwItemSpec, (LPARAM)&hi);
  FillRect(cd->hdc, &rc, ui_theme_brush(UI_TOK_LAYER));
  line = rc;
  line.top = line.bottom - 1;
  FillRect(cd->hdc, &line, ui_theme_brush(UI_TOK_STROKE));
  font = (HFONT)SendMessageW(hdr, WM_GETFONT, 0, 0);
  if (font == NULL)
    font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
  old = (HFONT)SelectObject(cd->hdc, font);
  SetBkMode(cd->hdc, TRANSPARENT);
  SetTextColor(cd->hdc, ui_theme_color(UI_TOK_TEXT_SECONDARY));
  dpi = ui_dpi_window(hdr);
  rc.left += ui_dpi_scale(8, dpi);
  rc.right -= ui_dpi_scale(4, dpi);
  DrawTextW(cd->hdc, text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
  SelectObject(cd->hdc, old);
  *result = CDRF_SKIPDEFAULT;
  return 1;
}

/* The list subclass: the header NM_CUSTOMDRAW reaches the ListView, not its parent. Only the dark palette
   draws the header; otherwise the default handling runs. */
static LRESULT CALLBACK list_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
  WNDPROC old = (WNDPROC)GetPropW(h, UI_PROP_LISTPROC);
  const ui_theme *t = ui_theme_current();

  if (old == NULL)
    return DefWindowProcW(h, msg, wp, lp);
  if (msg == WM_NOTIFY && t != NULL && t->dark) {
    NMHDR *nm = (NMHDR *)lp;
    LRESULT r = 0;
    if (nm->code == NM_CUSTOMDRAW && nm->hwndFrom == (HWND)SendMessageW(h, LVM_GETHEADER, 0, 0) &&
        ui_theme_header_customdraw((NMCUSTOMDRAW *)nm, &r))
      return r;
  }
  if (msg == WM_NCDESTROY) {
    SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)old);
    RemovePropW(h, UI_PROP_LISTPROC);
    RemovePropW(h, UI_PROP_LISTDARK);
    RemovePropW(h, UI_PROP_CTLDARK);
  }
  return CallWindowProcW(old, h, msg, wp, lp);
}

void ui_theme_style_list(HWND list)
{
  const ui_theme *t = ui_theme_current();
  HWND hdr;

  if (list == NULL || t == NULL)
    return;
  hdr = (HWND)SendMessageW(list, LVM_GETHEADER, 0, 0);
  if (GetPropW(list, UI_PROP_LISTPROC) == NULL) {
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(list, GWLP_WNDPROC, (LONG_PTR)list_proc);
    if (old != NULL)
      SetPropW(list, UI_PROP_LISTPROC, (HANDLE)old);
  }
  ui_theme_apply_control(list);
  if (t->dark) {
    SendMessageW(list, LVM_SETBKCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_LAYER));
    SendMessageW(list, LVM_SETTEXTBKCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_LAYER));
    SendMessageW(list, LVM_SETTEXTCOLOR, 0, (LPARAM)ui_theme_color(UI_TOK_TEXT));
    /* a themed header continues its column dividers through the list on Windows 11: the classic (empty)
       theme and the custom draw above paint it */
    if (hdr != NULL)
      set_window_theme(hdr, L"");
    SetPropW(list, UI_PROP_LISTDARK, (HANDLE)1);
  } else if (GetPropW(list, UI_PROP_LISTDARK) != NULL) {
    SendMessageW(list, LVM_SETBKCOLOR, 0, (LPARAM)GetSysColor(COLOR_WINDOW));
    SendMessageW(list, LVM_SETTEXTBKCOLOR, 0, (LPARAM)GetSysColor(COLOR_WINDOW));
    SendMessageW(list, LVM_SETTEXTCOLOR, 0, (LPARAM)GetSysColor(COLOR_WINDOWTEXT));
    if (hdr != NULL)
      set_window_theme(hdr, NULL);
    RemovePropW(list, UI_PROP_LISTDARK);
  }
  InvalidateRect(list, NULL, TRUE);
  if (hdr != NULL)
    InvalidateRect(hdr, NULL, TRUE);
}

/* The subclass of a themed dialog or plain window: on the dark palette it answers WM_CTLCOLOR* and erases the
   background with the surface brush, so the owner's own window procedure needs no theme code. */
static LRESULT CALLBACK themed_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
  WNDPROC old = (WNDPROC)GetPropW(h, UI_PROP_OLDPROC);
  const ui_theme *t = ui_theme_current();
  LRESULT r = 0;

  if (old == NULL)
    return DefWindowProcW(h, msg, wp, lp);
  if (t != NULL && t->dark) {
    if (msg == WM_ERASEBKGND) {
      RECT rc;
      GetClientRect(h, &rc);
      FillRect((HDC)wp, &rc, ui_theme_brush(UI_TOK_SURFACE));
      return 1;
    }
    if (ui_theme_ctlcolor(msg, wp, lp, &r))
      return r;
  }
  if (msg == WM_NCDESTROY) {
    SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)old);
    RemovePropW(h, UI_PROP_OLDPROC);
    RemovePropW(h, UI_PROP_DIALOG);
  }
  return CallWindowProcW(old, h, msg, wp, lp);
}

static BOOL CALLBACK apply_child_cb(HWND child, LPARAM lp)
{
  (void)lp;
  if (class_is(child, L"SysHeader32"))
    return TRUE;                             /* the list owns its header (ui_theme_style_list) */
  if (class_is(child, L"SysListView32"))
    ui_theme_style_list(child);
  else
    ui_theme_apply_control(child);
  return TRUE;
}

void ui_theme_apply_dialog(HWND dlg)
{
  const ui_theme *t = ui_theme_current();

  if (dlg == NULL || t == NULL)
    return;
  ui_theme_apply_window(dlg, UI_THEME_WND_DIALOG);
  if (GetPropW(dlg, UI_PROP_OLDPROC) == NULL) {
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)themed_proc);
    if (old != NULL)
      SetPropW(dlg, UI_PROP_OLDPROC, (HANDLE)old);
  }
  SetPropW(dlg, UI_PROP_DIALOG, (HANDLE)1);
  EnumChildWindows(dlg, apply_child_cb, 0);
}

int CALLBACK ui_theme_sheet_callback(HWND sheet, UINT msg, LPARAM lp)
{
  ui_win_sheet_callback(sheet, msg, lp);
  if (msg == PSCB_INITIALIZED)
    ui_theme_apply_dialog(sheet);              /* the frame, the tab control and OK / Cancel / Apply */
  return 0;
}

int ui_theme_ctlcolor(UINT msg, WPARAM wp, LPARAM lp, LRESULT *result)
{
  const ui_theme *t = ui_theme_current();
  HDC dc = (HDC)wp;
  int bg;

  (void)lp;
  if (t == NULL || !t->dark || result == NULL)
    return 0;
  /* edits and lists sit on the layer color, dialog backgrounds, labels and buttons on the surface (06 §5.1) */
  bg = msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORLISTBOX ? UI_TOK_LAYER : UI_TOK_SURFACE;
  switch (msg) {
  case WM_CTLCOLORDLG:
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN:
  case WM_CTLCOLOREDIT:
  case WM_CTLCOLORLISTBOX:
    SetTextColor(dc, ui_theme_color(UI_TOK_TEXT));
    SetBkColor(dc, ui_theme_color(bg));
    *result = (LRESULT)ui_theme_brush(bg);
    return 1;
  default:
    return 0;
  }
}

/* ---- fonts (06 §5.2) ---- */

static int CALLBACK font_exists_cb(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
  (void)lf;
  (void)tm;
  (void)type;
  *(int *)lp = 1;
  return 0;
}

static int font_exists(const wchar_t *face)
{
  LOGFONTW lf;
  HDC dc = GetDC(NULL);
  int found = 0;

  memset(&lf, 0, sizeof(lf));
  lf.lfCharSet = DEFAULT_CHARSET;
  wcsncpy_s(lf.lfFaceName, LF_FACESIZE, face, _TRUNCATE);
  EnumFontFamiliesExW(dc, &lf, (FONTENUMPROCW)font_exists_cb, (LPARAM)&found, 0);
  ReleaseDC(NULL, dc);
  return found;
}

typedef void *(WINAPI *ui_pfn_OpenThemeData)(HWND hwnd, const wchar_t *classes);
typedef HRESULT (WINAPI *ui_pfn_GetThemeFont)(void *theme, HDC dc, int part, int state, int prop, LOGFONTW *lf);
typedef HRESULT (WINAPI *ui_pfn_CloseThemeData)(void *theme);

/* TEXT_MAININSTRUCTION of the TEXTSTYLE class, the font of the Aero wizard and task dialog headings; 0 when the
   theme does not have it (the caller falls back to the bold message font). */
static int aero_instruction_font(LOGFONTW *lf, unsigned dpi)
{
  ui_pfn_OpenThemeData open_theme = (ui_pfn_OpenThemeData)sd_platform_resolve_by_name(L"uxtheme.dll",
                                                                                      "OpenThemeData");
  ui_pfn_GetThemeFont get_font = (ui_pfn_GetThemeFont)sd_platform_resolve_by_name(L"uxtheme.dll",
                                                                                  "GetThemeFont");
  ui_pfn_CloseThemeData close_theme = (ui_pfn_CloseThemeData)sd_platform_resolve_by_name(L"uxtheme.dll",
                                                                                         "CloseThemeData");
  void *theme;
  LOGFONTW tf;
  int ok = 0;
  long long h;
  unsigned sys = ui_dpi_system();

  if (open_theme == NULL || get_font == NULL || close_theme == NULL)
    return 0;
  theme = open_theme(NULL, L"TEXTSTYLE");
  if (theme == NULL)
    return 0;
  memset(&tf, 0, sizeof(tf));
  if (SUCCEEDED(get_font(theme, NULL, 1 /* TEXT_MAININSTRUCTION */, 0, TMT_FONT, &tf)) && tf.lfFaceName[0] != 0) {
    h = tf.lfHeight < 0 ? -(long long)tf.lfHeight : (long long)tf.lfHeight;
    if (h != 0) {
      if (sys == 0)
        sys = UI_DPI_BASE;
      if (dpi == 0)
        dpi = UI_DPI_BASE;
      h = (h * (long long)dpi + (long long)sys / 2) / (long long)sys;
      *lf = tf;
      lf->lfHeight = (LONG)-h;
      ok = 1;
    }
  }
  close_theme(theme);
  return ok;
}

HFONT ui_theme_font(int role, unsigned dpi)
{
  const ui_theme *t = ui_theme_current();
  HFONT base = ui_win_font(dpi);
  LOGFONTW lf;

  if (base == NULL || role == UI_FONT_BODY || t == NULL)
    return base;
  memset(&lf, 0, sizeof(lf));
  GetObjectW(base, sizeof(lf), &lf);
  DeleteObject(base);
  lf.lfWeight = FW_BOLD;                       /* Classic and XP: the message font in bold */
  if (t->tier == UI_TIER_FLUENT) {
    if (role == UI_FONT_HEADER) {
      lf.lfHeight = lf.lfHeight * 3 / 2;       /* a page title: one and a half times the body */
      if (font_exists(L"Segoe UI Variable Display")) {
        wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI Variable Display");
      } else if (font_exists(L"Segoe UI Semibold")) {
        wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI Semibold");
        lf.lfWeight = FW_NORMAL;
      }
    } else if (font_exists(L"Segoe UI Variable Text")) {
      wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI Variable Text");
    } else if (font_exists(L"Segoe UI Semibold")) {
      wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"Segoe UI Semibold");
      lf.lfWeight = FW_NORMAL;
    }
    if (lf.lfWeight == FW_BOLD)
      lf.lfWeight = FW_SEMIBOLD;
  } else if (t->tier == UI_TIER_AERO && role == UI_FONT_HEADER) {
    LOGFONTW tf;
    if (aero_instruction_font(&tf, dpi))
      lf = tf;
  }
  return CreateFontIndirectW(&lf);
}
