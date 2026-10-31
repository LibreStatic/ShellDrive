/* shelldrive-ui: the OS-tiered theme (06 §4, §5). The decision is ui_theme_model.c (pure).
 *
 * ui_theme_init resolves every post-XP function at run time (sd_platform_resolve_by_name for the dwmapi and
 * uxtheme entry points, GetProcAddress by ordinal for the dark helpers of 06 §3.6; never a static import, so
 * the XP import floor stays empty) and installs a thread WH_CBT hook, so every window of this thread gets the
 * title bar attribute and the dark-mode flag when it is first activated. ui_theme_refresh re-gathers the
 * inputs, re-selects and re-applies to every captioned window of this thread; the main window calls it on
 * WM_SETTINGCHANGE "ImmersiveColorSet", WM_THEMECHANGED, WM_SYSCOLORCHANGE and WM_DWMCOMPOSITIONCHANGED.
 * Only the UI thread calls these functions. */
#ifndef SD_UI_THEME_H
#define SD_UI_THEME_H

#include <windows.h>
#include <commctrl.h>

#include "ui_theme_model.h"

/* The kinds of top-level window ui_theme_apply_window knows (06 §3.3, §6.3). */
#define UI_THEME_WND_MAIN    0    /* the main window: Mica backdrop on Fluent 2c */
#define UI_THEME_WND_FLYOUT  1    /* the tray flyout: Acrylic backdrop and small corners on 11 */
#define UI_THEME_WND_DIALOG  2    /* dialogs and property sheets: no backdrop */

/* ui_theme_set_options must be called before ui_theme_init. style: UI_THEME_STYLE_AUTO or _CLASSIC (06 §5.3);
   dark_helpers_setting: 1 = the helpers of 3.6 are allowed, 0 = the kill switch; forced_tier: -1 none, else
   UI_FORCE_TIER(tier, level, dark), the --theme override of the test modes (06 §8.1). */
void ui_theme_set_options(int style_setting, int dark_helpers_setting, int forced_tier);

void ui_theme_init(void);
void ui_theme_shutdown(void);
/* Re-gathers the inputs, re-selects and applies the theme to the windows of this thread. */
void ui_theme_refresh(void);
/* The last decision; NULL before ui_theme_init. */
const ui_theme *ui_theme_current(void);
/* The color of a UI_TOK_* token of the current theme. */
COLORREF ui_theme_color(int token);
/* A cached solid brush of a UI_TOK_* token; recreated by ui_theme_refresh when the color changes. */
HBRUSH ui_theme_brush(int token);
/* Applies the title bar attribute, the dark-mode flag and, per kind, the DWM backdrop and corners. */
void ui_theme_apply_window(HWND hwnd, int kind);
/* Themes one control for the tier: the DarkMode_* classes with the helpers on dark, "Explorer" on the light
   Fluent and Aero ListViews, nothing on Classic (06 §3.6, §6.1). */
void ui_theme_apply_control(HWND ctl);
/* Dialogs and secondary windows on a dark Fluent theme (06 §3.5, §6.2, §6.4): ui_theme_apply_dialog themes
   dlg (UI_THEME_WND_DIALOG) and every child control, and subclasses dlg so that on the dark palette it answers
   WM_CTLCOLOR* and erases its background itself (works for dialogs and plain windows); call it from
   WM_INITDIALOG or after creating the children. ui_theme_refresh re-applies it to the windows that called it. ui_theme_ctlcolor answers WM_CTLCOLORDLG/STATIC/BTN/EDIT/LISTBOX: it returns 1 and sets *result
   to the brush to return when the dark palette applies, 0 otherwise (the default handling then runs, so
   Classic, Aero, light Fluent and High Contrast keep the system colors). */
void ui_theme_apply_dialog(HWND dlg);
int  ui_theme_ctlcolor(UINT msg, WPARAM wp, LPARAM lp, LRESULT *result);

/* Fonts by role (06 §5.2); the caller deletes the font. UI_FONT_HEADER: a window or page title (Aero:
   TEXT_MAININSTRUCTION of the TEXTSTYLE theme; Fluent: Segoe UI Variable Display or Segoe UI Semibold at one and
   a half times the body; Classic and XP: the message font in bold). UI_FONT_SECTION: a group title (Fluent:
   Segoe UI Variable Text or Semibold at the body size; otherwise bold). UI_FONT_BODY: the message font. */
#define UI_FONT_BODY    0
#define UI_FONT_HEADER  1
#define UI_FONT_SECTION 2
HFONT ui_theme_font(int role, unsigned dpi);

/* NM_CUSTOMDRAW of a ListView header on the dark palette: layer background, secondary text, a stroke line under
   the items (the model of the main window's header). Returns 1 and sets *result when it handled the notification. */
int ui_theme_header_customdraw(NMCUSTOMDRAW *cd, LRESULT *result);
/* Themes one ListView for the palette: the layer colors on dark (and back to the system colors after a switch to
   light), the control theme, and a subclass that draws the header. ui_theme_apply_dialog calls it for every
   list among the children. */
void ui_theme_style_list(HWND list);
/* PROPSHEETHEADER pfnCallback of the editor and the wizard: ui_win_sheet_callback plus the theme of the sheet
   frame, its tab control and its buttons on PSCB_INITIALIZED. */
int CALLBACK ui_theme_sheet_callback(HWND sheet, UINT msg, LPARAM lp);

#endif /* SD_UI_THEME_H */
