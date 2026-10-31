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

#endif /* SD_UI_THEME_H */
