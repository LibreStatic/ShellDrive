/* shelldrive-ui: dark mode of the title bars (03 §7.4). The decision is ui_dark_model.c (pure).
 *
 * ui_dark_init resolves DwmSetWindowAttribute at run time (sd_platform_resolve_by_name, never imported) and
 * installs a thread WH_CBT hook, so every window of this thread gets the title bar attribute when it is activated.
 * ui_dark_refresh re-reads the app theme and applies it to every captioned window of this thread; the main window
 * calls it on WM_SETTINGCHANGE "ImmersiveColorSet". Only the UI thread calls these functions. */
#ifndef SD_UI_DARK_H
#define SD_UI_DARK_H

void ui_dark_init(void);
void ui_dark_shutdown(void);
/* Re-reads AppsUseLightTheme and applies the decision to the windows of this thread. */
void ui_dark_refresh(void);
/* 1 when the last decision was dark. */
int  ui_dark_active(void);

#endif /* SD_UI_DARK_H */
