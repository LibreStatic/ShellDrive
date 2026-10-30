/* shelldrive-ui: the dark mode decision (03 §7.4).
 *
 * v1 follows the system only where Windows documents it: the title bar of our windows uses the immersive dark
 * attribute (DWMWA_USE_IMMERSIVE_DARK_MODE) on Windows 11 build 22000 and later, when the user chose the dark app
 * theme. Everything else stays light; client areas use system colors, so High Contrast renders correctly.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_DARK_MODEL_H
#define SD_UI_DARK_MODEL_H

#include <windows.h>

#define UI_DARK_MIN_BUILD  22000u     /* Windows 11: DWMWA_USE_IMMERSIVE_DARK_MODE is documented from here */
#define UI_DARK_ATTRIBUTE  20         /* DWMWA_USE_IMMERSIVE_DARK_MODE */

/* 1 when the title bars must use the dark attribute. os_build: the OS build number (0 when unknown).
   dwm_present: DwmSetWindowAttribute was resolved at run time. apps_use_light: AppsUseLightTheme under
   HKCU\...\Themes\Personalize, 0 (dark apps), 1 (light apps), or -1 when the value is absent (light). */
int ui_dark_wanted(unsigned os_build, int dwm_present, int apps_use_light);

#endif /* SD_UI_DARK_MODEL_H */
