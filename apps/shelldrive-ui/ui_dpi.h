/* shelldrive-ui: DPI scaling (03 §7.3, XP..11).
 *
 * The pure helpers (ui_dpi_scale, ui_dpi_font_height) are unit tested. The queries resolve the
 * Windows 8.1 and 10 APIs at run time (sd_platform_resolve, never imported: the floor lists of
 * tests/os-imports must stay XP-compatible). XP and Windows 7 use the system DPI read from a screen DC.
 * Per-monitor DPI on 8.1 and later comes from GetDpiForMonitor, per-window DPI on 10 1607 and later
 * from GetDpiForWindow. WM_DPICHANGED is handled by the main window (ui_main.c). */
#ifndef SD_UI_DPI_H
#define SD_UI_DPI_H

#include <windows.h>

#define UI_DPI_BASE 96u

/* value (in 96-DPI pixels) scaled to dpi, rounded half away from zero (MulDiv semantics). dpi 0 is 96;
   dpi is clamped to [48, 960] so a bad value cannot overflow. */
int ui_dpi_scale(int value, unsigned dpi);

/* Font point size to a LOGFONT lfHeight at dpi (negative: character height). */
int ui_dpi_font_height(int points, unsigned dpi);

/* Resolves the DPI APIs and reads the system DPI. Idempotent; call from the UI thread at startup. */
void ui_dpi_init(void);

/* System DPI, fixed for the session on XP..8 (GetDeviceCaps(LOGPIXELSX)). */
unsigned ui_dpi_system(void);

/* DPI of a window: GetDpiForWindow when available, else per-monitor (8.1+), else the system DPI. */
unsigned ui_dpi_window(HWND hwnd);

#endif /* SD_UI_DPI_H */
