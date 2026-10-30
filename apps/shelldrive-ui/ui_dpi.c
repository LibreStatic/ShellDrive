/* shelldrive-ui: DPI scaling helpers (ui_dpi.h). */
#include <windows.h>

#include "sd_platform/sd_platform.h"
#include "ui_dpi.h"

static unsigned g_system_dpi = UI_DPI_BASE;
static int g_inited;

static unsigned clamp_dpi(unsigned dpi)
{
  if (dpi == 0)
    return UI_DPI_BASE;
  if (dpi < 48u)
    return 48u;
  if (dpi > 960u)
    return 960u;
  return dpi;
}

int ui_dpi_scale(int value, unsigned dpi)
{
  unsigned long long mag, r;
  unsigned long long v = value < 0 ? (unsigned long long)(-(long long)value) : (unsigned long long)value;
  dpi = clamp_dpi(dpi);
  mag = v * (unsigned long long)dpi;
  r = (mag + UI_DPI_BASE / 2u) / UI_DPI_BASE;
  if (r > 0x7FFFFFFFull)
    r = 0x7FFFFFFFull;
  return value < 0 ? -(int)r : (int)r;
}

int ui_dpi_font_height(int points, unsigned dpi)
{
  /* A point is 1/72 inch; the height at 96 DPI is points * 96 / 72, rounded, then scaled. */
  int px96 = (int)(((long long)(points < 0 ? -points : points) * UI_DPI_BASE + 36) / 72);
  int px = ui_dpi_scale(px96, dpi);
  return -px;
}

void ui_dpi_init(void)
{
  sd_pfn_GetDpiForSystem get_system;
  HDC dc;

  if (g_inited)
    return;
  g_inited = 1;
  get_system = (sd_pfn_GetDpiForSystem)sd_platform_resolve(SD_API_GetDpiForSystem);
  if (get_system) {
    UINT d = get_system();
    g_system_dpi = clamp_dpi(d);
    return;
  }
  dc = GetDC(NULL);
  if (dc) {
    int d = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(NULL, dc);
    g_system_dpi = clamp_dpi(d > 0 ? (unsigned)d : 0u);
  }
}

unsigned ui_dpi_system(void)
{
  return g_system_dpi;
}

unsigned ui_dpi_window(HWND hwnd)
{
  sd_pfn_GetDpiForWindow get_window;
  sd_pfn_GetDpiForMonitor get_monitor;
  UINT d;

  get_window = (sd_pfn_GetDpiForWindow)sd_platform_resolve(SD_API_GetDpiForWindow);
  if (get_window && hwnd) {
    d = get_window(hwnd);
    if (d != 0)
      return clamp_dpi(d);
  }
  get_monitor = (sd_pfn_GetDpiForMonitor)sd_platform_resolve(SD_API_GetDpiForMonitor);
  if (get_monitor && hwnd) {
    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    UINT x = 0, y = 0;
    /* MDT_EFFECTIVE_DPI = 0 */
    if (mon && get_monitor(mon, 0, &x, &y) == S_OK && x != 0)
      return clamp_dpi(x);
  }
  return g_system_dpi;
}
