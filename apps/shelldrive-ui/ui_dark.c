/* shelldrive-ui: dark mode of the title bars (03 §7.4). See ui_dark.h.
 *
 * Only documented behaviour is used: DWMWA_USE_IMMERSIVE_DARK_MODE on build 22000 and later, read from the
 * per-user theme value AppsUseLightTheme. The undocumented uxtheme ordinals are not used (7.4). */
#include <windows.h>

#include "sd_platform/sd_platform.h"
#include "ui_dark.h"
#include "ui_dark_model.h"

typedef HRESULT (WINAPI *ui_pfn_DwmSetWindowAttribute)(HWND hwnd, DWORD attribute, LPCVOID value, DWORD size);

static ui_pfn_DwmSetWindowAttribute g_dwm_set;
static HHOOK g_hook;
static int g_dark;

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

static void apply_one(HWND hwnd, int dark)
{
  BOOL on = dark ? TRUE : FALSE;
  if (g_dwm_set != NULL && hwnd != NULL)
    g_dwm_set(hwnd, UI_DARK_ATTRIBUTE, &on, sizeof(on));
}

static int is_captioned(HWND hwnd)
{
  return (GetWindowLongW(hwnd, GWL_STYLE) & WS_CAPTION) == WS_CAPTION;
}

static BOOL CALLBACK enum_cb(HWND hwnd, LPARAM dark)
{
  if (is_captioned(hwnd))
    apply_one(hwnd, (int)dark);
  return TRUE;
}

/* A window that is activated for the first time gets the attribute before it is seen in its own mode. */
static LRESULT CALLBACK cbt_proc(int code, WPARAM wp, LPARAM lp)
{
  if (code == HCBT_ACTIVATE && g_dark && wp != 0 && is_captioned((HWND)wp))
    apply_one((HWND)wp, 1);
  return CallNextHookEx(g_hook, code, wp, lp);
}

void ui_dark_refresh(void)
{
  const sd_os_version *v = sd_os_version_get();
  int want = ui_dark_wanted(v ? v->build : 0, g_dwm_set != NULL, read_apps_use_light());
  g_dark = want;
  EnumThreadWindows(GetCurrentThreadId(), enum_cb, (LPARAM)want);
}

void ui_dark_init(void)
{
  g_dwm_set = (ui_pfn_DwmSetWindowAttribute)sd_platform_resolve_by_name(L"dwmapi.dll", "DwmSetWindowAttribute");
  if (g_dwm_set != NULL && sd_os_at_least(10, 0, UI_DARK_MIN_BUILD) && g_hook == NULL)
    g_hook = SetWindowsHookExW(WH_CBT, cbt_proc, NULL, GetCurrentThreadId());
  ui_dark_refresh();
}

void ui_dark_shutdown(void)
{
  if (g_hook != NULL)
    UnhookWindowsHookEx(g_hook);
  g_hook = NULL;
  g_dwm_set = NULL;
  g_dark = 0;
}

int ui_dark_active(void)
{
  return g_dark;
}
