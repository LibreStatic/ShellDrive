/* shelldrive-host.exe: agent and service host (03 §1.2, §1.3; D3). M0 foundation placeholder:
 * prints the version. The host agent adds the `agent` and `service` modes. */
#include <windows.h>

#include "sd/version.h"
#include "sd_platform/sd_platform.h"

static void out(const wchar_t *s)
{
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD n = (DWORD)lstrlenW(s), mode, written;
  if (h == NULL || h == INVALID_HANDLE_VALUE)
    return;
  if (GetConsoleMode(h, &mode)) {
    WriteConsoleW(h, s, n, &written, NULL);
  } else {
    char buf[512];
    int len = WideCharToMultiByte(CP_UTF8, 0, s, (int)n, buf, (int)sizeof(buf), NULL, NULL);
    if (len > 0)
      WriteFile(h, buf, (DWORD)len, &written, NULL);
  }
}

int wmain(int argc, wchar_t **argv)
{
  SD_UNUSED(argc);
  SD_UNUSED(argv);
  sd_platform_harden_dll_search();
  sd_platform_init();
  out(L"shelldrive-host " SD_VERSION_STRING_W L" (" TEXT(SD_FLAVOUR_NAME) L", " TEXT(SD_GIT_COMMIT) L")\r\n");
  return 0;
}
