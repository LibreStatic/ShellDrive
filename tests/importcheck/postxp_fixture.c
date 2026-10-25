/* Test fixture for sd-importcheck: statically imports a Vista+ function on purpose, so the audit
 * against the XP floor list must reject it. Never shipped. */
#include <windows.h>

__declspec(dllimport) ULONGLONG WINAPI GetTickCount64(VOID);

int main(void)
{
  return GetTickCount64() == 0 ? 1 : 0;
}
