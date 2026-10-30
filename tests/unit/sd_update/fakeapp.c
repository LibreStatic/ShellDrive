/* sd-test-update-fakeapp.exe: stands in for shelldrive-host.exe and setup.exe in the apply tests (never shipped).
 * Its exit code is the first digit of selftest.code next to the executable (default 0), for every command
 * line, so a test decides whether the "new" binary passes --selftest or the staged setup. */
#include <windows.h>

int wmain(int argc, wchar_t **argv)
{
  wchar_t path[MAX_PATH];
  DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
  wchar_t *slash;
  HANDLE h;
  char buf[16];
  DWORD got = 0;
  int code = 0;
  (void)argc;
  (void)argv;
  if (n == 0 || n >= MAX_PATH)
    return 3;
  slash = wcsrchr(path, L'\\');
  if (slash == NULL)
    return 3;
  wcscpy_s(slash + 1, (size_t)(MAX_PATH - (slash + 1 - path)), L"selftest.code");
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, NULL) && got > 0 && buf[0] >= '0' && buf[0] <= '9')
      code = buf[0] - '0';
    CloseHandle(h);
  }
  return code;
}
