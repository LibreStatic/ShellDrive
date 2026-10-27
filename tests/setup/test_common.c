/* Helpers shared by the setup tests (see test_common.h). The CAB fixtures are built here at run time with
   makecab: the traversal fixture has a member named ..\evil.txt, which only makecab (not the engine) would
   ever produce. Built once per process, removed at exit. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <stdlib.h>

#include "setup_int.h"
#include "test_common.h"

int test_read_file(const wchar_t *path, unsigned char **buf, size_t *size)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER len;
  DWORD got = 0;
  unsigned char *p;

  if (h == INVALID_HANDLE_VALUE)
    return 1;
  if (!GetFileSizeEx(h, &len) || len.QuadPart <= 0 || len.QuadPart > 64 * 1024 * 1024) {
    CloseHandle(h);
    return 1;
  }
  p = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)len.QuadPart);
  if (p == NULL || !ReadFile(h, p, (DWORD)len.QuadPart, &got, NULL) || got != (DWORD)len.QuadPart) {
    if (p != NULL)
      HeapFree(GetProcessHeap(), 0, p);
    CloseHandle(h);
    return 1;
  }
  CloseHandle(h);
  *buf = p;
  *size = (size_t)len.QuadPart;
  return 0;
}

int test_make_temp_dir(wchar_t *out, size_t cch)
{
  wchar_t temp[MAX_PATH];
  wchar_t hex[40];
  wchar_t leaf[64];
  if (sd_setup_temp_dir(temp, SD_SETUP_COUNTOF_LOCAL(temp)) != 0)
    return 1;
  if (sd_setup_random_hex(hex, SD_SETUP_COUNTOF_LOCAL(hex)) != 0)
    return 1;
  StringCchPrintfW(leaf, SD_SETUP_COUNTOF_LOCAL(leaf), L"sdtest-%s", hex);
  if (sd_setup_path_join(out, cch, temp, leaf) != 0)
    return 1;
  return CreateDirectoryW(out, NULL) ? 0 : 1;
}

void test_remove_tree(const wchar_t *dir)
{
  sd_setup_remove_tree(dir, NULL);
}

/* ---------------------------------------------------------------- fixtures */

static wchar_t g_fixture_dir[MAX_PATH];
static int g_fixture_state;          /* 0 = not built, 1 = built, -1 = failed */

static int write_text(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD n = (DWORD)strlen(text), w = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE)
    return 1;
  ok = WriteFile(h, text, n, &w, NULL);
  CloseHandle(h);
  return (ok && w == n) ? 0 : 1;
}

/* Narrow form of a wide path, for the DDF text (ASCII temp paths). */
static int narrow(const wchar_t *w, char *out, size_t cch)
{
  return WideCharToMultiByte(CP_ACP, 0, w, -1, out, (int)cch, NULL, NULL) > 0 ? 0 : 1;
}

static int run_makecab(const wchar_t *ddf)
{
  wchar_t exe[MAX_PATH];
  wchar_t cmd[MAX_PATH * 2];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 1;

  if (sd_setup_system_path(L"makecab.exe", exe, SD_SETUP_COUNTOF_LOCAL(exe)) != 0)
    return 1;
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF_LOCAL(cmd), L"\"%s\" /F \"%s\"", exe, ddf);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, g_fixture_dir, &si, &pi))
    return 1;
  WaitForSingleObject(pi.hProcess, 60000);
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code == 0 ? 0 : 1;
}

static void remove_fixtures_at_exit(void)
{
  if (g_fixture_state == 1)
    sd_setup_remove_tree(g_fixture_dir, NULL);
}

static int build_fixtures(void)
{
  wchar_t src[MAX_PATH], sub[MAX_PATH], p[MAX_PATH], ddf[MAX_PATH];
  char ascii_dir[MAX_PATH * 2], ascii_src[MAX_PATH * 2], ascii_ddf[MAX_PATH * 2];
  char text[4096];

  if (g_fixture_state != 0)
    return g_fixture_state == 1 ? 0 : 1;
  g_fixture_state = -1;

  if (test_make_temp_dir(g_fixture_dir, SD_SETUP_COUNTOF_LOCAL(g_fixture_dir)) != 0)
    return 1;
  if (sd_setup_path_join(src, MAX_PATH, g_fixture_dir, L"src") != 0 || !CreateDirectoryW(src, NULL))
    return 1;
  if (sd_setup_path_join(sub, MAX_PATH, src, L"sub") != 0 || !CreateDirectoryW(sub, NULL))
    return 1;
  g_fixture_state = 1;
  atexit(remove_fixtures_at_exit);

  if (sd_setup_path_join(p, MAX_PATH, src, L"shelldrive.exe") != 0 || write_text(p, "fake shelldrive\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, src, L"shelldrive-host.exe") != 0 || write_text(p, "fake host\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, src, L"shelldrive-ui.exe") != 0 || write_text(p, "fake ui\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, src, L"shelldrive-shellext.dll") != 0 ||
      write_text(p, "fake shell extension\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, src, L"uninstall.exe") != 0 || write_text(p, "fake uninstaller\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, sub, L"readme.txt") != 0 || write_text(p, "readme\r\n"))
    return 1;
  if (sd_setup_path_join(p, MAX_PATH, src, L"evil.txt") != 0 || write_text(p, "outside the destination\r\n"))
    return 1;

  if (narrow(g_fixture_dir, ascii_dir, sizeof(ascii_dir)) != 0 || narrow(src, ascii_src, sizeof(ascii_src)) != 0)
    return 1;

  /* ok.ddf: the members of a normal payload, the sub-folder member included. */
  StringCchPrintfA(text, sizeof(text),
                   ".OPTION EXPLICIT\r\n.Set CabinetNameTemplate=payload-ok.cab\r\n"
                   ".Set DiskDirectoryTemplate=%s\\\r\n.Set InfFileName=%s\\ok.inf\r\n"
                   ".Set RptFileName=%s\\ok.rpt\r\n.Set CompressionType=LZX\r\n.Set CompressionMemory=21\r\n"
                   ".Set Compress=ON\r\n.Set Cabinet=ON\r\n"
                   "\"%s\\shelldrive.exe\" shelldrive.exe\r\n"
                   "\"%s\\shelldrive-host.exe\" shelldrive-host.exe\r\n"
                   "\"%s\\shelldrive-ui.exe\" shelldrive-ui.exe\r\n"
                   "\"%s\\shelldrive-shellext.dll\" shelldrive-shellext.dll\r\n"
                   "\"%s\\uninstall.exe\" uninstall.exe\r\n"
                   "\"%s\\sub\\readme.txt\" sub\\readme.txt\r\n",
                   ascii_dir, ascii_dir, ascii_dir, ascii_src, ascii_src, ascii_src, ascii_src, ascii_src,
                   ascii_src);
  if (sd_setup_path_join(ddf, MAX_PATH, g_fixture_dir, L"ok.ddf") != 0 || narrow(ddf, ascii_ddf, sizeof(ascii_ddf)))
    return 1;
  if (write_text(ddf, text) != 0 || run_makecab(ddf) != 0)
    return 1;

  /* traversal.ddf: a member whose name climbs out of the destination. */
  StringCchPrintfA(text, sizeof(text),
                   ".OPTION EXPLICIT\r\n.Set CabinetNameTemplate=payload-traversal.cab\r\n"
                   ".Set DiskDirectoryTemplate=%s\\\r\n.Set InfFileName=%s\\traversal.inf\r\n"
                   ".Set RptFileName=%s\\traversal.rpt\r\n.Set CompressionType=LZX\r\n"
                   ".Set CompressionMemory=21\r\n.Set Compress=ON\r\n.Set Cabinet=ON\r\n"
                   "\"%s\\shelldrive.exe\" shelldrive.exe\r\n"
                   "\"%s\\evil.txt\" ..\\evil.txt\r\n",
                   ascii_dir, ascii_dir, ascii_dir, ascii_src, ascii_src);
  if (sd_setup_path_join(ddf, MAX_PATH, g_fixture_dir, L"traversal.ddf") != 0 ||
      narrow(ddf, ascii_ddf, sizeof(ascii_ddf)))
    return 1;
  if (write_text(ddf, text) != 0 || run_makecab(ddf) != 0)
    return 1;

  g_fixture_state = 1;
  return 0;
}

void test_fixture_path(const wchar_t *leaf, wchar_t *out, size_t cch)
{
  if (build_fixtures() != 0) {
    out[0] = L'\0';
    return;
  }
  sd_setup_path_join(out, cch, g_fixture_dir, leaf);
}
