/* Installer hooks over the real hidden verb (sd-test-host-fake.exe --installer-hook ...): webdav-tune (C28, 04 §8.3).
 *
 * Every test runs the hook in its own process with the test overrides of the host build:
 *   SHELLDRIVE_TEST_WEBDAV_PARAMS  an HKCU key used instead of HKLM\SYSTEM\...\Services\WebClient\Parameters
 *   SHELLDRIVE_TEST_PROGRAMDATA    a temporary folder used instead of %ProgramData%
 * so the real machine values and the machine state folder are never touched. The tests check the two limits, the
 * recorded originals, the idempotence of a repeat apply, the restoration on --revert, and that a value of another
 * type or a damaged record is refused instead of overwritten. */
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>

#include "sd_test.h"

static wchar_t g_dir[MAX_PATH];
static wchar_t g_key[256];
static wchar_t g_root[MAX_PATH];
static unsigned g_n;

/* Fresh executable folder, HKCU key and %ProgramData% root for this test. */
static int prepare(void)
{
  wchar_t exe[MAX_PATH];
  wchar_t temp[MAX_PATH];
  LARGE_INTEGER qpc;
  DWORD n;
  size_t i, slash = 0;

  n = GetModuleFileNameW(NULL, exe, MAX_PATH);
  if (n == 0 || n >= MAX_PATH)
    return 0;
  for (i = 0; exe[i] != L'\0'; i++)
    if (exe[i] == L'\\')
      slash = i;
  exe[slash] = L'\0';
  if (FAILED(StringCchCopyW(g_dir, SD_COUNTOF(g_dir), exe)))
    return 0;
  QueryPerformanceCounter(&qpc);
  g_n++;
  if (GetTempPathW(MAX_PATH, temp) == 0)
    return 0;
  if (FAILED(StringCchPrintfW(g_root, SD_COUNTOF(g_root), L"%ssd-hooks-%lu-%lu-%08lx", temp,
                              (unsigned long)GetCurrentProcessId(), (unsigned long)g_n,
                              (unsigned long)qpc.LowPart)))
    return 0;
  (void)CreateDirectoryW(g_root, NULL);
  if (FAILED(StringCchPrintfW(g_key, SD_COUNTOF(g_key), L"Software\\LibreStatic\\ShellDriveTest\\hooks-%lu-%lu-%08lx",
                              (unsigned long)GetCurrentProcessId(), (unsigned long)g_n,
                              (unsigned long)qpc.LowPart)))
    return 0;
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROGRAMDATA", g_root);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_WEBDAV_PARAMS", g_key);
  return 1;
}

static void delete_tree(const wchar_t *dir)
{
  wchar_t pattern[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE h;

  if (FAILED(StringCchPrintfW(pattern, SD_COUNTOF(pattern), L"%s\\*", dir)))
    return;
  h = FindFirstFileW(pattern, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      wchar_t path[MAX_PATH];
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        continue;
      if (FAILED(StringCchPrintfW(path, SD_COUNTOF(path), L"%s\\%s", dir, fd.cFileName)))
        continue;
      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        delete_tree(path);
      else
        (void)DeleteFileW(path);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  (void)RemoveDirectoryW(dir);
}

static void cleanup(void)
{
  /* The test key holds values only (no subkeys), so RegDeleteKeyW (XP floor) removes it. */
  (void)RegDeleteKeyW(HKEY_CURRENT_USER, g_key);
  (void)RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LibreStatic\\ShellDriveTest");   /* only if no other run left a key */
  delete_tree(g_root);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROGRAMDATA", NULL);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_WEBDAV_PARAMS", NULL);
}

static int reg_open(HKEY *out)
{
  DWORD disp = 0;
  return RegCreateKeyExW(HKEY_CURRENT_USER, g_key, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, out,
                         &disp) == ERROR_SUCCESS ? 0 : 1;
}

static int reg_set_dword(const wchar_t *name, DWORD value)
{
  HKEY k;
  LONG rc;

  if (reg_open(&k) != 0)
    return 0;
  rc = RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
  RegCloseKey(k);
  return rc == ERROR_SUCCESS ? 1 : 0;
}

static int reg_set_sz(const wchar_t *name, const wchar_t *value)
{
  HKEY k;
  LONG rc;
  DWORD bytes = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));

  if (reg_open(&k) != 0)
    return 0;
  rc = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)value, bytes);
  RegCloseKey(k);
  return rc == ERROR_SUCCESS ? 1 : 0;
}

/* A value of this test key: 1 and *present when it is a DWORD, 1 and *present = 0 when absent, 0 on another type. */
static int reg_get_dword(const wchar_t *name, DWORD *value, int *present)
{
  HKEY k;
  DWORD type = 0;
  DWORD size = sizeof(DWORD);
  DWORD data = 0;
  LONG rc;

  *present = 0;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, g_key, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    return 1;
  rc = RegQueryValueExW(k, name, NULL, &type, (BYTE *)&data, &size);
  RegCloseKey(k);
  if (rc == ERROR_FILE_NOT_FOUND)
    return 1;
  if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD))
    return 0;
  *value = data;
  *present = 1;
  return 1;
}

static int reg_get_type(const wchar_t *name, DWORD *type)
{
  HKEY k;
  wchar_t data[64];
  DWORD size = sizeof(data);
  LONG rc;

  if (RegOpenKeyExW(HKEY_CURRENT_USER, g_key, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    return 0;
  rc = RegQueryValueExW(k, name, NULL, type, (BYTE *)data, &size);
  RegCloseKey(k);
  return rc == ERROR_SUCCESS ? 1 : 0;
}

static DWORD run_hook(const wchar_t *verb)
{
  wchar_t cmd[MAX_PATH * 2];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 0xFFFFFFFFu;

  if (FAILED(StringCchPrintfW(cmd, SD_COUNTOF(cmd), L"\"%s\\sd-test-host-fake.exe\" --installer-hook webdav-tune %s",
                              g_dir, verb)))
    return code;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    return code;
  WaitForSingleObject(pi.hProcess, 30000);
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code;
}

static int state_path(wchar_t *out, size_t cch)
{
  return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\LibreStatic\\ShellDrive\\service\\state\\webdav-tune.ini", g_root))
           ? 1
           : 0;
}

/* Writes a webdav-tune.ini under the test ProgramData root, creating the folders the hook uses. */
static int write_state(const char *text)
{
  wchar_t dir[MAX_PATH];
  wchar_t file[MAX_PATH];
  HANDLE f;
  DWORD put = 0;

  if (FAILED(StringCchPrintfW(dir, SD_COUNTOF(dir), L"%s\\LibreStatic", g_root)) ||
      !CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return 0;
  if (FAILED(StringCchPrintfW(dir, SD_COUNTOF(dir), L"%s\\LibreStatic\\ShellDrive", g_root)) ||
      !CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return 0;
  if (FAILED(StringCchPrintfW(dir, SD_COUNTOF(dir), L"%s\\LibreStatic\\ShellDrive\\service", g_root)) ||
      !CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return 0;
  if (FAILED(StringCchPrintfW(dir, SD_COUNTOF(dir), L"%s\\LibreStatic\\ShellDrive\\service\\state", g_root)) ||
      !CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return 0;
  if (!state_path(file, SD_COUNTOF(file)))
    return 0;
  f = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
    return 0;
  if (!WriteFile(f, text, (DWORD)strlen(text), &put, NULL) || put != (DWORD)strlen(text)) {
    CloseHandle(f);
    return 0;
  }
  CloseHandle(f);
  return 1;
}

/* Both limits are set, the originals are recorded, BasicAuthLevel is never touched, and --revert restores them. */
SD_TEST(hooks_webdav_tune_apply_and_revert_restore_originals)
{
  wchar_t state[MAX_PATH];
  DWORD v = 0;
  int present = 0;

  SD_REQUIRE(prepare());
  SD_REQUIRE(reg_set_dword(L"FileSizeLimitInBytes", 50000000));
  SD_REQUIRE(reg_set_dword(L"FileAttributesLimitInBytes", 1000000));
  SD_REQUIRE(reg_set_dword(L"BasicAuthLevel", 2));

  SD_CHECK(run_hook(L"--apply") == 0);
  SD_REQUIRE(state_path(state, SD_COUNTOF(state)));
  SD_CHECK(GetFileAttributesW(state) != INVALID_FILE_ATTRIBUTES);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 0xFFFFFFFFu);
  SD_REQUIRE(reg_get_dword(L"FileAttributesLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 100000000u);
  SD_REQUIRE(reg_get_dword(L"BasicAuthLevel", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 2);

  SD_CHECK(run_hook(L"--revert") == 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 50000000u);
  SD_REQUIRE(reg_get_dword(L"FileAttributesLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 1000000u);
  SD_REQUIRE(reg_get_dword(L"BasicAuthLevel", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 2);
  SD_CHECK(GetFileAttributesW(state) == INVALID_FILE_ATTRIBUTES);

  cleanup();
}

/* Values that did not exist are recorded as absent and deleted again; a repeat apply keeps the first originals. */
SD_TEST(hooks_webdav_tune_records_absence_and_repeat_apply_keeps_originals)
{
  DWORD v = 0;
  int present = 0;

  SD_REQUIRE(prepare());
  SD_CHECK(run_hook(L"--apply") == 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 0xFFFFFFFFu);

  /* Somebody changes the tuned values before the repair run: they are not the originals. */
  SD_REQUIRE(reg_set_dword(L"FileSizeLimitInBytes", 7));
  SD_REQUIRE(reg_set_dword(L"FileAttributesLimitInBytes", 8));
  SD_CHECK(run_hook(L"--apply") == 0);

  SD_CHECK(run_hook(L"--revert") == 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(!present);
  SD_REQUIRE(reg_get_dword(L"FileAttributesLimitInBytes", &v, &present));
  SD_CHECK(!present);
  /* BasicAuthLevel was never created by the hook. */
  SD_REQUIRE(reg_get_dword(L"BasicAuthLevel", &v, &present));
  SD_CHECK(!present);

  cleanup();
}

/* A revert with no record is a no-op: the hook never applied, or an older install. */
SD_TEST(hooks_webdav_tune_revert_without_state_is_a_noop)
{
  DWORD v = 0;
  int present = 0;

  SD_REQUIRE(prepare());
  SD_REQUIRE(reg_set_dword(L"FileSizeLimitInBytes", 12345));
  SD_CHECK(run_hook(L"--revert") == 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 12345u);
  cleanup();
}

/* A damaged record is refused by both verbs; the values are left as they are. */
SD_TEST(hooks_webdav_tune_refuses_a_damaged_state)
{
  DWORD v = 0;
  int present = 0;

  SD_REQUIRE(prepare());
  SD_REQUIRE(reg_set_dword(L"FileSizeLimitInBytes", 111));
  SD_REQUIRE(reg_set_dword(L"FileAttributesLimitInBytes", 222));
  SD_REQUIRE(write_state("[webdav-tune]\r\nfile_size_limit_in_bytes = notanumber\r\n"
                         "file_attributes_limit_in_bytes = absent\r\n"));

  SD_CHECK(run_hook(L"--apply") != 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 111u);
  SD_REQUIRE(reg_get_dword(L"FileAttributesLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 222u);

  SD_CHECK(run_hook(L"--revert") != 0);
  SD_REQUIRE(reg_get_dword(L"FileSizeLimitInBytes", &v, &present));
  SD_CHECK(present);
  SD_CHECK(v == 111u);

  cleanup();
}

/* A value that is not a DWORD is not ours: the hook fails closed instead of replacing or deleting it. */
SD_TEST(hooks_webdav_tune_refuses_a_value_of_another_type)
{
  wchar_t state[MAX_PATH];
  DWORD type = 0;

  SD_REQUIRE(prepare());
  SD_REQUIRE(reg_set_sz(L"FileSizeLimitInBytes", L"nope"));
  SD_REQUIRE(reg_set_dword(L"FileAttributesLimitInBytes", 222));

  SD_CHECK(run_hook(L"--apply") != 0);
  SD_REQUIRE(reg_get_type(L"FileSizeLimitInBytes", &type));
  SD_CHECK(type == REG_SZ);
  /* Nothing was recorded either: the value check comes before the state file. */
  SD_REQUIRE(state_path(state, SD_COUNTOF(state)));
  SD_CHECK(GetFileAttributesW(state) == INVALID_FILE_ATTRIBUTES);
  cleanup();
}
