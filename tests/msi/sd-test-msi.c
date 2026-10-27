/* sd-test-msi: checks of a built per-machine MSI (docs/design/04 §8, CTest label msi). Opt-in (SD_BUILD_MSI=ON).
 *
 *   sd-test-msi tables <package.msi> <version> <upgrade-code> <platform> <installer-version> <launch-count>
 *       Reads the package through msi.dll only (nothing is installed):
 *         - ProductVersion, UpgradeCode, ProductName and Manufacturer of the Property table;
 *         - the Template summary: the platform prefix, and every LCID of the language table is listed (C43);
 *         - every LCID of the language table is a substorage (_Storages), and each transform applies to a scratch
 *           copy with MSITRANSFORM_VALIDATE_LANGUAGE (the name form ":<lcid>" selects it);
 *         - the InstallerVersion (summary "Pages" property) and the number of launch conditions (04 §8.2);
 *         - the components and features of 04 §8.3, the registry rows (HKLM Run value, the LibreStatic Version
 *           marker, no Uninstall\ShellDrive key: Windows Installer writes the Add/Remove entry of an MSI);
 *         - the installer hooks (04 §8.3, TM-R35): deferred, NoImpersonate exactly where the table says so.
 *   sd-test-msi admin <package.msi> <work-dir>
 *       Administrative install (msiexec /a) into <work-dir>\target: no registry, service or system change. Checks
 *       that the four binaries are laid out. The caller removes <work-dir>.
 *
 * Exit code 0 when every check passes; each check prints "ok" or "FAIL" with its name.
 */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PID_TEMPLATE_PROP 7    /* PIDSI_TEMPLATE */
#define PID_PAGECOUNT_PROP 14  /* PIDSI_PAGECOUNT: "Pages" holds the installer version used to build */
#define CA_TYPE_NOIMPERSONATE 0x800
#define CA_TYPE_DEFERRED 0x400

static int g_failures = 0;

static void check(int ok, const char *name)
{
  if (!ok)
    g_failures++;
  printf("%s %s\n", ok ? "ok  " : "FAIL", name);
}

/* The LCIDs of the MSI language table. Written out here on purpose: this is an independent check of the table in
 * tools/sd-msigen (sd-msigen lcids). */
static const unsigned g_lcids[] = {
  3082, 11274, 1034, 2058, 21514, 4106, 5130, 6154, 7178, 8202, 9226, 10250, 12298, 13322, 14346, 15370,
  16394, 17418, 18442, 19466, 20490, 22538,
  1036, 2060, 3084, 4108, 5132, 6156,
  1046, 2070,
  1040, 2064,
  1031, 2055, 3079, 4103, 5127
};
#define N_LCIDS (sizeof(g_lcids) / sizeof(g_lcids[0]))

/* Returns 1 and copies the first string of the first row into buf; 0 when the query has no row. */
static int query_first(MSIHANDLE db, const wchar_t *sql, wchar_t *buf, DWORD cch)
{
  MSIHANDLE view = 0, rec = 0;
  int found = 0;
  if (MsiDatabaseOpenViewW(db, sql, &view) != ERROR_SUCCESS)
    return 0;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS && MsiViewFetch(view, &rec) == ERROR_SUCCESS)
    found = MsiRecordGetStringW(rec, 1, buf, &cch) == ERROR_SUCCESS;
  if (rec)
    MsiCloseHandle(rec);
  MsiCloseHandle(view);
  return found;
}

/* Number of rows of a query; -1 when the query does not run. */
static int count_rows(MSIHANDLE db, const wchar_t *sql)
{
  MSIHANDLE view = 0, rec = 0;
  int n = 0;
  if (MsiDatabaseOpenViewW(db, sql, &view) != ERROR_SUCCESS)
    return -1;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    while (MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
      n++;
      MsiCloseHandle(rec);
      rec = 0;
    }
  }
  MsiCloseHandle(view);
  return n;
}

/* Reads one summary property: text into buf (may be NULL) and the integer value into *ival. */
static int summary_read(const wchar_t *path, UINT pid, wchar_t *buf, DWORD cch, int *ival_out)
{
  MSIHANDLE h = 0, sum = 0;
  UINT type = 0;
  INT ival = 0;
  FILETIME ft;
  wchar_t scratch[2048];
  DWORD n = buf ? cch : 2048;
  int ok = 0;
  if (MsiOpenDatabaseW(path, (LPCWSTR)MSIDBOPEN_READONLY, &h) != ERROR_SUCCESS)
    return 0;
  if (MsiGetSummaryInformationW(h, NULL, 0, &sum) == ERROR_SUCCESS) {
    ok = MsiSummaryInfoGetPropertyW(sum, pid, &type, &ival, &ft, buf ? buf : scratch, &n) == ERROR_SUCCESS;
    if (ival_out)
      *ival_out = ival;
    MsiCloseHandle(sum);
  }
  MsiCloseHandle(h);
  return ok;
}

/* True when the Template list ("platform;lcid,lcid,...") names lcid, delimiters included. */
static int template_lists(const wchar_t *tmpl, unsigned lcid)
{
  wchar_t wrapped[1024], token[24];
  swprintf_s(wrapped, 1024, L",%ls,", wcschr(tmpl, L';') ? wcschr(tmpl, L';') + 1 : tmpl);
  swprintf_s(token, 24, L",%u,", lcid);
  return wcsstr(wrapped, token) != NULL;
}

/* Applies the embedded transform ":<lcid>" to a fresh handle on the scratch copy (validation on, no install). */
static int transform_applies(const wchar_t *copy, unsigned lcid)
{
  MSIHANDLE h = 0;
  wchar_t name[32];
  UINT rc;
  int ok;
  swprintf_s(name, 32, L":%u", lcid);
  if (MsiOpenDatabaseW(copy, (LPCWSTR)MSIDBOPEN_TRANSACT, &h) != ERROR_SUCCESS)
    return 0;
  rc = MsiDatabaseApplyTransformW(h, name, MSITRANSFORM_VALIDATE_LANGUAGE);
  ok = rc == ERROR_SUCCESS;
  MsiCloseHandle(h);
  return ok;
}

/* Type column of a custom action; 0 when the action is missing. */
static int ca_type(MSIHANDLE db, const wchar_t *action, int *found)
{
  wchar_t sql[256];
  MSIHANDLE view = 0, rec = 0;
  int type = 0;
  *found = 0;
  swprintf_s(sql, 256, L"SELECT `Type` FROM `CustomAction` WHERE `Action` = '%ls'", action);
  if (MsiDatabaseOpenViewW(db, sql, &view) != ERROR_SUCCESS)
    return 0;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS && MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
    type = MsiRecordGetInteger(rec, 1);
    *found = 1;
  }
  if (rec)
    MsiCloseHandle(rec);
  MsiCloseHandle(view);
  return type;
}

static int all_present(MSIHANDLE db, const wchar_t *table_column_fmt, const wchar_t **names, size_t n,
                       const char *label)
{
  size_t i;
  int ok = 1;
  wchar_t sql[512], buf[256];
  for (i = 0; i < n; i++) {
    swprintf_s(sql, 512, table_column_fmt, names[i]);
    if (!query_first(db, sql, buf, 256)) {
      printf("     missing %ls\n", names[i]);
      ok = 0;
    }
  }
  printf("     (%s: %u names)\n", label, (unsigned)n);
  return ok;
}

/* Case-insensitive substring test. */
static int contains_ci(const wchar_t *hay, const wchar_t *needle)
{
  size_t n = wcslen(needle), i;
  for (i = 0; hay[i]; i++) {
    if (_wcsnicmp(hay + i, needle, n) == 0)
      return 1;
  }
  return 0;
}

/* True when a row of the Registry table has a key containing text (case-insensitive). */
static int any_key_contains(MSIHANDLE db, const wchar_t *text)
{
  MSIHANDLE view = 0, rec = 0;
  int found = 0;
  if (MsiDatabaseOpenViewW(db, L"SELECT `Key` FROM `Registry`", &view) != ERROR_SUCCESS)
    return 0;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    while (!found && MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
      wchar_t key[512];
      DWORD cch = 512;
      if (MsiRecordGetStringW(rec, 1, key, &cch) == ERROR_SUCCESS && contains_ci(key, text))
        found = 1;
      MsiCloseHandle(rec);
      rec = 0;
    }
  }
  MsiCloseHandle(view);
  return found;
}

static int run_tables(const wchar_t *msi, const wchar_t *version, const wchar_t *upgrade, const wchar_t *platform,
                      int installer_version, int launch_count)
{
  MSIHANDLE db = 0;
  wchar_t buf[2048], tmpl[1024], copy[MAX_PATH], temp_dir[MAX_PATH];
  wchar_t sql[512];
  unsigned i;
  int ival = 0, ok;
  const wchar_t *components[] = {
    L"C_Core_Cli", L"C_Core_Host", L"C_Core_Ui", L"C_ShellExt", L"C_StartMenu", L"C_Ini_Update",
    L"C_Ini_Backend", L"C_LinkedConn", L"C_Rm_Secrets", L"C_Rm_Keys", L"C_Rm_Data", L"SD_Reg_000"
  };
  const wchar_t *features[] = { L"ShellDrive", L"Core", L"ShellExt", L"StartMenu", L"Autostart" };
  const wchar_t *hooks[] = { L"CA_ProgramDataSecure", L"CA_WebDavTune_Apply", L"CA_WebDavTune_Revert",
                             L"CA_SignalShutdown", L"CA_UserCleanup" };
  const size_t nhooks = sizeof(hooks) / sizeof(hooks[0]);

  if (MsiOpenDatabaseW(msi, (LPCWSTR)MSIDBOPEN_READONLY, &db) != ERROR_SUCCESS) {
    check(0, "package opens read-only");
    return 0;
  }
  check(1, "package opens read-only");

  check(query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductVersion'", buf, 2048) &&
        wcscmp(buf, version) == 0, "ProductVersion equals the VERSION file");
  check(query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'UpgradeCode'", buf, 2048) &&
        _wcsicmp(buf, upgrade) == 0, "UpgradeCode of the flavour family (04 §8.2)");
  check(query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'", buf, 2048) &&
        wcscmp(buf, L"ShellDrive") == 0, "ProductName is ShellDrive");
  check(query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'Manufacturer'", buf, 2048) &&
        wcscmp(buf, L"LibreStatic") == 0, "Manufacturer is LibreStatic (D45)");

  ok = summary_read(msi, PID_TEMPLATE_PROP, tmpl, 1024, NULL);
  check(ok && wcsncmp(tmpl, platform, wcslen(platform)) == 0 && tmpl[wcslen(platform)] == L';',
        "Template platform prefix (Intel, x64, Arm64)");
  ok = 1;
  for (i = 0; i < N_LCIDS; i++) {
    if (!template_lists(tmpl, g_lcids[i])) {
      printf("     LCID %u not in Template\n", g_lcids[i]);
      ok = 0;
    }
  }
  check(ok && template_lists(tmpl, 1033), "Template lists 1033 and every transform LCID (C43)");

  ok = summary_read(msi, PID_PAGECOUNT_PROP, NULL, 0, &ival) && ival == installer_version;
  check(ok, "InstallerVersion of the flavour (04 §8.2)");

  ok = 1;
  for (i = 0; i < N_LCIDS; i++) {
    swprintf_s(sql, 512, L"SELECT `Name` FROM `_Storages` WHERE `Name` = '%u'", g_lcids[i]);
    if (!query_first(db, sql, buf, 2048)) {
      printf("     no substorage %u\n", g_lcids[i]);
      ok = 0;
    }
  }
  check(ok, "every LCID of the language table is a substorage (C43)");

  /* Scratch copy: the transforms are applied to it, never installed. */
  GetTempPathW(MAX_PATH, temp_dir);
  swprintf_s(copy, MAX_PATH, L"%lssd-test-msi-%lu.msi", temp_dir, (unsigned long)GetCurrentProcessId());
  ok = CopyFileW(msi, copy, FALSE) != 0;
  if (ok) {
    for (i = 0; i < N_LCIDS; i++) {
      if (!transform_applies(copy, g_lcids[i])) {
        printf("     transform :%u does not apply\n", g_lcids[i]);
        ok = 0;
      }
    }
  }
  DeleteFileW(copy);
  check(ok, "every language transform applies with the language check on");

  ok = 1;
  for (i = 0; i < sizeof(components) / sizeof(components[0]); i++) {
    swprintf_s(sql, 512, L"SELECT `Component` FROM `Component` WHERE `Component` = '%ls'", components[i]);
    if (!query_first(db, sql, buf, 2048)) {
      printf("     missing component %ls\n", components[i]);
      ok = 0;
    }
  }
  check(ok, "components of 04 §8.3 present");

  ok = 1;
  for (i = 0; i < sizeof(features) / sizeof(features[0]); i++) {
    swprintf_s(sql, 512, L"SELECT `Feature` FROM `Feature` WHERE `Feature` = '%ls'", features[i]);
    if (!query_first(db, sql, buf, 2048)) {
      printf("     missing feature %ls\n", features[i]);
      ok = 0;
    }
  }
  check(ok, "feature tree of 04 §8.3 present");

  check(query_first(db, L"SELECT `Value` FROM `Registry` WHERE `Key` = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
                        L" AND `Name` = 'ShellDrive'", buf, 2048),
        "HKLM Run value of the autostart feature");
  check(query_first(db, L"SELECT `Value` FROM `Registry` WHERE `Key` = 'Software\\LibreStatic\\ShellDrive'"
                        L" AND `Name` = 'Version'", buf, 2048),
        "LibreStatic Version marker for Intune detection (04 §8.3)");
  check(!any_key_contains(db, L"Uninstall\\ShellDrive"),
        "no Uninstall key of ShellDrive from the registration rows (Windows Installer writes the ARP entry)");
  check(count_rows(db, L"SELECT `Condition` FROM `LaunchCondition`") == launch_count,
        "launch conditions: MajorUpgrade downgrade check plus the OS check of the flavour (04 §8.2)");
  check(count_rows(db, L"SELECT `Section` FROM `IniFile` WHERE `Section` = 'update'") >= 2,
        "settings.ini [update] lines for the public properties (04 §8.4)");

  ok = 1;
  for (i = 0; i < nhooks; i++) {
    int found = 0, type = ca_type(db, hooks[i], &found);
    if (!found) {
      printf("     missing custom action %ls\n", hooks[i]);
      ok = 0;
      continue;
    }
    if (!(type & CA_TYPE_DEFERRED)) {
      printf("     %ls is not deferred\n", hooks[i]);
      ok = 0;
    }
    /* Only CA_UserCleanup runs impersonated (04 §8.3 table); the others are NoImpersonate. */
    if (((type & CA_TYPE_NOIMPERSONATE) != 0) != (wcscmp(hooks[i], L"CA_UserCleanup") != 0)) {
      printf("     %ls impersonation is wrong (type %d)\n", hooks[i], type);
      ok = 0;
    }
  }
  check(ok, "installer hooks: deferred; NoImpersonate exactly where 04 §8.3 says (TM-R35)");

  MsiCloseHandle(db);
  return g_failures == 0;
}

/* True when a file called name exists under dir (searched recursively). */
static int find_file(const wchar_t *dir, const wchar_t *name)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t pattern[MAX_PATH], sub[MAX_PATH];
  int found = 0;
  swprintf_s(pattern, MAX_PATH, L"%ls\\*", dir);
  h = FindFirstFileW(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      swprintf_s(sub, MAX_PATH, L"%ls\\%ls", dir, fd.cFileName);
      found = find_file(sub, name);
    } else {
      found = _wcsicmp(fd.cFileName, name) == 0;
    }
  } while (!found && FindNextFileW(h, &fd));
  FindClose(h);
  return found;
}

/* Absolute path with backslashes: msiexec does not take the forward slashes of CMake paths. */
static int full_path(const wchar_t *in, wchar_t *out, DWORD cch)
{
  return GetFullPathNameW(in, cch, out, NULL) != 0;
}

static int run_admin(const wchar_t *msi_in, const wchar_t *work_in)
{
  wchar_t msi[MAX_PATH], work[MAX_PATH], target[MAX_PATH], copy[MAX_PATH], cmd[2048];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 1;
  const wchar_t *files[] = { L"shelldrive.exe", L"shelldrive-host.exe", L"shelldrive-ui.exe",
                             L"shelldrive-shellext.dll" };
  unsigned i;
  int ok = 1;

  if (!full_path(msi_in, msi, MAX_PATH) || !full_path(work_in, work, MAX_PATH)) {
    check(0, "admin install: paths resolve");
    return 0;
  }
  swprintf_s(target, MAX_PATH, L"%ls\\target", work);
  swprintf_s(copy, MAX_PATH, L"%ls\\package.msi", work);
  CreateDirectoryW(work, NULL);
  CreateDirectoryW(target, NULL);
  check(CopyFileW(msi, copy, FALSE) != 0, "admin install: scratch copy of the package");

  /* msiexec /a copies the files to TARGETDIR: it is not an install (no registry, service or custom action). */
  swprintf_s(cmd, 2048, L"msiexec.exe /a \"%ls\" /qn TARGETDIR=\"%ls\"", copy, target);
  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    check(0, "admin install: msiexec starts");
    return 0;
  }
  if (WaitForSingleObject(pi.hProcess, 600000) != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, 1);
    check(0, "admin install: msiexec finishes within 10 minutes");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
  }
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  if (code != 0)
    printf("     msiexec exit code %lu\n", (unsigned long)code);
  check(code == 0, "admin install: msiexec exits 0");

  for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    if (!find_file(target, files[i])) {
      printf("     %ls not copied\n", files[i]);
      ok = 0;
    }
  }
  check(ok, "admin install: the binaries of the flavour are laid out");
  return ok && code == 0;
}

int wmain(int argc, wchar_t **argv)
{
  int ok;
  if (argc == 8 && wcscmp(argv[1], L"tables") == 0) {
    ok = run_tables(argv[2], argv[3], argv[4], argv[5], _wtoi(argv[6]), _wtoi(argv[7]));
  } else if (argc == 4 && wcscmp(argv[1], L"admin") == 0) {
    ok = run_admin(argv[2], argv[3]);
  } else {
    fprintf(stderr, "usage: sd-test-msi tables <msi> <version> <upgrade-code> <platform> <installer-version> <launch-count>\n"
                    "       sd-test-msi admin <msi> <work-dir>\n");
    return 2;
  }
  printf("%s\n", ok ? "PASS" : "FAILED");
  return ok ? 0 : 1;
}
