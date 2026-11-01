/* sd-test-msi: checks of a built per-machine MSI (docs/design/04 §8, CTest label msi). Opt-in (SD_BUILD_MSI=ON).
 *
 *   sd-test-msi tables <package.msi> <version> <upgrade-code> <platform> <installer-version> <launch-count> <shellext32> <ui>
 *       Reads the package through msi.dll only (nothing is installed):
 *         - ProductVersion, UpgradeCode, ProductName and Manufacturer of the Property table;
 *         - the Template summary: the platform prefix, and every LCID of the language table is listed (C43);
 *         - every LCID of the language table is a substorage (_Storages), and each transform applies to a scratch
 *           copy with MSITRANSFORM_VALIDATE_LANGUAGE (the name form ":<lcid>" selects it);
 *         - the InstallerVersion (summary "Pages" property) and the number of launch conditions (04 §8.2);
 *         - the components and features of 04 §8.3, the registry rows (HKLM Run value, the LibreStatic Version
 *           marker, no Uninstall\ShellDrive key: Windows Installer writes the Add/Remove entry of an MSI);
 *         - the installer hooks (04 §8.3, TM-R35): deferred, NoImpersonate exactly where the table says so.
 *         - with shellext32 = 1 (the x64 flavours, 04 §8.3, 03 §8.5): the x86 shell extension component in
 *           Program Files (x86)\LibreStatic\ShellDrive with Win64 = no, in the ShellExt feature, and its 32-bit
 *           registry rows in components without the 64-bit attribute; with 0 there is no such component or row.
 *         - with ui = 0 (the ARM32 package, 04 §5.1): no UI, shell extension or Start menu component, feature, file or
 *           registry row, no Dokany option, and the ARM32 launch condition (Windows 10 or later, build below 26100).
 *       <platform> is the Template prefix: Intel, x64, Arm64 or Arm.
 *   sd-test-msi admin <package.msi> <work-dir> <platform> <shellext32> <ui>
 *       Administrative install (msiexec /a) into <work-dir>\target: no registry, service or system change. Checks
 *       that the binaries of the flavour are laid out (four, or the CLI and the host with ui = 0), that shelldrive.exe
 *       is a PE image of the platform's machine and, with shellext32 = 1, that the native shell extension is there
 *       (the x86 copy has the same path in an admin image, see the admin check).
 *       The caller removes <work-dir>.
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

/* 1 when the Registry row of key with value name name ("" = the default value, Name NULL) has the value expect. */
static int registry_is(MSIHANDLE db, const wchar_t *key, const wchar_t *name, const wchar_t *expect)
{
  wchar_t sql[1024], nm[256], val[2048];
  MSIHANDLE view = 0, rec = 0;
  int found = 0;
  swprintf_s(sql, 1024, L"SELECT `Name`, `Value` FROM `Registry` WHERE `Key` = '%ls'", key);
  if (MsiDatabaseOpenViewW(db, sql, &view) != ERROR_SUCCESS)
    return 0;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    while (!found && MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
      DWORD ncch = 256, vcch = 2048;
      nm[0] = 0;
      if (!MsiRecordIsNull(rec, 1))
        MsiRecordGetStringW(rec, 1, nm, &ncch);
      if (wcscmp(nm, name) == 0 && MsiRecordGetStringW(rec, 2, val, &vcch) == ERROR_SUCCESS)
        found = wcscmp(val, expect) == 0;
      MsiCloseHandle(rec);
      rec = 0;
    }
  }
  MsiCloseHandle(view);
  return found;
}

/* 1 when the component of the Registry row with this key is installed by feature. */
static int key_in_feature(MSIHANDLE db, const wchar_t *key, const wchar_t *feature)
{
  wchar_t sql[1024], comp[128];
  swprintf_s(sql, 1024, L"SELECT `Component_` FROM `Registry` WHERE `Key` = '%ls'", key);
  if (!query_first(db, sql, comp, 128))
    return 0;
  swprintf_s(sql, 1024, L"SELECT `Feature_` FROM `FeatureComponents` WHERE `Component_` = '%ls' AND `Feature_` = '%ls'",
             comp, feature);
  return query_first(db, sql, comp, 128);
}

/* Attributes of a Component row (256 = msidbComponentAttributes64bit, set for Win64="yes"). 0 when there is no row. */
static int component_attributes(MSIHANDLE db, const wchar_t *component, int *attrs)
{
  wchar_t sql[512], buf[64];
  swprintf_s(sql, 512, L"SELECT `Attributes` FROM `Component` WHERE `Component` = '%ls'", component);
  if (!query_first(db, sql, buf, 64))
    return 0;
  *attrs = _wtoi(buf);
  return 1;
}

/* Number of Registry rows with this key and value whose component is 32-bit (no 64-bit attribute); -1 when the
   query does not run. The 64-bit rows of the same key and value are not counted (03 §8.5, 04 §8.3). */
static int view32_rows(MSIHANDLE db, const wchar_t *key, const wchar_t *value)
{
  MSIHANDLE view = 0, rec = 0;
  wchar_t sql[1024], comp[128];
  int n = 0;
  swprintf_s(sql, 1024, L"SELECT `Component_` FROM `Registry` WHERE `Key` = '%ls' AND `Value` = '%ls'", key, value);
  if (MsiDatabaseOpenViewW(db, sql, &view) != ERROR_SUCCESS)
    return -1;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    while (MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
      DWORD cch = 128;
      int attrs = 0;
      if (MsiRecordGetStringW(rec, 1, comp, &cch) == ERROR_SUCCESS && component_attributes(db, comp, &attrs) &&
          (attrs & 256) == 0)
        n++;
      MsiCloseHandle(rec);
      rec = 0;
    }
  }
  MsiCloseHandle(view);
  return n;
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

/* Sequence number of an action of an install sequence table, or -1 when the table has no such action. */
static int seq_of(MSIHANDLE db, const wchar_t *table, const wchar_t *action)
{
  wchar_t sql[512], buf[64];
  swprintf_s(sql, 512, L"SELECT `Sequence` FROM `%ls` WHERE `Action` = '%ls'", table, action);
  if (!query_first(db, sql, buf, 64))
    return -1;
  return _wtoi(buf);
}

/* The remembered choices of the package (04 §8.7): the RegistrySearch properties and the value names they read. */
static const wchar_t *g_remembered_prop[] = { L"SD_REG_DOKANY", L"SD_REG_ELC", L"SD_REG_ELC_OWNED" };
static const wchar_t *g_remembered_name[] = { L"DOKANY", L"ENABLELINKEDCONNECTIONS", L"ELC_OWNED" };

/* Number of rows of the File table whose file name (short|long form) contains text; -1 when the query does not run. */
static int count_files_containing(MSIHANDLE db, const wchar_t *text)
{
  MSIHANDLE view = 0, rec = 0;
  int n = 0;
  if (MsiDatabaseOpenViewW(db, L"SELECT `FileName` FROM `File`", &view) != ERROR_SUCCESS)
    return -1;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    while (MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
      wchar_t name[512];
      DWORD cch = 512;
      if (MsiRecordGetStringW(rec, 1, name, &cch) == ERROR_SUCCESS && wcsstr(name, text) != NULL)
        n++;
      MsiCloseHandle(rec);
      rec = 0;
    }
  }
  MsiCloseHandle(view);
  return n;
}

static int run_tables(const wchar_t *msi, const wchar_t *version, const wchar_t *upgrade, const wchar_t *platform,
                      int installer_version, int launch_count, int shellext32, int ui)
{
  MSIHANDLE db = 0;
  wchar_t buf[2048], tmpl[1024], copy[MAX_PATH], temp_dir[MAX_PATH];
  wchar_t sql[512];
  unsigned i;
  int ival = 0, ok;
  const wchar_t *components[] = {
    L"C_Core_Cli", L"C_Core_Host", L"C_Ini_Update", L"C_Ini_Backend", L"C_LinkedConn", L"C_Installer",
    L"C_Rm_Secrets", L"C_Rm_Keys", L"C_Rm_Data", L"SD_Reg_000"
  };
  const wchar_t *features[] = { L"ShellDrive", L"Core", L"Autostart" };
  /* The UI, the shell extension and the Start menu: in every package but ARM32 (04 §5.1). */
  const wchar_t *ui_components[] = { L"C_Core_Ui", L"C_ShellExt", L"C_StartMenu" };
  const wchar_t *ui_features[] = { L"ShellExt", L"StartMenu" };
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
        "Template platform prefix (Intel, x64, Arm64, Arm)");
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

  ok = 1;
  for (i = 0; i < sizeof(ui_components) / sizeof(ui_components[0]); i++) {
    swprintf_s(sql, 512, L"SELECT `Component` FROM `Component` WHERE `Component` = '%ls'", ui_components[i]);
    if (count_rows(db, sql) != (ui ? 1 : 0)) {
      printf("     component %ls %s\n", ui_components[i], ui ? "missing" : "present");
      ok = 0;
    }
  }
  for (i = 0; i < sizeof(ui_features) / sizeof(ui_features[0]); i++) {
    swprintf_s(sql, 512, L"SELECT `Feature` FROM `Feature` WHERE `Feature` = '%ls'", ui_features[i]);
    if (count_rows(db, sql) != (ui ? 1 : 0)) {
      printf("     feature %ls %s\n", ui_features[i], ui ? "missing" : "present");
      ok = 0;
    }
  }
  check(ok, ui ? "UI, shell extension and Start menu components and features present"
               : "no UI, shell extension or Start menu component or feature (ARM32, 04 §5.1)");
  check(count_files_containing(db, L"shelldrive-ui.exe") == (ui ? 1 : 0) &&
        any_key_contains(db, L"App Paths\\shelldrive-ui.exe") == ui,
        ui ? "the UI file and its App Paths row" : "no UI file and no App Paths row naming it (ARM32)");
  /* The Dokany option (04 §7.1): offered where a Dokany package exists, absent in ARM32, where WebDAV is the backend. */
  check(count_rows(db, L"SELECT `Control` FROM `Control` WHERE `Dialog_` = 'OptionsDlg' AND `Control` = 'DokanyCheckBox'") == ui &&
        query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'SD_DOKANY_STATE'", buf, 2048) &&
        wcscmp(buf, ui ? L"1" : L"0") == 0,
        ui ? "options page offers Dokany, on by default" : "no Dokany option, WebDAV backend by default (ARM32)");

  check(query_first(db, L"SELECT `Value` FROM `Registry` WHERE `Key` = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
                        L" AND `Name` = 'ShellDrive'", buf, 2048),
        "HKLM Run value of the autostart feature");
  check(query_first(db, L"SELECT `Value` FROM `Registry` WHERE `Key` = 'Software\\LibreStatic\\ShellDrive'"
                        L" AND `Name` = 'Version'", buf, 2048),
        "LibreStatic Version marker for Intune detection (04 §8.3)");
  if (!ui) {
    check(count_files_containing(db, L"shelldrive-shellext.dll") == 0 && !any_key_contains(db, L"ContextMenuHandlers") &&
          !any_key_contains(db, L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}"),
          "no shell extension file or registration row (ARM32)");
  }
  if (ui) {
    /* The shell extension rows (packaging/registration.txt, feature shellext, 03 §8.5): the same keys and values as the
       per-user registration in apps/shelldrive-shellext/shellext_register.c, all in the ShellExt feature. */
    static const struct { const wchar_t *key; const wchar_t *name; const wchar_t *value; } rows[] = {
      { L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}", L"", L"ShellDrive context menu" },
      { L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}\\InprocServer32", L"", L"[INSTALLDIR]shelldrive-shellext.dll" },
      { L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}\\InprocServer32", L"ThreadingModel", L"Apartment" },
      { L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}", L"", L"ShellDrive This PC context menu" },
      { L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}\\InprocServer32", L"", L"[INSTALLDIR]shelldrive-shellext.dll" },
      { L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}\\InprocServer32", L"ThreadingModel", L"Apartment" },
      { L"Software\\Classes\\Drive\\shellex\\ContextMenuHandlers\\ShellDrive", L"", L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}" },
      { L"Software\\Classes\\Directory\\shellex\\ContextMenuHandlers\\ShellDrive", L"", L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}" },
      { L"Software\\Classes\\*\\shellex\\ContextMenuHandlers\\ShellDrive", L"", L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}" },
      { L"Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\shellex\\ContextMenuHandlers\\ShellDrive", L"",
        L"{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}" },
      { L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}",
        L"ShellDrive context menu" },
      { L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", L"{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}",
        L"ShellDrive This PC context menu" },
    };
    size_t r;
    int ok_values = 1, ok_feature = 1;
    for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
      if (!registry_is(db, rows[r].key, rows[r].name, rows[r].value)) {
        printf("     wrong or missing %ls [%ls]\n", rows[r].key, rows[r].name);
        ok_values = 0;
      }
      if (!key_in_feature(db, rows[r].key, L"ShellExt")) {
        printf("     not in feature ShellExt: %ls\n", rows[r].key);
        ok_feature = 0;
      }
    }
    check(ok_values, "shell extension rows: CLSIDs with the DLL and Apartment, Drive/Directory/* and This PC handlers, Approved (03 §8.5)");
    check(ok_feature, "shell extension rows are in the ShellExt feature (no registration without the DLL)");
  }
  if (ui) {
    /* The 32-bit view of the shell extension (04 §8.3, 03 §8.5): the x86 DLL in INSTALLDIR\x86 (Win64 = no) and the
       CLSID and handler rows of the same keys with the x86 path, in components without the 64-bit attribute. The 64-bit
       rows of the same keys stay in 64-bit components. With shellext32 = 0 the package has none of this. */
    static const wchar_t clsid1[] = L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}";
    static const wchar_t clsid2[] = L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}";
    static const wchar_t thispc[] =
      L"Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\shellex\\ContextMenuHandlers\\ShellDrive";
    static const wchar_t handler[] = L"Software\\Classes\\Drive\\shellex\\ContextMenuHandlers\\ShellDrive";
    static const wchar_t dirhandler[] = L"Software\\Classes\\Directory\\shellex\\ContextMenuHandlers\\ShellDrive";
    static const wchar_t starhandler[] = L"Software\\Classes\\*\\shellex\\ContextMenuHandlers\\ShellDrive";
    static const wchar_t dll32[] = L"[SD_INSTALLDIR32]shelldrive-shellext.dll";
    static const wchar_t guid1[] = L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}";
    static const wchar_t guid2[] = L"{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}";
    wchar_t key_inproc1[256], key_inproc2[256];
    int ok32 = 1, n;
    size_t r;
    struct { const wchar_t *key; const wchar_t *value; } rows32[8];

    swprintf_s(key_inproc1, 256, L"%ls\\InprocServer32", clsid1);
    swprintf_s(key_inproc2, 256, L"%ls\\InprocServer32", clsid2);
    rows32[0].key = clsid1;      rows32[0].value = L"ShellDrive context menu";
    rows32[1].key = key_inproc1; rows32[1].value = dll32;
    rows32[2].key = clsid2;      rows32[2].value = L"ShellDrive This PC context menu";
    rows32[3].key = key_inproc2; rows32[3].value = dll32;
    rows32[4].key = handler;     rows32[4].value = guid1;
    rows32[5].key = dirhandler;  rows32[5].value = guid1;
    rows32[6].key = starhandler; rows32[6].value = guid1;
    rows32[7].key = thispc;      rows32[7].value = guid2;

    if (shellext32) {
      int attrs = 0;
      check(count_rows(db, L"SELECT `Component` FROM `Component` WHERE `Component` = 'C_ShellExt32'") == 1 &&
            component_attributes(db, L"C_ShellExt32", &attrs) && (attrs & 256) == 0,
            "32-bit shell extension component C_ShellExt32 has Win64 = no (04 §8.3)");
      check(query_first(db, L"SELECT `Directory_` FROM `Component` WHERE `Component` = 'C_ShellExt32'", buf, 2048) &&
            wcscmp(buf, L"SD_INSTALLDIR32") == 0 &&
            query_first(db, L"SELECT `Directory_Parent` FROM `Directory` WHERE `Directory` = 'SD_VENDOR_PF32'", buf, 2048) &&
            wcscmp(buf, L"ProgramFilesFolder") == 0,
            "32-bit shell extension is in Program Files (x86)\\LibreStatic\\ShellDrive");
      check(query_first(db, L"SELECT `Feature_` FROM `FeatureComponents` WHERE `Component_` = 'C_ShellExt32'", buf, 2048) &&
            wcscmp(buf, L"ShellExt") == 0, "32-bit shell extension component is in the ShellExt feature");
      for (r = 0; r < sizeof(rows32) / sizeof(rows32[0]); r++) {
        n = view32_rows(db, rows32[r].key, rows32[r].value);
        if (n != 1) {
          printf("     %d 32-bit rows for %ls [%ls]\n", n, rows32[r].key, rows32[r].value);
          ok32 = 0;
        }
      }
      check(ok32, "32-bit registry view: CLSIDs, handlers and the x86 DLL path in Win64 = no components (03 §8.5)");
      check(count_files_containing(db, L"shelldrive-shellext.dll") == 2,
            "two shell extension files in the package: the x64 copy and the x86 copy (04 §8.3)");
      check(view32_rows(db, key_inproc1, L"[INSTALLDIR]shelldrive-shellext.dll") == 0,
            "the 64-bit DLL path is registered only in 64-bit components");
    } else {
      check(count_files_containing(db, L"shelldrive-shellext.dll") == 1,
            "one shell extension file in this package (32-bit flavours)");
      check(count_rows(db, L"SELECT `Component` FROM `Component` WHERE `Component` = 'C_ShellExt32'") == 0,
            "no 32-bit shell extension component in this package (32-bit flavours)");
      check(view32_rows(db, key_inproc1, dll32) == 0 && view32_rows(db, key_inproc2, dll32) == 0,
            "no 32-bit registry rows in this package (32-bit flavours)");
    }
  }
  check(!any_key_contains(db, L"Uninstall\\ShellDrive"),
        "no Uninstall key of ShellDrive from the registration rows (Windows Installer writes the ARP entry)");
  check(count_rows(db, L"SELECT `Condition` FROM `LaunchCondition`") == launch_count,
        "launch conditions: MajorUpgrade downgrade check plus the OS check of the flavour (04 §8.2)");
  if (wcscmp(platform, L"Arm") == 0) {
    /* ARM32 (04 §5.1): Windows 10 or later (RT 8.1 has no CurrentMajorVersionNumber) and a build below 26100 (Windows 11
       24H2 runs no ARM32 app). */
    MSIHANDLE view = 0, rec = 0;
    int found = 0;
    check(count_rows(db, L"SELECT `Property` FROM `AppSearch` WHERE `Property` = 'SD_OSBUILD'") == 1 &&
          query_first(db, L"SELECT `Name` FROM `RegLocator` WHERE `Signature_` = 'SD_OSBUILD_RS'", buf, 2048) &&
          wcscmp(buf, L"CurrentBuildNumber") == 0,
          "ARM32: SD_OSBUILD reads CurrentBuildNumber (04 §5.1)");
    if (MsiDatabaseOpenViewW(db, L"SELECT `Condition` FROM `LaunchCondition`", &view) == ERROR_SUCCESS) {
      if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
        while (!found && MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
          DWORD cch = 2048;
          if (MsiRecordGetStringW(rec, 1, buf, &cch) == ERROR_SUCCESS)
            found = contains_ci(buf, L"SD_OSMAJOR >= 10") && contains_ci(buf, L"SD_OSBUILD < 26100");
          MsiCloseHandle(rec);
          rec = 0;
        }
      }
      MsiCloseHandle(view);
    }
    check(found, "ARM32 launch condition: Windows 10 or later and a build below 26100 (Windows 11 24H2)");
  }
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

  /* Remembered choices and EnableLinkedConnections ownership (04 §8.7). */
  check(!query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'DOKANY'", buf, 2048) &&
        !query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'ENABLELINKEDCONNECTIONS'", buf, 2048),
        "DOKANY and ENABLELINKEDCONNECTIONS have no default: command line, then registry, then default decide");
  check(query_first(db, L"SELECT `Value` FROM `Property` WHERE `Property` = 'ARPNOMODIFY'", buf, 2048) &&
        wcscmp(buf, L"0") == 0, "ARPNOMODIFY is 0 (Change offered, 04 §6.7)");

  ok = 1;
  for (i = 0; i < sizeof(g_remembered_prop) / sizeof(g_remembered_prop[0]); i++) {
    swprintf_s(sql, 512, L"SELECT `RegLocator`.`Signature_` FROM `RegLocator`, `AppSearch`"
                         L" WHERE `AppSearch`.`Signature_` = `RegLocator`.`Signature_`"
                         L" AND `AppSearch`.`Property` = '%ls' AND `RegLocator`.`Name` = '%ls'"
                         L" AND `RegLocator`.`Key` = 'SOFTWARE\\LibreStatic\\ShellDrive\\Installer'"
                         L" AND `RegLocator`.`Root` = 2", g_remembered_prop[i], g_remembered_name[i]);
    if (count_rows(db, sql) != 1) {
      printf("     no RegLocator/AppSearch row for %ls\n", g_remembered_prop[i]);
      ok = 0;
    }
  }
  check(ok, "RegistrySearch rows read the Installer key: DOKANY, ENABLELINKEDCONNECTIONS, ELC_OWNED (04 §8.7)");

  check(query_first(db, L"SELECT `Condition` FROM `Component` WHERE `Component` = 'C_LinkedConn'", buf, 2048) &&
        contains_ci(buf, L"SD_ELC_WRITE") && !contains_ci(buf, L"Installed"),
        "C_LinkedConn is installed only when the package owns the value (SD_ELC_WRITE, 04 §8.7)");
  check(query_first(db, L"SELECT `Condition` FROM `Component` WHERE `Component` = 'C_Ini_Backend'", buf, 2048) &&
        contains_ci(buf, L"SD_DOKANY_STATE"), "C_Ini_Backend follows the effective DOKANY state (settings.ini as stored)");
  check(count_rows(db, L"SELECT `Name` FROM `Registry` WHERE `Component_` = 'C_Installer'") == 3,
        "C_Installer writes DOKANY, ENABLELINKEDCONNECTIONS and ELC_OWNED (always installed)");

  /* Order: the registry is read in AppSearch, the choices are initialised once, the effective state is set before costing. */
  {
    static const wchar_t *ui_order[] = { L"AppSearch", L"SetSD_UI_DOKANY", L"SetSD_UI_ELC", L"SetSD_UI_INIT" };
    static const wchar_t *exec_order[] = { L"AppSearch", L"SetSD_UI_DOKANY", L"SetSD_UI_ELC", L"SetSD_UI_INIT",
                                           L"SetSD_DOKANY_STATE", L"SetSD_ELC_STATE", L"SetSD_ELC_WRITE" };
    int cost = seq_of(db, L"InstallExecuteSequence", L"CostInitialize");
    int prev = -1;
    ok = 1;
    for (i = 0; i < sizeof(ui_order) / sizeof(ui_order[0]); i++) {
      int s = seq_of(db, L"InstallUISequence", ui_order[i]);
      if (s <= prev) {
        printf("     InstallUISequence %ls out of order (%d)\n", ui_order[i], s);
        ok = 0;
      }
      prev = s;
    }
    prev = -1;
    for (i = 0; i < sizeof(exec_order) / sizeof(exec_order[0]); i++) {
      int s = seq_of(db, L"InstallExecuteSequence", exec_order[i]);
      if (s <= prev || s >= cost) {
        printf("     InstallExecuteSequence %ls out of order (%d, costing %d)\n", exec_order[i], s, cost);
        ok = 0;
      }
      prev = s;
    }
    check(ok, "options: registry read, init, then effective state, before CostInitialize (04 §8.7)");
  }

  /* ProgramData before any write (TM-R34, TM-R35): the programdata-secure hook runs before InstallFiles, from the Binary
     table (the installed copy does not exist yet), and MoveFiles, which writes profiles, runs after it. */
  {
    int cs = seq_of(db, L"InstallExecuteSequence", L"CA_ProgramDataSecure");
    int inst = seq_of(db, L"InstallExecuteSequence", L"InstallFiles");
    int mf = seq_of(db, L"InstallExecuteSequence", L"MoveFiles");
    int found = 0;
    int type = ca_type(db, L"CA_ProgramDataSecure", &found);
    check(found && cs > 0 && inst > 0 && cs < inst && cs < mf,
          "programdata-secure hook is scheduled before MoveFiles and InstallFiles (TM-R34, 04 §8.3)");
    check(query_first(db, L"SELECT `Source` FROM `CustomAction` WHERE `Action` = 'CA_ProgramDataSecure'"
                          L" AND `Source` = 'BIN_ShellDriveHost'", buf, 2048) && (type & CA_TYPE_DEFERRED),
          "programdata-secure hook runs from the Binary table (BinaryKey), deferred");
    check(query_first(db, L"SELECT `Name` FROM `Binary` WHERE `Name` = 'BIN_ShellDriveHost'", buf, 2048),
          "Binary table holds shelldrive-host.exe for the hook");
    check(mf > 0 && cs < mf, "MoveFiles (DEFAULTPROFILES) after the ProgramData check");
  }

  /* DEFAULTPROFILES (C9, 04 §8.4): the native MoveFile row copies *.ini from the property folder into the profiles folder,
     and its component exists with the Core feature. */
  check(count_rows(db, L"SELECT `FileKey` FROM `MoveFile` WHERE `FileKey` = 'SD_MF_DEFAULTPROFILES'"
                       L" AND `SourceFolder` = 'DEFAULTPROFILES' AND `SourceName` = '*.ini'"
                       L" AND `DestFolder` = 'SD_CAD_PROFILES' AND `Options` = 0 AND `Component_` = 'C_DefaultProfiles'") == 1,
        "DEFAULTPROFILES: MoveFile row copies *.ini from the property into the profiles folder (04 §8.4)");
  check(count_rows(db, L"SELECT `Component` FROM `Component` WHERE `Component` = 'C_DefaultProfiles'") == 1,
        "DEFAULTPROFILES: component C_DefaultProfiles present");

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

/* PE machine type of the image at path (IMAGE_FILE_MACHINE_I386 0x014c, AMD64 0x8664); 0 when it is not a PE image. */
static WORD pe_machine(const wchar_t *path)
{
  HANDLE h;
  BYTE hdr[8];
  DWORD got = 0, lfanew = 0;
  WORD machine = 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (ReadFile(h, hdr, 2, &got, NULL) && got == 2 && hdr[0] == 'M' && hdr[1] == 'Z' &&
      SetFilePointer(h, 0x3C, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
      ReadFile(h, &lfanew, 4, &got, NULL) && got == 4 &&
      SetFilePointer(h, (LONG)lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
      ReadFile(h, hdr, 6, &got, NULL) && got == 6 && hdr[0] == 'P' && hdr[1] == 'E' && hdr[2] == 0 && hdr[3] == 0)
    machine = (WORD)(hdr[4] | (hdr[5] << 8));
  CloseHandle(h);
  return machine;
}

/* True when a PE image of the given machine type has a full path that ends with suffix (case-insensitive), searched
   recursively under dir. */
static int find_pe_suffix(const wchar_t *dir, const wchar_t *suffix, WORD machine)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  size_t plen, slen = wcslen(suffix);
  int found = 0;
  swprintf_s(pattern, MAX_PATH, L"%ls\\*", dir);
  h = FindFirstFileW(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    swprintf_s(path, MAX_PATH, L"%ls\\%ls", dir, fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      found = find_pe_suffix(path, suffix, machine);
    } else {
      plen = wcslen(path);
      found = plen >= slen && _wcsicmp(path + plen - slen, suffix) == 0 && pe_machine(path) == machine;
    }
  } while (!found && FindNextFileW(h, &fd));
  FindClose(h);
  return found;
}

/* PE machine of a Template platform prefix: i386, AMD64, ARM64, ARMNT (Thumb-2); 0 for an unknown prefix. */
static WORD platform_machine(const wchar_t *platform)
{
  if (wcscmp(platform, L"Intel") == 0)
    return 0x014c;
  if (wcscmp(platform, L"x64") == 0)
    return 0x8664;
  if (wcscmp(platform, L"Arm64") == 0)
    return 0xAA64;
  if (wcscmp(platform, L"Arm") == 0)
    return 0x01C4;
  return 0;
}

static int run_admin(const wchar_t *msi_in, const wchar_t *work_in, const wchar_t *platform, int shellext32, int ui)
{
  wchar_t msi[MAX_PATH], work[MAX_PATH], target[MAX_PATH], copy[MAX_PATH], cmd[2048];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 1;
  const wchar_t *files[] = { L"shelldrive.exe", L"shelldrive-host.exe", L"shelldrive-ui.exe",
                             L"shelldrive-shellext.dll" };
  const unsigned nfiles = ui ? 4 : 2; /* ARM32: the CLI and the host only (04 §5.1) */
  WORD machine = platform_machine(platform);
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
    if (find_file(target, files[i]) != (i < nfiles)) {
      printf("     %ls %s\n", files[i], i < nfiles ? "not copied" : "present in a package without it");
      ok = 0;
    }
  }
  check(ok, "admin install: the binaries of the flavour are laid out");
  {
    int native = machine != 0 && find_pe_suffix(target, L"\\LibreStatic\\ShellDrive\\shelldrive.exe", machine);
    check(native, "admin install: shelldrive.exe is built for the package platform");
    ok = ok && native;
  }
  if (shellext32) {
    /* msiexec /a lays the folders out below TARGETDIR without their root, so Program Files and Program Files (x86)
       both become LibreStatic\ShellDrive here and the 32-bit copy is not visible. The native copy is checked by its PE
       machine type; the 32-bit copy is checked by its File, Component and Directory rows in the tables check. */
    int native = find_pe_suffix(target, L"\\LibreStatic\\ShellDrive\\shelldrive-shellext.dll", machine);
    check(native, "admin install: the native shell extension is laid out (04 §8.3)");
    ok = ok && native;
  }
  return ok && code == 0;
}

int wmain(int argc, wchar_t **argv)
{
  int ok;
  if (argc == 10 && wcscmp(argv[1], L"tables") == 0) {
    ok = run_tables(argv[2], argv[3], argv[4], argv[5], _wtoi(argv[6]), _wtoi(argv[7]), _wtoi(argv[8]),
                    _wtoi(argv[9]) == 1);
  } else if (argc == 7 && wcscmp(argv[1], L"admin") == 0) {
    ok = run_admin(argv[2], argv[3], argv[4], _wtoi(argv[5]) == 1, _wtoi(argv[6]) == 1);
  } else {
    fprintf(stderr, "usage: sd-test-msi tables <msi> <version> <upgrade-code> <platform> <installer-version> <launch-count> <shellext32> <ui>\n"
                    "       sd-test-msi admin <msi> <work-dir> <platform> <shellext32> <ui>\n");
    return 2;
  }
  printf("%s\n", ok ? "PASS" : "FAILED");
  return ok ? 0 : 1;
}
