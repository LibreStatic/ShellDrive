/* sd-msiembed: embeds language transforms into an MSI through msi.dll (docs/design/04 §8.6, C43).
 *
 *   sd-msiembed --db <package.msi> --mst <transform.mst> --lcid <n> [--lcid <n> ...]
 *       Stores the transform as the substorage "<n>" of the package for every LCID given (the same
 *       transform under each LCID of its language, C43) and adds the LCIDs to the Template summary property
 *       ("Intel;1033" becomes "Intel;1033,3082,11274,..."). The package is opened in transaction mode and
 *       committed only when every change succeeded.
 *   sd-msiembed --list <package.msi>
 *       Prints the substorage names (_Storages table), one per line.
 *
 * Substorage names are the bare LCID; TRANSFORMS=:<lcid> selects them (wisubstg.vbs of the Windows SDK uses
 * the same naming). Build-time tool, never shipped.
 */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PID_TEMPLATE_PROP 7 /* PIDSI_TEMPLATE */

static int fail(const char *what, UINT rc)
{
  fprintf(stderr, "sd-msiembed: %s failed (%u)\n", what, (unsigned)rc);
  return 1;
}

static int list_storages(const wchar_t *db)
{
  MSIHANDLE h = 0, view = 0, rec = 0;
  UINT rc = MsiOpenDatabaseW(db, (LPCWSTR)MSIDBOPEN_READONLY, &h);
  if (rc != ERROR_SUCCESS)
    return fail("open", rc);
  rc = MsiDatabaseOpenViewW(h, L"SELECT `Name` FROM `_Storages`", &view);
  if (rc == ERROR_SUCCESS)
    rc = MsiViewExecute(view, 0);
  if (rc != ERROR_SUCCESS) {
    MsiCloseHandle(h);
    return fail("query _Storages", rc);
  }
  while (MsiViewFetch(view, &rec) == ERROR_SUCCESS) {
    wchar_t name[256];
    DWORD cch = 256;
    if (MsiRecordGetStringW(rec, 1, name, &cch) == ERROR_SUCCESS)
      wprintf(L"%ls\n", name);
    MsiCloseHandle(rec);
    rec = 0;
  }
  MsiCloseHandle(view);
  MsiCloseHandle(h);
  return 0;
}

/* Adds lcid to the comma list after the ';' of the Template value unless it is already listed. */
static void template_add(wchar_t *tmpl, size_t cap, const wchar_t *lcid)
{
  wchar_t *semi = wcschr(tmpl, L';');
  wchar_t wrapped[1024], token[40];
  wchar_t *list;
  if (!semi)
    return;
  list = semi + 1;
  swprintf_s(wrapped, 1024, L",%ls,", list);
  swprintf_s(token, 40, L",%ls,", lcid);
  if (wcsstr(wrapped, token))
    return;
  if (*list)
    wcscat_s(tmpl, cap, L",");
  wcscat_s(tmpl, cap, lcid);
}

#define STEP(what, expr)                                                  \
  do {                                                                    \
    rc = (expr);                                                          \
    if (rc != ERROR_SUCCESS) {                                            \
      fprintf(stderr, "sd-msiembed: %s failed (%u)\n", (what), (unsigned)rc); \
      goto fail;                                                          \
    }                                                                     \
  } while (0)

static int embed(const wchar_t *db, const wchar_t *mst, const wchar_t **lcids, int nlcids)
{
  MSIHANDLE h = 0, view = 0, sum = 0;
  UINT rc = ERROR_SUCCESS;
  int i;
  wchar_t tmpl[1024];
  DWORD tmpl_cch = 1024;
  UINT type = 0;
  INT ival = 0;
  FILETIME ft;

  STEP("open database (transaction)", MsiOpenDatabaseW(db, (LPCWSTR)MSIDBOPEN_TRANSACT, &h));
  STEP("open _Storages view", MsiDatabaseOpenViewW(h, L"SELECT `Name`, `Data` FROM `_Storages`", &view));

  for (i = 0; i < nlcids; i++) {
    MSIHANDLE rec = MsiCreateRecord(2);
    if (!rec) {
      rc = ERROR_OUTOFMEMORY;
      goto fail;
    }
    STEP("name of the substorage", MsiRecordSetStringW(rec, 1, lcids[i]));
    STEP("transform stream", MsiRecordSetStreamW(rec, 2, mst));
    STEP("execute _Storages view", MsiViewExecute(view, rec));
    STEP("store substorage", MsiViewModify(view, MSIMODIFY_ASSIGN, rec));
    MsiCloseHandle(rec);
    rec = 0;
  }
  MsiCloseHandle(view);
  view = 0;

  /* Template: keep the platform prefix, add the LCIDs. */
  STEP("summary information", MsiGetSummaryInformationW(h, NULL, 20, &sum));
  STEP("read Template", MsiSummaryInfoGetPropertyW(sum, PID_TEMPLATE_PROP, &type, &ival, &ft, tmpl, &tmpl_cch));
  for (i = 0; i < nlcids; i++)
    template_add(tmpl, 1024, lcids[i]);
  STEP("set Template", MsiSummaryInfoSetPropertyW(sum, PID_TEMPLATE_PROP, 30 /* VT_LPSTR */, 0, NULL, tmpl));
  STEP("persist summary", MsiSummaryInfoPersist(sum));
  MsiCloseHandle(sum);
  sum = 0;

  STEP("commit", MsiDatabaseCommit(h));
  MsiCloseHandle(h);
  return 0;

fail:
  if (sum)
    MsiCloseHandle(sum);
  if (view)
    MsiCloseHandle(view);
  if (h)
    MsiCloseHandle(h);
  return 1;
}

int wmain(int argc, wchar_t **argv)
{
  const wchar_t *db = NULL, *mst = NULL;
  const wchar_t *lcids[64];
  int nlcids = 0, i;

  if (argc >= 3 && wcscmp(argv[1], L"--list") == 0)
    return list_storages(argv[2]);

  for (i = 1; i + 1 < argc; i++) {
    if (wcscmp(argv[i], L"--db") == 0) {
      db = argv[++i];
    } else if (wcscmp(argv[i], L"--mst") == 0) {
      mst = argv[++i];
    } else if (wcscmp(argv[i], L"--lcid") == 0) {
      if (nlcids == 64) {
        fprintf(stderr, "sd-msiembed: too many LCIDs\n");
        return 2;
      }
      lcids[nlcids++] = argv[++i];
    } else {
      fprintf(stderr, "sd-msiembed: unknown option\n");
      return 2;
    }
  }
  if (!db || !mst || nlcids == 0) {
    fprintf(stderr, "usage: sd-msiembed --db <msi> --mst <mst> --lcid <n> [--lcid <n> ...]\n"
                    "       sd-msiembed --list <msi>\n");
    return 2;
  }
  return embed(db, mst, lcids, nlcids);
}
