/* Machine data folder repair (03 §3.2, TM-R34; 04 §6.4). See svc_repair.h.
 *
 * Rules: a folder is trusted when it is a directory, not a reparse point, and owned by a trusted SID. Each check and
 * each security change goes through one handle opened with FILE_FLAG_OPEN_REPARSE_POINT, so a link is never followed.
 * The tree below the data folder is scanned without following links: a link, a foreign-owned folder or a failed open
 * anywhere in it makes the whole tree untrusted (fail closed). Only the CLI links this file (through shelldrive.exe)
 * and the unit tests. */
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <strsafe.h>
#include <string.h>

#include "svc_repair.h"

#define REP_VENDOR L"LibreStatic"
#define REP_DATA L"ShellDrive"
#define REP_MAX_DEPTH 24
#define REP_MAX_ENTRIES 20000u
#define REP_COUNT(a) (sizeof(a) / sizeof((a)[0]))

typedef struct rep_item {
  const wchar_t *rel;
  const wchar_t *sddl;
} rep_item;

/* The 03 §3.2 DACLs. Owner is not set here: a folder gets the default owner of the creating token (Administrators
   under UAC, SYSTEM under the service), which the owner rule accepts. */
static const wchar_t *const k_admin_read = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

/* Folders below the data folder, in creation order (a parent before its children). */
static const rep_item k_dirs[] = {
  { L"logs", L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" },
  { L"profiles", L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)" },
  { L"service", L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" },
  { L"service\\secrets", L"D:PAI(A;OICI;FA;;;SY)" },
  { L"service\\keys", L"D:PAI(A;OICI;FA;;;SY)" },
};

/* Stores that exist only once the program or the installer wrote them. */
static const rep_item k_files[] = {
  { L"known_hosts", L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)" },
  { L"settings.ini", L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)" },
};

enum { REP_MISSING = 0, REP_TRUSTED, REP_UNTRUSTED };

/* ---- seam: the shipping owner rule ---- */

static int real_owner_trusted(void *ctx, PSID owner)
{
  (void)ctx;
  return IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid);
}

int svc_repair_real_ops(svc_repair_ops *out)
{
  memset(out, 0, sizeof(*out));
  out->ctx = NULL;
  out->owner_trusted = real_owner_trusted;
  out->extra_ace = NULL;
  return 0;
}

/* The DACL text this repair sets: the 03 §3.2 text, plus the seam's extra ACE when the seam has one. */
static int compose_sddl(const svc_repair_ops *ops, const wchar_t *sddl, wchar_t *out, size_t cch)
{
  if (FAILED(StringCchCopyW(out, cch, sddl)))
    return 0;
  if (ops->extra_ace != NULL && ops->extra_ace[0] != 0)
    return SUCCEEDED(StringCchCatW(out, cch, ops->extra_ace)) ? 1 : 0;
  return 1;
}

/* ---- handles (never follow a link) ---- */

static DWORD open_entry(const wchar_t *path, DWORD access, HANDLE *h)
{
  *h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (*h == INVALID_HANDLE_VALUE) {
    *h = NULL;
    return GetLastError();
  }
  return 0;
}

static int is_missing(DWORD e)
{
  return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
}

/* 1 when the owner of the open handle is trusted. Fails closed. */
static int owner_is_trusted(const svc_repair_ops *ops, HANDLE h)
{
  PSID owner = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  int r = 0;
  if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd) != ERROR_SUCCESS)
    return 0;
  r = (owner != NULL && ops->owner_trusted(ops->ctx, owner)) ? 1 : 0;
  if (sd != NULL)
    LocalFree(sd);
  return r;
}

/* Sets a protected DACL on an open handle (SetSecurityInfo on the handle, never on a path). */
static DWORD set_dacl_on(HANDLE h, const wchar_t *sddl)
{
  PSECURITY_DESCRIPTOR sd = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  DWORD e;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return GetLastError();
  if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
    e = GetLastError();
  } else if (!present || dacl == NULL) {
    e = ERROR_INVALID_DATA;
  } else {
    e = SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL,
                        NULL, dacl, NULL);
  }
  LocalFree(sd);
  return e;
}

/* Checks one entry through a single handle. want_dir = 1: a folder (owner checked too); 0: a store file. A link, a
   wrong kind or an untrusted owner is REP_UNTRUSTED. When sddl is not NULL and the entry is trusted, the DACL is set
   on that same handle. A missing entry is REP_MISSING. */
static DWORD check_entry(const svc_repair_ops *ops, const wchar_t *path, const wchar_t *sddl, int want_dir, int *state)
{
  HANDLE h = NULL;
  BY_HANDLE_FILE_INFORMATION info;
  DWORD e, access;
  int trusted;
  *state = REP_UNTRUSTED;
  access = READ_CONTROL | FILE_READ_ATTRIBUTES | (sddl != NULL ? WRITE_DAC : 0);
  e = open_entry(path, access, &h);
  if (e != 0) {
    if (is_missing(e)) {
      *state = REP_MISSING;
      return 0;
    }
    return e;
  }
  if (!GetFileInformationByHandle(h, &info)) {
    e = GetLastError();
    CloseHandle(h);
    return e;
  }
  trusted = !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
  if (want_dir != ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0))
    trusted = 0;
  if (trusted && want_dir)
    trusted = owner_is_trusted(ops, h);
  if (trusted) {
    *state = REP_TRUSTED;
    if (sddl != NULL) {
      wchar_t full[512];
      if (!compose_sddl(ops, sddl, full, REP_COUNT(full)))
        e = ERROR_BUFFER_OVERFLOW;
      else
        e = set_dacl_on(h, full);
    }
  }
  CloseHandle(h);
  return e;
}

/* Scans everything below dir without following links, read only. *clean becomes 0 at the first link, foreign-owned
   folder, entry that cannot be opened, or limit. */
static void scan_tree(const svc_repair_ops *ops, const wchar_t *dir, int depth, DWORD *count, int *clean)
{
  WIN32_FIND_DATAW fd;
  HANDLE fh;
  wchar_t pattern[MAX_PATH], child[MAX_PATH];
  if (depth > REP_MAX_DEPTH || FAILED(StringCchPrintfW(pattern, REP_COUNT(pattern), L"%s\\*", dir))) {
    *clean = 0;
    return;
  }
  fh = FindFirstFileW(pattern, &fd);
  if (fh == INVALID_HANDLE_VALUE) {
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
      *clean = 0;
    return;
  }
  do {
    int state = REP_UNTRUSTED;
    if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0)
      continue;
    if (++(*count) > REP_MAX_ENTRIES || FAILED(StringCchPrintfW(child, REP_COUNT(child), L"%s\\%s", dir, fd.cFileName))) {
      *clean = 0;
      break;
    }
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      *clean = 0;
      break;
    }
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      continue;
    if (check_entry(ops, child, NULL, 1, &state) != 0 || state != REP_TRUSTED) {
      *clean = 0;
      break;
    }
    scan_tree(ops, child, depth + 1, count, clean);
    if (!*clean)
      break;
  } while (FindNextFileW(fh, &fd));
  FindClose(fh);
}

/* Renames an untrusted entry to the first free <path>.untrusted-<n>. A link is renamed itself, never followed. */
static DWORD move_aside(const wchar_t *path, wchar_t *aside, size_t cch)
{
  unsigned n;
  for (n = 1; n < 10000u; n++) {
    if (FAILED(StringCchPrintfW(aside, cch, L"%s.untrusted-%u", path, n)))
      return ERROR_BUFFER_OVERFLOW;
    if (GetFileAttributesW(aside) == INVALID_FILE_ATTRIBUTES)
      break;
  }
  if (n >= 10000u)
    return ERROR_ALREADY_EXISTS;
  return MoveFileExW(path, aside, 0) ? 0 : GetLastError();
}

static DWORD create_folder(const svc_repair_ops *ops, const wchar_t *path, const wchar_t *sddl)
{
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd = NULL;
  wchar_t full[512];
  DWORD e = 0;
  if (!compose_sddl(ops, sddl, full, REP_COUNT(full)))
    return ERROR_BUFFER_OVERFLOW;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(full, SDDL_REVISION_1, &sd, NULL))
    return GetLastError();
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  if (!CreateDirectoryW(path, &sa))
    e = GetLastError();
  LocalFree(sd);
  return e;
}

/* Brings a top folder (vendor or data) to its DACL. An untrusted one is moved aside; then a missing one is created.
   scan = 1 also checks the tree below it first. */
static DWORD ensure_top(const svc_repair_ops *ops, const wchar_t *path, int scan, svc_repair_result *out)
{
  int state = REP_UNTRUSTED;
  DWORD e;
  wchar_t aside[MAX_PATH];
  e = check_entry(ops, path, k_admin_read, 1, &state);
  if (e != 0)
    return e;
  if (state == REP_TRUSTED && scan) {
    DWORD count = 0;
    int clean = 1;
    scan_tree(ops, path, 0, &count, &clean);
    if (!clean)
      state = REP_UNTRUSTED;
  }
  if (state == REP_UNTRUSTED) {
    e = move_aside(path, aside, MAX_PATH);
    if (e != 0)
      return e;
    out->moved = 1;
    (void)StringCchCopyW(out->path, REP_COUNT(out->path), aside);
    state = REP_MISSING;
  }
  if (state == REP_MISSING) {
    e = create_folder(ops, path, k_admin_read);
    if (e != 0)
      return e;
  }
  out->folders++;
  return 0;
}

DWORD svc_repair_data(const svc_repair_ops *ops, const wchar_t *base, svc_repair_result *out)
{
  wchar_t root[MAX_PATH], vendor[MAX_PATH], data[MAX_PATH], path[MAX_PATH];
  HANDLE h = NULL;
  BY_HANDLE_FILE_INFORMATION info;
  size_t i, n;
  DWORD e;
  int state;
  memset(out, 0, sizeof(*out));
  if (base == NULL || base[0] == 0)
    return ERROR_PATH_NOT_FOUND;
  if (FAILED(StringCchCopyW(root, REP_COUNT(root), base)))
    return ERROR_BUFFER_OVERFLOW;
  n = lstrlenW(root);
  while (n > 0 && root[n - 1] == L'\\')
    root[--n] = 0;

  /* The base folder itself (%ProgramData%) is never renamed: a link there refuses the whole repair. */
  e = open_entry(root, FILE_READ_ATTRIBUTES, &h);
  if (e != 0)
    return e;
  if (!GetFileInformationByHandle(h, &info)) {
    e = GetLastError();
    CloseHandle(h);
    return e;
  }
  CloseHandle(h);
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    out->refused = 1;
    (void)StringCchCopyW(out->path, REP_COUNT(out->path), root);
    return ERROR_ACCESS_DENIED;
  }
  if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    return ERROR_DIRECTORY;

  if (FAILED(StringCchPrintfW(vendor, REP_COUNT(vendor), L"%s\\%s", root, REP_VENDOR)) ||
      FAILED(StringCchPrintfW(data, REP_COUNT(data), L"%s\\%s", vendor, REP_DATA)))
    return ERROR_BUFFER_OVERFLOW;

  /* 1. the vendor folder (D45): its own DACL only; what else it holds belongs to other LibreStatic products. */
  e = ensure_top(ops, vendor, 0, out);
  if (e != 0)
    return e;

  /* 2. the data folder with its whole tree. If the vendor folder was just moved aside, the data folder went with it
     and is created fresh here. */
  e = ensure_top(ops, data, 1, out);
  if (e != 0)
    return e;

  /* 3. the folders below the data folder, each through its own handle. A link that appeared since the scan refuses
     the repair, and nothing below it is followed. */
  for (i = 0; i < REP_COUNT(k_dirs); i++) {
    if (FAILED(StringCchPrintfW(path, REP_COUNT(path), L"%s\\%s", data, k_dirs[i].rel)))
      return ERROR_BUFFER_OVERFLOW;
    state = REP_UNTRUSTED;
    e = check_entry(ops, path, k_dirs[i].sddl, 1, &state);
    if (e != 0)
      return e;
    if (state == REP_UNTRUSTED) {
      (void)StringCchCopyW(out->path, REP_COUNT(out->path), path);
      out->refused = 1;
      return ERROR_ACCESS_DENIED;
    }
    if (state == REP_MISSING) {
      e = create_folder(ops, path, k_dirs[i].sddl);
      if (e != 0)
        return e;
    }
    out->folders++;
  }

  /* 4. the store files that exist. */
  for (i = 0; i < REP_COUNT(k_files); i++) {
    if (FAILED(StringCchPrintfW(path, REP_COUNT(path), L"%s\\%s", data, k_files[i].rel)))
      return ERROR_BUFFER_OVERFLOW;
    state = REP_UNTRUSTED;
    e = check_entry(ops, path, k_files[i].sddl, 0, &state);
    if (e != 0)
      return e;
    if (state == REP_UNTRUSTED) {
      (void)StringCchCopyW(out->path, REP_COUNT(out->path), path);
      out->refused = 1;
      return ERROR_ACCESS_DENIED;
    }
    if (state == REP_TRUSTED)
      out->folders++;
  }
  return 0;
}
