/* The machine data folder repair (apps/shelldrive-host/svc_repair.c, shelldrive service repair-data; 3.2, TM-R34).
 *
 * Every test runs on a fresh folder under %TEMP% that the test creates and removes. Nothing here touches the real
 * %ProgramData%, needs elevation, or creates a service. The owner rule is replaced by a seam (trust every owner, or
 * none); the shipping rule (SYSTEM and Administrators only) is checked on its own with well-known SIDs. Links are made
 * with FSCTL_SET_REPARSE_POINT (mount points need no privilege); a link always points at a sentinel folder inside the
 * test folder, and the tests check that the sentinel is never touched. */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <strsafe.h>
#include <string.h>

#include "sd_test.h"
#include "svc_folder.h"
#include "svc_repair.h"

#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT 0x000900A4u
#endif
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003u
#endif

#define T_COUNT(a) (sizeof(a) / sizeof((a)[0]))

typedef struct t_reparse_header {
  DWORD tag;
  WORD data_len;
  WORD reserved;
  WORD sub_off;
  WORD sub_len;
  WORD print_off;
  WORD print_len;
  wchar_t path[MAX_PATH * 2];
} t_reparse_header;

/* ---- seam owners ---- */

static int owner_any(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 1;
}

static int owner_none(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 0;
}

/* The owner of the test folders is this (non-elevated) process, so each DACL gets the owner rights as an extra ACE:
   the tree can then be built and removed, the way BUILTIN\Administrators can in the shipping build. */
static void ops_for(svc_repair_ops *o, int trust)
{
  o->ctx = NULL;
  o->owner_trusted = trust ? owner_any : owner_none;
  o->extra_ace = L"(A;OICI;FA;;;OW)";
}

/* ---- temp folders ---- */

static void join(wchar_t *out, size_t cch, const wchar_t *a, const wchar_t *b)
{
  StringCchPrintfW(out, cch, L"%s\\%s", a, b);
}

static int dir_exists(const wchar_t *path)
{
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static int path_exists(const wchar_t *path)
{
  return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static int is_link(const wchar_t *path)
{
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

/* Creates <TEMP>\sd-repair-<pid>-<qpc>-<n> and returns 1 on success. */
static int make_base(wchar_t *base, size_t cch, const wchar_t *name)
{
  wchar_t tmp[MAX_PATH];
  LARGE_INTEGER qpc;
  if (GetTempPathW(MAX_PATH, tmp) == 0)
    return 0;
  QueryPerformanceCounter(&qpc);
  StringCchPrintfW(base, cch, L"%ssd-repair-%lu-%lu-%s", tmp, (unsigned long)GetCurrentProcessId(),
                   (unsigned long)qpc.LowPart, name);
  return CreateDirectoryW(base, NULL) ? 1 : 0;
}

/* Removes a tree without following links: a link is removed itself, never its target. */
static void remove_tree(const wchar_t *dir)
{
  WIN32_FIND_DATAW fd;
  HANDLE fh;
  wchar_t pattern[MAX_PATH], child[MAX_PATH];
  StringCchPrintfW(pattern, T_COUNT(pattern), L"%s\\*", dir);
  fh = FindFirstFileW(pattern, &fd);
  if (fh != INVALID_HANDLE_VALUE) {
    do {
      if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0)
        continue;
      StringCchPrintfW(child, T_COUNT(child), L"%s\\%s", dir, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
          if (!RemoveDirectoryW(child))
            DeleteFileW(child);
        } else {
          remove_tree(child);
        }
      } else {
        DeleteFileW(child);
      }
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
  }
  RemoveDirectoryW(dir);
}

/* Makes a mount point at link pointing at target (an existing folder). 1 on success. */
static int make_junction(const wchar_t *link, const wchar_t *target)
{
  t_reparse_header h;
  wchar_t sub[MAX_PATH * 2];
  HANDLE hd;
  DWORD ret = 0, sub_bytes, print_bytes, data_len;
  if (!CreateDirectoryW(link, NULL))
    return 0;
  StringCchPrintfW(sub, T_COUNT(sub), L"\\??\\%s", target);
  memset(&h, 0, sizeof(h));
  sub_bytes = (DWORD)(lstrlenW(sub) * sizeof(wchar_t));
  print_bytes = (DWORD)(lstrlenW(target) * sizeof(wchar_t));
  h.tag = IO_REPARSE_TAG_MOUNT_POINT;
  h.sub_off = 0;
  h.sub_len = (WORD)sub_bytes;
  h.print_off = (WORD)(sub_bytes + sizeof(wchar_t));
  h.print_len = (WORD)print_bytes;
  StringCchCopyW(h.path, T_COUNT(h.path), sub);
  StringCchCopyW(h.path + lstrlenW(sub) + 1, T_COUNT(h.path) - lstrlenW(sub) - 1, target);
  data_len = 8 + sub_bytes + sizeof(wchar_t) + print_bytes + sizeof(wchar_t);
  h.data_len = (WORD)(data_len);
  hd = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hd == INVALID_HANDLE_VALUE)
    return 0;
  /* the buffer is the 8-byte header (tag, length, reserved) plus the mount point data */
  if (!DeviceIoControl(hd, FSCTL_SET_REPARSE_POINT, &h, 8 + data_len, NULL, 0, &ret, NULL)) {
    CloseHandle(hd);
    return 0;
  }
  CloseHandle(hd);
  return 1;
}

/* Reads the DACL of a folder back as SDDL (the text, for a substring check). */
static int dacl_text(const wchar_t *path, wchar_t *out, size_t cch)
{
  PSECURITY_DESCRIPTOR sd = NULL;
  wchar_t *text = NULL;
  int ok = 0;
  if (GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd) !=
      ERROR_SUCCESS)
    return 0;
  if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text,
                                                           NULL)) {
    StringCchCopyW(out, cch, text);
    LocalFree(text);
    ok = 1;
  }
  LocalFree(sd);
  return ok;
}

static int contains(const wchar_t *hay, const wchar_t *needle)
{
  size_t i, n = lstrlenW(hay), m = lstrlenW(needle);
  for (i = 0; i + m <= n; i++) {
    if (memcmp(hay + i, needle, m * sizeof(wchar_t)) == 0)
      return 1;
  }
  return 0;
}

/* Writes a small file (creates or replaces it). */
static int write_file(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD n = 0;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  WriteFile(h, text, (DWORD)strlen(text), &n, NULL);
  CloseHandle(h);
  return n == (DWORD)strlen(text);
}

/* Reads a whole small file into buf (NUL-terminated). Returns the byte count or -1. */
static int read_file(const wchar_t *path, char *buf, size_t cap)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD n = 0;
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  if (!ReadFile(h, buf, (DWORD)(cap - 1), &n, NULL))
    n = (DWORD)-1;
  CloseHandle(h);
  if (n == (DWORD)-1)
    return -1;
  buf[n] = 0;
  return (int)n;
}

/* ---- tests ---- */

SD_TEST(repair_builds_the_tree_in_an_empty_base)
{
  wchar_t base[MAX_PATH], p[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  DWORD e;
  SD_REQUIRE(make_base(base, T_COUNT(base), L"empty"));
  ops_for(&ops, 1);
  e = svc_repair_data(&ops, base, &r);
  SD_CHECK_EQ_INT((int)e, 0);
  SD_CHECK_EQ_INT(r.refused, 0);
  SD_CHECK_EQ_INT(r.moved, 0);
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive");
  SD_CHECK(dir_exists(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\logs");
  SD_CHECK(dir_exists(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles");
  SD_CHECK(dir_exists(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\service\\secrets");
  SD_CHECK(dir_exists(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\service\\keys");
  SD_CHECK(dir_exists(p));
  SD_CHECK_EQ_INT((int)r.folders, 7);       /* vendor, data, logs, profiles, service, secrets, keys */
  remove_tree(base);
}

SD_TEST(repair_keeps_a_sound_tree_and_its_stores)
{
  wchar_t base[MAX_PATH], p[MAX_PATH], dacl[512];
  svc_repair_ops ops;
  svc_repair_result r;
  char buf[64];
  SD_REQUIRE(make_base(base, T_COUNT(base), L"sound"));
  ops_for(&ops, 1);
  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles\\keep.ini");
  SD_CHECK(write_file(p, "[profile]\r\n"));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\known_hosts");
  SD_CHECK(write_file(p, "host\r\n"));

  /* a second run keeps the tree and the stores, and sets the documented DACL again */
  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  SD_CHECK_EQ_INT(r.moved, 0);
  SD_CHECK_EQ_INT(r.refused, 0);
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles\\keep.ini");
  SD_CHECK(read_file(p, buf, sizeof(buf)) > 0);
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles");
  SD_CHECK(dacl_text(p, dacl, T_COUNT(dacl)));
  SD_CHECK(contains(dacl, L"(A;OICI;FR;;;BU)"));
  remove_tree(base);
}

SD_TEST(repair_moves_a_junction_aside_and_never_follows_it)
{
  wchar_t base[MAX_PATH], p[MAX_PATH], target[MAX_PATH], aside[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  char buf[64];
  SD_REQUIRE(make_base(base, T_COUNT(base), L"junction"));
  ops_for(&ops, 1);
  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);

  /* a sentinel folder outside the tree, and a junction in place of the logs folder pointing at it */
  join(target, T_COUNT(target), base, L"sentinel");
  SD_REQUIRE(CreateDirectoryW(target, NULL));
  join(p, T_COUNT(p), target, L"precious.txt");
  SD_REQUIRE(write_file(p, "keep me"));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\logs");
  SD_REQUIRE(RemoveDirectoryW(p));
  SD_REQUIRE(make_junction(p, target));
  SD_CHECK(is_link(p));

  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  SD_CHECK_EQ_INT(r.moved, 1);
  SD_CHECK_EQ_INT(r.refused, 0);
  /* the untrusted tree moved aside, and a fresh logs folder took its place (not a link) */
  join(aside, T_COUNT(aside), base, L"LibreStatic\\ShellDrive.untrusted-1");
  SD_CHECK(lstrcmpiW(r.path, aside) == 0);
  SD_CHECK(dir_exists(aside));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\logs");
  SD_CHECK(dir_exists(p) && !is_link(p));
  /* the sentinel is untouched: the link was renamed, never followed */
  join(p, T_COUNT(p), target, L"precious.txt");
  SD_CHECK(read_file(p, buf, sizeof(buf)) == 7);
  SD_CHECK(memcmp(buf, "keep me", 7) == 0);
  remove_tree(base);
}

SD_TEST(repair_moves_a_junction_at_the_vendor_folder_aside)
{
  wchar_t base[MAX_PATH], p[MAX_PATH], target[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  char buf[64];
  SD_REQUIRE(make_base(base, T_COUNT(base), L"vendor"));
  ops_for(&ops, 1);
  join(target, T_COUNT(target), base, L"sentinel");
  SD_REQUIRE(CreateDirectoryW(target, NULL));
  join(p, T_COUNT(p), target, L"precious.txt");
  SD_REQUIRE(write_file(p, "keep me"));
  join(p, T_COUNT(p), base, L"LibreStatic");
  SD_REQUIRE(make_junction(p, target));

  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  SD_CHECK_EQ_INT(r.moved, 1);
  join(p, T_COUNT(p), base, L"LibreStatic.untrusted-1");
  SD_CHECK(is_link(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive");
  SD_CHECK(dir_exists(p) && !is_link(p));
  join(p, T_COUNT(p), target, L"precious.txt");
  SD_CHECK(read_file(p, buf, sizeof(buf)) == 7);
  remove_tree(base);
}

SD_TEST(repair_moves_an_untrusted_owner_aside_and_imports_nothing)
{
  wchar_t base[MAX_PATH], p[MAX_PATH], aside[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  char buf[64];
  SD_REQUIRE(make_base(base, T_COUNT(base), L"owner"));
  ops_for(&ops, 1);
  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles\\old.ini");
  SD_CHECK(write_file(p, "old"));

  /* no owner is trusted: the vendor folder (and with it the data folder) is untrusted */
  ops_for(&ops, 0);
  SD_CHECK_EQ_INT((int)svc_repair_data(&ops, base, &r), 0);
  SD_CHECK_EQ_INT(r.moved, 1);
  join(aside, T_COUNT(aside), base, L"LibreStatic.untrusted-1");
  SD_CHECK(lstrcmpiW(r.path, aside) == 0);
  join(p, T_COUNT(p), aside, L"ShellDrive\\profiles\\old.ini");
  SD_CHECK(read_file(p, buf, sizeof(buf)) == 3);
  /* the fresh tree does not import the old file */
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles\\old.ini");
  SD_CHECK(!path_exists(p));
  join(p, T_COUNT(p), base, L"LibreStatic\\ShellDrive\\profiles");
  SD_CHECK(dir_exists(p));
  remove_tree(base);
}

SD_TEST(repair_refuses_a_link_as_the_base)
{
  wchar_t base[MAX_PATH], link[MAX_PATH], target[MAX_PATH], p[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  DWORD e;
  SD_REQUIRE(make_base(base, T_COUNT(base), L"baselink"));
  join(target, T_COUNT(target), base, L"real");
  SD_REQUIRE(CreateDirectoryW(target, NULL));
  join(link, T_COUNT(link), base, L"link");
  SD_REQUIRE(make_junction(link, target));
  ops_for(&ops, 1);
  e = svc_repair_data(&ops, link, &r);
  SD_CHECK_EQ_INT((int)e, (int)ERROR_ACCESS_DENIED);
  SD_CHECK_EQ_INT(r.refused, 1);
  /* nothing was created behind the link */
  join(p, T_COUNT(p), target, L"LibreStatic");
  SD_CHECK(!path_exists(p));
  remove_tree(base);
}

SD_TEST(repair_reports_a_missing_base)
{
  wchar_t base[MAX_PATH], missing[MAX_PATH], p[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result r;
  DWORD e;
  SD_REQUIRE(make_base(base, T_COUNT(base), L"missing"));
  join(missing, T_COUNT(missing), base, L"not-here");
  ops_for(&ops, 1);
  e = svc_repair_data(&ops, missing, &r);
  SD_CHECK(e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND);
  SD_CHECK_EQ_INT(r.refused, 0);
  join(p, T_COUNT(p), missing, L"LibreStatic");
  SD_CHECK(!path_exists(p));
  remove_tree(base);
}

SD_TEST(repair_owner_rule_trusts_only_system_and_administrators)
{
  svc_repair_ops ops;
  BYTE sy[SECURITY_MAX_SID_SIZE], ba[SECURITY_MAX_SID_SIZE], world[SECURITY_MAX_SID_SIZE];
  DWORD n;
  svc_repair_real_ops(&ops);
  n = sizeof(sy);
  SD_REQUIRE(CreateWellKnownSid(WinLocalSystemSid, NULL, sy, &n));
  n = sizeof(ba);
  SD_REQUIRE(CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, ba, &n));
  n = sizeof(world);
  SD_REQUIRE(CreateWellKnownSid(WinWorldSid, NULL, world, &n));
  SD_CHECK(ops.owner_trusted(ops.ctx, (PSID)sy) == 1);
  SD_CHECK(ops.owner_trusted(ops.ctx, (PSID)ba) == 1);
  SD_CHECK(ops.owner_trusted(ops.ctx, (PSID)world) == 0);
}

/* The shared check (svc_folder.c, used by the service start and the repair): one reason per kind of entry. */
SD_TEST(folder_check_reports_reparse_kind_and_owner)
{
  wchar_t base[MAX_PATH], link[MAX_PATH], target[MAX_PATH], dir[MAX_PATH], file[MAX_PATH], miss[MAX_PATH];
  HANDLE h = NULL, f = NULL;
  svc_folder_reason why = SVC_FOLDER_OK;
  DWORD e;
  SD_REQUIRE(make_base(base, T_COUNT(base), L"folder"));
  join(target, T_COUNT(target), base, L"real");
  SD_REQUIRE(CreateDirectoryW(target, NULL));
  join(link, T_COUNT(link), base, L"link");
  SD_REQUIRE(make_junction(link, target));
  join(dir, T_COUNT(dir), base, L"dir");
  SD_REQUIRE(CreateDirectoryW(dir, NULL));
  join(file, T_COUNT(file), base, L"file");
  f = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  CloseHandle(f);
  join(miss, T_COUNT(miss), base, L"missing");

  /* a junction is a reparse point, whatever its owner, and it is not followed */
  SD_REQUIRE(svc_folder_open(link, READ_CONTROL | FILE_READ_ATTRIBUTES, &h) == 0);
  SD_REQUIRE(svc_folder_inspect(h, 1, owner_any, NULL, &why) == 0);
  CloseHandle(h);
  SD_CHECK(why == SVC_FOLDER_REPARSE);

  /* a file where a folder belongs */
  SD_REQUIRE(svc_folder_open(file, READ_CONTROL | FILE_READ_ATTRIBUTES, &h) == 0);
  SD_REQUIRE(svc_folder_inspect(h, 1, owner_any, NULL, &why) == 0);
  CloseHandle(h);
  SD_CHECK(why == SVC_FOLDER_KIND);

  /* a folder: the owner decides */
  SD_REQUIRE(svc_folder_open(dir, READ_CONTROL | FILE_READ_ATTRIBUTES, &h) == 0);
  SD_REQUIRE(svc_folder_inspect(h, 1, owner_none, NULL, &why) == 0);
  SD_CHECK(why == SVC_FOLDER_OWNER);
  SD_REQUIRE(svc_folder_inspect(h, 1, owner_any, NULL, &why) == 0);
  SD_CHECK(why == SVC_FOLDER_OK);
  CloseHandle(h);

  /* a store file is checked for kind and reparse point only: no owner rule */
  SD_REQUIRE(svc_folder_open(file, READ_CONTROL | FILE_READ_ATTRIBUTES, &h) == 0);
  SD_REQUIRE(svc_folder_inspect(h, 0, owner_none, NULL, &why) == 0);
  CloseHandle(h);
  SD_CHECK(why == SVC_FOLDER_OK);

  /* a missing path is reported as missing, never as trusted */
  e = svc_folder_open(miss, READ_CONTROL | FILE_READ_ATTRIBUTES, &h);
  SD_CHECK(e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND);
  SD_CHECK(h == NULL);
  SD_CHECK(lstrcmpW(svc_folder_reason_text(SVC_FOLDER_REPARSE), L"reparse_point") == 0);
  SD_CHECK(lstrcmpW(svc_folder_reason_text(SVC_FOLDER_OWNER), L"owner") == 0);
  remove_tree(base);
}
