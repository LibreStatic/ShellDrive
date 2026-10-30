/* Key file trust (2.6 rule 1, TM-R27) and the start re-apply of the 3.2 machine DACL (svc_folder.c): the checks that the
 * service runs on identity files before it hands their bytes to sd_mount.
 *
 * Every test works in a fresh folder under %TEMP% named with the process id and a QueryPerformanceCounter value, and
 * removes it again when the test ends (the wrapper runs the removal even when a check fails). Nothing here touches the
 * real %ProgramData%, the registry, the Event Log or the SCM, and nothing needs elevation. Links: a junction is made with
 * FSCTL_SET_REPARSE_POINT (no privilege); a file symbolic link needs SeCreateSymbolicLinkPrivilege, so when the process
 * cannot make one the test uses a user-defined reparse tag on a plain file instead (the same refusal path). Owners are
 * replaced by the seam (trust every owner, or none): the test process owns what it creates, so the trusted owner is
 * the test user, and the DACLs name OWNER RIGHTS (S-1-3-4) for it, as svc_repair's tests do. */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <strsafe.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"
#include "svc_folder.h"

#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT 0x000900A4u
#endif
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003u
#endif

#define T_COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* Reparse buffer of a mount point (junction), as svc_repair's tests build it. */
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

typedef BOOLEAN (WINAPI *t_pfn_create_symlink)(LPCWSTR link, LPCWSTR target, DWORD flags);

/* ---- folders ---- */

typedef struct t_root {
  wchar_t dir[MAX_PATH];     /* the unique test folder */
  wchar_t service[MAX_PATH]; /* <dir>\service: the machine service folder the paths are checked under */
  wchar_t sentinel[MAX_PATH];/* <dir>\sentinel: a link target outside the service folder */
} t_root;

static int t_root_make(t_root *r)
{
  wchar_t tmp[MAX_PATH];
  LARGE_INTEGER qpc;
  if (GetTempPathW(MAX_PATH, tmp) == 0)
    return 0;
  QueryPerformanceCounter(&qpc);
  StringCchPrintfW(r->dir, MAX_PATH, L"%ssdident-%lu-%lu", tmp, (unsigned long)GetCurrentProcessId(),
                   (unsigned long)qpc.LowPart);
  StringCchPrintfW(r->service, MAX_PATH, L"%s\\service", r->dir);
  StringCchPrintfW(r->sentinel, MAX_PATH, L"%s\\sentinel", r->dir);
  if (!CreateDirectoryW(r->dir, NULL))
    return 0;
  return CreateDirectoryW(r->service, NULL) && CreateDirectoryW(r->sentinel, NULL);
}

/* Removes a folder tree. Links are removed, never followed: a junction is removed as a folder, a file link or a
   reparse-tagged file as a file. */
static void t_tree_remove(const wchar_t *dir)
{
  WIN32_FIND_DATAW fd;
  wchar_t pat[MAX_PATH];
  HANDLE fh;
  StringCchPrintfW(pat, MAX_PATH, L"%s\\*", dir);
  fh = FindFirstFileW(pat, &fd);
  if (fh != INVALID_HANDLE_VALUE) {
    do {
      wchar_t child[MAX_PATH];
      int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0)
        continue;
      StringCchPrintfW(child, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !is_dir) {
        if (is_dir)
          RemoveDirectoryW(child);
        else
          DeleteFileW(child);
      } else {
        t_tree_remove(child);
      }
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
  }
  RemoveDirectoryW(dir);
}

static void t_root_remove(t_root *r)
{
  t_tree_remove(r->dir);
}

/* A mount point at link pointing at target (an existing folder). 1 on success. */
static int t_make_junction(const wchar_t *link, const wchar_t *target)
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
  h.data_len = (WORD)data_len;
  hd = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hd == INVALID_HANDLE_VALUE)
    return 0;
  if (!DeviceIoControl(hd, FSCTL_SET_REPARSE_POINT, &h, 8 + data_len, NULL, 0, &ret, NULL)) {
    CloseHandle(hd);
    return 0;
  }
  CloseHandle(hd);
  return 1;
}

/* ---- files ---- */

/* Creates a folder with the DACL of sddl. 1 on success. */
static int t_make_dir(const wchar_t *path, const wchar_t *sddl)
{
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd = NULL;
  int ok;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return 0;
  sa.lpSecurityDescriptor = sd;
  ok = CreateDirectoryW(path, &sa) ? 1 : 0;
  LocalFree(sd);
  return ok;
}

/* Creates a file with the DACL of sddl (NULL = inherited) and writes n bytes. 1 on success. */
static int t_make_file(const wchar_t *path, const wchar_t *sddl, const char *data, DWORD n)
{
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd = NULL;
  HANDLE h;
  DWORD w = 0;
  int ok = 0;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  if (sddl != NULL) {
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
      return 0;
    sa.lpSecurityDescriptor = sd;
  }
  h = CreateFileW(path, GENERIC_WRITE, 0, sddl != NULL ? &sa : NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    ok = WriteFile(h, data, n, &w, NULL) && w == n;
    CloseHandle(h);
  }
  if (sd != NULL)
    LocalFree(sd);
  return ok;
}

/* A file with a user-defined reparse tag (bit 31 set, so no Microsoft driver claims it): a link for the refusal
   path when the process cannot create a symbolic link. 1 on success. */
static int t_make_tagged_file(const wchar_t *path)
{
  HANDLE h;
  DWORD ret = 0;
  struct {
    DWORD tag;
    WORD len;
    WORD reserved;
    BYTE data[8];
  } rp;
  if (!t_make_file(path, NULL, "tagged", 6))
    return 0;
  memset(&rp, 0, sizeof(rp));
  rp.tag = 0x80000042u;
  rp.len = 8;
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &rp, sizeof(rp), NULL, 0, &ret, NULL)) {
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  return 1;
}

/* ---- seams ---- */

static int trust_all(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 1;
}

static int trust_none(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 0;
}

/* DACL of a key file the service accepts: the owner, SYSTEM and Administrators full control, Users read only. */
static const wchar_t k_file_good[] = L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
/* the same with Everyone able to write: a user-writable key file */
static const wchar_t k_file_user_write[] = L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)";

/* ---- cases (each runs under a fresh root; the wrapper removes it) ---- */

static void case_junction_refused(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t keys[MAX_PATH], path[MAX_PATH], target[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_OK;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  StringCchPrintfW(keys, MAX_PATH, L"%s\\keys", r->service);
  StringCchPrintfW(path, MAX_PATH, L"%s\\k.ppk", keys);
  StringCchPrintfW(target, MAX_PATH, L"%s\\k.ppk", r->sentinel);
  SD_REQUIRE(t_make_file(target, NULL, "outside", 7));
  /* the folder of the key is a junction to the sentinel: the key is never read through it */
  SD_REQUIRE(t_make_junction(keys, r->sentinel));
  StringCchPrintfW(path, MAX_PATH, L"%s\\keys\\k.ppk", r->service);
  e = svc_file_read_trusted(r->service, path, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_REPARSE);
  SD_CHECK(data == NULL);
  SD_CHECK_EQ_INT(len, 0);
}

static void case_symlink_refused(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t link[MAX_PATH], target[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_OK;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  t_pfn_create_symlink create_link;
  BOOLEAN made = FALSE;
  create_link = (t_pfn_create_symlink)sd_platform_resolve_by_name(L"kernel32.dll", "CreateSymbolicLinkW");
  StringCchPrintfW(link, MAX_PATH, L"%s\\link.ppk", r->service);
  StringCchPrintfW(target, MAX_PATH, L"%s\\k.ppk", r->sentinel);
  SD_REQUIRE(t_make_file(target, NULL, "outside", 7));
  if (create_link != NULL)
    made = create_link(link, target, 0);
  if (!made) {
    /* no privilege for a symbolic link: the same refusal on a file with another reparse tag */
    StringCchPrintfW(link, MAX_PATH, L"%s\\tagged.ppk", r->service);
    SD_REQUIRE(t_make_tagged_file(link));
  }
  e = svc_file_read_trusted(r->service, link, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_REPARSE);
  SD_CHECK(data == NULL);
}

static void case_foreign_owner_refused(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t path[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_OK;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  StringCchPrintfW(path, MAX_PATH, L"%s\\k.ppk", r->service);
  SD_REQUIRE(t_make_file(path, k_file_good, "key-material", 12));
  e = svc_file_read_trusted(r->service, path, trust_none, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_OWNER);
  SD_CHECK(data == NULL);
}

static void case_user_writable_refused(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t path[MAX_PATH], keys[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_OK;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  /* the key file: Everyone may write it */
  StringCchPrintfW(path, MAX_PATH, L"%s\\u.ppk", r->service);
  SD_REQUIRE(t_make_file(path, k_file_user_write, "key-material", 12));
  e = svc_file_read_trusted(r->service, path, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_ACL);
  SD_CHECK(data == NULL);
  /* a folder on the way with the same rule: a keys folder that Everyone may write refuses every key below it */
  StringCchPrintfW(keys, MAX_PATH, L"%s\\wkeys", r->service);
  SD_REQUIRE(t_make_dir(keys, L"D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;WD)"));
  StringCchPrintfW(path, MAX_PATH, L"%s\\k.ppk", keys);
  SD_REQUIRE(t_make_file(path, k_file_good, "key-material", 12));
  e = svc_file_read_trusted(r->service, path, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_ACL);
  SD_CHECK(data == NULL);
}

static void case_good_file_read_from_the_handle(sd_test_ctx *sd_t_, t_root *r)
{
  static const char body[] = "identity-bytes-42";
  wchar_t path[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_NO_RIGHTS;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  StringCchPrintfW(path, MAX_PATH, L"%s\\good.ppk", r->service);
  SD_REQUIRE(t_make_file(path, k_file_good, body, (DWORD)(sizeof(body) - 1)));
  e = svc_file_read_trusted(r->service, path, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_OK);
  SD_REQUIRE(data != NULL);
  SD_CHECK_EQ_INT(len, sizeof(body) - 1);
  SD_CHECK(len == sizeof(body) - 1 && memcmp(data, body, len) == 0);
  sd_secure_free(data, len);
}

static void case_folder_refused_where_a_file_belongs(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t path[MAX_PATH];
  svc_folder_reason why = SVC_FOLDER_OK;
  unsigned char *data = NULL;
  DWORD len = 0;
  DWORD e;
  StringCchPrintfW(path, MAX_PATH, L"%s\\dirkey", r->service);
  SD_REQUIRE(CreateDirectoryW(path, NULL));
  e = svc_file_read_trusted(r->service, path, trust_all, NULL, &data, &len, &why);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(why, SVC_FOLDER_KIND);
  SD_CHECK(data == NULL);
}

static void case_folder_dacl_reapplied_once(sd_test_ctx *sd_t_, t_root *r)
{
  wchar_t folder[MAX_PATH];
  HANDLE h = NULL;
  int changed = 0;
  DWORD e;
  StringCchPrintfW(folder, MAX_PATH, L"%s\\machine", r->service);
  SD_REQUIRE(CreateDirectoryW(folder, NULL));
  e = svc_folder_open(folder, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, &h);
  SD_REQUIRE(e == 0);
  /* the folder inherits the test root's DACL, which is not the 3.2 one: it is set back (owner rights keep the test
     process able to remove it) */
  e = svc_folder_apply_dacl(h, L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", &changed);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(changed, 1);
  /* a second start finds the DACL right and writes nothing */
  e = svc_folder_apply_dacl(h, L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", &changed);
  SD_CHECK_EQ_INT(e, 0);
  SD_CHECK_EQ_INT(changed, 0);
  CloseHandle(h);
}

/* ---- wrappers: one fresh root per test, removed afterwards ---- */

#define T_CASE(name, body)                                                          \
  SD_TEST(name)                                                                     \
  {                                                                                 \
    t_root r;                                                                       \
    if (!t_root_make(&r)) {                                                         \
      sd_test_fail(sd_t_, __FILE__, __LINE__, "the test folder cannot be made");    \
      t_root_remove(&r);                                                            \
      return;                                                                       \
    }                                                                               \
    body(sd_t_, &r);                                                                \
    t_root_remove(&r);                                                              \
  }

T_CASE(identity_file_through_a_junction_is_refused, case_junction_refused)
T_CASE(identity_file_symlink_or_link_tag_is_refused, case_symlink_refused)
T_CASE(identity_file_with_a_foreign_owner_is_refused, case_foreign_owner_refused)
T_CASE(identity_file_with_a_user_writable_acl_is_refused, case_user_writable_refused)
T_CASE(identity_file_good_is_read_from_the_checked_handle, case_good_file_read_from_the_handle)
T_CASE(identity_path_that_is_a_folder_is_not_a_file, case_folder_refused_where_a_file_belongs)
T_CASE(machine_folder_dacl_is_reapplied_once_then_left_alone, case_folder_dacl_reapplied_once)
