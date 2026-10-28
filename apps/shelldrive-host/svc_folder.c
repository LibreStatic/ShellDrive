/* Machine folder and key file trust (03 §3.2, 2.6 rule 1, TM-R27). See svc_folder.h. */
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "svc_folder.h"

/* Largest key file the service reads (identity and certificate files are a few KiB). */
#define SVC_FILE_MAX (256u * 1024u)

/* Rights that let a principal change a folder or file: write data or append, write attributes or EAs, delete, change
   the DACL or the owner, and the generic write and all bits. */
#define SVC_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | \
                          WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

int svc_folder_owner_shipping(void *ctx, PSID owner)
{
  (void)ctx;
  if (owner == NULL)
    return 0;
  return (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid)) ? 1 : 0;
}

DWORD svc_folder_open(const wchar_t *path, DWORD access, HANDLE *h)
{
  *h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (*h == INVALID_HANDLE_VALUE) {
    *h = NULL;
    return GetLastError();
  }
  return 0;
}

/* 1 when the owner of the open handle passes owner_ok. An unreadable owner is untrusted. */
static int owner_passes(svc_owner_fn owner_ok, void *ctx, HANDLE h)
{
  PSID owner = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  int r = 0;
  if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd) != ERROR_SUCCESS)
    return 0;
  r = (owner != NULL && owner_ok(ctx, owner)) ? 1 : 0;
  if (sd != NULL)
    LocalFree(sd);
  return r;
}

DWORD svc_folder_inspect(HANDLE h, int want_dir, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why)
{
  BY_HANDLE_FILE_INFORMATION info;
  *why = SVC_FOLDER_OK;
  if (!GetFileInformationByHandle(h, &info))
    return GetLastError();
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    *why = SVC_FOLDER_REPARSE;
    return 0;
  }
  if (want_dir != ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)) {
    *why = SVC_FOLDER_KIND;
    return 0;
  }
  if (want_dir && !owner_passes(owner_ok != NULL ? owner_ok : svc_folder_owner_shipping, ctx, h))
    *why = SVC_FOLDER_OWNER;
  return 0;
}

/* 1 when sid is the pseudo principal S-1-3-sub (CREATOR OWNER is S-1-3-0, OWNER RIGHTS is S-1-3-4). */
static int sid_is_creator_pseudo(PSID sid, BYTE sub)
{
  static const SID_IDENTIFIER_AUTHORITY creator = {{0, 0, 0, 0, 0, 3}};
  SID_IDENTIFIER_AUTHORITY *a;
  if (!IsValidSid(sid))
    return 0;
  a = GetSidIdentifierAuthority(sid);
  return (a != NULL && memcmp(a, &creator, sizeof(*a)) == 0 && *GetSidSubAuthorityCount(sid) == 1 &&
          *GetSidSubAuthority(sid, 0) == sub) ? 1 : 0;
}

/* The principals that may hold write rights (3.2): SYSTEM, Administrators, the owner (already trusted by the owner
   rule), CREATOR OWNER and OWNER RIGHTS (both resolve to the owner). */
static int principal_may_write(PSID sid, PSID owner)
{
  if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid))
    return 1;
  if (sid_is_creator_pseudo(sid, 0) || sid_is_creator_pseudo(sid, 4))
    return 1;
  return (owner != NULL && EqualSid(sid, owner)) ? 1 : 0;
}

/* 1 when an untrusted principal holds a write right in dacl. A NULL DACL (everyone) and an ACE type this check does not
   understand (object and callback ACEs) fail closed. Deny ACEs are not counted. */
static int dacl_untrusted_write(PACL dacl, PSID owner)
{
  ACL_SIZE_INFORMATION info;
  DWORD i;
  if (dacl == NULL)
    return 1;
  if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation))
    return 1;
  for (i = 0; i < info.AceCount; i++) {
    LPVOID p = NULL;
    ACE_HEADER *hdr;
    ACCESS_ALLOWED_ACE *a;
    if (!GetAce(dacl, i, &p) || p == NULL)
      return 1;
    hdr = (ACE_HEADER *)p;
    if (hdr->AceType == ACCESS_DENIED_ACE_TYPE)
      continue;
    if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE)
      return 1;
    a = (ACCESS_ALLOWED_ACE *)p;
    if ((a->Mask & SVC_WRITE_RIGHTS) != 0 && !principal_may_write((PSID)&a->SidStart, owner))
      return 1;
  }
  return 0;
}

/* Owner and DACL of an open file or folder, both read from the handle. Sets *why: OWNER when the owner is untrusted or
   cannot be read (fail closed), ACL when the DACL lets an untrusted principal write, OK otherwise. */
static void handle_owner_and_dacl(HANDLE h, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why)
{
  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  DWORD e = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
                            &dacl, NULL, &sd);
  *why = SVC_FOLDER_OK;
  if (e != ERROR_SUCCESS) {
    *why = SVC_FOLDER_OWNER;
  } else if (owner == NULL || !(owner_ok != NULL ? owner_ok(ctx, owner) : svc_folder_owner_shipping(ctx, owner))) {
    *why = SVC_FOLDER_OWNER;
  } else if (dacl_untrusted_write(dacl, owner)) {
    *why = SVC_FOLDER_ACL;
  }
  if (sd != NULL)
    LocalFree(sd);
}

/* 1 when the DACL want equals have, ACE by ACE in order (the inherited flag is not compared). */
static int same_dacl(PACL want, PACL have)
{
  ACL_SIZE_INFORMATION wi, hi;
  DWORD i;
  if (want == NULL || have == NULL)
    return 0;
  if (!GetAclInformation(want, &wi, sizeof(wi), AclSizeInformation) ||
      !GetAclInformation(have, &hi, sizeof(hi), AclSizeInformation))
    return 0;
  if (wi.AceCount != hi.AceCount)
    return 0;
  for (i = 0; i < wi.AceCount; i++) {
    LPVOID wp = NULL, hp = NULL;
    ACE_HEADER *wh, *hh;
    if (!GetAce(want, i, &wp) || !GetAce(have, i, &hp) || wp == NULL || hp == NULL)
      return 0;
    wh = (ACE_HEADER *)wp;
    hh = (ACE_HEADER *)hp;
    if (wh->AceType != hh->AceType)
      return 0;
    if (wh->AceType != ACCESS_ALLOWED_ACE_TYPE && wh->AceType != ACCESS_DENIED_ACE_TYPE)
      return 0;
    if ((wh->AceFlags & ~INHERITED_ACE) != (hh->AceFlags & ~INHERITED_ACE))
      return 0;
    if (((ACCESS_ALLOWED_ACE *)wp)->Mask != ((ACCESS_ALLOWED_ACE *)hp)->Mask)
      return 0;
    if (!EqualSid((PSID)&((ACCESS_ALLOWED_ACE *)wp)->SidStart, (PSID)&((ACCESS_ALLOWED_ACE *)hp)->SidStart))
      return 0;
  }
  return 1;
}

DWORD svc_folder_apply_dacl(HANDLE h, const wchar_t *sddl, int *changed)
{
  PSECURITY_DESCRIPTOR want_sd = NULL, have_sd = NULL;
  PACL want = NULL, have = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  SECURITY_DESCRIPTOR_CONTROL want_ctl = 0, have_ctl = 0;
  DWORD rev = 0, e;
  int same;
  *changed = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &want_sd, NULL))
    return GetLastError();
  if (!GetSecurityDescriptorDacl(want_sd, &present, &want, &defaulted) || !present ||
      !GetSecurityDescriptorControl(want_sd, &want_ctl, &rev)) {
    LocalFree(want_sd);
    return ERROR_INVALID_PARAMETER;
  }
  e = GetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &have, NULL, &have_sd);
  if (e != ERROR_SUCCESS) {
    LocalFree(want_sd);
    return e;
  }
  same = same_dacl(want, have) && have_sd != NULL && GetSecurityDescriptorControl(have_sd, &have_ctl, &rev) &&
         ((have_ctl & SE_DACL_PROTECTED) == (want_ctl & SE_DACL_PROTECTED));
  if (have_sd != NULL)
    LocalFree(have_sd);
  if (!same) {
    e = SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL,
                        NULL, want, NULL);
    if (e == ERROR_SUCCESS)
      *changed = 1;
  }
  LocalFree(want_sd);
  return e;
}

/* A folder between base and a key file: reparse point, kind, owner, then its DACL (the same rule as the file). */
static DWORD folder_trust(HANDLE h, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why)
{
  DWORD e = svc_folder_inspect(h, 1, owner_ok, ctx, why);
  if (e != 0 || *why != SVC_FOLDER_OK)
    return e;
  handle_owner_and_dacl(h, owner_ok, ctx, why);
  return 0;
}

DWORD svc_file_read_trusted(const wchar_t *base, const wchar_t *path, svc_owner_fn owner_ok, void *ctx,
                            unsigned char **data, DWORD *len, svc_folder_reason *why)
{
  size_t blen, plen, i;
  wchar_t prefix[MAX_PATH];
  BY_HANDLE_FILE_INFORMATION info;
  LARGE_INTEGER size;
  HANDLE h = NULL;
  unsigned char *buf;
  DWORD got = 0, total = 0, e = 0;
  *data = NULL;
  *len = 0;
  *why = SVC_FOLDER_NO_RIGHTS;
  if (base == NULL || path == NULL)
    return ERROR_INVALID_PARAMETER;
  blen = wcslen(base);
  plen = wcslen(path);
  if (blen == 0 || plen <= blen + 1 || wcsncmp(path, base, blen) != 0 || path[blen] != L'\\')
    return ERROR_INVALID_PARAMETER;
  /* every folder between base and the file, checked by handle, in order */
  for (i = blen + 1; i < plen; i++) {
    if (path[i] != L'\\')
      continue;
    if (i + 1 == plen || path[i - 1] == L'\\' || i >= MAX_PATH)
      return ERROR_INVALID_PARAMETER;
    memcpy(prefix, path, i * sizeof(wchar_t));
    prefix[i] = 0;
    e = svc_folder_open(prefix, READ_CONTROL | FILE_READ_ATTRIBUTES, &h);
    if (e != 0)
      return e;
    e = folder_trust(h, owner_ok, ctx, why);
    CloseHandle(h);
    if (e != 0 || *why != SVC_FOLDER_OK)
      return e;
  }
  /* the file: no link is followed, and the share mode gives no writers while it is read */
  /* BACKUP_SEMANTICS lets a folder open here too, so a folder where a key file belongs gets the kind refusal below
     instead of an access error (no privilege is used: the DACL still applies) */
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                  FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError();
  if (!GetFileInformationByHandle(h, &info)) {
    e = GetLastError();
    CloseHandle(h);
    return e;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    *why = SVC_FOLDER_REPARSE;
  else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    *why = SVC_FOLDER_KIND;
  else
    handle_owner_and_dacl(h, owner_ok, ctx, why);
  if (*why != SVC_FOLDER_OK) {
    CloseHandle(h);
    return 0;
  }
  if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > (LONGLONG)SVC_FILE_MAX) {
    CloseHandle(h);
    *why = SVC_FOLDER_NOT_FILE;
    return 0;
  }
  got = size.LowPart;
  buf = (unsigned char *)sd_alloc(got);
  if (buf == NULL) {
    CloseHandle(h);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  while (total < got) {
    DWORD n = 0;
    if (!ReadFile(h, buf + total, got - total, &n, NULL) || n == 0)
      break;
    total += n;
  }
  CloseHandle(h);
  if (total != got) {
    sd_secure_free(buf, got);
    *why = SVC_FOLDER_NO_RIGHTS;
    return ERROR_READ_FAULT;
  }
  *data = buf;
  *len = got;
  *why = SVC_FOLDER_OK;
  return 0;
}

const wchar_t *svc_folder_reason_text(svc_folder_reason why)
{
  switch (why) {
  case SVC_FOLDER_OWNER: return L"owner";
  case SVC_FOLDER_REPARSE: return L"reparse_point";
  case SVC_FOLDER_KIND: return L"not_directory";
  case SVC_FOLDER_NO_RIGHTS: return L"acl";
  case SVC_FOLDER_ACL: return L"acl";
  case SVC_FOLDER_NOT_FILE: return L"not_file";
  default: return L"ok";
  }
}
