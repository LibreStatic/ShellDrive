/* Machine folder trust (03 §3.2, TM-R34). See svc_folder.h. */
#include <windows.h>
#include <aclapi.h>

#include "svc_folder.h"

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

const wchar_t *svc_folder_reason_text(svc_folder_reason why)
{
  switch (why) {
  case SVC_FOLDER_OWNER: return L"owner";
  case SVC_FOLDER_REPARSE: return L"reparse_point";
  case SVC_FOLDER_KIND: return L"not_directory";
  case SVC_FOLDER_NO_RIGHTS: return L"acl";
  default: return L"ok";
  }
}
