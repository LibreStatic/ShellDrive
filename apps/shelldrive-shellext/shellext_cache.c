/* Loader of menu.cache for the This PC submenu (03 §8.2). The file is untrusted input: it is opened read-only,
 * must be owned by the user (or by the default owner of the user's token, which is what a file the user's agent
 * creates gets), is capped at SHX_CACHE_MAX_BYTES, and goes through the bounded parser of shellext_model.c.
 * Nothing here touches the network, the IPC pipe or a profile file. A missing or refused file is "no data". */
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "shellext_int.h"
#include "shellext_model.h"

#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif

/* 1 when the owner of the open file is the user or the default owner of the process token. */
static int cache_owner_ok(HANDLE file)
{
  PSID owner = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  HANDLE tok = NULL;
  TOKEN_USER *tu = NULL;
  TOKEN_OWNER *to = NULL;
  DWORD len = 0;
  int ok = 0;

  if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd) !=
          ERROR_SUCCESS ||
      owner == NULL)
    return 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    goto done;
  GetTokenInformation(tok, TokenUser, NULL, 0, &len);
  if (len != 0) {
    tu = (TOKEN_USER *)sd_alloc(len);
    if (tu != NULL && GetTokenInformation(tok, TokenUser, tu, len, &len) && EqualSid(owner, tu->User.Sid))
      ok = 1;
  }
  if (!ok) {
    len = 0;
    GetTokenInformation(tok, TokenOwner, NULL, 0, &len);
    if (len != 0) {
      to = (TOKEN_OWNER *)sd_alloc(len);
      if (to != NULL && GetTokenInformation(tok, TokenOwner, to, len, &len) && to->Owner != NULL &&
          EqualSid(owner, to->Owner))
        ok = 1;
    }
  }
done:
  if (tok != NULL)
    CloseHandle(tok);
  if (tu != NULL)
    sd_free(tu);
  if (to != NULL)
    sd_free(to);
  if (sd != NULL)
    LocalFree(sd);
  return ok;
}

static int cache_path(wchar_t *path, size_t cch)
{
  static const wchar_t tail[] = L"\\LibreStatic\\ShellDrive\\state\\menu.cache";
  wchar_t base[MAX_PATH];
  size_t n;

#ifdef SD_SHELLEXT_TEST
  {
    DWORD got = GetEnvironmentVariableW(L"SHELLDRIVE_TEST_MENU_CACHE", path, (DWORD)cch);
    if (got != 0)
      return got < cch;
  }
#endif
  if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0 /* SHGFP_TYPE_CURRENT */, base)))
    return 0;
  n = wcslen(base);
  if (n == 0 || n + wcslen(tail) + 1 > cch)
    return 0;
  memcpy(path, base, n * sizeof(wchar_t));
  memcpy(path + n, tail, (wcslen(tail) + 1) * sizeof(wchar_t));
  return 1;
}

size_t shx_menucache_load(shx_profile *out, size_t max)
{
  wchar_t path[MAX_PATH + 64];
  HANDLE h;
  LARGE_INTEGER size;
  unsigned char *buf;
  DWORD got = 0;
  size_t count = 0;

  if (out == NULL || max == 0 || !cache_path(path, SD_COUNTOF(path)))
    return 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (GetFileType(h) != FILE_TYPE_DISK || !GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
      size.QuadPart > (LONGLONG)SHX_CACHE_MAX_BYTES || !cache_owner_ok(h)) {
    CloseHandle(h);
    return 0;
  }
  buf = (unsigned char *)sd_alloc((size_t)size.QuadPart);
  if (buf != NULL && ReadFile(h, buf, (DWORD)size.QuadPart, &got, NULL) && got == (DWORD)size.QuadPart)
    count = shx_menucache_parse(buf, got, out, max);
  if (buf != NULL)
    sd_free(buf);
  CloseHandle(h);
  return count;
}
