/* shelldrive-setup: small helpers (run-time exports, paths, random names, tree removal). */
#include "setup_int.h"

#include <shlobj.h>
#include <wincrypt.h>
#include <string.h>

FARPROC sd_setup_proc(const wchar_t *module, const char *name)
{
  HMODULE m = GetModuleHandleW(module);
  if (m == NULL) {
    wchar_t path[MAX_PATH];
    if (sd_setup_system_path(module, path, SD_SETUP_COUNTOF(path)) == 0)
      m = LoadLibraryW(path);
  }
  if (m == NULL)
    return NULL;
  return GetProcAddress(m, name);
}

int sd_setup_system_path(const wchar_t *file, wchar_t *out, size_t cch)
{
  wchar_t dir[MAX_PATH];
  UINT n = GetSystemDirectoryW(dir, SD_SETUP_COUNTOF(dir));
  if (n == 0 || n >= SD_SETUP_COUNTOF(dir))
    return 1;
  return sd_setup_path_join(out, cch, dir, file);
}

int sd_setup_dir_with_slash(wchar_t *dst, size_t cch, const wchar_t *dir)
{
  size_t n;
  if (FAILED(StringCchCopyW(dst, cch, dir)))
    return 1;
  n = wcslen(dst);
  if (n > 0 && dst[n - 1] != L'\\') {
    if (n + 2 > cch)
      return 1;
    dst[n] = L'\\';
    dst[n + 1] = L'\0';
  }
  return 0;
}

int sd_setup_path_join(wchar_t *dst, size_t cch, const wchar_t *dir, const wchar_t *name)
{
  size_t n;
  if (sd_setup_dir_with_slash(dst, cch, dir) != 0)
    return 1;
  n = wcslen(dst);
  if (FAILED(StringCchCopyW(dst + n, cch - n, name)))
    return 1;
  return 0;
}

int sd_setup_special_folder(int csidl, wchar_t *out, size_t cch)
{
  wchar_t path[MAX_PATH];
  if (cch < MAX_PATH)
    return 1;
  if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, path)))
    return 1;
  return FAILED(StringCchCopyW(out, cch, path)) ? 1 : 0;
}

int sd_setup_random_hex(wchar_t *out, size_t cch)
{
  HCRYPTPROV prov = 0;
  unsigned char buf[16];

  memset(buf, 0, sizeof(buf));
  int i;

  if (cch < 33)
    return 1;
  if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    return 1;
  if (!CryptGenRandom(prov, sizeof(buf), buf)) {
    CryptReleaseContext(prov, 0);
    return 1;
  }
  CryptReleaseContext(prov, 0);
  for (i = 0; i < 16; i++) {
    static const wchar_t digits[] = L"0123456789abcdef";
    out[2 * i] = digits[buf[i] >> 4];
    out[2 * i + 1] = digits[buf[i] & 15];
  }
  out[32] = L'\0';
  return 0;
}

int sd_setup_temp_dir(wchar_t *out, size_t cch)
{
  DWORD n = GetTempPathW((DWORD)cch, out);
  return (n == 0 || n >= cch) ? 1 : 0;
}

static void remove_one(const wchar_t *path, unsigned *failed)
{
  if (!DeleteFileW(path)) {
    DWORD attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
      SetFileAttributesW(path, attrs & ~FILE_ATTRIBUTE_READONLY);
      if (DeleteFileW(path))
        return;
    }
    (*failed)++;
  }
}

static void remove_tree_rec(const wchar_t *dir, unsigned *failed, int depth)
{
  WIN32_FIND_DATAW fd;
  HANDLE find;
  wchar_t pattern[MAX_PATH];

  if (depth > 32) {
    (*failed)++;
    return;
  }
  if (sd_setup_path_join(pattern, MAX_PATH, dir, L"*") != 0)
    return;
  find = FindFirstFileW(pattern, &fd);
  if (find == INVALID_HANDLE_VALUE)
    return;
  do {
    wchar_t child[MAX_PATH];
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (sd_setup_path_join(child, MAX_PATH, dir, fd.cFileName) != 0) {
      (*failed)++;
      continue;
    }
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      /* Junctions and links are removed, never followed (TM-R28). */
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!RemoveDirectoryW(child))
          (*failed)++;
      } else {
        remove_one(child, failed);
      }
    } else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      remove_tree_rec(child, failed, depth + 1);
      if (!RemoveDirectoryW(child))
        (*failed)++;
    } else {
      remove_one(child, failed);
    }
  } while (FindNextFileW(find, &fd));
  FindClose(find);
}

int sd_setup_remove_tree(const wchar_t *dir, unsigned *failed)
{
  unsigned local = 0;
  DWORD attrs = GetFileAttributesW(dir);
  if (attrs == INVALID_FILE_ATTRIBUTES)
    return 0;
  if (failed == NULL)
    failed = &local;
  if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    remove_one(dir, failed);
    return 0;
  }
  remove_tree_rec(dir, failed, 0);
  if (!RemoveDirectoryW(dir) && GetLastError() != ERROR_FILE_NOT_FOUND)
    (*failed)++;
  return 0;
}

DWORD sd_setup_mkdirs(const wchar_t *dir)
{
  wchar_t path[MAX_PATH];
  size_t i, n;

  if (FAILED(StringCchCopyW(path, MAX_PATH, dir)))
    return ERROR_INVALID_PARAMETER;
  n = wcslen(path);
  while (n > 0 && path[n - 1] == L'\\') {
    path[--n] = L'\0';
  }
  for (i = 3; i < n; i++) {
    if (path[i] == L'\\') {
      path[i] = L'\0';
      if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return GetLastError();
      }
      path[i] = L'\\';
    }
  }
  if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    return GetLastError();
  return 0;
}

int sd_setup_ascii_to_wide(const char *src, wchar_t *dst, size_t cch)
{
  size_t i;
  if (src == NULL || cch == 0)
    return 1;
  for (i = 0; src[i] != '\0'; i++) {
    if (i + 1 >= cch || (unsigned char)src[i] >= 0x80)
      return 1;
    dst[i] = (wchar_t)(unsigned char)src[i];
  }
  dst[i] = L'\0';
  return 0;
}

int sd_setup_fail(sd_setup_result *r, int exit_code, sd_msg_id msg, long code)
{
  if (r != NULL) {
    r->exit_code = exit_code;
    r->msg = msg;
    r->code = code;
  }
  return exit_code;
}

void sd_setup_log_error(const char *event, const wchar_t *what, DWORD err)
{
  wchar_t line[MAX_PATH * 2];
  StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"%s (error %lu)", what ? what : L"", (unsigned long)err);
  sd_setup_log(event, line);
}
