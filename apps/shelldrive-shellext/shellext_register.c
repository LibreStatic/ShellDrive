/* Per-user registration of the context menu handler (03 §8.5): the development path and the portable
 * layout. Everything is written under HKEY_CURRENT_USER, so no administrator rights are needed. The installer
 * writes the same keys under HKLM\Software\Classes (04), which this code does not touch.
 *
 * Keys (relative to HKCU):
 *   Software\Classes\CLSID\{clsid}                          default = name (path class and This PC class)
 *   Software\Classes\CLSID\{clsid}\InprocServer32           default = DLL path, ThreadingModel = Apartment
 *   Software\Classes\{Drive,Directory,*}\shellex\ContextMenuHandlers\ShellDrive   default = {path clsid}
 *   Software\Classes\CLSID\{20D04FE0-...}\shellex\ContextMenuHandlers\ShellDrive default = {This PC clsid}
 *   Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved   value {clsid} = name (both)
 *
 * The Approved entry is needed where EnforceShellExtensionSecurity is set. Explorer's check for the per-user
 * list is [verify on Windows 10 and 11]. Unregister removes the leaves it created and the parent keys only
 * when they are empty (RegDeleteKeyW refuses non-empty keys), so other handlers are left alone. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd/base.h"
#include "shellext_int.h"

#define SHX_KEY_CLASSES     L"Software\\Classes"
#define SHX_KEY_CLSID       SHX_KEY_CLASSES L"\\CLSID\\" SHX_CLSID_TEXT
#define SHX_KEY_INPROC      SHX_KEY_CLSID L"\\InprocServer32"
#define SHX_KEY_CLSID_PC    SHX_KEY_CLASSES L"\\CLSID\\" SHX_CLSID_COMPUTER_TEXT
#define SHX_KEY_INPROC_PC   SHX_KEY_CLSID_PC L"\\InprocServer32"
#define SHX_CMH             L"\\shellex\\ContextMenuHandlers"
#define SHX_KEY_APPROVED    L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"

/* The path class is registered for Drive, Directory and * (all files); the This PC class under the Computer
   folder's CLSID (03 §8.2). */
#define SHX_KEY_PC_FOLDER   SHX_KEY_CLASSES L"\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

typedef struct shx_hook {
  const wchar_t *root;                 /* key under HKCU that owns the shellex subtree */
  const wchar_t *clsid;                /* class id text written as the handler's default value */
} shx_hook;

static const shx_hook k_hooks[] = {
  { SHX_KEY_CLASSES L"\\Drive", SHX_CLSID_TEXT },
  { SHX_KEY_CLASSES L"\\Directory", SHX_CLSID_TEXT },
  { SHX_KEY_CLASSES L"\\*", SHX_CLSID_TEXT },
  { SHX_KEY_PC_FOLDER, SHX_CLSID_COMPUTER_TEXT }
};

static LONG sx_set_string(const wchar_t *subkey, const wchar_t *value_name, const wchar_t *data)
{
  HKEY key = NULL;
  LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                            &key, NULL);
  if (rc != ERROR_SUCCESS)
    return rc;
  rc = RegSetValueExW(key, value_name, 0, REG_SZ, (const BYTE *)data, (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
  return rc;
}

static LONG sx_delete_key(const wchar_t *subkey)
{
  LONG rc = RegDeleteKeyW(HKEY_CURRENT_USER, subkey);
  if (rc == ERROR_FILE_NOT_FOUND)
    return ERROR_SUCCESS;
  return rc;
}

static LONG sx_delete_value(const wchar_t *subkey, const wchar_t *value_name)
{
  HKEY key = NULL;
  LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_SET_VALUE, &key);
  if (rc == ERROR_FILE_NOT_FOUND)
    return ERROR_SUCCESS;
  if (rc != ERROR_SUCCESS)
    return rc;
  rc = RegDeleteValueW(key, value_name);
  RegCloseKey(key);
  if (rc == ERROR_FILE_NOT_FOUND)
    return ERROR_SUCCESS;
  return rc;
}

static LONG sx_hook_key(const shx_hook *h, const wchar_t *tail, wchar_t *out, size_t cch)
{
  return _snwprintf_s(out, cch, _TRUNCATE, L"%s%s%s", h->root, SHX_CMH, tail) < 0 ? ERROR_INSUFFICIENT_BUFFER
                                                                                  : ERROR_SUCCESS;
}

HRESULT shx_register_server(void)
{
  wchar_t path[1024];
  wchar_t key[512];
  DWORD n;
  LONG rc;
  size_t i;

  n = GetModuleFileNameW(shx_module, path, (DWORD)SD_COUNTOF(path));
  if (n == 0 || n >= SD_COUNTOF(path))
    return E_FAIL;

  rc = sx_set_string(SHX_KEY_CLSID, NULL, SHX_DESCRIPTION);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC, NULL, path);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC, L"ThreadingModel", L"Apartment");
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_CLSID_PC, NULL, SHX_DESCRIPTION_COMPUTER);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC_PC, NULL, path);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC_PC, L"ThreadingModel", L"Apartment");
  for (i = 0; rc == ERROR_SUCCESS && i < SD_COUNTOF(k_hooks); i++) {
    rc = sx_hook_key(&k_hooks[i], L"\\" SHX_HANDLER_NAME, key, SD_COUNTOF(key));
    if (rc == ERROR_SUCCESS)
      rc = sx_set_string(key, NULL, k_hooks[i].clsid);
  }
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_APPROVED, SHX_CLSID_TEXT, SHX_DESCRIPTION);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_APPROVED, SHX_CLSID_COMPUTER_TEXT, SHX_DESCRIPTION_COMPUTER);
  return rc == ERROR_SUCCESS ? S_OK : E_FAIL;
}

HRESULT shx_unregister_server(void)
{
  wchar_t key[512];
  LONG rc;
  size_t i;

  /* Our leaves: a failure here is reported. */
  rc = sx_delete_value(SHX_KEY_APPROVED, SHX_CLSID_TEXT);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_value(SHX_KEY_APPROVED, SHX_CLSID_COMPUTER_TEXT);
  for (i = 0; rc == ERROR_SUCCESS && i < SD_COUNTOF(k_hooks); i++) {
    rc = sx_hook_key(&k_hooks[i], L"\\" SHX_HANDLER_NAME, key, SD_COUNTOF(key));
    if (rc == ERROR_SUCCESS)
      rc = sx_delete_key(key);
  }
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_INPROC);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_CLSID);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_INPROC_PC);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_CLSID_PC);
  if (rc != ERROR_SUCCESS)
    return E_FAIL;

  /* Shared parents: removed only when empty, so other handlers stay registered. Errors are ignored. */
  for (i = 0; i < SD_COUNTOF(k_hooks); i++) {
    if (sx_hook_key(&k_hooks[i], L"", key, SD_COUNTOF(key)) == ERROR_SUCCESS)
      (void)sx_delete_key(key);                       /* ...\ContextMenuHandlers */
    if (_snwprintf_s(key, SD_COUNTOF(key), _TRUNCATE, L"%s\\shellex", k_hooks[i].root) >= 0)
      (void)sx_delete_key(key);
    (void)sx_delete_key(k_hooks[i].root);
  }
  return S_OK;
}
