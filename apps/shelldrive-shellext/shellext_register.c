/* Per-user registration of the context menu handler (03 §8.5): the development path and the portable
 * layout. Everything is written under HKEY_CURRENT_USER, so no administrator rights are needed. The installer
 * writes the same keys under HKLM\Software\Classes (04), which this code does not touch.
 *
 * Keys (relative to HKCU):
 *   Software\Classes\CLSID\{clsid}                          default = name
 *   Software\Classes\CLSID\{clsid}\InprocServer32           default = DLL path, ThreadingModel = Apartment
 *   Software\Classes\Drive\shellex\ContextMenuHandlers\ShellDrive   default = {clsid}
 *   Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved   value {clsid} = name
 *
 * The Approved entry is needed where EnforceShellExtensionSecurity is set. Explorer's check for the per-user
 * list is [verify on Windows 10 and 11]. Unregister removes the leaves it created and the parent keys only
 * when they are empty (RegDeleteKeyW refuses non-empty keys), so other handlers are left alone. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd/base.h"
#include "shellext_int.h"

#define SHX_KEY_CLSID       L"Software\\Classes\\CLSID\\" SHX_CLSID_TEXT
#define SHX_KEY_INPROC      SHX_KEY_CLSID L"\\InprocServer32"
#define SHX_KEY_DRIVE       L"Software\\Classes\\Drive"
#define SHX_KEY_DRIVE_SHEX  SHX_KEY_DRIVE L"\\shellex"
#define SHX_KEY_DRIVE_CMH   SHX_KEY_DRIVE_SHEX L"\\ContextMenuHandlers"
#define SHX_KEY_DRIVE_ENTRY SHX_KEY_DRIVE_CMH L"\\" SHX_HANDLER_NAME
#define SHX_KEY_APPROVED    L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"

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

HRESULT shx_register_server(void)
{
  wchar_t path[1024];
  DWORD n;
  LONG rc;

  n = GetModuleFileNameW(shx_module, path, (DWORD)SD_COUNTOF(path));
  if (n == 0 || n >= SD_COUNTOF(path))
    return E_FAIL;

  rc = sx_set_string(SHX_KEY_CLSID, NULL, SHX_DESCRIPTION);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC, NULL, path);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_INPROC, L"ThreadingModel", L"Apartment");
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_DRIVE_ENTRY, NULL, SHX_CLSID_TEXT);
  if (rc == ERROR_SUCCESS)
    rc = sx_set_string(SHX_KEY_APPROVED, SHX_CLSID_TEXT, SHX_DESCRIPTION);
  return rc == ERROR_SUCCESS ? S_OK : E_FAIL;
}

HRESULT shx_unregister_server(void)
{
  LONG rc;

  /* Our leaves: a failure here is reported. */
  rc = sx_delete_value(SHX_KEY_APPROVED, SHX_CLSID_TEXT);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_DRIVE_ENTRY);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_INPROC);
  if (rc == ERROR_SUCCESS)
    rc = sx_delete_key(SHX_KEY_CLSID);
  if (rc != ERROR_SUCCESS)
    return E_FAIL;

  /* Shared parents: removed only when empty, so other handlers stay registered. Errors are ignored. */
  (void)sx_delete_key(SHX_KEY_DRIVE_CMH);
  (void)sx_delete_key(SHX_KEY_DRIVE_SHEX);
  (void)sx_delete_key(SHX_KEY_DRIVE);
  return S_OK;
}
