/* Explorer data written by the agent (03 §8.3, §8.7; M3). See explorer_data.h.
 *
 * Per user, under HKCU: the drive icon of every drive this agent maps
 *   <icon key>\<Letter>\DefaultIcon = "<shelldrive-ui.exe>",-1
 * (default <icon key> = Software\Classes\Applications\Explorer.exe\Drives, 03 §8.3 [verify on 7/10/11]).
 * The letters it wrote are listed in state\explorer.ini ([icons] letters) so that a crashed agent's icons
 * are removed at the next start. An icon is removed only when its DefaultIcon still points at our binary.
 *
 * Network locations (03 §8.7): one folder per profile in the NetHood folder, with a read-only attribute,
 * desktop.ini (folder class + a [ShellDrive] profile= marker we recognize) and target.lnk. The target is
 * the placeholder folder of the profile while the drive is not mapped and the drive root while it is.
 *
 * XP-compatible: SHChangeNotify, SHGetFolderPathW, CoCreateInstance (IShellLinkW) and MoveFileExW are on
 * the XP floor (tests/os-imports/xp-sp3-x86.txt). No Vista+ API is used. */
#include <windows.h>
#define INITGUID
#include <initguid.h>
#include <objbase.h>
#include <shlguid.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#include "explorer_data.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_policy/sd_policy.h"
#include "sd_config/sd_ini.h"
#include "sd_platform/sd_log.h"
#include "sd_base/sd_buf.h"

#define EX_LOG            "explorer"
#define ICON_KEY_DEFAULT  L"Software\\Classes\\Applications\\Explorer.exe\\Drives"
#define NETHOOD_CLSID     L"{0AFACED1-E828-11D1-9187-B532F1E9575D}"
#define UI_EXE_NAME       L"shelldrive-ui.exe"
#define ICON_INDEX        1                 /* -<id> of DefaultIcon / IconResource: the UI's icon resource */
#define PROFILE_MAX       256u
#define PROFILE_NAME_CCH  128u
#define NAME_CCH          96u

typedef struct ex_profile {
  char id[33];
  char name[PROFILE_NAME_CCH];
  int network_location;
} ex_profile;

static int g_inited;
static int g_icons_on;                     /* icons and the explorer.ini list */
static int g_netloc_on;                    /* Network location folders */
static int g_test;
static wchar_t g_icon_key[256];            /* HKCU subkey of the drive icons */
static wchar_t g_nethood_test[MAX_PATH];   /* test override of the NetHood folder */
static wchar_t g_ui_path[MAX_PATH];        /* <install dir>\shelldrive-ui.exe */
static int g_active[26];                   /* drives this agent shows as present */

/* ---- small helpers ---- */

static void copy_w(wchar_t *dst, size_t cch, const wchar_t *src)
{
  wcscpy_s(dst, cch, src);
}

static int cat_w(wchar_t *dst, size_t cch, const wchar_t *src)
{
  return wcscat_s(dst, cch, src) == 0;
}

static void utf8_to_wide(const char *s, wchar_t *out, size_t cch)
{
  out[0] = 0;
  if (s == NULL || cch == 0)
    return;
  if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cch) == 0)
    out[0] = 0;
  out[cch - 1] = 0;
}

static void wide_to_ascii(const wchar_t *w, char *out, size_t cch)
{
  size_t i;
  for (i = 0; i + 1 < cch && w[i]; i++)
    out[i] = (w[i] < 0x80) ? (char)w[i] : '?';
  out[i] = 0;
}

static int valid_id(const char *id)
{
  size_t i;
  if (strlen(id) != 32)
    return 0;
  for (i = 0; i < 32; i++)
    if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
      return 0;
  return 1;
}

/* Reserved characters and control characters become '_'; trailing dots and spaces are trimmed; an empty
   result is "ShellDrive"; at most NAME_CCH - 1 units (03 §8.7). */
static void sanitize_name(const wchar_t *in, wchar_t *out, size_t cch)
{
  size_t i, n = 0;
  for (i = 0; in[i] && n + 1 < cch && n < NAME_CCH - 1; i++) {
    wchar_t c = in[i];
    if (c < 0x20 || wcschr(L"\\/:*?\"<>|", c) != NULL)
      c = L'_';
    out[n++] = c;
  }
  while (n > 0 && (out[n - 1] == L'.' || out[n - 1] == L' '))
    n--;
  if (n == 0) {
    copy_w(out, cch, L"ShellDrive");
    return;
  }
  out[n] = 0;
}

/* Local per-user root: %LOCALAPPDATA%\LibreStatic\ShellDrive (03 §3.2). Test builds with the test
   variables use the test configuration root instead. */
static int local_root(wchar_t *out, size_t cch)
{
#ifdef SD_HOST_TEST_HOOKS
  if (g_test)
    return sd_config_root(out, cch) == SD_OK;
#endif
  if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, out) != S_OK)
    return 0;
  return cat_w(out, cch, L"\\LibreStatic\\ShellDrive");
}

static int mkdirs(const wchar_t *path)
{
  wchar_t buf[MAX_PATH];
  size_t i;
  copy_w(buf, SD_COUNTOF(buf), path);
  for (i = 1; buf[i]; i++) {
    if (buf[i] == L'\\' && i > 2 && buf[i - 1] != L':') {
      buf[i] = 0;
      CreateDirectoryW(buf, NULL);
      buf[i] = L'\\';
    }
  }
  CreateDirectoryW(buf, NULL);
  return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static int write_file(const wchar_t *path, const char *data, size_t len)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD wrote = 0;
  int ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = WriteFile(h, data, (DWORD)len, &wrote, NULL) && wrote == len;
  CloseHandle(h);
  return ok;
}

/* ---- roots and policy ---- */

static int nethood_path(wchar_t *out, size_t cch)
{
#ifdef SD_HOST_TEST_HOOKS
  if (g_test) {
    copy_w(out, cch, g_nethood_test);
    return out[0] != 0;
  }
#endif
  (void)cch;                          /* callers pass MAX_PATH buffers, which SHGetFolderPathW needs */
  return SHGetFolderPathW(NULL, CSIDL_NETHOOD, NULL, SHGFP_TYPE_CURRENT, out) == S_OK;
}

/* Policy DisableNetworkLocations = 1 (HKLM wins over HKCU, 03 §3.5; read through sd_policy). */
static int policy_disables_netloc(void)
{
  DWORD v = 0;
  return sd_policy_get_dword(SD_POLICY_DISABLENETWORKLOCATIONS, &v) && v != 0;
}

void explorer_init(void)
{
  wchar_t dir[MAX_PATH];
  DWORD n;
  size_t i;
  if (g_inited)
    return;
  g_inited = 1;
  n = GetModuleFileNameW(NULL, dir, MAX_PATH);
  if (n > 0 && n < MAX_PATH) {
    for (i = wcslen(dir); i > 0 && dir[i - 1] != L'\\'; i--)
      ;
    dir[i] = 0;
    copy_w(g_ui_path, SD_COUNTOF(g_ui_path), dir);
    cat_w(g_ui_path, SD_COUNTOF(g_ui_path), UI_EXE_NAME);
  }
  copy_w(g_icon_key, SD_COUNTOF(g_icon_key), ICON_KEY_DEFAULT);
  g_icons_on = 1;
  g_netloc_on = !policy_disables_netloc();
#ifdef SD_HOST_TEST_HOOKS
  /* tests: nothing in the user's keys or NetHood unless a test variable names a test location */
  {
    wchar_t v[MAX_PATH];
    g_test = 1;
    g_icons_on = 0;
    g_netloc_on = 0;
    if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_EXPLORER_KEY", v, SD_COUNTOF(v)) - 1u < SD_COUNTOF(v) - 1u) {
      copy_w(g_icon_key, SD_COUNTOF(g_icon_key), v);
      g_icons_on = 1;
    }
    if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", g_nethood_test, SD_COUNTOF(g_nethood_test)) - 1u <
        SD_COUNTOF(g_nethood_test) - 1u)
      g_netloc_on = 1;
    else
      g_nethood_test[0] = 0;
  }
#endif
}

/* ---- drive icons (03 §8.3) ---- */

static void icon_key_path(wchar_t letter, wchar_t *out, size_t cch)
{
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\%lc", g_icon_key, (wint_t)letter);
}

static void icon_default_value(wchar_t *out, size_t cch)
{
  _snwprintf_s(out, cch, _TRUNCATE, L"\"%s\",-%d", g_ui_path, ICON_INDEX);
}

static int icon_set(wchar_t letter)
{
  wchar_t key[300], value[MAX_PATH + 16], sub[320];
  HKEY hk;
  LONG rc;
  icon_key_path(letter, key, SD_COUNTOF(key));
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s\\DefaultIcon", key);
  icon_default_value(value, SD_COUNTOF(value));
  rc = RegCreateKeyExW(HKEY_CURRENT_USER, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
  if (rc != ERROR_SUCCESS) {
    SD_LOGW(EX_LOG, "drive icon key for %c: %d", (int)letter, (int)rc);
    return 0;
  }
  rc = RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
  RegCloseKey(hk);
  return rc == ERROR_SUCCESS;
}

/* Removes the icon only when its DefaultIcon is ours (starts with our binary), never someone else's. */
static void icon_remove(wchar_t letter)
{
  wchar_t key[300], sub[320], cur[MAX_PATH + 32], mine[MAX_PATH + 8];
  HKEY hk;
  DWORD t = 0, sz = sizeof(cur);
  int ours = 0;
  icon_key_path(letter, key, SD_COUNTOF(key));
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s\\DefaultIcon", key);
  if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
    if (RegQueryValueExW(hk, NULL, NULL, &t, (LPBYTE)cur, &sz) == ERROR_SUCCESS && t == REG_SZ) {
      cur[SD_COUNTOF(cur) - 1] = 0;
      _snwprintf_s(mine, SD_COUNTOF(mine), _TRUNCATE, L"\"%s\"", g_ui_path);
      ours = wcsncmp(cur, mine, wcslen(mine)) == 0;
    }
    RegCloseKey(hk);
    if (!ours)
      return;
    RegDeleteKeyW(HKEY_CURRENT_USER, sub);
    RegDeleteKeyW(HKEY_CURRENT_USER, key);
  }
}

/* ---- explorer.ini: the letters with an icon of ours ---- */

static int ini_path(wchar_t *out, size_t cch)
{
  wchar_t root[MAX_PATH];
  if (!local_root(root, SD_COUNTOF(root)))
    return 0;
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\state", root);
  if (!mkdirs(out))
    return 0;
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\state\\explorer.ini", root);
  return 1;
}

static sd_err ini_load(sd_ini **ini)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  DWORD size, got = 0;
  char *buf = NULL;
  sd_err e;
  uint32_t flags = 0;
  *ini = NULL;
  if (!ini_path(path, SD_COUNTOF(path)))
    return SD_E_NOT_FOUND;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return sd_ini_new(ini);
  size = GetFileSize(h, NULL);
  if (size == INVALID_FILE_SIZE || size > 65536) {
    CloseHandle(h);
    return sd_ini_new(ini);
  }
  buf = (char *)sd_alloc(size + 1u);
  if (buf == NULL || !ReadFile(h, buf, size, &got, NULL)) {
    CloseHandle(h);
    sd_free(buf);
    return sd_ini_new(ini);
  }
  CloseHandle(h);
  buf[got] = 0;
  e = sd_ini_parse(buf, got, ini, &flags);
  sd_free(buf);
  if (e != SD_OK)
    return sd_ini_new(ini);
  return SD_OK;
}

static void ini_save(sd_ini *ini)
{
  wchar_t path[MAX_PATH];
  sd_wr w;
  if (!ini_path(path, SD_COUNTOF(path)))
    return;
  sd_wr_init(&w, 4096);
  if (sd_ini_serialize(ini, &w) == SD_OK && sd_wr_ok(&w))
    (void)write_file(path, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* The letters list is one key: [icons] letters = DGH (uppercase letters). */
static void ini_set_letters(const char *letters)
{
  sd_ini *ini = NULL;
  if (ini_load(&ini) != SD_OK || ini == NULL)
    return;
  (void)sd_ini_set(ini, "icons", "letters", letters);
  ini_save(ini);
  sd_ini_free(ini);
}

static void ini_add_letter(wchar_t letter)
{
  sd_ini *ini = NULL;
  const char *cur;
  char next[32];
  size_t n = 0;
  if (ini_load(&ini) != SD_OK || ini == NULL)
    return;
  cur = sd_ini_get(ini, "icons", "letters");
  if (cur) {
    while (cur[n] && n + 2 < sizeof(next)) {
      next[n] = cur[n];
      n++;
    }
  }
  if (!(cur && strchr(cur, (char)letter) != NULL) && n + 2 < sizeof(next)) {
    next[n++] = (char)letter;
    next[n] = 0;
    (void)sd_ini_set(ini, "icons", "letters", next);
    ini_save(ini);
  }
  sd_ini_free(ini);
}

static void ini_remove_letter(wchar_t letter)
{
  sd_ini *ini = NULL;
  const char *cur;
  char next[32];
  size_t n = 0, i;
  if (ini_load(&ini) != SD_OK || ini == NULL)
    return;
  cur = sd_ini_get(ini, "icons", "letters");
  if (cur) {
    for (i = 0; cur[i] && n + 1 < sizeof(next); i++)
      if (cur[i] != (char)letter)
        next[n++] = cur[i];
    next[n] = 0;
    (void)sd_ini_set(ini, "icons", "letters", next);
    ini_save(ini);
  }
  sd_ini_free(ini);
}

/* ---- Network location entries (03 §8.7) ---- */

/* The [ShellDrive] profile= marker of a NetHood folder, "" when the folder is not ours. */
static int folder_marker(const wchar_t *folder, char *id, size_t cch)
{
  wchar_t ini[MAX_PATH], wid[64];
  copy_w(ini, SD_COUNTOF(ini), folder);
  cat_w(ini, SD_COUNTOF(ini), L"\\desktop.ini");
  id[0] = 0;
  if (GetPrivateProfileStringW(L"ShellDrive", L"profile", L"", wid, SD_COUNTOF(wid), ini) == 0)
    return 0;
  wide_to_ascii(wid, id, cch);
  return id[0] != 0;
}

/* Finds the NetHood folder of a profile id. */
static int find_entry(const wchar_t *nethood, const char *id, wchar_t *folder, size_t cch)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t pattern[MAX_PATH];
  int found = 0;
  _snwprintf_s(pattern, SD_COUNTOF(pattern), _TRUNCATE, L"%s\\*", nethood);
  h = FindFirstFileW(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  do {
    char mid[33];
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcscmp(fd.cFileName, L".") == 0 ||
        wcscmp(fd.cFileName, L"..") == 0)
      continue;
    _snwprintf_s(folder, cch, _TRUNCATE, L"%s\\%s", nethood, fd.cFileName);
    if (folder_marker(folder, mid, sizeof(mid)) && strcmp(mid, id) == 0) {
      found = 1;
      break;
    }
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  return found;
}

/* A folder whose name is the wanted name, or the wanted name with a " (n)" suffix (collision). */
static int leaf_matches(const wchar_t *leaf, const wchar_t *want)
{
  size_t n = wcslen(want);
  if (wcscmp(leaf, want) == 0)
    return 1;
  return wcsncmp(leaf, want, n) == 0 && leaf[n] == L' ' && leaf[n + 1] == L'(';
}

/* Deletes an entry folder of ours: desktop.ini, target.lnk and the folder. Only called after the marker
   check. */
static void delete_entry(const wchar_t *folder)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  SetFileAttributesW(folder, FILE_ATTRIBUTE_NORMAL);
  _snwprintf_s(pattern, SD_COUNTOF(pattern), _TRUNCATE, L"%s\\*", folder);
  h = FindFirstFileW(pattern, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        continue;
      _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\%s", folder, fd.cFileName);
      SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
      DeleteFileW(path);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryW(folder);
}

/* Placeholder folder of a profile: %LOCALAPPDATA%\LibreStatic\ShellDrive\places\<id>\ (03 §8.7). */
static int placeholder_dir(const char *id, wchar_t *out, size_t cch)
{
  wchar_t root[MAX_PATH], wid[40];
  size_t i;
  if (!local_root(root, SD_COUNTOF(root)))
    return 0;
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\places", root);
  if (!mkdirs(out))
    return 0;
  for (i = 0; id[i] && i + 1 < SD_COUNTOF(wid); i++)
    wid[i] = (wchar_t)id[i];
  wid[i] = 0;
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\places\\%s", root, wid);
  return mkdirs(out);
}

/* Writes the placeholder file "Connect to <name>.sdmount" (profile = <id>, 8.1 grammar) into the
   placeholder folder and returns the folder. */
static int ensure_placeholder(const char *id, const wchar_t *want, wchar_t *dir, size_t cch)
{
  wchar_t file[MAX_PATH];
  char text[64];
  if (!placeholder_dir(id, dir, cch))
    return 0;
  _snwprintf_s(file, SD_COUNTOF(file), _TRUNCATE, L"%s\\Connect to %s.sdmount", dir, want);
  _snprintf_s(text, sizeof(text), _TRUNCATE, "profile = %s\r\n", id);
  return write_file(file, text, strlen(text));
}

static void remove_placeholder(const char *id)
{
  wchar_t dir[MAX_PATH], pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  if (!placeholder_dir(id, dir, SD_COUNTOF(dir)))
    return;
  _snwprintf_s(pattern, SD_COUNTOF(pattern), _TRUNCATE, L"%s\\*.sdmount", dir);
  h = FindFirstFileW(pattern, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
      DeleteFileW(path);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryW(dir);
}

/* Target of the entry: the drive root when the drive is mapped, the placeholder folder otherwise. Writes
   target.lnk through IShellLinkW and a temp file moved over the old link (03 §8.7). */
static int write_link(const wchar_t *folder, const wchar_t *target)
{
  HRESULT hr;
  int inited;
  IShellLinkW *sl = NULL;
  IPersistFile *pf = NULL;
  wchar_t tmp[MAX_PATH], fin[MAX_PATH];
  int ok = 0;
  hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  inited = SUCCEEDED(hr);
  if (CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl) == S_OK) {
    if (sl->lpVtbl->SetPath(sl, target) == S_OK &&
        sl->lpVtbl->QueryInterface(sl, &IID_IPersistFile, (void **)&pf) == S_OK) {
      _snwprintf_s(tmp, SD_COUNTOF(tmp), _TRUNCATE, L"%s\\target.lnk.tmp", folder);
      _snwprintf_s(fin, SD_COUNTOF(fin), _TRUNCATE, L"%s\\target.lnk", folder);
      if (pf->lpVtbl->Save(pf, tmp, TRUE) == S_OK)
        ok = MoveFileExW(tmp, fin, MOVEFILE_REPLACE_EXISTING) != 0;
      pf->lpVtbl->Release(pf);
    }
    sl->lpVtbl->Release(sl);
  }
  if (inited)
    CoUninitialize();
  return ok;
}

/* Creates the entry folder with its desktop.ini, read-only attribute and link. */
static int create_entry(const wchar_t *nethood, const char *id, const wchar_t *want, const wchar_t *target,
                        wchar_t *folder, size_t cch)
{
  wchar_t ini[MAX_PATH], icon[MAX_PATH + 8], base[MAX_PATH];
  int n;
  for (n = 1; n <= 9; n++) {
    if (n == 1)
      _snwprintf_s(base, SD_COUNTOF(base), _TRUNCATE, L"%s\\%s", nethood, want);
    else
      _snwprintf_s(base, SD_COUNTOF(base), _TRUNCATE, L"%s\\%s (%d)", nethood, want, n);
    if (GetFileAttributesW(base) == INVALID_FILE_ATTRIBUTES)
      break;
  }
  if (n > 9)
    return 0;
  if (!CreateDirectoryW(base, NULL))
    return 0;
  copy_w(folder, cch, base);
  copy_w(ini, SD_COUNTOF(ini), base);
  cat_w(ini, SD_COUNTOF(ini), L"\\desktop.ini");
  WritePrivateProfileStringW(L".ShellClassInfo", L"CLSID2", NETHOOD_CLSID, ini);
  WritePrivateProfileStringW(L".ShellClassInfo", L"Flags", L"2", ini);
  _snwprintf_s(icon, SD_COUNTOF(icon), _TRUNCATE, L"%s,-%d", g_ui_path, ICON_INDEX);
  WritePrivateProfileStringW(L".ShellClassInfo", L"IconResource", icon, ini);
  {
    wchar_t wid[40];
    size_t i;
    for (i = 0; id[i] && i + 1 < SD_COUNTOF(wid); i++)
      wid[i] = (wchar_t)id[i];
    wid[i] = 0;
    WritePrivateProfileStringW(L"ShellDrive", L"profile", wid, ini);
  }
  SetFileAttributesW(ini, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
  (void)write_link(base, target);
  SetFileAttributesW(base, FILE_ATTRIBUTE_READONLY);     /* desktop.ini is honoured on read-only folders */
  return 1;
}

/* Brings the entry of one profile to the wanted state. */
static void netloc_sync(const char *id, const char *name, wchar_t letter, int present)
{
  wchar_t nethood[MAX_PATH], wname[PROFILE_NAME_CCH], want[NAME_CCH], folder[MAX_PATH], placeholder[MAX_PATH];
  wchar_t target[MAX_PATH];
  int found;
  if (!nethood_path(nethood, SD_COUNTOF(nethood)) || !mkdirs(nethood))
    return;
  utf8_to_wide(name, wname, SD_COUNTOF(wname));
  if (wname[0] == 0)
    copy_w(wname, SD_COUNTOF(wname), L"ShellDrive");
  sanitize_name(wname, want, SD_COUNTOF(want));
  if (!ensure_placeholder(id, want, placeholder, SD_COUNTOF(placeholder)))
    return;
  if (present && letter >= L'A' && letter <= L'Z') {
    target[0] = letter;
    target[1] = L':';
    target[2] = L'\\';
    target[3] = 0;
  } else {
    copy_w(target, SD_COUNTOF(target), placeholder);
  }
  found = find_entry(nethood, id, folder, SD_COUNTOF(folder));
  if (found) {
    const wchar_t *leaf = wcsrchr(folder, L'\\');
    if (!leaf || !leaf_matches(leaf + 1, want)) {
      delete_entry(folder);
      found = 0;
    }
  }
  if (!found) {
    if (!create_entry(nethood, id, want, target, folder, SD_COUNTOF(folder)))
      return;
  } else {
    (void)write_link(folder, target);
  }
  SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, folder, NULL);
}

/* ---- control thread entry points ---- */

void explorer_apply(const host_explorer_mount *m)
{
  int idx;
  if (m == NULL || m->letter < L'A' || m->letter > L'Z')
    return;
  idx = m->letter - L'A';
  if (g_icons_on) {
    if (m->present && !g_active[idx]) {
      if (icon_set(m->letter)) {
        wchar_t root[MAX_PATH];
        ini_add_letter(m->letter);
        _snwprintf_s(root, SD_COUNTOF(root), _TRUNCATE, L"%lc:\\", (wint_t)m->letter);
        SHChangeNotify(SHCNE_DRIVEADD, SHCNF_PATHW, root, NULL);
        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, root, NULL);
        g_active[idx] = 1;
      }
    } else if (!m->present && g_active[idx]) {
      wchar_t root[MAX_PATH];
      icon_remove(m->letter);
      ini_remove_letter(m->letter);
      _snwprintf_s(root, SD_COUNTOF(root), _TRUNCATE, L"%lc:\\", (wint_t)m->letter);
      SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATHW, root, NULL);
      g_active[idx] = 0;
    }
  }
  if (g_netloc_on && m->profile_id[0] && m->network_location)
    netloc_sync(m->profile_id, m->profile_name, m->letter, m->present);
}

typedef struct ex_collect {
  ex_profile *items;
  unsigned n;
} ex_collect;

static int collect_profile(void *ctx, const sd_profile *p, const wchar_t *path)
{
  ex_collect *c = (ex_collect *)ctx;
  SD_UNUSED(path);
  if (c->n < PROFILE_MAX) {
    ex_profile *x = &c->items[c->n++];
    memset(x, 0, sizeof(*x));
    strncpy_s(x->id, sizeof(x->id), p->id, _TRUNCATE);
    strncpy_s(x->name, sizeof(x->name), p->name, _TRUNCATE);
    x->network_location = p->network_location;
  }
  return 1;
}

/* Agent start (03 §8.7, lifecycle): Network location folders whose profile is gone or no longer asks
   for one are deleted; every profile that asks for one gets its folder back. Entries without our marker
   are never touched. */
static void netloc_reconcile(void)
{
  ex_collect c;
  wchar_t nethood[MAX_PATH], pattern[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  unsigned i;
  memset(&c, 0, sizeof(c));
  c.items = (ex_profile *)sd_calloc(PROFILE_MAX, sizeof(ex_profile));
  if (c.items == NULL)
    return;
  (void)sd_profile_enum(collect_profile, &c);
  if (!nethood_path(nethood, SD_COUNTOF(nethood)) || !mkdirs(nethood))
    goto done;

  _snwprintf_s(pattern, SD_COUNTOF(pattern), _TRUNCATE, L"%s\\*", nethood);
  h = FindFirstFileW(pattern, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      wchar_t folder[MAX_PATH];
      char mid[33];
      int keep = 0;
      if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcscmp(fd.cFileName, L".") == 0 ||
          wcscmp(fd.cFileName, L"..") == 0)
        continue;
      _snwprintf_s(folder, SD_COUNTOF(folder), _TRUNCATE, L"%s\\%s", nethood, fd.cFileName);
      if (!folder_marker(folder, mid, sizeof(mid)))
        continue;
      for (i = 0; i < c.n; i++)
        if (strcmp(c.items[i].id, mid) == 0 && c.items[i].network_location)
          keep = 1;
      if (!keep) {
        delete_entry(folder);
        remove_placeholder(mid);
      }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  for (i = 0; i < c.n; i++)
    if (c.items[i].network_location && valid_id(c.items[i].id))
      netloc_sync(c.items[i].id, c.items[i].name, 0, 0);
  SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, nethood, NULL);

done:
  sd_free(c.items);
}

/* Start: removes the icons listed by a crashed agent, then reconciles the Network locations. */
void explorer_reconcile_start(void)
{
  sd_ini *ini = NULL;
  if (g_icons_on && ini_load(&ini) == SD_OK && ini != NULL) {
    const char *letters = sd_ini_get(ini, "icons", "letters");
    if (letters) {
      size_t i;
      for (i = 0; letters[i]; i++) {
        wchar_t l = (wchar_t)(unsigned char)letters[i];
        if (l >= L'A' && l <= L'Z')
          icon_remove(l);
      }
    }
    sd_ini_free(ini);
    ini_set_letters("");
  } else if (ini) {
    sd_ini_free(ini);
  }
  if (g_netloc_on)
    netloc_reconcile();
}

/* Shutdown: every icon this agent wrote is removed (the mounts are gone by now). */
void explorer_shutdown(void)
{
  sd_ini *ini = NULL;
  int i;
  if (!g_icons_on)
    return;
  if (ini_load(&ini) == SD_OK && ini != NULL) {
    const char *letters = sd_ini_get(ini, "icons", "letters");
    if (letters) {
      size_t k;
      for (k = 0; letters[k]; k++) {
        wchar_t l = (wchar_t)(unsigned char)letters[k];
        if (l >= L'A' && l <= L'Z')
          icon_remove(l);
      }
    }
    sd_ini_free(ini);
  }
  ini_set_letters("");
  for (i = 0; i < 26; i++)
    g_active[i] = 0;
}
