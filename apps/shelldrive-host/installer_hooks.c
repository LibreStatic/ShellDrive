/* shelldrive-host --installer-hook <name> --apply|--revert (docs/design/03 §6.1, 04 §8.3).
 *
 * Hidden verbs run by the installers (the setup engine per user, MSI deferred actions per machine). Each is
 * idempotent. signal-shutdown is implemented here for the current account: it sets the shutdown events of
 * the agents of this user and session (04 §6.9 step 1). webdav-tune sets the two WebClient redirector limits
 * and records the values it replaced (C28). programdata-secure and user-cleanup are the other implemented
 * hooks. modern-menu is part of M5/the sparse package (D27); it logs that it is not implemented and succeeds,
 * so that an installer run is not blocked by a hook that has nothing to do yet. */
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "svc_repair.h"
#include "explorer_data.h"
#include "sd_config/sd_ini.h"

#define SD_HOOK_AGENT_EVENT L"Global\\com.librestatic.shelldrive.agent.shutdown."

typedef BOOL (WINAPI *sd_ProcessIdToSessionId_t)(DWORD, DWORD *);

static const wchar_t *const k_hooks[] = {
  L"webdav-tune", L"user-cleanup", L"modern-menu", L"signal-shutdown", L"programdata-secure"
};

/* %ProgramData%\LibreStatic and \ShellDrive are checked by handle and set back to the 3.2 DACLs; an untrusted folder is
   moved aside (TM-R34, 04 §6.4). The same repair the setup stub runs before any elevated write. */
static int programdata_secure(void)
{
  wchar_t base[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result rr;
  DWORD err;

  if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, base))) {
    wprintf(L"programdata-secure: the common application data folder is not known\n");
    return 1;
  }
  svc_repair_real_ops(&ops);
  memset(&rr, 0, sizeof(rr));
  err = svc_repair_data(&ops, base, &rr);
  if (err != 0) {
    wprintf(L"programdata-secure: the ProgramData folders could not be secured (error %lu)\n", (unsigned long)err);
    return 1;
  }
  if (rr.moved)
    wprintf(L"programdata-secure: an untrusted folder was moved aside to %s\n", rr.path);
  return 0;
}

/* Shutdown events of this account's agent in this session (the current process session). */
static int signal_own_agents(void)
{
  HANDLE token = NULL;
  BYTE buf[256];
  DWORD need = 0;
  TOKEN_USER *tu = (TOKEN_USER *)buf;
  wchar_t *sid_text = NULL;
  wchar_t name[256];
  DWORD session = 0;
  HANDLE ev;
  sd_ProcessIdToSessionId_t sess_of;
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  int rc = 1;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return 1;
  if (!GetTokenInformation(token, TokenUser, buf, sizeof(buf), &need) ||
      !ConvertSidToStringSidW(tu->User.Sid, &sid_text)) {
    CloseHandle(token);
    return 1;
  }
  CloseHandle(token);

  sess_of = k32 != NULL ? (sd_ProcessIdToSessionId_t)GetProcAddress(k32, "ProcessIdToSessionId") : NULL;
  if (sess_of == NULL || !sess_of(GetCurrentProcessId(), &session)) {
    LocalFree(sid_text);
    return 1;
  }

  StringCchPrintfW(name, sizeof(name) / sizeof(name[0]), L"%s%s.%lu", SD_HOOK_AGENT_EVENT, sid_text,
                   (unsigned long)session);
  LocalFree(sid_text);

  ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
  if (ev == NULL) {
    wprintf(L"signal-shutdown: no agent of this account is running in this session\n");
    return 0;
  }
  if (SetEvent(ev)) {
    wprintf(L"signal-shutdown: the agent was asked to exit\n");
    rc = 0;
  }
  CloseHandle(ev);
  return rc;
}

/* ---- webdav-tune (C28; 04 §8.3, 02 §7.1) ---------------------------------------------------------------- */

#define SD_WEBDAV_PARAMS_KEY L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters"
#define SD_WEBDAV_SIZE_NAME  L"FileSizeLimitInBytes"
#define SD_WEBDAV_ATTR_NAME  L"FileAttributesLimitInBytes"
#define SD_WEBDAV_SIZE_VALUE 0xFFFFFFFFu
#define SD_WEBDAV_ATTR_VALUE 100000000u
#define SD_WEBDAV_TUNE_FILE  L"webdav-tune.ini"
#define SD_WEBDAV_SECTION    "webdav-tune"
#define SD_WEBDAV_SIZE_KEY   "file_size_limit_in_bytes"
#define SD_WEBDAV_ATTR_KEY   "file_attributes_limit_in_bytes"
#define SD_WEBDAV_ABSENT     "absent"
#define SD_WEBDAV_STATE_MAX  4096

typedef struct webdav_original {
  DWORD value;
  int present;
} webdav_original;

/* Creates every component of dir that is missing. Drive paths only; the callers build them from a known folder. */
static int ensure_dirs(const wchar_t *dir)
{
  wchar_t tmp[MAX_PATH];
  size_t i;

  if (FAILED(StringCchCopyW(tmp, SD_COUNTOF(tmp), dir)))
    return 1;
  for (i = 3; tmp[i] != L'\0'; i++) {
    if (tmp[i] == L'\\') {
      tmp[i] = L'\0';
      (void)CreateDirectoryW(tmp, NULL);
      tmp[i] = L'\\';
    }
  }
  (void)CreateDirectoryW(tmp, NULL);
  return GetFileAttributesW(tmp) == INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

/* %ProgramData% (the test build may redirect it, like the other host test hooks). */
static int programdata_dir(wchar_t *out, size_t cch)
{
#ifdef SD_HOST_TEST_HOOKS
  DWORD n = GetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROGRAMDATA", out, (DWORD)cch);
  if (n > 0 && (size_t)n < cch)
    return 0;
#else
  (void)cch;
#endif
  return FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, out)) ? 1 : 0;
}

/* <ProgramData>\LibreStatic\ShellDrive\service\state\webdav-tune.ini (03 §6.1). */
static int webdav_state_path(wchar_t *out, size_t cch)
{
  wchar_t base[MAX_PATH];
  wchar_t dir[MAX_PATH];

  if (programdata_dir(base, SD_COUNTOF(base)) != 0)
    return 1;
  if (FAILED(StringCchPrintfW(dir, SD_COUNTOF(dir), L"%s\\LibreStatic\\ShellDrive\\service\\state", base)))
    return 1;
  if (ensure_dirs(dir) != 0)
    return 1;
  return FAILED(StringCchPrintfW(out, cch, L"%s\\%s", dir, SD_WEBDAV_TUNE_FILE)) ? 1 : 0;
}

/* The parameters key, or the HKCU key of the test build (never the real user's in tests). */
static void webdav_params_key(HKEY *root, const wchar_t **key)
{
  *root = HKEY_LOCAL_MACHINE;
  *key = SD_WEBDAV_PARAMS_KEY;
#ifdef SD_HOST_TEST_HOOKS
  {
    static wchar_t test[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"SHELLDRIVE_TEST_WEBDAV_PARAMS", test, SD_COUNTOF(test));
    if (n > 0 && (size_t)n < SD_COUNTOF(test)) {
      *root = HKEY_CURRENT_USER;
      *key = test;
    }
  }
#endif
}

/* Reads one DWORD value. A value of another type is an error: it is never replaced or deleted. */
static int webdav_read_dword(HKEY key, const wchar_t *name, webdav_original *v)
{
  DWORD type = 0;
  DWORD size = sizeof(DWORD);
  DWORD data = 0;
  LONG rc;

  memset(v, 0, sizeof(*v));
  rc = RegQueryValueExW(key, name, NULL, &type, (BYTE *)&data, &size);
  if (rc == ERROR_FILE_NOT_FOUND)
    return 0;
  if (rc != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(DWORD))
    return 1;
  v->value = data;
  v->present = 1;
  return 0;
}

static int webdav_write_dword(HKEY key, const wchar_t *name, DWORD value)
{
  return RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value, sizeof(value)) == ERROR_SUCCESS ? 0 : 1;
}

static int webdav_restore_dword(HKEY key, const wchar_t *name, const webdav_original *v)
{
  LONG rc;

  if (v->present)
    return webdav_write_dword(key, name, v->value);
  rc = RegDeleteValueW(key, name);
  return (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) ? 0 : 1;
}

static int webdav_parse_original(const char *text, webdav_original *v)
{
  uint32_t u = 0;

  memset(v, 0, sizeof(*v));
  if (text == NULL)
    return 1;
  if (strcmp(text, SD_WEBDAV_ABSENT) == 0)
    return 0;
  if (!sd_ini_parse_u32(text, &u))
    return 1;
  v->value = (DWORD)u;
  v->present = 1;
  return 0;
}

/* Reads the recorded originals. *exists is 0 when the file is absent (nothing was tuned); a damaged file is an error,
   so a repeat apply never overwrites them and a revert never guesses. */
static int webdav_read_state(const wchar_t *path, int *exists, webdav_original *size, webdav_original *attr)
{
  HANDLE f;
  char buf[SD_WEBDAV_STATE_MAX];
  DWORD got = 0;
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  int rc = 1;

  *exists = 0;
  memset(size, 0, sizeof(*size));
  memset(attr, 0, sizeof(*attr));
  f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
    return GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : 1;
  *exists = 1;
  if (!ReadFile(f, buf, (DWORD)sizeof(buf), &got, NULL) || got == 0 || got >= (DWORD)sizeof(buf))
    goto out;
  if (sd_ini_parse(buf, got, &ini, &flags) != SD_OK)
    goto out;
  if (webdav_parse_original(sd_ini_get(ini, SD_WEBDAV_SECTION, SD_WEBDAV_SIZE_KEY), size) != 0 ||
      webdav_parse_original(sd_ini_get(ini, SD_WEBDAV_SECTION, SD_WEBDAV_ATTR_KEY), attr) != 0)
    goto out;
  rc = 0;
out:
  if (ini != NULL)
    sd_ini_free(ini);
  CloseHandle(f);
  return rc;
}

/* Writes the originals before anything changes (tmp + replace, so a crash leaves either the old file or none). */
static int webdav_write_state(const wchar_t *path, const webdav_original *size, const webdav_original *attr)
{
  sd_ini *ini = NULL;
  sd_wr w;
  wchar_t tmp[MAX_PATH];
  HANDLE f;
  DWORD put = 0;
  char text[16];
  int rc = 1;

  sd_wr_init(&w, SD_WEBDAV_STATE_MAX);
  if (sd_ini_new(&ini) != SD_OK) {
    sd_wr_free(&w);
    return 1;
  }
  if (size->present && _snprintf_s(text, SD_COUNTOF(text), _TRUNCATE, "%lu", (unsigned long)size->value) < 0)
    goto out;
  if (sd_ini_set(ini, SD_WEBDAV_SECTION, SD_WEBDAV_SIZE_KEY, size->present ? text : SD_WEBDAV_ABSENT) != SD_OK)
    goto out;
  if (attr->present && _snprintf_s(text, SD_COUNTOF(text), _TRUNCATE, "%lu", (unsigned long)attr->value) < 0)
    goto out;
  if (sd_ini_set(ini, SD_WEBDAV_SECTION, SD_WEBDAV_ATTR_KEY, attr->present ? text : SD_WEBDAV_ABSENT) != SD_OK)
    goto out;
  if (sd_ini_serialize(ini, &w) != SD_OK || !sd_wr_ok(&w))
    goto out;
  if (FAILED(StringCchPrintfW(tmp, SD_COUNTOF(tmp), L"%s.tmp", path)))
    goto out;
  f = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
    goto out;
  if (!WriteFile(f, w.p, (DWORD)w.len, &put, NULL) || put != (DWORD)w.len || !FlushFileBuffers(f)) {
    CloseHandle(f);
    (void)DeleteFileW(tmp);
    goto out;
  }
  CloseHandle(f);
  if (!MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
    (void)DeleteFileW(tmp);
    goto out;
  }
  rc = 0;
out:
  sd_wr_free(&w);
  sd_ini_free(ini);
  return rc;
}

/* Sets FileSizeLimitInBytes=0xFFFFFFFF and FileAttributesLimitInBytes=100000000, recording the previous values once.
   Idempotent: a repair run or a second install keeps the originals of the first run. BasicAuthLevel is never read or
   written (A2, C28). */
static int webdav_tune_apply(void)
{
  HKEY root;
  const wchar_t *keypath;
  HKEY key = NULL;
  DWORD disp = 0;
  webdav_original cur_size, cur_attr, old_size, old_attr;
  wchar_t state[MAX_PATH];
  int have = 0;
  LONG rc;
  int result = 1;

  webdav_params_key(&root, &keypath);
  if (webdav_state_path(state, SD_COUNTOF(state)) != 0) {
    wprintf(L"webdav-tune: the machine state folder is not available\n");
    return 1;
  }
  rc = RegCreateKeyExW(root, keypath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key,
                       &disp);
  if (rc != ERROR_SUCCESS) {
    wprintf(L"webdav-tune: the WebClient parameters key cannot be opened (error %ld)\n", (long)rc);
    return 1;
  }
  if (webdav_read_dword(key, SD_WEBDAV_SIZE_NAME, &cur_size) != 0 ||
      webdav_read_dword(key, SD_WEBDAV_ATTR_NAME, &cur_attr) != 0) {
    wprintf(L"webdav-tune: a WebClient value has an unexpected type; nothing was changed\n");
    goto out;
  }
  if (webdav_read_state(state, &have, &old_size, &old_attr) != 0) {
    wprintf(L"webdav-tune: the recorded originals are unreadable; nothing was changed\n");
    goto out;
  }
  if (!have) {
    old_size = cur_size;
    old_attr = cur_attr;
    if (webdav_write_state(state, &old_size, &old_attr) != 0) {
      wprintf(L"webdav-tune: the recorded originals could not be written; nothing was changed\n");
      goto out;
    }
  }
  if (webdav_write_dword(key, SD_WEBDAV_SIZE_NAME, SD_WEBDAV_SIZE_VALUE) != 0 ||
      webdav_write_dword(key, SD_WEBDAV_ATTR_NAME, SD_WEBDAV_ATTR_VALUE) != 0) {
    wprintf(L"webdav-tune: the WebClient values could not be written\n");
    goto out;
  }
  wprintf(L"webdav-tune: the WebClient limits are set (originals recorded in %s)\n", state);
  result = 0;
out:
  RegCloseKey(key);
  return result;
}

/* Puts the recorded values back and removes the record. Without a record there is nothing to undo (a hook that never
   applied, or an older install): success. */
static int webdav_tune_revert(void)
{
  HKEY root;
  const wchar_t *keypath;
  HKEY key = NULL;
  webdav_original old_size, old_attr;
  wchar_t state[MAX_PATH];
  int exists = 0;
  LONG rc;

  webdav_params_key(&root, &keypath);
  if (webdav_state_path(state, SD_COUNTOF(state)) != 0) {
    wprintf(L"webdav-tune: the machine state folder is not available\n");
    return 1;
  }
  if (webdav_read_state(state, &exists, &old_size, &old_attr) != 0) {
    wprintf(L"webdav-tune: the recorded originals are unreadable; nothing was restored\n");
    return 1;
  }
  if (!exists) {
    wprintf(L"webdav-tune: no originals recorded; nothing to restore\n");
    return 0;
  }
  rc = RegOpenKeyExW(root, keypath, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
  if (rc == ERROR_FILE_NOT_FOUND) {
    (void)DeleteFileW(state);
    return 0;
  }
  if (rc != ERROR_SUCCESS) {
    wprintf(L"webdav-tune: the WebClient parameters key cannot be opened (error %ld)\n", (long)rc);
    return 1;
  }
  if (webdav_restore_dword(key, SD_WEBDAV_SIZE_NAME, &old_size) != 0 ||
      webdav_restore_dword(key, SD_WEBDAV_ATTR_NAME, &old_attr) != 0) {
    wprintf(L"webdav-tune: the originals could not be restored\n");
    RegCloseKey(key);
    return 1;
  }
  RegCloseKey(key);
  if (!DeleteFileW(state) && GetLastError() != ERROR_FILE_NOT_FOUND) {
    wprintf(L"webdav-tune: the originals are back but the record could not be removed\n");
    return 1;
  }
  wprintf(L"webdav-tune: the original WebClient limits are back\n");
  return 0;
}

/* argv as given to wmain: argv[1] == "--installer-hook", argv[2] = name, then --apply or --revert. */
int sd_host_installer_hook(int argc, wchar_t **argv)
{
  const wchar_t *name;
  int known = 0;
  int apply = 0;
  int i;
  size_t k;

  if (argc < 4) {
    wprintf(L"usage: shelldrive-host --installer-hook <name> --apply|--revert\n");
    return 2;
  }
  name = argv[2];
  for (k = 0; k < sizeof(k_hooks) / sizeof(k_hooks[0]); k++) {
    if (wcscmp(name, k_hooks[k]) == 0)
      known = 1;
  }
  if (!known) {
    wprintf(L"shelldrive-host: unknown installer hook %s\n", name);
    return 2;
  }
  for (i = 3; i < argc; i++) {
    if (wcscmp(argv[i], L"--apply") == 0)
      apply = 1;
    else if (wcscmp(argv[i], L"--revert") != 0) {
      wprintf(L"shelldrive-host: unknown option %s\n", argv[i]);
      return 2;
    }
  }

  if (wcscmp(name, L"signal-shutdown") == 0) {
    if (!apply)
      return 0;                /* nothing to undo: the agents were asked to exit already */
    return signal_own_agents();
  }

  if (wcscmp(name, L"programdata-secure") == 0) {
    /* Nothing to undo: the folders are trusted and stay. */
    if (!apply)
      return 0;
    return programdata_secure();
  }

  if (wcscmp(name, L"user-cleanup") == 0) {
    /* Explorer data of this user (03 8.7); other users of a per-machine install keep inert entries. */
    if (apply)
      explorer_cleanup_user();
    return 0;
  }

  if (wcscmp(name, L"webdav-tune") == 0) {
    if (!apply)
      return webdav_tune_revert();
    return webdav_tune_apply();
  }

  wprintf(L"installer hook %s: not yet implemented (M5)\n", name);
  return 0;
}
