/* ShellDriveSvc registration (03 §1.3, §6.1, 10.3; M5 part 2). See svc_scm.h.
 *
 * Only the CLI links this file (through shelldrive.exe) and the unit tests. Every rule that decides what is called,
 * in which order, and what is rolled back is in the svc_scm_* functions, which only see the seam. The advapi32
 * calls are in the scm_* functions of svc_scm_real_ops, the only place that touches the Service Control Manager or
 * HKLM. All import names here are on the XP SP2/SP3 floor lists (tests/os-imports). */
#include <windows.h>
#include <strsafe.h>
#include <string.h>

#include "sd_platform/sd_platform.h"
#include "svc_scm.h"

#define SVC_SCM_SERVICE_NAME L"ShellDriveSvc"
#define SVC_SCM_HOST_BINARY L"shelldrive-host.exe"
#define SVC_SCM_EVENTLOG_APP L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application"
#define SVC_SCM_DEPS L"Tcpip\0"                  /* multi-string: "Tcpip", then the empty terminator */
#define SVC_SCM_START_WAIT_MS 30000u
#define SVC_SCM_STOP_WAIT_MS 60000u
#define SVC_SCM_POLL_MS 250u
#define SVC_SCM_RESET_PERIOD_S 86400u            /* one day */
#define SVC_SCM_COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* SDK 7.1A headers may lack these (Vista additions): values from winsvc.h. */
#ifndef SERVICE_CONFIG_SERVICE_SID_INFO
#define SERVICE_CONFIG_SERVICE_SID_INFO 5
#endif
#ifndef SERVICE_SID_TYPE_UNRESTRICTED
#define SERVICE_SID_TYPE_UNRESTRICTED 0x00000001u
#endif

typedef struct svc_sid_info_s {
  DWORD type;                            /* same layout as SERVICE_SID_INFO */
} svc_sid_info_s;

/* ---- rules (seam only) ---- */

DWORD svc_scm_install(const svc_scm_ops *ops, const svc_install_spec *s)
{
  DWORD e;
  if (!ops->is_elevated(ops->ctx))
    return ERROR_ACCESS_DENIED;
  e = ops->create_service(ops->ctx, s);
  if (e != 0)
    return e;                            /* nothing of ours exists yet (ERROR_SERVICE_EXISTS and friends) */
  e = ops->set_description(ops->ctx, s);
  if (e == 0)
    e = ops->set_failure_actions(ops->ctx, s);
  if (e == 0 && s->sid_unrestricted && ops->is_vista_or_later(ops->ctx))
    e = ops->set_sid_type(ops->ctx, SERVICE_SID_TYPE_UNRESTRICTED);
  if (e == 0)
    e = ops->register_source(ops->ctx, SVC_SCM_EVENT_SOURCE, s->message_file, SVC_SCM_EVENT_TYPES);
  if (e != 0)
    (void)ops->delete_service(ops->ctx);  /* roll back: a half-configured service must not stay installed */
  return e;
}

DWORD svc_scm_uninstall(const svc_scm_ops *ops)
{
  DWORD e;
  if (!ops->is_elevated(ops->ctx))
    return ERROR_ACCESS_DENIED;
  (void)ops->stop_service(ops->ctx);     /* a service that is not running is fine */
  e = ops->delete_service(ops->ctx);
  if (e != 0)
    return e;
  e = ops->unregister_source(ops->ctx, SVC_SCM_EVENT_SOURCE);
  return e == ERROR_FILE_NOT_FOUND ? 0 : e;
}

DWORD svc_scm_start(const svc_scm_ops *ops)
{
  if (!ops->is_elevated(ops->ctx))
    return ERROR_ACCESS_DENIED;
  return ops->start_service(ops->ctx);
}

DWORD svc_scm_stop(const svc_scm_ops *ops)
{
  if (!ops->is_elevated(ops->ctx))
    return ERROR_ACCESS_DENIED;
  return ops->stop_service(ops->ctx);
}

int svc_path_check_of(const wchar_t *image, const svc_install_spec *expect)
{
  if (expect == NULL || image == NULL)
    return SVC_PATH_UNKNOWN;
  if (image[0] != L'"')
    return SVC_PATH_UNQUOTED;
  if (lstrcmpiW(image, expect->command) == 0)
    return SVC_PATH_OK;
  return SVC_PATH_OTHER;
}

DWORD svc_scm_status(const svc_scm_ops *ops, const svc_install_spec *expect, svc_status_report *out)
{
  DWORD e;
  memset(out, 0, sizeof(*out));
  e = ops->query_service(ops->ctx, out);
  if (e != 0)
    return e;
  out->binary_check = out->installed ? svc_path_check_of(out->binary, expect) : SVC_PATH_UNKNOWN;
  out->message_file[0] = 0;
  e = ops->query_source(ops->ctx, SVC_SCM_EVENT_SOURCE, out->message_file, SVC_SCM_COUNT(out->message_file));
  if (e == ERROR_FILE_NOT_FOUND) {
    out->message_file[0] = 0;
    out->source_check = SVC_SRC_MISSING;
    return 0;
  }
  if (e != 0)
    return e;
  if (expect == NULL)
    out->source_check = SVC_SRC_UNKNOWN;
  else if (lstrcmpiW(out->message_file, expect->message_file) == 0)
    out->source_check = SVC_SRC_OK;
  else
    out->source_check = SVC_SRC_OTHER;
  return 0;
}

DWORD svc_scm_host_spec(svc_install_spec *s, const wchar_t *description)
{
  wchar_t exe[MAX_PATH];
  DWORD n, i, cut = 0;
  DWORD attr;
  n = GetModuleFileNameW(NULL, exe, MAX_PATH);
  if (n == 0 || n >= MAX_PATH)
    return ERROR_BUFFER_OVERFLOW;
  for (i = 0; i < n; i++) {
    if (exe[i] == L'\\')
      cut = i + 1;                       /* keep the trailing backslash */
  }
  if (cut == 0)
    return ERROR_PATH_NOT_FOUND;
  exe[cut] = 0;
  if (FAILED(StringCchCatW(exe, MAX_PATH, SVC_SCM_HOST_BINARY)))
    return ERROR_BUFFER_OVERFLOW;
  attr = GetFileAttributesW(exe);
  if (attr == INVALID_FILE_ATTRIBUTES)
    return ERROR_FILE_NOT_FOUND;
  memset(s, 0, sizeof(*s));
  if (FAILED(StringCchCopyW(s->message_file, MAX_PATH, exe)))
    return ERROR_BUFFER_OVERFLOW;
  if (FAILED(StringCchPrintfW(s->command, SVC_SCM_COUNT(s->command), L"\"%s\" service", exe)))
    return ERROR_BUFFER_OVERFLOW;
  if (FAILED(StringCchCopyW(s->description, SVC_SCM_COUNT(s->description), description ? description : L"")))
    return ERROR_BUFFER_OVERFLOW;
  s->restart_ms[0] = 5000u;              /* 1.3: restart after 5 s, 30 s, then every 5 min */
  s->restart_ms[1] = 30000u;
  s->restart_ms[2] = 300000u;
  s->reset_period_s = SVC_SCM_RESET_PERIOD_S;
  s->sid_unrestricted = 1;
  return 0;
}

/* ---- Win32 seam (advapi32, XP+) ---- */

static DWORD open_service(DWORD manager_access, DWORD svc_access, SC_HANDLE *scm, SC_HANDLE *svc)
{
  DWORD e;
  *scm = OpenSCManagerW(NULL, NULL, manager_access);
  if (*scm == NULL)
    return GetLastError();
  *svc = OpenServiceW(*scm, SVC_SCM_SERVICE_NAME, svc_access);
  if (*svc == NULL) {
    e = GetLastError();
    CloseServiceHandle(*scm);
    *scm = NULL;
    return e;
  }
  return 0;
}

static void close_handles(SC_HANDLE scm, SC_HANDLE svc)
{
  if (svc != NULL)
    CloseServiceHandle(svc);
  if (scm != NULL)
    CloseServiceHandle(scm);
}

static DWORD scm_create_service(void *ctx, const svc_install_spec *s)
{
  SC_HANDLE scm, svc;
  (void)ctx;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (scm == NULL)
    return GetLastError();
  /* lpServiceStartName NULL = LocalSystem (1.3). */
  svc = CreateServiceW(scm, SVC_SCM_SERVICE_NAME, SVC_SCM_DISPLAY_NAME, SERVICE_ALL_ACCESS,
                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, s->command,
                       NULL, NULL, SVC_SCM_DEPS, NULL, NULL);
  if (svc == NULL) {
    DWORD e = GetLastError();
    CloseServiceHandle(scm);
    return e;
  }
  close_handles(scm, svc);
  return 0;
}

static DWORD scm_set_description(void *ctx, const svc_install_spec *s)
{
  SC_HANDLE scm = NULL, svc = NULL;
  SERVICE_DESCRIPTIONW d;
  DWORD e;
  (void)ctx;
  e = open_service(SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, &scm, &svc);
  if (e != 0)
    return e;
  d.lpDescription = (LPWSTR)s->description;
  if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &d))
    e = GetLastError();
  close_handles(scm, svc);
  return e;
}

static DWORD scm_set_failure_actions(void *ctx, const svc_install_spec *s)
{
  SC_HANDLE scm = NULL, svc = NULL;
  SC_ACTION acts[SVC_SCM_RESTART_COUNT];
  SERVICE_FAILURE_ACTIONSW fa;
  DWORD i, e;
  (void)ctx;
  for (i = 0; i < SVC_SCM_RESTART_COUNT; i++) {
    acts[i].Type = SC_ACTION_RESTART;
    acts[i].Delay = s->restart_ms[i];
  }
  memset(&fa, 0, sizeof(fa));
  fa.dwResetPeriod = s->reset_period_s;
  fa.cActions = SVC_SCM_RESTART_COUNT;
  fa.lpsaActions = acts;
  /* SC_ACTION_RESTART needs SERVICE_START on the handle as well, or ChangeServiceConfig2 fails with
     ERROR_ACCESS_DENIED even for SYSTEM (and the install rolls back) */
  e = open_service(SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG | SERVICE_START, &scm, &svc);
  if (e != 0)
    return e;
  if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa))
    e = GetLastError();
  close_handles(scm, svc);
  return e;
}

static DWORD scm_set_sid_type(void *ctx, DWORD sid_type)
{
  SC_HANDLE scm = NULL, svc = NULL;
  svc_sid_info_s info;
  DWORD e;
  (void)ctx;
  info.type = sid_type;
  e = open_service(SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, &scm, &svc);
  if (e != 0)
    return e;
  if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &info))
    e = GetLastError();
  close_handles(scm, svc);
  return e;
}

static DWORD scm_delete_service(void *ctx)
{
  SC_HANDLE scm = NULL, svc = NULL;
  DWORD e;
  (void)ctx;
  e = open_service(SC_MANAGER_CONNECT, DELETE, &scm, &svc);
  if (e != 0)
    return e;
  if (!DeleteService(svc))
    e = GetLastError();
  close_handles(scm, svc);
  return e;
}

static DWORD scm_start_service(void *ctx)
{
  SC_HANDLE scm = NULL, svc = NULL;
  SERVICE_STATUS st;
  DWORD waited = 0, e;
  (void)ctx;
  e = open_service(SC_MANAGER_CONNECT, SERVICE_START | SERVICE_QUERY_STATUS, &scm, &svc);
  if (e != 0)
    return e;
  if (!StartServiceW(svc, 0, NULL)) {
    e = GetLastError();
    close_handles(scm, svc);
    return e;
  }
  for (;;) {
    if (!QueryServiceStatus(svc, &st)) {
      e = GetLastError();
      break;
    }
    if (st.dwCurrentState == SERVICE_RUNNING) {
      e = 0;
      break;
    }
    if (st.dwCurrentState == SERVICE_STOPPED) {
      e = st.dwWin32ExitCode != 0 ? st.dwWin32ExitCode : ERROR_SERVICE_NEVER_STARTED;
      break;
    }
    if (waited >= SVC_SCM_START_WAIT_MS) {
      e = ERROR_SERVICE_REQUEST_TIMEOUT;
      break;
    }
    Sleep(SVC_SCM_POLL_MS);
    waited += SVC_SCM_POLL_MS;
  }
  close_handles(scm, svc);
  return e;
}

static DWORD scm_stop_service(void *ctx)
{
  SC_HANDLE scm = NULL, svc = NULL;
  SERVICE_STATUS st;
  DWORD waited = 0, e;
  (void)ctx;
  e = open_service(SC_MANAGER_CONNECT, SERVICE_STOP | SERVICE_QUERY_STATUS, &scm, &svc);
  if (e != 0)
    return e;
  if (!QueryServiceStatus(svc, &st)) {
    e = GetLastError();
    close_handles(scm, svc);
    return e;
  }
  if (st.dwCurrentState == SERVICE_STOPPED) {
    close_handles(scm, svc);
    return ERROR_SERVICE_NOT_ACTIVE;
  }
  if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
    e = GetLastError();
    close_handles(scm, svc);
    return e;
  }
  for (;;) {
    if (!QueryServiceStatus(svc, &st)) {
      e = GetLastError();
      break;
    }
    if (st.dwCurrentState == SERVICE_STOPPED) {
      e = 0;
      break;
    }
    if (waited >= SVC_SCM_STOP_WAIT_MS) {
      e = ERROR_SERVICE_REQUEST_TIMEOUT;
      break;
    }
    Sleep(SVC_SCM_POLL_MS);
    waited += SVC_SCM_POLL_MS;
  }
  close_handles(scm, svc);
  return e;
}

static DWORD scm_register_source(void *ctx, const wchar_t *source, const wchar_t *message_file, DWORD types)
{
  HKEY key = NULL;
  wchar_t path[256];
  DWORD e;
  (void)ctx;
  if (FAILED(StringCchPrintfW(path, SVC_SCM_COUNT(path), L"%s\\%s", SVC_SCM_EVENTLOG_APP, source)))
    return ERROR_BUFFER_OVERFLOW;
  e = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &key, NULL);
  if (e != ERROR_SUCCESS)
    return e;
  e = RegSetValueExW(key, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE *)message_file,
                     (DWORD)((lstrlenW(message_file) + 1) * sizeof(wchar_t)));
  if (e == ERROR_SUCCESS)
    e = RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD, (const BYTE *)&types, sizeof(types));
  RegCloseKey(key);
  return e;
}

static DWORD scm_unregister_source(void *ctx, const wchar_t *source)
{
  wchar_t path[256];
  (void)ctx;
  if (FAILED(StringCchPrintfW(path, SVC_SCM_COUNT(path), L"%s\\%s", SVC_SCM_EVENTLOG_APP, source)))
    return ERROR_BUFFER_OVERFLOW;
  return (DWORD)RegDeleteKeyW(HKEY_LOCAL_MACHINE, path);
}

/* TokenElevation (20) is Vista+; on XP the query fails and the SCM decides (access denied for non-admins). */
static int scm_is_elevated(void *ctx)
{
  HANDLE tok = NULL;
  DWORD elevated = 0, len = 0;
  int r = 1;
  (void)ctx;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 1;
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20, &elevated, sizeof(elevated), &len))
    r = elevated ? 1 : 0;
  CloseHandle(tok);
  return r;
}

static int scm_is_vista_or_later(void *ctx)
{
  (void)ctx;
  return sd_os_at_least(6, 0, 0);
}

/* Read-only: OpenSCManager with SC_MANAGER_CONNECT and OpenService with the query rights, which the default service
   security descriptor grants to every interactive user. A missing service is reported through out->installed. */
static DWORD scm_query_service(void *ctx, svc_status_report *out)
{
  SC_HANDLE scm = NULL, svc = NULL;
  SERVICE_STATUS st;
  QUERY_SERVICE_CONFIGW *cfg = NULL;
  DWORD e = 0, need = 0;
  BOOL ok;
  (void)ctx;
  out->installed = 0;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL)
    return GetLastError();
  svc = OpenServiceW(scm, SVC_SCM_SERVICE_NAME, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (svc == NULL) {
    e = GetLastError();
    CloseServiceHandle(scm);
    return e == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : e;
  }
  out->installed = 1;
  if (!QueryServiceStatus(svc, &st)) {
    e = GetLastError();
  } else {
    out->state = st.dwCurrentState;
    ok = QueryServiceConfigW(svc, NULL, 0, &need);
    if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && need > 0) {
      cfg = (QUERY_SERVICE_CONFIGW *)LocalAlloc(LMEM_FIXED, need);
      if (cfg == NULL)
        e = ERROR_NOT_ENOUGH_MEMORY;
      else if (!QueryServiceConfigW(svc, cfg, need, &need))
        e = GetLastError();
      else {
        out->start_type = cfg->dwStartType;
        if (cfg->lpBinaryPathName != NULL)
          (void)StringCchCopyW(out->binary, SVC_SCM_COUNT(out->binary), cfg->lpBinaryPathName);
      }
    } else {
      e = ok ? ERROR_INVALID_DATA : GetLastError();
    }
  }
  if (cfg != NULL)
    LocalFree(cfg);
  close_handles(scm, svc);
  return e;
}

/* Read-only: HKLM\...\EventLog\Application\<source>\EventMessageFile. A missing source is ERROR_FILE_NOT_FOUND; a source
   without a message file value gives an empty string (reported as another program's). */
static DWORD scm_query_source(void *ctx, const wchar_t *source, wchar_t *message_file, size_t cch)
{
  HKEY key = NULL;
  wchar_t path[256];
  DWORD e, type = 0, bytes;
  (void)ctx;
  if (message_file == NULL || cch == 0)
    return ERROR_INSUFFICIENT_BUFFER;
  message_file[0] = 0;
  if (FAILED(StringCchPrintfW(path, SVC_SCM_COUNT(path), L"%s\\%s", SVC_SCM_EVENTLOG_APP, source)))
    return ERROR_BUFFER_OVERFLOW;
  e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key);
  if (e != ERROR_SUCCESS)
    return e;
  bytes = (DWORD)(cch * sizeof(wchar_t));
  e = RegQueryValueExW(key, L"EventMessageFile", NULL, &type, (LPBYTE)message_file, &bytes);
  RegCloseKey(key);
  if (e == ERROR_FILE_NOT_FOUND || e == ERROR_MORE_DATA) {
    message_file[0] = 0;
    return ERROR_SUCCESS;
  }
  if (e != ERROR_SUCCESS)
    return e;
  if (type != REG_SZ && type != REG_EXPAND_SZ) {
    message_file[0] = 0;
    return ERROR_SUCCESS;
  }
  if (bytes / sizeof(wchar_t) < cch)
    message_file[bytes / sizeof(wchar_t)] = 0;
  message_file[cch - 1] = 0;
  return ERROR_SUCCESS;
}

int svc_scm_real_ops(svc_scm_ops *out)
{
  memset(out, 0, sizeof(*out));
  out->ctx = NULL;
  out->create_service = scm_create_service;
  out->set_description = scm_set_description;
  out->set_failure_actions = scm_set_failure_actions;
  out->set_sid_type = scm_set_sid_type;
  out->delete_service = scm_delete_service;
  out->start_service = scm_start_service;
  out->stop_service = scm_stop_service;
  out->register_source = scm_register_source;
  out->unregister_source = scm_unregister_source;
  out->is_elevated = scm_is_elevated;
  out->is_vista_or_later = scm_is_vista_or_later;
  out->query_service = scm_query_service;
  out->query_source = scm_query_source;
  return 0;
}
