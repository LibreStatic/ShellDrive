/* shelldrive diag --check (03 §10.5), diag --fix (03 §6.1, §1.7.2, §10.5) and the seam of the real system.
 * The support bundle is in cli_bundle.c. User-facing text comes from the cli catalog; JSON keys stay English. */
#include <windows.h>
#include <winsvc.h>
#include <string.h>
#include <stdio.h>

#include "cli_int.h"
#include "cli_diag.h"
#include "sd/version.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_config/sd_ini.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"
#include "sd_platform/sd_platform.h"
#include "sd_policy/sd_policy.h"
#include "svc_scm.h"

#define DIAG_WEBCLIENT_SERVICE  L"WebClient"
#define DIAG_W32TIME_SERVICE    L"W32Time"
#define DIAG_LINKED_KEY         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define DIAG_LINKED_VALUE       L"EnableLinkedConnections"
#define DIAG_WEBDAV_KEY         L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters"
#define DIAG_WEBDAV_SIZE_TUNED  0xFFFFFFFFu
#define DIAG_WEBDAV_ATTR_TUNED  100000000u
#define DIAG_WAIT_MS            10000u

/* ---- argument helpers for sd_l10n_format ---- */

#define ARG_S(i_, name_, value_) do { args[i_].name = name_; args[i_].type = SD_ARG_STR; args[i_].v.s = (value_); } while (0)
#define ARG_I(i_, name_, value_) do { args[i_].name = name_; args[i_].type = SD_ARG_INT; args[i_].v.i = (value_); } while (0)

/* Formats a catalog message into dst (truncated, never more than cch - 1 characters). */
static void format_to(wchar_t *dst, size_t cch, sd_msg_id id, const sd_arg *args, size_t n)
{
  wchar_t *s = sd_l10n_format_alloc(id, args, n);
  if (cch == 0)
    return;
  dst[0] = 0;
  if (s == NULL)
    return;
  wcsncpy_s(dst, cch, s, _TRUNCATE);
  sd_free(s);
}

static const wchar_t *tr(sd_msg_id id)
{
  return sd_l10n_get(id);
}

/* ---- the real system (registry, SCM, file system; read-only except the three changes) ---- */

static DWORD reg_get_dword(HKEY root, const wchar_t *path, const wchar_t *name, DWORD *out)
{
  HKEY k = NULL;
  DWORD type = 0, v = 0, sz = sizeof(v);
  LONG r = RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &k);
  if (r != ERROR_SUCCESS)
    return (DWORD)r;
  r = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)&v, &sz);
  RegCloseKey(k);
  if (r != ERROR_SUCCESS)
    return (DWORD)r;
  if (type != REG_DWORD || sz != sizeof(v))
    return ERROR_INVALID_DATA;
  *out = v;
  return ERROR_SUCCESS;
}

static diag_wc_state real_webclient_state(void *ctx, DWORD *start_type)
{
  SC_HANDLE scm, svc;
  SERVICE_STATUS ss;
  DWORD need = 0;
  diag_wc_state st = DIAG_WC_UNKNOWN;
  uint8_t buf[8192];
  QUERY_SERVICE_CONFIGW *qc = (QUERY_SERVICE_CONFIGW *)buf;
  (void)ctx;
  *start_type = DIAG_NOT_SET;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL)
    return DIAG_WC_UNKNOWN;
  svc = OpenServiceW(scm, DIAG_WEBCLIENT_SERVICE, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (svc == NULL) {
    st = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? DIAG_WC_MISSING : DIAG_WC_UNKNOWN;
    CloseServiceHandle(scm);
    return st;
  }
  if (QueryServiceConfigW(svc, qc, sizeof(buf), &need))
    *start_type = qc->dwStartType;
  if (QueryServiceStatus(svc, &ss)) {
    if (ss.dwCurrentState == SERVICE_RUNNING)
      st = DIAG_WC_RUNNING;
    else
      st = (*start_type == SERVICE_DISABLED) ? DIAG_WC_DISABLED : DIAG_WC_STOPPED;
  }
  CloseServiceHandle(svc);
  CloseServiceHandle(scm);
  return st;
}

static __int64 real_webdav_value(void *ctx, int which)
{
  DWORD v = 0;
  const wchar_t *name = which == DIAG_WEBDAV_FILE_SIZE ? L"FileSizeLimitInBytes" :
                        which == DIAG_WEBDAV_FILE_ATTRIBUTES ? L"FileAttributesLimitInBytes" : L"BasicAuthLevel";
  (void)ctx;
  if (reg_get_dword(HKEY_LOCAL_MACHINE, DIAG_WEBDAV_KEY, name, &v) != ERROR_SUCCESS)
    return -1;
  return (__int64)v;
}

static DWORD real_linked_connections(void *ctx)
{
  DWORD v = DIAG_NOT_SET;
  (void)ctx;
  if (reg_get_dword(HKEY_LOCAL_MACHINE, DIAG_LINKED_KEY, DIAG_LINKED_VALUE, &v) != ERROR_SUCCESS)
    return DIAG_NOT_SET;
  return v;
}

static int real_dokany_present(void *ctx)
{
  wchar_t dir[MAX_PATH];
  (void)ctx;
  if (GetSystemDirectoryW(dir, MAX_PATH) == 0 || wcslen(dir) + 16 >= MAX_PATH)
    return 0;
  wcscat_s(dir, MAX_PATH, L"\\dokan2.dll");
  return GetFileAttributesW(dir) != INVALID_FILE_ATTRIBUTES;
}

/* Vista+: TokenElevationType of the process token. Limited = an administrator account with a filtered token. */
static int real_split_token(void *ctx)
{
  HANDLE tok = NULL;
  DWORD type = 0, len = 0;
  int r = 0;
  (void)ctx;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)18 /* TokenElevationType */, &type, sizeof(type), &len))
    r = type == 3 /* TokenElevationTypeLimited */;
  CloseHandle(tok);
  return r;
}

static int real_service_running(const wchar_t *name)
{
  SC_HANDLE scm, svc;
  SERVICE_STATUS ss;
  int r = 0;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL)
    return 0;
  svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
  if (svc) {
    if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING)
      r = 1;
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
  return r;
}

static int real_time_service_running(void *ctx)
{
  (void)ctx;
  return real_service_running(DIAG_W32TIME_SERVICE);
}

/* A computer joined to a domain has USERDNSDOMAIN in the environment (set by the logon). */
static int real_domain_joined(void *ctx)
{
  wchar_t v[256];
  (void)ctx;
  return GetEnvironmentVariableW(L"USERDNSDOMAIN", v, SD_COUNTOF(v)) > 0;
}

static DWORD real_drive_mask(void *ctx)
{
  (void)ctx;
  return (DWORD)GetLogicalDrives();
}

static DWORD real_webclient_set_start(void *ctx, DWORD start_type)
{
  typedef BOOL (WINAPI *pfn_change)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR,
                                    LPCWSTR, LPCWSTR);
  pfn_change change = (pfn_change)sd_platform_resolve_by_name(L"advapi32.dll", "ChangeServiceConfigW");
  SC_HANDLE scm, svc;
  DWORD err = 0;
  (void)ctx;
  if (change == NULL)
    return ERROR_CALL_NOT_IMPLEMENTED;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL)
    return GetLastError();
  svc = OpenServiceW(scm, DIAG_WEBCLIENT_SERVICE, SERVICE_CHANGE_CONFIG);
  if (svc == NULL) {
    err = GetLastError();
  } else {
    /* only the start type changes (SERVICE_NO_CHANGE keeps the rest) */
    if (!change(svc, SERVICE_NO_CHANGE, start_type, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
      err = GetLastError();
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
  return err;
}

static DWORD real_webclient_start(void *ctx)
{
  SC_HANDLE scm, svc;
  SERVICE_STATUS ss;
  DWORD err = 0, waited = 0;
  (void)ctx;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL)
    return GetLastError();
  svc = OpenServiceW(scm, DIAG_WEBCLIENT_SERVICE, SERVICE_START | SERVICE_QUERY_STATUS);
  if (svc == NULL) {
    err = GetLastError();
  } else {
    if (!StartServiceW(svc, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
      err = GetLastError();
    while (err == 0 && waited < DIAG_WAIT_MS && QueryServiceStatus(svc, &ss) && ss.dwCurrentState != SERVICE_RUNNING) {
      Sleep(200);
      waited += 200;
    }
    if (err == 0 && (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState != SERVICE_RUNNING))
      err = ERROR_SERVICE_REQUEST_TIMEOUT;
    CloseServiceHandle(svc);
  }
  CloseServiceHandle(scm);
  return err;
}

static DWORD real_linked_set(void *ctx, DWORD value)
{
  HKEY k = NULL;
  LONG r;
  (void)ctx;
  r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, DIAG_LINKED_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
  if (r != ERROR_SUCCESS)
    return (DWORD)r;
  r = RegSetValueExW(k, DIAG_LINKED_VALUE, 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
  RegCloseKey(k);
  return (DWORD)r;
}

static int real_elevated(void *ctx)
{
  (void)ctx;
  return cli_is_elevated();
}

static const diag_env k_real_env = {
  NULL,
  real_webclient_state, real_webdav_value, real_linked_connections, real_dokany_present,
  real_split_token, real_elevated, real_time_service_running, real_domain_joined, real_drive_mask,
  real_webclient_set_start, real_webclient_start, real_linked_set
};

const diag_env *diag_env_real(void)
{
  return &k_real_env;
}

const diag_env *diag_env_current(void)
{
#ifdef SD_CLI_TEST_HOOKS
  wchar_t v[MAX_PATH];
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    return diag_env_fake();
#endif
  return &k_real_env;
}

/* ---- file helpers ---- */

int diag_read_file(const wchar_t *path, char **buf, size_t *len)
{
  HANDLE h;
  LARGE_INTEGER size;
  char *p;
  DWORD got = 0;
  *buf = NULL;
  *len = 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &size) || size.QuadPart > 64 * 1024 * 1024) {
    CloseHandle(h);
    return 0;
  }
  p = (char *)sd_alloc((size_t)size.QuadPart + 1);
  if (p == NULL) {
    CloseHandle(h);
    return 0;
  }
  if (!ReadFile(h, p, (DWORD)size.QuadPart, &got, NULL) || got != (DWORD)size.QuadPart) {
    CloseHandle(h);
    sd_free(p);
    return 0;
  }
  CloseHandle(h);
  p[got] = 0;
  *buf = p;
  *len = got;
  return 1;
}

/* settings.ini [log] privacy = strict (the user's setting; the policy is read separately). */
static int settings_strict(void)
{
  wchar_t root[MAX_PATH];
  char *buf = NULL;
  size_t len = 0;
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  int strict = 0;
  if (sd_config_root(root, SD_COUNTOF(root)) != SD_OK)
    return 0;
  wcscat_s(root, SD_COUNTOF(root), L"\\settings.ini");
  if (!diag_read_file(root, &buf, &len))
    return 0;
  if (sd_ini_parse(buf, len, &ini, &flags) == SD_OK) {
    const char *v = sd_ini_get(ini, "log", "privacy");
    strict = v != NULL && _stricmp(v, "strict") == 0;
    sd_ini_free(ini);
  }
  sd_free(buf);
  return strict;
}

/* ---- the agent (IPC, never started by a check) ---- */

static int agent_running(void)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK)
    return 0;
  sd_ipc_close(c);
  return 1;
}

/* ---- collection ---- */

static void set_row(diag_report *r, int row, int status, sd_msg_id id, const sd_arg *args, size_t n)
{
  r->status[row] = status;
  format_to(r->text[row], SD_COUNTOF(r->text[row]), id, args, n);
}

void diag_collect(const diag_env *env, diag_report *r)
{
  const sd_os_version *ov;
  sd_arg args[4];
  SYSTEMTIME st;
  TIME_ZONE_INFORMATION tz;
  DWORD tzr;
  DWORD wc_start = DIAG_NOT_SET;
  diag_wc_state wc;
  svc_scm_ops ops;
  svc_status_report svc;
  int i, free_letters = 0;
  DWORD mask;
  memset(r, 0, sizeof(*r));

  /* OS */
  ov = sd_os_version_get();
  r->os_major = (int)ov->major;
  r->os_minor = (int)ov->minor;
  r->os_build = (int)ov->build;
  _snwprintf_s(r->version, SD_COUNTOF(r->version), _TRUNCATE, L"%u.%u.%u", (unsigned)ov->major,
               (unsigned)ov->minor, (unsigned)ov->build);
  _snwprintf_s(r->flavour, SD_COUNTOF(r->flavour), _TRUNCATE, L"%S", SD_FLAVOUR_NAME);
  ARG_S(0, "version", r->version);
  ARG_S(1, "flavour", r->flavour);
  set_row(r, DIAG_ROW_OS, DIAG_OK, SD_MSG_CLI_DIAG_V_OS, args, 2);

  /* local time and UTC offset (the clock hint) */
  GetLocalTime(&st);
  _snwprintf_s(r->local_time, SD_COUNTOF(r->local_time), _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02u",
               (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour,
               (unsigned)st.wMinute, (unsigned)st.wSecond);
  memset(&tz, 0, sizeof(tz));
  tzr = GetTimeZoneInformation(&tz);
  {
    LONG bias = tz.Bias;
    if (tzr == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
    /* Bias is UTC minus local time, in minutes */
    _snprintf_s(r->utc_offset, sizeof(r->utc_offset), _TRUNCATE, "%c%02d:%02d", bias <= 0 ? '+' : '-',
                (int)((bias < 0 ? -bias : bias) / 60), (int)((bias < 0 ? -bias : bias) % 60));
  }

  /* agent and service */
  r->agent_running = agent_running();
  if (svc_scm_real_ops(&ops) == 0 && svc_scm_status(&ops, NULL, &svc) == 0) {
    r->service_installed = svc.installed;
    r->service_running = svc.installed && svc.state == SERVICE_RUNNING;
  }

  /* WebClient, WebDAV limits, Dokany, linked connections, elevation, domain, drives, time service */
  wc = env->webclient_state(env->ctx, &wc_start);
  r->webclient = wc;
  r->webclient_start = wc_start;
  r->domain_joined = env->domain_joined(env->ctx);
  r->size_limit = env->webdav_value(env->ctx, DIAG_WEBDAV_FILE_SIZE);
  r->attr_limit = env->webdav_value(env->ctx, DIAG_WEBDAV_FILE_ATTRIBUTES);
  r->auth_level = env->webdav_value(env->ctx, DIAG_WEBDAV_BASIC_AUTH);
  /* (-1 = not set: the limits are 64-bit so that 0xFFFFFFFF, the tuned value, stays a number) */
  r->dokany = env->dokany_present(env->ctx);
  r->linked_on = env->linked_connections(env->ctx) == 1;
  r->split_token = env->split_token(env->ctx);
  r->elevated = env->elevated(env->ctx);
  r->time_running = env->time_service_running(env->ctx);
  mask = env->drive_mask(env->ctx);
  for (i = 3; i < 26; i++)        /* D: .. Z: (ShellDrive mounts from D on) */
    if (!(mask & (1u << i))) free_letters++;
  r->free_letters = free_letters;

  /* settings and privacy */
  {
    sd_settings s;
    r->settings_ok = sd_settings_load(&s) == SD_OK;
  }
  {
    DWORD pol = 0;
    r->privacy_strict = (sd_policy_get_dword(SD_POLICY_LOGPRIVACY, &pol) && pol == 1) || settings_strict();
  }

  /* ---- rows ---- */
  /* agent */
  set_row(r, DIAG_ROW_AGENT, DIAG_OK, r->agent_running ? SD_MSG_CLI_DIAG_V_AGENT_RUNNING : SD_MSG_CLI_DIAG_V_AGENT_STOPPED,
          NULL, 0);
  /* service */
  if (!r->service_installed)
    set_row(r, DIAG_ROW_SERVICE, DIAG_OK, SD_MSG_CLI_DIAG_V_SERVICE_MISSING, NULL, 0);
  else if (r->service_running)
    set_row(r, DIAG_ROW_SERVICE, DIAG_OK, SD_MSG_CLI_DIAG_V_SERVICE_RUNNING, NULL, 0);
  else
    set_row(r, DIAG_ROW_SERVICE, DIAG_OK, SD_MSG_CLI_DIAG_V_SERVICE_STOPPED, NULL, 0);
  /* WebClient */
  switch (wc) {
  case DIAG_WC_RUNNING:
    if (r->domain_joined)
      set_row(r, DIAG_ROW_WEBCLIENT, DIAG_WARN, SD_MSG_CLI_DIAG_V_WEBCLIENT_DOMAIN, NULL, 0);
    else
      set_row(r, DIAG_ROW_WEBCLIENT, DIAG_OK, SD_MSG_CLI_DIAG_V_WEBCLIENT_RUNNING, NULL, 0);
    break;
  case DIAG_WC_STOPPED: set_row(r, DIAG_ROW_WEBCLIENT, DIAG_OK, SD_MSG_CLI_DIAG_V_WEBCLIENT_STOPPED, NULL, 0); break;
  case DIAG_WC_DISABLED: set_row(r, DIAG_ROW_WEBCLIENT, DIAG_OK, SD_MSG_CLI_DIAG_V_WEBCLIENT_DISABLED, NULL, 0); break;
  case DIAG_WC_MISSING: set_row(r, DIAG_ROW_WEBCLIENT, DIAG_OK, SD_MSG_CLI_DIAG_V_WEBCLIENT_MISSING, NULL, 0); break;
  default: set_row(r, DIAG_ROW_WEBCLIENT, DIAG_WARN, SD_MSG_CLI_DIAG_V_UNKNOWN, NULL, 0); break;
  }
  /* WebDAV limits (02 §7.1): the installer hook webdav-tune sets both */
  {
    wchar_t size_t_[24], attr_t[24];
    if (r->size_limit < 0) wcscpy_s(size_t_, SD_COUNTOF(size_t_), tr(SD_MSG_CLI_DIAG_V_NOT_SET));
    else _snwprintf_s(size_t_, SD_COUNTOF(size_t_), _TRUNCATE, L"%I64d", r->size_limit);
    if (r->attr_limit < 0) wcscpy_s(attr_t, SD_COUNTOF(attr_t), tr(SD_MSG_CLI_DIAG_V_NOT_SET));
    else _snwprintf_s(attr_t, SD_COUNTOF(attr_t), _TRUNCATE, L"%I64d", r->attr_limit);
    ARG_S(0, "size", size_t_);
    ARG_S(1, "attributes", attr_t);
    if (r->size_limit == DIAG_WEBDAV_SIZE_TUNED && r->attr_limit == DIAG_WEBDAV_ATTR_TUNED)
      set_row(r, DIAG_ROW_WEBDAV, DIAG_OK, SD_MSG_CLI_DIAG_V_WEBDAV, args, 2);
    else
      set_row(r, DIAG_ROW_WEBDAV, DIAG_WARN, SD_MSG_CLI_DIAG_V_WEBDAV_DEFAULT, args, 2);
  }
  /* Dokany */
  set_row(r, DIAG_ROW_DOKANY, DIAG_OK, r->dokany ? SD_MSG_CLI_DIAG_V_PRESENT : SD_MSG_CLI_DIAG_V_ABSENT, NULL, 0);
  /* linked connections (1.7.2) */
  if (r->linked_on)
    set_row(r, DIAG_ROW_LINKED, DIAG_OK, SD_MSG_CLI_DIAG_V_LINKED_ON, NULL, 0);
  else if (r->split_token)
    set_row(r, DIAG_ROW_LINKED, DIAG_WARN, SD_MSG_CLI_DIAG_V_LINKED_OFF_ADMIN, NULL, 0);
  else
    set_row(r, DIAG_ROW_LINKED, DIAG_OK, SD_MSG_CLI_DIAG_V_LINKED_OFF, NULL, 0);
  /* elevation */
  if (r->elevated)
    set_row(r, DIAG_ROW_ELEVATION, DIAG_OK, SD_MSG_CLI_DIAG_V_ELEV_YES, NULL, 0);
  else if (r->split_token)
    set_row(r, DIAG_ROW_ELEVATION, DIAG_OK, SD_MSG_CLI_DIAG_V_ELEV_SPLIT, NULL, 0);
  else
    set_row(r, DIAG_ROW_ELEVATION, DIAG_OK, SD_MSG_CLI_DIAG_V_ELEV_NO, NULL, 0);
  /* domain */
  set_row(r, DIAG_ROW_DOMAIN, DIAG_OK, r->domain_joined ? SD_MSG_CLI_DIAG_V_DOMAIN_YES : SD_MSG_CLI_DIAG_V_DOMAIN_NO,
          NULL, 0);
  /* drives */
  ARG_I(0, "count", free_letters);
  set_row(r, DIAG_ROW_DRIVES, free_letters > 0 ? DIAG_OK : DIAG_WARN, SD_MSG_CLI_DIAG_V_DRIVES, args, 1);
  /* settings */
  set_row(r, DIAG_ROW_SETTINGS, r->settings_ok ? DIAG_OK : DIAG_PROBLEM,
          r->settings_ok ? SD_MSG_CLI_DIAG_V_SETTINGS_OK : SD_MSG_CLI_DIAG_V_SETTINGS_BAD, NULL, 0);
  /* log privacy (03 §10.1) */
  set_row(r, DIAG_ROW_PRIVACY, DIAG_OK,
          r->privacy_strict ? SD_MSG_CLI_DIAG_V_PRIVACY_STRICT : SD_MSG_CLI_DIAG_V_PRIVACY_STANDARD, NULL, 0);
  /* clock: a stopped Windows Time service is the hint */
  {
    wchar_t off[12];
    _snwprintf_s(off, SD_COUNTOF(off), _TRUNCATE, L"%S", r->utc_offset);
    ARG_S(0, "time", r->local_time);
    ARG_S(1, "offset", off);
    ARG_S(2, "state", tr(r->time_running ? SD_MSG_CLI_DIAG_V_W32_RUNNING : SD_MSG_CLI_DIAG_V_W32_STOPPED));
    set_row(r, DIAG_ROW_CLOCK, r->time_running ? DIAG_OK : DIAG_WARN, SD_MSG_CLI_DIAG_V_CLOCK, args, 3);
  }
}

int diag_has_problem(const diag_report *r)
{
  int i;
  for (i = 0; i < DIAG_ROW_COUNT; i++)
    if (r->status[i] == DIAG_PROBLEM)
      return 1;
  return 0;
}

static const char *status_word(int s)
{
  return s == DIAG_PROBLEM ? "problem" : s == DIAG_WARN ? "warn" : "ok";
}

static const char *wc_word(diag_wc_state s)
{
  switch (s) {
  case DIAG_WC_RUNNING: return "running";
  case DIAG_WC_STOPPED: return "stopped";
  case DIAG_WC_DISABLED: return "disabled";
  case DIAG_WC_MISSING: return "missing";
  default: return "unknown";
  }
}

static void jw_limit(sd_json_writer *jw, const char *key, __int64 v)
{
  sd_jw_key(jw, key);
  if (v < 0) sd_jw_null(jw);
  else sd_jw_int(jw, (int64_t)v);
}

void diag_json_result(const diag_report *r, sd_json_writer *jw)
{
  int problems = 0, i;
  for (i = 0; i < DIAG_ROW_COUNT; i++)
    if (r->status[i] == DIAG_PROBLEM) problems++;
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "checks");
  sd_jw_obj_begin(jw);

  sd_jw_key(jw, "os"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_OS]));
  {
    char ver[32];
    sprintf_s(ver, sizeof(ver), "%d.%d.%d", r->os_major, r->os_minor, r->os_build);
    sd_jw_key(jw, "version"); sd_jw_cstr(jw, ver);
  }
  sd_jw_key(jw, "flavour"); sd_jw_cstr(jw, SD_FLAVOUR_NAME);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "agent"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_AGENT]));
  sd_jw_key(jw, "running"); sd_jw_bool(jw, r->agent_running);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "service"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_SERVICE]));
  sd_jw_key(jw, "installed"); sd_jw_bool(jw, r->service_installed);
  sd_jw_key(jw, "running"); sd_jw_bool(jw, r->service_running);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "webclient"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_WEBCLIENT]));
  sd_jw_key(jw, "state"); sd_jw_cstr(jw, wc_word(r->webclient));
  sd_jw_key(jw, "start_type"); if (r->webclient_start == DIAG_NOT_SET) sd_jw_null(jw); else sd_jw_int(jw, (int64_t)r->webclient_start);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "webdav"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_WEBDAV]));
  jw_limit(jw, "file_size_limit", r->size_limit);
  jw_limit(jw, "file_attributes_limit", r->attr_limit);
  jw_limit(jw, "basic_auth_level", r->auth_level);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "dokany"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_DOKANY]));
  sd_jw_key(jw, "present"); sd_jw_bool(jw, r->dokany);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "linked_connections"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_LINKED]));
  sd_jw_key(jw, "enabled"); sd_jw_bool(jw, r->linked_on);
  sd_jw_key(jw, "split_token_admin"); sd_jw_bool(jw, r->split_token);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "elevation"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_ELEVATION]));
  sd_jw_key(jw, "elevated"); sd_jw_bool(jw, r->elevated);
  sd_jw_key(jw, "split_token"); sd_jw_bool(jw, r->split_token);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "domain"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_DOMAIN]));
  sd_jw_key(jw, "joined"); sd_jw_bool(jw, r->domain_joined);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "drives"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_DRIVES]));
  sd_jw_key(jw, "free_letters"); sd_jw_int(jw, r->free_letters);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "settings"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_SETTINGS]));
  sd_jw_key(jw, "readable"); sd_jw_bool(jw, r->settings_ok);
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "log_privacy"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_PRIVACY]));
  sd_jw_key(jw, "mode"); sd_jw_cstr(jw, r->privacy_strict ? "strict" : "standard");
  sd_jw_obj_end(jw);

  sd_jw_key(jw, "clock"); sd_jw_obj_begin(jw);
  sd_jw_key(jw, "status"); sd_jw_cstr(jw, status_word(r->status[DIAG_ROW_CLOCK]));
  sd_jw_key(jw, "utc_offset"); sd_jw_cstr(jw, r->utc_offset);
  sd_jw_key(jw, "time_service_running"); sd_jw_bool(jw, r->time_running);
  sd_jw_obj_end(jw);

  sd_jw_obj_end(jw);
  sd_jw_key(jw, "problems"); sd_jw_int(jw, problems);
  sd_jw_obj_end(jw);
}

void diag_print_text(const diag_report *r)
{
  sd_arg args[3];
  int i;
  ARG_S(0, "version", SD_VERSION_STRING_W);
  say(SD_MSG_CLI_DIAG_HEADER, args, 1, 0);
  for (i = 0; i < DIAG_ROW_COUNT; i++) {
    static const sd_msg_id labels[DIAG_ROW_COUNT] = {
      SD_MSG_CLI_DIAG_LABEL_OS, SD_MSG_CLI_DIAG_LABEL_AGENT, SD_MSG_CLI_DIAG_LABEL_SERVICE,
      SD_MSG_CLI_DIAG_LABEL_WEBCLIENT, SD_MSG_CLI_DIAG_LABEL_WEBDAV, SD_MSG_CLI_DIAG_LABEL_DOKANY,
      SD_MSG_CLI_DIAG_LABEL_LINKED, SD_MSG_CLI_DIAG_LABEL_ELEVATION, SD_MSG_CLI_DIAG_LABEL_DOMAIN,
      SD_MSG_CLI_DIAG_LABEL_DRIVES, SD_MSG_CLI_DIAG_LABEL_SETTINGS, SD_MSG_CLI_DIAG_LABEL_PRIVACY,
      SD_MSG_CLI_DIAG_LABEL_CLOCK
    };
    static const sd_msg_id statuses[3] = { SD_MSG_CLI_DIAG_STATUS_OK, SD_MSG_CLI_DIAG_STATUS_WARN,
                                           SD_MSG_CLI_DIAG_STATUS_PROBLEM };
    ARG_S(0, "status", tr(statuses[r->status[i]]));
    ARG_S(1, "label", tr(labels[i]));
    ARG_S(2, "value", r->text[i]);
    say(SD_MSG_CLI_DIAG_ROW, args, 3, 0);
  }
  {
    int problems = 0, i2;
    for (i2 = 0; i2 < DIAG_ROW_COUNT; i2++)
      if (r->status[i2] == DIAG_PROBLEM) problems++;
    if (problems == 0) {
      say(SD_MSG_CLI_DIAG_SUMMARY_OK, NULL, 0, 0);
    } else {
      ARG_I(0, "count", problems);
      say(SD_MSG_CLI_DIAG_SUMMARY_PROBLEM, args, 1, 0);
    }
  }
}

/* ---- diag --check ---- */

int cli_run_diag_check(const cli_args *a)
{
  diag_report r;
  const diag_env *env = diag_env_current();
  diag_collect(env, &r);
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, 16 * 1024);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result");
    diag_json_result(&r, &jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
  } else {
    diag_print_text(&r);
  }
  return diag_has_problem(&r) ? 1 : 0;
}

/* ---- diag --fix ---- */

/* Asks a yes/no question on stderr (stdout stays clean for --json). 1 = yes. */
static int confirm(const cli_args *a, sd_msg_id question)
{
  char line[64];
  cli_eprint_raw(tr(question));
  /* a piped standard input is an answer source too, as can_prompt() in cli_common.c decides */
  if (!cli_read_line(line, sizeof(line), 1, a->use_stdin || !cli_stdin_is_console()))
    return 0;
  return answer_is(line, SD_MSG_CLI_DIAG_LETTER_YES, SD_MSG_CLI_DIAG_WORD_YES);
}

/* A policy that excludes WebDAV ("AllowedBackends" set without "webdav") refuses the WebClient change (exit 15).
   An unset policy allows everything. */
static int policy_excludes_webdav(void)
{
  wchar_t v[128];
  size_t i, n;
  if (!sd_policy_get_sz(SD_POLICY_ALLOWEDBACKENDS, v, SD_COUNTOF(v)) || v[0] == 0)
    return 0;
  n = wcslen(v);
  for (i = 0; i + 6 <= n; i++)
    if (_wcsnicmp(v + i, L"webdav", 6) == 0)
      return 0;
  return 1;
}

static int fix_failed(const cli_args *a, DWORD err)
{
  wchar_t num[24];
  if (a->json) {
    char detail[64];
    sprintf_s(detail, sizeof(detail), "win32 error %lu", (unsigned long)err);
    json_err("io_error", detail, 1);
  } else {
    sd_arg arg;
    arg.name = "code"; arg.type = SD_ARG_STR; arg.v.s = decimal(num, SD_COUNTOF(num), (long long)err);
    say(SD_MSG_CLI_DIAG_FIX_FAILED, &arg, 1, 1);
  }
  return 1;
}

static void fix_done(const cli_args *a, const char *item, int changed, sd_msg_id text)
{
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, 1024);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result"); sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "item"); sd_jw_cstr(&jw, item);
    sd_jw_key(&jw, "changed"); sd_jw_bool(&jw, changed);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
  } else {
    say(text, NULL, 0, 0);
  }
}

int cli_run_diag_fix(const cli_args *a)
{
  const diag_env *env = diag_env_current();
  err_ctx ec;
  memset(&ec, 0, sizeof(ec));
  if (!env->elevated(env->ctx))
    return fail_code(a, "elevation_required", "administrator required", &ec);

  if (wcscmp(a->fix_item, L"webclient") == 0) {
    DWORD start = DIAG_NOT_SET, e;
    diag_wc_state st;
    if (policy_excludes_webdav())
      return fail_code(a, "policy_denied", "AllowedBackends excludes WebDAV", &ec);
    st = env->webclient_state(env->ctx, &start);
    if (st == DIAG_WC_MISSING)
      return fail_code(a, "backend_unavailable", "WebClient", &ec);
    if (st == DIAG_WC_RUNNING && (start == SERVICE_DEMAND_START || start == SERVICE_AUTO_START)) {
      fix_done(a, "webclient", 0, SD_MSG_CLI_DIAG_FIX_WEBCLIENT_UNCHANGED);
      return 0;
    }
    if (env->domain_joined(env->ctx) && !a->json)
      say(SD_MSG_CLI_DIAG_FIX_DOMAIN_NOTE, NULL, 0, 0);
    if (!a->yes && !confirm(a, SD_MSG_CLI_DIAG_FIX_CONFIRM_WEBCLIENT))
      return fail_code(a, "cancelled", "no change", &ec);
    e = env->webclient_set_start(env->ctx, SERVICE_DEMAND_START);
    if (e)
      return fix_failed(a, e);
    e = env->webclient_start(env->ctx);
    if (e)
      return fix_failed(a, e);
    fix_done(a, "webclient", 1, SD_MSG_CLI_DIAG_FIX_WEBCLIENT_DONE);
    return 0;
  }

  /* linked-connections */
  if (env->linked_connections(env->ctx) == 1) {
    fix_done(a, "linked-connections", 0, SD_MSG_CLI_DIAG_FIX_LINKED_UNCHANGED);
    return 0;
  }
  if (!a->yes && !confirm(a, SD_MSG_CLI_DIAG_FIX_CONFIRM_LINKED))
    return fail_code(a, "cancelled", "no change", &ec);
  {
    DWORD e = env->linked_set(env->ctx, 1);
    if (e)
      return fix_failed(a, e);
  }
  fix_done(a, "linked-connections", 1, SD_MSG_CLI_DIAG_FIX_LINKED_DONE);
  return 0;
}
