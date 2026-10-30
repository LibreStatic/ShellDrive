/* sd_webdav: token-only mode decision and the WinHTTP self-test (TM-R19, 02 §7.4).
 *
 * Token-only mode lets a per-user mount be used by clients that do not go through the WebDAV redirector
 * (for example LibreOffice opening an http URL). The per-mount token in the path is then the only
 * authenticator. It is refused unless every condition of TM-R19 holds; the decision is one pure function
 * so it can be tested without a machine state.
 *
 * winhttp.dll, wtsapi32.dll and their functions are resolved at run time (XP floor, no static import). */
#include <windows.h>
#include <winhttp.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "wd_server.h"

#define WD_POLICY_ABSENT (-1)

/* ---- decision ---- */

sd_webdav_tok_verdict sd_webdav_token_only_decide(const sd_webdav_tok_input *in)
{
  if (in == NULL)
    return SD_WD_TOK_FORBIDDEN_POLICY;
  if (in->global)
    return SD_WD_TOK_FORBIDDEN_GLOBAL;
  /* absent = the documented default (1); only 1 and absent allow, anything else is refused (fail closed) */
  if (in->policy != WD_POLICY_ABSENT && in->policy != 1)
    return SD_WD_TOK_FORBIDDEN_POLICY;
  if (!in->confirmed)
    return SD_WD_TOK_NOT_CONFIRMED;
  if (in->rdsh)
    return SD_WD_TOK_RDSH;
  if (in->active_sessions > 1u)               /* 0xFFFFFFFF (unknown) is refused too */
    return SD_WD_TOK_SESSIONS;
  return SD_WD_TOK_OK;
}

const char *sd_webdav_tok_verdict_name(sd_webdav_tok_verdict v)
{
  switch (v) {
  case SD_WD_TOK_OK: return "ok";
  case SD_WD_TOK_FORBIDDEN_GLOBAL: return "global mount";
  case SD_WD_TOK_FORBIDDEN_POLICY: return "AllowWebDavTokenOnly";
  case SD_WD_TOK_NOT_CONFIRMED: return "not confirmed";
  case SD_WD_TOK_RDSH: return "remote desktop session host or remote session";
  case SD_WD_TOK_SESSIONS: return "several active sessions";
  }
  return "unknown";
}

/* ---- environment (read-only) ---- */

/* "WinNT" is a workstation; ServerNT and LanmanNT (and anything unreadable) are treated as RDSH-capable. */
static BOOL workstation_product(void)
{
  HKEY k;
  DWORD type = 0, cb = 0;
  wchar_t buf[32];
  BOOL ok = FALSE;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", 0, KEY_QUERY_VALUE,
                    &k) != ERROR_SUCCESS)
    return FALSE;
  cb = sizeof(buf) - sizeof(buf[0]);
  memset(buf, 0, sizeof(buf));
  if (RegQueryValueExW(k, L"ProductType", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ)
    ok = _wcsicmp(buf, L"WinNT") == 0;
  RegCloseKey(k);
  return ok;
}

typedef BOOL (WINAPI *pfn_WTSEnumerateSessionsW)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
typedef VOID (WINAPI *pfn_WTSFreeMemory)(PVOID);

/* Count of WTSActive sessions, or 0xFFFFFFFF when the enumeration is not available. */
static DWORD count_active_sessions(void)
{
  pfn_WTSEnumerateSessionsW enumerate;
  pfn_WTSFreeMemory release;
  PWTS_SESSION_INFOW info = NULL;
  DWORD i, n = 0, active = 0;
  enumerate = (pfn_WTSEnumerateSessionsW)sd_platform_resolve_by_name(L"wtsapi32.dll", "WTSEnumerateSessionsW");
  release = (pfn_WTSFreeMemory)sd_platform_resolve_by_name(L"wtsapi32.dll", "WTSFreeMemory");
  if (enumerate == NULL || release == NULL)
    return 0xFFFFFFFFu;
  if (!enumerate(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &n) || info == NULL)
    return 0xFFFFFFFFu;
  for (i = 0; i < n; i++) {
    if (info[i].State == WTSActive)
      active++;
  }
  release(info);
  return active;
}

void sd_webdav_token_only_environment(sd_webdav_tok_input *io)
{
  if (io == NULL)
    return;
  io->rdsh = (GetSystemMetrics(SM_REMOTESESSION) != 0) || !workstation_product();
  io->active_sessions = count_active_sessions();
}

/* ---- WinHTTP self-test ---- */

typedef HINTERNET (WINAPI *pfn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetTimeouts)(HINTERNET, int, int, int, int);
typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pfn_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pfn_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpCloseHandle)(HINTERNET);

typedef struct wh_api {
  pfn_WinHttpOpen open;
  pfn_WinHttpConnect connect;
  pfn_WinHttpOpenRequest open_request;
  pfn_WinHttpSetOption set_option;
  pfn_WinHttpSetTimeouts set_timeouts;
  pfn_WinHttpSendRequest send;
  pfn_WinHttpReceiveResponse receive;
  pfn_WinHttpQueryHeaders query;
  pfn_WinHttpCloseHandle close;
} wh_api;

static int wh_load(wh_api *a)
{
  const wchar_t *dll = L"winhttp.dll";
  a->open = (pfn_WinHttpOpen)sd_platform_resolve_by_name(dll, "WinHttpOpen");
  a->connect = (pfn_WinHttpConnect)sd_platform_resolve_by_name(dll, "WinHttpConnect");
  a->open_request = (pfn_WinHttpOpenRequest)sd_platform_resolve_by_name(dll, "WinHttpOpenRequest");
  a->set_option = (pfn_WinHttpSetOption)sd_platform_resolve_by_name(dll, "WinHttpSetOption");
  a->set_timeouts = (pfn_WinHttpSetTimeouts)sd_platform_resolve_by_name(dll, "WinHttpSetTimeouts");
  a->send = (pfn_WinHttpSendRequest)sd_platform_resolve_by_name(dll, "WinHttpSendRequest");
  a->receive = (pfn_WinHttpReceiveResponse)sd_platform_resolve_by_name(dll, "WinHttpReceiveResponse");
  a->query = (pfn_WinHttpQueryHeaders)sd_platform_resolve_by_name(dll, "WinHttpQueryHeaders");
  a->close = (pfn_WinHttpCloseHandle)sd_platform_resolve_by_name(dll, "WinHttpCloseHandle");
  return a->open && a->connect && a->open_request && a->set_option && a->set_timeouts && a->send &&
         a->receive && a->query && a->close;
}

#ifndef WINHTTP_OPTION_AUTOLOGON_POLICY
#define WINHTTP_OPTION_AUTOLOGON_POLICY 77
#endif
#ifndef WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH
#define WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH 2
#endif
#ifndef WINHTTP_AUTOLOGON_SECURITY_LEVEL_PROXY_ONLY
#define WINHTTP_AUTOLOGON_SECURITY_LEVEL_PROXY_ONLY 3
#endif

/* Answers the 401 that the server sends for a path without a token (no automatic Negotiate).
   Every failure records its step and the Win32 error for wd_selftest_last_diag (unit tests have
   no log sink). */
static volatile uint32_t g_selftest_step, g_selftest_err;

void wd_selftest_last_diag(uint32_t *step, uint32_t *err)
{
  *step = g_selftest_step;
  *err = g_selftest_err;
}

static sd_err wh_probe(const wh_api *a, uint16_t port, const wchar_t *path, int *status)
{
  HINTERNET session, conn = NULL, req = NULL;
  DWORD code = 0, cb = sizeof(code), level = WINHTTP_AUTOLOGON_SECURITY_LEVEL_PROXY_ONLY;
  sd_err e = SD_E_FAILURE;
  *status = 0;
  g_selftest_step = 1;                              /* WinHttpOpen */
  session = a->open(L"ShellDrive-webdav-selftest", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                    WINHTTP_NO_PROXY_BYPASS, 0);
  if (session == NULL) {
    g_selftest_err = GetLastError();
    return SD_E_FAILURE;
  }
  a->set_timeouts(session, 15000, 15000, 15000, 15000);
  /* numeric IPv4 loopback: "localhost" resolves to ::1 first on some systems, where the server
     does not listen, and this probe is about this machine's server only (never leaves it) */
  g_selftest_step = 2;                              /* WinHttpConnect */
  conn = a->connect(session, L"127.0.0.1", (INTERNET_PORT)port, 0);
  if (conn == NULL) { g_selftest_err = GetLastError(); goto out; }
  g_selftest_step = 3;                              /* WinHttpOpenRequest */
  req = a->open_request(conn, L"PROPFIND", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  if (req == NULL) { g_selftest_err = GetLastError(); goto out; }
  /* the probe must authenticate by the token alone, never by the default credentials (TM-R19) */
  g_selftest_step = 4;                              /* autologon policy */
  if (!a->set_option(req, WINHTTP_OPTION_AUTOLOGON_POLICY, &level, sizeof(level))) {
    g_selftest_err = GetLastError();
    goto out;
  }
  g_selftest_step = 5;                              /* send */
  if (!a->send(req, L"Depth: 0\r\n", (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    g_selftest_err = GetLastError();
    goto out;
  }
  g_selftest_step = 6;                              /* receive */
  if (!a->receive(req, NULL)) { g_selftest_err = GetLastError(); goto out; }
  g_selftest_step = 7;                              /* status query */
  if (!a->query(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &code, &cb, NULL)) {
    g_selftest_err = GetLastError();
    goto out;
  }
  *status = (int)code;
  e = SD_OK;
out:
  if (req) a->close(req);
  if (conn) a->close(conn);
  a->close(session);
  return e;
}

int wd_selftest_verdict(int token_status, int plain_status)
{
  if (token_status < 200 || token_status > 299)
    return 0;                                 /* the token must be accepted */
  if (plain_status < 400 || plain_status > 499)
    return 0;                                 /* a request without it must be refused */
  return 1;
}

sd_err sd_webdav_token_selftest(uint16_t port, const char *prefix)
{
  wh_api a;
  wchar_t token_path[160], plain_path[] = L"/";
  int ts = 0, ps = 0;
  sd_err e;
  if (port == 0 || prefix == NULL || prefix[0] != '/' || strlen(prefix) >= 64)
    return SD_E_INVALID_PARAM;
  if (!wh_load(&a))
    return SD_E_UNSUPPORTED;
  _snwprintf_s(token_path, SD_COUNTOF(token_path), _TRUNCATE, L"%S/", prefix);
  e = wh_probe(&a, port, token_path, &ts);
  if (e != SD_OK)
    return e;
  e = wh_probe(&a, port, plain_path, &ps);
  if (e != SD_OK)
    return e;
  if (!wd_selftest_verdict(ts, ps)) {
    SD_LOGW(WD_LOG, "token-only self-test: token request %d, plain request %d", ts, ps);
    return SD_E_AUTH_FAILED;
  }
  return SD_OK;
}
