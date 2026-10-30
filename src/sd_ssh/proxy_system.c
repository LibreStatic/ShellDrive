/* System proxy resolution, the opt-in SD_PROXY_SYSTEM source (01 §5.2, D20), and the opt-in
 * decision of TM-R10 (ssh_sysproxy_decide).
 *
 * winhttp.dll is loaded by full System32 path and its functions are resolved at run time (no static
 * import; WinHTTP 5.1 exists on XP SP1+). User processes read the IE settings of the current user
 * (WinHttpGetIEProxyConfigForCurrentUser); LocalSystem reads the WinHTTP default configuration
 * (netsh winhttp, WinHttpGetDefaultProxyConfiguration). With automatic detection or a PAC URL,
 * WinHttpGetProxyForUrl is asked for the synthetic URL https://<host>:<port>/ and the result is
 * marked discovered (TM-R10: no SSPI towards it unless policy allows). The bypass list is honoured.
 * A socks= entry selects SOCKS5, otherwise the https= or the generic entry selects HTTP CONNECT.
 * Blocking (WPAD may take seconds): worker threads only. */
#include <windows.h>
#include <winhttp.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "proxy_internal.h"

typedef BOOL (WINAPI *pfn_ie_cfg)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *);
typedef BOOL (WINAPI *pfn_default_cfg)(WINHTTP_PROXY_INFO *);
typedef HINTERNET (WINAPI *pfn_open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *pfn_for_url)(HINTERNET, LPCWSTR, WINHTTP_AUTOPROXY_OPTIONS *, WINHTTP_PROXY_INFO *);
typedef BOOL (WINAPI *pfn_close)(HINTERNET);

static int wlower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

/* '*' matches any run (also empty); case-insensitive */
static int wild_match(const wchar_t *pat, size_t pl, const wchar_t *s)
{
  size_t pi = 0, si = 0, star = (size_t)-1, mark = 0, sl = wcslen(s);
  while (si < sl) {
    if (pi < pl && (pat[pi] == L'?' || wlower(pat[pi]) == wlower(s[si]))) { pi++; si++; }
    else if (pi < pl && pat[pi] == L'*') { star = pi++; mark = si; }
    else if (star != (size_t)-1) { pi = star + 1; si = ++mark; }
    else return 0;
  }
  while (pi < pl && pat[pi] == L'*') pi++;
  return pi == pl;
}

int ssh_sysproxy_bypassed(const wchar_t *bypass, const wchar_t *host)
{
  const wchar_t *p = bypass;
  if (!bypass || !host || !host[0]) return 0;
  while (*p) {
    const wchar_t *s, *e;
    while (*p == L';' || *p == L' ' || *p == L',' || *p == L'\t' || *p == L'\r' || *p == L'\n') p++;
    s = p;
    while (*p && *p != L';' && *p != L' ' && *p != L',' && *p != L'\t' && *p != L'\r' && *p != L'\n') p++;
    e = p;
    if (s == e) continue;
    if ((size_t)(e - s) == 7 && _wcsnicmp(s, L"<local>", 7) == 0) {
      if (!wcschr(host, L'.') && !wcschr(host, L':')) return 1;
      continue;
    }
    {
      const wchar_t *sch = s;
      for (; sch + 2 < e; sch++) if (sch[0] == L':' && sch[1] == L'/' && sch[2] == L'/') { s = sch + 3; break; }
    }
    if (wild_match(s, (size_t)(e - s), host)) return 1;
  }
  return 0;
}

/* Parses "host[:port]" / "[v6][:port]" / "scheme://host:port" into out->host/port. */
static int parse_hostport(const wchar_t *s, size_t n, uint16_t defport, ssh_sysproxy *out)
{
  size_t i, hl;
  const wchar_t *h;
  uint32_t port = 0;
  for (i = 0; i + 2 < n; i++)
    if (s[i] == L':' && s[i + 1] == L'/' && s[i + 2] == L'/') { s += i + 3; n -= i + 3; break; }
  while (n && s[n - 1] == L'/') n--;
  if (!n) return 0;
  h = s;
  if (s[0] == L'[') {
    const wchar_t *rb = NULL;
    for (i = 0; i < n; i++) if (s[i] == L']') { rb = s + i; break; }
    if (!rb) return 0;
    hl = (size_t)(rb - s) + 1;                     /* keep the brackets: the DNS step strips them */
    s = rb + 1;
    n -= hl;
  } else {
    for (i = 0; i < n && s[i] != L':'; i++) {}
    hl = i;
    s += i;
    n -= i;
  }
  if (n) {
    if (s[0] != L':' || n < 2) return 0;
    for (i = 1; i < n; i++) {
      if (s[i] < L'0' || s[i] > L'9') return 0;
      port = port * 10u + (uint32_t)(s[i] - L'0');
      if (port > 65535) return 0;
    }
  }
  if (!hl || hl >= SD_COUNTOF(out->host)) return 0;
  memcpy(out->host, h, hl * sizeof(wchar_t));
  out->host[hl] = 0;
  out->port = (uint16_t)(port ? port : defport);
  return out->port != 0;
}

int ssh_sysproxy_pick(const wchar_t *list, ssh_sysproxy *out)
{
  const wchar_t *p = list;
  const wchar_t *socks = NULL, *https = NULL, *generic = NULL;
  size_t sl = 0, hl = 0, gl = 0;
  memset(out, 0, sizeof(*out));
  out->kind = SD_PROXY_NONE;
  if (!list) return 0;
  while (*p) {
    const wchar_t *s, *e, *eq = NULL, *q;
    while (*p == L';' || *p == L' ' || *p == L'\t') p++;
    s = p;
    while (*p && *p != L';' && *p != L' ' && *p != L'\t') p++;
    e = p;
    if (s == e) continue;
    for (q = s; q < e; q++) if (*q == L'=') { eq = q; break; }
    if (!eq) { if (!generic) { generic = s; gl = (size_t)(e - s); } continue; }
    if ((size_t)(eq - s) == 5 && _wcsnicmp(s, L"socks", 5) == 0 && !socks) { socks = eq + 1; sl = (size_t)(e - eq - 1); }
    else if ((size_t)(eq - s) == 5 && _wcsnicmp(s, L"https", 5) == 0 && !https) { https = eq + 1; hl = (size_t)(e - eq - 1); }
  }
  if (socks && parse_hostport(socks, sl, 1080, out)) { out->kind = SD_PROXY_SOCKS5; return 1; }
  if (https && parse_hostport(https, hl, 80, out)) { out->kind = SD_PROXY_HTTP; return 1; }
  if (generic && parse_hostport(generic, gl, 80, out)) { out->kind = SD_PROXY_HTTP; return 1; }
  out->kind = SD_PROXY_NONE;
  return 0;
}

static void synth_url(const wchar_t *host, uint16_t port, wchar_t *url, size_t cap)
{
  int v6 = wcschr(host, L':') != NULL && host[0] != L'[';
  _snwprintf_s(url, cap, _TRUNCATE, v6 ? L"https://[%ls]:%u/" : L"https://%ls:%u/", host, (unsigned)port);
}

sd_err ssh_sysproxy_resolve(const wchar_t *host, uint16_t port, int service, ssh_sysproxy *out)
{
  pfn_ie_cfg ie_cfg = (pfn_ie_cfg)sd_platform_resolve_by_name(L"winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser");
  pfn_default_cfg def_cfg = (pfn_default_cfg)sd_platform_resolve_by_name(L"winhttp.dll", "WinHttpGetDefaultProxyConfiguration");
  pfn_open w_open = (pfn_open)sd_platform_resolve_by_name(L"winhttp.dll", "WinHttpOpen");
  pfn_for_url for_url = (pfn_for_url)sd_platform_resolve_by_name(L"winhttp.dll", "WinHttpGetProxyForUrl");
  pfn_close w_close = (pfn_close)sd_platform_resolve_by_name(L"winhttp.dll", "WinHttpCloseHandle");
  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie;
  wchar_t *static_list = NULL, *bypass = NULL, *pac = NULL;
  int autodetect = 0;
  sd_err e = SD_OK;

  memset(out, 0, sizeof(*out));
  out->kind = SD_PROXY_NONE;
  if (service) {
    WINHTTP_PROXY_INFO pi;
    if (!def_cfg) return SD_E_PROXY;
    memset(&pi, 0, sizeof(pi));
    if (!def_cfg(&pi)) return SD_E_PROXY;
    if (pi.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && pi.lpszProxy &&
        !ssh_sysproxy_bypassed(pi.lpszProxyBypass, host))
      ssh_sysproxy_pick(pi.lpszProxy, out);
    if (pi.lpszProxy) GlobalFree(pi.lpszProxy);
    if (pi.lpszProxyBypass) GlobalFree(pi.lpszProxyBypass);
    return SD_OK;
  }
  if (!ie_cfg) return SD_E_PROXY;
  memset(&ie, 0, sizeof(ie));
  if (!ie_cfg(&ie)) return SD_E_PROXY;
  static_list = ie.lpszProxy;
  bypass = ie.lpszProxyBypass;
  pac = ie.lpszAutoConfigUrl;
  autodetect = ie.fAutoDetect != 0;

  if (ssh_sysproxy_bypassed(bypass, host)) goto done;      /* direct */
  if ((autodetect || (pac && pac[0])) && w_open && for_url && w_close) {
    HINTERNET hs = w_open(L"ShellDrive", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    int got = 0;
    if (hs) {
      WINHTTP_AUTOPROXY_OPTIONS ao;
      WINHTTP_PROXY_INFO pi;
      wchar_t url[400];
      synth_url(host, port, url, SD_COUNTOF(url));
      memset(&ao, 0, sizeof(ao));
      if (pac && pac[0]) { ao.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL; ao.lpszAutoConfigUrl = pac; }
      if (autodetect) {
        ao.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        ao.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
      }
      ao.fAutoLogonIfChallenged = TRUE;
      memset(&pi, 0, sizeof(pi));
      if (for_url(hs, url, &ao, &pi)) {
        got = 1;
        if (pi.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && pi.lpszProxy &&
            !ssh_sysproxy_bypassed(pi.lpszProxyBypass, host) && ssh_sysproxy_pick(pi.lpszProxy, out))
          out->discovered = 1;
      } else {
        sd_log(SD_LOG_INFO, "ssh", NULL, "system proxy: automatic configuration failed (%u)", (unsigned)GetLastError());
      }
      if (pi.lpszProxy) GlobalFree(pi.lpszProxy);
      if (pi.lpszProxyBypass) GlobalFree(pi.lpszProxyBypass);
      w_close(hs);
    }
    if (got) goto done;
    if (!static_list || !static_list[0]) { e = SD_E_PROXY; goto done; }   /* discovery failed, nothing static */
  }
  if (static_list && static_list[0]) ssh_sysproxy_pick(static_list, out);

done:
  if (ie.lpszProxy) GlobalFree(ie.lpszProxy);
  if (ie.lpszProxyBypass) GlobalFree(ie.lpszProxyBypass);
  if (ie.lpszAutoConfigUrl) GlobalFree(ie.lpszAutoConfigUrl);
  return e;
}

/* M5 service seam (03 3.8): the machine configuration only, through the same resolver as the service path. */
sd_err sd_ssh_proxy_machine(const wchar_t *host, uint16_t port, sd_proxy_kind *kind, wchar_t host_out[256],
                            uint16_t *port_out)
{
  ssh_sysproxy r;
  sd_err e;
  if (host == NULL || kind == NULL || host_out == NULL || port_out == NULL)
    return SD_E_INVALID_PARAM;
  *kind = SD_PROXY_NONE;
  host_out[0] = 0;
  *port_out = 0;
  memset(&r, 0, sizeof(r));
  e = ssh_sysproxy_resolve(host, port ? port : 22, 1, &r);
  if (e != SD_OK)
    return e;
  if (r.kind == SD_PROXY_NONE)
    return SD_OK;
  if (r.kind != SD_PROXY_HTTP && r.kind != SD_PROXY_SOCKS5)
    return SD_E_PROXY;
  wcscpy_s(host_out, 256, r.host);
  *port_out = r.port;
  *kind = r.kind;
  return SD_OK;
}

/* The opt-in decision (01 §5.2, 03 §3.5/§3.8, TM-R10). See proxy_internal.h. */
sd_err ssh_sysproxy_decide(int opt_in, int policy_system, int policy_sspi,
                           const ssh_sysproxy *res, ssh_sys_decision *out)
{
  memset(out, 0, sizeof(*out));
  if (!opt_in) return SD_OK;                             /* no opt-in: never a discovered proxy */
  if (!policy_system) return SD_E_PROXY;                 /* refused: policy AllowSystemProxy = 0 */
  out->kind = res->kind;
  out->discovered = res->discovered;
  out->sspi_allowed = res->kind != SD_PROXY_NONE && (!res->discovered || policy_sspi);   /* TM-R10 */
  if (res->kind != SD_PROXY_NONE) {
    memcpy(out->host, res->host, sizeof(out->host));
    out->port = res->port;
  }
  return SD_OK;
}
