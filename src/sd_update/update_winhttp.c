/* sd_update transport: WinHTTP (04 §9.4). Every WinHTTP entry point is resolved at run time from the System32
 * copy of winhttp.dll (sd_platform_load_system_dll), so the module adds no static import that Windows XP
 * lacks; the header constants come from winhttp.h and cost nothing at link time.
 *
 *   - HTTPS is requested with TLS 1.2 where the option exists (WinHTTP 5.1 on XP ignores the flag and uses
 *     what the OS offers). The TLS stack is the OS's; this module implements no TLS (04 §9.4).
 *   - Redirects are followed by hand: each Location must name a host on the allow list (the manifest's
 *     base hosts plus the GitHub release-asset hosts). A redirect from https to plain http is refused.
 *   - A response larger than the caller's limit (Content-Length or running total) is refused; nothing is
 *     used before the caller checks size and digest (T-69). */
#include <windows.h>
#include <winhttp.h>
#include <string.h>

#include "sd_update/sd_update.h"
#include "sd_platform/sd_platform.h"
#include "sd_base/sd_mem.h"
#include "update_internal.h"

#ifndef WINHTTP_OPTION_SECURE_PROTOCOLS
#define WINHTTP_OPTION_SECURE_PROTOCOLS 84
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY
#define WINHTTP_OPTION_REDIRECT_POLICY 88
#endif
#ifndef WINHTTP_OPTION_REDIRECT_POLICY_NEVER
#define WINHTTP_OPTION_REDIRECT_POLICY_NEVER 0
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_REFRESH
#define WINHTTP_FLAG_REFRESH 0x00000100
#endif

#define UPD_REDIRECTS_MAX 5
#define UPD_CHUNK         16384u
#define UPD_UA            L"ShellDrive-updater"

typedef HINTERNET (WINAPI *pfn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pfn_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pfn_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetTimeouts)(HINTERNET, int, int, int, int);
typedef BOOL (WINAPI *pfn_WinHttpCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *pfn_WinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

typedef struct wh_api {
  pfn_WinHttpOpen            open;
  pfn_WinHttpConnect         connect;
  pfn_WinHttpOpenRequest     open_request;
  pfn_WinHttpSendRequest     send_request;
  pfn_WinHttpReceiveResponse receive_response;
  pfn_WinHttpQueryHeaders    query_headers;
  pfn_WinHttpReadData        read_data;
  pfn_WinHttpSetOption       set_option;
  pfn_WinHttpSetTimeouts     set_timeouts;
  pfn_WinHttpCloseHandle     close;
  pfn_WinHttpCrackUrl        crack_url;
} wh_api;

typedef struct wh_impl {
  wh_api api;
  HINTERNET session;
} wh_impl;

static void *resolve_one(const wchar_t *dll, const char *name)
{
  return sd_platform_resolve_by_name(dll, name);
}

static int load_api(wh_api *a)
{
  static const wchar_t dll[] = L"winhttp.dll";
  if (sd_platform_load_system_dll(dll) == NULL)
    return 0;
  a->open = (pfn_WinHttpOpen)resolve_one(dll, "WinHttpOpen");
  a->connect = (pfn_WinHttpConnect)resolve_one(dll, "WinHttpConnect");
  a->open_request = (pfn_WinHttpOpenRequest)resolve_one(dll, "WinHttpOpenRequest");
  a->send_request = (pfn_WinHttpSendRequest)resolve_one(dll, "WinHttpSendRequest");
  a->receive_response = (pfn_WinHttpReceiveResponse)resolve_one(dll, "WinHttpReceiveResponse");
  a->query_headers = (pfn_WinHttpQueryHeaders)resolve_one(dll, "WinHttpQueryHeaders");
  a->read_data = (pfn_WinHttpReadData)resolve_one(dll, "WinHttpReadData");
  a->set_option = (pfn_WinHttpSetOption)resolve_one(dll, "WinHttpSetOption");
  a->set_timeouts = (pfn_WinHttpSetTimeouts)resolve_one(dll, "WinHttpSetTimeouts");
  a->close = (pfn_WinHttpCloseHandle)resolve_one(dll, "WinHttpCloseHandle");
  a->crack_url = (pfn_WinHttpCrackUrl)resolve_one(dll, "WinHttpCrackUrl");
  return a->open && a->connect && a->open_request && a->send_request && a->receive_response &&
         a->query_headers && a->read_data && a->set_option && a->set_timeouts && a->close && a->crack_url;
}

/* GitHub release-asset storage hosts (04 §9.4 step 3), in addition to the manifest's bases. */
static const wchar_t *const k_github_hosts[] = {
  L"github.com", L"objects.githubusercontent.com", L"release-assets.githubusercontent.com",
  L"github-releases.githubusercontent.com"
};

static int host_allowed(const sd_upd_transport *t, const wchar_t *host, size_t hlen)
{
  uint32_t i;
  size_t k;
  for (k = 0; k < SD_COUNTOF(k_github_hosts); k++) {
    if (wcslen(k_github_hosts[k]) == hlen && _wcsnicmp(k_github_hosts[k], host, hlen) == 0)
      return 1;
  }
  for (i = 0; i < t->nallow; i++) {
    if (wcslen(t->allow[i]) == hlen && _wcsnicmp(t->allow[i], host, hlen) == 0)
      return 1;
  }
  return 0;
}

/* Decimal Content-Length; anything that is not digits gives a value above every limit. */
static unsigned long long wide_decimal(const wchar_t *s)
{
  unsigned long long v = 0;
  size_t i;
  for (i = 0; s[i] != L'\0'; i++) {
    if (s[i] < L'0' || s[i] > L'9')
      return ~0ull;
    if (v > (~0ull - 9) / 10)
      return ~0ull;
    v = v * 10u + (unsigned long long)(s[i] - L'0');
  }
  return v;
}

/* Output sink: memory (buf/len) or file (handle). */
typedef struct wh_sink {
  uint8_t *buf;
  size_t len, cap;
  HANDLE file;
} wh_sink;

static sd_upd_res sink_put(wh_sink *s, const uint8_t *p, DWORD n)
{
  if (s->file != INVALID_HANDLE_VALUE) {
    DWORD put = 0;
    if (!WriteFile(s->file, p, n, &put, NULL) || put != n)
      return SD_UPD_E_IO;
    return SD_UPD_OK;
  }
  if (s->len + n > s->cap) {
    size_t nc = s->cap ? s->cap * 2 : UPD_CHUNK;
    uint8_t *nb;
    while (nc < s->len + n)
      nc *= 2;
    nb = (uint8_t *)sd_realloc(s->buf, nc);
    if (nb == NULL)
      return SD_UPD_E_NO_MEMORY;
    s->buf = nb;
    s->cap = nc;
  }
  memcpy(s->buf + s->len, p, n);
  s->len += n;
  return SD_UPD_OK;
}

static sd_upd_res fetch(sd_upd_transport *t, const wchar_t *url0, uint64_t max, wh_sink *sink)
{
  wh_impl *w = (wh_impl *)t->impl;
  wchar_t url[2048];
  int redirects;
  sd_upd_res res = SD_UPD_E_NETWORK;

  if (w == NULL || w->session == NULL)
    return SD_UPD_E_NETWORK;
  if (wcslen(url0) >= SD_COUNTOF(url))
    return SD_UPD_E_INVALID;
  upd_wcpy(url, SD_COUNTOF(url), url0);

  for (redirects = 0; redirects <= UPD_REDIRECTS_MAX; redirects++) {
    URL_COMPONENTS uc;
    wchar_t host[256];
    wchar_t pathq[2048];
    wchar_t *path_ptr;
    HINTERNET conn = NULL, req = NULL;
    DWORD status = 0, sz, flags = 0;
    int secure;
    BOOL ok;

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;
    if (!w->api.crack_url(url, 0, 0, &uc))
      return SD_UPD_E_NETWORK;
    secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    if (!secure && uc.nScheme != INTERNET_SCHEME_HTTP)
      return SD_UPD_E_NETWORK;
    if (uc.dwHostNameLength == 0 || uc.dwHostNameLength >= SD_COUNTOF(host))
      return SD_UPD_E_NETWORK;
    memcpy(host, uc.lpszHostName, uc.dwHostNameLength * sizeof(wchar_t));
    host[uc.dwHostNameLength] = L'\0';
    /* Path plus query string, NUL-terminated (the crack leaves them as lengths into the URL). */
    if ((size_t)uc.dwUrlPathLength + (size_t)uc.dwExtraInfoLength + 1 > SD_COUNTOF(pathq))
      return SD_UPD_E_NETWORK;
    pathq[0] = L'\0';
    if (uc.dwUrlPathLength)
      memcpy(pathq, uc.lpszUrlPath, uc.dwUrlPathLength * sizeof(wchar_t));
    if (uc.dwExtraInfoLength)
      memcpy(pathq + uc.dwUrlPathLength, uc.lpszExtraInfo, uc.dwExtraInfoLength * sizeof(wchar_t));
    pathq[uc.dwUrlPathLength + uc.dwExtraInfoLength] = L'\0';
    path_ptr = pathq[0] ? pathq : L"/";

    conn = w->api.connect(w->session, host, (INTERNET_PORT)uc.nPort, 0);
    if (conn == NULL) {
      res = SD_UPD_E_NETWORK;
      goto next_fail;
    }
    flags = WINHTTP_FLAG_REFRESH | (secure ? WINHTTP_FLAG_SECURE : 0);
    req = w->api.open_request(conn, L"GET", path_ptr, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (req == NULL) {
      res = SD_UPD_E_NETWORK;
      goto next_fail;
    }
    if (secure) {
      DWORD prot = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
      /* Ignored where the option is unknown; never a reason to fall back to a weaker protocol. */
      w->api.set_option(req, WINHTTP_OPTION_SECURE_PROTOCOLS, &prot, sizeof(prot));
    }
    {
      DWORD never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
      w->api.set_option(req, WINHTTP_OPTION_REDIRECT_POLICY, &never, sizeof(never));
    }
    ok = w->api.send_request(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0);
    if (!ok || !w->api.receive_response(req, NULL)) {
      res = SD_UPD_E_NETWORK;
      goto next_fail;
    }
    sz = sizeof(status);
    if (!w->api.query_headers(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &sz, NULL)) {
      res = SD_UPD_E_NETWORK;
      goto next_fail;
    }

    if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
      wchar_t loc[2048];
      URL_COMPONENTS lc;
      wchar_t lhost[256];
      sz = sizeof(loc);
      if (!w->api.query_headers(req, WINHTTP_QUERY_LOCATION, NULL, loc, &sz, NULL)) {
        res = SD_UPD_E_REDIRECT;
        goto next_fail;
      }
      memset(&lc, 0, sizeof(lc));
      lc.dwStructSize = sizeof(lc);
      lc.dwSchemeLength = (DWORD)-1;
      lc.dwHostNameLength = (DWORD)-1;
      lc.dwUrlPathLength = (DWORD)-1;
      lc.dwExtraInfoLength = (DWORD)-1;
      if (!w->api.crack_url(loc, 0, 0, &lc) || lc.dwHostNameLength == 0 || lc.dwHostNameLength >= SD_COUNTOF(lhost)) {
        res = SD_UPD_E_REDIRECT;
        goto next_fail;
      }
      if (lc.nScheme == INTERNET_SCHEME_HTTP && secure) {
        res = SD_UPD_E_REDIRECT;                /* never downgrade https to http */
        goto next_fail;
      }
      if (lc.nScheme != INTERNET_SCHEME_HTTPS && lc.nScheme != INTERNET_SCHEME_HTTP) {
        res = SD_UPD_E_REDIRECT;
        goto next_fail;
      }
      if (!host_allowed(t, lc.lpszHostName, lc.dwHostNameLength)) {
        res = SD_UPD_E_REDIRECT;                /* T-69: foreign host */
        goto next_fail;
      }
      if (req) w->api.close(req);
      if (conn) w->api.close(conn);
      upd_wcpy(url, SD_COUNTOF(url), loc);
      continue;
    }
    if (status < 200 || status > 299) {
      res = SD_UPD_E_NETWORK;
      goto next_fail;
    }

    /* Content-Length (when present) is checked before the body is read. */
    {
      wchar_t cl[32];
      sz = sizeof(cl);
      if (w->api.query_headers(req, WINHTTP_QUERY_CONTENT_LENGTH, NULL, cl, &sz, NULL)) {
        unsigned long long n = wide_decimal(cl);
        if (n > max) {
          res = SD_UPD_E_TOO_LARGE;
          goto next_fail;
        }
      }
    }
    {
      uint8_t *chunk = (uint8_t *)sd_alloc(UPD_CHUNK);
      unsigned long long total = 0;
      sd_upd_res wr = SD_UPD_OK;
      if (chunk == NULL) {
        res = SD_UPD_E_NO_MEMORY;
        goto next_fail;
      }
      for (;;) {
        DWORD got = 0;
        if (!w->api.read_data(req, chunk, UPD_CHUNK, &got)) {
          wr = SD_UPD_E_NETWORK;
          break;
        }
        if (got == 0)
          break;
        total += got;
        if (total > max) {
          wr = SD_UPD_E_TOO_LARGE;
          break;
        }
        wr = sink_put(sink, chunk, got);
        if (wr != SD_UPD_OK)
          break;
      }
      sd_free(chunk);
      res = wr;
    }
    if (req) w->api.close(req);
    if (conn) w->api.close(conn);
    return res;

next_fail:
    if (req) w->api.close(req);
    if (conn) w->api.close(conn);
    return res;
  }
  return SD_UPD_E_REDIRECT;
}

static sd_upd_res wh_get_mem(sd_upd_transport *t, const wchar_t *url, uint32_t max, uint8_t **buf, size_t *len)
{
  wh_sink s;
  sd_upd_res r;
  memset(&s, 0, sizeof(s));
  s.file = INVALID_HANDLE_VALUE;
  *buf = NULL;
  *len = 0;
  r = fetch(t, url, max, &s);
  if (r != SD_UPD_OK) {
    sd_free(s.buf);
    return r;
  }
  if (s.buf == NULL) {
    s.buf = (uint8_t *)sd_alloc(1);
    if (s.buf == NULL)
      return SD_UPD_E_NO_MEMORY;
  }
  *buf = s.buf;
  *len = s.len;
  return SD_UPD_OK;
}

static sd_upd_res wh_get_file(sd_upd_transport *t, const wchar_t *url, uint64_t max, const wchar_t *path)
{
  wh_sink s;
  sd_upd_res r;
  memset(&s, 0, sizeof(s));
  s.file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (s.file == INVALID_HANDLE_VALUE)
    return SD_UPD_E_IO;
  r = fetch(t, url, max, &s);
  if (r == SD_UPD_OK && !FlushFileBuffers(s.file))
    r = SD_UPD_E_IO;
  CloseHandle(s.file);
  if (r != SD_UPD_OK)
    DeleteFileW(path);
  return r;
}

static void wh_destroy(sd_upd_transport *t)
{
  wh_impl *w = (wh_impl *)t->impl;
  if (w) {
    if (w->session && w->api.close)
      w->api.close(w->session);
    sd_free(w);
  }
  sd_free(t);
}

static const sd_upd_transport_ops k_wh_ops = { wh_get_mem, wh_get_file, wh_destroy };

sd_upd_transport *sd_upd_transport_winhttp_create(int use_proxy)
{
  sd_upd_transport *t;
  wh_impl *w;
  DWORD access = use_proxy ? WINHTTP_ACCESS_TYPE_DEFAULT_PROXY : WINHTTP_ACCESS_TYPE_NO_PROXY;

  t = (sd_upd_transport *)sd_calloc(1, sizeof(*t));
  w = (wh_impl *)sd_calloc(1, sizeof(*w));
  if (t == NULL || w == NULL) {
    sd_free(t);
    sd_free(w);
    return NULL;
  }
  if (!load_api(&w->api)) {
    sd_free(t);
    sd_free(w);
    return NULL;
  }
  w->session = w->api.open(UPD_UA, access, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (w->session == NULL) {
    sd_free(t);
    sd_free(w);
    return NULL;
  }
  w->api.set_timeouts(w->session, 10000, 10000, 15000, 60000);
  t->ops = &k_wh_ops;
  t->impl = w;
  return t;
}

void sd_upd_transport_destroy(sd_upd_transport *t)
{
  if (t && t->ops && t->ops->destroy)
    t->ops->destroy(t);
}
