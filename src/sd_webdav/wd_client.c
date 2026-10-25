/* sd_webdav: WebClient service (02 §7.2), drive mapping, label, stale-mapping cleanup (TM-R17) and the
 * process-wide one-call mount used by sd_mount.
 *
 * Functions not on the XP floor list are resolved at run time: advapi32 QueryServiceConfigW and the
 * ETW EventRegister/EventWrite/EventUnregister (Vista+), mpr WNetOpenEnumW/WNetEnumResourceW/
 * WNetCloseEnum. WNetAddConnection2W / WNetCancelConnection2W are imported (on the floor). */
#include "wd_server.h"

#include <stdio.h>
#include <string.h>
#include <winnetwk.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"

/* ---- WebClient ---- */

typedef BOOL (WINAPI *pfn_QueryServiceConfigW)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
typedef struct wd_evdesc { USHORT id; UCHAR version, channel, level, opcode; USHORT task; ULONGLONG keyword; } wd_evdesc;
typedef ULONG (WINAPI *pfn_EventRegister)(const GUID *, PVOID, PVOID, ULONGLONG *);
typedef ULONG (WINAPI *pfn_EventWrite)(ULONGLONG, const wd_evdesc *, ULONG, PVOID);
typedef ULONG (WINAPI *pfn_EventUnregister)(ULONGLONG);

/* Microsoft-Windows-WebdavClient-LookupServiceTrigger {22B6D684-FA63-4578-87C9-EFFCBE6643C7} */
static const GUID k_webclient_trigger = { 0x22b6d684, 0xfa63, 0x4578, { 0x87, 0xc9, 0xef, 0xfc, 0xbe, 0x66, 0x43, 0xc7 } };

static void query_open(SC_HANDLE svc, sd_webdav_client_info *ci)
{
  SERVICE_STATUS_PROCESS sp;
  DWORD need = 0;
  pfn_QueryServiceConfigW qsc = (pfn_QueryServiceConfigW)sd_platform_resolve_by_name(L"advapi32.dll", "QueryServiceConfigW");
  if (qsc) {
    uint8_t buf[8192];
    if (qsc(svc, (LPQUERY_SERVICE_CONFIGW)buf, sizeof(buf), &need))
      ci->start_type = ((LPQUERY_SERVICE_CONFIGW)buf)->dwStartType;
    else
      ci->error = GetLastError();
  }
  ci->trigger_start = sd_os_at_least(6, 1, 0) && ci->start_type == SERVICE_DEMAND_START;
  if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&sp, sizeof(sp), &need)) {
    if (sp.dwCurrentState == SERVICE_RUNNING) {
      ci->state = SD_WD_CLIENT_RUNNING;
      ci->pid = sp.dwProcessId;
    } else {
      ci->state = ci->start_type == SERVICE_DISABLED ? SD_WD_CLIENT_DISABLED : SD_WD_CLIENT_STOPPED;
    }
  } else {
    ci->error = GetLastError();
    ci->state = ci->start_type == SERVICE_DISABLED ? SD_WD_CLIENT_DISABLED : SD_WD_CLIENT_UNKNOWN;
  }
}

sd_webdav_client_state sd_webdav_query_client(sd_webdav_client_info *out)
{
  sd_webdav_client_info ci;
  SC_HANDLE scm, svc;
  memset(&ci, 0, sizeof(ci));
  ci.start_type = 0xFFFFFFFFu;
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm == NULL) {
    ci.error = GetLastError();
  } else {
    svc = OpenServiceW(scm, L"WebClient", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (svc == NULL) {
      ci.error = GetLastError();
      if (ci.error == ERROR_SERVICE_DOES_NOT_EXIST)
        ci.state = SD_WD_CLIENT_MISSING;
    } else {
      query_open(svc, &ci);
      CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
  }
  if (out) *out = ci;
  return ci.state;
}

static int write_trigger_event(DWORD *err)
{
  pfn_EventRegister reg = (pfn_EventRegister)sd_platform_resolve_by_name(L"advapi32.dll", "EventRegister");
  pfn_EventWrite wr = (pfn_EventWrite)sd_platform_resolve_by_name(L"advapi32.dll", "EventWrite");
  pfn_EventUnregister unr = (pfn_EventUnregister)sd_platform_resolve_by_name(L"advapi32.dll", "EventUnregister");
  ULONGLONG h = 0;
  wd_evdesc d;
  ULONG rc;
  if (reg == NULL || wr == NULL || unr == NULL)
    return -1;
  rc = reg(&k_webclient_trigger, NULL, NULL, &h);
  if (rc != ERROR_SUCCESS) {
    *err = rc;
    return -1;
  }
  memset(&d, 0, sizeof(d));
  d.id = 1;
  d.level = 4;                             /* informational, as davclnt.dll does */
  rc = wr(h, &d, 0, NULL);
  unr(h);
  if (rc != ERROR_SUCCESS) {
    *err = rc;
    return -1;
  }
  return 0;
}

sd_err sd_webdav_ensure_client(uint32_t timeout_ms, sd_webdav_client_info *out)
{
  sd_webdav_client_info ci;
  SC_HANDLE scm, svc;
  uint64_t end;
  sd_webdav_query_client(&ci);
  if (out) *out = ci;
  if (ci.state == SD_WD_CLIENT_RUNNING)
    return SD_OK;
  if (ci.state == SD_WD_CLIENT_MISSING || ci.state == SD_WD_CLIENT_DISABLED)
    return SD_E_UNSUPPORTED;
  if (timeout_ms == 0)
    timeout_ms = 10000;
  /* 1. StartService works when the service DACL grants the user SERVICE_START (usually admins). */
  scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
  if (scm) {
    svc = OpenServiceW(scm, L"WebClient", SERVICE_START);
    if (svc) {
      if (StartServiceW(svc, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        ci.started_by_us = TRUE;
      else
        ci.error = GetLastError();
      CloseServiceHandle(svc);
    } else {
      ci.error = GetLastError();
    }
    CloseServiceHandle(scm);
  }
  /* 2. Windows 7+: the service trigger, which any user may fire (davclnt.dll does the same). */
  if (!ci.started_by_us && sd_os_at_least(6, 1, 0)) {
    DWORD e = 0;
    if (write_trigger_event(&e) == 0)
      ci.started_by_us = TRUE;
    else
      ci.error = e;
  }
  if (!ci.started_by_us) {
    ci.needs_admin = TRUE;
    if (out) *out = ci;
    SD_LOGW(WD_LOG, "WebClient is stopped and cannot be started without an administrator (%u)", (unsigned)ci.error);
    return SD_E_ACCESS_DENIED;
  }
  end = sd_tick_ms() + timeout_ms;
  for (;;) {
    sd_webdav_client_info now;
    sd_webdav_query_client(&now);
    if (now.state == SD_WD_CLIENT_RUNNING) {
      now.started_by_us = TRUE;
      if (out) *out = now;
      SD_LOGI(WD_LOG, "WebClient running (pid %u)", (unsigned)now.pid);
      return SD_OK;
    }
    if (sd_tick_ms() >= end) {
      now.started_by_us = ci.started_by_us;
      now.needs_admin = !sd_os_at_least(6, 1, 0);
      if (out) *out = now;
      return SD_E_TIMEOUT;
    }
    Sleep(100);
  }
}

/* ---- mapping ---- */

static volatile LONG g_mapped[26];          /* letters mapped by this process (crash filter) */

/* MountPoints2 key of the mapping. The redirector reports the connection as \\localhost@PORT\s-<token>
   (DavWWWRoot dropped; seen on Windows 11), so Explorer reads the label from that short form; the
   DavWWWRoot form is the one 02 §7.3 names. Both are written and removed. */
static void mp2_key(const sd_webdav_export *e, int short_form, wchar_t *out, size_t cap)
{
  if (short_form)
    _snwprintf_s(out, cap, _TRUNCATE,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##localhost@%u#s-%S",
                 (unsigned)e->srv->port, e->token);
  else
    _snwprintf_s(out, cap, _TRUNCATE,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##localhost@%u#DavWWWRoot#s-%S",
                 (unsigned)e->srv->port, e->token);
}

sd_err sd_webdav_map(const sd_webdav_export *e, wchar_t letter, DWORD *win32_error)
{
  NETRESOURCEW nr;
  wchar_t local[3], remote[128];
  BOOL xp = !sd_os_at_least(6, 0, 0);
  DWORD rc;
  if (win32_error) *win32_error = 0;
  if (e == NULL || letter < L'A' || letter > L'Z')
    return SD_E_INVALID_PARAM;
  local[0] = letter;
  local[1] = L':';
  local[2] = 0;
  if (sd_webdav_export_remote_name(e, xp, remote, SD_COUNTOF(remote)) != SD_OK)
    return SD_E_INVALID_PARAM;
  memset(&nr, 0, sizeof(nr));
  nr.dwType = RESOURCETYPE_DISK;
  nr.lpLocalName = local;
  nr.lpRemoteName = remote;
  nr.lpProvider = xp ? L"Web Client Network" : NULL;
  rc = WNetAddConnection2W(&nr, NULL, NULL, 0);    /* not CONNECT_UPDATE_PROFILE: never persistent */
  if (win32_error) *win32_error = rc;
  if (rc != NO_ERROR) {
    SD_LOGW(WD_LOG, "WNetAddConnection2W(%c:) failed: %u", (int)letter, (unsigned)rc);
    if (rc == ERROR_ALREADY_ASSIGNED || rc == ERROR_DEVICE_ALREADY_REMEMBERED)
      return SD_E_EXISTS;
    if (rc == ERROR_ACCESS_DENIED || rc == ERROR_LOGON_FAILURE)
      return SD_E_ACCESS_DENIED;
    return SD_E_FAILURE;
  }
  InterlockedExchange(&g_mapped[letter - L'A'], 1);
  ((sd_webdav_export *)e)->mapped = letter;
  if (e->label && !xp) {
    wchar_t key[256];
    HKEY hk;
    int form;
    for (form = 0; form < 2; form++) {
      mp2_key(e, form, key, SD_COUNTOF(key));
      if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hk, L"_LabelFromReg", 0, REG_SZ, (const BYTE *)e->label,
                       (DWORD)((wcslen(e->label) + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
      }
    }
  }
  return SD_OK;
}

sd_err sd_webdav_unmap(const sd_webdav_export *e, wchar_t letter)
{
  wchar_t local[3], key[256];
  DWORD rc;
  if (e == NULL || letter < L'A' || letter > L'Z')
    return SD_E_INVALID_PARAM;
  local[0] = letter;
  local[1] = L':';
  local[2] = 0;
  rc = WNetCancelConnection2W(local, 0, TRUE);
  InterlockedExchange(&g_mapped[letter - L'A'], 0);
  ((sd_webdav_export *)e)->mapped = 0;
  mp2_key(e, 0, key, SD_COUNTOF(key));
  RegDeleteKeyW(HKEY_CURRENT_USER, key);
  mp2_key(e, 1, key, SD_COUNTOF(key));
  RegDeleteKeyW(HKEY_CURRENT_USER, key);
  if (rc != NO_ERROR && rc != ERROR_NOT_CONNECTED) {
    SD_LOGW(WD_LOG, "WNetCancelConnection2W(%c:) failed: %u", (int)letter, (unsigned)rc);
    return SD_E_FAILURE;
  }
  return SD_OK;
}

void sd_webdav_emergency_unmap(void)
{
  int i;
  for (i = 0; i < 26; i++) {
    if (InterlockedCompareExchange(&g_mapped[i], 0, 0)) {
      wchar_t local[3];
      local[0] = (wchar_t)(L'A' + i);
      local[1] = L':';
      local[2] = 0;
      if (WNetCancelConnection2W(local, 0, TRUE) != NO_ERROR)
        continue;                          /* nothing else can be done in a crash filter */
      InterlockedExchange(&g_mapped[i], 0);
    }
  }
}

/* Parses "\\localhost@PORT\DavWWWRoot\s-<26>" or "http://localhost:PORT/s-<26>" (case-insensitive). */
static int ours(const wchar_t *r, uint16_t *port)
{
  const wchar_t *p;
  uint32_t v = 0, n = 0, i;
  wchar_t sep;
  if (_wcsnicmp(r, L"\\\\localhost@", 12) == 0) { p = r + 12; sep = L'\\'; }
  else if (_wcsnicmp(r, L"http://localhost:", 17) == 0) { p = r + 17; sep = L'/'; }
  else return 0;
  while (*p >= L'0' && *p <= L'9' && n < 5) { v = v * 10u + (uint32_t)(*p - L'0'); p++; n++; }
  if (n == 0 || v == 0 || v > 65535 || *p != sep)
    return 0;
  p++;
  if (sep == L'\\' && _wcsnicmp(p, L"DavWWWRoot\\", 11) == 0)
    p += 11;                               /* \\localhost@PORT\s-<token> works too (Windows 10/11) */
  if (p[0] != L's' || p[1] != L'-') return 0;
  p += 2;
  for (i = 0; i < WD_TOKEN_CHARS; i++, p++)
    if (!((*p >= L'a' && *p <= L'z') || (*p >= L'2' && *p <= L'7'))) return 0;
  if (*p != 0 && *p != sep) return 0;
  *port = (uint16_t)v;
  return 1;
}

typedef DWORD (APIENTRY *pfn_WNetOpenEnumW)(DWORD, DWORD, DWORD, LPNETRESOURCEW, LPHANDLE);
typedef DWORD (APIENTRY *pfn_WNetEnumResourceW)(HANDLE, LPDWORD, LPVOID, LPDWORD);
typedef DWORD (APIENTRY *pfn_WNetCloseEnum)(HANDLE);

sd_err sd_webdav_cleanup_mappings(uint16_t keep_port, uint16_t only_port, uint32_t *removed)
{
  pfn_WNetOpenEnumW oe = (pfn_WNetOpenEnumW)sd_platform_resolve_by_name(L"mpr.dll", "WNetOpenEnumW");
  pfn_WNetEnumResourceW er = (pfn_WNetEnumResourceW)sd_platform_resolve_by_name(L"mpr.dll", "WNetEnumResourceW");
  pfn_WNetCloseEnum ce = (pfn_WNetCloseEnum)sd_platform_resolve_by_name(L"mpr.dll", "WNetCloseEnum");
  HANDLE h;
  uint32_t count = 0;
  HKEY mp2;
  if (removed) *removed = 0;
  if (oe == NULL || er == NULL || ce == NULL)
    return SD_E_UNSUPPORTED;
  if (oe(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, NULL, &h) == NO_ERROR) {
    DWORD bufsz = 64u * 1024u;
    uint8_t *buf = (uint8_t *)sd_alloc(bufsz);
    while (buf) {
      DWORD n = 0xFFFFFFFFu, sz = bufsz, rc, i;
      rc = er(h, &n, buf, &sz);
      if (rc != NO_ERROR)
        break;
      for (i = 0; i < n; i++) {
        NETRESOURCEW *r = &((NETRESOURCEW *)buf)[i];
        uint16_t port;
        if (r->lpRemoteName && ours(r->lpRemoteName, &port) && port != keep_port && (!only_port || port == only_port)) {
          const wchar_t *name = (r->lpLocalName && r->lpLocalName[0]) ? r->lpLocalName : r->lpRemoteName;
          if (WNetCancelConnection2W(name, 0, TRUE) == NO_ERROR) {
            count++;
            SD_LOGI(WD_LOG, "removed stale WebDAV mapping on port %u", (unsigned)port);
          }
        }
      }
    }
    sd_free(buf);
    ce(h);
  }
  /* MountPoints2 entries of other ports */
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", 0,
                    KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | DELETE, &mp2) == ERROR_SUCCESS) {
    DWORD idx = 0;
    for (;;) {
      wchar_t name[256], unc[300];
      DWORD nl = SD_COUNTOF(name);
      size_t k;
      uint16_t port;
      if (RegEnumKeyExW(mp2, idx, name, &nl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
        break;
      /* "##localhost@PORT#DavWWWRoot#s-..." -> "\\localhost@PORT\DavWWWRoot\s-..." */
      for (k = 0; name[k] && k + 1 < SD_COUNTOF(unc); k++)
        unc[k] = name[k] == L'#' ? L'\\' : name[k];
      unc[k] = 0;
      if (ours(unc, &port) && port != keep_port && (!only_port || port == only_port) &&
          RegDeleteKeyW(mp2, name) == ERROR_SUCCESS)
        continue;                          /* same index now holds the next key */
      idx++;
    }
    RegCloseKey(mp2);
  }
  if (removed) *removed = count;
  return SD_OK;
}

/* ---- process-wide mount ---- */

struct sd_webdav_mount {
  sd_webdav_export *ex;
  wchar_t letter;
};

static sd_once g_mount_once = SD_ONCE_INIT;
static sd_mutex g_mount_mu;
static sd_webdav_server *g_srv;
static uint32_t g_refs;

/* 02 §7.1: the redirector refuses downloads above FileSizeLimitInBytes (default 50,000,000) and
   folders whose PROPFIND exceeds FileAttributesLimitInBytes (default 1,000,000, ~3,000 entries). The
   installer's WEBDAV_TUNING raises both; this only logs when the defaults are still in place. */
static void warn_redirector_limits(void)
{
  HKEY k;
  DWORD fs = 50000000u, fa = 1000000u, t, sz;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters", 0,
                    KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
    sz = sizeof(fs);
    if (RegQueryValueExW(k, L"FileSizeLimitInBytes", NULL, &t, (BYTE *)&fs, &sz) != ERROR_SUCCESS || t != REG_DWORD)
      fs = 50000000u;
    sz = sizeof(fa);
    if (RegQueryValueExW(k, L"FileAttributesLimitInBytes", NULL, &t, (BYTE *)&fa, &sz) != ERROR_SUCCESS || t != REG_DWORD)
      fa = 1000000u;
    RegCloseKey(k);
  }
  if (fs < 0xFFFFFFFFu)
    SD_LOGW(WD_LOG, "WebClient FileSizeLimitInBytes=%u: larger files cannot be opened (webdav_limits_default)",
            (unsigned)fs);
  if (fa < 100000000u)
    SD_LOGW(WD_LOG, "WebClient FileAttributesLimitInBytes=%u: folders over ~%u entries fail to list", (unsigned)fa,
            (unsigned)(fa / 330u));
}

static void mount_init(void *arg)
{
  SD_UNUSED(arg);
  sd_mutex_init(&g_mount_mu);
}

sd_err sd_webdav_mount_start(sd_vfs *vfs, const sd_webdav_mount_cfg *cfg, sd_webdav_mount **out)
{
  sd_webdav_mount *m;
  sd_webdav_export_cfg ec;
  sd_err e = SD_OK;
  DWORD werr = 0;
  if (out == NULL || vfs == NULL || cfg == NULL || cfg->struct_size < sizeof(*cfg) ||
      cfg->letter < L'A' || cfg->letter > L'Z')
    return SD_E_INVALID_PARAM;
  *out = NULL;
  sd_once_run(&g_mount_once, mount_init, NULL);
  m = (sd_webdav_mount *)sd_calloc(1, sizeof(*m));
  if (m == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_lock(&g_mount_mu);
  if (g_srv == NULL) {
    sd_webdav_server_cfg sc;
    uint32_t removed = 0;
    /* TM-R17 d: before binding, remove our stale mappings from earlier runs (any port) */
    sd_webdav_cleanup_mappings(0, 0, &removed);
    memset(&sc, 0, sizeof(sc));
    sc.struct_size = sizeof(sc);
    sc.owner_sid = cfg->owner_sid;
    e = sd_webdav_server_start(&sc, &g_srv);
    if (e == SD_OK)
      warn_redirector_limits();
  }
  if (e == SD_OK) {
    memset(&ec, 0, sizeof(ec));
    ec.struct_size = sizeof(ec);
    ec.read_only = cfg->read_only;
    ec.label = cfg->label;
    e = sd_webdav_export_add(g_srv, vfs, &ec, &m->ex);
  }
  if (e == SD_OK) {
    g_refs++;
    sd_mutex_unlock(&g_mount_mu);
    /* the redirector connects back to our server while this runs: no lock held */
    e = sd_webdav_map(m->ex, cfg->letter, &werr);
    sd_mutex_lock(&g_mount_mu);
    if (e != SD_OK) {
      sd_webdav_export_remove(m->ex);
      m->ex = NULL;
      g_refs--;
    }
  }
  if (e != SD_OK && g_refs == 0 && g_srv) {
    sd_webdav_server_stop(g_srv);
    g_srv = NULL;
  }
  sd_mutex_unlock(&g_mount_mu);
  if (e != SD_OK) {
    sd_free(m);
    return e;
  }
  m->letter = cfg->letter;
  *out = m;
  return SD_OK;
}

sd_err sd_webdav_mount_stop(sd_webdav_mount *m)
{
  sd_err e;
  if (m == NULL)
    return SD_E_INVALID_PARAM;
  e = sd_webdav_unmap(m->ex, m->letter);
  sd_mutex_lock(&g_mount_mu);
  sd_webdav_export_remove(m->ex);
  if (--g_refs == 0 && g_srv) {
    sd_webdav_server_stop(g_srv);
    g_srv = NULL;
  }
  sd_mutex_unlock(&g_mount_mu);
  sd_free(m);
  return e;
}

uint16_t sd_webdav_mount_port(const sd_webdav_mount *m)
{
  return (m && m->ex) ? m->ex->srv->port : 0;
}
