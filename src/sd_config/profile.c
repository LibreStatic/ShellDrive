/* sd_config: locations, profile model and profile files (03 §3.2-§3.6). */
#include <windows.h>
#include <shlobj.h>
#include <sddl.h>
#include <string.h>
#include <stdio.h>

#include "sd_config/sd_config.h"
#include "config_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"

#define VENDOR_DIR  L"LibreStatic"
#define PRODUCT_DIR L"ShellDrive"

static wchar_t g_root_override[MAX_PATH];

void sd_config_set_root_override(const wchar_t *dir)
{
  size_t n;
  g_root_override[0] = 0;
  if (dir == NULL)
    return;
  n = wcslen(dir);
  while (n > 3 && (dir[n - 1] == L'\\' || dir[n - 1] == L'/'))
    n--;
  if (n == 0 || n >= MAX_PATH)
    return;
  memcpy(g_root_override, dir, n * sizeof(wchar_t));
  g_root_override[n] = 0;
}

/* ---- small string helpers ---- */

static int wcat(wchar_t *dst, size_t cch, const wchar_t *src)
{
  size_t n = wcslen(dst), m = wcslen(src);
  if (n + m + 1 > cch)
    return 0;
  memcpy(dst + n, src, (m + 1) * sizeof(wchar_t));
  return 1;
}

static int wcpy(wchar_t *dst, size_t cch, const wchar_t *src)
{
  if (cch == 0)
    return 0;
  dst[0] = 0;
  return wcat(dst, cch, src);
}

static int scpy(char *dst, size_t cap, const char *src)
{
  size_t n = strlen(src);
  if (n + 1 > cap)
    return 0;
  memcpy(dst, src, n + 1);
  return 1;
}

static int has_ctl(const char *s)
{
  for (; *s; s++)
    if ((unsigned char)*s < 0x20 || *s == 0x7F)
      return 1;
  return 0;
}

static int utf8_from_wide(const wchar_t *w, size_t wn, char *out, size_t cap)
{
  size_t got = 0;
  if (cap == 0)
    return 0;
  if (sd_utf16_to_utf8(w, wn, out, cap - 1, &got, SD_UTF_STRICT) != SD_OK)
    return 0;
  out[got] = 0;
  return 1;
}

static int wide_from_utf8(const char *s, wchar_t *out, size_t cch)
{
  size_t got = 0;
  if (cch == 0)
    return 0;
  if (sd_utf8_to_utf16(s, strlen(s), out, cch - 1, &got, SD_UTF_STRICT) != SD_OK)
    return 0;
  out[got] = 0;
  return 1;
}

/* ---- profile model ---- */

void sd_profile_defaults(sd_profile *p)
{
  memset(p, 0, sizeof(*p));
  p->format = SD_PROFILE_FORMAT;
  p->port = 22;
  p->auth_methods = SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_KBDINT | SD_PROFILE_AUTH_PASSWORD;
  scpy(p->target, sizeof(p->target), "auto");
  p->symlinks = SD_PROFILE_SYMLINKS_FOLLOW_INSIDE;
  p->write_mode = SD_PROFILE_WRITE_THROUGH;
  p->backend = SD_PROFILE_BACKEND_AUTO;
  p->channels = 2;
  p->network_location = 1;
  sd_profile_m2_defaults(p);
  sd_profile_m3_defaults(p);
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

static int valid_host(const char *h)
{
  size_t n = strlen(h), i;
  if (n == 0 || n >= 256)
    return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)h[i];
    if (c <= 0x20 || c == 0x7F || c == '/' || c == '\\' || c == '@')
      return 0;
  }
  return 1;
}

static int target_ok(const char *t)
{
  if (strcmp(t, "auto") == 0)
    return 1;
  if (((t[0] >= 'A' && t[0] <= 'Z') || (t[0] >= 'a' && t[0] <= 'z')) && t[1] == ':' &&
      (t[2] == 0 || (t[2] == '\\' && t[3] == 0)))
    return 1;
  return 0;   /* folder targets: Dokany mount points arrive later */
}

sd_err sd_profile_validate(const sd_profile *p, const char **bad_key)
{
  const char *bad = NULL;
  if (p->format != SD_PROFILE_FORMAT) bad = "profile.format";
  else if (p->id[0] && !valid_id(p->id)) bad = "profile.id";
  else if (p->name[0] == 0 || has_ctl(p->name)) bad = "profile.name";
  else if (!valid_host(p->host)) bad = "profile.host";
  else if (p->port == 0) bad = "profile.port";
  else if (has_ctl(p->user)) bad = "profile.user";
  else if (has_ctl(p->remote_path)) bad = "profile.remote_path";
  else if (has_ctl(p->identity)) bad = "auth.identity";
  else if (p->auth_methods == 0) bad = "auth.methods";
  else if (!target_ok(p->target)) bad = "mount.target";
  else if (p->symlinks < 0 || p->symlinks > 2) bad = "mount.symlinks";
  else if (p->write_mode < 0 || p->write_mode > 1) bad = "mount.write_mode";
  else if (p->backend < 0 || p->backend > 2) bad = "mount.backend";
  else if (p->channels < 1 || p->channels > 2) bad = "connection.channels";
  else if (p->offline_wait_ms > 600000u) bad = "mount.offline_wait";
  else if (p->disk_cache_mb > 1024u * 1024u) bad = "cache.disk";
  else if (has_ctl(p->label)) bad = "mount.label";
  else if ((bad = sd_profile_m2_validate(p)) == NULL) bad = sd_profile_m3_validate(p);
  if (bad_key) *bad_key = bad;
  return bad ? SD_E_INVALID_PARAM : SD_OK;
}

static int parse_methods(const char *v, uint32_t *out)
{
  uint32_t m = 0;
  const char *p = v;
  while (*p) {
    const char *e;
    size_t n;
    while (*p == ' ' || *p == '\t' || *p == ',') p++;
    if (*p == 0) break;
    e = p;
    while (*e && *e != ',' && *e != ' ' && *e != '\t') e++;
    n = (size_t)(e - p);
    if (n == 9 && memcmp(p, "publickey", 9) == 0) m |= SD_PROFILE_AUTH_PUBLICKEY;
    else if (n == 20 && memcmp(p, "keyboard-interactive", 20) == 0) m |= SD_PROFILE_AUTH_KBDINT;
    else if (n == 8 && memcmp(p, "password", 8) == 0) m |= SD_PROFILE_AUTH_PASSWORD;
    else return 0;
    p = e;
  }
  if (m == 0)
    return 0;
  *out = m;
  return 1;
}

sd_err sd_profile_from_ini(const sd_ini *ini, sd_profile *p, const char **bad_key)
{
  const char *v;
  uint32_t u;
  int b;
#define BAD(k) do { if (bad_key) *bad_key = (k); return SD_E_INVALID_PARAM; } while (0)
  sd_profile_defaults(p);
  if (bad_key) *bad_key = NULL;
  if ((v = sd_ini_get(ini, "profile", "format")) != NULL) {
    if (!sd_ini_parse_u32(v, &u)) BAD("profile.format");
    if (u > SD_PROFILE_FORMAT) BAD("profile.format");   /* newer format: read-only elsewhere */
    p->format = (int)u;
  }
  if ((v = sd_ini_get(ini, "profile", "id")) != NULL && !scpy(p->id, sizeof(p->id), v)) BAD("profile.id");
  if ((v = sd_ini_get(ini, "profile", "name")) != NULL && !scpy(p->name, sizeof(p->name), v)) BAD("profile.name");
  if ((v = sd_ini_get(ini, "profile", "host")) == NULL || !scpy(p->host, sizeof(p->host), v)) BAD("profile.host");
  if ((v = sd_ini_get(ini, "profile", "port")) != NULL) {
    if (!sd_ini_parse_u32(v, &u) || u == 0 || u > 65535) BAD("profile.port");
    p->port = (uint16_t)u;
  }
  if ((v = sd_ini_get(ini, "profile", "user")) != NULL && !scpy(p->user, sizeof(p->user), v)) BAD("profile.user");
  if ((v = sd_ini_get(ini, "profile", "remote_path")) != NULL && !scpy(p->remote_path, sizeof(p->remote_path), v))
    BAD("profile.remote_path");
  if ((v = sd_ini_get(ini, "auth", "identity")) != NULL && !scpy(p->identity, sizeof(p->identity), v))
    BAD("auth.identity");
  if ((v = sd_ini_get(ini, "auth", "methods")) != NULL && !parse_methods(v, &p->auth_methods)) BAD("auth.methods");
  if ((v = sd_ini_get(ini, "mount", "target")) != NULL && !scpy(p->target, sizeof(p->target), v)) BAD("mount.target");
  if ((v = sd_ini_get(ini, "mount", "read_only")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) BAD("mount.read_only");
    p->read_only = b;
  }
  if ((v = sd_ini_get(ini, "mount", "symlinks")) != NULL) {
    if (strcmp(v, "follow_inside") == 0) p->symlinks = SD_PROFILE_SYMLINKS_FOLLOW_INSIDE;
    else if (strcmp(v, "follow") == 0) p->symlinks = SD_PROFILE_SYMLINKS_FOLLOW;
    else if (strcmp(v, "hide") == 0) p->symlinks = SD_PROFILE_SYMLINKS_HIDE;
    else BAD("mount.symlinks");     /* includes the reserved "reparse" (D12) */
  }
  if ((v = sd_ini_get(ini, "mount", "write_mode")) != NULL) {
    if (strcmp(v, "through") == 0) p->write_mode = SD_PROFILE_WRITE_THROUGH;
    else if (strcmp(v, "behind") == 0) p->write_mode = SD_PROFILE_WRITE_BEHIND;
    else BAD("mount.write_mode");
    p->write_mode_set = 1;          /* M4: an absent key takes [defaults] write_mode */
  }
  if ((v = sd_ini_get(ini, "mount", "label")) != NULL && !scpy(p->label, sizeof(p->label), v)) BAD("mount.label");
  if ((v = sd_ini_get(ini, "mount", "network_location")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) BAD("mount.network_location");
    p->network_location = b;
  }
  if ((v = sd_ini_get(ini, "mount", "backend")) != NULL) {
    if (strcmp(v, "auto") == 0) p->backend = SD_PROFILE_BACKEND_AUTO;
    else if (strcmp(v, "dokany") == 0) p->backend = SD_PROFILE_BACKEND_DOKANY;
    else if (strcmp(v, "webdav") == 0) p->backend = SD_PROFILE_BACKEND_WEBDAV;
    else BAD("mount.backend");
  }
  if ((v = sd_ini_get(ini, "mount", "offline_wait")) != NULL && !sd_ini_parse_duration_ms(v, &p->offline_wait_ms))
    BAD("mount.offline_wait");
  if ((v = sd_ini_get(ini, "mount", "reconnect_grace")) != NULL &&
      !sd_ini_parse_duration_ms(v, &p->reconnect_grace_ms))
    BAD("mount.reconnect_grace");
  if ((v = sd_ini_get(ini, "cache", "disk")) == NULL)
    v = sd_ini_get(ini, "cache", "read_cache_disk");   /* 3.4.1 legacy name, rewritten on save */
  if (v != NULL) {
    uint64_t sz;
    if (!sd_ini_parse_size(v, &sz) || sz > ((uint64_t)1 << 40)) BAD("cache.disk");
    p->disk_cache_mb = (uint32_t)((sz + (1u << 20) - 1) >> 20);
  }
  if ((v = sd_ini_get(ini, "connection", "channels")) != NULL) {
    if (!sd_ini_parse_u32(v, &u) || u < 1 || u > 2) BAD("connection.channels");
    p->channels = u;
  }
  {
    const char *m2 = sd_profile_m2_from_ini(ini, p);
    if (m2) BAD(m2);
  }
  {
    const char *m3 = sd_profile_m3_from_ini(ini, p);
    if (m3) BAD(m3);
  }
  if (p->name[0] == 0)
    scpy(p->name, sizeof(p->name), p->host);
#undef BAD
  return sd_profile_validate(p, bad_key);
}

static void u32_dec(char out[16], uint32_t v)
{
  char tmp[16];
  size_t n = 0, i = 0;
  do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
  while (n) out[i++] = tmp[--n];
  out[i] = 0;
}

static void u32_ms(char out[16], uint32_t ms)
{
  u32_dec(out, ms);
  strcat_s(out, 16, "ms");
}

sd_err sd_profile_to_ini(const sd_profile *p, sd_ini **ini)
{
  char num[16], methods[64];
  sd_err e;
  sd_ini *d;
  if (*ini == NULL && (e = sd_ini_new(ini)) != SD_OK)
    return e;
  d = *ini;
  {
    uint32_t v = (uint32_t)p->port, i = 0;
    char tmp[16];
    size_t n = 0;
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (n) num[i++] = tmp[--n];
    num[i] = 0;
  }
  methods[0] = 0;
  if (p->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) strcat_s(methods, sizeof(methods), "publickey");
  if (p->auth_methods & SD_PROFILE_AUTH_KBDINT) {
    if (methods[0]) strcat_s(methods, sizeof(methods), ", ");
    strcat_s(methods, sizeof(methods), "keyboard-interactive");
  }
  if (p->auth_methods & SD_PROFILE_AUTH_PASSWORD) {
    if (methods[0]) strcat_s(methods, sizeof(methods), ", ");
    strcat_s(methods, sizeof(methods), "password");
  }
#define SET(s, k, v) do { if ((e = sd_ini_set(d, (s), (k), (v))) != SD_OK) return e; } while (0)
  SET("profile", "format", "1");
  if (p->id[0]) SET("profile", "id", p->id);
  SET("profile", "name", p->name);
  SET("profile", "host", p->host);
  SET("profile", "port", num);
  SET("profile", "user", p->user);
  SET("profile", "remote_path", p->remote_path);
  if (p->identity[0] || sd_ini_get(d, "auth", "identity")) SET("auth", "identity", p->identity);
  SET("auth", "methods", methods);
  SET("mount", "target", p->target);
  SET("mount", "read_only", p->read_only ? "yes" : "no");
  SET("mount", "symlinks", p->symlinks == SD_PROFILE_SYMLINKS_FOLLOW ? "follow"
                         : p->symlinks == SD_PROFILE_SYMLINKS_HIDE ? "hide" : "follow_inside");
  /* M4: written only when the profile sets it; an absent key follows [defaults] write_mode */
  if (p->write_mode_set || sd_ini_get(d, "mount", "write_mode"))
    SET("mount", "write_mode", p->write_mode == SD_PROFILE_WRITE_BEHIND ? "behind" : "through");
  if (p->label[0] || sd_ini_get(d, "mount", "label")) SET("mount", "label", p->label);
  /* the default is yes: written only when it is off or the key is already present */
  if (!p->network_location || sd_ini_get(d, "mount", "network_location"))
    SET("mount", "network_location", p->network_location ? "yes" : "no");
  /* M1 keys: only when set or already present, so M0 files stay as they were */
  if (p->backend != SD_PROFILE_BACKEND_AUTO || sd_ini_get(d, "mount", "backend"))
    SET("mount", "backend", p->backend == SD_PROFILE_BACKEND_DOKANY ? "dokany"
                          : p->backend == SD_PROFILE_BACKEND_WEBDAV ? "webdav" : "auto");
  if (p->offline_wait_ms || sd_ini_get(d, "mount", "offline_wait")) {
    u32_ms(num, p->offline_wait_ms);
    SET("mount", "offline_wait", num);
  }
  if (p->reconnect_grace_ms || sd_ini_get(d, "mount", "reconnect_grace")) {
    u32_ms(num, p->reconnect_grace_ms);
    SET("mount", "reconnect_grace", num);
  }
  if (p->disk_cache_mb || sd_ini_get(d, "cache", "disk")) {
    u32_dec(num, p->disk_cache_mb);
    strcat_s(num, sizeof(num), "M");
    SET("cache", "disk", num);
  }
  if (p->channels != 2 || sd_ini_get(d, "connection", "channels"))
    SET("connection", "channels", p->channels == 1 ? "1" : "2");
#undef SET
  e = sd_profile_m2_to_ini(p, d);
  if (e != SD_OK)
    return e;
  (void)sd_ini_remove(d, "cache", "read_cache_disk");
  return sd_profile_m3_to_ini(p, d);
}

sd_err sd_profile_new_id(char out[33])
{
  static const char hex[] = "0123456789abcdef";
  uint8_t r[16];
  size_t i;
  sd_pfn_RtlGenRandom gen = (sd_pfn_RtlGenRandom)sd_platform_resolve(SD_API_RtlGenRandom);
  if (gen == NULL || !gen(r, sizeof(r)))
    return SD_E_CRYPTO;
  for (i = 0; i < 16; i++) {
    out[2 * i] = hex[r[i] >> 4];
    out[2 * i + 1] = hex[r[i] & 15];
  }
  out[32] = 0;
  sd_secure_zero(r, sizeof(r));
  return SD_OK;
}

sd_err sd_parse_host_spec(const wchar_t *spec, char *user, size_t user_cap, char *host, size_t host_cap,
                          uint16_t *port)
{
  const wchar_t *at = NULL, *h, *end, *colon = NULL, *p;
  size_t n;
  if (spec == NULL || user_cap == 0 || host_cap == 0 || port == NULL)
    return SD_E_INVALID_PARAM;
  user[0] = 0;
  host[0] = 0;
  *port = 22;
  n = wcslen(spec);
  for (p = spec; *p; p++)
    if (*p == L'@') at = p;
  h = at ? at + 1 : spec;
  end = spec + n;
  if (at && !utf8_from_wide(spec, (size_t)(at - spec), user, user_cap))
    return SD_E_INVALID_PARAM;
  if (at && at == spec)
    return SD_E_INVALID_PARAM;           /* "@host" */
  if (*h == L'[') {                      /* [v6]:port */
    const wchar_t *rb = wcschr(h, L']');
    if (rb == NULL || rb == h + 1)
      return SD_E_INVALID_PARAM;
    if (!utf8_from_wide(h + 1, (size_t)(rb - h - 1), host, host_cap))
      return SD_E_INVALID_PARAM;
    if (rb[1] == L':') colon = rb + 1;
    else if (rb[1] != 0) return SD_E_INVALID_PARAM;
  } else {
    int colons = 0;
    for (p = h; *p; p++)
      if (*p == L':') { colons++; colon = p; }
    if (colons > 1) colon = NULL;        /* bare IPv6 literal, no port */
    if (!utf8_from_wide(h, (size_t)((colon ? colon : end) - h), host, host_cap))
      return SD_E_INVALID_PARAM;
  }
  if (colon) {
    uint32_t v = 0;
    const wchar_t *d = colon + 1;
    if (*d == 0)
      return SD_E_INVALID_PARAM;
    for (; *d; d++) {
      if (*d < L'0' || *d > L'9') return SD_E_INVALID_PARAM;
      v = v * 10u + (uint32_t)(*d - L'0');
      if (v > 65535) return SD_E_INVALID_PARAM;
    }
    if (v == 0) return SD_E_INVALID_PARAM;
    *port = (uint16_t)v;
  }
  if (!valid_host(host) || has_ctl(user))
    return SD_E_INVALID_PARAM;
  return SD_OK;
}

wchar_t sd_parse_drive_letter(const wchar_t *s)
{
  wchar_t c;
  if (s == NULL)
    return 0;
  c = s[0];
  if (c >= L'a' && c <= L'z') c = (wchar_t)(c - L'a' + L'A');
  if (c < L'A' || c > L'Z' || s[1] != L':')
    return 0;
  if (s[2] == 0 || (s[2] == L'\\' && s[3] == 0))
    return c;
  return 0;
}

/* ---- locations ---- */

static sd_err folder(int csidl, wchar_t *out, size_t cch)
{
  wchar_t base[MAX_PATH];
  if (cch < MAX_PATH)
    return SD_E_INVALID_PARAM;
  if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, base)))
    return SD_E_NOT_FOUND;
  if (!wcpy(out, cch, base) || !wcat(out, cch, L"\\" VENDOR_DIR L"\\" PRODUCT_DIR))
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

sd_err sd_config_root(wchar_t *out, size_t cch)
{
  if (g_root_override[0])
    return wcpy(out, cch, g_root_override) ? SD_OK : SD_E_NAME_TOO_LONG;
  return folder(CSIDL_APPDATA, out, cch);
}

sd_err sd_config_profiles_dir(wchar_t *out, size_t cch)
{
  sd_err e = sd_config_root(out, cch);
  if (e == SD_OK && !wcat(out, cch, L"\\profiles"))
    e = SD_E_NAME_TOO_LONG;
  return e;
}

sd_err sd_config_logs_dir(wchar_t *out, size_t cch)
{
  sd_err e = g_root_override[0] ? sd_config_root(out, cch) : folder(CSIDL_LOCAL_APPDATA, out, cch);
  if (e == SD_OK && !wcat(out, cch, L"\\logs"))
    e = SD_E_NAME_TOO_LONG;
  return e;
}

static sd_err user_sddl(wchar_t *out, size_t cch)
{
  HANDLE tok;
  uint8_t buf[256];
  DWORD len = 0;
  LPWSTR sid = NULL;
  int ok;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return SD_E_ACCESS_DENIED;
  ok = GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len) &&
       ConvertSidToStringSidW(((TOKEN_USER *)buf)->User.Sid, &sid);
  CloseHandle(tok);
  if (!ok)
    return SD_E_ACCESS_DENIED;
  out[0] = 0;
  ok = wcat(out, cch, L"D:P(A;OICI;FA;;;") && wcat(out, cch, sid) && wcat(out, cch, L")(A;OICI;FA;;;SY)");
  LocalFree(sid);
  return ok ? SD_OK : SD_E_INVALID_PARAM;
}

/* Creates a directory with the protected per-user DACL (TM-R07) if it does not exist. */
static sd_err make_dir(const wchar_t *path, int protect)
{
  SECURITY_ATTRIBUTES sa, *psa = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  wchar_t sddl[256];
  DWORD attr = GetFileAttributesW(path);
  sd_err e = SD_OK;
  if (attr != INVALID_FILE_ATTRIBUTES)
    return (attr & FILE_ATTRIBUTE_DIRECTORY) ? SD_OK : SD_E_NOT_A_DIRECTORY;
  if (protect && user_sddl(sddl, SD_COUNTOF(sddl)) == SD_OK &&
      ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) {
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    psa = &sa;
  }
  if (!CreateDirectoryW(path, psa) && GetLastError() != ERROR_ALREADY_EXISTS)
    e = GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (sd) LocalFree(sd);
  return e;
}

sd_err sd_config_make_protected_dir(const wchar_t *path)
{
  if (path == NULL || path[0] == 0)
    return SD_E_INVALID_PARAM;
  return make_dir(path, 1);
}

/* Creates every missing component of `dir`; components whose prefix length is >= protect_from_len
   (the product folder and below) get the protected DACL. */
static sd_err make_tree(const wchar_t *dir, int protect_from_len)
{
  wchar_t buf[MAX_PATH];
  size_t i, n = wcslen(dir);
  sd_err e;
  if (n >= MAX_PATH)
    return SD_E_NAME_TOO_LONG;
  memcpy(buf, dir, (n + 1) * sizeof(wchar_t));
  for (i = 3; i <= n; i++) {
    if (buf[i] == L'\\' || buf[i] == 0) {
      wchar_t save = buf[i];
      buf[i] = 0;
      e = make_dir(buf, (int)i >= protect_from_len);
      buf[i] = save;
      if (e != SD_OK)
        return e;
    }
  }
  return SD_OK;
}

sd_err sd_config_ensure_dirs(void)
{
  wchar_t root[MAX_PATH], sub[MAX_PATH];
  sd_err e = sd_config_root(root, SD_COUNTOF(root));
  int protect_from;
  if (e != SD_OK)
    return e;
  protect_from = (int)wcslen(root);
  if ((e = make_tree(root, protect_from)) != SD_OK)
    return e;
  if ((e = sd_config_profiles_dir(sub, SD_COUNTOF(sub))) != SD_OK || (e = make_dir(sub, 1)) != SD_OK)
    return e;
  if ((e = sd_config_logs_dir(sub, SD_COUNTOF(sub))) == SD_OK) {
    size_t n = wcslen(sub);
    /* protect <...>\ShellDrive and logs\ (LOCALAPPDATA tree may differ from the root) */
    e = make_tree(sub, (int)(n - 5));
  }
  return e;
}

static sd_err load_ini(const wchar_t *path, sd_ini **ini);
static sd_err write_atomic(const wchar_t *path, const void *data, size_t len);

sd_err sd_config_cache_dir(const char *key, wchar_t *out, size_t cch)
{
  static const wchar_t hex[] = L"0123456789abcdef";
  uint64_t hsh = 1469598103934665603ull;
  wchar_t name[18];
  size_t base, i;
  sd_err e;
  if (key == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  for (i = 0; key[i]; i++) {
    hsh ^= (uint8_t)key[i];
    hsh *= 1099511628211ull;
  }
  name[0] = L'\\';
  for (i = 0; i < 16; i++)
    name[1 + i] = hex[(hsh >> (60 - 4 * i)) & 15u];
  name[17] = 0;
  e = g_root_override[0] ? sd_config_root(out, cch) : folder(CSIDL_LOCAL_APPDATA, out, cch);
  if (e != SD_OK)
    return e;
  base = wcslen(out);
  if (!wcat(out, cch, L"\\cache") || !wcat(out, cch, name))
    return SD_E_NAME_TOO_LONG;
  /* protect <...>\ShellDrive and everything below it (the LOCALAPPDATA tree may differ from the root) */
  return make_tree(out, (int)base);
}

static int identity_path(const wchar_t *dir, wchar_t *out, size_t cch)
{
  return dir && wcpy(out, cch, dir) && wcat(out, cch, L"\\identity.ini");
}

sd_err sd_config_identity_load(const wchar_t *dir, const char *hostkey_fp, uint32_t *uid, uint32_t *gid)
{
  wchar_t path[MAX_PATH];
  sd_ini *ini = NULL;
  const char *fp, *u, *g;
  sd_err e;
  if (hostkey_fp == NULL || hostkey_fp[0] == 0 || uid == NULL || gid == NULL ||
      !identity_path(dir, path, SD_COUNTOF(path)))
    return SD_E_INVALID_PARAM;
  if ((e = load_ini(path, &ini)) != SD_OK)
    return SD_E_NOT_FOUND;
  fp = sd_ini_get(ini, "identity", "hostkey");
  u = sd_ini_get(ini, "identity", "uid");
  g = sd_ini_get(ini, "identity", "gid");
  e = (fp && strcmp(fp, hostkey_fp) == 0 && u && g && sd_ini_parse_u32(u, uid) && sd_ini_parse_u32(g, gid))
      ? SD_OK : SD_E_NOT_FOUND;
  sd_ini_free(ini);
  return e;
}

sd_err sd_config_identity_store(const wchar_t *dir, const char *hostkey_fp, uint32_t uid, uint32_t gid)
{
  wchar_t path[MAX_PATH];
  sd_ini *ini = NULL;
  char num[16];
  sd_wr w;
  sd_err e;
  if (hostkey_fp == NULL || hostkey_fp[0] == 0 || has_ctl(hostkey_fp) || !identity_path(dir, path, SD_COUNTOF(path)))
    return SD_E_INVALID_PARAM;
  if ((e = sd_ini_new(&ini)) != SD_OK)
    return e;
  e = sd_ini_set(ini, "identity", "hostkey", hostkey_fp);
  u32_dec(num, uid);
  if (e == SD_OK) e = sd_ini_set(ini, "identity", "uid", num);
  u32_dec(num, gid);
  if (e == SD_OK) e = sd_ini_set(ini, "identity", "gid", num);
  sd_wr_init(&w, SD_INI_MAX_BYTES);
  if (e == SD_OK) e = sd_ini_serialize(ini, &w);
  if (e == SD_OK) e = write_atomic(path, w.p, w.len);
  sd_wr_free(&w);
  sd_ini_free(ini);
  return e;
}

/* [ui] language: a BCP 47 style tag of letters and hyphens, 1 to 15 characters, or "system" (= ""). */
static int settings_lang_valid(const char *v)
{
  size_t i, n = strlen(v);
  if (strcmp(v, "system") == 0) return 1;
  if (n == 0 || n > 15) return 0;
  for (i = 0; i < n; i++) {
    char c = v[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-')) return 0;
  }
  return 1;
}

/* M4: the [ui] notify_<kind> keys, in sd_notify_kind order, with the 7.7 defaults (mounted and the pool limit are off). */
static const char *const k_notify_keys[SD_NOTIFY_COUNT] = {
  "notify_connection_lost", "notify_reconnected", "notify_mount_failed", "notify_mounted",
  "notify_legacy_algorithms", "notify_hostkeys_offered", "notify_hostkeys_saved", "notify_proxy_password",
  "notify_pool_limited", "notify_service_attention", "notify_update_available", "notify_update_stale",
  "notify_terrapin", "notify_hostkeys_source", "notify_disk_cache"
};
static const unsigned char k_notify_defaults[SD_NOTIFY_COUNT] = { 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1 };

void sd_settings_defaults(sd_settings *s)
{
  memset(s, 0, sizeof(*s));
  s->log_level = 2;
  s->openssh_source = 1;
  s->putty_source = 1;
  s->notify = 1;
  s->default_backend = SD_PROFILE_BACKEND_AUTO;
  strcpy_s(s->update_channel, sizeof(s->update_channel), "stable");
  s->default_write_mode = SD_PROFILE_WRITE_THROUGH;
  s->log_privacy = SD_SETTINGS_PRIVACY_STANDARD;
  memcpy(s->notify_kind, k_notify_defaults, sizeof(s->notify_kind));
}

sd_err sd_settings_from_ini(const sd_ini *ini, sd_settings *s)
{
  static const char *const levels[] = { "error", "warn", "info", "debug", "trace" };
  const char *v;
  sd_err e = SD_OK;
  int i;
  sd_settings_defaults(s);
  if ((v = sd_ini_get(ini, "log", "level")) != NULL) {
    for (i = 0; i < 5; i++)
      if (strcmp(v, levels[i]) == 0) break;
    if (i < 5) s->log_level = i;
    else { SD_LOGW("config", "settings.ini: invalid [log] level"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "cache", "memory")) != NULL) {
    uint64_t sz;
    if (sd_ini_parse_size(v, &sz)) s->cache_memory = sz;
    else { SD_LOGW("config", "settings.ini: invalid [cache] memory"); e = SD_E_INVALID_PARAM; }
  }
  {
    int b;
    if ((v = sd_ini_get(ini, "hostkeys", "openssh_source")) != NULL) {
      if (sd_ini_parse_bool(v, &b)) s->openssh_source = b;
      else { SD_LOGW("config", "settings.ini: invalid [hostkeys] openssh_source"); e = SD_E_INVALID_PARAM; }
    }
    if ((v = sd_ini_get(ini, "hostkeys", "putty_source")) != NULL) {
      if (sd_ini_parse_bool(v, &b)) s->putty_source = b;
      else { SD_LOGW("config", "settings.ini: invalid [hostkeys] putty_source"); e = SD_E_INVALID_PARAM; }
    }
    if ((v = sd_ini_get(ini, "credentials", "persist")) != NULL) {
      if (strcmp(v, "local") == 0) s->persist_enterprise = 0;
      else if (strcmp(v, "enterprise") == 0) s->persist_enterprise = 1;
      else { SD_LOGW("config", "settings.ini: invalid [credentials] persist"); e = SD_E_INVALID_PARAM; }
    }
  }
  if ((v = sd_ini_get(ini, "ui", "language")) != NULL) {
    if (settings_lang_valid(v)) { strcpy_s(s->ui_language, sizeof(s->ui_language), v); }
    else { SD_LOGW("config", "settings.ini: invalid [ui] language"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "ui", "notify")) != NULL) {
    int b;
    if (sd_ini_parse_bool(v, &b)) s->notify = b;
    else { SD_LOGW("config", "settings.ini: invalid [ui] notify"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "defaults", "backend")) != NULL) {
    if (strcmp(v, "auto") == 0) s->default_backend = SD_PROFILE_BACKEND_AUTO;
    else if (strcmp(v, "dokany") == 0) s->default_backend = SD_PROFILE_BACKEND_DOKANY;
    else if (strcmp(v, "webdav") == 0) s->default_backend = SD_PROFILE_BACKEND_WEBDAV;
    else { SD_LOGW("config", "settings.ini: invalid [defaults] backend"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "update", "channel")) != NULL) {
    if (strcmp(v, "stable") == 0 || strcmp(v, "beta") == 0)
      strcpy_s(s->update_channel, sizeof(s->update_channel), v);
    else { SD_LOGW("config", "settings.ini: invalid [update] channel"); e = SD_E_INVALID_PARAM; }
  }
  /* M4 */
  if ((v = sd_ini_get(ini, "defaults", "write_mode")) != NULL) {
    if (strcmp(v, "through") == 0) s->default_write_mode = SD_PROFILE_WRITE_THROUGH;
    else if (strcmp(v, "behind") == 0) s->default_write_mode = SD_PROFILE_WRITE_BEHIND;
    else { SD_LOGW("config", "settings.ini: invalid [defaults] write_mode"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "log", "privacy")) != NULL) {
    if (strcmp(v, "standard") == 0) s->log_privacy = SD_SETTINGS_PRIVACY_STANDARD;
    else if (strcmp(v, "strict") == 0) s->log_privacy = SD_SETTINGS_PRIVACY_STRICT;
    else { SD_LOGW("config", "settings.ini: invalid [log] privacy"); e = SD_E_INVALID_PARAM; }
  }
  if ((v = sd_ini_get(ini, "agent", "start_at_logon")) != NULL) {
    int b;
    if (sd_ini_parse_bool(v, &b)) s->agent_start_at_logon = b ? 1 : 0;
    else { SD_LOGW("config", "settings.ini: invalid [agent] start_at_logon"); e = SD_E_INVALID_PARAM; }
  }
  {
    unsigned k;
    for (k = 0; k < SD_NOTIFY_COUNT; k++) {
      int b;
      if ((v = sd_ini_get(ini, "ui", k_notify_keys[k])) == NULL)
        continue;
      if (sd_ini_parse_bool(v, &b)) s->notify_kind[k] = b ? 1 : 0;
      else { SD_LOGW("config", "settings.ini: invalid [ui] %s", k_notify_keys[k]); e = SD_E_INVALID_PARAM; }
    }
  }
  return e;
}

sd_err sd_settings_load(sd_settings *s)
{
  wchar_t path[MAX_PATH];
  sd_ini *ini = NULL;
  sd_err e;
  sd_settings_defaults(s);
  if ((e = sd_config_root(path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if (!wcat(path, SD_COUNTOF(path), L"\\settings.ini"))
    return SD_E_NAME_TOO_LONG;
  if (load_ini(path, &ini) != SD_OK)
    return SD_OK;                     /* no settings file: defaults */
  e = sd_settings_from_ini(ini, s);
  sd_ini_free(ini);
  return e;
}

static void put_size(char out[32], uint64_t v)
{
  static const uint64_t g = 1024u * 1024u * 1024u, m = 1024u * 1024u, k = 1024u;
  if (v && v % g == 0) sprintf_s(out, 32, "%uG", (unsigned)(v / g));
  else if (v && v % m == 0) sprintf_s(out, 32, "%uM", (unsigned)(v / m));
  else if (v && v % k == 0) sprintf_s(out, 32, "%uK", (unsigned)(v / k));
  else sprintf_s(out, 32, "%llu", (unsigned long long)v);
}

sd_err sd_settings_save(const sd_settings *s)
{
  static const char *const levels[] = { "error", "warn", "info", "debug", "trace" };
  static const char *const backends[] = { "auto", "dokany", "webdav" };
  wchar_t path[MAX_PATH];
  sd_ini *ini = NULL;
  HANDLE lock = NULL;
  sd_wr w;
  char num[32];
  sd_err e;
  int lvl;
  if (s == NULL || s->default_backend < 0 || s->default_backend > 2 || s->default_write_mode < 0 ||
      s->default_write_mode > 1 || s->log_privacy < 0 || s->log_privacy > 1)
    return SD_E_INVALID_PARAM;
  if ((e = sd_config_ensure_dirs()) != SD_OK)
    return e;
  if ((e = sd_config_root(path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if (!wcat(path, SD_COUNTOF(path), L"\\settings.ini"))
    return SD_E_NAME_TOO_LONG;
  if ((e = sd_config_lock(&lock, 5000)) != SD_OK)
    return e;
  if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
    e = sd_ini_new(&ini);
  } else {
    e = load_ini(path, &ini);
  }
  lvl = s->log_level < 0 ? 0 : (s->log_level > 4 ? 4 : s->log_level);
  if (e == SD_OK) e = sd_ini_set(ini, "log", "level", levels[lvl]);
  if (e == SD_OK) {
    if (s->cache_memory) { put_size(num, s->cache_memory); e = sd_ini_set(ini, "cache", "memory", num); }
    else { (void)sd_ini_remove(ini, "cache", "memory"); }
  }
  if (e == SD_OK) e = sd_ini_set(ini, "hostkeys", "openssh_source", s->openssh_source ? "yes" : "no");
  if (e == SD_OK) e = sd_ini_set(ini, "hostkeys", "putty_source", s->putty_source ? "yes" : "no");
  if (e == SD_OK) e = sd_ini_set(ini, "credentials", "persist", s->persist_enterprise ? "enterprise" : "local");
  if (e == SD_OK) {
    if (s->ui_language[0]) e = sd_ini_set(ini, "ui", "language", s->ui_language);
    else (void)sd_ini_remove(ini, "ui", "language");
  }
  if (e == SD_OK) e = sd_ini_set(ini, "ui", "notify", s->notify ? "yes" : "no");
  if (e == SD_OK) e = sd_ini_set(ini, "defaults", "backend", backends[s->default_backend]);
  /* stable is the default: the key is written only for beta, and removed otherwise */
  if (e == SD_OK) {
    if (strcmp(s->update_channel, "beta") == 0) e = sd_ini_set(ini, "update", "channel", "beta");
    else (void)sd_ini_remove(ini, "update", "channel");
  }
  /* M4: every key is written, so the file says what is in effect */
  if (e == SD_OK) e = sd_ini_set(ini, "defaults", "write_mode", s->default_write_mode ? "behind" : "through");
  if (e == SD_OK) e = sd_ini_set(ini, "log", "privacy", s->log_privacy ? "strict" : "standard");
  if (e == SD_OK) e = sd_ini_set(ini, "agent", "start_at_logon", s->agent_start_at_logon ? "yes" : "no");
  {
    unsigned i;
    for (i = 0; e == SD_OK && i < SD_NOTIFY_COUNT; i++)
      e = sd_ini_set(ini, "ui", k_notify_keys[i], s->notify_kind[i] ? "yes" : "no");
  }
  if (e == SD_OK) {
    sd_wr_init(&w, SD_INI_MAX_BYTES);
    e = sd_ini_serialize(ini, &w);
    if (e == SD_OK) e = write_atomic(path, w.p, w.len);
    sd_wr_free(&w);
  }
  sd_ini_free(ini);
  sd_config_unlock(lock);
  return e;
}

/* ---- M4 settings helpers (03 §3.4, §7.7, §10.1) ---- */

const char *sd_notify_kind_key(sd_notify_kind k)
{
  if ((unsigned)k >= SD_NOTIFY_COUNT)
    return "";
  return k_notify_keys[(unsigned)k];
}

int sd_notify_kind_from_code(const char *code)
{
  static const struct { const char *code; int kind; } map[] = {
    { "legacy_algorithms", SD_NOTIFY_LEGACY_ALGORITHMS }, { "terrapin_exposed", SD_NOTIFY_TERRAPIN },
    { "pool_limited", SD_NOTIFY_POOL_LIMITED }, { "proxy_password", SD_NOTIFY_PROXY_PASSWORD },
    { "hostkey_source_insecure", SD_NOTIFY_HOSTKEYS_SOURCE }, { "disk_cache_refused", SD_NOTIFY_DISK_CACHE },
    { "update_stale", SD_NOTIFY_UPDATE_STALE }, { "service_attention", SD_NOTIFY_SERVICE_ATTENTION },
  };
  size_t i;
  if (code == NULL)
    return -1;
  for (i = 0; i < SD_COUNTOF(map); i++)
    if (strcmp(code, map[i].code) == 0)
      return map[i].kind;
  return -1;
}

int sd_settings_notify_on(const sd_settings *s, int kind)
{
  if (s == NULL || !s->notify)
    return 0;
  if (kind < 0 || kind >= SD_NOTIFY_COUNT)
    return 1;
  return s->notify_kind[kind] ? 1 : 0;
}

sd_err sd_profile_effective_write_mode(const sd_profile *p, const sd_settings *s, int policy_force_through, int *mode)
{
  int m;
  if (p == NULL || mode == NULL)
    return SD_E_INVALID_PARAM;
  m = p->write_mode_set ? p->write_mode : (s != NULL ? s->default_write_mode : SD_PROFILE_WRITE_THROUGH);
  if (m != SD_PROFILE_WRITE_THROUGH && m != SD_PROFILE_WRITE_BEHIND)
    m = SD_PROFILE_WRITE_THROUGH;
  if (policy_force_through && m == SD_PROFILE_WRITE_BEHIND) {
    if (p->write_mode_set) {
      *mode = SD_PROFILE_WRITE_THROUGH;
      return SD_E_ACCESS_DENIED;          /* 03 §3.5: ForceWriteThrough refuses an explicit behind */
    }
    m = SD_PROFILE_WRITE_THROUGH;         /* a default is clamped */
  }
  *mode = m;
  return SD_OK;
}

int sd_settings_effective_privacy(const sd_settings *s, int policy_value)
{
  if (policy_value == 0 || policy_value == 1)
    return policy_value;
  return s != NULL && s->log_privacy == SD_SETTINGS_PRIVACY_STRICT ? SD_SETTINGS_PRIVACY_STRICT
                                                                  : SD_SETTINGS_PRIVACY_STANDARD;
}

static int any_logon_profile_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  SD_UNUSED(path);
  if (p->autostart == SD_PROFILE_AUTOSTART_LOGON) {
    *(int *)ctx = 1;
    return 0;                              /* found: stop */
  }
  return 1;
}

int sd_settings_agent_run_wanted(const sd_settings *s)
{
  int found = 0;
  if (s != NULL && s->agent_start_at_logon)
    return 1;
  (void)sd_profile_enum(any_logon_profile_cb, &found);
  return found;
}

sd_err sd_config_log_key(uint8_t key[32])
{
  wchar_t dir[MAX_PATH], path[MAX_PATH];
  HANDLE h;
  DWORD n = 0;
  BOOL ok;
  sd_err e;
  if (key == NULL)
    return SD_E_INVALID_PARAM;
  if ((e = sd_config_root(dir, SD_COUNTOF(dir))) != SD_OK)
    return e;
  if (!wcat(dir, SD_COUNTOF(dir), L"\\state"))
    return SD_E_NAME_TOO_LONG;
  if (!wcpy(path, SD_COUNTOF(path), dir) || !wcat(path, SD_COUNTOF(path), L"\\log.key"))
    return SD_E_NAME_TOO_LONG;
  if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES && (e = sd_config_make_protected_dir(dir)) != SD_OK)
    return e;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    ok = ReadFile(h, key, 32, &n, NULL);
    CloseHandle(h);
    return ok && n == 32 ? SD_OK : SD_E_FAILURE;
  }
  if ((e = sd_random(key, 32)) != SD_OK)
    return e;
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_ACCESS_DENIED;             /* lost a race with another writer: the next start reads it */
  ok = WriteFile(h, key, 32, &n, NULL);
  CloseHandle(h);
  return ok && n == 32 ? SD_OK : SD_E_FAILURE;
}

sd_err sd_config_expand_path(const char *utf8, wchar_t *out, size_t cch)
{
  wchar_t raw[MAX_PATH * 2], tmp[MAX_PATH * 2];
  DWORD n;
  if (utf8 == NULL || cch == 0)
    return SD_E_INVALID_PARAM;
  if (!wide_from_utf8(utf8, raw, SD_COUNTOF(raw)))
    return SD_E_INVALID_PARAM;
  if (raw[0] == L'~' && (raw[1] == L'\\' || raw[1] == L'/')) {
    if (!wcpy(tmp, SD_COUNTOF(tmp), L"%USERPROFILE%\\") || !wcat(tmp, SD_COUNTOF(tmp), raw + 2))
      return SD_E_NAME_TOO_LONG;
    wcpy(raw, SD_COUNTOF(raw), tmp);
  }
  n = ExpandEnvironmentStringsW(raw, out, (DWORD)cch);
  if (n == 0 || n > cch)
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

/* ---- files ---- */

sd_err sd_config_lock(HANDLE *lock, DWORD timeout_ms)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  OVERLAPPED ov;
  uint64_t deadline = sd_tick_ms() + timeout_ms;
  sd_err e;
  *lock = NULL;
  if ((e = sd_config_ensure_dirs()) != SD_OK)
    return e;
  if ((e = sd_config_root(path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if (!wcat(path, SD_COUNTOF(path), L"\\config.lock"))
    return SD_E_NAME_TOO_LONG;
  h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_ACCESS_DENIED;
  for (;;) {
    memset(&ov, 0, sizeof(ov));
    if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)) {
      *lock = h;
      return SD_OK;
    }
    if (sd_tick_ms() >= deadline) {
      CloseHandle(h);
      return SD_E_TIMEOUT;
    }
    Sleep(20);
  }
}

void sd_config_unlock(HANDLE lock)
{
  OVERLAPPED ov;
  if (lock == NULL)
    return;
  memset(&ov, 0, sizeof(ov));
  UnlockFileEx(lock, 0, 1, 0, &ov);
  CloseHandle(lock);
}

static sd_err read_file(const wchar_t *path, char **data, size_t *len)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  char *buf;
  *data = NULL;
  *len = 0;
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > SD_INI_MAX_BYTES) {
    CloseHandle(h);
    return SD_E_INVALID_PARAM;
  }
  buf = (char *)sd_alloc((size_t)sz.QuadPart + 1);
  if (buf == NULL) {
    CloseHandle(h);
    return SD_E_NO_MEMORY;
  }
  if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart) {
    CloseHandle(h);
    sd_free(buf);
    return SD_E_FAILURE;
  }
  CloseHandle(h);
  buf[got] = 0;
  *data = buf;
  *len = got;
  return SD_OK;
}

static sd_err load_ini(const wchar_t *path, sd_ini **ini)
{
  char *data;
  size_t len;
  uint32_t flags = 0;
  sd_err e = read_file(path, &data, &len);
  if (e != SD_OK)
    return e;
  e = sd_ini_parse(data, len, ini, &flags);
  sd_free(data);
  if (e == SD_OK && (flags & SD_INI_F_ANSI_DECODED))
    SD_LOGW("config", "%ls is not UTF-8; decoded with the ANSI code page", path);
  if (e == SD_OK && (flags & SD_INI_F_INVALID_LINES))
    SD_LOGW("config", "%ls has lines that are not valid INI; they are kept but ignored", path);
  return e;
}

sd_err sd_profile_load_file(const wchar_t *path, sd_profile *p, const char **bad_key)
{
  sd_ini *ini = NULL;
  sd_err e = load_ini(path, &ini);
  if (e != SD_OK)
    return e;
  e = sd_profile_from_ini(ini, p, bad_key);
  sd_ini_free(ini);
  return e;
}

sd_err sd_profile_enum(sd_profile_enum_cb cb, void *ctx)
{
  wchar_t dir[MAX_PATH], pattern[MAX_PATH], path[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  sd_profile *pp;
  sd_err e = sd_config_profiles_dir(dir, SD_COUNTOF(dir));
  if (e != SD_OK)
    return e;
  if (!wcpy(pattern, SD_COUNTOF(pattern), dir) || !wcat(pattern, SD_COUNTOF(pattern), L"\\*.ini"))
    return SD_E_NAME_TOO_LONG;
  f = FindFirstFileExW(pattern, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  if (f == INVALID_HANDLE_VALUE)
    return SD_OK;   /* no profiles (or no folder yet) */
  if ((pp = (sd_profile *)sd_alloc(sizeof(*pp))) == NULL) {
    FindClose(f);
    return SD_E_NO_MEMORY;
  }
  do {
    const char *bad = NULL;
    size_t nl = wcslen(fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      continue;
    if (nl < 4 || _wcsicmp(fd.cFileName + nl - 4, L".ini") != 0)
      continue;   /* *.ini also matches *.ini.tmp on 8.3 names */
    if (!wcpy(path, SD_COUNTOF(path), dir) || !wcat(path, SD_COUNTOF(path), L"\\") ||
        !wcat(path, SD_COUNTOF(path), fd.cFileName))
      continue;
    if (sd_profile_load_file(path, pp, &bad) != SD_OK) {
      SD_LOGW("config", "skipping profile %ls (invalid %s)", path, bad ? bad : "file");
      continue;
    }
    if (!cb(ctx, pp, path))
      break;
  } while (FindNextFileW(f, &fd));
  FindClose(f);
  sd_free(pp);
  return SD_OK;
}

typedef struct find_ctx {
  const char *key;
  int by_id;
  sd_profile *out;
  wchar_t *path;
  size_t path_cch;
  int found;
} find_ctx;

static int ascii_ieq(const char *a, const char *b)
{
  for (; *a && *b; a++, b++) {
    char x = *a, y = *b;
    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
    if (x != y) return 0;
  }
  return *a == *b;
}

static int names_equal(const char *a, const char *b)
{
  wchar_t wa[128], wb[128];
  if (ascii_ieq(a, b))
    return 1;
  if (!wide_from_utf8(a, wa, SD_COUNTOF(wa)) || !wide_from_utf8(b, wb, SD_COUNTOF(wb)))
    return 0;
  return CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE, wa, -1, wb, -1) == CSTR_EQUAL;
}

static int find_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  find_ctx *f = (find_ctx *)ctx;
  int match = f->by_id ? strcmp(p->id, f->key) == 0 : names_equal(p->name, f->key);
  if (!match)
    return 1;
  if (f->out) *f->out = *p;
  if (f->path) wcpy(f->path, f->path_cch, path);
  f->found = 1;
  return 0;
}

sd_err sd_profile_find(const char *name_or_id, sd_profile *p, wchar_t *path_out, size_t path_cch)
{
  find_ctx f;
  sd_err e;
  if (name_or_id == NULL || name_or_id[0] == 0)
    return SD_E_INVALID_PARAM;
  memset(&f, 0, sizeof(f));
  f.key = name_or_id;
  f.out = p;
  f.path = path_out;
  f.path_cch = path_cch;
  /* ids first (exact), then names */
  f.by_id = valid_id(name_or_id);
  if (f.by_id) {
    if ((e = sd_profile_enum(find_cb, &f)) != SD_OK) return e;
    if (f.found) return SD_OK;
    f.by_id = 0;
  }
  if ((e = sd_profile_enum(find_cb, &f)) != SD_OK) return e;
  return f.found ? SD_OK : SD_E_NOT_FOUND;
}

static void slug(const char *name, wchar_t *out, size_t cch)
{
  size_t i, o = 0;
  int dash = 0;
  for (i = 0; name[i] && o + 1 < cch && o < 48; i++) {
    char c = name[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      out[o++] = (wchar_t)c;
      dash = 0;
    } else if (o > 0 && !dash) {
      out[o++] = L'-';
      dash = 1;
    }
  }
  while (o > 0 && out[o - 1] == L'-') o--;
  out[o] = 0;
}

static sd_err write_atomic(const wchar_t *path, const void *data, size_t len)
{
  wchar_t tmp[MAX_PATH];
  HANDLE h;
  DWORD put = 0;
  BOOL ok;
  if (!wcpy(tmp, SD_COUNTOF(tmp), path) || !wcat(tmp, SD_COUNTOF(tmp), L".tmp"))
    return SD_E_NAME_TOO_LONG;
  h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_ACCESS_DENIED;
  ok = WriteFile(h, data, (DWORD)len, &put, NULL) && put == (DWORD)len && FlushFileBuffers(h);
  CloseHandle(h);
  if (!ok || !MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(tmp);
    return SD_E_FAILURE;
  }
  return SD_OK;
}

sd_err sd_profile_save(sd_profile *p)
{
  wchar_t path[MAX_PATH], dir[MAX_PATH], name[64];
  sd_ini *ini = NULL;
  HANDLE lock = NULL;
  sd_profile *existing;
  sd_wr w;
  sd_err e;
  const char *bad = NULL;
  if (p->name[0] == 0)
    scpy(p->name, sizeof(p->name), p->host);
  if (p->id[0] == 0 && (e = sd_profile_new_id(p->id)) != SD_OK)
    return e;
  if ((e = sd_profile_validate(p, &bad)) != SD_OK)
    return e;
  if ((existing = (sd_profile *)sd_alloc(sizeof(*existing))) == NULL)
    return SD_E_NO_MEMORY;
  if ((e = sd_config_lock(&lock, 5000)) != SD_OK) {
    sd_free(existing);
    return e;
  }
  if (sd_profile_find(p->id, existing, path, SD_COUNTOF(path)) == SD_OK && strcmp(existing->id, p->id) == 0) {
    e = load_ini(path, &ini);
  } else {
    /* new file: <slug>.ini, or <slug>-<id prefix>.ini if taken */
    e = sd_config_profiles_dir(dir, SD_COUNTOF(dir));
    if (e == SD_OK) {
      slug(p->name, name, SD_COUNTOF(name));
      if (name[0] == 0) {
        size_t i;
        for (i = 0; i < 8; i++) name[i] = (wchar_t)p->id[i];
        name[8] = 0;
      }
      if (!wcpy(path, SD_COUNTOF(path), dir) || !wcat(path, SD_COUNTOF(path), L"\\") ||
          !wcat(path, SD_COUNTOF(path), name) || !wcat(path, SD_COUNTOF(path), L".ini"))
        e = SD_E_NAME_TOO_LONG;
      else if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        wchar_t suffix[10];
        size_t i;
        suffix[0] = L'-';
        for (i = 0; i < 8; i++) suffix[i + 1] = (wchar_t)p->id[i];
        suffix[9] = 0;
        path[wcslen(path) - 4] = 0;
        if (!wcat(path, SD_COUNTOF(path), suffix) || !wcat(path, SD_COUNTOF(path), L".ini"))
          e = SD_E_NAME_TOO_LONG;
      }
    }
  }
  if (e == SD_OK)
    e = sd_profile_to_ini(p, &ini);
  if (e == SD_OK) {
    sd_wr_init(&w, SD_INI_MAX_BYTES);
    e = sd_ini_serialize(ini, &w);
    if (e == SD_OK)
      e = write_atomic(path, w.p, w.len);
    sd_wr_free(&w);
  }
  sd_ini_free(ini);
  sd_config_unlock(lock);
  sd_free(existing);
  return e;
}

sd_err sd_profile_delete(const char *name_or_id)
{
  wchar_t path[MAX_PATH];
  HANDLE lock = NULL;
  sd_err e = sd_config_lock(&lock, 5000);
  if (e != SD_OK)
    return e;
  e = sd_profile_find(name_or_id, NULL, path, SD_COUNTOF(path));
  if (e == SD_OK && !DeleteFileW(path))
    e = SD_E_ACCESS_DENIED;
  sd_config_unlock(lock);
  return e;
}
