/* sd_secret: Credential Manager, DPAPI secret files and DPAPI-kept keys (03 §4). See sd_secret.h. */
#include <windows.h>
#include <wincred.h>
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <string.h>

#include "sd_secret/sd_secret.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"

#define SECRET_MAGIC "SDSEC1\0\0"
#define KEY_MAGIC    "SDKEY1\0\0"
#define FILE_MAX     (256u * 1024u)

static const char *const k_kind_names[] = { "password", "passphrase", "proxy" };

static struct {
  int init;
  CRITICAL_SECTION cs;
  wchar_t user_dir[MAX_PATH];
  wchar_t service_dir[MAX_PATH];
  char prefix[64];
  int persist_enterprise;
  int force_dpapi;
} g;

static void ensure_init(void)
{
  /* sd_secret_configure is called once at start (before threads); a first use without it gets
     the defaults. The critical section only guards concurrent first use. */
  if (!g.init) {
    InitializeCriticalSection(&g.cs);
    strcpy_s(g.prefix, sizeof(g.prefix), SD_SECRET_PREFIX);
    g.init = 1;
  }
}

static int wcopy(wchar_t *dst, size_t cch, const wchar_t *src)
{
  size_t n = src ? wcslen(src) : 0;
  if (n + 1 > cch) return 0;
  if (n) memcpy(dst, src, n * sizeof(wchar_t));
  dst[n] = 0;
  return 1;
}

static int wappend(wchar_t *dst, size_t cch, const wchar_t *src)
{
  size_t n = wcslen(dst);
  return wcopy(dst + n, cch - n, src);
}

sd_err sd_secret_configure(const sd_secret_config *cfg)
{
  ensure_init();
  EnterCriticalSection(&g.cs);
  g.user_dir[0] = g.service_dir[0] = 0;
  strcpy_s(g.prefix, sizeof(g.prefix), SD_SECRET_PREFIX);
  g.persist_enterprise = 0;
  g.force_dpapi = 0;
  if (cfg) {
    size_t pn = cfg->prefix ? strlen(cfg->prefix) : 0;
    if ((cfg->user_dir && !wcopy(g.user_dir, MAX_PATH, cfg->user_dir)) ||
        (cfg->service_dir && !wcopy(g.service_dir, MAX_PATH, cfg->service_dir)) ||
        (cfg->prefix && (pn == 0 || pn >= sizeof(g.prefix) || cfg->prefix[pn - 1] != ':'))) {
      g.user_dir[0] = g.service_dir[0] = 0;
      LeaveCriticalSection(&g.cs);
      return SD_E_INVALID_PARAM;
    }
    if (cfg->prefix) memcpy(g.prefix, cfg->prefix, pn + 1);
    g.persist_enterprise = cfg->persist_enterprise;
    g.force_dpapi = cfg->force_dpapi;
  }
  LeaveCriticalSection(&g.cs);
  return SD_OK;
}

/* ---- target names ---- */

static int put_c(char *out, size_t cap, size_t *o, char c)
{
  if (*o + 1 >= cap) return 0;
  out[(*o)++] = c;
  return 1;
}

static int put_s(char *out, size_t cap, size_t *o, const char *s)
{
  for (; *s; s++)
    if (!put_c(out, cap, o, *s)) return 0;
  return 1;
}

/* user part: '%' and A-Z escaped; host part lowercased. s = "<user>@<host>:<port>". */
static int put_userhost(char *out, size_t cap, size_t *o, const char *s)
{
  static const char hex[] = "0123456789ABCDEF";
  const char *at = strrchr(s, '@'), *p;
  if (at == NULL || at == s || at[1] == 0)
    return 0;
  for (p = s; p < at; p++) {
    unsigned char c = (unsigned char)*p;
    if (c < 0x20 || c == 0x7F) return 0;
    if (c == '%' || (c >= 'A' && c <= 'Z')) {
      if (!put_c(out, cap, o, '%') || !put_c(out, cap, o, hex[c >> 4]) || !put_c(out, cap, o, hex[c & 15]))
        return 0;
    } else if (!put_c(out, cap, o, (char)c)) {
      return 0;
    }
  }
  for (p = at; *p; p++) {
    char c = *p;
    if ((unsigned char)c < 0x20 || c == 0x7F) return 0;
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (!put_c(out, cap, o, c)) return 0;
  }
  return 1;
}

sd_err sd_secret_target_name(sd_secret_kind k, const char *target, char *out, size_t cap)
{
  size_t o = 0;
  int ok;
  ensure_init();
  if (target == NULL || out == NULL || cap == 0 || (unsigned)k > SD_SECRET_PROXY)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  ok = put_s(out, cap, &o, g.prefix) && put_s(out, cap, &o, k_kind_names[k]) && put_c(out, cap, &o, ':');
  if (ok) {
    if (k == SD_SECRET_PASSWORD) {
      ok = put_userhost(out, cap, &o, target);
    } else if (k == SD_SECRET_PROXY) {
      const char *colon = strchr(target, ':');
      size_t sl = colon ? (size_t)(colon - target) : 0;
      if (colon == NULL || !((sl == 4 && _strnicmp(target, "http", 4) == 0) ||
                             (sl == 6 && _strnicmp(target, "socks5", 6) == 0)))
        ok = 0;
      else
        ok = put_s(out, cap, &o, sl == 4 ? "http:" : "socks5:") && put_userhost(out, cap, &o, colon + 1);
    } else {
      const char *p;
      if (strncmp(target, "SHA256:", 7) != 0 || target[7] == 0)
        ok = 0;
      for (p = target; ok && *p; p++)
        if ((unsigned char)*p <= 0x20 || *p == 0x7F) ok = 0;
      if (ok) ok = put_s(out, cap, &o, target);
    }
  }
  if (!ok) {
    out[0] = 0;
    return SD_E_INVALID_PARAM;
  }
  out[o] = 0;
  return SD_OK;
}

static int dec_port(char *out, size_t cap, size_t *o, uint16_t port)
{
  char tmp[8];
  size_t n = 0;
  uint32_t v = port ? port : 22;
  do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
  while (n)
    if (!put_c(out, cap, o, tmp[--n])) return 0;
  return 1;
}

static int put_host(char *out, size_t cap, size_t *o, const char *host)
{
  int v6 = strchr(host, ':') != NULL && host[0] != '[';
  return (!v6 || put_c(out, cap, o, '[')) && put_s(out, cap, o, host) && (!v6 || put_c(out, cap, o, ']'));
}

sd_err sd_secret_target_password(const char *user, const char *host, uint16_t port, char *out, size_t cap)
{
  size_t o = 0;
  if (user == NULL || host == NULL || user[0] == 0 || host[0] == 0 || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  if (!put_s(out, cap, &o, user) || !put_c(out, cap, &o, '@') || !put_host(out, cap, &o, host) ||
      !put_c(out, cap, &o, ':') || !dec_port(out, cap, &o, port)) {
    out[0] = 0;
    return SD_E_NAME_TOO_LONG;
  }
  out[o] = 0;
  return SD_OK;
}

sd_err sd_secret_target_proxy(const char *scheme, const char *user, const char *host, uint16_t port,
                              char *out, size_t cap)
{
  size_t o = 0;
  if (scheme == NULL || (strcmp(scheme, "http") != 0 && strcmp(scheme, "socks5") != 0) || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  if (user == NULL || user[0] == 0 || host == NULL || host[0] == 0 || port == 0)
    return SD_E_INVALID_PARAM;
  if (!put_s(out, cap, &o, scheme) || !put_c(out, cap, &o, ':') || !put_s(out, cap, &o, user) ||
      !put_c(out, cap, &o, '@') || !put_host(out, cap, &o, host) || !put_c(out, cap, &o, ':') ||
      !dec_port(out, cap, &o, port)) {
    out[0] = 0;
    return SD_E_NAME_TOO_LONG;
  }
  out[o] = 0;
  return SD_OK;
}

/* Splits "<prefix><kind>:<raw>" back; 0 if the name is not ours. */
static int parse_full(const char *full, sd_secret_kind *k, const char **raw)
{
  size_t pl = strlen(g.prefix), i;
  if (_strnicmp(full, g.prefix, pl) != 0)
    return 0;
  full += pl;
  for (i = 0; i < SD_COUNTOF(k_kind_names); i++) {
    size_t n = strlen(k_kind_names[i]);
    if (_strnicmp(full, k_kind_names[i], n) == 0 && full[n] == ':') {
      *k = (sd_secret_kind)i;
      *raw = full + n + 1;
      return 1;
    }
  }
  return 0;
}

/* ---- locations ---- */

static sd_err service_root(wchar_t *out, size_t cch)
{
  wchar_t base[MAX_PATH];
  if (g.service_dir[0])
    return wcopy(out, cch, g.service_dir) ? SD_OK : SD_E_NAME_TOO_LONG;
  if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, base)))
    return SD_E_NOT_FOUND;
  if (!wcopy(out, cch, base) || !wappend(out, cch, L"\\LibreStatic\\ShellDrive\\service"))
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

/* SYSTEM-only folder for the service store (03 §4.5). */
static sd_err make_service_dir(const wchar_t *path)
{
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd = NULL;
  DWORD attr = GetFileAttributesW(path);
  BOOL ok;
  if (attr != INVALID_FILE_ATTRIBUTES)
    return (attr & FILE_ATTRIBUTE_DIRECTORY) ? SD_OK : SD_E_NOT_A_DIRECTORY;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)", SDDL_REVISION_1, &sd, NULL))
    return SD_E_ACCESS_DENIED;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  ok = CreateDirectoryW(path, &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
  LocalFree(sd);
  return ok ? SD_OK : SD_E_ACCESS_DENIED;
}

/* <root>\<sub> (created when create != 0). */
static sd_err store_dir(sd_secret_scope s, const wchar_t *sub, int create, wchar_t *out, size_t cch)
{
  sd_err e;
  if (s == SD_SECRET_SERVICE) {
    if ((e = service_root(out, cch)) != SD_OK)
      return e;
  } else if (g.user_dir[0]) {
    if (!wcopy(out, cch, g.user_dir))
      return SD_E_NAME_TOO_LONG;
  } else if ((e = sd_config_root(out, cch)) != SD_OK) {
    return e;
  }
  if (create) {
    if (s == SD_SECRET_SERVICE) {
      if ((e = make_service_dir(out)) != SD_OK) return e;
    } else if ((e = sd_config_make_protected_dir(out)) != SD_OK) {
      return e;
    }
  }
  if (!wappend(out, cch, L"\\") || !wappend(out, cch, sub))
    return SD_E_NAME_TOO_LONG;
  if (create)
    return s == SD_SECRET_SERVICE ? make_service_dir(out) : sd_config_make_protected_dir(out);
  return SD_OK;
}

static sd_err secret_file(sd_secret_scope s, const char *full, int create, wchar_t *out, size_t cch)
{
  static const wchar_t hex[] = L"0123456789abcdef";
  uint8_t h[32];
  wchar_t name[80];
  size_t i;
  sd_err e = store_dir(s, L"secrets", create, out, cch);
  if (e != SD_OK)
    return e;
  sd_hash(SD_HASH_SHA256, full, strlen(full), h);
  name[0] = L'\\';
  for (i = 0; i < 32; i++) {
    name[1 + 2 * i] = hex[h[i] >> 4];
    name[2 + 2 * i] = hex[h[i] & 15];
  }
  name[65] = 0;
  return (wappend(out, cch, name) && wappend(out, cch, L".sdsec")) ? SD_OK : SD_E_NAME_TOO_LONG;
}

/* ---- file helpers ---- */

static sd_err write_atomic(const wchar_t *path, const void *data, size_t len)
{
  wchar_t tmp[MAX_PATH + 8];
  HANDLE h;
  DWORD put = 0;
  BOOL ok;
  if (!wcopy(tmp, SD_COUNTOF(tmp), path) || !wappend(tmp, SD_COUNTOF(tmp), L".tmp"))
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

static sd_err read_all(const wchar_t *path, uint8_t **data, size_t *len)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  uint8_t *buf;
  *data = NULL;
  *len = 0;
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > FILE_MAX || sz.QuadPart < 16) {
    CloseHandle(h);
    return SD_E_KEY_FORMAT;
  }
  buf = (uint8_t *)sd_alloc((size_t)sz.QuadPart);
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
  *data = buf;
  *len = got;
  return SD_OK;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void put_le32(sd_wr *w, uint32_t v)
{
  uint8_t b[4];
  b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
  sd_wr_bytes(w, b, 4);
}

/* ---- DPAPI ---- */

static sd_err protect(const void *data, size_t len, const char *entropy, const wchar_t *descr, DATA_BLOB *out)
{
  DATA_BLOB in, ent;
  in.pbData = (BYTE *)data;
  in.cbData = (DWORD)len;
  ent.pbData = (BYTE *)entropy;
  ent.cbData = (DWORD)strlen(entropy);
  memset(out, 0, sizeof(*out));
  if (!CryptProtectData(&in, descr, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, out))
    return SD_E_CRYPTO;
  return SD_OK;
}

/* Decrypts into a secret buffer (exact length). descr_out (optional) receives the description as UTF-8. */
static sd_err unprotect(const uint8_t *blob, size_t len, const char *entropy, sd_secbuf **out, char *descr_out,
                        size_t descr_cap)
{
  DATA_BLOB in, ent, res;
  LPWSTR descr = NULL;
  sd_err e;
  in.pbData = (BYTE *)blob;
  in.cbData = (DWORD)len;
  ent.pbData = (BYTE *)entropy;
  ent.cbData = (DWORD)strlen(entropy);
  memset(&res, 0, sizeof(res));
  *out = NULL;
  if (!CryptUnprotectData(&in, &descr, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &res))
    return SD_E_CRYPTO;
  if (descr_out && descr_cap) {
    size_t got = 0;
    descr_out[0] = 0;
    if (descr && sd_utf16_to_utf8(descr, wcslen(descr), descr_out, descr_cap - 1, &got, SD_UTF_REPLACE) == SD_OK)
      descr_out[got] = 0;
  }
  if (descr) LocalFree(descr);
  e = sd_secbuf_new(res.cbData + 2, out);
  if (e == SD_OK) {
    memcpy((*out)->p, res.pbData, res.cbData);
    (*out)->len = res.cbData;
  }
  SecureZeroMemory(res.pbData, res.cbData);
  LocalFree(res.pbData);
  return e;
}

static int entropy_for(const char *base, const char *name, char *out, size_t cap)
{
  size_t o = 0;
  return put_s(out, cap, &o, base) && put_s(out, cap, &o, name) && (out[o] = 0, 1);
}

/* ---- value conversion (UTF-8 <-> UTF-16LE blob) ---- */

static sd_err to_blob(const char *value, size_t len, sd_secbuf **out)
{
  size_t got = 0;
  sd_err e;
  if (len > SD_SECRET_MAX_VALUE)
    return SD_E_INVALID_PARAM;
  if ((e = sd_secbuf_new((len + 1) * sizeof(wchar_t), out)) != SD_OK)
    return e;
  if (len && sd_utf8_to_utf16(value, len, (wchar_t *)(*out)->p, len, &got, SD_UTF_STRICT) != SD_OK) {
    sd_secbuf_free(*out);
    *out = NULL;
    return SD_E_INVALID_PARAM;
  }
  (*out)->len = got * sizeof(wchar_t);
  return SD_OK;
}

static sd_err from_blob(const uint8_t *blob, size_t len, sd_secbuf **out)
{
  size_t wn = len / sizeof(wchar_t), got = 0;
  wchar_t *w;
  sd_err e;
  if (len % 2)
    return SD_E_KEY_FORMAT;
  if ((e = sd_secbuf_new(wn * 3 + 1, out)) != SD_OK)
    return e;
  w = (wchar_t *)sd_alloc(wn * sizeof(wchar_t) + 2);
  if (w == NULL) {
    sd_secbuf_free(*out);
    *out = NULL;
    return SD_E_NO_MEMORY;
  }
  if (wn) memcpy(w, blob, wn * sizeof(wchar_t));
  e = wn ? sd_utf16_to_utf8(w, wn, (char *)(*out)->p, wn * 3, &got, SD_UTF_REPLACE) : SD_OK;
  sd_secure_free(w, wn * sizeof(wchar_t) + 2);
  if (e != SD_OK) {
    sd_secbuf_free(*out);
    *out = NULL;
    return e;
  }
  (*out)->p[got] = 0;
  (*out)->len = got;
  return SD_OK;
}

static int full_wide(const char *full, wchar_t *out, size_t cch)
{
  size_t got = 0;
  if (sd_utf8_to_utf16(full, strlen(full), out, cch - 1, &got, SD_UTF_STRICT) != SD_OK)
    return 0;
  out[got] = 0;
  return 1;
}

/* ---- Credential Manager ---- */

typedef BOOL (WINAPI *pfn_CredGetSessionTypes)(DWORD, LPDWORD);

static int credman_usable(void)
{
  DWORD persist[CRED_TYPE_MAXIMUM];
  pfn_CredGetSessionTypes f;
  if (g.force_dpapi)
    return 0;
  f = (pfn_CredGetSessionTypes)sd_platform_resolve_by_name(L"advapi32.dll", "CredGetSessionTypes");
  if (f == NULL)
    return 0;
  memset(persist, 0, sizeof(persist));
  if (!f(CRED_TYPE_MAXIMUM, persist))
    return 0;
  /* XP Home / Vista Home: generic credentials cannot persist (03 §4.2) */
  return persist[CRED_TYPE_GENERIC] >= CRED_PERSIST_LOCAL_MACHINE;
}

static DWORD credman_persist(void)
{
  DWORD persist[CRED_TYPE_MAXIMUM];
  pfn_CredGetSessionTypes f;
  if (!g.persist_enterprise)
    return CRED_PERSIST_LOCAL_MACHINE;
  f = (pfn_CredGetSessionTypes)sd_platform_resolve_by_name(L"advapi32.dll", "CredGetSessionTypes");
  memset(persist, 0, sizeof(persist));
  if (f && f(CRED_TYPE_MAXIMUM, persist) && persist[CRED_TYPE_GENERIC] >= CRED_PERSIST_ENTERPRISE)
    return CRED_PERSIST_ENTERPRISE;
  return CRED_PERSIST_LOCAL_MACHINE;
}

sd_secret_store sd_secret_store_for(sd_secret_scope s, size_t value_len)
{
  ensure_init();
  if (s == SD_SECRET_SERVICE || value_len * sizeof(wchar_t) > SD_SECRET_CREDMAN_MAX || !credman_usable())
    return SD_SECRET_STORE_DPAPI;
  return SD_SECRET_STORE_CREDMAN;
}

static sd_err credman_put(const char *full, const char *raw, sd_secret_kind k, const wchar_t *comment,
                          const sd_secbuf *blob)
{
  CREDENTIALW c;
  wchar_t name[SD_SECRET_MAX_TARGET], user[256];
  memset(&c, 0, sizeof(c));
  user[0] = 0;
  if (!full_wide(full, name, SD_COUNTOF(name)))
    return SD_E_INVALID_PARAM;
  if (k != SD_SECRET_PASSPHRASE) {
    const char *at = strrchr(raw, '@'), *start = raw;
    size_t got = 0;
    if (k == SD_SECRET_PROXY && strchr(raw, ':')) start = strchr(raw, ':') + 1;
    if (at && at > start && sd_utf8_to_utf16(start, (size_t)(at - start), user, SD_COUNTOF(user) - 1, &got,
                                            SD_UTF_REPLACE) == SD_OK)
      user[got] = 0;
  }
  c.Type = CRED_TYPE_GENERIC;
  c.TargetName = name;
  c.Comment = (LPWSTR)comment;
  c.CredentialBlobSize = (DWORD)blob->len;
  c.CredentialBlob = blob->p;
  c.Persist = credman_persist();
  c.UserName = user[0] ? user : NULL;
  if (!CredWriteW(&c, 0)) {
    DWORD le = GetLastError();
    SD_LOGW("secret", "CredWriteW failed (%u)", (unsigned)le);
    return le == ERROR_NO_SUCH_LOGON_SESSION ? SD_E_UNSUPPORTED : SD_E_FAILURE;
  }
  return SD_OK;
}

static sd_err credman_get(const char *full, sd_secbuf **out)
{
  wchar_t name[SD_SECRET_MAX_TARGET];
  PCREDENTIALW c = NULL;
  sd_err e;
  if (!full_wide(full, name, SD_COUNTOF(name)))
    return SD_E_INVALID_PARAM;
  if (!CredReadW(name, CRED_TYPE_GENERIC, 0, &c))
    return SD_E_NOT_FOUND;
  e = from_blob(c->CredentialBlob, c->CredentialBlobSize, out);
  if (c->CredentialBlobSize)
    SecureZeroMemory(c->CredentialBlob, c->CredentialBlobSize);
  CredFree(c);
  return e;
}

static int credman_delete(const char *full)
{
  wchar_t name[SD_SECRET_MAX_TARGET];
  return full_wide(full, name, SD_COUNTOF(name)) && CredDeleteW(name, CRED_TYPE_GENERIC, 0);
}

/* ---- DPAPI secret files ---- */

static sd_err dpapi_put(sd_secret_scope s, const char *full, const sd_secbuf *blob)
{
  wchar_t path[MAX_PATH], descr[SD_SECRET_MAX_TARGET];
  char ent[SD_SECRET_MAX_TARGET + 64];
  DATA_BLOB enc;
  sd_wr w;
  sd_err e;
  if ((e = secret_file(s, full, 1, path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if (!entropy_for("com.librestatic.shelldrive/secret/v1/", full, ent, sizeof(ent)) ||
      !full_wide(full, descr, SD_COUNTOF(descr)))
    return SD_E_NAME_TOO_LONG;
  if ((e = protect(blob->p, blob->len, ent, descr, &enc)) != SD_OK)
    return e;
  sd_wr_init(&w, FILE_MAX);
  sd_wr_bytes(&w, SECRET_MAGIC, 8);
  put_le32(&w, 1);
  put_le32(&w, enc.cbData);
  sd_wr_bytes(&w, enc.pbData, enc.cbData);
  LocalFree(enc.pbData);
  put_le32(&w, (uint32_t)strlen(full));          /* clear trailer: the target name (enumeration) */
  sd_wr_bytes(&w, full, strlen(full));
  e = sd_wr_ok(&w) ? write_atomic(path, w.p, w.len) : SD_E_NO_MEMORY;
  sd_wr_free(&w);
  return e;
}

/* Reads one .sdsec file. full != NULL: decrypt and check the name; full == NULL: only the clear
   target-name trailer is returned (enumeration, no decryption). */
static sd_err dpapi_read_path(const wchar_t *path, const char *full, sd_secbuf **blob, char *name, size_t name_cap)
{
  uint8_t *data = NULL;
  size_t len = 0, tl = 0;
  uint32_t n;
  const uint8_t *trailer = NULL;
  char ent[SD_SECRET_MAX_TARGET + 64], d[SD_SECRET_MAX_TARGET];
  sd_err e = read_all(path, &data, &len);
  if (e != SD_OK)
    return e;
  n = le32(data + 12);
  if (memcmp(data, SECRET_MAGIC, 8) != 0 || le32(data + 8) != 1 || n > len - 16) {
    sd_free(data);
    return SD_E_KEY_FORMAT;
  }
  if (len - 16 - n >= 4) {
    tl = le32(data + 16 + n);
    if (tl < SD_SECRET_MAX_TARGET && tl <= len - 20 - n)
      trailer = data + 20 + n;
  }
  if (full == NULL) {
    e = trailer ? SD_OK : SD_E_KEY_FORMAT;
    if (e == SD_OK && name && name_cap) {
      size_t c = SD_MIN(tl, name_cap - 1);
      memcpy(name, trailer, c);
      name[c] = 0;
    }
    sd_free(data);
    return e;
  }
  if (!entropy_for("com.librestatic.shelldrive/secret/v1/", full, ent, sizeof(ent))) {
    sd_free(data);
    return SD_E_NAME_TOO_LONG;
  }
  e = unprotect(data + 16, n, ent, blob, d, sizeof(d));
  sd_free(data);
  if (e == SD_OK && strcmp(d, full) != 0) {      /* a file copied over another name */
    sd_secbuf_free(*blob);
    *blob = NULL;
    e = SD_E_NOT_FOUND;
  } else if (e == SD_E_CRYPTO) {
    e = SD_E_NOT_FOUND;                          /* not ours (other user, other entropy) */
  }
  return e;
}

static sd_err dpapi_get(sd_secret_scope s, const char *full, sd_secbuf **out)
{
  wchar_t path[MAX_PATH];
  sd_secbuf *blob = NULL;
  sd_err e = secret_file(s, full, 0, path, SD_COUNTOF(path));
  if (e != SD_OK)
    return e;
  if ((e = dpapi_read_path(path, full, &blob, NULL, 0)) != SD_OK)
    return e == SD_E_KEY_FORMAT ? SD_E_NOT_FOUND : e;
  e = from_blob(blob->p, blob->len, out);
  sd_secbuf_free(blob);
  return e;
}

static int dpapi_delete(sd_secret_scope s, const char *full)
{
  wchar_t path[MAX_PATH];
  if (secret_file(s, full, 0, path, SD_COUNTOF(path)) != SD_OK)
    return 0;
  return DeleteFileW(path) != 0;
}

/* ---- public secret API ---- */

sd_err sd_secret_put(sd_secret_scope s, sd_secret_kind k, const char *target, const wchar_t *comment,
                     const char *value, size_t len)
{
  char full[SD_SECRET_MAX_TARGET];
  sd_secbuf *blob = NULL;
  sd_secret_store st;
  sd_err e;
  ensure_init();
  if (value == NULL || sd_secret_target_name(k, target, full, sizeof(full)) != SD_OK)
    return SD_E_INVALID_PARAM;
  if ((e = to_blob(value, len, &blob)) != SD_OK)
    return e;
  st = sd_secret_store_for(s, blob->len / sizeof(wchar_t));
  if (st == SD_SECRET_STORE_CREDMAN) {
    e = credman_put(full, target, k, comment, blob);
    if (e == SD_OK) {
      dpapi_delete(s, full);
    } else {
      SD_LOGW("secret", "Credential Manager refused the secret; using the DPAPI store");
      st = SD_SECRET_STORE_DPAPI;
    }
  }
  if (st == SD_SECRET_STORE_DPAPI) {
    e = dpapi_put(s, full, blob);
    if (e == SD_OK && s == SD_SECRET_USER && !g.force_dpapi)
      credman_delete(full);
  }
  sd_secbuf_free(blob);
  return e;
}

sd_err sd_secret_get(sd_secret_scope s, sd_secret_kind k, const char *target, sd_secbuf **out)
{
  char full[SD_SECRET_MAX_TARGET];
  sd_err e;
  ensure_init();
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  if ((e = sd_secret_target_name(k, target, full, sizeof(full))) != SD_OK)
    return e;
  if (s == SD_SECRET_USER && !g.force_dpapi) {
    e = credman_get(full, out);
    if (e != SD_E_NOT_FOUND)
      return e;
  }
  return dpapi_get(s, full, out);
}

sd_err sd_secret_delete(sd_secret_scope s, sd_secret_kind k, const char *target)
{
  char full[SD_SECRET_MAX_TARGET];
  int any = 0;
  sd_err e;
  ensure_init();
  if ((e = sd_secret_target_name(k, target, full, sizeof(full))) != SD_OK)
    return e;
  if (s == SD_SECRET_USER && !g.force_dpapi && credman_delete(full))
    any = 1;
  if (dpapi_delete(s, full))
    any = 1;
  return any ? SD_OK : SD_E_NOT_FOUND;
}

typedef struct name_list { char (*names)[SD_SECRET_MAX_TARGET]; uint8_t *store; uint32_t n, cap; } name_list;

static int list_add(name_list *l, const char *full, sd_secret_store st)
{
  if (l->n == l->cap) {
    uint32_t nc = l->cap ? l->cap * 2 : 16;
    char (*np)[SD_SECRET_MAX_TARGET] =
      (char (*)[SD_SECRET_MAX_TARGET])sd_alloc((size_t)nc * SD_SECRET_MAX_TARGET);
    uint8_t *q = (uint8_t *)sd_alloc(nc);
    if (np == NULL || q == NULL) { sd_free(np); sd_free(q); return 0; }
    if (l->n) {
      uint32_t k;
      for (k = 0; k < l->n; k++)       /* per element: keeps the analyzer's size model per entry */
        memcpy(np[k], l->names[k], SD_SECRET_MAX_TARGET);
      memcpy(q, l->store, l->n);
    }
    sd_free(l->names);
    sd_free(l->store);
    l->names = np;
    l->store = q;
    l->cap = nc;
  }
  _Analysis_assume_(l->n < l->cap);   /* the growth above guarantees room for one more */
  strcpy_s(l->names[l->n], SD_SECRET_MAX_TARGET, full);
  l->store[l->n] = (uint8_t)st;
  l->n++;
  return 1;
}

static void list_free(name_list *l)
{
  sd_free(l->names);
  sd_free(l->store);
  memset(l, 0, sizeof(*l));
}

/* Every target name of this prefix in the scope's stores (Credential Manager first). */
static void collect(sd_secret_scope s, name_list *l)
{
  wchar_t dir[MAX_PATH], pat[MAX_PATH], path[MAX_PATH], filter[80];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  memset(l, 0, sizeof(*l));
  if (s == SD_SECRET_USER && !g.force_dpapi) {
    DWORD count = 0, i;
    PCREDENTIALW *creds = NULL;
    size_t got = 0;
    if (sd_utf8_to_utf16(g.prefix, strlen(g.prefix), filter, SD_COUNTOF(filter) - 2, &got, SD_UTF_STRICT) == SD_OK) {
      filter[got] = L'*';
      filter[got + 1] = 0;
      if (CredEnumerateW(filter, 0, &count, &creds)) {
        for (i = 0; i < count; i++) {
          char full[SD_SECRET_MAX_TARGET];
          size_t fn = 0;
          sd_secret_kind k;
          const char *raw;
          if (creds[i]->Type != CRED_TYPE_GENERIC || creds[i]->TargetName == NULL)
            continue;
          if (sd_utf16_to_utf8(creds[i]->TargetName, wcslen(creds[i]->TargetName), full, sizeof(full) - 1, &fn,
                               SD_UTF_REPLACE) != SD_OK)
            continue;
          full[fn] = 0;
          if (parse_full(full, &k, &raw) && !list_add(l, full, SD_SECRET_STORE_CREDMAN))
            break;
        }
        CredFree(creds);
      }
    }
  }
  if (store_dir(s, L"secrets", 0, dir, SD_COUNTOF(dir)) == SD_OK && wcopy(pat, MAX_PATH, dir) &&
      wappend(pat, MAX_PATH, L"\\*.sdsec")) {
    f = FindFirstFileExW(pat, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
    if (f != INVALID_HANDLE_VALUE) {
      do {
        char full[SD_SECRET_MAX_TARGET];
        sd_secret_kind k;
        const char *raw;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!wcopy(path, MAX_PATH, dir) || !wappend(path, MAX_PATH, L"\\") || !wappend(path, MAX_PATH, fd.cFileName))
          continue;
        if (dpapi_read_path(path, NULL, NULL, full, sizeof(full)) == SD_OK && parse_full(full, &k, &raw))
          if (!list_add(l, full, SD_SECRET_STORE_DPAPI)) break;
      } while (FindNextFileW(f, &fd));
      FindClose(f);
    }
  }
}

sd_err sd_secret_enum(sd_secret_scope s, sd_secret_enum_cb cb, void *ctx)
{
  name_list l;
  uint32_t i;
  ensure_init();
  if (cb == NULL)
    return SD_E_INVALID_PARAM;
  collect(s, &l);
  for (i = 0; i < l.n; i++) {
    sd_secret_kind k;
    const char *raw;
    if (parse_full(l.names[i], &k, &raw) && !cb(ctx, k, raw, (sd_secret_store)l.store[i]))
      break;
  }
  list_free(&l);
  return SD_OK;
}

sd_err sd_secret_delete_all(sd_secret_scope s, uint32_t *removed)
{
  name_list l;
  uint32_t i, n = 0;
  ensure_init();
  collect(s, &l);
  for (i = 0; i < l.n; i++)
    if (l.store[i] == SD_SECRET_STORE_CREDMAN ? credman_delete(l.names[i]) : dpapi_delete(s, l.names[i]))
      n++;
  list_free(&l);
  if (removed) *removed = n;
  return SD_OK;
}

/* ---- DPAPI-kept keys (4.4): file management only; the image format belongs to sd_keyfile ---- */

static int valid_id(const char *id)
{
  size_t i;
  if (id == NULL || strlen(id) != 32) return 0;
  for (i = 0; i < 32; i++)
    if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
  return 1;
}

static sd_err key_path(sd_secret_scope s, const char *id, int create, wchar_t *out, size_t cch)
{
  wchar_t name[40];
  size_t i;
  sd_err e;
  if (!valid_id(id))
    return SD_E_INVALID_PARAM;
  if ((e = store_dir(s, L"keys", create, out, cch)) != SD_OK)
    return e;
  name[0] = L'\\';
  for (i = 0; i < 32; i++) name[1 + i] = (wchar_t)id[i];
  name[33] = 0;
  return (wappend(out, cch, name) && wappend(out, cch, L".sdkey")) ? SD_OK : SD_E_NAME_TOO_LONG;
}

sd_err sd_secret_key_new_id(char out[33])
{
  static const char hex[] = "0123456789abcdef";
  uint8_t r[16];
  size_t i;
  sd_pfn_RtlGenRandom gen = (sd_pfn_RtlGenRandom)sd_platform_resolve(SD_API_RtlGenRandom);
  if (out == NULL || gen == NULL || !gen(r, sizeof(r)))
    return SD_E_CRYPTO;
  for (i = 0; i < 16; i++) {
    out[2 * i] = hex[r[i] >> 4];
    out[2 * i + 1] = hex[r[i] & 15];
  }
  out[32] = 0;
  return SD_OK;
}

sd_err sd_secret_key_write(sd_secret_scope s, const char *id, const uint8_t *image, size_t len)
{
  wchar_t path[MAX_PATH];
  sd_err e;
  ensure_init();
  if (image == NULL || len < 16 || len > FILE_MAX || memcmp(image, KEY_MAGIC, 8) != 0)
    return SD_E_INVALID_PARAM;
  if ((e = key_path(s, id, 1, path, SD_COUNTOF(path))) != SD_OK)
    return e;
  return write_atomic(path, image, len);
}

sd_err sd_secret_key_read(sd_secret_scope s, const char *id, uint8_t **image, size_t *len)
{
  wchar_t path[MAX_PATH];
  sd_err e;
  ensure_init();
  if (image == NULL || len == NULL)
    return SD_E_INVALID_PARAM;
  *image = NULL;
  *len = 0;
  if ((e = key_path(s, id, 0, path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if ((e = read_all(path, image, len)) != SD_OK)
    return e;
  if (memcmp(*image, KEY_MAGIC, 8) != 0) {
    sd_free(*image);
    *image = NULL;
    *len = 0;
    return SD_E_KEY_FORMAT;
  }
  return SD_OK;
}

sd_err sd_secret_key_delete(sd_secret_scope s, const char *id)
{
  wchar_t path[MAX_PATH];
  sd_err e;
  ensure_init();
  if ((e = key_path(s, id, 0, path, SD_COUNTOF(path))) != SD_OK)
    return e;
  if (!DeleteFileW(path))
    return GetLastError() == ERROR_FILE_NOT_FOUND ? SD_E_NOT_FOUND : SD_E_ACCESS_DENIED;
  return SD_OK;
}

sd_err sd_secret_key_enum(sd_secret_scope s, sd_secret_key_enum_cb cb, void *ctx)
{
  wchar_t dir[MAX_PATH], pat[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE f;
  ensure_init();
  if (cb == NULL)
    return SD_E_INVALID_PARAM;
  if (store_dir(s, L"keys", 0, dir, SD_COUNTOF(dir)) != SD_OK || !wcopy(pat, MAX_PATH, dir) ||
      !wappend(pat, MAX_PATH, L"\\*.sdkey"))
    return SD_OK;
  f = FindFirstFileExW(pat, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  if (f == INVALID_HANDLE_VALUE)
    return SD_OK;
  do {
    char id[33];
    size_t i, n = wcslen(fd.cFileName);
    if (n != 38 || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || _wcsicmp(fd.cFileName + 32, L".sdkey") != 0)
      continue;
    for (i = 0; i < 32; i++) id[i] = (char)fd.cFileName[i];
    id[32] = 0;
    if (valid_id(id) && !cb(ctx, id))
      break;
  } while (FindNextFileW(f, &fd));
  FindClose(f);
  return SD_OK;
}
