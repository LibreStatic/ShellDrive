/* known_hosts stores (01 §7.1, §7.2; D7, D8; TM-R04, TM-R07). No transport dependency.
 *
 * M0: file stores SD_KH_STORE_USER and SD_KH_STORE_MACHINE with plain and @revoked entries; live
 * sources (OpenSSH, PuTTY) are accepted in the store list but reported SD_KH_SRC_DISABLED and never
 * consulted (their TM-R06 ACL checks are M2). Hashed |1| entries need HMAC-SHA1 (M2) and are
 * skipped; @cert-authority lines only feed sd_kh_types.has_ca.
 *
 * Files are re-read on every call (they are small and every call already runs on a worker item).
 * Writes go to a temp file created with an explicit protected DACL in the same CreateFileW call,
 * then MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH), serialized across processes by the named
 * mutex Local\com.librestatic.shelldrive.known_hosts.<hash> (Global\ for the machine store). */
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_ssh/sd_known_hosts.h"
#include "ssh_internal.h"

#define KH_MAX_FILE   (16u * 1024u * 1024u)
#define KH_MAX_LINE   (64u * 1024u)
#define KH_MAX_BLOB   16384u
#define KH_MAX_STORES 8u

typedef struct kh_store {
  sd_kh_store_kind kind;
  wchar_t *path;
  int writable;
} kh_store;

struct sd_known_hosts {
  sd_mutex lock;
  uint32_t count;
  kh_store stores[KH_MAX_STORES];
};

/* ---- pattern matching (OpenSSH match_pattern semantics, ASCII case-insensitive) ---- */

static char lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

static int wild_match(const char *s, size_t sn, const char *p, size_t pn)
{
  /* iterative glob with backtracking on the last '*' */
  size_t si = 0, pi = 0, star_p = (size_t)-1, star_s = 0;
  while (si < sn) {
    if (pi < pn && (p[pi] == '?' || lc(p[pi]) == lc(s[si]))) { si++; pi++; }
    else if (pi < pn && p[pi] == '*') { star_p = pi++; star_s = si; }
    else if (star_p != (size_t)-1) { pi = star_p + 1; si = ++star_s; }
    else return 0;
  }
  while (pi < pn && p[pi] == '*') pi++;
  return pi == pn;
}

int ssh_kh_match_patterns(const char *patterns, size_t plen, const char *name)
{
  size_t i = 0, nlen = strlen(name);
  int found = 0;
  while (i < plen) {
    size_t s = i, e;
    int neg = 0;
    while (i < plen && patterns[i] != ',') i++;
    e = i;
    if (i < plen) i++;   /* skip comma */
    if (s < e && patterns[s] == '!') { neg = 1; s++; }
    if (s == e) continue;
    if (e - s >= 3 && memcmp(patterns + s, "|1|", 3) == 0) continue;   /* hashed: M2 (needs HMAC-SHA1) */
    if (wild_match(name, nlen, patterns + s, e - s)) {
      if (neg) return -1;
      found = 1;
    }
  }
  return found;
}

int ssh_kh_wildcard_only(const char *patterns, size_t plen)
{
  size_t i = 0;
  int any_positive = 0;
  while (i < plen) {
    size_t s = i, e, k;
    while (i < plen && patterns[i] != ',') i++;
    e = i;
    if (i < plen) i++;
    if (s < e && patterns[s] == '!') continue;
    if (s == e) continue;
    any_positive = 1;
    if (patterns[s] == '[') {   /* [..]:port wrapper */
      size_t close = s;
      while (close < e && patterns[close] != ']') close++;
      if (close >= e) return 0;
      for (k = s + 1; k < close; k++)
        if (patterns[k] != '*' && patterns[k] != '?' && patterns[k] != '.') return 0;
      continue;
    }
    for (k = s; k < e; k++)
      if (patterns[k] != '*' && patterns[k] != '?' && patterns[k] != '.') return 0;
  }
  return any_positive;
}

sd_err ssh_kh_lookup_name(const char *host, uint16_t port, char *out, size_t cap)
{
  size_t n = strlen(host), i, o = 0;
  char num[8];
  int nn = 0;
  if (n == 0) return SD_E_INVALID_PARAM;
  if (n >= 2 && host[0] == '[' && host[n - 1] == ']') { host++; n -= 2; }
  if (port == 0) port = 22;
  if (port != 22) { if (o + 1 >= cap) return SD_E_INVALID_PARAM; out[o++] = '['; }
  for (i = 0; i < n; i++) {
    char c = host[i];
    if ((unsigned char)c <= 0x20 || (unsigned char)c >= 0x7F || c == ',' || c == '[' || c == ']')
      return SD_E_INVALID_PARAM;
    if (o + 1 >= cap) return SD_E_INVALID_PARAM;
    out[o++] = lc(c);
  }
  if (port != 22) {
    uint16_t p = port;
    while (p) { num[nn++] = (char)('0' + p % 10); p = (uint16_t)(p / 10); }
    if (o + 2 + (size_t)nn >= cap) return SD_E_INVALID_PARAM;
    out[o++] = ']';
    out[o++] = ':';
    while (nn) out[o++] = num[--nn];
  }
  out[o] = '\0';
  return SD_OK;
}

/* ---- line parsing ---- */

typedef enum { KH_PLAIN, KH_REVOKED, KH_CA } kh_marker;

typedef struct kh_line {
  kh_marker marker;
  const char *pat; size_t pat_len;
  const char *type; size_t type_len;
  const char *b64; size_t b64_len;
} kh_line;

static int is_ws(char c) { return c == ' ' || c == '\t'; }

static const char *next_field(const char *p, const char *end, const char **f, size_t *fl)
{
  while (p < end && is_ws(*p)) p++;
  *f = p;
  while (p < end && !is_ws(*p)) p++;
  *fl = (size_t)(p - *f);
  return p;
}

/* 1 on a usable line, 0 on comment/blank, -1 on a malformed line. */
static int parse_line(const char *s, size_t n, kh_line *l)
{
  const char *p = s, *end = s + n, *f;
  size_t fl;
  while (p < end && is_ws(*p)) p++;
  if (p == end || *p == '#') return 0;
  memset(l, 0, sizeof(*l));
  p = next_field(p, end, &f, &fl);
  if (fl && f[0] == '@') {
    if (fl == 8 && memcmp(f, "@revoked", 8) == 0) l->marker = KH_REVOKED;
    else if (fl == 15 && memcmp(f, "@cert-authority", 15) == 0) l->marker = KH_CA;
    else return -1;
    p = next_field(p, end, &f, &fl);
  }
  l->pat = f; l->pat_len = fl;
  p = next_field(p, end, &l->type, &l->type_len);
  p = next_field(p, end, &l->b64, &l->b64_len);
  if (!l->pat_len || !l->type_len || !l->b64_len) return -1;
  return 1;
}

/* Calls fn for every line (1-based number). fn returns nonzero to stop. */
typedef int (*kh_line_fn)(void *ctx, const char *line, size_t len, uint32_t lineno);

static void for_each_line(const char *text, size_t len, kh_line_fn fn, void *ctx)
{
  size_t i = 0;
  uint32_t no = 0;
  while (i < len) {
    size_t s = i, e;
    while (i < len && text[i] != '\n') i++;
    e = i;
    if (i < len) i++;
    no++;
    if (e > s && text[e - 1] == '\r') e--;
    if (e - s > KH_MAX_LINE) {
      SD_LOGD("ssh", "known_hosts line %u too long, skipped", no);
      continue;
    }
    if (fn(ctx, text + s, e - s, no)) return;
  }
}

static int decode_key(const kh_line *l, uint8_t *blob, size_t cap, size_t *blen)
{
  sd_span t;
  if (ssh_b64_decode(l->b64, l->b64_len, blob, cap, blen, 0) != SD_OK) return 0;
  t = ssh_blob_key_type(blob, *blen);
  return t.n == l->type_len && memcmp(t.p, l->type, t.n) == 0;
}

/* ---- in-memory check ---- */

typedef struct kh_check_ctx {
  const char *name;
  const uint8_t *blob; size_t blob_len;
  sd_span type;
  sd_hk_result *res;
  int have_match, have_mismatch, revoked, other_types;
  uint8_t *tmp;
} kh_check_ctx;

static int check_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_check_ctx *c = (kh_check_ctx *)vctx;
  kh_line l;
  size_t blen;
  int r = parse_line(s, n, &l);
  if (r <= 0) {
    if (r < 0) SD_LOGD("ssh", "known_hosts line %u malformed, skipped", no);
    return 0;
  }
  if (ssh_kh_match_patterns(l.pat, l.pat_len, c->name) != 1) return 0;
  if (l.marker == KH_CA) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) {
    SD_LOGD("ssh", "known_hosts line %u has an invalid key, skipped", no);
    return 0;
  }
  if (l.marker == KH_REVOKED) {
    if (blen == c->blob_len && memcmp(c->tmp, c->blob, blen) == 0) {
      c->revoked = 1;
      c->res->line = no;
      return 1;
    }
    return 0;
  }
  if (l.type_len == c->type.n && memcmp(l.type, c->type.p, l.type_len) == 0) {
    if (blen == c->blob_len && memcmp(c->tmp, c->blob, blen) == 0) {
      if (!c->have_match && !c->have_mismatch) {
        c->res->line = no;
        c->res->wildcard_only = ssh_kh_wildcard_only(l.pat, l.pat_len);
      }
      c->have_match = 1;
    } else if (!c->have_mismatch) {
      c->have_mismatch = 1;
      c->res->line = no;
      ssh_span_copy(c->type, c->res->stored_type, sizeof(c->res->stored_type));
      if (sd_hostkey_fingerprint_sha256(c->tmp, blen, c->res->stored_fp_sha256) != SD_OK)
        c->res->stored_fp_sha256[0] = '\0';
    }
  } else {
    c->other_types = 1;
  }
  return 0;
}

sd_err ssh_kh_check_buffer(const char *text, size_t len, const char *lookup_name, const uint8_t *blob,
                           size_t blob_len, sd_hk_result *res, int *found_other_types)
{
  kh_check_ctx c;
  memset(&c, 0, sizeof(c));
  memset(res, 0, sizeof(*res));
  c.type = ssh_blob_key_type(blob, blob_len);
  if (!c.type.n) return SD_E_INVALID_PARAM;
  c.name = lookup_name;
  c.blob = blob;
  c.blob_len = blob_len;
  c.res = res;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  for_each_line(text, len, check_line, &c);
  sd_free(c.tmp);
  if (c.revoked) res->status = SD_HK_REVOKED;
  else if (c.have_mismatch) res->status = SD_HK_MISMATCH;
  else if (c.have_match) { res->status = SD_HK_MATCH; res->trusted_before = 1; }
  else if (c.other_types) res->status = SD_HK_NEW_TYPE;
  else res->status = SD_HK_NEW;
  if (res->status != SD_HK_MISMATCH) { res->stored_type[0] = '\0'; res->stored_fp_sha256[0] = '\0'; }
  if (res->status == SD_HK_NEW || res->status == SD_HK_NEW_TYPE) res->line = 0;
  if (res->status != SD_HK_MATCH) res->wildcard_only = 0;
  if (found_other_types) *found_other_types = c.other_types;
  return SD_OK;
}

typedef struct kh_types_ctx { const char *name; sd_kh_types *out; uint8_t *tmp; } kh_types_ctx;

static int types_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_types_ctx *c = (kh_types_ctx *)vctx;
  kh_line l;
  size_t blen;
  uint32_t i;
  SD_UNUSED(no);
  if (parse_line(s, n, &l) <= 0) return 0;
  if (ssh_kh_match_patterns(l.pat, l.pat_len, c->name) != 1) return 0;
  if (l.marker == KH_CA) { c->out->has_ca = 1; return 0; }
  if (l.marker == KH_REVOKED) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) return 0;
  if (l.type_len >= sizeof(c->out->type[0])) return 0;
  for (i = 0; i < c->out->count; i++)
    if (strlen(c->out->type[i]) == l.type_len && memcmp(c->out->type[i], l.type, l.type_len) == 0) return 0;
  if (c->out->count >= SD_COUNTOF(c->out->type)) return 0;
  memcpy(c->out->type[c->out->count], l.type, l.type_len);
  c->out->type[c->out->count][l.type_len] = '\0';
  c->out->count++;
  return 0;
}

sd_err ssh_kh_types_buffer(const char *text, size_t len, const char *lookup_name, sd_kh_types *out)
{
  kh_types_ctx c;
  c.name = lookup_name;
  c.out = out;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  for_each_line(text, len, types_line, &c);
  sd_free(c.tmp);
  return SD_OK;
}

/* ---- fingerprint ---- */

sd_err sd_hostkey_fingerprint_sha256(const uint8_t *blob, size_t len, char out[64])
{
  uint8_t h[32];
  if (!blob || !len || !out) return SD_E_INVALID_PARAM;
  if (!ssh_crypto_ready()) { out[0] = '\0'; return SD_E_UNSUPPORTED; }
  sd_hash(SD_HASH_SHA256, blob, len, h);
  memcpy(out, "SHA256:", 7);
  if (!ssh_b64_encode(h, 32, out + 7, 64 - 7, 0)) return SD_E_INTERNAL;
  return SD_OK;
}

/* ---- files ---- */

static sd_err read_file(const wchar_t *path, char **text, size_t *len)
{
  HANDLE h;
  LARGE_INTEGER sz;
  DWORD got = 0;
  char *buf;
  *text = NULL;
  *len = 0;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    DWORD e = GetLastError();
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return SD_E_NOT_FOUND;
    return e == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_FAILURE;
  }
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > KH_MAX_FILE) { CloseHandle(h); return SD_E_FAILURE; }
  buf = (char *)sd_alloc((size_t)sz.QuadPart + 1);
  if (!buf) { CloseHandle(h); return SD_E_NO_MEMORY; }
  if (sz.QuadPart && (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    sd_free(buf);
    CloseHandle(h);
    return SD_E_FAILURE;
  }
  CloseHandle(h);
  buf[got] = '\0';
  *text = buf;
  *len = got;
  return SD_OK;
}

static wchar_t *wcsdup_sd(const wchar_t *s)
{
  size_t n = wcslen(s);
  wchar_t *d = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
  if (d) memcpy(d, s, (n + 1) * sizeof(wchar_t));
  return d;
}

static wchar_t *default_path(sd_kh_store_kind kind)
{
  wchar_t base[MAX_PATH], full[MAX_PATH + 64];
  int csidl = kind == SD_KH_STORE_MACHINE ? CSIDL_COMMON_APPDATA : CSIDL_APPDATA;
  size_t n;
  static const wchar_t k_tail[] = L"\\LibreStatic\\ShellDrive\\known_hosts";
  if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, 0, base))) return NULL;
  n = wcslen(base);
  if (n + SD_COUNTOF(k_tail) >= SD_COUNTOF(full)) return NULL;
  memcpy(full, base, n * sizeof(wchar_t));
  memcpy(full + n, k_tail, sizeof(k_tail));
  return wcsdup_sd(full);
}

sd_err sd_known_hosts_open(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out)
{
  sd_known_hosts *kh;
  uint32_t i;
  if (!out || (count && !stores) || count > KH_MAX_STORES) return SD_E_INVALID_PARAM;
  *out = NULL;
  kh = (sd_known_hosts *)sd_calloc(1, sizeof(*kh));
  if (!kh) return SD_E_NO_MEMORY;
  sd_mutex_init(&kh->lock);
  for (i = 0; i < count; i++) {
    kh_store *s = &kh->stores[kh->count];
    s->kind = stores[i].kind;
    if (s->kind == SD_KH_SRC_OPENSSH || s->kind == SD_KH_SRC_PUTTY) {
      SD_LOGI("ssh", "known_hosts live source %d disabled (M2)", (int)s->kind);
      s->writable = 0;
    } else if (s->kind == SD_KH_STORE_USER || s->kind == SD_KH_STORE_MACHINE) {
      s->path = stores[i].path ? wcsdup_sd(stores[i].path) : default_path(s->kind);
      if (!s->path) { sd_known_hosts_close(kh); return stores[i].path ? SD_E_NO_MEMORY : SD_E_FAILURE; }
      s->writable = stores[i].writable;
    } else {
      sd_known_hosts_close(kh);
      return SD_E_INVALID_PARAM;
    }
    kh->count++;
  }
  *out = kh;
  return SD_OK;
}

void sd_known_hosts_close(sd_known_hosts *kh)
{
  uint32_t i;
  if (!kh) return;
  for (i = 0; i < kh->count; i++) sd_free(kh->stores[i].path);
  sd_mutex_destroy(&kh->lock);
  sd_free(kh);
}

static int file_store(const kh_store *s) { return s->path != NULL; }

sd_err sd_known_hosts_check(sd_known_hosts *kh, const char *lookup_name, const uint8_t *blob, size_t len,
                            uint64_t now_unix, sd_hk_result *res)
{
  uint32_t i;
  int have_match = 0, have_mismatch = 0, other = 0;
  sd_hk_result match_res, best;
  SD_UNUSED(now_unix);
  if (!kh || !lookup_name || !blob || !len || !res) return SD_E_INVALID_PARAM;
  if (!ssh_blob_key_type(blob, len).n) return SD_E_INVALID_PARAM;
  memset(&match_res, 0, sizeof(match_res));
  memset(&best, 0, sizeof(best));
  best.status = SD_HK_NEW;
  sd_mutex_lock(&kh->lock);
  for (i = 0; i < kh->count; i++) {
    const kh_store *s = &kh->stores[i];
    char *text;
    size_t tlen;
    sd_hk_result r;
    int o = 0;
    sd_err e;
    if (!file_store(s)) continue;
    e = read_file(s->path, &text, &tlen);
    if (e == SD_E_NOT_FOUND) continue;
    if (e != SD_OK) {
      SD_LOGW("ssh", "known_hosts store %ls unreadable: %s", s->path, sd_err_name(e));
      continue;
    }
    e = ssh_kh_check_buffer(text, tlen, lookup_name, blob, len, &r, &o);
    sd_free(text);
    if (e != SD_OK) { sd_mutex_unlock(&kh->lock); return e; }
    r.store = s->kind;
    if (wcslen(s->path) < SD_COUNTOF(r.path)) memcpy(r.path, s->path, (wcslen(s->path) + 1) * sizeof(wchar_t));
    if (o) other = 1;
    if (r.status == SD_HK_REVOKED) { best = r; sd_mutex_unlock(&kh->lock); *res = best; return SD_OK; }
    if (r.status == SD_HK_MISMATCH && !have_mismatch) { have_mismatch = 1; best = r; }
    if (r.status == SD_HK_MATCH && !have_match) { have_match = 1; match_res = r; }
  }
  sd_mutex_unlock(&kh->lock);
  if (have_mismatch) *res = best;
  else if (have_match) *res = match_res;
  else {
    memset(res, 0, sizeof(*res));
    res->status = other ? SD_HK_NEW_TYPE : SD_HK_NEW;
  }
  return SD_OK;
}

sd_err sd_known_hosts_stored_types(sd_known_hosts *kh, const char *lookup_name, sd_kh_types *out)
{
  uint32_t i;
  if (!kh || !lookup_name || !out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  sd_mutex_lock(&kh->lock);
  for (i = 0; i < kh->count; i++) {
    char *text;
    size_t tlen;
    sd_err e;
    if (!file_store(&kh->stores[i])) continue;
    e = read_file(kh->stores[i].path, &text, &tlen);
    if (e != SD_OK) continue;
    e = ssh_kh_types_buffer(text, tlen, lookup_name, out);
    sd_free(text);
    if (e != SD_OK) { sd_mutex_unlock(&kh->lock); return e; }
  }
  sd_mutex_unlock(&kh->lock);
  return SD_OK;
}

/* ---- writing ---- */

static kh_store *find_store(sd_known_hosts *kh, sd_kh_store_kind kind)
{
  uint32_t i;
  for (i = 0; i < kh->count; i++)
    if (kh->stores[i].kind == kind && file_store(&kh->stores[i])) return &kh->stores[i];
  return NULL;
}

static HANDLE lock_file_mutex(const kh_store *s)
{
  wchar_t name[128];
  uint64_t h = 1469598103934665603ull;   /* FNV-1a 64 over the lowercased path */
  const wchar_t *p;
  const wchar_t *prefix = s->kind == SD_KH_STORE_MACHINE ? L"Global\\" : L"Local\\";
  static const wchar_t k_hex[] = L"0123456789abcdef";
  size_t o = 0, i;
  HANDLE m;
  DWORD w;
  for (p = s->path; *p; p++) {
    wchar_t c = *p;
    if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    h ^= (uint16_t)c;
    h *= 1099511628211ull;
  }
  for (i = 0; prefix[i]; i++) name[o++] = prefix[i];
  {
    static const wchar_t k_base[] = L"com.librestatic.shelldrive.known_hosts.";
    for (i = 0; k_base[i]; i++) name[o++] = k_base[i];
  }
  for (i = 0; i < 16; i++) name[o++] = k_hex[(h >> (60 - 4 * i)) & 15];
  name[o] = L'\0';
  m = CreateMutexW(NULL, FALSE, name);
  if (!m) return NULL;
  w = WaitForSingleObject(m, 10000);
  if (w != WAIT_OBJECT_0 && w != WAIT_ABANDONED) { CloseHandle(m); return NULL; }
  return m;
}

static void unlock_file_mutex(HANDLE m)
{
  if (m) { ReleaseMutex(m); CloseHandle(m); }
}

static sd_err build_sd(const kh_store *s, PSECURITY_DESCRIPTOR *psd)
{
  wchar_t sddl[256];
  HANDLE tok = NULL;
  uint8_t tu[256];
  DWORD got = 0;
  LPWSTR sid = NULL;
  size_t n;
  *psd = NULL;
  if (s->kind == SD_KH_STORE_MACHINE) {
    static const wchar_t k_machine[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
    memcpy(sddl, k_machine, sizeof(k_machine));
  } else {
    static const wchar_t k_pre[] = L"D:P(A;;FA;;;SY)(A;;FA;;;";
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return SD_E_FAILURE;
    if (!GetTokenInformation(tok, TokenUser, tu, sizeof(tu), &got)) { CloseHandle(tok); return SD_E_FAILURE; }
    CloseHandle(tok);
    if (!ConvertSidToStringSidW(((TOKEN_USER *)tu)->User.Sid, &sid)) return SD_E_FAILURE;
    n = wcslen(sid);
    if (SD_COUNTOF(k_pre) + n + 2 > SD_COUNTOF(sddl)) { LocalFree(sid); return SD_E_FAILURE; }
    memcpy(sddl, k_pre, sizeof(k_pre));
    memcpy(sddl + SD_COUNTOF(k_pre) - 1, sid, n * sizeof(wchar_t));
    sddl[SD_COUNTOF(k_pre) - 1 + n] = L')';
    sddl[SD_COUNTOF(k_pre) + n] = L'\0';
    LocalFree(sid);
  }
  sddl[SD_COUNTOF(sddl) - 1] = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, psd, NULL)) return SD_E_FAILURE;
  return SD_OK;
}

static void make_parent_dirs(const wchar_t *path)
{
  wchar_t buf[MAX_PATH + 64];
  size_t n = wcslen(path), i;
  if (n >= SD_COUNTOF(buf)) return;
  memcpy(buf, path, (n + 1) * sizeof(wchar_t));
  for (i = 3; i < n; i++) {
    if (buf[i] == L'\\' || buf[i] == L'/') {
      wchar_t c = buf[i];
      buf[i] = L'\0';
      CreateDirectoryW(buf, NULL);
      buf[i] = c;
    }
  }
}

static sd_err write_file_atomic(const kh_store *s, const char *data, size_t len)
{
  wchar_t tmp[MAX_PATH + 80];
  size_t n = wcslen(s->path);
  PSECURITY_DESCRIPTOR psd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE h;
  DWORD wrote = 0, pid = GetCurrentProcessId();
  int i;
  sd_err e;
  if (n + 24 >= SD_COUNTOF(tmp)) return SD_E_NAME_TOO_LONG;
  memcpy(tmp, s->path, n * sizeof(wchar_t));
  tmp[n++] = L'.'; tmp[n++] = L't'; tmp[n++] = L'm'; tmp[n++] = L'p';
  for (i = 7; i >= 0; i--) tmp[n++] = L"0123456789abcdef"[(pid >> (i * 4)) & 15];
  tmp[n] = L'\0';
  make_parent_dirs(s->path);
  e = build_sd(s, &psd);
  if (e != SD_OK) return e;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = psd;
  sa.bInheritHandle = FALSE;
  h = CreateFileW(tmp, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  LocalFree(psd);
  if (h == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_FAILURE;
  if ((len && (!WriteFile(h, data, (DWORD)len, &wrote, NULL) || wrote != (DWORD)len)) || !FlushFileBuffers(h)) {
    CloseHandle(h);
    DeleteFileW(tmp);
    return SD_E_FAILURE;
  }
  CloseHandle(h);
  if (!MoveFileExW(tmp, s->path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(tmp);
    return SD_E_FAILURE;
  }
  return SD_OK;
}

static int valid_name(const char *s)
{
  if (!s || !*s) return 0;
  for (; *s; s++)
    if ((unsigned char)*s <= 0x20 || (unsigned char)*s >= 0x7F || *s == ',' || *s == '#') return 0;
  return 1;
}

sd_err sd_known_hosts_add(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                          const uint8_t *blob, size_t len, const char *comment)
{
  kh_store *s;
  sd_span type;
  sd_wr w;
  char *text = NULL, *b64;
  size_t tlen = 0, b64cap, cl;
  HANDLE m;
  sd_err e;
  if (!kh || !valid_name(lookup_name) || !blob || !len || len > KH_MAX_BLOB) return SD_E_INVALID_PARAM;
  type = ssh_blob_key_type(blob, len);
  if (!type.n) return SD_E_INVALID_PARAM;
  s = find_store(kh, target);
  if (!s) return SD_E_NOT_FOUND;
  if (!s->writable) return SD_E_READ_ONLY;
  b64cap = ssh_b64_encoded_len(len, 1) + 1;
  b64 = (char *)sd_alloc(b64cap);
  if (!b64) return SD_E_NO_MEMORY;
  ssh_b64_encode(blob, len, b64, b64cap, 1);

  sd_mutex_lock(&kh->lock);
  m = lock_file_mutex(s);
  if (!m) { sd_mutex_unlock(&kh->lock); sd_free(b64); return SD_E_BUSY; }
  e = read_file(s->path, &text, &tlen);
  if (e == SD_E_NOT_FOUND) { e = SD_OK; text = NULL; tlen = 0; }
  if (e == SD_OK) {
    sd_wr_init(&w, KH_MAX_FILE + 256 * 1024);
    if (tlen) {
      sd_wr_bytes(&w, text, tlen);
      if (text[tlen - 1] != '\n') sd_wr_bytes(&w, "\r\n", 2);
    }
    sd_wr_bytes(&w, lookup_name, strlen(lookup_name));
    sd_wr_u8(&w, ' ');
    sd_wr_bytes(&w, type.p, type.n);
    sd_wr_u8(&w, ' ');
    sd_wr_bytes(&w, b64, strlen(b64));
    if (comment && *comment) {
      sd_wr_u8(&w, ' ');
      for (cl = 0; comment[cl]; cl++) {
        char c = comment[cl];
        sd_wr_u8(&w, (uint8_t)((c == '\r' || c == '\n' || c == '\0') ? ' ' : c));
      }
    }
    sd_wr_bytes(&w, "\r\n", 2);
    e = sd_wr_ok(&w) ? write_file_atomic(s, (const char *)w.p, w.len) : SD_E_NO_MEMORY;
    sd_wr_free(&w);
  }
  unlock_file_mutex(m);
  sd_mutex_unlock(&kh->lock);
  sd_free(text);
  sd_free(b64);
  return e;
}

typedef struct kh_remove_ctx {
  const char *name, *type;
  sd_wr *w;
  uint32_t removed;
} kh_remove_ctx;

static int remove_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_remove_ctx *c = (kh_remove_ctx *)vctx;
  kh_line l;
  SD_UNUSED(no);
  if (parse_line(s, n, &l) == 1 && l.marker == KH_PLAIN && ssh_kh_match_patterns(l.pat, l.pat_len, c->name) == 1 &&
      (!c->type || (strlen(c->type) == l.type_len && memcmp(c->type, l.type, l.type_len) == 0))) {
    c->removed++;
    return 0;
  }
  sd_wr_bytes(c->w, s, n);
  sd_wr_bytes(c->w, "\r\n", 2);
  return 0;
}

sd_err sd_known_hosts_remove(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const char *key_type)
{
  kh_store *s;
  kh_remove_ctx c;
  sd_wr w;
  char *text = NULL;
  size_t tlen = 0;
  HANDLE m;
  sd_err e;
  if (!kh || !valid_name(lookup_name)) return SD_E_INVALID_PARAM;
  s = find_store(kh, target);
  if (!s) return SD_E_NOT_FOUND;
  if (!s->writable) return SD_E_READ_ONLY;
  sd_mutex_lock(&kh->lock);
  m = lock_file_mutex(s);
  if (!m) { sd_mutex_unlock(&kh->lock); return SD_E_BUSY; }
  e = read_file(s->path, &text, &tlen);
  if (e == SD_OK) {
    sd_wr_init(&w, KH_MAX_FILE + 1024);
    c.name = lookup_name;
    c.type = key_type;
    c.w = &w;
    c.removed = 0;
    for_each_line(text, tlen, remove_line, &c);
    if (!sd_wr_ok(&w)) e = SD_E_NO_MEMORY;
    else if (c.removed == 0) e = SD_E_NOT_FOUND;
    else e = write_file_atomic(s, (const char *)w.p, w.len);
    sd_wr_free(&w);
  }
  unlock_file_mutex(m);
  sd_mutex_unlock(&kh->lock);
  sd_free(text);
  return e;
}

sd_err sd_known_hosts_import(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_store_kind target,
                             sd_kh_import_report *rep)
{
  SD_UNUSED(kh); SD_UNUSED(source); SD_UNUSED(target);
  if (rep) memset(rep, 0, sizeof(*rep));
  return SD_E_UNSUPPORTED;   /* live sources and PuTTY import: M2 */
}

sd_err sd_known_hosts_source_state(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_src_state *state,
                                   wchar_t *detail_sid, size_t detail_cap)
{
  uint32_t i;
  if (!kh || !state) return SD_E_INVALID_PARAM;
  if (detail_sid && detail_cap) detail_sid[0] = L'\0';
  for (i = 0; i < kh->count; i++) {
    const kh_store *s = &kh->stores[i];
    if (s->kind != source) continue;
    if (!file_store(s)) { *state = SD_KH_SRC_DISABLED; return SD_OK; }
    *state = GetFileAttributesW(s->path) == INVALID_FILE_ATTRIBUTES ? SD_KH_SRC_ABSENT : SD_KH_SRC_OK;
    return SD_OK;
  }
  *state = SD_KH_SRC_DISABLED;
  return SD_OK;
}
