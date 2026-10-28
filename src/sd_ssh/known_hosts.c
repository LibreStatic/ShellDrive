/* known_hosts stores (01 §7.1-§7.3; D7, D8; TM-R04, TM-R06, TM-R07). No transport dependency.
 *
 * Stores: SD_KH_STORE_MACHINE / SD_KH_STORE_USER files (ours, read-write per the store list) and
 * the live read-only sources SD_KH_SRC_OPENSSH (files) and SD_KH_SRC_PUTTY (registry, converted to
 * known_hosts lines by known_hosts_live.c). Every call re-reads what it needs (the files are small
 * and every call already runs on a worker item); live sources go through the TM-R06 checks on each
 * read.
 *
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
#include "sd_platform/sd_time.h"
#include "sd_ssh/sd_known_hosts.h"
#include "hostkey_internal.h"
#include "known_hosts_internal.h"
#include "ssh_internal.h"

#define KH_MAX_FILE   (16u * 1024u * 1024u)
#define KH_MAX_LINE   (64u * 1024u)
#define KH_MAX_BLOB   SSH_HOSTKEY_MAX
#define KH_MAX_STORES 8u

typedef struct kh_store {
  sd_kh_store_kind kind;
  wchar_t *path;           /* file stores, OpenSSH source files, PuTTY: subkey under HKCU */
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

/* |1|base64(salt)|base64(HMAC-SHA1(salt, name)) (OpenSSH HashKnownHosts). */
static int hashed_match(const char *p, size_t n, const char *name)
{
  const char *bar;
  uint8_t salt[64], want[64], got[SD_HASH_MAX_LEN];
  size_t sl = 0, wl = 0;
  sd_hmac_ctx h;
  if (n < 4 || memcmp(p, "|1|", 3) != 0) return 0;
  p += 3; n -= 3;
  bar = (const char *)memchr(p, '|', n);
  if (!bar) return 0;
  if (ssh_b64_decode(p, (size_t)(bar - p), salt, sizeof(salt), &sl, 0) != SD_OK || sl != SD_SHA1_LEN) return 0;
  if (ssh_b64_decode(bar + 1, n - (size_t)(bar - p) - 1, want, sizeof(want), &wl, 0) != SD_OK || wl != SD_SHA1_LEN)
    return 0;
  if (!ssh_crypto_ready()) return 0;
  sd_hmac_init(&h, SD_HASH_SHA1, salt, sl);
  sd_hmac_update(&h, name, strlen(name));
  sd_hmac_final(&h, got);
  sd_hmac_wipe(&h);
  return memcmp(got, want, SD_SHA1_LEN) == 0;
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
    if (e - s >= 3 && memcmp(patterns + s, "|1|", 3) == 0) {
      if (hashed_match(patterns + s, e - s, name)) { if (neg) return -1; found = 1; }
      continue;
    }
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

/* 1 if the pattern list is a single positive pattern naming exactly `name` (plain or hashed). */
static int explicit_single(const char *patterns, size_t plen, const char *name)
{
  size_t n = strlen(name), i;
  if (memchr(patterns, ',', plen)) return 0;
  if (plen >= 3 && memcmp(patterns, "|1|", 3) == 0) return hashed_match(patterns, plen, name);
  if (plen != n) return 0;
  for (i = 0; i < n; i++) {
    if (patterns[i] == '*' || patterns[i] == '?' || patterns[i] == '!') return 0;
    if (lc(patterns[i]) != lc(name[i])) return 0;
  }
  return 1;
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

/* ---- evaluation across stores ---- */

typedef struct kh_loc { sd_kh_store_kind kind; const wchar_t *path; uint32_t line; } kh_loc;

typedef struct kh_eval {
  const char *name;
  const uint8_t *key; size_t key_len; sd_span key_type;   /* the plain key presented */
  const uint8_t *ca; size_t ca_len;                        /* certificate: CA key; else NULL */
  /* current store */
  int live;
  sd_kh_store_kind kind; const wchar_t *path;
  /* results */
  int revoked; kh_loc rev;
  int mismatch; kh_loc mis; char mis_type[48]; char mis_fp[64];
  int match; kh_loc mat; int match_explicit;               /* match_explicit: some matching line not wildcard-only */
  int match_ours;                                          /* a match in one of our stores */
  /* per store: a key of the same type that differs is a MISMATCH only if no line of that store
     matches (several keys of one type per store are fine, e.g. after UpdateHostKeys); across stores
     any MISMATCH blocks (D7) */
  int s_match, s_mismatch; kh_loc s_mis; char s_mis_type[48]; char s_mis_fp[64];
  int ca_line; kh_loc cal;                                 /* a @cert-authority line with the cert's CA */
  int ca_any; kh_loc caany;                                /* any @cert-authority line applies to the name */
  int other_types;
  uint8_t *tmp;
} kh_eval;

static void set_loc(kh_eval *c, kh_loc *l, uint32_t no) { l->kind = c->kind; l->path = c->path; l->line = no; }

static int eval_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_eval *c = (kh_eval *)vctx;
  kh_line l;
  size_t blen;
  int r = parse_line(s, n, &l), wild;
  if (r <= 0) {
    if (r < 0) SD_LOGD("ssh", "known_hosts line %u malformed, skipped", no);
    return 0;
  }
  if (ssh_kh_match_patterns(l.pat, l.pat_len, c->name) != 1) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) {
    SD_LOGD("ssh", "known_hosts line %u has an invalid key, skipped", no);
    return 0;
  }
  wild = ssh_kh_wildcard_only(l.pat, l.pat_len);
  if (l.marker == KH_REVOKED) {
    if ((blen == c->key_len && memcmp(c->tmp, c->key, blen) == 0) ||
        (c->ca && blen == c->ca_len && memcmp(c->tmp, c->ca, blen) == 0)) {
      if (!c->revoked) set_loc(c, &c->rev, no);
      c->revoked = 1;
    }
    return 0;
  }
  if (l.marker == KH_CA) {
    if (c->live && wild) return 0;                         /* TM-R06 */
    if (!c->ca_any) set_loc(c, &c->caany, no);
    c->ca_any = 1;
    if (c->ca && blen == c->ca_len && memcmp(c->tmp, c->ca, blen) == 0) {
      if (!c->ca_line) set_loc(c, &c->cal, no);
      c->ca_line = 1;
    }
    return 0;
  }
  if (l.type_len == c->key_type.n && memcmp(l.type, c->key_type.p, l.type_len) == 0) {
    if (blen == c->key_len && memcmp(c->tmp, c->key, blen) == 0) {
      if (c->live && wild) return 0;                       /* TM-R06: never a MATCH from '*' in a live source */
      if (!c->match) set_loc(c, &c->mat, no);
      if (!wild && !c->match_explicit) { c->match_explicit = 1; set_loc(c, &c->mat, no); }
      c->match = 1;
      if (!c->live) c->match_ours = 1;
      c->s_match = 1;
    } else if (!c->s_mismatch) {
      c->s_mismatch = 1;
      set_loc(c, &c->s_mis, no);
      ssh_span_copy(c->key_type, c->s_mis_type, sizeof(c->s_mis_type));
      if (sd_hostkey_fingerprint_sha256(c->tmp, blen, c->s_mis_fp) != SD_OK) c->s_mis_fp[0] = '\0';
    }
  } else if (!(c->live && wild)) {
    c->other_types = 1;
  }
  return 0;
}

/* sd_hk_result: path is the file of the deciding entry, "" for the PuTTY registry (its subkey is not a file
   and has no lines), and line is 0 when not applicable. */
static void loc_to_res(const kh_loc *l, sd_hk_result *res)
{
  res->store = l->kind;
  res->line = l->kind == SD_KH_SRC_PUTTY ? 0 : l->line;
  res->path[0] = L'\0';
  if (l->path && l->kind != SD_KH_SRC_PUTTY && wcslen(l->path) < SD_COUNTOF(res->path))
    memcpy(res->path, l->path, (wcslen(l->path) + 1) * sizeof(wchar_t));
}

typedef struct kh_subject {
  const uint8_t *blob; size_t len;         /* as presented */
  ssh_cert cert; int is_cert, cert_ok;     /* certificate */
  const char *cert_why;
  const uint8_t *key; size_t key_len;      /* plain key */
} kh_subject;

static sd_err subject_init(kh_subject *s, const uint8_t *blob, size_t len)
{
  memset(s, 0, sizeof(*s));
  s->blob = blob;
  s->len = len;
  s->key = blob;
  s->key_len = len;
  if (ssh_blob_is_cert(blob, len)) {
    sd_err e = ssh_cert_parse(blob, len, &s->cert);
    if (e != SD_OK) return SD_E_INVALID_PARAM;
    s->is_cert = 1;
    s->key = s->cert.plain;
    s->key_len = s->cert.plain_len;
  }
  return SD_OK;
}

static void subject_free(kh_subject *s) { if (s->is_cert) ssh_cert_free(&s->cert); }

static void eval_init(kh_eval *c, const kh_subject *s, const char *name, uint8_t *tmp)
{
  memset(c, 0, sizeof(*c));
  c->name = name;
  c->key = s->key;
  c->key_len = s->key_len;
  c->key_type = ssh_blob_key_type(s->key, s->key_len);
  if (s->is_cert) { c->ca = s->cert.sig_key.p; c->ca_len = s->cert.sig_key.n; }
  c->tmp = tmp;
}

static void eval_buffer(kh_eval *c, const char *text, size_t len, sd_kh_store_kind kind, const wchar_t *path, int live)
{
  c->kind = kind;
  c->path = path;
  c->live = live;
  c->s_match = c->s_mismatch = 0;
  for_each_line(text, len, eval_line, c);
  if (c->s_mismatch && !c->s_match && !c->mismatch) {
    c->mismatch = 1;
    c->mis = c->s_mis;
    memcpy(c->mis_type, c->s_mis_type, sizeof(c->mis_type));
    memcpy(c->mis_fp, c->s_mis_fp, sizeof(c->mis_fp));
  }
}

/* Final decision (01 §7.1, D7). */
static void eval_decide(kh_eval *c, kh_subject *s, uint64_t now_unix, sd_hk_result *res, int *found_other_types)
{
  memset(res, 0, sizeof(*res));
  if (found_other_types) *found_other_types = c->other_types;
  if (c->revoked) { res->status = SD_HK_REVOKED; loc_to_res(&c->rev, res); return; }
  if (s->is_cert && c->ca_line) {
    const char *why = NULL;
    if (ssh_cert_check_host(&s->cert, s->blob, c->name, now_unix, &why) == SD_OK) {
      res->status = SD_HK_MATCH_CA;
      loc_to_res(&c->cal, res);
      res->trusted_before = 1;
      return;
    }
    s->cert_why = why;
    SD_LOGW("ssh", "host certificate for %Hs rejected: %s", c->name, why ? why : "?");
  }
  if (c->mismatch) {
    res->status = SD_HK_MISMATCH;
    loc_to_res(&c->mis, res);
    memcpy(res->stored_type, c->mis_type, sizeof(res->stored_type));
    memcpy(res->stored_fp_sha256, c->mis_fp, sizeof(res->stored_fp_sha256));
    return;
  }
  if (c->match) {
    res->status = SD_HK_MATCH;
    loc_to_res(&c->mat, res);
    res->trusted_before = 1;
    res->wildcard_only = !c->match_explicit;
    return;
  }
  if (s->is_cert && c->ca_any) {
    /* a CA is trusted for this name but the certificate did not validate: no TOFU path (TM-R04) */
    res->status = SD_HK_MISMATCH;
    loc_to_res(c->ca_line ? &c->cal : &c->caany, res);
    ssh_span_copy(ssh_blob_key_type(s->cert.sig_key.p, s->cert.sig_key.n), res->stored_type, sizeof(res->stored_type));
    if (sd_hostkey_fingerprint_sha256(s->cert.sig_key.p, s->cert.sig_key.n, res->stored_fp_sha256) != SD_OK)
      res->stored_fp_sha256[0] = '\0';
    return;
  }
  res->status = c->other_types ? SD_HK_NEW_TYPE : SD_HK_NEW;
}

sd_err ssh_kh_check_buffer(const char *text, size_t len, const char *lookup_name, const uint8_t *blob,
                           size_t blob_len, sd_hk_result *res, int *found_other_types)
{
  kh_eval c;
  kh_subject s;
  uint8_t *tmp;
  memset(res, 0, sizeof(*res));
  if (!ssh_blob_key_type(blob, blob_len).n) return SD_E_INVALID_PARAM;
  if (subject_init(&s, blob, blob_len) != SD_OK) return SD_E_INVALID_PARAM;
  tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!tmp) { subject_free(&s); return SD_E_NO_MEMORY; }
  eval_init(&c, &s, lookup_name, tmp);
  eval_buffer(&c, text, len, SD_KH_STORE_USER, NULL, 0);
  eval_decide(&c, &s, (uint64_t)sd_unix_time_now(), res, found_other_types);
  sd_free(tmp);
  subject_free(&s);
  return SD_OK;
}

typedef struct kh_types_ctx { const char *name; sd_kh_types *out; uint8_t *tmp; int live; } kh_types_ctx;

static int types_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_types_ctx *c = (kh_types_ctx *)vctx;
  kh_line l;
  size_t blen;
  uint32_t i;
  SD_UNUSED(no);
  if (parse_line(s, n, &l) <= 0) return 0;
  if (ssh_kh_match_patterns(l.pat, l.pat_len, c->name) != 1) return 0;
  if (c->live && ssh_kh_wildcard_only(l.pat, l.pat_len)) return 0;   /* TM-R06 */
  if (l.marker == KH_REVOKED) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) return 0;
  if (l.marker == KH_CA) { c->out->has_ca = 1; return 0; }
  if (l.type_len >= sizeof(c->out->type[0])) return 0;
  for (i = 0; i < c->out->count; i++)
    if (strlen(c->out->type[i]) == l.type_len && memcmp(c->out->type[i], l.type, l.type_len) == 0) return 0;
  if (c->out->count >= SD_COUNTOF(c->out->type)) return 0;
  memcpy(c->out->type[c->out->count], l.type, l.type_len);
  c->out->type[c->out->count][l.type_len] = '\0';
  c->out->count++;
  return 0;
}

static sd_err types_buffer(const char *text, size_t len, const char *lookup_name, sd_kh_types *out, int live)
{
  kh_types_ctx c;
  c.name = lookup_name;
  c.out = out;
  c.live = live;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  for_each_line(text, len, types_line, &c);
  sd_free(c.tmp);
  return SD_OK;
}

sd_err ssh_kh_types_buffer(const char *text, size_t len, const char *lookup_name, sd_kh_types *out)
{
  return types_buffer(text, len, lookup_name, out, 0);
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

static wchar_t *path_join(int csidl, const wchar_t *tail)
{
  wchar_t base[MAX_PATH], full[MAX_PATH + 64];
  size_t n, t = wcslen(tail);
  if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, 0, base))) return NULL;
  n = wcslen(base);
  if (n + t + 1 >= SD_COUNTOF(full)) return NULL;
  memcpy(full, base, n * sizeof(wchar_t));
  memcpy(full + n, tail, (t + 1) * sizeof(wchar_t));
  return wcsdup_sd(full);
}

static wchar_t *default_path(sd_kh_store_kind kind, int second)
{
  switch (kind) {
  case SD_KH_STORE_MACHINE: return path_join(CSIDL_COMMON_APPDATA, L"\\LibreStatic\\ShellDrive\\known_hosts");
  case SD_KH_STORE_USER: return path_join(CSIDL_APPDATA, L"\\LibreStatic\\ShellDrive\\known_hosts");
  case SD_KH_SRC_OPENSSH: return path_join(CSIDL_PROFILE, second ? L"\\.ssh\\known_hosts2" : L"\\.ssh\\known_hosts");
  case SD_KH_SRC_PUTTY: return wcsdup_sd(L"Software\\SimonTatham\\PuTTY\\SshHostKeys");
  }
  return NULL;
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
    sd_kh_store_kind kind = stores[i].kind;
    int live = kind == SD_KH_SRC_OPENSSH || kind == SD_KH_SRC_PUTTY, k, n;
    if (!live && kind != SD_KH_STORE_USER && kind != SD_KH_STORE_MACHINE) { sd_known_hosts_close(kh); return SD_E_INVALID_PARAM; }
    /* the default OpenSSH source is known_hosts plus known_hosts2 */
    n = (kind == SD_KH_SRC_OPENSSH && !stores[i].path) ? 2 : 1;
    for (k = 0; k < n; k++) {
      kh_store *s;
      if (kh->count >= KH_MAX_STORES) { sd_known_hosts_close(kh); return SD_E_INVALID_PARAM; }
      s = &kh->stores[kh->count];
      s->kind = kind;
      s->path = stores[i].path ? wcsdup_sd(stores[i].path) : default_path(kind, k);
      if (!s->path) { sd_known_hosts_close(kh); return stores[i].path ? SD_E_NO_MEMORY : SD_E_FAILURE; }
      s->writable = live ? 0 : stores[i].writable;
      kh->count++;
    }
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

static int is_live(const kh_store *s) { return s->kind == SD_KH_SRC_OPENSSH || s->kind == SD_KH_SRC_PUTTY; }

/* Reads a store's text: our files directly, live sources through the TM-R06 checks. SD_E_NOT_FOUND
   for an absent file, SD_E_ACCESS_DENIED for an insecure live source (skipped). */
static sd_err load_store(const kh_store *s, char **text, size_t *len)
{
  if (!is_live(s)) return read_file(s->path, text, len);
  {
    sd_kh_src_state st;
    sd_err e = ssh_kh_live_load(s->kind, s->path, text, len, &st, NULL, 0, NULL);
    if (e != SD_OK) return e;
    if (st == SD_KH_SRC_ABSENT) { sd_free(*text); *text = NULL; return SD_E_NOT_FOUND; }
    if (st != SD_KH_SRC_OK) {
      SD_LOGW("ssh", "known_hosts live source %ls skipped: hostkey_source_insecure", s->path);
      sd_free(*text);
      *text = NULL;
      return SD_E_ACCESS_DENIED;
    }
    return SD_OK;
  }
}

static kh_store *find_store(sd_known_hosts *kh, sd_kh_store_kind kind)
{
  uint32_t i;
  for (i = 0; i < kh->count; i++)
    if (kh->stores[i].kind == kind) return &kh->stores[i];
  return NULL;
}

void ssh_kh_date_comment(const char *prefix, char *out, size_t cap)
{
  SYSTEMTIME t;
  size_t n = strlen(prefix);
  GetSystemTime(&t);
  if (cap < n + 11) { if (cap) out[0] = '\0'; return; }
  memcpy(out, prefix, n);
  out[n++] = (char)('0' + (t.wYear / 1000) % 10); out[n++] = (char)('0' + (t.wYear / 100) % 10);
  out[n++] = (char)('0' + (t.wYear / 10) % 10); out[n++] = (char)('0' + t.wYear % 10); out[n++] = '-';
  out[n++] = (char)('0' + t.wMonth / 10); out[n++] = (char)('0' + t.wMonth % 10); out[n++] = '-';
  out[n++] = (char)('0' + t.wDay / 10); out[n++] = (char)('0' + t.wDay % 10);
  out[n] = '\0';
}

sd_err sd_known_hosts_check(sd_known_hosts *kh, const char *lookup_name, const uint8_t *blob, size_t len,
                            uint64_t now_unix, sd_hk_result *res)
{
  uint32_t i;
  kh_eval c;
  kh_subject s;
  uint8_t *tmp;
  int copy_from_live = 0;
  sd_kh_store_kind live_kind = SD_KH_SRC_OPENSSH;
  if (!kh || !lookup_name || !blob || !len || !res) return SD_E_INVALID_PARAM;
  if (!ssh_blob_key_type(blob, len).n) return SD_E_INVALID_PARAM;
  if (subject_init(&s, blob, len) != SD_OK) return SD_E_INVALID_PARAM;
  tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!tmp) { subject_free(&s); return SD_E_NO_MEMORY; }
  eval_init(&c, &s, lookup_name, tmp);
  sd_mutex_lock(&kh->lock);
  for (i = 0; i < kh->count; i++) {
    const kh_store *st = &kh->stores[i];
    char *text;
    size_t tlen;
    sd_err e = load_store(st, &text, &tlen);
    if (e == SD_E_NOT_FOUND || e == SD_E_ACCESS_DENIED) continue;
    if (e != SD_OK) {
      SD_LOGW("ssh", "known_hosts store %ls unreadable: %s", st->path, sd_err_name(e));
      continue;
    }
    eval_buffer(&c, text, tlen, st->kind, st->path, is_live(st));
    sd_free(text);
  }
  eval_decide(&c, &s, now_unix, res, NULL);
  if (res->status == SD_HK_MATCH && !c.match_ours && (res->store == SD_KH_SRC_OPENSSH || res->store == SD_KH_SRC_PUTTY)) {
    kh_store *u = find_store(kh, SD_KH_STORE_USER);
    copy_from_live = u && u->writable;
    live_kind = res->store;
  }
  sd_mutex_unlock(&kh->lock);
  if (copy_from_live) {
    /* D7: a key matched from a live source is copied into our user store with its origin */
    char comment[64];
    sd_err e;
    ssh_kh_date_comment(live_kind == SD_KH_SRC_PUTTY ? "# imported-from=putty added=" : "# imported-from=openssh added=",
                        comment, sizeof(comment));
    e = sd_known_hosts_add(kh, SD_KH_STORE_USER, lookup_name, s.key, s.key_len, comment);
    if (e != SD_OK) SD_LOGW("ssh", "copying the host key of %Hs into the user store failed: %s", lookup_name, sd_err_name(e));
  }
  sd_free(tmp);
  subject_free(&s);
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
    sd_err e = load_store(&kh->stores[i], &text, &tlen);
    if (e != SD_OK) continue;
    e = types_buffer(text, tlen, lookup_name, out, is_live(&kh->stores[i]));
    sd_free(text);
    if (e != SD_OK) { sd_mutex_unlock(&kh->lock); return e; }
  }
  sd_mutex_unlock(&kh->lock);
  return SD_OK;
}

/* ---- listing ---- */

typedef struct kh_list_ctx {
  const char *name;
  sd_kh_entry_cb cb; void *ctx;
  uint8_t *tmp;
  int stop;
} kh_list_ctx;

static int list_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_list_ctx *c = (kh_list_ctx *)vctx;
  kh_line l;
  size_t blen;
  char type[64];
  sd_kh_entry e;
  if (parse_line(s, n, &l) <= 0 || l.marker != KH_PLAIN) return 0;
  if (ssh_kh_match_patterns(l.pat, l.pat_len, c->name) != 1) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen) || l.type_len >= sizeof(type)) return 0;
  memcpy(type, l.type, l.type_len);
  type[l.type_len] = '\0';
  e.blob = c->tmp;
  e.len = blen;
  e.type = type;
  e.line = no;
  e.explicit_name = explicit_single(l.pat, l.pat_len, c->name);
  e.wildcard_only = ssh_kh_wildcard_only(l.pat, l.pat_len);
  if (c->cb(c->ctx, &e)) { c->stop = 1; return 1; }
  return 0;
}

sd_err sd_known_hosts_list(sd_known_hosts *kh, sd_kh_store_kind store, const char *lookup_name,
                           sd_kh_entry_cb cb, void *ctx)
{
  uint32_t i;
  kh_list_ctx c;
  int any = 0;
  if (!kh || !lookup_name || !cb) return SD_E_INVALID_PARAM;
  memset(&c, 0, sizeof(c));
  c.name = lookup_name;
  c.cb = cb;
  c.ctx = ctx;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  sd_mutex_lock(&kh->lock);
  for (i = 0; i < kh->count && !c.stop; i++) {
    char *text;
    size_t tlen;
    if (kh->stores[i].kind != store) continue;
    any = 1;
    if (load_store(&kh->stores[i], &text, &tlen) != SD_OK) continue;
    for_each_line(text, tlen, list_line, &c);
    sd_free(text);
  }
  sd_mutex_unlock(&kh->lock);
  sd_free(c.tmp);
  return any ? SD_OK : SD_E_NOT_FOUND;
}

typedef struct kh_all_ctx {
  sd_kh_all_cb cb;
  void *ctx;
  uint8_t *tmp;
  int stop;
} kh_all_ctx;

static int all_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_all_ctx *c = (kh_all_ctx *)vctx;
  kh_line l;
  size_t blen;
  char type[64], pat[256];
  sd_kh_all_entry e;
  if (parse_line(s, n, &l) <= 0 || l.marker != KH_PLAIN) return 0;
  if (l.pat_len >= sizeof(pat) || l.type_len >= sizeof(type)) return 0;
  if (!decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) return 0;
  memcpy(pat, l.pat, l.pat_len);
  pat[l.pat_len] = '\0';
  memcpy(type, l.type, l.type_len);
  type[l.type_len] = '\0';
  e.pattern = pat;
  e.blob = c->tmp;
  e.len = blen;
  e.type = type;
  e.line = no;
  e.hashed = l.pat[0] == '|';
  if (c->cb(c->ctx, &e)) { c->stop = 1; return 1; }
  return 0;
}

sd_err sd_known_hosts_list_all(sd_known_hosts *kh, sd_kh_store_kind store, sd_kh_all_cb cb, void *ctx)
{
  uint32_t i;
  kh_all_ctx c;
  int any = 0;
  if (!kh || !cb || (store != SD_KH_STORE_MACHINE && store != SD_KH_STORE_USER)) return SD_E_INVALID_PARAM;
  memset(&c, 0, sizeof(c));
  c.cb = cb;
  c.ctx = ctx;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  sd_mutex_lock(&kh->lock);
  for (i = 0; i < kh->count && !c.stop; i++) {
    char *text;
    size_t tlen;
    if (kh->stores[i].kind != store) continue;
    any = 1;
    if (load_store(&kh->stores[i], &text, &tlen) != SD_OK) continue;
    for_each_line(text, tlen, all_line, &c);
    sd_free(text);
  }
  sd_mutex_unlock(&kh->lock);
  sd_free(c.tmp);
  return any ? SD_OK : SD_E_NOT_FOUND;
}

/* ---- writing ---- */

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

/* writable file store of that kind, or an error */
static sd_err writable_store(sd_known_hosts *kh, sd_kh_store_kind target, kh_store **out)
{
  kh_store *s = find_store(kh, target);
  *out = NULL;
  if (!s || is_live(s)) return s ? SD_E_READ_ONLY : SD_E_NOT_FOUND;
  if (!s->writable) return SD_E_READ_ONLY;
  *out = s;
  return SD_OK;
}

static sd_err hashed_name(const char *name, char *out, size_t cap)
{
  uint8_t salt[SD_SHA1_LEN], mac[SD_HASH_MAX_LEN];
  sd_hmac_ctx h;
  size_t o;
  sd_err e;
  if (!ssh_crypto_ready()) return SD_E_UNSUPPORTED;
  e = ssh_random(salt, sizeof(salt));
  if (e != SD_OK) return e;
  sd_hmac_init(&h, SD_HASH_SHA1, salt, sizeof(salt));
  sd_hmac_update(&h, name, strlen(name));
  sd_hmac_final(&h, mac);
  sd_hmac_wipe(&h);
  if (cap < 64) return SD_E_INTERNAL;
  memcpy(out, "|1|", 3);
  o = 3 + ssh_b64_encode(salt, sizeof(salt), out + 3, cap - 3, 1);
  out[o++] = '|';
  if (!ssh_b64_encode(mac, SD_SHA1_LEN, out + o, cap - o, 1)) return SD_E_INTERNAL;
  return SD_OK;
}

sd_err sd_known_hosts_add_ex(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const uint8_t *blob, size_t len, const char *comment, uint32_t flags)
{
  kh_store *s;
  sd_span type;
  sd_wr w;
  char *text = NULL, *b64, hname[96];
  uint8_t *plain = NULL;
  size_t tlen = 0, b64cap, cl, plen = 0;
  HANDLE m;
  sd_err e;
  if (!kh || !valid_name(lookup_name) || !blob || !len || len > KH_MAX_BLOB) return SD_E_INVALID_PARAM;
  if (!ssh_blob_key_type(blob, len).n) return SD_E_INVALID_PARAM;
  e = writable_store(kh, target, &s);
  if (e != SD_OK) return e;
  if (flags & SD_KH_ADD_HASHED) {
    e = hashed_name(lookup_name, hname, sizeof(hname));
    if (e != SD_OK) return e;
  }
  /* a certificate is stored as its plain key (the CA is trusted through @cert-authority lines) */
  e = ssh_blob_plain_key(blob, len, &plain, &plen);
  if (e != SD_OK) return SD_E_INVALID_PARAM;
  type = ssh_blob_key_type(plain, plen);
  b64cap = ssh_b64_encoded_len(plen, 1) + 1;
  b64 = (char *)sd_alloc(b64cap);
  if (!b64) { sd_free(plain); return SD_E_NO_MEMORY; }
  ssh_b64_encode(plain, plen, b64, b64cap, 1);

  sd_mutex_lock(&kh->lock);
  m = lock_file_mutex(s);
  if (!m) { sd_mutex_unlock(&kh->lock); sd_free(b64); sd_free(plain); return SD_E_BUSY; }
  e = read_file(s->path, &text, &tlen);
  if (e == SD_E_NOT_FOUND) { e = SD_OK; text = NULL; tlen = 0; }
  if (e == SD_OK) {
    sd_wr_init(&w, KH_MAX_FILE + 256 * 1024);
    if (tlen) {
      sd_wr_bytes(&w, text, tlen);
      if (text[tlen - 1] != '\n') sd_wr_bytes(&w, "\r\n", 2);
    }
    if (flags & SD_KH_ADD_HASHED) sd_wr_bytes(&w, hname, strlen(hname));
    else sd_wr_bytes(&w, lookup_name, strlen(lookup_name));
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
  sd_free(plain);
  return e;
}

sd_err sd_known_hosts_add(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                          const uint8_t *blob, size_t len, const char *comment)
{
  return sd_known_hosts_add_ex(kh, target, lookup_name, blob, len, comment, 0);
}

typedef struct kh_remove_ctx {
  const char *name, *type;
  const uint8_t *blob; size_t blob_len;    /* remove_key: exact key, explicit single-name lines */
  uint8_t *tmp;
  sd_wr *w;
  uint32_t removed;
} kh_remove_ctx;

static int remove_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_remove_ctx *c = (kh_remove_ctx *)vctx;
  kh_line l;
  SD_UNUSED(no);
  if (parse_line(s, n, &l) == 1 && l.marker == KH_PLAIN && ssh_kh_match_patterns(l.pat, l.pat_len, c->name) == 1) {
    int drop;
    if (c->blob) {
      size_t blen;
      drop = explicit_single(l.pat, l.pat_len, c->name) && decode_key(&l, c->tmp, KH_MAX_BLOB, &blen) &&
             blen == c->blob_len && memcmp(c->tmp, c->blob, blen) == 0;
    } else {
      drop = !c->type || (strlen(c->type) == l.type_len && memcmp(c->type, l.type, l.type_len) == 0);
    }
    if (drop) { c->removed++; return 0; }
  }
  sd_wr_bytes(c->w, s, n);
  sd_wr_bytes(c->w, "\r\n", 2);
  return 0;
}

static sd_err remove_impl(sd_known_hosts *kh, sd_kh_store_kind target, kh_remove_ctx *c)
{
  kh_store *s;
  sd_wr w;
  char *text = NULL;
  size_t tlen = 0;
  HANDLE m;
  sd_err e = writable_store(kh, target, &s);
  if (e != SD_OK) return e;
  sd_mutex_lock(&kh->lock);
  m = lock_file_mutex(s);
  if (!m) { sd_mutex_unlock(&kh->lock); return SD_E_BUSY; }
  e = read_file(s->path, &text, &tlen);
  if (e == SD_OK) {
    sd_wr_init(&w, KH_MAX_FILE + 1024);
    c->w = &w;
    c->removed = 0;
    for_each_line(text, tlen, remove_line, c);
    if (!sd_wr_ok(&w)) e = SD_E_NO_MEMORY;
    else if (c->removed == 0) e = SD_E_NOT_FOUND;
    else e = write_file_atomic(s, (const char *)w.p, w.len);
    sd_wr_free(&w);
  }
  unlock_file_mutex(m);
  sd_mutex_unlock(&kh->lock);
  sd_free(text);
  return e;
}

sd_err sd_known_hosts_remove(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const char *key_type)
{
  kh_remove_ctx c;
  if (!kh || !valid_name(lookup_name)) return SD_E_INVALID_PARAM;
  memset(&c, 0, sizeof(c));
  c.name = lookup_name;
  c.type = key_type;
  return remove_impl(kh, target, &c);
}

sd_err sd_known_hosts_remove_key(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                                 const uint8_t *blob, size_t len)
{
  kh_remove_ctx c;
  sd_err e;
  if (!kh || !valid_name(lookup_name) || !blob || !len) return SD_E_INVALID_PARAM;
  memset(&c, 0, sizeof(c));
  c.name = lookup_name;
  c.blob = blob;
  c.blob_len = len;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  e = remove_impl(kh, target, &c);
  sd_free(c.tmp);
  return e;
}

typedef struct kh_has_ctx { const uint8_t *blob; size_t len; int found; } kh_has_ctx;

static int has_key_cb(void *ctx, const sd_kh_entry *e)
{
  kh_has_ctx *h = (kh_has_ctx *)ctx;
  if (e->len == h->len && memcmp(e->blob, h->blob, e->len) == 0) { h->found = 1; return 1; }
  return 0;
}

sd_err sd_known_hosts_apply_hostkeys(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                                     const sd_hk_key *add, uint32_t add_count,
                                     const sd_hk_key *remove, uint32_t remove_count)
{
  uint32_t i;
  char comment[64];
  sd_err e;
  if (!kh || !valid_name(lookup_name) || (add_count && !add) || (remove_count && !remove)) return SD_E_INVALID_PARAM;
  ssh_kh_date_comment("# updated-by=hostkeys-00 added=", comment, sizeof(comment));
  for (i = 0; i < add_count; i++) {
    kh_has_ctx h;
    if (!add[i].blob || !add[i].len) return SD_E_INVALID_PARAM;
    h.blob = add[i].blob;
    h.len = add[i].len;
    h.found = 0;
    e = sd_known_hosts_list(kh, target, lookup_name, has_key_cb, &h);
    if (e != SD_OK) return e;
    if (h.found) continue;
    e = sd_known_hosts_add(kh, target, lookup_name, add[i].blob, add[i].len, comment);
    if (e != SD_OK) return e;
  }
  for (i = 0; i < remove_count; i++) {
    if (!remove[i].blob || !remove[i].len) return SD_E_INVALID_PARAM;
    e = sd_known_hosts_remove_key(kh, target, lookup_name, remove[i].blob, remove[i].len);
    if (e != SD_OK && e != SD_E_NOT_FOUND) return e;
  }
  return SD_OK;
}

/* ---- import (one-shot copy from a live source, 01 §7.2/§7.3) ---- */

typedef struct kh_import_ctx {
  sd_known_hosts *kh;
  sd_kh_store_kind target;
  const char *comment;
  uint8_t *tmp;
  sd_kh_import_report *rep;
  sd_err err;
} kh_import_ctx;

typedef struct kh_cmp_ctx { const uint8_t *blob; size_t len; const char *type; int same, other; } kh_cmp_ctx;

static int cmp_cb(void *ctx, const sd_kh_entry *e)
{
  kh_cmp_ctx *c = (kh_cmp_ctx *)ctx;
  if (strcmp(e->type, c->type) != 0) return 0;
  if (e->len == c->len && memcmp(e->blob, c->blob, e->len) == 0) c->same = 1;
  else c->other = 1;
  return 0;
}

static int import_line(void *vctx, const char *s, size_t n, uint32_t no)
{
  kh_import_ctx *c = (kh_import_ctx *)vctx;
  kh_line l;
  size_t blen, i, start;
  int r = parse_line(s, n, &l);
  SD_UNUSED(no);
  if (r == 0) return 0;
  if (r < 0 || l.marker != KH_PLAIN || !decode_key(&l, c->tmp, KH_MAX_BLOB, &blen)) { c->rep->invalid_lines++; return 0; }
  /* one entry per positive, explicit (non-hashed, non-wildcard) name */
  start = 0;
  for (i = 0; i <= l.pat_len; i++) {
    if (i == l.pat_len || l.pat[i] == ',') {
      char name[320];
      size_t pn = i - start;
      const char *p = l.pat + start;
      start = i + 1;
      if (!pn || pn >= sizeof(name) || p[0] == '!' || p[0] == '|' || memchr(p, '*', pn) || memchr(p, '?', pn)) continue;
      memcpy(name, p, pn);
      name[pn] = '\0';
      {
        kh_cmp_ctx cc;
        char type[64];
        sd_err e;
        if (l.type_len >= sizeof(type)) continue;
        memcpy(type, l.type, l.type_len);
        type[l.type_len] = '\0';
        cc.blob = c->tmp; cc.len = blen; cc.type = type; cc.same = 0; cc.other = 0;
        (void)sd_known_hosts_list(c->kh, c->target, name, cmp_cb, &cc);
        if (cc.same) { c->rep->already_present++; continue; }
        if (cc.other) { c->rep->conflicts++; continue; }
        e = sd_known_hosts_add(c->kh, c->target, name, c->tmp, blen, c->comment);
        if (e != SD_OK) { c->err = e; return 1; }
        c->rep->imported++;
      }
    }
  }
  return 0;
}

sd_err sd_known_hosts_import(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_store_kind target,
                             sd_kh_import_report *rep)
{
  uint32_t i;
  sd_kh_import_report local;
  kh_import_ctx c;
  char comment[64];
  kh_store *t;
  int any = 0;
  sd_err e;
  if (!rep) rep = &local;
  memset(rep, 0, sizeof(*rep));
  if (!kh || (source != SD_KH_SRC_OPENSSH && source != SD_KH_SRC_PUTTY)) return SD_E_INVALID_PARAM;
  e = writable_store(kh, target, &t);
  if (e != SD_OK) return e;
  ssh_kh_date_comment(source == SD_KH_SRC_PUTTY ? "# imported-from=putty added=" : "# imported-from=openssh added=",
                      comment, sizeof(comment));
  memset(&c, 0, sizeof(c));
  c.kh = kh;
  c.target = target;
  c.comment = comment;
  c.rep = rep;
  c.tmp = (uint8_t *)sd_alloc(KH_MAX_BLOB);
  if (!c.tmp) return SD_E_NO_MEMORY;
  for (i = 0; i < kh->count && c.err == SD_OK; i++) {
    char *text = NULL;
    size_t tlen = 0;
    sd_kh_src_state st;
    uint32_t invalid = 0;
    if (kh->stores[i].kind != source) continue;
    any = 1;
    /* the store lock is taken by the add/list calls; the source itself is read without it */
    e = ssh_kh_live_load(source, kh->stores[i].path, &text, &tlen, &st, NULL, 0, &invalid);
    if (e != SD_OK) { c.err = e; break; }
    rep->invalid_lines += invalid;
    if (st == SD_KH_SRC_INSECURE) { sd_free(text); c.err = SD_E_ACCESS_DENIED; break; }
    if (st == SD_KH_SRC_OK) for_each_line(text, tlen, import_line, &c);
    sd_free(text);
  }
  sd_free(c.tmp);
  if (c.err != SD_OK) return c.err;
  return any ? SD_OK : SD_E_NOT_FOUND;
}

sd_err sd_known_hosts_source_state(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_src_state *state,
                                   wchar_t *detail_sid, size_t detail_cap)
{
  uint32_t i;
  int any = 0, ok = 0, insecure = 0;
  if (!kh || !state) return SD_E_INVALID_PARAM;
  if (detail_sid && detail_cap) detail_sid[0] = L'\0';
  for (i = 0; i < kh->count; i++) {
    const kh_store *s = &kh->stores[i];
    sd_kh_src_state st;
    char *text = NULL;
    size_t tlen = 0;
    if (s->kind != source) continue;
    any = 1;
    if (!is_live(s)) {
      if (GetFileAttributesW(s->path) != INVALID_FILE_ATTRIBUTES) ok = 1;
      continue;
    }
    if (ssh_kh_live_load(s->kind, s->path, &text, &tlen, &st, insecure ? NULL : detail_sid, detail_cap, NULL) != SD_OK)
      continue;
    sd_free(text);
    if (st == SD_KH_SRC_OK) ok = 1;
    else if (st == SD_KH_SRC_INSECURE) insecure = 1;
  }
  if (!any) *state = SD_KH_SRC_DISABLED;
  else if (insecure) *state = SD_KH_SRC_INSECURE;
  else *state = ok ? SD_KH_SRC_OK : SD_KH_SRC_ABSENT;
  return SD_OK;
}
