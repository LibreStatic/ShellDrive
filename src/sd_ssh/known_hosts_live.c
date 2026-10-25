/* Live read-only known_hosts sources (01 §7.2, §7.3; D7; TM-R06): %USERPROFILE%\.ssh\known_hosts(2)
 * and PuTTY's HKCU\Software\SimonTatham\PuTTY\SshHostKeys. A source is read only if nobody but the
 * user, SYSTEM and Administrators can change it; the checks run on the opened handle (file) or key
 * on every read. No transport dependency. */
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "hostkey_internal.h"
#include "known_hosts_internal.h"
#include "ssh_internal.h"

#define LIVE_MAX_FILE (16u * 1024u * 1024u)

/* ---- TM-R06 security descriptor check ---- */

static int sid_is(PSID sid, const wchar_t *str)
{
  PSID other = NULL;
  int eq;
  if (!ConvertStringSidToSidW(str, &other)) return 0;
  eq = EqualSid(sid, other) != 0;
  LocalFree(other);
  return eq;
}

static int sid_is_user(PSID sid)
{
  HANDLE tok = NULL;
  uint8_t tu[256];
  DWORD got = 0;
  int eq = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
  if (GetTokenInformation(tok, TokenUser, tu, sizeof(tu), &got)) eq = EqualSid(sid, ((TOKEN_USER *)tu)->User.Sid) != 0;
  CloseHandle(tok);
  return eq;
}

static int sid_trusted(PSID sid, int owner)
{
  if (sid_is_user(sid) || sid_is(sid, L"S-1-5-18") || sid_is(sid, L"S-1-5-32-544")) return 1;
  return !owner && sid_is(sid, L"S-1-3-4");   /* OWNER RIGHTS: the owner, already checked */
}

static void put_detail(wchar_t *out, size_t cap, PSID sid, const wchar_t *reason)
{
  LPWSTR s = NULL;
  size_t n;
  if (!out || !cap) return;
  out[0] = L'\0';
  if (sid && ConvertSidToStringSidW(sid, &s)) {
    n = wcslen(s);
    if (n < cap) memcpy(out, s, (n + 1) * sizeof(wchar_t));
    LocalFree(s);
    return;
  }
  if (reason) {
    n = wcslen(reason);
    if (n < cap) memcpy(out, reason, (n + 1) * sizeof(wchar_t));
  }
}

int ssh_kh_sd_secure(PSECURITY_DESCRIPTOR sd, DWORD bad_rights, const GENERIC_MAPPING *generic,
                     wchar_t *sid, size_t sid_cap)
{
  PSID owner = NULL;
  BOOL defaulted = FALSE, present = FALSE;
  PACL dacl = NULL;
  ACL_SIZE_INFORMATION info;
  DWORD i;
  if (!GetSecurityDescriptorOwner(sd, &owner, &defaulted) || !owner) { put_detail(sid, sid_cap, NULL, L"[no owner]"); return 0; }
  if (!sid_trusted(owner, 1)) { put_detail(sid, sid_cap, owner, NULL); return 0; }
  if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl) {
    put_detail(sid, sid_cap, NULL, L"[null DACL]");
    return 0;
  }
  if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) { put_detail(sid, sid_cap, NULL, L"[bad DACL]"); return 0; }
  for (i = 0; i < info.AceCount; i++) {
    ACE_HEADER *h = NULL;
    ACCESS_ALLOWED_ACE *a;
    ACCESS_MASK m;
    if (!GetAce(dacl, i, (LPVOID *)&h) || !h) continue;
    /* ACCESS_ALLOWED_ACE_TYPE (0) and ACCESS_ALLOWED_CALLBACK_ACE_TYPE (9) share the layout */
    if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != 9) continue;
    if (h->AceFlags & INHERIT_ONLY_ACE) continue;
    a = (ACCESS_ALLOWED_ACE *)h;
    m = a->Mask;
    MapGenericMask(&m, (PGENERIC_MAPPING)generic);
    if (!(m & bad_rights)) continue;
    if (!sid_trusted((PSID)&a->SidStart, 0)) { put_detail(sid, sid_cap, (PSID)&a->SidStart, NULL); return 0; }
  }
  return 1;
}

static const GENERIC_MAPPING k_file_map = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
static const GENERIC_MAPPING k_key_map = { KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS };

static int handle_secure(HANDLE h, SE_OBJECT_TYPE type, DWORD bad, const GENERIC_MAPPING *map, wchar_t *sid, size_t cap)
{
  PSECURITY_DESCRIPTOR sd = NULL;
  PSID owner = NULL;
  PACL dacl = NULL;
  int ok;
  if (GetSecurityInfo(h, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd) !=
      ERROR_SUCCESS) {
    put_detail(sid, cap, NULL, L"[security unreadable]");
    return 0;
  }
  ok = ssh_kh_sd_secure(sd, bad, map, sid, cap);
  LocalFree(sd);
  return ok;
}

/* ---- OpenSSH file ---- */

static sd_err load_openssh(const wchar_t *path, char **text, size_t *len, sd_kh_src_state *state, wchar_t *sid,
                           size_t cap)
{
  wchar_t dir[MAX_PATH + 64], root[MAX_PATH + 1];
  size_t n = wcslen(path), i;
  HANDLE h;
  BY_HANDLE_FILE_INFORMATION fi;
  DWORD fsflags = 0, got = 0;
  LARGE_INTEGER sz;
  char *buf;
  *state = SD_KH_SRC_ABSENT;
  if (n >= SD_COUNTOF(dir)) return SD_OK;
  memcpy(dir, path, (n + 1) * sizeof(wchar_t));
  for (i = n; i > 0 && dir[i - 1] != L'\\' && dir[i - 1] != L'/'; i--) {}
  if (i == 0) return SD_OK;
  dir[i - 1] = L'\0';

  /* the file */
  h = CreateFileW(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE) return SD_OK;   /* absent or unreadable */
  *state = SD_KH_SRC_INSECURE;
  if (!GetFileInformationByHandle(h, &fi) || (fi.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
    put_detail(sid, cap, NULL, L"[reparse point]");
    CloseHandle(h);
    return SD_OK;
  }
  if (!GetVolumePathNameW(path, root, SD_COUNTOF(root)) ||
      !GetVolumeInformationW(root, NULL, 0, NULL, NULL, &fsflags, NULL, 0) || !(fsflags & FILE_PERSISTENT_ACLS)) {
    put_detail(sid, cap, NULL, L"[no persistent ACLs]");
    CloseHandle(h);
    return SD_OK;
  }
  if (!handle_secure(h, SE_FILE_OBJECT, FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | DELETE,
                     &k_file_map, sid, cap)) {
    CloseHandle(h);
    return SD_OK;
  }
  /* the directory: whoever can add or delete entries can replace the file */
  {
    HANDLE hd = CreateFileW(dir, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION di;
    int ok;
    if (hd == INVALID_HANDLE_VALUE) { put_detail(sid, cap, NULL, L"[directory unreadable]"); CloseHandle(h); return SD_OK; }
    ok = GetFileInformationByHandle(hd, &di) && !(di.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    if (!ok) put_detail(sid, cap, NULL, L"[reparse point]");
    else ok = handle_secure(hd, SE_FILE_OBJECT, FILE_ADD_FILE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER, &k_file_map, sid, cap);
    CloseHandle(hd);
    if (!ok) { CloseHandle(h); return SD_OK; }
  }
  /* read from the checked handle */
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > LIVE_MAX_FILE) { CloseHandle(h); *state = SD_KH_SRC_ABSENT; return SD_OK; }
  buf = (char *)sd_alloc((size_t)sz.QuadPart + 1);
  if (!buf) { CloseHandle(h); return SD_E_NO_MEMORY; }
  if (sz.QuadPart && (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    sd_free(buf);
    CloseHandle(h);
    *state = SD_KH_SRC_ABSENT;
    return SD_OK;
  }
  CloseHandle(h);
  buf[got] = '\0';
  *text = buf;
  *len = got;
  *state = SD_KH_SRC_OK;
  return SD_OK;
}

/* ---- PuTTY registry ---- */

static int hexval(wchar_t c)
{
  if (c >= L'0' && c <= L'9') return c - L'0';
  if (c >= L'a' && c <= L'f') return c - L'a' + 10;
  if (c >= L'A' && c <= L'F') return c - L'A' + 10;
  return -1;
}

/* "0x<hex>" (big-endian magnitude, any length) -> bytes; returns length or 0. */
static size_t parse_hex(const wchar_t *s, size_t n, uint8_t *out, size_t cap)
{
  size_t i, digits, o = 0;
  if (n < 3 || s[0] != L'0' || (s[1] != L'x' && s[1] != L'X')) return 0;
  s += 2;
  n -= 2;
  while (n > 1 && s[0] == L'0') { s++; n--; }
  digits = n;
  if ((digits + 1) / 2 > cap) return 0;
  i = 0;
  if (digits & 1) {
    int v = hexval(s[0]);
    if (v < 0) return 0;
    out[o++] = (uint8_t)v;
    i = 1;
  }
  for (; i < digits; i += 2) {
    int hi = hexval(s[i]), lo = hexval(s[i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[o++] = (uint8_t)(hi << 4 | lo);
  }
  return o;
}

/* Splits data at commas into at most max fields. */
static uint32_t split_fields(const wchar_t *d, const wchar_t **f, size_t *fl, uint32_t max)
{
  uint32_t k = 0;
  const wchar_t *s = d;
  for (;;) {
    const wchar_t *e = wcschr(s, L',');
    if (k == max) return max + 1;
    f[k] = s;
    fl[k] = e ? (size_t)(e - s) : wcslen(s);
    k++;
    if (!e) return k;
    s = e + 1;
  }
}

/* Ed25519 point check for the PuTTY affine form: x, y < p and -x^2 + y^2 = 1 + d x^2 y^2 (mod p). */
static int ed25519_on_curve(const uint8_t *x, size_t xl, const uint8_t *y, size_t yl)
{
  static const uint8_t k_p[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed };
  static const uint8_t k_d[32] = {
    0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
    0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3 };
  sd_bn *b = (sd_bn *)sd_calloc(7, sizeof(sd_bn));
  sd_bn *p, *bx, *by, *x2, *y2, *t, *u;
  uint8_t ax[33], ay[33], at[33], sum[33];
  int ok = 0, i, carry;
  if (!b) return 0;
  p = &b[0]; bx = &b[1]; by = &b[2]; x2 = &b[3]; y2 = &b[4]; t = &b[5]; u = &b[6];
  if (xl > 32 || yl > 32) goto out;
  if (sd_bn_from_bytes(p, k_p, 32) != SD_OK || sd_bn_from_bytes(bx, x, xl) != SD_OK || sd_bn_from_bytes(by, y, yl) != SD_OK)
    goto out;
  if (sd_bn_vt_cmp(bx, p) >= 0 || sd_bn_vt_cmp(by, p) >= 0) goto out;
  if (sd_bn_ct_mul(t, bx, bx) != SD_OK || sd_bn_ct_mod(x2, t, p) != SD_OK) goto out;
  if (sd_bn_ct_mul(t, by, by) != SD_OK || sd_bn_ct_mod(y2, t, p) != SD_OK) goto out;
  if (sd_bn_ct_mul(t, x2, y2) != SD_OK || sd_bn_ct_mod(u, t, p) != SD_OK) goto out;    /* x^2 y^2 */
  if (sd_bn_from_bytes(bx, k_d, 32) != SD_OK || sd_bn_ct_mul(t, bx, u) != SD_OK || sd_bn_ct_mod(u, t, p) != SD_OK)
    goto out;                                                                        /* d x^2 y^2 */
  /* sum = 1 + x^2 + d x^2 y^2 (33 bytes), then mod p */
  if (sd_bn_to_bytes(x2, ax, 33) != SD_OK || sd_bn_to_bytes(u, at, 33) != SD_OK) goto out;
  memset(ay, 0, sizeof(ay));
  ay[32] = 1;
  carry = 0;
  for (i = 32; i >= 0; i--) {
    int v = ax[i] + at[i] + ay[i] + carry;
    sum[i] = (uint8_t)v;
    carry = v >> 8;
  }
  if (carry) goto out;
  if (sd_bn_from_bytes(t, sum, 33) != SD_OK || sd_bn_ct_mod(u, t, p) != SD_OK) goto out;
  ok = sd_bn_vt_cmp(u, y2) == 0;
out:
  sd_secure_zero(b, 7 * sizeof(sd_bn));
  sd_free(b);
  return ok;
}

sd_err ssh_putty_value_to_line(const wchar_t *name, const wchar_t *data, sd_wr *w)
{
  char nm[512], host[320], lookup[340], b64[4096];
  const char *type = NULL;
  size_t nl = 0, i;
  const wchar_t *f[4];
  size_t fl[4];
  uint32_t nf, port = 0;
  char *at, *colon;
  uint8_t blob[2600];
  sd_wr bw;
  sd_err e;
  ssh_pubkey pk;

  /* unescape %XX */
  for (i = 0; name[i]; i++) {
    wchar_t c = name[i];
    if (nl + 1 >= sizeof(nm)) return SD_E_KEY_FORMAT;
    if (c == L'%' && hexval(name[i + 1]) >= 0 && hexval(name[i + 2]) >= 0) {
      nm[nl++] = (char)(hexval(name[i + 1]) << 4 | hexval(name[i + 2]));
      i += 2;
    } else if (c < 0x80) {
      nm[nl++] = (char)c;
    } else {
      return SD_E_KEY_FORMAT;
    }
  }
  nm[nl] = '\0';
  at = strchr(nm, '@');
  if (!at) return SD_E_KEY_FORMAT;
  *at = '\0';
  colon = strchr(at + 1, ':');
  if (!colon || colon == at + 1) return SD_E_KEY_FORMAT;
  for (i = 1; at + i < colon; i++) {
    if (at[i] < '0' || at[i] > '9') return SD_E_KEY_FORMAT;
    port = port * 10u + (uint32_t)(at[i] - '0');
    if (port > 65535u) return SD_E_KEY_FORMAT;
  }
  if (!port || strlen(colon + 1) >= sizeof(host)) return SD_E_KEY_FORMAT;
  memcpy(host, colon + 1, strlen(colon + 1) + 1);
  if (ssh_kh_lookup_name(host, (uint16_t)port, lookup, sizeof(lookup)) != SD_OK) return SD_E_KEY_FORMAT;

  if (strcmp(nm, "dss") == 0 || strcmp(nm, "rsa") == 0 || strcmp(nm, "ssh-ed448") == 0) return SD_E_KEY_UNSUPPORTED;
  nf = split_fields(data, f, fl, 4);
  sd_wr_init_fixed(&bw, blob, sizeof(blob));
  if (strcmp(nm, "rsa2") == 0) {
    uint8_t ev[16], nv[2050];
    size_t el, nvl;
    if (nf != 2) return SD_E_KEY_FORMAT;
    el = parse_hex(f[0], fl[0], ev, sizeof(ev));
    nvl = parse_hex(f[1], fl[1], nv, sizeof(nv));
    if (!el || !nvl) return SD_E_KEY_FORMAT;
    type = "ssh-rsa";
    sd_wr_cstring(&bw, type);
    sd_wr_mpint(&bw, ev, el);
    sd_wr_mpint(&bw, nv, nvl);
  } else if (strcmp(nm, "ssh-ed25519") == 0) {
    uint8_t xv[40], yv[40], pk32[32];
    size_t xl, yl;
    if (nf != 2) return SD_E_KEY_FORMAT;
    xl = parse_hex(f[0], fl[0], xv, sizeof(xv));
    yl = parse_hex(f[1], fl[1], yv, sizeof(yv));
    if (!xl || !yl || xl > 32 || yl > 32 || !ed25519_on_curve(xv, xl, yv, yl)) return SD_E_KEY_FORMAT;
    memset(pk32, 0, sizeof(pk32));
    for (i = 0; i < yl; i++) pk32[i] = yv[yl - 1 - i];        /* little-endian y */
    pk32[31] = (uint8_t)((pk32[31] & 0x7f) | ((xv[xl - 1] & 1) << 7));
    type = "ssh-ed25519";
    sd_wr_cstring(&bw, type);
    sd_wr_string(&bw, pk32, 32);
  } else if (strncmp(nm, "ecdsa-sha2-nistp", 16) == 0) {
    static const struct { const char *type, *curve; size_t flen; } k_ec[] = {
      { "ecdsa-sha2-nistp256", "nistp256", 32 }, { "ecdsa-sha2-nistp384", "nistp384", 48 },
      { "ecdsa-sha2-nistp521", "nistp521", 66 } };
    uint8_t xv[70], yv[70], q[1 + 2 * 66];
    size_t xl, yl, k, flen = 0;
    char cn[16];
    for (k = 0; k < SD_COUNTOF(k_ec); k++) if (strcmp(nm, k_ec[k].type) == 0) { type = k_ec[k].type; flen = k_ec[k].flen; break; }
    if (!type || nf != 3 || fl[0] >= sizeof(cn)) return type ? SD_E_KEY_FORMAT : SD_E_KEY_UNSUPPORTED;
    for (i = 0; i < fl[0]; i++) cn[i] = (char)f[0][i];
    cn[fl[0]] = '\0';
    if (strcmp(cn, k_ec[k].curve) != 0) return SD_E_KEY_FORMAT;
    xl = parse_hex(f[1], fl[1], xv, sizeof(xv));
    yl = parse_hex(f[2], fl[2], yv, sizeof(yv));
    if (!xl || !yl || xl > flen || yl > flen) return SD_E_KEY_FORMAT;
    memset(q, 0, sizeof(q));
    q[0] = 4;
    memcpy(q + 1 + (flen - xl), xv, xl);
    memcpy(q + 1 + flen + (flen - yl), yv, yl);
    sd_wr_cstring(&bw, type);
    sd_wr_cstring(&bw, k_ec[k].curve);
    sd_wr_string(&bw, q, 1 + 2 * flen);
  } else {
    return SD_E_KEY_UNSUPPORTED;
  }
  if (!sd_wr_ok(&bw)) return SD_E_KEY_FORMAT;
  /* validate (RSA >= 1024 bits, EC point on the curve) */
  e = ssh_pubkey_parse(bw.p, bw.len, &pk);
  if (e != SD_OK) return SD_E_KEY_FORMAT;
  ssh_pubkey_free(&pk);
  if (!ssh_b64_encode(bw.p, bw.len, b64, sizeof(b64), 1)) return SD_E_KEY_FORMAT;
  sd_wr_bytes(w, lookup, strlen(lookup));
  sd_wr_u8(w, ' ');
  sd_wr_bytes(w, type, strlen(type));
  sd_wr_u8(w, ' ');
  sd_wr_bytes(w, b64, strlen(b64));
  sd_wr_u8(w, '\n');
  return sd_wr_ok(w) ? SD_OK : SD_E_NO_MEMORY;
}

static sd_err load_putty(const wchar_t *subkey, char **text, size_t *len, sd_kh_src_state *state, wchar_t *sid,
                         size_t cap, uint32_t *invalid)
{
  HKEY hk;
  DWORD sdlen = 0, nvals = 0, maxname = 0, maxdata = 0, i;
  PSECURITY_DESCRIPTOR sd;
  wchar_t *name, *data;
  sd_wr w;
  int secure;
  *state = SD_KH_SRC_ABSENT;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return SD_OK;
  *state = SD_KH_SRC_INSECURE;
  RegGetKeySecurity(hk, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, &sdlen);
  sd = sdlen ? (PSECURITY_DESCRIPTOR)sd_alloc(sdlen) : NULL;
  if (!sd || RegGetKeySecurity(hk, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sd, &sdlen) != ERROR_SUCCESS) {
    sd_free(sd);
    put_detail(sid, cap, NULL, L"[security unreadable]");
    RegCloseKey(hk);
    return SD_OK;
  }
  secure = ssh_kh_sd_secure(sd, KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_DAC | WRITE_OWNER, &k_key_map, sid, cap);
  sd_free(sd);
  if (!secure) { RegCloseKey(hk); return SD_OK; }
  if (RegQueryInfoKeyW(hk, NULL, NULL, NULL, NULL, NULL, NULL, &nvals, &maxname, &maxdata, NULL, NULL) != ERROR_SUCCESS) {
    RegCloseKey(hk);
    *state = SD_KH_SRC_ABSENT;
    return SD_OK;
  }
  name = (wchar_t *)sd_alloc(((size_t)maxname + 2) * sizeof(wchar_t));
  data = (wchar_t *)sd_alloc((size_t)maxdata + 4);
  if (!name || !data) { sd_free(name); sd_free(data); RegCloseKey(hk); return SD_E_NO_MEMORY; }
  sd_wr_init(&w, LIVE_MAX_FILE);
  for (i = 0; i < nvals && i < 100000u; i++) {
    DWORD nl = maxname + 1, dl = maxdata, type = 0;
    sd_err e;
    if (RegEnumValueW(hk, i, name, &nl, NULL, &type, (LPBYTE)data, &dl) != ERROR_SUCCESS) continue;
    if (type != REG_SZ) { if (invalid) (*invalid)++; continue; }
    name[nl] = L'\0';
    data[dl / sizeof(wchar_t)] = L'\0';
    e = ssh_putty_value_to_line(name, data, &w);
    if (e == SD_E_NO_MEMORY) break;
    if (e != SD_OK) {
      if (invalid) (*invalid)++;
      SD_LOGD("ssh", "PuTTY host key value %u skipped: %s", (unsigned)i, sd_err_name(e));
    }
  }
  sd_free(name);
  sd_free(data);
  RegCloseKey(hk);
  if (!sd_wr_ok(&w)) { sd_wr_free(&w); return SD_E_NO_MEMORY; }
  *text = (char *)sd_alloc(w.len + 1);
  if (!*text) { sd_wr_free(&w); return SD_E_NO_MEMORY; }
  if (w.len) memcpy(*text, w.p, w.len);
  (*text)[w.len] = '\0';
  *len = w.len;
  sd_wr_free(&w);
  *state = SD_KH_SRC_OK;
  return SD_OK;
}

sd_err ssh_kh_live_load(sd_kh_store_kind kind, const wchar_t *path, char **text, size_t *len,
                        sd_kh_src_state *state, wchar_t *detail_sid, size_t detail_cap, uint32_t *invalid)
{
  if (!text || !len || !state || !path) return SD_E_INVALID_PARAM;
  *text = NULL;
  *len = 0;
  if (detail_sid && detail_cap) detail_sid[0] = L'\0';
  if (kind == SD_KH_SRC_OPENSSH) return load_openssh(path, text, len, state, detail_sid, detail_cap);
  if (kind == SD_KH_SRC_PUTTY) return load_putty(path, text, len, state, detail_sid, detail_cap, invalid);
  return SD_E_INVALID_PARAM;
}
