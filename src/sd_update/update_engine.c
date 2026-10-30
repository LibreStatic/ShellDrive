/* sd_update engine (04 §9.1, §9.4, §9.6): check, stage, apply with rollback, cleanup.
 *
 * check:  load the trusted keyset (state first, compiled-in floor otherwise), fetch manifest.txt (and
 *         keyset.txt when the manifest names a newer keyset), verify the chain and the anti-rollback rules,
 *         record the accepted serial, the manifest bytes and last_verified, then compare the version and
 *         select the artifact. Nothing is installed here.
 * stage:  download the artifact from the manifest's bases (HTTPS first, then the HTTP mirror), enforce the
 *         manifest size and digest before the file is kept, in <staging>\<version>\.
 * apply:  setup mode runs the staged setup with /update /passive. File-swap mode replaces files in the
 *         install root, keeps the previous ones in install\.rollback\<old>\, runs --selftest and restores
 *         everything when the new binaries do not pass (04 §9.6).
 *
 * Every step logs an English event name under component "upd" (04 §13). */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_update/sd_update.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_ct.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_log.h"
#include "sd_base/sd_mem.h"
#include "update_internal.h"

#define UPD_TMP_SUFFIX  L".part"
#define UPD_IO_CHUNK    65536u

/* ---- names of the result ---- */

const char *sd_upd_res_name(sd_upd_res r)
{
  switch (r) {
  case SD_UPD_OK: return "ok";
  case SD_UPD_E_FORMAT: return "format";
  case SD_UPD_E_TOO_LARGE: return "too_large";
  case SD_UPD_E_PRODUCT: return "product_mismatch";
  case SD_UPD_E_FORMAT_VERSION: return "format_version_unknown";
  case SD_UPD_E_SIGNATURE: return "signature_invalid";
  case SD_UPD_E_UNKNOWN_KEY: return "key_unknown";
  case SD_UPD_E_KEY_EXPIRED: return "key_expired";
  case SD_UPD_E_KEY_REVOKED: return "key_revoked";
  case SD_UPD_E_KEYSET_SIGNATURE: return "keyset_signature_invalid";
  case SD_UPD_E_KEYSET_ROLLBACK: return "keyset_rollback";
  case SD_UPD_E_KEYSET_NEEDED: return "keyset_needed";
  case SD_UPD_E_CHANNEL_MISMATCH: return "channel_mismatch";
  case SD_UPD_E_EXPIRED: return "manifest_expired";
  case SD_UPD_E_FRESHNESS: return "manifest_too_long";
  case SD_UPD_E_ROLLBACK: return "serial_rollback";
  case SD_UPD_E_NO_TARGET: return "no_target";
  case SD_UPD_E_SIZE: return "size_mismatch";
  case SD_UPD_E_HASH: return "digest_mismatch";
  case SD_UPD_E_NETWORK: return "network";
  case SD_UPD_E_REDIRECT: return "redirect_refused";
  case SD_UPD_E_SELFTEST: return "selftest_failed";
  case SD_UPD_E_APPLY: return "apply_failed";
  case SD_UPD_E_DISABLED: return "disabled";
  case SD_UPD_E_STATE: return "state";
  case SD_UPD_E_IO: return "io";
  case SD_UPD_E_NO_MEMORY: return "no_memory";
  case SD_UPD_E_INVALID: return "invalid";
  }
  return "unknown";
}

const char *sd_upd_res_code(sd_upd_res r)
{
  switch (r) {
  case SD_UPD_OK: return "ok";
  case SD_UPD_E_NETWORK: case SD_UPD_E_REDIRECT: return "update_unavailable";
  case SD_UPD_E_NO_TARGET: return "update_no_target";
  case SD_UPD_E_SELFTEST: return "selftest_failed";
  case SD_UPD_E_APPLY: return "update_apply_failed";
  case SD_UPD_E_DISABLED: return "update_disabled";
  case SD_UPD_E_TOO_LARGE: case SD_UPD_E_SIZE: case SD_UPD_E_HASH: return "update_verify_failed";
  case SD_UPD_E_NO_MEMORY: return "no_memory";
  case SD_UPD_E_INVALID: return "usage";
  case SD_UPD_E_STATE: case SD_UPD_E_IO: return "update_apply_failed";
  default: return "update_verify_failed";
  }
}

/* ---- small helpers ---- */

static void ascii_to_wide(const char *in, wchar_t *out, size_t cap)
{
  size_t i;
  for (i = 0; i + 1 < cap && in[i]; i++)
    out[i] = (wchar_t)(unsigned char)in[i];
  out[i] = L'\0';
}

/* Creates every missing directory of a path (drive root and existing parts are fine). */
static void ensure_tree(const wchar_t *path)
{
  wchar_t tmp[MAX_PATH * 2];
  size_t i;
  tmp[0] = L'\0';
  if (!upd_wcpy(tmp, SD_COUNTOF(tmp), path))
    return;
  for (i = 1; i < SD_COUNTOF(tmp) && tmp[i] != L'\0'; i++) {
    if (tmp[i] == L'\\' || tmp[i] == L'/') {
      tmp[i] = L'\0';
      CreateDirectoryW(tmp, NULL);
      tmp[i] = L'\\';
    }
  }
  CreateDirectoryW(tmp, NULL);
}

static int join2(wchar_t *out, size_t cap, const wchar_t *a, const wchar_t *b)
{
  return upd_wcpy(out, cap, a) && upd_wcat(out, cap, L"\\") && upd_wcat(out, cap, b);
}

static int file_size_of(const wchar_t *path, uint64_t *size)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &sz)) {
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  *size = (uint64_t)sz.QuadPart;
  return 1;
}

/* Digest of a whole file with the manifest's algorithm. */
static sd_upd_res file_digest(const wchar_t *path, int alg, uint8_t *out)
{
  HANDLE h;
  uint8_t *buf;
  sd_hash_ctx c;
  sd_hash_alg ha = alg == 512 ? SD_HASH_SHA512 : SD_HASH_SHA256;
  sd_upd_res r = SD_UPD_OK;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_UPD_E_IO;
  buf = (uint8_t *)sd_alloc(UPD_IO_CHUNK);
  if (buf == NULL) {
    CloseHandle(h);
    return SD_UPD_E_NO_MEMORY;
  }
  sd_hash_init(&c, ha);
  for (;;) {
    DWORD got = 0;
    if (!ReadFile(h, buf, UPD_IO_CHUNK, &got, NULL)) {
      r = SD_UPD_E_IO;
      break;
    }
    if (got == 0)
      break;
    sd_hash_update(&c, buf, got);
  }
  sd_hash_final(&c, out);
  sd_free(buf);
  CloseHandle(h);
  return r;
}

/* Size and digest of path against the manifest entry (both or nothing is trusted). */
static sd_upd_res verify_file(const wchar_t *path, const sd_upd_file *f)
{
  uint64_t size = 0;
  uint8_t digest[64];
  sd_upd_res r;
  if (!file_size_of(path, &size))
    return SD_UPD_E_IO;
  if (size != f->size)
    return SD_UPD_E_SIZE;
  if ((r = file_digest(path, f->hash_alg, digest)) != SD_UPD_OK)
    return r;
  {
    size_t n = f->hash_alg == 512 ? 64 : 32;
    if (!sd_ct_memeq(digest, f->digest, n))
      return SD_UPD_E_HASH;
  }
  return SD_UPD_OK;
}

/* ---- flavour (04 §6.2) ---- */

typedef void (WINAPI *pfn_GetNativeSystemInfo)(LPSYSTEM_INFO);

/* The XP SDK does not define the newer architecture values; the numbers are the documented ones. */
#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif
#ifndef PROCESSOR_ARCHITECTURE_ARM
#define PROCESSOR_ARCHITECTURE_ARM 5
#endif

sd_upd_res sd_upd_detect_flavour(char *out, size_t cap)
{
  SYSTEM_INFO si;
  pfn_GetNativeSystemInfo fn;
  const sd_os_version *os;
  const char *name;
  if (out == NULL || cap < 16)
    return SD_UPD_E_INVALID;
  memset(&si, 0, sizeof(si));
  fn = (pfn_GetNativeSystemInfo)sd_platform_resolve_by_name(L"kernel32.dll", "GetNativeSystemInfo");
  if (fn)
    fn(&si);
  else
    GetSystemInfo(&si);
  os = sd_os_version_get();
  switch (si.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    name = (os->major == 5) ? "x64-xp" : "x64-modern";
    break;
  case PROCESSOR_ARCHITECTURE_ARM64:
#if defined(_M_ARM)
    /* An ARM32 build on an ARM64 host reports ARM64 here; it runs and updates as arm32 (04 §6.2). */
    name = "arm32";
#else
    name = "arm64";
#endif
    break;
  case PROCESSOR_ARCHITECTURE_ARM:
    name = "arm32";
    break;
  case PROCESSOR_ARCHITECTURE_INTEL:
    name = (sd_cpu_features() & SD_CPU_SSE2) ? "x86-sse2" : "x86-ia32";
    break;
  default:
    return SD_UPD_E_NO_TARGET;
  }
  strcpy_s(out, cap, name);
  return SD_UPD_OK;
}

static const char *arch_of(const char *flavour)
{
  if (strncmp(flavour, "x86-", 4) == 0) return "x86";
  if (strncmp(flavour, "x64-", 4) == 0) return "x64";
  return flavour;                              /* arm32, arm64 */
}

sd_upd_res sd_upd_select_file(const sd_upd_manifest *m, sd_upd_mode mode, const char *flavour, const sd_upd_file **out)
{
  char id[40];
  uint32_t i;
  const sd_upd_file *hit = NULL;
  const sd_upd_version *need = NULL;
  const sd_os_version *os;

  if (m == NULL || flavour == NULL || out == NULL)
    return SD_UPD_E_INVALID;
  *out = NULL;

  for (i = 0; i < m->nminos; i++) {
    if (strcmp(m->minos[i].flavour, flavour) == 0)
      need = &m->minos[i].version;
  }
  if (need) {
    os = sd_os_version_get();
    if (os->major < need->part[0] || (os->major == need->part[0] && os->minor < need->part[1]))
      return SD_UPD_E_NO_TARGET;
  }

  if (mode == SD_UPD_MODE_MSI)
    sprintf_s(id, sizeof(id), "msi-%s", flavour);
  else if (mode == SD_UPD_MODE_PORTABLE)
    sprintf_s(id, sizeof(id), "portable-%s", flavour);
  else
    sprintf_s(id, sizeof(id), "setup-universal");

  for (i = 0; i < m->nfiles && hit == NULL; i++) {
    if (strcmp(m->files[i].id, id) == 0)
      hit = &m->files[i];
  }
  if (hit == NULL && mode == SD_UPD_MODE_SETUP) {
    sprintf_s(id, sizeof(id), "setup-%s", arch_of(flavour));
    for (i = 0; i < m->nfiles && hit == NULL; i++) {
      if (strcmp(m->files[i].id, id) == 0)
        hit = &m->files[i];
    }
  }
  if (hit == NULL)
    return SD_UPD_E_NO_TARGET;
  *out = hit;
  return SD_UPD_OK;
}

/* ---- trust state ---- */

/* Roots blob: repeated [id 8 bytes][pub 32 bytes]. */
#define ROOT_REC 40u

static sd_upd_res read_roots(const sd_upd_state_dirs *st, sd_upd_root *roots, uint32_t *n, int *present)
{
  uint8_t *buf = NULL;
  size_t len = 0, i;
  sd_upd_res r;
  *present = 0;
  *n = 0;
  r = sd_upd_state_read_blob(st, L"roots", &buf, &len);
  if (r != SD_UPD_OK) {
    if (r == SD_UPD_E_STATE || r == SD_UPD_E_TOO_LARGE)
      return SD_UPD_OK;                        /* absent: the compiled-in roots apply */
    return r;
  }
  if (len == 0 || len % ROOT_REC != 0 || len / ROOT_REC > SD_UPD_MAX_ROOTS) {
    sd_free(buf);
    return SD_UPD_E_STATE;
  }
  for (i = 0; i < len / ROOT_REC; i++) {
    memcpy(roots[i].id, buf + i * ROOT_REC, 8);
    memcpy(roots[i].pub, buf + i * ROOT_REC + 8, 32);
  }
  *n = (uint32_t)(len / ROOT_REC);
  *present = 1;
  sd_free(buf);
  return SD_UPD_OK;
}

static sd_upd_res write_roots(const sd_upd_state_dirs *st, const sd_upd_root *roots, uint32_t n)
{
  uint8_t buf[SD_UPD_MAX_ROOTS * ROOT_REC];
  uint32_t i;
  for (i = 0; i < n; i++) {
    memcpy(buf + i * ROOT_REC, roots[i].id, 8);
    memcpy(buf + i * ROOT_REC + 8, roots[i].pub, 32);
  }
  return sd_upd_state_write_blob(st, L"roots", buf, n * ROOT_REC);
}

/* The keyset in effect: the stored one (with the roots it was accepted under) or the compiled-in floor,
   whichever has the higher version. Returns SD_UPD_E_KEYSET_SIGNATURE when nothing can be trusted. */
static sd_upd_res load_trust(const sd_upd_request *r, sd_upd_keyset *ks)
{
  sd_upd_root roots[SD_UPD_MAX_ROOTS];
  uint32_t nroots = 0, i;
  int have_roots = 0;
  sd_upd_res res;
  uint8_t *kb = NULL;
  size_t kl = 0;
  sd_upd_keyset stored, builtin;
  int have_stored = 0, have_builtin = 0;

  memset(ks, 0, sizeof(*ks));
  memset(&stored, 0, sizeof(stored));
  memset(&builtin, 0, sizeof(builtin));
  if ((res = read_roots(r->state, roots, &nroots, &have_roots)) != SD_UPD_OK)
    return res;
  if (!have_roots) {
    if (r->trust->nroots == 0 || r->trust->nroots > SD_UPD_MAX_ROOTS)
      return SD_UPD_E_KEYSET_SIGNATURE;
    nroots = r->trust->nroots;
    for (i = 0; i < nroots; i++)
      roots[i] = r->trust->roots[i];
  }

  if (sd_upd_state_read_blob(r->state, L"keyset", &kb, &kl) == SD_UPD_OK) {
    res = upd_keyset_load_stored(kb, kl, roots, nroots, &stored);
    sd_free(kb);
    kb = NULL;
    if (res != SD_UPD_OK)
      return res;
    have_stored = 1;
  }

  if (r->trust->keyset && r->trust->keyset_len) {
    res = sd_upd_keyset_verify(r->trust->keyset, r->trust->keyset_len, r->trust->roots, r->trust->nroots, 0, &builtin);
    if (res != SD_UPD_OK)
      return res;                              /* a broken compiled-in keyset is a build error: refuse */
    have_builtin = 1;
  }

  if (have_builtin && (!have_stored || builtin.version > stored.version)) {
    *ks = builtin;
    return SD_UPD_OK;
  }
  if (have_stored) {
    *ks = stored;
    for (i = 0; i < nroots; i++)
      ks->roots[i] = roots[i];
    ks->nroots = nroots;
    return SD_UPD_OK;
  }
  /* First run: no keyset yet. The roots are the trust anchor, version 0 makes the manifest's keyset
     "newer", and check fetches keyset.txt next to the manifest. */
  memset(ks, 0, sizeof(*ks));
  ks->nroots = nroots;
  for (i = 0; i < nroots; i++)
    ks->roots[i] = roots[i];
  return SD_UPD_OK;
}

/* https://host/path/manifest.txt -> https://host/path/keyset.txt */
static int sibling_url(const wchar_t *url, const wchar_t *name, wchar_t *out, size_t cap)
{
  size_t i, last = 0, n = wcslen(url);
  for (i = 0; i < n; i++) {
    if (url[i] == L'?')
      break;
    if (url[i] == L'/')
      last = i + 1;
  }
  if (last == 0 || last + wcslen(name) + 1 > cap)
    return 0;
  memcpy(out, url, last * sizeof(wchar_t));
  out[last] = L'\0';
  return upd_wcat(out, cap, name);
}

/* Downloads "<alt-or-primary>" manifest; reports which URL worked. */
static sd_upd_res fetch_manifest(const sd_upd_request *r, uint8_t **buf, size_t *len, const wchar_t **used)
{
  sd_upd_res res = r->tr->ops->get_mem(r->tr, r->manifest_url, SD_UPD_MANIFEST_MAX, buf, len);
  *used = r->manifest_url;
  if (res == SD_UPD_E_NETWORK && r->manifest_alt) {
    res = r->tr->ops->get_mem(r->tr, r->manifest_alt, SD_UPD_MANIFEST_MAX, buf, len);
    *used = r->manifest_alt;
  }
  return res;
}

/* ---- check ---- */

static void mark_stale(const sd_upd_request *r, sd_upd_offer *o)
{
  int64_t last = 0;
  if (sd_upd_state_read_verified(r->state, o->channel, &last) == SD_UPD_OK && last > 0 &&
      r->now - last > SD_UPD_STALE_SECONDS)
    o->stale = 1;
}

/* The manifest (about 12 KB) and the keyset live on the heap: check runs on the agent's pipe worker. */
typedef struct upd_check_ws {
  sd_upd_keyset ks;
  sd_upd_manifest m;
  wchar_t kurl[1024];
} upd_check_ws;

static sd_upd_res check_run(const sd_upd_request *r, sd_upd_offer *o, upd_check_ws *ws)
{
  sd_upd_version installed;
  uint8_t *mb = NULL, *old = NULL, *kb = NULL;
  size_t ml = 0, ol = 0, kl = 0;
  const wchar_t *used = NULL;
  uint64_t last_serial = 0;
  const sd_upd_file *file = NULL;
  sd_upd_res res;

  if (r == NULL || o == NULL || r->manifest_url == NULL || r->channel == NULL || r->installed_version == NULL ||
      r->flavour == NULL || r->tr == NULL || r->trust == NULL || r->state == NULL || r->state->user == NULL)
    return SD_UPD_E_INVALID;
  if (strcmp(r->channel, "stable") != 0 && strcmp(r->channel, "beta") != 0)
    return SD_UPD_E_INVALID;
  if (sd_upd_version_parse(r->installed_version, strlen(r->installed_version), &installed) != SD_UPD_OK)
    return SD_UPD_E_INVALID;

  memset(o, 0, sizeof(*o));
  strcpy_s(o->channel, sizeof(o->channel), r->channel);

  if ((res = load_trust(r, &ws->ks)) != SD_UPD_OK)
    return res;

  if ((res = fetch_manifest(r, &mb, &ml, &used)) != SD_UPD_OK) {
    mark_stale(r, o);
    SD_LOGW("upd", "update.check fetch failed: %s", sd_upd_res_name(res));
    return res;
  }
  res = sd_upd_manifest_parse(mb, ml, &ws->m);
  if (res != SD_UPD_OK)
    goto done;

  if (ws->m.keyset > ws->ks.version) {
    /* The manifest names a newer keyset: fetch, verify with the current roots, store (TM-R37). */
    if (!sibling_url(used, L"keyset.txt", ws->kurl, SD_COUNTOF(ws->kurl))) {
      res = SD_UPD_E_FORMAT;
      goto done;
    }
    if ((res = r->tr->ops->get_mem(r->tr, ws->kurl, SD_UPD_KEYSET_MAX, &kb, &kl)) != SD_UPD_OK)
      goto done;
    {
      sd_upd_keyset nks;
      res = sd_upd_keyset_verify(kb, kl, ws->ks.roots, ws->ks.nroots, ws->ks.version, &nks);
      if (res != SD_UPD_OK)
        goto done;
      if (sd_upd_state_write_blob(r->state, L"keyset", kb, kl) != SD_UPD_OK) {
        res = SD_UPD_E_STATE;
        goto done;
      }
      if (nks.rotated_roots && write_roots(r->state, nks.roots, nks.nroots) != SD_UPD_OK) {
        res = SD_UPD_E_STATE;
        goto done;
      }
      ws->ks = nks;
      SD_LOGI("upd", "update.keyset_updated version=%llu", (unsigned long long)ws->ks.version);
    }
  }

  res = sd_upd_state_read_serial(r->state, r->channel, &last_serial);
  if (res != SD_UPD_OK)
    goto done;
  res = sd_upd_manifest_verify(mb, ml, &ws->m, &ws->ks, r->channel, r->now, last_serial);
  if (res != SD_UPD_OK)
    goto done;

  /* Same serial: only the identical bytes are accepted (a re-signed manifest needs a new serial). */
  if (ws->m.serial == last_serial && last_serial != 0) {
    if (sd_upd_state_read_manifest(r->state, r->channel, &old, &ol) == SD_UPD_OK &&
        (ol != ml || !sd_ct_memeq(old, mb, ml))) {
      res = SD_UPD_E_ROLLBACK;
      goto done;
    }
  }
  if (ws->m.serial > last_serial && (res = sd_upd_state_write_serial(r->state, r->channel, ws->m.serial)) != SD_UPD_OK)
    goto done;
  if ((res = sd_upd_state_write_manifest(r->state, r->channel, mb, ml)) != SD_UPD_OK)
    goto done;
  if ((res = sd_upd_state_write_verified(r->state, r->channel, r->now)) != SD_UPD_OK)
    goto done;

  o->manifest = ws->m;
  o->serial = ws->m.serial;
  o->released = ws->m.released;
  o->expires = ws->m.expires;
  strcpy_s(o->version, sizeof(o->version), ws->m.version_str);
  strcpy_s(o->notes, sizeof(o->notes), ws->m.notes);

  if (sd_upd_version_cmp(&ws->m.version, &installed) > 0) {
    res = sd_upd_select_file(&ws->m, r->mode, r->flavour, &file);
    if (res != SD_UPD_OK)
      goto done;
    o->available = 1;
    o->file = *file;
    strcpy_s(o->file_id, sizeof(o->file_id), file->id);
    strcpy_s(o->file_name, sizeof(o->file_name), file->name);
    o->size = file->size;
    SD_LOGI("upd", "update.available version=%s serial=%llu channel=%s", o->version,
            (unsigned long long)ws->m.serial, o->channel);
  } else {
    SD_LOGD("upd", "update.check up to date version=%s", o->version);
  }
  res = SD_UPD_OK;

done:
  if (res != SD_UPD_OK)
    SD_LOGW("upd", "update.verify_failed %s", sd_upd_res_name(res));
  sd_free(mb);
  sd_free(old);
  sd_free(kb);
  return res;
}

sd_upd_res sd_upd_check(const sd_upd_request *r, sd_upd_offer *o)
{
  upd_check_ws *ws;
  sd_upd_res res;
  if (r == NULL || o == NULL)
    return SD_UPD_E_INVALID;
  ws = (upd_check_ws *)sd_calloc(1, sizeof(*ws));
  if (ws == NULL)
    return SD_UPD_E_NO_MEMORY;
  res = check_run(r, o, ws);
  sd_free(ws);
  return res;
}

/* ---- stage ---- */

static void allow_hosts(sd_upd_transport *t, const sd_upd_manifest *m)
{
  uint32_t i;
  t->nallow = 0;
  for (i = 0; i < m->nbases && t->nallow < SD_UPD_MAX_BASES; i++) {
    const char *p = strstr(m->bases[i], "://");
    const char *q;
    size_t n;
    if (p == NULL)
      continue;
    p += 3;
    q = p;
    while (*q && *q != '/' && *q != ':')
      q++;
    n = (size_t)(q - p);
    if (n == 0 || n >= 128)
      continue;
    ascii_to_wide(p, t->allow[t->nallow], n + 1);
    t->allow[t->nallow][n] = L'\0';
    t->nallow++;
  }
}

sd_upd_res sd_upd_stage(const sd_upd_request *r, const sd_upd_offer *o, wchar_t *staged, size_t cap)
{
  wchar_t ver[64], fname[128], dir[MAX_PATH * 2], path[MAX_PATH * 2], part[MAX_PATH * 2], url[2048], base[512];
  uint32_t i;
  sd_upd_res res = SD_UPD_E_NETWORK;

  if (r == NULL || o == NULL || !o->available || r->paths == NULL || r->paths->staging == NULL || staged == NULL)
    return SD_UPD_E_INVALID;
  if (cap < MAX_PATH)
    return SD_UPD_E_INVALID;
  ascii_to_wide(o->version, ver, SD_COUNTOF(ver));
  ascii_to_wide(o->file_name, fname, SD_COUNTOF(fname));
  if (!join2(dir, SD_COUNTOF(dir), r->paths->staging, ver) || !join2(path, SD_COUNTOF(path), dir, fname))
    return SD_UPD_E_INVALID;
  ensure_tree(dir);
  if (!upd_wcpy(part, SD_COUNTOF(part), path) || !upd_wcat(part, SD_COUNTOF(part), UPD_TMP_SUFFIX))
    return SD_UPD_E_INVALID;

  /* A complete earlier download of the same artifact is reused. */
  if (verify_file(path, &o->file) == SD_UPD_OK) {
    if (!upd_wcpy(staged, cap, path))
      return SD_UPD_E_INVALID;
    return SD_UPD_OK;
  }
  DeleteFileW(part);

  allow_hosts(r->tr, &o->manifest);
  for (i = 0; i < o->manifest.nbases; i++) {
    sd_upd_res dl;
    ascii_to_wide(o->manifest.bases[i], base, SD_COUNTOF(base));
    if (!upd_wcpy(url, SD_COUNTOF(url), base))
      continue;
    if (wcslen(url) == 0 || url[wcslen(url) - 1] != L'/')
      upd_wcat(url, SD_COUNTOF(url), L"/");
    if (!upd_wcat(url, SD_COUNTOF(url), fname))
      continue;
    dl = r->tr->ops->get_file(r->tr, url, o->file.size, part);
    if (dl == SD_UPD_OK) {
      dl = verify_file(part, &o->file);
      if (dl == SD_UPD_OK && !MoveFileExW(part, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        dl = SD_UPD_E_IO;
      if (dl == SD_UPD_OK) {
        if (!upd_wcpy(staged, cap, path))
          return SD_UPD_E_INVALID;
        SD_LOGI("upd", "update.staged file=%s size=%llu", o->file_id, (unsigned long long)o->size);
        return SD_UPD_OK;
      }
      DeleteFileW(part);
      res = dl;                                /* wrong size or digest: never use it, try the next base */
      SD_LOGW("upd", "update.verify_failed artifact %s", sd_upd_res_name(dl));
      continue;
    }
    DeleteFileW(part);
    res = dl;
    if (dl == SD_UPD_E_TOO_LARGE)
      return SD_UPD_E_SIZE;                    /* more than the manifest says: refuse, do not retry */
    if (dl != SD_UPD_E_NETWORK && dl != SD_UPD_E_REDIRECT)
      return dl;
  }
  return res;
}

/* ---- process helper ---- */

static sd_upd_res run_process(const wchar_t *exe, const wchar_t *args, uint32_t timeout_ms, DWORD *code)
{
  wchar_t cmd[2048];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD w;
  *code = (DWORD)-1;
  if (wcslen(exe) + wcslen(args) + 8 > SD_COUNTOF(cmd))
    return SD_UPD_E_INVALID;
  upd_wcpy(cmd, SD_COUNTOF(cmd), L"\"");
  upd_wcat(cmd, SD_COUNTOF(cmd), exe);
  upd_wcat(cmd, SD_COUNTOF(cmd), L"\" ");
  upd_wcat(cmd, SD_COUNTOF(cmd), args);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    return SD_UPD_E_APPLY;
  w = WaitForSingleObject(pi.hProcess, timeout_ms);
  if (w != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return SD_UPD_E_SELFTEST;
  }
  GetExitCodeProcess(pi.hProcess, code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return SD_UPD_OK;
}

sd_upd_res sd_upd_apply_setup(const wchar_t *staged_exe, uint32_t timeout_ms)
{
  DWORD code = (DWORD)-1;
  sd_upd_res r;
  if (staged_exe == NULL)
    return SD_UPD_E_INVALID;
  r = run_process(staged_exe, L"/update /passive", timeout_ms, &code);
  if (r != SD_UPD_OK)
    return r;
  if (code != 0) {
    SD_LOGE("upd", "update.apply_failed setup exit=%u", (unsigned)code);
    return SD_UPD_E_APPLY;
  }
  SD_LOGI("upd", "update.applied via setup");
  return SD_UPD_OK;
}

/* ---- file-swap apply with rollback (04 §9.6) ---- */

typedef struct upd_swap {
  wchar_t target[MAX_PATH * 2];
  wchar_t backup[MAX_PATH * 2];
  int had_old;                                /* backup copy exists */
  int placed;                                 /* new file moved in */
} upd_swap;

static void restore_all(upd_swap *sw, uint32_t n)
{
  uint32_t i;
  for (i = n; i-- > 0;) {
    if (sw[i].placed) {
      if (sw[i].had_old)
        MoveFileExW(sw[i].backup, sw[i].target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
      else
        DeleteFileW(sw[i].target);
    }
  }
}

sd_upd_res sd_upd_apply_files(const sd_upd_request *r, const wchar_t *payload, const wchar_t *const *names,
                              uint32_t count, const char *old_version, const char *new_version, uint32_t selftest_ms)
{
  upd_swap *sw;
  wchar_t rb[MAX_PATH * 2], ver[64], self[MAX_PATH * 2];
  uint32_t i;
  sd_upd_res res = SD_UPD_OK;
  DWORD code = (DWORD)-1;
  SD_UNUSED(new_version);

  if (r == NULL || r->paths == NULL || r->paths->install == NULL || payload == NULL || names == NULL ||
      count == 0 || count > SD_UPD_MAX_FILES || old_version == NULL)
    return SD_UPD_E_INVALID;
  sw = (upd_swap *)sd_calloc(count, sizeof(upd_swap));
  if (sw == NULL)
    return SD_UPD_E_NO_MEMORY;

  ascii_to_wide(old_version, ver, SD_COUNTOF(ver));
  {
    wchar_t rbroot[MAX_PATH * 2];
    if (!join2(rbroot, SD_COUNTOF(rbroot), r->paths->install, L".rollback") ||
        !join2(rb, SD_COUNTOF(rb), rbroot, ver))
      res = SD_UPD_E_INVALID;
  }
  if (res == SD_UPD_OK)
    ensure_tree(rb);

  /* Phase 1: keep the previous files, then move each new file over its name. */
  for (i = 0; res == SD_UPD_OK && i < count; i++) {
    wchar_t src[MAX_PATH * 2], staging_name[MAX_PATH * 2];
    DWORD attr;
    if (!join2(sw[i].target, SD_COUNTOF(sw[i].target), r->paths->install, names[i]) ||
        !join2(sw[i].backup, SD_COUNTOF(sw[i].backup), rb, names[i]) ||
        !join2(src, SD_COUNTOF(src), payload, names[i]) ||
        !upd_wcpy(staging_name, SD_COUNTOF(staging_name), sw[i].target) ||
        !upd_wcat(staging_name, SD_COUNTOF(staging_name), L".sd-new")) {
      res = SD_UPD_E_INVALID;
      break;
    }
    attr = GetFileAttributesW(sw[i].target);
    if (attr != INVALID_FILE_ATTRIBUTES) {
      if (!CopyFileW(sw[i].target, sw[i].backup, FALSE)) {
        res = SD_UPD_E_APPLY;
        break;
      }
      sw[i].had_old = 1;
    }
    if (!CopyFileW(src, staging_name, FALSE)) {
      res = SD_UPD_E_APPLY;
      break;
    }
    if (!MoveFileExW(staging_name, sw[i].target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      DeleteFileW(staging_name);
      res = SD_UPD_E_APPLY;                     /* a file in use cannot be replaced: the setup path does that */
      break;
    }
    sw[i].placed = 1;
  }

  /* Phase 2: the new binaries must pass --selftest (exit 0). */
  if (res == SD_UPD_OK) {
    if (r->paths->selftest_exe == NULL || !join2(self, SD_COUNTOF(self), r->paths->install, r->paths->selftest_exe)) {
      res = SD_UPD_E_INVALID;
    } else {
      sd_upd_res pr = run_process(self, L"--selftest", selftest_ms, &code);
      if (pr != SD_UPD_OK || code != 0) {
        SD_LOGE("upd", "update.rolled_back selftest exit=%u", (unsigned)code);
        res = SD_UPD_E_SELFTEST;
      }
    }
  }

  if (res != SD_UPD_OK) {
    restore_all(sw, count);
    SD_LOGE("upd", "update.rolled_back %s", sd_upd_res_name(res));
  } else {
    SD_LOGI("upd", "update.applied version=%s files=%u", new_version ? new_version : "?", (unsigned)count);
  }
  sd_free(sw);
  return res;
}

/* ---- cleanup (04 §9.6) ---- */

void sd_upd_cleanup_staging(const wchar_t *staging, const char *keep_version)
{
  wchar_t pattern[MAX_PATH * 2], keep[64];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  if (staging == NULL)
    return;
  if (!upd_wcpy(pattern, SD_COUNTOF(pattern), staging) || !upd_wcat(pattern, SD_COUNTOF(pattern), L"\\*"))
    return;
  if (keep_version)
    ascii_to_wide(keep_version, keep, SD_COUNTOF(keep));
  else
    keep[0] = L'\0';
  h = FindFirstFileW(pattern, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return;
  do {
    wchar_t dir[MAX_PATH * 2], file[MAX_PATH * 2], inner[MAX_PATH * 2];
    WIN32_FIND_DATAW fi;
    HANDLE hi;
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (keep[0] && wcscmp(fd.cFileName, keep) == 0)
      continue;
    if (!join2(dir, SD_COUNTOF(dir), staging, fd.cFileName) || !upd_wcpy(inner, SD_COUNTOF(inner), dir) ||
        !upd_wcat(inner, SD_COUNTOF(inner), L"\\*"))
      continue;
    hi = FindFirstFileW(inner, &fi);
    if (hi != INVALID_HANDLE_VALUE) {
      do {
        if (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
          continue;
        if (join2(file, SD_COUNTOF(file), dir, fi.cFileName))
          DeleteFileW(file);
      } while (FindNextFileW(hi, &fi));
      FindClose(hi);
    }
    RemoveDirectoryW(dir);
  } while (FindNextFileW(h, &fd));
  FindClose(h);
}
