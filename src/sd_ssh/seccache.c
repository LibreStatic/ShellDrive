/* Reconnect secret cache (01 §7.4, §8; review C20; TM-R05).
 *
 * sd_ssh is the only owner of cached secrets. Each entry is kept encrypted in process memory:
 * CryptProtectMemory(SAME_PROCESS) on Vista+ (crypt32, resolved at run time), RtlEncryptMemory
 * (advapi32 SystemFunction040, same-process option) on XP. When neither primitive is available the
 * cache refuses to store anything, so secrets are never kept in plain memory for reconnects.
 * Plain copies exist only transiently in sd_secbuf buffers handed to the auth code. I/O thread only. */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"
#include "conn_internal.h"

#define SC_BLOCK 16u                    /* CRYPTPROTECTMEMORY_BLOCK_SIZE / RTL_ENCRYPT_MEMORY_SIZE */
#define SC_MAX   (64u * 1024u)

typedef BOOLEAN (WINAPI *sc_rtl_crypt_fn)(PVOID mem, ULONG len, ULONG flags);

typedef struct sc_api {
  sd_pfn_CryptProtectMemory protect;
  sd_pfn_CryptUnprotectMemory unprotect;
  sc_rtl_crypt_fn rtl_enc, rtl_dec;
} sc_api;

static sd_once g_sc_once = SD_ONCE_INIT;
static sc_api g_sc;

static void sc_init(void *arg)
{
  SD_UNUSED(arg);
  g_sc.protect = (sd_pfn_CryptProtectMemory)sd_platform_resolve(SD_API_CryptProtectMemory);
  g_sc.unprotect = (sd_pfn_CryptUnprotectMemory)sd_platform_resolve(SD_API_CryptUnprotectMemory);
  if (!g_sc.protect || !g_sc.unprotect) {
    g_sc.protect = NULL;
    g_sc.unprotect = NULL;
    g_sc.rtl_enc = (sc_rtl_crypt_fn)sd_platform_resolve_by_name(L"advapi32.dll", "SystemFunction040");
    g_sc.rtl_dec = (sc_rtl_crypt_fn)sd_platform_resolve_by_name(L"advapi32.dll", "SystemFunction041");
    if (!g_sc.rtl_enc || !g_sc.rtl_dec) { g_sc.rtl_enc = NULL; g_sc.rtl_dec = NULL; }
  }
}

static const sc_api *sc(void)
{
  sd_once_run(&g_sc_once, sc_init, NULL);
  return &g_sc;
}

int ssh_secret_cache_available(void)
{
  const sc_api *a = sc();
  return a->protect != NULL || a->rtl_enc != NULL;
}

static int sc_crypt(uint8_t *p, size_t n, int enc)
{
  const sc_api *a = sc();
  if (a->protect) return enc ? a->protect(p, (DWORD)n, 0) != FALSE : a->unprotect(p, (DWORD)n, 0) != FALSE;
  if (a->rtl_enc) return enc ? a->rtl_enc(p, (ULONG)n, 0) != FALSE : a->rtl_dec(p, (ULONG)n, 0) != FALSE;
  return 0;
}

void ssh_secret_clear(ssh_secret *s)
{
  if (s->blob) sd_secure_free(s->blob, s->cap);
  s->blob = NULL;
  s->cap = s->len = 0;
}

sd_err ssh_secret_store(ssh_secret *s, const uint8_t *p, size_t n)
{
  size_t cap;
  uint8_t *b;
  ssh_secret_clear(s);
  if (n == 0 || n > SC_MAX) return SD_E_INVALID_PARAM;
  if (!ssh_secret_cache_available()) return SD_E_UNSUPPORTED;
  cap = (n + SC_BLOCK - 1) / SC_BLOCK * SC_BLOCK;
  b = (uint8_t *)sd_calloc(1, cap);
  if (!b) return SD_E_NO_MEMORY;
  memcpy(b, p, n);
  if (!sc_crypt(b, cap, 1)) { sd_secure_free(b, cap); return SD_E_INTERNAL; }
  s->blob = b;
  s->cap = cap;
  s->len = n;
  return SD_OK;
}

sd_err ssh_secret_load(const ssh_secret *s, sd_secbuf **out)
{
  sd_secbuf *b;
  sd_err e;
  *out = NULL;
  if (!s->blob) return SD_E_NOT_FOUND;
  e = sd_secbuf_new(s->cap, &b);
  if (e != SD_OK) return e;
  memcpy(b->p, s->blob, s->cap);
  if (!sc_crypt(b->p, s->cap, 0)) { sd_secbuf_free(b); return SD_E_INTERNAL; }
  sd_secure_zero(b->p + s->len, s->cap - s->len);
  b->len = s->len;
  *out = b;
  return SD_OK;
}

void ssh_seccache_init(ssh_seccache *sc_, uint32_t identities)
{
  memset(sc_, 0, sizeof(*sc_));
  if (identities) {
    sc_->pass = (ssh_secret *)sd_calloc(identities, sizeof(ssh_secret));
    if (sc_->pass) sc_->npass = identities;
  }
}

void ssh_seccache_clear(ssh_seccache *sc_)
{
  uint32_t i;
  ssh_secret_clear(&sc_->password);
  for (i = 0; i < sc_->npass; i++) ssh_secret_clear(&sc_->pass[i]);
}

void ssh_seccache_free(ssh_seccache *sc_)
{
  ssh_seccache_clear(sc_);
  sd_free(sc_->pass);
  sc_->pass = NULL;
  sc_->npass = 0;
}

int ssh_cache_usable(const sd_ssh_conn *c)
{
  return c->cache_secrets && !c->hostkey_just_accepted;
}
