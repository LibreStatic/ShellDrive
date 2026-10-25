/* sd_crypto_init, capabilities and the OS RNG (01 §2.2 "CSPRNG", §2.3).
 *
 * RNG: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG (Win7+), else with an opened
 * BCRYPT_RNG_ALGORITHM handle (Vista), else RtlGenRandom (advapi32 SystemFunction036, XP). No
 * user-space DRBG and no buffering here: every call goes to the OS. A failure is reported, never
 * papered over. */
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"

#include "crypto_internal.h"

static sd_once g_once = SD_ONCE_INIT;
static uint32_t g_flags;
static sd_crypto_caps g_caps;
static sd_bcrypt_handle g_rng_alg;          /* Vista fallback handle, NULL otherwise */
static int g_rng_preferred;                 /* system-preferred RNG works */
static volatile LONG g_force_own;           /* test hook */

static void probe_rng(void)
{
  sd_pfn_BCryptGenRandom gen = (sd_pfn_BCryptGenRandom)sd_platform_resolve(SD_API_BCryptGenRandom);
  sd_pfn_BCryptOpenAlgorithmProvider open_alg =
    (sd_pfn_BCryptOpenAlgorithmProvider)sd_platform_resolve(SD_API_BCryptOpenAlgorithmProvider);
  UCHAR probe[16];
  if (gen == NULL)
    return;
  if (gen(NULL, probe, sizeof(probe), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
    g_rng_preferred = 1;
  } else if (open_alg != NULL) {
    sd_bcrypt_handle h = NULL;
    if (open_alg(&h, L"RNG", NULL, 0) == 0)
      g_rng_alg = h;
  }
  SecureZeroMemory(probe, sizeof(probe));
}

static void init_once(void *arg)
{
  uint32_t flags = *(const uint32_t *)arg;
  g_flags = flags;
  sd_platform_init();
  g_caps.cpu = sd_cpu_features();
  g_caps.os = 0;
  if (!(flags & SD_CRYPTO_INIT_OWN_ONLY))
    sd_cng_probe(&g_caps.os);
  probe_rng();
}

sd_err sd_crypto_init(uint32_t flags)
{
  sd_once_run(&g_once, init_once, &flags);
  return SD_OK;
}

uint32_t sd_crypto_ensure_init(void)
{
  uint32_t flags = 0;
  sd_once_run(&g_once, init_once, &flags);
  return g_flags;
}

const sd_crypto_caps *sd_crypto_caps_get(void)
{
  sd_crypto_ensure_init();
  return &g_caps;
}

int sd_crypto_use_cng_aes(void)
{
  sd_crypto_ensure_init();
  return (g_caps.os & SD_OS_CNG) != 0 && g_force_own == 0;
}

int sd_crypto_use_cng_gcm(void)
{
  sd_crypto_ensure_init();
  return (g_caps.os & SD_OS_CNG_GCM) != 0 && g_force_own == 0;
}

void sd_crypto_test_force_own(int on)
{
  InterlockedExchange(&g_force_own, on ? 1 : 0);
}

sd_err sd_random(void *buf, size_t len)
{
  uint8_t *p = (uint8_t *)buf;
  sd_crypto_ensure_init();
  while (len) {
    ULONG chunk = len > 0x10000000u ? 0x10000000u : (ULONG)len;
    int ok = 0;
    if (g_rng_preferred || g_rng_alg) {
      sd_pfn_BCryptGenRandom gen = (sd_pfn_BCryptGenRandom)sd_platform_resolve(SD_API_BCryptGenRandom);
      ok = gen != NULL &&
           gen(g_rng_alg, p, chunk, g_rng_preferred ? BCRYPT_USE_SYSTEM_PREFERRED_RNG : 0) == 0;
    } else {
      sd_pfn_RtlGenRandom rtl = (sd_pfn_RtlGenRandom)sd_platform_resolve(SD_API_RtlGenRandom);
      ok = rtl != NULL && rtl(p, chunk) != 0;
    }
    if (!ok)
      return SD_E_CRYPTO;
    p += chunk;
    len -= chunk;
  }
  return SD_OK;
}
