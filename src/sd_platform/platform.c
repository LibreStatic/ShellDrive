#include <windows.h>
#include <intrin.h>

#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"

typedef struct api_entry { const wchar_t *dll; const char *fn; } api_entry;

#define SD_API_ENTRY_(name, dll, fn) { dll, fn },
static const api_entry g_api[SD_API_COUNT] = { SD_API_LIST(SD_API_ENTRY_) };
#undef SD_API_ENTRY_

/* Per-entry cache: g_api_state 0 = not resolved yet, 1 = resolved (pointer may be NULL). */
static void *volatile g_api_ptr[SD_API_COUNT];
static volatile LONG g_api_state[SD_API_COUNT];

static sd_once g_init_once = SD_ONCE_INIT;
static sd_os_version g_os;
static uint32_t g_cpu_detected;
static uint32_t g_cpu_env_mask = 0xFFFFFFFFu;
static volatile LONG g_cpu_test_mask = (LONG)0xFFFFFFFF;

HMODULE sd_platform_load_system_dll(const wchar_t *dll)
{
  wchar_t path[MAX_PATH + 64];
  UINT n;
  size_t i, dlen = wcslen(dll);
  HMODULE m;

  /* kernel32 and ntdll are mapped into every process; no load needed. */
  if (_wcsicmp(dll, L"kernel32.dll") == 0 || _wcsicmp(dll, L"ntdll.dll") == 0)
    return GetModuleHandleW(dll);

  n = GetSystemDirectoryW(path, MAX_PATH);
  if (n == 0 || n >= MAX_PATH || dlen > 60)
    return NULL;
  path[n++] = L'\\';
  for (i = 0; i <= dlen; i++)
    path[n + i] = dll[i];
  /* Full path, and dependencies searched from System32 too (XP-compatible flag). */
  m = GetModuleHandleW(path);
  if (m == NULL)
    m = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
  return m;
}

void *sd_platform_resolve_by_name(const wchar_t *dll, const char *function)
{
  HMODULE m = sd_platform_load_system_dll(dll);
  return m ? (void *)GetProcAddress(m, function) : NULL;
}

void *sd_platform_resolve(sd_api_id id)
{
  void *p;
  if ((unsigned)id >= (unsigned)SD_API_COUNT)
    return NULL;
  if (InterlockedCompareExchange(&g_api_state[id], 1, 1) == 1)
    return g_api_ptr[id];
  p = sd_platform_resolve_by_name(g_api[id].dll, g_api[id].fn);
  /* Benign race: concurrent resolvers store the same pointer. */
  g_api_ptr[id] = p;
  InterlockedExchange(&g_api_state[id], 1);
  return p;
}

void sd_platform_harden_dll_search(void)
{
  sd_pfn_SetDefaultDllDirectories set_default =
      (sd_pfn_SetDefaultDllDirectories)sd_platform_resolve(SD_API_SetDefaultDllDirectories);
  sd_pfn_SetDllDirectoryW set_dir;
  if (set_default && set_default(LOAD_LIBRARY_SEARCH_SYSTEM32))
    return;
  set_dir = (sd_pfn_SetDllDirectoryW)sd_platform_resolve(SD_API_SetDllDirectoryW);
  if (set_dir)
    set_dir(L"");                               /* removes the current directory from the search */
}

static void detect_os(void)
{
  OSVERSIONINFOEXW vi;
  sd_pfn_RtlGetVersion rtl = (sd_pfn_RtlGetVersion)sd_platform_resolve(SD_API_RtlGetVersion);
  ZeroMemory(&vi, sizeof(vi));
  vi.dwOSVersionInfoSize = sizeof(vi);
  if (rtl == NULL || rtl((OSVERSIONINFOW *)&vi) != 0)
    return;                                     /* RtlGetVersion exists since Windows 2000 */
  g_os.major = vi.dwMajorVersion;
  g_os.minor = vi.dwMinorVersion;
  g_os.build = vi.dwBuildNumber;
  g_os.sp_major = vi.wServicePackMajor;
  g_os.product_type = vi.wProductType;
}

static void detect_cpu(void)
{
  uint32_t f = 0;
  wchar_t env[32];
  DWORD n;

#if defined(_M_IX86) && defined(SD_X86_ARCH_IA32)
  /* x86-ia32: no run-time detection and no vector code at all (01 §2.3); sd-isacheck rejects even the
     guarded XGETBV below in this flavour. */
#elif defined(_M_X64) || defined(_M_IX86)
  {
    int r[4];
    uint32_t max_leaf;
    __cpuid(r, 0);
    max_leaf = (uint32_t)r[0];
    if (max_leaf >= 1) {
      __cpuid(r, 1);
      if (r[3] & (1 << 26)) f |= SD_CPU_SSE2;
      if (r[2] & (1 << 9))  f |= SD_CPU_SSSE3;
      if (r[2] & (1 << 25)) f |= SD_CPU_AESNI;
      if (r[2] & (1 << 1))  f |= SD_CPU_PCLMUL;
      if (max_leaf >= 7) {
        int osxsave = (r[2] & (1 << 27)) != 0;
        __cpuidex(r, 7, 0);
        if (r[1] & (1 << 29)) f |= SD_CPU_SHANI;
        /* AVX2 needs OS support for YMM state (XGETBV); XP never enables it. */
        if (osxsave && (r[1] & (1 << 5)) && (_xgetbv(0) & 6) == 6) f |= SD_CPU_AVX2;
      }
    }
  }
#elif defined(_M_ARM64)
  f |= SD_CPU_NEON;
  if (IsProcessorFeaturePresent(30 /* PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE */))
    f |= SD_CPU_ARMV8_CRYPTO;
#elif defined(_M_ARM)
  f |= SD_CPU_NEON;
#endif
  g_cpu_detected = f;

  n = GetEnvironmentVariableW(L"SD_CPU_MASK", env, SD_COUNTOF(env));
  if (n > 0 && n < SD_COUNTOF(env)) {
    uint32_t mask = 0;
    DWORD i;
    for (i = 0; i < n; i++) {
      wchar_t c = env[i];
      uint32_t d;
      if (c >= L'0' && c <= L'9') d = (uint32_t)(c - L'0');
      else if (c >= L'a' && c <= L'f') d = (uint32_t)(c - L'a' + 10);
      else if (c >= L'A' && c <= L'F') d = (uint32_t)(c - L'A' + 10);
      else if ((c == L'x' || c == L'X') && i == 1 && env[0] == L'0') continue;
      else break;
      mask = (mask << 4) | d;
    }
    g_cpu_env_mask = mask;
  }
}

static void platform_init_once(void *arg)
{
  SD_UNUSED(arg);
  detect_os();
  detect_cpu();
}

sd_err sd_platform_init(void)
{
  sd_once_run(&g_init_once, platform_init_once, NULL);
  return g_os.major != 0 ? SD_OK : SD_E_INTERNAL;
}

const sd_os_version *sd_os_version_get(void)
{
  sd_platform_init();
  return &g_os;
}

int sd_os_at_least(uint32_t major, uint32_t minor, uint32_t build)
{
  const sd_os_version *v = sd_os_version_get();
  if (v->major != major)
    return v->major > major;
  if (v->minor != minor)
    return v->minor > minor;
  return v->build >= build;
}

uint32_t sd_cpu_features(void)
{
  sd_platform_init();
  return g_cpu_detected & g_cpu_env_mask & (uint32_t)g_cpu_test_mask;
}

void sd_cpu_set_mask(uint32_t mask)
{
  InterlockedExchange(&g_cpu_test_mask, (LONG)mask);
}
