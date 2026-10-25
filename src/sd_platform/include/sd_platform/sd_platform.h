/* sd_platform: the Win32 layer under every module (00 §5, C39).
 *
 * - sd_platform_resolve(): post-XP APIs by GetProcAddress with a cached table (04 §2.4). DLLs that are
 *   not always loaded are loaded by full System32 path, never via the search path (01 §1).
 * - OS version via RtlGetVersion (not lied to by compatibility shims).
 * - CPU feature hooks for sd_crypto dispatch (01 §2.3).
 *
 * Thread safety: everything here is thread-safe. sd_platform_init() is idempotent and is also run
 * lazily by the functions that need it; call it early in main() anyway so failures surface there. */
#ifndef SD_PLATFORM_H
#define SD_PLATFORM_H

#include <windows.h>

#include "sd/base.h"
#include "sd/winapi_compat.h"
#include "sd_base/sd_err.h"

sd_err sd_platform_init(void);

/* ---- run-time API resolution ---- */

#define SD_API_LIST(X)                                                   \
  X(GetTickCount64,              L"kernel32.dll", "GetTickCount64")      \
  X(SetDefaultDllDirectories,    L"kernel32.dll", "SetDefaultDllDirectories") \
  X(SetDllDirectoryW,            L"kernel32.dll", "SetDllDirectoryW")    \
  X(SetThreadDescription,        L"kernel32.dll", "SetThreadDescription") \
  X(IsWow64Process,              L"kernel32.dll", "IsWow64Process")      \
  X(GetProductInfo,              L"kernel32.dll", "GetProductInfo")      \
  X(RtlGetVersion,               L"ntdll.dll",    "RtlGetVersion")       \
  X(RtlGenRandom,                L"advapi32.dll", "SystemFunction036")   \
  X(CryptProtectMemory,          L"crypt32.dll",  "CryptProtectMemory")  \
  X(CryptUnprotectMemory,        L"crypt32.dll",  "CryptUnprotectMemory") \
  X(BCryptOpenAlgorithmProvider, L"bcrypt.dll",   "BCryptOpenAlgorithmProvider") \
  X(BCryptCloseAlgorithmProvider,L"bcrypt.dll",   "BCryptCloseAlgorithmProvider") \
  X(BCryptGenRandom,             L"bcrypt.dll",   "BCryptGenRandom")     \
  X(BCryptGetProperty,           L"bcrypt.dll",   "BCryptGetProperty")   \
  X(BCryptSetProperty,           L"bcrypt.dll",   "BCryptSetProperty")   \
  X(BCryptGenerateSymmetricKey,  L"bcrypt.dll",   "BCryptGenerateSymmetricKey") \
  X(BCryptDestroyKey,            L"bcrypt.dll",   "BCryptDestroyKey")    \
  X(BCryptEncrypt,               L"bcrypt.dll",   "BCryptEncrypt")       \
  X(BCryptDecrypt,               L"bcrypt.dll",   "BCryptDecrypt")

#define SD_API_ENUM_(name, dll, fn) SD_API_##name,
typedef enum sd_api_id { SD_API_LIST(SD_API_ENUM_) SD_API_COUNT } sd_api_id;
#undef SD_API_ENUM_

/* Returns the cached function pointer, or NULL if the OS lacks it. Cast to the matching
   sd_pfn_<name> typedef from sd/winapi_compat.h. Adding an API: append to SD_API_LIST (and the
   typedef); this list is shared by every module, so keep entries grouped by DLL and only append. */
void *sd_platform_resolve(sd_api_id id);

/* Uncached resolution of anything else, by full System32 path. NULL if absent. */
void *sd_platform_resolve_by_name(const wchar_t *dll, const char *function);

/* Loads a System32 DLL by full path (GetSystemDirectoryW + name). The module stays loaded. */
HMODULE sd_platform_load_system_dll(const wchar_t *dll);

/* Restricts the DLL search path for the process: SetDefaultDllDirectories(SYSTEM32) when present,
   otherwise SetDllDirectoryW(L"") (removes the current directory). Call first thing in main(). */
void sd_platform_harden_dll_search(void);

/* ---- OS version ---- */

typedef struct sd_os_version {
  uint32_t major, minor, build;
  uint32_t sp_major;             /* service pack */
  uint32_t product_type;         /* VER_NT_WORKSTATION / _SERVER / _DOMAIN_CONTROLLER */
} sd_os_version;
const sd_os_version *sd_os_version_get(void);
int sd_os_at_least(uint32_t major, uint32_t minor, uint32_t build);

/* ---- CPU features (01 §2.3) ---- */

enum {
  SD_CPU_SSE2 = 1u << 0, SD_CPU_SSSE3 = 1u << 1, SD_CPU_AESNI = 1u << 2, SD_CPU_PCLMUL = 1u << 3,
  SD_CPU_SHANI = 1u << 4, SD_CPU_AVX2 = 1u << 5, SD_CPU_NEON = 1u << 6, SD_CPU_ARMV8_CRYPTO = 1u << 7
};
/* Detected features ANDed with the SD_CPU_MASK environment variable (hex, e.g. "0" forces every
   portable path; 04 §11.2) and with the mask from sd_cpu_set_mask(). Computed once. */
uint32_t sd_cpu_features(void);
/* Test hook: further restricts sd_cpu_features() (process-wide, call before first use). */
void sd_cpu_set_mask(uint32_t mask);

#endif /* SD_PLATFORM_H */
