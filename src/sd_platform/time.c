#include <windows.h>
#include <intrin.h>

#include "sd/winapi_compat.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"

/* 100 ns intervals between 1601-01-01 and 1970-01-01. */
#define SD_EPOCH_DIFF_100NS 116444736000000000ULL

/* XP fallback state: (wrap count << 32) | last 32-bit tick. The intrinsic, not the kernel32
   InterlockedCompareExchange64 export, which x86 XP lacks. */
static volatile __int64 g_tick_state;

static uint64_t tick_extend(void)
{
  for (;;) {
    __int64 old = _InterlockedCompareExchange64(&g_tick_state, 0, 0);   /* atomic read */
    uint32_t last = (uint32_t)old, hi = (uint32_t)((uint64_t)old >> 32);
#pragma warning(suppress: 28159)   /* deliberate: XP fallback, wraps are handled below */
    uint32_t now = GetTickCount();
    __int64 neu;
    if (now < last) {
      if (last - now < 0x80000000u)
        return ((uint64_t)hi << 32) | last;     /* another thread stored a later tick: stay monotonic */
      hi++;                                     /* real 49.7-day wrap */
    }
    neu = (__int64)(((uint64_t)hi << 32) | now);
    if (_InterlockedCompareExchange64(&g_tick_state, neu, old) == old)
      return (uint64_t)neu;
  }
}

uint64_t sd_tick_ms(void)
{
  /* sd_platform_resolve caches the pointer; the lookup costs one interlocked read. */
  sd_pfn_GetTickCount64 gtc64 = (sd_pfn_GetTickCount64)sd_platform_resolve(SD_API_GetTickCount64);
  return gtc64 ? gtc64() : tick_extend();
}

uint64_t sd_filetime_now(void)
{
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

int64_t sd_filetime_to_unix(uint64_t ft)
{
  if (ft >= SD_EPOCH_DIFF_100NS)
    return (int64_t)((ft - SD_EPOCH_DIFF_100NS) / 10000000ULL);
  return -(int64_t)((SD_EPOCH_DIFF_100NS - ft + 9999999ULL) / 10000000ULL);
}

uint64_t sd_unix_to_filetime(int64_t unix_seconds)
{
  const int64_t min_unix = -(int64_t)(SD_EPOCH_DIFF_100NS / 10000000ULL);
  const int64_t max_unix = (int64_t)((UINT64_MAX - SD_EPOCH_DIFF_100NS) / 10000000ULL);
  if (unix_seconds <= min_unix)
    return 0;
  if (unix_seconds >= max_unix)
    return UINT64_MAX;
  return (uint64_t)((int64_t)(SD_EPOCH_DIFF_100NS / 10000000ULL) + unix_seconds) * 10000000ULL;
}

int64_t sd_unix_time_now(void)
{
  return sd_filetime_to_unix(sd_filetime_now());
}
