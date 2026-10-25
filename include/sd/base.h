/* Cross-cutting language helpers (04 §2.3). No windows.h here: usable from sd_base and fuzz builds.
 *
 * The common dialect is what the v141 C compiler accepts: no VLAs, no _Generic, no <stdatomic.h>,
 * <threads.h>, _Thread_local or direct _Alignas. Use the macros below instead; atomics are
 * Interlocked* (sd_platform) only. */
#ifndef SD_BASE_H
#define SD_BASE_H

#include <stddef.h>
#include <stdint.h>

#define SD_INLINE        __inline
#define SD_FORCEINLINE   __forceinline
#define SD_NOINLINE      __declspec(noinline)
#define SD_NORETURN      __declspec(noreturn)
#define SD_ALIGN(n)      __declspec(align(n))
#define SD_UNUSED(x)     ((void)(x))
#define SD_COUNTOF(a)    (sizeof(a) / sizeof((a)[0]))

#define SD_CONCAT_(a, b) a##b
#define SD_CONCAT(a, b)  SD_CONCAT_(a, b)

/* Compile-time assertion usable at file scope and in blocks (C11 _Static_assert is not in v141 C). */
#define SD_STATIC_ASSERT(expr, msg) \
  typedef char SD_CONCAT(sd_static_assert_, __LINE__)[(expr) ? 1 : -1]

#define SD_MIN(a, b) ((a) < (b) ? (a) : (b))
#define SD_MAX(a, b) ((a) > (b) ? (a) : (b))

/* SAL annotations exist in every SDK we use (7.1A and 10.x) through <sal.h>. */
#include <sal.h>

#ifdef _WIN32
SD_STATIC_ASSERT(sizeof(wchar_t) == 2, "wchar_t must be UTF-16 on Windows");
#endif

#endif /* SD_BASE_H */
