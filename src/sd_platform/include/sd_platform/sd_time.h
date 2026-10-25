/* Monotonic and wall-clock time (XP-safe). Thread safety: all functions are thread-safe.
 *
 * sd_tick_ms() is the 64-bit monotonic millisecond tick used for deadlines everywhere (01 §3.2):
 * GetTickCount64 where present (Vista+), otherwise GetTickCount extended to 64 bits. On XP the
 * extension is correct as long as the function is called at least once per 49.7 days (any running
 * process with timers does). Do not use wall-clock time for timeouts. */
#ifndef SD_TIME_H
#define SD_TIME_H

#include <windows.h>

#include "sd/base.h"

uint64_t sd_tick_ms(void);

/* Wall clock: Unix seconds (UTC) and the FILETIME conversions used by sd_vfs (02 §3.2). */
int64_t  sd_unix_time_now(void);
uint64_t sd_filetime_now(void);                         /* 100 ns units since 1601-01-01 UTC */
int64_t  sd_filetime_to_unix(uint64_t ft);
uint64_t sd_unix_to_filetime(int64_t unix_seconds);     /* clamps values before 1601 to 0 */

#endif /* SD_TIME_H */
