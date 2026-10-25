/* XP-compatible threading primitives (04 §2.4: no SRW locks, condition variables or InitOnce).
 *
 * sd_mutex   CRITICAL_SECTION (recursive, like all critical sections). Never hold one across a
 *            blocking call into another module (review §4.1 rule 2).
 * sd_event   Win32 event (auto or manual reset).
 * sd_thread  _beginthreadex-based thread so the static CRT sets up per-thread state.
 * sd_once    Interlocked one-time initialization (InitOnceExecuteOnce is Vista+).
 *
 * Objects are owned by the caller (embed them in your structs); init/destroy are not thread-safe
 * against concurrent use of the same object, everything else is. */
#ifndef SD_THREAD_H
#define SD_THREAD_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define SD_WAIT_INFINITE 0xFFFFFFFFu

typedef struct sd_mutex { CRITICAL_SECTION cs; } sd_mutex;
void sd_mutex_init(sd_mutex *m);
void sd_mutex_destroy(sd_mutex *m);
void sd_mutex_lock(sd_mutex *m);
void sd_mutex_unlock(sd_mutex *m);
int  sd_mutex_trylock(sd_mutex *m);              /* 1 if acquired */

typedef struct sd_event { HANDLE h; } sd_event;
sd_err sd_event_init(sd_event *e, int manual_reset, int initially_set);
void   sd_event_destroy(sd_event *e);
void   sd_event_set(sd_event *e);
void   sd_event_reset(sd_event *e);
/* SD_OK when signaled, SD_E_TIMEOUT on timeout (ms; SD_WAIT_INFINITE allowed), SD_E_INTERNAL on error. */
sd_err sd_event_wait(sd_event *e, uint32_t timeout_ms);

typedef unsigned (__stdcall *sd_thread_fn)(void *arg);
typedef struct sd_thread { HANDLE h; uint32_t id; } sd_thread;
/* name: optional English thread name for debuggers (SetThreadDescription on 10 1607+). */
sd_err sd_thread_create(sd_thread *t, sd_thread_fn fn, void *arg, uint32_t stack_size,
                        const wchar_t *name);
/* Waits for exit and closes the handle. Returns SD_E_TIMEOUT if it did not exit (handle kept). */
sd_err sd_thread_join(sd_thread *t, uint32_t timeout_ms, uint32_t *exit_code);
uint32_t sd_thread_current_id(void);

typedef struct sd_once { volatile LONG state; } sd_once;   /* zero-initialize: SD_ONCE_INIT */
#define SD_ONCE_INIT { 0 }
/* Runs fn(arg) exactly once across threads; concurrent callers wait until it finished. */
void sd_once_run(sd_once *o, void (*fn)(void *arg), void *arg);

#endif /* SD_THREAD_H */
