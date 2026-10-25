#include <windows.h>
#include <process.h>

#include "sd/winapi_compat.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"

void sd_mutex_init(sd_mutex *m)
{
  /* Cannot fail on Vista+; on XP it fails only under extreme memory pressure, and then
     EnterCriticalSection still works (it allocates the event lazily). */
  (void)InitializeCriticalSectionAndSpinCount(&m->cs, 1000);
}

void sd_mutex_destroy(sd_mutex *m)
{
  DeleteCriticalSection(&m->cs);
}

void sd_mutex_lock(sd_mutex *m)
{
  EnterCriticalSection(&m->cs);
}

void sd_mutex_unlock(sd_mutex *m)
{
  LeaveCriticalSection(&m->cs);
}

int sd_mutex_trylock(sd_mutex *m)
{
  return TryEnterCriticalSection(&m->cs) ? 1 : 0;
}

sd_err sd_event_init(sd_event *e, int manual_reset, int initially_set)
{
  e->h = CreateEventW(NULL, manual_reset ? TRUE : FALSE, initially_set ? TRUE : FALSE, NULL);
  return e->h ? SD_OK : SD_E_NO_MEMORY;
}

void sd_event_destroy(sd_event *e)
{
  if (e->h) {
    CloseHandle(e->h);
    e->h = NULL;
  }
}

void sd_event_set(sd_event *e)
{
  SetEvent(e->h);
}

void sd_event_reset(sd_event *e)
{
  ResetEvent(e->h);
}

sd_err sd_event_wait(sd_event *e, uint32_t timeout_ms)
{
  DWORD r = WaitForSingleObject(e->h, timeout_ms);
  if (r == WAIT_OBJECT_0)
    return SD_OK;
  return r == WAIT_TIMEOUT ? SD_E_TIMEOUT : SD_E_INTERNAL;
}

sd_err sd_thread_create(sd_thread *t, sd_thread_fn fn, void *arg, uint32_t stack_size,
                        const wchar_t *name)
{
  unsigned id = 0;
  uintptr_t h = _beginthreadex(NULL, stack_size, fn, arg, 0, &id);
  if (h == 0) {
    t->h = NULL;
    t->id = 0;
    return SD_E_NO_MEMORY;
  }
  t->h = (HANDLE)h;
  t->id = id;
  if (name) {
    sd_pfn_SetThreadDescription set_desc =
        (sd_pfn_SetThreadDescription)sd_platform_resolve(SD_API_SetThreadDescription);
    if (set_desc)
      (void)set_desc(t->h, name);
  }
  return SD_OK;
}

sd_err sd_thread_join(sd_thread *t, uint32_t timeout_ms, uint32_t *exit_code)
{
  DWORD r, code = 0;
  if (t->h == NULL)
    return SD_E_INVALID_PARAM;
  r = WaitForSingleObject(t->h, timeout_ms);
  if (r == WAIT_TIMEOUT)
    return SD_E_TIMEOUT;
  if (r != WAIT_OBJECT_0)
    return SD_E_INTERNAL;
  GetExitCodeThread(t->h, &code);
  if (exit_code)
    *exit_code = code;
  CloseHandle(t->h);
  t->h = NULL;
  return SD_OK;
}

uint32_t sd_thread_current_id(void)
{
  return GetCurrentThreadId();
}

/* state: 0 = not started, 1 = running, 2 = done. */
void sd_once_run(sd_once *o, void (*fn)(void *arg), void *arg)
{
  LONG prev;
  if (InterlockedCompareExchange(&o->state, 2, 2) == 2)
    return;
  prev = InterlockedCompareExchange(&o->state, 1, 0);
  if (prev == 0) {
    fn(arg);
    InterlockedExchange(&o->state, 2);
    return;
  }
  while (InterlockedCompareExchange(&o->state, 2, 2) != 2)
    Sleep(1);                                   /* Sleep(0) could starve a lower-priority initializer */
}
