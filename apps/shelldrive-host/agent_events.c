/* The rules of two agent events (see agent_events.h). Pure functions: no locks, no I/O. */
#include <string.h>

#include "agent_events.h"

static int is(const char *a, const char *b)
{
  return a != NULL && strcmp(a, b) == 0;
}

static void copy_to(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (cap == 0)
    return;
  if (src != NULL)
    for (; src[i] != 0 && i + 1 < cap; i++)
      dst[i] = src[i];
  dst[i] = 0;
}

int agent_reason_on_state(char *drop, size_t cap, const char *st, const char *ecode, char *reason, size_t rcap)
{
  int carries, ends;
  if (drop == NULL || cap == 0 || st == NULL)
    return 0;
  if (is(st, "offline")) {                       /* the offline event has its own error object */
    if (ecode != NULL && ecode[0] != 0)
      copy_to(drop, cap, ecode);
    return 0;
  }
  carries = is(st, "connecting") || is(st, "authenticating") || is(st, "mounted");
  ends = is(st, "mounted") || is(st, "failed") || is(st, "unmounting") || is(st, "unmounted");
  if (carries && drop[0] != 0 && reason != NULL && rcap > 0) {
    copy_to(reason, rcap, drop);
    if (ends)
      drop[0] = 0;
    return 1;
  }
  if (ends)
    drop[0] = 0;
  return 0;
}

int agent_source_warn_take(uint32_t *done, uint32_t bit)
{
  if (done == NULL || bit == 0 || (*done & bit) != 0)
    return 0;
  *done |= bit;
  return 1;
}
