/* shelldrive-ui: the balloon rate limit (03 §7.7). See ui_notify_model.h.
 *
 * A slot is found by (subject, kind). A new pair takes a free slot, or the slot with the oldest tick when the table
 * is full, so the table never grows and a flood of subjects cannot exhaust memory. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd/base.h"
#include "ui_notify_model.h"

void ui_notify_limiter_init(ui_notify_limiter *l)
{
  memset(l, 0, sizeof(*l));
}

static int subject_equal(const wchar_t *a, const wchar_t *b)
{
  return wcscmp(a, b) == 0;
}

int ui_notify_limiter_take(ui_notify_limiter *l, const wchar_t *subject, int kind, unsigned long long now_ms,
                           unsigned long long *wait_ms)
{
  wchar_t key[UI_NOTIFY_SUBJECT_MAX + 1];
  ui_notify_slot *hit = NULL, *victim = NULL;
  size_t i;
  unsigned long long elapsed;

  if (wait_ms != NULL)
    *wait_ms = 0;
  if (l == NULL)
    return 1;
  memset(key, 0, sizeof(key));
  if (subject != NULL)
    wcsncpy_s(key, SD_COUNTOF(key), subject, _TRUNCATE);

  for (i = 0; i < UI_NOTIFY_SLOTS; i++) {
    ui_notify_slot *s = &l->slots[i];
    if (s->used && s->kind == kind && subject_equal(s->subject, key)) {
      hit = s;
      break;
    }
    if (!s->used) {
      if (victim == NULL || victim->used)
        victim = s;                        /* a free slot beats any used one */
    } else if (victim == NULL || (victim->used && s->last_ms < victim->last_ms)) {
      victim = s;
    }
  }

  if (hit == NULL) {
    /* first balloon of this pair: take a slot and allow it */
    hit = victim;
    memset(hit, 0, sizeof(*hit));
    hit->used = 1;
    hit->kind = kind;
    wcscpy_s(hit->subject, SD_COUNTOF(hit->subject), key);
    hit->last_ms = now_ms;
    return 1;
  }

  /* a tick before the recorded one (clock trouble) counts as no time elapsed: the balloon waits, never a burst */
  elapsed = now_ms >= hit->last_ms ? now_ms - hit->last_ms : 0;
  if (elapsed >= UI_NOTIFY_INTERVAL_MS) {
    hit->last_ms = now_ms;
    return 1;
  }
  if (wait_ms != NULL)
    *wait_ms = UI_NOTIFY_INTERVAL_MS - elapsed;
  return 0;
}
