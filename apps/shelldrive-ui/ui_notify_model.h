/* shelldrive-ui: the balloon rate limit of the notification area (03 §7.7).
 *
 * At most one balloon per (subject, event kind) every UI_NOTIFY_INTERVAL_MS. The subject is the mount (its drive
 * letter) or the host name of a host key announcement; the kind is the catalog message of the balloon. A balloon
 * that is not allowed yet is queued by ui_tray.c and shown when the limiter allows it.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_NOTIFY_MODEL_H
#define SD_UI_NOTIFY_MODEL_H

#include <windows.h>

#define UI_NOTIFY_INTERVAL_MS  60000u     /* 03 §7.7: one balloon per (mount, event type) per 60 s */
#define UI_NOTIFY_SLOTS        64         /* remembered (subject, kind) pairs; the oldest is reused */
#define UI_NOTIFY_SUBJECT_MAX  280        /* UTF-16 units, no terminator (a host name or a drive letter) */

typedef struct ui_notify_slot {
  int used;
  int kind;
  unsigned long long last_ms;             /* tick of the last balloon for this pair */
  wchar_t subject[UI_NOTIFY_SUBJECT_MAX + 1];
} ui_notify_slot;

typedef struct ui_notify_limiter {
  ui_notify_slot slots[UI_NOTIFY_SLOTS];
} ui_notify_limiter;

void ui_notify_limiter_init(ui_notify_limiter *l);

/* Asks whether a balloon for (subject, kind) may be shown at now_ms (a monotonic tick in ms). Returns 1 and records
   the time when it may; returns 0 and sets *wait_ms (when non-NULL) to the milliseconds until it may. A subject
   longer than UI_NOTIFY_SUBJECT_MAX is treated as its prefix. */
int ui_notify_limiter_take(ui_notify_limiter *l, const wchar_t *subject, int kind, unsigned long long now_ms,
                           unsigned long long *wait_ms);

#endif /* SD_UI_NOTIFY_MODEL_H */
