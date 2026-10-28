/* shelldrive-ui: the model of the event list (03 §7.7).
 *
 * "Every notification is also recorded in the main window's event list so nothing exists only as a transient
 * balloon." The list keeps the most recent UI_EV_MAX entries in a ring (the oldest is dropped first): when it
 * happened, the drive or server it is about, a kind (drive, host key, warning, error, information) and the text
 * as it was shown to the user. This module adds entries, filters them by kind and by a search text, and builds
 * the text that Copy puts on the clipboard.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_EVENTS_MODEL_H
#define SD_UI_EVENTS_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define UI_EV_MAX          200u      /* entries kept; the oldest is dropped first */
#define UI_EV_SUBJECT_MAX  64        /* UTF-16 units including the terminator */
#define UI_EV_TEXT_MAX     256
#define UI_EV_TIME_MAX     24        /* "YYYY-MM-DD HH:MM:SS" plus its NUL */

typedef enum ui_ev_kind {
  UI_EV_DRIVE = 0,                   /* a drive changed state (mounted, reconnecting, unmounted) */
  UI_EV_HOSTKEY,                     /* host key changed, wrong key type, new keys offered */
  UI_EV_WARNING,                     /* legacy algorithms, Terrapin, other warnings */
  UI_EV_ERROR,                       /* a mount failed, changes could not be written */
  UI_EV_INFO,                        /* updates and prompts that timed out */
  UI_EV_KINDS
} ui_ev_kind;

typedef struct ui_ev_time {
  unsigned year, month, day, hour, minute, second;
} ui_ev_time;

typedef struct ui_ev_entry {
  unsigned long long seq;            /* 1, 2, ... in the order the entries were added */
  ui_ev_time time;
  ui_ev_kind kind;
  wchar_t subject[UI_EV_SUBJECT_MAX]; /* drive letter ("E:") or server name; may be empty */
  wchar_t text[UI_EV_TEXT_MAX];
} ui_ev_entry;

typedef struct ui_ev_log {
  ui_ev_entry entry[UI_EV_MAX];
  size_t first;                      /* ring index of the oldest entry */
  size_t count;
  unsigned long long next_seq;
} ui_ev_log;

void ui_ev_init(ui_ev_log *l);
/* Forgets every entry; sequence numbers keep growing. */
void ui_ev_clear(ui_ev_log *l);

/* Adds an entry; over-long subject and text are cut and control characters become blanks. A kind out of range is
   stored as information. Returns the entry's sequence number. */
unsigned long long ui_ev_add(ui_ev_log *l, ui_ev_kind kind, const ui_ev_time *t, const wchar_t *subject,
                             const wchar_t *text);

/* Entry i, 0 = the oldest; NULL out of range. */
const ui_ev_entry *ui_ev_at(const ui_ev_log *l, size_t i);

/* "YYYY-MM-DD HH:MM:SS". */
void ui_ev_format_time(const ui_ev_time *t, wchar_t out[UI_EV_TIME_MAX]);

/* 1 when the entry passes the filters: kind_mask has bit (1 << kind) for each shown kind, search is matched
   case-insensitively against subject and text ("" or NULL matches everything). */
int ui_ev_match(const ui_ev_entry *e, unsigned kind_mask, const wchar_t *search);

/* Case-insensitive (ASCII) substring test; an empty needle matches. */
int ui_ev_contains(const wchar_t *s, const wchar_t *needle);

/* One line per matching entry, oldest first, joined with CR LF: "time<TAB>subject<TAB>kind<TAB>text". kind_label[k]
   is the localized name of kind k. Sets *lines to the number of entries written. sd_alloc'd, NUL-terminated (free
   with sd_free). */
sd_err ui_ev_build_text(const ui_ev_log *l, unsigned kind_mask, const wchar_t *search,
                        const wchar_t *const kind_label[UI_EV_KINDS], wchar_t **out, size_t *lines);

#endif /* SD_UI_EVENTS_MODEL_H */
