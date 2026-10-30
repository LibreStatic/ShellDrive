/* shelldrive-ui: the model of the Logs viewer (03 §10.1, §2.4.1).
 *
 * The viewer tails the agent's ring with log.tail: the first call returns the last records, every later one
 * passes the cursor of the previous reply and gets the records after it. This module keeps the records (at most
 * UI_LOG_MAX_RECORDS, the oldest dropped first), applies one log.tail result, filters the records by level and
 * a search text, and builds the text that the viewer shows.
 *
 * Pure: no window or process calls (except the UTF-8 conversion of the record texts), so the unit tests
 * (tests/ui) build this file on its own. */
#ifndef SD_UI_LOGS_MODEL_H
#define SD_UI_LOGS_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

#define UI_LOG_MAX_RECORDS 2000u     /* the viewer shows the last 2000 records (03 §7.5 Logs viewer) */
#define UI_LOG_CURSOR_MAX  64u       /* "<pid hex>.<boot tick hex>.<seq dec>" plus its NUL */
#define UI_LOG_LEVELS      5        /* error, warn, info, debug, trace (sd_log_level order) */

typedef struct ui_log_rec {
  uint64_t seq;
  int level;                         /* 0 error .. 4 trace; -1 when the agent sent an unknown level */
  wchar_t *line;                     /* "time level component [mount] text", sd_alloc'd */
} ui_log_rec;

typedef struct ui_log_model {
  ui_log_rec *rec;                   /* oldest first */
  size_t count;
  size_t cap;                        /* UI_LOG_MAX_RECORDS once allocated */
  char cursor[UI_LOG_CURSOR_MAX];    /* "" = no cursor yet: the next call returns the last records */
  int reset;                         /* the last reply was a reset (the agent started over) */
  uint64_t dropped;                  /* records the last reply reports as lost */
} ui_log_model;

void ui_logs_model_init(ui_log_model *m);
void ui_logs_model_free(ui_log_model *m);
/* Forgets the records and the cursor (the agent went away, or a new viewer session starts). */
void ui_logs_model_clear(ui_log_model *m);

/* Applies a log.tail result {records:[{seq,time,level,component,mount_id?,text}], cursor, reset, dropped}.
   A reset without dropped records clears the list (the records came from another agent process); a reset
   with dropped records keeps them, and the gap is reported in m->dropped. Returns the number of records
   appended, or SD_E_INVALID_PARAM for a malformed result (the model is then unchanged). */
sd_err ui_logs_model_apply(ui_log_model *m, const sd_json *result, size_t *appended);

/* 0 error .. 4 trace; -1 for any other text. */
int ui_log_level_parse(const char *s);

/* True when the record passes the level filter (level_max: the most verbose level shown, 0 .. 4) and the
   search text (case-insensitive, matched against the whole line; "" or NULL matches everything). */
int ui_logs_match(const ui_log_rec *r, int level_max, const wchar_t *search);

/* Text of every visible record, one per line (CRLF), sd_alloc'd and NUL-terminated (free with sd_free).
   *lines receives the number of visible records. */
sd_err ui_logs_build_text(const ui_log_model *m, int level_max, const wchar_t *search, wchar_t **out,
                          size_t *lines);

#endif /* SD_UI_LOGS_MODEL_H */
