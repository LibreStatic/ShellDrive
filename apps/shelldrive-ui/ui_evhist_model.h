/* shelldrive-ui: the agent's event history in the UI's event list (03 §2.4 events.recent, §7.7).
 *
 * A UI that starts after the agent has been running asks `events.recent` (feature `events.recent`) and shows the
 * history in its event list, so it is not empty. The history is read after the UI subscribed to the live events, so the
 * two overlap: a record of the history that this UI has already seen as a live event is not recorded twice. A record
 * carries no sequence number in the live events, so a live event is remembered by what it says (kind of event, mount,
 * state or warning code) and the second it came in; the history record matches when it says the same within a few
 * seconds. When the UI reconnects to the same agent it asks again, and only records newer than the last import are
 * taken (the sequence numbers count from 1 in each agent process, so a smaller last_seq means a new agent).
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_EVHIST_MODEL_H
#define SD_UI_EVHIST_MODEL_H

#include "sd/base.h"
#include "sd_base/sd_json.h"

#define UI_EVH_LIVE_SLOTS 64
#define UI_EVH_MATCH_SECONDS 5

/* One record of events.recent, as the agent sends it. Text is cut to these sizes. */
typedef struct ui_evh_rec {
  unsigned long long seq;
  long long time;                    /* unix seconds */
  char event[24];                    /* mount.state, warning, hostkeys.announced */
  char mount_id[16];
  char state[24];                    /* mount.state: the new state */
  char code[40];                     /* error code of a failed state, or the code of a warning */
} ui_evh_rec;

typedef struct ui_evh_live {
  int used;
  long long time;
  char event[24];
  char mount_id[16];
  char key[40];                      /* the state of a mount.state, the code of a warning, "" otherwise */
} ui_evh_live;

typedef struct ui_evh_state {
  unsigned long long imported_seq;   /* last_seq of the last import; 0 before the first one */
  unsigned long long min_seq;        /* records below this were imported already (set by ui_evh_begin) */
  ui_evh_live live[UI_EVH_LIVE_SLOTS];
  size_t next;                       /* the slot the next live event replaces (oldest first) */
} ui_evh_state;

void ui_evh_init(ui_evh_state *s);

/* A live event this UI has recorded. key: the new state of a mount.state, the code of a warning, NULL otherwise. */
void ui_evh_note_live(ui_evh_state *s, const char *event, const char *mount_id, const char *key, long long now);

/* Reads one element of the `events` array. 0 when it is not an object or has no event name or a sequence number. The
   event name must be one this UI knows how to show (mount.state, warning, hostkeys.announced); others return 0. */
int ui_evh_parse(const sd_json *rec, ui_evh_rec *out);

/* Starts an import: last_seq is the reply's last_seq. Fixes the lowest sequence number that is still to be recorded
   (everything when the agent is a new one). */
void ui_evh_begin(ui_evh_state *s, unsigned long long last_seq);

/* 1 when the record is to be recorded: it is newer than the last import and no live event said the same (a matching live
   event is used up). */
int ui_evh_wanted(ui_evh_state *s, const ui_evh_rec *r);

/* Ends the import. */
void ui_evh_end(ui_evh_state *s, unsigned long long last_seq);

/* The state of each mount while the history is replayed, to tell a reconnect from a first mount (ui_nt_of_mount_state). */
#define UI_EVH_TRACK 64
typedef struct ui_evh_track {
  char id[UI_EVH_TRACK][16];
  char state[UI_EVH_TRACK][24];
  size_t next;
} ui_evh_track;

void ui_evh_track_init(ui_evh_track *t);
/* The state the mount had before the record ("" when unknown). Remembers the record's state for the next one. */
void ui_evh_track_step(ui_evh_track *t, const char *mount_id, const char *state, char prev[24]);

#endif /* SD_UI_EVHIST_MODEL_H */
