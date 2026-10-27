/* shelldrive-ui: the updater consent model of the Settings window (03 §3.2, 04 §9.7, 03 §2.4, §2.8).
 *
 * The UI only asks: "Check now" sends update.check, "Install" (after a consent dialog) sends update.apply with
 * consent true, and the agent events update.available, update.progress and update.stale tell the UI what happened.
 * This file holds the state of that conversation and nothing else: no window, no IPC, no registry. ui_update.c
 * feeds it the replies and events; the Settings window reads the status kind and the policy view.
 *
 * States: IDLE (nothing running; the status text says what the last answer was), CHECKING (update.check in
 * flight), AVAILABLE (a newer version is offered and may be installed), INSTALLING (update.apply in flight),
 * FAILED (the last check or install failed; the error name is kept). A check or an install is never started
 * from another running one (the agent answers "busy" anyway).
 *
 * Policy (03 §3.5): DisableUpdateCheck turns the checks off ("managed by your organization"); UpdateChannel fixes
 * the channel. The policy values are read by ui_update.c through sd_policy and passed in as ui_upd_policy; the
 * model never reads the registry itself.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_UPDATE_MODEL_H
#define SD_UI_UPDATE_MODEL_H

#include <windows.h>

#define UI_UPD_VERSION_MAX  32
#define UI_UPD_NOTES_MAX    512
#define UI_UPD_CHANNEL_MAX  8
#define UI_UPD_REASON_MAX   16
#define UI_UPD_ERROR_MAX    40
#define UI_UPD_FILE_ID_MAX  64

typedef enum ui_upd_state {
  UI_UPD_IDLE = 0,
  UI_UPD_CHECKING,
  UI_UPD_AVAILABLE,
  UI_UPD_INSTALLING,
  UI_UPD_FAILED
} ui_upd_state;

/* Progress stages of update.progress (0 = none yet). */
typedef enum ui_upd_stage {
  UI_UPD_STAGE_NONE = 0,
  UI_UPD_STAGE_DOWNLOADING,
  UI_UPD_STAGE_APPLYING,
  UI_UPD_STAGE_DONE,
  UI_UPD_STAGE_FAILED
} ui_upd_stage;

/* One offer of a verified manifest (the update.check reply or update.available event). */
typedef struct ui_upd_offer {
  char version[UI_UPD_VERSION_MAX];
  char channel[UI_UPD_CHANNEL_MAX];
  char notes[UI_UPD_NOTES_MAX];         /* the notes link, https only (empty when none) */
  char file_id[UI_UPD_FILE_ID_MAX];
  unsigned long long size;              /* bytes */
} ui_upd_offer;

/* The reply of update.check, parsed by ui_update.c. enabled 0 means the agent did not check (reason says why). */
typedef struct ui_upd_check {
  int enabled;
  char reason[UI_UPD_REASON_MAX];       /* "policy", "settings" or "" */
  int available;
  int stale;
  char channel[UI_UPD_CHANNEL_MAX];
  ui_upd_offer offer;                   /* valid when available */
} ui_upd_check;

typedef struct ui_upd_model {
  ui_upd_state state;
  int enabled;                          /* the last check said updates are enabled (not turned off) */
  char reason[UI_UPD_REASON_MAX];       /* why checks are off, as the agent says it; "" when on */
  int stale;                            /* update.stale: the last verified manifest is old */
  long long stale_days;
  int has_offer;
  ui_upd_offer offer;
  ui_upd_stage stage;
  char error[UI_UPD_ERROR_MAX];         /* the failure of the last check or install ("" when none) */
  char channel[UI_UPD_CHANNEL_MAX];     /* the channel the agent reported last */
  char announced[UI_UPD_VERSION_MAX];   /* the version last announced by a balloon (one balloon per version) */
  int checked;                          /* a check completed in this session */
} ui_upd_model;

/* The policies of the updater (sd_policy): what the Settings window must show as managed. */
typedef struct ui_upd_policy {
  int check_off;                        /* DisableUpdateCheck = 1 */
  int channel_set;                      /* UpdateChannel is set (REG_SZ, "stable" or "beta") */
  char channel[UI_UPD_CHANNEL_MAX];     /* the policy channel when channel_set */
} ui_upd_policy;

/* Status kinds of the Settings window: one line of text per kind (ui_update.c picks the catalog message). */
typedef enum ui_upd_status_kind {
  UI_UPD_SHOW_IDLE = 0,
  UI_UPD_SHOW_CHECKING,
  UI_UPD_SHOW_CURRENT,
  UI_UPD_SHOW_AVAILABLE,
  UI_UPD_SHOW_INSTALLING,
  UI_UPD_SHOW_FAILED,
  UI_UPD_SHOW_OFF_POLICY,
  UI_UPD_SHOW_OFF_SETTINGS
} ui_upd_status_kind;

/* The controls of the update group: what is enabled and what is managed. */
typedef struct ui_upd_view {
  int channel_enabled;                  /* the channel list can be changed (not set by policy) */
  int channel_managed;                  /* the channel is set by policy: show "managed by your organization" */
  int check_enabled;                    /* "Check now" may be pressed */
  int check_managed;                    /* checks are off by policy: show "managed by your organization" */
  int install_enabled;                  /* "Install update": an offer exists and nothing is running */
  int notes_enabled;                    /* "Release notes": the offer has a notes link */
} ui_upd_view;

void ui_upd_model_init(ui_upd_model *m);

/* Starts a check. 1 when it may start (from IDLE, AVAILABLE or FAILED), 0 otherwise. */
int ui_upd_begin_check(ui_upd_model *m);

/* The update.check reply. error is NULL on success, or the error name of the failed call (the check is then
   FAILED with that name). r is ignored on error. */
void ui_upd_on_check(ui_upd_model *m, const char *error, const ui_upd_check *r);

/* Starts an install of the offer. 1 when it may start (AVAILABLE with an offer), 0 otherwise. */
int ui_upd_begin_install(ui_upd_model *m);

/* The update.apply reply: error is NULL on success, else the error name (FAILED). On success applied is 1 when a
   new version was installed, 0 when the agent answered "up_to_date". */
void ui_upd_on_apply(ui_upd_model *m, const char *error, int applied);

/* update.progress event: stage is "downloading", "applying", "done" or "failed" (other text is ignored). */
void ui_upd_on_progress(ui_upd_model *m, const char *stage);

/* update.available event. Returns 1 when the balloon should be shown: the version was not announced before. */
int ui_upd_on_available(ui_upd_model *m, const ui_upd_offer *o);

/* update.stale event: the last verified manifest is days old (the agent sends it after a failed check). */
void ui_upd_on_stale(ui_upd_model *m, long long days);

/* The agent connection changed. A check or an install cannot finish without the agent: it fails. */
void ui_upd_on_agent_state(ui_upd_model *m, int up);

/* The channel the Settings window shows: the policy channel when set, else the saved one, else "stable". */
const char *ui_upd_effective_channel(const ui_upd_policy *p, const char *saved);

/* What the Settings window shows as status, from the model and the policy. */
ui_upd_status_kind ui_upd_status_of(const ui_upd_model *m, const ui_upd_policy *p);

/* Which controls are enabled and which are marked as managed. agent_ok: the agent is connected and offers
   update.check; can_apply: the agent offers update.apply. */
void ui_upd_view_of(const ui_upd_model *m, const ui_upd_policy *p, int agent_ok, int can_apply, ui_upd_view *v);

#endif /* SD_UI_UPDATE_MODEL_H */
