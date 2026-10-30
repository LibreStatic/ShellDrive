/* shelldrive-ui: the settings model of the Settings window (03 §3.2, §7.5, §9.3).
 *
 * The window edits the fields below. They map onto sd_settings (settings.ini) except start_at_logon, which is the
 * per-user Run key of the tray (HKCU only, never a machine setting). The mapping keeps every sd_settings field the
 * window does not show, so saving never drops a value.
 *
 * Live and restart-required split (03 §2.4, decision 9): the notification, backend and cache budget settings are
 * read by the agent at its next reload or mount; the language is read at start-up, so the window says it needs a
 * restart. The update group stays disabled while the agent lacks the update.check feature (decision 10).
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_SETTINGS_MODEL_H
#define SD_UI_SETTINGS_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_config/sd_config.h"

#define UI_SET_CACHE_MB_MIN  16u
#define UI_SET_CACHE_MB_MAX  65536u
#define UI_SET_LANG_MAX      16       /* sd_settings.ui_language, including the NUL */

typedef struct ui_settings_model {
  char language[UI_SET_LANG_MAX];    /* "" = system default */
  int notify;                        /* balloons on */
  int default_backend;               /* SD_PROFILE_BACKEND_* */
  unsigned cache_mb;                 /* memory cache budget in MiB; 0 = the default budget */
  int start_at_logon;                /* tray Run key (not in settings.ini) */
  int openssh_source;                /* [hostkeys] openssh_source: trust host keys accepted in OpenSSH (5.1) */
  int putty_source;                  /* [hostkeys] putty_source: trust host keys accepted in PuTTY (5.1) */
  int roam_credentials;              /* [credentials] persist = enterprise (roam saved passwords, 3.4) */
  int write_mode;                    /* [defaults] write_mode: SD_PROFILE_WRITE_THROUGH or _BEHIND (profiles without their own) */
  int log_strict;                    /* [log] privacy = strict (keep host names and paths out of the log, 10.1) */
  int agent_logon;                   /* [agent] start_at_logon (the agent's Run value, 3.2 Start) */
  unsigned notify_kinds;             /* [ui] notify_<kind>: bit k is sd_notify_kind k (7.7); under the notify master */
} ui_settings_model;

/* Fields of the model, as bits of the masks below. */
#define UI_SET_F_LANGUAGE 0x01u      /* locked by policy UILanguage */
#define UI_SET_F_OPENSSH  0x02u      /* locked by policy DisableKnownHostsSources */
#define UI_SET_F_PUTTY    0x04u      /* locked by policy DisableKnownHostsSources */
#define UI_SET_F_NOTIFY   0x100u
#define UI_SET_F_BACKEND  0x200u
#define UI_SET_F_CACHE    0x400u
#define UI_SET_F_ROAMING  0x800u
#define UI_SET_F_LOGON    0x1000u
#define UI_SET_F_WRITE    0x2000u    /* locked by policy ForceWriteThrough */
#define UI_SET_F_PRIVACY  0x4000u    /* locked by policy LogPrivacy */
#define UI_SET_F_KINDS    0x8000u    /* any [ui] notify_<kind> switch */
#define UI_SET_F_AGENT    0x10000u   /* [agent] start_at_logon */

/* The policy values the window reads (03 §3.5). The view fills it from sd_policy; the tests fill it by hand. A
   locked field is shown read-only with the value the policy enforces and is never written back to settings.ini. */
typedef struct ui_set_policy {
  int  language_set;                 /* UILanguage has a valid value */
  char language[UI_SET_LANG_MAX];
  int  sources_disabled;             /* DisableKnownHostsSources = 1 */
  int  force_through;                /* ForceWriteThrough = 1: the default write mode is through */
  int  privacy_set;                  /* LogPrivacy has a value (0 or 1) */
  int  privacy_strict;               /* LogPrivacy = 1 */
} ui_set_policy;

/* Number of notification kinds with a switch, and the mask with all of them on. */
#define UI_SET_KIND_COUNT SD_NOTIFY_COUNT
#define UI_SET_KINDS_ALL  ((1u << UI_SET_KIND_COUNT) - 1u)

/* Mask of the UI_SET_F_* fields the policies lock. */
unsigned ui_settings_locked(const ui_set_policy *p);

/* Forces the displayed value of every locked field to what the policy enforces (language: the policy language;
   host key sources: off, because nothing is read from them). Returns the locked mask. */
unsigned ui_settings_apply_policy(ui_settings_model *m, const ui_set_policy *p);

/* Mask of the fields that differ between two models (the write diff: nothing changed, nothing is written). */
unsigned ui_settings_changed(const ui_settings_model *before, const ui_settings_model *after);

/* Like ui_settings_to_sd, but the fields in `locked` keep the value s holds. */
void ui_settings_to_sd_masked(const ui_settings_model *m, unsigned locked, sd_settings *s);

/* Note under a host key source toggle. enabled: the toggle is on; locked: a policy locks it; src_state: the
   sd_kh_src_state of the source (3 = INSECURE, TM-R06). */
typedef enum ui_set_note { UI_SET_NOTE_NONE = 0, UI_SET_NOTE_MANAGED, UI_SET_NOTE_INSECURE } ui_set_note;
ui_set_note ui_settings_source_note(int enabled, int locked, int src_state);

/* WebClient service state as the window words it (read-only, 02 §7.2). state: sd_webdav_client_state. */
typedef enum ui_set_webclient { UI_SET_WC_UNKNOWN = 0, UI_SET_WC_RUNNING, UI_SET_WC_STOPPED, UI_SET_WC_DISABLED,
                                UI_SET_WC_MISSING } ui_set_webclient;
ui_set_webclient ui_settings_webclient_kind(int state);

/* Languages offered by the combo box, in order. The first entry is the system default (""). */
#define UI_SET_LANG_COUNT 7
extern const char *const g_ui_set_lang_codes[UI_SET_LANG_COUNT];

/* Index of a language code in g_ui_set_lang_codes, 0 (system default) when unknown. */
int ui_settings_lang_index(const char *code);

/* Copies the window-visible fields of s into m. */
void ui_settings_from_sd(const sd_settings *s, ui_settings_model *m);

/* Writes the window-visible fields of m into s and leaves the other fields of s as they are. */
void ui_settings_to_sd(const ui_settings_model *m, sd_settings *s);

/* Parses the cache budget field: decimal MiB, 0 for the default budget, or 16..65536. SD_E_INVALID_PARAM for
   anything else (the window then keeps the field focused and shows its message). */
sd_err ui_settings_parse_cache(const wchar_t *text, unsigned *mb);

/* The Run key value that starts the tray at sign-in: "<exe>" --tray (quoted path). */
sd_err ui_settings_run_command(const wchar_t *exe, wchar_t *out, size_t cap);

/* M4 (03 §3.2 Start): the Run key value of the agent, "<host_exe>" agent --logon (quoted path). The value is
   ShellDriveAgent under HKCU Run; it exists when sd_settings_agent_run_wanted says so. */
sd_err ui_settings_agent_run_command(const wchar_t *host_exe, wchar_t *out, size_t cap);

#endif /* SD_UI_SETTINGS_MODEL_H */
