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
} ui_settings_model;

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

#endif /* SD_UI_SETTINGS_MODEL_H */
