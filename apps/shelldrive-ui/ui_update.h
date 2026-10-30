/* shelldrive-ui: the updater glue (see ui_update.c and ui_update_model.h). The Settings window's update group is the
 * only view of it; the tray gets the update.available balloon through the notification limiter.
 *
 * Only the UI thread calls these functions. Replies and events arrive through ui_windows_on_reply and
 * ui_windows_on_event (ui_win.c). */
#ifndef SD_UI_UPDATE_H
#define SD_UI_UPDATE_H

#include <windows.h>

#include "sd_base/sd_json.h"
#include "ui_update_model.h"

/* Agent features of the update group (hello, 03 §2.8): update.check and update.apply (ui_win.h bits). */

/* "Check now": update.check, deferred. Does nothing while checks are off or another call runs. */
void ui_update_check(void);

/* "Install update": a consent dialog owned by owner, then update.apply with consent true. */
void ui_update_install(HWND owner);

/* "Release notes": opens the https notes link of the offer in the browser. */
void ui_update_open_notes(HWND owner);

/* Replies of update.check and update.apply (kind is UI_IPC_UPDATE_CHECK or UI_IPC_UPDATE_APPLY). */
void ui_update_on_reply(int kind, sd_err err, const sd_json *result);

/* update.available, update.progress and update.stale. Other names are ignored. */
void ui_update_on_event(const char *name, const sd_json *data);

/* The agent connected or went away. */
void ui_update_on_agent_state(int up);

/* What the Settings window shows now. */
void ui_update_policy_now(ui_upd_policy *p);
void ui_update_view_now(int agent_ok, int can_apply, ui_upd_view *v);
/* The status line and the stale line. Both return the number of characters written, 0 for none. */
size_t ui_update_status_text(wchar_t *out, size_t cch);
size_t ui_update_stale_text(wchar_t *out, size_t cch);
/* The channel the list shows (stable or beta). */
void ui_update_channel_now(const char *saved, char *out, size_t cch);
/* True while a check or an install is running. */
int ui_update_busy(void);

/* Reset for the tests and the smoke test: a fresh model. */
void ui_update_reset(void);

#endif /* SD_UI_UPDATE_H */
