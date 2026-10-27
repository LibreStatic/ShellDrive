/* shelldrive-ui: the administrator side of the service prompts (03 §2.6 rule 3, §1.4 --elevated-admin, TM-R25).
 *
 * Pure: no window, IPC or token call. The service pipe client is ui_svc.c; the decisions it and the window code
 * take are here, so the unit tests (tests/ui) can check them on their own:
 *  - the attention count (the content-free attention event) and when the tray shows it: only for a user who is an
 *    administrator, and only while the count is positive;
 *  - where an answer goes: a service prompt is answered over the service pipe, and only by an elevated process that
 *    is an administrator (the service checks the same thing again);
 *  - the ShellExecute verb that relaunches the UI elevated: "runas" on Windows Vista and later, a plain launch on XP. */
#ifndef SD_UI_ADMIN_MODEL_H
#define SD_UI_ADMIN_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

/* The largest attention count taken from the wire. The service never has more prompts than its slot table holds. */
#define UI_ADMIN_COUNT_MAX 1024

typedef enum ui_answer_route {
  UI_ROUTE_AGENT = 0,         /* prompt.answer on the per-user agent pipe */
  UI_ROUTE_SERVICE            /* prompt.answer on the service pipe, from the elevated administrator UI */
} ui_answer_route;

/* Reads the count of an attention event ({"count": n}). n must be an integer from 0 to UI_ADMIN_COUNT_MAX.
   Anything else is SD_E_INVALID_PARAM and *count is left at 0. */
sd_err ui_admin_parse_attention(const sd_json *data, int *count);

/* 1 when the tray shows the attention state: the count is positive and the logged-on user is an administrator.
   A non-administrator never sees it, even when the service sends the count. */
int ui_admin_attention_shown(int count, int user_is_admin);

/* 1 when this process may answer service prompts at all: it is an elevated process of an administrator. The service
   refuses the answer otherwise (access_denied), so this only avoids a pointless call. */
int ui_admin_may_answer_service(int process_elevated, int user_is_admin);

/* Where an answer goes. The admin mode answers service prompts on the service pipe; the normal UI answers its agent. */
ui_answer_route ui_admin_answer_route(int elevated_admin_mode);

/* ShellExecute verb for the relaunch: "runas" on Windows Vista and later (UAC), "open" on XP (no elevation there). */
const wchar_t *ui_admin_launch_verb(int vista_or_later);

#endif /* SD_UI_ADMIN_MODEL_H */
