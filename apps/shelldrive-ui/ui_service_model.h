/* shelldrive-ui: the Service page (03 §1.3, §2.4 service.status / service.repair_data, §7.5).
 *
 * The page shows the service the way `shelldrive service status` does: install state, start type, the registered
 * program with its path check, the Event Log source, and, when the service runs and answers on its pipe, the machine
 * data folder (3.2: trusted or refused with the reason), the global drives, the open administrator prompts and the
 * loaded machine profiles. The view is filled from the reply of service.status, or, when the service is not installed,
 * not running or does not answer, from the Service Control Manager (ui_service.c reads it read-only with svc_scm.c).
 *
 * "Repair data..." runs the code of `shelldrive service repair-data`: through service.repair_data when the service
 * answers, in this process otherwise. It is enabled for administrators only, and only an elevated administrator runs it;
 * a non-elevated administrator is offered the relaunch (--elevated-service, UAC shield on Vista and later).
 *
 * Pure: no window, pipe, SCM or token call, so the unit tests (tests/ui) build this file on its own. The window code
 * (ui_service.c) maps the line kinds and enums to catalog messages. The numeric values of the check enums are those of
 * SVC_PATH_* and SVC_SRC_* in svc_scm.h (0 unknown, 1 ok, ...), so the window passes the SCM report through unchanged. */
#ifndef SD_UI_SERVICE_MODEL_H
#define SD_UI_SERVICE_MODEL_H

#include <windows.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

#define UI_SVC_PATH_MAX 520
#define UI_SVC_LINES_MAX 16

typedef enum ui_svc_state {
  UI_SVC_ST_NOT_INSTALLED = 0,
  UI_SVC_ST_RUNNING,
  UI_SVC_ST_STOPPED,
  UI_SVC_ST_STARTING,
  UI_SVC_ST_STOPPING,
  UI_SVC_ST_PAUSED,
  UI_SVC_ST_UNKNOWN
} ui_svc_state;

typedef enum ui_svc_starttype {
  UI_SVC_START_NONE = 0,
  UI_SVC_START_AUTOMATIC,
  UI_SVC_START_MANUAL,
  UI_SVC_START_DISABLED,
  UI_SVC_START_UNKNOWN
} ui_svc_starttype;

enum { UI_SVC_PROGRAM_UNKNOWN = 0, UI_SVC_PROGRAM_OK, UI_SVC_PROGRAM_UNQUOTED, UI_SVC_PROGRAM_OTHER };
enum { UI_SVC_SOURCE_UNKNOWN = 0, UI_SVC_SOURCE_OK, UI_SVC_SOURCE_MISSING, UI_SVC_SOURCE_OTHER };

typedef enum ui_svc_machine {
  UI_SVC_MACHINE_NONE = 0,      /* the service did not report it */
  UI_SVC_MACHINE_OK,
  UI_SVC_MACHINE_REFUSED
} ui_svc_machine;

typedef enum ui_svc_reason {
  UI_SVC_REASON_NONE = 0,
  UI_SVC_REASON_OWNER,          /* an owner that is not SYSTEM or Administrators */
  UI_SVC_REASON_LINK,           /* a link or a junction */
  UI_SVC_REASON_ACL,            /* permissions that let other accounts change it */
  UI_SVC_REASON_OTHER           /* a file where a folder belongs, or a reason this build does not know */
} ui_svc_reason;

typedef struct ui_svc_view {
  int valid;                    /* a status was read */
  ui_svc_state state;
  ui_svc_starttype start;
  int program_check;            /* UI_SVC_PROGRAM_* */
  int source_check;             /* UI_SVC_SOURCE_* */
  wchar_t program[UI_SVC_PATH_MAX];
  int pipe_reachable;           /* the service answered on its pipe */
  int service_reports;          /* service.status answered with the machine folder: the fields below are valid */
  int healthy;
  long long drives;
  long long prompts;
  long long profiles;
  ui_svc_machine machine;
  ui_svc_reason reason;
  wchar_t machine_path[UI_SVC_PATH_MAX];   /* the refused folder; only an elevated administrator gets it */
} ui_svc_view;

void ui_svc_view_init(ui_svc_view *v);

/* Reads the reply of service.status (the members of svc_status.c plus machine). SD_E_INVALID_PARAM when res is not an
   object or has no "installed" member; v is then left invalid. Unknown words become the UNKNOWN values. */
sd_err ui_svc_view_from_status(ui_svc_view *v, const sd_json *res);

/* The view from the Service Control Manager alone (the service is not installed, not running, or does not answer).
   state and start_type are the SERVICE_* values of QueryServiceStatus / QueryServiceConfig (0 when not installed);
   path_check and source_check are SVC_PATH_* and SVC_SRC_* of svc_scm_status. pipe_reachable stays 0. */
void ui_svc_view_from_scm(ui_svc_view *v, int installed, unsigned long state, unsigned long start_type,
                          int path_check, int source_check, const wchar_t *binary);

/* ---- what the page shows ---- */

typedef enum ui_svc_line_kind {
  UI_SVC_LINE_NOT_INSTALLED = 0,
  UI_SVC_LINE_STATE,            /* which: ui_svc_state */
  UI_SVC_LINE_START,            /* which: ui_svc_starttype */
  UI_SVC_LINE_PROGRAM,          /* text: the registered path */
  UI_SVC_LINE_PROGRAM_CHECK,    /* which: UI_SVC_PROGRAM_* */
  UI_SVC_LINE_SOURCE_CHECK,     /* which: UI_SVC_SOURCE_* */
  UI_SVC_LINE_PIPE_DOWN,        /* running, but the pipe does not answer */
  UI_SVC_LINE_OLD_SERVICE,      /* the pipe answers but service.status is unknown to it */
  UI_SVC_LINE_MACHINE_OK,
  UI_SVC_LINE_MACHINE_REFUSED,  /* which: ui_svc_reason */
  UI_SVC_LINE_MACHINE_PATH,     /* text: the refused folder */
  UI_SVC_LINE_DRIVES,           /* count */
  UI_SVC_LINE_PROMPTS,          /* count */
  UI_SVC_LINE_PROFILES          /* count */
} ui_svc_line_kind;

typedef struct ui_svc_line {
  ui_svc_line_kind kind;
  int which;
  long long count;
  const wchar_t *text;          /* points into the view */
} ui_svc_line;

/* The lines of the status block, in order. Returns the count (at most UI_SVC_LINES_MAX); 0 for an invalid view. */
size_t ui_svc_lines(const ui_svc_view *v, ui_svc_line out[UI_SVC_LINES_MAX]);

/* ---- repair ---- */

typedef enum ui_svc_repair_mode {
  UI_SVC_REPAIR_OFF = 0,        /* the button is disabled: not an administrator, or no status yet */
  UI_SVC_REPAIR_RUN,            /* enabled: this process is an elevated administrator */
  UI_SVC_REPAIR_ELEVATE         /* enabled with the UAC shield: an administrator that is not elevated */
} ui_svc_repair_mode;

/* process_elevated: this process has the full administrator token (the administrator check itself on XP).
   user_is_admin: the logged-on user is an administrator (ui_svc_user_is_admin). */
ui_svc_repair_mode ui_svc_repair_mode_of(const ui_svc_view *v, int process_elevated, int user_is_admin);

/* 1 when the button shows the UAC shield: the ELEVATE mode on Windows Vista and later. */
int ui_svc_repair_shield(ui_svc_repair_mode mode, int vista_or_later);

typedef enum ui_svc_repair_route {
  UI_SVC_ROUTE_PIPE = 0,        /* service.repair_data: the service answers */
  UI_SVC_ROUTE_DIRECT           /* the same code in this (elevated) process: the service is not running */
} ui_svc_repair_route;

ui_svc_repair_route ui_svc_repair_route_of(const ui_svc_view *v);

typedef enum ui_svc_repair_kind {
  UI_SVC_RP_DONE = 0,           /* repaired, nothing moved */
  UI_SVC_RP_MOVED,              /* an untrusted folder was moved aside and replaced */
  UI_SVC_RP_STILL_REFUSED,      /* repaired, but the service still refuses the layout (healthy false) */
  UI_SVC_RP_BUSY,               /* global drives exist */
  UI_SVC_RP_DENIED,             /* not an elevated administrator */
  UI_SVC_RP_LINK,               /* a link or junction at the base: nothing was changed */
  UI_SVC_RP_UNSUPPORTED,        /* a service without the method */
  UI_SVC_RP_FAILED
} ui_svc_repair_kind;

/* The result of a successful service.repair_data reply: moved and healthy (a reply without healthy counts as healthy).
   A moved folder wins over a refused layout in the message. */
ui_svc_repair_kind ui_svc_repair_kind_of_reply(const sd_json *res);

/* The error code of a failed service.repair_data call (access_denied, busy, repair_refused, usage, ...). */
ui_svc_repair_kind ui_svc_repair_kind_of_error(const char *code);

/* The result of the in-process repair: refused is svc_repair_result.refused, win32 the error (0 = none). */
ui_svc_repair_kind ui_svc_repair_kind_of_direct(int refused, unsigned long win32, int moved);

#endif /* SD_UI_SERVICE_MODEL_H */
