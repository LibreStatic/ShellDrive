/* shelldrive-ui internals (03 §1.4, §7): the application state and the functions shared by main.c,
 * ui_ipc.c, ui_model.c, ui_tray.c, ui_main.c and ui_icon.c. Only the UI thread touches g_app; the IPC
 * thread talks to the UI thread through PostMessage (the messages below) and never reads g_app.
 *
 * Not in the design yet (TODO, tracked for the next packages): the mount dialog ("Mount..." is disabled),
 * the prompt host (prompts.ui is not declared), the profile editor, and the balloon rate limit of 7.7. */
#ifndef SD_UI_INT_H
#define SD_UI_INT_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_l10n/sd_l10n_catalog.h"
#include "ui_wire.h"

/* Messages posted to the control window (WM_APP range). */
#define UI_WM_IPC_STATE  (WM_APP + 1)   /* wParam: 1 agent connected, 0 disconnected */
#define UI_WM_IPC_LIST   (WM_APP + 2)   /* lParam: sd_json* result of "list" (owned by the UI) */
#define UI_WM_IPC_EVENT  (WM_APP + 3)   /* lParam: sd_json* event envelope (owned by the UI) */
#define UI_WM_IPC_REPLY  (WM_APP + 4)   /* lParam: ui_ipc_reply* (owned by the UI) */
#define UI_WM_TRAY       (WM_APP + 5)   /* tray icon callback: lParam is the mouse message */

/* Command ids of the tray menu and the main window controls. */
#define UI_CMD_OPEN          1001
#define UI_CMD_EXIT          1002
#define UI_CMD_UNMOUNT_BASE  2000       /* + index of the mount in the model */
#define UI_CMD_MOUNT         3001
#define UI_CMD_UNMOUNT       3002
#define UI_CMD_REFRESH       3003
#define UI_CTL_LIST          4001
#define UI_CTL_STATUS        4002

#define UI_MAX_MOUNTS 64

typedef enum ui_ipc_kind { UI_IPC_LIST, UI_IPC_UNMOUNT, UI_IPC_MOUNT } ui_ipc_kind;

typedef struct ui_ipc_reply {
  ui_ipc_kind kind;
  sd_err err;                   /* SD_OK on success */
  wchar_t drive[3];             /* UI_IPC_UNMOUNT: the drive asked for */
  sd_json *result;              /* may be NULL */
} ui_ipc_reply;

/* One mount as the agent reports it in "list" (03 §2.4). Identifiers are ASCII, text is UTF-16. */
typedef struct ui_mount {
  char id[40];                  /* mount_id */
  char state[24];               /* state token: connecting, mounted, ... */
  wchar_t state_w[24];          /* the same token in UTF-16, shown when the token is unknown */
  wchar_t drive[3];             /* "X:" */
  wchar_t profile[128];
  wchar_t backend[16];
  wchar_t server[280];          /* host, with ":port" when not 22 */
} ui_mount;

typedef struct ui_model {
  ui_mount items[UI_MAX_MOUNTS];
  size_t count;
} ui_model;

typedef struct ui_app {
  HINSTANCE inst;
  HWND ctrl;                    /* message-only window: IPC, tray callbacks, WM_COPYDATA */
  HWND main;                    /* main window, created hidden or shown */
  HWND list, status, btn_mount, btn_unmount, btn_refresh;
  HFONT font;
  unsigned dpi;                 /* DPI of the main window (ui_dpi_window) */
  UINT wm_taskbar;              /* "TaskbarCreated": the tray icon is added again */
  wchar_t class_ctrl[320];      /* com.librestatic.shelldrive.ui.<SID> */
  wchar_t class_main[320];      /* com.librestatic.shelldrive.ui.<SID>.main */
  HANDLE mutex;                 /* SD_IPC_OBJ_UI_MUTEX, held for the life of the first instance */
  int agent_up;
  int quit;
  int prompt_host;              /* started with --prompt-host: never starts the agent, exits without it */
  ui_model model;
} ui_app;

extern ui_app g_app;

/* ---- main.c ---- */
void ui_app_handle_request(const ui_request *req);
void ui_app_on_agent_state(int up);
void ui_app_on_list(sd_json *result);
void ui_app_on_event(sd_json *event);
void ui_app_on_reply(ui_ipc_reply *reply);
void ui_app_quit(void);

/* ---- ui_model.c: the mount list and text helpers ---- */
void        ui_text_utf8(const char *s, wchar_t *out, size_t cch);
void        ui_text_ascii(const wchar_t *s, char *out, size_t cch);
void        ui_model_clear(ui_model *m);
void        ui_model_set_list(ui_model *m, const sd_json *result);
ui_mount   *ui_model_find_id(ui_model *m, const char *id);
ui_mount   *ui_model_find_drive(ui_model *m, const wchar_t *drive);
void        ui_model_remove(ui_model *m, ui_mount *item);
const wchar_t *ui_model_state_text(const ui_mount *item);
/* Formats a catalog message with one string argument and one optional integer (count). */
wchar_t    *ui_format1(sd_msg_id msg_id, const char *name, const wchar_t *value);
wchar_t    *ui_format_count(sd_msg_id msg_id, long long count);

/* ---- ui_ipc.c: the agent client thread ---- */
sd_err ui_ipc_start(void);
void   ui_ipc_stop(void);
sd_err ui_ipc_list(void);
sd_err ui_ipc_unmount(const wchar_t *drive);
sd_err ui_ipc_mount(const char *profile_id);

/* ---- ui_tray.c: notification area icon ---- */
sd_err ui_tray_add(void);
void   ui_tray_remove(void);
void   ui_tray_readd(void);
void   ui_tray_update(void);
void   ui_tray_callback(LPARAM mouse_message);
void   ui_tray_balloon(const char *code, const wchar_t *drive);

/* ---- ui_main.c: the main window ---- */
int    ui_main_register_class(HINSTANCE inst, const wchar_t *class_name);
HWND   ui_main_create(HINSTANCE inst, const wchar_t *class_name, int visible);
void   ui_main_show(void);
void   ui_main_refresh(void);
int    ui_main_test_controls(void);

/* ---- ui_icon.c: programmatically drawn icons (no third-party art) ---- */
typedef enum ui_icon_kind { UI_ICON_IDLE = 0, UI_ICON_CONNECTED, UI_ICON_WARNING, UI_ICON_COUNT } ui_icon_kind;
HICON  ui_icon_get(ui_icon_kind kind, int size);
void   ui_icon_free_all(void);

#endif /* SD_UI_INT_H */
