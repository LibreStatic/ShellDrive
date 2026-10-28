/* shelldrive-ui internals (03 §1.4, §7): the application state and the functions shared by main.c,
 * ui_ipc.c, ui_model.c, ui_tray.c, ui_main.c and ui_icon.c. Only the UI thread touches g_app; the IPC
 * thread talks to the UI thread through PostMessage (the messages below) and never reads g_app.
 *
 * The profile editor and the mount dialog (ui_editor.c), the profile list (ui_profiles.c), the import wizard
 * (ui_import.c), the .sdmount verb, the secondary windows of M3 (ui_win.h: host keys, Logs, Settings, About) and
 * the prompt host (prompts.ui, ui_prompt.c), the first-run wizard (ui_wizard.c), the balloon rate limit and queue
 * (ui_tray.c, ui_notify_model.c) and dark title bars (ui_dark.c) are in. Not yet: reconnect. */
#ifndef SD_UI_INT_H
#define SD_UI_INT_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n_catalog.h"
#include "ui_events_model.h"
#include "ui_wire.h"

/* Messages posted to the control window (WM_APP range). */
#define UI_WM_IPC_STATE  (WM_APP + 1)   /* wParam: 1 agent connected, 0 disconnected */
#define UI_WM_IPC_LIST   (WM_APP + 2)   /* lParam: sd_json* result of "list" (owned by the UI) */
#define UI_WM_IPC_EVENT  (WM_APP + 3)   /* lParam: sd_json* event envelope (owned by the UI) */
#define UI_WM_IPC_REPLY  (WM_APP + 4)   /* lParam: ui_ipc_reply* (owned by the UI) */
#define UI_WM_TRAY       (WM_APP + 5)   /* tray icon callback: lParam is the mouse message */
#define UI_WM_IPC_PROMPTS (WM_APP + 6)  /* lParam: sd_json* result of "prompt.list" (owned by the UI) */
#define UI_WM_SVC_ATTENTION (WM_APP + 7) /* wParam: count of prompts waiting for an administrator (ui_svc.c) */

/* Timer of the prompt host (--prompt-host): once a second, the idle exit of 60 s is counted. */
#define UI_TIMER_PROMPT_IDLE  1
#define UI_PROMPT_IDLE_MS     60000u
/* Timer of the queued balloons (7.7): once a second while balloons wait; ui_tray_flush shows the next one. */
#define UI_TIMER_NOTIFY       2

/* Command ids of the tray menu and the main window controls. */
#define UI_CMD_OPEN          1001
#define UI_CMD_EXIT          1002
#define UI_CMD_UNMOUNT_BASE  2000       /* + index of the mount in the model */
#define UI_CMD_MOUNT         3001
#define UI_CMD_UNMOUNT       3002
#define UI_CMD_REFRESH       3003
#define UI_CMD_NEW           3004
#define UI_CMD_EDIT          3005
#define UI_CMD_DELETE        3006
#define UI_CMD_DUPLICATE     3007
#define UI_CMD_OPEN_DRIVE    3008
#define UI_CMD_QUICK_MOUNT   3009
#define UI_CMD_IMPORT        3010
#define UI_CMD_ADMIN         1003       /* tray: relaunch elevated to answer the service prompts (ui_svc.c) */
#define UI_CMD_SECURITY      3011       /* Connection menu: the legacy and Terrapin details of the selected drive (ui_secdlg.c) */
#define UI_CTL_TOOLBAR       4003
#define UI_CTL_LIST          4001
#define UI_CTL_STATUS        4002

#define UI_MAX_MOUNTS 64

typedef enum ui_ipc_kind {
  UI_IPC_LIST, UI_IPC_UNMOUNT, UI_IPC_MOUNT, UI_IPC_ANSWER,
  UI_IPC_RELOAD,      /* config.reload (ui_ipc_config_reload, ui_settings.c) */
  UI_IPC_ANNOUNCED,   /* hostkey.announced.list (ui_hostkeys.c) */
  UI_IPC_ACCEPT,      /* hostkey.announced.accept (ui_hostkeys.c) */
  UI_IPC_LOG,         /* log.tail (ui_logs.c) */
  UI_IPC_UPDATE_CHECK, /* update.check (ui_update.c) */
  UI_IPC_UPDATE_APPLY, /* update.apply, consent true (ui_update.c) */
  UI_IPC_HK_ADD,       /* hostkey.add (ui_hostkeys.c): the agent connects to the server, which can take a while */
  UI_IPC_HK_REJECT     /* hostkey.announced.reject (ui_hostkeys.c): a declined offer leaves the announcements */
} ui_ipc_kind;

typedef struct ui_ipc_reply {
  ui_ipc_kind kind;
  sd_err err;                   /* SD_OK on success */
  wchar_t drive[3];             /* UI_IPC_UNMOUNT: the drive asked for */
  sd_json *result;              /* may be NULL */
} ui_ipc_reply;

/* One mount as the agent reports it in "list" (03 §2.4). Identifiers are ASCII, text is UTF-16. */
typedef struct ui_mount {
  char id[40];                  /* mount_id */
  char profile_id[33];          /* profile_id of the list item; "" for an ad-hoc mount */
  char state[24];               /* state token: connecting, mounted, ... */
  wchar_t state_w[24];          /* the same token in UTF-16, shown when the token is unknown */
  wchar_t drive[3];             /* "X:" */
  wchar_t profile[128];
  wchar_t backend[16];
  wchar_t server[280];          /* host, with ":port" when not 22 */
  char host[128];               /* host as the agent reports it, printable ASCII (dialogs of the main window) */
  char session[24];             /* connection.session ("" when the agent sent none), for the Reconnecting status */
  int attempt;                  /* connection.attempt */
  unsigned sec;                 /* UI_MV_SEC_* bits: legacy_algorithms and terrapin_exposed warnings (7.6) */
  char algos[256];              /* comma-joined algorithm names of the last legacy_algorithms warning, "" if unseen */
} ui_mount;

typedef struct ui_model {
  ui_mount items[UI_MAX_MOUNTS];
  size_t count;
} ui_model;

typedef struct ui_app {
  HINSTANCE inst;
  HWND ctrl;                    /* message-only window: IPC, tray callbacks, WM_COPYDATA */
  HWND main;                    /* main window, created hidden or shown */
  HWND list, status, toolbar;   /* toolbar: text buttons New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs (7.5) */
  HFONT font;
  unsigned dpi;                 /* DPI of the main window (ui_dpi_window) */
  UINT wm_taskbar;              /* "TaskbarCreated": the tray icon is added again */
  wchar_t class_ctrl[320];      /* com.librestatic.shelldrive.ui.<SID> */
  wchar_t class_main[320];      /* com.librestatic.shelldrive.ui.<SID>.main */
  HANDLE mutex;                 /* SD_IPC_OBJ_UI_MUTEX, held for the life of the first instance */
  int agent_up;
  int agent_features;           /* UI_FEAT_* of the connected agent (hello), 0 when none */
  int notify_on;                /* [ui] notify (settings.ini): balloons other than write_failed are shown when set */
  int quit;
  int prompt_host;              /* --prompt-host: prompt dialogs and tray only, no main window, never starts the agent */
  unsigned idle_ms;             /* prompt host: time without an open prompt (UI_PROMPT_IDLE_MS exits) */
  int elevated_admin;           /* --elevated-admin: service prompts only (ui_svc.c), no agent, no tray, prompt_host set too */
  int elevated_service;         /* --elevated-service: only the Service page (ui_service.c), no agent, no tray, no main window */
  int user_admin;               /* the logged-on user is an administrator (linked token on Vista+), see ui_svc_user_is_admin */
  int attention;                /* prompts waiting for an administrator on the service (0 unless user_admin) */
  ui_model model;
} ui_app;

extern ui_app g_app;

/* ---- main.c ---- */
void ui_app_handle_request(const ui_request *req);
void ui_app_on_attention(int count);
void ui_app_on_agent_state(int up);
void ui_app_on_list(sd_json *result);
void ui_app_on_event(sd_json *event);
void ui_app_on_reply(ui_ipc_reply *reply);
void ui_app_quit(void);
void ui_app_on_prompt_list(sd_json *result);
void ui_app_on_timer(UINT_PTR id);

/* ---- ui_model.c: the mount list and text helpers ---- */
void        ui_text_utf8(const char *s, wchar_t *out, size_t cch);
void        ui_text_ascii(const wchar_t *s, char *out, size_t cch);
void        ui_model_clear(ui_model *m);
void        ui_model_set_list(ui_model *m, const sd_json *result);
ui_mount   *ui_model_find_id(ui_model *m, const char *id);
ui_mount   *ui_model_find_drive(ui_model *m, const wchar_t *drive);
void        ui_model_remove(ui_model *m, ui_mount *item);
/* connection.session and connection.attempt of a list item or a mount.state event. */
void        ui_model_set_connection(ui_mount *it, const sd_json *data);
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
/* mount with the complete params object of 03 §2.4 (ui_mount_params_json). */
sd_err ui_ipc_mount_params(const char *json);
/* config.reload: the agent re-reads the profiles after a save or delete (03 §2.4, decision 3). */
sd_err ui_ipc_config_reload(void);
/* prompt.answer, see ui_ipc.c: the JSON is copied; the caller wipes its own copy. */
sd_err ui_ipc_answer(const char *json, size_t len);
/* Generic call for the secondary windows: the reply comes back as UI_WM_IPC_REPLY with this kind. params may be
   NULL. */
sd_err ui_ipc_call(ui_ipc_kind kind, const char *method, const char *params);

/* ---- ui_svc.c: the service pipe client (03 §2.6 rule 3): the attention watch of administrators and the
   elevated admin mode (--elevated-admin). Neither starts the service. ---- */
/* admin 0: the attention watch (subscribes to attention only). admin 1: prompts and answers (prompts.ui). */
sd_err ui_svc_start(int admin);
void   ui_svc_stop(void);
/* prompt.answer on the service pipe (admin mode). The JSON is copied; the caller wipes its own copy. */
sd_err ui_svc_answer(const char *json, size_t len);
/* 1 when the logged-on user is a member of BUILTIN\Administrators (the linked, elevated token on Vista and later). */
int    ui_svc_user_is_admin(void);
/* Relaunches this executable with --elevated-admin (UAC on Vista and later). Returns 1 when one is running or
   was started; the window owner gets a message only when the launch itself fails. */
int    ui_svc_launch_admin(HWND owner);
/* 1 when this process has the full administrator token (TokenElevation on Vista and later; the administrator check on XP). */
int    ui_svc_process_elevated(void);
/* Relaunches this executable with --elevated-service: the Service page alone, in an elevated process. Same return rules. */
int    ui_svc_launch_service_page(HWND owner);

/* ---- ui_tray.c: notification area icon ---- */
sd_err ui_tray_add(void);
void   ui_tray_remove(void);
void   ui_tray_readd(void);
void   ui_tray_update(void);
void   ui_tray_callback(LPARAM mouse_message);
void   ui_tray_balloon(const char *code, const wchar_t *drive);
/* Balloon with one catalog message; arg fills the placeholder called name ("drive" or "profile"). */
void   ui_tray_notify_msg(sd_msg_id msg, const char *name, const wchar_t *arg);
/* Balloon with a text the caller formatted; msg names the kind (the balloon click and the rate limit use it). */
void   ui_tray_notify_text(sd_msg_id msg, const wchar_t *subject, const wchar_t *text);
/* hostkeys.announced: the balloon "example.org offered new host keys. Review" when notifications are on. */
void   ui_tray_on_hostkeys_announced(const sd_json *data);
/* Shows the next queued balloon that the rate limit allows (UI_TIMER_NOTIFY, once a second). */
void   ui_tray_flush(void);

/* ---- ui_prompt.c: prompt dialogs (03 §2.5, §5.2, §7.6) ---- */
void   ui_prompt_on_request(const sd_json *data);
void   ui_prompt_on_closed(const char *prompt_id, const char *reason);
void   ui_prompt_on_list(const sd_json *result);
void   ui_prompt_close_all(void);
size_t ui_prompt_count(void);
int    ui_prompt_filter(MSG *msg);
int    ui_prompt_smoke_test(void);

/* ---- ui_profiles.c: the profile list and the .sdmount file ---- */
sd_err                 ui_profiles_load(void);
void                   ui_profiles_clear(void);
size_t                 ui_profiles_count(void);
const sd_profile      *ui_profiles_at(size_t i);
const sd_profile      *ui_profiles_find_id(const char *id);
sd_err                 ui_sdmount_read(const wchar_t *path, unsigned char *buf, size_t cap, size_t *len);
int                    ui_file_has_mark(const wchar_t *path);

/* ---- ui_editor.c: the profile editor, the mount dialog and the confirmation dialog (03 §7.5) ---- */
typedef enum ui_edit_mode { UI_EDIT_NEW = 0, UI_EDIT_EDIT, UI_EDIT_ADHOC } ui_edit_mode;
/* Runs the editor (modal, owner may be NULL). p is the profile in and out. Returns 1 when the user chose OK
   and every field is valid; the caller saves. */
int    ui_editor_run(HWND owner, ui_edit_mode mode, sd_profile *p);
/* Yes/No question; default_yes puts the default button on Yes. yes_id/no_id are catalog ids. */
int    ui_confirm(HWND owner, sd_msg_id title, sd_msg_id text_id, const wchar_t *arg, sd_msg_id yes_id,
                  sd_msg_id no_id, int default_yes);
/* The import dialog (PuTTY sessions or the OpenSSH config) with its preview; owner may be NULL. */
void   ui_import_run(HWND owner);
/* Creates every page of every editor mode hidden and destroys it (--test-editor). */
int    ui_editor_smoke_test(void);

/* ---- ui_main.c: the main window ---- */
int    ui_main_register_class(HINSTANCE inst, const wchar_t *class_name);
HWND   ui_main_create(HINSTANCE inst, const wchar_t *class_name, int visible);
void   ui_main_show(void);
void   ui_main_refresh(void);
int    ui_main_test_controls(void);
/* The selected profile of the list (NULL when none), and its mount (NULL when not mounted). */
const sd_profile *ui_main_selected_profile(void);
ui_mount         *ui_main_selected_mount(void);
void   ui_main_reload_profiles(void);
/* Shows a drive in Explorer (ShellExecuteW "explore"); drive is "X:". */
void   ui_open_drive(const wchar_t *drive);

/* ---- ui_hkissue.c: changed host key and wrong key type (03 §5.2, §5.4, TM-R04) ---- */
/* A mount.state event with an error: when it is host_key_mismatch or host_key_type_unavailable the balloon is raised (it
   cannot be disabled, 7.7) and the details are kept for the click. The drive is the mount's drive letter ("" if none). */
void   ui_hkissue_on_mount_state(const sd_json *data, const char *host, const wchar_t *drive);
/* The click on the balloon of the last issue: the details dialog of a changed key, the host key manager for a key type. */
void   ui_hkissue_open_last(void);
/* --test-windows: the dialog template builds and parses for every source. */
int    ui_hkissue_smoke(void);

/* ---- ui_secdlg.c: the legacy and Terrapin details dialog (03 §7.6) ---- */
/* Shows the details of the mount on drive ("X:"); modal over owner. A drive without a security warning shows nothing. */
void   ui_secdlg_open(HWND owner, const wchar_t *drive);
/* The mount of a pending "Refuse ... and reconnect" has been unmounted: mounts the profile again. */
void   ui_secdlg_on_unmounted(const char *profile_id);
int    ui_secdlg_smoke(void);

/* ---- ui_icon.c: programmatically drawn icons (no third-party art) ---- */
typedef enum ui_icon_kind { UI_ICON_IDLE = 0, UI_ICON_CONNECTED, UI_ICON_WARNING, UI_ICON_COUNT } ui_icon_kind;
HICON  ui_icon_get(ui_icon_kind kind, int size);
void   ui_icon_free_all(void);

/* ---- ui_events.c: the event list (03 §7.7) ---- */
/* Records one event (a notification, shown or not) in the list of the Events window; the time is now. */
void   ui_events_record(ui_ev_kind kind, const wchar_t *subject, const wchar_t *text);
size_t ui_events_count(void);

#endif /* SD_UI_INT_H */
