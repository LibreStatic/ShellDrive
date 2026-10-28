/* shelldrive-ui: the secondary windows of M3 (03 §5.1, §5.6, §3.2, §7.5, §10): the host key manager, the Logs
 * viewer, Settings and About. They are opened from the main window's menu and from the tray menu, one window per
 * kind. ui_win.c holds the shared helpers and the glue the main window calls (replies, events, agent state);
 * each window has its own file (ui_hostkeys.c, ui_logs.c, ui_settings.c, ui_about.c).
 *
 * Only the UI thread calls these functions. The IPC thread never touches a window: replies arrive as
 * ui_windows_on_reply through the control window, exactly like list and prompt replies (ui_ipc.c). */
#ifndef SD_UI_WIN_H
#define SD_UI_WIN_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_l10n/sd_l10n.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0      /* not in the SDK 7.1A headers of the XP flavours */
#endif

/* Agent features this UI uses (the hello reply, 03 §2.8). Bits of g_app.agent_features. */
#define UI_FEAT_LOG_TAIL  (1u << 0)    /* log.tail: the Logs viewer */
#define UI_FEAT_RELOAD    (1u << 1)    /* config.reload: Settings applies the saved file */
#define UI_FEAT_UPDATE    (1u << 2)    /* update.check: the update group of Settings is enabled */
#define UI_FEAT_UPDATE_APPLY (1u << 3) /* update.apply: "Install update" is offered */

/* Menu and tray command ids of the secondary windows (ui_int.h keeps the others). */
#define UI_CMD_HOSTKEYS   3101
#define UI_CMD_LOGS       3102
#define UI_CMD_SETTINGS   3103
#define UI_CMD_ABOUT      3104
#define UI_CMD_SERVICE    3105
#define UI_CMD_EVENTS     3106

/* ---- ui_win.c: shared helpers ---- */
/* Message font of the system at dpi; the caller deletes it. */
HFONT  ui_win_font(unsigned dpi);
/* Pixel width of one line of text in font. */
int    ui_win_text_width(HFONT font, const wchar_t *text);
/* "<control window class>.<suffix>" of a secondary window class. */
void   ui_win_class_name(const wchar_t *suffix, wchar_t out[320]);
/* Registers a window class once; true when it exists afterwards. */
int    ui_win_register(HINSTANCE inst, const wchar_t *name, WNDPROC proc);
/* Message box titled ShellDrive. */
void   ui_win_message(HWND owner, const wchar_t *text, UINT flags);
/* Error message box: the catalog message msg with {code} = the sd_err name. */
void   ui_win_error(HWND owner, sd_msg_id msg, sd_err err);
/* Copies text to the clipboard as CF_UNICODETEXT. */
int    ui_win_copy_text(HWND owner, const wchar_t *text, size_t len);
/* Sets the font of every child of wnd. */
void   ui_win_apply_font(HWND wnd, HFONT font);

/* ---- ui_win.c: glue used by the main window and the control window ---- */
void   ui_windows_command(UINT cmd);
void   ui_windows_on_reply(int kind, sd_err err, const sd_json *result);
void   ui_windows_on_event(const char *name, const sd_json *data);
void   ui_windows_on_agent_state(int up);
void   ui_windows_close_all(void);
/* Replies and events of the updater (ui_update.c), dispatched from ui_windows_on_reply and ui_windows_on_event. */
/* Creates every secondary window hidden, checks it and destroys it (--test-windows). 1 when all were created. */
int    ui_windows_smoke_test(void);

/* ---- ui_hostkeys.c: the host key manager (03 §5.1, §5.5, §5.6) ---- */
void   ui_hostkeys_open(void);
void   ui_hostkeys_open_for(const char *host);   /* opens the manager with the first key of host selected */
void   ui_hostkeys_close(void);
void   ui_hostkeys_on_reply(int kind, sd_err err, const sd_json *result);
void   ui_hostkeys_on_event(void);
void   ui_hostkeys_on_agent_state(int up);
HWND   ui_hostkeys_create_hidden(void);
int    ui_hostkeys_dialogs_smoke(void);   /* --test-windows: the two Add key from server dialogs build */

/* ---- ui_logs.c: the Logs viewer (03 §10, §2.4.1) ---- */
void   ui_logs_open(void);
void   ui_logs_close(void);
void   ui_logs_on_reply(sd_err err, const sd_json *result);
void   ui_logs_on_agent_state(int up);
HWND   ui_logs_create_hidden(void);

/* ---- ui_settings.c: the Settings window (03 §3.2, §7.5) ---- */
void   ui_settings_open(void);
void   ui_settings_close(void);
void   ui_settings_on_reply(int kind, sd_err err, const sd_json *result);
void   ui_settings_update_refresh(void);     /* the update group: status, enabled controls (ui_update.c) */
int    ui_settings_update_controls_ok(void); /* --test-windows: the update group controls exist */
int    ui_settings_security_smoke(void);    /* --test-windows: security controls, policy locks, WebClient text */
HWND   ui_settings_create_hidden(void);

/* ---- ui_service.c: the Service page (03 §1.3, §2.4 service.status / service.repair_data) ---- */
void   ui_service_open(void);
void   ui_service_close(void);
HWND   ui_service_create_hidden(void);
int    ui_service_is_open(void);
int    ui_service_controls_ok(void);       /* --test-windows: the controls exist, Repair data is off for a non-admin */

/* ---- ui_about.c: the About window ---- */
void   ui_about_open(void);
void   ui_about_close(void);
HWND   ui_about_create_hidden(void);

/* ---- ui_events.c: the event list window (03 §7.7) ---- */
void   ui_events_open(void);
void   ui_events_close(void);
HWND   ui_events_create_hidden(void);
int    ui_events_controls_ok(void);        /* --test-windows: rows follow the record, the search and Clear */

#endif /* SD_UI_WIN_H */
