/* shelldrive-ui: the Windows 11 tray flyout (06 §6.3, D47). See ui_flyout.c.
 *
 * Only on the Fluent tier at level 'b' or 'c' (build 22000+): a left click or Enter on the tray icon opens this small
 * window instead of the main window. The right click menu, and every other tier, keep the popup menu of ui_tray.c.
 * Only the UI thread calls these functions. */
#ifndef SD_UI_FLYOUT_H
#define SD_UI_FLYOUT_H

#include <windows.h>

/* 1 when the current theme shows the flyout (Fluent, level 'b' or 'c'). */
int  ui_flyout_wanted(void);
/* Opens the flyout above the tray icon; closes it when it is already open. Rows are rebuilt on each open. */
void ui_flyout_open(void);
void ui_flyout_close(void);
/* The mount list or the profiles changed: updates the open flyout in place (does nothing when closed). */
void ui_flyout_refresh(void);
/* Keyboard handling for the message loop (IsDialogMessage): 1 when the message was consumed. */
int  ui_flyout_filter(MSG *msg);
/* --test-flyout: creates the flyout hidden, checks the header and both buttons, destroys it. 1 on success. */
int  ui_flyout_smoke_test(void);

#endif /* SD_UI_FLYOUT_H */
