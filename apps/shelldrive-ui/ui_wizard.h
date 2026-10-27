/* shelldrive-ui: the first-run wizard (03 §5.5, §7.5).
 *
 * A PropertySheet in wizard style (PSH_WIZARD97, XP and later) with five in-memory pages: welcome, how drives are shown
 * (Dokany or WebDAV), import (ui_import.c), create the first profile (the profile editor) and finish. It opens once,
 * when there are no profiles and the UI was not started for the tray or as a prompt host (ui_wizard_model.c). Closing
 * it, by Finish or Cancel, sets [ui] first_run_done = yes in settings.ini so it is not shown again.
 *
 * Only the UI thread calls these functions. */
#ifndef SD_UI_WIZARD_H
#define SD_UI_WIZARD_H

#include <windows.h>

/* [ui] first_run_done in settings.ini: 1 when the wizard was finished or closed before. */
int  ui_wizard_first_run_done(void);
/* Writes [ui] first_run_done = yes (under config.lock; other settings and comments are kept). */
void ui_wizard_mark_done(void);
/* Opens the wizard when ui_wizard_should_show says so. owner may be NULL. */
void ui_wizard_run_if_needed(HWND owner, int tray_mode, int prompt_host);
/* Runs the wizard now (modal). */
void ui_wizard_run(HWND owner);
/* Creates every page hidden and destroys it (--test-wizard). 1 when all were created. */
int  ui_wizard_smoke_test(void);

#endif /* SD_UI_WIZARD_H */
