/* shelldrive-ui: the first-run wizard decision (03 §7.5).
 *
 * The wizard opens when the user has no saved profiles, the UI was not started for the tray (--tray) or as a prompt
 * host, and the wizard has not been finished or closed before ([ui] first_run_done = yes in settings.ini). Once it
 * has been shown, it is not shown again, even when the user later deletes every profile.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_WIZARD_MODEL_H
#define SD_UI_WIZARD_MODEL_H

#include <windows.h>

#include "sd/base.h"

/* 1 when the wizard must open now. profile_count: profiles read from the store. first_run_done: the settings flag.
   tray_mode: --tray. prompt_host: --prompt-host (never a setup window). */
int ui_wizard_should_show(size_t profile_count, int first_run_done, int tray_mode, int prompt_host);

#endif /* SD_UI_WIZARD_MODEL_H */
