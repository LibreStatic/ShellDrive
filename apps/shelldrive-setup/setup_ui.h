/* shelldrive-setup: the wizard window (docs/design/04 §6.3, §6.5, §7.3, §13).
 *
 * One window with plain Win32 controls (BUTTON, STATIC, EDIT) and no common controls: the stub keeps the
 * KnownDLL-only import rule, and comctl32 is not a KnownDLL (tests/os-imports/knowndlls.txt). The pages come
 * from setup_flow.c; the texts come from the installer catalog (l10n/installer). Pages are built on demand
 * and destroyed when the user leaves them. The progress view and the finish page use the same window.
 *
 * Call order of an interactive install: run_pages (stops before the progress page), begin_progress, the engine
 * with status as its progress callback, finish (the final page). /passive calls begin_progress directly; /quiet
 * creates no window at all. */
#ifndef SD_SETUP_UI_H
#define SD_SETUP_UI_H

#include <windows.h>

#include "setup_core.h"
#include "setup_flow.h"

typedef struct sd_setup_ui sd_setup_ui;

/* What the user chose on the pages. */
typedef struct sd_setup_choices {
  sd_setup_mode mode;            /* SD_SETUP_MODE_USER or SD_SETUP_MODE_PORTABLE (MACHINE is never offered) */
  wchar_t portable_dir[MAX_PATH];
  int dokany;                    /* 1 when the Dokany checkbox is checked (D36) */
  int launch;                    /* the finish page: start ShellDrive */
} sd_setup_choices;

/* What the pages show before the user answers. */
typedef struct sd_setup_defaults {
  sd_setup_mode mode;            /* the mode given on the command line, or SD_SETUP_MODE_AUTO */
  const wchar_t *portable_dir;   /* suggested folder of a portable copy; "" for none */
  sd_setup_dokany_plan dokany_plan;
  const wchar_t *uninstall_dir;  /* folder named on the removal page */
} sd_setup_defaults;

/* Creates the window, visible and empty. Returns 0 or 1. */
int sd_setup_ui_create(HINSTANCE inst, const wchar_t *title, sd_setup_ui **out);

/* Runs the interactive pages from the first one of the flow up to the progress page (which is not built here),
   or the removal confirmation for in->uninstall. Returns 1 when the user chose to go on, 0 when they cancelled or
   closed the window. out receives the answers. */
int sd_setup_ui_run_pages(sd_setup_ui *ui, const sd_flow_input *in, const sd_setup_defaults *d,
                          sd_setup_choices *out);

/* Builds every page of the flow once, in order, without any answer: the page names are written to the setup log
   (event "test.page") and each page is destroyed again. *built gets the number of pages built. Returns 1 when
   every page was created (0 otherwise). Used by the hidden /test-pages switch: nothing is installed. */
int sd_setup_ui_test_pages(sd_setup_ui *ui, const sd_flow_input *in, const sd_setup_defaults *d, unsigned *built);

/* Shows the progress view (status line and bar). Used after run_pages, or directly for /passive. */
void sd_setup_ui_begin_progress(sd_setup_ui *ui);

/* Sets the status line and the progress percentage (0..100), then pumps pending messages. */
void sd_setup_ui_status(sd_setup_ui *ui, const wchar_t *text, unsigned percent);

/* Pumps pending messages. Returns 0 once the user has closed the window (a cancel request). */
int sd_setup_ui_pump(sd_setup_ui *ui);

/* Shows the finish page with text and waits for Finish. *launch gets the "Launch ShellDrive" checkbox. Returns 1
   after Finish, 0 when the window was closed. */
int sd_setup_ui_finish(sd_setup_ui *ui, const wchar_t *text, int *launch);

/* Modal message for the final result (or the error) of the operation. */
void sd_setup_ui_message(HWND owner, const wchar_t *title, const wchar_t *text, int is_error);

void sd_setup_ui_destroy(sd_setup_ui *ui);

#endif /* SD_SETUP_UI_H */
