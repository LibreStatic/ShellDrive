/* shelldrive-setup: the page flow of the wizard (docs/design/04 §6.3, §6.5, §7.3, §13).
 *
 * Pure: no window or process calls, so the tests (tests/setup) build this file on its own. The window
 * (setup_ui.c) asks the flow for the page after the current one and shows what it returns; the answers
 * the user gives (the mode, the folder) are passed back in sd_flow_choice before the next question.
 *
 * Which pages show, in short:
 *   /quiet                 no page at all (SD_FLOW_NONE first)
 *   /passive               the progress page only
 *   /uninstall             the removal confirmation, then progress
 *   install, interactive   welcome, license, mode (unless /peruser, /portable or /permachine was given),
 *                          destination (portable without a folder), Dokany (all users only), progress, finish
 *
 * The mode page offers the all-users choice disabled in this build (SD_FLOW_MACHINE_AVAILABLE = 0): the
 * engine refuses per-machine installs today (setup_install.c, the MSI is not in this milestone). The Dokany
 * page is therefore reached only by a test (/test-pages /permachine) until that changes. */
#ifndef SD_SETUP_FLOW_H
#define SD_SETUP_FLOW_H

#include <windows.h>

#include "setup_core.h"
#include "sd_l10n_installer_ids.h"

/* Per-machine installs are refused by the engine in this build (04 §6.3, 6.10). Flip when the MSI lands. */
#define SD_FLOW_MACHINE_AVAILABLE 0

typedef enum sd_flow_page {
  SD_FLOW_NONE = 0,              /* no more pages: the caller goes on with the work */
  SD_FLOW_WELCOME,
  SD_FLOW_LICENSE,
  SD_FLOW_MODE,
  SD_FLOW_DESTINATION,
  SD_FLOW_DOKANY,
  SD_FLOW_PROGRESS,
  SD_FLOW_FINISH,
  SD_FLOW_UNINSTALL
} sd_flow_page;

/* What the command line fixes. */
typedef struct sd_flow_input {
  int quiet;
  int passive;
  int uninstall;                 /* the removal (uninstall.exe, /uninstall) */
  int mode_given;                /* /peruser, /permachine or /portable: the mode page is skipped */
  int dest_given;                /* /portable=<folder>: the destination page is skipped */
} sd_flow_input;

/* What the user chose on the pages so far. mode is SD_SETUP_MODE_USER, _MACHINE or _PORTABLE. */
typedef struct sd_flow_choice {
  sd_setup_mode mode;
} sd_flow_choice;

/* The page a run starts with: SD_FLOW_NONE for /quiet, SD_FLOW_PROGRESS for /passive. */
sd_flow_page sd_flow_first(const sd_flow_input *in);

/* The page after cur, given the choices so far. SD_FLOW_NONE after the last page. */
sd_flow_page sd_flow_next(const sd_flow_input *in, const sd_flow_choice *c, sd_flow_page cur);

/* The state of the Dokany checkbox for a plan (sd_setup_dokany_decide). note is the catalog message to show
   under the checkbox, or 0 for none. */
typedef struct sd_flow_dokany_view {
  int enabled;
  int checked;
  int has_note;                  /* note is set; message id 0 is a real id (the window title), so a flag */
  sd_msg_id note;
} sd_flow_dokany_view;

void sd_flow_dokany_view_of(sd_setup_dokany_plan plan, sd_flow_dokany_view *v);

/* Catalog message of a page's title. Returns 1 with *id set, or 0 for a page without one (SD_FLOW_NONE).
   Message id 0 is a real id (SD_MSG_INSTALLER_WINDOW_TITLE), so the result is a flag, not the id. */
int sd_flow_page_title(sd_flow_page p, sd_msg_id *id);

/* Short name of a page for the setup log and the test (pure ASCII). */
const char *sd_flow_page_name(sd_flow_page p);

#endif /* SD_SETUP_FLOW_H */
