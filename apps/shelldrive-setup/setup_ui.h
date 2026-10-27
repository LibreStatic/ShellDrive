/* shelldrive-setup: the minimal progress window of the stub (04 §6, frontend note).
 *
 * This is deliberately small. The setup pages (mode choice, options, Dokany, language) belong to the
 * frontend, which replaces this file with the same interface: the engine (setup_core.h) only needs a
 * progress callback and a place to show the final message. Text comes from the installer catalog. */
#ifndef SD_SETUP_UI_H
#define SD_SETUP_UI_H

#include <windows.h>

typedef struct sd_setup_ui sd_setup_ui;

/* Creates the window, visible and empty. Returns 0 or 1. */
int sd_setup_ui_create(HINSTANCE inst, const wchar_t *title, sd_setup_ui **out);

/* Sets the status line and the progress percentage (0..100), then pumps pending messages. */
void sd_setup_ui_status(sd_setup_ui *ui, const wchar_t *text, unsigned percent);

/* Pumps pending messages. Returns 0 once the user has closed the window (a cancel request). */
int sd_setup_ui_pump(sd_setup_ui *ui);

/* Modal message for the final result (or the error) of the operation. */
void sd_setup_ui_message(HWND owner, const wchar_t *title, const wchar_t *text, int is_error);

void sd_setup_ui_destroy(sd_setup_ui *ui);

#endif /* SD_SETUP_UI_H */
