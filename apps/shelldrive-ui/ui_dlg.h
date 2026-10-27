/* shelldrive-ui: in-memory dialog templates (03 §7.1).
 *
 * Dialogs are DLGTEMPLATEEX blobs built here from a small list of controls. The layout is a vertical stack
 * in dialog units: each text control is measured by a caller-supplied function (the real one measures with
 * DrawTextW and the dialog font, the tests use a fixed rule), so localized text is never clipped. The
 * dialog manager still owns the keyboard: tab order follows the order of the items, mnemonics and the
 * default and cancel buttons work through IsDialogMessage.
 *
 * Pure: no window or process calls; compiled into the unit tests (SD_UI_PURE_SOURCES). */
#ifndef SD_UI_DLG_H
#define SD_UI_DLG_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define UI_DLG_MAX_ITEMS  40
#define UI_DLG_TEXT_MAX   512           /* UTF-16 units of one control text, no terminator */
#define UI_DLG_TITLE_MAX  256
#define UI_DLG_FACE_MAX   32            /* LF_FACESIZE */

typedef enum ui_dlg_class {
  UI_DLG_STATIC = 0,
  UI_DLG_EDIT,
  UI_DLG_BUTTON,
  UI_DLG_CHECK
} ui_dlg_class;

typedef struct ui_dlg_item {
  ui_dlg_class cls;
  WORD id;
  DWORD style;                          /* WS_* / control style, without WS_CHILD or WS_VISIBLE */
  short x, y, cx, cy;                   /* dialog units, relative to the client area */
  wchar_t text[UI_DLG_TEXT_MAX + 1];
} ui_dlg_item;

/* Measures text in dialog units. width_dlu is the available width. Returns the height in dialog units
   of the wrapped text and writes the natural (unwrapped) width to *natural_dlu when non-NULL. */
typedef int (*ui_dlg_measure_fn)(void *ctx, const wchar_t *text, int width_dlu, int *natural_dlu);

typedef struct ui_dlg {
  wchar_t title[UI_DLG_TITLE_MAX + 1];
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points;                          /* font size in points */
  int width;                            /* dialog width in dialog units */
  int cursor;                           /* next free y, dialog units */
  int margin;                           /* left, right and bottom margin */
  DWORD style;                          /* dialog style, DS_SETFONT is added by ui_dlg_build */
  ui_dlg_measure_fn measure;
  void *measure_ctx;
  size_t count;
  ui_dlg_item items[UI_DLG_MAX_ITEMS];
} ui_dlg;

/* Starts a dialog. face/points: the dialog font (the message font of the system). */
sd_err ui_dlg_init(ui_dlg *d, const wchar_t *title, int width_dlu, const wchar_t *face, WORD points,
                   ui_dlg_measure_fn measure, void *measure_ctx);

/* Static text, full width, wrapped, measured. extra: SS_* style bits. */
sd_err ui_dlg_text(ui_dlg *d, WORD id, const wchar_t *text, DWORD extra);

/* Single-line edit, full width. extra: ES_* bits (ES_PASSWORD, ES_READONLY). */
sd_err ui_dlg_edit(ui_dlg *d, WORD id, DWORD extra);

/* Read-only multi-line edit with a vertical scroll bar, height measured from text, at most max_lines. */
sd_err ui_dlg_multiline(ui_dlg *d, WORD id, const wchar_t *text, int max_lines);

/* Check box, full width. */
sd_err ui_dlg_check(ui_dlg *d, WORD id, const wchar_t *text);   /* starts unchecked; the caller sets BM_SETCHECK */

/* Vertical space in dialog units. */
sd_err ui_dlg_space(ui_dlg *d, int dlu);

/* Push buttons, right aligned, in rows that wrap when they do not fit. def_id: BS_DEFPUSHBUTTON (0 = none). */
sd_err ui_dlg_buttons(ui_dlg *d, const WORD *ids, const wchar_t *const *texts, size_t n, WORD def_id);

/* Serializes the dialog: DLGTEMPLATEEX, WORD-aligned header and title, DWORD-aligned items. The dialog
   height is set to the cursor plus the bottom margin. Release *out with sd_free. */
sd_err ui_dlg_build(ui_dlg *d, unsigned char **out, size_t *out_bytes);

/* Offsets of the items of a built template, for the tests: returns the item count and fills the
   offsets (up to cap) of each DLGITEMTEMPLATEEX. Returns SD_E_INVALID_PARAM on a malformed blob. */
sd_err ui_dlg_parse_check(const unsigned char *blob, size_t bytes, size_t *count, size_t *offsets, size_t cap);

/* Dialog-unit helpers used by the layout (dialog units: x = base/4, y = base/8 pixels). */
#define UI_DLG_BUTTON_MIN   50
#define UI_DLG_EDIT_HEIGHT  14
#define UI_DLG_CHECK_HEIGHT 10
#define UI_DLG_BUTTON_HEIGHT 14
#define UI_DLG_GAP          4

#endif /* SD_UI_DLG_H */
