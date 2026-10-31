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

/* Vista and later (commctrl.h declares them only for those targets). */
#ifndef BS_COMMANDLINK
#define BS_COMMANDLINK    0x0000000EL
#define BS_DEFCOMMANDLINK 0x0000000FL
#endif

#define UI_DLG_MAX_ITEMS  40
#define UI_DLG_TEXT_MAX   512           /* UTF-16 units of one control text, no terminator */
#define UI_DLG_TITLE_MAX  256
#define UI_DLG_FACE_MAX   32            /* LF_FACESIZE */

typedef enum ui_dlg_class {
  UI_DLG_STATIC = 0,
  UI_DLG_EDIT,
  UI_DLG_BUTTON,
  UI_DLG_CHECK,
  UI_DLG_COMBO
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
  int min_height;                       /* dialog units: the height is at least this (pages of one sheet) */
  int heading_pct;                      /* size of the main instruction font relative to the dialog font, percent (0 = 100) */
  int command_links;                    /* 1: ui_dlg_commands builds BS_COMMANDLINK buttons, 0: plain push buttons */
  int icon_left, icon_bottom;           /* the icon column of ui_dlg_icon: content above icon_bottom is indented to icon_left */
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

/* The main instruction: static text like ui_dlg_text, laid out for a font heading_pct percent of the dialog font
   (the page sets the font and color at run time: ui_prompt.c). The measuring is scaled, so a larger font still
   fits its lines. */
sd_err ui_dlg_heading(ui_dlg *d, WORD id, const wchar_t *text, DWORD extra);

/* A 32 x 32 pixel icon static (SS_ICON) at the left of the next content; the page sets the icon with STM_SETICON.
   The text controls added while the cursor is above the icon's bottom are indented to its right. */
sd_err ui_dlg_icon(ui_dlg *d, WORD id);

/* Command links (Vista and later, command_links = 1): one BS_COMMANDLINK push button per choice, full width,
   stacked, each tall enough for its text and its note (notes[i] may be NULL; the page sets it with BCM_SETNOTE and
   re-measures with BCM_GETIDEALSIZE). With command_links = 0 these are the plain buttons of ui_dlg_buttons with
   the same texts and the notes are not shown. def_id: the default button (0 = none: trust decisions, TM-R03). */
sd_err ui_dlg_commands(ui_dlg *d, const WORD *ids, const wchar_t *const *texts, const wchar_t *const *notes,
                       size_t n, WORD def_id);

/* Single-line edit, full width. extra: ES_* bits (ES_PASSWORD, ES_READONLY). */
sd_err ui_dlg_edit(ui_dlg *d, WORD id, DWORD extra);

/* Read-only multi-line edit with a vertical scroll bar, height measured from text, at most max_lines. */
sd_err ui_dlg_multiline(ui_dlg *d, WORD id, const wchar_t *text, int max_lines);

/* Check box, full width. */
sd_err ui_dlg_check(ui_dlg *d, WORD id, const wchar_t *text);   /* starts unchecked; the caller sets BM_SETCHECK */

/* Drop-down list (CBS_DROPDOWNLIST), full width. The template height is the closed height of the box; the
   page code grows the box while the list is open (ui_editor.c, combo_resize). Items are added at run time. */
sd_err ui_dlg_combo(ui_dlg *d, WORD id);

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
#define UI_DLG_ICON_CX      22             /* 32 pixels at 96 DPI with a 9 pt font, in dialog units (x) */
#define UI_DLG_ICON_CY      18
#define UI_DLG_ICON_GAP     6
#define UI_DLG_LINK_PAD     8              /* top and bottom padding of a command link, dialog units */
#define UI_DLG_LINK_INDENT  14             /* left of a command link text (the arrow), dialog units */

#endif /* SD_UI_DLG_H */
