/* shelldrive-ui: the measuring context of the in-memory dialogs (03 §7.1). The layout of ui_dlg needs the
 * height of wrapped text in dialog units: ui_measure_cb measures with DrawTextW and the message font at the
 * screen DPI, so localized text is never clipped. Shared by the prompt dialogs and the profile editor. */
#ifndef SD_UI_MEASURE_H
#define SD_UI_MEASURE_H

#include <windows.h>

#include "ui_dlg.h"

typedef struct ui_measure {
  HDC dc;
  HFONT font;
  HFONT old;
  int base_x;                        /* average character width, pixels */
  int base_y;                        /* text height, pixels */
} ui_measure;

/* Message font of the system (Segoe UI on Vista and later, Tahoma or MS Shell Dlg on XP), read with
   SystemParametersInfo and sized for the screen DPI (03 §7.1). */
void ui_message_font(wchar_t face[UI_DLG_FACE_MAX], WORD *points, int *dpi);
void ui_measure_init(ui_measure *m, const wchar_t *face, WORD points, int dpi);
void ui_measure_free(ui_measure *m);
int  ui_measure_cb(void *ctx, const wchar_t *text, int width_dlu, int *natural);

#endif /* SD_UI_MEASURE_H */
