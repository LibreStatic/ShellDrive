/* shelldrive-ui: dialog text measurement (ui_measure.h). */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "ui_measure.h"

/* ---- measurement (the dialog font of the current DPI) ---- */

int ui_measure_cb(void *ctx, const wchar_t *text, int width_dlu, int *natural)
{
  ui_measure *m = (ui_measure *)ctx;
  RECT r;
  int px_w = width_dlu * m->base_x / 4;
  int h;
  SetRect(&r, 0, 0, px_w, 0);
  DrawTextW(m->dc, text, -1, &r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
  h = (r.bottom * 8 + m->base_y - 1) / m->base_y;
  if (natural != NULL) {
    RECT one;
    SetRect(&one, 0, 0, 0, 0);
    DrawTextW(m->dc, text, -1, &one, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    *natural = (one.right * 4 + m->base_x - 1) / m->base_x;
  }
  return h;
}

/* Message font of the system (Segoe UI on Vista and later, Tahoma or MS Shell Dlg on XP), read with
   SystemParametersInfo and sized for the screen DPI (03 §7.1). */
void ui_message_font(wchar_t face[UI_DLG_FACE_MAX], WORD *points, int *dpi)
{
  NONCLIENTMETRICSW ncm;
  HDC screen = GetDC(NULL);
  int d = screen != NULL ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
  if (screen != NULL)
    ReleaseDC(NULL, screen);
  if (d <= 0)
    d = 96;
  wcscpy_s(face, UI_DLG_FACE_MAX, L"MS Shell Dlg");
  *points = 8;
  memset(&ncm, 0, sizeof(ncm));
  ncm.cbSize = sizeof(ncm);
  if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
    wcsncpy_s(face, UI_DLG_FACE_MAX, ncm.lfMessageFont.lfFaceName, _TRUNCATE);
    if (ncm.lfMessageFont.lfHeight != 0) {
      int pt = MulDiv(-ncm.lfMessageFont.lfHeight, 72, d);
      if (pt > 0 && pt < 72)
        *points = (WORD)pt;
    }
  }
  *dpi = d;
}

void ui_measure_init(ui_measure *m, const wchar_t *face, WORD points, int dpi)
{
  LOGFONTW lf;
  TEXTMETRICW tm;
  SIZE sz;
  static const wchar_t alpha[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  memset(m, 0, sizeof(*m));
  m->dc = CreateCompatibleDC(NULL);
  memset(&lf, 0, sizeof(lf));
  lf.lfHeight = -MulDiv((int)points, dpi, 72);
  lf.lfCharSet = DEFAULT_CHARSET;
  lf.lfQuality = DEFAULT_QUALITY;
  wcsncpy_s(lf.lfFaceName, SD_COUNTOF(lf.lfFaceName), face, _TRUNCATE);
  m->font = CreateFontIndirectW(&lf);
  m->old = (HFONT)SelectObject(m->dc, m->font);
  GetTextMetricsW(m->dc, &tm);
  GetTextExtentPoint32W(m->dc, alpha, (int)wcslen(alpha), &sz);
  m->base_x = (sz.cx + 26) / 52;
  m->base_y = tm.tmHeight > 0 ? tm.tmHeight : 12;
  if (m->base_x < 1)
    m->base_x = 1;
}

void ui_measure_free(ui_measure *m)
{
  if (m->dc != NULL) {
    SelectObject(m->dc, m->old);
    DeleteDC(m->dc);
  }
  if (m->font != NULL)
    DeleteObject(m->font);
  memset(m, 0, sizeof(*m));
}

