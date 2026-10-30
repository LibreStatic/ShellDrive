/* shelldrive-ui: icons drawn in code (original art, no image files). Each state has its own shape as
 * well as a colour (03 §7.2): idle is a ring, connected a filled disc, warning a filled diamond.
 *
 * A colour icon is a 32-bpp DIB (alpha unused, the mask decides transparency) plus a 1-bpp AND mask,
 * which CreateIconIndirect accepts on XP and later. */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "ui_int.h"

#define UI_ICON_MAX_SIZE 64

/* Icons are never destroyed while the process runs: the window class and the tray keep using them. One
   entry per (kind, size); a DPI change adds an entry for the new size. */
#define UI_ICON_SLOTS 32
static struct {
  HICON icon;
  int kind;
  int size;
} g_cache[UI_ICON_SLOTS];

static unsigned rgb_for(ui_icon_kind kind)
{
  switch (kind) {
  case UI_ICON_CONNECTED: return 0x000078D4u;   /* blue */
  case UI_ICON_WARNING:   return 0x00F29F05u;   /* amber */
  default:                return 0x009A9A9Au;   /* grey */
  }
}

/* Inside test on doubled coordinates: the circle has radius size - 2 (in doubled units). */
static int inside(ui_icon_kind kind, int dx, int dy, int size)
{
  int r = size - 2;
  int d2 = dx * dx + dy * dy;
  int thick = 2 * (size / 8 > 0 ? size / 8 : 1);
  int ri = r - thick;
  switch (kind) {
  case UI_ICON_CONNECTED:
    return d2 <= r * r;
  case UI_ICON_WARNING: {
    int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
    return adx + ady <= r;
  }
  default:
    return d2 <= r * r && d2 >= ri * ri;
  }
}

static HICON draw_icon(ui_icon_kind kind, int size)
{
  BITMAPINFO bmi;
  void *bits = NULL;
  HDC dc;
  HBITMAP color, mask;
  ICONINFO info;
  HICON icon = NULL;
  int x, y, mask_stride;
  unsigned char *mbits;
  unsigned rgb = rgb_for(kind);
  uint32_t *px;

  memset(&bmi, 0, sizeof(bmi));
  bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bmi.bmiHeader.biWidth = size;
  bmi.bmiHeader.biHeight = -size;             /* top-down */
  bmi.bmiHeader.biPlanes = 1;
  bmi.bmiHeader.biBitCount = 32;
  bmi.bmiHeader.biCompression = BI_RGB;

  dc = GetDC(NULL);
  color = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
  ReleaseDC(NULL, dc);
  if (color == NULL || bits == NULL) {
    if (color)
      DeleteObject(color);
    return NULL;
  }
  px = (uint32_t *)bits;

  mask_stride = ((size + 15) / 16) * 2;       /* 1-bpp rows are WORD aligned */
  mbits = sd_alloc((size_t)mask_stride * (size_t)size);
  if (mbits == NULL) {
    DeleteObject(color);
    return NULL;
  }
  memset(mbits, 0xFF, (size_t)mask_stride * (size_t)size);   /* 1 = transparent */

  for (y = 0; y < size; y++) {
    for (x = 0; x < size; x++) {
      int dx = 2 * x - (size - 1), dy = 2 * y - (size - 1);
      if (inside(kind, dx, dy, size)) {
        px[y * size + x] = 0xFF000000u | rgb;
        mbits[y * mask_stride + x / 8] &= (unsigned char)~(0x80u >> (x % 8));
      } else {
        px[y * size + x] = 0;
      }
    }
  }

  mask = CreateBitmap(size, size, 1, 1, mbits);
  sd_free(mbits);
  if (mask != NULL) {
    memset(&info, 0, sizeof(info));
    info.fIcon = TRUE;
    info.hbmMask = mask;
    info.hbmColor = color;
    icon = CreateIconIndirect(&info);
    DeleteObject(mask);
  }
  DeleteObject(color);
  return icon;
}

HICON ui_icon_get(ui_icon_kind kind, int size)
{
  size_t i;
  unsigned k = (unsigned)kind;
  if (k >= UI_ICON_COUNT)
    k = UI_ICON_IDLE;
  if (size < 8)
    size = 8;
  if (size > UI_ICON_MAX_SIZE)
    size = UI_ICON_MAX_SIZE;
  for (i = 0; i < UI_ICON_SLOTS; i++)
    if (g_cache[i].icon != NULL && g_cache[i].kind == (int)k && g_cache[i].size == size)
      return g_cache[i].icon;
  for (i = 0; i < UI_ICON_SLOTS; i++) {
    if (g_cache[i].icon == NULL) {
      g_cache[i].icon = draw_icon((ui_icon_kind)k, size);
      g_cache[i].kind = (int)k;
      g_cache[i].size = size;
      return g_cache[i].icon;
    }
  }
  return NULL;
}

void ui_icon_free_all(void)
{
  size_t i;
  for (i = 0; i < UI_ICON_SLOTS; i++) {
    if (g_cache[i].icon)
      DestroyIcon(g_cache[i].icon);
    g_cache[i].icon = NULL;
    g_cache[i].size = 0;
  }
}
