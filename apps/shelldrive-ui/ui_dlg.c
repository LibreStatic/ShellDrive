/* shelldrive-ui: in-memory dialog templates (03 §7.1). See ui_dlg.h.
 *
 * Binary layout (DLGTEMPLATEEX, wDlgVer 1):
 *   header: WORD ver, WORD 0xFFFF, DWORD help, DWORD exstyle, DWORD style, WORD count, short x y cx cy,
 *           WORD menu (0), WORD class (0), WSTR title, [DS_SETFONT] WORD points, WORD weight, BYTE italic,
 *           BYTE charset, WSTR face; then padding to DWORD.
 *   item:   DWORD help, DWORD exstyle, DWORD style, short x y cx cy, DWORD id, WORD 0xFFFF, WORD class
 *           ordinal (0x80 button, 0x81 edit, 0x82 static), WSTR text, WORD 0 (no creation data); then padding
 *           to DWORD before the next item.
 * ui_dlg_parse_check walks the blob with the same rules the dialog manager uses. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "ui_dlg.h"

#define DLG_SIGNATURE    0xFFFFu
#define DLG_VERSION      1u
#define CLASS_BUTTON     0x0080u
#define CLASS_EDIT       0x0081u
#define CLASS_STATIC     0x0082u
#define CLASS_COMBO      0x0085u
#define DLG_MIN_TEXT_DLU 8
#define DLG_TEXT_PAD     2
#define DLG_BUTTON_PAD   8
#define DLG_DEFAULT_MARGIN 7

/* ---- growable byte buffer over sd_alloc ---- */

typedef struct dbuf {
  unsigned char *p;
  size_t len, cap;
  int err;
} dbuf;

static void db_reserve(dbuf *b, size_t extra)
{
  size_t need = b->len + extra, cap;
  unsigned char *np;
  if (b->err || need <= b->cap)
    return;
  cap = b->cap ? b->cap : 256;
  while (cap < need)
    cap *= 2;
  np = (unsigned char *)sd_realloc(b->p, cap);
  if (np == NULL) {
    b->err = 1;
    return;
  }
  b->p = np;
  b->cap = cap;
}

static void db_u8(dbuf *b, unsigned v)
{
  db_reserve(b, 1);
  if (!b->err)
    b->p[b->len++] = (unsigned char)(v & 0xFFu);
}

static void db_u16(dbuf *b, unsigned v)
{
  db_u8(b, v & 0xFFu);
  db_u8(b, (v >> 8) & 0xFFu);
}

static void db_u32(dbuf *b, unsigned long v)
{
  db_u16(b, (unsigned)(v & 0xFFFFul));
  db_u16(b, (unsigned)((v >> 16) & 0xFFFFul));
}

static void db_wstr(dbuf *b, const wchar_t *s)
{
  size_t i, n = s ? wcslen(s) : 0;
  for (i = 0; i < n; i++)
    db_u16(b, (unsigned)(unsigned short)s[i]);
  db_u16(b, 0);
}

static void db_align4(dbuf *b)
{
  while (b->len % 4 != 0)
    db_u8(b, 0);
}

/* ---- builder ---- */

sd_err ui_dlg_init(ui_dlg *d, const wchar_t *title, int width_dlu, const wchar_t *face, WORD points,
                   ui_dlg_measure_fn measure, void *measure_ctx)
{
  if (d == NULL || measure == NULL || width_dlu < 100 || width_dlu > 1000)
    return SD_E_INVALID_PARAM;
  memset(d, 0, sizeof(*d));
  wcsncpy_s(d->title, SD_COUNTOF(d->title), title ? title : L"", _TRUNCATE);
  wcsncpy_s(d->face, SD_COUNTOF(d->face), face ? face : L"MS Shell Dlg", _TRUNCATE);
  d->points = points ? points : 8;
  d->width = width_dlu;
  d->margin = DLG_DEFAULT_MARGIN;
  d->cursor = DLG_DEFAULT_MARGIN;
  d->min_height = 0;
  d->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER;
  d->measure = measure;
  d->measure_ctx = measure_ctx;
  return SD_OK;
}

static ui_dlg_item *next_item(ui_dlg *d)
{
  ui_dlg_item *it;
  if (d->count >= UI_DLG_MAX_ITEMS)
    return NULL;
  it = &d->items[d->count++];
  memset(it, 0, sizeof(*it));
  return it;
}

static void set_text(ui_dlg_item *it, const wchar_t *text)
{
  wcsncpy_s(it->text, SD_COUNTOF(it->text), text ? text : L"", _TRUNCATE);
}

static int text_height(const ui_dlg *d, const wchar_t *text)
{
  int h = d->measure(d->measure_ctx, text ? text : L"", d->width - 2 * d->margin, NULL);
  return h < DLG_MIN_TEXT_DLU ? DLG_MIN_TEXT_DLU : h;
}

sd_err ui_dlg_text(ui_dlg *d, WORD id, const wchar_t *text, DWORD extra)
{
  ui_dlg_item *it;
  int h;
  if (d == NULL || (it = next_item(d)) == NULL)
    return SD_E_INVALID_PARAM;
  h = text_height(d, text) + DLG_TEXT_PAD;
  it->cls = UI_DLG_STATIC;
  it->id = id;
  it->style = WS_CHILD | WS_VISIBLE | SS_LEFT | extra;
  it->x = (short)d->margin;
  it->y = (short)d->cursor;
  it->cx = (short)(d->width - 2 * d->margin);
  it->cy = (short)h;
  set_text(it, text);
  d->cursor += h + UI_DLG_GAP;
  return SD_OK;
}

sd_err ui_dlg_edit(ui_dlg *d, WORD id, DWORD extra)
{
  ui_dlg_item *it;
  if (d == NULL || (it = next_item(d)) == NULL)
    return SD_E_INVALID_PARAM;
  it->cls = UI_DLG_EDIT;
  it->id = id;
  it->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_LEFT | extra;
  it->x = (short)d->margin;
  it->y = (short)d->cursor;
  it->cx = (short)(d->width - 2 * d->margin);
  it->cy = UI_DLG_EDIT_HEIGHT;
  d->cursor += UI_DLG_EDIT_HEIGHT + UI_DLG_GAP;
  return SD_OK;
}

sd_err ui_dlg_multiline(ui_dlg *d, WORD id, const wchar_t *text, int max_lines)
{
  ui_dlg_item *it;
  int h;
  if (d == NULL || max_lines < 1 || (it = next_item(d)) == NULL)
    return SD_E_INVALID_PARAM;
  h = text_height(d, text) + DLG_TEXT_PAD;
  if (h > max_lines * 8)
    h = max_lines * 8;
  if (h < 16)
    h = 16;
  it->cls = UI_DLG_EDIT;
  it->id = id;
  it->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE |
              ES_AUTOVSCROLL | ES_READONLY | ES_LEFT;
  it->x = (short)d->margin;
  it->y = (short)d->cursor;
  it->cx = (short)(d->width - 2 * d->margin);
  it->cy = (short)h;
  set_text(it, text);
  d->cursor += h + UI_DLG_GAP;
  return SD_OK;
}

sd_err ui_dlg_combo(ui_dlg *d, WORD id)
{
  ui_dlg_item *it;
  if (d == NULL || (it = next_item(d)) == NULL)
    return SD_E_INVALID_PARAM;
  it->cls = UI_DLG_COMBO;
  it->id = id;
  it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS | CBS_AUTOHSCROLL;
  it->x = (short)d->margin;
  it->y = (short)d->cursor;
  it->cx = (short)(d->width - 2 * d->margin);
  it->cy = UI_DLG_EDIT_HEIGHT;
  d->cursor += UI_DLG_EDIT_HEIGHT + UI_DLG_GAP;
  return SD_OK;
}

sd_err ui_dlg_check(ui_dlg *d, WORD id, const wchar_t *text)
{
  ui_dlg_item *it;
  int h;
  if (d == NULL || (it = next_item(d)) == NULL)
    return SD_E_INVALID_PARAM;
  h = text_height(d, text);
  if (h < UI_DLG_CHECK_HEIGHT)
    h = UI_DLG_CHECK_HEIGHT;
  it->cls = UI_DLG_CHECK;
  it->id = id;
  it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_MULTILINE | BS_LEFT;
  it->x = (short)d->margin;
  it->y = (short)d->cursor;
  it->cx = (short)(d->width - 2 * d->margin);
  it->cy = (short)h;
  set_text(it, text);
  d->cursor += h + UI_DLG_GAP;
  return SD_OK;
}

sd_err ui_dlg_space(ui_dlg *d, int dlu)
{
  if (d == NULL || dlu < 0)
    return SD_E_INVALID_PARAM;
  d->cursor += dlu;
  return SD_OK;
}

sd_err ui_dlg_buttons(ui_dlg *d, const WORD *ids, const wchar_t *const *texts, size_t n, WORD def_id)
{
  int avail;
  size_t start = 0;
  if (d == NULL || ids == NULL || texts == NULL || n == 0 || n > UI_DLG_MAX_ITEMS)
    return SD_E_INVALID_PARAM;
  if (d->count + n > UI_DLG_MAX_ITEMS)
    return SD_E_INVALID_PARAM;
  avail = d->width - 2 * d->margin;
  while (start < n) {
    int widths[UI_DLG_MAX_ITEMS];
    int total = 0, x;
    size_t i, end = start;
    for (i = start; i < n; i++) {
      int nat = 0, w;
      (void)d->measure(d->measure_ctx, texts[i], d->width, &nat);
      w = nat + 2 * DLG_BUTTON_PAD;
      if (w < UI_DLG_BUTTON_MIN)
        w = UI_DLG_BUTTON_MIN;
      if (i > start && total + UI_DLG_GAP + w > avail)
        break;
      widths[i] = w;
      total += (i > start ? UI_DLG_GAP : 0) + w;
      end = i + 1;
    }
    x = d->margin + avail - total;
    for (i = start; i < end; i++) {
      ui_dlg_item *it = next_item(d);
      if (it == NULL)
        return SD_E_INVALID_PARAM;
      it->cls = UI_DLG_BUTTON;
      it->id = ids[i];
      it->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                  ((def_id != 0 && ids[i] == def_id) ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON);
      it->x = (short)x;
      it->y = (short)d->cursor;
      it->cx = (short)widths[i];
      it->cy = UI_DLG_BUTTON_HEIGHT;
      set_text(it, texts[i]);
      x += widths[i] + UI_DLG_GAP;
    }
    d->cursor += UI_DLG_BUTTON_HEIGHT + UI_DLG_GAP;
    start = end;
  }
  return SD_OK;
}

sd_err ui_dlg_build(ui_dlg *d, unsigned char **out, size_t *out_bytes)
{
  dbuf b;
  size_t i;
  int height;
  if (d == NULL || out == NULL || out_bytes == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  *out_bytes = 0;
  memset(&b, 0, sizeof(b));
  height = d->cursor + d->margin;
  if (height < d->min_height)
    height = d->min_height;
  if (height > 0x7FFF)
    return SD_E_INVALID_PARAM;

  db_u16(&b, DLG_VERSION);
  db_u16(&b, DLG_SIGNATURE);
  db_u32(&b, 0);                                  /* help id */
  db_u32(&b, 0);                                  /* extended style */
  db_u32(&b, d->style | DS_SETFONT);
  db_u16(&b, (unsigned)d->count);
  db_u16(&b, 0);                                  /* x */
  db_u16(&b, 0);                                  /* y */
  db_u16(&b, (unsigned)d->width);
  db_u16(&b, (unsigned)height);
  db_u16(&b, 0);                                  /* no menu */
  db_u16(&b, 0);                                  /* default window class */
  db_wstr(&b, d->title);
  db_u16(&b, d->points);
  db_u16(&b, FW_NORMAL);
  db_u8(&b, 0);                                   /* not italic */
  db_u8(&b, DEFAULT_CHARSET);
  db_wstr(&b, d->face);

  for (i = 0; i < d->count; i++) {
    const ui_dlg_item *it = &d->items[i];
    unsigned ord = it->cls == UI_DLG_EDIT ? CLASS_EDIT
                 : it->cls == UI_DLG_STATIC ? CLASS_STATIC
                 : it->cls == UI_DLG_COMBO ? CLASS_COMBO : CLASS_BUTTON;
    db_align4(&b);
    db_u32(&b, 0);                                /* help id */
    db_u32(&b, 0);                                /* extended style */
    db_u32(&b, it->style);
    db_u16(&b, (unsigned)(unsigned short)it->x);
    db_u16(&b, (unsigned)(unsigned short)it->y);
    db_u16(&b, (unsigned)(unsigned short)it->cx);
    db_u16(&b, (unsigned)(unsigned short)it->cy);
    db_u32(&b, it->id);
    db_u16(&b, DLG_SIGNATURE);                    /* class is an ordinal */
    db_u16(&b, ord);
    db_wstr(&b, it->text);
    db_u16(&b, 0);                                /* no creation data */
  }
  db_align4(&b);

  if (b.err || b.p == NULL) {
    sd_free(b.p);
    return SD_E_NO_MEMORY;
  }
  *out = b.p;
  *out_bytes = b.len;
  return SD_OK;
}

/* ---- parser (tests) ---- */

static int rd_u16(const unsigned char *p, size_t n, size_t *pos, unsigned *v)
{
  if (*pos + 2 > n)
    return 0;
  *v = p[*pos] | ((unsigned)p[*pos + 1] << 8);
  *pos += 2;
  return 1;
}

static int rd_u32(const unsigned char *p, size_t n, size_t *pos, unsigned long *v)
{
  unsigned lo, hi;
  if (!rd_u16(p, n, pos, &lo) || !rd_u16(p, n, pos, &hi))
    return 0;
  *v = lo | ((unsigned long)hi << 16);
  return 1;
}

static int skip_wstr(const unsigned char *p, size_t n, size_t *pos)
{
  unsigned c;
  do {
    if (!rd_u16(p, n, pos, &c))
      return 0;
  } while (c != 0);
  return 1;
}

static void align_pos(size_t *pos)
{
  while (*pos % 4 != 0)
    (*pos)++;
}

sd_err ui_dlg_parse_check(const unsigned char *blob, size_t bytes, size_t *count, size_t *offsets, size_t cap)
{
  size_t pos = 0, n = 0;
  unsigned v, nitems, i;
  unsigned long style = 0;

  if (blob == NULL || count == NULL)
    return SD_E_INVALID_PARAM;
  if (!rd_u16(blob, bytes, &pos, &v) || v != DLG_VERSION)
    return SD_E_INVALID_PARAM;
  if (!rd_u16(blob, bytes, &pos, &v) || v != DLG_SIGNATURE)
    return SD_E_INVALID_PARAM;
  pos += 8;                                       /* help id, extended style */
  if (!rd_u32(blob, bytes, &pos, &style) || !rd_u16(blob, bytes, &pos, &nitems))
    return SD_E_INVALID_PARAM;
  pos += 8;                                       /* x y cx cy */
  pos += 4;                                       /* menu and class (both 0) */
  if (!skip_wstr(blob, bytes, &pos))
    return SD_E_INVALID_PARAM;
  if (style & DS_SETFONT) {
    pos += 4;                                     /* points, weight */
    pos += 2;                                     /* italic, charset */
    if (!skip_wstr(blob, bytes, &pos))
      return SD_E_INVALID_PARAM;
  }
  align_pos(&pos);
  for (i = 0; i < nitems; i++) {
    if (pos > bytes)
      return SD_E_INVALID_PARAM;
    if (offsets != NULL && n < cap)
      offsets[n] = pos;
    n++;
    pos += 24;                                    /* help id .. id */
    if (!rd_u16(blob, bytes, &pos, &v) || v != DLG_SIGNATURE)
      return SD_E_INVALID_PARAM;
    pos += 2;                                     /* class ordinal */
    if (!skip_wstr(blob, bytes, &pos))
      return SD_E_INVALID_PARAM;
    if (!rd_u16(blob, bytes, &pos, &v) || v != 0)
      return SD_E_INVALID_PARAM;
    align_pos(&pos);
  }
  if (pos != bytes)
    return SD_E_INVALID_PARAM;
  *count = n;
  return SD_OK;
}
