/* In-memory dialog templates (apps/shelldrive-ui/ui_dlg.c): sizes, DWORD alignment of the items, control
   count and class, layout inside the dialog, the button row, wrapping and the rejection of bad input. The
   text measure is a fixed rule, so no window or DC is needed. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "ui_dlg.h"

#define TEST_WIDTH 300
#define DLG_DEFAULT_MARGIN_FOR_TEST 7   /* ui_dlg_init's margin */

/* DLGTEMPLATEEX header offsets: ver 0, signature 2, help 4, exstyle 8, style 12, count 16, x 18, y 20,
   cx 22, cy 24, menu 26, class 28, title 30. Item offsets: help 0, exstyle 4, style 8, x 12, y 14, cx 16,
   cy 18, id 20, signature 24, class ordinal 26. */

/* Two characters per dialog unit of line width; each line is 8 dialog units high. */
static int fake_measure(void *ctx, const wchar_t *text, int width_dlu, int *natural)
{
  size_t n = wcslen(text), per;
  int lines;
  (void)ctx;
  per = (size_t)(width_dlu * 2);
  if (per == 0)
    per = 1;
  lines = (int)((n + per - 1) / per);
  if (lines < 1)
    lines = 1;
  if (natural != NULL)
    *natural = (int)n * 2;
  return lines * 8;
}

static unsigned rd16(const unsigned char *p, size_t at)
{
  return p[at] | ((unsigned)p[at + 1] << 8);
}

static short rds16(const unsigned char *p, size_t at)
{
  return (short)(unsigned short)rd16(p, at);
}

static unsigned long rd32(const unsigned char *p, size_t at)
{
  return rd16(p, at) | ((unsigned long)rd16(p, at + 2) << 16);
}

/* Reads the WSTR at pos and moves pos past its terminator; returns NULL-terminated copy in out. */
static void read_wstr(const unsigned char *p, size_t n, size_t *pos, wchar_t *out, size_t cch)
{
  size_t k = 0;
  for (;;) {
    unsigned c;
    if (*pos + 2 > n) {
      out[0] = 0;
      return;
    }
    c = rd16(p, *pos);
    *pos += 2;
    if (c == 0)
      break;
    if (k + 1 < cch)
      out[k++] = (wchar_t)c;
  }
  out[k] = 0;
}

/* Builds a dialog with the given layout and returns the blob (caller frees). */
static sd_err build_sample(ui_dlg *d, unsigned char **blob, size_t *len)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  static const wchar_t *const texts[2] = { L"OK", L"Cancel" };
  sd_err e;

  e = ui_dlg_init(d, L"Test title", TEST_WIDTH, L"Segoe UI", 9, fake_measure, NULL);
  if (e != SD_OK)
    return e;
  e = ui_dlg_text(d, 100, L"A line of text that is measured by the fake rule.", 0);
  if (e == SD_OK) e = ui_dlg_edit(d, 101, 0);
  if (e == SD_OK) e = ui_dlg_edit(d, 102, ES_PASSWORD);
  if (e == SD_OK) e = ui_dlg_check(d, 103, L"Save on this computer");
  if (e == SD_OK) e = ui_dlg_multiline(d, 104, L"Fingerprint text", 2);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, IDOK);
  if (e != SD_OK)
    return e;
  return ui_dlg_build(d, blob, len);
}

SD_TEST(dlg_empty_template_parses)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 99;
  sd_err e;

  SD_CHECK(ui_dlg_init(&d, L"Empty", TEST_WIDTH, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  e = ui_dlg_build(&d, &blob, &len);
  SD_REQUIRE(e == SD_OK && blob != NULL);
  SD_CHECK(ui_dlg_parse_check(blob, len, &count, NULL, 0) == SD_OK);
  SD_CHECK_EQ_INT(count, 0);
  /* DLGTEMPLATEEX: version 1, signature 0xFFFF */
  SD_CHECK_EQ_INT(rd16(blob, 0), 1);
  SD_CHECK_EQ_INT(rd16(blob, 2), 0xFFFF);
  SD_CHECK_EQ_INT(rd16(blob, 16), 0);             /* cDlgItems */
  sd_free(blob);
}

SD_TEST(dlg_items_aligned_and_counted)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[16];
  size_t i;

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  SD_CHECK(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  /* text, edit, password edit, check, multiline, two buttons */
  SD_CHECK_EQ_INT(count, 7);
  SD_CHECK_EQ_INT(d.count, 7);
  for (i = 0; i < count; i++) {
    SD_CHECK(offs[i] % 4 == 0);
    if (i > 0)
      SD_CHECK(offs[i] > offs[i - 1]);
  }
  /* the blob ends on a DWORD boundary, after the last item */
  SD_CHECK_EQ_INT(len % 4, 0);
  sd_free(blob);
}

SD_TEST(dlg_controls_have_expected_classes_and_ids)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[16];

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  SD_REQUIRE(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  /* DLGITEMTEMPLATEEX: id at +20, class ordinal at +26 after 0xFFFF at +24 */
  SD_CHECK_EQ_INT(rd32(blob, offs[0] + 20), 100);
  SD_CHECK_EQ_INT(rd16(blob, offs[0] + 26), 0x0082);      /* static */
  SD_CHECK_EQ_INT(rd16(blob, offs[1] + 26), 0x0081);      /* edit */
  SD_CHECK_EQ_INT(rd32(blob, offs[1] + 20), 101);
  SD_CHECK_EQ_INT(rd32(blob, offs[2] + 20), 102);
  SD_CHECK((rd32(blob, offs[2] + 8) & ES_PASSWORD) != 0);  /* style of the password edit */
  SD_CHECK_EQ_INT(rd16(blob, offs[3] + 26), 0x0080);      /* check box is a button class */
  SD_CHECK_EQ_INT(rd32(blob, offs[5] + 20), IDOK);
  SD_CHECK_EQ_INT(rd32(blob, offs[6] + 20), IDCANCEL);
  SD_CHECK((rd32(blob, offs[5] + 8) & BS_DEFPUSHBUTTON) != 0);   /* IDOK is the default */
  SD_CHECK((rd32(blob, offs[6] + 8) & BS_DEFPUSHBUTTON) == 0);
  sd_free(blob);
}

SD_TEST(dlg_title_and_font_are_encoded)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, pos = 30;
  wchar_t title[64], face[32];
  unsigned long style;

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  style = rd32(blob, 12);
  SD_CHECK((style & DS_SETFONT) != 0);
  SD_CHECK((style & WS_CAPTION) != 0);
  read_wstr(blob, len, &pos, title, SD_COUNTOF(title));
  SD_CHECK(wcscmp(title, L"Test title") == 0);
  SD_CHECK_EQ_INT(rd16(blob, pos), 9);                   /* point size */
  pos += 6;                                              /* point size, weight, italic, charset */
  read_wstr(blob, len, &pos, face, SD_COUNTOF(face));
  SD_CHECK(wcscmp(face, L"Segoe UI") == 0);
  sd_free(blob);
}

SD_TEST(dlg_layout_stays_inside_the_dialog)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[16], i;
  int width, height;

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  SD_REQUIRE(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  width = rd16(blob, 22);
  height = rd16(blob, 24);
  SD_CHECK_EQ_INT(width, TEST_WIDTH);
  SD_CHECK_EQ_INT(height, d.cursor + d.margin);
  for (i = 0; i < count; i++) {
    short x = rds16(blob, offs[i] + 12), y = rds16(blob, offs[i] + 14);
    short cx = rds16(blob, offs[i] + 16), cy = rds16(blob, offs[i] + 18);
    SD_CHECK(x >= 0 && y >= 0);
    SD_CHECK(x + cx <= width);
    SD_CHECK(y + cy <= height);
    SD_CHECK(cx > 0 && cy > 0);
  }
  sd_free(blob);
}

SD_TEST(dlg_button_row_is_right_aligned)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[16];
  short right, y0, y1;

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  SD_REQUIRE(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  y0 = rds16(blob, offs[5] + 14);
  y1 = rds16(blob, offs[6] + 14);
  SD_CHECK_EQ_INT(y0, y1);                                /* one row */
  right = (short)(rds16(blob, offs[6] + 12) + rds16(blob, offs[6] + 16));
  SD_CHECK_EQ_INT(right, TEST_WIDTH - DLG_DEFAULT_MARGIN_FOR_TEST);
  sd_free(blob);
}

SD_TEST(dlg_buttons_wrap_when_they_do_not_fit)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  static const WORD ids[2] = { IDOK, IDCANCEL };
  static const wchar_t *const texts[2] = {
    L"a button text far too long for one row of this dialog and more and more and more and more and more and more and more and more and more",
    L"another button text far too long for one row of this dialog and more and more and more and more and more and more"
  };
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[8];

  SD_REQUIRE(ui_dlg_init(&d, L"Wrap", TEST_WIDTH, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  SD_REQUIRE(ui_dlg_buttons(&d, ids, texts, 2, 0) == SD_OK);
  SD_REQUIRE(ui_dlg_build(&d, &blob, &len) == SD_OK);
  SD_REQUIRE(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  SD_CHECK_EQ_INT(count, 2);
  SD_CHECK(rds16(blob, offs[1] + 14) > rds16(blob, offs[0] + 14));   /* second row, below the first */
  sd_free(blob);
}

SD_TEST(dlg_multiline_height_is_capped)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, offs[4];
  wchar_t big[2000];
  size_t i;

  for (i = 0; i < SD_COUNTOF(big) - 1; i++)
    big[i] = L'x';
  big[SD_COUNTOF(big) - 1] = 0;
  SD_REQUIRE(ui_dlg_init(&d, L"Cap", TEST_WIDTH, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  SD_REQUIRE(ui_dlg_multiline(&d, 7, big, 2) == SD_OK);
  SD_REQUIRE(ui_dlg_build(&d, &blob, &len) == SD_OK);
  SD_REQUIRE(ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK);
  SD_CHECK_EQ_INT(rds16(blob, offs[0] + 18), 16);         /* two lines at most, never below one control line */
  sd_free(blob);
}

SD_TEST(dlg_rejects_too_many_items_and_bad_input)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  size_t i;
  unsigned char *blob = NULL;
  size_t len = 0;

  SD_REQUIRE(ui_dlg_init(&d, L"Full", TEST_WIDTH, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  for (i = 0; i < UI_DLG_MAX_ITEMS; i++)
    SD_REQUIRE(ui_dlg_text(&d, (WORD)(200 + i), L"x", 0) == SD_OK);
  SD_CHECK(ui_dlg_text(&d, 999, L"one too many", 0) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_dlg_init(&d, L"Narrow", 50, L"Segoe UI", 9, fake_measure, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_dlg_init(&d, L"No measure", TEST_WIDTH, L"Segoe UI", 9, NULL, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(ui_dlg_build(&d, &blob, &len) == SD_OK);
  sd_free(blob);
}

SD_TEST(dlg_parse_rejects_truncated_blob)
{
  static ui_dlg d;                     /* large: static keeps it off the stack (tests run one at a time) */
  unsigned char *blob = NULL;
  size_t len = 0, count = 0;

  SD_REQUIRE(build_sample(&d, &blob, &len) == SD_OK);
  SD_CHECK(ui_dlg_parse_check(blob, len - 2, &count, NULL, 0) != SD_OK);
  SD_CHECK(ui_dlg_parse_check(blob, len + 4, &count, NULL, 0) != SD_OK);
  SD_CHECK(ui_dlg_parse_check(NULL, 0, &count, NULL, 0) != SD_OK);
  sd_free(blob);
}
