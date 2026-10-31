/* The OS-tiered messages and trust prompts (06 §6.2): the MB_* flags to task dialog mapping, the plain text
   fallback, and the dialog generator's main instruction, icon column and command links. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "ui_dlg.h"
#include "ui_taskdlg_model.h"

/* Two characters per dialog unit of line width; each line is 8 dialog units high. */
static int fake_measure(void *ctx, const wchar_t *text, int width_dlu, int *natural)
{
  size_t n = wcslen(text), per = (size_t)(width_dlu * 2);
  int lines;
  (void)ctx;
  if (per == 0)
    per = 1;
  lines = (int)((n + per - 1) / per);
  if (lines < 1)
    lines = 1;
  if (natural != NULL)
    *natural = (int)n * 2;
  return lines * 8;
}

SD_TEST(taskdlg_map_buttons_and_default)
{
  ui_task_map m;
  SD_CHECK(ui_task_map_flags(MB_OK, &m) == 1);
  SD_CHECK_EQ_INT(m.buttons, UI_TASK_BTN_OK);
  SD_CHECK_EQ_INT(m.default_id, IDOK);
  SD_CHECK_EQ_INT(m.allow_cancel, 1);

  SD_CHECK(ui_task_map_flags(MB_OKCANCEL, &m) == 1);
  SD_CHECK_EQ_INT(m.buttons, UI_TASK_BTN_OK | UI_TASK_BTN_CANCEL);
  SD_CHECK_EQ_INT(m.default_id, IDOK);
  SD_CHECK(ui_task_map_flags(MB_OKCANCEL | MB_DEFBUTTON2, &m) == 1);
  SD_CHECK_EQ_INT(m.default_id, IDCANCEL);          /* repair data and the like keep Cancel as the default */

  SD_CHECK(ui_task_map_flags(MB_YESNO | MB_DEFBUTTON2, &m) == 1);
  SD_CHECK_EQ_INT(m.buttons, UI_TASK_BTN_YES | UI_TASK_BTN_NO);
  SD_CHECK_EQ_INT(m.default_id, IDNO);
  SD_CHECK_EQ_INT(m.allow_cancel, 0);               /* no Cancel button: Escape does not answer No for the user */

  SD_CHECK(ui_task_map_flags(MB_YESNOCANCEL, &m) == 1);
  SD_CHECK_EQ_INT(m.buttons, UI_TASK_BTN_YES | UI_TASK_BTN_NO | UI_TASK_BTN_CANCEL);
  SD_CHECK_EQ_INT(m.default_id, IDYES);
  SD_CHECK(ui_task_map_flags(MB_YESNOCANCEL | MB_DEFBUTTON3, &m) == 1);
  SD_CHECK_EQ_INT(m.default_id, IDCANCEL);
  SD_CHECK_EQ_INT(m.allow_cancel, 1);

  SD_CHECK(ui_task_map_flags(MB_RETRYCANCEL, &m) == 1);
  SD_CHECK_EQ_INT(m.default_id, IDRETRY);

  /* a default past the last button falls back to the first */
  SD_CHECK(ui_task_map_flags(MB_YESNO | MB_DEFBUTTON3, &m) == 1);
  SD_CHECK_EQ_INT(m.default_id, IDYES);
}

SD_TEST(taskdlg_map_icons)
{
  ui_task_map m;
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONERROR, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_ERROR);
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONSTOP, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_ERROR);
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONWARNING, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_WARNING);
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONEXCLAMATION, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_WARNING);
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONINFORMATION, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_INFO);
  SD_CHECK(ui_task_map_flags(MB_YESNO | MB_ICONQUESTION, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_NONE);       /* the guidelines drop the question icon */
  SD_CHECK(ui_task_map_flags(MB_OK, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_NONE);
  /* MB_SETFOREGROUND and friends do not matter */
  SD_CHECK(ui_task_map_flags(MB_OK | MB_ICONERROR | MB_SETFOREGROUND, &m) == 1);
  SD_CHECK_EQ_INT(m.icon, UI_TASK_ICON_ERROR);
}

SD_TEST(taskdlg_map_rejects_what_a_task_dialog_lacks)
{
  ui_task_map m;
  SD_CHECK(ui_task_map_flags(MB_ABORTRETRYIGNORE, &m) == 0);
  SD_CHECK(ui_task_map_flags(MB_OK, NULL) == 0);
}

SD_TEST(taskdlg_plain_text_joins_the_parts)
{
  wchar_t buf[64];
  size_t n;
  n = ui_task_plain_text(L"Main", L"Content", L"Details", buf, SD_COUNTOF(buf));
  SD_CHECK_EQ_INT(n, wcslen(L"Main\n\nContent\n\nDetails"));
  SD_CHECK(wcscmp(buf, L"Main\n\nContent\n\nDetails") == 0);
  n = ui_task_plain_text(L"Main", NULL, L"Details", buf, SD_COUNTOF(buf));
  SD_CHECK(wcscmp(buf, L"Main\n\nDetails") == 0);
  n = ui_task_plain_text(L"Main", L"", NULL, buf, SD_COUNTOF(buf));
  SD_CHECK(wcscmp(buf, L"Main") == 0);
  SD_CHECK_EQ_INT(n, 4);
  /* too small a buffer, or no main text: nothing */
  SD_CHECK_EQ_INT(ui_task_plain_text(L"Main", L"Content", NULL, buf, 8), 0);
  SD_CHECK(buf[0] == 0);
  SD_CHECK_EQ_INT(ui_task_plain_text(L"", L"Content", NULL, buf, SD_COUNTOF(buf)), 0);
  SD_CHECK_EQ_INT(ui_task_plain_text(NULL, NULL, NULL, buf, SD_COUNTOF(buf)), 0);
}

SD_TEST(dlg_heading_is_taller_with_a_larger_font)
{
  static ui_dlg a, b;
  const wchar_t *text = L"The authenticity of host example.org (port 22) can't be established.";
  int ha, hb;
  SD_REQUIRE(ui_dlg_init(&a, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  SD_REQUIRE(ui_dlg_init(&b, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  b.heading_pct = 160;
  SD_CHECK(ui_dlg_heading(&a, 1, text, 0) == SD_OK);
  SD_CHECK(ui_dlg_heading(&b, 1, text, 0) == SD_OK);
  ha = a.items[0].cy;
  hb = b.items[0].cy;
  SD_CHECK(hb > ha);
  SD_CHECK_EQ_INT(a.items[0].cx, 300 - 2 * 7);
  /* a heading that wraps in the narrower virtual column takes more lines */
  SD_CHECK(ui_dlg_heading(&b, 2, L"A longer main instruction that surely wraps more than once at a larger size.", 0) == SD_OK);
  SD_CHECK(b.items[1].cy >= hb);
  SD_CHECK(b.cursor > a.cursor);
}

SD_TEST(dlg_icon_indents_the_text_beside_it)
{
  static ui_dlg d;
  int icon_bottom;
  SD_REQUIRE(ui_dlg_init(&d, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  SD_CHECK(ui_dlg_icon(&d, 50) == SD_OK);
  SD_CHECK(ui_dlg_heading(&d, 51, L"Heading", 0) == SD_OK);
  SD_CHECK_EQ_INT(d.items[0].x, 7);
  SD_CHECK_EQ_INT(d.items[0].cx, UI_DLG_ICON_CX);
  SD_CHECK_EQ_INT(d.items[1].x, d.icon_left);               /* beside the icon */
  SD_CHECK_EQ_INT(d.items[1].cx, 300 - d.icon_left - 7);
  icon_bottom = d.icon_bottom;
  while (d.cursor < icon_bottom)
    SD_CHECK(ui_dlg_text(&d, 52, L"More text beside the icon.", 0) == SD_OK);
  /* below the icon the full width is back */
  SD_CHECK(ui_dlg_text(&d, 53, L"Below the icon.", 0) == SD_OK);
  SD_CHECK_EQ_INT(d.items[d.count - 1].x, 7);
  SD_CHECK_EQ_INT(d.items[d.count - 1].cx, 300 - 14);
}

SD_TEST(dlg_commands_are_links_or_plain_buttons)
{
  static ui_dlg link, plain;
  static const WORD ids[3] = { IDOK, 225, IDCANCEL };
  static const wchar_t *const texts[3] = { L"Trust and connect", L"Connect once", L"Cancel" };
  static const wchar_t *const notes[3] = { L"Saves the key.", L"Does not save it, so ShellDrive asks again next time.", NULL };
  unsigned char *blob = NULL;
  size_t len = 0, count = 0, i;

  SD_REQUIRE(ui_dlg_init(&link, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  link.command_links = 1;
  SD_CHECK(ui_dlg_commands(&link, ids, texts, notes, 3, 0) == SD_OK);
  SD_CHECK_EQ_INT(link.count, 3);
  for (i = 0; i < 3; i++) {
    SD_CHECK_EQ_INT(link.items[i].style & 0xF, BS_COMMANDLINK);     /* 0x0E, never the default link */
    SD_CHECK_EQ_INT(link.items[i].x, 7);
    SD_CHECK_EQ_INT(link.items[i].cx, 300 - 14);
    SD_CHECK(link.items[i].style & WS_TABSTOP);
    if (i > 0)
      SD_CHECK(link.items[i].y > link.items[i - 1].y + link.items[i - 1].cy - 1);
  }
  SD_CHECK(link.items[1].cy > link.items[2].cy);                    /* the longer note takes more height */
  SD_CHECK(ui_dlg_build(&link, &blob, &len) == SD_OK);
  SD_CHECK(ui_dlg_parse_check(blob, len, &count, NULL, 0) == SD_OK);
  SD_CHECK_EQ_INT(count, 3);
  sd_free(blob);

  SD_REQUIRE(ui_dlg_init(&plain, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  SD_CHECK(ui_dlg_commands(&plain, ids, texts, notes, 3, 0) == SD_OK);
  SD_CHECK_EQ_INT(plain.count, 3);
  for (i = 0; i < 3; i++) {
    SD_CHECK_EQ_INT(plain.items[i].style & 0xF, BS_PUSHBUTTON);     /* no default button: trust decision */
    SD_CHECK_EQ_INT(plain.items[i].cy, UI_DLG_BUTTON_HEIGHT);
  }
}

SD_TEST(dlg_commands_mark_only_the_requested_default)
{
  static ui_dlg d;
  static const WORD ids[2] = { IDOK, IDCANCEL };
  static const wchar_t *const texts[2] = { L"Yes", L"No" };
  SD_REQUIRE(ui_dlg_init(&d, L"T", 300, L"Segoe UI", 9, fake_measure, NULL) == SD_OK);
  d.command_links = 1;
  SD_CHECK(ui_dlg_commands(&d, ids, texts, NULL, 2, IDCANCEL) == SD_OK);
  SD_CHECK_EQ_INT(d.items[0].style & 0xF, BS_COMMANDLINK);
  SD_CHECK_EQ_INT(d.items[1].style & 0xF, 0xF);                     /* BS_DEFCOMMANDLINK */
  SD_CHECK(ui_dlg_commands(&d, NULL, texts, NULL, 2, 0) != SD_OK);
}
