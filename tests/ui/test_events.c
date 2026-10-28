/* Event list (apps/shelldrive-ui/ui_events_model.c, 03 7.7): the bounded ring, the filters and the copy text. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "sd_base/sd_mem.h"
#include "ui_events_model.h"

static const ui_ev_time k_t0 = { 2026, 10, 28, 9, 5, 3 };

static const wchar_t *const k_labels[UI_EV_KINDS] = { L"Drive", L"Host key", L"Warning", L"Error", L"Information" };

SD_TEST(events_ring_keeps_the_newest_entries)
{
  static ui_ev_log l;
  size_t i;
  unsigned long long last = 0;
  ui_ev_init(&l);
  for (i = 0; i < UI_EV_MAX + 5; i++) {
    wchar_t text[16];
    swprintf_s(text, 16, L"event %u", (unsigned)i);
    last = ui_ev_add(&l, UI_EV_INFO, &k_t0, L"E:", text);
  }
  SD_CHECK_EQ_INT((int)l.count, (int)UI_EV_MAX);
  SD_CHECK(ui_ev_at(&l, 0)->seq == 6);                    /* the first five were dropped */
  SD_CHECK(ui_ev_at(&l, 0)->seq < ui_ev_at(&l, 1)->seq);
  SD_CHECK(ui_ev_at(&l, UI_EV_MAX - 1)->seq == last);
  SD_CHECK(wcscmp(ui_ev_at(&l, UI_EV_MAX - 1)->text, L"event 204") == 0);
  SD_CHECK(ui_ev_at(&l, UI_EV_MAX) == NULL);
  ui_ev_clear(&l);
  SD_CHECK_EQ_INT((int)l.count, 0);
  SD_CHECK(ui_ev_add(&l, UI_EV_INFO, &k_t0, L"", L"after clear") > last);   /* numbers are never reused */
}

SD_TEST(events_text_is_cut_and_flattened)
{
  static ui_ev_log l;
  wchar_t big[UI_EV_TEXT_MAX * 2];
  const ui_ev_entry *e;
  size_t i;
  ui_ev_init(&l);
  for (i = 0; i + 1 < SD_COUNTOF(big); i++)
    big[i] = L'x';
  big[SD_COUNTOF(big) - 1] = 0;
  (void)ui_ev_add(&l, (ui_ev_kind)99, &k_t0, L"a\tb\r\nc", big);
  e = ui_ev_at(&l, 0);
  SD_REQUIRE(e != NULL);
  SD_CHECK_EQ_INT((int)e->kind, (int)UI_EV_INFO);          /* an unknown kind is information */
  SD_CHECK(wcscmp(e->subject, L"a b  c") == 0);
  SD_CHECK_EQ_INT((int)wcslen(e->text), (int)UI_EV_TEXT_MAX - 1);
}

SD_TEST(events_time_format)
{
  wchar_t out[UI_EV_TIME_MAX];
  ui_ev_format_time(&k_t0, out);
  SD_CHECK(wcscmp(out, L"2026-10-28 09:05:03") == 0);
}

SD_TEST(events_filters_by_kind_and_text)
{
  static ui_ev_log l;
  ui_ev_init(&l);
  (void)ui_ev_add(&l, UI_EV_DRIVE, &k_t0, L"E:", L"Connected");
  (void)ui_ev_add(&l, UI_EV_HOSTKEY, &k_t0, L"Example.ORG", L"The identity has changed");
  (void)ui_ev_add(&l, UI_EV_ERROR, &k_t0, L"F:", L"Failed (auth_failed).");
  SD_CHECK(ui_ev_match(ui_ev_at(&l, 1), 0xFFu, L"example"));            /* subject, any case */
  SD_CHECK(ui_ev_match(ui_ev_at(&l, 1), 0xFFu, L"IDENTITY"));           /* text */
  SD_CHECK(!ui_ev_match(ui_ev_at(&l, 1), 0xFFu, L"nothing"));
  SD_CHECK(ui_ev_match(ui_ev_at(&l, 0), 0xFFu, L""));
  SD_CHECK(ui_ev_match(ui_ev_at(&l, 0), 0xFFu, NULL));
  SD_CHECK(!ui_ev_match(ui_ev_at(&l, 0), 1u << UI_EV_ERROR, L""));      /* kind mask */
  SD_CHECK(ui_ev_match(ui_ev_at(&l, 2), 1u << UI_EV_ERROR, L"auth_"));
  SD_CHECK(ui_ev_contains(L"abc", L"abc") && !ui_ev_contains(L"ab", L"abc") && ui_ev_contains(L"", L""));
}

SD_TEST(events_copy_text_lists_the_matching_rows)
{
  static ui_ev_log l;
  wchar_t *text = NULL;
  size_t lines = 0;
  ui_ev_init(&l);
  (void)ui_ev_add(&l, UI_EV_DRIVE, &k_t0, L"E:", L"Connected");
  (void)ui_ev_add(&l, UI_EV_ERROR, &k_t0, L"F:", L"Failed (x).");
  SD_CHECK(ui_ev_build_text(&l, 0xFFu, L"", k_labels, &text, &lines) == SD_OK);
  SD_CHECK_EQ_INT((int)lines, 2);
  SD_CHECK(wcscmp(text, L"2026-10-28 09:05:03\tE:\tDrive\tConnected\r\n"
                        L"2026-10-28 09:05:03\tF:\tError\tFailed (x).\r\n") == 0);
  sd_free(text);
  SD_CHECK(ui_ev_build_text(&l, 0xFFu, L"failed", k_labels, &text, &lines) == SD_OK);
  SD_CHECK_EQ_INT((int)lines, 1);
  SD_CHECK(wcscmp(text, L"2026-10-28 09:05:03\tF:\tError\tFailed (x).\r\n") == 0);
  sd_free(text);
  SD_CHECK(ui_ev_build_text(&l, 0xFFu, L"zzz", k_labels, &text, &lines) == SD_OK);
  SD_CHECK_EQ_INT((int)lines, 0);
  SD_CHECK(text != NULL && text[0] == 0);
  sd_free(text);
}
