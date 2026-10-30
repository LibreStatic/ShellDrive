/* The balloon rate limit (apps/shelldrive-ui/ui_notify_model.c, 03 §7.7): one balloon per (subject, kind) per
   60 s, the wait it reports, independence of subjects and kinds, and a bounded table. Pure: no window calls. */
#include <windows.h>
#include <wchar.h>

#include "sd_test.h"
#include "ui_notify_model.h"

#define NT_KIND_A 1
#define NT_KIND_B 2

SD_TEST(notify_limit_one_per_subject_and_kind)
{
  static ui_notify_limiter l;
  unsigned long long wait = 0;
  ui_notify_limiter_init(&l);

  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 0, &wait), 1);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 1000, &wait), 0);
  SD_CHECK_EQ_U64(wait, 59000u);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 59999, &wait), 0);
  SD_CHECK_EQ_U64(wait, 1u);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 60000, &wait), 1);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 60001, NULL), 0);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 120000, NULL), 1);
}

SD_TEST(notify_limit_is_per_subject_and_kind)
{
  static ui_notify_limiter l;
  ui_notify_limiter_init(&l);

  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_A, 5000, NULL), 1);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_B, 5000, NULL), 1);   /* another event type */
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"F:", NT_KIND_A, 5000, NULL), 1);   /* another mount */
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"F:", NT_KIND_A, 5001, NULL), 0);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"E:", NT_KIND_B, 5001, NULL), 0);
  /* a host name works as a subject too (hostkeys.announced) */
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"example.org", NT_KIND_A, 5001, NULL), 1);
}

SD_TEST(notify_clock_going_back_is_not_a_burst)
{
  static ui_notify_limiter l;
  unsigned long long wait = 0;
  ui_notify_limiter_init(&l);

  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"X:", NT_KIND_A, 100000, NULL), 1);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, L"X:", NT_KIND_A, 50000, &wait), 0);
  SD_CHECK_EQ_U64(wait, 60000u);
}

SD_TEST(notify_table_is_bounded_and_keeps_recent_pairs)
{
  static ui_notify_limiter l;
  wchar_t subject[16];
  unsigned i;
  ui_notify_limiter_init(&l);

  /* more subjects than slots: every first balloon is allowed, the table reuses its oldest slots */
  for (i = 0; i < UI_NOTIFY_SLOTS + 36; i++) {
    _snwprintf_s(subject, SD_COUNTOF(subject), _TRUNCATE, L"h%u", i);
    SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, subject, NT_KIND_A, i, NULL), 1);
  }
  /* the most recent subject is still limited */
  _snwprintf_s(subject, SD_COUNTOF(subject), _TRUNCATE, L"h%u", UI_NOTIFY_SLOTS + 35);
  SD_CHECK_EQ_INT(ui_notify_limiter_take(&l, subject, NT_KIND_A, UI_NOTIFY_SLOTS + 36, NULL), 0);
}

SD_TEST(notify_interval_is_one_minute)
{
  SD_CHECK_EQ_U64((unsigned long long)UI_NOTIFY_INTERVAL_MS, 60000u);
}
