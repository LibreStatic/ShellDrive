/* The theme decision and palette (apps/shelldrive-ui/ui_theme_model.c, 06 §4, §5.1, §3.6). Pure: the inputs
   are the OS version and the settings-like flags of ui_theme_inputs. */
#include <windows.h>

#include <string.h>

#include "sd_test.h"
#include "ui_theme_model.h"

/* A Windows 11 24H2 host: Fluent 2c, light apps, themed, composition on. */
static ui_theme_inputs mk_inputs(void)
{
  ui_theme_inputs in;
  memset(&in, 0, sizeof(in));
  in.os_major = 10;
  in.os_minor = 0;
  in.os_build = 26100;
  in.dwm_present = 1;
  in.composition = 1;
  in.high_contrast = 0;
  in.apps_use_light = 1;
  in.themed = 1;
  in.remote_session = 0;
  in.style_setting = UI_THEME_STYLE_AUTO;
  in.dark_helpers_setting = 1;
  in.helper_ordinals = 1;
  in.forced_tier = -1;
  return in;
}

static ui_theme select_with(const ui_theme_inputs *in)
{
  ui_theme t;
  ui_theme_select(in, &t);
  return t;
}

/* The tier table of 06 §8.1: one row per OS the lab runs (§8.2). */
SD_TEST(theme_tiers_follow_the_os)
{
  ui_theme_inputs in;
  ui_theme t;

  in = mk_inputs();
  in.os_major = 5; in.os_minor = 1; in.os_build = 2600;          /* XP SP3 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.level, 0);
  SD_CHECK_EQ_INT(t.glass, 0);
  SD_CHECK_EQ_INT(t.task_dialogs, 0);        /* no TaskDialogIndirect on XP */

  in = mk_inputs();
  in.os_major = 6; in.os_minor = 0; in.os_build = 6002;          /* Vista SP2, composed */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_AERO);
  SD_CHECK_EQ_INT(t.glass, 1);
  SD_CHECK_EQ_INT(t.task_dialogs, 1);

  in.composition = 0;                        /* Basic or Classic theme on 7 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_AERO);
  SD_CHECK_EQ_INT(t.glass, 0);               /* the glass band drops, the tier stays (06 §3.2) */
  SD_CHECK_EQ_INT(t.task_dialogs, 1);

  in.composition = 1;
  in.remote_session = 1;                     /* an RDP session */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.glass, 0);

  in = mk_inputs();
  in.os_major = 6; in.os_minor = 1; in.os_build = 7601;          /* 7 SP1 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_AERO);
  SD_CHECK_EQ_INT(t.glass, 1);

  in = mk_inputs();
  in.os_major = 6; in.os_minor = 2; in.os_build = 9200;          /* 8 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_FLUENT);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_A);
  SD_CHECK_EQ_INT(t.command_bar, 1);
  SD_CHECK_EQ_INT(t.backdrop, 0);
  SD_CHECK_EQ_INT(t.corners, 0);

  in.os_build = 10240;                       /* 10 1507 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_FLUENT);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_A);

  in.os_build = 17763;                       /* 10 1809 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_A);

  in.os_build = 19045;                       /* 10 22H2 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_A);

  in.os_build = 22000;                       /* 11 21H2 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_B);
  SD_CHECK_EQ_INT(t.corners, 1);
  SD_CHECK_EQ_INT(t.backdrop, 0);

  in.os_build = 22621;                       /* 11 22H2 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_C);
  SD_CHECK_EQ_INT(t.backdrop, 1);
  SD_CHECK_EQ_INT(t.corners, 1);

  in.os_build = 26100;                       /* 11 24H2 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_C);
  SD_CHECK_EQ_INT(t.backdrop, 1);
}

SD_TEST(theme_high_contrast_and_the_classic_setting_force_classic)
{
  ui_theme_inputs in;
  ui_theme t;

  in = mk_inputs();
  in.os_build = 19045;
  in.high_contrast = 1;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.task_dialogs, 1);        /* they follow High Contrast by themselves (06 §4) */
  SD_CHECK_EQ_INT(t.command_bar, 0);
  SD_CHECK_EQ_INT(t.dark, 0);

  in.high_contrast = 0;
  in.style_setting = UI_THEME_STYLE_CLASSIC;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.task_dialogs, 1);

  in = mk_inputs();                          /* the Windows Classic theme: not themed */
  in.themed = 0;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.task_dialogs, 1);

  in = mk_inputs();                          /* the setting cannot lift the XP floor */
  in.os_major = 5; in.os_minor = 1; in.os_build = 2600;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.task_dialogs, 0);
}

SD_TEST(theme_dark_follows_the_app_theme_and_the_helpers)
{
  ui_theme_inputs in;
  ui_theme t;

  in = mk_inputs();
  in.os_build = 19045;
  in.apps_use_light = 0;                     /* 10 22H2 with dark apps: the helpers of 3.6 (D47) */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 1);
  SD_CHECK_EQ_INT(t.dark_helpers, 1);

  in.dark_helpers_setting = 0;               /* the kill switch (06 §3.6) */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 0);                /* Windows 10 has no documented path */
  SD_CHECK_EQ_INT(t.dark_helpers, 0);

  in = mk_inputs();
  in.os_build = 10240;
  in.apps_use_light = 0;                     /* 10 1507: the helpers do not exist yet */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 0);

  in = mk_inputs();
  in.os_build = 22000;
  in.apps_use_light = 0;                     /* 11: the documented title bar */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 1);
  SD_CHECK_EQ_INT(t.dark_helpers, 1);

  in.dark_helpers_setting = 0;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 1);                /* the documented path survives the kill switch */
  SD_CHECK_EQ_INT(t.dark_helpers, 0);

  in.dark_helpers_setting = 1;
  in.apps_use_light = 1;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 0);

  in.apps_use_light = -1;                    /* value absent: light (03 §7.4) */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 0);

  in = mk_inputs();
  in.os_major = 6; in.os_minor = 1; in.os_build = 7601;
  in.apps_use_light = 0;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.dark, 0);                /* Aero never goes dark */
}

SD_TEST(theme_titlebar_attr_19_20_or_none)
{
  ui_theme_inputs in;
  ui_theme t;

  in = mk_inputs();
  in.apps_use_light = 0;
  t = select_with(&in);                      /* 26100 */
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_20);

  in.os_build = 22000;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_20);

  in.os_build = 19045;                       /* 10 22H2: 20 from build 18985 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_20);

  in.os_build = 18362;                       /* 10 1903: still the undocumented 19 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_19);

  in.os_build = 17763;                       /* 10 1809 */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_19);

  in.dark_helpers_setting = 0;               /* without the helpers Windows 10 stays light */
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_NONE);

  in = mk_inputs();
  in.apps_use_light = 1;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.titlebar_attr, UI_THEME_TITLEBAR_ATTR_NONE);
}

SD_TEST(theme_helpers_allow_list)
{
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(10240u, 1, 1), 0);   /* 1507: the ordinals do not exist */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(17762u, 1, 1), 0);   /* one build below 1809 */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(17763u, 1, 1), 1);   /* 1809 */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(19045u, 0, 1), 1);   /* allow-listed: no ordinal check needed */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(26100u, 1, 1), 1);   /* the newest build the lab tested */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(26101u, 1, 1), 1);   /* newer: allowed while the exports resolve */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(26101u, 0, 1), 0);   /* newer without the exports: off */
  SD_CHECK_EQ_INT(ui_theme_helpers_allowed(26101u, 1, 0), 0);   /* the kill switch wins */
  SD_CHECK_EQ_INT((int)UI_THEME_HELPERS_MAX_TESTED, 26100);
}

SD_TEST(theme_forced_tier_overrides_the_os)
{
  ui_theme_inputs in;
  ui_theme t;

  in = mk_inputs();
  in.os_build = 19045;                       /* a Windows 10 host exercising the other tiers (06 §8.1) */
  in.forced_tier = UI_FORCE_TIER(UI_TIER_CLASSIC, 0, 0);
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_CLASSIC);
  SD_CHECK_EQ_INT(t.level, 0);               /* only Fluent has a sub-level (06 §3.3) */
  SD_CHECK_EQ_INT(t.command_bar, 0);

  in.forced_tier = UI_FORCE_TIER(UI_TIER_AERO, 0, 0);
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_AERO);
  SD_CHECK_EQ_INT(t.level, 0);
  SD_CHECK_EQ_INT(t.glass, 1);               /* composition is on here */

  in.forced_tier = UI_FORCE_TIER(UI_TIER_FLUENT, UI_LEVEL_A, 0);
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_FLUENT);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_A);
  SD_CHECK_EQ_INT(t.backdrop, 0);

  in.forced_tier = UI_FORCE_TIER(UI_TIER_FLUENT, UI_LEVEL_C, 0);
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_C);
  SD_CHECK_EQ_INT(t.backdrop, 1);            /* the 2c code path runs on the forced level */

  in = mk_inputs();
  in.os_major = 5; in.os_minor = 1; in.os_build = 2600;
  in.apps_use_light = 0;
  in.forced_tier = UI_FORCE_TIER(UI_TIER_FLUENT, UI_LEVEL_B, 1);
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_FLUENT);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_B);
  SD_CHECK_EQ_INT(t.dark, 0);                /* XP has no helpers, whatever the override says */
  SD_CHECK_EQ_INT(t.corners, 0);
  SD_CHECK_EQ_INT(t.task_dialogs, 0);

  in = mk_inputs();                          /* -1 follows the OS */
  in.forced_tier = -1;
  t = select_with(&in);
  SD_CHECK_EQ_INT(t.tier, UI_TIER_FLUENT);
  SD_CHECK_EQ_INT(t.level, UI_LEVEL_C);
}

SD_TEST(theme_palette_meets_the_contrast_floors)
{
  static const COLORREF k_accents[] = {
    RGB(0x00, 0x78, 0xD4), RGB(0xFF, 0xB9, 0x00), RGB(0xE8, 0x11, 0x23),
    RGB(0x00, 0xCC, 0x6A), RGB(0xFF, 0xFF, 0xFF), RGB(0x00, 0x00, 0x00)
  };
  static const int k_dark[2] = { 0, 1 };
  COLORREF sys[UI_TOK_COUNT], out[UI_TOK_COUNT];
  ui_theme t;
  size_t i;
  int d;

  /* Classic and Aero return the system colors untouched (06 §5.1). */
  memset(&t, 0, sizeof(t));
  t.tier = UI_TIER_CLASSIC;
  for (i = 0; i < (size_t)UI_TOK_COUNT; i++)
    sys[i] = RGB((int)i * 3, 5, 9);
  ui_theme_palette(&t, RGB(1, 2, 3), sys, out);
  for (i = 0; i < (size_t)UI_TOK_COUNT; i++)
    SD_CHECK_EQ_INT(out[i], sys[i]);

  /* Fluent light and dark: the floors of 7.1 for every accent the tests feed (06 §5.1). */
  for (d = 0; d < 2; d++) {
    memset(&t, 0, sizeof(t));
    t.tier = UI_TIER_FLUENT;
    t.level = k_dark[d] ? UI_LEVEL_B : UI_LEVEL_A;
    t.dark = k_dark[d];
    for (i = 0; i < SD_COUNTOF(k_accents); i++) {
      ui_theme_palette(&t, k_accents[i], sys, out);
      SD_CHECK(ui_theme_contrast_x100(out[UI_TOK_TEXT], out[UI_TOK_LAYER]) >= 450);
      SD_CHECK(ui_theme_contrast_x100(out[UI_TOK_TEXT_SECONDARY], out[UI_TOK_LAYER]) >= 450);
      SD_CHECK(ui_theme_contrast_x100(out[UI_TOK_ACCENT], out[UI_TOK_LAYER]) >= 300);
      SD_CHECK(ui_theme_contrast_x100(out[UI_TOK_ACCENT_TEXT], out[UI_TOK_ACCENT]) >= 450);
      SD_CHECK_EQ_INT(out[UI_TOK_FOCUS], out[UI_TOK_TEXT]);
    }
  }
}
