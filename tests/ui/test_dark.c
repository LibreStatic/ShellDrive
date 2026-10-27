/* The dark mode decision (apps/shelldrive-ui/ui_dark_model.c, 03 §7.4). Pure: the inputs are the OS build, whether
   DwmSetWindowAttribute was resolved, and the AppsUseLightTheme value (-1 when absent). */
#include <windows.h>

#include "sd_test.h"
#include "ui_dark_model.h"

SD_TEST(dark_needs_build_22000_and_the_api)
{
  SD_CHECK_EQ_INT(ui_dark_wanted(22000u, 1, 0), 1);
  SD_CHECK_EQ_INT(ui_dark_wanted(22631u, 1, 0), 1);
  SD_CHECK_EQ_INT(ui_dark_wanted(21999u, 1, 0), 0);      /* last Windows 10 build */
  SD_CHECK_EQ_INT(ui_dark_wanted(22000u, 0, 0), 0);      /* API not resolved */
  SD_CHECK_EQ_INT((int)UI_DARK_MIN_BUILD, 22000);
  SD_CHECK_EQ_INT((int)UI_DARK_ATTRIBUTE, 20);
}

SD_TEST(dark_follows_the_app_theme_value)
{
  SD_CHECK_EQ_INT(ui_dark_wanted(22631u, 1, 0), 1);      /* dark apps */
  SD_CHECK_EQ_INT(ui_dark_wanted(22631u, 1, 1), 0);      /* light apps */
  SD_CHECK_EQ_INT(ui_dark_wanted(22631u, 1, -1), 0);     /* value absent: light */
}

SD_TEST(dark_stays_light_on_older_systems)
{
  SD_CHECK_EQ_INT(ui_dark_wanted(2600u, 1, 0), 0);       /* Windows XP */
  SD_CHECK_EQ_INT(ui_dark_wanted(7601u, 1, 0), 0);       /* Windows 7 SP1 */
  SD_CHECK_EQ_INT(ui_dark_wanted(9200u, 1, 0), 0);       /* Windows 8 */
  SD_CHECK_EQ_INT(ui_dark_wanted(19045u, 1, 0), 0);      /* Windows 10 22H2 */
  SD_CHECK_EQ_INT(ui_dark_wanted(0u, 1, 0), 0);          /* unknown version */
}
