/* DPI scaling helpers (apps/shelldrive-ui/ui_dpi.c). Pure arithmetic: no window is needed. */
#include <windows.h>

#include "sd_test.h"
#include "ui_dpi.h"

SD_TEST(dpi_scale_rounding_and_clamp)
{
  SD_CHECK_EQ_INT(ui_dpi_scale(96, 96), 96);
  SD_CHECK_EQ_INT(ui_dpi_scale(10, 144), 15);
  SD_CHECK_EQ_INT(ui_dpi_scale(7, 120), 9);          /* 8.75 rounds to 9 */
  SD_CHECK_EQ_INT(ui_dpi_scale(-7, 120), -9);        /* symmetric for negative values */
  SD_CHECK_EQ_INT(ui_dpi_scale(0, 200), 0);
  SD_CHECK_EQ_INT(ui_dpi_scale(10, 0), 10);          /* dpi 0 means 96 */
  SD_CHECK_EQ_INT(ui_dpi_scale(96, 1000), 960);      /* clamped to 960 */
  SD_CHECK_EQ_INT(ui_dpi_scale(100, 10), 50);        /* clamped to 48 */
  SD_CHECK_EQ_INT(ui_dpi_scale(2147483647, 960) > 0, 1);   /* no overflow */
}

SD_TEST(dpi_font_height)
{
  SD_CHECK_EQ_INT(ui_dpi_font_height(9, 96), -12);
  SD_CHECK_EQ_INT(ui_dpi_font_height(9, 120), -15);
  SD_CHECK_EQ_INT(ui_dpi_font_height(9, 144), -18);
  SD_CHECK_EQ_INT(ui_dpi_font_height(8, 96), -11);   /* 8 * 96 / 72 = 10.67 rounds to 11 */
}
