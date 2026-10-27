/* The first-run wizard decision (apps/shelldrive-ui/ui_wizard_model.c, 03 §7.5): it opens once, for an empty store,
   and never for --tray or the prompt host. The pages themselves are created by the smoke test (--test-wizard). */
#include <windows.h>

#include "sd_test.h"
#include "ui_wizard_model.h"

SD_TEST(wizard_opens_for_an_empty_store_only_once)
{
  SD_CHECK_EQ_INT(ui_wizard_should_show(0, 0, 0, 0), 1);
  SD_CHECK_EQ_INT(ui_wizard_should_show(0, 1, 0, 0), 0);    /* first_run_done = yes */
  SD_CHECK_EQ_INT(ui_wizard_should_show(1, 0, 0, 0), 0);    /* a profile exists */
  SD_CHECK_EQ_INT(ui_wizard_should_show(5, 0, 0, 0), 0);
}

SD_TEST(wizard_never_opens_for_tray_or_prompt_host)
{
  SD_CHECK_EQ_INT(ui_wizard_should_show(0, 0, 1, 0), 0);    /* --tray */
  SD_CHECK_EQ_INT(ui_wizard_should_show(0, 0, 0, 1), 0);    /* --prompt-host */
  SD_CHECK_EQ_INT(ui_wizard_should_show(0, 0, 1, 1), 0);
}
