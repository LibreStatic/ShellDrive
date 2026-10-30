/* shelldrive-ui: the first-run wizard decision (03 §7.5). See ui_wizard_model.h. */
#include <windows.h>

#include "sd/base.h"
#include "ui_wizard_model.h"

int ui_wizard_should_show(size_t profile_count, int first_run_done, int tray_mode, int prompt_host)
{
  if (tray_mode || prompt_host || first_run_done)
    return 0;
  return profile_count == 0 ? 1 : 0;
}
