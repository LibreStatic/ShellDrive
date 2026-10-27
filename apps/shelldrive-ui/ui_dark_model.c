/* shelldrive-ui: the dark mode decision (03 §7.4). See ui_dark_model.h. */
#include <windows.h>

#include "ui_dark_model.h"

int ui_dark_wanted(unsigned os_build, int dwm_present, int apps_use_light)
{
  if (os_build < UI_DARK_MIN_BUILD || !dwm_present)
    return 0;                 /* XP, 7, 8, 8.1, 10: stay light (03 §7.4) */
  return apps_use_light == 0 ? 1 : 0;   /* -1 (absent) and 1 (light apps) are light */
}
