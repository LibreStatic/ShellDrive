/* shelldrive-ui: the theme decision and the palette (06 §4, §5.1). See ui_theme_model.h. */
#include <windows.h>

#include <math.h>
#include <string.h>

#include "ui_theme_model.h"

/* The contrast floors of 7.1, times 100: the accent is a UI boundary (3:1) and is adjusted in the palette
   until it reads as text against the layer (4.5:1). */
#define UI_CONTRAST_TEXT_X100   450
#define UI_CONTRAST_ACCENT_X100 450
/* The step of one accent adjustment, in RGB units toward black (light) or white (dark). */
#define UI_ACCENT_STEP 8

static int is_aero_os(const ui_theme_inputs *in)
{
  return in->os_major == 6 && (in->os_minor == 0 || in->os_minor == 1);
}

static int is_fluent_os(const ui_theme_inputs *in)
{
  return in->os_major > 6 || (in->os_major == 6 && in->os_minor >= 2);
}

void ui_theme_select(const ui_theme_inputs *in, ui_theme *out)
{
  int tier, level = 0, helpers, apps_light;

  memset(out, 0, sizeof(*out));

  /* The tier: High Contrast, the classic setting or no visual styles force Classic (3.1, 7.1); the OS
     decides otherwise. task_dialogs, command_links and the Aero wizard stay on Vista+ in every tier, they
     follow High Contrast by themselves (06 §4). */
  if (in->high_contrast || in->style_setting == UI_THEME_STYLE_CLASSIC || !in->themed)
    tier = UI_TIER_CLASSIC;
  else if (is_aero_os(in))
    tier = UI_TIER_AERO;
  else if (is_fluent_os(in))
    tier = UI_TIER_FLUENT;
  else
    tier = UI_TIER_CLASSIC;                    /* XP and anything older (06 §3.1) */

  if (tier == UI_TIER_FLUENT) {
    if (in->os_build >= UI_THEME_BUILD_LEVEL_C)
      level = UI_LEVEL_C;
    else if (in->os_build >= UI_THEME_BUILD_WIN11)
      level = UI_LEVEL_B;
    else
      level = UI_LEVEL_A;                      /* 8, 8.1 and 10 (06 §3.3) */
  }

  if (in->forced_tier != -1) {                 /* the --theme override of the test modes (06 §8.1) */
    tier = UI_FORCE_TIER_OF(in->forced_tier);
    if (tier != UI_TIER_FLUENT)
      level = 0;                               /* only Fluent has a sub-level (06 §3.3) */
    else if (UI_FORCE_LEVEL_OF(in->forced_tier) != 0)
      level = UI_FORCE_LEVEL_OF(in->forced_tier);
  }

  out->tier = tier;
  out->level = level;
  out->command_bar = tier == UI_TIER_FLUENT;
  out->task_dialogs = in->os_major >= 6;
  out->command_links = out->task_dialogs;
  out->aero_wizard = out->task_dialogs;
  out->glass = tier == UI_TIER_AERO && in->composition && !in->remote_session && in->dwm_present;
  out->backdrop = tier == UI_TIER_FLUENT && level == UI_LEVEL_C && in->dwm_present;
  out->corners = tier == UI_TIER_FLUENT && in->os_build >= UI_THEME_BUILD_WIN11 && in->dwm_present;

  helpers = ui_theme_helpers_allowed(in->os_build, in->helper_ordinals, in->dark_helpers_setting);

  /* Dark: Fluent only, when apps use the dark theme, through the documented title bar on 22000+ or the
     helpers from 1809 (06 §3.5, §3.6). Windows 10 without the helpers stays light. */
  apps_light = in->apps_use_light;
  if (in->forced_tier != -1 && UI_FORCE_DARK_OF(in->forced_tier))
    apps_light = 0;                          /* the -dark suffix of --theme (06 §8.1) */
  if (tier == UI_TIER_FLUENT && apps_light == 0 && in->dwm_present &&
      (in->os_build >= UI_THEME_BUILD_WIN11 || helpers))
    out->dark = 1;
  out->dark_helpers = out->dark && helpers;

  /* The title bar attribute: 20 from build 18985, 19 on 17763..18984 with the helpers, nothing otherwise. */
  if (out->dark) {
    if (in->os_build >= UI_THEME_BUILD_ATTR20_MIN)
      out->titlebar_attr = UI_THEME_TITLEBAR_ATTR_20;
    else if (out->dark_helpers)
      out->titlebar_attr = UI_THEME_TITLEBAR_ATTR_19;
  }
}

int ui_theme_helpers_allowed(unsigned build, int ordinals_present, int setting)
{
  if (!setting || build < UI_THEME_BUILD_HELPERS_MIN)
    return 0;                        /* the kill switch, or a build without the ordinals (06 §3.6) */
  if (build <= UI_THEME_HELPERS_MAX_TESTED)
    return 1;                        /* on the allow-list kept from the lab runs */
  return ordinals_present ? 1 : 0;   /* newer builds keep them only while the exports resolve */
}

/* WCAG 2.x relative luminance of one sRGB channel. */
static double channel_luminance(unsigned c)
{
  double v = (double)c / 255.0;
  if (v <= 0.03928)
    return v / 12.92;
  return pow((v + 0.055) / 1.055, 2.4);
}

unsigned ui_theme_contrast_x100(COLORREF a, COLORREF b)
{
  double la = 0.2126 * channel_luminance(a & 0xFF) + 0.7152 * channel_luminance((a >> 8) & 0xFF) +
              0.0722 * channel_luminance((a >> 16) & 0xFF);
  double lb = 0.2126 * channel_luminance(b & 0xFF) + 0.7152 * channel_luminance((b >> 8) & 0xFF) +
              0.0722 * channel_luminance((b >> 16) & 0xFF);
  double hi = la > lb ? la : lb;
  double lo = la > lb ? lb : la;

  return (unsigned)(((hi + 0.05) / (lo + 0.05)) * 100.0 + 0.5);
}

/* One step of the accent adjustment: toward white on dark, toward black on light. */
static COLORREF accent_step(COLORREF c, int dark)
{
  int r = (int)(c & 0xFF), g = (int)((c >> 8) & 0xFF), b = (int)((c >> 16) & 0xFF);

  if (dark) {
    r += UI_ACCENT_STEP < 255 - r ? UI_ACCENT_STEP : 255 - r;
    g += UI_ACCENT_STEP < 255 - g ? UI_ACCENT_STEP : 255 - g;
    b += UI_ACCENT_STEP < 255 - b ? UI_ACCENT_STEP : 255 - b;
  } else {
    r -= UI_ACCENT_STEP < r ? UI_ACCENT_STEP : r;
    g -= UI_ACCENT_STEP < g ? UI_ACCENT_STEP : g;
    b -= UI_ACCENT_STEP < b ? UI_ACCENT_STEP : b;
  }
  return RGB(r, g, b);
}

/* The accent is adjusted until it meets the text floor against the layer (5.1); the direction is bounded,
   so the loop ends at the ramp end at the latest. */
static COLORREF adjust_accent(COLORREF accent, COLORREF layer, int dark)
{
  int i;
  for (i = 0; i < 40 && ui_theme_contrast_x100(accent, layer) < UI_CONTRAST_ACCENT_X100; i++) {
    COLORREF next = accent_step(accent, dark);
    if (next == accent)
      break;
    accent = next;
  }
  return accent;
}

/* Black or white, whichever contrasts more with the accent. */
static COLORREF accent_text_for(COLORREF accent)
{
  return ui_theme_contrast_x100(RGB(255, 255, 255), accent) >=
         ui_theme_contrast_x100(RGB(0, 0, 0), accent) ? RGB(255, 255, 255) : RGB(0, 0, 0);
}

/* White blended 8% over the layer: the dark selection of 5.1. */
static COLORREF blend_selection(COLORREF layer)
{
  int r = (int)(layer & 0xFF), g = (int)((layer >> 8) & 0xFF), b = (int)((layer >> 16) & 0xFF);

  return RGB((unsigned)((r * 92 + 255 * 8 + 50) / 100), (unsigned)((g * 92 + 255 * 8 + 50) / 100),
             (unsigned)((b * 92 + 255 * 8 + 50) / 100));
}

void ui_theme_palette(const ui_theme *t, COLORREF accent, const COLORREF sys[UI_TOK_COUNT],
                      COLORREF out[UI_TOK_COUNT])
{
  COLORREF layer;
  int dark;

  if (t->tier != UI_TIER_FLUENT) {
    memcpy(out, sys, sizeof(COLORREF) * UI_TOK_COUNT);   /* Classic and Aero: the system colors (06 §5.1) */
    return;
  }

  dark = t->dark;
  out[UI_TOK_SURFACE] = dark ? RGB(0x1F, 0x21, 0x28) : RGB(0xF3, 0xF3, 0xF3);
  layer = dark ? RGB(0x2A, 0x2C, 0x33) : RGB(0xFF, 0xFF, 0xFF);
  out[UI_TOK_LAYER] = layer;
  out[UI_TOK_TEXT] = dark ? RGB(0xFF, 0xFF, 0xFF) : RGB(0x1A, 0x1A, 0x1A);
  out[UI_TOK_TEXT_SECONDARY] = dark ? RGB(0xC5, 0xC5, 0xC5) : RGB(0x5C, 0x5C, 0x5C);
  out[UI_TOK_STROKE] = dark ? RGB(0x38, 0x3B, 0x43) : RGB(0xE0, 0xE3, 0xE8);
  out[UI_TOK_SELECTION] = dark ? blend_selection(layer) : RGB(0xEA, 0xF1, 0xFB);
  out[UI_TOK_WARNING] = dark ? RGB(0xFC, 0xE1, 0x00) : RGB(0x8A, 0x53, 0x00);
  out[UI_TOK_ERROR] = dark ? RGB(0xFF, 0x99, 0xA4) : RGB(0xC4, 0x2B, 0x1C);
  accent = adjust_accent(accent, layer, dark);
  out[UI_TOK_ACCENT] = accent;
  out[UI_TOK_ACCENT_TEXT] = accent_text_for(accent);
  out[UI_TOK_FOCUS] = out[UI_TOK_TEXT];
}
