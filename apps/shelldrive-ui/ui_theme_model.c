/* shelldrive-ui: the theme decision and the palette (06 §4, §5.1). See ui_theme_model.h. */
#include <windows.h>

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
  if (in->forced_tier != -1 && UI_FORCE_LIGHT_OF(in->forced_tier))
    apps_light = 1;                          /* the -light suffix of --theme */
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

/* WCAG 2.x linear value of each 8-bit sRGB channel: c/255/12.92 up to 0.03928, else ((c/255+0.055)/1.055)^2.4.
   A table instead of pow(): the x86 CRT math dispatcher is not on the x86-ia32 ISA allow list (tools/sd-isacheck). */
static const double k_linear[256] = {
  0.0000000000, 0.0003035270, 0.0006070540, 0.0009105810, 0.0012141079, 0.0015176349,
  0.0018211619, 0.0021246889, 0.0024282159, 0.0027317429, 0.0030352698, 0.0033465358,
  0.0036765073, 0.0040247170, 0.0043914420, 0.0047769535, 0.0051815167, 0.0056053916,
  0.0060488330, 0.0065120908, 0.0069954102, 0.0074990320, 0.0080231930, 0.0085681256,
  0.0091340587, 0.0097212173, 0.0103298230, 0.0109600940, 0.0116122452, 0.0122864884,
  0.0129830323, 0.0137020830, 0.0144438436, 0.0152085144, 0.0159962934, 0.0168073758,
  0.0176419545, 0.0185002201, 0.0193823610, 0.0202885631, 0.0212190104, 0.0221738848,
  0.0231533662, 0.0241576324, 0.0251868596, 0.0262412219, 0.0273208916, 0.0284260395,
  0.0295568344, 0.0307134437, 0.0318960331, 0.0331047666, 0.0343398068, 0.0356013149,
  0.0368894504, 0.0382043716, 0.0395462353, 0.0409151969, 0.0423114106, 0.0437350293,
  0.0451862044, 0.0466650863, 0.0481718242, 0.0497065660, 0.0512694584, 0.0528606470,
  0.0544802764, 0.0561284900, 0.0578054302, 0.0595112382, 0.0612460542, 0.0630100177,
  0.0648032667, 0.0666259386, 0.0684781698, 0.0703600957, 0.0722718507, 0.0742135684,
  0.0761853815, 0.0781874218, 0.0802198203, 0.0822827071, 0.0843762115, 0.0865004620,
  0.0886555863, 0.0908417112, 0.0930589628, 0.0953074666, 0.0975873471, 0.0998987282,
  0.1022417331, 0.1046164841, 0.1070231030, 0.1094617108, 0.1119324278, 0.1144353738,
  0.1169706678, 0.1195384280, 0.1221387722, 0.1247718176, 0.1274376804, 0.1301364767,
  0.1328683216, 0.1356333297, 0.1384316150, 0.1412632911, 0.1441284709, 0.1470272665,
  0.1499597898, 0.1529261520, 0.1559264637, 0.1589608351, 0.1620293756, 0.1651321945,
  0.1682694002, 0.1714411007, 0.1746474037, 0.1778884160, 0.1811642442, 0.1844749945,
  0.1878207723, 0.1912016827, 0.1946178304, 0.1980693196, 0.2015562538, 0.2050787364,
  0.2086368701, 0.2122307574, 0.2158605001, 0.2195261997, 0.2232279573, 0.2269658735,
  0.2307400485, 0.2345505822, 0.2383975738, 0.2422811225, 0.2462013267, 0.2501582847,
  0.2541520943, 0.2581828529, 0.2622506575, 0.2663556048, 0.2704977910, 0.2746773121,
  0.2788942635, 0.2831487404, 0.2874408377, 0.2917706498, 0.2961382708, 0.3005437944,
  0.3049873141, 0.3094689228, 0.3139887134, 0.3185467781, 0.3231432091, 0.3277780981,
  0.3324515363, 0.3371636150, 0.3419144249, 0.3467040564, 0.3515325995, 0.3564001441,
  0.3613067798, 0.3662525956, 0.3712376805, 0.3762621230, 0.3813260114, 0.3864294338,
  0.3915724777, 0.3967552307, 0.4019777798, 0.4072402119, 0.4125426135, 0.4178850708,
  0.4232676700, 0.4286904966, 0.4341536362, 0.4396571738, 0.4452011945, 0.4507857828,
  0.4564110232, 0.4620769997, 0.4677837961, 0.4735314961, 0.4793201831, 0.4851499401,
  0.4910208498, 0.4969329951, 0.5028864580, 0.5088813209, 0.5149176654, 0.5209955732,
  0.5271151257, 0.5332764040, 0.5394794890, 0.5457244614, 0.5520114015, 0.5583403896,
  0.5647115057, 0.5711248295, 0.5775804404, 0.5840784179, 0.5906188409, 0.5972017884,
  0.6038273389, 0.6104955708, 0.6172065624, 0.6239603917, 0.6307571363, 0.6375968740,
  0.6444796820, 0.6514056374, 0.6583748173, 0.6653872983, 0.6724431570, 0.6795424696,
  0.6866853124, 0.6938717613, 0.7011018919, 0.7083757799, 0.7156935005, 0.7230551289,
  0.7304607401, 0.7379104088, 0.7454042095, 0.7529422168, 0.7605245047, 0.7681511472,
  0.7758222183, 0.7835377915, 0.7912979403, 0.7991027380, 0.8069522577, 0.8148465722,
  0.8227857544, 0.8307698768, 0.8387990117, 0.8468732315, 0.8549926081, 0.8631572135,
  0.8713671192, 0.8796223969, 0.8879231179, 0.8962693534, 0.9046611744, 0.9130986518,
  0.9215818563, 0.9301108584, 0.9386857285, 0.9473065367, 0.9559733532, 0.9646862479,
  0.9734452904, 0.9822505503, 0.9911020971, 1.0000000000
};

static double channel_luminance(unsigned c)
{
  return k_linear[c & 0xFF];
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
