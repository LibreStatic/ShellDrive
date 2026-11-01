/* shelldrive-ui: the theme decision and palette (06 §4, §5.1). The decision is ui_theme_model.c (pure).
 *
 * ui_theme_select picks one of the OS tiers of 06 §3 for the running system: Classic (XP, High Contrast, no
 * visual styles, or the classic setting), Aero (Vista/7) and Fluent (8 and later) with the sub-levels
 * 'a' (8-10), 'b' (11 22000+) and 'c' (11 22621+). Dark follows AppsUseLightTheme: the documented title bar
 * on 22000+, and on Windows 10 from 1809 the undocumented uxtheme helpers of 06 §3.6 (option B, D47) behind
 * a build allow-list and a kill switch. Pure: no window or process calls, so the unit tests (tests/ui) build
 * this file on its own; ui_theme.c (not pure) gathers the inputs and applies the decision. */
#ifndef SD_UI_THEME_MODEL_H
#define SD_UI_THEME_MODEL_H

#include <windows.h>

/* Tiers (06 §4). */
#define UI_TIER_CLASSIC 0
#define UI_TIER_AERO    1
#define UI_TIER_FLUENT  2

/* Fluent sub-levels (06 §3.3): level is 0 outside Fluent, else 'a', 'b' or 'c'. */
#define UI_LEVEL_A 'a'
#define UI_LEVEL_B 'b'
#define UI_LEVEL_C 'c'

/* The [ui] style setting (06 §5.3). */
#define UI_THEME_STYLE_AUTO    0
#define UI_THEME_STYLE_CLASSIC 1

/* Build floors of the model (06 §3.3, §3.6, §12). */
#define UI_THEME_BUILD_HELPERS_MIN  17763u  /* 10 1809: the uxtheme dark-mode helpers exist */
#define UI_THEME_BUILD_ATTR20_MIN   18985u  /* the title bar attribute becomes 20 (20 from here) */
#define UI_THEME_BUILD_WIN11        22000u  /* Fluent 2b: documented dark title bar, corner preference */
#define UI_THEME_BUILD_LEVEL_C      22621u  /* Fluent 2c: DWMWA_SYSTEMBACKDROP_TYPE */
#define UI_THEME_HELPERS_MAX_TESTED 26100u  /* newest build the lab tested the helpers on (06 §3.6) */

/* The title bar attribute ids the model reports (DWMWA_USE_IMMERSIVE_DARK_MODE and its undocumented
   predecessor; the caller resolves DwmSetWindowAttribute at run time). */
#define UI_THEME_TITLEBAR_ATTR_NONE 0
#define UI_THEME_TITLEBAR_ATTR_19   19
#define UI_THEME_TITLEBAR_ATTR_20   20

/* forced_tier packs the test override of 06 §8.1 (--theme=...): bits 0-7 the tier (UI_TIER_*), bits 8-15
   the forced Fluent sub-level ('a'..'c', 0 = the level of this OS), bit 16 forces the dark palette (the
   -dark suffix), bit 17 forces the light palette (the -light suffix; wins over -dark). -1 means no override. */
#define UI_FORCE_TIER(tier, level, dark) \
  ((tier) | ((int)(unsigned char)(level) << 8) | ((dark) ? 0x10000 : 0))
#define UI_FORCE_TIER_OF(f)  ((f) & 0xFF)
#define UI_FORCE_LEVEL_OF(f) (((f) >> 8) & 0xFF)
#define UI_FORCE_DARK_OF(f)  (((f) >> 16) & 0x01)
#define UI_FORCE_LIGHT_BIT   0x20000
#define UI_FORCE_LIGHT_OF(f) (((f) >> 17) & 0x01)

typedef struct ui_theme_inputs {
  unsigned os_major, os_minor, os_build;
  int dwm_present;          /* DwmSetWindowAttribute resolved */
  int composition;          /* DwmIsCompositionEnabled, 1 on 8+ */
  int high_contrast;        /* SPI_GETHIGHCONTRAST, HCF_HIGHCONTRASTON */
  int apps_use_light;       /* AppsUseLightTheme: 0, 1, or -1 when absent */
  int themed;               /* IsAppThemed() && IsThemeActive(), 0 on the Windows Classic theme */
  int remote_session;       /* GetSystemMetrics(SM_REMOTESESSION) */
  int style_setting;        /* [ui] style: auto, classic (5.3) */
  int dark_helpers_setting; /* 1 = the helpers of 3.6 are allowed, 0 = the kill switch */
  int helper_ordinals;      /* the uxtheme ordinals of 3.6 resolved (only looked up from build 17763) */
  int forced_tier;          /* -1 none; else UI_FORCE_TIER(tier, level, dark), for the test modes */
} ui_theme_inputs;

typedef struct ui_theme {
  int tier;                 /* UI_TIER_CLASSIC, UI_TIER_AERO, UI_TIER_FLUENT */
  int level;                /* 0, or 'a' / 'b' / 'c' for Fluent */
  int glass, backdrop, dark, corners, command_bar, task_dialogs, command_links, aero_wizard;
  int dark_helpers;         /* the undocumented helpers of 3.6 are in use */
  int titlebar_attr;        /* 0 none, 19 or 20; the DWM attribute that turns the title bar dark */
} ui_theme;

/* Picks the tier and its mechanisms for the inputs (06 §4). Each mechanism is also gated by its own
   resolved function pointer in ui_theme.c, so a missing export degrades that mechanism alone. */
void ui_theme_select(const ui_theme_inputs *in, ui_theme *out);

/* 1 when the dark-mode helpers of 3.6 may be used: the kill switch off, build 17763 or later, and either a
   build on the tested allow-list (up to UI_THEME_HELPERS_MAX_TESTED) or, on a newer build, the proof that
   the ordinal exports resolve. */
int ui_theme_helpers_allowed(unsigned build, int ordinals_present, int setting);

/* Palette tokens (06 §5.1). */
typedef enum ui_tok {
  UI_TOK_SURFACE, UI_TOK_LAYER, UI_TOK_TEXT, UI_TOK_TEXT_SECONDARY, UI_TOK_ACCENT, UI_TOK_ACCENT_TEXT,
  UI_TOK_STROKE, UI_TOK_SELECTION, UI_TOK_FOCUS, UI_TOK_WARNING, UI_TOK_ERROR, UI_TOK_COUNT
} ui_tok;

/* Fills out with the colors of the theme: Classic and Aero get the sys values (the caller fills them from
   GetSysColor), Fluent light/dark the palettes of 5.1. The accent is adjusted, lighter on dark and darker
   on light, until it meets the contrast floor against the layer. */
void ui_theme_palette(const ui_theme *t, COLORREF accent, const COLORREF sys[UI_TOK_COUNT],
                      COLORREF out[UI_TOK_COUNT]);

/* WCAG 2.x contrast ratio of two colors, times 100 (sRGB linearization). */
unsigned ui_theme_contrast_x100(COLORREF a, COLORREF b);

#endif /* SD_UI_THEME_MODEL_H */
