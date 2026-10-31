# 06 — OS-tiered UI rendering (proposal)

Status: **proposal, not accepted.** It extends 03 §7 (tray and main window) and §11 (accessibility) and, once the
user accepts an option of §10, its decisions are folded into 03 §7.1, §7.4 and §11 and recorded in `decisions.md`.
Until then 03 stays authoritative. Conventions are 03's: "XP" means Windows XP SP3, every API newer than XP is
resolved at run time (`sd_platform_resolve`, `sd_platform_resolve_by_name`), and facts not confirmed against a primary
source are marked **[verify]** and listed in the lab plan (§8).

Scope: `apps/shelldrive-ui` (tray, main window, first-run wizard, profile editor, prompts, the M3 windows). The shell
extension (`apps/shelldrive-shellext`) draws nothing of its own beyond menu bitmaps and keeps 03 §8; the setup EXE
(04) is out of scope.

---

## 1. Where the UI stands (survey, 2026-10-31)

- Toolkit (03 §7.1): pure Win32 and comctl32 v6 from the manifest, dialogs generated in memory from C tables with a
  measuring layout pass (`ui_dlg.c`), property sheets for the profile editor (`ui_editor.c`) and a `PSH_WIZARD97`
  wizard (`ui_wizard.c`). Main window (`ui_main.c`): menu bar, flat text-only toolbar, report ListView with groups,
  status bar; `COLOR_BTNFACE` class brush.
- Font: the `SPI_GETNONCLIENTMETRICS` message font, rescaled to the window DPI (`ui_win_font`): Tahoma on XP, Segoe
  UI on Vista and later. No theme fonts (`TEXT_MAININSTRUCTION`), no Segoe UI Variable.
- DPI (03 §7.3, `ui_dpi.c`): PerMonitorV2 on 10 1703+, system DPI elsewhere, `WM_DPICHANGED` re-runs the layout.
  This already adapts per OS and needs no change here.
- Dark mode (03 §7.4, `ui_dark.c`, `ui_dark_model.c`): only the title bar, with `DWMWA_USE_IMMERSIVE_DARK_MODE` on
  build 22000+ when `AppsUseLightTheme = 0`, applied to every captioned window of the UI thread by a `WH_CBT` hook.
  Client areas stay light (`GetSysColor`), so on Windows 11 dark a window has a dark title bar over a light body.
- Tray (03 §7.2): `NOTIFYICONDATA` size and version per OS, light/dark icon variants from `SystemUsesLightTheme`,
  standard popup menu.
- Not used anywhere: DWM frame extension or backdrops, `uxtheme` drawing (`DrawThemeTextEx`, buffered paint),
  `TaskDialogIndirect`, command links, `PSH_AEROWIZARD`, custom draw. Message boxes are `MessageBoxW`.
- Imports: the XP floor lists (`tests/os-imports/xp-*.txt`) have neither `dwmapi.dll` nor `uxtheme.dll`, so on the
  XP flavours both must stay dynamic; the x64-modern floor (Windows 10 1507) has `uxtheme.dll!*` but not `dwmapi.dll`.

What adapts per OS today: DPI, the notification structure, the tray icon variant and the Windows 11 dark title bar.
Everything else renders the same from XP to 11, which is why the UI reads as an XP-era application on 10 and 11.

## 2. Goals and non-goals

- One code base, **one binary per flavour**, choosing the look at run time (§4). The XP floor and the import checks
  stay as they are.
- Each tier looks native to its OS generation: XP classic with visual styles; Vista/7 Aero; 10/11 Fluent-like.
- Documented APIs first. Anything undocumented is an explicit, separately decided option (§10, option B).
- No new third-party code (D1), no new runtime dependency, no change to the IPC, the models or the strings of
  existing screens beyond what §7 lists.
- Accessibility and High Contrast never regress: every tier keeps standard controls and their MSAA/UIA proxies.
- Non-goal: WinUI 3, XAML Islands, Direct2D/DirectWrite rendering (§3.4). Non-goal: animations beyond what DWM and
  the common controls do themselves.

## 3. Mechanisms per tier

### 3.1 Tier 0, Classic (XP; also the fallback everywhere)

What exists today: comctl32 v6 visual styles (Luna, Royale, Classic), Tahoma message font, Wizard97, standard
dialogs. Additions that cost nothing on XP:

- Consistent spacing tokens (margins, row gaps) in the layout tables, at 96-DPI units scaled per DPI. These help every
  tier and are the only XP-visible change.
- Nothing from `dwmapi` or post-XP `uxtheme`/comctl32; `SetWindowTheme` and `OpenThemeData` exist on XP but are not
  needed by this tier.

Classic is also chosen on any OS when High Contrast is on, when the user or policy forces it (§5.3), and as the
fallback of any tier whose capability probe fails.

### 3.2 Tier 1, Aero (Vista, 7; composition on)

| Mechanism | API | Floor | Load |
|---|---|---|---|
| Glass header band in the main window | `DwmExtendFrameIntoClientArea`, `DwmIsCompositionEnabled` | Vista | `dwmapi.dll` by name |
| Text and icons on glass | `DrawThemeTextEx` (`DTT_COMPOSITED`, `DTT_GLOWSIZE`), `BeginBufferedPaint` / `BufferedPaintSetAlpha` | Vista | `uxtheme.dll` by name |
| Main instruction font and color | `OpenThemeData(L"TEXTSTYLE")`, `GetThemeFont` / `GetThemeColor` (`TEXT_MAININSTRUCTION`) | Vista | `uxtheme.dll` |
| Task dialogs for errors and confirmations (not trust decisions, §6.2) | `TaskDialogIndirect` | Vista, comctl32 v6 | `GetProcAddress` on the loaded comctl32 |
| Command links in prompts | `BS_COMMANDLINK`, `BCM_SETNOTE`, `BCM_GETIDEALSIZE` | Vista | style chosen at run time |
| Aero wizard | `PSH_AEROWIZARD` | Vista | flag chosen at run time |
| Larger, crisp icons | `LoadIconMetric` / `LoadIconWithScaleDown` | Vista | comctl32 by name |

Notes:

- Composition can be off on Vista and 7 (Basic or Classic theme, some RDP sessions, VMs without a WDDM driver).
  The tier checks `DwmIsCompositionEnabled` at start and on `WM_DWMCOMPOSITIONCHANGED` and drops the glass band
  (keeping task dialogs, command links, the Aero wizard and theme fonts, which do not need composition).
- On 8, 8.1 and 10 the extended frame is drawn opaque, without blur **[verify]**, so the glass band is used on Vista
  and 7 only. 8/8.1 use tier 2 in its light form.
- GDI text drawn on an extended frame comes out with alpha 0 (invisible). Every pixel we draw on glass goes through
  buffered paint or `DrawThemeTextEx`; child controls are never placed on the glass region.

### 3.3 Tier 2, Fluent (8, 8.1, 10, 11)

Sub-levels by documented capability, not by marketing version:

| Level | Build | Adds |
|---|---|---|
| 2a | 8 – 10 (9200 – 19045) | Flat light look: white content surface, accent color from `DwmGetColorizationColor`, Segoe UI with the theme text sizes, command bar instead of the menu bar (§6.1), no backdrop. |
| 2b | 11 21H2 (22000+) | Dark title bar (already shipped), client-area dark palette (§3.5), `DWMWA_WINDOW_CORNER_PREFERENCE` (33) for our popups, `DWMWA_BORDER_COLOR` (34) to match the accent. |
| 2c | 11 22H2 (22621+) | Mica backdrop: `DWMWA_SYSTEMBACKDROP_TYPE` (38) = `DWMSBT_MAINWINDOW` (2) on the main window, `DWMSBT_TRANSIENTWINDOW` (3, Acrylic) on the tray flyout if built (§6.3). |

- `DWMWA_SYSTEMBACKDROP_TYPE` is documented from 22621; the earlier undocumented `DWMWA_MICA_EFFECT` (1029) of
  22000 is not used.
- DWM disables the backdrop itself (solid fallback color) when transparency effects are off, in battery saver, in
  most RDP sessions and when the window is inactive. Our drawing must look right on the solid fallback, which it
  does if the backdrop region is drawn as "transparent over the theme background" and nothing relies on blur.
- Mica is only visible where the client pixels are transparent: the frame is extended into the top band of the
  window (title + command bar, as in File Explorer and Notepad) and the band is painted with buffered paint. The
  content area (the ListView) stays an opaque "layer" surface. Whether the toolbar control can be custom drawn into
  the extended region with correct alpha is spike **S1** (§8.3); the fallback is a Mica title bar over an opaque
  command bar, which is still visually consistent with Windows 11.
- Fonts: the message font stays the base (Segoe UI). On 11, "Segoe UI Variable Text/Display" is used for the window
  title and section headers when `EnumFontFamiliesExW` finds it; otherwise Segoe UI at the theme sizes.
- Rounded corners on top-level windows come from Windows 11 itself; we only set the preference on our own popups.
  Inside the client area we keep square GDI shapes (GDI `RoundRect` is not antialiased); selection and focus use
  filled rectangles with a 1-px accent line, which reads as Fluent without antialiasing.

### 3.4 Rejected mechanisms

- **WinUI 3 (Windows App SDK).** Needs the Windows App SDK runtime (framework package or a self-contained copy of
  tens of MB), C++/WinRT, Windows 10 1809+. Not callable from C in any maintainable way, adds a runtime dependency
  and Microsoft binaries to redistribute, cannot exist in the XP flavours, and would split every screen into two
  implementations. Rejected.
- **XAML Islands (system XAML).** Windows 10 1903+, C++/WinRT, effectively frozen by Microsoft in favor of WinUI 3.
  Same split and same C problem. Rejected (03 §7.1 already excludes it).
- **Direct2D / DirectWrite for owner-drawn surfaces.** Available on 7 SP1 (and Vista SP2 with the platform update),
  loadable dynamically, gives antialiased rounded shapes. It adds a second rendering path for little visible gain
  over GDI + buffered paint for a list-and-buttons UI. Not now; revisit only if a future screen needs it.
- **Separate "modern" binaries.** The x86 and x64-xp flavours run on XP through 11, so they need run-time tiers
  regardless; x64-modern still spans 10 1507 to 11 and needs levels 2a–2c at run time. A separate build would add
  flavours and lab runs without removing any run-time check.

### 3.5 Dark client areas

There is no documented Win32 dark mode for the common controls (03 §7.4 stands). With documented messages only, the
main window's controls can be painted dark:

| Control | Documented technique | Residual light parts |
|---|---|---|
| ListView | `LVM_SETBKCOLOR`, `LVM_SETTEXTCOLOR`, `LVM_SETTEXTBKCOLOR`; `NM_CUSTOMDRAW` for group headers and selection | scroll bars |
| Header | `NM_CUSTOMDRAW` from the header (`CDDS_ITEMPREPAINT`), background in `WM_ERASEBKGND` of a subclass | none |
| Toolbar / command bar | `NM_CUSTOMDRAW` (`TBCDRF_*`, `CDRF_SKIPDEFAULT` with our own item drawing) | none |
| Status band | replaced by a `STATIC` (`SS_OWNERDRAW` keeps its window text as the accessible name) | none |
| Edit, list box | `WM_CTLCOLOREDIT` / `WM_CTLCOLORLISTBOX` | scroll bars, edit border on some themes |
| Push buttons, check boxes, radios | `NM_CUSTOMDRAW` from v6 buttons (text color and background), focus ring drawn by us | check glyph keeps the light theme part **[verify]** |
| Menu bar, popup menus | none documented short of fully owner-drawn menus | menu bar (removed in tier 2, §6.1), popup menus stay light |
| Property sheet tabs, combo drop-downs, spin boxes, date pickers | none practical | stay light |

Conclusion: with documented APIs, the **main window** (and the tray flyout) can be fully dark except scroll bars;
dialogs with combo boxes, tabs and spin boxes (profile editor, Settings) cannot. Those keep the light body with a
dark title bar, as today, unless option B (§10) is chosen. The pure decision function `ui_dark_wanted` grows into the
theme model of §5.

## 4. Tier selection

A single pure function, `ui_theme_select`, in a new `ui_theme_model.c` (unit tested like `ui_dark_model.c`):

```c
typedef struct ui_theme_inputs {
  unsigned os_major, os_minor, os_build;
  int dwm_present;          /* DwmSetWindowAttribute resolved */
  int composition;          /* DwmIsCompositionEnabled, 1 on 8+ */
  int high_contrast;        /* SPI_GETHIGHCONTRAST, HCF_HIGHCONTRASTON */
  int apps_use_light;       /* AppsUseLightTheme: 0, 1, or -1 when absent */
  int themed;               /* IsAppThemed() && IsThemeActive(), 0 on the Windows Classic theme */
  int remote_session;       /* GetSystemMetrics(SM_REMOTESESSION) */
  int style_setting;        /* [ui] style: auto, classic (5.3) */
} ui_theme_inputs;

typedef struct ui_theme {
  int tier;                 /* UI_TIER_CLASSIC, UI_TIER_AERO, UI_TIER_FLUENT */
  int level;                /* 0, or 'a' / 'b' / 'c' for Fluent */
  int glass, backdrop, dark, corners, command_bar, task_dialogs, command_links, aero_wizard;
} ui_theme;

void ui_theme_select(const ui_theme_inputs *in, ui_theme *out);
```

Rules, in order: High Contrast or `style = classic` or not themed → Classic (task dialogs and the Aero wizard stay
on, they follow High Contrast by themselves). XP → Classic. Vista/7 → Aero, `glass` only with composition and not
in a remote session. 8–10 → Fluent 2a. 22000+ → 2b, `dark` from `AppsUseLightTheme`. 22621+ → 2c with `backdrop`.
Each mechanism is also gated by its own resolved function pointer, so a missing export degrades that mechanism
alone.

`ui_theme.c` (not pure) gathers the inputs, resolves the functions, owns the palette (brushes, colors, fonts per
DPI) and re-selects on `WM_SETTINGCHANGE` (`ImmersiveColorSet`, `WindowsThemeElement`), `WM_THEMECHANGED`,
`WM_SYSCOLORCHANGE`, `WM_DWMCOMPOSITIONCHANGED` and `WM_DPICHANGED`. `ui_dark.c` becomes the title-bar part of it.
Windows ask the theme for colors and brushes instead of calling `GetSysColor` directly; in Classic and High Contrast
the theme returns exactly the `GetSysColor` values, so those paths are unchanged.

New run-time resolutions, all by name from System32 (`sd_platform_resolve_by_name`), cached in `ui_theme.c`:
`dwmapi!DwmExtendFrameIntoClientArea`, `DwmIsCompositionEnabled`, `DwmGetColorizationColor`,
`DwmSetWindowAttribute` (already used), `uxtheme!BufferedPaintInit`, `BeginBufferedPaint`, `EndBufferedPaint`,
`BufferedPaintSetAlpha`, `DrawThemeTextEx`, `OpenThemeData`, `CloseThemeData`, `GetThemeFont`, `GetThemeColor`,
`IsAppThemed`, `IsThemeActive`, `comctl32!TaskDialogIndirect`, `LoadIconMetric`. No new static import in any flavour;
`importcheck` proves it on every build (§8.1).

## 5. Palette, typography, settings

### 5.1 Palette

Semantic tokens, not raw colors: `surface`, `layer`, `text`, `text_secondary`, `accent`, `accent_text`, `stroke`,
`selection`, `focus`, `warning`, `error`. Classic maps each token to a `COLOR_*` system color. Fluent light/dark use
the Windows 11 neutral ramps (light surface ~#F3F3F3 with white layer; dark surface ~#202020 with #2B2B2B layer) and
the user's accent from `DwmGetColorizationColor`, adjusted in the model until it meets the contrast floor of §6.4.
The model computes WCAG contrast ratios, so the unit tests can assert them for every accent the tests feed it.

### 5.2 Typography

| Role | Classic | Aero | Fluent |
|---|---|---|---|
| Body | message font | message font | message font (Segoe UI) |
| Window header / page title | message font bold | `TEXT_MAININSTRUCTION` (theme font and color) | Segoe UI Variable Display semibold, 20 px at 96 DPI, else Segoe UI Semibold |
| Section header | message font bold | theme `TEXT_INSTRUCTION` **[verify part id]** | Segoe UI Variable Text semibold, 14 px |
| Secondary text | message font, `COLOR_GRAYTEXT` | same | body size, `text_secondary` |

Every font is created per DPI by the theme and freed on DPI or setting change; the layout pass measures with the
same fonts, so longer German and French strings keep fitting.

### 5.3 User setting and policy

`[ui] style = auto | classic` in the user settings (03 §3), shown in Settings as "Appearance": "Match Windows
(recommended)" / "Classic". A Group Policy value `UiStyle` (03 §3.5) can force `classic` for locked-down or
remote-desktop fleets. Changing it re-selects the tier live (§4) without a restart.

## 6. Screens per tier

### 6.1 Main window

| | Classic (XP) | Aero (Vista/7) | Fluent (10/11) |
|---|---|---|---|
| Frame | standard | glass band across the top (title + command bar) when composed | 2a: light; 2b: dark title bar, rounded by Windows; 2c: Mica band |
| Commands | menu bar + text toolbar (today) | menu bar + toolbar on the glass band with glow text | command bar (toolbar with text, icons from the existing image list) + "More" overflow button holding the menu bar's items; Alt still opens the overflow menu |
| List | ListView with groups | same, Explorer theme (`SetWindowTheme(L"Explorer")`, documented) for the hover/selection look | opaque layer card, our row selection and group header drawing; dark on 2b/2c |
| Status | status bar | status bar | status text strip (owner-drawn STATIC) with the Start link as a real button |
| Empty state | text in the list | same | centered "No connections yet" with a "New connection" button **(new strings)** |

The "More" overflow keeps every menu command reachable with the keyboard (03 §11) and keeps the accelerators.

### 6.2 Prompts (host key, legacy algorithm, token-only WebDAV, credentials)

- Trust decisions keep **no default button** (TM-R03). `TaskDialogIndirect` always has a default button (the first
  one when `nDefaultButton` matches none), so trust prompts are **not** task dialogs. They stay our generated dialogs
  and gain, per tier: the main-instruction font (Aero, Fluent), a shield or warning icon from `LoadIconMetric`
  (Vista+), command links for the choices (`BS_COMMANDLINK` with `BCM_SETNOTE` notes, Vista+; plain buttons on XP),
  and the dark palette on 2b/2c (all their controls are in the dark-capable set of §3.5).
- Non-trust messages (errors with a code, "delete this connection?", agent start failed) use `TaskDialogIndirect`
  on Vista+ with the error code in the expandable details, and `MessageBoxW` on XP. One helper,
  `ui_win_task(owner, main, content, details, buttons)`, hides the split.

### 6.3 Tray

- Icon: unchanged (light/dark variants already follow `SystemUsesLightTheme`).
- Menu: standard popup menu on every tier (it stays light on Windows 11 dark; see option B).
- Optional, later: a Windows 11 flyout (a small popup window with Acrylic, rounded small corners, one row per
  profile with a mount toggle, "Open ShellDrive", "Settings") opened by left click on 2c; the popup menu stays on
  right click / Apps key. Not in the first slice.

### 6.4 Profile editor, Settings, host key manager, Logs, Events, About

- Classic: as today. Aero: theme header fonts; the profile editor stays a property sheet. Fluent: header fonts,
  spacing tokens, light body with dark title bar on 2b/2c (tabs, combos and spin boxes cannot be dark, §3.5).
- Later and separately decided: a Fluent profile editor with a left navigation list (ListBox styled as a nav pane)
  instead of tabs. Not proposed for 1.0.

### 6.5 First-run wizard

`PSH_WIZARD97` on XP, `PSH_AEROWIZARD` on Vista+ (documented flag, comctl32 v6), which gives the Aero wizard frame on
7 and the flat wizard look on 10/11 with the same pages. Page headers move to the page title fields the Aero wizard
uses; the strings already exist.

## 7. Accessibility and localization

### 7.1 Accessibility (amends 03 §11)

- 03 §11 "no custom-drawn controls in v1" becomes "no custom controls": standard controls may be **custom drawn or
  owner drawn**, because the control, its window text and its MSAA/UIA proxy stay the system's. No new window class
  paints text that a screen reader cannot get; the status strip and empty state are STATIC/BUTTON windows.
- Focus: every custom-drawn control draws a visible focus ring (2 px `focus` token) and honors
  `WM_UPDATEUISTATE` / `UISF_HIDEFOCUS`; tab order still comes from the layout tables.
- Contrast: body text ≥ 4.5:1 and UI boundaries (focus ring, selection, borders) ≥ 3:1 against their surface, checked
  by the unit tests for light, dark and a set of accent colors (§5.1). Status is never color only (03 §11 stands).
- High Contrast: forces Classic, so every color comes from `GetSysColor` and no backdrop or glass is drawn.
- `SPI_GETCLIENTAREAANIMATION` off: no hover fades (we draw none in the first slice anyway).
- The UIA tree of each screen is checked with Inspect / Accessibility Insights on 11 and Narrator on 10 and 11, and
  with MSAA (Inspect32) on XP, for names, roles and focus order.

### 7.2 Localization (03 §9)

- No layout-sensitive change: all text still goes through the measuring layout pass; command links are measured with
  `BCM_GETIDEALSIZE`. The six locales are all Latin script, and Segoe UI (Variable) covers them.
- New strings, each in en, es (voseo), fr ("vous"), pt-BR, it, de before it is done: Appearance setting (label and two
  choices), "More" overflow button and its tooltip, empty-state text and button, command-link notes for the trust
  prompts (one per choice), task-dialog main instructions where today's message is a single sentence (split into
  instruction and content). The first slice (§9) needs only the Appearance strings and "More".
- Plural forms are unaffected; no string is concatenated with tier-specific text.

## 8. Tests and lab plan

### 8.1 Automated (local gate and CI)

- `tests/ui`: `test_theme.c` drives `ui_theme_select` across a table of (OS, build, HC, composition, theme, setting)
  rows, and the palette contrast checks of §7.1. `test_dark.c` folds into it.
- `--test-window` reports the selected tier and level and checks that the main window created the controls of that
  tier; a new `--theme=classic|aero|fluent-a|fluent-b|fluent-c` override (test modes only) forces a tier, so the
  smoke runs on the host exercise every tier's code path without the matching OS.
- `importcheck` on every flavour stays the guard: no `dwmapi.dll` import anywhere, no post-XP `uxtheme` or comctl32
  export on the XP flavours.
- `x64-analysis` (PREfast) covers the new paint code.

### 8.2 Lab (Hyper-V VMs under `D:\sdlab`, 04 §11.4)

| Target | Tier shown | Available now | Notes |
|---|---|---|---|
| `sd-xp-sp3-x86` | Classic | no — needs the maintainer's product-key install | Luna and Windows Classic theme; 120 DPI run |
| `sd-win7-sp1-x86`, `sd-win7-sp1-x64` | Aero, composition **off** | yes | Hyper-V's synthetic video has no WDDM driver, so Aero glass does not compose in the VM **[verify]**: this checks the fallback; glass itself needs an RDP 7 session with desktop composition or real hardware |
| `sd-win10-ltsc21-x64` (19044) | Fluent 2a | yes | light; dark only to confirm 2a ignores it |
| `sd-win11-23h2-x64` | Fluent 2b/2c | no — the VM has no OS (host DVD defect) | |
| Development host (Windows 11 26100) | Fluent 2c | yes | Mica, dark, light, accent colors, 100/150/200 % |

Screenshots: the lab guest runs the harness as SYSTEM, which has no interactive desktop, so screenshots need an
autologon user and a scheduled task in that session that starts `shelldrive-ui.exe --theme-shot <file>` (a test mode
that opens the main window with fixture profiles and captures it with `PrintWindow`; `PrintWindow` does not capture
the Mica backdrop, so the 2c shots come from a host-side capture of the desktop). The WMI thumbnail the lab already
uses (`GetVirtualSystemThumbnailImage`) is a low-resolution backup.

### 8.3 Spikes before the first slice is merged

- **S1** Custom-drawn toolbar inside the extended frame with correct alpha (buffered paint), on 7 (glass) and
  11 (Mica). Fallback: band without child controls; the command bar sits on the opaque layer.
- **S2** Dark check boxes and radio buttons with v6 `NM_CUSTOMDRAW`: whether the glyph can stay theme-drawn while the
  text and background are ours **[verify]**.
- **S3** `WM_DWMCOMPOSITIONCHANGED` and theme switches at run time on 7 and 11 without leaking fonts or brushes
  (GDI object count before and after 50 switches).

## 9. First vertical slice (proposed)

Main window and theme plumbing only:

1. `ui_theme_model.c` (pure, tested) and `ui_theme.c`; `ui_dark.c` folded in; the settings key and policy of §5.3
   with the Appearance control in Settings and its strings in all six languages.
2. Main window on Fluent 2b/2c: Mica band (or the S1 fallback), dark and light palettes, command bar with the "More"
   overflow replacing the menu bar, custom-drawn ListView rows and headers, status strip, Segoe UI Variable headers.
3. Fluent 2a (10) light variant of the same window; Aero (7) theme fonts and glass band with the composition-off
   fallback; Classic (XP) unchanged except spacing tokens.
4. Tests of §8.1, gate `tools/ci-local.ps1` green, screenshots: host (11: light, dark, Mica on/off), Win10 VM,
   Win7 VM (composition off), XP when the VM exists.

The tray, prompts, task dialogs, the Aero wizard and the other windows follow in later slices in the order §6 lists
them.

## 10. Options for the user

| Option | What | Cost | Risk |
|---|---|---|---|
| **A (recommended)** | Run-time tiers in one binary per flavour, documented APIs only: Classic / Aero / Fluent 2a–2c as above. Dark client areas only on 11 and only where documented techniques reach (main window, prompts). | medium; one theme module, custom draw in the main window, then screen by screen | popup menus, scroll bars and tabbed dialogs stay light on 11 dark |
| B | A plus the undocumented dark-mode helpers on 10 1809+ (`uxtheme` ordinals 135 `SetPreferredAppMode`, 133 `AllowDarkModeForWindow`, theme classes `DarkMode_Explorer` / `DarkMode_CFD`) behind a build allow-list, for dark menus, scroll bars, combos and tabs; dark title bar on 10 20H1+ via attribute 20 | A + small; most of the dark gaps close | reverses 03 §7.4; ordinals may change in any Windows update; needs a kill switch and a lab run per Windows release |
| C | Minimal: only what needs no custom drawing — task dialogs, command links, Aero wizard, theme fonts, Mica title bar (`DWMSBT_MAINWINDOW` without frame extension), corner preference | small | the client area still looks like today on 10/11; no dark body |
| D | Separate modern UI (WinUI 3 or Direct2D) for x64-modern/arm64 only | large; two UIs | rejected in §3.4 |

Decisions asked: the option (A, B or C); whether the first slice is §9 as written; whether Win10 should get the dark
palette with the undocumented title-bar attribute (only meaningful with B).

## 11. Risks

- **Custom draw scope creep.** Each custom-drawn control is code that must handle DPI, focus, disabled state and
  theme changes. Mitigation: only the main window and the prompts are custom drawn in A; everything else keeps the
  system look with theme fonts.
- **Visual mismatch.** A Fluent main window next to a classic property sheet. Accepted for 1.0; the dark title bar
  and shared fonts keep them related.
- **Verification gaps.** No Win11 VM and no working Aero glass in Hyper-V (§8.2). Mitigation: the host covers 2c,
  forced-tier smoke tests cover the code paths, and the gaps are listed in `docs/dev/lab-results.md`.
- **Behavior differences between Windows 11 builds** for backdrops and borders. Mitigation: everything is a DWM
  attribute that fails harmlessly; the model gates by documented build floors.
- **Remote Desktop.** DWM drops the backdrop over RDP; glass is off on 7 RDP unless composition is enabled. The
  solid fallback must be tested (§8.2).
- **Undocumented APIs** (option B only): see §10.

## 12. Platform facts used (sources)

| Fact | Source |
|---|---|
| `DWMWA_USE_IMMERSIVE_DARK_MODE` (20) and `DWMWA_WINDOW_CORNER_PREFERENCE` (33), `DWMWA_BORDER_COLOR` (34) from 22000; `DWMWA_SYSTEMBACKDROP_TYPE` (38) from 22621 | [DWMWINDOWATTRIBUTE](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute), [DWM_SYSTEMBACKDROP_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwm_systembackdrop_type) |
| Mica in Win32 apps, fallback when transparency is off | [Apply Mica in Win32 desktop apps](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/ui/apply-mica-win32) |
| `DwmExtendFrameIntoClientArea`, `DwmIsCompositionEnabled` (Vista+; composition always on from 8) | [DwmExtendFrameIntoClientArea](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/nf-dwmapi-dwmextendframeintoclientarea), [DwmIsCompositionEnabled](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/nf-dwmapi-dwmiscompositionenabled) |
| Custom frames and text on glass (`DrawThemeTextEx`, buffered paint) | [Custom Window Frame Using DWM](https://learn.microsoft.com/en-us/windows/win32/dwm/customframe) |
| `TaskDialogIndirect`: Vista, comctl32 v6; `nDefaultButton` falls back to the first button | [TASKDIALOGCONFIG](https://learn.microsoft.com/en-us/windows/win32/api/commctrl/ns-commctrl-taskdialogconfig) |
| Command links (`BS_COMMANDLINK`, `BCM_SETNOTE`), Vista+ | [Button styles](https://learn.microsoft.com/en-us/windows/win32/controls/button-styles) |
| `PSH_AEROWIZARD`, Vista+ | [PROPSHEETHEADER](https://learn.microsoft.com/en-us/windows/win32/api/prsht/ns-prsht-propsheetheadera_v2) |
| Windows App SDK / WinUI 3 floor and deployment | [Windows App SDK system requirements](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/system-requirements) |
| Custom draw of common controls | [About Custom Draw](https://learn.microsoft.com/en-us/windows/win32/controls/about-custom-draw) |
