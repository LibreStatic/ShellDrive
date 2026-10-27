/* shelldrive-ui: the Settings window (03 §3.2, §7.5, §9.3, §2.4 decision 9 and 10).
 *
 * The window edits the settings the UI shows (ui_settings_model.c) and saves them with sd_settings_save, which
 * keeps every other key of settings.ini. Start at sign-in is the per-user Run key of the tray (HKCU only). After a
 * save the agent is asked to reload the file (config.reload) when it supports it. The language is read at start-up,
 * so a language change is reported as needing a restart. The update group stays disabled until the agent reports
 * the update.check feature (decision 10). */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_settings_model.h"
#include "ui_update.h"
#include "ui_win.h"

#define ST_ID_LANG       4401
#define ST_ID_NOTIFY     4402
#define ST_ID_LOGON      4403
#define ST_ID_BACKEND    4404
#define ST_ID_CACHE      4405
#define ST_ID_UPDATES    4406
#define ST_ID_SAVE       4407
#define ST_ID_CANCEL     4408
#define ST_ID_STATUS     4409
#define ST_ID_LBL_LANG   4410
#define ST_ID_LBL_BACK   4411
#define ST_ID_LBL_CACHE  4412
#define ST_ID_HINT_CACHE 4413
#define ST_ID_NOTE_UPD   4414
#define ST_ID_NOTE_REST  4415
#define ST_ID_GROUP_UPD  4416
#define ST_ID_CHANNEL    4417
#define ST_ID_LBL_CHANNEL 4418
#define ST_ID_NOTE_POLICY 4419
#define ST_ID_UPD_CHECK  4420
#define ST_ID_UPD_INSTALL 4421
#define ST_ID_UPD_NOTES 4422
#define ST_ID_UPD_STATUS 4423
#define ST_ID_UPD_STALE  4424
#define ST_CLIENT_W      640
#define ST_CLIENT_H      600

#define ST_RUN_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define ST_RUN_VALUE L"ShellDriveTray"

/* Endonyms of the languages in the combo box: names are shown in their own language, as the language list of
   the installer does (not translated). */
static const wchar_t *const k_lang_names[UI_SET_LANG_COUNT] = {
  NULL, L"English", L"Espa\x00f1ol", L"Fran\x00e7" L"ais", L"Portugu\x00ea" L"s (Brasil)", L"Italiano", L"Deutsch"
};

static struct {
  HWND wnd, lang, notify, logon, backend, cache, status;
  HWND lbl_lang, lbl_back, lbl_cache, hint_cache, note_upd, note_rest, grp_upd, btn_save, btn_cancel;
  HWND channel, lbl_channel, note_policy, upd_status, upd_stale, btn_check, btn_install, btn_notes;
  HFONT font;
  unsigned dpi;
  ui_settings_model model;            /* as loaded */
  sd_settings loaded;                 /* the full file contents, merged on save */
  int logon_before;                   /* the Run key as read when the window opened */
} g_st;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_st.dpi);
}

static void status_msg(sd_msg_id id)
{
  if (g_st.status)
    SetWindowTextW(g_st.status, sd_l10n_get(id));
}

/* ---- the Run key (per-user, HKCU only) ---- */

static int run_key_on(void)
{
  HKEY k;
  DWORD type = 0, size = 0;
  int on = 0;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, ST_RUN_KEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    return 0;
  on = RegQueryValueExW(k, ST_RUN_VALUE, NULL, &type, NULL, &size) == ERROR_SUCCESS;
  RegCloseKey(k);
  return on;
}

static sd_err run_key_set(int on)
{
  HKEY k = NULL;
  LONG r;
  if (on) {
    wchar_t exe[MAX_PATH * 2], cmd[MAX_PATH * 2 + 32];
    if (GetModuleFileNameW(NULL, exe, SD_COUNTOF(exe)) == 0)
      return SD_E_FAILURE;
    if (ui_settings_run_command(exe, cmd, SD_COUNTOF(cmd)) != SD_OK)
      return SD_E_INVALID_PARAM;
    r = RegCreateKeyExW(HKEY_CURRENT_USER, ST_RUN_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (r == ERROR_SUCCESS) {
      r = RegSetValueExW(k, ST_RUN_VALUE, 0, REG_SZ, (const BYTE *)cmd,
                         (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
      RegCloseKey(k);
    }
  } else {
    r = RegOpenKeyExW(HKEY_CURRENT_USER, ST_RUN_KEY, 0, KEY_SET_VALUE, &k);
    if (r == ERROR_SUCCESS) {
      r = RegDeleteValueW(k, ST_RUN_VALUE);
      RegCloseKey(k);
    }
    if (r == ERROR_FILE_NOT_FOUND)
      r = ERROR_SUCCESS;
  }
  return r == ERROR_SUCCESS ? SD_OK : SD_E_FAILURE;
}

/* ---- controls ---- */

static void populate(void)
{
  int i;
  SendMessageW(g_st.lang, CB_RESETCONTENT, 0, 0);
  SendMessageW(g_st.lang, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_LANG_SYSTEM));
  for (i = 1; i < UI_SET_LANG_COUNT; i++)
    SendMessageW(g_st.lang, CB_ADDSTRING, 0, (LPARAM)k_lang_names[i]);
  SendMessageW(g_st.lang, CB_SETCURSEL, ui_settings_lang_index(g_st.model.language), 0);

  SendMessageW(g_st.notify, BM_SETCHECK, g_st.model.notify ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(g_st.logon, BM_SETCHECK, g_st.model.start_at_logon ? BST_CHECKED : BST_UNCHECKED, 0);

  SendMessageW(g_st.backend, CB_RESETCONTENT, 0, 0);
  SendMessageW(g_st.backend, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_BACKEND_AUTO));
  SendMessageW(g_st.backend, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_BACKEND_DOKANY));
  SendMessageW(g_st.backend, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_BACKEND_WEBDAV));
  SendMessageW(g_st.backend, CB_SETCURSEL,
               (g_st.model.default_backend >= 0 && g_st.model.default_backend <= 2) ? g_st.model.default_backend : 0,
               0);
  {
    wchar_t v[16];
    swprintf_s(v, SD_COUNTOF(v), L"%u", g_st.model.cache_mb);
    SetWindowTextW(g_st.cache, v);
  }
  /* the update group: channel list (a policy may fix it), status and buttons (decision 10, 04 §9.7) */
  SendMessageW(g_st.channel, CB_RESETCONTENT, 0, 0);
  SendMessageW(g_st.channel, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_CHANNEL_STABLE));
  SendMessageW(g_st.channel, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_CHANNEL_BETA));
  {
    char ch[UI_UPD_CHANNEL_MAX];
    ui_update_channel_now(g_st.loaded.update_channel, ch, sizeof(ch));
    SendMessageW(g_st.channel, CB_SETCURSEL, strcmp(ch, "beta") == 0 ? 1 : 0, 0);
  }
  ui_settings_update_refresh();
}

static void load(void)
{
  sd_settings s;
  sd_settings_defaults(&s);
  if (sd_settings_load(&s) != SD_OK)
    SD_LOGW("ui", "settings.ini has invalid values; the valid ones are shown");
  g_st.loaded = s;
  ui_settings_from_sd(&s, &g_st.model);
  g_st.model.start_at_logon = run_key_on() ? 1 : 0;
  g_st.logon_before = g_st.model.start_at_logon;
  populate();
}

static void on_save(void)
{
  ui_settings_model m;
  sd_settings s;
  wchar_t cache[32];
  unsigned mb = 0;
  sd_err e;
  int lang_changed;
  int lang_index;

  GetWindowTextW(g_st.cache, cache, SD_COUNTOF(cache));
  if (ui_settings_parse_cache(cache, &mb) != SD_OK) {
    status_msg(SD_MSG_UI_SETTINGS_CACHE_INVALID);
    SetFocus(g_st.cache);
    return;
  }
  lang_index = (int)SendMessageW(g_st.lang, CB_GETCURSEL, 0, 0);
  if (lang_index < 0 || lang_index >= UI_SET_LANG_COUNT)
    lang_index = 0;
  memset(&m, 0, sizeof(m));
  strcpy_s(m.language, sizeof(m.language), g_ui_set_lang_codes[lang_index]);
  m.notify = SendMessageW(g_st.notify, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.start_at_logon = SendMessageW(g_st.logon, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.default_backend = (int)SendMessageW(g_st.backend, CB_GETCURSEL, 0, 0);
  if (m.default_backend < 0 || m.default_backend > 2)
    m.default_backend = 0;
  m.cache_mb = mb;

  s = g_st.loaded;
  ui_settings_to_sd(&m, &s);
  /* the channel is saved unless a policy sets it (the list is then disabled, 03 §3.5) */
  {
    ui_upd_policy pol;
    int ci = (int)SendMessageW(g_st.channel, CB_GETCURSEL, 0, 0);
    ui_update_policy_now(&pol);
    if (!pol.channel_set)
      strcpy_s(s.update_channel, sizeof(s.update_channel), ci == 1 ? "beta" : "stable");
  }
  e = sd_settings_save(&s);
  if (e != SD_OK) {
    ui_win_error(g_st.wnd, SD_MSG_UI_SETTINGS_SAVE_FAILED, e);
    return;
  }
  g_app.notify_on = s.notify ? 1 : 0;
  if (m.start_at_logon != g_st.logon_before) {
    e = run_key_set(m.start_at_logon);
    if (e != SD_OK) {
      status_msg(SD_MSG_UI_SETTINGS_RUN_FAILED);
      return;
    }
  }
  /* the agent applies the file to new mounts and connections (config.reload, 2.4) */
  if (g_app.agent_up && (g_app.agent_features & UI_FEAT_RELOAD))
    (void)ui_ipc_call(UI_IPC_RELOAD, "config.reload", NULL);

  lang_changed = strcmp(m.language, g_st.model.language) != 0;
  g_st.model = m;
  g_st.loaded = s;
  if (lang_changed)
    ui_win_message(g_st.wnd, sd_l10n_get(SD_MSG_UI_SETTINGS_RESTART_NOTE), MB_OK | MB_ICONINFORMATION);
  DestroyWindow(g_st.wnd);
}

/* The update group: channel list, status line, buttons and the policy notes (04 §9.7). Called after every change
   of the updater model (replies, events, agent state). */
void ui_settings_update_refresh(void)
{
  ui_upd_view v;
  ui_upd_policy pol;
  wchar_t text[512];
  int agent_ok, can_apply;

  if (g_st.wnd == NULL || !IsWindow(g_st.wnd) || g_st.channel == NULL)
    return;
  agent_ok = (g_app.agent_up && (g_app.agent_features & UI_FEAT_UPDATE)) ? 1 : 0;
  can_apply = (g_app.agent_up && (g_app.agent_features & UI_FEAT_UPDATE_APPLY)) ? 1 : 0;
  ui_update_view_now(agent_ok, can_apply, &v);
  ui_update_policy_now(&pol);
  EnableWindow(g_st.channel, v.channel_enabled ? TRUE : FALSE);
  EnableWindow(g_st.btn_check, v.check_enabled ? TRUE : FALSE);
  EnableWindow(g_st.btn_install, v.install_enabled ? TRUE : FALSE);
  EnableWindow(g_st.btn_notes, v.notes_enabled ? TRUE : FALSE);
  SetWindowTextW(g_st.note_policy,
                 (v.channel_managed || v.check_managed) ? sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_MANAGED) : L"");
  SetWindowTextW(g_st.note_upd,
                 (g_app.agent_up && !agent_ok) ? sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATES_UNAVAILABLE) : L"");
  ui_update_status_text(text, SD_COUNTOF(text));
  SetWindowTextW(g_st.upd_status, text);
  ui_update_stale_text(text, SD_COUNTOF(text));
  SetWindowTextW(g_st.upd_stale, text);
}

/* --test-windows: every control of the update group was created. */
int ui_settings_update_controls_ok(void)
{
  return g_st.channel && g_st.note_policy && g_st.upd_status && g_st.upd_stale && g_st.btn_check &&
         g_st.btn_install && g_st.btn_notes && g_st.note_upd;
}

void ui_settings_on_reply(int kind, sd_err err, const sd_json *result)
{
  (void)kind;
  (void)result;
  if (err != SD_OK)
    SD_LOGW("ui", "config.reload not applied (%s)", sd_err_name(err));
}

/* ---- layout ---- */

static void place(HWND c, int x, int y, int w, int h)
{
  if (c)
    MoveWindow(c, x, y, w > 0 ? w : 0, h > 0 ? h : 0, TRUE);
}

static void layout(HWND hwnd)
{
  RECT rc;
  int m, rh, gap, W, H, y, lw, cw, x, bw1, bw2, by, sh, note_h, bw, xp;
  int lw_a, lw_b, lw_c;
  if (!g_st.lang)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(10);
  rh = dpx(24);
  gap = dpx(8);
  sh = dpx(20);
  note_h = dpx(36);

  lw_a = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_LANGUAGE));
  lw_b = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_BACKEND));
  lw_c = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_CACHE));
  lw = lw_a;
  if (lw_b > lw) lw = lw_b;
  if (lw_c > lw) lw = lw_c;
  lw += dpx(12);
  cw = dpx(260);

  y = m;
  place(g_st.lbl_lang, m, y + dpx(4), lw, rh);
  place(g_st.lang, m + lw, y, cw, dpx(200));
  y += rh + gap;
  place(g_st.notify, m, y, W - 2 * m, rh);
  y += rh + gap / 2;
  place(g_st.logon, m, y, W - 2 * m, rh);
  y += rh + gap;
  place(g_st.lbl_back, m, y + dpx(4), lw, rh);
  place(g_st.backend, m + lw, y, cw, dpx(200));
  y += rh + gap;
  place(g_st.lbl_cache, m, y + dpx(4), lw, rh);
  place(g_st.cache, m + lw, y, dpx(100), rh);
  x = m + lw + dpx(100) + gap;
  place(g_st.hint_cache, x, y + dpx(4), W - x - m, rh);
  y += rh + gap * 2;
  place(g_st.grp_upd, m, y, W - 2 * m, rh);
  y += rh + gap / 2;
  place(g_st.lbl_channel, m, y + dpx(4), lw, rh);
  place(g_st.channel, m + lw, y, cw, dpx(200));
  xp = m + lw + cw + gap;
  place(g_st.note_policy, xp, y + dpx(4), W - xp - m, rh);
  y += rh + gap / 2;
  place(g_st.upd_status, m, y, W - 2 * m, note_h);
  y += note_h;
  place(g_st.upd_stale, m, y, W - 2 * m, rh);
  y += rh + gap / 2;
  bw = dpx(140);
  place(g_st.btn_check, m, y, bw, dpx(26));
  place(g_st.btn_install, m + bw + gap, y, bw + dpx(40), dpx(26));
  place(g_st.btn_notes, m + bw + gap + bw + dpx(40) + gap, y, bw + dpx(20), dpx(26));
  y += dpx(26) + gap / 2;
  place(g_st.note_upd, m, y, W - 2 * m, note_h);
  y += note_h + gap;
  place(g_st.note_rest, m, y, W - 2 * m, note_h);

  by = H - m - sh - gap - dpx(26);
  place(g_st.status, m, H - m - sh, W - 2 * m, sh);
  bw1 = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_BTN_SAVE)) + dpx(32);
  bw2 = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_BTN_CANCEL)) + dpx(32);
  if (bw1 < dpx(96)) bw1 = dpx(96);
  if (bw2 < dpx(96)) bw2 = dpx(96);
  place(g_st.btn_cancel, W - m - bw2, by, bw2, dpx(26));
  place(g_st.btn_save, W - m - bw2 - gap - bw1, by, bw1, dpx(26));
}

static void on_command(WORD id, WORD code)
{
  if (id == ST_ID_SAVE && code == BN_CLICKED)
    on_save();
  else if (id == ST_ID_CANCEL && code == BN_CLICKED)
    DestroyWindow(g_st.wnd);
  else if (id == ST_ID_UPD_CHECK && code == BN_CLICKED)
    ui_update_check();
  else if (id == ST_ID_UPD_INSTALL && code == BN_CLICKED)
    ui_update_install(g_st.wnd);
  else if (id == ST_ID_UPD_NOTES && code == BN_CLICKED)
    ui_update_open_notes(g_st.wnd);
}

static HWND make_child(const wchar_t *cls, const wchar_t *text, DWORD style, int id, HWND parent)
{
  return CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, parent,
                         (HMENU)(UINT_PTR)id, g_app.inst, NULL);
}

static void create_children(HWND hwnd)
{
  g_st.lbl_lang = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_LANGUAGE), SS_LEFT | SS_NOPREFIX,
                             ST_ID_LBL_LANG, hwnd);
  g_st.lang = make_child(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, ST_ID_LANG, hwnd);
  g_st.notify = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_NOTIFY), WS_TABSTOP | BS_AUTOCHECKBOX,
                           ST_ID_NOTIFY, hwnd);
  g_st.logon = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_LOGON), WS_TABSTOP | BS_AUTOCHECKBOX,
                          ST_ID_LOGON, hwnd);
  g_st.lbl_back = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_BACKEND), SS_LEFT | SS_NOPREFIX,
                             ST_ID_LBL_BACK, hwnd);
  g_st.backend = make_child(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, ST_ID_BACKEND, hwnd);
  g_st.lbl_cache = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_CACHE), SS_LEFT | SS_NOPREFIX,
                              ST_ID_LBL_CACHE, hwnd);
  g_st.cache = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, 0, 0, 10, 10,
                               hwnd, (HMENU)(UINT_PTR)ST_ID_CACHE, g_app.inst, NULL);
  g_st.hint_cache = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_CACHE_HINT), SS_LEFT | SS_NOPREFIX,
                               ST_ID_HINT_CACHE, hwnd);
  g_st.grp_upd = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_GROUP_UPDATES), SS_LEFT | SS_NOPREFIX,
                            ST_ID_GROUP_UPD, hwnd);
  g_st.lbl_channel = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_CHANNEL), SS_LEFT | SS_NOPREFIX,
                                ST_ID_LBL_CHANNEL, hwnd);
  g_st.channel = make_child(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, ST_ID_CHANNEL, hwnd);
  g_st.note_policy = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_POLICY, hwnd);
  g_st.upd_status = make_child(L"STATIC", L"", SS_LEFT, ST_ID_UPD_STATUS, hwnd);
  g_st.upd_stale = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_UPD_STALE, hwnd);
  g_st.btn_check = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_CHECK_NOW),
                              WS_TABSTOP | BS_PUSHBUTTON, ST_ID_UPD_CHECK, hwnd);
  g_st.btn_install = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_INSTALL),
                                WS_TABSTOP | BS_PUSHBUTTON, ST_ID_UPD_INSTALL, hwnd);
  g_st.btn_notes = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_NOTES),
                              WS_TABSTOP | BS_PUSHBUTTON, ST_ID_UPD_NOTES, hwnd);
  g_st.note_upd = make_child(L"STATIC", L"", SS_LEFT, ST_ID_NOTE_UPD, hwnd);
  g_st.note_rest = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_LIVE_NOTE), SS_LEFT,
                              ST_ID_NOTE_REST, hwnd);
  g_st.status = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_STATUS, hwnd);
  g_st.btn_save = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_BTN_SAVE),
                             WS_TABSTOP | BS_DEFPUSHBUTTON, ST_ID_SAVE, hwnd);
  g_st.btn_cancel = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_BTN_CANCEL), WS_TABSTOP | BS_PUSHBUTTON,
                               ST_ID_CANCEL, hwnd);
  SendMessageW(g_st.cache, EM_SETLIMITTEXT, 8, 0);
  ui_win_apply_font(hwnd, g_st.font);
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_st.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_st.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_st.font = ui_win_font(dpi);
  ui_win_apply_font(hwnd, g_st.font);
  if (old)
    DeleteObject(old);
  layout(hwnd);
}

static LRESULT CALLBACK st_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_st.wnd = hwnd;
    g_st.dpi = ui_dpi_window(hwnd);
    g_st.font = ui_win_font(g_st.dpi);
    create_children(hwnd);
    layout(hwnd);
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp), HIWORD(wp));
    return 0;
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    if (g_st.font)
      DeleteObject(g_st.font);
    memset(&g_st, 0, sizeof(g_st));
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static HWND create_window(int visible)
{
  wchar_t cls[320];
  HWND w;
  ui_win_class_name(L"settings", cls);
  if (!ui_win_register(g_app.inst, cls, st_proc))
    return NULL;
  if (g_st.wnd != NULL && IsWindow(g_st.wnd))
    return g_st.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_SETTINGS_TITLE), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, ST_CLIENT_W, ST_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(ST_CLIENT_W, ui_dpi_window(w)),
               ui_dpi_scale(ST_CLIENT_H, ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(w, SW_SHOW);
  return w;
}

void ui_settings_open(void)
{
  HWND w;
  if (g_st.wnd != NULL && IsWindow(g_st.wnd)) {
    ShowWindow(g_st.wnd, IsIconic(g_st.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_st.wnd);
    return;
  }
  w = create_window(1);
  if (w != NULL)
    load();
}

void ui_settings_close(void)
{
  if (g_st.wnd != NULL && IsWindow(g_st.wnd))
    DestroyWindow(g_st.wnd);
}

HWND ui_settings_create_hidden(void)
{
  return create_window(0);
}
