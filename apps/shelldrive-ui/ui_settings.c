/* shelldrive-ui: the Settings window (03 §3.2, §7.5, §9.3, §2.4 decision 9 and 10).
 *
 * The window edits the settings the UI shows (ui_settings_model.c) and saves them with sd_settings_save, which
 * keeps every other key of settings.ini. Start at sign-in is the per-user Run key of the tray (HKCU only). After a
 * save the agent is asked to reload the file (config.reload) when it supports it. The language is read at start-up,
 * so a language change is reported as needing a restart. The update group stays disabled until the agent reports
 * the update.check feature (decision 10). */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_policy/sd_policy.h"
#include "sd_ssh/sd_known_hosts.h"
#include "sd_webdav/sd_webdav.h"
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
#define ST_ID_TAB        4425
#define ST_ID_CHK_OPENSSH 4426
#define ST_ID_CHK_PUTTY  4427
#define ST_ID_NOTE_OPENSSH 4428
#define ST_ID_NOTE_PUTTY 4429
#define ST_ID_CHK_ROAM   4430
#define ST_ID_HINT_ROAM  4431
#define ST_ID_LBL_WC     4433
#define ST_ID_VAL_WC     4434
#define ST_ID_NOTE_LANG  4435
#define ST_ID_AGENT_LOGON 4436
#define ST_ID_LBL_WRITE  4437
#define ST_ID_WRITE      4438
#define ST_ID_NOTE_WRITE 4439
#define ST_ID_CHK_PRIVACY 4440
#define ST_ID_NOTE_PRIVACY 4441
#define ST_ID_HINT_KINDS 4442
#define ST_ID_KIND_BASE  4450       /* + sd_notify_kind */
#define ST_CLIENT_H      800

#define ST_RUN_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define ST_RUN_VALUE L"ShellDriveTray"

/* Endonyms of the languages in the combo box: names are shown in their own language, as the language list of
   the installer does (not translated). */
static const wchar_t *const k_lang_names[UI_SET_LANG_COUNT] = {
  NULL, L"English", L"Espa\x00f1ol", L"Fran\x00e7" L"ais", L"Portugu\x00ea" L"s (Brasil)", L"Italiano", L"Deutsch"
};

/* Label of each notification kind switch, in sd_notify_kind order (03 7.7). */
static const sd_msg_id k_kind_label[SD_NOTIFY_COUNT] = {
  SD_MSG_UI_SETTINGS_NK_CONNECTION_LOST, SD_MSG_UI_SETTINGS_NK_RECONNECTED, SD_MSG_UI_SETTINGS_NK_MOUNT_FAILED,
  SD_MSG_UI_SETTINGS_NK_MOUNTED, SD_MSG_UI_SETTINGS_NK_LEGACY_ALGORITHMS, SD_MSG_UI_SETTINGS_NK_HOSTKEYS_OFFERED,
  SD_MSG_UI_SETTINGS_NK_HOSTKEYS_SAVED, SD_MSG_UI_SETTINGS_NK_PROXY_PASSWORD, SD_MSG_UI_SETTINGS_NK_POOL_LIMITED,
  SD_MSG_UI_SETTINGS_NK_SERVICE_ATTENTION, SD_MSG_UI_SETTINGS_NK_UPDATE_AVAILABLE, SD_MSG_UI_SETTINGS_NK_UPDATE_STALE,
  SD_MSG_UI_SETTINGS_NK_TERRAPIN, SD_MSG_UI_SETTINGS_NK_HOSTKEYS_SOURCE, SD_MSG_UI_SETTINGS_NK_DISK_CACHE
};

static struct {
  HWND wnd, lang, notify, logon, backend, cache, status;
  HWND lbl_lang, lbl_back, lbl_cache, hint_cache, note_upd, note_rest, grp_upd, btn_save, btn_cancel;
  HWND channel, lbl_channel, note_policy, upd_status, upd_stale, btn_check, btn_install, btn_notes;
  HWND tab, chk_openssh, chk_putty, note_openssh, note_putty, chk_roam, hint_roam, lbl_wc, val_wc;
  HWND note_lang;
  HWND agent_logon, lbl_write, write, note_write, chk_privacy, note_privacy, hint_kinds;
  HWND kind[SD_NOTIFY_COUNT];         /* [ui] notify_<kind> switches (Notifications page) */
  ui_set_policy policy;               /* the Group Policy values read when the window opened (03 §3.5) */
  unsigned locked;                    /* UI_SET_F_* fields the policies lock */
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

/* Sets (on) or removes one value of the per-user Run key. Missing values are not an error when removing. */
static sd_err run_value_set(const wchar_t *value, const wchar_t *cmd, int on)
{
  HKEY k = NULL;
  LONG r;
  if (on) {
    r = RegCreateKeyExW(HKEY_CURRENT_USER, ST_RUN_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);
    if (r == ERROR_SUCCESS) {
      r = RegSetValueExW(k, value, 0, REG_SZ, (const BYTE *)cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
      RegCloseKey(k);
    }
  } else {
    r = RegOpenKeyExW(HKEY_CURRENT_USER, ST_RUN_KEY, 0, KEY_SET_VALUE, &k);
    if (r == ERROR_SUCCESS) {
      r = RegDeleteValueW(k, value);
      RegCloseKey(k);
    }
    if (r == ERROR_FILE_NOT_FOUND)
      r = ERROR_SUCCESS;
  }
  return r == ERROR_SUCCESS ? SD_OK : SD_E_FAILURE;
}

/* The tray's value: "<this program>" --tray. */
static sd_err run_key_set(int on)
{
  wchar_t exe[MAX_PATH * 2], cmd[MAX_PATH * 2 + 32] = L"";
  if (on) {
    if (GetModuleFileNameW(NULL, exe, SD_COUNTOF(exe)) == 0)
      return SD_E_FAILURE;
    if (ui_settings_run_command(exe, cmd, SD_COUNTOF(cmd)) != SD_OK)
      return SD_E_INVALID_PARAM;
  }
  return run_value_set(ST_RUN_VALUE, cmd, on);
}

/* The agent's value (M4, 03 §3.2 Start): shelldrive-host.exe next to this program, agent --logon. It is wanted when
   [agent] start_at_logon is yes or a profile has autostart = logon (sd_settings_agent_run_wanted). */
#define ST_AGENT_RUN_VALUE L"ShellDriveAgent"

static sd_err agent_run_set(int on)
{
  wchar_t exe[MAX_PATH * 2], cmd[MAX_PATH * 2 + 32] = L"";
  wchar_t *slash;
  if (on) {
    if (GetModuleFileNameW(NULL, exe, SD_COUNTOF(exe)) == 0)
      return SD_E_FAILURE;
    slash = wcsrchr(exe, L'\\');
    if (slash == NULL)
      return SD_E_FAILURE;
    slash[1] = L'\0';
    if (wcscat_s(exe, SD_COUNTOF(exe), L"shelldrive-host.exe") != 0)
      return SD_E_NAME_TOO_LONG;
    if (ui_settings_agent_run_command(exe, cmd, SD_COUNTOF(cmd)) != SD_OK)
      return SD_E_INVALID_PARAM;
  }
  return run_value_set(ST_AGENT_RUN_VALUE, cmd, on);
}

/* ---- policies and read-only status ---- */

/* Reads the policies that lock a setting through sd_policy (never the registry directly). */
static void policy_read(ui_set_policy *p)
{
  DWORD dw = 0;
  wchar_t w[UI_SET_LANG_MAX];
  memset(p, 0, sizeof(*p));
  if (sd_policy_get_sz(SD_POLICY_UILANGUAGE, w, SD_COUNTOF(w)) && w[0] != L'\0') {
    char code[UI_SET_LANG_MAX];
    size_t i;
    for (i = 0; w[i] != L'\0' && i + 1 < sizeof(code); i++)
      code[i] = w[i] < 0x80 ? (char)w[i] : '?';
    code[i] = '\0';
    if (ui_settings_lang_index(code) > 0) {
      p->language_set = 1;
      strcpy_s(p->language, sizeof(p->language), g_ui_set_lang_codes[ui_settings_lang_index(code)]);
    }
  }
  if (sd_policy_get_dword(SD_POLICY_DISABLEKNOWNHOSTSSOURCES, &dw) && dw == 1)
    p->sources_disabled = 1;
  if (sd_policy_get_dword(SD_POLICY_FORCEWRITETHROUGH, &dw) && dw != 0)
    p->force_through = 1;
  if (sd_policy_get_dword(SD_POLICY_LOGPRIVACY, &dw) && (dw == 0 || dw == 1)) {
    p->privacy_set = 1;
    p->privacy_strict = dw == 1 ? 1 : 0;
  }
}

/* State of a live host key source (TM-R06), read-only: a file that other users can write reads as INSECURE. */
static int source_state(sd_kh_store_kind kind)
{
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  sd_kh_src_state state = SD_KH_SRC_ABSENT;
  memset(&st, 0, sizeof(st));
  st.kind = kind;
  if (sd_known_hosts_open(&st, 1, &kh) != SD_OK)
    return (int)SD_KH_SRC_ABSENT;
  if (sd_known_hosts_source_state(kh, kind, &state, NULL, 0) != SD_OK)
    state = SD_KH_SRC_ABSENT;
  sd_known_hosts_close(kh);
  return (int)state;
}

static const wchar_t *note_text(ui_set_note n)
{
  if (n == UI_SET_NOTE_MANAGED)
    return sd_l10n_get(SD_MSG_UI_SETTINGS_UPDATE_MANAGED);
  if (n == UI_SET_NOTE_INSECURE)
    return sd_l10n_get(SD_MSG_UI_SETTINGS_SRC_INSECURE);
  return L"";
}

/* Read-only: the WebClient service state (never starts or changes the service, 02 7.2, TM-R21). */
static void webclient_refresh(void)
{
  sd_webdav_client_info ci;
  sd_msg_id id;
  memset(&ci, 0, sizeof(ci));
  (void)sd_webdav_query_client(&ci);
  switch (ui_settings_webclient_kind((int)ci.state)) {
  case UI_SET_WC_RUNNING:  id = SD_MSG_UI_SETTINGS_WEBCLIENT_RUNNING; break;
  case UI_SET_WC_STOPPED:  id = SD_MSG_UI_SETTINGS_WEBCLIENT_STOPPED; break;
  case UI_SET_WC_DISABLED: id = SD_MSG_UI_SETTINGS_WEBCLIENT_DISABLED; break;
  case UI_SET_WC_MISSING:  id = SD_MSG_UI_SETTINGS_WEBCLIENT_MISSING; break;
  default:                 id = SD_MSG_UI_SETTINGS_WEBCLIENT_UNKNOWN; break;
  }
  SetWindowTextW(g_st.val_wc, sd_l10n_get(id));
}

/* ---- controls ---- */

/* Shows m in the controls and disables the locked ones (a policy value is read-only). */
static void show_model(const ui_settings_model *m, unsigned locked, int openssh_state, int putty_state)
{
  int k;
  SendMessageW(g_st.lang, CB_SETCURSEL, ui_settings_lang_index(m->language), 0);
  EnableWindow(g_st.lang, (locked & UI_SET_F_LANGUAGE) ? FALSE : TRUE);
  SetWindowTextW(g_st.note_lang, (locked & UI_SET_F_LANGUAGE) ? note_text(UI_SET_NOTE_MANAGED) : L"");
  SendMessageW(g_st.chk_openssh, BM_SETCHECK, m->openssh_source ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(g_st.chk_putty, BM_SETCHECK, m->putty_source ? BST_CHECKED : BST_UNCHECKED, 0);
  EnableWindow(g_st.chk_openssh, (locked & UI_SET_F_OPENSSH) ? FALSE : TRUE);
  EnableWindow(g_st.chk_putty, (locked & UI_SET_F_PUTTY) ? FALSE : TRUE);
  SetWindowTextW(g_st.note_openssh,
                 note_text(ui_settings_source_note(m->openssh_source, (locked & UI_SET_F_OPENSSH) != 0, openssh_state)));
  SetWindowTextW(g_st.note_putty,
                 note_text(ui_settings_source_note(m->putty_source, (locked & UI_SET_F_PUTTY) != 0, putty_state)));
  SendMessageW(g_st.chk_roam, BM_SETCHECK, m->roam_credentials ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(g_st.agent_logon, BM_SETCHECK, m->agent_logon ? BST_CHECKED : BST_UNCHECKED, 0);
  SendMessageW(g_st.write, CB_SETCURSEL, m->write_mode == SD_PROFILE_WRITE_BEHIND ? 1 : 0, 0);
  EnableWindow(g_st.write, (locked & UI_SET_F_WRITE) ? FALSE : TRUE);
  SetWindowTextW(g_st.note_write, (locked & UI_SET_F_WRITE) ? note_text(UI_SET_NOTE_MANAGED) : L"");
  SendMessageW(g_st.chk_privacy, BM_SETCHECK, m->log_strict ? BST_CHECKED : BST_UNCHECKED, 0);
  EnableWindow(g_st.chk_privacy, (locked & UI_SET_F_PRIVACY) ? FALSE : TRUE);
  SetWindowTextW(g_st.note_privacy, (locked & UI_SET_F_PRIVACY) ? note_text(UI_SET_NOTE_MANAGED) : L"");
  SendMessageW(g_st.notify, BM_SETCHECK, m->notify ? BST_CHECKED : BST_UNCHECKED, 0);
  for (k = 0; k < SD_NOTIFY_COUNT; k++) {
    SendMessageW(g_st.kind[k], BM_SETCHECK, (m->notify_kinds & (1u << k)) ? BST_CHECKED : BST_UNCHECKED, 0);
    EnableWindow(g_st.kind[k], m->notify ? TRUE : FALSE);    /* the kinds sit under the master switch */
  }
}

/* The kind switches follow the master switch: they are disabled (not cleared) while notifications are off. */
static void kinds_follow_master(void)
{
  BOOL on = SendMessageW(g_st.notify, BM_GETCHECK, 0, 0) == BST_CHECKED ? TRUE : FALSE;
  int k;
  for (k = 0; k < SD_NOTIFY_COUNT; k++)
    EnableWindow(g_st.kind[k], on);
}


static void fill_lang(void)
{
  int i;
  SendMessageW(g_st.lang, CB_RESETCONTENT, 0, 0);
  SendMessageW(g_st.lang, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_LANG_SYSTEM));
  for (i = 1; i < UI_SET_LANG_COUNT; i++)
    SendMessageW(g_st.lang, CB_ADDSTRING, 0, (LPARAM)k_lang_names[i]);
}

static void populate_write(void)
{
  SendMessageW(g_st.write, CB_RESETCONTENT, 0, 0);
  SendMessageW(g_st.write, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_WRITE_THROUGH));
  SendMessageW(g_st.write, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(SD_MSG_UI_SETTINGS_WRITE_BEHIND));
}

static void populate(void)
{
  fill_lang();
  populate_write();

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
  show_model(&g_st.model, g_st.locked, source_state(SD_KH_SRC_OPENSSH), source_state(SD_KH_SRC_PUTTY));
  webclient_refresh();
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
  policy_read(&g_st.policy);
  g_st.locked = ui_settings_apply_policy(&g_st.model, &g_st.policy);
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
  unsigned changed;
  int lang_index;
  int chan_changed = 0;
  int k;

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
  m.openssh_source = SendMessageW(g_st.chk_openssh, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.putty_source = SendMessageW(g_st.chk_putty, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.roam_credentials = SendMessageW(g_st.chk_roam, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.agent_logon = SendMessageW(g_st.agent_logon, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  m.write_mode = SendMessageW(g_st.write, CB_GETCURSEL, 0, 0) == 1 ? SD_PROFILE_WRITE_BEHIND : SD_PROFILE_WRITE_THROUGH;
  m.log_strict = SendMessageW(g_st.chk_privacy, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
  for (k = 0; k < SD_NOTIFY_COUNT; k++)
    if (SendMessageW(g_st.kind[k], BM_GETCHECK, 0, 0) == BST_CHECKED)
      m.notify_kinds |= 1u << k;

  s = g_st.loaded;
  ui_settings_to_sd_masked(&m, g_st.locked, &s);
  /* the channel is saved unless a policy sets it (the list is then disabled, 03 §3.5) */
  {
    ui_upd_policy pol;
    int ci = (int)SendMessageW(g_st.channel, CB_GETCURSEL, 0, 0);
    ui_update_policy_now(&pol);
    if (!pol.channel_set) {
      chan_changed = (ci == 1) != (strcmp(g_st.loaded.update_channel, "beta") == 0);
      strcpy_s(s.update_channel, sizeof(s.update_channel), ci == 1 ? "beta" : "stable");
    }
  }
  /* write only what changed: nothing changed in settings.ini means no write and no reload */
  changed = ui_settings_changed(&g_st.model, &m) & ~UI_SET_F_LOGON;
  if (changed != 0 || chan_changed) {
    e = sd_settings_save(&s);
    if (e != SD_OK) {
      ui_win_error(g_st.wnd, SD_MSG_UI_SETTINGS_SAVE_FAILED, e);
      return;
    }
    g_app.settings = s;
  }
  /* the agent's Run value follows [agent] start_at_logon and the profiles with autostart = logon (M4) */
  e = agent_run_set(sd_settings_agent_run_wanted(&s));
  if (e != SD_OK) {
    status_msg(SD_MSG_UI_SETTINGS_RUN_FAILED);
    return;
  }
  if (m.start_at_logon != g_st.logon_before) {
    e = run_key_set(m.start_at_logon);
    if (e != SD_OK) {
      status_msg(SD_MSG_UI_SETTINGS_RUN_FAILED);
      return;
    }
  }
  /* the agent applies the file to new mounts and connections (config.reload, 2.4) */
  if ((changed != 0 || chan_changed) && g_app.agent_up && (g_app.agent_features & UI_FEAT_RELOAD))
    (void)ui_ipc_call(UI_IPC_RELOAD, "config.reload", NULL);

  g_st.model = m;
  g_st.loaded = s;
  if (changed & UI_SET_F_LANGUAGE)
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

/* --test-windows: the round 17 controls (default write mode, log privacy, agent start, per-kind switches) exist, show
   a model, follow the master switch and the policy locks. Synthetic model and policy, nothing is read or written. */
static int settings_r17_smoke(void)
{
  ui_settings_model m;
  ui_set_policy pol;
  unsigned locked;
  int k, ok;
  if (!(g_st.agent_logon && g_st.lbl_write && g_st.write && g_st.note_write && g_st.chk_privacy && g_st.note_privacy &&
        g_st.hint_kinds))
    return 0;
  for (k = 0; k < SD_NOTIFY_COUNT; k++)
    if (g_st.kind[k] == NULL)
      return 0;
  memset(&m, 0, sizeof(m));
  memset(&pol, 0, sizeof(pol));
  populate_write();
  m.notify = 1;
  m.write_mode = SD_PROFILE_WRITE_BEHIND;
  m.log_strict = 1;
  m.agent_logon = 1;
  m.notify_kinds = (1u << SD_NOTIFY_CONNECTION_LOST) | (1u << SD_NOTIFY_TERRAPIN);
  show_model(&m, 0, 0, 0);
  ok = IsWindowEnabled(g_st.write) && IsWindowEnabled(g_st.chk_privacy) &&
       SendMessageW(g_st.write, CB_GETCOUNT, 0, 0) == 2 &&
       SendMessageW(g_st.write, CB_GETCURSEL, 0, 0) == 1 &&
       SendMessageW(g_st.chk_privacy, BM_GETCHECK, 0, 0) == BST_CHECKED &&
       SendMessageW(g_st.agent_logon, BM_GETCHECK, 0, 0) == BST_CHECKED &&
       SendMessageW(g_st.kind[SD_NOTIFY_CONNECTION_LOST], BM_GETCHECK, 0, 0) == BST_CHECKED &&
       SendMessageW(g_st.kind[SD_NOTIFY_MOUNTED], BM_GETCHECK, 0, 0) == BST_UNCHECKED &&
       IsWindowEnabled(g_st.kind[SD_NOTIFY_TERRAPIN]) && GetWindowTextLengthW(g_st.note_write) == 0;
  /* the master switch off disables the kind switches without clearing them */
  m.notify = 0;
  show_model(&m, 0, 0, 0);
  ok = ok && !IsWindowEnabled(g_st.kind[SD_NOTIFY_TERRAPIN]) &&
       SendMessageW(g_st.kind[SD_NOTIFY_TERRAPIN], BM_GETCHECK, 0, 0) == BST_CHECKED;
  /* policies: the write mode shows through and the privacy shows the policy value, both read-only with the note */
  m.notify = 1;
  pol.force_through = 1;
  pol.privacy_set = 1;
  pol.privacy_strict = 0;
  locked = ui_settings_apply_policy(&m, &pol);
  show_model(&m, locked, 0, 0);
  ok = ok && !IsWindowEnabled(g_st.write) && !IsWindowEnabled(g_st.chk_privacy) &&
       SendMessageW(g_st.write, CB_GETCURSEL, 0, 0) == 0 &&
       SendMessageW(g_st.chk_privacy, BM_GETCHECK, 0, 0) == BST_UNCHECKED &&
       GetWindowTextLengthW(g_st.note_write) > 0 && GetWindowTextLengthW(g_st.note_privacy) > 0;
  return ok ? 1 : 0;
}

/* --test-windows: the security controls exist, and a policy lock disables them and shows the policy value. The
   controls are driven with a synthetic model and policy; nothing is read from or written to the machine. */
int ui_settings_security_smoke(void)
{
  ui_settings_model m;
  ui_set_policy pol;
  unsigned locked;
  int ok;
  if (!(g_st.tab && g_st.chk_openssh && g_st.chk_putty && g_st.note_openssh && g_st.note_putty && g_st.chk_roam &&
        g_st.hint_roam && g_st.lbl_wc && g_st.val_wc && g_st.note_lang))
    return 0;
  memset(&m, 0, sizeof(m));
  memset(&pol, 0, sizeof(pol));
  fill_lang();
  m.openssh_source = 1;
  m.putty_source = 1;
  m.roam_credentials = 1;
  strcpy_s(m.language, sizeof(m.language), "de");
  show_model(&m, 0, 0, 0);
  ok = IsWindowEnabled(g_st.chk_openssh) && IsWindowEnabled(g_st.chk_putty) && IsWindowEnabled(g_st.lang) &&
       SendMessageW(g_st.chk_roam, BM_GETCHECK, 0, 0) == BST_CHECKED &&
       SendMessageW(g_st.lang, CB_GETCURSEL, 0, 0) == ui_settings_lang_index("de") &&
       GetWindowTextLengthW(g_st.note_openssh) == 0;
  /* an insecure source file shows its note; a locked control is disabled, read-only and unchecked */
  show_model(&m, 0, 3, 3);
  ok = ok && GetWindowTextLengthW(g_st.note_openssh) > 0 && GetWindowTextLengthW(g_st.note_putty) > 0;
  pol.language_set = 1;
  strcpy_s(pol.language, sizeof(pol.language), "fr");
  pol.sources_disabled = 1;
  locked = ui_settings_apply_policy(&m, &pol);
  show_model(&m, locked, 3, 3);
  ok = ok && !IsWindowEnabled(g_st.chk_openssh) && !IsWindowEnabled(g_st.chk_putty) && !IsWindowEnabled(g_st.lang) &&
       SendMessageW(g_st.chk_openssh, BM_GETCHECK, 0, 0) == BST_UNCHECKED &&
       SendMessageW(g_st.lang, CB_GETCURSEL, 0, 0) == ui_settings_lang_index("fr") &&
       GetWindowTextLengthW(g_st.note_lang) > 0;
  /* the read-only WebClient status text */
  webclient_refresh();
  ok = ok && GetWindowTextLengthW(g_st.val_wc) > 0;
  return ok && settings_r17_smoke() ? 1 : 0;
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

/* The pages of the tab control (General, Security, Updates). The controls are siblings of the tab; a page shows
   its own controls and hides the others. */
enum { ST_PAGE_GENERAL = 0, ST_PAGE_SECURITY, ST_PAGE_NOTIFY, ST_PAGE_UPDATES, ST_PAGE_COUNT };

static void show_page(int page)
{
  HWND general[16], security[8], notify[1 + SD_NOTIFY_COUNT], updates[10];
  const size_t ng = SD_COUNTOF(general), ns = SD_COUNTOF(security), nn = SD_COUNTOF(notify),
               nu = SD_COUNTOF(updates);
  size_t i;
  general[0] = g_st.lbl_lang;   general[1] = g_st.lang;       general[2] = g_st.note_lang;
  general[3] = g_st.notify;     general[4] = g_st.logon;      general[5] = g_st.lbl_back;
  general[6] = g_st.backend;    general[7] = g_st.lbl_cache;  general[8] = g_st.cache;
  general[9] = g_st.hint_cache; general[10] = g_st.lbl_wc;    general[11] = g_st.val_wc;
  security[0] = g_st.chk_openssh; security[1] = g_st.note_openssh; security[2] = g_st.chk_putty;
  security[3] = g_st.note_putty;  security[4] = g_st.chk_roam;     security[5] = g_st.hint_roam;
  security[6] = g_st.chk_privacy; security[7] = g_st.note_privacy;
  general[12] = g_st.agent_logon; general[13] = g_st.lbl_write;    general[14] = g_st.write;
  general[15] = g_st.note_write;
  notify[0] = g_st.hint_kinds;
  for (i = 0; i < SD_NOTIFY_COUNT; i++)
    notify[1 + i] = g_st.kind[i];
  updates[0] = g_st.grp_upd;      updates[1] = g_st.lbl_channel;   updates[2] = g_st.channel;
  updates[3] = g_st.note_policy;  updates[4] = g_st.upd_status;    updates[5] = g_st.upd_stale;
  updates[6] = g_st.btn_check;    updates[7] = g_st.btn_install;   updates[8] = g_st.btn_notes;
  updates[9] = g_st.note_upd;
  for (i = 0; i < ng; i++)
    if (general[i]) ShowWindow(general[i], page == ST_PAGE_GENERAL ? SW_SHOW : SW_HIDE);
  for (i = 0; i < ns; i++)
    if (security[i]) ShowWindow(security[i], page == ST_PAGE_SECURITY ? SW_SHOW : SW_HIDE);
  for (i = 0; i < nn; i++)
    if (notify[i]) ShowWindow(notify[i], page == ST_PAGE_NOTIFY ? SW_SHOW : SW_HIDE);
  for (i = 0; i < nu; i++)
    if (updates[i]) ShowWindow(updates[i], page == ST_PAGE_UPDATES ? SW_SHOW : SW_HIDE);
}

static void layout(HWND hwnd)
{
  RECT rc, ir;
  int m, rh, gap, W, H, y, lw, cw, x, bw1, bw2, by, sh, note_h, bw, xp, x0, pw, nh, tabh;
  int lw_a, lw_b, lw_c, lw_d, lw_e, k;
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
  lw_d = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_WEBCLIENT));
  lw = lw_a;
  if (lw_b > lw) lw = lw_b;
  if (lw_c > lw) lw = lw_c;
  if (lw_d > lw) lw = lw_d;
  lw_e = ui_win_text_width(g_st.font, sd_l10n_get(SD_MSG_UI_SETTINGS_WRITE_DEFAULT));
  if (lw_e > lw) lw = lw_e;
  lw += dpx(12);
  cw = dpx(260);

  /* bottom: status line, buttons, the live/restart note; the tab control takes the rest */
  by = H - m - sh - gap - dpx(26);
  nh = note_h;
  tabh = by - gap - nh - gap - m;
  place(g_st.tab, m, m, W - 2 * m, tabh);
  ir.left = 0; ir.top = 0; ir.right = W - 2 * m; ir.bottom = tabh;
  TabCtrl_AdjustRect(g_st.tab, FALSE, &ir);
  x0 = m + ir.left + gap;
  pw = ir.right - ir.left - 2 * gap;
  y = m + ir.top + gap;

  /* General */
  place(g_st.lbl_lang, x0, y + dpx(4), lw, rh);
  place(g_st.lang, x0 + lw, y, cw, dpx(200));
  xp = x0 + lw + cw + gap;
  place(g_st.note_lang, xp, y + dpx(4), x0 + pw - xp, rh);
  y += rh + gap;
  place(g_st.notify, x0, y, pw, rh);
  y += rh + gap / 2;
  place(g_st.logon, x0, y, pw, rh);
  y += rh + gap / 2;
  place(g_st.agent_logon, x0, y, pw, rh);
  y += rh + gap;
  place(g_st.lbl_back, x0, y + dpx(4), lw, rh);
  place(g_st.backend, x0 + lw, y, cw, dpx(200));
  y += rh + gap;
  place(g_st.lbl_write, x0, y + dpx(4), lw, rh);
  place(g_st.write, x0 + lw, y, cw, dpx(200));
  SendMessageW(g_st.write, CB_SETDROPPEDWIDTH, (WPARAM)(pw - lw > cw ? pw - lw : cw), 0);
  xp = x0 + lw + cw + gap;
  place(g_st.note_write, xp, y + dpx(4), x0 + pw - xp, rh);
  y += rh + gap;
  place(g_st.lbl_cache, x0, y + dpx(4), lw, rh);
  place(g_st.cache, x0 + lw, y, dpx(100), rh);
  x = x0 + lw + dpx(100) + gap;
  place(g_st.hint_cache, x, y + dpx(4), x0 + pw - x, rh);
  y += rh + gap;
  place(g_st.lbl_wc, x0, y + dpx(4), lw, rh);
  place(g_st.val_wc, x0 + lw, y + dpx(4), pw - lw, note_h);

  /* Security */
  y = m + ir.top + gap;
  place(g_st.chk_openssh, x0, y, pw, rh);
  y += rh;
  place(g_st.note_openssh, x0 + dpx(20), y, pw - dpx(20), sh);
  y += sh + gap;
  place(g_st.chk_putty, x0, y, pw, rh);
  y += rh;
  place(g_st.note_putty, x0 + dpx(20), y, pw - dpx(20), sh);
  y += sh + gap;
  place(g_st.chk_roam, x0, y, pw, rh);
  y += rh;
  place(g_st.hint_roam, x0 + dpx(20), y, pw - dpx(20), note_h);
  y += note_h + gap;
  place(g_st.chk_privacy, x0, y, pw, rh);
  y += rh;
  place(g_st.note_privacy, x0 + dpx(20), y, pw - dpx(20), sh);

  /* Notifications */
  y = m + ir.top + gap;
  place(g_st.hint_kinds, x0, y, pw, note_h);
  y += note_h + gap / 2;
  for (k = 0; k < SD_NOTIFY_COUNT; k++) {
    place(g_st.kind[k], x0, y, pw, rh);
    y += rh + 2;
  }

  /* Updates */
  y = m + ir.top + gap;
  place(g_st.grp_upd, x0, y, pw, rh);
  y += rh + gap / 2;
  place(g_st.lbl_channel, x0, y + dpx(4), lw, rh);
  place(g_st.channel, x0 + lw, y, cw, dpx(200));
  xp = x0 + lw + cw + gap;
  place(g_st.note_policy, xp, y + dpx(4), x0 + pw - xp, rh);
  y += rh + gap / 2;
  place(g_st.upd_status, x0, y, pw, note_h);
  y += note_h;
  place(g_st.upd_stale, x0, y, pw, rh);
  y += rh + gap / 2;
  bw = dpx(140);
  place(g_st.btn_check, x0, y, bw, dpx(26));
  place(g_st.btn_install, x0 + bw + gap, y, bw + dpx(40), dpx(26));
  place(g_st.btn_notes, x0 + bw + gap + bw + dpx(40) + gap, y, bw + dpx(20), dpx(26));
  y += dpx(26) + gap / 2;
  place(g_st.note_upd, x0, y, pw, note_h);

  place(g_st.note_rest, m, by - gap - nh, W - 2 * m, nh);
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
  else if (id == ST_ID_NOTIFY && code == BN_CLICKED)
    kinds_follow_master();
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
  TCITEMW ti;
  static const sd_msg_id tabs[ST_PAGE_COUNT] = { SD_MSG_UI_SETTINGS_TAB_GENERAL, SD_MSG_UI_SETTINGS_TAB_SECURITY,
                                                 SD_MSG_UI_SETTINGS_TAB_NOTIFICATIONS,
                                                 SD_MSG_UI_SETTINGS_GROUP_UPDATES };
  int i;
  g_st.tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS, 0, 0, 10,
                             10, hwnd, (HMENU)(UINT_PTR)ST_ID_TAB, g_app.inst, NULL);
  for (i = 0; i < ST_PAGE_COUNT && g_st.tab; i++) {
    memset(&ti, 0, sizeof(ti));
    ti.mask = TCIF_TEXT;
    ti.pszText = (LPWSTR)sd_l10n_get(tabs[i]);
    (void)SendMessageW(g_st.tab, TCM_INSERTITEMW, (WPARAM)i, (LPARAM)&ti);
  }
  g_st.note_lang = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_LANG, hwnd);
  g_st.chk_openssh = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_TRUST_OPENSSH),
                                WS_TABSTOP | BS_AUTOCHECKBOX, ST_ID_CHK_OPENSSH, hwnd);
  g_st.note_openssh = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_OPENSSH, hwnd);
  g_st.chk_putty = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_TRUST_PUTTY), WS_TABSTOP | BS_AUTOCHECKBOX,
                              ST_ID_CHK_PUTTY, hwnd);
  g_st.note_putty = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_PUTTY, hwnd);
  g_st.chk_roam = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_ROAM), WS_TABSTOP | BS_AUTOCHECKBOX,
                             ST_ID_CHK_ROAM, hwnd);
  g_st.hint_roam = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_ROAM_HINT), SS_LEFT | SS_NOPREFIX,
                              ST_ID_HINT_ROAM, hwnd);
  g_st.agent_logon = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_AGENT_LOGON),
                                WS_TABSTOP | BS_AUTOCHECKBOX, ST_ID_AGENT_LOGON, hwnd);
  g_st.lbl_write = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_WRITE_DEFAULT), SS_LEFT | SS_NOPREFIX,
                              ST_ID_LBL_WRITE, hwnd);
  g_st.write = make_child(L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, ST_ID_WRITE, hwnd);
  g_st.note_write = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_WRITE, hwnd);
  g_st.chk_privacy = make_child(L"BUTTON", sd_l10n_get(SD_MSG_UI_SETTINGS_LOG_PRIVACY),
                                WS_TABSTOP | BS_AUTOCHECKBOX, ST_ID_CHK_PRIVACY, hwnd);
  g_st.note_privacy = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_NOTE_PRIVACY, hwnd);
  g_st.hint_kinds = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_NOTIFY_HINT), SS_LEFT | SS_NOPREFIX,
                               ST_ID_HINT_KINDS, hwnd);
  for (i = 0; i < SD_NOTIFY_COUNT; i++)
    g_st.kind[i] = make_child(L"BUTTON", sd_l10n_get(k_kind_label[i]), WS_TABSTOP | BS_AUTOCHECKBOX,
                              ST_ID_KIND_BASE + i, hwnd);
  g_st.lbl_wc = make_child(L"STATIC", sd_l10n_get(SD_MSG_UI_SETTINGS_WEBCLIENT), SS_LEFT | SS_NOPREFIX,
                           ST_ID_LBL_WC, hwnd);
  g_st.val_wc = make_child(L"STATIC", L"", SS_LEFT | SS_NOPREFIX, ST_ID_VAL_WC, hwnd);
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
  show_page(ST_PAGE_GENERAL);
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
  case WM_NOTIFY:
    if (lp != 0 && ((const NMHDR *)lp)->idFrom == ST_ID_TAB && ((const NMHDR *)lp)->code == TCN_SELCHANGE) {
      show_page((int)SendMessageW(g_st.tab, TCM_GETCURSEL, 0, 0));
      return 0;
    }
    break;
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
