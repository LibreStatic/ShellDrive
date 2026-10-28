/* shelldrive-ui: the legacy and Terrapin details dialog (03 §7.6).
 *
 * Opened from the Connection menu ("Security details...") and from the balloon of a legacy_algorithms or
 * terrapin_exposed warning. It says what the Security column shows: the outdated algorithms the connection negotiated
 * (category, name and a one-line reason each) and the Terrapin text. Buttons: "Don't warn again for this server" (stores
 * legacy_accepted = sha256 of the sorted algorithm list in the profile; a different set warns again; it never silences
 * Terrapin), "Refuse outdated algorithms for this server" (sets legacy_algorithms = refuse and offers to reconnect) and
 * Close. The two settings need the saved profile of the mount and, for the first, the algorithm names, which the agent
 * sends only with the warning event (a list of a UI that started later has the code only, see ui_mainview_model.h). */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "ui_dlg.h"
#include "ui_int.h"
#include "ui_mainview_model.h"
#include "ui_measure.h"
#include "ui_win.h"

#define SEC_ID_LIST   4601
#define SEC_ID_KEEP   4602
#define SEC_ID_REFUSE 4603
#define SEC_WIDTH     300
#define SEC_MAX_ALGOS 16

static char g_reconnect_profile[33];      /* a profile to mount again once its drive is unmounted ("" when none) */

typedef struct sec_dlg {
  char profile_id[33];
  wchar_t drive[3];
  char algos[UI_MV_ALGOS_MAX];
  unsigned sec;
} sec_dlg;

static void widen(const char *s, wchar_t *out, size_t cch)
{
  size_t i;
  for (i = 0; i + 1 < cch && s[i] != 0; i++)
    out[i] = (wchar_t)(unsigned char)s[i];
  out[i] = 0;
}

static sd_msg_id cat_msg(ui_mv_cat c)
{
  switch (c) {
  case UI_MV_CAT_KEX:     return SD_MSG_UI_SECDLG_CAT_KEX;
  case UI_MV_CAT_HOSTKEY: return SD_MSG_UI_SECDLG_CAT_HOSTKEY;
  case UI_MV_CAT_CIPHER:  return SD_MSG_UI_SECDLG_CAT_CIPHER;
  case UI_MV_CAT_MAC:     return SD_MSG_UI_SECDLG_CAT_MAC;
  default:                return SD_MSG_UI_SECDLG_CAT_OTHER;
  }
}

static sd_msg_id why_msg(ui_mv_why w)
{
  switch (w) {
  case UI_MV_WHY_KEX_SHA1:     return SD_MSG_UI_SECDLG_WHY_KEX;
  case UI_MV_WHY_CBC:          return SD_MSG_UI_SECDLG_WHY_CBC;
  case UI_MV_WHY_MAC_SHA1:     return SD_MSG_UI_SECDLG_WHY_MAC;
  case UI_MV_WHY_HOSTKEY_SHA1: return SD_MSG_UI_SECDLG_WHY_HOSTKEY;
  default:                     return SD_MSG_UI_SECDLG_WHY_OTHER;
  }
}

/* One line per outdated algorithm: "Cipher: 3des-cbc (CBC cipher mode, ...)". */
static void algo_lines(const char *csv, wchar_t *out, size_t cap)
{
  char names[SEC_MAX_ALGOS][64];
  size_t i, n = ui_mv_algos_split(csv, names, SEC_MAX_ALGOS);
  out[0] = 0;
  for (i = 0; i < n; i++) {
    ui_mv_cat cat;
    ui_mv_why why;
    wchar_t wname[64];
    wchar_t *line;
    sd_arg a[3];
    ui_mv_algo_info(names[i], &cat, &why);
    widen(names[i], wname, SD_COUNTOF(wname));
    a[0].name = "category";
    a[0].type = SD_ARG_STR;
    a[0].v.s = sd_l10n_get(cat_msg(cat));
    a[1].name = "algorithm";
    a[1].type = SD_ARG_STR;
    a[1].v.s = wname;
    a[2].name = "reason";
    a[2].type = SD_ARG_STR;
    a[2].v.s = sd_l10n_get(why_msg(why));
    line = sd_l10n_format_alloc(SD_MSG_UI_SECDLG_ALGO_LINE, a, 3);
    if (line == NULL)
      continue;
    if (i > 0)
      wcscat_s(out, cap, L"\r\n");
    wcscat_s(out, cap, line);
    sd_free(line);
  }
}

/* Template of the dialog for a mount. Release *blob with sd_free. */
static sd_err build_dialog(const char *host, unsigned sec, const char *algos, int can_keep, int can_refuse,
                           unsigned char **blob, size_t *len)
{
  WORD ids[3];
  const wchar_t *texts[3];
  size_t nb = 0;
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96;
  ui_measure m;
  wchar_t whost[128];
  wchar_t lines[SEC_MAX_ALGOS * 200];
  wchar_t *legacy = NULL, *terrapin = NULL;
  int have_list = (sec & UI_MV_SEC_LEGACY) && algos[0] != 0;
  sd_arg a[1];
  ui_dlg *d = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
  sd_err e;
  if (d == NULL)
    return SD_E_NO_MEMORY;
  widen(host, whost, SD_COUNTOF(whost));
  a[0].name = "host";
  a[0].type = SD_ARG_STR;
  a[0].v.s = whost;
  if (sec & UI_MV_SEC_LEGACY)
    legacy = sd_l10n_format_alloc(SD_MSG_UI_SECDLG_LEGACY, a, 1);
  if (sec & UI_MV_SEC_TERRAPIN)
    terrapin = sd_l10n_format_alloc(SD_MSG_UI_SECDLG_TERRAPIN, a, 1);
  if (have_list)
    algo_lines(algos, lines, SD_COUNTOF(lines));
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  if (can_keep) { ids[nb] = SEC_ID_KEEP; texts[nb++] = sd_l10n_get(SD_MSG_UI_SECDLG_BTN_KEEP); }
  if (can_refuse) { ids[nb] = SEC_ID_REFUSE; texts[nb++] = sd_l10n_get(SD_MSG_UI_SECDLG_BTN_REFUSE); }
  ids[nb] = IDCANCEL; texts[nb++] = sd_l10n_get(SD_MSG_UI_SECDLG_BTN_CLOSE);
  e = ui_dlg_init(d, sd_l10n_get(SD_MSG_UI_SECDLG_TITLE), SEC_WIDTH, face, points, ui_measure_cb, &m);
  if (e == SD_OK && terrapin != NULL) e = ui_dlg_text(d, 0, terrapin, SS_NOPREFIX);
  if (e == SD_OK && legacy != NULL) e = ui_dlg_text(d, 0, legacy, SS_NOPREFIX);
  if (e == SD_OK && (sec & UI_MV_SEC_LEGACY)) {
    if (have_list) {
      if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_SECDLG_LIST_LABEL), 0);
      if (e == SD_OK) e = ui_dlg_multiline(d, SEC_ID_LIST, lines, SEC_MAX_ALGOS);
    } else {
      e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_SECDLG_LIST_UNKNOWN), SS_NOPREFIX);
    }
  }
  if (e == SD_OK) e = ui_dlg_space(d, 4);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, nb, IDCANCEL);
  if (e == SD_OK) e = ui_dlg_build(d, blob, len);
  ui_measure_free(&m);
  sd_free(d);
  sd_free(legacy);
  sd_free(terrapin);
  return e;
}

static int save_profile(HWND owner, sd_profile *p)
{
  sd_err e = sd_profile_save(p);
  if (e != SD_OK) {
    ui_win_error(owner, SD_MSG_UI_SETTINGS_SAVE_FAILED, e);
    return 0;
  }
  ui_main_reload_profiles();
  ui_ipc_config_reload();
  return 1;
}

static void do_keep(HWND owner, const sec_dlg *c)
{
  const sd_profile *cur = ui_profiles_find_id(c->profile_id);
  sd_profile p;
  char hash[80];
  if (cur == NULL || !ui_mv_algos_hash(c->algos, hash))
    return;
  p = *cur;
  if (strlen(hash) >= sizeof(p.legacy_accepted))
    return;
  strcpy_s(p.legacy_accepted, sizeof(p.legacy_accepted), hash);
  if (save_profile(owner, &p))
    ui_win_message(owner, sd_l10n_get(SD_MSG_UI_SECDLG_KEEP_DONE), MB_OK | MB_ICONINFORMATION);
}

static void do_refuse(HWND owner, const sec_dlg *c)
{
  const sd_profile *cur = ui_profiles_find_id(c->profile_id);
  sd_profile p;
  wchar_t *text;
  if (cur == NULL)
    return;
  p = *cur;
  p.legacy_algorithms = SD_PROFILE_LEGACY_REFUSE;
  if (!save_profile(owner, &p))
    return;
  /* the setting applies to the next connection: offer to reconnect now */
  text = ui_format1(SD_MSG_UI_SECDLG_REFUSE_ASK, "drive", c->drive);
  if (text == NULL)
    return;
  if (MessageBoxW(owner, text, L"ShellDrive", MB_YESNO | MB_ICONQUESTION) == IDYES && g_app.agent_up) {
    strcpy_s(g_reconnect_profile, sizeof(g_reconnect_profile), c->profile_id);
    ui_ipc_unmount(c->drive);
  }
  sd_free(text);
}

static INT_PTR CALLBACK sec_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  sec_dlg *c = (sec_dlg *)GetWindowLongPtrW(hwnd, DWLP_USER);
  switch (msg) {
  case WM_INITDIALOG:
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)lp);
    return TRUE;
  case WM_COMMAND:
    if (c == NULL)
      break;
    if (LOWORD(wp) == SEC_ID_KEEP) {
      do_keep(hwnd, c);
      EndDialog(hwnd, IDOK);
      return TRUE;
    }
    if (LOWORD(wp) == SEC_ID_REFUSE) {
      do_refuse(hwnd, c);
      EndDialog(hwnd, IDOK);
      return TRUE;
    }
    if (LOWORD(wp) == IDCANCEL) {
      EndDialog(hwnd, IDCANCEL);
      return TRUE;
    }
    break;
  default:
    break;
  }
  return FALSE;
}

void ui_secdlg_open(HWND owner, const wchar_t *drive)
{
  ui_mount *m = ui_model_find_drive(&g_app.model, drive);
  unsigned char *blob = NULL;
  size_t len = 0;
  sec_dlg c;
  int can_keep, can_refuse;
  if (m == NULL || m->sec == 0)
    return;
  memset(&c, 0, sizeof(c));
  strcpy_s(c.profile_id, sizeof(c.profile_id), m->profile_id);
  wcscpy_s(c.drive, SD_COUNTOF(c.drive), m->drive);
  strcpy_s(c.algos, sizeof(c.algos), m->algos);
  c.sec = m->sec;
  /* both settings are stored in the saved profile; "Don't warn again" also needs the algorithm names */
  can_refuse = (m->sec & UI_MV_SEC_LEGACY) && ui_profiles_find_id(m->profile_id) != NULL;
  can_keep = can_refuse && m->algos[0] != 0;
  if (build_dialog(m->host, m->sec, m->algos, can_keep, can_refuse, &blob, &len) == SD_OK && blob != NULL)
    DialogBoxIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, owner, sec_proc, (LPARAM)&c);
  sd_free(blob);
}

void ui_secdlg_on_unmounted(const char *profile_id)
{
  if (g_reconnect_profile[0] == 0 || profile_id == NULL || strcmp(profile_id, g_reconnect_profile) != 0)
    return;
  g_reconnect_profile[0] = 0;
  if (ui_ipc_mount(profile_id) != SD_OK)
    SD_LOGW("ui", "the drive could not be mounted again after the legacy algorithm setting changed");
}

/* --test-windows: the template builds and parses for the legacy, Terrapin and both cases, with and without names. */
int ui_secdlg_smoke(void)
{
  static const unsigned k_sec[] = { UI_MV_SEC_LEGACY, UI_MV_SEC_TERRAPIN, UI_MV_SEC_LEGACY | UI_MV_SEC_TERRAPIN,
                                    UI_MV_SEC_LEGACY };
  static const char *const k_algos[] = { "3des-cbc,hmac-sha1,diffie-hellman-group1-sha1,ssh-rsa", "", "hmac-sha1", "" };
  size_t i, count = 0, offs[UI_DLG_MAX_ITEMS];
  int ok = 1;
  for (i = 0; i < SD_COUNTOF(k_sec) && ok; i++) {
    unsigned char *blob = NULL;
    size_t len = 0;
    int legacy = (k_sec[i] & UI_MV_SEC_LEGACY) != 0;
    int named = k_algos[i][0] != 0;
    int keep = legacy && named, refuse = legacy;
    /* texts: terrapin and legacy intros as present; the list label and edit with names, one text without; buttons */
    size_t want = ((k_sec[i] & UI_MV_SEC_TERRAPIN) ? 1u : 0u) + (legacy ? 1u : 0u) + (legacy ? (named ? 2u : 1u) : 0u) +
                  (keep ? 1u : 0u) + (refuse ? 1u : 0u) + 1u;
    ok = build_dialog("example.org", k_sec[i], k_algos[i], keep, refuse, &blob, &len) == SD_OK && blob != NULL &&
         ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK && count == want;
    sd_free(blob);
  }
  return ok;
}
