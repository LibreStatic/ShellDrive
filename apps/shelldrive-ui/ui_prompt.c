/* shelldrive-ui: prompt dialogs (03 §2.5, §5.2, §5.4, §7.6, §7.7, §11).
 *
 * One modeless dialog per prompt.request, up to UI_PROMPT_MAX_OPEN at a time (the agent's queue holds 16).
 * The dialog built from a ui_prompt (ui_prompt_model.c) through the in-memory templates of ui_dlg.c. Answers
 * go to the agent through the IPC thread (ui_ipc_answer); the UI thread never talks to the pipe.
 *
 * Trust decisions have no default button (TM-R03): hostkey dialogs focus the fingerprint, so Enter does
 * nothing until the user moves to a button. Escape and the window close box cancel. The dialog never answers
 * on its own: prompt.closed (answered elsewhere, timeout, superseded) only closes it, and a timeout also
 * shows a tray balloon. Secrets: edit text is copied into sd_alloc buffers, the answer builder wipes them,
 * the JSON is wiped after it is queued, and the edit controls are cleared when the dialog goes away. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "ui_dlg.h"
#include "ui_int.h"
#include "ui_measure.h"
#include "ui_prompt_model.h"

#define UI_PROMPT_MAX_OPEN   16
#define UI_PROMPT_WIDTH      300     /* dialog units */
#define UI_PROMPT_REFRESH_MS 15000u  /* remaining-time text (accessibility: not every second) */
#define UI_PROMPT_CASCADE    24     /* pixels between stacked dialogs */

#define ID_P_EDIT_BASE   200         /* 200 + index: response edits */
#define ID_P_SAVE        220
#define ID_P_ERR         221
#define ID_P_DEADLINE    222
#define ID_P_FP          223          /* read-only fingerprint of a host key */
#define ID_P_BTN_ONCE    225
#define ID_P_TEXT_BASE   300         /* 300 + index: static text lines */
#define TIMER_REFRESH    1

typedef struct ui_pdlg {
  ui_prompt *p;
  HWND hwnd;
  HWND edits[UI_PROMPT_MAX_ITEMS];
  size_t nedits;
  HWND save;
  HWND err;
  HWND deadline;
  uint64_t deadline_at;              /* sd_tick_ms value when the prompt times out */
  int closing;
} ui_pdlg;

static ui_pdlg *g_open[UI_PROMPT_MAX_OPEN];
static size_t g_nopen;

/* ---- text helpers ---- */

static wchar_t *fmt(sd_msg_id id, const sd_arg *args, size_t n)
{
  return sd_l10n_format_alloc(id, args, n);
}

static void wipe_text(wchar_t *s, size_t units)
{
  if (s != NULL)
    SecureZeroMemory(s, units * sizeof(wchar_t));
}

/* ---- dialog layout ---- */

static sd_err add_hop_lines(ui_dlg *d, const ui_prompt *p)
{
  sd_arg a[2];
  wchar_t *t;
  sd_err e = SD_OK;
  if (p->hop >= 2) {
    a[0].name = "hop"; a[0].type = SD_ARG_INT; a[0].v.i = p->hop;
    a[1].name = "hops"; a[1].type = SD_ARG_INT; a[1].v.i = p->hops;
    t = fmt(SD_MSG_UI_PROMPT_HOP_INFO, a, 2);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 90, t, 0);
    sd_free(t);
    if (e != SD_OK)
      return e;
    a[0].name = "via"; a[0].type = SD_ARG_STR; a[0].v.s = p->via;
    t = fmt(SD_MSG_UI_PROMPT_REACH_VIA, a, 1);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 91, t, 0);
    sd_free(t);
  }
  return e;
}

static sd_err add_profile_line(ui_dlg *d, const ui_prompt *p)
{
  sd_arg a[1];
  wchar_t *t;
  sd_err e;
  a[0].name = "profile"; a[0].type = SD_ARG_STR; a[0].v.s = p->profile;
  t = fmt(SD_MSG_UI_PROMPT_PROFILE_LINE, a, 1);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_TEXT_BASE + 92, t, SS_NOPREFIX);
  sd_free(t);
  return e;
}

static sd_err add_intro_host(ui_dlg *d, const ui_prompt *p, sd_msg_id id)
{
  sd_arg a[2];
  wchar_t *t;
  sd_err e;
  a[0].name = "host"; a[0].type = SD_ARG_STR; a[0].v.s = p->host;
  a[1].name = "port"; a[1].type = SD_ARG_INT; a[1].v.i = p->port;
  t = fmt(id, a, 2);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_TEXT_BASE, t, SS_NOPREFIX);
  sd_free(t);
  return e;
}

static sd_err add_hostkey_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[3] = { IDOK, ID_P_BTN_ONCE, IDCANCEL };
  const wchar_t *texts[3];
  sd_arg a[1];
  wchar_t *t;
  sd_err e;

  e = add_intro_host(d, p, SD_MSG_UI_PROMPT_HOSTKEY_INTRO);
  if (e == SD_OK) e = add_hop_lines(d, p);
  if (e == SD_OK) e = add_profile_line(d, p);
  a[0].name = "type"; a[0].type = SD_ARG_STR; a[0].v.s = p->key_type;
  t = fmt(SD_MSG_UI_PROMPT_KEY_TYPE, a, 1);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = e == SD_OK ? ui_dlg_text(d, ID_P_TEXT_BASE + 93, t, SS_NOPREFIX) : e;
  sd_free(t);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 94, sd_l10n_get(SD_MSG_UI_PROMPT_FIELD_FINGERPRINT), 0);
  if (e == SD_OK) e = ui_dlg_multiline(d, ID_P_FP, p->fingerprint, 1);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 95, sd_l10n_get(SD_MSG_UI_PROMPT_HOSTKEY_CHECK), 0);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 96, sd_l10n_get(SD_MSG_UI_PROMPT_HOSTKEY_CHOICE), 0);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 97, sd_l10n_get(SD_MSG_UI_PROMPT_CHOOSE_BUTTON), 0);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_TRUST);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_ONCE);
  texts[2] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 3, 0);
  return e;
}

static sd_err add_changed_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[1] = { IDCANCEL };
  const wchar_t *texts[1];
  sd_arg a[1];
  wchar_t *t;
  sd_err e = add_intro_host(d, p, SD_MSG_UI_PROMPT_CHANGED_INTRO);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 93, sd_l10n_get(SD_MSG_UI_PROMPT_CHANGED_WARNING), 0);
  a[0].name = "fingerprint"; a[0].type = SD_ARG_STR; a[0].v.s = p->stored_fingerprint;
  t = fmt(SD_MSG_UI_PROMPT_CHANGED_STORED, a, 1);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = e == SD_OK ? ui_dlg_text(d, ID_P_TEXT_BASE + 94, t, SS_NOPREFIX) : e;
  sd_free(t);
  a[0].v.s = p->fingerprint;
  t = fmt(SD_MSG_UI_PROMPT_CHANGED_OFFERED, a, 1);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = e == SD_OK ? ui_dlg_text(d, ID_P_TEXT_BASE + 95, t, SS_NOPREFIX) : e;
  sd_free(t);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CLOSE);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 1, 0);
  return e;
}

/* One response edit with its label. label_id: a message id, password-style when secret. */
static sd_err add_field(ui_dlg *d, const wchar_t *label, size_t index, int secret)
{
  sd_err e = ui_dlg_text(d, ID_P_TEXT_BASE + 60 + (WORD)index, label, 0);
  if (e == SD_OK)
    e = ui_dlg_edit(d, (WORD)(ID_P_EDIT_BASE + index), secret ? ES_PASSWORD : 0);
  return e;
}

static sd_err add_deadline(ui_dlg *d, const ui_prompt *p)
{
  wchar_t *t;
  sd_arg a[1];
  sd_err e = SD_OK;
  if (!p->has_deadline)
    return SD_OK;
  a[0].name = "count";
  a[0].type = SD_ARG_INT;
  a[0].v.i = (long long)((p->deadline_ms + 59999) / 60000);
  if (a[0].v.i < 1)
    a[0].v.i = 1;
  t = ui_format_count(SD_MSG_UI_PROMPT_DEADLINE, a[0].v.i);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_DEADLINE, t, SS_NOPREFIX);
  sd_free(t);
  return e;
}

static sd_err add_password_dialog(ui_dlg *d, const ui_prompt *p, int passphrase)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];
  sd_err e = SD_OK;
  if (passphrase) {
    wchar_t *t;
    sd_arg a[1];
    a[0].name = "fingerprint"; a[0].type = SD_ARG_STR; a[0].v.s = p->key_fingerprint;
    t = fmt(SD_MSG_UI_PROMPT_KEY_FINGERPRINT, a, 1);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 98, t, SS_NOPREFIX);
    sd_free(t);
  } else {
    sd_arg a[2];
    wchar_t *t;
    a[0].name = "host"; a[0].type = SD_ARG_STR; a[0].v.s = p->host;
    a[1].name = "user"; a[1].type = SD_ARG_STR; a[1].v.s = p->user;
    t = fmt(SD_MSG_UI_PROMPT_TARGET_LINE, a, 2);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 98, t, SS_NOPREFIX);
    sd_free(t);
  }
  if (e == SD_OK) e = add_profile_line(d, p);
  if (e == SD_OK) e = add_hop_lines(d, p);
  if (e == SD_OK && p->hostkey_just_accepted)
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 99, sd_l10n_get(SD_MSG_UI_PROMPT_JUST_ACCEPTED), 0);
  if (e == SD_OK && p->is_reconnect)
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 100, sd_l10n_get(SD_MSG_UI_PROMPT_RECONNECT), 0);
  if (e == SD_OK) e = add_field(d, sd_l10n_get(passphrase ? SD_MSG_UI_PROMPT_FIELD_PASSPHRASE : SD_MSG_UI_PROMPT_FIELD_PASSWORD), 0, 1);
  if (e == SD_OK && p->can_save)
    e = ui_dlg_check(d, ID_P_SAVE, sd_l10n_get(SD_MSG_UI_PROMPT_CHECK_SAVE));
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_ERR, L"", 0);
  if (e == SD_OK) e = add_deadline(d, p);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CONNECT);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, IDOK);
  return e;
}

static sd_err add_kbdint_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];
  sd_err e;
  size_t i;

  e = add_intro_host(d, p, SD_MSG_UI_PROMPT_KBDINT_INTRO);
  if (e == SD_OK) e = add_hop_lines(d, p);
  if (e == SD_OK) e = add_profile_line(d, p);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 101, sd_l10n_get(SD_MSG_UI_PROMPT_SERVER_CAPTION), 0);
  if (e == SD_OK && p->name[0] != 0)
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 102, p->name, SS_NOPREFIX);
  if (e == SD_OK && p->instruction[0] != 0)
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 103, p->instruction, SS_NOPREFIX);
  for (i = 0; e == SD_OK && i < p->item_count; i++) {
    sd_arg a[2];
    wchar_t *t;
    a[0].name = "n"; a[0].type = SD_ARG_INT; a[0].v.i = (long long)i + 1;
    a[1].name = "total"; a[1].type = SD_ARG_INT; a[1].v.i = (long long)p->item_count;
    t = fmt(SD_MSG_UI_PROMPT_KBD_ANSWER, a, 2);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    /* the server's own text is shown above the field, unchanged apart from the sanitizing */
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 104 + (WORD)i, p->items[i].text, SS_NOPREFIX);
    if (e == SD_OK)
      e = ui_dlg_text(d, ID_P_TEXT_BASE + 120 + (WORD)i, t, 0);
    if (e == SD_OK)
      e = ui_dlg_edit(d, (WORD)(ID_P_EDIT_BASE + i), p->items[i].echo ? 0 : ES_PASSWORD);
    sd_free(t);
  }
  if (e == SD_OK && p->can_save && p->item_count == 1 && !p->items[0].echo)
    e = ui_dlg_check(d, ID_P_SAVE, sd_l10n_get(SD_MSG_UI_PROMPT_CHECK_SAVE));
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_ERR, L"", 0);
  if (e == SD_OK) e = add_deadline(d, p);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_VERIFY);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, IDOK);
  return e;
}

static sd_err add_password_change_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];
  sd_arg a[1];
  wchar_t *t;
  sd_err e;

  a[0].name = "user"; a[0].type = SD_ARG_STR; a[0].v.s = p->user;
  t = fmt(SD_MSG_UI_PROMPT_CHANGE_INTRO, a, 1);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_TEXT_BASE, t, SS_NOPREFIX);
  sd_free(t);
  if (e == SD_OK) e = add_profile_line(d, p);
  if (e == SD_OK) e = add_field(d, sd_l10n_get(SD_MSG_UI_PROMPT_FIELD_CURRENT), 0, 1);
  if (e == SD_OK) e = add_field(d, sd_l10n_get(SD_MSG_UI_PROMPT_FIELD_NEW), 1, 1);
  if (e == SD_OK) e = add_field(d, sd_l10n_get(SD_MSG_UI_PROMPT_FIELD_RETYPE), 2, 1);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_ERR, L"", 0);
  if (e == SD_OK) e = add_deadline(d, p);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CHANGE);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, IDOK);
  return e;
}

static sd_err add_legacy_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];
  sd_arg a[2];
  wchar_t *t;
  sd_err e;

  a[0].name = "host"; a[0].type = SD_ARG_STR; a[0].v.s = p->host;
  a[1].name = "algorithms"; a[1].type = SD_ARG_STR; a[1].v.s = p->algorithms;
  t = fmt(SD_MSG_UI_PROMPT_LEGACY_INTRO, a, 2);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_TEXT_BASE, t, SS_NOPREFIX);
  sd_free(t);
  if (e == SD_OK) e = add_profile_line(d, p);
  if (e == SD_OK) e = add_hop_lines(d, p);
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_TEXT_BASE + 93, sd_l10n_get(SD_MSG_UI_PROMPT_LEGACY_TEXT), 0);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_ANYWAY);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, 0);
  return e;
}

static sd_err add_proxy_dialog(ui_dlg *d, const ui_prompt *p)
{
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];
  sd_arg a[3];
  wchar_t *t;
  sd_err e;

  a[0].name = "proxy_host"; a[0].type = SD_ARG_STR; a[0].v.s = p->proxy_host;
  a[1].name = "proxy_port"; a[1].type = SD_ARG_INT; a[1].v.i = p->proxy_port;
  a[2].name = "host"; a[2].type = SD_ARG_STR; a[2].v.s = p->host;
  t = fmt(SD_MSG_UI_PROMPT_PROXY_INTRO, a, 3);
  if (t == NULL)
    return SD_E_NO_MEMORY;
  e = ui_dlg_text(d, ID_P_TEXT_BASE, t, SS_NOPREFIX);
  sd_free(t);
  if (e == SD_OK) {
    a[0].name = "user"; a[0].type = SD_ARG_STR; a[0].v.s = p->user;
    t = fmt(SD_MSG_UI_PROMPT_PROXY_USER, a, 1);
    if (t == NULL)
      return SD_E_NO_MEMORY;
    e = ui_dlg_text(d, ID_P_TEXT_BASE + 92, t, SS_NOPREFIX);
    sd_free(t);
  }
  if (e == SD_OK) e = add_profile_line(d, p);
  if (e == SD_OK) e = add_field(d, sd_l10n_get(SD_MSG_UI_PROMPT_FIELD_PROXY), 0, 1);
  if (e == SD_OK && p->can_save)
    e = ui_dlg_check(d, ID_P_SAVE, sd_l10n_get(SD_MSG_UI_PROMPT_CHECK_SAVE));
  if (e == SD_OK) e = ui_dlg_text(d, ID_P_ERR, L"", 0);
  if (e == SD_OK) e = add_deadline(d, p);
  texts[0] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CONNECT);
  texts[1] = sd_l10n_get(SD_MSG_UI_PROMPT_BTN_CANCEL);
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 2, IDOK);
  return e;
}

/* Title of the dialog (formatted by the kind's own placeholders). */
static wchar_t *dialog_title(const ui_prompt *p)
{
  sd_arg a[2];
  switch (p->kind) {
  case UI_PK_HOSTKEY:
    return fmt(SD_MSG_UI_PROMPT_TITLE_HOSTKEY, NULL, 0);
  case UI_PK_HOSTKEY_CHANGED:
    return fmt(SD_MSG_UI_PROMPT_TITLE_CHANGED, NULL, 0);
  case UI_PK_PASSPHRASE:
  case UI_PK_PROXY_PASSWORD:
    a[0].name = "profile"; a[0].type = SD_ARG_STR; a[0].v.s = p->profile;
    return fmt(p->kind == UI_PK_PASSPHRASE ? SD_MSG_UI_PROMPT_TITLE_PASSPHRASE : SD_MSG_UI_PROMPT_TITLE_PROXY, a, 1);
  case UI_PK_KBDINT:
  case UI_PK_PASSWORD:
  case UI_PK_PASSWORD_CHANGE:
  case UI_PK_LEGACY_ACK:
    a[0].name = "host"; a[0].type = SD_ARG_STR; a[0].v.s = p->host;
    return fmt(p->kind == UI_PK_PASSWORD ? SD_MSG_UI_PROMPT_TITLE_PASSWORD
             : p->kind == UI_PK_KBDINT ? SD_MSG_UI_PROMPT_TITLE_KBDINT
             : p->kind == UI_PK_PASSWORD_CHANGE ? SD_MSG_UI_PROMPT_TITLE_CHANGE
             : SD_MSG_UI_PROMPT_TITLE_LEGACY, a, 1);
  default:
    return NULL;
  }
}

static sd_err build_dialog(const ui_prompt *p, ui_dlg *d, unsigned char **blob, size_t *len)
{
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points;
  int dpi;
  ui_measure m;
  wchar_t *title;
  sd_err e;

  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  title = dialog_title(p);
  e = ui_dlg_init(d, title ? title : L"ShellDrive", UI_PROMPT_WIDTH, face, points, ui_measure_cb, &m);
  if (e == SD_OK) {
    switch (p->kind) {
    case UI_PK_HOSTKEY:
      e = add_hostkey_dialog(d, p);
      break;
    case UI_PK_HOSTKEY_CHANGED:
      e = add_changed_dialog(d, p);
      break;
    case UI_PK_PASSWORD:
      e = add_password_dialog(d, p, 0);
      break;
    case UI_PK_PASSPHRASE:
      e = add_password_dialog(d, p, 1);
      break;
    case UI_PK_KBDINT:
      e = add_kbdint_dialog(d, p);
      break;
    case UI_PK_PASSWORD_CHANGE:
      e = add_password_change_dialog(d, p);
      break;
    case UI_PK_LEGACY_ACK:
      e = add_legacy_dialog(d, p);
      break;
    case UI_PK_PROXY_PASSWORD:
      e = add_proxy_dialog(d, p);
      break;
    default:
      e = SD_E_INVALID_PARAM;
      break;
    }
  }
  sd_free(title);
  ui_measure_free(&m);
  if (e == SD_OK)
    e = ui_dlg_build(d, blob, len);
  return e;
}

/* ---- the open list ---- */

static void list_add(ui_pdlg *pd)
{
  if (g_nopen < UI_PROMPT_MAX_OPEN)
    g_open[g_nopen++] = pd;
}

static void list_remove(ui_pdlg *pd)
{
  size_t i;
  for (i = 0; i < g_nopen; i++) {
    if (g_open[i] == pd) {
      memmove(&g_open[i], &g_open[i + 1], (g_nopen - i - 1) * sizeof(g_open[0]));
      g_nopen--;
      return;
    }
  }
}

static ui_pdlg *find_by_id(const char *prompt_id)
{
  size_t i;
  for (i = 0; i < g_nopen; i++)
    if (strcmp(g_open[i]->p->prompt_id, prompt_id) == 0)
      return g_open[i];
  return NULL;
}

/* ---- responses ---- */

static int read_edit(HWND edit, wchar_t **out)
{
  int n;
  wchar_t *buf;
  *out = NULL;
  n = GetWindowTextLengthW(edit);
  if (n < 0 || n > UI_PROMPT_TEXT_MAX)
    return 0;
  buf = (wchar_t *)sd_calloc((size_t)n + 2, sizeof(wchar_t));
  if (buf == NULL)
    return 0;
  GetWindowTextW(edit, buf, n + 1);
  *out = buf;
  return 1;
}

static void set_err(ui_pdlg *pd, sd_msg_id id)
{
  if (pd->err != NULL)
    SetWindowTextW(pd->err, sd_l10n_get(id));
}

static void destroy_dialog(ui_pdlg *pd)
{
  if (!pd->closing) {
    pd->closing = 1;
    DestroyWindow(pd->hwnd);
  }
}

/* Sends one answer for the prompt and closes the dialog when it is queued. action: accept, once, answer,
   reject or cancel. For answer the edits are read and checked here. */
static void submit(ui_pdlg *pd, const char *action)
{
  wchar_t *resp[UI_PROMPT_MAX_ITEMS + 1];
  size_t n = 0, i, want = 0;
  int save = 0;
  char *json = NULL;
  size_t json_len = 0;
  sd_err e;
  int ok = 1;

  if (pd->closing)
    return;
  memset(resp, 0, sizeof(resp));
  if (strcmp(action, "answer") == 0) {
    if (pd->p->kind == UI_PK_PASSWORD_CHANGE)
      want = 3;
    else
      want = pd->nedits;
    if (want == 0 || pd->nedits < want) {
      /* prompts with no field (should not happen): nothing to answer, so reject */
      action = "reject";
    } else {
      for (i = 0; i < want && ok; i++) {
        if (!read_edit(pd->edits[i], &resp[i]))
          ok = 0;
        else if (resp[i] == NULL || resp[i][0] == 0)
          ok = 0;
        n++;
      }
      if (ok && pd->p->kind == UI_PK_PASSWORD_CHANGE && wcscmp(resp[1], resp[2]) != 0)
        ok = 0;
      if (!ok) {
        for (i = 0; i < n; i++) {
          if (resp[i] != NULL)
            ui_secret_free(resp[i], sizeof(wchar_t) * (wcslen(resp[i]) + 2));
          resp[i] = NULL;
        }
        if (pd->p->kind == UI_PK_PASSWORD_CHANGE && pd->edits[1] != NULL && pd->edits[2] != NULL) {
          SetWindowTextW(pd->edits[2], L"");
          SetWindowTextW(pd->edits[1], L"");
          SetFocus(pd->edits[1]);
          set_err(pd, SD_MSG_UI_PROMPT_MISMATCH);
        } else {
          set_err(pd, SD_MSG_UI_PROMPT_EMPTY);
        }
        return;
      }
    }
  }
  if (pd->save != NULL && IsDlgButtonChecked(pd->hwnd, ID_P_SAVE) == BST_CHECKED)
    save = 1;

  /* wipes the response buffers on every path */
  e = ui_prompt_build_answer(pd->p->prompt_id, action, resp, strcmp(action, "answer") == 0 ? n : 0, save,
                             &json, &json_len);
  for (i = 0; i < n; i++) {
    if (resp[i] != NULL)
      ui_secret_free(resp[i], sizeof(wchar_t) * (wcslen(resp[i]) + 2));
  }
  if (e != SD_OK || json == NULL) {
    SD_LOGW("ui", "prompt answer not built (%s)", sd_err_name(e));
    set_err(pd, SD_MSG_UI_PROMPT_SEND_FAILED);
    return;
  }
  e = ui_ipc_answer(json, json_len);
  ui_secret_free(json, json_len + 1);
  if (e != SD_OK) {
    set_err(pd, SD_MSG_UI_PROMPT_SEND_FAILED);
    return;
  }
  for (i = 0; i < pd->nedits; i++)
    SetWindowTextW(pd->edits[i], L"");
  destroy_dialog(pd);
}

/* Cancel from the window: reject for trust decisions, cancel for the other kinds (03 §2.5). */
static void cancel_action(ui_pdlg *pd)
{
  submit(pd, (pd->p->kind == UI_PK_HOSTKEY || pd->p->kind == UI_PK_HOSTKEY_CHANGED ||
              pd->p->kind == UI_PK_LEGACY_ACK) ? "reject" : "cancel");
}

static void primary_action(ui_pdlg *pd)
{
  switch (pd->p->kind) {
  case UI_PK_HOSTKEY:
    submit(pd, "accept");
    break;
  case UI_PK_HOSTKEY_CHANGED:
    cancel_action(pd);
    break;
  case UI_PK_LEGACY_ACK:
    submit(pd, "accept");
    break;
  case UI_PK_KBDINT:
    if (pd->p->item_count == 0)
      submit(pd, "reject");
    else
      submit(pd, "answer");
    break;
  default:
    submit(pd, "answer");
    break;
  }
}

/* ---- deadline text ---- */

static void refresh_deadline(ui_pdlg *pd)
{
  long long left;
  uint64_t now;
  long long minutes;
  wchar_t *t;
  if (pd->deadline == NULL)
    return;
  now = sd_tick_ms();
  left = pd->deadline_at > now ? (long long)(pd->deadline_at - now) : 0;
  if (left < 0)
    left = 0;
  minutes = ((long long)left + 59999) / 60000;
  if (minutes < 1)
    minutes = 1;
  t = ui_format_count(SD_MSG_UI_PROMPT_DEADLINE, minutes);
  if (t != NULL) {
    SetWindowTextW(pd->deadline, t);
    sd_free(t);
  }
}

/* ---- dialog procedure ---- */

static void place_dialog(ui_pdlg *pd)
{
  RECT r;
  int k = (int)(g_nopen % 5);                 /* g_nopen counts the other dialogs (this one is not listed yet) */
  if (GetWindowRect(pd->hwnd, &r)) {
    OffsetRect(&r, k * UI_PROMPT_CASCADE, k * UI_PROMPT_CASCADE);
    SetWindowPos(pd->hwnd, HWND_TOP, r.left, r.top, 0, 0, SWP_NOSIZE);
  }
}

static INT_PTR CALLBACK prompt_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  ui_pdlg *pd = (ui_pdlg *)GetWindowLongPtrW(hwnd, DWLP_USER);
  switch (msg) {
  case WM_INITDIALOG: {
    size_t i;
    pd = (ui_pdlg *)lp;
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)pd);
    pd->hwnd = hwnd;
    pd->nedits = pd->p->kind == UI_PK_PASSWORD_CHANGE ? 3
               : pd->p->kind == UI_PK_KBDINT ? pd->p->item_count
               : (pd->p->kind == UI_PK_HOSTKEY || pd->p->kind == UI_PK_HOSTKEY_CHANGED ||
                  pd->p->kind == UI_PK_LEGACY_ACK) ? 0 : 1;
    if (pd->p->kind == UI_PK_KBDINT && pd->nedits > UI_PROMPT_MAX_ITEMS)
      pd->nedits = UI_PROMPT_MAX_ITEMS;
    for (i = 0; i < pd->nedits; i++)
      pd->edits[i] = GetDlgItem(hwnd, ID_P_EDIT_BASE + (int)i);
    pd->save = GetDlgItem(hwnd, ID_P_SAVE);
    pd->err = GetDlgItem(hwnd, ID_P_ERR);
    pd->deadline = GetDlgItem(hwnd, ID_P_DEADLINE);
    if (pd->p->has_deadline)
      pd->deadline_at = sd_tick_ms() + (uint64_t)pd->p->deadline_ms;
    if (pd->deadline != NULL)
      SetTimer(hwnd, TIMER_REFRESH, UI_PROMPT_REFRESH_MS, NULL);
    place_dialog(pd);
    if (pd->p->kind == UI_PK_HOSTKEY) {
      HWND fp = GetDlgItem(hwnd, ID_P_FP);
      if (fp != NULL)
        SetFocus(fp);
    } else if (pd->nedits > 0 && pd->edits[0] != NULL) {
      SetFocus(pd->edits[0]);
    } else {
      SetFocus(GetDlgItem(hwnd, IDCANCEL));
    }
    return FALSE;
  }
  case WM_COMMAND:
    if (pd == NULL)
      break;
    switch (LOWORD(wp)) {
    case IDOK:
      primary_action(pd);
      return TRUE;
    case IDCANCEL:
      cancel_action(pd);
      return TRUE;
    case ID_P_BTN_ONCE:
      submit(pd, "once");
      return TRUE;
    default:
      break;
    }
    break;
  case WM_TIMER:
    if (pd != NULL && wp == TIMER_REFRESH)
      refresh_deadline(pd);
    return TRUE;
  case WM_CLOSE:
    if (pd != NULL)
      cancel_action(pd);
    return TRUE;
  case WM_DESTROY:
    if (pd != NULL) {
      size_t i;
      KillTimer(hwnd, TIMER_REFRESH);
      for (i = 0; i < pd->nedits; i++) {
        if (pd->edits[i] != NULL)
          SetWindowTextW(pd->edits[i], L"");   /* the edit text is cleared; see the file comment */
      }
      list_remove(pd);
      pd->hwnd = NULL;
    }
    return TRUE;
  case WM_NCDESTROY:
    if (pd != NULL) {
      SetWindowLongPtrW(hwnd, DWLP_USER, 0);
      sd_secure_free(pd->p, sizeof(*pd->p));
      sd_free(pd);
    }
    return TRUE;
  default:
    break;
  }
  return FALSE;
}

/* ---- creation ---- */

static sd_err create_dialog(ui_prompt *p, int show, HWND *out)
{
  ui_dlg *d;                         /* about 40 KB: on the heap, not the stack */
  unsigned char *blob = NULL;
  size_t blob_len = 0;
  ui_pdlg *pd;
  HWND hwnd;
  sd_err e;

  *out = NULL;
  pd = (ui_pdlg *)sd_calloc(1, sizeof(*pd));
  if (pd == NULL)
    return SD_E_NO_MEMORY;
  pd->p = p;
  d = (ui_dlg *)sd_calloc(1, sizeof(*d));
  if (d == NULL) {
    sd_free(pd);
    return SD_E_NO_MEMORY;
  }
  e = build_dialog(p, d, &blob, &blob_len);
  sd_free(d);
  if (e != SD_OK) {
    sd_free(pd);
    return e;
  }
  hwnd = CreateDialogIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, NULL, prompt_proc, (LPARAM)pd);
  sd_free(blob);
  if (hwnd == NULL) {
    sd_free(pd);
    return SD_E_FAILURE;
  }
  list_add(pd);
  *out = hwnd;
  if (show) {
    ShowWindow(hwnd, SW_SHOWNORMAL);
    if (GetForegroundWindow() != hwnd) {
      FLASHWINFO fi;
      memset(&fi, 0, sizeof(fi));
      fi.cbSize = sizeof(fi);
      fi.hwnd = hwnd;
      fi.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
      fi.uCount = 3;
      FlashWindowEx(&fi);
    }
  }
  return SD_OK;
}

/* ---- public ---- */

void ui_prompt_on_request(const sd_json *data)
{
  ui_prompt *p;
  sd_err e;
  HWND hwnd;
  if (data == NULL)
    return;
  p = (ui_prompt *)sd_calloc(1, sizeof(*p));
  if (p == NULL)
    return;
  e = ui_prompt_parse(data, p);
  if (e != SD_OK) {
    SD_LOGW("ui", "prompt.request rejected (%s)", sd_err_name(e));
    sd_secure_free(p, sizeof(*p));
    return;
  }
  if (find_by_id(p->prompt_id) != NULL) {
    /* the agent sends a prompt again after a reconnect: the open dialog stays */
    sd_secure_free(p, sizeof(*p));
    return;
  }
  if (g_nopen >= UI_PROMPT_MAX_OPEN) {
    SD_LOGW("ui", "too many open prompts: %s left to its deadline", p->prompt_id);
    sd_secure_free(p, sizeof(*p));
    return;
  }
  e = create_dialog(p, 1, &hwnd);
  if (e != SD_OK) {
    SD_LOGW("ui", "prompt dialog not created (%s)", sd_err_name(e));
    sd_secure_free(p, sizeof(*p));
  }
}

void ui_prompt_on_closed(const char *prompt_id, const char *reason)
{
  ui_pdlg *pd = prompt_id ? find_by_id(prompt_id) : NULL;
  if (pd == NULL)
    return;
  if (reason != NULL && strcmp(reason, "timeout") == 0)
    ui_tray_notify_msg(SD_MSG_UI_PROMPT_TIMEOUT, "profile", pd->p->profile);
  destroy_dialog(pd);
}

void ui_prompt_on_list(const sd_json *result)
{
  size_t i, n;
  const sd_json *arr = sd_json_get(result, "prompts");
  size_t k;
  n = sd_json_count(arr);
  /* close the dialogs whose prompts the agent no longer holds (answered elsewhere, expired while away) */
  for (k = g_nopen; k > 0; k--) {
    ui_pdlg *pd = g_open[k - 1];
    int listed = 0;
    for (i = 0; i < n && !listed; i++) {
      const char *id = sd_json_get_str(sd_json_at(arr, i), "prompt_id");
      if (id != NULL && strcmp(id, pd->p->prompt_id) == 0)
        listed = 1;
    }
    if (!listed)
      destroy_dialog(pd);
  }
}

void ui_prompt_close_all(void)
{
  while (g_nopen > 0) {
    ui_pdlg *pd = g_open[g_nopen - 1];
    destroy_dialog(pd);
    if (g_nopen > 0 && g_open[g_nopen - 1] == pd)
      list_remove(pd);                       /* DestroyWindow did not reach WM_DESTROY: never loop */
  }
}

size_t ui_prompt_count(void)
{
  return g_nopen;
}

int ui_prompt_filter(MSG *msg)
{
  size_t i;
  for (i = 0; i < g_nopen; i++) {
    if (g_open[i]->hwnd != NULL && IsDialogMessageW(g_open[i]->hwnd, msg))
      return 1;
  }
  return 0;
}

/* Smoke test (--test-prompts): every kind is built and its dialog created hidden, then destroyed. */
int ui_prompt_smoke_test(void)
{
  static const ui_prompt_kind kinds[] = {
    UI_PK_HOSTKEY, UI_PK_HOSTKEY_CHANGED, UI_PK_PASSWORD, UI_PK_PASSPHRASE, UI_PK_KBDINT,
    UI_PK_PASSWORD_CHANGE, UI_PK_LEGACY_ACK, UI_PK_PROXY_PASSWORD
  };
  size_t k;
  int ok = 1;
  for (k = 0; k < SD_COUNTOF(kinds); k++) {
    ui_prompt *p = (ui_prompt *)sd_calloc(1, sizeof(*p));
    HWND hwnd = NULL;
    if (p == NULL)
      return 0;
    ui_prompt_fixture(kinds[k], p);
    if (create_dialog(p, 0, &hwnd) != SD_OK || hwnd == NULL || !IsWindow(hwnd)) {
      ok = 0;
      sd_secure_free(p, sizeof(*p));
      continue;
    }
    DestroyWindow(hwnd);
  }
  return ok;
}
