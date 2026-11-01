/* shelldrive-ui: a changed host key and a wrong host key type (03 §5.2, §5.4, TM-R04).
 *
 * A failed mount whose mount.state error is host_key_mismatch raises the balloon "The identity of {host} has changed.
 * ShellDrive stopped the connection." (7.7: always shown, cannot be disabled). A click opens the details dialog: the
 * stored and the offered key (type and SHA-256 fingerprint), the store and line where the old key lives, and what the
 * user can do. There is no "connect anyway": to accept the new key the user removes the old one in the host key manager
 * (which asks for a confirmation that warns about interception) and connects again, which is a first contact (5.4).
 * When the old key lives in a read-only live source (OpenSSH or PuTTY) ShellDrive cannot remove it; the dialog names
 * the file and offers "Open file location" and "Stop using keys from this source" (turns the source off in settings.ini,
 * because a mismatch in any source blocks, D7).
 *
 * host_key_type_unavailable raises its own balloon; a click opens the details dialog of 5.2: the key types stored for the
 * name next to the host key algorithms the server offered (and the key it presented, with its SHA-256 fingerprint), so a
 * key type change is always visible. Buttons: "Manage host keys..." and "Add key from server..." (opens the manager and
 * the review of the server's keys, verified inside a connection that uses the stored key). The agent sends no fingerprint
 * of the stored keys (the known_hosts type list has none), so the stored side shows types only. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "ui_dlg.h"
#include "ui_hkissue_model.h"
#include "ui_int.h"
#include "ui_measure.h"
#include "ui_win.h"

#define HKI_ID_KEYS   4501
#define HKI_ID_MANAGE 4502
#define HKI_ID_OPEN   4503
#define HKI_ID_STOP   4504
#define HKI_ID_ADD    4505
#define HKI_WIDTH     300

static ui_hki g_last;                  /* the issue the last balloon was about */

static void host_wide(const ui_hki *h, wchar_t *out, size_t cch)
{
  size_t i;
  for (i = 0; i + 1 < cch && h->host[i] != 0; i++)
    out[i] = (wchar_t)(unsigned char)h->host[i];
  out[i] = 0;
}

static int user_store_path(wchar_t *out, size_t cap)
{
  wchar_t root[MAX_PATH];
  if (sd_config_root(root, SD_COUNTOF(root)) != SD_OK || wcslen(root) + 13 >= cap)
    return 0;
  wcscpy_s(out, cap, root);
  wcscat_s(out, cap, L"\\known_hosts");
  return 1;
}

static ui_hki_source source_of(const ui_hki *h)
{
  wchar_t user[MAX_PATH];
  return ui_hki_source_of(h, user_store_path(user, SD_COUNTOF(user)) ? user : NULL);
}

static void widen_ascii(const char *s, wchar_t *out, size_t cch)
{
  size_t i;
  for (i = 0; i + 1 < cch && s[i] != 0; i++)
    out[i] = (wchar_t)(unsigned char)s[i];
  out[i] = 0;
}

/* ---- the balloons ---- */

void ui_hkissue_on_mount_state(const sd_json *data, const char *host, const wchar_t *drive)
{
  ui_hki h;
  wchar_t whost[UI_HKI_HOST_MAX];
  (void)drive;
  if (ui_hki_parse(data, host, &h) == UI_HKI_NONE)
    return;
  g_last = h;
  host_wide(&h, whost, SD_COUNTOF(whost));
  if (h.kind == UI_HKI_CHANGED) {
    ui_tray_notify_msg(SD_MSG_UI_HKI_NOTIFY_CHANGED, "host", whost);
  } else if (ui_hki_has_stored_type(&h)) {
    sd_arg a[2];
    wchar_t stored[UI_HKI_STORED_MAX * (UI_HKI_TYPE_MAX + 2)], *text;
    char list[UI_HKI_STORED_MAX * (UI_HKI_TYPE_MAX + 2)];
    if (ui_hki_stored_list(&h, list, sizeof(list)) == 0)
      strcpy_s(list, sizeof(list), h.stored_type);
    widen_ascii(list, stored, SD_COUNTOF(stored));
    a[0].name = "host";
    a[0].type = SD_ARG_STR;
    a[0].v.s = whost;
    a[1].name = "stored";
    a[1].type = SD_ARG_STR;
    a[1].v.s = stored;
    text = sd_l10n_format_alloc(SD_MSG_UI_HKI_NOTIFY_TYPE_STORED, a, 2);
    if (text != NULL) {
      ui_tray_notify_text(SD_MSG_UI_HKI_NOTIFY_TYPE_STORED, whost, text);
      sd_free(text);
    }
  } else {
    ui_tray_notify_msg(SD_MSG_UI_HKI_NOTIFY_TYPE, "host", whost);
  }
}

/* ---- the details dialog ---- */

typedef struct hki_dlg {
  ui_hki issue;
  ui_hki_source src;
} hki_dlg;

static wchar_t *fmt_type_fp(sd_msg_id id, const char *type, const char *fp)
{
  sd_arg a[2];
  wchar_t wt[UI_HKI_TYPE_MAX], wf[UI_HKI_FP_MAX];
  size_t i;
  for (i = 0; i + 1 < SD_COUNTOF(wt) && type[i] != 0; i++)
    wt[i] = (wchar_t)(unsigned char)type[i];
  wt[i] = 0;
  for (i = 0; i + 1 < SD_COUNTOF(wf) && fp[i] != 0; i++)
    wf[i] = (wchar_t)(unsigned char)fp[i];
  wf[i] = 0;
  a[0].name = "type";
  a[0].type = SD_ARG_STR;
  a[0].v.s = wt;
  a[1].name = "fp";
  a[1].type = SD_ARG_STR;
  a[1].v.s = wf;
  return sd_l10n_format_alloc(id, a, 2);
}

/* "Stored key: ..." and "Offered now: ..." as the two lines of the fingerprint edit control. */
static void key_lines(const ui_hki *h, wchar_t *out, size_t cap)
{
  wchar_t *a = fmt_type_fp(SD_MSG_UI_HKI_LINE_STORED, h->stored_type, h->stored_fp);
  wchar_t *b = fmt_type_fp(SD_MSG_UI_HKI_LINE_OFFERED, h->offered_type, h->offered_fp);
  out[0] = 0;
  if (a != NULL)
    wcscat_s(out, cap, a);
  wcscat_s(out, cap, L"\r\n");
  if (b != NULL)
    wcscat_s(out, cap, b);
  sd_free(a);
  sd_free(b);
}

static wchar_t *where_text(const ui_hki *h, ui_hki_source src)
{
  sd_arg a[2];
  switch (ui_hki_where_of(src)) {
  case UI_HKI_WHERE_USER:
  case UI_HKI_WHERE_MACHINE:
    a[0].name = "line";
    a[0].type = SD_ARG_INT;
    a[0].v.i = (long long)h->line;
    return sd_l10n_format_alloc(ui_hki_where_of(src) == UI_HKI_WHERE_USER ? SD_MSG_UI_HKI_WHERE_USER
                                                                          : SD_MSG_UI_HKI_WHERE_MACHINE, a, 1);
  case UI_HKI_WHERE_PUTTY:
    return sd_l10n_format_alloc(SD_MSG_UI_HKI_WHERE_PUTTY, NULL, 0);
  default:
    a[0].name = "path";
    a[0].type = SD_ARG_STR;
    a[0].v.s = h->path;
    a[1].name = "line";
    a[1].type = SD_ARG_INT;
    a[1].v.i = (long long)h->line;
    return sd_l10n_format_alloc(SD_MSG_UI_HKI_WHERE_FILE, a, 2);
  }
}

static sd_msg_id todo_msg(ui_hki_source src)
{
  switch (ui_hki_todo_of(src)) {
  case UI_HKI_TODO_USER:    return SD_MSG_UI_HKI_TODO_USER;
  case UI_HKI_TODO_MACHINE: return SD_MSG_UI_HKI_TODO_MACHINE;
  default:                  return SD_MSG_UI_HKI_TODO_SOURCE;
  }
}

/* Builds the template of the details dialog for an issue. Release *blob with sd_free. */
static sd_err build_dialog(const ui_hki *h, ui_hki_source src, unsigned char **blob, size_t *len)
{
  WORD ids[4];
  const wchar_t *texts[4];
  size_t nb = 0;
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96;
  ui_measure m;
  wchar_t whost[UI_HKI_HOST_MAX];
  wchar_t lines[2 * (UI_HKI_TYPE_MAX + UI_HKI_FP_MAX + 64) + 8];
  wchar_t *intro, *where;
  sd_arg a[1];
  ui_dlg *d = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
  sd_err e;
  if (d == NULL)
    return SD_E_NO_MEMORY;
  host_wide(h, whost, SD_COUNTOF(whost));
  a[0].name = "host";
  a[0].type = SD_ARG_STR;
  a[0].v.s = whost;
  intro = sd_l10n_format_alloc(SD_MSG_UI_HKI_INTRO, a, 1);
  where = where_text(h, src);
  key_lines(h, lines, SD_COUNTOF(lines));
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  ids[nb] = HKI_ID_MANAGE; texts[nb++] = sd_l10n_get(SD_MSG_UI_HKI_BTN_MANAGE);
  if (ui_hki_source_can_open(src, h->path)) {
    ids[nb] = HKI_ID_OPEN; texts[nb++] = sd_l10n_get(SD_MSG_UI_HKI_BTN_OPEN);
  }
  if (ui_hki_source_can_stop(src)) {
    ids[nb] = HKI_ID_STOP; texts[nb++] = sd_l10n_get(SD_MSG_UI_HKI_BTN_STOP);
  }
  ids[nb] = IDCANCEL; texts[nb++] = sd_l10n_get(SD_MSG_UI_HKI_BTN_CLOSE);
  e = ui_dlg_init(d, sd_l10n_get(SD_MSG_UI_HKI_TITLE), HKI_WIDTH, face, points, ui_measure_cb, &m);
  if (e == SD_OK) e = ui_dlg_text(d, 0, intro != NULL ? intro : L"", SS_NOPREFIX);
  if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_HKI_KEYS_LABEL), 0);
  if (e == SD_OK) e = ui_dlg_multiline(d, HKI_ID_KEYS, lines, 2);
  if (e == SD_OK) e = ui_dlg_space(d, 2);
  if (e == SD_OK) e = ui_dlg_text(d, 0, where != NULL ? where : L"", SS_NOPREFIX);
  if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(todo_msg(src)), SS_NOPREFIX);
  if (e == SD_OK) e = ui_dlg_space(d, 4);
  /* the safe button, Close, is the default one: Enter never leads to a changed trust decision */
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, nb, IDCANCEL);
  if (e == SD_OK) e = ui_dlg_build(d, blob, len);
  ui_measure_free(&m);
  sd_free(d);
  sd_free(intro);
  sd_free(where);
  return e;
}

/* "Stored key types: ..." and "Offered by the server: ..." and, when the server presented a key, "Offered now: ...". */
static void type_lines(const ui_hki *h, wchar_t *out, size_t cap)
{
  char list[UI_HKI_OFFERED_MAX * (UI_HKI_TYPE_MAX + 2)];
  wchar_t wl[UI_HKI_OFFERED_MAX * (UI_HKI_TYPE_MAX + 2)];
  wchar_t *line;
  sd_arg a[1];
  out[0] = 0;
  if (ui_hki_stored_list(h, list, sizeof(list)) == 0)
    strcpy_s(list, sizeof(list), h->stored_type);
  widen_ascii(list, wl, SD_COUNTOF(wl));
  a[0].name = "types";
  a[0].type = SD_ARG_STR;
  a[0].v.s = wl[0] != 0 ? wl : sd_l10n_get(SD_MSG_UI_HKI_TYPES_NONE);
  line = sd_l10n_format_alloc(SD_MSG_UI_HKI_LINE_STORED_TYPES, a, 1);
  if (line != NULL) {
    wcscat_s(out, cap, line);
    sd_free(line);
  }
  wcscat_s(out, cap, L"\r\n");
  if (ui_hki_offered_list(h, list, sizeof(list)) == 0)
    list[0] = 0;
  widen_ascii(list, wl, SD_COUNTOF(wl));
  a[0].v.s = wl[0] != 0 ? wl : sd_l10n_get(SD_MSG_UI_HKI_TYPES_NONE);
  line = sd_l10n_format_alloc(SD_MSG_UI_HKI_LINE_OFFERED_TYPES, a, 1);
  if (line != NULL) {
    wcscat_s(out, cap, line);
    sd_free(line);
  }
  if (ui_hki_has_offered_key(h)) {
    line = fmt_type_fp(SD_MSG_UI_HKI_LINE_OFFERED, h->offered_type, h->offered_fp);
    wcscat_s(out, cap, L"\r\n");
    if (line != NULL) {
      wcscat_s(out, cap, line);
      sd_free(line);
    }
  }
}

/* Builds the template of the key type dialog (5.2). Release *blob with sd_free. */
static sd_err build_type_dialog(const ui_hki *h, unsigned char **blob, size_t *len)
{
  static const WORD ids[3] = { HKI_ID_MANAGE, HKI_ID_ADD, IDCANCEL };
  const wchar_t *texts[3];
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96;
  ui_measure m;
  wchar_t whost[UI_HKI_HOST_MAX];
  wchar_t lines[(UI_HKI_STORED_MAX + UI_HKI_OFFERED_MAX) * (UI_HKI_TYPE_MAX + 2) + 2 * (UI_HKI_TYPE_MAX + UI_HKI_FP_MAX + 64)];
  wchar_t *intro;
  sd_arg a[1];
  ui_dlg *d = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
  sd_err e;
  if (d == NULL)
    return SD_E_NO_MEMORY;
  host_wide(h, whost, SD_COUNTOF(whost));
  a[0].name = "host";
  a[0].type = SD_ARG_STR;
  a[0].v.s = whost;
  intro = sd_l10n_format_alloc(SD_MSG_UI_HKI_TYPE_INTRO, a, 1);
  type_lines(h, lines, SD_COUNTOF(lines));
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  texts[0] = sd_l10n_get(SD_MSG_UI_HKI_BTN_MANAGE);
  texts[1] = sd_l10n_get(SD_MSG_UI_HKI_BTN_ADD);
  texts[2] = sd_l10n_get(SD_MSG_UI_HKI_BTN_CLOSE);
  e = ui_dlg_init(d, sd_l10n_get(SD_MSG_UI_HKI_TYPE_TITLE), HKI_WIDTH, face, points, ui_measure_cb, &m);
  if (e == SD_OK) e = ui_dlg_text(d, 0, intro != NULL ? intro : L"", SS_NOPREFIX);
  if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_HKI_KEYS_LABEL), 0);
  if (e == SD_OK) e = ui_dlg_multiline(d, HKI_ID_KEYS, lines, 6);
  if (e == SD_OK) e = ui_dlg_space(d, 2);
  if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_HKI_TYPE_TODO), SS_NOPREFIX);
  if (e == SD_OK) e = ui_dlg_space(d, 4);
  /* Close is the default button: Enter never adds a key */
  if (e == SD_OK) e = ui_dlg_buttons(d, ids, texts, 3, IDCANCEL);
  if (e == SD_OK) e = ui_dlg_build(d, blob, len);
  ui_measure_free(&m);
  sd_free(d);
  sd_free(intro);
  return e;
}

/* "Stop using keys from this source": asks, then turns the source off in settings.ini and tells the agent. */
static void stop_source(HWND owner, ui_hki_source src)
{
  sd_settings s;
  wchar_t *text, *title;
  const wchar_t *name = src == UI_HKI_SRC_PUTTY ? L"PuTTY" : L"OpenSSH";
  sd_err e;
  int answer;
  text = ui_format1(SD_MSG_UI_HKI_STOP_CONFIRM, "source", name);
  title = ui_format1(SD_MSG_UI_HKI_STOP_TITLE, "source", name);
  if (text == NULL || title == NULL) {
    sd_free(text);
    sd_free(title);
    return;
  }
  /* No is the default button: Enter never turns a source off */
  answer = ui_win_task(owner, title, text, NULL, MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
  sd_free(text);
  sd_free(title);
  if (answer != IDYES)
    return;
  sd_settings_defaults(&s);
  (void)sd_settings_load(&s);
  if (src == UI_HKI_SRC_PUTTY)
    s.putty_source = 0;
  else
    s.openssh_source = 0;
  e = sd_settings_save(&s);
  if (e != SD_OK) {
    ui_win_error(owner, SD_MSG_UI_SETTINGS_SAVE_FAILED, e);
    return;
  }
  (void)ui_ipc_config_reload();
  text = ui_format1(SD_MSG_UI_HKI_STOP_DONE, "source", name);
  if (text != NULL) {
    ui_win_message(owner, text, MB_OK | MB_ICONINFORMATION);
    sd_free(text);
  }
}

static void open_location(HWND owner, const ui_hki *h)
{
  wchar_t args[UI_HKI_PATH_MAX + 16];
  if (ui_hki_select_args(h->path, args, SD_COUNTOF(args)))
    ShellExecuteW(owner, L"open", L"explorer.exe", args, NULL, SW_SHOWNORMAL);
}

static INT_PTR CALLBACK hki_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  hki_dlg *c = (hki_dlg *)GetWindowLongPtrW(hwnd, DWLP_USER);
  switch (msg) {
  case WM_INITDIALOG:
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)lp);
    return TRUE;
  case WM_COMMAND:
    if (c == NULL)
      break;
    switch (LOWORD(wp)) {
    case HKI_ID_MANAGE:
      EndDialog(hwnd, HKI_ID_MANAGE);
      return TRUE;
    case HKI_ID_ADD:
      EndDialog(hwnd, HKI_ID_ADD);
      return TRUE;
    case HKI_ID_OPEN:
      open_location(hwnd, &c->issue);
      return TRUE;
    case HKI_ID_STOP:
      stop_source(hwnd, c->src);
      return TRUE;
    case IDCANCEL:
      EndDialog(hwnd, IDCANCEL);
      return TRUE;
    default:
      break;
    }
    break;
  default:
    break;
  }
  return FALSE;
}

static void show_changed(const ui_hki *h)
{
  unsigned char *blob = NULL;
  size_t len = 0;
  hki_dlg c;
  INT_PTR r = IDCANCEL;
  c.issue = *h;
  c.src = source_of(h);
  if (build_dialog(h, c.src, &blob, &len) == SD_OK && blob != NULL)
    r = DialogBoxIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, g_app.main, hki_proc, (LPARAM)&c);
  sd_free(blob);
  if (r == HKI_ID_MANAGE)
    ui_hostkeys_open_for(h->host);
}

static void show_type(const ui_hki *h)
{
  unsigned char *blob = NULL;
  size_t len = 0;
  hki_dlg c;
  INT_PTR r = IDCANCEL;
  c.issue = *h;
  c.src = UI_HKI_SRC_USER;
  if (build_type_dialog(h, &blob, &len) == SD_OK && blob != NULL)
    r = DialogBoxIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, g_app.main, hki_proc, (LPARAM)&c);
  sd_free(blob);
  if (r == HKI_ID_MANAGE)
    ui_hostkeys_open_for(h->host);
  else if (r == HKI_ID_ADD)
    ui_hostkeys_add_for(h->host, ui_hki_add_target(h));
}

void ui_hkissue_open_last(void)
{
  if (g_last.kind == UI_HKI_CHANGED)
    show_changed(&g_last);
  else if (g_last.kind == UI_HKI_TYPE_UNAVAILABLE)
    show_type(&g_last);
}

/* --test-windows: the template builds and parses for every source, with and without the optional buttons. */
int ui_hkissue_smoke(void)
{
  static const ui_hki_source k_src[] = { UI_HKI_SRC_USER, UI_HKI_SRC_MACHINE, UI_HKI_SRC_OPENSSH, UI_HKI_SRC_PUTTY,
                                         UI_HKI_SRC_FILE };
  ui_hki h;
  size_t i, count = 0, offs[UI_DLG_MAX_ITEMS];
  int ok = 1;
  memset(&h, 0, sizeof(h));
  h.kind = UI_HKI_CHANGED;
  strcpy_s(h.host, sizeof(h.host), "example.org");
  strcpy_s(h.stored_type, sizeof(h.stored_type), "ssh-ed25519");
  strcpy_s(h.stored_fp, sizeof(h.stored_fp), "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG");
  strcpy_s(h.offered_type, sizeof(h.offered_type), "ssh-ed25519");
  strcpy_s(h.offered_fp, sizeof(h.offered_fp), "SHA256:ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvut");
  wcscpy_s(h.path, SD_COUNTOF(h.path), L"C:\\Users\\test\\.ssh\\known_hosts");
  h.line = 7;
  for (i = 0; i < SD_COUNTOF(k_src) && ok; i++) {
    unsigned char *blob = NULL;
    size_t len = 0;
    /* intro, label, edit, where, todo, then the buttons: Manage and Close always, Open and Stop by source */
    size_t want = 5 + 2 + (ui_hki_source_can_open(k_src[i], h.path) ? 1u : 0u) +
                  (ui_hki_source_can_stop(k_src[i]) ? 1u : 0u);
    ok = build_dialog(&h, k_src[i], &blob, &len) == SD_OK && blob != NULL &&
         ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK && count == want;
    sd_free(blob);
  }
  if (ok) {
    /* the key type dialog (5.2): without and with the key the server presented */
    unsigned char *blob = NULL;
    size_t len = 0, j;
    ui_hki t;
    memset(&t, 0, sizeof(t));
    t.kind = UI_HKI_TYPE_UNAVAILABLE;
    strcpy_s(t.host, sizeof(t.host), "example.org");
    strcpy_s(t.stored_types[0], UI_HKI_TYPE_MAX, "ssh-ed25519");
    strcpy_s(t.stored_types[1], UI_HKI_TYPE_MAX, "ssh-rsa");
    t.n_stored = 2;
    strcpy_s(t.offered_types[0], UI_HKI_TYPE_MAX, "ecdsa-sha2-nistp256");
    t.n_offered = 1;
    for (j = 0; j < 2 && ok; j++) {
      if (j == 1) {
        strcpy_s(t.offered_type, sizeof(t.offered_type), "ecdsa-sha2-nistp256");
        strcpy_s(t.offered_fp, sizeof(t.offered_fp), "SHA256:ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvut");
      }
      /* intro, label, edit, todo, then Manage, Add and Close */
      ok = build_type_dialog(&t, &blob, &len) == SD_OK && blob != NULL &&
           ui_dlg_parse_check(blob, len, &count, offs, SD_COUNTOF(offs)) == SD_OK && count == 7;
      sd_free(blob);
      blob = NULL;
    }
  }
  return ok;
}
