/* shelldrive-ui: the import dialog (03 §3.7, §7.5): PuTTY sessions or the OpenSSH config file, read by sd_config's
 * importers, shown as a preview with one check box per connection. Candidates that already exist are unchecked
 * (sd_import_mark_duplicates); entries the importer skipped are listed with the reason and cannot be checked.
 * Nothing is written until "Import" (sd_import_write), then the profiles are read again and the agent is told. */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_import.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dlg.h"
#include "ui_int.h"
#include "ui_measure.h"

#define IMP_WIDTH      340
#define IMP_LIST       1600            /* the list view (created over the placeholder edit) */
#define IMP_PUTTY      1601
#define IMP_OPENSSH    1602
#define IMP_RUN        1603
#define IMP_SKIP_BIT   0x80000000u     /* LVITEM lParam: a skipped entry, low bits = its index */
#define IMP_COLS       4

typedef struct imp_ctx {
  HWND dlg;
  HWND list;
  sd_import_result res;
  int loaded;
} imp_ctx;

static void set_list_columns(HWND list)
{
  static const sd_msg_id titles[IMP_COLS] = { SD_MSG_UI_IMPORT_COL_NAME, SD_MSG_UI_IMPORT_COL_SERVER,
                                              SD_MSG_UI_IMPORT_COL_USER, SD_MSG_UI_IMPORT_COL_NOTE };
  static const int widths[IMP_COLS] = { 120, 120, 70, 150 };
  int i;
  for (i = 0; i < IMP_COLS; i++) {
    LVCOLUMNW col;
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = (LPWSTR)sd_l10n_get(titles[i]);
    col.cx = widths[i];
    col.iSubItem = i;
    SendMessageW(list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
}

/* One row: the cells of the candidate or the skipped entry, and its check state. */
static void add_row(HWND list, int row, const wchar_t *cells[IMP_COLS], LPARAM tag, int checked, int checkable)
{
  LVITEMW it;
  int j;
  memset(&it, 0, sizeof(it));
  it.mask = LVIF_TEXT | LVIF_PARAM;
  it.iItem = row;
  it.lParam = tag;
  it.pszText = (LPWSTR)cells[0];
  SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&it);
  for (j = 1; j < IMP_COLS; j++) {
    LVITEMW sub;
    memset(&sub, 0, sizeof(sub));
    sub.iItem = row;
    sub.iSubItem = j;
    sub.pszText = (LPWSTR)cells[j];
    SendMessageW(list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&sub);
  }
  if (checkable)
    ListView_SetCheckState(list, row, checked);
}

/* Fills the list from the importer result: candidates first (checked when selected), then the skipped entries. */
static void fill_list(imp_ctx *c)
{
  uint32_t i;
  int row = 0;
  SendMessageW(c->list, LVM_DELETEALLITEMS, 0, 0);
  for (i = 0; i < c->res.count; i++) {
    const sd_import_candidate *cand = &c->res.items[i];
    wchar_t name[160], server[300], user[160], note[200];
    const wchar_t *cells[IMP_COLS];
    wchar_t host[256];
    note[0] = 0;
    ui_text_utf8(cand->p.name, name, SD_COUNTOF(name));
    ui_text_utf8(cand->p.host, host, SD_COUNTOF(host));
    wcsncpy_s(server, SD_COUNTOF(server), host, _TRUNCATE);
    if (cand->p.port != 22 && cand->p.port != 0) {
      wchar_t num[12];
      wsprintfW(num, L":%u", (unsigned)cand->p.port);
      wcscat_s(server, SD_COUNTOF(server), num);
    }
    ui_text_utf8(cand->p.user, user, SD_COUNTOF(user));
    if (cand->flags & SD_IMPORT_F_DUPLICATE)
      wcscpy_s(note, SD_COUNTOF(note), sd_l10n_get(SD_MSG_UI_IMPORT_NOTE_DUPLICATE));
    else if (cand->flags & SD_IMPORT_F_ONLY_THIS_KEY)
      wcscpy_s(note, SD_COUNTOF(note), sd_l10n_get(SD_MSG_UI_IMPORT_NOTE_ONLY_KEY));
    cells[0] = name;
    cells[1] = server;
    cells[2] = user;
    cells[3] = note;
    add_row(c->list, row, cells, (LPARAM)i, cand->selected, 1);
    row++;
  }
  for (i = 0; i < c->res.nskipped; i++) {
    const sd_import_skip *sk = &c->res.skipped[i];
    wchar_t src[160], item[160], note[240];
    const wchar_t *cells[IMP_COLS];
    sd_arg a[1];
    wchar_t *formatted;
    ui_text_utf8(sk->source, src, SD_COUNTOF(src));
    ui_text_utf8(sk->item, item, SD_COUNTOF(item));
    a[0].name = "item";
    a[0].type = SD_ARG_STR;
    a[0].v.s = item;
    formatted = sd_l10n_format_alloc(SD_MSG_UI_IMPORT_NOTE_SKIPPED, a, 1);
    wcsncpy_s(note, SD_COUNTOF(note), formatted ? formatted : L"", _TRUNCATE);
    sd_free(formatted);
    cells[0] = src;
    cells[1] = L"";
    cells[2] = L"";
    cells[3] = note;
    add_row(c->list, row, cells, (LPARAM)(IMP_SKIP_BIT | i), 0, 0);
    row++;
  }
}

/* Reads the chosen source into c->res. */
static void load_source(imp_ctx *c, int putty)
{
  sd_import_env env;
  sd_err e;
  sd_import_result_free(&c->res);
  sd_import_result_init(&c->res);
  memset(&env, 0, sizeof(env));
  if (putty)
    e = sd_import_putty_registry(HKEY_CURRENT_USER, NULL, &c->res);
  else
    e = sd_import_ssh_config_file(NULL, &env, &c->res);
  if (e != SD_OK && c->res.count == 0 && c->res.nskipped == 0) {
    MessageBoxW(c->dlg, sd_l10n_get(putty ? SD_MSG_UI_IMPORT_ERROR_PUTTY : SD_MSG_UI_IMPORT_ERROR_OPENSSH),
                L"ShellDrive", MB_OK | MB_ICONWARNING);
    c->loaded = 0;
    SendMessageW(c->list, LVM_DELETEALLITEMS, 0, 0);
    return;
  }
  sd_import_mark_duplicates(&c->res, NULL);
  c->loaded = 1;
  fill_list(c);
}

/* Writes the checked candidates (sd_import_write) and reloads the profiles. */
static int import_checked(imp_ctx *c)
{
  int count = ListView_GetItemCount(c->list), row;
  uint32_t written = 0;
  sd_err e;
  if (!c->loaded)
    return 0;
  for (row = 0; row < count; row++) {
    LVITEMW it;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_PARAM;
    it.iItem = row;
    SendMessageW(c->list, LVM_GETITEMW, 0, (LPARAM)&it);
    if (!(it.lParam & (LPARAM)IMP_SKIP_BIT) && (uint32_t)it.lParam < c->res.count)
      c->res.items[it.lParam].selected = ListView_GetCheckState(c->list, row) ? 1 : 0;
  }
  e = sd_import_write(&c->res, &written);
  if (e != SD_OK && written == 0) {
    MessageBoxW(c->dlg, sd_l10n_get(SD_MSG_UI_ERROR_SAVE), L"ShellDrive", MB_OK | MB_ICONERROR);
    return 0;
  }
  if (written > 0) {
    ui_main_reload_profiles();
    ui_ipc_config_reload();
  }
  return 1;
}

static INT_PTR CALLBACK import_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  imp_ctx *c = (imp_ctx *)GetWindowLongPtrW(hwnd, DWLP_USER);
  switch (msg) {
  case WM_INITDIALOG: {
    RECT rc;
    HWND placeholder = GetDlgItem(hwnd, IMP_LIST);
    c = (imp_ctx *)lp;
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)c);
    c->dlg = hwnd;
    if (placeholder == NULL)
      return FALSE;
    GetWindowRect(placeholder, &rc);
    MapWindowPoints(NULL, hwnd, (LPPOINT)&rc, 2);
    DestroyWindow(placeholder);
    c->list = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                              rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, hwnd,
                              (HMENU)(UINT_PTR)IMP_LIST, g_app.inst, NULL);
    if (c->list == NULL)
      return FALSE;
    SendMessageW(c->list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
    set_list_columns(c->list);
    SendMessageW(c->list, WM_SETFONT, SendMessageW(hwnd, WM_GETFONT, 0, 0), MAKELPARAM(TRUE, 0));
    return TRUE;
  }
  case WM_COMMAND:
    if (c == NULL)
      break;
    switch (LOWORD(wp)) {
    case IMP_PUTTY:
      load_source(c, 1);
      return TRUE;
    case IMP_OPENSSH:
      load_source(c, 0);
      return TRUE;
    case IMP_RUN:
      if (import_checked(c))
        EndDialog(hwnd, IDOK);
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

void ui_import_run(HWND owner)
{
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96;
  ui_measure m;
  ui_dlg *d;
  unsigned char *blob = NULL;
  size_t len = 0;
  imp_ctx c;
  sd_err e;
  static const WORD src_ids[2] = { IMP_PUTTY, IMP_OPENSSH };
  static const WORD run_ids[2] = { IMP_RUN, IDCANCEL };
  const wchar_t *src_texts[2];
  const wchar_t *run_texts[2];

  memset(&c, 0, sizeof(c));
  sd_import_result_init(&c.res);
  d = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
  if (d == NULL)
    return;
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  src_texts[0] = sd_l10n_get(SD_MSG_UI_IMPORT_PUTTY);
  src_texts[1] = sd_l10n_get(SD_MSG_UI_IMPORT_OPENSSH);
  run_texts[0] = sd_l10n_get(SD_MSG_UI_IMPORT_RUN);
  run_texts[1] = sd_l10n_get(SD_MSG_UI_IMPORT_CLOSE);
  e = ui_dlg_init(d, sd_l10n_get(SD_MSG_UI_IMPORT_TITLE), IMP_WIDTH, face, points, ui_measure_cb, &m);
  if (e == SD_OK) e = ui_dlg_text(d, 0, sd_l10n_get(SD_MSG_UI_IMPORT_INTRO), 0);
  if (e == SD_OK) e = ui_dlg_buttons(d, src_ids, src_texts, 2, 0);
  /* eleven line breaks: the placeholder is as tall as the list view that replaces it (12 lines) */
  if (e == SD_OK) e = ui_dlg_multiline(d, IMP_LIST, L"\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n", 12);
  if (e == SD_OK) e = ui_dlg_buttons(d, run_ids, run_texts, 2, IMP_RUN);
  if (e == SD_OK) e = ui_dlg_build(d, &blob, &len);
  ui_measure_free(&m);
  sd_free(d);
  if (e == SD_OK && blob != NULL)
    DialogBoxIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, owner, import_proc, (LPARAM)&c);
  sd_free(blob);
  sd_import_result_free(&c.res);
  ui_main_refresh();
}
