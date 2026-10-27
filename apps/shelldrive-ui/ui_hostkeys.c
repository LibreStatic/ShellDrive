/* shelldrive-ui: the host key manager (03 §5.1, §5.5, §5.6).
 *
 * Two tabs. "Known keys" lists the plain keys of the machine store (read-only here) and the user store, read
 * with sd_known_hosts (the same library the CLI uses, hk_list/hk_import/hk_remove in apps/shelldrive/cli_cmds2.c);
 * this window does no known_hosts file I/O of its own. Remove deletes one key from the user store after a
 * confirmation; Import copies the keys of PuTTY or of an OpenSSH known_hosts file into the user store.
 * "Announced keys" lists the UpdateHostKeys announcements the agent holds (hostkey.announced.list). Add keys
 * applies the proven additions; Add and remove also applies the removals, after a confirmation. Nothing changes
 * until the user asks for it (5.6). */
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_json.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_ssh/sd_known_hosts.h"
#include "ui_dpi.h"
#include "ui_hostkeys_model.h"
#include "ui_int.h"
#include "ui_win.h"

#define HK_ID_TAB          4201
#define HK_ID_LIST_KNOWN   4202
#define HK_ID_LIST_ANN     4203
#define HK_ID_REMOVE       4204
#define HK_ID_PUTTY        4205
#define HK_ID_OPENSSH      4206
#define HK_ID_REFRESH      4207
#define HK_ID_ADD          4208
#define HK_ID_ADDALL       4209
#define HK_ID_STATUS       4210

#define HK_TAB_KNOWN       0
#define HK_TAB_ANNOUNCED   1
#define HK_MAX_KEYS        65536u
#define HK_MAX_ANN         1024u
#define HK_ANN_ID_MAX      64
#define HK_CLIENT_W        760
#define HK_CLIENT_H        460

typedef struct hk_entry {
  ui_hk_row row;
  uint8_t *blob;                     /* public key blob, for sd_known_hosts_remove_key */
  size_t blen;
} hk_entry;

typedef struct hk_ann {
  char id[HK_ANN_ID_MAX];            /* announcement id, echoed back to hostkey.announced.accept */
  char host[UI_HK_HOST_MAX];
  int add;                           /* 1: key to add, 0: key to remove */
  char type[UI_HK_TYPE_MAX];
  char fp[UI_HK_FP_MAX];
} hk_ann;

static struct {
  HWND wnd, tab, list_known, list_ann, status;
  HWND btn_remove, btn_putty, btn_openssh, btn_refresh, btn_add, btn_addall;
  HFONT font;
  unsigned dpi;
  hk_entry *keys;
  size_t nkeys, capkeys;
  hk_ann *anns;
  size_t nanns, capanns;
  int ann_wait;                      /* hostkey.announced.list in flight */
  int accept_wait;                   /* hostkey.announced.accept in flight */
  wchar_t accept_host[UI_HK_HOST_MAX];
} g_hk;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_hk.dpi);
}

static void status_text(const wchar_t *text)
{
  if (g_hk.status)
    SetWindowTextW(g_hk.status, text ? text : L"");
}

static void status_msg(sd_msg_id id)
{
  status_text(sd_l10n_get(id));
}

static void status_count(sd_msg_id id, size_t n)
{
  wchar_t *t = ui_format_count(id, (long long)n);
  if (t != NULL) {
    status_text(t);
    sd_free(t);
  }
}

static int sel_index(HWND list)
{
  if (list == NULL)
    return -1;
  return (int)SendMessageW(list, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
}

static LPARAM item_param(HWND list, int idx)
{
  LVITEMW it;
  memset(&it, 0, sizeof(it));
  it.mask = LVIF_PARAM;
  it.iItem = idx;
  if (!SendMessageW(list, LVM_GETITEMW, 0, (LPARAM)&it))
    return -1;
  return it.lParam;
}

static void insert_row(HWND list, int row, wchar_t cells[][UI_HK_CELL_MAX], int ncols, LPARAM param)
{
  LVITEMW it;
  int j;
  memset(&it, 0, sizeof(it));
  it.mask = LVIF_TEXT | LVIF_PARAM;
  it.iItem = row;
  it.pszText = cells[0];
  it.lParam = param;
  SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&it);
  for (j = 1; j < ncols; j++) {
    LVITEMW sub;
    memset(&sub, 0, sizeof(sub));
    sub.iSubItem = j;
    sub.pszText = cells[j];
    SendMessageW(list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&sub);
  }
}

static void set_columns(void)
{
  static const int known_w[UI_HK_CELLS] = { 170, 50, 90, 250, 130 };
  static const int ann_w[4] = { 170, 120, 90, 250 };
  int i;
  if (g_hk.list_known)
    for (i = 0; i < UI_HK_CELLS; i++)
      SendMessageW(g_hk.list_known, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(known_w[i]));
  if (g_hk.list_ann)
    for (i = 0; i < 4; i++)
      SendMessageW(g_hk.list_ann, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(ann_w[i]));
}

/* ---- known_hosts access (sd_known_hosts, the stores of 5.1) ---- */

static int user_store_path(wchar_t *out, size_t cap)
{
  wchar_t root[MAX_PATH];
  if (sd_config_root(root, SD_COUNTOF(root)) != SD_OK)
    return 0;
  if (wcslen(root) + 13 >= cap)
    return 0;
  wcscpy_s(out, cap, root);
  wcscat_s(out, cap, L"\\known_hosts");
  return 1;
}

/* Opens the machine store (read-only), the user store (writable) and, when extra is set, one source. */
static sd_known_hosts *open_stores(int with_machine, sd_kh_store_kind extra, const wchar_t *extra_path)
{
  sd_kh_store stores[3];
  uint32_t n = 0;
  sd_known_hosts *kh = NULL;
  static wchar_t user_kh[MAX_PATH];
  if (!user_store_path(user_kh, SD_COUNTOF(user_kh)))
    return NULL;
  memset(stores, 0, sizeof(stores));
  if (with_machine) {
    stores[n].kind = SD_KH_STORE_MACHINE;
    stores[n].path = NULL;
    stores[n].writable = 0;
    n++;
  }
  stores[n].kind = SD_KH_STORE_USER;
  stores[n].path = user_kh;
  stores[n].writable = 1;
  n++;
  if (extra != SD_KH_STORE_MACHINE) {
    stores[n].kind = extra;
    stores[n].path = extra_path;
    stores[n].writable = 0;
    n++;
  }
  if (sd_known_hosts_open(stores, n, &kh) != SD_OK)
    return NULL;
  return kh;
}

typedef struct hk_collect {
  ui_hk_store store;
} hk_collect;

static int collect_cb(void *ctx, const sd_kh_all_entry *e)
{
  hk_collect *c = (hk_collect *)ctx;
  hk_entry *k;
  char fp[UI_HK_FP_MAX];
  if (g_hk.nkeys >= HK_MAX_KEYS)
    return 1;
  if (g_hk.nkeys == g_hk.capkeys) {
    size_t ncap = g_hk.capkeys ? g_hk.capkeys * 2 : 64;
    hk_entry *p = (hk_entry *)sd_realloc(g_hk.keys, ncap * sizeof(hk_entry));
    if (p == NULL)
      return 1;
    g_hk.keys = p;
    g_hk.capkeys = ncap;
  }
  if (sd_hostkey_fingerprint_sha256(e->blob, e->len, fp) != SD_OK)
    strcpy_s(fp, sizeof(fp), "?");
  k = &g_hk.keys[g_hk.nkeys];
  memset(k, 0, sizeof(*k));
  if (ui_hk_row_init(&k->row, c->store, e->pattern, e->hashed, e->type, fp, e->line) != SD_OK)
    return 0;
  k->blob = (uint8_t *)sd_alloc(e->len);
  if (k->blob == NULL)
    return 1;
  memcpy(k->blob, e->blob, e->len);
  k->blen = e->len;
  g_hk.nkeys++;
  return 0;
}

static void clear_keys(void)
{
  size_t i;
  for (i = 0; i < g_hk.nkeys; i++)
    sd_free(g_hk.keys[i].blob);
  g_hk.nkeys = 0;
}

static void clear_anns(void)
{
  g_hk.nanns = 0;
}

static void populate_known(void)
{
  size_t i;
  wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX];
  const wchar_t *hashed = sd_l10n_get(SD_MSG_UI_HOSTKEYS_HASHED);
  const wchar_t *machine = sd_l10n_get(SD_MSG_UI_HOSTKEYS_SRC_MACHINE);
  const wchar_t *user = sd_l10n_get(SD_MSG_UI_HOSTKEYS_SRC_USER);
  if (g_hk.list_known == NULL)
    return;
  SendMessageW(g_hk.list_known, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_hk.list_known, LVM_DELETEALLITEMS, 0, 0);
  for (i = 0; i < g_hk.nkeys; i++) {
    ui_hk_row_cells(&g_hk.keys[i].row, hashed, machine, user, cells);
    insert_row(g_hk.list_known, (int)i, cells, UI_HK_CELLS, (LPARAM)i);
  }
  SendMessageW(g_hk.list_known, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_hk.list_known, NULL, TRUE);
}

static void populate_ann(void)
{
  size_t i;
  wchar_t cells[4][UI_HK_CELL_MAX];
  if (g_hk.list_ann == NULL)
    return;
  SendMessageW(g_hk.list_ann, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_hk.list_ann, LVM_DELETEALLITEMS, 0, 0);
  for (i = 0; i < g_hk.nanns; i++) {
    const hk_ann *a = &g_hk.anns[i];
    ui_hk_announce_cells(a->host, a->add, a->type, a->fp, sd_l10n_get(SD_MSG_UI_HOSTKEYS_ACTION_ADD),
                         sd_l10n_get(SD_MSG_UI_HOSTKEYS_ACTION_REMOVE), cells);
    insert_row(g_hk.list_ann, (int)i, cells, 4, (LPARAM)i);
  }
  SendMessageW(g_hk.list_ann, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_hk.list_ann, NULL, TRUE);
}

static void refresh_known(void)
{
  sd_known_hosts *kh;
  hk_collect c;
  clear_keys();
  kh = open_stores(1, SD_KH_STORE_MACHINE, NULL);
  if (kh != NULL) {
    c.store = UI_HK_STORE_MACHINE;
    (void)sd_known_hosts_list_all(kh, SD_KH_STORE_MACHINE, collect_cb, &c);
    c.store = UI_HK_STORE_USER;
    (void)sd_known_hosts_list_all(kh, SD_KH_STORE_USER, collect_cb, &c);
    sd_known_hosts_close(kh);
  } else {
    status_msg(SD_MSG_UI_HOSTKEYS_STORE_FAILED);
  }
  populate_known();
  if (kh != NULL)
    status_count(SD_MSG_UI_HOSTKEYS_STATUS_KNOWN, g_hk.nkeys);
}

/* ---- buttons ---- */

static int ann_has_removals(const char *id)
{
  size_t i;
  for (i = 0; i < g_hk.nanns; i++)
    if (!g_hk.anns[i].add && strcmp(g_hk.anns[i].id, id) == 0)
      return 1;
  return 0;
}

static void update_buttons(void)
{
  int tab = g_hk.tab ? (int)SendMessageW(g_hk.tab, TCM_GETCURSEL, 0, 0) : HK_TAB_KNOWN;
  int sel = sel_index(g_hk.list_known);
  int ann_sel = sel_index(g_hk.list_ann);
  int removable = 0, ann_ok = 0, has_removals = 0;
  if (sel >= 0 && (size_t)sel < g_hk.nkeys) {
    LPARAM p = item_param(g_hk.list_known, sel);
    if (p >= 0 && (size_t)p < g_hk.nkeys) {
      const hk_entry *k = &g_hk.keys[p];
      removable = k->row.removable && k->row.store == UI_HK_STORE_USER;
    }
  }
  if (ann_sel >= 0) {
    LPARAM p = item_param(g_hk.list_ann, ann_sel);
    if (p >= 0 && (size_t)p < g_hk.nanns) {
      ann_ok = !g_hk.ann_wait && !g_hk.accept_wait && g_app.agent_up;
      has_removals = ann_has_removals(g_hk.anns[p].id);
    }
  }
  if (g_hk.btn_remove)
    EnableWindow(g_hk.btn_remove, tab == HK_TAB_KNOWN && removable);
  if (g_hk.btn_putty)
    EnableWindow(g_hk.btn_putty, tab == HK_TAB_KNOWN);
  if (g_hk.btn_openssh)
    EnableWindow(g_hk.btn_openssh, tab == HK_TAB_KNOWN);
  if (g_hk.btn_add)
    EnableWindow(g_hk.btn_add, tab == HK_TAB_ANNOUNCED && ann_ok);
  if (g_hk.btn_addall)
    EnableWindow(g_hk.btn_addall, tab == HK_TAB_ANNOUNCED && ann_ok && has_removals);
  if (g_hk.btn_refresh)
    EnableWindow(g_hk.btn_refresh, TRUE);
}

static void show_tab(void)
{
  int tab = (int)SendMessageW(g_hk.tab, TCM_GETCURSEL, 0, 0);
  int known = tab == HK_TAB_KNOWN;
  ShowWindow(g_hk.list_known, known ? SW_SHOW : SW_HIDE);
  ShowWindow(g_hk.list_ann, known ? SW_HIDE : SW_SHOW);
  ShowWindow(g_hk.btn_remove, known ? SW_SHOW : SW_HIDE);
  ShowWindow(g_hk.btn_putty, known ? SW_SHOW : SW_HIDE);
  ShowWindow(g_hk.btn_openssh, known ? SW_SHOW : SW_HIDE);
  ShowWindow(g_hk.btn_add, known ? SW_HIDE : SW_SHOW);
  ShowWindow(g_hk.btn_addall, known ? SW_HIDE : SW_SHOW);
}

/* ---- layout ---- */

static int button_width(HWND btn)
{
  wchar_t text[128];
  int w;
  GetWindowTextW(btn, text, SD_COUNTOF(text));
  w = ui_win_text_width(g_hk.font, text) + dpx(24);
  return w < dpx(100) ? dpx(100) : w;
}

static void layout(HWND hwnd)
{
  RECT rc, tabrc;
  int m, bh, sh, W, H, by, x, i;
  HWND btns[6];
  if (!g_hk.tab || !g_hk.status)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(8);
  bh = dpx(26);
  sh = dpx(20);
  MoveWindow(g_hk.status, m, H - m - sh, W - 2 * m > 0 ? W - 2 * m : 0, sh, TRUE);
  by = H - m - sh - m - bh;
  btns[0] = g_hk.btn_remove;
  btns[1] = g_hk.btn_putty;
  btns[2] = g_hk.btn_openssh;
  btns[3] = g_hk.btn_add;
  btns[4] = g_hk.btn_addall;
  btns[5] = g_hk.btn_refresh;
  x = m;
  for (i = 0; i < 6; i++) {
    int visible;
    if (!btns[i])
      continue;
    visible = (int)SendMessageW(g_hk.tab, TCM_GETCURSEL, 0, 0) == HK_TAB_KNOWN ? (i < 3 || i == 5)
                                                                              : (i == 3 || i == 4 || i == 5);
    if (!visible)
      continue;
    MoveWindow(btns[i], x, by, button_width(btns[i]), bh, TRUE);
    x += button_width(btns[i]) + m;
  }
  MoveWindow(g_hk.tab, m, m, W - 2 * m > 0 ? W - 2 * m : 0, by - 2 * m > 0 ? by - 2 * m : 0, TRUE);
  GetClientRect(g_hk.tab, &tabrc);
  TabCtrl_AdjustRect(g_hk.tab, FALSE, &tabrc);
  MoveWindow(g_hk.list_known, tabrc.left, tabrc.top, tabrc.right - tabrc.left, tabrc.bottom - tabrc.top, TRUE);
  MoveWindow(g_hk.list_ann, tabrc.left, tabrc.top, tabrc.right - tabrc.left, tabrc.bottom - tabrc.top, TRUE);
}

/* ---- actions ---- */

static void remove_selected(void)
{
  int sel = sel_index(g_hk.list_known);
  hk_entry *k;
  sd_known_hosts *kh;
  sd_err e;
  wchar_t host[UI_HK_HOST_MAX], type[UI_HK_TYPE_MAX];
  sd_arg args[2];
  wchar_t *text;
  LPARAM p;
  if (sel < 0)
    return;
  p = item_param(g_hk.list_known, sel);
  if (p < 0 || (size_t)p >= g_hk.nkeys)
    return;
  k = &g_hk.keys[p];
  if (!k->row.removable || k->row.store != UI_HK_STORE_USER)
    return;
  ui_text_utf8(k->row.host, host, SD_COUNTOF(host));
  ui_text_utf8(k->row.type, type, SD_COUNTOF(type));
  args[0].name = "host";
  args[0].type = SD_ARG_STR;
  args[0].v.s = host;
  args[1].name = "type";
  args[1].type = SD_ARG_STR;
  args[1].v.s = type;
  text = sd_l10n_format_alloc(SD_MSG_UI_HOSTKEYS_CONFIRM_REMOVE, args, 2);
  if (text == NULL)
    return;
  if (MessageBoxW(g_hk.wnd, text, L"ShellDrive", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
    sd_free(text);
    return;
  }
  sd_free(text);
  kh = open_stores(0, SD_KH_STORE_MACHINE, NULL);
  if (kh == NULL) {
    status_msg(SD_MSG_UI_HOSTKEYS_STORE_FAILED);
    return;
  }
  e = sd_known_hosts_remove_key(kh, SD_KH_STORE_USER, k->row.lookup, k->blob, k->blen);
  sd_known_hosts_close(kh);
  if (e != SD_OK) {
    ui_win_error(g_hk.wnd, SD_MSG_UI_HOSTKEYS_REMOVE_FAILED, e);
    return;
  }
  status_msg(SD_MSG_UI_HOSTKEYS_REMOVED);
  refresh_known();
}

static int pick_known_hosts_file(wchar_t *path, size_t cap)
{
  OPENFILENAMEW ofn;
  wchar_t filter[160];
  wchar_t title[128];
  wchar_t initial[MAX_PATH];
  const wchar_t *all = sd_l10n_get(SD_MSG_UI_HOSTKEYS_FILE_ALL);
  size_t n = wcslen(all);
  if (n + 8 >= SD_COUNTOF(filter))
    return 0;
  wcscpy_s(filter, SD_COUNTOF(filter), all);
  wcscpy_s(filter + n + 1, SD_COUNTOF(filter) - n - 1, L"*.*");
  filter[n + 4] = L'\0';
  filter[n + 5] = L'\0';
  wcscpy_s(title, SD_COUNTOF(title), sd_l10n_get(SD_MSG_UI_HOSTKEYS_PICK_TITLE));
  if (ExpandEnvironmentStringsW(L"%USERPROFILE%\\.ssh", initial, SD_COUNTOF(initial)) == 0)
    initial[0] = L'\0';
  path[0] = L'\0';
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_hk.wnd;
  ofn.lpstrFilter = filter;
  ofn.nFilterIndex = 1;
  ofn.lpstrFile = path;
  ofn.nMaxFile = (DWORD)cap;
  ofn.lpstrInitialDir = initial;
  ofn.lpstrTitle = title;
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
  return GetOpenFileNameW(&ofn) ? 1 : 0;
}

static void import_keys(sd_kh_store_kind src, const wchar_t *src_path)
{
  sd_known_hosts *kh;
  sd_kh_import_report rep;
  sd_err e;
  kh = open_stores(0, src, src_path);
  if (kh == NULL) {
    status_msg(SD_MSG_UI_HOSTKEYS_STORE_FAILED);
    return;
  }
  memset(&rep, 0, sizeof(rep));
  e = sd_known_hosts_import(kh, src, SD_KH_STORE_USER, &rep);
  sd_known_hosts_close(kh);
  if (e != SD_OK) {
    ui_win_error(g_hk.wnd, SD_MSG_UI_HOSTKEYS_IMPORT_FAILED, e);
    return;
  }
  if (rep.imported == 0)
    status_msg(SD_MSG_UI_HOSTKEYS_IMPORT_NONE);
  else
    status_count(SD_MSG_UI_HOSTKEYS_IMPORTED, rep.imported);
  refresh_known();
}

static void import_putty(void)
{
  import_keys(SD_KH_SRC_PUTTY, NULL);
}

static void import_openssh(void)
{
  wchar_t path[MAX_PATH * 2];
  if (!pick_known_hosts_file(path, SD_COUNTOF(path)))
    return;
  import_keys(SD_KH_SRC_OPENSSH, path);
}

/* hostkey.announced.list: the agent answers with every announcement it holds (2.4). */
static void request_announced(void)
{
  if (!g_app.agent_up) {
    clear_anns();
    populate_ann();
    status_msg(SD_MSG_UI_HOSTKEYS_AGENT_DOWN);
    update_buttons();
    return;
  }
  if (g_hk.ann_wait)
    return;
  if (ui_ipc_call(UI_IPC_ANNOUNCED, "hostkey.announced.list", NULL) == SD_OK)
    g_hk.ann_wait = 1;
  update_buttons();
}

static int valid_ann_id(const char *s)
{
  size_t i, n = strlen(s);
  if (n == 0 || n >= HK_ANN_ID_MAX)
    return 0;
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
          c == '.'))
      return 0;
  }
  return 1;
}

static int add_ann_list(const sd_json *arr, const char *id, const char *host, int add)
{
  size_t i, n = sd_json_count(arr);
  for (i = 0; i < n; i++) {
    const sd_json *key = sd_json_at(arr, i);
    const char *type = sd_json_get_str(key, "type");
    const char *fp = sd_json_get_str(key, "fingerprint");
    hk_ann *a;
    if (g_hk.nanns >= HK_MAX_ANN)
      return 0;
    if (g_hk.nanns == g_hk.capanns) {
      size_t ncap = g_hk.capanns ? g_hk.capanns * 2 : 16;
      hk_ann *p = (hk_ann *)sd_realloc(g_hk.anns, ncap * sizeof(hk_ann));
      if (p == NULL)
        return 0;
      g_hk.anns = p;
      g_hk.capanns = ncap;
    }
    a = &g_hk.anns[g_hk.nanns];
    memset(a, 0, sizeof(*a));
    strcpy_s(a->id, sizeof(a->id), id);
    strcpy_s(a->host, sizeof(a->host), host);
    strcpy_s(a->type, sizeof(a->type), type ? type : "?");
    strcpy_s(a->fp, sizeof(a->fp), fp ? fp : "?");
    a->add = add;
    g_hk.nanns++;
  }
  return 1;
}

static void parse_announced(const sd_json *result)
{
  const sd_json *arr = sd_json_get(result, "announcements");
  size_t i, n = sd_json_count(arr);
  clear_anns();
  for (i = 0; i < n; i++) {
    const sd_json *an = sd_json_at(arr, i);
    const char *id = sd_json_get_str(an, "id");
    const char *host = sd_json_get_str(an, "host");
    if (id == NULL || !valid_ann_id(id))
      continue;
    if (host == NULL || strlen(host) >= UI_HK_HOST_MAX)
      host = "";
    if (!add_ann_list(sd_json_get(an, "add"), id, host, 1))
      break;
    if (!add_ann_list(sd_json_get(an, "remove"), id, host, 0))
      break;
  }
}

static void accept_selected(int add_only)
{
  int sel = sel_index(g_hk.list_ann);
  LPARAM p;
  const hk_ann *a;
  char params[HK_ANN_ID_MAX + 48];
  if (sel < 0)
    return;
  p = item_param(g_hk.list_ann, sel);
  if (p < 0 || (size_t)p >= g_hk.nanns)
    return;
  a = &g_hk.anns[p];
  if (!add_only && ann_has_removals(a->id)) {
    if (MessageBoxW(g_hk.wnd, sd_l10n_get(SD_MSG_UI_HOSTKEYS_CONFIRM_ACCEPT_REMOVALS), L"ShellDrive",
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
      return;
  }
  sprintf_s(params, sizeof(params), "{\"id\":\"%s\",\"add_only\":%s}", a->id, add_only ? "true" : "false");
  ui_text_utf8(a->host, g_hk.accept_host, SD_COUNTOF(g_hk.accept_host));
  if (ui_ipc_call(UI_IPC_ACCEPT, "hostkey.announced.accept", params) == SD_OK) {
    g_hk.accept_wait = 1;
    update_buttons();
  } else {
    status_msg(SD_MSG_UI_HOSTKEYS_ACCEPT_FAILED_QUEUE);
  }
}

/* ---- replies and events (ui_win.c) ---- */

void ui_hostkeys_on_reply(int kind, sd_err err, const sd_json *result)
{
  if (kind == UI_IPC_ANNOUNCED) {
    g_hk.ann_wait = 0;
    if (err == SD_OK && result != NULL) {
      parse_announced(result);
    } else {
      clear_anns();
      status_msg(err == SD_E_DISCONNECTED ? SD_MSG_UI_HOSTKEYS_AGENT_DOWN : SD_MSG_UI_HOSTKEYS_ANNOUNCED_FAILED);
    }
    populate_ann();
    if (err == SD_OK)
      status_count(SD_MSG_UI_HOSTKEYS_STATUS_ANNOUNCED, g_hk.nanns);
  } else if (kind == UI_IPC_ACCEPT) {
    g_hk.accept_wait = 0;
    if (err != SD_OK) {
      ui_win_error(g_hk.wnd, SD_MSG_UI_HOSTKEYS_ACCEPT_FAILED, err);
    } else {
      wchar_t *t;
      sd_arg a;
      a.name = "host";
      a.type = SD_ARG_STR;
      a.v.s = g_hk.accept_host;
      t = sd_l10n_format_alloc(SD_MSG_UI_HOSTKEYS_ACCEPTED, &a, 1);
      if (t != NULL) {
        status_text(t);
        sd_free(t);
      }
      request_announced();
    }
  }
  update_buttons();
}

void ui_hostkeys_on_event(void)
{
  if (g_hk.wnd != NULL)
    request_announced();
}

void ui_hostkeys_on_agent_state(int up)
{
  if (g_hk.wnd == NULL)
    return;
  if (!up) {
    clear_anns();
    g_hk.ann_wait = 0;
    g_hk.accept_wait = 0;
    populate_ann();
  }
  if (up)
    request_announced();
  update_buttons();
}

/* ---- window ---- */

static void create_children(HWND hwnd)
{
  LVCOLUMNW col;
  int i;
  static const sd_msg_id known_cols[UI_HK_CELLS] = {
    SD_MSG_UI_HOSTKEYS_COL_HOST, SD_MSG_UI_HOSTKEYS_COL_PORT, SD_MSG_UI_HOSTKEYS_COL_TYPE,
    SD_MSG_UI_HOSTKEYS_COL_FP, SD_MSG_UI_HOSTKEYS_COL_SOURCE
  };
  static const sd_msg_id ann_cols[4] = {
    SD_MSG_UI_HOSTKEYS_COL_HOST, SD_MSG_UI_HOSTKEYS_COL_CHANGE, SD_MSG_UI_HOSTKEYS_COL_TYPE,
    SD_MSG_UI_HOSTKEYS_COL_FP
  };
  HINSTANCE inst = g_app.inst;

  g_hk.tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, hwnd,
                             (HMENU)(UINT_PTR)HK_ID_TAB, inst, NULL);
  g_hk.list_known = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                        LVS_SHOWSELALWAYS,
                                    0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)HK_ID_LIST_KNOWN, inst, NULL);
  g_hk.list_ann = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0,
                                  10, 10, hwnd, (HMENU)(UINT_PTR)HK_ID_LIST_ANN, inst, NULL);
  g_hk.btn_remove = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_HOSTKEYS_BTN_REMOVE),
                                    WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                    (HMENU)(UINT_PTR)HK_ID_REMOVE, inst, NULL);
  g_hk.btn_putty = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_HOSTKEYS_BTN_IMPORT_PUTTY),
                                   WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                   (HMENU)(UINT_PTR)HK_ID_PUTTY, inst, NULL);
  g_hk.btn_openssh = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_HOSTKEYS_BTN_IMPORT_OPENSSH),
                                     WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                     (HMENU)(UINT_PTR)HK_ID_OPENSSH, inst, NULL);
  g_hk.btn_add = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_HOSTKEYS_BTN_ADD),
                                 WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                 (HMENU)(UINT_PTR)HK_ID_ADD, inst, NULL);
  g_hk.btn_addall = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_HOSTKEYS_BTN_ADD_ALL),
                                    WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                    (HMENU)(UINT_PTR)HK_ID_ADDALL, inst, NULL);
  g_hk.btn_refresh = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_MAIN_REFRESH),
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                     (HMENU)(UINT_PTR)HK_ID_REFRESH, inst, NULL);
  g_hk.status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10,
                                hwnd, (HMENU)(UINT_PTR)HK_ID_STATUS, inst, NULL);

  SendMessageW(g_hk.list_known, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
  SendMessageW(g_hk.list_ann, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
  for (i = 0; i < UI_HK_CELLS; i++) {
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
    col.pszText = (LPWSTR)sd_l10n_get(known_cols[i]);
    col.iSubItem = i;
    col.cx = 100;
    SendMessageW(g_hk.list_known, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
  for (i = 0; i < 4; i++) {
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
    col.pszText = (LPWSTR)sd_l10n_get(ann_cols[i]);
    col.iSubItem = i;
    col.cx = 100;
    SendMessageW(g_hk.list_ann, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
  {
    static const sd_msg_id tabs[2] = { SD_MSG_UI_HOSTKEYS_TAB_KNOWN, SD_MSG_UI_HOSTKEYS_TAB_ANNOUNCED };
    for (i = 0; i < 2; i++) {
      TCITEMW it;
      memset(&it, 0, sizeof(it));
      it.mask = TCIF_TEXT;
      it.pszText = (LPWSTR)sd_l10n_get(tabs[i]);
      SendMessageW(g_hk.tab, TCM_INSERTITEMW, (WPARAM)i, (LPARAM)&it);
    }
  }
  ui_win_apply_font(hwnd, g_hk.font);
  set_columns();
  show_tab();
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_hk.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_hk.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_hk.font = ui_win_font(dpi);
  ui_win_apply_font(hwnd, g_hk.font);
  if (old)
    DeleteObject(old);
  set_columns();
  layout(hwnd);
}

static void on_command(WORD id, WORD code)
{
  if (code != BN_CLICKED)
    return;
  switch (id) {
  case HK_ID_REMOVE:
    remove_selected();
    break;
  case HK_ID_PUTTY:
    import_putty();
    break;
  case HK_ID_OPENSSH:
    import_openssh();
    break;
  case HK_ID_REFRESH:
    refresh_known();
    request_announced();
    break;
  case HK_ID_ADD:
    accept_selected(1);
    break;
  case HK_ID_ADDALL:
    accept_selected(0);
    break;
  default:
    break;
  }
  update_buttons();
}

static LRESULT CALLBACK hk_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_hk.wnd = hwnd;
    g_hk.dpi = ui_dpi_window(hwnd);
    g_hk.font = ui_win_font(g_hk.dpi);
    create_children(hwnd);
    layout(hwnd);
    update_buttons();
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp), HIWORD(wp));
    return 0;
  case WM_NOTIFY: {
    const NMHDR *h = (const NMHDR *)lp;
    if (h->idFrom == HK_ID_TAB && h->code == TCN_SELCHANGE) {
      show_tab();
      update_buttons();
    } else if ((h->idFrom == HK_ID_LIST_KNOWN || h->idFrom == HK_ID_LIST_ANN) && h->code == LVN_ITEMCHANGED) {
      update_buttons();
    }
    return 0;
  }
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    if (g_hk.font)
      DeleteObject(g_hk.font);
    clear_keys();
    sd_free(g_hk.keys);
    sd_free(g_hk.anns);
    memset(&g_hk, 0, sizeof(g_hk));
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
  ui_win_class_name(L"hostkeys", cls);
  if (!ui_win_register(g_app.inst, cls, hk_proc))
    return NULL;
  if (g_hk.wnd != NULL && IsWindow(g_hk.wnd))
    return g_hk.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_HOSTKEYS_TITLE), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, HK_CLIENT_W, HK_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(HK_CLIENT_W, ui_dpi_window(w)), ui_dpi_scale(HK_CLIENT_H,
               ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(w, SW_SHOW);
  return w;
}

void ui_hostkeys_open(void)
{
  HWND w;
  if (g_hk.wnd != NULL && IsWindow(g_hk.wnd)) {
    ShowWindow(g_hk.wnd, IsIconic(g_hk.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_hk.wnd);
    return;
  }
  w = create_window(1);
  if (w == NULL)
    return;
  refresh_known();
  request_announced();
}

void ui_hostkeys_close(void)
{
  if (g_hk.wnd != NULL && IsWindow(g_hk.wnd))
    DestroyWindow(g_hk.wnd);
}

HWND ui_hostkeys_create_hidden(void)
{
  return create_window(0);
}
