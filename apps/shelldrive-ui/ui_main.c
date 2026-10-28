/* shelldrive-ui: the main window, the connection manager (03 §7.5, reduced to the profile list and its actions).
 *
 * One row per saved profile (sorted by name), joined with the agent's mounts by profile id: a profile that is
 * mounted shows its drive and state, one that is not shows "Not mounted". Mounts that match no saved profile
 * (ad-hoc mounts) follow as rows of their own. Buttons: New, Edit, Duplicate, Delete, Quick mount (ad-hoc
 * dialog), Mount, Unmount, Open (Explorer) and Refresh. Enter or double-click mounts a profile, or opens its
 * drive when mounted; the Delete key deletes after confirmation. Closing the window hides it; the tray icon keeps
 * the application running. Sizes are scaled from 96-DPI values with ui_dpi_scale; on WM_DPICHANGED the suggested
 * rectangle is applied, the font is rebuilt and the layout runs again (7.3). */
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "ui_dark.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_profile_model.h"
#include "ui_win.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#define UI_CLIENT_W  680
#define UI_CLIENT_H  420
#define UI_COLUMNS   5
#define UI_ROWS_MAX  (512 + UI_MAX_MOUNTS)
#define UI_BTN_ROWS  2
#define UI_BTN_COLS  5
#define UI_BUTTONS   10

typedef struct ui_row {
  int profile;                  /* index in the profile list, -1 for an ad-hoc mount */
  int mount;                    /* index in the mount model, -1 when not mounted */
} ui_row;

static const wchar_t k_title[] = L"ShellDrive";
static ui_row g_rows[UI_ROWS_MAX];
static size_t g_nrows;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_app.dpi);
}

static HFONT make_font(unsigned dpi)
{
  NONCLIENTMETRICSW ncm;
  LOGFONTW lf;
  unsigned sys = ui_dpi_system();
  long long h;

  memset(&ncm, 0, sizeof(ncm));
  ncm.cbSize = sizeof(ncm);
  if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
    lf = ncm.lfMessageFont;
  } else {
    memset(&lf, 0, sizeof(lf));
    GetObjectW(GetStockObject(DEFAULT_GUI_FONT), sizeof(lf), &lf);
  }
  /* The message font height is in pixels of the system DPI; move it to the window DPI. */
  h = lf.lfHeight < 0 ? -(long long)lf.lfHeight : (long long)lf.lfHeight;
  if (h == 0)
    h = 12;
  if (sys == 0)
    sys = UI_DPI_BASE;
  h = (h * (long long)dpi + (long long)sys / 2) / (long long)sys;
  lf.lfHeight = (LONG)-h;
  return CreateFontIndirectW(&lf);
}

static HWND button_at(int i)
{
  HWND b[UI_BUTTONS];
  b[0] = g_app.btn_new;
  b[1] = g_app.btn_edit;
  b[2] = g_app.btn_duplicate;
  b[3] = g_app.btn_delete;
  b[4] = g_app.btn_quick;
  b[5] = g_app.btn_import;
  b[6] = g_app.btn_mount;
  b[7] = g_app.btn_unmount;
  b[8] = g_app.btn_open;
  b[9] = g_app.btn_refresh;
  return b[i];
}

static void set_children_font(void)
{
  int i;
  for (i = 0; i < UI_BUTTONS; i++)
    if (button_at(i))
      SendMessageW(button_at(i), WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.list)
    SendMessageW(g_app.list, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.status)
    SendMessageW(g_app.status, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
}

static void set_columns(void)
{
  static const int widths[UI_COLUMNS] = { 170, 60, 130, 80, 170 };
  int i;
  if (!g_app.list)
    return;
  for (i = 0; i < UI_COLUMNS; i++)
    SendMessageW(g_app.list, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(widths[i]));
}

static void layout(HWND hwnd)
{
  RECT rc, sb;
  int m, bh, bw, y, w, h, sbh, lh, i, r;
  if (!g_app.list || !g_app.status)
    return;
  m = dpx(8);
  bh = dpx(26);
  bw = dpx(120);
  GetClientRect(hwnd, &rc);
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  SendMessageW(g_app.status, WM_SIZE, 0, 0);   /* the status bar positions itself at the bottom */
  GetWindowRect(g_app.status, &sb);
  sbh = sb.bottom - sb.top;
  for (i = 0; i < UI_BUTTONS; i++) {
    HWND b = button_at(i);
    if (!b)
      continue;
    r = i / UI_BTN_COLS;
    MoveWindow(b, m + (i % UI_BTN_COLS) * (bw + m / 2), m + r * (bh + m / 2), bw, bh, TRUE);
  }
  y = m + UI_BTN_ROWS * (bh + m / 2) + m / 2;
  lh = h - y - sbh - m;
  if (lh < 0)
    lh = 0;
  MoveWindow(g_app.list, m, y, w - 2 * m > 0 ? w - 2 * m : 0, lh, TRUE);
}

/* ---- rows ---- */

static void build_rows(void)
{
  size_t i, j;
  g_nrows = 0;
  for (i = 0; i < ui_profiles_count() && g_nrows < UI_ROWS_MAX; i++) {
    const sd_profile *p = ui_profiles_at(i);
    ui_row *r = &g_rows[g_nrows++];
    r->profile = (int)i;
    r->mount = -1;
    for (j = 0; j < g_app.model.count; j++) {
      if (p->id[0] && strcmp(g_app.model.items[j].profile_id, p->id) == 0) {
        r->mount = (int)j;
        break;
      }
    }
  }
  for (j = 0; j < g_app.model.count && g_nrows < UI_ROWS_MAX; j++) {
    const ui_mount *m = &g_app.model.items[j];
    if (m->profile_id[0] && ui_profiles_find_id(m->profile_id) != NULL)
      continue;
    g_rows[g_nrows].profile = -1;
    g_rows[g_nrows].mount = (int)j;
    g_nrows++;
  }
}

static const ui_row *selected_row(void)
{
  int sel;
  if (!g_app.list)
    return NULL;
  sel = (int)SendMessageW(g_app.list, LVM_GETNEXTITEM, (WPARAM)-1, MAKELPARAM(LVNI_SELECTED, 0));
  if (sel < 0 || (size_t)sel >= g_nrows)
    return NULL;
  return &g_rows[sel];
}

const sd_profile *ui_main_selected_profile(void)
{
  const ui_row *r = selected_row();
  return r && r->profile >= 0 ? ui_profiles_at((size_t)r->profile) : NULL;
}

ui_mount *ui_main_selected_mount(void)
{
  const ui_row *r = selected_row();
  return r && r->mount >= 0 ? &g_app.model.items[r->mount] : NULL;
}

/* "host" or "host:port" (the SSH default port is left out). */
static void profile_server(const sd_profile *p, wchar_t *out, size_t cch)
{
  wchar_t host[256];
  ui_text_utf8(p->host, host, SD_COUNTOF(host));
  wcsncpy_s(out, cch, host, _TRUNCATE);
  if (p->port != 22 && p->port != 0) {
    wchar_t num[12];
    size_t len = wcslen(out);
    wsprintfW(num, L":%u", (unsigned)p->port);
    if (len + wcslen(num) + 1 <= cch)
      wcscat_s(out, cch, num);
  }
}

static void update_buttons(void)
{
  const ui_row *r = selected_row();
  int mounted = r != NULL && r->mount >= 0;
  int has_profile = r != NULL && r->profile >= 0;

  EnableWindow(g_app.btn_edit, has_profile);
  EnableWindow(g_app.btn_duplicate, has_profile);
  EnableWindow(g_app.btn_delete, has_profile);
  EnableWindow(g_app.btn_mount, has_profile && !mounted && g_app.agent_up);
  EnableWindow(g_app.btn_unmount, mounted && g_app.agent_up);
  EnableWindow(g_app.btn_open, mounted);
  EnableWindow(g_app.btn_refresh, g_app.agent_up);
  EnableWindow(g_app.btn_new, TRUE);
  EnableWindow(g_app.btn_quick, TRUE);
}

static void set_status_text(void)
{
  wchar_t *t;
  const wchar_t *text;
  if (!g_app.status)
    return;
  if (!g_app.agent_up) {
    text = sd_l10n_get(SD_MSG_UI_STATUS_AGENT_DOWN);
    SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)text);
    return;
  }
  t = ui_format_count(SD_MSG_UI_STATUS_COUNT, (long long)g_app.model.count);
  if (t != NULL) {
    SendMessageW(g_app.status, SB_SETTEXTW, 0, (LPARAM)t);
    sd_free(t);
  }
}

void ui_main_refresh(void)
{
  size_t i;
  if (!g_app.list)
    return;
  build_rows();
  SendMessageW(g_app.list, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_app.list, LVM_DELETEALLITEMS, 0, 0);
  for (i = 0; i < g_nrows; i++) {
    const ui_row *row = &g_rows[i];
    const ui_mount *m = row->mount >= 0 ? &g_app.model.items[row->mount] : NULL;
    const sd_profile *p = row->profile >= 0 ? ui_profiles_at((size_t)row->profile) : NULL;
    wchar_t name[160], server[300];
    const wchar_t *cells[UI_COLUMNS];
    LVITEMW it;
    int j;

    if (p) {
      ui_text_utf8(p->name, name, SD_COUNTOF(name));
      profile_server(p, server, SD_COUNTOF(server));
    } else if (m) {
      wcsncpy_s(name, SD_COUNTOF(name), m->profile, _TRUNCATE);
      wcsncpy_s(server, SD_COUNTOF(server), m->server, _TRUNCATE);
    } else {
      name[0] = 0;
      server[0] = 0;
    }
    cells[0] = name;
    cells[1] = m ? m->drive : L"";
    cells[2] = m ? ui_model_state_text(m) : sd_l10n_get(SD_MSG_UI_MAIN_NOT_MOUNTED);
    cells[3] = m ? m->backend : L"";
    cells[4] = server;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = (int)i;
    it.pszText = (LPWSTR)cells[0];
    SendMessageW(g_app.list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    for (j = 1; j < UI_COLUMNS; j++) {
      LVITEMW sub;
      memset(&sub, 0, sizeof(sub));
      sub.iItem = (int)i;
      sub.iSubItem = j;
      sub.pszText = (LPWSTR)cells[j];
      SendMessageW(g_app.list, LVM_SETITEMTEXTW, (WPARAM)i, (LPARAM)&sub);
    }
  }
  SendMessageW(g_app.list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_app.list, NULL, TRUE);
  set_status_text();
  update_buttons();
  ui_tray_update();
}

void ui_main_reload_profiles(void)
{
  sd_err e = ui_profiles_load();
  if (e != SD_OK)
    SD_LOGW("ui", "the profile list could not be read (%s)", sd_err_name(e));
  ui_main_refresh();
}

/* ---- actions ---- */

static void message(sd_msg_id id, UINT flags)
{
  MessageBoxW(g_app.main, sd_l10n_get(id), k_title, flags);
}

/* Saves a profile (sd_profile_save), then has the agent read the store again (03 §2.4). */
static int save_profile(sd_profile *p)
{
  sd_err e = sd_profile_save(p);
  if (e != SD_OK) {
    message(SD_MSG_UI_ERROR_SAVE, MB_OK | MB_ICONERROR);
    return 0;
  }
  ui_main_reload_profiles();
  ui_ipc_config_reload();
  return 1;
}

static void select_profile_id(const char *id)
{
  size_t i;
  for (i = 0; i < g_nrows; i++) {
    const sd_profile *p = g_rows[i].profile >= 0 ? ui_profiles_at((size_t)g_rows[i].profile) : NULL;
    if (p && strcmp(p->id, id) == 0) {
      ListView_SetItemState(g_app.list, (int)i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      ListView_EnsureVisible(g_app.list, (int)i, FALSE);
      break;
    }
  }
}

static void do_new(void)
{
  sd_profile p;
  sd_profile_defaults(&p);
  if (!ui_editor_run(g_app.main, UI_EDIT_NEW, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

static void do_edit(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  sd_profile p;
  if (cur == NULL)
    return;
  p = *cur;
  if (!ui_editor_run(g_app.main, UI_EDIT_EDIT, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

/* A copy opens in the editor as a new profile, so its name can be changed before it is saved. */
static void do_duplicate(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  sd_profile p;
  if (cur == NULL)
    return;
  p = *cur;
  p.id[0] = 0;
  if (strlen(p.name) + 4 < sizeof(p.name))
    strcat_s(p.name, sizeof(p.name), " (2)");
  if (!ui_editor_run(g_app.main, UI_EDIT_NEW, &p))
    return;
  if (save_profile(&p))
    select_profile_id(p.id);
}

static void do_delete(void)
{
  const sd_profile *cur = ui_main_selected_profile();
  wchar_t name[160];
  char id[33];
  sd_err e;
  if (cur == NULL)
    return;
  strcpy_s(id, sizeof(id), cur->id);
  ui_text_utf8(cur->name, name, SD_COUNTOF(name));
  if (!ui_confirm(g_app.main, SD_MSG_UI_DELETE_TITLE, SD_MSG_UI_DELETE_TEXT, name, SD_MSG_UI_DELETE_YES,
                  SD_MSG_UI_DELETE_NO, 0))
    return;
  e = sd_profile_delete(id);
  if (e != SD_OK) {
    message(SD_MSG_UI_ERROR_DELETE, MB_OK | MB_ICONERROR);
    return;
  }
  ui_main_reload_profiles();
  ui_ipc_config_reload();
}

static void do_mount_selected(void)
{
  const sd_profile *p = ui_main_selected_profile();
  if (p && ui_ipc_mount(p->id) != SD_OK)
    message(SD_MSG_UI_ERROR_MOUNT, MB_OK | MB_ICONERROR);
}

/* The ad-hoc mount dialog: the connection goes to the agent as an "adhoc" object (03 §2.4). */
static void do_quick_mount(void)
{
  sd_profile p;
  char target[16], params[2048];
  const char *backend = "auto";
  sd_err e;
  sd_profile_defaults(&p);
  if (!ui_editor_run(g_app.main, UI_EDIT_ADHOC, &p))
    return;
  if (ui_pform_get(&p, UI_PF_TARGET, target, sizeof(target)) != SD_OK)
    strcpy_s(target, sizeof(target), "auto");
  if (p.backend == SD_PROFILE_BACKEND_DOKANY)
    backend = "dokany";
  else if (p.backend == SD_PROFILE_BACKEND_WEBDAV)
    backend = "webdav";
  e = ui_mount_params_json(&p, 1, target, p.read_only, backend, params, sizeof(params));
  if (e != SD_OK || ui_ipc_mount_params(params) != SD_OK)
    message(SD_MSG_UI_ERROR_MOUNT, MB_OK | MB_ICONERROR);
}

static void do_unmount_selected(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m && m->drive[0])
    ui_ipc_unmount(m->drive);
}

/* Shows a drive in Explorer (the "explore" verb of ShellExecuteW, 03 §8.1). */
void ui_open_drive(const wchar_t *drive)
{
  wchar_t root[4];
  if (drive == NULL || drive[0] == 0 || drive[1] != L':')
    return;
  root[0] = drive[0];
  root[1] = L':';
  root[2] = L'\\';
  root[3] = 0;
  ShellExecuteW(g_app.main, L"explore", root, NULL, NULL, SW_SHOWNORMAL);
}

static void do_open_selected(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m)
    ui_open_drive(m->drive);
}

/* Enter or double-click: open the drive of a mounted profile, mount a profile that is not mounted. */
static void activate_selected(void)
{
  const ui_row *r = selected_row();
  if (r == NULL)
    return;
  if (r->mount >= 0)
    do_open_selected();
  else
    do_mount_selected();
}

static void on_command(WORD id)
{
  switch (id) {
  case UI_CMD_NEW:         do_new(); break;
  case UI_CMD_EDIT:        do_edit(); break;
  case UI_CMD_DUPLICATE:   do_duplicate(); break;
  case UI_CMD_DELETE:      do_delete(); break;
  case UI_CMD_QUICK_MOUNT: do_quick_mount(); break;
  case UI_CMD_IMPORT:      ui_import_run(g_app.main); break;
  case UI_CMD_MOUNT:       do_mount_selected(); break;
  case UI_CMD_UNMOUNT:     do_unmount_selected(); break;
  case UI_CMD_OPEN_DRIVE:  do_open_selected(); break;
  case UI_CMD_REFRESH:     ui_ipc_list(); break;
  case UI_CMD_HOSTKEYS:
  case UI_CMD_LOGS:
  case UI_CMD_SETTINGS:
  case UI_CMD_SERVICE:
  case UI_CMD_ABOUT:
    ui_windows_command(id);
    break;
  default:
    break;
  }
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_app.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_app.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_app.font = make_font(dpi);
  set_children_font();
  if (old)
    DeleteObject(old);
  set_columns();
  layout(hwnd);
}

static HWND make_button(HWND parent, sd_msg_id text, int id)
{
  return CreateWindowExW(0, L"BUTTON", sd_l10n_get(text), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0,
                         10, 10, parent, (HMENU)(UINT_PTR)id, g_app.inst, NULL);
}

static HMENU build_menu(void)
{
  HMENU bar = CreateMenu();
  HMENU tools = CreatePopupMenu();
  HMENU help = CreatePopupMenu();
  if (bar == NULL || tools == NULL || help == NULL) {
    if (bar) DestroyMenu(bar);
    if (tools) DestroyMenu(tools);
    if (help) DestroyMenu(help);
    return NULL;
  }
  AppendMenuW(tools, MF_STRING, UI_CMD_HOSTKEYS, sd_l10n_get(SD_MSG_UI_MENU_HOSTKEYS));
  AppendMenuW(tools, MF_STRING, UI_CMD_LOGS, sd_l10n_get(SD_MSG_UI_MENU_LOGS));
  AppendMenuW(tools, MF_STRING, UI_CMD_SERVICE, sd_l10n_get(SD_MSG_UI_MENU_SERVICE));
  AppendMenuW(tools, MF_SEPARATOR, 0, NULL);
  AppendMenuW(tools, MF_STRING, UI_CMD_SETTINGS, sd_l10n_get(SD_MSG_UI_MENU_SETTINGS));
  AppendMenuW(help, MF_STRING, UI_CMD_ABOUT, sd_l10n_get(SD_MSG_UI_MENU_ABOUT));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)tools, sd_l10n_get(SD_MSG_UI_MENU_TOOLS));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, sd_l10n_get(SD_MSG_UI_MENU_HELP));
  return bar;
}

static int on_create(HWND hwnd)
{
  LVCOLUMNW col;
  int i;

  g_app.dpi = ui_dpi_window(hwnd);
  g_app.font = make_font(g_app.dpi);
  SetMenu(hwnd, build_menu());

  g_app.btn_new = make_button(hwnd, SD_MSG_UI_MAIN_NEW, UI_CMD_NEW);
  g_app.btn_edit = make_button(hwnd, SD_MSG_UI_MAIN_EDIT, UI_CMD_EDIT);
  g_app.btn_duplicate = make_button(hwnd, SD_MSG_UI_MAIN_DUPLICATE, UI_CMD_DUPLICATE);
  g_app.btn_delete = make_button(hwnd, SD_MSG_UI_MAIN_DELETE, UI_CMD_DELETE);
  g_app.btn_quick = make_button(hwnd, SD_MSG_UI_MAIN_QUICK_MOUNT, UI_CMD_QUICK_MOUNT);
  g_app.btn_import = make_button(hwnd, SD_MSG_UI_MAIN_IMPORT, UI_CMD_IMPORT);
  g_app.btn_mount = make_button(hwnd, SD_MSG_UI_MAIN_MOUNT, UI_CMD_MOUNT);
  g_app.btn_unmount = make_button(hwnd, SD_MSG_UI_MAIN_UNMOUNT, UI_CMD_UNMOUNT);
  g_app.btn_open = make_button(hwnd, SD_MSG_UI_MAIN_OPEN, UI_CMD_OPEN_DRIVE);
  g_app.btn_refresh = make_button(hwnd, SD_MSG_UI_MAIN_REFRESH, UI_CMD_REFRESH);
  g_app.list = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                   LVS_SHOWSELALWAYS,
                               0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)UI_CTL_LIST, g_app.inst, NULL);
  g_app.status = CreateWindowExW(0, L"msctls_statusbar32", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                 (HMENU)(UINT_PTR)UI_CTL_STATUS, g_app.inst, NULL);
  for (i = 0; i < UI_BUTTONS; i++) {
    if (button_at(i) == NULL)
      return -1;
  }
  if (!g_app.list || !g_app.status)
    return -1;

  SendMessageW(g_app.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
  for (i = 0; i < UI_COLUMNS; i++) {
    const wchar_t *text;
    switch (i) {
    case 0: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_NAME); break;
    case 1: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_DRIVE); break;
    case 2: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_STATE); break;
    case 3: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_BACKEND); break;
    default: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SERVER); break;
    }
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
    col.pszText = (LPWSTR)text;
    col.iSubItem = i;
    col.cx = 100;
    SendMessageW(g_app.list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
  set_columns();
  set_children_font();
  if (ui_profiles_load() != SD_OK)
    SD_LOGW("ui", "the profile list could not be read");
  layout(hwnd);
  set_status_text();
  ui_main_refresh();
  return 0;
}

static void on_notify(const NMHDR *nm)
{
  if (nm->idFrom != UI_CTL_LIST)
    return;
  if (nm->code == LVN_ITEMCHANGED) {
    update_buttons();
  } else if (nm->code == NM_DBLCLK) {
    activate_selected();
  } else if (nm->code == LVN_KEYDOWN) {
    const NMLVKEYDOWN *kd = (const NMLVKEYDOWN *)nm;
    if (kd->wVKey == VK_DELETE)
      do_delete();
    else if (kd->wVKey == VK_RETURN)
      activate_selected();
  }
}

static LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  if (g_app.wm_taskbar != 0 && msg == g_app.wm_taskbar) {
    ui_tray_readd();
    return 0;
  }
  switch (msg) {
  case WM_CREATE:
    return on_create(hwnd) == 0 ? 0 : -1;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp));
    return 0;
  case WM_NOTIFY:
    on_notify((const NMHDR *)lp);
    return 0;
  case WM_CLOSE:
    ShowWindow(hwnd, SW_HIDE);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_SETTINGCHANGE:
    /* the app theme changed (7.4): dark title bars follow it; the broadcast reaches every top-level window */
    if (lp != 0 && wcscmp((const wchar_t *)lp, L"ImmersiveColorSet") == 0)
      ui_dark_refresh();
    break;
  case WM_DESTROY:
    if (g_app.font)
      DeleteObject(g_app.font);
    g_app.font = NULL;
    if (g_app.main == hwnd)
      g_app.main = NULL;
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

int ui_main_register_class(HINSTANCE inst, const wchar_t *class_name)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = main_proc;
  wc.hInstance = inst;
  wc.hIcon = ui_icon_get(UI_ICON_IDLE, GetSystemMetrics(SM_CXICON));
  wc.hIconSm = ui_icon_get(UI_ICON_IDLE, GetSystemMetrics(SM_CXSMICON));
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = class_name;
  if (RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    return 0;
  return 1;
}

HWND ui_main_create(HINSTANCE inst, const wchar_t *class_name, int visible)
{
  HWND hwnd;
  g_app.inst = inst;
  hwnd = CreateWindowExW(0, class_name, k_title, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
                         CW_USEDEFAULT, UI_CLIENT_W, UI_CLIENT_H, NULL, NULL, inst, NULL);
  if (hwnd == NULL)
    return NULL;
  g_app.main = hwnd;
  /* The creation size is in pixels of 96 DPI; WM_CREATE has set the window DPI by now. */
  SetWindowPos(hwnd, NULL, 0, 0, dpx(UI_CLIENT_W), dpx(UI_CLIENT_H), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(hwnd, SW_SHOW);
  return hwnd;
}

void ui_main_show(void)
{
  if (!g_app.main)
    return;
  ShowWindow(g_app.main, IsIconic(g_app.main) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(g_app.main);
}

int ui_main_test_controls(void)
{
  int i;
  for (i = 0; i < UI_BUTTONS; i++)
    if (!button_at(i) || !IsWindow(button_at(i)))
      return 0;
  return g_app.list && g_app.status && IsWindow(g_app.list) && IsWindow(g_app.status);
}
