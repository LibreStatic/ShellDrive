/* shelldrive-ui: the main window, the connection manager (03 §7.5).
 *
 * A toolbar with text labels (New, Edit, Delete, Mount, Unmount, Open, Host keys, Logs) above a report ListView with
 * the columns Name, Server, Drive, Backend, Status and Security. Status and Security show an icon and text. The rows
 * are in ListView groups ("My connections", "Provided by your organization", "Global drives"; LVM_ENABLEGROUPVIEW needs
 * comctl32 v6, XP and later; without it the list is flat). Duplicate, Quick mount, Import, Refresh and the security
 * details are in the Connection menu.
 *
 * One row per saved profile (sorted by name inside its group), joined with the agent's mounts by profile id: a profile
 * that is mounted shows its drive and state, one that is not shows "Not mounted". Mounts that match no saved profile
 * (ad-hoc mounts) follow as rows of their own. Enter or double-click mounts a profile, or opens its drive when
 * mounted; the Delete key deletes after confirmation. Closing the window hides it; the tray icon keeps the application
 * running. Sizes are scaled from 96-DPI values with ui_dpi_scale; on WM_DPICHANGED the suggested rectangle is applied,
 * the font and the image list are rebuilt and the layout runs again (7.3). */
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
#include "ui_mainview_model.h"
#include "ui_profile_model.h"
#include "ui_win.h"

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

/* ListView groups are comctl32 v6 (XP and later). The group structure is spelled out in its XP layout: the Vista
   fields are not needed and the XP SDK of the v141_xp toolset does not declare them. */
#ifndef LVM_INSERTGROUP
#define LVM_INSERTGROUP     (LVM_FIRST + 145)
#endif
#ifndef LVM_REMOVEALLGROUPS
#define LVM_REMOVEALLGROUPS (LVM_FIRST + 160)
#endif
#ifndef LVM_ENABLEGROUPVIEW
#define LVM_ENABLEGROUPVIEW (LVM_FIRST + 157)
#endif
#ifndef LVIF_GROUPID
#define LVIF_GROUPID        0x0100
#endif
#define UI_LVGF_HEADER      0x00000001u
#define UI_LVGF_GROUPID     0x00000010u
#ifndef LVS_EX_DOUBLEBUFFER
#define LVS_EX_DOUBLEBUFFER 0x00010000
#endif
#ifndef LVS_EX_SUBITEMIMAGES
#define LVS_EX_SUBITEMIMAGES 0x00000002
#endif

typedef struct ui_lvgroup {
  UINT cbSize, mask;
  LPWSTR pszHeader;
  int cchHeader;
  LPWSTR pszFooter;
  int cchFooter;
  int iGroupId;
  UINT stateMask, state, uAlign;
} ui_lvgroup;

#define UI_CLIENT_W  760
#define UI_CLIENT_H  420
#define UI_COLUMNS   6
#define UI_ROWS_MAX  (512 + UI_MAX_MOUNTS)
#define UI_TB_BUTTONS 8

/* Columns: 0 Name, 1 Server, 2 Drive, 3 Backend, 4 Status, 5 Security (7.5). */
#define UI_COL_STATUS   4
#define UI_COL_SECURITY 5

typedef struct ui_row {
  int profile;                  /* index in the profile list, -1 for an ad-hoc mount */
  int mount;                    /* index in the mount model, -1 when not mounted */
  int group;                    /* ui_mv_group */
} ui_row;

static const wchar_t k_title[] = L"ShellDrive";
static ui_row g_rows[UI_ROWS_MAX];
static size_t g_nrows;
static HIMAGELIST g_images;
static int g_groups_on;

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

static void set_children_font(void)
{
  if (g_app.toolbar)
    SendMessageW(g_app.toolbar, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.list)
    SendMessageW(g_app.list, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
  if (g_app.status)
    SendMessageW(g_app.status, WM_SETFONT, (WPARAM)g_app.font, MAKELPARAM(TRUE, 0));
}

static void set_columns(void)
{
  static const int widths[UI_COLUMNS] = { 160, 140, 60, 70, 140, 130 };
  int i;
  if (!g_app.list)
    return;
  for (i = 0; i < UI_COLUMNS; i++)
    SendMessageW(g_app.list, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(widths[i]));
}

/* The small icons of the Status and Security cells: connected, idle, warning (ui_mv_icon order minus none). */
static void build_images(void)
{
  int sz = dpx(16);
  if (g_images) {
    ImageList_Destroy(g_images);
    g_images = NULL;
  }
  g_images = ImageList_Create(sz, sz, ILC_COLOR32, 3, 0);
  if (g_images == NULL)
    return;
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_CONNECTED, sz));
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_IDLE, sz));
  ImageList_AddIcon(g_images, ui_icon_get(UI_ICON_WARNING, sz));
  if (g_app.list)
    SendMessageW(g_app.list, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)g_images);
}

static int image_of(ui_mv_icon icon)
{
  switch (icon) {
  case UI_MV_ICON_OK:   return 0;
  case UI_MV_ICON_IDLE: return 1;
  case UI_MV_ICON_WARN: return 2;
  default:              return -1;
  }
}

/* The toolbar wraps its buttons when the window is narrow; its height is the bottom of the last button. */
static int toolbar_height(int width)
{
  RECT r;
  int n;
  if (!g_app.toolbar)
    return 0;
  MoveWindow(g_app.toolbar, 0, 0, width, dpx(30), FALSE);
  n = (int)SendMessageW(g_app.toolbar, TB_BUTTONCOUNT, 0, 0);
  if (n <= 0 || !SendMessageW(g_app.toolbar, TB_GETITEMRECT, (WPARAM)(n - 1), (LPARAM)&r))
    return dpx(30);
  return r.bottom + dpx(2);
}

static void layout(HWND hwnd)
{
  RECT rc, sb;
  int m, w, h, sbh, lh, y, th;
  if (!g_app.list || !g_app.status || !g_app.toolbar)
    return;
  m = dpx(8);
  GetClientRect(hwnd, &rc);
  w = rc.right - rc.left;
  h = rc.bottom - rc.top;
  SendMessageW(g_app.status, WM_SIZE, 0, 0);   /* the status bar positions itself at the bottom */
  GetWindowRect(g_app.status, &sb);
  sbh = sb.bottom - sb.top;
  th = toolbar_height(w - 2 * m > 0 ? w - 2 * m : 0);
  MoveWindow(g_app.toolbar, m, m / 2, w - 2 * m > 0 ? w - 2 * m : 0, th, TRUE);
  y = m / 2 + th + m / 2;
  lh = h - y - sbh - m;
  if (lh < 0)
    lh = 0;
  MoveWindow(g_app.list, m, y, w - 2 * m > 0 ? w - 2 * m : 0, lh, TRUE);
}

/* ---- rows ---- */

/* Rows of a group follow each other; the profile list is sorted by name already, so the order inside a group is too. */
static void build_rows(void)
{
  size_t i, j;
  int g;
  ui_row all[UI_ROWS_MAX];
  size_t n = 0;

  for (i = 0; i < ui_profiles_count() && n < UI_ROWS_MAX; i++) {
    const sd_profile *p = ui_profiles_at(i);
    ui_row *r = &all[n++];
    r->profile = (int)i;
    r->mount = -1;
    r->group = (int)ui_mv_group_of_scope(p->scope);
    for (j = 0; j < g_app.model.count; j++) {
      if (p->id[0] && strcmp(g_app.model.items[j].profile_id, p->id) == 0) {
        r->mount = (int)j;
        break;
      }
    }
  }
  for (j = 0; j < g_app.model.count && n < UI_ROWS_MAX; j++) {
    const ui_mount *m = &g_app.model.items[j];
    if (m->profile_id[0] && ui_profiles_find_id(m->profile_id) != NULL)
      continue;
    all[n].profile = -1;
    all[n].mount = (int)j;
    all[n].group = (int)ui_mv_group_of_scope(-1);
    n++;
  }
  g_nrows = 0;
  for (g = 0; g < (int)UI_MV_GROUPS; g++)
    for (i = 0; i < n; i++)
      if (all[i].group == g)
        g_rows[g_nrows++] = all[i];
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

/* The text of the Status cell: "Reconnecting (3)" while the connection retries, otherwise the state. */
static void status_text(const ui_mount *m, wchar_t *out, size_t cch)
{
  if (m == NULL) {
    wcsncpy_s(out, cch, sd_l10n_get(SD_MSG_UI_MAIN_NOT_MOUNTED), _TRUNCATE);
    return;
  }
  if (ui_mv_status_of(m->state, m->session, m->attempt) == UI_MV_ST_RECONNECTING) {
    sd_arg a[1];
    wchar_t *t;
    a[0].name = "attempt";
    a[0].type = SD_ARG_INT;
    a[0].v.i = (long long)m->attempt;
    t = sd_l10n_format_alloc(SD_MSG_UI_MAIN_STATUS_RECONNECTING, a, 1);
    if (t != NULL) {
      wcsncpy_s(out, cch, t, _TRUNCATE);
      sd_free(t);
      return;
    }
  }
  wcsncpy_s(out, cch, ui_model_state_text(m), _TRUNCATE);
}

/* The text of the Security cell (7.5, 7.6). */
static const wchar_t *security_text(unsigned sec)
{
  if ((sec & UI_MV_SEC_LEGACY) && (sec & UI_MV_SEC_TERRAPIN))
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_BOTH);
  if (sec & UI_MV_SEC_TERRAPIN)
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_TERRAPIN);
  if (sec & UI_MV_SEC_LEGACY)
    return sd_l10n_get(SD_MSG_UI_MAIN_SEC_LEGACY);
  return L"";
}

static void enable_tb(int id, int on)
{
  if (g_app.toolbar)
    SendMessageW(g_app.toolbar, TB_ENABLEBUTTON, (WPARAM)id, MAKELPARAM(on ? TRUE : FALSE, 0));
}

static void enable_menu(UINT id, int on)
{
  HMENU bar = g_app.main ? GetMenu(g_app.main) : NULL;
  if (bar)
    EnableMenuItem(bar, id, MF_BYCOMMAND | (on ? MF_ENABLED : MF_GRAYED));
}

static void update_buttons(void)
{
  const ui_row *r = selected_row();
  int mounted = r != NULL && r->mount >= 0;
  int has_profile = r != NULL && r->profile >= 0;
  int secure = mounted && g_app.model.items[r->mount].sec != 0;

  enable_tb(UI_CMD_NEW, TRUE);
  enable_tb(UI_CMD_EDIT, has_profile);
  enable_tb(UI_CMD_DELETE, has_profile);
  enable_tb(UI_CMD_MOUNT, has_profile && !mounted && g_app.agent_up);
  enable_tb(UI_CMD_UNMOUNT, mounted && g_app.agent_up);
  enable_tb(UI_CMD_OPEN_DRIVE, mounted);
  enable_tb(UI_CMD_HOSTKEYS, TRUE);
  enable_tb(UI_CMD_LOGS, TRUE);
  enable_menu(UI_CMD_DUPLICATE, has_profile);
  enable_menu(UI_CMD_QUICK_MOUNT, TRUE);
  enable_menu(UI_CMD_IMPORT, TRUE);
  enable_menu(UI_CMD_REFRESH, g_app.agent_up);
  enable_menu(UI_CMD_SECURITY, secure);
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

/* One group header for each group that has rows. Without group view support the list stays flat. */
static void insert_groups(void)
{
  static const sd_msg_id titles[UI_MV_GROUPS] = { SD_MSG_UI_MAIN_GROUP_MINE, SD_MSG_UI_MAIN_GROUP_ORG,
                                                  SD_MSG_UI_MAIN_GROUP_GLOBAL };
  int used[UI_MV_GROUPS] = { 0, 0, 0 };
  size_t i;
  int g;
  for (i = 0; i < g_nrows; i++)
    used[g_rows[i].group] = 1;
  SendMessageW(g_app.list, LVM_REMOVEALLGROUPS, 0, 0);
  for (g = 0; g < (int)UI_MV_GROUPS; g++) {
    ui_lvgroup grp;
    if (!used[g])
      continue;
    memset(&grp, 0, sizeof(grp));
    grp.cbSize = sizeof(grp);
    grp.mask = UI_LVGF_HEADER | UI_LVGF_GROUPID;
    grp.pszHeader = (LPWSTR)sd_l10n_get(titles[g]);
    grp.cchHeader = (int)wcslen(grp.pszHeader);
    grp.iGroupId = g;
    SendMessageW(g_app.list, LVM_INSERTGROUP, (WPARAM)-1, (LPARAM)&grp);
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
  if (g_groups_on)
    insert_groups();
  for (i = 0; i < g_nrows; i++) {
    const ui_row *row = &g_rows[i];
    const ui_mount *m = row->mount >= 0 ? &g_app.model.items[row->mount] : NULL;
    const sd_profile *p = row->profile >= 0 ? ui_profiles_at((size_t)row->profile) : NULL;
    wchar_t name[160], server[300], status[96];
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
    status_text(m, status, SD_COUNTOF(status));
    cells[0] = name;
    cells[1] = server;
    cells[2] = m ? m->drive : L"";
    cells[3] = m ? m->backend : L"";
    cells[UI_COL_STATUS] = status;
    cells[UI_COL_SECURITY] = m ? security_text(m->sec) : L"";
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT | (g_groups_on ? LVIF_GROUPID : 0);
    it.iItem = (int)i;
    it.pszText = (LPWSTR)cells[0];
    it.iGroupId = row->group;
    SendMessageW(g_app.list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    for (j = 1; j < UI_COLUMNS; j++) {
      LVITEMW sub;
      memset(&sub, 0, sizeof(sub));
      sub.mask = LVIF_TEXT;
      sub.iItem = (int)i;
      sub.iSubItem = j;
      sub.pszText = (LPWSTR)cells[j];
      if (j == UI_COL_STATUS && m != NULL) {
        sub.iImage = image_of(ui_mv_status_icon(ui_mv_status_of(m->state, m->session, m->attempt)));
        if (sub.iImage >= 0)
          sub.mask |= LVIF_IMAGE;
      } else if (j == UI_COL_SECURITY && m != NULL) {
        sub.iImage = image_of(ui_mv_sec_icon(m->sec));
        if (sub.iImage >= 0)
          sub.mask |= LVIF_IMAGE;
      }
      SendMessageW(g_app.list, LVM_SETITEMW, 0, (LPARAM)&sub);
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

static void do_security_details(void)
{
  const ui_mount *m = ui_main_selected_mount();
  if (m && m->sec != 0)
    ui_secdlg_open(g_app.main, m->drive);
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
  case UI_CMD_SECURITY:    do_security_details(); break;
  case UI_CMD_HOSTKEYS:
  case UI_CMD_LOGS:
  case UI_CMD_SETTINGS:
  case UI_CMD_SERVICE:
  case UI_CMD_EVENTS:
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
  build_images();
  set_columns();
  layout(hwnd);
}

static HMENU build_menu(void)
{
  HMENU bar = CreateMenu();
  HMENU conn = CreatePopupMenu();
  HMENU tools = CreatePopupMenu();
  HMENU help = CreatePopupMenu();
  if (bar == NULL || conn == NULL || tools == NULL || help == NULL) {
    if (bar) DestroyMenu(bar);
    if (conn) DestroyMenu(conn);
    if (tools) DestroyMenu(tools);
    if (help) DestroyMenu(help);
    return NULL;
  }
  AppendMenuW(conn, MF_STRING, UI_CMD_DUPLICATE, sd_l10n_get(SD_MSG_UI_MAIN_DUPLICATE));
  AppendMenuW(conn, MF_STRING, UI_CMD_QUICK_MOUNT, sd_l10n_get(SD_MSG_UI_MAIN_QUICK_MOUNT));
  AppendMenuW(conn, MF_STRING, UI_CMD_IMPORT, sd_l10n_get(SD_MSG_UI_MAIN_IMPORT));
  AppendMenuW(conn, MF_SEPARATOR, 0, NULL);
  AppendMenuW(conn, MF_STRING, UI_CMD_SECURITY, sd_l10n_get(SD_MSG_UI_MENU_SECURITY));
  AppendMenuW(conn, MF_SEPARATOR, 0, NULL);
  AppendMenuW(conn, MF_STRING, UI_CMD_REFRESH, sd_l10n_get(SD_MSG_UI_MAIN_REFRESH));
  AppendMenuW(tools, MF_STRING, UI_CMD_HOSTKEYS, sd_l10n_get(SD_MSG_UI_MENU_HOSTKEYS));
  AppendMenuW(tools, MF_STRING, UI_CMD_LOGS, sd_l10n_get(SD_MSG_UI_MENU_LOGS));
  AppendMenuW(tools, MF_STRING, UI_CMD_EVENTS, sd_l10n_get(SD_MSG_UI_MENU_EVENTS));
  AppendMenuW(tools, MF_STRING, UI_CMD_SERVICE, sd_l10n_get(SD_MSG_UI_MENU_SERVICE));
  AppendMenuW(tools, MF_SEPARATOR, 0, NULL);
  AppendMenuW(tools, MF_STRING, UI_CMD_SETTINGS, sd_l10n_get(SD_MSG_UI_MENU_SETTINGS));
  AppendMenuW(help, MF_STRING, UI_CMD_ABOUT, sd_l10n_get(SD_MSG_UI_MENU_ABOUT));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)conn, sd_l10n_get(SD_MSG_UI_MENU_CONNECTION));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)tools, sd_l10n_get(SD_MSG_UI_MENU_TOOLS));
  AppendMenuW(bar, MF_POPUP, (UINT_PTR)help, sd_l10n_get(SD_MSG_UI_MENU_HELP));
  return bar;
}

/* The toolbar of 7.5: text buttons, no icons. Separators group the connection, the drive and the tools. */
static HWND make_toolbar(HWND parent)
{
  static const struct { int cmd; sd_msg_id text; } k_buttons[] = {
    { UI_CMD_NEW, SD_MSG_UI_MAIN_NEW },       { UI_CMD_EDIT, SD_MSG_UI_MAIN_EDIT },
    { UI_CMD_DELETE, SD_MSG_UI_MAIN_DELETE }, { 0, 0 },
    { UI_CMD_MOUNT, SD_MSG_UI_MAIN_MOUNT },   { UI_CMD_UNMOUNT, SD_MSG_UI_MAIN_UNMOUNT },
    { UI_CMD_OPEN_DRIVE, SD_MSG_UI_MAIN_OPEN }, { 0, 0 },
    { UI_CMD_HOSTKEYS, SD_MSG_UI_MENU_HOSTKEYS }, { UI_CMD_LOGS, SD_MSG_UI_MENU_LOGS }
  };
  HWND tb;
  TBBUTTON b[SD_COUNTOF(k_buttons)];
  size_t i;

  tb = CreateWindowExW(0, TOOLBARCLASSNAMEW, L"",
                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBSTYLE_FLAT | TBSTYLE_LIST | TBSTYLE_WRAPABLE |
                           CCS_NODIVIDER | CCS_NOPARENTALIGN | CCS_NORESIZE,
                       0, 0, 10, 10, parent, (HMENU)(UINT_PTR)UI_CTL_TOOLBAR, g_app.inst, NULL);
  if (tb == NULL)
    return NULL;
  SendMessageW(tb, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
  memset(b, 0, sizeof(b));
  for (i = 0; i < SD_COUNTOF(k_buttons); i++) {
    if (k_buttons[i].cmd == 0) {
      b[i].fsStyle = BTNS_SEP;
      continue;
    }
    b[i].iBitmap = I_IMAGENONE;
    b[i].idCommand = k_buttons[i].cmd;
    b[i].fsState = TBSTATE_ENABLED;
    b[i].fsStyle = BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT;
    b[i].iString = (INT_PTR)sd_l10n_get(k_buttons[i].text);
  }
  SendMessageW(tb, TB_ADDBUTTONSW, (WPARAM)SD_COUNTOF(k_buttons), (LPARAM)b);
  return tb;
}

static int on_create(HWND hwnd)
{
  LVCOLUMNW col;
  int i;

  g_app.dpi = ui_dpi_window(hwnd);
  g_app.font = make_font(g_app.dpi);
  SetMenu(hwnd, build_menu());

  g_app.toolbar = make_toolbar(hwnd);
  g_app.list = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                   LVS_SHOWSELALWAYS,
                               0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)UI_CTL_LIST, g_app.inst, NULL);
  g_app.status = CreateWindowExW(0, L"msctls_statusbar32", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                 (HMENU)(UINT_PTR)UI_CTL_STATUS, g_app.inst, NULL);
  if (!g_app.toolbar || !g_app.list || !g_app.status)
    return -1;

  SendMessageW(g_app.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
               LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_SUBITEMIMAGES | LVS_EX_DOUBLEBUFFER);
  /* groups need comctl32 v6; the message fails (negative) on an older control and the list stays flat (XP without the
     manifest cannot happen, the manifest is part of the executable; this keeps a failure from hiding the rows) */
  g_groups_on = (int)SendMessageW(g_app.list, LVM_ENABLEGROUPVIEW, TRUE, 0) >= 0;
  build_images();
  for (i = 0; i < UI_COLUMNS; i++) {
    const wchar_t *text;
    switch (i) {
    case 0: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_NAME); break;
    case 1: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SERVER); break;
    case 2: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_DRIVE); break;
    case 3: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_BACKEND); break;
    case 4: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_STATE); break;
    default: text = sd_l10n_get(SD_MSG_UI_MAIN_COL_SECURITY); break;
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
    if (g_images) {
      ImageList_Destroy(g_images);
      g_images = NULL;
    }
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

/* --test-window: the toolbar has its eight buttons, the list its six columns and the image list, and the menu
   has the Connection items. Groups are reported only when the control supports them (always with the v6 manifest). */
int ui_main_test_controls(void)
{
  static const int k_cmds[UI_TB_BUTTONS] = { UI_CMD_NEW, UI_CMD_EDIT, UI_CMD_DELETE, UI_CMD_MOUNT, UI_CMD_UNMOUNT,
                                             UI_CMD_OPEN_DRIVE, UI_CMD_HOSTKEYS, UI_CMD_LOGS };
  HWND header;
  HMENU bar;
  int i;
  if (!g_app.list || !g_app.status || !g_app.toolbar || !IsWindow(g_app.list) || !IsWindow(g_app.status) ||
      !IsWindow(g_app.toolbar))
    return 0;
  for (i = 0; i < UI_TB_BUTTONS; i++)
    if (SendMessageW(g_app.toolbar, TB_COMMANDTOINDEX, (WPARAM)k_cmds[i], 0) < 0)
      return 0;
  /* eight buttons and two separators */
  if ((int)SendMessageW(g_app.toolbar, TB_BUTTONCOUNT, 0, 0) != UI_TB_BUTTONS + 2)
    return 0;
  header = (HWND)SendMessageW(g_app.list, LVM_GETHEADER, 0, 0);
  if (header == NULL || (int)SendMessageW(header, HDM_GETITEMCOUNT, 0, 0) != UI_COLUMNS)
    return 0;
  if (g_images == NULL || (HIMAGELIST)SendMessageW(g_app.list, LVM_GETIMAGELIST, LVSIL_SMALL, 0) != g_images)
    return 0;
  bar = g_app.main ? GetMenu(g_app.main) : NULL;
  if (bar == NULL || GetMenuState(bar, UI_CMD_SECURITY, MF_BYCOMMAND) == (UINT)-1 ||
      GetMenuState(bar, UI_CMD_DUPLICATE, MF_BYCOMMAND) == (UINT)-1)
    return 0;
  return 1;
}
