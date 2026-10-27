/* shelldrive-ui: the Logs viewer (03 §10.1, §2.4.1, §7.5).
 *
 * The window tails the agent's log ring with log.tail (poll every second while it is visible, one call in
 * flight at a time). The first call returns the last 2000 records; each later call passes the cursor of the
 * previous reply, so only new records travel. The model (ui_logs_model.c) keeps the records and applies the
 * cursor rules: a reset clears the list, dropped records are reported in the status line. The level filter and
 * the search text are applied locally to the kept records. Copy selection copies the selected lines (or all of
 * them when nothing is selected); Open log folder opens the per-user log folder (3.2). */
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_logs_model.h"
#include "ui_win.h"

#define LG_ID_LEVEL     4301
#define LG_ID_SEARCH    4302
#define LG_ID_VIEW      4303
#define LG_ID_COPY      4304
#define LG_ID_FOLDER    4305
#define LG_ID_STATUS    4306
#define LG_ID_LBL_LEVEL 4307
#define LG_ID_LBL_FIND  4308
#define LG_TIMER        1
#define LG_POLL_MS      1000
#define LG_LINES_FIRST  2000
#define LG_LINES_NEXT   500
#define LG_CLIENT_W     820
#define LG_CLIENT_H     520
#define LG_DEFAULT_LEVEL 2            /* info and above: the agent's default log level */

static struct {
  HWND wnd, level, search, view, btn_copy, btn_folder, status, lbl_level, lbl_find;
  HFONT font, mono;
  unsigned dpi;
  ui_log_model model;
  int in_flight;
  int folder_hint;                    /* the "old agent" status is shown once per open */
} g_lg;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_lg.dpi);
}

static void status_text(const wchar_t *text)
{
  if (g_lg.status)
    SetWindowTextW(g_lg.status, text ? text : L"");
}

static void status_msg(sd_msg_id id)
{
  status_text(sd_l10n_get(id));
}

static void status_err(sd_msg_id id, sd_err err)
{
  wchar_t code[64];
  wchar_t *t;
  ui_text_utf8(sd_err_name(err), code, SD_COUNTOF(code));
  t = ui_format1(id, "code", code);
  if (t != NULL) {
    status_text(t);
    sd_free(t);
  }
}

static void status_count(sd_msg_id id, size_t n)
{
  wchar_t *t = ui_format_count(id, (long long)n);
  if (t != NULL) {
    status_text(t);
    sd_free(t);
  }
}

static int level_max(void)
{
  int i = (int)SendMessageW(g_lg.level, CB_GETCURSEL, 0, 0);
  return i < 0 ? LG_DEFAULT_LEVEL : i;
}

/* Rebuilds the text of the view from the model and the filters. The view keeps its place: at the end it follows
   new records, elsewhere it keeps the first visible line and the selection. */
static void rebuild_view(void)
{
  wchar_t search[256];
  wchar_t *text = NULL;
  size_t lines = 0;
  int first, len;
  DWORD sel_start = 0, sel_end = 0;
  int at_end;

  GetWindowTextW(g_lg.search, search, SD_COUNTOF(search));
  if (ui_logs_build_text(&g_lg.model, level_max(), search, &text, &lines) != SD_OK)
    return;
  first = (int)SendMessageW(g_lg.view, EM_GETFIRSTVISIBLELINE, 0, 0);
  SendMessageW(g_lg.view, EM_GETSEL, (WPARAM)&sel_start, (LPARAM)&sel_end);
  len = GetWindowTextLengthW(g_lg.view);
  at_end = len == 0 || (int)sel_end >= len;

  SendMessageW(g_lg.view, WM_SETREDRAW, FALSE, 0);
  SetWindowTextW(g_lg.view, text);
  if (at_end) {
    int n = GetWindowTextLengthW(g_lg.view);
    SendMessageW(g_lg.view, EM_SETSEL, (WPARAM)n, (LPARAM)n);
    SendMessageW(g_lg.view, EM_SCROLLCARET, 0, 0);
  } else {
    int now = (int)SendMessageW(g_lg.view, EM_GETFIRSTVISIBLELINE, 0, 0);
    SendMessageW(g_lg.view, EM_SETSEL, sel_start, sel_end);
    if (first > now)
      SendMessageW(g_lg.view, EM_LINESCROLL, 0, first - now);
  }
  SendMessageW(g_lg.view, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_lg.view, NULL, TRUE);
  sd_free(text);
  status_count(SD_MSG_UI_LOGS_STATUS_COUNT, lines);
}

static void poll(void)
{
  char params[160];
  if (g_lg.wnd == NULL || !IsWindowVisible(g_lg.wnd) || IsIconic(g_lg.wnd))
    return;
  if (g_lg.in_flight)
    return;
  if (!g_app.agent_up) {
    status_msg(SD_MSG_UI_LOGS_AGENT_DOWN);
    return;
  }
  if ((g_app.agent_features & UI_FEAT_LOG_TAIL) == 0) {
    if (!g_lg.folder_hint)
      status_msg(SD_MSG_UI_LOGS_OLD_AGENT);
    g_lg.folder_hint = 1;
    return;
  }
  if (g_lg.model.cursor[0] != '\0')
    sprintf_s(params, sizeof(params), "{\"cursor\":\"%s\",\"lines\":%d}", g_lg.model.cursor, LG_LINES_NEXT);
  else
    sprintf_s(params, sizeof(params), "{\"lines\":%d}", LG_LINES_FIRST);
  if (ui_ipc_call(UI_IPC_LOG, "log.tail", params) == SD_OK)
    g_lg.in_flight = 1;
}

void ui_logs_on_reply(sd_err err, const sd_json *result)
{
  size_t added = 0;
  int before;
  g_lg.in_flight = 0;
  if (g_lg.wnd == NULL)
    return;
  if (err != SD_OK) {
    if (err == SD_E_DISCONNECTED)
      status_msg(SD_MSG_UI_LOGS_AGENT_DOWN);
    else
      status_err(SD_MSG_UI_LOGS_READ_FAILED, err);
    return;
  }
  before = (int)g_lg.model.count;
  if (ui_logs_model_apply(&g_lg.model, result, &added) != SD_OK) {
    status_msg(SD_MSG_UI_LOGS_BAD_REPLY);
    return;
  }
  if (added || before != (int)g_lg.model.count || g_lg.model.reset)
    rebuild_view();
  if (g_lg.model.dropped > 0)
    status_count(SD_MSG_UI_LOGS_DROPPED, (size_t)g_lg.model.dropped);
}

void ui_logs_on_agent_state(int up)
{
  if (g_lg.wnd == NULL)
    return;
  if (!up) {
    g_lg.in_flight = 0;
    status_msg(SD_MSG_UI_LOGS_AGENT_DOWN);
  }
  g_lg.folder_hint = 0;
  poll();
}

static void copy_selection(void)
{
  DWORD s = 0, e = 0;
  int len = GetWindowTextLengthW(g_lg.view);
  wchar_t *buf;
  size_t n;
  if (len <= 0)
    return;
  buf = (wchar_t *)sd_alloc(((size_t)len + 1) * sizeof(wchar_t));
  if (buf == NULL)
    return;
  GetWindowTextW(g_lg.view, buf, len + 1);
  SendMessageW(g_lg.view, EM_GETSEL, (WPARAM)&s, (LPARAM)&e);
  if (e > s && (int)e <= len) {
    n = e - s;
    ui_win_copy_text(g_lg.wnd, buf + s, n);
  } else {
    ui_win_copy_text(g_lg.wnd, buf, (size_t)len);
  }
  sd_free(buf);
}

static void open_folder(void)
{
  wchar_t path[MAX_PATH];
  HINSTANCE r;
  if (sd_config_logs_dir(path, SD_COUNTOF(path)) != SD_OK) {
    status_msg(SD_MSG_UI_LOGS_OPEN_FAILED);
    return;
  }
  r = ShellExecuteW(g_lg.wnd, L"open", path, NULL, NULL, SW_SHOWNORMAL);
  if ((INT_PTR)r <= 32)
    status_msg(SD_MSG_UI_LOGS_OPEN_FAILED);
}

static void layout(HWND hwnd)
{
  RECT rc;
  int m, rh, sh, bh, W, H, y, by, lw1, lw2, x;
  if (!g_lg.view || !g_lg.status)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(8);
  rh = dpx(24);
  sh = dpx(20);
  bh = dpx(26);

  lw1 = ui_win_text_width(g_lg.font, sd_l10n_get(SD_MSG_UI_LOGS_LEVEL_LABEL)) + dpx(8);
  MoveWindow(g_lg.lbl_level, m, m + dpx(4), lw1, rh, TRUE);
  x = m + lw1;
  MoveWindow(g_lg.level, x, m, dpx(230), dpx(200), TRUE);
  x += dpx(230) + m;
  lw2 = ui_win_text_width(g_lg.font, sd_l10n_get(SD_MSG_UI_LOGS_SEARCH_LABEL)) + dpx(8);
  MoveWindow(g_lg.lbl_find, x, m + dpx(4), lw2, rh, TRUE);
  x += lw2;
  MoveWindow(g_lg.search, x, m, W - x - m > 0 ? W - x - m : 0, rh, TRUE);

  y = m + rh + m;
  MoveWindow(g_lg.status, m, H - m - sh, W - 2 * m > 0 ? W - 2 * m : 0, sh, TRUE);
  by = H - m - sh - m - bh;
  MoveWindow(g_lg.btn_copy, m, by, ui_win_text_width(g_lg.font, sd_l10n_get(SD_MSG_UI_LOGS_BTN_COPY)) + dpx(32),
             bh, TRUE);
  x = m + ui_win_text_width(g_lg.font, sd_l10n_get(SD_MSG_UI_LOGS_BTN_COPY)) + dpx(32) + m;
  MoveWindow(g_lg.btn_folder, x, by,
             ui_win_text_width(g_lg.font, sd_l10n_get(SD_MSG_UI_LOGS_BTN_FOLDER)) + dpx(32), bh, TRUE);
  MoveWindow(g_lg.view, m, y, W - 2 * m > 0 ? W - 2 * m : 0, by - m - y > 0 ? by - m - y : 0, TRUE);
}

static void on_command(WORD id, WORD code)
{
  if (id == LG_ID_LEVEL && code == CBN_SELCHANGE) {
    rebuild_view();
  } else if (id == LG_ID_SEARCH && code == EN_CHANGE) {
    rebuild_view();
  } else if (id == LG_ID_COPY && code == BN_CLICKED) {
    copy_selection();
  } else if (id == LG_ID_FOLDER && code == BN_CLICKED) {
    open_folder();
  }
}

static void create_children(HWND hwnd)
{
  HINSTANCE inst = g_app.inst;
  size_t i;
  static const sd_msg_id levels[5] = {
    SD_MSG_UI_LOGS_LEVEL_ERROR, SD_MSG_UI_LOGS_LEVEL_WARN, SD_MSG_UI_LOGS_LEVEL_INFO,
    SD_MSG_UI_LOGS_LEVEL_DEBUG, SD_MSG_UI_LOGS_LEVEL_TRACE
  };

  g_lg.lbl_level = CreateWindowExW(0, L"STATIC", sd_l10n_get(SD_MSG_UI_LOGS_LEVEL_LABEL),
                                   WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                                   (HMENU)(UINT_PTR)LG_ID_LBL_LEVEL, inst, NULL);
  g_lg.level = CreateWindowExW(0, L"COMBOBOX", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST, 0, 0, 10, 10,
                               hwnd, (HMENU)(UINT_PTR)LG_ID_LEVEL, inst, NULL);
  g_lg.lbl_find = CreateWindowExW(0, L"STATIC", sd_l10n_get(SD_MSG_UI_LOGS_SEARCH_LABEL),
                                  WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                                  (HMENU)(UINT_PTR)LG_ID_LBL_FIND, inst, NULL);
  g_lg.search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 10, 10, hwnd,
                                (HMENU)(UINT_PTR)LG_ID_SEARCH, inst, NULL);
  g_lg.view = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                  ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL,
                              0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)LG_ID_VIEW, inst, NULL);
  g_lg.btn_copy = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_LOGS_BTN_COPY),
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                  (HMENU)(UINT_PTR)LG_ID_COPY, inst, NULL);
  g_lg.btn_folder = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_LOGS_BTN_FOLDER),
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                    (HMENU)(UINT_PTR)LG_ID_FOLDER, inst, NULL);
  g_lg.status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10,
                                hwnd, (HMENU)(UINT_PTR)LG_ID_STATUS, inst, NULL);

  for (i = 0; i < 5; i++)
    SendMessageW(g_lg.level, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(levels[i]));
  SendMessageW(g_lg.level, CB_SETCURSEL, LG_DEFAULT_LEVEL, 0);
  SendMessageW(g_lg.view, EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFEu, 0);
  SendMessageW(g_lg.view, WM_SETFONT, (WPARAM)g_lg.mono, MAKELPARAM(TRUE, 0));
  ui_win_apply_font(hwnd, g_lg.font);
  SendMessageW(g_lg.view, WM_SETFONT, (WPARAM)g_lg.mono, MAKELPARAM(TRUE, 0));
}

static HFONT make_mono(unsigned dpi)
{
  return CreateFontW(-ui_dpi_scale(13, dpi), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                     OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
                     L"Courier New");
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_lg.font, oldm = g_lg.mono;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_lg.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_lg.font = ui_win_font(dpi);
  g_lg.mono = make_mono(dpi);
  ui_win_apply_font(hwnd, g_lg.font);
  SendMessageW(g_lg.view, WM_SETFONT, (WPARAM)g_lg.mono, MAKELPARAM(TRUE, 0));
  if (old)
    DeleteObject(old);
  if (oldm)
    DeleteObject(oldm);
  layout(hwnd);
}

static LRESULT CALLBACK lg_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_lg.wnd = hwnd;
    g_lg.dpi = ui_dpi_window(hwnd);
    g_lg.font = ui_win_font(g_lg.dpi);
    g_lg.mono = make_mono(g_lg.dpi);
    create_children(hwnd);
    layout(hwnd);
    SetTimer(hwnd, LG_TIMER, LG_POLL_MS, NULL);
    status_msg(g_app.agent_up ? SD_MSG_UI_LOGS_LOADING : SD_MSG_UI_LOGS_AGENT_DOWN);
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    on_command(LOWORD(wp), HIWORD(wp));
    return 0;
  case WM_TIMER:
    if (wp == LG_TIMER)
      poll();
    return 0;
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    KillTimer(hwnd, LG_TIMER);
    if (g_lg.font)
      DeleteObject(g_lg.font);
    if (g_lg.mono)
      DeleteObject(g_lg.mono);
    ui_logs_model_free(&g_lg.model);
    memset(&g_lg, 0, sizeof(g_lg));
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
  ui_win_class_name(L"logs", cls);
  if (!ui_win_register(g_app.inst, cls, lg_proc))
    return NULL;
  if (g_lg.wnd != NULL && IsWindow(g_lg.wnd))
    return g_lg.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_LOGS_TITLE), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, LG_CLIENT_W, LG_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(LG_CLIENT_W, ui_dpi_window(w)),
               ui_dpi_scale(LG_CLIENT_H, ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(w, SW_SHOW);
  return w;
}

void ui_logs_open(void)
{
  HWND w;
  if (g_lg.wnd != NULL && IsWindow(g_lg.wnd)) {
    ShowWindow(g_lg.wnd, IsIconic(g_lg.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_lg.wnd);
    poll();
    return;
  }
  ui_logs_model_init(&g_lg.model);
  w = create_window(1);
  if (w != NULL)
    poll();
}

void ui_logs_close(void)
{
  if (g_lg.wnd != NULL && IsWindow(g_lg.wnd))
    DestroyWindow(g_lg.wnd);
}

HWND ui_logs_create_hidden(void)
{
  return create_window(0);
}
