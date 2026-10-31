/* shelldrive-ui: the event list (03 §7.7).
 *
 * Every notification of the tray (connection state, warnings, host key problems, updates) is recorded here by
 * ui_events_record whether or not its balloon was shown, so nothing exists only as a transient balloon. The record
 * lives for the life of the process (ui_events_model.c keeps the last UI_EV_MAX entries); the window is a view of
 * it: a list with the time, the drive or server, the kind and the text, a search box, Copy list (the rows that
 * match, tab separated) and Clear. Only the UI thread calls these functions. */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dpi.h"
#include "ui_events_model.h"
#include "ui_int.h"
#include "ui_theme.h"
#include "ui_win.h"

#define EV_ID_LIST     4401
#define EV_ID_SEARCH   4402
#define EV_ID_LBL_FIND 4403
#define EV_ID_COPY     4404
#define EV_ID_CLEAR    4405
#define EV_ID_STATUS   4406
#define EV_CLIENT_W    860
#define EV_CLIENT_H    460
#define EV_COLS        4
#define EV_ALL_KINDS   ((1u << UI_EV_KINDS) - 1u)

static ui_ev_log g_log;
static int g_log_ready;

static struct {
  HWND wnd, list, search, lbl_find, btn_copy, btn_clear, status;
  HFONT font;
  unsigned dpi;
} g_ev;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_ev.dpi);
}

static void log_init_once(void)
{
  if (!g_log_ready) {
    ui_ev_init(&g_log);
    g_log_ready = 1;
  }
}

static const wchar_t *kind_label(ui_ev_kind k)
{
  static const sd_msg_id ids[UI_EV_KINDS] = {
    SD_MSG_UI_EVENTS_KIND_DRIVE, SD_MSG_UI_EVENTS_KIND_HOSTKEY, SD_MSG_UI_EVENTS_KIND_WARNING,
    SD_MSG_UI_EVENTS_KIND_ERROR, SD_MSG_UI_EVENTS_KIND_INFO
  };
  return sd_l10n_get(ids[(unsigned)k < (unsigned)UI_EV_KINDS ? k : UI_EV_INFO]);
}

static void search_text(wchar_t *out, size_t cap)
{
  out[0] = 0;
  if (g_ev.search != NULL)
    GetWindowTextW(g_ev.search, out, (int)cap);
}

static void refresh_view(void)
{
  wchar_t search[128];
  size_t i, row = 0;
  wchar_t *t;
  if (g_ev.list == NULL)
    return;
  search_text(search, SD_COUNTOF(search));
  SendMessageW(g_ev.list, WM_SETREDRAW, FALSE, 0);
  SendMessageW(g_ev.list, LVM_DELETEALLITEMS, 0, 0);
  /* newest first: the latest event is the one the user looks for */
  for (i = g_log.count; i > 0; i--) {
    const ui_ev_entry *e = ui_ev_at(&g_log, i - 1);
    wchar_t tm[UI_EV_TIME_MAX];
    LVITEMW it;
    int j;
    wchar_t *cells[EV_COLS];
    if (!ui_ev_match(e, EV_ALL_KINDS, search))
      continue;
    ui_ev_format_time(&e->time, tm);
    cells[0] = tm;
    cells[1] = (wchar_t *)e->subject;
    cells[2] = (wchar_t *)kind_label(e->kind);
    cells[3] = (wchar_t *)e->text;
    memset(&it, 0, sizeof(it));
    it.mask = LVIF_TEXT;
    it.iItem = (int)row;
    it.pszText = cells[0];
    SendMessageW(g_ev.list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    for (j = 1; j < EV_COLS; j++) {
      LVITEMW sub;
      memset(&sub, 0, sizeof(sub));
      sub.iSubItem = j;
      sub.pszText = cells[j];
      SendMessageW(g_ev.list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&sub);
    }
    row++;
  }
  SendMessageW(g_ev.list, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(g_ev.list, NULL, TRUE);
  t = ui_format_count(SD_MSG_UI_EVENTS_STATUS_COUNT, (long long)row);
  if (t != NULL) {
    SetWindowTextW(g_ev.status, t);
    sd_free(t);
  }
  EnableWindow(g_ev.btn_copy, row > 0);
  EnableWindow(g_ev.btn_clear, g_log.count > 0);
}

static void add_entry(ui_ev_kind kind, const ui_ev_time *t, const wchar_t *subject, const wchar_t *text)
{
  log_init_once();
  (void)ui_ev_add(&g_log, kind, t, subject, text);
  if (g_ev.wnd != NULL)
    refresh_view();
}

void ui_events_record(ui_ev_kind kind, const wchar_t *subject, const wchar_t *text)
{
  SYSTEMTIME st;
  ui_ev_time t;
  GetLocalTime(&st);
  t.year = st.wYear;
  t.month = st.wMonth;
  t.day = st.wDay;
  t.hour = st.wHour;
  t.minute = st.wMinute;
  t.second = st.wSecond;
  add_entry(kind, &t, subject, text);
}

void ui_events_record_at(ui_ev_kind kind, long long unix_time, const wchar_t *subject, const wchar_t *text)
{
  ULARGE_INTEGER u;
  FILETIME utc, local;
  SYSTEMTIME st;
  ui_ev_time t;
  if (unix_time <= 0) {
    ui_events_record(kind, subject, text);
    return;
  }
  /* seconds since 1970 to 100 ns ticks since 1601, then to the local time of the user */
  u.QuadPart = ((unsigned long long)unix_time + 11644473600ull) * 10000000ull;
  utc.dwLowDateTime = u.LowPart;
  utc.dwHighDateTime = u.HighPart;
  if (!FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &st)) {
    ui_events_record(kind, subject, text);
    return;
  }
  t.year = st.wYear;
  t.month = st.wMonth;
  t.day = st.wDay;
  t.hour = st.wHour;
  t.minute = st.wMinute;
  t.second = st.wSecond;
  add_entry(kind, &t, subject, text);
}

size_t ui_events_count(void)
{
  log_init_once();
  return g_log.count;
}

static void copy_list(void)
{
  wchar_t search[128];
  wchar_t *text = NULL;
  const wchar_t *labels[UI_EV_KINDS];
  size_t lines = 0;
  int k;
  for (k = 0; k < UI_EV_KINDS; k++)
    labels[k] = kind_label((ui_ev_kind)k);
  search_text(search, SD_COUNTOF(search));
  if (ui_ev_build_text(&g_log, EV_ALL_KINDS, search, labels, &text, &lines) != SD_OK)
    return;
  if (lines > 0)
    ui_win_copy_text(g_ev.wnd, text, wcslen(text));
  sd_free(text);
}

static void clear_list(void)
{
  ui_ev_clear(&g_log);
  refresh_view();
}

static void set_columns(void)
{
  static const int w[EV_COLS] = { 140, 140, 100, 440 };
  int i;
  for (i = 0; i < EV_COLS; i++)
    SendMessageW(g_ev.list, LVM_SETCOLUMNWIDTH, (WPARAM)i, (LPARAM)dpx(w[i]));
}

static void layout(HWND hwnd)
{
  RECT rc;
  int m, rh, sh, bh, W, H, y, by, lw, x, bw;
  if (!g_ev.list || !g_ev.status)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(8);
  rh = dpx(24);
  sh = dpx(20);
  bh = dpx(26);
  lw = ui_win_text_width(g_ev.font, sd_l10n_get(SD_MSG_UI_LOGS_SEARCH_LABEL)) + dpx(8);
  MoveWindow(g_ev.lbl_find, m, m + dpx(4), lw, rh, TRUE);
  x = m + lw;
  MoveWindow(g_ev.search, x, m, W - x - m > 0 ? W - x - m : 0, rh, TRUE);
  y = m + rh + m;
  MoveWindow(g_ev.status, m, H - m - sh, W - 2 * m > 0 ? W - 2 * m : 0, sh, TRUE);
  by = H - m - sh - m - bh;
  bw = ui_win_text_width(g_ev.font, sd_l10n_get(SD_MSG_UI_EVENTS_BTN_COPY)) + dpx(32);
  MoveWindow(g_ev.btn_copy, m, by, bw, bh, TRUE);
  x = m + bw + m;
  bw = ui_win_text_width(g_ev.font, sd_l10n_get(SD_MSG_UI_EVENTS_BTN_CLEAR)) + dpx(32);
  MoveWindow(g_ev.btn_clear, x, by, bw, bh, TRUE);
  MoveWindow(g_ev.list, m, y, W - 2 * m > 0 ? W - 2 * m : 0, by - m - y > 0 ? by - m - y : 0, TRUE);
}

static void create_children(HWND hwnd)
{
  HINSTANCE inst = g_app.inst;
  static const sd_msg_id cols[EV_COLS] = {
    SD_MSG_UI_EVENTS_COL_TIME, SD_MSG_UI_EVENTS_COL_SUBJECT, SD_MSG_UI_EVENTS_COL_KIND, SD_MSG_UI_EVENTS_COL_TEXT
  };
  int i;
  g_ev.lbl_find = CreateWindowExW(0, L"STATIC", sd_l10n_get(SD_MSG_UI_LOGS_SEARCH_LABEL),
                                  WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                                  (HMENU)(UINT_PTR)EV_ID_LBL_FIND, inst, NULL);
  g_ev.search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 10, 10, hwnd,
                                (HMENU)(UINT_PTR)EV_ID_SEARCH, inst, NULL);
  g_ev.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                              0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)EV_ID_LIST, inst, NULL);
  g_ev.btn_copy = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_EVENTS_BTN_COPY),
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                  (HMENU)(UINT_PTR)EV_ID_COPY, inst, NULL);
  g_ev.btn_clear = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_EVENTS_BTN_CLEAR),
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                   (HMENU)(UINT_PTR)EV_ID_CLEAR, inst, NULL);
  g_ev.status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10,
                                hwnd, (HMENU)(UINT_PTR)EV_ID_STATUS, inst, NULL);
  SendMessageW(g_ev.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);
  for (i = 0; i < EV_COLS; i++) {
    LVCOLUMNW col;
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH;
    col.pszText = (LPWSTR)sd_l10n_get(cols[i]);
    col.iSubItem = i;
    col.cx = 100;
    SendMessageW(g_ev.list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col);
  }
  ui_win_apply_font(hwnd, g_ev.font);
  set_columns();
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_ev.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_ev.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_ev.font = ui_win_font(dpi);
  ui_win_apply_font(hwnd, g_ev.font);
  if (old)
    DeleteObject(old);
  set_columns();
  layout(hwnd);
}

static LRESULT CALLBACK ev_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_ev.wnd = hwnd;
    g_ev.dpi = ui_dpi_window(hwnd);
    g_ev.font = ui_win_font(g_ev.dpi);
    create_children(hwnd);
    ui_theme_apply_dialog(hwnd);
    layout(hwnd);
    refresh_view();
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    if (LOWORD(wp) == EV_ID_COPY && HIWORD(wp) == BN_CLICKED)
      copy_list();
    else if (LOWORD(wp) == EV_ID_CLEAR && HIWORD(wp) == BN_CLICKED)
      clear_list();
    else if (LOWORD(wp) == EV_ID_SEARCH && HIWORD(wp) == EN_CHANGE)
      refresh_view();
    return 0;
  case WM_CLOSE:
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    if (g_ev.font)
      DeleteObject(g_ev.font);
    memset(&g_ev, 0, sizeof(g_ev));
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
  log_init_once();
  ui_win_class_name(L"events", cls);
  if (!ui_win_register(g_app.inst, cls, ev_proc))
    return NULL;
  if (g_ev.wnd != NULL && IsWindow(g_ev.wnd))
    return g_ev.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_EVENTS_TITLE), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, EV_CLIENT_W, EV_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(EV_CLIENT_W, ui_dpi_window(w)),
               ui_dpi_scale(EV_CLIENT_H, ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible)
    ShowWindow(w, SW_SHOW);
  return w;
}

void ui_events_open(void)
{
  if (g_ev.wnd != NULL && IsWindow(g_ev.wnd)) {
    ShowWindow(g_ev.wnd, IsIconic(g_ev.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_ev.wnd);
    return;
  }
  (void)create_window(1);
}

void ui_events_close(void)
{
  if (g_ev.wnd != NULL && IsWindow(g_ev.wnd))
    DestroyWindow(g_ev.wnd);
}

HWND ui_events_create_hidden(void)
{
  return create_window(0);
}

/* --test-windows: three events show as three rows, a search narrows them, Clear empties the list. The window must
   exist (ui_events_create_hidden). */
int ui_events_controls_ok(void)
{
  static const wchar_t k_text[] = L"Smoke event";
  int ok;
  if (g_ev.list == NULL || g_ev.search == NULL)
    return 0;
  ui_ev_clear(&g_log);
  ui_events_record(UI_EV_DRIVE, L"E:", k_text);
  ui_events_record(UI_EV_WARNING, L"example.org", L"Other");
  ui_events_record(UI_EV_ERROR, L"F:", k_text);
  ok = ListView_GetItemCount(g_ev.list) == 3 && IsWindowEnabled(g_ev.btn_copy) && IsWindowEnabled(g_ev.btn_clear);
  SetWindowTextW(g_ev.search, L"smoke");
  refresh_view();
  ok = ok && ListView_GetItemCount(g_ev.list) == 2;
  /* an entry of the agent's history carries the time it happened (2001-09-09 01:46:40 UTC is 1000000000) */
  ui_events_record_at(UI_EV_DRIVE, 1000000000ll, L"G:", k_text);
  ok = ok && ListView_GetItemCount(g_ev.list) == 3;
  {
    const ui_ev_entry *e = ui_ev_at(&g_log, g_log.count - 1);
    ok = ok && e != NULL && e->time.year >= 2001 && e->time.year <= 2001 && e->time.month >= 9 && e->time.month <= 9;
  }
  SetWindowTextW(g_ev.search, L"");
  clear_list();
  ok = ok && ListView_GetItemCount(g_ev.list) == 0 && !IsWindowEnabled(g_ev.btn_copy) &&
       !IsWindowEnabled(g_ev.btn_clear);
  return ok;
}
