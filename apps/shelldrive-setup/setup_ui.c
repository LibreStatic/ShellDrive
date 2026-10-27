/* shelldrive-setup: the wizard window (see setup_ui.h). Only user32, gdi32 and shell32 (KnownDLLs, already imported by
   the stub). No common controls, so the stub needs no comctl32 import (04 §2.4). The folder dialog and the item
   list helpers are resolved at run time (SHBrowseForFolderW, SHGetPathFromIDListW, CoTaskMemFree), not imported. */
#include "setup_int.h"

#include <shlobj.h>
#include <string.h>

#include "sd_l10n/sd_l10n.h"
#include "setup_flow.h"
#include "setup_ui.h"

#define SD_UI_CLASS      L"ShellDriveSetupWindow"
#define SD_UI_CLIENT_W   500
#define SD_UI_CLIENT_H   330
#define SD_UI_MARGIN     16
#define SD_UI_TEXT_ID    101           /* progress status line */
#define SD_UI_MAX_PAGE   24            /* child windows of one page */
#define SD_UI_HISTORY    16            /* pages remembered for Back */
#define SD_UI_BAR_TOP    110
#define SD_UI_BAR_H      18
#define SD_UI_BTN_Y      290
#define SD_UI_BTN_H      26
#define SD_UI_BTN_W      96

/* Control ids of the pages (the fixed buttons use the ones below them). */
enum {
  SD_ID_TITLE = 201, SD_ID_BODY, SD_ID_BODY2, SD_ID_NOTE, SD_ID_EDIT, SD_ID_BROWSE, SD_ID_OPT, SD_ID_LAUNCH,
  SD_ID_R_USER, SD_ID_R_MACHINE, SD_ID_R_PORTABLE, SD_ID_LICENSE, SD_ID_REASON,
  SD_ID_BACK = 301, SD_ID_NEXT, SD_ID_CANCEL
};

/* Result of the last button press or window message of a page. */
enum { SD_ACT_NONE = 0, SD_ACT_BACK, SD_ACT_NEXT, SD_ACT_CANCEL };

struct sd_setup_ui {
  HWND hwnd;
  HINSTANCE inst;
  HFONT font;
  HWND back, next, cancel;       /* fixed buttons, shown per page */
  HWND page[SD_UI_MAX_PAGE];     /* children of the current page, destroyed when the page is left */
  size_t npage;
  HWND status;                   /* progress status line */
  HWND radio_user, radio_machine, radio_portable, edit, opt, launch;
  unsigned percent;
  int closed;
  int action;
  int failed;                    /* a control of a page could not be created */
  int progress;                  /* the progress view is shown */
  sd_flow_page shown;            /* the page on the screen */
  wchar_t portable_dir[MAX_PATH];
  wchar_t uninstall_dir[MAX_PATH];
  sd_setup_dokany_plan dokany_plan;
  sd_setup_mode default_mode;
};

/* Folder dialog and item-list helpers: shell32 and ole32 entry points resolved at run time (04 §2.4). */
typedef LPITEMIDLIST (WINAPI *sd_SHBrowseForFolderW_t)(LPBROWSEINFOW);
typedef BOOL (WINAPI *sd_SHGetPathFromIDListW_t)(LPCITEMIDLIST, LPWSTR);
typedef void (WINAPI *sd_CoTaskMemFree_t)(LPVOID);

static LRESULT CALLBACK ui_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
static void browse_folder(sd_setup_ui *ui);

static void bar_rect(const sd_setup_ui *ui, RECT *bar)
{
  RECT client;
  (void)ui;
  GetClientRect(ui->hwnd, &client);
  bar->left = SD_UI_MARGIN;
  bar->right = client.right - SD_UI_MARGIN;
  bar->top = SD_UI_BAR_TOP;
  bar->bottom = bar->top + SD_UI_BAR_H;
}

static LRESULT CALLBACK ui_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  sd_setup_ui *ui = (sd_setup_ui *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

  switch (msg) {
  case WM_CREATE: {
    CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
    return 0;
  }
  case WM_PAINT: {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    if (ui != NULL && ui->progress) {
      RECT bar, fill;
      HBRUSH back, front;
      bar_rect(ui, &bar);
      back = CreateSolidBrush(RGB(230, 230, 230));
      front = CreateSolidBrush(RGB(0, 120, 215));
      FillRect(dc, &bar, back);
      fill = bar;
      fill.right = bar.left + (LONG)((bar.right - bar.left) * (ui->percent > 100 ? 100 : ui->percent) / 100);
      FillRect(dc, &fill, front);
      DeleteObject(back);
      DeleteObject(front);
    }
    EndPaint(hwnd, &ps);
    return 0;
  }
  case WM_COMMAND:
    if (ui != NULL) {
      WORD id = LOWORD(wp);
      WORD code = HIWORD(wp);
      if (id == SD_ID_BACK && code == BN_CLICKED)
        ui->action = SD_ACT_BACK;
      else if (id == SD_ID_NEXT && code == BN_CLICKED)
        ui->action = SD_ACT_NEXT;
      else if (id == SD_ID_CANCEL && code == BN_CLICKED)
        ui->action = SD_ACT_CANCEL;
      else if (id == SD_ID_BROWSE && code == BN_CLICKED)
        browse_folder(ui);
      else if (id == IDOK)
        ui->action = SD_ACT_NEXT;
      else if (id == IDCANCEL)
        ui->action = SD_ACT_CANCEL;
    }
    return 0;
  case WM_CLOSE:
    if (ui != NULL) {
      ui->closed = 1;
      ui->action = SD_ACT_CANCEL;
    }
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static int register_class(HINSTANCE inst)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = ui_proc;
  wc.hInstance = inst;
  wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = SD_UI_CLASS;
  if (RegisterClassExW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    return 1;
  return 0;
}

/* ---- text ---- */

/* Formats a catalog message with the given folder. Returns buf. */
static const wchar_t *text_of(sd_msg_id id, const wchar_t *folder, wchar_t *buf, size_t cch)
{
  sd_setup_result r;
  memset(&r, 0, sizeof(r));
  if (folder != NULL)
    StringCchCopyW(r.folder, SD_SETUP_COUNTOF(r.folder), folder);
  if (sd_setup_format_message(&r, id, buf, cch) < 0)
    buf[0] = L'\0';
  return buf;
}

/* ---- controls of a page ---- */

static HWND add_child(sd_setup_ui *ui, const wchar_t *cls, const wchar_t *text, DWORD style, DWORD exstyle, int x,
                      int y, int w, int h, int id)
{
  HWND c;
  if (ui->npage >= SD_UI_MAX_PAGE) {
    ui->failed = 1;
    return NULL;
  }
  c = CreateWindowExW(exstyle, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, ui->hwnd,
                      (HMENU)(INT_PTR)id, ui->inst, NULL);
  if (c == NULL) {
    ui->failed = 1;
    return NULL;
  }
  if (ui->font != NULL)
    SendMessageW(c, WM_SETFONT, (WPARAM)ui->font, FALSE);
  ui->page[ui->npage++] = c;
  return c;
}

static HWND add_text(sd_setup_ui *ui, const wchar_t *text, int x, int y, int w, int h, int id)
{
  return add_child(ui, L"STATIC", text, SS_LEFT | SS_NOPREFIX, 0, x, y, w, h, id);
}

static HWND add_heading(sd_setup_ui *ui, sd_msg_id title)
{
  wchar_t buf[256];
  return add_text(ui, text_of(title, NULL, buf, SD_SETUP_COUNTOF(buf)), SD_UI_MARGIN, 14,
                  SD_UI_CLIENT_W - 2 * SD_UI_MARGIN, 22, SD_ID_TITLE);
}

static void clear_page(sd_setup_ui *ui)
{
  size_t i;
  for (i = 0; i < ui->npage; i++)
    DestroyWindow(ui->page[i]);
  ui->npage = 0;
  ui->radio_user = ui->radio_machine = ui->radio_portable = NULL;
  ui->edit = ui->opt = ui->launch = ui->status = NULL;
  ui->progress = 0;                /* the progress bar is painted by the progress page only */
}

/* Shows or hides the fixed buttons and sets their state for the page. */
static void set_buttons(sd_setup_ui *ui, int show, int back_on, sd_msg_id next_label)
{
  wchar_t buf[64];
  SetWindowTextW(ui->next, text_of(next_label, NULL, buf, SD_SETUP_COUNTOF(buf)));
  ShowWindow(ui->back, show ? SW_SHOW : SW_HIDE);
  ShowWindow(ui->next, show ? SW_SHOW : SW_HIDE);
  ShowWindow(ui->cancel, show ? SW_SHOW : SW_HIDE);
  EnableWindow(ui->back, back_on ? TRUE : FALSE);
}

/* The page builders. Each creates its children and sets the buttons. */

static void build_welcome(sd_setup_ui *ui, int back_on)
{
  wchar_t buf[512];
  add_heading(ui, SD_MSG_INSTALLER_WELCOME_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_WELCOME_TEXT, NULL, buf, SD_SETUP_COUNTOF(buf)), SD_UI_MARGIN, 48,
           SD_UI_CLIENT_W - 2 * SD_UI_MARGIN, 80, SD_ID_BODY);
  set_buttons(ui, 1, back_on, SD_MSG_INSTALLER_BUTTON_NEXT);
}

static void build_license(sd_setup_ui *ui, int back_on, int last)
{
  wchar_t intro[512];
  wchar_t *body, *raw;
  size_t i, k, n, cch = 8192;

  add_heading(ui, SD_MSG_INSTALLER_LICENSE_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_LICENSE_INTRO, NULL, intro, SD_SETUP_COUNTOF(intro)), SD_UI_MARGIN, 40,
           SD_UI_CLIENT_W - 2 * SD_UI_MARGIN, 34, SD_ID_BODY);

  /* The catalog keeps \n; an edit control needs \r\n. The text is copied with the breaks converted. */
  raw = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(wchar_t));
  body = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(wchar_t));
  if (raw != NULL && body != NULL) {
    text_of(SD_MSG_INSTALLER_LICENSE_TEXT, NULL, raw, cch);
    n = wcslen(raw);
    k = 0;
    for (i = 0; i < n && k + 2 < cch; i++) {
      if (raw[i] == L'\n' && (i == 0 || raw[i - 1] != L'\r'))
        body[k++] = L'\r';
      body[k++] = raw[i];
    }
    body[k] = L'\0';
    add_child(ui, L"EDIT", body, ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
              WS_EX_CLIENTEDGE, SD_UI_MARGIN, 80, SD_UI_CLIENT_W - 2 * SD_UI_MARGIN, 196, SD_ID_LICENSE);
  } else {
    ui->failed = 1;
  }
  if (raw != NULL)
    HeapFree(GetProcessHeap(), 0, raw);
  if (body != NULL)
    HeapFree(GetProcessHeap(), 0, body);
  set_buttons(ui, 1, back_on, last ? SD_MSG_INSTALLER_BUTTON_INSTALL : SD_MSG_INSTALLER_BUTTON_NEXT);
}

static void build_mode(sd_setup_ui *ui, int back_on, int last)
{
  wchar_t buf[512];
  int x = SD_UI_MARGIN, w = SD_UI_CLIENT_W - 2 * SD_UI_MARGIN;
  add_heading(ui, SD_MSG_INSTALLER_MODE_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_MODE_TEXT, NULL, buf, SD_SETUP_COUNTOF(buf)), x, 44, w, 22, SD_ID_BODY);

  ui->radio_user = add_child(ui, L"BUTTON", text_of(SD_MSG_INSTALLER_MODE_USER, NULL, buf, SD_SETUP_COUNTOF(buf)),
                             BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 0, x + 8, 84, w - 8, 22, SD_ID_R_USER);
  ui->radio_portable = add_child(ui, L"BUTTON",
                                 text_of(SD_MSG_INSTALLER_MODE_PORTABLE, NULL, buf, SD_SETUP_COUNTOF(buf)),
                                 BS_AUTORADIOBUTTON | WS_TABSTOP, 0, x + 8, 112, w - 8, 22, SD_ID_R_PORTABLE);
  /* The all-users choice is shown, disabled, with its reason (the engine refuses it in this build). */
  ui->radio_machine = add_child(ui, L"BUTTON",
                                text_of(SD_MSG_INSTALLER_MODE_MACHINE, NULL, buf, SD_SETUP_COUNTOF(buf)),
                                BS_AUTORADIOBUTTON | WS_TABSTOP | (SD_FLOW_MACHINE_AVAILABLE ? 0 : WS_DISABLED), 0,
                                x + 8, 140, w - 8, 22, SD_ID_R_MACHINE);
  add_text(ui, text_of(SD_MSG_INSTALLER_MODE_MACHINE_REASON, NULL, buf, SD_SETUP_COUNTOF(buf)), x + 28, 170, w - 28,
           44, SD_ID_REASON);

  if (ui->radio_user != NULL)
    SendMessageW(ui->radio_user, BM_SETCHECK,
                 (ui->default_mode != SD_SETUP_MODE_PORTABLE && ui->default_mode != SD_SETUP_MODE_MACHINE)
                   ? BST_CHECKED : BST_UNCHECKED, 0);
  if (ui->radio_portable != NULL)
    SendMessageW(ui->radio_portable, BM_SETCHECK,
                 ui->default_mode == SD_SETUP_MODE_PORTABLE ? BST_CHECKED : BST_UNCHECKED, 0);
  if (ui->radio_machine != NULL)
    SendMessageW(ui->radio_machine, BM_SETCHECK,
                 ui->default_mode == SD_SETUP_MODE_MACHINE ? BST_CHECKED : BST_UNCHECKED, 0);
  set_buttons(ui, 1, back_on, last ? SD_MSG_INSTALLER_BUTTON_INSTALL : SD_MSG_INSTALLER_BUTTON_NEXT);
}

/* Folder dialog of the destination page. The result goes into the edit box. */
static void browse_folder(sd_setup_ui *ui)
{
  sd_SHBrowseForFolderW_t browse = (sd_SHBrowseForFolderW_t)sd_setup_proc(L"shell32.dll", "SHBrowseForFolderW");
  sd_SHGetPathFromIDListW_t to_path = (sd_SHGetPathFromIDListW_t)sd_setup_proc(L"shell32.dll", "SHGetPathFromIDListW");
  sd_CoTaskMemFree_t free_pidl = (sd_CoTaskMemFree_t)sd_setup_proc(L"ole32.dll", "CoTaskMemFree");
  BROWSEINFOW bi;
  LPITEMIDLIST pidl;
  wchar_t path[MAX_PATH];
  wchar_t title[256];

  if (browse == NULL || to_path == NULL)
    return;
  memset(&bi, 0, sizeof(bi));
  bi.hwndOwner = ui->hwnd;
  bi.lpszTitle = text_of(SD_MSG_INSTALLER_DEST_TITLE, NULL, title, SD_SETUP_COUNTOF(title));
  bi.ulFlags = BIF_RETURNONLYFSDIRS;
  pidl = browse(&bi);
  if (pidl == NULL)
    return;
  if (to_path(pidl, path))
    SetWindowTextW(ui->edit, path);
  if (free_pidl != NULL)
    free_pidl(pidl);
}

static void build_destination(sd_setup_ui *ui, int back_on, int last)
{
  wchar_t buf[512];
  int x = SD_UI_MARGIN, w = SD_UI_CLIENT_W - 2 * SD_UI_MARGIN;
  add_heading(ui, SD_MSG_INSTALLER_DEST_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_DEST_TEXT, NULL, buf, SD_SETUP_COUNTOF(buf)), x, 44, w, 40, SD_ID_BODY);
  ui->edit = add_child(ui, L"EDIT", ui->portable_dir, ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, x, 98, 370, 24,
                       SD_ID_EDIT);
  add_child(ui, L"BUTTON", text_of(SD_MSG_INSTALLER_BUTTON_BROWSE, NULL, buf, SD_SETUP_COUNTOF(buf)),
            BS_PUSHBUTTON | WS_TABSTOP, 0, x + 380, 97, w - 380, SD_UI_BTN_H - 2, SD_ID_BROWSE);
  set_buttons(ui, 1, back_on, last ? SD_MSG_INSTALLER_BUTTON_INSTALL : SD_MSG_INSTALLER_BUTTON_NEXT);
}

static void build_dokany(sd_setup_ui *ui, int back_on, int last)
{
  wchar_t buf[512];
  sd_flow_dokany_view v;
  int x = SD_UI_MARGIN, w = SD_UI_CLIENT_W - 2 * SD_UI_MARGIN;

  sd_flow_dokany_view_of(ui->dokany_plan, &v);
  add_heading(ui, SD_MSG_INSTALLER_DOKANY_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_DOKANY_TEXT, NULL, buf, SD_SETUP_COUNTOF(buf)), x, 44, w, 120, SD_ID_BODY);
  ui->opt = add_child(ui, L"BUTTON", text_of(SD_MSG_INSTALLER_DOKANY_OPTION, NULL, buf, SD_SETUP_COUNTOF(buf)),
                      BS_AUTOCHECKBOX | WS_TABSTOP | (v.enabled ? 0 : WS_DISABLED), 0, x, 176, w, 22, SD_ID_OPT);
  if (ui->opt != NULL)
    SendMessageW(ui->opt, BM_SETCHECK, v.checked ? BST_CHECKED : BST_UNCHECKED, 0);
  if (v.has_note)
    add_text(ui, text_of(v.note, NULL, buf, SD_SETUP_COUNTOF(buf)), x + 20, 206, w - 20, 44, SD_ID_NOTE);
  set_buttons(ui, 1, back_on, last ? SD_MSG_INSTALLER_BUTTON_INSTALL : SD_MSG_INSTALLER_BUTTON_NEXT);
}

static void build_progress(sd_setup_ui *ui)
{
  ui->progress = 1;
  ui->status = add_child(ui, L"STATIC", L"", SS_LEFT | SS_NOPREFIX, 0, SD_UI_MARGIN, 56,
                         SD_UI_CLIENT_W - 2 * SD_UI_MARGIN, 40, SD_UI_TEXT_ID);
  set_buttons(ui, 0, 0, SD_MSG_INSTALLER_BUTTON_NEXT);
  InvalidateRect(ui->hwnd, NULL, TRUE);
}

static void build_finish(sd_setup_ui *ui, const wchar_t *text)
{
  wchar_t buf[512];
  int x = SD_UI_MARGIN, w = SD_UI_CLIENT_W - 2 * SD_UI_MARGIN;
  ui->progress = 0;
  add_heading(ui, SD_MSG_INSTALLER_FINISH_TITLE);
  add_text(ui, text != NULL ? text : L"", x, 44, w, 60, SD_ID_BODY);
  ui->launch = add_child(ui, L"BUTTON", text_of(SD_MSG_INSTALLER_FINISH_LAUNCH, NULL, buf, SD_SETUP_COUNTOF(buf)),
                         BS_AUTOCHECKBOX | WS_TABSTOP, 0, x, 120, w, 22, SD_ID_LAUNCH);
  if (ui->launch != NULL)
    SendMessageW(ui->launch, BM_SETCHECK, BST_CHECKED, 0);
  set_buttons(ui, 1, 0, SD_MSG_INSTALLER_BUTTON_FINISH);
  ShowWindow(ui->back, SW_HIDE);
  ShowWindow(ui->cancel, SW_HIDE);
}

static void build_uninstall(sd_setup_ui *ui, int back_on)
{
  wchar_t buf[512];
  int x = SD_UI_MARGIN, w = SD_UI_CLIENT_W - 2 * SD_UI_MARGIN;
  add_heading(ui, SD_MSG_INSTALLER_UNINSTALL_TITLE);
  add_text(ui, text_of(SD_MSG_INSTALLER_UNINSTALL_TEXT, ui->uninstall_dir, buf, SD_SETUP_COUNTOF(buf)), x, 44, w, 60,
           SD_ID_BODY);
  add_text(ui, text_of(SD_MSG_INSTALLER_UNINSTALL_QUESTION, NULL, buf, SD_SETUP_COUNTOF(buf)), x, 120, w, 44,
           SD_ID_BODY2);
  set_buttons(ui, 1, back_on, SD_MSG_INSTALLER_BUTTON_UNINSTALL);
}

/* Builds the page cur. back_on: Back has a page to return to. last: the page is the one before the progress. */
static void show_page(sd_setup_ui *ui, sd_flow_page cur, int back_on, int last)
{
  clear_page(ui);
  ui->shown = cur;
  switch (cur) {
  case SD_FLOW_WELCOME:     build_welcome(ui, back_on); break;
  case SD_FLOW_LICENSE:     build_license(ui, back_on, last); break;
  case SD_FLOW_MODE:        build_mode(ui, back_on, last); break;
  case SD_FLOW_DESTINATION: build_destination(ui, back_on, last); break;
  case SD_FLOW_DOKANY:      build_dokany(ui, back_on, last); break;
  case SD_FLOW_PROGRESS:    build_progress(ui); break;
  case SD_FLOW_FINISH:      build_finish(ui, L""); break;
  case SD_FLOW_UNINSTALL:   build_uninstall(ui, back_on); break;
  case SD_FLOW_NONE:
  default:
    break;
  }
}

/* Waits for a button press or a close. Messages for the dialog keys (Tab, Enter, Esc) go through IsDialogMessage. */
static int wait_action(sd_setup_ui *ui)
{
  MSG msg;
  ui->action = SD_ACT_NONE;
  while (ui->action == SD_ACT_NONE) {
    if (GetMessageW(&msg, NULL, 0, 0) <= 0) {
      ui->action = SD_ACT_CANCEL;
      break;
    }
    if (!IsDialogMessageW(ui->hwnd, &msg)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
  }
  return ui->action;
}

/* Reads the answers of the page that is being left. Returns 0 when the answer is not usable (stay on the page). */
static int read_page(sd_setup_ui *ui, sd_flow_page cur, sd_setup_choices *c)
{
  switch (cur) {
  case SD_FLOW_MODE:
    if (ui->radio_portable != NULL && SendMessageW(ui->radio_portable, BM_GETCHECK, 0, 0) == BST_CHECKED)
      c->mode = SD_SETUP_MODE_PORTABLE;
    else if (ui->radio_machine != NULL && SendMessageW(ui->radio_machine, BM_GETCHECK, 0, 0) == BST_CHECKED)
      c->mode = SD_SETUP_MODE_MACHINE;
    else
      c->mode = SD_SETUP_MODE_USER;
    /* the all-users choice is disabled in this build; it cannot be checked, so this is a test seam only */
    if (c->mode == SD_SETUP_MODE_MACHINE && !SD_FLOW_MACHINE_AVAILABLE)
      c->mode = SD_SETUP_MODE_USER;
    return 1;
  case SD_FLOW_DESTINATION: {
    wchar_t folder[MAX_PATH];
    GetWindowTextW(ui->edit, folder, SD_SETUP_COUNTOF(folder));
    if (folder[0] == L'\0') {
      SetFocus(ui->edit);
      return 0;
    }
    StringCchCopyW(c->portable_dir, SD_SETUP_COUNTOF(c->portable_dir), folder);
    return 1;
  }
  case SD_FLOW_DOKANY:
    c->dokany = ui->opt != NULL && SendMessageW(ui->opt, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
    return 1;
  default:
    return 1;
  }
}

/* Runs the pages of the flow. The Back history is kept here; the window shows one page at a time. */
int sd_setup_ui_run_pages(sd_setup_ui *ui, const sd_flow_input *in, const sd_setup_defaults *d, sd_setup_choices *out)
{
  sd_flow_choice fc;
  sd_flow_page history[SD_UI_HISTORY];
  size_t nh = 0;
  sd_flow_page cur;
  int act;

  if (ui == NULL || in == NULL || d == NULL || out == NULL)
    return 0;
  memset(out, 0, sizeof(*out));
  StringCchCopyW(ui->uninstall_dir, SD_SETUP_COUNTOF(ui->uninstall_dir), d->uninstall_dir ? d->uninstall_dir : L"");
  StringCchCopyW(ui->portable_dir, SD_SETUP_COUNTOF(ui->portable_dir), d->portable_dir ? d->portable_dir : L"");
  ui->dokany_plan = d->dokany_plan;
  ui->default_mode = d->mode;

  out->mode = (d->mode == SD_SETUP_MODE_AUTO) ? SD_SETUP_MODE_USER : d->mode;
  StringCchCopyW(out->portable_dir, SD_SETUP_COUNTOF(out->portable_dir), ui->portable_dir);
  cur = sd_flow_first(in);
  while (cur != SD_FLOW_NONE && cur != SD_FLOW_PROGRESS) {
    sd_flow_page next;
    int last;

    fc.mode = out->mode;
    next = sd_flow_next(in, &fc, cur);
    /* the page before the progress view: its button says Install (the mode page says Next: its answer decides) */
    last = (next == SD_FLOW_PROGRESS) && cur != SD_FLOW_MODE && cur != SD_FLOW_UNINSTALL;
    ui->failed = 0;
    show_page(ui, cur, nh > 0, last);
    if (ui->failed) {
      clear_page(ui);
      return 0;
    }
    act = wait_action(ui);
    if (act == SD_ACT_CANCEL) {
      clear_page(ui);
      return 0;
    }
    if (act == SD_ACT_BACK) {
      if (nh > 0) {
        clear_page(ui);
        cur = history[--nh];
      }
      continue;
    }
    if (!read_page(ui, cur, out))
      continue;
    if (nh < SD_UI_HISTORY)
      history[nh++] = cur;
    clear_page(ui);
    fc.mode = out->mode;
    cur = sd_flow_next(in, &fc, cur);
  }
  clear_page(ui);
  return cur == SD_FLOW_PROGRESS ? 1 : 0;
}

/* The page names, in order, written to the setup log. Nothing is answered and nothing is installed. */
int sd_setup_ui_test_pages(sd_setup_ui *ui, const sd_flow_input *in, const sd_setup_defaults *d, unsigned *built)
{
  sd_flow_choice c;
  sd_flow_page cur;
  unsigned n = 0;

  if (built != NULL)
    *built = 0;
  if (ui == NULL || in == NULL || d == NULL)
    return 0;
  StringCchCopyW(ui->uninstall_dir, SD_SETUP_COUNTOF(ui->uninstall_dir), d->uninstall_dir ? d->uninstall_dir : L"");
  StringCchCopyW(ui->portable_dir, SD_SETUP_COUNTOF(ui->portable_dir), d->portable_dir ? d->portable_dir : L"");
  ui->dokany_plan = d->dokany_plan;
  ui->default_mode = d->mode;
  c.mode = (d->mode == SD_SETUP_MODE_AUTO) ? SD_SETUP_MODE_USER : d->mode;

  ui->failed = 0;
  cur = sd_flow_first(in);
  while (cur != SD_FLOW_NONE && n < 32) {
    wchar_t name[32];
    char ascii[32];
    if (cur == SD_FLOW_PROGRESS)
      build_progress(ui);
    else if (cur == SD_FLOW_FINISH)
      build_finish(ui, L"");
    else
      show_page(ui, cur, n > 0, 0);
    if (ui->failed)
      break;
    /* the page is painted and handled once, then removed */
    sd_setup_ui_pump(ui);
    StringCchCopyA(ascii, SD_SETUP_COUNTOF(ascii), sd_flow_page_name(cur));
    sd_setup_ascii_to_wide(ascii, name, SD_SETUP_COUNTOF(name));
    sd_setup_log("test.page", name);
    clear_page(ui);
    n++;
    cur = sd_flow_next(in, &c, cur);
  }
  if (built != NULL)
    *built = n;
  return ui->failed ? 0 : 1;
}

void sd_setup_ui_begin_progress(sd_setup_ui *ui)
{
  if (ui == NULL)
    return;
  clear_page(ui);
  ui->shown = SD_FLOW_PROGRESS;
  build_progress(ui);
}

void sd_setup_ui_status(sd_setup_ui *ui, const wchar_t *text, unsigned percent)
{
  RECT bar;
  if (ui == NULL)
    return;
  ui->percent = percent;
  if (ui->status != NULL)
    SetWindowTextW(ui->status, text != NULL ? text : L"");
  if (ui->hwnd != NULL) {
    bar_rect(ui, &bar);
    InvalidateRect(ui->hwnd, &bar, TRUE);
  }
  sd_setup_ui_pump(ui);
}

int sd_setup_ui_pump(sd_setup_ui *ui)
{
  MSG msg;
  if (ui == NULL)
    return 1;
  while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return !ui->closed;
}

int sd_setup_ui_finish(sd_setup_ui *ui, const wchar_t *text, int *launch)
{
  int act;
  if (launch != NULL)
    *launch = 0;
  if (ui == NULL)
    return 0;
  clear_page(ui);
  build_finish(ui, text);
  act = wait_action(ui);
  if (act == SD_ACT_NEXT) {
    if (launch != NULL && ui->launch != NULL)
      *launch = SendMessageW(ui->launch, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0;
    return 1;
  }
  return 0;
}

void sd_setup_ui_message(HWND owner, const wchar_t *title, const wchar_t *text, int is_error)
{
  MessageBoxW(owner, text, title, MB_OK | (is_error ? MB_ICONERROR : MB_ICONINFORMATION));
}

/* Creates the window with its fixed buttons. The client area is SD_UI_CLIENT_W x SD_UI_CLIENT_H. */
int sd_setup_ui_create(HINSTANCE inst, const wchar_t *title, sd_setup_ui **out)
{
  sd_setup_ui *ui;
  RECT rc;
  DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
  wchar_t buf[64];

  *out = NULL;
  if (register_class(inst) != 0)
    return 1;
  ui = (sd_setup_ui *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ui));
  if (ui == NULL)
    return 1;
  ui->inst = inst;
  ui->font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

  SetRect(&rc, 0, 0, SD_UI_CLIENT_W, SD_UI_CLIENT_H);
  AdjustWindowRectEx(&rc, style, FALSE, 0);
  ui->hwnd = CreateWindowExW(0, SD_UI_CLASS, title, style, CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left,
                             rc.bottom - rc.top, NULL, NULL, inst, ui);
  if (ui->hwnd == NULL) {
    HeapFree(GetProcessHeap(), 0, ui);
    return 1;
  }
  ui->back = CreateWindowExW(0, L"BUTTON", text_of(SD_MSG_INSTALLER_BUTTON_BACK, NULL, buf, SD_SETUP_COUNTOF(buf)),
                             WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, SD_UI_CLIENT_W - 3 * SD_UI_BTN_W - 24 - 8,
                             SD_UI_BTN_Y, SD_UI_BTN_W, SD_UI_BTN_H, ui->hwnd, (HMENU)(INT_PTR)SD_ID_BACK, inst, NULL);
  ui->next = CreateWindowExW(0, L"BUTTON", text_of(SD_MSG_INSTALLER_BUTTON_NEXT, NULL, buf, SD_SETUP_COUNTOF(buf)),
                             WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON, SD_UI_CLIENT_W - 2 * SD_UI_BTN_W - 24,
                             SD_UI_BTN_Y, SD_UI_BTN_W, SD_UI_BTN_H, ui->hwnd, (HMENU)(INT_PTR)SD_ID_NEXT, inst, NULL);
  ui->cancel = CreateWindowExW(0, L"BUTTON", text_of(SD_MSG_INSTALLER_BUTTON_CANCEL, NULL, buf, SD_SETUP_COUNTOF(buf)),
                               WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, SD_UI_CLIENT_W - SD_UI_BTN_W - SD_UI_MARGIN,
                               SD_UI_BTN_Y, SD_UI_BTN_W, SD_UI_BTN_H, ui->hwnd, (HMENU)(INT_PTR)SD_ID_CANCEL, inst,
                               NULL);
  if (ui->back == NULL || ui->next == NULL || ui->cancel == NULL) {
    DestroyWindow(ui->hwnd);
    HeapFree(GetProcessHeap(), 0, ui);
    return 1;
  }
  SendMessageW(ui->back, WM_SETFONT, (WPARAM)ui->font, FALSE);
  SendMessageW(ui->next, WM_SETFONT, (WPARAM)ui->font, FALSE);
  SendMessageW(ui->cancel, WM_SETFONT, (WPARAM)ui->font, FALSE);
  ShowWindow(ui->back, SW_HIDE);
  ShowWindow(ui->next, SW_HIDE);
  ShowWindow(ui->cancel, SW_HIDE);
  ShowWindow(ui->hwnd, SW_SHOWNORMAL);
  UpdateWindow(ui->hwnd);
  *out = ui;
  return 0;
}

void sd_setup_ui_destroy(sd_setup_ui *ui)
{
  if (ui == NULL)
    return;
  clear_page(ui);
  if (ui->hwnd != NULL)
    DestroyWindow(ui->hwnd);
  HeapFree(GetProcessHeap(), 0, ui);
}
