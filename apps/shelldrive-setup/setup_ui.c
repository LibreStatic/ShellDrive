/* shelldrive-setup: minimal progress window (see setup_ui.h). Only user32 and gdi32 (KnownDLLs). No
   common controls, so the stub needs no comctl32 import (04 §2.4). */
#include "setup_int.h"

#include "setup_ui.h"

#include <string.h>

#define SD_UI_CLASS L"ShellDriveSetupWindow"
#define SD_UI_TEXT_ID 101

struct sd_setup_ui {
  HWND hwnd;
  HWND text;
  unsigned percent;
  int closed;
};

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
    RECT client, bar, fill;
    HBRUSH back, front;
    if (ui != NULL) {
      GetClientRect(hwnd, &client);
      bar.left = 16;
      bar.right = client.right - 16;
      bar.top = client.bottom - 34;
      bar.bottom = bar.top + 14;
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
  case WM_CLOSE:
    if (ui != NULL)
      ui->closed = 1;
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

int sd_setup_ui_create(HINSTANCE inst, const wchar_t *title, sd_setup_ui **out)
{
  sd_setup_ui *ui;
  HFONT font;
  RECT rc;

  *out = NULL;
  if (register_class(inst) != 0)
    return 1;
  ui = (sd_setup_ui *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ui));
  if (ui == NULL)
    return 1;

  SetRect(&rc, 0, 0, 440, 130);
  AdjustWindowRectEx(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);
  ui->hwnd = CreateWindowExW(0, SD_UI_CLASS, title, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top, NULL, NULL,
                             inst, ui);
  if (ui->hwnd == NULL) {
    HeapFree(GetProcessHeap(), 0, ui);
    return 1;
  }
  ui->text = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 16, 14, 404, 40, ui->hwnd,
                             (HMENU)(INT_PTR)SD_UI_TEXT_ID, inst, NULL);
  font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
  if (ui->text != NULL)
    SendMessageW(ui->text, WM_SETFONT, (WPARAM)font, FALSE);
  ShowWindow(ui->hwnd, SW_SHOWNORMAL);
  UpdateWindow(ui->hwnd);
  *out = ui;
  return 0;
}

void sd_setup_ui_status(sd_setup_ui *ui, const wchar_t *text, unsigned percent)
{
  if (ui == NULL)
    return;
  ui->percent = percent;
  SetWindowTextW(ui->text, text != NULL ? text : L"");
  InvalidateRect(ui->hwnd, NULL, TRUE);
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

void sd_setup_ui_message(HWND owner, const wchar_t *title, const wchar_t *text, int is_error)
{
  MessageBoxW(owner, text, title, MB_OK | (is_error ? MB_ICONERROR : MB_ICONINFORMATION));
}

void sd_setup_ui_destroy(sd_setup_ui *ui)
{
  if (ui == NULL)
    return;
  if (ui->hwnd != NULL)
    DestroyWindow(ui->hwnd);
  HeapFree(GetProcessHeap(), 0, ui);
}
