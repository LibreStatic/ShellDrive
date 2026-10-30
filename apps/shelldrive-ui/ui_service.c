/* shelldrive-ui: the Service page (03 §1.3, §2.4 service.status / service.repair_data, §7.5).
 *
 * A window with the status block of the service (ui_service_model.c decides what it says) and two buttons:
 * Refresh, and Repair data... which runs the repair of `shelldrive service repair-data`. Status is read in a short
 * worker thread (the SCM is queried read-only with svc_scm.c; when the service runs, service.status on its pipe adds the
 * machine data folder, the global drives and the open prompts). Repair goes through service.repair_data when the service
 * answers and runs svc_repair.c in this process otherwise; both need an elevated administrator, so a non-elevated
 * administrator gets the shield and the offer to reopen this page elevated (--elevated-service, ui_svc.c).
 *
 * The worker threads connect to the service pipe for one call and close it; they never start the service and never
 * touch a window: the result is a heap object posted to the window. */
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>

#include "sd/version.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_platform.h"
#include "svc_repair.h"
#include "svc_scm.h"
#include "ui_dpi.h"
#include "ui_int.h"
#include "ui_service_model.h"
#include "ui_win.h"

#ifndef BCM_SETSHIELD
#define BCM_SETSHIELD 0x160C            /* BCM_FIRST + 0xC: Vista; not in the SDK 7.1A headers of the XP flavours */
#endif

#define SV_ID_STATUS   4401
#define SV_ID_NOTE     4402
#define SV_ID_REFRESH  4403
#define SV_ID_REPAIR   4404
#define SV_ID_CLOSE    4405
#define SV_TIMER       1
#define SV_POLL_MS     5000
#define SV_CLIENT_W    640
#define SV_CLIENT_H    360
#define SV_CALL_MS     5000u
#define SV_REPAIR_MS   120000u

#define SV_WM_STATUS   (WM_APP + 60)    /* lParam: sv_result* of a status job */
#define SV_WM_REPAIR   (WM_APP + 61)    /* lParam: sv_result* of a repair job */

typedef struct sv_result {
  ui_svc_view view;
  int status_ok;                        /* status job: the SCM query worked */
  DWORD scm_error;
  ui_svc_repair_kind kind;              /* repair job */
  char code[64];                        /* the error name or number to show with a failure */
} sv_result;

typedef struct sv_job {
  HWND wnd;
  int repair;                           /* 0 status, 1 repair */
  ui_svc_repair_route route;
} sv_job;

static struct {
  HWND wnd, status, note, btn_refresh, btn_repair, btn_close;
  HFONT font;
  unsigned dpi;
  ui_svc_view view;
  int in_flight;
  int repairing;
  int loading;                          /* no status yet: the first read is in flight */
} g_sv;

static int dpx(int v)
{
  return ui_dpi_scale(v, g_sv.dpi);
}

/* ---- the worker: SCM and pipe, no window access ---- */

static void sv_post(HWND wnd, UINT msg, sv_result *r)
{
  if (!PostMessageW(wnd, msg, 0, (LPARAM)r))
    sd_free(r);
}

static sd_err sv_connect(sd_ipc_conn **c)
{
  sd_ipc_hello hello;
  memset(&hello, 0, sizeof(hello));
  hello.client_kind = "ui";
  hello.client_version = SD_VERSION_STRING;
  hello.lang = sd_l10n_lang_code(sd_l10n_lang());
  hello.caps = 0;
  return sd_ipc_connect(SD_IPC_SERVICE, &hello, 0, SV_CALL_MS, c);
}

/* service.status on the pipe, merged into v (the SCM part stays as the SCM said it). */
static void sv_pipe_status(ui_svc_view *v)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  ui_svc_view piped;
  memset(&err, 0, sizeof(err));
  if (sv_connect(&c) != SD_OK)
    return;
  if (sd_ipc_call_raw(c, "service.status", NULL, 0, SV_CALL_MS, &res, &err) != SD_OK) {
    /* an older service answers hello but does not know the method ("usage"): reachable, nothing more to show */
    v->pipe_reachable = strcmp(err.code, "usage") == 0 ? 1 : 0;
  } else if (ui_svc_view_from_status(&piped, res) == SD_OK) {
    v->pipe_reachable = 1;
    v->service_reports = piped.service_reports;
    v->healthy = piped.healthy;
    v->drives = piped.drives;
    v->prompts = piped.prompts;
    v->profiles = piped.profiles;
    v->machine = piped.machine;
    v->reason = piped.reason;
    wcscpy_s(v->machine_path, UI_SVC_PATH_MAX, piped.machine_path);
  }
  sd_json_free(res);
  sd_ipc_close(c);
}

static void sv_do_status(sv_result *r)
{
  svc_scm_ops ops;
  svc_install_spec spec;
  svc_status_report rep;
  int have_spec;
  DWORD e;
  svc_scm_real_ops(&ops);
  have_spec = svc_scm_host_spec(&spec, L"") == 0;
  e = svc_scm_status(&ops, have_spec ? &spec : NULL, &rep);
  if (e != 0) {
    r->scm_error = e;
    return;
  }
  r->status_ok = 1;
  ui_svc_view_from_scm(&r->view, rep.installed, rep.state, rep.start_type, rep.binary_check, rep.source_check,
                       rep.binary);
  if (rep.installed && rep.state == SERVICE_RUNNING)
    sv_pipe_status(&r->view);
}

static void sv_do_repair_pipe(sv_result *r)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_err e;
  memset(&err, 0, sizeof(err));
  e = sv_connect(&c);
  if (e != SD_OK) {
    r->kind = UI_SVC_RP_FAILED;
    strcpy_s(r->code, sizeof(r->code), sd_err_name(e));
    return;
  }
  e = sd_ipc_call_raw(c, "service.repair_data", NULL, 0, SV_REPAIR_MS, &res, &err);
  if (e == SD_OK) {
    r->kind = ui_svc_repair_kind_of_reply(res);
  } else {
    r->kind = ui_svc_repair_kind_of_error(err.code);
    strcpy_s(r->code, sizeof(r->code), err.code[0] ? err.code : sd_err_name(e));
  }
  sd_json_free(res);
  sd_ipc_close(c);
}

/* The same repair, in this process (the service is not running): needs the elevated token itself. */
static void sv_do_repair_direct(sv_result *r)
{
  svc_repair_ops ops;
  svc_repair_result rep;
  wchar_t base[MAX_PATH];
  DWORD e;
  memset(&rep, 0, sizeof(rep));
  if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base) != S_OK) {
    r->kind = UI_SVC_RP_FAILED;
    strcpy_s(r->code, sizeof(r->code), "io_error");
    return;
  }
  svc_repair_real_ops(&ops);
  e = svc_repair_data(&ops, base, &rep);
  r->kind = ui_svc_repair_kind_of_direct(rep.refused, e, rep.moved);
  if (r->kind == UI_SVC_RP_FAILED)
    sprintf_s(r->code, sizeof(r->code), "%lu", (unsigned long)e);
}

static DWORD WINAPI sv_thread(void *arg)
{
  sv_job *job = (sv_job *)arg;
  sv_result *r = (sv_result *)sd_calloc(1, sizeof(*r));
  HWND wnd = job->wnd;
  int repair = job->repair;
  ui_svc_repair_route route = job->route;
  sd_free(job);
  if (r == NULL)
    return 0;
  if (repair) {
    if (route == UI_SVC_ROUTE_PIPE)
      sv_do_repair_pipe(r);
    else
      sv_do_repair_direct(r);
    sv_post(wnd, SV_WM_REPAIR, r);
  } else {
    sv_do_status(r);
    sv_post(wnd, SV_WM_STATUS, r);
  }
  return 0;
}

static int sv_start(int repair, ui_svc_repair_route route)
{
  HANDLE h;
  sv_job *job = (sv_job *)sd_calloc(1, sizeof(*job));
  if (job == NULL)
    return 0;
  job->wnd = g_sv.wnd;
  job->repair = repair;
  job->route = route;
  h = CreateThread(NULL, 0, sv_thread, job, 0, NULL);
  if (h == NULL) {
    sd_free(job);
    return 0;
  }
  CloseHandle(h);
  return 1;
}

/* ---- the window ---- */

static sd_msg_id state_msg(int which)
{
  switch ((ui_svc_state)which) {
  case UI_SVC_ST_RUNNING: return SD_MSG_UI_SERVICE_STATE_RUNNING;
  case UI_SVC_ST_STOPPED: return SD_MSG_UI_SERVICE_STATE_STOPPED;
  case UI_SVC_ST_STARTING: return SD_MSG_UI_SERVICE_STATE_STARTING;
  case UI_SVC_ST_STOPPING: return SD_MSG_UI_SERVICE_STATE_STOPPING;
  case UI_SVC_ST_PAUSED: return SD_MSG_UI_SERVICE_STATE_PAUSED;
  default: return SD_MSG_UI_SERVICE_STATE_UNKNOWN;
  }
}

static sd_msg_id start_msg(int which)
{
  switch ((ui_svc_starttype)which) {
  case UI_SVC_START_AUTOMATIC: return SD_MSG_UI_SERVICE_START_TYPE_AUTOMATIC;
  case UI_SVC_START_MANUAL: return SD_MSG_UI_SERVICE_START_TYPE_MANUAL;
  case UI_SVC_START_DISABLED: return SD_MSG_UI_SERVICE_START_TYPE_DISABLED;
  default: return SD_MSG_UI_SERVICE_START_TYPE_UNKNOWN;
  }
}

static sd_msg_id program_msg(int which)
{
  switch (which) {
  case UI_SVC_PROGRAM_OK: return SD_MSG_UI_SERVICE_PROGRAM_OK;
  case UI_SVC_PROGRAM_UNQUOTED: return SD_MSG_UI_SERVICE_PROGRAM_UNQUOTED;
  case UI_SVC_PROGRAM_OTHER: return SD_MSG_UI_SERVICE_PROGRAM_OTHER;
  default: return SD_MSG_UI_SERVICE_PROGRAM_UNKNOWN;
  }
}

static sd_msg_id source_msg(int which)
{
  switch (which) {
  case UI_SVC_SOURCE_OK: return SD_MSG_UI_SERVICE_SOURCE_OK;
  case UI_SVC_SOURCE_MISSING: return SD_MSG_UI_SERVICE_SOURCE_MISSING;
  case UI_SVC_SOURCE_OTHER: return SD_MSG_UI_SERVICE_SOURCE_OTHER;
  default: return SD_MSG_UI_SERVICE_SOURCE_UNKNOWN;
  }
}

static sd_msg_id refused_msg(int which)
{
  switch ((ui_svc_reason)which) {
  case UI_SVC_REASON_OWNER: return SD_MSG_UI_SERVICE_MACHINE_OWNER;
  case UI_SVC_REASON_LINK: return SD_MSG_UI_SERVICE_MACHINE_LINK;
  case UI_SVC_REASON_ACL: return SD_MSG_UI_SERVICE_MACHINE_ACL;
  default: return SD_MSG_UI_SERVICE_MACHINE_OTHER;
  }
}

static wchar_t *dup_text(const wchar_t *t)
{
  size_t n = wcslen(t) + 1;
  wchar_t *c = (wchar_t *)sd_alloc(n * sizeof(wchar_t));
  if (c != NULL)
    memcpy(c, t, n * sizeof(wchar_t));
  return c;
}

/* The text of one line of the status block; the caller frees it with sd_free. */
static wchar_t *line_text(const ui_svc_line *l)
{
  switch (l->kind) {
  case UI_SVC_LINE_NOT_INSTALLED: return dup_text(sd_l10n_get(SD_MSG_UI_SERVICE_NOT_INSTALLED));
  case UI_SVC_LINE_STATE: return ui_format1(SD_MSG_UI_SERVICE_STATE_LINE, "state", sd_l10n_get(state_msg(l->which)));
  case UI_SVC_LINE_START: return ui_format1(SD_MSG_UI_SERVICE_START_LINE, "type", sd_l10n_get(start_msg(l->which)));
  case UI_SVC_LINE_PROGRAM: return ui_format1(SD_MSG_UI_SERVICE_PROGRAM_LINE, "path", l->text);
  case UI_SVC_LINE_PROGRAM_CHECK: return dup_text(sd_l10n_get(program_msg(l->which)));
  case UI_SVC_LINE_SOURCE_CHECK: return dup_text(sd_l10n_get(source_msg(l->which)));
  case UI_SVC_LINE_PIPE_DOWN: return dup_text(sd_l10n_get(SD_MSG_UI_SERVICE_PIPE_DOWN));
  case UI_SVC_LINE_OLD_SERVICE: return dup_text(sd_l10n_get(SD_MSG_UI_SERVICE_OLD_SERVICE));
  case UI_SVC_LINE_MACHINE_OK: return dup_text(sd_l10n_get(SD_MSG_UI_SERVICE_MACHINE_OK));
  case UI_SVC_LINE_MACHINE_REFUSED: return dup_text(sd_l10n_get(refused_msg(l->which)));
  case UI_SVC_LINE_MACHINE_PATH: return ui_format1(SD_MSG_UI_SERVICE_MACHINE_PATH, "path", l->text);
  case UI_SVC_LINE_DRIVES: return ui_format_count(SD_MSG_UI_SERVICE_DRIVES, l->count);
  case UI_SVC_LINE_PROMPTS: return ui_format_count(SD_MSG_UI_SERVICE_PROMPTS, l->count);
  case UI_SVC_LINE_PROFILES: return ui_format_count(SD_MSG_UI_SERVICE_PROFILES, l->count);
  default: return NULL;
  }
}

static void show_text(const wchar_t *text)
{
  if (g_sv.status)
    SetWindowTextW(g_sv.status, text ? text : L"");
}

static void show_view(void)
{
  ui_svc_line lines[UI_SVC_LINES_MAX];
  size_t n, i, total = 0;
  wchar_t *all;
  wchar_t *parts[UI_SVC_LINES_MAX];
  n = ui_svc_lines(&g_sv.view, lines);
  for (i = 0; i < n; i++) {
    parts[i] = line_text(&lines[i]);
    total += (parts[i] ? wcslen(parts[i]) : 0) + 2;
  }
  all = (wchar_t *)sd_alloc((total + 1) * sizeof(wchar_t));
  if (all == NULL) {
    for (i = 0; i < n; i++)
      sd_free(parts[i]);
    return;
  }
  all[0] = 0;
  for (i = 0; i < n; i++) {
    if (parts[i] != NULL) {
      if (all[0] != 0)
        wcscat_s(all, total + 1, L"\r\n");
      wcscat_s(all, total + 1, parts[i]);
    }
    sd_free(parts[i]);
  }
  show_text(all);
  sd_free(all);
}

static ui_svc_repair_mode current_mode(void)
{
  if (g_sv.repairing)
    return UI_SVC_REPAIR_OFF;
  return ui_svc_repair_mode_of(&g_sv.view, ui_svc_process_elevated(), g_app.user_admin);
}

/* The note under the status: why Repair data is off, or that it asks for administrator rights. */
static void update_controls(void)
{
  ui_svc_repair_mode mode = current_mode();
  sd_msg_id note = SD_MSG_UI_SERVICE_NOTE_REPAIRING;
  int has_note = 1;
  if (g_sv.btn_repair == NULL)
    return;
  EnableWindow(g_sv.btn_repair, mode != UI_SVC_REPAIR_OFF);
  SendMessageW(g_sv.btn_repair, BCM_SETSHIELD, 0, ui_svc_repair_shield(mode, sd_os_at_least(6, 0, 0)) ? 1 : 0);
  EnableWindow(g_sv.btn_refresh, !g_sv.in_flight);
  if (g_sv.repairing)
    note = SD_MSG_UI_SERVICE_NOTE_REPAIRING;
  else if (g_sv.loading)
    note = SD_MSG_UI_SERVICE_LOADING;
  else if (g_sv.view.valid && !g_app.user_admin)
    note = SD_MSG_UI_SERVICE_NOTE_ADMIN_ONLY;
  else if (mode == UI_SVC_REPAIR_ELEVATE)
    note = SD_MSG_UI_SERVICE_NOTE_ELEVATE;
  else
    has_note = 0;
  SetWindowTextW(g_sv.note, has_note ? sd_l10n_get(note) : L"");
}

static void request_status(void)
{
  if (g_sv.in_flight || g_sv.wnd == NULL)
    return;
  if (sv_start(0, UI_SVC_ROUTE_PIPE)) {
    g_sv.in_flight = 1;
    update_controls();
  }
}

static void on_status(sv_result *r)
{
  g_sv.in_flight = 0;
  g_sv.loading = 0;
  if (r->status_ok) {
    g_sv.view = r->view;
    show_view();
  } else {
    wchar_t code[24];
    wchar_t *t;
    swprintf_s(code, SD_COUNTOF(code), L"%lu", (unsigned long)r->scm_error);
    t = ui_format1(SD_MSG_UI_SERVICE_READ_FAILED, "code", code);
    if (t != NULL) {
      show_text(t);
      sd_free(t);
    }
  }
  update_controls();
}

static sd_msg_id repair_msg(ui_svc_repair_kind k)
{
  switch (k) {
  case UI_SVC_RP_DONE: return SD_MSG_UI_SERVICE_REPAIR_DONE;
  case UI_SVC_RP_MOVED: return SD_MSG_UI_SERVICE_REPAIR_MOVED;
  case UI_SVC_RP_STILL_REFUSED: return SD_MSG_UI_SERVICE_REPAIR_STILL_REFUSED;
  case UI_SVC_RP_BUSY: return SD_MSG_UI_SERVICE_REPAIR_BUSY;
  case UI_SVC_RP_DENIED: return SD_MSG_UI_SERVICE_REPAIR_DENIED;
  case UI_SVC_RP_LINK: return SD_MSG_UI_SERVICE_REPAIR_LINK;
  case UI_SVC_RP_UNSUPPORTED: return SD_MSG_UI_SERVICE_REPAIR_UNSUPPORTED;
  default: return SD_MSG_UI_SERVICE_REPAIR_FAILED;
  }
}

static void on_repair(sv_result *r)
{
  wchar_t code[64];
  wchar_t *t;
  UINT flags = r->kind == UI_SVC_RP_DONE || r->kind == UI_SVC_RP_MOVED ? MB_ICONINFORMATION : MB_ICONWARNING;
  g_sv.repairing = 0;
  ui_text_utf8(r->code, code, SD_COUNTOF(code));
  t = ui_format1(repair_msg(r->kind), "code", code);
  if (t != NULL) {
    ui_win_message(g_sv.wnd, t, MB_OK | flags);
    sd_free(t);
  }
  update_controls();
  request_status();
}

static void do_repair(void)
{
  ui_svc_repair_mode mode = current_mode();
  if (mode == UI_SVC_REPAIR_ELEVATE) {
    /* an administrator without the elevated token: reopen this page elevated (UAC), nothing is changed here */
    if (ui_confirm(g_sv.wnd, SD_MSG_UI_SERVICE_ELEVATE_TITLE, SD_MSG_UI_SERVICE_ELEVATE_TEXT, NULL,
                   SD_MSG_UI_SERVICE_ELEVATE_YES, SD_MSG_UI_SERVICE_ELEVATE_NO, 1))
      (void)ui_svc_launch_service_page(g_sv.wnd);
    return;
  }
  if (mode != UI_SVC_REPAIR_RUN)
    return;
  /* the default button is the safe one: the repair can move a folder aside */
  if (!ui_confirm(g_sv.wnd, SD_MSG_UI_SERVICE_REPAIR_TITLE, SD_MSG_UI_SERVICE_REPAIR_TEXT, NULL,
                  SD_MSG_UI_SERVICE_REPAIR_YES, SD_MSG_UI_SERVICE_REPAIR_NO, 0))
    return;
  if (sv_start(1, ui_svc_repair_route_of(&g_sv.view))) {
    g_sv.repairing = 1;
    update_controls();
  }
}

static void layout(HWND hwnd)
{
  RECT rc;
  int m, bh, nh, W, H, by, ny, bw1, bw2, bw3, x;
  if (g_sv.status == NULL || g_sv.btn_close == NULL)
    return;
  GetClientRect(hwnd, &rc);
  W = rc.right - rc.left;
  H = rc.bottom - rc.top;
  m = dpx(8);
  bh = dpx(26);
  nh = dpx(20);
  bw1 = ui_win_text_width(g_sv.font, sd_l10n_get(SD_MSG_UI_SERVICE_BTN_REFRESH)) + dpx(32);
  bw2 = ui_win_text_width(g_sv.font, sd_l10n_get(SD_MSG_UI_SERVICE_BTN_REPAIR)) + dpx(48);   /* room for the shield */
  bw3 = ui_win_text_width(g_sv.font, sd_l10n_get(SD_MSG_UI_SERVICE_BTN_CLOSE)) + dpx(32);
  by = H - m - bh;
  ny = by - m - nh;
  x = m;
  MoveWindow(g_sv.btn_refresh, x, by, bw1, bh, TRUE);
  x += bw1 + m;
  MoveWindow(g_sv.btn_repair, x, by, bw2, bh, TRUE);
  MoveWindow(g_sv.btn_close, W - m - bw3, by, bw3, bh, TRUE);
  MoveWindow(g_sv.note, m, ny, W - 2 * m > 0 ? W - 2 * m : 0, nh, TRUE);
  MoveWindow(g_sv.status, m, m, W - 2 * m > 0 ? W - 2 * m : 0, ny - 2 * m > 0 ? ny - 2 * m : 0, TRUE);
}

static void create_children(HWND hwnd)
{
  HINSTANCE inst = g_app.inst;
  g_sv.status = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
                                    ES_AUTOVSCROLL | ES_NOHIDESEL,
                                0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)SV_ID_STATUS, inst, NULL);
  g_sv.note = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 10, 10, hwnd,
                              (HMENU)(UINT_PTR)SV_ID_NOTE, inst, NULL);
  g_sv.btn_refresh = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_SERVICE_BTN_REFRESH),
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                     (HMENU)(UINT_PTR)SV_ID_REFRESH, inst, NULL);
  g_sv.btn_repair = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_SERVICE_BTN_REPAIR),
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED | BS_PUSHBUTTON, 0, 0, 10, 10,
                                    hwnd, (HMENU)(UINT_PTR)SV_ID_REPAIR, inst, NULL);
  g_sv.btn_close = CreateWindowExW(0, L"BUTTON", sd_l10n_get(SD_MSG_UI_SERVICE_BTN_CLOSE),
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10, hwnd,
                                   (HMENU)(UINT_PTR)SV_ID_CLOSE, inst, NULL);
  ui_win_apply_font(hwnd, g_sv.font);
}

static void on_dpi(HWND hwnd, unsigned dpi, const RECT *suggested)
{
  HFONT old = g_sv.font;
  if (dpi == 0)
    dpi = UI_DPI_BASE;
  g_sv.dpi = dpi;
  if (suggested)
    SetWindowPos(hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left,
                 suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
  g_sv.font = ui_win_font(dpi);
  ui_win_apply_font(hwnd, g_sv.font);
  if (old)
    DeleteObject(old);
  layout(hwnd);
}

static LRESULT CALLBACK sv_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_CREATE:
    g_sv.wnd = hwnd;
    g_sv.dpi = ui_dpi_window(hwnd);
    g_sv.font = ui_win_font(g_sv.dpi);
    ui_svc_view_init(&g_sv.view);
    create_children(hwnd);
    layout(hwnd);
    update_controls();
    return 0;
  case WM_SIZE:
    layout(hwnd);
    return 0;
  case WM_COMMAND:
    if (HIWORD(wp) == BN_CLICKED) {
      if (LOWORD(wp) == SV_ID_REFRESH)
        request_status();
      else if (LOWORD(wp) == SV_ID_REPAIR)
        do_repair();
      else if (LOWORD(wp) == SV_ID_CLOSE)
        SendMessageW(hwnd, WM_CLOSE, 0, 0);
    }
    return 0;
  case WM_TIMER:
    if (wp == SV_TIMER && IsWindowVisible(hwnd) && !IsIconic(hwnd) && !g_sv.repairing)
      request_status();
    return 0;
  case SV_WM_STATUS: {
    sv_result *r = (sv_result *)lp;
    if (r != NULL) {
      on_status(r);
      sd_free(r);
    }
    return 0;
  }
  case SV_WM_REPAIR: {
    sv_result *r = (sv_result *)lp;
    if (r != NULL) {
      on_repair(r);
      sd_free(r);
    }
    return 0;
  }
  case WM_CLOSE:
    if (g_sv.repairing) {
      MessageBeep(MB_ICONWARNING);      /* a repair in flight is not interrupted */
      return 0;
    }
    DestroyWindow(hwnd);
    return 0;
  case WM_DPICHANGED:
    on_dpi(hwnd, (unsigned)LOWORD(wp), (const RECT *)lp);
    return 0;
  case WM_DESTROY:
    KillTimer(hwnd, SV_TIMER);
    if (g_sv.font)
      DeleteObject(g_sv.font);
    memset(&g_sv, 0, sizeof(g_sv));
    /* the elevated page process lives as long as this window */
    if (g_app.elevated_service)
      ui_app_quit();
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
  ui_win_class_name(L"service", cls);
  if (!ui_win_register(g_app.inst, cls, sv_proc))
    return NULL;
  if (g_sv.wnd != NULL && IsWindow(g_sv.wnd))
    return g_sv.wnd;
  w = CreateWindowExW(0, cls, sd_l10n_get(SD_MSG_UI_SERVICE_TITLE), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                      CW_USEDEFAULT, CW_USEDEFAULT, SV_CLIENT_W, SV_CLIENT_H, NULL, NULL, g_app.inst, NULL);
  if (w == NULL)
    return NULL;
  SetWindowPos(w, NULL, 0, 0, ui_dpi_scale(SV_CLIENT_W, ui_dpi_window(w)),
               ui_dpi_scale(SV_CLIENT_H, ui_dpi_window(w)), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  if (visible) {
    ShowWindow(w, SW_SHOW);
    g_sv.loading = 1;
    update_controls();
    SetTimer(w, SV_TIMER, SV_POLL_MS, NULL);
    request_status();
  }
  return w;
}

void ui_service_open(void)
{
  if (g_sv.wnd != NULL && IsWindow(g_sv.wnd)) {
    ShowWindow(g_sv.wnd, IsIconic(g_sv.wnd) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(g_sv.wnd);
    request_status();
    return;
  }
  (void)create_window(1);
}

void ui_service_close(void)
{
  if (g_sv.wnd != NULL && IsWindow(g_sv.wnd))
    DestroyWindow(g_sv.wnd);
}

HWND ui_service_create_hidden(void)
{
  return create_window(0);
}

int ui_service_is_open(void)
{
  return g_sv.wnd != NULL && IsWindow(g_sv.wnd) ? 1 : 0;
}

/* --test-windows: the controls exist, Refresh is on, and Repair data is off for a process that is not an
   administrator (g_app.user_admin is 0 in the smoke modes) and for a window that has no status yet. */
int ui_service_controls_ok(void)
{
  if (g_sv.wnd == NULL || g_sv.status == NULL || g_sv.btn_repair == NULL || g_sv.btn_refresh == NULL ||
      g_sv.btn_close == NULL || g_sv.note == NULL)
    return 0;
  return IsWindowEnabled(g_sv.btn_refresh) && !IsWindowEnabled(g_sv.btn_repair) ? 1 : 0;
}
