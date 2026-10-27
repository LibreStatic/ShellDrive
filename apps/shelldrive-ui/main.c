/* shelldrive-ui.exe: tray icon and main window of ShellDrive (03 §1.4, §2, §7).
 *
 * One instance per (user, session): the named mutex SD_IPC_OBJ_UI_MUTEX. A second launch forwards its
 * command line as a versioned payload (ui_wire.c) with WM_COPYDATA to the first instance's message-only
 * window and exits. The receiving window accepts the message only from a process whose token user SID is
 * ours and whose integrity level is not lower than ours (TM-R26, T-48); everything else is dropped.
 *
 * Modes: no arguments opens the main window; --tray starts with the window hidden (Run key); --prompt-host
 * and --action <verb> <target> are the verbs of ui_wire.c; --test-window is the smoke test of tests/ui: it
 * creates the main window hidden, checks the window class and its controls, and exits 0. */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>
#include <commctrl.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "ui_dpi.h"
#include "ui_int.h"

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

ui_app g_app;

static wchar_t g_sid[256];

/* ---- identities for the WM_COPYDATA sender check (TM-R26) ---- */

typedef struct ui_identity {
  unsigned char *sid;           /* copy of the token user SID */
  DWORD sid_len;
  int has_integrity;            /* Vista and later */
  DWORD integrity;              /* mandatory label RID */
} ui_identity;

static ui_identity g_self;

static int read_identity(HANDLE tok, ui_identity *id)
{
  DWORD need = 0;
  TOKEN_USER *tu;

  memset(id, 0, sizeof(*id));
  GetTokenInformation(tok, TokenUser, NULL, 0, &need);
  if (need == 0)
    return 0;
  tu = sd_alloc(need);
  if (tu == NULL)
    return 0;
  if (!GetTokenInformation(tok, TokenUser, tu, need, &need)) {
    sd_free(tu);
    return 0;
  }
  id->sid_len = GetLengthSid(tu->User.Sid);
  id->sid = sd_alloc(id->sid_len);
  if (id->sid == NULL || !CopySid(id->sid_len, id->sid, tu->User.Sid)) {
    sd_free(id->sid);
    memset(id, 0, sizeof(*id));
    sd_free(tu);
    return 0;
  }
  sd_free(tu);

  if (sd_os_at_least(6, 0, 0)) {
    TOKEN_MANDATORY_LABEL *label;
    need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    if (need != 0) {
      label = sd_alloc(need);
      if (label != NULL && GetTokenInformation(tok, TokenIntegrityLevel, label, need, &need)) {
        UCHAR *count = GetSidSubAuthorityCount(label->Label.Sid);
        if (count != NULL && *count > 0) {
          id->integrity = *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1));
          id->has_integrity = 1;
        }
      }
      sd_free(label);
    }
  }
  return 1;
}

static int read_self(void)
{
  HANDLE tok = NULL;
  int ok = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  ok = read_identity(tok, &g_self);
  CloseHandle(tok);
  return ok;
}

/* True when the window belongs to a process of this user with an integrity level not below ours. */
static int sender_trusted(HWND sender)
{
  DWORD pid = 0;
  HANDLE proc, tok;
  ui_identity id;
  int ok = 0;

  if (sender == NULL || !GetWindowThreadProcessId(sender, &pid) || pid == 0)
    return 0;
  proc = OpenProcess(sd_os_at_least(6, 0, 0) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION,
                     FALSE, pid);
  if (proc == NULL)
    return 0;
  if (OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
    if (read_identity(tok, &id)) {
      ok = g_self.sid != NULL && id.sid != NULL && EqualSid(id.sid, g_self.sid);
      if (ok && id.has_integrity && g_self.has_integrity && id.integrity < g_self.integrity)
        ok = 0;
      sd_free(id.sid);
    }
    CloseHandle(tok);
  }
  CloseHandle(proc);
  return ok;
}

/* ---- requests ---- */

void ui_app_handle_request(const ui_request *req)
{
  char id[40];
  ui_mount *m;

  switch (req->verb) {
  case UI_VERB_NONE:
  case UI_VERB_SHOW:
    ui_main_show();
    break;
  case UI_VERB_TRAY:
  case UI_VERB_PROMPT_HOST:
    /* TODO (prompt host package): --prompt-host shows the prompt window; --tray changes nothing here. */
    break;
  case UI_VERB_UNMOUNT:
    /* The drive must be one of this UI's mounts; the agent checks again. */
    m = ui_model_find_drive(&g_app.model, req->target);
    if (m == NULL) {
      SD_LOGW("ui", "unmount request for a drive that is not mounted: dropped");
      break;
    }
    ui_ipc_unmount(m->drive);
    break;
  case UI_VERB_MOUNT:
    ui_text_ascii(req->target, id, sizeof(id));
    ui_ipc_mount(id);
    break;
  case UI_VERB_MOUNT_FILE:
  case UI_VERB_RECONNECT:
    /* TODO (mount dialog package): the verb is valid but has no handler yet. */
    SD_LOGI("ui", "action has no handler in this build");
    break;
  default:
    break;
  }
}

void ui_app_on_agent_state(int up)
{
  g_app.agent_up = up ? 1 : 0;
  if (!up)
    ui_model_clear(&g_app.model);
  ui_main_refresh();
  if (!up && g_app.prompt_host)
    ui_app_quit();              /* a prompt host lives only as long as the agent that started it */
}

void ui_app_on_list(sd_json *result)
{
  ui_model_set_list(&g_app.model, result);
  sd_json_free(result);
  ui_main_refresh();
}

void ui_app_on_event(sd_json *ev)
{
  const char *name = sd_json_get_str(ev, "event");
  const sd_json *data = sd_json_get(ev, "data");

  if (name != NULL && strcmp(name, "mount.state") == 0) {
    const char *id = sd_json_get_str(data, "mount_id");
    const char *st = sd_json_get_str(data, "state");
    ui_mount *m = ui_model_find_id(&g_app.model, id);
    if (m == NULL) {
      /* A mount this UI has not listed yet: ask for the list again. */
      if (st != NULL && strcmp(st, "unmounted") != 0)
        ui_ipc_list();
    } else if (st != NULL && strcmp(st, "unmounted") == 0) {
      ui_model_remove(&g_app.model, m);
    } else if (st != NULL && strlen(st) < sizeof(m->state)) {
      strcpy_s(m->state, sizeof(m->state), st);
      ui_text_utf8(m->state, m->state_w, SD_COUNTOF(m->state_w));
    }
    ui_main_refresh();
  } else if (name != NULL && strcmp(name, "warning") == 0) {
    const char *code = sd_json_get_str(data, "code");
    ui_mount *m = ui_model_find_id(&g_app.model, sd_json_get_str(data, "mount_id"));
    ui_tray_balloon(code, m ? m->drive : L"");
  }
  sd_json_free(ev);
}

void ui_app_on_reply(ui_ipc_reply *r)
{
  if (r->kind == UI_IPC_UNMOUNT && r->err != SD_OK) {
    wchar_t *t = ui_format1(SD_MSG_UI_ERROR_UNMOUNT, "drive", r->drive);
    if (t != NULL) {
      MessageBoxW(g_app.main, t, L"ShellDrive", MB_OK | MB_ICONERROR);
      sd_free(t);
    }
  }
  sd_json_free(r->result);
  sd_free(r);
}

void ui_app_quit(void)
{
  g_app.quit = 1;
  PostQuitMessage(0);
}

/* ---- control window: WM_COPYDATA, IPC results, tray callbacks ---- */

static LRESULT on_copydata(HWND sender, const COPYDATASTRUCT *cds)
{
  ui_request req;
  if (cds == NULL || cds->dwData != UI_WIRE_CDATA_TAG) {
    SD_LOGW("ui", "copydata with an unknown tag: dropped");
    return FALSE;
  }
  if (!sender_trusted(sender)) {
    SD_LOGW("ui", "copydata from another user or a higher integrity level: dropped");
    return FALSE;
  }
  if (ui_request_from_payload(cds->lpData, cds->cbData, &req) != SD_OK) {
    SD_LOGW("ui", "copydata payload rejected: dropped");
    return FALSE;
  }
  ui_app_handle_request(&req);
  return TRUE;
}

static LRESULT CALLBACK ctrl_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_COPYDATA:
    return on_copydata((HWND)wp, (const COPYDATASTRUCT *)lp);
  case UI_WM_IPC_STATE:
    ui_app_on_agent_state(wp != 0);
    return 0;
  case UI_WM_IPC_LIST:
    ui_app_on_list((sd_json *)lp);
    return 0;
  case UI_WM_IPC_EVENT:
    ui_app_on_event((sd_json *)lp);
    return 0;
  case UI_WM_IPC_REPLY:
    ui_app_on_reply((ui_ipc_reply *)lp);
    return 0;
  case UI_WM_TRAY:
    ui_tray_callback(lp);
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static int register_ctrl_class(HINSTANCE inst)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = ctrl_proc;
  wc.hInstance = inst;
  wc.lpszClassName = g_app.class_ctrl;
  return RegisterClassExW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

static void build_class_names(void)
{
  wcscpy_s(g_app.class_ctrl, SD_COUNTOF(g_app.class_ctrl), L"com.librestatic.shelldrive.ui.");
  wcscat_s(g_app.class_ctrl, SD_COUNTOF(g_app.class_ctrl), g_sid);
  wcscpy_s(g_app.class_main, SD_COUNTOF(g_app.class_main), g_app.class_ctrl);
  wcscat_s(g_app.class_main, SD_COUNTOF(g_app.class_main), L".main");
}

/* Sends the command line to the running instance. The sender is a private message-only window, so the
   receiver can check our process (its token user and integrity level). */
static int forward_to_running(int argc, wchar_t **argv)
{
  unsigned char *buf = NULL;
  size_t n = 0;
  HWND target, sender;
  COPYDATASTRUCT cds;
  DWORD_PTR result = 0;
  int ok = 0;

  if (ui_wire_encode(argc, (const wchar_t *const *)argv, &buf, &n) != SD_OK)
    return 0;
  target = FindWindowExW(HWND_MESSAGE, NULL, g_app.class_ctrl, NULL);
  sender = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, g_app.inst, NULL);
  if (target != NULL && sender != NULL) {
    cds.dwData = UI_WIRE_CDATA_TAG;
    cds.cbData = (DWORD)n;
    cds.lpData = buf;
    ok = SendMessageTimeoutW(target, WM_COPYDATA, (WPARAM)sender, (LPARAM)&cds, SMTO_ABORTIFHUNG, 5000,
                             &result) != 0 &&
         result != 0;
  }
  if (sender != NULL)
    DestroyWindow(sender);
  sd_free(buf);
  return ok;
}

/* Smoke test (--test-window): the main window class is registered, the window and its controls exist,
   and the window stays hidden. */
static int run_smoke_test(void)
{
  WNDCLASSEXW wc;
  HWND w;
  int ok;

  if (!ui_main_register_class(g_app.inst, g_app.class_main))
    return 1;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  if (GetClassInfoExW(g_app.inst, g_app.class_main, &wc) == 0)
    return 1;
  w = ui_main_create(g_app.inst, g_app.class_main, 0);
  if (w == NULL || !IsWindow(w))
    return 1;
  ok = ui_main_test_controls() && !IsWindowVisible(w);
  DestroyWindow(w);
  return ok ? 0 : 1;
}

int WINAPI wWinMain(_In_ HINSTANCE inst, _In_opt_ HINSTANCE prev, _In_ LPWSTR cmd, _In_ int show)
{
  wchar_t **argv = NULL;
  int argc = 0, rc = 1;
  ui_request req;
  wchar_t lang_buf[32];
  const wchar_t *lang = NULL;
  DWORD session = 0;
  INITCOMMONCONTROLSEX icc;
  HANDLE mutex = NULL;
  int existed = 0;
  sd_err e;
  MSG msg;

  (void)prev;
  (void)cmd;
  (void)show;
  sd_platform_harden_dll_search();
  sd_platform_init();
  ui_dpi_init();
  g_app.inst = inst;
  g_app.wm_taskbar = RegisterWindowMessageW(L"TaskbarCreated");

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == NULL)
    return 1;

  if (GetEnvironmentVariableW(L"SHELLDRIVE_LANG", lang_buf, SD_COUNTOF(lang_buf)) - 1u <
      SD_COUNTOF(lang_buf) - 1u)
    lang = lang_buf;
  sd_l10n_init(&sd_l10n_catalog_ui, lang);

  memset(&icc, 0, sizeof(icc));
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
  InitCommonControlsEx(&icc);

  if (sd_ipc_current_identity(g_sid, SD_COUNTOF(g_sid), &session) != SD_OK || !read_self())
    goto done;
  build_class_names();

  if (argc > 1 && wcscmp(argv[1], L"--test-window") == 0) {
    rc = run_smoke_test();
    goto done;
  }

  if (ui_request_from_args(argc - 1, (const wchar_t *const *)(argv + 1), &req) != SD_OK) {
    SD_LOGW("ui", "command line not recognized");
    rc = 2;
    goto done;
  }

  g_app.prompt_host = req.verb == UI_VERB_PROMPT_HOST;
  e = sd_ipc_object_create(SD_IPC_OBJ_UI_MUTEX, &mutex, &existed);
  if (e != SD_OK || mutex == NULL)
    goto done;
  g_app.mutex = mutex;
  if (existed) {
    rc = forward_to_running(argc - 1, argv + 1) ? 0 : 1;
    goto done;
  }

  if (!register_ctrl_class(inst) || !ui_main_register_class(inst, g_app.class_main))
    goto done;
  g_app.ctrl = CreateWindowExW(0, g_app.class_ctrl, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
  if (g_app.ctrl == NULL || ui_main_create(inst, g_app.class_main, 0) == NULL)
    goto done;
  /* Explorer may not be ready yet; TaskbarCreated adds the icon later. */
  ui_tray_add();
  if (ui_ipc_start() != SD_OK)
    goto done;
  ui_app_handle_request(&req);

  while (GetMessageW(&msg, NULL, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  rc = 0;

  ui_ipc_stop();
  ui_tray_remove();
  if (g_app.main != NULL && IsWindow(g_app.main))
    DestroyWindow(g_app.main);
  if (g_app.ctrl != NULL && IsWindow(g_app.ctrl))
    DestroyWindow(g_app.ctrl);
  ui_icon_free_all();

done:
  if (mutex != NULL)
    CloseHandle(mutex);
  if (argv != NULL)
    LocalFree(argv);
  return rc;
}
