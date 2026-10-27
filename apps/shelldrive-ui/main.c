/* shelldrive-ui.exe: tray icon and main window of ShellDrive (03 §1.4, §2, §7).
 *
 * One instance per (user, session): the named mutex SD_IPC_OBJ_UI_MUTEX. A second launch forwards its
 * command line as a versioned payload (ui_wire.c) with WM_COPYDATA to the first instance's message-only
 * window and exits. The receiving window accepts the message only from a process whose token user SID is
 * ours and whose integrity level is not lower than ours (TM-R26, T-48); everything else is dropped.
 *
 * Modes: no arguments opens the main window; --tray starts with the window hidden (Run key); --prompt-host
 * and --action <verb> <target> are the verbs of ui_wire.c; --test-window is the smoke test of tests/ui: it
 * creates the main window hidden, checks the window class and its controls, and exits 0; --test-prompts
 * creates every prompt dialog hidden and destroys it (exit 0 when all were created).
 *
 * --prompt-host (03 §1.4, §2.5 step 3): the agent starts this process when a prompt has nobody to answer it.
 * It shows the tray icon and the prompt dialogs only, never starts an agent, leaves when the agent goes away
 * and after 60 s with no open prompt. A prompt-host process that finds a running UI forwards and exits. */
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
#include "sd_config/sd_config.h"
#include "ui_int.h"
#include "ui_sdmount.h"
#include "ui_win.h"

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

/* --action mount-file <path> (03 §8.1): the file must be a valid .sdmount naming one of the user's profiles. A file
   with Mark of the Web asks first. Nothing else in the file is read, so it can only start a configured mount. */
static void handle_mount_file(const wchar_t *path)
{
  unsigned char *buf;
  size_t n = 0;
  char id[33];
  sd_err e;
  const sd_profile *p = NULL;

  buf = (unsigned char *)sd_alloc(UI_SDMOUNT_MAX_BYTES + 1u);
  if (buf == NULL)
    return;
  e = ui_sdmount_read(path, buf, UI_SDMOUNT_MAX_BYTES + 1u, &n);
  if (e == SD_OK)
    e = ui_sdmount_parse(buf, n, id);
  sd_free(buf);
  if (e == SD_OK && ui_profiles_load() == SD_OK)
    p = ui_profiles_find_id(id);
  if (e != SD_OK || p == NULL) {
    MessageBoxW(g_app.main, sd_l10n_get(SD_MSG_UI_MOUNT_FILE_INVALID), L"ShellDrive", MB_OK | MB_ICONWARNING);
    return;
  }
  if (ui_file_has_mark(path)) {
    wchar_t name[160];
    ui_text_utf8(p->name, name, SD_COUNTOF(name));
    if (!ui_confirm(g_app.main, SD_MSG_UI_MOUNT_FILE_TITLE, SD_MSG_UI_MOUNT_FILE_MARK, name,
                    SD_MSG_UI_MOUNT_FILE_CONNECT, SD_MSG_UI_MOUNT_FILE_CANCEL, 0))
      return;
  }
  ui_ipc_mount(id);
}

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
    /* --tray changes nothing here; --prompt-host was handled in wWinMain (g_app.prompt_host). */
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
  case UI_VERB_OPEN:
    /* The shell extension's "Open" verb: the drive is one of ours (03 §8.2); Explorer shows it. */
    ui_open_drive(req->target);
    break;
  case UI_VERB_MOUNT_FILE:
    handle_mount_file(req->target);
    break;
  case UI_VERB_RECONNECT:
    /* The agent has no reconnect method yet (03 §2.4): the verb is accepted and logged only. */
    SD_LOGI("ui", "reconnect is not available in this build");
    break;
  default:
    break;
  }
}

void ui_app_on_agent_state(int up)
{
  g_app.agent_up = up ? 1 : 0;
  ui_windows_on_agent_state(g_app.agent_up);
  if (!up) {
    /* the agent is gone: its prompts are gone with it (dialogs close without an answer) */
    ui_model_clear(&g_app.model);
    ui_prompt_close_all();
    if (g_app.prompt_host) {
      SD_LOGI("ui", "prompt host: the agent is gone, leaving");
      ui_app_quit();
      return;
    }
  }
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
  } else if (name != NULL && strcmp(name, "prompt.request") == 0) {
    ui_prompt_on_request(data);
  } else if (name != NULL && strcmp(name, "prompt.closed") == 0) {
    ui_prompt_on_closed(sd_json_get_str(data, "prompt_id"), sd_json_get_str(data, "reason"));
  } else if (name != NULL && strcmp(name, "hostkeys.announced") == 0) {
    ui_windows_on_event(name, data);
  }
  sd_json_free(ev);
}

void ui_app_on_prompt_list(sd_json *result)
{
  ui_prompt_on_list(result);
  sd_json_free(result);
}

/* Once a second. The prompt host leaves after UI_PROMPT_IDLE_MS with no open prompt (03 §1.4). */
void ui_app_on_timer(UINT_PTR id)
{
  if (id != UI_TIMER_PROMPT_IDLE || !g_app.prompt_host)
    return;
  if (ui_prompt_count() > 0) {
    g_app.idle_ms = 0;
    return;
  }
  g_app.idle_ms += 1000u;
  if (g_app.idle_ms >= UI_PROMPT_IDLE_MS) {
    SD_LOGI("ui", "prompt host: no prompt for 60 s, leaving");
    ui_app_quit();
  }
}

void ui_app_on_reply(ui_ipc_reply *r)
{
  if (r->kind >= UI_IPC_ANNOUNCED) {
    ui_windows_on_reply((int)r->kind, r->err, r->result);
  } else if (r->kind == UI_IPC_ANSWER) {
    /* answers close their dialog when queued; a refused one (answered elsewhere) needs no message */
    if (r->err != SD_OK)
      SD_LOGI("ui", "prompt answer not accepted by the agent (%s)", sd_err_name(r->err));
  } else if (r->kind == UI_IPC_MOUNT && r->err != SD_OK) {
    /* a refused or failed mount: the mount state events say what happened; this says the request did not start */
    MessageBoxW(g_app.main, sd_l10n_get(SD_MSG_UI_ERROR_MOUNT), L"ShellDrive", MB_OK | MB_ICONERROR);
  } else if (r->kind == UI_IPC_UNMOUNT && r->err != SD_OK) {
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
  case UI_WM_IPC_PROMPTS:
    ui_app_on_prompt_list((sd_json *)lp);
    return 0;
  case WM_TIMER:
    ui_app_on_timer(wp);
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
  {
    sd_settings st;
    sd_settings_defaults(&st);
    (void)sd_settings_load(&st);
    g_app.notify_on = st.notify ? 1 : 0;
  }

  memset(&icc, 0, sizeof(icc));
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
  InitCommonControlsEx(&icc);

  if (sd_ipc_current_identity(g_sid, SD_COUNTOF(g_sid), &session) != SD_OK || !read_self())
    goto done;
  build_class_names();

  if (argc > 1 && (wcscmp(argv[1], L"--test-window") == 0 || wcscmp(argv[1], L"--test-prompts") == 0 ||
                   wcscmp(argv[1], L"--test-editor") == 0 || wcscmp(argv[1], L"--test-windows") == 0)) {
    /* the smoke tests never read or write the user's profiles: the store is a temporary folder */
    wchar_t tmp[MAX_PATH];
    if (GetTempPathW(SD_COUNTOF(tmp), tmp) > 0 && wcslen(tmp) < SD_COUNTOF(tmp) - 32) {
      wchar_t dir[MAX_PATH + 32];
      wcscpy_s(dir, SD_COUNTOF(dir), tmp);
      wcscat_s(dir, SD_COUNTOF(dir), L"shelldrive-ui-test");
      sd_config_set_root_override(dir);
    }
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-window") == 0) {
    rc = run_smoke_test();
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-prompts") == 0) {
    rc = ui_prompt_smoke_test() ? 0 : 1;
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-editor") == 0) {
    rc = ui_editor_smoke_test() ? 0 : 1;
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-windows") == 0) {
    rc = ui_windows_smoke_test() ? 0 : 1;
    goto done;
  }

  if (ui_request_from_args(argc - 1, (const wchar_t *const *)(argv + 1), &req) != SD_OK) {
    SD_LOGW("ui", "command line not recognized");
    rc = 2;
    goto done;
  }

  /* set before the IPC thread starts: it reads the flag at its first connect */
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
  if (g_app.ctrl == NULL)
    goto done;
  if (!g_app.prompt_host && ui_main_create(inst, g_app.class_main, 0) == NULL)
    goto done;
  if (g_app.prompt_host)
    SetTimer(g_app.ctrl, UI_TIMER_PROMPT_IDLE, 1000, NULL);
  /* Explorer may not be ready yet; TaskbarCreated adds the icon later. */
  ui_tray_add();
  if (ui_ipc_start() != SD_OK)
    goto done;
  ui_app_handle_request(&req);

  while (GetMessageW(&msg, NULL, 0, 0) > 0) {
    if (ui_prompt_filter(&msg))
      continue;                        /* IsDialogMessage: keyboard handling of the prompt dialogs */
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  rc = 0;

  ui_windows_close_all();
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
