/* shelldrive-setup: the setup stub (docs/design/04 §6.1-§6.9, TM-R33-R35).

   Entry point rules: the first statement restricts DLL search (SetDefaultDllDirectories where it exists,
   else SetDllDirectoryW(L"")); the only static imports are KnownDLLs (checked by sd-importcheck, TST-30).
   The payload comes from the RT_RCDATA resource of the flavour the host needs, and its SHA-256 comes from
   the PAYLOAD_TABLE resource; both are checked before anything is unpacked. uninstall.exe (this program
   without payload) runs its removal from a copy in a fresh %TEMP% folder, so it never deletes the image it
   runs from (04 §6.7). */
#include "setup_int.h"

#include <sddl.h>
#include <shellapi.h>
#include <string.h>

#include "sd_l10n/sd_l10n.h"
#include "setup_ui.h"

#ifndef SD_VERSION_STRING_W
#define SD_VERSION_STRING_W L"0.0.0"
#endif

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

#define SD_TITLE L"ShellDrive Setup"

typedef BOOL (WINAPI *sd_SetDefaultDllDirectories_t)(DWORD);
typedef BOOL (WINAPI *sd_SetDllDirectoryW_t)(LPCWSTR);

static void restrict_dll_search(void)
{
  sd_SetDefaultDllDirectories_t set_dirs =
    (sd_SetDefaultDllDirectories_t)sd_setup_proc(L"kernel32.dll", "SetDefaultDllDirectories");
  sd_SetDllDirectoryW_t clear_dir = (sd_SetDllDirectoryW_t)sd_setup_proc(L"kernel32.dll", "SetDllDirectoryW");

  if (set_dirs != NULL)
    set_dirs(LOAD_LIBRARY_SEARCH_SYSTEM32);
  else if (clear_dir != NULL)
    clear_dir(L"");              /* XP, and Vista without KB2533623: drop the current directory (04 §6.4) */
}

/* Shows the final message of an operation: errors always, success only when not quiet. */
static void show_result(const sd_setup_result *res, int quiet)
{
  wchar_t text[1024];
  wchar_t logline[MAX_PATH + 128];
  wchar_t full[MAX_PATH + 1280];

  if (res->msg == 0)
    return;
  if (res->exit_code == SD_SETUP_EXIT_OK && quiet)
    return;
  if (sd_setup_format_message(res, res->msg, text, SD_SETUP_COUNTOF(text)) < 0)
    return;
  StringCchCopyW(full, SD_SETUP_COUNTOF(full), text);
  if (res->exit_code != SD_SETUP_EXIT_OK && res->log_path[0] != L'\0' &&
      sd_setup_format_message(res, SD_MSG_INSTALLER_LOG_SAVED, logline, SD_SETUP_COUNTOF(logline)) >= 0) {
    StringCchCatW(full, SD_SETUP_COUNTOF(full), L"\r\n");
    StringCchCatW(full, SD_SETUP_COUNTOF(full), logline);
  }
  sd_setup_ui_message(NULL, SD_TITLE, full, res->exit_code != SD_SETUP_EXIT_OK);
}

/* Progress callback: formats the stage with its folder and shows it in the window. */
static void progress_cb(void *ctx, sd_msg_id stage, const wchar_t *folder, unsigned percent)
{
  sd_setup_ui *ui = (sd_setup_ui *)ctx;
  wchar_t text[512];
  sd_setup_result tmp;

  memset(&tmp, 0, sizeof(tmp));
  if (folder != NULL)
    StringCchCopyW(tmp.folder, SD_SETUP_COUNTOF(tmp.folder), folder);
  if (stage != 0 && sd_setup_format_message(&tmp, stage, text, SD_SETUP_COUNTOF(text)) >= 0)
    sd_setup_ui_status(ui, text, percent);
  else
    sd_setup_ui_status(ui, L"", percent);
}

static void fail_result(sd_setup_result *res, int exit_code, sd_msg_id msg)
{
  memset(res, 0, sizeof(*res));
  res->exit_code = exit_code;
  res->msg = msg;
}

/* Copies this image into a fresh folder under %TEMP% that only the user and SYSTEM may write, then starts
   the copy with the uninstall switches. The copy waits for this process to exit (04 §6.7). */
static int relaunch_uninstall_from_temp(const wchar_t *install_dir, const wchar_t *self, int quiet)
{
  wchar_t temp[MAX_PATH];
  wchar_t hex[40];
  wchar_t leaf[64];
  wchar_t copy_dir[MAX_PATH];
  wchar_t copy_exe[MAX_PATH];
  wchar_t sid[128];
  wchar_t sddl[256];
  wchar_t cmd[MAX_PATH * 3];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  int rc = 1;

  if (sd_setup_temp_dir(temp, SD_SETUP_COUNTOF(temp)) != 0 || sd_setup_random_hex(hex, SD_SETUP_COUNTOF(hex)) != 0)
    return 1;
  StringCchPrintfW(leaf, SD_SETUP_COUNTOF(leaf), L"ShellDrive-uninstall-%s", hex);
  if (sd_setup_path_join(copy_dir, MAX_PATH, temp, leaf) != 0)
    return 1;
  if (sd_setup_current_sid(sid, SD_SETUP_COUNTOF(sid)) != 0)
    return 1;
  StringCchPrintfW(sddl, SD_SETUP_COUNTOF(sddl), L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", sid);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return 1;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  if (!CreateDirectoryW(copy_dir, &sa)) {
    LocalFree(sd);
    return 1;
  }
  LocalFree(sd);

  if (sd_setup_path_join(copy_exe, MAX_PATH, copy_dir, L"uninstall.exe") != 0 || !CopyFileW(self, copy_exe, FALSE))
    return 1;

  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd),
                   L"\"%s\" /uninstall-from-temp /installdir=\"%s\" /waitpid=%lu %s", copy_exe, install_dir,
                   (unsigned long)GetCurrentProcessId(), quiet ? L"/quiet" : L"/passive");
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (CreateProcessW(copy_exe, cmd, NULL, NULL, FALSE, 0, NULL, copy_dir, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    rc = 0;
  }
  return rc;
}

/* True when the running image sits in the install folder recorded for the account. */
static int running_from_install_dir(const wchar_t *self, const wchar_t *install_dir)
{
  wchar_t here[MAX_PATH];
  wchar_t dir[MAX_PATH];
  wchar_t *slash;
  size_t n;

  StringCchCopyW(here, SD_SETUP_COUNTOF(here), self);
  slash = wcsrchr(here, L'\\');
  if (slash == NULL)
    return 0;
  *slash = L'\0';
  StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), install_dir);
  n = wcslen(dir);
  while (n > 0 && dir[n - 1] == L'\\')
    dir[--n] = L'\0';
  return _wcsicmp(here, dir) == 0;
}

static int run_uninstall(HINSTANCE inst, const sd_setup_args *args, const wchar_t *self, sd_setup_result *res)
{
  sd_setup_uninstall_opts uo;
  sd_setup_ui *ui = NULL;
  wchar_t dir[MAX_PATH];
  int rc;

  memset(&uo, 0, sizeof(uo));
  dir[0] = L'\0';
  if (args->install_dir[0] != L'\0') {
    StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), args->install_dir);
  } else {
    sd_setup_registered_install_dir(dir, SD_SETUP_COUNTOF(dir));
  }

  if (dir[0] != L'\0' && running_from_install_dir(self, dir) && !args->uninstall_relaunched) {
    if (relaunch_uninstall_from_temp(dir, self, args->quiet) == 0) {
      /* The copy in %TEMP% now does the work and reports on its own window. */
      memset(res, 0, sizeof(*res));
      res->exit_code = SD_SETUP_EXIT_OK;
      return SD_SETUP_EXIT_OK;
    }
    /* Could not copy: continue from here; the folder removal fails only for the running image. */
  }

  if (args->wait_pid != 0) {
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)args->wait_pid);
    if (parent != NULL) {
      WaitForSingleObject(parent, 30000);
      CloseHandle(parent);
    }
  }

  uo.install_dir = dir[0] != L'\0' ? dir : NULL;
  uo.force = args->force;
  uo.log_path = args->log_path[0] != L'\0' ? args->log_path : NULL;
  if (!args->quiet && sd_setup_ui_create(inst, SD_TITLE, &ui) == 0) {
    uo.progress = progress_cb;
    uo.progress_ctx = ui;
  }
  rc = sd_setup_uninstall(&uo, res);
  sd_setup_ui_destroy(ui);
  return rc;
}

static int run_install(HINSTANCE inst, const sd_setup_args *args, sd_setup_result *res)
{
  sd_setup_host host;
  sd_setup_flavour flavour = SD_SETUP_FL_NONE;
  sd_msg_id reason = 0;
  sd_setup_payload payload;
  sd_setup_install_opts io;
  unsigned char expected[32];
  sd_setup_ui *ui = NULL;
  HRSRC hres;
  HGLOBAL hglob;
  HRSRC htab;
  HGLOBAL htglob;
  int rc;

  if (args->extract_dir[0] != L'\0') {
    /* /extract= (admin deployment copy) needs the MSI and the stages of 04 §6.4: not in this build. */
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_GENERIC);
    return SD_SETUP_EXIT_FATAL;
  }

  sd_setup_detect_host(&host);
  if (sd_setup_select_flavour(&host, args->flavour_forced ? args->flavour : SD_SETUP_FL_NONE, &flavour, &reason) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, reason);
    if (args->flavour_forced && sd_setup_flavour_name(args->flavour) != NULL)
      StringCchCopyW(res->text, SD_SETUP_COUNTOF(res->text), sd_setup_flavour_name(args->flavour));
    return SD_SETUP_EXIT_FATAL;
  }

  memset(&payload, 0, sizeof(payload));
  hres = FindResourceW(inst, sd_setup_payload_resource(flavour), RT_RCDATA);
  hglob = hres != NULL ? LoadResource(inst, hres) : NULL;
  if (hglob == NULL) {
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_MISSING);
    StringCchCopyW(res->text, SD_SETUP_COUNTOF(res->text), sd_setup_flavour_name(flavour));
    return SD_SETUP_EXIT_FATAL;
  }
  payload.data = (const unsigned char *)LockResource(hglob);
  payload.size = SizeofResource(inst, hres);

  /* Without the table there is no verified hash: the stub refuses (TM-R38 until the signature exists). */
  htab = FindResourceW(inst, L"PAYLOAD_TABLE", RT_RCDATA);
  htglob = htab != NULL ? LoadResource(inst, htab) : NULL;
  if (htglob == NULL ||
      sd_setup_payload_table_lookup((const char *)LockResource(htglob), SizeofResource(inst, htab),
                                    sd_setup_flavour_name(flavour), expected) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED);
    return SD_SETUP_EXIT_FATAL;
  }

  if (!args->quiet && sd_setup_ui_create(inst, SD_TITLE, &ui) != 0)
    ui = NULL;

  memset(&io, 0, sizeof(io));
  io.mode = args->mode == SD_SETUP_MODE_PORTABLE ? SD_SETUP_MODE_PORTABLE : SD_SETUP_MODE_USER;
  io.install_dir = args->install_dir[0] != L'\0' ? args->install_dir : NULL;
  io.portable_dir = args->portable_dir;
  io.version = SD_VERSION_STRING_W;
  io.flavour = flavour;
  io.payload = &payload;
  io.expected_sha256 = expected;
  io.autostart = args->autostart;
  io.force = args->force;
  io.update = args->update;
  io.log_path = args->log_path[0] != L'\0' ? args->log_path : NULL;
  io.progress = progress_cb;
  io.progress_ctx = ui;

  rc = sd_setup_install(&io, res);
  sd_setup_ui_destroy(ui);
  return rc;
}

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmdline, int show)
{
  sd_setup_args args;
  sd_setup_result res;
  wchar_t **argv = NULL;
  int argc = 0;
  const wchar_t *bad = NULL;
  wchar_t self[MAX_PATH];
  int rc;

  (void)prev;
  (void)cmdline;
  (void)show;
  restrict_dll_search();
  memset(&res, 0, sizeof(res));

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == NULL)
    return SD_SETUP_EXIT_FATAL;

  rc = sd_setup_parse_args(argc, (const wchar_t *const *)argv, &args, &bad);
  sd_l10n_init(&sd_l10n_catalog_installer, args.lang[0] != L'\0' ? args.lang : NULL);
  if (rc != 0) {
    fail_result(&res, rc, SD_MSG_INSTALLER_ERROR_ARGS);
    StringCchCopyW(res.text, SD_SETUP_COUNTOF(res.text), bad != NULL ? bad : L"");
    show_result(&res, 0);
    LocalFree(argv);
    return rc;
  }

  if (args.help) {
    fail_result(&res, SD_SETUP_EXIT_OK, SD_MSG_INSTALLER_HELP);
    show_result(&res, 0);
    LocalFree(argv);
    return SD_SETUP_EXIT_OK;
  }

  if (args.mode == SD_SETUP_MODE_MACHINE) {
    /* Per-machine installs go through the MSI and the elevation stages (04 §6.3-§6.4), not in this build. */
    fail_result(&res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MACHINE_UNSUPPORTED);
    show_result(&res, 0);
    LocalFree(argv);
    return SD_SETUP_EXIT_FATAL;
  }

  GetModuleFileNameW(NULL, self, SD_SETUP_COUNTOF(self));
  if (args.mode == SD_SETUP_MODE_UNINSTALL)
    rc = run_uninstall(inst, &args, self, &res);
  else
    rc = run_install(inst, &args, &res);

  show_result(&res, args.quiet);
  LocalFree(argv);
  return rc;
}
