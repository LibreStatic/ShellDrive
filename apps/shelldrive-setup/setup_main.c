/* shelldrive-setup: the setup stub (docs/design/04 §6.1-§6.9, TM-R33-R35).

   Entry point rules: the first statement restricts DLL search (SetDefaultDllDirectories where it exists,
   else SetDllDirectoryW(L"")); the only static imports are KnownDLLs (checked by sd-importcheck, TST-30).
   The payload comes from the RT_RCDATA resource of the flavour the host needs, and its SHA-256 comes from
   the PAYLOAD_TABLE resource; both are checked before anything is unpacked. uninstall.exe (this program
   without payload) runs its removal from a copy in a fresh %TEMP% folder, so it never deletes the image it
   runs from (04 §6.7).

   Interactive runs show the wizard (setup_ui.c, the page flow in setup_flow.c). /quiet shows nothing,
   /passive shows the progress view only. /test-pages is a hidden switch for the tests: it builds the pages and
   installs nothing (tests/setup). */
#include "setup_int.h"

#include <sddl.h>
#include <shellapi.h>
#include <string.h>

#include "sd_l10n/sd_l10n.h"
#include "setup_elevate.h"
#include "setup_flow.h"
#include "setup_trust.h"
#include "setup_payload_sig.h"
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

/* Shows the final message of an operation. Errors are always shown. A success is shown only when show_success
   is set: the installer's success is the finish page, a passive or quiet run shows nothing. */
static void show_result(const sd_setup_result *res, int show_success)
{
  wchar_t text[1024];
  wchar_t logline[MAX_PATH + 128];
  wchar_t full[MAX_PATH + 1280];

  if (res->msg == 0)
    return;
  if (res->exit_code == SD_SETUP_EXIT_OK && !show_success)
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
   the copy with the uninstall switches. flag is "/quiet", "/passive" or "" (interactive). The copy waits for
   this process to exit (04 §6.7). */
static int relaunch_uninstall_from_temp(const wchar_t *install_dir, const wchar_t *self, const wchar_t *flag)
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
                   (unsigned long)GetCurrentProcessId(), flag);
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

/* Starts the installed ShellDrive (finish page, "Launch ShellDrive"). A failure is shown to the user. */
static void launch_shelldrive(const wchar_t *folder, HWND owner)
{
  wchar_t exe[MAX_PATH];
  wchar_t cmd[MAX_PATH + 4];
  wchar_t text[512];
  sd_setup_result tmp;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  if (folder == NULL || sd_setup_path_join(exe, MAX_PATH, folder, L"shelldrive-ui.exe") != 0)
    return;
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\"", exe);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, folder, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return;
  }
  memset(&tmp, 0, sizeof(tmp));
  if (sd_setup_format_message(&tmp, SD_MSG_INSTALLER_LAUNCH_FAILED, text, SD_SETUP_COUNTOF(text)) >= 0)
    sd_setup_ui_message(owner, SD_TITLE, text, 1);
}

static int run_machine_elevated(sd_setup_ui *ui, const sd_setup_args *args, const wchar_t *self, sd_setup_result *res,
                                sd_msg_id done);

/* Starts the UI that an all-users install put in place, as the logged-on user (04 §6.4): this is the unelevated parent, never
   the elevated stage. A failure is shown. */
static void launch_installed_ui(void)
{
  sd_setup_elev_ops ops;
  wchar_t text[512];
  sd_setup_result tmp;

  sd_setup_elev_real_ops(&ops);
  if (sd_setup_elev_launch_installed(&ops) == 0)
    return;
  memset(&tmp, 0, sizeof(tmp));
  if (sd_setup_format_message(&tmp, SD_MSG_INSTALLER_LAUNCH_FAILED, text, SD_SETUP_COUNTOF(text)) >= 0)
    sd_setup_ui_message(NULL, SD_TITLE, text, 1);
}

/* True when this uninstall is the per-machine one (04 §6.7): the ShellDrive MSI is registered in the machine registry, and
   either no folder was named or the named folder is the machine install folder (or the running image sits there). dir gets
   the machine folder when none was named. Read-only. */
static int is_machine_uninstall(const wchar_t *self, wchar_t *dir, size_t cch, wchar_t *code, size_t ccode)
{
  wchar_t mdir[MAX_PATH];
  int known;

  if (!sd_setup_machine_product(code, ccode))
    return 0;
  known = sd_setup_machine_install_dir(mdir, SD_SETUP_COUNTOF(mdir)) == 0;
  if (dir[0] == L'\0') {
    /* Only the machine install is known here: the elevated stage finds the product itself. */
    if (known)
      StringCchCopyW(dir, cch, mdir);
    return 1;
  }
  return known && (_wcsicmp(mdir, dir) == 0 || running_from_install_dir(self, mdir));
}

static int run_uninstall(HINSTANCE inst, const sd_setup_args *args, const wchar_t *self, sd_setup_result *res)
{
  sd_setup_uninstall_opts uo;
  sd_setup_ui *ui = NULL;
  sd_flow_input flow;
  sd_setup_defaults defs;
  sd_setup_choices choice;
  wchar_t dir[MAX_PATH];
  wchar_t code[64];
  int interactive = !args->quiet && !args->passive;
  int machine;
  int rc;

  memset(&uo, 0, sizeof(uo));
  memset(&flow, 0, sizeof(flow));
  memset(&defs, 0, sizeof(defs));
  memset(&choice, 0, sizeof(choice));
  dir[0] = L'\0';
  if (args->install_dir[0] != L'\0') {
    StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), args->install_dir);
  } else {
    sd_setup_registered_install_dir(dir, SD_SETUP_COUNTOF(dir));
  }
  machine = is_machine_uninstall(self, dir, SD_SETUP_COUNTOF(dir), code, SD_SETUP_COUNTOF(code));

  if (!args->quiet && sd_setup_ui_create(inst, SD_TITLE, &ui) != 0)
    ui = NULL;

  /* The removal confirmation comes first, once: the copy in %TEMP% started below does not ask again. */
  if (interactive && !args->uninstall_relaunched) {
    if (ui == NULL) {
      fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_GENERIC);
      return SD_SETUP_EXIT_FATAL;
    }
    flow.uninstall = 1;
    defs.mode = SD_SETUP_MODE_UNINSTALL;
    defs.uninstall_dir = dir;
    defs.dokany_plan = SD_SETUP_DOKANY_SKIP_PLAN;
    if (!sd_setup_ui_run_pages(ui, &flow, &defs, &choice)) {
      sd_setup_ui_destroy(ui);
      fail_result(res, SD_SETUP_EXIT_CANCEL, 0);
      return SD_SETUP_EXIT_CANCEL;
    }
  }

  if (machine) {
    /* Per-machine: the elevated stages run msiexec /x for the registered product (04 §6.7). The image is not copied to
       %TEMP%: Windows Installer removes the installed files itself. */
    if (ui != NULL)
      sd_setup_ui_begin_progress(ui);
    rc = run_machine_elevated(ui, args, self, res, SD_MSG_INSTALLER_DONE_UNINSTALL);
    sd_setup_ui_destroy(ui);
    return rc;
  }

  if (dir[0] != L'\0' && running_from_install_dir(self, dir) && !args->uninstall_relaunched) {
    const wchar_t *flag = args->quiet ? L"/quiet" : (args->passive ? L"/passive" : L"");
    if (relaunch_uninstall_from_temp(dir, self, flag) == 0) {
      /* The copy in %TEMP% now does the work and reports on its own window. */
      sd_setup_ui_destroy(ui);
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
  if (ui != NULL) {
    sd_setup_ui_begin_progress(ui);
    uo.progress = progress_cb;
    uo.progress_ctx = ui;
  }
  rc = sd_setup_uninstall(&uo, res);
  sd_setup_ui_destroy(ui);
  return rc;
}

/* The payload of the flavour this host runs, and its SHA-256 from the PAYLOAD_TABLE resource (04 §6.1). Returns 0, or 1
   with *msg set. Nothing is unpacked here. A payload without a valid release signature gets its own message (TM-R38). */
static int load_payload(HINSTANCE inst, sd_setup_flavour flavour, sd_setup_payload *payload, unsigned char expected[32],
                        sd_msg_id *msg)
{
  HRSRC hres;
  HGLOBAL hglob;
  HRSRC htab;
  HGLOBAL htglob;

  hres = FindResourceW(inst, sd_setup_payload_resource(flavour), RT_RCDATA);
  hglob = hres != NULL ? LoadResource(inst, hres) : NULL;
  if (hglob == NULL) {
    *msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_MISSING;
    return 1;
  }
  payload->data = (const unsigned char *)LockResource(hglob);
  payload->size = SizeofResource(inst, hres);

  /* Without the table there is no verified hash: the stub refuses (TM-R38 until the signature exists). */
  htab = FindResourceW(inst, L"PAYLOAD_TABLE", RT_RCDATA);
  htglob = htab != NULL ? LoadResource(inst, htab) : NULL;
  if (htglob == NULL ||
      sd_setup_payload_table_lookup((const char *)LockResource(htglob), SizeofResource(inst, htab),
                                    sd_setup_flavour_name(flavour), expected) != 0) {
    *msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED;
    return 1;
  }
  /* TM-R38: the table must carry a valid release signature (PAYLOAD_SIG) in every path that extracts, the elevated
     stage 2 included; fails closed. */
  if (sd_setup_payload_sig_check(inst, (const unsigned char *)LockResource(htglob), SizeofResource(inst, htab)) !=
      SD_SETUP_PSIG_OK) {
    *msg = SD_MSG_INSTALLER_ERROR_PAYLOAD_SIGNATURE;
    return 1;
  }
  return 0;
}

/* The flavour of this host, the same choice in every stage (the forwarded switches carry /flavour= when it was forced). */
static int host_flavour(sd_setup_flavour *flavour, sd_msg_id *reason, const sd_setup_args *args)
{
  sd_setup_host host;
  sd_setup_detect_host(&host);
  return sd_setup_select_flavour(&host, args->flavour_forced ? args->flavour : SD_SETUP_FL_NONE, flavour, reason);
}

/* /extract=<dir> (04 §6.5): the MSI of the payload is written to the folder, for administrators who deploy it themselves.
   Nothing is installed, and no elevation is needed: the folder is the user's own. The copy is ShellDrive.msi. */
static int run_extract(const sd_setup_payload *payload, const sd_setup_args *args, sd_setup_result *res)
{
  wchar_t temp[MAX_PATH];
  wchar_t hex[40];
  wchar_t leaf[64];
  wchar_t work[MAX_PATH];
  wchar_t msi[MAX_PATH];
  wchar_t dst[MAX_PATH];
  sd_setup_result cab;
  DWORD attrs;
  unsigned files = 0;

  memset(&cab, 0, sizeof(cab));
  if (sd_setup_temp_dir(temp, SD_SETUP_COUNTOF(temp)) != 0 || sd_setup_random_hex(hex, SD_SETUP_COUNTOF(hex)) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE);
    return SD_SETUP_EXIT_FATAL;
  }
  StringCchPrintfW(leaf, SD_SETUP_COUNTOF(leaf), L"ShellDrive-extract-%s", hex);
  if (sd_setup_path_join(work, MAX_PATH, temp, leaf) != 0 || sd_setup_mkdirs(work) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE);
    return SD_SETUP_EXIT_FATAL;
  }
  if (sd_setup_cab_extract(payload, work, NULL, &cab, &files) != 0) {
    sd_setup_remove_tree(work, NULL);
    fail_result(res, SD_SETUP_EXIT_FATAL, cab.msg != 0 ? cab.msg : SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT);
    return SD_SETUP_EXIT_FATAL;
  }
  if (sd_setup_path_join(msi, MAX_PATH, work, L"ShellDrive.msi") != 0) {
    sd_setup_remove_tree(work, NULL);
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE);
    return SD_SETUP_EXIT_FATAL;
  }
  attrs = GetFileAttributesW(msi);
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    sd_setup_remove_tree(work, NULL);
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_MISSING);
    return SD_SETUP_EXIT_FATAL;
  }
  if (sd_setup_mkdirs(args->extract_dir) != 0 ||
      sd_setup_path_join(dst, MAX_PATH, args->extract_dir, L"ShellDrive.msi") != 0 || !CopyFileW(msi, dst, FALSE)) {
    sd_setup_remove_tree(work, NULL);
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE);
    return SD_SETUP_EXIT_FATAL;
  }
  sd_setup_remove_tree(work, NULL);
  memset(res, 0, sizeof(*res));
  res->exit_code = SD_SETUP_EXIT_OK;
  StringCchCopyW(res->folder, SD_SETUP_COUNTOF(res->folder), args->extract_dir);
  return SD_SETUP_EXIT_OK;
}

/* Progress of the parent while the elevated stages run: the value is a percentage, or SD_SETUP_ELEV_TICK (pump only). */
static void elev_progress(void *ctx, unsigned value)
{
  sd_setup_ui *ui = (sd_setup_ui *)ctx;
  if (value == SD_SETUP_ELEV_TICK) {
    if (ui != NULL)
      sd_setup_ui_pump(ui);
    return;
  }
  sd_setup_ui_status(ui, L"", value);
}

/* Per-machine install or uninstall (04 §6.3, 6.4, 6.7): the unelevated parent starts the two stages and relays their progress
   to ui (which has begun its progress view, or is NULL for /quiet). The UAC prompt is the consent step. No path is passed to
   the elevated stages. done is the success message; a reboot-pending uninstall also gets it. */
static int run_machine_elevated(sd_setup_ui *ui, const sd_setup_args *args, const wchar_t *self, sd_setup_result *res,
                                sd_msg_id done)
{
  sd_setup_elev_ops ops;
  wchar_t base[MAX_PATH];
  int rc;

  if (sd_setup_common_appdata(base, SD_SETUP_COUNTOF(base)) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION);
    return SD_SETUP_EXIT_FATAL;
  }
  sd_setup_elev_real_ops(&ops);
  rc = sd_setup_elev_parent_ex(&ops, base, self, args, res, elev_progress, ui);
  if (res->msg == 0 && (rc == SD_SETUP_EXIT_OK || (rc == SD_SETUP_EXIT_REBOOT && done == SD_MSG_INSTALLER_DONE_UNINSTALL)))
    res->msg = done;
  return rc;
}

/* The install: per-user, portable or all users (04 §6.3). The payload is checked first, so a damaged or unsigned setup
   stops before any page. Interactive runs show the wizard; the all-users choice runs the elevated stages. */
static int run_install(HINSTANCE inst, const sd_setup_args *args, const wchar_t *self, sd_setup_result *res)
{
  sd_setup_host host;
  sd_setup_flavour flavour = SD_SETUP_FL_NONE;
  sd_msg_id reason = 0;
  sd_setup_payload payload;
  sd_setup_install_opts io;
  unsigned char expected[32];
  sd_setup_ui *ui = NULL;
  sd_flow_input flow;
  sd_setup_defaults defs;
  sd_setup_choices choice;
  sd_setup_mode mode;
  const wchar_t *portable_dir;
  int interactive = !args->quiet && !args->passive;
  int rc;

  sd_setup_detect_host(&host);
  if (sd_setup_select_flavour(&host, args->flavour_forced ? args->flavour : SD_SETUP_FL_NONE, &flavour, &reason) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, reason);
    if (args->flavour_forced && sd_setup_flavour_name(args->flavour) != NULL)
      StringCchCopyW(res->text, SD_SETUP_COUNTOF(res->text), sd_setup_flavour_name(args->flavour));
    return SD_SETUP_EXIT_FATAL;
  }
  /* The flavour is checked before any UAC prompt and before any page (TM-R38). */
  if (load_payload(inst, flavour, &payload, expected, &reason) != 0) {
    fail_result(res, SD_SETUP_EXIT_FATAL, reason);
    if (reason == SD_MSG_INSTALLER_ERROR_PAYLOAD_MISSING)
      StringCchCopyW(res->text, SD_SETUP_COUNTOF(res->text), sd_setup_flavour_name(flavour));
    return SD_SETUP_EXIT_FATAL;
  }
  if (args->extract_dir[0] != L'\0')
    return run_extract(&payload, args, res);

  if (!args->quiet && sd_setup_ui_create(inst, SD_TITLE, &ui) != 0)
    ui = NULL;

  mode = args->mode == SD_SETUP_MODE_PORTABLE ? SD_SETUP_MODE_PORTABLE
         : args->mode == SD_SETUP_MODE_MACHINE ? SD_SETUP_MODE_MACHINE
                                               : SD_SETUP_MODE_USER;
  portable_dir = args->portable_dir;
  if (interactive) {
    if (ui == NULL) {
      fail_result(res, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_GENERIC);
      return SD_SETUP_EXIT_FATAL;
    }
    memset(&flow, 0, sizeof(flow));
    memset(&defs, 0, sizeof(defs));
    memset(&choice, 0, sizeof(choice));
    flow.mode_given = args->mode != SD_SETUP_MODE_AUTO;
    flow.dest_given = args->portable_dir[0] != L'\0';
    defs.mode = args->mode;
    defs.portable_dir = args->portable_dir;
    defs.uninstall_dir = L"";
    defs.dokany_plan = sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, args->dokany_set, args->dokany,
                                              host.os_major, host.os_minor);
    if (!sd_setup_ui_run_pages(ui, &flow, &defs, &choice)) {
      sd_setup_ui_destroy(ui);
      fail_result(res, SD_SETUP_EXIT_CANCEL, 0);
      return SD_SETUP_EXIT_CANCEL;
    }
    mode = choice.mode;
    portable_dir = choice.portable_dir;
  }
  if (ui != NULL)
    sd_setup_ui_begin_progress(ui);

  if (mode == SD_SETUP_MODE_MACHINE) {
    rc = run_machine_elevated(ui, args, self, res, SD_MSG_INSTALLER_DONE_INSTALL);
  } else {
    memset(&io, 0, sizeof(io));
    io.mode = mode;
    io.install_dir = args->install_dir[0] != L'\0' ? args->install_dir : NULL;
    io.portable_dir = portable_dir;
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
  }
  if (rc == SD_SETUP_EXIT_OK && interactive && ui != NULL) {
    /* The finish page carries the success text and the Launch checkbox. An all-users install starts the UI the MSI
       installed, from this unelevated parent (the folder comes from the machine registry); see launch_installed_ui. */
    wchar_t text[1024];
    int launch = 0;
    if (sd_setup_format_message(res, res->msg, text, SD_SETUP_COUNTOF(text)) < 0)
      text[0] = L'\0';
    if (sd_setup_ui_finish(ui, text, &launch) && launch) {
      if (mode == SD_SETUP_MODE_MACHINE)
        launch_installed_ui();
      else
        launch_shelldrive(res->folder, NULL);
    }
  }
  sd_setup_ui_destroy(ui);
  return rc;
}

/* The elevated stages (--elevated-stage1 and --elevated-child, 04 §6.4). Stage 1 needs no payload; stage 2 checks the
   payload table of its own image before it extracts anything. */
static int run_elevated_stage(HINSTANCE inst, const sd_setup_args *args, const wchar_t *self)
{
  sd_setup_flavour flavour = SD_SETUP_FL_NONE;
  sd_msg_id reason = 0;
  sd_setup_payload payload;
  unsigned char expected[32];
  sd_setup_elev_ops ops;
  wchar_t base[MAX_PATH];
  DWORD rc;

  if (sd_setup_common_appdata(base, SD_SETUP_COUNTOF(base)) != 0)
    return SD_SETUP_EXIT_FATAL;
  sd_setup_elev_real_ops(&ops);
  if (args->elevate_stage == 1) {
    DWORD child = 0;
    rc = sd_setup_elev_stage1(&ops, base, self, args, &child);
    return rc == 0 ? SD_SETUP_EXIT_OK : SD_SETUP_EXIT_FATAL;
  }
  /* A per-machine uninstall needs no payload: its stage 2 runs msiexec /x for the registered product (04 §6.7). */
  if (args->mode == SD_SETUP_MODE_UNINSTALL) {
    rc = sd_setup_elev_stage2_uninstall(&ops, base, self, args);
    return (int)rc;
  }
  if (host_flavour(&flavour, &reason, args) != 0 || load_payload(inst, flavour, &payload, expected, &reason) != 0)
    return SD_SETUP_EXIT_FATAL;
  rc = sd_setup_elev_stage2(&ops, base, self, args, &payload, expected);
  return (int)rc;
}

/* /test-pages: builds every page of the flow for the command line, writes the page names to the log and returns.
   Nothing is installed, no registry value is written and no file is touched. */
static int run_test_pages(HINSTANCE inst, const sd_setup_args *args)
{
  sd_setup_ui *ui = NULL;
  sd_setup_host host;
  sd_flow_input flow;
  sd_setup_defaults defs;
  unsigned built = 0;
  int ok;

  if (args->log_path[0] != L'\0')
    sd_setup_log_open(args->log_path);
  if (sd_setup_ui_create(inst, SD_TITLE, &ui) != 0) {
    sd_setup_log_close();
    return SD_SETUP_EXIT_FATAL;
  }
  sd_setup_detect_host(&host);
  memset(&flow, 0, sizeof(flow));
  memset(&defs, 0, sizeof(defs));
  flow.passive = args->passive;
  flow.uninstall = args->mode == SD_SETUP_MODE_UNINSTALL;
  flow.mode_given = args->mode != SD_SETUP_MODE_AUTO;
  flow.dest_given = args->portable_dir[0] != L'\0';
  defs.mode = args->mode;
  defs.portable_dir = args->portable_dir;
  defs.uninstall_dir = args->install_dir;
  defs.dokany_plan = sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, args->dokany_set, args->dokany, host.os_major,
                                            host.os_minor);
  ok = sd_setup_ui_test_pages(ui, &flow, &defs, &built);
  sd_setup_ui_destroy(ui);
  sd_setup_log_close();
  return ok && built > 0 ? SD_SETUP_EXIT_OK : SD_SETUP_EXIT_FATAL;
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
    show_result(&res, 1);
    LocalFree(argv);
    return rc;
  }

  if (args.help) {
    fail_result(&res, SD_SETUP_EXIT_OK, SD_MSG_INSTALLER_HELP);
    show_result(&res, 1);
    LocalFree(argv);
    return SD_SETUP_EXIT_OK;
  }

  if (args.test_pages) {
    rc = run_test_pages(inst, &args);
    LocalFree(argv);
    return rc;
  }

  GetModuleFileNameW(NULL, self, SD_SETUP_COUNTOF(self));

  /* The two elevated stages (04 §6.4): no window, no UI, nothing printed. */
  if (args.elevate_stage != 0) {
    rc = run_elevated_stage(inst, &args, self);
    LocalFree(argv);
    return rc;
  }

  if (args.mode == SD_SETUP_MODE_UNINSTALL)
    rc = run_uninstall(inst, &args, self, &res);
  else
    rc = run_install(inst, &args, self, &res);

  /* A removal says so in a message box when it was shown interactively; an install ends on its finish page. */
  show_result(&res, args.mode == SD_SETUP_MODE_UNINSTALL && !args.quiet && !args.passive);
  LocalFree(argv);
  return rc;
}
