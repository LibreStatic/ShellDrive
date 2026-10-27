/* shelldrive-setup: install, repair, upgrade, portable extraction and uninstall for the account (per-user)
   and portable modes (docs/design/04 §6.3, §6.7, §6.8, §6.9, §13).

   Per-user work never needs elevation: files go to %LOCALAPPDATA%\Programs\LibreStatic\ShellDrive (or
   /installdir), registration to HKCU, the shortcut to the account's Programs folder. Per-machine installs
   go through our MSI and the two elevated stages (04 §6.4); they are not in this build and report
   SD_MSG_INSTALLER_ERROR_MACHINE_UNSUPPORTED. The payload is staged in a fresh temp folder first, so a
   failed extraction never touches the installed files. */
#include "setup_int.h"

#include <shlobj.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SD_STATE_SUBKEY     L"Software\\LibreStatic\\ShellDrive"
#define SD_UNINSTALL_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive"
#define SD_DEFAULT_SUFFIX   L"Programs\\LibreStatic\\ShellDrive"
#define SD_AGENT_WAIT_MS    15000u
#define SD_HOST_EXE         L"shelldrive-host.exe"
#define SD_UI_EXE           L"shelldrive-ui.exe"
#define SD_UNINSTALL_EXE    L"uninstall.exe"
#define SD_SHORTCUT_NAME    L"ShellDrive.lnk"
#define SD_PORTABLE_MARK    L"shelldrive.portable"
#define SD_FILE_PERSISTENT_ACLS 0x00000008

static void setup_logf(const char *event, const wchar_t *fmt, ...)
{
  wchar_t buf[1024];
  va_list ap;
  va_start(ap, fmt);
  StringCchVPrintfW(buf, SD_SETUP_COUNTOF(buf), fmt, ap);
  va_end(ap);
  sd_setup_log(event, buf);
}

static void report(sd_setup_progress_fn fn, void *ctx, sd_msg_id stage, const wchar_t *folder, unsigned pct)
{
  if (fn != NULL)
    fn(ctx, stage, folder, pct);
}

static void strip_slash(wchar_t *s)
{
  size_t n = wcslen(s);
  while (n > 0 && s[n - 1] == L'\\')
    s[--n] = L'\0';
}

static int reg_read_sz(HKEY root, const wchar_t *sub, const wchar_t *name, wchar_t *out, DWORD cbytes)
{
  HKEY hk = NULL;
  DWORD type = 0;
  DWORD size = cbytes;
  LONG rc;

  if (out == NULL || cbytes < sizeof(wchar_t))
    return 1;
  rc = RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE, &hk);
  if (rc != ERROR_SUCCESS)
    return 1;
  rc = RegQueryValueExW(hk, name, NULL, &type, (BYTE *)out, &size);
  RegCloseKey(hk);
  if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    return 1;
  out[cbytes / sizeof(wchar_t) - 1] = L'\0';
  return 0;
}

int sd_setup_registered_install_dir(wchar_t *out, size_t cch)
{
  wchar_t raw[MAX_PATH * 2];
  if (reg_read_sz(HKEY_CURRENT_USER, SD_STATE_SUBKEY, L"InstallDir", raw, sizeof(raw)) != 0)
    return 1;
  if (FAILED(StringCchCopyW(out, cch, raw)))
    return 1;
  strip_slash(out);
  return 0;
}

static int exists_key(HKEY root, const wchar_t *sub)
{
  HKEY hk = NULL;
  if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS)
    return 0;
  RegCloseKey(hk);
  return 1;
}

/* Default account install folder, or the requested one, without a trailing backslash. */
static int resolve_user_dir(const wchar_t *requested, wchar_t *out, size_t cch)
{
  wchar_t base[MAX_PATH];

  if (requested != NULL && requested[0] != L'\0') {
    if (FAILED(StringCchCopyW(out, cch, requested)))
      return 1;
    strip_slash(out);
    return 0;
  }
  if (sd_setup_special_folder(CSIDL_LOCAL_APPDATA, base, SD_SETUP_COUNTOF(base)) != 0)
    return 1;
  if (sd_setup_path_join(out, cch, base, SD_DEFAULT_SUFFIX) != 0)
    return 1;
  return 0;
}

/* Start menu Programs folder of the account, or the test seam. */
static int resolve_programs_dir(const wchar_t *requested, wchar_t *out, size_t cch)
{
  if (requested != NULL && requested[0] != L'\0')
    return FAILED(StringCchCopyW(out, cch, requested)) ? 1 : 0;
  return sd_setup_special_folder(CSIDL_PROGRAMS, out, cch);
}

/* Wait for running agents of this account. Returns 0 when setup may go on. */
static int stop_agents(int force, int skip, sd_setup_progress_fn fn, void *ctx, sd_setup_result *r)
{
  unsigned signalled = 0, still = 0;

  if (skip)
    return 0;
  report(fn, ctx, SD_MSG_INSTALLER_PROGRESS_STOP, NULL, 10);
  sd_setup_signal_agents(NULL, &signalled);
  if (signalled > 0)
    setup_logf("agents.signalled", L"%u agent(s) asked to exit", signalled);
  sd_setup_wait_agents(SD_AGENT_WAIT_MS, &still);
  if (still > 0) {
    setup_logf("agents.running", L"%u agent(s) still running after %u ms", still, SD_AGENT_WAIT_MS);
    if (!force) {
      sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_RUNNING, 0);
      return 1;
    }
  }
  return 0;
}

/* Extracts the payload into a fresh staging folder under %TEMP% and returns its path in staging. */
static int make_staging(wchar_t *staging, size_t cch, sd_setup_result *r)
{
  wchar_t temp[MAX_PATH];
  wchar_t hex[40];
  wchar_t leaf[64];

  if (sd_setup_temp_dir(temp, SD_SETUP_COUNTOF(temp)) != 0 || sd_setup_random_hex(hex, SD_SETUP_COUNTOF(hex)) != 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, (long)GetLastError());
  StringCchPrintfW(leaf, SD_SETUP_COUNTOF(leaf), L"ShellDrive-setup-%s", hex);
  if (sd_setup_path_join(staging, cch, temp, leaf) != 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  if (!CreateDirectoryW(staging, NULL))
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, (long)GetLastError());
  return 0;
}

/* Moves src over dst. A file that is in use (a running agent, a loaded shell extension) is renamed aside
   to dst.sd-old-<n> first; NTFS allows renaming a loaded image (04 §6.9 step 3). */
static DWORD move_over(const wchar_t *src, const wchar_t *dst, unsigned *aside)
{
  DWORD err;
  unsigned n;

  if (MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
    return 0;
  err = GetLastError();
  if (GetFileAttributesW(dst) == INVALID_FILE_ATTRIBUTES)
    return err;

  for (n = 1; n < 100; n++) {
    wchar_t old[MAX_PATH];
    StringCchPrintfW(old, SD_SETUP_COUNTOF(old), L"%s.sd-old-%u", dst, n);
    if (GetFileAttributesW(old) != INVALID_FILE_ATTRIBUTES)
      continue;
    if (!MoveFileExW(dst, old, 0))
      return GetLastError();
    if (aside != NULL)
      (*aside)++;
    if (MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
      return 0;
    return GetLastError();
  }
  return err;
}

/* Moves every member of the staging tree into dst, recursively. */
static int place_tree(const wchar_t *src, const wchar_t *dst, unsigned *files, unsigned long long *bytes,
                      unsigned *aside, sd_setup_result *r)
{
  WIN32_FIND_DATAW fd;
  HANDLE find;
  wchar_t pattern[MAX_PATH];

  if (sd_setup_mkdirs(dst) != 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  if (sd_setup_path_join(pattern, MAX_PATH, src, L"*") != 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  find = FindFirstFileW(pattern, &fd);
  if (find == INVALID_HANDLE_VALUE)
    return 0;
  do {
    wchar_t from[MAX_PATH], to[MAX_PATH];
    DWORD err;
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (sd_setup_path_join(from, MAX_PATH, src, fd.cFileName) != 0 ||
        sd_setup_path_join(to, MAX_PATH, dst, fd.cFileName) != 0) {
      FindClose(find);
      return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
    }
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      int rc = place_tree(from, to, files, bytes, aside, r);
      if (rc != 0) {
        FindClose(find);
        return rc;
      }
      continue;
    }
    err = move_over(from, to, aside);
    if (err != 0) {
      FindClose(find);
      setup_logf("file.replace", L"%s (error %lu)", to, (unsigned long)err);
      if (r != NULL)
        StringCchCopyW(r->text, SD_SETUP_COUNTOF(r->text), fd.cFileName);
      return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_FILE_LOCKED, (long)err);
    }
    (*files)++;
    if (bytes != NULL)
      *bytes += ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
  } while (FindNextFileW(find, &fd));
  FindClose(find);
  return 0;
}

/* Total size of the files under dir, in bytes. */
static unsigned long long tree_bytes(const wchar_t *dir, int depth)
{
  WIN32_FIND_DATAW fd;
  HANDLE find;
  wchar_t pattern[MAX_PATH];
  unsigned long long total = 0;

  if (depth > 16 || sd_setup_path_join(pattern, MAX_PATH, dir, L"*") != 0)
    return 0;
  find = FindFirstFileW(pattern, &fd);
  if (find == INVALID_HANDLE_VALUE)
    return 0;
  do {
    wchar_t child[MAX_PATH];
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    if (sd_setup_path_join(child, MAX_PATH, dir, fd.cFileName) != 0)
      continue;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      total += tree_bytes(child, depth + 1);
    else
      total += ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
  } while (FindNextFileW(find, &fd));
  FindClose(find);
  return total;
}

static int folder_has_entries(const wchar_t *dir)
{
  WIN32_FIND_DATAW fd;
  HANDLE find;
  wchar_t pattern[MAX_PATH];
  int any = 0;

  if (sd_setup_path_join(pattern, MAX_PATH, dir, L"*") != 0)
    return 1;
  find = FindFirstFileW(pattern, &fd);
  if (find == INVALID_HANDLE_VALUE)
    return 0;
  do {
    if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
      any = 1;
  } while (!any && FindNextFileW(find, &fd));
  FindClose(find);
  return any;
}

/* Runs the shelldrive-host hook of the installed copy (04 §8.3). Failures are logged, not fatal here. */
static void run_host_hook(const wchar_t *install_dir, const wchar_t *hook)
{
  wchar_t exe[MAX_PATH];
  wchar_t cmd[MAX_PATH * 2];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = 0;

  if (sd_setup_path_join(exe, MAX_PATH, install_dir, SD_HOST_EXE) != 0)
    return;
  if (GetFileAttributesW(exe) == INVALID_FILE_ATTRIBUTES) {
    setup_logf("hook.skipped", L"%s not found", exe);
    return;
  }
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\" --installer-hook %s --apply", exe, hook);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, install_dir, &si, &pi)) {
    sd_setup_log_error("hook.start", cmd, GetLastError());
    return;
  }
  WaitForSingleObject(pi.hProcess, 60000);
  GetExitCodeProcess(pi.hProcess, &code);
  setup_logf("hook.done", L"%s exit %lu", hook, (unsigned long)code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
}

static void fill_done_fields(sd_setup_result *r, const wchar_t *folder, const wchar_t *version, unsigned files)
{
  StringCchCopyW(r->folder, SD_SETUP_COUNTOF(r->folder), folder);
  StringCchCopyW(r->version, SD_SETUP_COUNTOF(r->version), version);
  r->count = files;
}

static void finish_log(sd_setup_result *r)
{
  if (r->exit_code != SD_SETUP_EXIT_OK && sd_setup_log_path()[0] != L'\0') {
    StringCchCopyW(r->log_path, SD_SETUP_COUNTOF(r->log_path), sd_setup_log_path());
  }
}

/* Staged copy of the payload, then move into dst. Shared by per-user and portable installs. */
static int stage_and_place(const sd_setup_install_opts *o, const wchar_t *dst, sd_setup_result *r,
                           unsigned *files, unsigned long long *bytes)
{
  wchar_t staging[MAX_PATH];
  unsigned extracted = 0;
  unsigned aside = 0;
  int rc;

  rc = make_staging(staging, SD_SETUP_COUNTOF(staging), r);
  if (rc != 0)
    return rc;

  rc = sd_setup_cab_extract(o->payload, staging, NULL, r, &extracted);
  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_EXTRACT, NULL, 40);
  if (rc != 0) {
    sd_setup_remove_tree(staging, NULL);
    return rc;
  }
  setup_logf("payload.extracted", L"%u member(s) into staging", extracted);

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_COPY, dst, 60);
  rc = place_tree(staging, dst, files, bytes, &aside, r);
  if (aside > 0)
    setup_logf("file.aside", L"%u file(s) renamed aside (in use)", aside);
  sd_setup_remove_tree(staging, NULL);
  return rc;
}

static int verify_payload(const sd_setup_install_opts *o, sd_setup_result *r)
{
  unsigned char sha[32];
  if (o->expected_sha256 == NULL)
    return 0;
  sd_setup_sha256(o->payload->data, o->payload->size, sha);
  if (memcmp(sha, o->expected_sha256, 32) != 0) {
    setup_logf("payload.hash_mismatch", L"the embedded package does not match its recorded SHA-256");
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED, 0);
  }
  return 0;
}

static int install_user(const sd_setup_install_opts *o, sd_setup_result *r)
{
  wchar_t dir[MAX_PATH];
  wchar_t installed[64] = L"";
  wchar_t programs[MAX_PATH];
  wchar_t lnk[MAX_PATH];
  wchar_t target[MAX_PATH];
  const wchar_t *version = o->version != NULL ? o->version : L"0.0.0";
  unsigned files = 0;
  unsigned long long bytes = 0;
  sd_setup_regctx rc;
  int rv;

  if (resolve_user_dir(o->install_dir, dir, SD_SETUP_COUNTOF(dir)) != 0)
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);

  if (exists_key(HKEY_LOCAL_MACHINE, SD_UNINSTALL_SUBKEY)) {
    setup_logf("install.refused", L"a per-machine ShellDrive is registered");
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MACHINE_EXISTS, 0);
  }

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_CHECK, NULL, 5);
  if (reg_read_sz(HKEY_CURRENT_USER, SD_STATE_SUBKEY, L"Version", installed, sizeof(installed)) == 0) {
    int cmp = sd_setup_version_compare(installed, version);
    setup_logf("install.previous", L"installed %s, this setup %s", installed, version);
    if (cmp > 0 && !o->update) {
      StringCchCopyW(r->version, SD_SETUP_COUNTOF(r->version), installed);
      return sd_setup_fail(r, SD_SETUP_EXIT_NEWER, SD_MSG_INSTALLER_ERROR_NEWER_INSTALLED, 0);
    }
    setup_logf("install.kind", cmp == 0 ? L"repair (same version)" : (cmp < 0 ? L"upgrade" : L"downgrade (/update)"));
  } else {
    setup_logf("install.kind", L"new install");
  }

  if (stop_agents(o->force, o->skip_agents, o->progress, o->progress_ctx, r) != 0)
    return r->exit_code;

  rv = verify_payload(o, r);
  if (rv != 0)
    return rv;

  rv = stage_and_place(o, dir, r, &files, &bytes);
  if (rv != 0)
    return rv;
  bytes = tree_bytes(dir, 0);

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_REGISTER, NULL, 80);
  memset(&rc, 0, sizeof(rc));
  rc.root = HKEY_CURRENT_USER;
  {
    wchar_t slashed[MAX_PATH];
    if (sd_setup_dir_with_slash(slashed, SD_SETUP_COUNTOF(slashed), dir) != 0)
      return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
    rc.install_dir = slashed;
    rc.version = version;
    rc.flavour = sd_setup_flavour_name(o->flavour);
    rc.install_bytes = bytes;
    rc.autostart = o->autostart == 1;
    if (sd_setup_reg_apply(&rc) != 0)
      return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  }

  if (!o->skip_shortcut) {
    report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_SHORTCUT, NULL, 90);
    if (resolve_programs_dir(o->programs_dir, programs, SD_SETUP_COUNTOF(programs)) == 0 &&
        sd_setup_path_join(lnk, MAX_PATH, programs, SD_SHORTCUT_NAME) == 0 &&
        sd_setup_path_join(target, MAX_PATH, dir, SD_UI_EXE) == 0) {
      if (sd_setup_shortcut_create(lnk, target, dir, L"ShellDrive", target) != 0)
        setup_logf("shortcut.failed", L"could not create %s", lnk);
      else
        setup_logf("shortcut.created", L"%s", lnk);
    }
  }

  fill_done_fields(r, dir, version, files);
  r->exit_code = SD_SETUP_EXIT_OK;
  r->msg = SD_MSG_INSTALLER_DONE_INSTALL;
  setup_logf("install.done", L"ShellDrive %s in %s, %u file(s), %I64u bytes", version, dir, files, bytes);
  report(o->progress, o->progress_ctx, 0, dir, 100);
  return 0;
}

static int install_portable(const sd_setup_install_opts *o, sd_setup_result *r)
{
  wchar_t dir[MAX_PATH];
  wchar_t data[MAX_PATH];
  wchar_t mark[MAX_PATH];
  wchar_t root[8];
  unsigned files = 0;
  unsigned long long bytes = 0;
  DWORD flags = 0;
  HANDLE h;
  int rv;

  if (o->portable_dir == NULL || o->portable_dir[0] == L'\0')
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  if (FAILED(StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), o->portable_dir)))
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  strip_slash(dir);

  if (GetFileAttributesW(dir) != INVALID_FILE_ATTRIBUTES && folder_has_entries(dir)) {
    StringCchCopyW(r->folder, SD_SETUP_COUNTOF(r->folder), dir);
    return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PORTABLE_NOT_EMPTY, 0);
  }

  rv = verify_payload(o, r);
  if (rv != 0)
    return rv;

  /* Drives without persistent ACLs (FAT, exFAT, most USB sticks) get a warning (04 §6.8). */
  if (dir[1] == L':') {
    StringCchPrintfW(root, SD_SETUP_COUNTOF(root), L"%c:\\", dir[0]);
    if (GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0) && !(flags & SD_FILE_PERSISTENT_ACLS)) {
      r->warn_volume = 1;
      setup_logf("portable.volume", L"%s has no persistent ACLs", root);
    }
  }

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_PORTABLE, dir, 20);
  rv = stage_and_place(o, dir, r, &files, &bytes);
  if (rv != 0)
    return rv;

  /* A portable copy carries no uninstaller (04 §6.8: no registration of any kind). */
  if (sd_setup_path_join(mark, MAX_PATH, dir, SD_UNINSTALL_EXE) == 0)
    DeleteFileW(mark);
  if (sd_setup_path_join(data, MAX_PATH, dir, L"data") == 0)
    sd_setup_mkdirs(data);
  if (sd_setup_path_join(mark, MAX_PATH, dir, SD_PORTABLE_MARK) == 0) {
    h = CreateFileW(mark, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
    else
      return sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, (long)GetLastError());
  }

  fill_done_fields(r, dir, o->version != NULL ? o->version : L"0.0.0", files);
  r->exit_code = SD_SETUP_EXIT_OK;
  r->msg = SD_MSG_INSTALLER_DONE_PORTABLE;
  setup_logf("portable.done", L"%s, %u file(s)", dir, files);
  report(o->progress, o->progress_ctx, 0, dir, 100);
  return 0;
}

static void open_log_for(const wchar_t *requested)
{
  wchar_t path[MAX_PATH];
  wchar_t temp[MAX_PATH];
  SYSTEMTIME st;

  if (requested != NULL) {
    sd_setup_log_open(requested);
    return;
  }
  if (sd_setup_temp_dir(temp, SD_SETUP_COUNTOF(temp)) != 0)
    return;
  GetLocalTime(&st);
  StringCchPrintfW(path, SD_SETUP_COUNTOF(path), L"%sShellDrive-setup-%04u%02u%02u-%02u%02u%02u.log", temp,
                   (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour,
                   (unsigned)st.wMinute, (unsigned)st.wSecond);
  sd_setup_log_open(path);
}

int sd_setup_install(const sd_setup_install_opts *o, sd_setup_result *r)
{
  sd_setup_result local;
  sd_setup_host host;

  if (r == NULL)
    r = &local;
  memset(r, 0, sizeof(*r));
  r->exit_code = SD_SETUP_EXIT_FATAL;

  open_log_for(o->log_path);
  sd_setup_detect_host(&host);
  setup_logf("setup.start", L"mode=%d flavour=%s version=%s native=0x%04x sse2=%d os=%u.%u admin=%d",
       (int)o->mode, sd_setup_flavour_name(o->flavour) ? sd_setup_flavour_name(o->flavour) : L"none",
       o->version ? o->version : L"0.0.0", (unsigned)host.native_machine, host.sse2, host.os_major, host.os_minor,
       host.is_admin);

  if (o->payload == NULL || o->payload->data == NULL || o->flavour == SD_SETUP_FL_NONE) {
    sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_MISSING, 0);
    if (sd_setup_flavour_name(o->flavour) != NULL)
      StringCchCopyW(r->text, SD_SETUP_COUNTOF(r->text), sd_setup_flavour_name(o->flavour));
  } else if (o->mode == SD_SETUP_MODE_MACHINE) {
    sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MACHINE_UNSUPPORTED, 0);
  } else if (o->mode == SD_SETUP_MODE_PORTABLE) {
    install_portable(o, r);
  } else {
    install_user(o, r);
  }

  if (r->exit_code != SD_SETUP_EXIT_OK) {
    if (r->msg != 0)
      setup_logf("setup.failed", L"message %lu, code %ld", (unsigned long)r->msg, r->code);
    else
      setup_logf("setup.failed", L"exit %d", r->exit_code);
  }
  finish_log(r);
  sd_setup_log_close();
  return r->exit_code;
}

/* ------------------------------------------------------------------ uninstall */

int sd_setup_uninstall(const sd_setup_uninstall_opts *o, sd_setup_result *r)
{
  sd_setup_result local;
  wchar_t dir[MAX_PATH];
  wchar_t registered[MAX_PATH * 2];
  wchar_t programs[MAX_PATH];
  wchar_t lnk[MAX_PATH];
  wchar_t cache[MAX_PATH];
  wchar_t local_app[MAX_PATH];
  wchar_t roaming[MAX_PATH];
  unsigned failed = 0;
  sd_setup_regctx rc;

  if (r == NULL)
    r = &local;
  memset(r, 0, sizeof(*r));
  r->exit_code = SD_SETUP_EXIT_FATAL;

  open_log_for(o->log_path);
  setup_logf("uninstall.start", L"force=%d", o->force);

  if (o->install_dir != NULL && o->install_dir[0] != L'\0') {
    StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), o->install_dir);
    strip_slash(dir);
  } else if (reg_read_sz(HKEY_CURRENT_USER, SD_STATE_SUBKEY, L"InstallDir", registered, sizeof(registered)) == 0) {
    StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), registered);
    strip_slash(dir);
  } else {
    sd_setup_fail(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_NOT_INSTALLED, 0);
    finish_log(r);
    sd_setup_log_close();
    return r->exit_code;
  }
  StringCchCopyW(r->folder, SD_SETUP_COUNTOF(r->folder), dir);

  if (stop_agents(o->force, o->skip_agents, o->progress, o->progress_ctx, r) != 0) {
    finish_log(r);
    sd_setup_log_close();
    return r->exit_code;
  }

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_UNINSTALL, dir, 30);
  if (!o->skip_hooks)
    run_host_hook(dir, L"user-cleanup");

  memset(&rc, 0, sizeof(rc));
  rc.root = HKEY_CURRENT_USER;
  sd_setup_reg_remove(&rc);
  setup_logf("uninstall.registration", L"account registration removed");

  if (!o->skip_shortcut && resolve_programs_dir(o->programs_dir, programs, SD_SETUP_COUNTOF(programs)) == 0 &&
      sd_setup_path_join(lnk, MAX_PATH, programs, SD_SHORTCUT_NAME) == 0) {
    DeleteFileW(lnk);
  }

  /* Caches are always removed (TM-R28, 04 §6.7); settings and profiles are kept. */
  if (sd_setup_special_folder(CSIDL_LOCAL_APPDATA, local_app, SD_SETUP_COUNTOF(local_app)) == 0 &&
      sd_setup_path_join(cache, MAX_PATH, local_app, L"LibreStatic\\ShellDrive\\cache") == 0) {
    sd_setup_remove_tree(cache, &failed);
  }

  report(o->progress, o->progress_ctx, SD_MSG_INSTALLER_PROGRESS_UNINSTALL, dir, 70);
  sd_setup_remove_tree(dir, &failed);
  if (failed > 0)
    setup_logf("uninstall.incomplete", L"%u item(s) could not be removed", failed);

  if (sd_setup_special_folder(CSIDL_APPDATA, roaming, SD_SETUP_COUNTOF(roaming)) == 0)
    setup_logf("uninstall.kept", L"settings and profiles kept under %s\\LibreStatic\\ShellDrive", roaming);

  r->exit_code = failed > 0 ? SD_SETUP_EXIT_REBOOT : SD_SETUP_EXIT_OK;
  r->msg = SD_MSG_INSTALLER_DONE_UNINSTALL;
  setup_logf("uninstall.done", L"exit %d", r->exit_code);
  report(o->progress, o->progress_ctx, 0, dir, 100);
  finish_log(r);
  sd_setup_log_close();
  return r->exit_code;
}
