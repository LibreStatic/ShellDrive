/* shelldrive-setup: two-stage elevation for per-machine installs (docs/design/04 §6.4, TM-R33, TM-R34, T-62, T-63).
   The stages are described in setup_elevate.h.

   Pipe protocol: one line per message, UTF-16, "P <percent>" for progress, "M <msg id> <code>" for the message stage 2
   wants shown, and "R <exit code>" as the final line. The stub imports no CRT string search (04 §2.4, ISA audit), so the
   line parsing below is written out.

   Stage 2 never trusts a path from the command line: it derives the stage folder from its own image, checks the folder and
   its name, and only then extracts the payload and runs msiexec. Stage 1 extracts nothing. */
#include "setup_int.h"

#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <string.h>

#include "setup_elevate.h"
#include "setup_trust.h"
#include "svc_repair.h"

#define SD_ELEV_NAME_PREFIX L"ShellDrive-setup-"
#define SD_ELEV_NAME_PREFIX_LEN 17
#define SD_ELEV_HEX_LEN 32
#define SD_ELEV_STAGE_LEAF L"shelldrive-setup.exe"
#define SD_ELEV_PAYLOAD_DIR L"payload"
#define SD_ELEV_MSI_LEAF L"ShellDrive.msi"
#define SD_ELEV_MSI_LOG L"msi.log"
#define SD_ELEV_CMD_CCH 2048
#define SD_ELEV_FWD_CCH 1024

/* Pipe DACL: the launching user's SID only (04 §6.4). */
static const wchar_t *const k_pipe_sddl_fmt = L"D:P(A;;GRGW;;;%s)";

/* ------------------------------------------------------------------ names */

static int is_hex(wchar_t c)
{
  return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
}

static int has_prefix(const wchar_t *s, const wchar_t *prefix)
{
  while (*prefix != L'\0') {
    if (*s != *prefix)
      return 0;
    s++;
    prefix++;
  }
  return 1;
}

int sd_setup_elev_pipe_name_ok(const wchar_t *name)
{
  size_t i;
  if (name == NULL || wcslen(name) != SD_ELEV_NAME_PREFIX_LEN + SD_ELEV_HEX_LEN || !has_prefix(name, SD_ELEV_NAME_PREFIX))
    return 0;
  for (i = SD_ELEV_NAME_PREFIX_LEN; name[i] != L'\0'; i++) {
    if (!is_hex(name[i]))
      return 0;
  }
  return 1;
}

int sd_setup_elev_pipe_new_name(wchar_t *out, size_t cch)
{
  wchar_t hex[40];
  size_t i;
  if (out == NULL || cch < SD_ELEV_NAME_PREFIX_LEN + SD_ELEV_HEX_LEN + 1)
    return 1;
  if (sd_setup_random_hex(hex, SD_SETUP_COUNTOF(hex)) != 0)
    return 1;
  /* The random hex is upper case; the pipe name uses lower case. */
  for (i = 0; i < SD_ELEV_HEX_LEN; i++) {
    if (hex[i] >= L'A' && hex[i] <= L'F')
      hex[i] = (wchar_t)(hex[i] + (L'a' - L'A'));
  }
  hex[SD_ELEV_HEX_LEN] = L'\0';
  StringCchPrintfW(out, cch, L"%s%s", SD_ELEV_NAME_PREFIX, hex);
  return sd_setup_elev_pipe_name_ok(out) ? 0 : 1;
}

int sd_setup_elev_root(const wchar_t *base, wchar_t *out, size_t cch)
{
  wchar_t vendor[MAX_PATH];
  wchar_t product[MAX_PATH];
  if (base == NULL || out == NULL)
    return 1;
  if (sd_setup_path_join(vendor, MAX_PATH, base, L"LibreStatic") != 0)
    return 1;
  if (sd_setup_path_join(product, MAX_PATH, vendor, L"ShellDrive") != 0)
    return 1;
  return sd_setup_path_join(out, cch, product, L"setup");
}

/* 1 when leaf is 32 lower-case or upper-case hex digits (a stage folder name from sd_setup_create_stage_dir). */
static int stage_leaf_ok(const wchar_t *leaf)
{
  size_t i;
  if (leaf == NULL || wcslen(leaf) != SD_ELEV_HEX_LEN)
    return 0;
  for (i = 0; i < SD_ELEV_HEX_LEN; i++) {
    wchar_t c = leaf[i];
    if (c >= L'A' && c <= L'F')
      c = (wchar_t)(c + (L'a' - L'A'));
    if (!is_hex(c))
      return 0;
  }
  return 1;
}

/* 1 when image is <root>\<32 hex>\shelldrive-setup.exe. Compares text only; nothing is opened. */
static int image_in_stage(const wchar_t *root, const wchar_t *image)
{
  wchar_t dir[MAX_PATH];
  wchar_t *slash;

  if (wcslen(image) >= MAX_PATH)
    return 0;
  StringCchCopyW(dir, SD_SETUP_COUNTOF(dir), image);
  slash = wcsrchr(dir, L'\\');
  if (slash == NULL || _wcsicmp(slash + 1, SD_ELEV_STAGE_LEAF) != 0)
    return 0;
  *slash = L'\0';
  slash = wcsrchr(dir, L'\\');
  if (slash == NULL || !stage_leaf_ok(slash + 1))
    return 0;
  *slash = L'\0';
  return _wcsicmp(dir, root) == 0;
}

/* The folder of a path: the path without its last component. Returns 0 or 1. */
static int parent_of(const wchar_t *path, wchar_t *out, size_t cch)
{
  wchar_t *slash;
  if (wcslen(path) >= cch)
    return 1;
  StringCchCopyW(out, cch, path);
  slash = wcsrchr(out, L'\\');
  if (slash == NULL)
    return 1;
  *slash = L'\0';
  return 0;
}

/* ------------------------------------------------------------------ the real seam */

static int real_is_elevated(void *ctx)
{
  sd_setup_host h;
  (void)ctx;
  sd_setup_detect_host(&h);
  return h.is_admin;
}

static DWORD real_secure(void *ctx, const wchar_t *base)
{
  sd_setup_trust_result tr;
  (void)ctx;
  return sd_setup_secure_programdata(base, &tr);
}

static DWORD real_create_stage(void *ctx, const wchar_t *setup_dir, const wchar_t *extra_ace, wchar_t *out, size_t cch)
{
  (void)ctx;
  return sd_setup_create_stage_dir(setup_dir, extra_ace, out, cch);
}

static DWORD real_copy_image(void *ctx, const wchar_t *src, const wchar_t *dst)
{
  HANDLE in;
  HANDLE out;
  unsigned char *buf;
  DWORD got = 0;
  DWORD put = 0;
  DWORD err = 0;

  (void)ctx;
  /* Read sharing only: nobody can write or delete the source while it is copied (04 §6.4, stage 1 step d). */
  in = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (in == INVALID_HANDLE_VALUE)
    return GetLastError();
  out = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (out == INVALID_HANDLE_VALUE) {
    err = GetLastError();
    CloseHandle(in);
    return err;
  }
  buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, 65536);
  if (buf == NULL) {
    CloseHandle(out);
    CloseHandle(in);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  for (;;) {
    if (!ReadFile(in, buf, 65536, &got, NULL)) {
      err = GetLastError();
      break;
    }
    if (got == 0)
      break;
    if (!WriteFile(out, buf, got, &put, NULL) || put != got) {
      err = ERROR_WRITE_FAULT;
      break;
    }
  }
  HeapFree(GetProcessHeap(), 0, buf);
  CloseHandle(out);
  CloseHandle(in);
  return err;
}

static DWORD real_run(void *ctx, const wchar_t *exe, const wchar_t *cmdline, const wchar_t *dir, int runas,
                      DWORD *exit_code)
{
  wchar_t cmd[SD_ELEV_CMD_CCH];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  SHELLEXECUTEINFOW sei;
  HANDLE proc = NULL;
  DWORD err = 0;

  (void)ctx;
  if (exit_code == NULL || exe == NULL || cmdline == NULL)
    return ERROR_INVALID_PARAMETER;
  if (FAILED(StringCchCopyW(cmd, SD_ELEV_CMD_CCH, cmdline)))
    return ERROR_INSUFFICIENT_BUFFER;

  if (runas) {
    /* Vista and later: the UAC prompt. XP: the Run As dialog for a limited user (04 §6.4). A refusal is ERROR_CANCELLED. */
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exe;
    sei.lpParameters = cmd;
    sei.lpDirectory = dir;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei))
      return GetLastError();
    proc = sei.hProcess;
  } else {
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi))
      return GetLastError();
    CloseHandle(pi.hThread);
    proc = pi.hProcess;
  }
  if (proc == NULL)
    return ERROR_INTERNAL_ERROR;
  WaitForSingleObject(proc, INFINITE);
  if (!GetExitCodeProcess(proc, exit_code))
    err = GetLastError();
  CloseHandle(proc);
  return err;
}

static int real_folder_trusted(void *ctx, const wchar_t *dir)
{
  svc_repair_ops ops;
  DWORD attrs;
  PSID owner = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  int ok = 0;

  (void)ctx;
  attrs = GetFileAttributesW(dir);
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    return 0;
  if (GetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL,
                            &sd) != ERROR_SUCCESS)
    return 0;
  svc_repair_real_ops(&ops);
  ok = ops.owner_trusted != NULL && ops.owner_trusted(ops.ctx, owner) != 0;
  LocalFree(sd);
  return ok;
}

static int real_find_machine_product(void *ctx, wchar_t *code, size_t cch)
{
  (void)ctx;
  return sd_setup_machine_product(code, cch);
}

static int real_machine_dir(void *ctx, wchar_t *out, size_t cch)
{
  (void)ctx;
  return sd_setup_machine_install_dir(out, cch) == 0;
}

static int real_launch(void *ctx, const wchar_t *exe, const wchar_t *cmdline, const wchar_t *dir)
{
  wchar_t cmd[SD_ELEV_CMD_CCH];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  (void)ctx;
  if (exe == NULL || cmdline == NULL || FAILED(StringCchCopyW(cmd, SD_ELEV_CMD_CCH, cmdline)))
    return 0;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  /* No runas and no wait: the UI runs with this process's token, the logged-on user (04 §6.4). */
  if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi))
    return 0;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 1;
}

void sd_setup_elev_real_ops(sd_setup_elev_ops *out)
{
  out->ctx = NULL;
  out->is_elevated = real_is_elevated;
  out->secure_programdata = real_secure;
  out->create_stage = real_create_stage;
  out->copy_image = real_copy_image;
  out->run = real_run;
  out->folder_trusted = real_folder_trusted;
  out->find_machine_product = real_find_machine_product;
  out->machine_dir = real_machine_dir;
  out->launch = real_launch;
}

/* ------------------------------------------------------------------ pipe */

DWORD sd_setup_elev_pipe_create(const wchar_t *name, HANDLE *out)
{
  wchar_t path[128];
  wchar_t sid[128];
  wchar_t sddl[256];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE h;
  DWORD err;

  if (out == NULL || !sd_setup_elev_pipe_name_ok(name))
    return ERROR_INVALID_PARAMETER;
  *out = INVALID_HANDLE_VALUE;
  if (FAILED(StringCchPrintfW(path, SD_SETUP_COUNTOF(path), L"\\\\.\\pipe\\%s", name)))
    return ERROR_BUFFER_OVERFLOW;
  if (sd_setup_current_sid(sid, SD_SETUP_COUNTOF(sid)) != 0)
    return ERROR_NO_TOKEN;
  StringCchPrintfW(sddl, SD_SETUP_COUNTOF(sddl), k_pipe_sddl_fmt, sid);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return GetLastError();
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  /* FIRST_PIPE_INSTANCE: a name created earlier by someone else makes this fail. */
  h = CreateNamedPipeW(path, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, 1, 0, 4096, 0, &sa);
  err = h == INVALID_HANDLE_VALUE ? GetLastError() : 0;
  LocalFree(sd);
  if (h != INVALID_HANDLE_VALUE)
    *out = h;
  return err;
}

DWORD sd_setup_elev_pipe_open(const wchar_t *name, HANDLE *out)
{
  wchar_t path[128];
  HANDLE h;

  if (out == NULL || !sd_setup_elev_pipe_name_ok(name))
    return ERROR_INVALID_PARAMETER;
  *out = INVALID_HANDLE_VALUE;
  if (FAILED(StringCchPrintfW(path, SD_SETUP_COUNTOF(path), L"\\\\.\\pipe\\%s", name)))
    return ERROR_BUFFER_OVERFLOW;
  WaitNamedPipeW(path, 5000);
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError();
  *out = h;
  return 0;
}

DWORD sd_setup_elev_pipe_write(HANDLE client, const wchar_t *text)
{
  wchar_t line[256];
  DWORD put = 0;
  DWORD bytes;

  if (client == INVALID_HANDLE_VALUE || client == NULL || text == NULL)
    return ERROR_INVALID_PARAMETER;
  if (FAILED(StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"%s\n", text)))
    return ERROR_BUFFER_OVERFLOW;
  bytes = (DWORD)(wcslen(line) * sizeof(wchar_t));
  if (!WriteFile(client, line, bytes, &put, NULL) || put != bytes)
    return ERROR_WRITE_FAULT;
  return 0;
}

DWORD sd_setup_elev_pipe_collect(HANDLE server, wchar_t *out, size_t cch)
{
  wchar_t chunk[256];
  DWORD got = 0;
  size_t used = 0;

  if (out == NULL || cch == 0)
    return ERROR_INVALID_PARAMETER;
  out[0] = L'\0';
  if (server == INVALID_HANDLE_VALUE || server == NULL)
    return ERROR_INVALID_HANDLE;
  /* The server end is nonblocking (CreateNamedPipe): a missing client gives ERROR_PIPE_LISTENING, never a wait. */
  if (!ConnectNamedPipe(server, NULL)) {
    DWORD e = GetLastError();
    if (e != ERROR_PIPE_CONNECTED && e != ERROR_PIPE_LISTENING && e != ERROR_NO_DATA)
      return e;
  }
  for (;;) {
    size_t n;
    if (!ReadFile(server, chunk, sizeof(chunk), &got, NULL)) {
      DWORD e = GetLastError();
      if (e == ERROR_NO_DATA || e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_LISTENING)
        break;
      return e;
    }
    if (got == 0)
      break;
    if (got % sizeof(wchar_t) != 0)
      return ERROR_INVALID_DATA;
    n = got / sizeof(wchar_t);
    if (used + n + 1 > cch)
      return ERROR_BUFFER_OVERFLOW;
    memcpy(out + used, chunk, got);
    used += n;
  }
  out[used] = L'\0';
  return 0;
}

/* The number after the last "R " that starts a line. */
int sd_setup_elev_result_line(const wchar_t *text, DWORD *exit_code)
{
  const wchar_t *p;
  const wchar_t *found = NULL;
  DWORD code = 0;

  if (text == NULL || exit_code == NULL)
    return 1;
  for (p = text; *p != L'\0'; p++) {
    if ((p == text || p[-1] == L'\n') && p[0] == L'R' && p[1] == L' ')
      found = p;
  }
  if (found == NULL || found[2] < L'0' || found[2] > L'9')
    return 1;
  for (p = found + 2; *p >= L'0' && *p <= L'9'; p++)
    code = code * 10 + (DWORD)(*p - L'0');
  *exit_code = code;
  return 0;
}

/* The "M <id> <code>" line, if any. Returns 1 when one was found. */
static int message_line(const wchar_t *text, sd_msg_id *msg, long *code)
{
  const wchar_t *p;
  unsigned long id = 0;
  long c = 0;
  int neg = 0;

  for (p = text; *p != L'\0'; p++) {
    if ((p == text || p[-1] == L'\n') && p[0] == L'M' && p[1] == L' ')
      break;
  }
  if (*p == L'\0')
    return 0;
  p += 2;
  if (*p < L'0' || *p > L'9')
    return 0;
  for (; *p >= L'0' && *p <= L'9'; p++)
    id = id * 10 + (unsigned long)(*p - L'0');
  if (*p != L' ')
    return 0;
  p++;
  if (*p == L'-') {
    neg = 1;
    p++;
  }
  if (*p < L'0' || *p > L'9')
    return 0;
  for (; *p >= L'0' && *p <= L'9'; p++)
    c = c * 10 + (long)(*p - L'0');
  *msg = (sd_msg_id)id;
  *code = neg ? -c : c;
  return 1;
}

/* ------------------------------------------------------------------ forwarded switches */

int sd_setup_elev_forward(const sd_setup_args *args, wchar_t *out, size_t cch)
{
  wchar_t tmp[128];
  const wchar_t *dokany;

  if (args == NULL || out == NULL || cch == 0)
    return 1;
  out[0] = L'\0';
  if (args->quiet)
    StringCchCatW(out, cch, L"/quiet ");
  else if (args->passive)
    StringCchCatW(out, cch, L"/passive ");
  if (args->mode == SD_SETUP_MODE_UNINSTALL)
    StringCchCatW(out, cch, L"/uninstall ");
  if (args->norestart)
    StringCchCatW(out, cch, L"/norestart ");
  if (args->force)
    StringCchCatW(out, cch, L"/force ");
  if (args->update)
    StringCchCatW(out, cch, L"/update ");
  if (args->dokany_set) {
    dokany = args->dokany == SD_SETUP_DOKANY_SKIP ? L"skip" : args->dokany == SD_SETUP_DOKANY_INSTALL ? L"install" : L"auto";
    StringCchPrintfW(tmp, SD_SETUP_COUNTOF(tmp), L"/dokany=%s ", dokany);
    StringCchCatW(out, cch, tmp);
  }
  if (args->lang[0] != L'\0') {
    StringCchPrintfW(tmp, SD_SETUP_COUNTOF(tmp), L"/lang=%s ", args->lang);
    StringCchCatW(out, cch, tmp);
  }
  if (args->flavour_forced) {
    /* The same flavour in every stage: the stages would otherwise pick their own (flavour_forced is checked by the host). */
    StringCchPrintfW(tmp, SD_SETUP_COUNTOF(tmp), L"/flavour=%s ", sd_setup_flavour_name(args->flavour));
    StringCchCatW(out, cch, tmp);
  }
  StringCchCatW(out, cch, args->props);
  return 0;
}

/* ------------------------------------------------------------------ parent */

static int fail_result(sd_setup_result *r, int exit_code, sd_msg_id msg, long code)
{
  memset(r, 0, sizeof(*r));
  r->exit_code = exit_code;
  r->msg = msg;
  r->code = code;
  return exit_code;
}

/* One stage start, run on a worker thread so that the parent can relay the progress lines while it waits. */
typedef struct elev_job {
  const sd_setup_elev_ops *ops;
  const wchar_t *base;
  const wchar_t *self;
  sd_setup_args args;
  DWORD rc;
  DWORD child;
} elev_job;

static DWORD WINAPI elev_job_main(LPVOID param)
{
  elev_job *j = (elev_job *)param;
  wchar_t fwd[SD_ELEV_FWD_CCH];
  wchar_t cmd[SD_ELEV_CMD_CCH];

  if (j->ops->is_elevated(j->ops->ctx)) {
    /* Already an administrator (XP, UAC off, or an elevated launch): no runas, but the same stage 1 (04 §6.4). */
    j->args.elevate_stage = 1;
    j->rc = sd_setup_elev_stage1(j->ops, j->base, j->self, &j->args, &j->child);
  } else if (sd_setup_elev_forward(&j->args, fwd, SD_SETUP_COUNTOF(fwd)) != 0) {
    j->rc = ERROR_BUFFER_OVERFLOW;
  } else {
    /* No path goes to the elevated stages (TM-R33, TM-R34): the /log= copy is written by the parent from the pipe. */
    StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\" /elevated-stage1 /pipe=%s %s", j->self, j->args.pipe_name,
                     fwd);
    j->rc = j->ops->run(j->ops->ctx, j->self, cmd, NULL, 1, &j->child);
  }
  return 0;
}

/* The result channel, read by the parent (04 §6.4). Lines are UTF-16: "P <n>", "M <id> <code>" and "R <n>" are control text
   (kept in text). The log block is "G" (opens it), then "L <hex>" lines of 1 to 64 bytes of msi.log, then "T" when the log
   was cut at SD_ELEV_LOG_CAP, and the block ends with the "R" line. The parent treats the block as bytes only: it never
   reads a path or a command from it. Anything malformed or oversized sets bad, and nothing is written. */
#define SD_ELEV_LOG_CAP ((size_t)4 * 1024 * 1024)
#define SD_ELEV_LINE_CCH 256
#define SD_ELEV_TEXT_CCH 2048

typedef struct elev_rx {
  wchar_t line[SD_ELEV_LINE_CCH];
  size_t nline;
  int discard;                  /* the current line is too long: skip to its end */
  int have_odd;                 /* a read ended on half a UTF-16 unit */
  unsigned char odd;
  wchar_t text[SD_ELEV_TEXT_CCH];
  size_t ntext;
  int block;                    /* 1 after "G" */
  int truncated;                /* 1 after "T" */
  int bad;                      /* malformed or oversized: nothing is written */
  unsigned char *log;
  size_t nlog;
} elev_rx;

static int hex_nibble(wchar_t c)
{
  if (c >= L'0' && c <= L'9')
    return c - L'0';
  if (c >= L'a' && c <= L'f')
    return c - L'a' + 10;
  if (c >= L'A' && c <= L'F')
    return c - L'A' + 10;
  return -1;
}

static void rx_hex_line(elev_rx *rx, const wchar_t *hex, size_t m)
{
  size_t i;
  size_t nb;

  if (!rx->block || m == 0 || (m % 2) != 0 || m > 2 * 64 || rx->log == NULL) {
    rx->bad = 1;
    return;
  }
  nb = m / 2;
  if (rx->nlog + nb > SD_ELEV_LOG_CAP) {
    rx->bad = 1;
    return;
  }
  for (i = 0; i < nb; i++) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      rx->bad = 1;
      return;
    }
    rx->log[rx->nlog++] = (unsigned char)((hi << 4) | lo);
  }
}

static void rx_line(elev_rx *rx)
{
  const wchar_t *l = rx->line;
  size_t n = rx->nline;

  /* A bad log block only drops the log (rx->bad); control lines still count, so the stage result is never lost. */
  if (n == 1 && l[0] == L'G') {
    if (rx->block) {
      rx->bad = 1;
      return;
    }
    rx->block = 1;
    rx->log = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, SD_ELEV_LOG_CAP);
    if (rx->log == NULL)
      rx->bad = 1;
    return;
  }
  if (n == 1 && l[0] == L'T') {
    if (!rx->block)
      rx->bad = 1;
    else
      rx->truncated = 1;
    return;
  }
  if (n >= 2 && l[0] == L'L' && l[1] == L' ') {
    rx_hex_line(rx, l + 2, n - 2);
    return;
  }
  /* Control text: appended with its line break, so that the line-start tests of last_progress and the result parsers hold. */
  if (rx->ntext + n + 2 > SD_ELEV_TEXT_CCH) {
    rx->bad = 1;
    return;
  }
  memcpy(rx->text + rx->ntext, l, n * sizeof(wchar_t));
  rx->ntext += n;
  rx->text[rx->ntext++] = L'\n';
  rx->text[rx->ntext] = L'\0';
}

static void rx_char(elev_rx *rx, wchar_t c)
{
  if (c == L'\n') {
    if (!rx->discard)
      rx_line(rx);
    rx->nline = 0;
    rx->discard = 0;
    return;
  }
  if (rx->discard)
    return;
  if (rx->nline + 1 >= SD_ELEV_LINE_CCH) {
    rx->bad = 1;
    rx->discard = 1;
    return;
  }
  rx->line[rx->nline++] = c;
}

/* Feeds n bytes of the pipe to the line reader (UTF-16LE). */
static void rx_bytes(elev_rx *rx, const unsigned char *p, DWORD n)
{
  DWORD i = 0;

  if (rx->have_odd && n > 0) {
    rx_char(rx, (wchar_t)(rx->odd | ((unsigned)p[0] << 8)));
    rx->have_odd = 0;
    i = 1;
  }
  for (; i + 1 < n; i += 2)
    rx_char(rx, (wchar_t)(p[i] | ((unsigned)p[i + 1] << 8)));
  if (i < n) {
    rx->odd = p[i];
    rx->have_odd = 1;
  }
}

/* Reads everything the stage has written so far (the server end is nonblocking). Returns the number of bytes read. */
static DWORD rx_read(HANDLE server, elev_rx *rx)
{
  unsigned char buf[1024];
  DWORD got = 0;
  DWORD total = 0;
  DWORD e;

  if (!ConnectNamedPipe(server, NULL)) {
    e = GetLastError();
    if (e != ERROR_PIPE_CONNECTED && e != ERROR_PIPE_LISTENING && e != ERROR_NO_DATA)
      return 0;
  }
  for (;;) {
    got = 0;
    if (!ReadFile(server, buf, sizeof(buf), &got, NULL) || got == 0)
      break;
    rx_bytes(rx, buf, got);
    total += got;
  }
  return total;
}

/* The last "P <n>" line of the control text: 1 with *value set when there is one. */
static int last_progress(const wchar_t *text, unsigned *value)
{
  const wchar_t *p;
  int found = 0;
  unsigned v = 0;

  for (p = text; *p != L'\0'; p++) {
    if ((p == text || p[-1] == L'\n') && p[0] == L'P' && p[1] == L' ' && p[2] >= L'0' && p[2] <= L'9') {
      const wchar_t *q;
      v = 0;
      for (q = p + 2; *q >= L'0' && *q <= L'9'; q++)
        v = v * 10 + (unsigned)(*q - L'0');
      if (v > 100)
        v = 100;
      found = 1;
    }
  }
  *value = v;
  return found;
}

/* Drains the pipe and reports a new percentage. Returns 1 when any byte was read. */
static int relay_read(HANDLE server, elev_rx *rx, sd_setup_elev_progress_fn progress, void *ctx, unsigned *last)
{
  unsigned value = 0;
  int got = rx_read(server, rx) != 0;

  if (last_progress(rx->text, &value) && value != *last) {
    *last = value;
    if (progress != NULL)
      progress(ctx, value);
  }
  return got;
}

/* 1 when path may take the log copy: an absolute drive path of a .log file, no parent-folder component, in a folder that
   exists and is not a reparse point. An existing target must be a plain file (it is replaced). */
static int log_target_ok(const wchar_t *path)
{
  wchar_t dir[MAX_PATH];
  size_t n = wcslen(path);
  size_t i;
  DWORD a;

  if (n < 8 || n >= MAX_PATH || path[1] != L':' || path[2] != L'\\' || wcschr(path, L'"') != NULL)
    return 0;
  for (i = 0; i + 1 < n; i++) {
    if (path[i] == L'.' && path[i + 1] == L'.')
      return 0;
  }
  if (_wcsicmp(path + n - 4, L".log") != 0 || parent_of(path, dir, MAX_PATH) != 0)
    return 0;
  a = GetFileAttributesW(dir);
  if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY) == 0 || (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    return 0;
  a = GetFileAttributesW(path);
  if (a != INVALID_FILE_ATTRIBUTES && ((a & FILE_ATTRIBUTE_DIRECTORY) != 0 || (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0))
    return 0;
  return 1;
}

/* Writes the bytes to path with the parent's own token (CREATE_ALWAYS). 0 or 1. */
static int write_log_file(const wchar_t *path, const unsigned char *data, size_t n)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD put = 0;
  int ok = 1;

  if (h == INVALID_HANDLE_VALUE)
    return 1;
  if (n > 0 && (!WriteFile(h, data, (DWORD)n, &put, NULL) || put != (DWORD)n))
    ok = 0;
  CloseHandle(h);
  return ok ? 0 : 1;
}

/* After the stage has finished: writes the relayed log block to log_path, or logs why it did not. Frees the block. */
static void elev_finish_log(elev_rx *rx, const wchar_t *log_path)
{
  if (rx->block && !rx->bad && log_path != NULL && log_path[0] != L'\0') {
    if (!log_target_ok(log_path)) {
      sd_setup_log("elevate.log_refused", L"the log path is not a usable .log file; nothing was written");
    } else if (write_log_file(log_path, rx->log, rx->nlog) == 0) {
      sd_setup_log(rx->truncated ? "elevate.log_truncated" : "elevate.log_written",
                   rx->truncated ? L"the stage log was cut at the size cap" : L"the stage log was written to the log path");
    } else {
      sd_setup_log("elevate.log_failed", L"the stage log could not be written");
    }
  } else if (rx->block && rx->bad) {
    sd_setup_log("elevate.log_malformed", L"the stage log block was malformed or too large; nothing was written");
  }
  if (rx->log != NULL)
    HeapFree(GetProcessHeap(), 0, rx->log);
  rx->log = NULL;
}

int sd_setup_elev_parent_ex(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                            const sd_setup_args *args, sd_setup_result *r, sd_setup_elev_progress_fn progress,
                            void *ctx)
{
  elev_job job;
  elev_rx rx;
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE thread = NULL;
  sd_msg_id msg = 0;
  long mcode = 0;
  unsigned last = (unsigned)-1;
  int drained = 0;
  DWORD rc;

  if (r == NULL)
    return SD_SETUP_EXIT_FATAL;
  memset(r, 0, sizeof(*r));
  if (ops == NULL || base == NULL || self == NULL || args == NULL)
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_GENERIC, 0);

  memset(&job, 0, sizeof(job));
  memset(&rx, 0, sizeof(rx));
  job.ops = ops;
  job.base = base;
  job.self = self;
  job.args = *args;
  if (sd_setup_elev_pipe_new_name(job.args.pipe_name, SD_SETUP_COUNTOF(job.args.pipe_name)) != 0)
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION, 0);
  rc = sd_setup_elev_pipe_create(job.args.pipe_name, &server);
  if (rc != 0)
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION, (long)rc);
  sd_setup_log("elevate.parent", job.args.pipe_name);

  thread = CreateThread(NULL, 0, elev_job_main, &job, 0, NULL);
  if (thread == NULL) {
    CloseHandle(server);
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION, (long)GetLastError());
  }
  /* Drain the pipe while the stage runs: a busy pipe blocks the stage, so the wait is short while data keeps coming.
     The tick lets the caller pump its window. */
  for (;;) {
    DWORD w = WaitForSingleObject(thread, drained ? 0 : 20);
    drained = relay_read(server, &rx, progress, ctx, &last);
    if (progress != NULL)
      progress(ctx, SD_SETUP_ELEV_TICK);
    if (w != WAIT_TIMEOUT)
      break;
  }
  CloseHandle(thread);
  rc = job.rc;

  /* The stage has finished: read the rest, then write the log block (if any) with the parent's token. */
  relay_read(server, &rx, progress, ctx, &last);
  CloseHandle(server);
  elev_finish_log(&rx, args->log_path);

  if (rc == ERROR_CANCELLED)
    return fail_result(r, SD_SETUP_EXIT_CANCEL, 0, 0);
  if (rc != 0) {
    sd_setup_log("elevate.failed", L"the elevated stage did not run");
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION, (long)rc);
  }

  if (sd_setup_elev_result_line(rx.text, &job.child) != 0)
    return fail_result(r, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_ELEVATION, (long)job.child);

  if (message_line(rx.text, &msg, &mcode)) {
    r->msg = msg;
    r->code = mcode;
  }
  r->exit_code = (int)job.child;
  if (job.child != SD_SETUP_EXIT_OK && job.child != SD_SETUP_EXIT_REBOOT && r->msg == 0)
    r->msg = SD_MSG_INSTALLER_ERROR_ELEVATION;
  sd_setup_log("elevate.result", L"the parent received the stage result");
  return r->exit_code;
}

int sd_setup_elev_parent(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                         const sd_setup_args *args, sd_setup_result *r)
{
  return sd_setup_elev_parent_ex(ops, base, self, args, r, NULL, NULL);
}

/* ------------------------------------------------------------------ stage 1 */

/* 1 when path is a plain file: it exists, is not a folder and is not a reparse point. */
static int plain_file(const wchar_t *path)
{
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0 && (a & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

DWORD sd_setup_elev_stage1(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                           const sd_setup_args *args, DWORD *child_exit)
{
  wchar_t root[MAX_PATH];
  wchar_t stage[MAX_PATH];
  wchar_t image[MAX_PATH];
  wchar_t fwd[SD_ELEV_FWD_CCH];
  wchar_t cmd[SD_ELEV_CMD_CCH];
  DWORD rc;

  if (ops == NULL || base == NULL || self == NULL || args == NULL || child_exit == NULL)
    return ERROR_INVALID_PARAMETER;
  *child_exit = (DWORD)SD_SETUP_EXIT_FATAL;
  if (!ops->is_elevated(ops->ctx))
    return ERROR_ACCESS_DENIED;
  if (!sd_setup_elev_pipe_name_ok(args->pipe_name))
    return ERROR_INVALID_PARAMETER;

  /* The vendor folders first (04 §6.4, TM-R34), then the stage root. */
  rc = ops->secure_programdata(ops->ctx, base);
  if (rc != 0)
    return rc;
  if (sd_setup_elev_root(base, root, SD_SETUP_COUNTOF(root)) != 0)
    return ERROR_BUFFER_OVERFLOW;
  if (sd_setup_mkdirs(root) != 0)
    return ERROR_PATH_NOT_FOUND;

  /* Step c: a new folder with its protected DACL in one call. */
  rc = ops->create_stage(ops->ctx, root, NULL, stage, SD_SETUP_COUNTOF(stage));
  if (rc != 0)
    return rc;
  if (sd_setup_path_join(image, MAX_PATH, stage, SD_ELEV_STAGE_LEAF) != 0)
    return ERROR_BUFFER_OVERFLOW;

  /* Step d: its own image. */
  rc = ops->copy_image(ops->ctx, self, image);
  if (rc != 0)
    return rc;

  /* Step e: stage 2 from the copy, with the same elevated token, and wait for it. */
  if (sd_setup_elev_forward(args, fwd, SD_SETUP_COUNTOF(fwd)) != 0)
    return ERROR_BUFFER_OVERFLOW;
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\" /elevated-child /pipe=%s %s", image, args->pipe_name, fwd);
  rc = ops->run(ops->ctx, image, cmd, stage, 0, child_exit);
  if (rc != 0)
    return rc;
  sd_setup_log("elevate.stage1", L"stage 2 finished");
  /* A successful stage removes its folder; a failed one keeps the MSI log for diagnosis (admin-only folder). */
  if (*child_exit == 0)
    sd_setup_remove_tree(stage, NULL);
  return 0;
}

/* ------------------------------------------------------------------ stage 2 */

/* Reports the message (when msg is not 0) and the exit code, then closes the channel. */
static DWORD stage2_end(HANDLE pipe, DWORD exit_code, sd_msg_id msg, long code)
{
  wchar_t line[128];
  if (msg != 0) {
    StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"M %lu %ld", (unsigned long)msg, code);
    sd_setup_elev_pipe_write(pipe, line);
  }
  StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"R %lu", (unsigned long)exit_code);
  sd_setup_elev_pipe_write(pipe, line);
  CloseHandle(pipe);
  sd_setup_log("elevate.stage2", line);
  return exit_code;
}

static void progress(HANDLE pipe, unsigned percent)
{
  wchar_t line[32];
  StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"P %u", percent);
  sd_setup_elev_pipe_write(pipe, line);
}

/* Sends msi.log of the stage folder over the pipe: "G", then "L <hex>" lines of up to 64 bytes, then "T" when the file is
   larger than SD_ELEV_LOG_CAP (only the first SD_ELEV_LOG_CAP bytes are sent). Nothing is sent when the file is not a
   plain file. Stage 2 never writes outside its folder; the path to the user's /log= is not known here. */
static void send_stage_log(HANDLE pipe, const wchar_t *dir)
{
  static const wchar_t digits[] = L"0123456789abcdef";
  wchar_t path[MAX_PATH];
  wchar_t line[SD_ELEV_LINE_CCH];
  unsigned char buf[64];
  HANDLE f;
  DWORD got = 0;
  size_t sent = 0;
  size_t i;
  int truncated = 0;

  sd_setup_elev_pipe_write(pipe, L"G");
  if (sd_setup_path_join(path, MAX_PATH, dir, SD_ELEV_MSI_LOG) != 0 || !plain_file(path))
    return;
  f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
    return;
  for (;;) {
    size_t want = sizeof(buf);
    if (sent == SD_ELEV_LOG_CAP) {
      /* At the cap: one more byte means the log is cut. */
      unsigned char probe;
      DWORD pg = 0;
      if (ReadFile(f, &probe, 1, &pg, NULL) && pg == 1)
        truncated = 1;
      break;
    }
    if (SD_ELEV_LOG_CAP - sent < want)
      want = SD_ELEV_LOG_CAP - sent;
    if (!ReadFile(f, buf, (DWORD)want, &got, NULL) || got == 0)
      break;
    line[0] = L'L';
    line[1] = L' ';
    for (i = 0; i < got; i++) {
      line[2 + 2 * i] = digits[buf[i] >> 4];
      line[3 + 2 * i] = digits[buf[i] & 15];
    }
    line[2 + 2 * got] = L'\0';
    if (sd_setup_elev_pipe_write(pipe, line) != 0)
      break;
    sent += got;
  }
  CloseHandle(f);
  if (truncated)
    sd_setup_elev_pipe_write(pipe, L"T");
}

/* The checks every stage 2 starts with (04 §6.4): an administrator token, a pipe name of the right shape, and a stage folder
   under the root that holds this image, with a trusted owner. Nothing from the command line is a path: the folder comes from
   this image (TM-R33, TM-R34). Returns 0 with dir set, or 1 with the message and code to report. */
static int stage2_guard(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                        const sd_setup_args *args, wchar_t *dir, size_t cch, sd_msg_id *msg, long *code)
{
  wchar_t root[MAX_PATH];

  *msg = 0;
  *code = 0;
  if (!ops->is_elevated(ops->ctx)) {
    *msg = SD_MSG_INSTALLER_ERROR_ELEVATION;
    *code = ERROR_ACCESS_DENIED;
    return 1;
  }
  if (!sd_setup_elev_pipe_name_ok(args->pipe_name) || sd_setup_elev_root(base, root, SD_SETUP_COUNTOF(root)) != 0) {
    *msg = SD_MSG_INSTALLER_ERROR_ELEVATION;
    *code = ERROR_INVALID_PARAMETER;
    return 1;
  }
  if (!image_in_stage(root, self) || parent_of(self, dir, cch) != 0) {
    *msg = SD_MSG_INSTALLER_ERROR_STAGE_UNTRUSTED;
    return 1;
  }
  if (!ops->folder_trusted(ops->ctx, dir)) {
    *msg = SD_MSG_INSTALLER_ERROR_STAGE_UNTRUSTED;
    return 1;
  }
  return 0;
}

DWORD sd_setup_elev_stage2(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                           const sd_setup_args *args, const sd_setup_payload *payload,
                           const unsigned char expected[32])
{
  HANDLE pipe = INVALID_HANDLE_VALUE;
  wchar_t dir[MAX_PATH];
  wchar_t pdir[MAX_PATH];
  wchar_t msi[MAX_PATH];
  wchar_t log[MAX_PATH];
  wchar_t exe[MAX_PATH];
  wchar_t cmd[SD_ELEV_CMD_CCH];
  unsigned char sha[32];
  sd_setup_result cab;
  unsigned files = 0;
  DWORD mcode = 0;
  DWORD rc;

  if (ops == NULL || base == NULL || self == NULL || args == NULL || payload == NULL || expected == NULL)
    return SD_SETUP_EXIT_FATAL;
  /* Without the channel nothing can be reported, so nothing starts. */
  if (sd_setup_elev_pipe_open(args->pipe_name, &pipe) != 0)
    return SD_SETUP_EXIT_FATAL;

  {
    sd_msg_id gmsg = 0;
    long gcode = 0;
    if (stage2_guard(ops, base, self, args, dir, SD_SETUP_COUNTOF(dir), &gmsg, &gcode) != 0)
      return stage2_end(pipe, SD_SETUP_EXIT_FATAL, gmsg, gcode);
  }

  /* The payload table check again, on the bytes this image carries. */
  sd_setup_sha256(payload->data, payload->size, sha);
  if (memcmp(sha, expected, 32) != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED, 0);

  progress(pipe, 10);
  memset(&cab, 0, sizeof(cab));
  if (sd_setup_path_join(pdir, MAX_PATH, dir, SD_ELEV_PAYLOAD_DIR) != 0 || sd_setup_mkdirs(pdir) != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_WRITE, 0);
  if (sd_setup_cab_extract(payload, pdir, NULL, &cab, &files) != 0) {
    sd_setup_remove_tree(pdir, NULL);
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, cab.msg != 0 ? cab.msg : SD_MSG_INSTALLER_ERROR_PAYLOAD_EXTRACT, 0);
  }
  progress(pipe, 40);

  /* The MSI must be a plain file in the payload folder: no link, no folder. */
  if (sd_setup_path_join(msi, MAX_PATH, pdir, SD_ELEV_MSI_LEAF) != 0 || !plain_file(msi)) {
    sd_setup_remove_tree(pdir, NULL);
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_MISSING, 0);
  }
  if (sd_setup_path_join(log, MAX_PATH, dir, SD_ELEV_MSI_LOG) != 0 ||
      sd_setup_system_path(L"msiexec.exe", exe, MAX_PATH) != 0) {
    sd_setup_remove_tree(pdir, NULL);
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_FAILED, 0);
  }
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\" /i \"%s\" %s%s /L*v \"%s\" %s", exe, msi,
                   args->quiet ? L"/qn" : L"/qb", args->norestart ? L" /norestart" : L"", log, args->props);

  progress(pipe, 60);
  rc = ops->run(ops->ctx, exe, cmd, dir, 0, &mcode);
  /* The msiexec log goes back over the pipe, before the result line (the parent writes the /log= copy). */
  send_stage_log(pipe, dir);
  sd_setup_remove_tree(pdir, NULL);
  if (rc != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_FAILED, (long)rc);
  if (mcode != SD_SETUP_EXIT_OK && mcode != SD_SETUP_EXIT_REBOOT)
    return stage2_end(pipe, mcode, SD_MSG_INSTALLER_ERROR_MSI_FAILED, (long)mcode);

  progress(pipe, 100);
  return stage2_end(pipe, mcode, 0, 0);
}

/* ------------------------------------------------------------------ per-machine uninstall and launch */

/* 1 when code has the shape of a braced product code (either letter case). */
static int product_code_ok(const wchar_t *code)
{
  size_t i;
  if (wcslen(code) != 38 || code[0] != L'{' || code[37] != L'}')
    return 0;
  for (i = 1; i < 37; i++) {
    wchar_t c = code[i];
    if (i == 9 || i == 14 || i == 19 || i == 24) {
      if (c != L'-')
        return 0;
    } else if (!is_hex(c) && !(c >= L'A' && c <= L'F')) {
      return 0;
    }
  }
  return 1;
}

DWORD sd_setup_elev_stage2_uninstall(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *self,
                                     const sd_setup_args *args)
{
  HANDLE pipe = INVALID_HANDLE_VALUE;
  wchar_t dir[MAX_PATH];
  wchar_t log[MAX_PATH];
  wchar_t exe[MAX_PATH];
  wchar_t code[64];
  wchar_t cmd[SD_ELEV_CMD_CCH];
  sd_msg_id gmsg = 0;
  long gcode = 0;
  DWORD mcode = 0;
  DWORD rc;

  if (ops == NULL || base == NULL || self == NULL || args == NULL)
    return SD_SETUP_EXIT_FATAL;
  if (sd_setup_elev_pipe_open(args->pipe_name, &pipe) != 0)
    return SD_SETUP_EXIT_FATAL;
  if (stage2_guard(ops, base, self, args, dir, SD_SETUP_COUNTOF(dir), &gmsg, &gcode) != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, gmsg, gcode);

  /* The product code is the one the machine registry holds for the ShellDrive MSI. It is never taken from the command
     line, and nothing runs when the registry has none or its value is not a product code. */
  code[0] = L'\0';
  if (!ops->find_machine_product(ops->ctx, code, SD_SETUP_COUNTOF(code)) || !product_code_ok(code))
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_NOT_INSTALLED, 0);

  progress(pipe, 10);
  if (sd_setup_path_join(log, MAX_PATH, dir, SD_ELEV_MSI_LOG) != 0 ||
      sd_setup_system_path(L"msiexec.exe", exe, MAX_PATH) != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_FAILED, 0);
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\" /x %s %s%s /L*v \"%s\" %s", exe, code,
                   args->quiet ? L"/qn" : L"/qb", args->norestart ? L" /norestart" : L"", log, args->props);

  progress(pipe, 60);
  rc = ops->run(ops->ctx, exe, cmd, dir, 0, &mcode);
  send_stage_log(pipe, dir);
  if (rc != 0)
    return stage2_end(pipe, SD_SETUP_EXIT_FATAL, SD_MSG_INSTALLER_ERROR_MSI_FAILED, (long)rc);
  if (mcode != SD_SETUP_EXIT_OK && mcode != SD_SETUP_EXIT_REBOOT)
    return stage2_end(pipe, mcode, SD_MSG_INSTALLER_ERROR_MSI_FAILED, (long)mcode);

  progress(pipe, 100);
  return stage2_end(pipe, mcode, 0, 0);
}

int sd_setup_elev_launch_installed(const sd_setup_elev_ops *ops)
{
  wchar_t dir[MAX_PATH];
  wchar_t exe[MAX_PATH];
  wchar_t cmd[MAX_PATH + 4];

  if (ops == NULL || ops->is_elevated == NULL || ops->machine_dir == NULL || ops->launch == NULL)
    return 1;
  /* The UI must not run with an administrator token: a parent that holds one does not start it. */
  if (ops->is_elevated(ops->ctx)) {
    sd_setup_log("launch.refused", L"the installer holds an administrator token; ShellDrive was not started");
    return 1;
  }
  if (!ops->machine_dir(ops->ctx, dir, MAX_PATH) || sd_setup_path_join(exe, MAX_PATH, dir, L"shelldrive-ui.exe") != 0)
    return 1;
  StringCchPrintfW(cmd, SD_SETUP_COUNTOF(cmd), L"\"%s\"", exe);
  if (ops->launch(ops->ctx, exe, cmd, dir))
    return 0;
  sd_setup_log("launch.failed", L"the installed ShellDrive could not be started");
  return 1;
}
