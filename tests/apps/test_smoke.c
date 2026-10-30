/* Host/CLI smoke test with the scripted fake backend (no network, no Dokany):
 * sd-test-cli.exe (the real CLI sources + SD_CLI_TEST_HOOKS) auto-starts sd-test-host-fake.exe
 * (the real agent sources + the fake backend + SD_HOST_TEST_HOOKS) and both run under an isolated
 * instance suffix and configuration root, so a real agent of the user is never touched. */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_platform/sd_time.h"

static wchar_t g_dir[MAX_PATH];     /* folder of the test executables */
static wchar_t g_root[MAX_PATH];    /* configuration root of this run */
static wchar_t g_suffix[64];

typedef struct run_result {
  DWORD exit_code;
  char out[16384];
  char err[16384];
} run_result;

static void wcat_u(wchar_t *dst, size_t cch, unsigned v)
{
  wchar_t tmp[16], o[16];
  size_t n = 0, i = 0;
  do { tmp[n++] = (wchar_t)(L'0' + v % 10); v /= 10; } while (v);
  while (n) o[i++] = tmp[--n];
  o[i] = 0;
  wcscat_s(dst, cch, o);
}

static int setup(void)
{
  static unsigned stamp;   /* one root per process: PIDs repeat, and an old root keeps its profiles */
  wchar_t v[MAX_PATH];
  DWORD n = GetModuleFileNameW(NULL, g_dir, MAX_PATH);
  size_t i, slash = 0;
  if (n == 0 || n >= MAX_PATH)
    return 0;
  for (i = 0; g_dir[i]; i++)
    if (g_dir[i] == L'\\') slash = i;
  g_dir[slash] = 0;
  if (stamp == 0) {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    stamp = qpc.LowPart | 1u;
  }
  /* the IPC names (Global\ shutdown event, pipes) carry the suffix: PID and stamp, as the root does */
  wcscpy_s(g_suffix, 64, L"smoke");
  wcat_u(g_suffix, 64, (unsigned)GetCurrentProcessId());
  wcscat_s(g_suffix, 64, L"x");
  wcat_u(g_suffix, 64, stamp);
  if (GetTempPathW(MAX_PATH, g_root) == 0)
    return 0;
  wcscat_s(g_root, MAX_PATH, L"sd-smoke-");
  wcat_u(g_root, MAX_PATH, (unsigned)GetCurrentProcessId());
  wcscat_s(g_root, MAX_PATH, L"-");
  wcat_u(g_root, MAX_PATH, stamp);
  CreateDirectoryW(g_root, NULL);
  wcscpy_s(v, MAX_PATH, g_root);
  wcscat_s(v, MAX_PATH, L"\\profiles");
  CreateDirectoryW(v, NULL);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_INSTANCE", g_suffix);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", g_root);
  wcscpy_s(v, MAX_PATH, g_dir);
  wcscat_s(v, MAX_PATH, L"\\sd-test-host-fake.exe");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_HOST_EXE", v);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_IDLE_MS", L"60000");
  SetEnvironmentVariableW(L"SHELLDRIVE_LANG", L"en");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_UI_LAUNCH", L"0");   /* never start the real prompt UI */
  sd_ipc_set_instance_suffix(g_suffix);
  return GetFileAttributesW(v) != INVALID_FILE_ATTRIBUTES;
}

static HANDLE temp_file(const wchar_t *name)
{
  wchar_t p[MAX_PATH];
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;
  wcscpy_s(p, MAX_PATH, g_root);
  wcscat_s(p, MAX_PATH, name);
  return CreateFileW(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
}

static void slurp(HANDLE h, char *out, size_t cap)
{
  DWORD got = 0;
  SetFilePointer(h, 0, NULL, FILE_BEGIN);
  if (!ReadFile(h, out, (DWORD)(cap - 1), &got, NULL))
    got = 0;
  out[got] = 0;
}

/* Runs sd-test-cli.exe with `args`, feeding `input` on stdin. */
static int run(const wchar_t *args, const char *input, run_result *r)
{
  wchar_t exe[MAX_PATH], cmd[2048];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  SECURITY_ATTRIBUTES sa;
  HANDLE in_r = NULL, in_w = NULL, out, err;
  DWORD put;
  int ok;
  memset(r, 0, sizeof(*r));
  wcscpy_s(exe, MAX_PATH, g_dir);
  wcscat_s(exe, MAX_PATH, L"\\sd-test-cli.exe");
  wcscpy_s(cmd, 2048, L"\"");
  wcscat_s(cmd, 2048, exe);
  wcscat_s(cmd, 2048, L"\" ");
  wcscat_s(cmd, 2048, args);
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;
  if (!CreatePipe(&in_r, &in_w, &sa, 65536))
    return 0;
  SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
  if (input) WriteFile(in_w, input, (DWORD)strlen(input), &put, NULL);
  CloseHandle(in_w);
  out = temp_file(L"\\out.txt");
  err = temp_file(L"\\err.txt");
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_r;
  si.hStdOutput = out;
  si.hStdError = err;
  ok = CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  CloseHandle(in_r);
  if (ok) {
    if (WaitForSingleObject(pi.hProcess, 60000) != WAIT_OBJECT_0) {
      TerminateProcess(pi.hProcess, 99);
      WaitForSingleObject(pi.hProcess, 5000);
    }
    GetExitCodeProcess(pi.hProcess, &r->exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
  slurp(out, r->out, sizeof(r->out));
  slurp(err, r->err, sizeof(r->err));
  CloseHandle(out);
  CloseHandle(err);
  return ok;
}

static void add_letter(wchar_t *s, size_t cch, wchar_t l)
{
  wchar_t t[3];
  t[0] = l; t[1] = L':'; t[2] = 0;
  wcscat_s(s, cch, t);
}

static void free_letters(wchar_t *a, wchar_t *b)
{
  DWORD used = GetLogicalDrives();
  wchar_t l;
  *a = *b = 0;
  for (l = L'R'; l >= L'E'; l--) {
    if (used & (1u << (l - L'A'))) continue;
    if (!*a) *a = l;
    else if (!*b) { *b = l; break; }
  }
}

static int agent_running(void)
{
  sd_ipc_hello h;
  sd_ipc_conn *c = NULL;
  memset(&h, 0, sizeof(h));
  h.client_kind = "cli";
  if (sd_ipc_connect(SD_IPC_AGENT, &h, 0, 1000, &c) != SD_OK)
    return 0;
  sd_ipc_close(c);
  return 1;
}

#define RUN(args, input) (run((args), (input), &r) ? (int)r.exit_code : -1)
#define EXPECT(cond, what) do { if (!(cond)) sd_test_fail(sd_t_, __FILE__, __LINE__, "%s\n  stdout: %s\n  stderr: %s", \
                                                     (what), r.out, r.err); } while (0)

/* Writes a text file into the isolated configuration root. */
static HANDLE write_root_file(const wchar_t *name, const char *content)
{
  wchar_t p[MAX_PATH];
  HANDLE h;
  DWORD put;
  wcscpy_s(p, MAX_PATH, g_root);
  wcscat_s(p, MAX_PATH, name);
  h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE)
    WriteFile(h, content, (DWORD)strlen(content), &put, NULL);
  return h;
}

/* A known_hosts file in a directory whose DACL passes the live-source check (TM-R06, 01 §7.2):
   only the owner, SYSTEM and Administrators may write. temp folders do not always qualify. */
static int write_trusted_hk_file(const char *content)
{
  wchar_t dir[MAX_PATH], path[MAX_PATH];
  PSECURITY_DESCRIPTOR sd = NULL;
  HANDLE h;
  DWORD put;
  int ok;
  wcscpy_s(dir, MAX_PATH, g_root);
  wcscat_s(dir, MAX_PATH, L"\\hkimp");
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", SDDL_REVISION_1, &sd, NULL))
    return 0;
  ok = CreateDirectoryW(dir, NULL) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
  if (ok) ok = SetFileSecurityW(dir, DACL_SECURITY_INFORMATION, sd) != 0;
  LocalFree(sd);
  if (!ok) return 0;
  wcscpy_s(path, MAX_PATH, dir);
  wcscat_s(path, MAX_PATH, L"\\known_hosts");
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  WriteFile(h, content, (DWORD)strlen(content), &put, NULL);
  CloseHandle(h);
  sd = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)", SDDL_REVISION_1, &sd, NULL))
    return 0;
  ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd) != 0;
  LocalFree(sd);
  return ok;
}

SD_TEST(smoke_version_help_usage)
{
  static run_result r;   /* 32 KiB: off the stack */
  SD_REQUIRE(setup());
  EXPECT(RUN(L"--version", NULL) == 0 && strstr(r.out, "ShellDrive 0.") != NULL, "--version");
  EXPECT(RUN(L"version --json", NULL) == 0 && strstr(r.out, "\"ok\":true") != NULL, "version --json");
  EXPECT(RUN(L"--help", NULL) == 0 && strstr(r.out, "Usage: shelldrive") != NULL &&
         strstr(r.out, "Mount a profile or a server as a drive.") != NULL, "--help");
  EXPECT(RUN(L"frobnicate", NULL) == 2 && strstr(r.err, "Unknown command: frobnicate") != NULL, "unknown command");
  EXPECT(RUN(L"mount", NULL) == 2 && strstr(r.err, "needs more arguments") != NULL, "missing argument");
  EXPECT(RUN(L"mount --host x.test --letter C:", NULL) == 2 && strstr(r.err, "Invalid drive letter") != NULL, "letter");
  EXPECT(RUN(L"--json mount", NULL) == 2 && strstr(r.out, "\"code\":\"usage\"") != NULL, "usage json");
  EXPECT(RUN(L"--lang xx list", NULL) == 2, "bad --lang");
  /* localized output: Spanish (voseo) and German, UTF-8 when redirected */
  EXPECT(RUN(L"--lang es frobnicate", NULL) == 2 && strstr(r.err, "Ejecut\xc3\xa1") != NULL, "es");
  EXPECT(RUN(L"--lang de list", NULL) == 0 && strstr(r.out, "Es sind keine Laufwerke eingebunden.") != NULL, "de");
  /* no agent: list does not start one */
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"mounts\":[]") != NULL, "list without agent");
  SD_CHECK(!agent_running());
}

SD_TEST(smoke_mount_prompts_and_errors)
{
  static run_result r;   /* 32 KiB: off the stack */
  wchar_t l1, l2, args[512];
  char want[64];
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1 && l2);

  /* TOFU accept + password over --stdin, auto-starting the agent */
  wcscpy_s(args, 512, L"mount --host alice@good.test --letter ");
  add_letter(args, 512, l1);
  wcscat_s(args, 512, L" --stdin --json");
  EXPECT(RUN(args, "y\nsecret\n") == 0 && strstr(r.out, "\"state\":\"mounted\"") != NULL, "mount good.test");
  EXPECT(strstr(r.err, "SHA256:") != NULL && strstr(r.err, "can't be established") != NULL, "TOFU text");
  SD_CHECK(agent_running());
  want[0] = '"'; want[1] = (char)l1; want[2] = ':'; want[3] = '"'; want[4] = 0;
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, want) != NULL && strstr(r.out, "good.test") != NULL &&
         strstr(r.out, "\"mounted\"") != NULL, "list shows the mount");
  EXPECT(RUN(L"list", NULL) == 0 && strstr(r.out, "alice@good.test") != NULL && strstr(r.out, "1 drive mounted.") != NULL,
         "list text");

  /* same letter again: target_in_use (10) */
  wcscpy_s(args, 512, L"mount --host bob@other.test --prompt none --letter ");
  add_letter(args, 512, l1);
  EXPECT(RUN(args, NULL) == 10 && strstr(r.err, "already in use") != NULL, "target_in_use");

  /* changed host key: hard failure (6), no prompt, details shown */
  wcscpy_s(args, 512, L"mount --host bob@mismatch.test --stdin --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, "y\n") == 6 && strstr(r.err, "has changed") != NULL && strstr(r.err, "line 3") != NULL &&
         strstr(r.err, "Trust this key") == NULL, "mismatch");

  /* unknown key, not allowed to ask: host_key_unknown (5) */
  wcscpy_s(args, 512, L"--json mount --host carol@new.test --prompt none --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, NULL) == 5 && strstr(r.out, "\"code\":\"host_key_unknown\"") != NULL, "host_key_unknown");

  /* the default answer is no: empty line rejects (5) */
  wcscpy_s(args, 512, L"mount --host carol@new.test --stdin --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, "\n") == 5 && strstr(r.err, "did not trust") != NULL, "reject by default");

  /* the port is an identifier: never digit-grouped by the user locale ("port 2,222" regression) */
  wcscpy_s(args, 512, L"mount --host carol@new.test:2222 --stdin --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, "\n") == 5 && strstr(r.err, "(port 2222)") != NULL, "port not grouped");

  /* wrong password twice: auth_failed (4); each answer asks "Save the answer?" (4.2) */
  wcscpy_s(args, 512, L"mount --host dave@pw.test --stdin --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, "o\nwrong\nn\nwrong\nn\n") == 4 && strstr(r.err, "Signing in to pw.test failed") != NULL, "auth_failed");

  /* "once" did not store the key: pw.test asks again; EOF on stdin rejects (5) */
  EXPECT(RUN(args, "") == 5, "once is not stored");

  /* unreachable server (7) */
  wcscpy_s(args, 512, L"mount --host eve@unreachable.test --stdin --letter ");
  add_letter(args, 512, l2);
  EXPECT(RUN(args, "") == 7 && strstr(r.err, "refused the connection") != NULL, "conn_refused");

  /* profile mount: good.test is trusted now, only the password is asked */
  {
    wchar_t p[MAX_PATH];
    char ini[256];
    HANDLE h;
    DWORD put;
    wcscpy_s(p, MAX_PATH, g_root);
    wcscat_s(p, MAX_PATH, L"\\profiles\\web.ini");
    strcpy_s(ini, sizeof(ini), "[profile]\r\nname = Web\r\nhost = good.test\r\nuser = alice\r\n[mount]\r\ntarget = ?:\r\n");
    *strchr(ini, '?') = (char)l2;
    h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SD_REQUIRE(h != INVALID_HANDLE_VALUE);
    WriteFile(h, ini, (DWORD)strlen(ini), &put, NULL);
    CloseHandle(h);
  }
  EXPECT(RUN(L"mount web --stdin", "secret\n") == 0 && strstr(r.out, "Mounted Web on") != NULL, "profile mount");
  EXPECT(RUN(L"mount Web --stdin", "secret\n") == 10, "already_mounted");
  EXPECT(RUN(L"mount nosuch --prompt none", NULL) == 3 && strstr(r.err, "no profile named nosuch") != NULL,
         "profile_not_found");

  /* unmount by letter and by profile, then nothing is left */
  wcscpy_s(args, 512, L"unmount ");
  add_letter(args, 512, l1);
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "Unmounted") != NULL, "unmount letter");
  EXPECT(RUN(L"unmount Web", NULL) == 0, "unmount profile");
  EXPECT(RUN(L"unmount Q:", NULL) == 3 && strstr(r.err, "No ShellDrive drive matches") != NULL, "mount_not_found");
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"mounts\":[]") != NULL, "empty after unmount");

  /* agent stop: the pipe goes away */
  EXPECT(RUN(L"agent stop", NULL) == 0 && strstr(r.out, "stopped") != NULL, "agent stop");
  {
    uint64_t end = sd_tick_ms() + 10000;
    while (agent_running() && sd_tick_ms() < end) Sleep(100);
  }
  SD_CHECK(!agent_running());
  EXPECT(RUN(L"agent stop", NULL) == 0 && strstr(r.out, "not running") != NULL, "agent stop again");
}

/* M2 CLI: --jump, --proxy, password change, legacy ack and the save question over --stdin. */
SD_TEST(smoke_mount_m2_flags_and_prompts)
{
  static run_result r;   /* 32 KiB: off the stack */
  wchar_t l1, l2, args[768];
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1 && l2);

  /* jump chain + keyboard-interactive OTP: bastion TOFU, bastion password, no save,
     target TOFU, the kbd password round, the OTP round */
  wcscpy_s(args, 768, L"mount --host carol@kbd.test --jump alice@bastion.test --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nsecret\nn\ny\nsecret\n123456\n") == 0, "jump + kbdint mount");
  EXPECT(strstr(r.err, "Jump host 1 of 2") != NULL && strstr(r.err, "Reached through jump host") != NULL,
         "jump chain prompt lines");
  EXPECT(strstr(r.err, "Verification code") != NULL, "otp prompt text");

  /* proxy with a user: the proxy password is asked (not saved), then TOFU and the server password */
  wcscpy_s(args, 768, L"mount --host dave@pw.test --proxy http://pu@10.0.0.1:3128 --stdin --letter ");
  add_letter(args, 768, l2);
  EXPECT(RUN(args, "proxypw\nn\ny\nsecret\n") == 0, "proxy password mount");
  EXPECT(strstr(r.err, "Password for the proxy") != NULL, "proxy prompt");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount all");

  /* password change (SSH_MSG_USERAUTH_PASSWD_CHANGEREQ): TOFU, current, new, confirm */
  wcscpy_s(args, 768, L"mount --host erin@chpw.test --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nsecret\nn\nsecret\nn3w\nn3w\n") == 0, "password change mount");
  EXPECT(strstr(r.err, "change the password") != NULL && strstr(r.err, "Your password has expired.") != NULL,
         "password change prompts");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount all");

  /* legacy ack (profile with legacy_algorithms = ask): TOFU, continue?, password */
  {
    wchar_t p[MAX_PATH];
    char ini[256];
    HANDLE h;
    DWORD put;
    wcscpy_s(p, MAX_PATH, g_root);
    wcscat_s(p, MAX_PATH, L"\\profiles\\legacyask.ini");
    strcpy_s(ini, sizeof(ini), "[profile]\r\nname = LegacyAsk\r\nhost = legacy.test\r\nuser = lara\r\n"
                               "[security]\r\nlegacy_algorithms = ask\r\n[mount]\r\ntarget = ?:\r\n");
    *strchr(ini, '?') = (char)l2;
    h = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SD_REQUIRE(h != INVALID_HANDLE_VALUE);
    WriteFile(h, ini, (DWORD)strlen(ini), &put, NULL);
    CloseHandle(h);
  }
  EXPECT(RUN(L"mount LegacyAsk --stdin", "y\ny\nsecret\nn\n") == 0, "legacy ask mount");
  EXPECT(strstr(r.err, "uses outdated encryption") != NULL && strstr(r.err, "3des-cbc,hmac-sha1") != NULL &&
         strstr(r.err, "Continue anyway") != NULL, "legacy ack prompt");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount all");

  /* the save question is offered (can_save); the default answer keeps nothing */
  wcscpy_s(args, 768, L"mount --host gina@save.test --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nsecret\nn\n") == 0, "save question asked");
  EXPECT(strstr(r.err, "Save the answer") != NULL, "save question text");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount all");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
}

/* M2 CLI: --connections reaches the pool, and status reports the 2FA rule (pool < wanted, D18). */
SD_TEST(smoke_status_and_pool_flag)
{
  static run_result r;
  wchar_t l1, l2, args[512];
  int i;
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1);

  /* publickey only (identity): the mount needs no typed answer; the pool member still asks for a
     password and is cancelled, so the pool stays at 1 of 3 */
  wcscpy_s(args, 512, L"mount --host gus@pool.test --connections 3 --identity C:\\k\\id --stdin --json --letter ");
  add_letter(args, 512, l1);
  EXPECT(RUN(args, "y\n") == 0 && strstr(r.out, "\"state\":\"mounted\"") != NULL, "pool flag mount");
  for (i = 0; i < 30; i++) {
    if (RUN(L"status --json", NULL) == 0 && strstr(r.out, "\"pool_wanted\":3") != NULL)
      break;
    Sleep(100);
  }
  EXPECT(i < 30, "status shows the pool rule");
  EXPECT(RUN(L"status pool.test", NULL) == 0 && strstr(r.out, "pool.test") != NULL, "status by profile");
  EXPECT(RUN(L"status nosuchstat", NULL) == 3 && strstr(r.err, "No ShellDrive drive matches") != NULL,
         "status not found");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
}

/* M2 CLI: profile import from ssh_config (preview, dry run, duplicates, write, mount). */
SD_TEST(smoke_profile_import)
{
  static run_result r;
  wchar_t l1, l2, args[768], p[MAX_PATH];
  HANDLE h;
  static const char cfg[] =
    "Host smokeimp\r\n  HostName good.test\r\n  User bob\r\n  IdentityFile C:\\k\\id_ed25519\r\n"
    "\r\nHost webdup\r\n  HostName good.test\r\n  User alice\r\n";
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1);
  h = write_root_file(L"\\smokecfg", cfg);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  CloseHandle(h);
  wcscpy_s(p, MAX_PATH, g_root);
  wcscat_s(p, MAX_PATH, L"\\smokecfg");

  /* dry run: the duplicate of the "web" profile is unselected, nothing is written */
  wcscpy_s(args, 768, L"profile import ssh-config ");
  wcscat_s(args, 768, p);
  wcscat_s(args, 768, L" --dry-run --json");
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"dry_run\":true") != NULL &&
         strstr(r.out, "\"source\":\"webdup\"") != NULL && strstr(r.out, "\"selected\":false") != NULL,
         "profile import dry run");
  EXPECT(RUN(L"mount smokeimp --prompt none", NULL) == 3, "dry run wrote nothing");

  /* real import: the duplicate stays out, smokeimp is written */
  wcscpy_s(args, 768, L"profile import ssh-config ");
  wcscat_s(args, 768, p);
  wcscat_s(args, 768, L" --json");
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"imported\":1") != NULL, "profile import writes one");

  /* the imported profile mounts (publickey; only the key trust is asked) */
  wcscpy_s(args, 768, L"mount smokeimp --stdin --json --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\n") == 0 && strstr(r.out, "\"state\":\"mounted\"") != NULL, "imported profile mounts");

  /* error cases: unknown session and unreadable file are "not found" (3) */
  EXPECT(RUN(L"profile import putty NoSuchSessionXYZ", NULL) == 3, "putty session not found");
  wcscpy_s(args, 768, L"profile import ssh-config ");
  wcscat_s(args, 768, g_root);
  wcscat_s(args, 768, L"\\nosuch.cfg");
  EXPECT(RUN(args, NULL) == 3, "ssh_config not found");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
}

/* M2 CLI: hostkey list/import/remove in this process, and the UpdateHostKeys review (5.6) over IPC. */
SD_TEST(smoke_hostkey_commands)
{
  static run_result r;
  wchar_t l1, l2, args[768], p[MAX_PATH];
  HANDLE h;
  int i;
  /* a real ed25519 public blob (throwaway key generated for this test) */
  static const char kh_line[] = "smokehk.test ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIJPQ/a+syj5MkprlW0zba5copBFI6SboNSepzryXyz6Q added=2026-10-27 by=shelldrive-test\n";
  static const char imp_line[] = "imp.test ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIJPQ/a+syj5MkprlW0zba5copBFI6SboNSepzryXyz6Q\n";
  SD_REQUIRE(setup());
  h = write_root_file(L"\\known_hosts", kh_line);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  CloseHandle(h);
  SD_REQUIRE(write_trusted_hk_file(imp_line));

  EXPECT(RUN(L"hostkey list smokehk.test --json", NULL) == 0 && strstr(r.out, "\"store\":\"user\"") != NULL &&
         strstr(r.out, "SHA256:") != NULL && strstr(r.out, "\"type\":\"ssh-ed25519\"") != NULL,
         "hostkey list json");
  EXPECT(RUN(L"hostkey list smokehk.test", NULL) == 0 && strstr(r.out, "ssh-ed25519") != NULL, "hostkey list text");
  EXPECT(RUN(L"hostkey list nokey.test", NULL) == 0 && strstr(r.out, "No host key is stored") != NULL,
         "hostkey list empty");
  EXPECT(RUN(L"hostkey list", NULL) == 2, "hostkey list needs a host");

  wcscpy_s(p, MAX_PATH, g_root);
  wcscat_s(p, MAX_PATH, L"\\hkimp\\known_hosts");
  wcscpy_s(args, 768, L"hostkey import --from openssh ");
  wcscat_s(args, 768, p);
  wcscat_s(args, 768, L" --json");
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"imported\":1") != NULL, "hostkey import");
  EXPECT(RUN(L"hostkey list imp.test --json", NULL) == 0 && strstr(r.out, "\"store\":\"user\"") != NULL,
         "imported key is listed");
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"already_present\":1") != NULL, "import again keeps");

  EXPECT(RUN(L"hostkey remove smokehk.test --json", NULL) == 0, "hostkey remove");
  EXPECT(RUN(L"hostkey remove smokehk.test", NULL) == 3 && strstr(r.err, "No host key of") != NULL,
         "remove again is not found");

  EXPECT(RUN(L"hostkey list --announced --json", NULL) == 0, "no announcements without an agent");

  /* the review path: a mount whose server announces new keys keeps the announcement in the agent */
  free_letters(&l1, &l2);
  SD_REQUIRE(l1);
  wcscpy_s(args, 768, L"mount --host fay@rotate.test --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nsecret\nn\n") == 0, "rotate mount");
  for (i = 0; i < 30; i++) {
    if (RUN(L"hostkey list --announced --json", NULL) == 0 && strstr(r.out, "rotate.test") != NULL &&
        strstr(r.out, "\"id\":\"a-") != NULL)
      break;
    Sleep(100);
  }
  EXPECT(i < 30, "announcement listed");
  EXPECT(RUN(L"hostkey accept-announced a-1 --add-only --json", NULL) == 0 &&
         strstr(r.out, "\"removed\":0") != NULL, "accept add-only");
  EXPECT(RUN(L"hostkey accept-announced a-1", NULL) == 3, "announcement consumed");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
}

/* TM-R19 (03 §7.5): the agent starts the WebDAV mount without SSPI (SHELLDRIVE_TEST_WD_NOAUTH=1, read by the fake
   at start), so the token-only question reaches the console. The variable is set before the first run (that run
   starts the agent, which inherits it) and cleared at the end of each test. */
static void wd_noauth(int on)
{
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_WD_NOAUTH", on ? L"1" : NULL);
}

/* The question line of the console prompt (cli.prompt.webdav_token_only_question, en). */
#define TOKEN_ONLY_TEXT "less protected connection"

/* "y" on the console: the enable is mounted over WebDAV in token-only mode (list reports backend webdav). */
SD_TEST(smoke_webdav_token_only_cli_yes)
{
  static run_result r;
  wchar_t l1, l2, args[768];
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1);
  wd_noauth(1);
  /* host key (y), then the token-only question (y); publickey, so no password is asked */
  wcscpy_s(args, 768, L"mount --host tokyes.test --backend webdav --identity C:\\k\\id --stdin --json --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\ny\n") == 0 && strstr(r.out, "\"state\":\"mounted\"") != NULL, "token-only mount");
  EXPECT(strstr(r.err, TOKEN_ONLY_TEXT) != NULL, "token-only question asked on the console");
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"backend\":\"webdav\"") != NULL &&
         strstr(r.out, "\"state\":\"mounted\"") != NULL, "list shows the webdav mount");
  EXPECT(RUN(L"unmount --all", NULL) == 0, "unmount");
  EXPECT(RUN(L"agent stop", NULL) == 0 && strstr(r.out, "stopped") != NULL, "agent stop");
  wd_noauth(0);
}

/* "n" and an empty line (the default is no) both refuse: exit 4 (authentication, 03 §6.2) with the
   token_only_refused code, nothing mounted, and the question was asked. */
SD_TEST(smoke_webdav_token_only_cli_refused)
{
  static run_result r;
  wchar_t l1, l2, args[768];
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1 && l2);
  wd_noauth(1);
  wcscpy_s(args, 768, L"--json mount --host tokno.test --backend webdav --identity C:\\k\\id --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nn\n") == 4 && strstr(r.out, "\"code\":\"token_only_refused\"") != NULL, "answer n refuses");
  EXPECT(strstr(r.err, TOKEN_ONLY_TEXT) != NULL, "question asked for n");
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"mounts\":[]") != NULL, "nothing mounted after n");

  wcscpy_s(args, 768, L"--json mount --host tokempty.test --backend webdav --identity C:\\k\\id --stdin --letter ");
  add_letter(args, 768, l2);
  EXPECT(RUN(args, "y\n\n") == 4 && strstr(r.out, "\"code\":\"token_only_refused\"") != NULL, "empty answer refuses");
  EXPECT(strstr(r.err, TOKEN_ONLY_TEXT) != NULL, "question asked for an empty answer");
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"mounts\":[]") != NULL, "nothing mounted after empty");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
  wd_noauth(0);
}

/* --prompt none: the question is never asked on the console; the mount is refused with prompt_required (exit 4).
   The host key is stored first (a refused token-only question does not undo the host trust). */
SD_TEST(smoke_webdav_token_only_prompt_none)
{
  static run_result r;
  wchar_t l1, l2, args[768];
  SD_REQUIRE(setup());
  free_letters(&l1, &l2);
  SD_REQUIRE(l1);
  wd_noauth(1);
  wcscpy_s(args, 768, L"mount --host tokprompt.test --backend webdav --identity C:\\k\\id --stdin --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, "y\nn\n") == 4, "host key stored, token-only refused");
  wcscpy_s(args, 768, L"--json mount --host tokprompt.test --backend webdav --identity C:\\k\\id --prompt none --letter ");
  add_letter(args, 768, l1);
  EXPECT(RUN(args, NULL) == 4 && strstr(r.out, "\"code\":\"prompt_required\"") != NULL, "prompt none refuses");
  EXPECT(strstr(r.err, TOKEN_ONLY_TEXT) == NULL, "prompt none does not ask");
  EXPECT(RUN(L"list --json", NULL) == 0 && strstr(r.out, "\"mounts\":[]") != NULL, "nothing mounted with prompt none");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
  wd_noauth(0);
}

/* hostkey add, accept-announced and list --announced with --machine without an elevated console (exit 9). The elevated
   path talks to the service pipe, which no smoke test starts: it is covered by the service tests (tests/unit/sd_svc,
   svc_hostkey_*). SHELLDRIVE_TEST_ELEVATED=0 reports a non-elevated token; the store is never touched. */
SD_TEST(smoke_hostkey_add_machine)
{
  static run_result r;
  SD_REQUIRE(setup());
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", L"0");
  EXPECT(RUN(L"hostkey add --from-server smokehk.test --machine", NULL) == 9 &&
         strstr(r.err, "elevated console") != NULL, "machine add needs an elevated console");
  EXPECT(RUN(L"hostkey add --from-server smokehk.test --machine --json", NULL) == 9 &&
         strstr(r.out, "access_denied") != NULL, "machine add json is access_denied");
  EXPECT(RUN(L"hostkey accept-announced a-1 --machine", NULL) == 9, "machine accept needs an elevated console");
  EXPECT(RUN(L"hostkey list --announced --machine", NULL) == 9 &&
         strstr(r.err, "elevated console") != NULL, "machine announcements need an elevated console");
  EXPECT(RUN(L"hostkey list --announced --machine --json", NULL) == 9 &&
         strstr(r.out, "access_denied") != NULL, "machine announcements json is access_denied");
  /* without --machine the agent does the connect (smoke_hostkey_add_offers covers the rest; the CLI starts the agent
     on demand and this test stops it at the end): a first contact that nobody answers is refused, and a fingerprint
     that matches nothing is refused as well */
  EXPECT(RUN(L"hostkey add --from-server smokehk.test", NULL) == 5 &&
         strstr(r.err, "[y]es") != NULL, "user add without an answer is refused");
  EXPECT(RUN(L"hostkey add --from-server smokehk.test --expect SHA256:abcdefgh --json", NULL) == 5 &&
         strstr(r.out, "host_key_rejected") != NULL, "user add json with a fingerprint that matches nothing");
  EXPECT(RUN(L"hostkey add smokehk.test", NULL) == 2, "add needs --from-server");
  EXPECT(RUN(L"hostkey add --from-server smokehk.test --expect md5:abcdef", NULL) == 2, "bad --expect");
  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", NULL);
}

/* diag bench (03 §6.1, 02 §11) through the real CLI: usage errors, a drive that is not there, and short runs into a
   folder of the test (SHELLDRIVE_TEST_BENCH_ROOT, test builds only). Timings are never asserted: the reports must carry
   the structure and the numbers, and the folder must be empty again afterwards. */
SD_TEST(smoke_diag_bench)
{
  static run_result r;
  wchar_t root[MAX_PATH], pat[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE fh;
  int leftover = 0;
  LARGE_INTEGER qpc;
  SD_REQUIRE(setup());
  EXPECT(RUN(L"diag bench", NULL) == 2, "diag bench needs a drive");
  EXPECT(RUN(L"diag check Y:", NULL) == 2 && strstr(r.err, "check") != NULL, "only diag bench exists");
  EXPECT(RUN(L"bench Y: --size 0", NULL) == 2, "size 0 refused");
  EXPECT(RUN(L"bench Y: --write-mode sync", NULL) == 2, "unknown write mode refused");
  EXPECT(RUN(L"--json bench Y: --scenario nope", NULL) == 2 && strstr(r.out, "\"code\":\"usage\"") != NULL, "bad scenario json");
  if (GetFileAttributesW(L"Y:\\") == INVALID_FILE_ATTRIBUTES)
    EXPECT(RUN(L"--json bench Y:", NULL) == 3 && strstr(r.out, "\"code\":\"mount_not_found\"") != NULL, "no drive Y:");

  /* a folder of the test stands in for the drive */
  SD_REQUIRE(GetTempPathW(MAX_PATH, root) != 0);
  wcscat_s(root, MAX_PATH, L"sd-bench-");
  wcat_u(root, MAX_PATH, (unsigned)GetCurrentProcessId());
  wcscat_s(root, MAX_PATH, L"-");
  QueryPerformanceCounter(&qpc);
  wcat_u(root, MAX_PATH, (unsigned)qpc.LowPart);
  SD_REQUIRE(CreateDirectoryW(root, NULL));
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_BENCH_ROOT", root);
  EXPECT(RUN(L"--json diag bench Y: --scenario open --size 1", NULL) == 0 &&
         strstr(r.out, "\"ok\":true") != NULL && strstr(r.out, "\"name\":\"open\"") != NULL &&
         strstr(r.out, "\"read_p95_ms\":") != NULL && strstr(r.out, "\"write_mode\":\"through\"") != NULL &&
         strstr(r.out, "\"pool\":null") != NULL && strstr(r.out, "\"cleaned\":true") != NULL, "open json");
  EXPECT(RUN(L"--json bench Y: --scenario seq-write --size 1 --write-mode behind", NULL) == 0 &&
         strstr(r.out, "\"name\":\"seq-write\"") != NULL && strstr(r.out, "\"block_bytes\":1048576") != NULL &&
         strstr(r.out, "\"mb_per_s\":") != NULL && strstr(r.out, "\"write_mode\":\"behind\"") != NULL, "seq write json");
  EXPECT(RUN(L"--json bench Y: --scenario seq-write-64k --size 1", NULL) == 0 &&
         strstr(r.out, "\"block_bytes\":65536") != NULL, "64 KiB write json");
  EXPECT(RUN(L"--json bench Y: --scenario seq-read --size 1", NULL) == 0 &&
         strstr(r.out, "\"name\":\"seq-read\"") != NULL, "seq read json (prepares its own file)");
  EXPECT(RUN(L"--json bench Y: --scenario small-files --size 1", NULL) == 0 &&
         strstr(r.out, "\"files\":1000") != NULL && strstr(r.out, "\"ms_per_file\":") != NULL, "small files json");
  EXPECT(RUN(L"bench Y: --scenario open --size 1", NULL) == 0 && strstr(r.out, "Benchmark of Y:") != NULL &&
         strstr(r.out, "Open of an existing file") != NULL && strstr(r.out, "Temporary folder removed.") != NULL,
         "human report");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_BENCH_ROOT", NULL);

  /* every file of the runs went with the run: the folder is empty */
  wcscpy_s(pat, MAX_PATH, root);
  wcscat_s(pat, MAX_PATH, L"\\*");
  fh = FindFirstFileW(pat, &fd);
  if (fh != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) leftover++;
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
  }
  EXPECT(leftover == 0, "the bench left nothing in the folder");
  RemoveDirectoryW(root);
  SD_CHECK(!agent_running());
}

/* hostkey add without --machine (03 §6.1, 5.2, TM-R04) through the agent and the scripted fake (host_fake_backend.c):
   *.known.test verifies with a stored key and has an ECDSA and an ssh-rsa key besides it; *.changed.test does not
   match the stored key; any other host is a first contact with one ssh-ed25519 key (TOFU). */

/* copies the text after the first occurrence of key (up to the next quote) into dst */
static int json_value_after(const char *out, const char *key, char *dst, size_t cap)
{
  const char *p = strstr(out, key);
  size_t n = 0;
  if (p == NULL)
    return 0;
  p += strlen(key);
  while (p[n] && p[n] != '"' && n + 1 < cap) {
    dst[n] = p[n];
    n++;
  }
  dst[n] = 0;
  return n > 0;
}

static void ascii_to_wide(const char *s, wchar_t *d, size_t cap)
{
  size_t i;
  for (i = 0; s[i] && i + 1 < cap; i++)
    d[i] = (wchar_t)(unsigned char)s[i];
  d[i] = 0;
}

SD_TEST(smoke_hostkey_add_offers)
{
  static run_result r;
  char fp[96], id[32];
  wchar_t fpw[128], idw[64], args[768];
  SD_REQUIRE(setup());

  /* first contact: the question, the answer decides; the key is stored only after yes */
  EXPECT(RUN(L"hostkey add --from-server tofu.test --stdin", "y\n") == 0 && strstr(r.err, "[y]es") != NULL,
         "first contact asks, yes adds");
  EXPECT(RUN(L"hostkey list tofu.test --json", NULL) == 0 && strstr(r.out, "ssh-ed25519") != NULL &&
         strstr(r.out, "\"store\":\"user\"") != NULL, "first contact key stored after yes");
  EXPECT(RUN(L"hostkey add --from-server refused.test --stdin", "n\n") == 5 && strstr(r.err, "[y]es") != NULL,
         "first contact refused with no");
  EXPECT(RUN(L"hostkey list refused.test", NULL) == 0 && strstr(r.out, "No host key is stored") != NULL,
         "refused key not stored");
  /* the refused offer is rejected in the agent (hostkey.announced.reject): it is no longer listed for review */
  EXPECT(RUN(L"hostkey list --announced --json", NULL) == 0 && strstr(r.out, "refused.test") == NULL,
         "a refused offer leaves the announcement list");

  /* the server offers no key of the requested type: nothing to add */
  EXPECT(RUN(L"hostkey add --from-server tofu.test --type ssh-rsa --json", NULL) == 0 &&
         strstr(r.out, "\"keys\":[]") != NULL && strstr(r.out, "\"id\"") == NULL, "no key of that type to add");

  /* a verified host: the other keys are offered (JSON only offers; the id is for accept-announced) */
  EXPECT(RUN(L"hostkey add --from-server pinned.known.test --json", NULL) == 0 && strstr(r.out, "\"verified\":true") != NULL &&
         strstr(r.out, "ecdsa-sha2-nistp256") != NULL && strstr(r.out, "ssh-rsa") != NULL,
         "verified host offers its other keys");
  EXPECT(json_value_after(r.out, "\"id\":\"", id, sizeof(id)), "the offer has an id");
  ascii_to_wide(id, idw, SD_COUNTOF(idw));
  wcscpy_s(args, 768, L"hostkey accept-announced ");
  wcscat_s(args, 768, idw);
  wcscat_s(args, 768, L" --add-only --json");
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"added\":2") != NULL, "offer accepted with add-only");
  EXPECT(RUN(L"hostkey list pinned.known.test --json", NULL) == 0 && strstr(r.out, "ecdsa-sha2-nistp256") != NULL &&
         strstr(r.out, "ssh-rsa") != NULL, "accepted keys stored");

  /* a stored key that does not match the server: the connection fails, nothing is offered */
  EXPECT(RUN(L"hostkey add --from-server x.changed.test --json", NULL) == 6 &&
         strstr(r.out, "host_key_mismatch") != NULL, "a stored key that does not match fails");

  /* --expect: the key with that fingerprint is stored with no question (scripts) */
  EXPECT(RUN(L"hostkey add --from-server expect.test --json", NULL) == 0 &&
         json_value_after(r.out, "\"fingerprint\":\"", fp, sizeof(fp)), "first contact reports its fingerprint");
  ascii_to_wide(fp, fpw, SD_COUNTOF(fpw));
  wcscpy_s(args, 768, L"hostkey add --from-server expect.test --expect ");
  wcscat_s(args, 768, fpw);
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "Updated the host keys") != NULL, "--expect match stores without a question");
  EXPECT(RUN(L"hostkey list expect.test --json", NULL) == 0 && strstr(r.out, "ssh-ed25519") != NULL,
         "--expect key listed");

  /* --expect that matches nothing: refused, nothing stored (first contact exit 5, verified host exit 6) */
  EXPECT(RUN(L"hostkey add --from-server expect2.test --expect SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --json",
             NULL) == 5 && strstr(r.out, "host_key_rejected") != NULL, "first contact with a wrong --expect is refused");
  EXPECT(RUN(L"hostkey list expect2.test", NULL) == 0 && strstr(r.out, "No host key is stored") != NULL,
         "nothing stored after a wrong --expect");
  EXPECT(RUN(L"hostkey add --from-server pinned.known.test --expect SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --json",
             NULL) == 6 && strstr(r.out, "host_key_mismatch") != NULL, "verified host with a wrong --expect is a mismatch");

  EXPECT(RUN(L"agent stop", NULL) == 0, "agent stop");
}

/* ---- diag (M6, 03 §6.1, §10.5) through the real CLI ----
   The checks and fixes read and write the fake of the system seam (SHELLDRIVE_TEST_DIAG_FAKE, test builds only),
   a text file of the test. The real WebClient service, registry and drives are never touched by these tests. */
static int smoke_write_text(const wchar_t *path, const char *content)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD put = 0;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  WriteFile(h, content, (DWORD)strlen(content), &put, NULL);
  CloseHandle(h);
  return 1;
}

static size_t smoke_read_bytes(const wchar_t *path, unsigned char *buf, size_t cap)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD got = 0;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL))
    got = 0;
  CloseHandle(h);
  buf[got] = 0;
  return got;
}

static int smoke_has(const unsigned char *hay, size_t hn, const char *needle)
{
  size_t i, nn = strlen(needle);
  if (hn < nn)
    return 0;
  for (i = 0; i + nn <= hn; i++)
    if (memcmp(hay + i, needle, nn) == 0)
      return 1;
  return 0;
}

static void smoke_fake_path(wchar_t *p)
{
  wcscpy_s(p, MAX_PATH, g_root);
  wcscat_s(p, MAX_PATH, L"\\diag-fake.txt");
}

SD_TEST(smoke_diag_check_and_fix)
{
  static run_result r;
  static char text[4096];
  wchar_t fake[MAX_PATH];
  SD_REQUIRE(setup());
  smoke_fake_path(fake);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", fake);

  /* checks: WebClient stopped (start type 4 = disabled), tuned WebDAV limits, not elevated */
  SD_REQUIRE(smoke_write_text(fake, "webclient=stopped\r\nwebclient_start=4\r\nsize=4294967295\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=1\r\nsplit=0\r\nw32=1\r\ndomain=0\r\ndrives=3\r\n"
                                    "elevated=0\r\n"));
  EXPECT(RUN(L"--json diag --check", NULL) == 0 && strstr(r.out, "\"ok\":true") != NULL &&
         strstr(r.out, "\"state\":\"stopped\"") != NULL && strstr(r.out, "\"start_type\":4") != NULL &&
         strstr(r.out, "\"problems\":0") != NULL && strstr(r.out, "\"file_size_limit\":4294967295") != NULL,
         "json checks read the fake WebClient state");
  EXPECT(RUN(L"diag", NULL) == 0 && strstr(r.out, "WebClient") != NULL && strstr(r.out, "diagnostics") != NULL,
         "human checks report");
  EXPECT(RUN(L"--json diag", NULL) == 0 && strstr(r.out, "\"checks\"") != NULL, "plain diag is the checks");

  /* a running WebClient on a domain-joined computer is a warning, not a problem */
  SD_REQUIRE(smoke_write_text(fake, "webclient=running\r\nwebclient_start=3\r\nsize=50000000\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=0\r\nsplit=0\r\nw32=0\r\ndomain=1\r\ndrives=3\r\n"
                                    "elevated=0\r\n"));
  EXPECT(RUN(L"--json diag --check", NULL) == 0 && strstr(r.out, "\"webclient\":{\"status\":\"warn\"") != NULL &&
         strstr(r.out, "\"webdav\":{\"status\":\"warn\"") != NULL,
         "domain WebClient and untuned WebDAV warn");

  /* fixes need an administrator: refused with exit 9 and nothing changes */
  EXPECT(RUN(L"--json diag --fix webclient --yes", NULL) == 9 && strstr(r.out, "elevation_required") != NULL,
         "fix refused without elevation");
  EXPECT(RUN(L"diag --fix linked-connections --yes", NULL) == 9, "linked fix refused without elevation");

  /* elevated (the fake grants it): the WebClient fix sets manual start and starts the service */
  SD_REQUIRE(smoke_write_text(fake, "webclient=stopped\r\nwebclient_start=4\r\nsize=50000000\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=0\r\nsplit=0\r\nw32=0\r\ndomain=0\r\ndrives=3\r\n"
                                    "elevated=1\r\n"));
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", L"0");
  EXPECT(RUN(L"--json diag --fix webclient --yes", NULL) == 9, "SHELLDRIVE_TEST_ELEVATED=0 denies even a fake grant");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", NULL);
  EXPECT(RUN(L"--json diag --fix webclient --yes", NULL) == 0 && strstr(r.out, "\"changed\":true") != NULL,
         "webclient fix when elevated");
  SD_REQUIRE(smoke_read_bytes(fake, (unsigned char *)text, sizeof(text)) > 0);
  EXPECT(strstr(text, "webclient_start=3") != NULL && strstr(text, "webclient=running") != NULL,
         "the fake shows manual start and running");
  EXPECT(RUN(L"--json diag --fix webclient --yes", NULL) == 0 && strstr(r.out, "\"changed\":false") != NULL,
         "a second webclient fix changes nothing");

  /* linked connections: the question is asked; a no leaves the value alone (exit 13) */
  EXPECT(RUN(L"diag --fix linked-connections", "n\r\n") == 13, "a no is a cancellation");
  SD_REQUIRE(smoke_read_bytes(fake, (unsigned char *)text, sizeof(text)) > 0);
  EXPECT(strstr(text, "linked=none") != NULL, "a cancelled fix changes nothing");
  EXPECT(RUN(L"diag --fix linked-connections", "y\r\n") == 0, "a yes sets EnableLinkedConnections");
  SD_REQUIRE(smoke_read_bytes(fake, (unsigned char *)text, sizeof(text)) > 0);
  EXPECT(strstr(text, "linked=1") != NULL, "the fake shows the linked value");
  EXPECT(RUN(L"--json diag --fix linked-connections --yes", NULL) == 0 && strstr(r.out, "\"changed\":false") != NULL,
         "linked fix is idempotent");

  /* no WebClient at all: the fix cannot run (backend unavailable, exit 11) */
  SD_REQUIRE(smoke_write_text(fake, "webclient=missing\r\nelevated=1\r\nlinked=1\r\n"));
  EXPECT(RUN(L"--json diag --fix webclient --yes", NULL) == 11 && strstr(r.out, "backend_unavailable") != NULL,
         "missing WebClient");

  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", NULL);
  DeleteFileW(fake);
}

SD_TEST(smoke_diag_bundle)
{
  static run_result r;
  static unsigned char zip[1 << 20];
  wchar_t fake[MAX_PATH], profile[MAX_PATH], path[MAX_PATH], args[1024];
  size_t got;
  SD_REQUIRE(setup());
  smoke_fake_path(fake);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", fake);
  SD_REQUIRE(smoke_write_text(fake, "webclient=missing\r\nelevated=0\r\ndrives=3\r\n"));

  /* a profile with a host, a user, a remote path and a password: the password must never reach the bundle */
  wcscpy_s(profile, MAX_PATH, g_root);
  wcscat_s(profile, MAX_PATH, L"\\profiles\\bundle-test.ini");
  SD_REQUIRE(smoke_write_text(profile, "name = bundle-test\r\nhost = secret.example.test\r\nuser = carol\r\n"
                                       "remote_path = /home/carol/private\r\npassword = hunter2-pass\r\n"));

  /* anonymized by default */
  wcscpy_s(path, MAX_PATH, g_root);
  wcscat_s(path, MAX_PATH, L"\\bundle-anon.zip");
  DeleteFileW(path);
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"--json diag --bundle \"%s\"", path);
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"anonymized\":true") != NULL && strstr(r.out, "\"files\":") != NULL,
         "bundle written, anonymized");
  got = smoke_read_bytes(path, zip, sizeof(zip));
  EXPECT(got > 200 && zip[0] == 'P' && zip[1] == 'K' && zip[2] == 3 && zip[3] == 4, "the file is a ZIP");
  EXPECT(smoke_has(zip, got, "README.txt") && smoke_has(zip, got, "check.json") && smoke_has(zip, got, "versions.txt") &&
         smoke_has(zip, got, "agent.json") && smoke_has(zip, got, "crash/list.txt") &&
         smoke_has(zip, got, "config/profiles/bundle-test.ini"), "the expected entries");
  EXPECT(!smoke_has(zip, got, "hunter2-pass"), "no password in the bundle");
  EXPECT(!smoke_has(zip, got, "secret.example.test") && !smoke_has(zip, got, "carol") &&
         !smoke_has(zip, got, "/home/carol"), "host, user and remote path are anonymized");
  EXPECT(smoke_has(zip, got, "host = h:"), "the host field is a token");

  /* --no-anonymize keeps the names, and still no secret */
  wcscpy_s(path, MAX_PATH, g_root);
  wcscat_s(path, MAX_PATH, L"\\bundle-plain.zip");
  DeleteFileW(path);
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"--json diag --bundle \"%s\" --no-anonymize", path);
  EXPECT(RUN(args, NULL) == 0 && strstr(r.out, "\"anonymized\":false") != NULL, "bundle without anonymization");
  got = smoke_read_bytes(path, zip, sizeof(zip));
  EXPECT(smoke_has(zip, got, "secret.example.test") && smoke_has(zip, got, "carol") &&
         !smoke_has(zip, got, "hunter2-pass"), "names kept, password still removed");

  /* an existing file is never replaced */
  EXPECT(RUN(args, NULL) == 1, "an existing bundle file is refused");

  DeleteFileW(path);
  wcscpy_s(path, MAX_PATH, g_root);
  wcscat_s(path, MAX_PATH, L"\\bundle-anon.zip");
  DeleteFileW(path);
  DeleteFileW(profile);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", NULL);
  DeleteFileW(fake);
}

/* diag round 19 rows (03 §10.5, 8.6, 8.7, 02 §6.3, 04 §9.2, 04 §13): fake values only, nothing real is read. */
SD_TEST(smoke_diag_round19_rows)
{
  static run_result r;
  static unsigned char zip[1 << 20];
  wchar_t fake[MAX_PATH], machine[MAX_PATH], logs[MAX_PATH], logfile[MAX_PATH], path[MAX_PATH], args[1024];
  size_t got;
  SD_REQUIRE(setup());
  smoke_fake_path(fake);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_DIAG_FAKE", fake);

  /* Dokany 2.3.1 installed and not denied; the menu package registered; one NetHood entry that no profile wants */
  SD_REQUIRE(smoke_write_text(fake, "webclient=stopped\r\nwebclient_start=4\r\nsize=4294967295\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=1\r\ndokany_version=2.3.1\r\nsplit=0\r\nw32=1\r\n"
                                    "domain=0\r\ndrives=3\r\nelevated=0\r\nmenu=1\r\n"
                                    "netloc=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                                    "netloc_wanted=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"));
  EXPECT(RUN(L"--json diag --check", NULL) == 0 &&
         strstr(r.out, "\"dokany\":{\"status\":\"ok\",\"present\":true,\"version\":\"2.3.1\",\"deny\":null}") != NULL &&
         strstr(r.out, "\"windows11_menu\":{\"status\":\"ok\",\"registered\":true}") != NULL &&
         strstr(r.out, "\"network_locations\":{\"status\":\"warn\",\"known\":true,\"wanted\":1,\"missing\":1,\"stale\":1}") != NULL &&
         strstr(r.out, "\"logs\":{\"status\":\"ok\",\"setup_logs\":0,") != NULL,
         "round 19 rows in json: version, menu, network locations out of sync, logs");

  /* the installed version is on the deny list: a warning with the reason, not a problem */
  SD_REQUIRE(smoke_write_text(fake, "webclient=stopped\r\nwebclient_start=4\r\nsize=4294967295\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=1\r\ndokany_version=2.3.1\r\n"
                                    "dokany_deny=2.0.0-2.3.1 cve-test-reason\r\nsplit=0\r\nw32=1\r\ndomain=0\r\n"
                                    "drives=3\r\nelevated=0\r\nmenu=0\r\n"
                                    "netloc=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"
                                    "netloc_wanted=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"));
  EXPECT(RUN(L"--json diag --check", NULL) == 0 &&
         strstr(r.out, "\"dokany\":{\"status\":\"warn\",\"present\":true,\"version\":\"2.3.1\",\"deny\":\"cve-test-reason\"}") != NULL &&
         strstr(r.out, "\"windows11_menu\":{\"status\":\"ok\",\"registered\":false}") != NULL &&
         strstr(r.out, "\"network_locations\":{\"status\":\"ok\",\"known\":true,\"wanted\":1,\"missing\":0,\"stale\":0}") != NULL,
         "a deny-listed Dokany warns with the reason; network locations in sync");
  EXPECT(RUN(L"diag --check", NULL) == 0 && strstr(r.out, "cve-test-reason") != NULL &&
         strstr(r.out, "1 network location in sync.") != NULL && strstr(r.out, "Windows 11 menu") != NULL,
         "the human report carries the deny reason and the sync count");

  /* the NetHood folder is unknown: the row says so and nothing is compared */
  SD_REQUIRE(smoke_write_text(fake, "webclient=stopped\r\nwebclient_start=4\r\nsize=4294967295\r\nattr=100000000\r\n"
                                    "auth=2\r\nlinked=none\r\ndokany=0\r\nsplit=0\r\nw32=1\r\ndomain=0\r\n"
                                    "drives=3\r\nelevated=0\r\n"));
  EXPECT(RUN(L"--json diag --check", NULL) == 0 &&
         strstr(r.out, "\"dokany\":{\"status\":\"ok\",\"present\":false,\"version\":null,\"deny\":null}") != NULL &&
         strstr(r.out, "\"network_locations\":{\"status\":\"ok\",\"known\":false,\"wanted\":0,\"missing\":0,\"stale\":0}") != NULL,
         "absent Dokany and an unknown NetHood folder");

  /* the bundle carries the service-side logs of the machine data folder (read only, anonymized like logs/) */
  wcscpy_s(machine, MAX_PATH, g_root);
  wcscat_s(machine, MAX_PATH, L"\\machine");
  CreateDirectoryW(machine, NULL);
  wcscpy_s(logs, MAX_PATH, machine);
  wcscat_s(logs, MAX_PATH, L"\\logs");
  CreateDirectoryW(logs, NULL);
  wcscpy_s(logfile, MAX_PATH, logs);
  wcscat_s(logfile, MAX_PATH, L"\\dokany-install.log");
  SD_REQUIRE(smoke_write_text(logfile, "Dokany install, exit 0\r\n"));
  wcscpy_s(path, MAX_PATH, g_root);
  wcscat_s(path, MAX_PATH, L"\\bundle-r19.zip");
  DeleteFileW(path);
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"--json diag --bundle \"%s\"", path);
  EXPECT(RUN(args, NULL) == 0, "bundle with the machine logs written");
  got = smoke_read_bytes(path, zip, sizeof(zip));
  EXPECT(got > 200 && smoke_has(zip, got, "service-logs/dokany-install.log"), "the service-side log is in the bundle");
  DeleteFileW(logfile);
  DeleteFileW(path);
  DeleteFileW(logs);
  RemoveDirectoryW(logs);
  RemoveDirectoryW(machine);
  SD_CHECK(!agent_running());
}

/* ---- location add|remove|repair (03 §6.1, §8.7): no agent; the NetHood folder is a temporary one ---- */

/* 1 when the ini text holds `key = want` (the first key of that name, "=" with or without spaces). */
static int ini_value_is(const char *text, const char *key, const char *want)
{
  const char *p = strstr(text, key);
  size_t n = strlen(want);
  if (p == NULL)
    return 0;
  p += strlen(key);
  while (*p == ' ' || *p == '\t' || *p == '=')
    p++;
  return strncmp(p, want, n) == 0 && (p[n] == '\r' || p[n] == '\n' || p[n] == 0);
}

static int path_exists(const wchar_t *p)
{
  return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

/* A folder of the test NetHood; marker (wide text) is the [ShellDrive] profile= value, NULL = a foreign folder. */
static void make_folder(const wchar_t *folder, const wchar_t *marker)
{
  wchar_t ini[MAX_PATH];
  CreateDirectoryW(folder, NULL);
  _snwprintf_s(ini, SD_COUNTOF(ini), _TRUNCATE, L"%s\\desktop.ini", folder);
  if (marker)
    WritePrivateProfileStringW(L"ShellDrive", L"profile", marker, ini);
}

/* Deletes an entry folder by hand (a lost entry): its attributes are cleared first. */
static void drop_entry_folder(const wchar_t *folder)
{
  wchar_t f[MAX_PATH];
  _snwprintf_s(f, SD_COUNTOF(f), _TRUNCATE, L"%s\\desktop.ini", folder);
  SetFileAttributesW(f, FILE_ATTRIBUTE_NORMAL);
  DeleteFileW(f);
  _snwprintf_s(f, SD_COUNTOF(f), _TRUNCATE, L"%s\\target.lnk", folder);
  SetFileAttributesW(f, FILE_ATTRIBUTE_NORMAL);
  DeleteFileW(f);
  SetFileAttributesW(folder, FILE_ATTRIBUTE_NORMAL);
  RemoveDirectoryW(folder);
}

SD_TEST(smoke_location_verbs)
{
  static run_result r;
  static unsigned char text[4096];
  wchar_t nh[MAX_PATH], prof[MAX_PATH], other[MAX_PATH], folder[MAX_PATH], place[MAX_PATH], gone[MAX_PATH],
          foreign[MAX_PATH];
  SD_REQUIRE(setup());
  wcscpy_s(nh, MAX_PATH, g_root);
  wcscat_s(nh, MAX_PATH, L"\\nethood");
  CreateDirectoryW(nh, NULL);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", nh);
  /* the configuration root is shared by the smoke tests of this process: profiles other tests left would count
     in repair, so this test starts with an empty profiles folder */
  {
    wchar_t pat[MAX_PATH], one[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    _snwprintf_s(pat, SD_COUNTOF(pat), _TRUNCATE, L"%s\\profiles\\*.ini", g_root);
    h = FindFirstFileW(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
      do {
        _snwprintf_s(one, SD_COUNTOF(one), _TRUNCATE, L"%s\\profiles\\%s", g_root, fd.cFileName);
        DeleteFileW(one);
      } while (FindNextFileW(h, &fd));
      FindClose(h);
    }
  }
  _snwprintf_s(folder, SD_COUNTOF(folder), _TRUNCATE, L"%s\\office", nh);
  _snwprintf_s(gone, SD_COUNTOF(gone), _TRUNCATE, L"%s\\gone", nh);
  _snwprintf_s(foreign, SD_COUNTOF(foreign), _TRUNCATE, L"%s\\foreign", nh);
  _snwprintf_s(place, SD_COUNTOF(place), _TRUNCATE, L"%s\\places\\1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f", g_root);
  _snwprintf_s(prof, SD_COUNTOF(prof), _TRUNCATE, L"%s\\profiles\\office.ini", g_root);
  _snwprintf_s(other, SD_COUNTOF(other), _TRUNCATE, L"%s\\profiles\\machine.ini", g_root);
  SD_REQUIRE(smoke_write_text(prof, "[profile]\r\nformat = 1\r\nid = 1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f\r\n"
                                    "name = office\r\nhost = files.example.test\r\nuser = alice\r\n"
                                    "[mount]\r\nnetwork_location = no\r\n"));

  /* add: the entry and its placeholder appear, the profile asks for a Network location, JSON says what was done */
  EXPECT(RUN(L"--json location add office", NULL) == 0 &&
         strstr(r.out, "\"ok\":true") != NULL && strstr(r.out, "\"action\":\"add\"") != NULL &&
         strstr(r.out, "\"created\":true") != NULL,
         "location add in json: the result carries the action and created");
  EXPECT(path_exists(folder) && path_exists(place), "the entry folder and the placeholder folder exist");
  smoke_read_bytes(prof, text, sizeof(text) - 1);
  EXPECT(ini_value_is((const char *)text, "network_location", "yes"), "add writes mount.network_location = yes");

  /* a second add finds the entry in place and creates nothing */
  EXPECT(RUN(L"location add office", NULL) == 0 && strstr(r.out, "already in place") != NULL,
         "a second add says the entry is already in place");

  /* remove: the entry and the placeholder go, the profile stops asking for one */
  EXPECT(RUN(L"location remove office", NULL) == 0 && strstr(r.out, "Network location removed for office.") != NULL,
         "location remove prints its confirmation");
  EXPECT(!path_exists(folder) && !path_exists(place), "remove deletes the entry and the placeholder");
  smoke_read_bytes(prof, text, sizeof(text) - 1);
  EXPECT(ini_value_is((const char *)text, "network_location", "no"), "remove writes mount.network_location = no");

  /* a service profile has no Network location: refused with the usage exit code, nothing is written */
  SD_REQUIRE(smoke_write_text(other, "[profile]\r\nformat = 1\r\nid = 2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f70\r\n"
                                     "name = machine\r\nhost = svc.example.test\r\nuser = bob\r\n"
                                     "scope = service\r\nservice_access = Administrators\r\n"));
  EXPECT(RUN(L"location add machine", NULL) == 2 && strstr(r.err, "service profile") != NULL,
         "a service profile is refused with exit 2");
  EXPECT(RUN(L"location add nobody", NULL) == 3, "an unknown profile is refused with exit 3");

  /* repair: a marked folder of a profile that is gone is deleted, a foreign folder stays, and a lost entry of
     office comes back (two entries changed) */
  make_folder(gone, L"ffeeddccbbaa99887766554433221100");
  make_folder(foreign, NULL);
  EXPECT(RUN(L"location add office", NULL) == 0 && path_exists(folder), "office has its entry again");
  drop_entry_folder(folder);
  EXPECT(RUN(L"--json location repair", NULL) == 0 && strstr(r.out, "\"action\":\"repair\"") != NULL &&
         strstr(r.out, "\"changed\":2") != NULL,
         "repair reports the two changes in json");
  EXPECT(!path_exists(gone) && path_exists(foreign) && path_exists(folder),
         "repair deletes the marked stale folder, keeps the foreign one and restores the lost entry");

  /* nothing left to do: the human report says so */
  EXPECT(RUN(L"location repair", NULL) == 0 && strstr(r.out, "0 network locations repaired.") != NULL,
         "a repair with nothing to do reports 0");

  /* without a NetHood folder (test seam unset) nothing is written and the verb fails */
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", NULL);
  EXPECT(RUN(L"location repair", NULL) == 1 && strstr(r.err, "could not be written") != NULL,
         "without a NetHood folder the repair fails with exit 1");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", NULL);
  DeleteFileW(other);
}
