/* Host/CLI smoke test with the scripted fake backend (no network, no Dokany):
 * sd-test-cli.exe (the real CLI sources + SD_CLI_TEST_HOOKS) auto-starts sd-test-host-fake.exe
 * (the real agent sources + the fake backend + SD_HOST_TEST_HOOKS) and both run under an isolated
 * instance suffix and configuration root, so a real agent of the user is never touched. */
#include <windows.h>
#include <sddl.h>
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
  wcscpy_s(g_suffix, 64, L"smoke");
  wcat_u(g_suffix, 64, (unsigned)GetCurrentProcessId());
  if (GetTempPathW(MAX_PATH, g_root) == 0)
    return 0;
  wcscat_s(g_root, MAX_PATH, L"sd-smoke-");
  wcat_u(g_root, MAX_PATH, (unsigned)GetCurrentProcessId());
  if (stamp == 0) {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    stamp = qpc.LowPart | 1u;
  }
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
