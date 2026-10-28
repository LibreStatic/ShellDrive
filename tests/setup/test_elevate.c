/* Tests of the two-stage elevation (apps/shelldrive-setup/setup_elevate.c, 04 §6.4). Every process start, elevation check
   and msiexec call goes through the seam: the fake below records the command lines, never elevates, never runs msiexec
   and never starts a stage. Paths live in a temp folder; nothing touches the real %ProgramData%. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "setup_elevate.h"
#include "setup_int.h"
#include "setup_trust.h"
#include "test_common.h"

typedef struct fake {
  int elevated;
  int secure_calls;
  int trust;
  int run_count;
  int last_runas;
  int image_present_at_run;
  int reply;                    /* 1: a stage child writes "R <reply_code>" to the pipe named on its command line */
  DWORD reply_code;
  DWORD run_result;             /* what run returns */
  DWORD run_exit;               /* the exit code it stores */
  wchar_t last_exe[MAX_PATH];
  wchar_t last_dir[MAX_PATH];
  wchar_t last_cmd[2048];
} fake_t;

/* Writes one "R <n>" line to the pipe named in cmd, the way a finished stage does. */
static void reply_to_pipe(const wchar_t *cmd, DWORD code)
{
  const wchar_t *p = wcsstr(cmd, L"/pipe=");
  wchar_t name[64];
  HANDLE client = INVALID_HANDLE_VALUE;
  wchar_t line[32];

  if (p == NULL)
    return;
  p += 6;
  StringCchCopyW(name, SD_SETUP_COUNTOF(name), p);
  {
    wchar_t *sp = wcschr(name, L' ');
    if (sp != NULL)
      *sp = L'\0';
  }
  if (sd_setup_elev_pipe_open(name, &client) != 0)
    return;
  StringCchPrintfW(line, SD_SETUP_COUNTOF(line), L"R %lu", (unsigned long)code);
  sd_setup_elev_pipe_write(client, line);
  CloseHandle(client);
}

static int f_is_elevated(void *ctx)
{
  return ((fake_t *)ctx)->elevated;
}

static DWORD f_secure(void *ctx, const wchar_t *base)
{
  (void)base;
  ((fake_t *)ctx)->secure_calls++;
  return 0;
}

/* The stage folder of the tests keeps the owner's full control (the tests run as the owner, not as Administrators). */
static DWORD f_create_stage(void *ctx, const wchar_t *setup_dir, const wchar_t *extra_ace, wchar_t *out, size_t cch)
{
  (void)ctx;
  (void)extra_ace;
  return sd_setup_create_stage_dir(setup_dir, L"(A;OICI;FA;;;OW)", out, cch);
}

static DWORD f_copy(void *ctx, const wchar_t *src, const wchar_t *dst)
{
  (void)ctx;
  return CopyFileW(src, dst, TRUE) ? 0 : GetLastError();
}

static DWORD f_run(void *ctx, const wchar_t *exe, const wchar_t *cmdline, const wchar_t *dir, int runas, DWORD *exit_code)
{
  fake_t *f = (fake_t *)ctx;
  f->run_count++;
  f->last_runas = runas;
  StringCchCopyW(f->last_exe, SD_SETUP_COUNTOF(f->last_exe), exe);
  StringCchCopyW(f->last_cmd, SD_SETUP_COUNTOF(f->last_cmd), cmdline);
  StringCchCopyW(f->last_dir, SD_SETUP_COUNTOF(f->last_dir), dir != NULL ? dir : L"");
  f->image_present_at_run = GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES;
  if (f->reply && wcsstr(cmdline, L"/elevated-") != NULL)
    reply_to_pipe(cmdline, f->reply_code);
  if (exit_code != NULL)
    *exit_code = f->run_exit;
  return f->run_result;
}

static int f_trusted(void *ctx, const wchar_t *dir)
{
  (void)dir;
  return ((fake_t *)ctx)->trust;
}

static void fake_make(sd_setup_elev_ops *ops, fake_t *f)
{
  memset(f, 0, sizeof(*f));
  f->trust = 1;
  memset(ops, 0, sizeof(*ops));
  ops->ctx = f;
  ops->is_elevated = f_is_elevated;
  ops->secure_programdata = f_secure;
  ops->create_stage = f_create_stage;
  ops->copy_image = f_copy;
  ops->run = f_run;
  ops->folder_trusted = f_trusted;
}

/* A temp base folder, the fixture CAB as payload (payload-ok.cab: no MSI) and its SHA-256. */
static int load_fixture(const wchar_t *leaf, unsigned char **data, size_t *size, unsigned char sha[32])
{
  wchar_t path[MAX_PATH];
  test_fixture_path(leaf, path, MAX_PATH);
  if (test_read_file(path, data, size) != 0)
    return 1;
  sd_setup_sha256(*data, *size, sha);
  return 0;
}

/* Writes a file with the given text at path. */
static int write_file(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD put = 0;
  if (h == INVALID_HANDLE_VALUE)
    return 1;
  WriteFile(h, text, (DWORD)strlen(text), &put, NULL);
  CloseHandle(h);
  return put == strlen(text) ? 0 : 1;
}

/* A stage folder under base, as stage 1 would create it: <base>\LibreStatic\ShellDrive\setup\<hex>, with the image. */
static int make_stage(const wchar_t *base, wchar_t *image, size_t cch)
{
  wchar_t root[MAX_PATH];
  wchar_t stage[MAX_PATH];
  if (sd_setup_elev_root(base, root, SD_SETUP_COUNTOF(root)) != 0)
    return 1;
  if (sd_setup_create_stage_dir(root, L"(A;OICI;FA;;;OW)", stage, SD_SETUP_COUNTOF(stage)) != 0)
    return 1;
  if (sd_setup_path_join(image, cch, stage, L"shelldrive-setup.exe") != 0)
    return 1;
  return write_file(image, "image") == 0 ? 0 : 1;
}

/* Reads every line the pipe collected after a stage. 0 when the read worked. */
static DWORD collect(HANDLE server, wchar_t *text, size_t cch)
{
  return sd_setup_elev_pipe_collect(server, text, cch);
}

/* A new pipe name and its server end. 0 on success. */
static DWORD make_pipe(wchar_t *name, HANDLE *server)
{
  if (sd_setup_elev_pipe_new_name(name, 64) != 0)
    return 1;
  return sd_setup_elev_pipe_create(name, server);
}

/* ------------------------------------------------------------------ names and the channel */

SD_TEST(setup_elev_pipe_names)
{
  wchar_t name[64];

  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789abcdef0123456789abcdef") == 1);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789abcdef0123456789abcde") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789abcdef0123456789abcdef0") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"Other-setup-0123456789abcdef0123456789abcdef") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789ABCDEF0123456789ABCDEF") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789abcdef0123456789abcd\"f") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(L"ShellDrive-setup-0123456789abcdef0123456789abcd f") == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(NULL) == 0);

  SD_REQUIRE(sd_setup_elev_pipe_new_name(name, SD_SETUP_COUNTOF(name)) == 0);
  SD_CHECK(sd_setup_elev_pipe_name_ok(name) == 1);
}

SD_TEST(setup_elev_pipe_roundtrip)
{
  wchar_t name[64];
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE client = INVALID_HANDLE_VALUE;
  wchar_t text[256];
  DWORD code = 0;

  SD_REQUIRE(make_pipe(name, &server) == 0);
  /* The client writes and closes before the parent collects: the stage has finished when the parent reads. */
  SD_REQUIRE(sd_setup_elev_pipe_open(name, &client) == 0);
  SD_REQUIRE(sd_setup_elev_pipe_write(client, L"P 40") == 0);
  SD_REQUIRE(sd_setup_elev_pipe_write(client, L"M 42 7") == 0);
  SD_REQUIRE(sd_setup_elev_pipe_write(client, L"R 3010") == 0);
  CloseHandle(client);

  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"P 40\n") != NULL);
  SD_CHECK(wcsstr(text, L"M 42 7\n") != NULL);
  SD_CHECK(sd_setup_elev_result_line(text, &code) == 0);
  SD_CHECK(code == 3010);
  CloseHandle(server);

  /* A channel nobody wrote to: an empty read, and no result line. */
  SD_REQUIRE(make_pipe(name, &server) == 0);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(text[0] == L'\0');
  SD_CHECK(sd_setup_elev_result_line(text, &code) != 0);
  CloseHandle(server);
}

SD_TEST(setup_elev_result_line_parse)
{
  DWORD code = 99;
  SD_CHECK(sd_setup_elev_result_line(L"R 0\n", &code) == 0 && code == 0);
  SD_CHECK(sd_setup_elev_result_line(L"P 10\nR 5\nR 7\n", &code) == 0 && code == 7);
  SD_CHECK(sd_setup_elev_result_line(L"xR 5\n", &code) != 0);
  SD_CHECK(sd_setup_elev_result_line(L"R x\n", &code) != 0);
  SD_CHECK(sd_setup_elev_result_line(L"", &code) != 0);
}

/* ------------------------------------------------------------------ forwarded switches */

SD_TEST(setup_elev_forward_switches)
{
  static const wchar_t *const argv[] = { L"setup.exe", L"/permachine", L"/quiet", L"/norestart", L"/lang=de",
                                         L"/dokany=skip", L"/flavour=x86-ia32", L"/log=C:\\x.log",
                                         L"/installdir=C:\\dir", L"DEFAULTPROFILES=C:\\My dir" };
  sd_setup_args a;
  const wchar_t *bad = NULL;
  wchar_t fwd[1024];

  SD_REQUIRE(sd_setup_parse_args((int)SD_SETUP_COUNTOF(argv), argv, &a, &bad) == 0);
  SD_REQUIRE(sd_setup_elev_forward(&a, fwd, SD_SETUP_COUNTOF(fwd)) == 0);
  SD_CHECK(wcsstr(fwd, L"/quiet") != NULL);
  SD_CHECK(wcsstr(fwd, L"/norestart") != NULL);
  SD_CHECK(wcsstr(fwd, L"/lang=de") != NULL);
  SD_CHECK(wcsstr(fwd, L"/dokany=skip") != NULL);
  SD_CHECK(wcsstr(fwd, L"/flavour=x86-ia32") != NULL);
  SD_CHECK(wcsstr(fwd, L"\"DEFAULTPROFILES=C:\\My dir\"") != NULL);
  /* Never forwarded: the mode, the paths of the user's run, and anything internal. */
  SD_CHECK(wcsstr(fwd, L"/permachine") == NULL);
  SD_CHECK(wcsstr(fwd, L"/log") == NULL);
  SD_CHECK(wcsstr(fwd, L"/installdir") == NULL);
  SD_CHECK(wcsstr(fwd, L"/elevated") == NULL);
}

SD_TEST(setup_elev_args_stage_switches)
{
  static const wchar_t *const ok_argv[] = { L"s.exe", L"/elevated-child", L"/pipe=ShellDrive-setup-0123456789abcdef0123456789abcdef" };
  static const wchar_t *const bad_argv[] = { L"s.exe", L"/elevated-child", L"/elevated-stage1" };
  sd_setup_args a;
  const wchar_t *bad = NULL;

  SD_REQUIRE(sd_setup_parse_args((int)SD_SETUP_COUNTOF(ok_argv), ok_argv, &a, &bad) == 0);
  SD_CHECK(a.elevate_stage == 2);
  SD_CHECK(sd_setup_elev_pipe_name_ok(a.pipe_name) == 1);
  SD_CHECK(sd_setup_parse_args((int)SD_SETUP_COUNTOF(bad_argv), bad_argv, &a, &bad) != 0);
}

/* ------------------------------------------------------------------ stage 1 */

SD_TEST(setup_elev_stage1_needs_elevation)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t name[64];
  sd_setup_args a;
  DWORD child = 0;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  fake_make(&ops, &f);
  f.elevated = 0;
  SD_REQUIRE(sd_setup_elev_pipe_new_name(name, SD_SETUP_COUNTOF(name)) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  SD_CHECK(sd_setup_elev_stage1(&ops, base, L"C:\\x\\setup.exe", &a, &child) == ERROR_ACCESS_DENIED);
  SD_CHECK(f.run_count == 0);
  SD_CHECK(f.secure_calls == 0);
  test_remove_tree(base);
}

SD_TEST(setup_elev_stage1_copies_and_starts_stage2)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t self[MAX_PATH];
  wchar_t name[64];
  sd_setup_args a;
  DWORD child = 99;
  DWORD rc;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(self, MAX_PATH, base, L"download-setup.exe") == 0);
  SD_REQUIRE(write_file(self, "download image") == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  f.run_exit = 0;
  SD_REQUIRE(sd_setup_elev_pipe_new_name(name, SD_SETUP_COUNTOF(name)) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.quiet = 1;
  a.lang[0] = L'd';
  a.lang[1] = L'e';

  rc = sd_setup_elev_stage1(&ops, base, self, &a, &child);
  SD_CHECK(rc == 0);
  SD_CHECK(child == 0);
  SD_CHECK(f.secure_calls == 1);
  SD_CHECK(f.run_count == 1);
  /* The child is the copy in the stage folder, started without runas, with the pipe and the forwarded switches. */
  SD_CHECK(f.last_runas == 0);
  SD_CHECK(f.image_present_at_run == 1);
  SD_CHECK(wcsstr(f.last_exe, L"\\LibreStatic\\ShellDrive\\setup\\") != NULL);
  SD_CHECK(_wcsicmp(f.last_exe + wcslen(f.last_exe) - 20, L"shelldrive-setup.exe") == 0);
  SD_CHECK(wcsstr(f.last_cmd, L"/elevated-child") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/pipe=ShellDrive-setup-") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/quiet") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/lang=de") != NULL);
  /* A successful stage removes its folder. */
  SD_CHECK(GetFileAttributesW(f.last_dir) == INVALID_FILE_ATTRIBUTES);
  test_remove_tree(base);
}

/* ------------------------------------------------------------------ stage 2 */

static DWORD run_stage2(const sd_setup_elev_ops *ops, const wchar_t *base, const wchar_t *image,
                        const sd_setup_args *a, const unsigned char *data, size_t size, const unsigned char sha[32])
{
  sd_setup_payload p;
  p.data = data;
  p.size = size;
  return sd_setup_elev_stage2(ops, base, image, a, &p, sha);
}

SD_TEST(setup_elev_stage2_refuses_image_outside_stage)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t name[64];
  wchar_t text[512];
  HANDLE server = INVALID_HANDLE_VALUE;
  sd_setup_args a;
  unsigned char *data = NULL;
  size_t size = 0;
  unsigned char sha[32];
  DWORD rc;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(load_fixture(L"payload-ok.cab", &data, &size, sha) == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  SD_REQUIRE(make_pipe(name, &server) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.elevate_stage = 2;

  /* The image is in the user's folder, not in a stage folder: nothing starts, the failure is reported. */
  rc = run_stage2(&ops, base, L"C:\\Users\\someone\\Downloads\\shelldrive-setup.exe", &a, data, size, sha);
  SD_CHECK(rc == SD_SETUP_EXIT_FATAL);
  SD_CHECK(f.run_count == 0);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"R 1603") != NULL);
  CloseHandle(server);
  HeapFree(GetProcessHeap(), 0, data);
  test_remove_tree(base);
}

SD_TEST(setup_elev_stage2_refuses_untrusted_folder_and_bad_hash)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t image[MAX_PATH];
  wchar_t name[64];
  wchar_t text[512];
  HANDLE server = INVALID_HANDLE_VALUE;
  sd_setup_args a;
  unsigned char *data = NULL;
  size_t size = 0;
  unsigned char sha[32];
  unsigned char wrong[32];

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(load_fixture(L"payload-ok.cab", &data, &size, sha) == 0);
  SD_REQUIRE(make_stage(base, image, MAX_PATH) == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  SD_REQUIRE(make_pipe(name, &server) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.elevate_stage = 2;

  /* A folder whose owner is not trusted: refused, nothing extracted, nothing run. */
  f.trust = 0;
  SD_CHECK(run_stage2(&ops, base, image, &a, data, size, sha) == SD_SETUP_EXIT_FATAL);
  SD_CHECK(f.run_count == 0);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"R 1603") != NULL);
  CloseHandle(server);

  /* A payload that does not match its table hash: refused before extraction. */
  SD_REQUIRE(make_pipe(name, &server) == 0);
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  f.trust = 1;
  memcpy(wrong, sha, 32);
  wrong[0] ^= 0xff;
  SD_CHECK(run_stage2(&ops, base, image, &a, data, size, wrong) == SD_SETUP_EXIT_FATAL);
  SD_CHECK(f.run_count == 0);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"R 1603") != NULL);
  CloseHandle(server);

  HeapFree(GetProcessHeap(), 0, data);
  test_remove_tree(base);
}

SD_TEST(setup_elev_stage2_without_msi_runs_nothing)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t image[MAX_PATH];
  wchar_t name[64];
  wchar_t text[512];
  HANDLE server = INVALID_HANDLE_VALUE;
  sd_setup_args a;
  unsigned char *data = NULL;
  size_t size = 0;
  unsigned char sha[32];

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(load_fixture(L"payload-ok.cab", &data, &size, sha) == 0);
  SD_REQUIRE(make_stage(base, image, MAX_PATH) == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  SD_REQUIRE(make_pipe(name, &server) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.elevate_stage = 2;

  /* payload-ok.cab carries no ShellDrive.msi: stage 2 stops before msiexec. */
  SD_CHECK(run_stage2(&ops, base, image, &a, data, size, sha) == SD_SETUP_EXIT_FATAL);
  SD_CHECK(f.run_count == 0);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"P 40\n") != NULL);
  SD_CHECK(wcsstr(text, L"R 1603") != NULL);
  CloseHandle(server);

  HeapFree(GetProcessHeap(), 0, data);
  test_remove_tree(base);
}

SD_TEST(setup_elev_stage2_runs_msiexec_for_the_msi)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t image[MAX_PATH];
  wchar_t name[64];
  wchar_t text[512];
  HANDLE server = INVALID_HANDLE_VALUE;
  sd_setup_args a;
  unsigned char *data = NULL;
  size_t size = 0;
  unsigned char sha[32];
  DWORD rc;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(load_fixture(L"payload-msi.cab", &data, &size, sha) == 0);
  SD_REQUIRE(make_stage(base, image, MAX_PATH) == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  f.run_exit = 3010;
  SD_REQUIRE(make_pipe(name, &server) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.elevate_stage = 2;
  a.quiet = 1;
  a.norestart = 1;
  StringCchCopyW(a.props, SD_SETUP_COUNTOF(a.props), L"\"DEFAULTPROFILES=C:\\My dir\" ");

  rc = run_stage2(&ops, base, image, &a, data, size, sha);
  SD_CHECK(rc == 3010);
  SD_CHECK(f.run_count == 1);
  /* msiexec, not a copy of this program; /i the extracted MSI in the stage payload folder, quiet, logged, with the
     forwarded properties. The tests never run it: the seam only records the line. */
  SD_CHECK(_wcsicmp(f.last_exe + wcslen(f.last_exe) - 11, L"msiexec.exe") == 0);
  SD_CHECK(wcsstr(f.last_cmd, L" /i ") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"ShellDrive.msi") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"\\payload\\") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/qn") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/norestart") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/L*v") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"\"DEFAULTPROFILES=C:\\My dir\"") != NULL);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  SD_CHECK(wcsstr(text, L"P 100\n") != NULL);
  SD_CHECK(wcsstr(text, L"R 3010") != NULL);
  CloseHandle(server);

  /* The extracted payload folder is removed once msiexec has returned; the stage folder itself stays. */
  {
    wchar_t pdir[MAX_PATH];
    SD_CHECK(sd_setup_path_join(pdir, MAX_PATH, f.last_dir, L"payload") == 0);
    SD_CHECK(GetFileAttributesW(pdir) == INVALID_FILE_ATTRIBUTES);
    SD_CHECK(GetFileAttributesW(f.last_dir) != INVALID_FILE_ATTRIBUTES);
  }
  HeapFree(GetProcessHeap(), 0, data);
  test_remove_tree(base);
}

SD_TEST(setup_elev_stage2_reports_msiexec_failure)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  wchar_t image[MAX_PATH];
  wchar_t name[64];
  wchar_t text[512];
  HANDLE server = INVALID_HANDLE_VALUE;
  sd_setup_args a;
  unsigned char *data = NULL;
  size_t size = 0;
  unsigned char sha[32];
  DWORD rc;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(load_fixture(L"payload-msi.cab", &data, &size, sha) == 0);
  SD_REQUIRE(make_stage(base, image, MAX_PATH) == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  f.run_exit = 1603;
  SD_REQUIRE(make_pipe(name, &server) == 0);
  memset(&a, 0, sizeof(a));
  StringCchCopyW(a.pipe_name, SD_SETUP_COUNTOF(a.pipe_name), name);
  a.elevate_stage = 2;

  rc = run_stage2(&ops, base, image, &a, data, size, sha);
  SD_CHECK(rc == 1603);
  SD_CHECK(collect(server, text, SD_SETUP_COUNTOF(text)) == 0);
  /* The message line names the all-users failure with the msiexec code, then the result. */
  SD_CHECK(wcsstr(text, L" 1603\n") != NULL);
  SD_CHECK(wcsstr(text, L"R 1603") != NULL);
  CloseHandle(server);
  HeapFree(GetProcessHeap(), 0, data);
  test_remove_tree(base);
}

/* ------------------------------------------------------------------ parent */

SD_TEST(setup_elev_parent_cancelled_uac)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  sd_setup_args a;
  sd_setup_result r;
  wchar_t self[MAX_PATH];

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(self, MAX_PATH, base, L"download-setup.exe") == 0);
  SD_REQUIRE(write_file(self, "download image") == 0);
  fake_make(&ops, &f);
  f.elevated = 0;
  f.run_result = ERROR_CANCELLED;
  memset(&a, 0, sizeof(a));
  a.mode = SD_SETUP_MODE_MACHINE;

  SD_CHECK(sd_setup_elev_parent(&ops, base, self, &a, &r) == SD_SETUP_EXIT_CANCEL);
  SD_CHECK(r.exit_code == SD_SETUP_EXIT_CANCEL);
  SD_CHECK(r.msg == 0);
  SD_CHECK(f.run_count == 1);
  SD_CHECK(f.last_runas == 1);
  SD_CHECK(wcsstr(f.last_cmd, L"/elevated-stage1") != NULL);
  SD_CHECK(wcsstr(f.last_cmd, L"/pipe=ShellDrive-setup-") != NULL);
  test_remove_tree(base);
}

SD_TEST(setup_elev_parent_silent_channel_fails)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  sd_setup_args a;
  sd_setup_result r;
  wchar_t self[MAX_PATH];

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(self, MAX_PATH, base, L"download-setup.exe") == 0);
  SD_REQUIRE(write_file(self, "download image") == 0);
  fake_make(&ops, &f);
  f.elevated = 0;
  f.run_exit = 0;   /* the stage "succeeds" but reports nothing: never success */
  memset(&a, 0, sizeof(a));
  a.mode = SD_SETUP_MODE_MACHINE;

  SD_CHECK(sd_setup_elev_parent(&ops, base, self, &a, &r) == SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_ELEVATION);
  test_remove_tree(base);
}

SD_TEST(setup_elev_parent_in_process_when_elevated)
{
  sd_setup_elev_ops ops;
  fake_t f;
  wchar_t base[MAX_PATH];
  sd_setup_args a;
  sd_setup_result r;
  wchar_t self[MAX_PATH];

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(self, MAX_PATH, base, L"download-setup.exe") == 0);
  SD_REQUIRE(write_file(self, "download image") == 0);
  fake_make(&ops, &f);
  f.elevated = 1;
  f.reply = 1;
  f.reply_code = 0;
  f.run_exit = 0;
  memset(&a, 0, sizeof(a));
  a.mode = SD_SETUP_MODE_MACHINE;
  a.quiet = 1;

  /* Already elevated: no runas; stage 1 runs in this process and the child reports through the pipe. */
  SD_CHECK(sd_setup_elev_parent(&ops, base, self, &a, &r) == SD_SETUP_EXIT_OK);
  SD_CHECK(r.exit_code == SD_SETUP_EXIT_OK);
  SD_CHECK(r.msg == 0);
  SD_CHECK(f.run_count == 1);
  SD_CHECK(f.last_runas == 0);
  test_remove_tree(base);
}
