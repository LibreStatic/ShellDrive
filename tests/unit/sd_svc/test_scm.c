/* ShellDriveSvc registration rules (apps/shelldrive-host/svc_scm.c) against a fake Service Control Manager.
 *
 * The fake implements the svc_scm_ops seam and records the calls in order. None of these tests calls
 * svc_scm_real_ops, so they never create, start, stop or delete a service, never write the Event Log source and never
 * touch HKLM. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "svc_scm.h"

#define FAKE_MAX_CALLS 16
#define SVC_SCM_COUNT_T(a) (sizeof(a) / sizeof((a)[0]))
#define T_SID_UNRESTRICTED 1u              /* SERVICE_SID_TYPE_UNRESTRICTED (winsvc.h) */

typedef struct fake_scm {
  int elevated;
  int vista;
  const char *fail_op;                 /* the operation that fails, NULL = none */
  DWORD fail_code;
  const char *calls[FAKE_MAX_CALLS];
  int ncalls;
  DWORD sid_type;                      /* 0 = not set */
  DWORD restart_ms[SVC_SCM_RESTART_COUNT];
  DWORD reset_period_s;
  wchar_t command[MAX_PATH * 2];
  wchar_t description[256];
  wchar_t source[64];
  wchar_t message_file[MAX_PATH];
  DWORD types;
} fake_scm;

static DWORD record(fake_scm *f, const char *op)
{
  if (f->ncalls < FAKE_MAX_CALLS)
    f->calls[f->ncalls++] = op;
  if (f->fail_op != NULL && strcmp(f->fail_op, op) == 0)
    return f->fail_code;
  return 0;
}

static DWORD f_create(void *ctx, const svc_install_spec *s)
{
  fake_scm *f = (fake_scm *)ctx;
  StringCchCopyW(f->command, SVC_SCM_COUNT_T(f->command), s->command);
  StringCchCopyW(f->message_file, SVC_SCM_COUNT_T(f->message_file), s->message_file);
  return record(f, "create");
}

static DWORD f_description(void *ctx, const svc_install_spec *s)
{
  fake_scm *f = (fake_scm *)ctx;
  StringCchCopyW(f->description, SVC_SCM_COUNT_T(f->description), s->description);
  return record(f, "description");
}

static DWORD f_failure(void *ctx, const svc_install_spec *s)
{
  fake_scm *f = (fake_scm *)ctx;
  int i;
  for (i = 0; i < SVC_SCM_RESTART_COUNT; i++)
    f->restart_ms[i] = s->restart_ms[i];
  f->reset_period_s = s->reset_period_s;
  return record(f, "failure");
}

static DWORD f_sid(void *ctx, DWORD sid_type)
{
  fake_scm *f = (fake_scm *)ctx;
  f->sid_type = sid_type;
  return record(f, "sid");
}

static DWORD f_delete(void *ctx)
{
  return record((fake_scm *)ctx, "delete");
}

static DWORD f_start(void *ctx)
{
  return record((fake_scm *)ctx, "start");
}

static DWORD f_stop(void *ctx)
{
  return record((fake_scm *)ctx, "stop");
}

static DWORD f_register(void *ctx, const wchar_t *source, const wchar_t *message_file, DWORD types)
{
  fake_scm *f = (fake_scm *)ctx;
  StringCchCopyW(f->source, SVC_SCM_COUNT_T(f->source), source);
  StringCchCopyW(f->message_file, SVC_SCM_COUNT_T(f->message_file), message_file);
  f->types = types;
  return record(f, "register");
}

static DWORD f_unregister(void *ctx, const wchar_t *source)
{
  (void)source;
  return record((fake_scm *)ctx, "unregister");
}

static int f_elevated(void *ctx)
{
  return ((fake_scm *)ctx)->elevated;
}

static int f_vista(void *ctx)
{
  return ((fake_scm *)ctx)->vista;
}

static void fake_ops(svc_scm_ops *o, fake_scm *f)
{
  memset(o, 0, sizeof(*o));
  o->ctx = f;
  o->create_service = f_create;
  o->set_description = f_description;
  o->set_failure_actions = f_failure;
  o->set_sid_type = f_sid;
  o->delete_service = f_delete;
  o->start_service = f_start;
  o->stop_service = f_stop;
  o->register_source = f_register;
  o->unregister_source = f_unregister;
  o->is_elevated = f_elevated;
  o->is_vista_or_later = f_vista;
}

static void fake_init(fake_scm *f, int elevated, int vista)
{
  memset(f, 0, sizeof(*f));
  f->elevated = elevated;
  f->vista = vista;
}

/* True when the recorded calls equal the expected list exactly. */
static int calls_are(const fake_scm *f, const char *const *want, int n)
{
  int i;
  if (f->ncalls != n)
    return 0;
  for (i = 0; i < n; i++) {
    if (strcmp(f->calls[i], want[i]) != 0)
      return 0;
  }
  return 1;
}

static int has_call(const fake_scm *f, const char *op)
{
  int i;
  for (i = 0; i < f->ncalls; i++) {
    if (strcmp(f->calls[i], op) == 0)
      return 1;
  }
  return 0;
}

SD_TEST(scm_install_registers_the_service_in_order)
{
  static const char *const want[] = { "create", "description", "failure", "sid", "register" };
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 1, 1);
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  StringCchCopyW(s.command, SVC_SCM_COUNT_T(s.command), L"\"C:\\ShellDrive\\shelldrive-host.exe\" service");
  StringCchCopyW(s.message_file, SVC_SCM_COUNT_T(s.message_file), L"C:\\ShellDrive\\shelldrive-host.exe");
  StringCchCopyW(s.description, SVC_SCM_COUNT_T(s.description), L"Test description");
  s.restart_ms[0] = 5000u;
  s.restart_ms[1] = 30000u;
  s.restart_ms[2] = 300000u;
  s.reset_period_s = 86400u;
  s.sid_unrestricted = 1;
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, 0);
  SD_CHECK(calls_are(&f, want, 5));
  SD_CHECK(lstrcmpW(f.command, s.command) == 0);
  SD_CHECK(lstrcmpW(f.description, L"Test description") == 0);
  SD_CHECK(f.restart_ms[0] == 5000u && f.restart_ms[1] == 30000u && f.restart_ms[2] == 300000u);
  SD_CHECK(f.reset_period_s == 86400u);
  SD_CHECK(f.sid_type == T_SID_UNRESTRICTED);
  SD_CHECK(lstrcmpW(f.source, L"ShellDrive") == 0);
  SD_CHECK(lstrcmpW(f.message_file, L"C:\\ShellDrive\\shelldrive-host.exe") == 0);
  SD_CHECK(f.types == 7u);
}

SD_TEST(scm_install_skips_the_sid_type_before_vista)
{
  static const char *const want[] = { "create", "description", "failure", "register" };
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 1, 0);
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  s.sid_unrestricted = 1;
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, 0);
  SD_CHECK(calls_are(&f, want, 4));
  SD_CHECK(f.sid_type == 0);
}

SD_TEST(scm_install_refuses_without_elevation)
{
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 0, 1);
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, (int)ERROR_ACCESS_DENIED);
  SD_CHECK_EQ_INT(f.ncalls, 0);
  /* uninstall, start and stop are refused the same way */
  SD_CHECK_EQ_INT((int)svc_scm_uninstall(&ops), (int)ERROR_ACCESS_DENIED);
  SD_CHECK_EQ_INT(f.ncalls, 0);
}

SD_TEST(scm_install_rolls_back_a_failed_configuration)
{
  static const char *const want[] = { "create", "description", "failure", "delete" };
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 1, 1);
  f.fail_op = "failure";
  f.fail_code = 5u;
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, 5);
  SD_CHECK(calls_are(&f, want, 4));
  SD_CHECK(!has_call(&f, "register"));
}

SD_TEST(scm_install_rolls_back_a_failed_event_source)
{
  static const char *const want[] = { "create", "description", "failure", "sid", "register", "delete" };
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 1, 1);
  f.fail_op = "register";
  f.fail_code = 5u;
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  s.sid_unrestricted = 1;
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, 5);
  SD_CHECK(calls_are(&f, want, 6));
  /* the source was not ours to remove: no unregister after a failed register */
  SD_CHECK(!has_call(&f, "unregister"));
}

SD_TEST(scm_install_leaves_an_existing_service_alone)
{
  static const char *const want[] = { "create" };
  fake_scm f;
  svc_scm_ops ops;
  svc_install_spec s;
  DWORD e;
  fake_init(&f, 1, 1);
  f.fail_op = "create";
  f.fail_code = ERROR_SERVICE_EXISTS;
  fake_ops(&ops, &f);
  memset(&s, 0, sizeof(s));
  e = svc_scm_install(&ops, &s);
  SD_CHECK_EQ_INT((int)e, (int)ERROR_SERVICE_EXISTS);
  SD_CHECK(calls_are(&f, want, 1));
}

SD_TEST(scm_uninstall_stops_deletes_then_unregisters)
{
  static const char *const want[] = { "stop", "delete", "unregister" };
  fake_scm f;
  svc_scm_ops ops;
  fake_init(&f, 1, 1);
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT((int)svc_scm_uninstall(&ops), 0);
  SD_CHECK(calls_are(&f, want, 3));
}

SD_TEST(scm_uninstall_reports_a_missing_service)
{
  static const char *const want[] = { "stop", "delete" };
  fake_scm f;
  svc_scm_ops ops;
  fake_init(&f, 1, 1);
  f.fail_op = "delete";
  f.fail_code = ERROR_SERVICE_DOES_NOT_EXIST;
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT((int)svc_scm_uninstall(&ops), (int)ERROR_SERVICE_DOES_NOT_EXIST);
  SD_CHECK(calls_are(&f, want, 2));
}

SD_TEST(scm_uninstall_tolerates_a_missing_event_source)
{
  fake_scm f;
  svc_scm_ops ops;
  fake_init(&f, 1, 1);
  f.fail_op = "unregister";
  f.fail_code = ERROR_FILE_NOT_FOUND;
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT((int)svc_scm_uninstall(&ops), 0);
  SD_CHECK(has_call(&f, "unregister"));
}

SD_TEST(scm_start_and_stop_need_elevation)
{
  fake_scm f;
  svc_scm_ops ops;
  fake_init(&f, 0, 1);
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT((int)svc_scm_start(&ops), (int)ERROR_ACCESS_DENIED);
  SD_CHECK_EQ_INT((int)svc_scm_stop(&ops), (int)ERROR_ACCESS_DENIED);
  SD_CHECK_EQ_INT(f.ncalls, 0);
}

SD_TEST(scm_start_and_stop_pass_the_result_through)
{
  fake_scm f;
  svc_scm_ops ops;
  fake_init(&f, 1, 1);
  f.fail_op = "start";
  f.fail_code = ERROR_SERVICE_ALREADY_RUNNING;
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT((int)svc_scm_start(&ops), (int)ERROR_SERVICE_ALREADY_RUNNING);
  SD_CHECK(has_call(&f, "start"));
  f.fail_op = "stop";
  f.fail_code = ERROR_SERVICE_NOT_ACTIVE;
  SD_CHECK_EQ_INT((int)svc_scm_stop(&ops), (int)ERROR_SERVICE_NOT_ACTIVE);
  SD_CHECK(has_call(&f, "stop"));
}

SD_TEST(scm_host_spec_points_at_the_host_next_to_the_program)
{
  /* Only reads the program's own folder. Without shelldrive-host.exe beside the test program the spec is refused. */
  svc_install_spec s;
  DWORD e;
  memset(&s, 0, sizeof(s));
  e = svc_scm_host_spec(&s, L"text");
  if (e == 0) {
    size_t n = lstrlenW(s.message_file);
    SD_CHECK(n > 20 && lstrcmpW(s.message_file + n - 20, L"\\shelldrive-host.exe") == 0);
    SD_CHECK(s.command[0] == L'"');
    SD_CHECK(wcsncmp(s.command + 1, s.message_file, n) == 0 && s.command[n + 1] == L'"');
    SD_CHECK(lstrcmpW(s.description, L"text") == 0);
    SD_CHECK(s.restart_ms[0] == 5000u && s.restart_ms[2] == 300000u);
    SD_CHECK(s.reset_period_s == 86400u);
    SD_CHECK(s.sid_unrestricted == 1);
  } else {
    SD_CHECK_EQ_INT((int)e, (int)ERROR_FILE_NOT_FOUND);
  }
}
