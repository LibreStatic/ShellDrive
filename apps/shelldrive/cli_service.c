/* shelldrive service ...: global drives through the service pipe (03 §1.3, §2.2, §6.1, §6.2; M5).
 *
 *   service list                      global drives this user may see (others: letters only, 2.2)
 *   service mount <profile>           starts a global drive; waits for the result (Ctrl+C leaves it running)
 *   service unmount <profile|X:>      stops a global drive (administrators only)
 *   service status <profile|X:>       one drive
 *   service status                    the service: installed, state, start type, program path and Event Log source
 *                                     (no elevation); when running, its health, global drives and waiting admin prompts
 *
 *   service install | uninstall       registers or removes ShellDriveSvc and its Event Log source (elevated, 1.3, 10.3)
 *   service start | stop              starts or stops ShellDriveSvc (elevated)
 *   service repair-data               repairs the machine data folder and its stores (elevated, 3.2, TM-R34)
 *
 * Exit codes: status reports exit 0 (also when not installed); query failures exit 1. */
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "cli_int.h"
#include "svc_repair.h"
#include "svc_scm.h"
#include "sd/version.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n_cli_ids.h"

#define SVC_WAIT_MS 60000u
#define SVC_POLL_MS 500u

static void utf8_of(const wchar_t *w, char *out, size_t cch)
{
  out[0] = 0;
  if (w && w[0])
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cch, NULL, NULL);
  out[cch - 1] = 0;
}

/* Changing a global drive needs an elevated token (6.1). On XP the query is unavailable: the service decides. */
static int is_elevated(void)
{
  HANDLE tok = NULL;
  DWORD elevated = 0, len = 0;
  int r = 1;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 1;
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20 /* TokenElevation */, &elevated, sizeof(elevated), &len))
    r = elevated ? 1 : 0;
  CloseHandle(tok);
  return r;
}

static int connect_service(sd_ipc_conn **c)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = "cli";
  h.client_version = SD_VERSION_STRING;
  h.lang = sd_l10n_lang_code(sd_l10n_lang());
  h.caps = 0;
  return sd_ipc_connect(SD_IPC_SERVICE, &h, 0, CALL_TIMEOUT, c) == SD_OK;
}

/* Request body naming a drive ("X:" or "X:\") or a profile (built with the JSON writer: names may hold any text). */
static sd_err key_request(const cli_args *a, int force, sd_wr *w)
{
  char key[512];
  sd_json_writer jw;
  size_t n;
  utf8_of(a->arg2, key, sizeof(key));
  n = strlen(key);
  sd_wr_init(w, 1024);
  sd_jw_init(&jw, w);
  sd_jw_obj_begin(&jw);
  if (n == 2 && key[1] == ':') {
    sd_jw_key(&jw, "target");
  } else {
    sd_jw_key(&jw, "profile");
  }
  sd_jw_cstr(&jw, key);
  if (force) {
    sd_jw_key(&jw, "force");
    sd_jw_bool(&jw, 1);
  }
  sd_jw_obj_end(&jw);
  return sd_jw_finish(&jw);
}

static sd_msg_id state_id(const char *st)
{
  if (strcmp(st, "connecting") == 0) return SD_MSG_CLI_SERVICE_STATE_CONNECTING;
  if (strcmp(st, "mounted") == 0) return SD_MSG_CLI_SERVICE_STATE_MOUNTED;
  if (strcmp(st, "failed") == 0) return SD_MSG_CLI_SERVICE_STATE_FAILED;
  if (strcmp(st, "offline") == 0) return SD_MSG_CLI_SERVICE_STATE_OFFLINE;
  if (strcmp(st, "unmounting") == 0) return SD_MSG_CLI_SERVICE_STATE_UNMOUNTING;
  return 0;
}

/* One line of list and status: target, label and the localized state. */
static void print_drive(const sd_json *m)
{
  const char *tgt = sd_json_get_str(m, "target");
  const char *lbl = sd_json_get_str(m, "label");
  const char *st = sd_json_get_str(m, "state");
  wchar_t *wt = wide(tgt ? tgt : ""), *wl = wide(lbl ? lbl : ""), *ws = NULL;
  sd_msg_id sid = st ? state_id(st) : 0;
  const wchar_t *state_text = sid ? sd_l10n_get(sid) : L"";
  if (sid == 0 && st) {
    ws = wide(st);
    state_text = ws ? ws : L"";
  }
  {
    sd_arg args[3];
    args[0].name = "target"; args[0].type = SD_ARG_STR; args[0].v.s = wt ? wt : L"";
    args[1].name = "label"; args[1].type = SD_ARG_STR; args[1].v.s = wl ? wl : L"";
    args[2].name = "state"; args[2].type = SD_ARG_STR; args[2].v.s = state_text;
    say(SD_MSG_CLI_SERVICE_LIST_ITEM, args, 3, 0);
  }
  sd_free(wt);
  sd_free(wl);
  sd_free(ws);
}

static int run_list(const cli_args *a, sd_ipc_conn *c)
{
  sd_ipc_error err;
  sd_json *res = NULL;
  const sd_json *arr;
  size_t i, n;
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &res, &err) != SD_OK)
    return fail_ipc(a, &err, NULL);
  arr = sd_json_get(res, "mounts");
  n = sd_json_count(arr);
  if (a->json) {
    json_ok(res);
  } else if (n == 0) {
    say(SD_MSG_CLI_SERVICE_NONE, NULL, 0, 0);
  } else {
    for (i = 0; i < n; i++)
      print_drive(sd_json_at(arr, i));
  }
  sd_json_free(res);
  return 0;
}

static int run_status(const cli_args *a, sd_ipc_conn *c)
{
  sd_wr w;
  sd_ipc_error err;
  sd_json *res = NULL;
  int rc;
  if (key_request(a, 0, &w) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "request", NULL);
  }
  rc = sd_ipc_call_raw(c, "status", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err) == SD_OK ? 0 : -1;
  sd_wr_free(&w);
  if (rc != 0)
    return fail_ipc(a, &err, NULL);
  if (a->json)
    json_ok(res);
  else
    print_drive(res);
  sd_json_free(res);
  return 0;
}

static int run_unmount(const cli_args *a, sd_ipc_conn *c)
{
  sd_wr w;
  sd_ipc_error err;
  sd_json *res = NULL;
  int rc;
  if (key_request(a, a->force, &w) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "request", NULL);
  }
  rc = sd_ipc_call_raw(c, "unmount", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err) == SD_OK ? 0 : -1;
  sd_wr_free(&w);
  if (rc != 0)
    return fail_ipc(a, &err, NULL);
  if (a->json) {
    json_ok(res);
  } else {
    sd_arg arg;
    arg.name = "name";
    arg.type = SD_ARG_STR;
    arg.v.s = a->arg2;
    say(SD_MSG_CLI_SERVICE_UNMOUNTING, &arg, 1, 0);
  }
  sd_json_free(res);
  return 0;
}

static int run_mount(const cli_args *a, sd_ipc_conn *c)
{
  char profile[256], params[384];
  sd_wr w;
  sd_json_writer jw;
  sd_ipc_error err;
  sd_json *res = NULL, *st = NULL;
  const char *mid, *tgt;
  DWORD waited = 0;
  utf8_of(a->arg2, profile, sizeof(profile));
  sd_wr_init(&w, 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "profile");
  sd_jw_cstr(&jw, profile);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "request", NULL);
  }
  if (sd_ipc_call_raw(c, "mount", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err) != SD_OK) {
    sd_wr_free(&w);
    return fail_ipc(a, &err, NULL);
  }
  sd_wr_free(&w);
  mid = sd_json_get_str(res, "mount_id");
  tgt = sd_json_get_str(res, "target");
  if (a->json) {
    json_ok(res);
  } else {
    wchar_t *wt = wide(tgt ? tgt : "");
    say1w(SD_MSG_CLI_SERVICE_CONNECTING, "target", wt ? wt : L"", 0);
    sd_free(wt);
  }
  if (mid == NULL) {
    sd_json_free(res);
    return 0;
  }
  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"mount_id\":\"%s\"}", mid);
  for (;;) {
    const char *state;
    int rc = 0;
    if (sd_ipc_call_raw(c, "status", params, strlen(params), CALL_TIMEOUT, &st, &err) != SD_OK) {
      rc = fail_ipc(a, &err, NULL);
      sd_json_free(res);
      return rc;
    }
    state = sd_json_get_str(st, "state");
    if (state && strcmp(state, "mounted") == 0) {
      if (!a->json) {
        wchar_t *wt = wide(tgt ? tgt : "");
        say1w(SD_MSG_CLI_SERVICE_MOUNTED, "target", wt ? wt : L"", 0);
        sd_free(wt);
      }
      sd_json_free(st);
      sd_json_free(res);
      return 0;
    }
    if (state && (strcmp(state, "failed") == 0 || strcmp(state, "offline") == 0)) {
      const sd_json *le = sd_json_get(st, "last_error");
      const char *code = sd_json_get_str(le, "code");
      const char *detail = sd_json_get_str(le, "detail");
      rc = fail_code(a, code ? code : "io_error", detail, NULL);
      sd_json_free(st);
      sd_json_free(res);
      return rc;
    }
    sd_json_free(st);
    st = NULL;
    if (waited >= SVC_WAIT_MS)
      break;
    Sleep(SVC_POLL_MS);
    waited += SVC_POLL_MS;
  }
  sd_json_free(res);
  return 0;
}

static int is_verb(const wchar_t *v, const wchar_t *name)
{
  return v && wcscmp(v, name) == 0;
}

/* Maps a Win32 error of the Service Control Manager to a message and exit code (non-zero result). */
static int scm_error(DWORD e)
{
  sd_arg arg;
  switch (e) {
  case ERROR_ACCESS_DENIED:
    say(SD_MSG_CLI_SERVICE_NEED_ADMIN, NULL, 0, 1);
    return 9;
  case ERROR_SERVICE_EXISTS:
    say(SD_MSG_CLI_SERVICE_ALREADY_INSTALLED, NULL, 0, 1);
    return 1;
  case ERROR_SERVICE_DOES_NOT_EXIST:
    say(SD_MSG_CLI_SERVICE_NOT_INSTALLED, NULL, 0, 1);
    return 1;
  case ERROR_SERVICE_ALREADY_RUNNING:
    say(SD_MSG_CLI_SERVICE_ALREADY_RUNNING, NULL, 0, 1);
    return 1;
  case ERROR_SERVICE_NOT_ACTIVE:
    say(SD_MSG_CLI_SERVICE_NOT_RUNNING, NULL, 0, 1);
    return 1;
  default:
    arg.name = "code"; arg.type = SD_ARG_INT; arg.v.i = (long long)e;
    say(SD_MSG_CLI_SERVICE_SCM_FAILED, &arg, 1, 1);
    return 1;
  }
}

/* install, uninstall, start and stop (M5, 03 §1.3, §6.1). The rules and the SCM calls are in svc_scm.c; this only
   prints. The description is the localized text of this process (the cli domain). */
static int scm_verb(const wchar_t *verb)
{
  svc_scm_ops ops;
  svc_install_spec spec;
  sd_msg_id done;
  DWORD e;
  svc_scm_real_ops(&ops);
  if (is_verb(verb, L"install")) {
    e = svc_scm_host_spec(&spec, sd_l10n_get(SD_MSG_CLI_SERVICE_DESCRIPTION));
    if (e == 0)
      e = svc_scm_install(&ops, &spec);
    done = SD_MSG_CLI_SERVICE_INSTALLED;
  } else if (is_verb(verb, L"uninstall")) {
    e = svc_scm_uninstall(&ops);
    done = SD_MSG_CLI_SERVICE_UNINSTALLED;
  } else if (is_verb(verb, L"start")) {
    e = svc_scm_start(&ops);
    done = SD_MSG_CLI_SERVICE_STARTED;
  } else {
    e = svc_scm_stop(&ops);
    done = SD_MSG_CLI_SERVICE_STOPPED;
  }
  if (e != 0)
    return scm_error(e);
  say(done, NULL, 0, 0);
  return 0;
}

/* ---- service status (03 §6.1; M5 part 3) ---- */

/* What the running service reports over its pipe. reachable = 0 when the pipe does not answer. */
typedef struct svc_pipe_report {
  int reachable;
  int healthy;                 /* selftest: the machine data folder is trusted (3.2) */
  int64_t drives;              /* global drives: visible ones plus the letters of the others (2.2) */
  int64_t prompts;             /* open administrator prompts, from the content-free attention count (2.6) */
} svc_pipe_report;

static sd_msg_id svc_state_msg(DWORD st)
{
  switch (st) {
  case SERVICE_RUNNING: return SD_MSG_CLI_SERVICE_SVC_STATE_RUNNING;
  case SERVICE_STOPPED: return SD_MSG_CLI_SERVICE_SVC_STATE_STOPPED;
  case SERVICE_START_PENDING: return SD_MSG_CLI_SERVICE_SVC_STATE_STARTING;
  case SERVICE_STOP_PENDING: return SD_MSG_CLI_SERVICE_SVC_STATE_STOPPING;
  case SERVICE_PAUSED: return SD_MSG_CLI_SERVICE_SVC_STATE_PAUSED;
  default: return SD_MSG_CLI_SERVICE_SVC_STATE_UNKNOWN;
  }
}

static const char *svc_state_key(DWORD st)
{
  switch (st) {
  case SERVICE_RUNNING: return "running";
  case SERVICE_STOPPED: return "stopped";
  case SERVICE_START_PENDING: return "starting";
  case SERVICE_STOP_PENDING: return "stopping";
  case SERVICE_PAUSED: return "paused";
  default: return "unknown";
  }
}

static sd_msg_id start_type_msg(DWORD t)
{
  switch (t) {
  case SERVICE_AUTO_START: return SD_MSG_CLI_SERVICE_START_TYPE_AUTOMATIC;
  case SERVICE_DEMAND_START: return SD_MSG_CLI_SERVICE_START_TYPE_MANUAL;
  case SERVICE_DISABLED: return SD_MSG_CLI_SERVICE_START_TYPE_DISABLED;
  default: return SD_MSG_CLI_SERVICE_START_TYPE_UNKNOWN;
  }
}

static const char *start_type_key(DWORD t)
{
  switch (t) {
  case SERVICE_AUTO_START: return "automatic";
  case SERVICE_DEMAND_START: return "manual";
  case SERVICE_DISABLED: return "disabled";
  default: return "unknown";
  }
}

static const char *path_check_key(int c)
{
  switch (c) {
  case SVC_PATH_OK: return "ok";
  case SVC_PATH_UNQUOTED: return "unquoted";
  case SVC_PATH_OTHER: return "other";
  default: return "unknown";
  }
}

static const char *source_check_key(int c)
{
  switch (c) {
  case SVC_SRC_OK: return "registered";
  case SVC_SRC_MISSING: return "missing";
  case SVC_SRC_OTHER: return "other";
  default: return "unknown";
  }
}

static sd_msg_id path_check_msg(int c)
{
  switch (c) {
  case SVC_PATH_OK: return SD_MSG_CLI_SERVICE_STATUS_PROGRAM_OK;
  case SVC_PATH_UNQUOTED: return SD_MSG_CLI_SERVICE_STATUS_PROGRAM_UNQUOTED;
  case SVC_PATH_OTHER: return SD_MSG_CLI_SERVICE_STATUS_PROGRAM_OTHER;
  default: return SD_MSG_CLI_SERVICE_STATUS_PROGRAM_UNKNOWN;
  }
}

static sd_msg_id source_check_msg(int c)
{
  switch (c) {
  case SVC_SRC_OK: return SD_MSG_CLI_SERVICE_STATUS_SOURCE_OK;
  case SVC_SRC_MISSING: return SD_MSG_CLI_SERVICE_STATUS_SOURCE_MISSING;
  case SVC_SRC_OTHER: return SD_MSG_CLI_SERVICE_STATUS_SOURCE_OTHER;
  default: return SD_MSG_CLI_SERVICE_STATUS_SOURCE_UNKNOWN;
  }
}

/* Asks the running service: selftest (health), list (global drives) and the attention count (open admin prompts).
   Every call is open to any client, so no elevation is needed. */
static void query_pipe(svc_pipe_report *p)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL, *ev = NULL;
  int healthy = 0;
  memset(p, 0, sizeof(*p));
  if (!connect_service(&c))
    return;
  p->reachable = 1;
  if (sd_ipc_call_raw(c, "selftest", NULL, 0, CALL_TIMEOUT, &res, &err) == SD_OK) {
    if (sd_json_get_bool(res, "healthy", &healthy))
      p->healthy = healthy ? 1 : 0;
  }
  sd_json_free(res);
  res = NULL;
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &res, &err) == SD_OK) {
    p->drives = (int64_t)sd_json_count(sd_json_get(res, "mounts")) +
                (int64_t)sd_json_count(sd_json_get(res, "reserved_letters"));
  }
  sd_json_free(res);
  if (subscribe(c, "attention") && sd_ipc_next_event(c, 2000, &ev) == SD_OK && ev != NULL) {
    int64_t n = 0;
    if (sd_json_get_int64(sd_json_get(ev, "data"), "count", &n))
      p->prompts = n;
  }
  sd_json_free(ev);
  sd_ipc_close(c);
}

static void print_report(const svc_status_report *r, const svc_pipe_report *p)
{
  if (!r->installed) {
    say(SD_MSG_CLI_SERVICE_STATUS_NOT_INSTALLED, NULL, 0, 0);
  } else {
    sd_arg arg;
    arg.name = "state"; arg.type = SD_ARG_STR; arg.v.s = sd_l10n_get(svc_state_msg(r->state));
    say(SD_MSG_CLI_SERVICE_STATUS_STATE_LINE, &arg, 1, 0);
    arg.name = "type"; arg.type = SD_ARG_STR; arg.v.s = sd_l10n_get(start_type_msg(r->start_type));
    say(SD_MSG_CLI_SERVICE_STATUS_START_LINE, &arg, 1, 0);
    arg.name = "path"; arg.type = SD_ARG_STR; arg.v.s = r->binary;
    say(SD_MSG_CLI_SERVICE_STATUS_PROGRAM_LINE, &arg, 1, 0);
    say(path_check_msg(r->binary_check), NULL, 0, 0);
  }
  say(source_check_msg(r->source_check), NULL, 0, 0);
  if (r->installed && r->state == SERVICE_RUNNING) {
    if (!p->reachable) {
      say(SD_MSG_CLI_SERVICE_STATUS_PIPE_DOWN, NULL, 0, 0);
    } else {
      sd_arg arg;
      say(p->healthy ? SD_MSG_CLI_SERVICE_STATUS_HEALTHY : SD_MSG_CLI_SERVICE_STATUS_IDLE, NULL, 0, 0);
      arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)p->drives;
      say(SD_MSG_CLI_MOUNTED_COUNT, &arg, 1, 0);
      arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)p->prompts;
      say(SD_MSG_CLI_SERVICE_STATUS_PROMPTS, &arg, 1, 0);
    }
  }
}

/* The same facts as print_report, as one JSON object with English keys (03 §6.3). */
static void print_report_json(const svc_status_report *r, const svc_pipe_report *p, int pipe_queried)
{
  sd_wr w;
  sd_json_writer jw;
  sd_json *j = NULL;
  char path[1600], message_file[1600];
  utf8_of(r->binary, path, sizeof(path));
  utf8_of(r->message_file, message_file, sizeof(message_file));
  sd_wr_init(&w, 512);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "installed");
  sd_jw_bool(&jw, r->installed);
  sd_jw_key(&jw, "state");
  sd_jw_cstr(&jw, r->installed ? svc_state_key(r->state) : "not_installed");
  sd_jw_key(&jw, "start_type");
  if (r->installed) sd_jw_cstr(&jw, start_type_key(r->start_type)); else sd_jw_null(&jw);
  sd_jw_key(&jw, "program");
  if (r->installed) {
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "path");
    sd_jw_cstr(&jw, path);
    sd_jw_key(&jw, "check");
    sd_jw_cstr(&jw, path_check_key(r->binary_check));
    sd_jw_obj_end(&jw);
  } else {
    sd_jw_null(&jw);
  }
  sd_jw_key(&jw, "event_source");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "state");
  sd_jw_cstr(&jw, source_check_key(r->source_check));
  sd_jw_key(&jw, "message_file");
  sd_jw_cstr(&jw, message_file);
  sd_jw_obj_end(&jw);
  sd_jw_key(&jw, "pipe");
  if (pipe_queried) {
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "reachable");
    sd_jw_bool(&jw, p->reachable);
    sd_jw_key(&jw, "healthy");
    sd_jw_bool(&jw, p->healthy);
    sd_jw_key(&jw, "global_drives");
    sd_jw_int(&jw, p->drives);
    sd_jw_key(&jw, "prompts");
    sd_jw_int(&jw, p->prompts);
    sd_jw_obj_end(&jw);
  } else {
    sd_jw_null(&jw);
  }
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK && sd_json_parse((const char *)w.p, w.len, 16, &j) == SD_OK)
    json_ok(j);
  sd_json_free(j);
  sd_wr_free(&w);
}

/* shelldrive service status (no argument): reads the SCM and, when running, the service pipe. Exit 0 whenever the
   facts could be read, also when the service is not installed; a failed SCM query is exit 1. */
static int run_service_report(const cli_args *a)
{
  svc_scm_ops ops;
  svc_install_spec spec;
  svc_status_report r;
  svc_pipe_report p;
  int have_spec, queried = 0;
  DWORD e;
  svc_scm_real_ops(&ops);
  have_spec = svc_scm_host_spec(&spec, L"") == 0;
  e = svc_scm_status(&ops, have_spec ? &spec : NULL, &r);
  if (e != 0) {
    if (a->json)
      return fail_code(a, "io_error", "the service manager query failed", NULL);
    return scm_error(e);
  }
  memset(&p, 0, sizeof(p));
  if (r.installed && r.state == SERVICE_RUNNING) {
    query_pipe(&p);
    queried = 1;
  }
  if (a->json)
    print_report_json(&r, &p, queried);
  else
    print_report(&r, &p);
  return 0;
}

/* shelldrive service repair-data (elevated; 3.2, TM-R34). The repair itself is in svc_repair.c. */
static int run_repair(const cli_args *a)
{
  svc_repair_ops ops;
  svc_repair_result r;
  wchar_t base[MAX_PATH];
  DWORD e;
  if (!is_elevated()) {
    say(SD_MSG_CLI_SERVICE_NEED_ADMIN, NULL, 0, 1);
    return 9;
  }
  if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base) != S_OK) {
    if (a->json)
      return fail_code(a, "io_error", "the common application data folder is not known", NULL);
    {
      sd_arg arg;
      arg.name = "code"; arg.type = SD_ARG_INT; arg.v.i = (long long)ERROR_PATH_NOT_FOUND;
      say(SD_MSG_CLI_SERVICE_REPAIR_FAILED, &arg, 1, 1);
    }
    return 1;
  }
  svc_repair_real_ops(&ops);
  e = svc_repair_data(&ops, base, &r);
  if (r.refused) {
    if (a->json)
      return fail_code(a, "io_error", "a link or a junction is in the machine data folder", NULL);
    say1w(SD_MSG_CLI_SERVICE_REPAIR_REFUSED, "path", r.path, 1);
    return 1;
  }
  if (e != 0) {
    if (a->json)
      return fail_code(a, "io_error", "the machine data folder could not be repaired", NULL);
    {
      sd_arg arg;
      arg.name = "code"; arg.type = SD_ARG_INT; arg.v.i = (long long)e;
      say(SD_MSG_CLI_SERVICE_REPAIR_FAILED, &arg, 1, 1);
    }
    return 1;
  }
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_json *j = NULL;
    char moved_to[1600];
    utf8_of(r.path, moved_to, sizeof(moved_to));
    sd_wr_init(&w, 256);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "moved");
    sd_jw_bool(&jw, r.moved);
    sd_jw_key(&jw, "moved_to");
    if (r.moved) sd_jw_cstr(&jw, moved_to); else sd_jw_null(&jw);
    sd_jw_key(&jw, "folders");
    sd_jw_int(&jw, (int64_t)r.folders);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK && sd_json_parse((const char *)w.p, w.len, 16, &j) == SD_OK)
      json_ok(j);
    sd_json_free(j);
    sd_wr_free(&w);
  } else if (r.moved) {
    say1w(SD_MSG_CLI_SERVICE_REPAIR_MOVED, "path", r.path, 0);
  } else {
    say(SD_MSG_CLI_SERVICE_REPAIR_OK, NULL, 0, 0);
  }
  return 0;
}

int cli_run_service(const cli_args *a)
{
  sd_ipc_conn *c = NULL;
  int rc;
  const wchar_t *verb = a->positional;
  if (verb == NULL)
    return 2;
  if (is_verb(verb, L"install") || is_verb(verb, L"uninstall") || is_verb(verb, L"start") ||
      is_verb(verb, L"stop"))
    return scm_verb(verb);
  if (is_verb(verb, L"status") && a->arg2 == NULL)
    return run_service_report(a);
  if (is_verb(verb, L"repair-data"))
    return run_repair(a);
  if ((is_verb(verb, L"mount") || is_verb(verb, L"unmount")) && !is_elevated()) {
    say(SD_MSG_CLI_SERVICE_NEED_ADMIN, NULL, 0, 1);
    return 9;
  }
  if (!connect_service(&c)) {
    say(SD_MSG_CLI_SERVICE_UNAVAILABLE, NULL, 0, 1);
    return 8;
  }
  if (is_verb(verb, L"list"))
    rc = run_list(a, c);
  else if (is_verb(verb, L"mount"))
    rc = run_mount(a, c);
  else if (is_verb(verb, L"unmount"))
    rc = run_unmount(a, c);
  else
    rc = run_status(a, c);
  sd_ipc_close(c);
  return rc;
}
