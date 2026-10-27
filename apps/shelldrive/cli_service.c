/* shelldrive service ...: global drives through the service pipe (03 §1.3, §2.2, §6.1, §6.2; M5).
 *
 *   service list                      global drives this user may see (others: letters only, 2.2)
 *   service mount <profile>           starts a global drive; waits for the result (Ctrl+C leaves it running)
 *   service unmount <profile|X:>      stops a global drive (administrators only)
 *   service status <profile|X:>       one drive
 *
 *   service install | uninstall       registers or removes ShellDriveSvc and its Event Log source (elevated, 1.3, 10.3)
 *   service start | stop              starts or stops ShellDriveSvc (elevated)
 *
 * repair-data is parsed and reported as not in this build yet. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "cli_int.h"
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
  if (is_verb(verb, L"repair-data")) {
    sd_arg arg;
    arg.name = "verb"; arg.type = SD_ARG_STR; arg.v.s = verb;
    say(SD_MSG_CLI_SERVICE_UNIMPLEMENTED, &arg, 1, 1);
    return 1;
  }
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
