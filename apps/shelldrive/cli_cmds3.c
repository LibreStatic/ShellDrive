/* shelldrive.exe M3 commands (03 §6.1): refresh <X:|PATH>[\sub\path], cache clear [<profile>|X:|--all] [--force],
 * profile test <profile> (connect, sign in and realpath, no mount) and status --stats (the connection and cache
 * counters of the agent, 02 §11). Exit codes follow 03 §6.2 (not_mounted 3, write_behind_pending 8). Every
 * user-facing string comes from the cli catalog; JSON keys and error codes stay English. */
#include <windows.h>
#include <string.h>

#include "cli_int.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

#define TEST_CALL_TIMEOUT 600000u     /* profile.test may wait for prompts (120 s each) */

/* Connects to a running agent without starting one; NULL when none runs. */
static sd_ipc_conn *connect_running(void)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK)
    return NULL;
  return c;
}

/* "X:" or "X:\..." (any case): the drive letter in upper case; rest points at the text after "X:". */
static int drive_prefix(const wchar_t *s, wchar_t *letter, const wchar_t **rest)
{
  if (s == NULL || !((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) || s[1] != L':')
    return 0;
  if (s[2] != 0 && s[2] != L'\\' && s[2] != L'/')
    return 0;
  *letter = (s[0] >= L'a' && s[0] <= L'z') ? (wchar_t)(s[0] - L'a' + L'A') : s[0];
  *rest = s + 2;
  return 1;
}

/* ---- refresh ---- */

int cli_run_refresh(const cli_args *a)
{
  sd_ipc_conn *c;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_wr w;
  sd_json_writer jw;
  err_ctx ec;
  wchar_t letter = 0;
  const wchar_t *rest = NULL;
  char target[3], *path = NULL;
  int rc;
  memset(&ec, 0, sizeof(ec));
  ec.name = a->positional;
  if (!drive_prefix(a->positional, &letter, &rest))
    return fail_code(a, "invalid_target", "refresh needs a drive letter", &ec);
  fill_target(ec.target, letter);
  if (sd_wide_to_utf8_alloc(rest, (size_t)-1, SD_UTF_STRICT, &path) != SD_OK)
    return fail_code(a, "usage", "invalid path", &ec);
  target[0] = (char)letter;
  target[1] = ':';
  target[2] = 0;
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "target"); sd_jw_cstr(&jw, target);
  sd_jw_key(&jw, "path"); sd_jw_cstr(&jw, path);
  sd_jw_obj_end(&jw);
  sd_free(path);
  if (sd_jw_finish(&jw) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "cannot encode request", &ec);
  }
  c = connect_running();
  if (c == NULL) {
    sd_wr_free(&w);
    return fail_code(a, "not_mounted", "no agent is running", &ec);
  }
  if (sd_ipc_call_raw(c, "refresh", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, &ec);
    sd_ipc_close(c);
    sd_wr_free(&w);
    return rc;
  }
  sd_ipc_close(c);
  sd_wr_free(&w);
  if (a->json)
    json_ok(res);
  else if (!a->quiet)
    say1w(SD_MSG_CLI_REFRESH_DONE, "path", a->positional, 0);
  sd_json_free(res);
  return 0;
}

/* ---- cache clear ---- */

int cli_run_cache(const cli_args *a)
{
  sd_ipc_conn *c;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_wr w;
  sd_json_writer jw;
  err_ctx ec;
  wchar_t letter = 0;
  const wchar_t *rest = NULL;
  char *name = NULL;
  int rc;
  int64_t cleared = 0;
  memset(&ec, 0, sizeof(ec));
  ec.name = a->arg2;
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  if (a->all) {
    sd_jw_key(&jw, "all"); sd_jw_bool(&jw, 1);
  } else if (drive_prefix(a->arg2, &letter, &rest) && rest[0] == 0) {
    char t[3];
    fill_target(ec.target, letter);
    t[0] = (char)letter;
    t[1] = ':';
    t[2] = 0;
    sd_jw_key(&jw, "target"); sd_jw_cstr(&jw, t);
  } else {
    /* a mount id (m-...) or a profile name or id; the agent matches both */
    const char *key = (a->arg2[0] == L'm' && a->arg2[1] == L'-') ? "mount_id" : "profile_id";
    if (sd_wide_to_utf8_alloc(a->arg2, (size_t)-1, SD_UTF_STRICT, &name) != SD_OK) {
      sd_wr_free(&w);
      return fail_code(a, "usage", "invalid name", &ec);
    }
    sd_jw_key(&jw, key); sd_jw_cstr(&jw, name);
    sd_free(name);
  }
  if (a->force) { sd_jw_key(&jw, "force"); sd_jw_bool(&jw, 1); }
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "cannot encode request", &ec);
  }
  c = connect_running();
  if (c == NULL) {
    sd_wr_free(&w);
    if (a->all) {
      /* no agent: nothing is mounted, so nothing is cached */
      if (a->json) {
        static const char k[] = "{\"ok\":true,\"result\":{\"mounts\":[],\"cleared\":0,\"disk_tier\":true}}";
        cli_print_utf8_line(k, sizeof(k) - 1);
      } else if (!a->quiet) {
        sd_arg arg;
        arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = 0;
        say(SD_MSG_CLI_CACHE_CLEARED, &arg, 1, 0);
      }
      return 0;
    }
    return fail_code(a, "mount_not_found", "no agent is running", &ec);
  }
  if (sd_ipc_call_raw(c, "cache.clear", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, &ec);
    sd_ipc_close(c);
    sd_wr_free(&w);
    return rc;
  }
  sd_ipc_close(c);
  sd_wr_free(&w);
  if (a->json) {
    json_ok(res);
  } else if (!a->quiet) {
    sd_arg arg;
    sd_json_get_int64(res, "cleared", &cleared);
    arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)cleared;
    say(SD_MSG_CLI_CACHE_CLEARED, &arg, 1, 0);
  }
  sd_json_free(res);
  return 0;
}

/* ---- profile test ---- */

typedef struct test_call {
  sd_ipc_conn *c;
  const char *params;
  size_t len;
  sd_json *res;
  sd_ipc_error err;
  sd_err e;
  HANDLE done;
} test_call;

/* profile.test waits for prompts, so the call runs on its own thread while this one answers prompt events. */
static DWORD WINAPI test_call_thread(void *p)
{
  test_call *t = (test_call *)p;
  t->e = sd_ipc_call_raw(t->c, "profile.test", t->params, t->len, TEST_CALL_TIMEOUT, &t->res, &t->err);
  SetEvent(t->done);
  return 0;
}

static void print_test_result(const sd_json *r, const wchar_t *name)
{
  const sd_json *alg = sd_json_get(r, "algorithms");
  wchar_t *wh = wide(sd_json_get_str(r, "host")), *wu = wide(sd_json_get_str(r, "user"));
  wchar_t *wpath = wide(sd_json_get_str(r, "remote_path")), *wkey = wide(sd_json_get_str(r, "hostkey_fingerprint"));
  wchar_t *wkex = wide(sd_json_get_str(alg, "kex")), *wht = wide(sd_json_get_str(alg, "hostkey"));
  wchar_t *wc = wide(sd_json_get_str(alg, "cipher_c2s")), *wm = wide(sd_json_get_str(alg, "mac_c2s"));
  sd_arg args[4];
  int legacy = 0;
  args[0].name = "name"; args[0].type = SD_ARG_STR; args[0].v.s = name;
  args[1].name = "host"; args[1].type = SD_ARG_STR; args[1].v.s = wh ? wh : L"";
  args[2].name = "user"; args[2].type = SD_ARG_STR; args[2].v.s = wu ? wu : L"";
  args[3].name = "path"; args[3].type = SD_ARG_STR; args[3].v.s = (wpath && wpath[0]) ? wpath : L"/";
  say(SD_MSG_CLI_TEST_OK, args, 4, 0);
  args[0].name = "fingerprint"; args[0].type = SD_ARG_STR; args[0].v.s = wkey ? wkey : L"";
  say(SD_MSG_CLI_TEST_HOSTKEY, args, 1, 0);
  args[0].name = "kex"; args[0].type = SD_ARG_STR; args[0].v.s = wkex ? wkex : L"";
  args[1].name = "hostkey"; args[1].type = SD_ARG_STR; args[1].v.s = wht ? wht : L"";
  args[2].name = "cipher"; args[2].type = SD_ARG_STR; args[2].v.s = wc ? wc : L"";
  args[3].name = "mac"; args[3].type = SD_ARG_STR; args[3].v.s = wm ? wm : L"";
  say(SD_MSG_CLI_TEST_ALGORITHMS, args, 4, 0);
  if (sd_json_get_bool(r, "legacy", &legacy) && legacy)
    say(SD_MSG_CLI_TEST_LEGACY, NULL, 0, 0);
  sd_free(wh);
  sd_free(wu);
  sd_free(wpath);
  sd_free(wkey);
  sd_free(wkex);
  sd_free(wht);
  sd_free(wc);
  sd_free(wm);
}

int cli_run_profile_test(const cli_args *a)
{
  sd_ipc_conn *c = NULL;
  sd_wr w;
  sd_json_writer jw;
  err_ctx ec;
  test_call t;
  HANDLE th;
  char *name = NULL;
  int rc;
  sd_err e;
  memset(&ec, 0, sizeof(ec));
  ec.name = a->arg2;
  memset(&t, 0, sizeof(t));
  if (sd_wide_to_utf8_alloc(a->arg2, (size_t)-1, SD_UTF_STRICT, &name) != SD_OK)
    return fail_code(a, "usage", "invalid profile name", &ec);
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "profile"); sd_jw_cstr(&jw, name);
  sd_jw_key(&jw, "prompt_mode"); sd_jw_cstr(&jw, can_prompt(a) ? "console" : "none");
  sd_jw_obj_end(&jw);
  sd_free(name);
  if (sd_jw_finish(&jw) != SD_OK) {
    sd_wr_free(&w);
    return fail_code(a, "internal", "cannot encode request", &ec);
  }
  rc = connect_agent(a, 1, &c, &ec);
  if (rc != 0) {
    sd_wr_free(&w);
    return rc;
  }
  if (!subscribe(c, "mount")) {
    sd_wr_free(&w);
    sd_ipc_close(c);
    return fail_code(a, "agent_unavailable", "subscribe failed", &ec);
  }
  memset(&t, 0, sizeof(t));
  t.c = c;
  t.params = (const char *)w.p;
  t.len = w.len;
  t.done = CreateEventW(NULL, TRUE, FALSE, NULL);
  th = t.done ? CreateThread(NULL, 0, test_call_thread, &t, 0, NULL) : NULL;
  if (th == NULL) {
    if (t.done) CloseHandle(t.done);
    sd_wr_free(&w);
    sd_ipc_close(c);
    return fail_code(a, "internal", "cannot start the test", &ec);
  }
  for (;;) {
    sd_json *ev = NULL;
    if (WaitForSingleObject(t.done, 0) == WAIT_OBJECT_0)
      break;
    e = sd_ipc_next_event(c, 200, &ev);
    if (e == SD_E_DISCONNECTED)
      break;
    if (e == SD_OK && is(sd_json_get_str(ev, "event"), "prompt.request"))
      handle_prompt(a, c, sd_json_get(ev, "data"));
    sd_json_free(ev);
  }
  WaitForSingleObject(t.done, INFINITE);
  CloseHandle(th);
  CloseHandle(t.done);
  sd_wr_free(&w);
  sd_ipc_close(c);
  if (t.e != SD_OK) {
    rc = fail_ipc(a, &t.err, &ec);
    sd_json_free(t.res);
    return rc;
  }
  if (a->json) {
    json_ok(t.res);
  } else if (!a->quiet) {
    print_test_result(t.res, a->arg2);
  }
  sd_json_free(t.res);
  return 0;
}

/* ---- status --stats ---- */

static void print_stats_text(const sd_json *st)
{
  const sd_json *ses = sd_json_get(st, "session"), *cache = sd_json_get(st, "cache");
  int present = 0, vfs = 0;
  wchar_t b[4][24];
  sd_arg args[4];
  int64_t v;
  if (!sd_json_get_bool(ses, "present", &present) || !present) {
    say(SD_MSG_CLI_STATS_NONE, NULL, 0, 0);
    return;
  }
  v = 0; sd_json_get_int64(ses, "srtt_ms", &v);
  args[0].name = "srtt"; args[0].type = SD_ARG_STR; args[0].v.s = decimal(b[0], SD_COUNTOF(b[0]), v);
  v = 0; sd_json_get_int64(ses, "inflight", &v);
  args[1].name = "inflight"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(b[1], SD_COUNTOF(b[1]), v);
  v = 0; sd_json_get_int64(ses, "queued", &v);
  args[2].name = "queued"; args[2].type = SD_ARG_STR; args[2].v.s = decimal(b[2], SD_COUNTOF(b[2]), v);
  v = 0; sd_json_get_int64(ses, "generation", &v);
  args[3].name = "generation"; args[3].type = SD_ARG_STR; args[3].v.s = decimal(b[3], SD_COUNTOF(b[3]), v);
  say(SD_MSG_CLI_STATS_SESSION, args, 4, 0);
  v = 0; sd_json_get_int64(ses, "rx_bytes", &v);
  args[0].name = "rx"; args[0].type = SD_ARG_STR; args[0].v.s = decimal(b[0], SD_COUNTOF(b[0]), v);
  v = 0; sd_json_get_int64(ses, "tx_bytes", &v);
  args[1].name = "tx"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(b[1], SD_COUNTOF(b[1]), v);
  say(SD_MSG_CLI_STATS_TRANSFER, args, 2, 0);
  if (sd_json_get_bool(cache, "vfs", &vfs) && vfs) {
    int64_t hits = 0, misses = 0, wfail = 0, wb = 0;
    sd_json_get_int64(cache, "hits", &hits);
    sd_json_get_int64(cache, "misses", &misses);
    sd_json_get_int64(cache, "write_failed", &wfail);
    sd_json_get_int64(cache, "write_behind_bytes", &wb);
    args[0].name = "hits"; args[0].type = SD_ARG_STR; args[0].v.s = decimal(b[0], SD_COUNTOF(b[0]), hits);
    args[1].name = "misses"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(b[1], SD_COUNTOF(b[1]), misses);
    args[2].name = "failed"; args[2].type = SD_ARG_STR; args[2].v.s = decimal(b[2], SD_COUNTOF(b[2]), wfail);
    args[3].name = "queued"; args[3].type = SD_ARG_STR; args[3].v.s = decimal(b[3], SD_COUNTOF(b[3]), wb);
    say(SD_MSG_CLI_STATS_CACHE, args, 4, 0);
  }
}

/* Whether a mount row of `list` matches the name typed after status --stats (drive, mount id or profile). */
static int row_matches(const sd_json *m, const wchar_t *name)
{
  wchar_t letter = 0;
  const wchar_t *rest = NULL;
  wchar_t *wid, *wp, *wt;
  int hit = 0;
  if (drive_prefix(name, &letter, &rest) && rest[0] == 0) {
    wt = wide(sd_json_get_str(m, "target"));
    hit = wt != NULL && wt[0] == letter && wt[1] == L':';
    sd_free(wt);
    return hit;
  }
  wid = wide(sd_json_get_str(m, "mount_id"));
  wp = wide(sd_json_get_str(m, "profile"));
  hit = (wid && _wcsicmp(wid, name) == 0) || (wp && _wcsicmp(wp, name) == 0);
  sd_free(wid);
  sd_free(wp);
  return hit;
}

/* status --stats: the counters of each matching mount (every mount without a name). */
int cli_run_status_stats(const cli_args *a)
{
  sd_ipc_conn *c;
  sd_json *list = NULL;
  sd_ipc_error err;
  const sd_json *arr;
  size_t i, n;
  int shown = 0, rc = 0;
  sd_wr w;
  sd_json_writer jw;
  err_ctx ec;
  memset(&ec, 0, sizeof(ec));
  memset(&w, 0, sizeof(w));
  memset(&jw, 0, sizeof(jw));
  ec.name = a->positional;
  c = connect_running();
  if (c == NULL) {
    if (a->positional)
      return fail_code(a, "mount_not_found", "no agent is running", &ec);
    if (a->json) {
      static const char k[] = "{\"ok\":true,\"result\":{\"mounts\":[]}}";
      cli_print_utf8_line(k, sizeof(k) - 1);
    } else {
      say(SD_MSG_CLI_LIST_EMPTY, NULL, 0, 0);
    }
    return 0;
  }
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &list, &err) != SD_OK) {
    rc = fail_ipc(a, &err, &ec);
    sd_ipc_close(c);
    return rc;
  }
  arr = sd_json_get(list, "mounts");
  n = sd_json_count(arr);
  if (a->json) {
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result"); sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "mounts"); sd_jw_arr_begin(&jw);
  }
  for (i = 0; i < n && rc == 0; i++) {
    const sd_json *m = sd_json_at(arr, i);
    const char *id = sd_json_get_str(m, "mount_id");
    sd_json *st = NULL;
    wchar_t *wname;
    if (id == NULL || (a->positional && !row_matches(m, a->positional)))
      continue;
    {
      /* the status call takes the mount id; the counters are read from its reply */
      sd_wr q;
      sd_json_writer qj;
      sd_wr_init(&q, 512);
      sd_jw_init(&qj, &q);
      sd_jw_obj_begin(&qj);
      sd_jw_key(&qj, "mount_id"); sd_jw_cstr(&qj, id);
      sd_jw_key(&qj, "stats"); sd_jw_bool(&qj, 1);
      sd_jw_obj_end(&qj);
      if (sd_jw_finish(&qj) == SD_OK && sd_ipc_call_raw(c, "status", (const char *)q.p, q.len, CALL_TIMEOUT, &st, &err) != SD_OK) {
        sd_wr_free(&q);
        rc = fail_ipc(a, &err, &ec);
        break;
      }
      sd_wr_free(&q);
    }
    shown++;
    if (a->json) {
      sd_jw_value(&jw, st);
    } else if (!a->quiet) {
      wchar_t *wt = wide(sd_json_get_str(m, "target")), *wp = wide(sd_json_get_str(m, "profile"));
      sd_arg args[2];
      wname = wp ? wp : wide(id);
      args[0].name = "target"; args[0].type = SD_ARG_STR; args[0].v.s = wt ? wt : L"?";
      args[1].name = "name"; args[1].type = SD_ARG_STR; args[1].v.s = wname ? wname : L"";
      say(SD_MSG_CLI_STATS_HEADER, args, 2, 0);
      print_stats_text(sd_json_get(st, "stats"));
      sd_free(wt);
      sd_free(wp);
      sd_free(wname);
    }
    sd_json_free(st);
  }
  if (rc == 0 && a->positional && shown == 0)
    rc = fail_code(a, "mount_not_found", "no matching mount", &ec);
  if (a->json && rc == 0) {
    sd_jw_arr_end(&jw);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
  }
  if (a->json)
    sd_wr_free(&w);
  sd_json_free(list);
  sd_ipc_close(c);
  return rc;
}
