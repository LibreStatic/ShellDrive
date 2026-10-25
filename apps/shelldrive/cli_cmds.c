/* shelldrive.exe commands over IPC (03 §6): mount, unmount, list, agent stop, help, version.
 *
 * Every user-facing string comes from the cli catalog (sd_l10n); JSON keys, codes and `detail` stay
 * English. Prompts (2.5): the CLI declares prompts.console when it can ask (an interactive console,
 * or --stdin), answers prompt.request events for its own mount with prompt.answer and wipes the
 * secret buffers afterwards. Host key TOFU defaults to "no" (TM-R03); a changed key is never a
 * prompt (the mount fails with host_key_mismatch, exit 6). */
#include <windows.h>
#include <string.h>

#include "cli.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

#define CALL_TIMEOUT 15000

/* ---- message helpers ---- */

static void say(sd_msg_id id, const sd_arg *args, size_t n, int to_stderr)
{
  wchar_t *s = sd_l10n_format_alloc(id, args, n);
  if (s == NULL)
    return;
  if (to_stderr) cli_eprint(s); else cli_print(s);
  sd_free(s);
}

static wchar_t *wide(const char *utf8)
{
  wchar_t *w = NULL;
  if (utf8 == NULL || sd_utf8_to_wide_alloc(utf8, (size_t)-1, SD_UTF_REPLACE, &w) != SD_OK)
    return NULL;
  return w;
}

/* Plain decimal for identifiers (ports, line numbers): SD_ARG_INT groups digits per user locale. */
static const wchar_t *decimal(wchar_t *buf, size_t cch, long long v)
{
  wchar_t tmp[24];
  size_t n = 0, i = 0;
  unsigned long long m = v < 0 ? (unsigned long long)0 - (unsigned long long)v : (unsigned long long)v;
  do { tmp[n++] = (wchar_t)(L'0' + (m % 10u)); m /= 10u; } while (m);
  if (v < 0 && i + 1 < cch) buf[i++] = L'-';
  while (n && i + 1 < cch) buf[i++] = tmp[--n];
  buf[i] = 0;
  return buf;
}

static void say1(sd_msg_id id, const char *name, const char *utf8, int to_stderr)
{
  wchar_t *w = wide(utf8 ? utf8 : "");
  sd_arg a[1];
  a[0].name = name; a[0].type = SD_ARG_STR; a[0].v.s = w ? w : L"";
  say(id, a, 1, to_stderr);
  sd_free(w);
}

static void say1w(sd_msg_id id, const char *name, const wchar_t *w, int to_stderr)
{
  sd_arg a[1];
  a[0].name = name; a[0].type = SD_ARG_STR; a[0].v.s = w ? w : L"";
  say(id, a, 1, to_stderr);
}

/* ---- JSON output (03 §6.3) ---- */

static void json_ok(const sd_json *result)
{
  sd_wr w;
  sd_json_writer jw;
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
  sd_jw_key(&jw, "result");
  if (result) sd_jw_value(&jw, result);
  else { sd_jw_obj_begin(&jw); sd_jw_obj_end(&jw); }
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    cli_print_utf8_line((const char *)w.p, w.len);
  sd_wr_free(&w);
}

static void json_err(const char *code, const char *detail, int exit_code)
{
  sd_wr w;
  sd_json_writer jw;
  sd_wr_init(&w, 64 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 0);
  sd_jw_key(&jw, "error");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "code"); sd_jw_cstr(&jw, code);
  sd_jw_key(&jw, "detail"); sd_jw_cstr(&jw, detail ? detail : "");
  sd_jw_key(&jw, "exit_code"); sd_jw_int(&jw, exit_code);
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    cli_print_utf8_line((const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* ---- localized errors ---- */

typedef struct err_ctx {
  const char *host;          /* UTF-8, for {host} */
  const wchar_t *name;       /* profile / target as typed, for {name} */
  wchar_t target[4];         /* "Z:" */
  const sd_json *detail;     /* error object from the agent (mismatch details) */
} err_ctx;

static int is(const char *a, const char *b) { return a && strcmp(a, b) == 0; }

static void print_error(const cli_args *a, const char *code, const char *detail, int exit_code, const err_ctx *ec)
{
  const char *host = ec && ec->host ? ec->host : "";
  if (a->json) {
    json_err(code, detail, exit_code);
    return;
  }
  if (is(code, "auth_failed")) say1(SD_MSG_CLI_ERROR_AUTH_FAILED, "host", host, 1);
  else if (is(code, "prompt_required")) say1(SD_MSG_CLI_ERROR_PROMPT_REQUIRED, "host", host, 1);
  else if (is(code, "host_key_unknown")) say1(SD_MSG_CLI_ERROR_HOST_KEY_UNKNOWN, "host", host, 1);
  else if (is(code, "host_key_rejected")) say1(SD_MSG_CLI_ERROR_HOST_KEY_REJECTED, "host", host, 1);
  else if (is(code, "host_key_mismatch")) {
    say1(SD_MSG_CLI_ERROR_HOST_KEY_MISMATCH, "host", host, 1);
    if (ec && ec->detail) {
      const sd_json *d = ec->detail;
      wchar_t *t = wide(sd_json_get_str(d, "stored_type")), *f = wide(sd_json_get_str(d, "stored_fp"));
      wchar_t *file = wide(sd_json_get_str(d, "store_path"));
      wchar_t *ot = wide(sd_json_get_str(d, "offered_type")), *of = wide(sd_json_get_str(d, "offered_fp"));
      int64_t line = 0;
      wchar_t lbuf[24];
      sd_arg args[4];
      sd_json_get_int64(d, "store_line", &line);
      if (f && f[0]) {
        args[0].name = "type"; args[0].type = SD_ARG_STR; args[0].v.s = t ? t : L"";
        args[1].name = "fingerprint"; args[1].type = SD_ARG_STR; args[1].v.s = f;
        args[2].name = "file"; args[2].type = SD_ARG_STR; args[2].v.s = file ? file : L"";
        args[3].name = "line"; args[3].type = SD_ARG_STR; args[3].v.s = decimal(lbuf, SD_COUNTOF(lbuf), line);
        say(SD_MSG_CLI_HK_MISMATCH_STORED, args, 4, 1);
      }
      if (of && of[0]) {
        args[0].name = "type"; args[0].type = SD_ARG_STR; args[0].v.s = ot ? ot : L"";
        args[1].name = "fingerprint"; args[1].type = SD_ARG_STR; args[1].v.s = of;
        say(SD_MSG_CLI_HK_MISMATCH_OFFERED, args, 2, 1);
      }
      say(SD_MSG_CLI_HK_MISMATCH_HINT, NULL, 0, 1);
      sd_free(t); sd_free(f); sd_free(file); sd_free(ot); sd_free(of);
    }
  }
  else if (is(code, "host_key_type_unavailable")) say1(SD_MSG_CLI_ERROR_HOST_KEY_TYPE_UNAVAILABLE, "host", host, 1);
  else if (is(code, "host_key_revoked")) say1(SD_MSG_CLI_ERROR_HOST_KEY_REVOKED, "host", host, 1);
  else if (is(code, "dns_failed")) say1(SD_MSG_CLI_ERROR_DNS_FAILED, "host", host, 1);
  else if (is(code, "conn_refused")) say1(SD_MSG_CLI_ERROR_CONN_REFUSED, "host", host, 1);
  else if (is(code, "net_unreachable")) say1(SD_MSG_CLI_ERROR_NET_UNREACHABLE, "host", host, 1);
  else if (is(code, "connect_failed") || is(code, "disconnected") || is(code, "protocol"))
    say1(SD_MSG_CLI_ERROR_CONNECT_FAILED, "host", host, 1);
  else if (is(code, "kex_failed")) say1(SD_MSG_CLI_ERROR_KEX_FAILED, "host", host, 1);
  else if (is(code, "legacy_refused")) say1(SD_MSG_CLI_ERROR_LEGACY_REFUSED, "host", host, 1);
  else if (is(code, "bad_passphrase")) say(SD_MSG_CLI_ERROR_BAD_PASSPHRASE, NULL, 0, 1);
  else if (is(code, "key_format") || is(code, "key_unsupported")) say(SD_MSG_CLI_ERROR_KEY_FORMAT, NULL, 0, 1);
  else if (is(code, "timeout")) say(SD_MSG_CLI_ERROR_TIMEOUT, NULL, 0, 1);
  else if (is(code, "cancelled")) say(SD_MSG_CLI_ERROR_CANCELLED, NULL, 0, 1);
  else if (is(code, "agent_unavailable")) say(SD_MSG_CLI_ERROR_AGENT_UNAVAILABLE, NULL, 0, 1);
  else if (is(code, "agent_untrusted")) say(SD_MSG_CLI_ERROR_AGENT_UNTRUSTED, NULL, 0, 1);
  else if (is(code, "access_denied")) say(SD_MSG_CLI_ERROR_ACCESS_DENIED, NULL, 0, 1);
  else if (is(code, "proto_unsupported")) say(SD_MSG_CLI_ERROR_PROTO_UNSUPPORTED, NULL, 0, 1);
  else if (is(code, "profile_not_found")) say1w(SD_MSG_CLI_ERROR_PROFILE_NOT_FOUND, "name", ec ? ec->name : NULL, 1);
  else if (is(code, "mount_not_found")) say1w(SD_MSG_CLI_ERROR_MOUNT_NOT_FOUND, "name", ec ? ec->name : NULL, 1);
  else if (is(code, "target_in_use")) {
    wchar_t t[3];
    size_t n = detail ? strlen(detail) : 0;
    t[0] = ec ? ec->target[0] : L'?';
    if ((t[0] == L'?' || t[0] == 0) && n >= 2 && detail[n - 1] == ':')
      t[0] = (wchar_t)(unsigned char)detail[n - 2];     /* "drive letter in use: X:" */
    t[1] = L':';
    t[2] = 0;
    say1w(SD_MSG_CLI_ERROR_TARGET_IN_USE, "target", t, 1);
  }
  else if (is(code, "invalid_target")) say1w(SD_MSG_CLI_ERROR_INVALID_TARGET, "value", ec ? ec->target : NULL, 1);
  else if (is(code, "already_mounted")) say(SD_MSG_CLI_ERROR_ALREADY_MOUNTED, NULL, 0, 1);
  else if (is(code, "webclient_disabled")) say(SD_MSG_CLI_ERROR_WEBCLIENT_DISABLED, NULL, 0, 1);
  else if (is(code, "backend_unavailable") && detail && strstr(detail, "WebClient"))
    say(SD_MSG_CLI_ERROR_WEBDAV_UNAVAILABLE, NULL, 0, 1);
  else if (is(code, "backend_unavailable")) say(SD_MSG_CLI_ERROR_BACKEND_UNAVAILABLE, NULL, 0, 1);
  else say1(SD_MSG_CLI_ERROR_GENERIC, "code", code, 1);
}

static int fail_ipc(const cli_args *a, const sd_ipc_error *e, const err_ctx *ec)
{
  int xc = e->exit_code ? e->exit_code : sd_ipc_exit_code_for_code(e->code);
  print_error(a, e->code[0] ? e->code : "internal", e->detail, xc, ec);
  return xc;
}

static int fail_code(const cli_args *a, const char *code, const char *detail, const err_ctx *ec)
{
  int xc = sd_ipc_exit_code_for_code(code);
  print_error(a, code, detail, xc, ec);
  return xc;
}

/* ---- connection ---- */

static int can_prompt(const cli_args *a)
{
  if (a->prompt == CLI_PROMPT_NONE || a->prompt == CLI_PROMPT_GUI)
    return 0;
  return cli_stdin_is_console() || a->use_stdin;
}

static int connect_agent(const cli_args *a, int start, sd_ipc_conn **c, const err_ctx *ec)
{
  sd_ipc_hello h;
  sd_err e;
  memset(&h, 0, sizeof(h));
  h.client_kind = "cli";
  h.client_version = SD_VERSION_STRING;
  h.lang = sd_l10n_lang_code(sd_l10n_lang());
  h.caps = can_prompt(a) ? SD_IPC_CAP_PROMPTS_CONSOLE : 0;
  e = sd_ipc_connect(SD_IPC_AGENT, &h, start, 10000, c);
  if (e == SD_OK)
    return 0;
  if (e == SD_E_ACCESS_DENIED) {
    fail_code(a, "agent_untrusted", "agent pipe owner check failed", ec);
    return 9;
  }
  if (e == SD_E_PROTOCOL)
    return fail_code(a, "proto_unsupported", "no common protocol version", ec);
  return fail_code(a, "agent_unavailable", "cannot connect to the agent", ec);
}

static int subscribe(sd_ipc_conn *c, const char *topic)
{
  char buf[96];
  sd_ipc_error err;
  sd_json *res = NULL;
  size_t n = strlen(topic);
  sd_err e;
  if (n > 32) return 0;
  memcpy(buf, "{\"topics\":[\"", 12);
  memcpy(buf + 12, topic, n);
  memcpy(buf + 12 + n, "\"]}", 4);
  e = sd_ipc_call_raw(c, "subscribe", buf, 12 + n + 3, CALL_TIMEOUT, &res, &err);
  sd_json_free(res);
  return e == SD_OK;
}

/* ---- prompts ---- */

static int answer(sd_ipc_conn *c, const char *prompt_id, const char *action, const char *secret)
{
  sd_wr w;
  sd_json_writer jw;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_err e;
  sd_wr_init_secret(&w, 64 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, prompt_id);
  sd_jw_key(&jw, "action"); sd_jw_cstr(&jw, action);
  if (secret) {
    sd_jw_key(&jw, "responses");
    sd_jw_arr_begin(&jw);
    sd_jw_cstr(&jw, secret);
    sd_jw_arr_end(&jw);
  }
  sd_jw_obj_end(&jw);
  e = sd_jw_finish(&jw);
  if (e == SD_OK)
    e = sd_ipc_call_raw(c, "prompt.answer", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err);
  sd_wr_free(&w);    /* secret writer: wiped */
  sd_json_free(res);
  return e == SD_OK;
}

/* Compares an answer with a localized letter or word, case-insensitively. */
static int answer_is(const char *ans, sd_msg_id letter, sd_msg_id word)
{
  wchar_t wa[64];
  size_t got = 0;
  const wchar_t *l = sd_l10n_get(letter), *wd = sd_l10n_get(word);
  if (sd_utf8_to_utf16(ans, strlen(ans), wa, SD_COUNTOF(wa) - 1, &got, SD_UTF_REPLACE) != SD_OK)
    return 0;
  wa[got] = 0;
  while (got && (wa[got - 1] == L' ' || wa[got - 1] == L'\t')) wa[--got] = 0;
  if (got == 0)
    return 0;
  return CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, wa, -1, l, -1) == CSTR_EQUAL ||
         CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, wa, -1, wd, -1) == CSTR_EQUAL;
}

static void handle_prompt(const cli_args *a, sd_ipc_conn *c, const sd_json *d)
{
  const char *pid = sd_json_get_str(d, "prompt_id");
  const char *kind = sd_json_get_str(d, "kind");
  const char *host = sd_json_get_str(d, "host");
  char line[1024];
  int ok, just = 0;
  if (pid == NULL || kind == NULL)
    return;
  if (strcmp(kind, "hostkey_unknown") == 0) {
    wchar_t *wh = wide(host), *wt = wide(sd_json_get_str(d, "key_type")), *wf = wide(sd_json_get_str(d, "fingerprint"));
    int64_t port = 22;
    wchar_t pbuf[24];
    sd_arg args[2];
    sd_json_get_int64(d, "port", &port);
    args[0].name = "host"; args[0].type = SD_ARG_STR; args[0].v.s = wh ? wh : L"";
    args[1].name = "port"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(pbuf, SD_COUNTOF(pbuf), port);
    say(SD_MSG_CLI_HK_UNKNOWN, args, 2, 1);
    args[0].name = "type"; args[0].type = SD_ARG_STR; args[0].v.s = wt ? wt : L"";
    args[1].name = "fingerprint"; args[1].type = SD_ARG_STR; args[1].v.s = wf ? wf : L"";
    say(SD_MSG_CLI_HK_FINGERPRINT, args, 2, 1);
    say(SD_MSG_CLI_HK_CHECK_HINT, NULL, 0, 1);
    sd_free(wh); sd_free(wt); sd_free(wf);
    cli_eprint_raw(sd_l10n_get(SD_MSG_CLI_HOSTKEY_DEFAULT_NO));
    ok = cli_read_line(line, sizeof(line), 1, a->use_stdin);
    /* Default is "no" (TM-R03): empty input, EOF or anything else rejects. */
    if (ok && answer_is(line, SD_MSG_CLI_HK_LETTER_YES, SD_MSG_CLI_HK_WORD_YES))
      answer(c, pid, "accept", NULL);
    else if (ok && answer_is(line, SD_MSG_CLI_HK_LETTER_ONCE, SD_MSG_CLI_HK_WORD_ONCE))
      answer(c, pid, "once", NULL);
    else
      answer(c, pid, "reject", NULL);
    return;
  }
  {
    int64_t round = 0;
    sd_json_get_bool(d, "hostkey_just_accepted", &just);
    sd_json_get_int64(d, "round", &round);
    if (round > 0)
      say(SD_MSG_CLI_PROMPT_RETRY, NULL, 0, 1);
    if (just)
      say(SD_MSG_PROMPT_HOSTKEY_JUST_ACCEPTED, NULL, 0, 1);
  }
  if (strcmp(kind, "kbdint") == 0) {
    const sd_json *k = sd_json_get(d, "kbdint"), *prompts = sd_json_get(k, "prompts");
    size_t i, n = sd_json_count(prompts);
    char *answers[8];
    say1(SD_MSG_CLI_PROMPT_SERVER_SAYS, "host", host, 1);
    if (n == 0 || n > 8) {
      answer(c, pid, "cancel", NULL);
      return;
    }
    {
      const char *name = sd_json_get_str(k, "name"), *instr = sd_json_get_str(k, "instruction");
      wchar_t *w;
      if (name && name[0] && (w = wide(name)) != NULL) { cli_eprint(w); sd_free(w); }
      if (instr && instr[0] && (w = wide(instr)) != NULL) { cli_eprint(w); sd_free(w); }
    }
    memset(answers, 0, sizeof(answers));
    ok = 1;
    for (i = 0; i < n && ok; i++) {
      const sd_json *it = sd_json_at(prompts, i);
      int echo = 0;
      wchar_t *w = wide(sd_json_get_str(it, "text"));
      sd_json_get_bool(it, "echo", &echo);
      if (w) { cli_eprint_raw(w); sd_free(w); }
      answers[i] = (char *)sd_alloc(1024);
      ok = answers[i] && cli_read_line(answers[i], 1024, echo, a->use_stdin);
    }
    if (ok) {
      sd_wr w;
      sd_json_writer jw;
      sd_ipc_error err;
      sd_json *res = NULL;
      sd_wr_init_secret(&w, 64 * 1024);
      sd_jw_init(&jw, &w);
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, pid);
      sd_jw_key(&jw, "action"); sd_jw_cstr(&jw, "answer");
      sd_jw_key(&jw, "responses");
      sd_jw_arr_begin(&jw);
      for (i = 0; i < n; i++) sd_jw_cstr(&jw, answers[i]);
      sd_jw_arr_end(&jw);
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK)
        sd_ipc_call_raw(c, "prompt.answer", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err);
      sd_json_free(res);
      sd_wr_free(&w);
    } else {
      answer(c, pid, "cancel", NULL);
    }
    for (i = 0; i < 8; i++)
      if (answers[i]) sd_secure_free(answers[i], 1024);
    return;
  }
  {
    wchar_t *s;
    sd_arg args[2];
    wchar_t *wu = wide(sd_json_get_str(d, "user")), *wh = wide(host), *wk = wide(sd_json_get_str(d, "key_path"));
    if (strcmp(kind, "passphrase") == 0) {
      args[0].name = "key"; args[0].type = SD_ARG_STR; args[0].v.s = wk ? wk : L"";
      s = sd_l10n_format_alloc(SD_MSG_CLI_PROMPT_PASSPHRASE, args, 1);
    } else {
      args[0].name = "user"; args[0].type = SD_ARG_STR; args[0].v.s = wu ? wu : L"";
      args[1].name = "host"; args[1].type = SD_ARG_STR; args[1].v.s = wh ? wh : L"";
      s = sd_l10n_format_alloc(SD_MSG_CLI_PROMPT_PASSWORD, args, 2);
    }
    if (s) { cli_eprint_raw(s); sd_free(s); }
    sd_free(wu); sd_free(wh); sd_free(wk);
    ok = cli_read_line(line, sizeof(line), 0, a->use_stdin);
    if (ok)
      answer(c, pid, "answer", line);
    else
      answer(c, pid, "cancel", NULL);
    SecureZeroMemory(line, sizeof(line));
  }
}

/* ---- commands ---- */

static void fill_target(wchar_t out[4], wchar_t l)
{
  out[0] = l ? l : L'?';
  out[1] = L':';
  out[2] = 0;
}

static int cmd_mount(const cli_args *a)
{
  sd_ipc_conn *c = NULL;
  sd_wr w;
  sd_json_writer jw;
  sd_ipc_error err;
  sd_json *res = NULL;
  err_ctx ec;
  char user[128], host[256], mount_id[32], name_u8[256];
  uint16_t port = 22;
  int rc = 0;
  sd_err e;

  memset(&ec, 0, sizeof(ec));
  user[0] = host[0] = name_u8[0] = 0;
  ec.name = a->positional;
  fill_target(ec.target, a->letter);
  if (a->host_spec) {
    if (sd_parse_host_spec(a->host_spec, user, sizeof(user), host, sizeof(host), &port) != SD_OK)
      return fail_code(a, "usage", "invalid host", &ec);
    ec.host = host;
  }
  sd_wr_init(&w, 64 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  if (a->host_spec) {
    sd_jw_key(&jw, "adhoc");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, host);
    sd_jw_key(&jw, "port"); sd_jw_int(&jw, port);
    if (user[0]) { sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, user); }
    if (a->identity) {
      wchar_t full[MAX_PATH];
      char *u = NULL;
      DWORD n = GetFullPathNameW(a->identity, MAX_PATH, full, NULL);   /* the agent runs elsewhere */
      if (n == 0 || n >= MAX_PATH || sd_wide_to_utf8_alloc(full, n, SD_UTF_STRICT, &u) != SD_OK) {
        sd_wr_free(&w);
        return fail_code(a, "usage", "invalid identity path", &ec);
      }
      sd_jw_key(&jw, "identity"); sd_jw_cstr(&jw, u);
      sd_free(u);
    }
    if (a->remote_path) {
      char *u = NULL;
      if (sd_wide_to_utf8_alloc(a->remote_path, (size_t)-1, SD_UTF_STRICT, &u) != SD_OK) {
        sd_wr_free(&w);
        return fail_code(a, "usage", "invalid remote path", &ec);
      }
      sd_jw_key(&jw, "remote_path"); sd_jw_cstr(&jw, u);
      sd_free(u);
    }
    sd_jw_obj_end(&jw);
  } else {
    char *u = NULL;
    if (sd_wide_to_utf8_alloc(a->positional, (size_t)-1, SD_UTF_STRICT, &u) != SD_OK) {
      sd_wr_free(&w);
      return fail_code(a, "usage", "invalid profile name", &ec);
    }
    sd_jw_key(&jw, "profile"); sd_jw_cstr(&jw, u);
    sd_free(u);
  }
  if (a->letter) {
    char t[3];
    t[0] = (char)a->letter; t[1] = ':'; t[2] = 0;
    sd_jw_key(&jw, "target"); sd_jw_cstr(&jw, t);
  }
  if (a->read_only) { sd_jw_key(&jw, "read_only"); sd_jw_bool(&jw, 1); }
  if (a->backend) { sd_jw_key(&jw, "backend"); sd_jw_cstr(&jw, a->backend); }
  sd_jw_key(&jw, "prompt_mode"); sd_jw_cstr(&jw, can_prompt(a) ? "console" : "none");
  sd_jw_obj_end(&jw);
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
  e = sd_ipc_call_raw(c, "mount", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err);
  sd_wr_free(&w);
  if (e != SD_OK) {
    rc = fail_ipc(a, &err, &ec);
    sd_ipc_close(c);
    return rc;
  }
  {
    const char *id = sd_json_get_str(res, "mount_id"), *t = sd_json_get_str(res, "target");
    const char *pn = sd_json_get_str(res, "profile");
    size_t n = id ? strlen(id) : 0;
    if (n == 0 || n >= sizeof(mount_id)) {
      sd_json_free(res);
      sd_ipc_close(c);
      return fail_code(a, "internal", "bad mount reply", &ec);
    }
    memcpy(mount_id, id, n + 1);
    if (t && t[0]) { ec.target[0] = (wchar_t)t[0]; ec.target[1] = L':'; ec.target[2] = 0; }
    if (pn && strlen(pn) < sizeof(name_u8)) memcpy(name_u8, pn, strlen(pn) + 1);
    if (!ec.host) {
      /* profile mounts: the host for messages comes from the profile name */
      ec.host = name_u8;
    }
  }
  if (a->no_wait) {
    wchar_t *wn = wide(name_u8);
    sd_arg args[2];
    if (a->json) json_ok(res);
    else {
      args[0].name = "name"; args[0].type = SD_ARG_STR; args[0].v.s = wn ? wn : L"";
      args[1].name = "target"; args[1].type = SD_ARG_STR; args[1].v.s = ec.target;
      say(SD_MSG_CLI_MOUNT_STARTED, args, 2, 0);
    }
    sd_free(wn);
    sd_json_free(res);
    sd_ipc_close(c);
    return 0;
  }
  sd_json_free(res);
  res = NULL;
  if (!a->json && !a->quiet)
    say1(SD_MSG_CLI_MOUNT_CONNECTING, "host", ec.host, 1);

  for (;;) {
    sd_json *ev = NULL;
    const char *name;
    const sd_json *data;
    e = sd_ipc_next_event(c, INFINITE, &ev);
    if (e != SD_OK) {
      rc = fail_code(a, "agent_unavailable", "agent disconnected", &ec);
      break;
    }
    name = sd_json_get_str(ev, "event");
    data = sd_json_get(ev, "data");
    if (!is(sd_json_get_str(data, "mount_id"), mount_id)) {
      sd_json_free(ev);
      continue;
    }
    if (is(name, "prompt.request")) {
      handle_prompt(a, c, data);
    } else if (is(name, "mount.state")) {
      const char *st = sd_json_get_str(data, "state");
      if (is(st, "mounted")) {
        if (a->json) {
          sd_wr r;
          sd_json_writer rj;
          sd_json *obj = NULL;
          sd_wr_init(&r, 4096);
          sd_jw_init(&rj, &r);
          sd_jw_obj_begin(&rj);
          sd_jw_key(&rj, "mount_id"); sd_jw_cstr(&rj, mount_id);
          {
            char t[3];
            t[0] = (char)ec.target[0]; t[1] = ':'; t[2] = 0;
            sd_jw_key(&rj, "target"); sd_jw_cstr(&rj, t);
          }
          sd_jw_key(&rj, "profile"); sd_jw_cstr(&rj, name_u8);
          sd_jw_key(&rj, "state"); sd_jw_cstr(&rj, "mounted");
          sd_jw_obj_end(&rj);
          if (sd_jw_finish(&rj) == SD_OK && sd_json_parse((const char *)r.p, r.len, 8, &obj) == SD_OK)
            json_ok(obj);
          sd_json_free(obj);
          sd_wr_free(&r);
        } else {
          wchar_t *wn = wide(name_u8);
          sd_arg args[2];
          args[0].name = "name"; args[0].type = SD_ARG_STR; args[0].v.s = wn ? wn : L"";
          args[1].name = "target"; args[1].type = SD_ARG_STR; args[1].v.s = ec.target;
          say(SD_MSG_CLI_MOUNT_DONE, args, 2, 0);
          sd_free(wn);
        }
        rc = 0;
        sd_json_free(ev);
        break;
      }
      if (is(st, "failed") || is(st, "unmounted")) {
        const sd_json *er = sd_json_get(data, "error");
        const char *code = sd_json_get_str(er, "code");
        int64_t xc = 0;
        ec.detail = er;
        if (!sd_json_get_int64(er, "exit_code", &xc) || xc == 0)
          xc = code ? sd_ipc_exit_code_for_code(code) : 1;
        print_error(a, code ? code : "cancelled", sd_json_get_str(er, "detail"), (int)xc, &ec);
        rc = (int)xc;
        sd_json_free(ev);
        break;
      }
    }
    sd_json_free(ev);
  }
  sd_ipc_close(c);
  return rc;
}

static const sd_ipc_hello *quiet_hello(sd_ipc_hello *h)
{
  memset(h, 0, sizeof(*h));
  h->client_kind = "cli";
  h->client_version = SD_VERSION_STRING;
  h->lang = sd_l10n_lang_code(sd_l10n_lang());
  return h;
}

static int cmd_unmount(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_wr w;
  sd_json_writer jw;
  err_ctx ec;
  wchar_t letter = a->positional ? sd_parse_drive_letter(a->positional) : 0;
  char ids[16][32];
  char letters[16];
  size_t nids = 0, i, done = 0;
  int rc;
  sd_err e;
  memset(&ec, 0, sizeof(ec));
  ec.name = a->positional;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello),
                     0, 5000, &c) != SD_OK) {
    if (a->all) {
      if (a->json) json_ok(NULL);
      return 0;
    }
    return fail_code(a, "mount_not_found", "agent not running", &ec);
  }
  if (!subscribe(c, "mount")) {
    sd_ipc_close(c);
    return fail_code(a, "agent_unavailable", "subscribe failed", &ec);
  }
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  if (a->all) {
    sd_jw_key(&jw, "all"); sd_jw_bool(&jw, 1);
  } else {
    char *u = NULL;
    if (sd_wide_to_utf8_alloc(a->positional, (size_t)-1, SD_UTF_STRICT, &u) == SD_OK) {
      if (letter) { sd_jw_key(&jw, "target"); }
      else if (strncmp(u, "m-", 2) == 0) { sd_jw_key(&jw, "mount_id"); }
      else { sd_jw_key(&jw, "profile"); }
      sd_jw_cstr(&jw, u);
      sd_free(u);
    }
  }
  if (a->force) { sd_jw_key(&jw, "force"); sd_jw_bool(&jw, 1); }
  sd_jw_obj_end(&jw);
  e = sd_jw_finish(&jw) == SD_OK ? sd_ipc_call_raw(c, "unmount", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err)
                                  : SD_E_INTERNAL;
  sd_wr_free(&w);
  if (e != SD_OK) {
    rc = fail_ipc(a, &err, &ec);
    sd_ipc_close(c);
    return rc;
  }
  {
    const sd_json *arr = sd_json_get(res, "mounts");
    for (i = 0; i < sd_json_count(arr) && nids < 16; i++) {
      const char *id = sd_json_get_str(sd_json_at(arr, i), "mount_id");
      const char *t = sd_json_get_str(sd_json_at(arr, i), "target");
      if (id && strlen(id) < 32) {
        memcpy(ids[nids], id, strlen(id) + 1);
        letters[nids] = t ? t[0] : '?';
        nids++;
      }
    }
  }
  /* wait (bounded) for every mount to report unmounted */
  while (done < nids) {
    sd_json *ev = NULL;
    const sd_json *data;
    const char *st, *id;
    if (sd_ipc_next_event(c, 30000, &ev) != SD_OK)
      break;
    data = sd_json_get(ev, "data");
    st = sd_json_get_str(data, "state");
    id = sd_json_get_str(data, "mount_id");
    if (is(sd_json_get_str(ev, "event"), "mount.state") && (is(st, "unmounted") || is(st, "failed"))) {
      for (i = 0; i < nids; i++) {
        if (ids[i][0] && is(id, ids[i])) {
          if (!a->json) {
            wchar_t t[3];
            t[0] = (wchar_t)letters[i]; t[1] = L':'; t[2] = 0;
            say1w(SD_MSG_CLI_UNMOUNT_DONE, "target", t, 0);
          }
          ids[i][0] = 0;
          done++;
        }
      }
    }
    sd_json_free(ev);
  }
  if (a->json) json_ok(res);
  sd_json_free(res);
  sd_ipc_close(c);
  if (done < nids)
    return fail_code(a, "timeout", "unmount did not complete", &ec);
  return 0;
}

static void pad_print(wchar_t *line, size_t cap, size_t *len, const wchar_t *s, size_t width)
{
  size_t n = wcslen(s), i;
  for (i = 0; i < n && *len + 1 < cap; i++) line[(*len)++] = s[i];
  for (; i < width && *len + 1 < cap; i++) line[(*len)++] = L' ';
  if (*len + 1 < cap) line[(*len)++] = L' ';
  line[*len] = 0;
}

static sd_msg_id state_msg(const char *st);

/* M1: an offline mount whose session is still trying shows "reconnecting". */
static sd_msg_id mount_state_msg(const sd_json *m)
{
  const char *st = sd_json_get_str(m, "state");
  const char *sess = sd_json_get_str(sd_json_get(m, "connection"), "session");
  if (is(st, "offline") && (is(sess, "disconnected") || is(sess, "reconnect_wait") || is(sess, "connecting")))
    return SD_MSG_CLI_STATE_RECONNECTING;
  return state_msg(st);
}

static sd_msg_id state_msg(const char *st)
{
  if (is(st, "connecting")) return SD_MSG_CLI_STATE_CONNECTING;
  if (is(st, "authenticating")) return SD_MSG_CLI_STATE_AUTHENTICATING;
  if (is(st, "mounted")) return SD_MSG_CLI_STATE_MOUNTED;
  if (is(st, "offline")) return SD_MSG_CLI_STATE_OFFLINE;
  if (is(st, "auth_required")) return SD_MSG_CLI_STATE_AUTH_REQUIRED;
  if (is(st, "unmounting")) return SD_MSG_CLI_STATE_UNMOUNTING;
  if (is(st, "unmounted")) return SD_MSG_CLI_STATE_UNMOUNTED;
  return SD_MSG_CLI_STATE_FAILED;
}

static int cmd_list(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  const sd_json *arr;
  size_t i, n;
  int rc;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello),
                     0, 5000, &c) != SD_OK) {
    /* no agent: nothing is mounted in this session */
    if (a->json) cli_print_utf8_line("{\"ok\":true,\"result\":{\"mounts\":[]}}", 34);
    else say(SD_MSG_CLI_LIST_EMPTY, NULL, 0, 0);
    return 0;
  }
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, NULL);
    sd_ipc_close(c);
    return rc;
  }
  sd_ipc_close(c);
  if (a->json) {
    json_ok(res);
    sd_json_free(res);
    return 0;
  }
  arr = sd_json_get(res, "mounts");
  n = sd_json_count(arr);
  if (n == 0) {
    say(SD_MSG_CLI_LIST_EMPTY, NULL, 0, 0);
  } else {
    wchar_t line[1024];
    size_t len = 0;
    line[0] = 0;
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_LIST_COL_DRIVE), 8);
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_LIST_COL_STATE), 22);
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_LIST_COL_SERVER), 30);
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_LIST_COL_PROFILE), 0);
    cli_print(line);
    for (i = 0; i < n; i++) {
      const sd_json *m = sd_json_at(arr, i);
      wchar_t *t = wide(sd_json_get_str(m, "target")), *p = wide(sd_json_get_str(m, "profile"));
      const char *h = sd_json_get_str(m, "host"), *u = sd_json_get_str(m, "user");
      char server[512];
      wchar_t *ws;
      int64_t port = 22;
      sd_json_get_int64(m, "port", &port);
      server[0] = 0;
      if (u && h && strlen(u) + strlen(h) + 16 < sizeof(server)) {
        size_t o = 0, k;
        for (k = 0; u[k]; k++) server[o++] = u[k];
        server[o++] = '@';
        for (k = 0; h[k]; k++) server[o++] = h[k];
        if (port != 22) {
          char tmp[8];
          size_t tn = 0;
          int64_t v = port;
          server[o++] = ':';
          do { tmp[tn++] = (char)('0' + v % 10); v /= 10; } while (v && tn < 7);
          while (tn) server[o++] = tmp[--tn];
        }
        server[o] = 0;
      }
      ws = wide(server);
      len = 0;
      line[0] = 0;
      pad_print(line, SD_COUNTOF(line), &len, t ? t : L"", 8);
      pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(mount_state_msg(m)), 22);
      pad_print(line, SD_COUNTOF(line), &len, ws ? ws : L"", 30);
      pad_print(line, SD_COUNTOF(line), &len, p ? p : L"", 0);
      cli_print(line);
      sd_free(t); sd_free(p); sd_free(ws);
    }
    {
      sd_arg arg;
      arg.name = "count";
      arg.type = SD_ARG_INT;
      arg.v.i = (long long)n;
      say(SD_MSG_CLI_MOUNTED_COUNT, &arg, 1, 0);
    }
    /* write-behind data that could not be written (C45): always shown */
    for (i = 0; i < n; i++) {
      const sd_json *m = sd_json_at(arr, i);
      int64_t wf = 0;
      if (sd_json_get_int64(m, "write_failed", &wf) && wf > 0) {
        wchar_t *t = wide(sd_json_get_str(m, "target")), *wp = wide(sd_json_get_str(m, "last_write_failed"));
        sd_arg args[3];
        args[0].name = "target"; args[0].type = SD_ARG_STR; args[0].v.s = t ? t : L"";
        args[1].name = "count"; args[1].type = SD_ARG_INT; args[1].v.i = (long long)wf;
        args[2].name = "path"; args[2].type = SD_ARG_STR; args[2].v.s = wp ? wp : L"";
        say(SD_MSG_CLI_LIST_WRITE_FAILED, args, 3, 0);
        sd_free(t);
        sd_free(wp);
      }
    }
  }
  sd_json_free(res);
  return 0;
}

static int cmd_agent_stop(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  int rc;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello),
                     0, 5000, &c) != SD_OK) {
    if (a->json) json_ok(NULL);
    else say(SD_MSG_CLI_AGENT_NOT_RUNNING, NULL, 0, 0);
    return 0;
  }
  if (sd_ipc_call_raw(c, "agent.shutdown", "{\"unmount\":true}", 16, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, NULL);
    sd_ipc_close(c);
    return rc;
  }
  /* wait for the agent to go away (the pipe breaks) */
  {
    sd_json *ev = NULL;
    while (sd_ipc_next_event(c, 20000, &ev) == SD_OK)
      sd_json_free(ev);
  }
  sd_ipc_close(c);
  if (a->json) json_ok(res);
  else say(SD_MSG_CLI_AGENT_STOPPED, NULL, 0, 0);
  sd_json_free(res);
  return 0;
}

/* ---- help ---- */

static void help_line(const wchar_t *synopsis, sd_msg_id desc)
{
  wchar_t line[512];
  line[0] = 0;
  wcscpy_s(line, SD_COUNTOF(line), L"  ");
  wcscat_s(line, SD_COUNTOF(line), synopsis);
  cli_print(line);
  wcscpy_s(line, SD_COUNTOF(line), L"      ");
  wcscat_s(line, SD_COUNTOF(line), sd_l10n_get(desc));
  cli_print(line);
}

void cli_print_help(const wchar_t *topic)
{
  cli_print(sd_l10n_get(SD_MSG_CLI_USAGE));
  cli_print(L"");
  if (topic && wcscmp(topic, L"mount") == 0) {
    help_line(L"mount <profile> [--letter X:] [--backend auto|dokany|webdav] [--read-only] [--prompt auto|console|none] [--stdin] [--no-wait]",
              SD_MSG_CLI_HELP_MOUNT);
    help_line(L"mount --host [user@]host[:port] [--letter X:] [--identity FILE] [--remote-path PATH] ...",
              SD_MSG_CLI_HELP_MOUNT);
    cli_print(L"");
    cli_print(sd_l10n_get(SD_MSG_CLI_HELP_OPTIONS));
    help_line(L"--host [user@]host[:port]", SD_MSG_CLI_HELP_OPT_HOST);
    help_line(L"--letter X:  (--target X:)", SD_MSG_CLI_HELP_OPT_LETTER);
    help_line(L"--identity FILE  (-i FILE)", SD_MSG_CLI_HELP_OPT_IDENTITY);
    help_line(L"--remote-path PATH  (--path PATH)", SD_MSG_CLI_HELP_OPT_REMOTE_PATH);
    help_line(L"--backend auto|dokany|webdav", SD_MSG_CLI_HELP_OPT_BACKEND);
    help_line(L"--read-only", SD_MSG_CLI_HELP_OPT_READ_ONLY);
    help_line(L"--prompt auto|console|none", SD_MSG_CLI_HELP_OPT_PROMPT);
    help_line(L"--stdin", SD_MSG_CLI_HELP_OPT_STDIN);
    help_line(L"--no-wait", SD_MSG_CLI_HELP_OPT_NO_WAIT);
  } else if (topic && (wcscmp(topic, L"unmount") == 0 || wcscmp(topic, L"umount") == 0)) {
    help_line(L"unmount <X:|profile|mount-id> | --all", SD_MSG_CLI_HELP_UNMOUNT);
    cli_print(L"");
    cli_print(sd_l10n_get(SD_MSG_CLI_HELP_OPTIONS));
    help_line(L"--all", SD_MSG_CLI_HELP_OPT_ALL);
  } else if (topic && wcscmp(topic, L"list") == 0) {
    help_line(L"list", SD_MSG_CLI_HELP_LIST);
  } else if (topic && wcscmp(topic, L"agent") == 0) {
    help_line(L"agent stop", SD_MSG_CLI_HELP_AGENT_STOP);
  } else {
    cli_print(sd_l10n_get(SD_MSG_CLI_HELP_COMMANDS));
    help_line(L"mount <profile> | --host [user@]host[:port]", SD_MSG_CLI_HELP_MOUNT);
    help_line(L"unmount <X:|profile> | --all", SD_MSG_CLI_HELP_UNMOUNT);
    help_line(L"list", SD_MSG_CLI_HELP_LIST);
    help_line(L"agent stop", SD_MSG_CLI_HELP_AGENT_STOP);
    help_line(L"version", SD_MSG_CLI_HELP_VERSION);
    help_line(L"help [command]", SD_MSG_CLI_HELP_HELP);
    cli_print(L"");
    cli_print(sd_l10n_get(SD_MSG_CLI_HELP_MORE));
  }
  cli_print(L"");
  cli_print(sd_l10n_get(SD_MSG_CLI_HELP_GLOBAL_OPTIONS));
  help_line(L"--json", SD_MSG_CLI_HELP_OPT_JSON);
  help_line(L"--quiet", SD_MSG_CLI_HELP_OPT_QUIET);
  help_line(L"--lang en|es|fr|pt|it|de", SD_MSG_CLI_HELP_OPT_LANG);
}

static int cmd_version(const cli_args *a)
{
  if (a->json) {
    char buf[256];
    size_t n;
    strcpy_s(buf, sizeof(buf), "{\"ok\":true,\"result\":{\"version\":\"" SD_VERSION_STRING "\",\"commit\":\""
             SD_GIT_COMMIT "\",\"flavour\":\"" SD_FLAVOUR_NAME "\"}}");
    n = strlen(buf);
    cli_print_utf8_line(buf, n);
  } else {
    sd_arg arg = SD_S("version", SD_VERSION_STRING_W L" (" TEXT(SD_FLAVOUR_NAME) L", " TEXT(SD_GIT_COMMIT) L")");
    say(SD_MSG_CLI_VERSION, &arg, 1, 0);
  }
  return 0;
}

int cli_run(const cli_args *a)
{
  if (a->help || a->cmd == CLI_CMD_HELP) {
    cli_print_help(a->cmd == CLI_CMD_HELP ? a->positional : a->cmd_name);
    return 0;
  }
  switch (a->cmd) {
  case CLI_CMD_VERSION:    return cmd_version(a);
  case CLI_CMD_MOUNT:      return cmd_mount(a);
  case CLI_CMD_UNMOUNT:    return cmd_unmount(a);
  case CLI_CMD_LIST:       return cmd_list(a);
  case CLI_CMD_AGENT_STOP: return cmd_agent_stop(a);
  default:
    cli_print_help(NULL);
    return 2;
  }
}
