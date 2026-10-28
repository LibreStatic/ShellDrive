/* Helpers shared by the shelldrive.exe command files (03 §2, §6): localized messages, JSON output,
 * the error table and the agent connection. Moved out of cli_cmds.c when the profile, hostkey and
 * status commands arrived. */
#include <windows.h>
#include <string.h>

#include "cli_int.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

/* ---- message helpers ---- */

void say(sd_msg_id id, const sd_arg *args, size_t n, int to_stderr)
{
  wchar_t *s = sd_l10n_format_alloc(id, args, n);
  if (s == NULL)
    return;
  if (to_stderr) cli_eprint(s); else cli_print(s);
  sd_free(s);
}

wchar_t *wide(const char *utf8)
{
  wchar_t *w = NULL;
  if (utf8 == NULL || sd_utf8_to_wide_alloc(utf8, (size_t)-1, SD_UTF_REPLACE, &w) != SD_OK)
    return NULL;
  return w;
}

/* Plain decimal for identifiers (ports, line numbers): SD_ARG_INT groups digits per user locale. */
const wchar_t *decimal(wchar_t *buf, size_t cch, long long v)
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

void say1(sd_msg_id id, const char *name, const char *utf8, int to_stderr)
{
  wchar_t *w = wide(utf8 ? utf8 : "");
  sd_arg a[1];
  a[0].name = name; a[0].type = SD_ARG_STR; a[0].v.s = w ? w : L"";
  say(id, a, 1, to_stderr);
  sd_free(w);
}

void say1w(sd_msg_id id, const char *name, const wchar_t *w, int to_stderr)
{
  sd_arg a[1];
  a[0].name = name; a[0].type = SD_ARG_STR; a[0].v.s = w ? w : L"";
  say(id, a, 1, to_stderr);
}

/* Compares an answer with a localized letter or word, case-insensitively. */
int answer_is(const char *ans, sd_msg_id letter, sd_msg_id word)
{
  wchar_t wa[64];
  size_t got = 0;
  const wchar_t *l = sd_l10n_get(letter), *wd = sd_l10n_get(word);
  if (sd_utf8_to_utf16(ans, strlen(ans), wa, SD_COUNTOF(wa) - 1, &got, SD_UTF_REPLACE) != SD_OK)
    return 0;
  wa[got] = 0;
  while (got && (wa[got - 1] == L' ' || wa[got - 1] == L'\t' || wa[got - 1] == L'\r' || wa[got - 1] == L'\n'))
    wa[--got] = 0;
  if (got == 0)
    return 0;
  return CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, wa, -1, l, -1) == CSTR_EQUAL ||
         CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, wa, -1, wd, -1) == CSTR_EQUAL;
}

/* ---- JSON output (03 §6.3) ---- */

void json_ok(const sd_json *result)
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

void json_err(const char *code, const char *detail, int exit_code)
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

int is(const char *a, const char *b) { return a && strcmp(a, b) == 0; }

void print_error(const cli_args *a, const char *code, const char *detail, int exit_code, const err_ctx *ec)
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
  else if (is(code, "read_only_mount")) say1w(SD_MSG_CLI_BENCH_READ_ONLY, "target", ec ? ec->target : NULL, 1);
  else if (is(code, "host_key_not_found"))
    say1w(SD_MSG_CLI_ERROR_HOST_KEY_NOT_FOUND, "host", ec ? ec->name : NULL, 1);
  else if (is(code, "announcement_not_found")) say(SD_MSG_CLI_ERROR_ANNOUNCEMENT_NOT_FOUND, NULL, 0, 1);
  else if (is(code, "session_not_found"))
    say1w(SD_MSG_CLI_ERROR_SESSION_NOT_FOUND, "name", ec ? ec->name : NULL, 1);
  else if (is(code, "putty_not_found")) say(SD_MSG_CLI_ERROR_PUTTY_NOT_FOUND, NULL, 0, 1);
  else if (is(code, "file_not_found")) say1w(SD_MSG_CLI_ERROR_FILE_NOT_FOUND, "name", ec ? ec->name : NULL, 1);
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
  else if (is(code, "not_mounted")) say(SD_MSG_CLI_ERROR_NOT_MOUNTED, NULL, 0, 1);
  else if (is(code, "write_behind_pending")) say(SD_MSG_CLI_ERROR_WRITE_BEHIND_PENDING, NULL, 0, 1);
  else if (is(code, "webclient_disabled")) say(SD_MSG_CLI_ERROR_WEBCLIENT_DISABLED, NULL, 0, 1);
  else if (is(code, "backend_unavailable") && detail && strstr(detail, "WebClient"))
    say(SD_MSG_CLI_ERROR_WEBDAV_UNAVAILABLE, NULL, 0, 1);
  else if (is(code, "backend_unavailable")) say(SD_MSG_CLI_ERROR_BACKEND_UNAVAILABLE, NULL, 0, 1);
  else if (is(code, "elevation_required")) say(SD_MSG_CLI_DIAG_ELEVATION_REQUIRED, NULL, 0, 1);
  else if (is(code, "policy_denied")) say(SD_MSG_CLI_DIAG_FIX_POLICY, NULL, 0, 1);
  else say1(SD_MSG_CLI_ERROR_GENERIC, "code", code, 1);
}

int fail_ipc(const cli_args *a, const sd_ipc_error *e, const err_ctx *ec)
{
  int xc = e->exit_code ? e->exit_code : sd_ipc_exit_code_for_code(e->code);
  print_error(a, e->code[0] ? e->code : "internal", e->detail, xc, ec);
  return xc;
}

int fail_code(const cli_args *a, const char *code, const char *detail, const err_ctx *ec)
{
  int xc = sd_ipc_exit_code_for_code(code);
  print_error(a, code, detail, xc, ec);
  return xc;
}

/* ---- elevation ---- */

/* Changing a global drive or the machine store needs an elevated token (6.1). On XP the query is unavailable:
   the service decides. Test seam (tests/apps only, same style as the other SHELLDRIVE_TEST_* variables):
   SHELLDRIVE_TEST_ELEVATED=0 reports a non-elevated token. Only "0" is read, so a test can deny but never
   grant elevation. */
int cli_is_elevated(void)
{
  HANDLE tok = NULL;
  DWORD elevated = 0, len = 0;
  wchar_t v[4];
  int r = 1;
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_ELEVATED", v, SD_COUNTOF(v)) == 1 && v[0] == L'0')
    return 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 1;
  if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20 /* TokenElevation */, &elevated, sizeof(elevated), &len))
    r = elevated ? 1 : 0;
  CloseHandle(tok);
  return r;
}

/* ---- connection ---- */

int can_prompt(const cli_args *a)
{
  if (a->prompt == CLI_PROMPT_NONE || a->prompt == CLI_PROMPT_GUI)
    return 0;
  return cli_stdin_is_console() || a->use_stdin;
}

int connect_agent(const cli_args *a, int start, sd_ipc_conn **c, const err_ctx *ec)
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

int subscribe(sd_ipc_conn *c, const char *topic)
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

const sd_ipc_hello *quiet_hello(sd_ipc_hello *h)
{
  memset(h, 0, sizeof(*h));
  h->client_kind = "cli";
  h->client_version = SD_VERSION_STRING;
  h->lang = sd_l10n_lang_code(sd_l10n_lang());
  return h;
}

int answer_ex(sd_ipc_conn *c, const char *prompt_id, const char *action, const char *secret, int save,
              const wchar_t *save_comment)
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
  if (save) {
    char *u = NULL;
    sd_jw_key(&jw, "save"); sd_jw_bool(&jw, 1);
    if (save_comment && sd_wide_to_utf8_alloc(save_comment, (size_t)-1, SD_UTF_STRICT, &u) == SD_OK) {
      sd_jw_key(&jw, "save_comment"); sd_jw_cstr(&jw, u);
      sd_free(u);
    }
  }
  sd_jw_obj_end(&jw);
  e = sd_jw_finish(&jw);
  if (e == SD_OK)
    e = sd_ipc_call_raw(c, "prompt.answer", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err);
  sd_wr_free(&w);    /* secret writer: wiped */
  sd_json_free(res);
  return e == SD_OK;
}

int answer(sd_ipc_conn *c, const char *prompt_id, const char *action, const char *secret)
{
  return answer_ex(c, prompt_id, action, secret, 0, NULL);
}

void fill_target(wchar_t out[4], wchar_t l)
{
  out[0] = l ? l : L'?';
  out[1] = L':';
  out[2] = 0;
}
