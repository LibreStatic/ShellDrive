/* Internals shared by the command files of shelldrive.exe (cli_cmds.c, cli_cmds2.c): message
 * helpers, JSON output, localized errors and the agent connection (03 §2, §6). Not installed. */
#ifndef SD_CLI_INT_H
#define SD_CLI_INT_H

#include "cli.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"

#define CALL_TIMEOUT 15000

/* Context for localized error messages: the parts of the failed operation the texts name. */
typedef struct err_ctx {
  const char *host;          /* UTF-8, for {host} */
  const wchar_t *name;       /* profile / target / session / file as typed, for {name} */
  wchar_t target[4];         /* "Z:" */
  const sd_json *detail;     /* error object from the agent (mismatch details) */
} err_ctx;

/* ---- messages (cli_common.c) ---- */
void say(sd_msg_id id, const sd_arg *args, size_t n, int to_stderr);
wchar_t *wide(const char *utf8);               /* NULL on conversion failure; sd_free */
const wchar_t *decimal(wchar_t *buf, size_t cch, long long v);   /* plain digits, never grouped */
void say1(sd_msg_id id, const char *name, const char *utf8, int to_stderr);
void say1w(sd_msg_id id, const char *name, const wchar_t *w, int to_stderr);

/* Compares an answer with a localized letter or word, case-insensitively (trimmed). */
int answer_is(const char *ans, sd_msg_id letter, sd_msg_id word);

/* ---- JSON output (03 §6.3) ---- */
void json_ok(const sd_json *result);
void json_err(const char *code, const char *detail, int exit_code);

/* ---- localized errors (03 §6.2) ---- */
int is(const char *a, const char *b);
void print_error(const cli_args *a, const char *code, const char *detail, int exit_code, const err_ctx *ec);
int fail_ipc(const cli_args *a, const sd_ipc_error *e, const err_ctx *ec);
int fail_code(const cli_args *a, const char *code, const char *detail, const err_ctx *ec);

/* ---- connection ---- */
int can_prompt(const cli_args *a);
/* Answers one prompt.request event of this connection (cli_cmds.c; mount and profile test). */
void handle_prompt(const cli_args *a, sd_ipc_conn *c, const sd_json *d);
int connect_agent(const cli_args *a, int start, sd_ipc_conn **c, const err_ctx *ec);
int subscribe(sd_ipc_conn *c, const char *topic);
const sd_ipc_hello *quiet_hello(sd_ipc_hello *h);
/* Sends prompt.answer. save: keep the secret (with the localized comment) after a successful login. */
int answer_ex(sd_ipc_conn *c, const char *prompt_id, const char *action, const char *secret, int save,
              const wchar_t *save_comment);
int answer(sd_ipc_conn *c, const char *prompt_id, const char *action, const char *secret);

void fill_target(wchar_t out[4], wchar_t l);

#endif /* SD_CLI_INT_H */
