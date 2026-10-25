/* shelldrive.exe internals: command-line model, parser, output and commands (03 §6). */
#ifndef SD_CLI_H
#define SD_CLI_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

typedef enum cli_cmd {
  CLI_CMD_NONE, CLI_CMD_HELP, CLI_CMD_VERSION, CLI_CMD_MOUNT, CLI_CMD_UNMOUNT, CLI_CMD_LIST,
  CLI_CMD_AGENT_STOP
} cli_cmd;

typedef enum cli_prompt_mode { CLI_PROMPT_AUTO, CLI_PROMPT_CONSOLE, CLI_PROMPT_GUI, CLI_PROMPT_NONE } cli_prompt_mode;

typedef enum cli_usage_err {
  CLI_OK = 0,
  CLI_E_UNKNOWN_COMMAND,     /* bad = command */
  CLI_E_UNKNOWN_OPTION,      /* bad = option */
  CLI_E_MISSING_VALUE,       /* bad = option */
  CLI_E_MISSING_ARGUMENT,    /* bad = command */
  CLI_E_EXTRA_ARGUMENT,      /* bad = argument */
  CLI_E_BAD_VALUE,           /* bad = option, bad_value = value */
  CLI_E_CONFLICT,            /* bad = option, bad_value = other option */
  CLI_E_HOST_SPEC,           /* bad_value = spec */
  CLI_E_LETTER               /* bad_value = letter */
} cli_usage_err;

typedef struct cli_args {
  cli_cmd cmd;
  const wchar_t *cmd_name;   /* command word as typed, for messages */
  int json, quiet, use_stdin, no_wait, read_only, all, force, help;
  cli_prompt_mode prompt;
  const wchar_t *lang;
  const wchar_t *positional; /* mount: profile; unmount: X: | profile | mount id; help: topic */
  const wchar_t *host_spec;  /* mount --host [user@]host[:port] */
  wchar_t letter;            /* --letter / --target, 0 = auto */
  const wchar_t *identity;   /* --identity FILE */
  const wchar_t *remote_path;/* --remote-path / --path */
  const char *backend;       /* mount --backend: "auto" | "dokany" | "webdav"; NULL = profile/auto */
  cli_usage_err err;
  const wchar_t *bad;
  const wchar_t *bad_value;
} cli_args;

/* Splits a command line with the MSVC CRT rules (2008+): quotes group, 2n backslashes before a
   quote give n backslashes and toggle quoting, 2n+1 give n and a literal quote, "" inside quotes is
   a literal quote; argv[0] ends at the first space or closing quote with no escapes. One sd_alloc
   block, released with sd_free(*argv). */
sd_err cli_split_cmdline(const wchar_t *cmdline, int *argc, wchar_t ***argv);

/* Parses argv[1..] (argv[0] is the program). Never prints. Returns args->err. */
cli_usage_err cli_parse(int argc, wchar_t **argv, cli_args *args);

/* ---- output (cli_out.c) ---- */
void cli_out_init(int json, int quiet);
void cli_print(const wchar_t *s);              /* stdout, adds CRLF */
void cli_eprint(const wchar_t *s);             /* stderr / console, adds CRLF */
void cli_eprint_raw(const wchar_t *s);         /* stderr / console, no newline (prompts) */
void cli_print_utf8_line(const char *s, size_t n);  /* stdout, UTF-8 payload (JSON), adds CRLF */
int  cli_stdin_is_console(void);
/* Reads one line (without CR/LF) as UTF-8 into out (NUL-terminated). echo = 0 hides input on a
   console. Returns 0 on EOF / error. */
int  cli_read_line(char *out, size_t cap, int echo, int from_stdin);

/* ---- commands (cli_cmds.c) ---- */
int cli_run(const cli_args *a);                /* returns the process exit code (03 §6.2) */
void cli_print_help(const wchar_t *topic);

#endif /* SD_CLI_H */
