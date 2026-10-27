/* shelldrive.exe internals: command-line model, parser, output and commands (03 §6). */
#ifndef SD_CLI_H
#define SD_CLI_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

typedef enum cli_cmd {
  CLI_CMD_NONE, CLI_CMD_HELP, CLI_CMD_VERSION, CLI_CMD_MOUNT, CLI_CMD_UNMOUNT, CLI_CMD_LIST,
  CLI_CMD_AGENT_STOP, CLI_CMD_STATUS, CLI_CMD_PROFILE, CLI_CMD_HOSTKEY,
  CLI_CMD_REFRESH, CLI_CMD_CACHE,    /* M3: refresh <X:|PATH>[\sub\path], cache clear [<profile>|--all] */
  CLI_CMD_SERVICE                    /* M5: service list | mount | unmount | status (03 §6.1) */
} cli_cmd;

/* Repeatable --jump: at most SD_PROFILE_MAX_HOPS hops before the parse rejects one more. */
#define CLI_MAX_JUMP 8

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
  int stats, open_after;     /* status --stats (and the stats alias); mount --open */
  cli_prompt_mode prompt;
  const wchar_t *lang;
  const wchar_t *positional; /* mount: profile; unmount: X: | profile | mount id; help: topic;
                                profile/hostkey: the sub-verb ("import", "list", ...); status: filter */
  const wchar_t *arg2;       /* profile import: "putty" | "ssh-config"; hostkey: host / file / id */
  const wchar_t *arg3;       /* profile import putty: session; profile import ssh-config: file */
  const wchar_t *subverb;    /* alias of positional for profile/hostkey (readability) */
  const wchar_t *host_spec;  /* mount --host [user@]host[:port] */
  wchar_t letter;            /* --letter / --target, 0 = auto */
  const wchar_t *identity;   /* --identity FILE */
  const wchar_t *remote_path;/* --remote-path / --path */
  const char *backend;       /* mount --backend: "auto" | "dokany" | "webdav"; NULL = profile/auto */
  const wchar_t *jump[CLI_MAX_JUMP];   /* mount --jump, one entry per repeat, in order */
  int jump_count;
  const wchar_t *proxy;      /* mount --proxy scheme://[user@]host[:port] */
  int connections;           /* mount --connections N (1..4); 0 = not given */
  const wchar_t *hk_type;    /* hostkey remove --type T */
  const wchar_t *from;       /* hostkey import --from putty|openssh */
  int dry_run, add_only, announced;
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

/* ---- commands (cli_cmds.c, cli_cmds2.c) ---- */
int cli_run(const cli_args *a);                /* returns the process exit code (03 §6.2) */
void cli_print_help(const wchar_t *topic);
int cli_run_status(const cli_args *a);         /* cli_cmds2.c: status (03 §6.1) */
int cli_run_profile(const cli_args *a);        /* cli_cmds2.c: profile import (03 §3.7, §6.1) */
int cli_run_hostkey(const cli_args *a);        /* cli_cmds2.c: hostkey list/import/remove/accept-announced
                                                  (03 §5.5, §5.6, §6.1) */
int cli_run_refresh(const cli_args *a);        /* cli_cmds3.c: refresh <X:|PATH>[\sub\path] (03 §6.1) */
int cli_run_cache(const cli_args *a);          /* cli_cmds3.c: cache clear [<profile>|X:|--all] [--force] (03 §6.1) */
int cli_run_service(const cli_args *a);        /* cli_service.c: service list | mount | unmount | status (03 §1.3, §6.1; M5) */
int cli_run_profile_test(const cli_args *a);   /* cli_cmds3.c: profile test <profile> (03 §6.1) */
int cli_run_status_stats(const cli_args *a);   /* cli_cmds3.c: status --stats (03 §6.1, 02 §11) */

#endif /* SD_CLI_H */
