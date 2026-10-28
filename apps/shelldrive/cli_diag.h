/* shelldrive diag (03 §6.1, §10.5): the checks, the fixes and the support bundle.
 *
 * The system is reached only through diag_env, a seam of plain function pointers. The shipping binary fills it
 * with the Win32 calls (registry, service control manager, file system); the test build (SD_CLI_TEST_HOOKS) can
 * replace it with a fake that keeps its state in a file of the test, so no test changes the state of a real
 * machine. The seam is used for every write; the read-only service query of the agent is an IPC call. */
#ifndef CLI_DIAG_H
#define CLI_DIAG_H

#include <windows.h>

#include "cli.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_json.h"

/* WebClient service state as the SCM reports it (03 §10.5). */
typedef enum diag_wc_state {
  DIAG_WC_UNKNOWN = 0,
  DIAG_WC_RUNNING,
  DIAG_WC_STOPPED,
  DIAG_WC_DISABLED,
  DIAG_WC_MISSING
} diag_wc_state;

/* A DWORD value that is not set (or not readable). */
#define DIAG_NOT_SET 0xFFFFFFFFu

typedef struct diag_env {
  void *ctx;
  /* ---- read-only queries ---- */
  diag_wc_state (*webclient_state)(void *ctx, DWORD *start_type);   /* start_type: DIAG_NOT_SET if unknown */
  __int64 (*webdav_value)(void *ctx, int which);                   /* which: DIAG_WEBDAV_* ; -1 if absent (a DWORD
                                                                      limit can be 0xFFFFFFFF, so it is 64-bit) */
  DWORD (*linked_connections)(void *ctx);                          /* EnableLinkedConnections; DIAG_NOT_SET if absent */
  int   (*dokany_present)(void *ctx);
  int   (*split_token)(void *ctx);                                 /* 1 = administrator with a filtered token */
  int   (*elevated)(void *ctx);                                    /* 1 = the process token is elevated (cli_is_elevated) */
  int   (*time_service_running)(void *ctx);
  int   (*domain_joined)(void *ctx);
  DWORD (*drive_mask)(void *ctx);                                  /* bit n = letter 'A' + n in use */
  /* ---- changes (diag --fix only) ---- */
  DWORD (*webclient_set_start)(void *ctx, DWORD start_type);      /* Win32 error, 0 = done */
  DWORD (*webclient_start)(void *ctx);                             /* Win32 error, 0 = running */
  DWORD (*linked_set)(void *ctx, DWORD value);                     /* Win32 error, 0 = done */
} diag_env;

enum { DIAG_WEBDAV_FILE_SIZE, DIAG_WEBDAV_FILE_ATTRIBUTES, DIAG_WEBDAV_BASIC_AUTH };

/* The Win32 seam, and in test builds the fake of cli_diag_test.c (chosen by SHELLDRIVE_TEST_DIAG_FAKE). */
const diag_env *diag_env_real(void);
const diag_env *diag_env_current(void);
#ifdef SD_CLI_TEST_HOOKS
const diag_env *diag_env_fake(void);
#endif

/* Check rows, in the order of the report. */
enum {
  DIAG_ROW_OS, DIAG_ROW_AGENT, DIAG_ROW_SERVICE, DIAG_ROW_WEBCLIENT, DIAG_ROW_WEBDAV, DIAG_ROW_DOKANY,
  DIAG_ROW_LINKED, DIAG_ROW_ELEVATION, DIAG_ROW_DOMAIN, DIAG_ROW_DRIVES, DIAG_ROW_SETTINGS, DIAG_ROW_PRIVACY,
  DIAG_ROW_CLOCK, DIAG_ROW_COUNT
};
enum { DIAG_OK = 0, DIAG_WARN = 1, DIAG_PROBLEM = 2 };

typedef struct diag_report {
  int status[DIAG_ROW_COUNT];
  wchar_t text[DIAG_ROW_COUNT][256];     /* the localized value of each row (human output) */
  /* the values behind the rows (JSON output, English keys) */
  wchar_t version[32], flavour[32], local_time[32];
  int os_major, os_minor, os_build;
  char utc_offset[8];                    /* "+02:00" */
  int agent_running, service_installed, service_running;
  diag_wc_state webclient;
  DWORD webclient_start;
  __int64 size_limit, attr_limit, auth_level;   /* -1 = not set */
  int dokany, linked_on, elevated, split_token, domain_joined;
  int free_letters, settings_ok, privacy_strict, time_running;
} diag_report;

/* Runs the checks. The agent is asked over IPC without starting it. */
void diag_collect(const diag_env *env, diag_report *r);
/* 1 when at least one row is a problem. */
int diag_has_problem(const diag_report *r);
/* The checks as one JSON object: {"checks":{...},"problems":n} with English keys. */
void diag_json_result(const diag_report *r, sd_json_writer *jw);
/* The localized report on stdout. */
void diag_print_text(const diag_report *r);

/* Entry points of the three forms (cli_diag.c and cli_bundle.c). Each returns the process exit code. */
int cli_run_diag_check(const cli_args *a);
int cli_run_diag_fix(const cli_args *a);
int cli_run_diag_bundle(const cli_args *a);

/* Reads a whole file into memory: sd_alloc'd, NUL-terminated. 0 when the file cannot be read. */
int diag_read_file(const wchar_t *path, char **buf, size_t *len);

#endif /* CLI_DIAG_H */
