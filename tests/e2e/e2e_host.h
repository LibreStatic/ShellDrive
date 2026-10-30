/* End-to-end host of the tests/e2e driver: the service core in this process, and the CLI as a child process.
 * See e2e_host.c. */
#ifndef SD_E2E_HOST_H
#define SD_E2E_HOST_H

#include <windows.h>
#include <stddef.h>

/* Profile ids of the fixture (the names are "mounted" and "hkfirst"). */
#define E2E_PROFILE_MOUNTED "mounted"
#define E2E_HOST_FIRST      "hk.first.test"
#define E2E_PROXY_SPEC      "http://px@proxy.example:3128"

/* Starts the service core once (a thread of this process) on the per-run pipe name. Returns 1 when it listens. */
int e2e_core_start(void);
/* Stops the core and waits for it. Safe when it never started. */
int e2e_core_stop(void);

/* The CLI as a child process: args (the command line after the executable), the value of SHELLDRIVE_TEST_ELEVATED
   ("0", "1" or NULL = not set), SHELLDRIVE_TEST_SCM ("running", "absent" or NULL = not set), and the bytes written to its
   standard input (NULL = empty input, closed at once). Output (stdout and stderr together) is kept, NUL terminated. */
typedef struct e2e_cli_result {
  DWORD exit_code;
  char out[8192];
} e2e_cli_result;

int e2e_run_cli(const wchar_t *args, const wchar_t *elevated, const wchar_t *scm, const char *input,
                e2e_cli_result *r);

/* Number of machine-store writes of the fake backend, and the secret store read by the service (in-process). */
unsigned long e2e_machine_writes(void);
int e2e_secret_proxy_get(const char *user, char *out, size_t cap, int *found);

/* The text of an id field ("id":"...") in a JSON output, copied into id; 0 when there is none. */
int e2e_json_id(const char *out, char *id, size_t cap);

#endif /* SD_E2E_HOST_H */
