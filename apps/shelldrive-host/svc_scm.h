/* ShellDriveSvc registration: shelldrive service install | uninstall | start | stop (03 §1.3, §6.1, 10.3; M5).
 *
 * The rules (elevation check, order of the SCM calls, rollback) live in svc_scm.c as plain functions over a
 * function-pointer seam (svc_scm_ops). svc_scm_real_ops fills the seam with the advapi32 calls; the unit tests
 * (tests/unit/sd_svc) fill it with a fake, so they never create, start, stop or delete a real service and never
 * write the Event Log source. Only the CLI calls these functions; the service itself does not register anything. */
#ifndef SVC_SCM_H
#define SVC_SCM_H

#include <windows.h>

#define SVC_SCM_DISPLAY_NAME L"ShellDrive Service"
#define SVC_SCM_EVENT_SOURCE L"ShellDrive"
#define SVC_SCM_EVENT_TYPES 7u          /* TypesSupported: information, warning, error (10.3) */
#define SVC_SCM_RESTART_COUNT 3u

typedef struct svc_install_spec {
  wchar_t command[MAX_PATH * 2];        /* "<dir>\shelldrive-host.exe" service (quoted, the binary path) */
  wchar_t message_file[MAX_PATH];       /* "<dir>\shelldrive-host.exe": the event message file */
  wchar_t description[256];             /* localized, ChangeServiceConfig2W(SERVICE_CONFIG_DESCRIPTION) */
  DWORD restart_ms[SVC_SCM_RESTART_COUNT];   /* failure actions: restart after these delays (1.3) */
  DWORD reset_period_s;                 /* the failure count resets after this many seconds */
  int sid_unrestricted;                 /* 1 = SERVICE_SID_TYPE_UNRESTRICTED where the OS has it (Vista+) */
} svc_install_spec;

/* What svc_scm_status reports (03 §6.1, "service status"). */
enum { SVC_PATH_UNKNOWN = 0, SVC_PATH_OK, SVC_PATH_UNQUOTED, SVC_PATH_OTHER };
enum { SVC_SRC_UNKNOWN = 0, SVC_SRC_OK, SVC_SRC_MISSING, SVC_SRC_OTHER };

typedef struct svc_status_report {
  int installed;                        /* 0 when ShellDriveSvc does not exist */
  DWORD state;                          /* SERVICE_RUNNING and friends; 0 when not installed */
  DWORD start_type;                     /* SERVICE_AUTO_START and friends; 0 when not installed */
  wchar_t binary[MAX_PATH * 2];         /* the registered ImagePath, as stored */
  int binary_check;                     /* SVC_PATH_* */
  int source_check;                     /* SVC_SRC_* */
  wchar_t message_file[MAX_PATH];       /* EventMessageFile of the Event Log source, when registered */
} svc_status_report;

typedef struct svc_scm_ops {
  void *ctx;
  /* CreateServiceW: LocalSystem, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, Tcpip dependency. */
  DWORD (*create_service)(void *ctx, const svc_install_spec *s);
  DWORD (*set_description)(void *ctx, const svc_install_spec *s);
  DWORD (*set_failure_actions)(void *ctx, const svc_install_spec *s);
  DWORD (*set_sid_type)(void *ctx, DWORD sid_type);
  DWORD (*delete_service)(void *ctx);
  /* Returns after the service reports SERVICE_RUNNING (or the wait gives up). */
  DWORD (*start_service)(void *ctx);
  /* Returns after the service reports SERVICE_STOPPED (or the wait gives up). */
  DWORD (*stop_service)(void *ctx);
  DWORD (*register_source)(void *ctx, const wchar_t *source, const wchar_t *message_file, DWORD types);
  DWORD (*unregister_source)(void *ctx, const wchar_t *source);
  int (*is_elevated)(void *ctx);        /* 1 = elevated (or unknown on XP: the SCM decides) */
  int (*is_vista_or_later)(void *ctx);
  /* Read-only queries (no elevation needed). query_service fills installed, state, start_type and binary; a missing
     service is not an error (installed = 0, returns 0). query_source returns ERROR_FILE_NOT_FOUND when the source is
     not registered, else copies its EventMessageFile into message_file. */
  DWORD (*query_service)(void *ctx, svc_status_report *out);
  DWORD (*query_source)(void *ctx, const wchar_t *source, wchar_t *message_file, size_t cch);
} svc_scm_ops;

/* Fills the seam with the advapi32 calls. Returns 0. */
int svc_scm_real_ops(svc_scm_ops *out);

/* Builds the spec for this build from the directory of the running program (shelldrive.exe and shelldrive-host.exe
   are installed side by side). description is the localized text. Returns ERROR_FILE_NOT_FOUND when the host is
   missing. */
DWORD svc_scm_host_spec(svc_install_spec *s, const wchar_t *description);

/* Each returns a Win32 error code, 0 on success. Non-elevated callers get ERROR_ACCESS_DENIED before any call. */
DWORD svc_scm_install(const svc_scm_ops *ops, const svc_install_spec *s);
DWORD svc_scm_uninstall(const svc_scm_ops *ops);
DWORD svc_scm_start(const svc_scm_ops *ops);
DWORD svc_scm_stop(const svc_scm_ops *ops);

/* Reports the service and its Event Log source; needs no elevation. expect is the spec of this install
   (svc_scm_host_spec), or NULL when the host program is not next to the caller: the checks then say UNKNOWN.
   Returns a Win32 error only when a query itself fails. */
DWORD svc_scm_status(const svc_scm_ops *ops, const svc_install_spec *expect, svc_status_report *out);

/* The binary path check on its own: OK only when image equals expect->command (case-insensitive: quoted, this
   install's program, " service"); UNQUOTED when image does not start with a quote; OTHER otherwise. */
int svc_path_check_of(const wchar_t *image, const svc_install_spec *expect);

#endif /* SVC_SCM_H */
