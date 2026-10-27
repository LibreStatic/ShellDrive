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

#endif /* SVC_SCM_H */
