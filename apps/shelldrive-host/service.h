/* shelldrive-host service mode: ShellDriveSvc (03 §1.3, §2.2, §2.6; D6, D17, D35).
 *
 * svc_run is the one service core. It runs the same code under the Service Control Manager (svc_dispatch) and in
 * the console (svc_console_run, `shelldrive-host.exe service-debug`), and it is what the in-process tests call with a
 * fake mount backend (tests/unit/sd_svc). Only one core runs per process. */
#ifndef SERVICE_H
#define SERVICE_H

#include <windows.h>

#include "sd_mount/sd_mount.h"
#include "svc_folder.h"
#include "svc_repair.h"
#include "svc_scm.h"

#define SVC_SERVICE_NAME L"ShellDriveSvc"

/* Event Log sink (10.3): msg_id is an id of svc_events.mc, args are its %1..%n inserts. */
typedef void (*svc_event_fn)(void *ctx, DWORD msg_id, const wchar_t **args, size_t nargs);

/* proxy = system of a service profile (M5, 2.6 rule 1, 3.8). read: the WinHTTP machine configuration for host:port;
   kind is the SD_PROXY_* value (0 direct, 1 HTTP, 2 SOCKS5), the proxy in host_out / port_out. allow: the machine
   policy AllowSystemProxy; 0 refuses the leg with usage. Shipping: allow 0 (this build reads no policy yet, as the
   per-user path) and the real sd_ssh_proxy_machine. Tests pass a stub and set allow. */
typedef sd_err (*svc_sysproxy_read_fn)(void *ctx, const wchar_t *host, uint16_t port, int *kind, wchar_t host_out[256],
                                       uint16_t *port_out);
typedef struct svc_sysproxy_ops {
  int allow;
  svc_sysproxy_read_fn read;
  void *ctx;
} svc_sysproxy_ops;

typedef struct svc_opts {
  const sd_mount_backend *backend;   /* NULL = host_backend() (the real modules or the unavailable stub) */
  const wchar_t *machine_root;       /* NULL = %ProgramData%\LibreStatic\ShellDrive (tests: a temp folder) */
  const wchar_t *secret_dir;         /* NULL = <machine root>\service (tests: a temp folder) */
  int open_log;                      /* 1 = <machine root>\logs\service.log */
  void (*on_running)(void *ctx);     /* called once the control pipe listens (SCM: SERVICE_RUNNING) */
  void *ctx;
  svc_event_fn event;                /* NULL = no Event Log writes (console mode, tests); SCM: svc_eventlog_write */
  void *event_ctx;
  svc_owner_fn owner_trusted;        /* NULL = the shipping owner rule (3.2): SYSTEM or Administrators; tests replace it */
  int test_all_admin;                /* SD_SVC_TEST_HOOKS builds only: every client counts as an elevated admin */
  /* SD_SVC_TEST_HOOKS builds only (ignored by the shipping build): an SDDL ACE appended to every machine DACL the start
     sets or checks, e.g. "(A;OICI;FA;;;OW)". A non-elevated test process is only the owner of the folders it made, and
     the owner needs the rights BUILTIN\Administrators has; the same seam as svc_repair_ops.extra_ace. NULL = none. */
  const wchar_t *dacl_extra_ace;
  /* Seams of service.status and service.repair_data (03 §2.4). scm_ops: the Service Control Manager queries of
     svc_scm_status; NULL = the real SCM (SD_SVC_TEST_HOOKS builds never reach it: NULL there reports "not installed").
     repair_ops / repair_base: the owner rule and the base folder of svc_repair_data; NULL = the shipping rule and
     %ProgramData% (SD_SVC_TEST_HOOKS builds refuse the method when repair_base is NULL, so a test never touches the real
     machine folder). The pointers must stay valid for the life of svc_run. */
  const svc_scm_ops *scm_ops;
  const svc_repair_ops *repair_ops;
  const wchar_t *repair_base;
  /* proxy = system seams of service profiles (svc_sysproxy_ops above). NULL = refused (allow 0) with the real read. */
  const svc_sysproxy_ops *sysproxy_ops;
} svc_opts;

/* Blocks until svc_request_stop (or a stop control). Returns 0, or 1 when the core cannot start (no pipe, no folder
   rights). Every mount is unmounted (forced) before it returns. */
int  svc_run(const svc_opts *o);
/* Any thread. Safe to call when no core runs. */
void svc_request_stop(void);
/* Service entry: StartServiceCtrlDispatcherW. Returns the service exit code, or 1 when the process was not started by
   the SCM (the message says so, localized in the svc domain). */
int  svc_dispatch(void);
/* Console mode for `shelldrive-host.exe service-debug`: the same core, Ctrl+C stops it. */
int  svc_console_run(void);

#ifdef SD_SVC_TEST_HOOKS
/* SD_SVC_TEST_HOOKS builds only. forced = 0 reads the UpdateHostKeys policy from the registry (default); forced = 1 uses
   value (2 = accept proven keys, 1 = ask, 0 = never) for every announcement from now on. */
void svc_test_hk_policy(int forced, DWORD value);
/* SD_SVC_TEST_HOOKS builds only. on = 1: every new pipe connection counts as an elevated administrator at connect (the
   class of the reserved-instance rule, 2.2); the token class is used again when on = 0. Tests of the reserved instances
   use it for their raw instances, which an unelevated test process could not hold otherwise. */
void svc_test_connect_admin(int on);
#endif

#endif /* SERVICE_H */
