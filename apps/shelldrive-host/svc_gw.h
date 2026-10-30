/* Global WebDAV mechanism choice for service profiles (02 §7.7, 03 §1.3; D11, TM-R19).
 *
 * Pure logic, no Win32 calls: the caller reads the OS version, the settings and the service and WebClient state,
 * then asks svc_gw_decide. tests/unit/sd_svc drives the table without a service, an SCM or a second session.
 *
 *   system  the service maps the drive as LocalSystem (02 §7.7 mechanism A)
 *   link    the service defines a global DOS device on the UNC (mechanism B)
 *   attach  no drive before logon; each user's agent maps the UNC in its own logon session (02 §7.7 fallback)
 *   refuse  the mount fails with the IPC code of svc_gw_reason_code
 *
 * A mechanism is chosen only when its cell in the table is GO for the OS family. UNVERIFIED and NOGO cells are never
 * chosen; an explicit system or link request for such a cell is refused, it does not degrade to attach. Token-only
 * mode is refused for every global mount (TM-R19), whatever the table says. */
#ifndef SVC_GW_H
#define SVC_GW_H

#include <windows.h>

/* OS families of the M5 lab matrix (02 §7.7). Windows 8 (6.2) and 8.1 (6.3) share one column. Unknown covers
   Windows 2000 and older, Windows 10 preview builds reporting 6.4, and anything not listed. */
typedef enum svc_gw_family {
  SVC_GW_OS_UNKNOWN = 0,
  SVC_GW_OS_XP_2003,       /* 5.1 (XP), 5.2 (Server 2003, XP x64) */
  SVC_GW_OS_VISTA_7,       /* 6.0 (Vista), 6.1 (7, Server 2008 R2) */
  SVC_GW_OS_8_81,          /* 6.2 (8, Server 2012), 6.3 (8.1, Server 2012 R2) */
  SVC_GW_OS_10_11,         /* 10.0 (10, 11, Server 2016+) */
  SVC_GW_OS_COUNT
} svc_gw_family;

/* settings.ini [service] webdav_global_mode, parsed. INVALID is refused (usage). */
typedef enum svc_gw_mode {
  SVC_GW_MODE_INVALID = -1,
  SVC_GW_MODE_AUTO = 0,
  SVC_GW_MODE_SYSTEM,
  SVC_GW_MODE_LINK,
  SVC_GW_MODE_ATTACH
} svc_gw_mode;

/* Lab result of one mechanism on one OS family. Only GO is ever used. */
typedef enum svc_gw_status {
  SVC_GW_UNVERIFIED = 0,   /* not proven here (the spike could not run the lab criteria G1-G7) */
  SVC_GW_GO,               /* G1-G5 and G7 passed for this OS (02 §7.7) */
  SVC_GW_NOGO             /* a criterion failed in the lab */
} svc_gw_status;

/* WebClient service state, as the read-only SCM query reports it (sd_webdav_client_state, without the header). */
typedef enum svc_gw_client {
  SVC_GW_CLIENT_UNKNOWN = 0,
  SVC_GW_CLIENT_RUNNING,
  SVC_GW_CLIENT_STOPPED,
  SVC_GW_CLIENT_DISABLED,
  SVC_GW_CLIENT_MISSING
} svc_gw_client;

typedef enum svc_gw_mech {
  SVC_GW_REFUSE = 0,
  SVC_GW_SYSTEM,
  SVC_GW_LINK,
  SVC_GW_ATTACH
} svc_gw_mech;

typedef enum svc_gw_reason {
  SVC_GW_R_OK = 0,
  SVC_GW_R_TOKEN_ONLY,          /* TM-R19: never for a global mount */
  SVC_GW_R_MODE,                /* webdav_global_mode is not one of the four names */
  SVC_GW_R_SERVICE_DOWN,        /* the service core does not hold the pipe */
  SVC_GW_R_OS,                  /* OS family unknown */
  SVC_GW_R_CLIENT_MISSING,      /* WebClient not installed (Server: WebDAV-Redirector / Desktop Experience) */
  SVC_GW_R_CLIENT_DISABLED,     /* WebClient start type disabled (needs an administrator) */
  SVC_GW_R_CLIENT_UNKNOWN,      /* the SCM could not be queried */
  SVC_GW_R_NOT_VERIFIED_SYSTEM, /* system requested, its cell is not GO */
  SVC_GW_R_NOT_VERIFIED_LINK    /* link requested, its cell is not GO */
} svc_gw_reason;

/* Per OS family, the status of each mechanism. */
typedef struct svc_gw_table {
  svc_gw_status system[SVC_GW_OS_COUNT];
  svc_gw_status link[SVC_GW_OS_COUNT];
} svc_gw_table;

typedef struct svc_gw_input {
  svc_gw_family family;
  svc_gw_mode mode;
  int service_running;          /* nonzero when the service core holds its pipe */
  svc_gw_client client;
  int token_only;               /* the mount asks for token-only mode */
} svc_gw_input;

typedef struct svc_gw_verdict {
  svc_gw_mech mech;
  svc_gw_reason reason;
} svc_gw_verdict;

/* OS family from the major and minor version (RtlGetVersion or the manifest-independent sources). */
svc_gw_family svc_gw_family_of(DWORD major, DWORD minor);
/* "auto", "system", "link", "attach" (exact, lower case, as in settings.ini). Anything else: SVC_GW_MODE_INVALID. */
svc_gw_mode svc_gw_mode_parse(const char *s);

const char *svc_gw_family_name(svc_gw_family f);
const char *svc_gw_mode_name(svc_gw_mode m);
const char *svc_gw_mech_name(svc_gw_mech m);
/* English reason for the log (not localized: logs stay English). */
const char *svc_gw_reason_name(svc_gw_reason r);
/* IPC error code for a refusal (03 §2.4 vocabulary); "" for SVC_GW_R_OK. */
const char *svc_gw_reason_code(svc_gw_reason r);

/* The compiled table: every cell UNVERIFIED (see the notes in svc_gw.c). */
const svc_gw_table *svc_gw_compiled_table(void);

void svc_gw_decide_with(const svc_gw_table *t, const svc_gw_input *in, svc_gw_verdict *out);
void svc_gw_decide(const svc_gw_input *in, svc_gw_verdict *out);

#endif /* SVC_GW_H */
