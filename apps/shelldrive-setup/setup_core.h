/* shelldrive-setup engine: public interface (docs/design/04 §6).
 *
 * The engine is a static library (sd_setup_core) used by the setup stub (shelldrive-setup.exe; its
 * payload-less copy is uninstall.exe) and by tests/setup. It never shows UI itself: callers pass a
 * progress callback and format messages with sd_setup_format_message(). Nothing here imports a DLL that
 * is not a KnownDLL: cabinet.dll, the Toolhelp, Win8+ and ntdll entry points are resolved at run time
 * (04 §2.4, §6.4). Strings are wide except CAB member names, which are ASCII.
 *
 * Exit codes follow the MSI conventions (04 §6.5). */
#ifndef SD_SETUP_CORE_H
#define SD_SETUP_CORE_H

#include <windows.h>
#include <stddef.h>

#include "sd_l10n/sd_l10n_catalog.h"

#define SD_SETUP_EXIT_OK          0
#define SD_SETUP_EXIT_REBOOT      3010
#define SD_SETUP_EXIT_CANCEL      1602
#define SD_SETUP_EXIT_FATAL       1603
#define SD_SETUP_EXIT_NEWER       1638
#define SD_SETUP_EXIT_BADARGS     1639

/* Build flavours the setup can choose (04 §1.1). ARM32 has its own setup program. */
typedef enum sd_setup_flavour {
  SD_SETUP_FL_NONE = 0,
  SD_SETUP_FL_X86_IA32,
  SD_SETUP_FL_X86_SSE2,
  SD_SETUP_FL_X64_XP,
  SD_SETUP_FL_X64_MODERN,
  SD_SETUP_FL_ARM64,
  SD_SETUP_FL_ARM32
} sd_setup_flavour;

const wchar_t *sd_setup_flavour_name(sd_setup_flavour f);      /* "x86-ia32", ... or NULL */
sd_setup_flavour sd_setup_flavour_parse(const wchar_t *name);  /* SD_SETUP_FL_NONE if unknown */
const wchar_t *sd_setup_payload_resource(sd_setup_flavour f);   /* "PAYLOAD_X86_IA32", ... or NULL */

typedef enum sd_setup_mode {
  SD_SETUP_MODE_AUTO = 0,        /* no mode given: per-user in this build (open item, see 04 §6.3) */
  SD_SETUP_MODE_USER,
  SD_SETUP_MODE_MACHINE,
  SD_SETUP_MODE_PORTABLE,
  SD_SETUP_MODE_UNINSTALL
} sd_setup_mode;

typedef enum sd_setup_dokany_arg {
  SD_SETUP_DOKANY_AUTO = 0,      /* /dokany=auto: the pre-checked option (D36) */
  SD_SETUP_DOKANY_INSTALL,       /* /dokany=install: also upgrade (04 §7.3) */
  SD_SETUP_DOKANY_SKIP           /* /dokany=skip: WebDAV only */
} sd_setup_dokany_arg;

/* Parsed command line. Strings are copied, so argv may go away. */
typedef struct sd_setup_args {
  sd_setup_mode mode;
  int quiet;
  int passive;
  int norestart;
  int force;
  int update;
  int help;
  int test_pages;                /* hidden: /test-pages builds the wizard pages and installs nothing (tests) */
  int autostart;                 /* -1 unset, 0 or 1 */
  int flavour_forced;
  sd_setup_flavour flavour;
  int dokany_set;
  sd_setup_dokany_arg dokany;
  int uninstall_relaunched;      /* internal: /uninstall-from-temp, the copy in %TEMP% */
  unsigned long wait_pid;        /* internal: /waitpid=<pid>, the parent uninstaller to wait for */
  wchar_t lang[16];
  wchar_t log_path[MAX_PATH];
  wchar_t portable_dir[MAX_PATH];
  wchar_t extract_dir[MAX_PATH];
  wchar_t install_dir[MAX_PATH]; /* /installdir= (internal, tests) */
  unsigned properties;           /* PROPERTY=value pairs: accepted, logged, used by the MSI path only */
} sd_setup_args;

/* 0, or SD_SETUP_EXIT_BADARGS with *bad pointing at the offending argv element. argv[0] is skipped. */
int sd_setup_parse_args(int argc, const wchar_t *const *argv, sd_setup_args *out, const wchar_t **bad);

/* Host facts for the flavour choice (04 §6.2). */
typedef struct sd_setup_host {
  WORD native_machine;           /* IMAGE_FILE_MACHINE_I386 / AMD64 / ARM64 / ARMNT; 0 = unknown */
  int sse2;                      /* IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE) */
  unsigned os_major;             /* RtlGetVersion */
  unsigned os_minor;
  int is_admin;
} sd_setup_host;

void sd_setup_detect_host(sd_setup_host *h);

/* 0 with *out set when the flavour fits the host. Otherwise 1 with *reason set to a message id; the
   message takes {flavour} when the caller also supplies the requested name. A forced override is
   refused when the host cannot run it (04 §6.2). */
int sd_setup_select_flavour(const sd_setup_host *h, sd_setup_flavour override, sd_setup_flavour *out,
                            sd_msg_id *reason);

/* Dokany decision (04 §6.3, §7.3). Per-user installs never install Dokany. */
typedef enum sd_setup_dokany_plan {
  SD_SETUP_DOKANY_SKIP_PLAN = 0,
  SD_SETUP_DOKANY_INSTALL_PLAN,
  SD_SETUP_DOKANY_UNAVAILABLE_PLAN
} sd_setup_dokany_plan;

sd_setup_dokany_plan sd_setup_dokany_decide(sd_setup_mode mode, int dokany_set, sd_setup_dokany_arg arg,
                                            unsigned os_major, unsigned os_minor);

/* Dotted numeric versions ("1.2.3.4"), compared part by part. Returns <0, 0 or >0. */
int sd_setup_version_compare(const wchar_t *a, const wchar_t *b);

/* Outcome of an operation. The message fields fill the placeholders of sd_setup_format_message(). */
typedef struct sd_setup_result {
  int exit_code;
  sd_msg_id msg;                 /* message for the user; 0 when none */
  wchar_t text[MAX_PATH * 2];    /* {flavour}, {name}, {option}, {file}, {path} or {folder} (see format) */
  wchar_t folder[MAX_PATH];      /* {folder} and the install folder */
  wchar_t version[64];           /* {version} */
  wchar_t log_path[MAX_PATH];    /* {path} of installer.log.saved */
  long code;                     /* {code} */
  unsigned count;                /* {count} of installer.summary.files */
  int warn_volume;               /* installer.warn.volume applies */
} sd_setup_result;

/* Formats the message of r (msg, text and the fields above) into buf. Returns the length or -1. */
int sd_setup_format_message(const sd_setup_result *r, sd_msg_id id, wchar_t *buf, size_t cch);

/* Progress: stage is an installer.progress.* id and folder its {folder}, or NULL. */
typedef void (*sd_setup_progress_fn)(void *ctx, sd_msg_id stage, const wchar_t *folder, unsigned percent);

/* Payload source for an install: the CAB bytes (resource or file) and an optional expected SHA-256
   (from the payload table, 04 §6.1). */
typedef struct sd_setup_payload {
  const unsigned char *data;
  size_t size;
} sd_setup_payload;

typedef struct sd_setup_cab_limits {
  unsigned long long max_member; /* bytes, per member */
  unsigned long long max_total;  /* bytes, all members */
  unsigned max_members;
} sd_setup_cab_limits;

void sd_setup_cab_limits_default(sd_setup_cab_limits *l);

/* 1 when an ASCII CAB member name is a safe relative path: no drive, no leading separator, no "..", no
   empty component, no character Windows rejects, no non-ASCII byte, not longer than MAX_PATH. */
int sd_setup_cab_name_ok(const char *name);

/* Extracts every member under dest (an existing folder). Unsafe names, oversize members or totals, and
   multi-cabinet payloads abort: returns SD_SETUP_EXIT_FATAL with r->msg set. Members written before the
   failure stay; the caller removes dest. r may be NULL. */
int sd_setup_cab_extract(const sd_setup_payload *p, const wchar_t *dest, const sd_setup_cab_limits *lim,
                         sd_setup_result *r, unsigned *files_out);

/* SHA-256 (FIPS 180-4), no dependencies: the stub cannot link sd_crypto (CNG imports). */
void sd_setup_sha256(const void *data, size_t n, unsigned char out[32]);

/* Looks up the flavour's line of the PAYLOAD_TABLE resource: "<flavour> <64 hex digits> <size>" per line.
   Returns 0 and fills sha with the expected digest, or 1 when the flavour is not listed. */
int sd_setup_payload_table_lookup(const char *table, size_t n, const wchar_t *flavour, unsigned char sha[32]);

/* Shutdown events of running agents (04 §6.9 step 1, 03 §2.1). owner_sid NULL means the current user.
   *signalled gets the number of events set. Returns 0 or SD_SETUP_EXIT_FATAL. */
int sd_setup_signal_agents(const wchar_t *owner_sid, unsigned *signalled);

/* Waits up to timeout_ms for the agents of the current user to exit (their processes), and returns the
   number still running in *still. */
int sd_setup_wait_agents(unsigned timeout_ms, unsigned *still);

/* Registration rows (packaging/registration.txt, generated into sd_setup_regtable.c). */
typedef struct sd_setup_regrow {
  const wchar_t *subkey;
  const wchar_t *name;           /* L"" = default value */
  int is_dword;
  const wchar_t *data;
  int autostart;                 /* 1 = written only when sign-in start is chosen */
} sd_setup_regrow;
extern const sd_setup_regrow sd_setup_regtable[];
extern const size_t sd_setup_regtable_count;

/* Write (remove = 0) or remove (remove = 1) the rows under HKCU or HKLM via the hive root given.
   install_dir ends with a backslash; version and flavour fill the placeholders. */
typedef struct sd_setup_regctx {
  HKEY root;
  const wchar_t *install_dir;
  const wchar_t *version;
  const wchar_t *flavour;
  unsigned long long install_bytes;
  int autostart;
} sd_setup_regctx;

int sd_setup_reg_apply(const sd_setup_regctx *c);
int sd_setup_reg_remove(const sd_setup_regctx *c);

/* Operations. Paths default when NULL: install folder = %LOCALAPPDATA%\Programs\LibreStatic\ShellDrive,
   Start menu = Programs\ShellDrive.lnk. Writes the setup log to log_path when given ("" = none). */
typedef struct sd_setup_install_opts {
  sd_setup_mode mode;            /* SD_SETUP_MODE_USER or SD_SETUP_MODE_PORTABLE */
  const wchar_t *install_dir;
  const wchar_t *portable_dir;
  const wchar_t *programs_dir;   /* test seam for the Start menu folder */
  const wchar_t *version;
  sd_setup_flavour flavour;
  const sd_setup_payload *payload;
  const unsigned char *expected_sha256;
  int autostart;
  int force;
  int update;
  int skip_shortcut;
  int skip_hooks;
  int skip_agents;               /* tests only: never signal or wait for running agents */
  const wchar_t *log_path;
  sd_setup_progress_fn progress;
  void *progress_ctx;
} sd_setup_install_opts;

int sd_setup_install(const sd_setup_install_opts *o, sd_setup_result *r);

typedef struct sd_setup_uninstall_opts {
  const wchar_t *install_dir;    /* NULL = the InstallDir value of the account registration */
  const wchar_t *programs_dir;
  int force;
  int skip_shortcut;
  int skip_hooks;
  int skip_agents;               /* tests only: never signal or wait for running agents */
  const wchar_t *log_path;
  sd_setup_progress_fn progress;
  void *progress_ctx;
} sd_setup_uninstall_opts;

int sd_setup_uninstall(const sd_setup_uninstall_opts *o, sd_setup_result *r);

/* Log file (04 §13): English lines, UTF-8. */
int sd_setup_log_open(const wchar_t *path);
void sd_setup_log(const char *event, const wchar_t *text);
void sd_setup_log_close(void);
const wchar_t *sd_setup_log_path(void);

/* Start menu shortcut (IShellLinkW, 04 §6.7). */
int sd_setup_shortcut_create(const wchar_t *lnk, const wchar_t *target, const wchar_t *workdir,
                             const wchar_t *description, const wchar_t *icon);

/* Current account SID as a string, for the shutdown event name. Returns 0 on success. */
int sd_setup_current_sid(wchar_t *out, size_t cch);

/* InstallDir of the account registration (no trailing backslash). Returns 0 when registered. */
int sd_setup_registered_install_dir(wchar_t *out, size_t cch);

#endif /* SD_SETUP_CORE_H */
