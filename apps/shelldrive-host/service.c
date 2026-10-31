/* shelldrive-host service mode (03 §1.3, §2.2, §2.6, §3.2, §3.4.1, §4.5; D6, D17, D35; TM-R24..R27).
 *
 * Owns global mounts only: machine profiles with scope = service. The control thread is the caller of svc_run (the SCM
 * main thread or the console thread). sd_mount create/start/stop/destroy run only there; the pipe thread (IPC handlers)
 * touches the tables under g.lock and hands work to the control thread through a queue, like the agent does.
 *
 * Methods (2.4): list and status (filtered, 2.2), selftest and hello are open to every client; mount, unmount,
 * secret.set, secret.delete, config.reload, prompt.list and prompt.answer need an elevated administrator. Topics prompt,
 * log and hostkeys are refused to non-admins (topic gate). A service prompt is shown only to an elevated administrator
 * that subscribed to `prompt`; without one the mount fails with prompt_unavailable (2.6 rule 3).
 *
 * Host keys of the machine store (M5, 03 §2.6 rule 2, §5.6, §6.1): hostkey.add connects a hostkey mount with a machine
 * profile's own service credentials (no prompt is answered: the connection is refused every prompt except the
 * host-key question, which sd_mount takes itself), keeps the offered keys as announcements, and
 * hostkey.announced.accept writes them to the machine known_hosts after svc_store_check. Mount announcements (UpdateHostKeys
 * ask) are kept the same way and raise Event 2300. */
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "host.h"
#include "service.h"
#include "svc_access.h"
#include "svc_events.h"
#include "svc_gw.h"
#include "svc_repair.h"
#include "svc_scm.h"
#include "svc_status.h"
#include "sd/version.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_config/sd_ini.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_svc_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_policy/sd_policy.h"
#include "sd_secret/sd_secret.h"
#include "sd_ssh/sd_ssh.h"

/* Service control values that older SDK headers may not define (the XP flavour builds against 7.1A). */
#ifndef SERVICE_CONTROL_PRESHUTDOWN
#define SERVICE_CONTROL_PRESHUTDOWN 0x0000000F
#endif
#ifndef SERVICE_ACCEPT_PRESHUTDOWN
#define SERVICE_ACCEPT_PRESHUTDOWN 0x00000100
#endif
#ifndef SERVICE_ACCEPT_POWEREVENT
#define SERVICE_ACCEPT_POWEREVENT 0x00000040
#endif
#ifndef SERVICE_ACCEPT_SESSIONCHANGE
#define SERVICE_ACCEPT_SESSIONCHANGE 0x00000080
#endif

#define SVC_MAX_PROFILES 64
#define SVC_MAX_MOUNTS   32
#define SVC_MAX_PROMPTS  16
#define SVC_PROMPT_MS    120000u          /* 2.5: user-initiated operations; the service has no reconnect prompts */
#define SVC_MAX_MESSAGE_NONADMIN 65536u   /* 2.2, TM-R25: request cap of clients that are not elevated admins (admins: 1 MiB) */
#define SVC_RESERVED_ADMIN_INSTANCES 2u   /* 2.2, TM-R25: of the 32 pipe instances, these are kept for elevated admins */
#define SVC_IDLE_MS      60000u           /* 2.2: idle timeout of a non-subscribed client */
#define SVC_HELLO_MS      5000u           /* 2.2 (not given in 03 §2.2): a non-admin must send hello within 5 s of connecting */
#define SVC_SHUTDOWN_MS  15000u
#define SVC_MAX_HK        2u              /* hostkey.add connections at once (each holds one sd_ssh connection) */
#define SVC_MAX_ANNOUNCE  32u             /* kept announcements (hostkey.announced.list); the oldest goes when full */

/* ---- records ---- */

typedef struct svc_prof {
  sd_profile p;
  svc_acl acl;
} svc_prof;

typedef struct svc_prompt {
  int used;
  uint32_t id;                      /* "p-<id>" on the wire */
  struct svc_mount *mount;
  uint32_t mprompt;                 /* sd_mount prompt id */
  uint64_t deadline;
  int kind;
  char mount_id[16];
  char profile_id[33];
  char host[256];
  uint16_t port;
  char user[128];
  int is_reconnect, can_save;
} svc_prompt;

typedef struct svc_mount {
  char id[16];                      /* "g-<n>" */
  wchar_t letter;
  svc_prof *prof;                   /* the profile as it was when mounted */
  sd_mount *m;                      /* control thread only (NULL before create and after destroy) */
  sd_mount_state st;
  int stop_req, final, prompt_refused, started;
  const char *refuse_code;          /* IPC code of the refused prompt (prompt_unavailable, host_key_unknown) */
  char err_code[64];
  char err_detail[160];
  /* 02 §7.7 attach: the hosted WebDAV export, filled on MOUNTED, empty for a Dokany mount */
  uint16_t wd_port;
  wchar_t wd_remote[104], wd_remote_xp[104];
} svc_mount;

typedef struct svc_job {
  char id[16];
  int force;
} svc_job;

/* A host key kept for review: an UpdateHostKeys announcement of a global mount (mount_id set) or the keys of a
   hostkey.add offer (mount_id ""). hostkey.announced.accept writes it to the machine store (5.6). */
typedef struct svc_ann {
  struct svc_ann *next;
  char id[16];                      /* "a-<n>" on the wire */
  char mount_id[16];
  sd_mount_announcement a;
} svc_ann;

/* One hostkey.add request: a connect-only hostkey mount on the control thread. The reply is deferred (sd_ipc_defer) and
   sent once, when the mount is final (svc_hk_reply); the record is released by svc_tick after that. */
typedef struct svc_hk {
  struct svc_hk *next;
  sd_mount *m;                      /* control thread only; NULL when the mount was never created */
  svc_prof *prof;                   /* a copy of the machine profile (control thread only) */
  uint64_t defer_cid;
  int64_t defer_rid;
  int replied;                      /* control thread only: the reply is sent, the record can be released */
  char host[256];
  uint16_t port;
  char lookup[300];
  char type[64];
  char expect[96];
} svc_hk;

typedef struct svc_work {
  struct svc_work *next;
  void (*fn)(void *arg);
  void *arg;
} svc_work;

static struct svc_state {
  sd_mutex lock;                    /* tables, queue, prompt slots; never held across a sd_mount call */
  sd_mutex reap;                    /* serializes sd_mount_destroy with sd_mount_answer (both may be on other threads) */
  sd_event wake, stop;
  sd_ipc_server *srv;
  const sd_mount_backend *be;
  wchar_t root[MAX_PATH], profiles[MAX_PATH], service_dir[MAX_PATH], kh[MAX_PATH], logfile[MAX_PATH];
  wchar_t vendor[MAX_PATH];         /* %ProgramData%\LibreStatic, default location only (D45, 3.2) */
  svc_owner_fn owner_trusted;       /* NULL = the shipping owner rule (3.2); tests replace it */
  const wchar_t *dacl_extra;        /* SD_SVC_TEST_HOOKS only: an ACE appended to every machine DACL (svc_opts) */
  int idle;                        /* layout refused (owner, reparse point, no rights): nothing is loaded */
  svc_folder_reason refused_why;    /* why the layout was refused (idle), SVC_FOLDER_OK otherwise */
  wchar_t refused_path[MAX_PATH];   /* the first refused folder (idle), empty otherwise */
  int open_log;                     /* svc_opts.open_log: the repair closes and reopens the log around the move */
  int repairing;                    /* a service.repair_data runs: a second one is busy */
  const svc_scm_ops *scm_ops;       /* svc_opts seams of service.status and service.repair_data */
  const svc_repair_ops *repair_ops;
  const svc_sysproxy_ops *sysproxy; /* proxy = system seams (svc_opts.sysproxy_ops); the shipping ops refuse by policy */
  const wchar_t *repair_base;
  int running, stopping;
  int test_all_admin;               /* SD_SVC_TEST_HOOKS only, see caller_is_admin */
#ifdef SD_SVC_TEST_HOOKS
  int test_hk_policy_forced;        /* SD_SVC_TEST_HOOKS only: svc_test_hk_policy replaces the registry value */
  DWORD test_hk_policy;
  int test_connect_admin;           /* SD_SVC_TEST_HOOKS only: every new connection counts as admin at connect */
  int test_admin_any;               /* SD_SVC_TEST_HOOKS only: every client, whatever its hello kind, is an admin for the methods */
  int test_sysproxy_forced;         /* SD_SVC_TEST_HOOKS only: svc_test_sysproxy_policy replaces the machine policies */
  DWORD test_sysproxy_allow, test_sysproxy_sspi;
#endif
  svc_event_fn event;               /* Event Log sink (10.3), NULL = none */
  void *event_ctx;
  svc_prof *profs[SVC_MAX_PROFILES];
  uint32_t nprofs;
  svc_mount *mounts[SVC_MAX_MOUNTS];
  uint32_t next_mount, next_prompt;
  svc_prompt prompts[SVC_MAX_PROMPTS];
  svc_ann *anns;                    /* kept host keys (g.lock); nann counts them */
  uint32_t nann, next_ann;
  svc_hk *hks;                      /* hostkey.add requests in flight (g.lock); nhk counts them */
  uint32_t nhk;
  svc_work *qh, *qt;
  svc_refuse_entry refuse[SVC_REFUSE_SLOTS];   /* Event 3101 throttle; written on the pipe thread only */
} g;

/* Admin check of the callers. SD_SVC_TEST_HOOKS builds (tests/unit/sd_svc) may treat a "testadmin" client as an elevated
   administrator so that the admin methods are exercised without an elevated test process; the restricted-token client
   still hits the real check. Shipping builds never compile the override. */
static int caller_is_admin(sd_ipc_client *c)
{
#ifdef SD_SVC_TEST_HOOKS
  if (g.test_all_admin && strcmp(sd_ipc_client_kind(c), "testadmin") == 0)
    return 1;
  if (g.test_admin_any)
    return 1;
#endif
  return sd_ipc_client_is_admin(c) ? 1 : 0;
}

/* ---- small helpers ---- */

static void svc_log_info(const char *fmt, ...);

static void wide_from_utf8(const char *s, wchar_t *out, size_t cch)
{
  if (cch == 0) return;
  out[0] = 0;
  if (s && s[0])
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cch);
  out[cch - 1] = 0;
}

static void utf8_from_wide(const wchar_t *w, char *out, size_t cch)
{
  if (cch == 0) return;
  out[0] = 0;
  if (w && w[0])
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cch, NULL, NULL);
  out[cch - 1] = 0;
}

static uint64_t svc_now(void) { return sd_tick_ms(); }

static void target_of(wchar_t letter, char out[4])
{
  out[0] = (char)letter;
  out[1] = ':';
  out[2] = 0;
}

static void say(sd_msg_id id)
{
  wchar_t *s = sd_l10n_format_alloc(id, NULL, 0);
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  if (s == NULL)
    return;
  if (h != NULL && h != INVALID_HANDLE_VALUE) {
    DWORD n = 0;
    if (GetConsoleMode(h, &n)) {
      WriteConsoleW(h, s, (DWORD)wcslen(s), &n, NULL);
      WriteConsoleW(h, L"\r\n", 2, &n, NULL);
    } else {
      char buf[1024];
      int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, buf, (int)sizeof(buf), NULL, NULL);
      if (len > 1)
        WriteFile(h, buf, (DWORD)(len - 1), &n, NULL);
      WriteFile(h, "\r\n", 2, &n, NULL);
    }
  }
  sd_free(s);
}

static void svc_log_info(const char *fmt, ...)
{
  char line[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, ap);
  va_end(ap);
  SD_LOGI("svc", "%s", line);
}

/* ---- work queue (the control thread runs it) ---- */

/* Appends a job for the control thread; g.lock held (svc_mount_queue detaches a failed record and queues its
   release in one critical section, so a concurrent mount of the same profile cannot slip in between). */
static void svc_enqueue_locked(void (*fn)(void *), void *arg)
{
  svc_work *w = (svc_work *)sd_alloc(sizeof(*w));
  if (w == NULL)
    return;
  w->next = NULL;
  w->fn = fn;
  w->arg = arg;
  if (g.qt) g.qt->next = w; else g.qh = w;
  g.qt = w;
  SetEvent(g.wake.h);
}

static void svc_enqueue(void (*fn)(void *), void *arg)
{
  sd_mutex_lock(&g.lock);
  svc_enqueue_locked(fn, arg);
  sd_mutex_unlock(&g.lock);
}

static void svc_post(void *ctx, void (*fn)(void *), void *arg)
{
  (void)ctx;
  svc_enqueue(fn, arg);
}

static void svc_drain(void)
{
  for (;;) {
    svc_work *w;
    sd_mutex_lock(&g.lock);
    w = g.qh;
    if (w) {
      g.qh = w->next;
      if (g.qh == NULL) g.qt = NULL;
    }
    sd_mutex_unlock(&g.lock);
    if (w == NULL)
      break;
    w->fn(w->arg);
    sd_free(w);
  }
}

/* ---- machine layout (3.2) ---- */

static sd_err svc_compute_paths(const wchar_t *override_root)
{
  if (override_root && override_root[0]) {
    wcsncpy_s(g.root, MAX_PATH, override_root, _TRUNCATE);
  } else {
    wchar_t base[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base) != S_OK)
      return SD_E_FAILURE;
    _snwprintf_s(g.root, MAX_PATH, _TRUNCATE, L"%s\\LibreStatic\\ShellDrive", base);
    _snwprintf_s(g.vendor, MAX_PATH, _TRUNCATE, L"%s\\LibreStatic", base);
  }
  _snwprintf_s(g.profiles, MAX_PATH, _TRUNCATE, L"%s\\profiles", g.root);
  _snwprintf_s(g.service_dir, MAX_PATH, _TRUNCATE, L"%s\\service", g.root);
  _snwprintf_s(g.kh, MAX_PATH, _TRUNCATE, L"%s\\known_hosts", g.root);
  _snwprintf_s(g.logfile, MAX_PATH, _TRUNCATE, L"%s\\logs\\service.log", g.root);
  return SD_OK;
}

/* The 3.2 DACLs of the machine folders (SDDL with inheritance), set when a folder is created and re-applied at start
   when it is wrong (svc_check_existing). */
static const wchar_t k_svc_dacl_admin_read[] = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";
static const wchar_t k_svc_dacl_admin[] = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
static const wchar_t k_svc_dacl_system[] = L"D:PAI(A;OICI;FA;;;SY)";

/* The first machine folder refused at start (3.2, TM-R34) and why: Event 3102 names both. */
typedef struct svc_refusal {
  wchar_t path[MAX_PATH];
  svc_folder_reason why;
} svc_refusal;

static void svc_refuse(svc_refusal *w, const wchar_t *path, svc_folder_reason why)
{
  if (w == NULL)
    return;
  _snwprintf_s(w->path, MAX_PATH, _TRUNCATE, L"%s", path);
  w->why = why;
}

/* The DACL text of a machine folder: the 3.2 SDDL, plus the test seam's extra ACE (SD_SVC_TEST_HOOKS builds only; the
   shipping build has no extra ACE). */
static void svc_dacl_text(const wchar_t *sddl, wchar_t *out, size_t cch)
{
  _snwprintf_s(out, cch, _TRUNCATE, L"%s%s", sddl, g.dacl_extra != NULL ? g.dacl_extra : L"");
}

/* An existing machine folder is used only when it is a folder, not a reparse point, and its owner is trusted (3.2).
   A refused folder is never fixed here: repair-data does that. Every check runs on a handle that does not follow links. */
static sd_err svc_check_existing(const wchar_t *path, const wchar_t *sddl, svc_refusal *w)
{
  HANDLE h = NULL;
  svc_folder_reason why = SVC_FOLDER_NO_RIGHTS;
  wchar_t dtext[512];
  DWORD e = svc_folder_open(path, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, &h);
  if (e != 0)   /* WRITE_DAC is only needed when the DACL is wrong: the checks themselves need READ_CONTROL */
    e = svc_folder_open(path, READ_CONTROL | FILE_READ_ATTRIBUTES, &h);
  if (e == 0) {
    int changed = 0;
    e = svc_folder_inspect(h, 1, g.owner_trusted, NULL, &why);
    if (e != 0) {
      why = SVC_FOLDER_NO_RIGHTS;
    } else if (why == SVC_FOLDER_OK) {
      /* 3.2: the start re-applies the machine DACL of a trusted folder when it is wrong (repair-data is still the way
         to fix an untrusted one) */
      svc_dacl_text(sddl, dtext, SD_COUNTOF(dtext));
      if (svc_folder_apply_dacl(h, dtext, &changed) != 0)
        why = SVC_FOLDER_ACL;
      else if (changed)
        SD_LOGI("svc", "the 3.2 DACL of a machine folder was re-applied at start");
    }
    CloseHandle(h);
  }
  if (why != SVC_FOLDER_OK) {
    svc_refuse(w, path, why);
    return SD_E_ACCESS_DENIED;
  }
  return SD_OK;
}

/* Creates one folder with its 3.2 DACL when it is missing. An existing folder is checked (svc_check_existing); a folder
   that cannot be created refuses the layout. */
static sd_err svc_mkdir(const wchar_t *path, const wchar_t *sddl, svc_refusal *w)
{
  HANDLE h = NULL;
  DWORD e = svc_folder_open(path, FILE_READ_ATTRIBUTES, &h);
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  wchar_t dtext[512];
  if (e == 0) {
    CloseHandle(h);
    return svc_check_existing(path, sddl, w);
  }
  if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
    svc_refuse(w, path, SVC_FOLDER_NO_RIGHTS);
    return SD_E_ACCESS_DENIED;
  }
  svc_dacl_text(sddl, dtext, SD_COUNTOF(dtext));
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dtext, SDDL_REVISION_1, &sd, NULL)) {
    svc_refuse(w, path, SVC_FOLDER_NO_RIGHTS);
    return SD_E_INTERNAL;
  }
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  if (!CreateDirectoryW(path, &sa)) {
    e = GetLastError();
    LocalFree(sd);
    if (e == ERROR_ALREADY_EXISTS)
      return svc_check_existing(path, sddl, w);
    svc_refuse(w, path, SVC_FOLDER_NO_RIGHTS);
    return SD_E_ACCESS_DENIED;
  }
  LocalFree(sd);
  return SD_OK;
}

/* The vendor folder (D45), only for the default location (the tests create their own root). It is checked like the
   rest of the tree; when it is missing nothing is created here (the data folder is created below it by svc_mkdir). */
static sd_err svc_check_vendor(svc_refusal *w)
{
  HANDLE h = NULL;
  DWORD e;
  if (g.vendor[0] == 0)
    return SD_OK;
  e = svc_folder_open(g.vendor, FILE_READ_ATTRIBUTES, &h);
  if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
    return SD_OK;
  if (e == 0)
    CloseHandle(h);
  return svc_check_existing(g.vendor, k_svc_dacl_admin_read, w);
}

static sd_err svc_ensure_layout(svc_refusal *w)
{
  wchar_t path[MAX_PATH];
  sd_err e;
  if ((e = svc_check_vendor(w)) != SD_OK) return e;
  if ((e = svc_mkdir(g.root, k_svc_dacl_admin_read, w)) != SD_OK) return e;
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\logs", g.root);
  if ((e = svc_mkdir(path, k_svc_dacl_admin, w)) != SD_OK) return e;
  if ((e = svc_mkdir(g.profiles, k_svc_dacl_admin_read, w)) != SD_OK) return e;
  if ((e = svc_mkdir(g.service_dir, k_svc_dacl_admin, w)) != SD_OK) return e;
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\secrets", g.service_dir);
  if ((e = svc_mkdir(path, k_svc_dacl_system, w)) != SD_OK) return e;
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\keys", g.service_dir);
  return svc_mkdir(path, k_svc_dacl_system, w);
}

/* ---- profiles ---- */

/* Resolves one service_access entry (an account name) to a SID string. */
typedef BOOL (WINAPI *pfn_LookupAccountNameW)(LPCWSTR system, LPCWSTR account, PSID sid, LPDWORD cb_sid,
                                              LPWSTR domain, LPDWORD cch_domain, PSID_NAME_USE use);

/* LookupAccountNameW is resolved at run time: it is not on the static floor list (tests/os-imports) */
static int svc_resolve_entry(void *ctx, const char *entry, char *sid_out, size_t cap)
{
  static pfn_LookupAccountNameW lookup;
  wchar_t wname[256], wdom[256], *wstr = NULL;
  BYTE sidbuf[256];
  PSID sid = (PSID)sidbuf;
  DWORD slen = sizeof(sidbuf), dlen = 256;
  SID_NAME_USE use;
  (void)ctx;
  if (lookup == NULL)
    lookup = (pfn_LookupAccountNameW)sd_platform_resolve_by_name(L"advapi32.dll", "LookupAccountNameW");
  if (lookup == NULL)
    return 0;
  wide_from_utf8(entry, wname, SD_COUNTOF(wname));
  if (!lookup(NULL, wname, sid, &slen, wdom, &dlen, &use))
    return 0;
  if (!ConvertSidToStringSidW(sid, &wstr))
    return 0;
  utf8_from_wide(wstr, sid_out, cap);
  LocalFree(wstr);
  return 1;
}

/* A SID from its string form (UTF-8 in the resolved lists); LocalFree when done. */
static PSID sid_of(const char *s)
{
  wchar_t w[SVC_SID_MAX];
  PSID sid = NULL;
  wide_from_utf8(s, w, SD_COUNTOF(w));
  if (!ConvertStringSidToSidW(w, &sid))
    return NULL;
  return sid;
}

static void svc_free_profiles_locked(void)
{
  uint32_t i;
  for (i = 0; i < g.nprofs; i++) {
    sd_free(g.profs[i]);
    g.profs[i] = NULL;
  }
  g.nprofs = 0;
}

/* A machine profile is read through a checked handle (2.6 rule 1, TM-R27): every folder from the machine root to the file
   and the file itself are checked (reparse point, owner, DACL) by svc_file_read_trusted, and only then parsed. A refused
   or unreadable file is not loaded; the other profiles still load. */
static sd_err svc_profile_read(const wchar_t *path, sd_profile *p, const char **bad)
{
  unsigned char *buf = NULL;
  DWORD len = 0, e;
  svc_folder_reason why = SVC_FOLDER_OK;
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  sd_err r;
  e = svc_file_read_trusted(g.root, path, g.owner_trusted, NULL, &buf, &len, &why);
  if (e != 0) {
    *bad = "unreadable";
    return SD_E_NOT_FOUND;
  }
  if (why != SVC_FOLDER_OK) {
    *bad = "refused: owner, reparse point, not a plain file or a writable ACL (TM-R27)";
    return SD_E_ACCESS_DENIED;
  }
  r = sd_ini_parse((const char *)buf, len, &ini, &flags);
  sd_secure_free(buf, len);
  if (r != SD_OK) {
    *bad = "not INI";
    return r;
  }
  r = sd_profile_from_ini(ini, p, bad);
  sd_ini_free(ini);
  return r;
}

/* Loads every machine profile of scope service. A profile that fails validation or name resolution is logged and not
   loaded (2.6 rule 1: a profile is refused, the others still load). */
static uint32_t svc_load_profiles(void)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t pat[MAX_PATH];
  svc_prof *list[SVC_MAX_PROFILES];
  uint32_t n = 0, i;
  if (g.idle)
    return 0;
  _snwprintf_s(pat, MAX_PATH, _TRUNCATE, L"%s\\*.ini", g.profiles);
  h = FindFirstFileW(pat, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      wchar_t path[MAX_PATH];
      svc_prof *x;
      const char *bad = NULL, *why = NULL;
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        continue;
      if (n >= SVC_MAX_PROFILES)
        break;
      _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\%s", g.profiles, fd.cFileName);
      x = (svc_prof *)sd_calloc(1, sizeof(*x));
      if (x == NULL)
        break;
      if (svc_profile_read(path, &x->p, &bad) != SD_OK) {
        SD_LOGW("svc", "machine profile %ls not loaded: %s", fd.cFileName, bad ? bad : "unreadable");
        sd_free(x);
        continue;
      }
      if (x->p.scope != SD_PROFILE_SCOPE_SERVICE) {
        sd_free(x);                      /* users and user templates are not the service's business */
        continue;
      }
      if (x->p.id[0] == 0 || svc_validate_profile(&x->p, &bad, &why) != SD_OK) {
        SD_LOGW("svc", "machine profile %ls not loaded: %s (%s)", fd.cFileName, bad ? bad : "no id", why ? why : "");
        sd_free(x);
        continue;
      }
      if (svc_acl_build(&x->p, svc_resolve_entry, NULL, &x->acl) != SD_OK) {
        SD_LOGW("svc", "machine profile %ls not loaded: service_access does not resolve (fail closed)", fd.cFileName);
        sd_free(x);
        continue;
      }
      {
        uint32_t k;
        int dup = 0;
        for (k = 0; k < n; k++)
          if (strcmp(list[k]->p.id, x->p.id) == 0) dup = 1;
        if (dup) {
          sd_free(x);
          continue;
        }
      }
      list[n++] = x;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  sd_mutex_lock(&g.lock);
  svc_free_profiles_locked();
  for (i = 0; i < n; i++)
    g.profs[g.nprofs++] = list[i];
  sd_mutex_unlock(&g.lock);
  return n;
}

/* Finds a profile by id (exact) or name (case-insensitive). Locked by the caller. */
static svc_prof *find_profile_locked(const char *key)
{
  uint32_t i;
  if (key == NULL || key[0] == 0)
    return NULL;
  for (i = 0; i < g.nprofs; i++)
    if (strcmp(g.profs[i]->p.id, key) == 0)
      return g.profs[i];
  for (i = 0; i < g.nprofs; i++)
    if (_stricmp(g.profs[i]->p.name, key) == 0)
      return g.profs[i];
  return NULL;
}

/* ---- mount records ---- */

static svc_mount *find_by_id_locked(const char *id)
{
  uint32_t i;
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] && strcmp(g.mounts[i]->id, id) == 0)
      return g.mounts[i];
  return NULL;
}

static svc_mount *find_by_m_locked(sd_mount *m)
{
  uint32_t i;
  if (m == NULL)
    return NULL;
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] && g.mounts[i]->m == m)
      return g.mounts[i];
  return NULL;
}

/* A request key: mount_id, target ("X:" or "X:\") or profile (id or name). */
static svc_mount *find_mount_locked(const sd_json *params)
{
  const char *id = sd_json_get_str(params, "mount_id");
  const char *tgt = sd_json_get_str(params, "target");
  const char *prof = sd_json_get_str(params, "profile");
  uint32_t i;
  if (id)
    return find_by_id_locked(id);
  if (tgt && tgt[0] && (tgt[0] | 0x20) >= 'a' && (tgt[0] | 0x20) <= 'z' && tgt[1] == ':') {
    wchar_t l = (wchar_t)(tgt[0] & ~0x20);
    for (i = 0; i < SVC_MAX_MOUNTS; i++)
      if (g.mounts[i] && g.mounts[i]->letter == l)
        return g.mounts[i];
    return NULL;
  }
  if (prof) {
    for (i = 0; i < SVC_MAX_MOUNTS; i++)
      if (g.mounts[i] && g.mounts[i]->prof &&
          (strcmp(g.mounts[i]->prof->p.id, prof) == 0 || _stricmp(g.mounts[i]->prof->p.name, prof) == 0))
        return g.mounts[i];
  }
  return NULL;
}

static int letter_taken_locked(wchar_t l)
{
  uint32_t i;
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] && g.mounts[i]->letter == l)
      return 1;
  return 0;
}

/* The drive letter an auto mount takes: the highest free letter from Z: down to D: (0 when none). */
static wchar_t pick_letter_locked(void)
{
  DWORD used = GetLogicalDrives();
  wchar_t l;
  for (l = L'Z'; l >= L'D'; l--) {
    DWORD bit = 1ul << (l - L'A');
    if ((used & bit) == 0 && !letter_taken_locked(l))
      return l;
  }
  return 0;
}

/* ---- identity of the caller (2.2, 03 §2.2 membership) ---- */

static void member_of(sd_ipc_client *c, const svc_acl *acl, svc_member *out)
{
  uint32_t i;
  memset(out, 0, sizeof(*out));
  out->admin_elevated = caller_is_admin(c);
  for (i = 0; i < acl->n_access && !out->in_access; i++) {
    PSID sid = sid_of(acl->access[i]);
    int mem = 0;
    if (sid) {
      if (sd_ipc_client_member_of(c, sid, &mem) == SD_OK && mem)
        out->in_access = 1;
      LocalFree(sid);
    }
  }
  for (i = 0; i < acl->n_write && !out->in_write; i++) {
    PSID sid = sid_of(acl->write[i]);
    int mem = 0;
    if (sid) {
      if (sd_ipc_client_member_of(c, sid, &mem) == SD_OK && mem)
        out->in_write = 1;
      LocalFree(sid);
    }
  }
}

static sd_err fail(sd_ipc_error *err, sd_err e, const char *code, const char *detail)
{
  sd_ipc_error_set(err, e, code, detail);
  return err->err;
}

static sd_err need_admin(sd_ipc_client *c, sd_ipc_error *err)
{
  if (!caller_is_admin(c))
    return fail(err, SD_E_ACCESS_DENIED, "access_denied", "an elevated administrator is required");
  return SD_OK;
}

/* ---- broadcasts ---- */

static void broadcast_event(const char *topic, const char *event, sd_wr *data)
{
  sd_wr w;
  sd_wr_init(&w, 1024);
  if (sd_ipc_build_event(event, (const char *)data->p, data->len, &w) == SD_OK && g.srv != NULL)
    sd_ipc_broadcast(g.srv, topic, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

static void write_mount_event_data(sd_json_writer *jw, const char *id, wchar_t letter, const char *state)
{
  char tgt[4];
  target_of(letter, tgt);
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "mount_id"); sd_jw_cstr(jw, id);
  sd_jw_key(jw, "target"); sd_jw_cstr(jw, tgt);
  sd_jw_key(jw, "state"); sd_jw_cstr(jw, state);
  sd_jw_obj_end(jw);
}

/* Filtered mount.state (topic mount, 2.4): letter and state only, the same for every subscriber. */
static void announce_state(const char *id, wchar_t letter, const char *state)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 512);
  sd_jw_init(&jw, &d);
  write_mount_event_data(&jw, id, letter, state);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_event("mount", "mount.state", &d);
  sd_wr_free(&d);
}

/* ---- sd_mount callbacks (control thread) ---- */

/* ---- Event Log (10.3) ---- */

static void svc_event(DWORD id, const wchar_t **args, size_t nargs)
{
  if (g.event != NULL)
    g.event(g.event_ctx, id, args, nargs);
}

/* Mount state events of a global drive: mounted, unmounted, and failed with the IPC code. Messages stay English. */
static void svc_event_mount(sd_mount_state st, const char *prof_id, wchar_t letter, const char *err_code)
{
  wchar_t wprof[256], wtarget[4], wcode[64];
  const wchar_t *args[3];
  wide_from_utf8(prof_id, wprof, SD_COUNTOF(wprof));
  wtarget[0] = letter;
  wtarget[1] = L':';
  wtarget[2] = 0;
  args[0] = wprof;
  args[1] = wtarget;
  if (st == SD_MOUNT_MOUNTED) {
    svc_event(SVC_MSG_MOUNTED, args, 2);
  } else if (st == SD_MOUNT_UNMOUNTED) {
    svc_event(SVC_MSG_UNMOUNTED, args, 2);
  } else if (st == SD_MOUNT_FAILED) {
    wide_from_utf8(err_code, wcode, SD_COUNTOF(wcode));
    args[2] = wcode;
    svc_event(SVC_MSG_MOUNT_FAILED, args, 3);
  }
}

/* Event 3102 (10.3): a machine folder refused at start. %1 is the folder, %2 the reason (owner, reparse_point,
   not_directory, acl). The service stays idle and nothing is repaired here (repair-data does that). */
static void svc_event_untrusted(const svc_refusal *w)
{
  const wchar_t *args[2];
  args[0] = w->path;
  args[1] = svc_folder_reason_text(w->why);
  svc_event(SVC_MSG_UNTRUSTED_FOLDER, args, 2);
}

/* A key file of a service profile refused by the trust rules (TM-R27): the same Event 3102 with the file as %1. The
   mount then fails with the usage error; the service stays up. */
static void svc_event_key_refused(const wchar_t *path, svc_folder_reason why)
{
  const wchar_t *args[2];
  args[0] = path;
  args[1] = svc_folder_reason_text(why);
  svc_event(SVC_MSG_UNTRUSTED_FOLDER, args, 2);
}

/* The SCM sink: ReportEventW under source ShellDrive (registered by `shelldrive service install`). The message file
   is shelldrive-host.exe itself, so the ids of svc_events.mc resolve in the Application log. */
static void svc_eventlog_write(void *ctx, DWORD id, const wchar_t **args, size_t nargs)
{
  HANDLE h;
  WORD type;
  (void)ctx;
  switch ((id >> 30) & 3u) {
  case 3u: type = EVENTLOG_ERROR_TYPE; break;
  case 2u: type = EVENTLOG_WARNING_TYPE; break;
  case 1u: type = EVENTLOG_INFORMATION_TYPE; break;
  default: type = EVENTLOG_SUCCESS; break;
  }
  h = RegisterEventSourceW(NULL, SVC_SCM_EVENT_SOURCE);
  if (h == NULL)
    return;
  (void)ReportEventW(h, type, 0, id, NULL, (WORD)nargs, 0, args, NULL);
  DeregisterEventSource(h);
}

static void svc_on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  char id[16] = "", state[24], prof_id[256] = "", err_code[64] = "";
  wchar_t letter = 0;
  svc_mount *r;
  const char *code = NULL;
  sd_mount_attach at;
  int have_at = 0;
  (void)ctx;
  /* 02 §7.7: the hosted export exists as soon as the mount is up; read it before taking g.lock (the mount's
     own lock must never be held while g.lock is asked for the other way round). */
  memset(&at, 0, sizeof(at));
  if (st == SD_MOUNT_MOUNTED && m != NULL) {
    sd_mount_get_attach(m, &at);
    have_at = at.webdav_remote[0] != 0;
  }
  sd_mutex_lock(&g.lock);
  r = find_by_m_locked(m);
  if (r) {
    r->st = st;
    if (have_at) {
      r->wd_port = at.webdav_port;
      wcscpy_s(r->wd_remote, SD_COUNTOF(r->wd_remote), at.webdav_remote);
      wcscpy_s(r->wd_remote_xp, SD_COUNTOF(r->wd_remote_xp), at.webdav_remote_xp);
    }
    strcpy_s(id, sizeof(id), r->id);
    letter = r->letter;
    if (r->prof != NULL)
      strcpy_s(prof_id, sizeof(prof_id), r->prof->p.id);
    if (st == SD_MOUNT_FAILED || st == SD_MOUNT_UNMOUNTED) {
      r->final = 1;
      if (st == SD_MOUNT_FAILED) {
        code = r->prompt_refused ? (r->refuse_code ? r->refuse_code : "prompt_unavailable") : sd_err_name(why);
        strcpy_s(r->err_code, sizeof(r->err_code), code);
        strcpy_s(r->err_detail, sizeof(r->err_detail), "mount failed");
        strcpy_s(err_code, sizeof(err_code), code);
      }
    }
  }
  sd_mutex_unlock(&g.lock);
  if (r == NULL)
    return;
  strcpy_s(state, sizeof(state), sd_mount_state_name(st));
  SD_LOGI("svc", "mount %s: %s (%s)", id, state, sd_err_name(why));
  announce_state(id, letter, state);
  svc_event_mount(st, prof_id, letter, err_code);
}

/* ---- attention (2.6 rule 3) ---- */

/* Number of open routed prompts. Takes g.lock: never call it with g.lock held. */
static uint32_t svc_open_prompts(void)
{
  uint32_t i, n = 0;
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_PROMPTS; i++)
    if (g.prompts[i].used)
      n++;
  sd_mutex_unlock(&g.lock);
  return n;
}

/* Builds the attention event {count} into w (initialized by the caller). Content-free: only the number. */
static sd_err build_attention(uint32_t count, sd_wr *w)
{
  sd_wr d;
  sd_json_writer jw;
  sd_err e = SD_E_FAILURE;
  sd_wr_init(&d, 64);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "count");
  sd_jw_int(&jw, (int64_t)count);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    e = sd_ipc_build_event("attention", (const char *)d.p, d.len, w);
  sd_wr_free(&d);
  return e;
}

/* Sent whenever the number of open prompts changes, 0 included, so an admin UI clears its state. Not with g.lock held. */
static void svc_broadcast_attention(void)
{
  sd_wr w;
  sd_wr_init(&w, 128);
  if (g.srv != NULL && build_attention(svc_open_prompts(), &w) == SD_OK)
    sd_ipc_broadcast(g.srv, "attention", (const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* Hands the prompt to an elevated administrator that subscribed to `prompt` (2.5, 2.6 rule 3); refuses it otherwise. */
static void svc_on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  svc_prompt *slot = NULL;
  svc_mount *r;
  uint32_t i, subs;
  int refuse = 0;
  uint32_t pid = 0;
  (void)ctx;
  /* 2.6 rule 2: there is no trust on first use for the service. An unknown host key is never accepted here; the admin
     pins it first (hostkey add --machine --from-server), so the mount fails with host_key_unknown (exit 5). */
  subs = (g.srv && p->kind != SD_MP_HOSTKEY) ? sd_ipc_topic_subscribers(g.srv, "prompt", SD_IPC_CAP_PROMPTS_UI) : 0;
  sd_mutex_lock(&g.lock);
  r = find_by_m_locked(m);
  if (r == NULL || subs == 0) {
    if (r) {
      r->prompt_refused = 1;
      r->refuse_code = (p->kind == SD_MP_HOSTKEY) ? "host_key_unknown" : "prompt_unavailable";
    }
    refuse = 1;
  } else {
    for (i = 0; i < SVC_MAX_PROMPTS && slot == NULL; i++)
      if (!g.prompts[i].used)
        slot = &g.prompts[i];
    if (slot == NULL) {
      r->prompt_refused = 1;
      refuse = 1;
    } else {
      memset(slot, 0, sizeof(*slot));
      slot->used = 1;
      slot->id = ++g.next_prompt;
      slot->mount = r;
      slot->mprompt = p->id;
      slot->deadline = svc_now() + SVC_PROMPT_MS;
      slot->kind = (int)p->kind;
      strcpy_s(slot->mount_id, sizeof(slot->mount_id), r->id);
      strcpy_s(slot->profile_id, sizeof(slot->profile_id), r->prof->p.id);
      strcpy_s(slot->host, sizeof(slot->host), p->host);
      slot->port = p->port;
      strcpy_s(slot->user, sizeof(slot->user), p->user);
      slot->is_reconnect = p->is_reconnect;
      slot->can_save = p->can_save;
      pid = slot->id;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (refuse) {
    SD_LOGW("svc", "a prompt (%s) has no elevated administrator to answer it; the mount fails", sd_mount_prompt_kind_name(p->kind));
    (void)sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
    return;
  }
  {
    sd_wr d;
    sd_json_writer jw;
    char pidstr[24];
    _snprintf_s(pidstr, sizeof(pidstr), _TRUNCATE, "p-%u", (unsigned)pid);
    sd_wr_init(&d, 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, pidstr);
    sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, slot->mount_id);
    sd_jw_key(&jw, "profile_id"); sd_jw_cstr(&jw, slot->profile_id);
    sd_jw_key(&jw, "kind"); sd_jw_cstr(&jw, sd_mount_prompt_kind_name(p->kind));
    sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, slot->host);
    sd_jw_key(&jw, "port"); sd_jw_int(&jw, slot->port);
    sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, slot->user);
    sd_jw_key(&jw, "is_reconnect"); sd_jw_bool(&jw, slot->is_reconnect);
    sd_jw_key(&jw, "can_save"); sd_jw_bool(&jw, 0);            /* the service never saves a secret it was given */
    sd_jw_key(&jw, "queued"); sd_jw_bool(&jw, 0);
    sd_jw_key(&jw, "deadline_ms"); sd_jw_int(&jw, SVC_PROMPT_MS);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK) {
      broadcast_event("prompt", "prompt.request", &d);
      svc_broadcast_attention();
    }
    sd_wr_free(&d);
  }
}

static void svc_on_prompt_closed(void *ctx, sd_mount *m, uint32_t prompt_id)
{
  uint32_t i;
  char pidstr[24];
  char mid[16] = "";
  int closed = 0;
  (void)ctx;
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_PROMPTS; i++) {
    svc_prompt *s = &g.prompts[i];
    if (s->used && s->mount && s->mount->m == m && s->mprompt == prompt_id) {
      s->used = 0;
      strcpy_s(mid, sizeof(mid), s->mount_id);
      _snprintf_s(pidstr, sizeof(pidstr), _TRUNCATE, "p-%u", (unsigned)s->id);
      closed = 1;
      break;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (closed) {
    sd_wr d;
    sd_json_writer jw;
    sd_wr_init(&d, 256);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "prompt_id"); sd_jw_cstr(&jw, pidstr);
    sd_jw_key(&jw, "mount_id"); sd_jw_cstr(&jw, mid);
    sd_jw_key(&jw, "reason"); sd_jw_cstr(&jw, "answered");
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      broadcast_event("prompt", "prompt.closed", &d);
    sd_wr_free(&d);
    svc_broadcast_attention();
  }
}

static int svc_secret_get(void *ctx, sd_mount *m, int kind, const char *target, char *out, size_t cap)
{
  sd_secbuf *b = NULL;
  int ok = 0;
  (void)ctx;
  (void)m;
  if (sd_secret_get(SD_SECRET_SERVICE, (sd_secret_kind)kind, target, &b) == SD_OK) {
    if (b->len + 1 <= cap) {
      memcpy(out, b->p, b->len);
      out[b->len] = 0;
      ok = 1;
    }
    sd_secbuf_free(b);
  }
  return ok;
}

static void svc_on_warning(void *ctx, sd_mount *m, const char *code, uint32_t hop, const char *detail)
{
  (void)ctx;
  (void)m;
  SD_LOGW("svc", "mount warning %s (hop %u) %s", code ? code : "", (unsigned)hop, detail ? detail : "");
}

static void svc_on_write_failed(void *ctx, sd_mount *m, const wchar_t *path, UINT64 bytes, const char *status)
{
  (void)ctx;
  (void)m;
  (void)path;
  SD_LOGW("svc", "write-behind data lost (%llu bytes, %s)", (unsigned long long)bytes, status ? status : "");
}

/* Event 1200 (03 10.3, TM-R24): a successful change through a global drive, at info. %1 profile, %2 requestor SID,
   %3 account name (DOMAIN\name, or the SID alone when it does not resolve), %4 operation, %5 remote path. The vfs has
   already coalesced repeats per 60 s. The lookup runs on the control thread; the SID is valid during the callback. */
static void svc_on_audit(void *ctx, sd_mount *m, PSID sid, const char *op, const wchar_t *path)
{
  char prof_id[256] = "";
  wchar_t sidw[128] = L"", acct[300] = L"", name[128] = L"", dom[128] = L"", wprof[256] = L"", wop[48] = L"";
  LPWSTR sidstr = NULL;
  DWORD name_len = (DWORD)SD_COUNTOF(name), dom_len = (DWORD)SD_COUNTOF(dom);
  SID_NAME_USE use;
  svc_mount *r;
  const wchar_t *args[5];
  (void)ctx;
  if (sid == NULL)
    return;
  sd_mutex_lock(&g.lock);
  r = find_by_m_locked(m);
  if (r != NULL && r->prof != NULL)
    strcpy_s(prof_id, sizeof(prof_id), r->prof->p.id);
  sd_mutex_unlock(&g.lock);
  if (ConvertSidToStringSidW(sid, &sidstr)) {
    wcsncpy_s(sidw, SD_COUNTOF(sidw), sidstr, _TRUNCATE);
    LocalFree(sidstr);
  }
  if (LookupAccountSidW(NULL, sid, name, &name_len, dom, &dom_len, &use)) {
    if (dom[0] != 0) {
      wcsncpy_s(acct, SD_COUNTOF(acct), dom, _TRUNCATE);
      wcsncat_s(acct, SD_COUNTOF(acct), L"\\", _TRUNCATE);
    }
    wcsncat_s(acct, SD_COUNTOF(acct), name, _TRUNCATE);
  } else {
    wcsncpy_s(acct, SD_COUNTOF(acct), sidw, _TRUNCATE);
  }
  wide_from_utf8(prof_id, wprof, SD_COUNTOF(wprof));
  wide_from_utf8(op ? op : "", wop, SD_COUNTOF(wop));
  args[0] = wprof;
  args[1] = sidw;
  args[2] = acct;
  args[3] = wop;
  args[4] = path ? path : L"";
  svc_event(SVC_MSG_AUDIT, args, 5);
}

static void svc_on_notice(void *ctx, sd_mount *m, const char *code, const char *detail)
{
  (void)ctx;
  (void)m;
  SD_LOGI("svc", "notice %s %s", code ? code : "", detail ? detail : "");
}

/* ---- chains of service profiles (M5, 2.6 rule 1, 3.4.1, 3.8) ----

   A machine profile's chain is resolved with sd_chain_resolve over the machine profiles only (a jump names a service
   profile, never a user one). Every hop and every proxy leg then follows the service rules: the machine known_hosts
   store only (set by the callers, read-only), no TOFU (a host-key prompt is refused, 2.6 rule 2), one identity file
   under the service folder read through a checked handle (TM-R27) and handed over as a key blob, no agent and no
   keyboard-interactive, and every secret from the service secret store. The arena holds the strings and key bytes
   sd_mount_create copies; it is wiped with svc_chain_free. */
typedef struct svc_chain {
  uint32_t count;
  sd_mount_hop hop[SD_MOUNT_MAX_HOPS];
  wchar_t host[SD_MOUNT_MAX_HOPS][256];
  char user[SD_MOUNT_MAX_HOPS][128];
  char alias[SD_MOUNT_MAX_HOPS][256];
  char label[SD_MOUNT_MAX_HOPS][MAX_PATH * 3];
  unsigned char *blob[SD_MOUNT_MAX_HOPS];
  DWORD blob_len[SD_MOUNT_MAX_HOPS];
  wchar_t proxy_host[SD_MOUNT_MAX_HOPS][256];
  char proxy_user[SD_MOUNT_MAX_HOPS][128];
} svc_chain;

static void svc_chain_free(svc_chain *c)
{
  uint32_t i;
  if (c == NULL)
    return;
  for (i = 0; i < SD_MOUNT_MAX_HOPS; i++)
    if (c->blob[i])
      sd_secure_free(c->blob[i], c->blob_len[i]);
  sd_free(c);
}

/* proxy_auth of a service leg (3.8), as the per-user agent maps it. */
static uint32_t svc_proxy_auth_of(const sd_proxy_spec *x, int pa)
{
  if (x->kind == SD_PROFILE_PROXY_SOCKS5)
    return x->user[0] ? SD_PROXY_AUTH_USERPASS : 0;
  switch (pa) {
  case SD_PROFILE_PROXY_AUTH_BASIC:     return SD_PROXY_AUTH_BASIC;
  case SD_PROFILE_PROXY_AUTH_NEGOTIATE: return SD_PROXY_AUTH_SSPI | (x->user[0] ? SD_PROXY_AUTH_BASIC : 0);
  case SD_PROFILE_PROXY_AUTH_NONE:      return 0;
  default:                              return SD_PROXY_AUTH_SSPI_KERBEROS | (x->user[0] ? SD_PROXY_AUTH_BASIC : 0);
  }
}

/* Lookup of sd_chain_resolve: the machine profiles only. The control thread calls it without g.lock held. */
static sd_err svc_chain_lookup(void *ctx, const char *key, sd_profile *out)
{
  svc_prof *x;
  (void)ctx;
  sd_mutex_lock(&g.lock);
  x = find_profile_locked(key);
  if (x != NULL)
    *out = x->p;
  sd_mutex_unlock(&g.lock);
  return x != NULL ? SD_OK : SD_E_NOT_FOUND;
}

/* Whether the service secret store holds the proxy password of this leg (sd_mount reads it with secret_get later). */
static int svc_proxy_secret_present(const sd_proxy_spec *x)
{
  char target[SD_SECRET_MAX_TARGET];
  sd_secbuf *b = NULL;
  int ok = 0;
  if (x->user[0] == 0)
    return 0;
  if (sd_secret_target_proxy(x->kind == SD_PROFILE_PROXY_SOCKS5 ? "socks5" : "http", x->user, x->host, x->port, target,
                             sizeof(target)) != SD_OK)
    return 0;
  if (sd_secret_get(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, &b) == SD_OK) {
    ok = 1;
    sd_secbuf_free(b);
  }
  return ok;
}

/* The identity file of one hop (TM-R27): the key blob read through a checked handle; the bytes stay in the arena. */
static const char *svc_chain_identity(svc_chain *c, uint32_t i, const sd_chain_hop *s)
{
  wchar_t identw[MAX_PATH];
  svc_folder_reason fr = SVC_FOLDER_OK;
  DWORD fe;
  sd_mount_hop *d = &c->hop[i];
  if (s->identity_count == 0)
    return NULL;
  if (sd_config_expand_path(s->identity[0], identw, SD_COUNTOF(identw)) != SD_OK ||
      !svc_path_under(identw, g.service_dir))
    return "identity file outside the service folder (TM-R27)";
  fe = svc_file_read_trusted(g.service_dir, identw, g.owner_trusted, NULL, &c->blob[i], &c->blob_len[i], &fr);
  if (fe != 0)
    return "identity file cannot be read (TM-R27)";
  if (fr != SVC_FOLDER_OK) {
    svc_event_key_refused(identw, fr);
    return "identity file refused: owner, reparse point, not a plain file or a writable ACL (TM-R27)";
  }
  utf8_from_wide(identw, c->label[i], sizeof(c->label[i]));
  d->key_blob = c->blob[i];
  d->key_blob_len = c->blob_len[i];
  d->key_label = c->label[i];
  return NULL;
}

static int svc_sysproxy_allowed(void);
static int svc_sysproxy_sspi(void);

/* The leg that reaches hop i (3.8): none, a configured HTTP or SOCKS5 proxy (a service secret for a user), or the
   machine configuration read through the seam (proxy = system, refused unless the machine policy allows it). */
static const char *svc_chain_leg(svc_chain *c, uint32_t i, const sd_chain *ch)
{
  const sd_proxy_spec *x = &ch->proxy[i];
  sd_mount_hop *d = &c->hop[i];
  int pa = ch->proxy_auth[i];
  int fb = (ch->proxy_fallback_direct & (1u << i)) != 0;
  const char *bad = NULL, *why = NULL;
  if (x->kind == SD_PROFILE_PROXY_NONE)
    return NULL;
  if (x->kind == SD_PROFILE_PROXY_SYSTEM) {
    int kind = SD_PROXY_NONE;
    wchar_t hostw[256];
    uint16_t port = 0;
    sd_err e;
    int sspi = 0;
    if (g.sysproxy == NULL || g.sysproxy->read == NULL || !svc_sysproxy_allowed())
      return "proxy = system is refused by policy AllowSystemProxy (TM-R10)";
    sspi = svc_sysproxy_sspi();
    if (svc_proxy_leg_check(x, pa, 0, &bad, &why) != SD_OK) {
      SD_LOGW("svc", "chain leg %u refused: %s (%s)", (unsigned)i, bad, why);
      return why;
    }
    e = g.sysproxy->read(g.sysproxy->ctx, c->host[i], d->port, &kind, hostw, &port);
    if (e != SD_OK)
      return fb ? NULL : "the system proxy cannot be read (TM-R10)";
    if (kind == SD_PROXY_NONE)
      return NULL;
    if (kind != SD_PROXY_HTTP && kind != SD_PROXY_SOCKS5)
      return "the system proxy is not usable";
    wcscpy_s(c->proxy_host[i], SD_COUNTOF(c->proxy_host[i]), hostw);
    d->proxy.kind = kind;
    d->proxy.host = c->proxy_host[i];
    d->proxy.port = port;
    d->proxy.user = NULL;
    /* TM-R10: no SSPI towards a proxy obtained from proxy = system unless AllowSystemProxySspi = 1; then the
       Kerberos-only Negotiate of proxy_auth auto (no credentials here, 2.6 rule 1) */
    d->proxy.auth = (sspi && pa != SD_PROFILE_PROXY_AUTH_NONE) ? SD_PROXY_AUTH_SSPI_KERBEROS : 0;
    d->proxy.allow_discovered_sspi = sspi;
    d->proxy.allow_system = 0;
    d->proxy.fallback_direct = fb;
    return NULL;
  }
  wide_from_utf8(x->host, c->proxy_host[i], SD_COUNTOF(c->proxy_host[i]));
  if (svc_proxy_leg_check(x, pa, svc_proxy_secret_present(x), &bad, &why) != SD_OK) {
    SD_LOGW("svc", "chain leg %u refused: %s (%s)", (unsigned)i, bad, why);
    return why;
  }
  d->proxy.kind = x->kind;
  d->proxy.host = c->proxy_host[i];
  d->proxy.port = x->port;
  if (x->user[0]) {
    strcpy_s(c->proxy_user[i], sizeof(c->proxy_user[i]), x->user);
    d->proxy.user = c->proxy_user[i];
  }
  d->proxy.auth = svc_proxy_auth_of(x, pa);
  d->proxy.fallback_direct = 0;
  return NULL;
}

/* One hop with the service rules (svc_chain_hop_check). hku is the host key mode of the target; the jump hosts
   never update host keys (no announcements from them). */
static const char *svc_chain_hop(svc_chain *c, uint32_t i, const sd_chain *ch, const sd_profile *p, int hku)
{
  const sd_chain_hop *s = &ch->hop[i];
  sd_mount_hop *d = &c->hop[i];
  const char *bad = NULL, *why = NULL;
  uint32_t methods = 0;
  if (svc_chain_hop_check(s, &bad, &why) != SD_OK) {
    SD_LOGW("svc", "chain hop %u refused: %s (%s)", (unsigned)i, bad, why);
    return why;
  }
  wide_from_utf8(s->host, c->host[i], SD_COUNTOF(c->host[i]));
  if (s->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) methods |= SD_AUTH_PUBLICKEY;
  if (s->auth_methods & SD_PROFILE_AUTH_PASSWORD) methods |= SD_AUTH_PASSWORD;
  strcpy_s(c->user[i], sizeof(c->user[i]), s->user[0] ? s->user : p->user);
  if (s->host_key_alias[0]) {
    strcpy_s(c->alias[i], sizeof(c->alias[i]), s->host_key_alias);
    d->host_key_alias = c->alias[i];
  }
  d->host = c->host[i];
  d->port = s->port ? s->port : 22;
  d->user = c->user[i];
  d->auth_methods = methods;
  d->agents = 0;                      /* D17: no agent in the service */
  d->agent_keys = NULL;
  d->identities = NULL;
  d->identity_count = 0;
  d->identities_only = s->identities_only;   /* D37: resolved by sd_chain_resolve */
  d->certificate = NULL;
  d->update_host_keys = (i + 1 == ch->count) ? hku : SD_HKU_NO;
  d->no_save = 1;                     /* the service never keeps a secret it was given (2.5) */
  why = svc_chain_identity(c, i, s);
  if (why != NULL)
    return why;
  return svc_chain_leg(c, i, ch);
}

/* Builds the hops of a machine profile (the last one is the target). Returns NULL with *out set, or the refusal
   (*out is NULL). Control thread only, without g.lock. */
static const char *svc_chain_build(svc_chain **out, const sd_profile *p, int hku)
{
  svc_chain *c;
  sd_chain *ch = NULL;
  const char *why = NULL;
  uint32_t i;
  sd_err e;
  *out = NULL;
  c = (svc_chain *)sd_calloc(1, sizeof(*c));
  if (c == NULL)
    return "out of memory";
  e = sd_chain_resolve(p, svc_chain_lookup, NULL, &ch, &why);
  if (e != SD_OK || ch == NULL || ch->count == 0 || ch->count > SD_MOUNT_MAX_HOPS) {
    sd_free(c);
    sd_free(ch);
    return why ? why : "the jump hosts cannot be resolved";
  }
  c->count = ch->count;
  why = NULL;                       /* a resolved chain: the hop checks below decide */
  for (i = 0; i < ch->count && why == NULL; i++)
    why = svc_chain_hop(c, i, ch, p, hku);
  sd_free(ch);
  if (why != NULL) {
    svc_chain_free(c);
    return why;
  }
  *out = c;
  return NULL;
}

/* Machine policy and the real read of proxy = system (3.8). The seam is svc_opts.sysproxy_ops. */
static sd_err svc_sysproxy_machine_read(void *ctx, const wchar_t *host, uint16_t port, int *kind, wchar_t *host_out,
                                        uint16_t *port_out)
{
  sd_proxy_kind k = SD_PROXY_NONE;
  sd_err e;
  (void)ctx;
  e = sd_ssh_proxy_machine(host, port, &k, host_out, port_out);
  *kind = (int)k;
  return e;
}

static const svc_sysproxy_ops k_sysproxy_shipping = { -1, svc_sysproxy_machine_read, NULL };

/* One machine policy of proxy = system (03 §3.5, 3.8): HKLM only, a missing or other-typed value reads as 0. */
static int svc_sysproxy_policy_flag(sd_policy_id id)
{
  DWORD v = 0;
  return sd_policy_machine_get_dword(id, &v) && v == 1;
}

/* AllowSystemProxy for one leg: the seam's own answer, or the machine policy when the seam says -1. */
static int svc_sysproxy_allowed(void)
{
#ifdef SD_SVC_TEST_HOOKS
  if (g.test_sysproxy_forced)
    return g.test_sysproxy_allow == 1;
#endif
  if (g.sysproxy->allow >= 0)
    return g.sysproxy->allow != 0;
  return svc_sysproxy_policy_flag(SD_POLICY_ALLOWSYSTEMPROXY);
}

/* AllowSystemProxySspi (TM-R10): SSPI towards a system proxy only when the seam asks for the policy and it is 1. */
static int svc_sysproxy_sspi(void)
{
#ifdef SD_SVC_TEST_HOOKS
  if (g.test_sysproxy_forced)
    return g.test_sysproxy_sspi == 1;
#endif
  if (g.sysproxy->allow >= 0)
    return 0;
  return svc_sysproxy_policy_flag(SD_POLICY_ALLOWSYSTEMPROXYSSPI);
}

/* ---- host keys kept for review (M5, 03 §5.6, §6.1) ---- */

static void write_keys_json(sd_json_writer *jw, const char *key, const sd_mount_hostkey *k, uint32_t n)
{
  uint32_t i;
  sd_jw_key(jw, key);
  sd_jw_arr_begin(jw);
  for (i = 0; i < n; i++) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "type"); sd_jw_cstr(jw, k[i].type);
    sd_jw_key(jw, "fingerprint"); sd_jw_cstr(jw, k[i].fp_sha256);
    sd_jw_obj_end(jw);
  }
  sd_jw_arr_end(jw);
}

/* One announcement as hostkey.announced.list and the hostkeys.announced event show it (5.6). drop_adds: the additions
   were already written to the machine store, so only the removals are shown (no copy of the record is made). */
static void write_ann_obj(sd_json_writer *jw, const char *id, const char *mount_id, const sd_mount_announcement *a,
                          int drop_adds)
{
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "id"); sd_jw_cstr(jw, id);
  sd_jw_key(jw, "mount_id"); sd_jw_cstr(jw, mount_id);
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, a->host);
  sd_jw_key(jw, "lookup_name"); sd_jw_cstr(jw, a->lookup_name);
  sd_jw_key(jw, "hop"); sd_jw_int(jw, (int64_t)a->hop_index + 1);
  write_keys_json(jw, "add", a->add, drop_adds ? 0u : a->add_count);
  write_keys_json(jw, "remove", a->remove, a->remove_count);
  sd_jw_obj_end(jw);
}

/* Keeps an announcement for review, newest first. When SVC_MAX_ANNOUNCE are kept the oldest is dropped. The id is copied
   to id_out under g.lock. drop_adds keeps the removals only (the additions were stored). Returns 0 only when the record
   cannot be allocated. */
static int ann_keep(const char *mount_id, const sd_mount_announcement *a, int drop_adds, char *id_out, size_t cap)
{
  svc_ann *x = (svc_ann *)sd_calloc(1, sizeof(*x));
  svc_ann *last, *prev = NULL;
  if (x == NULL)
    return 0;
  x->a = *a;
  if (drop_adds)
    x->a.add_count = 0;
  strcpy_s(x->mount_id, sizeof(x->mount_id), mount_id ? mount_id : "");
  sd_mutex_lock(&g.lock);
  g.next_ann++;
  _snprintf_s(x->id, sizeof(x->id), _TRUNCATE, "a-%u", (unsigned)g.next_ann);
  x->next = g.anns;
  g.anns = x;
  g.nann++;
  if (g.nann > SVC_MAX_ANNOUNCE) {
    for (last = g.anns; last->next != NULL; last = last->next)
      prev = last;
    if (prev != NULL) prev->next = NULL; else g.anns = NULL;
    g.nann--;
    SD_LOGW("svc", "%u host key announcements are kept: the oldest one (%s) was dropped", (unsigned)SVC_MAX_ANNOUNCE,
            last->id);
    sd_free(last);
  }
  strcpy_s(id_out, cap, x->id);
  sd_mutex_unlock(&g.lock);
  return 1;
}

/* The fingerprints of n keys, comma separated, into out ("-" when there are none). */
static void join_fps(const sd_mount_hostkey *k, uint32_t n, wchar_t *out, size_t cch)
{
  uint32_t i;
  out[0] = 0;
  for (i = 0; i < n && i < SD_MOUNT_ANNOUNCE_MAX; i++) {
    wchar_t w[96];
    if (i)
      wcsncat_s(out, cch, L", ", _TRUNCATE);
    wide_from_utf8(k[i].fp_sha256, w, SD_COUNTOF(w));
    wcsncat_s(out, cch, w, _TRUNCATE);
  }
  if (out[0] == 0)
    wcsncpy_s(out, cch, L"-", _TRUNCATE);
}

/* Event 2300 (10.3): %1 host, %2 the new fingerprints, %3 the ones no longer offered. */
static void svc_event_announced(const sd_mount_announcement *a, int drop_adds)
{
  wchar_t host[256], added[512], removed[512];
  const wchar_t *args[3];
  wide_from_utf8(a->host, host, SD_COUNTOF(host));
  join_fps(a->add, drop_adds ? 0u : a->add_count, added, SD_COUNTOF(added));
  join_fps(a->remove, a->remove_count, removed, SD_COUNTOF(removed));
  args[0] = host;
  args[1] = added;
  args[2] = removed;
  svc_event(SVC_MSG_HOSTKEYS_ANNOUNCED, args, 3);
}

static sd_err svc_machine_apply(const sd_mount_announcement *a, int add_only);

/* The machine known_hosts is read by the service's mounts and hostkey connections (5.1): it is checked on its handle
   before the read, as a write is (svc_store_check, TM-R27), so a file an untrusted principal can change is never the
   source of the trusted keys. A missing file is not a refusal (no stored key). Returns NULL, or the refusal text. Only
   the check on the handle: the mount opens the file again, so a change between the two is not excluded (open item). */
static const char *svc_kh_read_check(void)
{
  svc_folder_reason why = SVC_FOLDER_OK;
  DWORD e;
  if (g.kh[0] == 0)
    return "machine known_hosts path is not set";
  e = svc_store_check(g.kh, g.owner_trusted, NULL, &why);
  if (e != 0 || why != SVC_FOLDER_OK) {
    SD_LOGW("svc", "the machine known_hosts is refused for reading (win32 %u, reason %d) (TM-R27)", (unsigned)e,
            (int)why);
    return "machine known_hosts refused: owner, reparse point, not a plain file or a writable ACL (TM-R27)";
  }
  return NULL;
}

/* The UpdateHostKeys policy of the machine (03 §3.5): 2 lets the service add the proven keys of an announcement to the
   machine store by itself (5.6). HKLM wins over HKCU, as for every policy. Read at each announcement, so a change
   applies to the next one. Tests force the value (svc_test_hk_policy). */
static int svc_policy_hk_accept(void)
{
#ifdef SD_SVC_TEST_HOOKS
  if (g.test_hk_policy_forced)
    return g.test_hk_policy == 2;
#endif
  {
    DWORD v = 0;
    return sd_policy_machine_get_dword(SD_POLICY_UPDATEHOSTKEYS, &v) && v == 2;
  }
}

#ifdef SD_SVC_TEST_HOOKS
void svc_test_hk_policy(int forced, DWORD value)
{
  g.test_hk_policy_forced = forced;
  g.test_hk_policy = value;
}

void svc_test_connect_admin(int on)
{
  g.test_connect_admin = on;
}

#ifdef SD_SVC_TEST_HOOKS
void svc_test_admin_all_clients(int on)
{
  g.test_admin_any = on;
}
#endif

void svc_test_sysproxy_policy(int forced, DWORD allow, DWORD sspi)
{
  g.test_sysproxy_forced = forced;
  g.test_sysproxy_allow = allow;
  g.test_sysproxy_sspi = sspi;
}
#endif

/* UpdateHostKeys (5.6) of a global mount, policy ask: the announcement is kept for an administrator and announced
   (Event 2300, topic hostkeys). Under policy 2 (svc_policy_hk_accept) the proven new keys are written to the machine
   store first, with the same checks as an accept; the removals always wait for an administrator (as in the agent).
   A failed write keeps the whole announcement for review. */
static void svc_on_hostkeys(void *ctx, sd_mount *m, const sd_mount_announcement *a, int applied, sd_err err)
{
  char mid[16] = "", id[16] = "";
  int drop_adds = 0;
  svc_mount *r;
  sd_wr d;
  sd_json_writer jw;
  (void)ctx;
  (void)err;
  if (applied) {
    /* a service mount never applies an announcement itself (its hop is ask), so this is a fault: nothing is changed */
    SD_LOGW("svc", "an applied host key announcement was reported for a service mount; nothing is changed");
    return;
  }
  if (a->add_count != 0 && svc_policy_hk_accept()) {
    sd_err ae = svc_machine_apply(a, 1);                /* add only: removals need the review (5.6) */
    SD_LOGI("svc", "UpdateHostKeys policy 2: %u new key(s) for %Hs saved to the machine store (%s)",
            (unsigned)a->add_count, a->lookup_name, sd_err_name(ae));
    if (ae == SD_OK) {
      if (a->remove_count == 0)
        return;
      drop_adds = 1;                                    /* what is left to review: the removals */
    }
  }
  sd_mutex_lock(&g.lock);
  r = find_by_m_locked(m);
  if (r != NULL)
    strcpy_s(mid, sizeof(mid), r->id);
  sd_mutex_unlock(&g.lock);
  if (!ann_keep(mid, a, drop_adds, id, sizeof(id))) {
    SD_LOGW("svc", "host keys announced for %Hs were not kept (out of memory)", a->lookup_name);
    return;
  }
  SD_LOGI("svc", "host keys announced for %Hs kept for review (%s)", a->lookup_name, id);
  svc_event_announced(a, drop_adds);
  sd_wr_init(&d, 4096);
  sd_jw_init(&jw, &d);
  write_ann_obj(&jw, id, mid, a, drop_adds);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast_event("hostkeys", "hostkeys.announced", &d);
  sd_wr_free(&d);
}

/* Writes an announcement to the machine known_hosts (5.6, TM-R27). The file is checked first (owner and DACL, on its
   handle); a refused file is not changed. Runs on the control thread or on the pipe thread (hostkey.announced.accept),
   never with g.lock held. */
static sd_err svc_machine_apply(const sd_mount_announcement *a, int add_only)
{
  sd_kh_store st;
  svc_folder_reason why = SVC_FOLDER_OK;
  DWORD e;
  if (g.kh[0] == 0)
    return SD_E_FAILURE;
  e = svc_store_check(g.kh, g.owner_trusted, NULL, &why);
  if (e != 0 || why != SVC_FOLDER_OK) {
    SD_LOGW("svc", "the machine known_hosts is refused (win32 %u, reason %d): not changed", (unsigned)e, (int)why);
    return SD_E_ACCESS_DENIED;
  }
  memset(&st, 0, sizeof(st));
  st.kind = SD_KH_STORE_MACHINE;
  st.path = g.kh;
  st.writable = 1;
  return sd_mount_apply_hostkeys_to(g.be, &st, 1, SD_KH_STORE_MACHINE, a, add_only);
}

/* ---- hostkey add: the connect-only hostkey mount (M5, 03 §2.6 rule 2, §6.1) ---- */

static int hk_type_ok(const char *t)
{
  size_t i, n = strlen(t);
  if (n == 0 || n >= 64) return 0;
  for (i = 0; i < n; i++)
    if (!((t[i] >= 'a' && t[i] <= 'z') || (t[i] >= '0' && t[i] <= '9') || t[i] == '-' || t[i] == '@' || t[i] == '.'))
      return 0;
  return 1;
}

/* The IPC code and the English detail of a failed hostkey connection (the CLI maps the code to its text). */
static void hk_error_text(sd_err e, const char *mount_code, const char **code, char *detail, size_t cap)
{
  *code = "connect_failed";
  strcpy_s(detail, cap, "cannot get the host keys of the server");
  if (e == SD_E_UNSUPPORTED) {
    *code = "not_implemented";
    strcpy_s(detail, cap, "hostkey add is not available on this backend");
  } else if (e == SD_E_HOSTKEY_MISMATCH) {
    *code = "host_key_mismatch";
    strcpy_s(detail, cap, "the server's host key does not match the stored one");
  } else if (e == SD_E_HOSTKEY_TYPE_UNAVAILABLE) {
    *code = "host_key_type_unavailable";
    strcpy_s(detail, cap, "the server offers none of the key types stored for it");
  } else if (e == SD_E_HOSTKEY_REJECTED) {
    *code = "host_key_rejected";
    strcpy_s(detail, cap, "the host key was not accepted");
  } else if (e == SD_E_INVALID_PARAM) {
    *code = "usage";
    strcpy_s(detail, cap, "invalid host");
  } else if (e == SD_E_NO_MEMORY) {
    *code = NULL;
    strcpy_s(detail, cap, "out of memory");
  } else if (mount_code != NULL) {
    *code = mount_code;
  }
}

/* Sends the deferred reply of a hostkey.add once (control thread). */
static void svc_hk_send(svc_hk *hk, sd_err e, const char *code, const char *detail, const char *json, size_t len)
{
  sd_err se;
  if (hk->replied)
    return;
  hk->replied = 1;
  if (g.srv == NULL)
    return;
  se = sd_ipc_reply_deferred(g.srv, hk->defer_cid, hk->defer_rid, e, code, detail, json, len);
  if (se != SD_OK && se != SD_E_NOT_FOUND)
    SD_LOGW("svc", "hostkey add reply for %Hs not sent (%s)", hk->lookup, sd_err_name(se));
}

/* The keys of a finished hostkey connection: the requested type only, fingerprints recomputed from the blobs. With
   expect the one key with that fingerprint goes to the machine store with no question (scripts); otherwise the keys are
   kept as an announcement (hostkey.announced.accept {id, add_only: true} stores them after the administrator's yes).
   Writes the reply members into jw (the caller opened and closes the object); on failure sets *code and detail. */
static sd_err svc_hk_complete(sd_json_writer *jw, const svc_hk *hk, sd_mount_hk_fetch *f, const char **code, char *detail,
                              size_t cap)
{
  uint32_t i, n = 0;
  int found = -1;
  const char *type = hk->type[0] ? hk->type : NULL;
  const char *expect = hk->expect[0] ? hk->expect : NULL;
  int verified = f->verified != 0;
  for (i = 0; i < f->count; i++) {
    if (type != NULL && strcmp(f->keys[i].type, type) != 0)
      continue;
    if (sd_hostkey_fingerprint_sha256(f->keys[i].blob, f->keys[i].len, f->keys[i].fp_sha256) != SD_OK)
      continue;
    if (n != i)
      f->keys[n] = f->keys[i];
    n++;
  }
  f->count = n;
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, hk->host);
  sd_jw_key(jw, "lookup_name"); sd_jw_cstr(jw, hk->lookup);
  sd_jw_key(jw, "verified"); sd_jw_bool(jw, verified);
  if (expect != NULL) {
    sd_mount_announcement *a;
    sd_err e;
    for (i = 0; i < n; i++)
      if (strcmp(f->keys[i].fp_sha256, expect) == 0) { found = (int)i; break; }
    if (found < 0) {
      *code = verified ? "host_key_mismatch" : "host_key_rejected";
      strcpy_s(detail, cap, "no key of the server has that fingerprint");
      return verified ? SD_E_HOSTKEY_MISMATCH : SD_E_HOSTKEY_REJECTED;
    }
    a = (sd_mount_announcement *)sd_calloc(1, sizeof(*a));
    if (a == NULL) {
      *code = NULL;
      strcpy_s(detail, cap, "out of memory");
      return SD_E_NO_MEMORY;
    }
    a->add[0] = f->keys[found];
    a->add_count = 1;
    strcpy_s(a->host, sizeof(a->host), hk->host);
    strcpy_s(a->lookup_name, sizeof(a->lookup_name), hk->lookup);
    e = svc_machine_apply(a, 1);
    sd_free(a);
    if (e != SD_OK) {
      *code = NULL;
      strcpy_s(detail, cap, "cannot update known_hosts");
      return e;
    }
    SD_LOGI("svc", "hostkey add: stored one key of %Hs (%s)", hk->lookup, verified ? "verified" : "first contact");
    sd_jw_key(jw, "added"); sd_jw_int(jw, 1);
    sd_jw_key(jw, "removed"); sd_jw_int(jw, 0);
    write_keys_json(jw, "keys", f->keys, n);
    return SD_OK;
  }
  write_keys_json(jw, "keys", f->keys, n);
  if (n > 0) {
    sd_mount_announcement *a = (sd_mount_announcement *)sd_calloc(1, sizeof(*a));
    char id[16];
    if (a == NULL) {
      *code = NULL;
      strcpy_s(detail, cap, "out of memory");
      return SD_E_NO_MEMORY;
    }
    memcpy(a->add, f->keys, n * sizeof(f->keys[0]));
    a->add_count = n;
    strcpy_s(a->host, sizeof(a->host), hk->host);
    strcpy_s(a->lookup_name, sizeof(a->lookup_name), hk->lookup);
    if (!ann_keep("", a, 0, id, sizeof(id))) {
      sd_free(a);
      *code = NULL;
      strcpy_s(detail, cap, "out of memory");
      return SD_E_NO_MEMORY;
    }
    sd_free(a);
    sd_jw_key(jw, "id"); sd_jw_cstr(jw, id);
    SD_LOGI("svc", "hostkey add: %Hs offers %u key(s), kept for review (%s)", hk->lookup, (unsigned)n, id);
  }
  return SD_OK;
}

/* Control thread: the hostkey mount ended (final); the deferred hostkey.add request is answered once. */
static void svc_hk_reply(svc_hk *hk, sd_mount *m, sd_err why)
{
  sd_mount_hk_fetch *f = NULL;
  sd_mount_failure fl;
  sd_wr d;
  sd_json_writer jw;
  const char *code = NULL;
  char detail[256];
  sd_err e = why;
  int ok = 0;
  detail[0] = 0;
  if (why == SD_OK) {
    f = (sd_mount_hk_fetch *)sd_calloc(1, sizeof(*f));
    e = f == NULL ? SD_E_NO_MEMORY : sd_mount_get_hostkeys(m, f);
    /* a connection that ended before the keys were read (a stop) is a failure, not an empty answer */
    if (e == SD_OK && f->verified == 0 && f->count == 0)
      e = SD_E_FAILURE;
  }
  if (e == SD_OK) {
    sd_wr_init(&d, 16 * 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    e = svc_hk_complete(&jw, hk, f, &code, detail, sizeof(detail));
    if (e == SD_OK) {
      sd_jw_obj_end(&jw);
      if (sd_jw_finish(&jw) == SD_OK) {
        ok = 1;
      } else {
        e = SD_E_INTERNAL;
        code = NULL;
        strcpy_s(detail, sizeof(detail), "reply too large");
      }
    }
    if (ok)
      svc_hk_send(hk, SD_OK, NULL, NULL, (const char *)d.p, d.len);
    sd_wr_free(&d);
  }
  if (!ok) {
    /* the mount's recorded failure decides the code, whatever the state's reason says (the failure may be reported
       with SD_OK as its reason) */
    memset(&fl, 0, sizeof(fl));
    sd_mount_get_failure(m, &fl);
    if (fl.err != SD_OK || why != SD_OK) {
      if (fl.err != SD_OK)
        e = fl.err;
      code = NULL;
      detail[0] = 0;
      hk_error_text(e, fl.code, &code, detail, sizeof(detail));
      if (fl.detail[0] != 0 && code != NULL && strcmp(code, "connect_failed") == 0)
        strcpy_s(detail, sizeof(detail), fl.detail);
    } else if (code == NULL && detail[0] == 0) {
      code = "connect_failed";
      strcpy_s(detail, sizeof(detail), "cannot get the host keys of the server");
    }
    svc_hk_send(hk, e, code, detail, NULL, 0);
  }
  sd_free(f);
}

static void svc_hk_on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  svc_hk *hk = (svc_hk *)ctx;
  if (hk == NULL || hk->replied)
    return;
  if (st != SD_MOUNT_UNMOUNTED && st != SD_MOUNT_FAILED)
    return;
  if (!sd_mount_is_final(m))
    return;
  svc_hk_reply(hk, m, why);
}

/* A hostkey connection raises no routed prompt: the host-key question is taken by sd_mount itself (first contact, 5.2),
   and every other prompt (a password or a passphrase the service cannot ask for, 2.6) is refused. */
static void svc_hk_on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  svc_hk *hk = (svc_hk *)ctx;
  if (p->kind == SD_MP_HOSTKEY)     /* only a jump host's key reaches here (sd_mount takes the target's first contact) */
    SD_LOGW("svc", "hostkey add for %Hs: the key of jump host %Hs is not in the machine store: refused (add it first)",
            hk ? hk->lookup : "", p->host);
  else
    SD_LOGW("svc", "hostkey add for %Hs asked for a %s prompt: refused (no one can answer it)",
            hk ? hk->lookup : "", sd_mount_prompt_kind_name(p->kind));
  (void)sd_mount_answer(m, p->id, SD_MA_REJECT, 0, NULL);
}

/* Control thread: starts the connect-only mount of one hostkey.add with the machine profile's service credentials. */
static void job_hk_start(void *arg)
{
  svc_hk *hk = (svc_hk *)arg;
  sd_mount_params pr;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  wchar_t hostw[256], namew[160];
  svc_chain *chain = NULL;          /* the hops (TM-R27 key bytes inside), wiped after sd_mount_create copied them */
  sd_kh_store store;
  const sd_profile *p = &hk->prof->p;
  const char *why = NULL;
  uint32_t methods = 0;
  sd_err e = SD_OK;

  memset(&pr, 0, sizeof(pr));
  pr.struct_size = sizeof(pr);
  wide_from_utf8(p->host, hostw, SD_COUNTOF(hostw));
  pr.host = hostw;
  pr.port = p->port ? p->port : 22;
  pr.user = p->user;
  if (p->user[0] == 0)
    why = "service profile without a user";
  if (p->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) methods |= SD_AUTH_PUBLICKEY;
  if (p->auth_methods & SD_PROFILE_AUTH_PASSWORD) methods |= SD_AUTH_PASSWORD;
  if (methods == 0 && why == NULL)
    why = "no non-interactive authentication method";
  pr.auth_methods = methods;
  if (why == NULL) {
    why = svc_chain_build(&chain, p, SD_HKU_NO);
    if (why == NULL) {
      pr.hops = chain->hop;
      pr.hop_count = chain->count;
    }
  }
  if (why == NULL)
    why = svc_kh_read_check();
  if (why == NULL) {
    /* the machine store is read here (the stored types decide what the server offers); writes are the accept's (5.6) */
    memset(&store, 0, sizeof(store));
    store.kind = SD_KH_STORE_MACHINE;
    store.path = g.kh;
    store.writable = 0;
    pr.kh_stores = &store;
    pr.kh_store_count = 1;
    pr.hostkey_fetch = 1;                       /* connect-only: no sftp, no vfs, no drive (03 §6.1) */
    pr.hostkey_type = hk->type[0] ? hk->type : NULL;
    wide_from_utf8(p->name, namew, SD_COUNTOF(namew));
    pr.profile_name = namew;
    pr.backend = SD_MOUNT_BACKEND_DOKANY;
    pr.global_mount = 0;
    pr.letter = 0;                              /* a hostkey mount has no drive (params.hostkey_fetch) */
    pr.connections = 1;
    pr.no_secret_cache = 1;                     /* the service never keeps a secret it was given (2.5) */
    pr.legacy_policy = p->legacy_algorithms;
    pr.refuse_terrapin_exposed = p->refuse_terrapin_exposed;
    memset(&cb, 0, sizeof(cb));
    cb.ctx = hk;
    cb.post = svc_post;
    cb.on_state = svc_hk_on_state;
    cb.on_prompt = svc_hk_on_prompt;
    cb.secret_get = svc_secret_get;
    cb.on_warning = svc_on_warning;
    cb.on_notice = svc_on_notice;
    e = sd_mount_create(g.be, &pr, &cb, &m);
  }
  svc_chain_free(chain);            /* sd_mount_create copied the strings and the key bytes */
  if (why != NULL) {
    SD_LOGW("svc", "hostkey add for %Hs refused: %s", hk->lookup, why);
    svc_hk_send(hk, SD_E_INVALID_PARAM, "usage", why, NULL, 0);
    return;
  }
  if (e != SD_OK) {
    SD_LOGW("svc", "hostkey add for %Hs: the connection cannot start (%s)", hk->lookup, sd_err_name(e));
    svc_hk_send(hk, e, "connect_failed", "cannot start the connection", NULL, 0);
    return;
  }
  hk->m = m;
  (void)sd_mount_start(m);       /* the reply comes through svc_hk_on_state */
}

/* Control thread, from svc_tick: a request whose reply is sent. Its mount is destroyed and the record leaves the list. */
static void svc_hk_release(svc_hk *hk)
{
  sd_mount *m = hk->m;
  svc_hk **pp;
  sd_mutex_lock(&g.lock);
  for (pp = &g.hks; *pp; pp = &(*pp)->next)
    if (*pp == hk) { *pp = hk->next; break; }
  g.nhk--;
  sd_mutex_unlock(&g.lock);
  hk->m = NULL;
  if (m)
    sd_mount_destroy(m);
  sd_free(hk->prof);
  sd_free(hk);
}

/* ---- control-thread jobs ---- */

static svc_gw_client svc_gw_client_of(sd_webdav_client_state s)
{
  switch (s) {
  case SD_WD_CLIENT_RUNNING: return SVC_GW_CLIENT_RUNNING;
  case SD_WD_CLIENT_STOPPED: return SVC_GW_CLIENT_STOPPED;
  case SD_WD_CLIENT_DISABLED: return SVC_GW_CLIENT_DISABLED;
  case SD_WD_CLIENT_MISSING: return SVC_GW_CLIENT_MISSING;
  default: return SVC_GW_CLIENT_UNKNOWN;
  }
}

/* 02 §7.7, the M5 spike: the mechanism of a global WebDAV mount. Only attach is built; it is what auto resolves to
   while the compiled table has no GO cell. A system or link verdict (a lab-flipped cell) is refused here until that
   mechanism exists, never served as attach. The mode is always auto: the service does not read settings.ini
   (webdav_global_mode needs the checked read of TM-R27 first). NULL = attach, else an English reason (log, usage). */
static const char *svc_webdav_mechanism(void)
{
  svc_gw_input in;
  svc_gw_verdict v;
  sd_webdav_client_info ci;
  const sd_os_version *ov = sd_os_version_get();
  memset(&in, 0, sizeof(in));
  memset(&ci, 0, sizeof(ci));
  in.family = ov ? svc_gw_family_of(ov->major, ov->minor) : SVC_GW_OS_UNKNOWN;
  in.mode = SVC_GW_MODE_AUTO;
  in.service_running = 1;
  in.client = g.be->webdav_query_client ? svc_gw_client_of(g.be->webdav_query_client(&ci)) : SVC_GW_CLIENT_MISSING;
  in.token_only = 0;
  svc_gw_decide(&in, &v);
  if (v.mech == SVC_GW_ATTACH)
    return NULL;
  if (v.mech == SVC_GW_REFUSE) {
    SD_LOGW("svc", "global WebDAV refused: %s", svc_gw_reason_name(v.reason));
    return svc_gw_reason_name(v.reason);
  }
  SD_LOGW("svc", "global WebDAV mechanism %s is not built (attach only)", svc_gw_mech_name(v.mech));
  return "this global WebDAV mechanism is not in this build (attach only, 02 7.7)";
}

static void job_start(void *arg)
{
  svc_job *j = (svc_job *)arg;
  svc_mount *r;
  sd_mount_params pr;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  wchar_t hostw[256], labelw[160], namew[160], fsw[32];
  wchar_t wsddl_buf[1024];
  char sddl[1024];
  PSECURITY_DESCRIPTOR sd_bytes = NULL;
  ULONG sd_len = 0;
  svc_chain *chain = NULL;          /* the hops; key bytes (TM-R27) are wiped after sd_mount_create copied them */
  PSID acc_sids[SVC_ACL_MAX], wr_sids[SVC_ACL_MAX];   /* M5: per-request lists (LocalFree after sd_mount_create) */
  uint32_t n_acc_s = 0, n_wr_s = 0, k;
  sd_kh_store store;
  sd_err e;
  const char *why = NULL;
  uint32_t methods = 0;

  sd_mutex_lock(&g.lock);
  r = find_by_id_locked(j->id);
  if (r == NULL || r->stop_req) {
    if (r) r->final = 1;
    sd_mutex_unlock(&g.lock);
    sd_free(j);
    return;
  }
  sd_mutex_unlock(&g.lock);
  /* the record's profile and letter never change, and only this thread frees the record */
  {
    const sd_profile *p = &r->prof->p;
    memset(&pr, 0, sizeof(pr));
    pr.struct_size = sizeof(pr);
    wide_from_utf8(p->host, hostw, SD_COUNTOF(hostw));
    pr.host = hostw;
    pr.port = p->port ? p->port : 22;
    pr.user = p->user;
    if (p->user[0] == 0) why = "service profile without a user";
    if (p->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) methods |= SD_AUTH_PUBLICKEY;
    if (p->auth_methods & SD_PROFILE_AUTH_PASSWORD) methods |= SD_AUTH_PASSWORD;
    if (methods == 0) why = "no non-interactive authentication method";
    pr.auth_methods = methods;
    if (why == NULL) {
      /* 2.6 rule 1, TM-R27: the key bytes go to sd_mount as key blobs, so the mount never opens a path again */
      why = svc_chain_build(&chain, p, SD_HKU_ASK);
      if (why == NULL) {
        pr.hops = chain->hop;
        pr.hop_count = chain->count;
      }
    }
    pr.remote_path = p->remote_path;
    pr.letter = r->letter;
    pr.read_only = p->read_only;
    pr.symlinks = p->symlinks;
    {
      /* M4 (03 §3.4, §3.5): the effective write mode, [defaults] write_mode for an unset key (see the agent) */
      sd_settings st;
      DWORD fv = 0;
      int wm = p->write_mode;
      int force = sd_policy_get_dword(SD_POLICY_FORCEWRITETHROUGH, &fv) && fv != 0;
      sd_settings_defaults(&st);
      (void)sd_settings_load(&st);
      if (why == NULL && sd_profile_effective_write_mode(p, &st, force, &wm) != SD_OK)
        why = "write mode behind is not allowed by policy";
      pr.write_mode = wm;
    }
    wide_from_utf8(p->label[0] ? p->label : p->name, labelw, SD_COUNTOF(labelw));
    pr.volume_label = labelw;
    wide_from_utf8(p->name, namew, SD_COUNTOF(namew));
    pr.profile_name = namew;
    /* D11, 02 §7.7: Dokany is the global path; a profile forced to WebDAV is hosted by the service and
       attached per user at logon (attach), never mapped by LocalSystem (mechanism A is a no-go). */
    pr.backend = p->backend == SD_PROFILE_BACKEND_WEBDAV ? SD_MOUNT_BACKEND_WEBDAV : SD_MOUNT_BACKEND_DOKANY;
    if (why == NULL && pr.backend == SD_MOUNT_BACKEND_WEBDAV)
      why = svc_webdav_mechanism();
    pr.global_mount = 1;
    pr.legacy_policy = p->legacy_algorithms;
    pr.refuse_terrapin_exposed = p->refuse_terrapin_exposed;
    pr.compression = p->compression;
    pr.connections = 1;
    pr.no_secret_cache = p->cache_secrets ? 0 : 1;
    pr.offline_wait_ms = p->offline_wait_ms;
    pr.reconnect_grace_ms = p->reconnect_grace_ms;
    pr.channels = p->channels;
    pr.tuning.attr_ttl_ms = p->attr_ttl_ms;
    pr.tuning.dir_ttl_ms = p->dir_ttl_ms;
    pr.tuning.neg_ttl_ms = p->neg_ttl_ms;
    pr.tuning.open_revalidate_ms = p->open_revalidate_ms;
    pr.tuning.max_readahead = p->max_readahead;
    pr.tuning.umask = p->umask;
    pr.tuning.hide_dotfiles = p->hide_dotfiles;
    pr.tuning.map_readonly = p->map_readonly;
    pr.tuning.show_special = p->show_special;
    pr.tuning.case_sensitive = p->case_sensitive;
    pr.tuning.fsync_on_flush = p->fsync_on_flush;
    pr.tuning.remote_case = p->remote_case;
    pr.tuning.shell_active_show = sd_profile_block_shell_active(p) ? 0 : 1;   /* D41 */
    pr.tuning.identity_probe_exec = p->identity_probe_exec;
    wide_from_utf8(p->fs_name, fsw, SD_COUNTOF(fsw));
    wcsncpy_s(pr.tuning.fs_name, SD_COUNTOF(pr.tuning.fs_name), fsw, _TRUNCATE);
    /* known_hosts: the machine store only, read-only for the service (5.1, 5.6); checked like a write before it is read */
    if (why == NULL)
      why = svc_kh_read_check();
    memset(&store, 0, sizeof(store));
    store.kind = SD_KH_STORE_MACHINE;
    store.path = g.kh;
    store.writable = 0;
    pr.kh_stores = &store;
    pr.kh_store_count = 1;
    /* the volume security descriptor carries service_access and service_access_write (D35, 02 §6.4) */
    if (why == NULL && svc_volume_sddl(&r->prof->acl, sddl, sizeof(sddl)) != SD_OK)
      why = "service_access does not encode";
    if (why == NULL) {
      wide_from_utf8(sddl, wsddl_buf, SD_COUNTOF(wsddl_buf));
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wsddl_buf, SDDL_REVISION_1, &sd_bytes, &sd_len))
        why = "service_access does not encode";
    }
    if (why == NULL) {
      pr.volume_sd = sd_bytes;
      pr.volume_sd_len = sd_len;
    }
    /* the same lists as SIDs for the per-request check in sd_vfs (M5, 02 6.7, 7.7); sd_mount copies them */
    for (k = 0; why == NULL && k < r->prof->acl.n_access; k++) {
      acc_sids[n_acc_s] = sid_of(r->prof->acl.access[k]);
      if (acc_sids[n_acc_s] == NULL)
        why = "service_access does not resolve";
      else
        n_acc_s++;
    }
    for (k = 0; why == NULL && k < r->prof->acl.n_write; k++) {
      wr_sids[n_wr_s] = sid_of(r->prof->acl.write[k]);
      if (wr_sids[n_wr_s] == NULL)
        why = "service_access_write does not resolve";
      else
        n_wr_s++;
    }
    pr.access_sids = acc_sids;
    pr.n_access = n_acc_s;
    pr.write_sids = wr_sids;
    pr.n_write = n_wr_s;
  }
  if (why != NULL) {
    for (k = 0; k < n_acc_s; k++)
      LocalFree(acc_sids[k]);
    for (k = 0; k < n_wr_s; k++)
      LocalFree(wr_sids[k]);
    sd_mutex_lock(&g.lock);
    r->final = 1;
    r->st = SD_MOUNT_FAILED;
    strcpy_s(r->err_code, sizeof(r->err_code), "usage");
    strcpy_s(r->err_detail, sizeof(r->err_detail), why);
    sd_mutex_unlock(&g.lock);
    SD_LOGW("svc", "mount %s refused: %s", j->id, why);
    svc_chain_free(chain);
    announce_state(j->id, r->letter, "failed");
    sd_free(j);
    return;
  }
  memset(&cb, 0, sizeof(cb));
  cb.post = svc_post;
  cb.on_state = svc_on_state;
  cb.on_prompt = svc_on_prompt;
  cb.on_prompt_closed = svc_on_prompt_closed;
  cb.on_write_failed = svc_on_write_failed;
  cb.on_notice = svc_on_notice;
  cb.on_audit = svc_on_audit;
  cb.secret_get = svc_secret_get;
  cb.on_warning = svc_on_warning;
  cb.on_hostkeys_announced = svc_on_hostkeys;
  e = sd_mount_create(g.be, &pr, &cb, &m);
  svc_chain_free(chain);            /* sd_mount_create copied the strings and the key bytes */
  if (sd_bytes) LocalFree(sd_bytes);
  for (k = 0; k < n_acc_s; k++)
    LocalFree(acc_sids[k]);
  for (k = 0; k < n_wr_s; k++)
    LocalFree(wr_sids[k]);
  if (e != SD_OK) {
    sd_mutex_lock(&g.lock);
    r->final = 1;
    r->st = SD_MOUNT_FAILED;
    strcpy_s(r->err_code, sizeof(r->err_code), sd_err_name(e));
    strcpy_s(r->err_detail, sizeof(r->err_detail), "mount create failed");
    sd_mutex_unlock(&g.lock);
    announce_state(j->id, r->letter, "failed");
    sd_free(j);
    return;
  }
  sd_mutex_lock(&g.lock);
  r->m = m;
  r->started = 1;
  sd_mutex_unlock(&g.lock);
  sd_free(j);
  (void)sd_mount_start(m);       /* completion comes through svc_on_state */
}

static void job_stop(void *arg)
{
  svc_job *j = (svc_job *)arg;
  svc_mount *r;
  sd_mount *m = NULL;
  sd_mutex_lock(&g.lock);
  r = find_by_id_locked(j->id);
  if (r) {
    r->stop_req = 1;
    m = r->m;
    if (m == NULL)
      r->final = 1;            /* never created: the tick removes it */
  }
  sd_mutex_unlock(&g.lock);
  /* a failed mount that is already torn down needs no further stop; the tick removes its record */
  if (m && !sd_mount_is_final(m))
    (void)sd_mount_stop_ex(m, j->force);
  sd_free(j);
}

/* Destroys a mount whose teardown is complete and removes its record (control thread). */
static void reap_mount(svc_mount *r)
{
  sd_mount *m;
  uint32_t i;
  int reaped_prompts = 0;
  sd_mutex_lock(&g.reap);
  sd_mutex_lock(&g.lock);
  m = r->m;
  r->m = NULL;
  for (i = 0; i < SVC_MAX_PROMPTS; i++) {
    if (g.prompts[i].used && g.prompts[i].mount == r) {
      g.prompts[i].used = 0;
      reaped_prompts = 1;
    }
  }
  sd_mutex_unlock(&g.lock);
  if (m)
    sd_mount_destroy(m);
  if (reaped_prompts)
    svc_broadcast_attention();
  sd_mutex_unlock(&g.reap);
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] == r) {
      g.mounts[i] = NULL;
      break;
    }
  sd_mutex_unlock(&g.lock);
  SD_LOGI("svc", "mount %s removed", r->id);
  sd_free(r->prof);
  sd_free(r);
}

/* Control thread, from svc_mount_queue: releases a final failed record that a new mount of the same profile
   detached from the table. The teardown is the tick's own reap after an unmount: the sd_mount already ended
   (or was never created), and prompts of the record, if any, are dropped with it. */
static void job_reap_failed(void *arg)
{
  reap_mount((svc_mount *)arg);
}

/* Control-thread timer: reaps finished mounts, expires open prompts (2.5). */
static void svc_tick(void)
{
  svc_mount *reap[SVC_MAX_MOUNTS];
  uint32_t n = 0, i, nexp = 0;
  struct { char mid[16]; sd_mount *m; uint32_t mprompt; } expired[SVC_MAX_PROMPTS];
  uint64_t now = svc_now();
  memset(expired, 0, sizeof(expired));
  /* only this thread creates, destroys and removes records, so they stay valid after the lock is released; sd_mount
     is queried outside g.lock (lock order: sd_mount never waits on g.lock while we hold it) */
  sd_mutex_lock(&g.lock);
  /* a failed mount keeps its record and letter until the user unmounts it (1.11): reap only after a stop */
  for (i = 0; i < SVC_MAX_MOUNTS; i++) {
    if (g.mounts[i] && g.mounts[i]->final && g.mounts[i]->stop_req)
      reap[n++] = g.mounts[i];
  }
  for (i = 0; i < SVC_MAX_PROMPTS; i++) {
    svc_prompt *s = &g.prompts[i];
    if (s->used && now >= s->deadline && nexp < SVC_MAX_PROMPTS) {
      s->used = 0;
      strcpy_s(expired[nexp].mid, sizeof(expired[nexp].mid), s->mount_id);
      expired[nexp].m = s->mount ? s->mount->m : NULL;
      expired[nexp].mprompt = s->mprompt;
      nexp++;
    }
  }
  sd_mutex_unlock(&g.lock);
  for (i = 0; i < nexp; i++) {
    if (expired[i].m)
      (void)sd_mount_answer(expired[i].m, expired[i].mprompt, SD_MA_REJECT, 0, NULL);
    SD_LOGW("svc", "a service prompt expired without an answer (%s)", expired[i].mid);
  }
  if (nexp > 0)
    svc_broadcast_attention();
  for (i = 0; i < n; i++) {
    svc_mount *r = reap[i];
    if (r->m == NULL || sd_mount_is_final(r->m))
      reap_mount(r);
  }
  /* hostkey requests whose reply went out: their mounts are final, so they are destroyed here (control thread) */
  {
    svc_hk *done[SVC_MAX_HK];
    svc_hk *h;
    uint32_t nd = 0;
    sd_mutex_lock(&g.lock);
    for (h = g.hks; h != NULL && nd < SVC_MAX_HK; h = h->next)
      if (h->replied)
        done[nd++] = h;
    sd_mutex_unlock(&g.lock);
    for (i = 0; i < nd; i++)
      svc_hk_release(done[i]);
  }
}

static void svc_shutdown_all(void)
{
  uint32_t i, waited = 0;
  for (i = 0; i < SVC_MAX_MOUNTS; i++) {
    svc_mount *r;
    svc_job *j;
    sd_mutex_lock(&g.lock);
    r = g.mounts[i];
    j = NULL;
    if (r && !r->stop_req) {
      j = (svc_job *)sd_calloc(1, sizeof(*j));
      if (j) {
        strcpy_s(j->id, sizeof(j->id), r->id);
        j->force = 1;
      }
    }
    sd_mutex_unlock(&g.lock);
    if (j)
      job_stop(j);
  }
  /* hostkey connections still open are stopped; their replies go out as they end (svc_hk_on_state) */
  {
    sd_mount *hm[SVC_MAX_HK];
    svc_hk *h;
    uint32_t nh = 0;
    sd_mutex_lock(&g.lock);
    for (h = g.hks; h != NULL && nh < SVC_MAX_HK; h = h->next)
      if (h->m != NULL && !h->replied)
        hm[nh++] = h->m;
    sd_mutex_unlock(&g.lock);
    for (i = 0; i < nh; i++)
      (void)sd_mount_stop_ex(hm[i], 1);
  }
  /* run the teardown: the control loop is gone, so pump the queue and the tick here */
  while (waited < SVC_SHUTDOWN_MS) {
    int pending = 0;
    svc_drain();
    svc_tick();
    sd_mutex_lock(&g.lock);
    for (i = 0; i < SVC_MAX_MOUNTS; i++)
      if (g.mounts[i]) pending = 1;
    if (g.nhk > 0)
      pending = 1;
    sd_mutex_unlock(&g.lock);
    if (!pending)
      break;
    Sleep(50);
    waited += 50;
  }
  if (waited >= SVC_SHUTDOWN_MS)
    SD_LOGE("svc", "shutdown timed out with mounts still tearing down");
}

static void svc_loop(void)
{
  HANDLE hs[2];
  hs[0] = g.stop.h;
  hs[1] = g.wake.h;
  for (;;) {
    svc_drain();
    svc_tick();
    if (sd_event_wait(&g.stop, 0) == SD_OK)
      break;
    WaitForMultipleObjects(2, hs, FALSE, 1000);
  }
  svc_drain();
  svc_shutdown_all();
}

/* ---- pipe methods ---- */

static void write_summary(sd_json_writer *jw, svc_mount *r)
{
  char tgt[4], id[16];
  const char *state = sd_mount_state_name(r->st);
  target_of(r->letter, tgt);
  strcpy_s(id, sizeof(id), r->id);
  sd_jw_key(jw, "mount_id"); sd_jw_cstr(jw, id);
  sd_jw_key(jw, "target"); sd_jw_cstr(jw, tgt);
  sd_jw_key(jw, "state"); sd_jw_cstr(jw, state);
  sd_jw_key(jw, "label"); sd_jw_cstr(jw, r->prof->p.label[0] ? r->prof->p.label : r->prof->p.name);
}

static void write_details(sd_json_writer *jw, svc_mount *r)
{
  sd_jw_key(jw, "profile"); sd_jw_cstr(jw, r->prof->p.id);
  sd_jw_key(jw, "profile_name"); sd_jw_cstr(jw, r->prof->p.name);
  sd_jw_key(jw, "host"); sd_jw_cstr(jw, r->prof->p.host);
  sd_jw_key(jw, "port"); sd_jw_int(jw, r->prof->p.port ? r->prof->p.port : 22);
  sd_jw_key(jw, "user"); sd_jw_cstr(jw, r->prof->p.user);
  sd_jw_key(jw, "remote_path"); sd_jw_cstr(jw, r->prof->p.remote_path);
  sd_jw_key(jw, "backend"); sd_jw_cstr(jw, "dokany");
  sd_jw_key(jw, "global"); sd_jw_bool(jw, 1);
  if (r->final && r->err_code[0]) {
    sd_jw_key(jw, "last_error");
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "code"); sd_jw_cstr(jw, r->err_code);
    sd_jw_key(jw, "detail"); sd_jw_cstr(jw, r->err_detail);
    sd_jw_obj_end(jw);
  }
}

static sd_err handle_list(sd_ipc_client *c, sd_json_writer *res)
{
  uint32_t i;
  sd_jw_key(res, "mounts");
  sd_jw_arr_begin(res);
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_MOUNTS; i++) {
    svc_mount *r = g.mounts[i];
    svc_member mb;
    svc_rights rt;
    if (r == NULL)
      continue;
    member_of(c, &r->prof->acl, &mb);
    svc_decide(&mb, &rt);
    if (!rt.see_state)
      continue;
    sd_jw_obj_begin(res);
    write_summary(res, r);
    if (rt.see_details)
      write_details(res, r);
    sd_jw_obj_end(res);
  }
  sd_jw_arr_end(res);
  /* every other global mount shows its letter only (2.2, TM-R25) */
  sd_jw_key(res, "reserved_letters");
  sd_jw_arr_begin(res);
  for (i = 0; i < SVC_MAX_MOUNTS; i++) {
    svc_mount *r = g.mounts[i];
    svc_member mb;
    svc_rights rt;
    char tgt[4];
    if (r == NULL)
      continue;
    member_of(c, &r->prof->acl, &mb);
    svc_decide(&mb, &rt);
    if (rt.see_state)
      continue;
    target_of(r->letter, tgt);
    sd_jw_cstr(res, tgt);
  }
  sd_jw_arr_end(res);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* mount.attach_info {mount_id | target | profile} (02 §7.7, 03 §2.4): the export a member's agent maps in its own
   logon session. Only a caller in that profile's service_access gets it (D35); the reply carries the UNC with the
   path token, never a credential. A Dokany global mount has nothing to attach. Read-only, no administrator needed. */
static sd_err handle_attach_info(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  svc_mount *r;
  svc_member mb;
  svc_rights rt;
  char unc[256] = "", xp[256] = "", tgt[4], id[16];
  int webdav;
  sd_mutex_lock(&g.lock);
  r = find_mount_locked(params);
  if (r == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "mount_not_found", "no matching mount");
  }
  member_of(c, &r->prof->acl, &mb);
  svc_decide(&mb, &rt);
  if (!rt.use) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_ACCESS_DENIED, "access_denied", "the caller is not in service_access for this drive");
  }
  webdav = r->prof->p.backend == SD_PROFILE_BACKEND_WEBDAV;
  if (webdav) {
    utf8_from_wide(r->wd_remote, unc, sizeof(unc));
    utf8_from_wide(r->wd_remote_xp, xp, sizeof(xp));
  }
  strcpy_s(id, sizeof(id), r->id);
  target_of(r->letter, tgt);
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, id);
  sd_jw_key(res, "target"); sd_jw_cstr(res, tgt);
  sd_jw_key(res, "label"); sd_jw_cstr(res, r->prof->p.label[0] ? r->prof->p.label : r->prof->p.name);
  sd_jw_key(res, "backend");
  sd_jw_cstr(res, sd_mount_backend_kind_name(webdav ? SD_MOUNT_BACKEND_WEBDAV : SD_MOUNT_BACKEND_DOKANY));
  sd_jw_key(res, "state"); sd_jw_cstr(res, sd_mount_state_name(r->st));
  sd_jw_key(res, "attach"); sd_jw_bool(res, unc[0] != 0);
  if (unc[0]) {
    sd_jw_key(res, "unc"); sd_jw_cstr(res, unc);
    sd_jw_key(res, "xp_url"); sd_jw_cstr(res, xp);
    sd_jw_key(res, "port"); sd_jw_int(res, r->wd_port);
  }
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

static sd_err handle_status(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  svc_mount *r;
  svc_member mb;
  svc_rights rt;
  sd_mutex_lock(&g.lock);
  r = find_mount_locked(params);
  if (r == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "not_mounted", "no such global mount");
  }
  member_of(c, &r->prof->acl, &mb);
  svc_decide(&mb, &rt);
  if (!rt.see_state) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_ACCESS_DENIED, "access_denied", "not a user of this drive");
  }
  write_summary(res, r);
  if (rt.see_details)
    write_details(res, r);
  sd_mutex_unlock(&g.lock);
  return SD_OK;
}

/* The one code path that brings a global mount up (2.4 "mount"; 1.8 and 3.4.1 boot autostart): finds the loaded
   service profile `key`, refuses a duplicate of a live mount, picks the drive letter and publishes the record,
   then queues the start job for the control thread. A final failed record of the profile is no duplicate: `failed`
   is the terminal state of a mount (03 1.11), so it holds no live drive and the record is detached and released,
   its letter going to the new mount (03 1.11 keeps a failed record only until it is unmounted or replaced). Takes
   g.lock. Returns SD_OK and fills out_id and out_target; on failure returns the sd_err of the reply, with *code
   set (NULL for the plain errors) and detail filled. */
static sd_err svc_mount_queue(const char *key, const char *tgt, char out_id[16], char out_target[4],
                              const char **code, char detail[200])
{
  svc_prof *src;
  svc_prof *copy = NULL;
  svc_mount *r = NULL;
  wchar_t letter = 0;
  svc_job *job;
  uint32_t i, slot = SVC_MAX_MOUNTS;
  const char *bad = NULL, *why = NULL;
  sd_mutex_lock(&g.lock);
  src = find_profile_locked(key);
  if (src == NULL) {
    sd_mutex_unlock(&g.lock);
    *code = "profile_not_found";
    strcpy_s(detail, 200, "no machine profile of scope service with that id or name");
    return SD_E_NOT_FOUND;
  }
  if (svc_validate_profile(&src->p, &bad, &why) != SD_OK) {
    sd_mutex_unlock(&g.lock);
    *code = "usage";
    _snprintf_s(detail, 200, _TRUNCATE, "%s: %s", bad ? bad : "profile", why ? why : "refused");
    return SD_E_INVALID_PARAM;
  }
  {
    svc_mount *failed = NULL;         /* a final failed record of this profile, detached for release */
    for (i = 0; i < SVC_MAX_MOUNTS; i++) {
      svc_mount *old = g.mounts[i];
      if (old == NULL || strcmp(old->prof->p.id, src->p.id) != 0)
        continue;
      /* `already_mounted` protects a live mount (03 6.2 conflict, exit 10); a failed record of the profile never
         blocks a new mount (03 1.11: failed is terminal, the offline state is the one that keeps the drive). The
         record goes the way the tick releases an unmounted record, only now: detached here under g.lock, released
         by the control thread. A live record, or a failed one whose sd_mount has not ended yet, still answers
         already_mounted. */
      if (failed == NULL && old->final && old->st == SD_MOUNT_FAILED && !old->stop_req &&
          (old->m == NULL || sd_mount_is_final(old->m))) {
        failed = old;
        g.mounts[i] = NULL;
        old->stop_req = 1;
        continue;
      }
      sd_mutex_unlock(&g.lock);
      *code = "already_mounted";
      strcpy_s(detail, 200, "this profile is already mounted");
      return SD_E_EXISTS;
    }
    if (failed != NULL) {
      SD_LOGI("svc", "mount %s replaced by a new mount of the same profile", failed->id);
      svc_enqueue_locked(job_reap_failed, failed);   /* control thread: destroy r->m, drop the record */
    }
  }
  copy = (svc_prof *)sd_alloc(sizeof(*copy));
  if (copy == NULL) {
    sd_mutex_unlock(&g.lock);
    *code = NULL;
    strcpy_s(detail, 200, "out of memory");
    return SD_E_NO_MEMORY;
  }
  memcpy(copy, src, sizeof(*copy));
  /* the requested target wins over the profile's; "auto" (or nothing) picks a free letter (3.4.1 mount.target) */
  {
    const char *want = (tgt && tgt[0]) ? tgt : src->p.target;
    if (want[0] && _stricmp(want, "auto") != 0) {
      wchar_t wt[8];
      wide_from_utf8(want, wt, SD_COUNTOF(wt));
      letter = sd_parse_drive_letter(wt);
      if (letter == 0) {
        sd_mutex_unlock(&g.lock);
        sd_free(copy);
        *code = "invalid_target";
        strcpy_s(detail, 200, "the target is not a drive letter");
        return SD_E_INVALID_PARAM;
      }
    }
  }
  if (letter == 0)
    letter = pick_letter_locked();
  if (letter == 0 || letter_taken_locked(letter) || (GetLogicalDrives() & (1ul << (letter - L'A')))) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    *code = "target_in_use";
    strcpy_s(detail, 200, "no free drive letter for this mount");
    return SD_E_EXISTS;
  }
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] == NULL) {
      slot = i;
      break;
    }
  if (slot == SVC_MAX_MOUNTS) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    *code = "busy";
    strcpy_s(detail, 200, "too many global mounts");
    return SD_E_BUSY;
  }
  r = (svc_mount *)sd_calloc(1, sizeof(*r));
  if (r == NULL) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    *code = NULL;
    strcpy_s(detail, 200, "out of memory");
    return SD_E_NO_MEMORY;
  }
  g.next_mount++;
  _snprintf_s(r->id, sizeof(r->id), _TRUNCATE, "g-%u", (unsigned)g.next_mount);
  r->letter = letter;
  r->prof = copy;
  r->st = SD_MOUNT_CONNECTING;
  /* the job is allocated before the record is published: no record without a job to start it */
  job = (svc_job *)sd_calloc(1, sizeof(*job));
  if (job == NULL) {
    sd_mutex_unlock(&g.lock);
    sd_free(r->prof);
    sd_free(r);
    *code = NULL;
    strcpy_s(detail, 200, "out of memory");
    return SD_E_NO_MEMORY;
  }
  strcpy_s(job->id, sizeof(job->id), r->id);
  strcpy_s(out_id, 16, r->id);
  target_of(letter, out_target);
  g.mounts[slot] = r;
  sd_mutex_unlock(&g.lock);
  SD_LOGI("svc", "mount %s queued for %c:", r->id, (char)letter);
  svc_enqueue(job_start, job);
  return SD_OK;
}

static sd_err handle_mount(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *key = sd_json_get_str(params, "profile");
  const char *tgt = sd_json_get_str(params, "target");
  sd_err e;
  char id[16], target[4];
  const char *code = NULL;
  char detail[200];
  e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (key == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "mount needs a profile");
  e = svc_mount_queue(key, tgt, id, target, &code, detail);
  if (e != SD_OK)
    return fail(err, e, code, detail);
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, id);
  sd_jw_key(res, "target"); sd_jw_cstr(res, target);
  sd_jw_key(res, "state"); sd_jw_cstr(res, "connecting");
  return SD_OK;
}

/* 1.8 Boot: brings up every loaded machine profile whose [mount] autostart is boot (3.4.1) when the profiles
   were loaded or reloaded. The mounts go through the same queue as a "mount" request, so the SCM start is not
   blocked: RUNNING is reported first and the control thread starts each mount afterwards, each with its own
   sd_mount reconnect backoff — a network that is not up yet only delays the mount. A profile that is already
   mounted is left alone (a reload never double-mounts); every auto-mounted profile is logged at INFO. */
static void svc_autostart_boot_mounts(void)
{
  char ids[SVC_MAX_PROFILES][33], names[SVC_MAX_PROFILES][128];
  uint32_t n = 0, i;
  sd_mutex_lock(&g.lock);
  for (i = 0; i < g.nprofs && n < SVC_MAX_PROFILES; i++) {
    if (g.profs[i]->p.autostart != SD_PROFILE_AUTOSTART_BOOT)
      continue;
    strcpy_s(ids[n], sizeof(ids[n]), g.profs[i]->p.id);
    strcpy_s(names[n], sizeof(names[n]), g.profs[i]->p.name);
    n++;
  }
  sd_mutex_unlock(&g.lock);
  for (i = 0; i < n; i++) {
    sd_err e;
    const char *code = NULL;
    char id[16], target[4], detail[200];
    e = svc_mount_queue(ids[i], NULL, id, target, &code, detail);
    if (e == SD_OK)
      SD_LOGI("svc", "autostart boot: profile %s (%s) mounts as %s", ids[i], names[i], target);
    else if (e != SD_E_EXISTS)             /* already mounted: a reload keeps the one mount */
      SD_LOGW("svc", "autostart boot: profile %s not mounted: %s (%s)", ids[i], sd_err_name(e),
              code ? code : detail[0] ? detail : "");
  }
}

static sd_err handle_unmount(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  svc_mount *r;
  svc_job *job;
  int force = 0;
  char id[16];
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  sd_mutex_lock(&g.lock);
  r = find_mount_locked(params);
  if (r == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "not_mounted", "no such global mount");
  }
  strcpy_s(id, sizeof(id), r->id);
  (void)sd_json_get_bool(params, "force", &force);
  if (r->stop_req) {
    sd_mutex_unlock(&g.lock);
  } else {
    r->stop_req = 1;
    sd_mutex_unlock(&g.lock);
    job = (svc_job *)sd_calloc(1, sizeof(*job));
    if (job == NULL)
      return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
    strcpy_s(job->id, sizeof(job->id), id);
    job->force = force;
    svc_enqueue(job_stop, job);
  }
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, id);
  sd_jw_key(res, "state"); sd_jw_cstr(res, "unmounting");
  return SD_OK;
}

static sd_err handle_selftest(sd_json_writer *res)
{
  int healthy = 1;
  uint32_t n;
  sd_mutex_lock(&g.lock);
  n = g.nprofs;
  sd_mutex_unlock(&g.lock);
  if (g.idle) healthy = 0;
  sd_jw_key(res, "healthy"); sd_jw_bool(res, healthy);
  sd_jw_key(res, "checks");
  sd_jw_arr_begin(res);
  sd_jw_obj_begin(res);
  sd_jw_key(res, "name"); sd_jw_cstr(res, "pipe");
  sd_jw_key(res, "result"); sd_jw_cstr(res, "pass");
  sd_jw_obj_end(res);
  sd_jw_obj_begin(res);
  sd_jw_key(res, "name"); sd_jw_cstr(res, "layout");
  sd_jw_key(res, "result"); sd_jw_cstr(res, g.idle ? "fail" : "pass");
  if (g.idle) { sd_jw_key(res, "detail"); sd_jw_cstr(res, "machine folder refused (owner, reparse point or rights)"); }
  sd_jw_obj_end(res);
  sd_jw_obj_begin(res);
  sd_jw_key(res, "name"); sd_jw_cstr(res, "profiles");
  sd_jw_key(res, "result"); sd_jw_cstr(res, "pass");
  {
    char d[64];
    _snprintf_s(d, sizeof(d), _TRUNCATE, "%u loaded", (unsigned)n);
    sd_jw_key(res, "detail"); sd_jw_cstr(res, d);
  }
  sd_jw_obj_end(res);
  sd_jw_arr_end(res);
  return SD_OK;
}

/* secret.set / secret.delete with kind "proxy" (4.5, 3.8, 2.6 rule 1): the password of a proxy leg of the service. proxy
   is a spec without a password (sd_proxy_spec_parse refuses user:pass@), http://user@host:port or
   socks5://user@host:port; the target is the one svc_proxy_secret_present reads for that leg. The value is never
   echoed back, and the reply has no secret. */
static sd_err handle_proxy_secret(const char *spec, const char *value, int set, sd_json_writer *res, sd_ipc_error *err)
{
  sd_proxy_spec x;
  char target[SD_SECRET_MAX_TARGET];
  sd_err e;
  if (spec == NULL || (set && (value == NULL || value[0] == 0)))
    return fail(err, SD_E_INVALID_PARAM, "usage", "secret needs proxy and a non-empty value");
  if (sd_proxy_spec_parse(spec, &x) != SD_OK || (x.kind != SD_PROFILE_PROXY_HTTP && x.kind != SD_PROFILE_PROXY_SOCKS5) ||
      x.user[0] == 0)
    return fail(err, SD_E_INVALID_PARAM, "usage", "proxy needs http:// or socks5:// with a user and no password");
  e = sd_secret_target_proxy(x.kind == SD_PROFILE_PROXY_SOCKS5 ? "socks5" : "http", x.user, x.host, x.port, target,
                             sizeof(target));
  if (e != SD_OK)
    return fail(err, e, NULL, "bad target");
  if (set) {
    e = sd_secret_put(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, NULL, value, strlen(value));
    if (e != SD_OK)
      return fail(err, e, NULL, "secret store failed");
    sd_jw_key(res, "stored"); sd_jw_bool(res, 1);
  } else {
    e = sd_secret_delete(SD_SECRET_SERVICE, SD_SECRET_PROXY, target);
    if (e != SD_OK)
      return fail(err, e == SD_E_NOT_FOUND ? SD_E_NOT_FOUND : e, e == SD_E_NOT_FOUND ? "secret_not_found" : NULL,
                  "no such secret");
    sd_jw_key(res, "deleted"); sd_jw_bool(res, 1);
  }
  return SD_OK;
}

static sd_err handle_secret(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err, int set)
{
  const char *key = sd_json_get_str(params, "profile");
  const char *kind = sd_json_get_str(params, "kind");
  const char *value = set ? sd_json_get_str(params, "value") : "";
  svc_prof *p;
  char target[SD_SECRET_MAX_TARGET];
  wchar_t comment[160];
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (kind != NULL && strcmp(kind, "proxy") == 0)
    return handle_proxy_secret(sd_json_get_str(params, "proxy"), value, set, res, err);
  if (key == NULL || kind == NULL || value == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "secret needs profile, kind and value");
  if (strcmp(kind, "password") != 0)
    return fail(err, SD_E_UNSUPPORTED, "usage", "only password secrets are supported for service profiles in this build");
  sd_mutex_lock(&g.lock);
  p = find_profile_locked(key);
  if (p == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "profile_not_found", "no machine profile of scope service with that id or name");
  }
  e = sd_secret_target_password(p->p.user, p->p.host, p->p.port ? p->p.port : 22, target, sizeof(target));
  wide_from_utf8(p->p.name, comment, SD_COUNTOF(comment));
  sd_mutex_unlock(&g.lock);
  if (e != SD_OK)
    return fail(err, e, NULL, "bad target");
  if (set) {
    e = sd_secret_put(SD_SECRET_SERVICE, SD_SECRET_PASSWORD, target, comment, value, strlen(value));
    if (e != SD_OK)
      return fail(err, e, NULL, "secret store failed");
    sd_jw_key(res, "stored"); sd_jw_bool(res, 1);
  } else {
    e = sd_secret_delete(SD_SECRET_SERVICE, SD_SECRET_PASSWORD, target);
    if (e != SD_OK)
      return fail(err, e == SD_E_NOT_FOUND ? SD_E_NOT_FOUND : e, e == SD_E_NOT_FOUND ? "secret_not_found" : NULL,
                  "no such secret");
    sd_jw_key(res, "deleted"); sd_jw_bool(res, 1);
  }
  return SD_OK;
}

static sd_err handle_prompt_list(sd_ipc_client *c, sd_json_writer *res, sd_ipc_error *err)
{
  uint32_t i;
  sd_err e = need_admin(c, err);
  uint64_t now = svc_now();
  if (e != SD_OK)
    return e;
  sd_jw_key(res, "prompts");
  sd_jw_arr_begin(res);
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_PROMPTS; i++) {
    svc_prompt *s = &g.prompts[i];
    char pidstr[24];
    if (!s->used) continue;
    _snprintf_s(pidstr, sizeof(pidstr), _TRUNCATE, "p-%u", (unsigned)s->id);
    sd_jw_obj_begin(res);
    sd_jw_key(res, "prompt_id"); sd_jw_cstr(res, pidstr);
    sd_jw_key(res, "mount_id"); sd_jw_cstr(res, s->mount_id);
    sd_jw_key(res, "profile_id"); sd_jw_cstr(res, s->profile_id);
    /* the same fields as prompt.request (2.5), so an administrator UI that connects late can show the dialog */
    sd_jw_key(res, "kind"); sd_jw_cstr(res, sd_mount_prompt_kind_name((sd_mount_prompt_kind)s->kind));
    sd_jw_key(res, "host"); sd_jw_cstr(res, s->host);
    sd_jw_key(res, "port"); sd_jw_int(res, s->port);
    sd_jw_key(res, "user"); sd_jw_cstr(res, s->user);
    sd_jw_key(res, "is_reconnect"); sd_jw_bool(res, s->is_reconnect);
    sd_jw_key(res, "can_save"); sd_jw_bool(res, 0);
    sd_jw_key(res, "queued"); sd_jw_bool(res, 0);
    sd_jw_key(res, "deadline_ms"); sd_jw_int(res, s->deadline > now ? (int64_t)(s->deadline - now) : 0);
    sd_jw_obj_end(res);
  }
  sd_mutex_unlock(&g.lock);
  sd_jw_arr_end(res);
  return SD_OK;
}

static sd_err handle_prompt_answer(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *pid = sd_json_get_str(params, "prompt_id");
  const char *action = sd_json_get_str(params, "action");
  const sd_json *responses = sd_json_get(params, "responses");
  const char *resp[SD_MOUNT_PROMPT_MAX_ITEMS];
  uint32_t n = 0, i;
  sd_mount *m = NULL;
  uint32_t mprompt = 0;
  uint32_t slot = SVC_MAX_PROMPTS;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (pid == NULL || action == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "prompt.answer needs prompt_id and action");
  if (responses && sd_json_type_of(responses) == SD_JSON_ARRAY) {
    for (i = 0; i < sd_json_count(responses) && n < SD_MOUNT_PROMPT_MAX_ITEMS; i++) {
      const char *s = sd_json_str(sd_json_at(responses, i), NULL);
      resp[n++] = s ? s : "";
    }
  }
  {
    uint32_t want = 0;
    if (sscanf_s(pid, "p-%u", &want) != 1)
      return fail(err, SD_E_NOT_FOUND, "not_found", "no such prompt");
    sd_mutex_lock(&g.reap);
    sd_mutex_lock(&g.lock);
    for (i = 0; i < SVC_MAX_PROMPTS; i++)
      if (g.prompts[i].used && g.prompts[i].id == want) {
        slot = i;
        break;
      }
    if (slot == SVC_MAX_PROMPTS) {
      sd_mutex_unlock(&g.lock);
      sd_mutex_unlock(&g.reap);
      return fail(err, SD_E_NOT_FOUND, "not_found", "no such prompt");
    }
    m = g.prompts[slot].mount ? g.prompts[slot].mount->m : NULL;
    mprompt = g.prompts[slot].mprompt;
    g.prompts[slot].used = 0;
    sd_mutex_unlock(&g.lock);
    if (m) {
      if (strcmp(action, "accept") == 0 || strcmp(action, "answer") == 0)
        (void)sd_mount_answer(m, mprompt, SD_MA_RESPONSES, n, resp);
      else
        (void)sd_mount_answer(m, mprompt, SD_MA_REJECT, 0, NULL);
    }
    sd_mutex_unlock(&g.reap);
  }
  svc_broadcast_attention();
  (void)res;
  return SD_OK;
}

static sd_err handle_config_reload(sd_ipc_client *c, sd_json_writer *res, sd_ipc_error *err)
{
  uint32_t n;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  n = svc_load_profiles();
  svc_autostart_boot_mounts();
  sd_jw_key(res, "profiles");
  sd_jw_obj_begin(res);
  sd_jw_key(res, "loaded"); sd_jw_int(res, n);
  sd_jw_key(res, "errors"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  sd_jw_obj_end(res);
  sd_jw_key(res, "settings"); sd_jw_cstr(res, "unchanged");
  sd_jw_key(res, "restart_required"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  return SD_OK;
}

/* hostkey.add {host, port, lookup, type?, expect?, profile?} (03 §2.4, §6.1): the machine profile whose host and port
   match (or the one named by profile) connects through a hostkey mount with its service credentials. The reply is
   deferred until the connection ends; it is the agent's reply shape (host, lookup_name, verified, keys, id or added). */
static sd_err handle_hk_add(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *host = sd_json_get_str(params, "host");
  const char *lookup = sd_json_get_str(params, "lookup");
  const char *type = sd_json_get_str(params, "type");
  const char *expect = sd_json_get_str(params, "expect");
  const char *key = sd_json_get_str(params, "profile");
  const char *bad = NULL, *why = NULL;
  int64_t port = 22;
  svc_prof *src = NULL, *copy;
  svc_hk *hk;
  sd_err e = need_admin(c, err);
  uint32_t i;
  char detail[200];
  if (e != SD_OK)
    return e;
  sd_json_get_int64(params, "port", &port);
  if (host == NULL || host[0] == 0 || lookup == NULL || lookup[0] == 0 || port < 1 || port > 65535)
    return fail(err, SD_E_INVALID_PARAM, "usage", "host, port and lookup required");
  if (strlen(host) >= 256 || strlen(lookup) >= 300)
    return fail(err, SD_E_INVALID_PARAM, "usage", "host or lookup too long");
  if (type != NULL && !hk_type_ok(type))
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid key type");
  if (expect != NULL && strlen(expect) >= 96)
    return fail(err, SD_E_INVALID_PARAM, "usage", "invalid fingerprint");
  if (sd_event_wait(&g.stop, 0) == SD_OK)
    return fail(err, SD_E_BUSY, "busy", "the service is stopping");
  copy = (svc_prof *)sd_alloc(sizeof(*copy));
  if (copy == NULL)
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  sd_mutex_lock(&g.lock);
  if (g.nhk >= SVC_MAX_HK) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    return fail(err, SD_E_BUSY, "busy", "too many host key requests");
  }
  for (i = 0; i < g.nprofs && src == NULL; i++) {
    const svc_prof *q = g.profs[i];
    uint16_t qp = q->p.port ? q->p.port : 22;
    if (_stricmp(q->p.host, host) != 0 || qp != (uint16_t)port)
      continue;
    if (key == NULL || strcmp(q->p.id, key) == 0 || _stricmp(q->p.name, key) == 0)
      src = g.profs[i];
  }
  if (src == NULL) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    return fail(err, SD_E_NOT_FOUND, "profile_not_found", "no machine profile of scope service uses this host and port");
  }
  memcpy(copy, src, sizeof(*copy));
  sd_mutex_unlock(&g.lock);
  if (svc_validate_profile(&copy->p, &bad, &why) != SD_OK) {
    sd_free(copy);
    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s: %s", bad ? bad : "profile", why ? why : "refused");
    return fail(err, SD_E_INVALID_PARAM, "usage", detail);
  }
  hk = (svc_hk *)sd_calloc(1, sizeof(*hk));
  if (hk == NULL) {
    sd_free(copy);
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  }
  hk->prof = copy;
  hk->port = (uint16_t)port;
  strcpy_s(hk->host, sizeof(hk->host), host);
  strcpy_s(hk->lookup, sizeof(hk->lookup), lookup);
  if (type != NULL)
    strcpy_s(hk->type, sizeof(hk->type), type);
  if (expect != NULL)
    strcpy_s(hk->expect, sizeof(hk->expect), expect);
  /* the request is answered when its connection ends (svc_hk_reply); taken before the record is linked */
  if (!sd_ipc_defer(c, &hk->defer_rid)) {
    sd_free(copy);
    sd_free(hk);
    return fail(err, SD_E_INTERNAL, NULL, "hostkey.add outside a request");
  }
  hk->defer_cid = sd_ipc_client_id(c);
  sd_mutex_lock(&g.lock);
  if (g.nhk >= SVC_MAX_HK) {
    sd_mutex_unlock(&g.lock);
    (void)sd_ipc_reply_deferred(g.srv, hk->defer_cid, hk->defer_rid, SD_E_BUSY, "busy", "too many host key requests",
                                NULL, 0);
    sd_free(copy);
    sd_free(hk);
    return SD_OK;
  }
  hk->next = g.hks;
  g.hks = hk;
  g.nhk++;
  sd_mutex_unlock(&g.lock);
  SD_LOGI("svc", "hostkey add for %Hs queued", lookup);
  svc_enqueue(job_hk_start, hk);
  (void)res;
  return SD_OK;
}

/* hostkey.announced.list (03 §2.4): the kept host keys, for an elevated administrator. */
static sd_err handle_hk_list(sd_ipc_client *c, sd_json_writer *res, sd_ipc_error *err)
{
  svc_ann *x;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  sd_jw_key(res, "announcements");
  sd_jw_arr_begin(res);
  sd_mutex_lock(&g.lock);
  for (x = g.anns; x != NULL; x = x->next)
    write_ann_obj(res, x->id, x->mount_id, &x->a, 0);
  sd_mutex_unlock(&g.lock);
  sd_jw_arr_end(res);
  return SD_OK;
}

/* hostkey.announced.reject {id} (5.6, 03 §2.4, elevated administrators): drops a kept announcement; no store is changed.
   The CLI sends it when the administrator answers no, so a refused offer leaves the list at once. */
static sd_err handle_hk_reject(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *id = sd_json_get_str(params, "id");
  svc_ann **pp, *x = NULL;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (id == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "id required");
  sd_mutex_lock(&g.lock);
  for (pp = &g.anns; *pp != NULL; pp = &(*pp)->next)
    if (strcmp((*pp)->id, id) == 0) {
      x = *pp;
      *pp = x->next;
      g.nann--;
      break;
    }
  sd_mutex_unlock(&g.lock);
  if (x == NULL)
    return fail(err, SD_E_NOT_FOUND, "announcement_not_found", "no such announcement");
  SD_LOGI("svc", "host keys of %Hs not added (%s rejected)", x->a.lookup_name, x->id);
  sd_jw_key(res, "host"); sd_jw_cstr(res, x->a.host);
  sd_jw_key(res, "rejected"); sd_jw_bool(res, 1);
  sd_free(x);
  return SD_OK;
}

/* hostkey.announced.accept {id, add_only} (5.6, 03 §2.4): writes a kept announcement to the machine known_hosts. The
   record leaves the list while it is written and returns to it when the write fails. */
static sd_err handle_hk_accept(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *id = sd_json_get_str(params, "id");
  int add_only = 0;
  svc_ann **pp, *x = NULL;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  sd_json_get_bool(params, "add_only", &add_only);
  if (id == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "id required");
  sd_mutex_lock(&g.lock);
  for (pp = &g.anns; *pp != NULL; pp = &(*pp)->next)
    if (strcmp((*pp)->id, id) == 0) {
      x = *pp;
      *pp = x->next;
      g.nann--;
      break;
    }
  sd_mutex_unlock(&g.lock);
  if (x == NULL)
    return fail(err, SD_E_NOT_FOUND, "announcement_not_found", "no such announcement");
  e = svc_machine_apply(&x->a, add_only);
  if (e != SD_OK) {
    sd_mutex_lock(&g.lock);                      /* keep it for another try */
    x->next = g.anns;
    g.anns = x;
    g.nann++;
    sd_mutex_unlock(&g.lock);
    return fail(err, e, NULL, "cannot update known_hosts");
  }
  SD_LOGI("svc", "machine host keys of %Hs updated (%u added, %u removed)", x->a.lookup_name,
          (unsigned)x->a.add_count, add_only ? 0u : (unsigned)x->a.remove_count);
  sd_jw_key(res, "host"); sd_jw_cstr(res, x->a.host);
  sd_jw_key(res, "added"); sd_jw_int(res, x->a.add_count);
  sd_jw_key(res, "removed"); sd_jw_int(res, add_only ? 0 : x->a.remove_count);
  sd_free(x);
  return SD_OK;
}

/* ---- service.status and service.repair_data (03 §2.4, §6.1) ---- */

/* The SCM seam of service.status: svc_opts.scm_ops, else the real calls. A test build with no seam never reaches the
   SCM (NULL: the report says "not installed"). */
static const svc_scm_ops *svc_scm_seam(svc_scm_ops *real)
{
  if (g.scm_ops != NULL)
    return g.scm_ops;
#ifdef SD_SVC_TEST_HOOKS
  (void)real;
  return NULL;
#else
  svc_scm_real_ops(real);
  return real;
#endif
}

/* service.status: open to every client. The facts of `shelldrive service status --json` (svc_status.c) as this
   service sees them, plus the machine data folder as found at start. The refused folder's path goes to elevated
   administrators only. */
static sd_err handle_service_status(sd_ipc_client *c, sd_json_writer *res, sd_ipc_error *err)
{
  svc_scm_ops real;
  const svc_scm_ops *ops = svc_scm_seam(&real);
  svc_install_spec spec;
  svc_status_report r;
  svc_pipe_report p;
  svc_machine_report m;
  uint32_t i, drives = 0;
  memset(&spec, 0, sizeof(spec));
  memset(&r, 0, sizeof(r));
  memset(&p, 0, sizeof(p));
  memset(&m, 0, sizeof(m));
  if (ops != NULL) {
    int have_spec = svc_scm_host_spec(&spec, L"") == 0;
    if (svc_scm_status(ops, have_spec ? &spec : NULL, &r) != 0)
      return fail(err, SD_E_FAILURE, "io_error", "the service manager query failed");
  }
  p.reachable = 1;
  p.prompts = (int64_t)svc_open_prompts();
  sd_mutex_lock(&g.lock);
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] != NULL)
      drives++;
  m.profiles = (int64_t)g.nprofs;
  m.ok = g.idle ? 0 : 1;
  m.why = g.refused_why;
  if (!m.ok && caller_is_admin(c))
    _snwprintf_s(m.path, MAX_PATH, _TRUNCATE, L"%s", g.refused_path);
  sd_mutex_unlock(&g.lock);
  p.healthy = m.ok;
  p.drives = (int64_t)drives;
  svc_status_write_members(res, &r, &p, &m);
  return SD_OK;
}

/* service.repair_data: elevated administrators only. Runs svc_repair_data (the code of `shelldrive service
   repair-data`) on %ProgramData%, then checks the layout again exactly like the start does and, when it is trusted,
   leaves the idle state and loads the machine profiles. Refused (busy) while a global drive exists: the repair can
   move the folder that holds its secrets. The log is closed around the move (an open file would block the rename). */
static sd_err handle_service_repair(sd_ipc_client *c, sd_json_writer *res, sd_ipc_error *err)
{
  svc_repair_ops real_ops;
  const svc_repair_ops *ops;
  svc_repair_result r;
  svc_refusal refusal;
  wchar_t base[MAX_PATH];
  DWORD we;
  uint32_t i;
  int busy = 0, healthy;
  sd_err e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (g.repair_base != NULL) {
    _snwprintf_s(base, MAX_PATH, _TRUNCATE, L"%s", g.repair_base);
  } else {
#ifdef SD_SVC_TEST_HOOKS
    return fail(err, SD_E_FAILURE, "io_error", "no base folder for the repair (test build)");
#else
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base) != S_OK)
      return fail(err, SD_E_FAILURE, "io_error", "the common application data folder is not known");
#endif
  }
  if (g.repair_ops != NULL) {
    ops = g.repair_ops;
  } else {
    svc_repair_real_ops(&real_ops);
    ops = &real_ops;
  }
  sd_mutex_lock(&g.lock);
  if (g.repairing)
    busy = 1;
  for (i = 0; i < SVC_MAX_MOUNTS && !busy; i++)
    if (g.mounts[i] != NULL)
      busy = 1;
  if (!busy) {
    /* nothing is mounted: stop serving profiles while the tree is rebuilt */
    g.repairing = 1;
    g.idle = 1;
    svc_free_profiles_locked();
  }
  sd_mutex_unlock(&g.lock);
  if (busy)
    return fail(err, SD_E_BUSY, "busy", "unmount the global drives before repairing the machine data folder");

  if (g.open_log)
    sd_log_close();
  memset(&r, 0, sizeof(r));
  we = svc_repair_data(ops, base, &r);
  memset(&refusal, 0, sizeof(refusal));
  e = svc_ensure_layout(&refusal);
  if (g.open_log)
    (void)sd_log_open_file(g.logfile);
  sd_mutex_lock(&g.lock);
  g.idle = e == SD_OK ? 0 : 1;
  g.refused_why = e == SD_OK ? SVC_FOLDER_OK : refusal.why;
  if (e == SD_OK)
    g.refused_path[0] = 0;
  else
    _snwprintf_s(g.refused_path, MAX_PATH, _TRUNCATE, L"%s", refusal.path);
  healthy = g.idle ? 0 : 1;
  g.repairing = 0;
  sd_mutex_unlock(&g.lock);
  if (healthy) {
    (void)svc_load_profiles();
    svc_autostart_boot_mounts();
  }
  svc_log_info("machine data folder repair: error %u, %u folders, %s, %s", (unsigned)we, (unsigned)r.folders,
               r.moved ? "moved aside" : "kept", healthy ? "trusted" : "still refused");

  if (r.refused)
    return fail(err, SD_E_ACCESS_DENIED, "repair_refused", "a link or a junction is in the machine data folder");
  if (we != 0)
    return fail(err, SD_E_FAILURE, "io_error", "the machine data folder could not be repaired");
  svc_status_write_repair(res, &r);
  sd_jw_key(res, "healthy");
  sd_jw_bool(res, healthy);
  return SD_OK;
}

static sd_err svc_ipc_handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                              sd_json_writer *res, sd_ipc_error *err)
{
  (void)ctx;
  if (strcmp(method, "list") == 0) return handle_list(client, res);
  if (strcmp(method, "hostkey.add") == 0) return handle_hk_add(client, params, res, err);
  if (strcmp(method, "hostkey.announced.list") == 0) return handle_hk_list(client, res, err);
  if (strcmp(method, "hostkey.announced.accept") == 0) return handle_hk_accept(client, params, res, err);
  if (strcmp(method, "hostkey.announced.reject") == 0) return handle_hk_reject(client, params, res, err);
  if (strcmp(method, "status") == 0) return handle_status(client, params, res, err);
  if (strcmp(method, "mount") == 0) return handle_mount(client, params, res, err);
  if (strcmp(method, "unmount") == 0) return handle_unmount(client, params, res, err);
  if (strcmp(method, "mount.attach_info") == 0) return handle_attach_info(client, params, res, err);
  if (strcmp(method, "selftest") == 0) return handle_selftest(res);
  if (strcmp(method, "service.status") == 0) return handle_service_status(client, res, err);
  if (strcmp(method, "service.repair_data") == 0) return handle_service_repair(client, res, err);
  if (strcmp(method, "secret.set") == 0) return handle_secret(client, params, res, err, 1);
  if (strcmp(method, "secret.delete") == 0) return handle_secret(client, params, res, err, 0);
  if (strcmp(method, "prompt.list") == 0) return handle_prompt_list(client, res, err);
  if (strcmp(method, "prompt.answer") == 0) return handle_prompt_answer(client, params, res, err);
  if (strcmp(method, "config.reload") == 0) return handle_config_reload(client, res, err);
  return fail(err, SD_E_UNSUPPORTED, "usage", "unknown method");
}

/* prompt, log and hostkeys are elevated-admin topics (2.2, TM-R25); the rest are open to every client. */
static int svc_topic_allowed(void *ctx, sd_ipc_client *client, const char *topic)
{
  (void)ctx;
  if (strcmp(topic, "prompt") == 0 || strcmp(topic, "log") == 0 || strcmp(topic, "hostkeys") == 0)
    return caller_is_admin(client);
  return 1;
}

static int svc_ipc_is_admin(void *ctx, sd_ipc_client *client)
{
  (void)ctx;
  return caller_is_admin(client);
}

/* The class of a new connection, before hello (2.2): the token decides (the server), unless a test forces admin. */
static int svc_admin_at_connect(void *ctx)
{
  (void)ctx;
#ifdef SD_SVC_TEST_HOOKS
  return g.test_connect_admin ? 1 : 0;
#else
  return 0;
#endif
}

/* Event 3101 (10.3, TM-R25): a client refused at hello or over the rate limit. %1 is the SID (not written when the
   token gave none), %2 the reason: token, per_sid, reserved or rate. At most once per SID per 10 minutes. Runs on the
   pipe thread, the only writer of the throttle table. */
static void svc_on_refused(void *ctx, sd_ipc_client *client, const char *reason)
{
  PSID sid = sd_ipc_client_sid(client);
  LPWSTR text = NULL;
  wchar_t why[32];
  const wchar_t *args[2];
  (void)ctx;
  if (sid == NULL || !ConvertSidToStringSidW(sid, &text))
    return;
  if (svc_refuse_log_due(g.refuse, SVC_REFUSE_SLOTS, text, sd_tick_ms())) {
    wide_from_utf8(reason, why, SD_COUNTOF(why));
    args[0] = text;
    args[1] = why;
    svc_event(SVC_MSG_CLIENT_REFUSED, args, 2);
  }
  LocalFree(text);
}

/* attention: a new subscriber gets the current count at once, so a UI that starts after a prompt knows about it. */
static void svc_on_subscribe(void *ctx, sd_ipc_client *client, const char *topic)
{
  sd_wr w;
  (void)ctx;
  if (strcmp(topic, "attention") != 0 || g.srv == NULL)
    return;
  sd_wr_init(&w, 128);
  if (build_attention(svc_open_prompts(), &w) == SD_OK)
    (void)sd_ipc_send_to(g.srv, sd_ipc_client_id(client), (const char *)w.p, w.len);
  sd_wr_free(&w);
}

static const char *const k_service_features[] = {
  "list", "status", "mount", "unmount", "selftest", "secret.set", "secret.delete", "prompt.list",
  "prompt.answer", "config.reload", "prompt.routing", "hostkey.add", "hostkey.announced.list",
  "hostkey.announced.accept", "hostkey.announced.reject", "service.status", "service.repair_data",
  "mount.attach_info", NULL
};

/* ---- the core ---- */

static void svc_setup_secrets(const wchar_t *dir)
{
  sd_secret_config sc;
  wchar_t userdir[MAX_PATH];
  memset(&sc, 0, sizeof(sc));
  /* the service never reads the user scope: point it at a folder that does not exist, so no user secret can be
     mistaken for a service one (or the other way round) */
  _snwprintf_s(userdir, MAX_PATH, _TRUNCATE, L"%s\\no-user-scope", g.root);
  sc.user_dir = userdir;
  sc.service_dir = dir;
  sc.force_dpapi = 1;            /* service secrets are DPAPI files under SYSTEM (4.5), never Credential Manager */
  (void)sd_secret_configure(&sc);
}

int svc_run(const svc_opts *o)
{
  sd_ipc_server_cfg cfg;
  svc_refusal refusal;
  sd_err e;
  int rc = 0;
  memset(&g, 0, sizeof(g));
  sd_mutex_init(&g.lock);
  sd_mutex_init(&g.reap);
  if (sd_event_init(&g.wake, 0, 0) != SD_OK || sd_event_init(&g.stop, 1, 0) != SD_OK) {
    sd_mutex_destroy(&g.lock);
    sd_mutex_destroy(&g.reap);
    return 1;
  }
  g.be = (o && o->backend) ? o->backend : host_backend();
  g.event = o ? o->event : NULL;
  g.event_ctx = o ? o->event_ctx : NULL;
  g.owner_trusted = o ? o->owner_trusted : NULL;
  g.open_log = o && o->open_log ? 1 : 0;
  g.scm_ops = o ? o->scm_ops : NULL;
  g.repair_ops = o ? o->repair_ops : NULL;
  g.repair_base = o ? o->repair_base : NULL;
  g.sysproxy = (o && o->sysproxy_ops) ? o->sysproxy_ops : &k_sysproxy_shipping;
#ifdef SD_SVC_TEST_HOOKS
  g.test_all_admin = o ? o->test_all_admin : 0;
  g.dacl_extra = o ? o->dacl_extra_ace : NULL;
#endif
  if (svc_compute_paths(o ? o->machine_root : NULL) != SD_OK) {
    rc = 1;
    goto out_free_events;
  }
  if (o && o->open_log && sd_log_open_file(g.logfile) != SD_OK)
    SD_LOGW("svc", "the service log is not open");
  memset(&refusal, 0, sizeof(refusal));
  e = svc_ensure_layout(&refusal);
  if (e != SD_OK) {
    g.idle = 1;
    g.refused_why = refusal.why;
    _snwprintf_s(g.refused_path, MAX_PATH, _TRUNCATE, L"%s", refusal.path);
    SD_LOGE("svc", "the machine folder is refused (%s): the service stays idle (3.2)", sd_err_name(e));
    svc_event_untrusted(&refusal);
  }
  svc_setup_secrets(o && o->secret_dir ? o->secret_dir : g.service_dir);
  (void)svc_load_profiles();
  svc_log_info("service starting; %u machine profiles", (unsigned)g.nprofs);
  svc_autostart_boot_mounts();

  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = svc_ipc_handler;
  cfg.ctx = NULL;
  cfg.max_instances = 32;
  cfg.max_message = SD_IPC_MAX_MESSAGE;   /* 2.2: admins, 1 MiB */
  cfg.max_message_nonadmin = SVC_MAX_MESSAGE_NONADMIN;
  cfg.idle_timeout_ms = SVC_IDLE_MS;
  cfg.max_per_sid = 4;                    /* TM-R25 */
  cfg.max_requests_per_sec = 10;          /* TM-R25; admins are exempt in the server */
  cfg.reserved_admin_instances = SVC_RESERVED_ADMIN_INSTANCES;
  cfg.hello_timeout_ms = SVC_HELLO_MS;    /* 2.2: a non-admin that does not say hello in time is closed */
  cfg.admin_at_connect = svc_admin_at_connect;
  cfg.is_admin = svc_ipc_is_admin;
  cfg.on_refused = svc_on_refused;
  cfg.features = k_service_features;
  cfg.topic_allowed = svc_topic_allowed;
  cfg.on_subscribe = svc_on_subscribe;
  e = sd_ipc_server_start_ex(SD_IPC_SERVICE, &cfg, &g.srv);
  if (e != SD_OK) {
    wchar_t why[64];
    const wchar_t *args[1];
    SD_LOGE("svc", "the control pipe did not start (%s)", sd_err_name(e));
    wide_from_utf8(sd_err_name(e), why, SD_COUNTOF(why));
    args[0] = why;
    svc_event(SVC_MSG_START_FAILED, args, 1);
    rc = 1;
    goto out_secrets;
  }
  g.running = 1;
  if (o && o->on_running)
    o->on_running(o->ctx);
  svc_log_info("service running");
  {
    const wchar_t *args[1];
    args[0] = SD_VERSION_STRING_W;
    svc_event(SVC_MSG_STARTED, args, 1);
  }
  svc_loop();
  g.running = 0;
  g.stopping = 1;
  sd_ipc_server_stop(g.srv);
  g.srv = NULL;
  svc_log_info("service stopped");
  svc_event(SVC_MSG_STOPPED, NULL, 0);

out_secrets:
  (void)sd_secret_configure(NULL);
  sd_mutex_lock(&g.lock);
  svc_free_profiles_locked();
  sd_mutex_unlock(&g.lock);
  if (o && o->open_log)
    sd_log_close();
out_free_events:
  sd_event_destroy(&g.stop);
  sd_event_destroy(&g.wake);
  sd_mutex_destroy(&g.reap);
  sd_mutex_destroy(&g.lock);
  return rc;
}

void svc_request_stop(void)
{
  if (g.stop.h != NULL)
    sd_event_set(&g.stop);
  if (g.wake.h != NULL)
    SetEvent(g.wake.h);
}

/* ---- console mode ---- */

static BOOL WINAPI console_ctrl(DWORD type)
{
  if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
    svc_request_stop();
    return TRUE;
  }
  return FALSE;
}

static void console_running(void *ctx)
{
  (void)ctx;
  say(SD_MSG_SVC_DEBUG_STARTED);
}

int svc_console_run(void)
{
  svc_opts o;
  int rc;
  sd_l10n_init(&sd_l10n_catalog_svc, NULL);
  memset(&o, 0, sizeof(o));
  o.open_log = 1;
  o.on_running = console_running;
  SetConsoleCtrlHandler(console_ctrl, TRUE);
  rc = svc_run(&o);
  SetConsoleCtrlHandler(console_ctrl, FALSE);
  say(SD_MSG_SVC_DEBUG_STOPPED);
  return rc;
}

/* ---- Service Control Manager ---- */

static SERVICE_STATUS_HANDLE g_scm_handle;
static SERVICE_STATUS g_scm_status;
static DWORD g_scm_checkpoint;

static void scm_report(DWORD state, DWORD win32_exit, DWORD wait_hint)
{
  g_scm_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_scm_status.dwCurrentState = state;
  g_scm_status.dwControlsAccepted = state == SERVICE_RUNNING
      ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_POWEREVENT |
         SERVICE_ACCEPT_SESSIONCHANGE)
      : 0;
  g_scm_status.dwWin32ExitCode = win32_exit;
  g_scm_status.dwServiceSpecificExitCode = 0;
  g_scm_status.dwWaitHint = wait_hint;
  g_scm_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : ++g_scm_checkpoint;
  if (g_scm_handle)
    SetServiceStatus(g_scm_handle, &g_scm_status);
}

static DWORD WINAPI scm_control(DWORD ctrl, DWORD evt, LPVOID data, LPVOID ctx)
{
  (void)evt;
  (void)data;
  (void)ctx;
  switch (ctrl) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
  case SERVICE_CONTROL_PRESHUTDOWN:
    scm_report(SERVICE_STOP_PENDING, NO_ERROR, 30000);
    svc_request_stop();
    return NO_ERROR;
  case SERVICE_CONTROL_POWEREVENT:
    SD_LOGI("svc", "power event %u", (unsigned)evt);     /* no action: mounts stay (1.3) */
    return NO_ERROR;
  case SERVICE_CONTROL_SESSIONCHANGE:
    SD_LOGI("svc", "session change %u", (unsigned)evt);  /* the admin-session list arrives with the UI (2.6) */
    return NO_ERROR;
  case SERVICE_CONTROL_INTERROGATE:
    return NO_ERROR;
  default:
    return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static void scm_running(void *ctx)
{
  (void)ctx;
  scm_report(SERVICE_RUNNING, NO_ERROR, 0);
}

static void WINAPI scm_main(DWORD argc, LPWSTR *argv)
{
  svc_opts o;
  int rc;
  (void)argc;
  (void)argv;
  g_scm_handle = RegisterServiceCtrlHandlerExW(SVC_SERVICE_NAME, scm_control, NULL);
  if (g_scm_handle == NULL)
    return;
  memset(&g_scm_status, 0, sizeof(g_scm_status));
  scm_report(SERVICE_START_PENDING, NO_ERROR, 10000);
  memset(&o, 0, sizeof(o));
  o.open_log = 1;
  o.on_running = scm_running;
  o.event = svc_eventlog_write;
  rc = svc_run(&o);
  g_scm_status.dwServiceSpecificExitCode = (DWORD)rc;
  scm_report(SERVICE_STOPPED, rc ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR, 0);
}

int svc_dispatch(void)
{
  SERVICE_TABLE_ENTRYW table[2];
  sd_l10n_init(&sd_l10n_catalog_svc, NULL);
  memset(table, 0, sizeof(table));
  table[0].lpServiceName = (LPWSTR)SVC_SERVICE_NAME;
  table[0].lpServiceProc = scm_main;
  if (!StartServiceCtrlDispatcherW(table)) {
    say(SD_MSG_SVC_NOT_SCM);
    return 1;
  }
  return (int)g_scm_status.dwServiceSpecificExitCode;
}
