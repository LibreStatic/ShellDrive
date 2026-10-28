/* shelldrive-host service mode (03 §1.3, §2.2, §2.6, §3.2, §3.4.1, §4.5; D6, D17, D35; TM-R24..R27).
 *
 * Owns global mounts only: machine profiles with scope = service. The control thread is the caller of svc_run (the SCM
 * main thread or the console thread). sd_mount create/start/stop/destroy run only there; the pipe thread (IPC handlers)
 * touches the tables under g.lock and hands work to the control thread through a queue, like the agent does.
 *
 * Methods (2.4): list and status (filtered, 2.2), selftest and hello are open to every client; mount, unmount,
 * secret.set, secret.delete, config.reload, prompt.list and prompt.answer need an elevated administrator. Topics prompt,
 * log and hostkeys are refused to non-admins (topic gate). A service prompt is shown only to an elevated administrator
 * that subscribed to `prompt`; without one the mount fails with prompt_unavailable (2.6 rule 3). */
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
#include "svc_scm.h"
#include "sd/version.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_svc_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
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
#define SVC_MAX_MESSAGE  65536u           /* 2.2: one cap for every client of the service pipe in this build */
#define SVC_IDLE_MS      60000u           /* 2.2: idle timeout of a non-subscribed client */
#define SVC_SHUTDOWN_MS  15000u

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
} svc_mount;

typedef struct svc_job {
  char id[16];
  int force;
} svc_job;

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
  int running, stopping;
  int test_all_admin;               /* SD_SVC_TEST_HOOKS only, see caller_is_admin */
  svc_event_fn event;               /* Event Log sink (10.3), NULL = none */
  void *event_ctx;
  svc_prof *profs[SVC_MAX_PROFILES];
  uint32_t nprofs;
  svc_mount *mounts[SVC_MAX_MOUNTS];
  uint32_t next_mount, next_prompt;
  svc_prompt prompts[SVC_MAX_PROMPTS];
  svc_work *qh, *qt;
} g;

/* Admin check of the callers. SD_SVC_TEST_HOOKS builds (tests/unit/sd_svc) may treat a "testadmin" client as an elevated
   administrator so that the admin methods are exercised without an elevated test process; the restricted-token client
   still hits the real check. Shipping builds never compile the override. */
static int caller_is_admin(sd_ipc_client *c)
{
#ifdef SD_SVC_TEST_HOOKS
  if (g.test_all_admin && strcmp(sd_ipc_client_kind(c), "testadmin") == 0)
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

static void svc_enqueue(void (*fn)(void *), void *arg)
{
  svc_work *w = (svc_work *)sd_alloc(sizeof(*w));
  if (w == NULL)
    return;
  w->next = NULL;
  w->fn = fn;
  w->arg = arg;
  sd_mutex_lock(&g.lock);
  if (g.qt) g.qt->next = w; else g.qh = w;
  g.qt = w;
  sd_mutex_unlock(&g.lock);
  SetEvent(g.wake.h);
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
      if (sd_profile_load_file(path, &x->p, &bad) != SD_OK) {
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
  (void)ctx;
  sd_mutex_lock(&g.lock);
  r = find_by_m_locked(m);
  if (r) {
    r->st = st;
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

static void svc_on_notice(void *ctx, sd_mount *m, const char *code, const char *detail)
{
  (void)ctx;
  (void)m;
  SD_LOGI("svc", "notice %s %s", code ? code : "", detail ? detail : "");
}

static void svc_on_hostkeys(void *ctx, sd_mount *m, const sd_mount_announcement *a, int applied, sd_err err)
{
  (void)ctx;
  (void)m;
  (void)a;
  (void)applied;
  SD_LOGW("svc", "host keys were announced for a global mount; the machine store is not updated in this build (%s)",
          sd_err_name(err));
}

/* ---- control-thread jobs ---- */

static void job_start(void *arg)
{
  svc_job *j = (svc_job *)arg;
  svc_mount *r;
  sd_mount_params pr;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  wchar_t hostw[256], labelw[160], namew[160], identw[MAX_PATH], fsw[32];
  wchar_t wsddl_buf[1024];
  char sddl[1024];
  PSECURITY_DESCRIPTOR sd_bytes = NULL;
  ULONG sd_len = 0;
  unsigned char *keybuf = NULL;     /* identity file bytes, read through a checked handle (TM-R27); wiped after use */
  DWORD keylen = 0;
  sd_mount_hop hop;
  char keylabel[MAX_PATH * 3];
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
    if (p->identity[0] && why == NULL) {
      if (sd_config_expand_path(p->identity, identw, SD_COUNTOF(identw)) != SD_OK ||
          !svc_path_under(identw, g.service_dir)) {
        why = "identity file outside the service folder (TM-R27)";
      } else {
        /* 2.6 rule 1, TM-R27: the file is checked and read through one handle (svc_file_read_trusted); the bytes go to
           sd_mount as a key blob (the hop path), so the mount never opens the path again */
        svc_folder_reason fr = SVC_FOLDER_OK;
        DWORD fe = svc_file_read_trusted(g.service_dir, identw, g.owner_trusted, NULL, &keybuf, &keylen, &fr);
        if (fe != 0) {
          why = "identity file cannot be read (TM-R27)";
        } else if (fr != SVC_FOLDER_OK) {
          svc_event_key_refused(identw, fr);
          why = "identity file refused: owner, reparse point, not a plain file or a writable ACL (TM-R27)";
        } else {
          memset(&hop, 0, sizeof(hop));
          utf8_from_wide(identw, keylabel, sizeof(keylabel));
          hop.host = hostw;
          hop.port = pr.port;
          hop.user = p->user;
          hop.key_blob = keybuf;
          hop.key_blob_len = keylen;
          hop.key_label = keylabel;
          hop.identities_only = 1;                 /* D37: the key given is the only one offered */
          hop.auth_methods = pr.auth_methods;
          hop.update_host_keys = SD_HKU_ASK;
          pr.hops = &hop;
          pr.hop_count = 1;
        }
      }
    }
    pr.remote_path = p->remote_path;
    pr.letter = r->letter;
    pr.read_only = p->read_only;
    pr.symlinks = p->symlinks;
    pr.write_mode = p->write_mode;
    wide_from_utf8(p->label[0] ? p->label : p->name, labelw, SD_COUNTOF(labelw));
    pr.volume_label = labelw;
    wide_from_utf8(p->name, namew, SD_COUNTOF(namew));
    pr.profile_name = namew;
    pr.backend = SD_MOUNT_BACKEND_DOKANY;          /* global drives are Dokany in this build (1.3, D11) */
    pr.global_mount = 1;
    pr.legacy_policy = p->legacy_algorithms;
    pr.refuse_terrapin_exposed = p->refuse_terrapin_exposed;
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
    /* known_hosts: the machine store only, read-only for the service (5.1, 5.6) */
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
  }
  if (why != NULL) {
    sd_mutex_lock(&g.lock);
    r->final = 1;
    r->st = SD_MOUNT_FAILED;
    strcpy_s(r->err_code, sizeof(r->err_code), "usage");
    strcpy_s(r->err_detail, sizeof(r->err_detail), why);
    sd_mutex_unlock(&g.lock);
    SD_LOGW("svc", "mount %s refused: %s", j->id, why);
    sd_secure_free(keybuf, keylen);
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
  cb.secret_get = svc_secret_get;
  cb.on_warning = svc_on_warning;
  cb.on_hostkeys_announced = svc_on_hostkeys;
  e = sd_mount_create(g.be, &pr, &cb, &m);
  sd_secure_free(keybuf, keylen);   /* sd_mount_create copied the key bytes */
  if (sd_bytes) LocalFree(sd_bytes);
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
  /* run the teardown: the control loop is gone, so pump the queue and the tick here */
  while (waited < SVC_SHUTDOWN_MS) {
    int pending = 0;
    svc_drain();
    svc_tick();
    sd_mutex_lock(&g.lock);
    for (i = 0; i < SVC_MAX_MOUNTS; i++)
      if (g.mounts[i]) pending = 1;
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

static sd_err handle_mount(sd_ipc_client *c, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  const char *key = sd_json_get_str(params, "profile");
  const char *tgt = sd_json_get_str(params, "target");
  svc_prof *src;
  svc_prof *copy = NULL;
  svc_mount *r = NULL;
  sd_err e;
  wchar_t letter = 0;
  svc_job *job;
  uint32_t i, slot = SVC_MAX_MOUNTS;
  const char *bad = NULL, *why = NULL;
  char detail[200];
  e = need_admin(c, err);
  if (e != SD_OK)
    return e;
  if (key == NULL)
    return fail(err, SD_E_INVALID_PARAM, "usage", "mount needs a profile");
  sd_mutex_lock(&g.lock);
  src = find_profile_locked(key);
  if (src == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NOT_FOUND, "profile_not_found", "no machine profile of scope service with that id or name");
  }
  if (svc_validate_profile(&src->p, &bad, &why) != SD_OK) {
    sd_mutex_unlock(&g.lock);
    _snprintf_s(detail, sizeof(detail), _TRUNCATE, "%s: %s", bad ? bad : "profile", why ? why : "refused");
    return fail(err, SD_E_INVALID_PARAM, "usage", detail);
  }
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] && strcmp(g.mounts[i]->prof->p.id, src->p.id) == 0) {
      sd_mutex_unlock(&g.lock);
      return fail(err, SD_E_EXISTS, "already_mounted", "this profile is already mounted");
    }
  copy = (svc_prof *)sd_alloc(sizeof(*copy));
  if (copy == NULL) {
    sd_mutex_unlock(&g.lock);
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
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
        return fail(err, SD_E_INVALID_PARAM, "invalid_target", "the target is not a drive letter");
      }
    }
  }
  if (letter == 0)
    letter = pick_letter_locked();
  if (letter == 0 || letter_taken_locked(letter) || (GetLogicalDrives() & (1ul << (letter - L'A')))) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    return fail(err, SD_E_EXISTS, "target_in_use", "no free drive letter for this mount");
  }
  for (i = 0; i < SVC_MAX_MOUNTS; i++)
    if (g.mounts[i] == NULL) {
      slot = i;
      break;
    }
  if (slot == SVC_MAX_MOUNTS) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    return fail(err, SD_E_BUSY, "busy", "too many global mounts");
  }
  r = (svc_mount *)sd_calloc(1, sizeof(*r));
  if (r == NULL) {
    sd_mutex_unlock(&g.lock);
    sd_free(copy);
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
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
    return fail(err, SD_E_NO_MEMORY, NULL, "out of memory");
  }
  strcpy_s(job->id, sizeof(job->id), r->id);
  g.mounts[slot] = r;
  sd_mutex_unlock(&g.lock);
  SD_LOGI("svc", "mount %s queued for %c:", r->id, (char)letter);
  svc_enqueue(job_start, job);
  sd_jw_key(res, "mount_id"); sd_jw_cstr(res, r->id);
  {
    char tgt2[4];
    target_of(letter, tgt2);
    sd_jw_key(res, "target"); sd_jw_cstr(res, tgt2);
  }
  sd_jw_key(res, "state"); sd_jw_cstr(res, "connecting");
  return SD_OK;
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
  sd_jw_key(res, "profiles");
  sd_jw_obj_begin(res);
  sd_jw_key(res, "loaded"); sd_jw_int(res, n);
  sd_jw_key(res, "errors"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  sd_jw_obj_end(res);
  sd_jw_key(res, "settings"); sd_jw_cstr(res, "unchanged");
  sd_jw_key(res, "restart_required"); sd_jw_arr_begin(res); sd_jw_arr_end(res);
  return SD_OK;
}

static sd_err svc_ipc_handler(void *ctx, sd_ipc_client *client, const char *method, const sd_json *params,
                              sd_json_writer *res, sd_ipc_error *err)
{
  (void)ctx;
  if (strcmp(method, "list") == 0) return handle_list(client, res);
  if (strcmp(method, "status") == 0) return handle_status(client, params, res, err);
  if (strcmp(method, "mount") == 0) return handle_mount(client, params, res, err);
  if (strcmp(method, "unmount") == 0) return handle_unmount(client, params, res, err);
  if (strcmp(method, "selftest") == 0) return handle_selftest(res);
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
  "prompt.answer", "config.reload", "prompt.routing", NULL
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
    SD_LOGE("svc", "the machine folder is refused (%s): the service stays idle (3.2)", sd_err_name(e));
    svc_event_untrusted(&refusal);
  }
  svc_setup_secrets(o && o->secret_dir ? o->secret_dir : g.service_dir);
  (void)svc_load_profiles();
  svc_log_info("service starting; %u machine profiles", (unsigned)g.nprofs);

  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.handler = svc_ipc_handler;
  cfg.ctx = NULL;
  cfg.max_instances = 32;
  cfg.max_message = SVC_MAX_MESSAGE;
  cfg.idle_timeout_ms = SVC_IDLE_MS;
  cfg.max_per_sid = 4;                    /* TM-R25 */
  cfg.max_requests_per_sec = 10;          /* TM-R25; admins are exempt in the server */
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
    SD_LOGI("svc", "power event %lu", (unsigned long)evt);     /* no action: mounts stay (1.3) */
    return NO_ERROR;
  case SERVICE_CONTROL_SESSIONCHANGE:
    SD_LOGI("svc", "session change %lu", (unsigned long)evt);  /* the admin-session list arrives with the UI (2.6) */
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
