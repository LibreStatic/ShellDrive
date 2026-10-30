/* shelldrive-setup: command line, host detection, flavour and Dokany decisions, version order, payload
   table lookup and CAB member-name rules (docs/design/04 §6.2, §6.5, §7.3, §6.1, TM-R33). Pure logic
   first; the detection functions only read facts. */
#include "setup_int.h"

#include <ctype.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

/* ------------------------------------------------------------------ flavours */

static const wchar_t *const k_flavour_names[] = {
  NULL, L"x86-ia32", L"x86-sse2", L"x64-xp", L"x64-modern", L"arm64", L"arm32"
};

static const wchar_t *const k_payload_names[] = {
  NULL, L"PAYLOAD_X86_IA32", L"PAYLOAD_X86_SSE2", L"PAYLOAD_X64_XP", L"PAYLOAD_X64_MODERN", L"PAYLOAD_ARM64",
  L"PAYLOAD_ARM32"
};

const wchar_t *sd_setup_flavour_name(sd_setup_flavour f)
{
  if ((int)f < 0 || (size_t)f >= SD_SETUP_COUNTOF(k_flavour_names))
    return NULL;
  return k_flavour_names[f];
}

const wchar_t *sd_setup_payload_resource(sd_setup_flavour f)
{
  if ((int)f <= 0 || (size_t)f >= SD_SETUP_COUNTOF(k_payload_names))
    return NULL;
  return k_payload_names[f];
}

sd_setup_flavour sd_setup_flavour_parse(const wchar_t *name)
{
  size_t i;
  if (name == NULL)
    return SD_SETUP_FL_NONE;
  for (i = 1; i < SD_SETUP_COUNTOF(k_flavour_names); i++) {
    if (_wcsicmp(name, k_flavour_names[i]) == 0)
      return (sd_setup_flavour)i;
  }
  return SD_SETUP_FL_NONE;
}

/* ------------------------------------------------------------------ command line */

static int arg_is(const wchar_t *tok, const wchar_t *name)
{
  return _wcsicmp(tok, name) == 0;
}

/* Matches "/name=" (case-insensitive) and returns the value after '=' or NULL. */
static const wchar_t *arg_value(const wchar_t *tok, const wchar_t *name)
{
  size_t n = wcslen(name);
  if (tok[0] != L'/' && tok[0] != L'-')
    return NULL;
  if (_wcsnicmp(tok + 1, name, n) != 0)
    return NULL;
  if (tok[1 + n] != L'=')
    return NULL;
  return tok + 2 + n;
}

static int copy_path_arg(wchar_t *dst, size_t cch, const wchar_t *src)
{
  if (src[0] == L'\0')
    return 0;
  return SUCCEEDED(StringCchCopyW(dst, cch, src)) ? 1 : 0;
}

static int is_lang_code(const wchar_t *s)
{
  static const wchar_t *const langs[] = { L"en", L"es", L"fr", L"pt-BR", L"pt", L"it", L"de" };
  size_t i;
  for (i = 0; i < SD_SETUP_COUNTOF(langs); i++) {
    if (_wcsicmp(s, langs[i]) == 0)
      return 1;
  }
  return 0;
}

static int is_property_token(const wchar_t *tok)
{
  const wchar_t *eq = wcschr(tok, L'=');
  const wchar_t *p;
  if (eq == NULL || eq == tok)
    return 0;
  for (p = tok; p < eq; p++) {
    if (!(iswalnum(*p) || *p == L'_'))
      return 0;
  }
  return 1;
}

int sd_setup_parse_args(int argc, const wchar_t *const *argv, sd_setup_args *out, const wchar_t **bad)
{
  int i;
  int mode_given = 0;

  memset(out, 0, sizeof(*out));
  out->autostart = -1;
  out->mode = SD_SETUP_MODE_AUTO;
  if (bad != NULL)
    *bad = NULL;

  for (i = 1; i < argc; i++) {
    const wchar_t *tok = argv[i];
    const wchar_t *v;

    if (tok == NULL || tok[0] == L'\0')
      goto bad_token;

    if (tok[0] != L'/' && tok[0] != L'-') {
      if (is_property_token(tok) && wcschr(tok, L'"') == NULL) {
        /* Kept quoted for the msiexec command line (04 §8.4); the elevated stages receive them the same way. */
        size_t used = wcslen(out->props);
        size_t need = wcslen(tok) + 4;
        if (used + need >= SD_SETUP_COUNTOF(out->props))
          goto bad_token;
        StringCchPrintfW(out->props + used, SD_SETUP_COUNTOF(out->props) - used, L"\"%s\" ", tok);
        out->properties++;
        continue;
      }
      goto bad_token;
    }

    if (arg_is(tok + 1, L"quiet") || arg_is(tok + 1, L"q")) {
      out->quiet = 1;
    } else if (arg_is(tok + 1, L"passive")) {
      out->passive = 1;
    } else if (arg_is(tok + 1, L"norestart")) {
      out->norestart = 1;
    } else if (arg_is(tok + 1, L"force")) {
      out->force = 1;
    } else if (arg_is(tok + 1, L"update")) {
      out->update = 1;
    } else if (arg_is(tok + 1, L"uninstall")) {
      if (mode_given && out->mode != SD_SETUP_MODE_UNINSTALL)
        goto bad_token;
      out->mode = SD_SETUP_MODE_UNINSTALL;
      mode_given = 1;
    } else if (arg_is(tok + 1, L"uninstall-from-temp")) {
      out->uninstall_relaunched = 1;
      out->mode = SD_SETUP_MODE_UNINSTALL;
      mode_given = 1;
    } else if (arg_is(tok + 1, L"peruser")) {
      if (mode_given && out->mode != SD_SETUP_MODE_USER)
        goto bad_token;
      out->mode = SD_SETUP_MODE_USER;
      mode_given = 1;
    } else if (arg_is(tok + 1, L"permachine")) {
      if (mode_given && out->mode != SD_SETUP_MODE_MACHINE)
        goto bad_token;
      out->mode = SD_SETUP_MODE_MACHINE;
      mode_given = 1;
    } else if (arg_is(tok + 1, L"help") || arg_is(tok + 1, L"?")) {
      out->help = 1;
    } else if (arg_is(tok + 1, L"test-pages")) {
      out->test_pages = 1;
    } else if (arg_is(tok + 1, L"elevated-stage1") || arg_is(tok + 1, L"elevated-child")) {
      /* Internal: the two elevated stages (setup_elevate.c). Only one of them per command line. */
      int stage = arg_is(tok + 1, L"elevated-stage1") ? 1 : 2;
      if (out->elevate_stage != 0 && out->elevate_stage != stage)
        goto bad_token;
      out->elevate_stage = stage;
    } else if ((v = arg_value(tok, L"pipe")) != NULL) {
      if (!copy_path_arg(out->pipe_name, SD_SETUP_COUNTOF(out->pipe_name), v))
        goto bad_token;
    } else if ((v = arg_value(tok, L"portable")) != NULL) {
      if (mode_given && out->mode != SD_SETUP_MODE_PORTABLE)
        goto bad_token;
      if (!copy_path_arg(out->portable_dir, SD_SETUP_COUNTOF(out->portable_dir), v))
        goto bad_token;
      out->mode = SD_SETUP_MODE_PORTABLE;
      mode_given = 1;
    } else if ((v = arg_value(tok, L"dokany")) != NULL) {
      if (arg_is(v, L"auto")) {
        out->dokany = SD_SETUP_DOKANY_AUTO;
      } else if (arg_is(v, L"install")) {
        out->dokany = SD_SETUP_DOKANY_INSTALL;
      } else if (arg_is(v, L"skip")) {
        out->dokany = SD_SETUP_DOKANY_SKIP;
      } else {
        goto bad_token;
      }
      out->dokany_set = 1;
    } else if ((v = arg_value(tok, L"autostart")) != NULL) {
      if (v[0] == L'0' && v[1] == L'\0')
        out->autostart = 0;
      else if (v[0] == L'1' && v[1] == L'\0')
        out->autostart = 1;
      else
        goto bad_token;
    } else if ((v = arg_value(tok, L"flavour")) != NULL) {
      out->flavour = sd_setup_flavour_parse(v);
      if (out->flavour == SD_SETUP_FL_NONE)
        goto bad_token;
      out->flavour_forced = 1;
    } else if ((v = arg_value(tok, L"lang")) != NULL) {
      if (!is_lang_code(v) || wcslen(v) >= SD_SETUP_COUNTOF(out->lang))
        goto bad_token;
      StringCchCopyW(out->lang, SD_SETUP_COUNTOF(out->lang), v);
    } else if ((v = arg_value(tok, L"log")) != NULL) {
      if (!copy_path_arg(out->log_path, SD_SETUP_COUNTOF(out->log_path), v))
        goto bad_token;
    } else if ((v = arg_value(tok, L"extract")) != NULL) {
      if (!copy_path_arg(out->extract_dir, SD_SETUP_COUNTOF(out->extract_dir), v))
        goto bad_token;
    } else if ((v = arg_value(tok, L"waitpid")) != NULL) {
      unsigned long pid = 0;
      const wchar_t *d = v;
      if (*d == L'\0')
        goto bad_token;
      for (; *d != L'\0'; d++) {
        if (*d < L'0' || *d > L'9')
          goto bad_token;
        /* 4294967295 is the largest value of unsigned long: reject anything above it. */
        if (pid > 429496729ul || (pid == 429496729ul && *d > L'5'))
          goto bad_token;
        pid = pid * 10 + (unsigned long)(*d - L'0');
      }
      out->wait_pid = pid;
    } else if ((v = arg_value(tok, L"installdir")) != NULL) {
      if (!copy_path_arg(out->install_dir, SD_SETUP_COUNTOF(out->install_dir), v))
        goto bad_token;
    } else {
      /* Unknown switch, or an elevation stage this build does not implement (04 §6.4). */
      goto bad_token;
    }
    continue;

  bad_token:
    if (bad != NULL)
      *bad = tok;
    return SD_SETUP_EXIT_BADARGS;
  }

  if (out->quiet && out->passive)
    out->passive = 0;
  return 0;
}

/* ------------------------------------------------------------------ host and flavour */

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386 0x014c
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif
#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#endif

typedef BOOL (WINAPI *sd_IsWow64Process2_t)(HANDLE, USHORT *, USHORT *);
typedef BOOL (WINAPI *sd_IsWow64Process_t)(HANDLE, BOOL *);
typedef void (WINAPI *sd_GetNativeSystemInfo_t)(SYSTEM_INFO *);
typedef LONG (WINAPI *sd_RtlGetVersion_t)(OSVERSIONINFOW *);
typedef BOOL (WINAPI *sd_CheckTokenMembership_t)(HANDLE, PSID, PBOOL);
typedef BOOL (WINAPI *sd_AllocateAndInitializeSid_t)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD,
                                                     DWORD, DWORD, DWORD, DWORD, DWORD, PSID *);
typedef void *(WINAPI *sd_FreeSid_t)(PSID);

static int detect_is_admin(void)
{
  sd_CheckTokenMembership_t check = (sd_CheckTokenMembership_t)sd_setup_proc(L"advapi32.dll", "CheckTokenMembership");
  sd_AllocateAndInitializeSid_t alloc =
    (sd_AllocateAndInitializeSid_t)sd_setup_proc(L"advapi32.dll", "AllocateAndInitializeSid");
  sd_FreeSid_t freesid = (sd_FreeSid_t)sd_setup_proc(L"advapi32.dll", "FreeSid");
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  PSID admins = NULL;
  BOOL member = FALSE;
  int result = 0;

  if (check == NULL || alloc == NULL || freesid == NULL)
    return 0;
  if (!alloc(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins))
    return 0;
  if (check(NULL, admins, &member) && member)
    result = 1;
  freesid(admins);
  return result;
}

void sd_setup_detect_host(sd_setup_host *h)
{
  sd_IsWow64Process2_t wow2;
  sd_IsWow64Process_t wow;
  sd_GetNativeSystemInfo_t gnsi;
  sd_RtlGetVersion_t rtl;
  OSVERSIONINFOW ver;

  memset(h, 0, sizeof(*h));
  h->native_machine = 0;

  wow2 = (sd_IsWow64Process2_t)sd_setup_proc(L"kernel32.dll", "IsWow64Process2");
  if (wow2 != NULL) {
    USHORT process_machine = 0, native_machine = 0;
    if (wow2(GetCurrentProcess(), &process_machine, &native_machine) && native_machine != 0)
      h->native_machine = (WORD)native_machine;
  }
  if (h->native_machine == 0) {
    BOOL is_wow = FALSE;
    wow = (sd_IsWow64Process_t)sd_setup_proc(L"kernel32.dll", "IsWow64Process");
    if (wow == NULL || !wow(GetCurrentProcess(), &is_wow) || !is_wow) {
#if defined(_M_ARM)
      /* A 32-bit process on a 32-bit ARM OS: the ARM32 stub (04 §5.1). */
      h->native_machine = IMAGE_FILE_MACHINE_ARMNT;
#else
      /* A 32-bit process on a 32-bit OS (this stub is always x86 code). */
      h->native_machine = IMAGE_FILE_MACHINE_I386;
#endif
    } else {
      gnsi = (sd_GetNativeSystemInfo_t)sd_setup_proc(L"kernel32.dll", "GetNativeSystemInfo");
      if (gnsi != NULL) {
        SYSTEM_INFO si;
        memset(&si, 0, sizeof(si));
        gnsi(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
          h->native_machine = IMAGE_FILE_MACHINE_AMD64;
        else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
          h->native_machine = IMAGE_FILE_MACHINE_ARM64;
      }
    }
  }

  h->sse2 = IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE) ? 1 : 0;

  rtl = (sd_RtlGetVersion_t)sd_setup_proc(L"ntdll.dll", "RtlGetVersion");
  memset(&ver, 0, sizeof(ver));
  ver.dwOSVersionInfoSize = sizeof(ver);
  if (rtl != NULL && rtl(&ver) == 0) {
    h->os_major = ver.dwMajorVersion;
    h->os_minor = ver.dwMinorVersion;
  } else {
    /* Pre-NT5 fallback: never reached on XP+, kept so that a missing export cannot pick a wrong flavour. */
    h->os_major = 5;
    h->os_minor = 1;
  }
  h->is_admin = detect_is_admin();
}

int sd_setup_select_flavour(const sd_setup_host *h, sd_setup_flavour override, sd_setup_flavour *out,
                            sd_msg_id *reason)
{
#if defined(_M_ARM)
  /* The ARM32 stub is ARM32 code (04 §1.1, §6.2). Every ARM host runs it, natively or emulated on ARM64, and the
     only flavour it installs is arm32. The universal x86 stub never takes this path. */
  if (h->native_machine != IMAGE_FILE_MACHINE_ARMNT && h->native_machine != IMAGE_FILE_MACHINE_ARM64) {
    *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_CPU;
    return 1;
  }
  if (override != SD_SETUP_FL_NONE && override != SD_SETUP_FL_ARM32) {
    *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_BITNESS;
    return 1;
  }
  *out = SD_SETUP_FL_ARM32;
  return 0;
#else
  sd_setup_flavour base = SD_SETUP_FL_NONE;

  switch (h->native_machine) {
  case IMAGE_FILE_MACHINE_I386:
    base = h->sse2 ? SD_SETUP_FL_X86_SSE2 : SD_SETUP_FL_X86_IA32;
    if (override == SD_SETUP_FL_NONE || override == SD_SETUP_FL_X86_IA32) {
      if (override == SD_SETUP_FL_X86_IA32)
        base = SD_SETUP_FL_X86_IA32;
    } else if (override == SD_SETUP_FL_X86_SSE2) {
      if (!h->sse2) {
        *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_SSE2;
        return 1;
      }
      base = SD_SETUP_FL_X86_SSE2;
    } else {
      *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_BITNESS;
      return 1;
    }
    break;

  case IMAGE_FILE_MACHINE_AMD64:
    base = (h->os_major >= 10) ? SD_SETUP_FL_X64_MODERN : SD_SETUP_FL_X64_XP;
    if (override == SD_SETUP_FL_NONE) {
      /* base as chosen above */
    } else if (override == SD_SETUP_FL_X64_XP) {
      base = SD_SETUP_FL_X64_XP;
    } else if (override == SD_SETUP_FL_X64_MODERN) {
      if (h->os_major < 10) {
        *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_OS;
        return 1;
      }
      base = SD_SETUP_FL_X64_MODERN;
    } else {
      *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_BITNESS;
      return 1;
    }
    break;

  case IMAGE_FILE_MACHINE_ARM64:
    if (override != SD_SETUP_FL_NONE && override != SD_SETUP_FL_ARM64) {
      *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_BITNESS;
      return 1;
    }
    base = SD_SETUP_FL_ARM64;
    break;

  case IMAGE_FILE_MACHINE_ARMNT:
    *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_ARM32;
    return 1;

  default:
    *reason = SD_MSG_INSTALLER_ERROR_FLAVOUR_CPU;
    return 1;
  }

  *out = base;
  return 0;
#endif
}

/* ------------------------------------------------------------------ Dokany and versions */

sd_setup_dokany_plan sd_setup_dokany_decide(sd_setup_mode mode, int dokany_set, sd_setup_dokany_arg arg,
                                            unsigned os_major, unsigned os_minor)
{
  int driver_ok = (os_major > 6) || (os_major == 6 && os_minor >= 1);

  /* Per-user installs never install the driver (04 §6.3). */
  if (mode != SD_SETUP_MODE_MACHINE)
    return SD_SETUP_DOKANY_SKIP_PLAN;
  if (dokany_set && arg == SD_SETUP_DOKANY_SKIP)
    return SD_SETUP_DOKANY_SKIP_PLAN;
  /* Pre-checked default (D36): install when the OS can take the driver (7 SP1+ per 04 §6.3). */
  if (!driver_ok)
    return SD_SETUP_DOKANY_UNAVAILABLE_PLAN;
  return SD_SETUP_DOKANY_INSTALL_PLAN;
}

static int parse_version_part(const wchar_t **p, unsigned long *out)
{
  unsigned long v = 0;
  int any = 0;
  while (**p >= L'0' && **p <= L'9') {
    v = v * 10 + (unsigned long)(**p - L'0');
    (*p)++;
    any = 1;
    if (v > 0xFFFFFFFFul / 10)
      v = 0xFFFFFFFFul;
  }
  *out = any ? v : 0;
  return any;
}

int sd_setup_version_compare(const wchar_t *a, const wchar_t *b)
{
  const wchar_t *pa = a ? a : L"";
  const wchar_t *pb = b ? b : L"";
  int i;

  for (i = 0; i < 4; i++) {
    unsigned long va = 0, vb = 0;
    parse_version_part(&pa, &va);
    parse_version_part(&pb, &vb);
    if (va != vb)
      return va < vb ? -1 : 1;
    if (*pa == L'.')
      pa++;
    if (*pb == L'.')
      pb++;
  }
  return 0;
}

/* ------------------------------------------------------------------ payload table and CAB names */

static int hex_nibble(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* One line per flavour: "<name> <sha256 hex> <size>". Lines that do not name the flavour are skipped. */
int sd_setup_payload_table_lookup(const char *table, size_t n, const wchar_t *flavour, unsigned char sha[32])
{
  size_t i = 0;
  size_t flen;

  if (table == NULL || flavour == NULL)
    return 1;
  flen = wcslen(flavour);

  while (i < n) {
    size_t tok = 0;
    int match = 1;
    int j;

    /* Field 1: the flavour name, compared character by character. */
    while (i < n && table[i] != ' ' && table[i] != '\t' && table[i] != '\r' && table[i] != '\n') {
      if (tok >= flen || (wchar_t)(unsigned char)table[i] != flavour[tok])
        match = 0;
      tok++;
      i++;
    }
    if (tok != flen)
      match = 0;

    /* Field 2: 64 hex digits. */
    while (i < n && (table[i] == ' ' || table[i] == '\t'))
      i++;
    if (match && i + 64 <= n) {
      for (j = 0; j < 32; j++) {
        int hi = hex_nibble(table[i + 2 * j]);
        int lo = hex_nibble(table[i + 2 * j + 1]);
        if (hi < 0 || lo < 0) {
          match = 0;
          break;
        }
        sha[j] = (unsigned char)((hi << 4) | lo);
      }
      if (match)
        return 0;
    }

    /* Skip to the end of this line. */
    while (i < n && table[i] != '\n')
      i++;
    if (i < n)
      i++;
  }
  return 1;
}

void sd_setup_cab_limits_default(sd_setup_cab_limits *l)
{
  l->max_member = 512ull * 1024 * 1024;
  l->max_total = 1536ull * 1024 * 1024;
  l->max_members = 4096;
}

static int is_reserved_device(const char *comp, size_t len)
{
  static const char *const names[] = {
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
  };
  size_t i;
  for (i = 0; i < SD_SETUP_COUNTOF(names); i++) {
    size_t nl = strlen(names[i]);
    size_t k;
    if (len < nl)
      continue;
    for (k = 0; k < nl; k++) {
      if (toupper((unsigned char)comp[k]) != names[i][k])
        break;
    }
    if (k == nl && (len == nl || comp[nl] == '.'))
      return 1;
  }
  return 0;
}

int sd_setup_cab_name_ok(const char *name)
{
  size_t len, i, comp_start = 0;

  if (name == NULL)
    return 0;
  len = strlen(name);
  if (len == 0 || len >= MAX_PATH)
    return 0;
  if (name[0] == '\\' || name[0] == '/')
    return 0;
  if (len >= 2 && name[1] == ':')
    return 0;

  for (i = 0; i <= len; i++) {
    unsigned char c = (unsigned char)name[i];
    if (i == len || c == '\\') {
      size_t clen = i - comp_start;
      if (clen == 0)
        return 0;                 /* empty component: "a\\\\b" or trailing separator */
      if (clen == 1 && name[comp_start] == '.')
        return 0;
      if (clen == 2 && name[comp_start] == '.' && name[comp_start + 1] == '.')
        return 0;                 /* traversal */
      if (name[i - 1] == '.' || name[i - 1] == ' ')
        return 0;                 /* Windows strips trailing dots and spaces */
      if (is_reserved_device(name + comp_start, clen))
        return 0;
      comp_start = i + 1;
      continue;
    }
    if (c >= 0x80 || c < 0x20)
      return 0;
    if (c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
      return 0;
  }
  return 1;
}
