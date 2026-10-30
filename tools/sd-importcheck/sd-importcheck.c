/* sd-importcheck: PE import / delay-import / TLS / subsystem / CFG / CET audit (04 §2.4).
 *
 *   sd-importcheck --floor <list.txt> [--floor ...] [--subsystem 5.02] [--require-cfg | --forbid-cfg]
 *                  [--require-cet] [--require-safeseh] [--no-delayload] [--no-tls] <image>...
 *   sd-importcheck --list <image>          print every import as dll!function (to build floor lists)
 *
 * Floor list lines: "dll!function", "dll!#ordinal" or "dll!*" (any function of that DLL); '#' starts a
 * comment. DLL names compare case-insensitively, function names exactly. Imports by ordinal from
 * ws2_32.dll and wsock32.dll (the SDK 7.1A import libraries bind the WinSock 1.1 set by ordinal) are
 * mapped to their names first, so the floor list judges them by name. Every image must also be
 * /DYNAMICBASE and /NXCOMPAT, and DLLs must not have a TLS directory (implicit TLS breaks on XP when
 * loaded with LoadLibrary). --require-safeseh (x86 flavours, 04 §3.2): a 32-bit image must carry a
 * SafeSEH handler table in its load-config directory, or be marked IMAGE_DLLCHARACTERISTICS_NO_SEH.
 * Exit code 0 = clean, 1 = violations, 2 = usage or I/O error.
 * Build-time tool, never shipped. */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SD_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20
#define SD_DLLCHAR_EX_CET_COMPAT            0x0001
#define SD_DLLCHAR_GUARD_CF                 0x4000

typedef struct sd_delay_descr {          /* IMAGE_DELAYLOAD_DESCRIPTOR (RVA form) */
  DWORD attributes, dll_name_rva, hmod_rva, iat_rva, int_rva, bound_iat_rva, unload_iat_rva, timestamp;
} sd_delay_descr;

typedef struct image {
  const char *path;
  unsigned char *data;
  size_t size;
  int pe64;
  IMAGE_FILE_HEADER *fh;
  void *oh;
  IMAGE_SECTION_HEADER *sec;
  unsigned nsec;
} image;

static char **g_floor;
static size_t g_nfloor, g_capfloor;
static int g_violations;

/* --knowndlls <list>: the only DLL names a checked image may import statically (04 §2.4, TM-R33). */
static char **g_known;
static size_t g_nknown, g_capknown;

static void lower(char *s)
{
  for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static int known_load(const char *path)
{
  FILE *f = fopen(path, "rb");
  char line[512] = { 0 };
  if (!f) {
    fprintf(stderr, "sd-importcheck: cannot open KnownDLLs list %s\n", path);
    return 0;
  }
  while (fgets(line, sizeof(line), f)) {
    size_t b = 0, e = strcspn(line, "#\r\n");
    char *p;
    while (b < e && (line[b] == ' ' || line[b] == '\t')) b++;
    while (e > b && (line[e - 1] == ' ' || line[e - 1] == '\t')) e--;
    line[e] = 0;
    p = line + b;
    if (!*p) continue;
    if (g_nknown == g_capknown) {
      char **nk;
      g_capknown = g_capknown ? g_capknown * 2 : 32;
      nk = (char **)realloc(g_known, g_capknown * sizeof(char *));
      if (!nk) exit(2);
      g_known = nk;
    }
    g_known[g_nknown] = _strdup(p);
    if (!g_known[g_nknown]) exit(2);
    lower(g_known[g_nknown]);
    g_nknown++;
  }
  fclose(f);
  return 1;
}

static int known_allows(const char *dll_lower)
{
  size_t i;
  for (i = 0; i < g_nknown; i++) {
    if (strcmp(g_known[i], dll_lower) == 0) return 1;
  }
  return 0;
}

static int floor_load(const char *path)
{
  FILE *f = fopen(path, "rb");
  char line[1024] = { 0 };
  if (!f) {
    fprintf(stderr, "sd-importcheck: cannot open floor list %s\n", path);
    return 0;
  }
  while (fgets(line, sizeof(line), f)) {
    char *p = line, *e, *bang;
#pragma warning(suppress: 28199)   /* fgets wrote the buffer; the analyzer cannot see it */
    while (*p == ' ' || *p == '\t') p++;
    e = p + strcspn(p, "#\r\n");
    while (e > p && (e[-1] == ' ' || e[-1] == '\t')) e--;
    *e = 0;
    if (!*p) continue;
    bang = strchr(p, '!');
    if (!bang) {
      fprintf(stderr, "sd-importcheck: %s: malformed line '%s'\n", path, p);
      fclose(f);
      return 0;
    }
    *bang = 0;
    lower(p);
    *bang = '!';
    if (g_nfloor == g_capfloor) {
      g_capfloor = g_capfloor ? g_capfloor * 2 : 512;
      char **nf = (char **)realloc(g_floor, g_capfloor * sizeof(char *));
      if (!nf) exit(2);
      g_floor = nf;
    }
    g_floor[g_nfloor] = _strdup(p);
    if (!g_floor[g_nfloor]) exit(2);
    g_nfloor++;
  }
  fclose(f);
  return 1;
}

static int floor_allows(const char *dll_lower, const char *fn)
{
  char key[1024];
  size_t i;
  snprintf(key, sizeof(key), "%s!%s", dll_lower, fn);
  for (i = 0; i < g_nfloor; i++) {
    const char *f = g_floor[i];
    size_t dl = strlen(dll_lower);
    if (strcmp(f, key) == 0) return 1;
    if (strncmp(f, dll_lower, dl) == 0 && f[dl] == '!' && strcmp(f + dl + 1, "*") == 0) return 1;
  }
  return 0;
}

/* Frozen ordinals of the WinSock DLLs, exactly as the SDK 7.1A import libraries bind them (cross-checked
   against the export tables of ws2_32.dll and wsock32.dll). The two DLLs differ at 10-12. Any other
   ordinal is reported as "#n" and must be on the floor list as such. */
typedef struct ord_name { unsigned short ord; const char *name; } ord_name;

#define SD_WINSOCK11_COMMON \
  { 1, "accept" }, { 2, "bind" }, { 3, "closesocket" }, { 4, "connect" }, { 5, "getpeername" }, \
  { 6, "getsockname" }, { 7, "getsockopt" }, { 8, "htonl" }, { 9, "htons" }, { 13, "listen" }, \
  { 14, "ntohl" }, { 15, "ntohs" }, { 16, "recv" }, { 17, "recvfrom" }, { 18, "select" }, { 19, "send" }, \
  { 20, "sendto" }, { 21, "setsockopt" }, { 22, "shutdown" }, { 23, "socket" }, { 51, "gethostbyaddr" }, \
  { 52, "gethostbyname" }, { 53, "getprotobyname" }, { 54, "getprotobynumber" }, { 55, "getservbyname" }, \
  { 56, "getservbyport" }, { 57, "gethostname" }, { 101, "WSAAsyncSelect" }, { 102, "WSAAsyncGetHostByAddr" }, \
  { 103, "WSAAsyncGetHostByName" }, { 104, "WSAAsyncGetProtoByNumber" }, { 105, "WSAAsyncGetProtoByName" }, \
  { 106, "WSAAsyncGetServByPort" }, { 107, "WSAAsyncGetServByName" }, { 108, "WSACancelAsyncRequest" }, \
  { 109, "WSASetBlockingHook" }, { 110, "WSAUnhookBlockingHook" }, { 111, "WSAGetLastError" }, \
  { 112, "WSASetLastError" }, { 113, "WSACancelBlockingCall" }, { 114, "WSAIsBlocking" }, { 115, "WSAStartup" }, \
  { 116, "WSACleanup" }, { 151, "__WSAFDIsSet" }, { 500, "WEP" }

static const ord_name k_ws2_32_ords[] = {
  SD_WINSOCK11_COMMON, { 10, "ioctlsocket" }, { 11, "inet_addr" }, { 12, "inet_ntoa" }, { 0, NULL }
};

static const ord_name k_wsock32_ords[] = {
  SD_WINSOCK11_COMMON, { 10, "inet_addr" }, { 11, "inet_ntoa" }, { 12, "ioctlsocket" },
  { 1100, "inet_network" }, { 1101, "getnetbyname" }, { 1102, "rcmd" }, { 1103, "rexec" }, { 1104, "rresvport" },
  { 1105, "sethostname" }, { 1106, "dn_expand" }, { 1107, "WSARecvEx" }, { 1108, "s_perror" },
  { 1109, "GetAddressByNameA" }, { 1110, "GetAddressByNameW" }, { 1111, "EnumProtocolsA" },
  { 1112, "EnumProtocolsW" }, { 1113, "GetTypeByNameA" }, { 1114, "GetTypeByNameW" }, { 1115, "GetNameByTypeA" },
  { 1116, "GetNameByTypeW" }, { 1117, "SetServiceA" }, { 1118, "SetServiceW" }, { 1119, "GetServiceA" },
  { 1120, "GetServiceW" }, { 1130, "NPLoadNameSpaces" }, { 1140, "TransmitFile" }, { 1141, "AcceptEx" },
  { 1142, "GetAcceptExSockaddrs" }, { 0, NULL }
};

/* Name of an import by ordinal, or NULL when the DLL/ordinal is not in a known table. */
static const char *ordinal_name(const char *dll_lower, unsigned ord)
{
  const ord_name *t = NULL;
  if (strcmp(dll_lower, "ws2_32.dll") == 0) t = k_ws2_32_ords;
  else if (strcmp(dll_lower, "wsock32.dll") == 0) t = k_wsock32_ords;
  for (; t && t->name; t++)
    if (t->ord == ord) return t->name;
  return NULL;
}

static void *rva_ptr(const image *im, DWORD rva, size_t need)
{
  unsigned i;
  for (i = 0; i < im->nsec; i++) {
    const IMAGE_SECTION_HEADER *s = &im->sec[i];
    DWORD vsize = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
    if (rva >= s->VirtualAddress && rva < s->VirtualAddress + vsize) {
      size_t off = (size_t)s->PointerToRawData + (rva - s->VirtualAddress);
      if (off + need > im->size || rva - s->VirtualAddress + need > s->SizeOfRawData) return NULL;
      return im->data + off;
    }
  }
  return NULL;
}

static const char *rva_str(const image *im, DWORD rva)
{
  const char *s = (const char *)rva_ptr(im, rva, 1);
  size_t max;
  if (!s) return NULL;
  max = im->size - (size_t)((const unsigned char *)s - im->data);
  return memchr(s, 0, max) ? s : NULL;
}

static IMAGE_DATA_DIRECTORY *data_dir(const image *im, int idx)
{
  if (im->pe64) {
    IMAGE_OPTIONAL_HEADER64 *o = (IMAGE_OPTIONAL_HEADER64 *)im->oh;
    return (DWORD)idx < o->NumberOfRvaAndSizes ? &o->DataDirectory[idx] : NULL;
  } else {
    IMAGE_OPTIONAL_HEADER32 *o = (IMAGE_OPTIONAL_HEADER32 *)im->oh;
    return (DWORD)idx < o->NumberOfRvaAndSizes ? &o->DataDirectory[idx] : NULL;
  }
}

static int image_load(image *im, const char *path)
{
  FILE *f = fopen(path, "rb");
  long n;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS32 *nt;
  memset(im, 0, sizeof(*im));
  im->path = path;
  if (!f) { fprintf(stderr, "sd-importcheck: cannot open %s\n", path); return 0; }
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  im->data = (unsigned char *)malloc((size_t)n);
  if (!im->data || fread(im->data, 1, (size_t)n, f) != (size_t)n) { fclose(f); return 0; }
  fclose(f);
  im->size = (size_t)n;
  dos = (IMAGE_DOS_HEADER *)im->data;
  if (im->size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
      (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > im->size) {
    fprintf(stderr, "sd-importcheck: %s is not a PE image\n", path);
    return 0;
  }
  nt = (IMAGE_NT_HEADERS32 *)(im->data + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    fprintf(stderr, "sd-importcheck: %s has no PE signature\n", path);
    return 0;
  }
  im->fh = &nt->FileHeader;
  im->oh = &nt->OptionalHeader;
  im->pe64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  im->sec = (IMAGE_SECTION_HEADER *)((unsigned char *)im->oh + im->fh->SizeOfOptionalHeader);
  im->nsec = im->fh->NumberOfSections;
  if ((size_t)((unsigned char *)(im->sec + im->nsec) - im->data) > im->size) {
    fprintf(stderr, "sd-importcheck: %s: truncated section table\n", path);
    return 0;
  }
  return 1;
}

static void violation(const image *im, const char *fmt, const char *a, const char *b)
{
  g_violations++;
  fprintf(stderr, "sd-importcheck: %s: ", im->path);
  fprintf(stderr, fmt, a, b);
  fputc('\n', stderr);
}

/* Walks a thunk array (INT). Calls back with function name or "#ordinal". */
static void walk_thunks(const image *im, const char *dll, DWORD thunk_rva, int list, int delay)
{
  char dll_lower[256], fn[600], ord_note[32];
  size_t step = im->pe64 ? 8 : 4;
  snprintf(dll_lower, sizeof(dll_lower), "%s", dll);
  lower(dll_lower);
  if (!list && g_nknown > 0 && !known_allows(dll_lower)) {
    g_violations++;
    fprintf(stderr, "sd-importcheck: %s: imports %s, which is not on the KnownDLLs list (TM-R33)\n", im->path,
            dll_lower);
    return;
  }
  for (;; thunk_rva += (DWORD)step) {
    const unsigned char *t = (const unsigned char *)rva_ptr(im, thunk_rva, step);
    ULONGLONG v;
    if (!t) { violation(im, "bad thunk table for %s%s", dll, ""); return; }
    v = im->pe64 ? *(const ULONGLONG *)t : *(const DWORD *)t;
    if (v == 0) break;
    ord_note[0] = 0;
    if (im->pe64 ? (v & IMAGE_ORDINAL_FLAG64) != 0 : (v & IMAGE_ORDINAL_FLAG32) != 0) {
      unsigned ord = (unsigned)(v & 0xFFFF);
      const char *name = ordinal_name(dll_lower, ord);
      if (name) {
        snprintf(fn, sizeof(fn), "%s", name);
        snprintf(ord_note, sizeof(ord_note), " (by ordinal #%u)", ord);
      } else {
        snprintf(fn, sizeof(fn), "#%u", ord);
      }
    } else {
      const char *name = rva_str(im, (DWORD)(v + 2));
      if (!name) { violation(im, "bad import name in %s%s", dll, ""); return; }
      snprintf(fn, sizeof(fn), "%s", name);
    }
    if (list) {
      printf("%s!%s%s%s\n", dll_lower, fn, ord_note, delay ? "   (delay-load)" : "");
    } else if (!floor_allows(dll_lower, fn)) {
      g_violations++;
      fprintf(stderr, "sd-importcheck: %s: %s!%s%s%s is not on the OS floor list\n", im->path, dll_lower, fn,
              ord_note, delay ? " (delay-load)" : "");
    }
  }
}

static void check_imports(const image *im, int list, int no_delay)
{
  IMAGE_DATA_DIRECTORY *d = data_dir(im, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if (d && d->VirtualAddress) {
    DWORD rva = d->VirtualAddress;
    for (;; rva += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
      IMAGE_IMPORT_DESCRIPTOR *id = (IMAGE_IMPORT_DESCRIPTOR *)rva_ptr(im, rva, sizeof(*id));
      const char *dll;
      if (!id) { violation(im, "bad import directory%s%s", "", ""); break; }
      if (id->Name == 0) break;
      dll = rva_str(im, id->Name);
      if (!dll) { violation(im, "bad import DLL name%s%s", "", ""); break; }
      walk_thunks(im, dll, id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk, list, 0);
    }
  }
  d = data_dir(im, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
  if (d && d->VirtualAddress) {
    DWORD rva = d->VirtualAddress;
    if (no_delay && !list)
      violation(im, "has a delay-load import directory (forbidden here)%s%s", "", "");
    for (;; rva += sizeof(sd_delay_descr)) {
      sd_delay_descr *dd = (sd_delay_descr *)rva_ptr(im, rva, sizeof(*dd));
      const char *dll;
      if (!dd) { violation(im, "bad delay-import directory%s%s", "", ""); break; }
      if (dd->dll_name_rva == 0) break;
      dll = rva_str(im, dd->dll_name_rva);
      if (!dll) break;
      walk_thunks(im, dll, dd->int_rva, list, 1);
    }
  }
}

static int has_cet(const image *im)
{
  IMAGE_DATA_DIRECTORY *d = data_dir(im, IMAGE_DIRECTORY_ENTRY_DEBUG);
  DWORD i, n;
  if (!d || !d->VirtualAddress) return 0;
  n = d->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
  for (i = 0; i < n; i++) {
    IMAGE_DEBUG_DIRECTORY *dd = (IMAGE_DEBUG_DIRECTORY *)rva_ptr(im, d->VirtualAddress + i * sizeof(*dd), sizeof(*dd));
    if (!dd) return 0;
    if (dd->Type == SD_DEBUG_TYPE_EX_DLLCHARACTERISTICS && dd->SizeOfData >= 4 &&
        (size_t)dd->PointerToRawData + 4 <= im->size) {
      DWORD v = *(const DWORD *)(im->data + dd->PointerToRawData);
      return (v & SD_DLLCHAR_EX_CET_COMPAT) != 0;
    }
  }
  return 0;
}

/* /SAFESEH: IMAGE_LOAD_CONFIG_DIRECTORY32.SEHandlerTable (offset 0x40) set, or NO_SEH. */
static int has_safeseh(const image *im, WORD dllchar)
{
  IMAGE_DATA_DIRECTORY *d = data_dir(im, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
  const unsigned char *lc;
  DWORD size, table;
  if (dllchar & IMAGE_DLLCHARACTERISTICS_NO_SEH) return 1;
  if (!d || !d->VirtualAddress) return 0;
  lc = (const unsigned char *)rva_ptr(im, d->VirtualAddress, 0x48);
  if (!lc) return 0;
  memcpy(&size, lc, 4);
  if (size < 0x48) return 0;
  memcpy(&table, lc + 0x40, 4);
  return table != 0;
}

int main(int argc, char **argv)
{
  int i, list = 0, require_cfg = 0, forbid_cfg = 0, require_cet = 0, require_safeseh = 0, no_delay = 0, no_tls = 0;
  int nimages = 0;
  int sub_major = -1, sub_minor = -1;
  for (i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (strcmp(a, "--floor") == 0 && i + 1 < argc) { if (!floor_load(argv[++i])) return 2; }
    else if (strcmp(a, "--subsystem") == 0 && i + 1 < argc) {
      if (sscanf(argv[++i], "%d.%d", &sub_major, &sub_minor) != 2) { fprintf(stderr, "bad --subsystem\n"); return 2; }
    }
    else if (strcmp(a, "--require-cfg") == 0) require_cfg = 1;
    else if (strcmp(a, "--forbid-cfg") == 0) forbid_cfg = 1;
    else if (strcmp(a, "--require-cet") == 0) require_cet = 1;
    else if (strcmp(a, "--require-safeseh") == 0) require_safeseh = 1;
    else if (strcmp(a, "--no-delayload") == 0) no_delay = 1;
    else if (strcmp(a, "--no-tls") == 0) no_tls = 1;
    else if (strcmp(a, "--knowndlls") == 0 && i + 1 < argc) { if (!known_load(argv[++i])) return 2; }
    else if (strcmp(a, "--list") == 0) list = 1;
    else if (a[0] == '-') { fprintf(stderr, "sd-importcheck: unknown option %s\n", a); return 2; }
    else {
      image im;
      WORD dllchar, smaj, smin;
      IMAGE_DATA_DIRECTORY *tls;
      nimages++;
      if (!image_load(&im, a)) return 2;
      if (!list && g_nfloor == 0) { fprintf(stderr, "sd-importcheck: no --floor list given\n"); return 2; }
      check_imports(&im, list, no_delay);
      if (list) { free(im.data); continue; }
      if (im.pe64) {
        IMAGE_OPTIONAL_HEADER64 *o = (IMAGE_OPTIONAL_HEADER64 *)im.oh;
        dllchar = o->DllCharacteristics; smaj = o->MajorSubsystemVersion; smin = o->MinorSubsystemVersion;
      } else {
        IMAGE_OPTIONAL_HEADER32 *o = (IMAGE_OPTIONAL_HEADER32 *)im.oh;
        dllchar = o->DllCharacteristics; smaj = o->MajorSubsystemVersion; smin = o->MinorSubsystemVersion;
      }
      if (sub_major >= 0 && (smaj != sub_major || smin != sub_minor)) {
        char got[32], want[32];
        snprintf(got, sizeof(got), "%u.%02u", smaj, smin);
        snprintf(want, sizeof(want), "%d.%02d", sub_major, sub_minor);
        violation(&im, "subsystem version is %s, expected %s", got, want);
      }
      if (!(dllchar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) violation(&im, "not /DYNAMICBASE%s%s", "", "");
      if (!(dllchar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) violation(&im, "not /NXCOMPAT%s%s", "", "");
      if (require_cfg && !(dllchar & SD_DLLCHAR_GUARD_CF)) violation(&im, "missing /guard:cf%s%s", "", "");
      if (forbid_cfg && (dllchar & SD_DLLCHAR_GUARD_CF)) violation(&im, "has /guard:cf (not allowed on this flavour)%s%s", "", "");
      if (require_cet && !has_cet(&im)) violation(&im, "missing /CETCOMPAT%s%s", "", "");
      if (require_safeseh && (im.pe64 || !has_safeseh(&im, dllchar)))
        violation(&im, "missing /SAFESEH handler table (32-bit images only)%s%s", "", "");
      tls = data_dir(&im, IMAGE_DIRECTORY_ENTRY_TLS);
      if ((no_tls || (im.fh->Characteristics & IMAGE_FILE_DLL)) && tls && tls->VirtualAddress)
        violation(&im, "has a TLS directory (no implicit TLS in DLLs, 04 §2.4)%s%s", "", "");
      free(im.data);
    }
  }
  if (nimages == 0) {
    fprintf(stderr, "usage: sd-importcheck --floor <list> [options] <image>... | --list <image>\n");
    return 2;
  }
  if (g_violations) {
    fprintf(stderr, "sd-importcheck: %d violation(s)\n", g_violations);
    return 1;
  }
  return 0;
}
