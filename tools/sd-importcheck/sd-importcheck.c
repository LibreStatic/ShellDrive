/* sd-importcheck: PE import / delay-import / TLS / subsystem / CFG / CET audit (04 §2.4).
 *
 *   sd-importcheck --floor <list.txt> [--floor ...] [--subsystem 5.02] [--require-cfg | --forbid-cfg]
 *                  [--require-cet] [--no-delayload] [--no-tls] <image>...
 *   sd-importcheck --list <image>          print every import as dll!function (to build floor lists)
 *
 * Floor list lines: "dll!function", "dll!#ordinal" or "dll!*" (any function of that DLL); '#' starts a
 * comment. DLL names compare case-insensitively, function names exactly. Every image must also be
 * /DYNAMICBASE and /NXCOMPAT, and DLLs must not have a TLS directory (implicit TLS breaks on XP when
 * loaded with LoadLibrary). Exit code 0 = clean, 1 = violations, 2 = usage or I/O error.
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

static void lower(char *s)
{
  for (; *s; s++) *s = (char)tolower((unsigned char)*s);
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
  char dll_lower[256], fn[600];
  size_t step = im->pe64 ? 8 : 4;
  snprintf(dll_lower, sizeof(dll_lower), "%s", dll);
  lower(dll_lower);
  for (;; thunk_rva += (DWORD)step) {
    const unsigned char *t = (const unsigned char *)rva_ptr(im, thunk_rva, step);
    ULONGLONG v;
    if (!t) { violation(im, "bad thunk table for %s%s", dll, ""); return; }
    v = im->pe64 ? *(const ULONGLONG *)t : *(const DWORD *)t;
    if (v == 0) break;
    if (im->pe64 ? (v & IMAGE_ORDINAL_FLAG64) != 0 : (v & IMAGE_ORDINAL_FLAG32) != 0) {
      snprintf(fn, sizeof(fn), "#%u", (unsigned)(v & 0xFFFF));
    } else {
      const char *name = rva_str(im, (DWORD)(v + 2));
      if (!name) { violation(im, "bad import name in %s%s", dll, ""); return; }
      snprintf(fn, sizeof(fn), "%s", name);
    }
    if (list) {
      printf("%s!%s%s\n", dll_lower, fn, delay ? "   (delay-load)" : "");
    } else if (!floor_allows(dll_lower, fn)) {
      g_violations++;
      fprintf(stderr, "sd-importcheck: %s: %s!%s%s is not on the OS floor list\n", im->path, dll_lower, fn,
              delay ? " (delay-load)" : "");
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

int main(int argc, char **argv)
{
  int i, list = 0, require_cfg = 0, forbid_cfg = 0, require_cet = 0, no_delay = 0, no_tls = 0, nimages = 0;
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
    else if (strcmp(a, "--no-delayload") == 0) no_delay = 1;
    else if (strcmp(a, "--no-tls") == 0) no_tls = 1;
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
