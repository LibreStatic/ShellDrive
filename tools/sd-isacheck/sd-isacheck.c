/* sd-isacheck: instruction-set audit of x86 images and the constant-time helper-call gate (04 §2.4,
 * §3.2; 01 §2.3, §2.4 rule 3, §2.7.5; TM-R02, TST-03).
 *
 *   sd-isacheck --floor ia32|sse2 [--allow <list.txt>]... [--entry <symbol>] [--list] <image>...
 *       Linear-sweep disassembly of every code section of a 32-bit PE image, function by function, with
 *       the function boundaries taken from the image's PDB through dbghelp (SymEnumSymbols: private
 *       function symbols with their sizes, plus public symbols for assembler routines). Fails on any
 *       instruction above the floor: "ia32" = no MMX/SSE/SSE2/SSE3+/AVX/AVX-512/3DNow!/FXSR-XSAVE (the
 *       x86-ia32 flavour, Pentium Pro class); "sse2" = no SSE3+/AVX/AVX-512/3DNow! (the x86-sse2
 *       flavour; its fast paths with newer instructions must sit in allow-listed, CPUID-dispatched
 *       functions). Functions matching the allow list (static CRT routines that dispatch on
 *       __isa_available / __sse2_available at run time) are reported with --list but do not fail.
 *       On the sse2 floor a function that reads __isa_available (the auto-vectorizer's SSE4.x loops are
 *       guarded that way) counts as dispatching and its hits are allowed too.
 *       --entry: the image entry point must be <symbol> and that function must be IA32-clean even on
 *       the sse2 floor (the x86-sse2 entry thunk sd_cpucheck_entry, 04 §3.2).
 *       Jump tables inside .text: a dword covered by a base relocation at an instruction boundary is
 *       data. In a sized (compiler-generated) function the sweep stops there, because MSVC places switch
 *       tables after the function body; in an unsized (assembler) range the dword is skipped.
 *
 *   sd-isacheck --ct-lib <lib> --ct-member <object name>... [--config <cfg>] [--list]
 *       Constant-time gate (TM-R02): reads the COFF objects of the given members of a static library
 *       and fails if any code section has a relocation to a compiler runtime helper (_allmul, _alldiv,
 *       _aulldiv, _allrem, _aullrem, _alldvrm, _aulldvrm, _allshl, _allshr, _aullshr and the floating-
 *       point conversion helpers). With /Gy every function is its own COMDAT section, so the report names
 *       the calling function. --list also prints every external symbol those functions reference.
 *       --config: the gate judges optimized (Release) objects only, as shipped (01 §2.7.5); with any other
 *       configuration it reports a skip and exits 0, because /Od turns even constant 64-bit shifts into
 *       _allshl/_aullshr calls.
 *
 *   sd-isacheck --selftest      decoder self-test on known encodings
 *
 * SD_ISACHECK_DEBUG=1 prints dbghelp's symbol search (when a PDB is not found). The PDB must sit next
 * to the image and match it exactly; the images record only the PDB file name (/PDBALTPATH).
 *
 * Exit code 0 = clean, 1 = violations, 2 = usage, I/O or missing symbols. Build-time tool, never shipped. */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4091)   /* dbghelp.h of SDK 7.1A: typedef without a name */
#include <dbghelp.h>
#pragma warning(pop)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "x86_decode.h"

#define SD_SYMTAG_FUNCTION 5
#define SD_SYMTAG_PUBLIC   10
#define SD_MIN_SIZE(a, b)  ((a) < (b) ? (a) : (b))
#define SD_MIN_DWORD(a, b) ((DWORD)((a) < (b) ? (a) : (b)))

static int g_violations;
static int g_list;

/* ---------------------------------------------------------------- utilities */

static unsigned char *read_file(const char *path, size_t *size)
{
  FILE *f = fopen(path, "rb");
  long n;
  unsigned char *d;
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
  d = (unsigned char *)malloc((size_t)n + 1);
  if (!d || fread(d, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(d); return NULL; }
  fclose(f);
  *size = (size_t)n;
  return d;
}

typedef struct strlist { char **v; size_t n, cap; } strlist;

static void strlist_add(strlist *l, const char *s)
{
  if (l->n == l->cap) {
    char **nv;
    l->cap = l->cap ? l->cap * 2 : 64;
    nv = (char **)realloc(l->v, l->cap * sizeof(char *));
    if (!nv) exit(2);
    l->v = nv;
  }
  l->v[l->n] = _strdup(s);
  if (!l->v[l->n]) exit(2);
  l->n++;
}

/* Allow-list entry: exact name, a prefix when it ends in '*', a suffix when it starts with '*'. */
static int glob_match(const char *pat, const char *s)
{
  size_t pl = strlen(pat), sl = strlen(s);
  if (pl && pat[pl - 1] == '*') return strncmp(pat, s, pl - 1) == 0;
  if (pl && pat[0] == '*') return sl >= pl - 1 && strcmp(s + sl - (pl - 1), pat + 1) == 0;
  return strcmp(pat, s) == 0;
}

static int list_match(const strlist *l, const char *s)
{
  size_t i;
  for (i = 0; i < l->n; i++)
    if (glob_match(l->v[i], s)) return 1;
  return 0;
}

static int load_allow(strlist *l, const char *path)
{
  FILE *f = fopen(path, "rb");
  char line[512] = { 0 };
  if (!f) { fprintf(stderr, "sd-isacheck: cannot open allow list %s\n", path); return 0; }
  while (fgets(line, sizeof(line), f)) {
    char *p = line, *e;
#pragma warning(suppress: 28199)   /* fgets wrote the buffer; the analyzer cannot see it */
    while (*p == ' ' || *p == '\t') p++;
    e = p + strcspn(p, "# \t\r\n");
    *e = 0;
    if (*p) strlist_add(l, p);
  }
  fclose(f);
  return 1;
}

/* ---------------------------------------------------------------- PE image */

typedef struct sym {
  DWORD rva, size;
  int sized;
  char name[160];
} sym;

typedef struct image {
  const char *path;
  unsigned char *data;
  size_t size;
  IMAGE_NT_HEADERS32 *nt;
  IMAGE_SECTION_HEADER *sec;
  unsigned nsec;
  unsigned char *relmap;      /* 1 at every RVA where a HIGHLOW base relocation starts */
  sym *syms;
  size_t nsyms, capsyms;
  DWORD isa_available_va;     /* VA of the CRT's __isa_available (0 if absent) */
} image;

static const unsigned char *rva_ptr(const image *im, DWORD rva, size_t *avail)
{
  unsigned i;
  for (i = 0; i < im->nsec; i++) {
    const IMAGE_SECTION_HEADER *s = &im->sec[i];
    if (rva >= s->VirtualAddress && rva < s->VirtualAddress + s->SizeOfRawData) {
      size_t off = (size_t)s->PointerToRawData + (rva - s->VirtualAddress);
      if (off >= im->size) return NULL;
      *avail = SD_MIN_SIZE(im->size - off, (size_t)(s->VirtualAddress + s->SizeOfRawData - rva));
      return im->data + off;
    }
  }
  return NULL;
}

static int image_load(image *im, const char *path)
{
  IMAGE_DOS_HEADER *dos;
  memset(im, 0, sizeof(*im));
  im->path = path;
  im->data = read_file(path, &im->size);
  if (!im->data) { fprintf(stderr, "sd-isacheck: cannot read %s\n", path); return 0; }
  dos = (IMAGE_DOS_HEADER *)im->data;
  if (im->size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
      (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > im->size) {
    fprintf(stderr, "sd-isacheck: %s is not a PE image\n", path);
    return 0;
  }
  im->nt = (IMAGE_NT_HEADERS32 *)(im->data + dos->e_lfanew);
  if (im->nt->Signature != IMAGE_NT_SIGNATURE || im->nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      im->nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    fprintf(stderr, "sd-isacheck: %s is not a 32-bit x86 PE image\n", path);
    return 0;
  }
  im->sec = (IMAGE_SECTION_HEADER *)((unsigned char *)&im->nt->OptionalHeader + im->nt->FileHeader.SizeOfOptionalHeader);
  im->nsec = im->nt->FileHeader.NumberOfSections;
  if ((size_t)((unsigned char *)(im->sec + im->nsec) - im->data) > im->size) {
    fprintf(stderr, "sd-isacheck: %s: truncated section table\n", path);
    return 0;
  }
  return 1;
}

static void load_relocs(image *im)
{
  IMAGE_DATA_DIRECTORY *d = &im->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  DWORD img = im->nt->OptionalHeader.SizeOfImage, off = 0;
  im->relmap = (unsigned char *)calloc(img + 4, 1);
  if (!im->relmap) exit(2);
  if (im->nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC || !d->VirtualAddress) return;
  while (off + sizeof(IMAGE_BASE_RELOCATION) <= d->Size) {
    size_t avail = 0;
    const IMAGE_BASE_RELOCATION *b = (const IMAGE_BASE_RELOCATION *)rva_ptr(im, d->VirtualAddress + off, &avail);
    DWORD k, cnt;
    if (!b || avail < sizeof(*b) || b->SizeOfBlock < sizeof(*b) || b->SizeOfBlock > avail) break;
    cnt = (b->SizeOfBlock - (DWORD)sizeof(*b)) / 2;
    for (k = 0; k < cnt; k++) {
      WORD e = ((const WORD *)(b + 1))[k];
      DWORD rva = b->VirtualAddress + (e & 0x0FFF);
      if ((e >> 12) == IMAGE_REL_BASED_HIGHLOW && rva < img) im->relmap[rva] = 1;
    }
    off += b->SizeOfBlock;
  }
}

typedef struct enum_ctx { image *im; DWORD64 base; } enum_ctx;

static BOOL CALLBACK on_symbol(PSYMBOL_INFOW si, ULONG size, PVOID user)
{
  enum_ctx *c = (enum_ctx *)user;
  image *im = c->im;
  sym *s;
  (void)size;
  if (si->Tag != SD_SYMTAG_FUNCTION && si->Tag != SD_SYMTAG_PUBLIC) return TRUE;
  if (si->Address < c->base || si->Address - c->base >= im->nt->OptionalHeader.SizeOfImage) return TRUE;
  if (im->nsyms == im->capsyms) {
    sym *ns;
    im->capsyms = im->capsyms ? im->capsyms * 2 : 1024;
    ns = (sym *)realloc(im->syms, im->capsyms * sizeof(sym));
    if (!ns) exit(2);
    im->syms = ns;
  }
  s = &im->syms[im->nsyms++];
  s->rva = (DWORD)(si->Address - c->base);
  s->size = si->Tag == SD_SYMTAG_FUNCTION ? si->Size : 0;
  s->sized = s->size != 0;
  WideCharToMultiByte(CP_UTF8, 0, si->Name, (int)si->NameLen, s->name, (int)sizeof(s->name) - 1, NULL, NULL);
  s->name[sizeof(s->name) - 1] = 0;
  if (si->NameLen < sizeof(s->name)) s->name[si->NameLen] = 0;
  return TRUE;
}

static int sym_cmp(const void *a, const void *b)
{
  const sym *x = (const sym *)a, *y = (const sym *)b;
  if (x->rva != y->rva) return x->rva < y->rva ? -1 : 1;
  return y->sized - x->sized;          /* sized (private) entry first */
}

static BOOL CALLBACK on_dbghelp(HANDLE hp, ULONG action, ULONG64 data, ULONG64 user)
{
  (void)hp; (void)user;
  if (action == CBA_DEBUG_INFO) fwprintf(stderr, L"dbghelp: %ls", (const wchar_t *)(ULONG_PTR)data);
  return FALSE;
}

static int load_symbols(image *im)
{
  static ULONG_PTR s_handle = 0x5D150000;
  HANDLE hp = (HANDLE)(s_handle++);
  wchar_t wpath[MAX_PATH], wdir[MAX_PATH], *slash;
  DWORD64 base = im->nt->OptionalHeader.ImageBase, got;
  IMAGEHLP_MODULEW64 mi;
  enum_ctx ctx;
  size_t i, j;
  if (!MultiByteToWideChar(CP_UTF8, 0, im->path, -1, wpath, MAX_PATH) ||
      !GetFullPathNameW(wpath, MAX_PATH, wdir, NULL)) return 0;
  wcscpy(wpath, wdir);
  slash = wcsrchr(wdir, L'\\');
  if (slash) *slash = 0;
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_EXACT_SYMBOLS);
  if (getenv("SD_ISACHECK_DEBUG")) SymSetOptions(SymGetOptions() | SYMOPT_DEBUG);
  if (!SymInitializeW(hp, wdir, FALSE)) { fprintf(stderr, "sd-isacheck: SymInitialize failed (%lu)\n", GetLastError()); return 0; }
  if (getenv("SD_ISACHECK_DEBUG")) SymRegisterCallbackW64(hp, on_dbghelp, 0);
  got = SymLoadModuleExW(hp, NULL, wpath, NULL, base, im->nt->OptionalHeader.SizeOfImage, NULL, 0);
  memset(&mi, 0, sizeof(mi));
  mi.SizeOfStruct = sizeof(mi);
  if (!got || !SymGetModuleInfoW64(hp, got, &mi) || mi.SymType != SymPdb) {
    fprintf(stderr, "sd-isacheck: %s: no matching PDB next to the image (function boundaries need it; "
            "error %lu, symbol type %d)\n", im->path, got ? 0ul : GetLastError(), (int)mi.SymType);
    SymCleanup(hp);
    return 0;
  }
  ctx.im = im;
  ctx.base = got;
  SymEnumSymbolsW(hp, got, L"*", on_symbol, &ctx);
  if (!im->isa_available_va) {
    union { SYMBOL_INFOW si; unsigned char raw[sizeof(SYMBOL_INFOW) + 64 * sizeof(wchar_t)]; } u;
    memset(&u, 0, sizeof(u));
    u.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
    u.si.MaxNameLen = 64;
    if (SymFromNameW(hp, L"__isa_available", &u.si) && u.si.Address > got)
      im->isa_available_va = (DWORD)u.si.Address;
  }
  SymCleanup(hp);
  if (im->nsyms == 0) { fprintf(stderr, "sd-isacheck: %s: the PDB has no function symbols\n", im->path); return 0; }
  qsort(im->syms, im->nsyms, sizeof(sym), sym_cmp);
  for (i = 0, j = 0; i < im->nsyms; i++)          /* one entry per address, the sized one wins */
    if (j == 0 || im->syms[j - 1].rva != im->syms[i].rva) im->syms[j++] = im->syms[i];
  im->nsyms = j;
  return 1;
}

static const sym *sym_at(const image *im, DWORD rva)
{
  size_t lo = 0, hi = im->nsyms;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (im->syms[mid].rva <= rva) lo = mid + 1; else hi = mid;
  }
  return lo ? &im->syms[lo - 1] : NULL;
}

static int isa_violates(x86_isa isa, int floor_sse2)
{
  if (isa == X86_ISA_BASE) return 0;
  if (!floor_sse2) return 1;
  return isa == X86_ISA_SSE3PLUS || isa == X86_ISA_AVX || isa == X86_ISA_AVX512 || isa == X86_ISA_3DNOW;
}

typedef struct sweep_stats { unsigned long insns, undecodable, allowed_hits, hits; } sweep_stats;

static void print_bytes(const unsigned char *p, unsigned n)
{
  unsigned k;
  for (k = 0; k < n && k < 12; k++) fprintf(stderr, "%s%02X", k ? " " : "", p[k]);
}

/* Sweeps [start, end) of symbol s. Returns the number of reported (non-allowed) hits. */
static unsigned long sweep(const image *im, const sym *s, DWORD start, DWORD end, int floor_sse2,
                           const strlist *allow, int ignore_allow, sweep_stats *st)
{
  DWORD pos = start;
  unsigned long bad = 0;
  int allowed = !ignore_allow && s && list_match(allow, s->name);
  /* sse2 floor: MSVC's auto-vectorizer emits SSE4.x loops behind "cmp __isa_available, 2; jl scalar".
     A function that reads __isa_available (an absolute, relocated reference) dispatches at run time, so its
     newer instructions are reported as allowed. Never on the ia32 floor (no detection there, 01 §2.3). */
  if (!allowed && !ignore_allow && floor_sse2 && im->isa_available_va) {
    DWORD r;
    for (r = start; r + 4 <= end && !allowed; r++) {
      size_t av = 0;
      const unsigned char *q;
      DWORD v;
      if (!im->relmap[r]) continue;
      q = rva_ptr(im, r, &av);
      if (!q || av < 4) continue;
      memcpy(&v, q, 4);
      if (v == im->isa_available_va) allowed = 1;
    }
  }
  while (pos < end) {
    size_t avail = 0;
    const unsigned char *p;
    x86_insn in;
    if (im->relmap[pos]) {                    /* absolute address at an instruction boundary: data */
      if (s && s->sized) break;
      pos += 4;
      continue;
    }
    p = rva_ptr(im, pos, &avail);
    if (!p) break;
    if (avail > end - pos) avail = end - pos;
    x86_decode(p, avail, &in);
    if (in.len == 0) { st->undecodable++; pos++; continue; }
    st->insns++;
    if (isa_violates(in.isa, floor_sse2)) {
      if (allowed) {
        st->allowed_hits++;
        if (g_list) {
          fprintf(stderr, "sd-isacheck: %s: allowed %s at %s+0x%lX (rva 0x%08lX): ", im->path, x86_isa_name(in.isa),
                  s->name, (unsigned long)(pos - s->rva), (unsigned long)pos);
          print_bytes(p, in.len);
          fputc('\n', stderr);
        }
      } else {
        st->hits++;
        bad++;
        g_violations++;
        fprintf(stderr, "sd-isacheck: %s: %s instruction in %s+0x%lX (rva 0x%08lX): ", im->path, x86_isa_name(in.isa),
                s ? s->name : "<no symbol>", s ? (unsigned long)(pos - s->rva) : 0ul, (unsigned long)pos);
        print_bytes(p, in.len);
        fputc('\n', stderr);
      }
    }
    pos += in.len;
  }
  return bad;
}

static int check_image(const char *path, int floor_sse2, const strlist *allow, const char *entry)
{
  image im;
  sweep_stats st;
  unsigned i;
  unsigned long gap_bytes = 0;
  memset(&st, 0, sizeof(st));
  if (!image_load(&im, path)) return 0;
  load_relocs(&im);
  if (!load_symbols(&im)) return 0;
  {
    size_t k;
    for (k = 0; k < im.nsyms; k++)
      if (!im.isa_available_va && strcmp(im.syms[k].name, "__isa_available") == 0)
        im.isa_available_va = (DWORD)(im.nt->OptionalHeader.ImageBase + im.syms[k].rva);
  }
  if (getenv("SD_ISACHECK_DEBUG")) {
    size_t k;
    fprintf(stderr, "sd-isacheck: __isa_available at 0x%08lX\n", (unsigned long)im.isa_available_va);
    for (k = 0; k < im.nsyms; k++)
      if (strstr(im.syms[k].name, "isa_avail")) fprintf(stderr, "  sym %s rva 0x%lX\n", im.syms[k].name, (unsigned long)im.syms[k].rva);
  }
  for (i = 0; i < im.nsec; i++) {
    const IMAGE_SECTION_HEADER *sc = &im.sec[i];
    DWORD sbeg = sc->VirtualAddress, send = sc->VirtualAddress + SD_MIN_DWORD(sc->Misc.VirtualSize, sc->SizeOfRawData);
    DWORD covered = sbeg;
    size_t k;
    if (!(sc->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))) continue;
    for (k = 0; k < im.nsyms; k++) {
      const sym *s = &im.syms[k];
      DWORD next = k + 1 < im.nsyms ? im.syms[k + 1].rva : send, end;
      if (s->rva < sbeg || s->rva >= send) continue;
      if (next > send) next = send;
      end = s->sized ? SD_MIN_DWORD(s->rva + s->size, send) : next;
      if (s->rva > covered) gap_bytes += s->rva - covered;
      sweep(&im, s, s->rva, end, floor_sse2, allow, 0, &st);
      if (end > covered) covered = end;
    }
    if (send > covered) gap_bytes += send - covered;
  }
  if (entry) {
    DWORD ep = im.nt->OptionalHeader.AddressOfEntryPoint;
    const sym *s = sym_at(&im, ep);
    if (!s || s->rva != ep || strcmp(s->name, entry) != 0) {
      g_violations++;
      fprintf(stderr, "sd-isacheck: %s: entry point is %s, expected %s\n", path, s && s->rva == ep ? s->name : "<unknown>", entry);
    } else {
      DWORD end = s->sized ? s->rva + s->size : (s + 1 < im.syms + im.nsyms ? s[1].rva : ep + 1);
      sweep_stats est;
      memset(&est, 0, sizeof(est));
      if (sweep(&im, s, s->rva, end, 0, allow, 1, &est))
        fprintf(stderr, "sd-isacheck: %s: the entry thunk %s must be IA32-clean (compile it /arch:IA32)\n", path, entry);
    }
  }
  if (g_list || st.undecodable)
    printf("sd-isacheck: %s: %lu instructions, %lu undecodable bytes, %lu allow-listed hits, %lu violations, "
           "%lu bytes outside symbols\n", path, st.insns, st.undecodable, st.allowed_hits, st.hits, gap_bytes);
  free(im.data);
  free(im.relmap);
  free(im.syms);
  return 1;
}

/* ---------------------------------------------------------------- constant-time gate */

static const char *const k_helpers[] = {
  "_allmul", "_aullmul", "_alldiv", "_aulldiv", "_allrem", "_aullrem", "_alldvrm", "_aulldvrm",
  "_allshl", "_allshr", "_aullshr",
  "_ftol", "_ftol2", "_ftol2_sse", "_ftoul3", "_dtol3", "_dtoui3", "_dtoul3", "_ltod3", "_ultod3",
  NULL
};

/* Undecorated C name of an x86 COFF symbol: drops the leading '_' (cdecl/stdcall) and "@n". */
static void undecorate(const char *in, char *out, size_t cap)
{
  const char *at;
  size_t n;
  if (*in == '_' || *in == '@') in++;
  at = strchr(in, '@');
  n = at ? (size_t)(at - in) : strlen(in);
  if (n >= cap) n = cap - 1;
  memcpy(out, in, n);
  out[n] = 0;
}

static const char *coff_sym_name(const unsigned char *obj, size_t size, const IMAGE_SYMBOL *s, DWORD strtab_off, char *buf)
{
  if (s->N.Name.Short) {
    memcpy(buf, s->N.ShortName, 8);
    buf[8] = 0;
    return buf;
  }
  if ((size_t)strtab_off + s->N.Name.Long >= size) return "?";
  {
    const char *p = (const char *)obj + strtab_off + s->N.Name.Long;
    if (!memchr(p, 0, size - (strtab_off + s->N.Name.Long))) return "?";
    return p;
  }
}

static void check_object(const char *lib, const char *member, const unsigned char *obj, size_t size)
{
  const IMAGE_FILE_HEADER *fh = (const IMAGE_FILE_HEADER *)obj;
  const IMAGE_SECTION_HEADER *sec;
  const IMAGE_SYMBOL *syms;
  DWORD strtab, nsym, si;
  int s;
  if (size < sizeof(*fh) || fh->Machine != IMAGE_FILE_MACHINE_I386) {
    fprintf(stderr, "sd-isacheck: %s(%s): not an x86 COFF object (/GL objects are not supported)\n", lib, member);
    g_violations++;
    return;
  }
  sec = (const IMAGE_SECTION_HEADER *)(obj + sizeof(*fh) + fh->SizeOfOptionalHeader);
  syms = (const IMAGE_SYMBOL *)(obj + fh->PointerToSymbolTable);
  nsym = fh->NumberOfSymbols;
  strtab = fh->PointerToSymbolTable + nsym * IMAGE_SIZEOF_SYMBOL;
  if ((size_t)((const unsigned char *)(sec + fh->NumberOfSections) - obj) > size || strtab > size) {
    fprintf(stderr, "sd-isacheck: %s(%s): truncated object\n", lib, member);
    g_violations++;
    return;
  }
  for (s = 0; s < fh->NumberOfSections; s++) {
    const IMAGE_SECTION_HEADER *sc = &sec[s];
    const IMAGE_RELOCATION *r;
    char fname[256] = "<section>", buf[9];
    WORD k;
    if (!(sc->Characteristics & IMAGE_SCN_CNT_CODE) || !sc->NumberOfRelocations) continue;
    /* The function this COMDAT section holds: a function-typed symbol defined in it. */
    for (si = 0; si < nsym; si += 1 + syms[si].NumberOfAuxSymbols) {
      const IMAGE_SYMBOL *y = &syms[si];
      if (y->SectionNumber == s + 1 && ISFCN(y->Type)) {
        undecorate(coff_sym_name(obj, size, y, strtab, buf), fname, sizeof(fname));
        break;
      }
    }
    r = (const IMAGE_RELOCATION *)(obj + sc->PointerToRelocations);
    if ((size_t)sc->PointerToRelocations + (size_t)sc->NumberOfRelocations * sizeof(IMAGE_RELOCATION) > size) continue;
    for (k = 0; k < sc->NumberOfRelocations; k++) {
      const IMAGE_SYMBOL *t;
      char tname[256];
      int h;
      if (r[k].SymbolTableIndex >= nsym) continue;
      t = &syms[r[k].SymbolTableIndex];
      if (t->StorageClass != IMAGE_SYM_CLASS_EXTERNAL || t->SectionNumber != IMAGE_SYM_UNDEFINED) continue;
      undecorate(coff_sym_name(obj, size, t, strtab, buf), tname, sizeof(tname));
      for (h = 0; k_helpers[h]; h++)
        if (strcmp(tname, k_helpers[h]) == 0) break;
      if (k_helpers[h]) {
        g_violations++;
        fprintf(stderr, "sd-isacheck: ct: %s(%s): %s references compiler runtime helper %s "
                "(constant-time code must use sd_ct64.h, TM-R02)\n", lib, member, fname, tname);
      } else if (g_list) {
        printf("sd-isacheck: ct: %s: %s -> %s\n", member, fname, tname);
      }
    }
  }
}

/* Archive (.lib) walk: "!<arch>\n", 60-byte member headers, "/" linker members, "//" long names. */
static int check_lib(const char *lib, const strlist *members)
{
  size_t size = 0, off = 8, i;
  unsigned char *d = read_file(lib, &size);
  const char *longnames = NULL;
  size_t longsize = 0;
  int *seen;
  if (!d) { fprintf(stderr, "sd-isacheck: cannot read %s\n", lib); return 0; }
  if (size < 8 || memcmp(d, "!<arch>\n", 8) != 0) { fprintf(stderr, "sd-isacheck: %s is not a library\n", lib); free(d); return 0; }
  seen = (int *)calloc(members->n + 1, sizeof(int));
  if (!seen) exit(2);
  while (off + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) <= size) {
    const IMAGE_ARCHIVE_MEMBER_HEADER *h = (const IMAGE_ARCHIVE_MEMBER_HEADER *)(d + off);
    char field[17], name[MAX_PATH], *base;
    size_t msize, data = off + sizeof(*h);
    memcpy(field, h->Size, 10);
    field[10] = 0;
    msize = (size_t)strtoul(field, NULL, 10);
    if (data + msize > size) break;
    memcpy(field, h->Name, 16);
    field[16] = 0;
    if (field[0] == '/' && field[1] == '/') {
      longnames = (const char *)d + data;
      longsize = msize;
    } else if (field[0] == '/' && field[1] >= '0' && field[1] <= '9' && longnames) {
      size_t lo = (size_t)strtoul(field + 1, NULL, 10), n = 0;
      while (lo + n < longsize && longnames[lo + n] && n < sizeof(name) - 1) n++;
      memcpy(name, longnames + lo, n);
      name[n] = 0;
    } else if (field[0] != '/') {
      char *e = strchr(field, '/');
      if (e) *e = 0;
      strcpy(name, field);
    } else {
      name[0] = 0;                                  /* linker member */
    }
    if (!(field[0] == '/' && (field[1] == ' ' || field[1] == '/')) && name[0]) {
      base = strrchr(name, '\\');
      if (!base) base = strrchr(name, '/');
      base = base ? base + 1 : name;
      for (i = 0; i < members->n; i++) {
        if (_stricmp(base, members->v[i]) == 0) {
          seen[i] = 1;
          check_object(lib, base, d + data, msize);
        }
      }
    }
    off = data + msize + (msize & 1);
  }
  for (i = 0; i < members->n; i++) {
    if (!seen[i]) {
      g_violations++;
      fprintf(stderr, "sd-isacheck: ct: %s has no member %s (the constant-time source list is stale)\n", lib, members->v[i]);
    }
  }
  free(seen);
  free(d);
  return 1;
}

/* ---------------------------------------------------------------- self-test */

typedef struct vec { const char *hex; unsigned len; x86_isa isa; } vec;

static const vec k_vectors[] = {
  { "8B4508", 3, X86_ISA_BASE },                 /* mov eax,[ebp+8] */
  { "8D0485" "00104000", 7, X86_ISA_BASE },      /* lea eax,[eax*4+0x401000] */
  { "69C010000000", 6, X86_ISA_BASE },           /* imul eax,eax,16 */
  { "66B83412", 4, X86_ISA_BASE },               /* mov ax,0x1234 */
  { "F7C178563412", 6, X86_ISA_BASE },           /* test ecx,imm32 */
  { "F6C101", 3, X86_ISA_BASE },                 /* test cl,1 */
  { "C8100000", 4, X86_ISA_BASE },               /* enter 16,0 */
  { "A100104000", 5, X86_ISA_BASE },             /* mov eax,[moffs32] */
  { "DD0500104000", 6, X86_ISA_BASE },           /* fld qword [disp32] */
  { "E800000000", 5, X86_ISA_BASE },             /* call rel32 */
  { "0FA2", 2, X86_ISA_BASE },                   /* cpuid */
  { "0F44C1", 3, X86_ISA_BASE },                 /* cmove eax,ecx */
  { "0FC70E", 3, X86_ISA_BASE },                 /* cmpxchg8b [esi] */
  { "0F1F440000", 5, X86_ISA_BASE },             /* nop dword [eax+eax] */
  { "C406", 2, X86_ISA_BASE },                   /* les eax,[esi] (not VEX) */
  { "6206", 2, X86_ISA_BASE },                   /* bound eax,[esi] (not EVEX) */
  { "F3A5", 2, X86_ISA_BASE },                   /* rep movsd */
  { "0F7FC1", 3, X86_ISA_MMX },                  /* movq mm1,mm0 */
  { "0FEFC0", 3, X86_ISA_MMX },                  /* pxor mm0,mm0 */
  { "0F77", 2, X86_ISA_MMX },                    /* emms */
  { "0F1000", 3, X86_ISA_SSE },                  /* movups xmm0,[eax] */
  { "F30F10442404", 6, X86_ISA_SSE },            /* movss xmm0,[esp+4] */
  { "0F1808", 3, X86_ISA_SSE },                  /* prefetcht0 [eax] */
  { "0FAEF8", 3, X86_ISA_SSE },                  /* sfence */
  { "0FAE5DFC", 4, X86_ISA_SSE },                /* stmxcsr [ebp-4] */
  { "660FEFC0", 4, X86_ISA_SSE2 },               /* pxor xmm0,xmm0 */
  { "F20F100500104000", 8, X86_ISA_SSE2 },       /* movsd xmm0,[disp32] */
  { "660F6F01", 4, X86_ISA_SSE2 },               /* movdqa xmm0,[ecx] */
  { "F30F6F01", 4, X86_ISA_SSE2 },               /* movdqu xmm0,[ecx] */
  { "F30F7EC1", 4, X86_ISA_SSE2 },               /* movq xmm0,xmm1 */
  { "0FAEE8", 3, X86_ISA_SSE2 },                 /* lfence */
  { "0FC301", 3, X86_ISA_SSE2 },                 /* movnti [ecx],eax */
  { "0FD4C1", 3, X86_ISA_SSE2 },                 /* paddq mm0,mm1 */
  { "660F3800C1", 5, X86_ISA_SSE3PLUS },         /* pshufb xmm0,xmm1 */
  { "660F3A0FC108", 6, X86_ISA_SSE3PLUS },       /* palignr xmm0,xmm1,8 */
  { "F20F7CC1", 4, X86_ISA_SSE3PLUS },           /* haddps xmm0,xmm1 */
  { "F30FB8C1", 4, X86_ISA_SSE3PLUS },           /* popcnt eax,ecx */
  { "C5F9EFC0", 4, X86_ISA_AVX },                /* vpxor xmm0,xmm0,xmm0 */
  { "C4E27900C1", 5, X86_ISA_AVX },              /* vpshufb xmm0,xmm0,xmm1 */
  { "C5F877", 3, X86_ISA_AVX },                  /* vzeroupper */
  { "62F17D48EFC0", 6, X86_ISA_AVX512 },         /* vpxord zmm0,zmm0,zmm0 */
  { "0F0FC1B4", 4, X86_ISA_3DNOW },              /* pfmul mm0,mm1 */
  { "0FAE00", 3, X86_ISA_SYSEXT },               /* fxsave [eax] */
  { "0F01D0", 3, X86_ISA_SYSEXT },               /* xgetbv */
  { NULL, 0, X86_ISA_BASE }
};

static int selftest(void)
{
  int i, fails = 0, n = 0;
  for (i = 0; k_vectors[i].hex; i++) {
    unsigned char b[32];
    size_t k, len = 0;
    const char *h = k_vectors[i].hex;
    x86_insn in;
    for (k = 0; h[k] && h[k + 1] && len < sizeof(b) - 1; k += 2) {
      char t[3];
      t[0] = h[k];
      t[1] = h[k + 1];
      t[2] = 0;
      b[len++] = (unsigned char)strtoul(t, NULL, 16);
    }
    b[len] = 0x90;                     /* a following byte, so a too-long decode is visible */
    x86_decode(b, len + 1, &in);
    n++;
    if (in.len != k_vectors[i].len || in.isa != k_vectors[i].isa) {
      fails++;
      fprintf(stderr, "sd-isacheck: selftest: %s: got len %u isa %s, want len %u isa %s\n", h, in.len,
              x86_isa_name(in.isa), k_vectors[i].len, x86_isa_name(k_vectors[i].isa));
    }
  }
  printf("sd-isacheck: selftest: %d vectors, %d failures\n", n, fails);
  return fails ? 1 : 0;
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
  strlist allow = { 0 }, members = { 0 };
  const char *entry = NULL, *ct_lib = NULL, *config = NULL;
  int i, floor_sse2 = -1, nimages = 0;
  for (i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (strcmp(a, "--selftest") == 0) return selftest();
    if (strcmp(a, "--floor") == 0 && i + 1 < argc) {
      const char *f = argv[++i];
      if (strcmp(f, "ia32") == 0) floor_sse2 = 0;
      else if (strcmp(f, "sse2") == 0) floor_sse2 = 1;
      else { fprintf(stderr, "sd-isacheck: --floor must be ia32 or sse2\n"); return 2; }
    } else if (strcmp(a, "--allow") == 0 && i + 1 < argc) {
      if (!load_allow(&allow, argv[++i])) return 2;
    } else if (strcmp(a, "--entry") == 0 && i + 1 < argc) {
      entry = argv[++i];
    } else if (strcmp(a, "--ct-lib") == 0 && i + 1 < argc) {
      ct_lib = argv[++i];
    } else if (strcmp(a, "--ct-member") == 0 && i + 1 < argc) {
      strlist_add(&members, argv[++i]);
    } else if (strcmp(a, "--config") == 0 && i + 1 < argc) {
      config = argv[++i];
    } else if (strcmp(a, "--list") == 0) {
      g_list = 1;
    } else if (a[0] == '-') {
      fprintf(stderr, "sd-isacheck: unknown option %s\n", a);
      return 2;
    } else {
      if (floor_sse2 < 0) { fprintf(stderr, "sd-isacheck: --floor is required before the images\n"); return 2; }
      nimages++;
      if (!check_image(a, floor_sse2, &allow, entry)) return 2;
    }
  }
  if (ct_lib) {
    if (members.n == 0) { fprintf(stderr, "sd-isacheck: --ct-lib needs --ct-member\n"); return 2; }
    if (config && _stricmp(config, "Release") != 0) {
      printf("sd-isacheck: ct: skipped for %s (the gate applies to optimized Release objects)\n", config);
      return 0;
    }
    if (!check_lib(ct_lib, &members)) return 2;
  } else if (nimages == 0) {
    fprintf(stderr, "usage: sd-isacheck --floor ia32|sse2 [--allow list] [--entry sym] [--list] <image>...\n"
                    "       sd-isacheck --ct-lib <lib> --ct-member <obj>... [--list]\n"
                    "       sd-isacheck --selftest\n");
    return 2;
  }
  if (g_violations) {
    fprintf(stderr, "sd-isacheck: %d violation(s)\n", g_violations);
    return 1;
  }
  return 0;
}
