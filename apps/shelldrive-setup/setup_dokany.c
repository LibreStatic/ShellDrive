/* shelldrive-setup: Dokany chaining decisions (docs/design/04 §7.3; C31, D32). See setup_dokany.h. */
#include "setup_int.h"

#include <string.h>
#include <wchar.h>

#include "setup_dokany.h"

#define SD_PE_NAME_MAX 64
#define SD_PE_MAX_IMPORTS 4096
#define SD_PE_MAX_SECTIONS 96

static int rd16(const unsigned char *img, size_t n, size_t off, DWORD *v)
{
  if (off > n || n - off < 2)
    return 1;
  *v = (DWORD)img[off] | ((DWORD)img[off + 1] << 8);
  return 0;
}

static int rd32(const unsigned char *img, size_t n, size_t off, DWORD *v)
{
  if (off > n || n - off < 4)
    return 1;
  *v = (DWORD)img[off] | ((DWORD)img[off + 1] << 8) | ((DWORD)img[off + 2] << 16) | ((DWORD)img[off + 3] << 24);
  return 0;
}

/* Maps an RVA to a file offset through the section table. The byte at the RVA must lie in the raw data of its section
   (a zero-filled tail is not readable here), and need bytes must be inside the image. */
static int rva_to_off(const unsigned char *img, size_t n, size_t sec_off, DWORD nsec, DWORD rva, size_t need,
                      size_t *off)
{
  DWORD i;

  for (i = 0; i < nsec; i++) {
    size_t s = sec_off + (size_t)i * 40;
    DWORD vsz;
    DWORD va;
    DWORD rsz;
    DWORD raw;
    DWORD span;
    DWORD delta;
    size_t o;

    if (rd32(img, n, s + 8, &vsz) || rd32(img, n, s + 12, &va) || rd32(img, n, s + 16, &rsz) ||
        rd32(img, n, s + 20, &raw))
      return 1;
    span = vsz > rsz ? vsz : rsz;
    if (rva < va || rva - va >= span)
      continue;
    delta = rva - va;
    if (delta >= rsz)
      return 1;
    o = (size_t)raw + (size_t)delta;
    if (o > n || n - o < need)
      return 1;
    *off = o;
    return 0;
  }
  return 1;
}

/* 1 when the name at off (NUL-terminated, ASCII, inside the image) is a VC++ 2015-2022 runtime module. */
static int name_is_vcr(const unsigned char *img, size_t n, size_t off)
{
  char low[SD_PE_NAME_MAX];
  size_t k = 0;

  while (off + k < n && k < sizeof(low) - 1) {
    unsigned char c = img[off + k];
    if (c == 0)
      break;
    if (c >= 'A' && c <= 'Z')
      c = (unsigned char)(c + ('a' - 'A'));
    low[k] = (char)c;
    k++;
  }
  low[k] = '\0';
  return strncmp(low, "vcruntime140", 12) == 0 || strncmp(low, "msvcp140", 8) == 0;
}

int sd_setup_pe_vcr_state(const unsigned char *img, size_t n, sd_setup_vcr_state *state)
{
  DWORD e_lfanew = 0;
  DWORD nsec = 0;
  DWORD optsz = 0;
  DWORD magic = 0;
  DWORD imp_rva = 0;
  DWORD imp_size = 0;
  size_t pe_off;
  size_t opt_off;
  size_t dd_off;
  size_t sec_off;
  size_t desc = 0;
  int found = 0;
  int done = 0;
  DWORD i;

  if (state == NULL)
    return 1;
  *state = SD_SETUP_VCR_UNKNOWN;
  if (img == NULL || n < 0x40 || img[0] != 'M' || img[1] != 'Z')
    return 1;
  if (rd32(img, n, 0x3c, &e_lfanew) || e_lfanew < 0x40 || (size_t)e_lfanew > n)
    return 1;
  pe_off = (size_t)e_lfanew;
  if (n - pe_off < 24 || memcmp(img + pe_off, "PE\0\0", 4) != 0)
    return 1;
  if (rd16(img, n, pe_off + 6, &nsec) || rd16(img, n, pe_off + 20, &optsz))
    return 1;
  if (nsec > SD_PE_MAX_SECTIONS)
    return 1;
  opt_off = pe_off + 24;
  if (rd16(img, n, opt_off, &magic))
    return 1;
  if (magic == 0x10B)
    dd_off = opt_off + 96;       /* PE32: DataDirectory after 28 + 68 bytes */
  else if (magic == 0x20B)
    dd_off = opt_off + 112;      /* PE32+ */
  else
    return 1;
  /* Import directory is entry 1 of the data directories. */
  if ((size_t)optsz < (dd_off - opt_off) + 16)
    return 1;
  if (rd32(img, n, dd_off + 8, &imp_rva) || rd32(img, n, dd_off + 12, &imp_size))
    return 1;
  if (imp_rva == 0)
    imp_size = 0;
  if (imp_rva == 0 || imp_size == 0) {
    *state = SD_SETUP_VCR_NOT_NEEDED;
    return 0;
  }
  sec_off = opt_off + (size_t)optsz;
  if (rva_to_off(img, n, sec_off, nsec, imp_rva, 20, &desc))
    return 1;

  /* IMAGE_IMPORT_DESCRIPTOR array, ended by an all-zero record (its Name RVA is zero). */
  for (i = 0; i < SD_PE_MAX_IMPORTS && !done; i++) {
    size_t d = desc + (size_t)i * 20;
    DWORD name_rva;
    size_t no;

    if (d > n || n - d < 20)
      return 1;
    if (rd32(img, n, d + 12, &name_rva))
      return 1;
    if (name_rva == 0) {
      done = 1;
      break;
    }
    if (rva_to_off(img, n, sec_off, nsec, name_rva, 1, &no))
      return 1;
    if (name_is_vcr(img, n, no))
      found = 1;
  }
  if (!done)
    return 1;
  *state = found ? SD_SETUP_VCR_NEEDED : SD_SETUP_VCR_NOT_NEEDED;
  return 0;
}

sd_setup_dokany_chain sd_setup_dokany_choose(sd_setup_vcr_state vcr, int have_msi, int have_bundle)
{
  switch (vcr) {
  case SD_SETUP_VCR_NOT_NEEDED:
    return have_msi ? SD_SETUP_DOKANY_CHAIN_MSI : SD_SETUP_DOKANY_CHAIN_UNAVAILABLE;
  case SD_SETUP_VCR_NEEDED:
    return have_bundle ? SD_SETUP_DOKANY_CHAIN_BUNDLE : SD_SETUP_DOKANY_CHAIN_UNAVAILABLE;
  default:
    return SD_SETUP_DOKANY_CHAIN_UNAVAILABLE;
  }
}

int sd_setup_dokany_command(sd_setup_dokany_chain chain, const wchar_t *sysdir, const wchar_t *package,
                            const wchar_t *log, wchar_t *exe, size_t ecch, wchar_t *args, size_t acch)
{
  if (package == NULL || log == NULL || exe == NULL || args == NULL)
    return 1;
  if (wcschr(package, L'"') != NULL || wcschr(log, L'"') != NULL)
    return 1;
  if (chain == SD_SETUP_DOKANY_CHAIN_MSI) {
    if (sysdir == NULL || sd_setup_path_join(exe, ecch, sysdir, L"msiexec.exe") != 0)
      return 1;
    return FAILED(StringCchPrintfW(args, acch, L"/i \"%s\" /qn /norestart /l*v \"%s\"", package, log)) ? 1 : 0;
  }
  if (chain == SD_SETUP_DOKANY_CHAIN_BUNDLE) {
    if (FAILED(StringCchCopyW(exe, ecch, package)))
      return 1;
    return FAILED(StringCchPrintfW(args, acch, L"/install /quiet /norestart /log \"%s\"", log)) ? 1 : 0;
  }
  return 1;
}

DWORD sd_setup_dokany_run(sd_setup_dokany_chain chain, const sd_setup_payload *package,
                          const unsigned char expected_sha256[32], const wchar_t *sysdir, const wchar_t *package_path,
                          const wchar_t *log, sd_setup_dokany_run_fn run, void *ctx, DWORD *exit_code)
{
  unsigned char sha[32];
  wchar_t exe[MAX_PATH * 2];
  wchar_t args[MAX_PATH * 4];
  DWORD code = 0;
  DWORD err;

  if (exit_code != NULL)
    *exit_code = 0;
  if (chain != SD_SETUP_DOKANY_CHAIN_MSI && chain != SD_SETUP_DOKANY_CHAIN_BUNDLE)
    return ERROR_NOT_SUPPORTED;
  /* Without a runner nothing is started: the engine never installs Dokany on its own (C31 is a lab item). */
  if (run == NULL)
    return ERROR_CALL_NOT_IMPLEMENTED;
  if (package == NULL || package->data == NULL || expected_sha256 == NULL)
    return ERROR_INVALID_PARAMETER;
  /* The bytes are checked again here, immediately before they are run (TM-R23, T-65). */
  sd_setup_sha256(package->data, package->size, sha);
  if (memcmp(sha, expected_sha256, sizeof(sha)) != 0)
    return ERROR_INVALID_DATA;
  if (sd_setup_dokany_command(chain, sysdir, package_path, log, exe, SD_SETUP_COUNTOF(exe), args,
                              SD_SETUP_COUNTOF(args)) != 0)
    return ERROR_INVALID_PARAMETER;
  err = run(ctx, exe, args, &code);
  if (err != 0)
    return err;
  if (exit_code != NULL)
    *exit_code = code;
  if (code == 0 || code == 3010)
    return 0;
  return code;
}
