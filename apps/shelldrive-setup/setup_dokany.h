/* shelldrive-setup: Dokany chaining (docs/design/04 §7.3; C31, D32).

   Decides how the Dokany driver package is chained after ShellDrive's own install: the upstream MSI when dokan2.dll
   needs no VC++ runtime, the unmodified upstream DokanSetup.exe bundle when it does. The decision and the command lines
   are pure. The only process start goes through a runner the caller injects; this build injects none, so the engine
   can never install Dokany by itself (sd_setup_dokany_run refuses). */
#ifndef SD_SETUP_DOKANY_H
#define SD_SETUP_DOKANY_H

#include <windows.h>
#include <stddef.h>

#include "setup_core.h"

/* VC++ dependency of dokan2.dll (C31): unknown when the image cannot be parsed (fails closed). */
typedef enum sd_setup_vcr_state {
  SD_SETUP_VCR_UNKNOWN = -1,
  SD_SETUP_VCR_NOT_NEEDED = 0,
  SD_SETUP_VCR_NEEDED = 1
} sd_setup_vcr_state;

/* Parses the PE image in img (a copy of dokan2.dll, read as bytes, never loaded) and reports whether its import table
   names a VC++ 2015-2022 runtime module (vcruntime140*.dll or msvcp140*.dll, any case). Returns 0 and *state, or 1
   for a malformed image (*state is then SD_SETUP_VCR_UNKNOWN). Only the import directory is read; every offset and
   length is checked against n. */
int sd_setup_pe_vcr_state(const unsigned char *img, size_t n, sd_setup_vcr_state *state);

typedef enum sd_setup_dokany_chain {
  SD_SETUP_DOKANY_CHAIN_NONE = 0,       /* nothing to chain: the choice was "skip" or the driver is already there */
  SD_SETUP_DOKANY_CHAIN_MSI,            /* msiexec /i Dokan_<arch>.msi (no VC++ runtime needed) */
  SD_SETUP_DOKANY_CHAIN_BUNDLE,         /* DokanSetup.exe bundle, unmodified (VC++ runtime needed) */
  SD_SETUP_DOKANY_CHAIN_UNAVAILABLE     /* no suitable package, or the dependency is unknown: WebDAV only */
} sd_setup_dokany_chain;

/* have_msi and have_bundle say which packages are present in the payload; vcr is the VC++ state of dokan2.dll. */
sd_setup_dokany_chain sd_setup_dokany_choose(sd_setup_vcr_state vcr, int have_msi, int have_bundle);

/* Command line of a chain step. sysdir is the System32 folder (msiexec is taken from it, never from PATH); package is the
   file of the chosen package; log is the install log. Returns 0, or 1 when the chain is NONE or UNAVAILABLE or a buffer
   is too small. The MSI form is `msiexec /i "<package>" /qn /norestart /l*v "<log>"`; the bundle form is
   `DokanSetup.exe /install /quiet /norestart /log "<log>"` (its switches are [lab-verify], 04 §7.3). */
int sd_setup_dokany_command(sd_setup_dokany_chain chain, const wchar_t *sysdir, const wchar_t *package,
                            const wchar_t *log, wchar_t *exe, size_t ecch, wchar_t *args, size_t acch);

/* The process starter. It receives the program and its arguments and returns the Win32 error of the start, and the exit
   code of the program in *exit_code. */
typedef DWORD (*sd_setup_dokany_run_fn)(void *ctx, const wchar_t *exe, const wchar_t *args, DWORD *exit_code);

/* Runs one chain step when the package bytes match expected_sha256 (checked again here, at install time, TM-R23).
   run is required: with NULL the call returns ERROR_CALL_NOT_IMPLEMENTED and starts nothing. Returns 0 when the program
   exited with 0 or 3010 (reboot needed), otherwise a Win32 error. */
DWORD sd_setup_dokany_run(sd_setup_dokany_chain chain, const sd_setup_payload *package,
                          const unsigned char expected_sha256[32], const wchar_t *sysdir, const wchar_t *package_path,
                          const wchar_t *log, sd_setup_dokany_run_fn run, void *ctx, DWORD *exit_code);

#endif /* SD_SETUP_DOKANY_H */
