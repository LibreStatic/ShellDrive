/* The keyring compiled into the stub and its resource wrapper (docs/design/04 §6.1, §9.3; TM-R38). The pure
 * verifier lives in setup_payload_sig.c (library sd_payload_sig_text, shared with tools/sd-release, which must not
 * pull this file in: the keyring of the build depends on the tool that generates it). The single call site of
 * sd_setup_payload_sig_check is the stub (setup_main.c, run_install).
 *
 * The repository file setup_keyring.inc holds only a revoked placeholder, so no payload verifies until the release
 * build generates it: cmake/SdKeyring.cmake runs `sd-release keyring` and puts the generated directory FIRST on the
 * include path of this target, so the angle include below picks the generated file (a quoted include would always
 * find the placeholder beside the sources, whichever -I comes first). */
#include <windows.h>

#include "setup_payload_sig.h"

static const sd_setup_psig_key k_builtin_keys[] = {
#include <setup_keyring.inc>
};

sd_setup_psig_res sd_setup_payload_sig_check(HINSTANCE inst, const uint8_t *table, size_t tlen)
{
  HRSRC hr;
  HGLOBAL hg;
  const uint8_t *p;
  DWORD n;

  hr = FindResourceW(inst, L"PAYLOAD_SIG", RT_RCDATA);
  hg = hr != NULL ? LoadResource(inst, hr) : NULL;
  if (hg == NULL || table == NULL)
    return SD_SETUP_PSIG_E_RESOURCE;
  p = (const uint8_t *)LockResource(hg);
  n = SizeofResource(inst, hr);
  if (p == NULL || n == 0)
    return SD_SETUP_PSIG_E_RESOURCE;
  return sd_setup_psig_verify(table, tlen, p, n, k_builtin_keys,
                              sizeof(k_builtin_keys) / sizeof(k_builtin_keys[0]),
                              SD_SETUP_BUILD_CHANNEL, sd_setup_psig_now());
}
