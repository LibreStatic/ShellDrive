/* fuzz_keyfile: private and public key files of every supported format (OpenSSH, PEM/PKCS#1/SEC1/PKCS#8,
   PPK v2/v3, and the probe that classifies them). The passphrase is fixed, so encrypted files reach the KDF and
   the cipher paths. The probe runs first because it does no KDF work. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_keyfile.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  static const char pass[] = "fuzz-passphrase";
  sd_ssh_key_probe_info info;
  sd_ssh_key *k = NULL;
  sd_err e;

  if (size > 64u * 1024u) return 0;
  (void)sd_ssh_key_probe(data, size, &info);
  e = sd_ssh_key_load(data, size, pass, sizeof(pass) - 1, &k);
  if (e == SD_OK && k) {
    size_t blen = 0;
    const uint8_t *blob = sd_ssh_key_public_blob(k, &blen);
    SD_FUZZ_CHECK(blob != NULL && blen > 0);
    (void)sd_ssh_key_type(k);
    (void)sd_ssh_key_bits(k);
    (void)sd_ssh_key_comment(k);
  }
  if (k) sd_ssh_key_free(k);
  return 0;
}
