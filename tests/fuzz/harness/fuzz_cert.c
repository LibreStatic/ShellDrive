/* fuzz_cert: OpenSSH certificate blobs (sd_ssh_cert_parse, validity window, plain-key extraction) and the
   certificate form of public key lines (sd_ssh_pubkey_parse). Each input is tried as a raw blob and as a text line. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_keyfile.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_ssh_cert_info ci;
  uint8_t blob[8192];
  size_t blen = 0;
  char type[128];
  sd_err e;

  if (size > 64u * 1024u) return 0;
  memset(&ci, 0, sizeof(ci));
  e = sd_ssh_cert_parse(data, size, &ci);
  if (e == SD_OK) {
    (void)sd_ssh_cert_valid_at(&ci, 0);
    (void)sd_ssh_cert_valid_at(&ci, 0xffffffffffffffffull);
  }
  e = sd_ssh_pubkey_parse(data, size, blob, sizeof(blob), &blen, type, sizeof(type));
  if (e == SD_OK) SD_FUZZ_CHECK(blen <= sizeof(blob));
  return 0;
}
