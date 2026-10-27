/* fuzz_known_hosts: known_hosts lines (plain, hashed, wildcard, @revoked/@cert-authority markers, comments) through
   the in-memory lookup and the stored-types query (TM-R04). The file bytes are the input; the lookup name and the
   host key blob are fixed, so the parser and matcher see every line. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "ssh_internal.h"

/* ssh-ed25519 public key blob: string "ssh-ed25519", string(32 bytes). The key is a fixed test value. */
static const uint8_t k_blob[4 + 11 + 4 + 32] = {
  0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9',
  0, 0, 0, 32,
  0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d, 0x73,
  0x65, 0x32, 0x15, 0x77, 0x1e, 0x2a, 0x3f, 0x23, 0x88, 0x6a, 0x7d, 0x34, 0x9e, 0x3a, 0xd6, 0x1c
};

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  static const char name[] = "example.com";
  sd_hk_result res;
  int found_other = 0;
  sd_kh_types types;
  sd_err e;

  if (size > 64u * 1024u) return 0;
  memset(&res, 0, sizeof(res));
  e = ssh_kh_check_buffer((const char *)data, size, name, k_blob, sizeof(k_blob), &res, &found_other);
  (void)e;
  memset(&types, 0, sizeof(types));
  e = ssh_kh_types_buffer((const char *)data, size, name, &types);
  if (e == SD_OK) SD_FUZZ_CHECK(types.count <= 8);
  return 0;
}
