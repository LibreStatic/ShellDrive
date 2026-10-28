/* fuzz_inflate: zlib@openssh.com decoder (01 section 12.2, 01 section 4.7). Whole streams go through the one-shot
   RFC 1950 path, and the same bytes go through the packet decoder cut into pieces of 1 to 61 bytes, the way
   packets arrive over SSH. Errors are expected; crashes, out-of-bounds writes and output beyond the
   per-packet limit are not. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "ssh_zlib.h"

static uint8_t g_out[SSH_ZLIB_PACKET_MAX];

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  size_t outn = 0, off = 0, step;
  ssh_zinf *z;
  if (size > 1024u * 1024u) return 0;
  (void)ssh_zlib_oneshot(data, size, g_out, sizeof(g_out), &outn);
  SD_FUZZ_CHECK(outn <= sizeof(g_out));

  z = ssh_zinf_new();
  if (!z) return 0;
  step = size ? (size_t)(data[0] % 61u) + 1u : 1u;
  while (off < size) {
    size_t n = size - off < step ? size - off : step, o = 0;
    sd_err e = ssh_zinf_packet(z, data + off, n, g_out, sizeof(g_out), &o);
    SD_FUZZ_CHECK(o <= sizeof(g_out));
    if (e != SD_OK) break;
    off += n;
    step = (step * 7u) % 61u + 1u;
  }
  ssh_zinf_free(z);
  return 0;
}
