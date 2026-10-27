/* fuzz_state: snapshot reader of the shared-state section (sd_state_read_buffer, the reader used by the shell DLL,
   TST-24). A snapshot from a foreign or damaged writer must be rejected without touching memory outside the buffer;
   the reader only ever gets the bytes and their size. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "sd_state/sd_state.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_state_snapshot *snap = NULL;
  uint8_t *copy;

  if (size > 256u * 1024u) return 0;
  if (sd_state_snapshot_new(&snap) != SD_OK || !snap) return 0;
  /* A copy with exactly `size` bytes, so that any read past the end is seen by the sanitizer. */
  copy = (uint8_t *)malloc(size ? size : 1);
  if (copy) {
    if (size) memcpy(copy, data, size);
    (void)sd_state_read_buffer(copy, size, snap);
    free(copy);
  }
  sd_state_snapshot_free(snap);
  return 0;
}
