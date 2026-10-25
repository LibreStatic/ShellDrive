/* Secret buffers for passwords, passphrases, private keys and session keys (01 §12.1, 03 §4.6).
 *
 * Zeroized on free; never logged (sd_log has no specifier for them). Buffers of a page or more are
 * VirtualAlloc'ed and VirtualLock'ed (best effort: lock failure is ignored); smaller ones come from
 * the process heap. One owner at a time; no internal locking. */
#ifndef SD_SECBUF_H
#define SD_SECBUF_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

typedef struct sd_secbuf {
  uint8_t *p;
  size_t   len;     /* bytes in use, set by the owner (<= cap) */
  size_t   cap;
  uint32_t flags;   /* internal */
} sd_secbuf;

sd_err sd_secbuf_new(size_t cap, sd_secbuf **out);          /* zero-filled, len = 0 */
sd_err sd_secbuf_from(const void *data, size_t n, sd_secbuf **out);
void   sd_secbuf_free(sd_secbuf *b);                          /* NULL is a no-op */

#endif /* SD_SECBUF_H */
