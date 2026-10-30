/* In-memory ring of the agent's most recent log records (03 §10.1, M3 `log.tail`, decision 12).
 *
 * Fed by an sd_log sink, so every record is already formatted and redacted by sd_platform logging.
 * The ring keeps LOG_RING_RECORDS records (about 4.5 MiB worst case); sequence numbers start at 1 and
 * are never reused within one agent process. Records are copied, never referenced, so readers never
 * see a torn record. */
#ifndef SD_HOST_LOG_RING_H
#define SD_HOST_LOG_RING_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_log.h"

#define LOG_RING_RECORDS 4096
#define LOG_RING_TEXT    1024

typedef struct log_ring_rec {
  uint64_t seq;
  int      level;                 /* sd_log_level: 0 error .. 4 trace */
  char     time[32];              /* ISO 8601 UTC, as printed in the log line */
  char     component[32];
  char     mount_id[16];          /* "" when the record is not about a mount */
  char     text[LOG_RING_TEXT];   /* English message, truncated */
} log_ring_rec;

/* Allocates the ring and installs the sink. Call once, before the first log record that must be kept. */
sd_err log_ring_start(void);
void   log_ring_stop(void);

/* Visits records with seq >= from in ascending order, under the ring lock; fn returns 0 to stop.
   *oldest and *newest report the retained range (0 and 0 when the ring is empty). fn must not log. */
typedef int (*log_ring_fn)(void *ctx, const log_ring_rec *r);
void log_ring_scan(uint64_t from, uint64_t *oldest, uint64_t *newest, log_ring_fn fn, void *ctx);

#endif /* SD_HOST_LOG_RING_H */
