/* State snapshot producer of the agent (03 §8.2.1, M3): publishes the mounts into
 * Local\com.librestatic.shelldrive.state.<SID> through sd_state. The writer is single: every call is made
 * under the agent lock (g.lock), which also keeps the entry buffer below single-threaded. */
#ifndef SD_HOST_STATE_PRODUCER_H
#define SD_HOST_STATE_PRODUCER_H

#include <windows.h>
#include <stdint.h>

#include "sd_base/sd_err.h"

/* One mount as the producer needs it. Strings are valid for the call (they point into the agent record). */
typedef struct host_state_src {
  uint32_t mount_num;
  const char *mount_id;        /* "m-N" */
  const char *profile_id;      /* 32 lowercase hex digits, "" for ad hoc mounts */
  const char *profile_name;    /* UTF-8 */
  const char *remote_url;      /* sftp://user@host:port/path, UTF-8, never credentials; "" if none */
  const wchar_t *label;        /* drive label as Explorer shows it */
  wchar_t letter;              /* 'A'..'Z' */
  uint32_t state;              /* SD_STATE_S_* */
  uint32_t backend;            /* SD_STATE_B_* */
  int read_only;
  int network_location;
} host_state_src;

/* Creates the section and publishes an empty snapshot (a crashed agent's entries are replaced at once).
   Failure (squatted section, no memory) is logged by the caller; the agent runs without a snapshot. */
sd_err host_state_open(void);

/* Publishes n mounts (n <= SD_STATE_MAX_ENTRIES) with the given header flags. A no-op when not open. */
void host_state_publish(const host_state_src *items, uint32_t n, uint32_t flags);

/* Shutdown: publishes an empty snapshot with the shutting-down flag, then closes the section. */
void host_state_close(void);

#endif /* SD_HOST_STATE_PRODUCER_H */
