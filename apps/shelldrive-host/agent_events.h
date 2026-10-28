/* The rules of two agent events (03 §2.4 mount.state reason, §5.1 warning hostkey_source_insecure), kept apart
 * from agent.c so that the unit tests (tests/apps) can run them without a mount. */
#ifndef SD_HOST_AGENT_EVENTS_H
#define SD_HOST_AGENT_EVENTS_H

#include <stddef.h>
#include <stdint.h>

/* mount.state `reason` (03 §2.4). drop: the error code that took the mount offline, kept per mount (cap bytes, "" when
   none). st: sd_mount_state_name() of the new state; ecode: the error code of that state, NULL when it has none.
   Returns 1 and copies the reason into reason when the event carries one: the code of the offline period is sent with
   connecting, authenticating and mounted, and ends with the mounted state (or with failed, unmounting or unmounted).
   Returns 0 otherwise. */
int agent_reason_on_state(char *drop, size_t cap, const char *st, const char *ecode, char *reason, size_t rcap);

/* hostkey_source_insecure is warned once per live source and agent run (03 §5.1). done: a bit mask of the sources
   warned so far; bit: the source's bit (1u << index). Returns 1 when the bit was clear (the caller warns) and sets it. */
int agent_source_warn_take(uint32_t *done, uint32_t bit);

#endif /* SD_HOST_AGENT_EVENTS_H */
