/* Reader of the agent's state section, layout v1 (03 §8.2.1, TM-R26). The shell extension sees the
   section only through this interface, so the reader can later be replaced by sd_state without touching
   the menu code.
 *
 * Contract: shx_snapshot_read copies the section, validates the copy and never reads the mapped view
 * again after the copy. A missing section, a foreign owner or label (checked by sd_ipc_state_open),
 * a bad header, or three unstable reads all mean "no data": the function returns 0 and the caller
 * shows no drive items. Bad entries are dropped one by one. Nothing here touches the network, the IPC
 * pipe or any profile file. */
#ifndef SD_SHELLEXT_SNAPSHOT_H
#define SD_SHELLEXT_SNAPSHOT_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#define SHX_SNAP_MAGIC        0x54534453u     /* "SDST" */
#define SHX_SNAP_HEADER_BYTES 64u
#define SHX_SNAP_ENTRY_BYTES  1792u
#define SHX_SNAP_MAX_ENTRIES  128u
#define SHX_SNAP_MAX_BYTES    262144u         /* section size, sd_ipc SD_IPC_STATE_BYTES */

/* Entry flags (bit 0 IN_USE; bits 7.. must be zero). */
#define SHX_F_IN_USE          0x00000001u
#define SHX_F_GLOBAL          0x00000002u
#define SHX_F_READ_ONLY       0x00000004u
#define SHX_F_HAS_REMOTE_URL  0x00000008u
#define SHX_F_TRUNCATED       0x00000010u
#define SHX_F_NEEDS_ADMIN     0x00000020u
#define SHX_F_NETWORK_LOCATION 0x00000040u
#define SHX_F_KNOWN_MASK      0x0000007Fu

/* Mount states (03 §8.2.1). Values above 8 are read as 0 (unknown). */
#define SHX_STATE_UNKNOWN       0u
#define SHX_STATE_CONNECTING    1u
#define SHX_STATE_AUTHENTICATING 2u
#define SHX_STATE_MOUNTED       3u
#define SHX_STATE_OFFLINE       4u
#define SHX_STATE_AUTH_REQUIRED 5u
#define SHX_STATE_FAILED        6u
#define SHX_STATE_UNMOUNTING    7u
#define SHX_STATE_UNMOUNTED     8u

/* One validated entry. Only the fields the menu needs are copied out. */
typedef struct shx_entry {
  uint32_t flags;
  uint32_t state;
  uint32_t backend;
  uint32_t mount_num;
  WCHAR    letter;      /* 'A'..'Z', or 0 for an entry without a drive letter */
  WCHAR    remote_url[321];  /* sftp://user@host:port/path, NUL-terminated; empty without HAS_REMOTE_URL */
} shx_entry;

/* Copies up to max valid entries into out and returns how many were written (0 = no usable data).
   Bounded: at most three tries of the seqlock read. */
size_t shx_snapshot_read(shx_entry *out, size_t max);

#endif /* SD_SHELLEXT_SNAPSHOT_H */
