/* sd_state: the mount state snapshot section (03 §1.6, §8.2, §8.2.1; TM-R26).
 *
 * The agent (writer) publishes the state of its mounts into Local\com.librestatic.shelldrive.state.<SID>;
 * the shell extension (reader) copies it inside QueryContextMenu. Both sides use this module, so the
 * DLL links sd_state with no dependency beyond sd_base, sd_platform and sd_ipc.
 *
 * The layout is architecture independent: every field is read and written at its byte offset in
 * little-endian, there are no pointers and strings are UTF-16LE in fixed slots. The codec functions
 * work on any byte buffer (tests and the section alike); the section helpers add the owner and label
 * checks of sd_ipc_state_open/create.
 *
 * Writer rules: one writer; the caller serializes publishes (the agent calls it under its state lock).
 * Strings longer than their slot are cut (never inside a surrogate pair), always NUL-terminated, and
 * the entry gets SD_STATE_EF_TRUNCATED. Reader rules: copy-then-validate, at most SD_STATE_READ_TRIES
 * attempts; a structural error or exhausted retries means "no data" (the caller shows no drive items). */
#ifndef SD_STATE_H
#define SD_STATE_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#include "sd_base/sd_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- layout v1 constants (03 §8.2.1) ---- */
#define SD_STATE_MAGIC              0x54534453u     /* "SDST" little-endian */
#define SD_STATE_LAYOUT_V1          1u
#define SD_STATE_LAYOUT_READER_MAX  2u              /* a v1 reader accepts layouts 1 and 2 (N+1) */
#define SD_STATE_HEADER_SIZE        64u
#define SD_STATE_ENTRY_SIZE         1792u           /* v1 entry stride written by this module */
#define SD_STATE_ENTRY_SIZE_MAX     4096u
#define SD_STATE_MAX_ENTRIES        128u
#define SD_STATE_MAX_BYTES          262144u         /* = SD_IPC_STATE_BYTES, the section size */
#define SD_STATE_READ_TRIES         3u

/* header flags (offset 40) */
#define SD_STATE_HF_SHUTTING_DOWN   0x1u            /* entries are advisory */

/* entry flags (offset 0); other bits are written as zero and ignored by readers */
#define SD_STATE_EF_IN_USE           0x01u
#define SD_STATE_EF_GLOBAL           0x02u
#define SD_STATE_EF_READ_ONLY        0x04u
#define SD_STATE_EF_HAS_REMOTE_URL   0x08u
#define SD_STATE_EF_TRUNCATED        0x10u
#define SD_STATE_EF_NEEDS_ADMIN      0x20u
#define SD_STATE_EF_NETWORK_LOCATION 0x40u

/* entry state (offset 4): values above SD_STATE_S_UNMOUNTED read as SD_STATE_S_UNKNOWN */
enum {
  SD_STATE_S_UNKNOWN = 0, SD_STATE_S_CONNECTING, SD_STATE_S_AUTHENTICATING, SD_STATE_S_MOUNTED,
  SD_STATE_S_OFFLINE, SD_STATE_S_AUTH_REQUIRED, SD_STATE_S_FAILED, SD_STATE_S_UNMOUNTING,
  SD_STATE_S_UNMOUNTED
};

/* entry backend (offset 8): values above SD_STATE_B_DOKANY read as SD_STATE_B_UNKNOWN */
enum { SD_STATE_B_UNKNOWN = 0, SD_STATE_B_WEBDAV, SD_STATE_B_DOKANY };

/* String slot sizes in UTF-16 code units. */
#define SD_STATE_ID_CCH      32u                    /* mount_id, profile_id */
#define SD_STATE_NAME_CCH    128u                   /* profile_name */
#define SD_STATE_TARGET_CCH  260u                   /* target */
#define SD_STATE_LABEL_CCH   64u                    /* label */
#define SD_STATE_URL_CCH     320u                   /* remote_url */

/* One mount, decoded or to be published. Strings are NUL-terminated in memory (arrays hold the slot and its NUL). The byte layout of the
   section is defined by the offsets in the codec, not by this struct. */
typedef struct sd_state_entry {
  uint32_t flags;                                   /* SD_STATE_EF_* */
  uint32_t state;                                   /* SD_STATE_S_* */
  uint32_t backend;                                 /* SD_STATE_B_* */
  uint32_t mount_num;                               /* agent-local number; 0 for global entries */
  uint16_t letter;                                  /* 'A'..'Z' or 0 */
  wchar_t  mount_id[SD_STATE_ID_CCH + 1u];               /* e.g. m-3 */
  wchar_t  profile_id[SD_STATE_ID_CCH + 1u];             /* 32 lowercase hex digits or empty */
  wchar_t  profile_name[SD_STATE_NAME_CCH + 1u];
  wchar_t  target[SD_STATE_TARGET_CCH + 1u];             /* X:, a folder path or the WebDAV UNC */
  wchar_t  label[SD_STATE_LABEL_CCH + 1u];
  wchar_t  remote_url[SD_STATE_URL_CCH + 1u];            /* sftp://user@host:port/path, never credentials */
} sd_state_entry;

/* Decoded header fields (of the validated copy). */
typedef struct sd_state_header {
  uint32_t layout_version;
  uint32_t header_size;
  uint32_t total_size;
  uint32_t entry_size;
  uint32_t entry_count;
  uint32_t seq;
  uint32_t writer_pid;
  uint32_t writer_session;
  uint64_t published_filetime;
  uint32_t flags;
  uint32_t max_entries;
} sd_state_header;

/* ---- writer ---- */

typedef struct sd_state_publish {
  const sd_state_entry *entries;   /* entry_count entries (may be NULL when entry_count is 0) */
  uint32_t entry_count;            /* 0..SD_STATE_MAX_ENTRIES */
  uint32_t flags;                  /* SD_STATE_HF_* */
  uint32_t writer_pid;             /* 0 = this process */
  uint32_t writer_session;         /* 0 = this process's session */
  uint64_t published_filetime;     /* 0 = now */
} sd_state_publish;

/* Copies src into an entry string array of cch + 1 units (the slot and its NUL). A source of at most cch
   units is copied whole. A longer one is cut to cch - 1 units, never between a surrogate pair, and the
   function returns 1: the caller sets SD_STATE_EF_TRUNCATED on the entry. src may be NULL (empty). */
int sd_state_set_string(wchar_t *dst, uint32_t cch, const wchar_t *src);

/* Seqlock publish into a buffer of `size` bytes (a mapped view or a heap block): seq goes odd, the header
   and the entries are written, then seq goes even again, with full barriers. A stale odd seq (a writer that
   died mid-write) is made even first. *truncated_entries (optional) receives the number of entries with
   a cut string. SD_E_INVALID_PARAM for a bad count or a buffer that is too small. Layout 1, v1 stride. */
sd_err sd_state_publish_buffer(void *base, size_t size, const sd_state_publish *in, uint32_t *truncated_entries);

/* Same with an explicit layout and entry stride. For tests and tools (a writer of another layout).
   entry_size must be at least SD_STATE_ENTRY_SIZE, at most SD_STATE_ENTRY_SIZE_MAX, a multiple of 8. */
sd_err sd_state_publish_layout(void *base, size_t size, const sd_state_publish *in, uint32_t layout_version,
                               uint32_t entry_size, uint32_t *truncated_entries);

/* The agent's section, created with sd_ipc_state_create (owner and label checked; a squatted section
   fails with SD_E_ACCESS_DENIED). */
typedef struct sd_state_writer sd_state_writer;
sd_err sd_state_writer_open(sd_state_writer **out);
/* Publishes into the section. The caller serializes calls. */
sd_err sd_state_writer_publish(sd_state_writer *w, const sd_state_publish *in, uint32_t *truncated_entries);
/* Unmaps and closes the handle. The contents stay until the last handle is gone. */
void   sd_state_writer_close(sd_state_writer *w);

/* ---- reader ---- */

/* Receiving buffer (heap): the raw copy of the validated bytes and the decoded entries. */
typedef struct sd_state_snapshot {
  sd_state_header header;          /* header of the validated copy */
  uint32_t count;                  /* valid entries in entries[0..count) */
  uint32_t dropped;                /* entries dropped by validation */
  uint32_t attempts;               /* copy attempts used (1..SD_STATE_READ_TRIES) */
  sd_state_entry *entries;         /* SD_STATE_MAX_ENTRIES entries */
  uint8_t *copy;                   /* SD_STATE_MAX_BYTES scratch */
} sd_state_snapshot;

sd_err sd_state_snapshot_new(sd_state_snapshot **out);
void   sd_state_snapshot_free(sd_state_snapshot *s);

/* Copy-then-validate over a buffer of `size` bytes. SD_OK with the valid entries (possibly none);
   SD_E_INVALID_PARAM for a header that fails validation (no data, no retry); SD_E_BUSY when every
   attempt saw an odd or changing seq (no data). Any error means: show no drive items. */
sd_err sd_state_read_buffer(const void *base, size_t size, sd_state_snapshot *snap);

/* Opens the section (sd_ipc_state_open: owner and label checked, FILE_MAP_READ), maps it read-only,
   reads it with sd_state_read_buffer and unmaps it. SD_E_NOT_FOUND when no agent runs in this session,
   SD_E_ACCESS_DENIED for a squatted section. Nothing outlives the call. */
sd_err sd_state_read_section(sd_state_snapshot *snap);

/* Name of an entry state ("mounted", ...), for logs and tests. */
const char *sd_state_state_name(uint32_t state);

#ifdef __cplusplus
}
#endif

#endif /* SD_STATE_H */
