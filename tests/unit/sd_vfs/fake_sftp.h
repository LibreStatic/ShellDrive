/* In-memory fake of the sd_sftp async API (src/sd_sftp/include/sd_sftp/sd_sftp.h) for sd_vfs and
 * sd_dokan tests. It implements exactly the sd_sftp_* functions sd_vfs calls, with the same
 * contract: completions run on one worker thread ("I/O thread"), never inside the submit call.
 *
 * The remote tree is POSIX-like: byte names, symlinks (resolved by stat/open/realpath, not by
 * lstat/remove/rename), directories, regular files and FIFOs. Names compare byte-exactly unless the
 * session is created case-insensitive. Test hooks below build trees, inject malformed directory
 * entries (which a real sd_sftp would already drop, TM-R12), count operations, add a simulated
 * round-trip latency (requests stay pipelined), hold writes on the wire, and simulate a disconnect
 * and reconnect with generations and stale handles (01 §10.6). Thread safety: every function is
 * thread-safe. */
#ifndef SD_FAKE_SFTP_H
#define SD_FAKE_SFTP_H

#include "sd_sftp/sd_sftp.h"

typedef struct fake_config {
  const char *home;           /* default "/home/user" (created) */
  int case_insensitive;       /* 0 = byte-exact names */
  uint32_t ext;               /* SD_SFTP_EXT_*; default posix-rename|statvfs|fsync when 0 and !no_ext */
  int no_ext;                 /* advertise no extensions */
  uint32_t max_read, max_write;   /* default 256 KiB */
  uint32_t uid, gid;          /* identity of the account (default 1000/1000), home owner */
  uint32_t latency_ms;        /* per-request delay before execution (pipelined, FIFO); 0 = none */
  int home_uid_set; uint32_t home_uid;   /* owner of the home directory if it differs (D10 tests) */
} fake_config;

sd_sftp_session *fake_session_create(const fake_config *cfg);   /* cfg may be NULL; READY on return */
void             fake_session_destroy(sd_sftp_session *s);

/* Tree building (paths absolute or relative to home; parents must exist). Return 0 on success. */
int fake_mkdir(sd_sftp_session *s, const char *path, uint32_t perm);
int fake_put(sd_sftp_session *s, const char *path, const void *data, size_t len, uint32_t perm);
int fake_symlink(sd_sftp_session *s, const char *path, const char *target);
int fake_mkfifo(sd_sftp_session *s, const char *path);
int fake_set_owner(sd_sftp_session *s, const char *path, uint32_t uid, uint32_t gid);

/* Inspection. fake_get copies up to cap bytes; returns the file size or -1 if absent. */
long long fake_get(sd_sftp_session *s, const char *path, void *buf, size_t cap);
int       fake_exists(sd_sftp_session *s, const char *path);   /* lstat semantics */
uint32_t  fake_mode(sd_sftp_session *s, const char *path);
int64_t   fake_mtime(sd_sftp_session *s, const char *path);

/* Malformed or extra READDIR entries for one directory (raw bytes, may contain '/', NUL, ...). */
void fake_inject_dirent(sd_sftp_session *s, const char *dir, const char *name, uint32_t len, uint32_t mode);

/* Operation counters (by SD_FAKE_OP_*), reset with fake_reset_counts. */
enum { FOP_OPEN, FOP_OPENDIR, FOP_READDIR, FOP_READ, FOP_WRITE, FOP_STAT, FOP_LSTAT, FOP_FSTAT, FOP_SETSTAT,
       FOP_FSETSTAT, FOP_MKDIR, FOP_RMDIR, FOP_REMOVE, FOP_RENAME, FOP_REALPATH, FOP_READLINK, FOP_STATVFS,
       FOP_FSYNC, FOP_CLOSE, FOP_REOPEN, FOP_COUNT };
uint32_t fake_count(sd_sftp_session *s, int op);
void     fake_reset_counts(sd_sftp_session *s);
uint32_t fake_open_handles(sd_sftp_session *s);

/* Simulated link state: SD_SFTP_ST_READY or SD_SFTP_ST_DISCONNECTED (every request then fails,
   handles stay valid: a short blip without a reconnect). */
void fake_set_state(sd_sftp_session *s, sd_sftp_state st);
/* Connection loss (01 §10.6): DISCONNECTED; held and queued requests complete with
   SD_E_DISCONNECTED (maybe_executed = 1 for writes that were "sent"), every handle becomes stale. */
void fake_disconnect(sd_sftp_session *s);
/* READY again with generation + 1; stale handles need sd_sftp_file_reopen. */
void fake_reconnect(sd_sftp_session *s);
/* While on, WRITE requests are held "on the wire" (not executed) until released or a disconnect. */
void fake_hold_writes(sd_sftp_session *s, int on);
uint32_t fake_held_writes(sd_sftp_session *s);
/* Remote changes behind the vfs's back. */
int  fake_overwrite(sd_sftp_session *s, const char *path, const void *data, size_t len, int64_t mtime);
int  fake_set_mtime(sd_sftp_session *s, const char *path, int64_t mtime);
/* Fails the next matching operation with err (one shot). */
void fake_fail_next(sd_sftp_session *s, int op, sd_err err);

#endif /* SD_FAKE_SFTP_H */
