/* Process-wide logger (03 §10.1, review §4 "shared logging API").
 *
 * Record format (one UTF-8 line, CRLF):
 *   2026-10-24T18:03:11.482Z 4412 7720 INFO  ssh  [m-3] kex done kex=curve25519-sha256
 *   (UTC ISO 8601, pid, tid, level, component, optional mount id, English message)
 *
 * Messages are English, never contain secrets, and network strings are length-bounded and escaped
 * by the formatter. The format language is a restricted printf subset; there is deliberately no
 * specifier for secret buffers:
 *   %s  UTF-8 string (control bytes escaped as \xNN, truncated at 512 bytes; NULL prints "(null)")
 *   %ls UTF-16 string (same rules)      %c  ASCII character
 *   %d %u %x  int / unsigned / hex      %lld %llu %llx  64-bit      %zu  size_t
 *   %p  pointer                          %%  literal percent
 * Anything else renders as "%?". Records over 4 KiB are truncated.
 *
 * Sinks: an optional log file (size rotation: SD_LOG_ROTATE_BYTES, SD_LOG_GENERATIONS files
 * <name>.1 .. <name>.5), OutputDebugStringW while a debugger is attached, and up to 4 callback sinks
 * (tests, IPC log streaming). M0 writes synchronously under one lock; the background logger thread
 * and lock-free queue of 03 §10.1 replace it later without API change.
 *
 * Thread safety: all functions are thread-safe. Sink callbacks run with the logger lock held and
 * must not log. */
#ifndef SD_LOG_H
#define SD_LOG_H

#include <stdarg.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

typedef enum sd_log_level {
  SD_LOG_ERROR = 0, SD_LOG_WARN, SD_LOG_INFO, SD_LOG_DEBUG, SD_LOG_TRACE
} sd_log_level;

#define SD_LOG_ROTATE_BYTES (5u * 1024u * 1024u)
#define SD_LOG_GENERATIONS  5

void         sd_log_set_level(sd_log_level max_level);   /* default SD_LOG_INFO */
sd_log_level sd_log_get_level(void);
int          sd_log_enabled(sd_log_level level);

/* Opens (creates or appends) the log file; replaces a previous one. NULL closes the file sink. */
sd_err sd_log_open_file(const wchar_t *path);
void   sd_log_close(void);                                 /* flushes and closes all sinks */

/* Privacy of names and paths (03 §10.1, TM-R31). Typed fields for the formatter:
     %Hs  host name      %Us  user name      %Rs  remote path
   standard (default): host and user are printed; a remote path only in error, debug and trace records.
   strict: all three are replaced by a keyed hash ("h:3f9a1c", "u:...", "p:...") in every record. hash computes
   the 32-byte MAC of a UTF-8 string (HMAC-SHA-256 with state\log.key, the caller's job); with no hash function the
   field prints "[redacted]". Call at start-up and after a settings reload (a record in flight may use either mode). */
typedef enum sd_log_privacy { SD_LOG_PRIVACY_STANDARD = 0, SD_LOG_PRIVACY_STRICT = 1 } sd_log_privacy;
typedef void (*sd_log_hash_fn)(void *ctx, const char *utf8, size_t len, uint8_t out[32]);
void           sd_log_set_privacy(sd_log_privacy mode, sd_log_hash_fn hash, void *ctx);
sd_log_privacy sd_log_get_privacy(void);

typedef void (*sd_log_sink_fn)(void *ctx, sd_log_level level, const char *line, size_t len);
sd_err sd_log_add_sink(sd_log_sink_fn fn, void *ctx);     /* line excludes the CRLF */
void   sd_log_remove_sink(sd_log_sink_fn fn, void *ctx);

/* component: short English tag ("ssh", "sftp", "vfs", "ipc", ...); mount_id may be NULL. */
void sd_log(sd_log_level level, const char *component, const char *mount_id,
            _Printf_format_string_ const char *fmt, ...);
void sd_logv(sd_log_level level, const char *component, const char *mount_id,
             const char *fmt, va_list ap);

/* Formats with the same restricted language into buf (always NUL-terminated if cap > 0).
   Returns the number of bytes written, excluding the NUL. */
size_t sd_log_format(char *buf, size_t cap, const char *fmt, va_list ap);

#define SD_LOGE(comp, ...) sd_log(SD_LOG_ERROR, comp, NULL, __VA_ARGS__)
#define SD_LOGW(comp, ...) sd_log(SD_LOG_WARN,  comp, NULL, __VA_ARGS__)
#define SD_LOGI(comp, ...) sd_log(SD_LOG_INFO,  comp, NULL, __VA_ARGS__)
#define SD_LOGD(comp, ...) do { if (sd_log_enabled(SD_LOG_DEBUG)) sd_log(SD_LOG_DEBUG, comp, NULL, __VA_ARGS__); } while (0)

#endif /* SD_LOG_H */
