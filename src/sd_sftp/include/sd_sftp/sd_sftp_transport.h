/* sd_sftp transport interface: the byte stream an SFTP session runs on.
 *
 * sd_sftp_session_create() builds this on top of an sd_ssh connection and its "sftp" subsystem
 * channel (01 §9). sd_sftp_session_create_transport() takes any other implementation of the same
 * shape: tests use it to run sd_sftp against a scripted fake server or a local OpenSSH sftp-server
 * over pipes (D21: test infrastructure only).
 *
 * The contract mirrors sd_ssh channels exactly:
 * - post / is_io_thread may be called from any thread. post(fn, arg) runs fn(arg) on the
 *   transport's single I/O thread, in posting order, never synchronously inside post.
 * - open, write, consumed, close and probe are called by sd_sftp on the I/O thread only.
 * - The sink callbacks are invoked by the transport on the I/O thread only, serialized:
 *   on_open exactly once after open; err != SD_OK means the stream never opened and no further
 *   callback follows;
 *   on_data for received bytes (the transport may deliver more only after consumed() returned
 *   enough credit; sd_sftp consumes every byte before returning from on_data);
 *   on_writable when write() previously accepted less than offered and space is available again;
 *   on_eof / on_closed when the stream ends (on_closed is the last callback; after close() the
 *   transport must deliver on_closed).
 * - destroy is called once, from a control thread (never the I/O thread), after on_closed or when
 *   the stream was never opened; it stops the I/O thread and frees the transport. Posted functions
 *   that have not run by then are dropped.
 * Thread safety: as listed above. Ownership: the transport struct is copied; ctx stays owned by the
 * transport and is released by destroy.
 *
 * M1 additions (all optional; a zero-filled tail keeps the M0 single-stream, single-connection
 * contract above, and the session then ends in FAILED when the stream is lost):
 * - caps & SD_SFTP_TP_REOPEN: after close() was called and every stream that was opened has
 *   delivered on_closed (or, for a stream still opening, on_open(err)), open() may be called again;
 *   it builds a fresh connection on the same I/O thread (sd_ssh: same sd_ssh_conn, pinned host key,
 *   reconnect secret cache). sd_sftp's reconnect loop needs this cap.
 * - caps & SD_SFTP_TP_STREAMS: a second stream (idx 1, the "bulk" SFTP channel, D19) on the same
 *   connection. open_stream(1) is called on the I/O thread only after stream 0 reported
 *   on_open(SD_OK); its on_open is delivered asynchronously (never inside open_stream), with an error
 *   when the server refuses another session channel (sd_sftp then degrades to one channel).
 *   write_stream / consumed_stream address a stream by index (0 is the stream of open()); close()
 *   closes every stream and the connection. When the connection dies, every open stream gets
 *   on_closed and every opening stream gets on_open(err).
 * - rtt (optional): the connection's smoothed RTT (sd_ssh keepalive samples, 01 §4.6) for
 *   sd_sftp_session_stats(); any thread. */
#ifndef SD_SFTP_TRANSPORT_H
#define SD_SFTP_TRANSPORT_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_sftp/sd_sftp.h"

typedef struct sd_sftp_transport {
  void *ctx;
  sd_err (*post)(void *ctx, void (*fn)(void *), void *arg);                 /* any thread */
  int    (*is_io_thread)(void *ctx);                                         /* any thread */
  sd_err (*open)(void *ctx, const sd_ssh_channel_sink *sink, void *sink_ctx);
  sd_err (*write)(void *ctx, const uint8_t *p, size_t n, size_t *accepted);
  void   (*consumed)(void *ctx, size_t n);
  void   (*close)(void *ctx);
  void   (*probe)(void *ctx);                                  /* optional liveness check; may be NULL */
  const sd_ssh_negotiated *(*negotiated)(void *ctx);           /* optional; NULL or NULL result: no SSH */
  void   (*destroy)(void *ctx);                                /* control thread */
  /* ---- M1 (zero when unused) ---- */
  uint32_t caps;                                               /* SD_SFTP_TP_* */
  sd_err (*open_stream)(void *ctx, uint32_t idx, const sd_ssh_channel_sink *sink, void *sink_ctx);
  sd_err (*write_stream)(void *ctx, uint32_t idx, const uint8_t *p, size_t n, size_t *accepted);
  void   (*consumed_stream)(void *ctx, uint32_t idx, size_t n);
  void   (*rtt)(void *ctx, uint32_t *srtt_ms, uint32_t *rttvar_ms);
  /* ---- M2 pool (zero when unused; a pool transport reports caps & SD_SFTP_TP_POOL) ---- */
  /* Called on the I/O thread after the primary reported READY. realpath_dot is the primary's
     realpath(".") (the pool admission check, 01 §10.9); NULL when the session never learned it. */
  void   (*notify_ready)(void *ctx, const char *realpath_dot);
  /* Per-member statistics, members 1..3, written to out[idx - 1] (member 1 is out[0]; the primary
     is the session's own conn[0]). Only admitted members are written; *count receives their number.
     Any thread. */
  void   (*member_stats)(void *ctx, sd_sftp_conn_stats out[3], uint32_t *count);
} sd_sftp_transport;

enum { SD_SFTP_TP_REOPEN = 1u << 0, SD_SFTP_TP_STREAMS = 1u << 1, SD_SFTP_TP_POOL = 1u << 2 };

/* Like sd_sftp_session_create() but over an arbitrary transport. On failure the transport is not
   destroyed (the caller still owns it); on success the session owns it. */
sd_err sd_sftp_session_create_transport(const sd_sftp_transport *t, const sd_sftp_options *opt,
                                        sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out);

#endif /* SD_SFTP_TRANSPORT_H */
