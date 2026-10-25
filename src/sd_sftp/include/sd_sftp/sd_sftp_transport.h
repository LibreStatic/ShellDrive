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
 * transport and is released by destroy. */
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
} sd_sftp_transport;

/* Like sd_sftp_session_create() but over an arbitrary transport. On failure the transport is not
   destroyed (the caller still owns it); on success the session owns it. */
sd_err sd_sftp_session_create_transport(const sd_sftp_transport *t, const sd_sftp_options *opt,
                                        sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out);

#endif /* SD_SFTP_TRANSPORT_H */
