/* Test transports for sd_sftp (test fixtures only, never shipped; D21).
 *
 * - tl_loop: a single I/O thread running posted functions in order.
 * - fake server: sd_sftp talks to a scripted handler that sees every complete client packet (on the
 *   I/O thread) and answers with fake_reply(); replies are delivered asynchronously, in order.
 * - process transport: sd_sftp talks to a child process over stdin/stdout pipes (OpenSSH
 *   sftp-server inside WSL for the interop tests). */
#ifndef SFTP_TEST_TP_H
#define SFTP_TEST_TP_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_sftp/sd_sftp_transport.h"

typedef struct tl_loop tl_loop;
tl_loop *tl_loop_new(void);
void     tl_loop_free(tl_loop *l);                     /* stops and joins; drops unrun items */
sd_err   tl_post(tl_loop *l, void (*fn)(void *), void *arg);
int      tl_is_io(tl_loop *l);

/* ---- fake server ---- */
typedef struct fake_srv fake_srv;
/* pkt points at the packet body (type byte first), n bytes. */
typedef void (*fake_handler)(fake_srv *f, void *ctx, const uint8_t *pkt, size_t n);
fake_srv *fake_new(fake_handler h, void *ctx);
void      fake_transport(fake_srv *f, sd_sftp_transport *out);   /* session owns it after create */
void      fake_reply(fake_srv *f, const void *bytes, size_t n);  /* any thread; raw stream bytes */
void      fake_reply_wr(fake_srv *f, sd_wr *w);                  /* sends and frees w */
void      fake_hangup(fake_srv *f);                              /* server closes the stream */
uint32_t  fake_packets(fake_srv *f);                             /* client packets seen */
void      fake_free_if_unused(fake_srv *f);                      /* when no session took it */
void      fake_run(fake_srv *f, void (*fn)(void *), void *arg);  /* runs fn on the I/O thread */

/* Packet builder: begins a reply of `type` with id (id_present). Finish with fake_reply_wr. */
void pk_begin(sd_wr *w, uint8_t type, uint32_t id);
void pk_status(fake_srv *f, uint32_t id, uint32_t code, const char *msg);
void pk_handle(fake_srv *f, uint32_t id, const char *h);
void pk_attrs_body(sd_wr *w, uint32_t perm, uint64_t size);   /* SIZE|UIDGID(1000)|PERM|TIMES */

/* ---- process transport ---- */
typedef struct proc_tp proc_tp;
/* cmdline is passed to CreateProcessW (modifiable copy made). */
sd_err proc_new(const wchar_t *cmdline, sd_sftp_transport *out, proc_tp **handle);
void   proc_pause(proc_tp *p, int paused);   /* 1: hold received data (simulates a stalled server) */

/* Runs a command line, waits up to timeout_ms; returns the exit code or -1. */
int run_cmd(const wchar_t *cmdline, uint32_t timeout_ms);

#endif /* SFTP_TEST_TP_H */
