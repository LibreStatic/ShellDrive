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
/* M1: multi-stream / reconnect fakes. Call before fake_transport(). */
void      fake_set_caps(fake_srv *f, uint32_t caps);             /* SD_SFTP_TP_REOPEN | SD_SFTP_TP_STREAMS */
void      fake_refuse_bulk(fake_srv *f, sd_err e);               /* open_stream(1) fails with e */
void      fake_fail_opens(fake_srv *f, LONG n, sd_err e);        /* the next n open() calls fail with e */
uint32_t  fake_opens(fake_srv *f);                               /* open() calls (connection attempts) */
uint32_t  fake_gen(fake_srv *f);                                 /* current connection generation */
uint32_t  fake_cur_stream(fake_srv *f);                          /* stream of the packet being handled */
int       fake_stream_open(fake_srv *f, uint32_t idx);
void      fake_reply_on(fake_srv *f, uint32_t idx, const void *bytes, size_t n);
/* M2 pool (01 §10.9): streams 2..4 model members 1..3 and the caps gain
 * SD_SFTP_TP_STREAMS | SD_SFTP_TP_POOL. `connections` is the pool size including the primary; the
 * transport's notify_ready admits members 1..connections-1 through sftp_session_pool_change() once
 * fake_set_session() supplied the session (this is what the SSH pool does on admission). Call before
 * fake_transport(). member_stats reports the admitted members in out[member-1], like the SSH pool. */
void      fake_set_pool(fake_srv *f, uint32_t connections);
void      fake_set_session(fake_srv *f, sd_sftp_session *s);
/* Plays the pool's decision path (sftp_ssh.c pool_decided) on the session's I/O thread with an
   explicit member generation, so tests can post a duplicate or stale member drop. */
void      fake_pool_change(fake_srv *f, uint32_t member, int admitted, sd_err reason, uint32_t gen);
void      fake_drop_member(fake_srv *f, uint32_t member);       /* the member channel dies alone */
/* Member stream failure injection (write path only): fail_member_writes fails every write with e
 * while the stream stays open (the drop report is still in flight); limit_member_writes accepts at
 * most `budget` more bytes and then accepts 0, like a full member TX queue. member 0 / budget < 0
 * clears. Set from the test thread, read on the fake's I/O thread. */
void      fake_fail_member_writes(fake_srv *f, uint32_t member, sd_err e);
void      fake_limit_member_writes(fake_srv *f, uint32_t member, LONG budget);
uint32_t  fake_stream_packets(fake_srv *f, uint32_t idx);       /* client packets seen on a stream */
/* Pool admission pacing (01 §10.9), modelled like sftp_ssh.c: attempts start 500 ms apart, a
 * transiently refused member retries after 500 ms then 2 s and is abandoned for the generation
 * after three refusals (an EV_POOL refusal per refusal, then SD_E_POOL_ABANDONED); a
 * SD_E_HOSTKEY_MISMATCH / SD_E_NOT_FOUND refusal stops the generation's admissions at once.
 * fake_refuse_member fails the member's next n admission attempts with e (n = 0 clears; set before
 * the generation's admissions start). fake_member_attempt_at reports the tick of the member's
 * attempt (1..3) of the current generation, attempts their number. */
void      fake_refuse_member(fake_srv *f, uint32_t member, LONG n, sd_err e);
uint64_t  fake_member_attempt_at(fake_srv *f, uint32_t member, uint32_t attempt);   /* attempt 1..3 */
uint32_t  fake_member_attempts(fake_srv *f, uint32_t member);

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
