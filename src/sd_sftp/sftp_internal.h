/* sd_sftp internal structures shared by the session core and the sync wrappers. I/O-thread-only
 * fields are marked; everything else is noted with its lock. */
#ifndef SD_SFTP_INTERNAL_H
#define SD_SFTP_INTERNAL_H

#include <windows.h>

#include "sd_platform/sd_thread.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_sftp/sd_sftp_transport.h"
#include "sftp_proto.h"

#define SFTP_COMP "sftp"

typedef struct sftp_item {
  struct sftp_item *next;
  uint32_t type;           /* IT_* */
  void    *ptr;
  uint64_t id;
} sftp_item;
enum { IT_SUBMIT = 1, IT_CANCEL, IT_RELEASE, IT_CLOSE, IT_TICK, IT_START, IT_RECONNECT, IT_STOP };

typedef struct sftp_range { struct sftp_range *next; uint64_t off; uint32_t len; } sftp_range;

typedef struct sftp_wire {
  struct sftp_wire *hnext;
  struct sftp_req *r;   /* NULL: orphan (background close) */
  struct sd_sftp_file *df;  /* striped data handle this wire counts on (01 §10.9) */
  uint32_t id;
  uint32_t ch;             /* SFTP channel (stream) the request went out on */
  uint32_t phase;
  uint32_t expect;         /* EXP_* bits of acceptable reply types (STATUS always) */
  uint64_t off;            /* data chunk: absolute file offset */
  uint32_t len;            /* data chunk length */
  uint32_t bytes;          /* accounted in inflight_bytes */
  uint64_t sent_ms;
} sftp_wire;

struct sd_sftp_file {
  sftp_item rel_item;
  sd_sftp_session *s;
  volatile LONG refs;
  struct sd_sftp_file *fprev, *fnext;   /* session list, under s->lock */
  uint8_t  handle[SFTP_MAX_HANDLE];
  uint32_t hlen;
  char    *path;
  uint32_t oflags;
  int      is_dir;
  int      meta;                         /* request class of handle ops */
  uint32_t ch;                           /* channel the handle lives on (I/O thread) */
  uint32_t generation;
  volatile LONG stale;
  volatile LONG closing;                 /* sd_sftp_close submitted */
  int      wire_closed;                  /* I/O thread */
  int      written;                      /* I/O thread: a WRITE was sent */
  int      drop_logged;                  /* I/O thread */
  sd_sftp_attrs attrs_at_open;
  void    *user;
  /* M2 striping (01 §10.9; I/O thread only) */
  int      striped;                      /* SD_SFTP_O_STRIPED honoured */
  uint32_t stripe_bytes;                 /* striping unit (default 1 MiB) */
  uint32_t route_n;                      /* members in the routing table incl. the primary (1..4) */
  uint8_t  route_map[4];                 /* route_map[k % route_n] = member (0 primary, 1..3) */
  int      data_wires;                   /* in-flight striped READ/WRITE wires on every channel */
  int      sub_state[3];                 /* SST_* of members 1..3 */
  struct sd_sftp_file *sub[3];           /* lazily opened sub-handles (owned references) */
};
enum { SST_NONE = 0, SST_OPENING, SST_OPEN, SST_FAILED };

typedef struct sftp_req {
  sftp_item item;
  struct sftp_req *qnext;             /* class queue (I/O thread) */
  struct sftp_req *lprev, *lnext;     /* live list (I/O thread) */
  struct sftp_req *tnext;             /* token table (global lock) */
  sd_sftp_session *s;
  uint32_t op, phase, flags;
  uint64_t deadline;
  uint64_t token;
  sd_sftp_cb cb; void *ctx;
  sd_sftp_file *f, *f2;                  /* references held */
  char *p1, *p2;
  sd_sftp_attrs a; int has_attrs;
  uint32_t u1;                           /* oflags, rename flags, no_follow */
  uint32_t target_ch;                    /* nonzero: internal request bound to that channel */
  uint64_t off, off2, len64;
  uint8_t *buf; uint32_t len;
  uint32_t *ids; uint32_t nu, ng;        /* names_by_id */
  /* progress (I/O thread) */
  int queued, qclass, done, sent, in_live, emit_pending, cancel_pending;
  int waiting;                           /* on the WAIT_READY list */
  int barrier_started;                   /* striped barrier wires were emitted */
  uint32_t wires;
  uint64_t emit_off;                     /* relative */
  sftp_range *reissue;
  uint64_t eof_at, err_at;               /* relative, UINT64_MAX = none */
  sd_err   cerr;
  sd_sftp_file *newf;                    /* open result not yet handed out */
  uint8_t  ph[SFTP_MAX_HANDLE]; uint32_t phlen; int ph_open;   /* probe handle */
  uint32_t ph_ch;
  int      probe_found;
  char    *msg;
  sd_sftp_completion c;
} sftp_req;

/* sftp_ssh.c -> session (I/O thread): an authentication prompt was raised during a reconnect. */
void sftp_session_auth_prompt(sd_sftp_session *s);
/* sftp_ssh.c -> session (primary I/O thread): a pool member settled; admitted=0 carries the reason.
   gen is the pool's per-member generation the event belongs to (0: the current session generation);
   a drop whose gen is not the member's admitted generation is ignored (a stale posted event, or the
   second report of a drop already handled - 01 §10.9). */
void sftp_session_pool_change(sd_sftp_session *s, uint32_t member, int admitted, sd_err reason, uint32_t gen);
/* sftp_ssh.c -> session (primary I/O thread): the pool refused to admit a member that is not
   admitted in the current generation. reason is the transient failure (the pool retries with
   backoff) or SD_E_POOL_ABANDONED when it gave up for this generation after three refusals
   (01 §10.9). Informational EV_POOL only: nothing was ever admitted, so there is no member
   lifecycle (member_lost) to settle and the connection count does not change. */
void sftp_session_pool_refused(sd_sftp_session *s, uint32_t member, sd_err reason);

#endif /* SD_SFTP_INTERNAL_H */
