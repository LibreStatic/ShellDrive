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
enum { IT_SUBMIT = 1, IT_CANCEL, IT_RELEASE, IT_CLOSE, IT_TICK, IT_START };

typedef struct sftp_range { struct sftp_range *next; uint64_t off; uint32_t len; } sftp_range;

typedef struct sftp_wire {
  struct sftp_wire *hnext;
  struct sftp_req *r;   /* NULL: orphan (background close) */
  uint32_t id;
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
  uint32_t generation;
  volatile LONG stale;
  volatile LONG closing;                 /* sd_sftp_close submitted */
  int      wire_closed;                  /* I/O thread */
  int      written;                      /* I/O thread: a WRITE was sent */
  int      drop_logged;                  /* I/O thread */
  sd_sftp_attrs attrs_at_open;
  void    *user;
};

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
  uint64_t off, off2, len64;
  uint8_t *buf; uint32_t len;
  uint32_t *ids; uint32_t nu, ng;        /* names_by_id */
  /* progress (I/O thread) */
  int queued, qclass, done, sent, in_live, emit_pending, cancel_pending;
  uint32_t wires;
  uint64_t emit_off;                     /* relative */
  sftp_range *reissue;
  uint64_t eof_at, err_at;               /* relative, UINT64_MAX = none */
  sd_err   cerr;
  sd_sftp_file *newf;                    /* open result not yet handed out */
  uint8_t  ph[SFTP_MAX_HANDLE]; uint32_t phlen; int ph_open;   /* probe handle */
  int      probe_found;
  char    *msg;
  sd_sftp_completion c;
} sftp_req;

#endif /* SD_SFTP_INTERNAL_H */
