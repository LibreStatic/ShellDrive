/* Shared helpers for the sd_sftp tests: completion waiters and session event capture. */
#ifndef SFTP_TEST_UTIL_H
#define SFTP_TEST_UTIL_H

#include "sd_platform/sd_thread.h"
#include "sd_sftp/sd_sftp.h"

enum { W_STAT = 0, W_OPEN, W_RW, W_NAME, W_DIR, W_VFS };
typedef struct waiter waiter;
struct waiter {
  sd_event ev;
  int kind;                 /* W_*: which union member to copy */
  void (*dir_cb)(waiter *w, const sd_sftp_completion *c);   /* optional, W_DIR */
  void *user;
  volatile LONG calls;
  sd_err err;
  uint32_t sftp_status;
  int maybe_executed;
  int session_ready;        /* DISCONNECTED from a pool member; the session stayed READY */
  char msg[256];
  sd_sftp_file *file;
  sd_sftp_attrs attrs;
  uint32_t bytes; int eof;
  char path[1024]; uint32_t path_len;
  uint32_t count, dropped;
  char names[8][64];        /* first readdir names */
  sd_sftp_statvfs vfs;
  int on_io_thread;
  void *session;            /* for the io-thread check */
};

void waiter_init(waiter *w, void *session);
void waiter_reset(waiter *w, int kind);
void waiter_free(waiter *w);
int  waiter_wait(waiter *w, uint32_t ms);       /* 1 if completed */
void waiter_cb(void *ctx, const sd_sftp_completion *c);

typedef struct evlog {
  sd_event ready, ended;
  sd_sftp_state states[32];
  sd_err reasons[32];
  volatile LONG n;
  uint32_t ext; uint64_t max_read, max_write; uint32_t quirks; uint32_t uid; char home[256];
  uint32_t ext_count;
  volatile LONG n_pool;         /* SD_SFTP_EV_POOL events */
  volatile LONG n_pool_drop;    /* of those, the ones with a non-OK reason (a member was dropped) */
  uint32_t pool_member, pool_conns; sd_err pool_reason;
} evlog;
void evlog_init(evlog *e);
void evlog_free(evlog *e);
void evlog_cb(void *ctx, const sd_sftp_event *ev);
int  evlog_has(const evlog *e, sd_sftp_state st);

#endif
