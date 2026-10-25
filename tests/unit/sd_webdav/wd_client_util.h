/* Test-only HTTP/1.1 client over a raw loopback socket, with client-side SSPI (Negotiate) so the
 * server's authentication path runs exactly as with the redirector. */
#ifndef SD_WD_CLIENT_UTIL_H
#define SD_WD_CLIENT_UTIL_H

#include <winsock2.h>
#include <windows.h>

#include "sd/base.h"

typedef struct tc_conn { SOCKET s; char buf[256 * 1024]; size_t len; } tc_conn;

typedef struct tc_resp {
  int status;
  char head[4096];
  char *body; size_t body_n;      /* sd_alloc; freed by tc_resp_free */
  int closed;                     /* the server closed the connection after the response */
} tc_resp;

int  tc_connect(tc_conn *c, uint16_t port, int ipv6);     /* 0 on success */
void tc_close(tc_conn *c);
int  tc_send(tc_conn *c, const void *p, size_t n);
/* Reads one response (Content-Length framed; HEAD/204/304 without body when no_body). */
int  tc_read(tc_conn *c, tc_resp *r, int no_body, uint32_t timeout_ms);
void tc_resp_free(tc_resp *r);
/* Returns the value of header name in r->head (copied into out), or 0 if absent. */
int  tc_header(const tc_resp *r, const char *name, char *out, size_t cap);
/* 1 when the peer closed (recv returns 0) within timeout_ms. */
int  tc_wait_closed(tc_conn *c, uint32_t timeout_ms);

/* Sends "<method> <path> HTTP/1.1" with Host: localhost:<port>, extra header lines and body, and reads
   the response. */
int  tc_request(tc_conn *c, uint16_t port, const char *method, const char *path, const char *extra,
                const void *body, size_t body_n, tc_resp *r);
/* Runs the Negotiate exchange with a PROPFIND depth 0 on path; returns the final status. */
int  tc_authenticate(tc_conn *c, uint16_t port, const char *path);

#endif
