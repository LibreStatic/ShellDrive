/* sd_webdav private: pure protocol helpers (no sockets, no vfs), unit-tested in tests/unit/sd_webdav.
 *
 * - wd_sb: growable byte buffer with a hard cap.
 * - HTTP/1.1 request head parser with the pre-authentication limits of 02 §7.3 (TM-R20), chunked
 *   body decoder (chunk-size lines <= 32 bytes).
 * - Request-target decoding (02 §7.5, TM-R12): never yields '/', '\', NUL, controls, '.' or '..'.
 * - Host header check (DNS rebinding), Destination parsing, href encoding.
 * - Minimal namespace-aware XML parser (no DTD, depth <= 32, <= 1 MiB) and escaping.
 * - Base64, base32 tokens, RFC 1123 / RFC 3339 dates, Range, Timeout, If-header lock tokens. */
#ifndef SD_WD_PROTO_H
#define SD_WD_PROTO_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* ---- limits (02 §7.3, §7.5) ---- */
#define WD_MAX_REQUEST_LINE  (8u * 1024u)
#define WD_MAX_HEAD          (32u * 1024u)
#define WD_MAX_HEADERS       64u
#define WD_MAX_CHUNK_LINE    32u
#define WD_MAX_XML           (1u << 20)
#define WD_MAX_XML_DEPTH     32u
#define WD_MAX_XML_NODES     8192u
#define WD_MAX_SEGMENTS      256u
#define WD_UNAUTH_DRAIN_MAX  (64u * 1024u)
#define WD_TOKEN_CHARS       26u          /* 130 bits, base32 */

/* ---- growable buffer ---- */
typedef struct wd_sb { char *p; size_t n, cap, max; int oom; } wd_sb;
void wd_sb_init(wd_sb *b, size_t max);     /* max = hard cap (0 = 64 MiB) */
void wd_sb_free(wd_sb *b);
void wd_sb_add(wd_sb *b, const void *p, size_t n);
void wd_sb_str(wd_sb *b, const char *s);
void wd_sb_fmt(wd_sb *b, const char *fmt, ...);       /* vsnprintf, bounded at 1 KiB per call */
void wd_sb_xml(wd_sb *b, const char *s, size_t n);    /* XML-escaped text */

/* ---- HTTP request head ---- */
typedef struct wd_hdr { const char *name, *val; uint32_t nlen, vlen; } wd_hdr;

typedef struct wd_req {
  char method[24];
  const char *target; uint32_t tlen;
  int minor;                       /* HTTP/1.<minor> */
  wd_hdr h[WD_MAX_HEADERS]; uint32_t nh;
  /* framing */
  int has_length; uint64_t length; int chunked;
  int close;                       /* Connection: close, or HTTP/1.0 without keep-alive */
  int expect_continue;
  size_t head_len;                 /* bytes consumed including the final CRLF CRLF */
} wd_req;

enum { WD_PARSE_MORE = 0, WD_PARSE_DONE = 1, WD_PARSE_ERROR = -1 };
/* Parses buf[0..len). Leading CRLFs are skipped. On WD_PARSE_ERROR *status is the HTTP status to send
   (400, 431, 501, 505) and the connection must be closed. Pointers in r point into buf. */
int wd_http_parse_head(const char *buf, size_t len, wd_req *r, int *status);
/* First header with this name (case-insensitive); count receives the number of occurrences. */
const wd_hdr *wd_req_header(const wd_req *r, const char *name, uint32_t *count);
int  wd_req_has_prefix_header(const wd_req *r, const char *prefix);   /* e.g. "Sec-Fetch-" */
int  wd_ieq(const char *a, size_t an, const char *b);                 /* case-insensitive, b NUL-terminated */
const char *wd_status_text(int status);

/* Chunked transfer decoding. Feed raw bytes; decoded data is reported through (out, *out_n) slices
   of the input (no copy). */
typedef struct wd_chunked {
  int state; uint64_t left; uint32_t linelen; uint32_t trailer_bytes; int done;
} wd_chunked;
void wd_chunked_init(wd_chunked *c);
/* Consumes from in[0..n): *used bytes; data slice [*data, *data + *data_n) (may be empty). Returns
   0 on progress, -1 on a framing error. Call repeatedly until *used == n or c->done. */
int  wd_chunked_feed(wd_chunked *c, const char *in, size_t n, size_t *used, const char **data, size_t *data_n);

/* ---- request target (02 §7.5) ---- */
typedef struct wd_path {
  uint32_t nseg;
  char *seg[WD_MAX_SEGMENTS];      /* decoded UTF-8, NUL-terminated, into buf */
  int trailing_slash;
  char *buf;                       /* owned (sd_alloc) */
} wd_path;
/* Decodes an origin-form path. Returns 0 or 400. */
int  wd_path_decode(const char *t, size_t n, wd_path *out);
void wd_path_free(wd_path *p);
/* vfs path from segments [first..nseg): L"\\a\\b" (root: L"\\"). NULL on OOM / invalid UTF-8. */
WCHAR *wd_path_to_vfs(const wd_path *p, uint32_t first);
/* Percent-encodes one UTF-8 segment for an href (unreserved characters kept). */
void wd_href_seg(wd_sb *b, const char *seg, size_t n);
/* Is s exactly "s-" + 26 base32 characters? */
int  wd_is_token_seg(const char *s);
int  wd_ct_equal(const char *a, const char *b, size_t n);   /* constant-time */

/* Host header check (DNS rebinding, T-33): exactly localhost:PORT, 127.0.0.1:PORT or [::1]:PORT. */
int  wd_host_ok(const char *v, size_t n, uint16_t port);
/* Destination: absolute http URI whose authority equals host (case-insensitive). Returns 0 and the
   decoded path, 400 when malformed, 502 for another authority. */
int  wd_destination_parse(const char *v, size_t n, const char *host, size_t host_n, wd_path *out);

/* ---- XML ---- */
typedef struct wd_xnode {
  const char *ns; const char *name;      /* resolved namespace URI ("" = none) and local name */
  const char *text;                      /* unescaped concatenated character data, "" if none */
  int parent, child, next;               /* indices, -1 = none */
} wd_xnode;
typedef struct wd_xdoc { wd_xnode *n; uint32_t count; char *arena; } wd_xdoc;
/* Parses a complete document. Returns 0, or 400 (malformed, DTD, depth, size, not UTF-8). */
int  wd_xml_parse(const char *p, size_t n, wd_xdoc *out);
void wd_xml_free(wd_xdoc *d);
/* First child of node i with (ns, name); -1 if none. i = -1 means the root. */
int  wd_xml_child(const wd_xdoc *d, int i, const char *ns, const char *name);
int  wd_xml_is(const wd_xdoc *d, int i, const char *ns, const char *name);

/* ---- encodings and values ---- */
size_t wd_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap);     /* returns length or 0 */
int    wd_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_n);  /* 0 ok */
/* 26 lowercase base32 chars from 130 random bits, NUL-terminated (27 bytes). 0 on success. */
int    wd_make_token(char out[WD_TOKEN_CHARS + 1]);
int    wd_random(void *p, size_t n);                      /* RtlGenRandom; 0 on success */
void   wd_uuid(char out[37]);                             /* random v4 UUID text */

void   wd_rfc1123(uint64_t filetime, char out[32]);       /* "Sun, 06 Nov 1994 08:49:37 GMT" */
void   wd_rfc3339(uint64_t filetime, char out[32]);       /* "1994-11-06T08:49:37Z" */
int    wd_parse_rfc1123(const char *s, size_t n, uint64_t *filetime);   /* 0 ok (also RFC 850/asctime-free) */

/* Range: bytes=a-b | a- | -n against size. Returns 0 = no/ignored range (send 200), 1 = single
   satisfiable range [*first, *last], 416 = unsatisfiable. Multi-range -> 0. */
int    wd_range_parse(const char *v, size_t n, uint64_t size, uint64_t *first, uint64_t *last);
/* Timeout: "Second-n" (capped at 3600) | "Infinite" (3600); first acceptable value; default 3600. */
uint32_t wd_timeout_parse(const char *v, size_t n);
/* Extracts the lock tokens ("<opaquelocktoken:...>" inside parentheses) of an If header. Returns the
   count stored (up to max), tokens copied without angle brackets. */
uint32_t wd_if_tokens(const char *v, size_t n, char tokens[][80], uint32_t max);

#endif /* SD_WD_PROTO_H */
