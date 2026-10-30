/* sd_update test fixtures: test keys and signed keyset/manifest files generated at test time by sd-updsign
 * in a temporary directory, a manifest/keyset body builder, and a loopback HTTP server (winsock, 127.0.0.1
 * only). No test touches the network beyond the loopback interface. */
#ifndef SD_UPDATE_TEST_FIXTURE_H
#define SD_UPDATE_TEST_FIXTURE_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "sd_update/sd_update.h"

/* 2026-10-27T12:00:00Z, the "now" of every fixture. */
#define FX_NOW_STR "2026-10-27T12:00:00Z"

typedef struct fx_key {
  wchar_t seed_path[MAX_PATH];
  uint8_t seed[32];
  uint8_t pub[32];
  char pub_b64[48];
  uint8_t id[8];
  char id_hex[17];
} fx_key;

typedef struct fx {
  wchar_t dir[MAX_PATH];        /* temporary root; removed by fx_done */
  wchar_t tool[MAX_PATH];       /* sd-updsign.exe */
  fx_key root_a, root_b, root_c, stable, beta, rogue;
} fx;

int  fx_init(fx *f, const char *name);
void fx_done(fx *f);
int  fx_path(const fx *f, const wchar_t *rel, wchar_t *out, size_t cap);
int  fx_write(const wchar_t *path, const void *p, size_t n);
int  fx_read(const wchar_t *path, uint8_t **buf, size_t *n);
void fx_remove_tree(const wchar_t *dir);

/* Text builder for bodies. */
typedef struct fx_text { char *p; size_t n, cap; } fx_text;
void fx_text_add(fx_text *t, const char *fmt, ...);

/* keyset.txt: stable and beta keys valid from 2026-01-01; the given "to" dates and options change that. */
typedef struct fx_keyset_opts {
  uint64_t version;
  const char *stable_to;        /* default 2030-01-01 */
  const char *beta_to;          /* default 2030-01-01 */
  const char *stable_from;      /* default 2026-01-01 */
  int revoke_stable;
  int include_beta;             /* default 1 */
  int rotate;                   /* root lines: root_c and root_b become the roots (needs both roots to sign) */
} fx_keyset_opts;

/* Body (unsigned) of keyset.txt. Returns the length. */
size_t fx_keyset_body(const fx *f, char *out, size_t cap, const fx_keyset_opts *o);
/* Signs body with the given roots (one sig line each). Output file bytes in *out (free with sd_free). */
int fx_sign_keyset(fx *f, const char *body, size_t blen, const fx_key *const *roots, int nroots,
                   uint8_t **out, size_t *olen);

typedef struct fx_file_entry {
  const char *id;               /* e.g. portable-x64-modern */
  const char *name;             /* file name in the artifact set */
  const wchar_t *path;          /* local file: its size and SHA-256 are written into the manifest */
} fx_file_entry;

typedef struct fx_manifest_opts {
  const char *channel;          /* stable | beta */
  const char *product;          /* default com.librestatic.shelldrive */
  uint64_t keyset;
  uint64_t serial;
  const char *version;
  const char *released;         /* default 2026-10-24T12:00:00Z */
  const char *expires;          /* default 2026-11-23T00:00:00Z */
  const char *base;             /* base URL with trailing slash */
  const char *extra;            /* raw lines appended before the sig line (may be NULL) */
  const fx_file_entry *files;
  int nfiles;
} fx_manifest_opts;

size_t fx_manifest_body(char *out, size_t cap, const fx_manifest_opts *o);
/* Signs with a release key (domain of manifests). Output in *out (sd_free). */
int fx_sign_manifest(fx *f, const char *body, size_t blen, const fx_key *k, uint8_t **out, size_t *olen);

/* Loopback HTTP/1.1 server on 127.0.0.1 (ephemeral port). Routes match the request path exactly. */
typedef struct fx_route {
  const char *path;
  const uint8_t *body;
  size_t len;
  int status;                   /* 200 default when 0 */
  const char *location;         /* Location header for 3xx */
  unsigned long long declared;  /* Content-Length override (0 = len); used for the oversize test */
} fx_route;

typedef struct fx_server {
  uintptr_t ls;                /* SOCKET (kept out of this header: winsock2 must come first in fixture.c) */
  HANDLE thread;
  uint16_t port;
  const fx_route *routes;
  int nroutes;
  volatile LONG stop;
  int served;
} fx_server;

int  fx_server_start(fx_server *s, const fx_route *routes, int n);
void fx_server_stop(fx_server *s);

/* Hex SHA-256 of a file in "sha256:<hex>" form, and its size. */
int fx_file_digest(const wchar_t *path, char *out, size_t cap, uint64_t *size);

#endif /* SD_UPDATE_TEST_FIXTURE_H */
