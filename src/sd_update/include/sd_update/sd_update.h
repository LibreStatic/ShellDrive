/* sd_update: the updater engine (04 §9, TM-R36, TM-R37, TM-R23, D30, D45).
 *
 * Layers, bottom up:
 *   1. Pure functions (update_verify.c): strict parsing of manifest.txt and keyset.txt, base64, dates,
 *      version comparison, the signature chain root -> keyset -> manifest. No I/O, no clock: `now` is
 *      an argument, so every rule is unit-testable with fixtures.
 *   2. State (update_state.c): last_serial.<channel>, last_verified.<channel>, the accepted keyset and
 *      roots, the last verified manifest per channel. Monotonic writes (MoveFileEx replace, WRITE_THROUGH).
 *   3. Transport (update_winhttp.c): WinHTTP resolved at run time (XP-safe), HTTPS first, the plain HTTP
 *      mirror as fallback (D30). Redirects are checked against an allow list. No own TLS.
 *   4. Engine (update_engine.c): check (fetch, verify, compare), stage (download, size, digest), apply
 *      (file replacement with rollback, or running the staged setup), --selftest of the new binaries.
 *
 * Thread safety: pure functions are reentrant. The engine is not: one check or apply at a time per
 * state directory (the agent serializes them). Manifest text is ASCII; paths are UTF-16. */
#ifndef SD_UPDATE_H
#define SD_UPDATE_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* ---- format constants (04 §9.2, §9.3) ---- */
#define SD_UPD_PRODUCT            "com.librestatic.shelldrive"
#define SD_UPD_DOMAIN_MANIFEST    "com.librestatic.shelldrive release manifest v1\n"
#define SD_UPD_DOMAIN_KEYSET      "com.librestatic.shelldrive keyset v1\n"
#define SD_UPD_MANIFEST_MAX       (64u * 1024u)
#define SD_UPD_KEYSET_MAX         (64u * 1024u)
#define SD_UPD_LINE_MAX           1024u
#define SD_UPD_MAX_FILES          32u
#define SD_UPD_MAX_BASES          8u
#define SD_UPD_MAX_MINOS          16u
#define SD_UPD_MAX_DENY           16u
#define SD_UPD_MAX_KEYS           32u
#define SD_UPD_MAX_ROOTS          4u
#define SD_UPD_MAX_FILE_BYTES     (2ull * 1024ull * 1024ull * 1024ull)
#define SD_UPD_STALE_SECONDS      (14 * 86400)     /* last_verified older than this: update.stale */
#define SD_UPD_STABLE_MAX_DAYS    30               /* expires - released (TM-R36) */
#define SD_UPD_BETA_MAX_DAYS      14
#define SD_UPD_SELFTEST_MS        60000u

/* Result of every operation. The IPC code (sd_upd_res_code) and the log name (sd_upd_res_name) are
   stable English spellings. Append new values at the end. */
typedef enum sd_upd_res {
  SD_UPD_OK = 0,
  SD_UPD_E_FORMAT,            /* malformed manifest or keyset (strict parse) */
  SD_UPD_E_TOO_LARGE,         /* over SD_UPD_MANIFEST_MAX / SD_UPD_KEYSET_MAX, or a file over its size */
  SD_UPD_E_PRODUCT,           /* product is not com.librestatic.shelldrive (D45) */
  SD_UPD_E_FORMAT_VERSION,    /* unknown shelldrive-manifest / keyset major: update the application manually */
  SD_UPD_E_SIGNATURE,         /* a signature does not verify over the exact bytes */
  SD_UPD_E_UNKNOWN_KEY,       /* sig key id not in the keyset, or not authorized for this channel */
  SD_UPD_E_KEY_EXPIRED,       /* the key's validity dates do not include now */
  SD_UPD_E_KEY_REVOKED,       /* revoke line for the key */
  SD_UPD_E_KEYSET_SIGNATURE,  /* keyset not signed by the trusted root(s), or rotation without both */
  SD_UPD_E_KEYSET_ROLLBACK,   /* keyset version lower than the stored one (TM-R37) */
  SD_UPD_E_KEYSET_NEEDED,     /* manifest names a newer keyset: fetch keyset.txt and verify again */
  SD_UPD_E_CHANNEL_MISMATCH,  /* manifest channel differs from the configured channel (TM-R37) */
  SD_UPD_E_EXPIRED,           /* expires in the past: "cannot verify updates" (TM-R36) */
  SD_UPD_E_FRESHNESS,         /* expires more than 30 (stable) / 14 (beta) days after released */
  SD_UPD_E_ROLLBACK,          /* serial lower than the last accepted of this channel, or same serial with other bytes */
  SD_UPD_E_NO_TARGET,         /* no file for this install mode and flavour, or the OS is below min-os */
  SD_UPD_E_SIZE,              /* downloaded size differs from the manifest */
  SD_UPD_E_HASH,              /* digest differs from the manifest */
  SD_UPD_E_NETWORK,           /* no base URL could be fetched (HTTPS and HTTP mirror both failed) */
  SD_UPD_E_REDIRECT,          /* redirect to a host that is not allowed (T-69) */
  SD_UPD_E_SELFTEST,          /* new binaries failed --selftest; the previous version was restored */
  SD_UPD_E_APPLY,             /* replacing files or running the staged setup failed */
  SD_UPD_E_DISABLED,          /* updates disabled by policy, settings or portable mode */
  SD_UPD_E_STATE,             /* state directory unusable (cannot write last_serial etc.) */
  SD_UPD_E_IO,                /* local file error */
  SD_UPD_E_NO_MEMORY,
  SD_UPD_E_INVALID            /* bad argument */
} sd_upd_res;

const char *sd_upd_res_name(sd_upd_res r);   /* "signature_invalid" ... log spelling, never NULL */
const char *sd_upd_res_code(sd_upd_res r);   /* IPC error code: update_verify_failed, update_unavailable, ... */

/* ---- versions and time ---- */

typedef struct sd_upd_version {
  uint32_t part[4];
  uint32_t n;                  /* 1..4 numeric components */
} sd_upd_version;

sd_upd_res sd_upd_version_parse(const char *s, size_t len, sd_upd_version *out);
int        sd_upd_version_cmp(const sd_upd_version *a, const sd_upd_version *b);   /* <0, 0, >0 */

/* "YYYY-MM-DDTHH:MM:SSZ" (strict, UTC) -> unix seconds. */
sd_upd_res sd_upd_time_parse(const char *s, size_t len, int64_t *unix_s);
/* "YYYY-MM-DD" -> unix seconds of 00:00:00Z (end_of_day = 0) or 23:59:59Z (end_of_day = 1). */
sd_upd_res sd_upd_date_parse(const char *s, size_t len, int end_of_day, int64_t *unix_s);

/* ---- keys ---- */

/* Key ID = first 8 bytes of SHA-256(public key). */
void sd_upd_key_id(const uint8_t pub[32], uint8_t id[8]);

typedef struct sd_upd_root {
  uint8_t id[8];
  uint8_t pub[32];
} sd_upd_root;

typedef struct sd_upd_keyset_key {
  uint8_t  id[8];
  char     channel[8];         /* "stable" | "beta" */
  uint8_t  pub[32];
  int64_t  valid_from, valid_to;
  int      revoked;
} sd_upd_keyset_key;

typedef struct sd_upd_keyset {
  uint64_t version;
  uint32_t nroots;                              /* roots in effect after this keyset */
  sd_upd_root roots[SD_UPD_MAX_ROOTS];
  uint32_t nkeys;
  sd_upd_keyset_key keys[SD_UPD_MAX_KEYS];
  int      rotated_roots;                       /* the keyset carried root lines (signed by both old roots) */
} sd_upd_keyset;

/* Parses keyset.txt and verifies it: signed by a current root (by both when it carries root lines).
   stored_version: the highest keyset version accepted so far (0 = none). A lower version is
   SD_UPD_E_KEYSET_ROLLBACK; an equal one is accepted. `out` is valid only on SD_UPD_OK. */
sd_upd_res sd_upd_keyset_verify(const uint8_t *data, size_t len, const sd_upd_root *roots, uint32_t nroots,
                                uint64_t stored_version, sd_upd_keyset *out);

/* ---- manifest (04 §9.2) ---- */

typedef struct sd_upd_file {
  char     id[32];             /* setup-universal, msi-x64-modern, portable-x86-ia32, dokany-x64 ... */
  char     name[128];          /* file name only: no separators, no "..", printable ASCII */
  uint64_t size;
  int      hash_alg;           /* 256 or 512 */
  uint8_t  digest[64];
} sd_upd_file;

typedef struct sd_upd_minos {
  char     flavour[16];
  sd_upd_version version;
} sd_upd_minos;

typedef struct sd_upd_deny {
  sd_upd_version min, max;
  char     reason[32];
} sd_upd_deny;

typedef struct sd_upd_manifest {
  char     channel[8];
  uint64_t keyset;             /* keyset version the signing key is listed in */
  uint64_t serial;
  char     version_str[32];
  sd_upd_version version;
  int64_t  released, expires;
  char     notes[256];
  uint32_t nminos;
  sd_upd_minos minos[SD_UPD_MAX_MINOS];
  uint32_t nfiles;
  sd_upd_file files[SD_UPD_MAX_FILES];
  uint32_t nbases;
  char     bases[SD_UPD_MAX_BASES][256];
  uint32_t ndeny;
  sd_upd_deny deny[SD_UPD_MAX_DENY];
  char     dokany_version[32]; /* from the dokany line (empty when absent) */
  uint8_t  sig_key_id[8];
  uint8_t  sig[64];
  uint32_t sig_offset;         /* bytes [0, sig_offset) are the signed body */
} sd_upd_manifest;

/* Strict syntax only (no keys, no clock): printable ASCII and LF line ends, one record per line, the
   first line "shelldrive-manifest 1", a single sig line as the last line. Unknown keys are ignored. */
sd_upd_res sd_upd_manifest_parse(const uint8_t *data, size_t len, sd_upd_manifest *out);

/* Full verification of a parsed manifest: product (D45), signature by a key of the keyset that is
   authorized for m->channel and valid at now (TM-R37), channel equal to expected_channel, expires after
   now and freshness (TM-R36), serial against last_serial (anti-rollback per channel). An equal serial is
   accepted here; the engine also requires the same bytes as the last accepted manifest of the channel. */
sd_upd_res sd_upd_manifest_verify(const uint8_t *data, size_t len, const sd_upd_manifest *m,
                                  const sd_upd_keyset *ks, const char *expected_channel, int64_t now,
                                  uint64_t last_serial);

/* Base64 (RFC 4648, standard alphabet, padded, canonical). Returns the decoded length or -1. */
int sd_upd_base64_decode(const char *s, size_t len, uint8_t *out, size_t cap);

/* ---- state (04 §9.2, §9.3; C8) ---- */

typedef struct sd_upd_state_dirs {
  const wchar_t *user;         /* per-user state dir (read and written) */
  const wchar_t *machine;      /* per-machine state dir (read only for the agent); may be NULL */
} sd_upd_state_dirs;

/* Maximum over the readable copies of last_serial.<channel> (per channel, so beta cannot block stable).
   Migrates the pre-integration single file last_serial to last_serial.<channel> once. */
sd_upd_res sd_upd_state_read_serial(const sd_upd_state_dirs *d, const char *channel, uint64_t *serial);
/* Writes last_serial.<channel> in the user dir. Refuses a value lower than the current maximum. */
sd_upd_res sd_upd_state_write_serial(const sd_upd_state_dirs *d, const char *channel, uint64_t serial);
sd_upd_res sd_upd_state_read_verified(const sd_upd_state_dirs *d, const char *channel, int64_t *unix_s);
sd_upd_res sd_upd_state_write_verified(const sd_upd_state_dirs *d, const char *channel, int64_t unix_s);
/* Named blobs in the user dir: keyset (accepted keyset.txt) and roots (accepted "root <id> <base64>" lines).
   Read returns SD_UPD_E_STATE with *len = 0 when the file does not exist. Free *buf with sd_free. */
sd_upd_res sd_upd_state_read_blob(const sd_upd_state_dirs *d, const wchar_t *name, uint8_t **buf, size_t *len);
sd_upd_res sd_upd_state_write_blob(const sd_upd_state_dirs *d, const wchar_t *name, const uint8_t *buf, size_t len);
/* Last verified manifest bytes of a channel (same-serial check, dokany-deny list). */
sd_upd_res sd_upd_state_read_manifest(const sd_upd_state_dirs *d, const char *channel, uint8_t **buf, size_t *len);
sd_upd_res sd_upd_state_write_manifest(const sd_upd_state_dirs *d, const char *channel, const uint8_t *buf, size_t len);

/* ---- transport (04 §9.4) ---- */

typedef struct sd_upd_transport sd_upd_transport;

typedef struct sd_upd_transport_ops {
  /* Downloads url into memory, at most max bytes. */
  sd_upd_res (*get_mem)(sd_upd_transport *t, const wchar_t *url, uint32_t max, uint8_t **buf, size_t *len);
  /* Downloads url into the file at path (truncated), at most max bytes. */
  sd_upd_res (*get_file)(sd_upd_transport *t, const wchar_t *url, uint64_t max, const wchar_t *path);
  void (*destroy)(sd_upd_transport *t);
} sd_upd_transport_ops;

struct sd_upd_transport {
  const sd_upd_transport_ops *ops;
  void *impl;
  uint32_t nallow;                                /* extra hosts redirects may go to (manifest bases) */
  wchar_t allow[SD_UPD_MAX_BASES][128];
};

/* WinHTTP transport. use_proxy = 1: WINHTTP_ACCESS_TYPE_DEFAULT_PROXY (the agent). 0: no proxy (tests
   against a loopback server). Every WinHTTP entry point is resolved at run time (XP-safe). NULL when
   WinHTTP cannot be loaded. */
sd_upd_transport *sd_upd_transport_winhttp_create(int use_proxy);
void              sd_upd_transport_destroy(sd_upd_transport *t);

/* ---- engine (04 §9.1, §9.6) ---- */

typedef enum sd_upd_mode {
  SD_UPD_MODE_SETUP = 1,       /* per-user EXE install: setup-universal or setup-<arch> */
  SD_UPD_MODE_MSI,             /* msi-<flavour> */
  SD_UPD_MODE_PORTABLE         /* portable-<flavour>: the UI offers a manual download; never applied */
} sd_upd_mode;

typedef struct sd_upd_trust {
  const sd_upd_root *roots;    /* compiled-in root public keys; with none, nothing verifies */
  uint32_t nroots;
  const uint8_t *keyset;       /* compiled-in keyset.txt (the floor, verified on use); may be NULL */
  size_t keyset_len;
} sd_upd_trust;

typedef struct sd_upd_paths {
  const wchar_t *staging;      /* downloads go to <staging>\<version>\ */
  const wchar_t *install;      /* install root for file-swap apply; NULL = not supported */
  const wchar_t *selftest_exe; /* relative to install, e.g. L"shelldrive-host.exe" */
} sd_upd_paths;

typedef struct sd_upd_request {
  const wchar_t *manifest_url;     /* bootstrap or configured manifest URL (https or http) */
  const wchar_t *manifest_alt;     /* fallback when manifest_url fails with a network error (the HTTP mirror); may be NULL */
  const char *channel;             /* "stable" | "beta" */
  const char *installed_version;   /* SD_VERSION_STRING of the running build */
  const char *flavour;             /* target flavour, re-evaluated per check (sd_upd_detect_flavour) */
  sd_upd_mode mode;
  int64_t now;                     /* unix seconds */
  sd_upd_transport *tr;
  const sd_upd_trust *trust;
  const sd_upd_state_dirs *state;
  const sd_upd_paths *paths;
} sd_upd_request;

typedef struct sd_upd_offer {
  int      available;              /* verified and newer than the installed version */
  int      stale;                  /* no verified manifest for SD_UPD_STALE_SECONDS before this check */
  char     version[32];
  char     channel[8];
  char     notes[256];
  char     file_id[32];
  char     file_name[128];
  uint64_t size;
  uint64_t serial;
  int64_t  released, expires;
  sd_upd_file file;                /* the selected artifact */
  sd_upd_manifest manifest;        /* verified manifest (copied) */
} sd_upd_offer;

/* Detects the target flavour from the running OS and CPU (04 §6.2): x86-ia32, x86-sse2, x64-xp,
   x64-modern, arm32, arm64. out_cap >= 16. */
sd_upd_res sd_upd_detect_flavour(char *out, size_t out_cap);

/* Fetch the manifest (and keyset when named newer), verify, compare with the installed version and pick
   the artifact for mode and flavour. Updates last_verified and the accepted serial, keyset, roots and
   manifest bytes. Installs nothing. */
sd_upd_res sd_upd_check(const sd_upd_request *r, sd_upd_offer *out);

/* Downloads the offer's artifact to <staging>\<version>\<name>, checks size and digest, keeps it there. */
sd_upd_res sd_upd_stage(const sd_upd_request *r, const sd_upd_offer *o, wchar_t *staged_path, size_t cap);

/* Setup mode: runs "<staged> /update /passive" and waits (timeout_ms). Elevation is the caller's job. */
sd_upd_res sd_upd_apply_setup(const wchar_t *staged_exe, uint32_t timeout_ms);

/* File-swap mode: payload_dir holds the new files named names[0..count). They replace the same names in
   paths->install; the previous files go to install\.rollback\<old_version>\. The selftest exe runs with
   --selftest (exit 0 = healthy). On any failure everything is restored and SD_UPD_E_SELFTEST or
   SD_UPD_E_APPLY is returned (04 §9.6). */
sd_upd_res sd_upd_apply_files(const sd_upd_request *r, const wchar_t *payload_dir, const wchar_t *const *names,
                              uint32_t count, const char *old_version, const char *new_version, uint32_t selftest_ms);

/* Removes staging version directories other than keep_version (04 §9.6 cleanup). */
void sd_upd_cleanup_staging(const wchar_t *staging, const char *keep_version);

/* Selects the artifact: exact ids "msi-<f>", "portable-<f>", or for SETUP "setup-universal" then
   "setup-<arch>". Applies min-os for the flavour against the running OS. */
sd_upd_res sd_upd_select_file(const sd_upd_manifest *m, sd_upd_mode mode, const char *flavour, const sd_upd_file **out);

#endif /* SD_UPDATE_H */
