/* Neutral error enum shared by all core modules (01 §10.2, review C13, C25).
 *
 * SD_ERR_LIST is the single master table: the enum and sd_err_name() are generated from it, and every
 * mapping table elsewhere (sd_vfs_status, NTSTATUS, HTTP, IPC code, exit code) must be built from it
 * too and checked by a unit test that covers every value. Append new values at the end of a group;
 * never reuse or rename an IPC spelling (the second column), clients localize by it.
 *
 * Thread safety: pure data, any thread. */
#ifndef SD_ERR_H
#define SD_ERR_H

#include "sd/base.h"

#define SD_ERR_LIST(X)                                                       \
  X(SD_OK,                         "ok")                                     \
  /* filesystem-ish results */                                               \
  X(SD_E_EOF,                      "eof")                                    \
  X(SD_E_NOT_FOUND,                "not_found")                              \
  X(SD_E_ACCESS_DENIED,            "access_denied")                          \
  X(SD_E_EXISTS,                   "exists")                                 \
  X(SD_E_NOT_EMPTY,                "not_empty")                              \
  X(SD_E_NOT_A_DIRECTORY,          "not_a_directory")                        \
  X(SD_E_IS_A_DIRECTORY,           "is_a_directory")                         \
  X(SD_E_NO_SPACE,                 "no_space")                               \
  X(SD_E_QUOTA,                    "quota")                                  \
  X(SD_E_READ_ONLY,                "read_only")                              \
  X(SD_E_INVALID_NAME,             "invalid_name")                           \
  X(SD_E_NAME_TOO_LONG,            "name_too_long")                          \
  X(SD_E_LINK_LOOP,                "link_loop")                              \
  X(SD_E_LOCK_CONFLICT,            "lock_conflict")                          \
  X(SD_E_INVALID_PARAM,            "invalid_param")                          \
  X(SD_E_UNSUPPORTED,              "unsupported")                            \
  X(SD_E_FAILURE,                  "failure")                                \
  /* session / transport */                                                  \
  X(SD_E_DISCONNECTED,             "disconnected")                           \
  X(SD_E_STALE_HANDLE,             "stale_handle")                           \
  X(SD_E_TIMEOUT,                  "timeout")                                \
  X(SD_E_CANCELLED,                "cancelled")                              \
  X(SD_E_PROTOCOL,                 "protocol")                               \
  X(SD_E_BUSY,                     "busy")                                   \
  X(SD_E_WOULD_DEADLOCK,           "would_deadlock")                         \
  X(SD_E_SHUTDOWN,                 "shutdown")                               \
  X(SD_E_DNS,                      "dns_failed")                             \
  X(SD_E_CONN_REFUSED,             "conn_refused")                           \
  X(SD_E_NET_UNREACHABLE,          "net_unreachable")                        \
  X(SD_E_KEX_FAILED,               "kex_failed")                             \
  X(SD_E_HOSTKEY_REJECTED,         "host_key_rejected")                      \
  X(SD_E_HOSTKEY_MISMATCH,         "host_key_mismatch")                      \
  X(SD_E_HOSTKEY_REVOKED,          "host_key_revoked")                       \
  X(SD_E_HOSTKEY_TYPE_UNAVAILABLE, "host_key_type_unavailable")              \
  X(SD_E_AUTH_FAILED,              "auth_failed")                            \
  X(SD_E_AUTH_REQUIRED,            "prompt_required")                        \
  X(SD_E_LEGACY_REJECTED,          "legacy_refused")                         \
  X(SD_E_PROXY,                    "proxy_connect_failed")                   \
  X(SD_E_PROXY_AUTH,               "proxy_auth_failed")                      \
  X(SD_E_POOL_ABANDONED,           "pool_abandoned")                         \
  /* local */                                                                \
  X(SD_E_NO_MEMORY,                "no_memory")                              \
  X(SD_E_CRYPTO,                   "crypto")                                 \
  X(SD_E_KEY_FORMAT,               "key_format")                             \
  X(SD_E_KEY_UNSUPPORTED,          "key_unsupported")                        \
  X(SD_E_BAD_PASSPHRASE,           "bad_passphrase")                         \
  X(SD_E_KEY_PASSPHRASE_REQUIRED,  "key_passphrase_required")                \
  X(SD_E_INTERNAL,                 "internal")

#define SD_ERR_ENUM_(sym, name) sym,
typedef enum sd_err { SD_ERR_LIST(SD_ERR_ENUM_) SD_ERR_COUNT } sd_err;
#undef SD_ERR_ENUM_

/* Stable English identifier for logs, JSON and IPC (e.g. "not_found"). Never NULL: values outside the
   enum return "unknown". */
const char *sd_err_name(sd_err e);

/* Reverse lookup of an IPC spelling; returns SD_ERR_COUNT when unknown. */
sd_err sd_err_from_name(const char *name);

#endif /* SD_ERR_H */
