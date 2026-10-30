/* Service access rules for global drives (03 §1.3, §2.2, §2.6, §3.4.1; D17, D35; TM-R24, TM-R25).
 *
 * Pure logic, no Win32 calls: the service resolves names and token memberships, then asks these functions.
 * Tests (tests/unit/sd_svc) drive every row of the decision table without a service or an elevated process.
 *
 *   service_access        who may use the drive (read; listed in the status/list output)
 *   service_access_write  who may change files (subset of service_access; BUILTIN\Administrators in the list
 *                         always gets write, 03 §3.4.1)
 *   elevated admin        BUILTIN\Administrators enabled in an elevated token (the only caller that may mount,
 *                         unmount, read details or set secrets; 2.2)
 */
#ifndef SVC_ACCESS_H
#define SVC_ACCESS_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_config/sd_config.h"

#define SVC_SID_MAX 190          /* characters of a SID string, with the terminator */
#define SVC_ACL_MAX 32           /* entries per list */

/* Resolved access lists of one machine profile: SID strings only ("S-1-5-..."). write[] is a subset of access[]. */
typedef struct svc_acl {
  uint32_t n_access, n_write;
  char access[SVC_ACL_MAX][SVC_SID_MAX];
  char write[SVC_ACL_MAX][SVC_SID_MAX];
} svc_acl;

/* What the caller is, as far as the decision needs it. */
typedef struct svc_member {
  int in_access;           /* the caller's token matches an entry of service_access (user SID or enabled group) */
  int in_write;            /* ... of service_access_write */
  int admin_elevated;      /* elevated BUILTIN\Administrators (sd_ipc_client_is_admin) */
} svc_member;

/* What the caller may do with one global mount. */
typedef struct svc_rights {
  int see_letter;          /* the letter (always: it is visible system-wide, 2.2) */
  int see_state;           /* label and state (service_access members and admins) */
  int see_details;         /* host, user, remote path, errors (elevated admins only) */
  int use;                 /* read the drive */
  int write;               /* change files */
  int manage;              /* mount, unmount, secret.set, prompt.answer (elevated admins only) */
} svc_rights;

void svc_decide(const svc_member *m, svc_rights *out);

/* Resolves one service_access entry (a SID string, or an account name) to a SID string. Returns 1 when resolved. */
typedef int (*svc_resolve_fn)(void *ctx, const char *entry, char *sid_out, size_t cap);

/* Builds the resolved lists from the profile's service_access and service_access_write. SD_E_NOT_FOUND when an entry
   does not resolve (fail closed), SD_E_INVALID_PARAM when a write entry is not in the access list or the lists are
   too long. */
sd_err svc_acl_build(const sd_profile *p, svc_resolve_fn resolve, void *ctx, svc_acl *out);

/* Machine profile checks at load and before every mount (2.6 rule 1, D17, 03 §3.4.1). Returns SD_OK, or SD_E_INVALID_PARAM
   with *bad_key naming the offending key and *why a short English reason (for logs). Refused: scope other than service,
   no user, agent-based authentication (auth.agent = pageant or openssh, D17), kbdint (2.6), WebDAV backend (the global
   WebDAV spike is not in this build, D11). Jump hosts and proxies are checked per hop when the chain is built
   (svc_chain_hop_check, svc_proxy_leg_check). */
sd_err svc_validate_profile(const sd_profile *p, const char **bad_key, const char **why);

/* One hop of a service chain (2.6 rule 1, M5, 3.4.1): the service rules of the hop. Refused: more than one identity
   file (a hop takes one key blob), a certificate, identity_store (a user-kept key, service secrets only), an agent
   (Pageant or OpenSSH, D17), agent_keys, keyboard-interactive, and no publickey or password method. */
sd_err svc_chain_hop_check(const sd_chain_hop *h, const char **bad_key, const char **why);

/* One proxy leg of a service chain (2.6 rule 1, 3.8). proxy_auth is the profile's SD_PROFILE_PROXY_AUTH_*;
   secret_present says whether a proxy secret for this leg is in the service secret store. Allowed: no proxy; a
   proxy with no user (Negotiate through SSPI with the machine account; auto is Kerberos only); a user (HTTP Basic or
   SOCKS5 username and password) only with a service secret. Refused: basic without a user or without the secret, and
   proxy = system with basic or negotiate (the machine configuration has no credentials, TM-R10). */
sd_err svc_proxy_leg_check(const sd_proxy_spec *x, int proxy_auth, int secret_present, const char **bad_key,
                           const char **why);

/* Volume security descriptor of a global mount, SDDL: SYSTEM and Administrators full control, each access entry
   read/traverse (FRFX), each write entry full control (FA), all inherited to containers and objects. Writes
   "O:SYG:SY" and the DACL into out. SD_E_NO_SPACE when cap is too small. */
sd_err svc_volume_sddl(const svc_acl *acl, char *out, size_t cap);

/* Machine path rule for identity files of service profiles (TM-R27, 2.6): the expanded path must begin with the
   machine service folder followed by a backslash and must not contain a reparse-ambiguous "..\" segment. */
int svc_path_under(const wchar_t *path, const wchar_t *folder);

/* Event 3101 throttle (10.3, TM-R25): one entry per SID that was refused or over quota. */
#define SVC_REFUSE_WINDOW_MS (10u * 60u * 1000u)
#define SVC_REFUSE_SLOTS 32
#define SVC_REFUSE_SID_CCH 96

typedef struct svc_refuse_entry {
  int used;
  uint64_t last_ms;                    /* when the event was last written for this SID */
  wchar_t sid[SVC_REFUSE_SID_CCH];     /* SID string */
} svc_refuse_entry;

/* 1 when an Event 3101 may be written for sid now (not written for it in the last 10 minutes), and records it;
   0 otherwise. tab holds n entries; when full, the entry logged longest ago is reused. now_ms is the caller's
   monotonic clock (tests pass their own times). Not thread-safe: the caller serializes it. */
int svc_refuse_log_due(svc_refuse_entry *tab, size_t n, const wchar_t *sid, uint64_t now_ms);

#endif /* SVC_ACCESS_H */
