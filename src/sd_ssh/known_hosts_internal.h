/* sd_ssh private: known_hosts helpers shared by known_hosts.c, known_hosts_live.c and the unit tests.
 * No transport dependency. */
#ifndef SD_SSH_KNOWN_HOSTS_INTERNAL_H
#define SD_SSH_KNOWN_HOSTS_INTERNAL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_known_hosts.h"

/* Loads a live read-only source (01 §7.2, TM-R06) as known_hosts text (PuTTY values are converted to
   "<lookup_name> <type> <base64>" lines, one per value). *state: OK (text valid), ABSENT, or INSECURE
   (text NULL; detail_sid receives the SID that may write, or a reason in brackets). invalid counts
   PuTTY values that could not be converted (may be NULL). Errors only for out-of-memory / bad
   parameters; an unreadable source is ABSENT. */
sd_err ssh_kh_live_load(sd_kh_store_kind kind, const wchar_t *path, char **text, size_t *len,
                        sd_kh_src_state *state, wchar_t *detail_sid, size_t detail_cap, uint32_t *invalid);

/* One PuTTY SshHostKeys value (name "<type>@<port>:<host>" with %XX escapes, data as stored) to a
   known_hosts line appended to w. SD_E_KEY_UNSUPPORTED for skipped types (dss, rsa (SSH-1), ed448),
   SD_E_KEY_FORMAT for malformed or invalid keys. */
sd_err ssh_putty_value_to_line(const wchar_t *name, const wchar_t *data, sd_wr *w);

/* TM-R06 check of a security descriptor: owner and every allow ACE granting any of bad_rights must be
   the current user, SYSTEM, Administrators (or OWNER RIGHTS). Returns 1 if secure; otherwise 0 and the
   offending SID string in sid (if given). generic: the object's GENERIC_MAPPING. */
int ssh_kh_sd_secure(PSECURITY_DESCRIPTOR sd, DWORD bad_rights, const GENERIC_MAPPING *generic,
                     wchar_t *sid, size_t sid_cap);

/* "<prefix>YYYY-MM-DD" (UTC). */
void ssh_kh_date_comment(const char *prefix, char *out, size_t cap);

#endif /* SD_SSH_KNOWN_HOSTS_INTERNAL_H */
